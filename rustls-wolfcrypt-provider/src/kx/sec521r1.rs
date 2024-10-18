use crate::{error::check_if_zero, types::types::*};
use foreign_types::ForeignType;
use std::mem;
use wolfcrypt_rs::*;

pub struct KeyExchangeSecP521r1 {
    pub priv_key_bytes: Vec<u8>,
    pub pub_key_bytes: Vec<u8>,
}

pub struct ECCPubKey {
    qx: Vec<u8>,
    qx_len: word32,
    qy: Vec<u8>,
    qy_len: word32,
}

impl KeyExchangeSecP521r1 {
    pub fn use_secp521r1() -> Self {
        let mut key: ecc_key = unsafe { mem::zeroed() };
        let key_object = ECCKeyObject::new(&mut key);
        let mut rng: WC_RNG = unsafe { mem::zeroed() };
        let rng_object: WCRngObject = WCRngObject::new(&mut rng);
        let mut ret;
        let mut pub_key_raw = ECCPubKey {
            qx: [0; 66].to_vec(),
            qx_len: 66,
            qy: [0; 66].to_vec(),
            qy_len: 66,
        };
        let mut priv_key_raw: [u8; 66] = [0; 66];
        let mut priv_key_raw_len: word32 = priv_key_raw.len() as word32;

        // We initiliaze the key pair.
        key_object.init();

        // We initiliaze the rng object.
        rng_object.init();

        let key_size = unsafe { wc_ecc_get_curve_size_from_id(ecc_curve_id_ECC_SECP521R1) };

        ret = unsafe {
            wc_ecc_make_key_ex(
                &mut rng,
                key_size,
                key_object.as_ptr(),
                ecc_curve_id_ECC_SECP521R1,
            )
        };
        check_if_zero(ret).unwrap();

        ret = unsafe {
            wc_ecc_export_private_only(
                key_object.as_ptr(),
                priv_key_raw.as_mut_ptr(),
                &mut priv_key_raw_len,
            )
        };
        check_if_zero(ret).unwrap();

        ret = unsafe {
            wc_ecc_export_public_raw(
                key_object.as_ptr(),
                pub_key_raw.qx.as_mut_ptr(),
                &mut pub_key_raw.qx_len,
                pub_key_raw.qy.as_mut_ptr(),
                &mut pub_key_raw.qy_len,
            )
        };
        check_if_zero(ret).unwrap();

        let mut pub_key_bytes = Vec::new();

        pub_key_bytes.push(0x04);
        pub_key_bytes.extend(pub_key_raw.qx.clone());
        pub_key_bytes.extend(pub_key_raw.qy.clone());
        pub_key_bytes.as_slice();

        KeyExchangeSecP521r1 {
            priv_key_bytes: priv_key_raw.to_vec(),
            pub_key_bytes: pub_key_bytes.to_vec(),
        }
    }

    pub fn derive_shared_secret(&self, peer_pub_key: Vec<u8>) -> Vec<u8> {
        let mut priv_key: ecc_key = unsafe { mem::zeroed() };
        let priv_key_object: ECCKeyObject = ECCKeyObject::new(&mut priv_key);
        let mut pub_key: ecc_key = unsafe { mem::zeroed() };
        let pub_key_object: ECCKeyObject = ECCKeyObject::new(&mut pub_key);
        let mut ret;
        let mut out: [u8; 66] = [0; 66];
        let mut out_len: word32 = out.len() as word32;
        let mut rng: WC_RNG = unsafe { mem::zeroed() };
        let rng_object: WCRngObject = WCRngObject::new(&mut rng);

        priv_key_object.init();

        pub_key_object.init();

        ret = unsafe {
            wc_ecc_import_private_key_ex(
                self.priv_key_bytes.as_ptr(),
                self.priv_key_bytes.len() as word32,
                std::ptr::null_mut(),
                0,
                priv_key_object.as_ptr(),
                ecc_curve_id_ECC_SECP521R1,
            )
        };
        check_if_zero(ret).unwrap();

        /*
         * Skipping first byte because rustls uses this format:
         * https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8.2.
         * */
        ret = unsafe {
            wc_ecc_import_unsigned(
                pub_key_object.as_ptr(),
                peer_pub_key[1..67].as_ptr(),
                peer_pub_key[67..].as_ptr(),
                std::ptr::null_mut(),
                ecc_curve_id_ECC_SECP521R1,
            )
        };
        check_if_zero(ret).unwrap();

        rng_object.init();

        ret = unsafe { wc_ecc_set_rng(pub_key_object.as_ptr(), rng_object.as_ptr()) };
        check_if_zero(ret).unwrap();

        ret = unsafe { wc_ecc_set_rng(priv_key_object.as_ptr(), rng_object.as_ptr()) };
        check_if_zero(ret).unwrap();

        ret = unsafe {
            wc_ecc_shared_secret(
                priv_key_object.as_ptr(),
                pub_key_object.as_ptr(),
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        check_if_zero(ret).unwrap();

        out.to_vec()
    }
}

impl rustls::crypto::ActiveKeyExchange for KeyExchangeSecP521r1 {
    fn complete(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<rustls::crypto::SharedSecret, rustls::Error> {
        // We derive the shared secret with our private key and
        // the received public key.
        let secret = self.derive_shared_secret(peer_pub_key.to_vec());

        Ok(rustls::crypto::SharedSecret::from(secret.as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key_bytes.as_slice()
    }

    fn group(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::secp521r1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::ActiveKeyExchange;

    #[test]
    fn test_secp521r1_kx() {
        let alice = Box::new(KeyExchangeSecP521r1::use_secp521r1());
        let bob = Box::new(KeyExchangeSecP521r1::use_secp521r1());

        assert_eq!(
            alice.derive_shared_secret(bob.pub_key().try_into().unwrap()),
            bob.derive_shared_secret(alice.pub_key().try_into().unwrap()),
        )
    }
}
