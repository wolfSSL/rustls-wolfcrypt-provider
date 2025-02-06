use crate::{error::check_if_zero, types::*};
use alloc::boxed::Box;
use core::mem;
use core::ptr;
use foreign_types::ForeignType;
use wolfcrypt_rs::*;

pub struct KeyExchangeSecP256r1 {
    priv_key_bytes: Box<[u8]>,
    pub_key_bytes: Box<[u8]>,
}

pub struct ECCPubKey {
    qx: [u8; 32],
    qx_len: word32,
    qy: [u8; 32],
    qy_len: word32,
}

impl KeyExchangeSecP256r1 {
    pub fn use_secp256r1() -> Self {
        let mut key: ecc_key = unsafe { mem::zeroed() };
        let key_object = ECCKeyObject::new(&mut key);
        let mut rng: WC_RNG = unsafe { mem::zeroed() };
        let rng_object: WCRngObject = WCRngObject::new(&mut rng);
        let mut ret;
        let mut pub_key_raw = ECCPubKey {
            qx: [0; 32],
            qx_len: 32,
            qy: [0; 32],
            qy_len: 32,
        };

        key_object.init();
        rng_object.init();

        let key_size = unsafe { wc_ecc_get_curve_size_from_id(ecc_curve_id_ECC_SECP256R1) };

        let mut priv_key_raw = [0u8; 32];
        let mut priv_key_raw_len: word32 = priv_key_raw.len() as word32;

        ret = unsafe {
            wc_ecc_make_key_ex(
                rng_object.as_ptr(),
                key_size,
                key_object.as_ptr(),
                ecc_curve_id_ECC_SECP256R1,
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
        // One byte prefix (0x04) + 32 bytes X coord + 32 bytes Y coord
        let mut pub_key_bytes = [0x04; 65];

        // Copy X coordinate into bytes 1-32
        pub_key_bytes[1..33].copy_from_slice(&pub_key_raw.qx);

        // Copy Y coordinate into bytes 33-64
        pub_key_bytes[33..65].copy_from_slice(&pub_key_raw.qy);

        KeyExchangeSecP256r1 {
            priv_key_bytes: Box::new(priv_key_raw),
            pub_key_bytes: Box::new(pub_key_bytes),
        }
    }

    pub fn derive_shared_secret(&self, peer_pub_key: &[u8]) -> Box<[u8]> {
        let mut priv_key: ecc_key = unsafe { mem::zeroed() };
        let priv_key_object = ECCKeyObject::new(&mut priv_key);
        let mut pub_key: ecc_key = unsafe { mem::zeroed() };
        let pub_key_object = ECCKeyObject::new(&mut pub_key);
        let mut rng: WC_RNG = unsafe { mem::zeroed() };
        let rng_object = WCRngObject::new(&mut rng);
        let mut ret: i32;

        priv_key_object.init();
        pub_key_object.init();

        ret = unsafe {
            wc_ecc_import_private_key_ex(
                self.priv_key_bytes.as_ptr(),
                self.priv_key_bytes.len() as word32,
                ptr::null_mut(),
                0,
                priv_key_object.as_ptr(),
                ecc_curve_id_ECC_SECP256R1,
            )
        };
        check_if_zero(ret).unwrap();

        ret = unsafe {
            wc_ecc_import_unsigned(
                pub_key_object.as_ptr(),
                peer_pub_key[1..33].as_ptr(),
                peer_pub_key[33..].as_ptr(),
                ptr::null_mut(),
                ecc_curve_id_ECC_SECP256R1,
            )
        };
        check_if_zero(ret).unwrap();

        rng_object.init();

        ret = unsafe { wc_ecc_set_rng(pub_key_object.as_ptr(), rng_object.as_ptr()) };
        check_if_zero(ret).unwrap();

        ret = unsafe { wc_ecc_set_rng(priv_key_object.as_ptr(), rng_object.as_ptr()) };
        check_if_zero(ret).unwrap();

        let mut out = [0u8; 32];
        let mut out_len: word32 = out.len() as word32;

        ret = unsafe {
            wc_ecc_shared_secret(
                priv_key_object.as_ptr(),
                pub_key_object.as_ptr(),
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        check_if_zero(ret).unwrap();

        Box::new(out)
    }
}

impl rustls::crypto::ActiveKeyExchange for KeyExchangeSecP256r1 {
    fn complete(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<rustls::crypto::SharedSecret, rustls::Error> {
        let secret = self.derive_shared_secret(peer_pub_key);
        Ok(rustls::crypto::SharedSecret::from(&*secret))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key_bytes
    }

    fn group(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::secp256r1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::ActiveKeyExchange;

    #[test]
    fn test_secp256r1_kx() {
        let alice = Box::new(KeyExchangeSecP256r1::use_secp256r1());
        let bob = Box::new(KeyExchangeSecP256r1::use_secp256r1());

        assert_eq!(
            alice.derive_shared_secret(bob.pub_key()),
            bob.derive_shared_secret(alice.pub_key()),
        )
    }
}
