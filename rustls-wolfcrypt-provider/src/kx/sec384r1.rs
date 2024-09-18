use std::mem;
use wolfcrypt_rs::*;
use foreign_types::{ForeignType};
use crate::types::types::*;

pub struct KeyExchangeSecP384r1 {
    pub priv_key_bytes: Vec<u8>,
    pub pub_key_bytes: Vec<u8>,
}

pub struct ECCPubKey {
    qx: Vec<u8>,
    qx_len: word32,
    qy: Vec<u8>,
    qy_len: word32
}

impl KeyExchangeSecP384r1 {
    pub fn use_secp384r1() -> Self {
        unsafe {
            let mut key: ecc_key = mem::zeroed();
            let key_object = ECCKeyObject::from_ptr(&mut key);
            let mut rng: WC_RNG = mem::zeroed();
            let mut ret;
            let mut pub_key_raw = ECCPubKey {
                qx: [0; 48].to_vec(),
                qx_len: 48,
                qy: [0; 48].to_vec(),
                qy_len: 48,
            };
            let mut priv_key_raw: [u8; 48] = [0; 48];
            let mut priv_key_raw_len: word32 = priv_key_raw.len() as word32;

            ret = wc_ecc_init(key_object.as_ptr());
            if ret != 0 {
                panic!("failed while calling wc_ecc_init, ret = {}", ret);
            }

            ret = wc_InitRng(&mut rng);
            if ret != 0 {
                panic!("failed while calling wc_InitRng, ret = {}", ret);
            }

            let key_size = wc_ecc_get_curve_size_from_id(ecc_curve_id_ECC_SECP384R1);

            ret = wc_ecc_make_key_ex(
                &mut rng, 
                key_size, 
                key_object.as_ptr(),
                ecc_curve_id_ECC_SECP384R1
            );
            if ret != 0 {
                panic!("failed while calling wc_ecc_make_key, ret = {}", ret);
            }

            ret = wc_ecc_export_private_only(
                key_object.as_ptr(), 
                priv_key_raw.as_mut_ptr(), 
                &mut priv_key_raw_len
            );
            if ret != 0 {
                panic!("failed while calling wc_ecc_export_private_only, ret = {}", ret);
            }

            ret = wc_ecc_export_public_raw(
                key_object.as_ptr(),
                pub_key_raw.qx.as_mut_ptr(),
                &mut pub_key_raw.qx_len,
                pub_key_raw.qy.as_mut_ptr(),
                &mut pub_key_raw.qy_len,
            );
            if ret != 0 {
                panic!("failed while calling wc_ecc_export_public_raw, ret = {}", ret);
            }

            let mut pub_key_bytes = Vec::new();

            pub_key_bytes.push(0x04);
            pub_key_bytes.extend(pub_key_raw.qx.clone());
            pub_key_bytes.extend(pub_key_raw.qy.clone());
            pub_key_bytes.as_slice();

            KeyExchangeSecP384r1 {
                priv_key_bytes: priv_key_raw.to_vec(),
                pub_key_bytes: pub_key_bytes.to_vec()
            }
        }
    }

    pub fn derive_shared_secret(&self, peer_pub_key: Vec<u8>) -> Vec<u8> {
        unsafe {
            let mut priv_key: ecc_key = mem::zeroed();
            let mut pub_key: ecc_key = mem::zeroed();
            let mut ret;
            let mut out: [u8; 48] = [0; 48];
            let mut out_len: word32 = out.len() as word32;
            let mut rng: WC_RNG = mem::zeroed();

            ret = wc_ecc_init(&mut priv_key);
            if ret != 0 {
                panic!("failed while calling wc_ecc_init, ret = {}", ret);
            }

            ret = wc_ecc_init(&mut pub_key);
            if ret != 0 {
                panic!("failed while calling wc_ecc_init, ret = {}", ret);
            }

            ret = wc_ecc_import_private_key_ex(
                self.priv_key_bytes.as_ptr(), 
                self.priv_key_bytes.len() as word32, 
                std::ptr::null_mut(), 
                0,   
                &mut priv_key,
                ecc_curve_id_ECC_SECP384R1
            );
            if ret != 0 {
                panic!("failed while calling wc_ecc_import_private_key_ex, with ret value: {}", ret);
            }

            /* 
             * Skipping first byte because rustls uses this format:
             * https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8.2.
             * */
            ret = wc_ecc_import_unsigned(
                &mut pub_key,
                peer_pub_key[1..49].as_ptr(),             
                peer_pub_key[49..].as_ptr(),             
                std::ptr::null_mut(),                 
                ecc_curve_id_ECC_SECP384R1
            );
            if ret != 0 {
                panic!("failed while calling wc_ecc_import_unsigned, with ret value: {}", ret);
            }

            ret = wc_InitRng(&mut rng);
            if ret != 0 {
                panic!("failed while calling wc_InitRng, ret = {}", ret);
            }

            ret = wc_ecc_set_rng(
                    &mut pub_key, 
                    &mut rng
            );
             if ret != 0 {
                panic!("failed while calling wc_ecc_set_rng, ret = {}", ret);
            }

            ret = wc_ecc_set_rng(
                    &mut priv_key, 
                    &mut rng
            );
            if ret != 0 {
                panic!("failed while calling wc_ecc_set_rng, ret = {}", ret);
            }

            ret = wc_ecc_shared_secret(
                &mut priv_key, 
                &mut pub_key, 
                out.as_mut_ptr(), 
                &mut out_len
            );
            if ret != 0 {
                panic!("failed while calling wc_ecc_shared_secret, with ret value: {}", ret);
            }

            out.to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::ActiveKeyExchange;

    #[test]
    fn test_secp384r1_kx() {
        let alice = Box::new(KeyExchangeSecP384r1::use_secp384r1());
        let bob = Box::new(KeyExchangeSecP384r1::use_secp384r1());

        assert_eq!(
            alice.derive_shared_secret(bob.pub_key().try_into().unwrap()),
            bob.derive_shared_secret(alice.pub_key().try_into().unwrap()),
        )
    }
}
