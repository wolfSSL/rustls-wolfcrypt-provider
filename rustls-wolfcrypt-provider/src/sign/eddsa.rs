use crate::error::*;
use crate::types::*;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem;
use foreign_types::ForeignType;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};

use wolfcrypt_rs::*;

const ALL_EDDSA_SCHEMES: &[SignatureScheme] = &[SignatureScheme::ED25519, SignatureScheme::ED448];

#[derive(Clone, Debug)]
pub struct Ed25519PrivateKey {
    priv_key: Arc<Vec<u8>>,
    pub_key: Arc<Vec<u8>>,
    algo: SignatureAlgorithm,
}

impl TryFrom<&PrivateKeyDer<'_>> for Ed25519PrivateKey {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs8(der) => {
                let mut ed25519_c_type: ed25519_key = unsafe { mem::zeroed() };
                let ed25519_key_object = ED25519KeyObject::new(&mut ed25519_c_type);
                let mut priv_key_raw: [u8; 32] = [0; 32];
                let mut priv_key_raw_len: word32 = priv_key_raw.len() as word32;
                let mut pub_key_raw: [u8; 32] = [0; 32];
                let pub_key_raw_len: word32 = pub_key_raw.len() as word32;
                let pkcs8: &[u8] = der.secret_pkcs8_der();
                let pkcs8_sz: word32 = pkcs8.len() as word32;
                let mut ret;

                // This function initiliazes an ed25519_key object for
                // using it to sign a message.
                ed25519_key_object.init();

                let mut idx: u32 = 0;

                // This function reads in an ED25519 private key from the input buffer, input,
                // parses the private key, and uses it to generate an ed25519_key object,
                // which it stores in key.
                ret = unsafe {
                    wc_Ed25519PrivateKeyDecode(
                        pkcs8.as_ptr() as *mut u8,
                        &mut idx,
                        ed25519_key_object.as_ptr(),
                        pkcs8_sz,
                    )
                };
                check_if_zero(ret)
                    .map_err(|_| rustls::Error::General("FFI function failed".into()))?;

                ret = unsafe {
                    wc_ed25519_make_public(
                        ed25519_key_object.as_ptr(),
                        pub_key_raw.as_mut_ptr(),
                        pub_key_raw_len,
                    )
                };
                check_if_zero(ret)
                    .map_err(|_| rustls::Error::General("FFI function failed".into()))?;

                ret = unsafe {
                    wc_ed25519_export_private_only(
                        ed25519_key_object.as_ptr(),
                        priv_key_raw.as_mut_ptr(),
                        &mut priv_key_raw_len,
                    )
                };
                check_if_zero(ret)
                    .map_err(|_| rustls::Error::General("FFI function failed".into()))?;

                Ok(Self {
                    priv_key: Arc::new(priv_key_raw.to_vec()),
                    pub_key: Arc::new(pub_key_raw.to_vec()),
                    algo: SignatureAlgorithm::ED25519,
                })
            }
            _ => Err(rustls::Error::General(
                "Unsupported private key format".into(),
            )),
        }
    }
}

impl SigningKey for Ed25519PrivateKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        // Iterate through all ECDSA schemes and check if any is in the offered list
        ALL_EDDSA_SCHEMES.iter().find_map(|&scheme| {
            if offered.contains(&scheme) {
                Some(Box::new(Ed25519Signer {
                    priv_key: self.priv_key.clone(),
                    pub_key: self.pub_key.clone(),
                    scheme,
                }) as Box<dyn Signer>)
            } else {
                None
            }
        })
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.algo
    }
}

#[derive(Clone, Debug)]
pub struct Ed25519Signer {
    priv_key: Arc<Vec<u8>>,
    pub_key: Arc<Vec<u8>>,
    scheme: SignatureScheme,
}

impl Signer for Ed25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut ret;
        let message_length: word32 = message.len() as word32;
        let mut sig: [u8; ED25519_SIG_SIZE as usize] = [0; ED25519_SIG_SIZE as usize];
        let mut sig_sz: word32 = sig.len() as word32;
        let priv_key_raw = &self.priv_key;
        let pub_key_raw = &self.pub_key;
        let mut ed25519_c_type: ed25519_key = unsafe { mem::zeroed() };
        let ed25519_key_object = ED25519KeyObject::new(&mut ed25519_c_type);

        ed25519_key_object.init();

        ret = unsafe {
            wc_ed25519_import_private_key(
                priv_key_raw.as_ptr(),
                priv_key_raw.len() as word32,
                pub_key_raw.as_ptr(),
                pub_key_raw.len() as word32,
                ed25519_key_object.as_ptr(),
            )
        };
        check_if_zero(ret).unwrap();

        ret = unsafe {
            wc_ed25519_sign_msg(
                message.as_ptr(),
                message_length,
                sig.as_mut_ptr(),
                &mut sig_sz,
                ed25519_key_object.as_ptr(),
            )
        };
        if ret < 0 {
            panic!("{}", ret);
        }

        let mut sig_vec = sig.to_vec();

        sig_vec.truncate(sig_sz as usize);

        Ok(sig_vec)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}
