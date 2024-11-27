use crate::error::*;
use crate::types::types::*;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem;
use foreign_types::ForeignType;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};

use wolfcrypt_rs::*;

#[derive(Clone, Debug)]
pub struct Ed25519SigningKeySign {
    key: Arc<ED25519KeyObject>,
    scheme: SignatureScheme,
}

impl Ed25519SigningKeySign {
    pub fn get_key(&self) -> Arc<ED25519KeyObject> {
        Arc::clone(&self.key)
    }
}

impl TryFrom<&PrivateKeyDer<'_>> for Ed25519SigningKeySign {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs8(der) => {
                let mut ed25519_c_type: ed25519_key = unsafe { mem::zeroed() };
                let ed25519_key_object = ED25519KeyObject::new(&mut ed25519_c_type);
                let pkcs8: &[u8] = der.secret_pkcs8_der();
                let pkcs8_sz: word32 = pkcs8.len() as word32;
                let mut ret;

                // This function initiliazes an ed25519_key object for
                // using it to sign a message.
                ed25519_key_object.init();

                let mut idx: u32 = 0;

                // This function finds the beginning of the traditional
                // private key inside a PKCS#8 unencrypted buffer.
                ret = unsafe {
                    wc_GetPkcs8TraditionalOffset(pkcs8.as_ptr() as *mut u8, &mut idx, pkcs8_sz)
                };
                check_if_greater_than_zero(ret)
                    .map_err(|_| rustls::Error::General("FFI function failed".into()))?;

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

                Ok(Self {
                    key: Arc::new(ed25519_key_object),
                    scheme: SignatureScheme::ED25519,
                })
            }
            _ => {
                return Err(rustls::Error::General(
                    "Unsupported private key format".into(),
                ))
            }
        }
    }
}

impl SigningKey for Ed25519SigningKeySign {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(self.clone()))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

impl Signer for Ed25519SigningKeySign {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let ret;
        let message_length: word32 = message.len() as word32;
        let mut sig: [u8; 1024] = [0; 1024];
        let mut sig_sz: word32 = sig.len() as word32;
        let ed25519_key_arc = self.get_key();
        let ed25519_key_object = ed25519_key_arc.as_ref();

        // This function signs a message digest
        // using an ecc_key object to guarantee authenticity.
        ret = unsafe {
            wc_ed25519_sign_msg(
                message.as_ptr(),
                message_length,
                sig.as_mut_ptr(),
                &mut sig_sz,
                ed25519_key_object.as_ptr(),
            )
        };
        check_if_zero(ret).unwrap();

        let sig_vec = sig.to_vec();

        Ok(sig_vec)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

#[derive(Clone, Debug)]
pub struct Ed448SigningKeySign {
    key: Arc<ED448KeyObject>,
    scheme: SignatureScheme,
}

impl Ed448SigningKeySign {
    pub fn get_key(&self) -> Arc<ED448KeyObject> {
        Arc::clone(&self.key)
    }
}

impl TryFrom<&PrivateKeyDer<'_>> for Ed448SigningKeySign {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs8(der) => {
                let mut ed448_c_type: ed448_key = unsafe { mem::zeroed() };
                let ed448_key_object = ED448KeyObject::new(&mut ed448_c_type);
                let pkcs8: &[u8] = der.secret_pkcs8_der();
                let pkcs8_sz: word32 = pkcs8.len() as word32;
                let mut ret;

                // This function initiliazes an ed448_key object for
                // using it to sign a message.
                ed448_key_object.init();

                let mut idx: u32 = 0;

                // This function finds the beginning of the traditional
                // private key inside a PKCS#8 unencrypted buffer.
                ret = unsafe {
                    wc_GetPkcs8TraditionalOffset(pkcs8.as_ptr() as *mut u8, &mut idx, pkcs8_sz)
                };
                check_if_greater_than_zero(ret)
                    .map_err(|_| rustls::Error::General("FFI function failed".into()))?;

                // This function reads in an ED448 private key from the input buffer, input,
                // parses the private key, and uses it to generate an ed448_key object,
                // which it stores in key.
                ret = unsafe {
                    wc_Ed448PrivateKeyDecode(
                        pkcs8.as_ptr() as *mut u8,
                        &mut idx,
                        ed448_key_object.as_ptr(),
                        pkcs8_sz,
                    )
                };
                check_if_zero(ret)
                    .map_err(|_| rustls::Error::General("FFI function failed".into()))?;

                Ok(Self {
                    key: Arc::new(ed448_key_object),
                    scheme: SignatureScheme::ED448,
                })
            }
            _ => {
                return Err(rustls::Error::General(
                    "Unsupported private key format".into(),
                ))
            }
        }
    }
}

impl SigningKey for Ed448SigningKeySign {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(self.clone()))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED448
    }
}

impl Signer for Ed448SigningKeySign {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let ret;
        let message_length: word32 = message.len() as word32;
        let mut sig: [u8; 64] = [0; 64];
        let mut sig_sz: word32 = sig.len() as word32;
        let ed448_key_arc = self.get_key();
        let ed448_key_object = ed448_key_arc.as_ref();

        // This function signs a message digest
        // using an ecc_key object to guarantee authenticity.
        ret = unsafe {
            wc_ed448_sign_msg(
                message.as_ptr(),
                message_length,
                sig.as_mut_ptr(),
                &mut sig_sz,
                ed448_key_object.as_ptr(),
                core::ptr::null_mut(),
                0,
            )
        };
        check_if_zero(ret).unwrap();

        let sig_vec = sig.to_vec();

        Ok(sig_vec)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}
