use crate::error::*;
use crate::types::types::*;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use foreign_types::ForeignType;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};
use std::mem;
use wolfcrypt_rs::*;

#[derive(Clone, Debug)]
pub struct RsaPssSha256Sign {
    key: Arc<RsaKeyObject>,
    scheme: SignatureScheme,
}

impl RsaPssSha256Sign {
    pub fn get_key(&self) -> Arc<RsaKeyObject> {
        Arc::clone(&self.key)
    }
}

impl TryFrom<&PrivateKeyDer<'_>> for RsaPssSha256Sign {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs8(der) => {
                env_logger::init();
                log::error!("HGA9U0OHGOUAHGOUA");
                let mut rsa_key_c_type: RsaKey = unsafe { mem::zeroed() };
                let rsa_key_object = unsafe { RsaKeyObject::from_ptr(&mut rsa_key_c_type) };
                let pkcs8: &[u8] = der.secret_pkcs8_der();
                let pkcs8_sz: word32 = pkcs8.len() as word32;
                let mut ret;

                ret = unsafe { wc_InitRsaKey(rsa_key_object.as_ptr(), std::ptr::null_mut()) };
                check_if_zero(ret).unwrap();

                let mut idx: u32 = 0;

                // This function finds the beginning of the traditional
                // private key inside a PKCS#8 unencrypted buffer.
                ret = unsafe {
                    wc_GetPkcs8TraditionalOffset(pkcs8.as_ptr() as *mut u8, &mut idx, pkcs8_sz)
                };
                check_if_zero(ret).unwrap();

                ret = unsafe {
                    wc_RsaPrivateKeyDecode(
                        pkcs8.as_ptr() as *mut u8,
                        &mut idx,
                        rsa_key_object.as_ptr(),
                        pkcs8_sz,
                    )
                };
                check_if_zero(ret).unwrap();

                Ok(Self {
                    key: Arc::new(rsa_key_object),
                    scheme: SignatureScheme::RSA_PSS_SHA256,
                })
            }
            _ => panic!("unsupported private key format"),
        }
    }
}

impl SigningKey for RsaPssSha256Sign {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(self.clone()))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

impl Signer for RsaPssSha256Sign {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut rng: WC_RNG = unsafe { mem::zeroed() };
        let rng_object: WCRngObject = WCRngObject::new(&mut rng);
        let mut sig: [u8; 265] = [0; 265];
        let rsa_key_arc = self.get_key();
        let rsa_key_object = rsa_key_arc.as_ref();

        rng_object.init();

        // This function signs a message digest
        // using an RsaKey object to guarantee authenticity.
        // Note, it also takes care of the hashing (Sha256 in this case).
        let ret = unsafe {
            wc_RsaPSS_Sign(
                message.as_ptr(),
                (message.len() + 1) as word32,
                sig.as_mut_ptr(),
                sig.len() as word32,
                wc_HashType_WC_HASH_TYPE_SHA256,
                WC_MGF1SHA256.try_into().unwrap(),
                rsa_key_object.as_ptr(),
                rng_object.as_ptr(),
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
pub struct RsaPssSha384Sign {
    key: Arc<RsaKeyObject>,
    scheme: SignatureScheme,
}

impl RsaPssSha384Sign {
    pub fn get_key(&self) -> Arc<RsaKeyObject> {
        Arc::clone(&self.key)
    }
}

impl TryFrom<&PrivateKeyDer<'_>> for RsaPssSha384Sign {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs8(der) => {
                let mut rsa_key_c_type: RsaKey = unsafe { mem::zeroed() };
                let rsa_key_object = unsafe { RsaKeyObject::from_ptr(&mut rsa_key_c_type) };
                let pkcs8: &[u8] = der.secret_pkcs8_der();
                let pkcs8_sz: word32 = pkcs8.len() as word32;
                let mut ret;

                ret = unsafe { wc_InitRsaKey(rsa_key_object.as_ptr(), std::ptr::null_mut()) };
                check_if_zero(ret).unwrap();

                let mut idx: u32 = 0;

                // This function finds the beginning of the traditional
                // private key inside a PKCS#8 unencrypted buffer.
                ret = unsafe {
                    wc_GetPkcs8TraditionalOffset(pkcs8.as_ptr() as *mut u8, &mut idx, pkcs8_sz)
                };
                check_if_zero(ret).unwrap();

                ret = unsafe {
                    wc_RsaPrivateKeyDecode(
                        pkcs8.as_ptr() as *mut u8,
                        &mut idx,
                        rsa_key_object.as_ptr(),
                        pkcs8_sz,
                    )
                };
                check_if_zero(ret).unwrap();

                Ok(Self {
                    key: Arc::new(rsa_key_object),
                    scheme: SignatureScheme::RSA_PSS_SHA384,
                })
            }
            _ => panic!("unsupported private key format"),
        }
    }
}

impl SigningKey for RsaPssSha384Sign {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(self.clone()))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

impl Signer for RsaPssSha384Sign {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut rng: WC_RNG = unsafe { mem::zeroed() };
        let rng_object: WCRngObject = WCRngObject::new(&mut rng);
        let mut sig: [u8; 265] = [0; 265];
        let rsa_key_arc = self.get_key();
        let rsa_key_object = rsa_key_arc.as_ref();

        rng_object.init();

        // This function signs a message digest
        // using an RsaKey object to guarantee authenticity.
        // Note, it also takes care of the hashing (Sha384 in this case).
        let ret = unsafe {
            wc_RsaPSS_Sign(
                message.as_ptr(),
                (message.len() + 1) as word32,
                sig.as_mut_ptr(),
                sig.len() as word32,
                wc_HashType_WC_HASH_TYPE_SHA384,
                WC_MGF1SHA384.try_into().unwrap(),
                rsa_key_object.as_ptr(),
                rng_object.as_ptr(),
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
pub struct RsaPssSha512Sign {
    key: Arc<RsaKeyObject>,
    scheme: SignatureScheme,
}

impl RsaPssSha512Sign {
    pub fn get_key(&self) -> Arc<RsaKeyObject> {
        Arc::clone(&self.key)
    }
}

impl TryFrom<&PrivateKeyDer<'_>> for RsaPssSha512Sign {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs8(der) => {
                let mut rsa_key_c_type: RsaKey = unsafe { mem::zeroed() };
                let rsa_key_object = unsafe { RsaKeyObject::from_ptr(&mut rsa_key_c_type) };
                let pkcs8: &[u8] = der.secret_pkcs8_der();
                let pkcs8_sz: word32 = pkcs8.len() as word32;
                let mut ret;

                ret = unsafe { wc_InitRsaKey(rsa_key_object.as_ptr(), std::ptr::null_mut()) };
                check_if_zero(ret).unwrap();

                let mut idx: u32 = 0;

                // This function finds the beginning of the traditional
                // private key inside a PKCS#8 unencrypted buffer.
                ret = unsafe {
                    wc_GetPkcs8TraditionalOffset(pkcs8.as_ptr() as *mut u8, &mut idx, pkcs8_sz)
                };
                check_if_zero(ret).unwrap();

                ret = unsafe {
                    wc_RsaPrivateKeyDecode(
                        pkcs8.as_ptr() as *mut u8,
                        &mut idx,
                        rsa_key_object.as_ptr(),
                        pkcs8_sz,
                    )
                };
                check_if_zero(ret).unwrap();

                Ok(Self {
                    key: Arc::new(rsa_key_object),
                    scheme: SignatureScheme::RSA_PSS_SHA512,
                })
            }
            _ => panic!("unsupported private key format"),
        }
    }
}

impl SigningKey for RsaPssSha512Sign {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(self.clone()))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

impl Signer for RsaPssSha512Sign {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut rng: WC_RNG = unsafe { mem::zeroed() };
        let rng_object: WCRngObject = WCRngObject::new(&mut rng);
        let mut sig: [u8; 265] = [0; 265];
        let rsa_key_arc = self.get_key();
        let rsa_key_object = rsa_key_arc.as_ref();

        rng_object.init();

        // This function signs a message digest
        // using an RsaKey object to guarantee authenticity.
        // Note, it also takes care of the hashing (Sha512 in this case).
        let ret = unsafe {
            wc_RsaPSS_Sign(
                message.as_ptr(),
                (message.len() + 1) as word32,
                sig.as_mut_ptr(),
                sig.len() as word32,
                wc_HashType_WC_HASH_TYPE_SHA512,
                WC_MGF1SHA512.try_into().unwrap(),
                rsa_key_object.as_ptr(),
                rng_object.as_ptr(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer() {
        let mut rsa_key_c_type: RsaKey = unsafe { mem::zeroed() };
        let rsa_key_object = unsafe { RsaKeyObject::from_ptr(&mut rsa_key_c_type) };
        let mut ret;
        let message = "This is the string to be signed".as_bytes();
        let mut signature: [u8; 256] = [0; 256];
        let mut final_output: [u8; 64] = [0; 64];
        let sz;

        ret = unsafe { wc_InitRsaKey(rsa_key_object.as_ptr(), std::ptr::null_mut()) };
        check_if_zero(ret).unwrap();

        let mut rng_c_type: WC_RNG = unsafe { mem::zeroed() };
        let rng_object = WCRngObject::new(&mut rng_c_type);
        rng_object.init();

        unsafe { wc_RsaSetRNG(rsa_key_object.as_ptr(), rng_object.as_ptr()) };

        ret = unsafe {
            wc_MakeRsaKey(
                rsa_key_object.as_ptr(),
                2048,
                WC_RSA_EXPONENT.into(),
                rng_object.as_ptr(),
            )
        };
        check_if_zero(ret).unwrap();

        ret = unsafe {
            wc_RsaPSS_Sign(
                message.as_ptr(),
                (message.len() + 1) as word32,
                signature.as_mut_ptr(),
                signature.len() as word32,
                wc_HashType_WC_HASH_TYPE_SHA256,
                WC_MGF1SHA256.try_into().unwrap(),
                rsa_key_object.as_ptr(),
                rng_object.as_ptr(),
            )
        };
        check_if_greater_than_zero(ret).unwrap();

        sz = ret;

        ret = unsafe {
            wc_RsaPSS_Verify(
                signature.as_mut_ptr(),
                sz as word32,
                final_output.as_mut_ptr(),
                final_output.len() as word32,
                wc_HashType_WC_HASH_TYPE_SHA256,
                WC_MGF1SHA256.try_into().unwrap(),
                rsa_key_object.as_ptr(),
            )
        };

        assert!(ret > 0);
    }
}
