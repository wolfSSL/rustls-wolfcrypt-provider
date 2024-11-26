use crate::error::*;
use crate::types::types::*;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::mem;
use core::ptr;
use foreign_types::ForeignType;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};
use wolfcrypt_rs::*;

#[derive(Clone, Debug)]
pub struct RsaPkcs1Sha256 {
    key: Arc<RsaKeyObject>,
    scheme: SignatureScheme,
}

impl RsaPkcs1Sha256 {
    pub fn get_key(&self) -> Arc<RsaKeyObject> {
        Arc::clone(&self.key)
    }
}

impl TryFrom<&PrivateKeyDer<'_>> for RsaPkcs1Sha256 {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs1(der) => {
                let mut rsa_key_c_type: RsaKey = unsafe { mem::zeroed() };
                let rsa_key_object = unsafe { RsaKeyObject::from_ptr(&mut rsa_key_c_type) };
                let pkcs1: &[u8] = der.secret_pkcs1_der();
                let pkcs1_sz: word32 = pkcs1.len() as word32;
                let mut ret;

                ret = unsafe { wc_InitRsaKey(rsa_key_object.as_ptr(), ptr::null_mut()) };
                check_if_zero(ret).unwrap();

                let mut idx: u32 = 0;

                ret = unsafe {
                    wc_RsaPrivateKeyDecode(
                        pkcs1.as_ptr() as *mut u8,
                        &mut idx,
                        rsa_key_object.as_ptr(),
                        pkcs1_sz,
                    )
                };
                check_if_zero(ret).map_err(|_| rustls::Error::General("FFI function failed".into()))?;

                Ok(Self {
                    key: Arc::new(rsa_key_object),
                    scheme: SignatureScheme::RSA_PKCS1_SHA256,
                })
            }
            _ => return Err(rustls::Error::General("Unsupported private key format".into())),
        }
    }
}

impl SigningKey for RsaPkcs1Sha256 {
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

impl Signer for RsaPkcs1Sha256 {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut rng: WC_RNG = unsafe { mem::zeroed() };
        let rng_object: WCRngObject = WCRngObject::new(&mut rng);
        let mut sig: [u8; 265] = [0; 265];
        let mut sig_len: word32 = sig.len() as word32;
        let rsa_key_arc = self.get_key();
        let rsa_key_object = rsa_key_arc.as_ref();

        rng_object.init();

        // This function signs a message digest
        // using an RsaKey object to guarantee authenticity.
        // Note, it also takes care of the hashing (Sha256 in this case).
        let ret = unsafe {
            wc_SignatureGenerate(
                wc_HashType_WC_HASH_TYPE_SHA256,
                wc_SignatureType_WC_SIGNATURE_TYPE_RSA_W_ENC,
                message.as_ptr(),
                message.len() as word32,
                sig.as_mut_ptr(),
                &mut sig_len,
                rsa_key_object.as_ptr() as *const c_void,
                mem::size_of_val(&rsa_key_object.as_ptr())
                    .try_into()
                    .unwrap(),
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
pub struct RsaPkcs1Sha384 {
    key: Arc<RsaKeyObject>,
    scheme: SignatureScheme,
}

impl RsaPkcs1Sha384 {
    pub fn get_key(&self) -> Arc<RsaKeyObject> {
        Arc::clone(&self.key)
    }
}

impl TryFrom<&PrivateKeyDer<'_>> for RsaPkcs1Sha384 {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs1(der) => {
                let mut rsa_key_c_type: RsaKey = unsafe { mem::zeroed() };
                let rsa_key_object = unsafe { RsaKeyObject::from_ptr(&mut rsa_key_c_type) };
                let pkcs1: &[u8] = der.secret_pkcs1_der();
                let pkcs1_sz: word32 = pkcs1.len() as word32;
                let mut ret;

                ret = unsafe { wc_InitRsaKey(rsa_key_object.as_ptr(), ptr::null_mut()) };
                check_if_zero(ret).unwrap();

                let mut idx: u32 = 0;

                ret = unsafe {
                    wc_RsaPrivateKeyDecode(
                        pkcs1.as_ptr() as *mut u8,
                        &mut idx,
                        rsa_key_object.as_ptr(),
                        pkcs1_sz,
                    )
                };
                check_if_zero(ret).map_err(|_| rustls::Error::General("FFI function failed".into()))?;

                Ok(Self {
                    key: Arc::new(rsa_key_object),
                    scheme: SignatureScheme::RSA_PKCS1_SHA384,
                })
            }
            _ => return Err(rustls::Error::General("Unsupported private key format".into())),
        }
    }
}

impl SigningKey for RsaPkcs1Sha384 {
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

impl Signer for RsaPkcs1Sha384 {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut rng: WC_RNG = unsafe { mem::zeroed() };
        let rng_object: WCRngObject = WCRngObject::new(&mut rng);
        let mut sig: [u8; 265] = [0; 265];
        let mut sig_len: word32 = sig.len() as word32;
        let rsa_key_arc = self.get_key();
        let rsa_key_object = rsa_key_arc.as_ref();

        rng_object.init();

        // This function signs a message digest
        // using an RsaKey object to guarantee authenticity.
        // Note, it also takes care of the hashing (Sha384 in this case).
        let ret = unsafe {
            wc_SignatureGenerate(
                wc_HashType_WC_HASH_TYPE_SHA384,
                wc_SignatureType_WC_SIGNATURE_TYPE_RSA_W_ENC,
                message.as_ptr(),
                message.len() as word32,
                sig.as_mut_ptr(),
                &mut sig_len,
                rsa_key_object.as_ptr() as *const c_void,
                mem::size_of_val(&rsa_key_object.as_ptr())
                    .try_into()
                    .unwrap(),
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
pub struct RsaPkcs1Sha512 {
    key: Arc<RsaKeyObject>,
    scheme: SignatureScheme,
}

impl RsaPkcs1Sha512 {
    pub fn get_key(&self) -> Arc<RsaKeyObject> {
        Arc::clone(&self.key)
    }
}

impl TryFrom<&PrivateKeyDer<'_>> for RsaPkcs1Sha512 {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs1(der) => {
                let mut rsa_key_c_type: RsaKey = unsafe { mem::zeroed() };
                let rsa_key_object = unsafe { RsaKeyObject::from_ptr(&mut rsa_key_c_type) };
                let pkcs1: &[u8] = der.secret_pkcs1_der();
                let pkcs1_sz: word32 = pkcs1.len() as word32;
                let mut ret;

                ret = unsafe { wc_InitRsaKey(rsa_key_object.as_ptr(), ptr::null_mut()) };
                check_if_zero(ret).unwrap();

                let mut idx: u32 = 0;

                ret = unsafe {
                    wc_RsaPrivateKeyDecode(
                        pkcs1.as_ptr() as *mut u8,
                        &mut idx,
                        rsa_key_object.as_ptr(),
                        pkcs1_sz,
                    )
                };
                check_if_zero(ret).map_err(|_| rustls::Error::General("FFI function failed".into()))?;

                Ok(Self {
                    key: Arc::new(rsa_key_object),
                    scheme: SignatureScheme::RSA_PKCS1_SHA512,
                })
            }
            _ => return Err(rustls::Error::General("Unsupported private key format".into())),
        }
    }
}

impl SigningKey for RsaPkcs1Sha512 {
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

impl Signer for RsaPkcs1Sha512 {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut rng: WC_RNG = unsafe { mem::zeroed() };
        let rng_object: WCRngObject = WCRngObject::new(&mut rng);
        let mut sig: [u8; 265] = [0; 265];
        let mut sig_len: word32 = sig.len() as word32;
        let rsa_key_arc = self.get_key();
        let rsa_key_object = rsa_key_arc.as_ref();

        rng_object.init();

        // This function signs a message digest
        // using an RsaKey object to guarantee authenticity.
        // Note, it also takes care of the hashing (Sha512 in this case).
        let ret = unsafe {
            wc_SignatureGenerate(
                wc_HashType_WC_HASH_TYPE_SHA512,
                wc_SignatureType_WC_SIGNATURE_TYPE_RSA_W_ENC,
                message.as_ptr(),
                message.len() as word32,
                sig.as_mut_ptr(),
                &mut sig_len,
                rsa_key_object.as_ptr() as *const c_void,
                mem::size_of_val(&rsa_key_object.as_ptr())
                    .try_into()
                    .unwrap(),
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
