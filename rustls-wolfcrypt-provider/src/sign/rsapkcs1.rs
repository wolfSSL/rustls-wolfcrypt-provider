use crate::error::*;
use crate::types::*;
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

const ALL_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
];

#[derive(Clone, Debug)]
pub struct RsaPkcs1PrivateKey {
    key: Arc<RsaKeyObject>,
    algo: SignatureAlgorithm,
}

impl RsaPkcs1PrivateKey {
    pub fn get_key(&self) -> Arc<RsaKeyObject> {
        Arc::clone(&self.key)
    }
}

const RSA_PKCS1_SIG_SIZE: u32 = 512;

impl TryFrom<&PrivateKeyDer<'_>> for RsaPkcs1PrivateKey {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs1(der) => {
                let pkcs1: &[u8] = der.secret_pkcs1_der();
                let pkcs1_sz: word32 = pkcs1.len() as word32;
                let mut ret;
                let rsa_key_box = Box::new(unsafe { mem::zeroed::<RsaKey>() });
                let rsa_key_ptr = Box::into_raw(rsa_key_box);
                let rsa_key_object = unsafe { RsaKeyObject::from_ptr(rsa_key_ptr) };

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
                check_if_zero(ret)
                    .map_err(|_| rustls::Error::General("FFI function failed".into()))?;

                Ok(Self {
                    key: Arc::new(rsa_key_object),
                    algo: SignatureAlgorithm::RSA,
                })
            }
            _ => Err(rustls::Error::General(
                "Unsupported private key format".into(),
            )),
        }
    }
}

impl SigningKey for RsaPkcs1PrivateKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        // Iterate through all RSA schemes and check if any is in the offered list
        ALL_RSA_SCHEMES.iter().find_map(|&scheme| {
            if offered.contains(&scheme) {
                Some(Box::new(RsaPkcs1Signer {
                    key: self.get_key(),
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
pub struct RsaPkcs1Signer {
    key: Arc<RsaKeyObject>,
    scheme: SignatureScheme,
}

impl RsaPkcs1Signer {
    pub fn get_key(&self) -> Arc<RsaKeyObject> {
        Arc::clone(&self.key)
    }
}

impl Signer for RsaPkcs1Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut rng: WC_RNG = unsafe { mem::zeroed() };
        let rng_object: WCRngObject = WCRngObject::new(&mut rng);
        let mut sig: [u8; RSA_PKCS1_SIG_SIZE as usize] = [0; RSA_PKCS1_SIG_SIZE as usize];
        let mut sig_len: word32 = sig.len() as word32;
        let rsa_key_arc = self.get_key();
        let rsa_key_object = rsa_key_arc.as_ref();

        // Define Rust-style aliases for binding constants
        const HASH_TYPE_SHA256: u32 = wc_HashType_WC_HASH_TYPE_SHA256;
        const HASH_TYPE_SHA384: u32 = wc_HashType_WC_HASH_TYPE_SHA384;
        const HASH_TYPE_SHA512: u32 = wc_HashType_WC_HASH_TYPE_SHA512;

        // Determine the hashing algorithm, digest size, and MGF type based on the scheme
        let hash_type: u32 = match self.scheme {
            SignatureScheme::RSA_PKCS1_SHA256 => HASH_TYPE_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384 => HASH_TYPE_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512 => HASH_TYPE_SHA512,
            _ => {
                return Err(rustls::Error::General(
                    "Unsupported signature scheme".into(),
                ));
            }
        };

        rng_object.init();

        let derefenced_rsa_key_c_type = unsafe { *(rsa_key_object.as_ptr()) };

        // Sign the digest using the appropriate scheme
        let ret = unsafe {
            wc_SignatureGenerate(
                hash_type,
                wc_SignatureType_WC_SIGNATURE_TYPE_RSA_W_ENC,
                message.as_ptr(),
                message.len() as word32,
                sig.as_mut_ptr(),
                &mut sig_len,
                rsa_key_object.as_ptr() as *const c_void,
                mem::size_of_val(&derefenced_rsa_key_c_type)
                    .try_into()
                    .unwrap(),
                rng_object.as_ptr(),
            )
        };
        check_if_zero(ret).map_err(|_| rustls::Error::General("FFI function failed".into()))?;

        let sz = unsafe {
            wc_SignatureGetSize(
                wc_SignatureType_WC_SIGNATURE_TYPE_RSA_W_ENC,
                rsa_key_object.as_ptr() as *const c_void,
                mem::size_of_val(&derefenced_rsa_key_c_type)
                    .try_into()
                    .unwrap(),
            )
        };

        // Convert the signature to a Vec and truncate to the actual size
        let mut sig_vec = sig.to_vec();
        sig_vec.truncate(sz as usize);

        Ok(sig_vec)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}
