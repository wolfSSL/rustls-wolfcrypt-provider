use crate::error::*;
use crate::types::types::*;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::vec;
use core::mem;
use foreign_types::ForeignType;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};

use core::ptr;
use wolfcrypt_rs::*;

const ALL_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
];

#[derive(Clone, Debug)]
pub struct RsaPssPrivateKey {
    key: Arc<RsaKeyObject>,
    algo: SignatureAlgorithm,
}

impl RsaPssPrivateKey {
    pub fn get_key(&self) -> Arc<RsaKeyObject> {
        Arc::clone(&self.key)
    }
}

impl TryFrom<&PrivateKeyDer<'_>> for RsaPssPrivateKey {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs8(der) => {
                let mut rsa_key_c_type: RsaKey = unsafe { mem::zeroed() };
                let rsa_key_object = unsafe { RsaKeyObject::from_ptr(&mut rsa_key_c_type) };
                let pkcs8: &[u8] = der.secret_pkcs8_der();
                let pkcs8_sz: word32 = pkcs8.len() as word32;
                let mut ret;

                ret = unsafe { wc_InitRsaKey(rsa_key_object.as_ptr(), ptr::null_mut()) };
                check_if_zero(ret).unwrap();

                let mut idx: u32 = 0;

                ret = unsafe {
                    wc_RsaPrivateKeyDecode(
                        pkcs8.as_ptr() as *mut u8,
                        &mut idx,
                        rsa_key_object.as_ptr(),
                        pkcs8_sz,
                    )
                };
                check_if_zero(ret)
                    .map_err(|_| rustls::Error::General("FFI function failed".into()))?;

                Ok(Self {
                    key: Arc::new(rsa_key_object),
                    algo: SignatureAlgorithm::RSA
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

impl SigningKey for RsaPssPrivateKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        // Iterate through all RSA schemes and check if any is in the offered list
        ALL_RSA_SCHEMES.iter().find_map(|&scheme| {
            if offered.contains(&scheme) {
                Some(Box::new(RsaPssSigner{key: self.get_key(), scheme: scheme}) as Box<dyn Signer>)
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
pub struct RsaPssSigner {
    key: Arc<RsaKeyObject>,
    scheme: SignatureScheme,
}

impl RsaPssSigner {
    pub fn get_key(&self) -> Arc<RsaKeyObject> {
        Arc::clone(&self.key)
    }
}

impl Signer for RsaPssSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut rng: WC_RNG = unsafe { mem::zeroed() };
        let rng_object: WCRngObject = WCRngObject::new(&mut rng);
        let mut sig: [u8; 265] = [0; 265];
        let rsa_key_arc = self.get_key();
        let rsa_key_object = rsa_key_arc.as_ref();
        let mut digest: Vec<u8>;
        let digest_length: word32;
        let hash_type;
        let mgf_type;
    
        // Define Rust-style aliases for binding constants
        const HASH_TYPE_SHA256: u32 = wc_HashType_WC_HASH_TYPE_SHA256;
        const HASH_TYPE_SHA384: u32 = wc_HashType_WC_HASH_TYPE_SHA384;
        const HASH_TYPE_SHA512: u32 = wc_HashType_WC_HASH_TYPE_SHA512;
    
        const MGF1_SHA256: u32 = WC_MGF1SHA256;
        const MGF1_SHA384: u32 = WC_MGF1SHA384;
        const MGF1_SHA512: u32 = WC_MGF1SHA512;
    
        // Determine the hashing algorithm, digest size, and MGF type based on the scheme
        match self.scheme {
            SignatureScheme::RSA_PSS_SHA256 => {
                digest = vec![0; WC_SHA256_DIGEST_SIZE as usize];
                digest_length = WC_SHA256_DIGEST_SIZE as word32;
                hash_type = HASH_TYPE_SHA256;
                mgf_type = MGF1_SHA256;
            }
            SignatureScheme::RSA_PSS_SHA384 => {
                digest = vec![0; WC_SHA384_DIGEST_SIZE as usize];
                digest_length = WC_SHA384_DIGEST_SIZE as word32;
                hash_type = HASH_TYPE_SHA384;
                mgf_type = MGF1_SHA384;
            }
            SignatureScheme::RSA_PSS_SHA512 => {
                digest = vec![0; WC_SHA512_DIGEST_SIZE as usize];
                digest_length = WC_SHA512_DIGEST_SIZE as word32;
                hash_type = HASH_TYPE_SHA512;
                mgf_type = MGF1_SHA512;
            }
            _ => {
                return Err(rustls::Error::General("Unsupported signature scheme".into()));
            }
        }
    
        // Initialize RNG
        rng_object.init();
    
        // Hash the message using the selected hashing algorithm
        let ret = unsafe {
            match hash_type {
                HASH_TYPE_SHA256 => wc_Sha256Hash(
                    message.as_ptr(),
                    message.len() as word32,
                    digest.as_mut_ptr(),
                ),
                HASH_TYPE_SHA384 => wc_Sha384Hash(
                    message.as_ptr(),
                    message.len() as word32,
                    digest.as_mut_ptr(),
                ),
                HASH_TYPE_SHA512 => wc_Sha512Hash(
                    message.as_ptr(),
                    message.len() as word32,
                    digest.as_mut_ptr(),
                ),
                _ => -1, // Should not reach here
            }
        };
        check_if_zero(ret).unwrap();
    
        // Sign the digest using the appropriate scheme
        let ret = unsafe {
            wc_RsaPSS_Sign(
                digest.as_ptr(),
                digest_length,
                sig.as_mut_ptr(),
                sig.len() as word32,
                hash_type,
                mgf_type.try_into().unwrap(),
                rsa_key_object.as_ptr(),
                rng_object.as_ptr(),
            )
        };
        check_if_greater_than_zero(ret)
            .map_err(|_| rustls::Error::General("FFI function failed".into()))?;
    
        let sz = ret;
    
        // Convert the signature to a Vec and truncate to the actual size
        let mut sig_vec = sig.to_vec();
        sig_vec.truncate(sz as usize);
    
        Ok(sig_vec)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}