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
pub struct EcdsaSigningKeyP256Sign {
    key: Arc<ECCKeyObject>,
    scheme: SignatureScheme,
}

impl EcdsaSigningKeyP256Sign {
    pub fn get_key(&self) -> Arc<ECCKeyObject> {
        Arc::clone(&self.key)
    }
}

impl TryFrom<&PrivateKeyDer<'_>> for EcdsaSigningKeyP256Sign {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs8(der) => {
                let mut ecc_c_type: ecc_key = unsafe { mem::zeroed() };
                let ecc_key_object = ECCKeyObject::new(&mut ecc_c_type);
                let pkcs8: &[u8] = der.secret_pkcs8_der();
                let pkcs8_sz: word32 = pkcs8.len() as word32;
                let mut ret;

                // This function initializes an ecc_key object for
                // future use with message signing.
                ecc_key_object.init();

                let mut idx: u32 = 0;

                // This function finds the beginning of the traditional
                // private key inside a PKCS#8 unencrypted buffer.
                ret = unsafe {
                    wc_GetPkcs8TraditionalOffset(pkcs8.as_ptr() as *mut u8, &mut idx, pkcs8_sz)
                };
                check_if_zero(ret).unwrap();

                // This function reads in an ECC private key from the input buffer, input,
                // parses the private key, and uses it to generate an ecc_key object,
                // which it stores in key.
                ret = unsafe {
                    wc_EccPrivateKeyDecode(
                        pkcs8.as_ptr() as *mut u8,
                        &mut idx,
                        ecc_key_object.as_ptr(),
                        pkcs8_sz,
                    )
                };
                check_if_zero(ret).unwrap();

                Ok(Self {
                    key: Arc::new(ecc_key_object),
                    scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
                })
            }
            _ => panic!("unsupported private key format"),
        }
    }
}

impl SigningKey for EcdsaSigningKeyP256Sign {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(self.clone()))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

impl Signer for EcdsaSigningKeyP256Sign {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut ret;
        let mut rng: WC_RNG = unsafe { mem::zeroed() };
        let rng_object: WCRngObject = WCRngObject::new(&mut rng);
        let mut digest: [u8; 32] = [0; 32];
        let message_length: word32 = message.len() as word32;
        let digest_length: word32 = digest.len() as word32;
        let mut sig: [u8; 265] = [0; 265];
        let mut sig_sz: word32 = sig.len() as word32;
        let ecc_key_arc = self.get_key();
        let ecc_key_object = ecc_key_arc.as_ref();

        // We hash the message, since it's not, using Sha256 (ECDSA_NISTP256_SHA256)
        ret = unsafe { wc_Sha256Hash(message.as_ptr(), message_length, digest.as_mut_ptr()) };
        check_if_zero(ret).unwrap();

        rng_object.init();

        // This function signs a message digest
        // using an ecc_key object to guarantee authenticity.
        ret = unsafe {
            wc_ecc_sign_hash(
                digest.as_mut_ptr(),
                digest_length,
                sig.as_mut_ptr(),
                &mut sig_sz,
                &mut rng,
                ecc_key_object.as_ptr(),
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
pub struct EcdsaSigningKeyP384Sign {
    key: Arc<ECCKeyObject>,
    scheme: SignatureScheme,
}

impl EcdsaSigningKeyP384Sign {
    pub fn get_key(&self) -> Arc<ECCKeyObject> {
        Arc::clone(&self.key)
    }
}

impl TryFrom<&PrivateKeyDer<'_>> for EcdsaSigningKeyP384Sign {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs8(der) => {
                let mut ecc_c_type: ecc_key = unsafe { mem::zeroed() };
                let ecc_key_object = ECCKeyObject::new(&mut ecc_c_type);
                let pkcs8: &[u8] = der.secret_pkcs8_der();
                let pkcs8_sz: word32 = pkcs8.len() as word32;
                let mut ret;

                // This function initializes an ecc_key object for
                // future use with message verification.
                ecc_key_object.init();

                let mut idx: u32 = 0;

                // This function finds the beginning of the traditional
                // private key inside a PKCS#8 unencrypted buffer.
                ret = unsafe {
                    wc_GetPkcs8TraditionalOffset(pkcs8.as_ptr() as *mut u8, &mut idx, pkcs8_sz)
                };
                check_if_zero(ret).unwrap();

                // This function reads in an ECC private key from the input buffer, input,
                // parses the private key, and uses it to generate an ecc_key object,
                // which it stores in key.
                ret = unsafe {
                    wc_EccPrivateKeyDecode(
                        pkcs8.as_ptr() as *mut u8,
                        &mut idx,
                        ecc_key_object.as_ptr(),
                        pkcs8_sz,
                    )
                };
                check_if_zero(ret).unwrap();

                Ok(Self {
                    key: Arc::new(ecc_key_object),
                    scheme: SignatureScheme::ECDSA_NISTP384_SHA384,
                })
            }
            _ => panic!("unsupported private key format"),
        }
    }
}

impl SigningKey for EcdsaSigningKeyP384Sign {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(self.clone()))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

impl Signer for EcdsaSigningKeyP384Sign {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut ret;
        let mut rng: WC_RNG = unsafe { mem::zeroed() };
        let rng_object: WCRngObject = WCRngObject::new(&mut rng);
        let mut digest: [u8; 32] = [0; 32];
        let message_length: word32 = message.len() as word32;
        let digest_length: word32 = digest.len() as word32;
        let mut sig: [u8; 265] = [0; 265];
        let mut sig_sz: word32 = sig.len() as word32;
        let ecc_key_arc = self.get_key();
        let ecc_key_object = ecc_key_arc.as_ref();

        // We hash the message, since it's not hashed, using Sha384 (ECDSA_NISTP384_SHA384)
        ret = unsafe { wc_Sha384Hash(message.as_ptr(), message_length, digest.as_mut_ptr()) };
        check_if_zero(ret).unwrap();

        rng_object.init();

        // This function signs a message digest
        // using an ecc_key object to guarantee authenticity.
        ret = unsafe {
            wc_ecc_sign_hash(
                digest.as_mut_ptr(),
                digest_length,
                sig.as_mut_ptr(),
                &mut sig_sz,
                &mut rng,
                ecc_key_object.as_ptr(),
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
pub struct EcdsaSigningKeyP521Sign {
    key: Arc<ECCKeyObject>,
    scheme: SignatureScheme,
}

impl EcdsaSigningKeyP521Sign {
    pub fn get_key(&self) -> Arc<ECCKeyObject> {
        Arc::clone(&self.key)
    }
}

impl TryFrom<&PrivateKeyDer<'_>> for EcdsaSigningKeyP521Sign {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs8(der) => {
                let mut ecc_c_type: ecc_key = unsafe { mem::zeroed() };
                let ecc_key_object = ECCKeyObject::new(&mut ecc_c_type);
                let pkcs8: &[u8] = der.secret_pkcs8_der();
                let pkcs8_sz: word32 = pkcs8.len() as word32;
                let mut ret;

                // This function initializes an ecc_key object for
                // future use with message verification.
                ecc_key_object.init();

                let mut idx: u32 = 0;

                // This function finds the beginning of the traditional
                // private key inside a PKCS#8 unencrypted buffer.
                ret = unsafe {
                    wc_GetPkcs8TraditionalOffset(pkcs8.as_ptr() as *mut u8, &mut idx, pkcs8_sz)
                };
                check_if_zero(ret).unwrap();

                // This function reads in an ECC private key from the input buffer, input,
                // parses the private key, and uses it to generate an ecc_key object,
                // which it stores in key.
                ret = unsafe {
                    wc_EccPrivateKeyDecode(
                        pkcs8.as_ptr() as *mut u8,
                        &mut idx,
                        ecc_key_object.as_ptr(),
                        pkcs8_sz,
                    )
                };
                check_if_zero(ret).unwrap();

                Ok(Self {
                    key: Arc::new(ecc_key_object),
                    scheme: SignatureScheme::ECDSA_NISTP521_SHA512,
                })
            }
            _ => panic!("unsupported private key format"),
        }
    }
}

impl SigningKey for EcdsaSigningKeyP521Sign {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(self.clone()))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

impl Signer for EcdsaSigningKeyP521Sign {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut ret;
        let mut rng: WC_RNG = unsafe { mem::zeroed() };
        let rng_object: WCRngObject = WCRngObject::new(&mut rng);
        let mut digest: [u8; 32] = [0; 32];
        let message_length: word32 = message.len() as word32;
        let digest_length: word32 = digest.len() as word32;
        let mut sig: [u8; 265] = [0; 265];
        let mut sig_sz: word32 = sig.len() as word32;
        let ecc_key_arc = self.get_key();
        let ecc_key_object = ecc_key_arc.as_ref();

        // We hash the message, since it's not hashed, using Sha521 (ECDSA_NISTP521_512)
        ret = unsafe { wc_Sha512Hash(message.as_ptr(), message_length, digest.as_mut_ptr()) };
        check_if_zero(ret).unwrap();

        rng_object.init();

        // This function signs a message digest
        // using an ecc_key object to guarantee authenticity.
        ret = unsafe {
            wc_ecc_sign_hash(
                digest.as_mut_ptr(),
                digest_length,
                sig.as_mut_ptr(),
                &mut sig_sz,
                &mut rng,
                ecc_key_object.as_ptr(),
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
        unsafe {
            let message = "message to verify".as_bytes();
            let message_length: word32 = message.len() as word32;
            let mut digest: [u8; 32] = [0; 32];
            let digest_length: word32 = digest.len() as word32;
            let mut ecc_c_type: ecc_key = mem::zeroed();
            let ecc_key_object = ECCKeyObject::from_ptr(&mut ecc_c_type);
            let mut rng: WC_RNG = mem::zeroed();
            let mut sig: [u8; 265] = [0; 265];
            let mut sig_sz: word32 = sig.len() as word32;
            let mut ret;

            ret = wc_Sha256Hash(message.as_ptr(), message_length, digest.as_mut_ptr());
            check_if_zero(ret).unwrap();

            ret = wc_InitRng(&mut rng);
            check_if_zero(ret).unwrap();

            ret = wc_ecc_init(ecc_key_object.as_ptr());
            check_if_zero(ret).unwrap();

            ret = wc_ecc_make_key(&mut rng, 32, ecc_key_object.as_ptr());
            check_if_zero(ret).unwrap();

            ret = wc_ecc_sign_hash(
                digest.as_mut_ptr(),
                digest_length,
                sig.as_mut_ptr(),
                &mut sig_sz,
                &mut rng,
                ecc_key_object.as_ptr(),
            );
            check_if_zero(ret).unwrap();

            let mut is_valid_sig: i32 = 0;
            ret = wc_ecc_verify_hash(
                sig.as_mut_ptr(),
                sig_sz,
                digest.as_mut_ptr(),
                digest_length,
                &mut is_valid_sig,
                ecc_key_object.as_ptr(),
            );
            check_if_zero(ret).unwrap();

            wc_FreeRng(&mut rng);

            assert_eq!(1, is_valid_sig);
        }
    }
}
