use crate::error::*;
use crate::types::types::*;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem;
use core::ptr;
use foreign_types::ForeignType;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};

use wolfcrypt_rs::*;

#[derive(Clone, Debug)]
pub struct EcdsaSigningKeyP256Sha256Sign {
    key: Arc<Vec<u8>>,
    scheme: SignatureScheme,
}

impl TryFrom<&PrivateKeyDer<'_>> for EcdsaSigningKeyP256Sha256Sign {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs8(der) => {
                let mut ecc_c_type: ecc_key = unsafe { mem::zeroed() };
                let ecc_key_object = ECCKeyObject::new(&mut ecc_c_type);
                let pkcs8: &[u8] = der.secret_pkcs8_der();
                let pkcs8_sz: word32 = pkcs8.len() as word32;
                let mut priv_key_bytes: [u8; 32] = [0; 32];
                let mut priv_key_bytes_len: word32 = priv_key_bytes.len() as word32;
                let mut ret;

                // This function initializes an ecc_key object for
                // future use with message signing.
                ecc_key_object.init();

                let mut idx: u32 = 0;

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
                check_if_zero(ret)
                    .map_err(|_| rustls::Error::General("FFI function failed".into()))?;

                ret = unsafe {
                    wc_ecc_export_private_only(
                        ecc_key_object.as_ptr(),
                        priv_key_bytes.as_mut_ptr(),
                        &mut priv_key_bytes_len,
                    )
                };
                check_if_zero(ret)
                    .map_err(|_| rustls::Error::General("FFI function failed".into()))?;

                Ok(Self {
                    key: Arc::new(priv_key_bytes.to_vec()),
                    scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
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

impl SigningKey for EcdsaSigningKeyP256Sha256Sign {
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

impl Signer for EcdsaSigningKeyP256Sha256Sign {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut ret;
        let mut rng: WC_RNG = unsafe { mem::zeroed() };
        let rng_object: WCRngObject = WCRngObject::new(&mut rng);
        let mut digest: [u8; WC_SHA256_DIGEST_SIZE as usize] = [0; WC_SHA256_DIGEST_SIZE as usize];
        let message_length: word32 = message.len() as word32;
        let digest_length: word32 = digest.len() as word32;
        let mut sig: [u8; ECC_MAX_SIG_SIZE as usize] = [0; ECC_MAX_SIG_SIZE as usize];
        let mut sig_sz: word32 = sig.len() as word32;
        let priv_key_bytes = &self.key;
        let mut priv_key: ecc_key = unsafe { mem::zeroed() };
        let priv_key_object = ECCKeyObject::new(&mut priv_key);

        // We hash the message, since it's not, using Sha256 (ECDSA_NISTP256_SHA256)
        ret = unsafe { wc_Sha256Hash(message.as_ptr(), message_length, digest.as_mut_ptr()) };
        check_if_zero(ret).unwrap();

        rng_object.init();

        priv_key_object.init();

        ret = unsafe {
            wc_ecc_import_private_key_ex(
                priv_key_bytes.as_ptr(),
                priv_key_bytes.len() as word32,
                ptr::null_mut(),
                0,
                priv_key_object.as_ptr(),
                ecc_curve_id_ECC_SECP256R1,
            )
        };
        check_if_zero(ret).unwrap();

        ret = unsafe { wc_ecc_set_curve(priv_key_object.as_ptr(), 32, ecc_curve_id_ECC_SECP256R1) };
        check_if_zero(ret).unwrap();

        // This function signs a message digest
        // using an ecc_key object to guarantee authenticity.
        ret = unsafe {
            wc_ecc_sign_hash(
                digest.as_mut_ptr(),
                digest_length,
                sig.as_mut_ptr(),
                &mut sig_sz,
                &mut rng,
                priv_key_object.as_ptr(),
            )
        };
        check_if_zero(ret).unwrap();

        let mut sig_vec = sig.to_vec();

        sig_vec.truncate(sig_sz as usize);

        Ok(sig_vec)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

#[derive(Clone, Debug)]
pub struct EcdsaSigningKeyP384Sha384Sign {
    key: Arc<Vec<u8>>,
    scheme: SignatureScheme,
}

impl TryFrom<&PrivateKeyDer<'_>> for EcdsaSigningKeyP384Sha384Sign {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs8(der) => {
                let mut ecc_c_type: ecc_key = unsafe { mem::zeroed() };
                let ecc_key_object = ECCKeyObject::new(&mut ecc_c_type);
                let pkcs8: &[u8] = der.secret_pkcs8_der();
                let pkcs8_sz: word32 = pkcs8.len() as word32;
                let mut priv_key_bytes: [u8; 48] = [0; 48];
                let mut priv_key_bytes_len: word32 = priv_key_bytes.len() as word32;
                let mut ret;

                // This function initializes an ecc_key object for
                // future use with message signing.
                ecc_key_object.init();

                let mut idx: u32 = 0;

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
                check_if_zero(ret)
                    .map_err(|_| rustls::Error::General("FFI function failed".into()))?;

                ret = unsafe {
                    wc_ecc_export_private_only(
                        ecc_key_object.as_ptr(),
                        priv_key_bytes.as_mut_ptr(),
                        &mut priv_key_bytes_len,
                    )
                };
                check_if_zero(ret)
                    .map_err(|_| rustls::Error::General("FFI function failed".into()))?;

                Ok(Self {
                    key: Arc::new(priv_key_bytes.to_vec()),
                    scheme: SignatureScheme::ECDSA_NISTP384_SHA384,
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

impl SigningKey for EcdsaSigningKeyP384Sha384Sign {
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

impl Signer for EcdsaSigningKeyP384Sha384Sign {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut ret;
        let mut rng: WC_RNG = unsafe { mem::zeroed() };
        let rng_object: WCRngObject = WCRngObject::new(&mut rng);
        let mut digest: [u8; WC_SHA384_DIGEST_SIZE as usize] = [0; WC_SHA384_DIGEST_SIZE as usize];
        let message_length: word32 = message.len() as word32;
        let digest_length: word32 = digest.len() as word32;
        let mut sig: [u8; ECC_MAX_SIG_SIZE as usize] = [0; ECC_MAX_SIG_SIZE as usize];
        let mut sig_sz: word32 = sig.len() as word32;
        let priv_key_bytes = &self.key;
        let mut priv_key: ecc_key = unsafe { mem::zeroed() };
        let priv_key_object = ECCKeyObject::new(&mut priv_key);

        // We hash the message, since it's not, using Sha384 (ECDSA_NISTP384_SHA384)
        ret = unsafe { wc_Sha384Hash(message.as_ptr(), message_length, digest.as_mut_ptr()) };
        check_if_zero(ret).unwrap();

        rng_object.init();

        priv_key_object.init();

        ret = unsafe {
            wc_ecc_import_private_key_ex(
                priv_key_bytes.as_ptr(),
                priv_key_bytes.len() as word32,
                ptr::null_mut(),
                0,
                priv_key_object.as_ptr(),
                ecc_curve_id_ECC_SECP384R1,
            )
        };
        check_if_zero(ret).unwrap();

        ret = unsafe { wc_ecc_set_curve(priv_key_object.as_ptr(), 48, ecc_curve_id_ECC_SECP384R1) };
        check_if_zero(ret).unwrap();

        // This function signs a message digest
        // using an ecc_key object to guarantee authenticity.
        ret = unsafe {
            wc_ecc_sign_hash(
                digest.as_mut_ptr(),
                digest_length,
                sig.as_mut_ptr(),
                &mut sig_sz,
                &mut rng,
                priv_key_object.as_ptr(),
            )
        };
        check_if_zero(ret).unwrap();

        let mut sig_vec = sig.to_vec();

        sig_vec.truncate(sig_sz as usize);

        Ok(sig_vec)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

#[derive(Clone, Debug)]
pub struct EcdsaSigningKeyP521Sha512Sign {
    key: Arc<Vec<u8>>,
    scheme: SignatureScheme,
}

impl TryFrom<&PrivateKeyDer<'_>> for EcdsaSigningKeyP521Sha512Sign {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs8(der) => {
                let mut ecc_c_type: ecc_key = unsafe { mem::zeroed() };
                let ecc_key_object = ECCKeyObject::new(&mut ecc_c_type);
                let pkcs8: &[u8] = der.secret_pkcs8_der();
                let pkcs8_sz: word32 = pkcs8.len() as word32;
                let mut priv_key_bytes: [u8; 66] = [0; 66];
                let mut priv_key_bytes_len: word32 = priv_key_bytes.len() as word32;
                let mut ret;

                // This function initializes an ecc_key object for
                // future use with message signing.
                ecc_key_object.init();

                let mut idx: u32 = 0;

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
                check_if_zero(ret)
                    .map_err(|_| rustls::Error::General("FFI function failed".into()))?;

                ret = unsafe {
                    wc_ecc_export_private_only(
                        ecc_key_object.as_ptr(),
                        priv_key_bytes.as_mut_ptr(),
                        &mut priv_key_bytes_len,
                    )
                };
                check_if_zero(ret).unwrap();

                Ok(Self {
                    key: Arc::new(priv_key_bytes.to_vec()),
                    scheme: SignatureScheme::ECDSA_NISTP521_SHA512,
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

impl SigningKey for EcdsaSigningKeyP521Sha512Sign {
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

impl Signer for EcdsaSigningKeyP521Sha512Sign {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut ret;
        let mut rng: WC_RNG = unsafe { mem::zeroed() };
        let rng_object: WCRngObject = WCRngObject::new(&mut rng);
        let mut digest: [u8; WC_SHA512_DIGEST_SIZE as usize] = [0; WC_SHA512_DIGEST_SIZE as usize];
        let message_length: word32 = message.len() as word32;
        let digest_length: word32 = digest.len() as word32;
        let mut sig: [u8; ECC_MAX_SIG_SIZE as usize] = [0; ECC_MAX_SIG_SIZE as usize];
        let mut sig_sz: word32 = sig.len() as word32;
        let priv_key_bytes = &self.key;
        let mut priv_key: ecc_key = unsafe { mem::zeroed() };
        let priv_key_object = ECCKeyObject::new(&mut priv_key);

        // We hash the message, since it's not, using Sha512 (ECDSA_NISTP521_SHA512)
        ret = unsafe { wc_Sha512Hash(message.as_ptr(), message_length, digest.as_mut_ptr()) };
        check_if_zero(ret).unwrap();

        rng_object.init();

        priv_key_object.init();

        ret = unsafe {
            wc_ecc_import_private_key_ex(
                priv_key_bytes.as_ptr(),
                priv_key_bytes.len() as word32,
                ptr::null_mut(),
                0,
                priv_key_object.as_ptr(),
                ecc_curve_id_ECC_SECP521R1,
            )
        };
        check_if_zero(ret).unwrap();

        ret = unsafe { wc_ecc_set_curve(priv_key_object.as_ptr(), 66, ecc_curve_id_ECC_SECP521R1) };
        check_if_zero(ret).unwrap();

        // This function signs a message digest
        // using an ecc_key object to guarantee authenticity.
        ret = unsafe {
            wc_ecc_sign_hash(
                digest.as_mut_ptr(),
                digest_length,
                sig.as_mut_ptr(),
                &mut sig_sz,
                &mut rng,
                priv_key_object.as_ptr(),
            )
        };
        check_if_zero(ret).unwrap();

        let mut sig_vec = sig.to_vec();

        sig_vec.truncate(sig_sz as usize);

        Ok(sig_vec)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}
