use crate::alloc::string::ToString;
use crate::error::*;
use crate::types::*;
use alloc::boxed::Box;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::mem;
use core::ptr;
use foreign_types::ForeignType;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};

use wolfcrypt_rs::*;

/// A unified ECDSA signing key that supports P-256, P-384, P-521.
/// Internally, we store the raw private key bytes plus
/// which scheme we should use (determined by WolfSSL after decode).
#[derive(Clone, Debug)]
pub struct EcdsaSigningKey {
    /// Raw private key bytes exported from WolfSSL (`wc_ecc_export_private_only`)
    /// in big-endian format.
    key: Arc<Vec<u8>>,
    /// The signature scheme to use (e.g. ECDSA_NISTP256_SHA256).
    scheme: SignatureScheme,
}

impl TryFrom<&PrivateKeyDer<'_>> for EcdsaSigningKey {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        let der_formatted = match value {
            PrivateKeyDer::Pkcs8(der) => der.secret_pkcs8_der(),
            PrivateKeyDer::Sec1(der) => der.secret_sec1_der(),
            PrivateKeyDer::Pkcs1(_) => {
                return Err(rustls::Error::General(
                    "Unsupported ECDSA key format (PKCS#1)".into(),
                ))
            }
            _ => {
                return Err(rustls::Error::General(
                    "Unsupported ECDSA key format (not PKCS#8)".into(),
                ))
            }
        };

        let mut ecc_c_type: ecc_key = unsafe { mem::zeroed() };
        let ecc_key_object = ECCKeyObject::new(&mut ecc_c_type);

        ecc_key_object.init();

        let mut idx: u32 = 0;
        let ret = unsafe {
            wc_EccPrivateKeyDecode(
                der_formatted.as_ptr() as *mut u8,
                &mut idx,
                ecc_key_object.as_ptr(),
                der_formatted.len() as word32,
            )
        };
        check_if_zero(ret)
            .map_err(|_| rustls::Error::General("wc_EccPrivateKeyDecode failed".into()))?;

        let key_size = unsafe { wc_ecc_size(ecc_key_object.as_ptr()) };
        if key_size == 0 {
            return Err(rustls::Error::General(
                "wc_ecc_size returned 0; invalid key?".into(),
            ));
        }

        let mut priv_key_bytes = vec![0u8; key_size as usize];
        let mut priv_key_bytes_len = priv_key_bytes.len() as word32;

        let ret = unsafe {
            wc_ecc_export_private_only(
                ecc_key_object.as_ptr(),
                priv_key_bytes.as_mut_ptr(),
                &mut priv_key_bytes_len,
            )
        };
        check_if_zero(ret)
            .map_err(|_| rustls::Error::General("wc_ecc_export_private_only failed".into()))?;

        priv_key_bytes.truncate(priv_key_bytes_len as usize);

        let scheme =
            curve_id_to_scheme(key_size).map_err(|e| rustls::Error::General(e.to_string()))?;

        Ok(Self {
            key: Arc::new(priv_key_bytes),
            scheme,
        })
    }
}

/// Converts a key size to a `SignatureScheme` (e.g. 32 -> ECDSA_NISTP256_SHA256).
fn curve_id_to_scheme(key_size: i32) -> Result<SignatureScheme, &'static str> {
    match key_size {
        32 => Ok(SignatureScheme::ECDSA_NISTP256_SHA256),
        48 => Ok(SignatureScheme::ECDSA_NISTP384_SHA384),
        66 => Ok(SignatureScheme::ECDSA_NISTP521_SHA512),
        _ => Err("Unsupported ECC key size"),
    }
}

impl SigningKey for EcdsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        // If the server (or peer) offered the scheme we have, we can sign with it
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

impl Signer for EcdsaSigningKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let digest = hash_message_for_scheme(self.scheme, message)
            .map_err(|_| rustls::Error::General("hash failed".into()))?;

        let mut rng: WC_RNG = unsafe { mem::zeroed() };
        let rng_object: WCRngObject = WCRngObject::new(&mut rng);
        rng_object.init();

        let mut ecc_c_type: ecc_key = unsafe { mem::zeroed() };
        let ecc_key_object = ECCKeyObject::new(&mut ecc_c_type);
        ecc_key_object.init();

        let curve_id = scheme_to_curve_id(self.scheme)
            .map_err(|e| rustls::Error::General(format!("scheme_to_curve_id unsupported: {e}")))?;

        let ret = unsafe {
            wc_ecc_import_private_key_ex(
                self.key.as_ptr(),
                self.key.len() as word32,
                ptr::null_mut(),
                0,
                ecc_key_object.as_ptr(),
                curve_id,
            )
        };
        check_if_zero(ret)
            .map_err(|_| rustls::Error::General("wc_ecc_import_private_key_ex failed".into()))?;

        let ret =
            unsafe { wc_ecc_set_curve(ecc_key_object.as_ptr(), self.key.len() as i32, curve_id) };
        check_if_zero(ret).map_err(|_| rustls::Error::General("wc_ecc_set_curve failed".into()))?;

        let mut sig = [0u8; ECC_MAX_SIG_SIZE as usize];
        let mut sig_sz: word32 = sig.len() as word32;

        let ret = unsafe {
            wc_ecc_sign_hash(
                digest.as_ptr() as *mut u8,
                digest.len() as word32,
                sig.as_mut_ptr(),
                &mut sig_sz,
                rng_object.as_ptr(),
                ecc_key_object.as_ptr(),
            )
        };
        check_if_zero(ret).map_err(|_| rustls::Error::General("wc_ecc_sign_hash failed".into()))?;

        // truncate to actual sig size
        let mut sig_vec = sig.to_vec();
        sig_vec.truncate(sig_sz as usize);

        Ok(sig_vec)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

/// Hash the input `message` according to the scheme’s hash algorithm.
/// Returns the raw digest bytes.
fn hash_message_for_scheme(
    scheme: SignatureScheme,
    message: &[u8],
) -> Result<Vec<u8>, &'static str> {
    match scheme {
        SignatureScheme::ECDSA_NISTP256_SHA256 => {
            let mut digest = vec![0u8; WC_SHA256_DIGEST_SIZE as usize];
            let ret = unsafe {
                wc_Sha256Hash(
                    message.as_ptr(),
                    message.len() as word32,
                    digest.as_mut_ptr(),
                )
            };
            if ret != 0 {
                return Err("wc_Sha256Hash failed");
            }
            Ok(digest)
        }
        SignatureScheme::ECDSA_NISTP384_SHA384 => {
            let mut digest = vec![0u8; WC_SHA384_DIGEST_SIZE as usize];
            let ret = unsafe {
                wc_Sha384Hash(
                    message.as_ptr(),
                    message.len() as word32,
                    digest.as_mut_ptr(),
                )
            };
            if ret != 0 {
                return Err("wc_Sha384Hash failed");
            }
            Ok(digest)
        }
        SignatureScheme::ECDSA_NISTP521_SHA512 => {
            let mut digest = vec![0u8; WC_SHA512_DIGEST_SIZE as usize];
            let ret = unsafe {
                wc_Sha512Hash(
                    message.as_ptr(),
                    message.len() as word32,
                    digest.as_mut_ptr(),
                )
            };
            if ret != 0 {
                return Err("wc_Sha512Hash failed");
            }
            Ok(digest)
        }
        _ => Err("Unsupported scheme for ECDSA signing"),
    }
}

/// Converts a rustls `SignatureScheme` to the WolfSSL curve id (ecc_curve_id_ECC_...).
fn scheme_to_curve_id(scheme: SignatureScheme) -> Result<i32, &'static str> {
    match scheme {
        SignatureScheme::ECDSA_NISTP256_SHA256 => Ok(ecc_curve_id_ECC_SECP256R1),
        SignatureScheme::ECDSA_NISTP384_SHA384 => Ok(ecc_curve_id_ECC_SECP384R1),
        SignatureScheme::ECDSA_NISTP521_SHA512 => Ok(ecc_curve_id_ECC_SECP521R1),
        _ => Err("Not an ECDSA_NISTPxxx_SHAxxx scheme"),
    }
}
