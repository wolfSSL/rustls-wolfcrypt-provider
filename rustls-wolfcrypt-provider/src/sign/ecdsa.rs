use crate::alloc::string::ToString;
use crate::verify::Hash;
use alloc::boxed::Box;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};

use wolfssl_wolfcrypt::ecc::ECC;
use wolfssl_wolfcrypt::random::RNG;
use zeroize::Zeroizing;

/// Private key size of the largest supported curve, P-521.
const MAX_ECC_KEY_SIZE: usize = 66;

/// Largest DER-encoded signature for P-521: a SEQUENCE header (3 bytes) around
/// two INTEGERs, each with a 2-byte header and possibly a leading zero byte.
const ECC_MAX_SIG_SIZE: usize = 2 * MAX_ECC_KEY_SIZE + 9;

/// A unified ECDSA signing key that supports P-256, P-384, P-521.
/// Internally, we store the raw private key bytes plus
/// which scheme we should use (determined by WolfSSL after decode).
#[derive(Clone)]
pub struct EcdsaSigningKey {
    /// Raw private key bytes exported from wolfSSL (`ECC::export_private`)
    /// in big-endian format.
    key: Arc<Zeroizing<Vec<u8>>>,
    /// The signature scheme to use (e.g. ECDSA_NISTP256_SHA256).
    scheme: SignatureScheme,
}

impl fmt::Debug for EcdsaSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaSigningKey")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
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

        let mut key = ECC::import_der(der_formatted, None, None)
            .map_err(|_| rustls::Error::General("wc_EccPrivateKeyDecode failed".into()))?;

        // The export writes exactly the curve's key size, so a buffer big
        // enough for P-521 also tells us which curve the key is on.
        let mut priv_key_bytes = Zeroizing::new(vec![0u8; MAX_ECC_KEY_SIZE]);
        #[cfg(fips)]
        let _read = wolfssl_wolfcrypt::fips::PrivateKeyRead::enable().ok();
        let key_size = key
            .export_private(&mut priv_key_bytes)
            .map_err(|_| rustls::Error::General("wc_ecc_export_private_only failed".into()))?;
        priv_key_bytes.truncate(key_size);

        let scheme =
            curve_id_to_scheme(key_size).map_err(|e| rustls::Error::General(e.to_string()))?;

        Ok(Self {
            key: Arc::new(priv_key_bytes),
            scheme,
        })
    }
}

/// Converts a key size to a `SignatureScheme` (e.g. 32 -> ECDSA_NISTP256_SHA256).
fn curve_id_to_scheme(key_size: usize) -> Result<SignatureScheme, &'static str> {
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
        let (curve_id, hash) = scheme_to_curve_and_hash(self.scheme)
            .map_err(|e| rustls::Error::General(format!("scheme_to_curve_id unsupported: {e}")))?;

        let (digest, digest_len) = hash
            .digest(message)
            .map_err(|_| rustls::Error::General("hash failed".into()))?;

        let rng = RNG::new().map_err(|_| rustls::Error::General("wc_InitRng failed".into()))?;

        let mut key = ECC::import_private_key_ex(&self.key, &[], curve_id, None, None)
            .map_err(|_| rustls::Error::General("wc_ecc_import_private_key_ex failed".into()))?;

        let mut sig = [0u8; ECC_MAX_SIG_SIZE];
        let sig_sz = key
            .sign_hash(&digest[..digest_len], &mut sig, &rng)
            .map_err(|_| rustls::Error::General("wc_ecc_sign_hash failed".into()))?;

        Ok(sig[..sig_sz].to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

/// Converts a rustls `SignatureScheme` to the wolfSSL curve id and the hash to sign with.
fn scheme_to_curve_and_hash(scheme: SignatureScheme) -> Result<(i32, Hash), &'static str> {
    match scheme {
        SignatureScheme::ECDSA_NISTP256_SHA256 => Ok((ECC::SECP256R1, Hash::Sha256)),
        SignatureScheme::ECDSA_NISTP384_SHA384 => Ok((ECC::SECP384R1, Hash::Sha384)),
        SignatureScheme::ECDSA_NISTP521_SHA512 => Ok((ECC::SECP521R1, Hash::Sha512)),
        _ => Err("Not an ECDSA_NISTPxxx_SHAxxx scheme"),
    }
}
