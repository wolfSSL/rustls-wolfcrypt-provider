use crate::error::*;
use crate::types::*;
use alloc::boxed::Box;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::mem;
use foreign_types::ForeignType;
use pkcs8::der::asn1::OctetStringRef;
use pkcs8::der::Decode;
use pkcs8::{ObjectIdentifier, PrivateKeyInfo};
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};

use wolfssl_wolfcrypt::sys::*;
use zeroize::Zeroizing;

const ALL_EDDSA_SCHEMES: &[SignatureScheme] = &[SignatureScheme::ED25519];

/// id-Ed25519 (RFC 8410).
const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// An ED25519 private key with its optional embedded public key.
type Ed25519KeyPair = (Zeroizing<Vec<u8>>, Option<[u8; 32]>);

#[derive(Clone)]
pub struct Ed25519PrivateKey {
    priv_key: Arc<Zeroizing<Vec<u8>>>,
    pub_key: Arc<Vec<u8>>,
    algo: SignatureAlgorithm,
}

impl fmt::Debug for Ed25519PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519PrivateKey")
            .field("algo", &self.algo)
            .finish_non_exhaustive()
    }
}
impl Ed25519PrivateKey {
    /// Extract ED25519 private and if available public key values from a PKCS#8 DER formatted key
    fn extract_key_pair(input_key: &[u8]) -> Result<Ed25519KeyPair, rustls::Error> {
        let bad_key = || rustls::Error::General("Invalid ED25519 PKCS#8 key".into());

        // Parsed in Rust rather than with wc_Ed25519PrivateKeyDecode, which passes
        // the embedded public key on with its leading BIT STRING "unused bits"
        // octet, so the import rejects it. The pkcs8 crate strips that octet and
        // checks that only a v2 key carries a public key.
        let info = PrivateKeyInfo::try_from(input_key).map_err(|_| bad_key())?;
        if info.algorithm.oid != ED25519_OID {
            return Err(bad_key());
        }

        // The private key field holds the 32-byte key wrapped in an OCTET STRING.
        let private_key = OctetStringRef::from_der(info.private_key).map_err(|_| bad_key())?;
        if private_key.as_bytes().len() != ED25519_KEY_SIZE as usize {
            return Err(bad_key());
        }

        let pub_key = info
            .public_key
            .map(|pk| pk.try_into().map_err(|_| bad_key()))
            .transpose()?;

        Ok((Zeroizing::new(private_key.as_bytes().to_vec()), pub_key))
    }
}

impl TryFrom<&PrivateKeyDer<'_>> for Ed25519PrivateKey {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs8(der) => {
                let pkcs8: &[u8] = der.secret_pkcs8_der();
                let (priv_key_raw, pub_option) = match Ed25519PrivateKey::extract_key_pair(pkcs8) {
                    Ok((priv_value, pub_value)) => (priv_value, pub_value),

                    Err(error) => return Err(error),
                };

                let mut ret;
                let mut pub_key_raw: [u8; 32] = [0; 32];
                let pub_key_raw_len: word32 = pub_key_raw.len() as word32;

                // Generate pub key part if not given
                if pub_option.is_none() {
                    let mut ed25519_c_type: ed25519_key = unsafe { mem::zeroed() };
                    let ed25519_key_object = ED25519KeyObject::new(&mut ed25519_c_type);
                    // This function initiliazes an ed25519_key object for
                    // using it to sign a message.
                    ed25519_key_object
                        .init()
                        .map_err(|_| rustls::Error::General("wc_ed25519_init failed".into()))?;

                    ret = unsafe {
                        wc_ed25519_import_private_only(
                            priv_key_raw.as_ptr(),
                            priv_key_raw.len() as word32,
                            ed25519_key_object.as_ptr(),
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
                }

                Ok(Self {
                    priv_key: Arc::new(priv_key_raw),
                    pub_key: Arc::new(match pub_option {
                        Some(pub_value) => pub_value.to_vec(),
                        None => pub_key_raw.to_vec(),
                    }),
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

#[derive(Clone)]
pub struct Ed25519Signer {
    priv_key: Arc<Zeroizing<Vec<u8>>>,
    pub_key: Arc<Vec<u8>>,
    scheme: SignatureScheme,
}

impl fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519Signer")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
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

        let mut key =
            Ed25519::new().map_err(|_| rustls::Error::General("wc_ed25519_init failed".into()))?;

        ret = unsafe {
            wc_ed25519_import_private_key(
                priv_key_raw.as_ptr(),
                priv_key_raw.len() as word32,
                pub_key_raw.as_ptr(),
                pub_key_raw.len() as word32,
                ed25519_key_object.as_ptr(),
            )
        };

        check_if_zero(ret)
            .map_err(|_| rustls::Error::General("wc_ed25519_import_private_key failed".into()))?;

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
            return Err(rustls::Error::General(format!(
                "wc_ed25519_sign_msg failed: {ret}",
            )));
        }

        let mut sig_vec = sig.to_vec();

        sig_vec.truncate(sig_sz as usize);

        Ok(sig_vec)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::PrivatePkcs8KeyDer;

    /// RFC 8410 section 10.3 example key (no embedded public key), with the
    /// given PKCS#8 version: 0 is v1, 1 is v2.
    fn pkcs8_without_public_key(version: u8) -> Vec<u8> {
        let mut der = alloc::vec![
            0x30, 0x2e, 0x02, 0x01, version, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        der.extend_from_slice(&[
            0xd4, 0xee, 0x72, 0xdb, 0xf9, 0x13, 0x58, 0x4a, 0xd5, 0xb6, 0xd8, 0xf1, 0xf7, 0x69,
            0xf8, 0xad, 0x3a, 0xfe, 0x7c, 0x28, 0xcb, 0xf1, 0xd4, 0xfb, 0xe0, 0x97, 0xa8, 0x8f,
            0x44, 0x75, 0x58, 0x42,
        ]);
        der
    }

    fn load(der: &[u8]) -> Result<Ed25519PrivateKey, rustls::Error> {
        Ed25519PrivateKey::try_from(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)))
    }

    #[test]
    fn test_v1_without_public_key_is_accepted() {
        assert!(load(&pkcs8_without_public_key(0)).is_ok());
    }

    #[test]
    fn test_v2_without_public_key_is_rejected() {
        assert!(load(&pkcs8_without_public_key(1)).is_err());
    }
}
