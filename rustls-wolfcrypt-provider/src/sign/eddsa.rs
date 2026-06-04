use crate::error::*;
use crate::types::*;
use alloc::boxed::Box;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::mem;
use foreign_types::ForeignType;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};

use wolfcrypt_rs::*;
use zeroize::Zeroizing;

const ALL_EDDSA_SCHEMES: &[SignatureScheme] = &[SignatureScheme::ED25519];

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
    fn extract_key_pair(input_key: &[u8]) -> Result<([u8; 32], Option<[u8; 32]>), rustls::Error> {
        let mut private_key_raw: [u8; 32] = [0; ED25519_KEY_SIZE as usize];
        let mut private_key_raw_len: word32 = private_key_raw.len() as word32;
        // Scratch buffer large enough for any public-key form wolfSSL may emit:
        // a bare 32-byte point, a 33-byte prefixed point, or an uncompressed point.
        let mut public_key_scratch: [u8; 65] = [0; 65];
        let mut public_key_scratch_len: word32 = public_key_scratch.len() as word32;
        let mut idx: word32 = 0;

        // Parse the PKCS#8 structure with wolfSSL's own ASN parser. This is the
        // same parser wc_Ed25519PrivateKeyDecode uses internally, but calling it
        // directly lets us normalise the public key before it is imported.
        //
        // For an RFC 5958 (PKCS#8 v2) key that embeds the optional public key,
        // DecodeAsymKey returns the [1] field as a raw DER BIT STRING body: the
        // 32-byte key prefixed by its "unused bits" 0x00 octet (33 bytes total).
        // wc_Ed25519PrivateKeyDecode forwards those 33 bytes straight to
        // wc_ed25519_import_public_ex, which only accepts 32 bytes, a 0x40-prefixed
        // compressed point, or an 0x04 uncompressed point, so it fails with
        // BAD_FUNC_ARG (-173). We strip the prefix ourselves instead.
        let ret = unsafe {
            DecodeAsymKey(
                input_key.as_ptr(),
                &mut idx,
                input_key.len() as word32,
                private_key_raw.as_mut_ptr(),
                &mut private_key_raw_len,
                public_key_scratch.as_mut_ptr(),
                &mut public_key_scratch_len,
                Key_Sum_ED25519k as i32,
            )
        };
        check_if_zero(ret)
            .map_err(|_| rustls::Error::General("DecodeAsymKey (ED25519) failed".into()))?;

        // Normalise the optional public key based on the length the parser reported.
        let pub_key: Option<[u8; 32]> = match public_key_scratch_len {
            // No embedded public key; the caller derives it from the private seed.
            0 => None,
            // Bare 32-byte public key.
            len if len == ED25519_PUB_KEY_SIZE => Some(
                public_key_scratch[..ED25519_PUB_KEY_SIZE as usize]
                    .try_into()
                    .unwrap(),
            ),
            // BIT STRING body: leading 0x00 "unused bits" octet + 32-byte key.
            len if len == ED25519_PUB_KEY_SIZE + 1 && public_key_scratch[0] == 0x00 => Some(
                public_key_scratch[1..1 + ED25519_PUB_KEY_SIZE as usize]
                    .try_into()
                    .unwrap(),
            ),
            _ => {
                return Err(rustls::Error::General(
                    "Unexpected ED25519 public key encoding".into(),
                ))
            }
        };

        Ok((private_key_raw, pub_key))
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
                    ed25519_key_object.init();

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
                    priv_key: Arc::new(Zeroizing::new(priv_key_raw.to_vec())),
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

        ed25519_key_object.init();

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
