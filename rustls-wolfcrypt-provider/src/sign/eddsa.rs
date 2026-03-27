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
        let mut public_key_raw: [u8; 32] = [0; ED25519_PUB_KEY_SIZE as usize];
        let mut private_key_raw: [u8; 32] = [0; ED25519_KEY_SIZE as usize];
        let mut skip_bytes: usize;
        let mut key_sub_slice = input_key;

        const SHORT_FORM_LEN_MAX: u8 = 127;
        const TAG_SEQUENCE: u8 = 0x30;
        const TAG_OCTET_SEQUENCE: u8 = 0x04;
        const TAG_OPTIONAL_SET_OF_ATTRIBUTES: u8 = 0x80; //Implicit, context-specific, and primitive underlying type (SET OF)
        const TAG_OPTIONAL_PUBLIC_KEY_BIT_STRING: u8 = 0x81; //Implicit, context-specific, and primitive underlying type (BIT STRING)

        // The input key is encoded in PKCS#8 DER format with a structure as in
        // https://www.rfc-editor.org/rfc/rfc5958.html
        //
        // AsymmetricKeyPackage ::= SEQUENCE SIZE (1..MAX) OF OneAsymmetricKey

        // OneAsymmetricKey ::= SEQUENCE {
        //     version                   Version,
        //     privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
        //     privateKey                PrivateKey,
        //     attributes            [0] Attributes OPTIONAL,
        //     ...,
        //     [[2: publicKey        [1] PublicKey OPTIONAL ]],
        //     ...
        //     }

        // The key structure must begin with a SEQUENCE tag with at least 2 bytes length if short
        // length format is used
        if key_sub_slice[0] != TAG_SEQUENCE || key_sub_slice.len() < 2 {
            return Err(rustls::Error::General(
                "Faulty PKCS#8 ED25519 private key structure".into(),
            ));
        }
        // Check which length format and skip tag and length encoding bytes
        if key_sub_slice[1] > SHORT_FORM_LEN_MAX {
            skip_bytes = (2 + (key_sub_slice[1] & 0x7F)) as usize;
        } else {
            skip_bytes = 2;
        }

        // Skip version (3 bytes), algorithm ID sequence (0x30 + length encoding bytes + 5 ID bytes),
        skip_bytes += 3 + 7;
        key_sub_slice = input_key.get(skip_bytes..).unwrap();

        // Check if next bytes are 0x04, 0x22, 0x04, 0x20
        if !matches!(
            key_sub_slice,
            [TAG_OCTET_SEQUENCE, 0x22, TAG_OCTET_SEQUENCE, 0x20, ..]
        ) {
            return Err(rustls::Error::General(
                "Faulty PKCS#8 ED25519 private key structure".into(),
            ));
        }

        // Copy private key value
        skip_bytes += 4;
        key_sub_slice = input_key.get(skip_bytes..).unwrap();
        private_key_raw.copy_from_slice(&key_sub_slice[..ED25519_KEY_SIZE as usize]);
        skip_bytes += ED25519_KEY_SIZE as usize;
        key_sub_slice = input_key.get(skip_bytes..).unwrap();

        // Check if optional SET OF attributes exists and skip
        if key_sub_slice.first() == Some(&TAG_OPTIONAL_SET_OF_ATTRIBUTES) {
            skip_bytes += (2 + (key_sub_slice[1])) as usize;
            key_sub_slice = input_key.get(skip_bytes..).unwrap();
        }

        // Check if optional public key value exists. If exists, skip tag, length encoding byte,
        // and bits-used byte
        if key_sub_slice.first() == Some(&TAG_OPTIONAL_PUBLIC_KEY_BIT_STRING) {
            public_key_raw.copy_from_slice(&key_sub_slice[3..(3 + ED25519_KEY_SIZE as usize)]);
            Ok((private_key_raw, Some(public_key_raw)))
        } else {
            Ok((private_key_raw, None))
        }
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
        check_if_zero(ret).unwrap();

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
                "wc_ed25519_sign_msg failed: {}",
                ret
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
