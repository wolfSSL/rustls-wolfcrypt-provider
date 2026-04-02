use crate::error::*;
use crate::types::*;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::mem;
use foreign_types::ForeignType;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};

use core::ptr;
use wolfcrypt_rs::*;
use zeroize::Zeroizing;

const ALL_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
];

const MAX_RSA_SIG_SIZE: usize = 512;
const HASH_TYPE_SHA256: u32 = wc_HashType_WC_HASH_TYPE_SHA256;
const HASH_TYPE_SHA384: u32 = wc_HashType_WC_HASH_TYPE_SHA384;
const HASH_TYPE_SHA512: u32 = wc_HashType_WC_HASH_TYPE_SHA512;

const MGF1_SHA256: u32 = WC_MGF1SHA256;
const MGF1_SHA384: u32 = WC_MGF1SHA384;
const MGF1_SHA512: u32 = WC_MGF1SHA512;

/// Which DER format the stored key bytes are in.
#[derive(Clone, Debug)]
enum RsaKeyFormat {
    Pkcs8,
    Pkcs1,
}

#[derive(Clone)]
pub struct RsaPrivateKey {
    /// Raw DER-encoded private key bytes.
    der_bytes: Arc<Zeroizing<Vec<u8>>>,
    format: RsaKeyFormat,
    algo: SignatureAlgorithm,
}

impl fmt::Debug for RsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPrivateKey")
            .field("format", &self.format)
            .field("algo", &self.algo)
            .finish_non_exhaustive()
    }
}

/// Owns both the heap-allocated RsaKey and its RsaKeyObject wrapper.
/// Rust drops fields in declaration order: `object` (which calls
/// wc_FreeRsaKey) is dropped first, then `_storage` frees the heap,
/// preventing use-after-free.
struct OwnedRsaKey {
    object: RsaKeyObject,
    _storage: Box<RsaKey>,
}

impl OwnedRsaKey {
    fn as_ptr(&self) -> *mut RsaKey {
        self.object.as_ptr()
    }
}

/// Import the stored DER bytes into a fresh RsaKey C struct.
fn import_rsa_key(der_bytes: &[u8], format: &RsaKeyFormat) -> Result<OwnedRsaKey, rustls::Error> {
    let mut rsa_key_box = Box::new(unsafe { mem::zeroed::<RsaKey>() });
    let rsa_key_object = unsafe { RsaKeyObject::from_ptr(&mut *rsa_key_box) };

    let ret = unsafe { wc_InitRsaKey(rsa_key_object.as_ptr(), ptr::null_mut()) };
    check_if_zero(ret).map_err(|_| rustls::Error::General("wc_InitRsaKey failed".into()))?;

    let mut idx: u32 = 0;

    let decode_ret = match format {
        RsaKeyFormat::Pkcs8 | RsaKeyFormat::Pkcs1 => unsafe {
            wc_RsaPrivateKeyDecode(
                der_bytes.as_ptr() as *mut u8,
                &mut idx,
                rsa_key_object.as_ptr(),
                der_bytes.len() as word32,
            )
        },
    };
    check_if_zero(decode_ret)
        .map_err(|_| rustls::Error::General("wc_RsaPrivateKeyDecode failed".into()))?;

    Ok(OwnedRsaKey {
        object: rsa_key_object,
        _storage: rsa_key_box,
    })
}

impl TryFrom<&PrivateKeyDer<'_>> for RsaPrivateKey {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        let (der_bytes, format) = match value {
            PrivateKeyDer::Pkcs8(der) => (der.secret_pkcs8_der().to_vec(), RsaKeyFormat::Pkcs8),
            PrivateKeyDer::Pkcs1(der) => (der.secret_pkcs1_der().to_vec(), RsaKeyFormat::Pkcs1),
            _ => {
                return Err(rustls::Error::General(
                    "Unsupported private key format".into(),
                ))
            }
        };

        // Validate that the key can be decoded before accepting it.
        let _rsa_key = import_rsa_key(&der_bytes, &format)?;

        Ok(Self {
            der_bytes: Arc::new(Zeroizing::new(der_bytes)),
            format,
            algo: SignatureAlgorithm::RSA,
        })
    }
}

impl SigningKey for RsaPrivateKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        // Iterate through all RSA schemes and check if any is in the offered list
        ALL_RSA_SCHEMES.iter().find_map(|&scheme| {
            if offered.contains(&scheme) {
                Some(Box::new(RsaSigner {
                    der_bytes: Arc::clone(&self.der_bytes),
                    format: self.format.clone(),
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
pub struct RsaSigner {
    der_bytes: Arc<Zeroizing<Vec<u8>>>,
    format: RsaKeyFormat,
    scheme: SignatureScheme,
}

impl fmt::Debug for RsaSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaSigner")
            .field("format", &self.format)
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

impl Signer for RsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let rsa_key = import_rsa_key(&self.der_bytes, &self.format)?;

        // Prepare a random generator
        let mut rng: WC_RNG = unsafe { mem::zeroed() };
        let rng_object = WCRngObject::new(&mut rng);
        rng_object.init();

        // Allocate enough space for the signature
        let mut sig_buf = [0u8; MAX_RSA_SIG_SIZE];

        match self.scheme {
            // ------------------------------------------------
            // RSA-PSS branch:
            // ------------------------------------------------
            SignatureScheme::RSA_PSS_SHA256
            | SignatureScheme::RSA_PSS_SHA384
            | SignatureScheme::RSA_PSS_SHA512 => {
                // We'll do explicit hashing plus wc_RsaPSS_Sign.

                // 1) Determine hash algorithm & MGF
                let (hash_ty, mgf_ty, digest_len) = match self.scheme {
                    SignatureScheme::RSA_PSS_SHA256 => {
                        (HASH_TYPE_SHA256, MGF1_SHA256, WC_SHA256_DIGEST_SIZE)
                    }
                    SignatureScheme::RSA_PSS_SHA384 => {
                        (HASH_TYPE_SHA384, MGF1_SHA384, WC_SHA384_DIGEST_SIZE)
                    }
                    SignatureScheme::RSA_PSS_SHA512 => {
                        (HASH_TYPE_SHA512, MGF1_SHA512, WC_SHA512_DIGEST_SIZE)
                    }
                    _ => unreachable!(),
                };

                // 2) Hash the message ourselves
                let mut digest = vec![0u8; digest_len as usize];
                let ret = unsafe {
                    match hash_ty {
                        HASH_TYPE_SHA256 => wc_Sha256Hash(
                            message.as_ptr(),
                            message.len() as u32,
                            digest.as_mut_ptr(),
                        ),
                        HASH_TYPE_SHA384 => wc_Sha384Hash(
                            message.as_ptr(),
                            message.len() as u32,
                            digest.as_mut_ptr(),
                        ),
                        HASH_TYPE_SHA512 => wc_Sha512Hash(
                            message.as_ptr(),
                            message.len() as u32,
                            digest.as_mut_ptr(),
                        ),
                        _ => -1,
                    }
                };
                check_if_zero(ret)
                    .map_err(|_| rustls::Error::General("Failed to hash for PSS".into()))?;

                // 3) Sign with wc_RsaPSS_Sign
                let ret = unsafe {
                    wc_RsaPSS_Sign(
                        digest.as_ptr(),
                        digest_len,
                        sig_buf.as_mut_ptr(),
                        sig_buf.len() as u32,
                        hash_ty,
                        mgf_ty.try_into().unwrap(),
                        rsa_key.as_ptr(),
                        rng_object.as_ptr(),
                    )
                };
                check_if_greater_than_zero(ret)
                    .map_err(|_| rustls::Error::General("wc_RsaPSS_Sign failed".into()))?;

                let sig_len = ret as usize;
                let mut sig_vec = sig_buf.to_vec();
                sig_vec.truncate(sig_len);
                Ok(sig_vec)
            }

            // ------------------------------------------------
            // RSA-PKCS#1 branch:
            // ------------------------------------------------
            SignatureScheme::RSA_PKCS1_SHA256
            | SignatureScheme::RSA_PKCS1_SHA384
            | SignatureScheme::RSA_PKCS1_SHA512 => {
                // We'll let wc_SignatureGenerate do the hashing & PKCS#1.
                let hash_ty = match self.scheme {
                    SignatureScheme::RSA_PKCS1_SHA256 => HASH_TYPE_SHA256,
                    SignatureScheme::RSA_PKCS1_SHA384 => HASH_TYPE_SHA384,
                    SignatureScheme::RSA_PKCS1_SHA512 => HASH_TYPE_SHA512,
                    _ => unreachable!(),
                };

                let mut sig_len: u32 = sig_buf.len() as u32;

                // wc_SignatureGenerate will produce a PKCS#1 signature, including hashing.
                let deref_rsa_key_c_type = unsafe { *(rsa_key.as_ptr()) };
                let ret = unsafe {
                    wc_SignatureGenerate(
                        hash_ty,
                        wc_SignatureType_WC_SIGNATURE_TYPE_RSA_W_ENC,
                        message.as_ptr(),
                        message.len() as u32,
                        sig_buf.as_mut_ptr(),
                        &mut sig_len,
                        rsa_key.as_ptr() as *const core::ffi::c_void,
                        mem::size_of_val(&deref_rsa_key_c_type).try_into().unwrap(),
                        rng_object.as_ptr(),
                    )
                };
                check_if_zero(ret)
                    .map_err(|_| rustls::Error::General("wc_SignatureGenerate failed".into()))?;

                // Check how big the actual signature is
                let actual_sig_size = unsafe {
                    wc_SignatureGetSize(
                        wc_SignatureType_WC_SIGNATURE_TYPE_RSA_W_ENC,
                        rsa_key.as_ptr() as *const core::ffi::c_void,
                        mem::size_of_val(&deref_rsa_key_c_type).try_into().unwrap(),
                    )
                };

                let mut sig_vec = sig_buf.to_vec();
                // Truncate to the size returned by wc_SignatureGetSize or the updated `sig_len`.
                let min_len = core::cmp::min(actual_sig_size as usize, sig_len as usize);
                sig_vec.truncate(min_len);

                Ok(sig_vec)
            }

            // If someone tries a scheme that isn't RSA...
            _ => Err(rustls::Error::General("Unsupported RSA scheme".into())),
        }
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}
