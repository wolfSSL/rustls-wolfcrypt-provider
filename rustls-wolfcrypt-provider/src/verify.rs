use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use rustls::SignatureScheme;
use webpki::alg_id;
use wolfcrypt_rs::*;
use std::mem;
use foreign_types::{ForeignType, ForeignTypeRef, Opaque};
use std::ptr::NonNull;
use std::{os::raw::c_void};
use der::Reader;
use rsa::signature::Verifier;
use rsa::{pkcs1v15, BigUint, RsaPublicKey};

pub static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[RSA_PSS_SHA256, RSA_PKCS1_SHA256],
    mapping: &[
        (SignatureScheme::RSA_PSS_SHA256, &[RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[RSA_PKCS1_SHA256]),
    ],
};

static RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm = &RsaPssSha256Verify;
static RSA_PKCS1_SHA256: &dyn SignatureVerificationAlgorithm = &RsaPkcs1Sha256Verify;

pub struct RsaKeyObjectRef(Opaque);
unsafe impl ForeignTypeRef for RsaKeyObjectRef {
    type CType = RsaKey;
}

#[derive(Debug, Clone, Copy)]
pub struct RsaKeyObject(NonNull<RsaKey>);
unsafe impl Sync for RsaKeyObject{}
unsafe impl Send for RsaKeyObject{}
unsafe impl ForeignType for RsaKeyObject {
    type CType = RsaKey;

    type Ref = RsaKeyObjectRef;

    unsafe fn from_ptr(ptr: *mut Self::CType) -> Self {
        Self(NonNull::new_unchecked(ptr))
    }

    fn as_ptr(&self) -> *mut Self::CType {
        self.0.as_ptr()
    }
}

#[derive(Debug)]
struct RsaPssSha256Verify;

impl SignatureVerificationAlgorithm for RsaPssSha256Verify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_PSS_SHA256
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        unsafe {
            let mut rsa_key_struct: RsaKey = mem::zeroed();
            let rsa_key_object = RsaKeyObject::from_ptr(&mut rsa_key_struct);
            let mut ret;

            ret = wc_InitRsaKey(rsa_key_object.as_ptr(), std::ptr::null_mut());
            if ret != 0 {
                panic!("error while calling wc_InitRsaKey, ret value: {}", ret);
            }
            // public_key: unfortunately this is not a whole SPKI, but just the key material.
            // decode the two integers manually.
            let mut reader = der::SliceReader::new(public_key).map_err(|_| InvalidSignature)?;
            let ne: [der::asn1::UintRef; 2] = reader
                .decode()
                .map_err(|_| InvalidSignature)?;

            let n = ne[0].as_bytes();
            let e = ne[1].as_bytes();

            ret = wc_RsaPublicKeyDecodeRaw(
                    n.as_ptr(), 
                    mem::size_of_val(&n).try_into().unwrap(), 
                    e.as_ptr(), 
                    mem::size_of_val(&e).try_into().unwrap(), 
                    rsa_key_object.as_ptr()
            );
            if ret != 0 {
                panic!("error while calling wc_RsaPublicKeyDecodeRaw, ret value: {}", ret);
            }

            let message_len: word32 = message.len() as word32;
            let signature_len: word32 = signature.len() as word32;

            ret = wc_SignatureVerify(
                wc_HashType_WC_HASH_TYPE_SHA256,
                wc_SignatureType_WC_SIGNATURE_TYPE_RSA,
                message.as_ptr(), 
                message_len,
                signature.as_ptr(), 
                signature_len,
                rsa_key_object.as_ptr() as *const c_void, 
                mem::size_of_val(&rsa_key_struct).try_into().unwrap()
            );

            if ret >= 0 { 
                Ok(()) 
            } else { 
                // FIXME: -201 -> Rsa Padding error
                log::error!("value of ret: {}", ret);
                log::error!("value of signature_len: {}", signature_len);
                log::error!("value of wc_SignatureGetSize: {}", wc_SignatureGetSize(wc_SignatureType_WC_SIGNATURE_TYPE_RSA, rsa_key_object.as_ptr() as *const c_void, mem::size_of_val(&rsa_key_struct).try_into().unwrap()));

                Err(InvalidSignature) 
            }
        }
    }
}

#[derive(Debug)]
struct RsaPkcs1Sha256Verify;

impl SignatureVerificationAlgorithm for RsaPkcs1Sha256Verify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_PKCS1_SHA256
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let public_key = decode_spki_spk(public_key)?;

        let signature = pkcs1v15::Signature::try_from(signature).map_err(|_| InvalidSignature)?;

        pkcs1v15::VerifyingKey::<sha2::Sha256>::new(public_key)
            .verify(message, &signature)
            .map_err(|_| InvalidSignature)
    }
}

fn decode_spki_spk(spki_spk: &[u8]) -> Result<RsaPublicKey, InvalidSignature> {
    // public_key: unfortunately this is not a whole SPKI, but just the key material.
    // decode the two integers manually.
    let mut reader = der::SliceReader::new(spki_spk).map_err(|_| InvalidSignature)?;
    let ne: [der::asn1::UintRef; 2] = reader
        .decode()
        .map_err(|_| InvalidSignature)?;

    RsaPublicKey::new(
        BigUint::from_bytes_be(ne[0].as_bytes()),
        BigUint::from_bytes_be(ne[1].as_bytes()),
    )
    .map_err(|_| InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_pss() {
        unsafe {
            let mut rng: WC_RNG = mem::zeroed();
            let mut rsa_key: RsaKey = mem::zeroed();
            let mut ret;
            let mut encrypted: [u8; 256] = [0; 256];
            let encrypted_length: word32 = encrypted.len() as word32;
            let text = "message".as_bytes();
            let mut message: [u8; 32] = [0; 32];
            let message_length: word32 = message.len() as word32;
            let text_length = text.len().min(message.len());
            message[..text_length].copy_from_slice(&text[..text_length]);

            ret = wc_InitRsaKey(&mut rsa_key, std::ptr::null_mut());
            if ret != 0 {
                panic!("error while calling wc_InitRsaKey, ret value: {}", ret);
            }

            ret = wc_InitRng(&mut rng);
            if ret != 0 {
                panic!("error while calling wc_InitRng, ret value: {}", ret);
            }

            ret = wc_RsaSetRNG(&mut rsa_key, &mut rng);
            if ret != 0 {
                panic!("error while calling wc_RsaSetRNG, ret value: {}", ret);
            }

            ret = wc_MakeRsaKey(&mut rsa_key, 2048, WC_RSA_EXPONENT.into(), &mut rng);
            if ret != 0 {
                panic!("error while calling wc_MakeRsaKey, ret value: {}", ret);
            }

            ret = wc_RsaPSS_Sign(
                message.as_mut_ptr(), 
                message_length,
                encrypted.as_mut_ptr(), 
                encrypted_length,
                wc_HashType_WC_HASH_TYPE_SHA256, 
                WC_MGF1SHA256.try_into().unwrap(),
                &mut rsa_key, 
                &mut rng
            );
            if ret < 0 {
                panic!("error while calling wc_RsaPSS_Sign, ret value: {}", ret);
            }

            let sig_sz = ret;
            let mut decrypted: [u8; 256] = [0; 256];
            let decrypted_length: word32 = decrypted.len() as word32;

            ret = wc_RsaPSS_Verify(
                encrypted.as_mut_ptr(), 
                sig_sz.try_into().unwrap(), 
                decrypted.as_mut_ptr(), 
                decrypted_length,
                wc_HashType_WC_HASH_TYPE_SHA256, 
                WC_MGF1SHA256.try_into().unwrap(), 
                &mut rsa_key
            );
            if ret < 0 {
                panic!("error while calling wc_RsaPSS_Verify, ret value: {}", ret);
            }

            assert!(ret > 0);
        }
    }
}
