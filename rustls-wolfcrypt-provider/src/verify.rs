use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use rustls::SignatureScheme;
use webpki::alg_id;
use wolfcrypt_rs::*;
use std::mem;

pub static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[RSA_PSS_SHA256],
    mapping: &[
        (SignatureScheme::RSA_PSS_SHA256, &[RSA_PSS_SHA256]),
    ],
};

static RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm = &RsaPssSha256Verify;

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
            let mut idx: word32 = 0 as word32;
            let mut rsa_key: RsaKey = mem::zeroed();
            let mut ret;

            ret = wc_InitRsaKey(&mut rsa_key, std::ptr::null_mut());
            if ret != 0 {
                panic!("error while calling wc_InitRsaKey, ret value: {}", ret);
            }

            ret = wc_RsaPublicKeyDecode(
                public_key.as_ptr(),
                &mut idx,
                &mut rsa_key,
                public_key.len() as word32,
            );
            if ret != 0 {
                panic!("error while calling wc_RsaPublicKeyDecode, ret value: {}", ret);
            }

            let mut decrypted: [u8; 256] = [0; 256];
            let decrypted_length: word32 = decrypted.len() as word32;

            ret = wc_RsaPSS_Verify(
                message.as_ptr() as *mut u8, 
                signature.len().try_into().unwrap(), 
                decrypted.as_mut_ptr(), 
                decrypted_length,
                wc_HashType_WC_HASH_TYPE_SHA256, 
                WC_MGF1SHA256.try_into().unwrap(), 
                &mut rsa_key
            );
            if ret < 0 {
                panic!("error while calling wc_RsaPSS_Verify, ret value: {}", ret);
            }

            if ret > 0 { 
                Ok(()) 
            } else { 
                Err(InvalidSignature) 
            }
        }
    }
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
