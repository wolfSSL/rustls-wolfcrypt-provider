use crate::types::*;
use der::Reader;
use foreign_types::ForeignType;
use rsa::BigUint;
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use std::ffi::c_void;
use std::mem;
use webpki::alg_id;
use wolfcrypt_rs::*;

#[derive(Debug)]
pub struct RsaPkcs1Sha256Verify;

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
        unsafe {
            let mut rsa_key_struct = wc_decode_spki_spk(public_key)?;
            let rsa_key_object = RsaKeyObject::from_ptr(&mut rsa_key_struct);

            // Also performs the hashing (SHA256 in this case),
            // see: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Signature.html#function-wc_signatureverify
            let ret = wc_SignatureVerify(
                wc_HashType_WC_HASH_TYPE_SHA256,
                wc_SignatureType_WC_SIGNATURE_TYPE_RSA_W_ENC,
                message.as_ptr(),
                message.len() as word32,
                signature.as_ptr(),
                signature.len() as word32,
                rsa_key_object.as_ptr() as *const c_void,
                mem::size_of_val(&rsa_key_struct).try_into().unwrap(),
            );

            if ret == 0 {
                Ok(())
            } else {
                log::error!("ret value: {}", ret);
                Err(InvalidSignature)
            }
        }
    }
}

#[derive(Debug)]
pub struct RsaPkcs1Sha384Verify;

impl SignatureVerificationAlgorithm for RsaPkcs1Sha384Verify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_PKCS1_SHA384
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        unsafe {
            let mut rsa_key_struct = wc_decode_spki_spk(public_key)?;
            let rsa_key_object = RsaKeyObject::from_ptr(&mut rsa_key_struct);

            // Also performs the hashing (SHA384 in this case),
            // see: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Signature.html#function-wc_signatureverify
            let ret = wc_SignatureVerify(
                wc_HashType_WC_HASH_TYPE_SHA384,
                wc_SignatureType_WC_SIGNATURE_TYPE_RSA_W_ENC,
                message.as_ptr(),
                message.len() as word32,
                signature.as_ptr(),
                signature.len() as word32,
                rsa_key_object.as_ptr() as *const c_void,
                mem::size_of_val(&rsa_key_struct).try_into().unwrap(),
            );

            if ret == 0 {
                Ok(())
            } else {
                log::error!("ret value: {}", ret);
                Err(InvalidSignature)
            }
        }
    }
}

fn wc_decode_spki_spk(spki_spk: &[u8]) -> Result<RsaKey, InvalidSignature> {
    unsafe {
        let mut reader = der::SliceReader::new(spki_spk).map_err(|_| InvalidSignature)?;
        let ne: [der::asn1::UintRef; 2] = reader.decode().map_err(|_| InvalidSignature)?;
        let n = BigUint::from_bytes_be(ne[0].as_bytes());
        let e = BigUint::from_bytes_be(ne[1].as_bytes());
        let n_bytes = n.to_bytes_be();
        let e_bytes = e.to_bytes_be();

        let mut rsa_key_struct: RsaKey = mem::zeroed();
        let rsa_key_object = RsaKeyObject::from_ptr(&mut rsa_key_struct);
        let mut ret;

        // This function initializes a provided RsaKey struct. It also takes in a heap identifier,
        // for use with user defined memory overrides (see XMALLOC, XFREE, XREALLOC).
        ret = wc_InitRsaKey(rsa_key_object.as_ptr(), std::ptr::null_mut());
        if ret != 0 {
            panic!("error while calling wc_InitRsaKey, ret value: {}", ret);
        }

        // This function decodes the raw elements of an RSA public key, taking in
        // the public modulus (n) and exponent (e). It stores these raw elements in the provided
        // RsaKey structure, allowing one to use them in the encryption/decryption process.
        ret = wc_RsaPublicKeyDecodeRaw(
            n_bytes.as_ptr(),
            n_bytes.capacity().try_into().unwrap(),
            e_bytes.as_ptr(),
            e_bytes.capacity().try_into().unwrap(),
            rsa_key_object.as_ptr(),
        );

        if ret == 0 {
            Ok(rsa_key_struct)
        } else {
            log::error!("ret value: {}", ret);
            Err(InvalidSignature)
        }
    }
}
