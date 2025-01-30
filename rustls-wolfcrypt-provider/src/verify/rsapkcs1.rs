use crate::error::check_if_zero;
use crate::error::*;
use crate::types::types::*;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::mem;
use foreign_types::ForeignType;
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};

use core::ptr;
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
        let signature: Vec<u8> = signature.to_vec();
        let mut rsa_key_c_type: RsaKey = unsafe { mem::zeroed() };
        let rsa_key_object = unsafe { RsaKeyObject::from_ptr(&mut rsa_key_c_type) };
        let mut ret;

        ret = unsafe { wc_InitRsaKey(rsa_key_object.as_ptr(), ptr::null_mut()) };
        check_if_zero(ret).unwrap();

        let mut idx = 0;
        ret = unsafe {
            wc_RsaPublicKeyDecode(
                public_key.as_ptr(),
                &mut idx,
                rsa_key_object.as_ptr(),
                public_key.len() as word32,
            )
        };
        check_if_zero(ret).unwrap();

        let derefenced_rsa_key_c_type = unsafe { *(rsa_key_object.as_ptr()) };

        // Verify the message signed with RSA-PSS.
        // In this case 'message' has been, supposedly,
        // been signed by 'signature'.
        // Also takes care of the hashing:
        // https://www.wolfssl.com/documentation/manuals/wolfssl/group__Signature.html#function-wc_signatureverify.
        ret = unsafe {
            wc_SignatureVerify(
                wc_HashType_WC_HASH_TYPE_SHA256,
                wc_SignatureType_WC_SIGNATURE_TYPE_RSA_W_ENC,
                message.as_ptr(),
                message.len() as word32,
                signature.as_ptr(),
                signature.len() as word32,
                rsa_key_object.as_ptr() as *const c_void,
                mem::size_of_val(&derefenced_rsa_key_c_type)
                    .try_into()
                    .unwrap(),
            )
        };

        if let Err(WCError::Failure) = check_if_zero(ret) {
            Err(InvalidSignature)
        } else {
            Ok(())
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
        let signature: Vec<u8> = signature.to_vec();
        let mut rsa_key_c_type: RsaKey = unsafe { mem::zeroed() };
        let rsa_key_object = unsafe { RsaKeyObject::from_ptr(&mut rsa_key_c_type) };
        let mut ret;

        ret = unsafe { wc_InitRsaKey(rsa_key_object.as_ptr(), ptr::null_mut()) };
        check_if_zero(ret).unwrap();

        let mut idx = 0;
        ret = unsafe {
            wc_RsaPublicKeyDecode(
                public_key.as_ptr(),
                &mut idx,
                rsa_key_object.as_ptr(),
                public_key.len() as word32,
            )
        };
        check_if_zero(ret).unwrap();

        let dereferenced_rsa_key_c_type = unsafe { *(rsa_key_object.as_ptr()) };

        // Verify the message signed with RSA-PSS.
        // In this case 'message' has been, supposedly,
        // been signed by 'signature'.
        // Also takes care of the hashing:
        // https://www.wolfssl.com/documentation/manuals/wolfssl/group__Signature.html#function-wc_signatureverify.
        ret = unsafe {
            wc_SignatureVerify(
                wc_HashType_WC_HASH_TYPE_SHA384,
                wc_SignatureType_WC_SIGNATURE_TYPE_RSA_W_ENC,
                message.as_ptr(),
                message.len() as word32,
                signature.as_ptr(),
                signature.len() as word32,
                rsa_key_object.as_ptr() as *const c_void,
                mem::size_of_val(&dereferenced_rsa_key_c_type).try_into().unwrap(),
            )
        };

        if let Err(WCError::Failure) = check_if_zero(ret) {
            Err(InvalidSignature)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
pub struct RsaPkcs1Sha512Verify;

impl SignatureVerificationAlgorithm for RsaPkcs1Sha512Verify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_PKCS1_SHA512
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let signature: Vec<u8> = signature.to_vec();
        let mut rsa_key_c_type: RsaKey = unsafe { mem::zeroed() };
        let rsa_key_object = unsafe { RsaKeyObject::from_ptr(&mut rsa_key_c_type) };
        let mut ret;

        ret = unsafe { wc_InitRsaKey(rsa_key_object.as_ptr(), ptr::null_mut()) };
        check_if_zero(ret).unwrap();

        let mut idx = 0;
        ret = unsafe {
            wc_RsaPublicKeyDecode(
                public_key.as_ptr(),
                &mut idx,
                rsa_key_object.as_ptr(),
                public_key.len() as word32,
            )
        };
        check_if_zero(ret).unwrap();

        let dereferenced_rsa_key_c_type = unsafe { *(rsa_key_object.as_ptr()) };

        // Verify the message signed with RSA-PSS.
        // In this case 'message' has been, supposedly,
        // been signed by 'signature'.
        // Also takes care of the hashing:
        // https://www.wolfssl.com/documentation/manuals/wolfssl/group__Signature.html#function-wc_signatureverify.
        ret = unsafe {
            wc_SignatureVerify(
                wc_HashType_WC_HASH_TYPE_SHA512,
                wc_SignatureType_WC_SIGNATURE_TYPE_RSA_W_ENC,
                message.as_ptr(),
                message.len() as word32,
                signature.as_ptr(),
                signature.len() as word32,
                rsa_key_object.as_ptr() as *const c_void,
                mem::size_of_val(&dereferenced_rsa_key_c_type).try_into().unwrap(),
            )
        };

        if let Err(WCError::Failure) = check_if_zero(ret) {
            Err(InvalidSignature)
        } else {
            Ok(())
        }
    }
}
