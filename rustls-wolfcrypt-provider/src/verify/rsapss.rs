use crate::error::*;
use crate::types::types::*;
use alloc::vec::Vec;
use core::mem;
use core::ptr;
use foreign_types::ForeignType;
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use webpki::alg_id;
use wolfcrypt_rs::*;

#[derive(Debug)]
pub struct RsaPssSha256Verify;

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
        let mut digest: [u8; 32] = [0; 32];
        let mut out: [u8; 256] = [0; 256];
        let mut signature: Vec<u8> = signature.to_vec();
        let mut rsa_key_c_type: RsaKey = unsafe { mem::zeroed() };
        let rsa_key_object = unsafe { RsaKeyObject::from_ptr(&mut rsa_key_c_type) };
        let mut ret;

        ret = unsafe { wc_InitRsaKey(rsa_key_object.as_ptr(), ptr::null_mut()) };
        check_if_zero(ret).unwrap();

        // This function returns the size of the digest (output) for a hash_type.
        // The returns size is used to make sure the output buffer
        // provided to wc_Hash is large enough.
        let digest_sz = unsafe { wc_HashGetDigestSize(wc_HashType_WC_HASH_TYPE_SHA256) };

        // This function performs a hash on the provided data buffer and
        // returns it in the hash buffer provided.
        // In this case we hash with Sha256 (RSA_PSS_SHA256).
        // We hash the message since it's not hashed.
        ret = unsafe {
            wc_Hash(
                wc_HashType_WC_HASH_TYPE_SHA256,
                message.as_ptr(),
                message.len() as word32,
                digest.as_mut_ptr(),
                digest_sz as word32,
            )
        };
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

        // Verify the message signed with RSA-PSS.
        // In this case 'message' has been, supposedly,
        // been signed by 'signature'.
        ret = unsafe {
            wc_RsaPSS_VerifyCheck(
                signature.as_mut_ptr(),
                signature.len() as word32,
                out.as_mut_ptr(),
                out.len() as word32,
                digest.as_mut_ptr(),
                digest_sz as word32,
                wc_HashType_WC_HASH_TYPE_SHA256,
                WC_MGF1SHA256.try_into().unwrap(),
                rsa_key_object.as_ptr(),
            )
        };

        if let Err(WCError::Failure) = check_if_greater_than_zero(ret) {
            Err(InvalidSignature)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
pub struct RsaPssSha384Verify;

impl SignatureVerificationAlgorithm for RsaPssSha384Verify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_PSS_SHA384
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let mut digest: [u8; 48] = [0; 48];
        let mut out: [u8; 256] = [0; 256];
        let mut signature: Vec<u8> = signature.to_vec();
        let mut rsa_key_c_type: RsaKey = unsafe { mem::zeroed() };
        let rsa_key_object = unsafe { RsaKeyObject::from_ptr(&mut rsa_key_c_type) };
        let mut ret;

        ret = unsafe { wc_InitRsaKey(rsa_key_object.as_ptr(), ptr::null_mut()) };
        check_if_zero(ret).unwrap();

        // This function returns the size of the digest (output) for a hash_type.
        // The returns size is used to make sure the output buffer
        // provided to wc_Hash is large enough.
        let digest_sz = unsafe { wc_HashGetDigestSize(wc_HashType_WC_HASH_TYPE_SHA384) };

        // This function performs a hash on the provided data buffer and
        // returns it in the hash buffer provided.
        // In this case we hash with Sha256 (RSA_PSS_SHA256).
        // We hash the message since it's not hashed.
        ret = unsafe {
            wc_Hash(
                wc_HashType_WC_HASH_TYPE_SHA384,
                message.as_ptr(),
                message.len() as word32,
                digest.as_mut_ptr(),
                digest_sz as word32,
            )
        };
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

        // Verify the message signed with RSA-PSS.
        // In this case 'message' has been, supposedly,
        // been signed by 'signature'.
        ret = unsafe {
            wc_RsaPSS_VerifyCheck(
                signature.as_mut_ptr(),
                signature.len() as word32,
                out.as_mut_ptr(),
                out.len() as word32,
                digest.as_mut_ptr(),
                digest_sz as word32,
                wc_HashType_WC_HASH_TYPE_SHA384,
                WC_MGF1SHA384.try_into().unwrap(),
                rsa_key_object.as_ptr(),
            )
        };

        if let Err(WCError::Failure) = check_if_greater_than_zero(ret) {
            Err(InvalidSignature)
        } else {
            Ok(())
        }
    }
}


#[derive(Debug)]
pub struct RsaPssSha512Verify;

impl SignatureVerificationAlgorithm for RsaPssSha512Verify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_PSS_SHA512
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let mut digest: [u8; 64] = [0; 64];
        let mut out: [u8; 256] = [0; 256];
        let mut signature: Vec<u8> = signature.to_vec();
        let mut rsa_key_c_type: RsaKey = unsafe { mem::zeroed() };
        let rsa_key_object = unsafe { RsaKeyObject::from_ptr(&mut rsa_key_c_type) };
        let mut ret;

        ret = unsafe { wc_InitRsaKey(rsa_key_object.as_ptr(), ptr::null_mut()) };
        check_if_zero(ret).unwrap();

        // This function returns the size of the digest (output) for a hash_type.
        // The returns size is used to make sure the output buffer
        // provided to wc_Hash is large enough.
        let digest_sz = unsafe { wc_HashGetDigestSize(wc_HashType_WC_HASH_TYPE_SHA512) };

        // This function performs a hash on the provided data buffer and
        // returns it in the hash buffer provided.
        // In this case we hash with Sha256 (RSA_PSS_SHA256).
        // We hash the message since it's not hashed.
        ret = unsafe {
            wc_Hash(
                wc_HashType_WC_HASH_TYPE_SHA512,
                message.as_ptr(),
                message.len() as word32,
                digest.as_mut_ptr(),
                digest_sz as word32,
            )
        };
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

        // Verify the message signed with RSA-PSS.
        // In this case 'message' has been, supposedly,
        // been signed by 'signature'.
        ret = unsafe {
            wc_RsaPSS_VerifyCheck(
                signature.as_mut_ptr(),
                signature.len() as word32,
                out.as_mut_ptr(),
                out.len() as word32,
                digest.as_mut_ptr(),
                digest_sz as word32,
                wc_HashType_WC_HASH_TYPE_SHA512,
                WC_MGF1SHA512.try_into().unwrap(),
                rsa_key_object.as_ptr(),
            )
        };

        if let Err(WCError::Failure) = check_if_greater_than_zero(ret) {
            Err(InvalidSignature)
        } else {
            Ok(())
        }
    }
}