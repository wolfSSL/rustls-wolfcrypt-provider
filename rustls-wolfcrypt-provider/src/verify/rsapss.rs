use crate::error::*;
use crate::types::types::*;
use alloc::vec::Vec;
use core::mem;
use core::ptr;
use der::Reader;
use foreign_types::ForeignType;
use rsa::BigUint;
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
        let mut ret;
        let mut digest: [u8; 32] = [0; 32];
        let mut out: [u8; 256] = [0; 256];
        let mut signature: Vec<u8> = signature.to_vec();

        let mut rsa_key_c_type = wc_decode_spki_spk(public_key)?;
        let rsa_key_object = unsafe { RsaKeyObject::from_ptr(&mut rsa_key_c_type) };

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
        let mut ret;
        let mut digest: [u8; 48] = [0; 48];
        let mut out: [u8; 256] = [0; 256];
        let mut signature: Vec<u8> = signature.to_vec();

        let mut rsa_key_c_type = wc_decode_spki_spk(public_key)?;
        let rsa_key_object = unsafe { RsaKeyObject::from_ptr(&mut rsa_key_c_type) };

        // This function returns the size of the digest (output) for a hash_type.
        // The returns size is used to make sure the output buffer
        // provided to wc_Hash is large enough.
        let digest_sz = unsafe { wc_HashGetDigestSize(wc_HashType_WC_HASH_TYPE_SHA384) };

        // This function performs a hash on the provided data buffer and
        // returns it in the hash buffer provided.
        // In this case we hash with Sha384 (RSA_PSS_SHA384).
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

fn wc_decode_spki_spk(spki_spk: &[u8]) -> Result<RsaKey, InvalidSignature> {
    let mut reader = der::SliceReader::new(spki_spk).map_err(|_| InvalidSignature)?;
    let ne: [der::asn1::UintRef; 2] = reader.decode().map_err(|_| InvalidSignature)?;
    let n = BigUint::from_bytes_be(ne[0].as_bytes());
    let e = BigUint::from_bytes_be(ne[1].as_bytes());
    let n_bytes = n.to_bytes_be();
    let e_bytes = e.to_bytes_be();

    let mut rsa_key_c_type: RsaKey = unsafe { mem::zeroed() };
    let rsa_key_object = unsafe { RsaKeyObject::from_ptr(&mut rsa_key_c_type) };
    let mut ret;

    // This function initializes a provided RsaKey struct. It also takes in a heap identifier,
    // for use with user defined memory overrides (see XMALLOC, XFREE, XREALLOC).
    ret = unsafe { wc_InitRsaKey(rsa_key_object.as_ptr(), ptr::null_mut()) };
    check_if_zero(ret).unwrap();

    // This function decodes the raw elements of an RSA public key, taking in
    // the public modulus (n) and exponent (e). It stores these raw elements in the provided
    // RsaKey structure, allowing one to use them in the encryption/decryption process.
    ret = unsafe {
        wc_RsaPublicKeyDecodeRaw(
            n_bytes.as_ptr(),
            n_bytes.capacity().try_into().unwrap(),
            e_bytes.as_ptr(),
            e_bytes.capacity().try_into().unwrap(),
            rsa_key_object.as_ptr(),
        )
    };

    if let Err(WCError::Failure) = check_if_zero(ret) {
        Err(InvalidSignature)
    } else {
        Ok(rsa_key_c_type)
    }
}
