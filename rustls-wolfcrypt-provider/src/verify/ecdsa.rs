use crate::{
    error::{check_if_one, check_if_zero, WCError},
    types::*,
};
use core::mem;
use core::ptr;
use foreign_types::ForeignType;
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use webpki::alg_id;
use wolfcrypt_rs::*;

#[derive(Debug)]
pub struct EcdsaNistp256Sha256;

impl SignatureVerificationAlgorithm for EcdsaNistp256Sha256 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P256
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_SHA256
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        unsafe {
            let mut ecc_c_type: ecc_key = mem::zeroed();
            let ecc_key_object = ECCKeyObject::from_ptr(&mut ecc_c_type);
            let mut digest: [u8; WC_SHA256_DIGEST_SIZE as usize] =
                [0; WC_SHA256_DIGEST_SIZE as usize];
            let mut ret;
            let mut stat: i32 = 0;

            ecc_key_object.init();

            /*
             * Skipping first byte because rustls uses this format:
             * https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8.2.
             * */
            ret = wc_ecc_import_unsigned(
                ecc_key_object.as_ptr(),
                public_key[1..33].as_ptr(), /* Public "x" Coordinate */
                public_key[33..].as_ptr(),  /* Public "y" Coordinate */
                ptr::null_mut(),            /* Private "d" (optional) */
                ecc_curve_id_ECC_SECP256R1, /* ECC Curve Id */
            );
            check_if_zero(ret).unwrap();

            // This function returns the size of the digest (output) for a hash_type.
            // The returns size is used to make sure the output buffer
            // provided to wc_Hash is large enough.
            let digest_sz = wc_HashGetDigestSize(wc_HashType_WC_HASH_TYPE_SHA256);

            // This function performs a hash on the provided data buffer and
            // returns it in the hash buffer provided.
            // In this case we hash with Sha256 (RSA_PSS_SHA256).
            // We hash the message since it's not hashed.
            ret = wc_Hash(
                wc_HashType_WC_HASH_TYPE_SHA256,
                message.as_ptr(),
                message.len() as word32,
                digest.as_mut_ptr(),
                digest_sz as word32,
            );
            check_if_zero(ret).unwrap();

            ret = wc_ecc_verify_hash(
                signature.as_ptr(),
                signature.len() as word32,
                digest.as_ptr(),
                digest_sz as word32,
                &mut stat,
                ecc_key_object.as_ptr(),
            );
            if stat != 1 {
                panic!("ret = {}, stat = {}", ret, stat);
            }

            if let Err(WCError::Failure) = check_if_one(stat) {
                Err(InvalidSignature)
            } else {
                Ok(())
            }
        }
    }
}

#[derive(Debug)]
pub struct EcdsaNistp384Sha384;

impl SignatureVerificationAlgorithm for EcdsaNistp384Sha384 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P384
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_SHA384
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        unsafe {
            let mut ecc_c_type: ecc_key = mem::zeroed();
            let ecc_key_object = ECCKeyObject::from_ptr(&mut ecc_c_type);
            let mut digest: [u8; WC_SHA384_DIGEST_SIZE as usize] =
                [0; WC_SHA384_DIGEST_SIZE as usize];
            let mut ret;
            let mut stat: i32 = 0;

            ecc_key_object.init();

            /*
             * Skipping first byte because rustls uses this format:
             * https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8.2.
             * */
            ret = wc_ecc_import_unsigned(
                ecc_key_object.as_ptr(),
                public_key[1..49].as_ptr(), /* Public "x" Coordinate */
                public_key[49..].as_ptr(),  /* Public "y" Coordinate */
                ptr::null_mut(),            /* Private "d" (optional) */
                ecc_curve_id_ECC_SECP384R1, /* ECC Curve Id */
            );
            check_if_zero(ret).unwrap();

            // This function returns the size of the digest (output) for a hash_type.
            // The returns size is used to make sure the output buffer
            // provided to wc_Hash is large enough.
            let digest_sz = wc_HashGetDigestSize(wc_HashType_WC_HASH_TYPE_SHA384);

            // This function performs a hash on the provided data buffer and
            // returns it in the hash buffer provided.
            // In this case we hash with Sha384.
            // We hash the message since it's not hashed.
            ret = wc_Hash(
                wc_HashType_WC_HASH_TYPE_SHA384,
                message.as_ptr(),
                message.len() as word32,
                digest.as_mut_ptr(),
                digest_sz as word32,
            );
            check_if_zero(ret).unwrap();

            ret = wc_ecc_verify_hash(
                signature.as_ptr(),
                signature.len() as word32,
                digest.as_ptr(),
                digest_sz as word32,
                &mut stat,
                ecc_key_object.as_ptr(),
            );
            if stat != 1 {
                panic!("ret = {}, stat = {}", ret, stat);
            }

            if let Err(WCError::Failure) = check_if_one(stat) {
                Err(InvalidSignature)
            } else {
                Ok(())
            }
        }
    }
}

#[derive(Debug)]
pub struct EcdsaNistp521Sha512;

impl SignatureVerificationAlgorithm for EcdsaNistp521Sha512 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P521
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_SHA512
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        unsafe {
            let mut ecc_c_type: ecc_key = mem::zeroed();
            let ecc_key_object = ECCKeyObject::from_ptr(&mut ecc_c_type);
            let mut digest: [u8; WC_SHA512_DIGEST_SIZE as usize] =
                [0; WC_SHA512_DIGEST_SIZE as usize];
            let mut ret;
            let mut stat: i32 = 0;

            ecc_key_object.init();

            /*
             * Skipping first byte because rustls uses this format:
             * https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8.2.
             * */
            ret = wc_ecc_import_unsigned(
                ecc_key_object.as_ptr(),
                public_key[1..67].as_ptr(), /* Public "x" Coordinate */
                public_key[67..].as_ptr(),  /* Public "y" Coordinate */
                ptr::null_mut(),            /* Private "d" (optional) */
                ecc_curve_id_ECC_SECP521R1, /* ECC Curve Id */
            );
            check_if_zero(ret).unwrap();

            // This function returns the size of the digest (output) for a hash_type.
            // The returns size is used to make sure the output buffer
            // provided to wc_Hash is large enough.
            let digest_sz = wc_HashGetDigestSize(wc_HashType_WC_HASH_TYPE_SHA512);

            // This function performs a hash on the provided data buffer and
            // returns it in the hash buffer provided.
            // In this case we hash with Sha512.
            // We hash the message since it's not hashed.
            ret = wc_Hash(
                wc_HashType_WC_HASH_TYPE_SHA512,
                message.as_ptr(),
                message.len() as word32,
                digest.as_mut_ptr(),
                digest_sz as word32,
            );
            check_if_zero(ret).unwrap();

            ret = wc_ecc_verify_hash(
                signature.as_ptr(),
                signature.len() as word32,
                digest.as_ptr(),
                digest_sz as word32,
                &mut stat,
                ecc_key_object.as_ptr(),
            );
            if stat != 1 {
                panic!("ret = {}, stat = {}", ret, stat);
            }

            if let Err(WCError::Failure) = check_if_one(stat) {
                Err(InvalidSignature)
            } else {
                Ok(())
            }
        }
    }
}
