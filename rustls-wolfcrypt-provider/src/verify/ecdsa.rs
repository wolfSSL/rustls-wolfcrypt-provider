use crate::types::*;
use foreign_types::ForeignType;
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use std::mem;
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
            let ecc_object = ECCKeyObject::from_ptr(&mut ecc_c_type);
            let mut digest: [u8; 32] = [0; 32];
            let mut ret;
            let mut stat: i32 = 0;

            ret = wc_ecc_init(ecc_object.as_ptr());
            if ret != 0 {
                panic!("failed when calling wc_ecc_init, ret = {}", ret);
            }

            /* Import public key x/y */
            ret = wc_ecc_import_unsigned(
                ecc_object.as_ptr(),
                public_key[1..33].as_ptr(), /* Public "x" Coordinate */
                public_key[33..].as_ptr(),  /* Public "y" Coordinate */
                std::ptr::null_mut(),       /* Private "d" (optional) */
                ecc_curve_id_ECC_SECP256R1, /* ECC Curve Id */
            );
            if ret != 0 {
                panic!("failed when calling wc_ecc_import_unsigned, ret = {}", ret);
            }

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
            if ret != 0 {
                panic!("error while calling wc_hash, ret = {}", ret);
            }

            ret = wc_ecc_verify_hash(
                signature.as_ptr(),
                signature.len() as word32,
                digest.as_ptr(),
                digest_sz as word32,
                &mut stat,
                ecc_object.as_ptr(),
            );
            if ret != 0 {
                panic!("error while calling wc_ecc_verify_hash, ret = {}", ret);
            }

            if stat == 1 {
                Ok(())
            } else {
                log::error!("stat value in EcdsaNistp256Sha256: {}", ret);
                Err(InvalidSignature)
            }
        }
    }
}

#[derive(Debug)]
pub struct EcdsaNistp384Sha256;

impl SignatureVerificationAlgorithm for EcdsaNistp384Sha256 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P384
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
            let ecc_object = ECCKeyObject::from_ptr(&mut ecc_c_type);
            let mut digest: [u8; 32] = [0; 32];
            let mut ret;
            let mut stat: i32 = 0;

            ret = wc_ecc_init(ecc_object.as_ptr());
            if ret != 0 {
                panic!("failed when calling wc_ecc_init, ret = {}", ret);
            }

            /* Import public key x/y */
            ret = wc_ecc_import_unsigned(
                ecc_object.as_ptr(),
                public_key[1..49].as_ptr(), /* Public "x" Coordinate */
                public_key[49..].as_ptr(),  /* Public "y" Coordinate */
                std::ptr::null_mut(),       /* Private "d" (optional) */
                ecc_curve_id_ECC_SECP384R1, /* ECC Curve Id */
            );
            if ret != 0 {
                panic!("failed when calling wc_ecc_import_unsigned, ret = {}", ret);
            }

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
            if ret != 0 {
                panic!("error while calling wc_hash, ret = {}", ret);
            }

            ret = wc_ecc_verify_hash(
                signature.as_ptr(),
                signature.len() as word32,
                digest.as_ptr(),
                digest_sz as word32,
                &mut stat,
                ecc_object.as_ptr(),
            );
            if ret != 0 {
                panic!("error while calling wc_ecc_verify_hash, ret = {}", ret);
            }

            if stat == 1 {
                Ok(())
            } else {
                log::error!("stat value in EcdsaNistp384Sha256: {}", ret);
                Err(InvalidSignature)
            }
        }
    }
}

#[derive(Debug)]
pub struct EcdsaNistp256Sha384;

impl SignatureVerificationAlgorithm for EcdsaNistp256Sha384 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P256
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
            let ecc_object = ECCKeyObject::from_ptr(&mut ecc_c_type);
            let mut digest: [u8; 48] = [0; 48];
            let mut ret;
            let mut stat: i32 = 0;

            ret = wc_ecc_init(ecc_object.as_ptr());
            if ret != 0 {
                panic!("failed when calling wc_ecc_init, ret = {}", ret);
            }

            /* Import public key x/y */
            ret = wc_ecc_import_unsigned(
                ecc_object.as_ptr(),
                public_key[1..33].as_ptr(), /* Public "x" Coordinate */
                public_key[33..].as_ptr(),  /* Public "y" Coordinate */
                std::ptr::null_mut(),       /* Private "d" (optional) */
                ecc_curve_id_ECC_SECP256R1, /* ECC Curve Id */
            );
            if ret != 0 {
                panic!("failed when calling wc_ecc_import_unsigned, ret = {}", ret);
            }

            // This function returns the size of the digest (output) for a hash_type.
            // The returns size is used to make sure the output buffer
            // provided to wc_Hash is large enough.
            let digest_sz = wc_HashGetDigestSize(wc_HashType_WC_HASH_TYPE_SHA384);

            // This function performs a hash on the provided data buffer and
            // returns it in the hash buffer provided.
            // In this case we hash with Sha384 (RSA_PSS_SHA384).
            // We hash the message since it's not hashed.
            ret = wc_Hash(
                wc_HashType_WC_HASH_TYPE_SHA384,
                message.as_ptr(),
                message.len() as word32,
                digest.as_mut_ptr(),
                digest_sz as word32,
            );
            if ret != 0 {
                panic!("error while calling wc_hash, ret = {}", ret);
            }

            ret = wc_ecc_verify_hash(
                signature.as_ptr(),
                signature.len() as word32,
                digest.as_ptr(),
                digest_sz as word32,
                &mut stat,
                ecc_object.as_ptr(),
            );
            if ret != 0 {
                panic!("error while calling wc_ecc_verify_hash, ret = {}", ret);
            }

            if stat == 1 {
                Ok(())
            } else {
                log::error!("stat value in EcdsaNistp256Sha384: {}", ret);
                Err(InvalidSignature)
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
            let ecc_object = ECCKeyObject::from_ptr(&mut ecc_c_type);
            let mut digest: [u8; 48] = [0; 48];
            let mut ret;
            let mut stat: i32 = 0;

            ret = wc_ecc_init(ecc_object.as_ptr());
            if ret != 0 {
                panic!("failed when calling wc_ecc_init, ret = {}", ret);
            }

            /* Import public key x/y */
            ret = wc_ecc_import_unsigned(
                ecc_object.as_ptr(),
                public_key[1..49].as_ptr(), /* Public "x" Coordinate */
                public_key[49..].as_ptr(),  /* Public "y" Coordinate */
                std::ptr::null_mut(),       /* Private "d" (optional) */
                ecc_curve_id_ECC_SECP384R1, /* ECC Curve Id */
            );
            if ret != 0 {
                panic!("failed when calling wc_ecc_import_unsigned, ret = {}", ret);
            }

            // This function returns the size of the digest (output) for a hash_type.
            // The returns size is used to make sure the output buffer
            // provided to wc_Hash is large enough.
            let digest_sz = wc_HashGetDigestSize(wc_HashType_WC_HASH_TYPE_SHA384);

            // This function performs a hash on the provided data buffer and
            // returns it in the hash buffer provided.
            // In this case we hash with Sha256 (RSA_PSS_SHA256).
            // We hash the message since it's not hashed.
            ret = wc_Hash(
                wc_HashType_WC_HASH_TYPE_SHA384,
                message.as_ptr(),
                message.len() as word32,
                digest.as_mut_ptr(),
                digest_sz as word32,
            );
            if ret != 0 {
                panic!("error while calling wc_hash, ret = {}", ret);
            }

            ret = wc_ecc_verify_hash(
                signature.as_ptr(),
                signature.len() as word32,
                digest.as_ptr(),
                digest_sz as word32,
                &mut stat,
                ecc_object.as_ptr(),
            );
            if ret != 0 {
                panic!("error while calling wc_ecc_verify_hash, ret = {}", ret);
            }

            if stat == 1 {
                Ok(())
            } else {
                log::error!("stat value in EcdsaNistp384Sha384: {}", ret);
                Err(InvalidSignature)
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
            let ecc_object = ECCKeyObject::from_ptr(&mut ecc_c_type);

            let mut digest: [u8; 64] = [0; 64];
            let mut ret;
            let mut stat: i32 = 0;

            ret = wc_ecc_init(ecc_object.as_ptr());
            if ret != 0 {
                panic!("failed when calling wc_ecc_init, ret = {}", ret);
            }

            /* Import public key x/y */
            ret = wc_ecc_import_unsigned(
                ecc_object.as_ptr(),
                public_key[1..67].as_ptr(), /* Public "x" Coordinate */
                public_key[67..].as_ptr(),  /* Public "y" Coordinate */
                std::ptr::null_mut(),       /* Private "d" (optional) */
                ecc_curve_id_ECC_SECP521R1, /* ECC Curve Id */
            );
            if ret != 0 {
                panic!("failed when calling wc_ecc_import_unsigned, ret = {}", ret);
            }

            // This function returns the size of the digest (output) for a hash_type.
            // The returns size is used to make sure the output buffer
            // provided to wc_Hash is large enough.
            let digest_sz = wc_HashGetDigestSize(wc_HashType_WC_HASH_TYPE_SHA512);

            // This function performs a hash on the provided data buffer and
            // returns it in the hash buffer provided.
            // In this case we hash with Sha256 (RSA_PSS_SHA256).
            // We hash the message since it's not hashed.
            ret = wc_Hash(
                wc_HashType_WC_HASH_TYPE_SHA512,
                message.as_ptr(),
                message.len() as word32,
                digest.as_mut_ptr(),
                digest_sz as word32,
            );
            if ret != 0 {
                panic!("error while calling wc_hash, ret = {}", ret);
            }

            ret = wc_ecc_verify_hash(
                signature.as_ptr(),
                signature.len() as word32,
                digest.as_ptr(),
                digest_sz as word32,
                &mut stat,
                ecc_object.as_ptr(),
            );
            if ret != 0 {
                panic!("error while calling wc_ecc_verify_hash, ret = {}", ret);
            }

            if stat == 1 {
                Ok(())
            } else {
                log::error!("stat value in EcdsaNistp521Sha512: {}", ret);
                Err(InvalidSignature)
            }
        }
    }
}
