use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use rustls::SignatureScheme;
use webpki::alg_id;
use wolfcrypt_rs::*;
use std::mem;
use foreign_types::{ForeignType, ForeignTypeRef, Opaque};
use std::ptr::NonNull;
use der::Reader;
use std::vec::Vec;
use rsa::{BigUint};
use std::ffi::c_void;

pub static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, ECDSA_P256_SHA256, ECDSA_P384_SHA256, ECDSA_P256_SHA384, ECDSA_P384_SHA384, ECDSA_P521_SHA512],
    mapping: &[
        (SignatureScheme::RSA_PSS_SHA256, &[RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PSS_SHA384, &[RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[RSA_PKCS1_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[RSA_PKCS1_SHA384]),
        (SignatureScheme::ECDSA_NISTP256_SHA256, &[ECDSA_P256_SHA256, ECDSA_P384_SHA256]),
        (SignatureScheme::ECDSA_NISTP384_SHA384, &[ECDSA_P256_SHA384, ECDSA_P384_SHA384]),
        (SignatureScheme::ECDSA_NISTP521_SHA512, &[ECDSA_P521_SHA512]),
    ],
};

static RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm = &RsaPssSha256Verify;
static RSA_PSS_SHA384: &dyn SignatureVerificationAlgorithm = &RsaPssSha384Verify;
static RSA_PKCS1_SHA256: &dyn SignatureVerificationAlgorithm = &RsaPkcs1Sha256Verify;
static RSA_PKCS1_SHA384: &dyn SignatureVerificationAlgorithm = &RsaPkcs1Sha384Verify;
static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &EcdsaNistp256Sha256;
static ECDSA_P256_SHA384: &dyn SignatureVerificationAlgorithm = &EcdsaNistp256Sha384;
static ECDSA_P384_SHA256: &dyn SignatureVerificationAlgorithm = &EcdsaNistp384Sha256;
static ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &EcdsaNistp384Sha384;
static ECDSA_P521_SHA512: &dyn SignatureVerificationAlgorithm = &EcdsaNistp521Sha512;

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
            let mut ret;
            let digest_sz;
            let mut digest: [u8; 32] = [0; 32];
            let mut out: [u8; 256] = [0; 256];
            let mut signature: Vec<u8> = signature.to_vec();

            let mut rsa_key_struct = wc_decode_spki_spk(public_key)?;
            let rsa_key_object = RsaKeyObject::from_ptr(&mut rsa_key_struct);


            // This function returns the size of the digest (output) for a hash_type. 
            // The returns size is used to make sure the output buffer 
            // provided to wc_Hash is large enough.
            digest_sz = wc_HashGetDigestSize(
                wc_HashType_WC_HASH_TYPE_SHA256
            );

            // This function performs a hash on the provided data buffer and 
            // returns it in the hash buffer provided.
            // In this case we hash with Sha256 (RSA_PSS_SHA256).
            // We hash the message since it's not hashed.
            ret = wc_Hash(
                    wc_HashType_WC_HASH_TYPE_SHA256, 
                    message.as_ptr(), 
                    message.len() as word32, 
                    digest.as_mut_ptr(), 
                    digest_sz as word32
            );
            if ret != 0 {
                panic!("error while calling wc_hash, ret = {}", ret);
            } 

            // Verify the message signed with RSA-PSS.
            // In this case 'message' has been, supposedly, 
            // been signed by 'signature'.
            ret = wc_RsaPSS_VerifyCheck(
                    signature.as_mut_ptr(), 
                    signature.len() as word32, 
                    out.as_mut_ptr(), 
                    out.len() as word32,
                    digest.as_mut_ptr(), 
                    digest_sz as word32, 
                    wc_HashType_WC_HASH_TYPE_SHA256, 
                    WC_MGF1SHA256.try_into().unwrap(), 
                    rsa_key_object.as_ptr()
            );

            if ret >= 0 { 
                Ok(()) 
            } else { 
                log::error!("value of ret: {}", ret);
                Err(InvalidSignature) 
            }
        }
    }
}

#[derive(Debug)]
struct RsaPssSha384Verify;

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
        unsafe {
            let mut ret;
            let digest_sz;
            let mut digest: [u8; 48] = [0; 48];
            let mut out: [u8; 256] = [0; 256];
            let mut signature: Vec<u8> = signature.to_vec();

            let mut rsa_key_struct = wc_decode_spki_spk(public_key)?;
            let rsa_key_object = RsaKeyObject::from_ptr(&mut rsa_key_struct);


            // This function returns the size of the digest (output) for a hash_type. 
            // The returns size is used to make sure the output buffer 
            // provided to wc_Hash is large enough.
            digest_sz = wc_HashGetDigestSize(
                wc_HashType_WC_HASH_TYPE_SHA384
            );

            // This function performs a hash on the provided data buffer and 
            // returns it in the hash buffer provided.
            // In this case we hash with Sha384 (RSA_PSS_SHA384).
            // We hash the message since it's not hashed.
            ret = wc_Hash(
                    wc_HashType_WC_HASH_TYPE_SHA384, 
                    message.as_ptr(), 
                    message.len() as word32, 
                    digest.as_mut_ptr(), 
                    digest_sz as word32
            );
            if ret != 0 {
                panic!("error while calling wc_hash, ret = {}", ret);
            } 

            // Verify the message signed with RSA-PSS.
            // In this case 'message' has been, supposedly, 
            // been signed by 'signature'.
            ret = wc_RsaPSS_VerifyCheck(
                    signature.as_mut_ptr(), 
                    signature.len() as word32, 
                    out.as_mut_ptr(), 
                    out.len() as word32,
                    digest.as_mut_ptr(), 
                    digest_sz as word32, 
                    wc_HashType_WC_HASH_TYPE_SHA384, 
                    WC_MGF1SHA384.try_into().unwrap(), 
                    rsa_key_object.as_ptr()
            );

            if ret >= 0 { 
                Ok(()) 
            } else { 
                log::error!("value of ret: {}", ret);
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
        unsafe {
            let mut rsa_key_struct = wc_decode_spki_spk(public_key)?;
            let rsa_key_object = RsaKeyObject::from_ptr(&mut rsa_key_struct);
            let ret;

            // Also performs the hashing (SHA256 in this case), 
            // see: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Signature.html#function-wc_signatureverify
            ret = wc_SignatureVerify(
                    wc_HashType_WC_HASH_TYPE_SHA256, 
                    wc_SignatureType_WC_SIGNATURE_TYPE_RSA_W_ENC,
                    message.as_ptr(), 
                    message.len() as word32,
                    signature.as_ptr(), 
                    signature.len() as word32,
                    rsa_key_object.as_ptr() as *const c_void, 
                    mem::size_of_val(&rsa_key_struct).try_into().unwrap()
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
struct RsaPkcs1Sha384Verify;

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
            let ret;

            // Also performs the hashing (SHA384 in this case), 
            // see: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Signature.html#function-wc_signatureverify
            ret = wc_SignatureVerify(
                    wc_HashType_WC_HASH_TYPE_SHA384, 
                    wc_SignatureType_WC_SIGNATURE_TYPE_RSA_W_ENC,
                    message.as_ptr(), 
                    message.len() as word32,
                    signature.as_ptr(), 
                    signature.len() as word32,
                    rsa_key_object.as_ptr() as *const c_void, 
                    mem::size_of_val(&rsa_key_struct).try_into().unwrap()
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
struct EcdsaNistp256Sha256;

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
            let mut ecc_struct: ecc_key = mem::zeroed();
            let ecc_object = ECCKeyObject::from_ptr(&mut ecc_struct);
            let digest_sz;
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
                public_key[1..33].as_ptr(),                        /* Public "x" Coordinate */
                public_key[33..].as_ptr(),       /* Public "y" Coordinate */
                std::ptr::null_mut(),                       /* Private "d" (optional) */
                ecc_curve_id_ECC_SECP256R1                  /* ECC Curve Id */
            );
            if ret != 0 {
                panic!("failed when calling wc_ecc_import_unsigned, ret = {}", ret);
            }

            // This function returns the size of the digest (output) for a hash_type.
            // The returns size is used to make sure the output buffer
            // provided to wc_Hash is large enough.
            digest_sz = wc_HashGetDigestSize(
                wc_HashType_WC_HASH_TYPE_SHA256
            );

            // This function performs a hash on the provided data buffer and
            // returns it in the hash buffer provided.
            // In this case we hash with Sha256 (RSA_PSS_SHA256).
            // We hash the message since it's not hashed.
            ret = wc_Hash(
                wc_HashType_WC_HASH_TYPE_SHA256,
                message.as_ptr(),
                message.len() as word32,
                digest.as_mut_ptr(),
                digest_sz as word32
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
                ecc_object.as_ptr()
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
struct EcdsaNistp384Sha256;

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
            let mut ecc_struct: ecc_key = mem::zeroed();
            let ecc_object = ECCKeyObject::from_ptr(&mut ecc_struct);
            let digest_sz;
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
                public_key[1..49].as_ptr(),                        /* Public "x" Coordinate */
                public_key[49..].as_ptr(),       /* Public "y" Coordinate */
                std::ptr::null_mut(),                       /* Private "d" (optional) */
                ecc_curve_id_ECC_SECP384R1                  /* ECC Curve Id */
            );
            if ret != 0 {
                panic!("failed when calling wc_ecc_import_unsigned, ret = {}", ret);
            }

            // This function returns the size of the digest (output) for a hash_type.
            // The returns size is used to make sure the output buffer
            // provided to wc_Hash is large enough.
            digest_sz = wc_HashGetDigestSize(
                wc_HashType_WC_HASH_TYPE_SHA256
            );

            // This function performs a hash on the provided data buffer and
            // returns it in the hash buffer provided.
            // In this case we hash with Sha256 (RSA_PSS_SHA256).
            // We hash the message since it's not hashed.
            ret = wc_Hash(
                wc_HashType_WC_HASH_TYPE_SHA256,
                message.as_ptr(),
                message.len() as word32,
                digest.as_mut_ptr(),
                digest_sz as word32
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
                ecc_object.as_ptr()
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
struct EcdsaNistp256Sha384;

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
            let mut ecc_struct: ecc_key = mem::zeroed();
            let ecc_object = ECCKeyObject::from_ptr(&mut ecc_struct);
            let digest_sz;
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
                public_key[1..33].as_ptr(),                        /* Public "x" Coordinate */
                public_key[33..].as_ptr(),       /* Public "y" Coordinate */
                std::ptr::null_mut(),                       /* Private "d" (optional) */
                ecc_curve_id_ECC_SECP256R1                  /* ECC Curve Id */
            );
            if ret != 0 {
                panic!("failed when calling wc_ecc_import_unsigned, ret = {}", ret);
            }

            // This function returns the size of the digest (output) for a hash_type.
            // The returns size is used to make sure the output buffer
            // provided to wc_Hash is large enough.
            digest_sz = wc_HashGetDigestSize(
                wc_HashType_WC_HASH_TYPE_SHA384
            );

            // This function performs a hash on the provided data buffer and
            // returns it in the hash buffer provided.
            // In this case we hash with Sha384 (RSA_PSS_SHA384).
            // We hash the message since it's not hashed.
            ret = wc_Hash(
                wc_HashType_WC_HASH_TYPE_SHA384,
                message.as_ptr(),
                message.len() as word32,
                digest.as_mut_ptr(),
                digest_sz as word32
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
                ecc_object.as_ptr()
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
struct EcdsaNistp384Sha384;

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
            let mut ecc_struct: ecc_key = mem::zeroed();
            let ecc_object = ECCKeyObject::from_ptr(&mut ecc_struct);
            let digest_sz;
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
                public_key[1..49].as_ptr(),                 /* Public "x" Coordinate */
                public_key[49..].as_ptr(),                  /* Public "y" Coordinate */
                std::ptr::null_mut(),                       /* Private "d" (optional) */
                ecc_curve_id_ECC_SECP384R1                  /* ECC Curve Id */
            );
            if ret != 0 {
                panic!("failed when calling wc_ecc_import_unsigned, ret = {}", ret);
            }

            // This function returns the size of the digest (output) for a hash_type.
            // The returns size is used to make sure the output buffer
            // provided to wc_Hash is large enough.
            digest_sz = wc_HashGetDigestSize(
                wc_HashType_WC_HASH_TYPE_SHA384
            );

            // This function performs a hash on the provided data buffer and
            // returns it in the hash buffer provided.
            // In this case we hash with Sha256 (RSA_PSS_SHA256).
            // We hash the message since it's not hashed.
            ret = wc_Hash(
                wc_HashType_WC_HASH_TYPE_SHA384,
                message.as_ptr(),
                message.len() as word32,
                digest.as_mut_ptr(),
                digest_sz as word32
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
                ecc_object.as_ptr()
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
struct EcdsaNistp521Sha512;

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
            let mut ecc_struct: ecc_key = mem::zeroed();
            let ecc_object = ECCKeyObject::from_ptr(&mut ecc_struct);
            let digest_sz;
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
                public_key[1..67].as_ptr(),                 /* Public "x" Coordinate */
                public_key[67..].as_ptr(),                  /* Public "y" Coordinate */
                std::ptr::null_mut(),                       /* Private "d" (optional) */
                ecc_curve_id_ECC_SECP521R1                  /* ECC Curve Id */
            );
            if ret != 0 {
                panic!("failed when calling wc_ecc_import_unsigned, ret = {}", ret);
            }

            // This function returns the size of the digest (output) for a hash_type.
            // The returns size is used to make sure the output buffer
            // provided to wc_Hash is large enough.
            digest_sz = wc_HashGetDigestSize(
                wc_HashType_WC_HASH_TYPE_SHA512
            );

            // This function performs a hash on the provided data buffer and
            // returns it in the hash buffer provided.
            // In this case we hash with Sha256 (RSA_PSS_SHA256).
            // We hash the message since it's not hashed.
            ret = wc_Hash(
                wc_HashType_WC_HASH_TYPE_SHA512,
                message.as_ptr(),
                message.len() as word32,
                digest.as_mut_ptr(),
                digest_sz as word32
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
                ecc_object.as_ptr()
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


fn wc_decode_spki_spk(spki_spk: &[u8]) -> Result<RsaKey, InvalidSignature> {
    unsafe {
        let mut reader = der::SliceReader::new(spki_spk).map_err(|_| InvalidSignature)?;
        let ne: [der::asn1::UintRef; 2] = reader
            .decode()
            .map_err(|_| InvalidSignature)?;
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
                rsa_key_object.as_ptr()
        );

        if ret == 0 {
            Ok(rsa_key_struct)
        } else {
            log::error!("ret value: {}", ret);
            Err(InvalidSignature)
        }
    }
}

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

pub struct ECCKeyObjectRef(Opaque);
unsafe impl ForeignTypeRef for ECCKeyObjectRef {
    type CType = ecc_key;
}

#[derive(Debug, Clone)]
pub struct ECCKeyObject(NonNull<ecc_key>);
unsafe impl Sync for ECCKeyObject{}
unsafe impl Send for ECCKeyObject{}
unsafe impl ForeignType for ECCKeyObject {
    type CType = ecc_key;

    type Ref = ECCKeyObjectRef;

    unsafe fn from_ptr(ptr: *mut Self::CType) -> Self {
        Self(NonNull::new_unchecked(ptr))
    }

    fn as_ptr(&self) -> *mut Self::CType {
        self.0.as_ptr()
    }
}
