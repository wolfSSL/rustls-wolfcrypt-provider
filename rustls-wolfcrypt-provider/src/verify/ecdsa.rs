use crate::{
    error::{check_if_one, check_if_zero, WCError},
    types::*,
};
use alloc::vec;
use core::mem;
use core::ptr;
use foreign_types::ForeignType;
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use rustls::SignatureScheme;
use webpki::alg_id;
use wolfcrypt_rs::*;

/// A unified ECDSA verifier for P-256, P-384, and P-521.
/// We store the `SignatureScheme` and switch logic accordingly.
#[derive(Debug)]
pub struct EcdsaVerifier {
    scheme: SignatureScheme,
}

impl EcdsaVerifier {
    /// Constructor for P-256 / ECDSA_NISTP256_SHA256
    pub const P256_SHA256: Self = Self {
        scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
    };

    /// Constructor for P-384 / ECDSA_NISTP384_SHA384
    pub const P384_SHA384: Self = Self {
        scheme: SignatureScheme::ECDSA_NISTP384_SHA384,
    };

    /// Constructor for P-521 / ECDSA_NISTP521_SHA512
    pub const P521_SHA512: Self = Self {
        scheme: SignatureScheme::ECDSA_NISTP521_SHA512,
    };
}

impl SignatureVerificationAlgorithm for EcdsaVerifier {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        match self.scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => alg_id::ECDSA_P256,
            SignatureScheme::ECDSA_NISTP384_SHA384 => alg_id::ECDSA_P384,
            SignatureScheme::ECDSA_NISTP521_SHA512 => alg_id::ECDSA_P521,
            _ => unreachable!("Unsupported scheme for ECDSA public_key_alg_id"),
        }
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        match self.scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => alg_id::ECDSA_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384 => alg_id::ECDSA_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512 => alg_id::ECDSA_SHA512,
            _ => unreachable!("Unsupported scheme for ECDSA signature_alg_id"),
        }
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        unsafe {
            // Initialize WolfSSL ECC key
            let mut ecc_c_type: ecc_key = mem::zeroed();
            let ecc_key_object = ECCKeyObject::from_ptr(&mut ecc_c_type);
            ecc_key_object.init();

            let mut ret;
            let mut stat: i32 = 0;

            // Determine curve, how many bytes to skip from public_key, and which hash to use
            let (curve_id, skip_len, wc_hash_type) = match self.scheme {
                SignatureScheme::ECDSA_NISTP256_SHA256 => (
                    ecc_curve_id_ECC_SECP256R1,
                    32,
                    wc_HashType_WC_HASH_TYPE_SHA256,
                ),
                SignatureScheme::ECDSA_NISTP384_SHA384 => (
                    ecc_curve_id_ECC_SECP384R1,
                    48,
                    wc_HashType_WC_HASH_TYPE_SHA384,
                ),
                SignatureScheme::ECDSA_NISTP521_SHA512 => (
                    ecc_curve_id_ECC_SECP521R1,
                    66,
                    wc_HashType_WC_HASH_TYPE_SHA512,
                ),
                _ => return Err(InvalidSignature),
            };

            /*
             * Skipping first byte because rustls uses this format:
             * https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8.2
             *
             * For P-256, skip_len=32 means public_key[1..33] is "x" and [33..65] is "y".
             * For P-384, skip_len=48 means public_key[1..49] is "x" and [49..97] is "y".
             * For P-521, skip_len=66 means public_key[1..67] is "x" and [67..133] is "y".
             */
            ret = wc_ecc_import_unsigned(
                ecc_key_object.as_ptr(),
                public_key[1..(1 + skip_len)].as_ptr(), // Public "x" coordinate
                public_key[(1 + skip_len)..].as_ptr(),  // Public "y" coordinate
                ptr::null_mut(),                        // Private "d" (optional)
                curve_id,
            );
            check_if_zero(ret).unwrap();

            // This function returns the size of the digest (output) for a hash_type.
            // The returned size is used to make sure the output buffer is large enough.
            let digest_sz = wc_HashGetDigestSize(wc_hash_type);

            // This function performs a hash on the provided data buffer and
            // returns it in the hash buffer provided.
            // We hash the message since it's not pre-hashed.
            let mut digest = vec![0u8; digest_sz as usize];
            ret = wc_Hash(
                wc_hash_type,
                message.as_ptr(),
                message.len() as word32,
                digest.as_mut_ptr(),
                digest_sz as word32,
            );
            check_if_zero(ret).unwrap();

            // Finally, verify the signature against the digest
            ret = wc_ecc_verify_hash(
                signature.as_ptr(),
                signature.len() as word32,
                digest.as_ptr(),
                digest_sz as word32,
                &mut stat,
                ecc_key_object.as_ptr(),
            );

            // If stat != 1, signature is invalid
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
