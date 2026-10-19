use super::Hash;
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use rustls_pki_types::alg_id;
use wolfssl_wolfcrypt::rsa::RSA;

const RSA_PSS_SIG_SIZE: usize = 512;

/// Verify the message signed with RSA-PSS.
/// In this case 'message' has been, supposedly,
/// been signed by 'signature'.
fn verify_pss(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    hash: Hash,
    hash_type: u32,
    mgf: i32,
) -> Result<(), InvalidSignature> {
    let mut out = [0u8; RSA_PSS_SIG_SIZE];
    let mut key = RSA::new_public_from_der(public_key).map_err(|_| InvalidSignature)?;

    // We hash the message since it's not hashed.
    let (digest, digest_len) = hash.digest(message)?;

    match key.pss_verify_check(signature, &mut out, &digest[..digest_len], hash_type, mgf) {
        Ok(len) if len > 0 => Ok(()),
        _ => Err(InvalidSignature),
    }
}

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
        verify_pss(
            public_key,
            message,
            signature,
            Hash::Sha256,
            RSA::HASH_TYPE_SHA256,
            RSA::MGF1SHA256,
        )
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
        verify_pss(
            public_key,
            message,
            signature,
            Hash::Sha384,
            RSA::HASH_TYPE_SHA384,
            RSA::MGF1SHA384,
        )
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
        verify_pss(
            public_key,
            message,
            signature,
            Hash::Sha512,
            RSA::HASH_TYPE_SHA512,
            RSA::MGF1SHA512,
        )
    }
}
