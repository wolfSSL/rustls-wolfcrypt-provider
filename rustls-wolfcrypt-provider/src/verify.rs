use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{SignatureVerificationAlgorithm};
use rustls::SignatureScheme;

mod rsapss;
mod rsapkcs1;
mod ecdsa;

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

static RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm = &rsapss::RsaPssSha256Verify;
static RSA_PSS_SHA384: &dyn SignatureVerificationAlgorithm = &rsapss::RsaPssSha384Verify;
static RSA_PKCS1_SHA256: &dyn SignatureVerificationAlgorithm = &rsapkcs1::RsaPkcs1Sha256Verify;
static RSA_PKCS1_SHA384: &dyn SignatureVerificationAlgorithm = &rsapkcs1::RsaPkcs1Sha384Verify;
static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &ecdsa::EcdsaNistp256Sha256;
static ECDSA_P256_SHA384: &dyn SignatureVerificationAlgorithm = &ecdsa::EcdsaNistp256Sha384;
static ECDSA_P384_SHA256: &dyn SignatureVerificationAlgorithm = &ecdsa::EcdsaNistp384Sha256;
static ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &ecdsa::EcdsaNistp384Sha384;
static ECDSA_P521_SHA512: &dyn SignatureVerificationAlgorithm = &ecdsa::EcdsaNistp521Sha512;
