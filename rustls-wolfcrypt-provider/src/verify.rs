use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::SignatureVerificationAlgorithm;
use rustls::SignatureScheme;

mod ecdsa;
pub mod eddsa;
mod rsapkcs1;
mod rsapss;

pub static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        RSA_PSS_SHA256,
        RSA_PSS_SHA384,
        RSA_PKCS1_SHA256,
        RSA_PKCS1_SHA384,
        ECDSA_P256_SHA256,
        ECDSA_P384_SHA384,
        ECDSA_P521_SHA512,
        ED25519,
    ],
    mapping: &[
        (SignatureScheme::RSA_PSS_SHA256, &[RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PSS_SHA384, &[RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA512, &[RSA_PSS_SHA512]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[RSA_PKCS1_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[RSA_PKCS1_SHA512]),
        (SignatureScheme::ECDSA_NISTP256_SHA256, &[ECDSA_P256_SHA256]),
        (SignatureScheme::ECDSA_NISTP384_SHA384, &[ECDSA_P384_SHA384]),
        (SignatureScheme::ECDSA_NISTP521_SHA512, &[ECDSA_P521_SHA512]),
        (SignatureScheme::ED25519, &[ED25519]),
    ],
};

static RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm = &rsapss::RsaPssSha256Verify;
static RSA_PSS_SHA384: &dyn SignatureVerificationAlgorithm = &rsapss::RsaPssSha384Verify;
static RSA_PSS_SHA512: &dyn SignatureVerificationAlgorithm = &rsapss::RsaPssSha512Verify;
static RSA_PKCS1_SHA256: &dyn SignatureVerificationAlgorithm = &rsapkcs1::RsaPkcs1Sha256Verify;
static RSA_PKCS1_SHA384: &dyn SignatureVerificationAlgorithm = &rsapkcs1::RsaPkcs1Sha384Verify;
static RSA_PKCS1_SHA512: &dyn SignatureVerificationAlgorithm = &rsapkcs1::RsaPkcs1Sha512Verify;
static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &ecdsa::EcdsaVerifier::P256_SHA256;
static ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &ecdsa::EcdsaVerifier::P384_SHA384;
static ECDSA_P521_SHA512: &dyn SignatureVerificationAlgorithm = &ecdsa::EcdsaVerifier::P521_SHA512;
static ED25519: &dyn SignatureVerificationAlgorithm = &eddsa::Ed25519;
