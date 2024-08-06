extern crate alloc;
extern crate std;

use alloc::sync::Arc;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::PrivateKeyDer;
use rustls::crypto::tls13::HkdfUsingHmac;
mod random;
mod hash;
mod kx;
mod sign;
mod hmac;
mod verify;
mod aead;

/*
 * Crypto provider struct that we populate with our own crypto backend (wolfcrypt).
 * */
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: ALL_CIPHER_SUITES.to_vec(),
        kx_groups: kx::ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: verify::ALGORITHMS,
        secure_random: &Provider,
        key_provider: &Provider,
    }
}

#[derive(Debug)]
struct Provider;

impl rustls::crypto::SecureRandom for Provider {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        random::wolfcrypt_random_buffer_generator(bytes);
        Ok(())
    }
}

impl rustls::crypto::KeyProvider for Provider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        Ok(Arc::new(
            sign::EcdsaSigningKeyP256::try_from(key_der).map_err(|err| {
                let err = rustls::OtherError(Arc::new(err));
                err
            })?,
        ))
    }
}

static ALL_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    TLS13_CHACHA20_POLY1305_SHA256,
    TLS12_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

pub static TLS13_CHACHA20_POLY1305_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::WCSha256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &HkdfUsingHmac(&hmac::WCSha256Hmac),
        aead_alg: &aead::Chacha20Poly1305,
        quic: None,
    });

pub static TLS12_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::WCSha256,
            confidentiality_limit: u64::MAX,
        },
        aead_alg: &aead::Chacha20Poly1305,
        prf_provider: &rustls::crypto::tls12::PrfUsingHmac(&hmac::WCSha256Hmac),
        kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign: &[
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ],
    });
