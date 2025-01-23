#![cfg_attr(not(test), no_std)]

#[cfg(test)]
extern crate std;

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::PrivateKeyDer;
pub mod error;
mod kx;
mod random;
mod verify;
mod prf;
mod hkdf;
use crate::prf::WCPrfUsingHmac;
use crate::hkdf::WCHkdfUsingHmac;
pub mod aead {
    pub mod aes128gcm;
    pub mod aes256gcm;
    pub mod chacha20;
}
pub mod sign {
    pub mod ecdsa;
    pub mod eddsa;
    pub mod rsapkcs1;
    pub mod rsapss;
}
use crate::aead::{aes128gcm, aes256gcm, chacha20};

pub mod hash {
    pub mod sha256;
    pub mod sha384;
}
use crate::hash::{sha256, sha384};

pub mod hmac {
    pub mod hmac;
}

use crate::hmac::hmac::WCShaHmac;

pub mod types {
    pub mod types;
}

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

pub fn provider_with_specified_ciphers(
    ciphers: Vec<rustls::SupportedCipherSuite>,
) -> CryptoProvider {
    CryptoProvider {
        cipher_suites: ciphers,
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
        if let Err(error::WCError::Failure) = random::wolfcrypt_random_buffer_generator(bytes) {
            Err(rustls::crypto::GetRandomFailed)
        } else {
            Ok(())
        }
    }
}

impl rustls::crypto::KeyProvider for Provider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        // Define supported algorithms as closures
        let algorithms: Vec<
            Box<
                dyn Fn(
                    &PrivateKeyDer<'static>,
                ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error>,
            >,
        > = vec![
            Box::new(|key| {
                sign::ecdsa::EcdsaSigningKeyP256Sha256Sign::try_from(key).map(|x| Arc::new(x) as _)
            }),
            Box::new(|key| {
                sign::ecdsa::EcdsaSigningKeyP384Sha384Sign::try_from(key).map(|x| Arc::new(x) as _)
            }),
            Box::new(|key| {
                sign::ecdsa::EcdsaSigningKeyP521Sha512Sign::try_from(key).map(|x| Arc::new(x) as _)
            }),
            Box::new(|key| sign::rsapss::RsaPssPrivateKey::try_from(key).map(|x| Arc::new(x) as _)),
            Box::new(|key| {
                sign::rsapkcs1::RsaPkcs1PrivateKey::try_from(key).map(|x| Arc::new(x) as _)
            }),
            Box::new(|key| {
                sign::rsapkcs1::RsaPkcs1PrivateKey::try_from(key).map(|x| Arc::new(x) as _)
            }),
            Box::new(|key| sign::eddsa::Ed25519PrivateKey::try_from(key).map(|x| Arc::new(x) as _)),
        ];

        for algorithm in algorithms {
            match algorithm(&key_der) {
                Ok(signing_key) => return Ok(signing_key), // Return the key if the algorithm succeeds
                Err(_) => continue, // Ignore the error and move to the next algorithm
            }
        }

        // If no algorithm succeeded, return an error
        Err(rustls::Error::General(
            "Unsupported private key format".into(),
        ))
    }
}

static ALL_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    TLS13_CHACHA20_POLY1305_SHA256,
    TLS13_AES_128_GCM_SHA256,
    TLS13_AES_256_GCM_SHA384,
    TLS12_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS12_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS12_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS12_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
];

static ALL_RSA_SCHEMES: &[rustls::SignatureScheme] = &[
    rustls::SignatureScheme::RSA_PSS_SHA256,
    rustls::SignatureScheme::RSA_PSS_SHA384,
    rustls::SignatureScheme::RSA_PSS_SHA512,
    rustls::SignatureScheme::RSA_PKCS1_SHA256,
    rustls::SignatureScheme::RSA_PKCS1_SHA384,
    rustls::SignatureScheme::RSA_PKCS1_SHA512,
];

static ALL_ECDSA_SCHEMES: &[rustls::SignatureScheme] = &[
    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
    rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
    rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
    rustls::SignatureScheme::ED25519,
];

pub static TLS13_CHACHA20_POLY1305_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &sha256::WCSha256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &WCHkdfUsingHmac(WCShaHmac::Sha256),
        aead_alg: &chacha20::Chacha20Poly1305,
        quic: None,
    });

pub static TLS13_AES_128_GCM_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &sha256::WCSha256,
            confidentiality_limit: 1 << 23,
        },
        hkdf_provider: &WCHkdfUsingHmac(WCShaHmac::Sha256),
        aead_alg: &aes128gcm::Aes128Gcm,
        quic: None,
    });

pub static TLS13_AES_256_GCM_SHA384: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &sha384::WCSha384,
            confidentiality_limit: 1 << 23,
        },
        hkdf_provider: &WCHkdfUsingHmac(WCShaHmac::Sha384),
        aead_alg: &aes256gcm::Aes256Gcm,
        quic: None,
    });

pub static TLS12_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &sha256::WCSha256,
            confidentiality_limit: u64::MAX,
        },
        aead_alg: &chacha20::Chacha20Poly1305,
        prf_provider: &WCPrfUsingHmac(WCShaHmac::Sha256),
        kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign: ALL_RSA_SCHEMES,
    });

pub static TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &sha256::WCSha256,
            confidentiality_limit: 1 << 23,
        },
        aead_alg: &aes128gcm::Aes128Gcm,
        prf_provider: &WCPrfUsingHmac(WCShaHmac::Sha256),
        kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign: ALL_RSA_SCHEMES,
    });

pub static TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &sha384::WCSha384,
            confidentiality_limit: 1 << 23,
        },
        aead_alg: &aes256gcm::Aes256Gcm,
        prf_provider: &WCPrfUsingHmac(WCShaHmac::Sha384),
        kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign: ALL_RSA_SCHEMES,
    });

pub static TLS12_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &sha256::WCSha256,
            confidentiality_limit: u64::MAX,
        },
        prf_provider: &WCPrfUsingHmac(WCShaHmac::Sha256),
        kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign: ALL_ECDSA_SCHEMES,
        aead_alg: &chacha20::Chacha20Poly1305,
    });

pub static TLS12_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &sha256::WCSha256,
            confidentiality_limit: 1 << 23,
        },
        aead_alg: &aes128gcm::Aes128Gcm,
        prf_provider: &WCPrfUsingHmac(WCShaHmac::Sha256),
        kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign: ALL_ECDSA_SCHEMES,
    });

pub static TLS12_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &sha384::WCSha384,
            confidentiality_limit: 1 << 23,
        },
        aead_alg: &aes256gcm::Aes256Gcm,
        prf_provider: &WCPrfUsingHmac(WCShaHmac::Sha384),
        kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign: ALL_ECDSA_SCHEMES,
    });
