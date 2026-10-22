use alloc::boxed::Box;
use rustls::crypto;
use wolfssl_wolfcrypt::prf::{prf, PRF_HASH_SHA256, PRF_HASH_SHA384};

use crate::hmac::*;

pub struct WCPrfUsingHmac(pub WCShaHmac);

impl crypto::tls12::Prf for WCPrfUsingHmac {
    fn fips(&self) -> bool {
        crate::fips()
    }

    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn crypto::ActiveKeyExchange>,
        peer_pub_key: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), rustls::Error> {
        let secret = kx.complete(peer_pub_key)?;
        wc_prf(output, secret.secret_bytes(), label, seed, self.0)
    }

    fn for_secret(&self, output: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
        wc_prf(output, secret, label, seed, self.0).expect("failed to calculate prf in for_secret")
    }
}

fn wc_prf(
    output: &mut [u8],
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    hmac_variant: WCShaHmac,
) -> Result<(), rustls::Error> {
    let hash_type = match hmac_variant {
        WCShaHmac::Sha256 => PRF_HASH_SHA256,
        WCShaHmac::Sha384 => PRF_HASH_SHA384,
    };

    // The TLS 1.2 PRF is P_hash(secret, label || seed) (RFC 5246, section 5).
    let label_seed = [label, seed].concat();

    #[cfg(fips)]
    let _read = wolfssl_wolfcrypt::fips::PrivateKeyRead::enable().ok();
    prf(secret, &label_seed, hash_type, output)
        .map_err(|_| rustls::Error::General("TLS 1.2 PRF failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::hmac::Hmac;

    #[test]
    fn test_hmac_variants() {
        let test_cases = [(WCShaHmac::Sha256, 32), (WCShaHmac::Sha384, 48)];

        for (variant, expected_size) in test_cases {
            let hmac = variant;
            let key = "this is my key".as_bytes();
            let hash = hmac.with_key(key);

            let tag1 = hash.sign_concat(
                &[],
                &[
                    "fake it".as_bytes(),
                    "till you".as_bytes(),
                    "make".as_bytes(),
                    "it".as_bytes(),
                ],
                &[],
            );

            let tag2 = hash.sign_concat(
                &[],
                &[
                    "fake it".as_bytes(),
                    "till you".as_bytes(),
                    "make".as_bytes(),
                    "it".as_bytes(),
                ],
                &[],
            );

            assert_eq!(tag1.as_ref(), tag2.as_ref());
            assert_eq!(tag1.as_ref().len(), expected_size);
        }
    }
}
