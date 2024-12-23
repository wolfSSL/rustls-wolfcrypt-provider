use rustls::crypto;
use alloc::boxed::Box;
use wolfcrypt_rs::*;

use crate::error::check_if_zero;
use crate::hmac::hmac::*;


pub struct WCPrfUsingHmac(pub WCShaHmac);

impl crypto::tls12::Prf for WCPrfUsingHmac {
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn crypto::ActiveKeyExchange>,
        peer_pub_key: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), rustls::Error> {
        let secret = kx.complete(peer_pub_key)?;
        Ok(wc_prf(output, secret.secret_bytes(), label, seed, self.0)?)
    }

    fn for_secret(
        &self,
        output: &mut [u8],
        secret: &[u8],
        label: &[u8],
        seed: &[u8]
    ) -> () {
        wc_prf(output, secret, label, seed, self.0)
            .expect("failed to calculate prf in for_secret")
    }
}

fn wc_prf(
    output: &mut [u8],
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    hmac_variant: WCShaHmac,
) -> Result<(), rustls::Error> {
    let mac_algorithm = match hmac_variant {
        WCShaHmac::Sha256 => wc_MACAlgorithm_sha256_mac,
        WCShaHmac::Sha384 => wc_MACAlgorithm_sha384_mac,
    };

    let ret = unsafe {
        wc_PRF_TLS(
            output.as_mut_ptr(),
            output.len() as word32,
            secret.as_ptr(),
            secret.len() as word32,
            label.as_ptr(),
            label.len() as word32,
            seed.as_ptr(),
            seed.len() as word32,
            1,
            mac_algorithm.try_into().unwrap(),
            core::ptr::null_mut(),
            INVALID_DEVID
        )
    };

    check_if_zero(ret).unwrap();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::hmac::Hmac;

    #[test]
    fn test_hmac_variants() {
        let test_cases = [
            (WCShaHmac::Sha256, 32),
            (WCShaHmac::Sha384, 48),
        ];

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
