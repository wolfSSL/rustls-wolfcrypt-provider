use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::mem;
use rustls::crypto::tls13::{self, Hkdf as RustlsHkdf};
use wolfcrypt_rs::*;

use crate::error::check_if_zero;
use crate::hmac::WCShaHmac;

pub struct WCHkdfUsingHmac(pub WCShaHmac);

impl RustlsHkdf for WCHkdfUsingHmac {
    fn extract_from_zero_ikm(
        &self,
        salt: Option<&[u8]>,
    ) -> Box<dyn rustls::crypto::tls13::HkdfExpander> {
        let hash_len = self.0.hash_len();
        let ikm = vec![0u8; hash_len];
        self.extract_from_secret(salt, &ikm)
    }

    fn extract_from_secret(
        &self,
        salt: Option<&[u8]>,
        ikm: &[u8],
    ) -> Box<dyn rustls::crypto::tls13::HkdfExpander> {
        let hash_len = self.0.hash_len();
        let mut extracted_key = vec![0u8; hash_len];
        let zero_salt = vec![0u8; hash_len];
        let salt_bytes = salt.unwrap_or(&zero_salt);

        let ret = unsafe {
            wc_HKDF_Extract(
                self.0.hash_type().try_into().unwrap(),
                salt_bytes.as_ptr(),
                salt_bytes.len() as u32,
                ikm.as_ptr(),
                ikm.len() as u32,
                extracted_key.as_mut_ptr(),
            )
        };
        check_if_zero(ret).unwrap();

        Box::new(WolfHkdfExpander::new(
            extracted_key,
            self.0.hash_type().try_into().unwrap(),
            self.0.hash_len(),
        ))
    }

    fn expander_for_okm(
        &self,
        okm: &rustls::crypto::tls13::OkmBlock,
    ) -> Box<dyn rustls::crypto::tls13::HkdfExpander> {
        Box::new(WolfHkdfExpander {
            extracted_key: okm.as_ref().to_vec(),
            hash_type: self.0.hash_type().try_into().unwrap(),
            hash_len: self.0.hash_len(),
        })
    }

    fn hmac_sign(
        &self,
        key: &rustls::crypto::tls13::OkmBlock,
        message: &[u8],
    ) -> rustls::crypto::hmac::Tag {
        let mut hmac = vec![0u8; self.0.hash_len()];
        let mut hmac_ctx = unsafe { mem::zeroed() };

        let mut ret = unsafe {
            wc_HmacSetKey(
                &mut hmac_ctx,
                self.0.hash_type().try_into().unwrap(),
                key.as_ref().as_ptr(),
                key.as_ref().len() as u32,
            )
        };
        check_if_zero(ret).unwrap();

        ret = unsafe { wc_HmacUpdate(&mut hmac_ctx, message.as_ptr(), message.len() as u32) };
        check_if_zero(ret).unwrap();

        ret = unsafe { wc_HmacFinal(&mut hmac_ctx, hmac.as_mut_ptr()) };
        check_if_zero(ret).unwrap();

        unsafe { wc_HmacFree(&mut hmac_ctx) };
        check_if_zero(ret).unwrap();

        rustls::crypto::hmac::Tag::new(&hmac)
    }
}

/// Expander implementation that holds the extracted key material from HKDF extract phase
struct WolfHkdfExpander {
    extracted_key: Vec<u8>, // The pseudorandom key (PRK) output from HKDF-Extract
    hash_type: i32,         // The wolfSSL hash algorithm identifier
    hash_len: usize,        // Length of the hash function output
}

impl WolfHkdfExpander {
    fn new(extracted_key: Vec<u8>, hash_type: i32, hash_len: usize) -> Self {
        Self {
            extracted_key,
            hash_type,
            hash_len,
        }
    }
}

impl tls13::HkdfExpander for WolfHkdfExpander {
    fn expand_slice(
        &self,
        info: &[&[u8]],
        output: &mut [u8],
    ) -> Result<(), tls13::OutputLengthError> {
        let info_concat = info.concat();

        if output.len() > 255 * self.hash_len {
            return Err(tls13::OutputLengthError);
        }

        unsafe {
            wc_HKDF_Expand(
                self.hash_type,
                self.extracted_key.as_ptr(),
                self.extracted_key.len() as u32,
                info_concat.as_ptr(),
                info_concat.len() as u32,
                output.as_mut_ptr(),
                output.len() as u32,
            );
        }

        Ok(())
    }

    fn expand_block(&self, info: &[&[u8]]) -> tls13::OkmBlock {
        let mut output = vec![0u8; self.hash_len];
        self.expand_slice(info, &mut output)
            .expect("expand_block failed");
        tls13::OkmBlock::new(&output)
    }

    fn hash_len(&self) -> usize {
        self.hash_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    /// Tests the HKDF implementation against RFC 5869 test vector A.1
    /// This is the primary compliance test using SHA-256
    #[test]
    fn test_hkdf_sha256() {
        // Test vectors from RFC 5869 Appendix A.1
        let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex!("000102030405060708090a0b0c");
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");
        let expected_okm = hex!(
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        );

        let hkdf = WCHkdfUsingHmac(WCShaHmac::new(wc_HashType_WC_HASH_TYPE_SHA256));
        let expander = hkdf.extract_from_secret(Some(&salt), &ikm);

        let mut okm = vec![0u8; 42]; // Length from test vector
        expander.expand_slice(&[&info], &mut okm).unwrap();

        assert_eq!(&okm[..], &expected_okm[..]);
    }

    /// Tests HKDF with SHA-384 to ensure it works with different hash functions
    /// Note: This test doesn't verify against RFC test vectors
    #[test]
    fn test_hkdf_sha384() {
        // Test with SHA384
        let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex!("000102030405060708090a0b0c");
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");

        let hkdf = WCHkdfUsingHmac(WCShaHmac::new(wc_HashType_WC_HASH_TYPE_SHA384));
        let expander = hkdf.extract_from_secret(Some(&salt), &ikm);

        let mut okm = vec![0u8; 48]; // SHA384 output length
        expander.expand_slice(&[&info], &mut okm).unwrap();

        // Just verify we can generate output - actual value would need a verified test vector
        assert!(!okm.iter().all(|&x| x == 0));
    }

    /// Verifies that the HKDF implementation correctly enforces the output length limit
    /// The limit is 255 times the hash length as specified in RFC 5869
    #[test]
    fn test_hkdf_output_length_limit() {
        let hkdf = WCHkdfUsingHmac(WCShaHmac::new(wc_HashType_WC_HASH_TYPE_SHA256));
        let expander = hkdf.extract_from_zero_ikm(None);

        // Maximum allowed length (255 * hash_len)
        let max_len = 255 * 32;
        let mut okm = vec![0u8; max_len];
        assert!(expander.expand_slice(&[&[]], &mut okm).is_ok());

        // Exceeding maximum length should fail
        let mut okm = vec![0u8; max_len + 1];
        assert!(expander.expand_slice(&[&[]], &mut okm).is_err());
    }

    /// Tests the special case of zero input key material
    /// This is important for TLS 1.3 which sometimes requires derivation from zero IKM
    #[test]
    fn test_hkdf_zero_ikm() {
        let hkdf = WCHkdfUsingHmac(WCShaHmac::new(wc_HashType_WC_HASH_TYPE_SHA256));
        let salt = hex!("000102030405060708090a0b0c");
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");

        let expander = hkdf.extract_from_zero_ikm(Some(&salt));

        let mut okm1 = vec![0u8; 32];
        expander.expand_slice(&[&info], &mut okm1).unwrap();

        // Verify that zero IKM produces consistent output
        let expander2 = hkdf.extract_from_zero_ikm(Some(&salt));
        let mut okm2 = vec![0u8; 32];
        expander2.expand_slice(&[&info], &mut okm2).unwrap();

        assert_eq!(okm1, okm2);
    }

    /// Tests that the implementation correctly handles multiple info components
    /// Verifies that passing multiple info slices produces the same result as their concatenation
    #[test]
    fn test_hkdf_multiple_info_components() {
        let hkdf = WCHkdfUsingHmac(WCShaHmac::new(wc_HashType_WC_HASH_TYPE_SHA256));
        let salt = hex!("000102030405060708090a0b0c");
        let info1 = hex!("f0f1f2f3");
        let info2 = hex!("f4f5f6f7");
        let info3 = hex!("f8f9");

        let expander = hkdf.extract_from_zero_ikm(Some(&salt));

        // Test with multiple info components
        let mut okm1 = vec![0u8; 32];
        expander
            .expand_slice(&[&info1, &info2, &info3], &mut okm1)
            .unwrap();

        // Test with concatenated info
        let mut info_concat = Vec::new();
        info_concat.extend_from_slice(&info1);
        info_concat.extend_from_slice(&info2);
        info_concat.extend_from_slice(&info3);

        let mut okm2 = vec![0u8; 32];
        expander.expand_slice(&[&info_concat], &mut okm2).unwrap();

        // Results should be identical
        assert_eq!(okm1, okm2);
    }
}
