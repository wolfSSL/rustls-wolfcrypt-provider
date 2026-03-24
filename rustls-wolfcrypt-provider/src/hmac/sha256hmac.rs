use crate::error::check_if_zero;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::mem;
use rustls::crypto;
use zeroize::Zeroizing;

use wolfcrypt_rs::*;

pub struct WCSha256Hmac;

impl crypto::hmac::Hmac for WCSha256Hmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(WCHmac256Key { key: Zeroizing::new(key.to_vec()) })
    }

    fn hash_output_len(&self) -> usize {
        32_usize
    }
}

struct WCHmac256Key {
    key: Zeroizing<Vec<u8>>,
}

impl crypto::hmac::Key for WCHmac256Key {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
        let hmac_object = self.hmac_init();

        self.hmac_update(hmac_object, first);

        for m in middle {
            self.hmac_update(hmac_object, m)
        }

        self.hmac_update(hmac_object, last);

        let digest = self.hmac_final(hmac_object);
        let digest_length = digest.len();

        crypto::hmac::Tag::new(&digest[..digest_length])
    }

    fn tag_len(&self) -> usize {
        32_usize
    }
}

impl WCHmac256Key {
    fn hmac_init(&self) -> *mut Hmac {
        let hmac_ptr = Box::into_raw(Box::new(unsafe { mem::zeroed::<Hmac>() }));

        // This function initializes an Hmac object, setting
        // its encryption type, key and HMAC length.
        let ret = unsafe {
            wc_HmacSetKey(
                hmac_ptr,
                WC_SHA256.try_into().unwrap(),
                self.key.as_ptr(),
                self.key.len() as word32,
            )
        };
        check_if_zero(ret).unwrap();

        hmac_ptr
    }

    fn hmac_update(&self, hmac_ptr: *mut Hmac, input: &[u8]) {
        let ret =
            unsafe { wc_HmacUpdate(hmac_ptr, input.as_ptr(), input.len() as word32) };

        check_if_zero(ret).unwrap();
    }

    fn hmac_final(&self, hmac_ptr: *mut Hmac) -> [u8; WC_SHA256_DIGEST_SIZE as usize] {
        let mut digest: [u8; WC_SHA256_DIGEST_SIZE as usize] = [0; WC_SHA256_DIGEST_SIZE as usize];

        // This function computes the final hash of an Hmac object's message.
        let ret = unsafe { wc_HmacFinal(hmac_ptr, digest.as_mut_ptr()) };
        check_if_zero(ret).unwrap();

        unsafe {
            wc_HmacFree(hmac_ptr);
            drop(Box::from_raw(hmac_ptr));
        }

        digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::hmac::Hmac;

    #[test]
    fn test_sha_256_hmac() {
        let hmac = WCSha256Hmac;
        let key = "this is my key".as_bytes();
        let hash = hmac.with_key(key);

        // First call to sign_concat
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

        // Second call to sign_concat with the same input
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

        // Assert that both tags are equal
        assert_eq!(tag1.as_ref(), tag2.as_ref());
    }
}
