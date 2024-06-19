use alloc::boxed::Box;

use std::cell::UnsafeCell;
use rustls::crypto;
use sha2::{Digest, Sha256};
use core::mem;
use std::{vec::Vec};

use wolfcrypt_rs::*;

pub struct WCSha256Hmac;

impl crypto::hmac::Hmac for WCSha256Hmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        unsafe {
            let hmac_object: wolfcrypt_rs::Hmac = mem::zeroed();
            Box::new(WCHmacKey {
                hmac_object: hmac_object.into(),
                key: key.to_vec().into()
            })
        }
    }

    fn hash_output_len(&self) -> usize {
        const WC_SHA_256_DIGEST_SIZE_USIZE: usize = WC_SHA256_DIGEST_SIZE as usize;
        WC_SHA_256_DIGEST_SIZE_USIZE
    }
}

struct WCHmacKey {
    hmac_object: UnsafeCell<wolfcrypt_rs::Hmac>,
    key: UnsafeCell<Vec<u8>>,
}

unsafe impl Sync for WCHmacKey {}
unsafe impl Send for WCHmacKey {}

impl WCHmacKey {
    fn hmac_init(&self) {
        unsafe {
            let ret;
            let hmac_object = &mut *self.hmac_object.get();
            let key = &mut *self.key.get();
            let key_raw_ptr: *const u8 = key.as_ptr();

            ret = wc_HmacSetKey(
                hmac_object, 
                WC_SHA256.try_into().unwrap(), 
                key_raw_ptr, 
                mem::size_of_val(&self.key).try_into().unwrap()
            );
            if ret != 0 {
                panic!("wc_HmacSetKey failed with ret value: {}", ret);
            }
        }
    }

    fn hmac_update(&self, buffer: &[u8]) {
        unsafe {
            let ret;
            let hmac_object = &mut *self.hmac_object.get();
            ret = wc_HmacUpdate(
                hmac_object, 
                buffer.as_ptr(), 
                mem::size_of_val(&self.key).try_into().unwrap()
            );
            if ret != 0 {
                panic!("wc_HmacUpdate failed with ret value: {}", ret);
            }
        }
    }

    fn hmac_final(&self, hmac_digest: *mut u8) {
        unsafe {
            let ret;
            let hmac_object = &mut *self.hmac_object.get();
            ret = wc_HmacFinal(
                hmac_object, 
                hmac_digest
            );
            if ret != 0 {
                panic!("wc_HmacFinal failed with ret value: {}", ret);
            }
        }
    }
}

impl crypto::hmac::Key for WCHmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
        // Initialize the HMAC object.
        self.hmac_init();

        // We update the message to authenticate using HMAC.
        self.hmac_update(first);
        for m in middle {
            self.hmac_update(m);
        }
        self.hmac_update(last);


        // Finally, we compute the final hash of the HMAC object created with self.init()...
        const WC_SHA_256_DIGEST_SIZE_USIZE: usize = WC_SHA256_DIGEST_SIZE as usize;
        let mut digest: [u8; WC_SHA_256_DIGEST_SIZE_USIZE] = [0; WC_SHA_256_DIGEST_SIZE_USIZE];
        self.hmac_final(digest.as_mut_ptr());
        let digest_length = mem::size_of_val(&digest);

        //...and tag it.
        crypto::hmac::Tag::new(&digest[..digest_length])
    }

    fn tag_len(&self) -> usize {
        Sha256::output_size()
    }
}

#[cfg(test)]
mod tests {
    use super::WCSha256Hmac;
    use rustls::crypto::hmac::Hmac;

  #[test]
    fn sha_256_hmac() {
        let hmac = WCSha256Hmac;
        let key = "this is my key".as_bytes();
        let hash = hmac.with_key(key);

        let _tag = hash.sign_concat(
            "fake it".as_bytes(),
            &["till you".as_bytes(), "make".as_bytes()],
            "it".as_bytes(),
        );

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

        // Second call to sign_concat with the same inputs
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
