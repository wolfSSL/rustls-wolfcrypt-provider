use crate::{error::check_if_zero, types::types::*};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::mem;
use foreign_types::ForeignType;
use rustls::crypto;

use wolfcrypt_rs::*;

pub struct WCSha256Hmac;

impl crypto::hmac::Hmac for WCSha256Hmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(WCHmac256Key { key: key.to_vec() })
    }

    fn hash_output_len(&self) -> usize {
        32_usize
    }
}

struct WCHmac256Key {
    key: Vec<u8>,
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
    fn hmac_init(&self) -> HmacObject {
        let mut hmac_c_type: Hmac = unsafe { mem::zeroed() };
        let hmac_object = unsafe { HmacObject::from_ptr(&mut hmac_c_type) };

        // This function initializes an Hmac object, setting
        // its encryption type, key and HMAC length.
        let ret = unsafe {
            wc_HmacSetKey(
                hmac_object.as_ptr(),
                WC_SHA256.try_into().unwrap(),
                self.key.as_ptr(),
                self.key.len() as word32,
            )
        };
        check_if_zero(ret).unwrap();

        hmac_object
    }

    fn hmac_update(&self, hmac_object: HmacObject, input: &[u8]) {
        // This function updates the message to authenticate using HMAC. It should be called after the
        // Hmac object has been initialized with wc_HmacSetKey. This function may be called multiple
        // times to update the message to hash. After calling wc_HmacUpdate as desired, one should call
        // wc_HmacFinal to obtain the final authenticated message tag.
        let ret =
            unsafe { wc_HmacUpdate(hmac_object.as_ptr(), input.as_ptr(), input.len() as word32) };

        check_if_zero(ret).unwrap();
    }

    fn hmac_final(&self, hmac_object: HmacObject) -> [u8; 32] {
        let mut digest: [u8; 32] = [0; 32];

        // This function computes the final hash of an Hmac object's message.
        let ret = unsafe { wc_HmacFinal(hmac_object.as_ptr(), digest.as_mut_ptr()) };
        check_if_zero(ret).unwrap();

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
