use alloc::boxed::Box;

use rustls::crypto;
use core::mem;
use std::{vec::Vec};
use foreign_types::{ForeignType, ForeignTypeRef, Opaque};
use std::{ptr::NonNull};

use wolfcrypt_rs::*;

pub struct WCSha256Hmac;

impl crypto::hmac::Hmac for WCSha256Hmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        unsafe {
            let mut hmac_c_type: wolfcrypt_rs::Hmac = mem::zeroed();
            let hmac_object = HmacObject::from_ptr(&mut hmac_c_type);

            Box::new(WCHmacKey {
                hmac_object: hmac_object,
                key: key.to_vec()
            })
        }
    }

    fn hash_output_len(&self) -> usize {
        32 as usize
    }
}

pub struct HmacObjectRef(Opaque);
unsafe impl ForeignTypeRef for HmacObjectRef {
    type CType = wolfcrypt_rs::Hmac;
}

pub struct HmacObject(NonNull<wolfcrypt_rs::Hmac>);
unsafe impl Sync for HmacObject {}
unsafe impl Send for HmacObject {}
unsafe impl ForeignType for HmacObject {
    type CType = wolfcrypt_rs::Hmac;

    type Ref = HmacObjectRef;

    unsafe fn from_ptr(ptr: *mut Self::CType) -> Self {
        Self(NonNull::new_unchecked(ptr))
    }

    fn as_ptr(&self) -> *mut Self::CType {
        self.0.as_ptr()
    }
}

struct WCHmacKey {
    hmac_object: HmacObject,
    key: Vec<u8>,
}

impl WCHmacKey {
    fn hmac_init(&self) {
        unsafe {
            let ret;

            ret = wc_HmacSetKey(
                self.hmac_object.as_ptr(), 
                WC_SHA256.try_into().unwrap(), 
                self.key.as_ptr(), 
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

            ret = wc_HmacUpdate(
                self.hmac_object.as_ptr(), 
                buffer.as_ptr(), 
                mem::size_of_val(&self.key).try_into().unwrap()
            );

            if ret != 0 {
                panic!("wc_HmacUpdate failed with ret value: {}, size of buffer: {}", ret, mem::size_of_val(&buffer));
            }
        }
    }

    fn hmac_final(&self, hmac_digest: &mut [u8]) {
        unsafe {
            let ret;

            ret = wc_HmacFinal(
                self.hmac_object.as_ptr(), 
                hmac_digest.as_mut_ptr()
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
        let mut digest = [0u8; 32];
        self.hmac_final(&mut digest);
        let digest_length: usize = 32 as usize;

        //...and tag it.
        crypto::hmac::Tag::new(&digest[..digest_length])
    }

    fn tag_len(&self) -> usize {
        32 as usize
    }
}

#[cfg(test)]
mod tests {
    use super::WCSha256Hmac;
    use rustls::crypto::hmac::Hmac;
    use std::{vec::Vec};

    #[test]
    fn sha_256_hmac() {
        let hmac = WCSha256Hmac;
        let key = "this is my key".as_bytes();
        let hash = hmac.with_key(key);

        // Create a very long message by repeating a pattern many times
        let pattern = "super long message to stress test the HMAC implementation".as_bytes();
        let mut long_message = Vec::new();
        for _ in 0..10000 {  // Adjust the number to increase or decrease the message length
            long_message.extend_from_slice(pattern);
        }

        // Convert the long message to a slice
        let long_message_slice = long_message.as_slice();

        // First call to sign_concat with the super long message
        let tag1 = hash.sign_concat(&[], &[long_message_slice], &[]);

        // Second call to sign_concat with the same super long message
        let tag2 = hash.sign_concat(&[], &[long_message_slice], &[]);

        // Assert that both tags are equal
        assert_eq!(tag1.as_ref(), tag2.as_ref());
    }
}
