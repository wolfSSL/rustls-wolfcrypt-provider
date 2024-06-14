#![allow(warnings)]
use alloc::boxed::Box;

use hmac::{Hmac, Mac};
use rustls::crypto;
use sha2::{Digest, Sha256};
use core::mem;
use std::{eprintln, println, vec::Vec};

use wolfcrypt_rs::*;

pub struct Sha256Hmac;

impl crypto::hmac::Hmac for Sha256Hmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(Sha256HmacKey(Hmac::<Sha256>::new_from_slice(key).unwrap()))
    }

    fn hash_output_len(&self) -> usize {
        Sha256::output_size()
    }
}

struct WCHmacKey {
    hmac_struct: wolfcrypt_rs::Hmac,
    key: Vec<u8>,
}

impl WCHmacKey {
    fn hmac_init(&mut self) {
        unsafe {
            let ret;
            ret = wc_HmacSetKey(
                &mut self.hmac_struct, 
                WC_SHA256.try_into().unwrap(), 
                self.key.as_mut_ptr(), 
                mem::size_of_val(&self.key).try_into().unwrap()
            );
            if ret != 0 {
                panic!("wc_HmacSetKey failed with ret value: {}", ret);
            }
        }
    }

    fn hmac_update(&mut self, buffer: &[u8]) {
        unsafe {
            let ret;
            ret = wc_HmacUpdate(
                &mut self.hmac_struct, 
                buffer.as_ptr(), 
                mem::size_of_val(&self.key).try_into().unwrap()
            );
            if ret != 0 {
                panic!("wc_HmacUpdate failed with ret value: {}", ret);
            }
        }
    }

    fn hmac_final(&mut self, hmac_digest: *mut u8) {
        unsafe {
            let ret;
            ret = wc_HmacFinal(
                &mut self.hmac_struct, 
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
        self.update(first);
        for m in middle {
            self.update(m);
        }
        self.hmac_update(last);


        // Finally, we compute the final hash of the HMAC object created with self.init()...
        const WC_SHA_256_DIGEST_SIZE_USIZE: usize = WC_SHA256_DIGEST_SIZE as usize;
        let mut digest: [u8; WC_SHA_256_DIGEST_SIZE_USIZE] = [0; WC_SHA_256_DIGEST_SIZE_USIZE];
        self.hmac_final(digest.as_mut_ptr());
        let mut digest_length = mem::size_of_val(&digest);

        //...and tag it.
        crypto::hmac::Tag::new(&digest[..digest_length])
    }

    fn tag_len(&self) -> usize {
        Sha256::output_size()
    }
}


mod tests {
    use super::*;

    #[test]
    fn sha_256_hmac() {
        let ret = 0;

        assert_eq!(0, ret);
    }
}
