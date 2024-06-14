use alloc::boxed::Box;

use hmac::{Hmac, Mac};
use rustls::crypto;
use sha2::{Digest, Sha256};
use core::mem;
use std::{eprintln, println};

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

struct Sha256HmacKey(Hmac<Sha256>);

impl crypto::hmac::Key for Sha256HmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
        let mut ctx = self.0.clone();
        ctx.update(first);
        for m in middle {
            ctx.update(m);
        }
        ctx.update(last);
        crypto::hmac::Tag::new(&ctx.finalize().into_bytes()[..])
    }

    fn tag_len(&self) -> usize {
        Sha256::output_size()
    }
}

mod tests {
    use super::*;

    #[test]
    fn sha_256_hmac() {
        unsafe {
            let mut hmac: wolfcrypt_rs::Hmac = mem::zeroed();
            let mut key: [u8; 24] = [9; 24];
            let mut buffer: [u8; 2048] = [123; 2048];
            const WC_SHA_256_DIGEST_SIZE_USIZE: usize = WC_SHA256_DIGEST_SIZE as usize;
            let mut hmac_digest: [u8; WC_SHA_256_DIGEST_SIZE_USIZE] = [0; WC_SHA_256_DIGEST_SIZE_USIZE];
            let mut ret;

            ret = wc_HmacSetKey(
                &mut hmac, 
                WC_SHA256.try_into().unwrap(), 
                key.as_mut_ptr(), 
                mem::size_of_val(&key).try_into().unwrap()
            );
            if ret != 0 {
                panic!("wc_HmacSetKey failed with ret value: {}", ret);
            }

            ret = wc_HmacUpdate(
                &mut hmac, 
                buffer.as_mut_ptr(), 
                mem::size_of_val(&key).try_into().unwrap()
            );
            if ret != 0 {
                panic!("wc_HmacUpdate failed with ret value: {}", ret);
            }

            ret = wc_HmacFinal(
                &mut hmac, 
                hmac_digest.as_mut_ptr()
            );
            if ret != 0 {
                panic!("wc_HmacFinal failed with ret value: {}", ret);
            }

            assert_eq!(0, ret);
        }
    }
}
