use crate::error::check_if_zero;
use alloc::{boxed::Box, vec, vec::Vec};
use core::mem;
use rustls::crypto;
use wolfcrypt_rs::*;
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub enum WCShaHmac {
    Sha256,
    Sha384,
}

impl WCShaHmac {
    fn digest_size(&self) -> usize {
        match self {
            WCShaHmac::Sha256 => WC_SHA256_DIGEST_SIZE as usize,
            WCShaHmac::Sha384 => WC_SHA384_DIGEST_SIZE as usize,
        }
    }

    fn algorithm(&self) -> i32 {
        match self {
            WCShaHmac::Sha256 => WC_SHA256.try_into().unwrap(),
            WCShaHmac::Sha384 => WC_SHA384.try_into().unwrap(),
        }
    }

    pub fn new(hash_type: wc_HashType) -> Self {
        match hash_type {
            WC_SHA256 => WCShaHmac::Sha256,
            WC_SHA384 => WCShaHmac::Sha384,
            _ => panic!("Unsupported hash type"),
        }
    }

    pub fn hash_type(&self) -> wc_HashType {
        match self {
            WCShaHmac::Sha256 => WC_SHA256,
            WCShaHmac::Sha384 => WC_SHA384,
        }
    }

    pub fn hash_len(&self) -> usize {
        match self {
            WCShaHmac::Sha256 => WC_SHA256_DIGEST_SIZE as usize,
            WCShaHmac::Sha384 => WC_SHA384_DIGEST_SIZE as usize,
        }
    }
}

impl crypto::hmac::Hmac for WCShaHmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(WCHmacKey {
            key: Zeroizing::new(key.to_vec()),
            variant: *self,
        })
    }

    fn hash_output_len(&self) -> usize {
        self.digest_size()
    }
}

struct WCHmacKey {
    key: Zeroizing<Vec<u8>>,
    variant: WCShaHmac,
}

impl crypto::hmac::Key for WCHmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
        let hmac_object = self.hmac_init();
        self.hmac_update(hmac_object, first);
        for m in middle {
            self.hmac_update(hmac_object, m)
        }
        self.hmac_update(hmac_object, last);
        let digest = self.hmac_final(hmac_object);
        crypto::hmac::Tag::new(&digest)
    }

    fn tag_len(&self) -> usize {
        self.variant.digest_size()
    }
}

impl WCHmacKey {
    fn hmac_init(&self) -> *mut Hmac {
        let hmac_ptr = Box::into_raw(Box::new(unsafe { mem::zeroed::<Hmac>() }));

        let ret = unsafe {
            wc_HmacSetKey(
                hmac_ptr,
                self.variant.algorithm(),
                self.key.as_ptr(),
                self.key.len() as word32,
            )
        };
        check_if_zero(ret).unwrap();
        hmac_ptr
    }

    fn hmac_update(&self, hmac_ptr: *mut Hmac, input: &[u8]) {
        let ret = unsafe { wc_HmacUpdate(hmac_ptr, input.as_ptr(), input.len() as word32) };
        check_if_zero(ret).unwrap();
    }

    fn hmac_final(&self, hmac_ptr: *mut Hmac) -> Vec<u8> {
        let mut digest = vec![0u8; self.variant.digest_size()];
        let ret = unsafe { wc_HmacFinal(hmac_ptr, digest.as_mut_ptr()) };
        check_if_zero(ret).unwrap();

        // Free the heap-allocated Hmac struct.
        unsafe {
            drop(Box::from_raw(hmac_ptr));
        }

        digest
    }
}
