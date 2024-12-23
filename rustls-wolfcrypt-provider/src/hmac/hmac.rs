use crate::{error::check_if_zero, types::types::*};
use alloc::{boxed::Box, vec::Vec, vec};
use core::mem;
use foreign_types::ForeignType;
use rustls::crypto;
use wolfcrypt_rs::*;

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
}

impl crypto::hmac::Hmac for WCShaHmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(WCHmacKey {
            key: key.to_vec(),
            variant: *self,
        })
    }

    fn hash_output_len(&self) -> usize {
        self.digest_size()
    }
}

struct WCHmacKey {
    key: Vec<u8>,
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
    fn hmac_init(&self) -> HmacObject {
        let mut hmac_c_type: Hmac = unsafe { mem::zeroed() };
        let hmac_object = unsafe { HmacObject::from_ptr(&mut hmac_c_type) };

        let ret = unsafe {
            wc_HmacSetKey(
                hmac_object.as_ptr(),
                self.variant.algorithm(),
                self.key.as_ptr(),
                self.key.len() as word32,
            )
        };
        check_if_zero(ret).unwrap();
        hmac_object
    }

    fn hmac_update(&self, hmac_object: HmacObject, input: &[u8]) {
        let ret = unsafe { 
            wc_HmacUpdate(
                hmac_object.as_ptr(),
                input.as_ptr(),
                input.len() as word32
            )
        };
        check_if_zero(ret).unwrap();
    }

    fn hmac_final(&self, hmac_object: HmacObject) -> Vec<u8> {
        let mut digest = vec![0u8; self.variant.digest_size()];
        let ret = unsafe { 
            wc_HmacFinal(
                hmac_object.as_ptr(),
                digest.as_mut_ptr()
            )
        };
        check_if_zero(ret).unwrap();
        digest
    }
}
