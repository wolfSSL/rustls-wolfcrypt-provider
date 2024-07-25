//use alloc::boxed::Box;
//use rustls::crypto;
//use core::mem;
//use std::{vec::Vec};
//use foreign_types::{ForeignType, ForeignTypeRef, Opaque};
//use std::ptr::NonNull;
//use wolfcrypt_rs::*;
//
//pub struct HmacObjectRef(Opaque);
//unsafe impl ForeignTypeRef for HmacObjectRef {
//    type CType = wolfcrypt_rs::Hmac;
//}
//
//unsafe impl ForeignType for HmacObject {
//    type CType = wolfcrypt_rs::Hmac;
//
//    type Ref = HmacObjectRef;
//
//    unsafe fn from_ptr(ptr: *mut Self::CType) -> Self {
//        Self(NonNull::new_unchecked(ptr))
//    }
//
//    fn as_ptr(&self) -> *mut Self::CType {
//        self.0.as_ptr()
//    }
//}
//
//pub struct HmacObject(NonNull<wolfcrypt_rs::Hmac>);
//unsafe impl Sync for HmacObject {}
//unsafe impl Send for HmacObject {}
//
//#[allow(unused)]
//pub const SHA256: &dyn crypto::hmac::Hmac = &WCSha256Hmac;
//
//pub struct WCSha256Hmac;
//
//impl crypto::hmac::Hmac for WCSha256Hmac {
//    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
//        unsafe {
//            let mut hmac_c_type: wolfcrypt_rs::Hmac = mem::zeroed();
//            let hmac_object = HmacObject::from_ptr(&mut hmac_c_type);
//            let ret;
//
//            ret = wc_HmacInit(
//                hmac_object.as_ptr(),
//                std::ptr::null_mut(),
//                INVALID_DEVID
//            );
//            if ret < 0 {
//                panic!("wc_HmacInit failed with ret value: {}", ret);
//            }
//
//            Box::new(WCHmacKey {
//                hmac_object: hmac_object,
//                key: key.to_vec()
//            })
//        }
//    }
//
//    fn hash_output_len(&self) -> usize {
//        32
//    }
//}
//
//struct WCHmacKey {
//    hmac_object: HmacObject,
//    key: Vec<u8>,
//}
//
//impl WCHmacKey {
//    fn hmac_init(&self) {
//        unsafe {
//            let ret;
//
//            ret = wc_HmacSetKey(
//                self.hmac_object.as_ptr(), 
//                WC_SHA256.try_into().unwrap(), 
//                self.key.as_ptr(), 
//                self.key.len().try_into().unwrap()
//            );
//
//            if ret < 0 {
//                panic!("wc_HmacSetKey failed with ret value: {}", ret);
//            }
//        }
//    }
//
//    fn hmac_update(&self, buffer: &[u8]) {
//        unsafe {
//            let ret;
//
//            ret = wc_HmacUpdate(
//                self.hmac_object.as_ptr(), 
//                buffer.as_ptr(), 
//                self.key.len().try_into().unwrap()
//            );
//
//            if ret < 0 {
//                panic!("wc_HmacUpdate failed with ret value: {}, size of buffer: {}", ret, mem::size_of_val(&buffer));
//            }
//        }
//    }
//
//    fn hmac_final(&self, hmac_digest: &mut [u8]) {
//        unsafe {
//            let ret;
//
//            ret = wc_HmacFinal(
//                self.hmac_object.as_ptr(), 
//                hmac_digest.as_mut_ptr()
//            );
//
//            if ret < 0 {
//                panic!("wc_HmacFinal failed with ret value: {}", ret);
//            }
//
//        }
//    }
//}
//
//impl crypto::hmac::Key for WCHmacKey {
//    fn sign(&self, data: &[&[u8]]) -> crypto::hmac::Tag {
//        self.sign_concat(&[], data, &[])
//    }
//
//    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
//        // Initialize the HMAC object.
//        self.hmac_init();
//
//        // We update the message to authenticate using HMAC.
//        self.hmac_update(first);
//        for m in middle {
//            self.hmac_update(m);
//        }
//        self.hmac_update(last);
//
//        // Finally, we compute the final hash of the HMAC object created with self.init()...
//        let mut digest = [0u8; 32];
//        self.hmac_final(&mut digest);
//        let digest_length: usize = 32 as usize;
//
//        //...and tag it.
//        crypto::hmac::Tag::new(&digest[..digest_length])
//    }
//
//    fn tag_len(&self) -> usize {
//        32
//    }
//}
//
//#[cfg(test)]
//mod tests {
//    use super::*;
//    use hex_literal::hex;
//
//    #[test]
//    fn sha_256_hmac() {
//        let hasher = SHA256.with_key("Very Secret".as_bytes());
//
//        let tag = hasher.sign(
//            &[
//                "yay".as_bytes(),
//                "this".as_bytes(),
//                "works".as_bytes(),
//                "well".as_bytes(),
//            ],
//        );
//
//        assert_eq!(
//            tag.as_ref(),
//            hex!("11fa4a6ee97bebfad9e1087145c556fec9a786cad0659aa10702d21bd2968305")
//        );
//    }
//}
use alloc::boxed::Box;

use hmac::{Hmac, Mac};
use rustls::crypto;
use sha2::{Digest, Sha256};

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
