use alloc::boxed::Box;
use core::mem;
use foreign_types::ForeignType;
use rustls::crypto::hash;
use wolfcrypt_rs::*;

use crate::error::check_if_zero;
use crate::types::*;

pub struct WCSha384;

impl hash::Hash for WCSha384 {
    fn start(&self) -> Box<dyn hash::Context> {
        let mut sha384_storage = Box::new(unsafe { mem::zeroed::<wc_Sha384>() });
        let sha384_object = unsafe { Sha384Object::from_ptr(&mut *sha384_storage) };
        let hash: [u8; WC_SHA384_DIGEST_SIZE as usize] = [0; WC_SHA384_DIGEST_SIZE as usize];

        let mut hasher = WCHasher384 {
            sha384_object,
            _sha384_storage: sha384_storage,
            hash,
        };

        hasher.wchasher_init();

        Box::new(WCSha384Context(hasher))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        let mut hasher = self.start();
        hasher.update(data);
        hasher.finish()
    }

    fn algorithm(&self) -> hash::HashAlgorithm {
        hash::HashAlgorithm::SHA384
    }

    fn output_len(&self) -> usize {
        WC_SHA384_DIGEST_SIZE as usize
    }
}

struct WCHasher384 {
    sha384_object: Sha384Object,
    _sha384_storage: Box<wc_Sha384>,
    hash: [u8; WC_SHA384_DIGEST_SIZE as usize],
}

impl WCHasher384 {
    fn wchasher_init(&mut self) {
        // This function initializes SHA384. This is automatically called by wc_Sha384Hash.
        let ret = unsafe { wc_InitSha384(self.sha384_object.as_ptr()) };
        check_if_zero(ret).expect("wc_InitSha384 failed");
    }

    fn wchasher_update(&mut self, data: &[u8]) {
        let length: word32 = data.len() as word32;

        // Hash the provided byte array of length len.
        // Can be called continually.
        let ret = unsafe { wc_Sha384Update(self.sha384_object.as_ptr(), data.as_ptr(), length) };
        check_if_zero(ret).expect("wc_Sha384Update failed");
    }

    fn wchasher_final(&mut self) -> &[u8] {
        // Finalizes hashing of data. Result is placed into hash.
        // Resets state of the sha384 struct.
        let ret = unsafe { wc_Sha384Final(self.sha384_object.as_ptr(), self.hash.as_mut_ptr()) };
        check_if_zero(ret).expect("wc_Sha384Final failed");

        &self.hash
    }
}

struct WCSha384Context(WCHasher384);

impl hash::Context for WCSha384Context {
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(self.0.clone().wchasher_final())
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(WCSha384Context(self.0.clone()))
    }

    fn finish(mut self: Box<Self>) -> hash::Output {
        hash::Output::new(self.0.wchasher_final())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.wchasher_update(data);
    }
}

#[cfg(test)]
mod tests {
    use super::WCSha384;
    use rustls::crypto::hash::Hash;

    #[test]
    fn test_sha384() {
        let wcsha384_c_type = WCSha384;
        let hash1 = wcsha384_c_type.hash("hello".as_bytes());
        let hash2 = wcsha384_c_type.hash("hello".as_bytes());

        let hash_str1 = hex::encode(hash1);
        let hash_str2 = hex::encode(hash2);

        assert_eq!(hash_str1, hash_str2);
    }
}

unsafe impl Sync for WCHasher384 {}
unsafe impl Send for WCHasher384 {}
impl Clone for WCHasher384 {
    fn clone(&self) -> WCHasher384 {
        let mut new_storage = Box::new(unsafe { mem::zeroed::<wc_Sha384>() });
        let new_object = unsafe { Sha384Object::from_ptr(&mut *new_storage) };
        let ret = unsafe { wc_InitSha384(new_object.as_ptr()) };
        check_if_zero(ret).expect("wc_InitSha384 failed in clone");
        let ret = unsafe { wc_Sha384Copy(self.sha384_object.as_ptr(), new_object.as_ptr()) };
        check_if_zero(ret).expect("wc_Sha384Copy failed");
        WCHasher384 {
            sha384_object: new_object,
            _sha384_storage: new_storage,
            hash: self.hash,
        }
    }
}
