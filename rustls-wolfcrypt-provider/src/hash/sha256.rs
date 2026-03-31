use crate::error::check_if_zero;
use crate::types::*;
use alloc::boxed::Box;
use core::mem;
use foreign_types::ForeignType;
use rustls::crypto::hash;

use wolfcrypt_rs::*;

pub struct WCSha256;

impl hash::Hash for WCSha256 {
    fn start(&self) -> Box<dyn hash::Context> {
        let mut sha256_storage = Box::new(unsafe { mem::zeroed::<wc_Sha256>() });
        let sha256_object = unsafe { Sha256Object::from_ptr(&mut *sha256_storage) };
        let hash: [u8; WC_SHA256_DIGEST_SIZE as usize] = [0; WC_SHA256_DIGEST_SIZE as usize];

        let mut hasher = WCHasher256 {
            sha256_object,
            _sha256_storage: sha256_storage,
            hash,
        };

        hasher.wchasher_init();

        Box::new(WCSha256Context(hasher))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        let mut hasher = self.start();
        hasher.update(data);
        hasher.finish()
    }

    fn algorithm(&self) -> hash::HashAlgorithm {
        hash::HashAlgorithm::SHA256
    }

    fn output_len(&self) -> usize {
        WC_SHA256_DIGEST_SIZE as usize
    }
}

struct WCHasher256 {
    sha256_object: Sha256Object,
    _sha256_storage: Box<wc_Sha256>,
    hash: [u8; WC_SHA256_DIGEST_SIZE as usize],
}

impl WCHasher256 {
    fn wchasher_init(&mut self) {
        // This function initializes SHA256. This is automatically called by wc_Sha256Hash.
        let ret = unsafe { wc_InitSha256(self.sha256_object.as_ptr()) };
        check_if_zero(ret).unwrap();
    }

    fn wchasher_update(&mut self, data: &[u8]) {
        let length: word32 = data.len() as word32;

        // Hash the provided byte array of length len.
        // Can be called continually.
        let ret = unsafe { wc_Sha256Update(self.sha256_object.as_ptr(), data.as_ptr(), length) };
        check_if_zero(ret).unwrap();
    }

    fn wchasher_final(&mut self) -> &[u8] {
        // Finalizes hashing of data. Result is placed into hash.
        // Resets state of the sha256 struct.
        let ret = unsafe { wc_Sha256Final(self.sha256_object.as_ptr(), self.hash.as_mut_ptr()) };
        check_if_zero(ret).unwrap();

        &self.hash
    }
}

struct WCSha256Context(WCHasher256);

impl hash::Context for WCSha256Context {
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(self.0.clone().wchasher_final())
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(WCSha256Context(self.0.clone()))
    }

    fn finish(mut self: Box<Self>) -> hash::Output {
        hash::Output::new(self.0.wchasher_final())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.wchasher_update(data);
    }
}

unsafe impl Sync for WCHasher256 {}
unsafe impl Send for WCHasher256 {}
impl Clone for WCHasher256 {
    fn clone(&self) -> WCHasher256 {
        let mut new_storage = Box::new(unsafe { mem::zeroed::<wc_Sha256>() });
        let new_object = unsafe { Sha256Object::from_ptr(&mut *new_storage) };
        let ret = unsafe { wc_InitSha256(new_object.as_ptr()) };
        check_if_zero(ret).unwrap();
        let ret = unsafe {
            wc_Sha256Copy(
                self.sha256_object.as_ptr(),
                new_object.as_ptr(),
            )
        };
        check_if_zero(ret).unwrap();
        WCHasher256 {
            sha256_object: new_object,
            _sha256_storage: new_storage,
            hash: self.hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::WCSha256;
    use rustls::crypto::hash::Hash;

    #[test]
    fn test_sha256() {
        let wcsha256_struct = WCSha256;
        let hash1 = wcsha256_struct.hash("hello".as_bytes());
        let hash2 = wcsha256_struct.hash("hello".as_bytes());

        let hash_str1 = hex::encode(hash1);
        let hash_str2 = hex::encode(hash2);

        assert_eq!(hash_str1, hash_str2);
    }
}
