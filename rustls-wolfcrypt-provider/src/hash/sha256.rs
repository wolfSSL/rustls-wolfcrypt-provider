use crate::error::check_if_zero;
use alloc::boxed::Box;
use core::mem;
use rustls::crypto::hash;

use wolfcrypt_rs::*;

pub struct WCSha256;

impl hash::Hash for WCSha256 {
    fn start(&self) -> Box<dyn hash::Context> {
        let sha256_c_type: wc_Sha256 = unsafe { mem::zeroed() };
        let hash: [u8; WC_SHA256_DIGEST_SIZE as usize] = [0; WC_SHA256_DIGEST_SIZE as usize];

        let mut hasher = WCHasher256 {
            sha256_c_type,
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
    sha256_c_type: wc_Sha256,
    hash: [u8; WC_SHA256_DIGEST_SIZE as usize],
}

impl WCHasher256 {
    fn wchasher_init(&mut self) {
        // This function initializes SHA256. This is automatically called by wc_Sha256Hash.
        let ret = unsafe { wc_InitSha256(&mut self.sha256_c_type) };
        check_if_zero(ret).unwrap();
    }

    fn wchasher_update(&mut self, data: &[u8]) {
        let length: word32 = data.len() as word32;

        // Hash the provided byte array of length len.
        // Can be called continually.
        let ret = unsafe { wc_Sha256Update(&mut self.sha256_c_type, data.as_ptr(), length) };
        check_if_zero(ret).unwrap();
    }

    fn wchasher_final(&mut self) -> &[u8] {
        // Finalizes hashing of data. Result is placed into hash.
        // Resets state of the sha256 struct.
        let ret = unsafe { wc_Sha256Final(&mut self.sha256_c_type, self.hash.as_mut_ptr()) };
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
    // Clone implementation.
    // Returns a copy of the WCHasher256 struct.
    fn clone(&self) -> WCHasher256 {
        WCHasher256 {
            sha256_c_type: self.sha256_c_type,
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
