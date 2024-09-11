use alloc::boxed::Box;
use rustls::crypto::hash;
use std::mem;
use wolfcrypt_rs::*;

pub struct WCSha256;

impl hash::Hash for WCSha256 {
    fn start(&self) -> Box<dyn hash::Context> {
        unsafe {
            let sha256_struct: wc_Sha256 = mem::zeroed();
            let hash: [u8; WC_SHA256_DIGEST_SIZE as usize] = [0; WC_SHA256_DIGEST_SIZE as usize];

            let mut hasher = WCHasher256 {
                sha256_struct,
                hash,
            };

            hasher.wchasher_init();

            Box::new(WCSha256Context(hasher))
        }
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
    sha256_struct: wc_Sha256,
    hash: [u8; WC_SHA256_DIGEST_SIZE as usize],
}

impl WCHasher256 {
    fn wchasher_init(&mut self) {
        unsafe {
            let ret;

            // This function initializes SHA256. This is automatically called by wc_Sha256Hash.
            ret = wc_InitSha256(&mut self.sha256_struct);
            if ret != 0 {
                panic!("wc_InitSha256 failed with ret: {}", ret);
            }
        }
    }

    fn wchasher_update(&mut self, data: &[u8]) {
        unsafe {
            let ret;
            let length: word32 = data.len() as word32;

            // Hash the provided byte array of length len. 
            // Can be called continually. 
            ret = wc_Sha256Update(&mut self.sha256_struct, data.as_ptr() as *const u8, length);
            if ret != 0 {
                panic!("wc_Sha256Update failed with ret: {}", ret);
            }
        }
    }

    fn wchasher_final(&mut self) -> &[u8] {
        unsafe {
            let ret;

            // Finalizes hashing of data. Result is placed into hash. 
            // Resets state of the sha256 struct.
            ret = wc_Sha256Final(&mut self.sha256_struct, self.hash.as_mut_ptr());
            if ret != 0 {
                panic!("wc_Sha256Final failed with ret: {}", ret);
            }

            &self.hash
        }
    }
}

struct WCSha256Context(WCHasher256);

impl hash::Context for WCSha256Context {
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(&self.0.clone().wchasher_final()[..])
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(WCSha256Context(self.0.clone()))
    }

    fn finish(mut self: Box<Self>) -> hash::Output {
        hash::Output::new(&self.0.wchasher_final()[..])
    }

    fn update(&mut self, data: &[u8]) {
        self.0.wchasher_update(data);
    }
}

#[cfg(test)]
mod tests {
    use super::{WCSha256};
    use rustls::crypto::hash::Hash;

    #[test]
    fn test_sha256() {
        let wcsha256_struct = WCSha256;
        let hash1 = wcsha256_struct.hash("hello".as_bytes());
        let hash2 = wcsha256_struct.hash("hello".as_bytes());

        let hash_str1 = hex::encode(hash1);
        let hash_str2 = hex::encode(hash2);

        assert_eq!(
            hash_str1,
            hash_str2
        );
    }
}

unsafe impl Sync for WCHasher256{}
unsafe impl Send for WCHasher256{}
impl Clone for WCHasher256 {
    // Clone implementation.
    // Returns a copy of the WCHasher256 struct.
    fn clone(&self) -> WCHasher256 {
        WCHasher256 {
            sha256_struct: self.sha256_struct.clone(),
            hash: self.hash.clone()
        }
    }
}
