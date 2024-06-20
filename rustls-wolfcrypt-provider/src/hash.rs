use alloc::boxed::Box;

use rustls::crypto::hash;
use sha2::Digest;

pub struct Sha256;

impl hash::Hash for Sha256 {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(Sha256Context(sha2::Sha256::new()))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        hash::Output::new(&sha2::Sha256::digest(data)[..])
    }

    fn algorithm(&self) -> hash::HashAlgorithm {
        hash::HashAlgorithm::SHA256
    }

    fn output_len(&self) -> usize {
        32
    }
}

struct Sha256Context(sha2::Sha256);

impl hash::Context for Sha256Context {
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(&self.0.clone().finalize()[..])
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(Sha256Context(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(&self.0.finalize()[..])
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

#[cfg(test)]
mod tests {
    use wolfcrypt_rs::{wc_Sha256, word32, wc_InitSha256, wc_Sha256Update, wc_Sha256Final};
    use std::mem;
    use std::{format, println};
    use alloc::string::{String, ToString};
    use hex;

    #[test]
    fn sha256_test() {
        unsafe {
            let mut sha256_struct: wc_Sha256 = mem::zeroed();
            let data = "data to be hashed".as_bytes();
            let length: word32 = data.len() as word32;
            let mut ret;
            let mut hash: [u8; 32] = [0; 32];

            ret = wc_InitSha256(&mut sha256_struct);
            if ret != 0 {
                panic!("wc_InitSha256 failed with ret: {}", ret);
            }

            ret = wc_Sha256Update(&mut sha256_struct, data.as_ptr() as *const u8, length);
            if ret != 0 {
                panic!("wc_Sha256Update failed with ret: {}", ret);
            }

            ret = wc_Sha256Final(&mut sha256_struct, hash.as_mut_ptr());
            if ret != 0 {
                panic!("wc_Sha256Final failed with ret: {}", ret);
            }

            let hash_str = hex::encode(hash);

            assert_eq!(hash_str, "4c87bc239d6d267654850138b28644c71ab275dfdba007e4dceef7f0e0f47026")
        }
    }
}
