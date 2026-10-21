use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};
use rustls::crypto::hash;
use wolfssl_wolfcrypt::sha::SHA256;

pub struct WCSha256;

impl hash::Hash for WCSha256 {
    fn fips(&self) -> bool {
        cfg!(fips)
    }

    fn start(&self) -> Box<dyn hash::Context> {
        let sha256 = SHA256::new().expect("SHA256::new failed");
        Box::new(WCSha256Context::new(sha256))
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
        SHA256::DIGEST_SIZE
    }
}

// `SHA256::copy` takes `&mut self` because `wc_Sha256Copy` may write to its
// source on some hardware ports (e.g. MAXQ10XX), while rustls forks a context
// through `&self`. The cell lets `fork` reach the state, and the `copying`
// flag makes concurrent forks take turns so only one `&mut` exists at a time.
struct WCSha256Context {
    state: UnsafeCell<SHA256>,
    copying: AtomicBool,
}

impl WCSha256Context {
    fn new(sha256: SHA256) -> Self {
        Self {
            state: UnsafeCell::new(sha256),
            copying: AtomicBool::new(false),
        }
    }

    fn copy(&self) -> SHA256 {
        while self
            .copying
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        // Safe because holding `copying` gives this thread sole access to the
        // state until it is released below, and `update` and `finish` need
        // `&mut self`.
        let copy = unsafe { &mut *self.state.get() }.copy();
        self.copying.store(false, Ordering::Release);
        copy.expect("SHA256::copy failed")
    }
}

fn finalize(sha256: &mut SHA256) -> hash::Output {
    let mut out = [0u8; SHA256::DIGEST_SIZE];
    sha256.finalize(&mut out).expect("SHA256::finalize failed");
    hash::Output::new(&out)
}

impl hash::Context for WCSha256Context {
    fn fork_finish(&self) -> hash::Output {
        finalize(&mut self.copy())
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(WCSha256Context::new(self.copy()))
    }

    fn finish(mut self: Box<Self>) -> hash::Output {
        finalize(self.state.get_mut())
    }

    fn update(&mut self, data: &[u8]) {
        self.state
            .get_mut()
            .update(data)
            .expect("SHA256::update failed");
    }
}

unsafe impl Sync for WCSha256Context {}
unsafe impl Send for WCSha256Context {}

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
