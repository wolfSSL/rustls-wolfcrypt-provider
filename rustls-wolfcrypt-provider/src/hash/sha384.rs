use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};
use rustls::crypto::hash;
use wolfssl_wolfcrypt::sha::SHA384;

pub struct WCSha384;

impl hash::Hash for WCSha384 {
    fn fips(&self) -> bool {
        cfg!(fips)
    }

    fn start(&self) -> Box<dyn hash::Context> {
        let sha384 = SHA384::new().expect("SHA384::new failed");
        Box::new(WCSha384Context::new(sha384))
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
        SHA384::DIGEST_SIZE
    }
}

// `SHA384::copy` takes `&mut self` because `wc_Sha384Copy` may write to its
// source on some hardware ports (e.g. MAXQ10XX), while rustls forks a context
// through `&self`. The cell lets `fork` reach the state, and the `copying`
// flag makes concurrent forks take turns so only one `&mut` exists at a time.
struct WCSha384Context {
    state: UnsafeCell<SHA384>,
    copying: AtomicBool,
}

impl WCSha384Context {
    fn new(sha384: SHA384) -> Self {
        Self {
            state: UnsafeCell::new(sha384),
            copying: AtomicBool::new(false),
        }
    }

    fn copy(&self) -> SHA384 {
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
        copy.expect("SHA384::copy failed")
    }
}

fn finalize(sha384: &mut SHA384) -> hash::Output {
    let mut out = [0u8; SHA384::DIGEST_SIZE];
    sha384.finalize(&mut out).expect("SHA384::finalize failed");
    hash::Output::new(&out)
}

impl hash::Context for WCSha384Context {
    fn fork_finish(&self) -> hash::Output {
        finalize(&mut self.copy())
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(WCSha384Context::new(self.copy()))
    }

    fn finish(mut self: Box<Self>) -> hash::Output {
        finalize(self.state.get_mut())
    }

    fn update(&mut self, data: &[u8]) {
        self.state
            .get_mut()
            .update(data)
            .expect("SHA384::update failed");
    }
}

unsafe impl Sync for WCSha384Context {}
unsafe impl Send for WCSha384Context {}

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
