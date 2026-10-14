use crate::error::*;
#[cfg(not(feature = "std"))]
use crate::types::*;
#[cfg(not(feature = "std"))]
use core::mem;
#[cfg(not(feature = "std"))]
use foreign_types::ForeignType;
#[cfg(not(feature = "std"))]
use wolfssl_wolfcrypt::sys::*;

// wolfCrypt rejects larger requests (RNG_MAX_BLOCK_LEN).
#[cfg(feature = "std")]
const MAX_CHUNK: usize = 0xFFFF;

#[cfg(feature = "std")]
std::thread_local! {
    static THREAD_RNG: std::cell::RefCell<Option<wolfssl_wolfcrypt::random::RNG>> =
        const { std::cell::RefCell::new(None) };
}

/// With `std`, one wolfCrypt RNG per thread, created on first use, instead of a
/// new one (seeded from the OS) on every call. A failed creation is retried on
/// the next call.
#[cfg(feature = "std")]
pub fn wolfcrypt_random_buffer_generator(buff: &mut [u8]) -> WCResult {
    use wolfssl_wolfcrypt::random::RNG;

    let result = THREAD_RNG
        .try_with(|cell| {
            let mut cell = cell.borrow_mut();
            if cell.is_none() {
                *cell = Some(RNG::new()?);
            }
            let rng = cell.as_ref().unwrap();
            buff.chunks_mut(MAX_CHUNK)
                .try_for_each(|chunk| rng.generate_block(chunk))
        })
        .unwrap_or(Err(-1));

    check_if_zero(result.err().unwrap_or(0))
}

#[cfg(not(feature = "std"))]
pub fn wolfcrypt_random_buffer_generator(buff: &mut [u8]) -> WCResult {
    let mut rng_c_type: WC_RNG = unsafe { mem::zeroed() };
    let rng_object = WCRngObject::new(&mut rng_c_type);
    let buff_length: word32 = buff.len() as word32;

    // Gets the seed (from OS) and key cipher for rng.
    // rng->drbg (deterministic random bit generator) allocated
    // (should be deallocated with wc_FreeRng).
    // This is a blocking operation.
    // Propagate an init failure (e.g. transient OS entropy/DRBG seeding error)
    // instead of panicking, so SecureRandom::fill can surface GetRandomFailed.
    rng_object.init()?;

    // Copies a sz bytes of pseudorandom data to output.
    // Will reseed rng if needed (blocking).
    let ret = unsafe { wc_RNG_GenerateBlock(rng_object.as_ptr(), buff.as_mut_ptr(), buff_length) };

    check_if_zero(ret)
}

#[cfg(test)]
mod tests {
    use super::wolfcrypt_random_buffer_generator;

    #[test]
    fn test_random() {
        let mut buff_1: [u8; 10] = [0; 10];
        let mut buff_2: [u8; 10] = [0; 10];

        wolfcrypt_random_buffer_generator(&mut buff_1).unwrap();
        wolfcrypt_random_buffer_generator(&mut buff_2).unwrap();

        assert_ne!(buff_1, buff_2);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_random_reuses_thread_rng() {
        let mut buff = [0u8; 10];
        wolfcrypt_random_buffer_generator(&mut buff).unwrap();

        assert!(super::THREAD_RNG.with(|cell| cell.borrow().is_some()));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_random_larger_than_one_chunk() {
        let mut buff = std::vec![0u8; 2 * super::MAX_CHUNK + 10];
        wolfcrypt_random_buffer_generator(&mut buff).unwrap();

        for chunk in buff.chunks(super::MAX_CHUNK) {
            assert!(chunk.iter().any(|&b| b != 0));
        }
    }
}
