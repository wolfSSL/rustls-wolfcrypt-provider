/*
 * Contains wrappers to interface with the 
 * <wolfssl/wolfcrypt/random.h> FFI binding
 * that can be used as input into the rustls
 * API.
 * */
use crate::bindings::*;

use core::mem;

// Calls wc_RNG_GenerateBlock, which copies a sz bytes of pseudorandom data to output. 
// Will reseed rng if needed (blocking).
pub fn wolfcrypt_random_buffer_generator(buff: &mut [u8]) {
    unsafe {
        let mut rng: WC_RNG = mem::zeroed();
        let buff_length: word32 = buff.len() as word32;
        let mut ret;

        ret = wc_InitRng(&mut rng);
        if ret != 0 {
            panic!("Error while initializing RNG!");
        }

        ret = wc_RNG_GenerateBlock(&mut rng, buff.as_mut_ptr(), buff_length);
        if ret != 0 {
            panic!("Error while generating block!");
        }
    }
}
