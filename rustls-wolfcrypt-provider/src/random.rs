use crate::types::*;
use core::mem;
use foreign_types::ForeignType;
use wolfcrypt_rs::*;

pub fn wolfcrypt_random_buffer_generator(buff: &mut [u8]) {
    unsafe {
        let mut rng: WC_RNG = mem::zeroed();
        let rng_object = WCRngObject::from_ptr(&mut rng);
        let buff_length: word32 = buff.len() as word32;
        let mut ret;

        // Gets the seed (from OS) and key cipher for rng.
        // rng->drbg (deterministic random bit generator) allocated
        // (should be deallocated with wc_FreeRng).
        // This is a blocking operation.
        ret = wc_InitRng(rng_object.as_ptr());
        if ret != 0 {
            panic!("Error while initializing RNG!");
        }

        // Copies a sz bytes of pseudorandom data to output.
        // Will reseed rng if needed (blocking).
        ret = wc_RNG_GenerateBlock(&mut rng, buff.as_mut_ptr(), buff_length);
        if ret != 0 {
            panic!("Error while generating block!");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::wolfcrypt_random_buffer_generator;

    #[test]
    fn test_random() {
        let mut buff_1: [u8; 10] = [0; 10];
        let mut buff_2: [u8; 10] = [0; 10];

        wolfcrypt_random_buffer_generator(&mut buff_1);
        wolfcrypt_random_buffer_generator(&mut buff_2);

        assert_ne!(buff_1, buff_2);
    }
}
