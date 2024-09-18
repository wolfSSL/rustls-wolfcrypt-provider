use wolfcrypt_rs::*;
use core::mem;
use foreign_types::{ForeignType, ForeignTypeRef, Opaque};
use std::{ptr::NonNull};

pub fn wolfcrypt_random_buffer_generator(buff: &mut [u8]) {
    unsafe {
        let mut rng: WC_RNG = mem::zeroed();
        let rng_object = WCRNGObject::from_ptr(&mut rng);
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

pub struct WCRNGObjectRef(Opaque);
unsafe impl ForeignTypeRef for WCRNGObjectRef {
    type CType = WC_RNG;
}

pub struct  WCRNGObject(NonNull<WC_RNG>);
unsafe impl Sync for WCRNGObject{}
unsafe impl Send for WCRNGObject{}
unsafe impl ForeignType for WCRNGObject {
    type CType = WC_RNG;

    type Ref = WCRNGObjectRef;

    unsafe fn from_ptr(ptr: *mut Self::CType) -> Self {
        Self(NonNull::new_unchecked(ptr))
    }

    fn as_ptr(&self) -> *mut Self::CType {
        self.0.as_ptr()
    }
}

impl Drop for WCRNGObject {
    fn drop(&mut self) {
        unsafe {
            // Correctly free the RNG object.
            let ret = wc_FreeRng(self.as_ptr());
            if ret != 0 {
                panic!("Error while freeing RNG!");
            }
        }
    }
}
