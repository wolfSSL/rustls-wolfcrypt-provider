/*
 * TODO: Write more sanity checks for more coverage of
 *       the wolfcrypt bindings, for now I only wrote
 *       a simple RSA encrypt/decrypt test even though all 
 *       the bindgen tests seems pass).
 * */

mod bindings;
pub use bindings::*;

use std::mem;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_encrypt_decrypt() {
        let mut rng: WC_RNG = unsafe { mem::zeroed() };
        let rng_ptr: *mut bindings::WC_RNG = &mut rng;
        let mut rsa_key: RsaKey = unsafe { mem::zeroed() };
        let rsa_key_ptr: *mut bindings::RsaKey = &mut rsa_key;
        let input: String = "I use Turing Machines to ask questions".to_string();
        let input_u8: *const u8 = input.as_ptr() as *const u8;
        let mut out: [u8; 256] = [0; 256];
        let out_ptr: *mut u8 = out.as_mut_ptr();
        let mut plain: [u8; 256] = [0; 256];
        let plain_ptr: *mut u8 = plain.as_mut_ptr();
        let mut ret;

        unsafe {
            ret = wc_InitRsaKey(rsa_key_ptr, std::ptr::null_mut());
            if ret != 0 {
                panic!("Error while initializing Rsa key! Ret value: {}", ret);
            }

            ret = wc_InitRng(rng_ptr);
            if ret != 0 {
                panic!("Error while initializing RNG!");
            }

            ret = wc_RsaSetRNG(rsa_key_ptr, rng_ptr);
            if ret != 0 {
                panic!("Error while setting rng to Rsa key! Ret value: {}", ret);
            }

            ret = wc_MakeRsaKey(rsa_key_ptr, 1024, 65537, rng_ptr);
            if ret != 0 {
                panic!("Error while creating the Rsa Key! Ret value: {}", ret);
            }

            ret = wc_RsaPublicEncrypt(
                input_u8,
                mem::size_of_val(&*input_u8).try_into().unwrap(),
                out_ptr,
                mem::size_of_val(&out).try_into().unwrap(),
                rsa_key_ptr,
                rng_ptr
            );

            if ret < 0 {
                panic!("Error while encrypting with RSA! Ret value: {}", ret);
            }

            ret = wc_RsaPrivateDecrypt(
                out_ptr,
                ret.try_into().unwrap(),
                plain_ptr,
                mem::size_of_val(&plain).try_into().unwrap(),
                rsa_key_ptr,
            );

            if ret < 0 {
                panic!("Error while decrypting with RSA! Ret value: {}", ret);
            }

            assert!(ret > 0);
        }
    }
}
