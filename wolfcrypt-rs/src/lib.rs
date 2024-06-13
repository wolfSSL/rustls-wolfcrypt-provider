pub mod bindings;
pub use bindings::*;

mod random;
pub use random::*;

use core::mem;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_encrypt_decrypt() {
        unsafe {
            let mut rng: WC_RNG = mem::zeroed();
            let rng_ptr: *mut bindings::WC_RNG = &mut rng;

            let mut rsa_key: RsaKey = mem::zeroed();
            let rsa_key_ptr: *mut bindings::RsaKey = &mut rsa_key;

            let mut input: String = "I use Turing Machines to ask questions".to_string();
            let input_ptr: *mut u8 = input.as_mut_ptr();
            let input_length: word32 = input.len() as word32;

            let mut out: [u8; 256] = [0; 256];
            let out_ptr: *mut u8 = out.as_mut_ptr();

            let mut plain: [u8; 256] = [0; 256];
            let plain_ptr: *mut u8 = plain.as_mut_ptr();

            let mut ret;
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
                input_ptr,
                input_length,
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

            let plain_str = String::from_utf8_lossy(&plain).to_string();
            let input_str = std::ffi::CStr::from_ptr(input_ptr as *const std::os::raw::c_char)
                .to_str()
                .expect("Failed to convert C string to str");

            assert_eq!(plain_str.trim_end_matches('\0'), input_str);

            wc_FreeRsaKey(rsa_key_ptr);
            wc_FreeRng(rng_ptr);
        }
    }

    #[test]
    fn random() {
        let mut buff_1: [u8; 10] = [0; 10];
        let mut buff_2: [u8; 10] = [0; 10];

        wolfcrypt_random_buffer_generator(&mut buff_1);
        wolfcrypt_random_buffer_generator(&mut buff_2);

        assert_ne!(buff_1, buff_2);
    }
}
