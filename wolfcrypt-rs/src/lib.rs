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
            let mut rsa_key: RsaKey = mem::zeroed();
            let mut input: String = "I use Turing Machines to ask questions".to_string();
            let input_ptr: *mut u8 = input.as_mut_ptr();
            let input_length: word32 = input.len() as word32;
            let mut out: [u8; 256] = [0; 256];
            let mut plain: [u8; 256] = [0; 256];

            let mut ret;
            ret = wc_InitRsaKey(&mut rsa_key, std::ptr::null_mut());
            if ret != 0 {
                panic!("Error while initializing Rsa key! Ret value: {}", ret);
            }

            ret = wc_InitRng(&mut rng);
            if ret != 0 {
                panic!("Error while initializing RNG!");
            }

            ret = wc_RsaSetRNG(&mut rsa_key, &mut rng);
            if ret != 0 {
                panic!("Error while setting rng to Rsa key! Ret value: {}", ret);
            }

            ret = wc_MakeRsaKey(&mut rsa_key, 1024, 65537, &mut rng);
            if ret != 0 {
                panic!("Error while creating the Rsa Key! Ret value: {}", ret);
            }

            ret = wc_RsaPublicEncrypt(
                input_ptr,
                input_length,
                out.as_mut_ptr(),
                mem::size_of_val(&out).try_into().unwrap(),
                &mut rsa_key,
                &mut rng,
            );

            if ret < 0 {
                panic!("Error while encrypting with RSA! Ret value: {}", ret);
            }

            ret = wc_RsaPrivateDecrypt(
                out.as_mut_ptr(),
                ret.try_into().unwrap(),
                plain.as_mut_ptr(),
                mem::size_of_val(&plain).try_into().unwrap(),
                &mut rsa_key,
            );

            if ret < 0 {
                panic!("Error while decrypting with RSA! Ret value: {}", ret);
            }

            let plain_str = String::from_utf8_lossy(&plain).to_string();
            let input_str = std::ffi::CStr::from_ptr(input_ptr as *const std::os::raw::c_char)
                .to_str()
                .expect("Failed to convert C string to str");

            assert_eq!(plain_str.trim_end_matches('\0'), input_str);

            wc_FreeRsaKey(&mut rsa_key);
            wc_FreeRng(&mut rng);
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
