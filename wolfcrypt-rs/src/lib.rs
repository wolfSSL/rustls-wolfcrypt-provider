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
        let mut out: [u8; 256] = [0; 256];
        let out_ptr: *mut u8 = out.as_mut_ptr();
        let mut plain: [u8; 256] = [0; 256];
        let plain_ptr: *mut u8 = plain.as_mut_ptr();
        let mut ret;

        unsafe {
            ret = wc_InitRng(&mut rng);
            if ret != 0 {
                panic!("Error while initializing RNG!");
            }

            let input_u8: *const u8 = input.as_ptr() as *const u8;

            ret = wc_RsaPublicEncrypt_ex(input_u8, mem::size_of_val(&*input_u8).try_into().unwrap(), out_ptr, mem::size_of_val(&out).try_into().unwrap(), rsa_key_ptr, rng_ptr, 
                WC_RSA_OAEP_PAD.try_into().unwrap(), wc_HashType_WC_HASH_TYPE_SHA, WC_MGF1SHA1.try_into().unwrap(), 
                std::ptr::null_mut(), 0);
            if ret < 0 {
                panic!("Error while encrypting with RSA!");
            }

            ret = wc_RsaPrivateDecrypt_ex(out_ptr, ret.try_into().unwrap(), plain_ptr, mem::size_of_val(&out).try_into().unwrap(), rsa_key_ptr,
                WC_RSA_OAEP_PAD.try_into().unwrap(), wc_HashType_WC_HASH_TYPE_SHA, WC_MGF1SHA1.try_into().unwrap(), 
                std::ptr::null_mut(), 0);
            if ret < 0 {
                panic!("Error while decrypting with RSA!");
            }

            assert_eq!(ret, 0);
        }
    }
}
