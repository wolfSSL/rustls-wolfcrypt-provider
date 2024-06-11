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
        let mut rsa_key: RsaKey = unsafe { mem::zeroed() };
        let mut input: String = "I use Turing Machines to ask questions";
        let mut out: [u8; 256] = [0; 256];
        let mut plain: [u8; 256] = [0; 256];
        let ret;

        unsafe {
            ret = wc_InitRng(&mut rng);
            if ret != 0 {
                panic!("Error while initializing RNG!");
            }

            ret = wc_RsaPublicEncrypt_ex(input, sizeof(input), out, sizeof(out), &rsa_key, &rng, 
                WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA, WC_MGF1SHA1, NULL, 0);
            if (ret < 0) {
                panic!("Error while encrypting with RSA!");
            }

            ret = wc_RsaPublicDecrypt_ex(input, sizeof(input), out, sizeof(out), &rsa_key, &rng, 
                WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA, WC_MGF1SHA1, NULL, 0);
            if (ret < 0) {
                panic!("Error while decrypting with RSA!");
            }

            assert_eq!(ret, 0);
        }
    }
}
