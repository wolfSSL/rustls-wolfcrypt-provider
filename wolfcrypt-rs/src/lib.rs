pub mod bindings;
pub use bindings::*;

/// Attach an RNG to a curve25519 key so the blinded scalar multiplication has
/// entropy. wolfSSL only compiles wc_curve25519_set_rng when it builds the
/// blinded, pure-C curve25519 implementation (WOLFSSL_CURVE25519_BLINDING,
/// i.e. no asm backend). On asm builds the symbol is absent and blinding isn't
/// used, so this becomes a no-op. The curve25519_blinding cfg is emitted by
/// build.rs based on whether that symbol appears in the generated bindings.
///
/// # Safety
/// key must point to an initialized curve25519_key, and rng to an
/// initialized WC_RNG that outlives the following shared-secret call.
#[cfg(curve25519_blinding)]
pub unsafe fn curve25519_set_rng(key: *mut curve25519_key, rng: *mut WC_RNG) -> i32 {
    wc_curve25519_set_rng(key, rng)
}

/// No-op variant: builds without curve25519 blinding don't attach an RNG.
///
/// # Safety
/// Same contract as the blinding variant; the arguments are ignored.
#[cfg(not(curve25519_blinding))]
pub unsafe fn curve25519_set_rng(_key: *mut curve25519_key, _rng: *mut WC_RNG) -> i32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::c_int;
    use core::mem;

    #[test]
    fn rsa_encrypt_decrypt() {
        let mut rng: WC_RNG = unsafe { mem::zeroed() };
        let mut rsa_key: RsaKey = unsafe { mem::zeroed() };
        let input = "I use Turing Machines to ask questions";
        let input_length = input.len() as word32;
        let mut out = [0u8; 256];
        let mut plain = [0u8; 256];

        // Initialize RSA key
        let ret = unsafe { wc_InitRsaKey(&mut rsa_key, std::ptr::null_mut()) };
        if ret != 0 {
            panic!("Error while initializing Rsa key! Ret value: {}", ret);
        }

        // Initialize RNG
        let ret = unsafe { wc_InitRng(&mut rng) };
        if ret != 0 {
            panic!("Error while initializing RNG!");
        }

        // Set RNG for RSA
        let ret = unsafe { wc_RsaSetRNG(&mut rsa_key, &mut rng) };
        if ret != 0 {
            panic!("Error while setting rng to Rsa key! Ret value: {}", ret);
        }

        // Generate RSA key
        let ret = unsafe {
            wc_MakeRsaKey(
                &mut rsa_key,
                2048 as c_int,
                WC_RSA_EXPONENT.into(),
                &mut rng,
            )
        };
        if ret != 0 {
            panic!("Error while creating the Rsa Key! Ret value: {}", ret);
        }

        // Encrypt
        let ret = unsafe {
            wc_RsaPublicEncrypt(
                input.as_ptr() as *mut u8,
                input_length,
                out.as_mut_ptr(),
                out.len() as word32,
                &mut rsa_key,
                &mut rng,
            )
        };
        if ret < 0 {
            panic!("Error while encrypting with RSA! Ret value: {}", ret);
        }
        let encrypted_len = ret;

        // Decrypt
        let ret = unsafe {
            wc_RsaPrivateDecrypt(
                out.as_mut_ptr(),
                encrypted_len as word32,
                plain.as_mut_ptr(),
                plain.len() as word32,
                &mut rsa_key,
            )
        };
        if ret < 0 {
            panic!("Error while decrypting with RSA! Ret value: {}", ret);
        }
        let decrypted_len = ret as usize;

        // Compare results
        let decrypted_str = std::str::from_utf8(&plain[..decrypted_len])
            .expect("Failed to convert decrypted data to string");
        assert_eq!(decrypted_str, input);

        // Cleanup
        unsafe {
            wc_FreeRsaKey(&mut rsa_key);
            wc_FreeRng(&mut rng);
        }
    }
}
