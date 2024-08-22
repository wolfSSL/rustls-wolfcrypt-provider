use std::mem;
use wolfcrypt_rs::*;
use foreign_types::{ForeignType, ForeignTypeRef, Opaque};
use std::{ptr::NonNull};

pub struct KeyExchangeX25519 {
    pub pub_key_bytes: Vec<u8>,
    pub priv_key_bytes: Vec<u8>,
}

impl KeyExchangeX25519 {
    pub fn use_curve25519() -> Self {
        unsafe {
            let mut key: curve25519_key = mem::zeroed();
            let key_object = Curve25519KeyObject::from_ptr(&mut key);
            let mut rng: WC_RNG = mem::zeroed();
            let mut ret;
            let mut pub_key_raw: [u8; 32] = [0; 32];
            let mut pub_key_raw_len: word32 = pub_key_raw.len() as word32;
            let mut priv_key_raw: [u8; 32] = [0; 32];
            let mut priv_key_raw_len: word32 = priv_key_raw.len() as word32;
            let endian: u32 = EC25519_LITTLE_ENDIAN;

            // This function initializes a Curve25519 key. 
            // It should be called before generating a key for the structure.
            ret = wc_curve25519_init(key_object.as_ptr());
            if ret < 0 {
                panic!("panic while calling wc_curve25519_init, ret = {}", ret);
            }

            ret = wc_InitRng(&mut rng);
            if ret < 0 {
                panic!("panic while calling wc_InitRng, ret = {}", ret);
            }

            // This function generates a Curve25519 key using the given random number generator, rng, 
            // of the size given (keysize), and stores it in the given curve25519_key structure. 
            ret = wc_curve25519_make_key(
                &mut rng, 
                32, 
                key_object.as_ptr()
            );
            if ret < 0 {
                panic!("wc_curve25519_make_key");
            }

            // Export curve25519 key pair. Big or little endian.
            ret = wc_curve25519_export_key_raw_ex(
                key_object.as_ptr(),
                priv_key_raw.as_mut_ptr(), 
                &mut priv_key_raw_len, 
                pub_key_raw.as_mut_ptr(), 
                &mut pub_key_raw_len,
                endian.try_into().unwrap()
            );
            if ret < 0 {
                panic!("panic while calling wc_curve25519_export_key_raw_ex, ret = {}", ret);
            }

            KeyExchangeX25519 {
                pub_key_bytes: pub_key_raw.to_vec(),
                priv_key_bytes: priv_key_raw.to_vec()
            }
        }
    }

    pub fn derive_shared_secret(&self, peer_pub_key: Vec<u8>) -> Vec<u8> {
        unsafe {
            let mut ret;
            let endian: u32 = EC25519_LITTLE_ENDIAN;
            let mut pub_key_provided: curve25519_key = mem::zeroed();
            let mut out: [u8; 32] = [0; 32];
            let mut out_len: word32 = out.len() as word32;
            let mut private_key: curve25519_key = mem::zeroed();

            // This function checks that a public key buffer holds a valid 
            // Curve25519 key value given the endian ordering.
            ret = wc_curve25519_check_public(
                peer_pub_key.as_ptr(), 
                32, 
                endian.try_into().unwrap()
            );
            if ret < 0 {
                panic!("panic while calling wc_curve25519_check_public, ret = {}", ret);
            }

            ret = wc_curve25519_init(&mut pub_key_provided);
            if ret < 0 {
                panic!("panic while calling wc_curve25519_init, ret = {}", ret);
            }

            // This function imports a public key from the given input buffer 
            // and stores it in the curve25519_key structure.
            ret = wc_curve25519_import_public_ex(
                peer_pub_key.as_ptr(), 
                32, 
                &mut pub_key_provided, 
                endian.try_into().unwrap()
            );
            if ret < 0 {
                panic!("panic while calling wc_curve25519_import_public_ex, ret = {}", ret);
            }

            ret = wc_curve25519_init(&mut private_key);
            if ret < 0 {
                panic!("panic while calling wc_curve25519_init, ret = {}", ret);
            }

            // This function imports a private key from the given input buffer
            // and stores it in the the curve25519_key structure.
            ret = wc_curve25519_import_private_ex(
                self.priv_key_bytes.as_ptr(), 
                32, 
                &mut private_key, 
                endian.try_into().unwrap()
            );
            if ret != 0 {
                panic!("panic while calling wc_curve25519_import_private, ret = {}", ret);
            }

            // This function computes a shared secret key given a secret private key and 
            // a received public key. Stores the generated secret in the buffer out.
            ret = wc_curve25519_shared_secret_ex(
                &mut private_key, 
                &mut pub_key_provided, 
                out.as_mut_ptr(),
                &mut out_len, 
                endian.try_into().unwrap()
            );
            if ret < 0 {
                panic!("panic while calling wc_curve25519_shared_secret_ex, ret = {}", ret);
            }

            out.to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::ActiveKeyExchange;

    #[test]
    fn test_curve25519_kx() {
        let alice = Box::new(KeyExchangeX25519::use_curve25519());
        let bob = Box::new(KeyExchangeX25519::use_curve25519());

        assert_eq!(
            alice.derive_shared_secret(bob.pub_key().try_into().unwrap()),
            bob.derive_shared_secret(alice.pub_key().try_into().unwrap()),
        )
    }
}

pub struct Curve25519KeyObjectRef(Opaque);
unsafe impl ForeignTypeRef for Curve25519KeyObjectRef {
    type CType = curve25519_key;
}

pub struct Curve25519KeyObject(NonNull<curve25519_key>);
unsafe impl Sync for Curve25519KeyObject{}
unsafe impl Send for Curve25519KeyObject{}
unsafe impl ForeignType for Curve25519KeyObject {
    type CType = curve25519_key;

    type Ref = Curve25519KeyObjectRef;

    unsafe fn from_ptr(ptr: *mut Self::CType) -> Self {
        Self(NonNull::new_unchecked(ptr))
    }

    fn as_ptr(&self) -> *mut Self::CType {
        self.0.as_ptr()
    }
}

