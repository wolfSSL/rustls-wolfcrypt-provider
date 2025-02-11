use crate::{error::check_if_zero, types::*};
use alloc::boxed::Box;
use core::mem;
use foreign_types::ForeignType;
use wolfcrypt_rs::*;

pub struct KeyExchangeX25519 {
    pub_key_bytes: Box<[u8]>,
    priv_key_bytes: Box<[u8]>,
}

impl KeyExchangeX25519 {
    pub fn use_curve25519() -> Self {
        let mut key: curve25519_key = unsafe { mem::zeroed() };
        let key_object = Curve25519KeyObject::new(&mut key);
        let mut rng: WC_RNG = unsafe { mem::zeroed() };
        let rng_object = WCRngObject::new(&mut rng);
        let mut ret;
        let mut pub_key_raw: [u8; 32] = [0; 32];
        let mut pub_key_raw_len: word32 = pub_key_raw.len() as word32;
        let mut priv_key_raw: [u8; 32] = [0; 32];
        let mut priv_key_raw_len: word32 = priv_key_raw.len() as word32;
        let endian: u32 = EC25519_LITTLE_ENDIAN;

        // We initialize the curve25519 key object.
        key_object.init();

        // We initialize the rng object.
        rng_object.init();

        // This function generates a Curve25519 key using the given random number generator, rng,
        // of the size given (keysize), and stores it in the given curve25519_key structure.
        ret = unsafe { wc_curve25519_make_key(&mut rng, 32, key_object.as_ptr()) };
        check_if_zero(ret).unwrap();

        // Export curve25519 key pair. Big or little endian.
        ret = unsafe {
            wc_curve25519_export_key_raw_ex(
                key_object.as_ptr(),
                priv_key_raw.as_mut_ptr(),
                &mut priv_key_raw_len,
                pub_key_raw.as_mut_ptr(),
                &mut pub_key_raw_len,
                endian.try_into().unwrap(),
            )
        };
        check_if_zero(ret).unwrap();

        KeyExchangeX25519 {
            pub_key_bytes: Box::new(pub_key_raw),
            priv_key_bytes: Box::new(priv_key_raw),
        }
    }

    pub fn derive_shared_secret(&self, peer_pub_key: &[u8]) -> Box<[u8]> {
        let mut ret;
        let endian: u32 = EC25519_LITTLE_ENDIAN;
        let mut pub_key_provided: curve25519_key = unsafe { mem::zeroed() };
        let pub_key_provided_object = Curve25519KeyObject::new(&mut pub_key_provided);
        let mut out: [u8; 32] = [0; 32];
        let mut out_len: word32 = out.len() as word32;
        let mut private_key: curve25519_key = unsafe { mem::zeroed() };
        let private_key_object = Curve25519KeyObject::new(&mut private_key);

        // This function checks that a public key buffer holds a valid
        // Curve25519 key value given the endian ordering.
        ret = unsafe {
            wc_curve25519_check_public(peer_pub_key.as_ptr(), 32, endian.try_into().unwrap())
        };
        check_if_zero(ret).unwrap();

        // We initialize the curve25519 key object before we import the public key in it.
        pub_key_provided_object.init();

        // This function imports a public key from the given input buffer
        // and stores it in the curve25519_key structure.
        ret = unsafe {
            wc_curve25519_import_public_ex(
                peer_pub_key.as_ptr(),
                32,
                &mut pub_key_provided,
                endian.try_into().unwrap(),
            )
        };
        check_if_zero(ret).unwrap();

        // We initialize the curve25519 key object before we import the private key in it.
        private_key_object.init();

        // This function imports a private key from the given input buffer
        // and stores it in the the curve25519_key structure.
        ret = unsafe {
            wc_curve25519_import_private_ex(
                self.priv_key_bytes.as_ptr(),
                32,
                private_key_object.as_ptr(),
                endian.try_into().unwrap(),
            )
        };
        check_if_zero(ret).unwrap();

        // This function computes a shared secret key given a secret private key and
        // a received public key. Stores the generated secret in the buffer out.
        ret = unsafe {
            wc_curve25519_shared_secret_ex(
                private_key_object.as_ptr(),
                &mut pub_key_provided,
                out.as_mut_ptr(),
                &mut out_len,
                endian.try_into().unwrap(),
            )
        };
        check_if_zero(ret).unwrap();

        Box::new(out)
    }
}

impl rustls::crypto::ActiveKeyExchange for KeyExchangeX25519 {
    fn complete(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<rustls::crypto::SharedSecret, rustls::Error> {
        // We derive the shared secret with our private key and
        // the received public key.
        let secret = self.derive_shared_secret(peer_pub_key);

        Ok(rustls::crypto::SharedSecret::from(&*secret))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key_bytes
    }

    fn group(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
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
