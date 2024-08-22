use alloc::boxed::Box;
use crypto::SupportedKxGroup;
use rustls::crypto;
use std::mem;
use wolfcrypt_rs::*;
use foreign_types::{ForeignType, ForeignTypeRef, Opaque};
use std::{ptr::NonNull};

pub const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[&X25519, /*&SecP256R1*/];

#[derive(Debug)]
pub struct X25519;

impl crypto::SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        Ok(Box::new(KeyExchangeX25519::use_curve25519()))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

#[derive(Debug)]
pub struct SecP256R1;

impl crypto::SupportedKxGroup for SecP256R1 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        Ok(Box::new(KeyExchangeSecP256r1::use_secp256r1()))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::secp256r1
    }
}

pub struct KeyExchangeX25519 {
    pub_key_bytes: Vec<u8>,
    priv_key_bytes: Vec<u8>,
}

pub struct KeyExchangeSecP256r1 {
    priv_key_bytes: Vec<u8>,
    pub_key_bytes: Vec<u8>,
}

pub struct ECCPubKey {
    qx: Vec<u8>,
    qx_len: word32,
    qy: Vec<u8>,
    qy_len: word32
}

impl KeyExchangeSecP256r1 {
    pub fn use_secp256r1() -> Self {
        unsafe {
            let mut key: ecc_key = mem::zeroed();
            let key_object = ECCKeyObject::from_ptr(&mut key);
            let mut rng: WC_RNG = mem::zeroed();
            let mut ret;
            let mut pub_key_raw = ECCPubKey {
                qx: [0; 32].to_vec(),
                qx_len: 32,
                qy: [0; 32].to_vec(),
                qy_len: 32,
            };
            let mut priv_key_raw: [u8; 32] = [0; 32];
            let mut priv_key_raw_len: word32 = priv_key_raw.len() as word32;

            ret = wc_ecc_init(key_object.as_ptr());
            if ret != 0 {
                panic!("failed while calling wc_ecc_init, ret = {}", ret);
            }

            ret = wc_InitRng(&mut rng);
            if ret != 0 {
                panic!("failed while calling wc_InitRng, ret = {}", ret);
            }

            ret = wc_ecc_make_key_ex(
                &mut rng, 
                32, 
                key_object.as_ptr(),
                ecc_curve_id_ECC_SECP256R1
            );
            if ret != 0 {
                panic!("failed while calling wc_ecc_make_key, ret = {}", ret);
            }

            ret = wc_ecc_export_private_only(
                key_object.as_ptr(), 
                priv_key_raw.as_mut_ptr(), 
                &mut priv_key_raw_len
            );
            if ret != 0 {
                panic!("failed while calling wc_ecc_export_private_only, ret = {}", ret);
            }

            ret = wc_ecc_export_public_raw(
                key_object.as_ptr(),
                pub_key_raw.qx.as_mut_ptr(),
                &mut pub_key_raw.qx_len,
                pub_key_raw.qy.as_mut_ptr(),
                &mut pub_key_raw.qy_len,
            );
            if ret != 0 {
                panic!("failed while calling wc_ecc_export_public_raw, ret = {}", ret);
            }

            let mut pub_key_bytes = Vec::new();

            pub_key_bytes.push(0x04);
            pub_key_bytes.extend(pub_key_raw.qx.clone());
            pub_key_bytes.extend(pub_key_raw.qy.clone());
            pub_key_bytes.as_slice();

            KeyExchangeSecP256r1 {
                priv_key_bytes: priv_key_raw.to_vec(),
                pub_key_bytes: pub_key_bytes.to_vec()
            }
        }
    }

    fn derive_shared_secret(&self, peer_pub_key: Vec<u8>) -> Vec<u8> {
        unsafe {
            let mut priv_key: ecc_key = mem::zeroed();
            let mut pub_key: ecc_key = mem::zeroed();
            let mut ret;
            let mut out: [u8; 32] = [0; 32];
            let mut out_len: word32 = out.len() as word32;
            let mut rng: WC_RNG = mem::zeroed();

            ret = wc_ecc_init(&mut priv_key);
            if ret != 0 {
                panic!("failed while calling wc_ecc_init, ret = {}", ret);
            }

            ret = wc_ecc_init(&mut pub_key);
            if ret != 0 {
                panic!("failed while calling wc_ecc_init, ret = {}", ret);
            }

            ret = wc_ecc_import_private_key_ex(
                self.priv_key_bytes.as_ptr(), 
                self.priv_key_bytes.len() as word32, 
                std::ptr::null_mut(), 
                0,   
                &mut priv_key,
                ecc_curve_id_ECC_SECP256R1
            );
            if ret != 0 {
                panic!("failed while calling wc_ecc_import_private_key_ex, with ret value: {}", ret);
            }

            /* 
             * Skipping first byte because rustls uses this format:
             * https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8.2.
             * */
            ret = wc_ecc_import_unsigned(
                &mut pub_key,
                peer_pub_key[1..33].as_ptr(),             
                peer_pub_key[33..].as_ptr(),             
                std::ptr::null_mut(),                 
                ecc_curve_id_ECC_SECP256R1
            );
            if ret != 0 {
                panic!("failed while calling wc_ecc_import_unsigned, with ret value: {}", ret);
            }

            ret = wc_InitRng(&mut rng);
            if ret != 0 {
                panic!("failed while calling wc_InitRng, ret = {}", ret);
            }

            ret = wc_ecc_set_rng(
                    &mut pub_key, 
                    &mut rng
            );
             if ret != 0 {
                panic!("failed while calling wc_ecc_set_rng, ret = {}", ret);
            }

            ret = wc_ecc_set_rng(
                    &mut priv_key, 
                    &mut rng
            );
            if ret != 0 {
                panic!("failed while calling wc_ecc_set_rng, ret = {}", ret);
            }

            ret = wc_ecc_shared_secret(
                &mut priv_key, 
                &mut pub_key, 
                out.as_mut_ptr(), 
                &mut out_len
            );
            if ret != 0 {
                panic!("failed while calling wc_ecc_import_unsigned, with ret value: {}", ret);
            }

            out.to_vec()
        }
    }
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

    fn derive_shared_secret(&self, peer_pub_key: Vec<u8>) -> Vec<u8> {
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

impl crypto::ActiveKeyExchange for KeyExchangeX25519 {
    fn complete(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<crypto::SharedSecret, rustls::Error> {
        // We derive the shared secret with our private key and 
        // the received public key.
        let secret = self.derive_shared_secret(peer_pub_key.to_vec());

        Ok(crypto::SharedSecret::from(secret.as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key_bytes
    }

    fn group(&self) -> rustls::NamedGroup {
        X25519.name()
    }
}

impl crypto::ActiveKeyExchange for KeyExchangeSecP256r1 {
    fn complete(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<crypto::SharedSecret, rustls::Error> {
        // We derive the shared secret with our private key and 
        // the received public key.
        let secret = self.derive_shared_secret(peer_pub_key.to_vec());

        Ok(crypto::SharedSecret::from(secret.as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key_bytes.as_slice()
    }

    fn group(&self) -> rustls::NamedGroup {
        X25519.name()
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

    #[test]
    fn test_secp256r1_kx() {
        env_logger::init();
        log::debug!("alice");
        let alice = Box::new(KeyExchangeSecP256r1::use_secp256r1());

        log::debug!("bob");
        let bob = Box::new(KeyExchangeSecP256r1::use_secp256r1());

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

pub struct ECCKeyObjectRef(Opaque);
unsafe impl ForeignTypeRef for ECCKeyObjectRef {
    type CType = ecc_key;
}

#[derive(Debug, Clone, Copy)]
pub struct ECCKeyObject(NonNull<ecc_key>);
unsafe impl Sync for ECCKeyObject{}
unsafe impl Send for ECCKeyObject{}
unsafe impl ForeignType for ECCKeyObject {
    type CType = ecc_key;

    type Ref = ECCKeyObjectRef;

    unsafe fn from_ptr(ptr: *mut Self::CType) -> Self {
        Self(NonNull::new_unchecked(ptr))
    }

    fn as_ptr(&self) -> *mut Self::CType {
        self.0.as_ptr()
    }
}
