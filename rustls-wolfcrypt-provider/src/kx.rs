use alloc::boxed::Box;
use crypto::SupportedKxGroup;
use rustls::crypto;
use std::mem;
use wolfcrypt_rs::*;
use foreign_types::{ForeignType, ForeignTypeRef, Opaque};
use std::{ptr::NonNull};

pub const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[&X25519 as &dyn SupportedKxGroup];

#[derive(Debug)]
pub struct X25519;

impl crypto::SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        Ok(Box::new(KeyExchange::use_curve25519()))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

#[derive(Debug)]
pub struct SecP256R1;

impl crypto::SupportedKxGroup for SecP256R1 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        Ok(Box::new(KeyExchange::use_secp256r1()))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::secp256r1
    }
}

pub struct KeyExchange {
    pub_key_bytes: Vec<u8>,
    priv_key_bytes: Vec<u8>,
    key_type: rustls::NamedGroup
}

impl KeyExchange {
    pub fn use_secp256r1() -> Self {
        unsafe {
            let mut priv_key: ecc_key = mem::zeroed();
            let priv_key_object = ECCKeyObject::from_ptr(&mut priv_key);
            let mut pub_key: ecc_key = mem::zeroed();
            let pub_key_object = ECCKeyObject::from_ptr(&mut pub_key);
            let mut rng: WC_RNG = mem::zeroed();
            let mut pub_key_raw: [u8; 133] = [0; 133];
            let mut pub_key_raw_len: word32 = pub_key_raw.len() as word32;
            let mut priv_key_raw: [u8; 66] = [0; 66];
            let mut priv_key_raw_len: word32 = priv_key_raw.len() as word32;
            let mut ret;

            // This function initializes a ECC key. 
            // It should be called before generating a key for the structure.
            ret = wc_ecc_init(pub_key_object.as_ptr());
            if ret < 0 {
                panic!("panic while calling wc_ecc_init, ret = {}", ret);
            }

            // This function initializes a ECC key. 
            // It should be called before generating a key for the structure.
            ret = wc_ecc_init(priv_key_object.as_ptr());
            if ret < 0 {
                panic!("panic while calling wc_ecc_init, ret = {}", ret);
            }

            ret = wc_InitRng(&mut rng);
            if ret < 0 {
                panic!("panic while calling wc_InitRng, ret = {}", ret);
            }

            let key_size = wc_ecc_get_curve_size_from_id(ecc_curve_id_ECC_SECP256R1);
            ret = wc_ecc_make_key_ex(
                &mut rng, 
                key_size, 
                priv_key_object.as_ptr(), 
                ecc_curve_id_ECC_SECP256R1
            );
            if ret != 0 {
                panic!("error while calling wc_ecc_make_key_ex, ret = {}", ret);
            }

            ret = wc_ecc_make_key_ex(
                &mut rng, 
                key_size, 
                pub_key_object.as_ptr(), 
                ecc_curve_id_ECC_SECP256R1
            );
            if ret != 0 {
                panic!("error while calling wc_ecc_make_key_ex, ret = {}", ret);
            }

            ret = wc_ecc_export_x963(
                pub_key_object.as_ptr(),
                pub_key_raw.as_mut_ptr(),
                &mut pub_key_raw_len,
            );
            if ret != 0 {
                panic!("error while calling wc_ecc_export_x963_ex, ret = {}", ret);
            }

            ret = wc_ecc_export_private_only(
                    priv_key_object.as_ptr(), 
                    priv_key_raw.as_mut_ptr(), 
                    &mut priv_key_raw_len
            );
            if ret != 0 {
                panic!("error while calling wc_ecc_export_private_only, ret = {}", ret);
            }

            KeyExchange {
                pub_key_bytes: pub_key_raw.to_vec(),
                priv_key_bytes: priv_key_raw.to_vec(),
                key_type: rustls::NamedGroup::secp256r1,
            }
        }
    }

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

            KeyExchange {
                pub_key_bytes: pub_key_raw.to_vec(),
                priv_key_bytes: priv_key_raw.to_vec(),
                key_type: rustls::NamedGroup::X25519,
            }
        }
    }

    fn derive_shared_secret(&self, peer_pub_key: Vec<u8>) ->  Vec<u8> {
        match self.key_type {
            rustls::NamedGroup::X25519 => {
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
            },
            rustls::NamedGroup::secp256r1 => {
                unsafe {
                    let mut out: [u8; 32] = [0; 32];
                    let mut out_len: word32 = out.len() as word32;
                    let mut ret;
                    let mut pub_key: ecc_key = mem::zeroed();
                    let pub_key_object: ECCKeyObject = ECCKeyObject::from_ptr(&mut pub_key);
                    let mut priv_key: ecc_key = mem::zeroed();
                    let priv_key_object: ECCKeyObject = ECCKeyObject::from_ptr(&mut priv_key);

                    ret = wc_ecc_init(pub_key_object.as_ptr());
                    if ret != 0 {
                        panic!("error while calling wc_ecc_init, ret = {}", ret);
                    }

                    ret = wc_ecc_init(priv_key_object.as_ptr());
                    if ret != 0 {
                        panic!("error while calling wc_ecc_init, ret = {}", ret);
                    }

                    ret = wc_ecc_import_x963(
                        peer_pub_key.as_ptr(),
                        peer_pub_key.len() as word32,
                        pub_key_object.as_ptr()
                    );
                    if ret != 0 {
                        panic!("error while calling wc_ecc_import_x963, ret = {}", ret);
                    }

                    ret = wc_ecc_import_private_key(
                        self.priv_key_bytes.as_ptr(),
                        self.priv_key_bytes.len() as word32,
                        self.pub_key_bytes.as_ptr(),
                        self.pub_key_bytes.len() as word32,
                        priv_key_object.as_ptr()
                    );
                    if ret != 0 {
                        panic!("error while calling wc_ecc_import_private_key, ret = {}", ret);
                    }

                    ret = wc_ecc_shared_secret(
                        priv_key_object.as_ptr(),
                        pub_key_object.as_ptr(),
                        out.as_mut_ptr(),
                        &mut out_len
                    );
                    if ret != 0 {
                        panic!("error while calling wc_ecc_shared_secret, ret = {}", ret);
                    }

                    out.to_vec()
                }
            },
            _ => unimplemented!(),
        }
    }
}

impl crypto::ActiveKeyExchange for KeyExchange {
    fn complete(
        self: Box<KeyExchange>,
        peer_pub_key: &[u8],
    ) -> Result<crypto::SharedSecret, rustls::Error> {
        // We derive the shared secret with our private key and 
        // the received public key.
        let secret = self.derive_shared_secret(peer_pub_key.to_vec());

        Ok(crypto::SharedSecret::from(secret.as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key_bytes.as_slice()
    }

    fn group(&self) -> rustls::NamedGroup {
        match self.key_type {
            rustls::NamedGroup::X25519 =>X25519.name(),
            rustls::NamedGroup::secp256r1 =>X25519.name(),
            _ => unimplemented!()
        }
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


#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::ActiveKeyExchange;

    #[test]
    fn test_curve25519_kx() {
        let alice = Box::new(KeyExchange::use_curve25519());
        let bob = Box::new(KeyExchange::use_curve25519());

        assert_eq!(
            alice.derive_shared_secret(bob.pub_key().try_into().unwrap()),
            bob.derive_shared_secret(alice.pub_key().try_into().unwrap()),
        )
    }

    #[test]
    fn test_secp256r1() {
        let alice = Box::new(KeyExchange::use_secp256r1());
        let bob = Box::new(KeyExchange::use_secp256r1());

        assert_eq!(
            alice.derive_shared_secret(bob.pub_key().try_into().unwrap()),
            bob.derive_shared_secret(alice.pub_key().try_into().unwrap()),
        )
    }
}
