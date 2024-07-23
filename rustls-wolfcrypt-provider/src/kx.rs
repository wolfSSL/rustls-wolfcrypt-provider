use wolfcrypt_rs::*;
use std::mem;
use foreign_types::{ForeignType, ForeignTypeRef, Opaque};
use std::{ptr::NonNull};
use rustls::crypto;
use std::boxed::Box;
use std::vec::Vec;
use crypto::SupportedKxGroup;

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

pub struct KeyExchange {
    key: Curve25519KeyObject,
    key_bytes: [u8; 32],
}

impl KeyExchange {
    pub fn use_curve25519() -> Self {
        unsafe {
            let mut key: curve25519_key = mem::zeroed();
            let key_object = Curve25519KeyObject::from_ptr(&mut key);
            let mut ret;
            let mut rng: WC_RNG = mem::zeroed();

            ret = wc_InitRng(&mut rng);
            if ret < 0 {
                panic!("failed when calling wc_InitRng");
            }

            ret = wc_curve25519_init(key_object.as_ptr());
            if ret < 0 {
                panic!("failed when calling wc_curve255519_init");
            }

            ret = wc_curve25519_make_key(&mut rng, 32, key_object.as_ptr());
            if ret < 0 {
                panic!("failed when calling wc_curve255519_init");
            }

            let mut out: [u8; 32] = [0; 32];
            let mut out_length: u32 = 32;

            ret = wc_curve25519_export_public(key_object.as_ptr(), out.as_mut_ptr(), &mut out_length);
            if ret < 0 {
                panic!("failed when calling wc_curve25519_export_public with ret value: {}", ret);
            }

            Self {
                key: key_object,
                key_bytes: out,
            }
        }
    }

    fn get_key_as_bytes(&self) -> [u8; 32] {
        self.key_bytes
    }

    fn derive_shared_secret(&mut self, peer_pub_key: [u8; 32]) -> Vec<u8> {
        unsafe {
            let mut ret;
            let mut peer_pub_key_struct: curve25519_key = mem::zeroed();
            let peer_pub_key_object = Curve25519KeyObject::from_ptr(&mut peer_pub_key_struct);
            let mut rng: WC_RNG = mem::zeroed();
            
            ret = wc_curve25519_init(peer_pub_key_object.as_ptr());
            if ret < 0 {
                panic!("failed when calling wc_curve255519_init");
            }

            ret = wc_InitRng(&mut rng);
            if ret < 0 {
                panic!("failed when calling wc_InitRng");
            }

            ret = wc_curve25519_check_public(
                    peer_pub_key.as_ptr(), 
                    32, 
                    EC25519_BIG_ENDIAN.try_into().unwrap()
            );
            if ret < 0 {
                panic!("failed when calling wc_curve25519_check_public_ex")
            }

            ret = wc_curve25519_import_public(
                    peer_pub_key.as_ptr(), 
                    32, 
                    peer_pub_key_object.as_ptr(),
            );
            if ret < 0 {
                panic!("failed when calling wc_curve25519_import_public");
            }

            let mut out: [u8; 32] = [0; 32];
            let mut out_length: word32 = 32 as word32;

            ret = wc_curve25519_shared_secret(
                    self.key.as_ptr(), 
                    peer_pub_key_object.as_ptr(), 
                    out.as_mut_ptr(), 
                    &mut out_length,
            );
            if ret < 0 {
                panic!("failed when calling wc_curve25519_shared_secret_ex: {}", ret);
            }

           out.to_vec()
        }
    }
}

impl crypto::ActiveKeyExchange for KeyExchange {
    fn complete(
        mut self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<crypto::SharedSecret, rustls::Error> {

        let shared_secret_v = self.derive_shared_secret(peer_pub_key.try_into().unwrap());
        let shared_secret_slice = shared_secret_v.as_slice();

        Ok(crypto::SharedSecret::from(&shared_secret_slice[..]))
    }

   fn pub_key(&self) -> &[u8] {
       self.key_bytes.as_slice()
   }

    fn group(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_curve25519() {
        let mut alice = KeyExchange::use_curve25519();
        let mut bob = KeyExchange::use_curve25519();

        assert_eq!(
            alice.derive_shared_secret(bob.get_key_as_bytes().try_into().unwrap()),
            bob.derive_shared_secret(alice.get_key_as_bytes().try_into().unwrap()),
        );
    }
}
