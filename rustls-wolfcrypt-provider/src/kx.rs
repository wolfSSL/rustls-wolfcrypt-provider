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
    public_key: Curve25519KeyObject,
    public_key_bytes: Vec<u8>,
    private_key: Curve25519KeyObject,
}

impl KeyExchange {
    pub fn use_curve25519() -> Self {
        unsafe {
            let mut public_key: curve25519_key = mem::zeroed();
            let mut private_key: curve25519_key = mem::zeroed();
            let public_key_object = Curve25519KeyObject::from_ptr(&mut public_key);
            let private_key_object = Curve25519KeyObject::from_ptr(&mut private_key);
            let mut ret;
            let mut rng: WC_RNG = mem::zeroed();

            ret = wc_curve25519_init(public_key_object.as_ptr());
            if ret != 0 {
                panic!("failed when calling wc_curve255519_init");
            }
            ret = wc_curve25519_init(private_key_object.as_ptr());
            if ret != 0 {
                panic!("failed when calling wc_curve255519_init");
            }

            ret = wc_InitRng(&mut rng);
            if ret != 0 {
                panic!("failed when calling wc_InitRng");
            }

            ret = wc_curve25519_make_key(&mut rng, 32, public_key_object.as_ptr());
            if ret != 0 {
                panic!("failed when calling wc_curve255519_init");
            }
            ret = wc_curve25519_make_key(&mut rng, 32, private_key_object.as_ptr());
            if ret != 0 {
                panic!("failed when calling wc_curve25519_make_key");
            }

            let mut out: [u8; CURVE25519_KEYSIZE as usize] = [0; CURVE25519_KEYSIZE as usize];
            let mut out_length: u32 = 32;

            ret = wc_curve25519_export_public(public_key_object.as_ptr(), out.as_mut_ptr(), &mut out_length);
            if ret != 0 {
                panic!("failed when calling wc_curve25519_export_public with ret value: {}", ret);
            }

            Self {
                public_key: public_key_object,
                public_key_bytes: out.to_vec(),
                private_key: private_key_object
            }
        }
    }

    fn get_public_key_bytes(&self) -> &[u8] {
        self.public_key_bytes.as_slice()
    }

    fn derive_shared_secret(&mut self, peer_pub_key: Vec<u8>) -> Vec<u8> {
        unsafe {
            let mut ret;
            let mut peer_pub_key_struct: curve25519_key = mem::zeroed();
            let peer_pub_key_object = Curve25519KeyObject::from_ptr(&mut peer_pub_key_struct);
            let mut rng: WC_RNG = mem::zeroed();
            
            ret = wc_curve25519_init(peer_pub_key_object.as_ptr());
            if ret != 0 {
                panic!("failed when calling wc_curve255519_init");
            }

            ret = wc_InitRng(&mut rng);
            if ret != 0 {
                panic!("failed when calling wc_InitRng");
            }

            ret = wc_curve25519_import_public(
                    peer_pub_key.as_ptr(), 
                    peer_pub_key.capacity().try_into().unwrap(), 
                    peer_pub_key_object.as_ptr()
            );
            if ret != 0 {
                panic!("failed when calling wc_curve25519_import_public");
            }

            let mut out: [u8; CURVE25519_KEYSIZE as usize] = [0; CURVE25519_KEYSIZE as usize];
            let mut out_length: word32 = out.len() as word32;

            ret = wc_curve25519_shared_secret(
                    self.private_key.as_ptr(), 
                    peer_pub_key_object.as_ptr(), 
                    out.as_mut_ptr(), 
                    &mut out_length
            );
            if ret != 0 {
                panic!("failed when calling wc_curve25519_shared_secret with ret value: {}", ret);
            }

           out.to_vec()
        }
    }
}

impl crypto::ActiveKeyExchange for KeyExchange {
    fn complete(
        mut self: Box<Self>,
        peer: &[u8],
    ) -> Result<crypto::SharedSecret, rustls::Error> {
        let peer_pub_key = peer.to_vec();

        let shared_secret_v = self.derive_shared_secret(peer_pub_key);
        let shared_secret_slice = shared_secret_v.as_slice();

        Ok(crypto::SharedSecret::from(&shared_secret_slice[..]))
    }

   fn pub_key(&self) -> &[u8] {
       self.public_key_bytes.as_slice()
   }

    fn group(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyExchange};
    
    #[test]
    fn test_curve25519() {
        let mut alice = KeyExchange::use_curve25519();
        let mut bob = KeyExchange::use_curve25519();

        let bob_public_key = (bob.get_public_key_bytes()).to_vec();
        let alice_public_key = (alice.get_public_key_bytes()).to_vec();

        assert_eq!(
            alice.derive_shared_secret(bob_public_key), 
            bob.derive_shared_secret(alice_public_key), 
        );
    }
}
