use wolfcrypt_rs::*;
use std::mem;
use foreign_types::{ForeignType, ForeignTypeRef, Opaque};
use std::{ptr::NonNull};
use rustls::crypto;
use std::boxed::Box;
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

#[derive(Clone)]
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

    fn get_key_as_bytes(&mut self) -> [u8; 32] {
        self.key_bytes
    }

    fn get_key(&mut self) -> Curve25519KeyObject {
        self.key.clone()
    }

    fn derive_shared_secret(&mut self, peer_pub_key: Curve25519KeyObject) -> [u8; 32] {
        unsafe {
            let ret;
            let mut out: [u8; 32] = [0; 32];
            let mut out_length: word32 = 32 as word32;

            ret = wc_curve25519_shared_secret(
                    self.key.as_ptr(), 
                    peer_pub_key.as_ptr(), 
                    out.as_mut_ptr(), 
                    &mut out_length,
            );
            if ret < 0 {
                panic!("failed when calling wc_curve25519_shared_secret_ex: {}", ret);
            }

           out
        }
    }
}

impl crypto::ActiveKeyExchange for KeyExchange {
    fn complete(
        mut self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<crypto::SharedSecret, rustls::Error> {
        unsafe {
            let mut peer_pub_key_struct: curve25519_key = mem::zeroed();
            let peer_pub_key_object = Curve25519KeyObject::from_ptr(&mut peer_pub_key_struct);
            let mut rng: WC_RNG = mem::zeroed();
            let mut ret;

            ret = wc_InitRng(&mut rng);
            if ret < 0 {
                panic!("failed when calling wc_InitRng");
            }

            ret = wc_curve25519_init(peer_pub_key_object.as_ptr());
            if ret < 0 {
                panic!("failed when calling wc_curve255519_init");
            }

            ret = wc_curve25519_import_public(
                peer_pub_key.as_ptr(), 
                32, 
                peer_pub_key_object.as_ptr(),
            );
            if ret < 0 {
                panic!("failed when calling wc_curve25519_import_public");
            }

            let shared_secret_v = self.derive_shared_secret(peer_pub_key_object);
            let shared_secret_slice = shared_secret_v.as_slice();

            Ok(crypto::SharedSecret::from(&shared_secret_slice[..]))
        }
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
        unsafe {
            let mut alice_key: curve25519_key = mem::zeroed();
            let alice_key_object = Curve25519KeyObject::from_ptr(&mut alice_key);

            let mut bob_key: curve25519_key = mem::zeroed();
            let bob_key_object = Curve25519KeyObject::from_ptr(&mut bob_key);

            let mut final_key_priv: curve25519_key = mem::zeroed();
            let final_key_object_priv = Curve25519KeyObject::from_ptr(&mut final_key_priv);

            let mut final_key_pub: curve25519_key = mem::zeroed();
            let final_key_object_pub = Curve25519KeyObject::from_ptr(&mut final_key_pub);

            let mut ret;
            let mut rng: WC_RNG = mem::zeroed();

            ret = wc_InitRng(&mut rng);
            if ret < 0 {
                panic!("failed when calling wc_InitRng");
            }

            ret = wc_curve25519_init(alice_key_object.as_ptr());
            if ret < 0 {
                panic!("failed when calling wc_curve255519_init");
            }

            ret = wc_curve25519_init(bob_key_object.as_ptr());
            if ret < 0 {
                panic!("failed when calling wc_curve255519_init");
            }

            ret = wc_curve25519_make_key(&mut rng, 32, alice_key_object.as_ptr());
            if ret < 0 {
                panic!("failed when calling wc_curve255519_init");
            }

            ret = wc_curve25519_make_key(&mut rng, 32, bob_key_object.as_ptr());
            if ret < 0 {
                panic!("failed when calling wc_curve255519_init");
            }

            let mut out_pub: [u8; 32] = [0; 32];
            let mut out_length_pub: u32 = 32;
            let mut out_priv: [u8; 32] = [0; 32];
            let mut out_length_priv: u32 = 32;

            ret = wc_curve25519_export_public(alice_key_object.as_ptr(), out_pub.as_mut_ptr(), &mut out_length_pub);
            if ret < 0 {
                panic!("failed when calling wc_curve25519_export_public with ret value: {}", ret);
            }

            ret = wc_curve25519_export_private_raw(alice_key_object.as_ptr(), out_priv.as_mut_ptr(), &mut out_length_priv);
            if ret < 0 {
                panic!("failed when calling wc_curve25519_export_public with ret value: {}", ret);
            }

            ret = wc_curve25519_init(final_key_object_pub.as_ptr());
            if ret < 0 {
                panic!("failed when calling wc_curve255519_init");
            }

            ret = wc_curve25519_init(final_key_object_priv.as_ptr());
            if ret < 0 {
                panic!("failed when calling wc_curve255519_init");
            }

            ret = wc_curve25519_import_public(
                out_pub.as_ptr(), 
                32, 
                final_key_object_pub.as_ptr(),
            );
            if ret < 0 {
                panic!("failed when calling wc_curve25519_import_public");
            }

            ret = wc_curve25519_import_private(
                out_priv.as_ptr(), 
                32, 
                final_key_object_priv.as_ptr(),
            );
            if ret < 0 {
                panic!("failed when calling wc_curve25519_import_public");
            }

            let mut bob_secret: [u8; 32] = [0; 32];
            let mut bob_secret_length: word32 = 32 as word32;

            ret = wc_curve25519_shared_secret(
                bob_key_object.as_ptr(), 
                final_key_object_pub.as_ptr(), 
                bob_secret.as_mut_ptr(), 
                &mut bob_secret_length,
            );
            if ret < 0 {
                panic!("failed when calling wc_curve25519_shared_secret_ex: {}", ret);
            }

            let mut final_secret: [u8; 32] = [0; 32];
            let mut final_secret_length: word32 = 32 as word32;

            ret = wc_curve25519_shared_secret(
                final_key_object_priv.as_ptr(), 
                bob_key_object.as_ptr(), 
                final_secret.as_mut_ptr(), 
                &mut final_secret_length,
            );
            if ret < 0 {
                panic!("failed when calling wc_curve25519_shared_secret_ex: {}", ret);
            }

            assert_eq!(
                bob_secret,
                final_secret,
            );
        }
    }
}
