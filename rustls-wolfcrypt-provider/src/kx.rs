use alloc::boxed::Box;
use crypto::SupportedKxGroup;
use rustls::crypto;
use std::mem;
use wolfcrypt_rs::*;
use foreign_types::{ForeignType, ForeignTypeRef, Opaque};
use std::{ptr::NonNull};

pub struct KeyExchange {
    priv_key: Curve25519KeyObject,
    pub_key: Curve25519KeyObject,
    pub_key_bytes: [u8; 32]
}

impl crypto::ActiveKeyExchange for KeyExchange {
    fn complete(
        self: Box<KeyExchange>,
        peer_pub_key: &[u8],
    ) -> Result<crypto::SharedSecret, rustls::Error> {
        unsafe {
            let peer_pub_key_array: [u8; 32] = peer_pub_key
                .try_into()
                .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
            let mut ret;
            let endian: u32 = EC25519_LITTLE_ENDIAN;
            let mut pub_key_provided: curve25519_key = mem::zeroed();
            let mut out: [u8; 32] = [0; 32];
            let mut out_len: word32 = out.len() as word32;

            ret = wc_curve25519_check_public(
                    peer_pub_key_array.as_ptr(), 
                    32, 
                    endian.try_into().unwrap()
            );
            if ret < 0 {
                panic!("wc_curve25519_check_public");
            }

            ret = wc_curve25519_init(&mut pub_key_provided);
            if ret < 0 {
                panic!("wc_curve25519_init");
            }

            ret = wc_curve25519_import_public_ex(
                peer_pub_key_array.as_ptr(), 
                32, 
                &mut pub_key_provided, 
                endian.try_into().unwrap()
            );
            if ret < 0 {
                panic!("wc_curve25519_import_public_ex");
            }

           ret = wc_curve25519_shared_secret_ex(
               self.priv_key.as_ptr(), 
               &mut pub_key_provided, 
               out.as_mut_ptr(),
               &mut out_len, 
               endian.try_into().unwrap()
           );
           if ret != 0 {
               panic!("wc_curve25519_shared_secret_ex, ret = {}", ret);
           }

            Ok(crypto::SharedSecret::from(&out[..]))
        }
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key_bytes
    }

    fn group(&self) -> rustls::NamedGroup {
        X25519.name()
    }
}

pub const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[&X25519 as &dyn SupportedKxGroup];

#[derive(Debug)]
pub struct X25519;

impl crypto::SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        unsafe {
            let mut private_key: curve25519_key = mem::zeroed();
            let mut public_key: curve25519_key = mem::zeroed();
            let public_key_object = Curve25519KeyObject::from_ptr(&mut public_key);
            let private_key_object = Curve25519KeyObject::from_ptr(&mut private_key);
            let mut rng: WC_RNG = mem::zeroed();
            let mut ret;
            let mut pub_key_raw: [u8; 32] = [0; 32];
            let mut pub_key_raw_len: word32 = pub_key_raw.len() as word32;

            ret = wc_curve25519_init(private_key_object.as_ptr());
            if ret < 0 {
                panic!("panic while calling wc_curve25519_init, ret = {}", ret);
            }

            ret = wc_curve25519_init(public_key_object.as_ptr());
            if ret < 0 {
                panic!("panic while calling wc_curve25519_init, ret = {}", ret);
            }

            ret = wc_InitRng(&mut rng);
            if ret < 0 {
                panic!("wc_InitRng");
            }

            ret = wc_curve25519_make_key(
                &mut rng, 
                32, 
                private_key_object.as_ptr()
            );
            if ret < 0 {
                panic!("wc_curve25519_make_key");
            }

            ret = wc_curve25519_make_key(
                &mut rng, 
                32, 
                public_key_object.as_ptr()
            );
            if ret < 0 {
                panic!("wc_curve25519_make_key");
            }

            ret = wc_curve25519_export_public(
                    public_key_object.as_ptr(), 
                    pub_key_raw.as_mut_ptr(), 
                    &mut pub_key_raw_len
            ); 
            if ret < 0 {
                panic!("wc_curve25519_make_key");
            }

           Ok(Box::new(
               KeyExchange {
                   pub_key: public_key_object,
                   priv_key: private_key_object,
                   pub_key_bytes: pub_key_raw
               }
           ))
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_curve25519_wc() {
        unsafe {
            let mut private_key: curve25519_key = mem::zeroed();
            let mut public_key: curve25519_key = mem::zeroed();
            let mut rng: WC_RNG = mem::zeroed();
            let mut out_1: [u8; 32] = [0; 32];
            let mut out_len_1: word32 = out_1.len() as word32;
            let mut out_2: [u8; 32] = [0; 32];
            let mut out_len_2: word32 = out_2.len() as word32;
            let endian: u32 = EC25519_LITTLE_ENDIAN;
            let mut ret;

            ret = wc_curve25519_init(&mut private_key);
            if ret < 0 {
                panic!("wc_curve25519_init");
            }
            ret = wc_curve25519_init(&mut public_key);
            if ret < 0 {
                panic!("wc_curve25519_init");
            }

            ret = wc_InitRng(&mut rng);
            if ret < 0 {
                panic!("wc_InitRng");
            }
            ret = wc_curve25519_make_key(
                    &mut rng, 
                    32, 
                    &mut private_key
            );
            if ret < 0 {
                panic!("wc_curve25519_make_key");
            }

            ret = wc_curve25519_make_key(
                    &mut rng, 
                    32, 
                    &mut public_key
            );
            if ret < 0 {
                panic!("wc_curve25519_make_key");
            }

            let pub_key_raw = hex!("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
            let priv_key_raw = hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
            let mut their_pub: curve25519_key = mem::zeroed();
            let mut their_priv: curve25519_key = mem::zeroed();

            ret = wc_curve25519_check_public(
                    pub_key_raw.as_ptr(), 
                    32, 
                    endian.try_into().unwrap()
            );
            if ret < 0 {
                panic!("wc_curve25519_check_public\n");
            }

            ret = wc_curve25519_init(&mut their_pub);
            if ret < 0 {
                panic!("wc_curve25519_init");
            }

            ret = wc_curve25519_init(&mut their_priv);
            if ret < 0 {
                panic!("wc_curve25519_init");
            }
            
            ret = wc_curve25519_import_public_ex(
                    pub_key_raw.as_ptr(), 
                    32, 
                    &mut their_pub, 
                    endian.try_into().unwrap()
            );
            if ret < 0 {
                panic!("wc_curve25519_import_public_ex");
            }

            ret = wc_curve25519_import_private_ex(
                    priv_key_raw.as_ptr(), 
                    32, 
                    &mut their_priv, 
                    endian.try_into().unwrap()
            );
            if ret != 0 {
                panic!("wc_curve25519_import_private alice failed\n");
            }

            ret = wc_curve25519_shared_secret_ex(
                    &mut private_key, 
                    &mut their_pub, 
                    out_1.as_mut_ptr(),
                    &mut out_len_1, 
                    endian.try_into().unwrap()
            );
            if ret != 0 {
                panic!("wc_curve25519_shared_secret_ex");
            }

            ret = wc_curve25519_shared_secret_ex(
                &mut their_priv, 
                &mut private_key, 
                out_2.as_mut_ptr(),
                &mut out_len_2, 
                endian.try_into().unwrap()
            );
            if ret != 0 {
                panic!("wc_curve25519_shared_secret_ex");
            }

            assert_eq!(
                out_1,
                out_2
            );
        }
    }
}
