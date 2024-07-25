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
        unsafe {
            let mut public_key: curve25519_key = mem::zeroed();
            let public_key_object = Curve25519KeyObject::from_ptr(&mut public_key);
            let mut private_key: curve25519_key = mem::zeroed();
            let private_key_object = Curve25519KeyObject::from_ptr(&mut private_key);
            let mut rng: WC_RNG = mem::zeroed();
            let mut ret;
            let mut pub_key_raw: [u8; 32] = [0; 32];
            let mut pub_key_raw_len: word32 = pub_key_raw.len() as word32;
            let endian: u32 = EC25519_LITTLE_ENDIAN;
            let mut priv_key_raw: [u8; 32] = [0; 32];
            let mut priv_key_raw_len: word32 = priv_key_raw.len() as word32;

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

            ret = wc_curve25519_export_public_ex(
                    public_key_object.as_ptr(), 
                    pub_key_raw.as_mut_ptr(), 
                    &mut pub_key_raw_len,
                    endian.try_into().unwrap()
            ); 
            if ret < 0 {
                panic!("wc_curve25519_export_public_ex");
            }

            ret = wc_curve25519_export_private_raw_ex(
                    private_key_object.as_ptr(), 
                    priv_key_raw.as_mut_ptr(), 
                    &mut priv_key_raw_len,
                    endian.try_into().unwrap()
            );
            if ret < 0 {
                panic!("wc_curve25519_export_private_raw_ex");
            }


           Ok(Box::new(
               KeyExchange {
                   pub_key_bytes: pub_key_raw,
                   priv_key_bytes: priv_key_raw
               }
           ))
        }
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

pub struct KeyExchange {
    pub_key_bytes: [u8; 32],
    priv_key_bytes: [u8; 32]
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
            let mut private_key: curve25519_key = mem::zeroed();

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

            ret = wc_curve25519_init(&mut private_key);
            if ret < 0 {
                panic!("wc_curve25519_init");
            }

            ret = wc_curve25519_import_private_ex(
                self.priv_key_bytes.as_ptr(), 
                32, 
                &mut private_key, 
                endian.try_into().unwrap()
            );
            if ret != 0 {
                panic!("wc_curve25519_import_private");
            }

           ret = wc_curve25519_shared_secret_ex(
               &mut private_key, 
               &mut pub_key_provided, 
               out.as_mut_ptr(),
               &mut out_len, 
               endian.try_into().unwrap()
           );
           if ret < 0 {
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
    fn test_curve25519() {
        let alice_prv = hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_pub = hex!("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_prv   = hex!("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_pub   = hex!("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let alice_secret: [u8; 32] = [0; 32];
        let bob_secret: [u8; 32] = [0; 32];
        let endian: u32 = EC25519_LITTLE_ENDIAN;

        assert_eq!(curve25519_secret(alice_prv, bob_pub, alice_secret, alice_secret.len() as word32, endian), 0);
        assert_eq!(curve25519_secret(bob_prv, alice_pub, bob_secret, bob_secret.len() as word32, endian), 0);

        assert_eq!(alice_secret, bob_secret);
    }

    fn curve25519_secret(mut priv_key_raw: [u8; 32], mut pub_key_raw: [u8; 32], mut secret: [u8; 32], mut secret_size: u32, endianess: u32) -> i32 {
        unsafe {
            let mut ret;
            let mut priv_key: curve25519_key = mem::zeroed();
            let mut pub_key: curve25519_key = mem::zeroed();

            ret = wc_curve25519_init(&mut pub_key);
            if ret == 0 {
                ret = wc_curve25519_init(&mut priv_key);
            }

            if ret == 0 {
                ret = wc_curve25519_import_private_ex(priv_key_raw.as_mut_ptr(), 32, &mut priv_key, endianess.try_into().unwrap());
                if ret != 0 {
                    panic!("wc_curve25519_import_private failed\n");
                }
            }

            if ret == 0 {
                ret = wc_curve25519_check_public(pub_key_raw.as_mut_ptr(), 32, endianess.try_into().unwrap());
                if ret != 0 {
                    panic!("wc_curve25519_check_public failed\n");
                }
            }

            if ret == 0 {
                ret = wc_curve25519_import_public_ex(pub_key_raw.as_mut_ptr(), 32, &mut pub_key, endianess.try_into().unwrap());
            }

            if ret == 0 {
                ret = wc_curve25519_shared_secret_ex(&mut priv_key, &mut pub_key, secret.as_mut_ptr(), &mut secret_size, endianess.try_into().unwrap());
            }

            wc_curve25519_free(&mut pub_key);
            wc_curve25519_free(&mut priv_key);
            return ret;
        }
    }
}
