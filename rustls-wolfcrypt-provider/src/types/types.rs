use wolfcrypt_rs::*;
use foreign_types::{ForeignType, ForeignTypeRef, Opaque};
use std::ptr::NonNull;

pub struct ECCKeyObjectRef(Opaque);
unsafe impl ForeignTypeRef for ECCKeyObjectRef {
    type CType = ecc_key;
}

#[derive(Debug, Clone)]
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

pub struct RsaKeyObjectRef(Opaque);
unsafe impl ForeignTypeRef for RsaKeyObjectRef {
    type CType = RsaKey;
}

#[derive(Debug, Clone, Copy)]
pub struct RsaKeyObject(NonNull<RsaKey>);
unsafe impl Sync for RsaKeyObject{}
unsafe impl Send for RsaKeyObject{}
unsafe impl ForeignType for RsaKeyObject {
    type CType = RsaKey;

    type Ref = RsaKeyObjectRef;

    unsafe fn from_ptr(ptr: *mut Self::CType) -> Self {
        Self(NonNull::new_unchecked(ptr))
    }

    fn as_ptr(&self) -> *mut Self::CType {
        self.0.as_ptr()
    }
}

pub struct WCRNGObjectRef(Opaque);
unsafe impl ForeignTypeRef for WCRNGObjectRef {
    type CType = WC_RNG;
}

pub struct  WCRNGObject(NonNull<WC_RNG>);
unsafe impl Sync for WCRNGObject{}
unsafe impl Send for WCRNGObject{}
unsafe impl ForeignType for WCRNGObject {
    type CType = WC_RNG;

    type Ref = WCRNGObjectRef;

    unsafe fn from_ptr(ptr: *mut Self::CType) -> Self {
        Self(NonNull::new_unchecked(ptr))
    }

    fn as_ptr(&self) -> *mut Self::CType {
        self.0.as_ptr()
    }
}
impl Drop for WCRNGObject {
    fn drop(&mut self) {
        unsafe {
            // Correctly free the RNG object.
            let ret = wc_FreeRng(self.as_ptr());
            if ret != 0 {
                panic!("Error while freeing RNG!");
            }
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
pub struct HmacObjectRef(Opaque);
unsafe impl ForeignTypeRef for HmacObjectRef {
    type CType = wolfcrypt_rs::Hmac;
}

#[derive(Debug, Clone, Copy)]
pub struct HmacObject(NonNull<wolfcrypt_rs::Hmac>);
unsafe impl Sync for HmacObject {}
unsafe impl Send for HmacObject {}
unsafe impl ForeignType for HmacObject {
    type CType = wolfcrypt_rs::Hmac;

    type Ref = HmacObjectRef;

    unsafe fn from_ptr(ptr: *mut Self::CType) -> Self {
        Self(NonNull::new_unchecked(ptr))
    }

    fn as_ptr(&self) -> *mut Self::CType {
        self.0.as_ptr()
    }
}

pub struct AesObjectRef(Opaque);
unsafe impl ForeignTypeRef for AesObjectRef {
    type CType = Aes;
}
#[derive(Debug, Clone, Copy)]
pub struct AesObject(NonNull<Aes>);
unsafe impl Sync for AesObject{}
unsafe impl Send for AesObject{}
unsafe impl ForeignType for AesObject {
    type CType = Aes;

    type Ref = AesObjectRef;

    unsafe fn from_ptr(ptr: *mut Self::CType) -> Self {
        Self(NonNull::new_unchecked(ptr))
    }

    fn as_ptr(&self) -> *mut Self::CType {
        self.0.as_ptr()
    }
}
