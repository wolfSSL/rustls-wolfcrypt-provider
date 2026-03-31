use crate::error::*;
use core::ptr::NonNull;
use foreign_types::{ForeignType, ForeignTypeRef, Opaque};
use log::error;

use wolfcrypt_rs::*;

macro_rules! define_foreign_type {
    ($struct_name:ident, $ref_name:ident, $c_type:ty, $init_function:ident) => {
        pub struct $ref_name(Opaque);
        unsafe impl ForeignTypeRef for $ref_name {
            type CType = $c_type;
        }

        #[derive(Debug)]
        pub struct $struct_name(NonNull<$c_type>);
        unsafe impl Sync for $struct_name {}
        unsafe impl Send for $struct_name {}
        unsafe impl ForeignType for $struct_name {
            type CType = $c_type;
            type Ref = $ref_name;

            unsafe fn from_ptr(ptr: *mut Self::CType) -> Self {
                Self(NonNull::new_unchecked(ptr))
            }

            fn as_ptr(&self) -> *mut Self::CType {
                self.0.as_ptr()
            }
        }

        impl $struct_name {
            /// Given a $c_type (FFI C binding), it creates an object around it
            /// using the ForeignType's function from_ptr function.
            pub fn new(c_type: &mut $c_type) -> $struct_name {
                unsafe {
                    let new_object: $struct_name = $struct_name::from_ptr(c_type);
                    new_object
                }
            }

            /// Given an $init_function, it calls it with the object's ptr as argument.
            pub fn init(&self) {
                unsafe { check_if_zero($init_function(self.as_ptr())).unwrap() }
            }
        }
    };

    ($struct_name:ident, $ref_name:ident, $c_type:ty, drop($drop_fn:ident), $init_function:ident) => {
        define_foreign_type!($struct_name, $ref_name, $c_type, $init_function);

        /// Implements Drop trait for cryptographic types that require cleanup.
        /// This safely frees memory and other resources when the type goes out of scope.
        /// Any cleanup errors are logged but cannot be returned since this is Drop.
        /// The unsafe block is needed for FFI calls to the underlying C functions.
        impl Drop for $struct_name {
            fn drop(&mut self) {
                let ret = unsafe { $drop_fn(self.as_ptr()) };
                match check_if_zero(ret) {
                    Err(err) => {
                        error!(
                            "Error while freeing resource in Drop for {}: {}",
                            stringify!($struct_name),
                            err
                        );
                    }
                    Ok(()) => {}
                }
            }
        }
    };

    ($struct_name:ident, $ref_name:ident, $c_type:ty, drop_void($drop_fn:ident), $init_function:ident) => {
        define_foreign_type!($struct_name, $ref_name, $c_type, $init_function);

        impl Drop for $struct_name {
            fn drop(&mut self) {
                unsafe { $drop_fn(self.as_ptr()) };
            }
        }
    };
}

macro_rules! define_foreign_type_with_copy {
    ($struct_name:ident, $ref_name:ident, $c_type:ty) => {
        pub struct $ref_name(Opaque);
        unsafe impl ForeignTypeRef for $ref_name {
            type CType = $c_type;
        }

        #[derive(Debug, Clone, Copy)]
        pub struct $struct_name(NonNull<$c_type>);
        unsafe impl Sync for $struct_name {}
        unsafe impl Send for $struct_name {}
        unsafe impl ForeignType for $struct_name {
            type CType = $c_type;
            type Ref = $ref_name;

            unsafe fn from_ptr(ptr: *mut Self::CType) -> Self {
                Self(NonNull::new_unchecked(ptr))
            }

            fn as_ptr(&self) -> *mut Self::CType {
                self.0.as_ptr()
            }
        }
    };
}

/// Like define_foreign_type_with_copy but without Copy (needed when Drop is implemented).
macro_rules! define_foreign_type_no_copy {
    ($struct_name:ident, $ref_name:ident, $c_type:ty) => {
        pub struct $ref_name(Opaque);
        unsafe impl ForeignTypeRef for $ref_name {
            type CType = $c_type;
        }

        #[derive(Debug)]
        pub struct $struct_name(NonNull<$c_type>);
        unsafe impl Sync for $struct_name {}
        unsafe impl Send for $struct_name {}
        unsafe impl ForeignType for $struct_name {
            type CType = $c_type;
            type Ref = $ref_name;

            unsafe fn from_ptr(ptr: *mut Self::CType) -> Self {
                Self(NonNull::new_unchecked(ptr))
            }

            fn as_ptr(&self) -> *mut Self::CType {
                self.0.as_ptr()
            }
        }
    };

    ($struct_name:ident, $ref_name:ident, $c_type:ty, drop($drop_fn:ident)) => {
        define_foreign_type_no_copy!($struct_name, $ref_name, $c_type);

        impl Drop for $struct_name {
            fn drop(&mut self) {
                let ret = unsafe { $drop_fn(self.as_ptr()) };
                match check_if_zero(ret) {
                    Err(err) => {
                        error!(
                            "Error while freeing resource in Drop for {}: {}",
                            stringify!($struct_name),
                            err
                        );
                    }
                    Ok(()) => {}
                }
            }
        }
    };

    ($struct_name:ident, $ref_name:ident, $c_type:ty, drop_void($drop_fn:ident)) => {
        define_foreign_type_no_copy!($struct_name, $ref_name, $c_type);

        impl Drop for $struct_name {
            fn drop(&mut self) {
                unsafe { $drop_fn(self.as_ptr()) };
            }
        }
    };
}

define_foreign_type!(
    WCRngObject,
    WCRngObjectRef,
    WC_RNG,
    drop(wc_FreeRng),
    wc_InitRng
);
define_foreign_type!(
    Curve25519KeyObject,
    Curve25519KeyObjectRef,
    curve25519_key,
    drop_void(wc_curve25519_free),
    wc_curve25519_init
);
define_foreign_type!(
    ECCKeyObject,
    ECCKeyObjectRef,
    ecc_key,
    drop(wc_ecc_free),
    wc_ecc_init
);
define_foreign_type!(
    ED25519KeyObject,
    ED25519KeyObjectRef,
    ed25519_key,
    drop_void(wc_ed25519_free),
    wc_ed25519_init
);
define_foreign_type!(
    ED448KeyObject,
    ED448KeyObjectRef,
    ed448_key,
    drop_void(wc_ed448_free),
    wc_ed448_init
);

define_foreign_type_no_copy!(RsaKeyObject, RsaKeyObjectRef, RsaKey, drop(wc_FreeRsaKey));
define_foreign_type_with_copy!(HmacObject, HmacObjectRef, wolfcrypt_rs::Hmac);
define_foreign_type_no_copy!(AesObject, AesObjectRef, Aes, drop_void(wc_AesFree));
