use crate::error::*;
use core::ptr::NonNull;
use foreign_types::{ForeignType, ForeignTypeRef, Opaque};
use log::error;

use wolfssl_wolfcrypt::sys::*;

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
            /// Returns the result so callers can propagate an init failure instead of
            /// panicking (e.g. so a failed wc_InitRng surfaces as a recoverable error).
            pub fn init(&self) -> WCResult {
                unsafe { check_if_zero($init_function(self.as_ptr())) }
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

/// Defines a foreign type without Copy (needed when Drop is implemented, so the
/// resource is freed exactly once).
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

define_foreign_type_no_copy!(RsaKeyObject, RsaKeyObjectRef, RsaKey, drop(wc_FreeRsaKey));
#[cfg(not(fips))]
define_foreign_type_no_copy!(ChaChaObject, ChaChaObjectRef, ChaCha);
