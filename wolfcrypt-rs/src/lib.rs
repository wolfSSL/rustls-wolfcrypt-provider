/*
 * These are used to suppress all the errors that rust complains
 * about our symbols and/or macro (since they don't follow rust's style
 * conversion).
 * */
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

/*
 * We include the bindings.
 *
 * Note: 
 * When running 'cargo test' there are 
 * a bunch of warnings about the u128 type not being FFI safe, 
 * can be fixed by upgrading to llvm-18.
 * */
pub mod bindings;
