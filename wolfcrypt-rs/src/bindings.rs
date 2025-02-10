/*
 * Allow attributes to suppress warnings in bindgen-generated code.
 * These warnings arise from:
 * - Naming conventions that don't match Rust style (e.g. from C symbols)
 * - Auto-generated unsafe code patterns
 * - Type/casting patterns common in C FFI but discouraged in pure Rust
 *
 * Since this code is auto-generated, these warnings cannot be fixed manually
 * and must be suppressed.
 */
#![allow(dead_code)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::useless_transmute)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::too_many_arguments)]
#![allow(improper_ctypes)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::ptr_offset_with_cast)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
