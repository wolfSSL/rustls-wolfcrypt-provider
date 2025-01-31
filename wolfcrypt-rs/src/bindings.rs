/*
 * These are used to suppress all the errors that rust complains
 * about our symbols and/or macro (since they don't follow rust's style
 * convention).
 * */
#![allow(dead_code)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::useless_transmute)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::too_many_arguments)]
#![allow(improper_ctypes)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
