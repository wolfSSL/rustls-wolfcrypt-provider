extern crate bindgen;

use std::env;
use std::path::PathBuf;
use std::path::Path;

fn main() {
    let wolfssl_lib_dir = Path::new(&"/opt/wolfssl-rs/lib/"); 
    let wolfssl_include_dir = Path::new(&"/opt/wolfssl-rs/include/");

    println!("cargo:rustc-link-search={}",
            wolfssl_lib_dir.to_str().unwrap()
    );
    println!("cargo:rustc-link-lib=static=wolfssl");

    let bindings = bindgen::Builder::default()
        .header("libraries.h")
        .clang_arg(format!("-I{}/", wolfssl_include_dir.to_str().unwrap()))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
