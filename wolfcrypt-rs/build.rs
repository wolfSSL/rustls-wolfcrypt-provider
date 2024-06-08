extern crate bindgen;

use std::env;
use std::path::PathBuf;
use std::path::Path;

/*
 * wolfssl_src = ./wolfssl/
 * wolfssl_include_dir = ./wolfssl/wolfssl/
 * wolfssl_lib_dir = /usr/local/lib
 * */


fn main() {
    let wolfssl_lib_dir = Path::new(&"/usr/local/lib"); 
    let wolfssl_include_dir = Path::new(&"wolfssl/wolfssl");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let builder = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("libraries.h")
        // Include libraries.
        .clang_arg(format!("-I{}", wolfssl_include_dir.to_str().unwrap()))
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));

    let builder = [
        "wolfssl/wolfssl/.*.h",
        "wolfssl/wolfssl/wolfcrypt/.*.h",
    ]
    .iter()
    .fold(builder, |b, p| {
        b.allowlist_file(wolfssl_include_dir.join(p).to_str().unwrap())
    });

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bindings: bindgen::Bindings = builder.generate().expect("Unable to generate bindings");
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    println!(
        "cargo:rustc-link-search=native={}",
        wolfssl_lib_dir.to_str().unwrap()
    );
    println!("cargo:rustc-link-lib=libwolfssl");
}
