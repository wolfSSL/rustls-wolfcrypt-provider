extern crate bindgen;

use std::env;
use std::fs;
use std::path::PathBuf;
use std::path::Path;

fn main() {
    let wolfssl_lib_dir = Path::new(&"/opt/wolfssl-install-dir/lib"); 
    let wolfssl_include_dir = Path::new(&"/opt/wolfssl-install-dir/include/wolfssl");

    println!("cargo:rustc-link-search={}",
            wolfssl_lib_dir.to_str().unwrap()
    );
    println!("cargo:rustc-link-lib=static=wolfssl");

    let bindings = bindgen::Builder::default()
        .header("libraries.h")
        .clang_arg(format!("-I{}", wolfssl_include_dir.to_str().unwrap()))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    // For convenience, we copy the content of bindings.rs into the new file
    // inside the src directory from the OUT_DIR.
    fs::copy(out_path.join("bindings.rs"), "./src/bindings.rs")
        .expect("Couldn't copy bindings to src directory!");
}
