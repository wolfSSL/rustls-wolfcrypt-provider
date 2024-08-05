extern crate bindgen;

use std::env;
use std::path::PathBuf;
use std::path::Path;
use std::process::Command;
use std::fs;

fn main() {
    // We check if the release was already fetched, if not, 
    // we fetch it and setup it.
    if !fs::metadata("wolfssl-5.7.2-stable").is_ok() {
        setup_wolfssl();
    }

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

fn setup_wolfssl() {
    // Step 1: Download the ZIP file using curl
    let output = Command::new("curl")
        .arg("-L")
        .arg("-o")
        .arg("wolfssl-5.7.2-stable.zip")
        .arg("https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.7.2-stable.zip")
        .output()
        .expect("Failed to execute curl command");

    if output.status.success() {
        println!("Download completed successfully.");

        // Step 2: Unzip the downloaded file
        let output = Command::new("unzip")
            .arg("wolfssl-5.7.2-stable.zip")
            .output()
            .expect("Failed to execute unzip command");

        if output.status.success() {
            println!("Unzipping completed successfully.");

            // Step 3: Remove the ZIP file
            if let Err(e) = fs::remove_file("wolfssl-5.7.2-stable.zip") {
                eprintln!("Error removing ZIP file: {}", e);
            } else {
                println!("Removed ZIP file successfully.");
            }

            // Step 4: Change the current working directory to the unzipped folder
            if let Err(e) = env::set_current_dir("wolfssl-5.7.2-stable") {
                eprintln!("Error changing directory: {}", e);
            } else {
                println!("Changed directory to wolfssl-5.7.2-stable.");

                // Step 5: Execute ./autogen.sh
                let output = Command::new("./autogen.sh")
                    .output()
                    .expect("Failed to execute ./autogen.sh");

                if output.status.success() {
                    println!("./autogen.sh completed successfully.");

                    // Step 6: Execute ./configure
                    let output = Command::new("./configure")
                        .arg("--enable-all")
                        .arg("--enable-all-crypto")
                        .arg("--disable-shared")
                        .arg("--prefix=/opt/wolfssl-rs/")
                        .output()
                        .expect("Failed to execute ./configure");

                    if output.status.success() {
                        println!("./configure completed successfully.");

                        // Step 7: Execute make
                        let output = Command::new("make")
                            .output()
                            .expect("Failed to execute make");

                        if output.status.success() {
                            println!("make completed successfully.");

                            // Step 8: Execute sudo make install
                            let output = Command::new("sudo")
                                .arg("make")
                                .arg("install")
                                .output()
                                .expect("Failed to execute sudo make install");

                            if output.status.success() {
                                println!("sudo make install completed successfully.");
                            } else {
                                eprintln!("Error executing sudo make install: {}", String::from_utf8_lossy(&output.stderr));
                            }
                        } else {
                            eprintln!("Error executing make: {}", String::from_utf8_lossy(&output.stderr));
                        }
                    } else {
                        eprintln!("Error executing ./configure: {}", String::from_utf8_lossy(&output.stderr));
                    }
                } else {
                    eprintln!("Error executing ./autogen.sh: {}", String::from_utf8_lossy(&output.stderr));
                }
            }
        } else {
            eprintln!("Error unzipping file: {}", String::from_utf8_lossy(&output.stderr));
        }
    } else {
        eprintln!("Error downloading file: {}", String::from_utf8_lossy(&output.stderr));
    }


    // Final step: we change the directory back to the root directory
    // to finally generate the bindings.
    if let Err(e) = env::set_current_dir("../") {
        eprintln!("Error changing directory: {}", e);
    } else {
        println!("Changed directory to wolfssl-5.7.2-stable.");
    }
}
