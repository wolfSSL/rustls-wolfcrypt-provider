extern crate bindgen;

use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io::{self, Read, Result};
use std::path::PathBuf;
use std::process::Command;

/// Version-related constants for WolfSSL
const WOLFSSL_DIR: &str = "wolfssl-5.7.6-stable";
const WOLFSSL_ZIP: &str = "wolfssl-5.7.6-stable.zip";
const WOLFSSL_URL: &str = "https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.7.6-stable.zip";
const WOLFSSL_SHA256: &str = "1aeb6e49222bb9d8cf012063f0dfc3f229084f24ce2b5740a2dcdb64d72b00bf";

/// Entry point for the build script.
/// Handles the main build process and exits with an error code if anything fails.
fn main() {
    if let Err(e) = run_build() {
        eprintln!("Build failed: {e}");
        std::process::exit(1);
    }
}

/// Orchestrates the entire build process.
///
/// This function:
/// 1. Checks if WolfSSL needs to be set up
/// 2. Sets up WolfSSL if necessary
/// 3. Generates Rust bindings for the WolfSSL library
///
/// Returns `Ok(())` if successful, or an error if any step fails.
fn run_build() -> Result<()> {
    let prefix = install_prefix();
    if fs::metadata(WOLFSSL_DIR).is_err() || fs::metadata(prefix.join("lib")).is_err() {
        setup_wolfssl()?;
    }

    generate_bindings()?;
    Ok(())
}

/// Generates Rust bindings for the WolfSSL library using bindgen.
///
/// This function:
/// 1. Sets up the library and include paths
/// 2. Configures the build environment
/// 3. Generates Rust bindings using bindgen
/// 4. Writes the bindings to a file
///
/// Returns `Ok(())` if successful, or an error if binding generation fails.
fn install_prefix() -> PathBuf {
    PathBuf::from(env::var("OUT_DIR").unwrap()).join("wolfssl-install")
}

fn generate_bindings() -> Result<()> {
    let prefix = install_prefix();
    let wolfssl_lib_dir = prefix.join("lib");
    let wolfssl_include_dir = prefix.join("include");

    println!(
        "cargo:rustc-link-search={}",
        wolfssl_lib_dir.to_str().unwrap()
    );
    println!("cargo:rustc-link-lib=static=wolfssl");

    let bindings = bindgen::Builder::default()
        .header("libraries.h")
        .clang_arg(format!("-I{}/", wolfssl_include_dir.to_str().unwrap()))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .map_err(|_| io::Error::other("Failed to generate bindings"))?;

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .map_err(|e| io::Error::other(format!("Couldn't write bindings: {}", e)))
}

/// Coordinates the complete setup process for WolfSSL.
///
/// This function executes all necessary steps in sequence:
/// 1. Downloads the WolfSSL source
/// 2. Extracts the archive
/// 3. Removes the downloaded archive
/// 4. Builds WolfSSL from source
/// 5. Returns to the original directory
///
/// Returns `Ok(())` if all steps complete successfully, or an error if any step fails.
fn setup_wolfssl() -> Result<()> {
    download_wolfssl()?;
    verify_download(WOLFSSL_ZIP, WOLFSSL_SHA256)?;
    unzip_wolfssl()?;
    remove_zip()?;
    build_wolfssl()?;
    change_back_to_root()?;
    Ok(())
}

/// Downloads the WolfSSL source code archive using curl.
///
/// Uses curl to download the specified version of WolfSSL from the official repository.
/// The download URL and filename are defined in the constants.
///
/// Returns `Ok(())` if the download succeeds, or an error if the download fails.
fn download_wolfssl() -> Result<()> {
    let output = Command::new("curl")
        .arg("-L")
        .arg("-o")
        .arg(WOLFSSL_ZIP)
        .arg(WOLFSSL_URL)
        .output()?;

    if !output.status.success() {
        return Err(io::Error::other(format!(
            "Failed to download: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    println!("Download completed successfully.");
    Ok(())
}

/// Verifies the SHA-256 hash of a downloaded file against an expected value.
///
/// Returns `Ok(())` if the hash matches, or an error if it doesn't.
fn verify_download(path: &str, expected_sha256: &str) -> Result<()> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let hash = hasher.finalize();
    let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
    if hex != expected_sha256 {
        return Err(io::Error::other(format!(
            "SHA-256 mismatch: expected {}, got {}",
            expected_sha256, hex
        )));
    }
    println!("SHA-256 verification passed.");
    Ok(())
}

/// Extracts the downloaded WolfSSL archive.
///
/// Uses the unzip command to extract the contents of the downloaded ZIP file.
/// The archive name is defined in the constants.
///
/// Returns `Ok(())` if extraction succeeds, or an error if it fails.
fn unzip_wolfssl() -> Result<()> {
    let output = Command::new("unzip").arg("-o").arg(WOLFSSL_ZIP).output()?;

    if !output.status.success() {
        return Err(io::Error::other(format!(
            "Failed to unzip: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    println!("Unzipping completed successfully.");
    Ok(())
}

/// Removes the downloaded ZIP file after extraction.
///
/// This cleanup step removes the ZIP file to save disk space.
///
/// Returns `Ok(())` if removal succeeds, or an error if it fails.
fn remove_zip() -> Result<()> {
    fs::remove_file(WOLFSSL_ZIP)?;
    println!("Removed ZIP file successfully.");
    Ok(())
}

/// Builds WolfSSL from source.
///
/// This function:
/// 1. Changes to the source directory
/// 2. Runs autogen.sh to generate build files
/// 3. Configures the build with specific options
/// 4. Builds the library
/// 5. Installs the library system-wide
///
/// Returns `Ok(())` if all build steps succeed, or an error if any step fails.
fn build_wolfssl() -> Result<()> {
    env::set_current_dir(WOLFSSL_DIR)?;
    println!("Changed directory to {WOLFSSL_DIR}.");

    let prefix = install_prefix();
    let prefix_arg = format!("--prefix={}", prefix.to_str().unwrap());

    run_command("./autogen.sh", &[])?;
    run_command(
        "./configure",
        &[
            "--enable-all",
            "--enable-all-crypto",
            "--enable-debug",
            "--disable-shared",
            &prefix_arg,
        ],
    )?;
    run_command("make", &[])?;
    run_command("make", &["install"])?;

    Ok(())
}

/// Helper function to execute shell commands.
///
/// Executes a command with given arguments and handles the output appropriately.
///
/// # Arguments
/// * `cmd` - The command to execute
/// * `args` - Array of arguments for the command
///
/// Returns `Ok(())` if the command executes successfully, or an error if it fails.
fn run_command(cmd: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(cmd).args(args).output()?;

    if !output.status.success() {
        return Err(io::Error::other(format!(
            "Failed to execute {}: {}",
            cmd,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    println!("{cmd} completed successfully.");
    Ok(())
}

/// Changes the working directory back to the root directory.
///
/// This function is called after building WolfSSL to return to the original
/// working directory for the rest of the build process.
///
/// Returns `Ok(())` if the directory change succeeds, or an error if it fails.
fn change_back_to_root() -> Result<()> {
    env::set_current_dir("../")?;
    println!("Changed directory back to root.");
    Ok(())
}
