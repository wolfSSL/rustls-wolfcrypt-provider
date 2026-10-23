// Turns on the `fips` cfg when wolfssl-wolfcrypt is built against a FIPS
// wolfSSL. The crate publishes that as FIPS=1 in its build metadata, which
// Cargo hands to crates depending on it directly as DEP_WOLFSSL_FIPS.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(fips)");
    println!("cargo::rerun-if-env-changed=DEP_WOLFSSL_FIPS");
    if std::env::var("DEP_WOLFSSL_FIPS").as_deref() == Ok("1") {
        println!("cargo::rustc-cfg=fips");
    }
    // The FIPS v5.2.3 module has no Ed25519, published as FIPS_V5_2_3=1.
    println!("cargo::rustc-check-cfg=cfg(fips_v5_2_3)");
    println!("cargo::rerun-if-env-changed=DEP_WOLFSSL_FIPS_V5_2_3");
    if std::env::var("DEP_WOLFSSL_FIPS_V5_2_3").as_deref() == Ok("1") {
        println!("cargo::rustc-cfg=fips_v5_2_3");
    }
}
