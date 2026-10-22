// Turns on the `fips` cfg when wolfssl-wolfcrypt is built against a FIPS
// wolfSSL. The crate publishes that as FIPS=1 in its build metadata, which
// Cargo hands to crates depending on it directly as DEP_WOLFSSL_FIPS.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(fips)");
    println!("cargo::rerun-if-env-changed=DEP_WOLFSSL_FIPS");
    if std::env::var("DEP_WOLFSSL_FIPS").as_deref() == Ok("1") {
        println!("cargo::rustc-cfg=fips");
    }
}
