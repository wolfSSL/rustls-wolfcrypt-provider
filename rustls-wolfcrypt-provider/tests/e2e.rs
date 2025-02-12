use foreign_types::ForeignType;
use lazy_static::lazy_static;
use rayon::prelude::*;
use rustls::version::{TLS12, TLS13};
use rustls::SignatureScheme;
use rustls_wolfcrypt_provider::error::*;
use rustls_wolfcrypt_provider::types::*;
use rustls_wolfcrypt_provider::{
    TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS12_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS13_AES_128_GCM_SHA256,
    TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
};
use std::env;
use std::fs::File;
use std::io::stdout;
use std::io::BufReader;
use std::io::{Read, Write};
use std::mem;
use std::net::TcpStream;
use std::process::{Child, Command};
use std::sync::Once;
use std::sync::{Arc, Mutex};
use std::thread;
use wolfcrypt_rs::*;

/*
 * Version config used by the server to specify
 * the tls version that we wanna use.
 * */
const TLSV1_2: &str = "-v 3";
const TLSV1_3: &str = "-v 4";

/*
 * Global mutex to ensure only one test can access the server at a time.
 * This is needed because both TLS 1.2 and TLS 1.3 tests spin up a local server
 * on the same port (4443). Without synchronization, tests running in parallel
 * could try to bind to the same port or interact with the wrong server instance.
*/
lazy_static! {
    static ref SERVER_LOCK: Mutex<()> = Mutex::new(());
}

/*
 * Initiliaze the thread pool once for all tests.
 * */
static INIT: Once = Once::new();

fn init_thread_pool() {
    INIT.call_once(|| {
        let num_cpus = num_cpus::get();
        rayon::ThreadPoolBuilder::new()
            .num_threads(num_cpus)
            .build_global()
            .unwrap();
    });
}

/*
 * Starts background job for wolfssl server (localhost:4443).
 * */
fn start_wolfssl_server(current_dir_string: String, tls_version: &str) -> Child {
    if let Err(e) = env::set_current_dir("../wolfcrypt-rs/wolfssl-5.7.6-stable/") {
        panic!("Error changing directory: {}", e);
    } else {
        println!("Changed directory to wolfssl-5.7.6-stable.");

        Command::new("./examples/server/server")
            .arg("-d")
            .arg("-c")
            .arg(current_dir_string.clone() + "/tests/certs/localhost.pem")
            .arg("-k")
            .arg(current_dir_string.clone() + "/tests/certs/localhost.key")
            .arg("-p")
            .arg("4443")
            .arg(tls_version)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("Failed to start wolfssl server.")
    }
}

#[cfg(test)]
mod tests {
    use rustls::crypto::CryptoProvider;
    use rustls_pki_types::{
        PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    };

    use super::*;

    #[test]
    fn test_tls12_against_server() {
        let _guard = SERVER_LOCK.lock().unwrap();
        let current_dir = env::current_dir().unwrap();
        let current_dir_string = current_dir.to_string_lossy().into_owned();

        let ciphers = [
            TLS12_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ];

        for cipher in ciphers {
            let server_thread = {
                let wolfssl_server = Arc::new(Mutex::new(start_wolfssl_server(
                    current_dir_string.clone(),
                    TLSV1_2,
                )));
                thread::spawn(move || {
                    wolfssl_server
                        .lock()
                        .unwrap()
                        .wait()
                        .expect("wolfssl server stopped unexpectedly");
                })
            };

            // Wait for the server to start
            thread::sleep(std::time::Duration::from_secs(1));

            let mut root_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let certs = rustls_pemfile::certs(&mut BufReader::new(
                &mut File::open(current_dir_string.clone() + "/tests/certs/RootCA.pem").unwrap(),
            ))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

            root_store.add_parsable_certificates(certs);

            let config = rustls::ClientConfig::builder_with_provider(
                rustls_wolfcrypt_provider::provider_with_specified_ciphers([cipher].to_vec())
                    .into(),
            )
            .with_protocol_versions(&[&TLS12])
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

            let server_name = "localhost".try_into().unwrap();
            let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
            let mut sock = TcpStream::connect("localhost:4443").unwrap();
            let mut tls = rustls::Stream::new(&mut conn, &mut sock);

            tls.write_all(
                concat!(
                    "GET / HTTP/1.1\r\n",
                    "Host: localhost\r\n",
                    "Connection: close\r\n",
                    "Accept-Encoding: identity\r\n",
                    "\r\n"
                )
                .as_bytes(),
            )
            .unwrap();

            let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
            writeln!(
                &mut std::io::stderr(),
                "Current ciphersuite: {:?}",
                ciphersuite.suite()
            )
            .unwrap();

            let mut plaintext = Vec::new();
            tls.read_to_end(&mut plaintext).unwrap();

            // Convert plaintext to a String
            let plaintext_str = String::from_utf8_lossy(&plaintext);

            // Split the string into lines and take the first line
            if let Some(first_line) = plaintext_str.lines().next() {
                stdout().write_all(first_line.as_bytes()).unwrap();
                stdout().write_all(b"\n").unwrap();
            }

            let _ = env::set_current_dir(current_dir_string.clone());

            drop(server_thread);
        }
    }

    #[test]
    fn test_tls13_against_server() {
        let _guard = SERVER_LOCK.lock().unwrap();
        let current_dir = env::current_dir().unwrap();
        let current_dir_string = current_dir.to_string_lossy().into_owned();

        let ciphers = [
            TLS13_CHACHA20_POLY1305_SHA256,
            TLS13_AES_128_GCM_SHA256,
            TLS13_AES_256_GCM_SHA384,
        ];

        for cipher in ciphers {
            let server_thread = {
                let wolfssl_server = Arc::new(Mutex::new(start_wolfssl_server(
                    current_dir_string.clone(),
                    TLSV1_3,
                )));
                thread::spawn(move || {
                    wolfssl_server
                        .lock()
                        .unwrap()
                        .wait()
                        .expect("wolfssl server stopped unexpectedly");
                })
            };

            // Wait for the server to start
            thread::sleep(std::time::Duration::from_secs(1));

            let mut root_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let certs = rustls_pemfile::certs(&mut BufReader::new(
                &mut File::open(current_dir_string.clone() + "/tests/certs/RootCA.pem").unwrap(),
            ))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

            root_store.add_parsable_certificates(certs);

            let config = rustls::ClientConfig::builder_with_provider(
                rustls_wolfcrypt_provider::provider_with_specified_ciphers([cipher].to_vec())
                    .into(),
            )
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

            let server_name = "localhost".try_into().unwrap();
            let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
            let mut sock = TcpStream::connect("localhost:4443").unwrap();
            let mut tls = rustls::Stream::new(&mut conn, &mut sock);

            tls.write_all(
                concat!(
                    "GET / HTTP/1.1\r\n",
                    "Host: localhost\r\n",
                    "Connection: close\r\n",
                    "Accept-Encoding: identity\r\n",
                    "\r\n"
                )
                .as_bytes(),
            )
            .unwrap();

            let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
            writeln!(
                &mut std::io::stderr(),
                "Current ciphersuite: {:?}",
                ciphersuite.suite()
            )
            .unwrap();

            let mut plaintext = Vec::new();
            tls.read_to_end(&mut plaintext).unwrap();

            // Convert plaintext to a String
            let plaintext_str = String::from_utf8_lossy(&plaintext);

            // Split the string into lines and take the first line
            if let Some(first_line) = plaintext_str.lines().next() {
                stdout().write_all(first_line.as_bytes()).unwrap();
                stdout().write_all(b"\n").unwrap();
            }

            let _ = env::set_current_dir(current_dir_string.clone());

            drop(server_thread);
        }
    }

    #[test]
    fn test_tl12_against_website() {
        let ciphers = [
            TLS12_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ];

        for cipher in ciphers {
            let root_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let config = rustls::ClientConfig::builder_with_provider(
                rustls_wolfcrypt_provider::provider_with_specified_ciphers([cipher].to_vec())
                    .into(),
            )
            .with_protocol_versions(&[&TLS12])
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

            let server_name = "www.rust-lang.org".try_into().unwrap();
            let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
            let mut sock = TcpStream::connect("www.rust-lang.org:443").unwrap();
            let mut tls = rustls::Stream::new(&mut conn, &mut sock);

            tls.write_all(
                concat!(
                    "GET / HTTP/1.1\r\n",
                    "Host: www.rust-lang.org\r\n",
                    "Connection: close\r\n",
                    "Accept-Encoding: identity\r\n",
                    "\r\n"
                )
                .as_bytes(),
            )
            .unwrap();

            let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
            writeln!(
                &mut std::io::stderr(),
                "Current ciphersuite: {:?}",
                ciphersuite.suite()
            )
            .unwrap();

            let mut plaintext = Vec::new();
            tls.read_to_end(&mut plaintext).unwrap();

            // Convert plaintext to a String
            let plaintext_str = String::from_utf8_lossy(&plaintext);

            // Split the string into lines and take the first line
            if let Some(first_line) = plaintext_str.lines().next() {
                stdout().write_all(first_line.as_bytes()).unwrap();
                stdout().write_all(b"\n").unwrap();
            }
        }
    }

    #[test]
    fn test_tl13_against_website() {
        let ciphers = [
            TLS13_CHACHA20_POLY1305_SHA256,
            TLS13_AES_128_GCM_SHA256,
            TLS13_AES_256_GCM_SHA384,
        ];

        for cipher in ciphers {
            let root_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let config = rustls::ClientConfig::builder_with_provider(
                rustls_wolfcrypt_provider::provider_with_specified_ciphers([cipher].to_vec())
                    .into(),
            )
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

            let server_name = "www.rust-lang.org".try_into().unwrap();
            let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
            let mut sock = TcpStream::connect("www.rust-lang.org:443").unwrap();
            let mut tls = rustls::Stream::new(&mut conn, &mut sock);

            tls.write_all(
                concat!(
                    "GET / HTTP/1.1\r\n",
                    "Host: www.rust-lang.org\r\n",
                    "Connection: close\r\n",
                    "Accept-Encoding: identity\r\n",
                    "\r\n"
                )
                .as_bytes(),
            )
            .unwrap();

            let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
            writeln!(
                &mut std::io::stderr(),
                "Current ciphersuite: {:?}",
                ciphersuite.suite(),
            )
            .unwrap();

            let mut plaintext = Vec::new();
            tls.read_to_end(&mut plaintext).unwrap();

            // Convert plaintext to a String
            let plaintext_str = String::from_utf8_lossy(&plaintext);

            // Split the string into lines and take the first line
            if let Some(first_line) = plaintext_str.lines().next() {
                stdout().write_all(first_line.as_bytes()).unwrap();
                stdout().write_all(b"\n").unwrap();
            }
        }
    }

    pub struct ECCPubKey {
        qx: Vec<u8>,
        qx_len: word32,
        qy: Vec<u8>,
        qy_len: word32,
    }

    #[test]
    fn ecdsa_sign_and_verify() {
        let wolfcrypt_default_provider = rustls_wolfcrypt_provider::provider();

        // Define schemes, curve IDs, and key sizes as tuples
        let test_configs = [
            (
                SignatureScheme::ECDSA_NISTP256_SHA256,
                ecc_curve_id_ECC_SECP256R1,
                32, // P256 key size
            ),
            (
                SignatureScheme::ECDSA_NISTP384_SHA384,
                ecc_curve_id_ECC_SECP384R1,
                48, // P384 key size
            ),
            (
                SignatureScheme::ECDSA_NISTP521_SHA512,
                ecc_curve_id_ECC_SECP521R1,
                66, // P521 key size
            ),
        ];

        for &(scheme, curve_id, key_size) in &test_configs {
            let mut der_ecc_key: Vec<u8> = vec![0; 200]; // Adjust size if needed
                                                         // Initialize RNG and ECC key objects
            let mut rng: WC_RNG = unsafe { mem::zeroed() };
            let rng_object: WCRngObject = WCRngObject::new(&mut rng);
            rng_object.init();
            let mut ecc_key_c_type: ecc_key = unsafe { mem::zeroed() };
            let key_object = ECCKeyObject::new(&mut ecc_key_c_type);
            key_object.init();

            let mut pub_key_raw = ECCPubKey {
                qx: vec![0; key_size],
                qx_len: key_size as u32,
                qy: vec![0; key_size],
                qy_len: key_size as u32,
            };

            // Generate ECC key
            let ret = unsafe {
                wc_ecc_make_key_ex(
                    rng_object.as_ptr(),
                    key_size as i32,
                    key_object.as_ptr(),
                    curve_id,
                )
            };
            check_if_zero(ret).unwrap();

            // Export public key
            let ret = unsafe {
                wc_ecc_export_public_raw(
                    key_object.as_ptr(),
                    pub_key_raw.qx.as_mut_ptr(),
                    &mut pub_key_raw.qx_len,
                    pub_key_raw.qy.as_mut_ptr(),
                    &mut pub_key_raw.qy_len,
                )
            };
            check_if_zero(ret).unwrap();

            let mut pub_key_bytes = Vec::new();
            pub_key_bytes.push(0x04); // Uncompressed point indicator
            pub_key_bytes.extend_from_slice(&pub_key_raw.qx.clone());
            pub_key_bytes.extend_from_slice(&pub_key_raw.qy.clone());

            // Export private key in DER format
            let ret = unsafe {
                wc_EccPrivateKeyToDer(
                    key_object.as_ptr(),
                    der_ecc_key.as_mut_ptr(),
                    der_ecc_key.len() as word32,
                )
            };
            check_if_greater_than_zero(ret).unwrap();

            // Trim to actual key size
            der_ecc_key.resize(ret as usize, 0);

            // Convert to PKCS#8 format and verify
            let rustls_private_key_pkcs8 =
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(der_ecc_key.as_slice()));

            sign_and_verify(
                &wolfcrypt_default_provider,
                scheme,
                rustls_private_key_pkcs8.clone_key(),
                pub_key_bytes.as_slice(),
            );

            // Convert to SEC1 format and verify
            let rustls_private_key_sec1 =
                PrivateKeyDer::from(PrivateSec1KeyDer::from(der_ecc_key.as_slice()));

            sign_and_verify(
                &wolfcrypt_default_provider,
                scheme,
                rustls_private_key_sec1.clone_key(),
                pub_key_bytes.as_slice(),
            );
        }
    }

    #[test]
    fn eddsa_sign_and_verify() {
        let wolfcrypt_default_provider = rustls_wolfcrypt_provider::provider();

        // Initialize RNG and ECC key objects
        let mut rng: WC_RNG = unsafe { mem::zeroed() };
        let rng_object: WCRngObject = WCRngObject::new(&mut rng);
        rng_object.init();

        let mut key_c_type: ed25519_key = unsafe { mem::zeroed() };
        let key_object = ED25519KeyObject::new(&mut key_c_type);
        key_object.init();

        let mut der_ed25519_key: Vec<u8> = vec![0; 200]; // Adjust size if needed
        let mut pub_key_raw: [u8; 32] = [0; 32];
        let mut pub_key_raw_len: word32 = pub_key_raw.len() as word32;
        let mut priv_key_raw: [u8; 32] = [0; 32];
        let mut priv_key_bytes_len: word32 = priv_key_raw.len() as word32;

        let mut ret;

        // Generate ECC key
        ret = unsafe { wc_ed25519_make_key(rng_object.as_ptr(), 32, key_object.as_ptr()) };
        check_if_zero(ret).unwrap();

        // Export private key
        ret = unsafe {
            wc_ed25519_export_private_only(
                key_object.as_ptr(),
                priv_key_raw.as_mut_ptr(),
                &mut priv_key_bytes_len,
            )
        };
        check_if_zero(ret).unwrap();

        // Export public key
        ret = unsafe {
            wc_ed25519_export_public(
                key_object.as_ptr(),
                pub_key_raw.as_mut_ptr(),
                &mut pub_key_raw_len,
            )
        };
        check_if_zero(ret).unwrap();

        // Export private key in DER format
        ret = unsafe {
            wc_Ed25519PrivateKeyToDer(
                key_object.as_ptr(),
                der_ed25519_key.as_mut_ptr(),
                der_ed25519_key.len() as word32,
            )
        };
        check_if_greater_than_zero(ret).unwrap();

        der_ed25519_key.resize(ret as usize, 0); // Trim to actual size
        let rustls_pkcs8_der = PrivatePkcs8KeyDer::from(der_ed25519_key.as_slice());
        let rustls_private_key = PrivateKeyDer::from(rustls_pkcs8_der);

        sign_and_verify(
            &wolfcrypt_default_provider,
            SignatureScheme::ED25519,
            rustls_private_key.clone_key(),
            pub_key_raw.as_slice(),
        );
    }

    #[test]
    fn rsa_pss_sign_and_verify() {
        init_thread_pool();

        let wolfcrypt_default_provider = rustls_wolfcrypt_provider::provider();
        let schemes = [
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ];

        let test_cases: Vec<_> = schemes
            .iter()
            .flat_map(|&scheme| [2048, 4096].iter().map(move |&key_size| (scheme, key_size)))
            .collect();

        test_cases.par_iter().for_each(|&(scheme, key_size)| {
            generate_and_test_pss_key(&wolfcrypt_default_provider, scheme, key_size).expect(
                &format!("Failed for scheme {:?} with key size {}", scheme, key_size),
            );
        });
    }

    fn generate_and_test_pss_key(
        provider: &CryptoProvider,
        scheme: SignatureScheme,
        key_size: usize,
    ) -> Result<(), anyhow::Error> {
        let mut rsa_key_c_type: RsaKey = unsafe { mem::zeroed() };
        let rsa_key_object = unsafe { RsaKeyObject::from_ptr(&mut rsa_key_c_type) };
        let mut priv_key_der: Vec<u8> = vec![0; 2392];
        let mut pub_key_der: Vec<u8> = vec![0; 2392];

        let ret = unsafe { wc_InitRsaKey(rsa_key_object.as_ptr(), std::ptr::null_mut()) };
        check_if_zero(ret).unwrap();

        let mut rng_c_type: WC_RNG = unsafe { mem::zeroed() };
        let rng_object = WCRngObject::new(&mut rng_c_type);
        rng_object.init();

        unsafe { wc_RsaSetRNG(rsa_key_object.as_ptr(), rng_object.as_ptr()) };

        let ret = unsafe {
            wc_MakeRsaKey(
                rsa_key_object.as_ptr(),
                key_size as i32,
                WC_RSA_EXPONENT.into(),
                rng_object.as_ptr(),
            )
        };
        check_if_zero(ret).unwrap();

        let ret = unsafe {
            wc_RsaKeyToDer(
                rsa_key_object.as_ptr(),
                priv_key_der.as_mut_ptr(),
                priv_key_der.len() as word32,
            )
        };
        check_if_greater_than_zero(ret).unwrap();
        priv_key_der.resize(ret as usize, 0);

        let rustls_pkcs8_der = PrivatePkcs8KeyDer::from(priv_key_der.as_slice());
        let rustls_private_key = PrivateKeyDer::from(rustls_pkcs8_der);

        let ret = unsafe {
            wc_RsaKeyToPublicDer(
                rsa_key_object.as_ptr(),
                pub_key_der.as_mut_ptr(),
                pub_key_der.len() as word32,
            )
        };
        check_if_greater_than_zero(ret).unwrap();
        pub_key_der.resize(ret as usize, 0);

        sign_and_verify(
            provider,
            scheme,
            rustls_private_key.clone_key(),
            pub_key_der.as_slice(),
        );

        Ok(())
    }

    #[test]
    fn rsa_pkcs1_sign_and_verify() {
        init_thread_pool();

        let wolfcrypt_default_provider = rustls_wolfcrypt_provider::provider();
        let test_cases: Vec<_> = [
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
        .iter()
        .flat_map(|&scheme| [2048, 4096].iter().map(move |&key_size| (scheme, key_size)))
        .collect();

        test_cases.par_iter().for_each(|&(scheme, key_size)| {
            generate_and_test_pkcs1_key(&wolfcrypt_default_provider, scheme, key_size).expect(
                &format!("Failed for scheme {:?} with key size {}", scheme, key_size),
            );
        });
    }

    fn generate_and_test_pkcs1_key(
        provider: &CryptoProvider,
        scheme: SignatureScheme,
        key_size: usize,
    ) -> Result<(), anyhow::Error> {
        let mut rsa_key_c_type: RsaKey = unsafe { mem::zeroed() };
        let rsa_key_object = unsafe { RsaKeyObject::from_ptr(&mut rsa_key_c_type) };
        let mut priv_key_der: Vec<u8> = vec![0; 2392];
        let mut pub_key_der: Vec<u8> = vec![0; 2392];

        let mut ret;

        ret = unsafe { wc_InitRsaKey(rsa_key_object.as_ptr(), std::ptr::null_mut()) };
        check_if_zero(ret).unwrap();

        let mut rng_c_type: WC_RNG = unsafe { mem::zeroed() };
        let rng_object = WCRngObject::new(&mut rng_c_type);
        rng_object.init();

        unsafe { wc_RsaSetRNG(rsa_key_object.as_ptr(), rng_object.as_ptr()) };

        ret = unsafe {
            wc_MakeRsaKey(
                rsa_key_object.as_ptr(),
                key_size as i32,
                WC_RSA_EXPONENT.into(),
                rng_object.as_ptr(),
            )
        };
        check_if_zero(ret).unwrap();

        ret = unsafe {
            wc_RsaKeyToDer(
                rsa_key_object.as_ptr(),
                priv_key_der.as_mut_ptr(),
                priv_key_der.len() as word32,
            )
        };
        check_if_greater_than_zero(ret).unwrap();
        priv_key_der.resize(ret as usize, 0);

        let rustls_pkcs1_der = PrivatePkcs1KeyDer::from(priv_key_der.as_slice());
        let rustls_private_key = PrivateKeyDer::from(rustls_pkcs1_der);

        ret = unsafe {
            wc_RsaKeyToPublicDer(
                rsa_key_object.as_ptr(),
                pub_key_der.as_mut_ptr(),
                pub_key_der.len() as word32,
            )
        };
        check_if_greater_than_zero(ret).unwrap();
        pub_key_der.resize(ret as usize, 0);

        sign_and_verify(
            provider,
            scheme,
            rustls_private_key.clone_key(),
            &pub_key_der,
        );
        Ok(())
    }

    fn sign_and_verify(
        provider: &rustls::crypto::CryptoProvider,
        scheme: SignatureScheme,
        rustls_private_key: PrivateKeyDer<'static>,
        pub_key: &[u8],
    ) {
        let data = "data to sign and verify".as_bytes();

        // Signing...
        let signing_key = provider
            .key_provider
            .load_private_key(rustls_private_key)
            .unwrap();

        let signer = signing_key
            .choose_scheme(&[scheme])
            .expect("signing provider supports this scheme");
        let signature = signer.sign(data).unwrap();

        // Verifying...
        let algs = provider
            .signature_verification_algorithms
            .mapping
            .iter()
            .find(|(k, _v)| *k == scheme)
            .map(|(_k, v)| *v)
            .expect("verifying provider supports this scheme");
        assert!(!algs.is_empty());
        assert!(algs
            .iter()
            .any(|alg| { alg.verify_signature(pub_key, data, &signature).is_ok() }));
    }
}
