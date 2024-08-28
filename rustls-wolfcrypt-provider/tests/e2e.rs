use std::io::{Read, Write};
use std::env;
use std::io::{stdout};
use std::process::{Command, Child};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::io::BufReader;
use std::fs::File;
use rustls_wolfcrypt_provider::{
   TLS13_CHACHA20_POLY1305_SHA256,
   TLS13_AES_128_GCM_SHA256,
   TLS13_AES_256_GCM_SHA384,
   TLS12_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
   TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
   TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
};
use rustls::{
    version::{TLS12, TLS13},
};
use serial_test::serial;

/*
 * Version config used by the server to specify
 * the tls version that we wanna use.
 * */
const TLSV1_2: &str = "-v 3";
const TLSV1_3: &str = "-v 4";

/* 
 * Starts background job for wolfssl server (localhost:4443).
 * */
fn start_wolfssl_server(current_dir_string: String, tls_version: &str) -> Child {
    if let Err(e) = env::set_current_dir("../wolfcrypt-rs/wolfssl-5.7.2-stable/") {
        panic!("Error changing directory: {}", e);
    } else {
        println!("Changed directory to wolfssl-5.7.2-stable.");

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
    use super::*;

    #[test]
    #[serial]
    fn test_tls12_against_server() {
        env_logger::init();

        let current_dir = env::current_dir().unwrap();
        let current_dir_string = current_dir.to_string_lossy().into_owned();

        let ciphers = [
            TLS12_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ];

        for cipher in ciphers {
            let server_thread = {
                let wolfssl_server = Arc::new(Mutex::new(start_wolfssl_server(current_dir_string.clone(), TLSV1_2)));
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

            let mut root_store = rustls::RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned(),
            );

            let certs = rustls_pemfile::certs(&mut BufReader::new(
                &mut File::open(current_dir_string.clone() + "/tests/certs/RootCA.pem").unwrap()))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();

            root_store.add_parsable_certificates(certs);

            let config =
                rustls::ClientConfig::builder_with_provider(
                    rustls_wolfcrypt_provider::provider_with_specified_ciphers([cipher].to_vec()).into()
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
            ).unwrap();

            let ciphersuite = tls
                .conn
                .negotiated_cipher_suite()
                .unwrap();
            writeln!(
                &mut std::io::stderr(),
                "Current ciphersuite: {:?}",
                ciphersuite.suite()
            ).unwrap();

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
    #[serial]
    fn test_tls13_against_server() {
        let current_dir = env::current_dir().unwrap();
        let current_dir_string = current_dir.to_string_lossy().into_owned();

        let ciphers = [
            TLS13_CHACHA20_POLY1305_SHA256,
            TLS13_AES_128_GCM_SHA256,
            TLS13_AES_256_GCM_SHA384,
        ];

        for cipher in ciphers {
            let server_thread = {
                let wolfssl_server = Arc::new(Mutex::new(start_wolfssl_server(current_dir_string.clone(), TLSV1_3)));
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

            let mut root_store = rustls::RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned(),
            );

            let certs = rustls_pemfile::certs(&mut BufReader::new(
                &mut File::open(current_dir_string.clone() + "/tests/certs/RootCA.pem").unwrap()))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();

            root_store.add_parsable_certificates(certs);

            let config =
                rustls::ClientConfig::builder_with_provider(
                    rustls_wolfcrypt_provider::provider_with_specified_ciphers([cipher].to_vec()).into()
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
            ).unwrap();

            let ciphersuite = tls
                .conn
                .negotiated_cipher_suite()
                .unwrap();
            writeln!(
                &mut std::io::stderr(),
                "Current ciphersuite: {:?}",
                ciphersuite.suite()
            ).unwrap();

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
    #[serial]
    fn test_tl12_against_website() {
        let ciphers = [
            TLS12_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ];

        for cipher in ciphers {
            let root_store = rustls::RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned(),
            );

            let config =
                rustls::ClientConfig::builder_with_provider(
                    rustls_wolfcrypt_provider::provider_with_specified_ciphers([cipher].to_vec()).into()
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
            ).unwrap();

            let ciphersuite = tls
                .conn
                .negotiated_cipher_suite()
                .unwrap();
            writeln!(
                &mut std::io::stderr(),
                "Current ciphersuite: {:?}",
                ciphersuite.suite()
            ).unwrap();

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
    #[serial]
    fn test_tl13_against_website() {
        let ciphers = [
            TLS13_CHACHA20_POLY1305_SHA256,
            TLS13_AES_128_GCM_SHA256,
            TLS13_AES_256_GCM_SHA384,
        ];

        for cipher in ciphers {
            let root_store = rustls::RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned(),
            );

            let config =
                rustls::ClientConfig::builder_with_provider(
                    rustls_wolfcrypt_provider::provider_with_specified_ciphers([cipher].to_vec()).into()
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
            ).unwrap();

            let ciphersuite = tls
                .conn
                .negotiated_cipher_suite()
                .unwrap();
            writeln!(
                &mut std::io::stderr(),
                "Current ciphersuite: {:?}",
                ciphersuite.suite()
            ).unwrap();

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
}
