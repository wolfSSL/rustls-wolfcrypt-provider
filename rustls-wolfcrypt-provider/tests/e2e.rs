use std::io::{Read, Write};
use std::io::{stdout};
use std::net::TcpStream;
use std::sync::Arc;
use rustls_wolfcrypt_provider::provider;
use rustls::{
    version::{TLS12, TLS13},
};

#[cfg(test)]
mod tests {
    use super::*;

    /* tls 1.2 against rust-lang.org */
    #[test]
    fn test_tls12() {
        env_logger::init();

        let root_store = rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned(),
        );

        let config =
            rustls::ClientConfig::builder_with_provider(provider().into())
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

    /* tls 1.3 against rust-lang.org */
    #[test]
    fn test_tls13() {
        let root_store = rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned(),
        );

        let config =
            rustls::ClientConfig::builder_with_provider(provider().into())
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
