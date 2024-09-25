use alloc::boxed::Box;
use crypto::SupportedKxGroup;
use rustls::crypto;

mod sec256r1;
mod sec384r1;
mod sec521r1;
mod x25519;

pub const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[&X25519, &SecP256R1, &SecP384R1, &SecP521R1];

#[derive(Debug)]
pub struct X25519;

impl crypto::SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        Ok(Box::new(x25519::KeyExchangeX25519::use_curve25519()))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

#[derive(Debug)]
pub struct SecP256R1;

impl crypto::SupportedKxGroup for SecP256R1 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        Ok(Box::new(sec256r1::KeyExchangeSecP256r1::use_secp256r1()))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::secp256r1
    }
}

#[derive(Debug)]
pub struct SecP384R1;

impl crypto::SupportedKxGroup for SecP384R1 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        Ok(Box::new(sec384r1::KeyExchangeSecP384r1::use_secp384r1()))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::secp384r1
    }
}

#[derive(Debug)]
pub struct SecP521R1;

impl crypto::SupportedKxGroup for SecP521R1 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        Ok(Box::new(sec521r1::KeyExchangeSecP521r1::use_secp521r1()))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::secp521r1
    }
}

impl crypto::ActiveKeyExchange for x25519::KeyExchangeX25519 {
    fn complete(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<crypto::SharedSecret, rustls::Error> {
        // We derive the shared secret with our private key and
        // the received public key.
        let secret = self.derive_shared_secret(peer_pub_key.to_vec());

        Ok(crypto::SharedSecret::from(secret.as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key_bytes
    }

    fn group(&self) -> rustls::NamedGroup {
        X25519.name()
    }
}

impl crypto::ActiveKeyExchange for sec256r1::KeyExchangeSecP256r1 {
    fn complete(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<crypto::SharedSecret, rustls::Error> {
        // We derive the shared secret with our private key and
        // the received public key.
        let secret = self.derive_shared_secret(peer_pub_key.to_vec());

        Ok(crypto::SharedSecret::from(secret.as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key_bytes.as_slice()
    }

    fn group(&self) -> rustls::NamedGroup {
        SecP256R1.name()
    }
}

impl crypto::ActiveKeyExchange for sec384r1::KeyExchangeSecP384r1 {
    fn complete(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<crypto::SharedSecret, rustls::Error> {
        // We derive the shared secret with our private key and
        // the received public key.
        let secret = self.derive_shared_secret(peer_pub_key.to_vec());

        Ok(crypto::SharedSecret::from(secret.as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key_bytes.as_slice()
    }

    fn group(&self) -> rustls::NamedGroup {
        SecP384R1.name()
    }
}

impl crypto::ActiveKeyExchange for sec521r1::KeyExchangeSecP521r1 {
    fn complete(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<crypto::SharedSecret, rustls::Error> {
        // We derive the shared secret with our private key and
        // the received public key.
        let secret = self.derive_shared_secret(peer_pub_key.to_vec());

        Ok(crypto::SharedSecret::from(secret.as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key_bytes.as_slice()
    }

    fn group(&self) -> rustls::NamedGroup {
        SecP521R1.name()
    }
}
