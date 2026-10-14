use alloc::boxed::Box;
use wolfssl_wolfcrypt::curve25519::Curve25519Key;
use wolfssl_wolfcrypt::random::RNG;

/// The generated key, kept for the whole exchange along with the RNG it was
/// generated with, which wolfSSL uses when curve25519 blinding is built in.
struct X25519Key(Curve25519Key);

// SAFETY: the key owns everything its pointers refer to (including its RNG),
// and is only used through `&mut`.
unsafe impl Send for X25519Key {}
unsafe impl Sync for X25519Key {}

pub struct KeyExchangeX25519 {
    pub_key_bytes: Box<[u8]>,
    key: X25519Key,
}

impl KeyExchangeX25519 {
    pub fn use_curve25519() -> Result<Self, rustls::Error> {
        let rng = RNG::new().map_err(|_| rustls::Error::General("wc_InitRng failed".into()))?;
        let mut key = Curve25519Key::generate(rng)
            .map_err(|_| rustls::Error::General("wc_curve25519_make_key failed".into()))?;

        let mut pub_key_raw = [0u8; Curve25519Key::KEYSIZE];
        key.export_public_ex(&mut pub_key_raw, false)
            .map_err(|_| rustls::Error::General("wc_curve25519_export_public_ex failed".into()))?;

        Ok(KeyExchangeX25519 {
            pub_key_bytes: Box::new(pub_key_raw),
            key: X25519Key(key),
        })
    }

    pub fn derive_shared_secret(
        &mut self,
        peer_pub_key: &[u8],
    ) -> Result<Box<[u8]>, rustls::Error> {
        if peer_pub_key.len() != Curve25519Key::KEYSIZE {
            return Err(rustls::Error::General(
                "Invalid peer public key length".into(),
            ));
        }

        Curve25519Key::check_public(peer_pub_key, false)
            .map_err(|_| rustls::Error::General("Invalid Curve25519 public key".into()))?;

        let mut peer_key = Curve25519Key::import_public_ex(peer_pub_key, false)
            .map_err(|_| rustls::Error::General("Failed to import Curve25519 public key".into()))?;

        let mut out = [0u8; Curve25519Key::KEYSIZE];
        Curve25519Key::shared_secret_ex(&mut self.key.0, &mut peer_key, &mut out, false).map_err(
            |ret| {
                rustls::Error::General(alloc::format!(
                    "Failed to compute Curve25519 shared secret (ret = {ret})"
                ))
            },
        )?;

        Ok(Box::new(out))
    }
}

impl rustls::crypto::ActiveKeyExchange for KeyExchangeX25519 {
    fn complete(
        mut self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<rustls::crypto::SharedSecret, rustls::Error> {
        // We derive the shared secret with our private key and
        // the received public key.
        let secret = self.derive_shared_secret(peer_pub_key)?;

        Ok(rustls::crypto::SharedSecret::from(&*secret))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key_bytes
    }

    fn group(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::ActiveKeyExchange;

    #[test]
    fn test_curve25519_kx() {
        let mut alice = Box::new(KeyExchangeX25519::use_curve25519().unwrap());
        let mut bob = Box::new(KeyExchangeX25519::use_curve25519().unwrap());
        let alice_pub = alice.pub_key().to_vec();
        let bob_pub = bob.pub_key().to_vec();

        assert_eq!(
            alice.derive_shared_secret(&bob_pub).unwrap(),
            bob.derive_shared_secret(&alice_pub).unwrap(),
        )
    }
}
