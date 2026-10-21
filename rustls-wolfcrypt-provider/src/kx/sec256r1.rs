use alloc::boxed::Box;
use wolfssl_wolfcrypt::ecc::ECC;
use wolfssl_wolfcrypt::random::RNG;
use zeroize::Zeroizing;

pub struct KeyExchangeSecP256r1 {
    priv_key_bytes: Zeroizing<Box<[u8]>>,
    pub_key_bytes: Box<[u8]>,
}

impl KeyExchangeSecP256r1 {
    pub fn use_secp256r1() -> Result<Self, rustls::Error> {
        let rng = RNG::new().map_err(|_| rustls::Error::General("wc_InitRng failed".into()))?;

        let key_size = ECC::get_curve_size_from_id(ECC::SECP256R1)
            .map_err(|_| rustls::Error::General("wc_ecc_get_curve_size_from_id failed".into()))?;

        let mut key = ECC::generate_ex(key_size, &rng, ECC::SECP256R1, None, None)
            .map_err(|_| rustls::Error::General("wc_ecc_make_key_ex failed".into()))?;

        let mut priv_key_raw: Zeroizing<Box<[u8]>> =
            Zeroizing::new(alloc::vec![0u8; 32].into_boxed_slice());
        #[cfg(fips)]
        let _read = wolfssl_wolfcrypt::fips::PrivateKeyRead::enable().ok();
        key.export_private(&mut priv_key_raw)
            .map_err(|_| rustls::Error::General("wc_ecc_export_private_only failed".into()))?;

        // One byte prefix (0x04) + 32 bytes X coord + 32 bytes Y coord
        let mut pub_key_bytes = [0u8; 65];
        key.export_x963(&mut pub_key_bytes)
            .map_err(|_| rustls::Error::General("wc_ecc_export_x963 failed".into()))?;

        Ok(KeyExchangeSecP256r1 {
            priv_key_bytes: priv_key_raw,
            pub_key_bytes: Box::new(pub_key_bytes),
        })
    }

    pub fn derive_shared_secret(&self, peer_pub_key: &[u8]) -> Result<Box<[u8]>, rustls::Error> {
        if peer_pub_key.len() != 65 {
            return Err(rustls::Error::General(
                "Invalid peer public key length".into(),
            ));
        }

        let mut priv_key =
            ECC::import_private_key_ex(&self.priv_key_bytes, &[], ECC::SECP256R1, None, None)
                .map_err(|_| rustls::Error::General("Failed to import ECC private key".into()))?;

        // rustls hands us the uncompressed point (0x04 || X || Y), see
        // https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8.2.
        let mut pub_key = ECC::import_x963_ex(peer_pub_key, ECC::SECP256R1, None, None)
            .map_err(|_| rustls::Error::General("Failed to import peer ECC public key".into()))?;

        let rng = RNG::new().map_err(|_| rustls::Error::General("wc_InitRng failed".into()))?;
        priv_key
            .set_rng(rng)
            .map_err(|_| rustls::Error::General("Failed to set RNG on private key".into()))?;

        let mut out = [0u8; 32];
        #[cfg(fips)]
        let _read = wolfssl_wolfcrypt::fips::PrivateKeyRead::enable().ok();
        priv_key
            .shared_secret(&mut pub_key, &mut out)
            .map_err(|_| rustls::Error::General("Failed to compute ECC shared secret".into()))?;

        Ok(Box::new(out))
    }
}

impl rustls::crypto::ActiveKeyExchange for KeyExchangeSecP256r1 {
    fn complete(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<rustls::crypto::SharedSecret, rustls::Error> {
        let secret = self.derive_shared_secret(peer_pub_key)?;
        Ok(rustls::crypto::SharedSecret::from(&*secret))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key_bytes
    }

    fn group(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::secp256r1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::ActiveKeyExchange;

    #[test]
    fn test_secp256r1_kx() {
        let alice = Box::new(KeyExchangeSecP256r1::use_secp256r1().unwrap());
        let bob = Box::new(KeyExchangeSecP256r1::use_secp256r1().unwrap());

        assert_eq!(
            alice.derive_shared_secret(bob.pub_key()).unwrap(),
            bob.derive_shared_secret(alice.pub_key()).unwrap(),
        )
    }
}
