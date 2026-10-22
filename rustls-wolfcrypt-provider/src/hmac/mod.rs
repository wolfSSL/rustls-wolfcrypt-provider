use alloc::{boxed::Box, vec, vec::Vec};
use rustls::crypto;
use wolfssl_wolfcrypt::hmac::HMAC;
use wolfssl_wolfcrypt::sha::{SHA256, SHA384};
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub enum WCShaHmac {
    Sha256,
    Sha384,
}

impl WCShaHmac {
    fn digest_size(&self) -> usize {
        match self {
            WCShaHmac::Sha256 => SHA256::DIGEST_SIZE,
            WCShaHmac::Sha384 => SHA384::DIGEST_SIZE,
        }
    }

    pub fn hash_type(&self) -> i32 {
        match self {
            WCShaHmac::Sha256 => HMAC::TYPE_SHA256,
            WCShaHmac::Sha384 => HMAC::TYPE_SHA384,
        }
    }

    pub fn hash_len(&self) -> usize {
        match self {
            WCShaHmac::Sha256 => SHA256::DIGEST_SIZE,
            WCShaHmac::Sha384 => SHA384::DIGEST_SIZE,
        }
    }
}

impl crypto::hmac::Hmac for WCShaHmac {
    fn fips(&self) -> bool {
        crate::fips()
    }

    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(WCHmacKey {
            key: Zeroizing::new(key.to_vec()),
            variant: *self,
        })
    }

    fn hash_output_len(&self) -> usize {
        self.digest_size()
    }
}

struct WCHmacKey {
    key: Zeroizing<Vec<u8>>,
    variant: WCShaHmac,
}

impl crypto::hmac::Key for WCHmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
        let mut hmac = HMAC::new(self.variant.hash_type(), &self.key).expect("HMAC::new failed");

        hmac.update(first).expect("HMAC::update failed");
        for m in middle {
            hmac.update(m).expect("HMAC::update failed");
        }
        hmac.update(last).expect("HMAC::update failed");

        let mut digest = vec![0u8; self.variant.digest_size()];
        hmac.finalize(&mut digest).expect("HMAC::finalize failed");
        crypto::hmac::Tag::new(&digest)
    }

    fn tag_len(&self) -> usize {
        self.variant.digest_size()
    }
}
