use super::Hash;
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use rustls::SignatureScheme;
use rustls_pki_types::alg_id;
use wolfssl_wolfcrypt::ecc::ECC;

/// A unified ECDSA verifier for P-256, P-384, and P-521.
/// We store the `SignatureScheme` and switch logic accordingly.
#[derive(Debug)]
pub struct EcdsaVerifier {
    scheme: SignatureScheme,
}

impl EcdsaVerifier {
    /// Constructor for P-256 / ECDSA_NISTP256_SHA256
    pub const P256_SHA256: Self = Self {
        scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
    };

    /// Constructor for P-384 / ECDSA_NISTP384_SHA384
    pub const P384_SHA384: Self = Self {
        scheme: SignatureScheme::ECDSA_NISTP384_SHA384,
    };

    /// Constructor for P-521 / ECDSA_NISTP521_SHA512
    pub const P521_SHA512: Self = Self {
        scheme: SignatureScheme::ECDSA_NISTP521_SHA512,
    };
}

impl SignatureVerificationAlgorithm for EcdsaVerifier {
    fn fips(&self) -> bool {
        crate::fips()
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        match self.scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => alg_id::ECDSA_P256,
            SignatureScheme::ECDSA_NISTP384_SHA384 => alg_id::ECDSA_P384,
            SignatureScheme::ECDSA_NISTP521_SHA512 => alg_id::ECDSA_P521,
            _ => unreachable!("Unsupported scheme for ECDSA public_key_alg_id"),
        }
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        match self.scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => alg_id::ECDSA_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384 => alg_id::ECDSA_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512 => alg_id::ECDSA_SHA512,
            _ => unreachable!("Unsupported scheme for ECDSA signature_alg_id"),
        }
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        // Determine curve, coordinate length, and which hash to use
        let (curve_id, coord_len, hash) = match self.scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => (ECC::SECP256R1, 32, Hash::Sha256),
            SignatureScheme::ECDSA_NISTP384_SHA384 => (ECC::SECP384R1, 48, Hash::Sha384),
            SignatureScheme::ECDSA_NISTP521_SHA512 => (ECC::SECP521R1, 66, Hash::Sha512),
            _ => return Err(InvalidSignature),
        };

        if public_key.len() != 1 + 2 * coord_len {
            return Err(InvalidSignature);
        }

        // rustls hands us the uncompressed point (0x04 || X || Y), see
        // https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8.2.
        let mut key =
            ECC::import_x963_ex(public_key, curve_id, None, None).map_err(|_| InvalidSignature)?;

        // We hash the message since it's not pre-hashed.
        let (digest, digest_len) = hash.digest(message)?;

        match key.verify_hash(signature, &digest[..digest_len]) {
            Ok(true) => Ok(()),
            _ => Err(InvalidSignature),
        }
    }
}
