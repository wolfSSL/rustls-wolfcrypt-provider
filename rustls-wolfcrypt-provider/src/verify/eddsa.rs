use crate::{
    error::{check_if_one, check_if_zero, WCError},
    types::*,
};
use core::mem;
use foreign_types::ForeignType;
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use webpki::alg_id;
use wolfcrypt_rs::*;

#[derive(Debug)]
pub struct Ed25519;

impl SignatureVerificationAlgorithm for Ed25519 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        unsafe {
            let mut ed25519_c_type: ed25519_key = mem::zeroed();
            let ed25519_key_object = ED25519KeyObject::from_ptr(&mut ed25519_c_type);
            let mut ret = 0;
            let mut stat: i32 = 0;

            ed25519_key_object.init();
            check_if_zero(ret).unwrap();

            ret = wc_ed25519_import_public(
                public_key.as_ptr(),
                public_key.len() as word32,
                ed25519_key_object.as_ptr(),
            );
            check_if_zero(ret).unwrap();

            ret = wc_ed25519_verify_msg(
                signature.as_ptr(),
                signature.len() as word32,
                message.as_ptr(),
                message.len() as word32,
                &mut stat,
                ed25519_key_object.as_ptr(),
            );

            if let Err(WCError::Failure) = check_if_one(ret) {
                Ok(())
            } else {
                Err(InvalidSignature)
            }
        }
    }
}
