use aead::{AeadInPlace, KeyInit};
use alloc::boxed::Box;
use alloc::vec;
use rustls::crypto::cipher::{
    make_tls12_aad, make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv,
    KeyBlockShape, MessageDecrypter, MessageEncrypter, Nonce, OutboundOpaqueMessage,
    OutboundPlainMessage, PrefixedPayload, Tls12AeadAlgorithm, Tls13AeadAlgorithm,
    UnsupportedOperationError,
};
use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion};
use wolfssl_wolfcrypt::aes::Aes256Gcm as WCAes256Gcm;

const GCM_NONCE_LENGTH: usize = 12;
const GCM_TAG_LENGTH: usize = 16;

pub struct Aes256Gcm;

impl Tls12AeadAlgorithm for Aes256Gcm {
    fn fips(&self) -> bool {
        crate::fips()
    }

    fn encrypter(&self, key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter> {
        let mut iv_as_array = [0u8; GCM_NONCE_LENGTH];
        iv_as_array[..(GCM_NONCE_LENGTH - 8)].copy_from_slice(iv); // implicit
        iv_as_array[(GCM_NONCE_LENGTH - 8)..].copy_from_slice(extra); // explicit

        Box::new(WCTls12Encrypter {
            iv: iv_as_array.into(),
            cipher: new_cipher(&key),
        })
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        // Considering only the implicit nonce (4 bytes) for
        // the process of decryption.
        // So we substract the explicit one (8 bytes).
        let mut iv_implicit_as_array = [0u8; GCM_NONCE_LENGTH - 8];
        iv_implicit_as_array.copy_from_slice(iv);

        Box::new(WCTls12Decrypter {
            implicit_iv: iv_implicit_as_array,
            cipher: new_cipher(&key),
        })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: 32,
            fixed_iv_len: 4,
            explicit_nonce_len: 8,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        let mut iv_as_vec = vec![0u8; GCM_NONCE_LENGTH];

        iv_as_vec[..4].copy_from_slice(iv);
        iv_as_vec[4..].copy_from_slice(explicit);

        Ok(ConnectionTrafficSecrets::Aes256Gcm {
            key,
            iv: Iv::new(iv_as_vec.try_into().unwrap()),
        })
    }
}

fn new_cipher(key: &AeadKey) -> WCAes256Gcm {
    WCAes256Gcm::new_from_slice(key.as_ref()).expect("AES-256-GCM key must be 32 bytes")
}

// Since we use a different Iv (full_iv/implicit) based of
// the process on what we are doing (encryption/decryption)
// We separate the structs for the implementation.
pub struct WCTls12Encrypter {
    iv: Iv,
    cipher: WCAes256Gcm,
}

pub struct WCTls12Decrypter {
    implicit_iv: [u8; 4],
    cipher: WCAes256Gcm,
}

impl MessageEncrypter for WCTls12Encrypter {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        // We load the full payload into the PrefixedPayload struct,
        // required by OutboundOpaqueMessage.
        let total_len = self.encrypted_payload_len(m.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        // We copy the payload provided into the PrefixedPayload variable
        // just created using extend_from_chunks, since the payload
        // is contained inside the enum OutboundChunks.
        // At the beginning of it we add the the freshly created nonce, by including
        // the last 8 bytes (explicit one, the explicit one will be used later, so
        // we substract it in the length).
        let nonce = Nonce::new(&self.iv, seq).0;
        payload.extend_from_slice(&nonce[(GCM_NONCE_LENGTH - 8)..]);
        payload.extend_from_chunks(&m.payload);

        let aad = make_tls12_aad(seq, m.typ, m.version, m.payload.len());

        // Encrypt the message in place, after the explicit nonce, and get
        // the authentication tag back.
        let payload_start = GCM_NONCE_LENGTH - 4;
        let payload_end = m.payload.len() + (GCM_NONCE_LENGTH - 4);
        let auth_tag = self
            .cipher
            .encrypt_in_place_detached(
                aead::Nonce::<WCAes256Gcm>::from_slice(&nonce),
                &aad,
                &mut payload.as_mut()[payload_start..payload_end],
            )
            .map_err(|_| rustls::Error::General("AES-GCM encryption failed".into()))?;

        payload.extend_from_slice(&auth_tag);

        Ok(OutboundOpaqueMessage::new(m.typ, m.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + (GCM_NONCE_LENGTH - 4) + GCM_TAG_LENGTH
    }
}

impl MessageDecrypter for WCTls12Decrypter {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload = &mut m.payload;
        if payload.len() < (GCM_NONCE_LENGTH - 4) + GCM_TAG_LENGTH {
            return Err(rustls::Error::DecryptError);
        }
        let payload_len = payload.len();

        // First we copy the implicit nonce followed by copying
        // the explicit, both from the slice.
        let mut nonce = [0u8; GCM_NONCE_LENGTH];
        nonce[..(GCM_NONCE_LENGTH - 8)].copy_from_slice(self.implicit_iv.as_ref());
        nonce[(GCM_NONCE_LENGTH - 8)..].copy_from_slice(&payload[..(GCM_NONCE_LENGTH - 4)]);

        let mut auth_tag = [0u8; GCM_TAG_LENGTH];
        auth_tag.copy_from_slice(&payload[payload_len - GCM_TAG_LENGTH..]);
        let aad = make_tls12_aad(
            seq,
            m.typ,
            m.version,
            payload_len - GCM_TAG_LENGTH - (GCM_NONCE_LENGTH - 4),
        );

        // Finally, we have everything to decrypt the message
        // from the payload.
        let payload_start = GCM_NONCE_LENGTH - 4;
        let payload_end = payload_len - GCM_TAG_LENGTH;
        self.cipher
            .decrypt_in_place_detached(
                aead::Nonce::<WCAes256Gcm>::from_slice(&nonce),
                &aad,
                &mut payload[payload_start..payload_end],
                aead::Tag::<WCAes256Gcm>::from_slice(&auth_tag),
            )
            .map_err(|_| rustls::Error::DecryptError)?;

        payload.copy_within(payload_start..(payload_len - GCM_TAG_LENGTH), 0);
        payload.truncate(payload_len - ((payload_start) + GCM_TAG_LENGTH));

        Ok(m.into_plain_message())
    }
}

impl Tls13AeadAlgorithm for Aes256Gcm {
    fn fips(&self) -> bool {
        crate::fips()
    }

    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(WCTls13Cipher {
            cipher: new_cipher(&key),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(WCTls13Cipher {
            cipher: new_cipher(&key),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        32_usize
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes256Gcm { key, iv })
    }
}

pub struct WCTls13Cipher {
    cipher: WCAes256Gcm,
    iv: Iv,
}

impl MessageEncrypter for WCTls13Cipher {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let payload_len = m.payload.len();
        let total_len = self.encrypted_payload_len(payload_len);
        let mut payload = PrefixedPayload::with_capacity(total_len);

        // We copy the payload provided into the PrefixedPayload variable
        // just created using extend_from_chunks, since the payload
        // is contained inside the enum OutboundChunks, followed by
        // an extend_from_slice to add the ContentType at the end of it.
        payload.extend_from_chunks(&m.payload);
        payload.extend_from_slice(&m.typ.to_array());

        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(total_len);

        // Encrypt in place and get the authentication tag back.
        // Apparently we need to also need to include for the encoding type into the encrypted
        // payload, hence the + 1 otherwise the rustls returns EoF.
        let auth_tag = self
            .cipher
            .encrypt_in_place_detached(
                aead::Nonce::<WCAes256Gcm>::from_slice(&nonce.0),
                &aad,
                &mut payload.as_mut()[..payload_len + 1],
            )
            .map_err(|_| rustls::Error::General("AES-GCM encryption failed".into()))?;

        // Finally, we add the authentication tag at the end of it
        // after the process of encryption is done.
        payload.extend_from_slice(&auth_tag);

        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        // the + 1 refers to the encoded type (included in the encrypted payload).
        payload_len + 1 + GCM_TAG_LENGTH
    }
}

impl MessageDecrypter for WCTls13Cipher {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload = &mut m.payload;
        // In case peer misbehaves and sends plain text after it is not anymore allowed
        if payload.len() < GCM_TAG_LENGTH {
            return Err(rustls::Error::DecryptError);
        }
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(payload.len());
        let mut auth_tag = [0u8; GCM_TAG_LENGTH];
        let message_len = payload.len() - GCM_TAG_LENGTH;
        auth_tag.copy_from_slice(&payload[message_len..]);

        // Finally, we have everything to decrypt the message
        // from the payload.
        self.cipher
            .decrypt_in_place_detached(
                aead::Nonce::<WCAes256Gcm>::from_slice(&nonce.0),
                &aad,
                &mut payload[..message_len],
                aead::Tag::<WCAes256Gcm>::from_slice(&auth_tag),
            )
            .map_err(|_| rustls::Error::DecryptError)?;

        payload.truncate(message_len);

        m.into_tls13_unpadded_message()
    }
}

#[cfg(test)]
mod tests {
    use wolfssl_wolfcrypt::aes::GCM;
    use wycheproof::{aead::TestFlag, TestResult};

    const GCM_TAG_LENGTH: usize = super::GCM_TAG_LENGTH;

    #[test]
    fn test_aesgcm256() {
        let key: [u8; 32] = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
            0x83, 0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
            0x67, 0x30, 0x83, 0x08,
        ];

        let iv: [u8; 12] = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
        ];

        let plain: [u8; 60] = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5,
            0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d,
            0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf,
            0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39,
        ];

        let aad: [u8; 20] = [
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
            0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2,
        ];

        let cipher: [u8; 60] = [
            0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84,
            0x42, 0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd,
            0x25, 0x55, 0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0,
            0x8b, 0x10, 0x56, 0x82, 0x88, 0x38, 0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
            0xbc, 0xc9, 0xf6, 0x62,
        ];

        let tag: [u8; 16] = [
            0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68, 0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d,
            0x55, 0x1b,
        ];

        let mut result_encrypted: [u8; 60] = [0; 60];
        let mut result_decrypted: [u8; 60] = [0; 60];
        let mut result_tag: [u8; 16] = [0; 16];

        let mut gcm = GCM::new().unwrap();
        gcm.init(&key).unwrap();

        gcm.encrypt(&plain, &mut result_encrypted, &iv, &aad, &mut result_tag)
            .unwrap();

        assert_eq!(result_encrypted, cipher);
        assert_eq!(result_tag, tag);

        gcm.decrypt(&cipher, &mut result_decrypted, &iv, &aad, &result_tag)
            .unwrap();

        assert_eq!(result_decrypted, plain);
    }

    #[test]
    fn test_aesgcm256_wycheproof() {
        let test_name = wycheproof::aead::TestName::AesGcm;
        let test_set = wycheproof::aead::TestSet::load(test_name).unwrap();
        let mut counter = 0;

        for group in test_set
            .test_groups
            .into_iter()
            .filter(|group| group.key_size == 256)
            .filter(|group| group.nonce_size == 96)
        {
            for test in group.tests {
                counter += 1;

                let mut gcm = GCM::new().unwrap();
                gcm.init(&test.key).unwrap();

                let mut actual_ciphertext = test.pt.to_vec();
                let mut actual_tag = [0u8; GCM_TAG_LENGTH];

                let encrypt_result = gcm.encrypt(
                    &test.pt,
                    &mut actual_ciphertext,
                    &test.nonce,
                    &test.aad,
                    &mut actual_tag,
                );

                match &test.result {
                    TestResult::Invalid => {
                        if test.flags.contains(&TestFlag::ModifiedTag) {
                            assert_ne!(
                                actual_tag[..],
                                test.tag[..],
                                "Expected incorrect tag. Id {}: {}",
                                test.tc_id,
                                test.comment
                            );
                        }
                    }
                    TestResult::Valid | TestResult::Acceptable => {
                        assert!(
                            encrypt_result.is_ok(),
                            "Encryption failed for test case {}: {}",
                            test.tc_id,
                            test.comment
                        );

                        assert_eq!(
                            actual_ciphertext[..],
                            test.ct[..],
                            "Encryption failed for test case {}: {}",
                            test.tc_id,
                            test.comment
                        );

                        assert_eq!(
                            actual_tag[..],
                            test.tag[..],
                            "Tag mismatch in test case {}: {}",
                            test.tc_id,
                            test.comment
                        );
                    }
                }

                let mut decrypted_data = test.ct.to_vec();
                let decrypt_result = gcm.decrypt(
                    &test.ct,
                    &mut decrypted_data,
                    &test.nonce,
                    &test.aad,
                    &test.tag,
                );

                match &test.result {
                    TestResult::Invalid => {
                        assert!(
                            decrypt_result.is_err(),
                            "Decryption should have failed for invalid test case {}: {}",
                            test.tc_id,
                            test.comment
                        );
                    }
                    TestResult::Valid | TestResult::Acceptable => {
                        assert!(
                            decrypt_result.is_ok(),
                            "Decryption failed for test case {}: {}",
                            test.tc_id,
                            test.comment
                        );
                        assert_eq!(
                            decrypted_data[..],
                            test.pt[..],
                            "Decryption failed for test case {}: {}",
                            test.tc_id,
                            test.comment
                        );
                    }
                }
            }
        }

        assert!(
            counter > 50,
            "Insufficient number of tests run: {}",
            counter
        );
    }
}
