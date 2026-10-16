use aead::{AeadInPlace, KeyInit};
use alloc::boxed::Box;
use rustls::crypto::cipher::{
    make_tls12_aad, make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv,
    KeyBlockShape, MessageDecrypter, MessageEncrypter, Nonce, OutboundOpaqueMessage,
    OutboundPlainMessage, PrefixedPayload, Tls12AeadAlgorithm, Tls13AeadAlgorithm,
    UnsupportedOperationError, NONCE_LEN,
};
use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion};
use wolfssl_wolfcrypt::chacha20_poly1305::{ChaCha20Poly1305, ChaCha20Poly1305Aead};

const CHACHAPOLY1305_OVERHEAD: usize = 16;

pub struct Chacha20Poly1305;

fn new_cipher(key: &AeadKey) -> ChaCha20Poly1305Aead {
    ChaCha20Poly1305Aead::new_from_slice(key.as_ref())
        .expect("ChaCha20-Poly1305 key must be 32 bytes")
}

impl Tls12AeadAlgorithm for Chacha20Poly1305 {
    fn encrypter(&self, key: AeadKey, iv: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        Box::new(WCTls12Cipher {
            cipher: new_cipher(&key),
            iv: Iv::copy(iv),
        })
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(WCTls12Cipher {
            cipher: new_cipher(&key),
            iv: Iv::copy(iv),
        })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: 32,
            fixed_iv_len: 12,
            explicit_nonce_len: 0,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        _explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        // This should always be true because KeyBlockShape and the Iv nonce len are in agreement.
        debug_assert_eq!(NONCE_LEN, iv.len());
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 {
            key,
            iv: Iv::new(iv[..].try_into().unwrap()),
        })
    }
}

pub struct WCTls12Cipher {
    cipher: ChaCha20Poly1305Aead,
    iv: Iv,
}

impl MessageEncrypter for WCTls12Cipher {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());

        // We load the payload into the PrefixedPayload struct,
        // required by OutboundOpaqueMessage.
        let mut payload = PrefixedPayload::with_capacity(total_len);

        // We copy the payload provided into the PrefixedPayload variable
        // just created using extend_from_chunks, since the payload
        // is contained inside the enum OutboundChunks.
        payload.extend_from_chunks(&m.payload);

        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls12_aad(seq, m.typ, m.version, m.payload.len());

        //  Encrypts the message in place using the ChaCha20 stream cipher,
        //  performs Poly-1305 authentication (on the cipher text),
        //  and returns the generated authentication tag.
        let auth_tag = self
            .cipher
            .encrypt_in_place_detached(
                aead::Nonce::<ChaCha20Poly1305Aead>::from_slice(&nonce.0),
                &aad,
                payload.as_mut(),
            )
            .map_err(|_| rustls::Error::General("ChaCha20-Poly1305 encryption failed".into()))?;

        // Finally we add at the end of it the authentication tag.
        payload.extend_from_slice(&auth_tag);

        Ok(OutboundOpaqueMessage::new(m.typ, m.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + CHACHAPOLY1305_OVERHEAD
    }
}

impl MessageDecrypter for WCTls12Cipher {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload = &mut m.payload;
        if payload.len() < CHACHAPOLY1305_OVERHEAD {
            return Err(rustls::Error::DecryptError);
        }

        // We substract the tag, so this len will only consider
        // the message that we are trying to decrypt.
        let message_len = payload.len() - CHACHAPOLY1305_OVERHEAD;
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls12_aad(seq, m.typ, m.version, message_len);
        let mut auth_tag = [0u8; CHACHAPOLY1305_OVERHEAD];
        auth_tag.copy_from_slice(&payload[message_len..]);

        // This function decrypts input ciphertext, inCiphertext,
        // using the ChaCha20 stream cipher, into the output buffer, outPlaintext.
        // It also performs Poly-1305 authentication, comparing the given inAuthTag
        // to an authentication generated with the inAAD (arbitrary length additional authentication data).
        // Note: If the generated authentication tag does not match the supplied
        // authentication tag, the text is not decrypted.
        self.cipher
            .decrypt_in_place_detached(
                aead::Nonce::<ChaCha20Poly1305Aead>::from_slice(&nonce.0),
                &aad,
                // we decrypt only the payload, we don't include the tag.
                &mut payload[..message_len],
                aead::Tag::<ChaCha20Poly1305Aead>::from_slice(&auth_tag),
            )
            .map_err(|_| rustls::Error::DecryptError)?;

        // We extract the final result...
        payload.truncate(message_len);

        Ok(
            // ...And convert it into the
            // InboundPlainMessage type.
            m.into_plain_message(),
        )
    }
}

impl Tls13AeadAlgorithm for Chacha20Poly1305 {
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
        ChaCha20Poly1305::KEYSIZE
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }
}

pub struct WCTls13Cipher {
    cipher: ChaCha20Poly1305Aead,
    iv: Iv,
}

impl MessageEncrypter for WCTls13Cipher {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        // We copy the payload provided into the PrefixedPayload variable
        // just created using extend_from_chunks, since the payload
        // is contained inside the enum OutboundChunks, followed by
        // an extend_from_slice to add the ContentType at the end of it.
        payload.extend_from_chunks(&m.payload);
        payload.extend_from_slice(&m.typ.to_array());

        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(total_len);

        // Encrypts the message in place using the ChaCha20 stream cipher,
        // performs Poly-1305 authentication (on the cipher text),
        // and returns the generated authentication tag.
        // We need to also need to include for the encoding type, apparently, hence the + 1
        // otherwise the rustls returns EoF.
        let auth_tag = self
            .cipher
            .encrypt_in_place_detached(
                aead::Nonce::<ChaCha20Poly1305Aead>::from_slice(&nonce.0),
                &aad,
                &mut payload.as_mut()[..m.payload.len() + 1],
            )
            .map_err(|_| rustls::Error::General("ChaCha20-Poly1305 encryption failed".into()))?;

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
        payload_len + 1 + CHACHAPOLY1305_OVERHEAD
    }
}

impl MessageDecrypter for WCTls13Cipher {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload = &mut m.payload;
        if payload.len() < CHACHAPOLY1305_OVERHEAD {
            return Err(rustls::Error::DecryptError);
        }
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(payload.len());
        let mut auth_tag = [0u8; CHACHAPOLY1305_OVERHEAD];
        let message_len = payload.len() - CHACHAPOLY1305_OVERHEAD;
        auth_tag.copy_from_slice(&payload[message_len..]);

        // This function decrypts input ciphertext, inCiphertext,
        // using the ChaCha20 stream cipher, into the output buffer, outPlaintext.
        // It also performs Poly-1305 authentication, comparing the given inAuthTag
        // to an authentication generated with the inAAD (arbitrary length additional authentication data).
        // Note: If the generated authentication tag does not match the supplied
        // authentication tag, the text is not decrypted.
        self.cipher
            .decrypt_in_place_detached(
                aead::Nonce::<ChaCha20Poly1305Aead>::from_slice(&nonce.0),
                &aad,
                // [..message_len] since we want to exclude the
                // the auth_tag.
                &mut payload[..message_len],
                aead::Tag::<ChaCha20Poly1305Aead>::from_slice(&auth_tag),
            )
            .map_err(|_| rustls::Error::DecryptError)?;

        // We extract the final result...
        payload.truncate(message_len);

        m.into_tls13_unpadded_message()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wycheproof::{aead::TestFlag, TestResult};

    #[test]
    fn test_chacha() {
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let plain_text: [u8; 114] = [
            0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e,
            0x74, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x63, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20,
            0x49, 0x66, 0x20, 0x49, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
            0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e,
            0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, 0x63, 0x72,
            0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
            0x74, 0x2e,
        ];
        let iv: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let cipher: [u8; 114] = [
            /* expected output from operation */
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
            0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
            0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
            0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
            0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
            0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16,
        ];
        let auth_tag: [u8; 16] = [
            /* expected output from operation */
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x06, 0x91,
        ];
        let mut generated_plain_text = [0u8; 114];
        let mut generated_cipher_text = [0u8; 114];
        let mut generated_auth_tag = [0u8; ChaCha20Poly1305::AUTH_TAG_SIZE];

        ChaCha20Poly1305::encrypt(
            &key,
            &iv,
            &aad,
            &plain_text,
            &mut generated_cipher_text,
            &mut generated_auth_tag,
        )
        .unwrap();

        assert_eq!(generated_cipher_text, cipher);
        assert_eq!(generated_auth_tag, auth_tag);

        ChaCha20Poly1305::decrypt(
            &key,
            &iv,
            &aad,
            &cipher,
            &auth_tag,
            &mut generated_plain_text,
        )
        .unwrap();

        assert_eq!(generated_plain_text, plain_text);
    }

    #[test]
    fn test_chacha20poly1305_wycheproof() {
        let test_name = wycheproof::aead::TestName::ChaCha20Poly1305;
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

                let mut actual_ciphertext = test.pt.to_vec();
                let mut actual_tag = [0u8; ChaCha20Poly1305::AUTH_TAG_SIZE];

                let encrypt_result = ChaCha20Poly1305::encrypt(
                    &test.key,
                    &test.nonce,
                    &test.aad,
                    &test.pt,
                    &mut actual_ciphertext,
                    &mut actual_tag,
                );

                match &test.result {
                    TestResult::Invalid => {
                        if test.flags.iter().any(|flag| *flag == TestFlag::ModifiedTag) {
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
                let decrypt_result = ChaCha20Poly1305::decrypt(
                    &test.key,
                    &test.nonce,
                    &test.aad,
                    &test.ct,
                    &test.tag,
                    &mut decrypted_data,
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

        log::info!("Counter: {}", counter);
    }
}
