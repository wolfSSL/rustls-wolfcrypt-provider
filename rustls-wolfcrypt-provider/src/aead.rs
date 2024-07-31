use alloc::boxed::Box;

use chacha20poly1305::aead::Buffer;
use chacha20poly1305::{AeadInPlace, KeyInit, KeySizeUser};
use rustls::crypto::cipher::{
    make_tls12_aad, make_tls13_aad, AeadKey, BorrowedPayload, InboundOpaqueMessage,
    InboundPlainMessage, Iv, KeyBlockShape, MessageDecrypter, MessageEncrypter, Nonce,
    OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls12AeadAlgorithm,
    Tls13AeadAlgorithm, UnsupportedOperationError, NONCE_LEN,
};
use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion};
use std::mem;
use std::vec;
use wolfcrypt_rs::*;

pub struct Chacha20Poly1305;

impl Tls12AeadAlgorithm for Chacha20Poly1305 {
    fn encrypter(&self, key: AeadKey, iv: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        let mut key_as_array = [0u8; 32];
        key_as_array[..32].copy_from_slice(key.as_ref());

        Box::new(
            WCTls12Cipher {
                key: key_as_array,
                iv: Iv::copy(iv),
            }
        )
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(Tls12Cipher(
                chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref())
                .expect("key should be valid"),
                Iv::copy(iv),
        ))
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

struct Tls12Cipher(chacha20poly1305::ChaCha20Poly1305, Iv);

pub struct WCTls12Cipher {
    key: [u8; 32],
    iv: Iv,
}

impl MessageEncrypter for WCTls12Cipher {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        unsafe {
            let total_len = self.encrypted_payload_len(m.payload.len());
            let mut payload = PrefixedPayload::with_capacity(total_len);
            payload.extend_from_chunks(&m.payload);

            let nonce = Nonce::new(&self.iv, seq);
            let aad = make_tls12_aad(seq, m.typ, m.version, m.payload.len());
            let mut cipher = vec!(0u8; m.payload.len());
            let mut auth_tag: [u8; CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE as usize] = mem::zeroed();
            let payload_raw = payload.as_ref();
            let ret;

            ret = wc_ChaCha20Poly1305_Encrypt(
                self.key.as_ptr(), 
                nonce.0.as_ptr(), 
                aad.as_ptr(), 
                aad.len() as word32,
                payload_raw.as_ptr(),
                m.payload.len() as word32,
                cipher.as_mut_ptr(), 
                auth_tag.as_mut_ptr() 
            );
            if ret < 0 {
                panic!("error while calling wc_ChaCha20Poly1305_Encrypt");
            }

            let mut output = PrefixedPayload::with_capacity(total_len);

            output.extend_from_slice(cipher.as_slice());
            output.extend_from_slice(&auth_tag);

            Ok(
                OutboundOpaqueMessage::new(m.typ, m.version, output)
            )
        }
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + CHACHAPOLY1305_OVERHEAD
    }
}

impl MessageDecrypter for Tls12Cipher {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload = &m.payload;
        let nonce = chacha20poly1305::Nonce::from(Nonce::new(&self.1, seq).0);
        let aad = make_tls12_aad(
            seq,
            m.typ,
            m.version,
            payload.len() - CHACHAPOLY1305_OVERHEAD,
        );

        let payload = &mut m.payload;
        self.0
            .decrypt_in_place(&nonce, &aad, &mut DecryptBufferAdapter(payload))
            .map_err(|_| rustls::Error::DecryptError)?;

        Ok(m.into_plain_message())
    }
}


impl Tls13AeadAlgorithm for Chacha20Poly1305 {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Cipher(
            chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap(),
            iv,
        ))
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Cipher(
            chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap(),
            iv,
        ))
    }

    fn key_len(&self) -> usize {
        chacha20poly1305::ChaCha20Poly1305::key_size()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }
}


struct Tls13Cipher(chacha20poly1305::ChaCha20Poly1305, Iv);

impl MessageEncrypter for Tls13Cipher {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        payload.extend_from_chunks(&m.payload);
        payload.extend_from_slice(&m.typ.to_array());
        let nonce = chacha20poly1305::Nonce::from(Nonce::new(&self.1, seq).0);
        let aad = make_tls13_aad(total_len);

        self.0
            .encrypt_in_place(&nonce, &aad, &mut EncryptBufferAdapter(&mut payload))
            .map_err(|_| rustls::Error::EncryptError)
            .map(|_| {
                OutboundOpaqueMessage::new(
                    ContentType::ApplicationData,
                    ProtocolVersion::TLSv1_2,
                    payload,
                )
            })
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + CHACHAPOLY1305_OVERHEAD
    }
}

impl MessageDecrypter for Tls13Cipher {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload = &mut m.payload;
        let nonce = chacha20poly1305::Nonce::from(Nonce::new(&self.1, seq).0);
        let aad = make_tls13_aad(payload.len());

        self.0
            .decrypt_in_place(&nonce, &aad, &mut DecryptBufferAdapter(payload))
            .map_err(|_| rustls::Error::DecryptError)?;

        m.into_tls13_unpadded_message()
    }
}


const CHACHAPOLY1305_OVERHEAD: usize = 16;

struct EncryptBufferAdapter<'a>(&'a mut PrefixedPayload);

impl AsRef<[u8]> for EncryptBufferAdapter<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for EncryptBufferAdapter<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl Buffer for EncryptBufferAdapter<'_> {
    fn extend_from_slice(&mut self, other: &[u8]) -> chacha20poly1305::aead::Result<()> {
        self.0.extend_from_slice(other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len)
    }
}

struct DecryptBufferAdapter<'a, 'p>(&'a mut BorrowedPayload<'p>);

impl AsRef<[u8]> for DecryptBufferAdapter<'_, '_> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl AsMut<[u8]> for DecryptBufferAdapter<'_, '_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0
    }
}

impl Buffer for DecryptBufferAdapter<'_, '_> {
    fn extend_from_slice(&mut self, _: &[u8]) -> chacha20poly1305::aead::Result<()> {
        unreachable!("not used by `AeadInPlace::decrypt_in_place`")
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len)
    }
}

#[cfg(test)]
mod tests {
    use std::mem;
    use wolfcrypt_rs::*;

    #[test]
    fn test_chacha() {
        unsafe {
            let mut key: [u8; 32] = [
                0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
            ];
            let mut plain_text: [u8; 114] = [
                0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
                0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
                0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
                0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
                0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
                0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
                0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
                0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
                0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
                0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
                0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
                0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
                0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f,
                0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
                0x74, 0x2e
            ];
            let mut iv: [u8; 12] = [
                0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
                0x44, 0x45, 0x46, 0x47
            ];
            let mut aad: [u8; 12] = [
                0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
                0xc4, 0xc5, 0xc6, 0xc7
            ];
            let mut cipher: [u8; 114] = [ /* expected output from operation */
                0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
                0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
                0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
                0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
                0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
                0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
                0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
                0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
                0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
                0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
                0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
                0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
                0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
                0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
                0x61, 0x16
            ];
            let mut auth_tag: [u8; 16] = [ /* expected output from operation */
                0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
                0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
            ];
            let mut generated_plain_text: [u8; 114] = mem::zeroed();
            let mut generated_cipher_text: [u8; 114] = mem::zeroed();
            let mut generated_auth_tag: [u8; CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE as usize] = mem::zeroed();
            let mut ret;

            ret = wc_ChaCha20Poly1305_Encrypt(
                    key.as_mut_ptr(),
                    iv.as_mut_ptr(),
                    aad.as_mut_ptr(),
                    aad.len() as word32,
                    plain_text.as_mut_ptr(),
                    plain_text.len() as word32,
                    generated_cipher_text.as_mut_ptr(),
                    generated_auth_tag.as_mut_ptr()
                  );
            if ret != 0 {
                panic!("failed while calling wc_ChaCha20Poly1305_Encrypt, with ret value: {}", ret);
            }

            assert_eq!(generated_cipher_text, cipher);

            ret = wc_ChaCha20Poly1305_Decrypt(
                    key.as_mut_ptr(),
                    iv.as_mut_ptr(),
                    aad.as_mut_ptr(),
                    aad.len() as word32,
                    cipher.as_mut_ptr(),
                    cipher.len() as word32,
                    auth_tag.as_mut_ptr(),
                    generated_plain_text.as_mut_ptr()
                  );
            if ret != 0 {
                panic!("failed while calling wc_Chacha20Poly1305_Decrypt, with ret value: {}", ret);
            }

            assert_eq!(generated_plain_text, plain_text);
        }
    }
}
