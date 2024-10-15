use alloc::boxed::Box;
use foreign_types::ForeignType;
use rustls::crypto::cipher::{
    make_tls12_aad, make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv,
    KeyBlockShape, MessageDecrypter, MessageEncrypter, Nonce, OutboundOpaqueMessage,
    OutboundPlainMessage, PrefixedPayload, Tls12AeadAlgorithm, Tls13AeadAlgorithm,
    UnsupportedOperationError,
};
use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion};
use std::mem;
use std::vec;
use wolfcrypt_rs::*;
use crate::types::types::*;

const GCM_NONCE_LENGTH: usize = 12;
const GCM_TAG_LENGTH: usize = 16;

pub struct Aes256Gcm;

impl Tls12AeadAlgorithm for Aes256Gcm {
    fn encrypter(&self, key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter> {
        let mut iv_as_array = [0u8; GCM_NONCE_LENGTH];
        iv_as_array[..(GCM_NONCE_LENGTH - 8)].copy_from_slice(iv); // implicit
        iv_as_array[(GCM_NONCE_LENGTH - 8)..].copy_from_slice(extra); // explicit
        let key_as_slice = key.as_ref();

        Box::new(WCTls12Encrypter {
            iv: iv_as_array.into(),
            key: key_as_slice.to_vec(),
        })
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        // Considering only the implicit nonce (4 bytes) for
        // the process of decryption.
        // So we substract the explicit one (8 bytes).
        let mut iv_implicit_as_array = [0u8; GCM_NONCE_LENGTH - 8];
        iv_implicit_as_array.copy_from_slice(iv);

        let key_as_slice = key.as_ref();

        Box::new(WCTls12Decrypter {
            implicit_iv: iv_implicit_as_array,
            key: key_as_slice.to_vec(),
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

        iv_as_vec.copy_from_slice(iv);
        iv_as_vec.copy_from_slice(explicit);

        Ok(ConnectionTrafficSecrets::Aes256Gcm {
            key,
            iv: Iv::new(iv_as_vec.try_into().unwrap()),
        })
    }
}

// Since we use a different Iv (full_iv/implicit) based of
// the process on what we are doing (encryption/decryption)
// We separate the structs for the implementation.
pub struct WCTls12Encrypter {
    iv: Iv,
    key: Vec<u8>,
}

pub struct WCTls12Decrypter {
    implicit_iv: [u8; 4],
    key: Vec<u8>,
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
        let mut auth_tag = vec![0u8; GCM_TAG_LENGTH];
        let mut aes_c_type: Aes = unsafe { mem::zeroed() };
        let aes_object = unsafe { AesObject::from_ptr(&mut aes_c_type) };
        let mut ret;

        // Initialize Aes structure.
        ret = unsafe { wc_AesInit(aes_object.as_ptr(), std::ptr::null_mut(), INVALID_DEVID) };
        if ret < 0 {
            panic!("error while calling wc_AesInit");
        }

        // This function is used to set the key for AES GCM (Galois/Counter Mode).
        // It initializes an AES object with the given key.
        ret = unsafe {
            wc_AesGcmSetKey(
                aes_object.as_ptr(),
                self.key.as_ptr(),
                self.key.len() as word32,
            )
        };
        if ret < 0 {
            panic!("error while calling wc_AesGcmSetKey");
        }

        // This function encrypts the input message, held in the buffer in,
        // and stores the resulting cipher text in the output buffer out.
        // It requires a new iv (initialization vector) for each call to encrypt.
        // It also encodes the input authentication vector,
        // authIn, into the authentication tag, authTag.
        // We only care about the explicit IV, so we skip the first
        // 8 bytes.
        let payload_start = GCM_NONCE_LENGTH - 4;
        let payload_end = m.payload.len() + (GCM_NONCE_LENGTH - 4);
        ret = unsafe {
            wc_AesGcmEncrypt(
                aes_object.as_ptr(),
                payload.as_mut()[payload_start..payload_end].as_mut_ptr(),
                payload.as_ref()[payload_start..payload_end].as_ptr(),
                payload.as_ref()[payload_start..payload_end].len() as word32,
                nonce.as_ptr(),
                nonce.len() as word32,
                auth_tag.as_mut_ptr(),
                auth_tag.len() as word32,
                aad.as_ptr(),
                aad.len() as word32,
            )
        };
        if ret < 0 {
            panic!("error while calling wc_AesGcmEncrypt, ret = {}", ret);
        }

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
        let mut aes_c_type: Aes = unsafe { mem::zeroed() };
        let aes_object = unsafe { AesObject::from_ptr(&mut aes_c_type) };
        let mut ret;

        ret = unsafe { wc_AesInit(aes_object.as_ptr(), std::ptr::null_mut(), INVALID_DEVID) };
        if ret < 0 {
            panic!("error while calling wc_AesInit");
        }

        ret = unsafe {
            wc_AesGcmSetKey(
                aes_object.as_ptr(),
                self.key.as_ptr(),
                self.key.len() as word32,
            )
        };
        if ret < 0 {
            panic!("error while calling wc_AesGcmSetKey");
        }

        // Finally, we have everything to decrypt the message
        // from the payload.
        let payload_start = GCM_NONCE_LENGTH - 4;
        let payload_end = payload_len - GCM_TAG_LENGTH;
        ret = unsafe {
            wc_AesGcmDecrypt(
                aes_object.as_ptr(),
                payload[payload_start..payload_end].as_mut_ptr(),
                payload[payload_start..payload_end].as_ptr(),
                payload[payload_start..payload_end]
                    .len()
                    .try_into()
                    .unwrap(),
                nonce.as_ptr(),
                nonce.len() as word32,
                auth_tag.as_ptr(),
                auth_tag.len() as word32,
                aad.as_ptr(),
                aad.len() as word32,
            )
        };
        if ret < 0 {
            panic!("error while calling wc_AesGcmDecrypt, ret = {}", ret);
        }

        payload.copy_within(payload_start..(payload_len - GCM_TAG_LENGTH), 0);
        payload.truncate(payload_len - ((payload_start) + GCM_TAG_LENGTH));

        Ok(m.into_plain_message())
    }
}

impl Tls13AeadAlgorithm for Aes256Gcm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(WCTls13Cipher {
            key: key.as_ref().into(),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(WCTls13Cipher {
            key: key.as_ref().into(),
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
    key: Vec<u8>,
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
        let mut auth_tag: [u8; GCM_TAG_LENGTH] = unsafe { mem::zeroed() };
        let mut aes_c_type: Aes = unsafe { mem::zeroed() };
        let aes_object = unsafe { AesObject::from_ptr(&mut aes_c_type) };
        let mut ret;

        // Initialize Aes structure.
        ret = unsafe { wc_AesInit(aes_object.as_ptr(), std::ptr::null_mut(), INVALID_DEVID) };
        if ret < 0 {
            panic!("error while calling wc_AesInit");
        }

        // This function is used to set the key for AES GCM (Galois/Counter Mode).
        // It initializes an AES object with the given key.
        ret = unsafe {
            wc_AesGcmSetKey(
                aes_object.as_ptr(),
                self.key.as_ptr(),
                self.key.len() as word32,
            )
        };
        if ret < 0 {
            panic!("error while calling wc_AesGcmSetKey");
        }

        // This function encrypts the input message, held in the buffer in,
        // and stores the resulting cipher text in the output buffer out.
        // It requires a new iv (initialization vector) for each call to encrypt.
        // It also encodes the input authentication vector,
        // authIn, into the authentication tag, authTag.
        // Apparently we need to also need to include for the encoding type into the encrypted
        // payload, hence the + 1 otherwise the rustls returns EoF.
        ret = unsafe {
            wc_AesGcmEncrypt(
                aes_object.as_ptr(),
                payload.as_mut()[..payload_len + 1].as_mut_ptr(),
                payload.as_ref()[..payload_len + 1].as_ptr(),
                payload.as_ref()[..payload_len + 1].len() as word32,
                nonce.0.as_ptr(),
                nonce.0.len() as word32,
                auth_tag.as_mut_ptr(),
                auth_tag.len() as word32,
                aad.as_ptr(),
                aad.len() as word32,
            )
        };
        if ret < 0 {
            panic!("error while calling wc_AesGcmEncrypt, ret = {}", ret);
        }

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
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(payload.len());
        let mut auth_tag = [0u8; GCM_TAG_LENGTH];
        let message_len = payload.len() - GCM_TAG_LENGTH;
        auth_tag.copy_from_slice(&payload[message_len..]);
        let mut aes_c_type: Aes = unsafe { mem::zeroed() };
        let aes_object = unsafe { AesObject::from_ptr(&mut aes_c_type) };
        let mut ret;

        ret = unsafe { wc_AesInit(aes_object.as_ptr(), std::ptr::null_mut(), INVALID_DEVID) };
        if ret < 0 {
            panic!("error while calling wc_AesInit");
        }

        ret = unsafe {
            wc_AesGcmSetKey(
                aes_object.as_ptr(),
                self.key.as_ptr(),
                self.key.len() as word32,
            )
        };
        if ret < 0 {
            panic!("error while calling wc_AesGcmSetKey");
        }

        // Finally, we have everything to decrypt the message
        // from the payload.
        ret = unsafe {
            wc_AesGcmDecrypt(
                aes_object.as_ptr(),
                payload[..message_len].as_mut_ptr(),
                payload[..message_len].as_ptr(),
                payload[..message_len].len().try_into().unwrap(),
                nonce.0.as_ptr(),
                nonce.0.len() as word32,
                auth_tag.as_ptr(),
                auth_tag.len() as word32,
                aad.as_ptr(),
                aad.len() as word32,
            )
        };
        if ret < 0 {
            panic!("error while calling wc_AesGcmDecrypt, ret = {}", ret);
        }

        payload.truncate(message_len);

        m.into_tls13_unpadded_message()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aesgcm256() {
        unsafe {
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
            let mut aes_c_type: Aes = mem::zeroed();
            let aes_object = AesObject::from_ptr(&mut aes_c_type);
            let mut ret;

            // Initialize Aes structure.
            ret = wc_AesInit(aes_object.as_ptr(), std::ptr::null_mut(), INVALID_DEVID);
            if ret < 0 {
                panic!("error while calling wc_AesInit");
            }

            // This function is used to set the key for AES GCM (Galois/Counter Mode).
            // It initializes an AES object with the given key.
            ret = wc_AesGcmSetKey(aes_object.as_ptr(), key.as_ptr(), key.len() as word32);
            if ret < 0 {
                panic!("error while calling wc_AesGcmSetKey");
            }

            ret = wc_AesGcmEncrypt(
                aes_object.as_ptr(),
                result_encrypted.as_mut_ptr(),
                plain.as_ptr(),
                plain.len() as word32,
                iv.as_ptr(),
                iv.len() as word32,
                result_tag.as_mut_ptr(),
                result_tag.len() as word32,
                aad.as_ptr(),
                aad.len() as word32,
            );
            if ret < 0 {
                panic!("error while claling wc_AesGcmEncrypt");
            }

            assert_eq!(result_encrypted, cipher);
            assert_eq!(result_tag, tag);

            ret = wc_AesGcmDecrypt(
                aes_object.as_ptr(),
                result_decrypted.as_mut_ptr(),
                cipher.as_ptr(),
                cipher.len() as word32,
                iv.as_ptr(),
                iv.len() as word32,
                result_tag.as_mut_ptr(),
                result_tag.len() as word32,
                aad.as_ptr(),
                aad.len() as word32,
            );
            if ret < 0 {
                panic!("error while claling wc_AesGcmEncrypt");
            }

            assert_eq!(result_decrypted, plain);
        }
    }
}
