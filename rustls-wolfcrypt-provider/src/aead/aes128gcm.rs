use alloc::boxed::Box;
use rustls::crypto::cipher::{
    make_tls12_aad, AeadKey, InboundOpaqueMessage,
    InboundPlainMessage, Iv, KeyBlockShape, MessageDecrypter, MessageEncrypter, Nonce,
    OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls12AeadAlgorithm,
    UnsupportedOperationError, make_tls13_aad, Tls13AeadAlgorithm
};
use rustls::{ConnectionTrafficSecrets, ProtocolVersion, ContentType};
use std::mem;
use std::vec;
use foreign_types::{ForeignType};
use crate::types::types::*;
use wolfcrypt_rs::*;

const GCM_NONCE_LENGTH: usize = 12;
const GCM_TAG_LENGTH: usize = 16;

pub struct Aes128Gcm;

impl Tls12AeadAlgorithm for Aes128Gcm {
    fn encrypter(&self, key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter> {
        let mut iv_as_array = [0u8; GCM_NONCE_LENGTH];
        iv_as_array[..(GCM_NONCE_LENGTH-8)].copy_from_slice(iv); // implicit
        iv_as_array[(GCM_NONCE_LENGTH-8)..].copy_from_slice(extra); // explicit
        let key_as_slice = key.as_ref();

        Box::new(
            WCTls12Encrypter {
                iv: iv_as_array.into(),
                key: key_as_slice.to_vec()
            }
        )
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        // Considering only the implicit nonce (4 bytes) for 
        // the process of decryption.
        // So we substract the explicit one (8 bytes).
        let mut iv_implicit_as_array = [0u8; GCM_NONCE_LENGTH - 8];
        iv_implicit_as_array.copy_from_slice(iv);

        let key_as_slice = key.as_ref();

        Box::new(
            WCTls12Decrypter {
                implicit_iv: iv_implicit_as_array,
                key: key_as_slice.to_vec()
            }
        )
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: 16,
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
        let mut iv_as_vec = vec!(0u8; GCM_NONCE_LENGTH);

        iv_as_vec.copy_from_slice(&iv);
        iv_as_vec.copy_from_slice(&explicit);

        Ok(
            ConnectionTrafficSecrets::Aes128Gcm {
                key,
                iv: Iv::new(iv_as_vec.try_into().unwrap())
            }
        )
    }
}

// Since we use a different Iv (full_iv/implicit) based of
// the process on what we are doing (encryption/decryption)
// We separate the structs for the implementation.
pub struct WCTls12Encrypter {
    iv: Iv,
    key: Vec<u8>
}

pub struct WCTls12Decrypter {
    implicit_iv: [u8; 4],
    key: Vec<u8>
}

impl MessageEncrypter for WCTls12Encrypter {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        unsafe {
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
            payload.extend_from_slice(&nonce[(GCM_NONCE_LENGTH-8)..]);
            payload.extend_from_chunks(&m.payload);

            let aad = make_tls12_aad(seq, m.typ, m.version, m.payload.len());
            let mut auth_tag = vec!(0u8; GCM_TAG_LENGTH);
            let mut aes_struct: Aes = mem::zeroed();
            let aes_object = AesObject::from_ptr(&mut aes_struct);
            let mut ret;

            // Initialize Aes structure.
            ret = wc_AesInit(
                aes_object.as_ptr(),
                std::ptr::null_mut(),
                INVALID_DEVID
            );
            if ret < 0 {
                panic!("error while calling wc_AesInit");
            }

            // This function is used to set the key for AES GCM (Galois/Counter Mode). 
            // It initializes an AES object with the given key. 
            ret = wc_AesGcmSetKey(
                aes_object.as_ptr(),
                self.key.as_ptr(),
                self.key.len() as word32
            );
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
            let payload_start = GCM_NONCE_LENGTH-4;
            let payload_end = m.payload.len() + (GCM_NONCE_LENGTH-4);
            ret = wc_AesGcmEncrypt(
                    aes_object.as_ptr(), 
                    payload.as_mut()[payload_start..payload_end].as_mut_ptr(), 
                    payload.as_ref()[payload_start..payload_end].as_ptr(), 
                    payload.as_ref()[payload_start..payload_end].len() as word32, 
                    nonce.as_ptr(), 
                    nonce.len() as word32,
                    auth_tag.as_mut_ptr(), 
                    auth_tag.len() as word32, 
                    aad.as_ptr(), 
                    aad.len() as word32
            );
            if ret < 0 {
                panic!("error while calling wc_AesGcmEncrypt, ret = {}", ret);
            }

            payload.extend_from_slice(&auth_tag);

            Ok(
                OutboundOpaqueMessage::new(m.typ, m.version, payload)
            )
        }
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + (GCM_NONCE_LENGTH-4) + GCM_TAG_LENGTH
    }
}

impl MessageDecrypter for WCTls12Decrypter {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        unsafe {
            let payload = &mut m.payload;
            let payload_len = payload.len();

            // First we copy the implicit nonce followed by copying
            // the explicit, both from the slice.
            let mut nonce = [0u8; GCM_NONCE_LENGTH];
            nonce[..(GCM_NONCE_LENGTH - 8)].copy_from_slice(&self.implicit_iv.as_ref());
            nonce[(GCM_NONCE_LENGTH - 8)..].copy_from_slice(&payload[..(GCM_NONCE_LENGTH - 4)]);

            let mut auth_tag = [0u8; GCM_TAG_LENGTH];
            auth_tag.copy_from_slice(&payload[payload_len - GCM_TAG_LENGTH..]);
            let aad = make_tls12_aad(seq, m.typ, m.version, payload_len - GCM_TAG_LENGTH - (GCM_NONCE_LENGTH - 4));
            let mut aes_struct: Aes = mem::zeroed();
            let aes_object = AesObject::from_ptr(&mut aes_struct);
            let mut ret;

            ret = wc_AesInit(
                aes_object.as_ptr(),
                std::ptr::null_mut(),
                INVALID_DEVID
            );
            if ret < 0 {
                panic!("error while calling wc_AesInit");
            }

            ret = wc_AesGcmSetKey(
                aes_object.as_ptr(),
                self.key.as_ptr(),
                self.key.len() as word32
            );
            if ret < 0 {
                panic!("error while calling wc_AesGcmSetKey");
            }

            // Finally, we have everything to decrypt the message
            // from the payload.
            let payload_start = GCM_NONCE_LENGTH - 4;
            let payload_end = payload_len - GCM_TAG_LENGTH;
            ret = wc_AesGcmDecrypt(
                    aes_object.as_ptr(), 
                    payload[payload_start..payload_end].as_mut_ptr(), 
                    payload[payload_start..payload_end].as_ptr(), 
                    payload[payload_start..payload_end].len().try_into().unwrap(),
                    nonce.as_ptr(), 
                    nonce.len() as word32,
                    auth_tag.as_ptr(), 
                    auth_tag.len() as word32,
                    aad.as_ptr(), 
                    aad.len() as word32, 
            );
            if ret < 0 {
                panic!("error while calling wc_AesGcmDecrypt, ret = {}", ret);
            }

            payload.copy_within(payload_start..(payload_len - GCM_TAG_LENGTH), 0);
            payload.truncate(payload_len - ((payload_start) + GCM_TAG_LENGTH));

            Ok(
                m.into_plain_message()
            )
        }
    }
}

impl Tls13AeadAlgorithm for Aes128Gcm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(
            WCTls13Cipher{
                key: key.as_ref().into(),
                iv,
            }
        )
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(
            WCTls13Cipher{
                key: key.as_ref().into(),
                iv,
            }
        )
    }

    fn key_len(&self) -> usize {
        16 as usize
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(
            ConnectionTrafficSecrets::Aes128Gcm {
                key,
                iv,
            }
        )
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
        unsafe {
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
            let mut auth_tag: [u8; GCM_TAG_LENGTH as usize] = mem::zeroed();
            let mut aes_struct: Aes = mem::zeroed();
            let aes_object = AesObject::from_ptr(&mut aes_struct);
            let mut ret;

            // Initialize Aes structure.
            ret = wc_AesInit(
                aes_object.as_ptr(),
                std::ptr::null_mut(),
                INVALID_DEVID
            );
            if ret < 0 {
                panic!("error while calling wc_AesInit");
            }

            // This function is used to set the key for AES GCM (Galois/Counter Mode). 
            // It initializes an AES object with the given key. 
            ret = wc_AesGcmSetKey(
                aes_object.as_ptr(),
                self.key.as_ptr(),
                self.key.len() as word32
            );
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
            ret = wc_AesGcmEncrypt(
                    aes_object.as_ptr(), 
                    payload.as_mut()[..payload_len + 1].as_mut_ptr(), 
                    payload.as_ref()[..payload_len + 1].as_ptr(), 
                    payload.as_ref()[..payload_len + 1].len() as word32, 
                    nonce.0.as_ptr(), 
                    nonce.0.len() as word32,
                    auth_tag.as_mut_ptr(), 
                    auth_tag.len() as word32, 
                    aad.as_ptr(), 
                    aad.len() as word32
            );
            if ret < 0 {
                panic!("error while calling wc_AesGcmEncrypt, ret = {}", ret);
            }

            // Finally, we add the authentication tag at the end of it
            // after the process of encryption is done.
            payload.extend_from_slice(&auth_tag);

            Ok(
                OutboundOpaqueMessage::new(
                    ContentType::ApplicationData,
                    ProtocolVersion::TLSv1_2,
                    payload,
                )
            )
        }
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
        unsafe {
            let payload = &mut m.payload;
            let nonce = Nonce::new(&self.iv, seq);
            let aad = make_tls13_aad(payload.len());
            let mut auth_tag = [0u8; GCM_TAG_LENGTH];
            let message_len = payload.len() - GCM_TAG_LENGTH;
            auth_tag.copy_from_slice(&payload[message_len..]);
            let mut aes_struct: Aes = mem::zeroed();
            let aes_object = AesObject::from_ptr(&mut aes_struct);
            let mut ret;

            ret = wc_AesInit(
                aes_object.as_ptr(),
                std::ptr::null_mut(),
                INVALID_DEVID
            );
            if ret < 0 {
                panic!("error while calling wc_AesInit");
            }

            ret = wc_AesGcmSetKey(
                aes_object.as_ptr(),
                self.key.as_ptr(),
                self.key.len() as word32
            );
            if ret < 0 {
                panic!("error while calling wc_AesGcmSetKey");
            }

            // Finally, we have everything to decrypt the message
            // from the payload.
            ret = wc_AesGcmDecrypt(
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
            );
            if ret < 0 {
                panic!("error while calling wc_AesGcmDecrypt, ret = {}", ret);
            }

            payload.truncate(message_len);

            m.into_tls13_unpadded_message()
        }
    }
}
