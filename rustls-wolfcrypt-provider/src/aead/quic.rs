// Copyright 2018 Brian Smith.


//! QUIC Header Protection.
//!
//! See draft-ietf-quic-tls.

use alloc::vec;
use core::mem;
use foreign_types::ForeignType;

use alloc::vec::Vec;
use core::ptr;
use wolfcrypt_rs::*;
use rustls::{Error, crypto::cipher::AeadKey, quic};
use rustls::crypto::cipher::{Iv, Nonce};
use rustls::quic::Tag;
use alloc::boxed::Box;
use crate::error::check_if_zero;

use crate::types::AesObject;

const TAG_LEN: usize = 16;


/// A QUIC header protection algorithm.
#[derive(Debug, Clone, Copy)]
pub(crate) enum HeaderProtectionAlgorithm {
    Aes128,
    Aes256,
    ChaCha20,
}


/// A key for generating QUIC Header Protection masks.
pub struct HeaderProtectionKey {
    inner:  AeadKey,
    algorithm: HeaderProtectionAlgorithm,
}


impl HeaderProtectionKey {
    /// Create a new header protection key.
    ///
    /// `key_bytes` must be exactly `algorithm.key_len` bytes long.
    pub(crate) fn new(
        key: AeadKey,
        algorithm: HeaderProtectionAlgorithm,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: key,
            algorithm,
        })
    }

    fn xor_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
        masked: bool,
    ) -> Result<(), Error> {
        // This implements "Header Protection Application" almost verbatim.
        // <https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.1>

        let mask = self
            .generate_mask(sample)
            .map_err(|_| Error::General("sample of invalid length".into()))?;

        // The `unwrap()` will not panic because `new_mask` returns a
        // non-empty result.
        let (first_mask, pn_mask) = mask.split_first().unwrap();

        // It is OK for the `mask` to be longer than `packet_number`,
        // but a valid `packet_number` will never be longer than `mask`.
        if packet_number.len() > pn_mask.len() {
            return Err(Error::General("packet number too long".into()));
        }

        // Infallible from this point on. Before this point, `first` and
        // `packet_number` are unchanged.

        const LONG_HEADER_FORM: u8 = 0x80;
        let bits = match *first & LONG_HEADER_FORM == LONG_HEADER_FORM {
            true => 0x0f,  // Long header: 4 bits masked
            false => 0x1f, // Short header: 5 bits masked
        };

        let first_plain = match masked {
            // When unmasking, use the packet length bits after unmasking
            true => *first ^ (first_mask & bits),
            // When masking, use the packet length bits before masking
            false => *first,
        };
        let pn_len = (first_plain & 0x03) as usize + 1;

        *first ^= first_mask & bits;
        for (dst, m) in packet_number
            .iter_mut()
            .zip(pn_mask)
            .take(pn_len)
        {
            *dst ^= m;
        }

        Ok(())
    }

    fn generate_mask_aes(&self, sample: &[u8]) -> Result<Vec<u8>, Error> {

        let mut out_block = vec![0;16];
        let mut aes_c_type: Aes = unsafe { mem::zeroed() };
        let aes_object = unsafe { AesObject::from_ptr(&mut aes_c_type) };
        let mut ret;

        // Initialize Aes structure.
        ret = unsafe { wc_AesInit(aes_object.as_ptr(), ptr::null_mut(), INVALID_DEVID) };
        check_if_zero(ret).unwrap();

        // It initializes an AES object with the given key.
        ret = unsafe {
            wc_AesSetKey(
                aes_object.as_ptr(),
                self.inner.as_ref().as_ptr(),
                self.inner.as_ref().len() as word32,
                ptr::null_mut(),
                0
            )
        };
        check_if_zero(ret).unwrap();


        ret = unsafe {
            wc_AesEncryptDirect(
                aes_object.as_ptr(),
                out_block.as_mut_ptr(),
                sample.as_ptr()
            )
        };
        check_if_zero(ret).unwrap();

        // Free resources occupied by AES object
        unsafe {
            wc_AesFree(aes_object.as_ptr())
        }

        Ok(out_block)
    }


    fn generate_mask_chacha(&self, sample: &[u8]) -> Result<Vec<u8>, Error> {

        let mut out = vec![0;TAG_LEN];
        //Create ChaCha object
        let mut ctx = ChaCha{
            X: [0; 16],
            extra: [0; 12],
            left: 0,
            over: [0; 16],
        };

        //Set key for ChaCha object
        unsafe {
            wc_Chacha_SetKey(&mut ctx, self.inner.as_ref().as_ptr(), self.inner.as_ref().len() as word32);
        }

        let (ctr, nonce) = sample.split_at(4);
        let ctr = u32::from_le_bytes(ctr.try_into().unwrap());

        //Set IV for ChaCha object
        unsafe {
            wc_Chacha_SetIV(&mut ctx, nonce.as_ptr(), ctr);
        }

        //Encrypt sample
        unsafe {
            wc_Chacha_Process(&mut ctx, out.as_mut_ptr(), sample.as_ptr(), sample.len() as word32);
        }

        Ok(out)
    }


    /// Generate a new QUIC Header Protection mask.
    ///
    /// `sample` must be exactly `self.algorithm().sample_len()` bytes long.
    fn generate_mask(&self, sample: &[u8]) -> Result<[u8; 5], Error> {
        let mut mask = [0; 5];
        match self.algorithm {
            // https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.3
            HeaderProtectionAlgorithm::Aes128 | HeaderProtectionAlgorithm::Aes256 => {
                let block = self.generate_mask_aes(sample)
                    .map_err(|_e| Error::General("OpenSSL error: {e}".into()))?;
                mask.copy_from_slice(&block[..5]);
            }
            // https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.4
            HeaderProtectionAlgorithm::ChaCha20 => {
                let block = self.generate_mask_chacha(sample)
                    .map_err(|e| Error::General("OpenSSL error: {e}".into()))?;
                mask.copy_from_slice(&block[..5]);
            }
        }
        Ok(mask)
    }

    /// The key's algorithm.
    #[inline(always)]
    pub fn algorithm(&self) -> HeaderProtectionAlgorithm {
        self.algorithm
    }
}

impl quic::HeaderProtectionKey for HeaderProtectionKey {
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.xor_in_place(sample, first, packet_number, false)
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.xor_in_place(sample, first, packet_number, true)
    }

    #[inline]
    fn sample_len(&self) -> usize {
        TAG_LEN
    }
}

const SAMPLE_LEN: usize = TAG_LEN;

/// QUIC sample for new key masks
pub type Sample = [u8; SAMPLE_LEN];

#[derive(Debug, Clone, Copy)]
pub(crate) enum PacketKeyAlgorithm {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}





/// A QUIC packet protection key.
struct PacketKey {
    algo: PacketKeyAlgorithm,
    key: AeadKey,
    iv: Iv,
    confidentiality_limit: u64,
    integrity_limit: u64,
}

impl PacketKey {
    pub(crate) fn new(
        aead_algorithm: PacketKeyAlgorithm,
        key: AeadKey,
        iv: Iv,
        confidentiality_limit: u64,
        integrity_limit: u64,
    ) -> Self {
        Self {
            algo: aead_algorithm,
            key,
            iv,
            confidentiality_limit,
            integrity_limit,
        }
    }

    fn enc_in_place_aes(
        &self,
        nonce: Nonce,
        aad: &[u8],
        payload: &mut [u8],
    ) -> Result<Tag, Error> {

        let mut auth_tag = vec![0u8; TAG_LEN];
        let mut aes_c_type: Aes = unsafe { mem::zeroed() };
        let aes_object = unsafe { AesObject::from_ptr(&mut aes_c_type) };
        let mut ret;

        // Initialize Aes structure.
        ret = unsafe { wc_AesInit(aes_object.as_ptr(), ptr::null_mut(), INVALID_DEVID) };
        check_if_zero(ret).unwrap();

        // This function is used to set the key for AES GCM (Galois/Counter Mode).
        // It initializes an AES object with the given key.
        ret = unsafe {
            wc_AesGcmSetKey(
                aes_object.as_ptr(),
                self.key.as_ref().as_ptr(),
                self.key.as_ref().len() as word32,
            )
        };
        check_if_zero(ret).unwrap();

        // This function encrypts the input message, held in the buffer in,
        // and stores the resulting cipher text in the output buffer out.
        // It requires a new iv (initialization vector) for each call to encrypt.
        // It also encodes the input authentication vector,
        // authIn, into the authentication tag, authTag.

        ret = unsafe {
            wc_AesGcmEncrypt(
                aes_object.as_ptr(),
                payload.as_mut_ptr(),
                payload.as_ptr(),
                payload.as_ref().len() as word32,
                nonce.0.as_ptr(),
                nonce.0.len() as word32,
                auth_tag.as_mut_ptr(),
                auth_tag.len() as word32,
                aad.as_ptr(),
                aad.len() as word32,
            )
        };
        check_if_zero(ret).unwrap();


        Ok(quic::Tag::from(auth_tag.as_ref()))
    }

    fn enc_in_place_chacha20poly1305(&self, nonce: Nonce, aad: &[u8], payload: &mut [u8]) -> Result<Tag, Error> {

        let mut auth_tag: [u8; CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE as usize] =
            unsafe { mem::zeroed() };

        // This function encrypts an input message, inPlaintext,
        // using the ChaCha20 stream cipher, into the output buffer, outCiphertext.
        // It also performs Poly-1305 authentication (on the cipher text),
        // and stores the generated authentication tag in the output buffer, outAuthTag.

        let ret = unsafe {
            wc_ChaCha20Poly1305_Encrypt(
                self.key.as_ref().as_ptr(),
                nonce.0.as_ptr(),
                aad.as_ptr(),
                aad.len() as word32,
                payload.as_ref().as_ptr(),
                payload.len() as word32,
                payload.as_mut().as_mut_ptr(),
                auth_tag.as_mut_ptr(),
            )
        };
        check_if_zero(ret).unwrap();


        Ok(quic::Tag::from(auth_tag.as_ref()))
    }

    fn dec_in_place_aes<'a>(
        &self,
        nonce: Nonce,
        aad: &[u8],
        payload: &'a mut [u8],
    ) -> Result<(), Error> {
        
        let mut auth_tag = [0u8; TAG_LEN];
        let message_len = payload.len() - TAG_LEN;
        auth_tag.copy_from_slice(&payload[message_len..]);
        let mut aes_c_type: Aes = unsafe { mem::zeroed() };
        let aes_object = unsafe { AesObject::from_ptr(&mut aes_c_type) };
        let mut ret;

        ret = unsafe { wc_AesInit(aes_object.as_ptr(), ptr::null_mut(), INVALID_DEVID) };
        check_if_zero(ret).unwrap();

        ret = unsafe {
            wc_AesGcmSetKey(
                aes_object.as_ptr(),
                self.key.as_ref().as_ptr(),
                self.key.as_ref().len() as word32,
            )
        };
        check_if_zero(ret).unwrap();

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
        check_if_zero(ret).unwrap();

        Ok(())
    }

    fn dec_in_place_chacha20poly1305<'a>(
        &self,
        nonce: Nonce,
        aad: &[u8],
        payload: &'a mut [u8],
    ) -> Result<(), Error> {
        
        let mut auth_tag = [0u8; TAG_LEN];
        let message_len = payload.len() - TAG_LEN;
        auth_tag.copy_from_slice(&payload[message_len..]);

        // This function decrypts input ciphertext, inCiphertext,
        // using the ChaCha20 stream cipher, into the output buffer, outPlaintext.
        // It also performs Poly-1305 authentication, comparing the given inAuthTag
        // to an authentication generated with the inAAD (arbitrary length additional authentication data).
        // Note: If the generated authentication tag does not match the supplied
        // authentication tag, the text is not decrypted.
        let ret = unsafe {
            wc_ChaCha20Poly1305_Decrypt(
                self.key.as_ref().as_ptr(),
                nonce.0.as_ptr(),
                aad.as_ptr(),
                aad.len() as word32,
                // [..message_len] since we want to exclude the
                // the auth_tag.
                payload[..message_len].as_ptr(),
                message_len as word32,
                auth_tag.as_ptr(),
                payload[..message_len].as_mut_ptr(),
            )
        };
        check_if_zero(ret).unwrap();
        Ok(())
    }
}

impl quic::PacketKey for PacketKey {
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<Tag, Error> {
        let aad = header;
        let nonce = Nonce::new(&self.iv, packet_number);
        let tag = match self
            .algo {
            PacketKeyAlgorithm::Aes128Gcm | PacketKeyAlgorithm::Aes256Gcm => {
                self.enc_in_place_aes(nonce, aad, payload).map_err(|_| Error::EncryptError)?
            },
            PacketKeyAlgorithm::ChaCha20Poly1305 => {
                self.enc_in_place_chacha20poly1305(nonce, aad, payload).map_err(|_| Error::EncryptError)?
            },

        };

        Ok(tag)
    }



    /// Decrypt a QUIC packet
    ///
    /// Takes the packet `header`, which is used as the additional authenticated data, and the
    /// `payload`, which includes the authentication tag.
    ///
    /// If the return value is `Ok`, the decrypted payload can be found in `payload`, up to the
    /// length found in the return value.
    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let payload_len = payload.len();
        let aad = header;
        let nonce = Nonce::new(&self.iv, packet_number);
        match self
            .algo {
            PacketKeyAlgorithm::Aes128Gcm | PacketKeyAlgorithm::Aes256Gcm => {
                self.dec_in_place_aes(nonce, aad, payload).map_err(|_| Error::EncryptError)?
            },
            PacketKeyAlgorithm::ChaCha20Poly1305 => {
                self.dec_in_place_chacha20poly1305(nonce, aad, payload).map_err(|_| Error::EncryptError)?
            },

        };

        let plain_len = payload_len - TAG_LEN;
        Ok(&payload[..plain_len])
    }

    /// Tag length for the underlying AEAD algorithm
    #[inline]
    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    /// Confidentiality limit (see [`quic::PacketKey::confidentiality_limit`])
    fn confidentiality_limit(&self) -> u64 {
        self.confidentiality_limit
    }

    /// Integrity limit (see [`quic::PacketKey::integrity_limit`])
    fn integrity_limit(&self) -> u64 {
        self.integrity_limit
    }
}

pub(crate) struct KeyBuilder {
    pub(crate) packet_algo: PacketKeyAlgorithm,
    pub(crate) header_algo: HeaderProtectionAlgorithm,
    pub(crate) confidentiality_limit: u64,
    pub(crate) integrity_limit: u64,
}


impl quic::Algorithm for KeyBuilder {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn quic::PacketKey> {
        Box::new(PacketKey {
            algo: self.packet_algo,
            key,
            iv,
            confidentiality_limit: self.confidentiality_limit,
            integrity_limit: self.integrity_limit,
        })
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn quic::HeaderProtectionKey> {
        Box::new(HeaderProtectionKey {
            algorithm: self.header_algo,
            inner: key,
        })
    }

    fn aead_key_len(&self) -> usize {
       match self.packet_algo { 
           PacketKeyAlgorithm::Aes256Gcm | PacketKeyAlgorithm::ChaCha20Poly1305 => 32,
           PacketKeyAlgorithm::Aes128Gcm => 16,
       }
    }

    fn fips(&self) -> bool {
        false
    }
}




