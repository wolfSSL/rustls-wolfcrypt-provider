//! QUIC Header Protection.
//!
//! See draft-ietf-quic-tls.

#![allow(clippy::type_complexity)]
use alloc::vec;
use core::mem;
use foreign_types::ForeignType;
use zeroize::Zeroize;

use crate::error::check_if_zero;
use crate::types::{AesObject, ChaChaObject};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ptr;

use rustls::crypto::cipher::{Iv, Nonce};
use rustls::quic::Tag;
use rustls::{crypto::cipher::AeadKey, quic, Error};
use wolfcrypt_rs::*;

macro_rules! mask_array {
    () => {
        [0u8; 5]
    };
}
pub enum Cipher {
    Aes(AesCipher),
    ChaCha20(ChaChaCipher),
}

/// All the AEADs we support use 96-bit nonces.
pub const NONCE_LEN: usize = 96 / 8;

pub(crate) const TAG_LEN: usize = 16;

pub const AES_128_KEY_LEN: usize = 128 / 8;
pub const AES_256_KEY_LEN: usize = 256 / 8;

pub const CHACHA_KEY_LEN: usize = 32;
pub const SAMPLE_LEN: usize = TAG_LEN;
pub const MASK_LEN: usize = 5;

/// QUIC sample for new key masks
pub type Sample = [u8; SAMPLE_LEN];

/// A QUIC Header Protection Algorithm.
pub struct HPAlgorithm {
    hp_mask: fn(hp_cipher: &Cipher, sample: &[u8]) -> Result<[u8; MASK_LEN], Error>,
    init: fn(key: &[u8]) -> Result<Cipher, Error>,
    key_len: usize,
    id: HPAlgorithmID,
}

impl HPAlgorithm {
    /// The length of the key.
    #[inline(always)]
    pub fn key_len(&self) -> usize {
        self.key_len
    }

    /// The required sample length.
    #[inline(always)]
    pub fn sample_len(&self) -> usize {
        SAMPLE_LEN
    }
}

/// A QUIC header protection algorithm.
#[derive(Debug, Eq, PartialEq)]
pub enum HPAlgorithmID {
    Aes128,
    Aes256,
    ChaCha20,
}

impl PartialEq for HPAlgorithm {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for HPAlgorithm {}

/// AES-128.
pub static AES_128: HPAlgorithm = HPAlgorithm {
    key_len: AES_128_KEY_LEN,
    hp_mask: generate_mask_aes,
    id: HPAlgorithmID::Aes128,
    init: init_hp_aes_cipher,
};

/// AES-256.
pub static AES_256: HPAlgorithm = HPAlgorithm {
    key_len: AES_256_KEY_LEN,
    hp_mask: generate_mask_aes,
    id: HPAlgorithmID::Aes256,
    init: init_hp_aes_cipher,
};

fn init_hp_aes_cipher(key: &[u8]) -> Result<Cipher, Error> {
    let mut aes_cipher = AesCipher::new()?;
    aes_cipher.set_key(key)?;
    Ok(Cipher::Aes(aes_cipher))
}

fn generate_mask_aes(hp_cipher: &Cipher, sample: &[u8]) -> Result<[u8; MASK_LEN], Error> {
    let aes_cipher = match hp_cipher {
        Cipher::Aes(c) => c,
        _ => return Err(Error::General("Invalid cipher type".into())),
    };

    let mut mask = mask_array!();
    match aes_cipher.encrypt_sample(sample) {
        Ok(output) => mask.copy_from_slice(&output[..5]),
        Err(e) => return Err(e),
    }
    Ok(mask)
}

/// ChaCha20.
pub static CHACHA20: HPAlgorithm = HPAlgorithm {
    key_len: CHACHA_KEY_LEN,
    init: init_hp_chacha20_cipher,
    hp_mask: generate_mask_chacha20,
    id: HPAlgorithmID::ChaCha20,
};

fn init_hp_chacha20_cipher(key: &[u8]) -> Result<Cipher, Error> {
    let mut chacha_cipher = ChaChaCipher::new(None)?;
    chacha_cipher.set_key(key)?;
    Ok(Cipher::ChaCha20(chacha_cipher))
}

fn generate_mask_chacha20(hp_cipher: &Cipher, sample: &[u8]) -> Result<[u8; MASK_LEN], Error> {
    let chacha20_cipher = match hp_cipher {
        Cipher::ChaCha20(c) => c,
        _ => return Err(Error::General("Invalid cipher type".into())),
    };

    let mut mask = mask_array!();
    match chacha20_cipher.encrypt_sample(sample) {
        Ok(output) => mask.copy_from_slice(&output[..5]),
        Err(e) => return Err(e),
    }
    Ok(mask)
}

/// A key for generating QUIC Header Protection masks.
pub struct HeaderProtectionKey {
    hp_cipher: Cipher,
    algorithm: &'static HPAlgorithm,
}

impl HeaderProtectionKey {
    /// Create a new header protection key.
    ///
    /// `key_bytes` must be exactly `algorithm.key_len` bytes long.
    pub fn new(key: Vec<u8>, algorithm: &'static HPAlgorithm) -> Result<Self, Error> {
        if key.len() != algorithm.key_len {
            return Err(Error::General("Invalid key length".into()));
        }
        Ok(Self {
            hp_cipher: (algorithm.init)(&key)?,
            algorithm,
        })
    }

    fn header_protection(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
        masked: bool,
    ) -> Result<(), Error> {
        // This implements "Header Protection Application" almost verbatim.
        // <https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.1>

        if sample.len() != SAMPLE_LEN {
            return Err(Error::General("Invalid sample length".into()));
        }

        let mask = (self.algorithm.hp_mask)(&self.hp_cipher, sample)?;

        let (first_mask, pn_mask) = mask
            .split_first()
            .ok_or_else(|| Error::General("Function split_first failed".into()))?;

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
        for (dst, m) in packet_number.iter_mut().zip(pn_mask).take(pn_len) {
            *dst ^= m;
        }

        Ok(())
    }

    /// The key's algorithm.
    #[inline(always)]
    pub fn algorithm(&self) -> &'static HPAlgorithm {
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
        self.header_protection(sample, first, packet_number, false)
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.header_protection(sample, first, packet_number, true)
    }

    #[inline]
    fn sample_len(&self) -> usize {
        TAG_LEN
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum PacketKeyAlgorithmID {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

/// A QUIC packet protection algorithm.
pub struct AeadAlgorithm {
    init: fn(key: &[u8]) -> Result<Cipher, Error>,

    encrypt: fn(
        packet_cipher: &Cipher,
        nonce: &[u8],
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<Tag, Error>,
    decrypt: fn(
        packet_cipher: &Cipher,
        nonce: &[u8],
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<(), Error>,

    key_len: usize,
    id: PacketKeyAlgorithmID,
}

impl AeadAlgorithm {
    /// The length of the key.
    #[inline(always)]
    pub fn key_len(&self) -> usize {
        self.key_len
    }

    /// The length of a tag.
    #[inline(always)]
    pub fn tag_len(&self) -> usize {
        TAG_LEN
    }

    /// The length of the nonces.
    #[inline(always)]
    pub fn nonce_len(&self) -> usize {
        NONCE_LEN
    }
}

impl PartialEq for AeadAlgorithm {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for AeadAlgorithm {}

/// AES-128 in GCM mode with 128-bit tags and 96 bit nonces.
pub static AES_128_GCM: AeadAlgorithm = AeadAlgorithm {
    init: init_aes_gcm_cipher,
    encrypt: encrypt_aes_gcm,
    decrypt: decrypt_aes_gcm,
    key_len: AES_128_KEY_LEN,
    id: PacketKeyAlgorithmID::Aes128Gcm,
};

/// AES-256 in GCM mode with 128-bit tags and 96 bit nonces.
pub static AES_256_GCM: AeadAlgorithm = AeadAlgorithm {
    init: init_aes_gcm_cipher,
    encrypt: encrypt_aes_gcm,
    decrypt: decrypt_aes_gcm,
    key_len: AES_256_KEY_LEN,
    id: PacketKeyAlgorithmID::Aes256Gcm,
};

fn init_aes_gcm_cipher(key: &[u8]) -> Result<Cipher, Error> {
    let mut aes_cipher = AesCipher::new()?;
    aes_cipher.set_key(key)?;
    Ok(Cipher::Aes(aes_cipher))
}

fn encrypt_aes_gcm(
    packet_cipher: &Cipher,
    nonce: &[u8],
    aad: &[u8],
    in_out: &mut [u8],
) -> Result<Tag, Error> {
    let aes_cipher = match packet_cipher {
        Cipher::Aes(c) => c,
        _ => return Err(Error::General("Invalid cipher type".into())),
    };
    aes_cipher.encrypt_separate_tag(nonce, aad, in_out)
}

pub(super) fn decrypt_aes_gcm(
    packet_cipher: &Cipher,
    nonce: &[u8],
    aad: &[u8],
    in_out: &mut [u8],
) -> Result<(), Error> {
    let aes_cipher = match packet_cipher {
        Cipher::Aes(aes_key) => aes_key,
        _ => return Err(Error::General("Invalid cipher type".into())),
    };
    aes_cipher.decrypt(nonce, aad, in_out)
}

/// ChaCha20-Poly1305 as described in [RFC 8439].
///
/// The keys are 256 bits long and the nonces are 96 bits long.
///
/// [RFC 8439]: https://tools.ietf.org/html/rfc8439
pub static CHACHA20_POLY1305: AeadAlgorithm = AeadAlgorithm {
    init: init_chacha20_poly1305_cipher,
    encrypt: encrypt_chacha20_poly1305,
    decrypt: decrypt_chacha20_poly1305,
    key_len: CHACHA_KEY_LEN,
    id: PacketKeyAlgorithmID::ChaCha20Poly1305,
};

fn init_chacha20_poly1305_cipher(key: &[u8]) -> Result<Cipher, Error> {
    let key_array = <[u8; 32]>::try_from(key)
        .map_err(|_| Error::General("Invalid key length for ChaCha20-Poly1305".into()))?;
    let chacha_cipher = ChaChaCipher::new(Some(key_array))?;
    Ok(Cipher::ChaCha20(chacha_cipher))
}

fn encrypt_chacha20_poly1305(
    packet_cipher: &Cipher,
    nonce: &[u8],
    aad: &[u8],
    in_out: &mut [u8],
) -> Result<Tag, Error> {
    let chacha_cipher = match packet_cipher {
        Cipher::ChaCha20(chacha_key) => chacha_key,
        _ => return Err(Error::General("Invalid cipher type".into())),
    };
    chacha_cipher.encrypt_separate_tag(nonce, aad, in_out)
}

fn decrypt_chacha20_poly1305(
    packet_cipher: &Cipher,
    nonce: &[u8],
    aad: &[u8],
    in_out: &mut [u8],
) -> Result<(), Error> {
    let chacha_cipher = match packet_cipher {
        Cipher::ChaCha20(chacha_key) => chacha_key,
        _ => return Err(Error::General("Invalid cipher type".into())),
    };
    chacha_cipher.decrypt(nonce, aad, in_out)
}

pub(crate) struct PacketKey {
    /// Encrypts or decrypts a packet's payload
    packet_cipher: Cipher,
    /// Computes unique nonces for each packet
    iv: Iv,
    /// Confidentiality limit (see [`quic::PacketKey::confidentiality_limit`])
    confidentiality_limit: u64,
    /// Integrity limit (see [`quic::PacketKey::integrity_limit`])
    integrity_limit: u64,
    /// Algorithm for packet protection
    algorithm: &'static AeadAlgorithm,
}

impl PacketKey {
    pub(crate) fn new(
        key: AeadKey,
        iv: Iv,
        confidentiality_limit: u64,
        integrity_limit: u64,
        algorithm: &'static AeadAlgorithm,
    ) -> Result<Self, Error> {
        if key.as_ref().len() != algorithm.key_len {
            return Err(Error::General("Invalid key length".into()));
        }
        Ok(Self {
            packet_cipher: (algorithm.init)(key.as_ref())?,
            iv,
            confidentiality_limit,
            integrity_limit,
            algorithm,
        })
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
        let nonce = Nonce::new(&self.iv, packet_number).0;
        let tag = (self.algorithm.encrypt)(&self.packet_cipher, &nonce, aad, payload)?;
        Ok(quic::Tag::from(tag.as_ref()))
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
        let nonce = Nonce::new(&self.iv, packet_number).0;
        (self.algorithm.decrypt)(&self.packet_cipher, &nonce, aad, payload)?;
        let plain_len = payload_len - self.algorithm.tag_len();
        Ok(&payload[..plain_len])
    }

    /// Tag length for the underlying AEAD algorithm
    #[inline]
    fn tag_len(&self) -> usize {
        self.algorithm.tag_len()
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

pub(crate) struct KeyFactory {
    pub(crate) packet_algo: &'static AeadAlgorithm,
    pub(crate) header_algo: &'static HPAlgorithm,
    pub(crate) confidentiality_limit: u64,
    pub(crate) integrity_limit: u64,
}

impl quic::Algorithm for KeyFactory {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn quic::PacketKey> {
        Box::new(
            match PacketKey::new(
                key,
                iv,
                self.confidentiality_limit,
                self.integrity_limit,
                self.packet_algo,
            ) {
                Ok(packet_key) => packet_key,
                Err(e) => panic!("PacketKey object creation failed: {:?}", e),
            },
        )
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn quic::HeaderProtectionKey> {
        Box::new(
            match HeaderProtectionKey::new(key.as_ref().to_vec(), self.header_algo) {
                Ok(header_key) => header_key,
                Err(e) => panic!("HeaderProtection Key object creation failed: {:?}", e),
            },
        )
    }

    fn aead_key_len(&self) -> usize {
        self.packet_algo.key_len()
    }

    fn fips(&self) -> bool {
        false
    }
}

pub struct AesCipher {
    aes_object: AesObject,
    key: Vec<u8>,
}

impl Drop for AesCipher {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl AesCipher {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            aes_object: new_aes_object()?,
            key: Vec::new(),
        })
    }

    /// It initializes an AES cipher with the given key.
    pub fn set_key(&mut self, key: &[u8]) -> Result<(), Error> {
        if key.len() != AES_256_KEY_LEN && key.len() != AES_128_KEY_LEN {
            return Err(Error::General("Invalid key length".into()));
        }
        let ret = unsafe {
            wc_AesSetKey(
                self.aes_object.as_ptr(),
                key.as_ptr(),
                key.len() as word32,
                ptr::null_mut(),
                0,
            )
        };
        check_if_zero(ret)
            .map_err(|_| rustls::Error::General("Function AesSetKey failed".into()))?;
        self.key = key.to_vec();
        Ok(())
    }

    pub fn encrypt_sample(&self, sample: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out_block = vec![0; TAG_LEN];

        let ret = unsafe {
            wc_AesEncryptDirect(
                self.aes_object.as_ptr(),
                out_block.as_mut_ptr(),
                sample.as_ptr(),
            )
        };
        check_if_zero(ret).map_err(|_| rustls::Error::EncryptError)?;

        Ok(out_block)
    }

    pub fn encrypt_separate_tag(
        &self,
        nonce: &[u8],
        aad: &[u8],
        payload: &mut [u8],
    ) -> Result<Tag, Error> {
        let mut auth_tag = vec![0u8; TAG_LEN];
        let mut ret;

        // Prepare aes_object for encryption
        ret = unsafe {
            wc_AesGcmSetKey(
                self.aes_object.as_ptr(),
                self.key.as_ptr(),
                self.key.len() as word32,
            )
        };
        check_if_zero(ret)
            .map_err(|_| rustls::Error::General("Function AesGcmSetKey failed".into()))?;

        // This function encrypts the input message, held in the buffer in,
        // and stores the resulting cipher text in the output buffer out.
        // It requires a new iv (initialization vector) for each call to encrypt.
        // It also encodes the input authentication vector,
        // authIn, into the authentication tag, authTag.

        ret = unsafe {
            wc_AesGcmEncrypt(
                self.aes_object.as_ptr(),
                payload.as_mut_ptr(),
                payload.as_ptr(),
                payload.as_ref().len() as word32,
                nonce.as_ptr(),
                nonce.len() as word32,
                auth_tag.as_mut_ptr(),
                auth_tag.len() as word32,
                aad.as_ptr(),
                aad.len() as word32,
            )
        };
        check_if_zero(ret).map_err(|_| rustls::Error::EncryptError)?;

        Ok(quic::Tag::from(auth_tag.as_ref()))
    }
    pub fn decrypt(&self, nonce: &[u8], aad: &[u8], payload: &mut [u8]) -> Result<(), Error> {
        let mut auth_tag = [0u8; TAG_LEN];
        let message_len = payload.len() - TAG_LEN;
        auth_tag.copy_from_slice(&payload[message_len..]);

        let mut ret;

        // Prepare aes_object for decryption
        ret = unsafe {
            wc_AesGcmSetKey(
                self.aes_object.as_ptr(),
                self.key.as_ptr(),
                self.key.len() as word32,
            )
        };
        check_if_zero(ret)
            .map_err(|_| rustls::Error::General("Function AesGcmSetKey failed".into()))?;

        // Finally, we have everything to decrypt the message
        // from the payload.
        ret = unsafe {
            wc_AesGcmDecrypt(
                self.aes_object.as_ptr(),
                payload[..message_len].as_mut_ptr(),
                payload[..message_len].as_ptr(),
                payload[..message_len]
                    .len()
                    .try_into()
                    .map_err(|_| rustls::Error::General("Function try_into() failed".into()))?,
                nonce.as_ptr(),
                nonce.len() as word32,
                auth_tag.as_ptr(),
                auth_tag.len() as word32,
                aad.as_ptr(),
                aad.len() as word32,
            )
        };
        check_if_zero(ret).map_err(|_| rustls::Error::DecryptError)?;

        Ok(())
    }
}

pub struct ChaChaCipher {
    chacha_cipher: Option<ChaChaObject>,
    key: Option<[u8; CHACHA_KEY_LEN]>, // In case of packet protection, no need to initiate a cipher
}

impl Drop for ChaChaCipher {
    fn drop(&mut self) {
        if let Some(key) = self.key.as_mut() {
            key.zeroize();
        }
        self.key = None;
    }
}

impl ChaChaCipher {
    pub fn new(key: Option<[u8; CHACHA_KEY_LEN]>) -> Result<Self, Error> {
        match key {
            None => Ok(Self {
                chacha_cipher: Some(new_chacha_object()?),
                key: None,
            }),
            Some(key_bytes) => Ok(Self {
                chacha_cipher: None,
                key: Some(key_bytes),
            }),
        }
    }

    fn set_key(&mut self, key: &[u8]) -> Result<(), Error> {
        if key.len() != CHACHA_KEY_LEN {
            return Err(Error::General("Invalid key length".into()));
        }

        let chacha_cipher = self.chacha_cipher.as_ref().ok_or_else(|| {
            Error::General("Cipher is none. Create a cipher object before setting key".into())
        })?;
        //Set key for ChaCha object
        let ret =
            unsafe { wc_Chacha_SetKey(chacha_cipher.as_ptr(), key.as_ptr(), key.len() as word32) };
        check_if_zero(ret)
            .map_err(|_| rustls::Error::General("Function wc_Chacha_SetKey failed".into()))?;
        self.key = Some(
            key.try_into()
                .map_err(|_| Error::General("Key must be exactly 32 bytes".into()))?,
        );
        Ok(())
    }

    pub fn key_len(&self) -> usize {
        CHACHA_KEY_LEN
    }

    pub fn encrypt_sample(&self, sample: &[u8]) -> Result<Vec<u8>, Error> {
        let chacha_cipher = self.chacha_cipher.as_ref().ok_or_else(|| {
            Error::General("Cipher is none. Create a cipher object before encryption".into())
        })?;

        let mut out = vec![0; TAG_LEN];

        let (ctr, nonce) = sample.split_at(4);
        let ctr = u32::from_le_bytes(
            ctr.try_into()
                .map_err(|_| rustls::Error::General("Function try_into() failed".into()))?,
        );

        //Set IV for ChaCha object
        let mut ret = unsafe { wc_Chacha_SetIV(chacha_cipher.as_ptr(), nonce.as_ptr(), ctr) };
        check_if_zero(ret)
            .map_err(|_| rustls::Error::General("Function wc_Chacha_SetIV failed".into()))?;

        //Encrypt sample
        ret = unsafe {
            wc_Chacha_Process(
                chacha_cipher.as_ptr(),
                out.as_mut_ptr(),
                [0; TAG_LEN].as_ptr(),
                TAG_LEN as word32,
            )
        };
        check_if_zero(ret).map_err(|_| rustls::Error::EncryptError)?;

        Ok(out)
    }
    pub fn encrypt_separate_tag(
        &self,
        nonce: &[u8],
        aad: &[u8],
        payload: &mut [u8],
    ) -> Result<Tag, Error> {
        let chacha_key = self.key.as_ref().ok_or_else(|| {
            Error::General("Key is none. Generate a key before encryption".into())
        })?;

        let mut auth_tag: [u8; CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE as usize] =
            unsafe { mem::zeroed() };

        // This function encrypts an input message, inPlaintext,
        // using the ChaCha20 stream cipher, into the output buffer, outCiphertext.
        // It also performs Poly-1305 authentication (on the cipher text),
        // and stores the generated authentication tag in the output buffer, outAuthTag.

        let ret = unsafe {
            wc_ChaCha20Poly1305_Encrypt(
                chacha_key.as_ptr(),
                nonce.as_ptr(),
                aad.as_ptr(),
                aad.len() as word32,
                payload.as_ref().as_ptr(),
                payload.len() as word32,
                payload.as_mut().as_mut_ptr(),
                auth_tag.as_mut_ptr(),
            )
        };
        check_if_zero(ret).map_err(|_| rustls::Error::EncryptError)?;

        Ok(quic::Tag::from(auth_tag.as_ref()))
    }

    pub fn decrypt(&self, nonce: &[u8], aad: &[u8], payload: &mut [u8]) -> Result<(), Error> {
        let chacha_key = self.key.as_ref().ok_or_else(|| {
            Error::General("Key is none. Generate a key before decryption".into())
        })?;
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
                chacha_key.as_ptr(),
                nonce.as_ptr(),
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
        check_if_zero(ret).map_err(|_| rustls::Error::DecryptError)?;
        Ok(())
    }
}

fn new_aes_object() -> Result<AesObject, Error> {
    let aes_c_type_box = Box::new(unsafe { mem::zeroed::<Aes>() });
    let aes_c_type_ptr = Box::into_raw(aes_c_type_box);
    let aes_object = unsafe { AesObject::from_ptr(aes_c_type_ptr) };

    // Initialize Aes structure.
    let ret = unsafe { wc_AesInit(aes_object.as_ptr(), ptr::null_mut(), INVALID_DEVID) };
    check_if_zero(ret).map_err(|_| rustls::Error::General("Function AesInit failed".into()))?;
    Ok(aes_object)
}

fn new_chacha_object() -> Result<ChaChaObject, Error> {
    //Create ChaCha object
    let chacha_c_typ_box = Box::new(unsafe { mem::zeroed::<ChaCha>() });
    let chacha_c_typ_ptr = Box::into_raw(chacha_c_typ_box);
    let chacha_object = unsafe { ChaChaObject::from_ptr(chacha_c_typ_ptr) };

    Ok(chacha_object)
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use rustls::crypto::tls13::HkdfExpander;
    use std::prelude::v1::Vec;
    use std::vec;

    use crate::aead;
    use rustls::crypto::cipher::{AeadKey, Iv, NONCE_LEN};
    use rustls::quic::*;

    use crate::default_provider;
    use crate::{TLS13_AES_128_GCM_SHA256, TLS13_CHACHA20_POLY1305_SHA256};
    use rustls::crypto::tls13::OkmBlock;
    use rustls::internal::msgs::codec::Codec;
    use rustls::{ClientConfig, Error, ServerConfig, Side, SideData};
    use rustls_pki_types::PrivatePkcs8KeyDer;
    use std::sync::Arc;

    // Returns the sender's next secrets to use, or the receiver's error.
    fn step<L: SideData, R: SideData>(
        send: &mut ConnectionCommon<L>,
        recv: &mut ConnectionCommon<R>,
    ) -> Result<Option<rustls::quic::KeyChange>, Error> {
        let mut buf = Vec::new();
        let change = loop {
            let prev = buf.len();
            if let Some(x) = send.write_hs(&mut buf) {
                break Some(x);
            }
            if prev == buf.len() {
                break None;
            }
        };

        recv.read_hs(&buf)?;
        assert_eq!(recv.alert(), None);
        Ok(change)
    }

    fn make_default_client_config() -> ClientConfig {
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = rustls::ClientConfig::builder_with_provider(default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config
    }

    fn make_default_server_config() -> ServerConfig {
        let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Provider Server Example");
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Example CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = rcgen::KeyPair::generate_for(alg).unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        // Create a server end entity cert issued by the CA.
        let mut server_ee_params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        server_ee_params.is_ca = rcgen::IsCa::NoCa;
        server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = rcgen::KeyPair::generate_for(alg).unwrap();
        let server_cert = server_ee_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .unwrap();

        let mut server_config = ServerConfig::builder_with_provider(default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![server_cert.into()],
                PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
            )
            .unwrap();

        server_config.key_log = Arc::new(rustls::KeyLogFile::new());

        server_config
    }
    /// Encode each of `items`
    pub fn iter_to_vec_of_bytes<'a, T: Codec<'a>>(items: impl Iterator<Item = T>) -> Vec<u8> {
        let mut body = Vec::new();

        for i in items {
            i.encode(&mut body);
        }
        body
    }

    ///Encode length as prefix
    pub fn prefix_len(mut body: Vec<u8>, len: usize) -> Vec<u8> {
        match len {
            8 => {
                body.splice(0..0, [body.len() as u8]);
            }
            16 => {
                body.splice(0..0, (body.len() as u16).to_be_bytes());
            }
            24 => {
                let len = (body.len() as u32).to_be_bytes();
                body.insert(0, len[1]);
                body.insert(1, len[2]);
                body.insert(2, len[3]);
            }
            _ => panic!("wrong length!"),
        };
        body
    }

    fn make_extensions() -> Vec<Extension> {
        // Create extensions
        let mut extensions: Vec<Extension> = Vec::new();
        // kx group
        extensions.push(Extension {
            typ: 0x000a, // EllipticCurves
            body: prefix_len(
                iter_to_vec_of_bytes([rustls::NamedGroup::secp256r1].into_iter()),
                16,
            ),
        });
        // Sig algs
        extensions.push(Extension {
            typ: 0x000d, // SignatureAlgorithms
            body: prefix_len(
                rustls::SignatureScheme::RSA_PKCS1_SHA256
                    .to_array()
                    .to_vec(),
                16,
            ),
        });

        // Supported Versions,
        extensions.push(Extension {
            typ: 0x002b, // Supported Versions
            body: prefix_len(
                iter_to_vec_of_bytes(
                    [
                        rustls::ProtocolVersion::TLSv1_3,
                        rustls::ProtocolVersion::TLSv1_2,
                    ]
                    .into_iter(),
                ),
                8,
            ),
        });

        // Key share
        const SOME_POINT_ON_P256: &[u8] = &[
            4, 41, 39, 177, 5, 18, 186, 227, 237, 220, 254, 70, 120, 40, 18, 139, 173, 41, 3, 38,
            153, 25, 247, 8, 96, 105, 200, 196, 223, 108, 115, 40, 56, 199, 120, 121, 100, 234,
            172, 0, 229, 146, 31, 177, 73, 138, 96, 244, 96, 103, 102, 179, 217, 104, 80, 1, 85,
            141, 26, 151, 78, 115, 65, 81, 62,
        ];

        let mut share = prefix_len(SOME_POINT_ON_P256.to_vec(), 16);
        share.splice(0..0, rustls::NamedGroup::secp256r1.to_array());

        extensions.push(Extension {
            typ: 0x0033, // Key share
            body: prefix_len(share, 16),
        });
        extensions
    }
    fn make_client_hello() -> Vec<u8> {
        let mut ch: Vec<u8> = Vec::new();
        rustls::ProtocolVersion::TLSv1_2.encode(&mut ch);
        ch.extend_from_slice(&[0u8; 32]); // Encode random
        ch.extend_from_slice(&[0u8; 1]); // Encode session_id
        vec![
            rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
        ]
        .to_vec()
        .encode(&mut ch); // Encode cypher suites
        ch.extend_from_slice(&[0x01, 0x00]); // only null compression

        //Generate ch extensions
        let extensions = make_extensions();

        // Encode the extensions
        let mut exts = vec![];
        for e in extensions {
            e.typ.encode(&mut exts);
            exts.extend_from_slice(&(e.body.len() as u16).to_be_bytes());
            exts.extend_from_slice(&e.body);
        }
        ch.extend(prefix_len(exts, 16));
        // Apply handshake framing to ch data.
        let mut body = prefix_len(ch, 24);
        body.splice(0..0, rustls::HandshakeType::ClientHello.to_array());
        body
    }
    #[derive(Clone)]
    pub struct Extension {
        pub typ: u16,
        pub body: Vec<u8>,
    }

    #[derive(Debug, Clone)]
    struct ChaCha20TestVector {
        key: [u8; 32],
        sample: [u8; 16],
        mask: [u8; 5],
    }

    enum AesTestVector {
        Aes128 {
            key: [u8; 16],
            sample: [u8; 16],
            mask: [u8; 5],
        },
        Aes256 {
            key: [u8; 32],
            sample: [u8; 16],
            mask: [u8; 5],
        },
    }

    fn hkdf_expand_label(
        expander: &Box<dyn HkdfExpander>,
        label: &[u8],
        context: &[u8],
        n: usize,
        output: &mut [u8],
    ) {
        const LABEL_PREFIX: &[u8] = b"tls13 ";

        let output_len = u16::to_be_bytes(n as u16);
        let label_len = u8::to_be_bytes((LABEL_PREFIX.len() + label.len()) as u8);
        let context_len = u8::to_be_bytes(context.len() as u8);

        let info = &[
            &output_len[..],
            &label_len[..],
            LABEL_PREFIX,
            label,
            &context_len[..],
            context,
        ];

        let _ = expander.expand_slice(info, output);
    }

    fn test_short_packet(version: rustls::quic::Version, expected: &[u8]) {
        // Code taken from rustls with modification
        let chacha_key_len = TLS13_CHACHA20_POLY1305_SHA256
            .tls13()
            .unwrap()
            .quic
            .unwrap()
            .aead_key_len();

        const PN: u64 = 654360564;
        const SECRET: &[u8] = &[
            0x9a, 0xc3, 0x12, 0xa7, 0xf8, 0x77, 0x46, 0x8e, 0xbe, 0x69, 0x42, 0x27, 0x48, 0xad,
            0x00, 0xa1, 0x54, 0x43, 0xf1, 0x82, 0x03, 0xa0, 0x7d, 0x60, 0x60, 0xf6, 0x88, 0xf3,
            0x0f, 0x21, 0x63, 0x2b,
        ];

        let mut output = [0u8; aead::quic::CHACHA_KEY_LEN];
        let mut iv = [0u8; aead::quic::NONCE_LEN];
        // Derive Header Protection key
        let secret = OkmBlock::new(SECRET);
        let expander = TLS13_CHACHA20_POLY1305_SHA256
            .tls13()
            .unwrap()
            .hkdf_provider
            .expander_for_okm(&secret);
        //Derive hp key
        hkdf_expand_label(
            &expander,
            match version {
                rustls::quic::Version::V1Draft | rustls::quic::Version::V1 => b"quic hp",
                rustls::quic::Version::V2 => b"quicv2 hp",
                _ => todo!(),
            },
            &[],
            chacha_key_len,
            &mut output,
        );

        let hp_aead_key = AeadKey::from(output.clone());
        let header_protection_key = TLS13_CHACHA20_POLY1305_SHA256
            .tls13()
            .unwrap()
            .quic
            .unwrap()
            .header_protection_key(hp_aead_key);

        // Derive packet protection key and iv
        hkdf_expand_label(
            &expander,
            match version {
                rustls::quic::Version::V1Draft | rustls::quic::Version::V1 => b"quic key",
                rustls::quic::Version::V2 => b"quicv2 key",
                _ => todo!(),
            },
            &[],
            chacha_key_len,
            &mut output,
        );

        let pkt_aead_key = AeadKey::from(output);

        hkdf_expand_label(
            &expander,
            match version {
                rustls::quic::Version::V1Draft | rustls::quic::Version::V1 => b"quic iv",
                rustls::quic::Version::V2 => b"quicv2 iv",
                _ => todo!(),
            },
            &[],
            NONCE_LEN,
            &mut iv,
        );
        let iv = Iv::new(iv);

        let packet_protection_key = TLS13_CHACHA20_POLY1305_SHA256
            .tls13()
            .unwrap()
            .quic
            .unwrap()
            .packet_key(pkt_aead_key, iv);
        const PLAIN: &[u8] = &[0x42, 0x00, 0xbf, 0xf4, 0x01];

        let mut buf = PLAIN.to_vec();
        let (header, payload) = buf.split_at_mut(4);
        let tag = packet_protection_key
            .encrypt_in_place(PN, header, payload)
            .unwrap();
        buf.extend(tag.as_ref());

        let pn_offset = 1;
        let (header, sample) = buf.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let sample = &sample[..header_protection_key.sample_len()];
        header_protection_key
            .encrypt_in_place(sample, &mut first[0], rest)
            .unwrap();

        assert_eq!(&buf, expected);

        let (header, sample) = buf.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let sample = &sample[..header_protection_key.sample_len()];
        header_protection_key
            .decrypt_in_place(sample, &mut first[0], rest)
            .unwrap();

        let (header, payload_tag) = buf.split_at_mut(4);
        let plain = packet_protection_key
            .decrypt_in_place(PN, header, payload_tag)
            .unwrap();

        assert_eq!(plain, &PLAIN[4..]);
    }

    #[test]
    fn short_packet_header_protection() {
        // https://www.rfc-editor.org/rfc/rfc9001.html#name-chacha20-poly1305-short-hea
        test_short_packet(
            rustls::quic::Version::V1,
            &[
                0x4c, 0xfe, 0x41, 0x89, 0x65, 0x5e, 0x5c, 0xd5, 0x5c, 0x41, 0xf6, 0x90, 0x80, 0x57,
                0x5d, 0x79, 0x99, 0xc2, 0x5a, 0x5b, 0xfb,
            ],
        );
    }

    #[test]
    fn short_packet_header_protection_v2() {
        // https://www.ietf.org/archive/id/draft-ietf-quic-v2-10.html#name-chacha20-poly1305-short-head
        test_short_packet(
            rustls::quic::Version::V2,
            &[
                0x55, 0x58, 0xb1, 0xc6, 0x0a, 0xe7, 0xb6, 0xb9, 0x32, 0xbc, 0x27, 0xd7, 0x86, 0xf4,
                0xbc, 0x2b, 0xb2, 0x0f, 0x21, 0x62, 0xba,
            ],
        );
    }

    #[test]
    fn initial_test_vector_v2() {
        let tls13_cipher_suite = TLS13_AES_128_GCM_SHA256.tls13().unwrap();

        // https://www.ietf.org/archive/id/draft-ietf-quic-v2-10.html#name-sample-packet-protection-2
        let icid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let server = Keys::initial(
            rustls::quic::Version::V2,
            tls13_cipher_suite,
            TLS13_AES_128_GCM_SHA256.tls13().unwrap().quic.unwrap(),
            &icid,
            Side::Server,
        );
        let mut server_payload = [
            0x02, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x40, 0x5a, 0x02, 0x00, 0x00, 0x56, 0x03,
            0x03, 0xee, 0xfc, 0xe7, 0xf7, 0xb3, 0x7b, 0xa1, 0xd1, 0x63, 0x2e, 0x96, 0x67, 0x78,
            0x25, 0xdd, 0xf7, 0x39, 0x88, 0xcf, 0xc7, 0x98, 0x25, 0xdf, 0x56, 0x6d, 0xc5, 0x43,
            0x0b, 0x9a, 0x04, 0x5a, 0x12, 0x00, 0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00,
            0x24, 0x00, 0x1d, 0x00, 0x20, 0x9d, 0x3c, 0x94, 0x0d, 0x89, 0x69, 0x0b, 0x84, 0xd0,
            0x8a, 0x60, 0x99, 0x3c, 0x14, 0x4e, 0xca, 0x68, 0x4d, 0x10, 0x81, 0x28, 0x7c, 0x83,
            0x4d, 0x53, 0x11, 0xbc, 0xf3, 0x2b, 0xb9, 0xda, 0x1a, 0x00, 0x2b, 0x00, 0x02, 0x03,
            0x04,
        ];
        let mut server_header = [
            0xd1, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62,
            0xb5, 0x00, 0x40, 0x75, 0x00, 0x01,
        ];
        let tag = server
            .local
            .packet
            .encrypt_in_place(1, &server_header, &mut server_payload)
            .unwrap();
        let (first, rest) = server_header.split_at_mut(1);
        let rest_len = rest.len();
        server
            .local
            .header
            .encrypt_in_place(
                &server_payload[2..18],
                &mut first[0],
                &mut rest[rest_len - 2..],
            )
            .unwrap();
        let mut server_packet = server_header.to_vec();
        server_packet.extend(server_payload);
        server_packet.extend(tag.as_ref());
        let expected_server_packet = [
            0xdc, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62,
            0xb5, 0x00, 0x40, 0x75, 0xd9, 0x2f, 0xaa, 0xf1, 0x6f, 0x05, 0xd8, 0xa4, 0x39, 0x8c,
            0x47, 0x08, 0x96, 0x98, 0xba, 0xee, 0xa2, 0x6b, 0x91, 0xeb, 0x76, 0x1d, 0x9b, 0x89,
            0x23, 0x7b, 0xbf, 0x87, 0x26, 0x30, 0x17, 0x91, 0x53, 0x58, 0x23, 0x00, 0x35, 0xf7,
            0xfd, 0x39, 0x45, 0xd8, 0x89, 0x65, 0xcf, 0x17, 0xf9, 0xaf, 0x6e, 0x16, 0x88, 0x6c,
            0x61, 0xbf, 0xc7, 0x03, 0x10, 0x6f, 0xba, 0xf3, 0xcb, 0x4c, 0xfa, 0x52, 0x38, 0x2d,
            0xd1, 0x6a, 0x39, 0x3e, 0x42, 0x75, 0x75, 0x07, 0x69, 0x80, 0x75, 0xb2, 0xc9, 0x84,
            0xc7, 0x07, 0xf0, 0xa0, 0x81, 0x2d, 0x8c, 0xd5, 0xa6, 0x88, 0x1e, 0xaf, 0x21, 0xce,
            0xda, 0x98, 0xf4, 0xbd, 0x23, 0xf6, 0xfe, 0x1a, 0x3e, 0x2c, 0x43, 0xed, 0xd9, 0xce,
            0x7c, 0xa8, 0x4b, 0xed, 0x85, 0x21, 0xe2, 0xe1, 0x40,
        ];
        assert_eq!(server_packet[..], expected_server_packet[..]);
    }

    #[test]
    fn test_quic_rejects_missing_alpn() {
        //Code taken from rustls with modification
        let client_params = &b"client params"[..];
        let server_params = &b"server params"[..];

        let client_config = Arc::new(make_default_client_config());

        let mut server_config = make_default_server_config();
        server_config.alpn_protocols = vec!["foo".into()];
        let server_config = Arc::new(server_config);

        let mut client = rustls::quic::ClientConnection::new(
            client_config,
            rustls::quic::Version::V1,
            "localhost".try_into().unwrap(),
            client_params.into(),
        )
        .unwrap();
        let mut server = rustls::quic::ServerConnection::new(
            server_config,
            rustls::quic::Version::V1,
            server_params.into(),
        )
        .unwrap();

        assert_eq!(
            step(&mut client, &mut server).err().unwrap(),
            rustls::Error::NoApplicationProtocol
        );

        assert_eq!(
            server.alert(),
            Some(rustls::AlertDescription::NoApplicationProtocol)
        );
    }

    #[test]
    fn test_quic_invalid_early_data_size() {
        //Code taken from rustls with modification
        let mut server_config = make_default_server_config();
        server_config.alpn_protocols = vec!["foo".into()];

        let cases = [
            (None, true),
            (Some(0u32), true),
            (Some(5), false),
            (Some(0xffff_ffff), true),
        ];

        for &(size, ok) in cases.iter() {
            println!("early data size case: {size:?}");
            if let Some(new) = size {
                server_config.max_early_data_size = new;
            }

            let wrapped = Arc::new(server_config.clone());
            assert_eq!(
                rustls::quic::ServerConnection::new(
                    wrapped,
                    rustls::quic::Version::V1,
                    b"server params".to_vec(),
                )
                .is_ok(),
                ok
            );
        }
    }

    #[test]
    fn test_quic_server_no_params_received() {
        //Code taken from rustls with modification

        let server_config = make_default_server_config();
        let server_config = Arc::new(server_config);

        let mut server = rustls::quic::ServerConnection::new(
            server_config,
            rustls::quic::Version::V1,
            b"server params".to_vec(),
        )
        .unwrap();

        //Make a basic client hello
        let ch = make_client_hello();
        assert_eq!(
            server.read_hs(ch.as_slice()).err(),
            Some(Error::PeerMisbehaved(
                rustls::PeerMisbehaved::MissingQuicTransportParameters
            ))
        );
    }

    #[test]
    fn packet_key_api() {
        //Code taken from rustls
        use rustls::quic::{Keys, Version};
        use rustls::Side;

        // Test vectors: https://www.rfc-editor.org/rfc/rfc9001.html#name-client-initial
        const CONNECTION_ID: &[u8] = &[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        const PACKET_NUMBER: u64 = 2;
        const PLAIN_HEADER: &[u8] = &[
            0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
            0x00, 0x00, 0x44, 0x9e, 0x00, 0x00, 0x00, 0x02,
        ];

        const PAYLOAD: &[u8] = &[
            0x06, 0x00, 0x40, 0xf1, 0x01, 0x00, 0x00, 0xed, 0x03, 0x03, 0xeb, 0xf8, 0xfa, 0x56,
            0xf1, 0x29, 0x39, 0xb9, 0x58, 0x4a, 0x38, 0x96, 0x47, 0x2e, 0xc4, 0x0b, 0xb8, 0x63,
            0xcf, 0xd3, 0xe8, 0x68, 0x04, 0xfe, 0x3a, 0x47, 0xf0, 0x6a, 0x2b, 0x69, 0x48, 0x4c,
            0x00, 0x00, 0x04, 0x13, 0x01, 0x13, 0x02, 0x01, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00,
            0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
            0x63, 0x6f, 0x6d, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06,
            0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x10, 0x00, 0x07, 0x00, 0x05, 0x04, 0x61,
            0x6c, 0x70, 0x6e, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33,
            0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x93, 0x70, 0xb2, 0xc9, 0xca, 0xa4,
            0x7f, 0xba, 0xba, 0xf4, 0x55, 0x9f, 0xed, 0xba, 0x75, 0x3d, 0xe1, 0x71, 0xfa, 0x71,
            0xf5, 0x0f, 0x1c, 0xe1, 0x5d, 0x43, 0xe9, 0x94, 0xec, 0x74, 0xd7, 0x48, 0x00, 0x2b,
            0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x0d, 0x00, 0x10, 0x00, 0x0e, 0x04, 0x03, 0x05,
            0x03, 0x06, 0x03, 0x02, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x00, 0x2d, 0x00,
            0x02, 0x01, 0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01, 0x00, 0x39, 0x00, 0x32, 0x04,
            0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x05, 0x04, 0x80, 0x00, 0xff,
            0xff, 0x07, 0x04, 0x80, 0x00, 0xff, 0xff, 0x08, 0x01, 0x10, 0x01, 0x04, 0x80, 0x00,
            0x75, 0x30, 0x09, 0x01, 0x10, 0x0f, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57,
            0x08, 0x06, 0x04, 0x80, 0x00, 0xff, 0xff,
        ];

        let client_keys = Keys::initial(
            Version::V1,
            TLS13_AES_128_GCM_SHA256.tls13().unwrap(),
            TLS13_AES_128_GCM_SHA256.tls13().unwrap().quic.unwrap(),
            CONNECTION_ID,
            Side::Client,
        );
        assert_eq!(client_keys.local.packet.tag_len(), 16);

        let mut buf = Vec::new();
        buf.extend(PLAIN_HEADER);
        buf.extend(PAYLOAD);
        let header_len = PLAIN_HEADER.len();
        let tag_len = client_keys.local.packet.tag_len();
        let padding_len = 1200 - header_len - PAYLOAD.len() - tag_len;
        buf.extend(std::iter::repeat(0).take(padding_len));
        let (header, payload) = buf.split_at_mut(header_len);
        let tag = client_keys
            .local
            .packet
            .encrypt_in_place(PACKET_NUMBER, header, payload)
            .unwrap();

        let sample_len = client_keys.local.header.sample_len();
        let sample = &payload[..sample_len];
        let (first, rest) = header.split_at_mut(1);
        client_keys
            .local
            .header
            .encrypt_in_place(sample, &mut first[0], &mut rest[17..21])
            .unwrap();
        buf.extend_from_slice(tag.as_ref());

        const PROTECTED: &[u8] = &[
            0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
            0x00, 0x00, 0x44, 0x9e, 0x7b, 0x9a, 0xec, 0x34, 0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68,
            0x9f, 0xb8, 0xec, 0x11, 0xd2, 0x42, 0xb1, 0x23, 0xdc, 0x9b, 0xd8, 0xba, 0xb9, 0x36,
            0xb4, 0x7d, 0x92, 0xec, 0x35, 0x6c, 0x0b, 0xab, 0x7d, 0xf5, 0x97, 0x6d, 0x27, 0xcd,
            0x44, 0x9f, 0x63, 0x30, 0x00, 0x99, 0xf3, 0x99, 0x1c, 0x26, 0x0e, 0xc4, 0xc6, 0x0d,
            0x17, 0xb3, 0x1f, 0x84, 0x29, 0x15, 0x7b, 0xb3, 0x5a, 0x12, 0x82, 0xa6, 0x43, 0xa8,
            0xd2, 0x26, 0x2c, 0xad, 0x67, 0x50, 0x0c, 0xad, 0xb8, 0xe7, 0x37, 0x8c, 0x8e, 0xb7,
            0x53, 0x9e, 0xc4, 0xd4, 0x90, 0x5f, 0xed, 0x1b, 0xee, 0x1f, 0xc8, 0xaa, 0xfb, 0xa1,
            0x7c, 0x75, 0x0e, 0x2c, 0x7a, 0xce, 0x01, 0xe6, 0x00, 0x5f, 0x80, 0xfc, 0xb7, 0xdf,
            0x62, 0x12, 0x30, 0xc8, 0x37, 0x11, 0xb3, 0x93, 0x43, 0xfa, 0x02, 0x8c, 0xea, 0x7f,
            0x7f, 0xb5, 0xff, 0x89, 0xea, 0xc2, 0x30, 0x82, 0x49, 0xa0, 0x22, 0x52, 0x15, 0x5e,
            0x23, 0x47, 0xb6, 0x3d, 0x58, 0xc5, 0x45, 0x7a, 0xfd, 0x84, 0xd0, 0x5d, 0xff, 0xfd,
            0xb2, 0x03, 0x92, 0x84, 0x4a, 0xe8, 0x12, 0x15, 0x46, 0x82, 0xe9, 0xcf, 0x01, 0x2f,
            0x90, 0x21, 0xa6, 0xf0, 0xbe, 0x17, 0xdd, 0xd0, 0xc2, 0x08, 0x4d, 0xce, 0x25, 0xff,
            0x9b, 0x06, 0xcd, 0xe5, 0x35, 0xd0, 0xf9, 0x20, 0xa2, 0xdb, 0x1b, 0xf3, 0x62, 0xc2,
            0x3e, 0x59, 0x6d, 0x11, 0xa4, 0xf5, 0xa6, 0xcf, 0x39, 0x48, 0x83, 0x8a, 0x3a, 0xec,
            0x4e, 0x15, 0xda, 0xf8, 0x50, 0x0a, 0x6e, 0xf6, 0x9e, 0xc4, 0xe3, 0xfe, 0xb6, 0xb1,
            0xd9, 0x8e, 0x61, 0x0a, 0xc8, 0xb7, 0xec, 0x3f, 0xaf, 0x6a, 0xd7, 0x60, 0xb7, 0xba,
            0xd1, 0xdb, 0x4b, 0xa3, 0x48, 0x5e, 0x8a, 0x94, 0xdc, 0x25, 0x0a, 0xe3, 0xfd, 0xb4,
            0x1e, 0xd1, 0x5f, 0xb6, 0xa8, 0xe5, 0xeb, 0xa0, 0xfc, 0x3d, 0xd6, 0x0b, 0xc8, 0xe3,
            0x0c, 0x5c, 0x42, 0x87, 0xe5, 0x38, 0x05, 0xdb, 0x05, 0x9a, 0xe0, 0x64, 0x8d, 0xb2,
            0xf6, 0x42, 0x64, 0xed, 0x5e, 0x39, 0xbe, 0x2e, 0x20, 0xd8, 0x2d, 0xf5, 0x66, 0xda,
            0x8d, 0xd5, 0x99, 0x8c, 0xca, 0xbd, 0xae, 0x05, 0x30, 0x60, 0xae, 0x6c, 0x7b, 0x43,
            0x78, 0xe8, 0x46, 0xd2, 0x9f, 0x37, 0xed, 0x7b, 0x4e, 0xa9, 0xec, 0x5d, 0x82, 0xe7,
            0x96, 0x1b, 0x7f, 0x25, 0xa9, 0x32, 0x38, 0x51, 0xf6, 0x81, 0xd5, 0x82, 0x36, 0x3a,
            0xa5, 0xf8, 0x99, 0x37, 0xf5, 0xa6, 0x72, 0x58, 0xbf, 0x63, 0xad, 0x6f, 0x1a, 0x0b,
            0x1d, 0x96, 0xdb, 0xd4, 0xfa, 0xdd, 0xfc, 0xef, 0xc5, 0x26, 0x6b, 0xa6, 0x61, 0x17,
            0x22, 0x39, 0x5c, 0x90, 0x65, 0x56, 0xbe, 0x52, 0xaf, 0xe3, 0xf5, 0x65, 0x63, 0x6a,
            0xd1, 0xb1, 0x7d, 0x50, 0x8b, 0x73, 0xd8, 0x74, 0x3e, 0xeb, 0x52, 0x4b, 0xe2, 0x2b,
            0x3d, 0xcb, 0xc2, 0xc7, 0x46, 0x8d, 0x54, 0x11, 0x9c, 0x74, 0x68, 0x44, 0x9a, 0x13,
            0xd8, 0xe3, 0xb9, 0x58, 0x11, 0xa1, 0x98, 0xf3, 0x49, 0x1d, 0xe3, 0xe7, 0xfe, 0x94,
            0x2b, 0x33, 0x04, 0x07, 0xab, 0xf8, 0x2a, 0x4e, 0xd7, 0xc1, 0xb3, 0x11, 0x66, 0x3a,
            0xc6, 0x98, 0x90, 0xf4, 0x15, 0x70, 0x15, 0x85, 0x3d, 0x91, 0xe9, 0x23, 0x03, 0x7c,
            0x22, 0x7a, 0x33, 0xcd, 0xd5, 0xec, 0x28, 0x1c, 0xa3, 0xf7, 0x9c, 0x44, 0x54, 0x6b,
            0x9d, 0x90, 0xca, 0x00, 0xf0, 0x64, 0xc9, 0x9e, 0x3d, 0xd9, 0x79, 0x11, 0xd3, 0x9f,
            0xe9, 0xc5, 0xd0, 0xb2, 0x3a, 0x22, 0x9a, 0x23, 0x4c, 0xb3, 0x61, 0x86, 0xc4, 0x81,
            0x9e, 0x8b, 0x9c, 0x59, 0x27, 0x72, 0x66, 0x32, 0x29, 0x1d, 0x6a, 0x41, 0x82, 0x11,
            0xcc, 0x29, 0x62, 0xe2, 0x0f, 0xe4, 0x7f, 0xeb, 0x3e, 0xdf, 0x33, 0x0f, 0x2c, 0x60,
            0x3a, 0x9d, 0x48, 0xc0, 0xfc, 0xb5, 0x69, 0x9d, 0xbf, 0xe5, 0x89, 0x64, 0x25, 0xc5,
            0xba, 0xc4, 0xae, 0xe8, 0x2e, 0x57, 0xa8, 0x5a, 0xaf, 0x4e, 0x25, 0x13, 0xe4, 0xf0,
            0x57, 0x96, 0xb0, 0x7b, 0xa2, 0xee, 0x47, 0xd8, 0x05, 0x06, 0xf8, 0xd2, 0xc2, 0x5e,
            0x50, 0xfd, 0x14, 0xde, 0x71, 0xe6, 0xc4, 0x18, 0x55, 0x93, 0x02, 0xf9, 0x39, 0xb0,
            0xe1, 0xab, 0xd5, 0x76, 0xf2, 0x79, 0xc4, 0xb2, 0xe0, 0xfe, 0xb8, 0x5c, 0x1f, 0x28,
            0xff, 0x18, 0xf5, 0x88, 0x91, 0xff, 0xef, 0x13, 0x2e, 0xef, 0x2f, 0xa0, 0x93, 0x46,
            0xae, 0xe3, 0x3c, 0x28, 0xeb, 0x13, 0x0f, 0xf2, 0x8f, 0x5b, 0x76, 0x69, 0x53, 0x33,
            0x41, 0x13, 0x21, 0x19, 0x96, 0xd2, 0x00, 0x11, 0xa1, 0x98, 0xe3, 0xfc, 0x43, 0x3f,
            0x9f, 0x25, 0x41, 0x01, 0x0a, 0xe1, 0x7c, 0x1b, 0xf2, 0x02, 0x58, 0x0f, 0x60, 0x47,
            0x47, 0x2f, 0xb3, 0x68, 0x57, 0xfe, 0x84, 0x3b, 0x19, 0xf5, 0x98, 0x40, 0x09, 0xdd,
            0xc3, 0x24, 0x04, 0x4e, 0x84, 0x7a, 0x4f, 0x4a, 0x0a, 0xb3, 0x4f, 0x71, 0x95, 0x95,
            0xde, 0x37, 0x25, 0x2d, 0x62, 0x35, 0x36, 0x5e, 0x9b, 0x84, 0x39, 0x2b, 0x06, 0x10,
            0x85, 0x34, 0x9d, 0x73, 0x20, 0x3a, 0x4a, 0x13, 0xe9, 0x6f, 0x54, 0x32, 0xec, 0x0f,
            0xd4, 0xa1, 0xee, 0x65, 0xac, 0xcd, 0xd5, 0xe3, 0x90, 0x4d, 0xf5, 0x4c, 0x1d, 0xa5,
            0x10, 0xb0, 0xff, 0x20, 0xdc, 0xc0, 0xc7, 0x7f, 0xcb, 0x2c, 0x0e, 0x0e, 0xb6, 0x05,
            0xcb, 0x05, 0x04, 0xdb, 0x87, 0x63, 0x2c, 0xf3, 0xd8, 0xb4, 0xda, 0xe6, 0xe7, 0x05,
            0x76, 0x9d, 0x1d, 0xe3, 0x54, 0x27, 0x01, 0x23, 0xcb, 0x11, 0x45, 0x0e, 0xfc, 0x60,
            0xac, 0x47, 0x68, 0x3d, 0x7b, 0x8d, 0x0f, 0x81, 0x13, 0x65, 0x56, 0x5f, 0xd9, 0x8c,
            0x4c, 0x8e, 0xb9, 0x36, 0xbc, 0xab, 0x8d, 0x06, 0x9f, 0xc3, 0x3b, 0xd8, 0x01, 0xb0,
            0x3a, 0xde, 0xa2, 0xe1, 0xfb, 0xc5, 0xaa, 0x46, 0x3d, 0x08, 0xca, 0x19, 0x89, 0x6d,
            0x2b, 0xf5, 0x9a, 0x07, 0x1b, 0x85, 0x1e, 0x6c, 0x23, 0x90, 0x52, 0x17, 0x2f, 0x29,
            0x6b, 0xfb, 0x5e, 0x72, 0x40, 0x47, 0x90, 0xa2, 0x18, 0x10, 0x14, 0xf3, 0xb9, 0x4a,
            0x4e, 0x97, 0xd1, 0x17, 0xb4, 0x38, 0x13, 0x03, 0x68, 0xcc, 0x39, 0xdb, 0xb2, 0xd1,
            0x98, 0x06, 0x5a, 0xe3, 0x98, 0x65, 0x47, 0x92, 0x6c, 0xd2, 0x16, 0x2f, 0x40, 0xa2,
            0x9f, 0x0c, 0x3c, 0x87, 0x45, 0xc0, 0xf5, 0x0f, 0xba, 0x38, 0x52, 0xe5, 0x66, 0xd4,
            0x45, 0x75, 0xc2, 0x9d, 0x39, 0xa0, 0x3f, 0x0c, 0xda, 0x72, 0x19, 0x84, 0xb6, 0xf4,
            0x40, 0x59, 0x1f, 0x35, 0x5e, 0x12, 0xd4, 0x39, 0xff, 0x15, 0x0a, 0xab, 0x76, 0x13,
            0x49, 0x9d, 0xbd, 0x49, 0xad, 0xab, 0xc8, 0x67, 0x6e, 0xef, 0x02, 0x3b, 0x15, 0xb6,
            0x5b, 0xfc, 0x5c, 0xa0, 0x69, 0x48, 0x10, 0x9f, 0x23, 0xf3, 0x50, 0xdb, 0x82, 0x12,
            0x35, 0x35, 0xeb, 0x8a, 0x74, 0x33, 0xbd, 0xab, 0xcb, 0x90, 0x92, 0x71, 0xa6, 0xec,
            0xbc, 0xb5, 0x8b, 0x93, 0x6a, 0x88, 0xcd, 0x4e, 0x8f, 0x2e, 0x6f, 0xf5, 0x80, 0x01,
            0x75, 0xf1, 0x13, 0x25, 0x3d, 0x8f, 0xa9, 0xca, 0x88, 0x85, 0xc2, 0xf5, 0x52, 0xe6,
            0x57, 0xdc, 0x60, 0x3f, 0x25, 0x2e, 0x1a, 0x8e, 0x30, 0x8f, 0x76, 0xf0, 0xbe, 0x79,
            0xe2, 0xfb, 0x8f, 0x5d, 0x5f, 0xbb, 0xe2, 0xe3, 0x0e, 0xca, 0xdd, 0x22, 0x07, 0x23,
            0xc8, 0xc0, 0xae, 0xa8, 0x07, 0x8c, 0xdf, 0xcb, 0x38, 0x68, 0x26, 0x3f, 0xf8, 0xf0,
            0x94, 0x00, 0x54, 0xda, 0x48, 0x78, 0x18, 0x93, 0xa7, 0xe4, 0x9a, 0xd5, 0xaf, 0xf4,
            0xaf, 0x30, 0x0c, 0xd8, 0x04, 0xa6, 0xb6, 0x27, 0x9a, 0xb3, 0xff, 0x3a, 0xfb, 0x64,
            0x49, 0x1c, 0x85, 0x19, 0x4a, 0xab, 0x76, 0x0d, 0x58, 0xa6, 0x06, 0x65, 0x4f, 0x9f,
            0x44, 0x00, 0xe8, 0xb3, 0x85, 0x91, 0x35, 0x6f, 0xbf, 0x64, 0x25, 0xac, 0xa2, 0x6d,
            0xc8, 0x52, 0x44, 0x25, 0x9f, 0xf2, 0xb1, 0x9c, 0x41, 0xb9, 0xf9, 0x6f, 0x3c, 0xa9,
            0xec, 0x1d, 0xde, 0x43, 0x4d, 0xa7, 0xd2, 0xd3, 0x92, 0xb9, 0x05, 0xdd, 0xf3, 0xd1,
            0xf9, 0xaf, 0x93, 0xd1, 0xaf, 0x59, 0x50, 0xbd, 0x49, 0x3f, 0x5a, 0xa7, 0x31, 0xb4,
            0x05, 0x6d, 0xf3, 0x1b, 0xd2, 0x67, 0xb6, 0xb9, 0x0a, 0x07, 0x98, 0x31, 0xaa, 0xf5,
            0x79, 0xbe, 0x0a, 0x39, 0x01, 0x31, 0x37, 0xaa, 0xc6, 0xd4, 0x04, 0xf5, 0x18, 0xcf,
            0xd4, 0x68, 0x40, 0x64, 0x7e, 0x78, 0xbf, 0xe7, 0x06, 0xca, 0x4c, 0xf5, 0xe9, 0xc5,
            0x45, 0x3e, 0x9f, 0x7c, 0xfd, 0x2b, 0x8b, 0x4c, 0x8d, 0x16, 0x9a, 0x44, 0xe5, 0x5c,
            0x88, 0xd4, 0xa9, 0xa7, 0xf9, 0x47, 0x42, 0x41, 0xe2, 0x21, 0xaf, 0x44, 0x86, 0x00,
            0x18, 0xab, 0x08, 0x56, 0x97, 0x2e, 0x19, 0x4c, 0xd9, 0x34,
        ];

        assert_eq!(&buf, PROTECTED);

        let (header, payload) = buf.split_at_mut(header_len);
        let (first, rest) = header.split_at_mut(1);
        let sample = &payload[..sample_len];

        let server_keys = Keys::initial(
            Version::V1,
            TLS13_AES_128_GCM_SHA256.tls13().unwrap(),
            TLS13_AES_128_GCM_SHA256.tls13().unwrap().quic.unwrap(),
            CONNECTION_ID,
            Side::Server,
        );
        server_keys
            .remote
            .header
            .decrypt_in_place(sample, &mut first[0], &mut rest[17..21])
            .unwrap();
        let payload = server_keys
            .remote
            .packet
            .decrypt_in_place(PACKET_NUMBER, header, payload)
            .unwrap();

        assert_eq!(&payload[..PAYLOAD.len()], PAYLOAD);
        assert_eq!(payload.len(), buf.len() - header_len - tag_len);
    }

    #[test]
    fn test_aes_mask_generation() {
        //Test idea taken from ring
        // Copyright 2018 Brian Smith.
        let vectors = [
            AesTestVector::Aes128 {
                key: hex!("e8904ecc2e37a6e4cc02271e319c804b"),
                sample: hex!("13484ec85dc4d36349697c7d4ea1a159"),
                mask: hex!("67387ebf3a"),
            },
            AesTestVector::Aes128 {
                key: hex!("e8904ecc2e37a6e4cc02271e319c804b"),
                sample: hex!("00000000000000000000000fffffffff"),
                mask: hex!("feb191f8af"),
            },
            AesTestVector::Aes128 {
                key: hex!("e8904ecc2e37a6e4cc02271e319c804b"),
                sample: hex!("000000000000000fffffffffffffffff"),
                mask: hex!("6f23441ee8"),
            },
            AesTestVector::Aes256 {
                key: hex!("85af7213814aec7b92ace6284a906643912ec8853d00d158a927b8697c7ff585"),
                sample: hex!("82a0db90f4cee12fa4afeddb74396cf6"),
                mask: hex!("670897adf5"),
            },
            AesTestVector::Aes256 {
                key: hex!("85af7213814aec7b92ace6284a906643912ec8853d00d158a927b8697c7ff585"),
                sample: hex!("000000000000000000000000ffffffff"),
                mask: hex!("b77a18bb3f"),
            },
            AesTestVector::Aes256 {
                key: hex!("85af7213814aec7b92ace6284a906643912ec8853d00d158a927b8697c7ff585"),
                sample: hex!("000000000000000fffffffffffffffff"),
                mask: hex!("4aadd3cbef"),
            },
        ];

        let mut aes_cipher = crate::aead::quic::AesCipher::new().unwrap();
        let mut mask = [0u8; 5];

        for v in &vectors {
            let (v_key, v_sample, v_mask): (&[u8], &[u8], &[u8]) = match v {
                AesTestVector::Aes128 { key, sample, mask } => {
                    (key.as_slice(), sample.as_slice(), mask.as_slice())
                }
                AesTestVector::Aes256 { key, sample, mask } => {
                    (key.as_slice(), sample.as_slice(), mask.as_slice())
                }
            };
            let _ = aes_cipher.set_key(v_key);
            mask.copy_from_slice(&aes_cipher.encrypt_sample(v_sample).unwrap()[..5]);
            assert_eq!(v_mask, mask)
        }
    }

    #[test]
    fn test_chacha_mask_generation() {
        //Test idea taken from ring
        // Copyright 2018 Brian Smith.

        let test_vector = ChaCha20TestVector {
            key: hex!("59bdff7a5bcdaacf319d99646c6273ad96687d2c74ace678f15a1c710675bb23"),
            sample: hex!("215a7c1688b4ab7d830dcd052aef9f3c"),
            mask: hex!("6409a6196d"),
        };

        let mut chacha_cipher = crate::aead::quic::ChaChaCipher::new(None).unwrap();
        let mut mask = mask_array!();

        let _ = chacha_cipher.set_key(&test_vector.key);
        mask.copy_from_slice(&chacha_cipher.encrypt_sample(&test_vector.sample).unwrap()[..5]);
        assert_eq!(test_vector.mask, mask)
    }

    #[test]
    fn test_sample_len() {
        let hp_algs: Vec<&aead::quic::HPAlgorithm> = vec![
            &aead::quic::AES_128,
            &aead::quic::AES_256,
            &aead::quic::CHACHA20,
        ];
        let mut first = vec![0u8; 1];
        let mut packet_number = vec![0u8; 4];
        for alg in hp_algs {
            let key_len = alg.key_len();
            let key_data = vec![0u8; key_len];

            let key = aead::quic::HeaderProtectionKey::new(key_data, alg).unwrap();

            let sample_len = 16;
            let sample_data = vec![0u8; sample_len + 2];

            // Sample is the right size.
            assert!(key
                .encrypt_in_place(
                    &sample_data[..sample_len],
                    &mut first[0],
                    packet_number.as_mut_slice()
                )
                .is_ok());

            // Sample is one byte too small.
            assert!(key
                .encrypt_in_place(
                    &sample_data[..(sample_len - 1)],
                    &mut first[0],
                    packet_number.as_mut_slice()
                )
                .is_err());

            // Sample is one byte too big.
            assert!(key
                .encrypt_in_place(
                    &sample_data[..(sample_len + 1)],
                    &mut first[0],
                    packet_number.as_mut_slice()
                )
                .is_err());

            // Sample is empty.
            assert!(key
                .encrypt_in_place(&[], &mut first[0], packet_number.as_mut_slice())
                .is_err());
        }
    }

    #[test]
    fn test_key_len() {
        let hp_algs: Vec<&aead::quic::HPAlgorithm> = vec![
            &aead::quic::AES_128,
            &aead::quic::AES_256,
            &aead::quic::CHACHA20,
        ];
        for alg in hp_algs {
            let key_len = alg.key_len();
            let key_data = vec![0u8; key_len + 5];

            // Key is the right size.
            assert!(
                aead::quic::HeaderProtectionKey::new(key_data[..key_len].to_vec(), alg).is_ok()
            );

            // Key is one byte too small.
            assert!(
                aead::quic::HeaderProtectionKey::new(key_data[..key_len - 1].to_vec(), alg)
                    .is_err()
            );

            // Key is one byte too big.
            assert!(
                aead::quic::HeaderProtectionKey::new(key_data[..key_len + 1].to_vec(), alg)
                    .is_err()
            );

            // Key is empty.
            assert!(aead::quic::HeaderProtectionKey::new(Vec::new(), alg).is_err());
        }
    }
}
