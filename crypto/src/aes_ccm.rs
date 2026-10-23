//! AES-128-CCM for 802.11 CCMP: 13-byte nonce, 8-byte tag, L=2.
//! Formatting and authentication follow RFC 3610 §2.1–2.6 directly:
//! <https://www.rfc-editor.org/rfc/rfc3610.html#section-2>.
//! AES uses the existing RustCrypto backend; this module adds no block cipher.
//! Callers own nonce uniqueness and commit replay state only after open succeeds.

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub const NONCE_LEN: usize = 13;
pub const TAG_LEN: usize = 8;
pub const MAX_MESSAGE_LEN: usize = u16::MAX as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Length,
    Authentication,
}

/// Seal in place and return the detached tag. A nonce must never be reused
/// with the same key; callers must refuse 48-bit CCMP PN exhaustion.
pub fn seal(
    key: &[u8; 16],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    body: &mut [u8],
) -> Result<[u8; TAG_LEN], Error> {
    validate(body.len())?;
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let tag = authenticate(&cipher, nonce, aad, body);
    crypt(&cipher, nonce, body);
    Ok(tag)
}

/// Authenticate and open, committing plaintext only after MIC verification.
/// Every error leaves caller ciphertext unchanged; temporary plaintext is
/// zeroized on either path. Replay/PN state remains entirely caller-owned.
pub fn open(
    key: &[u8; 16],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    body: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), Error> {
    validate(body.len())?;
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut plaintext = Zeroizing::new(body.to_vec());
    crypt(&cipher, nonce, &mut plaintext);
    let expected = Zeroizing::new(authenticate(&cipher, nonce, aad, &plaintext));
    if !bool::from(expected.as_slice().ct_eq(tag)) {
        return Err(Error::Authentication);
    }
    body.copy_from_slice(&plaintext);
    Ok(())
}
fn validate(length: usize) -> Result<(), Error> {
    if length > MAX_MESSAGE_LEN {
        Err(Error::Length)
    } else {
        Ok(())
    }
}

struct Mac<'a> {
    cipher: &'a Aes128,
    state: Zeroizing<[u8; 16]>,
    block: Zeroizing<[u8; 16]>,
    used: usize,
}
impl<'a> Mac<'a> {
    fn new(cipher: &'a Aes128) -> Self {
        Self {
            cipher,
            state: Zeroizing::new([0; 16]),
            block: Zeroizing::new([0; 16]),
            used: 0,
        }
    }
    fn update(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.block[self.used] = byte;
            self.used += 1;
            if self.used == 16 {
                self.pad();
            }
        }
    }
    /// AAD and payload are padded independently. An aligned/empty input
    /// contributes no extra all-zero block (RFC 3610 §2.2).
    fn pad(&mut self) {
        if self.used == 0 {
            return;
        }
        for (state, block) in self.state.iter_mut().zip(self.block.iter()) {
            *state ^= *block;
        }
        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(&mut *self.state));
        self.block.zeroize();
        self.used = 0;
    }
}
fn authenticate(cipher: &Aes128, nonce: &[u8; 13], aad: &[u8], body: &[u8]) -> [u8; 8] {
    let mut first = [0u8; 16];
    first[0] = 0x19 | if aad.is_empty() { 0 } else { 0x40 }; // M'=3, L'=1.
    first[1..14].copy_from_slice(nonce);
    first[14..].copy_from_slice(&(body.len() as u16).to_be_bytes());
    let mut mac = Mac::new(cipher);
    mac.update(&first);
    if !aad.is_empty() {
        // RFC 3610 §2.2 encodes each associated-data length unambiguously.
        if aad.len() < 0xff00 {
            mac.update(&(aad.len() as u16).to_be_bytes());
        } else if aad.len() <= u32::MAX as usize {
            mac.update(&[0xff, 0xfe]);
            mac.update(&(aad.len() as u32).to_be_bytes());
        } else {
            mac.update(&[0xff, 0xff]);
            mac.update(&(aad.len() as u64).to_be_bytes());
        }
        mac.update(aad);
        mac.pad();
    }
    mac.update(body);
    mac.pad();
    let stream = counter(cipher, nonce, 0);
    let mut tag = [0u8; 8];
    for ((out, state), stream) in tag.iter_mut().zip(mac.state.iter()).zip(stream.iter()) {
        *out = *state ^ *stream;
    }
    tag
}
fn counter(cipher: &Aes128, nonce: &[u8; 13], index: u16) -> Zeroizing<[u8; 16]> {
    let mut block = Zeroizing::new([0u8; 16]);
    block[0] = 1; // L'=1, all reserved/tag/Adata bits clear.
    block[1..14].copy_from_slice(nonce);
    block[14..].copy_from_slice(&index.to_be_bytes());
    cipher.encrypt_block(GenericArray::from_mut_slice(&mut *block));
    block
}
fn crypt(cipher: &Aes128, nonce: &[u8; 13], bytes: &mut [u8]) {
    // MAX_MESSAGE_LEN bounds this to 4096 blocks; the counter cannot wrap.
    for (index, chunk) in bytes.chunks_mut(16).enumerate() {
        let stream = counter(cipher, nonce, (index + 1) as u16);
        for (byte, key) in chunk.iter_mut().zip(stream.iter()) {
            *byte ^= *key;
        }
    }
}

#[path = "aes_ccm_tests.rs"]
mod tests;
