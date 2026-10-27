//! The suspend image format (power-suspend design §3.3) and the
//! storage surface it is written to.
//!
//! Layout on the pre-configured suspend partition (all integers
//! little-endian):
//!
//! ```text
//! [ header page ]  preamble (plaintext claims) + AEAD-sealed body
//! [ manifest ]     per-chunk AEAD tags, in chunk order
//! [ hook region ]  hook blob directory + blobs (P2; length 0 here)
//! [ image chunks ] bulk image, AEAD per chunk, chunk index as AAD
//! ```
//!
//! The header page holds two regions with different trust levels,
//! per design §6.2's trust order. The *preamble* is plaintext —
//! magic, format version, image id, SMS epoch, the recorded policy,
//! the slot records for the image's SMS epoch, and the wrapped SMK —
//! and is treated as an untrusted *claim*: the resume side uses it to
//! select factors and unwrap, nothing more. The *sealed body* —
//! chunk count, image length, hook region length, and the manifest
//! root — is ChaCha20-Poly1305-sealed under the manifest key with the
//! entire preamble as AAD. A tampered preamble byte (a flipped
//! policy byte above all) therefore fails the header seal wholesale,
//! and no field from the preamble is trusted until it verifies.
//!
//! Chunk keys derive from the per-image SMK (design §3.1):
//! `image_key = HKDF(SMK, "narf-suspend/image")` and
//! `manifest_key = HKDF(SMK, "narf-suspend/manifest")`. Each chunk is
//! sealed with nonce `0u32 ‖ chunk_index` (the image key is unique
//! per image, so index nonces never repeat under a key) and AAD
//! `image_id ‖ chunk_index`, binding every chunk to its image and
//! its position. The manifest root is a SHA-256 Merkle root over the
//! chunk tags (leaf = `SHA256(tag)`, pair = `SHA256(l ‖ r)`, odd leaf
//! duplicated), binding the whole tag set into the sealed header.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use narf_block::{BlockDeviceSync, BlockIoError};
use narf_crypto::sha256::Sha256;

use super::slots::SlotRecord;
use super::ServiceError;

/// Page size of the format's fixed regions.
pub const PAGE_LEN: u64 = 4096;
/// Plaintext bytes per image chunk (design §3.3: AEAD per 1 MiB).
pub const CHUNK_LEN: u64 = 1024 * 1024;
/// Image header magic.
pub const IMAGE_MAGIC: &[u8; 8] = b"NARFSUS1";
/// Format version written and required by this implementation.
pub const FORMAT_VERSION: u32 = 1;
/// AEAD tag length of the ChaCha20-Poly1305 construction.
pub const TAG_LEN: usize = 16;
/// Wrapped-SMK blob length: 32 bytes ciphertext + 16 bytes tag.
pub const WRAPPED_SMK_LEN: usize = 48;
/// Sealed header body plaintext length (see `SealedBody`).
pub const SEALED_BODY_LEN: usize = 56;
/// Sealed header body stored length: plaintext + tag, at the end of
/// the header page.
pub const SEALED_BODY_STORED: u64 = (SEALED_BODY_LEN + TAG_LEN) as u64;

/// The policy levels of design §10.1, as recorded in an image. This
/// lane defines the *record* and its integrity; the policy engine
/// that selects levels and administers floors is P8 (#1006).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PolicyLevel {
    Off,
    Passphrase,
    Token,
    TokenTpm,
    Tpm,
}

impl PolicyLevel {
    /// Stable on-disk code in the header preamble.
    pub fn code(self) -> u8 {
        match self {
            PolicyLevel::Off => 0,
            PolicyLevel::Passphrase => 1,
            PolicyLevel::Token => 2,
            PolicyLevel::TokenTpm => 3,
            PolicyLevel::Tpm => 4,
        }
    }

    /// Decode a policy-level code. Unknown codes are rejected: an
    /// image claiming a policy this build cannot name must not be
    /// resumed under a guessed weaker reading.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(PolicyLevel::Off),
            1 => Some(PolicyLevel::Passphrase),
            2 => Some(PolicyLevel::Token),
            3 => Some(PolicyLevel::TokenTpm),
            4 => Some(PolicyLevel::Tpm),
            _ => None,
        }
    }
}

/// The governing policy recorded in an image's authenticated header
/// (design §10.3): the level in force when the image was written and
/// the policy epoch it was set under. Resume enforces *this* record,
/// never the machine's current configuration.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RecordedPolicy {
    pub level: PolicyLevel,
    pub policy_epoch: u64,
}

/// The untrusted header claims, parsed from the preamble. Nothing in
/// here is believed until [`super::image::OpenedImage`] verifies the
/// header seal; the type exists so the factor interaction can be
/// driven from the claims first (design §6.2 steps 2–4).
#[derive(Clone)]
pub struct ImageClaims {
    pub image_id: [u8; 16],
    pub sms_epoch: u64,
    pub policy: RecordedPolicy,
    pub slots: Vec<SlotRecord>,
    pub(crate) smk_wrap_nonce: [u8; 12],
    pub(crate) smk_wrap: [u8; WRAPPED_SMK_LEN],
    pub(crate) preamble: Vec<u8>,
}

impl fmt::Debug for ImageClaims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImageClaims")
            .field("sms_epoch", &self.sms_epoch)
            .field("policy", &self.policy)
            .field("slots", &self.slots.len())
            .field("preamble_len", &self.preamble.len())
            .finish_non_exhaustive()
    }
}

/// The header's sealed body, once verified: the facts about the
/// image that only the holder of the manifest key could have sealed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct SealedBody {
    pub chunk_count: u64,
    pub image_len: u64,
    pub hook_region_len: u64,
    pub manifest_root: [u8; 32],
}

/// Byte offset of the manifest for an image.
pub(crate) fn manifest_offset() -> u64 {
    PAGE_LEN
}

/// Byte offset of the hook region for an image with `chunk_count`
/// chunks.
pub(crate) fn hook_offset(chunk_count: u64) -> u64 {
    let manifest_bytes = chunk_count * TAG_LEN as u64;
    manifest_offset() + manifest_bytes.div_ceil(PAGE_LEN) * PAGE_LEN
}

/// Byte offset of chunk `index`'s ciphertext.
pub(crate) fn chunk_offset(chunk_count: u64, hook_region_len: u64, index: u64) -> u64 {
    hook_offset(chunk_count) + hook_region_len + index * CHUNK_LEN
}

/// Total partition bytes an image of `image_len` plaintext bytes
/// occupies (header + manifest + hook region + chunk ciphertext).
pub(crate) fn image_total_len(image_len: u64, hook_region_len: u64) -> u64 {
    let chunk_count = image_len.div_ceil(CHUNK_LEN);
    hook_offset(chunk_count) + hook_region_len + image_len
}

/// Header-seal nonce: the image id's first 12 bytes. The manifest
/// key is unique per image, and the image id is random per image, so
/// this nonce never repeats under a key.
pub(crate) fn header_nonce(image_id: &[u8; 16]) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&image_id[..12]);
    nonce
}

/// Chunk nonce: zero-extended chunk index (see the module docs for
/// why index nonces are safe here).
pub(crate) fn chunk_nonce(index: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&index.to_le_bytes());
    nonce
}

/// Chunk AAD: `image_id ‖ chunk_index`, binding the chunk to its
/// image and position.
pub(crate) fn chunk_aad(image_id: &[u8; 16], index: u64) -> [u8; 24] {
    let mut aad = [0u8; 24];
    aad[..16].copy_from_slice(image_id);
    aad[16..].copy_from_slice(&index.to_le_bytes());
    aad
}

/// AAD for the SMK wrap: `image_id ‖ sms_epoch ‖ policy_level`,
/// binding the wrapped per-image key to the image it belongs to, the
/// epoch it was wrapped under, and the policy the header claims.
pub(crate) fn smk_wrap_aad(image_id: &[u8; 16], sms_epoch: u64, level: PolicyLevel) -> Vec<u8> {
    let mut aad = Vec::with_capacity(25);
    aad.extend_from_slice(image_id);
    aad.extend_from_slice(&sms_epoch.to_le_bytes());
    aad.push(level.code());
    aad
}

/// SHA-256 Merkle root over the chunk tags (see the module docs for
/// the exact construction). An empty tag set hashes the empty input.
pub(crate) fn manifest_root(tags: &[[u8; TAG_LEN]]) -> [u8; 32] {
    if tags.is_empty() {
        let mut h = Sha256::new();
        h.update(&[]);
        return h.finalize();
    }
    let mut level: Vec<[u8; 32]> = tags
        .iter()
        .map(|tag| {
            let mut h = Sha256::new();
            h.update(tag);
            h.finalize()
        })
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = if pair.len() == 2 { pair[1] } else { pair[0] };
            let mut h = Sha256::new();
            h.update(&pair[0]);
            h.update(&right);
            next.push(h.finalize());
        }
        level = next;
    }
    level[0]
}

/// Byte-range storage for one suspend image: the writer/reader's
/// view of the suspend partition (or of one partition device). All
/// offsets are relative to the start of the image region.
pub trait ImageStore {
    /// Total bytes in the region.
    fn len_bytes(&self) -> u64;
    /// Read exactly `out.len()` bytes at `offset`.
    fn read_exact(&self, offset: u64, out: &mut [u8]) -> Result<(), ServiceError>;
    /// Write all of `data` at `offset`.
    fn write_all(&self, offset: u64, data: &[u8]) -> Result<(), ServiceError>;
    /// Make all prior writes durable.
    fn flush(&self) -> Result<(), ServiceError>;
}

/// [`ImageStore`] over the block layer: a registered partition
/// device behind `narf-block`'s synchronous surface. The suspend
/// partition is its own block device (the registry's partition
/// registration), so offsets map directly onto its LBAs.
#[derive(Clone)]
pub struct BlockStore {
    dev: Arc<dyn BlockDeviceSync>,
}

impl fmt::Debug for BlockStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockStore")
            .field("lba_size", &self.dev.lba_size())
            .field("capacity_lbas", &self.dev.capacity())
            .finish()
    }
}

fn store_err(_: BlockIoError) -> ServiceError {
    ServiceError::Store
}

impl BlockStore {
    pub fn new(dev: Arc<dyn BlockDeviceSync>) -> Self {
        Self { dev }
    }

    fn lba_size(&self) -> u64 {
        u64::from(self.dev.lba_size())
    }
}

impl ImageStore for BlockStore {
    fn len_bytes(&self) -> u64 {
        self.dev.capacity() * self.lba_size()
    }

    fn read_exact(&self, offset: u64, out: &mut [u8]) -> Result<(), ServiceError> {
        let lba_size = self.lba_size();
        if lba_size == 0 || offset % lba_size != 0 {
            return Err(ServiceError::Store);
        }
        let mut done = 0usize;
        while done < out.len() {
            let at = offset + done as u64;
            let remaining = out.len() - done;
            let full_blocks = remaining / lba_size as usize;
            if full_blocks > 0 {
                let n = full_blocks.min(u16::MAX as usize);
                self.dev
                    .read(
                        at / lba_size,
                        n as u16,
                        &mut out[done..done + n * lba_size as usize],
                    )
                    .map_err(store_err)?;
                done += n * lba_size as usize;
            } else {
                // Partial tail block: bounce through a scratch block
                // so BlockDeviceSync sees only whole LBAs.
                let mut scratch = alloc::vec![0u8; lba_size as usize];
                self.dev
                    .read(at / lba_size, 1, &mut scratch)
                    .map_err(store_err)?;
                out[done..].copy_from_slice(&scratch[..remaining]);
                done = out.len();
            }
        }
        Ok(())
    }

    fn write_all(&self, offset: u64, data: &[u8]) -> Result<(), ServiceError> {
        let lba_size = self.lba_size();
        if lba_size == 0 || offset % lba_size != 0 {
            return Err(ServiceError::Store);
        }
        let mut done = 0usize;
        while done < data.len() {
            let at = offset + done as u64;
            let remaining = data.len() - done;
            let full_blocks = remaining / lba_size as usize;
            if full_blocks > 0 {
                let n = full_blocks.min(u16::MAX as usize);
                self.dev
                    .write(
                        at / lba_size,
                        n as u16,
                        &data[done..done + n * lba_size as usize],
                    )
                    .map_err(store_err)?;
                done += n * lba_size as usize;
            } else {
                // Final partial block: zero-pad to a whole LBA. The
                // padding sits beyond the image's recorded length
                // and is never read back as image content.
                let mut padded = alloc::vec![0u8; lba_size as usize];
                padded[..remaining].copy_from_slice(&data[done..]);
                self.dev
                    .write(at / lba_size, 1, &padded)
                    .map_err(store_err)?;
                done = data.len();
            }
        }
        Ok(())
    }

    fn flush(&self) -> Result<(), ServiceError> {
        self.dev.flush().map_err(store_err)
    }
}
