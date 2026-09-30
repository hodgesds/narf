//! Read-only LUKS1 metadata parsing and passphrase-based keyslot unlock.
//!
//! This module deliberately does not format volumes or edit keyslots. Its
//! scope is the minimum needed to open an existing Linux installation:
//! AES-256-XTS with the `plain64` IV mode and PBKDF2-HMAC-SHA1/SHA256/SHA512.
//! The on-disk structures follow the LUKS1 format specification; the XTS
//! sector/tweak behavior is cross-checked against
//! `~/git/linux/drivers/md/dm-crypt.c`.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_capabilities::{Cap, Grant};
use narf_crypto::hkdf::hmac_sha256;
use narf_crypto::pbkdf2_sha1::{hmac_sha1, Sha1};
use narf_crypto::sha256::Sha256;
use narf_crypto::sha512::Sha512;
use narf_crypto::{aes_xts_256_decrypt, AesXts256, CryptoError, Key};
use zeroize::{Zeroize, Zeroizing};

use crate::encrypted::VkBytes;
use crate::registry::{BlockDeviceSync, BlockIoError};

/// LUKS1 always addresses metadata and encrypted data in 512-byte sectors.
pub const SECTOR_BYTES: usize = 512;
/// Serialized LUKS1 fixed header, including all eight keyslot records.
pub const HEADER_BYTES: usize = 592;
/// Number of keyslots in a LUKS1 header.
pub const KEYSLOTS: usize = 8;
/// Current LUKS1 enabled-keyslot marker, stored big-endian on disk.
pub const KEY_ENABLED: u32 = 0x00ac_71f3;
/// Current LUKS1 disabled-keyslot marker, stored big-endian on disk.
pub const KEY_DISABLED: u32 = 0x0000_dead;
const KEY_ENABLED_OLD: u32 = 0x0000_cafe;
const KEY_DISABLED_OLD: u32 = 0;
const MAGIC: &[u8; 6] = b"LUKS\xba\xbe";
const MAX_KEYSLOT_BYTES: usize = 16 * 1024 * 1024;

/// Hash algorithms permitted by this LUKS1 reader.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Luks1Hash {
    /// SHA-1, the original LUKS1 default.
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
}

impl Luks1Hash {
    fn digest_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

/// One decoded LUKS1 keyslot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Luks1KeySlot {
    /// Whether cryptsetup marked the slot active.
    pub active: bool,
    /// PBKDF2 iteration count for the passphrase-derived key.
    pub iterations: u32,
    /// PBKDF2 salt.
    pub salt: [u8; 32],
    /// Start of encrypted anti-forensic key material, in 512-byte sectors.
    pub key_material_offset: u32,
    /// Number of anti-forensic stripes.
    pub stripes: u32,
}

/// Decoded, validated LUKS1 metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Luks1Header {
    /// First encrypted payload sector, relative to the containing partition.
    pub payload_offset: u32,
    /// Volume-key length in bytes. This implementation accepts 64 only.
    pub key_bytes: u32,
    /// Hash used by both keyslot PBKDF2 and anti-forensic diffusion.
    pub hash: Luks1Hash,
    /// PBKDF2 digest of the correct recovered volume key.
    pub master_key_digest: [u8; 20],
    /// Salt for `master_key_digest`.
    pub master_key_digest_salt: [u8; 32],
    /// PBKDF2 iteration count for `master_key_digest`.
    pub master_key_digest_iterations: u32,
    /// LUKS UUID as stored in the fixed-width header field.
    pub uuid: String,
    /// All eight keyslots, in on-disk order.
    pub keyslots: [Luks1KeySlot; KEYSLOTS],
}

/// Failures while parsing or unlocking a LUKS1 volume.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Luks1Error {
    /// Underlying block I/O failed.
    Io(BlockIoError),
    /// The block device does not expose 512-byte logical sectors.
    UnsupportedLogicalBlockSize,
    /// The header is shorter than 592 bytes.
    ShortHeader,
    /// The six-byte LUKS magic is absent.
    BadMagic,
    /// Only version 1 is supported.
    UnsupportedVersion,
    /// Only AES is supported.
    UnsupportedCipher,
    /// Only XTS with the `plain64` IV generator is supported.
    UnsupportedCipherMode,
    /// The named PBKDF2/diffusion hash is not implemented.
    UnsupportedHash,
    /// Only a 64-byte AES-256-XTS volume key is supported.
    UnsupportedKeySize,
    /// A fixed-width string or numeric/range field is malformed.
    InvalidHeader,
    /// A header-controlled PBKDF2 count exceeds the caller's policy.
    WorkFactorTooLarge,
    /// The header has no enabled keyslot.
    NoActiveKeyslot,
    /// No enabled keyslot authenticated with the supplied passphrase.
    WrongPassphrase,
    /// The cap-gated AES-XTS primitive failed.
    Crypto(CryptoError),
}

impl From<BlockIoError> for Luks1Error {
    fn from(value: BlockIoError) -> Self {
        Self::Io(value)
    }
}

impl From<CryptoError> for Luks1Error {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

/// Resource policy for passphrase-based unlock.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Luks1UnlockPolicy {
    /// Maximum PBKDF2 iterations accepted for either a keyslot or the
    /// master-key digest. This bounds boot-time CPU denial of service by a
    /// corrupt or attacker-controlled header.
    pub max_pbkdf2_iterations: u32,
    /// Maximum sum of all PBKDF2 work attempted across enabled keyslots,
    /// including one master-key digest check per slot.
    pub max_total_pbkdf2_iterations: u64,
}

impl Default for Luks1UnlockPolicy {
    fn default() -> Self {
        Self {
            max_pbkdf2_iterations: 10_000_000,
            max_total_pbkdf2_iterations: 25_000_000,
        }
    }
}

impl Luks1Header {
    /// Parse and validate a serialized LUKS1 fixed header.
    pub fn parse(bytes: &[u8]) -> Result<Self, Luks1Error> {
        if bytes.len() < HEADER_BYTES {
            return Err(Luks1Error::ShortHeader);
        }
        if &bytes[..6] != MAGIC {
            return Err(Luks1Error::BadMagic);
        }
        if be_u16(bytes, 6) != 1 {
            return Err(Luks1Error::UnsupportedVersion);
        }
        if fixed_string(bytes, 8, 32)? != "aes" {
            return Err(Luks1Error::UnsupportedCipher);
        }
        if fixed_string(bytes, 40, 32)? != "xts-plain64" {
            return Err(Luks1Error::UnsupportedCipherMode);
        }
        let hash = match fixed_string(bytes, 72, 32)? {
            "sha1" => Luks1Hash::Sha1,
            "sha256" => Luks1Hash::Sha256,
            "sha512" => Luks1Hash::Sha512,
            _ => return Err(Luks1Error::UnsupportedHash),
        };

        let payload_offset = be_u32(bytes, 104);
        let key_bytes = be_u32(bytes, 108);
        if key_bytes != 64 {
            return Err(Luks1Error::UnsupportedKeySize);
        }
        if payload_offset < HEADER_BYTES.div_ceil(SECTOR_BYTES) as u32 {
            return Err(Luks1Error::InvalidHeader);
        }

        let mut master_key_digest = [0u8; 20];
        master_key_digest.copy_from_slice(&bytes[112..132]);
        let mut master_key_digest_salt = [0u8; 32];
        master_key_digest_salt.copy_from_slice(&bytes[132..164]);
        let master_key_digest_iterations = be_u32(bytes, 164);
        if master_key_digest_iterations == 0 {
            return Err(Luks1Error::InvalidHeader);
        }
        let uuid = String::from(fixed_string(bytes, 168, 40)?);

        let empty = Luks1KeySlot {
            active: false,
            iterations: 0,
            salt: [0; 32],
            key_material_offset: 0,
            stripes: 0,
        };
        let mut keyslots = [empty; KEYSLOTS];
        for (index, slot) in keyslots.iter_mut().enumerate() {
            let offset = 208 + index * 48;
            let marker = be_u32(bytes, offset);
            let active = match marker {
                KEY_ENABLED | KEY_ENABLED_OLD => true,
                KEY_DISABLED | KEY_DISABLED_OLD => false,
                _ => return Err(Luks1Error::InvalidHeader),
            };
            let iterations = be_u32(bytes, offset + 4);
            let mut salt = [0u8; 32];
            salt.copy_from_slice(&bytes[offset + 8..offset + 40]);
            let key_material_offset = be_u32(bytes, offset + 40);
            let stripes = be_u32(bytes, offset + 44);

            if active {
                validate_active_slot(
                    key_bytes,
                    payload_offset,
                    iterations,
                    key_material_offset,
                    stripes,
                )?;
            }
            *slot = Luks1KeySlot {
                active,
                iterations,
                salt,
                key_material_offset,
                stripes,
            };
        }

        Ok(Self {
            payload_offset,
            key_bytes,
            hash,
            master_key_digest,
            master_key_digest_salt,
            master_key_digest_iterations,
            uuid,
            keyslots,
        })
    }
}

/// Best-effort LUKS1 UUID probe for partition registration.
///
/// The UUID lies wholly within sector zero, so discovery can create the same
/// `/dev/disk/by-uuid` identity Linux uses before a passphrase is available.
/// Full parsing and all keyslot validation still happen in [`Luks1Header::parse`]
/// before unlock.
pub(crate) fn probe_uuid(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 208 || &bytes[..6] != MAGIC || be_u16(bytes, 6) != 1 {
        return None;
    }
    let uuid = fixed_string(bytes, 168, 40).ok()?;
    if uuid.len() != 36
        || uuid.bytes().enumerate().any(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte != b'-'
            } else {
                !byte.is_ascii_hexdigit()
            }
        })
    {
        return None;
    }
    Some(String::from(uuid))
}

fn validate_active_slot(
    key_bytes: u32,
    payload_offset: u32,
    iterations: u32,
    key_material_offset: u32,
    stripes: u32,
) -> Result<(), Luks1Error> {
    if iterations == 0 || stripes == 0 || key_material_offset < 2 {
        return Err(Luks1Error::InvalidHeader);
    }
    let material_bytes = (key_bytes as usize)
        .checked_mul(stripes as usize)
        .ok_or(Luks1Error::InvalidHeader)?;
    if material_bytes == 0 || material_bytes > MAX_KEYSLOT_BYTES {
        return Err(Luks1Error::InvalidHeader);
    }
    let material_sectors = material_bytes.div_ceil(SECTOR_BYTES) as u32;
    let end = key_material_offset
        .checked_add(material_sectors)
        .ok_or(Luks1Error::InvalidHeader)?;
    if end > payload_offset {
        return Err(Luks1Error::InvalidHeader);
    }
    Ok(())
}

fn fixed_string(bytes: &[u8], offset: usize, len: usize) -> Result<&str, Luks1Error> {
    let field = &bytes[offset..offset + len];
    let end = field
        .iter()
        .position(|&byte| byte == 0)
        .ok_or(Luks1Error::InvalidHeader)?;
    core::str::from_utf8(&field[..end]).map_err(|_| Luks1Error::InvalidHeader)
}

fn be_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn be_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

pub(crate) struct UnlockedLuks1 {
    pub(crate) header: Luks1Header,
    pub(crate) volume_key: VkBytes,
}

pub(crate) fn unlock(
    inner: Arc<dyn BlockDeviceSync>,
    passphrase: &[u8],
    policy: Luks1UnlockPolicy,
) -> Result<UnlockedLuks1, Luks1Error> {
    if inner.lba_size() as usize != SECTOR_BYTES {
        return Err(Luks1Error::UnsupportedLogicalBlockSize);
    }
    let header_sectors = HEADER_BYTES.div_ceil(SECTOR_BYTES);
    let mut serialized = [0u8; SECTOR_BYTES * 2];
    inner.read(0, header_sectors as u16, &mut serialized)?;
    let header = Luks1Header::parse(&serialized)?;
    if u64::from(header.payload_offset) >= inner.capacity() {
        return Err(Luks1Error::InvalidHeader);
    }
    if header.master_key_digest_iterations > policy.max_pbkdf2_iterations {
        return Err(Luks1Error::WorkFactorTooLarge);
    }

    let active_slots = header.keyslots.iter().filter(|slot| slot.active).count();
    if active_slots == 0 {
        return Err(Luks1Error::NoActiveKeyslot);
    }
    let requested_work = header
        .keyslots
        .iter()
        .filter(|slot| slot.active)
        .try_fold(0u64, |total, slot| {
            total
                .checked_add(u64::from(slot.iterations))?
                .checked_add(u64::from(header.master_key_digest_iterations))
        })
        .ok_or(Luks1Error::WorkFactorTooLarge)?;
    if requested_work > policy.max_total_pbkdf2_iterations {
        return Err(Luks1Error::WorkFactorTooLarge);
    }

    let xts_cap = Cap::<Key<AesXts256>, Grant>::bootstrap();
    for slot in header.keyslots.iter().filter(|slot| slot.active) {
        if slot.iterations > policy.max_pbkdf2_iterations {
            return Err(Luks1Error::WorkFactorTooLarge);
        }

        let key_bytes = header.key_bytes as usize;
        let material_bytes = key_bytes * slot.stripes as usize;
        let material_sectors = material_bytes.div_ceil(SECTOR_BYTES);
        if material_sectors > u16::MAX as usize
            || u64::from(slot.key_material_offset) + material_sectors as u64 > inner.capacity()
        {
            return Err(Luks1Error::InvalidHeader);
        }

        let derived = pbkdf2(
            header.hash,
            passphrase,
            &slot.salt,
            slot.iterations,
            key_bytes,
        );
        let mut xts_key = Zeroizing::new([0u8; 64]);
        xts_key.copy_from_slice(&derived);

        // cryptsetup encrypts/decrypts the complete 512-byte-aligned AF area,
        // starting its plain64 tweak at zero regardless of the keyslot's
        // physical offset. AF_merge consumes only key_bytes * stripes.
        let mut material = Zeroizing::new(alloc::vec![0u8; material_sectors * SECTOR_BYTES]);
        inner.read(
            u64::from(slot.key_material_offset),
            material_sectors as u16,
            &mut material,
        )?;
        aes_xts_256_decrypt(&xts_cap, &xts_key, 0, &mut material)?;

        let master_key = af_merge(
            header.hash,
            &material[..material_bytes],
            key_bytes,
            slot.stripes as usize,
        )?;
        let digest = pbkdf2(
            header.hash,
            &master_key,
            &header.master_key_digest_salt,
            header.master_key_digest_iterations,
            header.master_key_digest.len(),
        );
        if constant_time_eq(&digest, &header.master_key_digest) {
            let mut volume_key = [0u8; 64];
            volume_key.copy_from_slice(&master_key);
            return Ok(UnlockedLuks1 {
                header,
                volume_key: VkBytes::new(volume_key),
            });
        }
    }

    Err(Luks1Error::WrongPassphrase)
}

fn pbkdf2(
    hash: Luks1Hash,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output_len: usize,
) -> Zeroizing<Vec<u8>> {
    debug_assert!(iterations > 0);
    let digest_len = hash.digest_len();
    let mut output = Zeroizing::new(alloc::vec![0u8; output_len]);
    let mut salt_block = Zeroizing::new(Vec::with_capacity(salt.len() + 4));
    salt_block.extend_from_slice(salt);
    salt_block.extend_from_slice(&[0u8; 4]);

    for block_index in 1..=output_len.div_ceil(digest_len) {
        let index = u32::try_from(block_index).expect("PBKDF2 output exceeds u32 blocks");
        let suffix = salt_block.len() - 4;
        salt_block[suffix..].copy_from_slice(&index.to_be_bytes());

        let mut u = Zeroizing::new([0u8; 64]);
        let mut t = Zeroizing::new([0u8; 64]);
        hmac_into(hash, password, &salt_block, &mut u);
        t[..digest_len].copy_from_slice(&u[..digest_len]);
        for _ in 1..iterations {
            let previous = Zeroizing::new(*u);
            hmac_into(hash, password, &previous[..digest_len], &mut u);
            for i in 0..digest_len {
                t[i] ^= u[i];
            }
        }

        let output_offset = (block_index - 1) * digest_len;
        let take = (output_len - output_offset).min(digest_len);
        output[output_offset..output_offset + take].copy_from_slice(&t[..take]);
    }
    output
}

fn hmac_into(hash: Luks1Hash, key: &[u8], data: &[u8], out: &mut [u8; 64]) {
    out.zeroize();
    match hash {
        Luks1Hash::Sha1 => {
            let digest = Zeroizing::new(hmac_sha1(key, data));
            out[..20].copy_from_slice(&digest[..]);
        }
        Luks1Hash::Sha256 => {
            let digest = Zeroizing::new(hmac_sha256(key, data));
            out[..32].copy_from_slice(&digest[..]);
        }
        Luks1Hash::Sha512 => {
            let digest = Zeroizing::new(hmac_sha512(key, data));
            out.copy_from_slice(&digest[..]);
        }
    }
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    const BLOCK_BYTES: usize = 128;
    let mut key_block = Zeroizing::new([0u8; BLOCK_BYTES]);
    if key.len() > BLOCK_BYTES {
        let mut hasher = Sha512::new();
        hasher.update(key);
        key_block[..64].copy_from_slice(&hasher.finalize());
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = Zeroizing::new([0x36u8; BLOCK_BYTES]);
    let mut outer_pad = Zeroizing::new([0x5cu8; BLOCK_BYTES]);
    for index in 0..BLOCK_BYTES {
        inner_pad[index] ^= key_block[index];
        outer_pad[index] ^= key_block[index];
    }
    let mut inner = Sha512::new();
    inner.update(&inner_pad[..]);
    inner.update(data);
    let inner_digest = Zeroizing::new(inner.finalize());

    let mut outer = Sha512::new();
    outer.update(&outer_pad[..]);
    outer.update(&inner_digest[..]);
    outer.finalize()
}

fn hash_into(hash: Luks1Hash, prefix: &[u8], data: &[u8], out: &mut [u8; 64]) {
    out.zeroize();
    match hash {
        Luks1Hash::Sha1 => {
            let mut hasher = Sha1::new();
            hasher.update(prefix);
            hasher.update(data);
            let digest = Zeroizing::new(hasher.finalize());
            out[..20].copy_from_slice(&digest[..]);
        }
        Luks1Hash::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(prefix);
            hasher.update(data);
            let digest = Zeroizing::new(hasher.finalize());
            out[..32].copy_from_slice(&digest[..]);
        }
        Luks1Hash::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(prefix);
            hasher.update(data);
            let digest = Zeroizing::new(hasher.finalize());
            out.copy_from_slice(&digest[..]);
        }
    }
}

fn af_merge(
    hash: Luks1Hash,
    material: &[u8],
    key_bytes: usize,
    stripes: usize,
) -> Result<Zeroizing<Vec<u8>>, Luks1Error> {
    if stripes == 0 || material.len() != key_bytes.saturating_mul(stripes) {
        return Err(Luks1Error::InvalidHeader);
    }
    let mut state = Zeroizing::new(alloc::vec![0u8; key_bytes]);
    let mut diffused = Zeroizing::new(alloc::vec![0u8; key_bytes]);
    for stripe in material.chunks_exact(key_bytes).take(stripes - 1) {
        xor_in_place(&mut state, stripe);
        diffuse(hash, &state, &mut diffused);
        core::mem::swap(&mut state, &mut diffused);
        diffused.zeroize();
    }
    xor_in_place(
        &mut state,
        &material[(stripes - 1) * key_bytes..stripes * key_bytes],
    );
    Ok(state)
}

fn diffuse(hash: Luks1Hash, input: &[u8], output: &mut [u8]) {
    let digest_len = hash.digest_len();
    for (index, chunk) in input.chunks(digest_len).enumerate() {
        let mut digest = Zeroizing::new([0u8; 64]);
        hash_into(hash, &(index as u32).to_be_bytes(), chunk, &mut digest);
        let offset = index * digest_len;
        output[offset..offset + chunk.len()].copy_from_slice(&digest[..chunk.len()]);
    }
}

fn xor_in_place(left: &mut [u8], right: &[u8]) {
    for (left, right) in left.iter_mut().zip(right.iter()) {
        *left ^= *right;
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (&left, &right) in left.iter().zip(right.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

pub(crate) mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn header_fixture() -> [u8; 1024] {
        let mut bytes = [0u8; 1024];
        bytes[..6].copy_from_slice(MAGIC);
        bytes[6..8].copy_from_slice(&1u16.to_be_bytes());
        bytes[8..11].copy_from_slice(b"aes");
        bytes[40..51].copy_from_slice(b"xts-plain64");
        bytes[72..78].copy_from_slice(b"sha256");
        bytes[104..108].copy_from_slice(&4096u32.to_be_bytes());
        bytes[108..112].copy_from_slice(&64u32.to_be_bytes());
        bytes[164..168].copy_from_slice(&1000u32.to_be_bytes());
        bytes[168..204].copy_from_slice(b"01234567-89ab-cdef-0123-456789abcdef");
        bytes[208..212].copy_from_slice(&KEY_ENABLED.to_be_bytes());
        bytes[212..216].copy_from_slice(&2000u32.to_be_bytes());
        bytes[248..252].copy_from_slice(&8u32.to_be_bytes());
        bytes[252..256].copy_from_slice(&4000u32.to_be_bytes());
        for index in 1..KEYSLOTS {
            let offset = 208 + index * 48;
            bytes[offset..offset + 4].copy_from_slice(&KEY_DISABLED.to_be_bytes());
        }
        bytes
    }

    fn smoke_luks1_header_parse() -> TestResult {
        let fixture = header_fixture();
        let header = match Luks1Header::parse(&fixture) {
            Ok(header) => header,
            Err(_) => return TestResult::Fail("valid LUKS1 header rejected"),
        };
        if header.payload_offset != 4096
            || header.key_bytes != 64
            || header.hash != Luks1Hash::Sha256
            || header.uuid != "01234567-89ab-cdef-0123-456789abcdef"
            || !header.keyslots[0].active
            || header.keyslots[0].key_material_offset != 8
            || header.keyslots[0].stripes != 4000
        {
            return TestResult::Fail("LUKS1 header fields decoded incorrectly");
        }
        if probe_uuid(&fixture[..SECTOR_BYTES]).as_deref()
            != Some("01234567-89ab-cdef-0123-456789abcdef")
        {
            return TestResult::Fail("LUKS1 UUID probe disagreed with full parser");
        }
        TestResult::Pass
    }
    kernel_test_in!("block/luks1", smoke_luks1_header_parse);

    fn smoke_luks1_rejects_keyslot_past_payload() -> TestResult {
        let mut bytes = header_fixture();
        bytes[248..252].copy_from_slice(&4000u32.to_be_bytes());
        match Luks1Header::parse(&bytes) {
            Err(Luks1Error::InvalidHeader) => TestResult::Pass,
            _ => TestResult::Fail("overlapping LUKS1 keyslot accepted"),
        }
    }
    kernel_test_in!("block/luks1", smoke_luks1_rejects_keyslot_past_payload);

    fn smoke_luks1_pbkdf2_sha256_vector() -> TestResult {
        let derived = pbkdf2(Luks1Hash::Sha256, b"password", b"salt", 1, 32);
        let expected = [
            0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4,
            0xf8, 0x37, 0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c,
            0xb7, 0x0b, 0xe1, 0x7b,
        ];
        if derived.as_slice() == expected {
            TestResult::Pass
        } else {
            TestResult::Fail("PBKDF2-HMAC-SHA256 vector mismatch")
        }
    }
    kernel_test_in!("block/luks1", smoke_luks1_pbkdf2_sha256_vector);

    fn smoke_luks1_pbkdf2_sha512_vector() -> TestResult {
        let derived = pbkdf2(Luks1Hash::Sha512, b"password", b"salt", 1, 64);
        let expected = [
            0x86, 0x7f, 0x70, 0xcf, 0x1a, 0xde, 0x02, 0xcf, 0xf3, 0x75, 0x25, 0x99, 0xa3, 0xa5,
            0x3d, 0xc4, 0xaf, 0x34, 0xc7, 0xa6, 0x69, 0x81, 0x5a, 0xe5, 0xd5, 0x13, 0x55, 0x4e,
            0x1c, 0x8c, 0xf2, 0x52, 0xc0, 0x2d, 0x47, 0x0a, 0x28, 0x5a, 0x05, 0x01, 0xba, 0xd9,
            0x99, 0xbf, 0xe9, 0x43, 0xc0, 0x8f, 0x05, 0x02, 0x35, 0xd7, 0xd6, 0x8b, 0x1d, 0xa5,
            0x5e, 0x63, 0xf7, 0x3b, 0x60, 0xa5, 0x7f, 0xce,
        ];
        if derived.as_slice() == expected {
            TestResult::Pass
        } else {
            TestResult::Fail("PBKDF2-HMAC-SHA512 vector mismatch")
        }
    }
    kernel_test_in!("block/luks1", smoke_luks1_pbkdf2_sha512_vector);

    fn smoke_luks1_af_merge_vector() -> TestResult {
        let merged = af_merge(
            Luks1Hash::Sha256,
            &[1, 2, 3, 4, 0xaa, 0xbb, 0xcc, 0xdd],
            4,
            2,
        )
        .expect("valid AF stripes");
        if merged.as_slice() == [0x2c, 0x7f, 0x66, 0x0f] {
            TestResult::Pass
        } else {
            TestResult::Fail("LUKS1 AF merge vector mismatch")
        }
    }
    kernel_test_in!("block/luks1", smoke_luks1_af_merge_vector);
}
