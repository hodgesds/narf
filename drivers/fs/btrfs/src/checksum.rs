//! btrfs block checksums and the CRC32C directory-name hash.
//!
//! Metadata and data blocks use the checksum selected by the superblock:
//! CRC32C, xxhash64, SHA-256, or BLAKE2b-256. The digest occupies the first
//! [`size`] bytes of the fixed 32-byte on-disk checksum field.
//!
//! CRC32C also has two format-specific roles:
//!
//! * **CRC32C block checksums** — the on-disk value is
//!   the standard CRC32C with initial value `0xFFFF_FFFF` and a final XOR of
//!   `0xFFFF_FFFF`, computed over the block bytes *after* the 32-byte csum
//!   field. See [`block_csum`]. This mirrors Linux's crc32c crypto shash
//!   (`crypto/crc32c_generic.c`), whose `.init` seeds `~0` and `.final` emits
//!   `~crc`.
//!
//! * **Directory name hash** — `btrfs_name_hash()` in the kernel is the *raw*
//!   running CRC32C (`lib/crc32c.c`, no inversions) seeded with `~1`
//!   (`0xFFFF_FFFE`). Its result forms the `offset` of `DIR_ITEM` keys, so the
//!   same polynomial that validates a node also locates a file by name. See
//!   [`name_hash`].
//!
//! The directory-name hash remains CRC32C regardless of the block-checksum
//! selection.

use narf_filesystem::FsError;

use crate::format;

/// Reflected Castagnoli polynomial.
const POLY: u32 = 0x82F6_3B78;

/// Compile-time CRC32C lookup tables for slicing-by-8: `TABLES[k][b]` is
/// the CRC of byte `b` followed by `k` zero bytes, so eight input bytes are
/// folded in with eight independent lookups instead of eight dependent ones.
const fn build_tables() -> [[u32; 256]; 8] {
    let mut tables = [[0u32; 256]; 8];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                POLY ^ (crc >> 1)
            } else {
                crc >> 1
            };
            bit += 1;
        }
        tables[0][i] = crc;
        i += 1;
    }
    let mut k = 1usize;
    while k < 8 {
        let mut i = 0usize;
        while i < 256 {
            let prev = tables[k - 1][i];
            tables[k][i] = (prev >> 8) ^ tables[0][(prev & 0xff) as usize];
            i += 1;
        }
        k += 1;
    }
    tables
}

static TABLES: [[u32; 256]; 8] = build_tables();

/// One byte at a time: the definition, and the tail of [`crc32c`].
fn crc32c_bytewise(seed: u32, data: &[u8]) -> u32 {
    let mut crc = seed;
    for &byte in data {
        let idx = ((crc ^ u32::from(byte)) & 0xff) as usize;
        crc = TABLES[0][idx] ^ (crc >> 8);
    }
    crc
}

/// Raw running CRC32C update, matching Linux `crc32c(seed, data, len)`
/// (`lib/crc32c.c`): no pre/post inversion, the caller supplies the seed and
/// interprets the residue. This is the primitive both public helpers build on.
///
/// Eight bytes per step (slicing-by-8, as Linux's generic `crc32c` does
/// where there is no CPU instruction for it): every tree block written or
/// read is checksummed whole and every data sector once, so a 4 KiB write
/// checksums some 80 KiB — its sector and the tree blocks on the paths it
/// replaces — and a byte at a time that was most of what the write cost.
pub fn crc32c(seed: u32, data: &[u8]) -> u32 {
    let mut crc = seed;
    let mut words = data.chunks_exact(8);
    for word in &mut words {
        let lo = u32::from_le_bytes([word[0], word[1], word[2], word[3]]) ^ crc;
        let hi = u32::from_le_bytes([word[4], word[5], word[6], word[7]]);
        crc = TABLES[7][(lo & 0xff) as usize]
            ^ TABLES[6][((lo >> 8) & 0xff) as usize]
            ^ TABLES[5][((lo >> 16) & 0xff) as usize]
            ^ TABLES[4][(lo >> 24) as usize]
            ^ TABLES[3][(hi & 0xff) as usize]
            ^ TABLES[2][((hi >> 8) & 0xff) as usize]
            ^ TABLES[1][((hi >> 16) & 0xff) as usize]
            ^ TABLES[0][(hi >> 24) as usize];
    }
    crc32c_bytewise(crc, words.remainder())
}

/// Test-only: [`crc32c`] one byte at a time, to compare the two.
#[cfg(feature = "kernel-test")]
pub(crate) fn __test_crc32c_bytewise(seed: u32, data: &[u8]) -> u32 {
    crc32c_bytewise(seed, data)
}

/// On-disk block checksum (superblock and every tree node): standard CRC32C
/// with `~0` seed and final inversion. `data` is the block content starting
/// *after* the 32-byte csum field. The low 4 bytes of the result are what
/// btrfs stores; the remaining csum bytes are zero for CRC32C.
pub fn block_csum(data: &[u8]) -> u32 {
    !crc32c(!0u32, data)
}

/// Whether `csum_type` names an algorithm understood by this driver.
pub(crate) const fn is_supported(csum_type: u16) -> bool {
    matches!(
        csum_type,
        format::CSUM_TYPE_CRC32
            | format::CSUM_TYPE_XXHASH
            | format::CSUM_TYPE_SHA256
            | format::CSUM_TYPE_BLAKE2
    )
}

/// Number of significant bytes in an on-disk checksum of this type.
pub(crate) const fn size(csum_type: u16) -> Result<usize, FsError> {
    match csum_type {
        format::CSUM_TYPE_CRC32 => Ok(4),
        format::CSUM_TYPE_XXHASH => Ok(8),
        format::CSUM_TYPE_SHA256 | format::CSUM_TYPE_BLAKE2 => Ok(32),
        _ => Err(FsError::Unsupported),
    }
}

/// Compute a btrfs checksum in its fixed 32-byte on-disk representation.
pub(crate) fn digest(csum_type: u16, data: &[u8]) -> Result<[u8; format::CSUM_SIZE], FsError> {
    use sha2::Digest;

    let mut out = [0u8; format::CSUM_SIZE];
    match csum_type {
        format::CSUM_TYPE_CRC32 => {
            out[..4].copy_from_slice(&block_csum(data).to_le_bytes());
        }
        format::CSUM_TYPE_XXHASH => {
            out[..8].copy_from_slice(&xxhash64(data, 0).to_le_bytes());
        }
        format::CSUM_TYPE_SHA256 => {
            out.copy_from_slice(&sha2::Sha256::digest(data));
        }
        format::CSUM_TYPE_BLAKE2 => {
            type Blake2b256 = blake2::Blake2b<blake2::digest::consts::U32>;
            out.copy_from_slice(&Blake2b256::digest(data));
        }
        _ => return Err(FsError::Unsupported),
    }
    Ok(out)
}

/// Stamp the fixed checksum field at the start of a metadata node or
/// superblock. Both formats checksum every byte after that 32-byte field.
pub(crate) fn stamp_block(csum_type: u16, block: &mut [u8]) -> Result<(), FsError> {
    let data = block.get(format::CSUM_SIZE..).ok_or(FsError::InvalidData)?;
    let sum = digest(csum_type, data)?;
    block[..format::CSUM_SIZE].copy_from_slice(&sum);
    Ok(())
}

/// Verify the significant bytes of a fixed-size on-disk checksum field.
pub(crate) fn verify(csum_type: u16, data: &[u8], stored: &[u8]) -> Result<bool, FsError> {
    let n = size(csum_type)?;
    let stored = stored.get(..n).ok_or(FsError::InvalidData)?;
    Ok(digest(csum_type, data)?[..n] == *stored)
}

// xxHash64, matching Linux `xxh64(data, len, seed)`. Multi-byte input words
// and the returned on-disk integer are little-endian.
fn xxhash64(input: &[u8], seed: u64) -> u64 {
    const P1: u64 = 11_400_714_785_074_694_791;
    const P2: u64 = 14_029_467_366_897_019_727;
    const P3: u64 = 1_609_587_929_392_839_161;
    const P4: u64 = 9_650_029_242_287_828_579;
    const P5: u64 = 2_870_177_450_012_600_261;

    #[inline]
    fn round(acc: u64, lane: u64) -> u64 {
        acc.wrapping_add(lane.wrapping_mul(P2))
            .rotate_left(31)
            .wrapping_mul(P1)
    }

    #[inline]
    fn merge_round(acc: u64, lane: u64) -> u64 {
        (acc ^ round(0, lane)).wrapping_mul(P1).wrapping_add(P4)
    }

    #[inline]
    fn read_u64(input: &[u8], off: usize) -> u64 {
        u64::from_le_bytes(input[off..off + 8].try_into().expect("bounded xxhash lane"))
    }

    let mut off = 0usize;
    let mut hash = if input.len() >= 32 {
        let mut v1 = seed.wrapping_add(P1).wrapping_add(P2);
        let mut v2 = seed.wrapping_add(P2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(P1);
        while off + 32 <= input.len() {
            v1 = round(v1, read_u64(input, off));
            v2 = round(v2, read_u64(input, off + 8));
            v3 = round(v3, read_u64(input, off + 16));
            v4 = round(v4, read_u64(input, off + 24));
            off += 32;
        }
        let acc = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
        merge_round(merge_round(merge_round(merge_round(acc, v1), v2), v3), v4)
    } else {
        seed.wrapping_add(P5)
    };

    hash = hash.wrapping_add(input.len() as u64);
    while off + 8 <= input.len() {
        hash ^= round(0, read_u64(input, off));
        hash = hash.rotate_left(27).wrapping_mul(P1).wrapping_add(P4);
        off += 8;
    }
    if off + 4 <= input.len() {
        let lane = u32::from_le_bytes(input[off..off + 4].try_into().expect("bounded xxhash lane"));
        hash ^= u64::from(lane).wrapping_mul(P1);
        hash = hash.rotate_left(23).wrapping_mul(P2).wrapping_add(P3);
        off += 4;
    }
    while off < input.len() {
        hash ^= u64::from(input[off]).wrapping_mul(P5);
        hash = hash.rotate_left(11).wrapping_mul(P1);
        off += 1;
    }
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(P2);
    hash ^= hash >> 29;
    hash = hash.wrapping_mul(P3);
    hash ^ (hash >> 32)
}

/// `btrfs_name_hash()`: raw CRC32C seeded with `~1`, used as the `offset`
/// component of a `DIR_ITEM` key so a name resolves to its directory entry.
pub fn name_hash(name: &[u8]) -> u32 {
    crc32c(!1u32, name)
}
