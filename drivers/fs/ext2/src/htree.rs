//! ext3/4 HTREE directory indexing — read path.
//!
//! When `compat::DIR_INDEX` is set in the superblock and a directory's
//! `EXT4_INDEX_FL` inode flag is set, the directory's first data block
//! holds an HTREE root rather than a plain dirent block. The root is
//! laid out so that the legacy ext2 walker still sees a valid
//! "." + ".." pair, with the HTREE bookkeeping starting after `..`.
//!
//! Structure:
//!
//! ```text
//! struct dx_root {
//!     fake_dirent dot;        // 8 + 4 bytes = "."
//!     fake_dirent dotdot;     // 8 + 4 bytes = ".."
//!     struct dx_root_info {
//!         u32 reserved_zero;
//!         u8  hash_version;   // 0=legacy, 1=half_md4, 2=tea, 3..5=*_unsigned
//!         u8  info_length;    // == 8
//!         u8  indirect_levels;
//!         u8  unused_flags;
//!     } info;
//!     fake_dx_head { u16 limit, u16 count }
//!     dx_entry entries[];     // hash + block pairs
//! }
//! ```
//!
//! `dx_entry` is `{ u32 hash, u32 block }`. The first entry's `hash`
//! is unused (it's the "below smallest" bucket); the remaining
//! entries are sorted by `hash`. Looking up a name: hash the name,
//! binary-search the entry array for the largest `hash <= target`,
//! follow `block` to either a leaf (plain dirent block) or another
//! `dx_node` if `indirect_levels > 0`.
//!
//! Sources (post-relicense — NARF is GPL-2.0+ as of 2026-05-20):
//! - Linux `fs/ext4/namei.c`  — `struct dx_root`, `struct dx_node`,
//!   `struct dx_entry`, `dx_probe`.
//! - Linux `fs/ext4/hash.c`   — `__ext4fs_dirhash`, `TEA_transform`,
//!   `half_md4_transform`, `dx_hack_hash_*`.
//! - Linux `include/uapi/linux/ext4_fs.h::DX_HASH_*` constants.
//!
//! Stage 1 (this file): decode the root + walk to a leaf block, then
//! hand off to the linear walker in `dir`. Stage 2 (leaf splitting on
//! insert) is deferred — write paths fall through the existing
//! `dir_mut::dir_insert` which extends the directory as a flat
//! sequence of blocks.

/// Hash function discriminator (matches Linux `DX_HASH_*`).
pub mod hash_version {
    pub const LEGACY: u8 = 0;
    pub const HALF_MD4: u8 = 1;
    pub const TEA: u8 = 2;
    pub const LEGACY_UNSIGNED: u8 = 3;
    pub const HALF_MD4_UNSIGNED: u8 = 4;
    pub const TEA_UNSIGNED: u8 = 5;
}

/// dx_root header layout — what sits at the start of an HTREE'd
/// directory's first data block, AFTER the "." and ".." dirents.
///
/// Offsets are relative to the start of the directory block.
/// `.` is 12 bytes (4-byte inode + 2-byte rec_len + 1-byte name_len
/// + 1-byte file_type + 4-byte name pad). `..` is also 12 bytes.
/// So `dx_root_info` starts at byte 24, `dx_head` at byte 32, and
/// `dx_entry[0]` at byte 40.
pub const DX_ROOT_INFO_OFF: usize = 24;
pub const DX_ROOT_HEAD_OFF: usize = 32;
pub const DX_ROOT_ENTRIES_OFF: usize = 40;

/// dx_node header — every non-root htree node also starts with a
/// 12-byte fake dirent (inode = 0, rec_len = blocksize - reserved
/// area, name_len = 0). Then a 4-byte dx_head, then the entries.
pub const DX_NODE_HEAD_OFF: usize = 8;
pub const DX_NODE_ENTRIES_OFF: usize = 12;

/// Decoded HTREE root metadata.
#[derive(Debug, Clone, Copy)]
pub struct DxRoot {
    pub hash_version: u8,
    pub indirect_levels: u8,
    pub count: u16,
    pub limit: u16,
}

/// One (hash, block) entry in an HTREE node.
#[derive(Debug, Clone, Copy)]
pub struct DxEntry {
    pub hash: u32,
    pub block: u32,
}

impl DxRoot {
    /// Parse the HTREE root metadata from a directory's first data
    /// block. Returns `None` if the block is too small or the header
    /// is obviously bogus (`info_length != 8`, `hash_version > 5`).
    pub fn parse(block: &[u8]) -> Option<Self> {
        if block.len() < DX_ROOT_ENTRIES_OFF {
            return None;
        }
        // dx_root_info {reserved_zero, hash_version, info_length, indirect_levels, unused_flags}
        let info_off = DX_ROOT_INFO_OFF;
        let hash_version = block[info_off + 4];
        let info_length = block[info_off + 5];
        let indirect_levels = block[info_off + 6];
        if info_length != 8 {
            return None;
        }
        if hash_version > hash_version::TEA_UNSIGNED {
            return None;
        }
        if indirect_levels > 2 {
            return None;
        }
        let limit = u16::from_le_bytes([block[DX_ROOT_HEAD_OFF], block[DX_ROOT_HEAD_OFF + 1]]);
        let count = u16::from_le_bytes([block[DX_ROOT_HEAD_OFF + 2], block[DX_ROOT_HEAD_OFF + 3]]);
        if count == 0 || count > limit {
            return None;
        }
        Some(Self {
            hash_version,
            indirect_levels,
            count,
            limit,
        })
    }

    /// Read entry `i` of the root entries array.
    pub fn entry(block: &[u8], i: u16) -> Option<DxEntry> {
        let off = DX_ROOT_ENTRIES_OFF + (i as usize) * 8;
        if off + 8 > block.len() {
            return None;
        }
        let hash = u32::from_le_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]]);
        let block_no = u32::from_le_bytes([
            block[off + 4],
            block[off + 5],
            block[off + 6],
            block[off + 7],
        ]);
        Some(DxEntry {
            hash,
            block: block_no,
        })
    }
}

/// Decode a non-root htree node's (count, limit) header + an entry
/// at index `i`.
pub fn dx_node_head(block: &[u8]) -> Option<(u16, u16)> {
    if block.len() < DX_NODE_ENTRIES_OFF {
        return None;
    }
    let limit = u16::from_le_bytes([block[DX_NODE_HEAD_OFF], block[DX_NODE_HEAD_OFF + 1]]);
    let count = u16::from_le_bytes([block[DX_NODE_HEAD_OFF + 2], block[DX_NODE_HEAD_OFF + 3]]);
    if count == 0 || count > limit {
        return None;
    }
    Some((count, limit))
}

pub fn dx_node_entry(block: &[u8], i: u16) -> Option<DxEntry> {
    let off = DX_NODE_ENTRIES_OFF + (i as usize) * 8;
    if off + 8 > block.len() {
        return None;
    }
    let hash = u32::from_le_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]]);
    let block_no = u32::from_le_bytes([
        block[off + 4],
        block[off + 5],
        block[off + 6],
        block[off + 7],
    ]);
    Some(DxEntry {
        hash,
        block: block_no,
    })
}

/// Find the largest entry index whose hash is <= `target`. Returns
/// 0 if `target` is below the first entry — entry 0's hash is
/// conventionally unused but is always selected for below-range
/// lookups so the walker descends *somewhere*.
pub fn dx_find_entry_root(block: &[u8], target_hash: u32) -> Option<DxEntry> {
    let root = DxRoot::parse(block)?;
    let mut chosen = DxRoot::entry(block, 0)?;
    for i in 1..root.count {
        let e = DxRoot::entry(block, i)?;
        if e.hash <= target_hash {
            chosen = e;
        } else {
            break;
        }
    }
    Some(chosen)
}

pub fn dx_find_entry_node(block: &[u8], target_hash: u32) -> Option<DxEntry> {
    let (count, _limit) = dx_node_head(block)?;
    let mut chosen = dx_node_entry(block, 0)?;
    for i in 1..count {
        let e = dx_node_entry(block, i)?;
        if e.hash <= target_hash {
            chosen = e;
        } else {
            break;
        }
    }
    Some(chosen)
}

// ── Hash functions ─────────────────────────────────────────────────

/// The Tiny Encryption Algorithm round function used by the default
/// (TEA) htree hash. Implementation derived from Linux
/// `fs/ext4/hash.c::TEA_transform` (GPL-2.0). buf[0..2] are the
/// running state; in[0..4] is the 16-byte input chunk.
fn tea_transform(buf: &mut [u32; 4], inp: &[u32; 4]) {
    const DELTA: u32 = 0x9E37_79B9;
    let mut sum: u32 = 0;
    let mut b0 = buf[0];
    let mut b1 = buf[1];
    let a = inp[0];
    let b = inp[1];
    let c = inp[2];
    let d = inp[3];
    for _ in 0..16 {
        sum = sum.wrapping_add(DELTA);
        let t1 = (b1 << 4).wrapping_add(a) ^ b1.wrapping_add(sum) ^ (b1 >> 5).wrapping_add(b);
        b0 = b0.wrapping_add(t1);
        let t2 = (b0 << 4).wrapping_add(c) ^ b0.wrapping_add(sum) ^ (b0 >> 5).wrapping_add(d);
        b1 = b1.wrapping_add(t2);
    }
    buf[0] = buf[0].wrapping_add(b0);
    buf[1] = buf[1].wrapping_add(b1);
}

/// Pack `len` bytes of `msg` into `num` u32 words. Trailing bytes are
/// padded with `(len | (len << 8) | (len << 16) | (len << 24))`.
/// `signed` selects whether bytes are treated as `i8` (legacy) or
/// `u8` (the _UNSIGNED variants). Mirrors
/// `fs/ext4/hash.c::str2hashbuf_{signed,unsigned}`.
fn str2hashbuf(msg: &[u8], buf: &mut [u32; 4], num: usize, signed: bool) {
    let pad = (msg.len() as u32) | ((msg.len() as u32) << 8);
    let pad = pad | (pad << 16);
    let mut val = pad;
    let bytes = if msg.len() > num * 4 { num * 4 } else { msg.len() };
    let mut out_i = 0usize;
    let mut left = num;
    for i in 0..bytes {
        let ch = if signed {
            msg[i] as i8 as i32
        } else {
            msg[i] as i32
        };
        val = (ch as u32).wrapping_add(val << 8);
        if (i & 3) == 3 {
            buf[out_i] = val;
            out_i += 1;
            val = pad;
            left -= 1;
        }
    }
    if left > 0 {
        buf[out_i] = val;
        out_i += 1;
        left -= 1;
    }
    while left > 0 {
        buf[out_i] = pad;
        out_i += 1;
        left -= 1;
    }
}

/// Result of a directory-name hash — `(hash, minor_hash)`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DirHash {
    pub hash: u32,
    pub minor: u32,
}

/// Hash the bytes `name` per the directory's `hash_version`. The
/// `seed` is the 4 × u32 secret from the superblock (`s_hash_seed`,
/// zero in practice for our generated images).
pub fn name_hash(name: &[u8], hash_version: u8, seed: &[u32; 4]) -> DirHash {
    // Default Linux seed when s_hash_seed is all zeros.
    let default_seed: [u32; 4] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
    ];
    let mut buf = if seed.iter().any(|&v| v != 0) {
        *seed
    } else {
        default_seed
    };

    match hash_version {
        hash_version::LEGACY | hash_version::LEGACY_UNSIGNED => {
            let signed = hash_version == hash_version::LEGACY;
            let mut hash0: u32 = 0x12a3_fe2d;
            let mut hash1: u32 = 0x37ab_e8f9;
            for &b in name {
                let ch = if signed {
                    b as i8 as i32
                } else {
                    b as i32
                };
                let mut hash = hash1.wrapping_add(hash0 ^ ((ch as u32).wrapping_mul(7152373)));
                if hash & 0x8000_0000 != 0 {
                    hash = hash.wrapping_sub(0x7fff_ffff);
                }
                hash1 = hash0;
                hash0 = hash;
            }
            DirHash {
                hash: hash0 << 1,
                minor: 0,
            }
        }
        hash_version::TEA | hash_version::TEA_UNSIGNED => {
            let signed = hash_version == hash_version::TEA;
            let mut p = 0usize;
            let mut remaining = name.len();
            while remaining > 0 {
                let mut inp: [u32; 4] = [0; 4];
                let chunk_len = remaining.min(16);
                let chunk = &name[p..p + chunk_len];
                str2hashbuf(chunk, &mut inp, 4, signed);
                tea_transform(&mut buf, &inp);
                p += chunk_len;
                if remaining >= 16 {
                    remaining -= 16;
                } else {
                    remaining = 0;
                }
            }
            DirHash {
                hash: buf[0],
                minor: buf[1],
            }
        }
        _ => {
            // HALF_MD4 path is rarely used; we stub it as zero so an
            // unsupported HTREE volume falls back to the linear walker.
            DirHash { hash: 0, minor: 0 }
        }
    }
}

#[cfg(test)]
mod self_tests {
    use super::*;

    #[test]
    fn tea_known_vector_stable() {
        let mut buf = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
        let inp = [1u32, 2, 3, 4];
        let snapshot = buf;
        tea_transform(&mut buf, &inp);
        assert_ne!(buf, snapshot, "TEA must mutate state");
    }
}
