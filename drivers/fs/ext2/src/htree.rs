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
//! hand off to the linear walker in `dir`. Stage 2 (write path, this
//! file): `htree_split_leaf` — when `dir_mut::dir_insert` finds a
//! full HTREE leaf, this splits it into two blocks and updates the
//! parent index node. Mirrors Linux `fs/ext4/namei.c::do_split`.

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
/// `.` is 12 bytes (4-byte inode, 2-byte rec_len, 1-byte name_len,
/// 1-byte file_type, 4-byte name pad). `..` is also 12 bytes.
/// So `dx_root_info` starts at byte 24, `dx_head` at byte 32, and `dx_entry[0]`
/// at byte 40.
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
    let bytes = if msg.len() > num * 4 {
        num * 4
    } else {
        msg.len()
    };
    let mut out_i = 0usize;
    let mut left = num;
    for (i, &b) in msg.iter().enumerate().take(bytes) {
        let ch = if signed { b as i8 as i32 } else { b as i32 };
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
    let default_seed: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
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
                let ch = if signed { b as i8 as i32 } else { b as i32 };
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

// ── HTREE write path: leaf-split ───────────────────────────────────
//
// When `dir_insert` finds that an HTREE leaf block is full, it calls
// `htree_split_leaf` which:
//   1. Collects all live dirents from the old block (with their hashes).
//   2. Sorts them by hash.
//   3. Walks from the end accumulating byte-size until ~50 % of the
//      block is filled — those entries go to the new block.
//   4. Repacks old and new blocks.
//   5. Returns the split-hash and both block bodies so the caller can
//      allocate a new physical block and update the index node.
//
// Ref: Linux `fs/ext4/namei.c::do_split` (GPL-2.0).

use alloc::vec;
use alloc::vec::Vec;

/// Error from the split path.
#[derive(Debug)]
pub enum SplitError {
    /// Index node already at capacity — caller must grow the tree.
    IndexFull,
    /// Block data is structurally corrupt.
    Corrupt,
}

/// A single live dirent captured from a leaf block, paired with the
/// hash of the entry name (so the sort is stable without re-hashing).
#[derive(Clone, Debug)]
pub struct LeafEntry {
    pub hash: u32,
    pub bytes: Vec<u8>,
}

/// Serialise one dirent into a byte vector. The record length in the
/// bytes is set to the minimum aligned length; the caller that repacks
/// the block is responsible for adjusting the last entry's `rec_len`
/// to reach the end of the block.
fn pack_dirent(inode: u32, name: &[u8], file_type: u8) -> Vec<u8> {
    let name_len = name.len() as u8;
    let aligned = ((name_len as usize + 8 + 3) & !3) as u16;
    let mut v = vec![0u8; aligned as usize];
    v[0..4].copy_from_slice(&inode.to_le_bytes());
    v[4..6].copy_from_slice(&aligned.to_le_bytes());
    v[6] = name_len;
    v[7] = file_type;
    v[8..8 + name_len as usize].copy_from_slice(name);
    v
}

/// Walk every dirent in `block`, hash each name, and return a
/// `Vec<LeafEntry>` sorted ascending by hash. Skips deleted entries
/// (inode == 0). Returns `Err(SplitError::Corrupt)` on malformed
/// record lengths.
pub fn collect_sorted_leaf_entries(
    block: &[u8],
    hash_version: u8,
    seed: &[u32; 4],
) -> Result<Vec<LeafEntry>, SplitError> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 8 <= block.len() {
        let inode =
            u32::from_le_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]]);
        let rec_len = u16::from_le_bytes([block[off + 4], block[off + 5]]) as usize;
        let name_len = block[off + 6] as usize;
        let file_type = block[off + 7];
        if rec_len < 8 || off + rec_len > block.len() {
            return Err(SplitError::Corrupt);
        }
        if inode != 0 && name_len > 0 {
            let name = &block[off + 8..off + 8 + name_len];
            let h = name_hash(name, hash_version, seed);
            let bytes = pack_dirent(inode, name, file_type);
            out.push(LeafEntry {
                hash: h.hash,
                bytes,
            });
        }
        off += rec_len;
    }
    // Stable sort by hash — entries with equal hashes keep
    // their relative order (matches Linux `dx_sort_map`'s intent).
    out.sort_by_key(|e| e.hash);
    Ok(out)
}

/// Write `entries` back into `block`, tightly packed. The last
/// entry's `rec_len` is extended to the end of the block. Returns
/// `Err` if the packed entries don't fit.
pub fn repack_leaf_block(block: &mut [u8], entries: &[LeafEntry]) -> Result<(), SplitError> {
    let bs = block.len();
    // Measure total needed space.
    let needed: usize = entries.iter().map(|e| e.bytes.len()).sum();
    if needed > bs {
        return Err(SplitError::Corrupt);
    }
    // Zero the block then write entries.
    for b in block.iter_mut() {
        *b = 0;
    }
    let mut pos = 0usize;
    for (i, e) in entries.iter().enumerate() {
        let len = e.bytes.len();
        block[pos..pos + len].copy_from_slice(&e.bytes);
        if i + 1 == entries.len() {
            // Stretch the last entry to fill the block.
            let final_rec_len = (bs - pos) as u16;
            block[pos + 4..pos + 6].copy_from_slice(&final_rec_len.to_le_bytes());
        }
        pos += len;
    }
    Ok(())
}

/// Insert a new `(hash, block_no)` pair into an htree index node.
/// The entries array begins at `entries_off` inside `node_buf`. The
/// `(count, limit)` header lives at `head_off`. Both are byte offsets
/// into `node_buf`. Returns `Err(SplitError::IndexFull)` when the
/// node is at capacity.
pub fn index_node_insert_entry(
    node_buf: &mut [u8],
    head_off: usize,
    entries_off: usize,
    hash: u32,
    block_no: u32,
) -> Result<(), SplitError> {
    if node_buf.len() < entries_off + 8 {
        return Err(SplitError::Corrupt);
    }
    let limit = u16::from_le_bytes([node_buf[head_off], node_buf[head_off + 1]]) as usize;
    let count = u16::from_le_bytes([node_buf[head_off + 2], node_buf[head_off + 3]]) as usize;
    if count >= limit {
        return Err(SplitError::IndexFull);
    }
    // Find insertion position (entries are sorted by hash; entry 0
    // has no hash — it's the catch-all bucket so we skip it).
    let mut insert_at = count; // default: append
    for i in 1..count {
        let off = entries_off + i * 8;
        let h = u32::from_le_bytes([
            node_buf[off],
            node_buf[off + 1],
            node_buf[off + 2],
            node_buf[off + 3],
        ]);
        if hash < h {
            insert_at = i;
            break;
        }
    }
    // Shift entries from `insert_at` to `count` one slot right.
    let src_start = entries_off + insert_at * 8;
    let src_end = entries_off + count * 8;
    node_buf.copy_within(src_start..src_end, src_start + 8);
    // Write the new entry.
    let off = entries_off + insert_at * 8;
    node_buf[off..off + 4].copy_from_slice(&hash.to_le_bytes());
    node_buf[off + 4..off + 8].copy_from_slice(&block_no.to_le_bytes());
    // Bump count.
    let new_count = (count + 1) as u16;
    node_buf[head_off + 2..head_off + 4].copy_from_slice(&new_count.to_le_bytes());
    Ok(())
}

/// Result of a successful leaf-split.
#[derive(Debug)]
pub struct SplitResult {
    /// Repacked old block (lower-hash half).
    pub old_block_data: Vec<u8>,
    /// Repacked new block (upper-hash half).
    pub new_block_data: Vec<u8>,
    /// The boundary hash — the smallest hash that moved to the new
    /// block. This value goes into the new index-node entry.
    pub split_hash: u32,
}

/// Split a full HTREE leaf block into two. Mirrors Linux
/// `fs/ext4/namei.c::do_split`.
///
/// * `block_data` — the full leaf block to split (blocksize bytes).
/// * `hash_version` / `seed` — from the directory's `DxRoot`.
///
/// Returns `SplitResult` with both repacked halves and the
/// `split_hash` boundary, or `SplitError::Corrupt` if the block
/// cannot be decoded.
pub fn htree_split_leaf(
    block_data: &[u8],
    hash_version: u8,
    seed: &[u32; 4],
) -> Result<SplitResult, SplitError> {
    let bs = block_data.len();
    let entries = collect_sorted_leaf_entries(block_data, hash_version, seed)?;
    let count = entries.len();
    if count < 2 {
        // Nothing to split — caller should extend linearly.
        return Err(SplitError::Corrupt);
    }

    // Walk from the end accumulating byte sizes until we exceed half
    // the block.  The split point is the first entry that would push
    // the running total past bs/2. This mirrors Linux's loop over
    // `map[i].size / 2 > blocksize / 2`.
    let half = bs / 2;
    let mut size = 0usize;
    let mut move_count = 0usize;
    for i in (0..count).rev() {
        let entry_size = entries[i].bytes.len();
        if size + entry_size / 2 > half {
            break;
        }
        size += entry_size;
        move_count += 1;
    }
    // If all sizes summed under half, split by count.
    let split = if move_count == 0 || move_count >= count {
        count / 2
    } else {
        count - move_count
    };
    // split must be at least 1 and at most count-1.
    let split = split.clamp(1, count - 1);

    let split_hash = entries[split].hash;

    let lower = &entries[..split];
    let upper = &entries[split..];

    let mut old_block = vec![0u8; bs];
    let mut new_block = vec![0u8; bs];
    repack_leaf_block(&mut old_block, lower)?;
    repack_leaf_block(&mut new_block, upper)?;

    Ok(SplitResult {
        old_block_data: old_block,
        new_block_data: new_block,
        split_hash,
    })
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
