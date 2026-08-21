//! ext4 extent tree (replaces ext2/3 indirect-block addressing).
//!
//! ext4 stores a file's logical→physical block map as a tree of
//! **extents**. The tree's root sits in the inode's i_block[60]
//! area (the same 60-byte region ext2 used for the indirect-block
//! pointer table); for files larger than ~4 contiguous extents,
//! the root holds index entries pointing to deeper extent blocks.
//!
//! Layout (every extent / index node starts with a 12-byte
//! `ExtentHeader`):
//!
//! ```text
//!   bytes 0..2  eh_magic       = 0xF30A
//!   bytes 2..4  eh_entries     — number of entries that follow
//!   bytes 4..6  eh_max         — capacity of this node
//!   bytes 6..8  eh_depth       — 0 = leaf, >0 = index
//!   bytes 8..12 eh_generation
//! ```
//!
//! Followed by `eh_entries` x 12-byte entries:
//!
//! - **Leaf** (eh_depth == 0): `ExtentLeaf { ee_block:u32,
//!   ee_len:u16, ee_start_hi:u16, ee_start_lo:u32 }` — maps
//!   `[ee_block..ee_block+ee_len)` logical → contiguous
//!   `[start..start+ee_len)` physical (48-bit phys).
//! - **Index** (eh_depth > 0): `ExtentIndex { ei_block:u32,
//!   ei_leaf_lo:u32, ei_leaf_hi:u16, ei_unused:u16 }` — points
//!   at a child extent-block whose first leaf entry covers
//!   `ei_block`.
//!
//! Linux reference: `fs/ext4/extents.c`. Post 2026-05-20 GPL
//! relicense — direct citation allowed.

extern crate alloc;

use alloc::vec::Vec;

/// Magic value at offset 0 of every extent header. Reject the
/// extent tree (treat the inode as "no blocks") on mismatch.
pub const EXT4_EXTENT_MAGIC: u16 = 0xF30A;

/// Decoded extent header (12 bytes on disk).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ExtentHeader {
    pub magic: u16,
    pub entries: u16,
    pub max: u16,
    /// 0 = leaf node carrying `ExtentLeaf` entries;
    /// >0 = index node carrying `ExtentIndex` entries.
    pub depth: u16,
    pub generation: u32,
}

impl ExtentHeader {
    pub const LEN: usize = 12;

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::LEN {
            return None;
        }
        let magic = u16::from_le_bytes([buf[0], buf[1]]);
        if magic != EXT4_EXTENT_MAGIC {
            return None;
        }
        Some(Self {
            magic,
            entries: u16::from_le_bytes([buf[2], buf[3]]),
            max: u16::from_le_bytes([buf[4], buf[5]]),
            depth: u16::from_le_bytes([buf[6], buf[7]]),
            generation: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
        })
    }

    pub fn is_leaf(&self) -> bool {
        self.depth == 0
    }
}

/// Leaf extent — maps logical block range to contiguous physical.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ExtentLeaf {
    /// First logical block this extent covers.
    pub logical: u32,
    /// Length in blocks. `ee_len > 32768` marks an "uninitialized extent"
    /// (caller reads as zero) whose real length is `ee_len - 32768`; a value
    /// of *exactly* 32768 is a max-length INITIALIZED extent. See `parse`.
    pub len: u16,
    /// Whether the extent is marked uninitialized.
    pub is_uninitialized: bool,
    /// First physical block (48-bit; the high 16 bits live in
    /// `ee_start_hi`, the low 32 in `ee_start_lo`).
    pub physical: u64,
}

impl ExtentLeaf {
    pub const LEN: usize = 12;

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::LEN {
            return None;
        }
        let raw_len = u16::from_le_bytes([buf[4], buf[5]]);
        // ext4 (fs/ext4/ext4_extents.h): EXT_INIT_MAX_LEN = 32768. An extent is
        // uninitialized only when ee_len > 32768 (real length = ee_len - 32768);
        // ee_len <= 32768 is INITIALIZED with that exact length. ee_len == 32768
        // is therefore a max-length *initialized* extent — masking bit 15 here
        // wrongly zeroed a 128 MiB initialized run (block 0 of a 32768-block
        // extent read as a hole → "invalid ELF header" loading a large .so).
        let is_uninit = raw_len > 0x8000;
        let len = if is_uninit { raw_len - 0x8000 } else { raw_len };
        Some(Self {
            logical: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            len,
            is_uninitialized: is_uninit,
            physical: ((u16::from_le_bytes([buf[6], buf[7]]) as u64) << 32)
                | u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]) as u64,
        })
    }

    /// True iff `logical_block` falls within this extent.
    pub fn covers(&self, logical_block: u32) -> bool {
        logical_block >= self.logical && logical_block < self.logical + self.len as u32
    }

    /// Physical block backing the given logical block, or None if
    /// this extent doesn't cover it.
    pub fn translate(&self, logical_block: u32) -> Option<u64> {
        if !self.covers(logical_block) {
            return None;
        }
        Some(self.physical + (logical_block - self.logical) as u64)
    }
}

/// Index entry — points at a child extent node.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ExtentIndex {
    /// First logical block the child subtree covers.
    pub logical: u32,
    /// Block number of the child extent node (48-bit).
    pub leaf: u64,
}

impl ExtentIndex {
    pub const LEN: usize = 12;

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::LEN {
            return None;
        }
        Some(Self {
            logical: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            leaf: (u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64)
                | ((u16::from_le_bytes([buf[8], buf[9]]) as u64) << 32),
        })
    }
}

/// Result of an extent-tree lookup.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LookupOutcome {
    /// Logical block maps to this physical block. The high bit of
    /// `is_uninitialized` is propagated so the caller can return
    /// zeros for sparse-file extent regions instead of reading
    /// stale on-disk data.
    Mapped {
        physical: u64,
        is_uninitialized: bool,
    },
    /// Logical block is past the file's last extent (sparse hole or
    /// past EOF). Caller returns zeros for reads.
    Hole,
    /// Tree is malformed at this node. The caller should treat the
    /// whole inode as broken rather than silently mismap data.
    Corrupt,
    /// Logical block falls inside an index entry whose child block
    /// hasn't been read yet. Caller fetches the indicated phys
    /// block and recurses.
    DeeperLookupRequired { child_block: u64 },
}

/// Walk one extent-tree node (`buf` = 12-byte header + N entries).
/// For a leaf node, returns `Mapped` / `Hole` / `Corrupt` directly.
/// For an index node, returns `DeeperLookupRequired { child_block }`
/// naming the next block the caller should read + re-call this
/// function on. Walk terminates when a leaf returns Mapped or Hole.
pub fn lookup_in_node(buf: &[u8], logical_block: u32) -> LookupOutcome {
    let header = match ExtentHeader::parse(buf) {
        Some(h) => h,
        None => return LookupOutcome::Corrupt,
    };
    if header.entries as usize * 12 + ExtentHeader::LEN > buf.len() {
        return LookupOutcome::Corrupt;
    }
    let entries_start = ExtentHeader::LEN;
    if header.is_leaf() {
        // Find the extent that covers logical_block. Extents are
        // stored in increasing logical-block order so a linear scan
        // is fine (eh_entries ≤ eh_max ≤ ~340 for a 4-KiB block).
        for i in 0..header.entries as usize {
            let off = entries_start + i * ExtentLeaf::LEN;
            let leaf = match ExtentLeaf::parse(&buf[off..off + ExtentLeaf::LEN]) {
                Some(l) => l,
                None => return LookupOutcome::Corrupt,
            };
            if let Some(physical) = leaf.translate(logical_block) {
                return LookupOutcome::Mapped {
                    physical,
                    is_uninitialized: leaf.is_uninitialized,
                };
            }
            // Stop searching when the next leaf's logical is > us
            // (sparse file — logical_block falls in a hole between
            // extents).
            if leaf.logical > logical_block {
                return LookupOutcome::Hole;
            }
        }
        // Past the last extent.
        LookupOutcome::Hole
    } else {
        // Index node: find the index whose logical <= logical_block
        // and whose successor's logical > logical_block.
        let mut chosen: Option<ExtentIndex> = None;
        for i in 0..header.entries as usize {
            let off = entries_start + i * ExtentIndex::LEN;
            let idx = match ExtentIndex::parse(&buf[off..off + ExtentIndex::LEN]) {
                Some(i) => i,
                None => return LookupOutcome::Corrupt,
            };
            if idx.logical > logical_block {
                break;
            }
            chosen = Some(idx);
        }
        match chosen {
            Some(idx) => LookupOutcome::DeeperLookupRequired {
                child_block: idx.leaf,
            },
            None => LookupOutcome::Hole,
        }
    }
}

/// Walk every leaf extent under `buf` and collect (logical, physical,
/// len, is_uninitialized) tuples. Diagnostic / fsck-style helper —
/// the lookup path uses `lookup_in_node` instead because that's
/// O(log n) for depth-aware walks. This is a full O(n) tree walk
/// that needs a caller-supplied block-fetch callback to descend.
pub fn iter_leaf_extents(
    root_buf: &[u8],
    mut fetch_block: impl FnMut(u64) -> Option<Vec<u8>>,
) -> Vec<ExtentLeaf> {
    let mut out = Vec::new();
    let mut stack: Vec<Vec<u8>> = alloc::vec![root_buf.to_vec()];
    while let Some(buf) = stack.pop() {
        let header = match ExtentHeader::parse(&buf) {
            Some(h) => h,
            None => continue,
        };
        let entries_start = ExtentHeader::LEN;
        for i in 0..header.entries as usize {
            let off = entries_start + i * 12;
            if off + 12 > buf.len() {
                break;
            }
            if header.is_leaf() {
                if let Some(leaf) = ExtentLeaf::parse(&buf[off..off + 12]) {
                    out.push(leaf);
                }
            } else if let Some(idx) = ExtentIndex::parse(&buf[off..off + 12]) {
                if let Some(child) = fetch_block(idx.leaf) {
                    stack.push(child);
                }
            }
        }
    }
    out
}
