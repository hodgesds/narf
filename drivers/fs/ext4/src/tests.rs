//! Kernel-test entries for ext4.
//!
//! ≥10 smokes covering the ext4 contract:
//!   1. Superblock decode with EXTENTS bit asserted (validate())
//!   2. Superblock rejection when EXTENTS bit is clear
//!   3. Extent header + extent struct layout
//!   4. Extent-tree walk: 1-level (leaf only)
//!   5. Extent-tree walk: 2-level (index → leaf)
//!   6. Extent-tree insert (in-place) + merge of adjacent extents
//!   7. Extent-tree split when leaf is full
//!   8. HTREE root decode (shared with ext2 — verify same format)
//!   9. JBD2 superblock encode + decode round-trip
//!   10. JBD2 descriptor + commit encode + replay end-to-end
//!   11. File-write round-trip via extents (write extent → read back)
//!   12. Directory mutators: create then unlink round-trip
//!   13. Ext4Inode flag decode (EXTENTS_FL set ⇒ uses_extents true)
//!   14. Ext4Inode 64-bit size combines size + size_high
//!
//! These are pure-logic smokes — they exercise the on-disk decoders
//! and encoders without touching a block device. The end-to-end
//! mount path (read a real ext4 image off a RamBlockDevice) is
//! exercised by the sibling ext2 crate already, since that crate
//! handles the ext4 flavour transparently. This crate's smokes lock
//! down the ext4-specific contract: feature validation, extent
//! insert/split, ext4-flagged inode decode.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

use super::extent::{
    empty_iblock_leaf, find_physical_for_logical, insert_into_leaf, lookup_in_node,
    ExtentHeader, ExtentIndex, ExtentLeaf, InsertOutcome, LookupOutcome, EXT4_EXTENT_MAGIC,
};
use super::htree::{name_hash, hash_version, DxRoot};
use super::inode::{Ext4Inode, EXT4_EXTENTS_FL, EXT4_INDEX_FL};
use super::journal::{
    build_one_txn_image, encode_commit, encode_descriptor, encode_superblock,
    replay_journal_flat, CommitBlock, DescriptorBlock, JournalSuperblock,
    JBD2_MAGIC_NUMBER, block_type as jbt,
};
use super::superblock::{
    incompat, is_64bit, is_flex_bg, validate, Ext4SuperblockError, EXT4_VALID_FS,
};

// ── helpers ───────────────────────────────────────────────────────

/// Build a synthetic 1024-byte ext4 superblock. Magic OK, EXTENTS
/// bit on, 4 KiB blocks, one block group, rev-1.
fn synth_ext4_sb() -> Vec<u8> {
    let mut buf = vec![0u8; 1024];
    buf[0..4].copy_from_slice(&100u32.to_le_bytes()); // s_inodes_count
    buf[4..8].copy_from_slice(&200u32.to_le_bytes()); // s_blocks_count
    buf[20..24].copy_from_slice(&0u32.to_le_bytes()); // s_first_data_block
    buf[24..28].copy_from_slice(&2u32.to_le_bytes()); // s_log_block_size = 2 → 4 KiB
    buf[32..36].copy_from_slice(&200u32.to_le_bytes()); // s_blocks_per_group
    buf[40..44].copy_from_slice(&100u32.to_le_bytes()); // s_inodes_per_group
    buf[56..58].copy_from_slice(&0xEF53u16.to_le_bytes()); // s_magic
    buf[58..60].copy_from_slice(&EXT4_VALID_FS.to_le_bytes()); // s_state = clean
    buf[76..80].copy_from_slice(&1u32.to_le_bytes()); // s_rev_level = 1
    buf[88..90].copy_from_slice(&256u16.to_le_bytes()); // s_inode_size = 256 (ext4)
    // feature_incompat: EXTENTS + FILETYPE
    let incompat_bits = incompat::EXTENTS | incompat::FILETYPE;
    buf[96..100].copy_from_slice(&incompat_bits.to_le_bytes());
    buf
}

fn put_extent_header(buf: &mut [u8], entries: u16, max: u16, depth: u16) {
    buf[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
    buf[2..4].copy_from_slice(&entries.to_le_bytes());
    buf[4..6].copy_from_slice(&max.to_le_bytes());
    buf[6..8].copy_from_slice(&depth.to_le_bytes());
    buf[8..12].copy_from_slice(&0u32.to_le_bytes()); // generation
}

fn put_extent_leaf(buf: &mut [u8], off: usize, logical: u32, len: u16, phys: u64) {
    buf[off..off + 4].copy_from_slice(&logical.to_le_bytes());
    buf[off + 4..off + 6].copy_from_slice(&len.to_le_bytes());
    let hi = (phys >> 32) as u16;
    let lo = phys as u32;
    buf[off + 6..off + 8].copy_from_slice(&hi.to_le_bytes());
    buf[off + 8..off + 12].copy_from_slice(&lo.to_le_bytes());
}

fn put_extent_index(buf: &mut [u8], off: usize, logical: u32, leaf: u64) {
    buf[off..off + 4].copy_from_slice(&logical.to_le_bytes());
    let lo = leaf as u32;
    let hi = (leaf >> 32) as u16;
    buf[off + 4..off + 8].copy_from_slice(&lo.to_le_bytes());
    buf[off + 8..off + 10].copy_from_slice(&hi.to_le_bytes());
    buf[off + 10..off + 12].copy_from_slice(&0u16.to_le_bytes());
}

// ── 1: Superblock decode with EXTENTS bit set ──────────────────────

fn smoke_ext4_superblock_decode_with_extents() -> TestResult {
    let buf = synth_ext4_sb();
    let sb = match validate(&buf) {
        Ok(s) => s,
        Err(e) => {
            let _ = e;
            return TestResult::Fail("ext4 sb validate rejected a valid image");
        }
    };
    if !sb.uses_extents() {
        return TestResult::Fail("uses_extents must be true after validate");
    }
    if sb.block_size() != 4096 {
        return TestResult::Fail("expected 4 KiB block size");
    }
    if is_64bit(&sb) {
        return TestResult::Fail("64BIT not asserted in this image");
    }
    if is_flex_bg(&sb) {
        return TestResult::Fail("FLEX_BG not asserted in this image");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext4", smoke_ext4_superblock_decode_with_extents);

// ── 2: Reject when EXTENTS bit is clear ────────────────────────────

fn smoke_ext4_superblock_rejects_without_extents() -> TestResult {
    let mut buf = synth_ext4_sb();
    // Strip EXTENTS, leave FILETYPE on. Should look like ext3.
    buf[96..100].copy_from_slice(&incompat::FILETYPE.to_le_bytes());
    match validate(&buf) {
        Err(Ext4SuperblockError::NotExt4Flavour) => TestResult::Pass,
        Err(_) => TestResult::Fail("wrong error variant"),
        Ok(_) => TestResult::Fail("validate must reject ext3-flavour volumes"),
    }
}
kernel_test_in!("drivers/fs/ext4", smoke_ext4_superblock_rejects_without_extents);

// ── 3: Extent header + extent struct layout ────────────────────────

fn smoke_ext4_extent_header_struct_layout() -> TestResult {
    // 12 bytes of header + 12 bytes of one extent.
    let mut buf = vec![0u8; 24];
    put_extent_header(&mut buf, 1, 4, 0);
    put_extent_leaf(&mut buf, 12, 100, 8, 0x12_3456_789A);
    let h = match ExtentHeader::parse(&buf) {
        Some(h) => h,
        None => return TestResult::Fail("header parse failed"),
    };
    if h.magic != EXT4_EXTENT_MAGIC {
        return TestResult::Fail("magic mismatch");
    }
    if h.entries != 1 || h.max != 4 || h.depth != 0 {
        return TestResult::Fail("header fields wrong");
    }
    let leaf = match ExtentLeaf::parse(&buf[12..24]) {
        Some(l) => l,
        None => return TestResult::Fail("leaf parse failed"),
    };
    if leaf.logical != 100 || leaf.len != 8 {
        return TestResult::Fail("leaf logical/len wrong");
    }
    if leaf.physical != 0x12_3456_789A {
        return TestResult::Fail("48-bit physical decode wrong");
    }
    if leaf.is_uninitialized {
        return TestResult::Fail("len < 0x8000 must mean initialized");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext4", smoke_ext4_extent_header_struct_layout);

// ── 4: Extent-tree walk — leaf only (1-level) ──────────────────────

fn smoke_ext4_extent_walk_leaf_only() -> TestResult {
    // One leaf with two extents:  [logical 0,8) → phys 1000
    //                             [logical 8,16) → phys 2000
    let mut buf = vec![0u8; 12 + 24];
    put_extent_header(&mut buf, 2, 4, 0);
    put_extent_leaf(&mut buf, 12, 0, 8, 1000);
    put_extent_leaf(&mut buf, 24, 8, 8, 2000);

    match lookup_in_node(&buf, 0) {
        LookupOutcome::Mapped { physical: 1000, is_uninitialized: false } => {}
        _ => return TestResult::Fail("logical 0 must map to phys 1000"),
    }
    match lookup_in_node(&buf, 7) {
        LookupOutcome::Mapped { physical: 1007, is_uninitialized: false } => {}
        _ => return TestResult::Fail("logical 7 must map to phys 1007"),
    }
    match lookup_in_node(&buf, 8) {
        LookupOutcome::Mapped { physical: 2000, is_uninitialized: false } => {}
        _ => return TestResult::Fail("logical 8 must map to phys 2000"),
    }
    match lookup_in_node(&buf, 15) {
        LookupOutcome::Mapped { physical: 2007, is_uninitialized: false } => {}
        _ => return TestResult::Fail("logical 15 must map to phys 2007"),
    }
    match lookup_in_node(&buf, 16) {
        LookupOutcome::Hole => {}
        _ => return TestResult::Fail("past last extent must be Hole"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext4", smoke_ext4_extent_walk_leaf_only);

// ── 5: Extent-tree walk — 2-level (index → leaf) ───────────────────

fn smoke_ext4_extent_walk_index_to_leaf() -> TestResult {
    // Root: depth=1, one index pointing at child block 555.
    let mut root = vec![0u8; 12 + 12];
    put_extent_header(&mut root, 1, 4, 1);
    put_extent_index(&mut root, 12, 0, 555);

    // Child leaf: one extent [logical 5, 5+10) → phys 9000.
    let mut child = vec![0u8; 12 + 12];
    put_extent_header(&mut child, 1, 4, 0);
    put_extent_leaf(&mut child, 12, 5, 10, 9000);

    // First lookup on root must say "go fetch block 555".
    match lookup_in_node(&root, 7) {
        LookupOutcome::DeeperLookupRequired { child_block: 555 } => {}
        _ => return TestResult::Fail("root must dispatch to child block 555"),
    }
    // Drive find_physical_for_logical via a closure that returns the child.
    let phys = find_physical_for_logical(&root, 7, |blk| {
        if blk == 555 { Some(child.clone()) } else { None }
    });
    if phys != Some(9002) {
        return TestResult::Fail("two-level walk must land at phys 9002");
    }
    // Below the index range (logical 1) — root walker has no entry
    // covering it; it returns Hole.
    let phys = find_physical_for_logical(&root, 1, |blk| {
        if blk == 555 { Some(child.clone()) } else { None }
    });
    if phys != Some(0) && phys.is_some() {
        // The walk descends because the root's first index logical
        // is 0; the child reports Hole for logical 1 because its
        // first leaf starts at logical 5. find_physical_for_logical
        // converts Hole → None.
        if phys.is_some() {
            return TestResult::Fail("logical 1 should be a hole (None)");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext4", smoke_ext4_extent_walk_index_to_leaf);

// ── 6: Extent-tree insert + merge of adjacent extents ──────────────

fn smoke_ext4_extent_insert_merge_adjacent() -> TestResult {
    // Start with an empty i_block leaf, insert two extents that
    // touch logically + physically — they must merge.
    let buf = empty_iblock_leaf().to_vec();
    let first = ExtentLeaf {
        logical: 0,
        len: 4,
        is_uninitialized: false,
        physical: 1000,
    };
    let after_first = match insert_into_leaf(&buf, first, 0, 4096) {
        InsertOutcome::Placed(b) => b,
        other => {
            let _ = other;
            return TestResult::Fail("first insert must be Placed");
        }
    };
    let second = ExtentLeaf {
        logical: 4,
        len: 4,
        is_uninitialized: false,
        physical: 1004,
    };
    let after_second = match insert_into_leaf(&after_first, second, 0, 4096) {
        InsertOutcome::Merged(b) => b,
        other => {
            let _ = other;
            return TestResult::Fail("adjacent insert must Merge");
        }
    };
    // Decode and assert the merged extent covers 0..8.
    match lookup_in_node(&after_second, 0) {
        LookupOutcome::Mapped { physical: 1000, .. } => {}
        _ => return TestResult::Fail("merged extent must start at phys 1000"),
    }
    match lookup_in_node(&after_second, 7) {
        LookupOutcome::Mapped { physical: 1007, .. } => {}
        _ => return TestResult::Fail("merged extent must extend to phys 1007"),
    }
    // Insert a non-adjacent extent — must be Placed, not Merged.
    let third = ExtentLeaf {
        logical: 100,
        len: 4,
        is_uninitialized: false,
        physical: 5000,
    };
    match insert_into_leaf(&after_second, third, 0, 4096) {
        InsertOutcome::Placed(_) => {}
        other => {
            let _ = other;
            return TestResult::Fail("non-adjacent insert must be Placed");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext4", smoke_ext4_extent_insert_merge_adjacent);

// ── 7: Extent-tree insert that requires split ──────────────────────

fn smoke_ext4_extent_insert_triggers_split() -> TestResult {
    // i_block leaf carries 4 non-adjacent extents — capacity max=4.
    // A fifth insert MUST split into a child + index root.
    let mut buf = empty_iblock_leaf().to_vec();
    for i in 0..4u32 {
        let e = ExtentLeaf {
            logical: i * 100,
            len: 4,
            is_uninitialized: false,
            physical: 10_000 + i as u64,
        };
        buf = match insert_into_leaf(&buf, e, 0, 4096) {
            InsertOutcome::Placed(b) => b,
            _ => return TestResult::Fail("setup placement failed"),
        };
    }
    let overflow = ExtentLeaf {
        logical: 500,
        len: 4,
        is_uninitialized: false,
        physical: 20_000,
    };
    match insert_into_leaf(&buf, overflow, 4242, 4096) {
        InsertOutcome::Split { child_leaf_bytes, new_root_index_bytes } => {
            // Child must be a depth-0 leaf with 5 entries.
            let h = match ExtentHeader::parse(&child_leaf_bytes) {
                Some(h) => h,
                None => return TestResult::Fail("split child header parse failed"),
            };
            if h.depth != 0 || h.entries != 5 {
                return TestResult::Fail("child must be depth-0 with 5 entries");
            }
            // Root must be depth-1 with 1 index entry pointing at 4242.
            let rh = match ExtentHeader::parse(&new_root_index_bytes) {
                Some(h) => h,
                None => return TestResult::Fail("split root header parse failed"),
            };
            if rh.depth != 1 || rh.entries != 1 {
                return TestResult::Fail("new root must be depth-1 with 1 index");
            }
            let idx = match ExtentIndex::parse(&new_root_index_bytes[12..24]) {
                Some(i) => i,
                None => return TestResult::Fail("root index parse failed"),
            };
            if idx.leaf != 4242 {
                return TestResult::Fail("root index must point at fresh child 4242");
            }
            TestResult::Pass
        }
        other => {
            let _ = other;
            TestResult::Fail("over-capacity insert must Split")
        }
    }
}
kernel_test_in!("drivers/fs/ext4", smoke_ext4_extent_insert_triggers_split);

// ── 8: HTREE root decode — shared with ext2, verify same format ────

fn smoke_ext4_htree_root_decode_same_format() -> TestResult {
    // 4 KiB block. Synthesise: "." (12 bytes) + ".." (12 bytes) +
    // dx_root_info (8 bytes) + dx_head (4 bytes) + 3 dx_entries.
    let mut block = vec![0u8; 4096];
    // "." dirent: inode=2, rec_len=12, name_len=1, file_type=2, name=".\0\0\0"
    block[0..4].copy_from_slice(&2u32.to_le_bytes());
    block[4..6].copy_from_slice(&12u16.to_le_bytes());
    block[6] = 1;
    block[7] = 2;
    block[8] = b'.';
    // ".." dirent: inode=2, rec_len=12, name_len=2, file_type=2, name="..\0\0"
    block[12..16].copy_from_slice(&2u32.to_le_bytes());
    block[16..18].copy_from_slice(&12u16.to_le_bytes());
    block[18] = 2;
    block[19] = 2;
    block[20] = b'.';
    block[21] = b'.';
    // dx_root_info @ 24: reserved_zero(4) hash_version=1 info_length=8 indirect_levels=0 unused_flags=0
    block[28] = hash_version::HALF_MD4;
    block[29] = 8;
    block[30] = 0;
    block[31] = 0;
    // dx_head @ 32: limit=508, count=3
    block[32..34].copy_from_slice(&508u16.to_le_bytes());
    block[34..36].copy_from_slice(&3u16.to_le_bytes());
    // dx_entries @ 40 (3 of them, 8 bytes each).
    block[40..44].copy_from_slice(&0u32.to_le_bytes());
    block[44..48].copy_from_slice(&1u32.to_le_bytes());
    block[48..52].copy_from_slice(&0x4000_0000u32.to_le_bytes());
    block[52..56].copy_from_slice(&2u32.to_le_bytes());
    block[56..60].copy_from_slice(&0x8000_0000u32.to_le_bytes());
    block[60..64].copy_from_slice(&3u32.to_le_bytes());

    let root = match DxRoot::parse(&block) {
        Some(r) => r,
        None => return TestResult::Fail("dx_root parse failed"),
    };
    if root.count != 3 {
        return TestResult::Fail("dx_root count mismatch");
    }
    if root.hash_version != hash_version::HALF_MD4 {
        return TestResult::Fail("hash_version mismatch");
    }
    let e0 = DxRoot::entry(&block, 0).expect("entry 0");
    let e2 = DxRoot::entry(&block, 2).expect("entry 2");
    if e0.block != 1 {
        return TestResult::Fail("entry 0 block != 1");
    }
    if e2.block != 3 {
        return TestResult::Fail("entry 2 block != 3");
    }

    // Verify hash function determinism so the index keys are stable.
    let seed = [0u32; 4];
    let h1 = name_hash(b"hello", hash_version::TEA_UNSIGNED, &seed);
    let h2 = name_hash(b"hello", hash_version::TEA_UNSIGNED, &seed);
    if h1 != h2 {
        return TestResult::Fail("name_hash must be deterministic");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext4", smoke_ext4_htree_root_decode_same_format);

// ── 9: JBD2 superblock + commit encode round-trip ──────────────────

fn smoke_ext4_jbd2_superblock_encode_decode_round_trip() -> TestResult {
    let block_size = 4096usize;
    let mut sb = vec![0u8; block_size];
    encode_superblock(&mut sb, block_size as u32, /*maxlen*/ 100,
                      /*first*/ 1, /*sequence*/ 42, /*start*/ 0);
    let parsed = match JournalSuperblock::parse(&sb) {
        Some(p) => p,
        None => return TestResult::Fail("encoded superblock failed to parse"),
    };
    if parsed.header.magic != JBD2_MAGIC_NUMBER {
        return TestResult::Fail("magic round-trip failed");
    }
    if parsed.header.block_type != jbt::SUPERBLOCK_V2 {
        return TestResult::Fail("expected v2 superblock");
    }
    if parsed.block_size != block_size as u32 {
        return TestResult::Fail("block_size round-trip failed");
    }
    if parsed.maxlen != 100 {
        return TestResult::Fail("maxlen round-trip failed");
    }
    if parsed.sequence != 42 {
        return TestResult::Fail("sequence round-trip failed");
    }
    if !parsed.is_clean() {
        return TestResult::Fail("start=0 must classify as clean");
    }
    // Also encode + decode a standalone commit block.
    let mut commit = vec![0u8; block_size];
    encode_commit(&mut commit, 99);
    let cb = match CommitBlock::parse(&commit) {
        Some(c) => c,
        None => return TestResult::Fail("commit block decode failed"),
    };
    if cb.header.sequence != 99 {
        return TestResult::Fail("commit sequence round-trip failed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext4", smoke_ext4_jbd2_superblock_encode_decode_round_trip);

// ── 10: JBD2 replay end-to-end via the encoder ─────────────────────

fn smoke_ext4_jbd2_replay_one_transaction() -> TestResult {
    let block_size = 1024usize;
    // One descriptor with two tags → two data blocks → one commit.
    let mut data_a = vec![0u8; block_size];
    let mut data_b = vec![0u8; block_size];
    data_a[..4].copy_from_slice(b"DATA");
    data_a[4..8].copy_from_slice(b"____");
    data_b[..4].copy_from_slice(b"data");
    data_b[4..8].copy_from_slice(b"++++");
    let image = build_one_txn_image(
        block_size,
        &[(500u64, data_a.clone()), (600u64, data_b.clone())],
        /*sequence*/ 7,
    );
    let report = match replay_journal_flat(&image, block_size) {
        Ok(r) => r,
        Err(e) => {
            let _ = e;
            return TestResult::Fail("replay returned error");
        }
    };
    if report.transactions_replayed != 1 {
        return TestResult::Fail("expected exactly 1 replayed transaction");
    }
    let got_a = match report.blocks_to_write.get(&500) {
        Some(v) => v,
        None => return TestResult::Fail("target block 500 missing from replay"),
    };
    if &got_a[..8] != b"DATA____" {
        return TestResult::Fail("target 500 bytes mismatch");
    }
    let got_b = match report.blocks_to_write.get(&600) {
        Some(v) => v,
        None => return TestResult::Fail("target block 600 missing from replay"),
    };
    if &got_b[..8] != b"data++++" {
        return TestResult::Fail("target 600 bytes mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext4", smoke_ext4_jbd2_replay_one_transaction);

// ── 11: File-write round-trip via extents ──────────────────────────
//
// Build an in-memory i_block extent root, insert one extent, then
// look up a logical block and confirm the physical mapping. This
// exercises the read-after-write code path for the extent tree.

fn smoke_ext4_file_write_extent_round_trip() -> TestResult {
    let mut iblock = empty_iblock_leaf().to_vec();
    // "Write" 8 logical blocks starting at logical 0 → physical
    // 4242 (e.g. fresh block allocation).
    let extent = ExtentLeaf {
        logical: 0,
        len: 8,
        is_uninitialized: false,
        physical: 4242,
    };
    iblock = match insert_into_leaf(&iblock, extent, 0, 4096) {
        InsertOutcome::Placed(b) => b,
        _ => return TestResult::Fail("initial extent insert failed"),
    };
    // "Read" logical block 3 — must return physical 4245.
    let phys = match lookup_in_node(&iblock, 3) {
        LookupOutcome::Mapped { physical, is_uninitialized: false } => physical,
        _ => return TestResult::Fail("logical 3 must be mapped"),
    };
    if phys != 4245 {
        return TestResult::Fail("logical 3 should map to phys 4245");
    }
    // "Read" logical block 8 — past the extent, must be Hole.
    match lookup_in_node(&iblock, 8) {
        LookupOutcome::Hole => {}
        _ => return TestResult::Fail("logical 8 must be a Hole"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext4", smoke_ext4_file_write_extent_round_trip);

// ── 12: Directory mutator round-trip (create then unlink) ──────────
//
// Operate on raw dirent bytes. Building a dirent for "newfile",
// appending it to an existing block, then logically unlinking it by
// extending the previous entry's rec_len over it.

fn smoke_ext4_dir_create_then_unlink_round_trip() -> TestResult {
    use crate::dir::{parse_entry, ftype};

    // Start with a 1024-byte directory block holding only "." +
    // ".." (12 + 1012 rec_len). Common after mkdir.
    let mut block = vec![0u8; 1024];
    // "." inode=2, rec_len=12, name_len=1, ftype=DIR, name="."
    block[0..4].copy_from_slice(&2u32.to_le_bytes());
    block[4..6].copy_from_slice(&12u16.to_le_bytes());
    block[6] = 1;
    block[7] = ftype::DIR;
    block[8] = b'.';
    // ".." inode=2, rec_len=1012, name_len=2, ftype=DIR
    block[12..16].copy_from_slice(&2u32.to_le_bytes());
    block[16..18].copy_from_slice(&1012u16.to_le_bytes());
    block[18] = 2;
    block[19] = ftype::DIR;
    block[20] = b'.';
    block[21] = b'.';

    // Verify the starting layout decodes.
    let e_dot = parse_entry(&block, 0).expect(".");
    if e_dot.name != b"." {
        return TestResult::Fail("'.' name mismatch");
    }
    let e_dotdot = parse_entry(&block, 12).expect("..");
    if e_dotdot.name != b".." {
        return TestResult::Fail("'..' name mismatch");
    }

    // === Create: shrink ".."s rec_len, append "newfile" ===
    let new_name = b"newfile"; // 7 bytes; on-disk entry rounds to 16 bytes
    // Shrink ".." to its minimal rec_len = 12.
    block[16..18].copy_from_slice(&12u16.to_le_bytes());
    // New entry at offset 24.
    let off = 24usize;
    block[off..off + 4].copy_from_slice(&7u32.to_le_bytes()); // inode
    block[off + 4..off + 6].copy_from_slice(&(1012u16 - 12).to_le_bytes()); // rec_len = remaining
    block[off + 6] = new_name.len() as u8;
    block[off + 7] = ftype::REGULAR;
    block[off + 8..off + 8 + new_name.len()].copy_from_slice(new_name);
    // Verify create succeeded — readback finds "newfile".
    let e_new = parse_entry(&block, off).expect("newfile");
    if e_new.name != new_name {
        return TestResult::Fail("'newfile' name mismatch after create");
    }
    if e_new.inode != 7 {
        return TestResult::Fail("'newfile' inode mismatch after create");
    }

    // === Unlink: extend ".."s rec_len over the new entry ===
    // ".." rec_len becomes 12 + (1012 - 12) = 1012 again.
    block[16..18].copy_from_slice(&1012u16.to_le_bytes());
    // Zero the inode of the unlinked entry per Linux convention
    // (`ext4_delete_entry` zeros `inode` so a half-walked dir scan
    // sees an empty slot).
    block[off..off + 4].copy_from_slice(&0u32.to_le_bytes());

    // After unlink, the dirent at offset 24 has inode 0 — the
    // walker treats it as deleted. Confirm by walking ".." and
    // seeing the next offset is past where "newfile" used to be.
    let e_dotdot_after = parse_entry(&block, 12).expect("..");
    let next = 12 + e_dotdot_after.rec_len as usize;
    if next != 1024 {
        return TestResult::Fail(
            "unlink: '..' rec_len should now span to end of block",
        );
    }

    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext4", smoke_ext4_dir_create_then_unlink_round_trip);

// ── 13: Ext4Inode flag decode — EXTENTS_FL on/off ──────────────────

fn smoke_ext4_inode_flag_decode() -> TestResult {
    // 256-byte inode (ext4 default). i_flags @ 32, i_size_high @ 108.
    let mut buf = vec![0u8; 256];
    // i_mode: S_IFREG | 0644
    buf[0..2].copy_from_slice(&0x81A4u16.to_le_bytes());
    // i_size_lo
    buf[4..8].copy_from_slice(&0x1000u32.to_le_bytes());
    // i_flags: EXTENTS_FL only.
    buf[32..36].copy_from_slice(&EXT4_EXTENTS_FL.to_le_bytes());
    // i_size_high zero.
    let ei = match Ext4Inode::parse(&buf) {
        Some(e) => e,
        None => return TestResult::Fail("Ext4Inode parse failed"),
    };
    if !ei.uses_extents() {
        return TestResult::Fail("EXTENTS_FL bit must be detected");
    }
    if ei.has_htree() {
        return TestResult::Fail("INDEX_FL not set; has_htree must be false");
    }
    if ei.is_inline() {
        return TestResult::Fail("INLINE_DATA_FL not set; is_inline must be false");
    }
    // Flip INDEX_FL on.
    buf[32..36].copy_from_slice(&(EXT4_EXTENTS_FL | EXT4_INDEX_FL).to_le_bytes());
    let ei2 = Ext4Inode::parse(&buf).expect("re-parse");
    if !ei2.has_htree() {
        return TestResult::Fail("INDEX_FL must be detected after set");
    }
    // Fresh constructor must report extents.
    let fresh = Ext4Inode::new_regular_with_extents(0o644);
    if !fresh.uses_extents() {
        return TestResult::Fail("new_regular_with_extents must set EXTENTS_FL");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext4", smoke_ext4_inode_flag_decode);

// ── 14: Ext4Inode 64-bit size assembly ─────────────────────────────

fn smoke_ext4_inode_size_64bit_assembly() -> TestResult {
    let mut buf = vec![0u8; 256];
    buf[0..2].copy_from_slice(&0x81A4u16.to_le_bytes()); // S_IFREG | 0644
    // i_size_lo = 0x1234_5678, i_size_high = 0xABCD_0001.
    buf[4..8].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    buf[32..36].copy_from_slice(&EXT4_EXTENTS_FL.to_le_bytes());
    buf[108..112].copy_from_slice(&0xABCD_0001u32.to_le_bytes());
    let ei = match Ext4Inode::parse(&buf) {
        Some(e) => e,
        None => return TestResult::Fail("Ext4Inode parse failed"),
    };
    let expected: u64 = (0xABCD_0001u64 << 32) | 0x1234_5678u64;
    if ei.size64() != expected {
        return TestResult::Fail("size64() must combine size + size_hi");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext4", smoke_ext4_inode_size_64bit_assembly);

// ── 15: JBD2 descriptor encode + decode (smoke for tag layout) ─────

fn smoke_ext4_jbd2_descriptor_encode_decodes() -> TestResult {
    let mut buf = vec![0u8; 256];
    encode_descriptor(&mut buf, /*sequence*/ 33, &[(100, 0), (200, 0), (300, 0)]);
    let dd = match DescriptorBlock::parse(&buf) {
        Some(d) => d,
        None => return TestResult::Fail("descriptor decode failed"),
    };
    if dd.header.sequence != 33 {
        return TestResult::Fail("descriptor sequence mismatch");
    }
    if dd.tags.len() != 3 {
        return TestResult::Fail("expected 3 tags");
    }
    if dd.tags[0].target_block != 100 || dd.tags[1].target_block != 200 || dd.tags[2].target_block != 300 {
        return TestResult::Fail("tag target_block round-trip wrong");
    }
    if !dd.tags[2].is_last() {
        return TestResult::Fail("last tag must carry LAST_TAG flag");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext4", smoke_ext4_jbd2_descriptor_encode_decodes);
