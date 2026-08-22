//! Kernel-test entries for ext2.
//!
//! Two tiers:
//!  - Pure-logic smokes (superblock magic + block-size decode, dirent
//!    walker, inode-to-block-group math).
//!  - End-to-end mount + read against a heap-backed `RamBlockDevice`.
//!    The image is built byte-by-byte in `build_ext2_image` — the
//!    load-bearing proof that this driver is real, not paperware.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

use super::dir::{ftype, parse_entry};
use super::group_desc::GroupDesc;
use super::inode::Inode;
use super::metadata_csum::{
    bitmap_checksum, crc32c, directory_block_checksum, extent_block_checksum, group_desc_checksum,
    htree_block_checksum, inode_checksum, seed, verify_group_desc_checksum,
    verify_htree_block_checksum, verify_inode_checksum, verify_superblock, write_bitmap_checksum,
    write_directory_block_checksum, write_extent_block_checksum, write_group_desc_checksum,
    write_htree_block_checksum, write_inode_checksum, write_superblock_checksum,
};
use super::superblock::Superblock;

// ── Pure-logic smokes ──────────────────────────────────────────────

fn smoke_ext2_superblock_magic_and_block_size() -> TestResult {
    // OSDev "Ext2 — Superblock": magic at offset 56, block size =
    // 1024 << s_log_block_size. We synthesise a 1024-byte superblock
    // with `s_log_block_size = 2` (4 KiB block) and verify the
    // decoder.
    let mut buf = vec![0u8; 1024];
    // s_inodes_count
    buf[0..4].copy_from_slice(&100u32.to_le_bytes());
    // s_blocks_count
    buf[4..8].copy_from_slice(&200u32.to_le_bytes());
    // s_first_data_block
    buf[20..24].copy_from_slice(&0u32.to_le_bytes());
    // s_log_block_size = 2 → 4096-byte blocks
    buf[24..28].copy_from_slice(&2u32.to_le_bytes());
    // s_blocks_per_group
    buf[32..36].copy_from_slice(&200u32.to_le_bytes());
    // s_inodes_per_group
    buf[40..44].copy_from_slice(&100u32.to_le_bytes());
    // s_magic
    buf[56..58].copy_from_slice(&0xEF53u16.to_le_bytes());

    let sb = match Superblock::parse(&buf) {
        Some(s) => s,
        None => return TestResult::Fail("superblock parse failed"),
    };
    if sb.magic != 0xEF53 {
        return TestResult::Fail("magic mismatch");
    }
    if sb.block_size() != 4096 {
        return TestResult::Fail("block size != 4096 for log_block_size=2");
    }
    if sb.block_group_count() != 1 {
        return TestResult::Fail("expected exactly 1 block group");
    }

    // Wrong magic must reject.
    let mut bad = buf.clone();
    bad[56..58].copy_from_slice(&0u16.to_le_bytes());
    if Superblock::parse(&bad).is_some() {
        return TestResult::Fail("parse must reject wrong magic");
    }

    TestResult::Pass
}

fn smoke_ext4_csum_seed_validates_superblock() -> TestResult {
    // CRC32C's familiar wire-format test vector includes a final xor; ext4
    // chains the raw running state, so its equivalent seed convention leaves
    // the complement here.
    if crc32c(!0, b"123456789") != 0x1cf9_6d7c {
        return TestResult::Fail("CRC32C running-state convention mismatch");
    }

    let mut buf = vec![0u8; 1024];
    buf[0..4].copy_from_slice(&16u32.to_le_bytes());
    buf[4..8].copy_from_slice(&64u32.to_le_bytes());
    buf[20..24].copy_from_slice(&1u32.to_le_bytes());
    buf[32..36].copy_from_slice(&64u32.to_le_bytes());
    buf[40..44].copy_from_slice(&16u32.to_le_bytes());
    buf[56..58].copy_from_slice(&0xef53u16.to_le_bytes());
    buf[96..100].copy_from_slice(
        &(super::superblock::incompat::EXTENTS | super::superblock::incompat::CSUM_SEED)
            .to_le_bytes(),
    );
    buf[100..104].copy_from_slice(&super::superblock::ro_compat::METADATA_CSUM.to_le_bytes());
    buf[104..120].copy_from_slice(b"narf-ext4-csum!!");
    buf[624..628].copy_from_slice(&0x4d3c_2b1au32.to_le_bytes());

    let sb = match Superblock::parse(&buf) {
        Some(sb) => sb,
        None => return TestResult::Fail("metadata-csum superblock did not parse"),
    };
    if !sb.has_metadata_csum() || !sb.uses_csum_seed() || seed(&sb) != 0x4d3c_2b1a {
        return TestResult::Fail("metadata-csum feature/seed decode mismatch");
    }
    // ext4 superblock checksum intentionally ignores csum_seed.
    let checksum = crc32c(!0, &buf[..0x3fc]);
    buf[0x3fc..0x400].copy_from_slice(&checksum.to_le_bytes());
    if !verify_superblock(&sb, &buf) {
        return TestResult::Fail("valid csum_seed superblock rejected");
    }
    buf[120] ^= 1;
    if verify_superblock(&sb, &buf) {
        return TestResult::Fail("corrupt csum_seed superblock accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext4_csum_seed_validates_superblock);

fn smoke_ext2_scratch_waitqueue_wakes_and_handoffs() -> TestResult {
    if super::volume::__test_scratch_waitqueue_wakes_and_handoffs() {
        TestResult::Pass
    } else {
        TestResult::Fail("ext2 scratch waitqueue lost a wake or cancellation handoff")
    }
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext2_scratch_waitqueue_wakes_and_handoffs
);

fn smoke_ext4_csum_seed_metadata_writers_cover_checksum_fields() -> TestResult {
    let mut sb_bytes = vec![0u8; 1024];
    sb_bytes[56..58].copy_from_slice(&0xef53u16.to_le_bytes());
    sb_bytes[96..100].copy_from_slice(&super::superblock::incompat::CSUM_SEED.to_le_bytes());
    sb_bytes[100..104].copy_from_slice(&super::superblock::ro_compat::METADATA_CSUM.to_le_bytes());
    sb_bytes[624..628].copy_from_slice(&0x4d3c_2b1au32.to_le_bytes());
    let sb = match Superblock::parse(&sb_bytes) {
        Some(sb) => sb,
        None => return TestResult::Fail("checksummed superblock did not parse"),
    };

    let mut inode = vec![0x5a; 256];
    inode[100..104].copy_from_slice(&0x0102_0304u32.to_le_bytes());
    inode[128..130].copy_from_slice(&32u16.to_le_bytes());
    let before = match inode_checksum(&sb, 42, &inode) {
        Some(v) => v,
        None => return TestResult::Fail("inode checksum unavailable"),
    };
    if write_inode_checksum(&sb, 42, &mut inode).is_none()
        || inode_checksum(&sb, 42, &inode) != Some(before)
        || !verify_inode_checksum(&sb, 42, &inode)
        || u16::from_le_bytes([inode[124], inode[125]]) != before as u16
        || u16::from_le_bytes([inode[130], inode[131]]) != (before >> 16) as u16
    {
        return TestResult::Fail("inode checksum fields were not written correctly");
    }

    let mut desc = vec![0x31; 64];
    let group_before = match group_desc_checksum(&sb, 7, &desc) {
        Some(v) => v,
        None => return TestResult::Fail("group descriptor checksum unavailable"),
    };
    if write_group_desc_checksum(&sb, 7, &mut desc).is_none()
        || group_desc_checksum(&sb, 7, &desc) != Some(group_before)
        || !verify_group_desc_checksum(&sb, 7, &desc)
    {
        return TestResult::Fail("group descriptor checksum was not stable");
    }
    let bitmap = [0x55; 64];
    if bitmap_checksum(&sb, &bitmap) == bitmap_checksum(&sb, &[0x56; 64]) {
        return TestResult::Fail("bitmap checksum did not cover bitmap bytes");
    }
    if write_bitmap_checksum(&sb, &mut desc, &bitmap, false).is_none()
        || u16::from_le_bytes([desc[0x18], desc[0x19]])
            != bitmap_checksum(&sb, &bitmap).expect("metadata checksum enabled") as u16
    {
        return TestResult::Fail("bitmap checksum was not written to descriptor");
    }

    let mut directory = vec![0u8; 1024];
    let tail = directory.len() - 12;
    directory[tail + 4..tail + 6].copy_from_slice(&12u16.to_le_bytes());
    directory[tail + 7] = 0xde;
    let dir_before = match directory_block_checksum(&sb, 42, 0x0102_0304, &directory) {
        Some(v) => v,
        None => return TestResult::Fail("directory checksum unavailable"),
    };
    if write_directory_block_checksum(&sb, 42, 0x0102_0304, &mut directory).is_none()
        || directory_block_checksum(&sb, 42, 0x0102_0304, &directory) != Some(dir_before)
    {
        return TestResult::Fail("directory checksum was not stable");
    }

    // One-level HTREE root: entry zero's hash word is the count/limit
    // overlay, and its block word immediately follows it.
    let mut htree = vec![0u8; 1024];
    htree[0..4].copy_from_slice(&42u32.to_le_bytes());
    htree[4..6].copy_from_slice(&12u16.to_le_bytes());
    htree[6] = 1;
    htree[7] = ftype::DIR;
    htree[8] = b'.';
    htree[12..16].copy_from_slice(&2u32.to_le_bytes());
    htree[16..18].copy_from_slice(&(1024u16 - 12).to_le_bytes());
    htree[18] = 2;
    htree[19] = ftype::DIR;
    htree[20..22].copy_from_slice(b"..");
    htree[28] = super::htree::hash_version::TEA;
    htree[29] = 8;
    let limit = ((1024 - 32 - 8) / 8) as u16;
    htree[32..34].copy_from_slice(&limit.to_le_bytes());
    htree[34..36].copy_from_slice(&2u16.to_le_bytes());
    htree[36..40].copy_from_slice(&1u32.to_le_bytes());
    htree[40..44].copy_from_slice(&0x8000_0000u32.to_le_bytes());
    htree[44..48].copy_from_slice(&2u32.to_le_bytes());
    let dx_tail = 32 + limit as usize * 8;
    let before = match htree_block_checksum(&sb, 42, 0x0102_0304, &htree) {
        Some(checksum) => checksum,
        None => return TestResult::Fail("HTREE checksum unavailable"),
    };
    if write_htree_block_checksum(&sb, 42, 0x0102_0304, &mut htree).is_none()
        || !verify_htree_block_checksum(&sb, 42, 0x0102_0304, &htree)
        || u32::from_le_bytes(htree[dx_tail + 4..dx_tail + 8].try_into().unwrap()) != before
    {
        return TestResult::Fail("HTREE checksum writer did not round-trip");
    }
    htree[40] ^= 1;
    if verify_htree_block_checksum(&sb, 42, 0x0102_0304, &htree) {
        return TestResult::Fail("HTREE checksum accepted a changed index entry");
    }

    let mut extent = vec![0xa5; 4096];
    let extent_before = match extent_block_checksum(&sb, 42, 0x0102_0304, &extent) {
        Some(v) => v,
        None => return TestResult::Fail("extent checksum unavailable"),
    };
    if write_extent_block_checksum(&sb, 42, 0x0102_0304, &mut extent).is_none()
        || extent_block_checksum(&sb, 42, 0x0102_0304, &extent) != Some(extent_before)
    {
        return TestResult::Fail("extent checksum was not stable");
    }
    let mut superblock = sb_bytes;
    if write_superblock_checksum(&sb, &mut superblock).is_none()
        || !verify_superblock(&sb, &superblock)
    {
        return TestResult::Fail("superblock checksum writer did not round-trip");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext4_csum_seed_metadata_writers_cover_checksum_fields
);

fn smoke_ext2_dirent_walk_two_entries() -> TestResult {
    // Synthesise a 64-byte directory block with two entries:
    //   { inode=2, rec_len=12, name_len=1, file_type=DIR, name="." }
    //   { inode=3, rec_len=52, name_len=8, file_type=REG,
    //     name="hello.txt" + pad to 52 bytes }
    let mut buf = vec![0u8; 64];

    // Entry 0
    buf[0..4].copy_from_slice(&2u32.to_le_bytes());
    buf[4..6].copy_from_slice(&12u16.to_le_bytes());
    buf[6] = 1;
    buf[7] = ftype::DIR;
    buf[8] = b'.';
    // (bytes 9-11 are padding; rec_len = 12 advances past them)

    // Entry 1
    buf[12..16].copy_from_slice(&3u32.to_le_bytes());
    buf[16..18].copy_from_slice(&52u16.to_le_bytes());
    buf[18] = 8;
    buf[19] = ftype::REGULAR;
    buf[20..28].copy_from_slice(b"hi.world"); // 8 bytes
                                              // bytes 28..64 are padding

    // First entry
    let e0 = match parse_entry(&buf, 0) {
        Some(e) => e,
        None => return TestResult::Fail("entry 0 parse failed"),
    };
    if e0.inode != 2 || e0.rec_len != 12 || e0.name != b"." {
        return TestResult::Fail("entry 0 fields mismatch");
    }
    if e0.file_type != ftype::DIR {
        return TestResult::Fail("entry 0 file_type mismatch");
    }

    let e1 = match parse_entry(&buf, 12) {
        Some(e) => e,
        None => return TestResult::Fail("entry 1 parse failed"),
    };
    if e1.inode != 3 || e1.rec_len != 52 || e1.name != b"hi.world" {
        return TestResult::Fail("entry 1 fields mismatch");
    }
    if e1.file_type != ftype::REGULAR {
        return TestResult::Fail("entry 1 file_type mismatch");
    }

    // Out-of-bounds rec_len must fail
    let mut bad = vec![0u8; 16];
    bad[0..4].copy_from_slice(&5u32.to_le_bytes());
    bad[4..6].copy_from_slice(&100u16.to_le_bytes()); // rec_len too big
    bad[6] = 4;
    bad[7] = 1;
    if parse_entry(&bad, 0).is_some() {
        return TestResult::Fail("oversized rec_len must reject");
    }

    TestResult::Pass
}

fn smoke_ext2_inode_group_index_math() -> TestResult {
    // (inode - 1) / s_inodes_per_group = group index;
    // (inode - 1) % s_inodes_per_group = slot inside the group.
    // From the design paper §"Inodes".
    let inodes_per_group: u32 = 32;

    let pairs: &[(u32, u32, u32)] = &[
        (1, 0, 0),
        (2, 0, 1), // root
        (32, 0, 31),
        (33, 1, 0),
        (64, 1, 31),
        (65, 2, 0),
    ];
    for &(ino, group, idx) in pairs {
        let zero = ino - 1;
        let g = zero / inodes_per_group;
        let i = zero % inodes_per_group;
        if g != group || i != idx {
            return TestResult::Fail("inode group/index math wrong");
        }
    }

    TestResult::Pass
}

fn smoke_ext2_group_desc_parse() -> TestResult {
    // 32-byte group descriptor with hand-picked values.
    let mut buf = vec![0u8; 32];
    buf[0..4].copy_from_slice(&3u32.to_le_bytes()); // bg_block_bitmap
    buf[4..8].copy_from_slice(&4u32.to_le_bytes()); // bg_inode_bitmap
    buf[8..12].copy_from_slice(&5u32.to_le_bytes()); // bg_inode_table
    buf[12..14].copy_from_slice(&100u16.to_le_bytes()); // free blocks
    buf[14..16].copy_from_slice(&50u16.to_le_bytes()); // free inodes
    buf[16..18].copy_from_slice(&7u16.to_le_bytes()); // used dirs

    let gd = match GroupDesc::parse(&buf) {
        Some(g) => g,
        None => return TestResult::Fail("group desc parse failed"),
    };
    if gd.block_bitmap != 3
        || gd.inode_bitmap != 4
        || gd.inode_table != 5
        || gd.free_blocks_count != 100
        || gd.free_inodes_count != 50
        || gd.used_dirs_count != 7
    {
        return TestResult::Fail("group desc field mismatch");
    }
    TestResult::Pass
}

fn smoke_ext2_inode_parse_block_pointers() -> TestResult {
    // 128-byte inode with a directory mode + a couple of direct
    // block pointers + a single-indirect pointer.
    let mut buf = vec![0u8; 128];
    buf[0..2].copy_from_slice(&0x41EDu16.to_le_bytes()); // S_IFDIR | 0755
    buf[2..4].copy_from_slice(&0x5678u16.to_le_bytes()); // i_uid low
    buf[4..8].copy_from_slice(&1024u32.to_le_bytes()); // size
    buf[28..32].copy_from_slice(&2u32.to_le_bytes()); // i_blocks (sectors)
    buf[24..26].copy_from_slice(&0xdef0u16.to_le_bytes()); // i_gid low
    buf[120..122].copy_from_slice(&0x1234u16.to_le_bytes()); // i_uid high
    buf[122..124].copy_from_slice(&0x9abcu16.to_le_bytes()); // i_gid high
                                                             // i_block[0..14]
    let ptrs: [u32; 15] = [
        9, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 12 direct
        77, 0, 0, // single, double, triple
    ];
    for (i, p) in ptrs.iter().enumerate() {
        let off = 40 + i * 4;
        buf[off..off + 4].copy_from_slice(&p.to_le_bytes());
    }

    let inode = match Inode::parse(&buf) {
        Some(i) => i,
        None => return TestResult::Fail("inode parse failed"),
    };
    if !inode.is_dir() {
        return TestResult::Fail("S_IFDIR not detected");
    }
    if inode.size != 1024 {
        return TestResult::Fail("size mismatch");
    }
    if inode.uid != 0x1234_5678 || inode.gid != 0x9abc_def0 {
        return TestResult::Fail("32-bit inode owners mismatch");
    }
    if inode.block[0] != 9 || inode.block[1] != 10 || inode.block[12] != 77 {
        return TestResult::Fail("block pointer mismatch");
    }
    let mut encoded = vec![0u8; 128];
    inode.encode_into(&mut encoded);
    let reparsed = match Inode::parse(&encoded) {
        Some(inode) => inode,
        None => return TestResult::Fail("encoded inode did not parse"),
    };
    if reparsed.uid != inode.uid || reparsed.gid != inode.gid {
        return TestResult::Fail("32-bit inode owners did not encode round-trip");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext2_superblock_magic_and_block_size
);
kernel_test_in!("drivers/fs/ext2", smoke_ext2_dirent_walk_two_entries);
kernel_test_in!("drivers/fs/ext2", smoke_ext2_inode_group_index_math);
kernel_test_in!("drivers/fs/ext2", smoke_ext2_group_desc_parse);
kernel_test_in!("drivers/fs/ext2", smoke_ext2_inode_parse_block_pointers);

// ── End-to-end mount + read against RamBlockDevice ─────────────────

/// Synchronous-only future poll. RamBlockDevice's `submit` returns
/// `Ready` after the in-memory copy, so every ext2 op completes on
/// the first poll.
fn poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn raw_waker() -> RawWaker {
        unsafe fn no_clone(_: *const ()) -> RawWaker {
            raw_waker()
        }
        unsafe fn no_op(_: *const ()) {}
        const VTAB: RawWakerVTable = RawWakerVTable::new(no_clone, no_op, no_op, no_op);
        RawWaker::new(core::ptr::null(), &VTAB)
    }
    // SAFETY: `raw_waker()` returns a RawWaker built from `VTAB`, whose clone
    // function returns another such RawWaker and whose wake/drop functions are
    // no-ops, so every vtable contract is upheld and the null data pointer is
    // never dereferenced.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    // SAFETY: `fut` is a local owned by this function and never moved again
    // after this point (it is only polled through the returned pin), so the
    // pinning guarantee holds for the rest of the function.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let pinned = unsafe { Pin::new_unchecked(&mut fut) };
    match pinned.poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

/// Write a 32-bit LE value to `buf` at `off`.
fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

/// Build a minimal ext2 image:
///
/// - Block size: 1024
/// - 1 block group
/// - Layout (block index → contents):
///   - 0: boot/reserved
///   - 1: superblock (1024 bytes)
///   - 2: block group descriptor table (one 32-byte descriptor)
///   - 3: block bitmap (1 block)
///   - 4: inode bitmap (1 block)
///   - 5..=8: inode table (4 blocks → 32 inodes × 128 bytes)
///   - 9: root directory data
///   - 10: file data
///
/// Inode 2 = root directory (mode S_IFDIR, points to block 9).
/// Inode 12 = `data` file (mode S_IFREG, points to block 10).
fn build_ext2_image(file_data: &[u8]) -> Vec<u8> {
    const BS: usize = 1024;
    const TOTAL_BLOCKS: u32 = 64;
    const INODES_PER_GROUP: u32 = 32;
    const INODE_SIZE: u16 = 128;
    const BLOCKS_PER_GROUP: u32 = 64;

    let mut img = vec![0u8; BS * TOTAL_BLOCKS as usize];

    // ── Superblock at byte 1024 ──────────────────────────────────
    let sb = &mut img[1024..2048];
    put_u32(sb, 0, INODES_PER_GROUP); // inodes_count (single group)
    put_u32(sb, 4, TOTAL_BLOCKS); // blocks_count
    put_u32(sb, 20, 1); // s_first_data_block (1-KiB blocks)
    put_u32(sb, 24, 0); // s_log_block_size = 0 → 1024 byte blocks
    put_u32(sb, 32, BLOCKS_PER_GROUP); // blocks_per_group
    put_u32(sb, 40, INODES_PER_GROUP); // inodes_per_group
    put_u16(sb, 56, 0xEF53); // magic
    put_u32(sb, 76, 1); // s_rev_level = 1 (so s_inode_size is honoured)
    put_u16(sb, 88, INODE_SIZE); // s_inode_size

    // ── Block group descriptor at start of block 2 ──────────────
    let gdt_off = 2 * BS;
    put_u32(&mut img, gdt_off, 3); // bg_block_bitmap
    put_u32(&mut img, gdt_off + 4, 4); // bg_inode_bitmap
    put_u32(&mut img, gdt_off + 8, 5); // bg_inode_table
    put_u16(&mut img, gdt_off + 12, 0); // free blocks (we don't track in this test)
    put_u16(&mut img, gdt_off + 14, 0); // free inodes
    put_u16(&mut img, gdt_off + 16, 1); // used dirs (root)

    // ── Block bitmap (block 3) — mark blocks 0..=10 as used ─────
    // (Bitmap is little-endian per byte, bit 0 = first block in the
    // group. We only need the read path to ignore it.)
    let bm_off = 3 * BS;
    img[bm_off] = 0xFF; // blocks 0..=7 used
    img[bm_off + 1] = 0x07; // blocks 8..=10 used

    // ── Inode bitmap (block 4) — mark inodes 1, 2, 12 used ──────
    // Inode bitmap is 1-bit-per-inode; bit 0 = inode 1.
    let ibm_off = 4 * BS;
    img[ibm_off] = 0b0000_0011; // inodes 1, 2 used
    img[ibm_off + 1] = 0b0000_1000; // inode 12 used (bit 3 of byte 1)

    // ── Inode table (blocks 5..=8) ──────────────────────────────
    let itab_off = 5 * BS;

    // Root directory inode (#2) sits at index 1 of the table.
    let root_off = itab_off + INODE_SIZE as usize;
    put_u16(&mut img, root_off, 0x4000 | 0o755); // S_IFDIR | 0755
    put_u32(&mut img, root_off + 4, BS as u32); // size = 1 block
    put_u32(&mut img, root_off + 28, (BS / 512) as u32); // i_blocks
                                                         // i_block[0] = 9 (data block for the root dir)
    put_u32(&mut img, root_off + 40, 9);

    // File inode (#12) at index 11.
    let file_off = itab_off + 11 * INODE_SIZE as usize;
    put_u16(&mut img, file_off, 0x8000 | 0o644); // S_IFREG | 0644
    put_u32(&mut img, file_off + 4, file_data.len() as u32); // size
    put_u32(
        &mut img,
        file_off + 28,
        file_data.len().div_ceil(512) as u32,
    );
    if !file_data.is_empty() {
        put_u32(&mut img, file_off + 40, 10); // i_block[0] = 10
    }

    // ── Root directory data (block 9) ───────────────────────────
    // Three entries, padded so every record starts on a 4-byte
    // boundary and the last record extends to the end of the block.
    let root_data = 9 * BS;
    let mut cursor = 0usize;

    // "." → inode 2
    {
        let off = root_data + cursor;
        put_u32(&mut img, off, 2);
        put_u16(&mut img, off + 4, 12); // rec_len
        img[off + 6] = 1; // name_len
        img[off + 7] = ftype::DIR;
        img[off + 8] = b'.';
        cursor += 12;
    }

    // ".." → inode 2 (root's parent is itself in this trivial image)
    {
        let off = root_data + cursor;
        put_u32(&mut img, off, 2);
        put_u16(&mut img, off + 4, 12);
        img[off + 6] = 2;
        img[off + 7] = ftype::DIR;
        img[off + 8] = b'.';
        img[off + 9] = b'.';
        cursor += 12;
    }

    // "data" → inode 12 — last record fills the rest of the block
    {
        let off = root_data + cursor;
        let name = b"data";
        let remaining = BS - cursor;
        put_u32(&mut img, off, 12);
        put_u16(&mut img, off + 4, remaining as u16);
        img[off + 6] = name.len() as u8;
        img[off + 7] = ftype::REGULAR;
        img[off + 8..off + 8 + name.len()].copy_from_slice(name);
    }

    // ── File data (block 10) ────────────────────────────────────
    if !file_data.is_empty() {
        let data_off = 10 * BS;
        img[data_off..data_off + file_data.len()].copy_from_slice(file_data);
    }

    img
}

fn smoke_ext2_mount_ramblock_round_trip() -> TestResult {
    // End-to-end: build a minimal ext2 image, wrap it in
    // RamBlockDevice, mount via Ext2Volume::mount, enumerate the
    // root directory, look up `data`, read its bytes. Proves the
    // cap-bound DMA layer + superblock/BGDT/inode/dir walk all
    // work end-to-end.
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::{FileType, FsInstance};
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    let payload = b"narf-ext2\n";
    let img = build_ext2_image(payload);
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("Ext2Volume::mount failed"),
    };
    if volume.name() != "ext2" {
        return TestResult::Fail("expected ext2 name");
    }

    let root = volume.root();
    let entries = match poll_once(root.enumerate_async(0, 16)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("enumerate_async failed"),
    };
    // Root has ".", "..", "data". The driver's enumerator returns
    // every non-zero-inode entry; check that "data" is present.
    if !entries
        .iter()
        .any(|(n, t)| n == "data" && *t == FileType::File)
    {
        return TestResult::Fail("enumerate did not list `data` as File");
    }

    let file = match poll_once(root.lookup_async("data")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup_async data failed"),
    };
    if file.stat().size != payload.len() as u64 {
        return TestResult::Fail("stat.size mismatch");
    }
    let mut buf = [0u8; 16];
    let n = match poll_once(file.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("file.read failed"),
    };
    if n != payload.len() || &buf[..n] != payload {
        return TestResult::Fail("file content mismatch");
    }

    // NotFound for a missing name.
    use narf_filesystem::FsError;
    match poll_once(root.lookup_async("does-not-exist")) {
        Some(Err(FsError::NotFound)) => {}
        _ => return TestResult::Fail("lookup of missing name should NotFound"),
    }

    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_mount_ramblock_round_trip);

fn smoke_ext2_page_cache_reuses_1k_data_block() -> TestResult {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use narf_block::{
        ram::RamBlockDevice, BlockCompletion, BlockDevice, BlockFeature, BlockOp, BlockRequest,
        CancelResult, LbaRange,
    };
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    struct CountingBlock {
        inner: Arc<RamBlockDevice>,
        reads: AtomicUsize,
    }

    impl BlockDevice for CountingBlock {
        fn logical_block_size(&self) -> u32 {
            self.inner.logical_block_size()
        }
        fn physical_block_size(&self) -> u32 {
            self.inner.physical_block_size()
        }
        fn capacity_blocks(&self) -> u64 {
            self.inner.capacity_blocks()
        }
        fn supports(&self, feature: BlockFeature) -> bool {
            self.inner.supports(feature)
        }
        fn submit(
            &self,
            request: BlockRequest,
        ) -> impl core::future::Future<Output = BlockCompletion> + Send {
            if matches!(request.op, BlockOp::Read) {
                self.reads.fetch_add(1, Ordering::Relaxed);
            }
            self.inner.submit(request)
        }
        fn flush(&self) -> impl core::future::Future<Output = ()> + Send {
            self.inner.flush()
        }
        fn discard(&self, range: LbaRange) -> impl core::future::Future<Output = ()> + Send {
            self.inner.discard(range)
        }
        fn cancel(&self, tag: u64) -> impl core::future::Future<Output = CancelResult> + Send {
            self.inner.cancel(tag)
        }
    }

    let device = Arc::new(CountingBlock {
        inner: RamBlockDevice::from_image(512, build_ext2_image(b"page cache")),
        reads: AtomicUsize::new(0),
    });
    let volume = match poll_once(Ext2Volume::mount(device.clone(), DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = volume.root();
    let file = match poll_once(root.lookup_async("data")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup failed"),
    };
    let mut first = [0u8; 10];
    if !matches!(poll_once(file.read(0, &mut first)), Some(Ok(10))) {
        return TestResult::Fail("first read failed");
    }
    let reads_after_first = device.reads.load(Ordering::Relaxed);
    let mut second = [0u8; 10];
    if !matches!(poll_once(file.read(0, &mut second)), Some(Ok(10))) {
        return TestResult::Fail("second read failed");
    }
    if first != second || device.reads.load(Ordering::Relaxed) != reads_after_first {
        return TestResult::Fail("second read missed the cached 1 KiB ext block");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext2_page_cache_reuses_1k_data_block
);

/// Build a minimal EXT4 image: same block layout as `build_ext2_image`,
/// but the superblock sets the EXTENTS incompat feature and every inode
/// stores an extent tree in its `i_block[]` region instead of the
/// direct/indirect pointer chain. This exercises the ext4 read path —
/// `map_block` → `map_block_extents` — end to end (the thing a real
/// `mkfs.ext4` rootfs uses that a legacy ext2 image never touches).
fn build_ext4_extent_image(file_data: &[u8]) -> Vec<u8> {
    const BS: usize = 1024;
    const TOTAL_BLOCKS: u32 = 64;
    const INODES_PER_GROUP: u32 = 32;
    const INODE_SIZE: u16 = 128;
    const BLOCKS_PER_GROUP: u32 = 64;

    let mut img = vec![0u8; BS * TOTAL_BLOCKS as usize];

    // Superblock at byte 1024.
    let sb = 1024usize;
    put_u32(&mut img, sb, INODES_PER_GROUP);
    put_u32(&mut img, sb + 4, TOTAL_BLOCKS);
    put_u32(&mut img, sb + 20, 1); // s_first_data_block
    put_u32(&mut img, sb + 24, 0); // s_log_block_size → 1024
    put_u32(&mut img, sb + 32, BLOCKS_PER_GROUP);
    put_u32(&mut img, sb + 40, INODES_PER_GROUP);
    put_u16(&mut img, sb + 56, 0xEF53); // magic
    put_u32(&mut img, sb + 76, 1); // s_rev_level = 1
    put_u16(&mut img, sb + 88, INODE_SIZE);
    put_u32(&mut img, sb + 96, 0x40); // s_feature_incompat = INCOMPAT_EXTENTS

    // Block group descriptor at start of block 2.
    let gdt = 2 * BS;
    put_u32(&mut img, gdt, 3); // block bitmap
    put_u32(&mut img, gdt + 4, 4); // inode bitmap
    put_u32(&mut img, gdt + 8, 5); // inode table
    put_u16(&mut img, gdt + 16, 1); // used dirs (root)

    // Bitmaps (blocks 3, 4) — mark blocks 0..=10 and inodes 1,2,12 used.
    img[3 * BS] = 0xFF;
    img[3 * BS + 1] = 0x07;
    img[4 * BS] = 0b0000_0011;
    img[4 * BS + 1] = 0b0000_1000;

    let itab = 5 * BS;

    // Write an extent-tree root (header + one leaf extent) into an inode's
    // 60-byte i_block region, mapping logical block 0 → `phys` for `len`.
    fn write_extent_root(img: &mut [u8], inode_off: usize, phys: u32, len: u16) {
        put_u32(img, inode_off + 32, 0x0008_0000); // i_flags: EXT4_EXTENTS_FL
        let ib = inode_off + 40; // i_block[0]
        put_u16(img, ib, 0xF30A); // eh_magic
        put_u16(img, ib + 2, 1); // eh_entries
        put_u16(img, ib + 4, 4); // eh_max
        put_u16(img, ib + 6, 0); // eh_depth (0 = leaf)
        put_u32(img, ib + 8, 0); // eh_generation
        put_u32(img, ib + 12, 0); // ee_block (logical 0)
        put_u16(img, ib + 16, len); // ee_len
        put_u16(img, ib + 18, 0); // ee_start_hi
        put_u32(img, ib + 20, phys); // ee_start_lo
    }

    // Root directory inode (#2) at table index 1 — extent → dir data (blk 9).
    let root_off = itab + INODE_SIZE as usize;
    put_u16(&mut img, root_off, 0x4000 | 0o755); // S_IFDIR | 0755
    put_u32(&mut img, root_off + 4, BS as u32); // size = 1 block
    put_u32(&mut img, root_off + 28, (BS / 512) as u32); // i_blocks
    write_extent_root(&mut img, root_off, 9, 1);

    // File inode (#12) at table index 11 — extent → file data (blk 10).
    let file_off = itab + 11 * INODE_SIZE as usize;
    put_u16(&mut img, file_off, 0x8000 | 0o644); // S_IFREG | 0644
    put_u32(&mut img, file_off + 4, file_data.len() as u32);
    put_u32(
        &mut img,
        file_off + 28,
        file_data.len().div_ceil(512) as u32,
    );
    if !file_data.is_empty() {
        write_extent_root(&mut img, file_off, 10, 1);
    }

    // Root directory data (block 9): ".", "..", "data" → inode 12.
    let rd = 9 * BS;
    put_u32(&mut img, rd, 2);
    put_u16(&mut img, rd + 4, 12);
    img[rd + 6] = 1;
    img[rd + 7] = ftype::DIR;
    img[rd + 8] = b'.';
    put_u32(&mut img, rd + 12, 2);
    put_u16(&mut img, rd + 16, 12);
    img[rd + 18] = 2;
    img[rd + 19] = ftype::DIR;
    img[rd + 20] = b'.';
    img[rd + 21] = b'.';
    let e3 = rd + 24;
    let name = b"data";
    put_u32(&mut img, e3, 12);
    put_u16(&mut img, e3 + 4, (BS - 24) as u16);
    img[e3 + 6] = name.len() as u8;
    img[e3 + 7] = ftype::REGULAR;
    img[e3 + 8..e3 + 8 + name.len()].copy_from_slice(name);

    // File data (block 10).
    if !file_data.is_empty() {
        let data_off = 10 * BS;
        img[data_off..data_off + file_data.len()].copy_from_slice(file_data);
    }

    img
}

/// Turn the small extent fixture into a checksummed ext4 image. This mirrors
/// the real mount order: feature bits and seed first, then every dependent
/// inode and group descriptor, then the superblock checksum last.
fn sign_ext4_metadata_csum_fixture(img: &mut [u8]) -> Result<(), &'static str> {
    const BS: usize = 1024;
    const INODE_SIZE: usize = 128;
    const SB: usize = 1024;
    const GDT: usize = 2 * BS;
    const ITABLE: usize = 5 * BS;

    put_u32(
        img,
        SB + 96,
        super::superblock::incompat::EXTENTS | super::superblock::incompat::CSUM_SEED,
    );
    put_u32(img, SB + 100, super::superblock::ro_compat::METADATA_CSUM);
    put_u32(img, SB + 624, 0x4d3c_2b1a);
    let sb = Superblock::parse(&img[SB..SB + 1024]).ok_or("fixture superblock did not parse")?;

    // The fixture uses blocks 0..=10 and inodes 1, 2, and 12.
    put_u32(img, SB + 12, 53);
    put_u32(img, SB + 16, 29);
    put_u16(img, GDT + 12, 53);
    put_u16(img, GDT + 14, 29);
    // Inode 12 is the highest initialized inode, leaving 20 slots in the
    // uninitialized tail. Linux rejects newly allocated inodes beyond this
    // boundary unless the allocator advances it in the group descriptor.
    put_u16(img, GDT + 28, 20);

    // metadata_csum classic directories reserve the last 12 bytes for the
    // checksum carrier. Shorten the final "data" dirent to end at the tail.
    let root_dir = 9 * BS;
    put_u16(img, root_dir + 24 + 4, (BS - 24 - 12) as u16);
    let tail = root_dir + BS - 12;
    put_u32(img, tail, 0);
    put_u16(img, tail + 4, 12);
    img[tail + 6] = 0;
    img[tail + 7] = 0xde;
    put_u32(img, tail + 8, 0);
    write_directory_block_checksum(&sb, 2, 0, &mut img[root_dir..root_dir + BS])
        .ok_or("fixture root directory did not checksum")?;

    let block_bitmap = img[3 * BS..3 * BS + 8].to_vec();
    let inode_bitmap = img[4 * BS..4 * BS + 4].to_vec();
    write_bitmap_checksum(&sb, &mut img[GDT..GDT + 32], &block_bitmap, false)
        .ok_or("fixture block bitmap did not checksum")?;
    write_bitmap_checksum(&sb, &mut img[GDT..GDT + 32], &inode_bitmap, true)
        .ok_or("fixture inode bitmap did not checksum")?;

    for inode_no in [2u32, 12] {
        let index = (inode_no - 1) as usize;
        let inode = &mut img[ITABLE + index * INODE_SIZE..ITABLE + (index + 1) * INODE_SIZE];
        write_inode_checksum(&sb, inode_no, inode).ok_or("fixture inode did not checksum")?;
    }
    write_group_desc_checksum(&sb, 0, &mut img[GDT..GDT + 32])
        .ok_or("fixture group descriptor did not checksum")?;
    write_superblock_checksum(&sb, &mut img[SB..SB + 1024])
        .ok_or("fixture superblock did not checksum")?;
    Ok(())
}

fn smoke_ext4_metadata_csum_mount_and_corruption_rejection() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::{FsError, FsInstance};
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    let mut good = build_ext4_extent_image(b"checksummed extent data");
    if sign_ext4_metadata_csum_fixture(&mut good).is_err() {
        return TestResult::Fail("could not sign metadata-csum fixture");
    }
    let volume = match poll_once(Ext2Volume::mount(
        RamBlockDevice::from_image(512, good.clone()),
        DomainId::DRIVER_0,
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("checksummed ext4 fixture did not mount"),
    };
    if !matches!(poll_once(volume.root().lookup_async("data")), Some(Ok(_))) {
        return TestResult::Fail("checksummed ext4 fixture did not read inode metadata");
    }

    let mut bad_group = good.clone();
    bad_group[2 * 1024 + 8] ^= 1;
    if !matches!(
        poll_once(Ext2Volume::mount(
            RamBlockDevice::from_image(512, bad_group),
            DomainId::DRIVER_0,
        )),
        Some(Err(FsError::InvalidData))
    ) {
        return TestResult::Fail("mount accepted a corrupt group descriptor checksum");
    }

    let mut bad_inode = good;
    bad_inode[5 * 1024 + 128 + 4] ^= 1; // inode 2's size
    if !matches!(
        poll_once(Ext2Volume::mount(
            RamBlockDevice::from_image(512, bad_inode),
            DomainId::DRIVER_0,
        )),
        Some(Err(FsError::InvalidData))
    ) {
        return TestResult::Fail("mount accepted a corrupt root-inode checksum");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext4_metadata_csum_mount_and_corruption_rejection
);

fn smoke_ext4_metadata_csum_allocator_quarantines_bad_bitmap() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsError;
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    const BS: usize = 1024;
    let mut image = build_ext4_extent_image(b"checksummed extent data");
    if sign_ext4_metadata_csum_fixture(&mut image).is_err() {
        return TestResult::Fail("could not sign bitmap-quarantine fixture");
    }
    // Corrupt only the block bitmap. Mount validates the superblock, group
    // descriptor, and inodes; the allocator is responsible for validating a
    // bitmap immediately before it changes a bit.
    image[3 * BS + 7] ^= 0x80;
    let device = RamBlockDevice::from_image(512, image);
    let volume = match poll_once(Ext2Volume::mount(device.clone(), DomainId::DRIVER_0)) {
        Some(Ok(volume)) => volume,
        _ => return TestResult::Fail("bitmap-quarantine fixture did not mount"),
    };
    let before = device.snapshot();
    if !matches!(poll_once(volume.alloc_block()), Some(Err(FsError::NoSpace))) {
        return TestResult::Fail("allocator did not quarantine checksum-invalid group");
    }
    if device.snapshot() != before {
        return TestResult::Fail("allocator mutated a checksum-invalid group");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext4_metadata_csum_allocator_quarantines_bad_bitmap
);

fn smoke_ext4_metadata_csum_writable_mkdir_survives_remount() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    let mut image = build_ext4_extent_image(b"checksummed extent data");
    if sign_ext4_metadata_csum_fixture(&mut image).is_err() {
        return TestResult::Fail("could not sign writable metadata-csum fixture");
    }
    let device = RamBlockDevice::from_image(512, image);
    let volume = match poll_once(Ext2Volume::mount(device.clone(), DomainId::DRIVER_0)) {
        Some(Ok(volume)) => volume,
        _ => return TestResult::Fail("writable metadata-csum fixture did not mount"),
    };
    let root = volume.root();
    if !matches!(poll_once(root.mkdir("linger")), Some(Ok(_))) {
        return TestResult::Fail("mkdir failed on clean metadata-csum volume");
    }
    if !matches!(poll_once(root.mkdir("past-tail")), Some(Ok(_))) {
        return TestResult::Fail("second mkdir failed on clean metadata-csum volume");
    }
    let after = device.snapshot();
    let descriptor = &after[2 * 1024..2 * 1024 + 32];
    if u16::from_le_bytes([descriptor[28], descriptor[29]]) != 19 {
        return TestResult::Fail("inode allocation did not advance bg_itable_unused");
    }
    let sb = match Superblock::parse(&after[1024..2048]) {
        Some(sb) => sb,
        None => return TestResult::Fail("mutated superblock did not parse"),
    };
    if !verify_group_desc_checksum(&sb, 0, descriptor) {
        return TestResult::Fail("itable-unused update left stale group checksum");
    }
    drop(root);
    drop(volume);

    let remounted = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(volume)) => volume,
        _ => {
            return TestResult::Fail("metadata-csum volume failed checksum validation after mkdir")
        }
    };
    if !matches!(
        poll_once(remounted.root().lookup_dir_async("linger")),
        Some(Ok(_))
    ) {
        return TestResult::Fail("created directory was not readable after remount");
    }
    if !matches!(
        poll_once(remounted.root().lookup_dir_async("past-tail")),
        Some(Ok(_))
    ) {
        return TestResult::Fail("tail-advancing directory was not readable after remount");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext4_metadata_csum_writable_mkdir_survives_remount
);

/// `ExtentLeaf::parse`: an extent is uninitialized only when `ee_len > 32768`
/// (real length `ee_len - 32768`); `ee_len == 32768` is a MAX-LENGTH
/// INITIALIZED extent, not a hole. Masking bit 15 wrongly zeroed a 128 MiB
/// initialized run — block 0 of a 32768-block extent read as a hole, so a
/// large `.so` (libLLVM, whose first extent is exactly 32768 blocks) failed to
/// load with "invalid ELF header". Regression guard for that ext4 read bug.
fn smoke_ext4_extent_max_len_is_initialized() -> TestResult {
    use super::extent::ExtentLeaf;
    let mut buf = [0u8; 12];
    buf[0..4].copy_from_slice(&0u32.to_le_bytes()); // ee_block = 0
    buf[4..6].copy_from_slice(&0x8000u16.to_le_bytes()); // ee_len = 32768
    buf[6..8].copy_from_slice(&0u16.to_le_bytes()); // ee_start_hi
    buf[8..12].copy_from_slice(&413696u32.to_le_bytes()); // ee_start_lo
    match ExtentLeaf::parse(&buf) {
        Some(l) if !l.is_uninitialized && l.len == 32768 && l.physical == 413696 => {}
        Some(_) => {
            return TestResult::Fail("ee_len==32768 must be an INITIALIZED len-32768 extent")
        }
        None => return TestResult::Fail("parse(ee_len=32768) returned None"),
    }
    // The genuinely uninitialized case: ee_len == 32769 → uninit, real len 1.
    buf[4..6].copy_from_slice(&0x8001u16.to_le_bytes());
    match ExtentLeaf::parse(&buf) {
        Some(l) if l.is_uninitialized && l.len == 1 => TestResult::Pass,
        _ => TestResult::Fail("ee_len>32768 must be uninitialized with len = ee_len - 32768"),
    }
}
kernel_test_in!("drivers/fs/ext2", smoke_ext4_extent_max_len_is_initialized);

/// Build a two-block, one-level HTREE root on top of the compact ext4
/// fixture. Logical block zero is the checksummed index root and logical block
/// one is a classic checksummed leaf containing the original entries.
fn build_ext4_metadata_csum_htree_fixture() -> Result<Vec<u8>, &'static str> {
    const BS: usize = 1024;
    const SB: usize = BS;
    const GDT: usize = 2 * BS;
    const ITABLE: usize = 5 * BS;
    const INODE_SIZE: usize = 128;
    const ROOT_INODE: usize = ITABLE + INODE_SIZE;
    const FILE_INODE: usize = ITABLE + 11 * INODE_SIZE;

    let mut image = build_ext4_extent_image(b"htree-data");

    // Move the regular file from block 10 to 11 so blocks 9..10 can be the
    // root directory's contiguous two-block extent.
    image.copy_within(10 * BS..11 * BS, 11 * BS);
    image[10 * BS..11 * BS].fill(0);
    put_u32(&mut image, FILE_INODE + 60, 11);
    image[3 * BS + 1] |= 1 << 3; // block 11 is allocated

    put_u32(&mut image, ROOT_INODE + 4, (2 * BS) as u32);
    put_u32(&mut image, ROOT_INODE + 28, (2 * BS / 512) as u32);
    put_u32(
        &mut image,
        ROOT_INODE + 32,
        super::inode::I_FLAGS_EXTENTS | super::inode::I_FLAGS_INDEX,
    );
    put_u16(&mut image, ROOT_INODE + 56, 2); // extent length

    // Preserve the original linear directory as HTREE leaf block 1.
    image.copy_within(9 * BS..10 * BS, 10 * BS);
    put_u16(&mut image, 10 * BS + 24 + 4, (BS - 24 - 12) as u16);
    let leaf_tail = 11 * BS - 12;
    put_u32(&mut image, leaf_tail, 0);
    put_u16(&mut image, leaf_tail + 4, 12);
    image[leaf_tail + 6] = 0;
    image[leaf_tail + 7] = 0xde;
    put_u32(&mut image, leaf_tail + 8, 0);

    // Build the HTREE root. Entry zero's hash word is the `(limit, count)`
    // overlay; its block word points at logical directory block 1.
    let root = &mut image[9 * BS..10 * BS];
    root.fill(0);
    put_u32(root, 0, 2);
    put_u16(root, 4, 12);
    root[6] = 1;
    root[7] = ftype::DIR;
    root[8] = b'.';
    put_u32(root, 12, 2);
    put_u16(root, 16, (BS - 12) as u16);
    root[18] = 2;
    root[19] = ftype::DIR;
    root[20..22].copy_from_slice(b"..");
    root[28] = super::htree::hash_version::TEA;
    root[29] = 8;
    let limit = ((BS - 32 - 8) / 8) as u16;
    put_u16(root, 32, limit);
    put_u16(root, 34, 1);
    put_u32(root, 36, 1);
    let dx_tail = 32 + limit as usize * 8;
    put_u32(root, dx_tail, 0);
    put_u32(root, dx_tail + 4, 0);

    put_u32(&mut image, SB + 92, super::superblock::compat::DIR_INDEX);
    put_u32(
        &mut image,
        SB + 96,
        super::superblock::incompat::EXTENTS | super::superblock::incompat::CSUM_SEED,
    );
    put_u32(
        &mut image,
        SB + 100,
        super::superblock::ro_compat::METADATA_CSUM,
    );
    for (i, word) in [1u32, 2, 3, 4].iter().enumerate() {
        put_u32(&mut image, SB + 236 + i * 4, *word);
    }
    put_u32(&mut image, SB + 624, 0x4d3c_2b1a);
    put_u32(&mut image, SB + 12, 52); // 64 total - blocks 0..=11
    put_u32(&mut image, SB + 16, 29);
    put_u16(&mut image, GDT + 12, 52);
    put_u16(&mut image, GDT + 14, 29);

    let sb = Superblock::parse(&image[SB..SB + 1024]).ok_or("HTREE superblock parse")?;
    if sb.hash_seed != [1, 2, 3, 4] {
        return Err("HTREE hash seed did not parse");
    }
    write_directory_block_checksum(&sb, 2, 0, &mut image[10 * BS..11 * BS])
        .ok_or("HTREE leaf checksum")?;
    write_htree_block_checksum(&sb, 2, 0, &mut image[9 * BS..10 * BS])
        .ok_or("HTREE root checksum")?;
    let block_bitmap = image[3 * BS..3 * BS + 8].to_vec();
    let inode_bitmap = image[4 * BS..4 * BS + 4].to_vec();
    write_bitmap_checksum(&sb, &mut image[GDT..GDT + 32], &block_bitmap, false)
        .ok_or("HTREE block bitmap checksum")?;
    write_bitmap_checksum(&sb, &mut image[GDT..GDT + 32], &inode_bitmap, true)
        .ok_or("HTREE inode bitmap checksum")?;
    for inode_no in [2u32, 12] {
        let index = (inode_no - 1) as usize;
        write_inode_checksum(
            &sb,
            inode_no,
            &mut image[ITABLE + index * INODE_SIZE..ITABLE + (index + 1) * INODE_SIZE],
        )
        .ok_or("HTREE inode checksum")?;
    }
    write_group_desc_checksum(&sb, 0, &mut image[GDT..GDT + 32]).ok_or("HTREE group checksum")?;
    write_superblock_checksum(&sb, &mut image[SB..SB + 1024]).ok_or("HTREE superblock checksum")?;
    Ok(image)
}

fn smoke_ext4_metadata_csum_htree_insert_delete_survives_remount() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::{FsError, FsInstance};
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    let image = match build_ext4_metadata_csum_htree_fixture() {
        Ok(image) => image,
        Err(error) => return TestResult::Fail(error),
    };
    let device = RamBlockDevice::from_image(512, image);
    let volume = match poll_once(Ext2Volume::mount(device.clone(), DomainId::DRIVER_0)) {
        Some(Ok(volume)) => volume,
        _ => return TestResult::Fail("checksummed HTREE fixture did not mount"),
    };
    let root = volume.root();
    let fresh = match poll_once(root.create("fresh")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("checksummed HTREE insertion failed"),
    };
    if !matches!(poll_once(fresh.write(0, b"journal-header")), Some(Ok(14))) {
        return TestResult::Fail("checksummed HTREE fresh-file write failed");
    }
    drop(fresh);
    drop(root);
    drop(volume);

    let remounted = match poll_once(Ext2Volume::mount(device.clone(), DomainId::DRIVER_0)) {
        Some(Ok(volume)) => volume,
        _ => return TestResult::Fail("HTREE checksum validation failed after insertion"),
    };
    let root = remounted.root();
    let fresh = match poll_once(root.lookup_async("fresh")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("HTREE insertion was not durable"),
    };
    let mut payload = [0u8; 14];
    if !matches!(poll_once(fresh.read(0, &mut payload)), Some(Ok(14)))
        || &payload != b"journal-header"
    {
        return TestResult::Fail("checksummed HTREE fresh-file data was not durable");
    }
    drop(fresh);
    if !matches!(poll_once(root.unlink("fresh")), Some(Ok(()))) {
        return TestResult::Fail("checksummed HTREE deletion failed");
    }
    drop(root);
    drop(remounted);

    let remounted = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(volume)) => volume,
        _ => return TestResult::Fail("HTREE checksum validation failed after deletion"),
    };
    let root = remounted.root();
    if !matches!(
        poll_once(root.lookup_async("fresh")),
        Some(Err(FsError::NotFound))
    ) {
        return TestResult::Fail("HTREE deletion was not durable");
    }
    if !matches!(poll_once(root.lookup_async("data")), Some(Ok(_))) {
        return TestResult::Fail("HTREE mutation damaged an unrelated leaf entry");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext4_metadata_csum_htree_insert_delete_survives_remount
);

fn smoke_ext4_mount_extent_round_trip() -> TestResult {
    // End-to-end ext4: mount an EXTENT-based image, enumerate the root,
    // look up `data`, and read it back — driving the extent-tree block
    // mapping the legacy indirect-block test never touches.
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::{FileType, FsError, FsInstance};
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    let payload = b"narf-ext4-extents\n";
    let img = build_ext4_extent_image(payload);
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("Ext2Volume::mount (ext4) failed"),
    };

    let root = volume.root();
    let entries = match poll_once(root.enumerate_async(0, 16)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("enumerate_async (ext4) failed"),
    };
    if !entries
        .iter()
        .any(|(n, t)| n == "data" && *t == FileType::File)
    {
        return TestResult::Fail("ext4 enumerate did not list `data`");
    }

    let file = match poll_once(root.lookup_async("data")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("ext4 lookup_async data failed"),
    };
    if file.stat().size != payload.len() as u64 {
        return TestResult::Fail("ext4 stat.size mismatch");
    }
    let mut buf = [0u8; 32];
    let n = match poll_once(file.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("ext4 file.read (extent path) failed"),
    };
    if n != payload.len() || &buf[..n] != payload {
        return TestResult::Fail("ext4 file content mismatch — extent map wrong");
    }
    match poll_once(root.lookup_async("nope")) {
        Some(Err(FsError::NotFound)) => {}
        _ => return TestResult::Fail("ext4 lookup of missing name should NotFound"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext4_mount_extent_round_trip);

fn smoke_ext2_read_partial_offset() -> TestResult {
    // Read from a non-zero offset in the middle of the data block to
    // exercise the (logical block, in-block byte) split inside
    // `read_inode_at`.
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    let payload = b"abcdefghij0123456789";
    let img = build_ext2_image(payload);
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = volume.root();
    let file = match poll_once(root.lookup_async("data")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup failed"),
    };
    let mut buf = [0u8; 5];
    let n = match poll_once(file.read(10, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("read failed"),
    };
    if n != 5 || &buf[..] != b"01234" {
        return TestResult::Fail("partial read content mismatch");
    }
    // Read past EOF returns 0
    let n2 = match poll_once(file.read(payload.len() as u64, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("EOF read failed"),
    };
    if n2 != 0 {
        return TestResult::Fail("EOF read should return 0");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_read_partial_offset);

fn smoke_ext2_ino_is_real_inode_number() -> TestResult {
    // Regression guard for the musl DSO-dedup bug. ld-musl dedups shared
    // libraries by (st_dev, st_ino); when ext2 reported no inode and the
    // syscall layer synthesised st_ino from the file SIZE, the 8 same-size
    // `libxcb-*.so` (all 18136 bytes) aliased to one inode, so the linker
    // loaded only the first and every later lib's symbols (e.g.
    // `xcb_dri2_query_version_reply`) vanished with "symbol not found".
    // The fix: `FileOps::ino()` returns the real on-disk inode number, so
    // distinct files always carry distinct inodes regardless of size.
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    let payload = b"narf-ext2\n";
    let img = build_ext2_image(payload);
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let file = match poll_once(volume.root().lookup_async("data")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup data failed"),
    };
    // `data` is inode 12 in build_ext2_image. Pre-fix, ino() defaulted to
    // 0 for every node — a universal collision.
    if file.ino() != 12 {
        return TestResult::Fail("ext2 ino() is not the real on-disk inode (12)");
    }
    // And it must NOT be the size-derived hash that aliased same-size libs:
    // payload is 10 bytes, so a size<<1 value would be 20, never 12.
    if file.ino() == (file.stat().size << 1) {
        return TestResult::Fail("ino() looks size-derived — same-size files would alias");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_ino_is_real_inode_number);

// Ensure the helper is exercised even when some local closures are
// inlined by the optimizer.
#[allow(dead_code)]
fn _force_referenced() -> Vec<String> {
    Vec::new()
}

// ── ext3/4 feature detection + flavour ─────────────────────────────

fn smoke_ext_flavour_classifies_ext2_ext3_ext4() -> TestResult {
    use crate::superblock::{compat, incompat, ExtFlavour, Superblock};
    // Build a minimal superblock buffer (rev-1, with feature fields).
    let mut buf = alloc::vec![0u8; 512];
    // s_magic at offset 56.
    buf[56..58].copy_from_slice(&0xEF53u16.to_le_bytes());
    // s_rev_level = 1 (dynamic).
    buf[76..80].copy_from_slice(&1u32.to_le_bytes());
    // s_inode_size = 128.
    buf[88..90].copy_from_slice(&128u16.to_le_bytes());

    // Plain ext2: all feature flags zero.
    let sb = Superblock::parse(&buf).expect("parse");
    if sb.flavour() != ExtFlavour::Ext2 {
        return TestResult::Fail("zero features must classify as Ext2");
    }
    // ext3: HAS_JOURNAL compat bit set.
    buf[92..96].copy_from_slice(&compat::HAS_JOURNAL.to_le_bytes());
    let sb = Superblock::parse(&buf).expect("parse");
    if sb.flavour() != ExtFlavour::Ext3 {
        return TestResult::Fail("HAS_JOURNAL must classify as Ext3");
    }
    // ext4: EXTENTS incompat bit set.
    buf[96..100].copy_from_slice(&incompat::EXTENTS.to_le_bytes());
    let sb = Superblock::parse(&buf).expect("parse");
    if sb.flavour() != ExtFlavour::Ext4 {
        return TestResult::Fail("EXTENTS must classify as Ext4");
    }
    // ext4 path is sticky even with HAS_JOURNAL.
    buf[92..96].copy_from_slice(&compat::HAS_JOURNAL.to_le_bytes());
    let sb = Superblock::parse(&buf).expect("parse");
    if sb.flavour() != ExtFlavour::Ext4 {
        return TestResult::Fail("EXTENTS+HAS_JOURNAL must still be Ext4");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext_flavour_classifies_ext2_ext3_ext4
);

fn smoke_ext_check_incompat_rejects_unknown_features() -> TestResult {
    use crate::superblock::{incompat, FeatureError, Superblock};
    let mut buf = alloc::vec![0u8; 512];
    buf[56..58].copy_from_slice(&0xEF53u16.to_le_bytes());
    buf[76..80].copy_from_slice(&1u32.to_le_bytes());
    // ENCRYPT bit (0x10000) — driver doesn't support, must reject.
    buf[96..100].copy_from_slice(&incompat::ENCRYPT.to_le_bytes());
    let sb = Superblock::parse(&buf).expect("parse");
    match sb.check_incompat_features() {
        Err(FeatureError::UnsupportedIncompat(bits)) if bits & incompat::ENCRYPT != 0 => {
            TestResult::Pass
        }
        _ => TestResult::Fail("ENCRYPT incompat must trigger rejection"),
    }
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext_check_incompat_rejects_unknown_features
);

fn smoke_ext_64bit_block_count_combines_lo_and_hi() -> TestResult {
    use crate::superblock::{incompat, Superblock};
    let mut buf = alloc::vec![0u8; 1024];
    buf[56..58].copy_from_slice(&0xEF53u16.to_le_bytes());
    buf[76..80].copy_from_slice(&1u32.to_le_bytes());
    // s_blocks_count = 0x1000_0000
    buf[4..8].copy_from_slice(&0x1000_0000u32.to_le_bytes());
    // s_feature_incompat = 64BIT
    buf[96..100].copy_from_slice(&incompat::SIXTYFOURBIT.to_le_bytes());
    // s_blocks_count_hi = 0x0000_0042 at byte 336.
    buf[336..340].copy_from_slice(&0x0000_0042u32.to_le_bytes());
    let sb = Superblock::parse(&buf).expect("parse");
    let expected = (0x0000_0042u64 << 32) | 0x1000_0000u64;
    if sb.total_blocks() != expected {
        return TestResult::Fail("64-bit block count not assembled correctly");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext_64bit_block_count_combines_lo_and_hi
);

// ── ext4 extent parser ─────────────────────────────────────────────

fn smoke_ext4_extent_header_parse_and_leaf_translate() -> TestResult {
    use crate::extent::{
        lookup_in_node, ExtentHeader, ExtentLeaf, LookupOutcome, EXT4_EXTENT_MAGIC,
    };
    // Build a leaf node: 1 extent mapping logical [100..120) →
    // physical [5_000..5_020).
    let mut buf = alloc::vec![0u8; 12 + 12];
    // Header.
    buf[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
    buf[2..4].copy_from_slice(&1u16.to_le_bytes()); // entries=1
    buf[4..6].copy_from_slice(&4u16.to_le_bytes()); // max=4
    buf[6..8].copy_from_slice(&0u16.to_le_bytes()); // depth=0 leaf
                                                    // Leaf entry.
    buf[12..16].copy_from_slice(&100u32.to_le_bytes()); // logical=100
    buf[16..18].copy_from_slice(&20u16.to_le_bytes()); // len=20
    buf[18..20].copy_from_slice(&0u16.to_le_bytes()); // start_hi=0
    buf[20..24].copy_from_slice(&5_000u32.to_le_bytes()); // start_lo=5000

    let h = ExtentHeader::parse(&buf).expect("header");
    if h.entries != 1 || h.depth != 0 {
        return TestResult::Fail("header decode wrong");
    }
    let leaf = ExtentLeaf::parse(&buf[12..24]).expect("leaf");
    if leaf.translate(110) != Some(5_010) {
        return TestResult::Fail("translate(110) must yield 5010");
    }
    // Lookup-in-node: 110 → Mapped { physical: 5010 }.
    match lookup_in_node(&buf, 110) {
        LookupOutcome::Mapped {
            physical: 5_010,
            is_uninitialized: false,
        } => {}
        other => {
            let _ = other;
            return TestResult::Fail("lookup_in_node didn't yield Mapped(5010)");
        }
    }
    // Logical 200 falls past the only extent → Hole.
    match lookup_in_node(&buf, 200) {
        LookupOutcome::Hole => {}
        _ => return TestResult::Fail("past-EOF must yield Hole"),
    }
    // Logical 50 falls before the first extent → Hole.
    match lookup_in_node(&buf, 50) {
        LookupOutcome::Hole => {}
        _ => return TestResult::Fail("pre-first-extent must yield Hole"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext4_extent_header_parse_and_leaf_translate
);

fn smoke_ext4_extent_uninitialized_marker_propagates() -> TestResult {
    use crate::extent::{lookup_in_node, LookupOutcome, EXT4_EXTENT_MAGIC};
    let mut buf = alloc::vec![0u8; 24];
    buf[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
    buf[2..4].copy_from_slice(&1u16.to_le_bytes());
    buf[4..6].copy_from_slice(&4u16.to_le_bytes());
    // Leaf with high bit of len set → uninitialized.
    buf[12..16].copy_from_slice(&0u32.to_le_bytes());
    buf[16..18].copy_from_slice(&(0x8000u16 | 10u16).to_le_bytes()); // uninit, len=10
    buf[20..24].copy_from_slice(&7_000u32.to_le_bytes());
    match lookup_in_node(&buf, 5) {
        LookupOutcome::Mapped {
            physical: 7_005,
            is_uninitialized: true,
        } => TestResult::Pass,
        _ => TestResult::Fail("uninit bit must propagate through Mapped"),
    }
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext4_extent_uninitialized_marker_propagates
);

fn smoke_ext4_extent_index_returns_deeper_lookup() -> TestResult {
    use crate::extent::{lookup_in_node, LookupOutcome, EXT4_EXTENT_MAGIC};
    // Build an INDEX node with one index pointing at child block 99.
    let mut buf = alloc::vec![0u8; 24];
    buf[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
    buf[2..4].copy_from_slice(&1u16.to_le_bytes());
    buf[4..6].copy_from_slice(&4u16.to_le_bytes());
    buf[6..8].copy_from_slice(&1u16.to_le_bytes()); // depth=1 → index
                                                    // Index: logical=0, leaf=99.
    buf[12..16].copy_from_slice(&0u32.to_le_bytes());
    buf[16..20].copy_from_slice(&99u32.to_le_bytes());
    match lookup_in_node(&buf, 50) {
        LookupOutcome::DeeperLookupRequired { child_block: 99 } => TestResult::Pass,
        _ => TestResult::Fail("index node must yield DeeperLookupRequired"),
    }
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext4_extent_index_returns_deeper_lookup
);

fn smoke_ext4_extent_corrupt_header_yields_error() -> TestResult {
    use crate::extent::{lookup_in_node, LookupOutcome};
    let buf = alloc::vec![0u8; 24]; // magic == 0 — invalid
    match lookup_in_node(&buf, 0) {
        LookupOutcome::Corrupt => TestResult::Pass,
        _ => TestResult::Fail("zero magic must yield Corrupt"),
    }
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext4_extent_corrupt_header_yields_error
);

// ── 64-bit group descriptors ───────────────────────────────────────

fn smoke_ext4_group_desc_64byte_assembles_hi_lo_fields() -> TestResult {
    use crate::group_desc::{GroupDesc, GROUP_DESC_SIZE_64BIT};
    let mut buf = alloc::vec![0u8; GROUP_DESC_SIZE_64BIT];
    // Low 32 of block_bitmap.
    buf[0..4].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    // Low 32 of inode_bitmap.
    buf[4..8].copy_from_slice(&0xABCD_EF01u32.to_le_bytes());
    // Low 32 of inode_table.
    buf[8..12].copy_from_slice(&0x0F0F_0F0Fu32.to_le_bytes());
    // _hi fields.
    buf[32..36].copy_from_slice(&0x0000_0001u32.to_le_bytes()); // block_bitmap_hi
    buf[36..40].copy_from_slice(&0x0000_0002u32.to_le_bytes()); // inode_bitmap_hi
    buf[40..44].copy_from_slice(&0x0000_0003u32.to_le_bytes()); // inode_table_hi
    let gd = GroupDesc::parse_sized(&buf, GROUP_DESC_SIZE_64BIT).expect("parse");
    if gd.block_bitmap != (1u64 << 32) | 0x1234_5678 {
        return TestResult::Fail("block_bitmap hi/lo not assembled");
    }
    if gd.inode_bitmap != (2u64 << 32) | 0xABCD_EF01 {
        return TestResult::Fail("inode_bitmap hi/lo not assembled");
    }
    if gd.inode_table != (3u64 << 32) | 0x0F0F_0F0F {
        return TestResult::Fail("inode_table hi/lo not assembled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext4_group_desc_64byte_assembles_hi_lo_fields
);

fn smoke_ext4_group_desc_32byte_legacy_path_unchanged() -> TestResult {
    use crate::group_desc::GroupDesc;
    // Same ext2-shape descriptor: 32 bytes, no _hi fields. Should
    // decode the low 32 bits as u32 ext2 always did.
    let mut buf = alloc::vec![0u8; 32];
    buf[0..4].copy_from_slice(&100u32.to_le_bytes());
    buf[4..8].copy_from_slice(&101u32.to_le_bytes());
    buf[8..12].copy_from_slice(&102u32.to_le_bytes());
    buf[12..14].copy_from_slice(&50u16.to_le_bytes());
    buf[14..16].copy_from_slice(&60u16.to_le_bytes());
    buf[16..18].copy_from_slice(&3u16.to_le_bytes());
    let gd = GroupDesc::parse(&buf).expect("parse");
    if gd.block_bitmap != 100 || gd.inode_bitmap != 101 || gd.inode_table != 102 {
        return TestResult::Fail("ext2-shape block addresses lost");
    }
    if gd.free_blocks_count != 50 || gd.free_inodes_count != 60 {
        return TestResult::Fail("counts lost");
    }
    if gd.used_dirs_count != 3 {
        return TestResult::Fail("used_dirs_count lost");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext4_group_desc_32byte_legacy_path_unchanged
);

// ── ext4 map_block dispatch ────────────────────────────────────────
//
// Builds an Inode whose i_block[60] region carries an extent root
// and verifies that the extent-aware dispatch path picks the right
// physical block. The async-mount path needs a live BlockDevice
// which is out of scope here — the smoke exercises the pure
// serialise → lookup_in_node loop via a tiny stub instead.

fn smoke_ext4_inode_block_array_serialises_as_extent_root() -> TestResult {
    use crate::extent::{lookup_in_node, LookupOutcome, EXT4_EXTENT_MAGIC};
    use crate::inode::I_BLOCK_LEN;
    // Pack an extent root (header + 1 leaf, 60 bytes total) into a
    // [u32; 15] array as the inode loader would store i_block.
    let mut bytes = [0u8; 60];
    bytes[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
    bytes[2..4].copy_from_slice(&1u16.to_le_bytes()); // entries
    bytes[4..6].copy_from_slice(&4u16.to_le_bytes()); // max
    bytes[6..8].copy_from_slice(&0u16.to_le_bytes()); // depth = 0 (leaf)
                                                      // Leaf @ offset 12: logical=0, len=5, phys=300.
    bytes[12..16].copy_from_slice(&0u32.to_le_bytes());
    bytes[16..18].copy_from_slice(&5u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&0u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&300u32.to_le_bytes());

    // Now stuff bytes into a [u32; 15] like the inode parser does.
    let mut block_array = [0u32; I_BLOCK_LEN];
    for (i, slot) in block_array.iter_mut().enumerate() {
        let off = i * 4;
        *slot = u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
    }
    // Re-serialise back to bytes — what map_block_extents does.
    let mut node_buf = alloc::vec![0u8; 60];
    for (i, &b) in block_array.iter().enumerate() {
        node_buf[i * 4..i * 4 + 4].copy_from_slice(&b.to_le_bytes());
    }
    // Verify the round-trip + lookup against logical block 2.
    match lookup_in_node(&node_buf, 2) {
        LookupOutcome::Mapped {
            physical: 302,
            is_uninitialized: false,
        } => TestResult::Pass,
        other => {
            let _ = other;
            TestResult::Fail("inode → extent-root round-trip + lookup failed")
        }
    }
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext4_inode_block_array_serialises_as_extent_root
);

// ── JBD2 journal replay ────────────────────────────────────────────

fn put_u32_be(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_be_bytes());
}

fn build_journal_sb_v2(
    block_size: u32,
    maxlen: u32,
    first: u32,
    sequence: u32,
    start: u32,
) -> Vec<u8> {
    use crate::journal::{block_type, JBD2_MAGIC_NUMBER};
    let mut b = vec![0u8; block_size as usize];
    put_u32_be(&mut b, 0, JBD2_MAGIC_NUMBER);
    put_u32_be(&mut b, 4, block_type::SUPERBLOCK_V2);
    put_u32_be(&mut b, 8, 0); // h_sequence (unused on SB)
    put_u32_be(&mut b, 12, block_size);
    put_u32_be(&mut b, 16, maxlen);
    put_u32_be(&mut b, 20, first);
    put_u32_be(&mut b, 24, sequence);
    put_u32_be(&mut b, 28, start);
    b
}

fn smoke_jbd2_superblock_magic_and_fields() -> TestResult {
    use crate::journal::{JournalSuperblock, JBD2_MAGIC_NUMBER};
    let b = build_journal_sb_v2(1024, 100, 1, 42, 7);
    let sb = match JournalSuperblock::parse(&b) {
        Some(s) => s,
        None => return TestResult::Fail("jbd2 sb parse failed"),
    };
    if sb.block_size != 1024 || sb.maxlen != 100 || sb.first != 1 {
        return TestResult::Fail("jbd2 sb fields wrong");
    }
    if sb.sequence != 42 || sb.start != 7 {
        return TestResult::Fail("jbd2 sb seq/start wrong");
    }
    if sb.is_clean() {
        return TestResult::Fail("jbd2 sb with start != 0 must be unclean");
    }
    // Wrong magic must reject.
    let mut bad = b.clone();
    bad[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    if JournalSuperblock::parse(&bad).is_some() {
        return TestResult::Fail("bad magic must reject");
    }
    // Clean: start == 0.
    let clean = build_journal_sb_v2(1024, 100, 1, 1, 0);
    let sb = JournalSuperblock::parse(&clean).expect("parse");
    if !sb.is_clean() {
        return TestResult::Fail("start==0 must be clean");
    }
    // Confirm magic constant matches Linux's JBD2_MAGIC_NUMBER.
    if JBD2_MAGIC_NUMBER != 0xC03B_3998 {
        return TestResult::Fail("magic constant wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_jbd2_superblock_magic_and_fields);

fn smoke_jbd2_descriptor_block_decodes_two_tags() -> TestResult {
    use crate::journal::{block_type, tag_flag, DescriptorBlock, JBD2_MAGIC_NUMBER};
    let bs = 1024usize;
    let mut b = vec![0u8; bs];
    put_u32_be(&mut b, 0, JBD2_MAGIC_NUMBER);
    put_u32_be(&mut b, 4, block_type::DESCRIPTOR);
    put_u32_be(&mut b, 8, 5); // sequence
                              // tag 0: target=10, flags=0 — UUID follows.
    put_u32_be(&mut b, 12, 10);
    put_u32_be(&mut b, 16, 0);
    // (16-byte UUID stays as zeros.)
    // tag 1: target=20, flags=SAME_UUID|LAST_TAG.
    let t1_off = 12 + 8 + 16;
    put_u32_be(&mut b, t1_off, 20);
    put_u32_be(&mut b, t1_off + 4, tag_flag::SAME_UUID | tag_flag::LAST_TAG);
    let d = match DescriptorBlock::parse(&b) {
        Some(d) => d,
        None => return TestResult::Fail("descriptor parse failed"),
    };
    if d.tags.len() != 2 {
        return TestResult::Fail("expected 2 tags");
    }
    if d.tags[0].target_block != 10 || d.tags[1].target_block != 20 {
        return TestResult::Fail("tag target_block mismatch");
    }
    if !d.tags[1].is_last() {
        return TestResult::Fail("tag1 LAST_TAG bit not seen");
    }
    if d.tags[1].has_uuid() {
        return TestResult::Fail("tag1 SAME_UUID should skip UUID");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_jbd2_descriptor_block_decodes_two_tags
);

fn smoke_jbd2_commit_block_decodes() -> TestResult {
    use crate::journal::{block_type, CommitBlock, JBD2_MAGIC_NUMBER};
    let bs = 1024usize;
    let mut b = vec![0u8; bs];
    put_u32_be(&mut b, 0, JBD2_MAGIC_NUMBER);
    put_u32_be(&mut b, 4, block_type::COMMIT);
    put_u32_be(&mut b, 8, 7);
    let c = match CommitBlock::parse(&b) {
        Some(c) => c,
        None => return TestResult::Fail("commit parse failed"),
    };
    if c.header.sequence != 7 {
        return TestResult::Fail("commit sequence mismatch");
    }
    // Descriptor block must not parse as commit.
    let mut d = vec![0u8; bs];
    put_u32_be(&mut d, 0, JBD2_MAGIC_NUMBER);
    put_u32_be(&mut d, 4, block_type::DESCRIPTOR);
    if CommitBlock::parse(&d).is_some() {
        return TestResult::Fail("descriptor must not parse as commit");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_jbd2_commit_block_decodes);

fn smoke_jbd2_revoke_block_lists_targets() -> TestResult {
    use crate::journal::{block_type, RevokeBlock, JBD2_MAGIC_NUMBER};
    let bs = 1024usize;
    let mut b = vec![0u8; bs];
    put_u32_be(&mut b, 0, JBD2_MAGIC_NUMBER);
    put_u32_be(&mut b, 4, block_type::REVOKE);
    put_u32_be(&mut b, 8, 9);
    // r_count = 12 (hdr) + 4 (count itself) + 3*4 = 28.
    put_u32_be(&mut b, 12, 28);
    put_u32_be(&mut b, 16, 100);
    put_u32_be(&mut b, 20, 200);
    put_u32_be(&mut b, 24, 300);
    let r = match RevokeBlock::parse(&b) {
        Some(r) => r,
        None => return TestResult::Fail("revoke parse failed"),
    };
    if r.revoked.len() != 3 || r.revoked[0] != 100 || r.revoked[1] != 200 || r.revoked[2] != 300 {
        return TestResult::Fail("revoke targets mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_jbd2_revoke_block_lists_targets);

fn smoke_jbd2_replay_end_to_end_one_txn() -> TestResult {
    // Synthetic journal image. 1024-byte journal blocks.
    //   block 0: superblock (start=1, first=1, seq=5, maxlen=8)
    //   block 1: descriptor (seq=5, 1 tag → target FS block 42, LAST_TAG)
    //   block 2: data block (the bytes journaled for block 42)
    //   block 3: commit (seq=5)
    //   block 4+: zeroed (walk terminates on bad magic)
    use crate::journal::{block_type, replay_journal_flat, tag_flag, JBD2_MAGIC_NUMBER};
    let bs = 1024usize;
    let mut img = vec![0u8; bs * 8];
    let sb = build_journal_sb_v2(bs as u32, 8, 1, 5, 1);
    img[0..bs].copy_from_slice(&sb);

    // Descriptor at block 1.
    {
        let d = &mut img[bs..2 * bs];
        put_u32_be(d, 0, JBD2_MAGIC_NUMBER);
        put_u32_be(d, 4, block_type::DESCRIPTOR);
        put_u32_be(d, 8, 5);
        put_u32_be(d, 12, 42);
        put_u32_be(d, 16, tag_flag::SAME_UUID | tag_flag::LAST_TAG);
    }
    // Data at block 2.
    {
        let data = &mut img[2 * bs..3 * bs];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(0x10);
        }
    }
    // Commit at block 3.
    {
        let c = &mut img[3 * bs..4 * bs];
        put_u32_be(c, 0, JBD2_MAGIC_NUMBER);
        put_u32_be(c, 4, block_type::COMMIT);
        put_u32_be(c, 8, 5);
    }

    let report = match replay_journal_flat(&img, bs) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("replay returned error"),
    };
    if report.transactions_replayed != 1 {
        return TestResult::Fail("expected exactly 1 transaction replayed");
    }
    let got = match report.blocks_to_write.get(&42) {
        Some(v) => v,
        None => return TestResult::Fail("expected override for FS block 42"),
    };
    if got.len() != bs || got[0] != 0x10 || got[3] != 0x13 {
        return TestResult::Fail("replayed data content mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_jbd2_replay_end_to_end_one_txn);

fn smoke_jbd2_replay_clean_journal_no_overrides() -> TestResult {
    use crate::journal::replay_journal_flat;
    let bs = 1024usize;
    let mut img = vec![0u8; bs * 4];
    let sb = build_journal_sb_v2(bs as u32, 4, 1, 1, 0); // start==0
    img[0..bs].copy_from_slice(&sb);
    let report = match replay_journal_flat(&img, bs) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("clean replay must not error"),
    };
    if report.transactions_replayed != 0 || !report.blocks_to_write.is_empty() {
        return TestResult::Fail("clean journal must produce no overrides");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_jbd2_replay_clean_journal_no_overrides
);

fn smoke_jbd2_replay_revoke_suppresses_target() -> TestResult {
    // Same as the end-to-end smoke, but a revoke block at seq=5 for
    // target 42 sits between the data block and the commit. The
    // override map must NOT contain 42.
    use crate::journal::{block_type, replay_journal_flat, tag_flag, JBD2_MAGIC_NUMBER};
    let bs = 1024usize;
    let mut img = vec![0u8; bs * 8];
    let sb = build_journal_sb_v2(bs as u32, 8, 1, 5, 1);
    img[0..bs].copy_from_slice(&sb);

    {
        let d = &mut img[bs..2 * bs];
        put_u32_be(d, 0, JBD2_MAGIC_NUMBER);
        put_u32_be(d, 4, block_type::DESCRIPTOR);
        put_u32_be(d, 8, 5);
        put_u32_be(d, 12, 42);
        put_u32_be(d, 16, tag_flag::SAME_UUID | tag_flag::LAST_TAG);
    }
    img[2 * bs..3 * bs].fill(0xAB);
    {
        let r = &mut img[3 * bs..4 * bs];
        put_u32_be(r, 0, JBD2_MAGIC_NUMBER);
        put_u32_be(r, 4, block_type::REVOKE);
        put_u32_be(r, 8, 5);
        put_u32_be(r, 12, 20); // 12 hdr + 4 count + 1*4 = 20
        put_u32_be(r, 16, 42);
    }
    {
        let c = &mut img[4 * bs..5 * bs];
        put_u32_be(c, 0, JBD2_MAGIC_NUMBER);
        put_u32_be(c, 4, block_type::COMMIT);
        put_u32_be(c, 8, 5);
    }
    let report = match replay_journal_flat(&img, bs) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("replay errored"),
    };
    if report.blocks_to_write.contains_key(&42) {
        return TestResult::Fail("revoked target must not appear in overrides");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_jbd2_replay_revoke_suppresses_target
);

// ── Volume mount with unclean journaled image installs overrides ──

/// Build an ext3 (HAS_JOURNAL) image with `s_state == 0` (unclean)
/// and a tiny in-band journal at inode 8 that replays one block.
///
/// The journal contains a single transaction whose descriptor tag
/// targets block 9 (the root directory's data block) and whose data
/// block redirects the root directory to a single-entry dir listing
/// "REPLAYED" inode 12. The on-disk root directory (still on disk
/// at block 9) lists "ondisk-name" — so any test that observes
/// "REPLAYED" through `Ext2Volume` instead of "ondisk-name" has
/// proven that read_block consulted the override map.
fn build_ext3_unclean_image() -> Vec<u8> {
    const BS: usize = 1024;
    const TOTAL_BLOCKS: u32 = 128;
    const INODES_PER_GROUP: u32 = 32;
    const INODE_SIZE: u16 = 128;
    const BLOCKS_PER_GROUP: u32 = 128;

    let mut img = vec![0u8; BS * TOTAL_BLOCKS as usize];

    // Superblock at byte 1024 — ext3-shape (HAS_JOURNAL, s_state==0).
    let sb = &mut img[1024..2048];
    put_u32(sb, 0, INODES_PER_GROUP);
    put_u32(sb, 4, TOTAL_BLOCKS);
    put_u32(sb, 20, 1);
    put_u32(sb, 24, 0); // log_block_size = 0 → 1024
    put_u32(sb, 32, BLOCKS_PER_GROUP);
    put_u32(sb, 40, INODES_PER_GROUP);
    put_u16(sb, 56, 0xEF53);
    put_u16(sb, 58, 0); // s_state = 0 (unclean)
    put_u32(sb, 76, 1); // rev_level = 1
    put_u16(sb, 88, INODE_SIZE);
    // s_feature_compat = HAS_JOURNAL (0x4).
    put_u32(sb, 92, 0x4);
    // s_journal_inum = 8.
    put_u32(sb, 224, 8);

    // Block group descriptor at start of block 2.
    let gdt_off = 2 * BS;
    put_u32(&mut img, gdt_off, 3);
    put_u32(&mut img, gdt_off + 4, 4);
    put_u32(&mut img, gdt_off + 8, 5);
    put_u16(&mut img, gdt_off + 12, 0);
    put_u16(&mut img, gdt_off + 14, 0);
    put_u16(&mut img, gdt_off + 16, 1);

    // Inode table at blocks 5..=8 (4 blocks * 1024 / 128 = 32 inodes).
    let itab_off = 5 * BS;

    // Inode 2 (root dir).
    let root_off = itab_off + INODE_SIZE as usize;
    put_u16(&mut img, root_off, 0x4000 | 0o755);
    put_u32(&mut img, root_off + 4, BS as u32);
    put_u32(&mut img, root_off + 28, (BS / 512) as u32);
    put_u32(&mut img, root_off + 40, 9); // i_block[0] = 9

    // Inode 8 (the journal). 16 KiB journal stored in blocks
    // 16..=31 (16 × 1 KiB blocks).
    let journal_size_blocks: u32 = 16;
    let journal_start_block: u32 = 16;
    let journal_inode_off = itab_off + 7 * INODE_SIZE as usize;
    put_u16(&mut img, journal_inode_off, 0x8000 | 0o600); // regular file
    put_u32(
        &mut img,
        journal_inode_off + 4,
        journal_size_blocks * BS as u32,
    );
    put_u32(
        &mut img,
        journal_inode_off + 28,
        (journal_size_blocks * BS as u32) / 512,
    );
    // i_block[0..journal_size_blocks] map to the journal data blocks
    // 16..(16+journal_size_blocks). Only 12 direct fit in an inode —
    // we keep the journal short enough that 12 direct blocks cover
    // everything we need (descriptor + data + commit live in the
    // first 4 blocks).
    for i in 0..core::cmp::min(journal_size_blocks, 12) {
        put_u32(
            &mut img,
            journal_inode_off + 40 + (i * 4) as usize,
            journal_start_block + i,
        );
    }

    // ── On-disk root directory at block 9 (the STALE copy that
    // replay must override). One entry: "ondisk" → inode 12.
    {
        let off = 9 * BS;
        put_u32(&mut img, off, 12);
        put_u16(&mut img, off + 4, BS as u16);
        img[off + 6] = b"ondisk".len() as u8;
        img[off + 7] = ftype::REGULAR;
        img[off + 8..off + 8 + 6].copy_from_slice(b"ondisk");
    }

    // ── Journal contents at blocks 16..=19 ────────────────────
    // Block 16: JBD2 superblock_v2.
    {
        let j = &mut img[16 * BS..17 * BS];
        let mut tmp = build_journal_sb_v2_bytes(BS as u32, 12, 1, 5, 1);
        // Pad to BS.
        tmp.resize(BS, 0);
        j.copy_from_slice(&tmp);
    }
    // Block 17 (journal block 1): descriptor.
    {
        let d = &mut img[17 * BS..18 * BS];
        put_u32_be(d, 0, crate::journal::JBD2_MAGIC_NUMBER);
        put_u32_be(d, 4, crate::journal::block_type::DESCRIPTOR);
        put_u32_be(d, 8, 5);
        // tag: target FS block 9, SAME_UUID|LAST_TAG.
        put_u32_be(d, 12, 9);
        put_u32_be(
            d,
            16,
            crate::journal::tag_flag::SAME_UUID | crate::journal::tag_flag::LAST_TAG,
        );
    }
    // Block 18 (journal block 2): data — the replayed root dir.
    {
        let off = 18 * BS;
        put_u32(&mut img, off, 12); // inode
        put_u16(&mut img, off + 4, BS as u16); // rec_len fills block
        img[off + 6] = b"REPLAYED".len() as u8;
        img[off + 7] = ftype::REGULAR;
        img[off + 8..off + 8 + 8].copy_from_slice(b"REPLAYED");
    }
    // Block 19 (journal block 3): commit.
    {
        let c = &mut img[19 * BS..20 * BS];
        put_u32_be(c, 0, crate::journal::JBD2_MAGIC_NUMBER);
        put_u32_be(c, 4, crate::journal::block_type::COMMIT);
        put_u32_be(c, 8, 5);
    }

    img
}

fn build_journal_sb_v2_bytes(
    block_size: u32,
    maxlen: u32,
    first: u32,
    sequence: u32,
    start: u32,
) -> Vec<u8> {
    build_journal_sb_v2(block_size, maxlen, first, sequence, start)
}

fn smoke_ext3_unclean_mount_replays_root_dir() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    let img = build_ext3_unclean_image();
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed on unclean ext3 image"),
    };
    // Replay should have installed at least one override for block 9.
    if volume.journal_override_count() == 0 {
        return TestResult::Fail("expected ≥1 journal override after unclean ext3 mount");
    }
    // Reading the root directory should return the JOURNAL-side
    // entry (REPLAYED), not the on-disk stale entry (ondisk).
    let root = volume.root();
    let entries = match poll_once(root.enumerate_async(0, 16)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("enumerate_async failed"),
    };
    let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    if names.contains(&"ondisk") {
        return TestResult::Fail("post-replay enumeration must NOT see the on-disk stale entry");
    }
    if !names.contains(&"REPLAYED") {
        return TestResult::Fail("expected REPLAYED entry from replay override");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext3_unclean_mount_replays_root_dir);

// ── Write smoke tests ───────────────────────────────────────────────

fn smoke_ext2_write_then_read_back() -> TestResult {
    // Open the existing file, overwrite its contents, read back.
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    let initial = b"original";
    let img = build_ext2_image(initial);
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = volume.root();
    let file = match poll_once(root.lookup_async("data")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup failed"),
    };
    let payload = b"freshly written exact-content";
    let n = match poll_once(file.write(0, payload)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("write failed"),
    };
    if n != payload.len() {
        return TestResult::Fail("short write");
    }
    let mut buf = [0u8; 64];
    let m = match poll_once(file.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("read failed"),
    };
    if m != payload.len() || &buf[..m] != payload {
        return TestResult::Fail("read-back mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_write_then_read_back);

fn smoke_ext2_truncate_to_zero_then_extend() -> TestResult {
    // Truncate to zero, then grow via write, verify final state.
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    let initial = b"abcd";
    let img = build_ext2_image(initial);
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = volume.root();
    let file = match poll_once(root.lookup_async("data")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup failed"),
    };
    if poll_once(file.truncate(0)).and_then(|r| r.ok()).is_none() {
        return TestResult::Fail("truncate(0) failed");
    }
    if file.stat().size != 0 {
        return TestResult::Fail("size != 0 after truncate");
    }
    let new_payload = b"after-truncate-grow";
    let n = match poll_once(file.write(0, new_payload)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("post-truncate write failed"),
    };
    if n != new_payload.len() {
        return TestResult::Fail("short write");
    }
    let mut buf = [0u8; 64];
    let m = match poll_once(file.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("read failed"),
    };
    if m != new_payload.len() || &buf[..m] != new_payload {
        return TestResult::Fail("read-back mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_truncate_to_zero_then_extend);

fn smoke_ext2_alloc_inode_then_free_round_trip() -> TestResult {
    // Allocator round-trip: claim an inode, free it, verify
    // alloc returns the same slot again.
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    let img = build_ext2_image(b"x");
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let _ = volume.root(); // touch FsInstance
    let ino_a = match poll_once(volume.alloc_inode()) {
        Some(Ok(i)) => i,
        _ => return TestResult::Fail("alloc_inode failed"),
    };
    if ino_a == 0 || ino_a < volume.superblock.first_ino() {
        return TestResult::Fail("alloc_inode returned reserved ordinal");
    }
    if poll_once(volume.free_inode(ino_a))
        .and_then(|r| r.ok())
        .is_none()
    {
        return TestResult::Fail("free_inode failed");
    }
    let ino_b = match poll_once(volume.alloc_inode()) {
        Some(Ok(i)) => i,
        _ => return TestResult::Fail("alloc_inode second time failed"),
    };
    if ino_b != ino_a {
        return TestResult::Fail("second alloc should reclaim the freed slot");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext2_alloc_inode_then_free_round_trip
);

// ── Directory mutator smokes (Stage-1: create/unlink, mkdir/rmdir,
//     rename, hardlink, symlink fast+slow, HTREE root+leaf, full-dir
//     invariant). Each builds a fresh ext2 image, mounts via
//     RamBlockDevice, drives the mutator surface, and asserts the
//     observable state matches POSIX semantics.

fn smoke_ext2_create_then_unlink_round_trip() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::{FileType, FsInstance};
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    let img = build_ext2_image(b"x");
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = volume.root();
    // Create a new file "newfile".
    let new_file = match poll_once(root.create("newfile")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create failed"),
    };
    let _ = new_file;
    // It should appear in enumeration.
    let entries = match poll_once(root.enumerate_async(0, 16)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("enumerate after create failed"),
    };
    if !entries
        .iter()
        .any(|(n, t)| n == "newfile" && *t == FileType::File)
    {
        return TestResult::Fail("created file not visible in enumeration");
    }
    // Look up should succeed.
    if poll_once(root.lookup_async("newfile")).is_none() {
        return TestResult::Fail("lookup of created file failed");
    }
    // Unlink it.
    if poll_once(root.unlink("newfile"))
        .and_then(|r| r.ok())
        .is_none()
    {
        return TestResult::Fail("unlink failed");
    }
    // Re-enumerate — should be gone.
    let entries = match poll_once(root.enumerate_async(0, 16)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("enumerate after unlink failed"),
    };
    if entries.iter().any(|(n, _)| n == "newfile") {
        return TestResult::Fail("unlinked file still visible");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_create_then_unlink_round_trip);

fn smoke_ext2_mkdir_then_rmdir_round_trip() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::{FileType, FsInstance};
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    let img = build_ext2_image(b"x");
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = volume.root();
    // Make a fresh subdirectory.
    let _subdir = match poll_once(root.mkdir("subdir")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("mkdir failed"),
    };
    // Should appear in parent's enumeration as a Dir.
    let entries = match poll_once(root.enumerate_async(0, 16)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("enumerate after mkdir failed"),
    };
    if !entries
        .iter()
        .any(|(n, t)| n == "subdir" && *t == FileType::Dir)
    {
        return TestResult::Fail("mkdir target not a Dir in enumeration");
    }
    // Subdir should contain "." and ".." entries.
    let subdir = match poll_once(root.lookup_dir_async("subdir")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("lookup_dir_async of subdir failed"),
    };
    let sub_entries = match poll_once(subdir.enumerate_async(0, 16)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("enumerate subdir failed"),
    };
    if !sub_entries.iter().any(|(n, _)| n == ".") {
        return TestResult::Fail("subdir missing '.'");
    }
    if !sub_entries.iter().any(|(n, _)| n == "..") {
        return TestResult::Fail("subdir missing '..'");
    }
    // Drop the subdir handle before rmdir.
    drop(subdir);
    // rmdir should succeed (empty).
    if poll_once(root.rmdir("subdir"))
        .and_then(|r| r.ok())
        .is_none()
    {
        return TestResult::Fail("rmdir of empty dir failed");
    }
    // Should be gone.
    let entries = match poll_once(root.enumerate_async(0, 16)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("enumerate after rmdir failed"),
    };
    if entries.iter().any(|(n, _)| n == "subdir") {
        return TestResult::Fail("rmdir'd directory still visible");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_mkdir_then_rmdir_round_trip);

fn smoke_ext2_created_metadata_persists() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    let img = build_ext2_image(b"x");
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = volume.root();

    let file = match poll_once(root.create("owned-file")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create failed"),
    };
    // Cache the original inode in two independent handles before metadata is
    // changed. A later chmod or data write through either handle must merge
    // with the current inode, not restore its stale uid/gid snapshot.
    let stale_mode = match poll_once(root.lookup_async("owned-file")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("stale chmod handle lookup failed"),
    };
    let stale_writer = match poll_once(root.lookup_async("owned-file")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("stale writer handle lookup failed"),
    };
    if poll_once(file.set_owners(0x1234_5678, 0x9abc_def0))
        .and_then(Result::ok)
        .is_none()
        || poll_once(stale_mode.set_perms(0o4640))
            .and_then(Result::ok)
            .is_none()
        || !matches!(poll_once(stale_writer.write(0, b"x")), Some(Ok(1)))
    {
        return TestResult::Fail("file metadata update failed");
    }
    drop(file);
    let file = match poll_once(root.lookup_async("owned-file")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("file relookup failed"),
    };
    if file.owners() != (0x1234_5678, 0x9abc_def0) || file.stat().mode.perms != 0o4640 {
        return TestResult::Fail("file metadata did not persist");
    }
    if poll_once(file.set_owners(1000, 1001))
        .and_then(Result::ok)
        .is_none()
    {
        return TestResult::Fail("second file ownership update failed");
    }
    let file = match poll_once(root.lookup_async("owned-file")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("file relookup after chown failed"),
    };
    if file.owners() != (1000, 1001) || file.stat().mode.perms != 0o640 {
        return TestResult::Fail("chown did not clear file privilege bits");
    }

    let dir = match poll_once(root.mkdir("owned-dir")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("mkdir failed"),
    };
    let stale_dir = match poll_once(root.lookup_dir_async("owned-dir")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("stale directory handle lookup failed"),
    };
    if poll_once(dir.set_dir_owners_async(2000, 2001))
        .and_then(Result::ok)
        .is_none()
        || poll_once(stale_dir.set_dir_mode_async(0o2750))
            .and_then(Result::ok)
            .is_none()
    {
        return TestResult::Fail("directory metadata update failed");
    }
    drop(dir);
    let dir = match poll_once(root.lookup_dir_async("owned-dir")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("directory relookup failed"),
    };
    if dir.dir_owners() != (2000, 2001) || dir.dir_mode() != 0o2750 {
        return TestResult::Fail("directory metadata did not persist");
    }

    // `FsInstance::root()` creates a fresh handle each time. Metadata must
    // come from inode 2, not from a synthetic 0555/root-owned sentinel.
    let root_owner_handle = volume.root();
    let root_mode_handle = volume.root();
    if poll_once(root_owner_handle.set_dir_owners_async(3000, 3001))
        .and_then(Result::ok)
        .is_none()
        || poll_once(root_mode_handle.set_dir_mode_async(0o1770))
            .and_then(Result::ok)
            .is_none()
    {
        return TestResult::Fail("root inode metadata update failed");
    }
    let fresh_root = volume.root();
    if fresh_root.dir_owners() != (3000, 3001) || fresh_root.dir_mode() != 0o1770 {
        return TestResult::Fail("fresh root handle did not observe inode 2 metadata");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_created_metadata_persists);

fn smoke_ext2_rename_within_same_dir() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    let img = build_ext2_image(b"sentinel");
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = volume.root();
    // Rename "data" → "renamed".
    if poll_once(root.rename("data", "renamed"))
        .and_then(|r| r.ok())
        .is_none()
    {
        return TestResult::Fail("rename failed");
    }
    // Old name gone, new name present.
    let entries = match poll_once(root.enumerate_async(0, 16)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("enumerate after rename failed"),
    };
    if entries.iter().any(|(n, _)| n == "data") {
        return TestResult::Fail("old name still present after rename");
    }
    if !entries.iter().any(|(n, _)| n == "renamed") {
        return TestResult::Fail("new name not present after rename");
    }
    // Content survives rename.
    let f = match poll_once(root.lookup_async("renamed")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup after rename failed"),
    };
    let mut buf = [0u8; 16];
    let n = match poll_once(f.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("read after rename failed"),
    };
    if n != b"sentinel".len() || &buf[..n] != b"sentinel" {
        return TestResult::Fail("payload changed after rename");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_rename_within_same_dir);

fn smoke_ext2_rename_across_dirs() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    let img = build_ext2_image(b"x");
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = volume.root();
    // Build target directory.
    let _ = match poll_once(root.mkdir("destdir")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("mkdir destdir failed"),
    };
    // Drive the cross-directory volume API directly. The DirOps
    // rename() trait method only handles same-directory renames; the
    // volume helper exercises the full cross-dir path with the ".."
    // back-link rewrite for directory moves.
    let dest_dir = match poll_once(root.lookup_dir_async("destdir")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("lookup destdir failed"),
    };
    let _ = dest_dir;
    // Look up inode numbers via the volume's internal API.
    // The data file should move from root to destdir.
    let root_ino = crate::EXT2_ROOT_INO;
    let dest_ino = match poll_once(volume.dir_lookup(
        &poll_once(volume.read_inode(root_ino)).unwrap().unwrap(),
        b"destdir",
    )) {
        Some(Ok((i, _))) => i,
        _ => return TestResult::Fail("dir_lookup destdir failed"),
    };
    if poll_once(volume.dir_rename(root_ino, b"data", dest_ino, b"data"))
        .and_then(|r| r.ok())
        .is_none()
    {
        return TestResult::Fail("cross-dir dir_rename failed");
    }
    // After: root should NOT have "data"; destdir SHOULD.
    let root_entries = match poll_once(root.enumerate_async(0, 16)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("root enumerate failed"),
    };
    if root_entries.iter().any(|(n, _)| n == "data") {
        return TestResult::Fail("data still in root after cross-dir move");
    }
    let dest_dir = match poll_once(root.lookup_dir_async("destdir")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("re-lookup destdir failed"),
    };
    let dest_entries = match poll_once(dest_dir.enumerate_async(0, 16)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("destdir enumerate failed"),
    };
    if !dest_entries.iter().any(|(n, _)| n == "data") {
        return TestResult::Fail("data not in destdir after cross-dir move");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_rename_across_dirs);

fn smoke_ext2_hardlink_bumps_link_count() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    let img = build_ext2_image(b"shared-payload");
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let _ = volume.root();
    // Find the target inode (existing "data" inode = 12) and its link count.
    let target_ino: u32 = 12;
    let pre = match poll_once(volume.read_inode(target_ino)) {
        Some(Ok(i)) => i,
        _ => return TestResult::Fail("read_inode failed"),
    };
    if poll_once(volume.dir_hardlink(crate::EXT2_ROOT_INO, b"link", target_ino))
        .and_then(|r| r.ok())
        .is_none()
    {
        return TestResult::Fail("dir_hardlink failed");
    }
    let post = match poll_once(volume.read_inode(target_ino)) {
        Some(Ok(i)) => i,
        _ => return TestResult::Fail("read_inode post-link failed"),
    };
    if post.links_count != pre.links_count + 1 {
        return TestResult::Fail("links_count did not bump on hardlink");
    }
    // The original "data" + new "link" should map to the same inode.
    let root = volume.root();
    let f1 = match poll_once(root.lookup_async("data")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup data failed"),
    };
    let f2 = match poll_once(root.lookup_async("link")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup link failed"),
    };
    if f1.stat().size != f2.stat().size {
        return TestResult::Fail("hardlinked sizes differ");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_hardlink_bumps_link_count);

fn smoke_ext2_symlink_fast_round_trip() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    let img = build_ext2_image(b"x");
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = volume.root();
    let target_path = b"data"; // 4 bytes ≤ 60 — fast symlink.
                               // Create the symlink via the volume API (DirOps::symlink also wired).
    let sym_ino =
        match poll_once(volume.dir_create_symlink(crate::EXT2_ROOT_INO, b"sym", target_path)) {
            Some(Ok(i)) => i,
            _ => return TestResult::Fail("symlink create failed"),
        };
    // Read it back via the volume helper.
    let inode = match poll_once(volume.read_inode(sym_ino)) {
        Some(Ok(i)) => i,
        _ => return TestResult::Fail("read sym inode failed"),
    };
    if !inode.is_symlink() {
        return TestResult::Fail("created inode not a symlink");
    }
    if inode.blocks != 0 {
        return TestResult::Fail("fast symlink must not allocate data blocks");
    }
    let target = match poll_once(volume.read_symlink_target(&inode)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("read symlink target failed"),
    };
    if target != target_path {
        return TestResult::Fail("fast symlink target mismatch");
    }
    let _ = root;
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_symlink_fast_round_trip);

fn smoke_ext2_symlink_slow_round_trip() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    let img = build_ext2_image(b"x");
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let _ = volume.root();
    // 61+-byte target → slow symlink path (block allocated).
    let target_path = b"this-target-is-deliberately-longer-than-sixty-bytes-to-trigger-slow-path";
    let sym_ino =
        match poll_once(volume.dir_create_symlink(crate::EXT2_ROOT_INO, b"slowsym", target_path)) {
            Some(Ok(i)) => i,
            _ => return TestResult::Fail("slow symlink create failed"),
        };
    let inode = match poll_once(volume.read_inode(sym_ino)) {
        Some(Ok(i)) => i,
        _ => return TestResult::Fail("read inode failed"),
    };
    if !inode.is_symlink() {
        return TestResult::Fail("slow symlink not a symlink");
    }
    if inode.blocks == 0 {
        return TestResult::Fail("slow symlink must have allocated a data block");
    }
    if inode.block[0] == 0 {
        return TestResult::Fail("slow symlink block[0] missing");
    }
    let target = match poll_once(volume.read_symlink_target(&inode)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("read slow symlink target failed"),
    };
    if target != target_path {
        return TestResult::Fail("slow symlink target mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_symlink_slow_round_trip);

fn smoke_ext2_dir_full_block_invariant_holds() -> TestResult {
    // Verify the "last entry's rec_len extends to end-of-block"
    // invariant survives an insert into a full directory block at
    // the splice layer. We synthesise a fresh 1 KiB block, call
    // make_empty_dir, splice a third entry, and assert the new
    // last entry's tail still hits exactly byte 1024.
    use crate::dir::{ftype, splice};
    let bs = 1024;
    let mut block = alloc::vec![0u8; bs];
    splice::make_empty_dir(&mut block, 5, 2);
    // Splice in a regular entry — should succeed in the ".." slack.
    let off = match splice::insert_entry(&mut block, 7, b"extra", ftype::REGULAR) {
        splice::InsertResult::Ok { offset } => offset,
        _ => return TestResult::Fail("splice into make_empty_dir tail must succeed"),
    };
    // Walk forward from `off`: rec_len must take us to byte 1024.
    let rec_len = u16::from_le_bytes([block[off + 4], block[off + 5]]) as usize;
    if off + rec_len != bs {
        return TestResult::Fail("last entry's rec_len must extend exactly to end-of-block");
    }
    // Walking from byte 0 the cumulative rec_lens must also sum to bs.
    let dot_rec_len = u16::from_le_bytes([block[4], block[5]]) as usize;
    let dotdot_rec_len =
        u16::from_le_bytes([block[dot_rec_len + 4], block[dot_rec_len + 5]]) as usize;
    let extra_rec_len = u16::from_le_bytes([
        block[dot_rec_len + dotdot_rec_len + 4],
        block[dot_rec_len + dotdot_rec_len + 5],
    ]) as usize;
    if dot_rec_len + dotdot_rec_len + extra_rec_len != bs {
        return TestResult::Fail("cumulative rec_lens must equal block size");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_dir_full_block_invariant_holds);

// ── HTREE read-path smokes (pure-logic — no volume needed) ──────────

fn smoke_ext2_htree_root_decode() -> TestResult {
    use crate::dir::ftype;
    use crate::htree::{
        hash_version, DxRoot, DX_ROOT_ENTRIES_OFF, DX_ROOT_HEAD_OFF, DX_ROOT_INFO_OFF,
    };
    // Build a 1 KiB HTREE root directory block. Bytes 0..12 = fake
    // "." dirent, bytes 12..24 = fake ".." dirent, then info, head,
    // entries.
    let mut block = alloc::vec![0u8; 1024];
    // "." entry — 12 bytes.
    block[0..4].copy_from_slice(&2u32.to_le_bytes()); // self ino
    block[4..6].copy_from_slice(&12u16.to_le_bytes()); // rec_len = 12
    block[6] = 1;
    block[7] = ftype::DIR;
    block[8] = b'.';
    // ".." entry spans the remainder of the block; HTREE metadata is hidden
    // inside its otherwise-unused body from legacy directory walkers.
    block[12..16].copy_from_slice(&2u32.to_le_bytes());
    block[16..18].copy_from_slice(&(1024u16 - 12).to_le_bytes());
    block[18] = 2;
    block[19] = ftype::DIR;
    block[20] = b'.';
    block[21] = b'.';
    // dx_root_info: reserved_zero, hash_version=TEA, info_length=8,
    // indirect_levels=0, unused_flags=0.
    block[DX_ROOT_INFO_OFF + 4] = hash_version::TEA;
    block[DX_ROOT_INFO_OFF + 5] = 8;
    // dx_head: limit, count.
    block[DX_ROOT_HEAD_OFF..DX_ROOT_HEAD_OFF + 2].copy_from_slice(&10u16.to_le_bytes());
    block[DX_ROOT_HEAD_OFF + 2..DX_ROOT_HEAD_OFF + 4].copy_from_slice(&3u16.to_le_bytes());
    // 3 entries: (0, 5), (0xA000_0000, 6), (0xC000_0000, 7).
    block[DX_ROOT_ENTRIES_OFF + 4..DX_ROOT_ENTRIES_OFF + 8].copy_from_slice(&5u32.to_le_bytes());
    block[DX_ROOT_ENTRIES_OFF + 8..DX_ROOT_ENTRIES_OFF + 12]
        .copy_from_slice(&0xA000_0000u32.to_le_bytes());
    block[DX_ROOT_ENTRIES_OFF + 12..DX_ROOT_ENTRIES_OFF + 16].copy_from_slice(&6u32.to_le_bytes());
    block[DX_ROOT_ENTRIES_OFF + 16..DX_ROOT_ENTRIES_OFF + 20]
        .copy_from_slice(&0xC000_0000u32.to_le_bytes());
    block[DX_ROOT_ENTRIES_OFF + 20..DX_ROOT_ENTRIES_OFF + 24].copy_from_slice(&7u32.to_le_bytes());

    let root = match DxRoot::parse(&block) {
        Some(r) => r,
        None => return TestResult::Fail("DxRoot::parse failed"),
    };
    if root.hash_version != hash_version::TEA {
        return TestResult::Fail("hash_version mismatch");
    }
    if root.count != 3 || root.limit != 10 {
        return TestResult::Fail("count/limit mismatch");
    }
    if root.indirect_levels != 0 {
        return TestResult::Fail("indirect_levels mismatch");
    }
    let e0 = DxRoot::entry(&block, 0).unwrap();
    if e0.block != 5 {
        return TestResult::Fail("entry 0 block mismatch");
    }
    let e2 = DxRoot::entry(&block, 2).unwrap();
    if e2.hash != 0xC000_0000 || e2.block != 7 {
        return TestResult::Fail("entry 2 fields mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_htree_root_decode);

fn smoke_ext2_htree_lookup_chooses_correct_bucket() -> TestResult {
    use crate::dir::ftype;
    use crate::htree::{
        dx_find_entry_root, hash_version, DX_ROOT_ENTRIES_OFF, DX_ROOT_HEAD_OFF, DX_ROOT_INFO_OFF,
    };
    let mut block = alloc::vec![0u8; 1024];
    // Bare-minimum dirent prefix so DxRoot::parse accepts the block.
    block[0..4].copy_from_slice(&2u32.to_le_bytes());
    block[4..6].copy_from_slice(&12u16.to_le_bytes());
    block[6] = 1;
    block[7] = ftype::DIR;
    block[8] = b'.';
    block[12..16].copy_from_slice(&2u32.to_le_bytes());
    block[16..18].copy_from_slice(&(1024u16 - 12).to_le_bytes());
    block[18] = 2;
    block[19] = ftype::DIR;
    block[20] = b'.';
    block[21] = b'.';
    block[DX_ROOT_INFO_OFF + 4] = hash_version::TEA;
    block[DX_ROOT_INFO_OFF + 5] = 8;
    block[DX_ROOT_HEAD_OFF..DX_ROOT_HEAD_OFF + 2].copy_from_slice(&10u16.to_le_bytes());
    block[DX_ROOT_HEAD_OFF + 2..DX_ROOT_HEAD_OFF + 4].copy_from_slice(&3u16.to_le_bytes());
    // Sorted entries: (0, 5), (0x4000_0000, 6), (0x8000_0000, 7).
    block[DX_ROOT_ENTRIES_OFF + 4..DX_ROOT_ENTRIES_OFF + 8].copy_from_slice(&5u32.to_le_bytes());
    block[DX_ROOT_ENTRIES_OFF + 8..DX_ROOT_ENTRIES_OFF + 12]
        .copy_from_slice(&0x4000_0000u32.to_le_bytes());
    block[DX_ROOT_ENTRIES_OFF + 12..DX_ROOT_ENTRIES_OFF + 16].copy_from_slice(&6u32.to_le_bytes());
    block[DX_ROOT_ENTRIES_OFF + 16..DX_ROOT_ENTRIES_OFF + 20]
        .copy_from_slice(&0x8000_0000u32.to_le_bytes());
    block[DX_ROOT_ENTRIES_OFF + 20..DX_ROOT_ENTRIES_OFF + 24].copy_from_slice(&7u32.to_le_bytes());

    // Target hash 0x3000_0000 → falls in bucket 0 (below 0x4000_0000) → block 5.
    let e = dx_find_entry_root(&block, 0x3000_0000).unwrap();
    if e.block != 5 {
        return TestResult::Fail("hash 0x3 should land in bucket 0 (block 5)");
    }
    // Target hash 0x4000_0000 — exact match → bucket 1 (block 6).
    let e = dx_find_entry_root(&block, 0x4000_0000).unwrap();
    if e.block != 6 {
        return TestResult::Fail("hash 0x4 exact should land in bucket 1 (block 6)");
    }
    // Target hash 0x9000_0000 → bucket 2 (block 7).
    let e = dx_find_entry_root(&block, 0x9000_0000).unwrap();
    if e.block != 7 {
        return TestResult::Fail("hash 0x9 should land in bucket 2 (block 7)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext2_htree_lookup_chooses_correct_bucket
);

fn smoke_ext2_htree_tea_hash_deterministic() -> TestResult {
    use crate::htree::{hash_version, name_hash};
    let seed = [0u32; 4];
    let h1 = name_hash(b"hello", hash_version::TEA, &seed);
    let h2 = name_hash(b"hello", hash_version::TEA, &seed);
    if h1 != h2 {
        return TestResult::Fail("TEA hash not deterministic");
    }
    // Different name should yield (with overwhelming probability) a
    // different hash. If this ever flakes the hash is broken.
    let h3 = name_hash(b"world", hash_version::TEA, &seed);
    if h1 == h3 {
        return TestResult::Fail("TEA hash collision on tiny inputs");
    }
    // Legacy hash differs from TEA for the same input.
    let h_legacy = name_hash(b"hello", hash_version::LEGACY, &seed);
    if h1 == h_legacy {
        return TestResult::Fail("LEGACY and TEA must differ for non-empty input");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_htree_tea_hash_deterministic);

fn smoke_ext2_dir_splice_insert_and_delete() -> TestResult {
    use crate::dir::{ftype, rec_len_for, splice};
    // 1 KiB block with one initial "." entry consuming the whole
    // block (rec_len = 1024).
    let mut block = alloc::vec![0u8; 1024];
    block[0..4].copy_from_slice(&2u32.to_le_bytes());
    block[4..6].copy_from_slice(&1024u16.to_le_bytes());
    block[6] = 1;
    block[7] = ftype::DIR;
    block[8] = b'.';
    // Splice in "abc" → inode 5.
    match splice::insert_entry(&mut block, 5, b"abc", ftype::REGULAR) {
        splice::InsertResult::Ok { offset } => {
            if offset != rec_len_for(1) as usize {
                return TestResult::Fail("expected new entry at dot-tail");
            }
        }
        _ => return TestResult::Fail("expected Ok on splice into empty tail"),
    }
    // Duplicate → Exists.
    match splice::insert_entry(&mut block, 6, b"abc", ftype::REGULAR) {
        splice::InsertResult::Exists => {}
        _ => return TestResult::Fail("duplicate insert must yield Exists"),
    }
    // Delete the inserted "abc". The predecessor's rec_len should
    // grow back to the end of the block.
    let abc_off = rec_len_for(1) as usize;
    splice::delete_entry(&mut block, abc_off).unwrap();
    let dot_rec_len = u16::from_le_bytes([block[4], block[5]]);
    if dot_rec_len != 1024 {
        return TestResult::Fail("delete must coalesce predecessor to end-of-block");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_dir_splice_insert_and_delete);

fn smoke_ext2_dir_empty_check_recognises_dot_dotdot_only() -> TestResult {
    use crate::dir::{ftype, rec_len_for, splice};
    let mut block = alloc::vec![0u8; 1024];
    // Seed with "." and ".." per make_empty_dir.
    splice::make_empty_dir(&mut block, 5, 2);
    if !splice::is_dir_empty(&block) {
        return TestResult::Fail(". + .. only must be is_dir_empty");
    }
    // Splice an "extra" entry — no longer empty.
    let _ = splice::insert_entry(&mut block, 7, b"extra", ftype::REGULAR);
    if splice::is_dir_empty(&block) {
        return TestResult::Fail("non-trivial entry must break is_dir_empty");
    }
    // Sanity — the "." rec_len in a fresh empty-dir should be exactly
    // rec_len_for(1) = 12.
    let mut fresh = alloc::vec![0u8; 1024];
    splice::make_empty_dir(&mut fresh, 5, 2);
    let dot_rec_len = u16::from_le_bytes([fresh[4], fresh[5]]);
    if dot_rec_len != rec_len_for(1) {
        return TestResult::Fail(". rec_len must equal rec_len_for(1) = 12");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext2_dir_empty_check_recognises_dot_dotdot_only
);

// ── Item 3: timestamp fields ──────────────────────────────────────

fn smoke_ext2_inode_timestamps_parse_and_encode() -> TestResult {
    // Build a 128-byte inode buffer with known atime/ctime/mtime values.
    // Verify parse() decodes them, then encode_into() writes them back.
    let mut buf = vec![0u8; 128];
    // i_mode = S_IFREG | 0o644
    buf[0..2].copy_from_slice(&(0x8000u16 | 0o644).to_le_bytes());
    // i_size = 512
    buf[4..8].copy_from_slice(&512u32.to_le_bytes());
    // i_atime = 1_700_000_000
    buf[8..12].copy_from_slice(&1_700_000_000u32.to_le_bytes());
    // i_ctime = 1_700_000_001
    buf[12..16].copy_from_slice(&1_700_000_001u32.to_le_bytes());
    // i_mtime = 1_700_000_002
    buf[16..20].copy_from_slice(&1_700_000_002u32.to_le_bytes());
    // i_links_count = 1
    buf[26..28].copy_from_slice(&1u16.to_le_bytes());
    // i_blocks = 1
    buf[28..32].copy_from_slice(&1u32.to_le_bytes());

    let inode = match Inode::parse(&buf) {
        Some(i) => i,
        None => return TestResult::Fail("parse returned None"),
    };
    if inode.atime != 1_700_000_000 {
        return TestResult::Fail("atime mismatch after parse");
    }
    if inode.ctime != 1_700_000_001 {
        return TestResult::Fail("ctime mismatch after parse");
    }
    if inode.mtime != 1_700_000_002 {
        return TestResult::Fail("mtime mismatch after parse");
    }

    // Roundtrip through encode_into.
    let mut out = vec![0u8; 128];
    inode.encode_into(&mut out);
    let at = u32::from_le_bytes([out[8], out[9], out[10], out[11]]);
    let ct = u32::from_le_bytes([out[12], out[13], out[14], out[15]]);
    let mt = u32::from_le_bytes([out[16], out[17], out[18], out[19]]);
    if at != 1_700_000_000 || ct != 1_700_000_001 || mt != 1_700_000_002 {
        return TestResult::Fail("timestamps corrupted by encode_into roundtrip");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext2_inode_timestamps_parse_and_encode
);

fn smoke_ext2_inode_touch_ctime_only() -> TestResult {
    // touch_ctime must not change mtime.
    let mut inode = Inode::new_regular(0o644);
    inode.mtime = 1_000;
    inode.touch_ctime(9_999);
    if inode.ctime != 9_999 {
        return TestResult::Fail("touch_ctime did not update ctime");
    }
    if inode.mtime != 1_000 {
        return TestResult::Fail("touch_ctime must not change mtime");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_inode_touch_ctime_only);

fn smoke_ext2_inode_flags_htree_roundtrip() -> TestResult {
    use crate::inode::I_FLAGS_INDEX;
    // Build a buffer with i_flags = I_FLAGS_INDEX.
    let mut buf = vec![0u8; 128];
    buf[0..2].copy_from_slice(&(0x4000u16 | 0o755).to_le_bytes()); // S_IFDIR
    buf[26..28].copy_from_slice(&2u16.to_le_bytes());
    buf[32..36].copy_from_slice(&I_FLAGS_INDEX.to_le_bytes());
    let inode = match Inode::parse(&buf) {
        Some(i) => i,
        None => return TestResult::Fail("parse returned None"),
    };
    if !inode.is_htree() {
        return TestResult::Fail("I_FLAGS_INDEX not recognised by is_htree()");
    }
    // Roundtrip through encode_into.
    let mut out = vec![0u8; 128];
    inode.encode_into(&mut out);
    let f = u32::from_le_bytes([out[32], out[33], out[34], out[35]]);
    if f & I_FLAGS_INDEX == 0 {
        return TestResult::Fail("I_FLAGS_INDEX lost through encode_into");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_inode_flags_htree_roundtrip);

// ── Item 2: RENAME_NOREPLACE ──────────────────────────────────────

fn smoke_ext2_rename_noreplace_dest_exists_rejected() -> TestResult {
    // Simulate the collision check: inserting the same name twice in a
    // directory block should return InsertResult::Exists, which
    // dir_rename translates to InvalidPath.
    use crate::dir::ftype;
    use crate::dir::splice;

    let mut block = vec![0u8; 1024];
    // Seed with a "." entry.
    splice::make_empty_dir(&mut block, 2, 2);
    // Insert "foo".
    match splice::insert_entry(&mut block, 5, b"foo", ftype::REGULAR) {
        splice::InsertResult::Ok { .. } => {}
        _ => return TestResult::Fail("first insert of 'foo' should succeed"),
    }
    // Attempt to insert "foo" again — must return Exists.
    match splice::insert_entry(&mut block, 6, b"foo", ftype::REGULAR) {
        splice::InsertResult::Exists => {}
        splice::InsertResult::Ok { .. } => {
            return TestResult::Fail("duplicate 'foo' insert must return Exists")
        }
        splice::InsertResult::NoRoom => {
            return TestResult::Fail("duplicate 'foo' insert must return Exists, not NoRoom")
        }
        splice::InsertResult::Corrupt => {
            return TestResult::Fail("duplicate 'foo' insert must return Exists, not Corrupt")
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext2_rename_noreplace_dest_exists_rejected
);

// ── Item 1: HTREE split ───────────────────────────────────────────

fn smoke_ext2_htree_split_leaf_halves_entries() -> TestResult {
    use crate::htree::{
        collect_sorted_leaf_entries, hash_version, htree_split_leaf, repack_leaf_block,
    };

    let bs = 1024usize;
    let seed = [0u32; 4];
    let hv = hash_version::TEA;

    // Build a leaf block packed with short dirents.
    // Use rec_len_for(name_len) = (name_len + 8 + 3) & !3.
    // name "ab" → (2 + 8 + 3) & !3 = 12
    // We'll pack 40 entries of 12 bytes each = 480 bytes used.
    let mut block = vec![0u8; bs];
    let mut pos = 0usize;
    let entry_count = 40usize;
    for i in 0..entry_count {
        let name = alloc::format!("{:02}", i);
        let name_bytes = name.as_bytes();
        let rec = 12u16;
        block[pos..pos + 4].copy_from_slice(&((i as u32) + 10).to_le_bytes());
        block[pos + 4..pos + 6].copy_from_slice(&rec.to_le_bytes());
        block[pos + 6] = name_bytes.len() as u8;
        block[pos + 7] = 1u8; // REGULAR
        block[pos + 8..pos + 8 + name_bytes.len()].copy_from_slice(name_bytes);
        pos += rec as usize;
    }
    // Set last entry's rec_len to fill the block.
    let last = pos - 12;
    let fill = (bs - last) as u16;
    block[last + 4..last + 6].copy_from_slice(&fill.to_le_bytes());

    // Verify we can collect them.
    let entries = match collect_sorted_leaf_entries(&block, hv, &seed) {
        Ok(e) => e,
        Err(_) => return TestResult::Fail("collect_sorted_leaf_entries failed"),
    };
    if entries.len() != entry_count {
        return TestResult::Fail("wrong entry count from collect");
    }

    // Split.
    let split = match htree_split_leaf(&block, hv, &seed) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("htree_split_leaf failed"),
    };

    // Each half must be non-empty and re-parseable.
    let old_entries = match collect_sorted_leaf_entries(&split.old_block_data, hv, &seed) {
        Ok(e) => e,
        Err(_) => return TestResult::Fail("collect from old half failed"),
    };
    let new_entries = match collect_sorted_leaf_entries(&split.new_block_data, hv, &seed) {
        Ok(e) => e,
        Err(_) => return TestResult::Fail("collect from new half failed"),
    };
    if old_entries.is_empty() {
        return TestResult::Fail("old half is empty after split");
    }
    if new_entries.is_empty() {
        return TestResult::Fail("new half is empty after split");
    }
    if old_entries.len() + new_entries.len() != entry_count {
        return TestResult::Fail("entry count mismatch after split");
    }
    // All entries in old half must have hash < split_hash (or equal for ties).
    // All entries in new half must have hash >= split_hash.
    for e in &new_entries {
        if e.hash < split.split_hash {
            return TestResult::Fail("new half entry has hash below split_hash");
        }
    }
    let _ = repack_leaf_block; // silence unused warning
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext2_htree_split_leaf_halves_entries
);

fn smoke_ext2_htree_index_node_insert_sorted() -> TestResult {
    use crate::htree::{index_node_insert_entry, DX_NODE_ENTRIES_OFF, DX_NODE_HEAD_OFF};

    let bs = 1024usize;
    let mut node = vec![0u8; bs];

    // Initialise head: leave eight bytes for the dx checksum tail.
    let limit = ((bs - DX_NODE_ENTRIES_OFF - 8) / 8) as u16;
    node[DX_NODE_HEAD_OFF..DX_NODE_HEAD_OFF + 2].copy_from_slice(&limit.to_le_bytes());
    node[DX_NODE_HEAD_OFF + 2..DX_NODE_HEAD_OFF + 4].copy_from_slice(&1u16.to_le_bytes());
    // Entry 0: hash=0, block=1 (catch-all).
    node[DX_NODE_ENTRIES_OFF + 4..DX_NODE_ENTRIES_OFF + 8].copy_from_slice(&1u32.to_le_bytes());

    // Insert (hash=300, block=3), (hash=100, block=2), (hash=200, block=4).
    // After all inserts the order (by hash) should be: 0, 100, 200, 300.
    index_node_insert_entry(&mut node, DX_NODE_HEAD_OFF, DX_NODE_ENTRIES_OFF, 300, 3).unwrap();
    index_node_insert_entry(&mut node, DX_NODE_HEAD_OFF, DX_NODE_ENTRIES_OFF, 100, 2).unwrap();
    index_node_insert_entry(&mut node, DX_NODE_HEAD_OFF, DX_NODE_ENTRIES_OFF, 200, 4).unwrap();

    let count =
        u16::from_le_bytes([node[DX_NODE_HEAD_OFF + 2], node[DX_NODE_HEAD_OFF + 3]]) as usize;
    if count != 4 {
        return TestResult::Fail("count should be 4 after 3 inserts");
    }
    // Verify sorted order: entries at indices 0..4 should have
    // hashes 0, 100, 200, 300.
    let expected_hashes = [100u32, 200, 300];
    for (i, &eh) in expected_hashes.iter().enumerate() {
        let i = i + 1; // entry zero's hash word is the count/limit header
        let off = DX_NODE_ENTRIES_OFF + i * 8;
        let h = u32::from_le_bytes([node[off], node[off + 1], node[off + 2], node[off + 3]]);
        if h != eh {
            return TestResult::Fail("index entries not in sorted hash order");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_htree_index_node_insert_sorted);

fn smoke_ext2_htree_collect_sorted_entries() -> TestResult {
    use crate::htree::{collect_sorted_leaf_entries, hash_version};

    let bs = 1024usize;
    let seed = [0u32; 4];
    let hv = hash_version::TEA;

    // Build a block with 3 entries in reverse-alphabetical order
    // ("zzz", "mmm", "aaa") — collect must return them sorted by hash.
    let mut block = vec![0u8; bs];
    let names: &[&[u8]] = &[b"zzz", b"mmm", b"aaa"];
    let mut pos = 0usize;
    let inodes = [3u32, 2, 1];
    for (i, name) in names.iter().enumerate() {
        let rec = 12u16;
        block[pos..pos + 4].copy_from_slice(&inodes[i].to_le_bytes());
        block[pos + 4..pos + 6].copy_from_slice(&rec.to_le_bytes());
        block[pos + 6] = name.len() as u8;
        block[pos + 7] = 1u8;
        block[pos + 8..pos + 8 + name.len()].copy_from_slice(name);
        pos += rec as usize;
    }
    // Last entry spans to end of block.
    let last = pos - 12;
    let fill = (bs - last) as u16;
    block[last + 4..last + 6].copy_from_slice(&fill.to_le_bytes());

    let entries = match collect_sorted_leaf_entries(&block, hv, &seed) {
        Ok(e) => e,
        Err(_) => return TestResult::Fail("collect failed"),
    };
    if entries.len() != 3 {
        return TestResult::Fail("expected 3 entries");
    }
    // Verify ascending hash order.
    for i in 0..entries.len() - 1 {
        if entries[i].hash > entries[i + 1].hash {
            return TestResult::Fail("entries not sorted ascending by hash");
        }
    }
    let _ = inodes; // silence warning
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_htree_collect_sorted_entries);

// ─────────────────── Synchronous DirOps::lookup / lookup_dir ───────────────
//
// ext2 lookups are fundamentally async (inode + directory-block reads), but the
// synchronous VFS API (`DirOps::lookup`, `DirOps::lookup_dir`) must still work:
// bind-mount source resolution (`build_bind_fs`) and mount-subtree cloning walk
// a path with the sync API and cannot await. The driver drives the async lookup
// to completion via the scheduler's spin bridge. These tests pin that contract.

/// A nested ext2 image: root → "sub" (dir) → "deep" (file). Extends the flat
/// `build_ext2_image` with inode 13 (sub dir, block 11) and inode 14 (deep file,
/// block 12), so a DEEP synchronous walk (the StateDirectory=/var/lib/... shape)
/// can be exercised end-to-end.
fn build_ext2_image_nested(deep_data: &[u8]) -> Vec<u8> {
    const BS: usize = 1024;
    let mut img = build_ext2_image(b"flat-file\n");

    let itab_off = 5 * BS;
    const INODE_SIZE: usize = 128;

    // ── inode 13: "sub" directory (table index 12), data block 11 ──
    let sub_off = itab_off + 12 * INODE_SIZE;
    put_u16(&mut img, sub_off, 0x4000 | 0o755); // S_IFDIR | 0755
    put_u32(&mut img, sub_off + 4, BS as u32); // size = 1 block
    put_u32(&mut img, sub_off + 28, (BS / 512) as u32); // i_blocks
    put_u32(&mut img, sub_off + 40, 11); // i_block[0] = 11

    // ── inode 14: "deep" regular file (table index 13), data block 12 ──
    let deep_off = itab_off + 13 * INODE_SIZE;
    put_u16(&mut img, deep_off, 0x8000 | 0o644); // S_IFREG | 0644
    put_u32(&mut img, deep_off + 4, deep_data.len() as u32);
    put_u32(
        &mut img,
        deep_off + 28,
        deep_data.len().div_ceil(512) as u32,
    );
    if !deep_data.is_empty() {
        put_u32(&mut img, deep_off + 40, 12); // i_block[0] = 12
    }

    // ── inode bitmap (block 4): also mark inodes 13, 14 used ──
    let ibm_off = 4 * BS;
    img[ibm_off + 1] = 0b0011_1000; // inodes 12, 13, 14

    // ── block bitmap (block 3): also mark blocks 11, 12 used ──
    let bm_off = 3 * BS;
    img[bm_off + 1] = 0x1F; // blocks 8..=12

    // ── rewrite the root directory block (9): ".", "..", "data", "sub" ──
    let root_data = 9 * BS;
    for b in &mut img[root_data..root_data + BS] {
        *b = 0;
    }
    // Write one directory record at absolute byte offset `at`.
    fn put_dirent(img: &mut [u8], at: usize, ino: u32, name: &[u8], ftype_byte: u8, rec: u16) {
        put_u32(img, at, ino);
        put_u16(img, at + 4, rec);
        img[at + 6] = name.len() as u8;
        img[at + 7] = ftype_byte;
        img[at + 8..at + 8 + name.len()].copy_from_slice(name);
    }
    put_dirent(&mut img, root_data, 2, b".", ftype::DIR, 12);
    put_dirent(&mut img, root_data + 12, 2, b"..", ftype::DIR, 12);
    put_dirent(&mut img, root_data + 24, 12, b"data", ftype::REGULAR, 12);
    // "sub" is the last record — fills the rest of the block.
    put_dirent(
        &mut img,
        root_data + 36,
        13,
        b"sub",
        ftype::DIR,
        (BS - 36) as u16,
    );

    // ── sub directory data (block 11): ".", "..", "deep" ──
    let sub_data = 11 * BS;
    put_dirent(&mut img, sub_data, 13, b".", ftype::DIR, 12);
    put_dirent(&mut img, sub_data + 12, 2, b"..", ftype::DIR, 12);
    put_dirent(
        &mut img,
        sub_data + 24,
        14,
        b"deep",
        ftype::REGULAR,
        (BS - 24) as u16,
    );

    // ── deep file data (block 12) ──
    if !deep_data.is_empty() {
        let d = 12 * BS;
        img[d..d + deep_data.len()].copy_from_slice(deep_data);
    }

    img
}

fn mount_root(img: Vec<u8>) -> Option<alloc::sync::Arc<dyn narf_filesystem::DirOps>> {
    use crate::volume::Ext2Volume;
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return None,
    };
    Some(volume.root())
}

/// `DirOps::lookup` (SYNC) resolves a real file entry on ext2.
fn smoke_ext2_sync_lookup_resolves_file() -> TestResult {
    let root = match mount_root(build_ext2_image(b"payload!!\n")) {
        Some(r) => r,
        None => return TestResult::Fail("mount failed"),
    };
    match root.lookup("data") {
        Some(f) => {
            if f.stat().size != 10 {
                return TestResult::Fail("sync lookup returned wrong size");
            }
            TestResult::Pass
        }
        None => TestResult::Fail("sync lookup(\"data\") returned None on a real ext2 file"),
    }
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_sync_lookup_resolves_file);

/// `DirOps::lookup` (SYNC) returns None for a missing name.
fn smoke_ext2_sync_lookup_missing_is_none() -> TestResult {
    let root = match mount_root(build_ext2_image(b"x\n")) {
        Some(r) => r,
        None => return TestResult::Fail("mount failed"),
    };
    match root.lookup("nope") {
        None => TestResult::Pass,
        Some(_) => TestResult::Fail("sync lookup of a missing name must be None"),
    }
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_sync_lookup_missing_is_none);

/// `DirOps::lookup_dir` (SYNC) resolves a directory entry (".", which is the
/// root dir inode).
fn smoke_ext2_sync_lookup_dir_resolves() -> TestResult {
    let root = match mount_root(build_ext2_image(b"x\n")) {
        Some(r) => r,
        None => return TestResult::Fail("mount failed"),
    };
    match root.lookup_dir(".") {
        Some(_) => TestResult::Pass,
        None => TestResult::Fail("sync lookup_dir(\".\") returned None on a real ext2 dir"),
    }
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_sync_lookup_dir_resolves);

/// `DirOps::lookup_dir` (SYNC) returns None when the name is a FILE, not a dir.
fn smoke_ext2_sync_lookup_dir_on_file_is_none() -> TestResult {
    let root = match mount_root(build_ext2_image(b"x\n")) {
        Some(r) => r,
        None => return TestResult::Fail("mount failed"),
    };
    match root.lookup_dir("data") {
        None => TestResult::Pass,
        Some(_) => TestResult::Fail("sync lookup_dir on a FILE must be None"),
    }
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext2_sync_lookup_dir_on_file_is_none
);

/// A DEEP synchronous walk — root → "sub" (dir) → "deep" (file) — via the sync
/// API only. This is the shape `build_bind_fs` walks for systemd's
/// StateDirectory= (e.g. binding /var/lib/systemd/linger); a sync-stubbed
/// lookup_dir failed it NotFound → ENOENT → 226/EXIT_NAMESPACE.
fn smoke_ext2_sync_deep_walk() -> TestResult {
    let root = match mount_root(build_ext2_image_nested(b"deepdata")) {
        Some(r) => r,
        None => return TestResult::Fail("mount failed"),
    };
    let sub = match root.lookup_dir("sub") {
        Some(d) => d,
        None => return TestResult::Fail("sync lookup_dir(\"sub\") failed"),
    };
    match sub.lookup("deep") {
        Some(f) => {
            if f.stat().size != 8 {
                return TestResult::Fail("deep file wrong size");
            }
            TestResult::Pass
        }
        None => TestResult::Fail("sync lookup(\"deep\") under sub/ failed"),
    }
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_sync_deep_walk);

/// ext2 `rename` must ATOMICALLY REPLACE an existing destination.
///
/// `dir_rename` unconditionally applied RENAME_NOREPLACE semantics:
///
///     // RENAME_NOREPLACE: fail if the destination already exists.
///     if self.dir_lookup(&new_parent_probe, new_name).await.is_ok() {
///         return Err(FsError::InvalidPath);
///     }
///
/// POSIX and Linux require plain rename(2) to replace the destination.
/// Only renameat2(RENAME_NOREPLACE) refuses — and the syscall layer already
/// enforces that itself (returning the correct EEXIST), so this check was
/// both redundant and wrong, and it mapped to EINVAL rather than EEXIST.
///
/// Impact: this is the exact operation Qt's QSaveFile performs on every
/// write after the first — write a temp beside the target, rename it ONTO
/// the existing target. So every KConfig/KSycoca write on the ext2 rootfs
/// failed, surfacing as kwin logging
/// `Couldn't write ".../kwinrc" . Disk full?` (KConfig prints that for any
/// failed commit; the disk had 2.5 GB free).
///
/// Measured in-guest as uid 1000 before the fix:
///     rename(tmp -> target)   ok        [destination absent]
///     rename over EXISTING    errno=22  (EINVAL)
///
/// Note this could NOT be caught by the syscall-ABI suite: those tests run
/// on memfs, which replaces correctly, while the guest's /home is ext2.
/// The pass-1 assertion below (rename onto an ABSENT name) is kept because
/// it succeeds even on the broken code — the two together are what
/// distinguish "rename is broken" from "replacement is broken".
fn smoke_ext2_rename_replaces_existing_destination() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    let img = build_ext2_image(b"sentinel");
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = volume.root();

    // Pass 1: destination ABSENT — works even on the broken implementation.
    if poll_once(root.rename("data", "target"))
        .and_then(|r| r.ok())
        .is_none()
    {
        return TestResult::Fail("rename onto an absent destination failed");
    }

    // Stage a second source alongside the now-existing destination.
    if poll_once(root.create("tmp")).and_then(|r| r.ok()).is_none() {
        return TestResult::Fail("could not create the replacement source");
    }

    // Pass 2: destination EXISTS. QSaveFile's every-write case.
    if poll_once(root.rename("tmp", "target"))
        .and_then(|r| r.ok())
        .is_none()
    {
        return TestResult::Fail(
            "rename onto an EXISTING destination failed — POSIX requires atomic \
             replacement; this is Qt QSaveFile's path (KConfig 'Disk full?')",
        );
    }

    let entries = match poll_once(root.enumerate_async(0, 32)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("enumerate after replacing rename failed"),
    };
    if entries.iter().any(|(n, _)| n == "tmp") {
        return TestResult::Fail("source name still present after replacing rename");
    }
    if !entries.iter().any(|(n, _)| n == "target") {
        return TestResult::Fail("destination missing after replacing rename");
    }
    // Exactly one `target` entry — a replace must not leave a duplicate
    // directory entry behind, which a naive "insert then unlink" would.
    if entries.iter().filter(|(n, _)| n == "target").count() != 1 {
        return TestResult::Fail("duplicate directory entries for the replaced name");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext2_rename_replaces_existing_destination
);
