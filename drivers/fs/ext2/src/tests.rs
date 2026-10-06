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

/// A file's on-disk `i_mtime` must survive to `stat`: the node builds
/// `Stat.mtime_cycles` from it via `ns_to_cycles`, and statx decodes that back
/// with `cycles_to_ns`. Regression guard for the bug where `stat_from_inode`
/// hardcoded `mtime_cycles: 0`, so every ext2 file reported mtime 1970.
fn smoke_ext2_stat_reports_real_mtime() -> TestResult {
    let mut buf = vec![0u8; 128];
    buf[0..2].copy_from_slice(&0x81A4u16.to_le_bytes()); // S_IFREG | 0644
    buf[4..8].copy_from_slice(&512u32.to_le_bytes()); // size
    let mtime_secs: u32 = 1_700_000_000; // a real (2023) timestamp, not 0
    buf[16..20].copy_from_slice(&mtime_secs.to_le_bytes()); // i_mtime
    let inode = match Inode::parse(&buf) {
        Some(i) => i,
        None => return TestResult::Fail("inode parse failed"),
    };
    if inode.mtime != mtime_secs {
        return TestResult::Fail("i_mtime not parsed from the inode");
    }
    // The exact encode the stat path uses…
    let cycles = narf_time::ns_to_cycles((inode.mtime as u64) * 1_000_000_000);
    if cycles == 0 {
        return TestResult::Fail("a real mtime encoded to 0 (the pre-fix bug)");
    }
    // …decoded the way statx does; whole-second inputs must round-trip to the
    // same second (allow sub-second conversion rounding).
    let decoded_ns = narf_time::cycles_to_ns(cycles);
    let expected_ns = (mtime_secs as u64) * 1_000_000_000;
    if decoded_ns.abs_diff(expected_ns) >= 1_000_000_000 {
        return TestResult::Fail("mtime did not round-trip through statx's cycles<->ns");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext2_superblock_magic_and_block_size
);
kernel_test_in!("drivers/fs/ext2", smoke_ext2_dirent_walk_two_entries);
kernel_test_in!("drivers/fs/ext2", smoke_ext2_stat_reports_real_mtime);
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

/// Extend the minimal image's root directory across two cache folios. The
/// first named entry remains in block 9; `late` is placed in block 15, with
/// valid empty dirents in between. This lets the I/O-counting smoke prove that
/// lookup stops at the matching folio instead of flattening the whole inode.
fn build_ext2_multi_folio_directory_image() -> Vec<u8> {
    const BS: usize = 1024;
    const INODE_SIZE: usize = 128;
    let mut img = build_ext2_image(b"folio directory");
    let root_off = 5 * BS + INODE_SIZE;
    put_u32(&mut img, root_off + 4, (6 * BS) as u32);
    put_u32(&mut img, root_off + 28, (6 * BS / 512) as u32);
    for (logical, physical) in [9u32, 11, 12, 13, 14, 15].into_iter().enumerate() {
        put_u32(&mut img, root_off + 40 + logical * 4, physical);
    }

    for physical in [11usize, 12, 13, 14] {
        let off = physical * BS;
        put_u16(&mut img, off + 4, BS as u16);
    }
    let late = 15 * BS;
    put_u32(&mut img, late, 12);
    put_u16(&mut img, late + 4, BS as u16);
    img[late + 6] = 4;
    img[late + 7] = ftype::REGULAR;
    img[late + 8..late + 12].copy_from_slice(b"late");
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

/// A mounted volume answers `FsInstance::reconfigure` — the step
/// `mount -o remount` reaches with the fstab's ext4 parameters. The volume
/// used to inherit the trait's `Unsupported` for every string, so
/// `systemd-remount-fs` failed -EINVAL on any fstab line with an ext4
/// option in it.
fn smoke_ext2_volume_reconfigure_takes_ext4_params() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::{FsError, FsInstance};
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    let device = RamBlockDevice::from_image(512, build_ext2_image(b"x"));
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("Ext2Volume::mount failed"),
    };
    if volume
        .reconfigure("commit=60,errors=remount-ro,discard")
        .is_err()
    {
        return TestResult::Fail("reconfigure refused fstab ext4 parameters");
    }
    match volume.reconfigure("commit=60,not_an_ext4_option") {
        Err(FsError::Unsupported) => TestResult::Pass,
        _ => TestResult::Fail("reconfigure accepted a parameter ext4 does not have"),
    }
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext2_volume_reconfigure_takes_ext4_params
);

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

/// A block write invalidates only the cache pages it covers. The volume used
/// to drop its whole clean page cache on every `write_byte_range`, so each
/// small metadata or data write forced every later read on the volume back to
/// the device — a Plasma login writing its caches to an ext4 home re-read
/// plasmashell's libraries page by page and sat on a black screen for minutes.
fn smoke_ext2_block_write_invalidates_only_its_pages() -> TestResult {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use narf_block::{
        ram::RamBlockDevice, BlockCompletion, BlockDevice, BlockFeature, BlockOp, BlockRequest,
        CancelResult, LbaRange,
    };
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

    const BS: u64 = 1024;
    let device = Arc::new(CountingBlock {
        inner: RamBlockDevice::from_image(512, build_ext2_image(b"page cache")),
        reads: AtomicUsize::new(0),
    });
    let volume = match poll_once(Ext2Volume::mount(device.clone(), DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    // Block 10 (4 KiB device page 2, blocks 8-11) through the block-device
    // mapping. File data has its own per-inode mapping, which device writes
    // do not touch — on Linux too, writing the block device under a mounted
    // filesystem is not coherent with the files' page cache.
    let mut block = [0u8; BS as usize];
    if !matches!(poll_once(volume.read_block(10, &mut block)), Some(Ok(()))) {
        return TestResult::Fail("first block read failed");
    }

    // Block 20 is device page 5, which block 10 does not share.
    if !matches!(
        poll_once(volume.write_byte_range(20 * BS, &[0xa5; 16])),
        Some(Ok(()))
    ) {
        return TestResult::Fail("write to an unrelated block failed");
    }
    let reads_before = device.reads.load(Ordering::Relaxed);
    if !matches!(poll_once(volume.read_block(10, &mut block)), Some(Ok(())))
        || &block[..10] != b"page cache"
    {
        return TestResult::Fail("read after an unrelated write failed");
    }
    if device.reads.load(Ordering::Relaxed) != reads_before {
        return TestResult::Fail("a write to another page evicted the cached block");
    }

    // A write over the block itself must not leave the old bytes cached.
    if !matches!(
        poll_once(volume.write_byte_range(10 * BS, b"PAGE")),
        Some(Ok(()))
    ) {
        return TestResult::Fail("write over the cached block failed");
    }
    if !matches!(poll_once(volume.read_block(10, &mut block)), Some(Ok(())))
        || &block[..10] != b"PAGE cache"
    {
        return TestResult::Fail("a write over a cached block left the stale bytes visible");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext2_block_write_invalidates_only_its_pages
);
/// A page-cache miss holds only its own page's fill lock, and a write never
/// waits for fills: with a read of one page stalled at the device, a write to
/// another page completes at once. The fill lock used to be volume-wide and
/// the write took it for its whole device round trip, so one slow miss
/// stalled every write (and every other miss) on the volume. A fill that read
/// a page before a write landed must still not cache those old bytes.
fn smoke_ext2_write_does_not_wait_for_a_stalled_fill() -> TestResult {
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::future::Future;
    use core::sync::atomic::{AtomicBool, Ordering};
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use narf_block::{
        ram::RamBlockDevice, BlockCompletion, BlockDevice, BlockFeature, BlockOp, BlockRequest,
        CancelResult, LbaRange,
    };
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    /// Holds every read at the device while `held` is set.
    struct GatedBlock {
        inner: Arc<RamBlockDevice>,
        held: AtomicBool,
    }

    impl BlockDevice for GatedBlock {
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
            let gated = matches!(request.op, BlockOp::Read);
            async move {
                if gated {
                    core::future::poll_fn(|_| {
                        if self.held.load(Ordering::Acquire) {
                            Poll::Pending
                        } else {
                            Poll::Ready(())
                        }
                    })
                    .await;
                }
                self.inner.submit(request).await
            }
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

    fn noop_waker() -> Waker {
        fn raw() -> RawWaker {
            unsafe fn clone(_: *const ()) -> RawWaker {
                raw()
            }
            unsafe fn noop(_: *const ()) {}
            const VTAB: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
            RawWaker::new(core::ptr::null(), &VTAB)
        }
        // SAFETY: every vtable function is a no-op or rebuilds the same
        // RawWaker; the null data pointer is never dereferenced.
        unsafe { Waker::from_raw(raw()) }
    }

    const BS: u64 = 1024;
    let device = Arc::new(GatedBlock {
        inner: RamBlockDevice::from_image(512, build_ext2_image(b"page cache")),
        held: AtomicBool::new(false),
    });
    let volume = match poll_once(Ext2Volume::mount(device.clone(), DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    // Stall a miss on block 40 (page 10, which nothing has read) at the
    // device.
    device.held.store(true, Ordering::Release);
    let mut buf = [0u8; BS as usize];
    let mut fill = Box::pin(volume.read_block(40, &mut buf));
    if fill.as_mut().poll(&mut cx).is_ready() {
        return TestResult::Fail("the gated read completed without the device");
    }

    // Whole, aligned 512-byte sectors, so the writes need no read-modify-write
    // read (which the gate would hold).
    let sector = [0xa5u8; 512];
    let mut page_sector = [0xa5u8; 512];
    page_sector[..4].copy_from_slice(b"PAGE");
    // A write to another page (block 20, page 5) must not wait for it.
    let mut other = Box::pin(volume.write_byte_range(20 * BS, &sector));
    match other.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(())) => {}
        Poll::Ready(Err(_)) => return TestResult::Fail("write to another page failed"),
        Poll::Pending => return TestResult::Fail("a write waited behind a stalled fill"),
    }
    // A write over the page being filled lands while the fill is stalled.
    let mut over = Box::pin(volume.write_byte_range(40 * BS, &page_sector));
    if !matches!(over.as_mut().poll(&mut cx), Poll::Ready(Ok(()))) {
        return TestResult::Fail("write over the filling page did not complete");
    }

    // Release the device; the stalled fill finishes with whatever it read.
    device.held.store(false, Ordering::Release);
    let mut finished = false;
    for _ in 0..16 {
        if let Poll::Ready(r) = fill.as_mut().poll(&mut cx) {
            if r.is_err() {
                return TestResult::Fail("the stalled read failed");
            }
            finished = true;
            break;
        }
    }
    drop(fill);
    if !finished {
        return TestResult::Fail("the stalled read never finished after release");
    }

    // Whatever the racing fill read must not have been cached over the write.
    let mut after = [0u8; BS as usize];
    if !matches!(poll_once(volume.read_block(40, &mut after)), Some(Ok(_)))
        || &after[..4] != b"PAGE"
    {
        return TestResult::Fail("a fill that raced a write cached the old bytes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext2_write_does_not_wait_for_a_stalled_fill
);
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext2_page_cache_reuses_1k_data_block
);

/// A block device that counts reads and can hold every read at the device
/// (`held`). Shared by the page-cache concurrency smokes below.
pub(crate) struct GatedCountingBlock {
    pub(crate) inner: alloc::sync::Arc<narf_block::ram::RamBlockDevice>,
    pub(crate) held: core::sync::atomic::AtomicBool,
    pub(crate) reads: core::sync::atomic::AtomicUsize,
}

impl GatedCountingBlock {
    pub(crate) fn new(image: Vec<u8>) -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self {
            inner: narf_block::ram::RamBlockDevice::from_image(512, image),
            held: core::sync::atomic::AtomicBool::new(false),
            reads: core::sync::atomic::AtomicUsize::new(0),
        })
    }
}

impl narf_block::BlockDevice for GatedCountingBlock {
    fn logical_block_size(&self) -> u32 {
        self.inner.logical_block_size()
    }
    fn physical_block_size(&self) -> u32 {
        self.inner.physical_block_size()
    }
    fn capacity_blocks(&self) -> u64 {
        self.inner.capacity_blocks()
    }
    fn supports(&self, feature: narf_block::BlockFeature) -> bool {
        self.inner.supports(feature)
    }
    fn submit(
        &self,
        request: narf_block::BlockRequest,
    ) -> impl core::future::Future<Output = narf_block::BlockCompletion> + Send {
        use core::sync::atomic::Ordering;
        let gated = matches!(request.op, narf_block::BlockOp::Read);
        if gated {
            self.reads.fetch_add(1, Ordering::Relaxed);
        }
        async move {
            if gated {
                core::future::poll_fn(|_| {
                    if self.held.load(Ordering::Acquire) {
                        core::task::Poll::Pending
                    } else {
                        core::task::Poll::Ready(())
                    }
                })
                .await;
            }
            self.inner.submit(request).await
        }
    }
    fn flush(&self) -> impl core::future::Future<Output = ()> + Send {
        self.inner.flush()
    }
    fn discard(
        &self,
        range: narf_block::LbaRange,
    ) -> impl core::future::Future<Output = ()> + Send {
        self.inner.discard(range)
    }
    fn cancel(
        &self,
        tag: u64,
    ) -> impl core::future::Future<Output = narf_block::CancelResult> + Send {
        self.inner.cancel(tag)
    }
}

/// A waker whose wake is a no-op, for hand-polling futures in smokes.
pub(crate) fn noop_waker() -> core::task::Waker {
    use core::task::{RawWaker, RawWakerVTable, Waker};
    fn raw() -> RawWaker {
        unsafe fn clone(_: *const ()) -> RawWaker {
            raw()
        }
        unsafe fn noop(_: *const ()) {}
        const VTAB: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        RawWaker::new(core::ptr::null(), &VTAB)
    }
    // SAFETY: every vtable function is a no-op or rebuilds the same RawWaker;
    // the null data pointer is never dereferenced.
    unsafe { Waker::from_raw(raw()) }
}

/// A write to one page does not void a concurrent fill of a DIFFERENT page.
/// Linux invalidates exactly the written range (`invalidate_mapping_pages`,
/// the locked folio being filled); a fill whose own page was not written
/// publishes normally. The volume used to snapshot one volume-global
/// generation before every fill and refuse to publish if ANY write landed
/// meanwhile, so on a busy volume a fill's work was thrown away and the very
/// next read of that page went back to the device.
fn smoke_ext2_write_elsewhere_does_not_void_a_concurrent_fill() -> TestResult {
    use alloc::boxed::Box;
    use core::future::Future;
    use core::sync::atomic::Ordering;
    use core::task::{Context, Poll};
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    const BS: u64 = 1024;
    let device = GatedCountingBlock::new(build_ext2_image(b"page cache"));
    let volume = match poll_once(Ext2Volume::mount(device.clone(), DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    // Stall a miss on block 40 (page 10) at the device.
    device.held.store(true, Ordering::Release);
    let mut buf = [0u8; BS as usize];
    let mut fill = Box::pin(volume.read_block(40, &mut buf));
    if fill.as_mut().poll(&mut cx).is_ready() {
        return TestResult::Fail("the gated read completed without the device");
    }
    // A whole-sector write to block 20 (page 5): no read-modify-write read.
    let sector = [0x5au8; 512];
    let mut other = Box::pin(volume.write_byte_range(20 * BS, &sector));
    if !matches!(other.as_mut().poll(&mut cx), Poll::Ready(Ok(()))) {
        return TestResult::Fail("write to another page did not complete");
    }
    drop(other);
    device.held.store(false, Ordering::Release);
    let mut finished = false;
    for _ in 0..16 {
        if let Poll::Ready(r) = fill.as_mut().poll(&mut cx) {
            if r.is_err() {
                return TestResult::Fail("the stalled read failed");
            }
            finished = true;
            break;
        }
    }
    drop(fill);
    if !finished {
        return TestResult::Fail("the stalled read never finished after release");
    }

    // Page 10 was never written, so the fill must have been cached.
    let reads_before = device.reads.load(Ordering::Relaxed);
    let mut again = [0u8; BS as usize];
    if !matches!(poll_once(volume.read_block(40, &mut again)), Some(Ok(()))) {
        return TestResult::Fail("re-read of the filled block failed");
    }
    if device.reads.load(Ordering::Relaxed) != reads_before {
        return TestResult::Fail(
            "a write to another page voided the concurrent fill: the re-read went to the device",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext2_write_elsewhere_does_not_void_a_concurrent_fill
);
fn smoke_ext2_directory_lookup_stops_at_matching_folio() -> TestResult {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use narf_block::{
        ram::RamBlockDevice, BlockCompletion, BlockDevice, BlockFeature, BlockOp, BlockRequest,
        CancelResult, LbaRange,
    };
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    struct DirectoryCountingBlock {
        inner: Arc<RamBlockDevice>,
        reads: AtomicUsize,
    }

    impl BlockDevice for DirectoryCountingBlock {
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

    let device = Arc::new(DirectoryCountingBlock {
        inner: RamBlockDevice::from_image(512, build_ext2_multi_folio_directory_image()),
        reads: AtomicUsize::new(0),
    });
    let volume = match poll_once(Ext2Volume::mount(device.clone(), DomainId::DRIVER_0)) {
        Some(Ok(volume)) => volume,
        _ => return TestResult::Fail("mount failed"),
    };
    let root_inode = match poll_once(volume.read_inode(super::EXT2_ROOT_INO)) {
        Some(Ok(inode)) => inode,
        _ => return TestResult::Fail("root inode read failed"),
    };
    if !matches!(
        poll_once(volume.dir_lookup(&root_inode, b"data")),
        Some(Ok((12, _)))
    ) {
        return TestResult::Fail("first-folio directory lookup failed");
    }
    let reads_after_early = device.reads.load(Ordering::Relaxed);
    if !matches!(
        poll_once(volume.dir_lookup(&root_inode, b"late")),
        Some(Ok((12, _)))
    ) {
        return TestResult::Fail("later-folio directory lookup failed");
    }
    let reads_after_late = device.reads.load(Ordering::Relaxed);
    if reads_after_late <= reads_after_early {
        return TestResult::Fail("early lookup had already read the later directory folio");
    }
    if !matches!(
        poll_once(volume.dir_lookup(&root_inode, b"data")),
        Some(Ok((12, _)))
    ) || device.reads.load(Ordering::Relaxed) != reads_after_late
    {
        return TestResult::Fail("repeated lookup did not reuse the retained cache folio");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext2_directory_lookup_stops_at_matching_folio
);

/// Build a minimal EXT4 image: same block layout as `build_ext2_image`,
/// but the superblock sets the EXTENTS incompat feature and every inode
/// stores an extent tree in its `i_block[]` region instead of the
/// direct/indirect pointer chain. This exercises the ext4 read path —
/// `map_block` → `map_block_extents` — end to end (the thing a real
/// `mkfs.ext4` rootfs uses that a legacy ext2 image never touches).
fn build_ext4_extent_image(file_data: &[u8]) -> Vec<u8> {
    build_ext4_extent_image_sized(file_data, 128)
}

/// [`build_ext4_extent_image`] with `inode_size`-byte inodes. At 256 every
/// inode carries `i_extra_isize = 32`, leaving the in-inode xattr region
/// Linux's mkfs.ext4 default gives; the inode table grows to 8 blocks and
/// the directory/file data move to blocks 13/14.
fn build_ext4_extent_image_sized(file_data: &[u8], inode_size: u16) -> Vec<u8> {
    const BS: usize = 1024;
    const TOTAL_BLOCKS: u32 = 64;
    const INODES_PER_GROUP: u32 = 32;
    const BLOCKS_PER_GROUP: u32 = 64;
    let table_blocks = INODES_PER_GROUP as usize * inode_size as usize / BS;
    let dir_blk = 5 + table_blocks;
    let file_blk = dir_blk + 1;

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
    put_u16(&mut img, sb + 88, inode_size);
    put_u32(&mut img, sb + 96, 0x40); // s_feature_incompat = INCOMPAT_EXTENTS
    if inode_size > 128 {
        put_u16(&mut img, sb + 0x15C, 32); // s_min_extra_isize
        put_u16(&mut img, sb + 0x15E, 32); // s_want_extra_isize
    }

    // Block group descriptor at start of block 2.
    let gdt = 2 * BS;
    put_u32(&mut img, gdt, 3); // block bitmap
    put_u32(&mut img, gdt + 4, 4); // inode bitmap
    put_u32(&mut img, gdt + 8, 5); // inode table
    put_u16(&mut img, gdt + 16, 1); // used dirs (root)

    // Bitmaps (blocks 3, 4) — mark blocks 0..=file_blk and inodes 1,2,12 used.
    for bit in 0..=file_blk {
        img[3 * BS + bit / 8] |= 1 << (bit % 8);
    }
    img[4 * BS] = 0b0000_0011;
    img[4 * BS + 1] = 0b0000_1000;

    let itab = 5 * BS;

    // Write an extent-tree root (header + one leaf extent) into an inode's
    // 60-byte i_block region, mapping logical block 0 → `phys` for `len`.
    fn write_extent_root(img: &mut [u8], inode_off: usize, phys: u32, len: u16, isize: u16) {
        if isize > 128 {
            put_u16(img, inode_off + 128, 32); // i_extra_isize
        }
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
    let root_off = itab + inode_size as usize;
    put_u16(&mut img, root_off, 0x4000 | 0o755); // S_IFDIR | 0755
    put_u32(&mut img, root_off + 4, BS as u32); // size = 1 block
    put_u32(&mut img, root_off + 28, (BS / 512) as u32); // i_blocks
    write_extent_root(&mut img, root_off, dir_blk as u32, 1, inode_size);

    // File inode (#12) at table index 11 — extent → file data (blk 10).
    let file_off = itab + 11 * inode_size as usize;
    put_u16(&mut img, file_off, 0x8000 | 0o644); // S_IFREG | 0644
    put_u32(&mut img, file_off + 4, file_data.len() as u32);
    put_u32(
        &mut img,
        file_off + 28,
        file_data.len().div_ceil(512) as u32,
    );
    if !file_data.is_empty() {
        write_extent_root(&mut img, file_off, file_blk as u32, 1, inode_size);
    }

    // Root directory data (block 9): ".", "..", "data" → inode 12.
    let rd = dir_blk * BS;
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
        let data_off = file_blk * BS;
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

/// `open(O_CREAT)` on a real ext4 root must persist the creator's ownership
/// and final mode, including special mode bits, through a remount.  Desktop
/// lock files use this path; publishing a root-owned `0644` placeholder and
/// correcting it afterward is neither atomic nor crash-safe.
fn smoke_ext4_metadata_csum_create_persists_initial_attrs() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    let mut image = build_ext4_extent_image(b"checksummed extent data");
    if sign_ext4_metadata_csum_fixture(&mut image).is_err() {
        return TestResult::Fail("could not sign metadata-csum fixture");
    }
    let device = RamBlockDevice::from_image(512, image);
    let volume = match poll_once(Ext2Volume::mount(device.clone(), DomainId::DRIVER_0)) {
        Some(Ok(volume)) => volume,
        _ => return TestResult::Fail("metadata-csum fixture did not mount"),
    };
    let file = match poll_once(
        volume
            .root()
            .create_with_attrs("narf-lock", 0o6754, 1000, 1001),
    ) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("create_with_attrs failed on metadata-csum ext4"),
    };
    if file.owners() != (1000, 1001) || file.stat().mode.perms != 0o6754 {
        return TestResult::Fail("created inode did not retain its requested owner or mode");
    }
    drop(file);
    drop(volume);

    let remounted = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(volume)) => volume,
        _ => return TestResult::Fail("metadata-csum volume failed to remount after create"),
    };
    let file = match poll_once(remounted.root().lookup_async("narf-lock")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("created inode disappeared after remount"),
    };
    if file.owners() != (1000, 1001) || file.stat().mode.perms != 0o6754 {
        return TestResult::Fail("remounted created inode lost owner or mode metadata");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext4_metadata_csum_create_persists_initial_attrs
);

/// Rolling back a created inode must leave a valid deleted on-disk record.
/// Clearing only its bitmap bit leaves a zero deletion time and stale mode,
/// which e2fsck reports as a corrupt free inode.
fn smoke_ext2_free_inode_clears_deleted_slot() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_lib::id::DomainId;

    use crate::inode::Inode;
    use crate::volume::Ext2Volume;

    let volume = match poll_once(Ext2Volume::mount(
        RamBlockDevice::from_image(512, build_ext2_image(b"data")),
        DomainId::DRIVER_0,
    )) {
        Some(Ok(volume)) => volume,
        _ => return TestResult::Fail("ext2 fixture did not mount"),
    };
    let ino = match poll_once(volume.alloc_inode()) {
        Some(Ok(ino)) => ino,
        _ => return TestResult::Fail("inode allocation failed"),
    };
    if !matches!(
        poll_once(volume.write_new_inode(ino, &Inode::new_regular(0o600))),
        Some(Ok(()))
    ) {
        return TestResult::Fail("could not initialise test inode");
    }
    if !matches!(poll_once(volume.free_inode(ino)), Some(Ok(()))) {
        return TestResult::Fail("free_inode failed");
    }
    let deleted = match poll_once(volume.read_inode(ino)) {
        Some(Ok(inode)) => inode,
        _ => return TestResult::Fail("deleted inode no longer decodes"),
    };
    if deleted.mode != 0 || deleted.links_count != 0 || deleted.dtime == 0 {
        return TestResult::Fail("freed inode retained live metadata or lacked deletion time");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_free_inode_clears_deleted_slot);

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

// ── ext4 extent-tree write path ─────────────────────────────────────
//
// Every regular file Linux creates on ext4 carries EXT4_EXTENTS_FL. The
// driver could overwrite such a file in place but answered `Unsupported`
// (-EINVAL at write(2)) for any block that needed a new mapping, and for
// truncate/unlink — so glibc's updwtmpx append to /var/log/wtmp failed and
// systemd-update-utmp reported "Failed to write utmp record: Invalid
// argument".

/// Mount `img`, returning the volume and the `data` file.
#[allow(clippy::type_complexity)]
fn mount_ext4_data(
    device: alloc::sync::Arc<narf_block::ram::RamBlockDevice>,
) -> Result<
    (
        alloc::sync::Arc<crate::volume::Ext2Volume<narf_block::ram::RamBlockDevice>>,
        alloc::sync::Arc<dyn narf_filesystem::FileOps>,
    ),
    &'static str,
> {
    use narf_filesystem::FsInstance;
    let volume = match poll_once(crate::volume::Ext2Volume::mount(
        device,
        narf_lib::id::DomainId::DRIVER_0,
    )) {
        Some(Ok(v)) => v,
        _ => return Err("ext4 extent fixture did not mount"),
    };
    let file = match poll_once(volume.root().lookup_async("data")) {
        Some(Ok(f)) => f,
        _ => return Err("lookup of the extent-mapped `data` failed"),
    };
    Ok((volume, file))
}

/// glibc updwtmpx's shape — 384-byte appends — plus writes into holes
/// that force more than the root's four extents (`ext4_ext_grow_indepth`),
/// on a metadata_csum volume; everything reads back after a remount.
fn smoke_ext4_extent_file_grows_and_survives_remount() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    let payload = b"wtmp-seed";
    let mut image = build_ext4_extent_image(payload);
    if sign_ext4_metadata_csum_fixture(&mut image).is_err() {
        return TestResult::Fail("could not sign the metadata_csum fixture");
    }
    let device = RamBlockDevice::from_image(512, image);
    let (volume, file) = match mount_ext4_data(device.clone()) {
        Ok(v) => v,
        Err(e) => return TestResult::Fail(e),
    };
    let mut expected: Vec<u8> = payload.to_vec();
    // Twenty 384-byte records appended, like updwtmpx.
    for i in 0..20u8 {
        let rec = [i.wrapping_add(1); 384];
        let off = expected.len() as u64;
        match poll_once(file.write(off, &rec)) {
            Some(Ok(384)) => {}
            _ => return TestResult::Fail("appending to an extent-mapped file failed"),
        }
        expected.extend_from_slice(&rec);
    }
    // Writes into holes far past EOF: five more discontiguous extents.
    for block in [14u64, 17, 20, 23, 26] {
        let off = block * 1024 + 7;
        match poll_once(file.write(off, b"hole")) {
            Some(Ok(4)) => {}
            _ => return TestResult::Fail("writing into an extent-file hole failed"),
        }
        if expected.len() < off as usize {
            expected.resize(off as usize, 0);
        }
        expected.truncate(off as usize);
        expected.extend_from_slice(b"hole");
    }
    drop(file);
    drop(volume);
    let (_volume, file) = match mount_ext4_data(device) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("the grown extent volume did not remount"),
    };
    if file.stat().size != expected.len() as u64 {
        return TestResult::Fail("i_size after appends and hole writes is wrong");
    }
    let mut got = vec![0u8; expected.len()];
    let mut at = 0usize;
    while at < got.len() {
        match poll_once(file.read(at as u64, &mut got[at..])) {
            Some(Ok(0)) | None => break,
            Some(Ok(n)) => at += n,
            Some(Err(_)) => return TestResult::Fail("reading the grown extent file failed"),
        }
    }
    if got != expected {
        return TestResult::Fail("extent file contents differ after remount");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext4_extent_file_grows_and_survives_remount
);

/// `truncate(0)` frees the tree (then the file grows again), and unlink of
/// an extent-mapped file succeeds — both answered `Unsupported` before.
fn smoke_ext4_extent_truncate_and_unlink() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsError;
    let device = RamBlockDevice::from_image(512, build_ext4_extent_image(b"truncate-me"));
    let (volume, file) = match mount_ext4_data(device) {
        Ok(v) => v,
        Err(e) => return TestResult::Fail(e),
    };
    if !matches!(poll_once(file.truncate(0)), Some(Ok(()))) {
        return TestResult::Fail("truncate(0) of an extent-mapped file failed");
    }
    if file.stat().size != 0 {
        return TestResult::Fail("truncate(0) left a nonzero size");
    }
    if !matches!(poll_once(file.write(0, b"again")), Some(Ok(5))) {
        return TestResult::Fail("writing after truncate(0) failed");
    }
    let mut buf = [0u8; 8];
    if !matches!(poll_once(file.read(0, &mut buf)), Some(Ok(5))) || &buf[..5] != b"again" {
        return TestResult::Fail("data written after truncate(0) did not read back");
    }
    use narf_filesystem::FsInstance;
    let root = volume.root();
    if !matches!(poll_once(root.unlink("data")), Some(Ok(()))) {
        return TestResult::Fail("unlink of an extent-mapped file failed");
    }
    match poll_once(root.lookup_async("data")) {
        Some(Err(FsError::NotFound)) => TestResult::Pass,
        _ => TestResult::Fail("an unlinked extent file is still visible"),
    }
}
kernel_test_in!("drivers/fs/ext2", smoke_ext4_extent_truncate_and_unlink);

/// A write into an UNWRITTEN (fallocated) extent converts just that block:
/// the rest of the extent still reads as zeros, and the written block holds
/// the new bytes with zeros around them (`ext4_split_convert_extents`).
fn smoke_ext4_extent_write_converts_unwritten() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    let mut image = build_ext4_extent_image(b"x");
    let file_ib = 5 * 1024 + 11 * 128 + 40;
    // One 3-block unwritten extent over blocks 10..=12 (ee_len > 32768).
    put_u16(&mut image, file_ib + 16, 3 + 0x8000);
    put_u32(&mut image, 5 * 1024 + 11 * 128 + 4, 3 * 1024); // i_size
    image[3 * 1024 + 1] = 0x1F; // blocks 8..=12 in use
                                // Garbage on disk under the unwritten extent must never surface.
    for b in &mut image[10 * 1024..13 * 1024] {
        *b = 0xAA;
    }
    let device = RamBlockDevice::from_image(512, image);
    let (_volume, file) = match mount_ext4_data(device) {
        Ok(v) => v,
        Err(e) => return TestResult::Fail(e),
    };
    if !matches!(poll_once(file.write(1024 + 5, b"XY")), Some(Ok(2))) {
        return TestResult::Fail("writing into an unwritten extent failed");
    }
    let mut got = vec![0u8; 3 * 1024];
    let mut at = 0usize;
    while at < got.len() {
        match poll_once(file.read(at as u64, &mut got[at..])) {
            Some(Ok(0)) | None => break,
            Some(Ok(n)) => at += n,
            Some(Err(_)) => return TestResult::Fail("reading the converted extent failed"),
        }
    }
    let mut want = vec![0u8; 3 * 1024];
    want[1024 + 5] = b'X';
    want[1024 + 6] = b'Y';
    if got != want {
        return TestResult::Fail("unwritten blocks leaked stale data or lost the write");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext4_extent_write_converts_unwritten
);

/// A full volume answers `NoSpace` (-ENOSPC), the answer `ext4_mb_new_blocks`
/// gives — not the `Unsupported` (-EINVAL) the driver gave for every grow.
fn smoke_ext4_extent_grow_on_full_volume_is_enospc() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsError;
    let mut image = build_ext4_extent_image(b"full");
    for b in &mut image[3 * 1024..3 * 1024 + 8] {
        *b = 0xFF;
    }
    let device = RamBlockDevice::from_image(512, image);
    let (_volume, file) = match mount_ext4_data(device) {
        Ok(v) => v,
        Err(e) => return TestResult::Fail(e),
    };
    match poll_once(file.write(4096, b"more")) {
        Some(Err(FsError::NoSpace)) => TestResult::Pass,
        _ => TestResult::Fail("growing an extent file on a full volume must be NoSpace"),
    }
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext4_extent_grow_on_full_volume_is_enospc
);

// ── ext4 extended attributes and POSIX ACLs ─────────────────────────
//
// The driver had no xattr store: every set answered `Unsupported`, so the
// syscall layer returned -EOPNOTSUPP for `system.posix_acl_*`,
// systemd-tmpfiles concluded the root filesystem has no ACLs, and
// /var/log/journal never got its group:adm / group:wheel entries.

/// uapi `system.posix_acl_*` bytes (version 2): user::rwx group::r-x
/// group:<gid>:r-x mask::r-x other::---.
fn uapi_group_acl(gid: u32) -> Vec<u8> {
    use narf_filesystem::{
        AclEntry, PosixAcl, ACL_GROUP, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER, ACL_USER_OBJ,
    };
    PosixAcl::from_entries(vec![
        AclEntry::tagged(ACL_USER_OBJ, 7),
        AclEntry::tagged(ACL_GROUP_OBJ, 5),
        AclEntry::with_id(ACL_GROUP, gid, 5),
        AclEntry::tagged(ACL_MASK, 5),
        AclEntry::tagged(ACL_OTHER, 0),
    ])
    .to_xattr()
}

fn count_used_blocks(image: &[u8]) -> u32 {
    image[3 * 1024..3 * 1024 + 8]
        .iter()
        .map(|b| b.count_ones())
        .sum()
}

/// tmpfiles' `a+ /var/log/journal ... d:group:adm:r-x,group:adm:r-x`: an
/// access and a default ACL on a directory and a user xattr on a file land
/// in the in-inode region and an xattr block, survive a remount, update the
/// mode (`posix_acl_update_mode`), feed the VFS's `default_acl()` hook and
/// DAC check, and list.
fn smoke_ext4_xattr_acl_roundtrip_survives_remount() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::XATTR_NAME_POSIX_ACL_DEFAULT as DEFAULT;
    use narf_filesystem::{AclType, FsInstance, XATTR_NAME_POSIX_ACL_ACCESS as ACCESS};
    let device = RamBlockDevice::from_image(512, build_ext4_extent_image_sized(b"j", 256));
    let (volume, file) = match mount_ext4_data(device.clone()) {
        Ok(v) => v,
        Err(e) => return TestResult::Fail(e),
    };
    let adm = uapi_group_acl(4);
    let wheel = uapi_group_acl(998);
    let root = volume.root();
    if root.access_acl_present() != Some(false) {
        return TestResult::Fail("an xattr-free directory must say so cheaply");
    }
    if !matches!(poll_once(root.set_xattr(ACCESS, &adm, 0)), Some(Ok(()))) {
        return TestResult::Fail("setting an access ACL on an ext4 directory failed");
    }
    if !matches!(poll_once(root.set_xattr(DEFAULT, &wheel, 0)), Some(Ok(()))) {
        return TestResult::Fail("setting a default ACL on an ext4 directory failed");
    }
    if !matches!(poll_once(file.set_xattr(ACCESS, &adm, 0)), Some(Ok(()))) {
        return TestResult::Fail("setting an access ACL on an ext4 file failed");
    }
    // A value too big for the inode body forces the external block.
    let big = vec![0x5a; 300];
    if !matches!(poll_once(file.set_xattr("user.big", &big, 0)), Some(Ok(()))) {
        return TestResult::Fail("setting a 300-byte user xattr failed");
    }
    drop((file, root, volume));
    let (volume, file) = match mount_ext4_data(device) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("volume with xattrs did not remount"),
    };
    let root = volume.root();
    if poll_once(root.get_xattr(ACCESS)).and_then(Result::ok) != Some(adm.clone())
        || poll_once(root.get_xattr(DEFAULT)).and_then(Result::ok) != Some(wheel.clone())
    {
        return TestResult::Fail("directory ACLs did not survive the remount");
    }
    if root.access_acl_present() == Some(false) {
        return TestResult::Fail("a directory with an ACL must not claim to have none");
    }
    if root.default_acl() != Some(wheel) {
        return TestResult::Fail("DirOps::default_acl must hand the VFS the default ACL");
    }
    if poll_once(file.get_xattr(ACCESS)).and_then(Result::ok) != Some(adm)
        || poll_once(file.get_xattr("user.big")).and_then(Result::ok) != Some(big)
    {
        return TestResult::Fail("file xattrs did not survive the remount");
    }
    // posix_acl_update_mode: the mode becomes user::rwx, mask r-x, other --- = 0750.
    if root.dir_mode() & 0o777 != 0o750 || file.stat().mode.perms & 0o777 != 0o750 {
        return TestResult::Fail("setting an access ACL did not rewrite the mode");
    }
    let names = poll_once(file.list_xattr())
        .and_then(Result::ok)
        .unwrap_or_default();
    if names != b"system.posix_acl_access\0user.big\0" {
        return TestResult::Fail("listxattr did not report both attributes");
    }
    // The VFS DAC check sees the ACL: gid 4 may read, gid 5 may not.
    let acl = match poll_once(narf_filesystem::acl_of_file(file.as_ref(), AclType::Access)) {
        Some(Ok(Some(acl))) => acl,
        _ => return TestResult::Fail("acl_of_file did not decode the stored ACL"),
    };
    let owner = narf_filesystem::FileOwner {
        uid: 0,
        gid: 0,
        perms: 0o750,
        is_dir: false,
    };
    let read = narf_filesystem::AccessRequest {
        read: true,
        write: false,
        exec: false,
    };
    let member = narf_filesystem::Accessor {
        uid: 1000,
        gid: 4,
        ..Default::default()
    };
    let stranger = narf_filesystem::Accessor {
        uid: 1000,
        gid: 5,
        ..Default::default()
    };
    if !narf_filesystem::posix_access_ok_with_acl(owner, &member, read, Some(&acl))
        || narf_filesystem::posix_access_ok_with_acl(owner, &stranger, read, Some(&acl))
    {
        return TestResult::Fail("the stored ACL did not decide the DAC check");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext4_xattr_acl_roundtrip_survives_remount
);

/// 128-byte inodes (no in-inode region) on a metadata_csum volume: the ACL
/// goes to a checksummed xattr block, which the remount verifies.
fn smoke_ext4_xattr_block_metadata_csum_survives_remount() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::XATTR_NAME_POSIX_ACL_ACCESS as ACCESS;
    let mut image = build_ext4_extent_image(b"csum");
    if sign_ext4_metadata_csum_fixture(&mut image).is_err() {
        return TestResult::Fail("could not sign the metadata_csum fixture");
    }
    let device = RamBlockDevice::from_image(512, image);
    let (volume, file) = match mount_ext4_data(device.clone()) {
        Ok(v) => v,
        Err(e) => return TestResult::Fail(e),
    };
    let acl = uapi_group_acl(4);
    if !matches!(poll_once(file.set_xattr(ACCESS, &acl, 0)), Some(Ok(()))) {
        return TestResult::Fail("setting an ACL on a 128-byte inode failed");
    }
    drop((file, volume));
    let (_volume, file) = match mount_ext4_data(device) {
        Ok(v) => v,
        Err(_) => {
            return TestResult::Fail("metadata_csum volume with an xattr block did not remount")
        }
    };
    match poll_once(file.get_xattr(ACCESS)) {
        Some(Ok(v)) if v == acl => TestResult::Pass,
        _ => TestResult::Fail("the checksummed xattr block did not read back"),
    }
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext4_xattr_block_metadata_csum_survives_remount
);

/// `posix_acl_chmod` keeps the mask in step with chmod, and unlinking the
/// file releases its xattr block (`ext4_xattr_delete_inode`).
fn smoke_ext4_acl_chmod_masks_and_unlink_frees_block() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::{AclType, FsInstance, ACL_MASK, XATTR_NAME_POSIX_ACL_ACCESS as ACCESS};
    let device = RamBlockDevice::from_image(512, build_ext4_extent_image(b"chmod"));
    let (volume, file) = match mount_ext4_data(device.clone()) {
        Ok(v) => v,
        Err(e) => return TestResult::Fail(e),
    };
    let before = count_used_blocks(&device.snapshot());
    if !matches!(
        poll_once(file.set_xattr(ACCESS, &uapi_group_acl(4), 0)),
        Some(Ok(()))
    ) {
        return TestResult::Fail("setting an ACL failed");
    }
    if count_used_blocks(&device.snapshot()) != before + 1 {
        return TestResult::Fail("a 128-byte inode's ACL must take one xattr block");
    }
    if !matches!(poll_once(file.set_perms(0o600)), Some(Ok(()))) {
        return TestResult::Fail("chmod 0600 failed");
    }
    let acl = match poll_once(narf_filesystem::acl_of_file(file.as_ref(), AclType::Access)) {
        Some(Ok(Some(acl))) => acl,
        _ => return TestResult::Fail("the ACL vanished on chmod"),
    };
    if acl
        .entries
        .iter()
        .find(|e| e.tag == ACL_MASK)
        .map(|e| e.perm)
        != Some(0)
    {
        return TestResult::Fail("chmod 0600 must set the ACL mask to ---");
    }
    drop(file);
    if !matches!(poll_once(volume.root().unlink("data")), Some(Ok(()))) {
        return TestResult::Fail("unlink of the ACL-carrying file failed");
    }
    // The data block and the xattr block both come back.
    if count_used_blocks(&device.snapshot()) != before - 1 {
        return TestResult::Fail("unlink must free the file's xattr block");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext4_acl_chmod_masks_and_unlink_frees_block
);

/// Linux's refusals: a default ACL on a file (`acl ? -EACCES : 0`), an
/// ACL whose entries are not a valid sequence (-EINVAL), an unknown
/// `a_version` (`Unsupported`, which the syscall layer reports as
/// -EOPNOTSUPP for an ACL name), XATTR_CREATE/XATTR_REPLACE (-EEXIST /
/// -ENODATA), a missing attribute (-ENODATA), and a value no single block
/// can hold (-ENOSPC without ea_inode).
fn smoke_ext4_xattr_rejects_like_linux() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::XATTR_NAME_POSIX_ACL_DEFAULT as DEFAULT;
    use narf_filesystem::{FsError, XATTR_NAME_POSIX_ACL_ACCESS as ACCESS};
    let device = RamBlockDevice::from_image(512, build_ext4_extent_image_sized(b"neg", 256));
    let (_volume, file) = match mount_ext4_data(device) {
        Ok(v) => v,
        Err(e) => return TestResult::Fail(e),
    };
    let set = |name: &str, value: &[u8], flags: u32| poll_once(file.set_xattr(name, value, flags));
    if !matches!(
        set(DEFAULT, &uapi_group_acl(4), 0),
        Some(Err(FsError::PermissionDenied))
    ) {
        return TestResult::Fail("a default ACL on a regular file must be PermissionDenied");
    }
    // Removing a default ACL that cannot exist is a successful no-op.
    if !matches!(poll_once(file.remove_xattr(DEFAULT)), Some(Ok(()))) {
        return TestResult::Fail("removing a file's (absent) default ACL must succeed");
    }
    let mut bad_tag = uapi_group_acl(4);
    bad_tag[4] = 0x40;
    if !matches!(set(ACCESS, &bad_tag, 0), Some(Err(FsError::InvalidData))) {
        return TestResult::Fail("an ACL with an unknown tag must be InvalidData");
    }
    let mut v1 = uapi_group_acl(4);
    v1[0] = 1;
    if !matches!(set(ACCESS, &v1, 0), Some(Err(FsError::Unsupported))) {
        return TestResult::Fail("an ACL with a_version 1 must be Unsupported (EOPNOTSUPP)");
    }
    if !matches!(set("user.a", b"1", 1), Some(Ok(())))
        || !matches!(set("user.a", b"2", 1), Some(Err(FsError::Busy)))
    {
        return TestResult::Fail("XATTR_CREATE on an existing name must be Busy (EEXIST)");
    }
    if !matches!(set("user.missing", b"x", 2), Some(Err(FsError::NotFound))) {
        return TestResult::Fail("XATTR_REPLACE on a missing name must be NotFound (ENODATA)");
    }
    if !matches!(
        poll_once(file.get_xattr("user.missing")),
        Some(Err(FsError::NotFound))
    ) || !matches!(
        poll_once(file.remove_xattr("user.missing")),
        Some(Err(FsError::NotFound))
    ) {
        return TestResult::Fail("get/remove of a missing xattr must be NotFound (ENODATA)");
    }
    if !matches!(
        set("user.huge", &vec![1u8; 2048], 0),
        Some(Err(FsError::NoSpace))
    ) {
        return TestResult::Fail("a value larger than a block must be NoSpace (ENOSPC)");
    }
    match poll_once(file.get_xattr("user.a")) {
        Some(Ok(v)) if v == b"1" => TestResult::Pass,
        _ => TestResult::Fail("a refused XATTR_CREATE clobbered the stored value"),
    }
}
kernel_test_in!("drivers/fs/ext2", smoke_ext4_xattr_rejects_like_linux);

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

/// `DirOps::rename_to` — the cross-directory rename the VFS calls — must move
/// names on ext2/ext4 like `ext4_rename`. ext2 never implemented it, so every
/// cross-directory move fell back to `-EXDEV` for a directory (and a
/// link+unlink emulation for a file); Firefox's cache and profile writes hit
/// that on the CachyOS root. Covers, through the trait:
/// - a directory moved between directories: both parents' link counts and
///   the moved directory's `..` follow it;
/// - an existing EMPTY directory victim is replaced and released (its parent
///   loses the ".." back-link);
/// - a NON-EMPTY directory victim is refused with `Busy` (-ENOTEMPTY) and
///   nothing moves.
fn smoke_ext2_rename_to_moves_directories_across_dirs() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::{DirOps, FsError, FsInstance};
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    let img = build_ext2_image(b"x");
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = volume.root();
    let mkdir =
        |dir: &dyn DirOps, name: &str| poll_once(dir.mkdir(name)).is_some_and(|r| r.is_ok());
    if !mkdir(&*root, "a") || !mkdir(&*root, "b") {
        return TestResult::Fail("mkdir a/b failed");
    }
    let (a, b) = match (
        poll_once(root.lookup_dir_async("a")),
        poll_once(root.lookup_dir_async("b")),
    ) {
        (Some(Ok(a)), Some(Ok(b))) => (a, b),
        _ => return TestResult::Fail("lookup a/b failed"),
    };
    if !mkdir(&*a, "sub")
        || !mkdir(&*a, "x")
        || !mkdir(&*b, "x")
        || !mkdir(&*a, "y")
        || !mkdir(&*b, "z")
    {
        return TestResult::Fail("mkdir children failed");
    }
    let z = match poll_once(b.lookup_dir_async("z")) {
        Some(Ok(z)) => z,
        _ => return TestResult::Fail("lookup b/z failed"),
    };
    if !mkdir(&*z, "keep") {
        return TestResult::Fail("mkdir b/z/keep failed");
    }
    let ino = |parent: u32, name: &[u8]| -> Option<u32> {
        let dir = poll_once(volume.read_inode(parent))?.ok()?;
        poll_once(volume.dir_lookup(&dir, name))?
            .ok()
            .map(|(i, _)| i)
    };
    let links = |i: u32| {
        poll_once(volume.read_inode(i))
            .and_then(|r| r.ok())
            .map(|n| n.links_count)
    };
    let root_ino = crate::EXT2_ROOT_INO;
    let (Some(a_ino), Some(b_ino)) = (ino(root_ino, b"a"), ino(root_ino, b"b")) else {
        return TestResult::Fail("inode lookup of a/b failed");
    };

    // 1. Move directory a/sub → b/sub.
    match poll_once(a.rename_to("sub", &*b, "sub", 0)) {
        Some(Ok(())) => {}
        Some(Err(FsError::Unsupported)) => {
            return TestResult::Fail("ext2 rename_to is Unsupported (the VFS reports -EXDEV)")
        }
        _ => return TestResult::Fail("rename_to of a directory across dirs failed"),
    }
    let Some(sub_ino) = ino(b_ino, b"sub") else {
        return TestResult::Fail("b/sub missing after the move");
    };
    if ino(a_ino, b"sub").is_some() {
        return TestResult::Fail("a/sub still present after the move");
    }
    if ino(sub_ino, b"..") != Some(b_ino) {
        return TestResult::Fail("moved directory's .. does not name its new parent");
    }

    // 2. Replace the EMPTY directory b/x with a/x.
    let Some(old_bx) = ino(b_ino, b"x") else {
        return TestResult::Fail("b/x missing");
    };
    match poll_once(a.rename_to("x", &*b, "x", 0)) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("replacing an empty directory failed"),
    }
    if ino(b_ino, b"x") == Some(old_bx) || ino(a_ino, b"x").is_some() {
        return TestResult::Fail("empty-directory replacement did not move the name");
    }
    // a keeps only y (2 + 1); b holds sub, x, z (2 + 3).
    if links(a_ino) != Some(3) || links(b_ino) != Some(5) {
        return TestResult::Fail("parent link counts are wrong after the directory moves");
    }

    // 3. A NON-EMPTY victim (b/z holds keep) is refused, nothing changes.
    match poll_once(a.rename_to("y", &*b, "z", 0)) {
        Some(Err(FsError::Busy)) => {}
        _ => return TestResult::Fail("replacing a non-empty directory was not Busy (-ENOTEMPTY)"),
    }
    if ino(a_ino, b"y").is_none() || ino(b_ino, b"z").is_none() {
        return TestResult::Fail("a refused rename changed a directory");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext2_rename_to_moves_directories_across_dirs
);

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

/// Unlinking the last link of a fast symlink must not walk `i_block` as block
/// pointers: it holds the link text. Firefox's profile `lock -> IP:+PID`
/// symlink decoded to an out-of-range block number and `unlink` failed with
/// EIO, wedging every later launch on "profile in use". Linux never truncates
/// a fast symlink (`fs/ext4/inode.c::ext4_can_truncate`).
fn smoke_ext2_unlink_fast_symlink_skips_block_walk() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    let img = build_ext2_image(b"x");
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let target = b"10.0.2.15:+772";
    let sym_ino = match poll_once(volume.dir_create_symlink(crate::EXT2_ROOT_INO, b"lock", target))
    {
        Some(Ok(i)) => i,
        _ => return TestResult::Fail("fast symlink create failed"),
    };
    let inode = match poll_once(volume.read_inode(sym_ino)) {
        Some(Ok(i)) => i,
        _ => return TestResult::Fail("read symlink inode failed"),
    };
    if !inode.is_fast_symlink(volume.block_size() as u32) {
        return TestResult::Fail("short symlink was not classified as fast");
    }
    if !matches!(
        poll_once(volume.dir_unlink(crate::EXT2_ROOT_INO, b"lock")),
        Some(Ok(()))
    ) {
        return TestResult::Fail("unlink of a fast symlink failed");
    }
    let root_inode = match poll_once(volume.read_inode(crate::EXT2_ROOT_INO)) {
        Some(Ok(i)) => i,
        _ => return TestResult::Fail("root inode read failed"),
    };
    if !matches!(
        poll_once(volume.dir_lookup(&root_inode, b"lock")),
        Some(Err(_))
    ) {
        return TestResult::Fail("unlinked fast symlink still resolves");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext2_unlink_fast_symlink_skips_block_walk
);

// ── VFS-layer symlink hardening ────────────────────────────────────────
// The fast/slow round-trip tests above call `read_symlink_target` directly on
// the volume. These exercise the FileOps/VFS surface every real path walk and
// `readlink(2)` actually use — resolve_async{,_nofollow} → FileOps::read /
// symlink-follow — plus the exact 60/61-byte fast↔slow boundary. A regression
// where the VFS layer returns an empty target here is what turns a downstream
// consumer's fd→path resolution into an empty string.

// NOFOLLOW resolve of a FAST (inline) ext symlink returns the symlink node,
// and reading it through FileOps yields the inline target — the readlink(2) path.
fn smoke_ext2_symlink_vfs_readlink_fast() -> TestResult {
    use crate::volume::Ext2Volume;
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::{FileType, FsInstance};
    use narf_lib::id::DomainId;
    let device = RamBlockDevice::from_image(512, build_ext2_image(b"x"));
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    if !matches!(
        poll_once(volume.dir_create_symlink(crate::EXT2_ROOT_INO, b"sym", b"data")),
        Some(Ok(_))
    ) {
        return TestResult::Fail("fast symlink create failed");
    }
    let node = match poll_once(narf_filesystem::resolve_async_nofollow(
        volume.root(),
        "sym",
    )) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("resolve_async_nofollow of ext symlink failed"),
    };
    if node.stat().mode.file_type != FileType::Symlink {
        return TestResult::Fail("resolved ext node is not a symlink");
    }
    let mut buf = [0u8; 64];
    let n = match poll_once(node.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("FileOps::read of ext symlink target failed"),
    };
    if &buf[..n] != b"data" {
        return TestResult::Fail("VFS readlink of fast ext symlink returned wrong/empty target");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_symlink_vfs_readlink_fast);

// FOLLOW resolve THROUGH a fast ext symlink reaches the target file, not the
// symlink node — the path-walk case (open("/via-symlink/...")).
fn smoke_ext2_symlink_vfs_follow_fast() -> TestResult {
    use crate::volume::Ext2Volume;
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::{FileType, FsInstance};
    use narf_lib::id::DomainId;
    let device = RamBlockDevice::from_image(512, build_ext2_image(b"x"));
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    // `build_ext2_image` seeds a regular file "data" (content "x"); symlink to it.
    if !matches!(
        poll_once(volume.dir_create_symlink(crate::EXT2_ROOT_INO, b"lnk", b"data")),
        Some(Ok(_))
    ) {
        return TestResult::Fail("symlink create failed");
    }
    // FOLLOW resolve of "lnk" must land on the "data" FILE, not the symlink node.
    let node = match poll_once(narf_filesystem::resolve_async(volume.root(), "lnk")) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("resolve_async (follow) through ext symlink failed"),
    };
    if node.stat().mode.file_type == FileType::Symlink {
        return TestResult::Fail("follow-resolve returned the symlink, not the target file");
    }
    // The followed node is the seeded "data" file — reading it yields "x",
    // proving the symlink resolved to the correct target end-to-end.
    let mut buf = [0u8; 8];
    let n = match poll_once(node.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("read of followed symlink target failed"),
    };
    if &buf[..n] != b"x" {
        return TestResult::Fail("follow-resolve reached the wrong file (content mismatch)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_symlink_vfs_follow_fast);

// The 60/61-byte fast↔slow boundary, read back through the VFS: a 60-byte
// target is inline (fast, blocks==0), 61 bytes spills to a data block (slow),
// and both must read back byte-identical.
fn smoke_ext2_symlink_boundary_60_61() -> TestResult {
    use crate::volume::Ext2Volume;
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;
    let device = RamBlockDevice::from_image(512, build_ext2_image(b"x"));
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let t60 = [b'a'; 60];
    let t61 = [b'b'; 61];
    for (name, expect) in [
        (b"s60".as_slice(), t60.as_slice()),
        (b"s61".as_slice(), t61.as_slice()),
    ] {
        if !matches!(
            poll_once(volume.dir_create_symlink(crate::EXT2_ROOT_INO, name, expect)),
            Some(Ok(_))
        ) {
            return TestResult::Fail("boundary symlink create failed");
        }
        let leaf = core::str::from_utf8(name).unwrap();
        let node = match poll_once(narf_filesystem::resolve_async_nofollow(volume.root(), leaf)) {
            Some(Ok(n)) => n,
            _ => return TestResult::Fail("resolve of boundary symlink failed"),
        };
        let mut buf = [0u8; 128];
        let n = match poll_once(node.read(0, &mut buf)) {
            Some(Ok(n)) => n,
            _ => return TestResult::Fail("read of boundary symlink target failed"),
        };
        if &buf[..n] != expect {
            return TestResult::Fail("boundary symlink target mismatch (fast/slow off-by-one?)");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_symlink_boundary_60_61);

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

/// Linux keeps one in-memory inode per on-disk inode (`fs/inode.c`,
/// `iget_locked`): every lookup of every name of a file — including a hard
/// link — and every `root()` returns the same inode, which is what lets the
/// inode's page cache be shared. ext2 used to build a fresh node per
/// lookup, so two names of one file were two unrelated in-memory inodes.
fn smoke_ext2_icache_one_node_per_inode() -> TestResult {
    use alloc::sync::Arc;
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::testing;
    use crate::volume::Ext2Volume;

    let device = RamBlockDevice::from_image(512, testing::hard_link_image(b"one inode"));
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = volume.root();
    let (data, link) = match (
        poll_once(root.lookup_async("data")),
        poll_once(root.lookup_async("link")),
    ) {
        (Some(Ok(data)), Some(Ok(link))) => (data, link),
        _ => return TestResult::Fail("lookup of the two names failed"),
    };
    if !Arc::ptr_eq(&data, &link) {
        return TestResult::Fail("two names of one inode resolved to two in-memory inodes");
    }
    let again = match poll_once(root.lookup_async("data")) {
        Some(Ok(node)) => node,
        _ => return TestResult::Fail("second lookup failed"),
    };
    if !Arc::ptr_eq(&data, &again) {
        return TestResult::Fail("a repeated lookup built a second in-memory inode");
    }
    let root_again = volume.root();
    if !core::ptr::eq(
        Arc::as_ptr(&root) as *const (),
        Arc::as_ptr(&root_again) as *const (),
    ) {
        return TestResult::Fail("root() built a second in-memory root inode");
    }
    // A change made through one holder is the inode every holder sees.
    if poll_once(link.set_perms(0o600)).is_none_or(|r| r.is_err()) {
        return TestResult::Fail("chmod through the hard link failed");
    }
    if data.stat().mode.perms != 0o600 {
        return TestResult::Fail("chmod through one name is invisible through the other");
    }
    // Once nothing holds it, the inode leaves the cache (Linux evict).
    drop((data, link, again));
    if volume.icache_get(testing::FILE_INO).is_some() {
        return TestResult::Fail("an unreferenced inode stayed pinned in the inode cache");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_icache_one_node_per_inode);

/// `write(2)` updates the cached page in place (Linux
/// `generic_perform_write` copies into the page-cache folio) and writes it
/// through to the blocks: a read after the write is served from the same
/// page with no device read, and the disk holds the new bytes. ext2 used to
/// write the device and then drop the cached copy, so every write forced the
/// next read of that page back to the disk — and a mapping of the page could
/// never have seen the write.
fn smoke_ext2_write_updates_the_cached_page_in_place() -> TestResult {
    use core::sync::atomic::Ordering;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::testing;
    use crate::volume::Ext2Volume;

    let content: Vec<u8> = (0..6000).map(|i| (i % 251) as u8).collect();
    let device = GatedCountingBlock::new(testing::hard_link_image(&content));
    let volume = match poll_once(Ext2Volume::mount(device.clone(), DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let file = match poll_once(volume.root().lookup_async("data")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup failed"),
    };
    let mut buf = [0u8; 16];
    if !matches!(poll_once(file.read(4096, &mut buf)), Some(Ok(16))) {
        return TestResult::Fail("first read failed");
    }
    if !matches!(poll_once(file.write(4100, b"NEW!")), Some(Ok(4))) {
        return TestResult::Fail("write failed");
    }
    let reads_before = device.reads.load(Ordering::Relaxed);
    if !matches!(poll_once(file.read(4096, &mut buf)), Some(Ok(16))) {
        return TestResult::Fail("read after write failed");
    }
    if device.reads.load(Ordering::Relaxed) != reads_before {
        return TestResult::Fail("the write dropped the cached page: the next read hit the device");
    }
    if &buf[4..8] != b"NEW!" || buf[..4] != content[4096..4100] || buf[8..] != content[4104..4112] {
        return TestResult::Fail("the cached page does not hold the written bytes");
    }
    // File offset 4100 is block FILE_FIRST_BLOCK + 4, byte 4.
    let mut disk = [0u8; testing::BLOCK_SIZE];
    let block = u64::from(testing::FILE_FIRST_BLOCK) + 4;
    if !matches!(poll_once(volume.read_block(block, &mut disk)), Some(Ok(())))
        || &disk[4..8] != b"NEW!"
    {
        return TestResult::Fail("write(2) did not reach the disk");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext2_write_updates_the_cached_page_in_place
);

/// Truncation zeroes the rest of the new last block (Linux `ext2_setsize`
/// -> `block_truncate_page`), so growing the file again reads zeros there,
/// never the bytes that were cut off. ext2's shrink only rewrote `i_size`, so
/// a shrink followed by a grow resurrected the old tail.
fn smoke_ext2_truncate_then_extend_reads_zeros() -> TestResult {
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::testing;
    use crate::volume::Ext2Volume;

    let content = [0x5au8; 6000];
    let device = GatedCountingBlock::new(testing::hard_link_image(&content));
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let file = match poll_once(volume.root().lookup_async("data")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup failed"),
    };
    let mut buf = [0u8; 6000];
    if !matches!(poll_once(file.read(0, &mut buf)), Some(Ok(6000))) {
        return TestResult::Fail("initial read failed");
    }
    if poll_once(file.truncate(5000)).is_none_or(|r| r.is_err())
        || poll_once(file.truncate(6000)).is_none_or(|r| r.is_err())
    {
        return TestResult::Fail("truncate failed");
    }
    if !matches!(poll_once(file.read(0, &mut buf)), Some(Ok(6000))) {
        return TestResult::Fail("read after re-extension failed");
    }
    if buf[..5000].iter().any(|&b| b != 0x5a) {
        return TestResult::Fail("truncate damaged the bytes before the new EOF");
    }
    if buf[5000..].iter().any(|&b| b != 0) {
        return TestResult::Fail("re-extending a truncated file resurrected the cut-off bytes");
    }
    // Not just the cache: the block on disk was zeroed past the cut too.
    let mut disk = [0u8; testing::BLOCK_SIZE];
    let block = u64::from(testing::FILE_FIRST_BLOCK) + 4; // bytes 4096..5120
    if !matches!(poll_once(volume.read_block(block, &mut disk)), Some(Ok(())))
        || disk[..5000 - 4096].iter().any(|&b| b != 0x5a)
        || disk[5000 - 4096..].iter().any(|&b| b != 0)
    {
        return TestResult::Fail("the cut-off tail of the last block survived on disk");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext2_truncate_then_extend_reads_zeros
);

/// Removing the last link of an inode something still holds must not free it
/// (`ext2_evict_inode` runs from `iput_final`, at the LAST reference). The
/// unlinked inode keeps its size, data and inode number until then, so an
/// open descriptor still reads it and a `MAP_SHARED` mapping still faults it
/// in. KDE's KSharedDataCache depends on exactly this: it unlinks a corrupted
/// cache while other processes have it mapped. Freeing at unlink zeroed the
/// size under plasmashell's mapping (SIGBUS on its next write) and handed the
/// inode number and blocks to the replacement file.
fn smoke_ext2_unlink_keeps_an_open_inode_until_its_last_reference() -> TestResult {
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::testing;
    use crate::volume::Ext2Volume;

    let content = [0x5au8; 6000];
    let device = GatedCountingBlock::new(testing::hard_link_image(&content));
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = volume.root();
    let file = match poll_once(root.lookup_async("data")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup failed"),
    };
    // The fixture names the inode twice; drop both names.
    if !matches!(poll_once(root.unlink("data")), Some(Ok(())))
        || !matches!(poll_once(root.unlink("link")), Some(Ok(())))
    {
        return TestResult::Fail("unlink failed");
    }
    if file.stat().size != 6000 {
        return TestResult::Fail("unlinking the last name zeroed an open inode's size");
    }
    let mut buf = [0u8; 6000];
    if !matches!(poll_once(file.read(0, &mut buf)), Some(Ok(6000)))
        || buf.iter().any(|&b| b != 0x5a)
    {
        return TestResult::Fail("an open, unlinked inode no longer reads its data");
    }
    if file.mmap_fault(4096).is_err() {
        return TestResult::Fail("a mapping of an open, unlinked inode was refused");
    }
    // The inode number is still in use: a new file must get another one.
    let fresh = match poll_once(root.create("fresh")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create failed"),
    };
    if fresh.ino() == u64::from(testing::FILE_INO) {
        return TestResult::Fail("an open, unlinked inode number was reused");
    }
    // The last reference goes: the inode is released, so the next
    // allocation can have its number again.
    drop(file);
    let again = match poll_once(root.create("again")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create after the last reference failed"),
    };
    if again.ino() != u64::from(testing::FILE_INO) {
        return TestResult::Fail("dropping the last reference did not release the inode");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext2_unlink_keeps_an_open_inode_until_its_last_reference
);

/// Truncating DOWN releases every block wholly past the new EOF
/// (`ext4_truncate` -> `ext4_ind_truncate` / `ext4_ext_remove_space`). NARF
/// shrank only `i_size` and kept the blocks mapped, so the next extension —
/// a write past a hole, `ftruncate` up, an extending `fallocate` — read the
/// old bytes back where Linux guarantees zeros. fstests' fsx found it within
/// 60 operations, with and without mmap.
fn smoke_ext2_truncate_down_frees_blocks_past_eof() -> TestResult {
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::testing;
    use crate::volume::Ext2Volume;

    const BS: u64 = testing::BLOCK_SIZE as u64;
    // Six direct blocks of data, then one byte at block 14, which needs the
    // single-indirect block.
    let content = [0x5au8; 6000];
    let device = GatedCountingBlock::new(testing::hard_link_image(&content));
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let file = match poll_once(volume.root().lookup_async("data")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup failed"),
    };
    if !matches!(poll_once(file.write(14 * BS, &[0xa5])), Some(Ok(1))) {
        return TestResult::Fail("write through the single-indirect block failed");
    }
    let before = file.stat().blocks;
    // Keep blocks 0 and 1 (1500 bytes ends inside block 1).
    if poll_once(file.truncate(1500)).is_none_or(|r| r.is_err()) {
        return TestResult::Fail("truncate down failed");
    }
    // Released: direct blocks 2..=5, block 14 and the indirect block.
    let sectors = BS / 512;
    if file.stat().blocks + 6 * sectors != before {
        return TestResult::Fail("truncate down did not release the blocks past EOF");
    }
    if poll_once(file.truncate(15 * BS)).is_none_or(|r| r.is_err()) {
        return TestResult::Fail("re-extending truncate failed");
    }
    let mut buf = alloc::vec![0u8; 15 * BS as usize];
    if !matches!(poll_once(file.read(0, &mut buf)), Some(Ok(n)) if n == buf.len()) {
        return TestResult::Fail("read after re-extension failed");
    }
    if buf[..1500].iter().any(|&b| b != 0x5a) {
        return TestResult::Fail("truncate damaged the bytes before the new EOF");
    }
    if buf[1500..].iter().any(|&b| b != 0) {
        return TestResult::Fail("re-extension read back bytes from before the truncate");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext2_truncate_down_frees_blocks_past_eof
);

/// The extent-tree half of [`smoke_ext2_truncate_down_frees_blocks_past_eof`]
/// (`ext4_ext_remove_space(inode, first, EXT_MAX_BLOCKS - 1)`): extents past
/// the cut are freed, one straddling it is trimmed, and a tree that grew a
/// leaf block keeps working after the cut.
fn smoke_ext4_extent_truncate_down_frees_blocks_past_eof() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    const BS: u64 = 1024;
    let device = RamBlockDevice::from_image(512, build_ext4_extent_image(b"x"));
    let (_volume, file) = match mount_ext4_data(device) {
        Ok(v) => v,
        Err(e) => return TestResult::Fail(e),
    };
    // Blocks 0, 2, 4, ..., 14 written, the rest holes: eight one-block
    // extents, more than the in-inode root holds, so the tree gains a leaf.
    for i in 0..8u64 {
        if !matches!(
            poll_once(file.write(2 * i * BS, &[0xa0 + i as u8; 3])),
            Some(Ok(3))
        ) {
            return TestResult::Fail("seeding the extents failed");
        }
    }
    // A three-block extent at 16..=18 that the cut will split.
    if !matches!(
        poll_once(file.write(16 * BS, &[0xee; 3 * BS as usize])),
        Some(Ok(_))
    ) {
        return TestResult::Fail("seeding the straddling extent failed");
    }
    let before = file.stat().blocks;
    // Keep through block 16, into which the new EOF falls.
    let cut = 16 * BS + 10;
    if poll_once(file.truncate(cut)).is_none_or(|r| r.is_err()) {
        return TestResult::Fail("truncate down failed");
    }
    // Released: blocks 17 and 18 of the straddling extent.
    if file.stat().blocks + 2 * (BS / 512) != before {
        return TestResult::Fail("truncate down did not trim the straddling extent");
    }
    // Then cut into the middle of the one-block extents: 8, 10, 12, 14 and
    // what is left of the straddling extent (16) go — seven blocks in all.
    if poll_once(file.truncate(7 * BS)).is_none_or(|r| r.is_err()) {
        return TestResult::Fail("second truncate down failed");
    }
    if file.stat().blocks + 7 * (BS / 512) != before {
        return TestResult::Fail("truncate down did not free the extents past EOF");
    }
    if poll_once(file.truncate(20 * BS)).is_none_or(|r| r.is_err()) {
        return TestResult::Fail("re-extending truncate failed");
    }
    let mut buf = alloc::vec![0u8; 20 * BS as usize];
    if !matches!(poll_once(file.read(0, &mut buf)), Some(Ok(n)) if n == buf.len()) {
        return TestResult::Fail("read after re-extension failed");
    }
    for i in 0..4u64 {
        let at = (2 * i * BS) as usize;
        if buf[at..at + 3] != [0xa0 + i as u8; 3] {
            return TestResult::Fail("truncate damaged an extent before the new EOF");
        }
    }
    if buf[7 * BS as usize..].iter().any(|&b| b != 0) {
        return TestResult::Fail("re-extension read back bytes from before the truncate");
    }
    // The trimmed tree still grows.
    if !matches!(poll_once(file.write(9 * BS, b"new")), Some(Ok(3))) {
        return TestResult::Fail("writing into the trimmed tree failed");
    }
    let mut back = [0u8; 3];
    if !matches!(poll_once(file.read(9 * BS, &mut back)), Some(Ok(3))) || &back != b"new" {
        return TestResult::Fail("data written into the trimmed tree did not read back");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext4_extent_truncate_down_frees_blocks_past_eof
);

/// `fallocate` mode 0 and `FALLOC_FL_KEEP_SIZE` on an extent-mapped file
/// (`ext4_do_fallocate`): holes become unwritten extents — real blocks, so a
/// later write cannot hit ENOSPC, but reading back as zeros. Mode 0 moves
/// `i_size` to cover the range; KEEP_SIZE allocates past EOF and leaves it.
/// NARF had no ext4 `fallocate`: the syscall layer only raised the size,
/// so `posix_fallocate`'s promise of space was empty and KEEP_SIZE was
/// EOPNOTSUPP. A block-mapped file is EOPNOTSUPP on Linux too.
fn smoke_ext4_fallocate_preallocates_unwritten_extents() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsError;
    const BS: u64 = 1024;
    const KEEP_SIZE: u32 = 0x01;
    let device = RamBlockDevice::from_image(512, build_ext4_extent_image(b"x"));
    let (_volume, file) = match mount_ext4_data(device) {
        Ok(v) => v,
        Err(e) => return TestResult::Fail(e),
    };
    let sectors = BS / 512;
    let before = file.stat().blocks;
    // Mode 0 over blocks 0..8: block 0 is mapped already, 1..=7 are holes.
    if !matches!(poll_once(file.fallocate(0, 0, 8 * BS)), Some(Ok(()))) {
        return TestResult::Fail("fallocate mode 0 failed");
    }
    if file.stat().size != 8 * BS {
        return TestResult::Fail("fallocate mode 0 did not extend i_size");
    }
    if file.stat().blocks != before + 7 * sectors {
        return TestResult::Fail("fallocate mode 0 did not allocate the holes");
    }
    let mut buf = alloc::vec![0xffu8; 8 * BS as usize];
    if !matches!(poll_once(file.read(0, &mut buf)), Some(Ok(n)) if n == buf.len()) {
        return TestResult::Fail("read of the preallocated range failed");
    }
    if buf[0] != b'x' || buf[1..].iter().any(|&b| b != 0) {
        return TestResult::Fail("preallocated blocks did not read back as zeros");
    }
    // KEEP_SIZE past EOF: blocks 8..12 allocated, size unchanged.
    if !matches!(
        poll_once(file.fallocate(KEEP_SIZE, 8 * BS, 4 * BS)),
        Some(Ok(()))
    ) {
        return TestResult::Fail("fallocate KEEP_SIZE failed");
    }
    if file.stat().size != 8 * BS {
        return TestResult::Fail("fallocate KEEP_SIZE moved i_size");
    }
    if file.stat().blocks != before + 11 * sectors {
        return TestResult::Fail("fallocate KEEP_SIZE did not allocate past EOF");
    }
    // A write into the preallocated range lands; its neighbours stay zero.
    if !matches!(poll_once(file.write(3 * BS + 5, b"mid")), Some(Ok(3))) {
        return TestResult::Fail("write into a preallocated block failed");
    }
    if file.stat().blocks != before + 11 * sectors {
        return TestResult::Fail("writing into preallocated space allocated again");
    }
    let mut blk = [0xffu8; BS as usize];
    if !matches!(poll_once(file.read(3 * BS, &mut blk)), Some(Ok(_)))
        || &blk[5..8] != b"mid"
        || blk[..5].iter().chain(&blk[8..]).any(|&b| b != 0)
    {
        return TestResult::Fail("a write into preallocated space read back wrong");
    }
    // Truncating down releases the preallocation past the new EOF as well.
    if poll_once(file.truncate(2 * BS)).is_none_or(|r| r.is_err()) {
        return TestResult::Fail("truncate down failed");
    }
    if file.stat().blocks != before + sectors {
        return TestResult::Fail("truncate down kept preallocated blocks past EOF");
    }
    // A block-mapped file: -EOPNOTSUPP (`ext4_do_fallocate`).
    let content = [0x5au8; 100];
    let device = GatedCountingBlock::new(crate::testing::hard_link_image(&content));
    let volume = match poll_once(crate::volume::Ext2Volume::mount(
        device,
        narf_lib::id::DomainId::DRIVER_0,
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("block-map mount failed"),
    };
    use narf_filesystem::FsInstance;
    let mapped = match poll_once(volume.root().lookup_async("data")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("block-map lookup failed"),
    };
    match poll_once(mapped.fallocate(0, 0, 4 * BS)) {
        Some(Err(FsError::Unsupported)) if mapped.stat().size == 100 => TestResult::Pass,
        _ => TestResult::Fail(
            "fallocate on a block-mapped file must be Unsupported and change nothing",
        ),
    }
}
kernel_test_in!(
    "drivers/fs/ext2",
    smoke_ext4_fallocate_preallocates_unwritten_extents
);

/// ext4 keeps sub-second timestamps in a large inode's `i_*time_extra`
/// words (`ext4_decode_extra_time`: low 2 bits widen the seconds, upper 30
/// are nanoseconds). fontconfig validates its system caches against a font
/// directory's exact `st_mtim`; reporting the seconds alone (or zero) made
/// every cache look stale. The extra word must also survive a write-back
/// of an unchanged timestamp and be dropped when NARF rewrites the seconds.
fn smoke_ext2_extra_timestamps_round_trip() -> TestResult {
    use crate::inode::Inode;
    const MTIME: u32 = 1_700_000_000;
    const NSEC: u32 = 123_456_789;
    let mut buf = alloc::vec![0u8; 256];
    put_u16(&mut buf, 0, 0x4000 | 0o755); // S_IFDIR
    put_u32(&mut buf, 8, MTIME); // i_atime
    put_u32(&mut buf, 12, MTIME); // i_ctime
    put_u32(&mut buf, 16, MTIME); // i_mtime
    put_u16(&mut buf, 128, 32); // i_extra_isize: covers 132..160
    put_u32(&mut buf, 136, NSEC << 2); // i_mtime_extra, epoch 0
    put_u32(&mut buf, 140, (7 << 2) | 1); // i_atime_extra: 7 ns, epoch 1
    let Some(mut inode) = Inode::parse(&buf) else {
        return TestResult::Fail("256-byte inode did not parse");
    };
    let want = u64::from(MTIME) * 1_000_000_000 + u64::from(NSEC);
    if inode.mtime_ns() != want {
        return TestResult::Fail("i_mtime_extra nanoseconds were not decoded");
    }
    if inode.atime_ns() != (u64::from(MTIME) + (1 << 32)) * 1_000_000_000 + 7 {
        return TestResult::Fail("i_atime_extra epoch bits were not applied");
    }
    if inode.ctime_ns() != u64::from(MTIME) * 1_000_000_000 {
        return TestResult::Fail("a zero i_ctime_extra did not decode as whole seconds");
    }
    // Unchanged seconds: the extra word is written back as-is.
    let mut out = buf.clone();
    put_u32(&mut out, 136, 0);
    inode.encode_into(&mut out);
    if u32::from_le_bytes([out[136], out[137], out[138], out[139]]) != NSEC << 2 {
        return TestResult::Fail("encode_into dropped an unchanged i_mtime_extra");
    }
    // Rewritten at seconds precision: the old fraction must not survive.
    inode.mtime = MTIME + 5;
    if inode.mtime_ns() != u64::from(MTIME + 5) * 1_000_000_000 {
        return TestResult::Fail("a rewritten i_mtime kept the old nanoseconds");
    }
    inode.encode_into(&mut out);
    if u32::from_le_bytes([out[136], out[137], out[138], out[139]]) != 0 {
        return TestResult::Fail("encode_into kept nanoseconds for rewritten seconds");
    }
    // A 128-byte inode has no extra fields: whole seconds, no out-of-bounds.
    let Some(small) = Inode::parse(&buf[..128]) else {
        return TestResult::Fail("128-byte inode did not parse");
    };
    if small.mtime_ns() != u64::from(MTIME) * 1_000_000_000 {
        return TestResult::Fail("a 128-byte inode reported sub-second time");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_extra_timestamps_round_trip);

/// A directory on ext2/ext4 stats with its on-disk `i_mtime`, not the epoch:
/// `DirOps::dir_mtime_ns` is what the stat path reads for directories, and
/// `inode_attrs().mtime_ns` carries the exact value past the lossy
/// ns→cycles→ns round trip.
fn smoke_ext2_dir_reports_mtime() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    const ROOT_MTIME: u32 = 1_650_000_123;
    let mut img = build_ext2_image(b"x");
    put_u32(&mut img, 5 * 1024 + 128 + 16, ROOT_MTIME); // root i_mtime
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = volume.root();
    let want = u64::from(ROOT_MTIME) * 1_000_000_000;
    if root.dir_mtime_ns() != want {
        return TestResult::Fail("ext2 directory did not report its on-disk mtime");
    }
    if root.inode_attrs().mtime_ns != want {
        return TestResult::Fail("ext2 directory InodeAttrs::mtime_ns is not exact");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_dir_reports_mtime);

/// `link(2)` on ext2/ext4 gives the existing inode a second name and bumps
/// `i_links_count` (`ext4_link`); a name that already exists is refused
/// (EEXIST at the syscall layer). fontconfig's `FcAtomicLock` takes its
/// cache lock with `link(tmp, .LCK)`, so an unsupported link broke locking.
fn smoke_ext2_hardlink() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::{FsError, FsInstance};
    use narf_lib::id::DomainId;

    use crate::volume::Ext2Volume;

    let device = RamBlockDevice::from_image(512, build_ext2_image(b"x"));
    let volume = match poll_once(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = volume.root();
    // The fixture leaves i_links_count unset; compare against the starting
    // value rather than assume 1.
    let links_before = match poll_once(volume.read_inode(12)) {
        Some(Ok(inode)) => inode.links_count,
        _ => return TestResult::Fail("read of the data inode failed"),
    };
    if !matches!(poll_once(root.link("data", "alias")), Some(Ok(()))) {
        return TestResult::Fail("link of an existing file failed");
    }
    let (Some(Ok(data)), Some(Ok(alias))) = (
        poll_once(root.lookup_async("data")),
        poll_once(root.lookup_async("alias")),
    ) else {
        return TestResult::Fail("a linked name did not resolve");
    };
    if data.ino() != alias.ino() {
        return TestResult::Fail("the new link names a different inode");
    }
    match poll_once(volume.read_inode(data.ino() as u32)) {
        Some(Ok(inode)) if inode.links_count == links_before + 1 => {}
        _ => return TestResult::Fail("link did not raise i_links_count by one"),
    }
    if !matches!(
        poll_once(root.link("data", "alias")),
        Some(Err(FsError::Busy))
    ) {
        return TestResult::Fail("link onto an existing name was not refused");
    }
    if !matches!(
        poll_once(root.link("missing", "x")),
        Some(Err(FsError::NotFound))
    ) {
        return TestResult::Fail("link of a missing name did not report NotFound");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2", smoke_ext2_hardlink);
