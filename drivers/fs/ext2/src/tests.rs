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
        (2, 0, 1),    // root
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
    buf[4..8].copy_from_slice(&1024u32.to_le_bytes()); // size
    buf[28..32].copy_from_slice(&2u32.to_le_bytes()); // i_blocks (sectors)
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
    if inode.block[0] != 9 || inode.block[1] != 10 || inode.block[12] != 77 {
        return TestResult::Fail("block pointer mismatch");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/ext2", smoke_ext2_superblock_magic_and_block_size);
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
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut cx = Context::from_waker(&waker);
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
    put_u32(&mut img, gdt_off + 0, 3); // bg_block_bitmap
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
    let root_off = itab_off + 1 * INODE_SIZE as usize;
    put_u16(&mut img, root_off + 0, 0x4000 | 0o755); // S_IFDIR | 0755
    put_u32(&mut img, root_off + 4, BS as u32); // size = 1 block
    put_u32(&mut img, root_off + 28, (BS / 512) as u32); // i_blocks
    // i_block[0] = 9 (data block for the root dir)
    put_u32(&mut img, root_off + 40, 9);

    // File inode (#12) at index 11.
    let file_off = itab_off + 11 * INODE_SIZE as usize;
    put_u16(&mut img, file_off + 0, 0x8000 | 0o644); // S_IFREG | 0644
    put_u32(&mut img, file_off + 4, file_data.len() as u32); // size
    put_u32(
        &mut img,
        file_off + 28,
        ((file_data.len() + 511) / 512) as u32,
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
        put_u32(&mut img, off + 0, 2);
        put_u16(&mut img, off + 4, 12); // rec_len
        img[off + 6] = 1; // name_len
        img[off + 7] = ftype::DIR;
        img[off + 8] = b'.';
        cursor += 12;
    }

    // ".." → inode 2 (root's parent is itself in this trivial image)
    {
        let off = root_data + cursor;
        put_u32(&mut img, off + 0, 2);
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
        put_u32(&mut img, off + 0, 12);
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
kernel_test_in!("drivers/fs/ext2", smoke_ext_flavour_classifies_ext2_ext3_ext4);

fn smoke_ext_check_incompat_rejects_unknown_features() -> TestResult {
    use crate::superblock::{incompat, FeatureError, Superblock};
    let mut buf = alloc::vec![0u8; 512];
    buf[56..58].copy_from_slice(&0xEF53u16.to_le_bytes());
    buf[76..80].copy_from_slice(&1u32.to_le_bytes());
    // ENCRYPT bit (0x10000) — driver doesn't support, must reject.
    buf[96..100].copy_from_slice(&incompat::ENCRYPT.to_le_bytes());
    let sb = Superblock::parse(&buf).expect("parse");
    match sb.check_incompat_features() {
        Err(FeatureError::UnsupportedIncompat(bits))
            if bits & incompat::ENCRYPT != 0 =>
        {
            TestResult::Pass
        }
        _ => TestResult::Fail("ENCRYPT incompat must trigger rejection"),
    }
}
kernel_test_in!("drivers/fs/ext2", smoke_ext_check_incompat_rejects_unknown_features);

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
kernel_test_in!("drivers/fs/ext2", smoke_ext_64bit_block_count_combines_lo_and_hi);

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
        LookupOutcome::Mapped { physical: 5_010, is_uninitialized: false } => {}
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
kernel_test_in!("drivers/fs/ext2", smoke_ext4_extent_header_parse_and_leaf_translate);

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
        LookupOutcome::Mapped { physical: 7_005, is_uninitialized: true } => {
            TestResult::Pass
        }
        _ => TestResult::Fail("uninit bit must propagate through Mapped"),
    }
}
kernel_test_in!("drivers/fs/ext2", smoke_ext4_extent_uninitialized_marker_propagates);

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
kernel_test_in!("drivers/fs/ext2", smoke_ext4_extent_index_returns_deeper_lookup);

fn smoke_ext4_extent_corrupt_header_yields_error() -> TestResult {
    use crate::extent::{lookup_in_node, LookupOutcome};
    let buf = alloc::vec![0u8; 24]; // magic == 0 — invalid
    match lookup_in_node(&buf, 0) {
        LookupOutcome::Corrupt => TestResult::Pass,
        _ => TestResult::Fail("zero magic must yield Corrupt"),
    }
}
kernel_test_in!("drivers/fs/ext2", smoke_ext4_extent_corrupt_header_yields_error);

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
kernel_test_in!("drivers/fs/ext2", smoke_ext4_group_desc_64byte_assembles_hi_lo_fields);

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
kernel_test_in!("drivers/fs/ext2", smoke_ext4_group_desc_32byte_legacy_path_unchanged);
