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
    for i in 0..I_BLOCK_LEN {
        let off = i * 4;
        block_array[i] = u32::from_le_bytes([
            bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3],
        ]);
    }
    // Re-serialise back to bytes — what map_block_extents does.
    let mut node_buf = alloc::vec![0u8; 60];
    for (i, &b) in block_array.iter().enumerate() {
        node_buf[i * 4..i * 4 + 4].copy_from_slice(&b.to_le_bytes());
    }
    // Verify the round-trip + lookup against logical block 2.
    match lookup_in_node(&node_buf, 2) {
        LookupOutcome::Mapped { physical: 302, is_uninitialized: false } => {
            TestResult::Pass
        }
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
    use crate::journal::{
        block_type, tag_flag, DescriptorBlock, JBD2_MAGIC_NUMBER,
    };
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
kernel_test_in!("drivers/fs/ext2", smoke_jbd2_descriptor_block_decodes_two_tags);

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
    use crate::journal::{block_type, JBD2_MAGIC_NUMBER, RevokeBlock};
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
    if r.revoked.len() != 3
        || r.revoked[0] != 100
        || r.revoked[1] != 200
        || r.revoked[2] != 300
    {
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
    use crate::journal::{
        block_type, replay_journal_flat, tag_flag, JBD2_MAGIC_NUMBER,
    };
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
kernel_test_in!("drivers/fs/ext2", smoke_jbd2_replay_clean_journal_no_overrides);

fn smoke_jbd2_replay_revoke_suppresses_target() -> TestResult {
    // Same as the end-to-end smoke, but a revoke block at seq=5 for
    // target 42 sits between the data block and the commit. The
    // override map must NOT contain 42.
    use crate::journal::{
        block_type, replay_journal_flat, tag_flag, JBD2_MAGIC_NUMBER,
    };
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
kernel_test_in!("drivers/fs/ext2", smoke_jbd2_replay_revoke_suppresses_target);

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
    put_u32(&mut img, gdt_off + 0, 3);
    put_u32(&mut img, gdt_off + 4, 4);
    put_u32(&mut img, gdt_off + 8, 5);
    put_u16(&mut img, gdt_off + 12, 0);
    put_u16(&mut img, gdt_off + 14, 0);
    put_u16(&mut img, gdt_off + 16, 1);

    // Inode table at blocks 5..=8 (4 blocks * 1024 / 128 = 32 inodes).
    let itab_off = 5 * BS;

    // Inode 2 (root dir).
    let root_off = itab_off + 1 * INODE_SIZE as usize;
    put_u16(&mut img, root_off + 0, 0x4000 | 0o755);
    put_u32(&mut img, root_off + 4, BS as u32);
    put_u32(&mut img, root_off + 28, (BS / 512) as u32);
    put_u32(&mut img, root_off + 40, 9); // i_block[0] = 9

    // Inode 8 (the journal). 16 KiB journal stored in blocks
    // 16..=31 (16 × 1 KiB blocks).
    let journal_size_blocks: u32 = 16;
    let journal_start_block: u32 = 16;
    let journal_inode_off = itab_off + 7 * INODE_SIZE as usize;
    put_u16(&mut img, journal_inode_off + 0, 0x8000 | 0o600); // regular file
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
        put_u32(&mut img, off + 0, 12);
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
        put_u32(&mut img, off + 0, 12); // inode
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
        return TestResult::Fail(
            "expected ≥1 journal override after unclean ext3 mount",
        );
    }
    // Reading the root directory should return the JOURNAL-side
    // entry (REPLAYED), not the on-disk stale entry (ondisk).
    let root = volume.root();
    let entries = match poll_once(root.enumerate_async(0, 16)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("enumerate_async failed"),
    };
    let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    if names.iter().any(|n| *n == "ondisk") {
        return TestResult::Fail(
            "post-replay enumeration must NOT see the on-disk stale entry",
        );
    }
    if !names.iter().any(|n| *n == "REPLAYED") {
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
kernel_test_in!("drivers/fs/ext2", smoke_ext2_alloc_inode_then_free_round_trip);
