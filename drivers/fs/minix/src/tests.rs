//! Kernel-test entries for the MINIX driver.
//!
//! Pure-logic tests (no kernel runtime needed): superblock magic,
//! inode-number → block math, directory-entry decode.
//!
//! End-to-end test: build a minimal V3 image in heap memory and
//! mount it via `RamBlockDevice::from_image`.

use alloc::vec;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use super::dir::DirEntry as MinixDirEntry;
use super::inode::Inode;
use super::superblock::{magic, Superblock};
use super::{MinixVersion, NameLen};

// ── Pure-logic tests ────────────────────────────────────────────────

fn smoke_minix_superblock_magic_recognises_v1_v2_v3() -> TestResult {
    // Build a minimal 28-byte superblock with each magic. Other
    // fields are placeholders — `decode` doesn't validate them.
    let mut buf = vec![0u8; 1024];
    let off = 0;
    // ninodes = 8, imap = 1, zmap = 1, first_data_zone = 4,
    // log_zone_size = 0, max_size = 0x7FFFFFFF, magic = ?, nzones = 16.
    let header = [
        0x08, 0x00, // ninodes = 8 (V1) or low half of nzones (ignored)
        0x10, 0x00, // s_nzones (V1) = 16
        0x01, 0x00, // imap_blocks
        0x01, 0x00, // zmap_blocks
        0x04, 0x00, // firstdatazone
        0x00, 0x00, // log_zone_size
        0xFF, 0xFF, 0xFF, 0x7F, // max_size
    ];
    buf[off..off + 16].copy_from_slice(&header);

    for (m, expected_v, expected_n) in [
        (magic::V1_14, MinixVersion::V1, NameLen::N14),
        (magic::V1_30, MinixVersion::V1, NameLen::N30),
        (magic::V2_14, MinixVersion::V2, NameLen::N14),
        (magic::V2_30, MinixVersion::V2, NameLen::N30),
        (magic::V3, MinixVersion::V3, NameLen::N60),
    ] {
        buf[16] = (m & 0xFF) as u8;
        buf[17] = (m >> 8) as u8;
        // V2/V3 want s_zones at offset 20 — set to 16.
        buf[20..24].copy_from_slice(&16u32.to_le_bytes());
        // V3 also wants s_block_size at offset 24.
        buf[24..26].copy_from_slice(&1024u16.to_le_bytes());
        let sb = match Superblock::decode(&buf, 0) {
            Some(s) => s,
            None => return TestResult::Fail("decode failed for known magic"),
        };
        if sb.version != expected_v || sb.name_len != expected_n {
            return TestResult::Fail("wrong version/name-len decode");
        }
        if sb.block_size != 1024 {
            return TestResult::Fail("block_size != 1024");
        }
    }

    // Bogus magic must fail.
    buf[16] = 0x00;
    buf[17] = 0x00;
    if Superblock::decode(&buf, 0).is_some() {
        return TestResult::Fail("zero magic must not decode");
    }
    TestResult::Pass
}

fn smoke_minix_inode_location_math() -> TestResult {
    // V3 with 1024-byte blocks, 64-byte inodes => 16 inodes/block.
    // imap_blocks = 1, zmap_blocks = 2 → inode table starts at
    // block 2 + 1 + 2 = 5. Inode 1 sits at block 5 offset 0; inode
    // 17 sits at block 6 offset 0.
    let mut buf = vec![0u8; 1024];
    buf[0..2].copy_from_slice(&64u16.to_le_bytes()); // ninodes
    buf[2..4].copy_from_slice(&64u16.to_le_bytes()); // s_nzones (ignored on V3)
    buf[4..6].copy_from_slice(&1u16.to_le_bytes()); // imap
    buf[6..8].copy_from_slice(&2u16.to_le_bytes()); // zmap
    buf[16..18].copy_from_slice(&magic::V3.to_le_bytes());
    buf[20..24].copy_from_slice(&64u32.to_le_bytes());
    buf[24..26].copy_from_slice(&1024u16.to_le_bytes());

    let sb = match Superblock::decode(&buf, 0) {
        Some(s) => s,
        None => return TestResult::Fail("decode failed"),
    };
    if sb.inode_table_first_block() != 5 {
        return TestResult::Fail("inode table first block math wrong");
    }
    match sb.inode_location(1) {
        Some((5, 0)) => {}
        _ => return TestResult::Fail("inode 1 location wrong"),
    }
    match sb.inode_location(16) {
        Some((5, off)) if off == 15 * 64 => {}
        _ => return TestResult::Fail("inode 16 location wrong"),
    }
    match sb.inode_location(17) {
        Some((6, 0)) => {}
        _ => return TestResult::Fail("inode 17 location wrong"),
    }
    if sb.inode_location(0).is_some() {
        return TestResult::Fail("inode 0 must be rejected");
    }
    if sb.inode_location(65).is_some() {
        return TestResult::Fail("OOB inode must be rejected");
    }
    TestResult::Pass
}

fn smoke_minix_dir_entry_decode_v3_60byte() -> TestResult {
    // V3 entry: 2-byte ino + 60-byte name = 62 bytes/entry.
    let mut buf = vec![0u8; 62 * 3];
    // Entry 0: ino=1, name="."
    buf[0..2].copy_from_slice(&1u16.to_le_bytes());
    buf[2] = b'.';
    // Entry 1: ino=1, name=".."
    buf[62..64].copy_from_slice(&1u16.to_le_bytes());
    buf[64] = b'.';
    buf[65] = b'.';
    // Entry 2: ino=2, name="hello.txt"
    buf[124..126].copy_from_slice(&2u16.to_le_bytes());
    buf[126..126 + 9].copy_from_slice(b"hello.txt");

    let entries = MinixDirEntry::decode_all(NameLen::N60, &buf);
    if entries.len() != 3 {
        return TestResult::Fail("expected 3 entries");
    }
    if entries[0].ino != 1 || entries[0].name != "." {
        return TestResult::Fail("entry 0 wrong");
    }
    if entries[1].ino != 1 || entries[1].name != ".." {
        return TestResult::Fail("entry 1 wrong");
    }
    if entries[2].ino != 2 || entries[2].name != "hello.txt" {
        return TestResult::Fail("entry 2 wrong");
    }

    // A zero-ino slot in the middle must be silently skipped.
    let mut sparse = vec![0u8; 62 * 2];
    // Slot 1 has a real entry.
    sparse[62..64].copy_from_slice(&5u16.to_le_bytes());
    sparse[64..67].copy_from_slice(b"foo");
    let parsed = MinixDirEntry::decode_all(NameLen::N60, &sparse);
    if parsed.len() != 1 || parsed[0].ino != 5 || parsed[0].name != "foo" {
        return TestResult::Fail("sparse-slot decode wrong");
    }
    TestResult::Pass
}

fn smoke_minix_inode_decode_v1_v2() -> TestResult {
    // V1 inode: 32 bytes. Build: mode=IFREG|0o644, size=42,
    // mtime=0xCAFE, gid=0, nlinks=1, zone[0]=7.
    let mut v1 = vec![0u8; 32];
    v1[0..2].copy_from_slice(&((super::inode::mode::IFREG | 0o644) as u16).to_le_bytes());
    v1[4..8].copy_from_slice(&42u32.to_le_bytes());
    v1[8..12].copy_from_slice(&0xCAFEu32.to_le_bytes());
    v1[13] = 1;
    v1[14..16].copy_from_slice(&7u16.to_le_bytes());
    let i = match Inode::decode(MinixVersion::V1, &v1, 0) {
        Some(i) => i,
        None => return TestResult::Fail("V1 decode failed"),
    };
    if !i.is_reg() || i.size != 42 || i.mtime != 0xCAFE || i.zones[0] != 7 {
        return TestResult::Fail("V1 fields wrong");
    }

    // V2 inode: 64 bytes.
    let mut v2 = vec![0u8; 64];
    v2[0..2].copy_from_slice(&((super::inode::mode::IFDIR | 0o755) as u16).to_le_bytes());
    v2[2..4].copy_from_slice(&2u16.to_le_bytes()); // nlinks
    v2[8..12].copy_from_slice(&128u32.to_le_bytes()); // size
    v2[16..20].copy_from_slice(&0x1234u32.to_le_bytes()); // mtime
    v2[24..28].copy_from_slice(&0xABCDu32.to_le_bytes()); // zone[0]
    let j = match Inode::decode(MinixVersion::V2, &v2, 0) {
        Some(i) => i,
        None => return TestResult::Fail("V2 decode failed"),
    };
    if !j.is_dir() || j.size != 128 || j.mtime != 0x1234 || j.zones[0] != 0xABCD {
        return TestResult::Fail("V2 fields wrong");
    }
    if j.nlinks != 2 {
        return TestResult::Fail("V2 nlinks wrong");
    }

    TestResult::Pass
}

kernel_test_in!("drivers/fs/minix", smoke_minix_superblock_magic_recognises_v1_v2_v3);
kernel_test_in!("drivers/fs/minix", smoke_minix_inode_location_math);
kernel_test_in!("drivers/fs/minix", smoke_minix_dir_entry_decode_v3_60byte);
kernel_test_in!("drivers/fs/minix", smoke_minix_inode_decode_v1_v2);

// ── End-to-end mount + I/O against RamBlockDevice ──────────────────

/// Synchronous-only future poll. RamBlockDevice's `submit` returns
/// `Ready` after the in-memory copy, so every MINIX op completes on
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

/// Build a minimal V3 MINIX image in heap memory.
///
/// Layout (block size = 1024, V3 magic 0x4D5A, name_len = 60):
///   block 0 : boot block (zeros)
///   block 1 : superblock at offset 0 of the block
///   block 2 : inode bitmap (1 block)
///   block 3 : zone bitmap (1 block)
///   block 4 : inode table starts here. We have 16 inodes/block.
///   block 5 : data zone — root dir
///   block 6 : data zone — file payload
///
/// Inode 1 (root): mode = IFDIR|0755, size = 3*62 = 186 bytes,
///                 zone[0] = 5.
/// Inode 2 (file): mode = IFREG|0644, size = data.len(),
///                 zone[0] = 6.
fn build_minix3_image(data: &[u8]) -> Vec<u8> {
    const BS: usize = 1024;
    const NBLOCKS: usize = 32;
    let mut img = vec![0u8; BS * NBLOCKS];

    // ── Superblock (block 1) ────────────────────────────────────
    let sb = &mut img[BS..BS * 2];
    // ninodes = 32 (small).
    sb[0..2].copy_from_slice(&32u16.to_le_bytes());
    // s_nzones (V1 only) - leave zero.
    // imap_blocks = 1
    sb[4..6].copy_from_slice(&1u16.to_le_bytes());
    // zmap_blocks = 1
    sb[6..8].copy_from_slice(&1u16.to_le_bytes());
    // first_data_zone (advisory) = 5
    sb[8..10].copy_from_slice(&5u16.to_le_bytes());
    // log_zone_size = 0
    sb[10..12].copy_from_slice(&0u16.to_le_bytes());
    // max_size = 0x7FFFFFFF
    sb[12..16].copy_from_slice(&0x7FFFFFFFu32.to_le_bytes());
    // magic = 0x4D5A
    sb[16..18].copy_from_slice(&magic::V3.to_le_bytes());
    // s_state = 0
    // s_zones (V2/V3) at offset 20 = NBLOCKS
    sb[20..24].copy_from_slice(&(NBLOCKS as u32).to_le_bytes());
    // s_block_size at offset 24 = 1024
    sb[24..26].copy_from_slice(&1024u16.to_le_bytes());

    // ── Inode bitmap (block 2) ──────────────────────────────────
    // Bit 0 reserved, bits 1 + 2 set (inodes 1 and 2 used).
    img[BS * 2] = 0b0000_0111;

    // ── Zone bitmap (block 3) ───────────────────────────────────
    // The zone-bitmap is indexed by zone-number-within-data-region.
    // In our image, data zones start at block 5 with first_data_zone
    // = 5. But the zone bitmap convention is bit 0 = "zone 0 of
    // data region" = our absolute zone 5. For a read-only mount we
    // never touch the bitmap, so just mark some bits set.
    img[BS * 3] = 0b0000_0111;

    // ── Inode table (block 4 onwards) ───────────────────────────
    // Inode 1 at offset 0 of block 4.
    let it = BS * 4;
    let i1 = &mut img[it..it + 64];
    // mode = IFDIR | 0755
    let mode_dir = (super::inode::mode::IFDIR | 0o755) as u16;
    i1[0..2].copy_from_slice(&mode_dir.to_le_bytes());
    // nlinks = 2
    i1[2..4].copy_from_slice(&2u16.to_le_bytes());
    // size = 3 * 62 = 186 bytes (".", "..", file entry)
    i1[8..12].copy_from_slice(&186u32.to_le_bytes());
    // mtime = 0xCAFE
    i1[16..20].copy_from_slice(&0xCAFEu32.to_le_bytes());
    // zone[0] = 5
    i1[24..28].copy_from_slice(&5u32.to_le_bytes());

    // Inode 2 at offset 64.
    let i2 = &mut img[it + 64..it + 128];
    let mode_reg = (super::inode::mode::IFREG | 0o644) as u16;
    i2[0..2].copy_from_slice(&mode_reg.to_le_bytes());
    i2[2..4].copy_from_slice(&1u16.to_le_bytes()); // nlinks
    i2[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());
    i2[16..20].copy_from_slice(&0x1234u32.to_le_bytes()); // mtime
    i2[24..28].copy_from_slice(&6u32.to_le_bytes()); // zone[0] = 6

    // ── Root directory contents (block 5) ───────────────────────
    let dr = BS * 5;
    // Entry 0: ino=1, "."
    img[dr..dr + 2].copy_from_slice(&1u16.to_le_bytes());
    img[dr + 2] = b'.';
    // Entry 1: ino=1, ".."
    img[dr + 62..dr + 64].copy_from_slice(&1u16.to_le_bytes());
    img[dr + 64] = b'.';
    img[dr + 65] = b'.';
    // Entry 2: ino=2, "hi.txt"
    img[dr + 124..dr + 126].copy_from_slice(&2u16.to_le_bytes());
    img[dr + 126..dr + 132].copy_from_slice(b"hi.txt");

    // ── File data (block 6) ─────────────────────────────────────
    img[BS * 6..BS * 6 + data.len()].copy_from_slice(data);

    img
}

fn smoke_minix_mount_ramblock_round_trip() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::{FileType, FsInstance};
    use narf_lib::id::DomainId;

    use super::volume::MinixVolume;

    let payload = b"hello minix\n";
    let img = build_minix3_image(payload);
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(MinixVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("MinixVolume::mount failed"),
    };
    if volume.name() != "minix3" {
        return TestResult::Fail("expected V3 detection");
    }
    let root = volume.root();

    // Enumerate root: should see ".", "..", "hi.txt".
    let entries = match poll_once(root.enumerate_async(0, 16)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("enumerate_async failed"),
    };
    if entries.len() != 3 {
        return TestResult::Fail("expected 3 entries in root");
    }
    if !entries.iter().any(|(n, ft)| n == "hi.txt" && *ft == FileType::File) {
        return TestResult::Fail("hi.txt not enumerated as a file");
    }
    if !entries.iter().any(|(n, ft)| n == "." && *ft == FileType::Dir) {
        return TestResult::Fail("'.' not enumerated as a dir");
    }

    // Look up the file.
    let file = match poll_once(root.lookup_async("hi.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup_async hi.txt failed"),
    };

    // stat_async should give the correct size.
    let stat = match poll_once(file.stat_async()) {
        Some(Ok(s)) => s,
        _ => return TestResult::Fail("stat_async failed"),
    };
    if stat.size as usize != payload.len() {
        return TestResult::Fail("stat.size mismatch");
    }

    // Read back the contents.
    let mut buf = [0u8; 32];
    let n = match poll_once(file.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("file.read failed"),
    };
    if n != payload.len() || &buf[..n] != payload {
        return TestResult::Fail("file contents mismatch");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/fs/minix", smoke_minix_mount_ramblock_round_trip);

// ── Write smoke tests ───────────────────────────────────────────────

/// Build a fresh V3 image with enough room for write-path exercise.
/// `n_zones` (32) gives ~28 free data zones — plenty for a couple
/// of small files + directories.
fn build_minix3_image_writable() -> Vec<u8> {
    build_minix3_image(b"")
}

fn smoke_minix_write_then_read_back() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use super::volume::MinixVolume;

    let img = build_minix3_image_writable();
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(MinixVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = volume.root();

    // Existing hi.txt file: write data into it, read back.
    let file = match poll_once(root.lookup_async("hi.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup hi.txt failed"),
    };
    let payload = b"freshly written data";
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
kernel_test_in!("drivers/fs/minix", smoke_minix_write_then_read_back);

fn smoke_minix_create_file_then_delete() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::{FsError, FsInstance};
    use narf_lib::id::DomainId;

    use super::volume::MinixVolume;

    let img = build_minix3_image_writable();
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(MinixVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = volume.root();

    // Create a new file.
    let _new_file = match poll_once(root.create("new.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create failed"),
    };
    // Look it up.
    if poll_once(root.lookup_async("new.txt"))
        .and_then(|r| r.ok())
        .is_none()
    {
        return TestResult::Fail("created file not found on lookup");
    }
    // Unlink.
    if poll_once(root.unlink("new.txt")).and_then(|r| r.ok()).is_none() {
        return TestResult::Fail("unlink failed");
    }
    // Lookup must now miss.
    match poll_once(root.lookup_async("new.txt")) {
        Some(Err(FsError::NotFound)) => {}
        _ => return TestResult::Fail("unlinked file still resolves"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/minix", smoke_minix_create_file_then_delete);

fn smoke_minix_mkdir_then_rmdir() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::{FsError, FsInstance};
    use narf_lib::id::DomainId;

    use super::volume::MinixVolume;

    let img = build_minix3_image_writable();
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(MinixVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = volume.root();

    if poll_once(root.mkdir("sub")).and_then(|r| r.ok()).is_none() {
        return TestResult::Fail("mkdir failed");
    }
    if poll_once(root.lookup_dir_async("sub"))
        .and_then(|r| r.ok())
        .is_none()
    {
        return TestResult::Fail("created dir not found");
    }
    if poll_once(root.rmdir("sub")).and_then(|r| r.ok()).is_none() {
        return TestResult::Fail("rmdir failed");
    }
    match poll_once(root.lookup_async("sub")) {
        Some(Err(FsError::NotFound)) => {}
        _ => return TestResult::Fail("rmdir'd dir still resolves"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/minix", smoke_minix_mkdir_then_rmdir);
