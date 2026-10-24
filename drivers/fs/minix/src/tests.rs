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
    v1[0..2].copy_from_slice(&(super::inode::mode::IFREG | 0o644).to_le_bytes());
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
    v2[0..2].copy_from_slice(&(super::inode::mode::IFDIR | 0o755).to_le_bytes());
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

kernel_test_in!(
    "drivers/fs/minix",
    smoke_minix_superblock_magic_recognises_v1_v2_v3
);
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
    // SAFETY: `raw_waker`'s vtable upholds the `RawWaker` contract — `no_clone`
    // rebuilds an equivalent waker and `no_op` makes wake/drop side-effect-free
    // on the null data pointer, so all vtable functions are sound to invoke.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    // SAFETY: `fut` is a local owned by this fn and never moved after this
    // point (it lives until `poll_once` returns), so pinning `&mut fut` in
    // place satisfies `Pin::new_unchecked`'s never-move invariant.
    // SAFETY: Valid MMIO bounds or trusted driver environment
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
    let mode_dir = super::inode::mode::IFDIR | 0o755;
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
    let mode_reg = super::inode::mode::IFREG | 0o644;
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
    if !entries
        .iter()
        .any(|(n, ft)| n == "hi.txt" && *ft == FileType::File)
    {
        return TestResult::Fail("hi.txt not enumerated as a file");
    }
    if !entries
        .iter()
        .any(|(n, ft)| n == "." && *ft == FileType::Dir)
    {
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
    if poll_once(root.unlink("new.txt"))
        .and_then(|r| r.ok())
        .is_none()
    {
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

// ── Timestamps ──────────────────────────────────────────────────────
//
// Linux `minix_V2_iget` sets atime/mtime/ctime from the inode's three
// unsigned 32-bit seconds fields with 0 nanoseconds; `minix_V1_iget`
// reports V1's single `i_time` as all three. Before this, the driver fed
// the raw SECONDS into `Stat::mtime_cycles` (a monotonic-cycle count) and
// reported every directory as the epoch.

/// Write `atime`/`mtime`/`ctime` into the V3 inode `ino` of an image from
/// [`build_minix3_image`] (inode table at block 4, 64-byte inodes).
fn put_minix3_times(img: &mut [u8], ino: usize, atime: u32, mtime: u32, ctime: u32) {
    let off = 1024 * 4 + (ino - 1) * 64;
    img[off + 12..off + 16].copy_from_slice(&atime.to_le_bytes());
    img[off + 16..off + 20].copy_from_slice(&mtime.to_le_bytes());
    img[off + 20..off + 24].copy_from_slice(&ctime.to_le_bytes());
}

const NS: u64 = 1_000_000_000;

/// A file's stat times are its on-disk seconds, exactly, each from its own
/// field; `Stat::mtime_cycles` encodes the wall-clock ns, not raw seconds.
fn smoke_minix_file_reports_exact_times() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use super::volume::MinixVolume;

    const ATIME: u32 = 1_600_000_001;
    const MTIME: u32 = 1_700_000_002;
    const CTIME: u32 = 1_650_000_003;
    let mut img = build_minix3_image(b"payload");
    put_minix3_times(&mut img, 2, ATIME, MTIME, CTIME);
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(MinixVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let file = match poll_once(volume.root().lookup_async("hi.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup hi.txt failed"),
    };
    let attrs = file.inode_attrs();
    if attrs.mtime_ns != u64::from(MTIME) * NS {
        return TestResult::Fail("file mtime_ns is not the on-disk i_mtime");
    }
    if attrs.atime_ns != u64::from(ATIME) * NS {
        return TestResult::Fail("file atime_ns is not the on-disk i_atime");
    }
    if attrs.ctime_ns != u64::from(CTIME) * NS {
        return TestResult::Fail("file ctime_ns is not the on-disk i_ctime");
    }
    let stat = file.stat();
    if stat.mtime_cycles != narf_time::ns_to_cycles(u64::from(MTIME) * NS) {
        return TestResult::Fail("Stat::mtime_cycles does not encode the wall-clock mtime");
    }
    // Negative: the old encoding stuffed raw seconds into the cycle count.
    if stat.mtime_cycles == u64::from(MTIME) {
        return TestResult::Fail("Stat::mtime_cycles still holds raw seconds");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/minix", smoke_minix_file_reports_exact_times);

/// The mount root and a looked-up subdirectory report their on-disk
/// `i_mtime` through both `dir_mtime_ns` and `inode_attrs`, not the
/// epoch — including a fresh `root()` after a write to the root inode.
fn smoke_minix_dir_reports_mtime() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use super::volume::MinixVolume;

    const ROOT_MTIME: u32 = 1_650_000_123;
    const ROOT_CTIME: u32 = 1_650_000_456;
    let mut img = build_minix3_image(b"");
    put_minix3_times(&mut img, 1, ROOT_MTIME, ROOT_MTIME, ROOT_CTIME);
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(MinixVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = volume.root();
    let want = u64::from(ROOT_MTIME) * NS;
    if root.dir_mtime_ns() != want {
        return TestResult::Fail("root dir_mtime_ns is not the on-disk i_mtime");
    }
    let attrs = root.inode_attrs();
    if attrs.mtime_ns != want || attrs.ctime_ns != u64::from(ROOT_CTIME) * NS {
        return TestResult::Fail("root InodeAttrs times are not exact");
    }
    // mkdir rewrites the root inode; a fresh root() must still carry real
    // times, and the new subdirectory reports the same mtime however it is
    // reached.
    let sub = match poll_once(root.mkdir("sub")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("mkdir failed"),
    };
    if sub.dir_mtime_ns() == 0 || sub.dir_mtime_ns() != sub.inode_attrs().mtime_ns {
        return TestResult::Fail("new subdirectory reports no mtime");
    }
    let looked_up = match poll_once(root.lookup_dir_async("sub")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("lookup_dir sub failed"),
    };
    if looked_up.dir_mtime_ns() != sub.dir_mtime_ns() {
        return TestResult::Fail("looked-up subdirectory mtime differs from created");
    }
    if volume.root().dir_mtime_ns() != want {
        return TestResult::Fail("root() after a root-inode write lost its mtime");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/minix", smoke_minix_dir_reports_mtime);

/// Format edges: V1's single `i_time` is atime, mtime and ctime alike;
/// the seconds are UNSIGNED (`s_time_max = U32_MAX`), so a value past
/// 2038 is not a negative time; and a V2 write-back keeps atime and ctime
/// instead of zeroing / clobbering them.
fn smoke_minix_time_format_edges() -> TestResult {
    const LATE: u32 = 0xF000_0000; // year 2097, > i32::MAX
    let mut v1 = vec![0u8; 32];
    v1[0..2].copy_from_slice(&(super::inode::mode::IFREG | 0o644).to_le_bytes());
    v1[8..12].copy_from_slice(&LATE.to_le_bytes());
    let Some(i) = Inode::decode(MinixVersion::V1, &v1, 0) else {
        return TestResult::Fail("V1 decode failed");
    };
    let want = u64::from(LATE) * NS;
    if i.mtime_ns() != want || i.atime_ns() != want || i.ctime_ns() != want {
        return TestResult::Fail("V1 i_time is not reported as atime/mtime/ctime");
    }
    if i.mtime_ns() <= (i32::MAX as u64) * NS {
        return TestResult::Fail("post-2038 seconds decoded as signed");
    }

    let mut v2 = vec![0u8; 64];
    v2[0..2].copy_from_slice(&(super::inode::mode::IFREG | 0o644).to_le_bytes());
    v2[12..16].copy_from_slice(&11u32.to_le_bytes()); // i_atime
    v2[16..20].copy_from_slice(&22u32.to_le_bytes()); // i_mtime
    v2[20..24].copy_from_slice(&33u32.to_le_bytes()); // i_ctime
    let Some(j) = Inode::decode(MinixVersion::V2, &v2, 0) else {
        return TestResult::Fail("V2 decode failed");
    };
    if j.atime_ns() != 11 * NS || j.mtime_ns() != 22 * NS || j.ctime_ns() != 33 * NS {
        return TestResult::Fail("V2 times not decoded from their own fields");
    }
    let mut out = vec![0u8; 64];
    j.encode(MinixVersion::V2, &mut out, 0);
    if out[12..24] != v2[12..24] {
        return TestResult::Fail("V2 encode did not write back atime/mtime/ctime");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/minix", smoke_minix_time_format_edges);

/// The minix half of the `mmap_cache_generation` contract (see the
/// FAT smoke of the same name): the generation lives in the volume,
/// keyed by inode number, so every open of one file reports the same
/// value and a mutation through any open — or a final unlink that
/// releases the inode's zones — moves it for all of them.
fn smoke_minix_mmap_cache_generation_tracks_mutations() -> TestResult {
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

    let file = match poll_once(root.lookup_async("hi.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup hi.txt failed"),
    };
    let g0 = match file.mmap_cache_generation() {
        Some(g) => g,
        None => return TestResult::Fail("regular file reports no cache generation"),
    };
    let reopened = match poll_once(root.lookup_async("hi.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("second lookup failed"),
    };
    if reopened.mmap_cache_generation() != Some(g0) {
        return TestResult::Fail("two opens of one file disagree on generation");
    }
    if poll_once(reopened.write(0, b"HI"))
        .and_then(|r| r.ok())
        .is_none()
    {
        return TestResult::Fail("write through second open failed");
    }
    let g1 = file.mmap_cache_generation();
    if g1 == Some(g0) || reopened.mmap_cache_generation() != g1 {
        return TestResult::Fail("write through a second open did not invalidate");
    }
    if poll_once(file.truncate(1)).and_then(|r| r.ok()).is_none() {
        return TestResult::Fail("truncate failed");
    }
    if file.mmap_cache_generation() == g1 || file.mmap_cache_generation().is_none() {
        return TestResult::Fail("truncate did not move the generation");
    }
    // An unrelated file's generation does not move with hi.txt's.
    let other = match poll_once(root.create("other.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create other.txt failed"),
    };
    let og = other.mmap_cache_generation();
    if og.is_none() {
        return TestResult::Fail("created file reports no cache generation");
    }
    if poll_once(file.write(0, b"x")).and_then(|r| r.ok()) != Some(1) {
        return TestResult::Fail("second write failed");
    }
    if other.mmap_cache_generation() != og {
        return TestResult::Fail("a write to one file moved another file's generation");
    }
    // A directory is not a cacheable file.
    if poll_once(root.mkdir("subdir"))
        .and_then(|r| r.ok())
        .is_none()
    {
        return TestResult::Fail("mkdir failed");
    }
    let dir = match poll_once(root.lookup_async("subdir")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup subdir failed"),
    };
    if dir.mmap_cache_generation().is_some() {
        return TestResult::Fail("directory reports a cache generation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/minix",
    smoke_minix_mmap_cache_generation_tracks_mutations
);

/// The shared page cache keys retained pages by
/// `mmap_backing_identity`, so the identity must belong to the
/// inode, not to the node an open minted (issue #679): two opens of
/// one file report the volume anchor for its inode number, a
/// different inode reports a different anchor, and the value
/// survives the first open.
fn smoke_minix_mmap_identity_is_per_inode() -> TestResult {
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

    let first = match poll_once(root.lookup_async("hi.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup hi.txt failed"),
    };
    let second = match poll_once(root.lookup_async("hi.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("second lookup failed"),
    };
    if alloc::sync::Arc::ptr_eq(&first, &second) {
        return TestResult::Fail("expected two distinct opens of hi.txt");
    }
    if first.mmap_backing_identity() != second.mmap_backing_identity() {
        return TestResult::Fail("two opens of one inode report different mmap identities");
    }
    let other = match poll_once(root.create("other.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create other.txt failed"),
    };
    if other.mmap_backing_identity() == first.mmap_backing_identity() {
        return TestResult::Fail("two inodes share an mmap identity");
    }
    let identity = first.mmap_backing_identity();
    drop(first);
    if second.mmap_backing_identity() != identity {
        return TestResult::Fail("the identity changed while an open of the inode was alive");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/minix", smoke_minix_mmap_identity_is_per_inode);

/// Inode reuse after unlink (issue #679): the inode allocator hands
/// a freed number to the next create, so the new file necessarily
/// shares the old file's identity anchor while an open of the old
/// file is still alive — what must separate the two files is the
/// generation: the final unlink and the create each issue a fresh
/// one, so the old tenant's retained pages can never validate
/// against the new file.
fn smoke_minix_mmap_identity_inode_reuse_after_unlink() -> TestResult {
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

    let first = match poll_once(root.create("one.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create one.txt failed"),
    };
    if poll_once(first.write(0, b"ONE")).and_then(|r| r.ok()) != Some(3) {
        return TestResult::Fail("write through one.txt failed");
    }
    let ino = first.ino();
    let id_first = first.mmap_backing_identity();
    let gen_first = match first.mmap_cache_generation() {
        Some(g) => g,
        None => return TestResult::Fail("one.txt reports no cache generation"),
    };
    // Unlink while `first` stays open — the POSIX case that leaves a
    // live node holding a dead file's pages.
    if poll_once(root.unlink("one.txt"))
        .and_then(|r| r.ok())
        .is_none()
    {
        return TestResult::Fail("unlink one.txt failed");
    }
    let second = match poll_once(root.create("two.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create two.txt failed"),
    };
    if second.ino() != ino {
        return TestResult::Fail("inode number was not reused (test premise)");
    }
    if second.mmap_backing_identity() != id_first {
        return TestResult::Fail("reused inode reports a different identity");
    }
    if second.mmap_cache_generation() == Some(gen_first) {
        return TestResult::Fail(
            "new tenant of a recycled inode validates against the old tenant's generation",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/minix",
    smoke_minix_mmap_identity_inode_reuse_after_unlink
);

// ── Truncate-shrink fixtures (issue #844) ────────────────────────
//
// Before the fix, shrink only moved `i_size`: every zone past the
// new EOF stayed allocated, the partial tail zone kept its bytes,
// and a later regrow (a size-only bump) re-served the stale
// pre-shrink bytes instead of zeros. These fixtures pin the
// release-and-zero semantics at driver level, mirroring the
// syscall-level coherence pin for the same defect (Refs #742).

use narf_filesystem::FsInstance as _;

use super::volume::MinixVolume;

/// Position-dependent pattern that never produces a zero byte, so
/// any zero in a read range is proof of zero-fill and any stale
/// pre-shrink byte is distinguishable from it.
fn shrink_pattern_at(off: usize) -> u8 {
    (1 + (off % 250)) as u8
}

fn shrink_pattern(len: usize) -> Vec<u8> {
    (0..len).map(shrink_pattern_at).collect()
}

/// Zone-bitmap probe for the test images: the zone bitmap is
/// block 3 and `first_data_zone` is 5; the allocation ordinal for
/// zone `z` is `z - first_data_zone + 1` (see `free_zone`).
fn image_zone_used(img: &[u8], zone: u32) -> bool {
    let ordinal = zone - 5 + 1;
    img[3 * 1024 + (ordinal / 8) as usize] & (1u8 << (ordinal % 8)) != 0
}

/// Absolute zone numbers backing file-zone indices `0..count` of
/// `inode`, in index order (holes skipped — fixtures use fully
/// allocated files, and callers assert the count).
async fn file_zones(
    volume: &MinixVolume<narf_block::ram::RamBlockDevice>,
    inode: &Inode,
    count: u32,
) -> Vec<u32> {
    let mut out = Vec::new();
    for idx in 0..count {
        if let Ok(Some(z)) = volume.map_block(inode, idx).await {
            out.push(z);
        }
    }
    out
}

/// The #862 pin scenario at driver level: write a pattern across
/// multiple zones, shrink mid-zone, regrow — the regrown range
/// must read as zeros, the kept range as the pattern, and the
/// partial tail zone must be zeroed on disk (the regrow is a
/// size-only bump, so the zeros have to come from the shrink).
fn smoke_minix_truncate_shrink_regrow_reads_zeros() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_lib::id::DomainId;

    let device = RamBlockDevice::from_image(512, build_minix3_image_writable());
    let volume = match poll_once(MinixVolume::mount(device.clone(), DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let file = match poll_once(volume.root().lookup_async("hi.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup hi.txt failed"),
    };
    let data = shrink_pattern(3 * 4096);
    match poll_once(file.write(0, &data)) {
        Some(Ok(12288)) => {}
        _ => return TestResult::Fail("write pattern failed"),
    }
    let before = match poll_once(volume.read_inode(2)) {
        Some(Ok(i)) => i,
        _ => return TestResult::Fail("read inode failed"),
    };
    let zones = match poll_once(file_zones(&volume, &before, 12)) {
        Some(z) => z,
        _ => return TestResult::Fail("zone walk failed"),
    };
    if zones.len() != 12 {
        return TestResult::Fail("fixture file does not span 12 zones");
    }
    match poll_once(file.truncate(5000)) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("shrink to 5000 failed"),
    }
    let img = device.snapshot();
    for (idx, zone) in zones.iter().enumerate() {
        if image_zone_used(&img, *zone) != (idx < 5) {
            return TestResult::Fail("kept/released zone bitmap state wrong after shrink");
        }
    }
    // Partial tail zone (index 4, file bytes 4096..5120): [0, 904)
    // preserved, [904, 1024) zeroed on disk.
    let tail = &img[zones[4] as usize * 1024..zones[4] as usize * 1024 + 1024];
    for (i, b) in tail.iter().enumerate() {
        let want = if i < 904 {
            shrink_pattern_at(4096 + i)
        } else {
            0
        };
        if *b != want {
            return TestResult::Fail("partial tail zone not zeroed on disk by shrink");
        }
    }
    let shrunk = match poll_once(volume.read_inode(2)) {
        Some(Ok(i)) => i,
        _ => return TestResult::Fail("read shrunk inode failed"),
    };
    if shrunk.size != 5000 || shrunk.zones[5] != 0 || shrunk.zones[6] != 0 {
        return TestResult::Fail("on-disk inode not shrunk / direct tail slots not cleared");
    }
    match poll_once(file.truncate(3 * 4096)) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("regrow failed"),
    }
    let mut back = vec![0u8; 3 * 4096];
    match poll_once(file.read(0, &mut back)) {
        Some(Ok(12288)) => {}
        _ => return TestResult::Fail("read back failed"),
    }
    for (off, b) in back.iter().enumerate() {
        let want = if off < 5000 {
            shrink_pattern_at(off)
        } else {
            0
        };
        if *b != want {
            return TestResult::Fail("regrown range resurrected stale pre-shrink bytes");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/minix",
    smoke_minix_truncate_shrink_regrow_reads_zeros
);

/// Shrink from the indirect range back into the direct range: the
/// whole single-indirect chain detaches — its data zones AND the
/// indirect block itself are freed — and the freed zones are
/// genuinely reusable by a later file.
fn smoke_minix_truncate_shrink_releases_indirect_zones() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_lib::id::DomainId;

    let device = RamBlockDevice::from_image(512, build_minix3_image_writable());
    let volume = match poll_once(MinixVolume::mount(device.clone(), DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let file = match poll_once(volume.root().lookup_async("hi.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup hi.txt failed"),
    };
    let data = shrink_pattern(20480);
    match poll_once(file.write(0, &data)) {
        Some(Ok(20480)) => {}
        _ => return TestResult::Fail("write pattern failed"),
    }
    let before = match poll_once(volume.read_inode(2)) {
        Some(Ok(i)) => i,
        _ => return TestResult::Fail("read inode failed"),
    };
    let ind_block = before.zones[super::inode::IND_SLOT];
    if ind_block == 0 {
        return TestResult::Fail("fixture did not reach the indirect range");
    }
    let zones = match poll_once(file_zones(&volume, &before, 20)) {
        Some(z) => z,
        _ => return TestResult::Fail("zone walk failed"),
    };
    if zones.len() != 20 {
        return TestResult::Fail("fixture file does not span 20 zones");
    }
    match poll_once(file.truncate(5000)) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("shrink to 5000 failed"),
    }
    let after = match poll_once(volume.read_inode(2)) {
        Some(Ok(i)) => i,
        _ => return TestResult::Fail("read shrunk inode failed"),
    };
    if after.size != 5000
        || after.zones[super::inode::IND_SLOT] != 0
        || after.zones[5] != 0
        || after.zones[6] != 0
    {
        return TestResult::Fail("indirect root / direct tail slots not detached on disk");
    }
    let img = device.snapshot();
    for (idx, zone) in zones.iter().enumerate() {
        if image_zone_used(&img, *zone) != (idx < 5) {
            return TestResult::Fail("kept/released zone bitmap state wrong after shrink");
        }
    }
    if image_zone_used(&img, ind_block) {
        return TestResult::Fail("the indirect block itself was not freed");
    }
    // Freed zones are reusable: a fresh file allocates and reads
    // back cleanly, and the shrunk file's kept range is undisturbed.
    let other = match poll_once(volume.root().create("o.bin")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create o.bin failed"),
    };
    let payload = shrink_pattern(3000);
    match poll_once(other.write(0, &payload)) {
        Some(Ok(3000)) => {}
        _ => return TestResult::Fail("write o.bin failed"),
    }
    let mut back = vec![0u8; 3000];
    match poll_once(other.read(0, &mut back)) {
        Some(Ok(3000)) => {}
        _ => return TestResult::Fail("read o.bin failed"),
    }
    if back != payload {
        return TestResult::Fail("file written into freed zones reads back wrong");
    }
    let mut kept = vec![0u8; 5000];
    match poll_once(file.read(0, &mut kept)) {
        Some(Ok(5000)) => {}
        _ => return TestResult::Fail("read kept range failed"),
    }
    if kept != shrink_pattern(5000) {
        return TestResult::Fail("shrunk file's kept range was disturbed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/minix",
    smoke_minix_truncate_shrink_releases_indirect_zones
);

/// Shrink to a size still inside the single-indirect range: the
/// indirect block survives, only its out-of-range slots are
/// cleared (on disk) and their zones freed; the last kept indirect
/// zone's tail is zeroed.
fn smoke_minix_truncate_shrink_inside_indirect_keeps_block() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_lib::id::DomainId;

    let device = RamBlockDevice::from_image(512, build_minix3_image_writable());
    let volume = match poll_once(MinixVolume::mount(device.clone(), DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let file = match poll_once(volume.root().lookup_async("hi.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup hi.txt failed"),
    };
    let data = shrink_pattern(20480);
    match poll_once(file.write(0, &data)) {
        Some(Ok(20480)) => {}
        _ => return TestResult::Fail("write pattern failed"),
    }
    let before = match poll_once(volume.read_inode(2)) {
        Some(Ok(i)) => i,
        _ => return TestResult::Fail("read inode failed"),
    };
    let ind_block = before.zones[super::inode::IND_SLOT];
    if ind_block == 0 {
        return TestResult::Fail("fixture did not reach the indirect range");
    }
    let zones = match poll_once(file_zones(&volume, &before, 20)) {
        Some(z) => z,
        _ => return TestResult::Fail("zone walk failed"),
    };
    if zones.len() != 20 {
        return TestResult::Fail("fixture file does not span 20 zones");
    }
    // keep = ceil(10340 / 1024) = 11 zones (indices 0..10).
    match poll_once(file.truncate(10340)) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("shrink to 10340 failed"),
    }
    let after = match poll_once(volume.read_inode(2)) {
        Some(Ok(i)) => i,
        _ => return TestResult::Fail("read shrunk inode failed"),
    };
    if after.size != 10340 || after.zones[super::inode::IND_SLOT] != ind_block {
        return TestResult::Fail("indirect block did not survive a shrink into its range");
    }
    let img = device.snapshot();
    // On-disk indirect slots: slot s backs file index 7 + s; slots
    // for indices 7..10 live, indices 11.. cleared.
    let ind_off = ind_block as usize * 1024;
    for slot in 0..13usize {
        let off = ind_off + slot * 4;
        let val = u32::from_le_bytes(img[off..off + 4].try_into().unwrap());
        let want = if slot < 4 { zones[7 + slot] } else { 0 };
        if val != want {
            return TestResult::Fail("on-disk indirect slots wrong after partial shrink");
        }
    }
    for (idx, zone) in zones.iter().enumerate() {
        if image_zone_used(&img, *zone) != (idx < 11) {
            return TestResult::Fail("kept/released zone bitmap state wrong after shrink");
        }
    }
    if !image_zone_used(&img, ind_block) {
        return TestResult::Fail("kept indirect block was freed");
    }
    // Partial tail: index 10 covers 10240..11264; the new EOF is
    // 100 bytes in, so [100, 1024) of that zone is zeroed on disk.
    let tail_zone = zones[10] as usize * 1024;
    for i in 0..1024 {
        let want = if i < 100 {
            shrink_pattern_at(10240 + i)
        } else {
            0
        };
        if img[tail_zone + i] != want {
            return TestResult::Fail("indirect partial tail zone not zeroed on disk");
        }
    }
    let mut back = vec![0u8; 10340];
    match poll_once(file.read(0, &mut back)) {
        Some(Ok(10340)) => {}
        _ => return TestResult::Fail("read back failed"),
    }
    if back != shrink_pattern(10340) {
        return TestResult::Fail("kept range reads back wrong after partial shrink");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/minix",
    smoke_minix_truncate_shrink_inside_indirect_keeps_block
);

/// Shrink to zero takes the existing full-release path; pin that
/// it still releases every zone and clears the inode.
fn smoke_minix_truncate_shrink_to_zero_releases_all_zones() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_lib::id::DomainId;

    let device = RamBlockDevice::from_image(512, build_minix3_image_writable());
    let volume = match poll_once(MinixVolume::mount(device.clone(), DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let file = match poll_once(volume.root().lookup_async("hi.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup hi.txt failed"),
    };
    let data = shrink_pattern(3000);
    match poll_once(file.write(0, &data)) {
        Some(Ok(3000)) => {}
        _ => return TestResult::Fail("write pattern failed"),
    }
    let before = match poll_once(volume.read_inode(2)) {
        Some(Ok(i)) => i,
        _ => return TestResult::Fail("read inode failed"),
    };
    let zones = match poll_once(file_zones(&volume, &before, 3)) {
        Some(z) => z,
        _ => return TestResult::Fail("zone walk failed"),
    };
    if zones.len() != 3 {
        return TestResult::Fail("fixture file does not span 3 zones");
    }
    match poll_once(file.truncate(0)) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("shrink to zero failed"),
    }
    let after = match poll_once(volume.read_inode(2)) {
        Some(Ok(i)) => i,
        _ => return TestResult::Fail("read inode failed"),
    };
    if after.size != 0 || after.zones.iter().any(|z| *z != 0) {
        return TestResult::Fail("size-0 inode still claims zones");
    }
    let img = device.snapshot();
    for zone in &zones {
        if image_zone_used(&img, *zone) {
            return TestResult::Fail("zone not freed by shrink to zero");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/minix",
    smoke_minix_truncate_shrink_to_zero_releases_all_zones
);

/// Test-only block device that delegates to a RAM device but fails
/// write submissions once an armed budget of successful writes is
/// spent — used to fail a shrink mid-flight. `u32::MAX` budget
/// means disarmed.
struct FailWritesDevice {
    inner: alloc::sync::Arc<narf_block::ram::RamBlockDevice>,
    writes_left: alloc::sync::Arc<core::sync::atomic::AtomicU32>,
}

impl narf_block::BlockDevice for FailWritesDevice {
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
        req: narf_block::BlockRequest,
    ) -> impl core::future::Future<Output = narf_block::BlockCompletion> + Send {
        use core::sync::atomic::Ordering;
        let fail = if matches!(req.op, narf_block::BlockOp::Write { .. }) {
            // Spend one write from the armed budget. The observed
            // value is the budget before this write: u32::MAX =
            // disarmed (pass), n > 0 = spent one (pass), 0 = budget
            // exhausted (fail). `fetch_update` reports the value
            // via Ok when the closure updated it and via Err when
            // it declined (MAX / 0), so read both arms the same way.
            let observed =
                match self
                    .writes_left
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                        if v == u32::MAX || v == 0 {
                            None
                        } else {
                            Some(v - 1)
                        }
                    }) {
                    Ok(prev) => prev,
                    Err(cur) => cur,
                };
            observed == 0
        } else {
            false
        };
        let inner = self.inner.clone();
        async move {
            if fail {
                return narf_block::BlockCompletion {
                    tag: 0,
                    user_tag: req.user_tag,
                    result: Err(narf_block::BlockError::IOError),
                };
            }
            inner.submit(req).await
        }
    }
    async fn flush(&self) {}
    async fn discard(&self, _range: narf_block::LbaRange) {}
    async fn cancel(&self, _tag: u64) -> narf_block::CancelResult {
        narf_block::CancelResult::NotFound
    }
}

/// A write failure mid-shrink must leave the volume consistent:
/// the on-disk inode still claims the old size, every zone it
/// references is still allocated, and the kept data is intact.
/// (Zones detached before the failure may leak — marked used but
/// unreferenced — never the reverse.)
fn smoke_minix_truncate_shrink_failure_keeps_size_and_zones() -> TestResult {
    use core::sync::atomic::{AtomicU32, Ordering};

    use narf_block::ram::RamBlockDevice;
    use narf_lib::id::DomainId;

    let inner = RamBlockDevice::from_image(512, build_minix3_image_writable());
    let budget = alloc::sync::Arc::new(AtomicU32::new(u32::MAX));
    let device = alloc::sync::Arc::new(FailWritesDevice {
        inner: inner.clone(),
        writes_left: budget.clone(),
    });
    let volume = match poll_once(MinixVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let file = match poll_once(volume.root().lookup_async("hi.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup hi.txt failed"),
    };
    let data = shrink_pattern(20480);
    match poll_once(file.write(0, &data)) {
        Some(Ok(20480)) => {}
        _ => return TestResult::Fail("write pattern failed"),
    }
    // Budget: the shrink's indirect-block write-back (one 1024-byte
    // block = two 512-byte sector writes) plus one more write
    // succeed; the detach-persisting inode write then fails.
    budget.store(3, Ordering::SeqCst);
    match poll_once(file.truncate(5000)) {
        Some(Err(_)) => {}
        _ => return TestResult::Fail("armed device did not fail the shrink"),
    }
    if file.stat().size != 20480 {
        return TestResult::Fail("size moved despite the failed shrink");
    }
    let mut kept = vec![0u8; 5000];
    match poll_once(file.read(0, &mut kept)) {
        Some(Ok(5000)) => {}
        _ => return TestResult::Fail("read kept range failed"),
    }
    if kept != shrink_pattern(5000) {
        return TestResult::Fail("kept data damaged by the failed shrink");
    }
    let on_disk = match poll_once(volume.read_inode(2)) {
        Some(Ok(i)) => i,
        _ => return TestResult::Fail("read inode failed"),
    };
    if on_disk.size != 20480 {
        return TestResult::Fail("on-disk size moved despite the failed shrink");
    }
    let img = inner.snapshot();
    for idx in 0..20 {
        let zone = match poll_once(volume.map_block(&on_disk, idx)) {
            Some(Ok(z)) => z,
            _ => return TestResult::Fail("zone walk failed"),
        };
        if let Some(zone) = zone {
            if !image_zone_used(&img, zone) {
                return TestResult::Fail("a zone referenced by the live inode was freed");
            }
        }
    }
    // The volume is still usable: disarmed, the same shrink now
    // succeeds and the regrow reads zeros.
    budget.store(u32::MAX, Ordering::SeqCst);
    match poll_once(file.truncate(5000)) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("retry shrink failed"),
    }
    match poll_once(file.truncate(12288)) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("regrow failed"),
    }
    let mut back = vec![0u8; 12288];
    match poll_once(file.read(0, &mut back)) {
        Some(Ok(12288)) => {}
        _ => return TestResult::Fail("read back failed"),
    }
    for (off, b) in back.iter().enumerate() {
        let want = if off < 5000 {
            shrink_pattern_at(off)
        } else {
            0
        };
        if *b != want {
            return TestResult::Fail("post-recovery regrow resurrected stale bytes");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/minix",
    smoke_minix_truncate_shrink_failure_keeps_size_and_zones
);

/// Minimal V1 (0x138F, 30-char names) image in the V3 fixtures'
/// layout: 32 inodes, imap block 2, zmap block 3, inode table at
/// block 4, first data zone 5, root inode 1 (zone 5), `hi.txt`
/// inode 2 with zone 6 preassigned and size 0.
fn build_minix1_image_writable() -> Vec<u8> {
    const BS: usize = 1024;
    const NBLOCKS: usize = 32;
    let mut img = vec![0u8; BS * NBLOCKS];
    let sb = BS;
    img[sb..sb + 2].copy_from_slice(&32u16.to_le_bytes()); // s_ninodes
    img[sb + 2..sb + 4].copy_from_slice(&(NBLOCKS as u16).to_le_bytes()); // s_nzones
    img[sb + 4..sb + 6].copy_from_slice(&1u16.to_le_bytes()); // s_imap_blocks
    img[sb + 6..sb + 8].copy_from_slice(&1u16.to_le_bytes()); // s_zmap_blocks
    img[sb + 8..sb + 10].copy_from_slice(&5u16.to_le_bytes()); // s_firstdatazone
    img[sb + 10..sb + 12].copy_from_slice(&0u16.to_le_bytes()); // s_log_zone_size
    img[sb + 12..sb + 16].copy_from_slice(&0x7fff_ffffu32.to_le_bytes()); // s_max_size
    img[sb + 16..sb + 18].copy_from_slice(&0x138Fu16.to_le_bytes()); // V1, 30-char names
    img[BS * 2] = 0b0000_0111; // inode bitmap: reserved + inodes 1, 2
    img[BS * 3] = 0b0000_0111; // zone bitmap: reserved + zones 5, 6
                               // V1 inodes are 32 bytes; 32 per block, table at block 4.
    let put_inode = |img: &mut [u8], ino: usize, mode: u16, size: u32, nlinks: u8, zone0: u16| {
        let off = BS * 4 + (ino - 1) * 32;
        img[off..off + 2].copy_from_slice(&mode.to_le_bytes());
        img[off + 4..off + 8].copy_from_slice(&size.to_le_bytes());
        img[off + 8..off + 12].copy_from_slice(&0xcafeu32.to_le_bytes());
        img[off + 13] = nlinks;
        img[off + 14..off + 16].copy_from_slice(&zone0.to_le_bytes());
    };
    put_inode(&mut img, 1, 0o040755, 96, 2, 5); // root dir: 3 entries x 32 bytes
    put_inode(&mut img, 2, 0o100644, 0, 1, 6);
    let root_off = BS * 5;
    let put_entry = |img: &mut [u8], idx: usize, ino: u16, name: &str| {
        let off = root_off + idx * 32;
        img[off..off + 2].copy_from_slice(&ino.to_le_bytes());
        img[off + 2..off + 2 + name.len()].copy_from_slice(name.as_bytes());
    };
    put_entry(&mut img, 0, 1, ".");
    put_entry(&mut img, 1, 1, "..");
    put_entry(&mut img, 2, 2, "hi.txt");
    img
}

/// The same shrink semantics through the V1 on-disk widths: u16
/// zone pointers in the inode and in indirect blocks.
fn smoke_minix_truncate_shrink_regrow_v1() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_lib::id::DomainId;

    let device = RamBlockDevice::from_image(512, build_minix1_image_writable());
    let volume = match poll_once(MinixVolume::mount(device.clone(), DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let file = match poll_once(volume.root().lookup_async("hi.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup hi.txt failed"),
    };
    let data = shrink_pattern(10240);
    match poll_once(file.write(0, &data)) {
        Some(Ok(10240)) => {}
        _ => return TestResult::Fail("write pattern failed"),
    }
    let before = match poll_once(volume.read_inode(2)) {
        Some(Ok(i)) => i,
        _ => return TestResult::Fail("read inode failed"),
    };
    if before.zones[super::inode::IND_SLOT] == 0 {
        return TestResult::Fail("fixture did not reach the indirect range");
    }
    let zones = match poll_once(file_zones(&volume, &before, 10)) {
        Some(z) => z,
        _ => return TestResult::Fail("zone walk failed"),
    };
    if zones.len() != 10 {
        return TestResult::Fail("fixture file does not span 10 zones");
    }
    match poll_once(file.truncate(5000)) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("shrink to 5000 failed"),
    }
    let after = match poll_once(volume.read_inode(2)) {
        Some(Ok(i)) => i,
        _ => return TestResult::Fail("read shrunk inode failed"),
    };
    if after.size != 5000
        || after.zones[super::inode::IND_SLOT] != 0
        || after.zones[5] != 0
        || after.zones[6] != 0
    {
        return TestResult::Fail("V1 indirect root / direct tail slots not detached");
    }
    let img = device.snapshot();
    for (idx, zone) in zones.iter().enumerate() {
        if image_zone_used(&img, *zone) != (idx < 5) {
            return TestResult::Fail("V1 kept/released zone bitmap state wrong after shrink");
        }
    }
    match poll_once(file.truncate(10240)) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("regrow failed"),
    }
    let mut back = vec![0u8; 10240];
    match poll_once(file.read(0, &mut back)) {
        Some(Ok(10240)) => {}
        _ => return TestResult::Fail("read back failed"),
    }
    for (off, b) in back.iter().enumerate() {
        let want = if off < 5000 {
            shrink_pattern_at(off)
        } else {
            0
        };
        if *b != want {
            return TestResult::Fail("V1 regrown range resurrected stale pre-shrink bytes");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/minix", smoke_minix_truncate_shrink_regrow_v1);
