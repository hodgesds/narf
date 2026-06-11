//! Kernel-test entries for the ISO 9660 driver.
//!
//! Pure-logic tests cover the volume-descriptor type byte, directory-
//! record decode, and filename-suffix stripping. The end-to-end test
//! builds a minimal ECMA-119 image entirely in heap memory, wraps it
//! in `RamBlockDevice`, mounts via `Iso9660Volume::mount`, enumerates
//! the root, opens a file, and reads the bytes back.
//!
//! References (test fixture layout — same set as the rest of the
//! crate; no GPL/LGPL ISO 9660 code consulted):
//! - ECMA-119 §6.2.1 (System Area = first 16 sectors).
//! - ECMA-119 §6.2.2 / §8 (Volume Descriptor sequence at sector 16+).
//! - ECMA-119 §8.4 (PVD field offsets).
//! - ECMA-119 §9.1 (Directory Record layout).
//! - ECMA-119 §9.1.11.1 ("." = 0x00, ".." = 0x01).

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use super::descriptor::vd_type;
use super::dir::{flags as dir_flags, read_directory_record};
use super::node::decode_file_identifier;
use super::SECTOR_SIZE;

// ── Pure-logic smokes ──────────────────────────────────────────────

fn smoke_iso9660_vd_type_constants() -> TestResult {
    // ECMA-119 §8.1.1 — descriptor-type byte values. Spot-check the
    // three we depend on at mount time.
    if vd_type::BOOT_RECORD != 0 {
        return TestResult::Fail("BOOT_RECORD must be 0");
    }
    if vd_type::PRIMARY != 1 {
        return TestResult::Fail("PRIMARY must be 1");
    }
    if vd_type::TERMINATOR != 255 {
        return TestResult::Fail("TERMINATOR must be 255");
    }
    TestResult::Pass
}

fn smoke_iso9660_directory_record_decode() -> TestResult {
    // Hand-build a 33-byte fixed-prefix directory record (§9.1.1
    // through §9.1.10) and decode it through the public helper.
    // The bytes here are the canonical layout — every offset is
    // dictated by ECMA-119 with no implementation latitude.
    let mut sector = vec![0u8; SECTOR_SIZE];
    let off = 0;
    sector[off] = 33; // §9.1.1 length
    sector[off + 1] = 0; // §9.1.2 ext-attr len
                         // §9.1.3 — extent_location (both-endian); LE 0x0000_0014, BE
    sector[off + 2..off + 6].copy_from_slice(&20u32.to_le_bytes());
    sector[off + 6..off + 10].copy_from_slice(&20u32.to_be_bytes());
    // §9.1.4 — data_length (both-endian); LE 0x0000_002A, BE
    sector[off + 10..off + 14].copy_from_slice(&42u32.to_le_bytes());
    sector[off + 14..off + 18].copy_from_slice(&42u32.to_be_bytes());
    // §9.1.5 — recording_date_time (7 bytes — left zero).
    // §9.1.6 — file_flags: DIRECTORY bit set.
    sector[off + 25] = dir_flags::DIRECTORY;
    // §9.1.7/8 — file_unit_size, interleave_gap_size left zero.
    // §9.1.9 — volume_sequence_number both-endian.
    sector[off + 28..off + 30].copy_from_slice(&1u16.to_le_bytes());
    sector[off + 30..off + 32].copy_from_slice(&1u16.to_be_bytes());
    // §9.1.10 — file_identifier_length.
    sector[off + 32] = 1;

    let record = read_directory_record(&sector, off);
    if record.length != 33 {
        return TestResult::Fail("length byte mismatch");
    }
    if !record.is_directory() {
        return TestResult::Fail("DIRECTORY flag not surfaced");
    }
    if record.extent_lba_le() != 20 {
        return TestResult::Fail("extent_lba LE half mismatch");
    }
    if record.data_length_le() != 42 {
        return TestResult::Fail("data_length LE half mismatch");
    }
    if record.file_identifier_length != 1 {
        return TestResult::Fail("file_identifier_length mismatch");
    }
    TestResult::Pass
}

fn smoke_iso9660_decode_file_identifier_strips_version_and_dot() -> TestResult {
    // ECMA-119 §7.6 / §9.1.11: identifiers are "NAME.EXT;VER"
    // (uppercase) or single 0x00/0x01 bytes for "." / "..".
    if decode_file_identifier(&[0x00]) != "." {
        return TestResult::Fail("0x00 must decode as \".\"");
    }
    if decode_file_identifier(&[0x01]) != ".." {
        return TestResult::Fail("0x01 must decode as \"..\"");
    }
    if decode_file_identifier(b"TEST.TXT;1") != "TEST.TXT" {
        return TestResult::Fail("\";1\" suffix must be stripped");
    }
    if decode_file_identifier(b"README.;1") != "README" {
        return TestResult::Fail("trailing dot must be stripped on extension-less files");
    }
    if decode_file_identifier(b"DIRNAME") != "DIRNAME" {
        return TestResult::Fail("plain directory id must round-trip");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/iso9660", smoke_iso9660_vd_type_constants);
kernel_test_in!("drivers/fs/iso9660", smoke_iso9660_directory_record_decode);
kernel_test_in!(
    "drivers/fs/iso9660",
    smoke_iso9660_decode_file_identifier_strips_version_and_dot
);

// ── End-to-end mount + enumerate + read against RamBlockDevice ────

/// Synchronous-only future poll. `RamBlockDevice::submit` returns
/// `Ready` after the in-memory copy, so every ISO 9660 operation we
/// drive in tests completes on the first poll. Same shape as the
/// FAT crate's helper.
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
    // SAFETY: `raw_waker` builds a `RawWaker` whose vtable's clone/wake
    // ops are no-ops over a null data pointer, so all four vtable
    // functions honour the `RawWakerVTable` contract for any (here null)
    // data pointer.
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    // SAFETY: `fut` is a local owned by this function and never moved
    // again before it is dropped at end of scope, satisfying the
    // `Pin::new_unchecked` no-move invariant.
    let pinned = unsafe { Pin::new_unchecked(&mut fut) };
    match pinned.poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

/// Write a both-endian u32 (LE then BE) at `off`.
fn write_u32_be_le(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    buf[off + 4..off + 8].copy_from_slice(&v.to_be_bytes());
}

/// Write a both-endian u16 (LE then BE) at `off`.
fn write_u16_be_le(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
    buf[off + 2..off + 4].copy_from_slice(&v.to_be_bytes());
}

/// Build a single directory record at `dst[off..]`. Returns the
/// total bytes consumed (record length, padded to even).
fn write_dir_record(
    dst: &mut [u8],
    off: usize,
    extent_lba: u32,
    data_length: u32,
    file_flags: u8,
    identifier: &[u8],
) -> usize {
    let header = 33;
    let mut total = header + identifier.len();
    if total % 2 != 0 {
        total += 1; // §9.1 — padding to even-byte boundary.
    }
    debug_assert!(total <= u8::MAX as usize);
    dst[off] = total as u8; // §9.1.1
    dst[off + 1] = 0; // §9.1.2
    write_u32_be_le(dst, off + 2, extent_lba); // §9.1.3
    write_u32_be_le(dst, off + 10, data_length); // §9.1.4
                                                 // §9.1.5 — recording_date_time (7 bytes left zero).
    dst[off + 25] = file_flags; // §9.1.6
                                // §9.1.7/8 — left zero.
    write_u16_be_le(dst, off + 28, 1); // §9.1.9 — vol seq
    dst[off + 32] = identifier.len() as u8; // §9.1.10
    dst[off + 33..off + 33 + identifier.len()].copy_from_slice(identifier);
    total
}

/// Construct a minimal valid ISO 9660 image:
///
///   sectors 0..16   System Area (zeros, ECMA-119 §6.2.1)
///   sector 16       Primary Volume Descriptor (§8.4)
///   sector 17       Volume Descriptor Set Terminator (§8.3)
///   sector 18       Root directory extent (one sector,
///                   contains records for ".", "..", "TEST.TXT;1")
///   sector 19       (padding so file data aligns to sector 20)
///   sector 20       File contents — "narf-iso\n"
///
/// Returns `(image_bytes, file_payload)`.
fn build_iso9660_image() -> (Vec<u8>, &'static [u8]) {
    const TOTAL_SECTORS: usize = 24;
    let mut img = vec![0u8; SECTOR_SIZE * TOTAL_SECTORS];
    let payload: &'static [u8] = b"narf-iso\n";

    // Root directory occupies sector 18, length = one sector.
    let root_extent_lba: u32 = 18;
    let root_data_length: u32 = SECTOR_SIZE as u32;

    // Lay out the root directory records at sector 18.
    let root_off = 18 * SECTOR_SIZE;
    let mut cursor = 0usize;
    // "." record — id 0x00, points at the directory itself.
    cursor += write_dir_record(
        &mut img[root_off..],
        cursor,
        root_extent_lba,
        root_data_length,
        dir_flags::DIRECTORY,
        &[0x00],
    );
    // ".." record — id 0x01, points at the parent (== self for root).
    cursor += write_dir_record(
        &mut img[root_off..],
        cursor,
        root_extent_lba,
        root_data_length,
        dir_flags::DIRECTORY,
        &[0x01],
    );
    // "TEST.TXT;1" → sector 20, length = payload.len().
    let _ = write_dir_record(
        &mut img[root_off..],
        cursor,
        20,
        payload.len() as u32,
        0,
        b"TEST.TXT;1",
    );

    // Sector 16 — Primary Volume Descriptor (§8.4).
    let pvd_off = 16 * SECTOR_SIZE;
    img[pvd_off] = vd_type::PRIMARY; // §8.1.1
    img[pvd_off + 1..pvd_off + 6].copy_from_slice(b"CD001"); // §8.1.2
    img[pvd_off + 6] = 1; // §8.1.3 version
                          // §8.4.4 unused (zero).
                          // §8.4.5/6 — system + volume identifier left as zeros.
                          // §8.4.8 — volume_space_size (both-endian).
    write_u32_be_le(&mut img, pvd_off + 80, TOTAL_SECTORS as u32);
    // §8.4.10 — volume_set_size = 1.
    write_u16_be_le(&mut img, pvd_off + 120, 1);
    // §8.4.11 — volume_sequence_number = 1.
    write_u16_be_le(&mut img, pvd_off + 124, 1);
    // §8.4.12 — logical_block_size = 2048.
    write_u16_be_le(&mut img, pvd_off + 128, SECTOR_SIZE as u16);
    // §8.4.13 — path_table_size (left zero, optional path table).
    // §8.4.18 — root directory record (34 bytes embedded).
    let root_record_off = pvd_off + 156;
    let root_rec_len = write_dir_record(
        &mut img,
        root_record_off,
        root_extent_lba,
        root_data_length,
        dir_flags::DIRECTORY,
        &[0x00],
    );
    debug_assert_eq!(root_rec_len, 34);
    // §8.4.31 — file_structure_version = 1, at offset 881.
    img[pvd_off + 881] = 1;

    // Sector 17 — Volume Descriptor Set Terminator (§8.3).
    let term_off = 17 * SECTOR_SIZE;
    img[term_off] = vd_type::TERMINATOR;
    img[term_off + 1..term_off + 6].copy_from_slice(b"CD001");
    img[term_off + 6] = 1;

    // File contents at sector 20.
    let data_off = 20 * SECTOR_SIZE;
    img[data_off..data_off + payload.len()].copy_from_slice(payload);

    (img, payload)
}

fn smoke_iso9660_mount_ramblock_round_trip() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::{FileType, FsInstance};
    use narf_lib::id::DomainId;

    use crate::volume::Iso9660Volume;

    let (img, payload) = build_iso9660_image();
    let device = RamBlockDevice::from_image(SECTOR_SIZE as u32, img);

    let volume = match poll_once(Iso9660Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        Some(Err(_)) => return TestResult::Fail("Iso9660Volume::mount returned an error"),
        None => return TestResult::Fail("Iso9660Volume::mount did not complete on first poll"),
    };
    if volume.name() != "iso9660" {
        return TestResult::Fail("FsInstance::name did not report iso9660");
    }

    let root = volume.root();
    let entries = match poll_once(root.enumerate_async(0, 16)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("enumerate_async failed"),
    };
    if entries.len() != 1 || entries[0].0 != "TEST.TXT" || entries[0].1 != FileType::File {
        return TestResult::Fail("root entry mismatch (expected exactly TEST.TXT)");
    }

    let file = match poll_once(root.lookup_async("TEST.TXT")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup_async TEST.TXT failed"),
    };
    if file.stat().size != payload.len() as u64 {
        return TestResult::Fail("stat.size mismatch");
    }

    // Lookups must be case-insensitive (ECMA-119 §7.4.1).
    if poll_once(root.lookup_async("test.txt"))
        .and_then(|r| r.ok())
        .is_none()
    {
        return TestResult::Fail("case-insensitive lookup failed");
    }

    let mut buf = [0u8; 32];
    let n = match poll_once(file.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("file.read failed"),
    };
    if n != payload.len() || &buf[..n] != payload {
        return TestResult::Fail("file contents mismatch");
    }

    // EOF behaviour — read past end yields 0.
    let m = match poll_once(file.read(payload.len() as u64, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("EOF read failed"),
    };
    if m != 0 {
        return TestResult::Fail("read past end must return 0");
    }

    // A non-existent name must surface NotFound, not Unsupported.
    use narf_filesystem::FsError;
    match poll_once(root.lookup_async("NOSUCH.TXT")) {
        Some(Err(FsError::NotFound)) => {}
        _ => return TestResult::Fail("missing entry must yield NotFound"),
    }

    let _ = String::new(); // keep `alloc::string::String` import live for non-unicode builds
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/iso9660",
    smoke_iso9660_mount_ramblock_round_trip
);

/// ECMA-119 §6.1: ISO 9660 is non-rewritable. Every mutating
/// operation must surface `FsError::ReadOnly` (NOT `Unsupported`)
/// so callers can tell the difference between "this medium does
/// not accept writes" and "this driver has not implemented writes
/// yet."
fn smoke_iso9660_write_paths_are_read_only() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::{FsError, FsInstance};
    use narf_lib::id::DomainId;

    use crate::volume::Iso9660Volume;

    let (img, _payload) = build_iso9660_image();
    let device = RamBlockDevice::from_image(SECTOR_SIZE as u32, img);
    let volume = match poll_once(Iso9660Volume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = volume.root();

    // FileOps::write
    let file = match poll_once(root.lookup_async("TEST.TXT")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup TEST.TXT failed"),
    };
    match poll_once(file.write(0, b"x")) {
        Some(Err(FsError::ReadOnly)) => {}
        _ => return TestResult::Fail("write must yield ReadOnly"),
    }

    // FileOps::truncate
    match poll_once(file.truncate(0)) {
        Some(Err(FsError::ReadOnly)) => {}
        _ => return TestResult::Fail("truncate must yield ReadOnly"),
    }

    // DirOps mutators
    match poll_once(root.unlink("TEST.TXT")) {
        Some(Err(FsError::ReadOnly)) => {}
        _ => return TestResult::Fail("unlink must yield ReadOnly"),
    }
    match poll_once(root.create("new.txt")) {
        Some(Err(FsError::ReadOnly)) => {}
        _ => return TestResult::Fail("create must yield ReadOnly"),
    }
    match poll_once(root.mkdir("newdir")) {
        Some(Err(FsError::ReadOnly)) => {}
        _ => return TestResult::Fail("mkdir must yield ReadOnly"),
    }
    match poll_once(root.rmdir("newdir")) {
        Some(Err(FsError::ReadOnly)) => {}
        _ => return TestResult::Fail("rmdir must yield ReadOnly"),
    }
    match poll_once(root.symlink("link", "TEST.TXT")) {
        Some(Err(FsError::ReadOnly)) => {}
        _ => return TestResult::Fail("symlink must yield ReadOnly"),
    }
    match poll_once(root.rename("TEST.TXT", "NEW.TXT")) {
        Some(Err(FsError::ReadOnly)) => {}
        _ => return TestResult::Fail("rename must yield ReadOnly"),
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/iso9660",
    smoke_iso9660_write_paths_are_read_only
);
