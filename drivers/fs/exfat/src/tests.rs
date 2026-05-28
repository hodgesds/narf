//! Kernel-test entries for exFAT logic.
//!
//! Pure-logic tests cover:
//! - Boot-sector signature recognition (§3.1.2 `EXFAT   `).
//! - Cluster-shift math (§3.1.13 + §3.1.14).
//! - The §7.7 file-name fragment packing across multiple slots.
//! - Up-case table lookup for ASCII and a synthetic non-ASCII pair.
//! - Allocation-bitmap bit-position math (§7.1).
//!
//! End-to-end test mounts a hand-built exFAT image entirely in
//! heap memory through `RamBlockDevice`, enumerates the root,
//! looks up the file, and reads its bytes back.

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use super::boot::{ExfatBootSector, BOOT_SIGNATURE, EXFAT_SIGNATURE};
use super::dir::{
    entry_type, file_attr, name_hash, stream_flags, DIR_ENTRY_SIZE,
};
use super::fat::{classify, FatEntry};
use super::upcase::UpcaseTable;

// ── Boot-sector signature ──────────────────────────────────────────

fn smoke_exfat_boot_signature_recognised() -> TestResult {
    // §3.1.2 — FileSystemName is exactly 8 bytes "EXFAT   ".
    if EXFAT_SIGNATURE != b"EXFAT   " {
        return TestResult::Fail("EXFAT_SIGNATURE constant drifted from spec");
    }
    let mut boot = blank_boot();
    boot.filesystem_name = *EXFAT_SIGNATURE;
    if !boot.has_exfat_signature() {
        return TestResult::Fail("matching FileSystemName must validate");
    }
    boot.filesystem_name = *b"NTFS    ";
    if boot.has_exfat_signature() {
        return TestResult::Fail("non-EXFAT name must reject");
    }
    if BOOT_SIGNATURE != 0xAA55 {
        return TestResult::Fail("BOOT_SIGNATURE constant drifted from spec");
    }
    TestResult::Pass
}

fn blank_boot() -> ExfatBootSector {
    ExfatBootSector {
        jump_boot: [0; 3],
        filesystem_name: [0; 8],
        must_be_zero: [0; 53],
        partition_offset: 0,
        volume_length: 0,
        fat_offset: 0,
        fat_length: 0,
        cluster_heap_offset: 0,
        cluster_count: 0,
        first_cluster_of_root_directory: 0,
        volume_serial_number: 0,
        filesystem_revision: 0,
        volume_flags: 0,
        bytes_per_sector_shift: 9,
        sectors_per_cluster_shift: 0,
        number_of_fats: 1,
        drive_select: 0,
        percent_in_use: 0,
        reserved: [0; 7],
    }
}

// ── Cluster-shift math ─────────────────────────────────────────────

fn smoke_exfat_cluster_shift_math() -> TestResult {
    // §3.1.13 — BytesPerSector = 1 << shift; range [5..=12].
    // §3.1.14 — SectorsPerCluster = 1 << shift; capped so the
    //           product ≤ 25 (max 32 MiB cluster).
    let mut boot = blank_boot();
    boot.bytes_per_sector_shift = 9;   // 512 bytes/sector
    boot.sectors_per_cluster_shift = 3; // 8 sectors/cluster
    if boot.bytes_per_sector() != 512 {
        return TestResult::Fail("bytes_per_sector should be 512");
    }
    if boot.sectors_per_cluster() != 8 {
        return TestResult::Fail("sectors_per_cluster should be 8");
    }
    if boot.bytes_per_cluster() != 4096 {
        return TestResult::Fail("bytes_per_cluster should be 4096");
    }
    if !boot.shifts_in_range() {
        return TestResult::Fail("9+3 must be in-range");
    }

    // Out-of-range — reject.
    boot.bytes_per_sector_shift = 4; // 16 bytes/sector — below min
    if boot.shifts_in_range() {
        return TestResult::Fail("bps_shift=4 must be out-of-range");
    }
    boot.bytes_per_sector_shift = 12;
    boot.sectors_per_cluster_shift = 14; // 12+14=26 — above 25
    if boot.shifts_in_range() {
        return TestResult::Fail("sum > 25 must be out-of-range");
    }
    TestResult::Pass
}

// ── §7.7 file-name slot packing ────────────────────────────────────

fn smoke_exfat_filename_slot_packing() -> TestResult {
    // The §7.7 file-name entries hold up to 15 UTF-16 code units
    // each. A 30-character name must fit into exactly 2 slots; a
    // 31-character name needs 3 slots; the trailing positions in
    // the last slot are spec'd as ignored beyond `name_length`.
    let n30 = 30usize;
    let n31 = 31usize;
    if n30.div_ceil(15) != 2 {
        return TestResult::Fail("30-char name should need 2 slots");
    }
    if n31.div_ceil(15) != 3 {
        return TestResult::Fail("31-char name should need 3 slots");
    }
    let n1 = 1usize;
    if n1.div_ceil(15) != 1 {
        return TestResult::Fail("1-char name should need 1 slot");
    }
    TestResult::Pass
}

// ── §7.6.8 NameHash — sanity check ─────────────────────────────────

fn smoke_exfat_name_hash_changes_on_perturb() -> TestResult {
    // §7.6.8: NameHash is computed over the up-cased UTF-16
    // bytes. Two distinct names must (overwhelmingly likely) hash
    // differently; the same name two different ways must hash the
    // same when both are pre-upcased identically.
    let upcase = UpcaseTable::ascii_fallback();
    let n1: Vec<u16> = "FILE.TXT".encode_utf16().collect();
    let n2: Vec<u16> = "FILE.TX".encode_utf16().collect();
    let h1 = name_hash(&upcase.upcase(&n1));
    let h2 = name_hash(&upcase.upcase(&n2));
    if h1 == h2 {
        return TestResult::Fail("hashes must differ on perturb");
    }
    let n_lower: Vec<u16> = "file.txt".encode_utf16().collect();
    let h_lower = name_hash(&upcase.upcase(&n_lower));
    if h_lower != h1 {
        return TestResult::Fail("ASCII-folded forms must hash equal");
    }
    TestResult::Pass
}

// ── Up-case table lookup ───────────────────────────────────────────

fn smoke_exfat_upcase_ascii_lookup() -> TestResult {
    let t = UpcaseTable::ascii_fallback();
    if t.upcase_char(b'a' as u16) != b'A' as u16 {
        return TestResult::Fail("'a' must up-case to 'A'");
    }
    if t.upcase_char(b'z' as u16) != b'Z' as u16 {
        return TestResult::Fail("'z' must up-case to 'Z'");
    }
    if t.upcase_char(b'A' as u16) != b'A' as u16 {
        return TestResult::Fail("'A' must up-case to itself");
    }
    if t.upcase_char(0x00E9) != 0x00E9 {
        // ASCII fallback doesn't know about é; it must pass
        // through unchanged, which is the documented behaviour
        // of `ascii_fallback`.
        return TestResult::Fail("non-ASCII must pass through ASCII fallback");
    }

    // Decompressed table: build a tiny stream that maps the first
    // four code units to "ABCD" and identity-fills the rest via
    // the §7.2.5.2 0xFFFF run escape.
    let mut stream: Vec<u8> = Vec::new();
    for c in [b'A', b'B', b'C', b'D'] {
        stream.extend_from_slice(&(c as u16).to_le_bytes());
    }
    // 0xFFFF escape + run length covering the next 0x10000 - 4 entries.
    stream.extend_from_slice(&0xFFFFu16.to_le_bytes());
    stream.extend_from_slice(&((0x10000 - 4) as u16).to_le_bytes());
    let t = UpcaseTable::decompress(&stream);
    if t.upcase_char(0) != b'A' as u16 || t.upcase_char(3) != b'D' as u16 {
        return TestResult::Fail("decompressed prefix wrong");
    }
    if t.upcase_char(0x100) != 0x100 {
        return TestResult::Fail("identity fill broken");
    }
    TestResult::Pass
}

// ── Allocation-bitmap bit-position math (§7.1) ─────────────────────

fn smoke_exfat_bitmap_bit_position_math() -> TestResult {
    // §7.1: the bitmap holds one bit per cluster, bit 0 = cluster 2.
    // For cluster index `c`, the bit lives at bit `(c-2) % 8` of
    // byte `(c-2) / 8` of the stream.
    let cases = [(2u32, 0usize, 0u8), (3, 0, 1), (9, 0, 7), (10, 1, 0), (17, 1, 7)];
    for (cluster, byte, bit) in cases {
        let i = cluster - 2;
        let by = (i / 8) as usize;
        let bi = (i % 8) as u8;
        if by != byte || bi != bit {
            return TestResult::Fail("bitmap bit-position math drifted");
        }
    }
    TestResult::Pass
}

// ── FAT entry classifier (§3.3) ────────────────────────────────────

fn smoke_exfat_fat_classify() -> TestResult {
    if classify(0x0000_0000) != FatEntry::Free {
        return TestResult::Fail("0 must classify as Free");
    }
    if classify(0xFFFF_FFFF) != FatEntry::EndOfChain {
        return TestResult::Fail("0xFFFFFFFF must classify as EndOfChain");
    }
    if classify(0xFFFF_FFF7) != FatEntry::Bad {
        return TestResult::Fail("0xFFFFFFF7 must classify as Bad");
    }
    match classify(5) {
        FatEntry::Next(5) => {}
        _ => return TestResult::Fail("5 must classify as Next(5)"),
    }
    match classify(0xFFFF_FFF8) {
        FatEntry::Reserved(0xFFFF_FFF8) => {}
        _ => return TestResult::Fail("0xFFFFFFF8 must classify as Reserved"),
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/exfat", smoke_exfat_boot_signature_recognised);
kernel_test_in!("drivers/fs/exfat", smoke_exfat_cluster_shift_math);
kernel_test_in!("drivers/fs/exfat", smoke_exfat_filename_slot_packing);
kernel_test_in!("drivers/fs/exfat", smoke_exfat_name_hash_changes_on_perturb);
kernel_test_in!("drivers/fs/exfat", smoke_exfat_upcase_ascii_lookup);
kernel_test_in!("drivers/fs/exfat", smoke_exfat_bitmap_bit_position_math);
kernel_test_in!("drivers/fs/exfat", smoke_exfat_fat_classify);

// ── End-to-end mount + I/O against RamBlockDevice ──────────────────

/// One-shot future poller — RamBlockDevice resolves on the first
/// poll, so all our exFAT operations complete synchronously.
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

/// Geometry constants for our hand-built test image. Picked so
/// every region fits in a small handful of sectors.
const LBS: usize = 512;
const SECTORS_PER_CLUSTER: u32 = 1;
const FAT_OFFSET_SECTORS: u32 = 24;     // 24 reserved sectors (matches typical exFAT).
const FAT_LENGTH_SECTORS: u32 = 8;      // Plenty for a small image.
const CLUSTER_HEAP_OFFSET: u32 = 32;    // FAT_OFFSET + FAT_LENGTH.
const TOTAL_SECTORS: u64 = 256;
const CLUSTER_COUNT: u32 = 64;
const ROOT_DIRECTORY_CLUSTER: u32 = 2;
const BITMAP_CLUSTER: u32 = 3;
const UPCASE_CLUSTER: u32 = 4;
const FILE_CLUSTER: u32 = 5;

fn write_le_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn write_le_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn write_le_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn lba_off(img: &mut [u8], lba: u64) -> &mut [u8] {
    let start = lba as usize * LBS;
    &mut img[start..start + LBS]
}

/// Build a minimal exFAT image with one file at the root.
/// Layout:
/// - sector 0: main boot sector (signatures + geometry).
/// - sectors 1..24: reserved (zeros).
/// - sectors 24..32: FAT.
/// - sectors 32..: cluster heap (cluster 2 = root dir, cluster 3
///   = bitmap, cluster 4 = up-case table, cluster 5 = file data).
fn build_exfat_image(file_name: &str, file_data: &[u8]) -> Vec<u8> {
    let mut img: Vec<u8> = vec![0u8; (TOTAL_SECTORS as usize) * LBS];

    // ── Boot sector (§3.1) ───────────────────────────────────────
    {
        let s = lba_off(&mut img, 0);
        s[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]);     // §3.1.1 JumpBoot
        s[3..11].copy_from_slice(EXFAT_SIGNATURE);          // §3.1.2 FileSystemName
        // §3.1.3 MustBeZero stays at zero.
        write_le_u64(s, 64, 0);                              // §3.1.4 PartitionOffset
        write_le_u64(s, 72, TOTAL_SECTORS);                  // §3.1.5 VolumeLength
        write_le_u32(s, 80, FAT_OFFSET_SECTORS);             // §3.1.6 FatOffset
        write_le_u32(s, 84, FAT_LENGTH_SECTORS);             // §3.1.7 FatLength
        write_le_u32(s, 88, CLUSTER_HEAP_OFFSET);            // §3.1.8 ClusterHeapOffset
        write_le_u32(s, 92, CLUSTER_COUNT);                  // §3.1.9 ClusterCount
        write_le_u32(s, 96, ROOT_DIRECTORY_CLUSTER);         // §3.1.10 FirstClusterOfRootDirectory
        write_le_u32(s, 100, 0xDEADBEEF);                    // §3.1.11 VolumeSerialNumber
        write_le_u16(s, 104, 0x0100);                        // §3.1.12 FileSystemRevision (1.00)
        write_le_u16(s, 106, 0);                             // §3.1.13 VolumeFlags
        s[108] = 9;                                          // §3.1.13 BytesPerSectorShift (512)
        s[109] = 0;                                          // §3.1.14 SectorsPerClusterShift (1)
        s[110] = 1;                                          // §3.1.15 NumberOfFats
        s[111] = 0x80;                                       // §3.1.16 DriveSelect
        s[112] = 0;                                          // §3.1.17 PercentInUse
        // §3.1.19 BootSignature
        s[510] = 0x55;
        s[511] = 0xAA;
    }

    // ── FAT (§3.3) ───────────────────────────────────────────────
    // Index 0 = 0xFFFFFFF8|MediaType, index 1 = 0xFFFFFFFF.
    // Bitmap, up-case table, file all single-cluster: each entry
    // = EOC. Root dir is also single-cluster = EOC.
    {
        let s = lba_off(&mut img, FAT_OFFSET_SECTORS as u64);
        write_le_u32(s, 0, 0xFFFF_FFF8);                    // FAT[0]
        write_le_u32(s, 4, 0xFFFF_FFFF);                    // FAT[1]
        write_le_u32(s, (ROOT_DIRECTORY_CLUSTER as usize) * 4, 0xFFFF_FFFF);
        write_le_u32(s, (BITMAP_CLUSTER as usize) * 4, 0xFFFF_FFFF);
        write_le_u32(s, (UPCASE_CLUSTER as usize) * 4, 0xFFFF_FFFF);
        write_le_u32(s, (FILE_CLUSTER as usize) * 4, 0xFFFF_FFFF);
    }

    // ── Up-case table (§7.2): full 128-entry ASCII prefix
    // mapping a..z → A..Z (other ASCII identity), then a §7.2.5.2
    // 0xFFFF escape for the rest of the u16 range. Without the
    // a→A mapping the volume's table would be pure identity, in
    // which case lookup of "hello.txt" would never collide with
    // the on-disk "HELLO.TXT" hash.
    let upcase_stream_len: u32 = (0x80 * 2) + 4;
    {
        let upcase_lba = (CLUSTER_HEAP_OFFSET + (UPCASE_CLUSTER - 2) * SECTORS_PER_CLUSTER) as u64;
        let s = lba_off(&mut img, upcase_lba);
        // Explicit first 128 entries.
        for i in 0u16..0x80 {
            let mapped = if (b'a' as u16..=b'z' as u16).contains(&i) {
                i - (b'a' - b'A') as u16
            } else {
                i
            };
            s[(i as usize) * 2..(i as usize) * 2 + 2]
                .copy_from_slice(&mapped.to_le_bytes());
        }
        // §7.2.5.2 — 0xFFFF + run length identity-fills the rest.
        let off = 0x80 * 2;
        s[off..off + 2].copy_from_slice(&0xFFFFu16.to_le_bytes());
        s[off + 2..off + 4].copy_from_slice(&((0x10000 - 0x80) as u16).to_le_bytes());
    }

    // ── Allocation bitmap (§7.1): mark clusters 2..=5 in-use ─────
    // Bit (c-2) of byte (c-2)/8 = 1 for c in [2,3,4,5].
    let bitmap_byte_count: u64 = (CLUSTER_COUNT as u64).div_ceil(8);
    {
        let bm_lba = (CLUSTER_HEAP_OFFSET + (BITMAP_CLUSTER - 2) * SECTORS_PER_CLUSTER) as u64;
        let s = lba_off(&mut img, bm_lba);
        s[0] = 0b0000_1111; // bits 0..3 set → clusters 2,3,4,5 in use
    }

    // ── Root directory (cluster 2) ───────────────────────────────
    // Three primary entries (Bitmap 0x81, Up-case 0x82, File 0x85)
    // plus the Stream + Name slots for the file. Spec §6 requires
    // the bitmap entry to appear before any file entries that
    // reference allocated clusters; we mirror that here.
    {
        let root_lba =
            (CLUSTER_HEAP_OFFSET + (ROOT_DIRECTORY_CLUSTER - 2) * SECTORS_PER_CLUSTER) as u64;
        let s = lba_off(&mut img, root_lba);

        // §7.1 Allocation Bitmap entry (32 bytes).
        let bm = &mut s[0..32];
        bm[0] = entry_type::ALLOCATION_BITMAP;
        bm[1] = 0; // BitmapFlags (single FAT)
        write_le_u32(bm, 20, BITMAP_CLUSTER);
        write_le_u64(bm, 24, bitmap_byte_count);

        // §7.2 Up-case Table entry (32 bytes).
        let uc = &mut s[32..64];
        uc[0] = entry_type::UPCASE_TABLE;
        // §7.2.3 TableChecksum at offset 4..=7 — we don't verify
        // it on read, so leave as zero.
        write_le_u32(uc, 20, UPCASE_CLUSTER);
        write_le_u64(uc, 24, upcase_stream_len as u64);

        // §7.4 File Directory Entry (32 bytes) for our one file.
        // Pre-compute SecondaryCount from the name length.
        let name_utf16: Vec<u16> = file_name.encode_utf16().collect();
        let name_len = name_utf16.len() as u8;
        let name_slots = name_len.div_ceil(15);
        let secondary_count = 1u8 + name_slots; // 1 stream + N name

        let fe = &mut s[64..96];
        fe[0] = entry_type::FILE;
        fe[1] = secondary_count;
        // SetChecksum (§7.4.3) — we don't verify on read.
        write_le_u16(fe, 2, 0);
        // FileAttributes — Archive bit (regular file).
        write_le_u16(fe, 4, file_attr::ARCHIVE);
        // Timestamps left zero.

        // §7.6 Stream Extension entry (32 bytes).
        // Name hash is computed over the up-cased UTF-16 name.
        // Our ASCII names are already upper-case, so the identity
        // up-case table gives the same hash either way.
        let upcase = UpcaseTable::ascii_fallback();
        let upcased = upcase.upcase(&name_utf16);
        let hash = name_hash(&upcased);

        let se = &mut s[96..128];
        se[0] = entry_type::STREAM_EXTENSION;
        // GeneralSecondaryFlags: NoFatChain so we don't need to
        // walk the FAT for the single-cluster file.
        se[1] = stream_flags::ALLOCATION_POSSIBLE | stream_flags::NO_FAT_CHAIN;
        se[3] = name_len;
        write_le_u16(se, 4, hash);
        write_le_u64(se, 8, file_data.len() as u64); // ValidDataLength
        write_le_u32(se, 20, FILE_CLUSTER);
        write_le_u64(se, 24, file_data.len() as u64); // DataLength

        // §7.7 File Name entries (32 bytes each, up to 15 UTF-16
        // code units per slot).
        let mut written = 0usize;
        for slot in 0..name_slots as usize {
            let off = 128 + slot * DIR_ENTRY_SIZE;
            let ne = &mut s[off..off + DIR_ENTRY_SIZE];
            ne[0] = entry_type::FILE_NAME;
            ne[1] = 0; // GeneralSecondaryFlags
            for i in 0..15 {
                if written < name_utf16.len() {
                    let bytes = name_utf16[written].to_le_bytes();
                    ne[2 + i * 2] = bytes[0];
                    ne[2 + i * 2 + 1] = bytes[1];
                    written += 1;
                }
            }
        }
        // Anything after the last name slot remains 0x00 → that's
        // the END_OF_DIRECTORY sentinel, which is what we want.
    }

    // ── File data ─────────────────────────────────────────────────
    {
        let file_lba = (CLUSTER_HEAP_OFFSET + (FILE_CLUSTER - 2) * SECTORS_PER_CLUSTER) as u64;
        let s = lba_off(&mut img, file_lba);
        s[..file_data.len()].copy_from_slice(file_data);
    }

    img
}

fn smoke_exfat_mount_ramblock_round_trip() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::{FileType, FsInstance};
    use narf_lib::id::DomainId;

    use crate::volume::ExfatVolume;

    let payload: &[u8] = b"hello exfat\n";
    let img = build_exfat_image("HELLO.TXT", payload);
    let device = RamBlockDevice::from_image(LBS as u32, img);
    let volume = match poll_once(ExfatVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("ExfatVolume::mount failed"),
    };
    if volume.name() != "exfat" {
        return TestResult::Fail("volume.name() mismatch");
    }

    let root = volume.root();
    let entries = match poll_once(root.enumerate_async(0, 16)) {
        Some(Ok(v)) => v,
        Some(Err(_)) => return TestResult::Fail("enumerate_async returned Err"),
        None => return TestResult::Fail("enumerate_async pending"),
    };
    if entries.len() != 1 {
        return TestResult::Fail("expected exactly one entry");
    }
    if entries[0].0 != "HELLO.TXT" {
        return TestResult::Fail("entry name mismatch");
    }
    if entries[0].1 != FileType::File {
        return TestResult::Fail("entry type mismatch");
    }

    // Look up the file (case-insensitive — give a lower-case
    // probe to exercise the up-case table).
    let file = match poll_once(root.lookup_async("hello.txt")) {
        Some(Ok(f)) => f,
        Some(Err(_)) => return TestResult::Fail("lookup_async returned Err"),
        None => return TestResult::Fail("lookup_async pending"),
    };
    if file.stat().size as usize != payload.len() {
        return TestResult::Fail("stat.size wrong");
    }

    let mut buf = [0u8; 32];
    let n = match poll_once(file.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("file.read failed"),
    };
    if n != payload.len() || &buf[..n] != payload {
        return TestResult::Fail("file contents mismatch");
    }

    // Out-of-range read returns 0.
    let n2 = match poll_once(file.read(payload.len() as u64 + 100, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("file.read past EOF failed"),
    };
    if n2 != 0 {
        return TestResult::Fail("read past EOF should return 0");
    }

    // NotFound on missing entry.
    match poll_once(root.lookup_async("nope.txt")) {
        Some(Err(narf_filesystem::FsError::NotFound)) => {}
        _ => return TestResult::Fail("lookup of missing file should NotFound"),
    }

    let _ = "side-effect-free".to_string(); // exercise alloc::string import
    TestResult::Pass
}
kernel_test_in!("drivers/fs/exfat", smoke_exfat_mount_ramblock_round_trip);

// ── Write-path scaffolding smokes ────────────────────────────────

/// §6.3.3 SetChecksum is deterministic and skips bytes 2..4
/// (the checksum field itself). Verify round-trip on a constructed
/// 32-byte group.
fn smoke_exfat_set_checksum_round_trip() -> TestResult {
    use super::dir::{finalize_set_checksum, verify_set_checksum, set_checksum};

    // Build a 64-byte group (one primary + one secondary entry).
    let mut group = [0u8; 64];
    group[0] = 0x85; // FILE entry type
    group[1] = 1; // secondary_count
    // Bytes 4..32 are file attributes / timestamps / reserved.
    for i in 4..32 {
        group[i] = i as u8;
    }
    // Stream extension secondary
    group[32] = 0xC0;
    group[33] = 0x03; // ALLOCATION_POSSIBLE | NO_FAT_CHAIN
    for i in 34..64 {
        group[i] = i as u8;
    }
    // Compute + write back.
    finalize_set_checksum(&mut group);
    if !verify_set_checksum(&group) {
        return TestResult::Fail("verify after finalize must succeed");
    }
    // Perturb a byte that isn't part of the checksum field.
    group[10] ^= 0x55;
    if verify_set_checksum(&group) {
        return TestResult::Fail("verify after perturb must fail");
    }
    // Re-finalize, verify passes again.
    finalize_set_checksum(&mut group);
    if !verify_set_checksum(&group) {
        return TestResult::Fail("verify after re-finalize must succeed");
    }
    // Independent recompute matches the stored value.
    let stored = u16::from_le_bytes([group[2], group[3]]);
    if set_checksum(&group) != stored {
        return TestResult::Fail("recompute must match stored");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/exfat", smoke_exfat_set_checksum_round_trip);

/// §7.2.3 up-case-table checksum runs on the byte image of the
/// table stream, two bytes per code unit.
fn smoke_exfat_upcase_checksum_known_values() -> TestResult {
    use super::upcase::upcase_checksum;

    // Empty input → 0.
    if upcase_checksum(&[]) != 0 {
        return TestResult::Fail("empty input must yield 0");
    }
    // The §7.2.3 algorithm is rotate-right-1 + add. Verify the first
    // byte alone matches the formula: c0 = (((0 & 1) << 31) | (0 >> 1)) + 0xFE = 0xFE.
    if upcase_checksum(&[0xFE]) != 0xFE {
        return TestResult::Fail("single byte 0xFE must hash to 0xFE");
    }
    // Determinism check.
    let bytes = b"NARF-FS smoke test bytes";
    let a = upcase_checksum(bytes);
    let b = upcase_checksum(bytes);
    if a != b {
        return TestResult::Fail("non-deterministic");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/exfat", smoke_exfat_upcase_checksum_known_values);

// ── §6.3.2 SetChecksum on multi-entry groups ─────────────────────
//
// Per MS exFAT spec §6.3.2 the algorithm is:
//   checksum = ((checksum & 1) << 15) | (checksum >> 1)
//   checksum = (checksum + byte) & 0xFFFF
// applied to every byte in the set except bytes 2 and 3 of the first
// (primary) entry (the checksum field itself).
//
// The test vectors below are self-validating: `finalize_set_checksum`
// writes the computed value into bytes 2..4 of the primary entry; we
// then recompute with `set_checksum` and compare the stored and live
// values. A 3-entry set (primary + stream + one name slot) and a
// 5-entry set (primary + stream + three name slots) exercise different
// total byte counts.

/// Helper: advance the MS §6.3.2 checksum state by one byte.
fn exfat_checksum_step(acc: u16, b: u8) -> u16 {
    let rotated = ((acc & 1) << 15) | (acc >> 1);
    rotated.wrapping_add(b as u16)
}

/// Reference implementation of §6.3.2 set checksum over a byte slice,
/// skipping bytes 2 and 3 of the first entry. Used to cross-check the
/// production `set_checksum` in dir.rs.
fn ref_set_checksum(group: &[u8]) -> u16 {
    let mut acc: u16 = 0;
    for (i, &b) in group.iter().enumerate() {
        if i == 2 || i == 3 {
            continue;
        }
        acc = exfat_checksum_step(acc, b);
    }
    acc
}

fn smoke_exfat_set_checksum_3entry_set() -> TestResult {
    // 3-entry set: FileDirectory (0x85) + StreamExtension (0xC0) +
    // FileName (0xC1). 3 × 32 = 96 bytes total.
    // Spec §7.4 — primary entry first; secondary_count = 2.
    use super::dir::{finalize_set_checksum, recompute_set_checksum, verify_set_checksum, set_checksum};

    let mut group = [0u8; 96];
    // Primary: FileDirectory.
    group[0] = 0x85; // type
    group[1] = 2;    // SecondaryCount = 2
    // bytes 2..4 are the checksum field — left as zero initially.
    // FileAttributes = ARCHIVE (0x0020).
    group[4] = 0x20;
    group[5] = 0x00;
    // Stream Extension.
    group[32] = 0xC0; // type
    group[33] = 0x03; // GeneralSecondaryFlags
    group[35] = 5;    // NameLength = 5
    // FileName slot.
    group[64] = 0xC1; // type
    // First 5 UTF-16 chars of name "HELLO" packed LE.
    let hello: &[u16] = &[b'H' as u16, b'E' as u16, b'L' as u16, b'L' as u16, b'O' as u16];
    for (i, &cu) in hello.iter().enumerate() {
        let bytes = cu.to_le_bytes();
        group[66 + i * 2] = bytes[0];
        group[66 + i * 2 + 1] = bytes[1];
    }

    // Compute expected checksum via the reference implementation.
    let expected = ref_set_checksum(&group);

    // Production path: finalize + verify.
    finalize_set_checksum(&mut group);
    let stored = u16::from_le_bytes([group[2], group[3]]);
    if stored != expected {
        return TestResult::Fail("finalize_set_checksum: stored != reference for 3-entry set");
    }
    if !verify_set_checksum(&group) {
        return TestResult::Fail("verify_set_checksum failed after finalize on 3-entry set");
    }
    if set_checksum(&group) != stored {
        return TestResult::Fail("set_checksum recompute != stored for 3-entry set");
    }

    // recompute_set_checksum is equivalent to finalize_set_checksum.
    group[10] ^= 0x7F; // perturb a payload byte
    recompute_set_checksum(&mut group);
    if !verify_set_checksum(&group) {
        return TestResult::Fail("verify_set_checksum failed after recompute_set_checksum");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/fs/exfat", smoke_exfat_set_checksum_3entry_set);

fn smoke_exfat_set_checksum_5entry_set() -> TestResult {
    // 5-entry set: FileDirectory (0x85) + StreamExtension (0xC0) +
    // three FileName entries (0xC1). 5 × 32 = 160 bytes total.
    // SecondaryCount = 4 (1 stream + 3 name slots).
    use super::dir::{finalize_set_checksum, recompute_set_checksum, verify_set_checksum, set_checksum};

    let mut group = [0u8; 160];
    group[0] = 0x85; // primary type
    group[1] = 4;    // SecondaryCount = 4
    group[4] = 0x20; // FileAttributes = ARCHIVE
    group[32] = 0xC0; // stream extension
    group[33] = 0x01; // ALLOCATION_POSSIBLE
    group[35] = 40;   // NameLength = 40 (3 × 15 = 45 > 40 — fills 2 full + partial slot)
    // Three FileName entries.
    group[64]  = 0xC1;
    group[96]  = 0xC1;
    group[128] = 0xC1;
    // Fill each name slot with a distinct repeating pattern.
    for i in 0..15usize {
        let bytes = ((0x41u16 + i as u16) & 0xFF).to_le_bytes();
        group[66  + i * 2] = bytes[0]; // first slot: A..O
        group[98  + i * 2] = bytes[0].wrapping_add(0x10); // second: Q..
        group[130 + i * 2] = bytes[0].wrapping_add(0x20); // third: a..
    }

    let expected = ref_set_checksum(&group);
    finalize_set_checksum(&mut group);
    let stored = u16::from_le_bytes([group[2], group[3]]);
    if stored != expected {
        return TestResult::Fail("finalize_set_checksum: stored != reference for 5-entry set");
    }
    if !verify_set_checksum(&group) {
        return TestResult::Fail("verify_set_checksum failed after finalize on 5-entry set");
    }
    if set_checksum(&group) != stored {
        return TestResult::Fail("set_checksum recompute != stored for 5-entry set");
    }

    // Perturb + recompute via the canonical name.
    group[80] ^= 0xAA;
    recompute_set_checksum(&mut group);
    if !verify_set_checksum(&group) {
        return TestResult::Fail("verify_set_checksum failed after recompute_set_checksum on 5-entry");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/fs/exfat", smoke_exfat_set_checksum_5entry_set);
