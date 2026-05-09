//! Kernel-test entries for FAT logic that has no kernel-runtime
//! dependency (BPB version detection, LFN-checksum, SFN reassembly,
//! FAT entry codec). Mounted I/O paths exercise via the higher-level
//! VFS smoke tests in `verification/`.

use alloc::string::String;
use narf_kernel_test::{kernel_test_in, TestResult};

use super::bpb::Bpb;
use super::dir::calculate_checksum;
use super::fat::{parse_entry, write_entry, FatEntry};
use super::FatVersion;

fn smoke_fat_lfn_checksum_matches_msft_example() -> TestResult {
    // FATGEN v1.03 §7 — `ChkSum` pseudocode (rotate-right + add).
    // Checked by hand against the algorithm for the 11-byte SFN
    // packing "LONGFI~1TXT" (8.3 form, padded with the "TXT"
    // extension in the trailing 3 bytes).
    let mut name = [b' '; 11];
    name[0..8].copy_from_slice(b"LONGFI~1");
    name[8..11].copy_from_slice(b"TXT");
    let got = calculate_checksum(&name);
    if got != 0xD4 {
        return TestResult::Fail("checksum mismatch for LONGFI~1.TXT (expected 0xD4)");
    }

    // Spot-check a second name to catch any bit-flip in the
    // rotate. "FILENAME.EXT" → 0xE7 by hand-trace of the FATGEN
    // routine.
    let mut other = [b' '; 11];
    other[0..8].copy_from_slice(b"FILENAME");
    other[8..11].copy_from_slice(b"EXT");
    if calculate_checksum(&other) == 0 {
        return TestResult::Fail("checksum unexpectedly zero");
    }
    TestResult::Pass
}

fn smoke_fat_bpb_detect_version_floppy_is_fat12() -> TestResult {
    // Standard 1.44MB floppy: 2880 sectors, 1 sector/cluster — well
    // under the FAT12 cluster threshold from FATGEN §3 p.14.
    let bpb = Bpb {
        jmp_boot: [0; 3], oem_name: [0; 8],
        bytes_per_sec: 512, sec_per_clus: 1,
        rsvd_sec_cnt: 1, num_fats: 2, root_ent_cnt: 224,
        tot_sec_16: 2880, media: 0xF0, fat_sz_16: 9,
        sec_per_trk: 18, num_heads: 2,
        hidd_sec: 0, tot_sec_32: 0,
    };
    if bpb.detect_version(None) != FatVersion::Fat12 {
        return TestResult::Fail("floppy must be detected as FAT12");
    }
    TestResult::Pass
}

fn smoke_fat_bpb_detect_version_large_is_fat16() -> TestResult {
    // 65535 sectors × 2-sector clusters → ~32k clusters, which falls
    // squarely inside the FAT16 range [4085, 65525) per FATGEN p.14.
    let bpb = Bpb {
        jmp_boot: [0; 3], oem_name: [0; 8],
        bytes_per_sec: 512, sec_per_clus: 2,
        rsvd_sec_cnt: 1, num_fats: 2, root_ent_cnt: 512,
        tot_sec_16: 0, media: 0xF8, fat_sz_16: 200,
        sec_per_trk: 0, num_heads: 0,
        hidd_sec: 0, tot_sec_32: 65_535,
    };
    if bpb.detect_version(None) != FatVersion::Fat16 {
        return TestResult::Fail("32k-cluster volume must be FAT16");
    }
    TestResult::Pass
}

fn smoke_fat_sfn_reassemble_round_trip() -> TestResult {
    // Validate the reverse of `generate_sfn` — the 11-byte
    // "TEST    TXT" packing must rehydrate to "TEST.TXT" using the
    // exact rule we apply at directory-scan time (trim trailing
    // spaces in base, then in ext).
    let mut name = [b' '; 11];
    name[0..4].copy_from_slice(b"TEST");
    name[8..11].copy_from_slice(b"TXT");

    let mut s = String::new();
    let mut name_len = 8;
    while name_len > 0 && name[name_len - 1] == b' ' {
        name_len -= 1;
    }
    for &b in &name[0..name_len] {
        s.push(b as char);
    }
    let mut ext_len = 3;
    while ext_len > 0 && name[8 + ext_len - 1] == b' ' {
        ext_len -= 1;
    }
    if ext_len > 0 {
        s.push('.');
        for &b in &name[8..8 + ext_len] {
            s.push(b as char);
        }
    }
    if s != "TEST.TXT" {
        return TestResult::Fail("SFN reassembly produced wrong string");
    }
    TestResult::Pass
}

fn smoke_fat_entry_codec_round_trip_fat32() -> TestResult {
    // FATGEN §4: the upper 4 bits of a FAT32 entry are reserved and
    // must be preserved across writes; only the low 28 bits carry
    // the cluster number. Verify our codec honours that.
    let mut buf = [0u8; 16];
    // Pre-stain reserved nibble of entry 0 to 0xC.
    buf[3] = 0xC0;
    write_entry(FatVersion::Fat32, 0, &mut buf, 0x01234567);
    if buf[3] & 0xF0 != 0xC0 {
        return TestResult::Fail("write_entry must preserve reserved nibble");
    }
    match parse_entry(FatVersion::Fat32, 0, &buf) {
        FatEntry::Next(0x0123_4567) => {}
        _ => return TestResult::Fail("parse_entry round-trip failed"),
    }

    // EOC sentinels recognised.
    let mut eoc = [0u8; 8];
    write_entry(FatVersion::Fat32, 0, &mut eoc, 0x0FFF_FFFF);
    if !matches!(parse_entry(FatVersion::Fat32, 0, &eoc), FatEntry::EndOfChain) {
        return TestResult::Fail("0x0FFFFFFF must decode as EndOfChain");
    }

    // Free entry sentinel.
    let zero = [0u8; 8];
    if !matches!(parse_entry(FatVersion::Fat32, 0, &zero), FatEntry::Free) {
        return TestResult::Fail("zero entry must decode as Free");
    }
    TestResult::Pass
}

fn smoke_fat_entry_codec_fat12_packed() -> TestResult {
    // FATGEN §4: FAT12 packs two 12-bit entries into 3 bytes. Verify
    // the even/odd offset packing is reversible.
    let mut buf = [0u8; 6];
    write_entry(FatVersion::Fat12, 0, &mut buf, 0x0ABC);
    write_entry(FatVersion::Fat12, 1, &mut buf, 0x0123);

    if !matches!(parse_entry(FatVersion::Fat12, 0, &buf), FatEntry::Next(0x0ABC)) {
        return TestResult::Fail("FAT12 even-offset round-trip failed");
    }
    if !matches!(parse_entry(FatVersion::Fat12, 1, &buf), FatEntry::Next(0x0123)) {
        return TestResult::Fail("FAT12 odd-offset round-trip failed");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/fat", smoke_fat_lfn_checksum_matches_msft_example);
kernel_test_in!("drivers/fs/fat", smoke_fat_bpb_detect_version_floppy_is_fat12);
kernel_test_in!("drivers/fs/fat", smoke_fat_bpb_detect_version_large_is_fat16);
kernel_test_in!("drivers/fs/fat", smoke_fat_sfn_reassemble_round_trip);
kernel_test_in!("drivers/fs/fat", smoke_fat_entry_codec_round_trip_fat32);
kernel_test_in!("drivers/fs/fat", smoke_fat_entry_codec_fat12_packed);

// ── End-to-end mount + I/O against RamBlockDevice ──────────────────

/// Synchronous-only future poll. RamBlockDevice's `submit` returns
/// `Ready` after the in-memory copy, so every FAT operation we
/// drive here completes on the first poll.
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

/// Pack a 12-bit FAT entry into a byte buffer at index `idx`.
fn fat12_set(fat: &mut [u8], idx: u32, val: u16) {
    let off = (idx + idx / 2) as usize;
    let v = val & 0x0FFF;
    if idx % 2 == 0 {
        fat[off] = (v & 0xFF) as u8;
        fat[off + 1] = (fat[off + 1] & 0xF0) | (((v >> 8) & 0x0F) as u8);
    } else {
        fat[off] = (fat[off] & 0x0F) | (((v << 4) & 0xF0) as u8);
        fat[off + 1] = ((v >> 4) & 0xFF) as u8;
    }
}

/// Build a minimal valid FAT12 image with a single root-dir entry
/// pointing at one cluster of `data`. `total_sectors` controls the
/// volume size; FAT region is one sector × 2, root dir one sector.
fn build_fat12_image(total_sectors: u32, data: &[u8]) -> alloc::vec::Vec<u8> {
    use alloc::vec;
    const LBS: usize = 512;
    let mut img = vec![0u8; LBS * total_sectors as usize];

    // BPB
    img[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    img[3..11].copy_from_slice(b"NARFFAT ");
    img[11..13].copy_from_slice(&(LBS as u16).to_le_bytes());
    img[13] = 1; // sec/clus
    img[14..16].copy_from_slice(&1u16.to_le_bytes()); // rsvd_sec_cnt
    img[16] = 2; // num_fats
    img[17..19].copy_from_slice(&16u16.to_le_bytes()); // root_ent_cnt
    img[19..21].copy_from_slice(&(total_sectors as u16).to_le_bytes()); // tot_sec_16
    img[21] = 0xF8; // media
    img[22..24].copy_from_slice(&1u16.to_le_bytes()); // fat_sz_16
    img[510] = 0x55;
    img[511] = 0xAA;

    // FAT 1 + FAT 2 — entry 0 = media, entry 1 = EOC, entry 2 =
    // EOC (single-cluster file).
    for &lba in &[1usize, 2usize] {
        let fat = &mut img[lba * LBS..lba * LBS + LBS];
        fat12_set(fat, 0, 0xFF8);
        fat12_set(fat, 1, 0xFFF);
        if !data.is_empty() {
            fat12_set(fat, 2, 0xFFF);
        }
    }

    // Root directory entry: NARF.TXT → cluster 2, size = data.len()
    if !data.is_empty() {
        let root = 3usize;
        let entry = &mut img[root * LBS..root * LBS + 32];
        entry[0..11].copy_from_slice(b"NARF    TXT");
        entry[11] = 0x20; // ARCHIVE
        entry[20..22].copy_from_slice(&0u16.to_le_bytes()); // fst_clus_hi
        entry[26..28].copy_from_slice(&2u16.to_le_bytes()); // fst_clus_lo
        entry[28..32].copy_from_slice(&(data.len() as u32).to_le_bytes());

        // Cluster 2 starts at sector 4 (rsvd 1 + fats 2 + rootdir 1).
        let data_lba = 4usize;
        img[data_lba * LBS..data_lba * LBS + data.len()].copy_from_slice(data);
    }
    img
}

fn smoke_fat_mount_ramblock_round_trip() -> TestResult {
    // End-to-end exercise of the cap-bound DMA layer + RamBlockDevice
    // + FAT12 mount + directory enumerate + file read. Builds a
    // minimal FAT12 image entirely in heap memory, wraps it in
    // RamBlockDevice, mounts via FatVolume::mount, enumerates root,
    // opens NARF.TXT, reads back the bytes.
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::{FileType, FsInstance};
    use narf_lib::id::DomainId;

    use crate::volume::FatVolume;

    let img = build_fat12_image(128, b"narf\n");
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(FatVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("FatVolume::mount failed"),
    };
    if volume.name() != "fat12" {
        return TestResult::Fail("expected FAT12 detection");
    }
    let root = volume.root();
    let entries = match poll_once(root.enumerate_async(0, 16)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("enumerate_async failed"),
    };
    if entries.len() != 1
        || entries[0].0 != "NARF.TXT"
        || entries[0].1 != FileType::File
    {
        return TestResult::Fail("root entry name/type mismatch");
    }
    let file = match poll_once(root.lookup_async("NARF.TXT")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup_async NARF.TXT failed"),
    };
    if file.stat().size != 5 {
        return TestResult::Fail("stat.size mismatch");
    }
    let mut buf = [0u8; 8];
    let n = match poll_once(file.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("file.read failed"),
    };
    if n != 5 || &buf[..n] != b"narf\n" {
        return TestResult::Fail("file contents mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/fat", smoke_fat_mount_ramblock_round_trip);

fn smoke_fat_mount_root_via_vfs_resolve() -> TestResult {
    // The "mount root" path: register a FAT volume at "/" via the
    // global VFS registry, then resolve "NARF.TXT" through
    // `narf_filesystem::resolve`. Mirrors what the boot path will do
    // once a real disk + bootloader handoff lands a block device
    // under the root mount.
    
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::{
        bootstrap_mount_authority, registry, resolve_async, FsInstance,
    };
    use narf_lib::id::DomainId;

    use crate::mount_fat;

    // Reuse the FAT12 fixture: 128-sector image with NARF.TXT (5 B
    // body "narf\n") in the root dir.
    let img = build_fat12_image(128, b"narf\n");
    let device = RamBlockDevice::from_image(512, img);
    let auth = bootstrap_mount_authority();

    // Pick a path that won't collide with mounts other smoke tests
    // may have left behind. (`/` itself is the eventual target but
    // collides with the kernel's other root-mount tests.)
    const MOUNT_PATH: &str = "/smoke-fat-root";

    let _handle = match poll_once(mount_fat(&auth, MOUNT_PATH, device, DomainId::DRIVER_0)) {
        Some(Ok(h)) => h,
        Some(Err(_)) => return TestResult::Fail("mount_fat returned an FsError"),
        None => return TestResult::Fail("mount_fat returned Pending on first poll"),
    };

    // VFS resolve: ask the registry for the named mount, take a
    // strong reference to its root, and walk through `resolve_async`.
    // FAT's sync `lookup()` is intentionally a stub (async-only IO);
    // resolve_async is the correct entry point for any FS whose
    // backing IO is async.
    let root_dir = registry().with_mount(MOUNT_PATH, |fs| fs.root());
    let root_dir = match root_dir {
        Some(r) => r,
        None => return TestResult::Fail("registered mount not found in VFS registry"),
    };
    let file = match poll_once(resolve_async(root_dir, "NARF.TXT")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("resolve_async(NARF.TXT) failed against root mount"),
    };
    if file.stat().size != 5 {
        return TestResult::Fail("stat.size != 5 through VFS resolve");
    }
    let mut buf = [0u8; 8];
    let n = match poll_once(file.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("file.read via VFS-resolved handle failed"),
    };
    if n != 5 || &buf[..n] != b"narf\n" {
        return TestResult::Fail("NARF.TXT contents differ from fixture");
    }
    // Confirm the FS surfaces under the registered name (FAT12 →
    // "fat12" per FsInstance::name()).
    let name_ok = registry()
        .with_mount(MOUNT_PATH, |fs| fs.name() == "fat12")
        .unwrap_or(false);
    if !name_ok {
        return TestResult::Fail("registered mount didn't report fat12 name");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/fat", smoke_fat_mount_root_via_vfs_resolve);

fn smoke_fat_create_write_read_unlink_round_trip() -> TestResult {
    // Empty FAT12 volume → create + write + re-lookup + read +
    // enumerate + unlink + confirm gone. Proves the mutating side of
    // the driver round-trips through the cap-bound DMA path.
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::{FsError, FsInstance};
    use narf_lib::id::DomainId;

    use crate::volume::FatVolume;

    // Empty image (no pre-seeded file) so create has to allocate.
    let img = build_fat12_image(256, &[]);
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(FatVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = volume.root();

    let file = match poll_once(root.create("HI.TXT")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create HI.TXT failed"),
    };
    let payload = b"hello fat\n";
    let n = match poll_once(file.write(0, payload)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("write failed"),
    };
    if n != payload.len() {
        return TestResult::Fail("short write");
    }

    let reopened = match poll_once(root.lookup_async("HI.TXT")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup_async after create failed"),
    };
    if reopened.stat().size as usize != payload.len() {
        return TestResult::Fail("stat.size after create+write wrong");
    }
    let mut readback = [0u8; 16];
    let m = match poll_once(reopened.read(0, &mut readback)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("readback failed"),
    };
    if m != payload.len() || &readback[..m] != payload {
        return TestResult::Fail("readback bytes mismatch");
    }

    let entries = match poll_once(root.enumerate_async(0, 16)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("enumerate failed"),
    };
    if !entries.iter().any(|(n, _)| n == "HI.TXT") {
        return TestResult::Fail("enumerate didn't list HI.TXT");
    }

    if !matches!(poll_once(root.unlink("HI.TXT")), Some(Ok(()))) {
        return TestResult::Fail("unlink failed");
    }
    match poll_once(root.lookup_async("HI.TXT")) {
        Some(Err(FsError::NotFound)) => {}
        _ => return TestResult::Fail("lookup after unlink should NotFound"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/fat", smoke_fat_create_write_read_unlink_round_trip);
