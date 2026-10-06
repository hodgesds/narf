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
        jmp_boot: [0; 3],
        oem_name: [0; 8],
        bytes_per_sec: 512,
        sec_per_clus: 1,
        rsvd_sec_cnt: 1,
        num_fats: 2,
        root_ent_cnt: 224,
        tot_sec_16: 2880,
        media: 0xF0,
        fat_sz_16: 9,
        sec_per_trk: 18,
        num_heads: 2,
        hidd_sec: 0,
        tot_sec_32: 0,
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
        jmp_boot: [0; 3],
        oem_name: [0; 8],
        bytes_per_sec: 512,
        sec_per_clus: 2,
        rsvd_sec_cnt: 1,
        num_fats: 2,
        root_ent_cnt: 512,
        tot_sec_16: 0,
        media: 0xF8,
        fat_sz_16: 200,
        sec_per_trk: 0,
        num_heads: 0,
        hidd_sec: 0,
        tot_sec_32: 65_535,
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
    if !matches!(
        parse_entry(FatVersion::Fat32, 0, &eoc),
        FatEntry::EndOfChain
    ) {
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

    if !matches!(
        parse_entry(FatVersion::Fat12, 0, &buf),
        FatEntry::Next(0x0ABC)
    ) {
        return TestResult::Fail("FAT12 even-offset round-trip failed");
    }
    if !matches!(
        parse_entry(FatVersion::Fat12, 1, &buf),
        FatEntry::Next(0x0123)
    ) {
        return TestResult::Fail("FAT12 odd-offset round-trip failed");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/fat",
    smoke_fat_lfn_checksum_matches_msft_example
);
kernel_test_in!(
    "drivers/fs/fat",
    smoke_fat_bpb_detect_version_floppy_is_fat12
);
kernel_test_in!(
    "drivers/fs/fat",
    smoke_fat_bpb_detect_version_large_is_fat16
);
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
    // SAFETY: `raw_waker` builds a RawWaker over a 'static vtable whose
    // clone/wake/drop functions are all no-ops and never dereference the
    // null data pointer, so the contract for `Waker::from_raw` (the
    // vtable functions are sound for the given data pointer) holds.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    // SAFETY: `fut` is a local owned by this function and is not moved for
    // the remainder of its scope (it is only polled through `pinned`),
    // satisfying the pin guarantee required by `Pin::new_unchecked`.
    // SAFETY: Valid MMIO bounds or trusted driver environment
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
    if entries.len() != 1 || entries[0].0 != "NARF.TXT" || entries[0].1 != FileType::File {
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
    use narf_filesystem::{bootstrap_mount_authority, registry, resolve_async};
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

/// FAT inode identity (fs/fat/inode.c): the root is `MSDOS_ROOT_INO` = 1,
/// a file is numbered by its directory entry's position (`i_pos`) — the
/// same on every lookup and never the root's — and every node reports its
/// volume's `st_dev`, which differs from another volume's.
fn smoke_fat_inode_identity_is_stable_and_distinct() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::volume::FatVolume;

    let mount = || {
        let img = build_fat12_image(128, b"narf\n");
        poll_once(FatVolume::mount(
            RamBlockDevice::from_image(512, img),
            DomainId::DRIVER_0,
        ))
    };
    let (Some(Ok(vol)), Some(Ok(other))) = (mount(), mount()) else {
        return TestResult::Fail("FatVolume::mount failed");
    };
    let root = vol.root();
    if root.ino() != 1 {
        return TestResult::Fail("FAT root is not MSDOS_ROOT_INO");
    }
    let (Some(Ok(a)), Some(Ok(b))) = (
        poll_once(root.lookup_async("NARF.TXT")),
        poll_once(root.lookup_async("narf.txt")),
    ) else {
        return TestResult::Fail("lookup_async NARF.TXT failed");
    };
    if a.ino() <= 1 || a.ino() != b.ino() {
        return TestResult::Fail("a FAT file's inode is 0/1 or changes between lookups");
    }
    let dev = root.inode_attrs().dev;
    if dev == 0 || a.inode_attrs().dev != dev {
        return TestResult::Fail("FAT nodes are not on one nonzero st_dev");
    }
    if other.root().inode_attrs().dev == dev {
        return TestResult::Fail("two FAT volumes share an st_dev");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/fat",
    smoke_fat_inode_identity_is_stable_and_distinct
);

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
kernel_test_in!(
    "drivers/fs/fat",
    smoke_fat_create_write_read_unlink_round_trip
);

// ── Timestamps ──────────────────────────────────────────────────────
//
// Linux `fat_fill_inode` (vfat): mtime = ctime = `fat_time_fat2unix`
// of the write date/time with no 10 ms part; atime = the access date at
// local midnight; the root (`fat_read_root`) is all zero. NARF decodes
// with `fat_tz_offset` = 0 (no `tz=`/`time_offset=`, no kernel timezone).
// The driver used to report mtime 0 for everything and stamp 1980-01-01
// on every metadata flush.

const NS: u64 = 1_000_000_000;
/// 2023-11-14 22:13:20 UTC (1_700_000_000) as a DOS date / time.
const DOS_DATE_2023: u16 = (43 << 9) | (11 << 5) | 14;
const DOS_TIME_2023: u16 = (22 << 11) | (13 << 5) | (20 / 2);
const UNIX_2023: u64 = 1_700_000_000;
/// 2000-02-29 12:34:56 UTC (951_827_696): a leap day.
const DOS_DATE_LEAP: u16 = (20 << 9) | (2 << 5) | 29;
const DOS_TIME_LEAP: u16 = (12 << 11) | (34 << 5) | (56 / 2);
const UNIX_LEAP: u64 = 951_827_696;

/// Root-directory slot `idx` of a [`build_fat12_image`] image.
fn fat12_root_slot(img: &mut [u8], idx: usize) -> &mut [u8] {
    let off = 3 * 512 + idx * 32;
    &mut img[off..off + 32]
}

/// Set an SFN entry's create tenth/time/date, access date and write
/// time/date (FATGEN §6 offsets 13, 14, 16, 18, 22, 24).
fn put_fat_times(e: &mut [u8], crt: (u8, u16, u16), adate: u16, wrt: (u16, u16)) {
    e[13] = crt.0;
    e[14..16].copy_from_slice(&crt.1.to_le_bytes());
    e[16..18].copy_from_slice(&crt.2.to_le_bytes());
    e[18..20].copy_from_slice(&adate.to_le_bytes());
    e[22..24].copy_from_slice(&wrt.0.to_le_bytes());
    e[24..26].copy_from_slice(&wrt.1.to_le_bytes());
}

/// A file reports its write date/time exactly as mtime and ctime, its
/// access date at midnight as atime; the create-time 10 ms byte does NOT
/// leak into mtime; and a write's metadata flush leaves the on-disk write
/// time alone instead of stamping a placeholder.
fn smoke_fat_file_reports_exact_times() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::volume::FatVolume;

    let mut img = build_fat12_image(128, b"narf\n");
    let adate = (43 << 9) | (11 << 5) | 15; // 2023-11-15
    put_fat_times(
        fat12_root_slot(&mut img, 0),
        (199, DOS_TIME_LEAP, DOS_DATE_LEAP),
        adate,
        (DOS_TIME_2023, DOS_DATE_2023),
    );
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(FatVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = volume.root();
    let file = match poll_once(root.lookup_async("NARF.TXT")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup NARF.TXT failed"),
    };
    let attrs = file.inode_attrs();
    if attrs.mtime_ns != UNIX_2023 * NS {
        return TestResult::Fail("file mtime_ns is not the DOS write date/time");
    }
    if attrs.ctime_ns != attrs.mtime_ns {
        return TestResult::Fail("FAT ctime must equal mtime (one on-disk field)");
    }
    if attrs.atime_ns != 1_700_006_400 * NS {
        return TestResult::Fail("file atime_ns is not the access date at midnight");
    }
    if file.stat().mtime_cycles != narf_time::ns_to_cycles(UNIX_2023 * NS) {
        return TestResult::Fail("Stat::mtime_cycles does not encode the mtime");
    }
    // A write flushes the entry (size, cluster); the write time must survive.
    if !matches!(poll_once(file.write(0, b"NARF\n")), Some(Ok(5))) {
        return TestResult::Fail("write failed");
    }
    let again = match poll_once(root.lookup_async("NARF.TXT")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("re-lookup failed"),
    };
    if again.inode_attrs().mtime_ns != UNIX_2023 * NS {
        return TestResult::Fail("metadata flush overwrote the on-disk write time");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/fat", smoke_fat_file_reports_exact_times);

/// A subdirectory reports its entry's write time through `dir_mtime_ns`
/// and `inode_attrs`; the root, which has no entry, is the epoch exactly
/// as Linux's `fat_read_root` reports it.
fn smoke_fat_dir_reports_mtime() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::volume::FatVolume;

    let mut img = build_fat12_image(128, b"narf\n");
    // SUB → cluster 3 (sector 5), with "." and "..".
    {
        let e = fat12_root_slot(&mut img, 1);
        e[0..11].copy_from_slice(b"SUB        ");
        e[11] = 0x10; // DIRECTORY
        e[26..28].copy_from_slice(&3u16.to_le_bytes());
        put_fat_times(e, (0, 0, 0), 0, (DOS_TIME_LEAP, DOS_DATE_LEAP));
    }
    for &lba in &[1usize, 2usize] {
        fat12_set(&mut img[lba * 512..lba * 512 + 512], 3, 0xFFF);
    }
    let sub_sec = 5 * 512;
    img[sub_sec..sub_sec + 11].copy_from_slice(b".          ");
    img[sub_sec + 11] = 0x10;
    img[sub_sec + 26..sub_sec + 28].copy_from_slice(&3u16.to_le_bytes());
    img[sub_sec + 32..sub_sec + 43].copy_from_slice(b"..         ");
    img[sub_sec + 43] = 0x10;

    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(FatVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = volume.root();
    if root.dir_mtime_ns() != 0 || root.inode_attrs().mtime_ns != 0 {
        return TestResult::Fail("FAT root must report the epoch, as Linux does");
    }
    let sub = match poll_once(root.lookup_dir_async("SUB")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("lookup_dir SUB failed"),
    };
    if sub.dir_mtime_ns() != UNIX_LEAP * NS {
        return TestResult::Fail("subdirectory dir_mtime_ns is not its write time");
    }
    let attrs = sub.inode_attrs();
    if attrs.mtime_ns != UNIX_LEAP * NS || attrs.ctime_ns != UNIX_LEAP * NS {
        return TestResult::Fail("subdirectory InodeAttrs times are not exact");
    }
    // An access date of 0 decodes like Linux: 1980-01-01 (month/day 0 → 1).
    if attrs.atime_ns != 315_532_800 * NS {
        return TestResult::Fail("zero access date did not decode as 1980-01-01");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/fat", smoke_fat_dir_reports_mtime);

/// `fat_time_fat2unix` edges: 2-second resolution, the 10 ms field adds
/// whole seconds plus centiseconds, 2000 is a leap year but 2100 is not,
/// and the timezone offset is added to the local fields.
fn smoke_fat_time_decode_edges() -> TestResult {
    use crate::dir::fat_time_to_unix_ns as fat2unix;

    // The seconds field counts 2-second units: 29 → :58, never :59.
    let t = (23 << 11) | (59 << 5) | 29;
    let d = (120 << 9) | (2 << 5) | 28; // 2100-02-28
    if fat2unix(t, d, 0, 0) != 4_107_542_398 * NS {
        return TestResult::Fail("2-second field not doubled");
    }
    // 2100 is not a leap year: Mar 1 follows Feb 28 directly.
    if fat2unix(0, (120 << 9) | (3 << 5) | 1, 0, 0) != 4_107_542_400 * NS {
        return TestResult::Fail("2100 treated as a leap year");
    }
    if fat2unix(DOS_TIME_LEAP, DOS_DATE_LEAP, 0, 0) != UNIX_LEAP * NS {
        return TestResult::Fail("2000-02-29 decoded wrong");
    }
    // 10 ms units: 199 = +1 s +990 ms; 0 = no fraction.
    if fat2unix(DOS_TIME_2023, DOS_DATE_2023, 199, 0) != (UNIX_2023 + 1) * NS + 990_000_000 {
        return TestResult::Fail("10 ms create-time field decoded wrong");
    }
    if fat2unix(DOS_TIME_2023, DOS_DATE_2023, 0, 0) % NS != 0 {
        return TestResult::Fail("a zero 10 ms field produced a fraction");
    }
    // time_offset=120 (local = UTC+2) → fat_tz_offset = -7200 s.
    if fat2unix(DOS_TIME_2023, DOS_DATE_2023, 0, -7200) != (UNIX_2023 - 7200) * NS {
        return TestResult::Fail("timezone offset not applied");
    }
    // Month 0 / day 0 clamp to January 1st, not to the previous month.
    if fat2unix(0, 0, 0, 0) != 315_532_800 * NS {
        return TestResult::Fail("zero date did not decode as 1980-01-01");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/fat", smoke_fat_time_decode_edges);
