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
    write_entry(FatVersion::Fat32, 0, 0, &mut buf, 0x01234567);
    if buf[3] & 0xF0 != 0xC0 {
        return TestResult::Fail("write_entry must preserve reserved nibble");
    }
    match parse_entry(FatVersion::Fat32, 0, 0, &buf) {
        FatEntry::Next(0x0123_4567) => {}
        _ => return TestResult::Fail("parse_entry round-trip failed"),
    }

    // EOC sentinels recognised.
    let mut eoc = [0u8; 8];
    write_entry(FatVersion::Fat32, 0, 0, &mut eoc, 0x0FFF_FFFF);
    if !matches!(
        parse_entry(FatVersion::Fat32, 0, 0, &eoc),
        FatEntry::EndOfChain
    ) {
        return TestResult::Fail("0x0FFFFFFF must decode as EndOfChain");
    }

    // Free entry sentinel.
    let zero = [0u8; 8];
    if !matches!(parse_entry(FatVersion::Fat32, 0, 0, &zero), FatEntry::Free) {
        return TestResult::Fail("zero entry must decode as Free");
    }
    TestResult::Pass
}

fn smoke_fat_entry_codec_fat12_packed() -> TestResult {
    // FATGEN §4: FAT12 packs two 12-bit entries into 3 bytes. Verify
    // the even/odd offset packing is reversible.
    let mut buf = [0u8; 6];
    write_entry(FatVersion::Fat12, 0, 0, &mut buf, 0x0ABC);
    write_entry(FatVersion::Fat12, 1, 1, &mut buf, 0x0123);

    if !matches!(
        parse_entry(FatVersion::Fat12, 0, 0, &buf),
        FatEntry::Next(0x0ABC)
    ) {
        return TestResult::Fail("FAT12 even-offset round-trip failed");
    }
    if !matches!(
        parse_entry(FatVersion::Fat12, 1, 1, &buf),
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

/// FAT12 parity is the CLUSTER's (`fs/fat/fatent.c::fat12_ent_get` tests
/// `entry & 1`), while the codec is handed an offset inside whichever FAT
/// sector the caller read. 512 is not a multiple of 3, so from the second FAT
/// sector on the two disagree: cluster 342 sits at FAT byte 513, i.e. offset 1
/// of sector 1 — an even cluster at an offset an "offset % 3" test calls odd.
/// Decoding it with the wrong nibble layout read one neighbour's bits as the
/// chain link and wrote over the other neighbour's.
fn smoke_fat_entry_codec_fat12_parity_follows_cluster() -> TestResult {
    // Sector-relative bytes 0..3 of FAT sector 1: byte 0 holds the high
    // byte of cluster 341's split entry, bytes 1..3 clusters 342 and 343.
    let mut buf = [0u8; 4];
    buf[0] = 0x5A;
    write_entry(FatVersion::Fat12, 342, 1, &mut buf, 0x0ABC);
    write_entry(FatVersion::Fat12, 343, 2, &mut buf, 0x0123);
    if buf != [0x5A, 0xBC, 0x3A, 0x12] {
        return TestResult::Fail("FAT12 entries packed by offset parity, not cluster parity");
    }
    if !matches!(
        parse_entry(FatVersion::Fat12, 342, 1, &buf),
        FatEntry::Next(0x0ABC)
    ) || !matches!(
        parse_entry(FatVersion::Fat12, 343, 2, &buf),
        FatEntry::Next(0x0123)
    ) {
        return TestResult::Fail("FAT12 decode used offset parity, not cluster parity");
    }
    // A split entry (cluster 341: FAT byte 511, the sector's last) is coded
    // from a two-byte window; an odd cluster takes the high 12 bits.
    let mut pair = [0x0Fu8, 0x00];
    write_entry(FatVersion::Fat12, 341, 0, &mut pair, 0x0DEF);
    if pair != [0xFF, 0xDE] {
        return TestResult::Fail("split odd FAT12 entry clobbered its neighbour's nibble");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/fat",
    smoke_fat_entry_codec_fat12_parity_follows_cluster
);

/// A FAT12 file long enough to be chained past cluster 340 crosses the first
/// FAT sector boundary. Cluster 341's 12 bits are FAT bytes 511..512 — the
/// last byte of sector 0 and the first of sector 1 — and every cluster after
/// it lives at a sector offset whose `% 3` no longer matches its parity.
///
/// NARF indexed byte 512 of a 512-byte sector buffer for cluster 341 and
/// panicked the kernel (`index out of bounds: the len is 512 but the index is
/// 512`): any process that wrote ~170 KiB to the musl-demo FAT root took the
/// machine down. Linux reads both blocks for a split entry
/// (`fs/fat/fatent.c::fat12_ent_bread`) and keys the nibble layout on
/// `entry & 1`.
///
/// Every cluster of the file is written with a distinct pattern and read
/// back through the chain, so a wrong link (the parity half) shows up as a
/// byte mismatch rather than only as a missing panic.
fn smoke_fat12_chain_crosses_fat_sector_boundary() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::volume::FatVolume;

    // 1 reserved + 2 FATs × 2 sectors + 1 root-dir sector + 400 data
    // clusters: well under FAT12's 4085-cluster ceiling.
    const CLUSTERS: usize = 360;
    let img = build_fat12_image_fat_sectors(406, 2, &[]);
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(FatVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    if volume.name() != "fat12" {
        return TestResult::Fail("expected FAT12 detection");
    }
    let root = volume.root();
    let file = match poll_once(root.create("BIG.BIN")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create BIG.BIN failed"),
    };
    let mut payload = alloc::vec![0u8; CLUSTERS * 512];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = ((i / 512) as u8) ^ (i as u8).rotate_left(3);
    }
    match poll_once(file.write(0, &payload)) {
        Some(Ok(n)) if n == payload.len() => {}
        _ => return TestResult::Fail("write across the FAT sector boundary failed"),
    }
    let reopened = match poll_once(root.lookup_async("BIG.BIN")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup_async BIG.BIN failed"),
    };
    let mut readback = alloc::vec![0u8; payload.len()];
    match poll_once(reopened.read(0, &mut readback)) {
        Some(Ok(n)) if n == payload.len() => {}
        _ => return TestResult::Fail("read across the FAT sector boundary failed"),
    }
    if readback != payload {
        return TestResult::Fail("cluster chain past the first FAT sector read back wrong data");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/fat",
    smoke_fat12_chain_crosses_fat_sector_boundary
);

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
    build_fat12_image_fat_sectors(total_sectors, 1, data)
}

/// [`build_fat12_image`] with a FAT of `fat_sz` sectors per copy. One FAT12
/// sector maps only 341 entries, so a volume that allocates past cluster 340
/// needs more than one — and that is where entries start to straddle.
fn build_fat12_image_fat_sectors(
    total_sectors: u32,
    fat_sz: u16,
    data: &[u8],
) -> alloc::vec::Vec<u8> {
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
    img[22..24].copy_from_slice(&fat_sz.to_le_bytes()); // fat_sz_16
    img[510] = 0x55;
    img[511] = 0xAA;

    // FAT 1 + FAT 2 — entry 0 = media, entry 1 = EOC, entry 2 =
    // EOC (single-cluster file).
    let fat_sz = fat_sz as usize;
    for lba in [1usize, 1 + fat_sz] {
        let fat = &mut img[lba * LBS..lba * LBS + LBS];
        fat12_set(fat, 0, 0xFF8);
        fat12_set(fat, 1, 0xFFF);
        if !data.is_empty() {
            fat12_set(fat, 2, 0xFFF);
        }
    }

    // Root directory entry: NARF.TXT → cluster 2, size = data.len()
    if !data.is_empty() {
        let root = 1 + 2 * fat_sz;
        let entry = &mut img[root * LBS..root * LBS + 32];
        entry[0..11].copy_from_slice(b"NARF    TXT");
        entry[11] = 0x20; // ARCHIVE
        entry[20..22].copy_from_slice(&0u16.to_le_bytes()); // fst_clus_hi
        entry[26..28].copy_from_slice(&2u16.to_le_bytes()); // fst_clus_lo
        entry[28..32].copy_from_slice(&(data.len() as u32).to_le_bytes());

        // Cluster 2 follows the root directory (rsvd 1 + fats + rootdir 1).
        let data_lba = 2 + 2 * fat_sz;
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

fn smoke_fat_truncate_grow_extends_chain_and_reads_zero() -> TestResult {
    // #692 regression: the grow branch of truncate used to publish
    // the new i_size without extending the cluster chain, so a read
    // (or mmap fault) inside the grown range walked off the end of
    // the chain and returned EIO where Linux serves zeros. Linux
    // FAT extends the chain on grow and the grown range reads as
    // zeros — including the tail of the boundary cluster past the
    // shrunk EOF, and including clusters recycled from the range the
    // shrink just freed (they still hold the pre-shrink bytes on
    // disk, so extending without zeroing would resurrect them).
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::volume::FatVolume;

    const PAGE: u64 = 4096;
    let img = build_fat12_image(256, &[]);
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(FatVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = volume.root();
    let file = match poll_once(root.create("GROW.TXT")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create GROW.TXT failed"),
    };

    // Seed 3 pages of a non-zero pattern, shrink to ~1.2 pages
    // (frees the tail clusters), then grow back to 3 pages.
    let seed = alloc::vec![0x5Au8; (3 * PAGE) as usize];
    if !matches!(poll_once(file.write(0, &seed)), Some(Ok(n)) if n == seed.len()) {
        return TestResult::Fail("seed write failed");
    }
    if !matches!(poll_once(file.truncate(PAGE + PAGE / 5)), Some(Ok(()))) {
        return TestResult::Fail("shrink truncate failed");
    }
    if !matches!(poll_once(file.truncate(3 * PAGE)), Some(Ok(()))) {
        return TestResult::Fail("grow truncate failed");
    }
    if file.stat().size != 3 * PAGE {
        return TestResult::Fail("stat.size after grow wrong");
    }

    // The surviving head (up to the shrunk EOF) is intact.
    let mut head = alloc::vec![0u8; (PAGE + PAGE / 5) as usize];
    match poll_once(file.read(0, &mut head)) {
        Some(Ok(n)) if n == head.len() => {}
        _ => return TestResult::Fail("read of surviving head failed"),
    }
    if head.iter().any(|&b| b != 0x5A) {
        return TestResult::Fail("grow damaged bytes before the shrunk EOF");
    }

    // Everything from the shrunk EOF to the regrown size reads as
    // zeros — first the boundary-cluster straddle, then the third
    // page (the range that returned EIO before the fix).
    let grown_len = (3 * PAGE - (PAGE + PAGE / 5)) as usize;
    let mut grown = alloc::vec![0xFFu8; grown_len];
    match poll_once(file.read(PAGE + PAGE / 5, &mut grown)) {
        Some(Ok(n)) if n == grown_len => {}
        _ => return TestResult::Fail("read of the grown range failed (EIO regression)"),
    }
    if grown.iter().any(|&b| b != 0) {
        return TestResult::Fail("grown range does not read as zeros");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/fat",
    smoke_fat_truncate_grow_extends_chain_and_reads_zero
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

// ── Persistent boot log ─────────────────────────────────────────────

fn smoke_fat_bootlog_policy() -> TestResult {
    use crate::bootlog::{
        candidate_allowed, log_index, marker_matches, next_log_index, parse_config, Config,
        MAX_LOGS,
    };
    if parse_config(None) != Ok(Config::Disabled)
        || parse_config(Some("off")) != Ok(Config::Disabled)
        || parse_config(Some("short")).is_ok()
        || parse_config(Some("bad token!")).is_ok()
        || parse_config(Some("rx6750xt-0123"))
            != Ok(Config::Enabled {
                token: String::from("rx6750xt-0123"),
            })
    {
        return TestResult::Fail("narf.bootlog= parsing");
    }
    // Internal disks are never candidates, only USB mass storage.
    if !candidate_allowed("usb-msc0p1")
        || !candidate_allowed("usb-msc1")
        || [
            "nvme0p1",
            "nvme0",
            "ahci0p1",
            "vblk0p1",
            "mmcblk0p1",
            "sdhci0",
        ]
        .iter()
        .any(|n| candidate_allowed(n))
    {
        return TestResult::Fail("candidate filter must admit only usb-msc*");
    }
    if !marker_matches(b"rx6750xt-0123\n", "rx6750xt-0123")
        || !marker_matches(b"  rx6750xt-0123\r\nextra", "rx6750xt-0123")
        || marker_matches(b"rx6750xt-01234\n", "rx6750xt-0123")
        || marker_matches(b"", "rx6750xt-0123")
        || marker_matches(b"x", "")
    {
        return TestResult::Fail("marker comparison");
    }
    if log_index("NARF-BOOT-12.LOG") != Some(12)
        || log_index("narf-boot-.log").is_some()
        || log_index("narf-boot-1.log.bak").is_some()
        || next_log_index(["EFI", "narf-boot-2.log", "narf-boot-9.log"]) != Some(10)
        || next_log_index([]) != Some(1)
    {
        return TestResult::Fail("log index naming");
    }
    let last = alloc::format!("narf-boot-{MAX_LOGS}.log");
    if next_log_index([last.as_str()]).is_some() {
        return TestResult::Fail("must refuse past MAX_LOGS");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/fat", smoke_fat_bootlog_policy);

/// Marker-gated arming, sequential file naming, append and the size bound,
/// end to end on a FAT12 volume in RAM.
fn smoke_fat_bootlog_session_round_trip() -> TestResult {
    use crate::bootlog::{open_session, MARKER_FILE};
    use crate::volume::FatVolume;
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    let device = RamBlockDevice::from_image(512, build_fat12_image(512, &[]));
    let Some(Ok(volume)) = poll_once(FatVolume::mount(device, DomainId::DRIVER_0)) else {
        return TestResult::Fail("mount failed");
    };
    let token = "rx6750xt-0123";
    // No marker: never written to.
    if !matches!(
        poll_once(open_session(&volume, token, 4096, b"h\n")),
        Some(Ok(None))
    ) {
        return TestResult::Fail("a volume without the marker must not arm");
    }
    let root = volume.root();
    let Some(Ok(marker)) = poll_once(root.create(MARKER_FILE)) else {
        return TestResult::Fail("create marker");
    };
    if !matches!(poll_once(marker.write(0, b"other-token-99\n")), Some(Ok(_))) {
        return TestResult::Fail("write marker");
    }
    if !matches!(
        poll_once(open_session(&volume, token, 4096, b"h\n")),
        Some(Ok(None))
    ) {
        return TestResult::Fail("a different token must not arm");
    }
    let names = |root: &alloc::sync::Arc<dyn narf_filesystem::DirOps>| -> alloc::vec::Vec<String> {
        poll_once(root.enumerate_async(0, 64))
            .and_then(Result::ok)
            .unwrap_or_default()
            .into_iter()
            .map(|(n, _)| n)
            .collect()
    };
    if names(&root).iter().any(|n| n.starts_with("narf-boot")) {
        return TestResult::Fail("a refused volume must stay untouched");
    }
    // Matching token: arm, append, then hit a 200-byte bound.
    if !matches!(poll_once(marker.truncate(0)), Some(Ok(())))
        || !matches!(poll_once(marker.write(0, b"rx6750xt-0123\n")), Some(Ok(14)))
    {
        return TestResult::Fail("rewrite marker");
    }
    let Some(Ok(Some(mut first))) = poll_once(open_session(&volume, token, 200, b"header\n"))
    else {
        return TestResult::Fail("matching marker must arm");
    };
    if first.index != 1 {
        return TestResult::Fail("first log must be narf-boot-1.log");
    }
    let line = [b'x'; 100];
    for _ in 0..3 {
        if !matches!(poll_once(first.append(&line)), Some(Ok(100))) {
            return TestResult::Fail("append");
        }
    }
    if !first.is_full() || first.len() > 200 {
        return TestResult::Fail("size bound not enforced");
    }
    let Some(Ok(file)) = poll_once(root.lookup_async("narf-boot-1.log")) else {
        return TestResult::Fail("log file missing");
    };
    let mut back = [0u8; 256];
    let Some(Ok(n)) = poll_once(file.read(0, &mut back)) else {
        return TestResult::Fail("read back");
    };
    let text = &back[..n];
    if n as u64 != first.len()
        || !text.starts_with(b"header\nxxxx")
        || !text.ends_with(b"later lines were not saved]\n")
    {
        return TestResult::Fail("log contents / truncation note");
    }
    // Next boot gets the next number.
    let Some(Ok(Some(second))) = poll_once(open_session(&volume, token, 200, b"h\n")) else {
        return TestResult::Fail("second arm");
    };
    if second.index != 2 || !names(&root).iter().any(|n| n == "narf-boot-2.log") {
        return TestResult::Fail("second boot must create narf-boot-2.log");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/fat", smoke_fat_bootlog_session_round_trip);

/// The generic mmap page cache may retain a FAT file's pages across
/// an unmap only while `mmap_cache_generation` proves the bytes have
/// not changed. FAT mints a fresh node per lookup, so the generation
/// lives in the volume, keyed by the directory entry's position:
/// every open of one file must report the same value, a mutation
/// through any open must move it for all of them, and an unrelated
/// file's generation must not move.
fn smoke_fat_mmap_cache_generation_tracks_mutations() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::volume::FatVolume;

    let img = build_fat12_image(128, b"narf\n");
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
    let g0 = match file.mmap_cache_generation() {
        Some(g) => g,
        None => return TestResult::Fail("regular file reports no cache generation"),
    };
    // A second lookup is a second node object for the same file; the
    // values must agree or cross-open invalidation cannot work.
    let reopened = match poll_once(root.lookup_async("NARF.TXT")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("second lookup failed"),
    };
    if reopened.mmap_cache_generation() != Some(g0) {
        return TestResult::Fail("two opens of one file disagree on generation");
    }
    // A write through the second open moves the first open's value.
    if poll_once(reopened.write(0, b"NARF!")).and_then(|r| r.ok()) != Some(5) {
        return TestResult::Fail("write through second open failed");
    }
    let g1 = file.mmap_cache_generation();
    if g1 == Some(g0) || reopened.mmap_cache_generation() != g1 {
        return TestResult::Fail("write through a second open did not invalidate");
    }
    // Truncate moves it again.
    if poll_once(file.truncate(2)).and_then(|r| r.ok()).is_none() {
        return TestResult::Fail("truncate failed");
    }
    let g2 = file.mmap_cache_generation();
    if g2 == g1 || g2.is_none() {
        return TestResult::Fail("truncate did not move the generation");
    }
    // An unrelated file has its own generation, unmoved by the above.
    let other = match poll_once(root.create("OTHER.TXT")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create OTHER.TXT failed"),
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
    if poll_once(root.mkdir("SUBDIR"))
        .and_then(|r| r.ok())
        .is_none()
    {
        return TestResult::Fail("mkdir failed");
    }
    let dir = match poll_once(root.lookup_async("SUBDIR")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup SUBDIR failed"),
    };
    if dir.mmap_cache_generation().is_some() {
        return TestResult::Fail("directory reports a cache generation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/fat",
    smoke_fat_mmap_cache_generation_tracks_mutations
);

/// The shared page cache keys retained pages by
/// `mmap_backing_identity`, so the identity must belong to the file,
/// not to the node an open minted (issue #679): two opens of one file
/// report the volume anchor for its directory entry, a different file
/// reports a different anchor, and the value survives the first open.
fn smoke_fat_mmap_identity_is_per_file() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::volume::FatVolume;

    let img = build_fat12_image(128, b"narf\n");
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(FatVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = volume.root();

    let first = match poll_once(root.lookup_async("NARF.TXT")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup NARF.TXT failed"),
    };
    let second = match poll_once(root.lookup_async("NARF.TXT")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("second lookup failed"),
    };
    if alloc::sync::Arc::ptr_eq(&first, &second) {
        return TestResult::Fail("expected two distinct opens of NARF.TXT");
    }
    if first.mmap_backing_identity() != second.mmap_backing_identity() {
        return TestResult::Fail("two opens of one file report different mmap identities");
    }
    let other = match poll_once(root.create("OTHER.TXT")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create OTHER.TXT failed"),
    };
    if other.mmap_backing_identity() == first.mmap_backing_identity() {
        return TestResult::Fail("two files share an mmap identity");
    }
    let identity = first.mmap_backing_identity();
    drop(first);
    if second.mmap_backing_identity() != identity {
        return TestResult::Fail("the identity changed while an open of the file was alive");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/fat", smoke_fat_mmap_identity_is_per_file);

/// Slot reuse after rename (issue #679): rename vacates a directory
/// slot without re-keying the moved file's open nodes, and a later
/// create reuses the tombstoned slot. The new tenant necessarily
/// shares the slot's identity anchor — what must separate the two
/// files is the generation: rename and create each issue a fresh
/// one, so neither the moved file's retained pages nor the still-open
/// pre-rename node's pages can validate against the new tenant (and
/// vice versa). A fresh lookup of the renamed file keys by its new
/// slot instead.
fn smoke_fat_mmap_identity_slot_reuse_after_rename() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    use narf_lib::id::DomainId;

    use crate::volume::FatVolume;

    let img = build_fat12_image(128, b"narf\n");
    let device = RamBlockDevice::from_image(512, img);
    let volume = match poll_once(FatVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = volume.root();

    let a = match poll_once(root.create("AAAA.TXT")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create AAAA.TXT failed"),
    };
    if poll_once(a.write(0, b"AAAA-DATA")).and_then(|r| r.ok()) != Some(9) {
        return TestResult::Fail("write through AAAA.TXT failed");
    }
    let id_a = a.mmap_backing_identity();
    let gen_a = match a.mmap_cache_generation() {
        Some(g) => g,
        None => return TestResult::Fail("AAAA.TXT reports no cache generation"),
    };

    if poll_once(root.rename("AAAA.TXT", "BBBB.TXT"))
        .and_then(|r| r.ok())
        .is_none()
    {
        return TestResult::Fail("rename AAAA.TXT -> BBBB.TXT failed");
    }
    // The create below must land in AAAA's tombstoned slot: the
    // directory's free-slot scan is linear, and that tombstone is the
    // earliest free slot in the fixture's root directory.
    let c = match poll_once(root.create("CCCC.TXT")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create CCCC.TXT failed"),
    };
    if c.mmap_backing_identity() != id_a {
        return TestResult::Fail("create did not reuse the renamed-away slot (test premise)");
    }
    if c.mmap_cache_generation() == Some(gen_a) {
        return TestResult::Fail(
            "new tenant of a reused slot validates against the old tenant's generation",
        );
    }
    // The still-open pre-rename node keeps the old slot's identity,
    // but rename moved that slot's generation: its retained pages
    // are retired too, not silently carried to the new tenant.
    if a.mmap_cache_generation() == Some(gen_a) {
        return TestResult::Fail("rename did not invalidate the moved file's retained pages");
    }
    // A fresh lookup of the renamed file keys by its new slot.
    let b = match poll_once(root.lookup_async("BBBB.TXT")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup BBBB.TXT failed"),
    };
    if b.mmap_backing_identity() == id_a {
        return TestResult::Fail("renamed file kept its old slot identity on fresh lookup");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/fat",
    smoke_fat_mmap_identity_slot_reuse_after_rename
);
