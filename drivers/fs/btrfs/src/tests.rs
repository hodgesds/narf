//! btrfs driver kernel tests.
//!
//! Pure-logic tests (checksum, on-disk decoders) run without any block device;
//! end-to-end mount tests (added in later phases) drive a `RamBlockDevice` built
//! from a committed `mkfs.btrfs` fixture.

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_filesystem::FsError;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::id::DomainId;

use crate::btree;
use crate::checksum;
use crate::chunk::ChunkMap;
use crate::format::{self, BtrfsKey, Superblock};
use crate::volume::BtrfsVolume;

// ── Shared test harness ────────────────────────────────────────────

/// Primary fixture in the compact `NARFBTR1` sparse encoding produced by
/// `testdata/regen_fixture.sh` (a mixed-mode, CRC32C, single-device
/// `mkfs.btrfs` image with hello.txt / big.dat / subdir/note.txt).
const FIXTURE_SPARSE: &[u8] = include_bytes!("../testdata/fixture.img.sparse");

/// Same layout with 8 KiB data sectors and metadata nodes.
const FIXTURE_SECTOR8K_SPARSE: &[u8] = include_bytes!("../testdata/fixture-sector8k.img.sparse");

/// Genuine quota-enabled image with qgroup 0/5 assigned to parent 1/100.
const FIXTURE_QUOTA_SPARSE: &[u8] = include_bytes!("../testdata/fixture-quota.img.sparse");

/// Linux-created simple-quota image with post-enable owned extents and 0/5
/// assigned to parent 1/200.
const FIXTURE_SQUOTA_SPARSE: &[u8] = include_bytes!("../testdata/fixture-squota.img.sparse");

/// Same tree as the primary fixture but written with `--compress zlib`, so
/// `big.dat` is a zlib-compressed regular extent.
const FIXTURE_ZLIB_SPARSE: &[u8] = include_bytes!("../testdata/fixture-zlib.img.sparse");

/// Same tree written with `--compress zstd`.
const FIXTURE_ZSTD_SPARSE: &[u8] = include_bytes!("../testdata/fixture-zstd.img.sparse");

/// Same tree written with `--compress lzo`.
const FIXTURE_LZO_SPARSE: &[u8] = include_bytes!("../testdata/fixture-lzo.img.sparse");

/// Same tree written with each non-default btrfs checksum algorithm.
const FIXTURE_XXHASH_SPARSE: &[u8] = include_bytes!("../testdata/fixture-xxhash.img.sparse");
const FIXTURE_SHA256_SPARSE: &[u8] = include_bytes!("../testdata/fixture-sha256.img.sparse");
const FIXTURE_BLAKE2_SPARSE: &[u8] = include_bytes!("../testdata/fixture-blake2.img.sparse");

/// A normal directory containing a subvolume which itself contains a subvolume.
const FIXTURE_NESTEDSUBVOL_SPARSE: &[u8] =
    include_bytes!("../testdata/fixture-nestedsubvol.img.sparse");

/// 400 small files, forcing the FS b-tree to more than one level.
const FIXTURE_MANYFILES_SPARSE: &[u8] = include_bytes!("../testdata/fixture-manyfiles.img.sparse");

/// The on-disk default subvolume is `def` (not FS_TREE).
const FIXTURE_DEFAULTSUBVOL_SPARSE: &[u8] =
    include_bytes!("../testdata/fixture-defaultsubvol.img.sparse");

/// A realistic laptop-distro image: 128 MiB, non-mixed, nodesize 16384, zstd,
/// btrfs-progs default features (free-space-tree, no-holes, extref, skinny/big
/// metadata), with `root` (default) + `home` subvolumes.
const FIXTURE_LAPTOP_SPARSE: &[u8] = include_bytes!("../testdata/fixture-laptop.img.sparse");

/// Same small mixed layout as the primary fixture but WITH a free-space tree
/// (`space_cache=v2`); exercises the write path's free-space-tree maintenance.
const FIXTURE_FST_SPARSE: &[u8] = include_bytes!("../testdata/fixture-fst.img.sparse");

/// A 96 MiB mixed + free-space-tree image, large enough that mkfs wrote a second
/// superblock copy (the 64 MiB mirror); exercises writing all mirrors in lockstep.
const FIXTURE_MIRROR_SPARSE: &[u8] = include_bytes!("../testdata/fixture-mirror.img.sparse");

/// Like the mirror fixture but with one data block group fragmented so its free
/// space is a `FREE_SPACE_BITMAP` (not extent items); exercises the bitmap path.
const FIXTURE_BITMAP_SPARSE: &[u8] = include_bytes!("../testdata/fixture-bitmap.img.sparse");

/// Reconstruct the full zero-filled image from the sparse encoding.
fn decode_sparse(sparse: &[u8]) -> Vec<u8> {
    assert!(
        sparse.len() >= 20 && &sparse[0..8] == b"NARFBTR1",
        "bad fixture magic"
    );
    let total = u64::from_le_bytes(sparse[8..16].try_into().unwrap()) as usize;
    let n_runs = u32::from_le_bytes(sparse[16..20].try_into().unwrap()) as usize;
    let mut img = alloc::vec![0u8; total];
    let mut p = 20usize;
    for _ in 0..n_runs {
        let off = u64::from_le_bytes(sparse[p..p + 8].try_into().unwrap()) as usize;
        let len = u64::from_le_bytes(sparse[p + 8..p + 16].try_into().unwrap()) as usize;
        p += 16;
        img[off..off + len].copy_from_slice(&sparse[p..p + len]);
        p += len;
    }
    img
}

/// Poll a future that completes synchronously on `RamBlockDevice` (its `submit`
/// returns `Ready` after an in-memory copy), returning its output or `None`.
fn poll_once<F: core::future::Future>(mut future: F) -> Option<F::Output> {
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    fn raw_waker() -> RawWaker {
        unsafe fn clone(_: *const ()) -> RawWaker {
            raw_waker()
        }
        unsafe fn no_op(_: *const ()) {}
        const VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
        RawWaker::new(core::ptr::null(), &VTABLE)
    }

    // SAFETY: the no-op vtable never dereferences the null data pointer.
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut context = Context::from_waker(&waker);
    // SAFETY: `future` stays at this stack slot until dropped.
    let pinned = unsafe { Pin::new_unchecked(&mut future) };
    match pinned.poll(&mut context) {
        Poll::Ready(value) => Some(value),
        Poll::Pending => None,
    }
}

/// Mount a `NARFBTR1` sparse image on a fresh `RamBlockDevice` (512-byte LBAs).
fn mount_sparse(
    sparse: &[u8],
) -> Result<Arc<BtrfsVolume<narf_block::ram::RamBlockDevice>>, FsError> {
    use narf_block::ram::RamBlockDevice;
    let device = RamBlockDevice::from_image(512, decode_sparse(sparse));
    poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)).ok_or(FsError::InvalidData)?
}

/// Mount the primary (uncompressed) fixture.
fn mount_fixture() -> Result<Arc<BtrfsVolume<narf_block::ram::RamBlockDevice>>, FsError> {
    mount_sparse(FIXTURE_SPARSE)
}

/// Parse a `NARFBTR1` sparse image into `(total_size, runs)` WITHOUT
/// reconstructing the full (potentially large) image.
fn decode_sparse_runs(sparse: &[u8]) -> (u64, Vec<(u64, Vec<u8>)>) {
    assert!(
        sparse.len() >= 20 && &sparse[0..8] == b"NARFBTR1",
        "bad fixture magic"
    );
    let total = u64::from_le_bytes(sparse[8..16].try_into().unwrap());
    let n_runs = u32::from_le_bytes(sparse[16..20].try_into().unwrap()) as usize;
    let mut runs = Vec::with_capacity(n_runs);
    let mut p = 20usize;
    for _ in 0..n_runs {
        let off = u64::from_le_bytes(sparse[p..p + 8].try_into().unwrap());
        let len = u64::from_le_bytes(sparse[p + 8..p + 16].try_into().unwrap()) as usize;
        p += 16;
        runs.push((off, sparse[p..p + len].to_vec()));
        p += len;
    }
    (total, runs)
}

/// A read-only `BlockDeviceSync` presenting a large logical capacity while
/// storing only the non-zero runs of a sparse image (holes read as zeros). Lets
/// a 128 MiB laptop image be mounted in-kernel without a 128 MiB allocation.
#[derive(Debug)]
struct SparseImageDevice {
    runs: Vec<(u64, Vec<u8>)>,
    total: u64,
    lba_size: u32,
}

impl narf_block::BlockDeviceSync for SparseImageDevice {
    fn lba_size(&self) -> u32 {
        self.lba_size
    }
    fn capacity(&self) -> u64 {
        self.total / u64::from(self.lba_size)
    }
    fn read(
        &self,
        lba: u64,
        n_blocks: u16,
        out: &mut [u8],
    ) -> Result<(), narf_block::BlockIoError> {
        let start = lba * u64::from(self.lba_size);
        let len = u64::from(n_blocks) * u64::from(self.lba_size);
        if start + len > self.total {
            return Err(narf_block::BlockIoError::DriverError);
        }
        let n = out.len().min(len as usize);
        out[..n].fill(0);
        // Overlay any runs covering [start, start+n).
        for (roff, rbytes) in &self.runs {
            let rend = roff + rbytes.len() as u64;
            let ov_start = start.max(*roff);
            let ov_end = (start + n as u64).min(rend);
            if ov_start < ov_end {
                let dst = (ov_start - start) as usize;
                let src = (ov_start - roff) as usize;
                let cnt = (ov_end - ov_start) as usize;
                out[dst..dst + cnt].copy_from_slice(&rbytes[src..src + cnt]);
            }
        }
        Ok(())
    }
    fn write(&self, _lba: u64, _n: u16, _data: &[u8]) -> Result<(), narf_block::BlockIoError> {
        Err(narf_block::BlockIoError::DriverError)
    }
}

/// Mount a sparse image through the `SyncBlock` adapter (sparse-backed, so a
/// large logical image costs only its non-zero payload in RAM).
fn mount_sparse_device(sparse: &[u8]) -> Result<Arc<BtrfsVolume<narf_block::SyncBlock>>, FsError> {
    let (total, runs) = decode_sparse_runs(sparse);
    let dev: Arc<dyn narf_block::BlockDeviceSync> = Arc::new(SparseImageDevice {
        runs,
        total,
        lba_size: 512,
    });
    let async_dev = narf_block::SyncBlock::new(dev);
    poll_once(BtrfsVolume::mount(async_dev, DomainId::DRIVER_0)).ok_or(FsError::InvalidData)?
}

/// A *writable* sparse-backed device: a large logical capacity whose non-zero
/// base runs read as the fixture, with an in-memory per-LBA write overlay. Lets a
/// ≥64 MiB image be mounted read-write in-kernel without a full-size allocation
/// (only the fixture payload plus written blocks cost RAM). Shared via `Arc`, so
/// a remount over the same device observes prior writes.
#[derive(Debug)]
struct WritableSparseDevice {
    runs: Vec<(u64, Vec<u8>)>,
    total: u64,
    lba_size: u32,
    overlay: narf_lib::sync::IrqSafeSpinLock<alloc::collections::BTreeMap<u64, Vec<u8>>>,
}

impl narf_block::BlockDeviceSync for WritableSparseDevice {
    fn lba_size(&self) -> u32 {
        self.lba_size
    }
    fn capacity(&self) -> u64 {
        self.total / u64::from(self.lba_size)
    }
    fn read(
        &self,
        lba: u64,
        n_blocks: u16,
        out: &mut [u8],
    ) -> Result<(), narf_block::BlockIoError> {
        let bs = u64::from(self.lba_size);
        let start = lba * bs;
        let len = u64::from(n_blocks) * bs;
        if start + len > self.total {
            return Err(narf_block::BlockIoError::OutOfRange);
        }
        let n = out.len().min(len as usize);
        out[..n].fill(0);
        // Base image runs first…
        for (roff, rbytes) in &self.runs {
            let rend = roff + rbytes.len() as u64;
            let ov_start = start.max(*roff);
            let ov_end = (start + n as u64).min(rend);
            if ov_start < ov_end {
                let dst = (ov_start - start) as usize;
                let src = (ov_start - roff) as usize;
                let cnt = (ov_end - ov_start) as usize;
                out[dst..dst + cnt].copy_from_slice(&rbytes[src..src + cnt]);
            }
        }
        // …then any written blocks on top.
        let overlay = self.overlay.lock();
        for i in 0..n_blocks as u64 {
            if let Some(block) = overlay.get(&(lba + i)) {
                let dst = (i * bs) as usize;
                out[dst..dst + self.lba_size as usize].copy_from_slice(block);
            }
        }
        Ok(())
    }
    fn write(&self, lba: u64, n: u16, data: &[u8]) -> Result<(), narf_block::BlockIoError> {
        let bs = self.lba_size as usize;
        if data.len() < n as usize * bs {
            return Err(narf_block::BlockIoError::BufferTooSmall);
        }
        if (lba + u64::from(n)) * u64::from(self.lba_size) > self.total {
            return Err(narf_block::BlockIoError::OutOfRange);
        }
        let mut overlay = self.overlay.lock();
        for i in 0..n as usize {
            overlay.insert(lba + i as u64, data[i * bs..(i + 1) * bs].to_vec());
        }
        Ok(())
    }
}

/// Build a writable sparse-backed device from a `NARFBTR1` fixture (shared `Arc`).
fn writable_sparse(sparse: &[u8]) -> Arc<WritableSparseDevice> {
    let (total, runs) = decode_sparse_runs(sparse);
    Arc::new(WritableSparseDevice {
        runs,
        total,
        lba_size: 512,
        overlay: narf_lib::sync::IrqSafeSpinLock::new(alloc::collections::BTreeMap::new()),
    })
}

/// Mount a writable sparse-backed device (fresh `SyncBlock` over `dev`).
fn mount_writable(
    dev: Arc<WritableSparseDevice>,
) -> Result<Arc<BtrfsVolume<narf_block::SyncBlock>>, FsError> {
    let async_dev = narf_block::SyncBlock::new(dev as Arc<dyn narf_block::BlockDeviceSync>);
    poll_once(BtrfsVolume::mount(async_dev, DomainId::DRIVER_0)).ok_or(FsError::InvalidData)?
}

// ── Phase 0: checksum ──────────────────────────────────────────────

/// CRC32C check value. The canonical Castagnoli check for the ASCII string
/// "123456789" (init `~0`, final XOR `~0`) is `0xE306_9283`. `block_csum`
/// implements exactly that form, so it must reproduce the constant — proof the
/// polynomial and bit-reflection are correct before lookups/checksums depend on
/// it.
fn smoke_btrfs_crc32c_known_vector() -> TestResult {
    let got = checksum::block_csum(b"123456789");
    if got != 0xE306_9283 {
        return TestResult::Fail("crc32c block_csum check value mismatch");
    }
    // Empty input: standard CRC32C of "" is 0.
    if checksum::block_csum(b"") != 0 {
        return TestResult::Fail("crc32c of empty input must be 0");
    }
    // The raw primitive must differ from the inverted block form for non-empty
    // input, guarding against an accidental identity implementation.
    if checksum::crc32c(0, b"narf") == checksum::block_csum(b"narf") {
        return TestResult::Fail("raw crc32c must differ from inverted block_csum");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_crc32c_known_vector);

/// Known vectors for the three alternate algorithms, including xxhash64's
/// little-endian on-disk encoding and BLAKE2b's 32-byte output parameter.
fn smoke_btrfs_alternate_checksum_known_vectors() -> TestResult {
    let xxhash = match checksum::digest(format::CSUM_TYPE_XXHASH, b"") {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("xxhash64 digest failed"),
    };
    if xxhash[..8] != [0x99, 0xe9, 0xd8, 0x51, 0x37, 0xdb, 0x46, 0xef] {
        return TestResult::Fail("xxhash64 known vector mismatch");
    }

    let sha256 = match checksum::digest(format::CSUM_TYPE_SHA256, b"abc") {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("sha256 digest failed"),
    };
    if sha256
        != [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ]
    {
        return TestResult::Fail("sha256 known vector mismatch");
    }

    let blake2 = match checksum::digest(format::CSUM_TYPE_BLAKE2, b"abc") {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("blake2b-256 digest failed"),
    };
    if blake2
        != [
            0xbd, 0xdd, 0x81, 0x3c, 0x63, 0x42, 0x39, 0x72, 0x31, 0x71, 0xef, 0x3f, 0xee, 0x98,
            0x57, 0x9b, 0x94, 0x96, 0x4e, 0x3b, 0xb1, 0xcb, 0x3e, 0x42, 0x72, 0x62, 0xc8, 0xc0,
            0x68, 0xd5, 0x23, 0x19,
        ]
    {
        return TestResult::Fail("blake2b-256 known vector mismatch");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_alternate_checksum_known_vectors
);

// ── Phase 0: superblock decode ─────────────────────────────────────

/// Assemble a minimal but structurally valid 4096-byte superblock image.
fn build_superblock(magic: u64, csum_type: u16, num_devices: u64) -> alloc::vec::Vec<u8> {
    let mut sb = alloc::vec![0u8; format::SUPERBLOCK_SIZE];
    let put64 =
        |sb: &mut [u8], off: usize, v: u64| sb[off..off + 8].copy_from_slice(&v.to_le_bytes());
    let put32 =
        |sb: &mut [u8], off: usize, v: u32| sb[off..off + 4].copy_from_slice(&v.to_le_bytes());
    let put16 =
        |sb: &mut [u8], off: usize, v: u16| sb[off..off + 2].copy_from_slice(&v.to_le_bytes());

    put64(&mut sb, 64, magic); // magic
    put64(&mut sb, 72, 7); // generation
    put64(&mut sb, 80, 0x100_0000); // root (root-tree logical)
    put64(&mut sb, 88, 0x200_0000); // chunk_root
    put64(&mut sb, 112, 64 << 20); // total_bytes
    put64(&mut sb, 120, 1 << 20); // bytes_used
    put64(&mut sb, 136, num_devices); // num_devices
    put32(&mut sb, 144, 4096); // sectorsize
    put32(&mut sb, 148, 16384); // nodesize
    put32(&mut sb, 160, 0); // sys_chunk_array_size
    put16(&mut sb, 196, csum_type); // csum_type
    sb[198] = 0; // root_level
    sb[199] = 1; // chunk_root_level
    sb
}

fn smoke_btrfs_superblock_decode() -> TestResult {
    let good = build_superblock(format::BTRFS_MAGIC, format::CSUM_TYPE_CRC32, 1);
    let sb = match Superblock::decode(&good) {
        Ok(sb) => sb,
        Err(_) => return TestResult::Fail("valid superblock failed to decode"),
    };
    if sb.root != 0x100_0000 || sb.chunk_root != 0x200_0000 {
        return TestResult::Fail("root/chunk_root decoded wrong");
    }
    if sb.sectorsize != 4096 || sb.nodesize != 16384 || sb.chunk_root_level != 1 {
        return TestResult::Fail("geometry fields decoded wrong");
    }

    let mut sector8k = good.clone();
    sector8k[144..148].copy_from_slice(&8192u32.to_le_bytes());
    sector8k[148..152].copy_from_slice(&8192u32.to_le_bytes());
    if Superblock::decode(&sector8k).is_err() {
        return TestResult::Fail("8K sectors/nodes must be accepted");
    }
    for bad_sector in [2048u32, 12288, 131072] {
        let mut bad = good.clone();
        bad[144..148].copy_from_slice(&bad_sector.to_le_bytes());
        bad[148..152].copy_from_slice(&bad_sector.to_le_bytes());
        if !matches!(Superblock::decode(&bad), Err(FsError::Unsupported)) {
            return TestResult::Fail("invalid sector geometry must be Unsupported");
        }
    }

    // Bad magic → InvalidData.
    let bad_magic = build_superblock(0xDEAD_BEEF, format::CSUM_TYPE_CRC32, 1);
    if Superblock::decode(&bad_magic).is_ok() {
        return TestResult::Fail("bad magic must be rejected");
    }

    // Every kernel-defined checksum type is accepted; unknown values are not.
    for csum_type in [
        format::CSUM_TYPE_XXHASH,
        format::CSUM_TYPE_SHA256,
        format::CSUM_TYPE_BLAKE2,
    ] {
        let alternate = build_superblock(format::BTRFS_MAGIC, csum_type, 1);
        if Superblock::decode(&alternate).is_err() {
            return TestResult::Fail("supported alternate csum_type was rejected");
        }
    }
    let unknown = build_superblock(format::BTRFS_MAGIC, 4, 1);
    if !matches!(Superblock::decode(&unknown), Err(FsError::Unsupported)) {
        return TestResult::Fail("unknown csum_type must be Unsupported");
    }

    // Multi-device → Unsupported.
    let multidev = build_superblock(format::BTRFS_MAGIC, format::CSUM_TYPE_CRC32, 2);
    if !matches!(
        Superblock::decode(&multidev),
        Err(narf_filesystem::FsError::Unsupported)
    ) {
        return TestResult::Fail("num_devices != 1 must be Unsupported");
    }

    // Features that change tree or allocation semantics must be rejected at
    // mount/decode, rather than failing later after metadata has been touched.
    let mut raid56 = good.clone();
    raid56[188..196].copy_from_slice(&(1u64 << 7).to_le_bytes());
    if !matches!(Superblock::decode(&raid56), Err(FsError::Unsupported)) {
        return TestResult::Fail("RAID56 incompat feature must be Unsupported");
    }
    let mut unknown_incompat = good.clone();
    unknown_incompat[188..196].copy_from_slice(&(1u64 << 63).to_le_bytes());
    if !matches!(
        Superblock::decode(&unknown_incompat),
        Err(FsError::Unsupported)
    ) {
        return TestResult::Fail("unknown incompat feature must be Unsupported");
    }
    let mut verity = good.clone();
    verity[180..188].copy_from_slice(&(1u64 << 2).to_le_bytes());
    if !matches!(Superblock::decode(&verity), Err(FsError::Unsupported)) {
        return TestResult::Fail("unsupported compat-ro feature must be Unsupported");
    }

    let mut supported = good;
    supported[180..188].copy_from_slice(&format::SUPPORTED_COMPAT_RO_FLAGS.to_le_bytes());
    supported[188..196].copy_from_slice(&format::SUPPORTED_INCOMPAT_FLAGS.to_le_bytes());
    if Superblock::decode(&supported).is_err() {
        return TestResult::Fail("supported feature masks were rejected");
    }

    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_superblock_decode);

// ── Phase 1: chunk map ─────────────────────────────────────────────

/// Build a `sys_chunk_array` record: a 17-byte disk key (CHUNK_ITEM at
/// `logical`) followed by a `btrfs_chunk` with one SINGLE or DUP stripe.
fn build_sys_chunk(
    logical: u64,
    length: u64,
    physical: u64,
    chunk_type: u64,
    num_stripes: u16,
) -> Vec<u8> {
    let mut rec = Vec::new();
    // disk_key: objectid=FIRST_CHUNK_TREE(256), type=CHUNK_ITEM, offset=logical
    rec.extend_from_slice(&256u64.to_le_bytes());
    rec.push(format::CHUNK_ITEM_KEY);
    rec.extend_from_slice(&logical.to_le_bytes());
    // btrfs_chunk header (48 bytes)
    rec.extend_from_slice(&length.to_le_bytes()); // length
    rec.extend_from_slice(&3u64.to_le_bytes()); // owner (chunk tree)
    rec.extend_from_slice(&65536u64.to_le_bytes()); // stripe_len
    rec.extend_from_slice(&chunk_type.to_le_bytes()); // type
    rec.extend_from_slice(&4096u32.to_le_bytes()); // io_align
    rec.extend_from_slice(&4096u32.to_le_bytes()); // io_width
    rec.extend_from_slice(&4096u32.to_le_bytes()); // sector_size
    rec.extend_from_slice(&num_stripes.to_le_bytes()); // num_stripes
    rec.extend_from_slice(&0u16.to_le_bytes()); // sub_stripes
                                                // stripes
    for s in 0..num_stripes {
        rec.extend_from_slice(&1u64.to_le_bytes()); // devid
        rec.extend_from_slice(&(physical + u64::from(s) * length).to_le_bytes()); // offset
        rec.extend_from_slice(&[0u8; 16]); // dev_uuid
    }
    rec
}

fn smoke_btrfs_sys_chunk_array_parse() -> TestResult {
    // A single SINGLE chunk mapping logical 1 MiB → physical 5 MiB, len 1 MiB.
    let sys = build_sys_chunk(
        0x10_0000,
        0x10_0000,
        0x50_0000,
        format::BLOCK_GROUP_SYSTEM,
        1,
    );
    let map = match ChunkMap::seed_from_sys_array(&sys) {
        Ok(m) => m,
        Err(_) => return TestResult::Fail("SINGLE sys chunk failed to parse"),
    };
    // Start, middle, and just-inside-end map linearly.
    match (
        map.map_logical(0x10_0000),
        map.map_logical(0x10_0000 + 0x1000),
    ) {
        (Ok(0x50_0000), Ok(p)) if p == 0x50_0000 + 0x1000 => {}
        _ => return TestResult::Fail("SINGLE chunk mapped wrong physical offset"),
    }
    // Below and above the range are unmapped.
    if map.map_logical(0).is_ok() || map.map_logical(0x20_0000).is_ok() {
        return TestResult::Fail("out-of-range logical must be NotFound");
    }

    // DUP (2 stripes, same device) preserves both physical copies.
    let dup = build_sys_chunk(0, 0x10_0000, 0x80_0000, format::BLOCK_GROUP_DUP, 2);
    let dup_map = match ChunkMap::seed_from_sys_array(&dup) {
        Ok(map) => map,
        Err(_) => return TestResult::Fail("DUP chunk failed to parse"),
    };
    if dup_map.map_logical_copies(0x1000) != Ok((0x80_1000, Some(0x90_1000))) {
        return TestResult::Fail("DUP chunk did not preserve both stripes");
    }

    // Profile/stripe-count mismatches are corrupt, not silently truncated.
    let bad_single = build_sys_chunk(0, 0x10_0000, 0x80_0000, 0, 2);
    if !matches!(
        ChunkMap::seed_from_sys_array(&bad_single),
        Err(FsError::InvalidData)
    ) {
        return TestResult::Fail("two-stripe SINGLE chunk must be InvalidData");
    }

    // A RAID1 profile is rejected.
    let raid1 = build_sys_chunk(0, 0x10_0000, 0x80_0000, 1 << 4, 2);
    if !matches!(
        ChunkMap::seed_from_sys_array(&raid1),
        Err(FsError::Unsupported)
    ) {
        return TestResult::Fail("RAID1 chunk must be Unsupported");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_sys_chunk_array_parse);

fn smoke_btrfs_mount_reads_superblock() -> TestResult {
    let vol = match mount_fixture() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fixture failed to mount"),
    };
    if vol.magic() != format::BTRFS_MAGIC {
        return TestResult::Fail("mounted superblock magic wrong");
    }
    if vol.sectorsize() != 4096 || vol.nodesize() != 4096 {
        return TestResult::Fail("fixture geometry unexpected");
    }
    // The chunk map must be populated and cover the chunk-tree root.
    if vol.chunk_map_len() == 0 {
        return TestResult::Fail("chunk map empty after mount");
    }
    if vol.map_logical(vol.superblock().chunk_root).is_err() {
        return TestResult::Fail("chunk_root not mappable");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_mount_reads_superblock);

// ── Phase 2: B-tree decoders ───────────────────────────────────────

const HEADER_SIZE: usize = btree::HEADER_SIZE;

/// Build a leaf node (level 0) holding `items` (which must be key-sorted).
/// Item bodies are packed from the end of the node, as on disk.
fn build_leaf(items: &[(BtrfsKey, &[u8])]) -> Vec<u8> {
    let nodesize = 4096usize;
    let mut buf = alloc::vec![0u8; nodesize];
    buf[96..100].copy_from_slice(&(items.len() as u32).to_le_bytes());
    buf[100] = 0; // level = leaf
    let mut data_end = nodesize;
    for (i, (key, data)) in items.iter().enumerate() {
        let ioff = HEADER_SIZE + i * 25;
        buf[ioff..ioff + 8].copy_from_slice(&key.objectid.to_le_bytes());
        buf[ioff + 8] = key.item_type;
        buf[ioff + 9..ioff + 17].copy_from_slice(&key.offset.to_le_bytes());
        let data_start = data_end - data.len();
        let rel = data_start - HEADER_SIZE;
        buf[ioff + 17..ioff + 21].copy_from_slice(&(rel as u32).to_le_bytes());
        buf[ioff + 21..ioff + 25].copy_from_slice(&(data.len() as u32).to_le_bytes());
        buf[data_start..data_end].copy_from_slice(data);
        data_end = data_start;
    }
    buf
}

/// Build an internal node (level `lvl`) with `(key, blockptr)` pairs.
fn build_internal(lvl: u8, ptrs: &[(BtrfsKey, u64)]) -> Vec<u8> {
    let nodesize = 4096usize;
    let mut buf = alloc::vec![0u8; nodesize];
    buf[96..100].copy_from_slice(&(ptrs.len() as u32).to_le_bytes());
    buf[100] = lvl;
    for (i, (key, blockptr)) in ptrs.iter().enumerate() {
        let off = HEADER_SIZE + i * 33;
        buf[off..off + 8].copy_from_slice(&key.objectid.to_le_bytes());
        buf[off + 8] = key.item_type;
        buf[off + 9..off + 17].copy_from_slice(&key.offset.to_le_bytes());
        buf[off + 17..off + 25].copy_from_slice(&blockptr.to_le_bytes());
        buf[off + 25..off + 33].copy_from_slice(&7u64.to_le_bytes()); // generation
    }
    buf
}

fn smoke_btrfs_node_header_decode() -> TestResult {
    let leaf = build_leaf(&[(BtrfsKey::new(1, format::INODE_ITEM_KEY, 0), b"abc")]);
    let node = build_internal(2, &[(BtrfsKey::new(1, 1, 0), 0x1000)]);
    match (btree::level(&leaf), btree::level(&node)) {
        (Ok(0), Ok(2)) => {}
        _ => return TestResult::Fail("level decode wrong"),
    }
    if btree::nritems(&leaf).ok() != Some(1) || btree::nritems(&node).ok() != Some(1) {
        return TestResult::Fail("nritems decode wrong");
    }
    // Leaf item body round-trips.
    match btree::leaf_item_data(&leaf, 0) {
        Ok(b"abc") => {}
        _ => return TestResult::Fail("leaf item data decode wrong"),
    }
    if btree::internal_blockptr(&node, 0).ok() != Some(0x1000) {
        return TestResult::Fail("internal blockptr decode wrong");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_node_header_decode);

fn smoke_btrfs_leaf_key_search() -> TestResult {
    let k0 = BtrfsKey::new(1, format::INODE_ITEM_KEY, 0);
    let k1 = BtrfsKey::new(1, format::DIR_ITEM_KEY, 100);
    let k2 = BtrfsKey::new(1, format::DIR_ITEM_KEY, 500);
    let leaf = build_leaf(&[(k0, b"i"), (k1, b"d1"), (k2, b"d2")]);

    // Exact keys resolve to their own slot.
    for (want, key) in [(0usize, k0), (1, k1), (2, k2)] {
        if btree::leaf_lower_bound(&leaf, 3, &key).ok() != Some(want) {
            return TestResult::Fail("lower_bound of exact key wrong");
        }
    }
    // A key between k1 and k2 lands on k2's slot.
    let between = BtrfsKey::new(1, format::DIR_ITEM_KEY, 300);
    if btree::leaf_lower_bound(&leaf, 3, &between).ok() != Some(2) {
        return TestResult::Fail("lower_bound of gap key wrong");
    }
    // A key past the end lands at n.
    let past = BtrfsKey::new(2, 0, 0);
    if btree::leaf_lower_bound(&leaf, 3, &past).ok() != Some(3) {
        return TestResult::Fail("lower_bound past end wrong");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_leaf_key_search);

fn smoke_btrfs_internal_child_slot() -> TestResult {
    // Three children keyed at objectid 10, 20, 30.
    let node = build_internal(
        1,
        &[
            (BtrfsKey::new(10, 0, 0), 0xA000),
            (BtrfsKey::new(20, 0, 0), 0xB000),
            (BtrfsKey::new(30, 0, 0), 0xC000),
        ],
    );
    // Target below the first key clamps to slot 0.
    if btree::internal_child_slot(&node, 3, &BtrfsKey::new(5, 0, 0)).ok() != Some(0) {
        return TestResult::Fail("child_slot below first key should clamp to 0");
    }
    // Exact and in-between targets pick the covering child.
    if btree::internal_child_slot(&node, 3, &BtrfsKey::new(20, 0, 0)).ok() != Some(1) {
        return TestResult::Fail("child_slot of exact middle key wrong");
    }
    if btree::internal_child_slot(&node, 3, &BtrfsKey::new(25, 0, 0)).ok() != Some(1) {
        return TestResult::Fail("child_slot between keys should pick lower child");
    }
    if btree::internal_child_slot(&node, 3, &BtrfsKey::new(99, 0, 0)).ok() != Some(2) {
        return TestResult::Fail("child_slot past last key should pick last child");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_internal_child_slot);

// ── Phase 3: root tree + fs tree ───────────────────────────────────

fn smoke_btrfs_root_tree_finds_fs_tree() -> TestResult {
    let vol = match mount_fixture() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fixture failed to mount"),
    };
    // The completed chunk map must contain more than the system-chunk seed.
    if vol.chunk_map_len() < 2 {
        return TestResult::Fail("chunk map not completed by chunk-tree walk");
    }
    let (fs_root, _fs_level) = vol.fs_tree_root();
    if fs_root == 0 {
        return TestResult::Fail("FS_TREE root not located");
    }
    // The fs-tree root must be readable and contain the root directory inode
    // (256, INODE_ITEM, 0) — proves the full chunk-map + b-tree read path.
    let root_inode_key = BtrfsKey::new(format::FIRST_FREE_OBJECTID, format::INODE_ITEM_KEY, 0);
    match poll_once(btree::find_item(&*vol, fs_root, &root_inode_key)) {
        Some(Ok(Some(_))) => TestResult::Pass,
        _ => TestResult::Fail("root directory INODE_ITEM not found in fs tree"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_root_tree_finds_fs_tree);

// ── Phase 4: FsInstance + DirOps ───────────────────────────────────

/// Expected byte content of the fixture's `big.dat` (2000 × "L%04d\n").
fn expected_big() -> Vec<u8> {
    let mut v = Vec::with_capacity(12000);
    for i in 0..2000u32 {
        v.extend_from_slice(alloc::format!("L{:04}\n", i).as_bytes());
    }
    v
}

fn smoke_btrfs_mount_and_ls() -> TestResult {
    use narf_filesystem::FsInstance;
    let vol = match mount_fixture() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fixture failed to mount"),
    };
    if vol.name() != "btrfs" {
        return TestResult::Fail("fs name mismatch");
    }
    let root = vol.root();
    let entries = match poll_once(root.enumerate_async(0, 64)) {
        Some(Ok(e)) => e,
        _ => return TestResult::Fail("root enumerate failed"),
    };
    let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    for want in ["hello.txt", "big.dat", "subdir"] {
        if !names.contains(&want) {
            return TestResult::Fail("root listing missing an expected entry");
        }
    }
    // `subdir` enumerates as a directory and contains note.txt.
    let sub = match poll_once(root.lookup_dir_async("subdir")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("lookup_dir_async(subdir) failed"),
    };
    let sub_entries = match poll_once(sub.enumerate_async(0, 64)) {
        Some(Ok(e)) => e,
        _ => return TestResult::Fail("subdir enumerate failed"),
    };
    if !sub_entries.iter().any(|(n, _)| n == "note.txt") {
        return TestResult::Fail("subdir missing note.txt");
    }
    // Looking a directory up as a file, or a missing name, both fail cleanly.
    if poll_once(root.lookup_dir_async("does-not-exist"))
        .map(|r| r.is_ok())
        .unwrap_or(true)
    {
        return TestResult::Fail("missing name should not resolve");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_mount_and_ls);

// ── Phase 5: FileOps read ──────────────────────────────────────────

fn read_all(file: &alloc::sync::Arc<dyn narf_filesystem::FileOps>, size: usize) -> Option<Vec<u8>> {
    let mut buf = alloc::vec![0u8; size];
    match poll_once(file.read(0, &mut buf))? {
        Ok(n) => {
            buf.truncate(n);
            Some(buf)
        }
        Err(_) => None,
    }
}

fn qgroup_item(
    vol: &BtrfsVolume<narf_block::ram::RamBlockDevice>,
    item_type: u8,
    id: u64,
) -> Option<Vec<u8>> {
    let root_tree = vol.root_tree_root().0;
    let quota_root = poll_once(crate::roots::find_root(
        vol,
        root_tree,
        format::QUOTA_TREE_OBJECTID,
    ))
    .and_then(Result::ok)?
    .0;
    poll_once(btree::find_item(
        vol,
        quota_root,
        &BtrfsKey::new(0, item_type, id),
    ))
    .and_then(Result::ok)
    .flatten()
}

fn qgroup_relation_present(
    vol: &BtrfsVolume<narf_block::ram::RamBlockDevice>,
    child: u64,
    parent: u64,
) -> bool {
    let Some(Ok((quota_root, _))) = poll_once(crate::roots::find_root(
        vol,
        vol.root_tree_root().0,
        format::QUOTA_TREE_OBJECTID,
    )) else {
        return false;
    };
    [
        BtrfsKey::new(child, format::QGROUP_RELATION_KEY, parent),
        BtrfsKey::new(parent, format::QGROUP_RELATION_KEY, child),
    ]
    .into_iter()
    .all(|key| {
        poll_once(btree::find_item(vol, quota_root, &key))
            .and_then(Result::ok)
            .flatten()
            .is_some()
    })
}

fn smoke_btrfs_cat_inline_and_regular() -> TestResult {
    use narf_filesystem::FsInstance;
    let vol = match mount_fixture() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fixture failed to mount"),
    };
    let root = vol.root();

    // Tiny file -> stored inline.
    let hello = match poll_once(root.lookup_async("hello.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup hello.txt failed"),
    };
    match read_all(&hello, 64).as_deref() {
        Some(b"narf\n") => {}
        _ => return TestResult::Fail("inline file content wrong"),
    }

    // Larger file -> regular extents, spanning multiple sectors.
    let big = match poll_once(root.lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup big.dat failed"),
    };
    let want = expected_big();
    match read_all(&big, want.len() + 16) {
        Some(got) if got == want => {}
        _ => return TestResult::Fail("regular file content wrong"),
    }

    // Partial read across a sector boundary returns exactly the right slice.
    let mut mid = [0u8; 20];
    match poll_once(big.read(4090, &mut mid)) {
        Some(Ok(20)) if mid[..] == want[4090..4110] => {}
        _ => return TestResult::Fail("cross-sector partial read wrong"),
    }

    // Reading at/after EOF yields 0 (short read).
    let mut tail = [0u8; 8];
    match poll_once(big.read(want.len() as u64, &mut tail)) {
        Some(Ok(0)) => {}
        _ => return TestResult::Fail("read at EOF should return 0"),
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_cat_inline_and_regular);

/// An 8 KiB-sector image uses the filesystem sector size (not the device's
/// 512-byte LBA or NARF's 4 KiB page size) for checksum and COW allocation.
/// Exercise reads on both sides of an 8 KiB boundary, a partial overwrite,
/// remount, and checksum verification of the replacement extent.
fn smoke_btrfs_sector8k_read_write() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let vol = match mount_sparse(FIXTURE_SECTOR8K_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("8K-sector fixture failed to mount"),
    };
    if vol.sectorsize() != 8192 || vol.nodesize() != 8192 || !vol.supports_writes() {
        return TestResult::Fail("8K-sector geometry or write mode was wrong");
    }
    let device: Arc<RamBlockDevice> = vol.device.clone();
    let big = match poll_once(vol.root().lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("8K-sector regular file lookup failed"),
    };
    let original = expected_big();
    let mut crossing = [0u8; 32];
    if !matches!(poll_once(big.read(8180, &mut crossing)), Some(Ok(32)))
        || crossing[..] != original[8180..8212]
    {
        return TestResult::Fail("8K-sector cross-boundary read was wrong");
    }
    let patch = b"eight-kib-sector";
    if !matches!(poll_once(big.write(8188, patch)), Some(Ok(n)) if n == patch.len()) {
        return TestResult::Fail("8K-sector partial COW write failed");
    }
    let mut expected = original;
    expected[8188..8188 + patch.len()].copy_from_slice(patch);

    let vol2 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("8K-sector remount failed"),
    };
    if vol2.sectorsize() != 8192 || vol2.nodesize() != 8192 {
        return TestResult::Fail("8K-sector geometry changed after remount");
    }
    let big2 = match poll_once(vol2.root().lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("8K-sector remount lookup failed"),
    };
    if read_all(&big2, expected.len() + 16) != Some(expected) {
        return TestResult::Fail("8K-sector written data did not persist");
    }
    let (fs_root, _) = vol2.fs_tree_root();
    let Some(csum_root) = csum_root_of(&vol2) else {
        return TestResult::Fail("8K-sector csum tree was missing");
    };
    match poll_once(crate::csum::verify_file_data_csums(
        &vol2,
        fs_root,
        csum_root,
        big2.ino(),
    )) {
        Some(Ok(true)) => TestResult::Pass,
        _ => TestResult::Fail("8K-sector replacement checksums were invalid"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_sector8k_read_write);

/// A quota-enabled Linux image remains consistently accounted across COW
/// writes and subvolume lifecycle operations. V2 inheritance creates both
/// relation directions and applies limits; deletion removes all of them.
fn smoke_btrfs_qgroup_accounting_and_inheritance() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    const PARENT: u64 = (1u64 << 48) | 100;
    let device = RamBlockDevice::from_image(512, decode_sparse(FIXTURE_QUOTA_SPARSE));
    let vol = match poll_once(BtrfsVolume::mount_opts(
        device.clone(),
        DomainId::DRIVER_0,
        true,
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("quota fixture failed to mount"),
    };
    let initial = match qgroup_item(&vol, format::QGROUP_INFO_KEY, format::FS_TREE_OBJECTID) {
        Some(body) if body.len() == 40 => body,
        _ => return TestResult::Fail("top-level qgroup info was missing"),
    };
    let initial_rfer = format::le64(&initial, 8).unwrap_or(0);
    if initial_rfer == 0 || qgroup_item(&vol, format::QGROUP_INFO_KEY, PARENT).is_none() {
        return TestResult::Fail("fixture qgroup accounting or parent was empty");
    }

    let big = match poll_once(vol.root().lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("quota fixture regular file lookup failed"),
    };
    if !matches!(poll_once(big.write(100, b"QGROUP")), Some(Ok(6))) {
        return TestResult::Fail("quota-accounted COW write failed");
    }
    let after_write = match qgroup_item(&vol, format::QGROUP_INFO_KEY, format::FS_TREE_OBJECTID) {
        Some(body) if body.len() == 40 => body,
        _ => return TestResult::Fail("qgroup info vanished after write"),
    };
    if format::le64(&after_write, 0).ok() != Some(vol.superblock().generation)
        || format::le64(&after_write, 8).unwrap_or(0) == 0
    {
        return TestResult::Fail("qgroup generation/usage did not advance with write");
    }

    // Flattened btrfs_qgroup_inherit follows the 4096-byte V2 argument, exactly
    // as sys_ioctl passes the separately pointed-to userspace payload.
    let mut args = alloc::vec![0u8; 4096 + 80];
    args[16..24].copy_from_slice(&crate::node::BTRFS_SUBVOL_QGROUP_INHERIT.to_ne_bytes());
    args[24..32].copy_from_slice(&80u64.to_ne_bytes());
    args[56..62].copy_from_slice(b"qchild");
    let inherit = &mut args[4096..];
    inherit[0..8].copy_from_slice(&1u64.to_ne_bytes()); // SET_LIMITS
    inherit[8..16].copy_from_slice(&1u64.to_ne_bytes()); // one parent
    inherit[32..40].copy_from_slice(&1u64.to_ne_bytes()); // MAX_RFER flag
    inherit[40..48].copy_from_slice(&(32u64 << 10).to_ne_bytes());
    inherit[72..80].copy_from_slice(&PARENT.to_ne_bytes());
    if !matches!(
        poll_once(
            vol.root()
                .ioctl_async(crate::node::BTRFS_IOC_SUBVOL_CREATE_V2, 0, &args, 0,)
        ),
        Some(Ok(_))
    ) {
        return TestResult::Fail("V2 qgroup-inheriting subvolume create failed");
    }
    let child = match poll_once(BtrfsVolume::mount_subvol(
        device.clone(),
        DomainId::DRIVER_0,
        true,
        Some(crate::volume::Subvol::Name("qchild".into())),
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("qgroup child did not mount"),
    };
    let child_id = child.fs_tree_id();
    let child_info = match qgroup_item(&child, format::QGROUP_INFO_KEY, child_id) {
        Some(body) if body.len() == 40 => body,
        _ => return TestResult::Fail("new child qgroup info was missing"),
    };
    if format::le64(&child_info, 8).unwrap_or(0) < child.nodesize() as u64
        || qgroup_item(&child, format::QGROUP_INFO_KEY, PARENT).is_none()
    {
        return TestResult::Fail("new child qgroup usage was not recounted");
    }
    let limit = match qgroup_item(&child, format::QGROUP_LIMIT_KEY, child_id) {
        Some(body) if body.len() == 40 => body,
        _ => return TestResult::Fail("new child qgroup limit was missing"),
    };
    if format::le64(&limit, 0).ok() != Some(1) || format::le64(&limit, 8).ok() != Some(32u64 << 10)
    {
        return TestResult::Fail("inherited qgroup limit was wrong");
    }
    let quota_root = poll_once(crate::roots::find_root(
        &*child,
        child.root_tree_root().0,
        format::QUOTA_TREE_OBJECTID,
    ))
    .and_then(Result::ok)
    .map(|r| r.0)
    .unwrap_or(0);
    for key in [
        BtrfsKey::new(child_id, format::QGROUP_RELATION_KEY, PARENT),
        BtrfsKey::new(PARENT, format::QGROUP_RELATION_KEY, child_id),
    ] {
        if poll_once(btree::find_item(&*child, quota_root, &key))
            .and_then(Result::ok)
            .flatten()
            .is_none()
        {
            return TestResult::Fail("qgroup inheritance relation was incomplete");
        }
    }

    let payload = alloc::vec![0x5au8; 9000];
    let child_file = match poll_once(child.root().create("charged.bin")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("qgroup child file creation failed"),
    };
    if !matches!(
        poll_once(child_file.write(0, &payload)),
        Some(Ok(n)) if n == payload.len()
    ) {
        return TestResult::Fail("qgroup child data write failed");
    }
    let charged = match qgroup_item(&child, format::QGROUP_INFO_KEY, child_id) {
        Some(body) => format::le64(&body, 8).unwrap_or(0),
        None => 0,
    };
    if charged <= format::le64(&child_info, 8).unwrap_or(0) {
        return TestResult::Fail("child qgroup did not charge new data/metadata");
    }
    let over_limit = alloc::vec![0xa5u8; 40 * 1024];
    if !matches!(
        poll_once(child_file.write(0, &over_limit)),
        Some(Err(FsError::QuotaExceeded))
    ) {
        return TestResult::Fail("qgroup hard limit did not return QuotaExceeded");
    }
    let child_file_after = match poll_once(child.root().lookup_async("charged.bin")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("quota-limited file vanished after rejection"),
    };
    if read_all(&child_file_after, payload.len() + 8).as_deref() != Some(payload.as_slice()) {
        return TestResult::Fail("qgroup hard-limit rejection was not atomic");
    }

    let top = match poll_once(BtrfsVolume::mount_opts(
        device.clone(),
        DomainId::DRIVER_0,
        true,
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("top remount before qgroup deletion failed"),
    };
    let child_dir = match poll_once(top.root().lookup_dir_async("qchild")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("qgroup snapshot source lookup failed"),
    };
    if !matches!(
        poll_once(top.root().snapshot_with_quota_async(
            child_dir,
            "qsnap",
            false,
            narf_filesystem::FsQuotaInherit {
                flags: 0,
                parents: alloc::vec![PARENT],
                limit: [0; 5],
            },
        )),
        Some(Ok(()))
    ) {
        return TestResult::Fail("quota-inheriting snapshot failed");
    }
    let snapshot = match poll_once(BtrfsVolume::mount_subvol(
        device.clone(),
        DomainId::DRIVER_0,
        true,
        Some(crate::volume::Subvol::Name("qsnap".into())),
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("quota-inheriting snapshot did not mount"),
    };
    let snapshot_id = snapshot.fs_tree_id();
    if qgroup_item(&snapshot, format::QGROUP_INFO_KEY, snapshot_id).is_none() {
        return TestResult::Fail("snapshot qgroup was not created");
    }

    for name in ["qsnap", "qchild"] {
        let mut destroy = alloc::vec![0u8; 4096];
        destroy[56..56 + name.len()].copy_from_slice(name.as_bytes());
        if !matches!(
            poll_once(top.root().ioctl_async(
                crate::node::BTRFS_IOC_SNAP_DESTROY_V2,
                0,
                &destroy,
                0,
            )),
            Some(Ok(_))
        ) {
            return TestResult::Fail("quota subvolume/snapshot deletion failed");
        }
    }
    if qgroup_item(&top, format::QGROUP_INFO_KEY, child_id).is_some()
        || qgroup_item(&top, format::QGROUP_LIMIT_KEY, child_id).is_some()
        || qgroup_item(&top, format::QGROUP_INFO_KEY, snapshot_id).is_some()
    {
        return TestResult::Fail("deleted subvolume qgroup items survived");
    }
    let final_quota = poll_once(crate::roots::find_root(
        &*top,
        top.root_tree_root().0,
        format::QUOTA_TREE_OBJECTID,
    ))
    .and_then(Result::ok)
    .map(|r| r.0)
    .unwrap_or(0);
    if [
        BtrfsKey::new(child_id, format::QGROUP_RELATION_KEY, PARENT),
        BtrfsKey::new(PARENT, format::QGROUP_RELATION_KEY, child_id),
    ]
    .iter()
    .any(|key| {
        poll_once(btree::find_item(&*top, final_quota, key))
            .and_then(Result::ok)
            .flatten()
            .is_some()
    }) {
        return TestResult::Fail("deleted subvolume qgroup relation survived");
    }
    let status = qgroup_item(&top, format::QGROUP_STATUS_KEY, 0).unwrap_or_default();
    if format::le64(&status, 8).ok() != Some(top.superblock().generation)
        || format::le64(&status, 16).ok() != Some(1)
    {
        return TestResult::Fail("quota status did not finish at the committed generation");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_qgroup_accounting_and_inheritance
);

/// Exercise the complete full-qgroup administration lifecycle on an image
/// created without quotas: enable + initial rescan, higher-level create,
/// relation assignment, limit replacement, status/wait, unassign/destroy, and
/// disable with quota-tree reclamation.
fn smoke_btrfs_qgroup_admin_ioctls() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    const PARENT: u64 = (1u64 << 48) | 200;
    let device = RamBlockDevice::from_image(512, decode_sparse(FIXTURE_SPARSE));
    let vol = match poll_once(BtrfsVolume::mount_opts(
        device.clone(),
        DomainId::DRIVER_0,
        true,
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("quota-admin fixture failed to mount"),
    };
    if poll_once(crate::roots::find_root(
        &*vol,
        vol.root_tree_root().0,
        format::QUOTA_TREE_OBJECTID,
    ))
    .and_then(Result::ok)
    .is_some()
    {
        return TestResult::Fail("quota-admin fixture unexpectedly had quotas");
    }

    let mut ctl = [0u8; 16];
    ctl[0..8].copy_from_slice(&1u64.to_ne_bytes());
    let enable =
        match poll_once(
            vol.root()
                .ioctl_async(crate::node::BTRFS_IOC_QUOTA_CTL, 0, &ctl, 16),
        ) {
            Some(Ok(reply)) if reply.output.len() == 16 => reply,
            _ => return TestResult::Fail("quota enable ioctl failed"),
        };
    if u64::from_ne_bytes(enable.output[8..16].try_into().unwrap()) & 1 == 0 {
        return TestResult::Fail("quota enable did not return ON status");
    }
    let top_info = match qgroup_item(&vol, format::QGROUP_INFO_KEY, format::FS_TREE_OBJECTID) {
        Some(body) if body.len() == 40 => body,
        _ => return TestResult::Fail("quota enable did not create the top qgroup"),
    };
    if format::le64(&top_info, 0).ok() != Some(vol.superblock().generation)
        || format::le64(&top_info, 8).unwrap_or(0) == 0
    {
        return TestResult::Fail("initial synchronous quota rescan was incomplete");
    }

    let mut create = [0u8; 16];
    create[0..8].copy_from_slice(&1u64.to_ne_bytes());
    create[8..16].copy_from_slice(&PARENT.to_ne_bytes());
    if !matches!(
        poll_once(
            vol.root()
                .ioctl_async(crate::node::BTRFS_IOC_QGROUP_CREATE, 0, &create, 0,)
        ),
        Some(Ok(_))
    ) {
        return TestResult::Fail("higher-level qgroup create ioctl failed");
    }
    if !matches!(
        poll_once(
            vol.root()
                .ioctl_async(crate::node::BTRFS_IOC_QGROUP_CREATE, 0, &create, 0,)
        ),
        Some(Err(FsError::Busy))
    ) {
        return TestResult::Fail("duplicate qgroup create was not rejected");
    }

    let mut assign = [0u8; 24];
    assign[0..8].copy_from_slice(&1u64.to_ne_bytes());
    assign[8..16].copy_from_slice(&format::FS_TREE_OBJECTID.to_ne_bytes());
    assign[16..24].copy_from_slice(&PARENT.to_ne_bytes());
    if !matches!(
        poll_once(
            vol.root()
                .ioctl_async(crate::node::BTRFS_IOC_QGROUP_ASSIGN, 0, &assign, 0,)
        ),
        Some(Ok(_))
    ) {
        return TestResult::Fail("qgroup assignment ioctl failed");
    }
    let quota_root = poll_once(crate::roots::find_root(
        &*vol,
        vol.root_tree_root().0,
        format::QUOTA_TREE_OBJECTID,
    ))
    .and_then(Result::ok)
    .map(|root| root.0)
    .unwrap_or(0);
    for key in [
        BtrfsKey::new(
            format::FS_TREE_OBJECTID,
            format::QGROUP_RELATION_KEY,
            PARENT,
        ),
        BtrfsKey::new(
            PARENT,
            format::QGROUP_RELATION_KEY,
            format::FS_TREE_OBJECTID,
        ),
    ] {
        if poll_once(btree::find_item(&*vol, quota_root, &key))
            .and_then(Result::ok)
            .flatten()
            .is_none()
        {
            return TestResult::Fail("qgroup assignment was not bidirectional");
        }
    }

    // Linux permits setting a hard limit below current usage. The ioctl itself
    // succeeds; subsequent ordinary mutations enforce the new limit.
    let mut limit = [0u8; 48];
    limit[8..16].copy_from_slice(&1u64.to_ne_bytes());
    limit[16..24].copy_from_slice(&1u64.to_ne_bytes());
    if !matches!(
        poll_once(
            vol.root()
                .ioctl_async(crate::node::BTRFS_IOC_QGROUP_LIMIT, 0, &limit, 48,)
        ),
        Some(Ok(_))
    ) {
        return TestResult::Fail("qgroup limit ioctl rejected an exceeded limit");
    }
    let stored_limit =
        qgroup_item(&vol, format::QGROUP_LIMIT_KEY, format::FS_TREE_OBJECTID).unwrap_or_default();
    if format::le64(&stored_limit, 0).ok() != Some(1)
        || format::le64(&stored_limit, 8).ok() != Some(1)
    {
        return TestResult::Fail("qgroup limit ioctl did not persist its record");
    }

    let rescan = [0u8; 64];
    if !matches!(
        poll_once(
            vol.root()
                .ioctl_async(crate::node::BTRFS_IOC_QUOTA_RESCAN, 0, &rescan, 0,)
        ),
        Some(Ok(_))
    ) {
        return TestResult::Fail("synchronous quota rescan ioctl failed");
    }
    let status = match poll_once(vol.root().ioctl_async(
        crate::node::BTRFS_IOC_QUOTA_RESCAN_STATUS,
        0,
        &[],
        64,
    )) {
        Some(Ok(reply)) if reply.output.len() == 64 => reply,
        _ => return TestResult::Fail("quota rescan status ioctl failed"),
    };
    if status.output.iter().any(|byte| *byte != 0)
        || !matches!(
            poll_once(
                vol.root()
                    .ioctl_async(crate::node::BTRFS_IOC_QUOTA_RESCAN_WAIT, 0, &[], 0,)
            ),
            Some(Ok(_))
        )
    {
        return TestResult::Fail("completed synchronous rescan reported active");
    }

    // An assigned parent cannot be destroyed. Unassign it, then removal must
    // delete both its INFO and LIMIT records.
    create[0..8].copy_from_slice(&0u64.to_ne_bytes());
    if !matches!(
        poll_once(
            vol.root()
                .ioctl_async(crate::node::BTRFS_IOC_QGROUP_CREATE, 0, &create, 0,)
        ),
        Some(Err(FsError::Busy))
    ) {
        return TestResult::Fail("assigned parent qgroup was destroyable");
    }
    assign[0..8].copy_from_slice(&0u64.to_ne_bytes());
    if !matches!(
        poll_once(
            vol.root()
                .ioctl_async(crate::node::BTRFS_IOC_QGROUP_ASSIGN, 0, &assign, 0,)
        ),
        Some(Ok(_))
    ) || !matches!(
        poll_once(
            vol.root()
                .ioctl_async(crate::node::BTRFS_IOC_QGROUP_CREATE, 0, &create, 0,)
        ),
        Some(Ok(_))
    ) {
        return TestResult::Fail("qgroup unassign/destroy lifecycle failed");
    }
    if qgroup_item(&vol, format::QGROUP_INFO_KEY, PARENT).is_some()
        || qgroup_item(&vol, format::QGROUP_LIMIT_KEY, PARENT).is_some()
    {
        return TestResult::Fail("destroyed parent qgroup items survived");
    }

    // Enabling another quota mode while quotas are already active is an
    // idempotent no-op, matching Linux; it must not switch the live mode.
    let mut simple = [0u8; 16];
    simple[0..8].copy_from_slice(&4u64.to_ne_bytes());
    let mode_reply =
        match poll_once(
            vol.root()
                .ioctl_async(crate::node::BTRFS_IOC_QUOTA_CTL, 0, &simple, 16),
        ) {
            Some(Ok(reply)) => reply,
            _ => return TestResult::Fail("active full quotas rejected idempotent enable"),
        };
    if u64::from_ne_bytes(mode_reply.output[8..16].try_into().unwrap()) & (1 << 3) != 0 {
        return TestResult::Fail("active full quotas unexpectedly switched to simple mode");
    }

    ctl[0..8].copy_from_slice(&2u64.to_ne_bytes());
    if !matches!(
        poll_once(
            vol.root()
                .ioctl_async(crate::node::BTRFS_IOC_QUOTA_CTL, 0, &ctl, 16,)
        ),
        Some(Ok(_))
    ) {
        return TestResult::Fail("quota disable ioctl failed");
    }
    let remount = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount after quota disable failed"),
    };
    if poll_once(crate::roots::find_root(
        &*remount,
        remount.root_tree_root().0,
        format::QUOTA_TREE_OBJECTID,
    ))
    .and_then(Result::ok)
    .is_some()
    {
        return TestResult::Fail("disabled quota tree remained reachable");
    }
    let hello = match poll_once(remount.root().lookup_async("hello.txt")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("post-disable file lookup failed"),
    };
    if !matches!(poll_once(hello.write(0, b"quota-off")), Some(Ok(9))) {
        return TestResult::Fail("ordinary write failed after quota disable");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_qgroup_admin_ioctls);

/// Mount a Linux-created simple-quota filesystem containing real owner refs,
/// mutate it, and prove incremental owner accounting remains durable.
fn smoke_btrfs_linux_simple_quota_fixture() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    const PARENT: u64 = (1u64 << 48) | 200;
    let device = RamBlockDevice::from_image(512, decode_sparse(FIXTURE_SQUOTA_SPARSE));
    let vol = match poll_once(BtrfsVolume::mount_opts(
        device.clone(),
        DomainId::DRIVER_0,
        true,
    )) {
        Some(Ok(vol)) => vol,
        _ => return TestResult::Fail("Linux simple-quota fixture failed to mount"),
    };
    if vol.superblock().incompat_flags & format::INCOMPAT_SIMPLE_QUOTA == 0 {
        return TestResult::Fail("simple-quota incompat bit was not accepted");
    }
    let status = qgroup_item(&vol, format::QGROUP_STATUS_KEY, 0).unwrap_or_default();
    if status.len() < 40
        || format::le64(&status, 16).ok() != Some(1 | (1 << 3))
        || format::le64(&status, 32).unwrap_or(0) == 0
    {
        return TestResult::Fail("Linux simple-quota status was decoded incorrectly");
    }
    let initial =
        qgroup_item(&vol, format::QGROUP_INFO_KEY, format::FS_TREE_OBJECTID).unwrap_or_default();
    let initial_usage = format::le64(&initial, 8).unwrap_or(0);
    if initial.len() != 40
        || initial_usage == 0
        || format::le64(&initial, 24).ok() != Some(initial_usage)
    {
        return TestResult::Fail("Linux simple-quota usage was missing or asymmetric");
    }
    let parent_usage = qgroup_item(&vol, format::QGROUP_INFO_KEY, PARENT)
        .and_then(|body| format::le64(&body, 8).ok())
        .unwrap_or(0);
    if parent_usage != initial_usage || !qgroup_relation_present(&vol, 5, PARENT) {
        return TestResult::Fail("Linux simple-quota parent accounting was wrong");
    }

    let linux_owned = match poll_once(vol.root().lookup_async("simple-owned.dat")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("Linux-owned simple-quota file was missing"),
    };
    let (bytenr, len) = file_data_extent(&vol, linux_owned.ino()).unwrap_or((0, 0));
    if bytenr == 0 || data_extent_owner(&vol, bytenr, len) != Some(5) {
        return TestResult::Fail("Linux data extent owner ref was not understood");
    }

    let payload = alloc::vec![0x6du8; 20 * 1024];
    let created = match poll_once(vol.root().create("narf-simple.dat")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("simple-quota file create failed"),
    };
    if !matches!(
        poll_once(created.write(0, &payload)),
        Some(Ok(n)) if n == payload.len()
    ) {
        return TestResult::Fail("simple-quota data allocation failed");
    }
    let charged = qgroup_item(&vol, format::QGROUP_INFO_KEY, 5).unwrap_or_default();
    let charged_usage = format::le64(&charged, 8).unwrap_or(0);
    if charged_usage <= initial_usage || format::le64(&charged, 24).ok() != Some(charged_usage) {
        return TestResult::Fail("NARF allocation did not increment simple usage");
    }
    let (new_bytenr, new_len) = file_data_extent(&vol, created.ino()).unwrap_or((0, 0));
    if data_extent_owner(&vol, new_bytenr, new_len) != Some(5) {
        return TestResult::Fail("NARF data extent omitted the simple owner ref");
    }

    let remount = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(vol)) => vol,
        _ => return TestResult::Fail("simple-quota fixture failed to remount"),
    };
    let durable = qgroup_item(&remount, format::QGROUP_INFO_KEY, 5)
        .and_then(|body| format::le64(&body, 8).ok())
        .unwrap_or(0);
    let file = match poll_once(remount.root().lookup_async("narf-simple.dat")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("simple-quota file vanished on remount"),
    };
    if durable != charged_usage || read_all(&file, payload.len() + 1).as_deref() != Some(&payload) {
        return TestResult::Fail("simple-quota accounting/data was not durable");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_linux_simple_quota_fixture);

/// Exercise NARF-created simple quotas, hierarchy, shared snapshots, limits,
/// disable semantics, and the supported transition back to full qgroups.
fn smoke_btrfs_simple_quota_lifecycle() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    const PARENT: u64 = (1u64 << 48) | 210;
    let device = RamBlockDevice::from_image(512, decode_sparse(FIXTURE_SPARSE));
    let top = match poll_once(BtrfsVolume::mount_opts(
        device.clone(),
        DomainId::DRIVER_0,
        true,
    )) {
        Some(Ok(vol)) => vol,
        _ => return TestResult::Fail("simple-quota lifecycle fixture failed to mount"),
    };
    let mut ctl = [0u8; 16];
    ctl[0..8].copy_from_slice(&4u64.to_ne_bytes());
    let reply =
        match poll_once(
            top.root()
                .ioctl_async(crate::node::BTRFS_IOC_QUOTA_CTL, 0, &ctl, 16),
        ) {
            Some(Ok(reply)) => reply,
            _ => return TestResult::Fail("simple-quota enable failed"),
        };
    if u64::from_ne_bytes(reply.output[8..16].try_into().unwrap()) != 1 | (1 << 3)
        || top.superblock().incompat_flags & format::INCOMPAT_SIMPLE_QUOTA == 0
    {
        return TestResult::Fail("simple-quota mode was not persisted/reported");
    }
    let initial = qgroup_item(&top, format::QGROUP_INFO_KEY, 5).unwrap_or_default();
    if format::le64(&initial, 8).ok() != Some(0) || format::le64(&initial, 24).ok() != Some(0) {
        return TestResult::Fail("pre-enable extents were charged by simple quotas");
    }
    let rescan = [0u8; 64];
    if !matches!(
        poll_once(
            top.root()
                .ioctl_async(crate::node::BTRFS_IOC_QUOTA_RESCAN, 0, &rescan, 0,)
        ),
        Some(Err(FsError::InvalidData))
    ) {
        return TestResult::Fail("simple quotas incorrectly accepted a rescan");
    }

    let mut create_group = [0u8; 16];
    create_group[0..8].copy_from_slice(&1u64.to_ne_bytes());
    create_group[8..16].copy_from_slice(&PARENT.to_ne_bytes());
    if !matches!(
        poll_once(top.root().ioctl_async(
            crate::node::BTRFS_IOC_QGROUP_CREATE,
            0,
            &create_group,
            0,
        )),
        Some(Ok(_))
    ) {
        return TestResult::Fail("simple parent qgroup create failed");
    }
    let mut assign = [0u8; 24];
    assign[0..8].copy_from_slice(&1u64.to_ne_bytes());
    assign[8..16].copy_from_slice(&5u64.to_ne_bytes());
    assign[16..24].copy_from_slice(&PARENT.to_ne_bytes());
    if !matches!(
        poll_once(
            top.root()
                .ioctl_async(crate::node::BTRFS_IOC_QGROUP_ASSIGN, 0, &assign, 0,)
        ),
        Some(Ok(_))
    ) {
        return TestResult::Fail("simple parent assignment failed");
    }

    let top_payload = alloc::vec![0x35u8; 9 * 1024];
    let top_file = match poll_once(top.root().create("simple-new.dat")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("simple top-level file create failed"),
    };
    if !matches!(
        poll_once(top_file.write(0, &top_payload)),
        Some(Ok(n)) if n == top_payload.len()
    ) {
        return TestResult::Fail("simple top-level allocation failed");
    }
    let top_usage = qgroup_item(&top, format::QGROUP_INFO_KEY, 5)
        .and_then(|body| format::le64(&body, 8).ok())
        .unwrap_or(0);
    if top_usage == 0
        || qgroup_item(&top, format::QGROUP_INFO_KEY, PARENT)
            .and_then(|body| format::le64(&body, 8).ok())
            .unwrap_or(0)
            != top_usage
    {
        return TestResult::Fail("simple owner/parent charging did not advance");
    }

    let child_id = match poll_once(crate::write::create_subvolume(
        &top,
        format::FIRST_FREE_OBJECTID,
        "simple-child",
        false,
    )) {
        Some(Ok(id)) => id,
        _ => return TestResult::Fail("simple child subvolume create failed"),
    };
    if !qgroup_relation_present(&top, child_id, PARENT) {
        return TestResult::Fail("simple child did not auto-inherit destination parents");
    }
    let child_usage = qgroup_item(&top, format::QGROUP_INFO_KEY, child_id)
        .and_then(|body| format::le64(&body, 8).ok())
        .unwrap_or(0);
    if child_usage < top.nodesize() as u64 {
        return TestResult::Fail("simple child metadata was not owner-charged");
    }

    let child_dir = match poll_once(top.root().lookup_dir_async("simple-child")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("simple child traversal failed"),
    };
    if !matches!(
        poll_once(top.root().snapshot_async(child_dir, "simple-snap", false)),
        Some(Ok(()))
    ) {
        return TestResult::Fail("simple shared-root snapshot create failed");
    }
    let snapshot = match poll_once(BtrfsVolume::mount_subvol(
        device.clone(),
        DomainId::DRIVER_0,
        true,
        Some(crate::volume::Subvol::Name("simple-snap".into())),
    )) {
        Some(Ok(vol)) => vol,
        _ => return TestResult::Fail("simple snapshot failed to mount"),
    };
    let snapshot_id = snapshot.fs_tree_id();
    if qgroup_item(&snapshot, format::QGROUP_INFO_KEY, snapshot_id)
        .and_then(|body| format::le64(&body, 8).ok())
        .unwrap_or(u64::MAX)
        != 0
        || !qgroup_relation_present(&snapshot, snapshot_id, PARENT)
    {
        return TestResult::Fail("shared snapshot was charged or missed auto-inheritance");
    }

    // The source qgroup cannot disappear while the shared root still contains
    // metadata permanently owned by it. Once the snapshot COWs that final
    // holder, the debit must still find the orphaned qgroup.
    let top_for_delete = match poll_once(BtrfsVolume::mount(device.clone(), DomainId::DRIVER_0)) {
        Some(Ok(vol)) => vol,
        _ => return TestResult::Fail("top remount before simple child delete failed"),
    };
    if !matches!(
        poll_once(crate::write::destroy_subvolume(
            &top_for_delete,
            format::FIRST_FREE_OBJECTID,
            Some("simple-child"),
            None,
        )),
        Some(Ok(()))
    ) {
        return TestResult::Fail("simple shared-root source deletion failed");
    }
    let orphan_usage = qgroup_item(&top_for_delete, format::QGROUP_INFO_KEY, child_id)
        .and_then(|body| format::le64(&body, 8).ok())
        .unwrap_or(0);
    if orphan_usage != child_usage {
        return TestResult::Fail("simple source qgroup was dropped before its final debit");
    }
    let snapshot = match poll_once(BtrfsVolume::mount_subvol(
        device.clone(),
        DomainId::DRIVER_0,
        true,
        Some(crate::volume::Subvol::Id(snapshot_id)),
    )) {
        Some(Ok(vol)) => vol,
        _ => return TestResult::Fail("simple snapshot remount after source delete failed"),
    };

    let snap_payload = alloc::vec![0xabu8; 12 * 1024];
    let snap_file = match poll_once(snapshot.root().create("snapshot-owned.dat")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("simple snapshot private create failed"),
    };
    if !matches!(
        poll_once(snap_file.write(0, &snap_payload)),
        Some(Ok(n)) if n == snap_payload.len()
    ) {
        return TestResult::Fail("simple snapshot-local allocation failed");
    }
    let snap_usage = qgroup_item(&snapshot, format::QGROUP_INFO_KEY, snapshot_id)
        .and_then(|body| format::le64(&body, 8).ok())
        .unwrap_or(0);
    if snap_usage == 0 {
        return TestResult::Fail("simple snapshot-local allocation was not charged");
    }
    let debited_orphan = qgroup_item(&snapshot, format::QGROUP_INFO_KEY, child_id)
        .and_then(|body| format::le64(&body, 8).ok());
    if debited_orphan != Some(0) {
        return TestResult::Fail("simple orphan qgroup missed its final owner debit");
    }

    let mut limit = [0u8; 48];
    limit[8..16].copy_from_slice(&1u64.to_ne_bytes());
    limit[16..24].copy_from_slice(&snap_usage.to_ne_bytes());
    if !matches!(
        poll_once(
            snapshot
                .root()
                .ioctl_async(crate::node::BTRFS_IOC_QGROUP_LIMIT, 0, &limit, 48,)
        ),
        Some(Ok(_))
    ) {
        return TestResult::Fail("simple hard-limit install failed");
    }
    let too_large = alloc::vec![0xccu8; 32 * 1024];
    if !matches!(
        poll_once(snap_file.write(0, &too_large)),
        Some(Err(FsError::QuotaExceeded))
    ) {
        return TestResult::Fail("simple hard limit did not return QuotaExceeded");
    }
    let snap_file_after = match poll_once(snapshot.root().lookup_async("snapshot-owned.dat")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("simple-limited file vanished after rejection"),
    };
    if read_all(&snap_file_after, snap_payload.len() + 1).as_deref()
        != Some(snap_payload.as_slice())
    {
        return TestResult::Fail("simple hard-limit rejection was not atomic");
    }

    let top = match poll_once(BtrfsVolume::mount(device.clone(), DomainId::DRIVER_0)) {
        Some(Ok(vol)) => vol,
        _ => return TestResult::Fail("top remount before simple disable failed"),
    };
    ctl[0..8].copy_from_slice(&2u64.to_ne_bytes());
    if !matches!(
        poll_once(
            top.root()
                .ioctl_async(crate::node::BTRFS_IOC_QUOTA_CTL, 0, &ctl, 16,)
        ),
        Some(Ok(_))
    ) {
        return TestResult::Fail("simple quota disable failed");
    }
    let disabled = match poll_once(BtrfsVolume::mount(device.clone(), DomainId::DRIVER_0)) {
        Some(Ok(vol)) => vol,
        _ => return TestResult::Fail("simple-disabled filesystem failed to remount"),
    };
    if disabled.superblock().incompat_flags & format::INCOMPAT_SIMPLE_QUOTA == 0
        || qgroup_item(&disabled, format::QGROUP_STATUS_KEY, 0).is_some()
    {
        return TestResult::Fail("simple disable cleared owner format or retained quota tree");
    }

    ctl[0..8].copy_from_slice(&1u64.to_ne_bytes());
    if !matches!(
        poll_once(
            disabled
                .root()
                .ioctl_async(crate::node::BTRFS_IOC_QUOTA_CTL, 0, &ctl, 16,)
        ),
        Some(Ok(_))
    ) {
        return TestResult::Fail("simple-to-full quota transition failed");
    }
    let full_status = qgroup_item(&disabled, format::QGROUP_STATUS_KEY, 0).unwrap_or_default();
    if format::le64(&full_status, 16).ok() != Some(1) {
        return TestResult::Fail("full re-enable retained simple mode status");
    }
    let old_simple_file = match poll_once(disabled.root().lookup_async("simple-new.dat")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("old simple-owned file vanished after full enable"),
    };
    if !matches!(
        poll_once(old_simple_file.write(0, b"full-mode")),
        Some(Ok(9))
    ) {
        return TestResult::Fail("full quotas could not update an owner-ref extent");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_simple_quota_lifecycle);

/// Mount genuine mkfs images using every alternate checksum, COW-write regular
/// data, remount through the newly checksummed metadata/superblock, and verify
/// the algorithm-width CSUM tree entries emitted for the new extent.
fn smoke_btrfs_alternate_checksum_mounts() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    for (sparse, csum_type) in [
        (FIXTURE_XXHASH_SPARSE, format::CSUM_TYPE_XXHASH),
        (FIXTURE_SHA256_SPARSE, format::CSUM_TYPE_SHA256),
        (FIXTURE_BLAKE2_SPARSE, format::CSUM_TYPE_BLAKE2),
    ] {
        let vol = match mount_sparse(sparse) {
            Ok(v) => v,
            Err(_) => return TestResult::Fail("alternate-checksum fixture failed to mount"),
        };
        if vol.csum_type() != csum_type || !vol.supports_writes() {
            return TestResult::Fail("alternate-checksum volume mode is wrong");
        }
        let device: Arc<RamBlockDevice> = vol.device.clone();
        let root = vol.root();
        let hello = match poll_once(root.lookup_async("hello.txt")) {
            Some(Ok(f)) => f,
            _ => return TestResult::Fail("alternate-checksum lookup failed"),
        };
        if read_all(&hello, 64).as_deref() != Some(b"narf\n") {
            return TestResult::Fail("alternate-checksum inline read failed");
        }
        let big = match poll_once(root.lookup_async("big.dat")) {
            Some(Ok(f)) => f,
            _ => return TestResult::Fail("alternate-checksum regular lookup failed"),
        };
        if read_all(&big, 12_016) != Some(expected_big()) {
            return TestResult::Fail("alternate-checksum regular read failed");
        }
        let payload = replacement_big();
        match poll_once(big.write(0, &payload)) {
            Some(Ok(n)) if n == payload.len() => {}
            _ => return TestResult::Fail("alternate-checksum COW write failed"),
        }

        let vol2 = match poll_once(BtrfsVolume::mount(device.clone(), DomainId::DRIVER_0)) {
            Some(Ok(v)) => v,
            _ => return TestResult::Fail("alternate-checksum remount failed"),
        };
        if vol2.csum_type() != csum_type || !vol2.supports_writes() {
            return TestResult::Fail("alternate-checksum remount mode is wrong");
        }
        let big2 = match poll_once(vol2.root().lookup_async("big.dat")) {
            Some(Ok(f)) => f,
            _ => return TestResult::Fail("alternate-checksum remount lookup failed"),
        };
        if read_all(&big2, payload.len() + 16) != Some(payload) {
            return TestResult::Fail("alternate-checksum written data mismatch");
        }
        let (fs_root, _) = vol2.fs_tree_root();
        let csum_root = match csum_root_of(&vol2) {
            Some(root) => root,
            None => return TestResult::Fail("alternate-checksum csum root missing"),
        };
        match poll_once(crate::csum::verify_file_data_csums(
            &vol2,
            fs_root,
            csum_root,
            big2.ino(),
        )) {
            Some(Ok(true)) => {}
            _ => return TestResult::Fail("alternate-checksum written csums are invalid"),
        }

        // Exercise the separate log-tree stamping path and mount-time replay.
        let key = BtrfsKey::new(big2.ino(), format::INODE_ITEM_KEY, 0);
        let mut inode = match poll_once(btree::find_item(&vol2, fs_root, &key)) {
            Some(Ok(Some(body))) => body,
            _ => return TestResult::Fail("alternate-checksum inode item missing"),
        };
        const LOG_MARK: u64 = 0x0000_2233_4455_6677;
        inode[136..144].copy_from_slice(&LOG_MARK.to_le_bytes());
        if !matches!(
            poll_once(crate::write::write_log(&vol2, &[(key, inode)])),
            Some(Ok(()))
        ) {
            return TestResult::Fail("alternate-checksum write_log failed");
        }
        let vol3 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
            Some(Ok(v)) => v,
            _ => return TestResult::Fail("alternate-checksum log replay failed"),
        };
        let big3 = match poll_once(vol3.root().lookup_async("big.dat")) {
            Some(Ok(f)) => f,
            _ => return TestResult::Fail("alternate-checksum post-replay lookup failed"),
        };
        match poll_once(big3.statx_async(0, 0x7ff)) {
            Some(Ok(sx)) if sx.mtime.seconds == LOG_MARK as i64 => {}
            _ => return TestResult::Fail("alternate-checksum log record not replayed"),
        }
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_alternate_checksum_mounts);

// ── Phase 6: registration ──────────────────────────────────────────

fn smoke_btrfs_registration() -> TestResult {
    // The Subsys initcall must have registered the `btrfs` fstype builder.
    if narf_filesystem::lookup_fstype("btrfs").is_none() {
        return TestResult::Fail("btrfs fstype not registered");
    }
    // The builder rejects write-implying options before touching a device.
    if !matches!(
        crate::btrfs_fstype_builder("/dev/nope", "rw"),
        Err(FsError::Unsupported)
    ) {
        return TestResult::Fail("builder should reject rw option");
    }
    // A read-only mount of a missing device fails with NotFound, not a panic.
    if !matches!(
        crate::btrfs_fstype_builder("/dev/nope", "ro"),
        Err(FsError::NotFound)
    ) {
        return TestResult::Fail("builder should ENOENT a missing device");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_registration);

// ── Phase 7: checksum enforcement ──────────────────────────────────

fn smoke_btrfs_checksum_enforced() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;
    let sb_off = format::SUPERBLOCK_OFFSET as usize;

    // Corrupt a checksum-covered (but non-magic) superblock byte.
    let mut img = decode_sparse(FIXTURE_SPARSE);
    img[sb_off + 700] ^= 0xFF;

    // verify on → mount rejects the bad superblock checksum.
    let dev = RamBlockDevice::from_image(512, img.clone());
    if poll_once(BtrfsVolume::mount(dev, DomainId::DRIVER_0))
        .map(|r| r.is_ok())
        .unwrap_or(false)
    {
        return TestResult::Fail("corrupt superblock csum should fail with verify on");
    }
    // verify off → the same image mounts (the flag gates enforcement).
    let dev = RamBlockDevice::from_image(512, img);
    if !matches!(
        poll_once(BtrfsVolume::mount_opts(dev, DomainId::DRIVER_0, false)),
        Some(Ok(_))
    ) {
        return TestResult::Fail("verify-off should tolerate a bad superblock csum");
    }

    // Corrupt a byte inside the fs-tree root node and confirm the node
    // checksum guard rejects it during mount.
    let good = match mount_fixture() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("clean fixture failed to mount"),
    };
    let (fs_root, _) = good.fs_tree_root();
    let phys = match good.map_logical(fs_root) {
        Ok(p) => p as usize,
        Err(_) => return TestResult::Fail("fs root not mappable"),
    };
    drop(good);
    let mut img2 = decode_sparse(FIXTURE_SPARSE);
    img2[phys + 200] ^= 0xFF; // inside the node, past the csum field
    let dev = RamBlockDevice::from_image(512, img2);
    if poll_once(BtrfsVolume::mount(dev, DomainId::DRIVER_0))
        .map(|r| r.is_ok())
        .unwrap_or(false)
    {
        return TestResult::Fail("corrupt node csum should fail with verify on");
    }

    // Data checksums are enforced by ordinary FileOps reads too (not only the
    // explicit verifier used by checksum tests).
    let clean = match mount_fixture() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("clean fixture remount failed"),
    };
    let big = match poll_once(clean.root().lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup big.dat for corruption test failed"),
    };
    let (data_logical, _) = match file_data_extent(&clean, big.ino()) {
        Some(extent) => extent,
        None => return TestResult::Fail("big.dat data extent missing"),
    };
    let data_physical = match clean.map_logical(data_logical) {
        Ok(physical) => physical as usize,
        Err(_) => return TestResult::Fail("big.dat data extent not mappable"),
    };
    let mut img3 = decode_sparse(FIXTURE_SPARSE);
    img3[data_physical + 100] ^= 0x40;
    let dev = RamBlockDevice::from_image(512, img3);
    let corrupt = match poll_once(BtrfsVolume::mount(dev, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("data corruption should not prevent metadata mount"),
    };
    let big = match poll_once(corrupt.root().lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("corrupt-data lookup failed"),
    };
    let mut buf = [0u8; 512];
    if !matches!(
        poll_once(big.read(0, &mut buf)),
        Some(Err(FsError::InvalidData))
    ) {
        return TestResult::Fail("ordinary file read accepted bad data checksum");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_checksum_enforced);

// ── Phase 7: basic COW write ───────────────────────────────────────

/// Same length as `big.dat` (12000 bytes) but different content.
fn replacement_big() -> Vec<u8> {
    let mut v = Vec::with_capacity(12000);
    for i in 0..2000u32 {
        v.extend_from_slice(alloc::format!("M{:04}\n", i).as_bytes());
    }
    v
}

fn smoke_btrfs_cow_overwrite_roundtrip() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let vol = match mount_fixture() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fixture failed to mount"),
    };
    let device: alloc::sync::Arc<RamBlockDevice> = vol.device.clone();

    // Record the fs-tree root node bytes before the write (COW must not touch
    // them).
    let (old_fs_root, _) = vol.fs_tree_root();
    let old_node = match poll_once(vol.read_node(old_fs_root)) {
        Some(Ok(b)) => b,
        _ => return TestResult::Fail("could not read old fs root node"),
    };

    let big = match poll_once(vol.root().lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup big.dat failed"),
    };
    let new = replacement_big();
    match poll_once(big.write(0, &new)) {
        Some(Ok(n)) if n == new.len() => {}
        other => {
            let _ = other;
            return TestResult::Fail("cow write did not report full length");
        }
    }

    // Old fs-tree root node is byte-for-byte unchanged on disk (COW invariant).
    match poll_once(vol.read_node(old_fs_root)) {
        Some(Ok(after)) if after == old_node => {}
        _ => return TestResult::Fail("old fs-tree root node was mutated (not COW)"),
    }
    // The live volume advanced to a new fs-tree root.
    if vol.fs_tree_root().0 == old_fs_root {
        return TestResult::Fail("fs-tree root did not advance after write");
    }

    // Read back through the live volume: the new bytes are visible.
    match read_all(&big, new.len() + 16) {
        Some(got) if got == new => {}
        _ => return TestResult::Fail("live read-back does not match written data"),
    }

    // Remount from the same device storage: the on-disk COW chain (new
    // superblock -> new root tree -> new fs tree -> new extent) is consistent.
    let vol2 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount after write failed (broken COW chain)"),
    };
    let big2 = match poll_once(vol2.root().lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("remount lookup big.dat failed"),
    };
    match read_all(&big2, new.len() + 16) {
        Some(got) if got == new => TestResult::Pass,
        _ => TestResult::Fail("remounted read-back does not match written data"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_cow_overwrite_roundtrip);

fn smoke_btrfs_write_rejections() -> TestResult {
    use narf_filesystem::{FsError, FsInstance};
    let vol = match mount_fixture() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fixture failed to mount"),
    };
    let root = vol.root();

    // A write into a nested subvolume is ReadOnly (only the default subvol is
    // writable).
    let snap = match poll_once(root.lookup_dir_async("snap")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("lookup snap failed"),
    };
    let inside = match poll_once(snap.lookup_async("inside.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup snap/inside.txt failed"),
    };
    if !matches!(
        poll_once(inside.write(0, b"xxxxxxxxxxxxxx")),
        Some(Err(FsError::ReadOnly))
    ) {
        return TestResult::Fail("subvolume write should be ReadOnly");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_write_rejections);

fn smoke_btrfs_partial_and_append_write() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let vol = match mount_fixture() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    let big = match poll_once(vol.root().lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup big.dat failed"),
    };

    // Partial write in the middle (no size change).
    let patch = b"PATCHED!";
    match poll_once(big.write(100, patch)) {
        Some(Ok(n)) if n == patch.len() => {}
        _ => return TestResult::Fail("partial write failed"),
    }
    // Append past EOF (grows the file).
    let tail = b"APPENDED-TAIL\n";
    match poll_once(big.write(12000, tail)) {
        Some(Ok(n)) if n == tail.len() => {}
        _ => return TestResult::Fail("append write failed"),
    }

    // Build the expected content and verify via a fresh remount of the on-disk
    // image (the COW chain must be self-consistent).
    let mut want = expected_big();
    want[100..108].copy_from_slice(patch);
    want.extend_from_slice(tail); // grew to 12000 + tail

    let vol2 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount after write failed"),
    };
    let big2 = match poll_once(vol2.root().lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("remount lookup big.dat failed"),
    };
    // Size grew.
    if big2.stat().size != want.len() as u64 {
        return TestResult::Fail("file size did not grow to appended length");
    }
    match read_all(&big2, want.len() + 16) {
        Some(got) if got == want => TestResult::Pass,
        _ => TestResult::Fail("remounted content mismatch after partial+append"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_partial_and_append_write);

// ── Data checksums (CSUM tree) ─────────────────────────────────────

/// Locate a file's inode number and the volume's csum-tree root.
fn csum_root_of(vol: &BtrfsVolume<narf_block::ram::RamBlockDevice>) -> Option<u64> {
    let (root_tree, _) = vol.root_tree_root();
    poll_once(crate::roots::find_root(
        vol,
        root_tree,
        format::CSUM_TREE_OBJECTID,
    ))?
    .ok()
    .map(|(r, _)| r)
}

/// Prove our CRC32C data-checksum computation matches what mkfs.btrfs wrote:
/// every on-disk sector of big.dat must match its stored csum in the CSUM tree.
/// If this passes, the write path's selected-checksum dispatcher emits
/// checksums a real Linux kernel will accept.
fn smoke_btrfs_data_csum_matches_mkfs() -> TestResult {
    use narf_filesystem::FsInstance;
    let vol = match mount_fixture() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fixture failed to mount"),
    };
    let (fs_root, _) = vol.fs_tree_root();
    let csum_root = match csum_root_of(&vol) {
        Some(r) => r,
        None => return TestResult::Fail("csum tree root not found"),
    };
    let big = match poll_once(vol.root().lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup big.dat failed"),
    };
    let ino = big.ino();
    match poll_once(crate::csum::verify_file_data_csums(
        &vol, fs_root, csum_root, ino,
    )) {
        Some(Ok(true)) => {}
        Some(Ok(false)) => {
            return TestResult::Fail("our data csum does not match mkfs's stored csum")
        }
        _ => return TestResult::Fail("csum verification errored"),
    }
    // Sanity: a wrong sector must NOT match (guards against a stub that always
    // returns true).
    let bad = match crate::csum::compute_csums(
        format::CSUM_TYPE_CRC32,
        b"not-the-real-sector-bytes",
        4096,
    ) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("compute_csums errored"),
    };
    if bad.len() != 4 {
        return TestResult::Fail("compute_csums produced wrong length");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_data_csum_matches_mkfs);

/// After a COW write, the new extent must carry correct data checksums in the
/// CSUM tree — the property a real Linux kernel needs to read the file. Verified
/// against the same CRC32C form proven to match mkfs above.
fn smoke_btrfs_write_emits_csums() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let vol = match mount_fixture() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    let big = match poll_once(vol.root().lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup big.dat failed"),
    };
    // Overwrite, then also append to exercise a grown extent's csums.
    let new = replacement_big();
    if !matches!(poll_once(big.write(0, &new)), Some(Ok(_))) {
        return TestResult::Fail("overwrite failed");
    }
    if !matches!(poll_once(big.write(12000, b"CSUM-TAIL\n")), Some(Ok(_))) {
        return TestResult::Fail("append failed");
    }

    // Remount and verify every sector of big.dat's (new) extent matches its
    // freshly written CSUM-tree entry.
    let vol2 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount failed"),
    };
    let (fs_root, _) = vol2.fs_tree_root();
    let csum_root = match csum_root_of(&vol2) {
        Some(r) => r,
        None => return TestResult::Fail("csum root not found after write"),
    };
    let big2 = match poll_once(vol2.root().lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("remount lookup failed"),
    };
    let ino = big2.ino();
    match poll_once(crate::csum::verify_file_data_csums(
        &vol2, fs_root, csum_root, ino,
    )) {
        Some(Ok(true)) => TestResult::Pass,
        Some(Ok(false)) => TestResult::Fail("written extent has wrong/missing data csums"),
        _ => TestResult::Fail("csum verification errored after write"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_write_emits_csums);

/// The data extent an inode's single EXTENT_DATA points at: `(disk_bytenr, len)`.
fn file_data_extent<B: narf_block::BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ino: u64,
) -> Option<(u64, u64)> {
    let (fs_root, _) = vol.fs_tree_root();
    let items = poll_once(btree::collect_for(
        vol,
        fs_root,
        ino,
        format::EXTENT_DATA_KEY,
    ))?
    .ok()?;
    let (_k, body) = items.first()?;
    Some((format::le64(body, 21).ok()?, format::le64(body, 29).ok()?))
}

fn data_extent_owner<B: narf_block::BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    logical: u64,
    length: u64,
) -> Option<u64> {
    let (root_tree, _) = vol.root_tree_root();
    let (extent_root, _) = poll_once(crate::roots::find_root(
        vol,
        root_tree,
        format::EXTENT_TREE_OBJECTID,
    ))?
    .ok()?;
    let body = poll_once(btree::find_item(
        vol,
        extent_root,
        &BtrfsKey::new(logical, format::EXTENT_ITEM_KEY, length),
    ))?
    .ok()??;
    if body.get(24).copied()? != 172 {
        return None;
    }
    format::le64(&body, 25).ok()
}

/// Whether the extent tree has an `EXTENT_ITEM` for `(logical, length)`.
fn extent_item_present<B: narf_block::BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    logical: u64,
    length: u64,
) -> bool {
    let (root_tree, _) = vol.root_tree_root();
    let Some(Ok((extent_root, _))) = poll_once(crate::roots::find_root(
        vol,
        root_tree,
        format::EXTENT_TREE_OBJECTID,
    )) else {
        return false;
    };
    let key = BtrfsKey::new(logical, format::EXTENT_ITEM_KEY, length);
    matches!(
        poll_once(btree::find_item(vol, extent_root, &key)),
        Some(Ok(Some(_)))
    )
}

/// After a COW write, the extent tree must record the new data extent and have
/// freed the old one — the accounting that makes the image `btrfs check`-clean
/// and Linux read-write-mountable. Regression-guards it in the in-kernel suite
/// (the host `btrfs check` runs only where btrfs-progs is installed).
fn smoke_btrfs_write_extent_accounting() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let vol = match mount_fixture() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    let big = match poll_once(vol.root().lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup big.dat failed"),
    };
    let ino = big.ino();
    let old_extent = match file_data_extent(&vol, ino) {
        Some(e) => e,
        None => return TestResult::Fail("could not read big.dat's extent"),
    };
    // The old extent is accounted before the write.
    if !extent_item_present(&vol, old_extent.0, old_extent.1) {
        return TestResult::Fail("pre-write extent not in extent tree");
    }

    if !matches!(poll_once(big.write(0, &replacement_big())), Some(Ok(_))) {
        return TestResult::Fail("write failed");
    }

    // Remount and inspect the extent tree.
    let vol2 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount failed"),
    };
    let big2 = match poll_once(vol2.root().lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("remount lookup failed"),
    };
    let new_extent = match file_data_extent(&vol2, big2.ino()) {
        Some(e) => e,
        None => return TestResult::Fail("could not read new extent"),
    };
    // The write must have moved the extent (genuine COW), recorded the new one,
    // and freed the old one.
    if new_extent.0 == old_extent.0 {
        return TestResult::Fail("extent was not COWed to a new location");
    }
    if !extent_item_present(&vol2, new_extent.0, new_extent.1) {
        return TestResult::Fail("new extent not recorded in extent tree");
    }
    if extent_item_present(&vol2, old_extent.0, old_extent.1) {
        return TestResult::Fail("old extent not freed from extent tree");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_write_extent_accounting);

/// A tree-log written by `write_log` must be replayed into the fs tree on the
/// next mount and then cleared — btrfs crash recovery. Records a modified
/// INODE_ITEM for a file into a log (leaving the fs tree untouched), then a
/// remount must merge it (the file's mtime changes) and zero `super.log_root`.
fn smoke_btrfs_tree_log_replay() -> TestResult {
    use narf_filesystem::FsInstance;

    let device = writable_sparse(FIXTURE_FST_SPARSE);
    let vol = match mount_writable(device.clone()) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let f = match poll_once(vol.root().create("logged.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create failed"),
    };
    let ino = f.ino();
    const COLLIDE_A: &str = "n5wrWL7foZTV";
    const COLLIDE_B: &str = "Vf5Y4fyl9fqh";
    if !matches!(poll_once(vol.root().create(COLLIDE_A)), Some(Ok(_)))
        || !matches!(poll_once(vol.root().create(COLLIDE_B)), Some(Ok(_)))
    {
        return TestResult::Fail("logged collision setup failed");
    }

    // Read the committed INODE_ITEM and log a copy with a distinctive mtime,
    // WITHOUT touching the fs tree — as a crashed fsync would leave it.
    let (fs_root, _) = vol.fs_tree_root();
    let key = BtrfsKey::new(ino, format::INODE_ITEM_KEY, 0);
    let mut body = match poll_once(btree::find_item(&vol, fs_root, &key)) {
        Some(Ok(Some(b))) => b,
        _ => return TestResult::Fail("could not read inode item"),
    };
    const MARK: u64 = 0x0011_2233_4455;
    body[136..144].copy_from_slice(&MARK.to_le_bytes()); // mtime seconds
    let collision_index = match poll_once(btree::collect_for(
        &vol,
        fs_root,
        vol.root().ino(),
        format::DIR_INDEX_KEY,
    )) {
        Some(Ok(items)) => items
            .into_iter()
            .find(|(_, item_body)| crate::dir::find_dir_item(item_body, COLLIDE_A).is_ok()),
        _ => None,
    };
    let Some(collision_index) = collision_index else {
        return TestResult::Fail("logged collision index missing");
    };
    if !matches!(
        poll_once(crate::write::write_log(
            &vol,
            &[(key, body), collision_index]
        )),
        Some(Ok(()))
    ) {
        return TestResult::Fail("write_log failed");
    }
    // The log is pending (fs tree unchanged: the live mtime is still 0).
    if format::le64(&read_super_at(&device, format::SUPERBLOCK_OFFSET), 96).unwrap_or(0) == 0 {
        return TestResult::Fail("super.log_root not set after write_log");
    }
    if poll_once(f.statx_async(0, 0x7ff))
        .and_then(|r| r.ok())
        .map(|s| s.mtime.seconds)
        == Some(MARK as i64)
    {
        return TestResult::Fail("log leaked into the fs tree before replay");
    }

    // Remount: replay must merge the logged inode and clear the log pointer.
    let vol2 = match mount_writable(device.clone()) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("remount (replay) failed"),
    };
    if format::le64(&read_super_at(&device, format::SUPERBLOCK_OFFSET), 96).unwrap_or(1) != 0 {
        return TestResult::Fail("super.log_root not cleared after replay");
    }
    let f2 = match poll_once(vol2.root().lookup_async("logged.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("file missing after replay"),
    };
    match poll_once(f2.statx_async(0, 0x7ff)) {
        Some(Ok(sx)) if sx.mtime.seconds == MARK as i64 => {}
        _ => return TestResult::Fail("logged mtime not applied by replay"),
    }
    if !matches!(poll_once(vol2.root().lookup_async(COLLIDE_A)), Some(Ok(_)))
        || !matches!(poll_once(vol2.root().lookup_async(COLLIDE_B)), Some(Ok(_)))
    {
        return TestResult::Fail("tree-log replay damaged collision bucket");
    }
    // A subsequent remount finds no log (idempotent) and the state persists.
    let vol3 = match mount_writable(device) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("second remount failed"),
    };
    match poll_once(vol3.root().lookup_async("logged.txt")) {
        Some(Ok(_)) => TestResult::Pass,
        _ => TestResult::Fail("file lost after replay persisted"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_tree_log_replay);

/// Tree-log mappings are keyed by subvolume id, not hard-coded to FS_TREE. A
/// pending log emitted while a child is mounted must be replayed during the
/// next ordinary top-level mount, before mount-option selection.
fn smoke_btrfs_subvolume_tree_log_replay() -> TestResult {
    use narf_filesystem::FsInstance;

    let device = writable_sparse(FIXTURE_FST_SPARSE);
    let top = match mount_writable(device.clone()) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("subvolume-log fixture failed to mount"),
    };
    let mut args = alloc::vec![0u8; 4096];
    args[56..64].copy_from_slice(b"logchild");
    if !matches!(
        poll_once(
            top.root()
                .ioctl_async(crate::node::BTRFS_IOC_SUBVOL_CREATE_V2, 0, &args, 0,)
        ),
        Some(Ok(_))
    ) {
        return TestResult::Fail("log child creation failed");
    }
    let child = match poll_once(BtrfsVolume::mount_subvol(
        narf_block::SyncBlock::new(device.clone() as Arc<dyn narf_block::BlockDeviceSync>),
        DomainId::DRIVER_0,
        true,
        Some(crate::volume::Subvol::Name("logchild".into())),
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("log child mount failed"),
    };
    let file = match poll_once(child.root().create("pending")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("log child file creation failed"),
    };
    let key = BtrfsKey::new(file.ino(), format::INODE_ITEM_KEY, 0);
    let mut inode = match poll_once(btree::find_item(&*child, child.fs_tree_root().0, &key)) {
        Some(Ok(Some(body))) => body,
        _ => return TestResult::Fail("log child inode missing"),
    };
    const MARK: u64 = 0x0055_6677_8899;
    inode[136..144].copy_from_slice(&MARK.to_le_bytes());
    if !matches!(
        poll_once(crate::write::write_log(&child, &[(key, inode)])),
        Some(Ok(()))
    ) {
        return TestResult::Fail("nested-subvolume write_log failed");
    }

    let replayed_top = match mount_writable(device.clone()) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("top-level mount did not replay child log"),
    };
    if replayed_top.superblock().log_root != 0 {
        return TestResult::Fail("child log pointer survived replay");
    }
    let replayed_child = match poll_once(BtrfsVolume::mount_subvol(
        narf_block::SyncBlock::new(device as Arc<dyn narf_block::BlockDeviceSync>),
        DomainId::DRIVER_0,
        true,
        Some(crate::volume::Subvol::Name("logchild".into())),
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("replayed child did not remount"),
    };
    let file = match poll_once(replayed_child.root().lookup_async("pending")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("replayed child file missing"),
    };
    match poll_once(file.statx_async(0, 0x7ff)) {
        Some(Ok(stat)) if stat.mtime.seconds == MARK as i64 => TestResult::Pass,
        _ => TestResult::Fail("nested-subvolume log item was not replayed"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_subvolume_tree_log_replay);

/// A modern `DIR_LOG_INDEX` range makes the log authoritative for a span of
/// directory indexes. Entries absent from the log are deletions: replay must
/// unlink a data-bearing file and rmdir an empty directory, preserve an entry
/// present in the log, free the removed file's extent, and never copy the
/// log-only range marker into the FS tree.
fn smoke_btrfs_tree_log_deletion_replay() -> TestResult {
    use narf_filesystem::FsInstance;

    let device = writable_sparse(FIXTURE_FST_SPARSE);
    let vol = match mount_writable(device.clone()) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let root = vol.root();
    let parent = root.ino();
    let doomed = match poll_once(root.create("log-gone.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("doomed file create failed"),
    };
    if !matches!(
        poll_once(doomed.write(0, b"tree-log deletion payload\n")),
        Some(Ok(_))
    ) {
        return TestResult::Fail("doomed file write failed");
    }
    let old_extent = match file_data_extent(&vol, doomed.ino()) {
        Some(extent) => extent,
        None => return TestResult::Fail("doomed file extent missing"),
    };
    let keep = match poll_once(root.create("log-keep.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("kept file create failed"),
    };
    if !matches!(poll_once(keep.write(0, b"keep\n")), Some(Ok(_))) {
        return TestResult::Fail("kept file write failed");
    }
    if !matches!(poll_once(root.mkdir("log-gone-dir")), Some(Ok(_))) {
        return TestResult::Fail("doomed directory create failed");
    }

    // The three freshly-created entries have consecutive high directory indexes.
    // Log the middle entry and an authoritative range spanning all three: the two
    // absent names must be removed on replay.
    let (fs_root, _) = vol.fs_tree_root();
    let indices = match poll_once(btree::collect_for(
        &vol,
        fs_root,
        parent,
        format::DIR_INDEX_KEY,
    )) {
        Some(Ok(items)) => items,
        _ => return TestResult::Fail("directory indexes unavailable"),
    };
    let mut gone_index = None;
    let mut keep_item = None;
    let mut gone_dir_index = None;
    for (key, body) in indices {
        let entries = match crate::dir::decode_dir_items(&body) {
            Ok(entries) => entries,
            Err(_) => return TestResult::Fail("directory index malformed"),
        };
        if entries.len() != 1 {
            return TestResult::Fail("directory index contains multiple names");
        }
        match entries[0].name.as_str() {
            "log-gone.txt" => gone_index = Some(key.offset),
            "log-keep.txt" => keep_item = Some((key, body)),
            "log-gone-dir" => gone_dir_index = Some(key.offset),
            _ => {}
        }
    }
    let (gone_index, (keep_key, keep_body), gone_dir_index) =
        match (gone_index, keep_item, gone_dir_index) {
            (Some(a), Some(b), Some(c)) => (a, b, c),
            _ => return TestResult::Fail("new directory indexes not found"),
        };
    let range_start = gone_index.min(keep_key.offset).min(gone_dir_index);
    let range_end = gone_index.max(keep_key.offset).max(gone_dir_index);
    if range_end - range_start != 2 {
        return TestResult::Fail("new directory indexes are not consecutive");
    }
    let range_key = BtrfsKey::new(parent, format::DIR_LOG_INDEX_KEY, range_start);
    let log_items = [
        (range_key, range_end.to_le_bytes().to_vec()),
        (keep_key, keep_body),
    ];
    if !matches!(
        poll_once(crate::write::write_log(&vol, &log_items)),
        Some(Ok(()))
    ) {
        return TestResult::Fail("deletion-range write_log failed");
    }
    // A log is only an overlay: committed names remain visible before replay.
    if poll_once(root.lookup_async("log-gone.txt"))
        .and_then(|r| r.ok())
        .is_none()
        || poll_once(root.lookup_dir_async("log-gone-dir"))
            .and_then(|r| r.ok())
            .is_none()
    {
        return TestResult::Fail("deletion became visible before replay");
    }

    let vol2 = match mount_writable(device.clone()) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("deletion replay mount failed"),
    };
    let root2 = vol2.root();
    if !matches!(
        poll_once(root2.lookup_async("log-gone.txt")),
        Some(Err(FsError::NotFound))
    ) || !matches!(
        poll_once(root2.lookup_dir_async("log-gone-dir")),
        Some(Err(FsError::NotFound))
    ) {
        return TestResult::Fail("log-recorded deletions were not replayed");
    }
    let keep2 = match poll_once(root2.lookup_async("log-keep.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("logged survivor was removed"),
    };
    if read_all(&keep2, 16).as_deref() != Some(b"keep\n") {
        return TestResult::Fail("logged survivor content changed");
    }
    if extent_item_present(&vol2, old_extent.0, old_extent.1) {
        return TestResult::Fail("deleted file extent was not freed");
    }
    let (fs_root2, _) = vol2.fs_tree_root();
    if !matches!(
        poll_once(btree::find_item(&vol2, fs_root2, &range_key)),
        Some(Ok(None))
    ) {
        return TestResult::Fail("DIR_LOG_INDEX leaked into the fs tree");
    }
    if format::le64(&read_super_at(&device, format::SUPERBLOCK_OFFSET), 96).unwrap_or(1) != 0 {
        return TestResult::Fail("log root not cleared after deletion replay");
    }

    // A second mount has no log to replay and preserves both absence/presence.
    let vol3 = match mount_writable(device) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("post-deletion second mount failed"),
    };
    if !matches!(
        poll_once(vol3.root().lookup_async("log-gone.txt")),
        Some(Err(FsError::NotFound))
    ) || poll_once(vol3.root().lookup_async("log-keep.txt"))
        .and_then(|r| r.ok())
        .is_none()
    {
        return TestResult::Fail("deletion replay was not idempotent");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_tree_log_deletion_replay);

/// Every block (root + internals + leaves) the fs tree currently occupies.
fn fs_tree_blocks<B: narf_block::BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
) -> Option<alloc::collections::BTreeSet<u64>> {
    let (fs_root, _) = vol.fs_tree_root();
    let mut set = alloc::collections::BTreeSet::new();
    let mut stack = alloc::vec![fs_root];
    while let Some(addr) = stack.pop() {
        let node = poll_once(vol.read_node(addr))?.ok()?;
        set.insert(addr);
        if btree::level(&node).ok()? > 0 {
            for i in 0..btree::nritems(&node).ok()? as usize {
                stack.push(btree::internal_blockptr(&node, i).ok()?);
            }
        }
    }
    Some(set)
}

/// A namespace mutation must path-COW the fs tree — rewrite only the touched
/// root-to-leaf path — not rebuild the whole tree. On a multi-leaf tree a single
/// `create` should therefore share almost every block with the pre-create tree;
/// a whole-tree repack would share none. Guards the `O(fs size)` → `O(log N)`
/// property the namespace ops were converted to.
fn smoke_btrfs_namespace_create_is_path_cow() -> TestResult {
    use alloc::format;
    use narf_filesystem::FsInstance;

    let device = writable_sparse(FIXTURE_FST_SPARSE);
    let vol = match mount_writable(device.clone()) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    // Grow the fs tree to several leaves so path-COW sharing is observable.
    for i in 0..90 {
        if !matches!(
            poll_once(vol.root().create(&format!("f{i:03}"))),
            Some(Ok(_))
        ) {
            return TestResult::Fail("setup create failed");
        }
    }
    let before = match fs_tree_blocks(&vol) {
        Some(s) => s,
        None => return TestResult::Fail("could not walk fs tree"),
    };
    if before.len() < 3 {
        return TestResult::Fail("fs tree stayed single-leaf; test not meaningful");
    }

    if !matches!(poll_once(vol.root().create("one_more")), Some(Ok(_))) {
        return TestResult::Fail("create failed");
    }
    let after = match fs_tree_blocks(&vol) {
        Some(s) => s,
        None => return TestResult::Fail("could not re-walk fs tree"),
    };

    // Only the COWed path is new; the rest of the tree is shared in place.
    let rewritten = after.difference(&before).count();
    if rewritten >= before.len() {
        return TestResult::Fail("whole fs tree rewritten — not path-COW");
    }
    // Everything must still be readable after the shared-block create.
    let names = dir_names(&vol.root());
    if !names.iter().any(|n| n == "one_more") || !names.iter().any(|n| n == "f000") {
        return TestResult::Fail("entries lost after path-COW create");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_namespace_create_is_path_cow);

/// The superblock's `bytes_used` field.
fn super_bytes_used(dev: &WritableSparseDevice) -> u64 {
    let raw = read_super_at(dev, format::SUPERBLOCK_OFFSET);
    format::le64(&raw, 120).unwrap_or(u64::MAX)
}

/// Sum of every `BLOCK_GROUP_ITEM.used` in the extent tree — the value the
/// superblock's `bytes_used` must equal.
fn sum_block_group_used<B: narf_block::BlockDevice + 'static>(vol: &BtrfsVolume<B>) -> Option<u64> {
    let (root_tree, _) = vol.root_tree_root();
    let (ext_root, _) = poll_once(crate::roots::find_root(
        vol,
        root_tree,
        format::EXTENT_TREE_OBJECTID,
    ))?
    .ok()?;
    let mut cursor =
        poll_once(btree::Cursor::seek(vol, ext_root, &BtrfsKey::new(0, 0, 0)))?.ok()?;
    let mut total = 0u64;
    while let Some((key, body)) = cursor.current().ok()? {
        if key.item_type == format::BLOCK_GROUP_ITEM_KEY {
            total += format::le64(body, 0).ok()?;
        }
        poll_once(cursor.advance())?.ok()?;
    }
    Some(total)
}

/// The superblock's `bytes_used` must always equal the sum of every block
/// group's `used`. The extent tree is path-COWed while csum/root/free-space are
/// whole-repacked, so a per-block accounting slip (double-charged reuse, a
/// dropped delta) silently desyncs the counter — exactly what a host `btrfs
/// check` flags as "super bytes used … mismatches actual used". This guards it
/// across a multi-extent overwrite, a create, and an unlink, including a grow.
fn smoke_btrfs_bytes_used_matches_block_groups() -> TestResult {
    use narf_filesystem::FsInstance;

    let device = writable_sparse(FIXTURE_FST_SPARSE);
    let vol = match mount_writable(device.clone()) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };

    // A mix of mutations that exercise both commit paths and a chunk grow.
    let f = match poll_once(vol.root().create("accounting.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create failed"),
    };
    let payload = alloc::vec![0xa5u8; 300 * 1024]; // multi-extent
    if !matches!(poll_once(f.write(0, &payload)), Some(Ok(_))) {
        return TestResult::Fail("write failed");
    }
    if !matches!(poll_once(f.write(0, &payload[..64 * 1024])), Some(Ok(_))) {
        return TestResult::Fail("overwrite failed");
    }
    if !matches!(poll_once(crate::write::grow_add_chunk(&vol)), Some(Ok(()))) {
        return TestResult::Fail("grow failed");
    }
    if !matches!(poll_once(vol.root().create("tiny.txt")), Some(Ok(_))) {
        return TestResult::Fail("post-grow create failed");
    }
    if !matches!(poll_once(vol.root().unlink("accounting.dat")), Some(Ok(()))) {
        return TestResult::Fail("unlink failed");
    }

    let vol2 = match mount_writable(device.clone()) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("remount failed"),
    };
    let summed = match sum_block_group_used(&vol2) {
        Some(t) => t,
        None => return TestResult::Fail("could not sum block groups"),
    };
    if super_bytes_used(&device) != summed {
        return TestResult::Fail("super bytes_used desynced from block groups");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_bytes_used_matches_block_groups
);

// ── Free-space tree (space_cache=v2) write maintenance ─────────────

/// Every `FREE_SPACE_EXTENT` `(start, len)` in the volume's free-space tree.
/// The fixture's block groups are small enough to be tracked in extent mode
/// (no `FREE_SPACE_BITMAP` items), which is the only mode the write path emits.
fn fst_free_extents(vol: &BtrfsVolume<narf_block::ram::RamBlockDevice>) -> Option<Vec<(u64, u64)>> {
    let (root_tree, _) = vol.root_tree_root();
    let (fst_root, _) = poll_once(crate::roots::find_root(
        vol,
        root_tree,
        format::FREE_SPACE_TREE_OBJECTID,
    ))?
    .ok()?;
    let start = BtrfsKey::new(0, format::FREE_SPACE_EXTENT_KEY, 0);
    let mut cursor = poll_once(btree::Cursor::seek(vol, fst_root, &start))?.ok()?;
    let mut out = Vec::new();
    while let Some((key, _)) = cursor.current().ok()? {
        if key.item_type == format::FREE_SPACE_EXTENT_KEY {
            out.push((key.objectid, key.offset));
        }
        poll_once(cursor.advance())?.ok()?;
    }
    Some(out)
}

/// Whether `[start, start+len)` lies entirely within a single free extent.
fn fst_range_is_free(free: &[(u64, u64)], start: u64, len: u64) -> bool {
    free.iter()
        .any(|&(s, l)| s <= start && start.saturating_add(len) <= s.saturating_add(l))
}

/// After a COW write on a `space_cache=v2` image, the free-space tree must track
/// the allocation: the new data extent's range is no longer free, and the old
/// extent's range is freed. This is what keeps the free-space tree valid so a
/// real Linux kernel mounts the image read-write without rebuilding it (host
/// `btrfs check` regression-guards the same property where btrfs-progs exists).
fn smoke_btrfs_write_fst_maintenance() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    let big = match poll_once(vol.root().lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup big.dat failed"),
    };
    let ino = big.ino();
    let old_extent = match file_data_extent(&vol, ino) {
        Some(e) => e,
        None => return TestResult::Fail("could not read big.dat's extent"),
    };
    // Pre-write: the old extent's range is allocated (not free) in the FST.
    let pre_free = match fst_free_extents(&vol) {
        Some(f) => f,
        None => return TestResult::Fail("free-space tree not found (is this a v2 image?)"),
    };
    if fst_range_is_free(&pre_free, old_extent.0, old_extent.1) {
        return TestResult::Fail("live extent marked free in FST before write");
    }

    if !matches!(poll_once(big.write(0, &replacement_big())), Some(Ok(_))) {
        return TestResult::Fail("write failed");
    }

    // Remount from disk and inspect the free-space tree.
    let vol2 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount after write failed"),
    };
    let big2 = match poll_once(vol2.root().lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("remount lookup failed"),
    };
    let new_extent = match file_data_extent(&vol2, big2.ino()) {
        Some(e) => e,
        None => return TestResult::Fail("could not read new extent"),
    };
    if new_extent.0 == old_extent.0 {
        return TestResult::Fail("extent was not COWed to a new location");
    }
    let post_free = match fst_free_extents(&vol2) {
        Some(f) => f,
        None => return TestResult::Fail("free-space tree missing after write"),
    };
    // The new extent is now allocated (carved out of a free extent)…
    if fst_range_is_free(&post_free, new_extent.0, new_extent.1) {
        return TestResult::Fail("new extent still marked free in FST");
    }
    // …and the old extent's range has been returned to the free-space tree.
    if !fst_range_is_free(&post_free, old_extent.0, old_extent.1) {
        return TestResult::Fail("old extent not freed in FST");
    }
    // Content round-trips through the FST-maintaining write path.
    match read_all(&big2, replacement_big().len() + 16) {
        Some(got) if got == replacement_big() => TestResult::Pass,
        _ => TestResult::Fail("content mismatch after FST write"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_write_fst_maintenance);

// ── Namespace mutations (create / unlink) ──────────────────────────

/// Sorted entry names of a directory (via `enumerate_async`).
fn dir_names(dir: &Arc<dyn narf_filesystem::DirOps>) -> Vec<alloc::string::String> {
    match poll_once(dir.enumerate_async(0, 1024)) {
        Some(Ok(e)) => e.into_iter().map(|(n, _)| n).collect(),
        _ => Vec::new(),
    }
}

/// `create` inserts a new empty regular file whose inode, back-ref and directory
/// entries land on disk: it survives a remount, `lookup`s, `enumerate`s, and
/// `stat`s as a zero-length file — while the pre-existing entries are untouched.
/// Runs on the `space_cache=v2` fixture so create also maintains the free-space
/// tree (host `btrfs check` in the boot smoke guards on-disk validity).
fn smoke_btrfs_create_file() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    let created = match poll_once(vol.root().create("newfile.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create failed"),
    };
    if created.stat().size != 0 {
        return TestResult::Fail("new file is not empty");
    }

    // Remount from disk: the create must be durable and self-consistent.
    let vol2 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount after create failed"),
    };
    let root2 = vol2.root();
    let names = dir_names(&root2);
    for want in ["newfile.txt", "hello.txt", "big.dat"] {
        if !names.iter().any(|n| n == want) {
            return TestResult::Fail("listing missing an expected entry after create");
        }
    }
    match poll_once(root2.lookup_async("newfile.txt")) {
        Some(Ok(f)) => {
            if f.stat().size != 0 || f.stat().mode.file_type != narf_filesystem::FileType::File {
                return TestResult::Fail("remounted new file wrong size/type");
            }
        }
        _ => return TestResult::Fail("remount lookup of new file failed"),
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_create_file);

/// A `create`d empty file is then writable: the write allocates the file's first
/// data extent (inserting a fresh `EXTENT_DATA`), and after a remount the content
/// and size read back. Proves `create` + `write` compose end to end.
fn smoke_btrfs_write_created_file() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    let created = match poll_once(vol.root().create("written.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create failed"),
    };
    let payload = b"hello from a freshly created btrfs file\n";
    match poll_once(created.write(0, payload)) {
        Some(Ok(n)) if n == payload.len() => {}
        _ => return TestResult::Fail("write to created file failed"),
    }

    // Remount from disk: the created file's new extent must be durable.
    let vol2 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount after write-to-created failed"),
    };
    let f2 = match poll_once(vol2.root().lookup_async("written.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("remount lookup of created file failed"),
    };
    if f2.stat().size != payload.len() as u64 {
        return TestResult::Fail("created file size wrong after write");
    }
    match read_all(&f2, payload.len() + 16) {
        Some(got) if got == payload => TestResult::Pass,
        _ => TestResult::Fail("created file content mismatch after remount"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_write_created_file);

/// A create then unlink round-trips: the file is gone after unlink (remounted),
/// the pre-existing entries remain, and the volume still mounts cleanly.
fn smoke_btrfs_create_then_unlink() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    if !matches!(poll_once(vol.root().create("scratch.tmp")), Some(Ok(_))) {
        return TestResult::Fail("create failed");
    }
    match poll_once(vol.root().unlink("scratch.tmp")) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("unlink failed"),
    }

    let vol2 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount after unlink failed"),
    };
    let root2 = vol2.root();
    if poll_once(root2.lookup_async("scratch.tmp")).is_some_and(|r| r.is_ok()) {
        return TestResult::Fail("unlinked file still present after remount");
    }
    let names = dir_names(&root2);
    for want in ["hello.txt", "big.dat"] {
        if !names.iter().any(|n| n == want) {
            return TestResult::Fail("unlink collaterally removed an entry");
        }
    }
    if names.iter().any(|n| n == "scratch.tmp") {
        return TestResult::Fail("unlinked name still listed");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_create_then_unlink);

/// Unlinking a file that owns a data extent frees the extent and its checksum:
/// after remount the name and its `EXTENT_ITEM` are gone, while a sibling file is
/// still readable. Uses the plain (no free-space-tree) fixture, so this also
/// covers the non-FST unlink path.
fn smoke_btrfs_unlink_file_with_data() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let vol = match mount_fixture() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    let big = match poll_once(vol.root().lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup big.dat failed"),
    };
    let extent = match file_data_extent(&vol, big.ino()) {
        Some(e) => e,
        None => return TestResult::Fail("could not read big.dat's extent"),
    };
    if !extent_item_present(&vol, extent.0, extent.1) {
        return TestResult::Fail("pre-unlink extent not in extent tree");
    }

    match poll_once(vol.root().unlink("big.dat")) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("unlink big.dat failed"),
    }

    let vol2 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount after unlink failed"),
    };
    // big.dat is gone…
    if poll_once(vol2.root().lookup_async("big.dat")).is_some_and(|r| r.is_ok()) {
        return TestResult::Fail("big.dat still present after unlink");
    }
    // …its data extent is freed from the extent tree…
    if extent_item_present(&vol2, extent.0, extent.1) {
        return TestResult::Fail("freed data extent still in extent tree");
    }
    // …and a sibling file still reads correctly.
    match poll_once(vol2.root().lookup_async("hello.txt")) {
        Some(Ok(f)) => match read_all(&f, 64) {
            Some(got) if got == b"narf\n" => TestResult::Pass,
            _ => TestResult::Fail("sibling hello.txt content wrong after unlink"),
        },
        _ => TestResult::Fail("sibling hello.txt lookup failed after unlink"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_unlink_file_with_data);

/// `mkdir` creates a real, navigable, empty directory (nlink 1, listed by the
/// parent), and `rmdir` removes it — both surviving a remount. Runs on the
/// `space_cache=v2` fixture (host `btrfs check` in the boot smoke guards on-disk
/// validity).
fn smoke_btrfs_mkdir_and_rmdir() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    if !matches!(poll_once(vol.root().mkdir("sub")), Some(Ok(_))) {
        return TestResult::Fail("mkdir failed");
    }

    // Remount: the directory must be durable, navigable and empty.
    let vol2 = match poll_once(BtrfsVolume::mount(device.clone(), DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount after mkdir failed"),
    };
    let root2 = vol2.root();
    if !dir_names(&root2).iter().any(|n| n == "sub") {
        return TestResult::Fail("mkdir'd directory not listed");
    }
    match poll_once(root2.lookup_dir_async("sub")) {
        Some(Ok(d)) => {
            if !dir_names(&d).is_empty() {
                return TestResult::Fail("new directory is not empty");
            }
        }
        _ => return TestResult::Fail("mkdir'd directory not navigable"),
    }

    // Remove it and confirm the removal persists.
    match poll_once(root2.rmdir("sub")) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("rmdir failed"),
    }
    let vol3 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount after rmdir failed"),
    };
    let root3 = vol3.root();
    if poll_once(root3.lookup_dir_async("sub")).is_some_and(|r| r.is_ok()) {
        return TestResult::Fail("directory still present after rmdir");
    }
    for want in ["hello.txt", "big.dat"] {
        if !dir_names(&root3).iter().any(|n| n == want) {
            return TestResult::Fail("rmdir collaterally removed an entry");
        }
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_mkdir_and_rmdir);

/// Xattrs do not make an otherwise-empty directory non-empty. `rmdir` removes
/// every XATTR_ITEM with the inode in the same COW transaction.
fn smoke_btrfs_rmdir_xattr_directory() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    let root = vol.root();
    if !matches!(poll_once(root.mkdir("xdir")), Some(Ok(_))) {
        return TestResult::Fail("mkdir for xattr rmdir failed");
    }
    let xdir = match poll_once(root.lookup_async("xdir")) {
        Some(Ok(node)) => node,
        _ => return TestResult::Fail("xattr directory lookup failed"),
    };
    if !matches!(
        poll_once(xdir.set_xattr("user.narf", b"directory", 0)),
        Some(Ok(()))
    ) {
        return TestResult::Fail("directory setxattr failed");
    }
    if !matches!(poll_once(root.rmdir("xdir")), Some(Ok(()))) {
        return TestResult::Fail("rmdir rejected an xattr-only directory");
    }

    let remount = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount after xattr rmdir failed"),
    };
    if poll_once(remount.root().lookup_dir_async("xdir")).is_some_and(|r| r.is_ok()) {
        return TestResult::Fail("xattr directory survived rmdir");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_rmdir_xattr_directory);

/// `rmdir` of a non-empty directory is refused (`Busy`), and a file created
/// inside a `mkdir`'d directory is navigable after a remount (nested write).
fn smoke_btrfs_rmdir_nonempty_rejected() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    let sub = match poll_once(vol.root().mkdir("full")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("mkdir failed"),
    };
    if !matches!(poll_once(sub.create("inside.txt")), Some(Ok(_))) {
        return TestResult::Fail("create inside new directory failed");
    }
    // rmdir must refuse a non-empty directory.
    if !matches!(
        poll_once(vol.root().rmdir("full")),
        Some(Err(FsError::Busy))
    ) {
        return TestResult::Fail("rmdir of non-empty directory was not refused");
    }

    // Remount: the directory and its child are intact.
    let vol2 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount failed"),
    };
    match poll_once(vol2.root().lookup_dir_async("full")) {
        Some(Ok(d)) => {
            if !dir_names(&d).iter().any(|n| n == "inside.txt") {
                return TestResult::Fail("nested file missing after remount");
            }
        }
        _ => return TestResult::Fail("directory missing after remount"),
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_rmdir_nonempty_rejected);

/// `rename` re-keys a file's directory entries within a directory: the old name
/// disappears, the new name resolves to the same content, and the change is
/// durable across a remount.
fn smoke_btrfs_rename_file() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let vol = match mount_fixture() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    let want = expected_big();
    match poll_once(vol.root().rename("big.dat", "renamed.dat")) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("rename failed"),
    }

    let vol2 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount after rename failed"),
    };
    let root2 = vol2.root();
    if poll_once(root2.lookup_async("big.dat")).is_some_and(|r| r.is_ok()) {
        return TestResult::Fail("old name still present after rename");
    }
    match poll_once(root2.lookup_async("renamed.dat")) {
        Some(Ok(f)) => match read_all(&f, want.len() + 16) {
            Some(got) if got == want => TestResult::Pass,
            _ => TestResult::Fail("renamed file content changed"),
        },
        _ => TestResult::Fail("new name not found after rename"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_rename_file);

/// `rename` re-keys a directory to a free name (and rejects renaming a file onto
/// a directory — a kind mismatch).
fn smoke_btrfs_rename_dir() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    if !matches!(poll_once(vol.root().mkdir("old")), Some(Ok(_)))
        || !matches!(poll_once(vol.root().create("afile")), Some(Ok(_)))
    {
        return TestResult::Fail("setup failed");
    }
    // A file cannot be renamed onto a directory (kind mismatch → InvalidData).
    if !matches!(
        poll_once(vol.root().rename("afile", "old")),
        Some(Err(FsError::InvalidData))
    ) {
        return TestResult::Fail("file→dir rename was not refused");
    }
    // Renaming a directory to a free name succeeds.
    match poll_once(vol.root().rename("old", "fresh")) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("directory rename failed"),
    }

    let vol2 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount after rename failed"),
    };
    let root2 = vol2.root();
    if poll_once(root2.lookup_dir_async("old")).is_some_and(|r| r.is_ok()) {
        return TestResult::Fail("old directory name still present");
    }
    if !matches!(poll_once(root2.lookup_dir_async("fresh")), Some(Ok(_))) {
        return TestResult::Fail("renamed directory not found");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_rename_dir);

/// `rename` onto an existing file atomically replaces it: the destination ends up
/// with the source's content, the source name is gone, and the clobbered file's
/// old data extent is freed from the extent tree (the QSaveFile pattern).
fn smoke_btrfs_rename_overwrite_file() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    // Source: a freshly written file. Destination: the fixture's big.dat.
    let src = match poll_once(vol.root().create("staging.tmp")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create source failed"),
    };
    let payload = b"atomically-replaced-content\n";
    if !matches!(poll_once(src.write(0, payload)), Some(Ok(_))) {
        return TestResult::Fail("write source failed");
    }
    // Record big.dat's data extent so we can prove it is freed on overwrite.
    let dst_extent = match poll_once(vol.root().lookup_async("big.dat")) {
        Some(Ok(f)) => file_data_extent(&vol, f.ino()),
        _ => None,
    };

    match poll_once(vol.root().rename("staging.tmp", "big.dat")) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("overwrite rename failed"),
    }

    let vol2 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount after overwrite rename failed"),
    };
    let root2 = vol2.root();
    if poll_once(root2.lookup_async("staging.tmp")).is_some_and(|r| r.is_ok()) {
        return TestResult::Fail("source name still present after overwrite");
    }
    // big.dat now holds the source's content…
    match poll_once(root2.lookup_async("big.dat")) {
        Some(Ok(f)) => match read_all(&f, payload.len() + 16) {
            Some(got) if got == payload => {}
            _ => return TestResult::Fail("destination content not replaced"),
        },
        _ => return TestResult::Fail("destination missing after overwrite"),
    }
    // …and the clobbered file's old data extent is gone from the extent tree.
    if let Some((bytenr, len)) = dst_extent {
        if extent_item_present(&vol2, bytenr, len) {
            return TestResult::Fail("overwritten file's data extent not freed");
        }
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_rename_overwrite_file);

/// Rename-overwrite edits hardlink refs record-by-record: hardlinked source and
/// target peers survive with correct link counts/data/xattrs, while a last-link
/// target (and an ordinary last-link unlink) reclaims its xattr items.
fn smoke_btrfs_rename_hardlink_xattr_overwrite() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    let root = vol.root();

    // Both source and destination have a peer in the same packed INODE_REF.
    let source = match poll_once(root.create("rename-source")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("same-dir source creation failed"),
    };
    let source_ino = source.ino();
    let source_data = b"same-dir source\n";
    if !matches!(poll_once(source.write(0, source_data)), Some(Ok(_)))
        || !matches!(
            poll_once(source.set_xattr("user.source", b"kept", 0)),
            Some(Ok(()))
        )
        || !matches!(
            poll_once(root.link("rename-source", "rename-source-peer")),
            Some(Ok(()))
        )
    {
        return TestResult::Fail("same-dir source setup failed");
    }
    let victim = match poll_once(root.create("rename-target")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("same-dir target creation failed"),
    };
    let victim_ino = victim.ino();
    let victim_data = b"same-dir victim\n";
    if !matches!(poll_once(victim.write(0, victim_data)), Some(Ok(_)))
        || !matches!(
            poll_once(victim.set_xattr("user.victim", b"survives", 0)),
            Some(Ok(()))
        )
        || !matches!(
            poll_once(root.link("rename-target", "rename-target-peer")),
            Some(Ok(()))
        )
        || !matches!(
            poll_once(root.rename("rename-source", "rename-target")),
            Some(Ok(()))
        )
    {
        return TestResult::Fail("same-dir hardlink overwrite failed");
    }

    // A last-link xattr-bearing destination is reclaimed completely.
    let doomed = match poll_once(root.create("rename-doomed")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("last-link target creation failed"),
    };
    let doomed_ino = doomed.ino();
    if !matches!(
        poll_once(doomed.set_xattr("user.doomed", b"remove", 0)),
        Some(Ok(()))
    ) {
        return TestResult::Fail("last-link target xattr setup failed");
    }
    let replacement = match poll_once(root.create("rename-replacement")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("last-link replacement creation failed"),
    };
    let replacement_data = b"replacement\n";
    if !matches!(
        poll_once(replacement.write(0, replacement_data)),
        Some(Ok(_))
    ) || !matches!(
        poll_once(root.rename("rename-replacement", "rename-doomed")),
        Some(Ok(()))
    ) {
        return TestResult::Fail("xattr-bearing last-link overwrite failed");
    }

    // Last-link unlink follows the same inode teardown rule.
    let unlinked = match poll_once(root.create("unlink-xattr")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("xattr unlink target creation failed"),
    };
    let unlinked_ino = unlinked.ino();
    if !matches!(
        poll_once(unlinked.set_xattr("user.unlink", b"remove", 0)),
        Some(Ok(()))
    ) || !matches!(poll_once(root.unlink("unlink-xattr")), Some(Ok(())))
    {
        return TestResult::Fail("xattr-bearing unlink failed");
    }

    // Cross-directory: the source already has a peer in the destination and
    // the overwritten target has another peer there too.
    if !matches!(poll_once(root.mkdir("rename-src-dir")), Some(Ok(_)))
        || !matches!(poll_once(root.mkdir("rename-dst-dir")), Some(Ok(_)))
    {
        return TestResult::Fail("cross-dir setup mkdir failed");
    }
    let src_dir = match poll_once(root.lookup_dir_async("rename-src-dir")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("cross-dir source lookup failed"),
    };
    let dst_dir = match poll_once(root.lookup_dir_async("rename-dst-dir")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("cross-dir destination lookup failed"),
    };
    let cross_source = match poll_once(src_dir.create("cross-source")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("cross-dir source creation failed"),
    };
    let cross_source_ino = cross_source.ino();
    let cross_source_data = b"cross-dir source\n";
    if !matches!(
        poll_once(cross_source.write(0, cross_source_data)),
        Some(Ok(_))
    ) || !matches!(
        poll_once(src_dir.link_to("cross-source", &*dst_dir, "cross-source-peer")),
        Some(Ok(()))
    ) {
        return TestResult::Fail("cross-dir source hardlink setup failed");
    }
    let cross_target = match poll_once(dst_dir.create("cross-target")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("cross-dir target creation failed"),
    };
    let cross_target_ino = cross_target.ino();
    let cross_target_data = b"cross-dir victim\n";
    if !matches!(
        poll_once(cross_target.write(0, cross_target_data)),
        Some(Ok(_))
    ) || !matches!(
        poll_once(cross_target.set_xattr("user.cross-victim", b"kept", 0)),
        Some(Ok(()))
    ) || !matches!(
        poll_once(dst_dir.link("cross-target", "cross-target-peer")),
        Some(Ok(()))
    ) || !matches!(
        poll_once(src_dir.rename_to("cross-source", &*dst_dir, "cross-target", 0)),
        Some(Ok(()))
    ) {
        return TestResult::Fail("cross-dir hardlink overwrite failed");
    }
    // Both destination names now identify the moved source; POSIX specifies a
    // successful no-op when renaming one hardlink over the other.
    if !matches!(
        poll_once(dst_dir.rename("cross-target", "cross-source-peer")),
        Some(Ok(()))
    ) {
        return TestResult::Fail("same-inode rename was not a successful no-op");
    }

    let remounted = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(volume)) => volume,
        _ => return TestResult::Fail("hardlink/xattr rename remount failed"),
    };
    let root = remounted.root();
    if poll_once(root.lookup_async("rename-source")).is_some_and(|result| result.is_ok()) {
        return TestResult::Fail("same-dir source name survived overwrite");
    }
    let renamed = match poll_once(root.lookup_async("rename-target")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("same-dir renamed source missing"),
    };
    let source_peer = match poll_once(root.lookup_async("rename-source-peer")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("same-dir source peer missing"),
    };
    if renamed.ino() != source_ino
        || source_peer.ino() != source_ino
        || read_all(&renamed, source_data.len() + 8).as_deref() != Some(source_data)
        || poll_once(renamed.get_xattr("user.source")).map(|result| result.ok())
            != Some(Some(b"kept".to_vec()))
        || !matches!(poll_once(renamed.statx_async(0, 0x7ff)), Some(Ok(stat)) if stat.nlink == 2)
    {
        return TestResult::Fail("same-dir source refs/data/xattrs changed");
    }
    let victim_peer = match poll_once(root.lookup_async("rename-target-peer")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("same-dir target peer missing"),
    };
    if victim_peer.ino() != victim_ino
        || read_all(&victim_peer, victim_data.len() + 8).as_deref() != Some(victim_data)
        || poll_once(victim_peer.get_xattr("user.victim")).map(|result| result.ok())
            != Some(Some(b"survives".to_vec()))
        || !matches!(poll_once(victim_peer.statx_async(0, 0x7ff)), Some(Ok(stat)) if stat.nlink == 1)
    {
        return TestResult::Fail("same-dir target peer was not preserved");
    }
    let replaced = match poll_once(root.lookup_async("rename-doomed")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("last-link replacement missing"),
    };
    if read_all(&replaced, replacement_data.len() + 8).as_deref() != Some(replacement_data)
        || poll_once(root.lookup_async("rename-replacement")).is_some_and(|result| result.is_ok())
    {
        return TestResult::Fail("last-link replacement namespace/data wrong");
    }
    let fs_root = remounted.fs_tree_root().0;
    for ino in [doomed_ino, unlinked_ino] {
        match poll_once(btree::collect_for(
            &*remounted,
            fs_root,
            ino,
            format::XATTR_ITEM_KEY,
        )) {
            Some(Ok(items)) if items.is_empty() => {}
            Some(Ok(_)) => return TestResult::Fail("reclaimed inode left orphaned xattrs"),
            _ => return TestResult::Fail("reclaimed inode xattr scan failed"),
        }
    }

    let src_dir = match poll_once(root.lookup_dir_async("rename-src-dir")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("remounted cross-dir source missing"),
    };
    let dst_dir = match poll_once(root.lookup_dir_async("rename-dst-dir")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("remounted cross-dir destination missing"),
    };
    if poll_once(src_dir.lookup_async("cross-source")).is_some_and(|result| result.is_ok()) {
        return TestResult::Fail("cross-dir source name survived move");
    }
    let cross_renamed = match poll_once(dst_dir.lookup_async("cross-target")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("cross-dir renamed source missing"),
    };
    let cross_source_peer = match poll_once(dst_dir.lookup_async("cross-source-peer")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("cross-dir source peer missing"),
    };
    if cross_renamed.ino() != cross_source_ino
        || cross_source_peer.ino() != cross_source_ino
        || read_all(&cross_renamed, cross_source_data.len() + 8).as_deref()
            != Some(cross_source_data)
        || !matches!(poll_once(cross_renamed.statx_async(0, 0x7ff)), Some(Ok(stat)) if stat.nlink == 2)
    {
        return TestResult::Fail("cross-dir source refs/data changed");
    }
    let cross_target_peer = match poll_once(dst_dir.lookup_async("cross-target-peer")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("cross-dir target peer missing"),
    };
    if cross_target_peer.ino() != cross_target_ino
        || read_all(&cross_target_peer, cross_target_data.len() + 8).as_deref()
            != Some(cross_target_data)
        || poll_once(cross_target_peer.get_xattr("user.cross-victim")).map(|result| result.ok())
            != Some(Some(b"kept".to_vec()))
        || !matches!(poll_once(cross_target_peer.statx_async(0, 0x7ff)), Some(Ok(stat)) if stat.nlink == 1)
    {
        return TestResult::Fail("cross-dir target peer was not preserved");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_rename_hardlink_xattr_overwrite
);

/// Cross-directory `rename` (`rename_to`) moves a file into another directory: it
/// leaves the old parent, appears in the new one under the new name with its
/// content intact, and survives a remount.
fn smoke_btrfs_rename_cross_dir() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    let root = vol.root();
    if !matches!(poll_once(root.mkdir("sub")), Some(Ok(_))) {
        return TestResult::Fail("mkdir failed");
    }
    let mover = match poll_once(root.create("mover.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create failed"),
    };
    let payload = b"moved across directories\n";
    if !matches!(poll_once(mover.write(0, payload)), Some(Ok(_))) {
        return TestResult::Fail("write failed");
    }
    let sub = match poll_once(root.lookup_dir_async("sub")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("lookup sub failed"),
    };
    match poll_once(root.rename_to("mover.txt", &*sub, "moved.txt", 0)) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("cross-dir rename failed"),
    }

    let vol2 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount failed"),
    };
    let root2 = vol2.root();
    if poll_once(root2.lookup_async("mover.txt")).is_some_and(|r| r.is_ok()) {
        return TestResult::Fail("source still in old parent");
    }
    let sub2 = match poll_once(root2.lookup_dir_async("sub")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("sub missing after remount"),
    };
    match poll_once(sub2.lookup_async("moved.txt")) {
        Some(Ok(f)) => match read_all(&f, payload.len() + 16) {
            Some(got) if got == payload => TestResult::Pass,
            _ => TestResult::Fail("moved file content changed"),
        },
        _ => TestResult::Fail("file not in new parent"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_rename_cross_dir);

/// Cross-directory `rename` refuses to move a directory into its own subtree
/// (which would orphan a cycle).
fn smoke_btrfs_rename_cross_dir_loop_rejected() -> TestResult {
    use narf_filesystem::FsInstance;

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let root = vol.root();
    if !matches!(poll_once(root.mkdir("a")), Some(Ok(_))) {
        return TestResult::Fail("mkdir a failed");
    }
    let a = match poll_once(root.lookup_dir_async("a")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("lookup a failed"),
    };
    if !matches!(poll_once(a.mkdir("b")), Some(Ok(_))) {
        return TestResult::Fail("mkdir a/b failed");
    }
    let b = match poll_once(a.lookup_dir_async("b")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("lookup a/b failed"),
    };
    // Moving `a` into `a/b` is a loop and must be refused.
    match poll_once(root.rename_to("a", &*b, "a", 0)) {
        Some(Err(FsError::InvalidData)) => TestResult::Pass,
        _ => TestResult::Fail("directory loop move was not refused"),
    }
}

kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_rename_cross_dir_loop_rejected
);

/// A same-directory hard link: both names resolve to the same inode with the same
/// content, and the inode's `nlink` is 2 after a remount.
fn smoke_btrfs_link_same_dir() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    let orig = match poll_once(vol.root().create("orig.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create failed"),
    };
    let payload = b"shared inode content\n";
    if !matches!(poll_once(orig.write(0, payload)), Some(Ok(_))) {
        return TestResult::Fail("write failed");
    }
    match poll_once(vol.root().link("orig.txt", "hard.txt")) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("link failed"),
    }

    let vol2 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount failed"),
    };
    let root2 = vol2.root();
    let a = match poll_once(root2.lookup_async("orig.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("orig.txt missing"),
    };
    let b = match poll_once(root2.lookup_async("hard.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("hard.txt missing"),
    };
    if a.ino() != b.ino() {
        return TestResult::Fail("hard link is a different inode");
    }
    if read_all(&a, payload.len() + 8).as_deref() != Some(&payload[..])
        || read_all(&b, payload.len() + 8).as_deref() != Some(&payload[..])
    {
        return TestResult::Fail("linked names read different content");
    }
    match poll_once(a.statx_async(0, 0x7ff)) {
        Some(Ok(sx)) if sx.nlink == 2 => TestResult::Pass,
        _ => TestResult::Fail("nlink is not 2 after hard link"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_link_same_dir);

/// Real CRC32C-colliding UTF-8 names coexist in one DIR_ITEM bucket. Exercise
/// exact lookup plus record-level create, rename-out, rename-in, hard-link and
/// unlink edits, then verify the surviving collision peers after remount.
fn smoke_btrfs_dir_item_hash_collisions() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    const A: &str = "n5wrWL7foZTV";
    const B: &str = "Vf5Y4fyl9fqh";
    if checksum::name_hash(A.as_bytes()) != checksum::name_hash(B.as_bytes()) {
        return TestResult::Fail("collision test names no longer collide");
    }

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    let root = vol.root();
    let a = match poll_once(root.create(A)) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("first colliding create failed"),
    };
    let b = match poll_once(root.create(B)) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("second colliding create failed"),
    };
    if a.ino() == b.ino()
        || !matches!(poll_once(root.lookup_async(A)), Some(Ok(_)))
        || !matches!(poll_once(root.lookup_async(B)), Some(Ok(_)))
    {
        return TestResult::Fail("colliding names did not resolve independently");
    }

    // Remove A from the shared bucket and add it back from a different hash.
    if !matches!(poll_once(root.rename(A, "collision-moved")), Some(Ok(())))
        || !matches!(poll_once(root.lookup_async(B)), Some(Ok(_)))
        || !matches!(poll_once(root.rename("collision-moved", A)), Some(Ok(())))
    {
        return TestResult::Fail("rename did not preserve collision peer");
    }
    // Source lookup occurs in a collision bucket; then delete B alone and add a
    // hard link back under B, which is a destination collision append.
    if !matches!(poll_once(root.link(A, "collision-hard")), Some(Ok(())))
        || !matches!(poll_once(root.unlink(B)), Some(Ok(())))
        || !matches!(poll_once(root.lookup_async(A)), Some(Ok(_)))
        || !matches!(poll_once(root.link(A, B)), Some(Ok(())))
    {
        return TestResult::Fail("link/unlink collision edit failed");
    }

    // Directory removal uses the same record-level bucket deletion.
    if !matches!(poll_once(root.mkdir("collision-dirs")), Some(Ok(_))) {
        return TestResult::Fail("collision directory parent create failed");
    }
    let dirs = match poll_once(root.lookup_dir_async("collision-dirs")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("collision directory parent lookup failed"),
    };
    if !matches!(poll_once(dirs.mkdir(A)), Some(Ok(_)))
        || !matches!(poll_once(dirs.mkdir(B)), Some(Ok(_)))
        || !matches!(poll_once(dirs.rmdir(A)), Some(Ok(())))
        || !matches!(poll_once(dirs.lookup_dir_async(B)), Some(Ok(_)))
    {
        return TestResult::Fail("rmdir removed or damaged collision peer");
    }

    // Source and overwrite target occupy the very same hash bucket. The final
    // body must contain B pointing at A's inode, not competing key edits.
    if !matches!(poll_once(root.mkdir("collision-overwrite")), Some(Ok(_))) {
        return TestResult::Fail("collision overwrite parent create failed");
    }
    let overwrite_dir = match poll_once(root.lookup_dir_async("collision-overwrite")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("collision overwrite parent lookup failed"),
    };
    let overwrite_source = match poll_once(overwrite_dir.create(A)) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("collision overwrite source create failed"),
    };
    if !matches!(poll_once(overwrite_dir.create(B)), Some(Ok(_)))
        || !matches!(poll_once(overwrite_dir.rename(A, B)), Some(Ok(())))
    {
        return TestResult::Fail("same-bucket collision overwrite failed");
    }
    match poll_once(overwrite_dir.lookup_async(B)) {
        Some(Ok(f)) if f.ino() == overwrite_source.ino() => {}
        _ => return TestResult::Fail("collision overwrite retained wrong inode"),
    }
    if poll_once(overwrite_dir.lookup_async(A)).is_some_and(|result| result.is_ok()) {
        return TestResult::Fail("collision overwrite source name survived");
    }

    let vol2 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("collision remount failed"),
    };
    let root2 = vol2.root();
    let a2 = match poll_once(root2.lookup_async(A)) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("first collision name missing after remount"),
    };
    let b2 = match poll_once(root2.lookup_async(B)) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("second collision name missing after remount"),
    };
    if a2.ino() != b2.ino() {
        return TestResult::Fail("colliding hard links diverged after remount");
    }
    let dirs2 = match poll_once(root2.lookup_dir_async("collision-dirs")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("collision directory missing after remount"),
    };
    if poll_once(dirs2.lookup_async(A)).is_some_and(|result| result.is_ok())
        || !matches!(poll_once(dirs2.lookup_dir_async(B)), Some(Ok(_)))
    {
        return TestResult::Fail("rmdir collision state wrong after remount");
    }
    let overwrite_dir2 = match poll_once(root2.lookup_dir_async("collision-overwrite")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("collision overwrite parent missing after remount"),
    };
    if poll_once(overwrite_dir2.lookup_async(A)).is_some_and(|result| result.is_ok())
        || !matches!(poll_once(overwrite_dir2.lookup_async(B)), Some(Ok(_)))
    {
        return TestResult::Fail("collision overwrite state wrong after remount");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_dir_item_hash_collisions);

/// Cross-directory rename removes and appends exact records while both source
/// and destination parents already contain another name with the same hash.
fn smoke_btrfs_cross_dir_hash_collision_rename() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    const A: &str = "n5wrWL7foZTV";
    const B: &str = "Vf5Y4fyl9fqh";
    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    let root = vol.root();
    if !matches!(poll_once(root.mkdir("collision-src")), Some(Ok(_)))
        || !matches!(poll_once(root.mkdir("collision-dst")), Some(Ok(_)))
    {
        return TestResult::Fail("collision parent setup failed");
    }
    let src = match poll_once(root.lookup_dir_async("collision-src")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("source parent lookup failed"),
    };
    let dst = match poll_once(root.lookup_dir_async("collision-dst")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("destination parent lookup failed"),
    };
    if !matches!(poll_once(src.create(A)), Some(Ok(_)))
        || !matches!(poll_once(src.create(B)), Some(Ok(_)))
        || !matches!(poll_once(dst.create(B)), Some(Ok(_)))
        || !matches!(poll_once(src.rename_to(A, &*dst, A, 0)), Some(Ok(())))
    {
        return TestResult::Fail("cross-directory collision rename failed");
    }
    if !matches!(poll_once(src.lookup_async(B)), Some(Ok(_)))
        || !matches!(poll_once(dst.lookup_async(A)), Some(Ok(_)))
        || !matches!(poll_once(dst.lookup_async(B)), Some(Ok(_)))
    {
        return TestResult::Fail("cross-directory collision peer was damaged");
    }

    let vol2 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("cross-directory collision remount failed"),
    };
    let root2 = vol2.root();
    let src2 = match poll_once(root2.lookup_dir_async("collision-src")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("remount source parent missing"),
    };
    let dst2 = match poll_once(root2.lookup_dir_async("collision-dst")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("remount destination parent missing"),
    };
    if poll_once(src2.lookup_async(A)).is_some_and(|result| result.is_ok())
        || !matches!(poll_once(src2.lookup_async(B)), Some(Ok(_)))
        || !matches!(poll_once(dst2.lookup_async(A)), Some(Ok(_)))
        || !matches!(poll_once(dst2.lookup_async(B)), Some(Ok(_)))
    {
        return TestResult::Fail("cross-directory collision state wrong after remount");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_cross_dir_hash_collision_rename
);

/// A cross-directory hard link aliases the same inode into another directory, and
/// hard-linking a directory is refused (`EPERM`).
fn smoke_btrfs_link_cross_dir_and_reject_dir() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    let root = vol.root();
    if !matches!(poll_once(root.mkdir("d")), Some(Ok(_)))
        || !matches!(poll_once(root.create("f.txt")), Some(Ok(_)))
    {
        return TestResult::Fail("setup failed");
    }
    // Hard-linking a directory is EPERM.
    if !matches!(
        poll_once(root.link("d", "d2")),
        Some(Err(FsError::PermissionDenied))
    ) {
        return TestResult::Fail("hard link to directory was not refused");
    }
    // Cross-directory hard link f.txt → d/g.txt.
    let d = match poll_once(root.lookup_dir_async("d")) {
        Some(Ok(x)) => x,
        _ => return TestResult::Fail("lookup d failed"),
    };
    match poll_once(root.link_to("f.txt", &*d, "g.txt")) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("cross-dir link failed"),
    }

    let vol2 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount failed"),
    };
    let root2 = vol2.root();
    let f2 = match poll_once(root2.lookup_async("f.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("f.txt missing"),
    };
    let d2 = match poll_once(root2.lookup_dir_async("d")) {
        Some(Ok(x)) => x,
        _ => return TestResult::Fail("d missing"),
    };
    let g2 = match poll_once(d2.lookup_async("g.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("d/g.txt missing"),
    };
    if f2.ino() != g2.ino() {
        return TestResult::Fail("cross-dir link is a different inode");
    }
    match poll_once(f2.statx_async(0, 0x7ff)) {
        Some(Ok(sx)) if sx.nlink == 2 => TestResult::Pass,
        _ => TestResult::Fail("nlink is not 2 after cross-dir link"),
    }
}

kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_link_cross_dir_and_reject_dir
);

/// Unlinking one name of a hard-linked file drops `nlink` to 1 and keeps the
/// inode + data (the other name still reads it); unlinking the last name then
/// frees the data extent.
fn smoke_btrfs_unlink_hardlink() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    let a = match poll_once(vol.root().create("a.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create failed"),
    };
    let payload = b"two names, one inode\n";
    if !matches!(poll_once(a.write(0, payload)), Some(Ok(_))) {
        return TestResult::Fail("write failed");
    }
    if !matches!(poll_once(vol.root().link("a.txt", "b.txt")), Some(Ok(()))) {
        return TestResult::Fail("link failed");
    }
    // The shared data extent, recorded before any unlink.
    let extent = match poll_once(vol.root().lookup_async("a.txt")) {
        Some(Ok(f)) => file_data_extent(&vol, f.ino()),
        _ => None,
    };

    // Unlink one of the two names.
    if !matches!(poll_once(vol.root().unlink("a.txt")), Some(Ok(()))) {
        return TestResult::Fail("unlink of first link failed");
    }
    let vol2 = match poll_once(BtrfsVolume::mount(device.clone(), DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount failed"),
    };
    let root2 = vol2.root();
    if poll_once(root2.lookup_async("a.txt")).is_some_and(|r| r.is_ok()) {
        return TestResult::Fail("unlinked name still present");
    }
    let b = match poll_once(root2.lookup_async("b.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("surviving link missing"),
    };
    if read_all(&b, payload.len() + 8).as_deref() != Some(&payload[..]) {
        return TestResult::Fail("surviving link lost its content");
    }
    match poll_once(b.statx_async(0, 0x7ff)) {
        Some(Ok(sx)) if sx.nlink == 1 => {}
        _ => return TestResult::Fail("nlink did not drop to 1"),
    }
    // The data extent survives while a link remains.
    if let Some((bytenr, len)) = extent {
        if !extent_item_present(&vol2, bytenr, len) {
            return TestResult::Fail("data extent freed while still linked");
        }
    }

    // Unlink the last name — now the data must be freed.
    if !matches!(poll_once(root2.unlink("b.txt")), Some(Ok(()))) {
        return TestResult::Fail("unlink of last link failed");
    }
    let vol3 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount after last unlink failed"),
    };
    if poll_once(vol3.root().lookup_async("b.txt")).is_some_and(|r| r.is_ok()) {
        return TestResult::Fail("last name still present");
    }
    if let Some((bytenr, len)) = extent {
        if extent_item_present(&vol3, bytenr, len) {
            return TestResult::Fail("data extent not freed after last unlink");
        }
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_unlink_hardlink);

/// Extended-attribute writes: `set_xattr` creates and replaces attributes that
/// read back (and survive a remount), `list_xattr` enumerates them, and
/// `remove_xattr` deletes one while leaving the others.
fn smoke_btrfs_xattr_write() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    let f = match poll_once(vol.root().create("x.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create failed"),
    };
    if !matches!(
        poll_once(f.set_xattr("user.color", b"blue", 0)),
        Some(Ok(()))
    ) || !matches!(
        poll_once(f.set_xattr("user.size", b"large", 0)),
        Some(Ok(()))
    ) {
        return TestResult::Fail("set_xattr failed");
    }

    // Remount: both attributes are durable and read back.
    let vol2 = match poll_once(BtrfsVolume::mount(device.clone(), DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount failed"),
    };
    let f2 = match poll_once(vol2.root().lookup_async("x.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup after remount failed"),
    };
    if poll_once(f2.get_xattr("user.color")).map(|r| r.ok()) != Some(Some(b"blue".to_vec()))
        || poll_once(f2.get_xattr("user.size")).map(|r| r.ok()) != Some(Some(b"large".to_vec()))
    {
        return TestResult::Fail("xattr values wrong after remount");
    }
    // list_xattr enumerates both names (NUL-terminated).
    let names = match poll_once(f2.list_xattr()) {
        Some(Ok(b)) => b,
        _ => return TestResult::Fail("list_xattr failed"),
    };
    let has = |n: &[u8]| names.windows(n.len()).any(|w| w == n);
    if !has(b"user.color\0") || !has(b"user.size\0") {
        return TestResult::Fail("list_xattr missing a name");
    }

    // Replace one value, remove the other.
    if !matches!(
        poll_once(f2.set_xattr("user.color", b"red", 0)),
        Some(Ok(()))
    ) {
        return TestResult::Fail("replace xattr failed");
    }
    if !matches!(poll_once(f2.remove_xattr("user.size")), Some(Ok(()))) {
        return TestResult::Fail("remove_xattr failed");
    }

    let vol3 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount after edits failed"),
    };
    let f3 = match poll_once(vol3.root().lookup_async("x.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup after edits failed"),
    };
    if poll_once(f3.get_xattr("user.color")).map(|r| r.ok()) != Some(Some(b"red".to_vec())) {
        return TestResult::Fail("replaced value not persisted");
    }
    if poll_once(f3.get_xattr("user.size")).is_some_and(|r| r.is_ok()) {
        return TestResult::Fail("removed xattr still present");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_xattr_write);

/// Creating enough files overflows a single leaf, so the fs tree splits into
/// multiple leaves under an internal root (level 1). Every file survives a
/// remount, the tree is genuinely multi-level, and further mutations (unlink)
/// still work on the split tree.
fn smoke_btrfs_leaf_split() -> TestResult {
    use alloc::format;
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    const N: usize = 30;
    for i in 0..N {
        let name = format!("split-{i:04}.txt");
        if !matches!(poll_once(vol.root().create(&name)), Some(Ok(_))) {
            return TestResult::Fail("create failed before the leaf split completed");
        }
    }

    // Remount: the fs tree must now be multi-level and hold every file.
    let vol2 = match poll_once(BtrfsVolume::mount(device.clone(), DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount after split failed"),
    };
    if vol2.fs_tree_root().1 == 0 {
        return TestResult::Fail("fs tree did not split to a higher level");
    }
    let names = dir_names(&vol2.root());
    for i in 0..N {
        if !names.iter().any(|n| n == &format!("split-{i:04}.txt")) {
            return TestResult::Fail("a file was lost across the leaf split");
        }
    }
    // The originals are intact and a mutation still works on the split tree.
    if !names.iter().any(|n| n == "hello.txt") || !names.iter().any(|n| n == "big.dat") {
        return TestResult::Fail("pre-existing entries lost across the split");
    }
    match poll_once(vol2.root().unlink("split-0000.txt")) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("unlink on the split tree failed"),
    }
    let vol3 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount after split-tree unlink failed"),
    };
    if poll_once(vol3.root().lookup_async("split-0000.txt")).is_some_and(|r| r.is_ok()) {
        return TestResult::Fail("unlinked file present on the split tree");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_leaf_split);

/// Growing the filesystem allocates a new chunk at the end of the device: the
/// image stays mountable and readable, and files can be created into the new
/// space, surviving a remount.
fn smoke_btrfs_grow_add_chunk() -> TestResult {
    use alloc::format;
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    match poll_once(crate::write::grow_add_chunk(&vol)) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("grow_add_chunk failed"),
    }
    // Create a few files after the grow (their metadata/data can land in the new
    // chunk) and confirm everything is durable + readable across a remount.
    for i in 0..4 {
        if !matches!(
            poll_once(vol.root().create(&format!("grown-{i}.txt"))),
            Some(Ok(_))
        ) {
            return TestResult::Fail("create after grow failed");
        }
    }

    let vol2 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount after grow failed"),
    };
    // Pre-existing content is intact…
    match poll_once(vol2.root().lookup_async("hello.txt")) {
        Some(Ok(f)) => {
            if read_all(&f, 16).as_deref() != Some(b"narf\n") {
                return TestResult::Fail("hello.txt content wrong after grow");
            }
        }
        _ => return TestResult::Fail("hello.txt missing after grow"),
    }
    // …and the new files are present.
    let names = dir_names(&vol2.root());
    for i in 0..4 {
        if !names.iter().any(|n| n == &format!("grown-{i}.txt")) {
            return TestResult::Fail("a post-grow file was lost");
        }
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_grow_add_chunk);

/// Space reclaim: on an image with a free-space tree, repeatedly overwriting a
/// file reuses the space freed by the previous overwrite (each write allocates a
/// fresh extent + COWs whole trees, then frees the old blocks), so the free pool
/// stays roughly constant and the filesystem does **not** grow — proving freed
/// logical addresses are reclaimed rather than leaked. Every write succeeds and
/// the final content is durable across a remount.
fn smoke_btrfs_space_reclaim() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    let chunks_before = vol.chunk_map_len();
    let big = match poll_once(vol.root().lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup big.dat failed"),
    };
    let payload = replacement_big();
    // Far more churn (~32 KB each) than the initial data chunk holds: without
    // reclaim this exhausted the chunk and forced a grow; with reclaim the freed
    // space is reused every time, so no grow is needed.
    for _ in 0..150 {
        match poll_once(big.write(0, &payload)) {
            Some(Ok(n)) if n == payload.len() => {}
            _ => return TestResult::Fail("a write failed under space pressure"),
        }
    }
    if vol.chunk_map_len() != chunks_before {
        return TestResult::Fail("filesystem grew despite reclaimable free space");
    }

    // The content is durable across a remount.
    let vol2 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount failed"),
    };
    match poll_once(vol2.root().lookup_async("big.dat")) {
        Some(Ok(f)) => match read_all(&f, payload.len() + 16) {
            Some(got) if got == payload => TestResult::Pass,
            _ => TestResult::Fail("content wrong after reclaim churn"),
        },
        _ => TestResult::Fail("big.dat missing after reclaim churn"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_space_reclaim);

/// Read the 4096-byte superblock copy at physical byte `offset` from a device.
fn read_super_at(dev: &WritableSparseDevice, offset: u64) -> Vec<u8> {
    use narf_block::BlockDeviceSync;
    let mut buf = alloc::vec![0u8; format::SUPERBLOCK_SIZE];
    let lba = offset / u64::from(dev.lba_size());
    let n = (format::SUPERBLOCK_SIZE / dev.lba_size() as usize) as u16;
    dev.read(lba, n, &mut buf).unwrap();
    buf
}

/// A COW write updates EVERY superblock copy in lockstep: on a ≥64 MiB image
/// (mkfs wrote the 64 MiB mirror), after a write both the primary and the mirror
/// carry the new generation and root, each with its own `bytenr` and a valid
/// checksum — the invariant `btrfs check` enforces so a real kernel never
/// recovers from a stale mirror.
fn smoke_btrfs_superblock_mirror() -> TestResult {
    use narf_filesystem::FsInstance;

    let dev = writable_sparse(FIXTURE_MIRROR_SPARSE);
    let vol = match mount_writable(dev.clone()) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("mirror fixture failed to mount"),
    };
    let gen_before = vol.superblock().generation;

    // Overwrite big.dat so a COW commit flips the superblock(s).
    let big = match poll_once(vol.root().lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup big.dat failed"),
    };
    let payload = replacement_big();
    match poll_once(big.write(0, &payload)) {
        Some(Ok(n)) if n == payload.len() => {}
        _ => return TestResult::Fail("write failed"),
    }

    // Inspect both on-disk superblock copies directly.
    let primary = read_super_at(&dev, format::SUPERBLOCK_OFFSET);
    let mirror = read_super_at(&dev, 64 << 20);
    let field = |sb: &[u8], off: usize| u64::from_le_bytes(sb[off..off + 8].try_into().unwrap());
    // Each copy records its own physical location in bytenr@48.
    if field(&primary, 48) != format::SUPERBLOCK_OFFSET {
        return TestResult::Fail("primary bytenr wrong");
    }
    if field(&mirror, 48) != 64 << 20 {
        return TestResult::Fail("mirror bytenr wrong");
    }
    // Both advanced to the same new generation…
    let g = field(&primary, 72);
    if g <= gen_before || field(&mirror, 72) != g {
        return TestResult::Fail("mirror generation did not track the primary");
    }
    // …and name the same root tree.
    if field(&primary, 80) != field(&mirror, 80) {
        return TestResult::Fail("mirror root does not match primary");
    }
    // Each copy carries a valid (independently computed) checksum.
    for sb in [&primary, &mirror] {
        let stored = u32::from_le_bytes(sb[0..4].try_into().unwrap());
        if checksum::block_csum(&sb[format::CSUM_SIZE..format::SUPERBLOCK_SIZE]) != stored {
            return TestResult::Fail("superblock copy checksum invalid");
        }
    }

    // Remount over the same device: the write is durable and readable.
    let vol2 = match mount_writable(dev) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("remount failed"),
    };
    match poll_once(vol2.root().lookup_async("big.dat")) {
        Some(Ok(f)) => match read_all(&f, payload.len() + 16) {
            Some(got) if got == payload => TestResult::Pass,
            _ => TestResult::Fail("content wrong after remount"),
        },
        _ => TestResult::Fail("big.dat missing after remount"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_superblock_mirror);

/// Mount chooses the newest valid superblock copy, not unconditionally the
/// primary. The next transaction then rewrites every copy and heals the stale
/// primary so a subsequent mount no longer depends on the mirror.
fn smoke_btrfs_superblock_recovery() -> TestResult {
    use narf_block::BlockDeviceSync;
    use narf_filesystem::FsInstance;

    let dev = writable_sparse(FIXTURE_MIRROR_SPARSE);
    let mut primary = read_super_at(&dev, format::SUPERBLOCK_OFFSET);
    let mirror = read_super_at(&dev, 64 << 20);
    let field = |sb: &[u8], off: usize| u64::from_le_bytes(sb[off..off + 8].try_into().unwrap());
    let mirror_gen = field(&mirror, 72);
    if mirror_gen == 0 || field(&primary, 72) != mirror_gen {
        return TestResult::Fail("fixture superblock mirrors do not start in sync");
    }

    primary[72..80].copy_from_slice(&(mirror_gen - 1).to_le_bytes());
    if checksum::stamp_block(format::CSUM_TYPE_CRC32, &mut primary).is_err() {
        return TestResult::Fail("failed to restamp stale primary");
    }
    let lba = format::SUPERBLOCK_OFFSET / u64::from(dev.lba_size());
    let blocks = (format::SUPERBLOCK_SIZE / dev.lba_size() as usize) as u16;
    if dev.write(lba, blocks, &primary).is_err() {
        return TestResult::Fail("failed to install stale primary");
    }

    let vol = match mount_writable(dev.clone()) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("newer mirror was not mountable"),
    };
    if vol.superblock().generation != mirror_gen {
        return TestResult::Fail("mount selected the stale primary generation");
    }

    let big = match poll_once(vol.root().lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup after mirror recovery failed"),
    };
    let payload = replacement_big();
    match poll_once(big.write(0, &payload)) {
        Some(Ok(n)) if n == payload.len() => {}
        _ => return TestResult::Fail("healing transaction failed"),
    }

    let healed_primary = read_super_at(&dev, format::SUPERBLOCK_OFFSET);
    let healed_mirror = read_super_at(&dev, 64 << 20);
    if field(&healed_primary, 72) <= mirror_gen
        || field(&healed_primary, 72) != field(&healed_mirror, 72)
        || field(&healed_primary, 80) != field(&healed_mirror, 80)
    {
        return TestResult::Fail("transaction did not heal the stale primary");
    }
    match mount_writable(dev) {
        Ok(_) => TestResult::Pass,
        Err(_) => TestResult::Fail("healed volume did not remount"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_superblock_recovery);

/// A checksum-bad primary metadata stripe in a DUP chunk is recovered from the
/// second same-device copy. This uses the realistic non-mixed laptop fixture,
/// whose metadata profile is DUP, and corrupts only the mounted FS-tree root's
/// first physical copy.
fn smoke_btrfs_dup_metadata_recovery() -> TestResult {
    use narf_block::BlockDeviceSync;

    let dev = writable_sparse(FIXTURE_LAPTOP_SPARSE);
    let vol = match mount_writable(dev.clone()) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("laptop fixture failed to mount writable"),
    };
    let (fs_root, _) = vol.fs_tree_root();
    let (primary, mirror) = match vol.map_logical_copies(fs_root) {
        Ok((primary, Some(mirror))) => (primary, mirror),
        _ => return TestResult::Fail("laptop metadata root is not mapped as DUP"),
    };
    if primary == mirror {
        return TestResult::Fail("DUP metadata copies alias each other");
    }

    let blocks = (vol.nodesize() / dev.lba_size() as usize) as u16;
    let mut node = alloc::vec![0u8; vol.nodesize()];
    if dev
        .read(primary / u64::from(dev.lba_size()), blocks, &mut node)
        .is_err()
    {
        return TestResult::Fail("failed to read primary metadata stripe");
    }
    node[0] ^= 0x80; // invalidate only the stored checksum
    if dev
        .write(primary / u64::from(dev.lba_size()), blocks, &node)
        .is_err()
    {
        return TestResult::Fail("failed to corrupt primary metadata stripe");
    }

    match mount_writable(dev) {
        Ok(recovered) if recovered.root_inode().is_some() => TestResult::Pass,
        _ => TestResult::Fail("mount did not recover metadata from DUP mirror"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_dup_metadata_recovery);

/// A new chunk never overlaps a superblock mirror: the span helper caps a chunk
/// that would cross the 64 MiB mirror, and bumps a start landing inside its band.
fn smoke_btrfs_chunk_avoids_supers() -> TestResult {
    const M64: u64 = 64 << 20;
    const BAND: u64 = 65536;
    // A chunk starting well below the mirror is capped to end at the mirror.
    let (start, len) = crate::write::chunk_span_avoiding_supers(8 << 20, 96 << 20);
    if start != 8 << 20 || start + len != M64 {
        return TestResult::Fail("chunk not capped before the 64 MiB mirror");
    }
    // A start inside the reserved band is bumped past it.
    let (start, len) = crate::write::chunk_span_avoiding_supers(M64, 96 << 20);
    if start != M64 + BAND || start + len != 96 << 20 {
        return TestResult::Fail("start not bumped past the mirror band");
    }
    // Above the last relevant mirror, the whole remaining span is available.
    let (start, len) = crate::write::chunk_span_avoiding_supers(70 << 20, 96 << 20);
    if start != 70 << 20 || len != 26 << 20 {
        return TestResult::Fail("span above the mirror is wrong");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_chunk_avoids_supers);

/// The extent, csum and free-space trees are no longer limited to a single leaf:
/// creating many files each with a multi-sector data extent overflows them, and
/// the COW commit re-packs each into leaves under an internal root — resolving the
/// extent tree's self-reference (it records its own new blocks) with a fixed
/// point. Proven by the on-disk root levels rising above 0 and every file reading
/// back across the split trees after a remount.
/// On-disk root level of the tree with the given objectid (leaves are 0).
fn tree_level<B: narf_block::BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    objectid: u64,
) -> Option<u8> {
    let root_tree = vol.root_tree_root().0;
    poll_once(crate::roots::find_root(vol, root_tree, objectid))?
        .ok()
        .map(|(_, level)| level)
}

fn smoke_btrfs_multileaf_trees() -> TestResult {
    use narf_filesystem::FsInstance;

    const N: u32 = 90;
    const SZ: usize = 65536; // 16 sectors: a large csum item per file

    let dev = writable_sparse(FIXTURE_MIRROR_SPARSE);
    let vol = match mount_writable(dev.clone()) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("mirror fixture failed to mount"),
    };
    // Create N distinct files, each with a multi-sector data extent, so the
    // EXTENT and CSUM trees both overflow a single leaf. Freed metadata is
    // reclaimed each write, so the live data (all N extents) fits the initial
    // chunk without a grow. Each file gets a distinct byte pattern so cross-file
    // corruption is caught.
    for i in 0..N {
        let name = alloc::format!("d{i:03}.dat");
        let f = match poll_once(vol.root().create(&name)) {
            Some(Ok(f)) => f,
            _ => return TestResult::Fail("create failed under multi-leaf churn"),
        };
        let payload = alloc::vec![i as u8; SZ];
        match poll_once(f.write(0, &payload)) {
            Some(Ok(n)) if n == SZ => {}
            _ => return TestResult::Fail("write failed under multi-leaf churn"),
        }
    }

    // Both the extent and csum trees must have outgrown a single leaf.
    if tree_level(&vol, format::EXTENT_TREE_OBJECTID) != Some(1) {
        return TestResult::Fail("extent tree did not become multi-leaf");
    }
    if tree_level(&vol, format::CSUM_TREE_OBJECTID) != Some(1) {
        return TestResult::Fail("csum tree did not become multi-leaf");
    }

    // Grow the filesystem now that its trees are multi-leaf — chunk growth must
    // work on a multi-leaf filesystem.
    let chunks_before = vol.chunk_map_len();
    if !matches!(poll_once(crate::write::grow_add_chunk(&vol)), Some(Ok(()))) {
        return TestResult::Fail("grow_add_chunk failed on a multi-leaf filesystem");
    }
    if vol.chunk_map_len() <= chunks_before {
        return TestResult::Fail("multi-leaf grow did not add a chunk");
    }

    // Remount and read every file back through the now-split trees.
    let vol2 = match mount_writable(dev) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("remount failed"),
    };
    for i in 0..N {
        let name = alloc::format!("d{i:03}.dat");
        match poll_once(vol2.root().lookup_async(&name)) {
            Some(Ok(f)) => match read_all(&f, SZ + 16) {
                Some(got) if got.len() == SZ && got.iter().all(|&b| b == i as u8) => {}
                _ => return TestResult::Fail("file content wrong after remount"),
            },
            _ => return TestResult::Fail("file missing after remount"),
        }
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_multileaf_trees);

/// The tree-height math: leaves pack into internal nodes `fanout`-wide, and a tree
/// grows past two levels once the leaves overflow a single internal node.
fn smoke_btrfs_tree_levels() -> TestResult {
    use crate::write::{tree_block_count, tree_levels};
    // nodesize 4096: fanout = (4096 - 101) / 33 = 121 child pointers per node.
    let cases: &[(usize, &[usize])] = &[
        (1, &[1]),                    // a lone leaf is its own root (1 physical level)
        (2, &[2, 1]),                 // 2-level: leaves under one internal root
        (121, &[121, 1]),             // still 2-level — exactly one internal node's worth
        (122, &[122, 2, 1]),          // 3-level: leaves overflow one internal node
        (14642, &[14642, 122, 2, 1]), // 4-level (> 121^2 leaves)
    ];
    for &(leaves, want) in cases {
        if tree_levels(leaves, 4096) != want {
            return TestResult::Fail("tree_levels wrong");
        }
    }
    // Block count is the sum over levels.
    if tree_block_count(122, 4096) != 125 {
        return TestResult::Fail("tree_block_count wrong");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_tree_levels);

/// A tree taller than two levels: creating enough symlinks — each with a large
/// inline target, so roughly one fills a leaf — overflows a single internal node,
/// forcing the fs tree to a **third level** (root level 2). The COW write path
/// builds that tree, and every target reads back after a remount.
fn smoke_btrfs_tall_tree() -> TestResult {
    use narf_filesystem::FsInstance;

    // ~1 leaf per symlink; > 121 of them overflow one internal node.
    const N: u32 = 135;
    let target = |i: u32| alloc::format!("{i:0>3500}");

    let dev = writable_sparse(FIXTURE_MIRROR_SPARSE);
    let vol = match mount_writable(dev.clone()) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("mirror fixture failed to mount"),
    };
    for i in 0..N {
        let name = alloc::format!("l{i:03}");
        if !matches!(
            poll_once(vol.root().symlink(&name, &target(i))),
            Some(Ok(_))
        ) {
            return TestResult::Fail("symlink failed");
        }
    }

    // The fs tree must have grown past two levels (root level 2).
    match tree_level(&vol, format::FS_TREE_OBJECTID) {
        Some(2) => {}
        Some(_) => return TestResult::Fail("fs tree is not three levels tall"),
        None => return TestResult::Fail("fs tree root not found"),
    }

    // Remount and read every symlink target back through the three-level tree.
    let vol2 = match mount_writable(dev) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("remount failed"),
    };
    for i in 0..N {
        let name = alloc::format!("l{i:03}");
        let want = target(i);
        match poll_once(vol2.root().lookup_async(&name)) {
            Some(Ok(f)) => match read_all(&f, want.len() + 16) {
                Some(got) if got == want.as_bytes() => {}
                _ => return TestResult::Fail("symlink target wrong after remount"),
            },
            _ => return TestResult::Fail("symlink missing after remount"),
        }
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_tall_tree);

/// Whether any block group tracks its free space with a bitmap
/// (`FREE_SPACE_INFO.flags & USING_BITMAPS`).
fn fst_has_bitmap_bg<B: narf_block::BlockDevice + 'static>(vol: &BtrfsVolume<B>) -> bool {
    let root_tree = vol.root_tree_root().0;
    let fst_root = match poll_once(crate::roots::find_root(
        vol,
        root_tree,
        format::FREE_SPACE_TREE_OBJECTID,
    )) {
        Some(Ok((r, _))) => r,
        _ => return false,
    };
    let mut cursor = match poll_once(btree::Cursor::seek(vol, fst_root, &BtrfsKey::new(0, 0, 0))) {
        Some(Ok(c)) => c,
        _ => return false,
    };
    while let Ok(Some((key, body))) = cursor.current() {
        if key.item_type == format::FREE_SPACE_INFO_KEY && body.len() >= 8 {
            let flags = u32::from_le_bytes(body[4..8].try_into().unwrap());
            if flags & 1 != 0 {
                return true;
            }
        }
        if !matches!(poll_once(cursor.advance()), Some(Ok(()))) {
            break;
        }
    }
    false
}

/// A block group whose free space is a `FREE_SPACE_BITMAP` (not extent items):
/// the allocator decodes the bitmap into free ranges and the COW write path
/// clears/sets bits (rather than splitting/merging extents). Writing into and
/// overwriting files repeatedly reclaims from and returns to the bitmap group;
/// the content is durable and the group stays bitmap-tracked.
fn smoke_btrfs_free_space_bitmap() -> TestResult {
    use narf_filesystem::FsInstance;

    let dev = writable_sparse(FIXTURE_BITMAP_SPARSE);
    let vol = match mount_writable(dev.clone()) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("bitmap fixture failed to mount"),
    };
    if !fst_has_bitmap_bg(&vol) {
        return TestResult::Fail("fixture has no bitmap-tracked block group");
    }

    // Create a file and rewrite it several times: each write allocates a fresh
    // extent + COWs whole trees from the (fragmented) free space and frees the
    // old blocks — driving bitmap set/clear both ways.
    let f = match poll_once(vol.root().create("bmtest")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create failed"),
    };
    for round in 0..20u8 {
        let payload = alloc::vec![round ^ 0xa5; 4096];
        match poll_once(f.write(0, &payload)) {
            Some(Ok(4096)) => {}
            _ => return TestResult::Fail("write into bitmap group failed"),
        }
    }

    // The final content is durable across a remount, read back through the FST.
    let want = alloc::vec![19u8 ^ 0xa5; 4096];
    let vol2 = match mount_writable(dev) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("remount failed"),
    };
    if !fst_has_bitmap_bg(&vol2) {
        return TestResult::Fail("bitmap group lost across the writes");
    }
    match poll_once(vol2.root().lookup_async("bmtest")) {
        Some(Ok(f)) => match read_all(&f, want.len() + 16) {
            Some(got) if got == want => TestResult::Pass,
            _ => TestResult::Fail("content wrong after bitmap-group writes"),
        },
        _ => TestResult::Fail("bmtest missing after remount"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_free_space_bitmap);

/// Number of `EXTENT_DATA` items (extents) a file occupies.
fn file_extent_count(vol: &BtrfsVolume<narf_block::ram::RamBlockDevice>, ino: u64) -> usize {
    let (fs_root, _) = vol.fs_tree_root();
    poll_once(btree::collect_for(
        vol,
        fs_root,
        ino,
        format::EXTENT_DATA_KEY,
    ))
    .and_then(|r| r.ok())
    .map_or(0, |items| items.len())
}

/// Regular extent layout as `(file offset, disk bytenr, disk length)`.
fn regular_file_extents<B: narf_block::BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ino: u64,
) -> Option<Vec<(u64, u64, u64)>> {
    let (fs_root, _) = vol.fs_tree_root();
    let items = poll_once(btree::collect_for(
        vol,
        fs_root,
        ino,
        format::EXTENT_DATA_KEY,
    ))?
    .ok()?;
    items
        .into_iter()
        .map(|(key, body)| {
            if body.len() < 53 || body[20] != format::FILE_EXTENT_REG {
                return None;
            }
            Some((
                key.offset,
                format::le64(&body, 21).ok()?,
                format::le64(&body, 29).ok()?,
            ))
        })
        .collect()
}

/// A file larger than one extent: the write path tiles it into several data
/// extents, and a later write reads that multi-extent file back, frees every old
/// extent, and re-tiles it — all durable across remounts.
fn smoke_btrfs_multi_extent_write() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    const SZ: usize = 512 * 1024; // > MAX_WRITE_EXTENT (128 KiB) → 4 extents
    let make = |seed: u8| -> Vec<u8> {
        (0..SZ)
            .map(|i| (i as u8) ^ (i >> 8) as u8 ^ seed)
            .collect::<Vec<u8>>()
    };

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();

    let f = match poll_once(vol.root().create("multi.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create failed"),
    };
    let ino = f.ino();
    let p1 = make(0x11);
    match poll_once(f.write(0, &p1)) {
        Some(Ok(n)) if n == SZ => {}
        _ => return TestResult::Fail("first (large) write failed"),
    }
    if file_extent_count(&vol, ino) < 2 {
        return TestResult::Fail("large write did not tile into multiple extents");
    }

    // Remount: the multi-extent file reads back.
    let vol2 = match poll_once(BtrfsVolume::mount(device.clone(), DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount failed"),
    };
    let f2 = match poll_once(vol2.root().lookup_async("multi.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup after remount failed"),
    };
    if read_all(&f2, SZ + 16).as_deref() != Some(p1.as_slice()) {
        return TestResult::Fail("multi-extent content wrong after remount");
    }

    // Overwrite the (now multi-extent) file: reads all extents, frees them, re-tiles.
    let p2 = make(0x22);
    match poll_once(f2.write(0, &p2)) {
        Some(Ok(n)) if n == SZ => {}
        _ => return TestResult::Fail("overwrite of multi-extent file failed"),
    }

    // Remount again: the new content reads back.
    let vol3 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("second remount failed"),
    };
    match poll_once(vol3.root().lookup_async("multi.dat")) {
        Some(Ok(f)) => match read_all(&f, SZ + 16) {
            Some(got) if got == p2 => TestResult::Pass,
            _ => TestResult::Fail("content wrong after multi-extent overwrite"),
        },
        _ => TestResult::Fail("multi.dat missing after overwrite"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_multi_extent_write);

/// A small random write into a large file COWs only the intersected 128 KiB
/// extent. The other file items, physical extents, extent-tree records and
/// checksums remain live across the commit and remount.
fn smoke_btrfs_incremental_extent_write() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    const EXT: usize = 128 * 1024;
    const SZ: usize = 4 * EXT;
    let original = (0..SZ)
        .map(|i| (i as u8).wrapping_mul(37) ^ (i >> 11) as u8)
        .collect::<Vec<u8>>();

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    let created = match poll_once(vol.root().create("incremental.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create failed"),
    };
    let ino = created.ino();
    if !matches!(poll_once(created.write(0, &original)), Some(Ok(SZ))) {
        return TestResult::Fail("initial large write failed");
    }

    let before = match regular_file_extents(&vol, ino) {
        Some(v) if v.len() == 4 => v,
        _ => return TestResult::Fail("initial write did not produce four extents"),
    };
    // Reload the inode so its cached size reflects the first synchronous commit.
    let file = match poll_once(vol.root().lookup_async("incremental.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("post-create lookup failed"),
    };
    let patch = b"incremental-sector-COW";
    let patch_off = EXT + 777;
    if !matches!(
        poll_once(file.write(patch_off as u64, patch)),
        Some(Ok(n)) if n == patch.len()
    ) {
        return TestResult::Fail("small random write failed");
    }

    let after = match regular_file_extents(&vol, ino) {
        Some(v) if v.len() == 4 => v,
        _ => return TestResult::Fail("incremental write changed extent count"),
    };
    for i in [0usize, 2, 3] {
        if after[i] != before[i] {
            return TestResult::Fail("non-overlapping extent was rewritten");
        }
        if !extent_item_present(&vol, before[i].1, before[i].2) {
            return TestResult::Fail("preserved extent lost its extent-tree record");
        }
    }
    if after[1].0 != before[1].0 || after[1].1 == before[1].1 {
        return TestResult::Fail("intersected extent was not independently COWed");
    }
    if extent_item_present(&vol, before[1].1, before[1].2) {
        return TestResult::Fail("replaced extent remains in extent tree");
    }
    if !extent_item_present(&vol, after[1].1, after[1].2) {
        return TestResult::Fail("replacement extent missing from extent tree");
    }

    let mut expected = original;
    expected[patch_off..patch_off + patch.len()].copy_from_slice(patch);
    let vol2 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount failed"),
    };
    let file2 = match poll_once(vol2.root().lookup_async("incremental.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("remount lookup failed"),
    };
    if read_all(&file2, SZ + 16).as_deref() != Some(expected.as_slice()) {
        return TestResult::Fail("incremental write content mismatch after remount");
    }
    let (fs_root, _) = vol2.fs_tree_root();
    let csum_root = match csum_root_of(&vol2) {
        Some(r) => r,
        None => return TestResult::Fail("csum root missing after incremental write"),
    };
    match poll_once(crate::csum::verify_file_data_csums(
        &vol2, fs_root, csum_root, ino,
    )) {
        Some(Ok(true)) => TestResult::Pass,
        Some(Ok(false)) => TestResult::Fail("incremental extent checksums are invalid"),
        _ => TestResult::Fail("incremental checksum verification errored"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_incremental_extent_write);

/// Overwriting a small **inline** file (its data stored in the `EXTENT_DATA` item)
/// now works: the write reads the inline content and re-tiles it as a regular
/// extent. The new content is durable across a remount.
fn smoke_btrfs_inline_overwrite() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    let hello = match poll_once(vol.root().lookup_async("hello.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup hello.txt failed"),
    };
    let new = b"REPLACED-inline-with-a-regular-extent";
    match poll_once(hello.write(0, new)) {
        Some(Ok(n)) if n == new.len() => {}
        _ => return TestResult::Fail("inline overwrite failed"),
    }

    let vol2 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount failed"),
    };
    match poll_once(vol2.root().lookup_async("hello.txt")) {
        Some(Ok(f)) => match read_all(&f, new.len() + 16) {
            Some(got) if got == new => TestResult::Pass,
            _ => TestResult::Fail("content wrong after inline overwrite"),
        },
        _ => TestResult::Fail("hello.txt missing after remount"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_inline_overwrite);

/// Path-COW node primitives (the write-engine foundation): upserting past a
/// node's capacity re-tiles it into several valid, key-ordered leaves losing no
/// item; deleting removes one; and internal-node key-ptrs re-tile the same way.
fn smoke_btrfs_cow_node_split() -> TestResult {
    use crate::write::{cow_leaf_delete, cow_leaf_upsert, regroup_internal};
    const NS: usize = 4096;
    let mk = |oid: u64| BtrfsKey::new(oid, 1, 0);
    let body = alloc::vec![0x77u8; 900]; // ~4 such items fill a 4 KiB leaf

    // Upsert items into an empty leaf until it splits.
    let mut leaf = alloc::vec![0u8; NS]; // level 0, 0 items
    let mut split: Vec<Vec<u8>> = Vec::new();
    let mut inserted = 0u64;
    for i in 0..12u64 {
        let out = match cow_leaf_upsert(&leaf, &mk(i), &body, NS) {
            Ok(o) => o,
            Err(_) => return TestResult::Fail("cow_leaf_upsert errored"),
        };
        inserted = i + 1;
        if out.len() > 1 {
            split = out;
            break;
        }
        leaf = out.into_iter().next().unwrap();
    }
    if split.len() < 2 {
        return TestResult::Fail("leaf never split");
    }
    // Every item survived, all leaves are level 0, and keys are globally ordered.
    let mut keys: Vec<BtrfsKey> = Vec::new();
    for lf in &split {
        if btree::level(lf).unwrap_or(9) != 0 {
            return TestResult::Fail("split produced a non-leaf");
        }
        for j in 0..btree::nritems(lf).unwrap_or(0) as usize {
            keys.push(match btree::leaf_item_key(lf, j) {
                Ok(k) => k,
                Err(_) => return TestResult::Fail("bad key in split leaf"),
            });
        }
    }
    if keys.len() as u64 != inserted {
        return TestResult::Fail("items lost across the split");
    }
    if keys.windows(2).any(|w| w[0] >= w[1]) {
        return TestResult::Fail("keys not ordered across the split");
    }

    // Deleting removes exactly one item.
    let before = btree::nritems(&split[0]).unwrap_or(0) as usize;
    let target = match btree::leaf_item_key(&split[0], 0) {
        Ok(k) => k,
        Err(_) => return TestResult::Fail("first key read failed"),
    };
    let after = match cow_leaf_delete(&split[0], &target, NS) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("cow_leaf_delete errored"),
    };
    let remaining: usize = after
        .iter()
        .map(|lf| btree::nritems(lf).unwrap_or(0) as usize)
        .sum();
    if remaining != before - 1 {
        return TestResult::Fail("delete did not remove exactly one item");
    }

    // Internal-node key-ptrs re-tile past the fanout into ordered level-1 nodes.
    let ptrs: Vec<(BtrfsKey, u64, u64)> = (0..130u64).map(|i| (mk(i), 0x1000 + i, 7)).collect();
    let header = alloc::vec![0u8; NS];
    let nodes = regroup_internal(&header, &ptrs, NS, 1);
    if nodes.len() < 2 {
        return TestResult::Fail("internal node never split");
    }
    let total: usize = nodes
        .iter()
        .map(|nd| btree::nritems(nd).unwrap_or(0) as usize)
        .sum();
    if total != 130 || nodes.iter().any(|nd| btree::level(nd).unwrap_or(0) != 1) {
        return TestResult::Fail("internal re-tiling lost pointers or level");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_cow_node_split);

/// The path-COW engine applied to a real multi-level fs tree: a batch of
/// upserts + deletes produces a tree that, read back through a cursor, contains
/// exactly the expected items (edits applied, everything else untouched) — while
/// COWing only the touched paths (far fewer new blocks than the tree has).
fn smoke_btrfs_path_cow_engine() -> TestResult {
    use crate::write::{Edit, PathCow};

    // Read every (key, body) of the tree rooted at `root`, in key order.
    fn collect_all(
        vol: &BtrfsVolume<narf_block::ram::RamBlockDevice>,
        root: u64,
    ) -> Option<Vec<(BtrfsKey, Vec<u8>)>> {
        let mut cursor =
            poll_once(btree::Cursor::seek(vol, root, &BtrfsKey::new(0, 0, 0)))?.ok()?;
        let mut out = Vec::new();
        while let Some((k, b)) = cursor.current().ok()? {
            out.push((k, b.to_vec()));
            poll_once(cursor.advance())?.ok()?;
        }
        Some(out)
    }

    let vol = match mount_sparse(FIXTURE_MANYFILES_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("manyfiles fixture failed to mount"),
    };
    let (fs_root, fs_level) = vol.fs_tree_root();
    if fs_level == 0 {
        return TestResult::Fail("fixture fs tree is not multi-level");
    }

    let orig = match collect_all(&vol, fs_root) {
        Some(v) => v,
        None => return TestResult::Fail("could not read original tree"),
    };

    // Build a batch: 30 fresh upserts (objectids far above any existing) and 10
    // deletes of existing keys. Track the expected item set in parallel.
    let mut expected = orig.clone();
    let mut edits: Vec<Edit> = Vec::new();
    for i in 0..30u64 {
        let k = BtrfsKey::new(1_000_000 + i, format::INODE_ITEM_KEY, 0);
        let body = alloc::vec![i as u8; 40 + (i as usize % 20)];
        edits.push(Edit::Upsert(k, body.clone()));
        match expected.binary_search_by(|(ek, _)| ek.cmp(&k)) {
            Ok(p) => expected[p].1 = body,
            Err(p) => expected.insert(p, (k, body)),
        }
    }
    for (k, _) in orig.iter().step_by(37).take(10) {
        edits.push(Edit::Delete(*k));
        if let Ok(p) = expected.binary_search_by(|(ek, _)| ek.cmp(k)) {
            expected.remove(p);
        }
    }

    let gen = vol.superblock().generation + 1;
    let result = poll_once(async {
        let mut alloc = crate::allocator::Allocator::build(&vol).await?;
        let cow = PathCow::new(&vol, gen, fs_root, fs_level).await?;
        let out = cow.apply(&mut alloc, &edits).await?;
        // Stamp + write the new nodes so the tree is readable from its new root.
        for (addr, buf, _lvl) in &out.nodes {
            let mut b = buf.clone();
            crate::write::stamp_node(&mut b, *addr, gen, vol.csum_type())?;
            vol.write_logical(*addr, &b).await?;
        }
        Ok::<_, FsError>((
            out.root_addr,
            out.nodes.len(),
            out.freed.len(),
            out.root_level,
        ))
    });
    let (new_root, new_blocks, freed, new_level) = match result {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("path-COW engine errored"),
    };

    // Only the touched paths were COWed: far fewer new blocks than the whole tree,
    // some old path blocks were freed, and the tree stayed multi-level.
    if new_blocks >= orig.len() / 4 {
        return TestResult::Fail("path-COW rewrote too much of the tree");
    }
    if freed == 0 || new_level == 0 {
        return TestResult::Fail("path-COW freed nothing or collapsed the tree");
    }

    match collect_all(&vol, new_root) {
        Some(got) if got == expected => TestResult::Pass,
        Some(_) => TestResult::Fail("path-COW tree contents do not match expected"),
        None => TestResult::Fail("could not read path-COW tree"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_path_cow_engine);

/// `symlink` creates a symlink whose target (stored as an inline `EXTENT_DATA`)
/// reads back and whose type is `Symlink` after a remount — exactly how the VFS
/// follows it.
fn smoke_btrfs_symlink_create() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::{FileType, FsInstance};

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    let target = "../some/where/big.dat";
    if !matches!(poll_once(vol.root().symlink("mylink", target)), Some(Ok(_))) {
        return TestResult::Fail("symlink failed");
    }

    let vol2 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount after symlink failed"),
    };
    let root2 = vol2.root();
    if !dir_names(&root2).iter().any(|n| n == "mylink") {
        return TestResult::Fail("symlink not listed");
    }
    let link = match poll_once(root2.lookup_async("mylink")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup of symlink failed"),
    };
    if link.stat().mode.file_type != FileType::Symlink {
        return TestResult::Fail("created node is not a symlink");
    }
    match read_all(&link, target.len() + 16).as_deref() {
        Some(got) if got == target.as_bytes() => TestResult::Pass,
        _ => TestResult::Fail("symlink target content wrong"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_symlink_create);

/// Btrfs symlinks are always one uncompressed inline extent. Match Linux's
/// exact single-item limit: the largest fitting target persists, while the
/// next byte is rejected instead of emitting a non-interoperable regular
/// extent or failing later while packing the leaf.
fn smoke_btrfs_symlink_inline_limit() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("symlink-limit fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    let max = core::cmp::min(
        vol.nodesize() - crate::btree::HEADER_SIZE - format::DISK_KEY_SIZE - 8 - 21,
        vol.sectorsize() as usize - 1,
    );
    let accepted = "x".repeat(max);
    if !matches!(
        poll_once(vol.root().symlink("max-link", &accepted)),
        Some(Ok(_))
    ) {
        return TestResult::Fail("maximum inline symlink target was rejected");
    }
    let rejected = "y".repeat(max + 1);
    if !matches!(
        poll_once(vol.root().symlink("too-long", &rejected)),
        Some(Err(FsError::Unsupported))
    ) {
        return TestResult::Fail("oversized symlink target was accepted");
    }

    let vol2 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount after maximum symlink failed"),
    };
    let link = match poll_once(vol2.root().lookup_async("max-link")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("maximum symlink did not persist"),
    };
    if read_all(&link, accepted.len() + 1).as_deref() != Some(accepted.as_bytes()) {
        return TestResult::Fail("maximum symlink target changed after remount");
    }
    if !matches!(
        poll_once(vol2.root().lookup_async("too-long")),
        Some(Err(FsError::NotFound))
    ) {
        return TestResult::Fail("rejected symlink left a directory entry");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_symlink_inline_limit);

/// `mknod` creates a char device node that stats as `Special` with the right
/// `st_rdev` after a remount.
fn smoke_btrfs_mknod_device() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::{FileType, FsInstance};

    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fst fixture failed to mount"),
    };
    let device: Arc<RamBlockDevice> = vol.device.clone();
    // Linux dev_t for char device 1:3 (/dev/null), compact encoding.
    let rdev = (1u64 << 8) | 3;
    if !matches!(
        poll_once(vol.root().mknod("mychar", FileType::Special, rdev)),
        Some(Ok(_))
    ) {
        return TestResult::Fail("mknod failed");
    }

    let vol2 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount after mknod failed"),
    };
    let dev = match poll_once(vol2.root().lookup_async("mychar")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup of device node failed"),
    };
    if dev.stat().mode.file_type != FileType::Special {
        return TestResult::Fail("mknod'd node is not a char device");
    }
    match poll_once(dev.statx_async(0, 0x7ff)) {
        Some(Ok(sx)) if sx.rdev_major == 1 && sx.rdev_minor == 3 => TestResult::Pass,
        _ => TestResult::Fail("device rdev wrong after remount"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_mknod_device);

// ── Phase 8: boot auto-mount chain ─────────────────────────────────

/// A read-only synchronous block device over an in-memory image — the same
/// `BlockDeviceSync` surface a virtio-blk disk presents at boot, so this drives
/// the real detect → factory (`SyncBlock` + mount) auto-mount path.
#[derive(Debug)]
struct FixtureSyncDevice {
    data: Vec<u8>,
    lba_size: u32,
}

impl narf_block::BlockDeviceSync for FixtureSyncDevice {
    fn lba_size(&self) -> u32 {
        self.lba_size
    }
    fn capacity(&self) -> u64 {
        (self.data.len() / self.lba_size as usize) as u64
    }
    fn read(
        &self,
        lba: u64,
        n_blocks: u16,
        out: &mut [u8],
    ) -> Result<(), narf_block::BlockIoError> {
        let start = (lba * u64::from(self.lba_size)) as usize;
        let want = usize::from(n_blocks) * self.lba_size as usize;
        let end = start + want;
        if end > self.data.len() {
            return Err(narf_block::BlockIoError::DriverError);
        }
        let n = out.len().min(want);
        out[..n].copy_from_slice(&self.data[start..start + n]);
        Ok(())
    }
    fn write(&self, _lba: u64, _n: u16, _data: &[u8]) -> Result<(), narf_block::BlockIoError> {
        Err(narf_block::BlockIoError::DriverError)
    }
}

fn smoke_btrfs_autodetect_and_mount() -> TestResult {
    use narf_block::fs_detect::{detect_filesystem, FsType};
    use narf_block::{BlockDeviceSync, SyncBlock};
    use narf_filesystem::FsInstance;

    let img = decode_sparse(FIXTURE_SPARSE);
    let sync: Arc<dyn BlockDeviceSync> = Arc::new(FixtureSyncDevice {
        data: img,
        lba_size: 512,
    });

    // Superblock auto-detection must recognise the image as btrfs — the gate the
    // root-mount initcall uses to pick the driver.
    match detect_filesystem(&sync) {
        Ok(Some(FsType::Btrfs)) => {}
        _ => return TestResult::Fail("fs_detect did not recognise btrfs"),
    }

    // Mount through the SyncBlock adapter exactly as `btrfs_factory` does, then
    // confirm the mounted instance lists its root.
    let async_dev = SyncBlock::new(sync);
    let vol = match poll_once(BtrfsVolume::mount(async_dev, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount via SyncBlock adapter failed"),
    };
    let fs: Arc<dyn FsInstance> = vol;
    let entries = match poll_once(fs.root().enumerate_async(0, 64)) {
        Some(Ok(e)) => e,
        _ => return TestResult::Fail("auto-mounted root enumerate failed"),
    };
    if !entries.iter().any(|(n, _)| n == "big.dat") {
        return TestResult::Fail("auto-mounted fs missing expected file");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_autodetect_and_mount);

// ── Symlinks ───────────────────────────────────────────────────────

fn smoke_btrfs_symlink() -> TestResult {
    use narf_filesystem::{FileType, FsInstance};
    let vol = match mount_fixture() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fixture failed to mount"),
    };
    let root = vol.root();

    // The symlink shows up as a Symlink in readdir.
    let entries = match poll_once(root.enumerate_async(0, 64)) {
        Some(Ok(e)) => e,
        _ => return TestResult::Fail("enumerate failed"),
    };
    if !entries
        .iter()
        .any(|(n, t)| n == "link.txt" && *t == FileType::Symlink)
    {
        return TestResult::Fail("link.txt not listed as a symlink");
    }

    // Looking it up yields a node whose stat reports Symlink and whose contents
    // are the link target (this is what the VFS reads to follow the link).
    let link = match poll_once(root.lookup_async("link.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup link.txt failed"),
    };
    if link.stat().mode.file_type != FileType::Symlink {
        return TestResult::Fail("symlink stat is not Symlink");
    }
    match read_all(&link, 256).as_deref() {
        Some(b"hello.txt") => TestResult::Pass,
        _ => TestResult::Fail("symlink target content wrong"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_symlink);

// ── Extended attributes ────────────────────────────────────────────

fn smoke_btrfs_xattr() -> TestResult {
    use narf_filesystem::{FsError, FsInstance};
    let vol = match mount_fixture() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fixture failed to mount"),
    };
    let hello = match poll_once(vol.root().lookup_async("hello.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup hello.txt failed"),
    };
    // The known attribute round-trips.
    match poll_once(hello.get_xattr("user.narf")) {
        Some(Ok(v)) if v == b"hi" => {}
        _ => return TestResult::Fail("get_xattr(user.narf) wrong"),
    }
    // A missing attribute is NotFound.
    if !matches!(
        poll_once(hello.get_xattr("user.absent")),
        Some(Err(FsError::NotFound))
    ) {
        return TestResult::Fail("missing xattr should be NotFound");
    }
    // listxattr contains the NUL-terminated name.
    match poll_once(hello.list_xattr()) {
        Some(Ok(list)) if list.windows(10).any(|w| w == b"user.narf\0") => TestResult::Pass,
        _ => TestResult::Fail("list_xattr missing user.narf"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_xattr);

// ── statx ──────────────────────────────────────────────────────────

fn smoke_btrfs_statx() -> TestResult {
    use narf_filesystem::FsInstance;
    let vol = match mount_fixture() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fixture failed to mount"),
    };
    let big = match poll_once(vol.root().lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup big.dat failed"),
    };
    let sx = match poll_once(big.statx_async(0, 0)) {
        Some(Ok(sx)) => sx,
        _ => return TestResult::Fail("statx_async failed"),
    };
    if sx.size != 12000 {
        return TestResult::Fail("statx size wrong");
    }
    if sx.mode & 0o170000 != 0o100000 {
        return TestResult::Fail("statx mode is not a regular file");
    }
    if sx.nlink < 1 || sx.ino == 0 || sx.block_size != 4096 {
        return TestResult::Fail("statx nlink/ino/blocksize wrong");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_statx);

// ── zlib compression ───────────────────────────────────────────────

fn smoke_btrfs_zlib_read() -> TestResult {
    use narf_filesystem::FsInstance;
    let vol = match mount_sparse(FIXTURE_ZLIB_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("zlib fixture failed to mount"),
    };
    let big = match poll_once(vol.root().lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup big.dat failed"),
    };
    let want = expected_big();
    // Full decode of the zlib-compressed regular extent.
    match read_all(&big, want.len() + 16) {
        Some(got) if got == want => {}
        _ => return TestResult::Fail("zlib full read mismatch"),
    }
    // A partial read inside the compressed extent returns the right slice.
    let mut mid = [0u8; 20];
    match poll_once(big.read(4090, &mut mid)) {
        Some(Ok(20)) if mid[..] == want[4090..4110] => TestResult::Pass,
        _ => TestResult::Fail("zlib partial read mismatch"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_zlib_read);

fn smoke_btrfs_zstd_read() -> TestResult {
    use narf_filesystem::FsInstance;
    let vol = match mount_sparse(FIXTURE_ZSTD_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("zstd fixture failed to mount"),
    };
    let big = match poll_once(vol.root().lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup big.dat failed"),
    };
    let want = expected_big();
    match read_all(&big, want.len() + 16) {
        Some(got) if got == want => {}
        _ => return TestResult::Fail("zstd full read mismatch"),
    }
    let mut mid = [0u8; 20];
    match poll_once(big.read(4090, &mut mid)) {
        Some(Ok(20)) if mid[..] == want[4090..4110] => TestResult::Pass,
        _ => TestResult::Fail("zstd partial read mismatch"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_zstd_read);

fn smoke_btrfs_lzo_read() -> TestResult {
    use narf_filesystem::FsInstance;
    let vol = match mount_sparse(FIXTURE_LZO_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("lzo fixture failed to mount"),
    };
    let big = match poll_once(vol.root().lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup big.dat failed"),
    };
    let want = expected_big();
    // big.dat is a multi-segment LZO extent (3 sectors) — full decode.
    match read_all(&big, want.len() + 16) {
        Some(got) if got == want => {}
        _ => return TestResult::Fail("lzo full read mismatch"),
    }
    // A partial read that crosses an LZO segment (sector) boundary.
    let mut mid = [0u8; 20];
    match poll_once(big.read(4090, &mut mid)) {
        Some(Ok(20)) if mid[..] == want[4090..4110] => TestResult::Pass,
        _ => TestResult::Fail("lzo partial read mismatch"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_lzo_read);

/// Exercise a tail overwrite+grow for one readable compression codec, then
/// verify extent metadata, accounting and physical data checksums after
/// remount. Keeping codecs as separately registered tests makes architecture-
/// specific codec failures directly isolatable through the subsystem filter.
fn smoke_btrfs_compressed_cow_write_case(sparse: &[u8], compression: u8) -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    {
        let vol = match mount_sparse(sparse) {
            Ok(v) => v,
            Err(_) => return TestResult::Fail("compressed fixture failed to mount"),
        };
        let device: Arc<RamBlockDevice> = vol.device.clone();
        let big = match poll_once(vol.root().lookup_async("big.dat")) {
            Some(Ok(f)) => f,
            _ => return TestResult::Fail("compressed big.dat lookup failed"),
        };
        let ino = big.ino();
        let (fs_root, _) = vol.fs_tree_root();
        let old_items = match poll_once(btree::collect_for(
            &vol,
            fs_root,
            ino,
            format::EXTENT_DATA_KEY,
        )) {
            Some(Ok(items)) => items,
            _ => return TestResult::Fail("compressed extent lookup failed"),
        };
        if old_items.len() != 1
            || old_items[0].1.get(16).copied() != Some(compression)
            || old_items[0].1.get(20).copied() != Some(format::FILE_EXTENT_REG)
        {
            return TestResult::Fail("fixture does not contain expected compressed extent");
        }
        let old_extent = match file_data_extent(&vol, ino) {
            Some(extent) => extent,
            None => return TestResult::Fail("compressed physical extent missing"),
        };

        let mut want = expected_big();
        let offset = want.len() - 4;
        let patch = b"compressed-cow-tail\n";
        want.resize(offset + patch.len(), 0);
        want[offset..].copy_from_slice(patch);
        match poll_once(big.write(offset as u64, patch)) {
            Some(Ok(n)) if n == patch.len() => {}
            _ => return TestResult::Fail("compressed COW write failed"),
        }

        let vol2 = match poll_once(BtrfsVolume::mount(device, DomainId::DRIVER_0)) {
            Some(Ok(v)) => v,
            _ => return TestResult::Fail("compressed COW remount failed"),
        };
        let big2 = match poll_once(vol2.root().lookup_async("big.dat")) {
            Some(Ok(f)) => f,
            _ => return TestResult::Fail("compressed COW remount lookup failed"),
        };
        if read_all(&big2, want.len() + 16) != Some(want) {
            return TestResult::Fail("compressed COW content mismatch");
        }
        let (fs_root2, _) = vol2.fs_tree_root();
        let new_items = match poll_once(btree::collect_for(
            &vol2,
            fs_root2,
            ino,
            format::EXTENT_DATA_KEY,
        )) {
            Some(Ok(items)) => items,
            _ => return TestResult::Fail("replacement extent lookup failed"),
        };
        let expected_compression = if compression == format::COMPRESS_ZLIB {
            format::COMPRESS_ZLIB
        } else {
            format::COMPRESS_NONE
        };
        if new_items.iter().any(|(_, body)| {
            body.get(16).copied() != Some(expected_compression)
                || body.get(20).copied() != Some(format::FILE_EXTENT_REG)
        }) {
            return TestResult::Fail("replacement extent compression mode is wrong");
        }
        if compression == format::COMPRESS_ZLIB {
            let body = &new_items[0].1;
            let ram_bytes = format::le64(body, 8).unwrap_or(0);
            let disk_bytes = format::le64(body, 29).unwrap_or(u64::MAX);
            let num_bytes = format::le64(body, 45).unwrap_or(0);
            if disk_bytes >= ram_bytes
                || disk_bytes % u64::from(vol2.sectorsize()) != 0
                || num_bytes != ram_bytes
            {
                return TestResult::Fail("emitted zlib extent sizes are invalid");
            }
        }
        let new_extent = match file_data_extent(&vol2, ino) {
            Some(extent) => extent,
            None => return TestResult::Fail("replacement physical extent missing"),
        };
        if new_extent.0 == old_extent.0
            || extent_item_present(&vol2, old_extent.0, old_extent.1)
            || !extent_item_present(&vol2, new_extent.0, new_extent.1)
        {
            return TestResult::Fail("compressed extent accounting is wrong");
        }
        let csum_root = match csum_root_of(&vol2) {
            Some(root) => root,
            None => return TestResult::Fail("compressed COW csum root missing"),
        };
        match poll_once(crate::csum::verify_file_data_csums(
            &vol2, fs_root2, csum_root, ino,
        )) {
            Some(Ok(true)) => {}
            _ => return TestResult::Fail("compressed replacement physical csums are invalid"),
        }
    }
    TestResult::Pass
}

fn smoke_btrfs_zlib_cow_write() -> TestResult {
    smoke_btrfs_compressed_cow_write_case(FIXTURE_ZLIB_SPARSE, format::COMPRESS_ZLIB)
}

fn smoke_btrfs_zlib_codec_roundtrip() -> TestResult {
    let plain = expected_big();
    let encoded = match crate::write::compress_zlib_heap(&plain, 6) {
        Ok(encoded) => encoded,
        Err(_) => return TestResult::Fail("zlib encode failed"),
    };
    match miniz_oxide::inflate::decompress_to_vec_zlib(&encoded) {
        Ok(decoded) if decoded == plain => TestResult::Pass,
        _ => TestResult::Fail("zlib codec round-trip mismatch"),
    }
}

kernel_test_in!(
    "drivers/fs/btrfs/compression/zlib/codec",
    smoke_btrfs_zlib_codec_roundtrip
);

kernel_test_in!(
    "drivers/fs/btrfs/compression/zlib",
    smoke_btrfs_zlib_cow_write
);

fn smoke_btrfs_zstd_cow_write() -> TestResult {
    smoke_btrfs_compressed_cow_write_case(FIXTURE_ZSTD_SPARSE, format::COMPRESS_ZSTD)
}

kernel_test_in!(
    "drivers/fs/btrfs/compression/zstd",
    smoke_btrfs_zstd_cow_write
);

fn smoke_btrfs_lzo_cow_write() -> TestResult {
    smoke_btrfs_compressed_cow_write_case(FIXTURE_LZO_SPARSE, format::COMPRESS_LZO)
}

kernel_test_in!(
    "drivers/fs/btrfs/compression/lzo",
    smoke_btrfs_lzo_cow_write
);

// ── Subvolumes ─────────────────────────────────────────────────────

fn smoke_btrfs_subvolume() -> TestResult {
    use narf_filesystem::{FileType, FsInstance};
    let vol = match mount_fixture() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fixture failed to mount"),
    };
    let root = vol.root();

    // `snap` is a nested subvolume; it lists as a directory in the parent.
    let entries = match poll_once(root.enumerate_async(0, 64)) {
        Some(Ok(e)) => e,
        _ => return TestResult::Fail("root enumerate failed"),
    };
    if !entries
        .iter()
        .any(|(n, t)| n == "snap" && *t == FileType::Dir)
    {
        return TestResult::Fail("snap subvolume not listed as a directory");
    }

    // Descending crosses into the subvolume's own fs tree (ROOT_ITEM location).
    let snap = match poll_once(root.lookup_dir_async("snap")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("lookup_dir_async(snap) failed"),
    };
    let snap_entries = match poll_once(snap.enumerate_async(0, 64)) {
        Some(Ok(e)) => e,
        _ => return TestResult::Fail("snap enumerate failed"),
    };
    if !snap_entries.iter().any(|(n, _)| n == "inside.txt") {
        return TestResult::Fail("subvolume missing inside.txt");
    }

    // And a file inside the subvolume reads back its content.
    let inside = match poll_once(snap.lookup_async("inside.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup inside.txt failed"),
    };
    match read_all(&inside, 64).as_deref() {
        Some(b"inside subvol\n") => TestResult::Pass,
        _ => TestResult::Fail("subvolume file content wrong"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_subvolume);

// ── Deep (multi-level) b-tree ──────────────────────────────────────

fn smoke_btrfs_deep_tree() -> TestResult {
    use narf_filesystem::FsInstance;
    let vol = match mount_sparse(FIXTURE_MANYFILES_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("manyfiles fixture failed to mount"),
    };
    let root = vol.root();

    // Enumerate all 400 entries — exercises the cursor's descent through the
    // level-1 root node and advance across many leaves.
    let all = match poll_once(root.enumerate_async(0, 1000)) {
        Some(Ok(e)) => e,
        _ => return TestResult::Fail("enumerate all failed"),
    };
    if all.len() != 400 {
        return TestResult::Fail("expected 400 entries in a multi-level tree");
    }
    for want in ["file000.txt", "file200.txt", "file399.txt"] {
        if !all.iter().any(|(n, _)| n == want) {
            return TestResult::Fail("a boundary file is missing from the listing");
        }
    }

    // Paging via the cursor argument returns disjoint, complete slices.
    let page0 = poll_once(root.enumerate_async(0, 150)).and_then(|r| r.ok());
    let page2 = poll_once(root.enumerate_async(300, 150)).and_then(|r| r.ok());
    match (page0, page2) {
        (Some(a), Some(b)) if a.len() == 150 && b.len() == 100 => {}
        _ => return TestResult::Fail("paged enumerate returned wrong counts"),
    }

    // A file in a far leaf resolves and reads back (deep find_item).
    let f = match poll_once(root.lookup_async("file399.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup of a far-leaf file failed"),
    };
    match read_all(&f, 64).as_deref() {
        Some(b"content-of-file-399\n") => TestResult::Pass,
        _ => TestResult::Fail("far-leaf file content wrong"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_deep_tree);

// ── subvol= / subvolid= mount options ──────────────────────────────

fn smoke_btrfs_mount_subvol_option() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    // Option parsing.
    match crate::parse_mount_subvol("ro,subvol=snap") {
        Ok(Some(crate::volume::Subvol::Name(ref n))) if n == "snap" => {}
        _ => return TestResult::Fail("subvol=snap did not parse"),
    }
    match crate::parse_mount_subvol("subvolid=256") {
        Ok(Some(crate::volume::Subvol::Id(256))) => {}
        _ => return TestResult::Fail("subvolid=256 did not parse"),
    }
    match crate::parse_mount_subvol("subvol=/container/outer/inner/") {
        Ok(Some(crate::volume::Subvol::Name(ref n))) if n == "container/outer/inner" => {}
        _ => return TestResult::Fail("multi-level subvol path did not parse"),
    }
    for bad in ["subvol=a//b", "subvol=a/./b", "subvol=a/../b"] {
        if crate::parse_mount_subvol(bad).is_ok() {
            return TestResult::Fail("ambiguous subvol path should be rejected");
        }
    }
    if crate::parse_mount_subvol("bogus=1").is_ok() {
        return TestResult::Fail("unknown option should be rejected");
    }

    // Mounting with subvol=snap roots the volume inside the subvolume.
    let dev = RamBlockDevice::from_image(512, decode_sparse(FIXTURE_SPARSE));
    let sel = Some(crate::volume::Subvol::Name("snap".into()));
    let vol = match poll_once(BtrfsVolume::mount_subvol(
        dev,
        DomainId::DRIVER_0,
        true,
        sel,
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount subvol=snap failed"),
    };
    let entries = match poll_once(vol.root().enumerate_async(0, 64)) {
        Some(Ok(e)) => e,
        _ => return TestResult::Fail("subvol root enumerate failed"),
    };
    // The subvolume root contains inside.txt and NOT the parent's hello.txt.
    if !entries.iter().any(|(n, _)| n == "inside.txt")
        || entries.iter().any(|(n, _)| n == "hello.txt")
    {
        return TestResult::Fail("subvol root listing is not the subvolume's");
    }
    if !vol.supports_writes() {
        return TestResult::Fail("rw subvolume mounted read-only");
    }

    // subvolid= reaching the same subvolume works too (snap's id resolved by
    // switching a default mount, then mounting by that id).
    let probe = match mount_fixture() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("probe mount failed"),
    };
    if poll_once(probe.switch_to_subvol(&crate::volume::Subvol::Name("snap".into())))
        .map(|r| r.is_err())
        .unwrap_or(true)
    {
        return TestResult::Fail("switch_to_subvol by name failed");
    }

    // A path can cross an ordinary directory, enter a subvolume, and then enter
    // a subvolume nested inside it. Resolution starts at FS_TREE, not whichever
    // on-disk default subvolume mount_opts may have selected.
    let dev = RamBlockDevice::from_image(512, decode_sparse(FIXTURE_NESTEDSUBVOL_SPARSE));
    let sel = Some(crate::volume::Subvol::Name("container/outer/inner".into()));
    let nested = match poll_once(BtrfsVolume::mount_subvol(
        dev,
        DomainId::DRIVER_0,
        true,
        sel,
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("multi-level subvol mount failed"),
    };
    let entries = match poll_once(nested.root().enumerate_async(0, 16)) {
        Some(Ok(e)) => e,
        _ => return TestResult::Fail("nested subvol root enumerate failed"),
    };
    if entries.len() != 1 || entries[0].0 != "deep.txt" {
        return TestResult::Fail("multi-level subvol mounted the wrong tree");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_mount_subvol_option);

fn smoke_btrfs_subvolume_getflags_ioctl() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let mount_fresh = |path: &str| {
        let device = RamBlockDevice::from_image(512, decode_sparse(FIXTURE_NESTEDSUBVOL_SPARSE));
        poll_once(BtrfsVolume::mount_subvol(
            device,
            DomainId::DRIVER_0,
            true,
            Some(crate::volume::Subvol::Name(path.into())),
        ))
        .and_then(Result::ok)
    };
    let get_flags = |root: &dyn narf_filesystem::DirOps| {
        poll_once(root.ioctl_async(crate::node::BTRFS_IOC_SUBVOL_GETFLAGS, 0, &[], 8))
            .and_then(Result::ok)
            .and_then(|reply| reply.output.try_into().ok())
            .map(u64::from_ne_bytes)
    };
    let set_flags = |root: &dyn narf_filesystem::DirOps, flags: u64| {
        let input = flags.to_ne_bytes();
        poll_once(root.ioctl_async(crate::node::BTRFS_IOC_SUBVOL_SETFLAGS, 0, &input, 0))
    };

    let device = RamBlockDevice::from_image(512, decode_sparse(FIXTURE_NESTEDSUBVOL_SPARSE));
    let selected = crate::volume::Subvol::Name("container/outer/inner".into());
    let mount_selected = || {
        poll_once(BtrfsVolume::mount_subvol(
            device.clone(),
            DomainId::DRIVER_0,
            true,
            Some(selected.clone()),
        ))
        .and_then(Result::ok)
    };

    let writable = match mount_selected() {
        Some(v) => v,
        None => return TestResult::Fail("writable subvolume ioctl mount failed"),
    };
    let writable_root = writable.root();
    let original_fs_root = writable.fs_tree_root();
    let original_root_tree = writable.root_tree_root();
    let original_generation = writable.superblock().generation;
    if get_flags(&*writable_root) != Some(0) {
        return TestResult::Fail("writable subvolume returned incorrect flags");
    }
    if !matches!(
        poll_once(writable_root.ioctl_async(crate::node::BTRFS_IOC_SUBVOL_GETFLAGS, 0, &[], 4,)),
        Some(Err(FsError::InvalidData))
    ) {
        return TestResult::Fail("subvolume GETFLAGS accepted the wrong ABI size");
    }
    let ordinary = match poll_once(writable_root.lookup_async("deep.txt")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("subvolume ioctl ordinary-file lookup failed"),
    };
    if !matches!(
        poll_once(ordinary.ioctl_async(crate::node::BTRFS_IOC_SUBVOL_GETFLAGS, 0, &[], 8,)),
        Some(Err(FsError::InvalidData))
    ) {
        return TestResult::Fail("ordinary file accepted subvolume GETFLAGS");
    }
    if !matches!(
        poll_once(ordinary.ioctl_async(
            crate::node::BTRFS_IOC_SUBVOL_SETFLAGS,
            0,
            &crate::node::BTRFS_SUBVOL_RDONLY.to_ne_bytes(),
            0,
        )),
        Some(Err(FsError::InvalidData))
    ) {
        return TestResult::Fail("ordinary file accepted subvolume SETFLAGS");
    }
    if !matches!(
        poll_once(
            writable_root.ioctl_async(crate::node::BTRFS_IOC_SUBVOL_SETFLAGS, 0, &[0; 4], 0,)
        ),
        Some(Err(FsError::InvalidData))
    ) {
        return TestResult::Fail("subvolume SETFLAGS accepted the wrong input size");
    }
    if !matches!(
        set_flags(&*writable_root, 1 << 63),
        Some(Err(FsError::InvalidData))
    ) {
        return TestResult::Fail("subvolume SETFLAGS accepted an unknown flag");
    }

    let set_reply = match set_flags(&*writable_root, crate::node::BTRFS_SUBVOL_RDONLY) {
        Some(Ok(reply)) => reply,
        _ => return TestResult::Fail("setting subvolume read-only failed"),
    };
    if set_reply.result != 0 || !set_reply.output.is_empty() {
        return TestResult::Fail("subvolume SETFLAGS returned the wrong ABI reply");
    }
    if writable.supports_writes()
        || get_flags(&*writable_root) != Some(crate::node::BTRFS_SUBVOL_RDONLY)
    {
        return TestResult::Fail("SETFLAGS did not publish read-only state immediately");
    }
    if writable.fs_tree_root() != original_fs_root {
        return TestResult::Fail("root-only SETFLAGS rewrote the subvolume fs tree");
    }
    if writable.root_tree_root() == original_root_tree
        || writable.superblock().generation != original_generation + 1
    {
        return TestResult::Fail("SETFLAGS did not commit a new root-tree generation");
    }
    if !matches!(
        poll_once(writable_root.create("must-not-exist")),
        Some(Err(FsError::ReadOnly))
    ) {
        return TestResult::Fail("newly read-only subvolume accepted a mutation");
    }

    let remounted_readonly = match mount_selected() {
        Some(v) => v,
        None => return TestResult::Fail("read-only SETFLAGS remount failed"),
    };
    let remounted_readonly_root = remounted_readonly.root();
    if remounted_readonly.supports_writes()
        || get_flags(&*remounted_readonly_root) != Some(crate::node::BTRFS_SUBVOL_RDONLY)
        || remounted_readonly.fs_tree_root() != original_fs_root
    {
        return TestResult::Fail("read-only SETFLAGS state did not persist across remount");
    }

    let readonly_generation = remounted_readonly.superblock().generation;
    if !matches!(set_flags(&*remounted_readonly_root, 0), Some(Ok(_))) {
        return TestResult::Fail("clearing flags on a read-only subvolume failed");
    }
    if !remounted_readonly.supports_writes()
        || get_flags(&*remounted_readonly_root) != Some(0)
        || remounted_readonly.superblock().generation != readonly_generation + 1
    {
        return TestResult::Fail("clearing SETFLAGS did not publish writable state");
    }

    let remounted_writable = match mount_selected() {
        Some(v) => v,
        None => return TestResult::Fail("writable SETFLAGS remount failed"),
    };
    let remounted_writable_root = remounted_writable.root();
    if !remounted_writable.supports_writes() || get_flags(&*remounted_writable_root) != Some(0) {
        return TestResult::Fail("cleared SETFLAGS state did not persist across remount");
    }
    if !matches!(
        poll_once(remounted_writable_root.create("flags-write-ok")),
        Some(Ok(_))
    ) {
        return TestResult::Fail("writable subvolume rejected mutation after clearing flags");
    }

    let readonly = match mount_fresh("container/outer/rochild") {
        Some(vol) => vol,
        None => return TestResult::Fail("read-only subvolume ioctl mount failed"),
    };
    let readonly_root = readonly.root();
    if readonly.supports_writes()
        || get_flags(&*readonly_root) != Some(crate::node::BTRFS_SUBVOL_RDONLY)
    {
        return TestResult::Fail("read-only subvolume flag was not surfaced");
    }
    if !matches!(
        poll_once(readonly_root.create("must-not-exist")),
        Some(Err(FsError::ReadOnly))
    ) {
        return TestResult::Fail("read-only subvolume accepted a mutation");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_subvolume_getflags_ioctl);

fn smoke_btrfs_subvolume_create_ioctl() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::{FileType, FsInstance};

    let make_v2 = |name: &str, flags: u64| {
        let mut args = alloc::vec![0u8; 4096];
        args[16..24].copy_from_slice(&flags.to_ne_bytes());
        let end = 56 + name.len();
        if end < args.len() {
            args[56..end].copy_from_slice(name.as_bytes());
        }
        args
    };
    let make_legacy = |name: &str| {
        let mut args = alloc::vec![0u8; 4096];
        let end = 8 + name.len();
        if end < args.len() {
            args[8..end].copy_from_slice(name.as_bytes());
        }
        args
    };
    let device = RamBlockDevice::from_image(512, decode_sparse(FIXTURE_NESTEDSUBVOL_SPARSE));
    let top = match poll_once(BtrfsVolume::mount_opts(
        device.clone(),
        DomainId::DRIVER_0,
        true,
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("subvolume-create fixture mount failed"),
    };
    let root = top.root();

    if !matches!(
        poll_once(root.ioctl_async(crate::node::BTRFS_IOC_SUBVOL_CREATE_V2, 0, &[0; 8], 0,)),
        Some(Err(FsError::InvalidData))
    ) {
        return TestResult::Fail("SUBVOL_CREATE_V2 accepted the wrong ABI size");
    }
    let unknown = make_v2("badflags", 1 << 63);
    if !matches!(
        poll_once(root.ioctl_async(crate::node::BTRFS_IOC_SUBVOL_CREATE_V2, 0, &unknown, 0,)),
        Some(Err(FsError::InvalidData))
    ) {
        return TestResult::Fail("SUBVOL_CREATE_V2 accepted unknown flags");
    }
    let bad_name = make_v2("bad/name", 0);
    if !matches!(
        poll_once(root.ioctl_async(crate::node::BTRFS_IOC_SUBVOL_CREATE_V2, 0, &bad_name, 0,)),
        Some(Err(FsError::InvalidData))
    ) {
        return TestResult::Fail("SUBVOL_CREATE_V2 accepted a path instead of a name");
    }

    let fresh_args = make_v2("fresh", 0);
    if !matches!(
        poll_once(root.ioctl_async(
            crate::node::BTRFS_IOC_SUBVOL_CREATE_V2,
            0,
            &fresh_args,
            0,
        )),
        Some(Ok(ref reply)) if reply.result == 0 && reply.output.is_empty()
    ) {
        return TestResult::Fail("SUBVOL_CREATE_V2 writable create failed");
    }
    if !matches!(
        poll_once(root.ioctl_async(crate::node::BTRFS_IOC_SUBVOL_CREATE_V2, 0, &fresh_args, 0,)),
        Some(Err(FsError::InvalidData))
    ) {
        return TestResult::Fail("SUBVOL_CREATE_V2 accepted a duplicate name");
    }

    let readonly_args = make_v2("frozen", crate::node::BTRFS_SUBVOL_RDONLY);
    if !matches!(
        poll_once(root.ioctl_async(
            crate::node::BTRFS_IOC_SUBVOL_CREATE_V2,
            0,
            &readonly_args,
            0,
        )),
        Some(Ok(_))
    ) {
        return TestResult::Fail("SUBVOL_CREATE_V2 read-only create failed");
    }
    let legacy_args = make_legacy("legacy");
    if !matches!(
        poll_once(root.ioctl_async(crate::node::BTRFS_IOC_SUBVOL_CREATE, 0, &legacy_args, 0,)),
        Some(Ok(_))
    ) {
        return TestResult::Fail("legacy SUBVOL_CREATE failed");
    }
    let listed = match poll_once(root.enumerate_async(0, 64)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("subvolume-create parent enumerate failed"),
    };
    for name in ["fresh", "frozen", "legacy"] {
        if !listed
            .iter()
            .any(|(entry, kind)| entry == name && *kind == FileType::Dir)
        {
            return TestResult::Fail("created subvolume missing from parent directory");
        }
    }

    let mount_named = |name: &str| {
        poll_once(BtrfsVolume::mount_subvol(
            device.clone(),
            DomainId::DRIVER_0,
            true,
            Some(crate::volume::Subvol::Name(name.into())),
        ))
        .and_then(Result::ok)
    };
    let fresh = match mount_named("fresh") {
        Some(v) => v,
        None => return TestResult::Fail("created writable subvolume did not remount"),
    };
    if !fresh.supports_writes() {
        return TestResult::Fail("created writable subvolume remounted read-only");
    }
    let fresh_id = fresh.fs_tree_id();
    if fresh_id <= format::FIRST_FREE_OBJECTID {
        return TestResult::Fail("created subvolume did not receive a new tree id");
    }
    let fresh_root = fresh.root();
    if !matches!(
        poll_once(fresh_root.enumerate_async(0, 8)),
        Some(Ok(ref entries)) if entries.is_empty()
    ) {
        return TestResult::Fail("new subvolume was not empty");
    }
    let file = match poll_once(fresh_root.create("inside.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("created subvolume rejected file creation"),
    };
    if !matches!(poll_once(file.write(0, b"new subvolume\n")), Some(Ok(14))) {
        return TestResult::Fail("created subvolume rejected file write");
    }

    let frozen = match mount_named("frozen") {
        Some(v) => v,
        None => return TestResult::Fail("created read-only subvolume did not remount"),
    };
    if frozen.supports_writes()
        || !matches!(
            poll_once(frozen.root().create("blocked")),
            Some(Err(FsError::ReadOnly))
        )
    {
        return TestResult::Fail("created read-only subvolume accepted mutation");
    }

    // Remount the parent after the child transaction so its cached root tree is
    // current, then traverse into the child and read the persisted file.
    let remounted_top = match poll_once(BtrfsVolume::mount_opts(device, DomainId::DRIVER_0, true)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("parent remount after subvolume write failed"),
    };
    let traversed = match poll_once(remounted_top.root().lookup_dir_async("fresh")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("created subvolume was not traversable after remount"),
    };
    let persisted = match poll_once(traversed.lookup_async("inside.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("created subvolume file did not persist"),
    };
    if read_all(&persisted, 32).as_deref() != Some(b"new subvolume\n") {
        return TestResult::Fail("created subvolume file contents were wrong");
    }

    // The root tree must carry both directions of the parent relation.
    let root_tree = remounted_top.root_tree_root().0;
    let parent_id = remounted_top.fs_tree_id();
    if poll_once(btree::find_item(
        &*remounted_top,
        root_tree,
        &BtrfsKey::new(parent_id, format::ROOT_REF_KEY, fresh_id),
    ))
    .and_then(Result::ok)
    .flatten()
    .is_none()
        || poll_once(btree::find_item(
            &*remounted_top,
            root_tree,
            &BtrfsKey::new(fresh_id, format::ROOT_BACKREF_KEY, parent_id),
        ))
        .and_then(Result::ok)
        .flatten()
        .is_none()
    {
        return TestResult::Fail("created subvolume root refs were incomplete");
    }
    let root_item = match poll_once(btree::find_item(
        &*remounted_top,
        root_tree,
        &BtrfsKey::new(fresh_id, format::ROOT_ITEM_KEY, 0),
    )) {
        Some(Ok(Some(body))) if body.len() >= 263 => body,
        _ => return TestResult::Fail("created subvolume root item was missing"),
    };
    let uuid = &root_item[247..263];
    let uuid_root = match poll_once(crate::roots::find_root(
        &*remounted_top,
        root_tree,
        format::UUID_TREE_OBJECTID,
    )) {
        Some(Ok((root, _))) => root,
        _ => return TestResult::Fail("UUID tree was missing after subvolume creation"),
    };
    let uuid_key = BtrfsKey::new(
        u64::from_le_bytes(uuid[..8].try_into().unwrap()),
        format::UUID_KEY_SUBVOL,
        u64::from_le_bytes(uuid[8..].try_into().unwrap()),
    );
    if !matches!(
        poll_once(btree::find_item(&*remounted_top, uuid_root, &uuid_key)),
        Some(Ok(Some(ref body))) if body.as_slice() == fresh_id.to_le_bytes()
    ) {
        return TestResult::Fail("created subvolume UUID index was incomplete");
    }

    // Exercise the same multi-tree transaction with space_cache=v2 enabled;
    // every new parent/child/UUID/root/extent block must be removed from the
    // free-space tree in the converged fixed point.
    let fst_device = RamBlockDevice::from_image(512, decode_sparse(FIXTURE_FST_SPARSE));
    let fst_top = match poll_once(BtrfsVolume::mount_opts(
        fst_device.clone(),
        DomainId::DRIVER_0,
        true,
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("free-space-tree subvolume fixture mount failed"),
    };
    let fst_args = make_v2("fstchild", 0);
    if !matches!(
        poll_once(fst_top.root().ioctl_async(
            crate::node::BTRFS_IOC_SUBVOL_CREATE_V2,
            0,
            &fst_args,
            0,
        )),
        Some(Ok(_))
    ) {
        return TestResult::Fail("free-space-tree subvolume creation failed");
    }
    if !matches!(
        poll_once(BtrfsVolume::mount_subvol(
            fst_device,
            DomainId::DRIVER_0,
            true,
            Some(crate::volume::Subvol::Name("fstchild".into())),
        )),
        Some(Ok(ref child)) if child.supports_writes()
    ) {
        return TestResult::Fail("free-space-tree subvolume did not persist");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_subvolume_create_ioctl);

fn smoke_btrfs_snapshot_create_and_isolate() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let device = RamBlockDevice::from_image(512, decode_sparse(FIXTURE_FST_SPARSE));
    let source_big_extent;
    let pre_snapshot_root;
    {
        let vol = match poll_once(BtrfsVolume::mount_opts(
            device.clone(),
            DomainId::DRIVER_0,
            true,
        )) {
            Some(Ok(v)) => v,
            _ => return TestResult::Fail("snapshot fixture mount failed"),
        };
        let root = vol.root();
        let big = match poll_once(root.lookup_async("big.dat")) {
            Some(Ok(f)) => f,
            _ => return TestResult::Fail("source big.dat lookup failed"),
        };
        source_big_extent = match file_data_extent(&vol, big.ino()) {
            Some(extent) => extent,
            None => return TestResult::Fail("source big.dat extent missing"),
        };
        pre_snapshot_root = vol.fs_tree_root();
        if !matches!(
            poll_once(root.snapshot_async(root.clone(), "snap", false)),
            Some(Ok(()))
        ) {
            return TestResult::Fail("writable snapshot creation failed");
        }
        if !matches!(
            poll_once(root.snapshot_async(root.clone(), "snap", false)),
            Some(Err(FsError::InvalidData))
        ) {
            return TestResult::Fail("duplicate snapshot name was accepted");
        }
    }

    let snapshot_id;
    {
        let snap = match poll_once(BtrfsVolume::mount_subvol(
            device.clone(),
            DomainId::DRIVER_0,
            true,
            Some(crate::volume::Subvol::Name("snap".into())),
        )) {
            Some(Ok(v)) => v,
            _ => return TestResult::Fail("created snapshot did not remount"),
        };
        if !snap.supports_writes() {
            return TestResult::Fail("writable snapshot remounted read-only");
        }
        snapshot_id = snap.fs_tree_id();
        if snap.fs_tree_root() != pre_snapshot_root {
            return TestResult::Fail("snapshot did not retain the source point-in-time root");
        }
        let extent_root = match poll_once(crate::roots::find_root(
            &*snap,
            snap.root_tree_root().0,
            format::EXTENT_TREE_OBJECTID,
        )) {
            Some(Ok((root, _))) => root,
            _ => return TestResult::Fail("snapshot extent tree missing"),
        };
        let extent_item = match poll_once(btree::find_item(
            &*snap,
            extent_root,
            &BtrfsKey::new(
                source_big_extent.0,
                format::EXTENT_ITEM_KEY,
                source_big_extent.1,
            ),
        )) {
            Some(Ok(Some(body))) => body,
            _ => return TestResult::Fail("shared snapshot extent item missing"),
        };
        if format::le64(&extent_item, 0).ok() != Some(2) {
            return TestResult::Fail("shared extent aggregate refcount is not two");
        }
        let mut roots = Vec::new();
        let mut counts = Vec::new();
        let mut pos = 24usize;
        while pos < extent_item.len() {
            if extent_item[pos] != 178 || pos + 29 > extent_item.len() {
                return TestResult::Fail("shared extent inline ref encoding malformed");
            }
            roots.push(format::le64(&extent_item, pos + 1).unwrap_or(0));
            counts.push(format::le32(&extent_item, pos + 25).unwrap_or(0));
            pos += 29;
        }
        if roots.as_slice() != [format::FS_TREE_OBJECTID] || counts.as_slice() != [2] {
            return TestResult::Fail("implicit snapshot data reference was not retained");
        }
        let hello = match poll_once(snap.root().lookup_async("hello.txt")) {
            Some(Ok(f)) => f,
            _ => return TestResult::Fail("snapshot lost inline file"),
        };
        if read_all(&hello, 16).as_deref() != Some(b"narf\n") {
            return TestResult::Fail("snapshot inline content was wrong");
        }
        let big = match poll_once(snap.root().lookup_async("big.dat")) {
            Some(Ok(f)) => f,
            _ => return TestResult::Fail("snapshot lost regular extent file"),
        };
        if read_all(&big, expected_big().len() + 8).as_deref() != Some(expected_big().as_slice()) {
            return TestResult::Fail("snapshot regular extent content was wrong");
        }
        if file_data_extent(&snap, big.ino()) != Some(source_big_extent) {
            return TestResult::Fail("snapshot copied data instead of sharing its extent");
        }
        if !matches!(poll_once(big.write(100, b"SNAP")), Some(Ok(4))) {
            return TestResult::Fail("shared snapshot data write failed");
        }
    }

    // Mutating the source after snapshot creation must not alter the snapshot.
    {
        let source = match poll_once(BtrfsVolume::mount_opts(
            device.clone(),
            DomainId::DRIVER_0,
            true,
        )) {
            Some(Ok(v)) => v,
            _ => return TestResult::Fail("source remount after snapshot failed"),
        };
        let hello = match poll_once(source.root().lookup_async("hello.txt")) {
            Some(Ok(f)) => f,
            _ => return TestResult::Fail("source hello lookup failed"),
        };
        if !matches!(poll_once(hello.write(0, b"source\n")), Some(Ok(7))) {
            return TestResult::Fail("source mutation after snapshot failed");
        }
    }
    {
        let snap = match poll_once(BtrfsVolume::mount_subvol(
            device.clone(),
            DomainId::DRIVER_0,
            true,
            Some(crate::volume::Subvol::Id(snapshot_id)),
        )) {
            Some(Ok(v)) => v,
            _ => return TestResult::Fail("snapshot id remount failed"),
        };
        let hello = match poll_once(snap.root().lookup_async("hello.txt")) {
            Some(Ok(f)) => f,
            _ => return TestResult::Fail("snapshot hello lookup failed"),
        };
        if read_all(&hello, 16).as_deref() != Some(b"narf\n") {
            return TestResult::Fail("source write leaked into snapshot");
        }
        let big = match poll_once(snap.root().lookup_async("big.dat")) {
            Some(Ok(f)) => f,
            _ => return TestResult::Fail("snapshot big.dat remount lookup failed"),
        };
        let mut expected = expected_big();
        expected[100..104].copy_from_slice(b"SNAP");
        if read_all(&big, expected.len() + 8).as_deref() != Some(expected.as_slice()) {
            return TestResult::Fail("snapshot shared-data write did not persist");
        }
        if !matches!(poll_once(hello.write(0, b"snapshot\n")), Some(Ok(9))) {
            return TestResult::Fail("snapshot mutation failed");
        }
    }
    {
        let source = match poll_once(BtrfsVolume::mount_opts(
            device.clone(),
            DomainId::DRIVER_0,
            true,
        )) {
            Some(Ok(v)) => v,
            _ => return TestResult::Fail("source final remount failed"),
        };
        let hello = match poll_once(source.root().lookup_async("hello.txt")) {
            Some(Ok(f)) => f,
            _ => return TestResult::Fail("source final hello lookup failed"),
        };
        if read_all(&hello, 16).as_deref() != Some(b"source\n") {
            return TestResult::Fail("snapshot write leaked into source");
        }
        let big = match poll_once(source.root().lookup_async("big.dat")) {
            Some(Ok(f)) => f,
            _ => return TestResult::Fail("source final big.dat lookup failed"),
        };
        if read_all(&big, expected_big().len() + 8).as_deref() != Some(expected_big().as_slice()) {
            return TestResult::Fail("snapshot shared-data write leaked into source");
        }

        let root_tree = source.root_tree_root().0;
        let source_item = match poll_once(btree::find_item(
            &*source,
            root_tree,
            &BtrfsKey::new(source.fs_tree_id(), format::ROOT_ITEM_KEY, 0),
        )) {
            Some(Ok(Some(body))) if body.len() >= 263 => body,
            _ => return TestResult::Fail("source root item UUID missing"),
        };
        let snapshot_item = match poll_once(btree::find_item(
            &*source,
            root_tree,
            &BtrfsKey::new(snapshot_id, format::ROOT_ITEM_KEY, 0),
        )) {
            Some(Ok(Some(body))) if body.len() >= 279 => body,
            _ => return TestResult::Fail("snapshot root item ancestry missing"),
        };
        if snapshot_item[263..279] != source_item[247..263] {
            return TestResult::Fail("snapshot parent UUID did not name the source");
        }
    }

    // Read-only creation uses the same transaction but persists the root flag.
    let ro_device = RamBlockDevice::from_image(512, decode_sparse(FIXTURE_FST_SPARSE));
    {
        let vol = match poll_once(BtrfsVolume::mount_opts(
            ro_device.clone(),
            DomainId::DRIVER_0,
            true,
        )) {
            Some(Ok(v)) => v,
            _ => return TestResult::Fail("read-only snapshot fixture mount failed"),
        };
        let root = vol.root();
        if !matches!(
            poll_once(root.snapshot_async(root.clone(), "frozen-snap", true)),
            Some(Ok(()))
        ) {
            return TestResult::Fail("read-only snapshot creation failed");
        }
    }
    if !matches!(
        poll_once(BtrfsVolume::mount_subvol(
            ro_device,
            DomainId::DRIVER_0,
            true,
            Some(crate::volume::Subvol::Name("frozen-snap".into())),
        )),
        Some(Ok(ref snap)) if !snap.supports_writes()
    ) {
        return TestResult::Fail("read-only snapshot flag did not persist");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_snapshot_create_and_isolate);

fn smoke_btrfs_shared_root_snapshot_lifecycle() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let device = RamBlockDevice::from_image(512, decode_sparse(FIXTURE_FST_SPARSE));
    let top = match poll_once(BtrfsVolume::mount_opts(
        device.clone(),
        DomainId::DRIVER_0,
        true,
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("shared-root fixture mount failed"),
    };
    let origin_id = match poll_once(crate::write::create_subvolume(
        &top,
        format::FIRST_FREE_OBJECTID,
        "origin",
        false,
    )) {
        Some(Ok(id)) => id,
        _ => return TestResult::Fail("shared-root origin creation failed"),
    };
    let origin_dir = match poll_once(top.root().lookup_dir_async("origin")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("shared-root origin traversal failed"),
    };
    if !matches!(
        poll_once(top.root().snapshot_async(origin_dir, "shared", false)),
        Some(Ok(()))
    ) {
        return TestResult::Fail("constant-size shared-root snapshot failed");
    }

    let origin = match poll_once(BtrfsVolume::mount_subvol(
        device.clone(),
        DomainId::DRIVER_0,
        true,
        Some(crate::volume::Subvol::Id(origin_id)),
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("shared-root origin remount failed"),
    };
    let shared = match poll_once(BtrfsVolume::mount_subvol(
        device.clone(),
        DomainId::DRIVER_0,
        true,
        Some(crate::volume::Subvol::Name("shared".into())),
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("shared-root snapshot remount failed"),
    };
    let shared_id = shared.fs_tree_id();
    let shared_root = shared.fs_tree_root();
    if origin.fs_tree_root() != shared_root {
        return TestResult::Fail("snapshot did not share the origin metadata root");
    }
    let extent_root = match poll_once(crate::roots::find_root(
        &*shared,
        shared.root_tree_root().0,
        format::EXTENT_TREE_OBJECTID,
    )) {
        Some(Ok((root, _))) => root,
        _ => return TestResult::Fail("shared-root extent tree missing"),
    };
    let metadata = match poll_once(btree::find_item(
        &*shared,
        extent_root,
        &BtrfsKey::new(
            shared_root.0,
            format::METADATA_ITEM_KEY,
            u64::from(shared_root.1),
        ),
    )) {
        Some(Ok(Some(body))) => body,
        _ => return TestResult::Fail("shared metadata extent item missing"),
    };
    if format::le64(&metadata, 0).ok() != Some(2) {
        return TestResult::Fail("shared metadata root refcount was not two");
    }
    let mut root_refs = Vec::new();
    let mut pos = 24usize;
    while pos < metadata.len() {
        if metadata[pos] != 176 || pos + 9 > metadata.len() {
            return TestResult::Fail("shared metadata inline refs were malformed");
        }
        root_refs.push(format::le64(&metadata, pos + 1).unwrap_or(0));
        pos += 9;
    }
    if !root_refs.contains(&origin_id) || !root_refs.contains(&shared_id) {
        return TestResult::Fail("shared metadata did not name both subvolume roots");
    }

    // The first origin mutation must materialise it privately while the snapshot
    // keeps the old tree intact.
    if !matches!(poll_once(origin.root().create("origin-only")), Some(Ok(_))) {
        return TestResult::Fail("shared origin first mutation failed");
    }
    if origin.fs_tree_root() == shared_root {
        return TestResult::Fail("shared origin was not materialised before mutation");
    }
    let shared_after = match poll_once(BtrfsVolume::mount_subvol(
        device.clone(),
        DomainId::DRIVER_0,
        true,
        Some(crate::volume::Subvol::Id(shared_id)),
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("shared snapshot remount after COW failed"),
    };
    if !matches!(
        poll_once(shared_after.root().lookup_async("origin-only")),
        Some(Err(FsError::NotFound))
    ) {
        return TestResult::Fail("origin mutation leaked into shared snapshot");
    }

    // The snapshot is now the final holder of the old root. Deleting it must
    // reclaim that tree while leaving the materialised origin mountable.
    let parent = match poll_once(BtrfsVolume::mount_opts(
        device.clone(),
        DomainId::DRIVER_0,
        true,
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("shared-root parent remount failed"),
    };
    if !matches!(
        poll_once(crate::write::destroy_subvolume(
            &parent,
            format::FIRST_FREE_OBJECTID,
            Some("shared"),
            None,
        )),
        Some(Ok(()))
    ) {
        return TestResult::Fail("final shared-root snapshot deletion failed");
    }
    if !matches!(
        poll_once(BtrfsVolume::mount_subvol(
            device,
            DomainId::DRIVER_0,
            true,
            Some(crate::volume::Subvol::Id(origin_id)),
        )),
        Some(Ok(_))
    ) {
        return TestResult::Fail("origin was damaged by shared-root deletion");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_shared_root_snapshot_lifecycle
);

fn smoke_btrfs_subvolume_destroy_ioctl() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let make_args = |name: &str, v2: bool| {
        let mut args = alloc::vec![0u8; 4096];
        let offset = if v2 { 56 } else { 8 };
        args[offset..offset + name.len()].copy_from_slice(name.as_bytes());
        args
    };
    let device = RamBlockDevice::from_image(512, decode_sparse(FIXTURE_FST_SPARSE));
    let vol = match poll_once(BtrfsVolume::mount_opts(
        device.clone(),
        DomainId::DRIVER_0,
        true,
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("subvolume-destroy fixture mount failed"),
    };
    let root = vol.root();
    let initial_used = match poll_once(vol.read_raw_superblock()) {
        Some(Ok(raw)) => u64::from_le_bytes(raw[120..128].try_into().unwrap()),
        _ => return TestResult::Fail("initial bytes_used read failed"),
    };

    let create_empty = {
        let mut args = alloc::vec![0u8; 4096];
        args[56..61].copy_from_slice(b"empty");
        args
    };
    if !matches!(
        poll_once(root.ioctl_async(crate::node::BTRFS_IOC_SUBVOL_CREATE_V2, 0, &create_empty, 0,)),
        Some(Ok(_))
    ) {
        return TestResult::Fail("delete-test subvolume creation failed");
    }
    let empty_id = match poll_once(BtrfsVolume::mount_subvol(
        device.clone(),
        DomainId::DRIVER_0,
        true,
        Some(crate::volume::Subvol::Name("empty".into())),
    )) {
        Some(Ok(v)) => v.fs_tree_id(),
        _ => return TestResult::Fail("delete-test subvolume did not mount"),
    };
    let legacy = make_args("empty", false);
    if !matches!(
        poll_once(root.ioctl_async(crate::node::BTRFS_IOC_SNAP_DESTROY, 0, &legacy, 0,)),
        Some(Ok(_))
    ) {
        return TestResult::Fail("legacy subvolume destroy failed");
    }
    if !matches!(
        poll_once(root.lookup_dir_async("empty")),
        Some(Err(FsError::NotFound))
    ) || !matches!(
        poll_once(BtrfsVolume::mount_subvol(
            device.clone(),
            DomainId::DRIVER_0,
            true,
            Some(crate::volume::Subvol::Id(empty_id)),
        )),
        Some(Err(FsError::NotFound))
    ) {
        return TestResult::Fail("legacy-destroyed subvolume remained reachable");
    }

    // Delete an isolated snapshot with real regular data through V2-by-name.
    if !matches!(
        poll_once(root.snapshot_async(root.clone(), "snap-delete", false)),
        Some(Ok(()))
    ) {
        return TestResult::Fail("delete-test snapshot creation failed");
    }
    let snap = match poll_once(BtrfsVolume::mount_subvol(
        device.clone(),
        DomainId::DRIVER_0,
        true,
        Some(crate::volume::Subvol::Name("snap-delete".into())),
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("delete-test snapshot did not mount"),
    };
    let snap_id = snap.fs_tree_id();
    let root_tree_before = vol.root_tree_root().0;
    let snap_item = match poll_once(btree::find_item(
        &*vol,
        root_tree_before,
        &BtrfsKey::new(snap_id, format::ROOT_ITEM_KEY, 0),
    )) {
        Some(Ok(Some(body))) if body.len() >= 263 => body,
        _ => return TestResult::Fail("delete-test snapshot root item missing"),
    };
    let snap_uuid = snap_item[247..263].to_vec();
    let used_with_snapshot = match poll_once(vol.read_raw_superblock()) {
        Some(Ok(raw)) => u64::from_le_bytes(raw[120..128].try_into().unwrap()),
        _ => return TestResult::Fail("snapshot bytes_used read failed"),
    };
    if used_with_snapshot <= initial_used {
        return TestResult::Fail("snapshot creation did not account allocated space");
    }
    let v2_name = make_args("snap-delete", true);
    if !matches!(
        poll_once(root.ioctl_async(crate::node::BTRFS_IOC_SNAP_DESTROY_V2, 0, &v2_name, 0,)),
        Some(Ok(_))
    ) {
        return TestResult::Fail("V2 name snapshot destroy failed");
    }

    let remounted = match poll_once(BtrfsVolume::mount_opts(
        device.clone(),
        DomainId::DRIVER_0,
        true,
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("remount after snapshot destroy failed"),
    };
    if remounted.superblock().bytes_used >= used_with_snapshot {
        return TestResult::Fail("snapshot destroy did not reclaim space");
    }
    let root_tree = remounted.root_tree_root().0;
    if poll_once(btree::find_item(
        &*remounted,
        root_tree,
        &BtrfsKey::new(snap_id, format::ROOT_ITEM_KEY, 0),
    ))
    .and_then(Result::ok)
    .flatten()
    .is_some()
    {
        return TestResult::Fail("destroyed snapshot root item survived");
    }
    if let Some((uuid_root, _)) = poll_once(crate::roots::find_root(
        &*remounted,
        root_tree,
        format::UUID_TREE_OBJECTID,
    ))
    .and_then(Result::ok)
    {
        let uuid_key = BtrfsKey::new(
            u64::from_le_bytes(snap_uuid[..8].try_into().unwrap()),
            format::UUID_KEY_SUBVOL,
            u64::from_le_bytes(snap_uuid[8..].try_into().unwrap()),
        );
        if poll_once(btree::find_item(&*remounted, uuid_root, &uuid_key))
            .and_then(Result::ok)
            .flatten()
            .is_some()
        {
            return TestResult::Fail("destroyed snapshot UUID index survived");
        }
    }
    let source_hello = match poll_once(remounted.root().lookup_async("hello.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("snapshot destroy damaged source namespace"),
    };
    if read_all(&source_hello, 16).as_deref() != Some(b"narf\n") {
        return TestResult::Fail("snapshot destroy damaged source data");
    }

    // V2-by-id resolves the child name from DIR_INDEX and removes both indices.
    let byid_create = {
        let mut args = alloc::vec![0u8; 4096];
        args[56..60].copy_from_slice(b"byid");
        args
    };
    let remount_root = remounted.root();
    if !matches!(
        poll_once(remount_root.ioctl_async(
            crate::node::BTRFS_IOC_SUBVOL_CREATE_V2,
            0,
            &byid_create,
            0,
        )),
        Some(Ok(_))
    ) {
        return TestResult::Fail("by-id delete-test subvolume creation failed");
    }
    let byid = match poll_once(BtrfsVolume::mount_subvol(
        device.clone(),
        DomainId::DRIVER_0,
        true,
        Some(crate::volume::Subvol::Name("byid".into())),
    )) {
        Some(Ok(v)) => v.fs_tree_id(),
        _ => return TestResult::Fail("by-id delete-test subvolume did not mount"),
    };
    let mut byid_args = alloc::vec![0u8; 4096];
    byid_args[16..24].copy_from_slice(&(1u64 << 4).to_ne_bytes());
    byid_args[56..64].copy_from_slice(&byid.to_ne_bytes());
    if !matches!(
        poll_once(remount_root.ioctl_async(
            crate::node::BTRFS_IOC_SNAP_DESTROY_V2,
            0,
            &byid_args,
            0,
        )),
        Some(Ok(_))
    ) {
        return TestResult::Fail("V2 by-id subvolume destroy failed");
    }
    if !matches!(
        poll_once(remount_root.lookup_dir_async("byid")),
        Some(Err(FsError::NotFound))
    ) {
        return TestResult::Fail("V2 by-id destroy left the directory entry");
    }

    let mut bad_flags = alloc::vec![0u8; 4096];
    bad_flags[16..24].copy_from_slice(&(1u64 << 63).to_ne_bytes());
    if !matches!(
        poll_once(remount_root.ioctl_async(
            crate::node::BTRFS_IOC_SNAP_DESTROY_V2,
            0,
            &bad_flags,
            0,
        )),
        Some(Err(FsError::InvalidData))
    ) {
        return TestResult::Fail("snapshot destroy accepted unknown flags");
    }

    // A child that contains another subvolume cannot be reclaimed as one
    // exclusive tree; it must remain intact on the rejection path.
    let nested_device = RamBlockDevice::from_image(512, decode_sparse(FIXTURE_NESTEDSUBVOL_SPARSE));
    let nested = match poll_once(BtrfsVolume::mount_opts(
        nested_device,
        DomainId::DRIVER_0,
        true,
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("nested destroy-rejection fixture mount failed"),
    };
    let container = match poll_once(nested.root().lookup_dir_async("container")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("nested destroy-rejection parent missing"),
    };
    let outer_args = make_args("outer", false);
    if !matches!(
        poll_once(container.ioctl_async(crate::node::BTRFS_IOC_SNAP_DESTROY, 0, &outer_args, 0,)),
        Some(Err(FsError::Busy))
    ) || !matches!(poll_once(container.lookup_dir_async("outer")), Some(Ok(_)))
    {
        return TestResult::Fail("nested subvolume destroy rejection was not atomic");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_subvolume_destroy_ioctl);

/// A writable multi-component `subvol=` mount commits into that subvolume's
/// own tree id. The new root must be published through its `ROOT_ITEM`, data
/// backrefs must name the subvolume rather than tree 5, and both an explicit
/// remount and traversal from the top-level tree must observe the mutations.
fn smoke_btrfs_writable_nested_subvolume() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let device = RamBlockDevice::from_image(512, decode_sparse(FIXTURE_NESTEDSUBVOL_SPARSE));
    let selected = crate::volume::Subvol::Name("container/outer/inner".into());
    let payload = b"written through nested subvol mount\n";

    {
        let vol = match poll_once(BtrfsVolume::mount_subvol(
            device.clone(),
            DomainId::DRIVER_0,
            true,
            Some(selected.clone()),
        )) {
            Some(Ok(v)) => v,
            _ => return TestResult::Fail("nested writable mount failed"),
        };
        if !vol.supports_writes() || vol.fs_tree_id() == format::FS_TREE_OBJECTID {
            return TestResult::Fail("nested mount did not select a writable subvolume tree");
        }
        let root = vol.root();
        let file = match poll_once(root.create("created.txt")) {
            Some(Ok(f)) => f,
            _ => return TestResult::Fail("create in nested subvolume failed"),
        };
        if !matches!(poll_once(file.write(0, payload)), Some(Ok(n)) if n == payload.len()) {
            return TestResult::Fail("write in nested subvolume failed");
        }
        if !matches!(
            poll_once(file.set_xattr("user.nested", b"yes", 0)),
            Some(Ok(()))
        ) {
            return TestResult::Fail("xattr in nested subvolume failed");
        }
        if !matches!(
            poll_once(root.rename("created.txt", "renamed.txt")),
            Some(Ok(()))
        ) {
            return TestResult::Fail("rename in nested subvolume failed");
        }
        let child = match poll_once(root.mkdir("child")) {
            Some(Ok(d)) => d,
            _ => return TestResult::Fail("mkdir in nested subvolume failed"),
        };
        let inside = match poll_once(child.create("inside.txt")) {
            Some(Ok(f)) => f,
            _ => return TestResult::Fail("nested directory create failed"),
        };
        if !matches!(poll_once(inside.write(0, b"inside\n")), Some(Ok(7))) {
            return TestResult::Fail("nested directory write failed");
        }
    }

    let remounted = match poll_once(BtrfsVolume::mount_subvol(
        device.clone(),
        DomainId::DRIVER_0,
        true,
        Some(selected),
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("nested subvolume remount failed"),
    };
    let root = remounted.root();
    if poll_once(root.lookup_async("created.txt")).is_some_and(|r| r.is_ok()) {
        return TestResult::Fail("old nested-subvolume name survived rename");
    }
    let renamed = match poll_once(root.lookup_async("renamed.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("renamed nested-subvolume file missing"),
    };
    if read_all(&renamed, payload.len() + 8).as_deref() != Some(payload)
        || poll_once(renamed.get_xattr("user.nested")).map(|r| r.ok())
            != Some(Some(b"yes".to_vec()))
    {
        return TestResult::Fail("nested-subvolume data/xattr did not persist");
    }
    let child = match poll_once(root.lookup_dir_async("child")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("nested-subvolume directory missing"),
    };
    let inside = match poll_once(child.lookup_async("inside.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("nested-subvolume child file missing"),
    };
    if read_all(&inside, 16).as_deref() != Some(&b"inside\n"[..]) {
        return TestResult::Fail("nested-subvolume child data changed");
    }

    // The root-tree item was repointed, so entering the same subvolume from a
    // top-level mount must reach the new root as well.
    let top = match poll_once(BtrfsVolume::mount_subvol(
        device,
        DomainId::DRIVER_0,
        true,
        Some(crate::volume::Subvol::Id(format::FS_TREE_OBJECTID)),
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("top-level remount after nested write failed"),
    };
    let container = match poll_once(top.root().lookup_dir_async("container")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("container missing after nested write"),
    };
    let outer = match poll_once(container.lookup_dir_async("outer")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("outer subvolume missing after nested write"),
    };
    let inner = match poll_once(outer.lookup_dir_async("inner")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("inner subvolume missing after nested write"),
    };
    match poll_once(inner.lookup_async("renamed.txt")) {
        Some(Ok(f)) if read_all(&f, payload.len() + 8).as_deref() == Some(payload) => {
            TestResult::Pass
        }
        _ => TestResult::Fail("top-level traversal saw a stale nested-subvolume root"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_writable_nested_subvolume);

/// Linux refuses to delete a subvolume that still owns nested ROOT_REFs with
/// ENOTEMPTY. Once children are removed bottom-up, the parent deletion must
/// retire all root items/refs and remain absent after remount.
fn smoke_btrfs_nested_subvolume_delete_bottom_up() -> TestResult {
    use narf_block::ram::RamBlockDevice;
    use narf_filesystem::FsInstance;

    let destroy_args = |name: &str| {
        let mut args = alloc::vec![0u8; 4096];
        args[56..56 + name.len()].copy_from_slice(name.as_bytes());
        args
    };
    let device = RamBlockDevice::from_image(512, decode_sparse(FIXTURE_NESTEDSUBVOL_SPARSE));
    let outer = match poll_once(BtrfsVolume::mount_subvol(
        device.clone(),
        DomainId::DRIVER_0,
        true,
        Some(crate::volume::Subvol::Name("container/outer".into())),
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("outer subvolume mount for deletion failed"),
    };
    let outer_id = outer.fs_tree_id();
    let inner = match poll_once(BtrfsVolume::mount_subvol(
        device.clone(),
        DomainId::DRIVER_0,
        true,
        Some(crate::volume::Subvol::Name("container/outer/inner".into())),
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("inner subvolume mount for deletion failed"),
    };
    let inner_id = inner.fs_tree_id();
    let rochild = match poll_once(BtrfsVolume::mount_subvol(
        device.clone(),
        DomainId::DRIVER_0,
        true,
        Some(crate::volume::Subvol::Name(
            "container/outer/rochild".into(),
        )),
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("read-only child mount for deletion failed"),
    };
    let rochild_id = rochild.fs_tree_id();

    // The direct parent delete is rejected while both ROOT_REF children exist.
    let top = match poll_once(BtrfsVolume::mount_subvol(
        device.clone(),
        DomainId::DRIVER_0,
        true,
        Some(crate::volume::Subvol::Id(format::FS_TREE_OBJECTID)),
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("top-level mount for nested delete failed"),
    };
    let container = match poll_once(top.root().lookup_dir_async("container")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("nested-delete container lookup failed"),
    };
    if !matches!(
        poll_once(container.ioctl_async(
            crate::node::BTRFS_IOC_SNAP_DESTROY_V2,
            0,
            &destroy_args("outer"),
            0,
        )),
        Some(Err(FsError::Busy))
    ) {
        return TestResult::Fail("parent subvolume with children was not ENOTEMPTY-shaped");
    }

    for child_name in ["inner", "rochild"] {
        let args = destroy_args(child_name);
        if !matches!(
            poll_once(outer.root().ioctl_async(
                crate::node::BTRFS_IOC_SNAP_DESTROY_V2,
                0,
                &args,
                0,
            )),
            Some(Ok(_))
        ) {
            return TestResult::Fail("bottom-up child subvolume deletion failed");
        }
    }

    // The first top-level mount has a stale fs-tree view after the child-root
    // transactions. Remount before deleting the now-empty outer subvolume.
    let top2 = match poll_once(BtrfsVolume::mount_subvol(
        device.clone(),
        DomainId::DRIVER_0,
        true,
        Some(crate::volume::Subvol::Id(format::FS_TREE_OBJECTID)),
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("top-level remount before parent deletion failed"),
    };
    let container2 = match poll_once(top2.root().lookup_dir_async("container")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("container remount lookup failed"),
    };
    let outer_args = destroy_args("outer");
    if !matches!(
        poll_once(container2.ioctl_async(
            crate::node::BTRFS_IOC_SNAP_DESTROY_V2,
            0,
            &outer_args,
            0,
        )),
        Some(Ok(_))
    ) {
        return TestResult::Fail("empty parent subvolume deletion failed");
    }

    let final_top = match poll_once(BtrfsVolume::mount_subvol(
        device.clone(),
        DomainId::DRIVER_0,
        true,
        Some(crate::volume::Subvol::Id(format::FS_TREE_OBJECTID)),
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("final remount after nested delete failed"),
    };
    let final_container = match poll_once(final_top.root().lookup_dir_async("container")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("final container lookup failed"),
    };
    if !matches!(
        poll_once(final_container.lookup_dir_async("outer")),
        Some(Err(FsError::NotFound))
    ) {
        return TestResult::Fail("deleted nested hierarchy remained reachable");
    }
    for id in [outer_id, inner_id, rochild_id] {
        if !matches!(
            poll_once(BtrfsVolume::mount_subvol(
                device.clone(),
                DomainId::DRIVER_0,
                true,
                Some(crate::volume::Subvol::Id(id)),
            )),
            Some(Err(FsError::NotFound))
        ) {
            return TestResult::Fail("deleted nested subvolume root item survived");
        }
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_nested_subvolume_delete_bottom_up
);

// ── Hardlinks ──────────────────────────────────────────────────────

fn smoke_btrfs_hardlink() -> TestResult {
    use narf_filesystem::FsInstance;
    let vol = match mount_fixture() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fixture failed to mount"),
    };
    let root = vol.root();
    let orig = match poll_once(root.lookup_async("hello.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup hello.txt failed"),
    };
    let link = match poll_once(root.lookup_async("hardlink.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup hardlink.txt failed"),
    };
    // Both names resolve to the same inode.
    if orig.ino() == 0 || orig.ino() != link.ino() {
        return TestResult::Fail("hardlink does not share the inode");
    }
    // The shared inode reports a link count of 2.
    let sx = match poll_once(link.statx_async(0, 0)) {
        Some(Ok(sx)) => sx,
        _ => return TestResult::Fail("statx failed"),
    };
    if sx.nlink != 2 {
        return TestResult::Fail("hardlinked inode nlink != 2");
    }
    // And the content is identical.
    match read_all(&link, 64).as_deref() {
        Some(b"narf\n") => TestResult::Pass,
        _ => TestResult::Fail("hardlink content wrong"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_hardlink);

// ── Special files (device nodes / FIFO) ────────────────────────────

fn smoke_btrfs_special_files() -> TestResult {
    use narf_filesystem::{FileType, FsInstance};
    let vol = match mount_fixture() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fixture failed to mount"),
    };
    let root = vol.root();

    // Enumeration reports the right VFS file types.
    let entries = match poll_once(root.enumerate_async(0, 64)) {
        Some(Ok(e)) => e,
        _ => return TestResult::Fail("enumerate failed"),
    };
    let ftype = |name: &str| entries.iter().find(|(n, _)| n == name).map(|(_, t)| *t);
    if ftype("nulldev") != Some(FileType::Special)
        || ftype("blkdev") != Some(FileType::Block)
        || ftype("fifo") != Some(FileType::Fifo)
    {
        return TestResult::Fail("special-file types wrong in listing");
    }

    // The char device stats as S_IFCHR. (mkfs.btrfs --rootdir preserves the
    // node type but stores rdev == 0, so the device numbers themselves are not
    // asserted here; the rdev decode is covered by a pure test below.)
    let nulldev = match poll_once(root.lookup_async("nulldev")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup nulldev failed"),
    };
    if nulldev.stat().mode.file_type != FileType::Special {
        return TestResult::Fail("nulldev stat not Special");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_special_files);

fn smoke_btrfs_rdev_decode() -> TestResult {
    // btrfs stores the raw kernel dev_t: MKDEV(major, minor) = (major << 20) | minor.
    let mk = |rdev: u64| {
        let inode = crate::inode::InodeItem {
            size: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            nlink: 1,
            rdev,
            mtime_sec: 0,
            mtime_nsec: 0,
        };
        inode.rdev_major_minor()
    };
    // MKDEV(1, 3) and MKDEV(8, 16) — what a real kernel writes for /dev/null and
    // a scsi disk partition.
    if mk(0x10_0003) != (1, 3) || mk(0x80_0010) != (8, 16) {
        return TestResult::Fail("small dev_t decode wrong");
    }
    // Minor above 0xff: MKDEV(1, 256).
    if mk(0x10_0100) != (1, 256) {
        return TestResult::Fail("large-minor dev_t decode wrong");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_rdev_decode);

// ── Default subvolume + statfs ─────────────────────────────────────

fn smoke_btrfs_default_subvolume() -> TestResult {
    use narf_filesystem::FsInstance;
    // A plain mount must honor the on-disk default subvolume: this image's
    // default is `def`, so the root lists dfile.txt, not the top-level
    // FS_TREE's rootfile.txt.
    let vol = match mount_sparse(FIXTURE_DEFAULTSUBVOL_SPARSE) {
        Ok(v) => v,
        _ => return TestResult::Fail("defaultsubvol fixture failed to mount"),
    };
    let entries = match poll_once(vol.root().enumerate_async(0, 64)) {
        Some(Ok(e)) => e,
        _ => return TestResult::Fail("root enumerate failed"),
    };
    if !entries.iter().any(|(n, _)| n == "dfile.txt")
        || entries.iter().any(|(n, _)| n == "rootfile.txt")
    {
        return TestResult::Fail("plain mount did not land in the default subvolume");
    }
    if !vol.supports_writes() {
        return TestResult::Fail("rw default subvolume mounted read-only");
    }
    let device = vol.device.clone();
    if !matches!(
        poll_once(vol.root().create("default-created.txt")),
        Some(Ok(_))
    ) {
        return TestResult::Fail("create in on-disk default subvolume failed");
    }
    let remounted = match poll_once(BtrfsVolume::mount(device.clone(), DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("default-subvolume write did not remount"),
    };
    if !dir_names(&remounted.root())
        .iter()
        .any(|n| n == "default-created.txt")
    {
        return TestResult::Fail("default-subvolume mutation did not persist");
    }
    // subvolid=5 explicitly overrides the default and reaches the top-level tree.
    let top = match poll_once(BtrfsVolume::mount_subvol(
        device,
        DomainId::DRIVER_0,
        true,
        Some(crate::volume::Subvol::Id(format::FS_TREE_OBJECTID)),
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount subvolid=5 failed"),
    };
    let top_entries = poll_once(top.root().enumerate_async(0, 64)).and_then(|r| r.ok());
    match top_entries {
        Some(e) if e.iter().any(|(n, _)| n == "rootfile.txt") => TestResult::Pass,
        _ => TestResult::Fail("subvolid=5 did not reach the top-level tree"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_default_subvolume);

fn smoke_btrfs_statfs() -> TestResult {
    use narf_filesystem::FsInstance;
    let vol = match mount_fixture() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fixture failed to mount"),
    };
    let st = match poll_once(vol.statfs()) {
        Some(Ok(st)) => st,
        _ => return TestResult::Fail("statfs failed"),
    };
    // 16 MiB image, 4096-byte blocks -> 4096 total blocks; some used, some free.
    if st.block_size != 4096 || st.blocks != 4096 {
        return TestResult::Fail("statfs block geometry wrong");
    }
    if st.blocks_free == 0 || st.blocks_free >= st.blocks {
        return TestResult::Fail("statfs free-block count implausible");
    }
    if st.name_len != 255 {
        return TestResult::Fail("statfs name_len wrong");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_statfs);

// ── Realistic laptop-distro image ──────────────────────────────────

fn smoke_btrfs_laptop_image() -> TestResult {
    use narf_filesystem::FsInstance;
    // Non-mixed, nodesize 16384, default features (free-space-tree present),
    // zstd, root/home subvolumes — what a real laptop's btrfs looks like.
    let vol = match mount_sparse_device(FIXTURE_LAPTOP_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("laptop image failed to mount"),
    };
    if vol.nodesize() != 16384 {
        return TestResult::Fail("expected nodesize 16384 (non-mixed geometry)");
    }

    // A plain mount lands in the default subvolume `root`; it lists root's
    // contents (rootfile.txt, big.dat, etc/) and NOT the sibling `home` subvol.
    let root = vol.root();
    let entries = match poll_once(root.enumerate_async(0, 64)) {
        Some(Ok(e)) => e,
        _ => return TestResult::Fail("root enumerate failed"),
    };
    let has = |n: &str| entries.iter().any(|(name, _)| name == n);
    if !has("rootfile.txt") || !has("big.dat") || !has("etc") || has("home") {
        return TestResult::Fail("default subvolume is not `root`");
    }

    // Read a realistic file through a subdirectory.
    let etc = match poll_once(root.lookup_dir_async("etc")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("lookup etc failed"),
    };
    let osrel = match poll_once(etc.lookup_async("os-release")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup os-release failed"),
    };
    match read_all(&osrel, 128) {
        Some(b) if b.windows(11).any(|w| w == b"NARF Laptop") => {}
        _ => return TestResult::Fail("os-release content wrong"),
    }

    // Read a zstd-compressed file at nodesize 16384.
    let big = match poll_once(root.lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup big.dat failed"),
    };
    let want = expected_big();
    match read_all(&big, want.len() + 16) {
        Some(got) if got == want => {}
        _ => return TestResult::Fail("laptop big.dat (zstd) read mismatch"),
    }

    // Reach the `home` subvolume via the top-level tree and read a file in it.
    let (total, runs) = decode_sparse_runs(FIXTURE_LAPTOP_SPARSE);
    let dev: Arc<dyn narf_block::BlockDeviceSync> = Arc::new(SparseImageDevice {
        runs,
        total,
        lba_size: 512,
    });
    let top = match poll_once(BtrfsVolume::mount_subvol(
        narf_block::SyncBlock::new(dev),
        DomainId::DRIVER_0,
        true,
        Some(crate::volume::Subvol::Id(format::FS_TREE_OBJECTID)),
    )) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount top-level (subvolid=5) failed"),
    };
    let home = match poll_once(top.root().lookup_dir_async("home")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("lookup home subvolume failed"),
    };
    let user = match poll_once(home.lookup_dir_async("user")) {
        Some(Ok(d)) => d,
        _ => return TestResult::Fail("lookup home/user failed"),
    };
    let notes = match poll_once(user.lookup_async("notes.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup notes.txt failed"),
    };
    match read_all(&notes, 64).as_deref() {
        Some(b"home user file\n") => TestResult::Pass,
        _ => TestResult::Fail("home subvolume file content wrong"),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_laptop_image);
