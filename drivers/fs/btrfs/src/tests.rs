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

/// Same tree as the primary fixture but written with `--compress zlib`, so
/// `big.dat` is a zlib-compressed regular extent.
const FIXTURE_ZLIB_SPARSE: &[u8] = include_bytes!("../testdata/fixture-zlib.img.sparse");

/// Same tree written with `--compress zstd`.
const FIXTURE_ZSTD_SPARSE: &[u8] = include_bytes!("../testdata/fixture-zstd.img.sparse");

/// Same tree written with `--compress lzo`.
const FIXTURE_LZO_SPARSE: &[u8] = include_bytes!("../testdata/fixture-lzo.img.sparse");

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

    // Bad magic → InvalidData.
    let bad_magic = build_superblock(0xDEAD_BEEF, format::CSUM_TYPE_CRC32, 1);
    if Superblock::decode(&bad_magic).is_ok() {
        return TestResult::Fail("bad magic must be rejected");
    }

    // xxhash csum type → Unsupported.
    let xxhash = build_superblock(format::BTRFS_MAGIC, 1, 1);
    if !matches!(
        Superblock::decode(&xxhash),
        Err(narf_filesystem::FsError::Unsupported)
    ) {
        return TestResult::Fail("non-crc32c csum_type must be Unsupported");
    }

    // Multi-device → Unsupported.
    let multidev = build_superblock(format::BTRFS_MAGIC, format::CSUM_TYPE_CRC32, 2);
    if !matches!(
        Superblock::decode(&multidev),
        Err(narf_filesystem::FsError::Unsupported)
    ) {
        return TestResult::Fail("num_devices != 1 must be Unsupported");
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

    // DUP (2 stripes, same device) is accepted; stripe 0 is authoritative.
    let dup = build_sys_chunk(0, 0x10_0000, 0x80_0000, format::BLOCK_GROUP_DUP, 2);
    if ChunkMap::seed_from_sys_array(&dup).and_then(|m| m.map_logical(0)) != Ok(0x80_0000) {
        return TestResult::Fail("DUP chunk should map to stripe 0");
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

    // Overwriting an inline file is unsupported by the regular-extent COW path.
    let hello = match poll_once(root.lookup_async("hello.txt")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup hello.txt failed"),
    };
    if !matches!(
        poll_once(hello.write(0, b"narf\n")),
        Some(Err(FsError::Unsupported))
    ) {
        return TestResult::Fail("inline overwrite should be Unsupported");
    }

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
/// If this passes, the write path (which uses the same `block_csum`) emits
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
    let bad = crate::csum::compute_csums(b"not-the-real-sector-bytes", 4096);
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
fn file_data_extent(
    vol: &BtrfsVolume<narf_block::ram::RamBlockDevice>,
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

/// Whether the extent tree has an `EXTENT_ITEM` for `(logical, length)`.
fn extent_item_present(
    vol: &BtrfsVolume<narf_block::ram::RamBlockDevice>,
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
    if crate::parse_mount_subvol("subvol=a/b").is_ok() {
        return TestResult::Fail("multi-level subvol path should be rejected");
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
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_mount_subvol_option);

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
    // subvolid=5 explicitly overrides the default and reaches the top-level tree.
    let dev = narf_block::ram::RamBlockDevice::from_image(
        512,
        decode_sparse(FIXTURE_DEFAULTSUBVOL_SPARSE),
    );
    let top = match poll_once(BtrfsVolume::mount_subvol(
        dev,
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
