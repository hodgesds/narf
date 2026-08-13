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

/// 400 small files, forcing the FS b-tree to more than one level.
const FIXTURE_MANYFILES_SPARSE: &[u8] = include_bytes!("../testdata/fixture-manyfiles.img.sparse");

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

    // A size-changing write is refused (ReadOnly guard, before COW).
    let big = match poll_once(root.lookup_async("big.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup big.dat failed"),
    };
    let mut too_long = replacement_big();
    too_long.push(b'!');
    if !matches!(
        poll_once(big.write(0, &too_long)),
        Some(Err(FsError::ReadOnly))
    ) {
        return TestResult::Fail("size-changing write should be ReadOnly");
    }
    // A non-zero offset write is refused.
    if !matches!(
        poll_once(big.write(4, b"xxxx")),
        Some(Err(FsError::ReadOnly))
    ) {
        return TestResult::Fail("offset write should be ReadOnly");
    }

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
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_write_rejections);

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
    // Linux dev_t decomposition (glibc gnu_dev_major/minor).
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
    // Small classic encodings.
    if mk(0x103) != (1, 3) || mk(0x800) != (8, 0) {
        return TestResult::Fail("small dev_t decode wrong");
    }
    // Minor above 0xff exercises the high-minor path (makedev(1, 256)).
    if mk(0x10_0100) != (1, 256) {
        return TestResult::Fail("large-minor dev_t decode wrong");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_rdev_decode);
