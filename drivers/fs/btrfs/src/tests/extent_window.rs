use super::*;
use core::sync::atomic::{AtomicUsize, Ordering};
use narf_block::BlockDeviceSync;

/// Count reads of the synthetic file's tree, excluding mount/checksum trees.
struct WindowDevice {
    image: SparseImageDevice,
    tree_start: u64,
    tree_reads: AtomicUsize,
}

impl BlockDeviceSync for WindowDevice {
    fn lba_size(&self) -> u32 {
        self.image.lba_size()
    }
    fn capacity(&self) -> u64 {
        self.image.capacity()
    }
    fn is_read_only(&self) -> bool {
        true
    }
    fn read(&self, lba: u64, n: u16, out: &mut [u8]) -> Result<(), narf_block::BlockIoError> {
        if lba * 512 >= self.tree_start {
            self.tree_reads.fetch_add(1, Ordering::Relaxed);
        }
        self.image.read(lba, n, out)
    }
    fn write(&self, _: u64, _: u16, _: &[u8]) -> Result<(), narf_block::BlockIoError> {
        Err(narf_block::BlockIoError::ReadOnly)
    }
}

fn finish_node(mut bytes: Vec<u8>, logical: u64) -> Vec<u8> {
    bytes[48..56].copy_from_slice(&logical.to_le_bytes());
    bytes[80..88].copy_from_slice(&7u64.to_le_bytes()); // build_internal's child transid
    let sum = checksum::block_csum(&bytes[32..]);
    bytes[..4].copy_from_slice(&sum.to_le_bytes());
    bytes
}

/// An ELF-sized file with 512 explicit hole extents spread over 32 leaves.
/// A 1 KiB read in the middle must not read every leaf of the file's tree.
fn smoke_btrfs_small_read_does_not_scan_file_extent_tail() -> TestResult {
    const LEAVES: usize = 32;
    const PER_LEAF: usize = 16;
    const LOGICAL: u64 = 1 << 40;
    const INO: u64 = 0xff00;
    const SECTOR: u64 = 4096;
    let (total, mut runs) = decode_sparse_runs(FIXTURE_SPARSE);
    let mut pointers = Vec::new();
    let mut body = alloc::vec![0u8; 53];
    body[8..16].copy_from_slice(&SECTOR.to_le_bytes()); // ram_bytes
    body[20] = 1; // BTRFS_FILE_EXTENT_REG; disk_bytenr == 0 is a hole.
    body[45..53].copy_from_slice(&SECTOR.to_le_bytes()); // num_bytes
    for leaf in 0..LEAVES {
        let logical = LOGICAL + (leaf as u64 + 1) * SECTOR;
        let items: Vec<_> = (0..PER_LEAF)
            .map(|item| {
                let offset = (leaf * PER_LEAF + item) as u64 * SECTOR;
                (
                    BtrfsKey::new(INO, format::EXTENT_DATA_KEY, offset),
                    body.as_slice(),
                )
            })
            .collect();
        pointers.push((items[0].0, logical));
        runs.push((
            total + logical - LOGICAL,
            finish_node(build_leaf(&items), logical),
        ));
    }
    runs.push((total, finish_node(build_internal(1, &pointers), LOGICAL)));
    let length = (LEAVES as u64 + 1) * SECTOR;
    let dev = Arc::new(WindowDevice {
        image: SparseImageDevice {
            runs,
            total: total + length,
            lba_size: 512,
        },
        tree_start: total,
        tree_reads: AtomicUsize::new(0),
    });
    let block = narf_block::SyncBlock::new(dev.clone() as Arc<dyn BlockDeviceSync>);
    let vol = match poll_once(BtrfsVolume::mount(block, DomainId::DRIVER_0)) {
        Some(Ok(vol)) => vol,
        _ => return TestResult::Fail("read-window fixture mount failed"),
    };
    if vol.nodesize() != SECTOR as usize {
        return TestResult::Fail("read-window fixture nodesize changed");
    }
    vol.add_chunk_mapping(LOGICAL, length, 1, total);
    let size = (LEAVES * PER_LEAF) as u64 * SECTOR;
    let offset = size / 2 + 512;
    let mut dst = [0x5a; 1024];
    if !matches!(
        poll_once(crate::extent::read_file(
            &vol, LOGICAL, INO, size, offset, &mut dst
        )),
        Some(Ok(1024))
    ) || dst != [0; 1024]
    {
        return TestResult::Fail("small read did not return the selected hole window");
    }
    if dev.tree_reads.load(Ordering::Relaxed) > 4 {
        return TestResult::Fail("small read traversed unrelated file-extent leaves");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/btrfs/read_window",
    smoke_btrfs_small_read_does_not_scan_file_extent_tail
);
