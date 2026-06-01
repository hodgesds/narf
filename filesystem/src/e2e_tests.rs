//! End-to-end block-stack smoke tests — filesystem/VFS half.
//!
//! These smokes exercise the full path:
//!
//!   FakeBlockDevice (BlockDeviceSync) →
//!   narf_block::register_block_device →
//!   DevDir::lookup → BlockFile (FileOps) →
//!   FileOps::read / write / stat / poll_readiness
//!
//! And the disk-by-* directories:
//!   register_block_device_with_meta (GPT partition metadata) →
//!   DevDiskByLabel / DevDiskByPartUuid
//!
//! Smoke numbering continues from block/src/e2e_tests.rs:
//!   Smoke 1  — full path: probe → register → DevDir lookup → read
//!   Smoke 5  — GPT-style partition table label/partuuid resolution
//!   Smoke 6  — device unregister cleanup
//!   Smoke 7  — poll_readiness returns POLL_IN | POLL_OUT
//!   Smoke 8  — stat().size == 1024*1024, FileType::Special

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_kernel_test::{kernel_test_in, TestResult};

use narf_block::registry::{BlockDeviceSync, BlockIoError, PartitionMetadata};

// ── FakeBlockDevice ───────────────────────────────────────────────────

/// In-memory 1 MiB block device, 512-byte LBAs, with dispatch counters.
///
/// Shared between block/src/e2e_tests.rs (block-layer half) and this
/// file (filesystem/VFS half). Each test file defines its own local
/// copy so there is no cross-crate dependency.
struct FakeBlockDevice {
    data: narf_lib::sync::IrqSafeSpinLock<Vec<u8>>,
    lba_size: u32,
    read_count: AtomicU64,
    write_count: AtomicU64,
}

impl core::fmt::Debug for FakeBlockDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FakeBlockDevice")
            .field("lba_size", &self.lba_size)
            .finish_non_exhaustive()
    }
}

impl FakeBlockDevice {
    fn new_1mib() -> Arc<Self> {
        const N: usize = 1024 * 1024;
        Arc::new(Self {
            data: narf_lib::sync::IrqSafeSpinLock::new(vec![0u8; N]),
            lba_size: 512,
            read_count: AtomicU64::new(0),
            write_count: AtomicU64::new(0),
        })
    }

}

impl BlockDeviceSync for FakeBlockDevice {
    fn lba_size(&self) -> u32 {
        self.lba_size
    }

    fn capacity(&self) -> u64 {
        let g = self.data.lock();
        (g.len() / self.lba_size as usize) as u64
    }

    fn read(&self, lba: u64, n_blocks: u16, out: &mut [u8]) -> Result<(), BlockIoError> {
        self.read_count.fetch_add(1, Ordering::Relaxed);
        let g = self.data.lock();
        let bs = self.lba_size as usize;
        let start = lba as usize * bs;
        let end = start + n_blocks as usize * bs;
        if end > g.len() {
            return Err(BlockIoError::OutOfRange);
        }
        if out.len() < end - start {
            return Err(BlockIoError::BufferTooSmall);
        }
        out[..end - start].copy_from_slice(&g[start..end]);
        Ok(())
    }

    fn write(&self, lba: u64, n_blocks: u16, data: &[u8]) -> Result<(), BlockIoError> {
        self.write_count.fetch_add(1, Ordering::Relaxed);
        let mut g = self.data.lock();
        let bs = self.lba_size as usize;
        let start = lba as usize * bs;
        let end = start + n_blocks as usize * bs;
        if end > g.len() {
            return Err(BlockIoError::OutOfRange);
        }
        if data.len() < end - start {
            return Err(BlockIoError::BufferTooSmall);
        }
        g[start..end].copy_from_slice(&data[..end - start]);
        Ok(())
    }
}

// ── poll_once helper ──────────────────────────────────────────────────

fn poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn raw_waker() -> RawWaker {
        unsafe fn no_clone(_: *const ()) -> RawWaker { raw_waker() }
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

// ── GPT builder helper ────────────────────────────────────────────────

/// Write a minimal synthetic GPT into `disk` (a 1 MiB / 2048-LBA
/// backing buffer) declaring 1 partition with label "TESTPART" and
/// partuuid "11111111-2222-3333-4444-555555555555", spanning
/// LBAs 34..=2047.
///
/// Layout per UEFI spec 2.10 §5.3:
///   LBA 0  — protective MBR (0xEE entry + 0xAA55)
///   LBA 1  — primary GPT header ("EFI PART" + fields)
///   LBA 2  — partition entry array (128-byte entries, 2 slots used:
///             1 real + 1 sentinel/empty)
///   LBA 34+  — usable data area (partition 1 starts here)
fn write_synthetic_gpt(buf: &mut [u8]) {
    // LBA 0: protective MBR.
    let mbr = &mut buf[0..512];
    mbr[446 + 4] = 0xEE; // kind = GPT protective
    mbr[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes()); // start_lba = 1
    mbr[446 + 12..446 + 16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // whole disk
    mbr[510] = 0x55;
    mbr[511] = 0xAA;

    // LBA 1: primary GPT header (92-byte minimal).
    let h = &mut buf[512..1024];
    h[0..8].copy_from_slice(b"EFI PART");
    h[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // rev 1.0
    h[12..16].copy_from_slice(&92u32.to_le_bytes());         // header_size
    h[16..20].copy_from_slice(&0u32.to_le_bytes());          // header_crc (ignored)
    h[24..32].copy_from_slice(&1u64.to_le_bytes());          // my_lba
    h[32..40].copy_from_slice(&2047u64.to_le_bytes());       // alternate_lba
    h[40..48].copy_from_slice(&34u64.to_le_bytes());         // first_usable
    h[48..56].copy_from_slice(&2047u64.to_le_bytes());       // last_usable
    // disk_guid [56..72] — left zero
    h[72..80].copy_from_slice(&2u64.to_le_bytes());          // partition_entry_lba = 2
    h[80..84].copy_from_slice(&2u32.to_le_bytes());          // num_partition_entries
    h[84..88].copy_from_slice(&128u32.to_le_bytes());        // size_of_partition_entry

    // LBA 2: partition entry array (two 128-byte entries).
    // Entry 0: the real partition.
    let e = &mut buf[1024..1024 + 128];
    // type_guid [0..16] — use Linux root GUID (non-empty type)
    e[0..16].copy_from_slice(&[
        0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47,
        0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
    ]);
    // unique_partition_guid [16..32] — encode "11111111-2222-3333-4444-555555555555"
    // GPT GUIDs are stored as mixed-endian: first three fields LE, last two BE.
    e[16..20].copy_from_slice(&0x11111111u32.to_le_bytes()); // time_low
    e[20..22].copy_from_slice(&0x2222u16.to_le_bytes());     // time_mid
    e[22..24].copy_from_slice(&0x3333u16.to_le_bytes());     // time_hi
    e[24..26].copy_from_slice(&[0x44, 0x44]);                // clock_seq (BE)
    e[26..32].copy_from_slice(&[0x55, 0x55, 0x55, 0x55, 0x55, 0x55]); // node (BE)
    // start/end LBAs
    e[32..40].copy_from_slice(&34u64.to_le_bytes());         // starting_lba
    e[40..48].copy_from_slice(&2047u64.to_le_bytes());       // ending_lba (inclusive)
    // partition_name [56..128]: "TESTPART" as UTF-16LE
    let name = "TESTPART";
    for (i, c) in name.chars().enumerate() {
        let cu = c as u16;
        e[56 + i * 2] = cu as u8;
        e[57 + i * 2] = (cu >> 8) as u8;
    }
    // Entry 1: sentinel / empty (all zeros, starting at buf[1024 + 128]).
}

// ── registry snapshot/restore helpers ────────────────────────────────

macro_rules! with_clean_registry {
    ($snap:ident, $body:block) => {{
        let $snap = narf_block::registry::__snapshot_for_test();
        narf_block::registry::__reset_for_test();
        let __result = (|| $body)();
        narf_block::registry::__restore_for_test($snap);
        __result
    }};
}

// ── Smoke 1: full path — register → DevDir lookup → read ─────────────
//
// 1. Register FakeBlockDevice as "fake0".
// 2. Obtain the DevFs root and call lookup("fake0") → Arc<dyn FileOps>.
// 3. Read 512 bytes at offset 0 via FileOps::read.
// 4. Verify 512 bytes returned matching the fake's LBA-0 backing.
// 5. Verify read_count == 1 (one driver dispatch).

fn smoke_e2e_full_path_register_lookup_read() -> TestResult {
    use crate::{DevFs, FsInstance};

    let dev = FakeBlockDevice::new_1mib();
    // Pre-fill LBA 0 with a marker.
    {
        let mut g = dev.data.lock();
        for b in g[..512].iter_mut() { *b = 0xDE; }
    }
    let dev_arc = dev.clone() as Arc<dyn BlockDeviceSync>;

    with_clean_registry!(snap, {
        narf_block::register_block_device("fake0", dev_arc);

        // Resolve through DevFs root.
        let root = DevFs::new().root();
        let file_ops = match root.lookup("fake0") {
            Some(f) => f,
            None => return TestResult::Fail("DevDir lookup of 'fake0' returned None"),
        };

        // Read LBA 0 (512 bytes at offset 0).
        let mut buf = vec![0u8; 512];
        let result = poll_once(file_ops.read(0, &mut buf));
        match result {
            Some(Ok(512)) => {}
            other => {
                let _ = other;
                return TestResult::Fail("FileOps::read(0, 512) did not return Ok(512)");
            }
        }

        // Verify byte content.
        if buf.iter().any(|&b| b != 0xDE) {
            return TestResult::Fail("read bytes do not match LBA-0 backing");
        }

        // Verify read_count == 1.
        let rc = dev.read_count.load(Ordering::Relaxed);
        if rc != 1 {
            return TestResult::Fail("expected exactly 1 driver read call via BlockFile");
        }

        TestResult::Pass
    })
}
kernel_test_in!("filesystem/e2e", smoke_e2e_full_path_register_lookup_read);

// ── Smoke 5: GPT-style partition table — label/partuuid resolution ────
//
// 1. Create a FakeBlockDevice with a synthetic GPT at LBA 1 declaring
//    1 partition spanning LBAs 34..=2047, label "TESTPART",
//    partuuid "11111111-2222-3333-4444-555555555555".
// 2. Register the partition slice (start_lba=34, capacity=2014 LBAs)
//    with PartitionMetadata carrying the label/uuid.
// 3. Verify DevDiskByLabel::lookup("TESTPART") resolves correctly.
// 4. Verify DevDiskByPartUuid::lookup("11111111-2222-3333-4444-555555555555") resolves.
// 5. Read LBA 0 of the partition (= LBA 34 of the parent backing) and
//    verify the bytes match what was written there.

fn smoke_e2e_gpt_partition_label_partuuid_resolution() -> TestResult {
    use crate::devfs_block::{DevDiskByLabel, DevDiskByPartUuid};
    use crate::DirOps;
    use narf_block::{
        partition::PartitionBlockDevice,
        registry::register_block_device_with_meta,
    };

    // Build the fake disk with the synthetic GPT.
    let dev = FakeBlockDevice::new_1mib();
    {
        let mut g = dev.data.lock();
        write_synthetic_gpt(&mut g[..]);
        // Write a marker at LBA 34 (start of partition 1) for the read test.
        let lba34_off = 34 * 512;
        for b in g[lba34_off..lba34_off + 512].iter_mut() {
            *b = 0xF5;
        }
    }
    let parent: Arc<dyn BlockDeviceSync> = dev.clone();

    // Build the PartitionBlockDevice for partition 1 (LBAs 34..=2047).
    // PartitionBlockDevice translates sub-LBAs to parent LBAs.
    let part_dev: Arc<dyn BlockDeviceSync> =
        Arc::new(PartitionBlockDevice::new(parent, 34, 2014));

    // Build PartitionMetadata matching the GPT entry.
    // The partuuid string must match what the GPT scanner produces from
    // the mixed-endian GUID stored as:
    //   time_low=0x11111111 (LE) → "11111111"
    //   time_mid=0x2222 (LE)     → "2222"
    //   time_hi=0x3333 (LE)      → "3333"
    //   clock_seq=0x4444 (BE)    → "4444"
    //   node=0x555555555555 (BE) → "555555555555"
    // Canonical 8-4-4-4-12 form: "11111111-2222-3333-4444-555555555555".
    let meta = PartitionMetadata {
        partlabel: String::from("TESTPART"),
        partuuid: String::from("11111111-2222-3333-4444-555555555555"),
    };

    with_clean_registry!(snap, {
        register_block_device_with_meta("fake0p1", part_dev, Some(meta));

        // Resolve via by-label.
        let by_label = DevDiskByLabel;
        let f_label = match by_label.lookup("TESTPART") {
            Some(f) => f,
            None => return TestResult::Fail("by-label lookup of TESTPART returned None"),
        };

        // Resolve via by-partuuid.
        let by_partuuid = DevDiskByPartUuid;
        let f_uuid = match by_partuuid.lookup("11111111-2222-3333-4444-555555555555") {
            Some(f) => f,
            None => return TestResult::Fail("by-partuuid lookup returned None"),
        };

        // Both lookups must return a BlockFile-shaped FileOps.
        let stat_label = f_label.stat();
        let stat_uuid = f_uuid.stat();
        if stat_label.size != stat_uuid.size {
            return TestResult::Fail("by-label and by-partuuid sizes differ");
        }

        // Read LBA 0 of the partition (= LBA 34 of the parent).
        // PartitionBlockDevice translates lba=0 → parent lba=34.
        let mut buf = vec![0u8; 512];
        match poll_once(f_label.read(0, &mut buf)) {
            Some(Ok(512)) => {}
            other => {
                let _ = other;
                return TestResult::Fail("read LBA 0 of partition returned unexpected result");
            }
        }
        if buf.iter().any(|&b| b != 0xF5) {
            return TestResult::Fail("partition LBA 0 bytes don't match parent LBA 34");
        }

        TestResult::Pass
    })
}
kernel_test_in!("filesystem/e2e", smoke_e2e_gpt_partition_label_partuuid_resolution);

// ── Smoke 6: device unregister cleanup ───────────────────────────────
//
// 1. Register fake0 with a label "TESTPART" + partuuid.
// 2. Verify /dev/fake0 resolves (DevDir::lookup).
// 3. Verify by-label resolves.
// 4. Unregister.
// 5. Verify DevDir::lookup("fake0") returns None.
// 6. Verify by-label::lookup("TESTPART") returns None.

fn smoke_e2e_unregister_cleanup() -> TestResult {
    use crate::devfs_block::{lookup_block_file, DevDiskByLabel};
    use crate::DirOps;
    use narf_block::registry::{register_block_device_with_meta, unregister_block_device};

    let dev = FakeBlockDevice::new_1mib();
    let dev_arc = dev.clone() as Arc<dyn BlockDeviceSync>;
    let meta = PartitionMetadata {
        partlabel: String::from("TESTPART"),
        partuuid: String::from("aaaa0000-0000-0000-0000-000000000000"),
    };

    with_clean_registry!(snap, {
        register_block_device_with_meta("fake0", dev_arc, Some(meta));

        // Smoke: /dev/fake0 must be present.
        if lookup_block_file("fake0").is_none() {
            return TestResult::Fail("fake0 not found after registration");
        }

        // by-label must also find it.
        let by_label = DevDiskByLabel;
        if by_label.lookup("TESTPART").is_none() {
            return TestResult::Fail("TESTPART not found via by-label after registration");
        }

        // Unregister.
        unregister_block_device("fake0");

        // /dev/fake0 must now be absent.
        if lookup_block_file("fake0").is_some() {
            return TestResult::Fail("/dev/fake0 still visible after unregister");
        }

        // by-label must also be gone.
        if by_label.lookup("TESTPART").is_some() {
            return TestResult::Fail("TESTPART still visible via by-label after unregister");
        }

        TestResult::Pass
    })
}
kernel_test_in!("filesystem/e2e", smoke_e2e_unregister_cleanup);

// ── Smoke 7: poll_readiness returns POLL_IN | POLL_OUT ────────────────
//
// Verify that a freshly-opened BlockFile's poll_readiness() returns
// both POLL_IN and POLL_OUT. Block devices are always immediately
// ready for I/O at the VFS layer.

fn smoke_e2e_block_file_poll_readiness() -> TestResult {
    use crate::devfs_block::BlockFile;
    use crate::{FileOps, POLL_IN, POLL_OUT};

    let dev = FakeBlockDevice::new_1mib();
    let dev_arc = dev as Arc<dyn BlockDeviceSync>;
    let bf = BlockFile::from_dev(dev_arc);

    let ready = bf.poll_readiness();
    if ready & POLL_IN == 0 {
        return TestResult::Fail("POLL_IN not set on block device");
    }
    if ready & POLL_OUT == 0 {
        return TestResult::Fail("POLL_OUT not set on block device");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/e2e", smoke_e2e_block_file_poll_readiness);

// ── Smoke 8: stat returns correct size and FileType::Special ──────────
//
// 1 MiB FakeBlockDevice → BlockFile::stat() must report:
//   - size == 1024 * 1024
//   - mode.file_type == FileType::Special

fn smoke_e2e_block_file_stat_size_and_type() -> TestResult {
    use crate::devfs_block::BlockFile;
    use crate::{FileOps, FileType};

    let dev = FakeBlockDevice::new_1mib();
    let dev_arc = dev as Arc<dyn BlockDeviceSync>;
    let bf = BlockFile::from_dev(dev_arc);

    let stat = bf.stat();
    if stat.size != 1024 * 1024 {
        return TestResult::Fail("stat.size != 1 MiB for 1 MiB device");
    }
    if stat.mode.file_type != FileType::Special {
        return TestResult::Fail("stat.mode.file_type != FileType::Special");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/e2e", smoke_e2e_block_file_stat_size_and_type);
