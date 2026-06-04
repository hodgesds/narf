//! End-to-end block-stack smoke tests — block-layer half.
//!
//! These smokes exercise the path: FakeBlockDevice (implementing
//! BlockDeviceSync) → byte-range read/write translation (the same
//! logic as `narf_filesystem::devfs_block::BlockFile`) → driver call.
//!
//! This file covers the pure block-layer portion:
//!   Smoke 2  — unaligned read spanning 3 LBAs, read-counter == 1
//!   Smoke 3  — aligned write round-trip, write-counter == 1
//!   Smoke 4  — unaligned RMW preserves surrounding bytes
//!   Smoke 7  — FakeBlockDevice counter invariants (poll_readiness
//!              assertion is in filesystem/src/e2e_tests.rs)
//!   Smoke 8  — geometry: 1 MiB fake reports correct capacity
//!   Smoke 9  — large write is clamped, not EINVAL (documented)
//!
//! VFS-traversal smokes (register → devfs resolve_absolute → read,
//! GPT partition table, device unregister cleanup) live in
//! `filesystem/src/e2e_tests.rs` where the narf-filesystem crate is
//! directly available.
//!
//! FakeBlockDevice tracks read/write call counts via AtomicU64 so
//! smokes can assert dispatch happened the expected number of times.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::registry::{BlockDeviceSync, BlockIoError};

// ── FakeBlockDevice ───────────────────────────────────────────────────

/// In-memory block device backed by a Vec<u8>, 512-byte LBAs.
///
/// Exposes atomic read/write counters so smokes can assert dispatch.
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
    /// 1 MiB device (2048 x 512-byte sectors), zero-filled.
    fn new_1mib() -> Arc<Self> {
        const N: usize = 1024 * 1024;
        Arc::new(Self {
            data: narf_lib::sync::IrqSafeSpinLock::new(vec![0u8; N]),
            lba_size: 512,
            read_count: AtomicU64::new(0),
            write_count: AtomicU64::new(0),
        })
    }

    /// Fill all backing bytes with `fill_byte`.
    fn fill(&self, fill_byte: u8) {
        let mut g = self.data.lock();
        for b in g.iter_mut() {
            *b = fill_byte;
        }
    }

    /// Return a copy of backing bytes at [byte_off..byte_off+len].
    fn backing_slice(&self, byte_off: usize, len: usize) -> Vec<u8> {
        let g = self.data.lock();
        g[byte_off..byte_off + len].to_vec()
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

// ── BlockFileShim — minimal byte-range → LBA adapter ─────────────────
//
// Mirrors BlockFile::read_sync / write_sync from devfs_block.rs
// without depending on narf-filesystem (which would be a cycle).

struct BlockFileShim {
    dev: Arc<FakeBlockDevice>,
    lba_size: u32,
    lba_count: u64,
}

impl BlockFileShim {
    fn from_fake(dev: Arc<FakeBlockDevice>) -> Self {
        let lba_size = dev.lba_size();
        let lba_count = dev.capacity();
        Self {
            dev,
            lba_size,
            lba_count,
        }
    }

    fn byte_capacity(&self) -> u64 {
        self.lba_count * self.lba_size as u64
    }

    fn read(&self, offset: u64, dst: &mut [u8]) -> Result<usize, BlockIoError> {
        let bs = self.lba_size as u64;
        let cap = self.byte_capacity();
        if offset >= cap {
            return Ok(0); // EOF
        }
        let avail = (cap - offset) as usize;
        let len = dst.len().min(avail);
        let dst = &mut dst[..len];

        let first_lba = offset / bs;
        let intra_first = (offset % bs) as usize;
        let last_lba = (offset + len as u64 - 1) / bs;
        let n_lbas = (last_lba - first_lba + 1) as usize;

        let stage_len = n_lbas * self.lba_size as usize;
        let mut stage = vec![0u8; stage_len];
        self.dev.read(first_lba, n_lbas as u16, &mut stage)?;
        dst.copy_from_slice(&stage[intra_first..intra_first + len]);
        Ok(len)
    }

    fn write(&self, offset: u64, src: &[u8]) -> Result<usize, BlockIoError> {
        if src.is_empty() {
            return Ok(0);
        }
        let bs = self.lba_size as u64;
        let cap = self.byte_capacity();
        if offset >= cap {
            return Err(BlockIoError::OutOfRange);
        }
        let avail = (cap - offset) as usize;
        let len = src.len().min(avail);
        let src = &src[..len];

        let first_lba = offset / bs;
        let intra_first = (offset % bs) as usize;
        let last_lba = (offset + len as u64 - 1) / bs;
        let n_lbas = (last_lba - first_lba + 1) as usize;

        let stage_len = n_lbas * self.lba_size as usize;
        let mut stage = vec![0u8; stage_len];
        let needs_rmw = intra_first != 0 || len < stage_len;
        if needs_rmw {
            self.dev.read(first_lba, n_lbas as u16, &mut stage)?;
        }
        stage[intra_first..intra_first + len].copy_from_slice(src);
        self.dev.write(first_lba, n_lbas as u16, &stage)?;
        Ok(len)
    }
}

// ── Smoke 2: unaligned read spanning 3 LBAs ──────────────────────────
//
// Fill LBAs 0/1/2 with 0xAA/0xBB/0xCC. Read 1300 bytes starting at
// offset 200 (device bytes 200..1499). The last byte (1499) falls
// in LBA 2 (1024..1535), so the span covers exactly LBAs 0, 1, 2.
// The shim issues exactly 1 batched driver read (first_lba=0, n_lbas=3).
//
// Segment boundaries in buf[]:
//   buf[0..312]    device bytes 200..511   (LBA 0, 312 bytes)
//   buf[312..824]  device bytes 512..1023  (LBA 1, 512 bytes)
//   buf[824..1300] device bytes 1024..1499 (LBA 2, 476 bytes)

fn smoke_e2e_unaligned_read_spans_3_lbas() -> TestResult {
    let dev = FakeBlockDevice::new_1mib();
    {
        let mut g = dev.data.lock();
        for b in g[0..512].iter_mut() {
            *b = 0xAA;
        }
        for b in g[512..1024].iter_mut() {
            *b = 0xBB;
        }
        for b in g[1024..1536].iter_mut() {
            *b = 0xCC;
        }
    }
    let bf = BlockFileShim::from_fake(dev.clone());

    let mut buf = vec![0u8; 1300];
    match bf.read(200, &mut buf) {
        Ok(1300) => {}
        Ok(n) => {
            let _ = n;
            return TestResult::Fail("expected 1300 bytes returned");
        }
        Err(_) => return TestResult::Fail("unaligned 3-LBA read returned error"),
    }

    // The batched shim read issues 1 driver call covering LBAs 0..2.
    let rc = dev.read_count.load(Ordering::Relaxed);
    if rc != 1 {
        return TestResult::Fail("expected exactly 1 driver read call for 3-LBA span");
    }

    // Byte content (offset=200, len=1300 → device bytes 200..1499):
    //   buf[0..312]    from LBA 0 (device bytes 200..511)   -> 0xAA  (312 bytes)
    //   buf[312..824]  from LBA 1 (device bytes 512..1023)  -> 0xBB  (512 bytes)
    //   buf[824..1300] from LBA 2 (device bytes 1024..1499) -> 0xCC  (476 bytes)
    if buf[..312].iter().any(|&b| b != 0xAA) {
        return TestResult::Fail("3-LBA read: LBA 0 bytes wrong");
    }
    if buf[312..824].iter().any(|&b| b != 0xBB) {
        return TestResult::Fail("3-LBA read: LBA 1 bytes wrong");
    }
    if buf[824..1300].iter().any(|&b| b != 0xCC) {
        return TestResult::Fail("3-LBA read: LBA 2 bytes wrong");
    }
    TestResult::Pass
}
kernel_test_in!("block/e2e", smoke_e2e_unaligned_read_spans_3_lbas);

// ── Smoke 3: write round-trip (aligned 512-byte write at LBA 2) ───────
//
// Write 512 bytes of 0x42 at byte offset 1024 (start of LBA 2).
// Aligned full-block write: no RMW needed, read_count stays 0.
// Re-read and confirm bytes match.

fn smoke_e2e_write_round_trip_aligned() -> TestResult {
    let dev = FakeBlockDevice::new_1mib();
    let bf = BlockFileShim::from_fake(dev.clone());

    let payload = vec![0x42u8; 512];
    match bf.write(1024, &payload) {
        Ok(512) => {}
        other => {
            let _ = other;
            return TestResult::Fail("aligned write should return Ok(512)");
        }
    }

    // No RMW needed for aligned full-LBA write.
    let rc = dev.read_count.load(Ordering::Relaxed);
    let wc = dev.write_count.load(Ordering::Relaxed);
    if rc != 0 {
        return TestResult::Fail("aligned full-LBA write must not issue an RMW read");
    }
    if wc != 1 {
        return TestResult::Fail("expected exactly 1 driver write for aligned 512B write");
    }

    // Re-read and verify content.
    let mut buf = vec![0u8; 512];
    match bf.read(1024, &mut buf) {
        Ok(512) => {}
        other => {
            let _ = other;
            return TestResult::Fail("readback after aligned write failed");
        }
    }
    if buf.iter().any(|&b| b != 0x42) {
        return TestResult::Fail("readback bytes wrong after aligned write");
    }
    // Verify backing store directly.
    let backing = dev.backing_slice(1024, 512);
    if backing.iter().any(|&b| b != 0x42) {
        return TestResult::Fail("backing store not updated by aligned write");
    }
    TestResult::Pass
}
kernel_test_in!("block/e2e", smoke_e2e_write_round_trip_aligned);

// ── Smoke 4: unaligned RMW preserves surrounding bytes ────────────────
//
// Device pre-filled with 0xFF. Write 200 bytes of 0x00 at byte
// offset 100 (within LBA 0). Verify:
//   - bytes [0..100] remain 0xFF  (prefix preserved)
//   - bytes [100..300] are 0x00   (written region)
//   - bytes [300..512] remain 0xFF (suffix preserved)
// RMW must issue 1 read + 1 write.

fn smoke_e2e_unaligned_rmw_preserves_surrounding_bytes() -> TestResult {
    let dev = FakeBlockDevice::new_1mib();
    dev.fill(0xFF);
    let bf = BlockFileShim::from_fake(dev.clone());

    let payload = vec![0x00u8; 200];
    match bf.write(100, &payload) {
        Ok(200) => {}
        other => {
            let _ = other;
            return TestResult::Fail("unaligned write should return Ok(200)");
        }
    }

    let rc = dev.read_count.load(Ordering::Relaxed);
    let wc = dev.write_count.load(Ordering::Relaxed);
    if rc != 1 {
        return TestResult::Fail("partial-LBA write must issue 1 RMW read");
    }
    if wc != 1 {
        return TestResult::Fail("partial-LBA write must issue 1 write back");
    }

    let lba0 = dev.backing_slice(0, 512);
    if lba0[..100].iter().any(|&b| b != 0xFF) {
        return TestResult::Fail("RMW: bytes [0..100] before write range corrupted");
    }
    if lba0[100..300].iter().any(|&b| b != 0x00) {
        return TestResult::Fail("RMW: bytes [100..300] not written correctly");
    }
    if lba0[300..].iter().any(|&b| b != 0xFF) {
        return TestResult::Fail("RMW: bytes [300..512] after write range corrupted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "block/e2e",
    smoke_e2e_unaligned_rmw_preserves_surrounding_bytes
);

// ── Smoke 7 (block-side): FakeBlockDevice counter invariants ──────────
//
// Verifies the FakeBlockDevice tracking machinery is correct before
// the higher-level smokes rely on it.

fn smoke_e2e_fake_counter_invariants() -> TestResult {
    let dev = FakeBlockDevice::new_1mib();
    if dev.read_count.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("read_count must start at 0");
    }
    if dev.write_count.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("write_count must start at 0");
    }
    let mut buf = vec![0u8; 512];
    dev.read(0, 1, &mut buf).expect("read LBA 0");
    if dev.read_count.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("read_count must be 1 after one read");
    }
    dev.read(0, 1, &mut buf).expect("read LBA 0 again");
    if dev.read_count.load(Ordering::Relaxed) != 2 {
        return TestResult::Fail("read_count must be 2 after two reads");
    }
    let data = vec![0xEEu8; 512];
    dev.write(0, 1, &data).expect("write LBA 0");
    if dev.write_count.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("write_count must be 1 after one write");
    }
    TestResult::Pass
}
kernel_test_in!("block/e2e", smoke_e2e_fake_counter_invariants);

// ── Smoke 8 (block-side): 1 MiB geometry ─────────────────────────────
//
// The FileType::Special and stat().size == 1024*1024 assertions are
// in filesystem/src/e2e_tests.rs. This smoke pins the block-layer
// geometry that BlockFile::stat() computes from.

fn smoke_e2e_block_geometry_1mib() -> TestResult {
    let dev = FakeBlockDevice::new_1mib();
    let bs = dev.lba_size() as u64;
    let cap = dev.capacity();
    let byte_cap = cap * bs;

    if bs != 512 {
        return TestResult::Fail("FakeBlockDevice lba_size should be 512");
    }
    if cap != 2048 {
        return TestResult::Fail("1 MiB / 512 should give capacity = 2048 LBAs");
    }
    if byte_cap != 1024 * 1024 {
        return TestResult::Fail("1 MiB fake must report 1 MiB byte capacity");
    }
    TestResult::Pass
}
kernel_test_in!("block/e2e", smoke_e2e_block_geometry_1mib);

// ── Smoke 9: over-capacity write clamped to device capacity ──────────
//
// BlockFile::write_sync clamps len = src.len().min(avail) where
// avail = capacity - offset. There is no artificial max-write-size cap
// at the BlockFile level. This smoke documents that a write whose
// requested size exceeds the remaining device capacity is silently
// clamped to the available bytes, not rejected with a synthetic EINVAL.
//
// We use a 512 KiB write on a 256 KiB tail (offset = 768 KiB on a
// 1 MiB device) so the clamped length is exactly 256 KiB. The payload
// fits in the test-VM heap; 17 MiB did not.
//
// If a write-size cap is added to BlockFile later, update this smoke
// to assert Err(FsError::InvalidData) above the cap boundary.

fn smoke_e2e_large_write_clamped_not_einval() -> TestResult {
    let dev = FakeBlockDevice::new_1mib();
    let bf = BlockFileShim::from_fake(dev.clone());

    // 256 KiB remain at offset 768 KiB; request 512 KiB → clamped to 256 KiB.
    const OFFSET: u64 = 768 * 1024;
    const REQUEST: usize = 512 * 1024;
    const CLAMPED: usize = 256 * 1024; // 1 MiB - 768 KiB

    let payload = vec![0x55u8; REQUEST];
    match bf.write(OFFSET, &payload) {
        Ok(n) => {
            if n != CLAMPED {
                return TestResult::Fail(
                    "over-capacity write must be clamped to remaining device bytes",
                );
            }
        }
        Err(BlockIoError::OutOfRange) => {
            // Also acceptable: driver rejects the OOB portion.
        }
        Err(_) => {
            return TestResult::Fail("over-capacity write returned unexpected error");
        }
    }
    // Documented: no artificial write-size cap is enforced by BlockFile today.
    TestResult::Pass
}
kernel_test_in!("block/e2e", smoke_e2e_large_write_clamped_not_einval);

// ── Smoke 10: AHCI fake probe path ────────────────────────────────────
//
// Deferred. Constructing an in-memory AHCI register window requires
// the full PCI / MMIO scaffold from narf-drivers-storage (which is
// downstream of this crate). The AHCI driver has its own unit smokes.
// A future work item will add an AHCI fake-port probe smoke in
// drivers/storage/src/e2e_tests.rs.
