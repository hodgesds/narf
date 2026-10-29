//! Dataset Management / Write Zeroes smokes (#927): a fake
//! controller that captures the SQEs the driver posts and the
//! range-list page it DMA-reads them from, decoded here directly
//! from the NVM Command Set Specification (§3.2.3 Figures 38–41,
//! Write Zeroes Figures 72–73) — never via the driver's own
//! encoder — then the real trim end-to-end on QEMU's controller.

use alloc::vec;
use alloc::vec::Vec;

use narf_block::{BlockDevice, BlockFeature, LbaRange};
use narf_bus::{BarKind, MmioRegion};
use narf_io::alloc_coherent;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

use super::ns::{NamespaceInfo, NsIds};
use super::{Controller, IdentifyController, IoOpcode, NvmeError, Queue};
use super::{ONCS_DATASET_MGMT, ONCS_WRITE_ZEROES};

/// Queue depth of the fake controller; its SQ/CQ pages hold 16
/// entries each, and no test here submits more than 4 commands.
const FAKE_DEPTH: u16 = 16;

/// A `Controller` wired to RAM: the BAR is a 2-page coherent buffer
/// (doorbell offsets at 0x1000+ land in the second page), the I/O
/// queue's SQ/CQ are coherent pages the test inspects afterwards,
/// and every CQE is pre-posted with the phase bit set so submissions
/// complete synchronously. CQE 0 carries a caller-chosen status word
/// so a test can make the first command fail.
struct FakeCtrl {
    ctrl: Controller,
    /// Keeps the fake BAR mapping alive for `ctrl`'s lifetime.
    _bar: narf_io::DmaBuffer,
    sq_ptr: *const u8,
    dsm_ptr: *const u8,
    dsm_dma: u64,
}

fn fake_controller(oncs: u16, nsze: u64, cqe0_status: u16) -> Option<FakeCtrl> {
    let sq = alloc_coherent(4096, DomainId::DRIVER_0).ok()?;
    let cq = alloc_coherent(4096, DomainId::DRIVER_0).ok()?;
    let bar = alloc_coherent(8192, DomainId::DRIVER_0).ok()?;
    let dsm = alloc_coherent(4096, DomainId::DRIVER_0).ok()?;
    let sq_ptr = sq.cpu_ptr::<u8>();
    let cq_ptr = cq.cpu_ptr::<u8>();
    let dsm_ptr = dsm.cpu_ptr::<u8>();
    let dsm_dma = dsm.dma_addr().raw();
    // Pre-post every completion: status word = phase bit (offset 14
    // in the 16-byte CQE) plus the NVMe status field above it.
    // SAFETY: `cq` is a live 4 KiB coherent page; FAKE_DEPTH CQEs
    // occupy its first 256 bytes.
    unsafe {
        for i in 0..FAKE_DEPTH as usize {
            let status = if i == 0 { cqe0_status } else { 1 };
            core::ptr::write_volatile(cq_ptr.add(i * 16 + 14) as *mut u16, status);
        }
    }
    let mut ctrl = Controller::new(0);
    ctrl.bar0_region = Some(MmioRegion {
        phys: narf_memory::PhysAddr::new(bar.dma_addr().raw()),
        virt: bar.cpu_ptr::<u8>() as u64,
        len: bar.len() as u64,
        kind: BarKind::Mmio32 {
            prefetchable: false,
        },
    });
    ctrl.identify = Some(IdentifyController {
        vid: 0,
        ssvid: 0,
        sn: [0; 20],
        mn: [0; 40],
        fr: [0; 8],
        mdts: 0,
        ver: 0,
        nn: 1,
        rtd3e: 0,
        vwc: 0,
        oncs,
    });
    ctrl.primary_nsid = 1;
    ctrl.lba_bytes = 512;
    ctrl.nsze = nsze;
    ctrl.ns_usable = true;
    ctrl.namespaces = vec![NamespaceInfo {
        nsid: 1,
        lba_bytes: 512,
        nsze,
        usable: true,
        ids: NsIds::default(),
    }];
    ctrl.dsm_page = Some(dsm);
    ctrl.io_queues.push(Queue {
        sq_buf: sq,
        cq_buf: cq,
        qid: 1,
        depth: FAKE_DEPTH,
        sq_tail: 0,
        cq_head: 0,
        cq_phase: 1,
        db_stride: 4,
        next_cid: 0,
    });
    ctrl.io_queue_locks.push(IrqSafeSpinLock::new(()));
    Some(FakeCtrl {
        ctrl,
        _bar: bar,
        sq_ptr,
        dsm_ptr,
        dsm_dma,
    })
}

impl FakeCtrl {
    /// SQE `idx` as 16 little-endian dwords (the 64-byte common
    /// command format): w[0] = CDW0, w[1] = NSID, w[4..6] = MPTR,
    /// w[6..8] = PRP1, w[8..10] = PRP2, w[10..16] = CDW10..CDW15.
    fn sqe(&self, idx: usize) -> [u32; 16] {
        let mut w = [0u32; 16];
        for (j, word) in w.iter_mut().enumerate() {
            // SAFETY: the SQ page is a live 4 KiB coherent buffer and
            // `idx` < FAKE_DEPTH in every test.
            *word = unsafe {
                core::ptr::read_volatile(self.sq_ptr.add(idx * 64 + j * 4) as *const u32)
            };
        }
        w
    }

    /// Decode `nr` range definitions out of the captured range-list
    /// page, straight from Figure 41: bytes 0..4 context attributes,
    /// bytes 4..8 length in logical blocks (a 1-based count, §3.2.3),
    /// bytes 8..16 starting LBA. Returns (starting LBA, blocks).
    fn decode_ranges(&self, nr: usize) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        for i in 0..nr {
            // SAFETY: the range-list page is a live 4 KiB coherent
            // buffer; `nr` ≤ 256 in every test.
            let (len, slba) = unsafe {
                let at = self.dsm_ptr.add(i * 16);
                (
                    core::ptr::read_volatile(at.add(4) as *const u32) as u64,
                    core::ptr::read_volatile(at.add(8) as *const u64),
                )
            };
            out.push((slba, len));
        }
        out
    }

    /// Bytes `0..n` of the captured range-list page.
    fn dsm_bytes(&self, n: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for i in 0..n {
            // SAFETY: as in `decode_ranges`.
            out.push(unsafe { core::ptr::read_volatile(self.dsm_ptr.add(i)) });
        }
        out
    }
}

/// One DSM command: the SQE carries opcode 0x09, NR = ranges − 1,
/// AD = 1 and PRP1 at the range-list page; the list itself is pinned
/// byte-for-byte against the Figure 41 encoding (1-based lengths),
/// and an independent decode reproduces the requested set exactly —
/// distinct LBAs and lengths, so an off-by-one in either 0-based /
/// 1-based field changes the decoded set and fails here.
fn smoke_nvme_dsm_sqe_ranges() -> TestResult {
    let Some(mut fake) = fake_controller(ONCS_DATASET_MGMT | ONCS_WRITE_ZEROES, 1_000_000, 1)
    else {
        return TestResult::Fail("fake controller allocation failed");
    };
    if !fake.ctrl.supports_dataset_mgmt() || !fake.ctrl.supports_write_zeroes() {
        return TestResult::Fail("ONCS DSM / Write Zeroes bits not decoded");
    }
    let ranges = [
        LbaRange {
            start: 0x1000,
            blocks: 0x20,
        },
        LbaRange {
            start: 0x2000,
            blocks: 1,
        },
        LbaRange {
            start: 0x40,
            blocks: 0xFFFF,
        },
    ];
    let ns = fake.ctrl.primary_geom();
    if fake.ctrl.dataset_mgmt_ns(ns, &ranges).is_err() {
        return TestResult::Fail("dataset_mgmt_ns failed against the model controller");
    }
    let w = fake.sqe(0);
    if w[0] & 0xFF != IoOpcode::DatasetMgmt as u32 {
        return TestResult::Fail("SQE opcode is not Dataset Management (0x09)");
    }
    if w[1] != 1 {
        return TestResult::Fail("SQE NSID is not the namespace under test");
    }
    if w[4] != 0 || w[5] != 0 {
        return TestResult::Fail("SQE metadata pointer must be zero");
    }
    if (w[6] as u64) | ((w[7] as u64) << 32) != fake.dsm_dma {
        return TestResult::Fail("SQE PRP1 does not point at the range-list page");
    }
    if w[8] != 0 || w[9] != 0 {
        return TestResult::Fail("SQE PRP2 must be zero for a one-page range list");
    }
    if w[10] != 2 {
        return TestResult::Fail("CDW10 NR must be the 0-based range count (3 ranges -> 2)");
    }
    if w[11] != 0x4 {
        return TestResult::Fail("CDW11 must carry only Attribute - Deallocate (bit 2)");
    }
    if w[12..16].iter().any(|&x| x != 0) {
        return TestResult::Fail("CDW12..15 are reserved for Dataset Management");
    }
    // Byte-for-byte pin, Figure 41, little-endian: context
    // attributes (zero), 1-based length, starting LBA.
    let expected: [u8; 48] = [
        0, 0, 0, 0, 0x20, 0, 0, 0, 0x00, 0x10, 0, 0, 0, 0, 0, 0, //
        0, 0, 0, 0, 1, 0, 0, 0, 0x00, 0x20, 0, 0, 0, 0, 0, 0, //
        0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0x40, 0, 0, 0, 0, 0, 0, 0,
    ];
    if fake.dsm_bytes(48) != expected {
        return TestResult::Fail("range list bytes differ from the Figure 41 encoding");
    }
    if fake.decode_ranges(3) != [(0x1000, 0x20), (0x2000, 1), (0x40, 0xFFFF)] {
        return TestResult::Fail("decoded range set differs from the requested set");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_dsm_sqe_ranges);

/// Batching: 300 ranges split into commands of 256 + 44 (NR fields
/// 255 and 43); exactly 256 ranges fit one command whose list then
/// decodes to the full requested set.
fn smoke_nvme_dsm_batches_at_limit() -> TestResult {
    let ranges: Vec<LbaRange> = (0..300u64)
        .map(|i| LbaRange {
            start: i * 0x10,
            blocks: (i % 7) + 1,
        })
        .collect();
    let Some(mut fake) = fake_controller(ONCS_DATASET_MGMT, 1_000_000, 1) else {
        return TestResult::Fail("fake controller allocation failed");
    };
    let ns = fake.ctrl.primary_geom();
    if fake.ctrl.dataset_mgmt_ns(ns, &ranges).is_err() {
        return TestResult::Fail("300-range dataset_mgmt_ns failed");
    }
    let (w0, w1) = (fake.sqe(0), fake.sqe(1));
    if w0[10] != 255 || w1[10] != 43 {
        return TestResult::Fail("300 ranges must split as NR=255 then NR=43");
    }
    if w0[11] != 0x4 || w1[11] != 0x4 {
        return TestResult::Fail("every batched command must carry AD=1");
    }
    // The page is rewritten per command, so it now holds the second
    // command's 44 ranges — which must decode to ranges[256..300].
    let want: Vec<(u64, u64)> = ranges[256..].iter().map(|r| (r.start, r.blocks)).collect();
    if fake.decode_ranges(44) != want {
        return TestResult::Fail("second batch's range list differs from ranges[256..]");
    }
    // Exactly at the limit: one command, full set on the page.
    let Some(mut fake) = fake_controller(ONCS_DATASET_MGMT, 1_000_000, 1) else {
        return TestResult::Fail("fake controller allocation failed");
    };
    let ns = fake.ctrl.primary_geom();
    if fake.ctrl.dataset_mgmt_ns(ns, &ranges[..256]).is_err() {
        return TestResult::Fail("256-range dataset_mgmt_ns failed");
    }
    if fake.sqe(0)[10] != 255 || fake.sqe(1)[0] != 0 {
        return TestResult::Fail("256 ranges must be a single command (NR=255, no second SQE)");
    }
    let want: Vec<(u64, u64)> = ranges[..256].iter().map(|r| (r.start, r.blocks)).collect();
    if fake.decode_ranges(256) != want {
        return TestResult::Fail("at-limit range list differs from the requested set");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_dsm_batches_at_limit);

/// A controller without the ONCS Dataset Management bit is refused
/// before anything is posted — the failure the silent `Ok(())`
/// used to hide (#927) — and an out-of-range range is refused the
/// same way. A zero-length-only request succeeds with no command.
fn smoke_nvme_dsm_refusals() -> TestResult {
    let one = [LbaRange {
        start: 0x100,
        blocks: 8,
    }];
    // No DSM bit (Write Zeroes alone does not imply DSM).
    let Some(mut fake) = fake_controller(ONCS_WRITE_ZEROES, 1_000_000, 1) else {
        return TestResult::Fail("fake controller allocation failed");
    };
    if fake.ctrl.supports_dataset_mgmt() {
        return TestResult::Fail("supports_dataset_mgmt set without the ONCS bit");
    }
    let ns = fake.ctrl.primary_geom();
    if fake.ctrl.dataset_mgmt_ns(ns, &one) != Err(NvmeError::NotImplemented) {
        return TestResult::Fail("DSM on an unsupported controller must be NotImplemented");
    }
    if fake.sqe(0) != [0; 16] {
        return TestResult::Fail("a refused DSM must not post an SQE");
    }
    // Out of range: end beyond NSZE.
    let Some(mut fake) = fake_controller(ONCS_DATASET_MGMT, 1_000_000, 1) else {
        return TestResult::Fail("fake controller allocation failed");
    };
    let ns = fake.ctrl.primary_geom();
    let past = [LbaRange {
        start: 999_999,
        blocks: 2,
    }];
    if fake.ctrl.dataset_mgmt_ns(ns, &past) != Err(NvmeError::OutOfRange) {
        return TestResult::Fail("a range past NSZE must be OutOfRange");
    }
    if fake.sqe(0) != [0; 16] {
        return TestResult::Fail("an out-of-range DSM must not post an SQE");
    }
    // Zero-length ranges only: success, nothing posted.
    let empty = [LbaRange {
        start: 0,
        blocks: 0,
    }];
    if fake.ctrl.dataset_mgmt_ns(ns, &empty) != Ok(()) {
        return TestResult::Fail("an all-empty range set must succeed");
    }
    if fake.sqe(0) != [0; 16] {
        return TestResult::Fail("an all-empty range set must not post an SQE");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_dsm_refusals);

/// A controller error status on the DSM completion propagates to
/// the caller as `CommandFailed` — never swallowed into success.
fn smoke_nvme_dsm_error_propagates() -> TestResult {
    // CQE status: phase bit + NVMe status 0x02 (Invalid Field in
    // Command) in bits [15:1].
    let Some(mut fake) = fake_controller(ONCS_DATASET_MGMT, 1_000_000, 1 | (0x02 << 1)) else {
        return TestResult::Fail("fake controller allocation failed");
    };
    let ns = fake.ctrl.primary_geom();
    let one = [LbaRange {
        start: 0x100,
        blocks: 8,
    }];
    match fake.ctrl.dataset_mgmt_ns(ns, &one) {
        Err(NvmeError::CommandFailed { cmd, status }) if cmd == 0x09 && status == 0x02 => {
            TestResult::Pass
        }
        _ => TestResult::Fail("a controller error status must surface as CommandFailed"),
    }
}
kernel_test_in!("drivers/nvme", smoke_nvme_dsm_error_propagates);

/// Write Zeroes: opcode 0x08, SLBA split across CDW10/CDW11, the
/// 0-based NLB of Figure 73 in CDW12, no data pointer — and the
/// 65 536-block per-command split. An unsupported controller is
/// refused with nothing posted.
fn smoke_nvme_write_zeroes_sqe_split() -> TestResult {
    let Some(mut fake) = fake_controller(ONCS_DATASET_MGMT | ONCS_WRITE_ZEROES, 0x2_0000_0000, 1)
    else {
        return TestResult::Fail("fake controller allocation failed");
    };
    if !fake.ctrl.supports_write_zeroes() {
        return TestResult::Fail("ONCS Write Zeroes bit not decoded");
    }
    let ns = fake.ctrl.primary_geom();
    // SLBA above 4 GiB exercises the CDW11 half of the split;
    // 200 000 blocks = 3 full commands + 3 392.
    let lba = 0x1_0000_1234u64;
    if fake.ctrl.write_zeroes_ns(ns, lba, 200_000).is_err() {
        return TestResult::Fail("write_zeroes_ns failed against the model controller");
    }
    for i in 0..4usize {
        let w = fake.sqe(i);
        if w[0] & 0xFF != IoOpcode::WriteZeroes as u32 {
            return TestResult::Fail("SQE opcode is not Write Zeroes (0x08)");
        }
        if w[1] != 1 {
            return TestResult::Fail("SQE NSID is not the namespace under test");
        }
        if w[4..10].iter().any(|&x| x != 0) {
            return TestResult::Fail("Write Zeroes must not carry a data pointer");
        }
        let want_lba = lba + (i as u64) * 65_536;
        if w[10] != (want_lba & 0xFFFF_FFFF) as u32 || w[11] != (want_lba >> 32) as u32 {
            return TestResult::Fail("Write Zeroes SLBA split across CDW10/CDW11 is wrong");
        }
        let want_cdw12 = if i < 3 { 65_535 } else { 3_391 };
        if w[12] != want_cdw12 {
            return TestResult::Fail("Write Zeroes CDW12 must be the 0-based NLB");
        }
    }
    // Unsupported: DSM alone does not imply Write Zeroes.
    let Some(mut fake) = fake_controller(ONCS_DATASET_MGMT, 1_000_000, 1) else {
        return TestResult::Fail("fake controller allocation failed");
    };
    let ns = fake.ctrl.primary_geom();
    if fake.ctrl.write_zeroes_ns(ns, 0, 16) != Err(NvmeError::NotImplemented) {
        return TestResult::Fail(
            "Write Zeroes on an unsupported controller must be NotImplemented",
        );
    }
    if fake.sqe(0) != [0; 16] {
        return TestResult::Fail("a refused Write Zeroes must not post an SQE");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_write_zeroes_sqe_split);

/// End-to-end on QEMU's second controller (the flush smokes'
/// scratch disk): the registry's trim advertisement must agree
/// with the controller's ONCS, a real trim must complete, and the
/// trimmed block must read back as one of the three values
/// §3.2.3.2.1 permits for a deallocated block (all zeroes, all
/// ones, or the last data written). Data written after the trim
/// must round-trip.
fn smoke_nvme_trim_qemu() -> TestResult {
    if super::controller_count() < 2 {
        return TestResult::Skip("needs the kernel-test NVMe controllers");
    }
    let Some(dev) = narf_block::find_block_device("nvme1n1") else {
        return TestResult::Fail("nvme1n1 not registered");
    };
    // Advertisement truth on both surfaces (#927): the sync
    // registry device and the async adapter must claim Discard /
    // WriteZeroes exactly when the probed controllers' ONCS do.
    let dsm1 = super::with_controller_at(1, |c| c.supports_dataset_mgmt()).unwrap_or(false);
    if dev.supports_trim() != dsm1 {
        return TestResult::Fail("sync supports_trim disagrees with the controller's ONCS");
    }
    let async_dev = super::NvmeBlockDevice;
    let dsm0 = super::with_controller(|c| c.supports_dataset_mgmt()).unwrap_or(false);
    let wz0 = super::with_controller(|c| c.supports_write_zeroes()).unwrap_or(false);
    if async_dev.supports(BlockFeature::Discard) != dsm0
        || async_dev.supports(BlockFeature::WriteZeroes) != wz0
    {
        return TestResult::Fail("async supports() disagrees with the controller's ONCS");
    }
    if !dsm1 {
        return TestResult::Skip("QEMU controller does not advertise Dataset Management");
    }
    let lba = 60u64;
    let mut saved = [0u8; 512];
    if dev.read(lba, 1, &mut saved).is_err() {
        return TestResult::Fail("read failed");
    }
    let mut block = [0u8; 512];
    for (i, b) in block.iter_mut().enumerate() {
        *b = (i as u8) ^ 0xA5;
    }
    if dev.write(lba, 1, &block).is_err() {
        return TestResult::Fail("pattern write failed");
    }
    if dev.trim(lba, 1).is_err() {
        return TestResult::Fail("trim failed on a DSM-advertising controller");
    }
    let mut back = [0u8; 512];
    let read_ok = dev.read(lba, 1, &mut back).is_ok();
    let legal = back.iter().all(|&b| b == 0) || back.iter().all(|&b| b == 0xFF) || back == block;
    // The device must still serve ordinary I/O after the trim.
    let mut again = [0u8; 512];
    let rt_ok =
        dev.write(lba, 1, &block).is_ok() && dev.read(lba, 1, &mut again).is_ok() && again == block;
    let _ = dev.write(lba, 1, &saved);
    if !read_ok || !legal {
        return TestResult::Fail("read after trim returned a non-spec value");
    }
    if !rt_ok {
        return TestResult::Fail("write/read after trim did not round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_trim_qemu);
