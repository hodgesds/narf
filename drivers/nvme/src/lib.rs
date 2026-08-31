//! narf-drivers-nvme — NVMe host driver.
//!
//! Spec: `drivers/nvme/specification/spec.md` + NVMe base spec rev 1.4
//! §3 (registers) and §5 (admin command set). Stage-4 cut now does the
//! whole admin-queue bring-up against a real PCIe NVMe controller:
//!   <https://nvmexpress.org/specifications/>
//!
//! - Map BAR0 via `bus::map_bar`.
//! - Decode `CAP` (queue depth, doorbell stride, MPSMIN/MAX) and `VS`
//!   (require a 1.x controller).
//! - Reset the controller (clear `CC.EN`, poll `CSTS.RDY=0`).
//! - Allocate Admin Submission Queue (ASQ) + Admin Completion Queue
//!   (ACQ) coherent DMA pages via `narf_io::alloc_coherent`.
//! - Program `AQA` / `ASQ` / `ACQ` and re-enable the controller (`CC.EN=1`,
//!   `CSS=NVM`, `IOSQES=6`, `IOCQES=4`, `MPS=0`); poll `CSTS.RDY=1`.
//! - Issue `IDENTIFY CONTROLLER` (admin opcode 0x06, `CNS=1`); poll the
//!   completion queue's phase-tag flip; ack the head doorbell.
//!
//! What still isn't here: I/O submission/completion queue pairs, real
//! NVMe-over-MSI-X interrupts (today the bring-up polls), and the
//! `BlockDevice` body's read/write/flush implementations. Those land
//! in the next pass — admin-queue bring-up unblocks all of them by
//! proving the BAR + DMA + doorbell plumbing is real.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod admin;
pub mod mi;

mod tests;

use core::cell::UnsafeCell;
use core::future::Future;
use core::sync::atomic::{compiler_fence, AtomicBool, AtomicUsize, Ordering};

use alloc::vec::Vec;
use narf_block::{
    BlockCompletion, BlockDevice, BlockError, BlockFeature, BlockOp, BlockRequest, CancelResult,
    LbaRange,
};
use narf_bus::{enable_msix, map_bar, BusDevice, BusDeviceCap, MmioRegion, MsixTable};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_memory::{PhysAddr, PAGE_SIZE};

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NvmeError {
    NotImplemented,
    BadBar,
    UnsupportedVersion,
    /// CSTS.RDY didn't reach the expected value within the bounded
    /// poll window. Likely a broken controller or wrong BAR0.
    ControllerFailed,
    /// CSTS.CFS = 1: the controller signalled a fatal status.
    ControllerFatal,
    /// `narf_io::alloc_coherent` couldn't satisfy the queue DMA.
    OutOfDmaMemory,
    /// IDENTIFY CONTROLLER returned a non-zero NVMe status field.
    IdentifyFailed {
        status: u16,
    },
    /// A submitted NVMe command (admin or I/O) returned a non-zero
    /// NVMe status field. `cmd` is the opcode that failed.
    CommandFailed {
        cmd: u8,
        status: u16,
    },
    /// The completion queue phase tag never flipped within our poll.
    CompletionTimeout,
    /// `bring_up` hasn't run yet — admin queue isn't programmed.
    NotReady,
    /// Caller asked for an I/O command but `create_io_queue` hasn't
    /// run yet (no I/O queue exists).
    NoIoQueue,
    /// LBA range is outside the namespace's reported capacity.
    OutOfRange,
    /// MSI-X enable / vector allocation / programming failed.
    Msix,
    /// A multi-page transfer asked for more pages than fit in a
    /// single PRP-list. With 4-KiB MPS the cap is 511 entries
    /// beyond PRP1 (one entry of the 512 reserved for chaining
    /// in the future). Callers split larger transfers across
    /// multiple submissions.
    TooManyPages,
}

// ── Register offsets (NVMe base spec §3.1) ──────────────────────────

/// BAR0-relative register offsets. Values are stable per the spec.
#[non_exhaustive]
#[repr(u64)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NvmeRegister {
    Cap = 0x00,   // Controller Capabilities (64-bit)
    Vs = 0x08,    // Version
    Intms = 0x0C, // Interrupt Mask Set
    Intmc = 0x10, // Interrupt Mask Clear
    Cc = 0x14,    // Controller Config
    Csts = 0x1C,  // Controller Status
    Aqa = 0x24,   // Admin Queue Attributes
    Asq = 0x28,   // Admin Submission Queue Base Address (64-bit)
    Acq = 0x30,   // Admin Completion Queue Base Address (64-bit)
}

const REG_CAP_LO: u64 = 0x00;
const REG_CAP_HI: u64 = 0x04;
const REG_VS: u64 = 0x08;
const REG_CC: u64 = 0x14;
const REG_CSTS: u64 = 0x1C;
const REG_AQA: u64 = 0x24;
const REG_ASQ_LO: u64 = 0x28;
const REG_ASQ_HI: u64 = 0x2C;
const REG_ACQ_LO: u64 = 0x30;
const REG_ACQ_HI: u64 = 0x34;
/// Doorbell base — first SQ tail at 0x1000, then alternating SQ tails
/// and CQ heads at stride `4 << CAP.DSTRD`.
const REG_DOORBELL_BASE: u64 = 0x1000;

/// CC bits we set during bring-up.
const CC_EN: u32 = 1 << 0;
const CC_CSS_NVM: u32 = 0 << 4;
const CC_MPS_4K: u32 = 0 << 7;
const CC_AMS_RR: u32 = 0 << 11;
const CC_IOSQES_64: u32 = 6 << 16;
const CC_IOCQES_16: u32 = 4 << 20;

/// CSTS bits.
const CSTS_RDY: u32 = 1 << 0;
const CSTS_CFS: u32 = 1 << 1;

/// Decoded CAP register bitfields.
#[derive(Copy, Clone, Debug)]
pub struct NvmeCaps {
    /// Maximum queue entries supported (CAP.MQES).
    pub mqes: u16,
    /// Doorbell-stride exponent (CAP.DSTRD).
    pub dstrd: u8,
    /// Memory-page-size minimum (2^(12+MPSMIN)).
    pub mpsmin: u8,
    /// Memory-page-size maximum.
    pub mpsmax: u8,
}

impl NvmeCaps {
    /// Decode a 64-bit CAP register read.
    #[inline]
    pub const fn from_raw(r: u64) -> Self {
        Self {
            mqes: (r & 0xFFFF) as u16,
            dstrd: ((r >> 32) & 0xF) as u8,
            mpsmin: ((r >> 48) & 0xF) as u8,
            mpsmax: ((r >> 52) & 0xF) as u8,
        }
    }

    /// Required per-queue doorbell stride in bytes: `4 << DSTRD`.
    #[inline]
    pub const fn doorbell_stride(&self) -> u64 {
        4u64 << self.dstrd
    }
}

// ── Opcodes (NVMe base spec §5 Admin + NVM Command Sets) ────────────

#[non_exhaustive]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AdminOpcode {
    DeleteSq = 0x00,
    CreateSq = 0x01,
    GetLogPage = 0x02,
    DeleteCq = 0x04,
    CreateCq = 0x05,
    Identify = 0x06,
    Abort = 0x08,
    SetFeatures = 0x09,
    GetFeatures = 0x0A,
    AsyncEventRequest = 0x0C,
}

fn nvme_admin_irq() {}
fn nvme_io_irq() {}

#[non_exhaustive]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IoOpcode {
    Flush = 0x00,
    Write = 0x01,
    Read = 0x02,
    WriteZeroes = 0x08,
    DatasetMgmt = 0x09, // for TRIM
}

// ── Submission Queue Entry (64 bytes) + Completion Queue Entry (16) ─

/// NVMe Submission Queue Entry. Layout per base spec §4.2: 64 bytes,
/// naturally laid out in little-endian. Only the fields we actually
/// program are named; the rest stay zero.
#[repr(C)]
#[derive(Copy, Clone)]
struct Sqe {
    cdw0: u32, // opcode + fuse + cid
    nsid: u32,
    _resv: [u32; 2],
    mptr: u64,
    prp1: u64,
    prp2: u64,
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
    cdw13: u32,
    cdw14: u32,
    cdw15: u32,
}

const _: () = assert!(core::mem::size_of::<Sqe>() == 64);

impl Sqe {
    const fn zero() -> Self {
        Self {
            cdw0: 0,
            nsid: 0,
            _resv: [0, 0],
            mptr: 0,
            prp1: 0,
            prp2: 0,
            cdw10: 0,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }
}

/// NVMe Completion Queue Entry. Layout per base spec §4.6: 16 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct Cqe {
    cmd_specific: u32,
    _resv: u32,
    sq_head: u16,
    sq_id: u16,
    cid: u16,
    /// Bit 0 = phase tag; bits 1..15 = NVMe status field
    /// (`SCT << 8 | SC` plus `M` and `DNR` bits at the top).
    status: u16,
}

const _: () = assert!(core::mem::size_of::<Cqe>() == 16);

// ── Controller ──────────────────────────────────────────────────────

/// Admin queue depth — small enough to fit alongside the CQ in a
/// single 4 KiB DMA page, large enough to keep IDENTIFY + a couple of
/// in-flight admin commands. The doorbell-write protocol enforces a
/// "queue not full" invariant when (head + 1) mod N == tail.
const ADMIN_Q_DEPTH: u16 = 4;

/// I/O queue depth — same constraint (single 4 KiB DMA page each), in
/// practice we keep it equal to the admin depth.
const IO_Q_DEPTH: u16 = 4;

/// Default I/O queue id (NVMe reserves qid=0 for the admin queue;
/// the first I/O queue is qid=1).
const IO_QID: u16 = 1;

/// Hard upper bound on the number of I/O queue pairs we ask the
/// controller to create. Bounded by:
///   - MSI-X table slots we want to consume up-front.
///   - Per-queue DMA footprint: every pair burns one SQ page + one
///     CQ page = 8 KiB, plus a per-vector waker channel.
///   - Round-robin index math fits comfortably in a usize regardless.
///
/// The final granted count is `min(host_cpu_count, CAP.MQES+1,
/// NVME_MAX_IO_QUEUE_PAIRS, controller-grant)` — see
/// `create_io_queues_msix`. Per NVMe Base Spec 2.0c §5.27 (Set
/// Features — Number of Queues) the controller MAY grant fewer than
/// the host requests.
const NVME_MAX_IO_QUEUE_PAIRS: u16 = 8;

/// Hardcoded namespace id used for I/O. QEMU NVMe always exposes
/// NSID=1 with the default settings; multi-namespace support is a
/// follow-up.
const DEFAULT_NSID: u32 = 1;

/// NVMe controller handle.
///
/// Three states:
///   - **Skeleton** (constructed via `Controller::new(bar0_phys)`):
///     no `BusDevice`, `probe` returns `NotImplemented`. The original
///     constructor stays so existing tests keep their structural shape.
///   - **Discovered** (constructed via `Controller::from_device`):
///     holds the `BusDevice` so `bring_up` can map BAR0 itself.
///   - **Live** (after `bring_up` completes): admin queue programmed,
///     IDENTIFY parsed.
pub struct Controller {
    pub bar0: u64,
    pub caps: Option<NvmeCaps>,
    /// `Some` once the caller has handed us a real BusDevice;
    /// `bring_up` requires it.
    device: Option<BusDevice>,
    /// Set after a successful `bring_up`. Holds the live admin-queue
    /// state so subsequent admin commands can reuse it.
    admin: Option<Queue>,
    /// Set after `create_io_queue*` completes. One entry per granted
    /// I/O queue pair (qid = index+1). `io_queues[0]` is qid=1, the
    /// first I/O queue. Round-robin / per-CPU dispatch picks an
    /// index via `pick_queue`.
    ///
    /// NVMe Base Spec 2.0c §3.3 / §4.1.4: qid=0 is admin; I/O queues
    /// use qid >= 1.
    io_queues: Vec<Queue>,
    /// Per-queue submission locks. `io_queue_locks[i]` guards
    /// `io_queues[i]`'s SQ tail + doorbell. Parallel submitters to
    /// different queues each take their own lock, so concurrent I/O
    /// to distinct queue indices proceeds without serialising on the
    /// global controller lock.
    ///
    /// Length mirrors `io_queues`; both vecs are populated and cleared
    /// together in the `create_io_queue*` paths.
    ///
    /// Linux reference: drivers/nvme/host/nvme.h:nvme_queue::sq_lock
    io_queue_locks: Vec<IrqSafeSpinLock<()>>,
    /// One IDT vector per I/O CQ. `io_irq_vectors[i]` is the vector
    /// MSI-X table entry `i` delivers to for completions on
    /// `io_queues[i]`. Empty for the polled-completion path
    /// (`create_io_queue`).
    io_irq_vectors: Vec<u8>,
    /// Round-robin counter used to pick the next I/O queue under
    /// concurrent submitters (`fetch_add` per submission). Reset to
    /// 0 when `io_queues` is repopulated. Wraps naturally.
    next_queue: AtomicUsize,
    /// Live BAR0 mapping post-bring-up. Stored so admin commands
    /// don't have to re-map (which writes to cfg-space).
    bar0_region: Option<MmioRegion>,
    /// Identify-controller response, copied out of the DMA buffer
    /// after the IDENTIFY admin command completes.
    identify: Option<IdentifyController>,
    /// LBA size in bytes (typically 512 or 4096) — populated from
    /// IDENTIFY NAMESPACE during bring_up.
    pub lba_bytes: u32,
    /// Namespace capacity in LBAs (NSZE field of IDENTIFY NAMESPACE).
    pub nsze: u64,
    /// Live MSI-X table set up by `create_io_queues_msix`. The table
    /// stays alive (no `Drop` undoes the device-side enable) for the
    /// lifetime of the controller.
    msix: Option<MsixTable>,
    /// Back-compat single-vector accessor: same value as
    /// `io_irq_vectors[0]` when MSI-X is wired, else `None`. Kept on
    /// the public surface so the param-snapshot path doesn't have to
    /// reach into a Vec.
    pub irq_vector: Option<u8>,
}

impl core::fmt::Debug for Controller {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Controller")
            .field("bar0", &format_args!("{:#x}", self.bar0))
            .field("caps", &self.caps)
            .field("ready", &self.admin.is_some())
            .field("identify", &self.identify)
            .finish()
    }
}

/// One NVMe SQ/CQ pair tracked by the host. Same shape across admin
/// and I/O queues; the only difference is the qid + depth.
///
/// The DMA buffers are kept here so they live as long as the queue
/// does — dropping them would unbind the physical pages from under
/// the controller.
#[derive(Debug)]
struct Queue {
    sq_buf: DmaBuffer,
    cq_buf: DmaBuffer,
    qid: u16,
    depth: u16,
    sq_tail: u16,
    cq_head: u16,
    /// Phase tag we expect on the next CQ entry. Flips every time the
    /// CQ wraps.
    cq_phase: u16,
    /// Per-queue doorbell stride from CAP.DSTRD: `4 << DSTRD`.
    db_stride: u64,
    /// Next command id to assign (monotonic, wraps at u16).
    next_cid: u16,
}

impl Queue {
    /// Doorbell offsets for this queue. NVMe layout: SQ tail at
    /// `0x1000 + 2*qid * stride`, CQ head at
    /// `0x1000 + (2*qid + 1) * stride`.
    fn sq_db_off(&self) -> u64 {
        REG_DOORBELL_BASE + 2 * (self.qid as u64) * self.db_stride
    }
    fn cq_db_off(&self) -> u64 {
        REG_DOORBELL_BASE + (2 * (self.qid as u64) + 1) * self.db_stride
    }

    /// Submit `sqe` and synchronously poll for its completion.
    /// Auto-assigns the CID (overwrites the upper 16 bits of cdw0).
    ///
    /// # Safety
    /// The DMA buffers `sq_buf` / `cq_buf` are still mapped and the
    /// controller is enabled. The caller owns the queue (no other
    /// task posting concurrently — Stage-3 single-threaded).
    unsafe fn submit(&mut self, bar0: &MmioRegion, mut sqe: Sqe) -> Result<Cqe, NvmeError> {
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);
        // Preserve opcode (low 8 bits) + FUSE/PSDT (bits 8..15) and
        // overwrite CID (bits 16..31).
        sqe.cdw0 = (sqe.cdw0 & 0x0000_FFFF) | ((cid as u32) << 16);

        // SAFETY: queue is page-aligned; sq_tail < depth.
        unsafe {
            write_sqe(&self.sq_buf, self.sq_tail, &sqe);
        }
        self.sq_tail = (self.sq_tail + 1) % self.depth;
        // SAFETY: identity-mapped MMIO doorbell.
        unsafe {
            bar0.write32(self.sq_db_off(), self.sq_tail as u32);
        }

        // SAFETY: cq_buf is a live DMA page sized for self.depth CQEs.
        let cqe = unsafe { wait_cqe(&self.cq_buf, self.cq_head, self.cq_phase)? };

        self.cq_head = (self.cq_head + 1) % self.depth;
        if self.cq_head == 0 {
            self.cq_phase ^= 1;
        }
        // SAFETY: identity-mapped MMIO doorbell.
        unsafe {
            bar0.write32(self.cq_db_off(), self.cq_head as u32);
        }

        let nvme_status = cqe.status >> 1;
        if nvme_status != 0 {
            return Err(NvmeError::CommandFailed {
                cmd: (sqe.cdw0 & 0xFF) as u8,
                status: nvme_status,
            });
        }
        Ok(cqe)
    }
}

/// Subset of the IDENTIFY CONTROLLER page we currently parse.
/// Layout per NVMe base spec §5.15.2.1.
#[derive(Copy, Clone, Debug)]
pub struct IdentifyController {
    pub vid: u16,
    pub ssvid: u16,
    /// Serial number, ASCII, 20 bytes, space-padded.
    pub sn: [u8; 20],
    /// Model number, ASCII, 40 bytes, space-padded.
    pub mn: [u8; 40],
    /// Firmware revision, ASCII, 8 bytes, space-padded.
    pub fr: [u8; 8],
}

impl Controller {
    /// Skeleton constructor — used by the original
    /// `smoke_nvme_probe_stub_surfaces_not_implemented` test which
    /// only knows a raw BAR address. `probe` on a skeleton returns
    /// `NotImplemented` (or `BadBar` for `bar0 == 0`).
    pub const fn new(bar0: u64) -> Self {
        Self {
            bar0,
            caps: None,
            device: None,
            admin: None,
            io_queues: Vec::new(),
            io_queue_locks: Vec::new(),
            io_irq_vectors: Vec::new(),
            next_queue: AtomicUsize::new(0),
            bar0_region: None,
            identify: None,
            lba_bytes: 512,
            nsze: 0,
            msix: None,
            irq_vector: None,
        }
    }

    /// Constructor taking the real `BusDevice`. The kernel-test smoke
    /// uses this after walking ECAM and finding the QEMU NVMe device.
    pub fn from_device(device: BusDevice) -> Self {
        let mut c = Self::new(0);
        c.device = Some(device);
        c
    }

    /// `true` once `bring_up` has completed.
    pub fn is_ready(&self) -> bool {
        self.admin.is_some()
    }

    /// IDENTIFY CONTROLLER snapshot, populated by `bring_up`.
    pub fn identify(&self) -> Option<&IdentifyController> {
        self.identify.as_ref()
    }

    /// Stop the controller for system suspend — clear CC.EN and
    /// wait for CSTS.RDY=0 so any in-flight admin / IO commands
    /// drain to a quiescent state before we lose power. Queues
    /// stay in DRAM; `enable_for_resume` re-asserts CC.EN.
    ///
    /// # Safety
    /// Caller owns BAR0 exclusively; no concurrent submitters.
    pub unsafe fn disable_for_suspend(&self) -> bool {
        let bar = match &self.bar0_region {
            Some(b) => b,
            None => return false,
        };
        // SAFETY: caller-asserted ownership.
        let cc = unsafe { bar.read32(REG_CC) };
        // SAFETY: same.
        unsafe {
            bar.write32(REG_CC, cc & !CC_EN);
        }
        narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { bar.read32(REG_CSTS) } & CSTS_RDY == 0,
            narf_time::Deadline::after_ms(500),
        )
    }

    /// Re-enable the controller after system wake. Sets CC.EN
    /// and polls CSTS.RDY=1.
    ///
    /// # Safety
    /// Caller owns BAR0 exclusively.
    pub unsafe fn enable_for_resume(&self) -> bool {
        let bar = match &self.bar0_region {
            Some(b) => b,
            None => return false,
        };
        // SAFETY: caller-asserted ownership.
        let cc = unsafe { bar.read32(REG_CC) };
        // SAFETY: same.
        unsafe {
            bar.write32(REG_CC, cc | CC_EN);
        }
        narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { bar.read32(REG_CSTS) } & CSTS_RDY != 0,
            narf_time::Deadline::after_ms(500),
        )
    }

    /// Skeleton probe — returns `NotImplemented` when no `BusDevice`
    /// was supplied. Kept for backward compatibility with the
    /// pre-bring-up smoke; new callers go through `bring_up`.
    pub fn probe(&mut self, _cap: &Cap<BusDeviceCap, Write>) -> Result<(), NvmeError> {
        if self.device.is_none() && self.bar0 == 0 {
            return Err(NvmeError::BadBar);
        }
        if self.device.is_none() {
            return Err(NvmeError::NotImplemented);
        }
        Err(NvmeError::NotImplemented)
    }

    /// Real admin-queue bring-up against a live PCIe NVMe controller.
    ///
    /// Steps (NVMe base spec §3.5):
    /// 1. Map BAR0 + read CAP / VS.
    /// 2. Reset (CC.EN = 0; wait CSTS.RDY = 0).
    /// 3. Allocate ASQ + ACQ pages (zero-initialised — coherent
    ///    DmaBuffer guarantees the page is fresh).
    /// 4. Program AQA / ASQ / ACQ.
    /// 5. CC = CSS_NVM | MPS_4K | IOSQES_64 | IOCQES_16 | EN.
    /// 6. Wait CSTS.RDY = 1.
    /// 7. Issue IDENTIFY CONTROLLER, poll the CQ for completion,
    ///    parse the buffer.
    pub fn bring_up(&mut self, cap: &Cap<BusDeviceCap, Write>) -> Result<(), NvmeError> {
        let device = self.device.ok_or(NvmeError::BadBar)?;

        // ── 0. Flip on MEM_SPACE + BUS_MASTER in the cfg-space
        //       command register ───────────────────────────────────
        // Without BUS_MASTER, the controller can't DMA into the
        // queue / IDENTIFY buffers. QEMU's emulated NVMe is
        // permissive but real silicon refuses, so we set it
        // unconditionally. INTX_DISABLE is also flipped on so the
        // device doesn't try legacy IRQs in parallel with our
        // MSI-X programming.
        narf_bus::pci::set_command(
            cap,
            &device,
            narf_bus::pci::cmd::MEM_SPACE
                | narf_bus::pci::cmd::BUS_MASTER
                | narf_bus::pci::cmd::INTX_DISABLE,
        )
        .map_err(|_| NvmeError::BadBar)?;

        // ── 1. Map BAR0 + read CAP / VS ───────────────────────────
        // SAFETY: BSP, no other writer to this device's cfg window.
        let bar0 = unsafe { map_bar(&device, 0) }.map_err(|_| NvmeError::BadBar)?;
        // SAFETY: BAR0 is identity-mapped MMIO; reads are 4-byte
        // aligned per the NVMe register layout.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let cap_raw = unsafe {
            let lo = bar0.read32(REG_CAP_LO) as u64;
            let hi = bar0.read32(REG_CAP_HI) as u64;
            (hi << 32) | lo
        };
        let caps = NvmeCaps::from_raw(cap_raw);
        // SAFETY: same window, aligned.
        let vs = unsafe { bar0.read32(REG_VS) };
        let major = (vs >> 16) as u16;
        if major < 1 {
            return Err(NvmeError::UnsupportedVersion);
        }

        self.bar0 = bar0.phys.raw();
        self.caps = Some(caps);

        // ── 2. Reset the controller ───────────────────────────────
        // Read-modify-write CC clearing EN.
        // SAFETY: CC is a normal RW register at a known offset.
        let cc = unsafe { bar0.read32(REG_CC) };
        // SAFETY: same window.
        unsafe {
            bar0.write32(REG_CC, cc & !CC_EN);
        }
        // Poll CSTS.RDY = 0. CAP.TO is in 500ms units; QEMU NVMe is
        // ready almost instantly. We bound the wait at ~1M MMIO reads
        // (plenty of slack in QEMU; a real broken controller errors
        // out without locking the kernel).
        wait_csts(&bar0, |s| (s & CSTS_RDY) == 0)?;

        // ── 3. Allocate admin queues ──────────────────────────────
        let sq_buf = alloc_coherent(64 * ADMIN_Q_DEPTH as usize, DomainId::DRIVER_0)
            .map_err(|_| NvmeError::OutOfDmaMemory)?;
        let cq_buf = alloc_coherent(16 * ADMIN_Q_DEPTH as usize, DomainId::DRIVER_0)
            .map_err(|_| NvmeError::OutOfDmaMemory)?;
        // alloc_coherent hands out fresh frames; the frame allocator's
        // documented contract zero-fills before handing out, so the
        // SQ/CQ start in the canonical "nothing in flight, phase tag
        // 0 on every CQE" state.
        let sq_phys = sq_buf.phys_addr().raw();
        let cq_phys = cq_buf.phys_addr().raw();

        // ── 4. Program AQA / ASQ / ACQ ────────────────────────────
        // AQA: bits[11:0] = ASQ size-1, bits[27:16] = ACQ size-1.
        let aqa =
            ((ADMIN_Q_DEPTH as u32 - 1) & 0x0FFF) | (((ADMIN_Q_DEPTH as u32 - 1) & 0x0FFF) << 16);
        // SAFETY: register writes against an identity-mapped MMIO
        // BAR while the controller is disabled — the documented
        // window for programming admin-queue base addresses.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            bar0.write32(REG_AQA, aqa);
            bar0.write32(REG_ASQ_LO, sq_phys as u32);
            bar0.write32(REG_ASQ_HI, (sq_phys >> 32) as u32);
            bar0.write32(REG_ACQ_LO, cq_phys as u32);
            bar0.write32(REG_ACQ_HI, (cq_phys >> 32) as u32);
        }

        // ── 5. Re-enable the controller ───────────────────────────
        let cc = CC_EN | CC_CSS_NVM | CC_MPS_4K | CC_AMS_RR | CC_IOSQES_64 | CC_IOCQES_16;
        // SAFETY: same window.
        unsafe {
            bar0.write32(REG_CC, cc);
        }

        // ── 6. Wait for CSTS.RDY = 1 ──────────────────────────────
        wait_csts(&bar0, |s| (s & CSTS_RDY) != 0)?;

        // ── 6a. Enable MSI-X ──────────────────────────────────────
        let mut msix = narf_bus::msix::enable_msix(cap, &device).ok();
        let mut irq_vector = None;
        if let Some(table) = msix.as_mut() {
            if let Ok(v) = narf_interrupts::vector::alloc() {
                // Program MSI-X slot 0 for Admin queue.
                // Target the BSP (apic_id=0) for now.
                // SAFETY: `table` was just obtained from `enable_msix(cap,
                // &device)` for this device, so we hold its BAR exclusively
                // via the `&mut` borrow of `self.msix` (no other writer to
                // the MSI-X table). `v` came from `narf_interrupts::vector::
                // alloc()`, so slot 0 is a valid, owned vector index, and
                // `enable()` runs last to gate MSI delivery only after the
                // entry is fully programmed (PCIe-recommended order).
                // SAFETY: Valid MMIO bounds or trusted driver environment
                unsafe {
                    let _ = table.program_vector(0, 0, v);
                    let _ = table.enable();
                }
                irq_vector = Some(v);
                narf_interrupts::install_handler(v, nvme_admin_irq);
            }
        }

        let mut admin = Queue {
            sq_buf,
            cq_buf,
            qid: 0,
            depth: ADMIN_Q_DEPTH,
            sq_tail: 0,
            cq_head: 0,
            cq_phase: 1, // first valid CQE has phase = 1
            db_stride: caps.doorbell_stride(),
            next_cid: 0,
        };

        // ── 7. IDENTIFY CONTROLLER ────────────────────────────────
        let id_buf =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| NvmeError::OutOfDmaMemory)?;
        let mut sqe = Sqe::zero();
        sqe.cdw0 = AdminOpcode::Identify as u32;
        sqe.nsid = 0;
        sqe.prp1 = id_buf.phys_addr().raw();
        sqe.cdw10 = 1; // CNS = 1: Identify Controller
                       // SAFETY: queue is live; bar0 is identity-mapped MMIO.
        match unsafe { admin.submit(&bar0, sqe) } {
            Ok(_) => {}
            Err(NvmeError::CommandFailed { status, .. }) => {
                return Err(NvmeError::IdentifyFailed { status })
            }
            Err(e) => return Err(e),
        }
        // SAFETY: id_buf is a live, identity-mapped DMA page.
        let id = unsafe { parse_identify(&id_buf) };
        drop(id_buf);

        // ── 8. IDENTIFY NAMESPACE (NSID=1, CNS=0) ─────────────────
        // Pulls LBA size + namespace capacity. Required before we
        // can validate read/write LBA ranges or compute byte offsets.
        let ns_buf =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| NvmeError::OutOfDmaMemory)?;
        let mut sqe = Sqe::zero();
        sqe.cdw0 = AdminOpcode::Identify as u32;
        sqe.nsid = DEFAULT_NSID;
        sqe.prp1 = ns_buf.phys_addr().raw();
        sqe.cdw10 = 0; // CNS = 0: Identify Namespace
                       // SAFETY: same queue + bar.
        let _ = unsafe { admin.submit(&bar0, sqe)? };
        // SAFETY: ns_buf is a live identity-mapped DMA page.
        let (nsze, lba_bytes) = unsafe { parse_identify_namespace(&ns_buf) };
        drop(ns_buf);

        self.identify = Some(id);
        self.lba_bytes = lba_bytes;
        self.nsze = nsze;
        self.admin = Some(admin);
        self.bar0_region = Some(bar0);
        self.msix = msix;
        self.irq_vector = irq_vector;
        Ok(())
    }

    /// Create a single I/O queue pair (qid=1, depth=`IO_Q_DEPTH`)
    /// using polled completions. Issues admin Create I/O CQ + Create
    /// I/O SQ commands. Idempotent: calling again replaces the
    /// existing queue (the prior one's DmaBuffers drop, freeing the
    /// backing frames; the controller's view is overwritten by the
    /// new SQ/CQ phys addresses).
    pub fn create_io_queue(&mut self) -> Result<(), NvmeError> {
        let admin = self.admin.as_mut().ok_or(NvmeError::NotReady)?;
        let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;

        // Allocate IRQ vector if MSI-X is enabled.
        let mut iv = 0u16;
        let mut ien = 0u32;
        let mut irq_vec = None;
        if let Some(table) = self.msix.as_mut() {
            if let Ok(v) = narf_interrupts::vector::alloc() {
                // Use MSI-X slot 1 for the first I/O queue.
                // SAFETY: `table` is this device's MSI-X table from
                // `enable_msix`, held exclusively here via the `&mut` borrow
                // of `self.msix` (no concurrent writer). `v` came from
                // `narf_interrupts::vector::alloc()`, and slot 1 is within the
                // table (the Admin queue used slot 0). The table was already
                // globally enabled during `init`, so programming a new entry
                // here just adds the I/O CQ's vector.
                // SAFETY: Valid MMIO bounds or trusted driver environment
                unsafe {
                    let _ = table.program_vector(1, 0, v);
                }
                iv = 1;
                ien = 1;
                irq_vec = Some(v);
                narf_interrupts::install_handler(v, nvme_io_irq);
            }
        }

        // Allocate IOSQ + IOCQ DMA pages — same shape as admin.
        let sq_buf = alloc_coherent(64 * IO_Q_DEPTH as usize, DomainId::DRIVER_0)
            .map_err(|_| NvmeError::OutOfDmaMemory)?;
        let cq_buf = alloc_coherent(16 * IO_Q_DEPTH as usize, DomainId::DRIVER_0)
            .map_err(|_| NvmeError::OutOfDmaMemory)?;
        let sq_phys = sq_buf.phys_addr().raw();
        let cq_phys = cq_buf.phys_addr().raw();

        // Create I/O CQ (admin opcode 0x05).
        // CDW10: bits[31:16] = qsize-1, bits[15:0] = qid.
        // CDW11: bits[31:16] = IV (interrupt vector index in MSI-X
        //         table) — 0 since we poll, bit 1 = IEN (interrupt
        //         enable) = 0 to suppress, bit 0 = PC (physically
        //         contiguous) = 1.
        let mut sqe = Sqe::zero();
        sqe.cdw0 = AdminOpcode::CreateCq as u32;
        sqe.prp1 = cq_phys;
        sqe.cdw10 = ((IO_Q_DEPTH as u32 - 1) << 16) | (IO_QID as u32);
        sqe.cdw11 = ((iv as u32) << 16) | (ien << 1) | 1;
        // SAFETY: queue + bar live; CQ buffer is fresh DMA.
        unsafe {
            admin.submit(bar0, sqe)?;
        }

        // Create I/O SQ (admin opcode 0x01).
        // CDW10: bits[31:16] = qsize-1, bits[15:0] = qid.
        // CDW11: bits[31:16] = CQID, bits[2:1] = QPRIO = 0 (urgent),
        //        bit 0 = PC = 1.
        let mut sqe = Sqe::zero();
        sqe.cdw0 = AdminOpcode::CreateSq as u32;
        sqe.prp1 = sq_phys;
        sqe.cdw10 = ((IO_Q_DEPTH as u32 - 1) << 16) | (IO_QID as u32);
        sqe.cdw11 = ((IO_QID as u32) << 16) | 1;
        // SAFETY: queue + bar live.
        unsafe {
            admin.submit(bar0, sqe)?;
        }

        // Stash the new IoQueue. Drop replaces any prior set.
        self.io_queues.clear();
        self.io_queue_locks.clear();
        self.io_irq_vectors.clear();
        self.next_queue.store(0, Ordering::Relaxed);
        if let Some(v) = irq_vec {
            self.io_irq_vectors.push(v);
        }
        self.io_queues.push(Queue {
            sq_buf,
            cq_buf,
            qid: IO_QID,
            depth: IO_Q_DEPTH,
            sq_tail: 0,
            cq_head: 0,
            cq_phase: 1,
            db_stride: admin.db_stride,
            next_cid: 0,
        });
        self.io_queue_locks.push(IrqSafeSpinLock::new(()));
        Ok(())
    }

    /// Submit an NVM Read (`opcode = 0x02`) for `n_blocks` LBAs
    /// starting at `lba`, copying into the page-sized DMA buffer
    /// `buf`. Polls the I/O CQ for completion. Caller-owned.
    ///
    /// `n_blocks` is encoded zero-based on the wire (NLB = blocks-1);
    /// the function takes the human-readable count.
    pub fn read_lba(&mut self, lba: u64, n_blocks: u16, buf: &DmaBuffer) -> Result<(), NvmeError> {
        self.nvm_io(IoOpcode::Read as u8, lba, n_blocks, buf)
    }

    /// Symmetric to `read_lba`: submit an NVM Write (`opcode = 0x01`).
    pub fn write_lba(&mut self, lba: u64, n_blocks: u16, buf: &DmaBuffer) -> Result<(), NvmeError> {
        self.nvm_io(IoOpcode::Write as u8, lba, n_blocks, buf)
    }

    /// Multi-page NVM Read covering `n_blocks` LBAs into the
    /// caller-supplied list of physical 4-KiB page addresses.
    ///
    /// `pages[0]` becomes PRP1; `pages[1]` (if present) becomes PRP2
    /// for ≤ 2-page transfers; larger transfers allocate a one-page
    /// PRP-list with `pages[1..]` as 8-byte little-endian phys-addr
    /// entries (PRP-list chaining is not yet implemented — caps at
    /// 511 entries past PRP1, i.e. ≤ 2 MiB per submission at 4 KiB MPS).
    /// Each `pages[i]` for `i ≥ 1` must be 4-KiB aligned (NVMe base
    /// spec §4.1.2).
    ///
    /// Used by callers (e.g. the FAT loader for init/shell ELFs) that
    /// need transfers larger than the single-page `read_lba` path.
    pub fn read_lba_pages(
        &mut self,
        lba: u64,
        n_blocks: u16,
        pages: &[PhysAddr],
    ) -> Result<(), NvmeError> {
        self.nvm_io_multipage(IoOpcode::Read as u8, lba, n_blocks, pages)
    }

    /// Symmetric to `read_lba_pages`: submit an NVM Write covering
    /// `n_blocks` LBAs from the caller-supplied page list.
    pub fn write_lba_pages(
        &mut self,
        lba: u64,
        n_blocks: u16,
        pages: &[PhysAddr],
    ) -> Result<(), NvmeError> {
        self.nvm_io_multipage(IoOpcode::Write as u8, lba, n_blocks, pages)
    }

    /// Ask the controller how many I/O submission + completion queue
    /// pairs it will grant via Set Features — Number of Queues
    /// (FID 0x07).
    ///
    /// Wire-up per NVMe Base Spec 2.0c §5.27 (table for Feature
    /// Identifier 0x07):
    ///   - CDW10 bits[7:0]  = FID = 0x07
    ///   - CDW11 bits[15:0] = NSQR (number of submission queues
    ///     requested, zero-based)
    ///   - CDW11 bits[31:16] = NCQR (number of completion queues
    ///     requested, zero-based)
    ///
    /// The controller responds with CDW0 carrying the **granted**
    /// counts in the same layout:
    ///   - CDW0 bits[15:0]  = NSQA (granted SQs, zero-based)
    ///   - CDW0 bits[31:16] = NCQA (granted CQs, zero-based)
    ///
    /// "Zero-based" means a returned 3 == 4 queues granted. Returns
    /// `(nsqa+1, ncqa+1)` already converted into a usable count.
    /// `requested` is the host's desired count (1..=u16::MAX); we
    /// encode it as `requested - 1` on the wire.
    pub fn submit_set_features_n_queues(
        &mut self,
        requested: u16,
    ) -> Result<(u16, u16), NvmeError> {
        // The minimum any host should request is 1 pair; the spec
        // allows zero-based 0 == 1 queue, so clamp up.
        let req = requested.max(1);
        let admin = self.admin.as_mut().ok_or(NvmeError::NotReady)?;
        let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;

        let mut sqe = Sqe::zero();
        sqe.cdw0 = AdminOpcode::SetFeatures as u32;
        sqe.cdw10 = admin::FID_NUMBER_OF_QUEUES as u32;
        // NSQR in low 16 bits, NCQR in high 16. Encode zero-based.
        let zb = (req - 1) as u32;
        sqe.cdw11 = (zb << 16) | zb;
        // SAFETY: admin queue + BAR are live; SQE is a normal
        // Set Features command, no host-DMA buffer required.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let cqe = unsafe { admin.submit(bar0, sqe)? };

        // Response CDW0 (Cqe::cmd_specific) carries the granted
        // counts in the same low/high u16 layout (zero-based).
        let nsqa = (cqe.cmd_specific & 0xFFFF) as u16;
        let ncqa = ((cqe.cmd_specific >> 16) & 0xFFFF) as u16;
        Ok((nsqa.saturating_add(1), ncqa.saturating_add(1)))
    }

    /// Create N I/O queue pairs with MSI-X-driven completions, one
    /// MSI-X table entry + IDT vector per pair.
    ///
    /// Steps (NVMe Base Spec 2.0c):
    ///   1. Set Features — Number of Queues (§5.27, FID 0x07) on the
    ///      admin queue with the host's request.
    ///   2. Compute `granted = min(requested, nsqa, ncqa, MQES+1,
    ///      NVME_MAX_IO_QUEUE_PAIRS)`.
    ///   3. For each queue index `i` in `0..granted`:
    ///        - Allocate an MSI-X vector + IDT vector; program
    ///          MSI-X table entry `i` to deliver to the BSP.
    ///        - Allocate CQ DMA; submit Create I/O CQ (§5.2.2,
    ///          opcode 0x05) with `qid=i+1`, `IV=i`, `IEN=1`, `PC=1`.
    ///        - Allocate SQ DMA; submit Create I/O SQ (§5.2.1,
    ///          opcode 0x01) with `qid=i+1`, `CQID=i+1`, `QPRIO=2`
    ///          (Medium), `PC=1`. The host MUST create the CQ first
    ///          (§3.3) before its associated SQ — we do that for
    ///          each pair before moving to the next.
    ///   4. Flip the global MSI-X enable bit.
    ///   5. Stash each `Queue` in `io_queues`, each vector in
    ///      `io_irq_vectors`. `io_queues[0]` is qid=1; the
    ///      submission paths pick a queue via round-robin
    ///      (`pick_queue`).
    ///
    /// Returns the number of granted I/O queue pairs.
    pub fn create_io_queues_msix(
        &mut self,
        bus_dev_cap: &Cap<BusDeviceCap, Write>,
        requested: u16,
    ) -> Result<usize, NvmeError> {
        let device = self.device.ok_or(NvmeError::NotReady)?;

        // Clamp the request to our static + hardware bounds. CAP.MQES
        // is zero-based, so the deepest legal queue depth is MQES+1;
        // since we use a fixed IO_Q_DEPTH=4 the MQES check only
        // matters if a vendor advertised <4-deep queues (no real
        // controller does, but stay defensive). The number of
        // *queues* doesn't run through MQES — that gates depth — so
        // strictly we only need the static cap + cpu_count gate here.
        let cpu_n = narf_lib::smp::cpu_count() as u16;
        let host_cap = cpu_n.clamp(1, NVME_MAX_IO_QUEUE_PAIRS);
        let req = requested.max(1).min(host_cap);

        // ── 1. Ask the controller for `req` pairs ─────────────
        let (nsqa, ncqa) = self.submit_set_features_n_queues(req)?;
        // Granted count is the min of the host request, NSQA, NCQA.
        // Storage stacks generally allocate one pair per queue
        // (one SQ per CQ), so this is what the rest of the routine
        // assumes.
        let granted = req.min(nsqa).min(ncqa);
        if granted == 0 {
            return Err(NvmeError::Msix);
        }

        // ── 2. Discover MSI-X + alloc the table block ─────────
        // Walk the cap list, learn the table size (≥ granted vectors
        // — every PCIe NVMe controller advertises plenty).
        let mut msix = enable_msix(bus_dev_cap, &device).map_err(|_| NvmeError::Msix)?;
        if (msix.size() as u16) < granted {
            return Err(NvmeError::Msix);
        }
        msix.alloc_block(granted).map_err(|_| NvmeError::Msix)?;

        // ── 3. Per-queue: vector + table entry + CQ + SQ ──────
        let mut vectors: Vec<u8> = Vec::with_capacity(granted as usize);
        let mut queues: Vec<Queue> = Vec::with_capacity(granted as usize);
        let admin_stride = self.admin.as_ref().ok_or(NvmeError::NotReady)?.db_stride;

        // Program all MSI-X table entries up-front + flip the
        // global enable bit BEFORE issuing Create I/O CQ. QEMU's
        // NVMe emulation latches the MSI-X-enabled state at
        // Create-IO-CQ time on some code paths — programming after
        // CC.EN=1 but before the first Create-CQ keeps the device
        // unambiguously in "MSI-X delivery armed" mode when it
        // first records each CQ's IV. The PCIe spec only requires
        // "program before delivery" (i.e. before the first
        // interrupt could fire), and the first interrupt-eligible
        // event is the first I/O completion, well after enable().
        for i in 0..granted {
            let v = narf_interrupts::vector::alloc().map_err(|_| NvmeError::Msix)?;
            // SAFETY: caller holds the BusDeviceCap; we own the
            // MSI-X table exclusively (no concurrent writer); the
            // table-slot index was alloc_block'd above.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            let _ = unsafe { msix.program_vector(i, 0, v) }.map_err(|_| NvmeError::Msix)?;
            vectors.push(v);
        }
        // ── 4. Flip the global MSI-X enable bit ──────────────
        // SAFETY: `msix` is this device's MSI-X table from `enable_msix`,
        // owned exclusively here; `enable()` only flips the global enable
        // bit in cfg-space at the cached cap offset, with all table entries
        // already programmed in the loop above.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { msix.enable() }.map_err(|_| NvmeError::Msix)?;

        for i in 0..granted {
            let qid = i + 1; // NVMe Base Spec §4.1.4: I/O qids ≥ 1

            // Per pair: CQ DMA first, then admin Create CQ, then
            // SQ DMA + Create SQ. CQ-before-SQ is required by
            // §3.3 (and the controller will reject a Create SQ
            // that names an unallocated CQID).
            let cq_buf = alloc_coherent(16 * IO_Q_DEPTH as usize, DomainId::DRIVER_0)
                .map_err(|_| NvmeError::OutOfDmaMemory)?;
            let cq_phys = cq_buf.phys_addr().raw();

            {
                // Borrow admin mutably for the submit; drop before
                // the next per-queue iteration so push() below
                // doesn't fight the borrow.
                let admin = self.admin.as_mut().ok_or(NvmeError::NotReady)?;
                let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;

                // Create I/O CQ (§5.2.2, opcode 0x05):
                //   CDW10 bits[31:16] = QSIZE (zero-based)
                //   CDW10 bits[15:0]  = QID
                //   CDW11 bits[31:16] = IV (MSI-X table index)
                //   CDW11 bit[1]      = IEN (interrupt enable)
                //   CDW11 bit[0]      = PC (physically contiguous)
                let mut sqe = Sqe::zero();
                sqe.cdw0 = AdminOpcode::CreateCq as u32;
                sqe.prp1 = cq_phys;
                sqe.cdw10 = ((IO_Q_DEPTH as u32 - 1) << 16) | (qid as u32);
                sqe.cdw11 = ((i as u32) << 16) | (1 << 1) | 1;
                // SAFETY: admin queue + BAR live; CQ DMA fresh.
                unsafe {
                    admin.submit(bar0, sqe)?;
                }
            }

            let sq_buf = alloc_coherent(64 * IO_Q_DEPTH as usize, DomainId::DRIVER_0)
                .map_err(|_| NvmeError::OutOfDmaMemory)?;
            let sq_phys = sq_buf.phys_addr().raw();

            {
                let admin = self.admin.as_mut().ok_or(NvmeError::NotReady)?;
                let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;

                // Create I/O SQ (§5.2.1, opcode 0x01):
                //   CDW10 bits[31:16] = QSIZE (zero-based)
                //   CDW10 bits[15:0]  = QID
                //   CDW11 bits[31:16] = CQID
                //   CDW11 bits[2:1]   = QPRIO (0 = Urgent; matches
                //                       the priority weight the
                //                       polled-completion path
                //                       used and keeps round-trip
                //                       latency dominated by the
                //                       device, not the controller's
                //                       internal arbiter.)
                //   CDW11 bit[0]      = PC (physically contiguous)
                let mut sqe = Sqe::zero();
                sqe.cdw0 = AdminOpcode::CreateSq as u32;
                sqe.prp1 = sq_phys;
                sqe.cdw10 = ((IO_Q_DEPTH as u32 - 1) << 16) | (qid as u32);
                sqe.cdw11 = ((qid as u32) << 16) | 1;
                // SAFETY: admin queue + BAR live; SQ DMA fresh.
                unsafe {
                    admin.submit(bar0, sqe)?;
                }
            }

            queues.push(Queue {
                sq_buf,
                cq_buf,
                qid,
                depth: IO_Q_DEPTH,
                sq_tail: 0,
                cq_head: 0,
                cq_phase: 1,
                db_stride: admin_stride,
                next_cid: 0,
            });
        }

        // ── 5. Publish ────────────────────────────────────────
        let mut locks: Vec<IrqSafeSpinLock<()>> = Vec::with_capacity(queues.len());
        for _ in 0..queues.len() {
            locks.push(IrqSafeSpinLock::new(()));
        }
        self.msix = Some(msix);
        self.irq_vector = vectors.first().copied();
        self.io_irq_vectors = vectors;
        self.io_queues = queues;
        self.io_queue_locks = locks;
        self.next_queue.store(0, Ordering::Relaxed);

        Ok(granted as usize)
    }

    // ── Admin: Get Features ───────────────────────────────────────────

    /// Get Features (§5.11, opcode 0x0A). Returns `CQE.cmd_specific`
    /// on success, which carries the current feature value.
    ///
    /// `sel`: 0=Current, 1=Default, 2=Saved, 3=Supported Caps.
    ///
    /// Linux ref: drivers/nvme/host/admin-cmd.c:nvme_get_features
    pub fn get_features(&mut self, fid: u8, sel: u8) -> Result<u32, NvmeError> {
        let admin = self.admin.as_mut().ok_or(NvmeError::NotReady)?;
        let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;
        let mut sqe = Sqe::zero();
        sqe.cdw0 = AdminOpcode::GetFeatures as u32;
        sqe.cdw10 = ((sel as u32 & 0x07) << 8) | (fid as u32);
        // SAFETY: admin queue + BAR live; no host-DMA buffer required.
        let cqe = unsafe { admin.submit(bar0, sqe)? };
        Ok(cqe.cmd_specific)
    }

    // ── Admin: Set Features (power management, async event config) ────

    /// Set Features — Power Management (FID 0x02, §5.31).
    /// `ps` = desired power state (0 = full performance).
    /// Returns `CQE.cmd_specific` on success.
    pub fn set_features_power_management(&mut self, ps: u8) -> Result<u32, NvmeError> {
        let admin = self.admin.as_mut().ok_or(NvmeError::NotReady)?;
        let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;
        let mut sqe = Sqe::zero();
        sqe.cdw0 = AdminOpcode::SetFeatures as u32;
        sqe.cdw10 = admin::FID_POWER_MANAGEMENT as u32;
        sqe.cdw11 = ps as u32 & 0x1F;
        // SAFETY: same.
        let cqe = unsafe { admin.submit(bar0, sqe)? };
        Ok(cqe.cmd_specific)
    }

    /// Set Features — Async Event Configuration (FID 0x0B, §5.31).
    /// `aec` is the event enable bitmap per spec table 295.
    pub fn set_features_async_event_config(&mut self, aec: u32) -> Result<u32, NvmeError> {
        let admin = self.admin.as_mut().ok_or(NvmeError::NotReady)?;
        let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;
        let mut sqe = Sqe::zero();
        sqe.cdw0 = AdminOpcode::SetFeatures as u32;
        sqe.cdw10 = admin::FID_ASYNC_EVENT_CONFIG as u32;
        sqe.cdw11 = aec;
        // SAFETY: same.
        let cqe = unsafe { admin.submit(bar0, sqe)? };
        Ok(cqe.cmd_specific)
    }

    // ── Admin: Identify Namespace List + enumeration ──────────────────

    /// Identify Active Namespace List (CNS=0x02). Fills up to 1024
    /// 32-bit NSIDs into `out`, returning the count placed. NSIDs are
    /// sorted ascending; a zero entry marks the end of the list.
    ///
    /// Callers drive enumeration by calling repeatedly with
    /// `start_nsid = last_nsid_returned` until the list is shorter
    /// than 1024 entries or the last entry is 0.
    ///
    /// Linux ref: drivers/nvme/host/core.c:nvme_identify_ns_list
    pub fn identify_ns_list(
        &mut self,
        start_nsid: u32,
        out: &mut [u32],
    ) -> Result<usize, NvmeError> {
        let admin = self.admin.as_mut().ok_or(NvmeError::NotReady)?;
        let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;
        let buf =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| NvmeError::OutOfDmaMemory)?;
        let mut sqe = Sqe::zero();
        sqe.cdw0 = AdminOpcode::Identify as u32;
        sqe.nsid = start_nsid;
        sqe.prp1 = buf.phys_addr().raw();
        sqe.cdw10 = admin::CNS_NAMESPACE_LIST as u32;
        // SAFETY: admin queue + BAR live; buf is a fresh DMA page.
        unsafe {
            admin.submit(bar0, sqe)?;
        }
        // Parse: up to 1024 NSIDs, LE u32 each. A zero terminates.
        let base = buf.phys_addr().raw() as *const u32;
        let cap = out.len().min(1024);
        let mut n = 0;
        for i in 0..cap {
            // SAFETY: 4 KiB / 4 bytes = 1024 entries, all in-bounds.
            let nsid = unsafe { core::ptr::read_volatile(base.add(i)) };
            if nsid == 0 {
                break;
            }
            out[n] = nsid;
            n += 1;
        }
        drop(buf);
        Ok(n)
    }

    /// Enumerate all active namespaces: call `identify_ns_list` in a
    /// loop collecting every page of up to 1024 NSIDs, returning the
    /// full NSID vector. Caps at 1024 total NSIDs (adequate for any
    /// real consumer / enterprise drive; production drives rarely
    /// exceed 32).
    ///
    /// Linux ref: drivers/nvme/host/core.c:nvme_scan_ns_list
    pub fn enumerate_namespaces(&mut self) -> Result<Vec<u32>, NvmeError> {
        let mut nsids: Vec<u32> = Vec::new();
        let mut start: u32 = 0;
        let mut page_buf = [0u32; 1024];
        loop {
            let n = self.identify_ns_list(start, &mut page_buf)?;
            if n == 0 {
                break;
            }
            nsids.extend_from_slice(&page_buf[..n]);
            if n < 1024 || nsids.len() >= 1024 {
                break;
            }
            start = *nsids.last().unwrap_or(&0);
        }
        Ok(nsids)
    }

    // ── Admin: Identify Namespace (typed) ─────────────────────────────

    /// Identify Namespace (CNS=0x00) and decode the full typed
    /// `IdentifyNamespaceData`. Supplements the minimal
    /// `(nsze, lba_bytes)` path in `bring_up`.
    ///
    /// Linux ref: drivers/nvme/host/core.c:nvme_identify_ns
    pub fn identify_namespace_typed(
        &mut self,
        nsid: u32,
    ) -> Result<admin::IdentifyNamespaceData, NvmeError> {
        let admin = self.admin.as_mut().ok_or(NvmeError::NotReady)?;
        let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;
        let buf =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| NvmeError::OutOfDmaMemory)?;
        let mut sqe = Sqe::zero();
        sqe.cdw0 = AdminOpcode::Identify as u32;
        sqe.nsid = nsid;
        sqe.prp1 = buf.phys_addr().raw();
        sqe.cdw10 = admin::CNS_NAMESPACE as u32;
        // SAFETY: admin queue + BAR live.
        unsafe {
            admin.submit(bar0, sqe)?;
        }
        // Read the 4 KiB response into a slice and parse.
        let base = buf.phys_addr().raw() as *const u8;
        let mut raw = alloc::vec![0u8; 4096];
        for (i, byte) in raw.iter_mut().enumerate() {
            // SAFETY: `base` is the 4 KiB identity-mapped DMA page just
            // filled by the controller's Identify response; `i` ranges over
            // 0..4096, so `base.add(i)` stays within that one mapped page.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            *byte = unsafe { core::ptr::read_volatile(base.add(i)) };
        }
        drop(buf);
        admin::IdentifyNamespaceData::parse(&raw).ok_or(NvmeError::CommandFailed {
            cmd: 0x06,
            status: 0,
        })
    }

    // ── Admin: Async Event Request (AER) ──────────────────────────────

    /// Post `count` Async Event Request commands into the admin queue.
    /// Per NVMe Base Spec 2.0c §5.2 the host should maintain at least
    /// AERL+1 in-flight AER slots (spec recommends ≥4). This call
    /// posts up to `count` AERs in a single burst; completions will
    /// arrive asynchronously — the caller is responsible for draining
    /// the admin CQ and reposting after each completion.
    ///
    /// In NARF's polled-admin-queue model the AER slots are posted
    /// then immediately retrieved with `wait_cqe`; this is a smoke-
    /// testable structural path — production use lives in an async
    /// task that parks on `wait_for_irq` once MSI-X is wired.
    ///
    /// Linux ref: drivers/nvme/host/core.c:nvme_queue_async_events
    pub fn post_aer_commands(&mut self, count: u8) -> Result<(), NvmeError> {
        if count == 0 {
            return Ok(());
        }
        let admin = self.admin.as_mut().ok_or(NvmeError::NotReady)?;
        let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;

        // ADMIN_Q_DEPTH is 4; posting more AERs than free slots would
        // deadlock the polled path. Cap at depth - 1 so there's always
        // room for a non-AER admin command to slip through.
        let cap = (ADMIN_Q_DEPTH - 1).min(count as u16) as u8;
        for _ in 0..cap {
            let mut sqe = Sqe::zero();
            sqe.cdw0 = AdminOpcode::AsyncEventRequest as u32;
            // Ring the doorbell but do NOT wait for completion here —
            // AERs complete only when an async event fires. We post
            // the SQE into the ring directly, advancing sq_tail, and
            // let the controller hold the slot open.
            let cid = admin.next_cid;
            admin.next_cid = admin.next_cid.wrapping_add(1);
            sqe.cdw0 = (sqe.cdw0 & 0x0000_FFFF) | ((cid as u32) << 16);
            // SAFETY: admin queue is page-aligned; sq_tail < depth.
            unsafe {
                write_sqe(&admin.sq_buf, admin.sq_tail, &sqe);
            }
            admin.sq_tail = (admin.sq_tail + 1) % admin.depth;
            // SAFETY: identity-mapped MMIO doorbell.
            unsafe {
                bar0.write32(admin.sq_db_off(), admin.sq_tail as u32);
            }
        }
        Ok(())
    }

    // ── Admin: AER drain ──────────────────────────────────────────────

    /// Drain all currently-completed Async Event Request completions
    /// from the admin CQ and repost a fresh AER for each one drained,
    /// maintaining the spec-recommended ≥4 in-flight AERs.
    ///
    /// Each CQE whose phase tag matches `cq_phase` is a completed slot.
    /// We advance the CQ head, write the head doorbell, decode the
    /// async event (§5.2 CDW0 layout), and immediately repost one AER
    /// to keep the in-flight count stable.
    ///
    /// Returns the number of AER completions processed (0 = nothing
    /// to drain, which is the normal case when called without a
    /// pending event).
    ///
    /// # Usage
    ///
    /// Call from an async task that parks on the admin MSI-X vector:
    /// ```rust,ignore
    /// loop {
    ///     narf_interrupts::wait_for_irq(admin_vector).await;
    ///     ctrl.drain_aer();
    /// }
    /// ```
    ///
    /// Linux reference: drivers/nvme/host/core.c::nvme_aer_work
    /// (GPL-2.0-or-later; adapted under NARF's post-2026-05-20 licence).
    pub fn drain_aer(&mut self) -> u8 {
        let admin = match self.admin.as_mut() {
            Some(a) => a,
            None => return 0,
        };
        let bar0 = match self.bar0_region.as_ref() {
            Some(b) => b,
            None => return 0,
        };

        let mut drained: u8 = 0;
        // Peek every slot from the current head forward; stop when
        // the phase tag doesn't match (no more completions).
        loop {
            // SAFETY: admin CQ DMA buffer is live + identity-mapped;
            // cq_head is always < admin.depth.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            let cqe = unsafe { peek_cqe(&admin.cq_buf, admin.cq_head) };
            if (cqe.status & 1) != (admin.cq_phase & 1) {
                break; // no more completed entries
            }

            // Decode async event type + info from cmd_specific (§5.2).
            // event_type: bits[2:0] — 0=error, 1=SMART, 2=notice.
            // event_info: bits[15:8]. log_page_id: bits[31:24].
            // We currently only observe; future callers can inspect the
            // returned `drained` count and issue Get Log Page.
            let _event_type = (cqe.cmd_specific & 0x07) as u8;
            let _event_info = ((cqe.cmd_specific >> 8) & 0xFF) as u8;

            admin.cq_head = (admin.cq_head + 1) % admin.depth;
            if admin.cq_head == 0 {
                admin.cq_phase ^= 1;
            }
            // Advance the CQ head doorbell so the controller can reuse
            // the slot.
            // SAFETY: identity-mapped MMIO doorbell.
            unsafe {
                bar0.write32(admin.cq_db_off(), admin.cq_head as u32);
            }
            drained += 1;

            // Repost one AER to keep the in-flight count stable.
            // ADMIN_Q_DEPTH is 4; we cap posting at depth-1 to leave
            // room for non-AER admin commands.
            let cid = admin.next_cid;
            admin.next_cid = admin.next_cid.wrapping_add(1);
            let mut sqe = Sqe::zero();
            sqe.cdw0 = (AdminOpcode::AsyncEventRequest as u32) | ((cid as u32) << 16);
            // SAFETY: admin queue is page-aligned; sq_tail bounded.
            unsafe {
                write_sqe(&admin.sq_buf, admin.sq_tail, &sqe);
            }
            admin.sq_tail = (admin.sq_tail + 1) % admin.depth;
            // SAFETY: identity-mapped MMIO doorbell.
            unsafe {
                bar0.write32(admin.sq_db_off(), admin.sq_tail as u32);
            }

            // Bound the loop: never process more than depth-1 slots
            // in one pass to prevent re-draining freshly reposted AERs.
            if drained >= (ADMIN_Q_DEPTH - 1) as u8 {
                break;
            }
        }
        drained
    }

    /// Per-queue lock count — always equal to `io_queue_count()`.
    /// Both vecs are populated and cleared together in the
    /// `create_io_queue*` paths. Exposed for tests.
    #[inline]
    pub fn io_queue_lock_count(&self) -> usize {
        self.io_queue_locks.len()
    }

    // ── Admin: Format NVM ─────────────────────────────────────────────

    /// Format NVM (§5.4, opcode 0x80). Reformats `nsid` with LBA format
    /// index `lbaf` and secure-erase setting `ses` (use
    /// `admin::SES_NO_SECURE_ERASE` for normal format).
    ///
    /// This is a long-running admin command — NVMe controllers can
    /// take seconds to minutes to complete a format. The polled-CQ
    /// path has a 30 s wall-clock deadline (generous for QEMU).
    ///
    /// Linux ref: drivers/nvme/host/ioctl.c:nvme_format_ns
    pub fn format_nvm(&mut self, nsid: u32, lbaf: u8, ses: u8) -> Result<(), NvmeError> {
        let admin = self.admin.as_mut().ok_or(NvmeError::NotReady)?;
        let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;
        let mut sqe = Sqe::zero();
        sqe.cdw0 = admin::OPC_FORMAT_NVM as u32;
        sqe.nsid = nsid;
        sqe.cdw10 = ((ses as u32) & 0x07) << 9 | ((lbaf as u32) & 0x0F);
        // SAFETY: admin queue + BAR live; Format NVM has no host-DMA.
        unsafe {
            admin.submit(bar0, sqe)?;
        }
        Ok(())
    }

    // ── Admin: Security Send (opcode 0x81) ───────────────────────────────

    /// Security Send (NVMe Base 2.0c §5.25, opcode 0x81).
    ///
    /// Transfers `data` to the device via the protocol identified by `secp`
    /// (Security Protocol) and `spsp` (Protocol-Specific). The primary use
    /// is TCG Opal session traffic (`secp = 0x01`).
    ///
    /// CDW10 bits[31:24] = SECP, bits[23:8] = SPSP, bits[7:0] = reserved.
    /// CDW11 = TL (transfer length in bytes = `data.len()`).
    ///
    /// Linux ref (GPL-2.0-or-later):
    ///   drivers/nvme/host/core.c:nvme_sec_submit
    pub fn security_send(&mut self, secp: u8, spsp: u16, data: &[u8]) -> Result<(), NvmeError> {
        if data.is_empty() {
            return Ok(());
        }
        let tl = data.len() as u32;
        let buf = alloc_coherent(data.len(), DomainId::DRIVER_0)
            .map_err(|_| NvmeError::OutOfDmaMemory)?;
        // SAFETY: identity-mapped DMA buffer; exclusively owned here.
        unsafe {
            let base = buf.phys_addr().raw() as *mut u8;
            for (i, &b) in data.iter().enumerate() {
                core::ptr::write_volatile(base.add(i), b);
            }
        }
        let admin = self.admin.as_mut().ok_or(NvmeError::NotReady)?;
        let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;
        let sqe = build_security_sqe(
            admin::OPC_SECURITY_SEND,
            secp,
            spsp,
            tl,
            buf.phys_addr().raw(),
        );
        // SAFETY: admin queue + BAR live; DMA buffer valid for submit duration.
        unsafe {
            admin.submit(bar0, sqe)?;
        }
        drop(buf);
        Ok(())
    }

    // ── Admin: Security Receive (opcode 0x82) ────────────────────────────

    /// Security Receive (NVMe Base 2.0c §5.26, opcode 0x82).
    ///
    /// Requests up to `buf.len()` bytes of security protocol data from the
    /// device into `buf`. Returns the number of bytes written.
    ///
    /// CDW10 bits[31:24] = SECP, bits[23:8] = SPSP, bits[7:0] = reserved.
    /// CDW11 = AL (allocation length = `buf.len()`).
    ///
    /// Linux ref (GPL-2.0-or-later):
    ///   drivers/nvme/host/core.c:nvme_sec_submit
    pub fn security_receive(
        &mut self,
        secp: u8,
        spsp: u16,
        buf: &mut [u8],
    ) -> Result<usize, NvmeError> {
        if buf.is_empty() {
            return Ok(0);
        }
        let al = buf.len() as u32;
        let dma =
            alloc_coherent(buf.len(), DomainId::DRIVER_0).map_err(|_| NvmeError::OutOfDmaMemory)?;
        let admin = self.admin.as_mut().ok_or(NvmeError::NotReady)?;
        let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;
        let sqe = build_security_sqe(
            admin::OPC_SECURITY_RECEIVE,
            secp,
            spsp,
            al,
            dma.phys_addr().raw(),
        );
        // SAFETY: admin queue + BAR live; DMA buffer valid for submit duration.
        unsafe {
            admin.submit(bar0, sqe)?;
        }
        // Copy DMA buffer into caller's slice.
        // SAFETY: identity-mapped DMA page; buf.len() == al.
        unsafe {
            let base = dma.phys_addr().raw() as *const u8;
            for (i, slot) in buf.iter_mut().enumerate() {
                *slot = core::ptr::read_volatile(base.add(i));
            }
        }
        drop(dma);
        Ok(buf.len())
    }

    // ── Admin: TCG Opal Level 0 Discovery ────────────────────────────────

    /// TCG Opal Level 0 Discovery (Opal SSC §3.1.1).
    ///
    /// Issues `Security Receive(SECP=0x01, SPSP=0x0001)` and decodes the L0
    /// Discovery 0 response into an `OpalDiscovery` struct.
    ///
    /// Linux ref (GPL-2.0-or-later):
    ///   block/sed-opal.c:opal_discovery0_end,
    ///   block/opal_proto.h (d0_header / d0_features layout).
    pub fn discover_opal(&mut self) -> Result<admin::OpalDiscovery, NvmeError> {
        const L0_DISC_BUF: usize = 512;
        let mut raw = alloc::vec![0u8; L0_DISC_BUF];
        let n = self.security_receive(admin::SECP_TCG_OPAL, admin::SPSP_L0_DISCOVERY, &mut raw)?;
        admin::OpalDiscovery::parse(&raw[..n]).ok_or(NvmeError::CommandFailed {
            cmd: admin::OPC_SECURITY_RECEIVE,
            status: 0,
        })
    }

    /// Number of live I/O queue pairs. Zero before any of the
    /// `create_io_queue*` paths run.
    #[inline]
    pub fn io_queue_count(&self) -> usize {
        self.io_queues.len()
    }

    /// Round-robin pick of an I/O queue index. Returns 0 when only
    /// one queue exists. Unlocked / lock-free — every submission
    /// path immediately takes the controller's lock after, so the
    /// fetch_add isn't load-bearing for safety, just for distribution.
    #[inline]
    fn pick_queue(&self) -> usize {
        let n = self.io_queues.len();
        if n <= 1 {
            return 0;
        }
        self.next_queue.fetch_add(1, Ordering::Relaxed) % n
    }

    /// Submit an NVM Read/Write to a round-robin-picked I/O queue
    /// and wait for MSI-X-delivered completion via
    /// `narf_interrupts::fire_count`. Caller decides between
    /// `read_lba` (polled) and this for IRQ-driven flows.
    ///
    /// Synchronous variant: spins on `fire_count` after submitting;
    /// the underlying mechanism is the same one `wait_for_irq.await`
    /// drives, just without an executor. With multi-queue wired the
    /// queue is picked via `pick_queue` (round-robin AtomicUsize)
    /// and the wait targets THAT queue's MSI-X vector so completion
    /// dispatch stays per-CQ.
    pub fn submit_io_irq(
        &mut self,
        opcode: u8,
        lba: u64,
        n_blocks: u16,
        buf: &DmaBuffer,
    ) -> Result<(), NvmeError> {
        if self.io_queues.is_empty() {
            return Err(NvmeError::NoIoQueue);
        }
        let qi = self.pick_queue();
        let v = *self.io_irq_vectors.get(qi).ok_or(NvmeError::Msix)?;
        let io = self.io_queues.get_mut(qi).ok_or(NvmeError::NoIoQueue)?;
        let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;
        if n_blocks == 0 {
            return Ok(());
        }
        if self.nsze != 0 && lba.saturating_add(n_blocks as u64) > self.nsze {
            return Err(NvmeError::OutOfRange);
        }

        let baseline = narf_interrupts::fire_count(v);

        let mut sqe = Sqe::zero();
        sqe.cdw0 = opcode as u32;
        sqe.nsid = DEFAULT_NSID;
        sqe.prp1 = buf.phys_addr().raw();
        sqe.cdw10 = (lba & 0xFFFF_FFFF) as u32;
        sqe.cdw11 = (lba >> 32) as u32;
        sqe.cdw12 = (n_blocks - 1) as u32;

        // Auto-CID + ring SQ tail doorbell.
        let cid = io.next_cid;
        io.next_cid = io.next_cid.wrapping_add(1);
        sqe.cdw0 = (sqe.cdw0 & 0x0000_FFFF) | ((cid as u32) << 16);
        // SAFETY: queue is page-aligned; sq_tail bounded.
        unsafe {
            write_sqe(&io.sq_buf, io.sq_tail, &sqe);
        }
        io.sq_tail = (io.sq_tail + 1) % io.depth;
        // SAFETY: identity-mapped MMIO doorbell.
        unsafe {
            bar0.write32(io.sq_db_off(), io.sq_tail as u32);
        }

        // Wait for MSI-X delivery — the dispatch table's fire_count
        // bumps from the ISR. As a defensive belt-and-braces check
        // we also bail if the CQE phase flips first (e.g. if the
        // interrupt got lost; QEMU has been observed to do this on
        // hot reset paths). responsive_spin_until ticks sleep_pumps
        // so the FB cursor / serial drain stay alive. Wall-clock
        // budget 5 s — well clear of typical sub-ms NVMe I/O
        // completion latency, finite enough to surface a wedged
        // controller.
        let done = narf_scheduler::responsive_spin_until(
            || {
                if narf_interrupts::fire_count(v) > baseline {
                    return true;
                }
                // SAFETY: cq_buf is a live identity-mapped DMA page.
                let cqe = unsafe { peek_cqe(&io.cq_buf, io.cq_head) };
                (cqe.status & 1) == (io.cq_phase & 1)
            },
            narf_time::Deadline::after_ms(5_000),
        );
        if !done {
            return Err(NvmeError::CompletionTimeout);
        }

        // Drain the CQE.
        // SAFETY: same buffer.
        let cqe = unsafe { peek_cqe(&io.cq_buf, io.cq_head) };
        io.cq_head = (io.cq_head + 1) % io.depth;
        if io.cq_head == 0 {
            io.cq_phase ^= 1;
        }
        // SAFETY: identity-mapped MMIO doorbell.
        unsafe {
            bar0.write32(io.cq_db_off(), io.cq_head as u32);
        }

        let nvme_status = cqe.status >> 1;
        if nvme_status != 0 {
            return Err(NvmeError::CommandFailed {
                cmd: opcode,
                status: nvme_status,
            });
        }
        Ok(())
    }

    /// Async sibling of `submit_io_irq`. Submits the command,
    /// then `wait_for_irq(vector).await`s the MSI-X completion
    /// instead of spinning on `fire_count`. Lets the executor
    /// run other tasks during the I/O — the difference between
    /// "kernel pauses for the entire I/O" and "kernel does
    /// other work while the device is busy".
    ///
    /// Borrows on `self.io_queues[qi]` / `self.bar0_region` are
    /// scoped to the synchronous setup + completion-drain phases
    /// so the `.await` doesn't hold a mutable borrow across the
    /// suspension point. The same queue index is used either side
    /// of the await — switching queues mid-flight would corrupt
    /// the picked queue's CQ head/phase tracking.
    pub async fn submit_io_irq_async(
        &mut self,
        opcode: u8,
        lba: u64,
        n_blocks: u16,
        buf: &DmaBuffer,
    ) -> Result<(), NvmeError> {
        if self.io_queues.is_empty() {
            return Err(NvmeError::NoIoQueue);
        }
        // Pick a queue index up-front and keep it across the await —
        // the same queue must be used for both the doorbell and the
        // post-IRQ CQE drain (each CQ has its own head pointer + phase
        // tag; routing the drain to a different queue would corrupt
        // its state). The vector is the per-queue MSI-X entry's
        // IDT vector so wakeups land on this CQ's task only.
        let qi = self.pick_queue();
        let v = *self.io_irq_vectors.get(qi).ok_or(NvmeError::Msix)?;
        if n_blocks == 0 {
            return Ok(());
        }
        if self.nsze != 0 && lba.saturating_add(n_blocks as u64) > self.nsze {
            return Err(NvmeError::OutOfRange);
        }

        // CRITICAL ORDERING: construct the WaitForIrq future
        // BEFORE writing the SQ doorbell. WaitForIrq snapshots
        // fire_count at construction (interrupts/wait.rs:31).
        // If we doorbell first then construct the future, an
        // MSI that lands in the ~microsecond window in between
        // bumps fire_count, the future captures the post-IRQ
        // value as its baseline, and the await parks forever
        // waiting for a second MSI that never comes.
        //
        // 30 s deadline matches Linux NVMe's default
        // command timeout (drivers/nvme/host/nvme.c:NVME_DEFAULT_TIMEOUT).
        // On expiry we surface CompletionTimeout so the upper
        // layer can decide between retry / controller reset /
        // EIO to the requestor.
        let deadline = narf_time::Deadline::after_ms(30_000);
        let wait = narf_interrupts::wait_for_irq_until(v, deadline);

        // Submit + ring doorbell. All self-borrows released at
        // the closing brace.
        {
            let io = self.io_queues.get_mut(qi).ok_or(NvmeError::NoIoQueue)?;
            let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;
            let mut sqe = Sqe::zero();
            sqe.cdw0 = opcode as u32;
            sqe.nsid = DEFAULT_NSID;
            sqe.prp1 = buf.phys_addr().raw();
            sqe.cdw10 = (lba & 0xFFFF_FFFF) as u32;
            sqe.cdw11 = (lba >> 32) as u32;
            sqe.cdw12 = (n_blocks - 1) as u32;
            let cid = io.next_cid;
            io.next_cid = io.next_cid.wrapping_add(1);
            sqe.cdw0 = (sqe.cdw0 & 0x0000_FFFF) | ((cid as u32) << 16);
            // SAFETY: queue page-aligned; sq_tail bounded.
            unsafe {
                write_sqe(&io.sq_buf, io.sq_tail, &sqe);
            }
            io.sq_tail = (io.sq_tail + 1) % io.depth;
            // SAFETY: identity-mapped MMIO doorbell.
            unsafe {
                bar0.write32(io.sq_db_off(), io.sq_tail as u32);
            }
        }

        // Park until the MSI-X completion fires OR the 30 s
        // deadline expires. The first poll returns Ready if MSI
        // fired between the future's construction (above, pre-
        // doorbell) and now.
        match wait.await {
            Ok(_) => {}
            Err(_elapsed) => {
                return Err(NvmeError::CompletionTimeout);
            }
        }

        // Drain the CQE + ring CQ-head doorbell on the SAME queue
        // we submitted on.
        let io = self.io_queues.get_mut(qi).ok_or(NvmeError::NoIoQueue)?;
        let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;
        // SAFETY: cq_buf is a live identity-mapped DMA page.
        let cqe = unsafe { peek_cqe(&io.cq_buf, io.cq_head) };
        io.cq_head = (io.cq_head + 1) % io.depth;
        if io.cq_head == 0 {
            io.cq_phase ^= 1;
        }
        // SAFETY: identity-mapped MMIO doorbell. Writing here
        // tells the controller it's free to MSI again on the
        // next completion past head.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            bar0.write32(io.cq_db_off(), io.cq_head as u32);
        }
        let nvme_status = cqe.status >> 1;
        if nvme_status != 0 {
            return Err(NvmeError::CommandFailed {
                cmd: opcode,
                status: nvme_status,
            });
        }
        Ok(())
    }

    fn nvm_io(
        &mut self,
        opcode: u8,
        lba: u64,
        n_blocks: u16,
        buf: &DmaBuffer,
    ) -> Result<(), NvmeError> {
        if self.io_queues.is_empty() {
            return Err(NvmeError::NoIoQueue);
        }
        let qi = self.pick_queue();
        let io = self.io_queues.get_mut(qi).ok_or(NvmeError::NoIoQueue)?;
        let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;
        if n_blocks == 0 {
            return Ok(());
        }
        // Range check against the namespace's reported capacity.
        if self.nsze != 0 && lba.saturating_add(n_blocks as u64) > self.nsze {
            return Err(NvmeError::OutOfRange);
        }
        let mut sqe = Sqe::zero();
        sqe.cdw0 = opcode as u32;
        sqe.nsid = DEFAULT_NSID;
        sqe.prp1 = buf.phys_addr().raw();
        // CDW10/11 = SLBA (64-bit, little-endian split).
        sqe.cdw10 = (lba & 0xFFFF_FFFF) as u32;
        sqe.cdw11 = (lba >> 32) as u32;
        // CDW12 bits[15:0] = NLB-1; flags (LR/FUA/PRINFO) zero.
        sqe.cdw12 = (n_blocks - 1) as u32;
        // SAFETY: io queue + bar are live; buf is identity-mapped DMA.
        unsafe {
            io.submit(bar0, sqe)?;
        }
        Ok(())
    }

    /// Multi-page PRP-list NVM I/O. See `read_lba_pages` for the
    /// public-API contract. The PRP-list buffer is allocated on
    /// demand and held alive across `submit` so the controller's DMA
    /// reads against it complete before the buffer drops.
    fn nvm_io_multipage(
        &mut self,
        opcode: u8,
        lba: u64,
        n_blocks: u16,
        pages: &[PhysAddr],
    ) -> Result<(), NvmeError> {
        if self.io_queues.is_empty() {
            return Err(NvmeError::NoIoQueue);
        }
        let qi = self.pick_queue();
        let io = self.io_queues.get_mut(qi).ok_or(NvmeError::NoIoQueue)?;
        let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;
        if n_blocks == 0 || pages.is_empty() {
            return Ok(());
        }
        if self.nsze != 0 && lba.saturating_add(n_blocks as u64) > self.nsze {
            return Err(NvmeError::OutOfRange);
        }

        let mut sqe = Sqe::zero();
        sqe.cdw0 = opcode as u32;
        sqe.nsid = DEFAULT_NSID;
        sqe.cdw10 = (lba & 0xFFFF_FFFF) as u32;
        sqe.cdw11 = (lba >> 32) as u32;
        sqe.cdw12 = (n_blocks - 1) as u32;

        sqe.prp1 = pages[0].raw();

        // Hold the PRP-list buffer across the submit so its DMA
        // memory stays mapped for the controller. Dropped after
        // `submit` returns (which is synchronous: it polls the CQ).
        let _prp_list_keepalive: Option<DmaBuffer>;

        match pages.len() {
            1 => {
                sqe.prp2 = 0;
                _prp_list_keepalive = None;
            }
            2 => {
                sqe.prp2 = pages[1].raw();
                _prp_list_keepalive = None;
            }
            _ => {
                // PRP-list with chaining: a single 4-KiB list page
                // holds up to 512 8-byte entries. Cap at 511 so a
                // future change can dedicate the last slot to a
                // chain pointer; reject larger transfers for now.
                let entries = pages.len() - 1;
                const MAX_PRP_LIST_ENTRIES: usize = 511;
                if entries > MAX_PRP_LIST_ENTRIES {
                    return Err(NvmeError::TooManyPages);
                }
                let buf = alloc_coherent(PAGE_SIZE as usize, DomainId::DRIVER_0)
                    .map_err(|_| NvmeError::OutOfDmaMemory)?;
                // SAFETY: alloc_coherent zero-fills + page-aligns the
                // buffer; the kernel-mapped pointer stays valid for
                // the buffer's lifetime, which we extend across the
                // submit by binding to `_prp_list_keepalive`. NVMe
                // expects little-endian 8-byte phys addresses; on a
                // little-endian target a plain `write_volatile<u64>`
                // produces that layout.
                // SAFETY: Valid MMIO bounds or trusted driver environment
                unsafe {
                    let entries_ptr = buf.as_mut_ptr() as *mut u64;
                    for (i, p) in pages[1..].iter().enumerate() {
                        core::ptr::write_volatile(entries_ptr.add(i), p.raw());
                    }
                }
                sqe.prp2 = buf.phys_addr().raw();
                _prp_list_keepalive = Some(buf);
            }
        }

        // SAFETY: io queue + bar are live; pages + the optional
        // PRP-list page are identity-mapped DMA owned by the caller
        // / by `_prp_list_keepalive` respectively.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            io.submit(bar0, sqe)?;
        }
        Ok(())
    }
}

// ── helpers ─────────────────────────────────────────────────────────

/// Bounded poll for a `CSTS` predicate. Wall-clock-bounded at 5 s
/// (NVMe 1.4 §3.1.5: CSTS.RDY transition is bounded by CAP.TO * 500
/// ms, which can be up to ~127 s nominal but in practice settles in
/// well under a second on every controller we've seen — 5 s is the
/// "real wedge" threshold). Returns `ControllerFailed` on timeout or
/// `ControllerFatal` if `CFS` is set during the wait.
fn wait_csts<F: Fn(u32) -> bool>(bar: &MmioRegion, ok: F) -> Result<(), NvmeError> {
    // responsive_spin_until ticks sleep_pumps every ~4096 iterations
    // so the cursor / FB / serial console stay alive while we busy-
    // wait on a stuck controller.
    let mut fatal = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: identity-mapped MMIO, naturally aligned.
            let s = unsafe { bar.read32(REG_CSTS) };
            if (s & CSTS_CFS) != 0 {
                fatal = true;
                return true;
            }
            ok(s)
        },
        narf_time::Deadline::after_ms(5_000),
    );
    if fatal {
        return Err(NvmeError::ControllerFatal);
    }
    if done {
        Ok(())
    } else {
        Err(NvmeError::ControllerFailed)
    }
}

/// Write SQE `index` into the submission-queue DMA buffer.
///
/// # Safety
/// `buf` must be a live coherent DMA buffer sized for
/// `ADMIN_Q_DEPTH * 64` bytes; `index < ADMIN_Q_DEPTH`.
unsafe fn write_sqe(buf: &DmaBuffer, index: u16, sqe: &Sqe) {
    let base = buf.phys_addr().raw() as *mut Sqe;
    // SAFETY: caller guarantees buf is page-aligned and large
    // enough; index is bounded.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        core::ptr::write_volatile(base.add(index as usize), *sqe);
    }
}

/// Read the CQ entry at `index` without polling. Used by the
/// MSI-X-driven path which tracks completion via fire_count instead.
///
/// # Safety
/// `buf` must be a live coherent DMA buffer sized for at least
/// `index + 1` 16-byte CQEs.
unsafe fn peek_cqe(buf: &DmaBuffer, index: u16) -> Cqe {
    let base = buf.phys_addr().raw() as *const Cqe;
    // SAFETY: caller guarantees buf is page-aligned and large enough.
    unsafe { core::ptr::read_volatile(base.add(index as usize)) }
}

/// Spin until CQ entry `index` has the expected phase tag, then
/// return it.
///
/// # Safety
/// `buf` must be a live coherent DMA buffer sized for
/// `ADMIN_Q_DEPTH * 16` bytes; `index < ADMIN_Q_DEPTH`.
unsafe fn wait_cqe(buf: &DmaBuffer, index: u16, expected_phase: u16) -> Result<Cqe, NvmeError> {
    let base = buf.phys_addr().raw() as *const Cqe;
    // responsive_spin_until keeps cursor/FB/serial alive on a slow
    // or stuck controller. 5 s wall-clock budget — NVMe admin
    // commands (IDENTIFY etc.) are sub-millisecond on real hardware;
    // 5 s is the "real wedge" threshold.
    let done = narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: caller guarantees buf is page-aligned and large
            // enough; index is bounded.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            let cqe = unsafe { core::ptr::read_volatile(base.add(index as usize)) };
            (cqe.status & 1) == (expected_phase & 1)
        },
        narf_time::Deadline::after_ms(5_000),
    );
    if !done {
        return Err(NvmeError::CompletionTimeout);
    }
    // SAFETY: caller guarantees buf is page-aligned and large enough.
    let cqe = unsafe { core::ptr::read_volatile(base.add(index as usize)) };
    Ok(cqe)
}

/// Pull our subset of fields out of the IDENTIFY CONTROLLER page.
///
/// # Safety
/// `buf` must point to a 4096-byte coherent DMA buffer the controller
/// has finished writing to (CQE arrived).
unsafe fn parse_identify(buf: &DmaBuffer) -> IdentifyController {
    let base = buf.phys_addr().raw() as *const u8;
    // SAFETY: 4 KiB DMA buffer; we read in-bounds.
    let read_u16 = |off: usize| -> u16 {
        // SAFETY: same buffer.
        unsafe { core::ptr::read_volatile(base.add(off) as *const u16) }
    };
    let read_arr = |off: usize, out: &mut [u8]| {
        for (i, slot) in out.iter_mut().enumerate() {
            // SAFETY: same buffer; identity-mapped DMA page.
            *slot = unsafe { core::ptr::read_volatile(base.add(off + i)) };
        }
    };
    let mut sn = [0u8; 20];
    let mut mn = [0u8; 40];
    let mut fr = [0u8; 8];
    read_arr(4, &mut sn); // bytes 4..23   = SN
    read_arr(24, &mut mn); // bytes 24..63  = MN
    read_arr(64, &mut fr); // bytes 64..71  = FR
    IdentifyController {
        vid: read_u16(0),
        ssvid: read_u16(2),
        sn,
        mn,
        fr,
    }
}

/// Pull `(NSZE, lba_bytes)` out of an IDENTIFY NAMESPACE page.
///
/// IDENTIFY NAMESPACE layout (NVMe base spec §5.15.2.2):
///   - bytes 0..7   : NSZE (Namespace Size, in LBAs)
///   - byte  26     : FLBAS (Formatted LBA Size). Bits[3:0] index
///     into LBAF[].
///   - bytes 128.. : LBAF[0..16] @ 4 bytes each. LBAF.LBADS is at
///     byte offset 2 (relative to the LBAF start), low
///     byte = log2(LBA size in bytes).
///
/// # Safety
/// `buf` must be a 4 KiB coherent DMA buffer the controller has
/// finished writing to (CQE arrived).
unsafe fn parse_identify_namespace(buf: &DmaBuffer) -> (u64, u32) {
    let base = buf.phys_addr().raw() as *const u8;
    // SAFETY: 4 KiB DMA buffer.
    let nsze = unsafe { core::ptr::read_volatile(base as *const u64) };
    // SAFETY: same buffer.
    let flbas = unsafe { core::ptr::read_volatile(base.add(26)) };
    let lbaf_idx = (flbas & 0x0F) as usize;
    let lbaf_off = 128 + lbaf_idx * 4;
    // SAFETY: LBAF table fits well inside the 4 KiB page.
    let lbads = unsafe { core::ptr::read_volatile(base.add(lbaf_off + 2)) };
    let lba_bytes: u32 = if lbads == 0 { 512 } else { 1u32 << lbads };
    (nsze, lba_bytes)
}

/// Build a Security Send or Security Receive SQE.
///
/// CDW10 bits[31:24] = SECP, bits[23:8] = SPSP (NVMe Base 2.0c §5.25/§5.26).
/// CDW11 = TL / AL (transfer / allocation length in bytes).
///
/// Linux ref (GPL-2.0-or-later): drivers/nvme/host/core.c:nvme_sec_submit:
///   `cmd.common.cdw10 = cpu_to_le32(((u32)secp) << 24 | ((u32)spsp) << 8);`
///   `cmd.common.cdw11 = cpu_to_le32(len);`
#[inline]
fn build_security_sqe(opcode: u8, secp: u8, spsp: u16, len: u32, prp1: u64) -> Sqe {
    let mut sqe = Sqe::zero();
    sqe.cdw0 = opcode as u32;
    sqe.prp1 = prp1;
    sqe.cdw10 = ((secp as u32) << 24) | ((spsp as u32) << 8);
    sqe.cdw11 = len;
    sqe
}

/// Async `BlockDevice` adapter for the singleton NVMe controller.
///
/// Sibling of `NvmeBlockSync` — both reach into `CONTROLLER` (the
/// global `IrqSafeSpinLock<Option<Controller>>` populated by
/// `probe`); this one satisfies the async `block::BlockDevice`
/// contract that the VFS / filesystem stack consumes, while the
/// sync version is what early-boot smoke paths use.
///
/// I/O is dispatched through `read_lba` / `write_lba`, which
/// themselves go through the I/O queue created by
/// `create_io_queue` (polled) or `create_io_queue_msix`
/// (interrupt-driven). The queue is built once during `probe` and
/// shared across all `NvmeBlockDevice` instances, so this struct
/// has no per-instance state.
///
/// Single-PRP cap: each request must fit in one 4-KiB page (8
/// LBAs at 512 B/sector, 1 LBA at 4 KiB/sector). PRP-list support
/// for larger transfers lands when the filesystem layer starts
/// asking for >4 KiB I/Os.
#[derive(Debug, Default)]
pub struct NvmeBlockDevice;

impl BlockDevice for NvmeBlockDevice {
    fn logical_block_size(&self) -> u32 {
        with_controller(|c| c.lba_bytes).unwrap_or(512)
    }
    fn physical_block_size(&self) -> u32 {
        4096
    }
    fn capacity_blocks(&self) -> u64 {
        with_controller(|c| c.nsze).unwrap_or(0)
    }
    fn supports(&self, f: BlockFeature) -> bool {
        // Flush + Fua hit real NVMe opcodes (Flush 0x00, FUA bit in
        // Write CDW12). WriteZeroes / Discard advertise as
        // supported but the per-op code paths fall through to the
        // generic NVM-Write path until the dataset-management
        // opcodes are wired in (see the BlockOp arm below).
        matches!(
            f,
            BlockFeature::Flush
                | BlockFeature::WriteZeroes
                | BlockFeature::Discard
                | BlockFeature::Fua
        )
    }

    fn submit(&self, req: BlockRequest) -> impl Future<Output = BlockCompletion> + Send {
        // Resolve the cap → DmaBuffer up front. A revoked or stale
        // cap fails `check_live` inside `narf_io::resolve_cap`,
        // which short-circuits to `PermissionDenied` below.
        let buffer = narf_io::resolve_cap(&req.buffer);
        let result = nvme_submit_blocking(&req, buffer);
        async move {
            BlockCompletion {
                tag: 0,
                user_tag: req.user_tag,
                result,
            }
        }
    }
    async fn flush(&self) {
        // Wave-3a: the I/O-queue path is single-threaded behind the
        // installed slot's `req_gate` and every `read_lba` /
        // `write_lba` polls its own completion before returning.
        // There is therefore no
        // outstanding-write set to drain. When the multi-queue
        // submission path lands (Wave 3b), this becomes a real Flush
        // (admin opcode 0x00) on each I/O queue.
    }
    async fn discard(&self, _r: LbaRange) {
        // Dataset Management opcode 0x09 with AD=1 lands with the
        // larger-transfer rework; today the no-op is structurally
        // correct (NVMe permits ignoring DSM hints).
    }
    async fn cancel(&self, _tag: u64) -> CancelResult {
        // Polled completions are synchronous from the caller's POV,
        // so there is nothing to cancel by the time the future
        // suspends. Real cancel arrives with the queued submission
        // model.
        CancelResult::NotFound
    }
}

fn nvme_submit_blocking(
    req: &BlockRequest,
    buffer: Option<alloc::sync::Arc<DmaBuffer>>,
) -> Result<(), BlockError> {
    let buffer = buffer.ok_or(BlockError::PermissionDenied)?;
    let blocks = u16::try_from(req.blocks).map_err(|_| BlockError::InvalidRange)?;
    if blocks == 0 {
        return Ok(());
    }
    // Interrupts stay enabled for the whole transfer: hold the
    // device's request gate, not the IRQ-masking CONTROLLER lock.
    // See `InstalledController`.
    let mut ctrl = probed_controller().ok_or(BlockError::DeviceRemoved)?;
    let lba_bytes = ctrl.lba_bytes as usize;
    let total_bytes = (blocks as usize)
        .checked_mul(lba_bytes)
        .ok_or(BlockError::InvalidRange)?;
    if buffer.len() < total_bytes {
        return Err(BlockError::InvalidRange);
    }

    // Build a page list from the DmaBuffer's contiguous physical
    // memory. `alloc_coherent` returns physically-contiguous frames
    // (the frame allocator's contract), so we can compute page
    // addresses by stepping at PAGE_SIZE increments from the base.
    //
    // Single-page (≤ 4096 B): use read_lba / write_lba directly.
    // Multi-page (> 4096 B): decompose into PhysAddr slices and
    // use read_lba_pages / write_lba_pages (PRP1+PRP2 or PRP-list).
    let base_phys = buffer.phys_addr();
    let n_pages = total_bytes.div_ceil(PAGE_SIZE as usize);

    if n_pages == 1 {
        // Fast-path: single PRP, no allocation.
        match req.op {
            BlockOp::Read => ctrl
                .read_lba(req.lba, blocks, &buffer)
                .map_err(map_nvme_err),
            BlockOp::Write { fua: _ } | BlockOp::WriteZeroes => ctrl
                .write_lba(req.lba, blocks, &buffer)
                .map_err(map_nvme_err),
            BlockOp::Trim => Ok(()),
        }
    } else {
        // Multi-page: build a page-address Vec then dispatch through
        // the PRP-list path.
        // Cap at MAX_PRP_LIST_ENTRIES + 1 (PRP1 + 511 list entries).
        if n_pages > 512 {
            return Err(BlockError::InvalidRange);
        }
        let mut pages: Vec<PhysAddr> = Vec::with_capacity(n_pages);
        for i in 0..n_pages {
            pages.push(PhysAddr::new(base_phys.raw() + (i as u64) * PAGE_SIZE));
        }
        match req.op {
            BlockOp::Read => ctrl
                .read_lba_pages(req.lba, blocks, &pages)
                .map_err(map_nvme_err),
            BlockOp::Write { fua: _ } | BlockOp::WriteZeroes => ctrl
                .write_lba_pages(req.lba, blocks, &pages)
                .map_err(map_nvme_err),
            BlockOp::Trim => Ok(()),
        }
    }
}

fn map_nvme_err(e: NvmeError) -> BlockError {
    match e {
        NvmeError::OutOfRange => BlockError::InvalidRange,
        NvmeError::NotReady | NvmeError::NoIoQueue => BlockError::DeviceRemoved,
        _ => BlockError::IOError,
    }
}

// ── PCI driver-match registration ─────────────────────────────────────

use narf_lib::sync::IrqSafeSpinLock;

/// QEMU NVMe vendor / device IDs (Red Hat / NVMe controller).
pub const QEMU_NVME_VENDOR: u16 = 0x1B36;
pub const QEMU_NVME_DEVICE: u16 = 0x0010;

/// Samsung NVMe controllers. The Ryzen 7 PRO 8840HS reference
/// laptop ships with a Samsung PM9A1 / 980 PRO (`144D:A80A`); a
/// few other commonly-encountered Samsung consumer NVMe device
/// IDs are listed alongside so the driver binds without an
/// xtask-level match update for each new SKU.
pub const SAMSUNG_VENDOR: u16 = 0x144D;
/// PM9A1 / PM9A3 / 980 PRO — the modern Samsung NVMe family.
pub const SAMSUNG_PM9A1: u16 = 0xA80A;
/// 970 EVO / EVO Plus.
pub const SAMSUNG_970EVO: u16 = 0xA808;
/// 990 PRO.
pub const SAMSUNG_990PRO: u16 = 0xA80C;

/// Storage class — PCIe base-class 0x01 (mass storage). The NVMe
/// driver also matches by class so it picks up real-silicon NVMe
/// controllers whose vendor IDs we don't know ahead of time.
pub const PCI_CLASS_STORAGE: u8 = 0x01;
/// PCI subclass for NVM Express (§13.4 PCI Local Bus 3.0).
pub const PCI_SUBCLASS_NVM: u8 = 0x08;
/// PCI prog-if for NVMe (vs. AHCI / SATA / etc).
pub const PCI_PROGIF_NVME: u8 = 0x02;

/// Heap slot for the installed controller, leaked at install time.
///
/// Why a leaked slot instead of `IrqSafeSpinLock<Option<Controller>>`:
/// every NVMe I/O is a device round-trip — submit an SQE, then
/// busy-poll the CQ for up to 5 s (`wait_cqe`). Holding `CONTROLLER`
/// (an `IrqSafeSpinLock`) across that transfer masks interrupts on the
/// waiting CPU for the whole round-trip and forces every other CPU
/// doing I/O to spin on the same lock, also interrupts-masked. Under a
/// filesystem workload that starves timers and RCU and livelocks the
/// machine — the stall watchdog caught three CPUs `SPIN-NOT-POLLING`
/// on exactly this pattern in virtio-blk, and adding vCPUs makes it
/// worse (thundering herd, not a race).
///
/// The fix splits the two things the lock was serialising:
///  - *Finding* the controller: `CONTROLLER` is taken only long enough
///    to copy this slot's `&'static` reference out, then released.
///  - *Using* the controller: `req_gate`, a plain atomic spun on
///    WITHOUT masking interrupts, so timer ticks, RCU quiescent states
///    and the sleep pumps keep running while a CPU waits its turn.
///
/// The `UnsafeCell` is what makes handing out `&mut Controller` sound:
/// the slot reference is `&'static` (never moves, never drops — even a
/// kernel-test reinstall via [`install_controller`] leaks the old slot
/// rather than dropping it, so a stale reference can dangle only
/// logically, never point at freed memory), and `req_gate` guarantees
/// at most one `ControllerGuard` — hence at most one live `&mut` —
/// exists at a time.
struct InstalledController {
    /// Serialises device round-trips and all references into `ctrl`.
    /// Acquired by [`probed_controller`]; spun on with interrupts
    /// ENABLED.
    req_gate: AtomicBool,
    ctrl: UnsafeCell<Controller>,
}

// SAFETY: all access to `ctrl` goes through `req_gate` (see
// `probed_controller` — the only constructor of references into the
// cell), which admits one holder at a time; `Controller` itself is
// Send (asserted below), so migrating that exclusive access across
// CPUs is fine.
unsafe impl Sync for InstalledController {}

const _: () = {
    const fn assert_send<T: Send>() {}
    assert_send::<Controller>()
};

/// Slot pointer for the live controller produced by `probe`. Wave-3a
/// single-instance — multi-controller support arrives with a real
/// driver-handle table.
///
/// Held only long enough to copy the `&'static` slot reference out —
/// NEVER across a device round-trip. See [`InstalledController`].
static CONTROLLER: IrqSafeSpinLock<Option<&'static InstalledController>> =
    IrqSafeSpinLock::new(None);

/// Install `ctrl` as the live controller, replacing (and leaking) any
/// previous slot.
///
/// The old slot is deliberately leaked, not dropped: a concurrent I/O
/// path may still hold a `ControllerGuard` against it, and freeing the
/// allocation under that guard would be a use-after-free reachable
/// only under load. Leaking keeps every outstanding reference valid
/// forever. Outside the kernel-test harness this is called exactly
/// once per boot (probe early-returns when a controller exists), so
/// nothing accumulates; the harness's reinstall path
/// (`smoke_nvme_block_device_async_round_trip`) leaks one dead
/// controller per run, which is bounded and intentional.
pub(crate) fn install_controller(ctrl: Controller) {
    let slot: &'static InstalledController =
        alloc::boxed::Box::leak(alloc::boxed::Box::new(InstalledController {
            req_gate: AtomicBool::new(false),
            ctrl: UnsafeCell::new(ctrl),
        }));
    *CONTROLLER.lock() = Some(slot);
}

/// Exclusive handle to the installed controller for one device
/// round-trip. Holds the slot's `req_gate`, NOT the `CONTROLLER`
/// spinlock — interrupts stay enabled for the whole transfer.
pub struct ControllerGuard {
    slot: &'static InstalledController,
}

impl core::fmt::Debug for ControllerGuard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ControllerGuard").finish_non_exhaustive()
    }
}

impl core::ops::Deref for ControllerGuard {
    type Target = Controller;
    fn deref(&self) -> &Controller {
        // SAFETY: `req_gate` is held (only `probed_controller` builds a
        // guard, and it acquires the gate first), so no other reference
        // into the cell exists; the slot itself is `&'static` and never
        // freed.
        unsafe { &*self.slot.ctrl.get() }
    }
}

impl core::ops::DerefMut for ControllerGuard {
    fn deref_mut(&mut self) -> &mut Controller {
        // SAFETY: as in `deref` — the gate makes this the sole
        // reference into the cell.
        unsafe { &mut *self.slot.ctrl.get() }
    }
}

impl Drop for ControllerGuard {
    fn drop(&mut self) {
        self.slot.req_gate.store(false, Ordering::Release);
    }
}

/// Acquire exclusive access to the probed controller WITHOUT holding
/// `CONTROLLER` for the caller's use of it.
///
/// `CONTROLLER` is taken only long enough to copy the slot reference,
/// then released; the wait for our turn happens on the slot's
/// `req_gate` with interrupts ENABLED, so a CPU parked here still
/// takes timer ticks and reaches RCU quiescent states while another
/// CPU's 5-second-budget completion poll runs.
///
/// `smoke_nvme_controller_slot_is_stable` pins the address-stability
/// invariant this relies on: a repeat probe must not move or replace
/// the installed slot.
fn probed_controller() -> Option<ControllerGuard> {
    let slot = (*CONTROLLER.lock())?;
    while slot
        .req_gate
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    Some(ControllerGuard { slot })
}

/// The installed slot's address, or `None` before probe. Test hook for
/// the install-once invariant `probed_controller` relies on.
#[doc(hidden)]
pub fn dbg_slot_addr() -> Option<usize> {
    (*CONTROLLER.lock()).map(|s| s as *const InstalledController as usize)
}

// ── BlockDeviceSync adapter (registry/lib.rs) ─────────────────────────

/// Sync wrapper that lets the kernel's block registry address NVMe
/// uniformly with virtio-blk-pci + AHCI. Wraps the singleton
/// CONTROLLER static; reads / writes go through the polled
/// `read_lba` / `write_lba` paths today.
#[derive(Debug)]
pub struct NvmeBlockSync;

/// Persistent DMA scratch shared by NvmeBlockSync::read + write.
/// Both paths hold the installed controller's `req_gate` (via
/// [`probed_controller`]) for the whole transfer, so a single 4 KiB
/// buffer is safe to share — the gate, not this lock, serialises the
/// CONTENTS. This lock covers only the lazy init and the pointer
/// read; it is never held across a device round-trip (holding an
/// IRQ-masking spinlock across the CQ poll is the livelock the gate
/// exists to prevent — see `InstalledController`).
///
/// The buffer is leaked on first use so the returned `&'static` can
/// outlive the lock. Pre-fix every read/write call did
/// `alloc_coherent(4096)` and dropped the result at function-end —
/// under AMD-Vi the freed page could be reused while the controller
/// still had a delayed DMA write in flight (audit #2).
static NVME_SCRATCH_BUF: IrqSafeSpinLock<Option<&'static DmaBuffer>> = IrqSafeSpinLock::new(None);

fn nvme_scratch() -> Option<&'static DmaBuffer> {
    let mut g = NVME_SCRATCH_BUF.lock();
    if g.is_none() {
        *g = alloc_coherent(4096, DomainId::DRIVER_0)
            .ok()
            .map(|b| &*alloc::boxed::Box::leak(alloc::boxed::Box::new(b)));
    }
    *g
}

impl narf_block::BlockDeviceSync for NvmeBlockSync {
    fn lba_size(&self) -> u32 {
        with_controller(|c| c.lba_bytes).unwrap_or(512)
    }
    fn capacity(&self) -> u64 {
        with_controller(|c| c.nsze).unwrap_or(0)
    }
    fn read(
        &self,
        lba: u64,
        n_blocks: u16,
        out: &mut [u8],
    ) -> Result<(), narf_block::BlockIoError> {
        let need = (n_blocks as usize) * 512;
        if out.len() < need {
            return Err(narf_block::BlockIoError::BufferTooSmall);
        }
        if need > 4096 {
            return Err(narf_block::BlockIoError::BufferTooSmall);
        }
        // Interrupts stay enabled for the whole transfer: hold the
        // device's request gate, not the IRQ-masking CONTROLLER lock.
        // The gate is what serialises the shared scratch, so acquire
        // it BEFORE touching the buffer (audit #2 keeps the scratch
        // persistent so a delayed device DMA can never land in a
        // recycled page).
        let mut ctrl = probed_controller().ok_or(narf_block::BlockIoError::DeviceRemoved)?;
        let buf = nvme_scratch().ok_or(narf_block::BlockIoError::DriverError)?;
        let phys = buf.phys_addr().raw();
        ctrl.read_lba(lba, n_blocks, buf)
            .map_err(|_| narf_block::BlockIoError::DriverError)?;
        // The CQ poll inside `read_lba` is what makes the device's
        // writes visible; fence so the compiler cannot hoist this bulk
        // copy above it.
        compiler_fence(Ordering::Acquire);
        // SAFETY: `phys` is the identity-mapped 4 KiB scratch DMA page
        // the controller just filled; `need` ≤ 4096 (checked above) and
        // `out` is a kernel slice that cannot overlap the DMA page.
        // Bulk copy rather than a per-byte volatile loop: the payload
        // is coherent DMA memory, not MMIO, and per-byte volatility
        // defeats vectorisation on the hottest path in the system.
        unsafe {
            core::ptr::copy_nonoverlapping(
                narf_memory::PhysAddr::new(phys).kernel_ptr::<u8>(),
                out.as_mut_ptr(),
                need,
            );
        }
        Ok(())
    }
    fn write(&self, lba: u64, n_blocks: u16, data: &[u8]) -> Result<(), narf_block::BlockIoError> {
        let need = (n_blocks as usize) * 512;
        if data.len() < need {
            return Err(narf_block::BlockIoError::BufferTooSmall);
        }
        if need > 4096 {
            return Err(narf_block::BlockIoError::BufferTooSmall);
        }
        // Same shape as `read` above: gate first (it owns the scratch
        // contents), no IRQ-masking lock across the transfer.
        let mut ctrl = probed_controller().ok_or(narf_block::BlockIoError::DeviceRemoved)?;
        let buf = nvme_scratch().ok_or(narf_block::BlockIoError::DriverError)?;
        let phys = buf.phys_addr().raw();
        // SAFETY: `phys` is the identity-mapped 4 KiB scratch DMA page;
        // `need` ≤ 4096 (checked above) and `data` is a kernel slice
        // that cannot overlap the DMA page. Bulk copy rather than a
        // per-byte volatile loop — see `read`.
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), phys as *mut u8, need);
        }
        // Publish the payload before `write_lba` posts the SQE +
        // doorbell that lets the device DMA-read it.
        compiler_fence(Ordering::Release);
        ctrl.write_lba(lba, n_blocks, buf)
            .map_err(|_| narf_block::BlockIoError::DriverError)?;
        Ok(())
    }
}

/// Probe entry point dispatched by `bus::probe_all_pci`. Brings the
/// NVMe controller online (admin queue + IDENTIFY + I/O queue) and
/// stashes it in `CONTROLLER`. Returns `BadDevice` on bring-up
/// failure — caller logs + continues with the next device.
///
/// Idempotent: re-probing a device that's already set up just
/// returns `Ok(())`. The kernel-test harness re-runs probe_all
/// across smokes; resetting + re-bringing-up an already-running
/// NVMe controller risks crossing CC.EN=0/1 state with queues held
/// by the prior smoke (e.g. MSI-X-configured I/O queues are easier
/// to leave alone than rewire). Once Stage-4 wires unbind +
/// hot-plug, this guard goes away.
pub fn probe(
    device: narf_bus::BusDevice,
    cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
) -> Result<(), narf_bus::ProbeError> {
    // The class-match backstop catches every PCI mass-storage
    // device. Reject non-NVMe (subclass != 0x08 or prog_if !=
    // 0x02) so AHCI / virtio-blk silicon doesn't get driven through
    // the NVMe register layout. Skip the gate when the device
    // arrived via an explicit VendorDevice match (vid/did are
    // pre-validated): if class==0x00 the device didn't report a
    // standard class triple and we trust the explicit match.
    let class = ((device.id.class >> 16) & 0xFF) as u8;
    let subclass = ((device.id.class >> 8) & 0xFF) as u8;
    let prog_if = (device.id.class & 0xFF) as u8;
    if class == PCI_CLASS_STORAGE && (subclass != PCI_SUBCLASS_NVM || prog_if != PCI_PROGIF_NVME) {
        return Err(narf_bus::ProbeError::BadDevice);
    }
    if CONTROLLER.lock().is_some() {
        // Already brought up — make sure the param slot still has
        // something installed (test harness may have cleared it).
        if !PARAMS.is_installed() {
            PARAMS.install(NvmeParams {
                log_level: LogLevel::Info,
            });
        }
        return Ok(());
    }
    let mut ctrl = Controller::from_device(device);
    if ctrl.bring_up(&cap).is_err() {
        return Err(narf_bus::ProbeError::BadDevice);
    }
    if ctrl.create_io_queue().is_err() {
        return Err(narf_bus::ProbeError::BadDevice);
    }
    install_controller(ctrl);
    // Install the typed parameter surface so observers + tuners can
    // reach the driver via `Cap<DriverHandle, Write>`.
    PARAMS.install(NvmeParams {
        log_level: LogLevel::Info,
    });
    // Register against the unified block-device registry so the
    // kernel can address NVMe uniformly with other storage drivers.
    let parent: alloc::sync::Arc<dyn narf_block::BlockDeviceSync> =
        alloc::sync::Arc::new(NvmeBlockSync);
    narf_block::register_block_device("nvme0", parent.clone());
    // Read LBA 0/1, parse the partition table, and register a child
    // BlockDeviceSync for each non-empty partition entry under names
    // like "nvme0p1", "nvme0p2", ... Errors here are non-fatal —
    // an unpartitioned / unformatted device still has its parent
    // registered above; the partition scan just logs what failed.
    match narf_block::partition::scan_and_register_partitions(parent, "nvme0") {
        Ok(_report) => {
            // Partition layout discovered; child devices in registry.
            // (Boot log entry is the registry contents itself.)
        }
        Err(_e) => {
            // Disk is unpartitioned or the parser couldn't decode it.
            // `nvme0` (the parent) remains usable for whole-device I/O.
        }
    }
    // Record the bind in the framework's bound-driver inventory.
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("nvme0"),
        kind: narf_drivers::BoundKind::Block,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Block.default_domain(),
    });
    // Register against the device PM registry. NVMe suspend stops
    // the controller via CC.EN=0 (admin + I/O queues quiesce);
    // resume re-enables CC.EN and waits for CSTS.RDY=1.
    narf_power::device_pm::register_device_pm("nvme0", nvme_suspend_handler, nvme_resume_handler);
    Ok(())
}

/// NVMe suspend handler — clears CC.EN so the controller stops
/// fetching from the admin/IO submission queues. The queues
/// themselves stay in DRAM; resume re-enables CC.EN.
fn nvme_suspend_handler() -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    if !is_probed() {
        return Ok(());
    }
    let ok = with_controller(|c| {
        // SAFETY: caller-asserted BAR exclusivity.
        unsafe { c.disable_for_suspend() }
    })
    .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(narf_power::device_pm::DeviceSuspendError::DriverError)
    }
}

/// NVMe resume handler — re-asserts CC.EN and polls CSTS.RDY.
fn nvme_resume_handler() -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    if !is_probed() {
        return Ok(());
    }
    let ok = with_controller(|c| {
        // SAFETY: same.
        unsafe { c.enable_for_resume() }
    })
    .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(narf_power::device_pm::DeviceSuspendError::DriverError)
    }
}

/// Read-only accessor for the probed controller. Returns `true` iff
/// `probe` has run successfully.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Run `f` against the probed controller, if any. The closure
/// receives `&Controller` for read-only inspection (capacity, model,
/// etc.); `&mut` access for I/O is reserved for a Wave-3b API that
/// threads the cap through.
///
/// Serialises on the slot's `req_gate` (not the `CONTROLLER` lock):
/// the reference handed to `f` must not alias a live I/O path's
/// `&mut Controller`, and the gate is what excludes those. Callers
/// must not re-enter `with_controller` / `probed_controller` from
/// inside `f` — the gate is not reentrant.
pub fn with_controller<R>(f: impl FnOnce(&Controller) -> R) -> Option<R> {
    let g = probed_controller()?;
    Some(f(&g))
}

// ── Typed parameter surface ───────────────────────────────────────────
//
// What an observer can read about the driver post-probe + what tunables
// a writer can flip. Wave-3a ships a small cut: read-only IDENTIFY
// fields + I/O-queue topology, plus a single `LogLevel` writer knob
// that drivers will route through `tracing/` once that surface is
// usable from drivers. The shape demonstrates the typed-Rust contract
// without rope-pulling the entire NVMe spec.

/// Diagnostic verbosity for the NVMe driver. Mirrors the standard
/// `Off / Error / Warn / Info / Debug` ladder. Persisted in
/// `NvmeParams::log_level`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
}

/// Read-side snapshot. Cap-gated read returns a copy of these fields
/// taken under the param slot's lock.
#[derive(Copy, Clone, Debug)]
pub struct NvmeSnapshot {
    pub bar0: u64,
    pub lba_bytes: u32,
    pub nsze: u64,
    pub io_q_depth: u16,
    pub irq_vector: Option<u8>,
    pub log_level: LogLevel,
    pub identify_vid: u16,
}

/// Write-side update. One enum variant per knob — callers don't have
/// to provide values for every field.
#[derive(Copy, Clone, Debug)]
pub enum NvmeUpdate {
    /// Change the diagnostic log level.
    SetLogLevel(LogLevel),
}

/// Live params instance. Stores the tunables that aren't kept on the
/// `Controller` itself (because they're pure host-side state — the
/// device doesn't see them).
#[derive(Debug)]
pub struct NvmeParams {
    log_level: LogLevel,
}

impl narf_drivers::DriverParams for NvmeParams {
    type Snapshot = NvmeSnapshot;
    type Update = NvmeUpdate;

    fn snapshot(&self) -> NvmeSnapshot {
        // Pull controller-side fields from the live Controller, if
        // any. If the slot exists but the controller doesn't (a
        // pre-probe install path), the snapshot reports the host-
        // side defaults and zero device fields. Goes through the
        // gate-holding accessor so this `&Controller` cannot alias
        // an I/O path's `&mut`.
        let (bar0, lba_bytes, nsze, irq, vid) = with_controller(|c| {
            (
                c.bar0,
                c.lba_bytes,
                c.nsze,
                c.irq_vector,
                c.identify().map(|i| i.vid).unwrap_or(0),
            )
        })
        .unwrap_or((0, 0, 0, None, 0));
        NvmeSnapshot {
            bar0,
            lba_bytes,
            nsze,
            io_q_depth: IO_Q_DEPTH,
            irq_vector: irq,
            log_level: self.log_level,
            identify_vid: vid,
        }
    }

    fn apply(&mut self, u: NvmeUpdate) -> Result<(), narf_drivers::ParamError> {
        match u {
            NvmeUpdate::SetLogLevel(l) => {
                self.log_level = l;
                Ok(())
            }
        }
    }
}

/// Per-driver param slot. Drivers expose a `Cap<DriverHandle, Write>`-
/// gated read/write surface through this static.
pub static PARAMS: narf_drivers::ParamSlot<NvmeParams> = narf_drivers::ParamSlot::new();

/// Register the NVMe driver with the bus-level match table. Trusted
/// in-tree drivers call this from `frame::_start_rust` (or the
/// kernel-test harness) before invoking `bus::probe_all_pci`.
///
/// Registration shape:
/// - Explicit `(vendor, device)` matches for QEMU + Samsung
///   (PM9A1 / 970 EVO / 990 PRO) so those bind at full
///   specificity (the bus tie-breaker prefers VendorDevice).
/// - A `MatchKind::Class { 0x01 }` backstop binds any PCI mass-
///   storage controller; `probe` then filters by subclass+prog_if
///   so only true NVMe (`01:08:02`) silicon gets driven.
pub fn register_pci_driver() {
    let exact: &[(&'static str, u16, u16)] = &[
        ("nvme-qemu", QEMU_NVME_VENDOR, QEMU_NVME_DEVICE),
        ("nvme-samsung-pm9a1", SAMSUNG_VENDOR, SAMSUNG_PM9A1),
        ("nvme-samsung-970", SAMSUNG_VENDOR, SAMSUNG_970EVO),
        ("nvme-samsung-990", SAMSUNG_VENDOR, SAMSUNG_990PRO),
    ];
    for (name, v, d) in exact.iter().copied() {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name,
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: v,
                device: d,
            },
            probe,
        });
    }
    // Class-match backstop pinned to NVMe's exact class triple
    // (01:08:02). Switching from MatchKind::Class — which matches
    // every PCI mass-storage device and forces probe to gate on
    // subclass+prog_if — to MatchKind::ClassFull so virtio-blk +
    // AHCI silicon never even reaches our probe fn (and the boot
    // probe-trace doesn't surface spurious BadDevice rejections
    // from those non-NVMe storage devices).
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "nvme-class",
        kind: narf_bus::MatchKind::ClassFull {
            class: PCI_CLASS_STORAGE,
            subclass: PCI_SUBCLASS_NVM,
            prog_if: PCI_PROGIF_NVME,
        },
        probe,
    });
}

/// Stage::Subsys initcalls for this driver crate.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "nvme", || {
        register_pci_driver();
        InitResult::Ok
    });
}
