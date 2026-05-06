//! narf-drivers-nvme — NVMe host driver.
//!
//! Spec: `drivers/nvme/specification/spec.md` + NVMe base spec rev 1.4
//! §3 (registers) and §5 (admin command set). Stage-4 cut now does the
//! whole admin-queue bring-up against a real PCIe NVMe controller:
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

use core::future::Future;

use narf_block::{
    BlockCompletion, BlockDevice, BlockError, BlockFeature, BlockRequest, CancelResult, LbaRange,
};
use narf_bus::{enable_msix, map_bar, BusDevice, BusDeviceCap, MmioRegion, MsixTable};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;

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
    /// Set after `create_io_queue` completes. Single I/O queue pair
    /// (qid=1) handles all read/write traffic — multi-queue lands
    /// once the executor is ready to schedule per-CPU completions.
    io: Option<Queue>,
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
    /// Live MSI-X table set up by `create_io_queue_msix`. The table
    /// stays alive (no `Drop` undoes the device-side enable) for the
    /// lifetime of the controller.
    msix: Option<MsixTable>,
    /// IDT vector allocated for I/O-queue completions, programmed
    /// into MSI-X table entry 0. Drivers `wait_for_irq(self.irq_vector
    /// .unwrap())` to await an I/O completion.
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
            io: None,
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
        sqe.cdw11 = 1; // PC=1, IEN=0 (polling), IV=0
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

        // Stash the new IoQueue. Drop replaces any prior one.
        self.io = Some(Queue {
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

    /// Create the I/O queue pair with MSI-X-driven completions.
    ///
    /// Walks the device's MSI-X capability, allocates an IDT vector
    /// from `narf_interrupts::vector`, programs MSI-X table entry 0
    /// to deliver that vector to the BSP, flips the global MSI-X
    /// enable bit, then issues Create I/O CQ (`IV=0, IEN=1`) +
    /// Create I/O SQ.
    ///
    /// Returns the allocated IDT vector. Subsequent `submit_io_irq`
    /// calls use `narf_interrupts::fire_count(vector)` (or, for
    /// async callers, `wait_for_irq(vector)`) to detect completion.
    pub fn create_io_queue_msix(
        &mut self,
        bus_dev_cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<u8, NvmeError> {
        let device = self.device.ok_or(NvmeError::NotReady)?;
        // 1. Walk the cap list + sniff the MSI-X table size.
        let mut msix = enable_msix(bus_dev_cap, &device).map_err(|_| NvmeError::Msix)?;

        // 2. Allocate IDT vector + MSI-X table slot 0.
        let v = narf_interrupts::vector::alloc().map_err(|_| NvmeError::Msix)?;
        let _ = msix.alloc_vector().ok_or(NvmeError::Msix)?;

        // 3. Program MSI-X table entry 0 to deliver vector `v` to
        //    APIC id 0 (the BSP). On aarch64 this routes through the
        //    GIC ITS doorbell with EventID=v.
        // SAFETY: caller holds the BusDeviceCap; we own the MSI-X
        // table (no other writer); we issue this write before
        // enabling so the device can't fire stale data.
        let _ = unsafe { msix.program_vector(0, 0, v) }.map_err(|_| NvmeError::Msix)?;

        // 4. Flip the global MSI-X enable bit.
        // SAFETY: cfg-space write to a known cap-list offset.
        let _ = unsafe { msix.enable() }.map_err(|_| NvmeError::Msix)?;

        self.msix = Some(msix);
        self.irq_vector = Some(v);

        // 5. Allocate IOSQ + IOCQ DMA pages. Same shape as the
        //    polling create_io_queue, but with IEN=1 + IV=0 on the CQ.
        let admin = self.admin.as_mut().ok_or(NvmeError::NotReady)?;
        let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;
        let sq_buf = alloc_coherent(64 * IO_Q_DEPTH as usize, DomainId::DRIVER_0)
            .map_err(|_| NvmeError::OutOfDmaMemory)?;
        let cq_buf = alloc_coherent(16 * IO_Q_DEPTH as usize, DomainId::DRIVER_0)
            .map_err(|_| NvmeError::OutOfDmaMemory)?;
        let sq_phys = sq_buf.phys_addr().raw();
        let cq_phys = cq_buf.phys_addr().raw();

        // Create I/O CQ: PC=1, IEN=1, IV=0.
        let mut sqe = Sqe::zero();
        sqe.cdw0 = AdminOpcode::CreateCq as u32;
        sqe.prp1 = cq_phys;
        sqe.cdw10 = ((IO_Q_DEPTH as u32 - 1) << 16) | (IO_QID as u32);
        sqe.cdw11 = (0u32 << 16) | (1 << 1) | 1; // IV=0, IEN=1, PC=1
                                                 // SAFETY: queue + bar live; CQ DMA fresh.
        unsafe {
            admin.submit(bar0, sqe)?;
        }

        // Create I/O SQ: PC=1, CQID=IO_QID, QPRIO=0.
        let mut sqe = Sqe::zero();
        sqe.cdw0 = AdminOpcode::CreateSq as u32;
        sqe.prp1 = sq_phys;
        sqe.cdw10 = ((IO_Q_DEPTH as u32 - 1) << 16) | (IO_QID as u32);
        sqe.cdw11 = ((IO_QID as u32) << 16) | 1;
        // SAFETY: queue + bar live.
        unsafe {
            admin.submit(bar0, sqe)?;
        }

        self.io = Some(Queue {
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

        Ok(v)
    }

    /// Submit an NVM Read/Write to the I/O queue and wait for
    /// MSI-X-delivered completion via `narf_interrupts::fire_count`.
    /// Caller decides between `read_lba` (polled) and this for
    /// IRQ-driven flows.
    ///
    /// Synchronous variant: spins on `fire_count` after submitting;
    /// the underlying mechanism is the same one `wait_for_irq.await`
    /// drives, just without an executor.
    pub fn submit_io_irq(
        &mut self,
        opcode: u8,
        lba: u64,
        n_blocks: u16,
        buf: &DmaBuffer,
    ) -> Result<(), NvmeError> {
        let v = self.irq_vector.ok_or(NvmeError::Msix)?;
        let io = self.io.as_mut().ok_or(NvmeError::NoIoQueue)?;
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
        // hot reset paths).
        let mut spins = 0u32;
        loop {
            if narf_interrupts::fire_count(v) > baseline {
                break;
            }
            // SAFETY: cq_buf is a live identity-mapped DMA page.
            let cqe = unsafe { peek_cqe(&io.cq_buf, io.cq_head) };
            if (cqe.status & 1) == (io.cq_phase & 1) {
                break;
            }
            spins += 1;
            if spins > 10_000_000 {
                return Err(NvmeError::CompletionTimeout);
            }
            core::hint::spin_loop();
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

    fn nvm_io(
        &mut self,
        opcode: u8,
        lba: u64,
        n_blocks: u16,
        buf: &DmaBuffer,
    ) -> Result<(), NvmeError> {
        let io = self.io.as_mut().ok_or(NvmeError::NoIoQueue)?;
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
}

// ── helpers ─────────────────────────────────────────────────────────

/// Bounded poll for a `CSTS` predicate. Loops up to ~1M MMIO reads,
/// returning `ControllerFailed` on timeout or `ControllerFatal` if
/// `CFS` is set during the wait.
fn wait_csts<F: Fn(u32) -> bool>(bar: &MmioRegion, ok: F) -> Result<(), NvmeError> {
    for _ in 0..1_000_000u32 {
        // SAFETY: identity-mapped MMIO, naturally aligned.
        let s = unsafe { bar.read32(REG_CSTS) };
        if (s & CSTS_CFS) != 0 {
            return Err(NvmeError::ControllerFatal);
        }
        if ok(s) {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(NvmeError::ControllerFailed)
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
    for _ in 0..10_000_000u32 {
        // SAFETY: caller guarantees buf is page-aligned and large
        // enough; index is bounded.
        let cqe = unsafe { core::ptr::read_volatile(base.add(index as usize)) };
        if (cqe.status & 1) == (expected_phase & 1) {
            return Ok(cqe);
        }
        core::hint::spin_loop();
    }
    Err(NvmeError::CompletionTimeout)
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
///                    into LBAF[].
///   - bytes 128.. : LBAF[0..16] @ 4 bytes each. LBAF.LBADS is at
///                    byte offset 2 (relative to the LBAF start), low
///                    byte = log2(LBA size in bytes).
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

/// Stub `BlockDevice` impl. Every op returns `DeviceRemoved` —
/// structurally well-formed, body lands in the I/O-queue follow-up.
#[derive(Debug)]
pub struct NvmeBlockDevice(pub Controller);

impl BlockDevice for NvmeBlockDevice {
    fn logical_block_size(&self) -> u32 {
        512
    }
    fn physical_block_size(&self) -> u32 {
        4096
    }
    fn capacity_blocks(&self) -> u64 {
        0
    }
    fn supports(&self, f: BlockFeature) -> bool {
        matches!(
            f,
            BlockFeature::Flush
                | BlockFeature::WriteZeroes
                | BlockFeature::Discard
                | BlockFeature::Fua
        )
    }

    fn submit(&self, req: BlockRequest) -> impl Future<Output = BlockCompletion> {
        async move {
            BlockCompletion {
                tag: 0,
                user_tag: req.user_tag,
                result: Err(BlockError::DeviceRemoved),
            }
        }
    }
    fn flush(&self) -> impl Future<Output = ()> {
        async {}
    }
    fn discard(&self, _r: LbaRange) -> impl Future<Output = ()> {
        async {}
    }
    fn cancel(&self, _tag: u64) -> impl Future<Output = CancelResult> {
        async { CancelResult::NotFound }
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

/// Slot for the live controller produced by `probe`. Wave-3a
/// single-instance — multi-controller support arrives with a real
/// driver-handle table.
static CONTROLLER: IrqSafeSpinLock<Option<Controller>> = IrqSafeSpinLock::new(None);

// ── BlockDeviceSync adapter (registry/lib.rs) ─────────────────────────

/// Sync wrapper that lets the kernel's block registry address NVMe
/// uniformly with virtio-blk-pci + AHCI. Wraps the singleton
/// CONTROLLER static; reads / writes go through the polled
/// `read_lba` / `write_lba` paths today.
#[derive(Debug)]
pub struct NvmeBlockSync;

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
        // Allocate a single 4 KiB DMA buffer for the transfer (NVMe
        // controllers happily handle one PRP1).
        let buf = match alloc_coherent(4096, DomainId::DRIVER_0) {
            Ok(b) => b,
            Err(_) => return Err(narf_block::BlockIoError::DriverError),
        };
        let phys = buf.phys_addr().raw();
        // Capped at 8 sectors for the single-PRP path.
        if need > 4096 {
            return Err(narf_block::BlockIoError::BufferTooSmall);
        }
        let mut g = CONTROLLER.lock();
        let ctrl = g.as_mut().ok_or(narf_block::BlockIoError::DeviceRemoved)?;
        ctrl.read_lba(lba, n_blocks, &buf)
            .map_err(|_| narf_block::BlockIoError::DriverError)?;
        // SAFETY: identity-mapped DMA buffer.
        for i in 0..need {
            out[i] = unsafe { core::ptr::read_volatile((phys + i as u64) as *const u8) };
        }
        let _ = buf;
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
        let buf = match alloc_coherent(4096, DomainId::DRIVER_0) {
            Ok(b) => b,
            Err(_) => return Err(narf_block::BlockIoError::DriverError),
        };
        let phys = buf.phys_addr().raw();
        // SAFETY: identity-mapped DMA.
        unsafe {
            for i in 0..need {
                core::ptr::write_volatile((phys + i as u64) as *mut u8, data[i]);
            }
        }
        let mut g = CONTROLLER.lock();
        let ctrl = g.as_mut().ok_or(narf_block::BlockIoError::DeviceRemoved)?;
        ctrl.write_lba(lba, n_blocks, &buf)
            .map_err(|_| narf_block::BlockIoError::DriverError)?;
        let _ = buf;
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
    *CONTROLLER.lock() = Some(ctrl);
    // Install the typed parameter surface so observers + tuners can
    // reach the driver via `Cap<DriverHandle, Write>`.
    PARAMS.install(NvmeParams {
        log_level: LogLevel::Info,
    });
    // Register against the unified block-device registry so the
    // kernel can address NVMe uniformly with other storage drivers.
    narf_block::register_block_device(
        "nvme0",
        alloc::sync::Arc::new(NvmeBlockSync) as alloc::sync::Arc<dyn narf_block::BlockDeviceSync>,
    );
    // Record the bind in the framework's bound-driver inventory.
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("nvme0"),
        kind: narf_drivers::BoundKind::Block,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Block.default_domain(),
    });
    Ok(())
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
pub fn with_controller<R>(f: impl FnOnce(&Controller) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
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
        // side defaults and zero device fields.
        let g = CONTROLLER.lock();
        let (bar0, lba_bytes, nsze, irq, vid) = match g.as_ref() {
            Some(c) => (
                c.bar0,
                c.lba_bytes,
                c.nsze,
                c.irq_vector,
                c.identify().map(|i| i.vid).unwrap_or(0),
            ),
            None => (0, 0, 0, None, 0),
        };
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
    // Class-match backstop. `probe` checks subclass + prog_if so
    // we don't accidentally claim SATA / virtio-blk controllers.
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "nvme-class",
        kind: narf_bus::MatchKind::Class {
            class: PCI_CLASS_STORAGE,
            mask: 0xFF,
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
