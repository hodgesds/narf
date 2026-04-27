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

use core::future::Future;

use narf_block::{
    BlockCompletion, BlockDevice, BlockError, BlockFeature, BlockRequest,
    CancelResult, LbaRange,
};
use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
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
    IdentifyFailed { status: u16 },
    /// The completion queue phase tag never flipped within our poll.
    CompletionTimeout,
}

// ── Register offsets (NVMe base spec §3.1) ──────────────────────────

/// BAR0-relative register offsets. Values are stable per the spec.
#[non_exhaustive]
#[repr(u64)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NvmeRegister {
    Cap    = 0x00,   // Controller Capabilities (64-bit)
    Vs     = 0x08,   // Version
    Intms  = 0x0C,   // Interrupt Mask Set
    Intmc  = 0x10,   // Interrupt Mask Clear
    Cc     = 0x14,   // Controller Config
    Csts   = 0x1C,   // Controller Status
    Aqa    = 0x24,   // Admin Queue Attributes
    Asq    = 0x28,   // Admin Submission Queue Base Address (64-bit)
    Acq    = 0x30,   // Admin Completion Queue Base Address (64-bit)
}

const REG_CAP_LO: u64 = 0x00;
const REG_CAP_HI: u64 = 0x04;
const REG_VS:     u64 = 0x08;
const REG_CC:     u64 = 0x14;
const REG_CSTS:   u64 = 0x1C;
const REG_AQA:    u64 = 0x24;
const REG_ASQ_LO: u64 = 0x28;
const REG_ASQ_HI: u64 = 0x2C;
const REG_ACQ_LO: u64 = 0x30;
const REG_ACQ_HI: u64 = 0x34;
/// Doorbell base — first SQ tail at 0x1000, then alternating SQ tails
/// and CQ heads at stride `4 << CAP.DSTRD`.
const REG_DOORBELL_BASE: u64 = 0x1000;

/// CC bits we set during bring-up.
const CC_EN:        u32 = 1 << 0;
const CC_CSS_NVM:   u32 = 0 << 4;
const CC_MPS_4K:    u32 = 0 << 7;
const CC_AMS_RR:    u32 = 0 << 11;
const CC_IOSQES_64: u32 = 6 << 16;
const CC_IOCQES_16: u32 = 4 << 20;

/// CSTS bits.
const CSTS_RDY: u32 = 1 << 0;
const CSTS_CFS: u32 = 1 << 1;

/// Decoded CAP register bitfields.
#[derive(Copy, Clone, Debug)]
pub struct NvmeCaps {
    /// Maximum queue entries supported (CAP.MQES).
    pub mqes:      u16,
    /// Doorbell-stride exponent (CAP.DSTRD).
    pub dstrd:     u8,
    /// Memory-page-size minimum (2^(12+MPSMIN)).
    pub mpsmin:    u8,
    /// Memory-page-size maximum.
    pub mpsmax:    u8,
}

impl NvmeCaps {
    /// Decode a 64-bit CAP register read.
    #[inline]
    pub const fn from_raw(r: u64) -> Self {
        Self {
            mqes:    (r & 0xFFFF) as u16,
            dstrd:   ((r >> 32) & 0xF) as u8,
            mpsmin:  ((r >> 48) & 0xF) as u8,
            mpsmax:  ((r >> 52) & 0xF) as u8,
        }
    }

    /// Required per-queue doorbell stride in bytes: `4 << DSTRD`.
    #[inline]
    pub const fn doorbell_stride(&self) -> u64 { 4u64 << self.dstrd }
}

// ── Opcodes (NVMe base spec §5 Admin + NVM Command Sets) ────────────

#[non_exhaustive]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AdminOpcode {
    DeleteSq            = 0x00,
    CreateSq            = 0x01,
    GetLogPage          = 0x02,
    DeleteCq            = 0x04,
    CreateCq            = 0x05,
    Identify            = 0x06,
    Abort               = 0x08,
    SetFeatures         = 0x09,
    GetFeatures         = 0x0A,
    AsyncEventRequest   = 0x0C,
}

#[non_exhaustive]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IoOpcode {
    Flush       = 0x00,
    Write       = 0x01,
    Read        = 0x02,
    WriteZeroes = 0x08,
    DatasetMgmt = 0x09,  // for TRIM
}

// ── Submission Queue Entry (64 bytes) + Completion Queue Entry (16) ─

/// NVMe Submission Queue Entry. Layout per base spec §4.2: 64 bytes,
/// naturally laid out in little-endian. Only the fields we actually
/// program are named; the rest stay zero.
#[repr(C)]
#[derive(Copy, Clone)]
struct Sqe {
    cdw0:   u32,    // opcode + fuse + cid
    nsid:   u32,
    _resv:  [u32; 2],
    mptr:   u64,
    prp1:   u64,
    prp2:   u64,
    cdw10:  u32,
    cdw11:  u32,
    cdw12:  u32,
    cdw13:  u32,
    cdw14:  u32,
    cdw15:  u32,
}

const _: () = assert!(core::mem::size_of::<Sqe>() == 64);

impl Sqe {
    const fn zero() -> Self {
        Self {
            cdw0: 0, nsid: 0, _resv: [0, 0], mptr: 0,
            prp1: 0, prp2: 0,
            cdw10: 0, cdw11: 0, cdw12: 0, cdw13: 0, cdw14: 0, cdw15: 0,
        }
    }
}

/// NVMe Completion Queue Entry. Layout per base spec §4.6: 16 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct Cqe {
    cmd_specific: u32,
    _resv:        u32,
    sq_head:      u16,
    sq_id:        u16,
    cid:          u16,
    /// Bit 0 = phase tag; bits 1..15 = NVMe status field
    /// (`SCT << 8 | SC` plus `M` and `DNR` bits at the top).
    status:       u16,
}

const _: () = assert!(core::mem::size_of::<Cqe>() == 16);

// ── Controller ──────────────────────────────────────────────────────

/// Admin queue depth — small enough to fit alongside the CQ in a
/// single 4 KiB DMA page, large enough to keep IDENTIFY + a couple of
/// in-flight admin commands. The doorbell-write protocol enforces a
/// "queue not full" invariant when (head + 1) mod N == tail.
const ADMIN_Q_DEPTH: u16 = 4;

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
    pub bar0:     u64,
    pub caps:     Option<NvmeCaps>,
    /// `Some` once the caller has handed us a real BusDevice;
    /// `bring_up` requires it.
    device:       Option<BusDevice>,
    /// Set after a successful `bring_up`. Holds the live admin-queue
    /// state so subsequent admin commands can reuse it.
    admin:        Option<AdminQueue>,
    /// Live BAR0 mapping post-bring-up. Stored so admin commands
    /// don't have to re-map (which writes to cfg-space).
    bar0_region:  Option<MmioRegion>,
    /// Identify-controller response, copied out of the DMA buffer
    /// after the IDENTIFY admin command completes.
    identify:     Option<IdentifyController>,
}

impl core::fmt::Debug for Controller {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Controller")
            .field("bar0",     &format_args!("{:#x}", self.bar0))
            .field("caps",     &self.caps)
            .field("ready",    &self.admin.is_some())
            .field("identify", &self.identify)
            .finish()
    }
}

/// Admin queue state tracked across commands. The DMA buffers are
/// kept here so they live as long as the queue does — dropping them
/// would unbind the physical pages from under the controller.
#[derive(Debug)]
struct AdminQueue {
    sq_buf:     DmaBuffer,
    cq_buf:     DmaBuffer,
    sq_tail:    u16,
    cq_head:    u16,
    /// Phase tag we expect on the next CQ entry. Flips every time the
    /// CQ wraps.
    cq_phase:   u16,
    /// Per-queue doorbell stride from CAP.DSTRD: `4 << DSTRD`.
    db_stride:  u64,
    /// Next admin command id to assign (monotonic, wraps at u16).
    next_cid:   u16,
}

/// Subset of the IDENTIFY CONTROLLER page we currently parse.
/// Layout per NVMe base spec §5.15.2.1.
#[derive(Copy, Clone, Debug)]
pub struct IdentifyController {
    pub vid:    u16,
    pub ssvid:  u16,
    /// Serial number, ASCII, 20 bytes, space-padded.
    pub sn:     [u8; 20],
    /// Model number, ASCII, 40 bytes, space-padded.
    pub mn:     [u8; 40],
    /// Firmware revision, ASCII, 8 bytes, space-padded.
    pub fr:     [u8; 8],
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
            bar0_region: None,
            identify: None,
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
    pub fn is_ready(&self) -> bool { self.admin.is_some() }

    /// IDENTIFY CONTROLLER snapshot, populated by `bring_up`.
    pub fn identify(&self) -> Option<&IdentifyController> { self.identify.as_ref() }

    /// Skeleton probe — returns `NotImplemented` when no `BusDevice`
    /// was supplied. Kept for backward compatibility with the
    /// pre-bring-up smoke; new callers go through `bring_up`.
    pub fn probe(
        &mut self,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<(), NvmeError> {
        if self.device.is_none() && self.bar0 == 0 { return Err(NvmeError::BadBar); }
        if self.device.is_none() { return Err(NvmeError::NotImplemented); }
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
    pub fn bring_up(
        &mut self,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<(), NvmeError> {
        let device = self.device.ok_or(NvmeError::BadBar)?;

        // ── 1. Map BAR0 + read CAP / VS ───────────────────────────
        // SAFETY: BSP, no other writer to this device's cfg window.
        let bar0 = unsafe { map_bar(&device, 0) }
            .map_err(|_| NvmeError::BadBar)?;
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
        if major < 1 { return Err(NvmeError::UnsupportedVersion); }

        self.bar0 = bar0.phys.raw();
        self.caps = Some(caps);

        // ── 2. Reset the controller ───────────────────────────────
        // Read-modify-write CC clearing EN.
        // SAFETY: CC is a normal RW register at a known offset.
        let cc = unsafe { bar0.read32(REG_CC) };
        // SAFETY: same window.
        unsafe { bar0.write32(REG_CC, cc & !CC_EN); }
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
        let aqa = ((ADMIN_Q_DEPTH as u32 - 1) & 0x0FFF)
                | (((ADMIN_Q_DEPTH as u32 - 1) & 0x0FFF) << 16);
        // SAFETY: register writes against an identity-mapped MMIO
        // BAR while the controller is disabled — the documented
        // window for programming admin-queue base addresses.
        unsafe {
            bar0.write32(REG_AQA,    aqa);
            bar0.write32(REG_ASQ_LO, sq_phys as u32);
            bar0.write32(REG_ASQ_HI, (sq_phys >> 32) as u32);
            bar0.write32(REG_ACQ_LO, cq_phys as u32);
            bar0.write32(REG_ACQ_HI, (cq_phys >> 32) as u32);
        }

        // ── 5. Re-enable the controller ───────────────────────────
        let cc = CC_EN | CC_CSS_NVM | CC_MPS_4K | CC_AMS_RR
               | CC_IOSQES_64 | CC_IOCQES_16;
        // SAFETY: same window.
        unsafe { bar0.write32(REG_CC, cc); }

        // ── 6. Wait for CSTS.RDY = 1 ──────────────────────────────
        wait_csts(&bar0, |s| (s & CSTS_RDY) != 0)?;

        let mut admin = AdminQueue {
            sq_buf,
            cq_buf,
            sq_tail:   0,
            cq_head:   0,
            cq_phase:  1,  // first valid CQE has phase = 1
            db_stride: caps.doorbell_stride(),
            next_cid:  0,
        };

        // ── 7. IDENTIFY CONTROLLER ────────────────────────────────
        let id_buf = alloc_coherent(4096, DomainId::DRIVER_0)
            .map_err(|_| NvmeError::OutOfDmaMemory)?;
        let id_phys = id_buf.phys_addr().raw();

        let cid = admin.next_cid;
        admin.next_cid = admin.next_cid.wrapping_add(1);

        let mut sqe = Sqe::zero();
        // CDW0: opcode (bits 7:0), CID (bits 31:16). FUSE/PSDT zero.
        sqe.cdw0  = (AdminOpcode::Identify as u32) | ((cid as u32) << 16);
        sqe.nsid  = 0;
        sqe.prp1  = id_phys;
        // CDW10: CNS = 1 (Identify Controller).
        sqe.cdw10 = 1;

        // SAFETY: the SQ DMA buffer is page-aligned and sized for
        // ADMIN_Q_DEPTH SQEs; `sq_tail` is bounded by the modulo
        // arithmetic below.
        unsafe { write_sqe(&admin.sq_buf, admin.sq_tail, &sqe); }
        admin.sq_tail = (admin.sq_tail + 1) % ADMIN_Q_DEPTH;

        // Ring SQ0 tail doorbell: BAR0 + 0x1000 + (2*0)*stride.
        let sq0_db = REG_DOORBELL_BASE + 0 * (2 * admin.db_stride);
        // SAFETY: identity-mapped MMIO doorbell.
        unsafe { bar0.write32(sq0_db, admin.sq_tail as u32); }

        // Poll CQ entry 0 for the phase flip.
        // SAFETY: cq_buf is a live DMA page sized for ADMIN_Q_DEPTH CQEs.
        let cqe = unsafe { wait_cqe(&admin.cq_buf, admin.cq_head, admin.cq_phase)? };
        // NVMe status field is in the upper 15 bits of CQE.status;
        // bit 0 is the phase tag.
        let nvme_status = cqe.status >> 1;
        if nvme_status != 0 {
            return Err(NvmeError::IdentifyFailed { status: nvme_status });
        }

        // Acknowledge the completion: bump head + ring CQ0 head doorbell.
        admin.cq_head = (admin.cq_head + 1) % ADMIN_Q_DEPTH;
        if admin.cq_head == 0 { admin.cq_phase ^= 1; }
        let cq0_db = REG_DOORBELL_BASE + (2 * 0 + 1) * admin.db_stride;
        // SAFETY: identity-mapped MMIO doorbell.
        unsafe { bar0.write32(cq0_db, admin.cq_head as u32); }

        // Parse IDENTIFY CONTROLLER (4 KiB page; only the first
        // 0x100 bytes are interesting for our subset).
        // SAFETY: id_buf is a live, identity-mapped DMA page.
        let id = unsafe { parse_identify(&id_buf) };
        self.identify = Some(id);
        self.admin    = Some(admin);
        self.bar0_region = Some(bar0);
        // id_buf drops here — IDENTIFY is one-shot, the controller
        // doesn't reference the buffer after the CQE arrives.
        let _ = id_buf;
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
        if (s & CSTS_CFS) != 0 { return Err(NvmeError::ControllerFatal); }
        if ok(s) { return Ok(()); }
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
    unsafe { core::ptr::write_volatile(base.add(index as usize), *sqe); }
}

/// Spin until CQ entry `index` has the expected phase tag, then
/// return it.
///
/// # Safety
/// `buf` must be a live coherent DMA buffer sized for
/// `ADMIN_Q_DEPTH * 16` bytes; `index < ADMIN_Q_DEPTH`.
unsafe fn wait_cqe(buf: &DmaBuffer, index: u16, expected_phase: u16)
    -> Result<Cqe, NvmeError>
{
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
    read_arr(4,   &mut sn);  // bytes 4..23   = SN
    read_arr(24,  &mut mn);  // bytes 24..63  = MN
    read_arr(64,  &mut fr);  // bytes 64..71  = FR
    IdentifyController {
        vid:   read_u16(0),
        ssvid: read_u16(2),
        sn,
        mn,
        fr,
    }
}

/// Stub `BlockDevice` impl. Every op returns `DeviceRemoved` —
/// structurally well-formed, body lands in the I/O-queue follow-up.
#[derive(Debug)]
pub struct NvmeBlockDevice(pub Controller);

impl BlockDevice for NvmeBlockDevice {
    fn logical_block_size(&self)  -> u32 { 512 }
    fn physical_block_size(&self) -> u32 { 4096 }
    fn capacity_blocks(&self)     -> u64 { 0 }
    fn supports(&self, f: BlockFeature) -> bool {
        matches!(f, BlockFeature::Flush | BlockFeature::WriteZeroes
                  | BlockFeature::Discard | BlockFeature::Fua)
    }

    fn submit(&self, req: BlockRequest)
        -> impl Future<Output = BlockCompletion>
    {
        async move {
            BlockCompletion {
                tag:      0,
                user_tag: req.user_tag,
                result:   Err(BlockError::DeviceRemoved),
            }
        }
    }
    fn flush(&self)                    -> impl Future<Output = ()> { async {} }
    fn discard(&self, _r: LbaRange)    -> impl Future<Output = ()> { async {} }
    fn cancel(&self, _tag: u64)        -> impl Future<Output = CancelResult> {
        async { CancelResult::NotFound }
    }
}
