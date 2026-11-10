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

//! NVMe driver body. Compiled only for the built-in build; the crate root
//! (`lib.rs`) carries the dual-build wiring and re-exports this module's API.

pub mod admin;
pub mod chardev;
pub mod mi;
pub mod ns;
pub mod prp;
pub mod shutdown;

mod tests;
mod tests_cid;
mod tests_dsm;
mod tests_flush;
mod tests_gate;
mod tests_multi;
mod tests_retry;

use core::cell::UnsafeCell;
use core::future::Future;
use core::sync::atomic::{compiler_fence, AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

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
    /// `CAP.MPSMIN` asks for a memory page larger than the 4 KiB host
    /// page NARF programs into `CC.MPS` (Linux `nvme_enable_ctrl`
    /// refuses such a controller with `-ENODEV`).
    UnsupportedPageSize,
    /// The data buffer does not match the command: shorter than
    /// `n_blocks * lba_bytes`, not dword aligned, or zero length.
    BadTransfer,
    /// The transfer is larger than the controller's maximum data
    /// transfer size (Identify Controller MDTS, clamped to
    /// [`prp::NVME_HOST_MAX_TRANSFER`]). Callers split it.
    ExceedsMaxTransfer,
    /// A command timed out with its data buffers still owned by the
    /// controller. The queue state is no longer trusted and every
    /// later I/O is refused; the buffers it may still DMA into are
    /// never freed.
    ControllerDead,
    /// Reset/recovery re-identified the function and found a
    /// *different* controller (serial / model / vendor changed) than
    /// the one that was snapshotted before the reset — e.g. the
    /// device was hot-swapped while it was wedged. The recovered
    /// state was not trusted: the controller was stopped again and
    /// the slot is treated as removed (see
    /// [`Controller::reset_recover`]).
    IdentityChanged,
    /// The namespace's LBA format cannot be used for block I/O (LBA
    /// size outside 512..=4096 bytes, or per-block metadata).
    NamespaceUnusable,
    /// The controller's request gate did not come free: whoever holds it
    /// made no progress for [`GATE_STALL_FAIL_MS`] while this caller
    /// waited. The holder and the wait were logged; nothing was sent to
    /// the device for this caller. See [`acquire`].
    GateTimeout,
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
    /// Worst-case CSTS.RDY transition time in 500 ms units (CAP.TO,
    /// bits 31:24).
    pub to: u8,
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
            to: ((r >> 24) & 0xFF) as u8,
        }
    }

    /// CSTS.RDY transition budget in milliseconds. Linux
    /// `nvme_wait_ready` waits `(NVME_CAP_TIMEOUT(cap) + 1) * HZ / 2`;
    /// NARF keeps its former 5 s as a floor so a controller reporting
    /// TO = 0 is not given less time than before.
    #[inline]
    pub const fn ready_timeout_ms(&self) -> u64 {
        let linux = (self.to as u64 + 1) * 500;
        if linux < 5_000 {
            5_000
        } else {
            linux
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

/// Test hook: make the next [`Controller::bring_up`] fail its Identify
/// Controller command after CC.EN=1, as a controller that rejects or never
/// completes it would. Only the in-kernel smokes set it.
#[doc(hidden)]
pub static FAIL_IDENTIFY_FOR_TEST: AtomicBool = AtomicBool::new(false);
fn nvme_io_irq() {}

/// Test hook: the next N MSI-X entry programmings by
/// [`Controller::bring_up`] (admin entry 0) / [`Controller::create_io_queue`]
/// (I/O entry 1) fail, as `MsixTable::program_vector` does when the table
/// BAR cannot be mapped. Only the in-kernel smokes set it.
#[doc(hidden)]
pub static FAIL_MSIX_PROGRAM_FOR_TEST: AtomicU32 = AtomicU32::new(0);

/// The APIC ID this driver's MSI-X entries are steered to.
///
/// Every entry targets one CPU, as before: completions are consumed by
/// whichever CPU is waiting (the vector's global `fire_count`), so the
/// target only has to be a CPU that exists and takes interrupts. That CPU
/// is scheduler CPU 0, resolved to a real APIC ID through
/// `narf_interrupts::apic_id_of_cpu` (as `drivers/net/igc` does) instead of
/// the literal 0 the entries used to carry: scheduler CPU ids are APIC
/// IDs, so on a machine whose firmware lists an enabled CPU with APIC ID 0
/// the destination is unchanged, and on one that does not — where a
/// literal 0 addressed no CPU at all and every interrupt was lost — the
/// entries go to the CPU doing the bring-up. 0 when the topology is not
/// known (no MADT), as before.
fn msix_target_apic_id() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        narf_interrupts::apic_id_of_cpu(0)
            .or_else(|| narf_interrupts::apic_id_of_cpu(narf_lib::percpu::current_cpu()))
            .unwrap_or(0)
    }
    // No APIC: the argument is the ITS DeviceID, which this driver has
    // always passed as 0.
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
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

impl Cqe {
    /// Does this completion belong to the waiter for `cid` (NVMe
    /// base spec §4.6: the CQE's `cid` echoes the submission's
    /// CDW0 bits 16..31)? This one comparison is the whole of
    /// CID-matched completion tracking: a waiter owns exactly the
    /// CQE carrying its CID, never merely the next entry at the CQ
    /// head. The phase tag is checked separately by the caller —
    /// it says whether the entry is a fresh completion at all.
    #[inline]
    fn is_for(&self, cid: u16) -> bool {
        self.cid == cid
    }

    /// Sample a CQ slot the controller may be posting into right now.
    /// `word(i)` reads little-endian qword `i` of the 16-byte entry.
    ///
    /// The controller posts a completion while the host polls the slot, so
    /// the sample must never pair the new phase tag with fields of the
    /// slot's previous occupant. Qword 1 carries SQ head, SQ id, CID and
    /// status + phase tag: it is taken first and as ONE load, so a fresh
    /// phase tag always comes with the CID posted with it. Qword 0 (the
    /// command-specific result) is taken afterwards, when a fresh phase tag
    /// already seen means the whole entry is in place (Linux
    /// `nvme_cqe_pending` then `nvme_handle_cqe`: status first, the rest
    /// after).
    ///
    /// A field-by-field read of the entry loaded `cid` before `status`. A
    /// completion posted between the two loads then showed the previous
    /// occupant's CID under the new phase tag: the waiter took its own
    /// completion for a stray, consumed and dropped it, and timed out on a
    /// command that had completed.
    #[inline]
    fn sample(mut word: impl FnMut(usize) -> u64) -> Self {
        let hi = word(1);
        let lo = word(0);
        Self {
            cmd_specific: lo as u32,
            _resv: (lo >> 32) as u32,
            sq_head: hi as u16,
            sq_id: (hi >> 16) as u16,
            cid: (hi >> 32) as u16,
            status: (hi >> 48) as u16,
        }
    }
}

// ── Controller ──────────────────────────────────────────────────────

/// Admin queue depth — 8 entries: the SQ is 8 × 64 = 512 B and the CQ
/// 8 × 16 = 128 B, so each still fits in a single 4 KiB DMA page, and
/// the AER cap (`depth - 1` = 7) covers the NVMe Base Spec 2.0c §5.2
/// floor of AERL+1 ≥ 4 outstanding AERs while leaving one SQ slot
/// free for a non-AER admin command. The doorbell-write protocol
/// enforces a "queue not full" invariant when (head + 1) mod N == tail.
const ADMIN_Q_DEPTH: u16 = 8;

// Admin-queue arithmetic, pinned at compile time (#1618):
// - AQA encodes (depth - 1) in 12-bit fields (ASQS/ACQS), so depth ≤ 4096.
// - SQ (64 B/SQE) and CQ (16 B/CQE) each fit one 4 KiB DMA page.
// - The AER cap (depth - 1) covers the spec §5.2 floor of 4 AERs.
const _: () = assert!(ADMIN_Q_DEPTH <= 4096);
const _: () = assert!(ADMIN_Q_DEPTH as usize * 64 <= 4096);
const _: () = assert!(ADMIN_Q_DEPTH as usize * 16 <= 4096);
const _: () = assert!(ADMIN_Q_DEPTH > 4);

/// AERs posted at bring-up (#928): 3, leaving one admin SQ slot free
/// for a non-AER admin command (see [`Controller::post_aer_commands`]).
/// NVMe Base Spec 2.0c §5.2 recommends ≥4 outstanding; the admin
/// depth is 8 (#1618), so the queue could host 7 — the count stays
/// 3 because QEMU reports AERL=0 yet accepts only 3 and returns
/// "Cmd Limit Exceeded" on the 4th.
const AER_POST_COUNT: u8 = 3;

/// I/O queue depth — same constraint (single 4 KiB DMA page each).
/// Independent of the admin depth: only the admin queue needs the
/// AER headroom (§5.2), so the I/O depth stays at 4.
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

/// Namespace id the single-namespace helpers fall back to before a scan
/// found any namespace (I/O is then refused as `NamespaceUnusable`).
const DEFAULT_NSID: u32 = 1;

/// Pre-suspend identity of one controller, captured by
/// [`Controller::suspend_pm`] and consumed by [`Controller::resume_pm`].
///
/// Resume rebuilds the controller from scratch (the suspend teardown
/// destroys every queue), so the only thing tying the rebuilt controller
/// to the block devices registered at probe is this snapshot: if the
/// re-identified controller is not the one that was suspended — a disk
/// swapped while the machine slept — resume refuses rather than serving
/// a different disk under the old registrations.
#[derive(Clone, Debug)]
struct SuspendSnapshot {
    /// Identify Controller as read at suspend time.
    identify: IdentifyController,
    /// The registered namespace set as scanned at suspend time.
    namespaces: Vec<ns::NamespaceInfo>,
}

/// Whether a re-identified controller is the one a [`SuspendSnapshot`]
/// was taken from: drive identity (serial + model), namespace count and
/// the full registered-namespace set (NSID, size, LBA format,
/// EUI64/NGUID/UUID) must all be equal. The firmware revision is
/// deliberately NOT compared — it is the one identity field a
/// legitimate firmware update changes, and it names no data.
fn suspend_identity_matches(
    snap: &SuspendSnapshot,
    id: &IdentifyController,
    namespaces: &[ns::NamespaceInfo],
) -> bool {
    id.sn == snap.identify.sn
        && id.mn == snap.identify.mn
        && id.nn == snap.identify.nn
        && namespaces == snap.namespaces
}

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
    /// The admin queue's own IDT vector (MSI-X entry 0), allocated by
    /// `bring_up`. Kept apart from `irq_vector`, which the multi-queue
    /// setup repoints at the first I/O queue's vector: this is the one
    /// the AER supervisor parks on, and the one that must be released
    /// with the controller.
    admin_irq_vector: Option<u8>,
    /// Largest data transfer per command in bytes: Identify Controller
    /// MDTS in CAP.MPSMIN units, clamped to
    /// [`prp::NVME_HOST_MAX_TRANSFER`]. One page until `bring_up` has
    /// read Identify Controller.
    max_transfer: u32,
    /// False when the namespace's LBA format cannot carry block I/O
    /// (see [`prp::NamespaceFormat::usable`]).
    ns_usable: bool,
    /// Persistent PRP-list page for I/O transfers longer than two
    /// pages. Every I/O path holds `&mut Controller` until its CQE is
    /// consumed, so one page serves all of them, and it is never freed
    /// while the controller lives (a timed-out command may still read
    /// it — see `dead`).
    prp_list: Option<DmaBuffer>,
    /// Persistent one-page buffer holding the Dataset Management
    /// range list (at most [`DSM_MAX_RANGES`] 16-byte definitions =
    /// exactly one 4 KiB page) while a DSM command is in flight.
    /// Same lifetime discipline as `prp_list`: every DSM path holds
    /// `&mut self` until its CQE is consumed, and the page is never
    /// freed while the controller lives.
    dsm_page: Option<DmaBuffer>,
    /// Set when an I/O command timed out. The CQ head/phase no longer
    /// match the device and the command's buffers may still be DMA
    /// targets, so later I/O is refused with
    /// [`NvmeError::ControllerDead`].
    dead: bool,
    /// True while the controller is known to be disabled: never enabled,
    /// or CC.EN=0 with CSTS.RDY=0 confirmed by
    /// [`Controller::disable_after_failure`]. Cleared when bring-up
    /// writes CC.EN=1. A controller that is `dead` without this cannot be
    /// shown to have stopped DMA-ing ([`Controller::may_still_dma`]).
    stop_confirmed: bool,
    /// Set by [`Controller::suspend_pm`] once the controller has been
    /// quiesced (Flush + CC.SHN) and torn down for system suspend, and
    /// cleared by [`Controller::resume_pm`] after a full re-init and
    /// identity re-check. I/O is refused throughout the suspended
    /// window (`suspend_pm`'s teardown also leaves `dead` set); the
    /// flag exists so resume can tell a resumable teardown from a
    /// controller that merely died.
    suspended: bool,
    /// Identity captured at suspend, re-validated at resume (see
    /// [`SuspendSnapshot`]). `Some` exactly while `suspended` is set
    /// by this driver (a failed resume keeps it for the retry).
    suspend_snapshot: Option<SuspendSnapshot>,
    /// DMA pages a failed bring-up command handed the controller (an
    /// Identify target, an I/O CQ/SQ named by a failed Create). They are
    /// released only by [`Controller::disable_after_failure`], and only
    /// once CC.EN=0 / CSTS.RDY=0 confirms the controller stopped.
    in_flight_dma: Vec<DmaBuffer>,
    /// Registered namespaces from the bring-up scan, ascending NSID
    /// (Linux `nvme_scan_work`). Inactive, zero-capacity and unusable-format
    /// namespaces are not listed.
    namespaces: Vec<ns::NamespaceInfo>,
    /// NSID of `namespaces[0]` — the namespace `lba_bytes` / `nsze` and the
    /// single-namespace I/O helpers (`read_lba`, ...) address.
    primary_nsid: u32,
    /// The VS register value read at bring-up.
    vs: u32,
    /// Flush commands completed (see [`Controller::flush_nsid`]).
    flushes_completed: u64,
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
    /// Event words (`CQE.cmd_specific`, NVMe §5.2) of AER
    /// completions that arrived at the CQ head ahead of the
    /// command a waiter was matching (see
    /// [`Queue::submit_raw_ms`]). Bounded by `ADMIN_Q_DEPTH - 1`:
    /// at most that many AERs can be outstanding, so at most that
    /// many strays can precede one awaited CQE. Only used on the
    /// admin queue (`qid == 0`); I/O queues drop strays instead.
    stray_aer: [u32; (ADMIN_Q_DEPTH - 1) as usize],
    /// Number of valid entries in `stray_aer`.
    stray_aer_len: u8,
    /// CIDs of the AER commands currently outstanding on this
    /// queue (posted by [`Controller::post_aer_commands`],
    /// reposted by [`Controller::drain_aer`]). Lets every
    /// completion consumer tell an AER completion from another
    /// command's CQE by CID alone — the CQE carries no opcode
    /// (NVMe §4.6). Only used on the admin queue (`qid == 0`).
    aer_cids: [u16; (ADMIN_Q_DEPTH - 1) as usize],
    /// Number of valid entries in `aer_cids`.
    aer_cids_len: u8,
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

    /// Advance the CQ head past the entry just consumed (flipping
    /// the phase tag on wrap) and ring the CQ head doorbell so the
    /// controller can reuse the slot. Callers must have established
    /// that the head entry is a fresh completion (phase tag
    /// matches `cq_phase`); this only moves the pointer.
    fn advance_head(&mut self, bar0: &MmioRegion) {
        self.cq_head = (self.cq_head + 1) % self.depth;
        if self.cq_head == 0 {
            self.cq_phase ^= 1;
        }
        // SAFETY: identity-mapped MMIO doorbell.
        unsafe {
            bar0.write32(self.cq_db_off(), self.cq_head as u32);
        }
    }

    /// Record `cid` as an outstanding AER on this queue. Silent
    /// no-op when the table is full: callers cap posts at
    /// `ADMIN_Q_DEPTH - 1`, so this only fires if a burst
    /// over-posts — the untracked completion is then dropped
    /// rather than stashed, never misrouted.
    fn track_aer_cid(&mut self, cid: u16) {
        if (self.aer_cids_len as usize) < self.aer_cids.len() {
            self.aer_cids[self.aer_cids_len as usize] = cid;
            self.aer_cids_len += 1;
        }
    }

    /// Forget `cid` as an outstanding AER; true when it was
    /// present. Swap-remove: order in the table is meaningless.
    fn untrack_aer_cid(&mut self, cid: u16) -> bool {
        for i in 0..self.aer_cids_len as usize {
            if self.aer_cids[i] == cid {
                self.aer_cids_len -= 1;
                self.aer_cids[i] = self.aer_cids[self.aer_cids_len as usize];
                return true;
            }
        }
        false
    }

    /// Is `cid` an outstanding AER on this queue?
    fn is_aer_cid(&self, cid: u16) -> bool {
        self.aer_cids[..self.aer_cids_len as usize].contains(&cid)
    }

    /// Outstanding AER count. Diagnostic for tests + the AER
    /// supervisor.
    pub fn aer_outstanding(&self) -> usize {
        self.aer_cids_len as usize
    }

    /// Take the oldest stashed stray AER event word, if any
    /// (see [`Queue::submit_raw_ms`]).
    fn take_stray_aer(&mut self) -> Option<u32> {
        if self.stray_aer_len == 0 {
            return None;
        }
        let v = self.stray_aer[0];
        self.stray_aer
            .copy_within(1..self.stray_aer_len as usize, 0);
        self.stray_aer_len -= 1;
        Some(v)
    }

    /// Submit `sqe`, synchronously poll for its completion, and return
    /// the raw CQE **without** treating a nonzero NVMe status as an
    /// error. Auto-assigns the CID (overwrites the upper 16 bits of
    /// cdw0).
    ///
    /// Admin passthrough (`Controller::admin_passthrough`) needs the raw
    /// status word reported back to userspace even when the command
    /// failed, so it calls this directly; [`Queue::submit`] layers the
    /// status check on top for the driver's own internal callers.
    ///
    /// # Safety
    /// The DMA buffers `sq_buf` / `cq_buf` are still mapped and the
    /// controller is enabled. The caller owns the queue (no other
    /// task posting concurrently — Stage-3 single-threaded).
    unsafe fn submit_raw(&mut self, bar0: &MmioRegion, sqe: Sqe) -> Result<Cqe, NvmeError> {
        // SAFETY: forwarded under the caller's contract.
        unsafe { self.submit_raw_ms(bar0, sqe, CQE_TIMEOUT_MS, None) }
    }

    /// [`Self::submit_raw`] with a completion budget of `timeout_ms`.
    /// `vector` is the interrupt vector this queue's CQ is wired to, if
    /// any; the wait itself is polled, the vector only feeds the timeout
    /// report ([`log_cmd_timeout`]).
    ///
    /// # Safety
    /// Same invariants as [`Queue::submit_raw`].
    unsafe fn submit_raw_ms(
        &mut self,
        bar0: &MmioRegion,
        mut sqe: Sqe,
        timeout_ms: u64,
        vector: Option<u8>,
    ) -> Result<Cqe, NvmeError> {
        let opcode = (sqe.cdw0 & 0xFF) as u8;
        let started = narf_time::now_cycles();
        let fires_at_submit = vector.map(narf_interrupts::fire_count);
        // Test-only fault injection, I/O queues only (see
        // [`IO_LOSE_FOR_TEST`] / [`IO_LATE_FOR_TEST`]).
        let lose = self.qid != 0 && take_test_fault(&IO_LOSE_FOR_TEST);
        let late = self.qid != 0 && take_test_fault(&IO_LATE_FOR_TEST);
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
        if !lose {
            // SAFETY: identity-mapped MMIO doorbell.
            unsafe {
                bar0.write32(self.sq_db_off(), self.sq_tail as u32);
            }
        }

        // Wait for OUR completion, not just the next one: once AERs
        // are posted, an AER completion can sit at the CQ head
        // ahead of this command's CQE. Consuming it as ours would
        // report a spurious success — and for IDENTIFY-class
        // commands, parse a DMA buffer the controller had not
        // written yet. So loop on the CQ head until the CQE
        // carrying our CID arrives, within the caller's overall
        // `timeout_ms` budget. A stray whose CID is an outstanding
        // AER is stashed for `drain_aer` (admin queue only); any
        // other stray — another command's late completion, only
        // possible if the single-submitter invariant was broken —
        // is consumed and dropped so it can never be mistaken for
        // a later command's completion either. A dropped stray is
        // counted and reported ([`note_stray_cqe`]); a timeout is
        // reported where it is declared ([`log_cmd_timeout`]).
        //
        // The command is declared lost only after one last look at the
        // CQ once the budget is spent (Linux `nvme_timeout` →
        // `nvme_poll_irqdisable`, "timeout, completion polled"): the
        // budget can run out right after a stray was consumed, with
        // our completion sitting in the next slot. That last look
        // never blocks and examines at most `depth` entries.
        let deadline = narf_time::Deadline::after_ms(timeout_ms);
        if late {
            // Injected late completion: ignore the CQ for the whole
            // budget, so only the last look can find the entry.
            let _ = narf_scheduler::responsive_spin_until(|| false, deadline);
        }
        let mut last_look = self.depth;
        loop {
            let expired = deadline.expired();
            let cqe = if expired {
                // SAFETY: cq_buf is a live DMA page sized for self.depth CQEs.
                let cqe = unsafe { peek_cqe(&self.cq_buf, self.cq_head) };
                if last_look == 0 || (cqe.status & 1) != (self.cq_phase & 1) {
                    log_cmd_timeout(
                        bar0,
                        self,
                        opcode,
                        cid,
                        vector,
                        fires_at_submit,
                        Some(started),
                    );
                    return Err(NvmeError::CompletionTimeout);
                }
                last_look -= 1;
                cqe
            } else {
                let remaining_ms = narf_time::cycles_to_ns(deadline.remaining_cycles()) / 1_000_000;
                // SAFETY: cq_buf is a live DMA page sized for self.depth CQEs.
                let waited = unsafe {
                    wait_cqe_ms(
                        &self.cq_buf,
                        self.cq_head,
                        self.cq_phase,
                        remaining_ms.max(1),
                    )
                };
                match waited {
                    Ok(cqe) => cqe,
                    // The slice ran out with nothing fresh at the head;
                    // loop for the last look once the deadline has passed.
                    Err(_) => continue,
                }
            };

            let (head, phase) = (self.cq_head, self.cq_phase);
            self.advance_head(bar0);
            if cqe.is_for(cid) {
                if expired {
                    note_late_completion(bar0.phys.raw(), self.qid, opcode, cid, started);
                }
                return Ok(cqe);
            }
            if self.qid == 0 && self.untrack_aer_cid(cqe.cid) {
                // Stray AER completion: park its §5.2 event word
                // for `drain_aer`; the CQE itself is already off
                // the CQ.
                if (self.stray_aer_len as usize) < self.stray_aer.len() {
                    self.stray_aer[self.stray_aer_len as usize] = cqe.cmd_specific;
                    self.stray_aer_len += 1;
                }
                continue;
            }
            // Otherwise: another command's completion. Consumed and
            // dropped above, reported here; keep waiting for ours.
            note_stray_cqe(bar0.phys.raw(), self.qid, head, phase, Some(cid), &cqe);
        }
    }

    /// Submit `sqe` and synchronously poll for its completion, mapping a
    /// nonzero NVMe status to [`NvmeError::CommandFailed`].
    ///
    /// # Safety
    /// Same invariants as [`Queue::submit_raw`].
    unsafe fn submit(&mut self, bar0: &MmioRegion, sqe: Sqe) -> Result<Cqe, NvmeError> {
        // SAFETY: forwarded under the caller's contract.
        unsafe { self.submit_ms(bar0, sqe, CQE_TIMEOUT_MS, None) }
    }

    /// [`Self::submit`] with a completion budget of `timeout_ms`; `vector`
    /// as in [`Self::submit_raw_ms`].
    ///
    /// # Safety
    /// Same invariants as [`Queue::submit_raw`].
    unsafe fn submit_ms(
        &mut self,
        bar0: &MmioRegion,
        sqe: Sqe,
        timeout_ms: u64,
        vector: Option<u8>,
    ) -> Result<Cqe, NvmeError> {
        let opcode = (sqe.cdw0 & 0xFF) as u8;
        // SAFETY: forwarded under the caller's `submit` contract.
        let cqe = unsafe { self.submit_raw_ms(bar0, sqe, timeout_ms, vector)? };
        let nvme_status = cqe.status >> 1;
        if nvme_status != 0 {
            return Err(NvmeError::CommandFailed {
                cmd: opcode,
                status: nvme_status,
            });
        }
        Ok(cqe)
    }
}

/// Post one Async Event Request SQE into the admin queue and
/// track its CID as outstanding. Rings the SQ tail doorbell but
/// does NOT wait for completion — AERs complete only when an
/// async event fires. Shared by [`Controller::post_aer_commands`]
/// (burst post) and [`Controller::drain_aer`] (one repost per
/// drained completion, keeping the in-flight count stable).
fn post_one_aer(admin: &mut Queue, bar0: &MmioRegion) {
    let cid = admin.next_cid;
    admin.next_cid = admin.next_cid.wrapping_add(1);
    admin.track_aer_cid(cid);
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
}

/// How long one wait of the async I/O path may park before the CQ is
/// checked regardless of whether the queue's vector fired: the phase-poll
/// fallback for a lost or never-delivered MSI (the sync path checks the
/// CQE phase continuously; this is its async equivalent). The same
/// cadence as the AER supervisor's poll.
pub const ASYNC_CQ_POLL_MS: u64 = 250;

/// One I/O command in flight on the async path, from
/// [`Controller::submit_io_begin`] until [`Controller::submit_io_poll`]
/// reports it finished. Plain data: holding it borrows nothing.
#[derive(Copy, Clone, Debug)]
pub struct IoInFlight {
    /// Index into `io_queues` the command was submitted on.
    qi: usize,
    /// Its command identifier on that queue.
    cid: u16,
    /// Its opcode, for error and timeout reports (a CQE carries none).
    opcode: u8,
    /// The queue's interrupt vector.
    vector: u8,
    /// When the command is given up on (shared by every wait).
    deadline: narf_time::Deadline,
    /// `now_cycles()` at submission, for the timeout report.
    started: u64,
    /// The vector's `fire_count` at submission, for the timeout report.
    fires_at_submit: u64,
}

impl IoInFlight {
    /// A wait for this command's next reason to look at the CQ: the
    /// queue's vector firing, or [`ASYNC_CQ_POLL_MS`] passing, or the
    /// command's deadline — whichever is first. The `fire_count` baseline
    /// is taken here, so arm the wait BEFORE the CQ check it follows;
    /// an interrupt that lands between the check and the await then
    /// resolves the wait at once instead of being lost.
    pub fn wait(&self) -> narf_time::Timeout<narf_interrupts::WaitForIrq> {
        let slice = narf_time::Deadline::after_ms(ASYNC_CQ_POLL_MS);
        narf_interrupts::wait_for_irq_until(self.vector, slice.min(self.deadline))
    }

    /// The interrupt vector of the queue the command is on.
    pub fn vector(&self) -> u8 {
        self.vector
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
    /// Maximum Data Transfer Size (byte 77): a power of two in units of
    /// the CAP.MPSMIN page; 0 = no limit.
    pub mdts: u8,
    /// Version (bytes 80..84), as the VS register encodes it.
    pub ver: u32,
    /// Number of Namespaces (bytes 516..520): the largest valid NSID.
    pub nn: u32,
    /// RTD3 Entry Latency (bytes 88..92), microseconds; 0 = not reported.
    /// Bounds the CC.SHN shutdown wait (see [`shutdown::shutdown_timeout_ms`]).
    pub rtd3e: u32,
    /// Volatile Write Cache (byte 525): bit 0 = a volatile write cache is
    /// present, so completed writes are durable only after a Flush.
    pub vwc: u8,
    /// Optional NVM Command Support (bytes 256..258). Bit 2 = the
    /// Dataset Management command, bit 3 = the Write Zeroes command
    /// (see [`ONCS_DATASET_MGMT`] / [`ONCS_WRITE_ZEROES`]).
    pub oncs: u16,
}

/// ONCS bit 2: the controller supports the Dataset Management
/// command (NVM Command Set Specification §3.2.3, whose
/// processing-limit text keys DSM support off this bit).
pub const ONCS_DATASET_MGMT: u16 = 1 << 2;
/// ONCS bit 3: the controller supports the Write Zeroes command
/// (NVM Command Set Specification, Write Zeroes command; the WZSL
/// field's semantics key off this bit).
pub const ONCS_WRITE_ZEROES: u16 = 1 << 3;

/// What [`Controller::reset_recover`] found after re-identification.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RecoveryReport {
    /// The namespace set that came back differs from the pre-reset
    /// set (an NSID appeared / vanished, or a namespace's geometry
    /// or EUI64/NGUID/UUID changed). The controller identity matched;
    /// the caller re-publishes block devices from the fresh scan.
    pub namespaces_changed: bool,
}

/// Identity verdict of a reset/recovery, comparing the pre-reset
/// snapshot against the re-identified controller.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum RecoveryVerdict {
    /// Same controller, same namespace set.
    Unchanged,
    /// Same controller, namespace set changed.
    NamespacesChanged,
    /// A different controller (serial / model / vendor) answered.
    ControllerChanged,
}

/// Compare a reset's before/after identity snapshots. Controller
/// identity is serial + model + vendor (firmware revision excluded:
/// it is not identity, and it is not part of what the block registry
/// publishes). Namespace identity is the full registered set —
/// NSID, geometry, usability and EUI64/NGUID/UUID — in ascending
/// NSID order on both sides (the scan's order), so a slice compare
/// is the whole check.
fn recovery_verdict(
    before: &IdentifyController,
    before_ns: &[ns::NamespaceInfo],
    after: &IdentifyController,
    after_ns: &[ns::NamespaceInfo],
) -> RecoveryVerdict {
    if before.sn != after.sn || before.mn != after.mn || before.vid != after.vid {
        return RecoveryVerdict::ControllerChanged;
    }
    if before_ns != after_ns {
        return RecoveryVerdict::NamespacesChanged;
    }
    RecoveryVerdict::Unchanged
}

/// What one [`Controller::drain_aer_events`] pass found.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct AerDrain {
    /// AER completions processed (stashed + live-CQ).
    pub drained: u8,
    /// At least one drained event was a namespace-attribute-changed
    /// Notice: the namespace set may have changed and the caller
    /// should rescan (see [`Controller::rescan_namespaces`]).
    pub ns_changed: bool,
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
            admin_irq_vector: None,
            max_transfer: prp::NVME_CTRL_PAGE_SIZE as u32,
            ns_usable: false,
            prp_list: None,
            dsm_page: None,
            dead: false,
            stop_confirmed: true,
            suspended: false,
            suspend_snapshot: None,
            in_flight_dma: Vec::new(),
            namespaces: Vec::new(),
            primary_nsid: DEFAULT_NSID,
            vs: 0,
            flushes_completed: 0,
        }
    }

    /// Namespaces the bring-up scan registered (ascending NSID).
    pub fn namespaces(&self) -> &[ns::NamespaceInfo] {
        &self.namespaces
    }

    /// The bus device this controller drives, if any.
    pub fn bus_device(&self) -> Option<BusDevice> {
        self.device
    }

    /// Geometry of the primary namespace (what `lba_bytes` / `nsze`
    /// describe), for the single-namespace I/O helpers.
    fn primary_geom(&self) -> ns::NamespaceInfo {
        ns::NamespaceInfo {
            nsid: self.primary_nsid,
            lba_bytes: self.lba_bytes,
            nsze: self.nsze,
            usable: self.ns_usable,
            ids: ns::NsIds::default(),
        }
    }

    /// Geometry of namespace `nsid`, if the scan registered it.
    fn ns_geom(&self, nsid: u32) -> Option<ns::NamespaceInfo> {
        self.namespaces.iter().find(|n| n.nsid == nsid).copied()
    }

    /// Identify Controller VWC bit 0: completed writes may sit in a
    /// volatile cache until a Flush.
    pub fn has_volatile_write_cache(&self) -> bool {
        self.identify
            .is_some_and(|i| shutdown::has_volatile_write_cache(i.vwc))
    }

    /// Flush commands that completed successfully on this controller.
    pub fn flushes_completed(&self) -> u64 {
        self.flushes_completed
    }

    /// NVMe Flush (I/O opcode 0x00) of namespace `nsid`; returns once the
    /// controller completed it, i.e. once every write completed before it
    /// is on non-volatile media (NVM Command Set 1.0c §3.2.2). Linux
    /// `nvme_setup_flush`. Without a volatile write cache every completed
    /// write is already durable and no command is sent (Linux only turns on
    /// `REQ_PREFLUSH` for a VWC controller). A completion timeout
    /// ([`IO_TIMEOUT_MS`]) marks the controller dead, like every other I/O
    /// timeout; the block entry points then reset it and replay the Flush
    /// ([`run_with_replay`]).
    pub fn flush_nsid(&mut self, nsid: u32) -> Result<(), NvmeError> {
        if self.dead {
            return Err(NvmeError::ControllerDead);
        }
        if !self.has_volatile_write_cache() {
            return Ok(());
        }
        if self.io_queues.is_empty() {
            return Err(NvmeError::NoIoQueue);
        }
        let mut sqe = Sqe::zero();
        sqe.cdw0 = IoOpcode::Flush as u32;
        sqe.nsid = nsid;
        // Every I/O path consumes its completion before returning, so all
        // earlier writes are complete; one Flush on any queue covers them.
        // A Flush carries no data pointer.
        let qi = self.pick_queue();
        self.submit_sqe_polled(qi, sqe, io_timeout_ms())?;
        self.flushes_completed += 1;
        Ok(())
    }

    /// Submit a prebuilt SQE on I/O queue `qi` and poll its CQ for the
    /// completion, within `timeout_ms`. The polled sibling of
    /// [`Self::submit_sqe_irq`]: Flush, Dataset Management and Write
    /// Zeroes always take it, Read/Write when the queue has no vector.
    /// Callers pass [`io_timeout_ms`] (Linux `NVME_IO_TIMEOUT`, 30 s). A
    /// completion timeout marks the controller dead — the command and any
    /// page it names may still be live in the device — and leaves the
    /// reset + replay to the block entry points ([`run_with_replay`]).
    ///
    /// The caller guarantees what every I/O path here does: the SQE's data
    /// pointer (if any) names DMA memory that outlives the command — the
    /// caller's buffer across this synchronous call, or one of the
    /// controller's persistent pages.
    fn submit_sqe_polled(
        &mut self,
        qi: usize,
        sqe: Sqe,
        timeout_ms: u64,
    ) -> Result<Cqe, NvmeError> {
        let vector = self.io_irq_vectors.get(qi).copied();
        let io = self.io_queues.get_mut(qi).ok_or(NvmeError::NoIoQueue)?;
        let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;
        // SAFETY: the I/O queue and BAR0 are live, `&mut self` makes this
        // the queue's only submitter, and the data pointer is valid per
        // this function's contract.
        let r = unsafe { io.submit_ms(bar0, sqe, timeout_ms, vector) };
        if let Err(NvmeError::CompletionTimeout) = r {
            self.dead = true;
        }
        r
    }

    /// Identify Controller ONCS bit 2: the controller supports the
    /// Dataset Management command.
    pub fn supports_dataset_mgmt(&self) -> bool {
        self.identify
            .is_some_and(|i| i.oncs & ONCS_DATASET_MGMT != 0)
    }

    /// Identify Controller ONCS bit 3: the controller supports the
    /// Write Zeroes command.
    pub fn supports_write_zeroes(&self) -> bool {
        self.identify
            .is_some_and(|i| i.oncs & ONCS_WRITE_ZEROES != 0)
    }

    /// NVMe Dataset Management (I/O opcode 0x09) with the Deallocate
    /// attribute over `ranges` of namespace `ns` — the TRIM primitive
    /// (NVM Command Set Specification §3.2.3; Linux
    /// `nvme_setup_discard`). Ranges are issued in commands of at
    /// most [`DSM_MAX_RANGES`] 16-byte range definitions; a range
    /// longer than a definition's 32-bit length field is split.
    ///
    /// Wire encodings, per §3.2.3 Figures 39–41: CDW10 bits[7:0] =
    /// Number of Ranges, a **0-based** count; CDW11 bit 2 =
    /// Attribute – Deallocate; each range definition is 4 bytes of
    /// context attributes (zero here: no access hints), 4 bytes of
    /// length in logical blocks — a **1-based** value, the block
    /// count itself, unlike the 0-based NLB of Read/Write — and an
    /// 8-byte starting LBA.
    ///
    /// Errors are honest: an unsupported controller, an out-of-range
    /// range or a controller error status fails the call, so no
    /// caller is told a deallocation was issued when none was (#927).
    pub fn dataset_mgmt_ns(
        &mut self,
        ns: ns::NamespaceInfo,
        ranges: &[LbaRange],
    ) -> Result<(), NvmeError> {
        if self.dead {
            return Err(NvmeError::ControllerDead);
        }
        if !ns.usable {
            return Err(NvmeError::NamespaceUnusable);
        }
        if !self.supports_dataset_mgmt() {
            return Err(NvmeError::NotImplemented);
        }
        if self.io_queues.is_empty() {
            return Err(NvmeError::NoIoQueue);
        }
        // Flatten into wire entries: drop empty ranges, validate
        // bounds, split at the length field's capacity (1-based, so
        // one entry covers at most u32::MAX blocks).
        let mut entries: Vec<(u64, u32)> = Vec::new();
        for r in ranges {
            if r.blocks == 0 {
                continue;
            }
            if r.start
                .checked_add(r.blocks)
                .is_none_or(|end| end > ns.nsze)
            {
                return Err(NvmeError::OutOfRange);
            }
            let mut at = r.start;
            let mut left = r.blocks;
            while left > 0 {
                let n = core::cmp::min(left, u32::MAX as u64);
                entries.push((at, n as u32));
                at += n;
                left -= n;
            }
        }
        if entries.is_empty() {
            return Ok(());
        }
        // Raw pointer + DMA address out of the persistent page: the
        // page lives in `self` for the controller's whole life and
        // `&mut self` excludes every other I/O path, so encoding
        // through the pointer while `self` is borrowed mutably below
        // (queue pick / submit) cannot alias another command — the
        // same argument as the persistent PRP-list page.
        let (page_ptr, page_dma) = match self.dsm_page.as_ref() {
            Some(p) => (p.cpu_mut_ptr::<u8>(), p.dma_addr().raw()),
            None => return Err(NvmeError::OutOfDmaMemory),
        };
        for chunk in entries.chunks(DSM_MAX_RANGES) {
            // Encode this command's range list (Figure 41): context
            // attributes, the 1-based length, the starting LBA.
            // SAFETY: `page_ptr` is this controller's persistent 4 KiB
            // coherent page; `chunk` holds at most DSM_MAX_RANGES
            // entries, exactly one page of definitions; no command
            // referencing the page is in flight (each submit below
            // consumes its CQE before returning, and a timeout marks
            // the controller dead, refusing further chunks).
            unsafe {
                for (i, &(lba, blocks)) in chunk.iter().enumerate() {
                    let at = page_ptr.add(i * DSM_RANGE_BYTES);
                    core::ptr::write_volatile(at as *mut u32, 0);
                    core::ptr::write_volatile(at.add(4) as *mut u32, blocks);
                    core::ptr::write_volatile(at.add(8) as *mut u64, lba);
                }
            }
            // Publish the list before the SQE + doorbell that let
            // the controller fetch it.
            compiler_fence(Ordering::Release);
            let mut sqe = Sqe::zero();
            sqe.cdw0 = IoOpcode::DatasetMgmt as u32;
            sqe.nsid = ns.nsid;
            sqe.prp1 = page_dma;
            // CDW10 bits[7:0] = number of ranges, 0-based (Figure 39).
            sqe.cdw10 = (chunk.len() - 1) as u32;
            // CDW11 bit 2 = Attribute – Deallocate (Figure 40).
            sqe.cdw11 = DSM_CDW11_DEALLOCATE;
            // The range-list page is persistent DMA memory that
            // outlives the command.
            let qi = self.pick_queue();
            self.submit_sqe_polled(qi, sqe, io_timeout_ms())?;
        }
        Ok(())
    }

    /// NVMe Write Zeroes (I/O opcode 0x08) over `n_blocks` LBAs at
    /// `lba` of namespace `ns` (NVM Command Set Specification,
    /// Write Zeroes command, Figures 72–73). CDW12 bits[15:0] = NLB
    /// is a 16-bit **0-based** field, so a request is split into
    /// commands of at most 65 536 blocks. LR, FUA, PRINFO and DEAC
    /// stay clear: a plain Write Zeroes, whose reads-after return
    /// zeroes by construction.
    ///
    /// The command transfers no data — the data pointer is unused —
    /// so the buffer a `BlockOp::WriteZeroes` request carries is
    /// never read, let alone written to the device. (The pre-fix
    /// async path issued a plain Write of that buffer instead:
    /// stale bytes where zeroes were promised, #927.)
    pub fn write_zeroes_ns(
        &mut self,
        ns: ns::NamespaceInfo,
        lba: u64,
        n_blocks: u64,
    ) -> Result<(), NvmeError> {
        if self.dead {
            return Err(NvmeError::ControllerDead);
        }
        if !ns.usable {
            return Err(NvmeError::NamespaceUnusable);
        }
        if !self.supports_write_zeroes() {
            return Err(NvmeError::NotImplemented);
        }
        if self.io_queues.is_empty() {
            return Err(NvmeError::NoIoQueue);
        }
        if n_blocks == 0 {
            return Ok(());
        }
        if lba.checked_add(n_blocks).is_none_or(|end| end > ns.nsze) {
            return Err(NvmeError::OutOfRange);
        }
        let mut at = lba;
        let mut left = n_blocks;
        while left > 0 {
            let n = core::cmp::min(left, MAX_WRITE_ZEROES_BLOCKS);
            let mut sqe = Sqe::zero();
            sqe.cdw0 = IoOpcode::WriteZeroes as u32;
            sqe.nsid = ns.nsid;
            // CDW10/11 = SLBA (64-bit, little-endian split).
            sqe.cdw10 = (at & 0xFFFF_FFFF) as u32;
            sqe.cdw11 = (at >> 32) as u32;
            // CDW12 bits[15:0] = NLB, 0-based (Figure 73).
            sqe.cdw12 = (n - 1) as u32;
            // Write Zeroes carries no data pointer.
            let qi = self.pick_queue();
            self.submit_sqe_polled(qi, sqe, io_timeout_ms())?;
            at += n;
            left -= n;
        }
        Ok(())
    }

    /// Final quiesce for reboot / power-off (Linux `nvme_shutdown` →
    /// `nvme_dev_disable(shutdown = true)`): flush every namespace (when
    /// the controller has a VWC), then CC.SHN = normal and wait for
    /// CSTS.SHST = complete, bounded by RTD3E clamped to 5..=60 s. The
    /// controller refuses I/O afterwards. `None` before bring-up.
    pub fn shutdown(&mut self) -> Option<shutdown::QuiesceReport<NvmeError>> {
        let regs = BarRegs(*self.bar0_region.as_ref()?);
        let nsids: Vec<u32> = self.namespaces.iter().map(|n| n.nsid).collect();
        let vwc = self.identify.map(|i| i.vwc).unwrap_or(0);
        let timeout = shutdown::shutdown_timeout_ms(self.identify.map(|i| i.rtd3e).unwrap_or(0));
        let report = shutdown::quiesce(
            &nsids,
            vwc,
            &mut |nsid| self.flush_nsid(nsid),
            &regs,
            timeout,
            &mut |cond, ms| {
                narf_scheduler::responsive_spin_until(cond, narf_time::Deadline::after_ms(ms))
            },
        );
        self.dead = true;
        Some(report)
    }

    /// System-suspend quiesce + teardown (Linux `nvme_suspend` →
    /// `nvme_dev_disable(dev, shutdown = true)`): snapshot the identity
    /// [`Self::resume_pm`] must re-validate, Flush + CC.SHN via
    /// [`Self::shutdown`], then stop the controller and release its
    /// queues via [`Self::disable_after_failure`]. The caller holds the
    /// slot's request gate (the drain), so no command is in flight.
    ///
    /// On success the controller is disabled with `suspended` set and
    /// I/O refused (`dead`) until `resume_pm`. Failure leaves the
    /// controller stopped but NOT marked suspended: `resume_pm` is then
    /// a no-op and the disk stays down rather than half-rebuilt (a
    /// controller that cannot be confirmed stopped may still own DMA —
    /// its pages were leaked, never freed; see
    /// `disable_after_failure`). The one exception is
    /// [`shutdown::ShutdownOutcome::Gone`]: the function vanished
    /// mid-quiesce, nothing remains to stop, and the teardown is still
    /// recorded so a resume attempt re-runs bring-up and fails honestly
    /// there instead of pretending the disk came back.
    pub fn suspend_pm(
        &mut self,
        cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<shutdown::ShutdownOutcome, NvmeError> {
        if self.suspended {
            return Ok(shutdown::ShutdownOutcome::Complete);
        }
        if !self.is_ready() {
            return Err(NvmeError::NotReady);
        }
        let snapshot = SuspendSnapshot {
            identify: self.identify.ok_or(NvmeError::NotReady)?,
            namespaces: self.namespaces.clone(),
        };
        let report = self.shutdown().ok_or(NvmeError::NotReady)?;
        let stopped = self.disable_after_failure(cap);
        if !stopped && report.shutdown != shutdown::ShutdownOutcome::Gone {
            return Err(NvmeError::ControllerDead);
        }
        self.suspended = true;
        self.suspend_snapshot = Some(snapshot);
        Ok(report.shutdown)
    }

    /// System-resume re-init (Linux `nvme_resume` → `nvme_reset_ctrl`):
    /// the full probe sequence — [`Self::bring_up`] (reset, admin
    /// queue, IDENTIFY, namespace scan) + [`Self::create_io_queue`] —
    /// against the controller [`Self::suspend_pm`] tore down, then an
    /// identity re-check against the suspend snapshot.
    ///
    /// A no-op when the controller is not suspended: the suspend
    /// orchestrator resumes every device on rollback, including ones
    /// whose suspend never ran or failed before marking. A failed
    /// bring-up or queue create leaves the controller stopped and
    /// still marked suspended, so a later resume retries the re-init.
    /// An identity mismatch is permanent — a different disk woke up
    /// under this instance's registrations — so the controller is torn
    /// back down, unmarked, and the error propagates: the disk stays
    /// down (remove + re-probe is the way back; that lifecycle trigger
    /// is #929's work) rather than serving the wrong device.
    pub fn resume_pm(&mut self, cap: &Cap<BusDeviceCap, Write>) -> Result<(), NvmeError> {
        if !self.suspended {
            return Ok(());
        }
        let snapshot = self.suspend_snapshot.clone().ok_or(NvmeError::NotReady)?;
        self.bring_up(cap)?;
        if let Err(e) = self.create_io_queues_preferred(cap) {
            self.disable_after_failure(cap);
            return Err(e);
        }
        let id = self.identify.ok_or(NvmeError::NotReady)?;
        if !suspend_identity_matches(&snapshot, &id, &self.namespaces) {
            self.disable_after_failure(cap);
            self.suspended = false;
            self.suspend_snapshot = None;
            return Err(NvmeError::ControllerDead);
        }
        self.suspended = false;
        self.suspend_snapshot = None;
        Ok(())
    }

    /// Largest data transfer one I/O command may carry, in bytes.
    pub fn max_transfer_bytes(&self) -> u32 {
        self.max_transfer
    }

    /// `true` once an I/O command has timed out; see
    /// [`NvmeError::ControllerDead`].
    pub fn is_dead(&self) -> bool {
        self.dead
    }

    /// `true` when a command that timed out may still be live in the
    /// device: the controller is dead and was not confirmed disabled
    /// since. Memory such a command names — a caller's data buffer — must
    /// not be freed or reused while this holds. A controller that is
    /// alive again got there through a confirmed stop
    /// ([`Controller::reset_recover`] refuses to re-enable otherwise),
    /// which aborted whatever it still had.
    pub fn may_still_dma(&self) -> bool {
        self.dead && !self.stop_confirmed
    }

    /// `true` between a successful [`Controller::suspend_pm`] and the
    /// matching [`Controller::resume_pm`].
    pub fn is_suspended(&self) -> bool {
        self.suspended
    }

    /// Constructor taking the real `BusDevice`. The kernel-test smoke
    /// uses this after walking ECAM and finding the QEMU NVMe device.
    pub fn from_device(device: BusDevice) -> Self {
        let mut c = Self::new(0);
        c.device = Some(device);
        c
    }

    /// The admin queue's interrupt vector, if its MSI-X entry was
    /// programmed.
    pub fn admin_irq_vector(&self) -> Option<u8> {
        self.admin_irq_vector
    }

    /// The vector an AER completion fires: the admin queue's. (Falls back
    /// to `irq_vector` for a controller set up without `bring_up`.)
    fn aer_wait_vector(&self) -> Option<u8> {
        self.admin_irq_vector.or(self.irq_vector)
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
        self.vs = vs;
        // NARF programs CC.MPS = 0 (4 KiB pages) and builds every PRP
        // on 4 KiB boundaries. Refuse a controller whose minimum page
        // is larger before touching CC, as Linux `nvme_enable_ctrl`
        // does ("Minimum device page size ... too large for host").
        if !prp::host_page_supported(caps.mpsmin) {
            return Err(NvmeError::UnsupportedPageSize);
        }
        let ready_ms = caps.ready_timeout_ms();

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
        wait_csts(&bar0, ready_ms, |s| (s & CSTS_RDY) == 0)?;

        // ── 3. Allocate admin queues ──────────────────────────────
        let sq_buf = alloc_coherent(64 * ADMIN_Q_DEPTH as usize, DomainId::DRIVER_0)
            .map_err(|_| NvmeError::OutOfDmaMemory)?;
        let cq_buf = alloc_coherent(16 * ADMIN_Q_DEPTH as usize, DomainId::DRIVER_0)
            .map_err(|_| NvmeError::OutOfDmaMemory)?;
        // alloc_coherent hands out fresh frames; the frame allocator's
        // documented contract zero-fills before handing out, so the
        // SQ/CQ start in the canonical "nothing in flight, phase tag
        // 0 on every CQE" state.
        let sq_phys = sq_buf.dma_addr().raw();
        let cq_phys = cq_buf.dma_addr().raw();

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
        self.stop_confirmed = false;
        // SAFETY: same window.
        unsafe {
            bar0.write32(REG_CC, cc);
        }

        // From here the controller owns ASQ/ACQ and may DMA to them (and to
        // any Identify page below). Park every piece of that state in `self`
        // so a failure can stop the controller before anything is freed:
        // Linux `nvme_reset_work` → `nvme_dev_disable` → `nvme_disable_ctrl`
        // on an init error, never a bare free under CC.EN=1.
        self.admin = Some(Queue {
            sq_buf,
            cq_buf,
            qid: 0,
            depth: ADMIN_Q_DEPTH,
            sq_tail: 0,
            cq_head: 0,
            cq_phase: 1, // first valid CQE has phase = 1
            db_stride: caps.doorbell_stride(),
            next_cid: 0,
            stray_aer: [0; (ADMIN_Q_DEPTH - 1) as usize],
            stray_aer_len: 0,
            aer_cids: [0; (ADMIN_Q_DEPTH - 1) as usize],
            aer_cids_len: 0,
        });
        self.bar0_region = Some(bar0);
        if let Err(e) = self.bring_up_enabled(cap, &device, caps, ready_ms) {
            self.disable_after_failure(cap);
            return Err(e);
        }
        Ok(())
    }

    /// Steps 6–8 of [`Self::bring_up`], run with CC.EN=1 and the admin
    /// queue already parked in `self`. Any DMA page handed to the
    /// controller by a command that then fails goes to `in_flight_dma`.
    fn bring_up_enabled(
        &mut self,
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
        caps: NvmeCaps,
        ready_ms: u64,
    ) -> Result<(), NvmeError> {
        let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;
        // ── 6. Wait for CSTS.RDY = 1 ──────────────────────────────
        wait_csts(bar0, ready_ms, |s| (s & CSTS_RDY) != 0)?;

        // ── 6a. Enable MSI-X ──────────────────────────────────────
        self.msix = narf_bus::msix::enable_msix(cap, device).ok();
        if let Some(table) = self.msix.as_mut() {
            if let Ok(v) = narf_interrupts::vector::alloc() {
                // Program MSI-X slot 0 for the admin queue, steered to
                // `msix_target_apic_id`, then set the table's global
                // enable. Either step can fail (the table BAR does not
                // map, a config write is refused); an entry that was not
                // written must not be advertised as this queue's vector.
                let injected = take_test_fault(&FAIL_MSIX_PROGRAM_FOR_TEST);
                // SAFETY: `table` was just obtained from `enable_msix(cap,
                // device)` for this device, so we hold its BAR exclusively
                // via the `&mut` borrow of `self.msix` (no other writer to
                // the MSI-X table). `v` came from `narf_interrupts::vector::
                // alloc()`, so slot 0 is a valid, owned vector index, and
                // `enable()` runs last to gate MSI delivery only after the
                // entry is fully programmed (PCIe-recommended order).
                let programmed = !injected
                    && unsafe {
                        table.program_vector(0, msix_target_apic_id(), v).is_ok()
                            && table.enable().is_ok()
                    };
                if programmed {
                    self.irq_vector = Some(v);
                    self.admin_irq_vector = Some(v);
                    narf_interrupts::install_handler(v, nvme_admin_irq);
                } else {
                    // The admin queue has no vector: `admin_irq_vector`
                    // stays `None` (its commands are polled anyway, and the AER
                    // supervisor falls back to its timer), so a single
                    // I/O queue that would share entry 0 is created with
                    // IEN=0. The table itself is kept: the I/O queue
                    // setups program, check and enable their own entries.
                    use core::fmt::Write as _;
                    let _ = narf_interrupts::vector::free(v);
                    let _ = writeln!(
                        narf_console::Writer,
                        "nvme: bar {:#x}: WARNING: MSI-X admin entry could not be programmed; \
                         admin queue has no interrupt vector",
                        bar0.phys.raw()
                    );
                }
            }
        }
        let admin = self.admin.as_mut().ok_or(NvmeError::NotReady)?;

        // ── 7. IDENTIFY CONTROLLER ────────────────────────────────
        let id_buf =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| NvmeError::OutOfDmaMemory)?;
        let mut sqe = Sqe::zero();
        sqe.cdw0 = AdminOpcode::Identify as u32;
        sqe.nsid = 0;
        sqe.prp1 = id_buf.dma_addr().raw();
        sqe.cdw10 = 1; // CNS = 1: Identify Controller
        if FAIL_IDENTIFY_FOR_TEST.swap(false, Ordering::AcqRel) {
            self.in_flight_dma.push(id_buf);
            return Err(NvmeError::IdentifyFailed { status: 0x0006 });
        }
        // SAFETY: queue is live; bar0 is identity-mapped MMIO.
        match unsafe { admin.submit(bar0, sqe) } {
            Ok(_) => {}
            Err(e) => {
                // The controller may still write the page (a timed-out
                // command is not cancelled by giving up on it).
                self.in_flight_dma.push(id_buf);
                return Err(match e {
                    NvmeError::CommandFailed { status, .. } => NvmeError::IdentifyFailed { status },
                    e => e,
                });
            }
        }
        // SAFETY: id_buf is a live, identity-mapped DMA page.
        let id = unsafe { parse_identify(&id_buf) };
        drop(id_buf);

        // ── 8. Namespace scan (Linux `nvme_scan_work`) ────────────
        // Every active namespace with capacity and a usable LBA format,
        // with its EUI64 / NGUID / UUID. Pulls LBA size + capacity, which
        // I/O range checks need.
        let namespaces = match scan_namespaces(admin, bar0, self.vs, id.nn) {
            Ok(v) => v,
            Err((e, page)) => {
                // The failed command may still target the page.
                if let Some(page) = page {
                    self.in_flight_dma.push(page);
                }
                return Err(e);
            }
        };

        // Persistent PRP-list page for > 2-page transfers (see
        // `Controller::prp_list`).
        let prp_list = alloc_coherent(prp::NVME_CTRL_PAGE_SIZE, DomainId::DRIVER_0)
            .map_err(|_| NvmeError::OutOfDmaMemory)?;
        // Persistent Dataset Management range-list page (see
        // `Controller::dsm_page`).
        let dsm_page = alloc_coherent(prp::NVME_CTRL_PAGE_SIZE, DomainId::DRIVER_0)
            .map_err(|_| NvmeError::OutOfDmaMemory)?;

        self.max_transfer = prp::max_transfer_bytes(id.mdts, caps.mpsmin);
        self.identify = Some(id);
        match namespaces.first() {
            Some(p) => {
                self.primary_nsid = p.nsid;
                self.lba_bytes = p.lba_bytes;
                self.nsze = p.nsze;
                self.ns_usable = true;
            }
            None => {
                self.primary_nsid = DEFAULT_NSID;
                self.lba_bytes = 512;
                self.nsze = 0;
                self.ns_usable = false;
            }
        }
        self.namespaces = namespaces;
        self.prp_list = Some(prp_list);
        self.dsm_page = Some(dsm_page);

        // ── 9. Async Event Configuration + AERs (#928) ────────────
        // Enable SMART/health + namespace-attribute-changed events,
        // then post the AER slots the controller completes when one
        // fires. Best-effort AEC: a controller that rejects FID
        // 0x0B (Linux `nvme_configure_aen` likewise ignores the
        // result) still gets AERs posted against its default event
        // set, and a failed post leaves the controller usable —
        // AERs are observability, not bring-up. The AER supervisor
        // (Stage::Late) drains completions and rescans namespaces
        // on change events; `Queue::submit_raw_ms` is CID-aware so
        // a stray AER completion can never be mistaken for an admin
        // command's CQE while the slots are outstanding.
        let _ = self
            .set_features_async_event_config(admin::AEC_SMART_HEALTH | admin::AEC_NS_ATTR_CHANGED);
        let _ = self.post_aer_commands(AER_POST_COUNT);
        self.dead = false;
        Ok(())
    }

    /// Stop a controller whose bring-up failed after CC.EN=1, then release
    /// what it could DMA to. Linux `nvme_dev_disable(dev, false)`:
    /// `nvme_disable_ctrl` (clear CC.EN, `nvme_wait_ready` for CSTS.RDY=0
    /// bounded by CAP.TO), `pci_free_irq_vectors` (MSI-X off, vectors
    /// released) and `pci_disable_device` (bus mastering off), and only then
    /// `nvme_free_queues`.
    ///
    /// When RDY never drops (or CSTS reads all-ones: the function is gone)
    /// the controller cannot be shown to be idle, so every DMA page it was
    /// given — admin and I/O queues, the PRP list, any Identify target — is
    /// leaked with `mem::forget` rather than returned to the allocator.
    /// Returns `true` when the controller was confirmed stopped.
    pub fn disable_after_failure(&mut self, cap: &Cap<BusDeviceCap, Write>) -> bool {
        let timeout_ms = self.caps.map(|c| c.ready_timeout_ms()).unwrap_or(500);
        let stopped = match self.bar0_region.as_ref() {
            Some(bar) => {
                // SAFETY: BAR0 is this controller's identity-mapped MMIO and
                // `&mut self` excludes every other submitter.
                unsafe {
                    let cc = bar.read32(REG_CC);
                    bar.write32(REG_CC, cc & !CC_EN);
                }
                narf_scheduler::responsive_spin_until(
                    || {
                        // SAFETY: as above.
                        let csts = unsafe { bar.read32(REG_CSTS) };
                        csts != u32::MAX && csts & CSTS_RDY == 0
                    },
                    narf_time::Deadline::after_ms(timeout_ms),
                )
            }
            // CC.EN was never written: nothing was handed to the device.
            None => true,
        };
        if let Some(mut table) = self.msix.take() {
            // SAFETY: this controller owns the function's MSI-X capability;
            // the controller is disabled (or abandoned) so no source fires.
            unsafe { table.disable() };
        }
        // Every vector this controller allocated, each exactly once: the
        // admin queue's, and the I/O queues' (`irq_vector` aliases one of
        // them — the admin vector on the single-pair path, the first I/O
        // vector on the multi-queue path — and must not be freed twice,
        // nor the admin vector forgotten, which leaked one IDT vector and
        // its handler per multi-queue bring-up, i.e. per controller reset).
        let mut vectors: Vec<u8> = self
            .irq_vector
            .take()
            .into_iter()
            .chain(self.admin_irq_vector.take())
            .chain(self.io_irq_vectors.drain(..))
            .collect();
        vectors.sort_unstable();
        vectors.dedup();
        for v in vectors {
            narf_interrupts::dispatch::clear_handler(v);
            let _ = narf_interrupts::vector::free(v);
        }
        if let Some(device) = self.device {
            let _ = narf_bus::pci::clear_command(cap, &device, narf_bus::pci::cmd::BUS_MASTER);
        }
        let admin = self.admin.take();
        let io = core::mem::take(&mut self.io_queues);
        let prp_list = self.prp_list.take();
        let dsm_page = self.dsm_page.take();
        let pages = core::mem::take(&mut self.in_flight_dma);
        self.io_queue_locks.clear();
        self.dead = true;
        self.stop_confirmed = stopped;
        if stopped {
            drop((admin, io, prp_list, dsm_page, pages));
        } else {
            core::mem::forget(admin);
            core::mem::forget(io);
            core::mem::forget(prp_list);
            core::mem::forget(dsm_page);
            core::mem::forget(pages);
        }
        stopped
    }

    /// Reset a wedged controller and bring it back to live I/O in
    /// place (Linux `nvme_reset_work`): stop it
    /// ([`Self::disable_after_failure`]), run the full bring-up
    /// again ([`Self::bring_up`]), recreate the I/O queue, and only
    /// then trust it — after re-identification proves the function
    /// still hosts the same controller.
    ///
    /// Identity gate: the pre-reset IDENTIFY snapshot (serial /
    /// model / vendor — firmware revision deliberately excluded, it
    /// is not identity) and the registered namespace set (NSID +
    /// geometry + EUI64/NGUID/UUID, the comparison in
    /// [`recovery_verdict`]) are taken before the reset. A different
    /// controller serial/model/vendor afterwards means the function
    /// was hot-swapped while wedged: the new device is stopped again
    /// and [`NvmeError::IdentityChanged`] returned — its namespaces
    /// are never adopted under the old controller's publications. A
    /// changed namespace set on the *same* controller is reported in
    /// [`RecoveryReport::namespaces_changed`] so the caller can
    /// re-publish; the namespace data itself is re-read by the
    /// bring-up scan either way.
    ///
    /// When the wedged controller cannot be shown stopped (CSTS
    /// reads all-ones — the function is gone — or RDY never drops),
    /// its DMA pages have been leaked by `disable_after_failure` and
    /// there is nothing safe to re-initialise: returns
    /// [`NvmeError::ControllerFailed`] with the controller left dead.
    /// Every wait inside is bounded (CAP.TO-derived, as in bring-up).
    pub fn reset_recover(
        &mut self,
        cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<RecoveryReport, NvmeError> {
        if self.suspended {
            // Recovery loses to suspend: this controller was put
            // down by `suspend_pm`, and only `resume_pm` may bring
            // it back. (`recover_slot` refuses earlier still; this
            // guard keeps the invariant at the layer that owns the
            // state, for any future caller.)
            return Err(NvmeError::NotReady);
        }
        let before_id = self.identify.ok_or(NvmeError::NotReady)?;
        let before_ns = self.namespaces.clone();
        if !self.disable_after_failure(cap) {
            return Err(NvmeError::ControllerFailed);
        }
        // On failure `bring_up` has already stopped the controller.
        self.bring_up(cap)?;
        if let Err(e) = self.create_io_queues_preferred(cap) {
            self.disable_after_failure(cap);
            return Err(e);
        }
        let after_id = self.identify.ok_or(NvmeError::NotReady)?;
        match recovery_verdict(&before_id, &before_ns, &after_id, &self.namespaces) {
            RecoveryVerdict::ControllerChanged => {
                // Not the device we snapshotted: stop it again and
                // let the caller treat the slot as removed.
                self.disable_after_failure(cap);
                Err(NvmeError::IdentityChanged)
            }
            verdict => Ok(RecoveryReport {
                namespaces_changed: verdict == RecoveryVerdict::NamespacesChanged,
            }),
        }
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
            if first_io_cq_vector(table.size()) == 0 {
                // A one-entry table: the I/O CQ shares entry 0 with the
                // admin queue (Linux `nvme_create_cq`: `vector =
                // dev->num_vecs == 1 ? 0 : qid`). Naming IV 1 here would be
                // an Invalid Interrupt Vector and fail Create I/O CQ.
                if self.admin_irq_vector.is_some() {
                    ien = 1;
                }
            } else if let Ok(v) = narf_interrupts::vector::alloc() {
                // Use MSI-X slot 1 for the first I/O queue.
                let injected = take_test_fault(&FAIL_MSIX_PROGRAM_FOR_TEST);
                // SAFETY: `table` is this device's MSI-X table from
                // `enable_msix`, held exclusively here via the `&mut` borrow
                // of `self.msix` (no concurrent writer). `v` came from
                // `narf_interrupts::vector::alloc()`, and slot 1 is within the
                // table (the Admin queue used slot 0). The global enable is
                // normally already set by `bring_up`; it is set (again)
                // here because a bring-up whose admin entry could not be
                // programmed never reached it, and an IEN=1 queue behind a
                // disabled table would never interrupt.
                let programmed = !injected
                    && unsafe {
                        table.program_vector(1, msix_target_apic_id(), v).is_ok()
                            && table.enable().is_ok()
                    };
                if programmed {
                    iv = 1;
                    ien = 1;
                    irq_vec = Some(v);
                    narf_interrupts::install_handler(v, nvme_io_irq);
                } else {
                    // The entry was not written: creating the CQ with
                    // IEN=1 would point it at an unprogrammed entry. Keep
                    // IV=0 / IEN=0 — a polled queue, which every I/O path
                    // supports — and give the vector back.
                    use core::fmt::Write as _;
                    let _ = narf_interrupts::vector::free(v);
                    let _ = writeln!(
                        narf_console::Writer,
                        "nvme: bar {:#x}: WARNING: MSI-X I/O entry could not be programmed; \
                         I/O queue created polled (IEN=0)",
                        bar0.phys.raw()
                    );
                }
            }
        }

        // Allocate IOSQ + IOCQ DMA pages — same shape as admin.
        let sq_buf = alloc_coherent(64 * IO_Q_DEPTH as usize, DomainId::DRIVER_0)
            .map_err(|_| NvmeError::OutOfDmaMemory)?;
        let cq_buf = alloc_coherent(16 * IO_Q_DEPTH as usize, DomainId::DRIVER_0)
            .map_err(|_| NvmeError::OutOfDmaMemory)?;
        let sq_phys = sq_buf.dma_addr().raw();
        let cq_phys = cq_buf.dma_addr().raw();

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
        if let Err(e) = unsafe { admin.submit(bar0, sqe) } {
            // The controller may have created the CQ (or still be working
            // on the command): the page stays out of the allocator until
            // `disable_after_failure` confirms CC.EN=0.
            self.in_flight_dma.push(cq_buf);
            self.in_flight_dma.push(sq_buf);
            if let Some(v) = irq_vec {
                self.io_irq_vectors.push(v);
            }
            return Err(e);
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
        if let Err(e) = unsafe { admin.submit(bar0, sqe) } {
            self.in_flight_dma.push(cq_buf);
            self.in_flight_dma.push(sq_buf);
            if let Some(v) = irq_vec {
                self.io_irq_vectors.push(v);
            }
            return Err(e);
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
            stray_aer: [0; (ADMIN_Q_DEPTH - 1) as usize],
            stray_aer_len: 0,
            aer_cids: [0; (ADMIN_Q_DEPTH - 1) as usize],
            aer_cids_len: 0,
        });
        self.io_queue_locks.push(IrqSafeSpinLock::new(()));
        Ok(())
    }

    /// Submit an NVM Read (`opcode = 0x02`) for `n_blocks` LBAs
    /// starting at `lba` into the physically contiguous DMA buffer
    /// `buf` (PRP1 / PRP2 / PRP list built by [`prp::setup_prps`]).
    /// `n_blocks * lba_bytes` must fit in `buf` and in
    /// [`Self::max_transfer_bytes`]. Polls the I/O CQ for completion.
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
    /// for ≤ 2-page transfers; larger transfers write `pages[1..]`
    /// into the controller's persistent PRP-list page as 8-byte
    /// little-endian entries. The transfer is bounded by
    /// [`Self::max_transfer_bytes`] (≤ 2 MiB, so one list page always
    /// suffices). Every page must be 4-KiB aligned (NVMe base spec
    /// §4.1.1).
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

    /// Create one MSI-X I/O queue pair (`qid`, MSI-X table entry
    /// `iv`) for [`Self::create_io_queues_msix`]: CQ DMA + Create
    /// I/O CQ, then SQ DMA + Create I/O SQ. CQ-before-SQ is required
    /// by §3.3 (the controller rejects a Create SQ naming an
    /// unallocated CQID). On failure the pair's own DMA pages are
    /// parked in `in_flight_dma` — the controller may have created
    /// the queue (or still be working on the command) — and the
    /// error propagates to the caller, which parks the earlier pairs
    /// the same way.
    fn create_one_msix_queue(
        &mut self,
        qid: u16,
        iv: u16,
        admin_stride: u64,
    ) -> Result<Queue, NvmeError> {
        let cq_buf = alloc_coherent(16 * IO_Q_DEPTH as usize, DomainId::DRIVER_0)
            .map_err(|_| NvmeError::OutOfDmaMemory)?;
        let cq_phys = cq_buf.dma_addr().raw();
        // Create I/O CQ (§5.2.2, opcode 0x05):
        //   CDW10 bits[31:16] = QSIZE (zero-based)
        //   CDW10 bits[15:0]  = QID
        //   CDW11 bits[31:16] = IV (MSI-X table index)
        //   CDW11 bit[1]      = IEN (interrupt enable)
        //   CDW11 bit[0]      = PC (physically contiguous)
        let r: Result<(), NvmeError> = {
            let admin = self.admin.as_mut().ok_or(NvmeError::NotReady)?;
            let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;
            let mut sqe = Sqe::zero();
            sqe.cdw0 = AdminOpcode::CreateCq as u32;
            sqe.prp1 = cq_phys;
            sqe.cdw10 = ((IO_Q_DEPTH as u32 - 1) << 16) | (qid as u32);
            sqe.cdw11 = ((iv as u32) << 16) | (1 << 1) | 1;
            // SAFETY: admin queue + BAR live; CQ DMA fresh.
            unsafe { admin.submit(bar0, sqe) }.map(|_| ())
        };
        if let Err(e) = r {
            self.in_flight_dma.push(cq_buf);
            return Err(e);
        }

        let sq_buf = match alloc_coherent(64 * IO_Q_DEPTH as usize, DomainId::DRIVER_0) {
            Ok(b) => b,
            Err(_) => {
                self.in_flight_dma.push(cq_buf);
                return Err(NvmeError::OutOfDmaMemory);
            }
        };
        let sq_phys = sq_buf.dma_addr().raw();
        // Create I/O SQ (§5.2.1, opcode 0x01):
        //   CDW10 bits[31:16] = QSIZE (zero-based)
        //   CDW10 bits[15:0]  = QID
        //   CDW11 bits[31:16] = CQID
        //   CDW11 bits[2:1]   = QPRIO (0 = Urgent; matches the
        //                       priority weight the polled-completion
        //                       path used and keeps round-trip latency
        //                       dominated by the device, not the
        //                       controller's internal arbiter.)
        //   CDW11 bit[0]      = PC (physically contiguous)
        let r: Result<(), NvmeError> = {
            let admin = self.admin.as_mut().ok_or(NvmeError::NotReady)?;
            let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;
            let mut sqe = Sqe::zero();
            sqe.cdw0 = AdminOpcode::CreateSq as u32;
            sqe.prp1 = sq_phys;
            sqe.cdw10 = ((IO_Q_DEPTH as u32 - 1) << 16) | (qid as u32);
            sqe.cdw11 = ((qid as u32) << 16) | 1;
            // SAFETY: admin queue + BAR live; SQ DMA fresh.
            unsafe { admin.submit(bar0, sqe) }.map(|_| ())
        };
        if let Err(e) = r {
            self.in_flight_dma.push(cq_buf);
            self.in_flight_dma.push(sq_buf);
            return Err(e);
        }

        Ok(Queue {
            sq_buf,
            cq_buf,
            qid,
            depth: IO_Q_DEPTH,
            sq_tail: 0,
            cq_head: 0,
            cq_phase: 1,
            db_stride: admin_stride,
            next_cid: 0,
            stray_aer: [0; (ADMIN_Q_DEPTH - 1) as usize],
            stray_aer_len: 0,
            aer_cids: [0; (ADMIN_Q_DEPTH - 1) as usize],
            aer_cids_len: 0,
        })
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
    ///          MSI-X table entry `io_base+i` to deliver to the BSP
    ///          (`io_base` is 1 when the table has room, so entry 0
    ///          stays the admin queue's — Linux `nvme_create_cq`:
    ///          `vector = num_vecs == 1 ? 0 : qid` — and 0 on a
    ///          one-entry table, where the pair shares it).
    ///          The per-queue IDT handler (`nvme_io_irq`) is
    ///          installed for each vector, so completions are not
    ///          counted spurious.
    ///        - Allocate CQ DMA; submit Create I/O CQ (§5.2.2,
    ///          opcode 0x05) with `qid=i+1`, `IV=io_base+i`,
    ///          `IEN=1`, `PC=1`.
    ///        - Allocate SQ DMA; submit Create I/O SQ (§5.2.1,
    ///          opcode 0x01) with `qid=i+1`, `CQID=i+1`, `QPRIO=0`
    ///          (Urgent), `PC=1`. The host MUST create the CQ first
    ///          (§3.3) before its associated SQ — we do that for
    ///          each pair before moving to the next.
    ///   4. Flip the global MSI-X enable bit.
    ///   5. Stash each `Queue` in `io_queues`, each vector in
    ///      `io_irq_vectors`. `io_queues[0]` is qid=1; the
    ///      submission paths pick a queue via round-robin
    ///      (`pick_queue`).
    ///
    /// Error contract for the probe fallback
    /// ([`Self::create_io_queues_preferred`]): `NvmeError::Msix`
    /// means the failure happened *before* any I/O queue was
    /// created on the controller (Set Features refused, no MSI-X
    /// capability, table too small, vector exhaustion), so the
    /// caller may safely fall back to the single polled pair.
    /// Any other error means a queue may have been created: the
    /// partial state is parked (DMA into `in_flight_dma`,
    /// vectors freed, the MSI-X table restored) and the caller
    /// must NOT fall back — probe fails and the controller is
    /// stopped instead.
    ///
    /// Returns the number of granted I/O queue pairs.
    pub fn create_io_queues_msix(
        &mut self,
        bus_dev_cap: &Cap<BusDeviceCap, Write>,
        requested: u16,
    ) -> Result<usize, NvmeError> {
        use core::fmt::Write as _;
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
        // A refusal here is pre-creation (see the error contract
        // above): report it as Msix so the probe fallback can run.
        let (nsqa, ncqa) = match self.submit_set_features_n_queues(req) {
            Ok(v) => v,
            Err(e) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "nvme: Set Features (Number of Queues) failed ({e:?}); \
                     falling back to the single polled I/O queue"
                );
                return Err(NvmeError::Msix);
            }
        };
        // Granted count is the min of the host request, NSQA, NCQA.
        // Storage stacks generally allocate one pair per queue
        // (one SQ per CQ), so this is what the rest of the routine
        // assumes.
        let granted = req.min(nsqa).min(ncqa);
        if granted == 0 {
            return Err(NvmeError::Msix);
        }

        // ── 2. MSI-X table + block alloc ───────────────────────
        // Reuse the table `bring_up` already enabled (it programmed
        // entry 0 for the admin queue): re-discovering it would hand
        // back a second handle over the same capability with
        // `next_free` reset, and programming entries from 0 would
        // steal the admin queue's vector. When `bring_up` never
        // enabled MSI-X (`self.msix` is `None`), discover it fresh.
        let mut msix = match self.msix.take() {
            Some(t) => t,
            None => match enable_msix(bus_dev_cap, &device) {
                Ok(t) => t,
                Err(_) => return Err(NvmeError::Msix),
            },
        };
        // I/O entries start at 1 when the table has room, leaving
        // entry 0 to the admin queue; a one-entry table shares
        // entry 0 (Linux `nvme_create_cq`).
        let io_base: u16 = if msix.size() <= 1 { 0 } else { 1 };
        if msix.size() < granted + io_base {
            self.msix = Some(msix);
            return Err(NvmeError::Msix);
        }
        if msix.alloc_block(granted + io_base).is_err() {
            self.msix = Some(msix);
            return Err(NvmeError::Msix);
        }

        // ── 3. Per-queue: vector + table entry ─────────────────
        let mut vectors: Vec<u8> = Vec::with_capacity(granted as usize);
        let mut queues: Vec<Queue> = Vec::with_capacity(granted as usize);
        let admin_stride = match self.admin.as_ref() {
            Some(a) => a.db_stride,
            None => {
                self.msix = Some(msix);
                return Err(NvmeError::NotReady);
            }
        };

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
            let v = match narf_interrupts::vector::alloc() {
                Ok(v) => v,
                Err(_) => {
                    for v in vectors {
                        let _ = narf_interrupts::vector::free(v);
                    }
                    self.msix = Some(msix);
                    return Err(NvmeError::Msix);
                }
            };
            // SAFETY: caller holds the BusDeviceCap; we own the
            // MSI-X table exclusively (no concurrent writer); the
            // table-slot index was alloc_block'd above.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            if unsafe { msix.program_vector(io_base + i, msix_target_apic_id(), v) }.is_err() {
                let _ = narf_interrupts::vector::free(v);
                for v in vectors {
                    let _ = narf_interrupts::vector::free(v);
                }
                self.msix = Some(msix);
                return Err(NvmeError::Msix);
            }
            vectors.push(v);
        }
        // ── 4. Flip the global MSI-X enable bit ──────────────
        // SAFETY: `msix` is this device's MSI-X table from `enable_msix`,
        // owned exclusively here; `enable()` only flips the global enable
        // bit in cfg-space at the cached cap offset, with all table entries
        // already programmed in the loop above.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        if unsafe { msix.enable() }.is_err() {
            for v in vectors {
                let _ = narf_interrupts::vector::free(v);
            }
            self.msix = Some(msix);
            return Err(NvmeError::Msix);
        }

        for i in 0..granted {
            let qid = i + 1; // NVMe Base Spec §4.1.4: I/O qids ≥ 1
                             // Install the per-queue handler before the CQ exists,
                             // so a completion can never land on a vector with no
                             // handler (spurious) — same order as `create_io_queue`.
            narf_interrupts::install_handler(vectors[i as usize], nvme_io_irq);
            match self.create_one_msix_queue(qid, io_base + i, admin_stride) {
                Ok(q) => queues.push(q),
                Err(e) => {
                    // Mid-creation failure: park the DMA of the
                    // pairs that did get created, free every vector
                    // (handlers included), restore the MSI-X table.
                    // The controller may still own a half-created
                    // pair, so the caller must NOT fall back to the
                    // polled pair — the error propagates as-is (see
                    // the error contract above).
                    for q in queues {
                        self.in_flight_dma.push(q.sq_buf);
                        self.in_flight_dma.push(q.cq_buf);
                    }
                    for v in vectors {
                        narf_interrupts::dispatch::clear_handler(v);
                        let _ = narf_interrupts::vector::free(v);
                    }
                    self.msix = Some(msix);
                    return Err(e);
                }
            }
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

    /// Probe-time I/O queue setup (#928): negotiate the queue count
    /// and create the per-queue MSI-X pairs, falling back to the
    /// single polled pair when MSI-X is unavailable or the
    /// controller refuses the negotiation. The fallback runs only
    /// on [`NvmeError::Msix`], which
    /// [`Self::create_io_queues_msix`] guarantees means "nothing
    /// was created on the controller yet"; any other error (a queue
    /// may exist) propagates so probe stops the controller instead
    /// of layering a second queue set over a half-created one.
    /// Returns the number of live I/O queue pairs (1 on fallback).
    pub fn create_io_queues_preferred(
        &mut self,
        bus_dev_cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<usize, NvmeError> {
        match self.create_io_queues_msix(bus_dev_cap, NVME_MAX_IO_QUEUE_PAIRS) {
            Ok(n) => Ok(n),
            Err(NvmeError::Msix) => {
                self.create_io_queue()?;
                Ok(1)
            }
            Err(e) => Err(e),
        }
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

    // ── Admin: arbitrary passthrough (NVME_IOCTL_ADMIN_CMD) ───────────

    /// Execute an arbitrary admin command on behalf of userspace
    /// (`NVME_IOCTL_ADMIN_CMD`). This is the kernel side of smartctl /
    /// `nvme-cli` passthrough.
    ///
    /// `data` is the host transfer buffer named by the passthrough
    /// struct's `addr`/`data_len`. The transfer direction is taken from
    /// the opcode's data-transfer field (bits `[1:0]`, NVMe Base Spec
    /// §3.1.3.4): controller-to-host (`0b10`) fills `data` on return;
    /// host-to-controller (`0b01`) sends `data` as-is; bidirectional
    /// (`0b11`) does both. When `data` is empty no PRP is programmed.
    ///
    /// Unlike the driver's internal callers, a nonzero NVMe completion
    /// status is **not** an error here: it is returned in
    /// [`PassthruResult::status`] so the status word reaches userspace,
    /// matching Linux `nvme_submit_user_cmd`
    /// (drivers/nvme/host/ioctl.c).
    pub fn admin_passthrough(
        &mut self,
        cmd: &admin::AdminSqe,
        data: &mut [u8],
    ) -> Result<PassthruResult, NvmeError> {
        let admin_q = self.admin.as_mut().ok_or(NvmeError::NotReady)?;
        let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;

        // Data-transfer direction from the opcode's low two bits.
        let dir = cmd.opcode & 0x3;
        let to_host = dir == 0b10 || dir == 0b11; // controller -> host
        let to_dev = dir == 0b01 || dir == 0b11; // host -> controller

        let mut sqe = Sqe::zero();
        sqe.cdw0 = cmd.opcode as u32;
        sqe.nsid = cmd.nsid;
        sqe.cdw10 = cmd.cdw10;
        sqe.cdw11 = cmd.cdw11;
        sqe.cdw12 = cmd.cdw12;
        sqe.cdw13 = cmd.cdw13;
        sqe.cdw14 = cmd.cdw14;
        sqe.cdw15 = cmd.cdw15;

        // Allocate and map the transfer buffer as whole 4-KiB DMA pages;
        // hold them (and any PRP-list page) alive across the submit.
        let mut _data_pages: Vec<DmaBuffer> = Vec::new();
        let mut _prp_list_keepalive: Option<DmaBuffer> = None;

        if !data.is_empty() {
            let page = PAGE_SIZE as usize;
            let n_pages = data.len().div_ceil(page);
            const MAX_PASSTHRU_PAGES: usize = 512; // 2 MiB ceiling.
            if n_pages > MAX_PASSTHRU_PAGES {
                return Err(NvmeError::TooManyPages);
            }
            for _ in 0..n_pages {
                _data_pages.push(
                    alloc_coherent(page, DomainId::DRIVER_0)
                        .map_err(|_| NvmeError::OutOfDmaMemory)?,
                );
            }
            // Host -> controller: stage the user payload into the pages.
            if to_dev {
                let mut off = 0usize;
                for buf in &mut _data_pages {
                    let take = core::cmp::min(page, data.len() - off);
                    buf.as_mut_slice()[..take].copy_from_slice(&data[off..off + take]);
                    off += take;
                    if off == data.len() {
                        break;
                    }
                }
            }

            sqe.prp1 = _data_pages[0].dma_addr().raw();
            match n_pages {
                1 => {}
                2 => sqe.prp2 = _data_pages[1].dma_addr().raw(),
                _ => {
                    // PRP list: a single 4-KiB page holds up to 512 8-byte
                    // entries; the first data page is in PRP1, the remaining
                    // `n_pages - 1` go in the list. Capped at
                    // MAX_PASSTHRU_PAGES so the list never needs chaining.
                    let list = alloc_coherent(page, DomainId::DRIVER_0)
                        .map_err(|_| NvmeError::OutOfDmaMemory)?;
                    // SAFETY: alloc_coherent zero-fills + page-aligns the
                    // buffer; the kernel-mapped pointer stays valid for the
                    // buffer's lifetime, extended across the submit by
                    // `_prp_list_keepalive`. NVMe expects LE 8-byte phys
                    // addresses; a plain `write_volatile<u64>` on an LE
                    // target produces that layout.
                    // SAFETY: Valid MMIO bounds or trusted driver environment
                    unsafe {
                        let entries = list.as_mut_ptr() as *mut u64;
                        for (i, buf) in _data_pages[1..].iter().enumerate() {
                            core::ptr::write_volatile(entries.add(i), buf.dma_addr().raw());
                        }
                    }
                    sqe.prp2 = list.dma_addr().raw();
                    _prp_list_keepalive = Some(list);
                }
            }
        }

        // SAFETY: admin queue + BAR live; the DMA pages (and optional PRP
        // list) stay mapped until after `submit_raw` returns — it polls
        // the CQ synchronously, so the controller is done with them here.
        let cqe = match unsafe { admin_q.submit_raw(bar0, sqe) } {
            Ok(cqe) => cqe,
            Err(e) => {
                if e == NvmeError::CompletionTimeout {
                    // The device may still DMA into / out of these pages;
                    // freeing them would hand live DMA targets back to
                    // the allocator. Leak them instead.
                    core::mem::forget(_data_pages);
                    core::mem::forget(_prp_list_keepalive);
                }
                return Err(e);
            }
        };
        let status = cqe.status >> 1;

        // Controller -> host: copy the device's reply back out, only on a
        // successful transfer; a failed command leaves `data` untouched.
        if to_host && status == 0 {
            let page = PAGE_SIZE as usize;
            let mut off = 0usize;
            for buf in &_data_pages {
                let take = core::cmp::min(page, data.len() - off);
                data[off..off + take].copy_from_slice(&buf.as_slice()[..take]);
                off += take;
                if off == data.len() {
                    break;
                }
            }
        }

        Ok(PassthruResult {
            status,
            result: cqe.cmd_specific,
        })
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
        if !self.is_ready() {
            return Err(NvmeError::NotReady);
        }
        let buf =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| NvmeError::OutOfDmaMemory)?;
        let mut sqe = Sqe::zero();
        sqe.cdw0 = AdminOpcode::Identify as u32;
        sqe.nsid = start_nsid;
        sqe.prp1 = buf.dma_addr().raw();
        sqe.cdw10 = admin::CNS_NAMESPACE_LIST as u32;
        let buf = self.admin_submit_data(sqe, buf)?;
        // Parse: up to 1024 NSIDs, LE u32 each. A zero terminates.
        let base = buf.cpu_ptr::<u32>();
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

    /// Re-run the bring-up namespace scan against the live controller
    /// and adopt the fresh set (Linux `nvme_scan_work` on a
    /// namespace-attribute-changed AER). Returns `Ok(true)` when the
    /// registered set changed — a namespace appeared, vanished, or
    /// changed geometry/identity — and `Ok(false)` when it is
    /// identical to the bring-up scan. The fresh set is built in a
    /// local first and swapped in only on success, so a failed
    /// rescan leaves the previous registrations untouched (and a
    /// failed command's DMA page goes to `in_flight_dma`, as in
    /// bring-up).
    ///
    /// The caller re-publishes on `Ok(true)` (withdraw + register,
    /// as `recover_slot` does after a reset): this method only
    /// updates the controller's own view (`namespaces`,
    /// `primary_nsid`, `lba_bytes`, `nsze`, `ns_usable`).
    pub fn rescan_namespaces(&mut self) -> Result<bool, NvmeError> {
        if self.dead {
            return Err(NvmeError::ControllerDead);
        }
        if self.suspended {
            return Err(NvmeError::NotReady);
        }
        let id = self.identify.ok_or(NvmeError::NotReady)?;
        let vs = self.vs;
        let admin = self.admin.as_mut().ok_or(NvmeError::NotReady)?;
        let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;
        let fresh = match scan_namespaces(admin, bar0, vs, id.nn) {
            Ok(v) => v,
            Err((e, page)) => {
                if let Some(page) = page {
                    self.in_flight_dma.push(page);
                }
                return Err(e);
            }
        };
        let changed = fresh != self.namespaces;
        if changed {
            match fresh.first() {
                Some(p) => {
                    self.primary_nsid = p.nsid;
                    self.lba_bytes = p.lba_bytes;
                    self.nsze = p.nsze;
                    self.ns_usable = true;
                }
                None => {
                    self.primary_nsid = DEFAULT_NSID;
                    self.lba_bytes = 512;
                    self.nsze = 0;
                    self.ns_usable = false;
                }
            }
            self.namespaces = fresh;
        }
        Ok(changed)
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
        if !self.is_ready() {
            return Err(NvmeError::NotReady);
        }
        let buf =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| NvmeError::OutOfDmaMemory)?;
        let mut sqe = Sqe::zero();
        sqe.cdw0 = AdminOpcode::Identify as u32;
        sqe.nsid = nsid;
        sqe.prp1 = buf.dma_addr().raw();
        sqe.cdw10 = admin::CNS_NAMESPACE as u32;
        let buf = self.admin_submit_data(sqe, buf)?;
        // Read the 4 KiB response into a slice and parse.
        let base = buf.cpu_ptr::<u8>();
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

        // ADMIN_Q_DEPTH is 8; posting more AERs than free slots would
        // deadlock the polled path. Cap at depth - 1 so there's always
        // room for a non-AER admin command to slip through.
        let cap = (ADMIN_Q_DEPTH - 1).min(count as u16) as u8;
        for _ in 0..cap {
            post_one_aer(admin, bar0);
        }
        Ok(())
    }

    // ── Admin: AER drain ──────────────────────────────────────────────

    /// Drain all currently-completed Async Event Request completions
    /// from the admin CQ and repost a fresh AER for each one drained,
    /// maintaining the in-flight AER count.
    ///
    /// Two sources, in order: completions stashed by
    /// [`Queue::submit_raw_ms`] when an AER CQE landed at the admin
    /// CQ head ahead of the command that submit was waiting for,
    /// then live CQ entries whose phase tag matches `cq_phase`.
    /// CID-matched: only CQEs whose CID is an outstanding AER are
    /// consumed here. A head entry carrying another CID is a normal
    /// admin command's completion — consuming it would poison that
    /// command's waiter (the mirror image of the `submit_raw_ms`
    /// bug) — so the drain stops and leaves it for its waiter.
    /// Each drained entry is decoded (§5.2 CDW0 layout); a Notice
    /// with Namespace Attribute Changed sets `ns_changed`.
    ///
    /// Returns the drain outcome (0 drained = nothing to drain,
    /// which is the normal case when called without a pending
    /// event).
    ///
    /// # Usage
    ///
    /// Call from the AER supervisor task, which parks on the admin
    /// MSI-X vector:
    /// ```rust,ignore
    /// loop {
    ///     narf_interrupts::wait_for_irq(admin_vector).await;
    ///     ctrl.drain_aer_events();
    /// }
    /// ```
    ///
    /// Linux reference: drivers/nvme/host/core.c::nvme_aer_work
    /// (GPL-2.0-or-later; adapted under NARF's post-2026-05-20 licence).
    pub fn drain_aer_events(&mut self) -> AerDrain {
        let admin = match self.admin.as_mut() {
            Some(a) => a,
            None => return AerDrain::default(),
        };
        let bar0 = match self.bar0_region.as_ref() {
            Some(b) => b,
            None => return AerDrain::default(),
        };

        let mut out = AerDrain::default();
        // ── 1. Stashed strays ──────────────────────────────────
        // Already consumed from the CQ by `submit_raw_ms`; decode
        // + repost one AER each. Bounded with the live loop below
        // at depth-1 per pass. Reposting goes through
        // `post_one_aer`, so the fresh AER's CID is tracked —
        // the drain never loses track of an outstanding AER.
        while out.drained < (ADMIN_Q_DEPTH - 1) as u8 {
            let Some(ev) = admin.take_stray_aer() else {
                break;
            };
            if admin::async_event_is_ns_change(ev) {
                out.ns_changed = true;
            }
            out.drained += 1;
            // Repost one AER to keep the in-flight count stable.
            post_one_aer(admin, bar0);
        }

        // ── 2. Live admin CQ ────────────────────────────────────
        // Peek every slot from the current head forward; stop when
        // the phase tag doesn't match (no more completions).
        let mut orphans = 0u16;
        loop {
            // SAFETY: admin CQ DMA buffer is live + identity-mapped;
            // cq_head is always < admin.depth.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            let cqe = unsafe { peek_cqe(&admin.cq_buf, admin.cq_head) };
            if (cqe.status & 1) != (admin.cq_phase & 1) {
                break; // no more completed entries
            }
            // CID gate: only an outstanding AER's completion is an
            // event. A head entry carrying any other CID has no
            // waiter and never will: admin commands are synchronous
            // under `&mut self` (each consumes its own CQE before it
            // returns), so nothing can be mid-wait while this drain
            // runs. It is the late completion of an admin command
            // that timed out. Left at the head it would block every
            // AER behind it until some later admin command happened
            // to drop it — so drop it here: consumed, counted and
            // reported like any other stray. Bounded by the queue
            // depth.
            if !admin.is_aer_cid(cqe.cid) {
                if orphans >= admin.depth {
                    break;
                }
                orphans += 1;
                let (head, phase) = (admin.cq_head, admin.cq_phase);
                admin.advance_head(bar0);
                note_stray_cqe(bar0.phys.raw(), admin.qid, head, phase, None, &cqe);
                continue;
            }
            admin.untrack_aer_cid(cqe.cid);

            // Decode async event (§5.2 CDW0 layout) via the shared
            // decoder: Notice + Namespace Attribute Changed means
            // the namespace set may have changed.
            if admin::async_event_is_ns_change(cqe.cmd_specific) {
                out.ns_changed = true;
            }

            admin.advance_head(bar0);
            out.drained += 1;

            // Repost one AER to keep the in-flight count stable
            // (tracked, via `post_one_aer`). ADMIN_Q_DEPTH is 8;
            // we cap posting at depth-1 to leave room for
            // non-AER admin commands.
            post_one_aer(admin, bar0);
            // Bound the loop: never process more than depth-1 slots
            // in one pass to prevent re-draining freshly reposted AERs.
            if out.drained >= (ADMIN_Q_DEPTH - 1) as u8 {
                break;
            }
        }
        out
    }

    /// [`Self::drain_aer_events`] count-only wrapper, kept for the
    /// existing callers + smokes that only need "anything drained".
    pub fn drain_aer(&mut self) -> u8 {
        self.drain_aer_events().drained
    }

    /// Admin SQ occupancy: posted SQEs whose CQEs have not yet been
    /// consumed — `(sq_tail - cq_head) mod depth`. AERs posted via
    /// [`Self::post_aer_commands`] count here until [`Self::drain_aer`]
    /// consumes their completions. Exposed for tests: the AER smoke
    /// asserts the occupancy rises by exactly the spec §5.2 floor (4)
    /// after posting 4 AERs, proving the admin queue holds them.
    pub fn admin_sq_occupancy(&self) -> u16 {
        match &self.admin {
            Some(a) => (a.sq_tail + a.depth - a.cq_head) % a.depth,
            None => 0,
        }
    }

    /// Outstanding AER count on the admin queue: CIDs tracked in
    /// `aer_cids` (posted, not yet completed). A completion stashed
    /// by `submit_raw_ms` untracks its CID, so the count drops
    /// until `drain_aer` reposts the AER. Diagnostic for tests +
    /// the AER supervisor.
    pub fn aer_outstanding(&self) -> usize {
        self.admin.as_ref().map_or(0, |a| a.aer_outstanding())
    }

    /// Stray AER event words parked by `submit_raw_ms` and not yet
    /// drained by `drain_aer`. Diagnostic for tests.
    pub fn stray_aer_len(&self) -> u8 {
        self.admin.as_ref().map_or(0, |a| a.stray_aer_len)
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

    /// Submit admin command `sqe`, whose data pointer names `buf`, and
    /// hand the buffer back once the command completed. When the command
    /// times out it may still be live in the device — a late Identify or
    /// Security Receive would write into `buf` — so the buffer is NOT
    /// returned to the caller to be dropped: it is parked in
    /// `in_flight_dma`, which is released only once
    /// [`Self::disable_after_failure`] has confirmed the controller
    /// stopped (and leaked if it never does). An error-status completion
    /// is a completion: the device is done with the buffer, which is
    /// freed here.
    fn admin_submit_data(&mut self, sqe: Sqe, buf: DmaBuffer) -> Result<DmaBuffer, NvmeError> {
        let admin = self.admin.as_mut().ok_or(NvmeError::NotReady)?;
        let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;
        // SAFETY: admin queue + BAR live; `buf` is live DMA memory owned
        // here for the whole command, and parked below if the command
        // outlives this call.
        match unsafe { admin.submit(bar0, sqe) } {
            Ok(_) => Ok(buf),
            Err(e) => {
                if e == NvmeError::CompletionTimeout {
                    self.in_flight_dma.push(buf);
                }
                Err(e)
            }
        }
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
            let base = buf.cpu_mut_ptr::<u8>();
            for (i, &b) in data.iter().enumerate() {
                core::ptr::write_volatile(base.add(i), b);
            }
        }
        let sqe = build_security_sqe(
            admin::OPC_SECURITY_SEND,
            secp,
            spsp,
            tl,
            buf.dma_addr().raw(),
        );
        drop(self.admin_submit_data(sqe, buf)?);
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
        let sqe = build_security_sqe(
            admin::OPC_SECURITY_RECEIVE,
            secp,
            spsp,
            al,
            dma.dma_addr().raw(),
        );
        let dma = self.admin_submit_data(sqe, dma)?;
        // Copy DMA buffer into caller's slice.
        // SAFETY: identity-mapped DMA page; buf.len() == al.
        unsafe {
            let base = dma.cpu_ptr::<u8>();
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

    /// IDT vector per I/O queue: `io_irq_vectors[i]` is the vector
    /// MSI-X table entry `io_base+i` delivers to for completions
    /// on `io_queues[i]`. Empty on the polled path
    /// (`create_io_queue` without a spare vector).
    #[inline]
    pub fn io_irq_vectors(&self) -> &[u8] {
        &self.io_irq_vectors
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

    /// Submit a prebuilt SQE on I/O queue `qi` and wait for its
    /// MSI-X completion, draining the CQE carrying our CID (see
    /// [`Self::try_take_io_cqe`]). Shared core of
    /// [`Self::submit_io_irq`] and the `nvm_io_*` production paths
    /// (#928): the wait is IRQ-driven — the dispatch table's
    /// `fire_count` for the queue's vector, bumped by the ISR —
    /// with a CQE-phase check as the lost-interrupt fallback (QEMU
    /// has been observed to lose an MSI on hot reset paths).
    /// `responsive_spin_until` ticks sleep_pumps so the FB cursor /
    /// serial drain stay alive. Wall-clock budget [`IO_TIMEOUT_MS`]
    /// (30 s, Linux `NVME_IO_TIMEOUT`). When it runs out the CQ is
    /// looked at one last time ([`Self::reap_io_cqe`], Linux
    /// `nvme_timeout` → `nvme_poll_irqdisable`); only then is the
    /// command declared lost and the controller marked dead (the
    /// command's data / PRP-list pages may still be DMA targets).
    /// The reset + replay happen in the block entry points
    /// ([`run_with_replay`]), which own the slot. Requires
    /// `io_irq_vectors[qi]` to exist; callers without a vector use
    /// the polled [`Queue::submit`] instead.
    fn submit_sqe_irq(&mut self, qi: usize, mut sqe: Sqe) -> Result<(), NvmeError> {
        let v = *self.io_irq_vectors.get(qi).ok_or(NvmeError::Msix)?;
        let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;
        let opcode = (sqe.cdw0 & 0xFF) as u8;
        let started = narf_time::now_cycles();
        let fires_at_submit = Some(narf_interrupts::fire_count(v));
        // Test-only fault injection (see [`IO_LOSE_FOR_TEST`] /
        // [`IO_LATE_FOR_TEST`]).
        let lose = take_test_fault(&IO_LOSE_FOR_TEST);
        let late = take_test_fault(&IO_LATE_FOR_TEST);
        let deadline = narf_time::Deadline::after_ms(io_timeout_ms());

        // Auto-CID + ring SQ tail doorbell. Scoped so the queue
        // borrow ends before the wait below; the CID is kept for
        // the drain loop.
        let cid = {
            let io = self.io_queues.get_mut(qi).ok_or(NvmeError::NoIoQueue)?;
            let cid = io.next_cid;
            io.next_cid = io.next_cid.wrapping_add(1);
            sqe.cdw0 = (sqe.cdw0 & 0x0000_FFFF) | ((cid as u32) << 16);
            // SAFETY: queue is page-aligned; sq_tail bounded.
            unsafe {
                write_sqe(&io.sq_buf, io.sq_tail, &sqe);
            }
            io.sq_tail = (io.sq_tail + 1) % io.depth;
            if !lose {
                // SAFETY: identity-mapped MMIO doorbell.
                unsafe {
                    bar0.write32(io.sq_db_off(), io.sq_tail as u32);
                }
            }
            cid
        };

        // Wait for OUR completion: loop until the CQE carrying our
        // CID arrives at the head (see `try_take_io_cqe`). Each
        // wait is bounded by the shared deadline; the fire_count
        // baseline is re-read per iteration and the CQE phase is
        // always re-checked, so an MSI that lands between
        // iterations cannot be missed.
        loop {
            if late {
                // Injected late completion: ignore the CQ for the
                // whole budget, so only the last look can find it.
                let _ = narf_scheduler::responsive_spin_until(|| false, deadline);
                break;
            }
            if self.try_take_io_cqe(qi, cid, opcode)? {
                return Ok(());
            }
            if deadline.expired() {
                break;
            }
            let remaining_ms = narf_time::cycles_to_ns(deadline.remaining_cycles()) / 1_000_000;
            let baseline = narf_interrupts::fire_count(v);
            let done = narf_scheduler::responsive_spin_until(
                || {
                    if narf_interrupts::fire_count(v) > baseline {
                        return true;
                    }
                    let Some(io) = self.io_queues.get(qi) else {
                        return false;
                    };
                    // SAFETY: cq_buf is a live identity-mapped DMA page.
                    let cqe = unsafe { peek_cqe(&io.cq_buf, io.cq_head) };
                    (cqe.status & 1) == (io.cq_phase & 1)
                },
                narf_time::Deadline::after_ms(remaining_ms.max(1)),
            );
            if !done {
                break;
            }
        }

        // The budget is spent. One last look at the CQ before the
        // command is declared lost: the deadline can pass right after
        // a stray was consumed with ours in the next slot, and Linux
        // `nvme_timeout` polls the queue for exactly this reason.
        if self.reap_io_cqe(qi, cid, opcode)? {
            if let Some(bar0) = self.bar0_region.as_ref() {
                let qid = self.io_queues.get(qi).map_or(0, |q| q.qid);
                note_late_completion(bar0.phys.raw(), qid, opcode, cid, started);
            }
            return Ok(());
        }
        // The command (and its data / PRP-list pages) may still be
        // live in the device; stop trusting this queue.
        self.report_io_timeout(qi, opcode, cid, fires_at_submit, Some(started));
        self.dead = true;
        Err(NvmeError::CompletionTimeout)
    }

    /// Non-blocking drain of I/O queue `qi` for the CQE carrying `cid`:
    /// consume fresh head entries (strays are counted and dropped by
    /// [`Self::try_take_io_cqe`]) until ours turns up (`Ok(true)`), the
    /// head goes stale, or `depth` entries were examined (`Ok(false)`).
    /// `Err` when ours arrived with a nonzero status.
    fn reap_io_cqe(&mut self, qi: usize, cid: u16, opcode: u8) -> Result<bool, NvmeError> {
        let depth = self.io_queues.get(qi).map_or(1, |q| q.depth.max(1));
        for _ in 0..depth {
            if self.try_take_io_cqe(qi, cid, opcode)? {
                return Ok(true);
            }
            let Some(io) = self.io_queues.get(qi) else {
                return Ok(false);
            };
            // SAFETY: cq_buf is a live identity-mapped DMA page.
            let cqe = unsafe { peek_cqe(&io.cq_buf, io.cq_head) };
            if (cqe.status & 1) != (io.cq_phase & 1) {
                return Ok(false);
            }
            // A fresh stray was consumed; look at the next slot.
        }
        Ok(false)
    }

    /// Report a completion timeout of command `cid` on I/O queue `qi`
    /// ([`log_cmd_timeout`]). Read-only: the caller decides what the
    /// timeout means for the controller.
    fn report_io_timeout(
        &self,
        qi: usize,
        opcode: u8,
        cid: u16,
        fires_at_submit: Option<u64>,
        started: Option<u64>,
    ) {
        if let (Some(io), Some(bar0)) = (self.io_queues.get(qi), self.bar0_region.as_ref()) {
            let vector = self.io_irq_vectors.get(qi).copied();
            log_cmd_timeout(bar0, io, opcode, cid, vector, fires_at_submit, started);
        }
    }

    /// Try once to consume the CQE carrying `cid` from I/O queue
    /// `qi`. Returns `Ok(true)` when our CQE arrived (and its NVMe
    /// status was zero), `Ok(false)` when nothing for us is pending
    /// — no fresh CQE at the head, or the head CQE was a stray
    /// (consumed and dropped, never mistaken for ours) — and `Err`
    /// when our CQE arrived with a nonzero status. Callers loop:
    /// wait, retry. Shared by the sync and async IRQ-driven I/O
    /// paths so both match completions by CID.
    fn try_take_io_cqe(&mut self, qi: usize, cid: u16, opcode: u8) -> Result<bool, NvmeError> {
        let io = self.io_queues.get_mut(qi).ok_or(NvmeError::NoIoQueue)?;
        let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;
        // SAFETY: cq_buf is a live identity-mapped DMA page.
        let cqe = unsafe { peek_cqe(&io.cq_buf, io.cq_head) };
        if (cqe.status & 1) != (io.cq_phase & 1) {
            return Ok(false); // no fresh completion at the head
        }
        let (head, phase) = (io.cq_head, io.cq_phase);
        io.advance_head(bar0);
        if !cqe.is_for(cid) {
            // Stray completion (another submitter's late CQE, or a
            // corrupted head): consumed and dropped above, counted
            // and reported here. The caller waits and retries for
            // ours.
            note_stray_cqe(bar0.phys.raw(), io.qid, head, phase, Some(cid), &cqe);
            return Ok(false);
        }
        let nvme_status = cqe.status >> 1;
        if nvme_status != 0 {
            return Err(NvmeError::CommandFailed {
                cmd: opcode,
                status: nvme_status,
            });
        }
        Ok(true)
    }

    /// Submit an NVM Read/Write to a round-robin-picked I/O queue
    /// and wait for MSI-X-delivered completion via
    /// [`Self::submit_sqe_irq`]. Caller decides between `read_lba`
    /// (polled) and this for IRQ-driven flows.
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
        if n_blocks == 0 {
            return Ok(());
        }
        let sqe = self.build_nvm_sqe(
            opcode,
            lba,
            n_blocks as u32,
            buf.dma_addr().raw(),
            buf.len(),
        )?;
        let qi = self.pick_queue();
        self.submit_sqe_irq(qi, sqe)
    }

    /// Begin an IRQ-driven I/O submission: build the SQE, pick a
    /// queue, write the SQE and ring the doorbell. Returns the
    /// in-flight command ([`IoInFlight`]); the caller then loops
    /// "arm a wait ([`IoInFlight::wait`]), check the CQ
    /// ([`Self::submit_io_poll`]), await the wait" until the poll
    /// reports the command finished — see
    /// [`Self::submit_io_irq_async`], which is exactly that loop.
    ///
    /// This is the `block_on` / `IrqSafeSpinLock`-across-await
    /// restructure (AGENTS.md): NO await happens here and NO
    /// borrow is held across the caller's await — the wait future
    /// owns only the vector + its `fire_count` baseline, so the
    /// caller may release the slot gate (an atomic, never an
    /// IRQ-masking lock) before awaiting, then re-acquire and call
    /// `submit_io_poll`. The per-queue locks are only ever held in
    /// the short sync phases on either side of the await, never
    /// across it; no `block_on` appears anywhere on this path.
    ///
    /// No wait needs to exist before the doorbell: every wait is
    /// armed *before* the CQ check that follows it, so a completion
    /// whose interrupt fired before the wait was armed is already in
    /// the CQ when that check runs, and one that fires after is seen
    /// by the wait.
    ///
    /// `n_blocks == 0` is a [`NvmeError::BadTransfer`] here (via
    /// `build_nvm_sqe`); callers that treat empty transfers as
    /// success check first, as [`Self::submit_io_irq_async`] does.
    pub fn submit_io_begin(
        &mut self,
        opcode: u8,
        lba: u64,
        n_blocks: u16,
        buf: &DmaBuffer,
    ) -> Result<IoInFlight, NvmeError> {
        if self.io_queues.is_empty() {
            return Err(NvmeError::NoIoQueue);
        }
        let mut sqe = self.build_nvm_sqe(
            opcode,
            lba,
            n_blocks as u32,
            buf.dma_addr().raw(),
            buf.len(),
        )?;
        let qi = self.pick_queue();
        let vector = *self.io_irq_vectors.get(qi).ok_or(NvmeError::Msix)?;
        let started = narf_time::now_cycles();
        let fires_at_submit = narf_interrupts::fire_count(vector);
        // The same budget as the sync path (Linux `NVME_IO_TIMEOUT`).
        let deadline = narf_time::Deadline::after_ms(io_timeout_ms());

        let io = self.io_queues.get_mut(qi).ok_or(NvmeError::NoIoQueue)?;
        let bar0 = self.bar0_region.as_ref().ok_or(NvmeError::NotReady)?;
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
        Ok(IoInFlight {
            qi,
            cid,
            opcode,
            vector,
            deadline,
            started,
            fires_at_submit,
        })
    }

    /// Check on command `io` begun by [`Self::submit_io_begin`], on
    /// the queue it was submitted on. Never blocks.
    ///
    /// - `Ok(true)`: its completion was consumed (status zero). Done.
    /// - `Ok(false)`: not completed yet and the budget is not spent.
    ///   Whatever woke the caller — another queue's interrupt on a
    ///   shared vector, the late MSI of an earlier polled Flush on
    ///   this queue, the wait's poll slice running out — was not
    ///   this command's completion, and that is not an error: await
    ///   a fresh [`IoInFlight::wait`] and poll again. Strays at the
    ///   CQ head are consumed, counted and dropped on the way.
    /// - `Err(CommandFailed)`: it completed with an error status.
    /// - `Err(CompletionTimeout)`: the budget is spent and one last
    ///   look at the CQ did not find it. The controller is marked
    ///   dead — the command may still be live in the device, so its
    ///   buffers must not be reused or freed until the controller is
    ///   reset. A completion found by that last look is `Ok(true)`
    ///   (counted as a late completion).
    pub fn submit_io_poll(&mut self, io: &IoInFlight) -> Result<bool, NvmeError> {
        let expired = io.deadline.expired();
        if self.reap_io_cqe(io.qi, io.cid, io.opcode)? {
            if expired {
                if let Some(bar0) = self.bar0_region.as_ref() {
                    let qid = self.io_queues.get(io.qi).map_or(0, |q| q.qid);
                    note_late_completion(bar0.phys.raw(), qid, io.opcode, io.cid, io.started);
                }
            }
            return Ok(true);
        }
        if !expired {
            return Ok(false);
        }
        self.report_io_timeout(
            io.qi,
            io.opcode,
            io.cid,
            Some(io.fires_at_submit),
            Some(io.started),
        );
        self.dead = true;
        Err(NvmeError::CompletionTimeout)
    }

    /// Async sibling of `submit_io_irq`. Submits the command, then
    /// parks on the queue's MSI-X vector instead of spinning on
    /// `fire_count`. Lets the executor run other tasks during the
    /// I/O — the difference between "kernel pauses for the entire
    /// I/O" and "kernel does other work while the device is busy".
    ///
    /// The wait is a loop, not a single await: arm a wait, check the
    /// CQ, await, repeat, until the command's shared deadline
    /// ([`IO_TIMEOUT_MS`]). A wake that is not this command's
    /// completion just goes round again, and each wait is also
    /// bounded by [`ASYNC_CQ_POLL_MS`], so a completion whose
    /// interrupt never arrives is found by the next CQ check instead
    /// of costing the whole budget. Only when the deadline has
    /// passed and a last look at the CQ still finds nothing is the
    /// command declared lost (controller dead, `CompletionTimeout`).
    ///
    /// The composed form still holds `&mut self` — i.e. the slot
    /// gate — across the await: that is sound here because the gate
    /// is an atomic that leaves IRQs live (no `IrqSafeSpinLock` is
    /// held across the suspension point), so the MSI wake can fire;
    /// the cost is whole-controller serialisation for the I/O
    /// duration, the same as the sync path. Callers that need the
    /// gate released across the await use `submit_io_begin` /
    /// `submit_io_poll` directly. Completion matching is CID-aware
    /// (see [`Self::try_take_io_cqe`]); true concurrency still needs
    /// a per-queue CID waiter table + the `InstalledController`
    /// request-gate → async-Mutex migration, so until then one async
    /// I/O is in flight per controller.
    ///
    /// Dropping the future before it resolves abandons the command
    /// in the device; its completion is then a stray for the next
    /// submitter (consumed, counted, logged).
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
        if n_blocks == 0 {
            return Ok(());
        }
        let io = self.submit_io_begin(opcode, lba, n_blocks, buf)?;
        loop {
            // Arm BEFORE the check: see `submit_io_begin`.
            let wait = io.wait();
            if self.submit_io_poll(&io)? {
                return Ok(());
            }
            // Either outcome — the vector fired, or the slice ran out —
            // means "look at the CQ again".
            let _ = wait.await;
        }
    }

    /// Validate an NVM Read/Write against the controller and namespace
    /// limits and build its SQE, including the data pointer for the
    /// physically contiguous buffer at device address `dma` of `len`
    /// bytes.
    ///
    /// PRPs follow Linux `nvme_pci_setup_data_prp` (see [`prp`]); a
    /// transfer longer than two pages writes its list into the
    /// controller's persistent `prp_list` page, which is safe to reuse
    /// because every caller holds `&mut self` until the CQE is consumed.
    fn build_nvm_sqe(
        &mut self,
        opcode: u8,
        lba: u64,
        n_blocks: u32,
        dma: u64,
        len: usize,
    ) -> Result<Sqe, NvmeError> {
        let ns = self.primary_geom();
        self.build_nvm_sqe_ns(ns, false, opcode, lba, n_blocks, dma, len)
    }

    /// [`Self::build_nvm_sqe`] against namespace `ns`.
    #[allow(clippy::too_many_arguments)]
    fn build_nvm_sqe_ns(
        &mut self,
        ns: ns::NamespaceInfo,
        fua: bool,
        opcode: u8,
        lba: u64,
        n_blocks: u32,
        dma: u64,
        len: usize,
    ) -> Result<Sqe, NvmeError> {
        if self.dead {
            return Err(NvmeError::ControllerDead);
        }
        if !ns.usable {
            return Err(NvmeError::NamespaceUnusable);
        }
        // NLB is a 16-bit zero-based field (NVM Command Set §3.2.4).
        if n_blocks == 0 || n_blocks > 0x1_0000 {
            return Err(NvmeError::BadTransfer);
        }
        if lba
            .checked_add(n_blocks as u64)
            .is_none_or(|end| end > ns.nsze)
        {
            return Err(NvmeError::OutOfRange);
        }
        let bytes = n_blocks as u64 * ns.lba_bytes as u64;
        if bytes > len as u64 {
            return Err(NvmeError::BadTransfer);
        }
        if bytes > self.max_transfer as u64 {
            return Err(NvmeError::ExceedsMaxTransfer);
        }
        let bytes = bytes as usize;
        let pair = match self.prp_list.as_ref() {
            Some(list) => {
                // SAFETY: `list` is this controller's persistent 4 KiB
                // coherent page (PRPS_PER_PAGE u64 entries, page aligned);
                // `&mut self` excludes every other I/O path, and no
                // command referencing it is in flight (each path consumes
                // its CQE before returning, and a timeout marks the
                // controller dead, refused above).
                let entries = unsafe {
                    core::slice::from_raw_parts_mut(list.cpu_mut_ptr::<u64>(), prp::PRPS_PER_PAGE)
                };
                prp::setup_prps(dma, bytes, entries, &[list.dma_addr().raw()])
            }
            None => prp::setup_prps(dma, bytes, &mut [], &[]),
        }
        .map_err(|e| match e {
            prp::PrpError::ListTooSmall => NvmeError::ExceedsMaxTransfer,
            _ => NvmeError::BadTransfer,
        })?;
        // Publish the list entries before the SQE + doorbell that let
        // the controller fetch them.
        compiler_fence(Ordering::Release);

        let mut sqe = Sqe::zero();
        sqe.cdw0 = opcode as u32;
        sqe.nsid = ns.nsid;
        sqe.prp1 = pair.prp1;
        sqe.prp2 = pair.prp2;
        // CDW10/11 = SLBA (64-bit, little-endian split).
        sqe.cdw10 = (lba & 0xFFFF_FFFF) as u32;
        sqe.cdw11 = (lba >> 32) as u32;
        // CDW12 bits[15:0] = NLB-1; bit 30 = FUA (NVM Command Set 1.0c
        // Figure 63: the write is on media before completion), as Linux
        // `nvme_setup_rw` sets for `REQ_FUA`. LR / PRINFO stay zero.
        sqe.cdw12 = n_blocks - 1;
        if fua && opcode == IoOpcode::Write as u8 {
            sqe.cdw12 |= shutdown::CDW12_FUA;
        }
        Ok(sqe)
    }

    /// Polled NVM Read/Write of `n_blocks` LBAs at `lba` into / from the
    /// contiguous DMA range `dma .. dma + len`. A completion timeout
    /// marks the controller dead (see [`NvmeError::ControllerDead`]).
    #[allow(clippy::too_many_arguments)]
    fn nvm_io_dma(
        &mut self,
        ns: ns::NamespaceInfo,
        fua: bool,
        opcode: u8,
        lba: u64,
        n_blocks: u32,
        dma: u64,
        len: usize,
    ) -> Result<(), NvmeError> {
        if self.io_queues.is_empty() {
            return Err(NvmeError::NoIoQueue);
        }
        if n_blocks == 0 {
            return Ok(());
        }
        let sqe = self.build_nvm_sqe_ns(ns, fua, opcode, lba, n_blocks, dma, len)?;
        let qi = self.pick_queue();
        // IRQ path when this queue has a vector (#928): the
        // completion wait is MSI-X-driven instead of MMIO polling.
        // The polled submit stays the fallback for vector-less
        // boots (no MSI-X, or the single-queue path without a
        // spare vector).
        if self.io_irq_vectors.get(qi).is_some() {
            return self.submit_sqe_irq(qi, sqe);
        }
        // The data range and the PRP-list page are DMA memory that
        // outlives the command (the caller owns the data buffer across
        // this synchronous call; the list is persistent).
        self.submit_sqe_polled(qi, sqe, io_timeout_ms()).map(|_| ())
    }

    /// Polled NVM Read/Write of `n_blocks` LBAs to / from `buf` starting
    /// `offset` bytes into it. `buf` must be physically contiguous
    /// (every `alloc_coherent` buffer is).
    pub fn nvm_io_at(
        &mut self,
        opcode: u8,
        lba: u64,
        n_blocks: u32,
        buf: &DmaBuffer,
        offset: usize,
    ) -> Result<(), NvmeError> {
        let ns = self.primary_geom();
        self.nvm_io_ns_at(ns, false, opcode, lba, n_blocks, buf, offset)
    }

    /// [`Self::nvm_io_at`] against registered namespace `nsid`.
    pub fn nvm_io_nsid_at(
        &mut self,
        nsid: u32,
        opcode: u8,
        lba: u64,
        n_blocks: u32,
        buf: &DmaBuffer,
        offset: usize,
    ) -> Result<(), NvmeError> {
        let ns = self.ns_geom(nsid).ok_or(NvmeError::NamespaceUnusable)?;
        self.nvm_io_ns_at(ns, false, opcode, lba, n_blocks, buf, offset)
    }

    #[allow(clippy::too_many_arguments)]
    fn nvm_io_ns_at(
        &mut self,
        ns: ns::NamespaceInfo,
        fua: bool,
        opcode: u8,
        lba: u64,
        n_blocks: u32,
        buf: &DmaBuffer,
        offset: usize,
    ) -> Result<(), NvmeError> {
        if offset > buf.len() || offset & 0x3 != 0 {
            return Err(NvmeError::BadTransfer);
        }
        self.nvm_io_dma(
            ns,
            fua,
            opcode,
            lba,
            n_blocks,
            buf.dma_addr_at(offset as u64).raw(),
            buf.len() - offset,
        )
    }

    fn nvm_io(
        &mut self,
        opcode: u8,
        lba: u64,
        n_blocks: u16,
        buf: &DmaBuffer,
    ) -> Result<(), NvmeError> {
        self.nvm_io_at(opcode, lba, n_blocks as u32, buf, 0)
    }

    /// Multi-page PRP-list NVM I/O over a caller-supplied list of
    /// (not necessarily contiguous) 4 KiB pages. See `read_lba_pages`
    /// for the public-API contract. The list entries go into the
    /// persistent `prp_list` page, so no list memory is freed while the
    /// controller might still read it.
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
        if n_blocks == 0 || pages.is_empty() {
            return Ok(());
        }
        if self.dead {
            return Err(NvmeError::ControllerDead);
        }
        if !self.ns_usable {
            return Err(NvmeError::NamespaceUnusable);
        }
        if lba
            .checked_add(n_blocks as u64)
            .is_none_or(|end| end > self.nsze)
        {
            return Err(NvmeError::OutOfRange);
        }
        let bytes = n_blocks as u64 * self.lba_bytes as u64;
        if bytes > pages.len() as u64 * PAGE_SIZE {
            return Err(NvmeError::BadTransfer);
        }
        if bytes > self.max_transfer as u64 {
            return Err(NvmeError::ExceedsMaxTransfer);
        }
        if pages.iter().any(|p| p.raw() & (PAGE_SIZE - 1) != 0) {
            return Err(NvmeError::BadTransfer);
        }
        // Only the pages the transfer actually touches become PRPs.
        let used = (bytes as usize).div_ceil(PAGE_SIZE as usize);
        let pages = &pages[..used];

        let mut sqe = Sqe::zero();
        sqe.cdw0 = opcode as u32;
        sqe.nsid = self.primary_nsid;
        sqe.cdw10 = (lba & 0xFFFF_FFFF) as u32;
        sqe.cdw11 = (lba >> 32) as u32;
        sqe.cdw12 = (n_blocks - 1) as u32;
        sqe.prp1 = pages[0].raw();

        match pages.len() {
            1 => sqe.prp2 = 0,
            2 => sqe.prp2 = pages[1].raw(),
            _ => {
                // One list page holds PRPS_PER_PAGE entries; the
                // max-transfer clamp (≤ 2 MiB) keeps `pages.len() - 1`
                // within it, so no chaining is needed here.
                let entries = pages.len() - 1;
                if entries > prp::PRPS_PER_PAGE {
                    return Err(NvmeError::TooManyPages);
                }
                let list = self.prp_list.as_ref().ok_or(NvmeError::OutOfDmaMemory)?;
                // SAFETY: persistent 4 KiB coherent list page owned by
                // this controller; `&mut self` excludes other I/O and no
                // command referencing it is in flight (dead checked
                // above). `entries` ≤ PRPS_PER_PAGE.
                unsafe {
                    let entries_ptr = list.cpu_mut_ptr::<u64>();
                    for (i, p) in pages[1..].iter().enumerate() {
                        core::ptr::write_volatile(entries_ptr.add(i), p.raw());
                    }
                }
                compiler_fence(Ordering::Release);
                sqe.prp2 = list.dma_addr().raw();
            }
        }

        let qi = self.pick_queue();
        // IRQ path when this queue has a vector (#928); polled
        // submit stays the fallback for vector-less boots.
        if self.io_irq_vectors.get(qi).is_some() {
            return self.submit_sqe_irq(qi, sqe);
        }
        // The caller's pages and the persistent PRP-list page stay
        // mapped across this synchronous submit.
        self.submit_sqe_polled(qi, sqe, io_timeout_ms()).map(|_| ())
    }
}

// ── helpers ─────────────────────────────────────────────────────────

/// MSI-X table entry for the first I/O CQ: Linux `nvme_create_cq` uses
/// `vector = dev->num_vecs == 1 ? 0 : qid`, so a one-entry table shares
/// entry 0 with the admin queue.
pub fn first_io_cq_vector(msix_table_size: u16) -> u16 {
    if msix_table_size <= 1 {
        0
    } else {
        IO_QID
    }
}

/// Bounded poll for a `CSTS` predicate. Wall-clock-bounded at
/// `timeout_ms`, which bring-up derives from CAP.TO like Linux
/// `nvme_wait_ready` (NVMe 1.4 §3.1.5: the CSTS.RDY transition is
/// bounded by (CAP.TO + 1) * 500 ms; see
/// [`NvmeCaps::ready_timeout_ms`]). Returns `ControllerFailed` on
/// timeout or `ControllerFatal` if `CFS` is set during the wait.
fn wait_csts<F: Fn(u32) -> bool>(
    bar: &MmioRegion,
    timeout_ms: u64,
    ok: F,
) -> Result<(), NvmeError> {
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
        narf_time::Deadline::after_ms(timeout_ms),
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
    let base = buf.cpu_mut_ptr::<Sqe>();
    // SAFETY: caller guarantees buf is page-aligned and large
    // enough; index is bounded.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        core::ptr::write_volatile(base.add(index as usize), *sqe);
    }
}

/// Read the CQ entry at `index` without polling. Used by the
/// MSI-X-driven path which tracks completion via fire_count instead.
/// The entry is sampled phase-tag-first ([`Cqe::sample`]); the caller
/// still decides from the phase tag whether it is a fresh completion.
///
/// # Safety
/// `buf` must be a live coherent DMA buffer sized for at least
/// `index + 1` 16-byte CQEs.
unsafe fn peek_cqe(buf: &DmaBuffer, index: u16) -> Cqe {
    // Two qwords per 16-byte entry; the buffer is page-aligned.
    let base = buf.cpu_ptr::<u64>();
    Cqe::sample(|word| {
        // SAFETY: caller guarantees buf is page-aligned and large enough;
        // `word` is 0 or 1, inside entry `index`.
        u64::from_le(unsafe { core::ptr::read_volatile(base.add(index as usize * 2 + word)) })
    })
}

/// Ranges per Dataset Management command: CDW10's Number of Ranges
/// is an 8-bit 0-based field, so at most 256 (NVM Command Set
/// Specification §3.2.3).
pub const DSM_MAX_RANGES: usize = 256;
/// Bytes per Dataset Management range definition (§3.2.3 Figure 41).
const DSM_RANGE_BYTES: usize = 16;
/// CDW11 Attribute – Deallocate for Dataset Management (§3.2.3
/// Figure 40).
const DSM_CDW11_DEALLOCATE: u32 = 1 << 2;
/// Blocks per Write Zeroes command: CDW12's NLB is a 16-bit 0-based
/// field (Write Zeroes Figure 73).
const MAX_WRITE_ZEROES_BLOCKS: u64 = 0x1_0000;

const _: () = assert!(DSM_MAX_RANGES * DSM_RANGE_BYTES <= prp::NVME_CTRL_PAGE_SIZE);

/// Completions consumed from a CQ whose CID matched no waiter, across all
/// controllers (see [`note_stray_cqe`]).
static STRAY_CQE_DROPS: AtomicU64 = AtomicU64::new(0);
/// Commands declared timed out, across all controllers (see
/// [`log_cmd_timeout`]).
static CMD_TIMEOUTS: AtomicU64 = AtomicU64::new(0);

/// Stray completions dropped since boot: CQEs that were fresh at a CQ head
/// but carried a CID no waiter was matching (an outstanding AER's
/// completion is stashed, not dropped, and is not counted).
pub fn stray_cqe_drops() -> u64 {
    STRAY_CQE_DROPS.load(Ordering::Relaxed)
}

/// Command completion timeouts since boot (admin and I/O).
pub fn command_timeouts() -> u64 {
    CMD_TIMEOUTS.load(Ordering::Relaxed)
}

/// Whether the `n`th occurrence of a repeating event is logged: the 1st,
/// 10th, 100th, ... so a storm cannot flood the console.
fn log_due_decade(n: u64) -> bool {
    let mut p = 1u64;
    loop {
        if p == n {
            return true;
        }
        if p > n / 10 {
            return false;
        }
        p *= 10;
    }
}

/// Count, and (rate-limited) report, a completion that was consumed from
/// queue `qid` at CQ index `head` under phase tag `phase` while the waiter
/// was matching `expected_cid` (`None`: nobody was waiting on the queue at
/// all — see [`Controller::drain_aer_events`]). Linux `nvme_handle_cqe` warns "invalid id
/// %d completed on queue %d" for the same event. With one command in
/// flight per controller a stray means the device completed a command the
/// host no longer tracks (a late completion of a timed-out command) or
/// posted a corrupt entry — either way worth knowing about.
fn note_stray_cqe(bar: u64, qid: u16, head: u16, phase: u16, expected_cid: Option<u16>, cqe: &Cqe) {
    use core::fmt::Write as _;
    let n = STRAY_CQE_DROPS.fetch_add(1, Ordering::Relaxed) + 1;
    if log_due_decade(n) {
        let mut w = narf_console::Writer;
        let _ = write!(
            w,
            "nvme: bar {bar:#x}: WARNING: stray completion dropped on queue {qid} \
             (cq head {head}, phase {}): ",
            phase & 1
        );
        let _ = match expected_cid {
            Some(cid) => write!(w, "expected cid {cid:#06x}"),
            None => write!(w, "no command waiting"),
        };
        let _ = writeln!(
            w,
            ", seen cid {:#06x} sqid {} sqhd {} status {:#06x} result {:#010x} (stray #{n})",
            cqe.cid,
            cqe.sq_id,
            cqe.sq_head,
            cqe.status >> 1,
            cqe.cmd_specific,
        );
    }
}

/// Count and report a command completion timeout where it is declared:
/// the command (`opcode`, `cid`, queue), what the CQ head holds right now,
/// CSTS, the queue's interrupt vector with its `fire_count` (and how many
/// times it fired since the command was submitted, when the caller sampled
/// `fires_at_submit`), this CPU's interrupt state and the elapsed time
/// since `started` (`now_cycles` at submission). Linux `nvme_timeout`
/// prints the same class of line ("I/O tag %d (%04x) opcode %#x (%s) QID
/// %d timeout"). Not rate-limited: every timeout costs its whole budget
/// first.
fn log_cmd_timeout(
    bar0: &MmioRegion,
    q: &Queue,
    opcode: u8,
    cid: u16,
    vector: Option<u8>,
    fires_at_submit: Option<u64>,
    started: Option<u64>,
) {
    use core::fmt::Write as _;
    let n = CMD_TIMEOUTS.fetch_add(1, Ordering::Relaxed) + 1;
    // SAFETY: cq_buf is the queue's live coherent CQ page; cq_head < depth.
    let head = unsafe { peek_cqe(&q.cq_buf, q.cq_head) };
    // SAFETY: BAR0 is this controller's mapped register window; CSTS is a
    // read-only, side-effect-free register.
    let csts = unsafe { bar0.read32(REG_CSTS) };
    let fresh = (head.status & 1) == (q.cq_phase & 1);
    let mut w = narf_console::Writer;
    let _ = write!(
        w,
        "nvme: bar {:#x}: ERROR: command timeout #{n}: opcode {opcode:#04x} cid {cid:#06x} \
         queue {}",
        bar0.phys.raw(),
        q.qid,
    );
    match started {
        Some(t) => {
            let ms = narf_time::cycles_to_ns(narf_time::now_cycles().saturating_sub(t)) / 1_000_000;
            let _ = write!(w, " after {ms} ms");
        }
        None => {
            let _ = write!(w, " (elapsed n/a)");
        }
    }
    let _ = write!(
        w,
        "; cq head {} phase {} head-cqe[{} cid {:#06x} sqid {} sqhd {} status {:#06x}]; \
         sq tail {}; csts {csts:#x}",
        q.cq_head,
        q.cq_phase & 1,
        if fresh { "FRESH" } else { "stale" },
        head.cid,
        head.sq_id,
        head.sq_head,
        head.status >> 1,
        q.sq_tail,
    );
    match vector {
        Some(v) => {
            let fires = narf_interrupts::fire_count(v);
            let _ = write!(w, "; vector {v} fire_count {fires}");
            if let Some(f0) = fires_at_submit {
                let _ = write!(w, " (+{} since submit)", fires.saturating_sub(f0));
            }
        }
        None => {
            let _ = write!(w, "; vector none (polled)");
        }
    }
    let _ = writeln!(
        w,
        "; irqs {}{}",
        if narf_memory::context::irqs_enabled() {
            "enabled"
        } else {
            "DISABLED"
        },
        if narf_lib::context::in_irq() {
            ", in irq"
        } else {
            ""
        },
    );
}

/// Commands whose completion was only found by the last look at the CQ
/// after their budget ran out (see [`note_late_completion`]).
static LATE_COMPLETIONS: AtomicU64 = AtomicU64::new(0);
/// Timed-out block requests replayed after a controller reset (see
/// [`run_with_replay`]).
static IO_REPLAYS: AtomicU64 = AtomicU64::new(0);

/// Commands since boot whose completion was found by the final CQ poll at
/// timeout rather than by the wait (Linux "timeout, completion polled").
pub fn late_completions() -> u64 {
    LATE_COMPLETIONS.load(Ordering::Relaxed)
}

/// Block requests replayed after a timeout + controller reset since boot.
pub fn io_replays() -> u64 {
    IO_REPLAYS.load(Ordering::Relaxed)
}

/// Count and report a command that ran out its budget but whose completion
/// was sitting in the CQ at the last look. It completed, so nothing is
/// reset or replayed — but the wait missed it, which on an IRQ-driven
/// queue means the interrupt and the phase check both failed to end the
/// wait in time. Linux `nvme_timeout`: "I/O tag %d (%04x) QID %d timeout,
/// completion polled".
fn note_late_completion(bar: u64, qid: u16, opcode: u8, cid: u16, started: u64) {
    use core::fmt::Write as _;
    let n = LATE_COMPLETIONS.fetch_add(1, Ordering::Relaxed) + 1;
    let ms = narf_time::cycles_to_ns(narf_time::now_cycles().saturating_sub(started)) / 1_000_000;
    let _ = writeln!(
        narf_console::Writer,
        "nvme: bar {bar:#x}: WARNING: opcode {opcode:#04x} cid {cid:#06x} queue {qid} timed out \
         after {ms} ms, completion polled (late completion #{n})"
    );
}

/// Completion budget for admin commands (bring-up, namespace scan, queue
/// creation, passthrough). Deliberately NOT Linux's 60 s `admin_timeout`:
/// bring-up runs synchronously on the boot path, and an absent or broken
/// controller must fail its probe in seconds, not minutes. Admin commands
/// are never replayed.
const CQE_TIMEOUT_MS: u64 = 5_000;
/// Completion budget for every I/O-queue command — Read, Write, Flush,
/// Dataset Management, Write Zeroes: Linux `nvme_io_timeout` /
/// `NVME_IO_TIMEOUT`, 30 s. A healthy drive can legitimately take seconds
/// (garbage collection, a large cache flush, a power-state exit); 5 s was
/// short enough to fail a write inside a filesystem commit.
pub const IO_TIMEOUT_MS: u64 = 30_000;
/// How many times a timed-out block request is replayed after the
/// controller was reset, before the error is returned: Linux
/// `nvme_max_retries` (5). See [`run_with_replay`].
pub const IO_MAX_RETRIES: u32 = 5;

/// Test hook: when nonzero, the I/O completion budget in milliseconds
/// instead of [`IO_TIMEOUT_MS`]. Only the in-kernel smokes set it.
#[doc(hidden)]
pub static IO_TIMEOUT_MS_FOR_TEST: AtomicU64 = AtomicU64::new(0);
/// Test hook: the next N I/O-queue commands are *lost* — the SQE is
/// written but the SQ doorbell is not rung, so the device never sees the
/// command and no completion ever arrives. Only the in-kernel smokes set
/// it.
#[doc(hidden)]
pub static IO_LOSE_FOR_TEST: AtomicU32 = AtomicU32::new(0);
/// Test hook: the next N I/O-queue commands complete *late* — the command
/// is submitted normally but the wait ignores the CQ until the budget is
/// spent, so only the last look at the CQ can find the completion. Only
/// the in-kernel smokes set it.
#[doc(hidden)]
pub static IO_LATE_FOR_TEST: AtomicU32 = AtomicU32::new(0);

/// The I/O completion budget in force: [`IO_TIMEOUT_MS`] unless a smoke
/// shortened it.
#[inline]
fn io_timeout_ms() -> u64 {
    match IO_TIMEOUT_MS_FOR_TEST.load(Ordering::Relaxed) {
        0 => IO_TIMEOUT_MS,
        ms => ms,
    }
}

/// Consume one injected fault from `counter`, if any is armed. One relaxed
/// load when none is — the production cost of the hooks.
#[inline]
fn take_test_fault(counter: &AtomicU32) -> bool {
    if counter.load(Ordering::Relaxed) == 0 {
        return false;
    }
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |n| n.checked_sub(1))
        .is_ok()
}

/// Spin until CQ entry `index` has the expected phase tag, then return it;
/// `CompletionTimeout` after `timeout_ms`.
///
/// # Safety
/// `buf` must be a live coherent DMA buffer sized for at least
/// `index + 1` 16-byte CQEs.
unsafe fn wait_cqe_ms(
    buf: &DmaBuffer,
    index: u16,
    expected_phase: u16,
    timeout_ms: u64,
) -> Result<Cqe, NvmeError> {
    // responsive_spin_until keeps cursor/FB/serial alive on a slow
    // or stuck controller, and re-checks the condition once after the
    // deadline, so an entry that turned fresh at the very end is not
    // reported as a timeout.
    let done = narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: caller guarantees buf is page-aligned and large
            // enough; index is bounded.
            let cqe = unsafe { peek_cqe(buf, index) };
            (cqe.status & 1) == (expected_phase & 1)
        },
        narf_time::Deadline::after_ms(timeout_ms),
    );
    if !done {
        return Err(NvmeError::CompletionTimeout);
    }
    // The phase tag was seen fresh above, so the entry is complete.
    // SAFETY: caller guarantees buf is page-aligned and large enough.
    Ok(unsafe { peek_cqe(buf, index) })
}

/// Pull our subset of fields out of the IDENTIFY CONTROLLER page.
///
/// # Safety
/// `buf` must point to a 4096-byte coherent DMA buffer the controller
/// has finished writing to (CQE arrived).
unsafe fn parse_identify(buf: &DmaBuffer) -> IdentifyController {
    let base = buf.cpu_ptr::<u8>();
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
        // SAFETY: byte 77 of the same 4 KiB page.
        mdts: unsafe { core::ptr::read_volatile(base.add(77)) },
        // SAFETY: bytes 80..84 / 516..520 of the same 4 KiB page, 4-aligned.
        ver: unsafe { core::ptr::read_volatile(base.add(80) as *const u32) },
        // SAFETY: as above.
        nn: unsafe { core::ptr::read_volatile(base.add(516) as *const u32) },
        // SAFETY: bytes 88..92 of the same page, 4-aligned.
        rtd3e: unsafe { core::ptr::read_volatile(base.add(88) as *const u32) },
        // SAFETY: byte 525 of the same page.
        vwc: unsafe { core::ptr::read_volatile(base.add(525)) },
        // SAFETY: bytes 256..258 of the same page, 2-aligned.
        oncs: read_u16(256),
    }
}

/// [`shutdown::CtrlRegs`] over a controller's BAR0.
struct BarRegs(MmioRegion);

impl shutdown::CtrlRegs for BarRegs {
    fn read_cc(&self) -> u32 {
        // SAFETY: BAR0 of a controller the caller holds exclusively.
        unsafe { self.0.read32(REG_CC) }
    }
    fn write_cc(&self, v: u32) {
        // SAFETY: as above.
        unsafe { self.0.write32(REG_CC, v) }
    }
    fn read_csts(&self) -> u32 {
        // SAFETY: as above.
        unsafe { self.0.read32(REG_CSTS) }
    }
}

/// Admin Identify (opcode 0x06, `cns`, `nsid`) into the 4 KiB DMA `page`.
/// The page is zeroed first so a short structure never leaves stale bytes.
fn admin_identify(
    admin: &mut Queue,
    bar0: &MmioRegion,
    nsid: u32,
    cns: u8,
    page: &DmaBuffer,
) -> Result<(), NvmeError> {
    // SAFETY: `page` is a live 4 KiB coherent buffer no command currently
    // targets (the previous Identify into it completed).
    unsafe { core::ptr::write_bytes(page.cpu_mut_ptr::<u8>(), 0, 4096) };
    compiler_fence(Ordering::Release);
    let mut sqe = Sqe::zero();
    sqe.cdw0 = AdminOpcode::Identify as u32;
    sqe.nsid = nsid;
    sqe.prp1 = page.dma_addr().raw();
    sqe.cdw10 = cns as u32;
    // SAFETY: the admin queue and BAR0 are live (bring-up, CC.EN=1, RDY=1).
    unsafe { admin.submit(bar0, sqe) }.map(|_| ())
}

/// Copy the 4 KiB Identify result out of `page`.
fn identify_page_bytes(page: &DmaBuffer) -> Vec<u8> {
    compiler_fence(Ordering::Acquire);
    let mut raw = alloc::vec![0u8; 4096];
    // SAFETY: the controller finished writing `page` (its CQE was consumed);
    // `raw` is a fresh heap buffer that cannot overlap it.
    unsafe { core::ptr::copy_nonoverlapping(page.cpu_ptr::<u8>(), raw.as_mut_ptr(), 4096) };
    raw
}

/// Linux `nvme_scan_work`: list the active NSIDs (Active Namespace List
/// from NVMe 1.1, `1..=NN` before or when the list command fails), Identify
/// each, keep those with capacity and a usable format, and read their
/// identification descriptors (NVMe 1.3+).
///
/// A command the controller completes with an error status skips that
/// namespace (or that step). Any other failure — a completion timeout, a
/// fatal status — aborts the scan and hands the Identify page back with the
/// error: the controller may still DMA into it, so the caller parks it in
/// `in_flight_dma` until `disable_after_failure` proves the controller
/// stopped (and leaks it if it does not).
#[allow(clippy::type_complexity)]
fn scan_namespaces(
    admin: &mut Queue,
    bar0: &MmioRegion,
    vs: u32,
    nn: u32,
) -> Result<Vec<ns::NamespaceInfo>, (NvmeError, Option<DmaBuffer>)> {
    use core::fmt::Write as _;
    let page =
        alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| (NvmeError::OutOfDmaMemory, None))?;
    let fatal = |e: NvmeError| !matches!(e, NvmeError::CommandFailed { .. });

    // ── Which NSIDs ────────────────────────────────────────────────
    let mut nsids: Option<Vec<u32>> = None;
    if ns::use_ns_list(vs) {
        let mut list = Vec::new();
        let mut start = 0u32;
        let mut ok = true;
        loop {
            match admin_identify(admin, bar0, start, admin::CNS_NAMESPACE_LIST, &page) {
                Ok(()) => {}
                Err(e) if fatal(e) => return Err((e, Some(page))),
                Err(_) => {
                    ok = false;
                    break;
                }
            }
            let chunk = ns::decode_ns_list(&identify_page_bytes(&page));
            // Ascending and above `start`, or the device is confused.
            let n = chunk.len();
            let last = chunk.last().copied();
            list.extend(chunk.into_iter().filter(|&id| id > start));
            match last {
                Some(l)
                    if n == 1024 && l > start && (list.len() as u32) < ns::MAX_SCANNED_NSIDS =>
                {
                    start = l
                }
                _ => break,
            }
        }
        if ok {
            list.truncate(ns::MAX_SCANNED_NSIDS as usize);
            nsids = Some(list);
        }
    }
    let nsids = nsids.unwrap_or_else(|| (1..=nn.min(ns::MAX_SCANNED_NSIDS)).collect());

    // ── Identify each ──────────────────────────────────────────────
    let mut out = Vec::new();
    for nsid in nsids {
        match admin_identify(admin, bar0, nsid, admin::CNS_NAMESPACE, &page) {
            Ok(()) => {}
            Err(e) if fatal(e) => return Err((e, Some(page))),
            Err(_) => continue,
        }
        let mut info = match ns::classify_namespace(nsid, &identify_page_bytes(&page)) {
            Ok(info) => info,
            Err(why) => {
                let _ = writeln!(narf_console::Writer, "nvme: nsid {nsid} skipped: {why:?}");
                continue;
            }
        };
        if ns::use_ns_descriptors(vs) {
            match admin_identify(
                admin,
                bar0,
                nsid,
                admin::CNS_NAMESPACE_DESCRIPTOR_LIST,
                &page,
            ) {
                Ok(()) => ns::apply_ns_descriptors(&identify_page_bytes(&page), &mut info.ids),
                Err(e) if fatal(e) => return Err((e, Some(page))),
                Err(_) => {}
            }
        }
        out.push(info);
    }
    drop(page);
    Ok(out)
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

/// Async `BlockDevice` adapter for the first NVMe controller (`nvme0`).
///
/// Sibling of `NvmeBlockSync` — both reach instance 0's slot in
/// `CONTROLLERS` (populated by `probe`); this one satisfies the async `block::BlockDevice`
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
/// Transfer size: a request may cover any number of blocks its
/// (physically contiguous) buffer holds; `submit` splits it into
/// commands of at most [`Controller::max_transfer_bytes`] and builds
/// PRP1 / PRP2 / a PRP list for each (see [`prp`]).
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
        with_controller(|c| if c.ns_usable { c.nsze } else { 0 }).unwrap_or(0)
    }
    fn supports(&self, f: BlockFeature) -> bool {
        // Flush + Fua hit real NVMe opcodes (Flush 0x00, FUA bit in
        // Write CDW12) unconditionally. Discard and WriteZeroes are
        // claimed exactly when the probed controller's Identify
        // ONCS says it implements the opcode (Dataset Management /
        // Write Zeroes) — claiming either without it told the FS
        // layer a deallocation / zeroing had a device path when
        // none existed (#927, #841).
        match f {
            BlockFeature::Flush | BlockFeature::Fua => true,
            BlockFeature::Discard => {
                with_controller(|c| c.supports_dataset_mgmt()).unwrap_or(false)
            }
            BlockFeature::WriteZeroes => {
                with_controller(|c| c.supports_write_zeroes()).unwrap_or(false)
            }
            _ => false,
        }
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
    /// NVMe Flush of the primary namespace when the controller has a
    /// volatile write cache (see [`Controller::flush_nsid`]).
    async fn flush(&self) {
        let _ = nvme_flush_primary();
    }
    fn flush_result(&self) -> impl Future<Output = Result<(), BlockError>> + Send {
        let r = nvme_flush_primary();
        async move { r }
    }
    async fn discard(&self, r: LbaRange) {
        // Fire-and-forget at the trait, but the Dataset Management
        // command (AD=1) is really issued whenever the controller
        // supports it; an error is dropped here and surfaces on the
        // `submit` path (`BlockOp::Trim`), as with `SyncBlock`. A
        // controller without ONCS Dataset Management never has
        // Discard advertised, so no caller can be misled into
        // believing a range was deallocated when it was not (#927).
        let _ = nvme_discard_primary(&[r]);
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
    if req.blocks == 0 {
        return Ok(());
    }
    // Interrupts stay enabled for the whole transfer: hold the
    // device's request gate, not the IRQ-masking CONTROLLERS lock.
    // See `InstalledController`.
    let slot = slot_of(0).ok_or(BlockError::DeviceRemoved)?;
    let mut ctrl = acquire(slot).map_err(map_nvme_err)?;
    if ctrl.is_dead() {
        // An earlier request left the controller dead (its replays ran
        // out, or the reset at the timeout failed). Try the reset again
        // before refusing this request too (see `recover_slot`). The
        // guard is dropped first: recovery takes the gate itself.
        drop(ctrl);
        recover_slot(0).map_err(map_nvme_err)?;
        ctrl = probed_controller().ok_or(BlockError::DeviceRemoved)?;
    }
    // Trim and WriteZeroes move no data: they issue their own
    // opcodes against the namespace and never touch the request's
    // buffer (the pre-fix code wrote the buffer's stale contents
    // for WriteZeroes and silently succeeded for Trim, #927). A
    // controller without the ONCS bit fails the request via
    // `NvmeError::NotImplemented` — never a silent success.
    let (opcode, fua, what) = match req.op {
        BlockOp::Read => (IoOpcode::Read as u8, false, "read"),
        BlockOp::Write { fua } => (IoOpcode::Write as u8, fua, "write"),
        BlockOp::Trim => {
            return run_with_replay(slot, ctrl, "discard", |ctrl| {
                let ns = ctrl.primary_geom();
                ctrl.dataset_mgmt_ns(
                    ns,
                    &[LbaRange {
                        start: req.lba,
                        blocks: req.blocks as u64,
                    }],
                )
            })
            .map_err(map_nvme_err);
        }
        BlockOp::WriteZeroes => {
            return run_with_replay(slot, ctrl, "write-zeroes", |ctrl| {
                let ns = ctrl.primary_geom();
                ctrl.write_zeroes_ns(ns, req.lba, req.blocks as u64)
            })
            .map_err(map_nvme_err);
        }
    };
    let lba_bytes = ctrl.lba_bytes as u64;
    let total_bytes = (req.blocks as u64)
        .checked_mul(lba_bytes)
        .ok_or(BlockError::InvalidRange)?;
    if (buffer.len() as u64) < total_bytes {
        return Err(BlockError::InvalidRange);
    }
    // `alloc_coherent` buffers are physically contiguous, so each
    // command takes a window of the buffer and the PRPs are built over
    // it. Split at the controller's maximum transfer (MDTS), the way
    // the Linux block layer splits at `max_hw_sectors`.
    //
    // A replay (see `run_with_replay`) restarts the request at its first
    // block. The buffer is the caller's, pinned by the `Arc` for this
    // whole call and written by nobody else: a write's payload is intact
    // for the replay, and a read's destination is simply filled again.
    let result = run_with_replay(slot, ctrl, what, |ctrl| {
        let per_cmd = core::cmp::max(1, ctrl.max_transfer_bytes() as u64 / lba_bytes) as u32;
        let mut done: u32 = 0;
        while done < req.blocks {
            let n = core::cmp::min(per_cmd, req.blocks - done);
            let ns = ctrl.primary_geom();
            ctrl.nvm_io_ns_at(
                ns,
                fua,
                opcode,
                req.lba.saturating_add(done as u64),
                n,
                &buffer,
                (done as u64 * lba_bytes) as usize,
            )?;
            done += n;
        }
        Ok(())
    });
    if matches!(result, Err(NvmeError::CompletionTimeout)) {
        retain_buffer_while_device_live(slot, &buffer);
    }
    result.map_err(map_nvme_err)
}

/// Request buffers kept alive forever because a timed-out command might
/// still DMA into them (see [`retain_buffer_while_device_live`]).
static RETAINED_IO_BUFFERS: AtomicU64 = AtomicU64::new(0);

/// Buffers leaked since boot to keep a possibly-live command's DMA target
/// from being recycled.
pub fn retained_io_buffers() -> u64 {
    RETAINED_IO_BUFFERS.load(Ordering::Relaxed)
}

/// A request on `slot` using the caller's `buffer` failed with a command
/// timeout. Linux `nvme_timeout` disables the controller
/// (`nvme_dev_disable`) before it completes the request, so the request's
/// pages are never handed back under a live command; here the reset at the
/// timeout site ([`run_with_replay`]) normally does the same. When it
/// could not — the controller is still dead and was never confirmed
/// disabled (CSTS.RDY would not drop, the function is gone, the final
/// shutdown has begun, or the gate cannot even be taken to find out) —
/// the device may yet write a late read's data into the buffer, so one
/// reference to it is leaked: the memory can then never be recycled under
/// that write, exactly as [`Controller::disable_after_failure`] leaks the
/// queues when RDY never clears.
fn retain_buffer_while_device_live(
    slot: &'static InstalledController,
    buffer: &alloc::sync::Arc<DmaBuffer>,
) {
    use core::fmt::Write as _;
    let quiet = acquire(slot).is_ok_and(|ctrl| !ctrl.may_still_dma());
    if quiet {
        return;
    }
    core::mem::forget(alloc::sync::Arc::clone(buffer));
    RETAINED_IO_BUFFERS.fetch_add(1, Ordering::Relaxed);
    let _ = writeln!(
        narf_console::Writer,
        "nvme: {}: ERROR: controller not confirmed disabled after a command timeout; \
         keeping the request's {} byte DMA buffer alive forever (the device may still write it)",
        ns::controller_name(slot.instance),
        buffer.len(),
    );
}

/// Dataset Management (Deallocate) over `ranges` of the primary
/// namespace of controller instance 0 — the async `discard` path.
fn nvme_discard_primary(ranges: &[LbaRange]) -> Result<(), BlockError> {
    let slot = slot_of(0).ok_or(BlockError::DeviceRemoved)?;
    let mut ctrl = acquire(slot).map_err(map_nvme_err)?;
    if ctrl.is_dead() {
        // Same dead-controller recovery as the submit path.
        drop(ctrl);
        recover_slot(0).map_err(map_nvme_err)?;
        ctrl = probed_controller().ok_or(BlockError::DeviceRemoved)?;
    }
    run_with_replay(slot, ctrl, "discard", |ctrl| {
        let ns = ctrl.primary_geom();
        ctrl.dataset_mgmt_ns(ns, ranges)
    })
    .map_err(map_nvme_err)
}

fn nvme_flush_primary() -> Result<(), BlockError> {
    let slot = slot_of(0).ok_or(BlockError::DeviceRemoved)?;
    let mut ctrl = acquire(slot).map_err(map_nvme_err)?;
    if ctrl.is_dead() {
        // Same dead-controller recovery as the submit path.
        drop(ctrl);
        recover_slot(0).map_err(map_nvme_err)?;
        ctrl = probed_controller().ok_or(BlockError::DeviceRemoved)?;
    }
    run_with_replay(slot, ctrl, "flush", |ctrl| {
        let nsid = ctrl.primary_nsid;
        ctrl.flush_nsid(nsid)
    })
    .map_err(map_nvme_err)
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

/// Heap slot for one installed controller, leaked at install time.
///
/// Why a leaked slot instead of `IrqSafeSpinLock<Option<Controller>>`:
/// every NVMe I/O is a device round-trip — submit an SQE, then
/// wait on the CQ for up to 30 s ([`IO_TIMEOUT_MS`]). Holding an
/// `IrqSafeSpinLock` across that transfer masks interrupts on the
/// waiting CPU for the whole round-trip and forces every other CPU
/// doing I/O to spin on the same lock, also interrupts-masked. Under a
/// filesystem workload that starves timers and RCU and livelocks the
/// machine — the stall watchdog caught three CPUs `SPIN-NOT-POLLING`
/// on exactly this pattern in virtio-blk, and adding vCPUs makes it
/// worse (thundering herd, not a race).
///
/// The fix splits the two things the lock was serialising:
///  - *Finding* the controller: `CONTROLLERS` is taken only long enough
///    to copy a slot's `&'static` reference out, then released.
///  - *Using* the controller: `req_gate`, a plain atomic spun on
///    without changing the caller's interrupt state. Contended process
///    callers yield so a descheduled holder can run; masked callers service
///    pending cross-CPU work instead of stranding its acknowledgements.
///
/// One slot per controller (Linux: one `struct nvme_dev` per PCI
/// function, `nvme_probe` in `drivers/nvme/host/pci.c`). Each slot owns
/// its controller's BAR mapping, admin and I/O queues, MSI-X vectors, PRP
/// list and DMA scratch; two controllers never share a gate or a buffer,
/// so I/O to `nvme0` and `nvme1` proceeds in parallel.
///
/// The `UnsafeCell` is what makes handing out `&mut Controller` sound:
/// the slot reference is `&'static` (never moves, never drops — even a
/// kernel-test reinstall via [`install_controller`] leaks the old slot
/// rather than dropping it, so a stale reference can dangle only
/// logically, never point at freed memory), and `req_gate` guarantees
/// at most one `ControllerGuard` — hence at most one live `&mut` —
/// exists per slot at a time.
struct InstalledController {
    /// Serialises device round-trips and all references into `ctrl`.
    /// Acquired by [`acquire`] without changing the caller's interrupt state.
    req_gate: AtomicBool,
    /// Who took `req_gate` last: CPU in bits 63:48, scheduler task id (0 =
    /// outside any task poll) in bits 47:0. Diagnostic only — written right
    /// after the gate is won, read unsynchronised by waiters that have
    /// been waiting long enough to report ([`GateWait`]).
    gate_owner: AtomicU64,
    /// `narf_time::now_cycles()` when `req_gate` was last taken. Diagnostic
    /// only, as `gate_owner`.
    gate_since: AtomicU64,
    /// `narf_time::now_cycles()` of the holder's last progress mark
    /// ([`mark_gate_progress`]): a holder that legitimately keeps the gate
    /// across a reset and a replay is not a stalled holder.
    gate_progress: AtomicU64,
    /// Probe-order instance: the controller is `nvme<instance>`.
    instance: u32,
    /// PCI function this slot drives (`None` for a device-less test
    /// controller). Re-probing the same function is a no-op.
    bdf: Option<narf_bus::PcieAddr>,
    /// Set by [`remove_controller`]: every later I/O is refused.
    removed: AtomicBool,
    /// Command timeouts on this controller since a command last completed
    /// — the replay budget of [`run_with_replay`]. Written only under
    /// `req_gate`.
    timeout_streak: AtomicU32,
    /// This controller's DMA scratch for the sync block path, leaked on
    /// first use. Its contents are serialised by `req_gate`; this lock
    /// only covers the lazy init.
    scratch: IrqSafeSpinLock<Option<&'static DmaBuffer>>,
    /// BAR0 and the CC.SHN wait budget, copied out of the live controller
    /// so the final shutdown can still send CC.SHN — a register write
    /// that touches no queue state — when an in-flight command never
    /// releases `req_gate` (Linux `nvme_dev_disable` disables the
    /// controller after its freeze timeout whatever is still
    /// outstanding). `None` before bring-up. Behind a lock because
    /// resume's re-init replaces the BAR mapping and must refresh the
    /// pair (`resume_slot`); install and the final shutdown are the
    /// only other accessor / reader.
    shutdown_regs: IrqSafeSpinLock<Option<(MmioRegion, u64)>>,
    ctrl: UnsafeCell<Controller>,
}

// SAFETY: all access to `ctrl` goes through `req_gate` (see `acquire` —
// the only constructor of references into the cell), which admits one
// holder at a time; `Controller` itself is Send (asserted below), so
// migrating that exclusive access across CPUs is fine.
unsafe impl Sync for InstalledController {}

const _: () = {
    const fn assert_send<T: Send>() {}
    assert_send::<Controller>()
};

/// Every installed controller, indexed by position; `instance` equals the
/// position (slots are only appended or replaced in place). Held only long
/// enough to copy a `&'static` slot reference out — NEVER across a device
/// round-trip. See [`InstalledController`].
static CONTROLLERS: IrqSafeSpinLock<Vec<&'static InstalledController>> =
    IrqSafeSpinLock::new(Vec::new());

fn controller_bdf(ctrl: &Controller) -> Option<narf_bus::PcieAddr> {
    match ctrl.device?.addr {
        narf_bus::BusAddr::Pcie(a) => Some(a),
        _ => None,
    }
}

/// The `(BAR0, CC.SHN wait budget)` pair the final shutdown's forced
/// path needs, copied out of the live controller. Recomputed whenever a
/// bring-up replaces the controller's BAR mapping: at install
/// ([`leak_slot`]) and after a PM resume ([`resume_slot`]).
fn shutdown_regs_of(ctrl: &Controller) -> Option<(MmioRegion, u64)> {
    ctrl.bar0_region.map(|bar| {
        (
            bar,
            shutdown::shutdown_timeout_ms(ctrl.identify.map(|i| i.rtd3e).unwrap_or(0)),
        )
    })
}

fn leak_slot(
    instance: u32,
    bdf: Option<narf_bus::PcieAddr>,
    ctrl: Controller,
) -> &'static InstalledController {
    let shutdown_regs = shutdown_regs_of(&ctrl);
    alloc::boxed::Box::leak(alloc::boxed::Box::new(InstalledController {
        req_gate: AtomicBool::new(false),
        gate_owner: AtomicU64::new(0),
        gate_since: AtomicU64::new(0),
        gate_progress: AtomicU64::new(0),
        instance,
        bdf,
        removed: AtomicBool::new(false),
        timeout_streak: AtomicU32::new(0),
        scratch: IrqSafeSpinLock::new(None),
        shutdown_regs: IrqSafeSpinLock::new(shutdown_regs),
        ctrl: UnsafeCell::new(ctrl),
    }))
}

/// Install `ctrl` and return its instance number. A slot already driving
/// the same PCI function is replaced (and leaked) in place, keeping its
/// instance — the kernel-test harness's reinstall path. A controller with
/// no bus device replaces instance 0. Anything else is appended as the
/// next instance.
///
/// Old slots are deliberately leaked, not dropped: a concurrent I/O path
/// may still hold a `ControllerGuard` against one, and freeing it under
/// that guard would be a use-after-free reachable only under load. Outside
/// the harness every probe installs a new function exactly once, so
/// nothing accumulates.
pub(crate) fn install_controller(ctrl: Controller) -> u32 {
    let bdf = controller_bdf(&ctrl);
    let mut g = CONTROLLERS.lock();
    let pos = match bdf {
        Some(b) => g.iter().position(|s| s.bdf == Some(b)),
        None => (!g.is_empty()).then_some(0),
    };
    match pos {
        Some(i) => {
            let instance = g[i].instance;
            g[i] = leak_slot(instance, bdf, ctrl);
            instance
        }
        None => {
            let instance = g.len() as u32;
            g.push(leak_slot(instance, bdf, ctrl));
            instance
        }
    }
}

fn slot_of(instance: u32) -> Option<&'static InstalledController> {
    // Final shutdown has begun: no new request reaches any controller
    // (Linux `nvme_dev_disable` freezes the queues before it disables).
    if SHUTTING_DOWN.load(Ordering::Acquire) {
        return None;
    }
    let s = CONTROLLERS.lock().get(instance as usize).copied()?;
    (!s.removed.load(Ordering::Acquire)).then_some(s)
}

/// Set once [`shutdown_all_controllers`] starts; never cleared (the next
/// thing after it is the platform reset / S5).
static SHUTTING_DOWN: AtomicBool = AtomicBool::new(false);

/// Exclusive handle to one installed controller for one device
/// round-trip. Holds the slot's `req_gate`, NOT the `CONTROLLERS`
/// spinlock — the caller's interrupt state is preserved.
pub struct ControllerGuard {
    slot: &'static InstalledController,
}

impl core::fmt::Debug for ControllerGuard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ControllerGuard")
            .field("instance", &self.slot.instance)
            .finish_non_exhaustive()
    }
}

impl core::ops::Deref for ControllerGuard {
    type Target = Controller;
    fn deref(&self) -> &Controller {
        // SAFETY: `req_gate` is held (only `acquire` builds a guard, and it
        // acquires the gate first), so no other reference into the cell
        // exists; the slot itself is `&'static` and never freed.
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

/// How long a gate waiter waits before it first reports the holder.
pub const GATE_STALL_WARN_MS: u64 = 2_000;
/// Interval between a waiter's further reports while it keeps waiting.
pub const GATE_STALL_REPORT_EVERY_MS: u64 = 10_000;
/// A gate waiter gives up with [`NvmeError::GateTimeout`] once the gate has
/// been held, with no progress mark from its holder, for this long while
/// the waiter waited. Twice the I/O budget ([`IO_TIMEOUT_MS`]): the longest
/// a healthy holder goes between marks is one command's budget (a reset
/// and every replay mark progress), so only a holder that is not running
/// at all — or a controller whose reset itself is taking minutes — trips
/// it.
pub const GATE_STALL_FAIL_MS: u64 = 60_000;

/// Test hooks: when nonzero, replace [`GATE_STALL_WARN_MS`] /
/// [`GATE_STALL_FAIL_MS`]. Read only by a waiter that is already
/// contended, never on the uncontended path.
#[doc(hidden)]
pub static GATE_STALL_WARN_MS_FOR_TEST: AtomicU64 = AtomicU64::new(0);
#[doc(hidden)]
pub static GATE_STALL_FAIL_MS_FOR_TEST: AtomicU64 = AtomicU64::new(0);

/// Gate-stall reports logged, and gate waits that failed, since boot.
static GATE_STALL_REPORTS: AtomicU64 = AtomicU64::new(0);
static GATE_TIMEOUTS: AtomicU64 = AtomicU64::new(0);

/// Times a waiter reported a long wait for a controller's request gate.
pub fn gate_stall_reports() -> u64 {
    GATE_STALL_REPORTS.load(Ordering::Relaxed)
}

/// Gate waits that ended in [`NvmeError::GateTimeout`].
pub fn gate_timeouts() -> u64 {
    GATE_TIMEOUTS.load(Ordering::Relaxed)
}

/// Bits of `gate_owner` holding the task id; the CPU sits above them.
const GATE_OWNER_TASK_BITS: u32 = 48;

/// This context as a `gate_owner` word.
#[inline]
fn gate_owner_word() -> u64 {
    let cpu = narf_lib::percpu::current_cpu() as u64;
    let task = narf_scheduler::current_task_id().raw();
    (cpu << GATE_OWNER_TASK_BITS) | (task & ((1 << GATE_OWNER_TASK_BITS) - 1))
}

/// Try once to take `slot`'s gate; on success record who holds it and
/// since when. The record is the whole hot-path cost of the stall
/// diagnostics: two relaxed stores (plus one TSC read and two per-CPU
/// reads) per acquisition — no lock, no branch on the wait state, nothing
/// on release. Every acquisition goes through here, including the
/// shutdown / suspend / resume drains that poll the gate themselves.
#[inline]
fn try_take_gate(slot: &InstalledController) -> bool {
    if slot
        .req_gate
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return false;
    }
    slot.gate_owner.store(gate_owner_word(), Ordering::Relaxed);
    slot.gate_since
        .store(narf_time::now_cycles(), Ordering::Relaxed);
    true
}

/// Mark progress by the gate's holder: it is alive and moving (a reset
/// finished, a replay is starting), so waiters measure the stall from
/// here. Called under the gate.
fn mark_gate_progress(slot: &InstalledController) {
    slot.gate_progress
        .store(narf_time::now_cycles(), Ordering::Relaxed);
}

/// One contended wait for a gate: when it began and when it next reports.
/// Created only after the first spin round failed.
struct GateWait {
    started: u64,
    fail_ms: u64,
    next_report_ms: u64,
}

impl GateWait {
    fn begin() -> Self {
        let pick = |hook: &AtomicU64, default: u64| match hook.load(Ordering::Relaxed) {
            0 => default,
            ms => ms,
        };
        let warn_ms = pick(&GATE_STALL_WARN_MS_FOR_TEST, GATE_STALL_WARN_MS);
        Self {
            started: narf_time::now_cycles(),
            fail_ms: pick(&GATE_STALL_FAIL_MS_FOR_TEST, GATE_STALL_FAIL_MS),
            next_report_ms: warn_ms,
        }
    }

    /// Report a long wait when one is due; `Err` once the holder has
    /// shown no progress for the fail bound while this waiter waited.
    fn check(&mut self, slot: &InstalledController) -> Result<(), NvmeError> {
        use core::fmt::Write as _;
        let ms = |cycles: u64| narf_time::cycles_to_ns(cycles) / 1_000_000;
        let now = narf_time::now_cycles();
        let waited_ms = ms(now.saturating_sub(self.started));
        if waited_ms < self.next_report_ms {
            return Ok(());
        }
        // Unsynchronised reads of the holder's record: it may belong to a
        // holder that has since released (the gate changes hands while we
        // starve), which the report then shows as a short hold.
        let owner = slot.gate_owner.load(Ordering::Relaxed);
        let since = slot.gate_since.load(Ordering::Relaxed);
        let progress = slot.gate_progress.load(Ordering::Relaxed).max(since);
        let held_ms = ms(now.saturating_sub(since));
        // The stall this waiter can vouch for: no progress by the holder
        // since the later of "it last marked progress" and "we arrived".
        let stalled_ms = ms(now.saturating_sub(progress.max(self.started)));
        let failed = stalled_ms >= self.fail_ms;
        let holder_cpu = owner >> GATE_OWNER_TASK_BITS;
        let holder_task = owner & ((1 << GATE_OWNER_TASK_BITS) - 1);
        let cpu = narf_lib::percpu::current_cpu() as u64;
        let irqs = narf_memory::context::irqs_enabled();
        let in_irq = narf_lib::context::in_irq();
        GATE_STALL_REPORTS.fetch_add(1, Ordering::Relaxed);
        let mut w = narf_console::Writer;
        let _ = write!(
            w,
            "nvme: {}: {}: request gate {} by cpu {holder_cpu} task {holder_task} for {held_ms} ms \
             (last progress {} ms ago); waiter cpu {cpu} task {} waited {waited_ms} ms, irqs {}{}",
            ns::controller_name(slot.instance),
            if failed { "ERROR" } else { "WARNING" },
            if slot.req_gate.load(Ordering::Relaxed) {
                "held"
            } else {
                "last held"
            },
            ms(now.saturating_sub(progress)),
            narf_scheduler::current_task_id().raw(),
            if irqs { "enabled" } else { "DISABLED" },
            if in_irq { ", in irq" } else { "" },
        );
        if holder_cpu == cpu {
            // The holder took the gate on this CPU. Unless it is a task
            // this waiter can yield to, it cannot run until this wait
            // ends — the nested-pump / interrupted-holder deadlock.
            let _ = write!(
                w,
                "; holder is on THIS cpu (it runs only if this waiter yields or returns)"
            );
        }
        if failed {
            GATE_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
            let _ = writeln!(
                w,
                "; no progress for {stalled_ms} ms (limit {} ms): giving up, this request fails",
                self.fail_ms
            );
            return Err(NvmeError::GateTimeout);
        }
        let _ = writeln!(w);
        // Next report in `GATE_STALL_REPORT_EVERY_MS`, or when the fail
        // bound falls due, whichever is first.
        let to_fail = self.fail_ms.saturating_sub(stalled_ms).max(1);
        self.next_report_ms = waited_ms + GATE_STALL_REPORT_EVERY_MS.min(to_fail);
        Ok(())
    }
}

/// Take `slot`'s gate without masking interrupts. A brief spin handles a
/// holder running on another CPU; a longer wait yields so a holder suspended
/// on this CPU can resume. Atomic contexts cannot yield and must service
/// pending TLB/membarrier work, which the holder may be waiting for.
///
/// The wait is neither anonymous nor unbounded. A waiter that has waited
/// [`GATE_STALL_WARN_MS`] logs who holds the gate (CPU, task), for how
/// long, and who is waiting (CPU, task, interrupt state), and repeats that
/// every [`GATE_STALL_REPORT_EVERY_MS`]. Once the holder has shown no
/// progress for [`GATE_STALL_FAIL_MS`] of the waiter's wait, the waiter
/// logs an error and returns [`NvmeError::GateTimeout`] — it does not
/// panic. An error is the right failure here because it can be survived
/// and, in the one known way to wedge the gate, it *un*-wedges it: a
/// holder whose wait loop runs the scheduler pump, which polls a task
/// that wants the same controller, has the waiter sitting on top of the
/// holder's own stack — the holder cannot resume until the waiter
/// returns, and a panic there would take the machine down with the root
/// filesystem's holder merely preempted by its own callee. A waiter
/// that fails gets an I/O error; the log line says exactly who was
/// stuck behind whom.
fn acquire(slot: &'static InstalledController) -> Result<ControllerGuard, NvmeError> {
    let mut wait: Option<GateWait> = None;
    loop {
        for _ in 0..64 {
            if try_take_gate(slot) {
                return Ok(ControllerGuard { slot });
            }
            core::hint::spin_loop();
        }
        wait.get_or_insert_with(GateWait::begin).check(slot)?;
        if !narf_memory::context::irqs_enabled()
            || narf_lib::context::in_irq()
            || !narf_scheduler::cooperative_yield()
        {
            narf_lib::sync::service_masked_spin();
            core::hint::spin_loop();
        }
    }
}

/// Exclusive access to controller `instance`, or `None` if it is not
/// installed (or was removed), or its gate could not be taken
/// ([`NvmeError::GateTimeout`]).
///
/// `smoke_nvme_controller_slot_is_stable` pins the address-stability
/// invariant this relies on: a repeat probe must not move or replace an
/// installed slot.
fn controller_at(instance: u32) -> Option<ControllerGuard> {
    // A gate that never came free reads as "no controller" here: the
    // stall was logged by `acquire`, and every caller already treats
    // `None` as "cannot be served".
    slot_of(instance).and_then(|slot| acquire(slot).ok())
}

/// Exclusive access to the first controller (`nvme0`).
fn probed_controller() -> Option<ControllerGuard> {
    controller_at(0)
}

/// Instance 0's slot address, or `None` before probe. Test hook for the
/// install-once invariant `acquire` relies on.
#[doc(hidden)]
pub fn dbg_slot_addr() -> Option<usize> {
    dbg_slot_addr_at(0)
}

/// [`dbg_slot_addr`] for controller `instance`.
#[doc(hidden)]
pub fn dbg_slot_addr_at(instance: u32) -> Option<usize> {
    slot_of(instance).map(|s| s as *const InstalledController as usize)
}

/// Number of installed controllers (removed ones included: instance
/// numbers are never reused within a boot).
pub fn controller_count() -> usize {
    CONTROLLERS.lock().len()
}

/// Instance number of the controller driving PCI function `bdf`.
pub fn instance_of(bdf: narf_bus::PcieAddr) -> Option<u32> {
    CONTROLLERS
        .lock()
        .iter()
        .find(|s| s.bdf == Some(bdf) && !s.removed.load(Ordering::Acquire))
        .map(|s| s.instance)
}

// ── BlockDeviceSync adapters (registry/lib.rs) ────────────────────────

/// Block device for one namespace of one controller: what the registry
/// holds as `nvme<C>n<N>`. Resolves its controller by instance on every
/// call, so a kernel-test reinstall of that controller is picked up and a
/// removed controller reports `DeviceRemoved`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NvmeNamespaceBlock {
    instance: u32,
    nsid: u32,
}

impl NvmeNamespaceBlock {
    pub const fn new(instance: u32, nsid: u32) -> Self {
        Self { instance, nsid }
    }
    pub fn instance(&self) -> u32 {
        self.instance
    }
    pub fn nsid(&self) -> u32 {
        self.nsid
    }
}

/// Sync wrapper for the first controller's primary namespace — the
/// pre-multi-controller surface, kept for callers and smokes that address
/// "the" NVMe disk. The registry holds [`NvmeNamespaceBlock`]s.
#[derive(Debug)]
pub struct NvmeBlockSync;

/// Size of the persistent DMA scratch behind the sync block path. A
/// registry transfer is split into commands of at most
/// `min(scratch, max_transfer_bytes)` bytes; 128 KiB moves a standard
/// 16 KiB GPT entry array, or 32 4 KiB blocks, in one command.
const NVME_SYNC_SCRATCH_BYTES: usize = 128 * 1024;

/// `slot`'s DMA scratch, allocated (and leaked) on first use.
///
/// Leaked so the returned `&'static` can outlive the lock, and so a
/// command that times out can never leave the device DMA-ing into a
/// recycled page (audit #2: pre-fix every read/write call did
/// `alloc_coherent(4096)` and dropped the result at function end). If the
/// 128 KiB contiguous allocation fails the scratch falls back to one page;
/// transfers are then split per page. The caller holds `slot`'s gate,
/// which is what serialises the contents.
fn slot_scratch(slot: &InstalledController) -> Option<&'static DmaBuffer> {
    let mut g = slot.scratch.lock();
    if g.is_none() {
        *g = alloc_coherent(NVME_SYNC_SCRATCH_BYTES, DomainId::DRIVER_0)
            .or_else(|_| alloc_coherent(PAGE_SIZE as usize, DomainId::DRIVER_0))
            .ok()
            .map(|b| &*alloc::boxed::Box::leak(alloc::boxed::Box::new(b)));
    }
    *g
}

fn map_nvme_sync_err(e: NvmeError) -> narf_block::BlockIoError {
    match e {
        NvmeError::OutOfRange => narf_block::BlockIoError::OutOfRange,
        NvmeError::NotReady | NvmeError::NoIoQueue => narf_block::BlockIoError::DeviceRemoved,
        _ => narf_block::BlockIoError::DriverError,
    }
}

/// Blocks per command for the sync scratch path: bounded by the scratch
/// size and the controller's maximum transfer, never zero (the scratch
/// and the max transfer are both at least one 4 KiB page, and the LBA
/// size is at most 4 KiB for a usable namespace).
fn nvme_sync_chunk_blocks(scratch: usize, max_transfer: u32, lba_bytes: u32) -> u32 {
    let bytes = core::cmp::min(scratch, max_transfer as usize);
    core::cmp::max(1, bytes / lba_bytes.max(1) as usize) as u32
}

/// Geometry of namespace `nsid` (`None` = primary) on `ctrl`.
fn geom(ctrl: &Controller, nsid: Option<u32>) -> Option<ns::NamespaceInfo> {
    match nsid {
        Some(id) => ctrl.ns_geom(id),
        None => Some(ctrl.primary_geom()),
    }
}

fn sync_lba_size(instance: u32, nsid: Option<u32>) -> u32 {
    with_controller_at(instance, |c| geom(c, nsid).map(|g| g.lba_bytes))
        .flatten()
        .unwrap_or(512)
}

fn sync_capacity(instance: u32, nsid: Option<u32>) -> u64 {
    // A namespace whose format NARF cannot drive reports no capacity, as
    // Linux sets a zero-capacity disk.
    with_controller_at(instance, |c| {
        geom(c, nsid).map(|g| if g.usable { g.nsze } else { 0 })
    })
    .flatten()
    .unwrap_or(0)
}

/// Sync read/write of `n_blocks` LBAs of namespace `nsid` on controller
/// `instance` through the controller's scratch. `write` selects direction;
/// `data` is the source (write) or destination (read).
#[allow(clippy::too_many_arguments)]
fn sync_io(
    instance: u32,
    nsid: Option<u32>,
    write: bool,
    fua: bool,
    lba: u64,
    n_blocks: u16,
    data: SyncData<'_>,
) -> Result<(), narf_block::BlockIoError> {
    use narf_block::BlockIoError;
    if n_blocks == 0 {
        return Ok(());
    }
    // Interrupts stay enabled for the whole transfer: hold this
    // controller's request gate, not an IRQ-masking lock. The gate is what
    // serialises the controller's scratch, so acquire it BEFORE touching
    // the buffer.
    let slot = slot_of(instance).ok_or(BlockIoError::DeviceRemoved)?;
    let mut ctrl = acquire(slot).map_err(map_nvme_sync_err)?;
    if slot.removed.load(Ordering::Acquire) {
        return Err(BlockIoError::DeviceRemoved);
    }
    if ctrl.is_dead() {
        // An earlier request left the controller dead (its replays ran
        // out, or the reset at the timeout failed). Try the reset again
        // (dropping the guard first — recovery takes the gate itself),
        // then re-acquire and resolve the namespace geometry fresh: the
        // recovery re-scan may have changed it, and an identity mismatch
        // will have removed the slot.
        drop(ctrl);
        recover_slot(instance).map_err(map_nvme_sync_err)?;
        ctrl = acquire(slot).map_err(map_nvme_sync_err)?;
        if slot.removed.load(Ordering::Acquire) {
            return Err(BlockIoError::DeviceRemoved);
        }
    }
    let ns = geom(&ctrl, nsid).ok_or(BlockIoError::DeviceRemoved)?;
    let lba_bytes = ns.lba_bytes as usize;
    let need = n_blocks as usize * lba_bytes;
    if data.len() < need {
        return Err(BlockIoError::BufferTooSmall);
    }
    let buf = slot_scratch(slot).ok_or(BlockIoError::DriverError)?;
    let (opcode, what) = if write {
        (IoOpcode::Write as u8, "write")
    } else {
        (IoOpcode::Read as u8, "read")
    };
    let mut data = data;
    // A replay (see `run_with_replay`) restarts the request at its first
    // block and stages each chunk again from the caller's slice, so what a
    // replayed write sends never depends on what the scratch held when the
    // first attempt timed out; a replayed read fills the scratch, and then
    // the caller's buffer, afresh. `ns` stays valid across a replay: one
    // only happens when the reset found the namespace set unchanged.
    run_with_replay(slot, ctrl, what, |ctrl| {
        let chunk =
            nvme_sync_chunk_blocks(buf.len(), ctrl.max_transfer_bytes(), ns.lba_bytes) as usize;
        let mut done = 0usize;
        while done < n_blocks as usize {
            let n = core::cmp::min(chunk, n_blocks as usize - done);
            let bytes = n * lba_bytes;
            let at = done * lba_bytes;
            if let SyncData::Out(src) = &data {
                // SAFETY: the scratch is a live coherent DMA buffer of at
                // least `bytes` bytes (chunk is bounded by it);
                // `src[at..at + bytes]` is in bounds (`need` checked above)
                // and a kernel slice cannot overlap the DMA buffer.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        src.as_ptr().add(at),
                        buf.cpu_mut_ptr::<u8>(),
                        bytes,
                    );
                }
                // Publish the payload before the SQE + doorbell that lets
                // the device DMA-read it.
                compiler_fence(Ordering::Release);
            }
            ctrl.nvm_io_ns_at(
                ns,
                fua,
                opcode,
                lba.saturating_add(done as u64),
                n as u32,
                buf,
                0,
            )?;
            if let SyncData::In(dst) = &mut data {
                // The CQ poll inside `nvm_io_ns_at` is what makes the
                // device's writes visible; fence so the compiler cannot
                // hoist this bulk copy above it.
                compiler_fence(Ordering::Acquire);
                // SAFETY: as above, with `dst[at..at + bytes]` in bounds.
                // Bulk copy rather than a per-byte volatile loop: the
                // payload is coherent DMA memory, not MMIO.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        buf.cpu_ptr::<u8>(),
                        dst.as_mut_ptr().add(at),
                        bytes,
                    );
                }
            }
            done += n;
        }
        Ok(())
    })
    .map_err(map_nvme_sync_err)
}

/// Run block request `op` (`what`, for the log) against the controller
/// behind `ctrl`, and when one of its commands times out do what Linux
/// does instead of failing the request: reset the controller here, at the
/// timeout — not lazily on the next request — and replay the request, at
/// most [`IO_MAX_RETRIES`] times (Linux `nvme_timeout` → `nvme_reset_ctrl`;
/// `nvme_reset_work` cancels the outstanding requests, which
/// `nvme_complete_rq` → `nvme_retry_req` requeues until `nvme_max_retries`).
/// A filesystem therefore sees an error only when the controller cannot
/// be brought back or keeps timing out — not for one slow command.
///
/// Why a replay cannot duplicate, reorder or corrupt:
///  - One command is in flight per controller (the gate), and `ctrl` —
///    the gate — is held from the first attempt through the reset to the
///    last replay, so no other request can run in between.
///  - The replay only happens after [`Controller::reset_recover`]
///    confirmed CC.EN=0 / CSTS.RDY=0, which aborts whatever the device
///    still had of the timed-out command, and rebuilt every queue: no
///    completion of the old command can reach the new queues, and the
///    device can no longer read or write the old command's buffers.
///    A reset that cannot confirm the stop fails, and nothing is replayed.
///  - Every request that comes through here is idempotent when repeated
///    with the same arguments and nothing in between: Read, Write (same
///    data to the same LBAs — whether the first attempt wrote none, some
///    or all of it), Flush, Dataset Management deallocate and Write Zeroes
///    (same ranges). `op` rebuilds each command from the caller's
///    arguments, so nothing a timed-out attempt left in the controller's
///    scratch or PRP-list pages is reused (those pages are reallocated by
///    the reset anyway).
///  - If the reset reports a changed namespace set the request is NOT
///    replayed: its geometry was resolved against the old set.
///
/// The budget is the slot's `timeout_streak` — timeouts since a command
/// last completed — rather than a per-request counter, so a controller
/// that stopped answering altogether costs the first request its
/// replays and every later one a single attempt. Each exhausted or
/// refused replay still leaves the controller reset, not dead.
///
/// `op` must be restartable from scratch. Consumes the guard.
fn run_with_replay<T>(
    slot: &'static InstalledController,
    mut ctrl: ControllerGuard,
    what: &str,
    mut op: impl FnMut(&mut Controller) -> Result<T, NvmeError>,
) -> Result<T, NvmeError> {
    use core::fmt::Write as _;
    let mut replays = 0u32;
    loop {
        match op(&mut ctrl) {
            Err(NvmeError::CompletionTimeout) => {}
            r => {
                // A completion — success or an error status — is the
                // controller answering: the streak is over.
                if matches!(r, Ok(_) | Err(NvmeError::CommandFailed { .. }))
                    && slot.timeout_streak.load(Ordering::Relaxed) != 0
                {
                    slot.timeout_streak.store(0, Ordering::Relaxed);
                }
                return r;
            }
        }
        let name = ns::controller_name(slot.instance);
        let streak = slot.timeout_streak.fetch_add(1, Ordering::Relaxed) + 1;
        if SHUTTING_DOWN.load(Ordering::Acquire) {
            // The final shutdown is waiting for this gate to send
            // CC.SHN; a reset now would only race it.
            let _ = writeln!(
                narf_console::Writer,
                "nvme: {name}: ERROR: {what} timed out during shutdown; not reset, not replayed"
            );
            return Err(NvmeError::CompletionTimeout);
        }
        let _ = writeln!(
            narf_console::Writer,
            "nvme: {name}: {what} timed out ({streak} consecutive command timeout(s)); \
             resetting the controller"
        );
        ctrl = match recover_held(slot, ctrl) {
            Ok(Some(ctrl)) => ctrl,
            Ok(None) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "nvme: {name}: ERROR: namespace set changed across the reset; \
                     {what} not replayed"
                );
                return Err(NvmeError::CompletionTimeout);
            }
            // Logged by `recover_held`; the controller stays dead and the
            // next request tries the reset again.
            Err(_) => return Err(NvmeError::CompletionTimeout),
        };
        // Still the holder, and moving: gate waiters measure a stall from
        // here, not from the first attempt.
        mark_gate_progress(slot);
        if streak > IO_MAX_RETRIES {
            let _ = writeln!(
                narf_console::Writer,
                "nvme: {name}: ERROR: {what} failed: {streak} consecutive command timeouts \
                 (replayed {replays} time(s), limit {IO_MAX_RETRIES}); returning an I/O error"
            );
            return Err(NvmeError::CompletionTimeout);
        }
        replays += 1;
        IO_REPLAYS.fetch_add(1, Ordering::Relaxed);
        let _ = writeln!(
            narf_console::Writer,
            "nvme: {name}: replaying {what} (replay {replays}, timeout streak {streak} of \
             {IO_MAX_RETRIES})"
        );
    }
}

/// Caller buffer of [`sync_io`].
enum SyncData<'a> {
    In(&'a mut [u8]),
    Out(&'a [u8]),
}

impl SyncData<'_> {
    fn len(&self) -> usize {
        match self {
            SyncData::In(b) => b.len(),
            SyncData::Out(b) => b.len(),
        }
    }
}

impl narf_block::BlockDeviceSync for NvmeNamespaceBlock {
    fn lba_size(&self) -> u32 {
        sync_lba_size(self.instance, Some(self.nsid))
    }
    fn capacity(&self) -> u64 {
        sync_capacity(self.instance, Some(self.nsid))
    }
    fn read(&self, lba: u64, n: u16, out: &mut [u8]) -> Result<(), narf_block::BlockIoError> {
        let d = SyncData::In(out);
        sync_io(self.instance, Some(self.nsid), false, false, lba, n, d)
    }
    fn write(&self, lba: u64, n: u16, data: &[u8]) -> Result<(), narf_block::BlockIoError> {
        let d = SyncData::Out(data);
        sync_io(self.instance, Some(self.nsid), true, false, lba, n, d)
    }
    fn write_fua(&self, lba: u64, n: u16, data: &[u8]) -> Result<(), narf_block::BlockIoError> {
        let d = SyncData::Out(data);
        sync_io(self.instance, Some(self.nsid), true, true, lba, n, d)
    }
    fn flush(&self) -> Result<(), narf_block::BlockIoError> {
        sync_flush(self.instance, Some(self.nsid))
    }
    fn supports_trim(&self) -> bool {
        sync_supports_trim(self.instance, Some(self.nsid))
    }
    fn trim(&self, lba: u64, n_blocks: u64) -> Result<(), narf_block::BlockIoError> {
        sync_trim(self.instance, Some(self.nsid), lba, n_blocks)
    }
    fn capabilities(&self) -> narf_block::BlockCaps {
        sync_caps(self.instance)
    }
}

impl narf_block::BlockDeviceSync for NvmeBlockSync {
    fn lba_size(&self) -> u32 {
        sync_lba_size(0, None)
    }
    fn capacity(&self) -> u64 {
        sync_capacity(0, None)
    }
    fn read(&self, lba: u64, n: u16, out: &mut [u8]) -> Result<(), narf_block::BlockIoError> {
        sync_io(0, None, false, false, lba, n, SyncData::In(out))
    }
    fn write(&self, lba: u64, n: u16, data: &[u8]) -> Result<(), narf_block::BlockIoError> {
        sync_io(0, None, true, false, lba, n, SyncData::Out(data))
    }
    fn write_fua(&self, lba: u64, n: u16, data: &[u8]) -> Result<(), narf_block::BlockIoError> {
        sync_io(0, None, true, true, lba, n, SyncData::Out(data))
    }
    fn flush(&self) -> Result<(), narf_block::BlockIoError> {
        sync_flush(0, None)
    }
    fn supports_trim(&self) -> bool {
        sync_supports_trim(0, None)
    }
    fn trim(&self, lba: u64, n_blocks: u64) -> Result<(), narf_block::BlockIoError> {
        sync_trim(0, None, lba, n_blocks)
    }
    fn capabilities(&self) -> narf_block::BlockCaps {
        sync_caps(0)
    }
}

/// Flush namespace `nsid` (`None` = primary) of controller `instance`.
fn sync_flush(instance: u32, nsid: Option<u32>) -> Result<(), narf_block::BlockIoError> {
    let slot = slot_of(instance).ok_or(narf_block::BlockIoError::DeviceRemoved)?;
    let mut ctrl = acquire(slot).map_err(map_nvme_sync_err)?;
    if slot.removed.load(Ordering::Acquire) {
        return Err(narf_block::BlockIoError::DeviceRemoved);
    }
    if ctrl.is_dead() {
        // Same dead-controller recovery as the I/O path.
        drop(ctrl);
        recover_slot(instance).map_err(map_nvme_sync_err)?;
        ctrl = acquire(slot).map_err(map_nvme_sync_err)?;
        if slot.removed.load(Ordering::Acquire) {
            return Err(narf_block::BlockIoError::DeviceRemoved);
        }
    }
    let ns = geom(&ctrl, nsid).ok_or(narf_block::BlockIoError::DeviceRemoved)?;
    run_with_replay(slot, ctrl, "flush", |ctrl| ctrl.flush_nsid(ns.nsid)).map_err(map_nvme_sync_err)
}

/// Whether namespace `nsid` (`None` = primary) of controller
/// `instance` really deallocates on `trim`: the namespace must be
/// registered and usable, and the controller's Identify ONCS must
/// carry Dataset Management. This is what the `SyncBlock` adapter
/// turns into `BlockFeature::Discard` (#841, #927).
fn sync_supports_trim(instance: u32, nsid: Option<u32>) -> bool {
    with_controller_at(instance, |c| {
        geom(c, nsid).is_some_and(|g| g.usable) && c.supports_dataset_mgmt()
    })
    .unwrap_or(false)
}

/// Deallocate `n_blocks` blocks at `lba` on namespace `nsid`
/// (`None` = primary) of controller `instance` via Dataset
/// Management. Controller errors propagate — never a silent
/// success.
fn sync_trim(
    instance: u32,
    nsid: Option<u32>,
    lba: u64,
    n_blocks: u64,
) -> Result<(), narf_block::BlockIoError> {
    let slot = slot_of(instance).ok_or(narf_block::BlockIoError::DeviceRemoved)?;
    let mut ctrl = acquire(slot).map_err(map_nvme_sync_err)?;
    if slot.removed.load(Ordering::Acquire) {
        return Err(narf_block::BlockIoError::DeviceRemoved);
    }
    if ctrl.is_dead() {
        // Same dead-controller recovery as the I/O path.
        drop(ctrl);
        recover_slot(instance).map_err(map_nvme_sync_err)?;
        ctrl = acquire(slot).map_err(map_nvme_sync_err)?;
        if slot.removed.load(Ordering::Acquire) {
            return Err(narf_block::BlockIoError::DeviceRemoved);
        }
    }
    let ns = geom(&ctrl, nsid).ok_or(narf_block::BlockIoError::DeviceRemoved)?;
    run_with_replay(slot, ctrl, "discard", |ctrl| {
        ctrl.dataset_mgmt_ns(
            ns,
            &[LbaRange {
                start: lba,
                blocks: n_blocks,
            }],
        )
    })
    .map_err(map_nvme_sync_err)
}

/// NVMe Write always supports FUA natively; the cache is volatile when
/// Identify Controller VWC says so.
fn sync_caps(instance: u32) -> narf_block::BlockCaps {
    narf_block::BlockCaps {
        volatile_cache: with_controller_at(instance, |c| c.has_volatile_write_cache())
            .unwrap_or(false),
        fua: true,
    }
}

/// Probe entry point dispatched by `bus::probe_all_pci`, once per NVMe
/// PCI function (Linux `nvme_probe`). Brings that controller online
/// (BAR mapping, admin queue, IDENTIFY, namespace scan, I/O queue),
/// installs it as the next instance `nvme<C>`, and registers every
/// namespace `nvme<C>n<N>` plus its partitions with the block registry.
/// Returns `BadDevice` on bring-up failure — the controller is stopped
/// first (see [`Controller::disable_after_failure`]) and the caller logs +
/// continues with the next device; other controllers are unaffected.
///
/// Idempotent per PCI function: re-probing a function that is already
/// installed returns `Ok(())`; a function torn down by
/// [`remove_controller`] is brought up again under its old instance. The kernel-test harness re-runs probe_all
/// across smokes; resetting + re-bringing-up a running controller risks
/// crossing CC.EN=0/1 state with queues held by the prior smoke.
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
    let bdf = match device.addr {
        narf_bus::BusAddr::Pcie(a) => Some(a),
        _ => None,
    };
    let live = |s: &&InstalledController| s.bdf == bdf && !s.removed.load(Ordering::Acquire);
    if bdf.is_some() && CONTROLLERS.lock().iter().any(live) {
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
    // `bring_up` stops the controller itself on a failure after CC.EN=1.
    if ctrl.bring_up(&cap).is_err() {
        return Err(narf_bus::ProbeError::BadDevice);
    }
    // Negotiate the queue count + per-queue MSI-X pairs, falling
    // back to the single polled pair when MSI-X is unavailable
    // (#928). The IRQ submission paths then serve production I/O.
    if ctrl.create_io_queues_preferred(&cap).is_err() {
        // Linux `nvme_reset_work` → `nvme_dev_disable`: stop the live
        // controller before its queues go back to the allocator.
        ctrl.disable_after_failure(&cap);
        return Err(narf_bus::ProbeError::BadDevice);
    }
    let instance = install_controller(ctrl);
    // Install the typed parameter surface so observers + tuners can
    // reach the driver via `Cap<DriverHandle, Write>`.
    if !PARAMS.is_installed() {
        PARAMS.install(NvmeParams {
            log_level: LogLevel::Info,
        });
    }
    register_controller(instance, device, cap);
    Ok(())
}

/// Publish controller `instance`: block devices (namespaces + partitions,
/// each behind the registry's `narf.disks` guard), the bound-driver record,
/// device PM, and the `/dev/nvme<C>` controller node.
fn register_controller(instance: u32, device: narf_bus::BusDevice, cap: Cap<BusDeviceCap, Write>) {
    let bus_path = match device.addr {
        narf_bus::BusAddr::Pcie(a) => ns::bdf_string(a),
        _ => alloc::string::String::new(),
    };
    let Some((ident, namespaces)) = with_controller_at(instance, |c| {
        let id = c.identify();
        (
            ns::ControllerIdentity {
                instance,
                bus_path,
                vendor_id: device.id.vendor,
                model: id.map(|i| ns::trim_ascii(&i.mn)).unwrap_or_default(),
                serial: id.map(|i| ns::trim_ascii(&i.sn)).unwrap_or_default(),
                firmware: id.map(|i| ns::trim_ascii(&i.fr)).unwrap_or_default(),
            },
            c.namespaces().to_vec(),
        )
    }) else {
        return;
    };
    let names = ns::register_namespaces(&ident, &namespaces, |nsid| {
        alloc::sync::Arc::new(NvmeNamespaceBlock::new(instance, nsid))
            as alloc::sync::Arc<dyn narf_block::BlockDeviceSync>
    });
    let ctrl_name = ns::controller_name(instance);
    // Record the bind in the framework's bound-driver inventory.
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: ctrl_name.clone(),
        kind: narf_drivers::BoundKind::Block,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Block.default_domain(),
    });
    // Device PM: suspend quiesces + tears the controller down and
    // resume re-initialises it (see `NvmePm`), so NVMe-rooted machines
    // can complete system suspend. The PM entry carries the probe cap:
    // the callbacks receive none.
    narf_power::device_pm::register_device_pm_ops(
        &ctrl_name,
        alloc::sync::Arc::new(NvmePm { instance, cap }),
    );
    // `/dev/nvme<C>`: admin passthrough (smartctl / nvme-cli) for this
    // controller. devfs gates it on every one of its namespaces being
    // writable under `narf.disks`.
    narf_filesystem::devfs::register_nvme_controller(
        instance,
        alloc::sync::Arc::new(chardev::NvmeCharDev::new(instance)),
        names,
    );
}

/// Tear controller `instance` down (Linux `nvme_remove` →
/// `nvme_dev_disable`): refuse new I/O, withdraw its block devices,
/// partitions and `/dev/nvme<C>` node, wait for the in-flight round-trip
/// (the gate), then stop the controller with CC.EN=0 and only then release
/// its DMA — or leak every page the controller was given if CSTS.RDY never
/// drops (see [`Controller::disable_after_failure`]). Other controllers are
/// untouched.
///
/// Returns `None` if `instance` is not installed, else whether the
/// controller was confirmed stopped (`false` also when its request gate
/// never came free, in which case it was not touched).
pub fn remove_controller(instance: u32, cap: &Cap<BusDeviceCap, Write>) -> Option<bool> {
    let slot = slot_of(instance)?;
    slot.removed.store(true, Ordering::Release);
    withdraw_controller_publications(instance);
    // The slot is already refusing new requests. If the in-flight one
    // never releases the gate the controller cannot be touched safely:
    // report it as not confirmed stopped. Its DMA stays with the leaked
    // slot, exactly as when CSTS.RDY never drops.
    let Ok(mut ctrl) = acquire(slot) else {
        return Some(false);
    };
    Some(ctrl.disable_after_failure(cap))
}

/// Withdraw controller `instance`'s publications: every block device
/// (namespaces + partitions) the registry holds for it, and its
/// `/dev/nvme<C>` node. Shared by [`remove_controller`] and by
/// recovery's re-publish path.
fn withdraw_controller_publications(instance: u32) {
    let prefix = ns::controller_name(instance);
    for entry in narf_block::block_devices() {
        if entry
            .identity
            .as_ref()
            .is_some_and(|i| i.transport == "nvme" && i.controller == prefix)
        {
            narf_block::unregister_block_device(entry.name);
        }
    }
    narf_filesystem::devfs::unregister_nvme_controller(instance);
}

/// Recover installed controller `instance` after it was marked
/// dead (a command timed out): reset + re-init it in place via
/// [`Controller::reset_recover`], minting the device cap from the
/// bus bootstrap authority the way `probe_all` does.
///
/// A suspended controller is refused ([`NvmeError::NotReady`]),
/// never recovered: its `dead` is the suspend teardown's state, and
/// only resume may bring it back (see [`suspend_slot`] /
/// [`resume_slot`]).
///
/// Gate discipline: the reset runs under the slot's request gate,
/// acquired here — callers (the block entry points, when they find
/// the controller already dead) drop their guard before calling. The
/// timeout path, which already holds the gate and must keep it for
/// the replay, calls [`recover_held`] directly. The gate is an atomic
/// spun with interrupts enabled, and no registry lock is held across
/// the reset's bounded waits. A racing caller that finds the
/// controller already recovered returns `Ok` immediately.
///
/// On a namespace-set change the controller's publications are
/// withdrawn and re-registered from the fresh scan; the cap minted
/// for the reset is handed to that re-registration, so the device-PM
/// entry re-published for the controller carries the device's real
/// claimed cap (the PM callbacks receive none — see
/// [`register_controller`]). On
/// [`NvmeError::IdentityChanged`] the function hosts a different
/// device than the one that wedged: the slot is marked removed
/// (before the gate is released, so no racing caller can adopt the
/// foreign device) and its publications withdrawn — a later probe
/// binds the new device under this instance, exactly as after
/// [`remove_controller`].
fn recover_slot(instance: u32) -> Result<(), NvmeError> {
    let slot = slot_of(instance).ok_or(NvmeError::NotReady)?;
    recover_held(slot, acquire(slot)?).map(|_| ())
}

/// [`recover_slot`] under a gate the caller already holds. Returns the
/// guard — the gate never released — when the controller is live again
/// with the namespace set it had before (`Ok(Some)`), which is what lets
/// [`run_with_replay`] replay a timed-out request with nothing able to
/// run in between. `Ok(None)` means the controller is live but its
/// namespace set changed: the gate had to be released to re-publish the
/// block devices (`register_controller` serialises on the gate, which is
/// not reentrant), so the caller's view of the namespaces is stale. On
/// `Err` the gate is released and the controller stays dead (or, for
/// [`NvmeError::IdentityChanged`], removed).
fn recover_held(
    slot: &'static InstalledController,
    mut ctrl: ControllerGuard,
) -> Result<Option<ControllerGuard>, NvmeError> {
    use core::fmt::Write as _;
    let instance = slot.instance;
    let name = ns::controller_name(instance);
    if ctrl.is_suspended() {
        // Suspend wins over recovery: a suspended controller is
        // `dead` because the PM teardown put it down, not because
        // a command wedged it, and resurrecting it here would
        // serve I/O the suspend window exists to refuse.
        // Recovery of a suspended controller is deferred to
        // resume (`resume_slot` re-inits it); refuse the caller
        // instead. Checked before the not-dead early return so
        // the refusal holds whatever state the teardown left.
        return Err(NvmeError::NotReady);
    }
    if !ctrl.is_dead() {
        return Ok(Some(ctrl));
    }
    let device = ctrl.bus_device().ok_or(NvmeError::NotReady)?;
    let authority = narf_bus::bootstrap_registry_authority();
    let (_handle, cap) = narf_bus::claim_device_cap(&authority, device.addr)
        .map_err(|_| NvmeError::ControllerFailed)?;
    let _ = writeln!(
        narf_console::Writer,
        "nvme: {name}: controller dead (command timeout); resetting in place"
    );
    let outcome = ctrl.reset_recover(&cap);
    if matches!(outcome, Err(NvmeError::IdentityChanged)) {
        // Before the gate is released, so no racing caller can adopt
        // the foreign device.
        slot.removed.store(true, Ordering::Release);
    }
    match outcome {
        Ok(report) => {
            if report.namespaces_changed {
                // Re-publication takes the gate itself.
                drop(ctrl);
                withdraw_controller_publications(instance);
                register_controller(instance, device, cap);
                let _ = writeln!(
                    narf_console::Writer,
                    "nvme: {name}: recovered; namespace set changed, re-published"
                );
                Ok(None)
            } else {
                let _ = writeln!(narf_console::Writer, "nvme: {name}: recovered; I/O resumed");
                Ok(Some(ctrl))
            }
        }
        Err(NvmeError::IdentityChanged) => {
            drop(ctrl);
            withdraw_controller_publications(instance);
            let _ = writeln!(
                narf_console::Writer,
                "nvme: {name}: ERROR: a different controller answered after reset; \
                 treating the slot as removed (the new device binds on the next probe)"
            );
            Err(NvmeError::IdentityChanged)
        }
        Err(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "nvme: {name}: ERROR: reset/recovery failed ({e:?}); controller stays dead"
            );
            Err(e)
        }
    }
}

// ── AER supervisor (#928) ────────────────────────────────────────────

/// AER supervisor poll interval: the admin-vector wait's deadline,
/// so a lost or never-armed admin IRQ still gets a periodic drain.
/// 250 ms matches the e1000 IRQ-poll cadence; a namespace change is
/// noticed within a quarter second either way.
const AER_SUPERVISOR_POLL_MS: u64 = 250;

/// Set once by the Stage::Late initcall ([`spawn_aer_supervisor`]);
/// the supervisor is one task for all instances, and the initcall
/// may re-run under the kernel-test harness.
static AER_SUPERVISOR_STARTED: AtomicBool = AtomicBool::new(false);

/// Spawn the AER supervisor task (#928), idempotently. Runs from
/// the Stage::Late initcall, once the executor is up (drivers may
/// spawn from Stage::Late; spawning earlier, before
/// `scheduler::init`, panics).
pub fn spawn_aer_supervisor() {
    if AER_SUPERVISOR_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    narf_scheduler::spawn(aer_supervisor_task());
}

/// Drain + rescan one installed controller, re-publishing its block
/// devices when the namespace set changed. Sync: the caller (the
/// AER supervisor task, between its IRQ waits) owns no lock across
/// it — the slot gate is taken here, only for the drain + rescan,
/// and dropped before any re-publication.
fn aer_poll_instance(instance: u32) {
    use core::fmt::Write as _;
    let Some(slot) = slot_of(instance) else {
        return;
    };
    // Drain under the gate. The rescan (admin IDENTIFYs) runs under
    // the same hold so no I/O can interleave with the namespace-set
    // swap; re-publication happens after the guard drops.
    let (changed, device) = {
        // A stalled gate was logged by `acquire`; skip this round.
        let Ok(mut ctrl) = acquire(slot) else {
            return;
        };
        if slot.removed.load(Ordering::Acquire) || ctrl.is_dead() || ctrl.is_suspended() {
            return;
        }
        let drain = ctrl.drain_aer_events();
        if !drain.ns_changed {
            return;
        }
        match ctrl.rescan_namespaces() {
            Ok(changed) => (changed, ctrl.bus_device()),
            Err(_) => return,
        }
    };
    if !changed {
        return;
    }
    // Re-publish: withdraw the stale namespace devices + node, then
    // register the fresh set — the same pair `recover_slot` uses
    // after a reset that changed the namespace set.
    let Some(device) = device else {
        return;
    };
    let authority = narf_bus::bootstrap_registry_authority();
    let Ok((_handle, cap)) = narf_bus::claim_device_cap(&authority, device.addr) else {
        return;
    };
    withdraw_controller_publications(instance);
    register_controller(instance, device, cap);
    let _ = writeln!(
        narf_console::Writer,
        "nvme: {}: namespace set changed (AER), re-published",
        ns::controller_name(instance)
    );
}

/// AER supervisor task (#928): one task for all installed NVMe
/// controllers. For each instance it parks on the admin MSI-X
/// vector (250 ms deadline, so a lost or never-armed admin IRQ
/// still gets a periodic drain) and then drains AER completions,
/// rescanning + re-publishing namespaces on change events. The
/// waits hold no locks; the gate is taken only inside
/// `aer_poll_instance`, for the drain + rescan, and dropped
/// before re-publication.
async fn aer_supervisor_task() {
    loop {
        let n = controller_count();
        if n == 0 {
            // The supervisor is spawned even on machines with no NVMe. The
            // empty for-loop below has no await point and would monopolize
            // the executor, preventing init/getty and every peer from polling.
            narf_time::sleep_ms(AER_SUPERVISOR_POLL_MS).await;
            continue;
        }
        for instance in 0..n as u32 {
            let v = with_controller_at(instance, |c| c.aer_wait_vector()).flatten();
            match v {
                Some(v) => {
                    let _ = narf_interrupts::wait_for_irq_until(
                        v,
                        narf_time::Deadline::after_ms(AER_SUPERVISOR_POLL_MS),
                    )
                    .await;
                }
                None => {
                    narf_time::sleep_ms(AER_SUPERVISOR_POLL_MS).await;
                }
            }
            aer_poll_instance(instance);
        }
    }
}

/// How long the final shutdown waits for an in-flight command to release a
/// controller before it gives up on the Flush and sends CC.SHN regardless —
/// Linux `nvme_dev_disable(shutdown = true)` waits `NVME_IO_TIMEOUT` (30 s)
/// for the queues to freeze. A healthy controller's in-flight command drains
/// well inside this; a command that is itself timing out ([`IO_TIMEOUT_MS`],
/// the same 30 s) does not, and the shutdown then takes the forced path —
/// [`run_with_replay`] neither resets nor replays once shutdown has begun.
pub const SHUTDOWN_DRAIN_TIMEOUT_MS: u64 = 30_000;

/// What the final shutdown of one controller did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlotShutdown {
    /// The in-flight work drained: every namespace flushed, then CC.SHN.
    Normal(shutdown::QuiesceReport<NvmeError>),
    /// Never drained within the budget (or called from interrupt context):
    /// no Flush could be sent, CC.SHN was written straight to the register.
    /// The controller still commits its volatile cache on a normal shutdown.
    Forced(shutdown::ShutdownOutcome),
    /// The slot was never brought up (no BAR): nothing to shut down.
    NotReady,
}

/// Final shutdown of one controller: wait up to `drain_ms` for its request
/// gate (in-flight commands to finish) via `wait(cond, ms)`, then Flush +
/// CC.SHN; if the gate never frees, log loudly and send CC.SHN anyway.
/// `wait` is [`drain_wait`] in production and a model in tests.
fn shutdown_slot(
    slot: &'static InstalledController,
    drain_ms: u64,
    wait: &mut dyn FnMut(&mut dyn FnMut() -> bool, u64) -> bool,
) -> SlotShutdown {
    use core::fmt::Write as _;
    let name = ns::controller_name(slot.instance);
    let got = drain_ms > 0 && wait(&mut || try_take_gate(slot), drain_ms);
    if got {
        let mut ctrl = ControllerGuard { slot };
        return match ctrl.shutdown() {
            Some(report) => SlotShutdown::Normal(report),
            None => SlotShutdown::NotReady,
        };
    }
    let Some((bar, timeout_ms)) = *slot.shutdown_regs.lock() else {
        return SlotShutdown::NotReady;
    };
    let _ = writeln!(
        narf_console::Writer,
        "nvme: {name}: ERROR: an in-flight command still holds the controller after {drain_ms} ms; \
         sending CC.SHN WITHOUT a Flush (its write cache is committed by the shutdown itself; \
         any write still in flight may be lost)"
    );
    let regs = BarRegs(bar);
    let outcome = shutdown::normal_shutdown(&regs, timeout_ms, &mut |cond, ms| {
        narf_scheduler::responsive_spin_until(cond, narf_time::Deadline::after_ms(ms))
    });
    SlotShutdown::Forced(outcome)
}

/// The production drain wait: spin on `cond` in 100 ms slices with
/// interrupts enabled, cooperatively yielding between slices (a stackful
/// task descheduled on this CPU may be the one holding the gate), and log
/// every 5 s so a long drain is visible.
fn drain_wait(name: &str) -> impl FnMut(&mut dyn FnMut() -> bool, u64) -> bool + '_ {
    move |cond, budget_ms| {
        use core::fmt::Write as _;
        let start = narf_time::wall::monotonic_ns();
        let mut next_log_ms = 5_000;
        loop {
            if narf_scheduler::responsive_spin_until(&mut *cond, narf_time::Deadline::after_ms(100))
            {
                return true;
            }
            let waited_ms = narf_time::wall::monotonic_ns().saturating_sub(start) / 1_000_000;
            if waited_ms >= budget_ms {
                return false;
            }
            if waited_ms >= next_log_ms {
                let _ = writeln!(
                    narf_console::Writer,
                    "nvme: {name}: shutdown waiting for in-flight I/O ({waited_ms} ms of {budget_ms} ms)"
                );
                next_log_ms += 5_000;
            }
            let _ = narf_scheduler::cooperative_yield();
        }
    }
}

/// `narf_power::system` shutdown hook: the final quiesce of every
/// controller before reboot / power-off (Linux `nvme_shutdown`, run from
/// `device_shutdown`). New requests are refused from here on; each
/// controller's in-flight work is given [`SHUTDOWN_DRAIN_TIMEOUT_MS`] to
/// drain, then every namespace is flushed and CC.SHN sent, in instance
/// order. A controller that never drains still gets CC.SHN, loudly.
///
/// Runs in task context: `narf_power::system` refuses a reboot / power-off
/// from interrupt context before any hook runs. Should it ever be reached
/// from an IRQ regardless, waiting would only wait on the interrupted code,
/// so it goes straight to the forced CC.SHN.
pub fn shutdown_all_controllers() {
    use core::fmt::Write as _;
    SHUTTING_DOWN.store(true, Ordering::Release);
    let in_irq = narf_lib::context::in_irq();
    if in_irq {
        let _ = writeln!(
            narf_console::Writer,
            "nvme: ERROR: shutdown reached from interrupt context; no Flush possible, forcing CC.SHN"
        );
    }
    let drain_ms = if in_irq { 0 } else { SHUTDOWN_DRAIN_TIMEOUT_MS };
    let slots: Vec<&'static InstalledController> = CONTROLLERS.lock().clone();
    for slot in slots {
        if slot.removed.load(Ordering::Acquire) {
            continue;
        }
        let name = ns::controller_name(slot.instance);
        let start = narf_time::wall::monotonic_ns();
        let outcome = shutdown_slot(slot, drain_ms, &mut drain_wait(&name));
        let ms = narf_time::wall::monotonic_ns().saturating_sub(start) / 1_000_000;
        match outcome {
            SlotShutdown::Normal(report) => {
                let flushed = report.flushes.iter().filter(|(_, r)| r.is_ok()).count();
                let failed = report.flushes.len() - flushed;
                let _ = writeln!(
                    narf_console::Writer,
                    "nvme: {name}: flushed {flushed} namespace(s){} in {ms} ms; CC.SHN normal shutdown: {:?}",
                    if failed > 0 {
                        alloc::format!(" ({failed} flush failed)")
                    } else {
                        alloc::string::String::new()
                    },
                    report.shutdown
                );
            }
            SlotShutdown::Forced(outcome) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "nvme: {name}: NO FLUSH (controller busy) in {ms} ms; CC.SHN normal shutdown (forced): {outcome:?}"
                );
            }
            SlotShutdown::NotReady => {
                let _ = writeln!(
                    narf_console::Writer,
                    "nvme: {name}: never brought up; nothing to shut down"
                );
            }
        }
    }
}

/// What one controller's PM suspend did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlotSuspend {
    /// Drained, flushed, CC.SHN'd and torn down; [`resume_slot`]
    /// rebuilds the controller on resume.
    Suspended(shutdown::ShutdownOutcome),
    /// Already suspended: a repeated suspend is a no-op.
    AlreadySuspended,
    /// The request gate never freed within the drain budget; the
    /// controller was not touched.
    Busy,
    /// Never brought up: nothing to suspend.
    NotReady,
    /// The quiesce/teardown failed partway; the controller is left
    /// stopped, not suspended, and stays down until remove + re-probe.
    Failed,
}

/// What one controller's PM resume did.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SlotResume {
    /// Re-initialised and identity re-validated; I/O flows again.
    Resumed,
    /// Was not suspended: a rollback resume is a no-op.
    NotSuspended,
    /// The request gate never freed within the drain budget.
    Busy,
    /// Re-init or the identity re-check failed; the controller stays
    /// down (a later resume retries after a transient bring-up
    /// failure; an identity mismatch is permanent).
    Failed,
}

/// PM suspend of one controller: wait up to `drain_ms` for its request
/// gate (in-flight commands to finish) via `wait(cond, ms)`, then
/// [`Controller::suspend_pm`] — Flush + CC.SHN quiesce and queue
/// teardown. Unlike the final shutdown there is no forced path: a
/// controller that never drains reports [`SlotSuspend::Busy`] and the
/// suspend orchestrator aborts the system suspend (its documented
/// `Busy` contract) rather than powering down under live DMA. `wait`
/// is [`pm_drain_wait`] in production and a model in tests.
fn suspend_slot(
    slot: &'static InstalledController,
    cap: &Cap<BusDeviceCap, Write>,
    drain_ms: u64,
    wait: &mut dyn FnMut(&mut dyn FnMut() -> bool, u64) -> bool,
) -> SlotSuspend {
    let got = drain_ms > 0 && wait(&mut || try_take_gate(slot), drain_ms);
    if !got {
        return SlotSuspend::Busy;
    }
    let mut ctrl = ControllerGuard { slot };
    if ctrl.suspended {
        return SlotSuspend::AlreadySuspended;
    }
    if !ctrl.is_ready() {
        return SlotSuspend::NotReady;
    }
    match ctrl.suspend_pm(cap) {
        Ok(outcome) => SlotSuspend::Suspended(outcome),
        Err(_) => SlotSuspend::Failed,
    }
}

/// PM resume of one controller: take the request gate (bounded by
/// `drain_ms` via `wait`, as in [`suspend_slot`]), then
/// [`Controller::resume_pm`] — full re-init + identity re-check. On
/// success the slot's copied-out shutdown registers are refreshed:
/// the re-init replaced the controller's BAR mapping, and the final
/// shutdown's forced path must not write CC.SHN through the stale one.
fn resume_slot(
    slot: &'static InstalledController,
    cap: &Cap<BusDeviceCap, Write>,
    drain_ms: u64,
    wait: &mut dyn FnMut(&mut dyn FnMut() -> bool, u64) -> bool,
) -> SlotResume {
    let got = drain_ms > 0 && wait(&mut || try_take_gate(slot), drain_ms);
    if !got {
        return SlotResume::Busy;
    }
    let mut ctrl = ControllerGuard { slot };
    if !ctrl.suspended {
        return SlotResume::NotSuspended;
    }
    match ctrl.resume_pm(cap) {
        Ok(()) => {
            *slot.shutdown_regs.lock() = shutdown_regs_of(&ctrl);
            SlotResume::Resumed
        }
        Err(_) => SlotResume::Failed,
    }
}

/// The PM drain wait: [`drain_wait`] without the cooperative yield —
/// device-PM handlers run on the boot CPU with interrupts gated and
/// must not schedule (see `narf_power::device_pm`). Spins in 100 ms
/// slices via the responsive spin (the sleep pumps keep running) and
/// logs every 5 s so a long drain is visible.
fn pm_drain_wait(name: &str) -> impl FnMut(&mut dyn FnMut() -> bool, u64) -> bool + '_ {
    move |cond, budget_ms| {
        use core::fmt::Write as _;
        let start = narf_time::wall::monotonic_ns();
        let mut next_log_ms = 5_000;
        loop {
            if narf_scheduler::responsive_spin_until(&mut *cond, narf_time::Deadline::after_ms(100))
            {
                return true;
            }
            let waited_ms = narf_time::wall::monotonic_ns().saturating_sub(start) / 1_000_000;
            if waited_ms >= budget_ms {
                return false;
            }
            if waited_ms >= next_log_ms {
                let _ = writeln!(
                    narf_console::Writer,
                    "nvme: {name}: PM waiting for in-flight I/O ({waited_ms} ms of {budget_ms} ms)"
                );
                next_log_ms += 5_000;
            }
        }
    }
}

/// Per-controller suspend/resume (`DevicePmOps`).
///
/// Suspend is Linux `nvme_suspend` (`nvme_dev_disable(shutdown =
/// true)`): drain the request gate, Flush every namespace, CC.SHN,
/// queues torn down. Resume is Linux `nvme_resume`: a full controller
/// reset that rebuilds the admin and I/O queues and revalidates the
/// controller's identity before I/O flows again.
#[derive(Debug)]
struct NvmePm {
    instance: u32,
    /// The probe-time device authority, carried here because the
    /// `DevicePmOps` callbacks receive no cap: the teardown and the
    /// re-init write PCI config space (BUS_MASTER) and manage MSI-X
    /// through it (the amdgpu driver's stored-authority pattern).
    cap: Cap<BusDeviceCap, Write>,
}

impl narf_power::device_pm::DevicePmOps for NvmePm {
    fn suspend(&self) -> Result<(), narf_power::device_pm::DevicePmError> {
        use core::fmt::Write as _;
        use narf_power::device_pm::DeviceSuspendError as PmErr;
        let name = ns::controller_name(self.instance);
        // Not installed (or removed): nothing to quiesce. The PM entry
        // outlives removal because the registry has no unregister.
        let Some(slot) = slot_of(self.instance) else {
            return Ok(());
        };
        // Bind the wait closure to a local rather than creating it
        // inline in the `match` scrutinee: a temporary there lives in
        // the block's tail expression and drops *after* the block's
        // locals, but its type may access the `name` borrow on drop
        // (E0597). Declared after `name`, the local drops first.
        let mut wait = pm_drain_wait(&name);
        match suspend_slot(slot, &self.cap, SHUTDOWN_DRAIN_TIMEOUT_MS, &mut wait) {
            SlotSuspend::Suspended(shutdown::ShutdownOutcome::Complete)
            | SlotSuspend::Suspended(shutdown::ShutdownOutcome::NotEnabled)
            | SlotSuspend::AlreadySuspended
            | SlotSuspend::NotReady => Ok(()),
            SlotSuspend::Suspended(shutdown::ShutdownOutcome::Gone) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "nvme: {name}: controller vanished during suspend; nothing left to power down"
                );
                Ok(())
            }
            SlotSuspend::Suspended(shutdown::ShutdownOutcome::TimedOut) => {
                // `DeviceSuspendError::DriverError` is documented for
                // exactly this: the controller didn't acknowledge the
                // shutdown notification. The queues are still torn
                // down, so the orchestrator's rollback resume rebuilds
                // the controller.
                let _ = writeln!(
                    narf_console::Writer,
                    "nvme: {name}: CC.SHN not acknowledged within the RTD3E budget; torn down anyway, reporting DriverError"
                );
                Err(PmErr::DriverError)
            }
            SlotSuspend::Busy => {
                let _ = writeln!(
                    narf_console::Writer,
                    "nvme: {name}: suspend refused: in-flight I/O did not drain"
                );
                Err(PmErr::Busy)
            }
            SlotSuspend::Failed => Err(PmErr::DriverError),
        }
    }

    fn resume(&self) -> Result<(), narf_power::device_pm::DevicePmError> {
        use narf_power::device_pm::DeviceSuspendError as PmErr;
        let name = ns::controller_name(self.instance);
        let Some(slot) = slot_of(self.instance) else {
            return Ok(());
        };
        // See `suspend`: the wait closure must be a local declared
        // after `name`, not a block-tail temporary (E0597).
        let mut wait = pm_drain_wait(&name);
        match resume_slot(slot, &self.cap, SHUTDOWN_DRAIN_TIMEOUT_MS, &mut wait) {
            SlotResume::Resumed | SlotResume::NotSuspended => Ok(()),
            SlotResume::Busy => Err(PmErr::Busy),
            SlotResume::Failed => Err(PmErr::DriverError),
        }
    }
}

/// `true` iff at least one controller has been probed successfully.
pub fn is_probed() -> bool {
    !CONTROLLERS.lock().is_empty()
}

/// Run `f` against the first controller (`nvme0`), if any. See
/// [`with_controller_at`].
pub fn with_controller<R>(f: impl FnOnce(&Controller) -> R) -> Option<R> {
    with_controller_at(0, f)
}

/// Run `f` against controller `instance`, if installed. The closure
/// receives `&Controller` for read-only inspection (capacity, model,
/// namespaces, ...).
///
/// Serialises on the slot's `req_gate`: the reference handed to `f` must
/// not alias a live I/O path's `&mut Controller`, and the gate is what
/// excludes those. Callers must not re-enter `with_controller*` from
/// inside `f` for the same instance — the gate is not reentrant.
pub fn with_controller_at<R>(instance: u32, f: impl FnOnce(&Controller) -> R) -> Option<R> {
    let g = controller_at(instance)?;
    Some(f(&g))
}

/// Outcome of an admin passthrough command.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PassthruResult {
    /// NVMe completion status field (`SCT << 8 | SC`), 0 on success.
    pub status: u16,
    /// Command-specific completion dword 0 (CQE DW0) — e.g. the result
    /// of a Get Features, echoed back into the passthrough struct.
    pub result: u32,
}

/// Run an admin passthrough command against the first controller.
pub fn admin_passthrough(
    cmd: &admin::AdminSqe,
    data: &mut [u8],
) -> Option<Result<PassthruResult, NvmeError>> {
    admin_passthrough_at(0, cmd, data)
}

/// Run an admin passthrough command against controller `instance`.
///
/// Acquires exclusive controller access via the slot's `req_gate` (so it
/// serialises against that controller's I/O, exactly like
/// `with_controller_at`), runs the command, and returns the raw status +
/// CQE DW0. `None` if the controller is not installed. This is the entry
/// point the `/dev/nvme<C>` char device's `ioctl_user` handler calls for
/// `NVME_IOCTL_ADMIN_CMD`.
pub fn admin_passthrough_at(
    instance: u32,
    cmd: &admin::AdminSqe,
    data: &mut [u8],
) -> Option<Result<PassthruResult, NvmeError>> {
    let mut g = controller_at(instance)?;
    Some(g.admin_passthrough(cmd, data))
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
    narf_power::system::register_shutdown_hook("nvme", shutdown_all_controllers);
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
    // Remove hooks for the bus detach path (bus spec §9.5): a
    // Detach event for a bound NVMe function reaches `remove` via
    // the default dispatcher and tears the controller down.
    for (name, _, _) in exact.iter().copied() {
        narf_bus::register_pci_remove(name, remove);
    }
    narf_bus::register_pci_remove("nvme-class", remove);
}

/// Bus detach hook (registered for every NVMe match in
/// [`register_pci_driver`]): the function at `device`'s address went
/// away — tear its controller down. `remove_controller` withdraws
/// the block devices + `/dev/nvme<C>` node and disables the
/// controller with the same discipline as system shutdown.
fn remove(
    device: narf_bus::BusDevice,
    cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
) {
    let narf_bus::BusAddr::Pcie(addr) = device.addr else {
        return;
    };
    if let Some(instance) = instance_of(addr) {
        let _ = remove_controller(instance, &cap);
    }
}
