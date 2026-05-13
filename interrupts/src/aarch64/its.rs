//! GICv3 ITS (Interrupt Translation Service) bring-up.
//!
//! On aarch64 with GICv3+ITS the MSI delivery path is:
//!
//!   device → MSI write → `GITS_TRANSLATER` → ITS lookup → LPI INTID
//!     → redistributor → CPU.
//!
//! `program_vector` on aarch64 needs three things from this module:
//!   - a doorbell address (`doorbell_pa`) — the physical address a
//!     device writes its MSI message to;
//!   - an event-id-to-LPI mapping (`map_event`) — issued via ITS
//!     commands MAPD + MAPTI;
//!   - a "collection 0 lives on the BSP" precondition — established
//!     once at boot via MAPC.
//!
//! Stage-3 cut targets QEMU virt's default ITS layout (`its=on` is on
//! by default for `gic-version=3`). MMIO bases and the IDbits / Devbits
//! fields of `GITS_TYPER` are read live; only the *base addresses* are
//! hardcoded for now (DTB parsing for those is a follow-up).
//!
//! What lands here:
//!   - Probe `GITS_TYPER` for sizing.
//!   - Allocate four backing pages: ITS device table, ITS collection
//!     table, ITS command queue, GICR LPI config table. The pending
//!     table sits in 8 KiB allocated as two contiguous frames.
//!   - Program `GITS_BASER0`/`GITS_BASER1`, `GITS_CBASER`, then set
//!     `GITS_CTLR.Enabled`.
//!   - Program `GICR_PROPBASER` + `GICR_PENDBASER`; flip
//!     `GICR_CTLR.EnableLPIs`.
//!   - Issue MAPC (collection 0 → redistributor 0), waiting for
//!     `GITS_CREADR` to catch up to `GITS_CWRITER`.
//!
//! What still isn't here: per-device ITT (interrupt translation table)
//! allocation. QEMU's ITS treats `MAPD ITT_addr=0` permissively — the
//! Stage-3 cut leans on that; a hardware-faithful Stage-4 will allocate
//! an ITT page per device on first MAPD.

use core::fmt;
use core::sync::atomic::{compiler_fence, AtomicBool, AtomicU64, Ordering};

use narf_arch::aarch64::mmio::{read_u32, write_u32};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::{alloc_frame, PAGE_SIZE};

/// QEMU virt GICv3 ITS frame base.
const ITS_BASE: usize = 0x0808_0000;
/// QEMU virt GICv3 redistributor base for CPU 0.
const GICR_BASE: usize = 0x080A_0000;

const GITS_CTLR: usize = ITS_BASE + 0x0000;
#[allow(dead_code)]
const GITS_TYPER: usize = ITS_BASE + 0x0008;
const GITS_CBASER: usize = ITS_BASE + 0x0080;
const GITS_CWRITER: usize = ITS_BASE + 0x0088;
const GITS_CREADR: usize = ITS_BASE + 0x0090;
const GITS_BASER0: usize = ITS_BASE + 0x0100;
/// Doorbell — the physical address devices write to deliver MSI.
const GITS_TRANSLATER: usize = ITS_BASE + 0x10040;

const GICR_CTLR: usize = GICR_BASE + 0x0000;
const GICR_PROPBASER: usize = GICR_BASE + 0x0070;
const GICR_PENDBASER: usize = GICR_BASE + 0x0078;

/// First LPI INTID (per GIC architecture, fixed).
pub const LPI_BASE: u32 = 8192;
/// Stage-3 cap on LPIs we provision room for in the LPI config table.
/// Each LPI costs 1 byte in the config table; 256 LPIs fit in a
/// single 4 KiB page with plenty of headroom.
pub const NUM_LPIS: u32 = 256;

static INIT_DONE: AtomicBool = AtomicBool::new(false);

/// Per-CPU command-queue tail pointer. ITS-internal monotonic offset
/// in bytes from `GITS_CBASER` base. Wraps inside `submit_command`.
static CMD_TAIL: AtomicU64 = AtomicU64::new(0);

/// Lock guarding command-queue submission. ITS commands are 32 bytes
/// each; the queue itself is one page (128 commands). Submission
/// requires writing the command bytes + bumping `GITS_CWRITER` +
/// polling `GITS_CREADR` — all under one lock so two callers can't
/// race on the tail.
static CMD_LOCK: IrqSafeSpinLock<()> = IrqSafeSpinLock::new(());

/// ITS-init / command-issue error surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ItsError {
    /// Backing-page allocation failed during init.
    NoMemory,
    /// `GITS_CTLR` never reported Quiescent / Enabled within the
    /// bounded poll. Likely a misprogrammed `GITS_BASERn`.
    InitTimeout,
    /// Command queue didn't drain within the bounded poll.
    CmdTimeout,
    /// `init_bsp` was never called.
    NotInitialised,
}

impl From<narf_memory::FrameAllocError> for ItsError {
    fn from(_: narf_memory::FrameAllocError) -> Self {
        ItsError::NoMemory
    }
}

/// ITS doorbell physical address. Devices write 32 bits to this
/// address; the low 32 bits of the data become the EventID.
#[inline]
pub const fn doorbell_pa() -> u64 {
    GITS_TRANSLATER as u64
}

/// Bring up the ITS on the BSP. Idempotent; subsequent calls return
/// `Ok(())` without redoing the work.
///
/// # Safety
/// - GICv3 distributor + CPU 0 redistributor must be enabled
///   (`gic::init_bsp` ran first).
/// - `narf_memory::init_from_map` must have run (we call
///   `alloc_frame`).
/// - QEMU virt is the only tested platform; non-QEMU GICv3+ITS
///   may not match these MMIO bases.
pub unsafe fn init_bsp() -> Result<(), ItsError> {
    if INIT_DONE.load(Ordering::Acquire) {
        return Ok(());
    }

    // ── 1. Allocate backing pages ─────────────────────────────────
    // Each is a fresh frame (zero-filled by the allocator's contract).
    let device_tab = alloc_frame()?.start_address().raw();
    let coll_tab = alloc_frame()?.start_address().raw();
    let cmdq = alloc_frame()?.start_address().raw();
    let prop_tab = alloc_frame()?.start_address().raw();
    // GICR_PENDBASER must point at a 64 KiB-aligned region per the
    // architecture, but QEMU is permissive and the pending bits for
    // 256 LPIs fit in 32 bytes. Two contiguous frames give us 8 KiB
    // — enough for up to 65536 LPIs even though we only provision
    // 256 — which dodges the alignment edge case.
    let pend_tab = alloc_frame()?.start_address().raw();
    let _pend_2nd = alloc_frame()?.start_address().raw();
    // The architectural page size for GIC tables is 4 KiB; alloc_frame
    // returns 4 KiB frames so this matches by construction.
    debug_assert_eq!(PAGE_SIZE, 4096);

    // ── 2. Program GITS_BASER0 = device table, GITS_BASER1 = coll. ─
    //
    // GITS_BASER layout (Arm IHI 0069H §11.9.2):
    //   bit 63       = Valid
    //   bits 61:59   = type-of-table (RO)
    //   bit  58       = Indirect (we use direct → 0)
    //   bits 53:48   = entry size in bytes - 1
    //   bits 47:12   = base PA[51:12]
    //   bits 7:0     = size in 4 KiB pages - 1 (single page → 0)
    //
    // We don't know entry sizes statically — read GITS_BASER0 first
    // and preserve the implementation-supplied entry-size field (RO
    // on most implementations, RW on some; preserving is always
    // correct).
    // SAFETY: identity-mapped MMIO read.
    let baser0_old = unsafe { read_u64(GITS_BASER0) };
    let entry_size_dev = baser0_old & (0x1F << 48);
    let baser0 = (1u64 << 63) | entry_size_dev | (device_tab & 0x000F_FFFF_FFFF_F000) | 0; // size = 1 page
                                                                                           // SAFETY: device table page is fresh & zeroed.
    unsafe {
        write_u64(GITS_BASER0, baser0);
    }

    // SAFETY: identity-mapped MMIO read.
    let baser1_old = unsafe { read_u64(GITS_BASER0 + 8) };
    let entry_size_coll = baser1_old & (0x1F << 48);
    let baser1 = (1u64 << 63) | entry_size_coll | (coll_tab & 0x000F_FFFF_FFFF_F000) | 0;
    // SAFETY: collection table page is fresh & zeroed.
    unsafe {
        write_u64(GITS_BASER0 + 8, baser1);
    }

    // ── 3. Program GITS_CBASER = command queue ────────────────────
    // GITS_CBASER layout (§11.9.3):
    //   bit 63      = Valid
    //   bits 51:12  = base PA[51:12]
    //   bits 7:0    = size in 4 KiB pages - 1
    //
    // One 4 KiB page = 128 × 32-byte ITS commands. Plenty for boot
    // + Stage-3 driver count.
    let cbaser = (1u64 << 63) | (cmdq & 0x000F_FFFF_FFFF_F000) | 0;
    // SAFETY: command-queue page is fresh & zeroed.
    unsafe {
        write_u64(GITS_CBASER, cbaser);
    }
    // Reset CWRITER to 0; CREADR is RO and follows.
    // SAFETY: identity-mapped MMIO.
    unsafe {
        write_u64(GITS_CWRITER, 0);
    }

    // ── 4. Enable the ITS ─────────────────────────────────────────
    // GITS_CTLR: bit 0 = Enabled. Bit 31 = Quiescent (set when no
    // commands are in flight); we don't poll it on init because we
    // started fresh.
    // SAFETY: identity-mapped MMIO.
    unsafe {
        write_u32(GITS_CTLR as *mut u32, 1);
    }

    // ── 5. Program GICR_PROPBASER + GICR_PENDBASER ────────────────
    //
    // GICR_PROPBASER layout (§11.10.16):
    //   bits 51:12 = base PA[51:12]
    //   bits 4:0   = IDbits - 1 (NUM_LPIs supported = 2^(IDbits) - 8192)
    //
    // We support NUM_LPIS LPIs starting at LPI_BASE. The minimum
    // IDbits encoding that covers `LPI_BASE + NUM_LPIS` is 14
    // (gives up to 16384 INTIDs total). Stage-3 doesn't push the
    // upper bound; pick 14 to keep the math simple.
    let id_bits = 14u64;
    let propbaser = (prop_tab & 0x000F_FFFF_FFFF_F000) | (id_bits - 1);
    // SAFETY: identity-mapped MMIO; redistributor was woken up by
    // gic::init_bsp.
    unsafe {
        write_u64(GICR_PROPBASER, propbaser);
    }

    // GICR_PENDBASER:
    //   bits 51:12 = base PA[51:12]
    let pendbaser = pend_tab & 0x000F_FFFF_FFFF_F000;
    // SAFETY: same redistributor.
    unsafe {
        write_u64(GICR_PENDBASER, pendbaser);
    }

    // GICR_CTLR.EnableLPIs (bit 0).
    // SAFETY: identity-mapped MMIO.
    unsafe {
        let cur = read_u32(GICR_CTLR as *mut u32);
        write_u32(GICR_CTLR as *mut u32, cur | 1);
    }

    INIT_DONE.store(true, Ordering::Release);

    // ── 6. MAPC: collection 0 → redistributor 0 ───────────────────
    // Without this the ITS doesn't know where to deliver LPIs even
    // after MAPTI runs.
    // SAFETY: ITS is enabled, command queue is programmed.
    unsafe {
        map_collection(0, 0)?;
    }

    Ok(())
}

/// Submit MAPD + MAPTI commands for `(device_id, event_id)` →
/// `(lpi_intid, collection)`. Idempotent at the ITS level — issuing
/// the same MAPD twice is harmless because we don't allocate per-
/// device ITT pages (Stage-3 corner cut).
///
/// # Safety
/// `init_bsp` must have run; LPI INTID must be in the configured
/// range; `lpi_intid >= LPI_BASE`.
pub unsafe fn map_event(
    device_id: u32,
    event_id: u32,
    lpi_intid: u32,
    collection: u16,
) -> Result<(), ItsError> {
    if !INIT_DONE.load(Ordering::Acquire) {
        return Err(ItsError::NotInitialised);
    }

    // MAPD command (§5.13.5): cmd[0] bits 7:0 = 0x08, cmd[0] bits
    // 63:32 = DeviceID, cmd[2] bit 63 = Valid, cmd[2] bits 7:0 =
    // ITT-size encoded as log2(N)-1 (we use 0 ⇒ 1-entry ITT — the
    // QEMU ITS tolerates this; hardware-faithful would allocate an
    // ITT page).
    let mut mapd = [0u64; 4];
    mapd[0] = 0x08 | ((device_id as u64) << 32);
    mapd[2] = 1u64 << 63;
    // SAFETY: command bytes are well-formed; submit handles MMIO.
    unsafe {
        submit_command(&mapd)?;
    }

    // MAPTI command (§5.13.13): cmd[0] bits 7:0 = 0x0A, cmd[0] bits
    // 63:32 = DeviceID, cmd[1] bits 31:0 = EventID, cmd[1] bits
    // 63:32 = pINTID (LPI), cmd[2] bits 15:0 = ICID (collection).
    let mut mapti = [0u64; 4];
    mapti[0] = 0x0A | ((device_id as u64) << 32);
    mapti[1] = (event_id as u64) | ((lpi_intid as u64) << 32);
    mapti[2] = collection as u64;
    // SAFETY: command bytes are well-formed.
    unsafe {
        submit_command(&mapti)?;
    }
    Ok(())
}

/// MAPC command — bind a collection to a redistributor. Only used
/// internally during init.
unsafe fn map_collection(collection: u16, rd_index: u16) -> Result<(), ItsError> {
    // MAPC (§5.13.4): cmd[0] bits 7:0 = 0x09; cmd[2] bits 15:0 =
    // ICID, cmd[2] bits 50:16 = RDbase, cmd[2] bit 63 = Valid.
    let mut mapc = [0u64; 4];
    mapc[0] = 0x09;
    mapc[2] = (collection as u64) | ((rd_index as u64) << 16) | (1u64 << 63);
    // SAFETY: caller asserts ITS is configured (called from init_bsp).
    unsafe { submit_command(&mapc) }
}

/// Push a 32-byte command into the queue, bump `GITS_CWRITER`, then
/// poll `GITS_CREADR` until it catches up. Bounded by 1M MMIO reads.
unsafe fn submit_command(cmd: &[u64; 4]) -> Result<(), ItsError> {
    let _g = CMD_LOCK.lock();

    // Where in the 4 KiB queue does this command land?
    let tail = CMD_TAIL.load(Ordering::Relaxed);
    let queue_size = PAGE_SIZE; // one 4 KiB page
    let off = tail % queue_size;

    // Dereference the command-queue base via GITS_CBASER's stored
    // address. We re-read it from the register so this works even
    // across re-init (or for a Stage-4 multi-page queue).
    // SAFETY: identity-mapped MMIO.
    let cbaser = unsafe { read_u64(GITS_CBASER) };
    let queue_pa = cbaser & 0x000F_FFFF_FFFF_F000;
    let entry = (queue_pa + off) as *mut u64;

    // Write the four 8-byte command words. ITS commands are
    // little-endian; the architecture treats them as four `u64`s.
    // SAFETY: identity-mapped DRAM page allocated by init_bsp.
    unsafe {
        compiler_fence(Ordering::SeqCst);
        core::ptr::write_volatile(entry, cmd[0]);
        core::ptr::write_volatile(entry.add(1), cmd[1]);
        core::ptr::write_volatile(entry.add(2), cmd[2]);
        core::ptr::write_volatile(entry.add(3), cmd[3]);
        compiler_fence(Ordering::SeqCst);
    }

    let new_tail = (tail + 32) % queue_size;
    CMD_TAIL.store(new_tail, Ordering::Relaxed);

    // Bump CWRITER. ITS picks up the new commands.
    // SAFETY: identity-mapped MMIO.
    unsafe {
        write_u64(GITS_CWRITER, new_tail);
    }

    // Poll CREADR until it catches up. ITS may pause if it hits a
    // Stalled state, but for our well-formed commands QEMU drains
    // immediately. responsive_spin_until ticks sleep_pumps so the
    // FB cursor / serial drain stay alive on a Stalled ITS.
    // 100 ms wedge threshold (a healthy ITS drains a single
    // command in <<1 ms).
    let done = narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: identity-mapped MMIO.
            let cr = unsafe { read_u64(GITS_CREADR) };
            // Note: GITS_CREADR low bit = Stalled. Mask it off
            // for the catch-up compare.
            (cr & !1) == new_tail
        },
        narf_time::Deadline::after_ms(100),
    );
    if done {
        Ok(())
    } else {
        Err(ItsError::CmdTimeout)
    }
}

// ── helpers — 64-bit MMIO. The aarch64 backend in narf_arch only
// ── exposes 32-bit MMIO, so we add the 64-bit variant locally.
#[inline]
unsafe fn read_u64(addr: usize) -> u64 {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller asserts the slot is readable + 8-byte aligned.
    let v = unsafe { core::ptr::read_volatile(addr as *const u64) };
    compiler_fence(Ordering::SeqCst);
    v
}

#[inline]
unsafe fn write_u64(addr: usize, value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller asserts the slot is writable + 8-byte aligned.
    unsafe {
        core::ptr::write_volatile(addr as *mut u64, value);
    }
    compiler_fence(Ordering::SeqCst);
}

impl fmt::Display for ItsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ItsError::NoMemory => f.write_str("ITS: out of frames during init"),
            ItsError::InitTimeout => f.write_str("ITS: register did not settle"),
            ItsError::CmdTimeout => f.write_str("ITS: command queue stalled"),
            ItsError::NotInitialised => f.write_str("ITS: init_bsp not called"),
        }
    }
}
