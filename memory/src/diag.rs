//! Fixed-region kernel diagnostic state.
//!
//! A lock-free, alloc-free, IRQ-safe state bag that subsystems
//! update at well-known waypoints (boot phase, IRQ fire, #PF, panic,
//! heap milestones). A renderer reads the state and paints a fixed
//! corner of the framebuffer so a bare-metal operator can watch
//! kernel state without serial / paste / flash access.
//!
//! Why here (and not in `fb`): the updaters must be callable from
//! the panic sink, the `#PF` handler, and `interrupts::on_irq` —
//! all of which run with IF=0 and any of which may fire BEFORE the
//! FB driver has finished bringing up its writer. `narf-memory` is
//! the lowest crate every other one depends on, so updates from
//! anywhere are legal without a dependency cycle. The actual paint
//! pass lives in `fb::status` and reads through `snapshot()`.
//!
//! Contract:
//!   - All updaters are O(1) atomic ops with no allocation, no lock
//!     acquisition. Safe from IRQ context, the trap handler, and
//!     the panic sink.
//!   - `note_pf` is first-fault-wins: subsequent #PF observations
//!     don't overwrite the captured CR2/RIP. Operators want the
//!     earliest fault, not the latest.
//!   - `latch_panic` is also first-only: once latched, the renderer
//!     turns the panel red and shows the marker until reboot.
//!   - The renderer reads `snapshot()` which is a coherent-enough
//!     read of every field (each atomic load is independent — the
//!     state is informational, not a sync surface).

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

/// Coarse boot phases. Picks discrete waypoints rather than every
/// initcall so the operator sees forward progress without the
/// display thrashing. Updaters call `set_phase` at each transition.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BootPhase {
    /// Pre-Rust: BIOS / firmware / boot loader.
    Firmware = 0,
    /// `_start_rust` entered; UART early init not yet done.
    StartRust = 1,
    /// MMU + heap online; pre-initcalls.
    HeapUp = 2,
    /// `Stage::Early` running.
    InitEarly = 3,
    /// `Stage::Core` running.
    InitCore = 4,
    /// `Stage::PostCore` running.
    InitPostCore = 5,
    /// `Stage::Arch` running.
    InitArch = 6,
    /// `Stage::Subsys` running.
    InitSubsys = 7,
    /// `Stage::Fs` running.
    InitFs = 8,
    /// `Stage::Device` running.
    InitDevice = 9,
    /// `Stage::Late` running.
    InitLate = 10,
    /// All initcalls done; entering scheduler / userspace.
    Userspace = 11,
}

impl BootPhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            BootPhase::Firmware => "firmware",
            BootPhase::StartRust => "start_rust",
            BootPhase::HeapUp => "heap_up",
            BootPhase::InitEarly => "init:early",
            BootPhase::InitCore => "init:core",
            BootPhase::InitPostCore => "init:postcore",
            BootPhase::InitArch => "init:arch",
            BootPhase::InitSubsys => "init:subsys",
            BootPhase::InitFs => "init:fs",
            BootPhase::InitDevice => "init:device",
            BootPhase::InitLate => "init:late",
            BootPhase::Userspace => "userspace",
        }
    }

    /// Decode from a u8 (out-of-range collapses to Firmware).
    pub const fn from_u8(v: u8) -> Self {
        match v {
            1 => BootPhase::StartRust,
            2 => BootPhase::HeapUp,
            3 => BootPhase::InitEarly,
            4 => BootPhase::InitCore,
            5 => BootPhase::InitPostCore,
            6 => BootPhase::InitArch,
            7 => BootPhase::InitSubsys,
            8 => BootPhase::InitFs,
            9 => BootPhase::InitDevice,
            10 => BootPhase::InitLate,
            11 => BootPhase::Userspace,
            _ => BootPhase::Firmware,
        }
    }
}

static PHASE: AtomicU8 = AtomicU8::new(BootPhase::Firmware as u8);
static LAST_IRQ_VECTOR: AtomicU8 = AtomicU8::new(0);
static IRQ_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Sentinel `0` means "no #PF observed". A real CR2 of 0 (NULL
/// deref) is still reported — `FIRST_PF_LATCHED` separates the two
/// states without needing a sentinel value.
static FIRST_PF_CR2: AtomicU64 = AtomicU64::new(0);
static FIRST_PF_RIP: AtomicU64 = AtomicU64::new(0);
static FIRST_PF_LATCHED: AtomicBool = AtomicBool::new(false);
static PANIC_LATCHED: AtomicBool = AtomicBool::new(false);
static PANIC_MARKER: AtomicU64 = AtomicU64::new(0);
static HEAP_USED: AtomicU32 = AtomicU32::new(0);
static HEAP_TOTAL: AtomicU32 = AtomicU32::new(0);

/// Wi-Fi bring-up stage, in order. A bare-metal operator reads the
/// furthest stage reached and, on failure, which step failed — the
/// only Wi-Fi signal available without serial.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum WifiStage {
    /// No Wi-Fi driver has reported.
    None = 0,
    /// PCI function matched + identified.
    Probe = 1,
    /// Reset / link / interrupt setup.
    PowerUp = 2,
    /// Firmware transport up (MHI for ath11k).
    Transport = 3,
    /// Firmware booted to its run state.
    FwBoot = 4,
    /// Firmware control channel handshake (QMI for ath11k).
    Control = 5,
    /// Firmware command interface ready (WMI for ath11k).
    Commands = 6,
    /// Data-path rings live.
    DataPath = 7,
    /// Scan returned results.
    Scan = 8,
    /// Associated + keys installed.
    Connected = 9,
    /// Firmware crashed; the driver is resetting and re-initialising
    /// the device (ath11k `ath11k_core_reset` / `ath11k_core_restart`).
    /// The stage moves back to the bring-up stages as the device
    /// returns.
    Recovery = 10,
}

impl WifiStage {
    pub const fn as_str(self) -> &'static str {
        match self {
            WifiStage::None => "none",
            WifiStage::Probe => "probe",
            WifiStage::PowerUp => "power-up",
            WifiStage::Transport => "transport",
            WifiStage::FwBoot => "fw-boot",
            WifiStage::Control => "control",
            WifiStage::Commands => "commands",
            WifiStage::DataPath => "data-path",
            WifiStage::Scan => "scan",
            WifiStage::Connected => "connected",
            WifiStage::Recovery => "recovery",
        }
    }

    /// Decode from a u8 (out-of-range collapses to `None`).
    pub const fn from_u8(v: u8) -> Self {
        match v {
            1 => WifiStage::Probe,
            2 => WifiStage::PowerUp,
            3 => WifiStage::Transport,
            4 => WifiStage::FwBoot,
            5 => WifiStage::Control,
            6 => WifiStage::Commands,
            7 => WifiStage::DataPath,
            8 => WifiStage::Scan,
            9 => WifiStage::Connected,
            10 => WifiStage::Recovery,
            _ => WifiStage::None,
        }
    }
}

static WIFI_STAGE: AtomicU8 = AtomicU8::new(WifiStage::None as u8);
/// Driver-defined failing-step code; 0 = no failure latched.
static WIFI_ERR: AtomicU32 = AtomicU32::new(0);
/// Driver-defined detail word (typically the register value that
/// made the step fail).
static WIFI_DETAIL: AtomicU32 = AtomicU32::new(0);
/// Firmware crashes the Wi-Fi driver started a recovery for, and how
/// many of those recoveries completed.
static WIFI_CRASHES: AtomicU32 = AtomicU32::new(0);
static WIFI_RECOVERED: AtomicU32 = AtomicU32::new(0);

/// IRQ-safe: a Wi-Fi firmware crash was detected and recovery started
/// (also sets [`WifiStage::Recovery`]).
#[inline]
pub fn note_wifi_crash() {
    WIFI_CRASHES.fetch_add(1, Ordering::AcqRel);
    set_wifi_stage(WifiStage::Recovery);
}

/// IRQ-safe: a Wi-Fi firmware recovery completed.
#[inline]
pub fn note_wifi_recovered() {
    WIFI_RECOVERED.fetch_add(1, Ordering::AcqRel);
}

/// IRQ-safe: record that Wi-Fi bring-up reached `stage`.
#[inline]
pub fn set_wifi_stage(stage: WifiStage) {
    WIFI_STAGE.store(stage as u8, Ordering::Release);
}

/// IRQ-safe: latch a Wi-Fi bring-up failure. `err` is a non-zero
/// driver-defined step code, `detail` a supporting value. First
/// failure wins, like `note_pf`: the earliest failure explains the
/// rest.
#[inline]
pub fn latch_wifi_error(err: u32, detail: u32) {
    if err != 0
        && WIFI_ERR
            .compare_exchange(0, err, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    {
        WIFI_DETAIL.store(detail, Ordering::Release);
    }
}

/// IRQ-safe: bump the boot-phase marker.
#[inline]
pub fn set_phase(p: BootPhase) {
    PHASE.store(p as u8, Ordering::Release);
}

/// IRQ-safe: record a vector that just fired and bump the total.
/// Called from `interrupts::dispatch::on_irq` with the unsoft-masked
/// vector. O(1), two `fetch_add`/`store` ops, no allocation.
#[inline]
pub fn bump_irq(vector: u8) {
    LAST_IRQ_VECTOR.store(vector, Ordering::Relaxed);
    IRQ_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// IRQ-safe: record the first observed #PF. Subsequent calls are
/// no-ops so the operator sees the EARLIEST fault — usually the
/// one that triggered a cascade.
#[inline]
pub fn note_pf(cr2: u64, rip: u64) {
    if FIRST_PF_LATCHED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        FIRST_PF_CR2.store(cr2, Ordering::Release);
        FIRST_PF_RIP.store(rip, Ordering::Release);
    }
}

/// IRQ-safe: latch a panic. `marker` is a free-form u64 — common
/// choice is a hash of `file:line` for compact display. Subsequent
/// calls are no-ops; the first panic wins (recursive panics happen
/// during the panic sink itself).
#[inline]
pub fn latch_panic(marker: u64) {
    if PANIC_LATCHED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        PANIC_MARKER.store(marker, Ordering::Release);
    }
}

/// Set the heap state in KB. Updaters are encouraged to call this
/// at low frequency (a low-rate poll or on size-class growth) —
/// it's not on the alloc hot path.
#[inline]
pub fn set_heap_kb(used_kb: u32, total_kb: u32) {
    HEAP_USED.store(used_kb, Ordering::Relaxed);
    HEAP_TOTAL.store(total_kb, Ordering::Relaxed);
}

/// Lock-free snapshot of the diag state for the renderer.
#[derive(Copy, Clone, Debug)]
pub struct Snapshot {
    pub phase: BootPhase,
    pub last_irq_vector: u8,
    pub irq_total: u64,
    pub first_pf_cr2: u64,
    pub first_pf_rip: u64,
    pub first_pf_seen: bool,
    pub panic_latched: bool,
    pub panic_marker: u64,
    pub heap_used_kb: u32,
    pub heap_total_kb: u32,
    pub wifi_stage: WifiStage,
    pub wifi_err: u32,
    pub wifi_detail: u32,
    /// Firmware crashes a recovery was started for.
    pub wifi_crashes: u32,
    /// Recoveries that completed.
    pub wifi_recovered: u32,
}

pub fn snapshot() -> Snapshot {
    Snapshot {
        phase: BootPhase::from_u8(PHASE.load(Ordering::Acquire)),
        last_irq_vector: LAST_IRQ_VECTOR.load(Ordering::Relaxed),
        irq_total: IRQ_TOTAL.load(Ordering::Relaxed),
        first_pf_cr2: FIRST_PF_CR2.load(Ordering::Acquire),
        first_pf_rip: FIRST_PF_RIP.load(Ordering::Acquire),
        first_pf_seen: FIRST_PF_LATCHED.load(Ordering::Acquire),
        panic_latched: PANIC_LATCHED.load(Ordering::Acquire),
        panic_marker: PANIC_MARKER.load(Ordering::Acquire),
        heap_used_kb: HEAP_USED.load(Ordering::Relaxed),
        heap_total_kb: HEAP_TOTAL.load(Ordering::Relaxed),
        wifi_stage: WifiStage::from_u8(WIFI_STAGE.load(Ordering::Acquire)),
        wifi_err: WIFI_ERR.load(Ordering::Acquire),
        wifi_detail: WIFI_DETAIL.load(Ordering::Acquire),
        wifi_crashes: WIFI_CRASHES.load(Ordering::Acquire),
        wifi_recovered: WIFI_RECOVERED.load(Ordering::Acquire),
    }
}

/// Reset the state bag. Test-only — production code MUST NOT call
/// this; the latch semantics depend on first-write-wins.
#[doc(hidden)]
pub fn __reset_for_test() {
    PHASE.store(BootPhase::Firmware as u8, Ordering::Release);
    LAST_IRQ_VECTOR.store(0, Ordering::Relaxed);
    IRQ_TOTAL.store(0, Ordering::Relaxed);
    FIRST_PF_CR2.store(0, Ordering::Release);
    FIRST_PF_RIP.store(0, Ordering::Release);
    FIRST_PF_LATCHED.store(false, Ordering::Release);
    PANIC_LATCHED.store(false, Ordering::Release);
    PANIC_MARKER.store(0, Ordering::Release);
    HEAP_USED.store(0, Ordering::Relaxed);
    HEAP_TOTAL.store(0, Ordering::Relaxed);
    WIFI_STAGE.store(WifiStage::None as u8, Ordering::Release);
    WIFI_ERR.store(0, Ordering::Release);
    WIFI_DETAIL.store(0, Ordering::Release);
    WIFI_CRASHES.store(0, Ordering::Release);
    WIFI_RECOVERED.store(0, Ordering::Release);
}
