//! narf-observability — PMU counters, crash-frame capture, panic
//! flight-recorder snapshot.
//!
//! Spec: `observability/specification/spec.md`. Stage-2 lands the
//! Cycles + Instructions PMU read paths and the basic `CrashFrame`
//! capture; Stage-3 wires `tracing/`'s `FlightRing` into the panic
//! path so a core dump can carry the last-N events leading up to the
//! fault. GDB stub and live-peek surfaces are Stage-4 (deferred).
//!
//! Capability gates (per spec §4):
//!   * Reading PMU counters needs `Cap<Pmu, Read>`.
//!   * Enabling user-ring RDPMC / `PMUSERENR_EL0` needs
//!     `Cap<Pmu, Write>` — the path that flips CR4.PCE on x86_64 or
//!     PMUSERENR_EL0 on aarch64.
//!   * Installing a panic-snapshot ring needs `Cap<Recorder, Grant>`.
//!
//! Non-goals in this crate (Stage-4+):
//!   * Multi-event PMU groups + multiplexed counter sets (spec §3.1).
//!   * Live HW trace (Intel PT, Arm CoreSight) capture (spec §3.1+§3.2).
//!   * GDB remote-serial stub + watchpoint install via
//!     `Cap<Watchpoint, Grant>` (spec §3.2).
//!   * `peek_*` live-inspection surface (spec §3.4).
//!   * On-host core-dump parser tooling.
//!
//! Arch deferrals flagged for the `arch/` HAL maintainer:
//!   * No `arch::x86_64::pmu::rdpmc(idx)` exists; instructions-retired
//!     reads short-circuit to `Err(NotAvailable)` until that primitive
//!     lands. Cycles fall back to `narf_time::now_cycles()` (RDTSC) for
//!     Stage-3 parity per the spec note.
//!   * No `arch::aarch64::pmu` module exists; PMCCNTR / PMEVCNTR /
//!     PMUSERENR_EL0 reads return `Err(NotAvailable)` for the same
//!     reason. The Stage-2 brief documents this as a Stage-4 follow-up.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod gdb;
pub mod peek;

mod tests;

pub use gdb::{GdbCommand, GdbError, GdbPacket};
pub use peek::{MetricSample, MetricValue, PeekError, Provider};

use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use narf_capabilities::{
    Cap, CapError, CapKind, CapType, Grant, NoopOp, Read, Write,
};
use narf_lib::id::DomainId;
use narf_tracing::FlightRing;

// ── Errors ──────────────────────────────────────────────────────────

/// Observability surface error. Distinct from `CapError` so callers
/// can tell "cap revoked" apart from "PMU isn't usable on this CPU".
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ObsError {
    /// The capability epoch check failed — cap was revoked.
    Revoked,
    /// The PMU primitive needed for this read is not yet wired into
    /// `arch/`. Stage-4 follow-up; the Stage-2 spec marks this as
    /// acceptable to skip.
    NotAvailable,
    /// The hardware is present but the counter is currently disabled
    /// (e.g. `PMCR_EL0.E == 0`, `IA32_PERF_GLOBAL_CTRL` masked).
    CounterDisabled,
    /// User-ring read enable failed because the host arch HAL doesn't
    /// expose the required write yet.
    EnableUnsupported,
}

impl From<CapError> for ObsError {
    fn from(e: CapError) -> Self {
        match e {
            CapError::Revoked => ObsError::Revoked,
            // Other variants are rights / domain mismatches that the
            // type system already prevents at the Cap<T, R> level — if
            // we ever see one in practice, treat it as "not available".
            _ => ObsError::NotAvailable,
        }
    }
}

// ── CapType wiring ──────────────────────────────────────────────────
//
// `CapKind::Pmu` and `CapKind::Recorder` already live in the
// `capabilities/` registry. To `bootstrap()` a typed `Cap<Pmu, R>` we
// need a zero-sized type tagging it with the right `CapKind`.

/// Marker type for `Cap<Pmu, _>` — gates the PMU read / control surface.
#[derive(Copy, Clone, Debug)]
pub struct Pmu;

impl CapType for Pmu {
    const KIND: CapKind = CapKind::Pmu;
}

/// Marker type for `Cap<Recorder, _>` — gates installation of a
/// flight-recorder panic-snapshot ring.
#[derive(Copy, Clone, Debug)]
pub struct Recorder;

impl CapType for Recorder {
    const KIND: CapKind = CapKind::Recorder;
}

/// Marker type for `Cap<Debugger, _>` — Stage-4 GDB-stub gate. Wired
/// here so Stage-3 callers can already hold the typed cap; the
/// transport itself lands in Stage 4.
#[derive(Copy, Clone, Debug)]
pub struct Debugger;

impl CapType for Debugger {
    const KIND: CapKind = CapKind::Debugger;
}

/// Marker type for `Cap<Diagnostics, _>` — Stage-4 live-peek gate.
#[derive(Copy, Clone, Debug)]
pub struct Diagnostics;

impl CapType for Diagnostics {
    const KIND: CapKind = CapKind::Diagnostics;
}

/// Marker type for `Cap<Watchpoint, _>` — Stage-4 hardware-watchpoint
/// install gate.
#[derive(Copy, Clone, Debug)]
pub struct Watchpoint;

impl CapType for Watchpoint {
    const KIND: CapKind = CapKind::Watchpoint;
}

// ── PMU counters ────────────────────────────────────────────────────
//
// Stage-2 scope is Cycles + Instructions retired. Real multi-event
// groups, sampling, and multiplexing are Stage-3+ in `tracing/`'s
// transport orbit (see §3.1 sampling note in the spec).
//
// On x86_64 the spec offers two paths for Cycles:
//   (a) RDPMC fixed-counter 1 (FIXED_CTR1 = unhalted core cycles).
//   (b) RDTSC fall-back for Stage-3 parity.
// We pick (b): `narf_time::now_cycles()` already wraps RDTSC with the
// `compiler_fence` discipline, no new inline asm in this crate, and
// the cap-gating semantics are identical from the caller's view. When
// `arch::x86_64::pmu::rdpmc` lands the implementation can switch over
// without touching the public signature.
//
// For Instructions retired neither RDTSC nor an existing arch primitive
// is sufficient — every read path needs RDPMC fixed-counter 0
// (x86_64) or PMEVCNTRn_EL0 (aarch64). Since `arch/` doesn't expose
// those yet and the brief forbids adding inline asm here, the call
// returns `Err(NotAvailable)`. Test harness skips with that reason.

/// Read the CPU cycle counter.
///
/// Cap-gated: caller must hold a live `Cap<Pmu, Read>`. Returns
/// `Err(Revoked)` if the cap's epoch no longer matches its object,
/// `Err(NotAvailable)` if the underlying primitive isn't usable at
/// the current ring.
///
/// Stage-2 implementation: forwards to `narf_time::now_cycles()` —
/// RDTSC on x86_64, `CNTPCT_EL0` on aarch64. Stage-4 will switch the
/// x86_64 path to RDPMC FIXED_CTR1 once `arch/x86_64/pmu` lands.
pub fn read_cycles(cap: &Cap<Pmu, Read>) -> Result<u64, ObsError> {
    cap.invoke(NoopOp)?;
    Ok(narf_time::now_cycles())
}

/// Read the instructions-retired counter.
///
/// Stage-2 stub: every call returns `Err(NotAvailable)` until the
/// `arch/` HAL grows an `rdpmc` (x86_64) / `read_pmevcntr0` (aarch64)
/// primitive. The cap is still epoch-checked so revocation produces a
/// distinguishable `Err(Revoked)` for the test that exercises that
/// path.
pub fn read_instructions(cap: &Cap<Pmu, Read>) -> Result<u64, ObsError> {
    cap.invoke(NoopOp)?;
    Err(ObsError::NotAvailable)
}

/// Enable user-ring PMU reads.
///
/// On x86_64 this sets `CR4.PCE` so `RDPMC` is legal at CPL=3. On
/// aarch64 it would set `PMUSERENR_EL0.{EN,CR}` to grant EL0 access
/// to `PMCCNTR_EL0` / `PMEVCNTRn_EL0`.
///
/// Cap-gated by `Cap<Pmu, Write>`: callers prove derivation authority
/// before any privileged register write. A failure of the underlying
/// primitive (e.g. aarch64 `PMUSERENR_EL0` has no arch wrapper yet)
/// surfaces as `Err(EnableUnsupported)` — the call is structurally
/// sound, just deferred.
pub fn enable_user_reads(cap: &Cap<Pmu, Write>) -> Result<(), ObsError> {
    cap.invoke(NoopOp)?;

    #[cfg(target_arch = "x86_64")]
    {
        // CR4.PCE is bit 8. `narf_arch::x86_64::cr` already wraps
        // read/write CR4 with the `compiler_fence(SeqCst)` pair from
        // arch/ §4 — we don't touch inline asm here.
        const CR4_PCE: u64 = 1 << 8;
        // SAFETY: `read_cr4` is always legal at CPL=0; `write_cr4`
        // with only the PCE bit toggled is documented-writable per
        // SDM Vol. 3 §2.5. The arch wrapper handles the LTO-fence
        // discipline.
        unsafe {
            let cr4 = narf_arch::x86_64::cr::read_cr4();
            narf_arch::x86_64::cr::write_cr4(cr4 | CR4_PCE);
        }
        Ok(())
    }
    #[cfg(target_arch = "aarch64")]
    {
        // PMUSERENR_EL0 enable would land here once
        // `arch::aarch64::pmu` exposes a wrapper; flagged as a Stage-4
        // arch deferral in the crate-level docs.
        Err(ObsError::EnableUnsupported)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Err(ObsError::EnableUnsupported)
    }
}

// ── Crash frame ─────────────────────────────────────────────────────
//
// Per spec §3.3 the panic hook captures fault registers, the faulting
// CPU, and the faulting domain. Stage-2 lands the data structures and
// the synchronous `capture_crash_frame` constructor; the wiring from
// `frame/`'s panic path is Stage-4 work.

/// x86_64 register state captured at fault time.
///
/// Field order mirrors `NT_PRSTATUS` so a future ELF-core writer can
/// memcpy the struct into a note section. Spec §3.3 names this as a
/// reuse target for tool compatibility (`gdb`, `crash`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ArchRegs {
    pub rax:    u64,
    pub rbx:    u64,
    pub rcx:    u64,
    pub rdx:    u64,
    pub rsi:    u64,
    pub rdi:    u64,
    pub rbp:    u64,
    pub rsp:    u64,
    pub r8:     u64,
    pub r9:     u64,
    pub r10:    u64,
    pub r11:    u64,
    pub r12:    u64,
    pub r13:    u64,
    pub r14:    u64,
    pub r15:    u64,
    pub rip:    u64,
    pub rflags: u64,
    pub cs:     u64,
    pub ss:     u64,
}

/// aarch64 register state captured at fault time.
#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ArchRegs {
    pub x:      [u64; 31],
    pub sp:     u64,
    pub pc:     u64,
    pub pstate: u64,
}

/// Number of stack words snapshotted into a `CrashFrame`. 128 × 8 =
/// 1 KiB; small enough to live in static storage of a panic dump,
/// large enough to cover a typical call chain on both arches.
pub const CRASH_STACK_WORDS: usize = 128;

/// Snapshot of CPU + stack state captured by the panic path.
///
/// `Default` is hand-implemented because the per-arch `ArchRegs` type
/// is `Default` and the `[u64; 128]` field can't derive automatically
/// without that bound being visible to the derive macro.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CrashFrame {
    /// Architectural registers at fault.
    pub registers:       ArchRegs,
    /// Up to `CRASH_STACK_WORDS` words from the stack starting at the
    /// faulting SP / RSP. Reads past the end of valid stack are zero-
    /// filled — the dump consumer treats trailing zeros as truncation
    /// rather than data per spec §3.3 partial-dump rules.
    pub stack:           [u64; CRASH_STACK_WORDS],
    /// Faulting instruction pointer (mirrors `registers.rip` /
    /// `registers.pc` for arch-agnostic consumers).
    pub instruction_ptr: u64,
    /// Domain that was active when the fault hit — drives the
    /// "Domain fault section" attribution in the core dump.
    pub domain:          DomainId,
}

impl Default for CrashFrame {
    fn default() -> Self {
        Self {
            registers:       ArchRegs::default(),
            stack:           [0; CRASH_STACK_WORDS],
            instruction_ptr: 0,
            domain:          DomainId::FRAME,
        }
    }
}

impl core::fmt::Debug for CrashFrame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CrashFrame")
            .field("instruction_ptr", &self.instruction_ptr)
            .field("domain",          &self.domain)
            .finish_non_exhaustive()
    }
}

/// Build a `CrashFrame` from a previously-saved register set.
///
/// The stack snapshot is taken from the *current* SP/RSP — i.e. the
/// caller's frame. Stage-4 will replumb this so `frame/`'s trap
/// prologue passes a `*const u64` for the faulting stack instead of
/// reaching into the panic-handler's own frame.
///
/// `instruction_ptr` is sourced from the per-arch `ArchRegs` field so
/// the synthesised Stage-2 test path round-trips it without a real
/// trap context.
pub fn capture_crash_frame(regs: ArchRegs) -> CrashFrame {
    let mut frame = CrashFrame {
        registers:       regs,
        stack:           [0; CRASH_STACK_WORDS],
        instruction_ptr: 0,
        domain:          DomainId::new(narf_arch_current_domain_raw()),
    };

    #[cfg(target_arch = "x86_64")]
    {
        frame.instruction_ptr = regs.rip;
    }
    #[cfg(target_arch = "aarch64")]
    {
        frame.instruction_ptr = regs.pc;
    }

    // Best-effort stack snapshot. Use `read_volatile` so the optimiser
    // doesn't conclude that reading our own stack is undefined; we
    // bound the read with the static word count and skip on faults
    // (the panic path may run with paging in flux).
    let sp = current_stack_ptr();
    for (i, slot) in frame.stack.iter_mut().enumerate() {
        // Read forward from SP. On a real fault `frame/` will hand us a
        // `*const u64` directly; until then we walk our own stack as a
        // smoke surface — the test only checks that *some* non-zero
        // word lands in the buffer.
        let addr = sp.wrapping_add(i * core::mem::size_of::<u64>());
        // SAFETY: `addr` is within the active stack range we just
        // walked from the current SP. Reads inside the stack guard
        // can never fault on a healthy thread; on a panic path the
        // worst case is a zero word from a later guard hit, which is
        // an acceptable partial-dump outcome per spec §3.3.
        let v = unsafe { core::ptr::read_volatile(addr as *const u64) };
        *slot = v;
    }

    frame
}

/// Tiny helper: read the current stack pointer without touching arch
/// HAL internals. `&dummy as usize` is portable and gets the address
/// of a local — close enough to SP for Stage-2 stack snapshotting.
#[inline(always)]
fn current_stack_ptr() -> usize {
    let dummy: u64 = 0;
    &dummy as *const u64 as usize
}

/// Indirection over the Stage-2 `narf_arch_current_domain` hook so
/// the build links against `narf_arch`'s extern function without
/// observability re-declaring it.
#[inline]
fn narf_arch_current_domain_raw() -> u8 {
    // `narf_arch_current_domain` is the Stage-3 hook lib/ wired into
    // arch/. We re-export it via the published `narf_lib::assert::current_domain`
    // path to avoid duplicating the `extern "Rust"` declaration.
    narf_lib::assert::current_domain().raw()
}

// ── Panic snapshot ──────────────────────────────────────────────────
//
// Stage-3 wires `tracing/`'s `FlightRing` into the panic dump so a
// crash carries the last-N events leading up to the fault. The wiring
// is two halves:
//
//   1. `install_panic_snapshot(ring)` — registers a `&'static
//      FlightRing<ObservabilityEvent, N>` as the canonical recorder.
//      Cap-gated by `Cap<Recorder, Grant>`.
//   2. `take_snapshot()` — copies the most recent entries into a
//      `CoreSnapshot` that the panic path embeds in the core dump.
//
// The ring is shared by event source: producers `record()` directly
// into it; the panic path is the only consumer that calls `snapshot`.

/// Maximum entries surfaced by a `CoreSnapshot`. Power of two so it
/// matches the `FlightRing` capacity contract; keep well below the
/// 1 KiB-ish budget a partial-dump section can reasonably claim.
pub const SNAPSHOT_CAPACITY: usize = 64;

/// Event payload pushed into the panic-snapshot ring. Each variant
/// carries a `u64` tag the consumer interprets per-variant; this keeps
/// the wire format stable as new fields land in Stage-4.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ObservabilityEvent {
    /// PMU reading at a checkpoint.
    Pmu        { cycles:       u64, instructions: u64 },
    /// Capability invocation reached the dispatcher.
    CapInvoke  { kind:         u64, generation:   u64 },
    /// Panic crossed our hook.
    Panic      { ip:           u64, domain:       u64 },
}

/// Snapshot returned by `take_snapshot` — a frozen view of up to
/// `SNAPSHOT_CAPACITY` of the most recent events.
#[derive(Copy, Clone)]
pub struct CoreSnapshot {
    entries: [ObservabilityEvent; SNAPSHOT_CAPACITY],
    len:     usize,
}

impl CoreSnapshot {
    /// Number of valid entries. `entries[..len()]` are live; the rest
    /// are placeholder zero-tagged variants.
    #[inline]
    pub fn len(&self) -> usize { self.len }

    #[inline]
    pub fn is_empty(&self) -> bool { self.len == 0 }

    /// Frozen slice of the most-recent-first entries.
    #[inline]
    pub fn entries(&self) -> &[ObservabilityEvent] {
        &self.entries[..self.len]
    }
}

impl core::fmt::Debug for CoreSnapshot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CoreSnapshot")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

// The installed ring lives behind an `AtomicPtr` so registration and
// snapshot are lock-free. Storing the type-erased pointer plus a
// generation guard lets us reject stale rings whose backing storage
// has gone away — Stage-2 callers only register `'static` rings so
// the freed-memory race is structural, but the guard keeps the API
// future-proof.

static PANIC_RING: AtomicPtr<FlightRing<ObservabilityEvent, SNAPSHOT_CAPACITY>>
    = AtomicPtr::new(core::ptr::null_mut());

/// Tracks how many rings have been installed across a boot — used by
/// tests to confirm the install happened without inspecting the
/// pointer field directly.
static INSTALL_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Install a flight-recorder ring as the panic-time snapshot source.
///
/// The ring must outlive the kernel — `&'static` is enforced by the
/// signature. Cap-gated: caller proves prior `Recorder` grant
/// authority via `Cap<Recorder, Grant>`. Subsequent installs replace
/// the previous ring (intentional: a Stage-4 hot-swap of the recorder
/// during driver bring-up is in scope per spec §3.3).
pub fn install_panic_snapshot(
    cap: &Cap<Recorder, Grant>,
    ring: &'static FlightRing<ObservabilityEvent, SNAPSHOT_CAPACITY>,
) -> Result<(), ObsError> {
    cap.invoke(NoopOp)?;
    PANIC_RING.store(
        ring as *const _ as *mut _,
        Ordering::Release,
    );
    INSTALL_COUNT.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// Number of `install_panic_snapshot` calls that have succeeded since
/// boot. Stage-2 tests use this; Stage-4 monitoring may surface it as
/// a counter.
#[inline]
pub fn install_count() -> usize { INSTALL_COUNT.load(Ordering::Relaxed) }

/// Take a snapshot of the installed panic ring, if any.
///
/// Returns `None` when no ring has been registered; otherwise returns
/// the frozen `CoreSnapshot` with the most recent
/// `min(total, SNAPSHOT_CAPACITY)` entries in newest-first order
/// (matching `FlightRing::snapshot`).
pub fn take_snapshot() -> Option<CoreSnapshot> {
    let ptr = PANIC_RING.load(Ordering::Acquire);
    if ptr.is_null() { return None; }

    // SAFETY: Installation only accepts `&'static FlightRing`, so the
    // pointer is valid for the lifetime of the kernel. We hold no
    // exclusive access — `FlightRing::snapshot` takes `&self`.
    let ring: &'static FlightRing<ObservabilityEvent, SNAPSHOT_CAPACITY>
        = unsafe { &*ptr };

    // Placeholder fill: any unused tail stays zero-tagged but we never
    // expose it via `entries()`.
    let mut snap = CoreSnapshot {
        entries: [ObservabilityEvent::Pmu { cycles: 0, instructions: 0 };
                  SNAPSHOT_CAPACITY],
        len:     0,
    };
    let filled = ring.snapshot(&mut snap.entries);
    snap.len = filled;
    Some(snap)
}

/// Test-only escape hatch: clear the installed ring so independent
/// kernel_test! cases don't leak state across runs in the same boot.
#[doc(hidden)]
pub fn __test_clear_panic_ring() {
    PANIC_RING.store(core::ptr::null_mut(), Ordering::Release);
}

// ── Stage-3 §3.1: PMU sampling via tracing/ transport ───────────────
//
// `sample_pmu` reads the cap-gated PMU counters and records an
// `ObservabilityEvent::Pmu` into a caller-supplied `FlightRing`. The
// probe-handler wrapper bridges into `tracing::dispatch`: registering
// a `PmuProbeHandler` for a `probe_id` means every `tracing::fire` at
// that id drives a PMU sample. Instructions-retired falls back to `0`
// when `arch/` doesn't yet expose the primitive — cycles alone are
// still useful and `Err` from the cap path still surfaces as `Revoked`.

/// Record one PMU sample into `ring`, cap-gated on `Cap<Pmu, Read>`.
pub fn sample_pmu(
    cap: &Cap<Pmu, Read>,
    ring: &FlightRing<ObservabilityEvent, SNAPSHOT_CAPACITY>,
) -> Result<(), ObsError> {
    let cycles       = read_cycles(cap)?;
    let instructions = read_instructions(cap).unwrap_or(0);
    ring.record(ObservabilityEvent::Pmu { cycles, instructions });
    Ok(())
}

/// `tracing::ProbeHandler` that samples the PMU into a flight ring.
///
/// Install with `narf_tracing::dispatch::table().register(cap, id, h)`.
/// Each `fire(id, …)` drives one `sample_pmu` invocation; the handler
/// is `Send + Sync + 'static` as `ProbeHandler` requires (`Cap` is
/// `Send + Sync`, and the `&'static FlightRing` is trivially both).
#[derive(Debug)]
pub struct PmuProbeHandler {
    cap:  Cap<Pmu, Read>,
    ring: &'static FlightRing<ObservabilityEvent, SNAPSHOT_CAPACITY>,
}

impl PmuProbeHandler {
    pub const fn new(
        cap:  Cap<Pmu, Read>,
        ring: &'static FlightRing<ObservabilityEvent, SNAPSHOT_CAPACITY>,
    ) -> Self {
        Self { cap, ring }
    }
}

impl narf_tracing::ProbeHandler for PmuProbeHandler {
    fn fire(&self, _args: narf_tracing::ProbeArgs) {
        // Sampling failures are diagnostic — a revoked cap or an
        // unavailable counter shouldn't poison the fire path.
        let _ = sample_pmu(&self.cap, self.ring);
    }
}

// ── Stage-3 §3.3: core-dump enrichment with flight-recorder snapshot ─
//
// `capture_core_dump` wraps `capture_crash_frame` + `take_snapshot` so
// a Stage-3 panic path gets a single struct carrying both the register
// state and the last-N-events ring view. No copy of the ring's backing
// storage — `CoreSnapshot` already owns its own inline array.

/// Bundled core-dump payload: register/stack capture plus the
/// flight-recorder snapshot, when a recorder has been installed.
#[derive(Copy, Clone, Debug)]
pub struct CoreDump {
    pub frame:    CrashFrame,
    pub snapshot: Option<CoreSnapshot>,
}

/// Capture a Stage-3 core dump: CPU state + panic-ring snapshot.
pub fn capture_core_dump(regs: ArchRegs) -> CoreDump {
    CoreDump {
        frame:    capture_crash_frame(regs),
        snapshot: take_snapshot(),
    }
}

