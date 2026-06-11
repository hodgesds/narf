//! narf-tracing — static USDT-style probe markers + flight-recorder rings.
//!
//! Spec: `tracing/specification/spec.md` §3.1 (static markers) and
//! §3.3 (flight-recorder rings). Stage-1/Stage-2 scope per the
//! Stage-3 side-track C brief: compile-time probe sites with a
//! `.note.narf.probes` ELF-note-section entry per site, zero runtime
//! cost when unarmed (a single `nop`), and a basic fixed-size power-
//! of-two drop-oldest ring for Stage-2 flight-recorder use.
//!
//! Round-4 added runtime probe arming (`arm` / `disarm` against
//! `arch::patch_word`, cap-gated on `Cap<ProbeArming, Grant>`).
//! Round-5 (this iteration) lands the dynamic-probe dispatch surface
//! plus `FnTime` function-level timing aggregates — the §3.2 scope.
//!
//! Submodules:
//! - `dispatch`: cap-gated handler registry + `fire(probe_id, args)`
//!   that armed probe sites call. Up to 256 handlers, linear-scan
//!   lookup under an IRQ-safe lock (Stage 4 swaps to a hazard-
//!   pointer-backed per-slot table).
//! - `fntime`: `FnTime` scope accumulator with Welford online mean +
//!   variance + a log2-bucket histogram for approximate percentiles.
//! - `sketch`: the log2-bucket `Histogram` primitive `FnTime` uses.
//!   Kept alongside the t-Digest as a lock-free, atomic-only fast
//!   path; consumer migration to t-Digest is tracked separately.
//! - `tdigest`: clean-room implementation of Dunning & Ertl's
//!   t-Digest quantile sketch (arXiv:1902.04023) — ≈ 1% tail-quantile
//!   accuracy with bounded memory, satisfying the §3.2 accuracy ask.
//!
//! Non-goals in this crate (later stages):
//! - Tracer task / streaming rings (spec §3.4 — tracer domain).
//! - `frame/` panic-path snapshot hook (the ring is callable; the
//!   panic path wiring is deferred to the frame/ owner).
//! - Per-CPU-sharded handler dispatch (Stage 4 hazard-pointer path).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

mod tests;

pub mod dispatch;
pub mod fntime;
pub mod hwtrace;
pub mod sketch;
pub mod tdigest;

pub use hwtrace::{HwTraceConfig, HwTraceError, HwTraceMarker, HwTraceStatus};

pub use dispatch::{
    fire, reserve_probe_id, table as handler_table, HandlerTable, ProbeArgs, ProbeHandler,
    ProbeHandlerInstall, RegisterError,
};
pub use fntime::{scope, FnTime, ScopeGuard, Welford};
pub use sketch::{Histogram, HISTOGRAM_BUCKETS};
pub use tdigest::TDigest;

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};

use alloc::boxed::Box;

// ── Probe-site metadata ─────────────────────────────────────────────
//
// Every `probe!` call lays down one static `ProbeSite` in the
// dedicated `.note.narf.probes` section. The linker gathers them
// between `__narf_probes_start` and `__narf_probes_end`; `probes()`
// reconstitutes that as a slice.
//
// We deliberately use a plain `#[repr(C)]` struct rather than a real
// ELF GNU-note header. Stage-2 tooling consumes the section via the
// runtime accessor, not via `readelf -n`; the section name still
// matches the spec (§3.1) so a Stage-3+ tracer can recognise it. If a
// GNU-note layout becomes a hard requirement (e.g. bpftrace parity)
// the marker macro can grow a NT_STAPSDT-shaped header without
// changing the user-facing API.

/// Static description of one compile-time probe site.
///
/// One of these is emitted per `probe!()` call. The struct is
/// `#[repr(C)]` so its layout matches the `.note.narf.probes`
/// slice the linker assembles.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ProbeSite {
    /// Provider namespace — `"ipc"`, `"mem"`, `"sched"`, ... (null-
    /// terminator NOT required; `provider_len` is the authoritative bound).
    pub provider: &'static str,
    /// Probe name inside the provider — `"send"`, `"alloc"`, etc.
    pub name: &'static str,
    /// Source module path at the probe site. `module_path!()` at expansion.
    pub module: &'static str,
    /// Source file + line for diagnostics.
    pub file: &'static str,
    pub line: u32,
    /// Number of arguments passed to the `probe!` invocation.
    pub argc: u32,
    /// Comma-separated argument Rust-type names (`"u32,u16,&str"` etc.).
    /// Stage-3 arming uses this to validate handler signatures.
    pub args: &'static str,
}

impl core::fmt::Debug for ProbeSite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProbeSite")
            .field("provider", &self.provider)
            .field("name", &self.name)
            .field("module", &self.module)
            .field("line", &self.line)
            .field("argc", &self.argc)
            .finish_non_exhaustive()
    }
}

extern "Rust" {
    static __narf_probes_start: ProbeSite;
    static __narf_probes_end: ProbeSite;
}

/// Return every `probe!`-registered site the linker collected.
///
/// The slice is sorted by link order, not by provider/name — consumers
/// that need a stable order must sort themselves.
pub fn probes() -> &'static [ProbeSite] {
    // SAFETY: `__narf_probes_start` / `__narf_probes_end` are emitted
    // by the linker script as the boundaries of the
    // `.note.narf.probes` output section. Every entry in that section
    // is a `ProbeSite` (the `probe!` macro is the only writer).
    let start = unsafe { &__narf_probes_start as *const ProbeSite };
    // SAFETY: see the previous block — same linker-emitted symbol.
    let end = unsafe { &__narf_probes_end as *const ProbeSite };
    let bytes = (end as usize).saturating_sub(start as usize);
    let len = bytes / core::mem::size_of::<ProbeSite>();
    // SAFETY: start/len derived from the linker-defined boundaries of
    // a contiguous region of `ProbeSite` entries.
    unsafe { core::slice::from_raw_parts(start, len) }
}

// ── probe! macro ────────────────────────────────────────────────────
//
// Expands to:
//   1. A `nop` at the call site via inline asm on supported arches
//      (x86_64 / aarch64). Unsupported arches silently degrade to a
//      no-op Rust expression so host tests can still link. The asm
//      block carries `nostack, preserves_flags, nomem` so the optimiser
//      treats it as free; when unarmed the cost is 1 instruction fetch.
//   2. A `ProbeSite` static in `.note.narf.probes`, `#[used]` so
//      LTO doesn't drop it.

/// Place a compile-time USDT-style probe site.
///
/// ```ignore
/// use narf_tracing::probe;
/// probe!(ipc, send, "u32,u16,u32");
/// ```
///
/// Emits a `nop` (on supported arches) plus a `ProbeSite` entry in
/// `.note.narf.probes`. Unarmed cost: one instruction fetch.
///
/// Form: `probe!(provider, name)` or `probe!(provider, name, "argtypes")`.
/// The third form takes a `&'static str` describing the argument
/// types; Stage-3 arming uses it to validate handlers.
#[macro_export]
macro_rules! probe {
    ($provider:ident, $name:ident) => {
        $crate::probe!($provider, $name, "");
    };
    ($provider:ident, $name:ident, $args:expr) => {{
        // 1. The `nop` marker. We don't keep the address in Rust —
        //    Stage-3 arming will scan the site metadata to find it
        //    (a real STAPSDT-style header carries the VA; when we
        //    grow to that we'll read the relocation target here).
        //    Feature-gate arch-specific blocks so host / build-script
        //    targets don't fail to compile.
        $crate::__nop_marker();

        // 2. The ELF-note-section record. `#[used]` + a `const _` scope
        //    keeps multiple calls in the same module from colliding on
        //    the static's name (same pattern as verification/
        //    `kernel_test!`). The link_section name matches the spec
        //    verbatim — see `tracing/specification/spec.md` §3.1.
        const _: () = {
            #[used]
            #[link_section = ".note.narf.probes"]
            static SITE: $crate::ProbeSite = $crate::ProbeSite {
                provider: stringify!($provider),
                name: stringify!($name),
                module: module_path!(),
                file: file!(),
                line: line!(),
                argc: $crate::__count_args($args),
                args: $args,
            };
        };
    }};
}

/// Helper: emit the single `nop` instruction at the call site.
///
/// Factored out so the macro expansion stays small; `#[inline(always)]`
/// makes the call site equivalent to inlining the asm block directly.
#[inline(always)]
pub fn __nop_marker() {
    // SAFETY: `nop` has no side effects, reads no memory, clobbers no
    // registers; `nostack, preserves_flags, nomem` encode that to the
    // compiler. On unsupported arches we degrade to an empty block —
    // the probe-site metadata still lands in `.note.narf.probes`, only
    // the runtime-armable marker itself is absent.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("nop", options(nostack, preserves_flags, nomem));
    }
    // SAFETY: emits a single aarch64 `nop` (encodes to `0xD503201F`),
    // which has no side effects, reads/writes no memory and clobbers no
    // registers or flags; `nostack, preserves_flags, nomem` encode those
    // guarantees to the compiler.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        // `nop` on aarch64 encodes to `0xD503201F`; the assembler
        // mnemonic is portable, so we stick with it.
        core::arch::asm!("nop", options(nostack, preserves_flags, nomem));
    }
    // Other arches: no marker instruction. The probe-site record is
    // still emitted so offline tooling can observe the site.
}

/// Helper: count commas in the args-type string to derive `argc`
/// at const-time. Empty string → 0; otherwise commas + 1.
pub const fn __count_args(s: &'static str) -> u32 {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return 0;
    }
    let mut commas: u32 = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b',' {
            commas += 1;
        }
        i += 1;
    }
    commas + 1
}

// ── Flight-recorder ring ────────────────────────────────────────────
//
// Stage-2 scope per the side-track brief: fixed-size, power-of-two
// slots, drop-oldest semantics. Producer-side is wait-free; the
// overrun counter surfaces how much history the consumer missed.
//
// Not the final design — the §3.3 target (20-cycle armed record)
// demands a per-CPU layout with a seq-locked slot and a real
// SnapshotSink. Stage-2 basic shape gets the ergonomics right;
// Stage-3+ tightens the hot path.

/// Event trait: payloads must be POD so `record` is a single memcpy.
pub trait Event: Copy + 'static {}

// Blanket impl — any `Copy + 'static` type qualifies.
impl<T: Copy + 'static> Event for T {}

/// Fixed-size drop-oldest ring.
///
/// `N` must be a power of two; non-power-of-two `N` triggers a compile
/// error via the const assertion in `FlightRing::new`. The ring is
/// `Sync` so multiple producers may share it; on contention they race
/// on the head counter and every `record` call is wait-free at the
/// producer side (single `fetch_add`).
///
/// Drop-oldest: when the ring is full, the next `record` overwrites
/// slot `head % N` and bumps the `overrun` counter so consumers know
/// the history is lossy.
pub struct FlightRing<T: Event, const N: usize> {
    /// Monotonic producer counter. `head % N` is the next write slot.
    head: AtomicU64,
    /// Number of records that overwrote live history.
    overrun: AtomicU64,
    /// Per-slot sequence. Producers bump `seq` to an odd value before
    /// the write, then to the next even value after. Consumers can
    /// detect torn reads by observing an odd `seq`.
    seq: [AtomicU64; N],
    /// Slot storage. `MaybeUninit` + `UnsafeCell` so (a) we don't
    /// need `T: Default` / a runtime `init` value to const-construct
    /// the array, and (b) writes don't require `&mut` (we only hand
    /// out `&FlightRing`). Consumers gate reads on `seq != 0`, so
    /// uninitialised slots are never observed as payload.
    slots: [UnsafeCell<MaybeUninit<T>>; N],
}

impl<T: Event, const N: usize> core::fmt::Debug for FlightRing<T, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FlightRing")
            .field("capacity", &N)
            .field("head", &self.head.load(Ordering::Relaxed))
            .field("overrun", &self.overrun.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

// SAFETY: `record` uses atomics on `head` and per-slot `seq` to
// serialise writes to each slot. Consumers re-read `seq` around the
// payload load to detect tears. `T: Copy` means the cell holds no
// owning references.
unsafe impl<T: Event, const N: usize> Sync for FlightRing<T, N> {}

impl<T: Event, const N: usize> FlightRing<T, N> {
    /// Construct an empty ring.
    ///
    /// Const-asserts `N` is a non-zero power of two. A non-power-of-
    /// two capacity would force a `%` in the hot path; the point of
    /// drop-oldest is a single masked index.
    pub const fn new() -> Self {
        // Const-assert: N must be a non-zero power of two.
        // `N & (N - 1) == 0` and `N > 0`.
        assert!(
            N > 0 && (N & (N - 1)) == 0,
            "FlightRing capacity must be a non-zero power of two"
        );
        Self {
            head: AtomicU64::new(0),
            overrun: AtomicU64::new(0),
            // `const { … }` repeat-expressions side-step the
            // `T: Copy` requirement of plain `[expr; N]` — each cell
            // is separately const-evaluated. `AtomicU64::new` /
            // `UnsafeCell::new` / `MaybeUninit::uninit` are all const.
            seq: [const { AtomicU64::new(0) }; N],
            slots: [const { UnsafeCell::new(MaybeUninit::<T>::uninit()) }; N],
        }
    }

    /// Record `ev` into the ring, overwriting the oldest slot if full.
    ///
    /// Wait-free at the producer. When two producers race on the
    /// same slot (possible only if `fetch_add` wraps past N faster
    /// than a producer completes its write) the `seq`-protected
    /// snapshot is torn and consumers reject it — the overrun
    /// counter already reflects that the slot was overwritten.
    pub fn record(&self, ev: T) {
        let ticket = self.head.fetch_add(1, Ordering::Relaxed);
        let idx = (ticket as usize) & (N - 1);

        // Overrun accounting: every wrap past `N` bumps the counter.
        if ticket >= N as u64 {
            self.overrun.fetch_add(1, Ordering::Relaxed);
        }

        // Publish protocol: bump seq to odd, write, bump to even.
        let prev = self.seq[idx].load(Ordering::Relaxed);
        let odd = prev.wrapping_add(1) | 1;
        let even = odd.wrapping_add(1) & !1;

        self.seq[idx].store(odd, Ordering::Release);
        // SAFETY: per-slot `seq` going odd signals exclusive write
        // ownership to concurrent consumers; `T: Copy` means a byte-
        // wise write is well-defined. Concurrent producers on the
        // same slot will tear the seq but consumers reject torn reads.
        unsafe {
            // Write the full `MaybeUninit<T>` — since `T: Copy` this
            // is equivalent to a plain `T` store and leaves any prior
            // contents replaced rather than dropped (there's no Drop
            // to run on `Copy` types).
            core::ptr::write_volatile(self.slots[idx].get(), MaybeUninit::new(ev));
        }
        self.seq[idx].store(even, Ordering::Release);
    }
}

impl<T: Event, const N: usize> Default for FlightRing<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Event, const N: usize> FlightRing<T, N> {
    /// Current overrun count. Non-decreasing.
    pub fn overruns(&self) -> u64 {
        self.overrun.load(Ordering::Relaxed)
    }

    /// Total records written (monotonic; saturates at u64::MAX).
    pub fn total(&self) -> u64 {
        self.head.load(Ordering::Relaxed)
    }

    /// Snapshot the most recent `min(total, N)` entries into `out`.
    ///
    /// Returns the number of entries filled. A torn slot (seq observed
    /// as odd, or seq changed between pre-/post-reads) is skipped.
    /// Stage-3+ will grow a freeze-or-double-buffer protocol; this
    /// is the minimum useful consumer.
    pub fn snapshot(&self, out: &mut [T]) -> usize {
        let total = self.head.load(Ordering::Acquire);
        let available = core::cmp::min(total as usize, N);
        let want = core::cmp::min(out.len(), available);
        let mut filled = 0usize;

        // Walk newest-first: slot (head - 1 - i) for i in 0..want.
        for i in 0..want {
            let ticket = total.wrapping_sub(1).wrapping_sub(i as u64);
            let idx = (ticket as usize) & (N - 1);

            let s1 = self.seq[idx].load(Ordering::Acquire);
            if s1 == 0 || s1 & 1 != 0 {
                continue;
            } // uninitialised or torn
              // SAFETY: when `s1` is even and non-zero, the slot was
              // fully written at least once and no producer is mid-write
              // on it right now. The volatile read prevents the optimiser
              // from hoisting it out of the seq fence pair. `assume_init`
              // is valid because seq != 0 means a complete record landed.
            let val = unsafe { core::ptr::read_volatile(self.slots[idx].get()).assume_init() };
            let s2 = self.seq[idx].load(Ordering::Acquire);
            if s1 != s2 {
                continue;
            } // raced with a producer

            out[filled] = val;
            filled += 1;
        }
        filled
    }
}

// ── Armed / disarmed (Stage 3) ──────────────────────────────────────
//
// Arming flips a 4-byte patch slot adjacent to a probe's NOP sled
// using `arch::patch_word`, which takes care of the self-modifying-
// code synchronisation. The Stage-3 slot is a 32-bit marker that
// consumers load to decide whether the probe is enabled; a real
// Stage-4 handler-dispatch path would replace the slot with a branch
// to a trampoline. Cap-gated on `Cap<Probe, Grant>`.

use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant};

static GLOBAL_ARMED: AtomicUsize = AtomicUsize::new(0);

/// Are any probes currently armed?
#[inline]
pub fn any_armed() -> bool {
    GLOBAL_ARMED.load(Ordering::Relaxed) != 0
}

/// Cap-type marker for probe arming authority.
#[derive(Debug)]
pub struct ProbeArming;
impl CapType for ProbeArming {
    const KIND: CapKind = CapKind::Probe;
}

/// Arm the 4-byte patch slot at `target` with `word`, bumping the
/// global armed count. The slot must be 4-byte aligned and live in
/// writable+executable memory — see `arch::patch_word` for the full
/// safety contract.
///
/// # Safety
/// Caller must uphold `arch::patch_word`'s preconditions on `target`.
pub unsafe fn arm(
    cap: &Cap<ProbeArming, Grant>,
    target: *mut u32,
    word: u32,
) -> Result<(), CapError> {
    cap.check_live()?;
    // SAFETY: delegated to arch::patch_word per the caller's contract.
    unsafe {
        narf_arch::patch_word(target, word);
    }
    GLOBAL_ARMED.fetch_add(1, Ordering::Release);
    Ok(())
}

/// Disarm: patch `target` back to the caller-supplied `original` word
/// and decrement the global armed count.
///
/// # Safety
/// Same as `arm`.
pub unsafe fn disarm(
    cap: &Cap<ProbeArming, Grant>,
    target: *mut u32,
    original: u32,
) -> Result<(), CapError> {
    cap.check_live()?;
    // SAFETY: delegated to arch::patch_word.
    unsafe {
        narf_arch::patch_word(target, original);
    }
    GLOBAL_ARMED.fetch_sub(1, Ordering::Release);
    Ok(())
}

/// Test-only bump / clear kept for back-compat with Stage-2 users.
#[doc(hidden)]
pub fn __test_bump_armed() {
    GLOBAL_ARMED.fetch_add(1, Ordering::Relaxed);
}
#[doc(hidden)]
pub fn __test_clear_armed() {
    GLOBAL_ARMED.store(0, Ordering::Relaxed);
}

// ── Internal smoke probes ───────────────────────────────────────────
//
// Emit at least one probe from inside this crate so binaries that link
// `narf-tracing` but not any consumer still exercise `.note.narf.probes`
// population. `verification/` asserts probes() is non-empty.

#[inline(always)]
fn emit_internal_probes() {
    probe!(tracing, loaded);
    probe!(tracing, heartbeat, "u64");
}

/// Invoke the crate's internal probes so their `nop` sites execute.
///
/// Tests call this to prove the probe site emits the expected
/// instruction. `#[inline(never)]` keeps the site identifiable in
/// disassembly (Stage-3 arming will find it by module + line).
#[inline(never)]
pub fn exercise_internal_probes() {
    emit_internal_probes();
}

// ── Pluggable event sink (Wave J) ──────────────────────────────────
//
// `EventSink` is the install-once, runtime-swappable destination for
// `emit_event(type_id, &bytes)` calls. The trait is intentionally
// narrow (`record_raw`, `flush`, `name`) so the hot path is a single
// indirect call after the null-check fast-path.
//
// Pattern mirrors `power::install_governor` (`power/src/lib.rs:538`),
// with one critical exception: `probe!` and `emit_event` are on every
// IRQ entry / syscall / wakeup, so we can't afford an `IrqSafeSpinLock`
// in the load path. Instead, the slot is an `AtomicPtr` to a
// leaked `Box<Box<dyn EventSink>>` — fat-pointer trait objects don't
// fit in `AtomicPtr`, so we box-the-box and store the inner pointer.
// Install/uninstall swaps the pointer (Acquire/Release) and drops the
// displaced box. Hot-path loads use Relaxed; losing one event on a
// race is benign and an Acquire/Release pair on install ensures the
// box contents are visible whenever the pointer is.
//
// Default-noop fast path:
//   let p = SINK.load(Relaxed);
//   if p.is_null() { return; }
//   unsafe { (*p).record_raw(type_id, bytes); }
// On x86_64 that's `mov rax, [SINK]; test rax, rax; je .Lret` — ≈0.5 ns,
// branch-well-predicted as "no sink installed" outside of armed tracing.

/// Runtime-installable destination for emitted trace events.
///
/// Implementations must be cheap on the `record_raw` hot path; the
/// default `FlightRecorderSink` is a single masked-index ring write.
/// Heavyweight sinks (USB-serial, TCP) should buffer internally and
/// drain in `flush`.
pub trait EventSink: Send + Sync + 'static {
    /// Stable identifier — `"flight-recorder"`, `"serial"`, etc.
    /// Used by `current_event_sink_name()` and userspace tooling.
    fn name(&self) -> &'static str;
    /// Record a raw event. `type_id` is the consumer-defined event
    /// kind; `bytes` is the payload (any encoding the producer +
    /// consumer agree on). Must be wait-free; called from IRQ context.
    fn record_raw(&self, type_id: u64, bytes: &[u8]);
    /// Drain any internal buffering. No-op for unbuffered sinks.
    fn flush(&self);
}

/// Errors from `install_event_sink`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TracingError {
    /// The supplied cap was revoked before install.
    AuthorityRevoked,
}

impl From<CapError> for TracingError {
    fn from(_: CapError) -> Self {
        TracingError::AuthorityRevoked
    }
}

/// Cap-type marker for event-sink install authority.
#[derive(Debug)]
pub struct SinkMarker;
impl CapType for SinkMarker {
    const KIND: CapKind = CapKind::EventSink;
}

// Atomic slot for the active sink. Stores a raw pointer to a leaked
// `Box<dyn EventSink>` — i.e. the inner `Box` of a
// `Box<Box<dyn EventSink>>`. Null = no sink installed (fast-path
// return). `AtomicPtr<()>` because fat-pointer trait objects don't
// round-trip through `AtomicPtr<Box<dyn EventSink>>` cleanly; we
// reconstitute the `*mut Box<dyn EventSink>` at the use sites.
static SINK: AtomicPtr<()> = AtomicPtr::new(ptr::null_mut());

/// Default in-tree sink: writes raw bytes (truncated to 32 bytes) plus
/// `type_id` into a fixed-size `FlightRing`. Wraps the existing ring
/// machinery without duplicating it.
#[derive(Debug)]
pub struct FlightRecorderSink {
    ring: FlightRing<RawEvent, 256>,
}

/// One captured raw event for `FlightRecorderSink`. `Copy` so it
/// satisfies the `Event` blanket impl and lands in the ring as a
/// single memcpy. Payloads longer than 32 bytes are truncated; `len`
/// records the original length so consumers can flag truncation.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct RawEvent {
    pub type_id: u64,
    pub len: u32,
    pub bytes: [u8; 32],
}

impl FlightRecorderSink {
    /// Construct an empty recorder. `const` so it composes with
    /// `static` slots in tests / boot code.
    pub const fn new() -> Self {
        Self {
            ring: FlightRing::new(),
        }
    }
    /// Borrow the underlying ring (consumer-side snapshot access).
    pub fn ring(&self) -> &FlightRing<RawEvent, 256> {
        &self.ring
    }
}

impl Default for FlightRecorderSink {
    fn default() -> Self {
        Self::new()
    }
}

impl EventSink for FlightRecorderSink {
    fn name(&self) -> &'static str {
        "flight-recorder"
    }
    fn record_raw(&self, type_id: u64, bytes: &[u8]) {
        let mut ev = RawEvent {
            type_id,
            len: bytes.len() as u32,
            bytes: [0u8; 32],
        };
        let n = core::cmp::min(bytes.len(), ev.bytes.len());
        ev.bytes[..n].copy_from_slice(&bytes[..n]);
        self.ring.record(ev);
    }
    fn flush(&self) {
        // FlightRing is wait-free + in-memory; no buffering to drain.
    }
}

/// Live-debug sink that counts events. Spec calls for a hex dump to
/// the serial console, but `narf-tracing` deliberately does not depend
/// on a console crate (would invert layering). The counter is the
/// observable signal the smoke test asserts; downstream crates that
/// own the console can wrap this with a printing sink that delegates
/// here.
#[derive(Debug, Default)]
pub struct SerialSink {
    /// Total `record_raw` calls observed. Test hook + diagnostics.
    pub count: AtomicU64,
}

impl SerialSink {
    pub const fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
        }
    }
    /// Snapshot the event count seen so far.
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

impl EventSink for SerialSink {
    fn name(&self) -> &'static str {
        "serial"
    }
    fn record_raw(&self, _type_id: u64, _bytes: &[u8]) {
        // Stage-3 surface: count so smoke can observe receipt. A
        // console-printing variant lives downstream where the serial
        // sink is in scope.
        self.count.fetch_add(1, Ordering::Relaxed);
    }
    fn flush(&self) {
        // Unbuffered — the underlying writer (when wired) is itself
        // synchronous.
    }
}

/// Install `s` as the active event sink. Cap-gated on
/// `Cap<SinkMarker, Grant>`. The displaced sink (if any) is dropped.
///
/// Allocation: one `Box<Box<dyn EventSink>>` per install. Don't call
/// this from a hot path — install once at boot (or once per swap from
/// a control plane), never from an IRQ handler.
pub fn install_event_sink<S: EventSink>(
    cap: &Cap<SinkMarker, Grant>,
    s: S,
) -> Result<(), TracingError> {
    cap.check_live()?;
    // Box-the-box: fat-pointer dyn trait → thin pointer for AtomicPtr.
    let inner: Box<dyn EventSink> = Box::new(s);
    let outer: Box<Box<dyn EventSink>> = Box::new(inner);
    let raw: *mut Box<dyn EventSink> = Box::into_raw(outer);
    // Release on the swap so concurrent hot-path Acquire (or Relaxed,
    // since the box contents are reachable by data dependency through
    // the pointer) observes the fully-constructed sink.
    let prev = SINK.swap(raw as *mut (), Ordering::AcqRel);
    if !prev.is_null() {
        // SAFETY: every non-null SINK value was produced by a prior
        // `Box::into_raw` in this function and has not been freed since
        // (only the swap reaches it). Re-`from_raw` + drop reclaims.
        // The hot-path readers use Relaxed loads; an Acquire on the
        // swap above pairs with any future install's Release so this
        // store is visible before the reclaim.
        unsafe {
            drop(Box::from_raw(prev as *mut Box<dyn EventSink>));
        }
    }
    Ok(())
}

/// Snapshot the active sink's name, or `None` if no sink is installed.
pub fn current_event_sink_name() -> Option<&'static str> {
    let p = SINK.load(Ordering::Acquire) as *mut Box<dyn EventSink>;
    if p.is_null() {
        return None;
    }
    // SAFETY: SINK is only ever set by install_event_sink, which leaks
    // a `Box<Box<dyn EventSink>>`. The boxed contents live until a
    // subsequent install drops them; on the read side we never alias
    // through `&mut`, only `&`, so the &-borrow is sound.
    let sink: &dyn EventSink = unsafe { &**p };
    Some(sink.name())
}

/// Hot-path entry point: dispatch one event to the active sink.
///
/// Inlined null-check fast-path — when no sink is installed (the
/// common case outside of armed tracing) this lowers to
/// `mov rax, [SINK]; test rax, rax; je .Lret`. The Relaxed load is
/// safe because (a) the only thing we do with `p` after the null
/// check is dereference it, and the data dependency between the load
/// and the deref provides the consume-style ordering we need, and (b)
/// losing one event on a torn install is benign — the new sink is
/// already in place by the time the next call lands.
#[inline]
pub fn emit_event(type_id: u64, bytes: &[u8]) {
    let p = SINK.load(Ordering::Relaxed) as *mut Box<dyn EventSink>;
    if p.is_null() {
        return;
    }
    // SAFETY: see `install_event_sink` — every non-null SINK value
    // points at a live `Box<dyn EventSink>` until the next install
    // replaces it. We never form an `&mut` to that box, so concurrent
    // reads are sound; `record_raw` takes `&self`.
    unsafe {
        (*p).record_raw(type_id, bytes);
    }
}

/// Flush the active sink (if any). Cheap on `FlightRecorderSink`; a
/// real serial / network sink will drain its buffer.
pub fn flush_event_sink() {
    let p = SINK.load(Ordering::Acquire) as *mut Box<dyn EventSink>;
    if p.is_null() {
        return;
    }
    // SAFETY: see `emit_event`.
    unsafe {
        (*p).flush();
    }
}

/// One-shot tracing-subsystem init. Plants the default
/// `FlightRecorderSink` so behaviour is unchanged out of the box; a
/// downstream `install_event_sink` call may swap it later. Idempotent
/// — calling twice replaces the previous default with a fresh one
/// (the prior box is dropped).
pub fn init() {
    let cap: Cap<SinkMarker, Grant> = Cap::<SinkMarker, Grant>::bootstrap();
    // Default install can't meaningfully fail: bootstrap() returns a
    // live cap. If a downstream re-init races with itself, the second
    // call wins; that's the documented behaviour above.
    let _ = install_event_sink(&cap, FlightRecorderSink::new());
}
