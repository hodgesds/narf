//! narf-tracing — static USDT-style probe markers + flight-recorder rings.
//!
//! Spec: `tracing/specification/spec.md` §3.1 (static markers) and
//! §3.3 (flight-recorder rings). Stage-1/Stage-2 scope per the
//! Stage-3 side-track C brief: compile-time probe sites with a
//! `.note.narf.probes` ELF-note-section entry per site, zero runtime
//! cost when unarmed (a single `nop`), and a basic fixed-size power-
//! of-two drop-oldest ring for Stage-2 flight-recorder use.
//!
//! Non-goals in this crate (later stages / other tracks):
//! - Runtime arming of probe sites (needs `arch/` patch primitive
//!   + `capabilities/` install cap — Stage-3 main-track work).
//! - Dynamic probes, `FnTime`, aggregate sketches (spec §3.2+).
//! - Tracer task / streaming rings (spec §3.4 — Stage-2 tracer
//!   domain, side track not in scope here).
//! - `frame/` panic-path snapshot hook (the ring is callable; the
//!   panic path wiring is deferred to the frame/ owner).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

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
    pub provider:     &'static str,
    /// Probe name inside the provider — `"send"`, `"alloc"`, etc.
    pub name:         &'static str,
    /// Source module path at the probe site. `module_path!()` at expansion.
    pub module:       &'static str,
    /// Source file + line for diagnostics.
    pub file:         &'static str,
    pub line:         u32,
    /// Number of arguments passed to the `probe!` invocation.
    pub argc:         u32,
    /// Comma-separated argument Rust-type names (`"u32,u16,&str"` etc.).
    /// Stage-3 arming uses this to validate handler signatures.
    pub args:         &'static str,
}

impl core::fmt::Debug for ProbeSite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProbeSite")
            .field("provider", &self.provider)
            .field("name",     &self.name)
            .field("module",   &self.module)
            .field("line",     &self.line)
            .field("argc",     &self.argc)
            .finish_non_exhaustive()
    }
}

extern "Rust" {
    static __narf_probes_start: ProbeSite;
    static __narf_probes_end:   ProbeSite;
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
    let end   = unsafe { &__narf_probes_end   as *const ProbeSite };
    let bytes = (end as usize).saturating_sub(start as usize);
    let len   = bytes / core::mem::size_of::<ProbeSite>();
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
                name:     stringify!($name),
                module:   module_path!(),
                file:     file!(),
                line:     line!(),
                argc:     $crate::__count_args($args),
                args:     $args,
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
    if bytes.is_empty() { return 0; }
    let mut commas: u32 = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b',' { commas += 1; }
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
    head:     AtomicU64,
    /// Number of records that overwrote live history.
    overrun:  AtomicU64,
    /// Per-slot sequence. Producers bump `seq` to an odd value before
    /// the write, then to the next even value after. Consumers can
    /// detect torn reads by observing an odd `seq`.
    seq:      [AtomicU64; N],
    /// Slot storage. `MaybeUninit` + `UnsafeCell` so (a) we don't
    /// need `T: Default` / a runtime `init` value to const-construct
    /// the array, and (b) writes don't require `&mut` (we only hand
    /// out `&FlightRing`). Consumers gate reads on `seq != 0`, so
    /// uninitialised slots are never observed as payload.
    slots:    [UnsafeCell<MaybeUninit<T>>; N],
}

impl<T: Event, const N: usize> core::fmt::Debug for FlightRing<T, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FlightRing")
            .field("capacity", &N)
            .field("head",     &self.head.load(Ordering::Relaxed))
            .field("overrun",  &self.overrun.load(Ordering::Relaxed))
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
        assert!(N > 0 && (N & (N - 1)) == 0,
                "FlightRing capacity must be a non-zero power of two");
        Self {
            head:    AtomicU64::new(0),
            overrun: AtomicU64::new(0),
            // `const { … }` repeat-expressions side-step the
            // `T: Copy` requirement of plain `[expr; N]` — each cell
            // is separately const-evaluated. `AtomicU64::new` /
            // `UnsafeCell::new` / `MaybeUninit::uninit` are all const.
            seq:     [const { AtomicU64::new(0) }; N],
            slots:   [const { UnsafeCell::new(MaybeUninit::<T>::uninit()) }; N],
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
        let odd  = prev.wrapping_add(1) | 1;
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
    fn default() -> Self { Self::new() }
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
            if s1 == 0 || s1 & 1 != 0 { continue; } // uninitialised or torn
            // SAFETY: when `s1` is even and non-zero, the slot was
            // fully written at least once and no producer is mid-write
            // on it right now. The volatile read prevents the optimiser
            // from hoisting it out of the seq fence pair. `assume_init`
            // is valid because seq != 0 means a complete record landed.
            let val = unsafe {
                core::ptr::read_volatile(self.slots[idx].get()).assume_init()
            };
            let s2 = self.seq[idx].load(Ordering::Acquire);
            if s1 != s2 { continue; }    // raced with a producer

            out[filled] = val;
            filled += 1;
        }
        filled
    }
}

// ── Armed / disarmed helpers (scaffolding) ──────────────────────────
//
// Stage-2 scope is unarmed probe-site emission. Arming plumbing lives
// in Stage-3 main-track work (needs `arch/` patch + `capabilities/`).
// We still expose a single global armed flag so a Stage-3 consumer
// can cheaply gate handler execution while the crate is otherwise
// quiescent — today, always false.

static GLOBAL_ARMED: AtomicUsize = AtomicUsize::new(0);

/// Are any probes currently armed? Stage-2: always returns `false`
/// because no arming surface exists yet. Stage-3 arming bumps this.
pub fn any_armed() -> bool { GLOBAL_ARMED.load(Ordering::Relaxed) != 0 }

/// Arm / disarm scaffolding — exposed for tests only. Stage-3 replaces
/// this with a capability-gated patch path against `arch/`.
#[doc(hidden)]
pub fn __test_bump_armed()   { GLOBAL_ARMED.fetch_add(1, Ordering::Relaxed); }
#[doc(hidden)]
pub fn __test_clear_armed()  { GLOBAL_ARMED.store(0, Ordering::Relaxed); }

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
