//! Per-CPU storage primitive.
//!
//! Today's BSP-only NARF kernel takes shortcuts on per-CPU state:
//! every driver reaches for an `IrqSafeSpinLock<...>` and accepts
//! the contention that comes with it. That works for one core,
//! breaks the moment SMP userspace lands and N CPUs are funneling
//! through the same global lock. Drivers that route per-CPU
//! state — completion queues, soft-IRQ work, scratch buffers —
//! need a typed primitive that scales without touching every
//! call site once SMP arrives.
//!
//! Surface (intentionally minimal):
//!
//! ```ignore
//! use narf_arch::percpu::ThisCpu;
//! use core::sync::atomic::{AtomicU64, Ordering};
//!
//! narf_arch::per_cpu! {
//!     static COUNTER: AtomicU64 = AtomicU64::new(0);
//! }
//!
//! COUNTER.this_cpu().fetch_add(1, Ordering::Relaxed);
//! let mine = COUNTER.this_cpu().load(Ordering::Relaxed);
//! ```
//!
//! Storage is `[T; MAX_CPUS]` with each element living on its own
//! cache line is *not* enforced by the macro yet; the contention
//! that matters today is "who's even on the slot," and on x86_64
//! the prefetcher pulls neighbouring slots into the same line
//! anyway. False-sharing-aware layout (one cache line per slot,
//! padding fields) lands when SMP measurements show it's worth it.
//!
//! `current_cpu_id` returns `0` today (BSP-only); when SMP bring-up
//! is real, this routes through the existing GS.base / TPIDR_EL1
//! per-CPU area to read the real CPU id. **All callers must use
//! this accessor**, not assume "always BSP" — the surface is
//! forwards-compatible.

/// Maximum number of CPUs the kernel supports. 64 is enough for
/// every interesting development host + the small / medium
/// production targets we care about. Lifting this is mechanical:
/// it widens the per-CPU storage arrays linearly.
pub const MAX_CPUS: usize = 64;

/// Identifier of the currently-running CPU, in the closed range
/// `0..MAX_CPUS`. Today's BSP-only kernel always returns `0`; SMP
/// bring-up wires this through the per-arch per-CPU pointer.
#[inline]
pub fn current_cpu_id() -> u8 {
    // BSP-only invariant: only one CPU is running. SMP rewires
    // this to read from gs:cpu_id_offset (x86_64) or TPIDR_EL1
    // (aarch64); the offset/register identity lives in
    // `frame::x86_64::percpu::PerCpu` / its aarch64 counterpart.
    0
}

/// Convenience trait: `array.this_cpu()` returns `&array[current_cpu_id()]`.
/// Implemented for any `[T; N]` so callers can write
/// `MY_PER_CPU.this_cpu().fetch_add(...)` without a manual index.
pub trait ThisCpu<T> {
    fn this_cpu(&self) -> &T;
}

impl<T, const N: usize> ThisCpu<T> for [T; N] {
    #[inline]
    fn this_cpu(&self) -> &T {
        // The array is sized to MAX_CPUS by the macro; current_cpu_id
        // is bounded by MAX_CPUS by contract. This indexing never
        // panics in correct kernels — the bounds check is one extra
        // cmp/branch per access, which the prefetcher handles.
        &self[current_cpu_id() as usize % N]
    }
}

/// Declare a per-CPU static. Expands to `static $NAME: [TY; MAX_CPUS]`
/// initialised by repeating `$init` (using `[const { ... }; MAX_CPUS]`
/// so non-Copy types like `AtomicU64` are accepted).
///
/// ```ignore
/// per_cpu! {
///     static COUNTER: AtomicU64 = AtomicU64::new(0);
/// }
/// ```
#[macro_export]
macro_rules! per_cpu {
    ($(#[$attr:meta])* $vis:vis static $name:ident : $ty:ty = $init:expr;) => {
        $(#[$attr])*
        $vis static $name: [$ty; $crate::percpu::MAX_CPUS] =
            [const { $init }; $crate::percpu::MAX_CPUS];
    };
}
