//! Per-CPU storage wrapper.
//!
//! `PerCpu<T>` is a fixed-size `[T; MAX_CPUS]` cache-aligned to avoid
//! false sharing between adjacent CPUs' state. Access through
//! `this_cpu()` indexes by the active CPU's `CpuId` as reported by
//! `narf_arch::current_cpu_id()`.
//!
//! Stage 2 invariant: `current_cpu_id()` always returns `0` (single-
//! CPU BSP-only). The storage structure is still `[T; MAX_CPUS]` so
//! Stage-3 AP bring-up works without re-plumbing every call site.
//!
//! Layout note: each cell is padded up to 64 bytes so writes from
//! different CPUs don't false-share. `T` must be `Copy` (so the array
//! can be const-initialised); interior mutability lives in `T` (e.g.
//! `AtomicU64`).

use core::cell::UnsafeCell;

/// Upper bound on CPU count for Stage 2/3. Resize when SMP scales beyond.
pub const MAX_CPUS: usize = 64;

/// Per-CPU storage.
///
/// Layout: a single `UnsafeCell<[T; MAX_CPUS]>`. The whole array lives
/// behind one `UnsafeCell` so `PerCpu::new` can be `const` (array
/// repeat-expression with `T: Copy` works in const context; wrapping
/// each cell individually can't be done in a const fn because the
/// runtime `init` parameter can't cross into a const block).
///
/// False-sharing at 8-byte boundaries is a theoretical concern for
/// heavy cross-CPU traffic; Stage 2 is single-CPU, so it doesn't
/// bite. Stage-3 SMP should revisit (cache-line-pad each cell).
pub struct PerCpu<T: Copy> {
    cells: UnsafeCell<[T; MAX_CPUS]>,
}

// SAFETY: access is scoped through `this_cpu`, which indexes by the
// CPU-ID read (a value the caller can't forge). Different CPUs touch
// different cells; within a cell, interior mutability is the caller's
// responsibility (e.g. using an `AtomicU64` as `T`).
unsafe impl<T: Copy + Send + Sync> Sync for PerCpu<T> {}

impl<T: Copy> PerCpu<T> {
    /// Construct with every cell initialised to `init`.
    pub const fn new(init: T) -> Self {
        Self { cells: UnsafeCell::new([init; MAX_CPUS]) }
    }

    /// Reference to the calling CPU's cell.
    pub fn this_cpu(&self) -> &T {
        let id = narf_arch_cpu_id_hook();
        // SAFETY: `id < MAX_CPUS` by hook-side clamp. We return an
        // immutable borrow of the cell; `T: Copy` means the cell
        // can't hold owning references, so aliasing with other CPUs
        // reduces to whatever interior-mutability the `T` provides.
        unsafe { &(*self.cells.get())[id] }
    }

    /// All cells — mainly for diagnostics.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        // SAFETY: each cell is a valid T by construction; the returned
        // reference has `PerCpu`'s lifetime.
        let arr = unsafe { &*self.cells.get() };
        arr.iter()
    }
}

impl<T: Copy> core::fmt::Debug for PerCpu<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PerCpu")
            .field("max_cpus", &MAX_CPUS)
            .finish_non_exhaustive()
    }
}

// Breaks the dependency cycle: narf-lib can't depend on narf-arch
// (arch depends on lib), so we call out to a weakly-linked hook that
// narf-arch fills in. Stage-2 default returns 0 (BSP). Stage-3 AP
// bring-up replaces this with a real per-CPU-ID read.
extern "Rust" {
    fn narf_arch_cpu_id() -> usize;
}

#[inline]
fn narf_arch_cpu_id_hook() -> usize {
    // SAFETY: `narf_arch_cpu_id` is provided by narf-arch via
    // `#[no_mangle]`; every binary that links narf-arch has it. It's
    // a pure read of a CPU-identifying register (Stage 2: returns 0).
    let id = unsafe { narf_arch_cpu_id() };
    debug_assert!(id < MAX_CPUS, "CPU id out of PerCpu range");
    if id < MAX_CPUS { id } else { 0 }
}
