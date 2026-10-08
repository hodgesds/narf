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
//!
//! Hybrid-CPU registry: a flat `[AtomicU8; MAX_CPUS]` recording each
//! CPU's `CpuType` (P-core, E-core, Unknown). Populated by the BSP /
//! AP bring-up paths from CPUID leaf 0x1A on Intel Alder Lake+ silicon.
//! Read-only after SMP bring-up completes — the scheduler will
//! eventually consult it for affinity-hinted dispatch, but this pass
//! only exposes the data.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

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
        Self {
            cells: UnsafeCell::new([init; MAX_CPUS]),
        }
    }

    /// Reference to the calling CPU's cell.
    pub fn this_cpu(&self) -> &T {
        let id = narf_arch_cpu_id_hook();
        // SAFETY: `id < MAX_CPUS` by hook-side clamp. We return an
        // immutable borrow of the cell; `T: Copy` means the cell
        // can't hold owning references, so aliasing with other CPUs
        // reduces to whatever interior-mutability the `T` provides.
        // SAFETY: Valid memory or trusted environment
        unsafe { &(*self.cells.get())[id] }
    }

    /// All cells — mainly for diagnostics.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        // SAFETY: each cell is a valid T by construction; the returned
        // reference has `PerCpu`'s lifetime.
        // SAFETY: Valid memory or trusted environment
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
#[cfg(not(test))]
extern "Rust" {
    fn narf_arch_cpu_id() -> usize;
}

#[inline]
fn narf_arch_cpu_id_hook() -> usize {
    #[cfg(test)]
    {
        0
    }
    #[cfg(not(test))]
    {
        // SAFETY: `narf_arch_cpu_id` is provided by narf-arch via
        // `#[no_mangle]`; every binary that links narf-arch has it. It's
        // a pure read of a CPU-identifying register (Stage 2: returns 0).
        // SAFETY: Valid memory or trusted environment
        let id = unsafe { narf_arch_cpu_id() };
        debug_assert!(id < MAX_CPUS, "CPU id out of PerCpu range");
        if id < MAX_CPUS {
            id
        } else {
            0
        }
    }
}

/// Public accessor for the active CPU's logical index. Crates that
/// don't depend on narf-arch (memory's slab, drivers picking
/// per-CPU storage) reach the live CPU id through here.
#[inline]
pub fn current_cpu() -> usize {
    narf_arch_cpu_id_hook()
}

/// Cache-line-padded, monotonically increasing counters with one bank per
/// CPU.  The owner CPU updates only its own bank using relaxed load/store, so
/// an increment does not issue a locked RMW or bounce a cache line between
/// cores.  Readers take an eventually consistent snapshot and derive a
/// measurement interval with [`PerCpuCounterSnapshot::delta_since`].
///
/// This is suitable for diagnostics and telemetry, not for exact
/// cross-CPU accounting or admission control.  Counter values wrap naturally
/// at `u64::MAX`; `delta_since` deliberately uses wrapping subtraction so a
/// long-running counter still has a correct interval delta.
pub struct PerCpuCounterBank<const N: usize> {
    cells: [PerCpuCounterCell<N>; MAX_CPUS],
}

/// Keep each CPU's counter array on separate cache lines.  An array of these
/// cells has a stride that is a multiple of the alignment, so adjacent CPUs
/// cannot false-share a counter cache line.
#[repr(align(64))]
struct PerCpuCounterCell<const N: usize> {
    values: [AtomicU64; N],
}

impl<const N: usize> PerCpuCounterCell<N> {
    const fn new() -> Self {
        Self {
            values: [const { AtomicU64::new(0) }; N],
        }
    }
}

impl<const N: usize> PerCpuCounterBank<N> {
    /// Construct a zeroed, fixed-size counter bank.
    pub const fn new() -> Self {
        Self {
            cells: [const { PerCpuCounterCell::new() }; MAX_CPUS],
        }
    }

    /// Increment `counter` in the calling CPU's bank.  Invalid counter
    /// indices are ignored: instrumentation must not introduce a failure path
    /// into the code it is observing.
    #[inline]
    pub fn increment(&self, counter: usize) {
        self.add(counter, 1);
    }

    /// Add `value` to `counter` in the calling CPU's bank.
    ///
    /// Only the owning CPU writes a bank, so a relaxed load followed by a
    /// relaxed store is sufficient and avoids the cost of a locked `fetch_add`.
    /// Concurrent snapshot readers may observe either value, which is the
    /// intended eventually-consistent telemetry contract.
    #[inline]
    pub fn add(&self, counter: usize, value: u64) {
        if counter >= N {
            return;
        }
        let cpu = current_cpu().min(MAX_CPUS - 1);
        let slot = &self.cells[cpu].values[counter];
        slot.store(
            slot.load(Ordering::Relaxed).wrapping_add(value),
            Ordering::Relaxed,
        );
    }

    /// Aggregate a relaxed snapshot across every CPU's counter bank.
    pub fn snapshot(&self) -> PerCpuCounterSnapshot<N> {
        let mut snapshot = PerCpuCounterSnapshot::zero();
        for cell in &self.cells {
            for (index, value) in cell.values.iter().enumerate() {
                snapshot.values[index] =
                    snapshot.values[index].wrapping_add(value.load(Ordering::Relaxed));
            }
        }
        snapshot
    }

    /// Snapshot one CPU's counter bank without cross-CPU aggregation.  An
    /// invalid CPU index selects the BSP bank, matching [`PerCpu::this_cpu`]'s
    /// defensive clamping of an invalid architecture CPU id.
    pub fn snapshot_cpu(&self, cpu: usize) -> PerCpuCounterSnapshot<N> {
        let cell = &self.cells[cpu.min(MAX_CPUS - 1)];
        let mut snapshot = PerCpuCounterSnapshot::zero();
        for (index, value) in cell.values.iter().enumerate() {
            snapshot.values[index] = value.load(Ordering::Relaxed);
        }
        snapshot
    }
}

impl<const N: usize> Default for PerCpuCounterBank<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> core::fmt::Debug for PerCpuCounterBank<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PerCpuCounterBank")
            .field("counters_per_cpu", &N)
            .field("max_cpus", &MAX_CPUS)
            .finish_non_exhaustive()
    }
}

/// A point-in-time view of a [`PerCpuCounterBank`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PerCpuCounterSnapshot<const N: usize> {
    values: [u64; N],
}

impl<const N: usize> PerCpuCounterSnapshot<N> {
    /// A zero-valued snapshot.
    pub const fn zero() -> Self {
        Self { values: [0; N] }
    }

    /// Value of one counter, or zero for an invalid index.
    #[inline]
    pub fn get(&self, counter: usize) -> u64 {
        self.values.get(counter).copied().unwrap_or(0)
    }

    /// Per-counter delta since `previous`, using wrapping subtraction so it
    /// remains valid when a monotonic counter wraps around `u64::MAX`.
    pub fn delta_since(self, previous: Self) -> Self {
        let mut values = [0; N];
        let mut index = 0;
        while index < N {
            values[index] = self.values[index].wrapping_sub(previous.values[index]);
            index += 1;
        }
        Self { values }
    }
}

#[cfg(test)]
mod host_tests {
    use super::*;

    #[test]
    fn host_cpu_id_defaults_to_boot_cpu() {
        assert_eq!(current_cpu(), 0);
    }

    #[test]
    fn this_cpu_selects_boot_cpu_cell() {
        let cells = PerCpu::new(17u32);
        assert_eq!(*cells.this_cpu(), 17);
        assert_eq!(cells.iter().count(), MAX_CPUS);
    }

    #[test]
    fn counter_bank_snapshot_and_delta_are_monotonic() {
        let counters = PerCpuCounterBank::<3>::new();
        counters.increment(0);
        counters.add(1, 4);
        let before = counters.snapshot();
        assert_eq!(before.get(0), 1);
        assert_eq!(before.get(1), 4);
        assert_eq!(before.get(2), 0);

        counters.add(0, 9);
        counters.increment(2);
        let delta = counters.snapshot().delta_since(before);
        assert_eq!(delta.get(0), 9);
        assert_eq!(delta.get(1), 0);
        assert_eq!(delta.get(2), 1);
    }
}

// ── hybrid-CPU topology registry ──────────────────────────────────
//
// Intel Alder Lake / Raptor Lake / Meteor Lake (12th gen+) ship with
// heterogeneous cores: P-cores (Core, "Golden Cove" / "Redwood Cove"
// class) and E-cores (Atom, "Gracemont" / "Crestmont" class). CPUID
// leaf 0x1A reports per-logical-CPU `core_type` in EAX[31:24]:
//
//   0x20 = Atom    (E-core, throughput-optimised)
//   0x40 = Core    (P-core, latency-optimised)
//
// Linux reads this in `arch/x86/kernel/cpu/intel.c::intel_get_cpu_type`
// (callable as `get_this_hybrid_cpu_type()` from cpufreq / sched
// code) and stores it as a per-CPU `cpu_type` field. The scheduler
// then biases latency-sensitive tasks toward P-cores.
//
// NARF mirrors that storage model here. Each CPU writes its own slot
// during its bring-up path (BSP in `bare_main`, APs in
// `frame::x86_64::smp::_ap_start_rust`). The boot-log summary line
// reads the populated slots to print `cpu-topology: BSP=Core, 12
// P-cores + 4 E-cores`. AMD silicon (including the Renoir 4700U
// real-HW target) doesn't populate CPUID 0x1A at all and reports
// `Unknown` — which is the correct answer for uniform-core parts.

/// Reported CPU type from Intel's hybrid-CPU topology mechanism
/// (CPUID leaf 0x1A). `Unknown` covers (a) AMD / pre-12th-gen Intel
/// silicon that doesn't expose leaf 0x1A, (b) QEMU TCG which never
/// populates hybrid bits, and (c) the BSP slot before its bring-up
/// probe runs. Encoded as the raw EAX[31:24] byte so the wire
/// representation matches Linux's `X86_CPU_TYPE_*` defines.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CpuType {
    /// CPUID 0x1A EAX[31:24] not populated. AMD parts, pre-Alder
    /// Lake Intel, virtualised guests, and the BSP pre-probe.
    Unknown = 0,
    /// `X86_CPU_TYPE_INTEL_ATOM` — Gracemont / Crestmont E-core.
    Atom = 0x20,
    /// `X86_CPU_TYPE_INTEL_CORE` — Golden Cove / Redwood Cove P-core.
    Core = 0x40,
}

impl CpuType {
    /// Decode the raw EAX[31:24] byte from CPUID 0x1A. Unrecognised
    /// values map to `Unknown` so a future Intel core class
    /// (currently 0x10 is reserved for "Knights" Xeon Phi line and
    /// nothing else is documented) doesn't trip the kernel.
    #[inline]
    pub const fn from_raw(byte: u8) -> Self {
        match byte {
            0x20 => Self::Atom,
            0x40 => Self::Core,
            _ => Self::Unknown,
        }
    }

    /// `true` for Intel performance cores ("P-cores").
    #[inline]
    pub const fn is_p_core(self) -> bool {
        matches!(self, Self::Core)
    }

    /// `true` for Intel efficiency cores ("E-cores").
    #[inline]
    pub const fn is_e_core(self) -> bool {
        matches!(self, Self::Atom)
    }

    /// Short label for boot-log summary lines.
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Core => "Core",
            Self::Atom => "Atom",
            Self::Unknown => "Unknown",
        }
    }
}

/// Per-CPU hybrid-type registry. One atomic byte per logical CPU,
/// holding the `CpuType` raw value. Read order is `Relaxed`:
/// publication happens-before consumers under the SMP-bring-up
/// barrier (`mark_online`), and post-bring-up the registry is
/// read-only.
static CPU_TYPES: [AtomicU8; MAX_CPUS] = {
    // const-fn array repeat for non-Copy `AtomicU8`.
    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO: AtomicU8 = AtomicU8::new(0);
    [ZERO; MAX_CPUS]
};

/// Record this CPU's hybrid type. Called once per CPU during its
/// own bring-up, immediately after `set_current_cpu` writes the
/// logical id register so the slot index is correct.
///
/// # Safety
/// `logical_id` must match the calling CPU. Repeated writes from a
/// single CPU are tolerated (Relaxed atomic store); concurrent
/// writes from different CPUs target disjoint slots.
pub fn set_cpu_type(logical_id: u32, ty: CpuType) {
    if (logical_id as usize) < MAX_CPUS {
        CPU_TYPES[logical_id as usize].store(ty as u8, Ordering::Relaxed);
    }
}

/// Read the recorded `CpuType` for `logical_id`. Returns `Unknown`
/// for out-of-range ids, CPUs that haven't completed bring-up yet,
/// and silicon that doesn't expose CPUID 0x1A.
#[inline]
pub fn cpu_type(logical_id: u32) -> CpuType {
    if (logical_id as usize) >= MAX_CPUS {
        return CpuType::Unknown;
    }
    CpuType::from_raw(CPU_TYPES[logical_id as usize].load(Ordering::Relaxed))
}

/// Number of CPUs in the online bitmap matching `ty`. Used by the
/// boot-log summary line and (later) by scheduler heuristics that
/// size per-class queues.
pub fn count_cpu_type(ty: CpuType) -> u32 {
    // Bound the scan by MAX_CPUS — the online-bitmap stride is the
    // same width.
    let mut n: u32 = 0;
    for id in 0..MAX_CPUS as u32 {
        if !crate::smp::is_online(id) {
            continue;
        }
        if cpu_type(id) == ty {
            n += 1;
        }
    }
    n
}

#[doc(hidden)]
pub fn __cpu_type_reset_for_test() {
    for slot in &CPU_TYPES {
        slot.store(0, Ordering::Relaxed);
    }
}
