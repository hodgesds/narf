//! The memory-subsystem seam, and an interpreter-only stub behind it.
//!
//! `bpf/specification/spec.md` §3.3 puts the real implementations in
//! `memory/src/bpf_text.rs` and `memory/src/bpf_arena.rs`: an RX text
//! allocator over a hugepage-backed prog pack, an exception table, a guarded
//! arena window, and a per-CPU BPF stack region. None of that exists yet, and
//! none of it is this crate's to write. What is defined here is the *shape* of
//! the dependency, plus the smallest stub that lets the interpreter run — so
//! the runtime, the syscall surface, and the attach adapters can land and be
//! boot-verified before the allocator does.
//!
//! Nothing here allocates on the execution path. That is invariant §4.6: a
//! running program may not allocate, and the atomic stack provider is reached
//! from `tracing::dispatch::fire()` with IRQs masked and a spinlock held.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use narf_lib::percpu::{current_cpu, MAX_CPUS};
use narf_lib::sync::without_interrupts;

/// Bytes of BPF stack a single atomic invocation gets from the stub.
///
/// Linux's `MAX_BPF_STACK` is 512 because the BPF stack lives on the *kernel*
/// stack (`kernel/bpf/verifier.c::check_max_stack_depth_subprog`). NARF gives
/// BPF its own region, so the number here is a budget rather than an
/// architectural constraint — Stream B's real region will be far larger, and
/// `narf_bpf_verifier::MAX_STACK_BYTES` (16 KiB) is the ceiling the verifier
/// enforces against.
pub const STUB_STACK_BYTES: usize = 4096;

/// A source of BPF stack frames.
///
/// Two implementations by design (`bpf/specification/spec.md` §4.8): atomic
/// programs draw from a per-CPU region, sleepable programs get a heap stack
/// owned by the future, because a sleeping program cannot hold a per-CPU slot
/// across a yield.
pub trait BpfStack {
    /// Borrow a zeroed frame of at least `bytes`, or `None` if the provider
    /// is exhausted (nesting limit reached, or the request is larger than a
    /// frame).
    ///
    /// # Safety
    ///
    /// The returned frame aliases provider-owned storage. The caller must
    /// release it (by dropping the guard) before the current CPU can take
    /// another frame, and must not let the borrow outlive the guard.
    fn acquire(&self, bytes: usize) -> Option<StackFrame<'_>>;
}

/// A borrowed BPF stack frame. Releasing is `Drop`, so an early return from
/// the interpreter cannot leak a per-CPU slot.
///
/// **Not `Send`.** A per-CPU frame is only valid on the CPU that claimed it,
/// and the release must land on *that* CPU's flag. Making the type `!Send`
/// makes any future holding one `!Send` too, so it cannot be handed to
/// `narf_scheduler::spawn` and cannot be work-stolen mid-run — the migration
/// is prevented rather than detected.
#[derive(Debug)]
pub struct StackFrame<'a> {
    bytes: &'a mut [u8],
    /// Called with the CPU index recorded at acquire time — never with
    /// `current_cpu()` re-read at drop. Re-reading was a real bug: a task
    /// that migrated between acquire and drop cleared the *wrong* CPU's flag,
    /// leaking the original CPU's cell forever (it would decline every later
    /// program) and clearing a flag whose cell was still live, handing the
    /// same `&mut [u8]` out twice.
    release: Option<(fn(usize), usize)>,
    /// The real per-CPU region's lease, when this frame came from
    /// `memory::bpf_stack` rather than from the interpreter-only stub.
    ///
    /// Held rather than released explicitly: `StackLease` has its own `Drop`
    /// which returns the nesting level with IRQs masked and asserts it is
    /// dropped on the CPU it was taken on. Owning it here is what makes the
    /// runtime actually *use* the memory subsystem — the two halves of this
    /// subsystem were built in parallel and, until this, never connected: the
    /// region was allocated and mapped at boot and had no callers outside its
    /// own smokes.
    lease: Option<narf_memory::bpf_stack::StackLease>,
    /// `*mut ()` is the standard way to opt out of `Send`/`Sync` without the
    /// unstable `negative_impls`. Never dereferenced.
    _not_send: core::marker::PhantomData<*mut ()>,
}

impl StackFrame<'_> {
    /// The frame's bytes. R10 points one past the end (BPF stacks grow down).
    #[inline]
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        self.bytes
    }

    /// Frame length in bytes.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the frame is zero-length.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The CPU whose per-CPU region backs this frame, if any.
    ///
    /// `None` for the interpreter-only stub and for a sleepable program's heap
    /// stack. Exists so a caller can assert it is still on the CPU it started
    /// on — and so the lease is *read* rather than only held: its release runs
    /// in `StackLease::drop`, which the compiler cannot see as a use.
    #[inline]
    #[must_use]
    pub fn cpu(&self) -> Option<usize> {
        self.lease
            .as_ref()
            .map(narf_memory::bpf_stack::StackLease::cpu)
    }
}

impl Drop for StackFrame<'_> {
    fn drop(&mut self) {
        if let Some((f, cpu)) = self.release {
            f(cpu);
        }
    }
}

// ── the atomic (per-CPU) stub ───────────────────────────────────────

/// Per-CPU frame storage.
///
/// `narf_lib::percpu::PerCpu<T>` requires `T: Copy` so its cells can be
/// const-initialised, which a mutable byte array cannot be. A bare array of
/// `UnsafeCell`s with a hand-written `Sync` is the same trade the slab's
/// per-CPU magazine makes.
struct PerCpuFrames {
    cells: [UnsafeCell<[u8; STUB_STACK_BYTES]>; MAX_CPUS],
}

// SAFETY: a cell is only ever reached through `current_cpu()` inside
// `without_interrupts`, and only after `IN_USE[cpu]` transitions 0 → 1. Two
// CPUs therefore touch disjoint cells, and one CPU cannot re-enter its own
// cell because the depth counter declines the second acquire. This is the
// same argument the per-CPU slab magazine makes (`memory/src/slab.rs`), and
// it has the same load-bearing precondition: IRQs masked across the RMW.
//
// An earlier version of this comment also leaned on "handlers run under
// `dispatch::fire()` with IRQs masked for their whole duration". That premise
// was removed by this same series — `fire()` now drops its lock, and restores
// IRQs, before invoking a handler — so the frame is held across a preemptible
// region. What closes the gap is not IRQ masking but `StackFrame` being
// `!Send` (so the frame cannot migrate) and carrying the CPU index it was
// claimed on (so the release cannot land on the wrong flag even if it did).
unsafe impl Sync for PerCpuFrames {}

static FRAMES: PerCpuFrames = PerCpuFrames {
    cells: [const { UnsafeCell::new([0u8; STUB_STACK_BYTES]) }; MAX_CPUS],
};

/// Per-CPU nesting depth. `bpf/specification/spec.md` §1.5: re-entrancy is a
/// depth counter, not a global recursion guard — nesting to depth N is
/// supported and N+1 *declines the program* rather than corrupting anything.
/// The stub's N is 1; Stream B's region raises it.
static IN_USE: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];

/// Count of declined invocations, for the boot smoke and for diagnostics.
static DECLINED: AtomicUsize = AtomicUsize::new(0);

/// The interpreter-only per-CPU stack provider.
#[derive(Copy, Clone, Debug, Default)]
pub struct PerCpuStackStub;

/// Release the frame belonging to `cpu` — the CPU recorded at acquire time.
///
/// Deliberately takes the index rather than calling `current_cpu()`. See
/// [`StackFrame::release`].
fn release_cpu(cpu: usize) {
    without_interrupts(|| {
        debug_assert_eq!(
            cpu,
            current_cpu(),
            "a per-CPU BPF frame was released on a different CPU than it was \
             claimed on — StackFrame is !Send precisely to make this \
             impossible, so reaching here means something moved it anyway"
        );
        IN_USE[cpu].store(0, Ordering::Release);
    });
}

impl BpfStack for PerCpuStackStub {
    fn acquire(&self, bytes: usize) -> Option<StackFrame<'_>> {
        if bytes > STUB_STACK_BYTES {
            DECLINED.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        // The claim must be atomic *with respect to interrupts*: this runs
        // under `tracing::dispatch::fire()`, and an IRQ landing between the
        // load and the store would let a nested fire hand out the same cell.
        let claimed = without_interrupts(|| {
            let cpu = current_cpu();
            IN_USE[cpu]
                .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
                .then_some(cpu)
        });
        let cpu = match claimed {
            Some(c) => c,
            None => {
                DECLINED.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };
        // SAFETY: `IN_USE[cpu]` went 0 → 1 above with IRQs masked, so this
        // CPU has exclusive use of its cell until `release_current_cpu`
        // stores 0, which only `StackFrame::drop` does. No other CPU indexes
        // this cell.
        let all = unsafe { &mut *FRAMES.cells[cpu].get() };
        let frame = &mut all[..bytes];
        frame.fill(0);
        Some(StackFrame {
            bytes: frame,
            release: Some((release_cpu, cpu)),
            lease: None,
            _not_send: core::marker::PhantomData,
        })
    }
}

/// The real per-CPU BPF stack, from `memory::bpf_stack`.
///
/// This is the provider atomic programs use once `memory::bpf_stack::init` has
/// run at boot. [`PerCpuStackStub`] remains for `run_unverified` and for the
/// window before `init`, and is deliberately much smaller so that a program
/// verified against the real ceiling cannot silently fall back to it.
#[derive(Copy, Clone, Debug, Default)]
pub struct PerCpuRegion;

/// Invocations declined because the region was not initialised or was full.
static REGION_DECLINED: AtomicUsize = AtomicUsize::new(0);

impl BpfStack for PerCpuRegion {
    fn acquire(&self, bytes: usize) -> Option<StackFrame<'_>> {
        let lease = narf_memory::bpf_stack::try_enter().or_else(|| {
            REGION_DECLINED.fetch_add(1, Ordering::Relaxed);
            None
        })?;
        if (bytes as u64) > lease.len() {
            // Dropping the lease here releases the nesting level; returning
            // None makes the caller decline the program rather than run it on
            // a frame smaller than the verifier proved it needs.
            REGION_DECLINED.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        // R10 starts at `top` and grows down, so the usable frame is the
        // `bytes` immediately below it.
        let base = lease.top() - bytes as u64;
        // SAFETY: `[top - len, top)` is a distinct nesting level of this CPU's
        // BPF stack region, mapped RW at boot by `bpf_stack::init` and leased
        // exclusively to this activation until the `StackLease` we hold is
        // dropped. `StackLease` is `!Send` and asserts it is released on the
        // CPU that took it, and `StackFrame` is `!Send` for the same reason,
        // so no other CPU or nesting level can alias these bytes.
        let frame = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, bytes) };
        frame.fill(0);
        Some(StackFrame {
            bytes: frame,
            release: None,
            lease: Some(lease),
            _not_send: core::marker::PhantomData,
        })
    }
}

/// Invocations the real per-CPU region has declined.
#[must_use]
pub fn region_declined_count() -> usize {
    REGION_DECLINED.load(Ordering::Relaxed)
}

/// Whether the real per-CPU region is available.
///
/// `false` before `memory::bpf_stack::init` runs, which is why the stub still
/// exists.
#[must_use]
pub fn region_ready() -> bool {
    narf_memory::bpf_stack::ready()
}

/// How many invocations the per-CPU stub has declined (nesting or oversize).
#[must_use]
pub fn declined_count() -> usize {
    DECLINED.load(Ordering::Relaxed)
}

// ── the sleepable (heap) stack ──────────────────────────────────────

/// A heap stack owned by the program's future.
///
/// Sleepable programs cannot use the per-CPU region: another task may run on
/// this CPU while the program is parked at an await. Allocating here is
/// legal because a sleepable program is entered from process context, not
/// from a probe site — invariant §4.6 forbids allocation *while running*, and
/// this happens before the first instruction.
pub struct HeapStack {
    /// Interior mutability because [`BpfStack::acquire`] takes `&self` — the
    /// per-CPU provider has no other option, and one trait for both keeps the
    /// interpreter from branching on which stack it was handed.
    bytes: UnsafeCell<alloc::boxed::Box<[u8]>>,
    len: usize,
}

impl core::fmt::Debug for HeapStack {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HeapStack").field("len", &self.len).finish()
    }
}

impl HeapStack {
    /// Allocate a zeroed stack of `bytes`.
    #[must_use]
    pub fn new(bytes: usize) -> Self {
        Self {
            bytes: UnsafeCell::new(alloc::vec![0u8; bytes].into_boxed_slice()),
            len: bytes,
        }
    }
}

impl BpfStack for HeapStack {
    fn acquire(&self, bytes: usize) -> Option<StackFrame<'_>> {
        if bytes > self.len {
            return None;
        }
        // SAFETY: the returned `StackFrame` borrows `self` for its whole
        // life, so a second `acquire` cannot overlap it, and `HeapStack` is
        // not `Sync` (the `UnsafeCell` sees to that) so no other thread holds
        // a reference.
        let all = unsafe { &mut *self.bytes.get() };
        let frame = &mut all[..bytes];
        frame.fill(0);
        Some(StackFrame {
            bytes: frame,
            release: None,
            lease: None,
            // A heap stack is owned by the future and is not per-CPU, so it
            // would be safe to move. It inherits `!Send` anyway rather than
            // splitting the type — a sleepable program's frame moving between
            // CPUs is fine, but nothing needs it to, and one shape is easier
            // to reason about than two.
            _not_send: core::marker::PhantomData,
        })
    }
}

// ── the not-yet-implemented seams ───────────────────────────────────

/// Executable-text allocation (`memory/src/bpf_text.rs`, Stream B).
///
/// Declared so the JIT can be written against it; the interpreter needs none
/// of it, and this crate deliberately ships no implementation. Sealing is
/// separate from allocation because invariant §4.3 requires every extable
/// entry to be registered *before* the text becomes executable.
pub trait TextAlloc {
    /// A handle to a text region.
    type Handle;

    /// Reserve `len` bytes of not-yet-executable text.
    ///
    /// # Errors
    ///
    /// Implementation-defined; typically pack exhaustion.
    fn alloc(&self, len: usize) -> Result<Self::Handle, TextError>;

    /// Publish the region RX. Must be called after every fault site in the
    /// region has an extable entry.
    ///
    /// # Errors
    ///
    /// Implementation-defined.
    fn seal(&self, handle: &Self::Handle) -> Result<(), TextError>;
}

/// Why a text operation failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TextError {
    /// No RX allocator is installed — the state until Stream B lands.
    NotAvailable,
    /// The pack could not satisfy the request.
    Exhausted,
}

/// Exception-table registration (`frame/src/*/trap.rs`, Stream B).
///
/// One entry per faulting instruction the JIT emits: a fault at `fault_addr`
/// resumes at `fixup_addr` with `dst_reg` zeroed. That is Linux's
/// `ex_handler_bpf()` (`arch/x86/net/bpf_jit_comp.c:1479`), which is what
/// makes `task->mm->owner` safe to write without null checks.
pub trait ExtableRegistry {
    /// Register one recovery site.
    ///
    /// # Errors
    ///
    /// Implementation-defined.
    fn register(
        &self,
        fault_addr: usize,
        fixup_addr: usize,
        dst_reg: Option<u8>,
    ) -> Result<(), TextError>;
}
