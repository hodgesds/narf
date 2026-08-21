//! Pluggable work-steal strategy seam — Wave F of the modular-cores
//! plan (`docs/PLUGGABILITY.md`). Mirrors the `policy::Scheduler` /
//! `donation::DonationPolicy` shape from waves earlier:
//!
//! - `pub trait StealStrategy: Send + Sync + 'static` defines the
//!   policy that decides (a) the order in which an idle thief tries
//!   victim CPUs and (b) whether a particular task on a victim's
//!   queue is eligible to be stolen.
//! - `static STEAL` slot holds one `Arc<dyn StealStrategy>` so the
//!   executor can snapshot-out before taking any per-CPU queue lock,
//!   avoiding the STEAL → READY[victim] lock-order inversion.
//! - `install_steal_strategy(&cap, impl)` swaps it under a
//!   `Cap<Steal, Grant>` check.
//! - Default `NumaAwareSteal` matches today's two-phase same-NUMA-
//!   node-first / cross-node round-robin order byte-for-byte.
//! - Alternative `RandomSteal` permutes the online victim set with a
//!   tiny per-call LCG seeded from (thief, monotonic counter).
//!
//! Lock discipline: the executor mutates `READY[victim]` under
//! `IrqSafeSpinLock`. The steal-strategy slot has its own lock; impls
//! must NOT be invoked while the queue lock is held. The fast path
//! clones the `Arc<dyn StealStrategy>` out of the slot, drops the
//! slot lock, and only then walks victims (taking each victim's
//! READY lock per attempt).

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant};
use narf_lib::sync::IrqSafeSpinLock;

use crate::affinity::CpuId;
use crate::policy::TaskMeta;

/// Authority to install a steal strategy. Cap-gated via
/// `install_steal_strategy`; revocation is observed lazily on the
/// next install attempt.
#[derive(Copy, Clone, Debug)]
pub struct Steal;

impl CapType for Steal {
    const KIND: CapKind = CapKind::StealStrategy;
}

/// Errors `install_steal_strategy` can return.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StealError {
    /// The install cap has been revoked.
    CapRevoked,
}

impl From<CapError> for StealError {
    fn from(_: CapError) -> Self {
        StealError::CapRevoked
    }
}

/// Pluggable work-steal strategy. Implementors choose the order an
/// idle thief tries victims and may refuse to steal individual tasks.
///
/// **Hot-path constraint** (relative — work-stealing is the *cold*
/// path that fires only when a CPU has no local work; one alloc per
/// steal attempt is acceptable). Impls must still avoid re-entering
/// the scheduler or touching any `IrqSafeSpinLock` that an IRQ
/// handler could be waiting on.
pub trait StealStrategy: Send + Sync + 'static {
    /// Stable identifier — surfaced by `current_steal_strategy_name`.
    fn name(&self) -> &'static str;

    /// Choose victim ordering. `online` is the set of online CPUs
    /// other than `thief`; the returned vec yields victims in the
    /// order they should be tried. Empty = no steal this round.
    fn order_victims(&self, thief: CpuId, online: &[CpuId]) -> Vec<CpuId>;

    /// Permit/refuse stealing this specific task. Receives a
    /// read-only snapshot of the task's metadata
    /// (addr_space / affinity / class / priority / id). Default:
    /// refuse to steal an address-space-bearing (user) task UNTIL
    /// user-task SMP is enabled at boot
    /// ([`crate::enable_user_task_smp`], set iff cross-CPU TLB
    /// shootdown is wired). The single-in-flight-user-task executor
    /// state (`CURRENT`, `CURRENT_TASK`, `ACTIVE_USER_AS`, the poller
    /// jmpbuf) is now per-CPU, and APs are user-mode-capable
    /// (per-CPU GDT/TSS/SYSCALL), so once the flag is set user tasks
    /// migrate subject to their affinity mask. When the flag is off
    /// (xAPIC fallback) user tasks stay BOOT-pinned and this floor is
    /// belt-and-suspenders. Either way, respect the affinity mask so
    /// pinned tasks are never stolen across their pins. Custom impls
    /// may broaden the strategy preference (the dispatcher still enforces
    /// hard affinity before execution) or narrow it (e.g. only steal
    /// `SchedClass::Default` tasks).
    fn allow_steal(&self, thief: CpuId, task: &TaskMeta) -> bool {
        if task.addr_space && !crate::user_task_smp_enabled() {
            return false;
        }
        task.affinity.allowed.contains(thief)
    }
}

/// NUMA-aware steal — the pre-Wave-F default. Same-NUMA-node victims
/// first (when ACPI SRAT topology was published), then cross-node
/// victims in round-robin order starting at `thief + 1`. Matches the
/// previously hardcoded two-phase scan in `try_steal_one`
/// byte-for-byte.
#[derive(Copy, Clone, Debug, Default)]
pub struct NumaAwareSteal;

impl NumaAwareSteal {
    /// Construct the default strategy. `Default::default()` works
    /// too; this is here for symmetry with `RandomSteal::new`.
    #[inline]
    pub const fn new() -> Self {
        Self
    }
}

impl StealStrategy for NumaAwareSteal {
    fn name(&self) -> &'static str {
        "numa-aware"
    }

    fn order_victims(&self, thief: CpuId, online: &[CpuId]) -> Vec<CpuId> {
        let mut out: Vec<CpuId> = Vec::with_capacity(online.len());
        let my_node = narf_acpi::cpu_node(thief.0);

        // Phase 1: same-node victims in `online` order.
        if my_node.is_some() {
            for v in online {
                if narf_acpi::cpu_node(v.0) == my_node {
                    out.push(*v);
                }
            }
        }

        // Phase 2: cross-node victims (or every victim if topology is
        // unknown). Round-robin starting at `thief + 1`.
        let max = narf_lib::percpu::MAX_CPUS as u32;
        for i in 1..=max {
            let v = CpuId((thief.0 + i) % max);
            if v == thief {
                continue;
            }
            // Only consider CPUs the caller put in `online`.
            if !online.contains(&v) {
                continue;
            }
            // Same-node victims were already emitted in phase 1.
            if my_node.is_some() && narf_acpi::cpu_node(v.0) == my_node {
                continue;
            }
            out.push(v);
        }

        out
    }
}

/// Random steal — uniform permutation of `online` using a tiny LCG
/// seeded from the thief CPU id plus a monotonic counter. Doesn't
/// pull in heavy RNG infra and isn't cryptographic; the only
/// requirement is "doesn't produce the strict NumaAware ordering
/// every call".
#[derive(Copy, Clone, Debug, Default)]
pub struct RandomSteal;

impl RandomSteal {
    /// Construct a `RandomSteal`. The PRNG state lives in a static
    /// counter that ticks on every `order_victims` call.
    #[inline]
    pub const fn new() -> Self {
        Self
    }
}

/// Monotonic counter feeding the LCG seed. `Relaxed` is fine; the
/// PRNG only needs ordering to avoid pathological collisions.
static RANDOM_STEAL_TICK: AtomicU64 = AtomicU64::new(0);

/// Numerical Recipes LCG constants — well-known, public-domain,
/// adequate for "give me a non-trivial permutation per call".
#[inline]
fn lcg_step(state: &mut u64) -> u64 {
    *state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
    *state
}

impl StealStrategy for RandomSteal {
    fn name(&self) -> &'static str {
        "random"
    }

    fn order_victims(&self, thief: CpuId, online: &[CpuId]) -> Vec<CpuId> {
        let tick = RANDOM_STEAL_TICK.fetch_add(1, Ordering::Relaxed);
        let mut state = (thief.0 as u64)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(tick.wrapping_add(1));

        let mut out: Vec<CpuId> = online.to_vec();
        // Fisher-Yates shuffle using `lcg_step` for swap indices.
        if out.len() > 1 {
            for i in (1..out.len()).rev() {
                let j = (lcg_step(&mut state) as usize) % (i + 1);
                out.swap(i, j);
            }
        }
        out
    }
}

/// `Arc<dyn StealStrategy>` slot. Arc (not Box) so the steal-fast-path
/// can `clone()` out of the slot O(1) and drop the slot lock before
/// taking any `READY[victim]` lock — see the lock-discipline comment
/// at the top of the module.
static STEAL: [IrqSafeSpinLock<Option<Arc<dyn StealStrategy>>>; narf_lib::percpu::MAX_CPUS] =
    [const { IrqSafeSpinLock::new(None) }; narf_lib::percpu::MAX_CPUS];

#[inline]
fn local_slot() -> &'static IrqSafeSpinLock<Option<Arc<dyn StealStrategy>>> {
    &STEAL[narf_lib::percpu::current_cpu().min(narf_lib::percpu::MAX_CPUS - 1)]
}

/// Install a steal strategy. Cap-gated on `Cap<Steal, Grant>`.
/// Replaces the previous active strategy; the displaced `Arc` is
/// dropped (its refcount hits zero once the last in-flight steal
/// snapshot also drops).
pub fn install_steal_strategy<S: StealStrategy>(
    cap: &Cap<Steal, Grant>,
    s: S,
) -> Result<(), StealError> {
    cap.check_live()?;
    let replacement: Arc<dyn StealStrategy> = Arc::from(Box::new(s) as Box<dyn StealStrategy>);
    for slot in &STEAL {
        *slot.lock() = Some(replacement.clone());
    }
    Ok(())
}

/// Snapshot the active steal strategy's name. Returns `None` if
/// `init()` hasn't run yet.
pub fn current_steal_strategy_name() -> Option<&'static str> {
    let slot = local_slot().lock();
    slot.as_ref().map(|s| s.name())
}

/// Install the default `NumaAwareSteal` if no steal strategy is yet
/// installed. Idempotent — re-calling after an explicit
/// `install_steal_strategy` is a no-op. Called from `crate::init`.
pub(crate) fn install_default_if_unset() {
    let replacement: Arc<dyn StealStrategy> =
        Arc::from(Box::new(NumaAwareSteal) as Box<dyn StealStrategy>);
    for slot in &STEAL {
        let mut slot = slot.lock();
        if slot.is_none() {
            *slot = Some(replacement.clone());
        }
    }
}

/// Executor-side snapshot. Clones the active strategy out of the
/// slot, drops the slot lock, and returns the `Arc`. Callers walk
/// the resulting victim list without ever holding the STEAL lock
/// concurrently with any `READY[victim]` lock.
///
/// Returns `None` when nothing is installed (pre-`init` very early
/// boot path); the caller treats that as "no steal".
#[inline]
pub(crate) fn snapshot() -> Option<Arc<dyn StealStrategy>> {
    local_slot().lock().as_ref().cloned()
}
