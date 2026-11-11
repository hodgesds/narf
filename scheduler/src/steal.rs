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
//! - Optional `LlcAwareSteal` uses advisory CPU summaries for allocation-free
//!   donor selection and LLC-local search admission.
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
use core::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};

use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant};
use narf_lib::sync::IrqSafeSpinLock;

use crate::affinity::CpuId;
use crate::policy::TaskMeta;

mod pick2;
pub use pick2::Pick2Steal;

const MAX_CPUS: usize = narf_lib::percpu::MAX_CPUS;
const UNKNOWN_LLC: u64 = u64::MAX;
static TOPOLOGY_GENERATION: AtomicU64 = AtomicU64::new(0);
static LLC_IDS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(UNKNOWN_LLC) }; MAX_CPUS];

#[repr(u8)]
enum BootStealPolicy {
    Numa,
    Llc,
    Pick2,
}
static BOOT_STEAL_POLICY: AtomicU8 = AtomicU8::new(BootStealPolicy::Numa as u8);

/// Select the boot default before scheduler init. Runtime replacement still
/// requires the existing Cap<Steal, Grant>; populated slots are never overwritten
/// by install_default_if_unset.
pub fn set_default_steal_policy(name: &str) -> bool {
    let policy = match name {
        "numa" | "full" => BootStealPolicy::Numa,
        "llc" => BootStealPolicy::Llc,
        "pick2" => BootStealPolicy::Pick2,
        _ => return false,
    };
    BOOT_STEAL_POLICY.store(policy as u8, Ordering::Release);
    true
}

/// Facts only: populated on the executing CPU during BSP/AP scheduler startup.
/// Architectures without shared-cache identity discovery remain explicitly unknown.
pub(crate) fn register_current_cpu() {
    #[cfg(target_arch = "x86_64")]
    if let Some(cell) = LLC_IDS.get(narf_lib::percpu::current_cpu()) {
        cell.store(
            narf_arch::x86_64::cache_topology::current_llc_id().unwrap_or(UNKNOWN_LLC),
            Ordering::Release,
        );
    }
    // Publication is cold. A cached policy refreshes after AP discovery.
    TOPOLOGY_GENERATION.fetch_add(1, Ordering::Release);
}

pub(crate) fn llc_id(cpu: CpuId) -> Option<u64> {
    let value = LLC_IDS.get(cpu.0 as usize)?.load(Ordering::Acquire);
    (value != UNKNOWN_LLC).then_some(value)
}

/// Advisory, read-only facts for a steal policy. Hints can be stale: the core
/// revalidates the chosen queue, budgets, affinity, and migration constraints.
pub struct StealContext<'a> {
    pub online_mask: u64,
    pub topology_generation: u64,
    idle: &'a dyn Fn(CpuId) -> bool,
    runnable: &'a dyn Fn(CpuId) -> bool,
    llc: &'a dyn Fn(CpuId) -> Option<u64>,
    node: &'a dyn Fn(CpuId) -> Option<u32>,
    queued: &'a dyn Fn(CpuId) -> Option<usize>,
    clock: &'a dyn Fn() -> u64,
}

impl core::fmt::Debug for StealContext<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StealContext")
            .field("online_mask", &self.online_mask)
            .finish_non_exhaustive()
    }
}

impl<'a> StealContext<'a> {
    pub fn new(
        online_mask: u64,
        idle: &'a dyn Fn(CpuId) -> bool,
        runnable: &'a dyn Fn(CpuId) -> bool,
        llc: &'a dyn Fn(CpuId) -> Option<u64>,
        node: &'a dyn Fn(CpuId) -> Option<u32>,
        queued: &'a dyn Fn(CpuId) -> Option<usize>,
        clock: &'a dyn Fn() -> u64,
    ) -> Self {
        Self {
            online_mask,
            topology_generation: TOPOLOGY_GENERATION.load(Ordering::Acquire),
            idle,
            runnable,
            llc,
            node,
            queued,
            clock,
        }
    }
    pub fn online(&self) -> impl Iterator<Item = CpuId> {
        cpus_in(self.online_mask)
    }
    /// Nonblocking queued-work hint; None means unavailable or contended.
    /// This is not a count of affinity/budget/migration-eligible tasks.
    pub fn queued_load(&self, cpu: CpuId) -> Option<usize> {
        (self.queued)(cpu)
    }
    pub fn now_cycles(&self) -> u64 {
        (self.clock)()
    }
    pub fn is_idle(&self, cpu: CpuId) -> bool {
        (self.idle)(cpu)
    }
    pub fn may_have_runnable_peer(&self, cpu: CpuId) -> bool {
        (self.runnable)(cpu)
    }
    pub fn llc_id(&self, cpu: CpuId) -> Option<u64> {
        (self.llc)(cpu)
    }
    pub fn numa_node(&self, cpu: CpuId) -> Option<u32> {
        (self.node)(cpu)
    }
}

fn cpus_in(mut mask: u64) -> impl Iterator<Item = CpuId> {
    core::iter::from_fn(move || {
        if mask == 0 {
            return None;
        }
        let cpu = CpuId(mask.trailing_zeros());
        mask &= mask - 1;
        Some(cpu)
    })
}

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
/// Idle CPUs can search repeatedly; implementations should bound search work
/// and avoid allocating on each attempt. The legacy ordering adapter remains
/// available for existing policies. Impls must avoid re-entering
/// the scheduler or touching any `IrqSafeSpinLock` that an IRQ
/// handler could be waiting on.
pub trait StealStrategy: Send + Sync + 'static {
    /// Stable identifier — surfaced by `current_steal_strategy_name`.
    fn name(&self) -> &'static str;

    /// Choose victim ordering. `online` is the set of online CPUs
    /// other than `thief`; the returned vec yields victims in the
    /// order they should be tried. Empty = no steal this round.
    fn order_victims(&self, thief: CpuId, online: &[CpuId]) -> Vec<CpuId>;

    /// Visit candidates until one succeeds. The default preserves the legacy
    /// ordering API for existing custom policies; policies may avoid allocating
    /// a victim list and hold a search permit across the actual queue probes.
    fn visit_victims(
        &self,
        thief: CpuId,
        context: &StealContext<'_>,
        visit: &mut dyn FnMut(CpuId) -> bool,
    ) {
        // Only legacy ordering implementations need the full CPU list.
        let mut online = [CpuId(0); MAX_CPUS];
        let mut count = 0;
        for cpu in context.online() {
            if cpu != thief && (cpu.0 as usize) < MAX_CPUS {
                online[count] = cpu;
                count += 1;
            }
        }
        for victim in self.order_victims(thief, &online[..count]) {
            if visit(victim) {
                break;
            }
        }
    }

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

#[repr(align(64))]
struct SearchCount(AtomicUsize);

impl SearchCount {
    const fn new() -> Self {
        Self(AtomicUsize::new(0))
    }

    fn try_acquire(&self, limit: usize) -> Option<SearchPermit<'_>> {
        let current = self.0.load(Ordering::Relaxed);
        if current >= limit {
            return None;
        }
        // Best effort: a contending search waits for a later idle round,
        // rather than spinning on a shared policy counter.
        self.0
            .compare_exchange(current, current + 1, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| SearchPermit(self))
    }
}

struct SearchPermit<'a>(&'a SearchCount);
impl Drop for SearchPermit<'_> {
    fn drop(&mut self) {
        self.0 .0.fetch_sub(1, Ordering::Release);
    }
}

// Policy-owned admission, touched only by searches with possible donors.
// A cache domain uses its lowest currently described logical CPU as a lane.
static SEARCHES: [SearchCount; MAX_CPUS] = [const { SearchCount::new() }; MAX_CPUS];

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

/// LLC-aware idle search policy. Prefer this explicitly when its idle CPU
/// saving fits the workload's wakeup-latency budget.
#[derive(Copy, Clone, Debug, Default)]
pub struct LlcAwareSteal;

impl LlcAwareSteal {
    pub const fn new() -> Self {
        Self
    }
}

impl StealStrategy for LlcAwareSteal {
    fn name(&self) -> &'static str {
        "llc-aware"
    }
    fn order_victims(&self, thief: CpuId, online: &[CpuId]) -> Vec<CpuId> {
        NumaAwareSteal.order_victims(thief, online)
    }
    fn visit_victims(
        &self,
        thief: CpuId,
        context: &StealContext<'_>,
        visit: &mut dyn FnMut(CpuId) -> bool,
    ) {
        if thief.0 as usize >= MAX_CPUS {
            return;
        }
        let thief_bit = 1u64 << thief.0;
        let llc = context.llc_id(thief);
        let mut scope = thief_bit;
        let mut idle = thief_bit; // the caller is searching because it has no local work
        let mut candidates = 0u64;
        for cpu in context.online() {
            if cpu == thief || cpu.0 as usize >= MAX_CPUS {
                continue;
            }
            let bit = 1u64 << cpu.0;
            let cpu_idle = context.is_idle(cpu);
            // The peer hint is conservative and can outlive the last task.
            // An idle owner will consume a racing wake itself before there
            // is running-plus-queued surplus worth stealing.
            if !cpu_idle && context.may_have_runnable_peer(cpu) {
                candidates |= bit;
            }
            if cpu_idle {
                idle |= bit;
            }
            if llc.is_some() && context.llc_id(cpu) == llc {
                scope |= bit;
            }
        }
        if candidates == 0 {
            return;
        }

        // Idle demand and possible local donors set the search concurrency,
        // not task placement. A remote-only search admits one local searcher.
        // These advisory snapshots can change during hotplug or a wake;
        // authoritative ownership and eligibility stay in the core visitor.
        let _permit = if llc.is_some() {
            let demand = (idle & scope).count_ones() as usize;
            let supply = (candidates & scope).count_ones() as usize;
            let limit = demand.min(supply.max(1)).max(1);
            let Some(permit) = SEARCHES[scope.trailing_zeros() as usize].try_acquire(limit) else {
                return;
            };
            Some(permit)
        } else {
            None
        };

        let node = context.numa_node(thief);
        let mut local_node = 0;
        if node.is_some() {
            for cpu in context.online() {
                if cpu.0 < 64 && candidates & (1u64 << cpu.0) != 0 && context.numa_node(cpu) == node
                {
                    local_node |= 1u64 << cpu.0;
                }
            }
        }
        // LLC first, then the remainder of the NUMA node, then farther CPUs.
        // Walk every possible donor if needed, so pinned/cache-hot local work
        // cannot indefinitely hide an eligible remote task behind a probe cap.
        for tier in [
            candidates & scope,
            candidates & local_node & !scope,
            candidates & !local_node & !scope,
        ] {
            for offset in 1..MAX_CPUS {
                let cpu = CpuId(((thief.0 as usize + offset) % MAX_CPUS) as u32);
                if tier & (1u64 << cpu.0) != 0 && visit(cpu) {
                    return;
                }
            }
        }
    }
}

mod policy_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn search_permit_is_bounded_and_released() -> TestResult {
        let count = SearchCount::new();
        let Some(first) = count.try_acquire(1) else {
            return TestResult::Fail("first search refused");
        };
        let bounded = count.try_acquire(1).is_none();
        drop(first);
        if bounded && count.try_acquire(1).is_some() {
            TestResult::Pass
        } else {
            TestResult::Fail("search permit bound or release failed")
        }
    }
    kernel_test_in!("scheduler/steal", search_permit_is_bounded_and_released);

    fn idle_policy_skips_empty_donors_and_preserves_locality_fallback() -> TestResult {
        if narf_lib::smp::ever_online_bitmap() != 1 {
            return TestResult::Skip("synthetic LLC must not share admission state with real APs");
        }
        let online = 0b11110;
        let idle = |cpu: CpuId| cpu.0 == 1;
        let none = |_| false;
        let cache = |c: CpuId| Some(if c.0 == 0 || c.0 == 2 { 1 } else { 2 });
        let node = |c: CpuId| Some(if c.0 <= 3 { 0 } else { 1 });
        let empty = StealContext::new(online, &idle, &none, &cache, &node, &|_| Some(2), &|| 0);
        let mut probes = 0;
        LlcAwareSteal.visit_victims(CpuId(0), &empty, &mut |_| {
            probes += 1;
            false
        });
        if probes != 0 {
            return TestResult::Fail("empty donor was probed");
        }
        // CPU 1 deliberately has a stale positive peer hint while idle.
        let runnable = |c: CpuId| c.0 >= 1;
        let work = StealContext::new(online, &idle, &runnable, &cache, &node, &|_| Some(2), &|| 0);
        let mut visited = Vec::new();
        LlcAwareSteal.visit_victims(CpuId(0), &work, &mut |c| {
            visited.push(c);
            false
        });
        if visited != [CpuId(2), CpuId(3), CpuId(4)] {
            return TestResult::Fail("LLC/NUMA/remote ordering or donor filtering failed");
        }
        visited.clear();
        LlcAwareSteal.visit_victims(CpuId(0), &work, &mut |c| {
            visited.push(c);
            true
        });
        if visited == [CpuId(2)] {
            TestResult::Pass
        } else {
            TestResult::Fail("search continued after a successful steal")
        }
    }
    kernel_test_in!(
        "scheduler/steal",
        idle_policy_skips_empty_donors_and_preserves_locality_fallback
    );
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

/// Install the boot-selected policy (normally `NumaAwareSteal`) if no steal
/// strategy is yet installed. Idempotent — re-calling after an explicit
/// `install_steal_strategy` is a no-op. Called from `crate::init`.
pub(crate) fn install_default_if_unset() {
    let replacement: Arc<dyn StealStrategy> =
        if BOOT_STEAL_POLICY.load(Ordering::Acquire) == BootStealPolicy::Llc as u8 {
            Arc::new(LlcAwareSteal)
        } else if BOOT_STEAL_POLICY.load(Ordering::Acquire) == BootStealPolicy::Pick2 as u8 {
            Arc::new(Pick2Steal::new())
        } else {
            Arc::new(NumaAwareSteal)
        };
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
