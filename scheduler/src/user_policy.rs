//! Live Linux-compatible user-thread scheduling controls.
//!
//! Callers retain Linux credential/rlimit validation. This module owns the
//! executor configuration and shared RT bandwidth; its authority is explicitly
//! delegated by the frame at boot, never minted by a scheduling syscall.

use alloc::{
    collections::BTreeMap,
    sync::{Arc, Weak},
};
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, AtomicU8, Ordering};

use narf_capabilities::{Cap, Spend};
use narf_lib::sync::IrqSafeSpinLock;

use crate::{BudgetEligibility, BudgetView, CpuBudget, Priority, SchedClass, TaskId};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum UserPolicy {
    #[default]
    Normal,
    Batch,
    Idle,
    Fifo,
    RoundRobin,
}

impl UserPolicy {
    pub const fn is_realtime(self) -> bool {
        matches!(self, Self::Fifo | Self::RoundRobin)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UserScheduling {
    pub policy: UserPolicy,
    pub nice: i8,
    pub rt_priority: u8,
    /// Zero retains the ordinary executor slice. RR uses its CPU-time quantum.
    pub slice_cycles: u64,
}

impl UserScheduling {
    fn valid(self) -> bool {
        (-20..=19).contains(&self.nice)
            && if self.policy.is_realtime() {
                (1..=99).contains(&self.rt_priority)
                    && (self.policy != UserPolicy::RoundRobin || self.slice_cycles != 0)
            } else {
                self.rt_priority == 0
            }
    }

    pub(crate) const fn class(self) -> SchedClass {
        match self.policy {
            UserPolicy::Normal => SchedClass::Default,
            UserPolicy::Batch => SchedClass::Batch,
            UserPolicy::Idle => SchedClass::Idle,
            UserPolicy::Fifo | UserPolicy::RoundRobin => SchedClass::Realtime,
        }
    }

    pub(crate) const fn priority(self) -> Priority {
        if self.policy.is_realtime() {
            Priority(-(self.rt_priority as i8))
        } else {
            Priority(self.nice)
        }
    }
}

/// An explicit set of CPU-budget grants supplied by trusted boot code.
#[derive(Debug)]
pub struct UserSchedulingAuthority {
    budgets: [Cap<CpuBudget, Spend>; narf_lib::percpu::MAX_CPUS],
}

impl UserSchedulingAuthority {
    pub fn new(budgets: [Cap<CpuBudget, Spend>; narf_lib::percpu::MAX_CPUS]) -> Self {
        Self { budgets }
    }

    fn budget(&self, cpu: usize) -> Result<Cap<CpuBudget, Spend>, UserSchedulingError> {
        let cap = *self
            .budgets
            .get(cpu)
            .ok_or(UserSchedulingError::NoOnlineCpu)?;
        cap.check_live()
            .map_err(|_| UserSchedulingError::AuthorityRevoked)?;
        Ok(cap)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserSchedulingError {
    TaskNotFound,
    InvalidParameters,
    AuthorityRequired,
    AuthorityRevoked,
    NoOnlineCpu,
}

#[derive(Clone, Debug)]
struct Desired {
    config: UserScheduling,
    authority: Option<Arc<UserSchedulingAuthority>>,
    // A queue move is consumed once by the owning executor. Nice/authority
    // updates retain a pending move and never replay an already-applied turn.
    order: Option<i64>,
}

#[derive(Debug)]
pub(crate) struct UserControl {
    desired: IrqSafeSpinLock<Desired>,
    cell: IrqSafeSpinLock<Weak<crate::WakeCell>>,
    generation: AtomicU64,
    pub(crate) home: AtomicU32,
    pub(crate) inherited_affinity: AtomicBool,
    pub(crate) policy: AtomicU8,
    pub(crate) slice: AtomicU64,
    pub(crate) rr_remaining: AtomicU64,
    pub(crate) order: AtomicI64,
    pub(crate) blocked: AtomicBool,
    yielded: AtomicBool,
    waking: AtomicBool,
    /// Charged RT CPU time since the last genuine blocking operation.
    pub(crate) continuous_cycles: AtomicU64,
}

impl UserControl {
    fn new() -> Self {
        Self {
            desired: IrqSafeSpinLock::new(Desired {
                config: UserScheduling::default(),
                authority: None,
                order: None,
            }),
            cell: IrqSafeSpinLock::new(Weak::new()),
            generation: AtomicU64::new(1),
            home: AtomicU32::new(u32::MAX),
            inherited_affinity: AtomicBool::new(false),
            policy: AtomicU8::new(0),
            slice: AtomicU64::new(0),
            rr_remaining: AtomicU64::new(0),
            order: AtomicI64::new(0),
            blocked: AtomicBool::new(false),
            yielded: AtomicBool::new(false),
            waking: AtomicBool::new(false),
            continuous_cycles: AtomicU64::new(0),
        }
    }

    pub(crate) fn is_realtime(&self) -> bool {
        self.policy.load(Ordering::Acquire) >= UserPolicy::Fifo as u8
    }

    pub(crate) fn is_fifo(&self) -> bool {
        self.policy.load(Ordering::Acquire) == UserPolicy::Fifo as u8
    }

    pub(crate) fn mark_yield(&self) {
        if self.is_realtime() {
            self.yielded.store(true, Ordering::Release);
        }
    }

    pub(crate) fn rotate(&self) {
        self.order.store(next_tail(), Ordering::Release);
    }
}

#[derive(Debug)]
pub(crate) struct UserSlot {
    pub(crate) control: Arc<UserControl>,
    generation: u64,
    config: UserScheduling,
    authority: Option<Arc<UserSchedulingAuthority>>,
    base_cap: Option<Cap<CpuBudget, Spend>>,
}

static CONTROLS: IrqSafeSpinLock<BTreeMap<TaskId, Arc<UserControl>>> =
    IrqSafeSpinLock::new(BTreeMap::new());
static GENERATION: AtomicU64 = AtomicU64::new(1);
static SEEN: [AtomicU64; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; narf_lib::percpu::MAX_CPUS];
static NEXT_TAIL: AtomicI64 = AtomicI64::new(1);
static NEXT_HEAD: AtomicI64 = AtomicI64::new(-1);
static REQUEST: [crate::PerCpuHandoffFlag; narf_lib::percpu::MAX_CPUS] =
    [const { crate::PerCpuHandoffFlag(AtomicBool::new(false)) }; narf_lib::percpu::MAX_CPUS];

fn next_tail() -> i64 {
    NEXT_TAIL.fetch_add(1, Ordering::Relaxed)
}

/// Reserve a user-thread identity before fork/clone inheritance is published.
pub fn alloc_user_task_id() -> TaskId {
    let id = crate::alloc_task_id();
    CONTROLS.lock().insert(id, Arc::new(UserControl::new()));
    id
}

pub fn user_scheduling(id: TaskId) -> Option<UserScheduling> {
    let control = CONTROLS.lock().get(&id).cloned()?;
    let config = control.desired.lock().config;
    Some(config)
}

/// Publish validated policy atomically. The slot applies it at a safe executor
/// boundary; no queue lock, callback, or live continuation is acquired here.
pub fn set_user_scheduling(
    id: TaskId,
    config: UserScheduling,
    authority: Option<Arc<UserSchedulingAuthority>>,
) -> Result<(), UserSchedulingError> {
    publish(id, config, authority, true, None)
}

/// Inherit a parent's existing authority before making a child runnable.
/// Revocation remains attached to the grant and is enforced at dispatch.
pub fn inherit_user_scheduling(
    parent: TaskId,
    child: TaskId,
    config: UserScheduling,
) -> Result<(), UserSchedulingError> {
    let control = CONTROLS.lock().get(&parent).cloned();
    let authority = control
        .as_ref()
        .and_then(|control| control.desired.lock().authority.clone());
    if config.policy.is_realtime() && control.is_none() {
        return Err(UserSchedulingError::TaskNotFound);
    }
    publish(
        child,
        config,
        authority,
        false,
        Some(crate::inheritable_task_affinity(parent).is_some()),
    )
}

fn publish(
    id: TaskId,
    config: UserScheduling,
    authority: Option<Arc<UserSchedulingAuthority>>,
    validate_grants: bool,
    inherited_affinity: Option<bool>,
) -> Result<(), UserSchedulingError> {
    if !config.valid() {
        return Err(UserSchedulingError::InvalidParameters);
    }
    let control = CONTROLS
        .lock()
        .get(&id)
        .cloned()
        .ok_or(UserSchedulingError::TaskNotFound)?;
    if config.policy.is_realtime() {
        let grant = authority
            .as_ref()
            .ok_or(UserSchedulingError::AuthorityRequired)?;
        let cpus = crate::task_affinity(id)
            .unwrap_or_else(crate::online_cpu_set)
            .intersection(crate::online_cpu_set());
        if cpus.is_empty() {
            return Err(UserSchedulingError::NoOnlineCpu);
        }
        if validate_grants {
            for cpu in 0..narf_lib::percpu::MAX_CPUS {
                if cpus.contains(crate::CpuId(cpu as u32)) {
                    grant.budget(cpu)?;
                }
            }
        }
    }
    {
        let mut desired = control.desired.lock();
        if let Some(inherited) = inherited_affinity {
            control
                .inherited_affinity
                .store(inherited, Ordering::Release);
        }
        let same_authority = match (&desired.authority, &authority) {
            (Some(old), Some(new)) => Arc::ptr_eq(old, new),
            (None, None) => true,
            _ => false,
        };
        if desired.config == config
            && same_authority
            && control.generation.load(Ordering::Relaxed) != 1
        {
            return Ok(());
        }
        let lowered = desired.config.policy.is_realtime()
            && config.policy.is_realtime()
            && config.rt_priority < desired.config.rt_priority;
        let same_rt_priority = desired.config.policy.is_realtime()
            && config.policy.is_realtime()
            && desired.config.rt_priority == config.rt_priority;
        let order = if same_rt_priority {
            desired.order
        } else if lowered {
            Some(NEXT_HEAD.fetch_sub(1, Ordering::Relaxed))
        } else {
            Some(next_tail())
        };
        *desired = Desired {
            config,
            authority,
            order,
        };
        control.generation.fetch_add(1, Ordering::Release);
    }
    if let Some(cell) = control.cell.lock().upgrade() {
        cell.user_rt
            .store(config.policy.is_realtime(), Ordering::Release);
        cell.direct_eligible.store(false, Ordering::Release);
    }
    GENERATION.fetch_add(1, Ordering::Release);
    let cpu = control.home.load(Ordering::Acquire) as usize;
    if cpu < REQUEST.len() {
        REQUEST[cpu].store(true, Ordering::Release);
        if cpu == narf_lib::percpu::current_cpu() {
            crate::resched_current();
        } else {
            crate::resched_remote_force(cpu as u32);
        }
    }
    Ok(())
}

pub fn yield_user_scheduling(id: TaskId) {
    if let Some(control) = CONTROLS.lock().get(&id) {
        control.mark_yield();
    }
}

pub(crate) fn request_pending(cpu: usize) -> bool {
    REQUEST
        .get(cpu)
        .is_some_and(|request| request.load(Ordering::Acquire))
}

pub(crate) fn up_to_date(slot: &crate::TaskSlot) -> bool {
    slot.user_scheduling
        .as_ref()
        .is_none_or(|u| u.generation == u.control.generation.load(Ordering::Acquire))
}

pub(crate) fn take_request(cpu: usize) -> bool {
    REQUEST.get(cpu).is_some_and(|request| {
        request.load(Ordering::Acquire) && request.swap(false, Ordering::AcqRel)
    })
}

pub(crate) fn attach(id: TaskId, base_cap: Option<Cap<CpuBudget, Spend>>) -> UserSlot {
    let control = CONTROLS
        .lock()
        .entry(id)
        .or_insert_with(|| Arc::new(UserControl::new()))
        .clone();
    let generation = if control.generation.load(Ordering::Acquire) == 1 {
        1
    } else {
        0
    };
    UserSlot {
        control,
        generation,
        config: UserScheduling::default(),
        authority: None,
        base_cap,
    }
}

pub(crate) fn bind(user: &UserSlot, cell: &Arc<crate::WakeCell>) {
    let desired = user.control.desired.lock();
    cell.user_rt
        .store(desired.config.policy.is_realtime(), Ordering::Release);
    *user.control.cell.lock() = Arc::downgrade(cell);
}

pub(crate) fn note_rt_wake(cell: &crate::WakeCell, cpu: u32) {
    if !cell.user_rt.load(Ordering::Acquire)
        || crate::current_task_id_on(cpu as usize).raw() == cell.task
    {
        return;
    }
    if let Some(request) = REQUEST.get(cpu as usize) {
        request.store(true, Ordering::Release);
        if cpu as usize == narf_lib::percpu::current_cpu() {
            crate::resched_current();
        } else {
            crate::resched_remote_force(cpu);
        }
    }
}

pub fn release_user_scheduling(id: TaskId) {
    CONTROLS.lock().remove(&id);
}

pub(crate) fn refresh(slot: &mut crate::TaskSlot, cpu: usize) {
    let Some(user) = slot.user_scheduling.as_mut() else {
        return;
    };
    let previous = user.control.home.load(Ordering::Relaxed);
    if previous != cpu as u32 {
        user.control.home.store(cpu as u32, Ordering::Release);
    }
    let generation = user.control.generation.load(Ordering::Acquire);
    let refreshed = user.generation != generation;
    if refreshed {
        let (desired, generation) = {
            let mut desired = user.control.desired.lock();
            let snapshot = desired.clone();
            desired.order = None;
            (snapshot, user.control.generation.load(Ordering::Relaxed))
        };
        let slice_changed = user.config.slice_cycles != desired.config.slice_cycles;
        let changed = user.config.policy != desired.config.policy;
        if let Some(order) = desired.order {
            user.control.order.store(order, Ordering::Release);
        }
        user.config = desired.config;
        user.authority = desired.authority;
        slot.spec.class = user.config.class();
        slot.spec.priority = user.config.priority();
        slot.spec.budget_cap = if user.config.policy.is_realtime() {
            user.authority
                .as_ref()
                .and_then(|grant| grant.budgets.get(cpu).copied())
        } else {
            user.base_cap
        };
        // A grant revoked during publication must never become uncapped RT.
        assert!(
            !user.config.policy.is_realtime() || slot.spec.budget_cap.is_some(),
            "RT without delegated CPU grant"
        );
        user.control
            .policy
            .store(user.config.policy as u8, Ordering::Release);
        user.control
            .slice
            .store(user.config.slice_cycles, Ordering::Release);
        if changed {
            user.control
                .rr_remaining
                .store(user.config.slice_cycles, Ordering::Release);
        } else if slice_changed && user.config.policy == UserPolicy::RoundRobin {
            let left = user.control.rr_remaining.load(Ordering::Relaxed);
            user.control
                .rr_remaining
                .store(left.min(user.config.slice_cycles), Ordering::Release);
        }
        user.generation = generation;
        let ordinary = slot.spec.class == SchedClass::Default
            && slot.spec.priority == Priority::NORMAL
            && slot.spec.budget == crate::ResourceBudget::unthrottled()
            && slot.spec.budget_cap.is_none();
        slot.awake
            .direct_eligible
            .store(ordinary, Ordering::Release);
    } else if user.config.policy.is_realtime() {
        // Affinity migration changes which explicit CPU grant is spent.
        slot.spec.budget_cap = user
            .authority
            .as_ref()
            .and_then(|grant| grant.budgets.get(cpu).copied());
    }
    if user.control.is_realtime() && slot.awake.executor_runnable() {
        let waking = user.control.waking.swap(false, Ordering::AcqRel);
        if (previous != u32::MAX && previous != cpu as u32) || waking {
            user.control.rotate();
        }
    }
    if refreshed {
        crate::publish_possible_class(cpu, slot.spec.class.rank());
        crate::publish_class_fifo_shape(cpu, slot);
    }
}

pub(crate) fn refresh_queue(cpu: usize, queue: &mut alloc::collections::VecDeque<crate::TaskSlot>) {
    let _ = take_request(cpu);
    let generation = GENERATION.load(Ordering::Acquire);
    if SEEN[cpu].load(Ordering::Relaxed) != generation {
        for slot in queue {
            refresh(slot, cpu);
        }
        SEEN[cpu].store(generation, Ordering::Relaxed);
    }
}

pub(crate) fn order(slot: &crate::TaskSlot) -> i64 {
    slot.user_scheduling
        .as_ref()
        .filter(|u| u.config.policy.is_realtime())
        .map_or(0, |u| u.control.order.load(Ordering::Acquire))
}

pub(crate) fn after_dispatch(slot: &crate::TaskSlot, cycles: u64) {
    let Some(user) = slot.user_scheduling.as_ref() else {
        return;
    };
    if !user.config.policy.is_realtime() {
        return;
    }
    let control = &user.control;
    let yielded = control.yielded.swap(false, Ordering::AcqRel);
    let blocked = control.blocked.swap(false, Ordering::AcqRel);
    if user.config.policy.is_realtime() {
        control
            .continuous_cycles
            .fetch_add(cycles, Ordering::Relaxed);
        if user.config.policy == UserPolicy::RoundRobin {
            let remaining = control.rr_remaining.load(Ordering::Relaxed);
            if cycles >= remaining {
                control
                    .rr_remaining
                    .store(user.config.slice_cycles, Ordering::Release);
                control.rotate();
            } else {
                control
                    .rr_remaining
                    .store(remaining - cycles, Ordering::Release);
            }
        }
        if yielded {
            control.rotate();
        }
        if blocked {
            control.waking.store(true, Ordering::Release);
            control.continuous_cycles.store(0, Ordering::Release);
        }
    }
}

#[derive(Clone, Copy)]
struct RtAccount {
    end: u64,
    spent: u64,
}
#[repr(align(64))]
struct RtCpu(IrqSafeSpinLock<RtAccount>);
static RT_CPU: [RtCpu; narf_lib::percpu::MAX_CPUS] =
    [const { RtCpu(IrqSafeSpinLock::new(RtAccount { end: 0, spent: 0 })) };
        narf_lib::percpu::MAX_CPUS];

fn projected(account: RtAccount, cpu: usize, now: u64) -> (RtAccount, u64) {
    let period = narf_time::ns_to_cycles(1_000_000_000).max(1);
    let available = crate::RT_CPU_LIMIT_PPM
        .saturating_sub(crate::realtime_bandwidth(crate::CpuId(cpu as u32)).cpu_reserved_ppm);
    let capacity = ((period as u128 * available as u128) / 1_000_000) as u64;
    let mut account = account;
    if account.end == 0 {
        account.end = (now / period).saturating_add(1).saturating_mul(period);
    } else if now >= account.end {
        let periods = (now - account.end) / period + 1;
        account.spent = account
            .spent
            .saturating_sub(capacity.saturating_mul(periods));
        account.end = account.end.saturating_add(period.saturating_mul(periods));
    }
    (account, capacity)
}

pub(crate) fn rt_view(cpu: usize, now: u64) -> BudgetView {
    let (account, capacity) = projected(*RT_CPU[cpu].0.lock(), cpu, now);
    let remaining = capacity.saturating_sub(account.spent);
    BudgetView {
        eligibility: if remaining == 0 {
            BudgetEligibility::Throttled
        } else {
            BudgetEligibility::Eligible
        },
        remaining_cycles: remaining,
        replenish_at_cycles: Some(account.end),
        borrowed_cycles: 0,
        debt_cycles: account.spent.saturating_sub(capacity),
    }
}

pub(crate) fn begin(slot: &crate::TaskSlot, cpu: usize, now: u64) -> Option<BudgetView> {
    let user = slot.user_scheduling.as_ref()?;
    if !user.config.policy.is_realtime() {
        return None;
    }
    let mut account = RT_CPU[cpu].0.lock();
    *account = projected(*account, cpu, now).0;
    drop(account);
    Some(rt_view(cpu, now))
}

pub(crate) fn charge(slot: &crate::TaskSlot, cpu: usize, cycles: u64) {
    if slot
        .user_scheduling
        .as_ref()
        .is_some_and(|u| u.config.policy.is_realtime())
    {
        let mut account = RT_CPU[cpu].0.lock();
        account.spent = account.spent.saturating_add(cycles);
    }
    after_dispatch(slot, cycles);
}

/// Linux policy changes cannot withdraw the native budget's revocation gate.
pub(crate) fn authority_live(slot: &crate::TaskSlot) -> bool {
    slot.spec
        .budget_cap
        .as_ref()
        .is_none_or(|cap| cap.check_live().is_ok())
        && slot
            .user_scheduling
            .as_ref()
            .and_then(|user| user.base_cap.as_ref())
            .is_none_or(|cap| cap.check_live().is_ok())
}

pub(crate) fn budget_view(slot: &crate::TaskSlot, now: u64) -> BudgetView {
    let native = slot.account.view(now, &slot.spec.budget);
    if slot
        .user_scheduling
        .as_ref()
        .is_some_and(|u| u.config.policy.is_realtime())
    {
        let cpu = slot.awake.cpu.load(Ordering::Acquire) as usize;
        let rt = rt_view(cpu.min(RT_CPU.len() - 1), now);
        if rt.eligibility == BudgetEligibility::Throttled
            || rt.remaining_cycles < native.remaining_cycles
        {
            return rt;
        }
    }
    native
}

pub(crate) fn reset_for_test() {
    CONTROLS.lock().clear();
    for cpu in 0..RT_CPU.len() {
        *RT_CPU[cpu].0.lock() = RtAccount { end: 0, spent: 0 };
        SEEN[cpu].store(0, Ordering::Relaxed);
        REQUEST[cpu].store(false, Ordering::Relaxed);
    }
    GENERATION.fetch_add(1, Ordering::Release);
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use crate::{Affinity, CpuId, TaskSpec};
    use alloc::{boxed::Box, collections::VecDeque};
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn authority() -> Arc<UserSchedulingAuthority> {
        Arc::new(UserSchedulingAuthority::new(core::array::from_fn(|_| {
            Cap::bootstrap()
        })))
    }

    fn slot() -> crate::TaskSlot {
        let id = alloc_user_task_id();
        let cpu = narf_lib::percpu::current_cpu();
        let spec = TaskSpec {
            affinity: Affinity::pinned(CpuId(cpu as u32)),
            ..TaskSpec::default()
        };
        let affinity_generation = crate::register_task_affinity(id, spec.affinity, false);
        crate::TaskSlot {
            user_scheduling: Some(attach(id, None)),
            dispatch_reason: crate::DispatchReason::Policy,
            task: Box::pin(core::future::pending()),
            awake: crate::new_wake_cell(id, cpu as u32, true),
            id,
            spec,
            // Policy-fixture slot: an unregistered table. Policy
            // tests never resolve caps; the registry path is covered
            // by the scheduler's own spawn-path fixtures.
            authority: Arc::new(crate::CallerAuthority::prepared(
                id,
                narf_lib::id::DomainId::FRAME,
            )),
            affinity_generation,
            addr_space: None,
            account: crate::BudgetAccount::new(),
            donation: None,
            domain_saved: None,
            rt_reservation: None,
            nproc_guard: None,
            vruntime: 0,
        }
    }

    fn configure(
        slot: &crate::TaskSlot,
        policy: UserPolicy,
        priority: u8,
        grant: &Arc<UserSchedulingAuthority>,
    ) {
        set_user_scheduling(
            slot.id,
            UserScheduling {
                policy,
                rt_priority: priority,
                slice_cycles: 1000,
                nice: 0,
            },
            Some(grant.clone()),
        )
        .unwrap();
    }

    fn pick(queue: &mut VecDeque<crate::TaskSlot>) -> crate::TaskSlot {
        crate::policy::pick_next_slot(
            Some(&crate::ClassScheduler),
            CpuId(narf_lib::percpu::current_cpu() as u32),
            queue,
        )
        .unwrap()
        .1
    }

    fn smoke_user_rt_fifo_retains_position_and_yield_rotates() -> TestResult {
        crate::__reset_queues_for_test();
        let grant = authority();
        let a = slot();
        let b = slot();
        let ordinary = slot();
        configure(&a, UserPolicy::Fifo, 60, &grant);
        configure(&b, UserPolicy::Fifo, 60, &grant);
        let aid = a.id;
        let bid = b.id;
        let mut q = VecDeque::from([ordinary, b, a]);
        let a = pick(&mut q);
        if a.id != aid {
            return TestResult::Fail("FIFO admission order lost to physical queue order");
        }
        after_dispatch(&a, 100);
        q.push_back(a);
        let a = pick(&mut q);
        if a.id != aid {
            return TestResult::Fail("involuntary FIFO preemption rotated equal peers");
        }
        yield_user_scheduling(aid);
        after_dispatch(&a, 100);
        q.push_back(a);
        if pick(&mut q).id != bid {
            return TestResult::Fail("sched_yield did not rotate FIFO");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "scheduler/user_policy",
        smoke_user_rt_fifo_retains_position_and_yield_rotates
    );

    fn smoke_user_rr_carries_quantum_across_preemption_and_block() -> TestResult {
        crate::__reset_queues_for_test();
        let grant = authority();
        let a = slot();
        let b = slot();
        configure(&a, UserPolicy::RoundRobin, 50, &grant);
        configure(&b, UserPolicy::RoundRobin, 50, &grant);
        let aid = a.id;
        let bid = b.id;
        let mut q = VecDeque::from([a, b]);
        let mut a = pick(&mut q);
        after_dispatch(&a, 400);
        let control = a.user_scheduling.as_ref().unwrap().control.clone();
        control.blocked.store(true, Ordering::Release);
        after_dispatch(&a, 100);
        refresh(&mut a, narf_lib::percpu::current_cpu());
        if control.rr_remaining.load(Ordering::Acquire) != 500
            || control.continuous_cycles.load(Ordering::Relaxed) != 0
        {
            return TestResult::Fail("blocking refilled RR or retained RT watchdog time");
        }
        q.push_back(a);
        let b = pick(&mut q);
        if b.id != bid {
            return TestResult::Fail("woken RR did not join tail");
        }
        after_dispatch(&b, 1000);
        q.push_back(b);
        let a = pick(&mut q);
        if a.id != aid {
            return TestResult::Fail("RR expiry did not rotate");
        }
        yield_user_scheduling(aid);
        after_dispatch(&a, 50);
        if control.rr_remaining.load(Ordering::Acquire) != 450
            || control.continuous_cycles.load(Ordering::Relaxed) != 50
        {
            return TestResult::Fail("sched_yield refunded RR or RT watchdog time");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "scheduler/user_policy",
        smoke_user_rr_carries_quantum_across_preemption_and_block
    );

    fn smoke_user_rt_priority_change_and_external_policy_guard() -> TestResult {
        crate::__reset_queues_for_test();
        let grant = authority();
        let a = slot();
        let b = slot();
        let c = slot();
        configure(&a, UserPolicy::Fifo, 70, &grant);
        configure(&b, UserPolicy::Fifo, 60, &grant);
        configure(&c, UserPolicy::Fifo, 60, &grant);
        let aid = a.id;
        let mut q = VecDeque::from([b, c, a]);
        // Even an ordinary FIFO policy must preserve the live RT contract.
        let cpu = CpuId(narf_lib::percpu::current_cpu() as u32);
        let a = crate::policy::pick_next_slot(Some(&crate::FifoScheduler), cpu, &mut q)
            .unwrap()
            .1;
        if a.id != aid {
            return TestResult::Fail("external policy bypassed RT priority");
        }
        configure(&a, UserPolicy::Fifo, 60, &grant);
        q.push_back(a);
        if pick(&mut q).id != aid {
            return TestResult::Fail("lowered RT priority did not join head of its new queue");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "scheduler/user_policy",
        smoke_user_rt_priority_change_and_external_policy_guard
    );

    fn smoke_user_rt_shared_throttle_survives_thread_churn() -> TestResult {
        crate::__reset_queues_for_test();
        let grant = authority();
        let mut a = slot();
        configure(&a, UserPolicy::Fifo, 60, &grant);
        let cpu = narf_lib::percpu::current_cpu();
        refresh(&mut a, cpu);
        let now = narf_time::now_cycles();
        let initial = begin(&a, cpu, now).unwrap();
        charge(&a, cpu, initial.remaining_cycles.saturating_add(7));
        drop(a);
        let mut b = slot();
        configure(&b, UserPolicy::Fifo, 60, &grant);
        refresh(&mut b, cpu);
        if budget_view(&b, now).eligibility != BudgetEligibility::Throttled {
            return TestResult::Fail("thread churn refilled the shared RT pool");
        }
        let next = rt_view(cpu, initial.replenish_at_cycles.unwrap());
        if next.remaining_cycles != initial.remaining_cycles.saturating_sub(7)
            || next.debt_cycles != 0
        {
            return TestResult::Fail("RT replenishment lost overshoot debt");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "scheduler/user_policy",
        smoke_user_rt_shared_throttle_survives_thread_churn
    );

    fn smoke_user_policy_updates_are_live_and_failed_updates_atomic() -> TestResult {
        crate::__reset_queues_for_test();
        let mut a = slot();
        let cpu = narf_lib::percpu::current_cpu();
        let ordinary = UserScheduling {
            policy: UserPolicy::Batch,
            nice: 7,
            ..Default::default()
        };
        set_user_scheduling(a.id, ordinary, None).unwrap();
        if crate::direct_handoff_slot_eligible(&a, CpuId(cpu as u32)) {
            return TestResult::Fail("pending policy update allowed direct transfer");
        }
        refresh(&mut a, cpu);
        if a.spec.class != SchedClass::Batch || a.spec.priority != Priority(7) {
            return TestResult::Fail("normal policy/nice update did not reach slot");
        }
        let rt = UserScheduling {
            policy: UserPolicy::Fifo,
            rt_priority: 50,
            ..Default::default()
        };
        if set_user_scheduling(a.id, rt, None) != Err(UserSchedulingError::AuthorityRequired)
            || user_scheduling(a.id) != Some(ordinary)
        {
            return TestResult::Fail("failed RT request changed live state");
        }
        let grant = authority();
        configure(&a, UserPolicy::Fifo, 50, &grant);
        refresh(&mut a, cpu);
        let child = slot();
        inherit_user_scheduling(a.id, child.id, user_scheduling(a.id).unwrap()).unwrap();
        let mut child = child;
        refresh(&mut child, cpu);
        if child.spec.class != SchedClass::Realtime || child.spec.budget_cap.is_none() {
            return TestResult::Fail("fork did not inherit actual RT authority");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "scheduler/user_policy",
        smoke_user_policy_updates_are_live_and_failed_updates_atomic
    );
    fn smoke_user_rt_revocation_never_becomes_uncapped_service() -> TestResult {
        crate::__reset_queues_for_test();
        let grant = authority();
        let mut a = slot();
        let cpu = narf_lib::percpu::current_cpu();
        configure(&a, UserPolicy::Fifo, 60, &grant);
        grant.budgets[cpu].revoke();
        refresh(&mut a, cpu);
        if a.spec.class != SchedClass::Realtime
            || a.spec.budget_cap.is_none_or(|cap| cap.check_live().is_ok())
        {
            return TestResult::Fail("revocation lost the mandatory dispatch cap check");
        }
        let child = slot();
        inherit_user_scheduling(a.id, child.id, user_scheduling(a.id).unwrap()).unwrap();
        let mut child = child;
        refresh(&mut child, cpu);
        if child
            .spec
            .budget_cap
            .is_none_or(|cap| cap.check_live().is_ok())
        {
            return TestResult::Fail("fork resurrected a revoked RT grant");
        }
        let old = user_scheduling(a.id);
        if set_user_scheduling(
            a.id,
            UserScheduling {
                policy: UserPolicy::Fifo,
                rt_priority: 70,
                ..Default::default()
            },
            Some(grant),
        ) != Err(UserSchedulingError::AuthorityRevoked)
            || user_scheduling(a.id) != old
        {
            return TestResult::Fail("revoked setter changed configuration");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "scheduler/user_policy",
        smoke_user_rt_revocation_never_becomes_uncapped_service
    );
    fn smoke_user_rt_owned_wake_requests_prompt_preemption() -> TestResult {
        crate::__reset_queues_for_test();
        let grant = authority();
        let mut a = slot();
        let cpu = narf_lib::percpu::current_cpu();
        bind(a.user_scheduling.as_ref().unwrap(), &a.awake);
        configure(&a, UserPolicy::Fifo, 60, &grant);
        refresh(&mut a, cpu);
        let _ = take_request(cpu);
        a.awake.flag.store(false, Ordering::Release);
        crate::make_waker(a.awake.clone()).wake();
        if !request_pending(cpu) {
            return TestResult::Fail("owned RT wake lost its reschedule request");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "scheduler/user_policy",
        smoke_user_rt_owned_wake_requests_prompt_preemption
    );
    fn smoke_user_rt_nice_and_authority_updates_preserve_position() -> TestResult {
        crate::__reset_queues_for_test();
        let grant = authority();
        let mut a = slot();
        let cpu = narf_lib::percpu::current_cpu();
        configure(&a, UserPolicy::RoundRobin, 60, &grant);
        set_user_scheduling(
            a.id,
            UserScheduling {
                nice: 3,
                ..user_scheduling(a.id).unwrap()
            },
            Some(grant.clone()),
        )
        .unwrap();
        refresh(&mut a, cpu);
        if order(&a) <= 0 {
            return TestResult::Fail("nice update lost a pending RT queue move");
        }
        a.user_scheduling.as_ref().unwrap().control.rotate();
        let turn = order(&a);
        let config = UserScheduling {
            nice: 5,
            ..user_scheduling(a.id).unwrap()
        };
        set_user_scheduling(a.id, config, Some(grant)).unwrap();
        refresh(&mut a, cpu);
        if order(&a) != turn {
            return TestResult::Fail("RT nice update rewound its FIFO position");
        }
        let replacement = authority();
        set_user_scheduling(a.id, config, Some(replacement.clone())).unwrap();
        refresh(&mut a, cpu);
        if order(&a) != turn
            || a.spec.budget_cap.map(|cap| cap.slot()) != Some(replacement.budgets[cpu].slot())
        {
            return TestResult::Fail("replacement authority was ignored or reordered RT");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "scheduler/user_policy",
        smoke_user_rt_nice_and_authority_updates_preserve_position
    );
    fn smoke_user_policy_preserves_native_budget_authority() -> TestResult {
        crate::__reset_queues_for_test();
        let mut a = slot();
        let cpu = narf_lib::percpu::current_cpu();
        let base = Cap::<CpuBudget, Spend>::bootstrap();
        a.spec.budget_cap = Some(base);
        a.user_scheduling.as_mut().unwrap().base_cap = Some(base);
        set_user_scheduling(
            a.id,
            UserScheduling {
                nice: 5,
                ..Default::default()
            },
            None,
        )
        .unwrap();
        refresh(&mut a, cpu);
        if a.spec.budget_cap.map(|cap| cap.slot()) != Some(base.slot()) {
            return TestResult::Fail("nice change discarded native budget authority");
        }
        let grant = authority();
        configure(&a, UserPolicy::Fifo, 60, &grant);
        refresh(&mut a, cpu);
        base.revoke();
        if authority_live(&a) {
            return TestResult::Fail("RT grant bypassed revoked native budget");
        }
        set_user_scheduling(a.id, UserScheduling::default(), None).unwrap();
        refresh(&mut a, cpu);
        if authority_live(&a) || a.spec.budget_cap.is_none() {
            return TestResult::Fail("demotion discarded native revocation gate");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "scheduler/user_policy",
        smoke_user_policy_preserves_native_budget_authority
    );
    fn smoke_user_affinity_inherits_requests_without_boot_placement_pins() -> TestResult {
        crate::__reset_queues_for_test();
        let parent = slot();
        let cpu = narf_lib::percpu::current_cpu();
        let pin = crate::CpuSet::single(crate::CpuId(cpu as u32));
        if crate::inheritable_task_affinity(parent.id).is_some() {
            return TestResult::Fail("native boot placement became a Linux family constraint");
        }
        if crate::set_task_affinity(parent.id, pin).is_err()
            || crate::inheritable_task_affinity(parent.id) != Some(pin)
        {
            return TestResult::Fail("explicit affinity was not inheritable");
        }
        let mut child = slot();
        inherit_user_scheduling(parent.id, child.id, UserScheduling::default()).unwrap();
        let inherited = child
            .user_scheduling
            .as_ref()
            .unwrap()
            .control
            .inherited_affinity
            .load(Ordering::Acquire);
        child.affinity_generation = crate::register_task_affinity_with_inheritance(
            child.id,
            child.spec.affinity,
            false,
            inherited,
        );
        if crate::inheritable_task_affinity(child.id) != Some(pin) {
            return TestResult::Fail("inherited CPU request was lost for grandchildren");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "scheduler/user_policy",
        smoke_user_affinity_inherits_requests_without_boot_placement_pins
    );
}
