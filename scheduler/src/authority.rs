//! Task-owned caller authority. Identity lookup is a control-path operation;
//! dispatch borrows an already bound owner and never searches the task index.

use alloc::{
    collections::BTreeMap,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use core::task::{Context, Waker};
use narf_capabilities::{Cap, CapError, CapSlot, CapTable, CapType, Grant, Rights};
use narf_lib::{id::DomainId, sync::IrqSafeSpinLock};

use crate::TaskId;

const DOMAIN_MASK: u64 = 0xff;
const LIVE: u64 = 1 << 8;
const RETIRED: u64 = 1 << 9;
const IMAGE_STEP: u64 = 1 << 10;

/// Shared logical domain and admission state. Hardware trap neutralization is
/// separate: entering FRAME to service a trap does not replace its subject.
#[derive(Debug)]
pub(crate) struct DomainState(AtomicU64);

impl DomainState {
    pub(crate) fn new(domain: DomainId, live: bool) -> Self {
        Self(AtomicU64::new(
            IMAGE_STEP | u64::from(domain.raw()) | if live { LIVE } else { 0 },
        ))
    }

    #[inline]
    pub(crate) fn load(&self, order: Ordering) -> u8 {
        (self.0.load(order) & DOMAIN_MASK) as u8
    }

    /// Preserve terminal admission bits when a suspended scope restores its
    /// domain after a concurrent retirement. Ordinary switches usually do not
    /// change the value and need no atomic read/modify/write.
    pub(crate) fn store(&self, domain: u8, order: Ordering) {
        assert!(domain < 16, "invalid logical domain");
        let mut old = self.0.load(Ordering::Acquire);
        loop {
            let new = (old & !DOMAIN_MASK) | u64::from(domain);
            if new == old {
                return;
            }
            match self
                .0
                .compare_exchange_weak(old, new, order, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(observed) => old = observed,
            }
        }
    }
}

/// A bound submitting task's authority, retained by task state and dispatchers.
/// The Arc proves storage lifetime; the admission word proves current liveness.
#[derive(Debug)]
pub struct CallerAuthority {
    id: TaskId,
    pub(crate) domain: Arc<DomainState>,
    caps: IrqSafeSpinLock<CapTable>,
    watchers: IrqSafeSpinLock<Vec<Weak<AuthorityWatch>>>,
}

impl CallerAuthority {
    pub(crate) fn prepared(id: TaskId, domain: DomainId) -> Self {
        Self {
            id,
            domain: Arc::new(DomainState::new(domain, false)),
            caps: IrqSafeSpinLock::new(CapTable::new()),
            watchers: IrqSafeSpinLock::new(Vec::new()),
        }
    }

    pub const fn task_id(&self) -> TaskId {
        self.id
    }

    /// Current execution-image generation, or Revoked after retirement/before
    /// publication. One acquire read; no registry, lock, or refcount traffic.
    #[inline]
    pub fn image(&self) -> Result<u64, CapError> {
        let state = self.domain.0.load(Ordering::Acquire);
        if state & (LIVE | RETIRED) != LIVE {
            return Err(CapError::Revoked);
        }
        Ok(state / IMAGE_STEP)
    }

    /// Check the same live image and read its logical domain coherently.
    #[inline]
    pub fn domain_for_image(&self, image: u64) -> Result<DomainId, CapError> {
        let state = self.domain.0.load(Ordering::Acquire);
        if state & (LIVE | RETIRED) != LIVE || state / IMAGE_STEP != image {
            return Err(CapError::Revoked);
        }
        Ok(DomainId::new((state & DOMAIN_MASK) as u8))
    }

    pub fn lookup(&self, presented: CapSlot) -> Result<CapSlot, CapError> {
        self.image()?;
        self.caps.lock().lookup(presented)
    }

    /// Resolve the fixed wire cap array under this owner's table lock only.
    /// Empty-cap operations never enter a cap-table critical section.
    pub fn validate_caps(&self, caps: &[CapSlot; 4]) -> Result<(), CapError> {
        if caps.iter().all(CapSlot::is_empty) {
            return Ok(());
        }
        self.image()?;
        let table = self.caps.lock();
        for cap in caps.iter().filter(|cap| !cap.is_empty()) {
            table.lookup(*cap)?;
        }
        Ok(())
    }

    pub fn install_bootstrap<T: CapType, R: Rights>(
        &self,
        cap: &Cap<T, R>,
    ) -> Result<u32, CapError> {
        let table = &mut *self.caps.lock();
        if self.domain.0.load(Ordering::Acquire) & RETIRED != 0 {
            return Err(CapError::Revoked);
        }
        table.install_bootstrap(cap)
    }

    pub fn transfer_to(
        &self,
        receiver: &Self,
        grant: CapSlot,
        cap: CapSlot,
    ) -> Result<u32, CapError> {
        if grant.rights & Grant::BITS == 0 {
            return Err(CapError::RightsTooWeak);
        }
        self.image()?;
        let (grant, cap) = {
            let table = self.caps.lock();
            (table.lookup(grant)?, table.lookup(cap)?)
        };
        let table = &mut *receiver.caps.lock();
        receiver.image()?;
        table.install_transfer(grant, cap)
    }

    /// Stop new admission before exit/reap. Existing owners can finish their
    /// cancellation protocol but cannot use retained memory as a live grant.
    pub(crate) fn retire(&self) {
        if self.domain.0.fetch_or(RETIRED, Ordering::AcqRel) & RETIRED == 0 {
            self.notify_dispatchers();
        }
    }

    /// Register a wait endpoint once at dispatcher binding. Only weak edges
    /// point from authority to workers, so closure cannot form a task cycle.
    pub fn watch(&self) -> Arc<AuthorityWatch> {
        let watch = Arc::new(AuthorityWatch {
            waker: IrqSafeSpinLock::new(None),
        });
        let mut watchers = self.watchers.lock();
        watchers.retain(|w| w.strong_count() != 0);
        watchers.push(Arc::downgrade(&watch));
        watch
    }

    pub fn notify_dispatchers(&self) {
        let watchers = self.watchers.lock().clone();
        for watch in watchers.iter().filter_map(Weak::upgrade) {
            watch.wake();
        }
    }

    /// Successful exec invalidates sessions from the previous image. Overflow
    /// permanently retires the context instead of making an old binding live.
    pub(crate) fn replace_image(&self) {
        let _ = self
            .domain
            .0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                Some(old.checked_add(IMAGE_STEP).unwrap_or(old | RETIRED))
            });
        self.notify_dispatchers();
    }

    pub(crate) fn publish(&self) {
        let old = self.domain.0.fetch_or(LIVE, Ordering::Release);
        assert_eq!(
            old & (LIVE | RETIRED),
            0,
            "authority published twice or after retirement"
        );
    }
}

/// Unique task-creation/lifecycle control. Dispatcher handles cannot change
/// image identity or liveness. The scheduler separately owns final retirement.
#[derive(Debug)]
pub struct AuthorityControl {
    owner: Arc<CallerAuthority>,
}
impl AuthorityControl {
    pub fn retire(&self) {
        self.owner.retire();
    }
    pub fn replace_image(&self) {
        self.owner.replace_image();
    }
}

/// Create the authority and its lifecycle control together before publishing
/// either. A control token can never be obtained from an existing read handle.
pub fn create_user_authority(
    id: TaskId,
) -> Result<(Arc<CallerAuthority>, AuthorityControl), CapError> {
    let owner = Arc::new(CallerAuthority::prepared(id, DomainId::USERSPACE_K));
    let mut owners = OWNERS.lock();
    if owners.contains_key(&id) {
        return Err(CapError::Revoked);
    }
    let control = AuthorityControl {
        owner: owner.clone(),
    };
    owners.insert(id, owner.clone());
    Ok((owner, control))
}

#[cfg(feature = "kernel-test")]
impl CallerAuthority {
    pub fn __retire_for_test(&self) {
        self.retire();
    }
    pub fn __replace_image_for_test(&self) {
        self.replace_image();
    }
}

/// Retirement/image-change notification. The registration is cold; the gate
/// itself never locks this cell. Queue waiters arm then recheck admission.
#[derive(Debug)]
pub struct AuthorityWatch {
    waker: IrqSafeSpinLock<Option<Waker>>,
}
impl AuthorityWatch {
    pub fn register(&self, cx: &Context<'_>) {
        let mut waker = self.waker.lock();
        if !waker.as_ref().is_some_and(|w| w.will_wake(cx.waker())) {
            *waker = Some(cx.waker().clone());
        }
    }
    fn wake(&self) {
        let waker = self.waker.lock().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

// Existing cross-task installation/transfer APIs need an administrative index.
// It is never consulted by the bound caller-validation path.
static OWNERS: IrqSafeSpinLock<BTreeMap<TaskId, Arc<CallerAuthority>>> =
    IrqSafeSpinLock::new(BTreeMap::new());

/// Prepare a user task before constructing its future. Spawn consumes this
/// same owner; compatibility task preparation does not create native grants.
pub fn prepare_user_authority(id: TaskId) -> Arc<CallerAuthority> {
    prepare(id, DomainId::USERSPACE_K)
}

pub(crate) fn prepare(id: TaskId, domain: DomainId) -> Arc<CallerAuthority> {
    let mut owners = OWNERS.lock();
    if let Some(owner) = owners.get(&id) {
        return owner.clone();
    }
    let owner = Arc::new(CallerAuthority::prepared(id, domain));
    owners.insert(id, owner.clone());
    owner
}

/// Cold target selection for management APIs and dispatcher binding. Never
/// invoke this per submitted operation; retain the returned owner instead.
pub fn task_authority(id: TaskId) -> Option<Arc<CallerAuthority>> {
    OWNERS.lock().get(&id).cloned()
}

/// Drop an unpublished/retired task owner's administrative entry. Pointer
/// equality prevents an unrelated registration from being removed by cleanup.
pub fn release_caller_authority(control: &AuthorityControl) {
    let owner = &control.owner;
    owner.retire();
    let removed = {
        let mut owners = OWNERS.lock();
        if owners
            .get(&owner.id)
            .is_some_and(|entry| Arc::ptr_eq(entry, owner))
        {
            owners.remove(&owner.id)
        } else {
            None
        }
    };
    drop(removed);
}

pub(crate) fn unregister(id: TaskId) {
    let owner = OWNERS.lock().remove(&id);
    if let Some(owner) = owner {
        owner.retire();
    }
}

pub(crate) fn reset() {
    let old = core::mem::take(&mut *OWNERS.lock());
    for owner in old.values() {
        owner.retire();
    }
}

/// Explicit fixture construction; absent from production builds.
#[cfg(feature = "kernel-test")]
pub fn __set_task_active_domain_for_test(id: TaskId, domain: DomainId) {
    let owner = prepare(id, domain);
    owner.domain.store(domain.raw(), Ordering::Release);
    let old = owner.domain.0.load(Ordering::Acquire);
    if old & (LIVE | RETIRED) == 0 {
        owner.publish();
    }
}

// Each executor owns its cell. Keep poll publication off other CPUs' cache
// lines, and avoid a locked read/modify/write for same-CPU nested polls.
#[repr(align(64))]
struct CurrentCell(AtomicPtr<CallerAuthority>);
static CURRENT: [CurrentCell; narf_lib::percpu::MAX_CPUS] =
    [const { CurrentCell(AtomicPtr::new(core::ptr::null_mut())) }; narf_lib::percpu::MAX_CPUS];

pub(crate) struct CurrentGuard {
    cpu: usize,
    previous: *mut CallerAuthority,
}

impl CurrentGuard {
    pub(crate) fn enter(owner: &Arc<CallerAuthority>) -> Self {
        let cpu = narf_lib::percpu::current_cpu();
        let previous = CURRENT[cpu].0.load(Ordering::Relaxed);
        CURRENT[cpu]
            .0
            .store(Arc::as_ptr(owner).cast_mut(), Ordering::Release);
        Self { cpu, previous }
    }
}

impl Drop for CurrentGuard {
    fn drop(&mut self) {
        CURRENT[self.cpu].0.store(self.previous, Ordering::Release);
    }
}

pub(crate) fn clone_poll_owner() -> Option<Arc<CallerAuthority>> {
    let ptr = CURRENT[narf_lib::percpu::current_cpu()]
        .0
        .load(Ordering::Acquire);
    if ptr.is_null() {
        return None;
    }
    // SAFETY: CurrentGuard borrows the exclusively polled TaskSlot. That slot
    // pins a strong owner until its poll returns, including direct resumes.
    unsafe {
        Arc::increment_strong_count(ptr);
        Some(Arc::from_raw(ptr))
    }
}

pub(crate) fn update_scope_domain(domain: u8) {
    if crate::stackful::update_current_authority_domain(domain) {
        return;
    }
    let ptr = CURRENT[narf_lib::percpu::current_cpu()]
        .0
        .load(Ordering::Acquire);
    if !ptr.is_null() {
        // SAFETY: synchronous domain entry/exit occurs inside the current
        // task's pinned poll. No reference escapes or crosses an await.
        unsafe { (*ptr).domain.store(domain, Ordering::Release) };
    }
}

/// Publish logical domain scope state before executing confined code. The
/// existing architecture domain rights transition remains owned by its guard.
pub fn enter_domain_scope(domain: u8) -> u8 {
    let _pin = crate::preempt_disable();
    let previous = narf_arch::enter_domain_scope(domain);
    update_scope_domain(domain);
    previous
}

pub fn exit_domain_scope(previous: u8) {
    let _pin = crate::preempt_disable();
    narf_arch::exit_domain_scope(previous);
    update_scope_domain(previous);
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_authority_retained_owner_is_not_live() -> TestResult {
        let owner = CallerAuthority::prepared(TaskId(0xfa01_0001), DomainId::USERSPACE_K);
        if owner.image() != Err(CapError::Revoked) {
            return TestResult::Fail("prepared task admitted work");
        }
        owner.publish();
        let image = owner.image().unwrap();
        if owner.domain_for_image(image) != Ok(DomainId::USERSPACE_K) {
            return TestResult::Fail("wrong initial domain");
        }
        owner.replace_image();
        if owner.domain_for_image(image) != Err(CapError::Revoked) {
            return TestResult::Fail("old image remained usable");
        }
        let image = owner.image().unwrap();
        owner.retire();
        // A suspended domain guard can restore a byte after retirement, but
        // it must not restore its saved LIVE admission bit.
        owner
            .domain
            .store(DomainId::USERSPACE_K.raw(), Ordering::Release);
        if owner.domain_for_image(image) != Err(CapError::Revoked) {
            return TestResult::Fail("scope restore revived retired owner");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "scheduler/authority",
        smoke_authority_retained_owner_is_not_live
    );

    fn smoke_authority_cap_slots_are_owner_local() -> TestResult {
        #[derive(Debug)]
        struct Endpoint;
        impl CapType for Endpoint {
            const KIND: narf_capabilities::CapKind = narf_capabilities::CapKind::Endpoint;
        }
        let a = CallerAuthority::prepared(TaskId(0xfa01_0002), DomainId::USERSPACE_K);
        let b = CallerAuthority::prepared(TaskId(0xfa01_0003), DomainId::USERSPACE_K);
        let cap: Cap<Endpoint, narf_capabilities::Read> = Cap::bootstrap();
        let position = a.install_bootstrap(&cap).unwrap();
        a.publish();
        b.publish();
        let mut presented = cap.slot();
        presented.index = position;
        if a.lookup(presented) != Ok(cap.slot()) {
            return TestResult::Fail("owner could not resolve installed cap");
        }
        if b.lookup(presented) != Err(CapError::Revoked) {
            return TestResult::Fail("foreign slot crossed task boundary");
        }
        cap.revoke();
        if a.lookup(presented) != Err(CapError::Revoked) {
            return TestResult::Fail("cached owner bypassed object revocation");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "scheduler/authority",
        smoke_authority_cap_slots_are_owner_local
    );

    fn smoke_authority_scope_survives_suspension() -> TestResult {
        use core::sync::atomic::AtomicU32;
        static OUTCOME: AtomicU32 = AtomicU32::new(0);
        for own_stack in [false, true] {
            crate::__reset_queues_for_test();
            OUTCOME.store(0, Ordering::Relaxed);
            let future = async {
                let owner = task_authority(crate::current_task_id()).unwrap();
                let image = owner.image().unwrap();
                let previous = enter_domain_scope(DomainId::BPF.raw());
                let entered = owner.domain_for_image(image) == Ok(DomainId::BPF);
                crate::yield_now().await;
                let resumed = owner.domain_for_image(image) == Ok(DomainId::BPF)
                    && narf_arch::current_domain_byte() == DomainId::BPF.raw();
                exit_domain_scope(previous);
                let exited = owner.domain_for_image(image) == Ok(DomainId::USERSPACE_K);
                OUTCOME.store(u32::from(entered && resumed && exited), Ordering::Relaxed);
            };
            if own_stack {
                crate::spawn_stackful_with_options(
                    future,
                    crate::StackfulOptions {
                        domain: DomainId::USERSPACE_K,
                        ..Default::default()
                    },
                );
            } else {
                crate::spawn_with_spec_in_domain(
                    future,
                    crate::TaskSpec::default(),
                    DomainId::USERSPACE_K,
                );
            }
            crate::run_until_empty();
            if OUTCOME.load(Ordering::Relaxed) != 1 {
                return TestResult::Fail("logical scope lost across suspension");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "scheduler/authority",
        smoke_authority_scope_survives_suspension
    );
}
