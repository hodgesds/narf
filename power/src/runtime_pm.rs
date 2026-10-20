//! Runtime power management core: Linux `drivers/base/power/runtime.c`.
//!
//! A [`RuntimePmDevice`] carries the per-device runtime-PM state Linux keeps
//! in `struct dev_pm_info`: the status (`RPM_ACTIVE` / `RPM_SUSPENDING` /
//! `RPM_SUSPENDED` / `RPM_RESUMING`), the usage and active-child counts, the
//! disable depth, `runtime_auto` (sysfs `power/control`), the autosuspend
//! delay with `last_busy`, the sticky `runtime_error` and the pending
//! request word that `pm_runtime_work` consumes. The entry points mirror
//! the `pm_runtime_*` helpers of `include/linux/pm_runtime.h`.
//!
//! Async-first: `rpm_suspend` / `rpm_resume` / `rpm_idle` are futures. The
//! state lives behind an `IrqSafeSpinLock` that is never held across an
//! await; callbacks run unlocked and concurrent synchronous callers park on
//! a waker list until the transition finishes (Linux's `wait_queue`).
//! `RPM_ASYNC` requests and the autosuspend hrtimer go through an
//! [`RpmEnv`], which by default spawns executor tasks and sleeps on the
//! timer wheel ([`SchedulerEnv`]). Tests install a manual environment with
//! a fake clock, so autosuspend timing never depends on wall time.
//!
//! Parent/child ordering follows `rpm_resume` / `rpm_suspend`: a child's
//! resume holds a usage reference on its parent and resumes it first; an
//! active child counts in the parent's `child_count`, so the parent cannot
//! suspend until every child has; a child's successful suspend queues an
//! idle notification on its parent. `runtime_pm_pci` adds the PCI-bus
//! layer (`pci_pm_runtime_*`: config save/restore and D3hot/D3cold).
//!
//! Cancellation: dropping a future while its device callback runs leaves
//! the hardware state unknown. The core then records a sticky
//! [`RpmError::Cancelled`] (all later transitions fail until
//! [`RuntimePmDevice::set_active`] / [`RuntimePmDevice::set_suspended`]
//! re-establish the state while disabled) and wakes every waiter.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use narf_lib::sync::IrqSafeSpinLock;

/// Linux `enum rpm_status` (without `RPM_INVALID` / `RPM_BLOCKED`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RpmStatus {
    Active,
    Resuming,
    Suspended,
    Suspending,
}

/// Errors, by their Linux errno.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RpmError {
    /// `-EAGAIN`: conditions are wrong right now (usage held, wrong state,
    /// pending resume); a transient callback refusal.
    Again,
    /// `-EBUSY`: active children, or a transient callback refusal.
    Busy,
    /// `-EACCES`: runtime PM is disabled for the device.
    Access,
    /// `-EINVAL`: a previous callback failed (`runtime_error` is set), or
    /// the usage count would underflow.
    Invalid,
    /// `-EINPROGRESS`: a `NOWAIT` / `ASYNC` caller found a transition in
    /// flight.
    InProgress,
    /// `-EPERM`: the operation is not permitted in this configuration.
    NotPermitted,
    /// A callback's hard failure (any other errno). Sticky.
    Failed,
    /// A transition's future was dropped while its callback ran. Sticky.
    Cancelled,
}

impl RpmError {
    /// `-EAGAIN` / `-EBUSY`: rescheduled, never recorded as runtime_error.
    pub const fn is_transient(self) -> bool {
        matches!(self, RpmError::Again | RpmError::Busy)
    }
}

/// Linux's non-negative returns: 0 (`Done`) or 1 (`Already`, the device was
/// already in the requested state, or a `put` was allowed while suspended).
/// `Queued` is the 0 an `RPM_ASYNC` request returns once it is queued.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RpmOk {
    Done,
    Already,
    Queued,
}

/// Linux `RPM_*` request flags.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RpmFlags(u8);
impl RpmFlags {
    pub const NONE: Self = Self(0);
    pub const ASYNC: Self = Self(0x01);
    pub const NOWAIT: Self = Self(0x02);
    pub const GET_PUT: Self = Self(0x04);
    pub const AUTO: Self = Self(0x08);
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

pub type RpmFuture<'a> = Pin<Box<dyn Future<Output = Result<(), RpmError>> + Send + 'a>>;

/// The runtime half of Linux `struct dev_pm_ops`.
///
/// `runtime_suspend` must leave the device usable when it fails;
/// [`RpmError::Again`] / [`RpmError::Busy`] mean "try later" and keep runtime
/// PM working, any other error is recorded as `runtime_error` and blocks
/// further transitions. `runtime_idle` returning `Ok` lets the core
/// autosuspend (`rpm_idle` → `rpm_suspend(RPM_AUTO)`); an error is returned
/// to the caller without suspending. Implementations never retain an
/// IRQ-safe lock across an await.
pub trait RuntimePmOps: Send + Sync {
    fn runtime_suspend(&self) -> RpmFuture<'_>;
    fn runtime_resume(&self) -> RpmFuture<'_>;
    fn runtime_idle(&self) -> RpmFuture<'_> {
        Box::pin(async { Ok(()) })
    }
}

/// Deferred work and time for the core (`pm_wq`, `suspend_timer`,
/// `ktime_get_mono_fast_ns`).
pub trait RpmEnv: Send + Sync {
    /// Monotonic nanoseconds.
    fn now_ns(&self) -> u64;
    /// Run [`RuntimePmDevice::run_work`] later, in task context.
    fn queue_work(&self, dev: Arc<RuntimePmDevice>);
    /// Call [`RuntimePmDevice::timer_fn`] once `now_ns() >= expires_ns`.
    fn arm_timer(&self, dev: Arc<RuntimePmDevice>, expires_ns: u64);
}

/// The production environment: executor tasks and the timer wheel.
#[derive(Debug, Default)]
pub struct SchedulerEnv;
impl RpmEnv for SchedulerEnv {
    fn now_ns(&self) -> u64 {
        narf_time::monotonic_ns()
    }
    fn queue_work(&self, dev: Arc<RuntimePmDevice>) {
        narf_scheduler::spawn(async move { dev.run_work().await });
    }
    fn arm_timer(&self, dev: Arc<RuntimePmDevice>, expires_ns: u64) {
        narf_scheduler::spawn(async move {
            // Never fire early: the timer function ignores early calls, as
            // pm_suspend_timer_fn does, and an hrtimer never fires early.
            loop {
                let now = narf_time::monotonic_ns();
                if now >= expires_ns {
                    break;
                }
                let deadline = narf_time::Deadline::after_ns(expires_ns - now);
                narf_time::SleepUntil::new(deadline.as_instant()).await;
            }
            dev.timer_fn();
        });
    }
}

/// Linux `enum rpm_request`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Request {
    None,
    Idle,
    Suspend,
    Autosuspend,
    Resume,
}

#[derive(Debug)]
struct Inner {
    status: RpmStatus,
    usage_count: i32,
    child_count: u32,
    disable_depth: u32,
    runtime_auto: bool,
    ignore_children: bool,
    no_callbacks: bool,
    use_autosuspend: bool,
    autosuspend_delay_ms: i32,
    last_busy_ns: u64,
    runtime_error: Option<RpmError>,
    idle_notification: bool,
    deferred_resume: bool,
    request_pending: bool,
    request: Request,
    timer_expires: u64,
    timer_autosuspends: bool,
    /// The parent reference this device's active state holds.
    counted_in_parent: bool,
    waiters: Vec<Waker>,
    suspends: u64,
    resumes: u64,
}

/// Snapshot of a device's runtime-PM fields, for diagnostics and tests.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RpmState {
    pub status: RpmStatus,
    pub usage_count: i32,
    pub child_count: u32,
    pub disable_depth: u32,
    pub runtime_auto: bool,
    pub use_autosuspend: bool,
    pub autosuspend_delay_ms: i32,
    pub last_busy_ns: u64,
    pub runtime_error: Option<RpmError>,
    pub request_pending: bool,
    pub timer_expires_ns: u64,
    /// Completed runtime suspends and resumes (callback succeeded).
    pub suspends: u64,
    pub resumes: u64,
}

/// Linux `struct device`'s runtime-PM half.
pub struct RuntimePmDevice {
    name: String,
    ops: Option<Arc<dyn RuntimePmOps>>,
    parent: Option<Arc<RuntimePmDevice>>,
    env: Arc<dyn RpmEnv>,
    inner: IrqSafeSpinLock<Inner>,
}

impl fmt::Debug for RuntimePmDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimePmDevice")
            .field("name", &self.name)
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

/// Side effects decided under the lock and performed after releasing it.
#[derive(Default)]
struct Deferred {
    queue_work: bool,
    arm_timer: Option<u64>,
    wake: Vec<Waker>,
}

impl RuntimePmDevice {
    /// `pm_runtime_init`: suspended, disabled once, `runtime_auto` set,
    /// autosuspend off. `ops == None` is `pm_runtime_no_callbacks`.
    pub fn new(
        name: &str,
        ops: Option<Arc<dyn RuntimePmOps>>,
        parent: Option<Arc<RuntimePmDevice>>,
        env: Arc<dyn RpmEnv>,
    ) -> Arc<Self> {
        let no_callbacks = ops.is_none();
        Arc::new(Self {
            name: String::from(name),
            ops,
            parent,
            env,
            inner: IrqSafeSpinLock::new(Inner {
                status: RpmStatus::Suspended,
                usage_count: 0,
                child_count: 0,
                disable_depth: 1,
                runtime_auto: true,
                ignore_children: false,
                no_callbacks,
                use_autosuspend: false,
                autosuspend_delay_ms: 0,
                last_busy_ns: 0,
                runtime_error: None,
                idle_notification: false,
                deferred_resume: false,
                request_pending: false,
                request: Request::None,
                timer_expires: 0,
                timer_autosuspends: false,
                counted_in_parent: false,
                waiters: Vec::new(),
                suspends: 0,
                resumes: 0,
            }),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn parent(&self) -> Option<&Arc<RuntimePmDevice>> {
        self.parent.as_ref()
    }

    pub fn state(&self) -> RpmState {
        let i = self.inner.lock();
        RpmState {
            status: i.status,
            usage_count: i.usage_count,
            child_count: i.child_count,
            disable_depth: i.disable_depth,
            runtime_auto: i.runtime_auto,
            use_autosuspend: i.use_autosuspend,
            autosuspend_delay_ms: i.autosuspend_delay_ms,
            last_busy_ns: i.last_busy_ns,
            runtime_error: i.runtime_error,
            request_pending: i.request_pending,
            timer_expires_ns: i.timer_expires,
            suspends: i.suspends,
            resumes: i.resumes,
        }
    }
    pub fn status(&self) -> RpmStatus {
        self.inner.lock().status
    }
    /// `pm_runtime_suspended`: suspended with runtime PM enabled.
    pub fn suspended(&self) -> bool {
        let i = self.inner.lock();
        i.status == RpmStatus::Suspended && i.disable_depth == 0
    }
    /// `pm_runtime_active`: active, or runtime PM disabled.
    pub fn active(&self) -> bool {
        let i = self.inner.lock();
        i.status == RpmStatus::Active || i.disable_depth > 0
    }

    // ── Configuration ────────────────────────────────────────────────

    /// `pm_runtime_set_active` (`__pm_runtime_set_status(RPM_ACTIVE)`):
    /// only while disabled; an inactive parent that does not ignore its
    /// children refuses with `Busy`. Clears `runtime_error`.
    pub fn set_active(&self) -> Result<(), RpmError> {
        self.set_status(RpmStatus::Active)
    }
    /// `pm_runtime_set_suspended`.
    pub fn set_suspended(&self) -> Result<(), RpmError> {
        self.set_status(RpmStatus::Suspended)
    }
    fn set_status(&self, status: RpmStatus) -> Result<(), RpmError> {
        let mut i = self.inner.lock();
        if i.disable_depth == 0 {
            return Err(RpmError::Again);
        }
        if i.status == status {
            i.runtime_error = None;
            return Ok(());
        }
        if status == RpmStatus::Active && !i.counted_in_parent {
            if let Some(parent) = &self.parent {
                let mut p = parent.inner.lock();
                if p.disable_depth == 0 && !p.ignore_children && p.status != RpmStatus::Active {
                    return Err(RpmError::Busy);
                }
                p.child_count += 1;
                i.counted_in_parent = true;
            }
        } else if status == RpmStatus::Suspended && i.counted_in_parent {
            if let Some(parent) = &self.parent {
                let mut p = parent.inner.lock();
                p.child_count = p.child_count.saturating_sub(1);
            }
            i.counted_in_parent = false;
        }
        i.status = status;
        i.runtime_error = None;
        let wake = core::mem::take(&mut i.waiters);
        drop(i);
        wake.into_iter().for_each(Waker::wake);
        Ok(())
    }
    /// `pm_runtime_enable`.
    pub fn enable(&self) {
        let mut i = self.inner.lock();
        i.disable_depth = i.disable_depth.saturating_sub(1);
    }
    /// `pm_runtime_disable` (`__pm_runtime_disable(dev, true)`): waits for a
    /// running transition, carries out a pending resume request first, then
    /// increments the disable depth and cancels pending requests.
    pub async fn disable(self: &Arc<Self>) {
        loop {
            let resume = {
                let i = self.inner.lock();
                i.disable_depth == 0 && i.request_pending && i.request == Request::Resume
            };
            if resume {
                let _ = self.rpm_resume(RpmFlags::NONE).await;
            }
            self.wait_transition().await;
            let mut i = self.inner.lock();
            if matches!(i.status, RpmStatus::Resuming | RpmStatus::Suspending) {
                continue;
            }
            i.disable_depth += 1;
            i.request_pending = false;
            i.request = Request::None;
            i.timer_expires = 0;
            return;
        }
    }
    /// `pm_runtime_irq_safe` is not offered: every callback is async.
    /// `pm_suspend_ignore_children`.
    pub fn ignore_children(&self, enable: bool) {
        self.inner.lock().ignore_children = enable;
    }
    /// `pm_runtime_forbid`: hold a usage reference and resume.
    pub async fn forbid(self: &Arc<Self>) -> Result<RpmOk, RpmError> {
        {
            let mut i = self.inner.lock();
            if !i.runtime_auto {
                return Ok(RpmOk::Already);
            }
            i.runtime_auto = false;
            i.usage_count += 1;
        }
        self.rpm_resume(RpmFlags::NONE).await
    }
    /// `pm_runtime_allow`: drop the `forbid` reference and queue an idle
    /// check (`RPM_AUTO | RPM_ASYNC`).
    pub fn allow(self: &Arc<Self>) {
        let idle = {
            let mut i = self.inner.lock();
            if i.runtime_auto {
                return;
            }
            i.runtime_auto = true;
            matches!(Self::drop_usage(&mut i), Ok(0))
        };
        if idle {
            let _ = self.request(Request::Idle, RpmFlags::AUTO);
        }
    }
    /// `pm_runtime_forbid` on a device known to be active (`pci_pm_init`
    /// before any driver runs): no resume is needed, so no await.
    pub fn set_forbidden_active(&self) -> Result<(), RpmError> {
        let mut i = self.inner.lock();
        if !i.runtime_auto {
            return Ok(());
        }
        if i.status != RpmStatus::Active {
            return Err(RpmError::Again);
        }
        i.runtime_auto = false;
        i.usage_count += 1;
        Ok(())
    }
    /// `pm_runtime_mark_last_busy`.
    pub fn mark_last_busy(&self) {
        let now = self.env.now_ns();
        self.inner.lock().last_busy_ns = now;
    }
    /// `pm_runtime_set_autosuspend_delay` (with `update_autosuspend`).
    pub async fn set_autosuspend_delay(self: &Arc<Self>, delay_ms: i32) {
        let (old_delay, old_use) = {
            let mut i = self.inner.lock();
            let old = (i.autosuspend_delay_ms, i.use_autosuspend);
            i.autosuspend_delay_ms = delay_ms;
            old
        };
        self.update_autosuspend(old_delay, old_use).await;
    }
    /// `__pm_runtime_use_autosuspend`.
    pub async fn use_autosuspend(self: &Arc<Self>, use_it: bool) {
        let (old_delay, old_use) = {
            let mut i = self.inner.lock();
            let old = (i.autosuspend_delay_ms, i.use_autosuspend);
            i.use_autosuspend = use_it;
            old
        };
        self.update_autosuspend(old_delay, old_use).await;
    }
    async fn update_autosuspend(self: &Arc<Self>, old_delay: i32, old_use: bool) {
        let (use_it, delay) = {
            let i = self.inner.lock();
            (i.use_autosuspend, i.autosuspend_delay_ms)
        };
        if use_it && delay < 0 {
            if !old_use || old_delay >= 0 {
                self.inner.lock().usage_count += 1;
                let _ = self.rpm_resume(RpmFlags::NONE).await;
            }
        } else {
            if old_use && old_delay < 0 {
                self.inner.lock().usage_count -= 1;
            }
            let _ = self.rpm_idle(RpmFlags::AUTO).await;
        }
    }

    // ── Usage-count entry points ─────────────────────────────────────

    /// `pm_runtime_get_noresume`.
    pub fn get_noresume(&self) {
        self.inner.lock().usage_count += 1;
    }
    /// `pm_runtime_put_noidle`.
    pub fn put_noidle(&self) {
        let mut i = self.inner.lock();
        if i.usage_count > 0 {
            i.usage_count -= 1;
        }
    }
    /// `pm_runtime_get_sync`: take a reference and resume. The reference is
    /// kept even when resume fails, as in Linux; the caller always puts.
    pub async fn get_sync(self: &Arc<Self>) -> Result<RpmOk, RpmError> {
        self.inner.lock().usage_count += 1;
        self.rpm_resume(RpmFlags::NONE).await
    }
    /// `pm_runtime_resume_and_get`: as `get_sync`, dropping the reference
    /// on failure.
    pub async fn resume_and_get(self: &Arc<Self>) -> Result<RpmOk, RpmError> {
        let result = self.get_sync().await;
        if result.is_err() {
            self.put_noidle();
        }
        result
    }
    /// `pm_runtime_get` (`RPM_GET_PUT | RPM_ASYNC`): reference plus an
    /// asynchronous resume request.
    pub fn get(self: &Arc<Self>) -> Result<RpmOk, RpmError> {
        self.inner.lock().usage_count += 1;
        self.request_resume()
    }
    /// `pm_runtime_get_if_active` (`pm_runtime_get_conditional(dev, true)`):
    /// a reference only if the device is active; `Ok(false)` otherwise;
    /// `Invalid` while runtime PM is disabled.
    pub fn get_if_active(&self) -> Result<bool, RpmError> {
        let mut i = self.inner.lock();
        if i.disable_depth > 0 {
            return Err(RpmError::Invalid);
        }
        if i.status != RpmStatus::Active {
            return Ok(false);
        }
        i.usage_count += 1;
        Ok(true)
    }
    /// `pm_runtime_put` (`RPM_GET_PUT | RPM_ASYNC` idle).
    pub fn put(self: &Arc<Self>) -> Result<RpmOk, RpmError> {
        {
            let mut i = self.inner.lock();
            if Self::drop_usage(&mut i)? > 0 {
                return Ok(RpmOk::Done);
            }
        }
        self.request(Request::Idle, RpmFlags::GET_PUT)
    }
    /// `pm_runtime_put_sync` (`RPM_GET_PUT` idle, synchronous).
    pub async fn put_sync(self: &Arc<Self>) -> Result<RpmOk, RpmError> {
        {
            let mut i = self.inner.lock();
            if Self::drop_usage(&mut i)? > 0 {
                return Ok(RpmOk::Done);
            }
        }
        self.rpm_idle(RpmFlags::GET_PUT).await
    }
    /// `pm_runtime_put_autosuspend`: mark last busy, drop the reference and
    /// queue an autosuspend (`RPM_GET_PUT | RPM_ASYNC | RPM_AUTO`).
    pub fn put_autosuspend(self: &Arc<Self>) -> Result<RpmOk, RpmError> {
        self.mark_last_busy();
        {
            let mut i = self.inner.lock();
            if Self::drop_usage(&mut i)? > 0 {
                return Ok(RpmOk::Done);
            }
        }
        self.request(Request::Autosuspend, RpmFlags::AUTO)
    }
    fn drop_usage(i: &mut Inner) -> Result<i32, RpmError> {
        if i.usage_count <= 0 {
            // rpm_drop_usage_count: "Runtime PM usage count underflow!"
            return Err(RpmError::Invalid);
        }
        i.usage_count -= 1;
        Ok(i.usage_count)
    }

    // ── Request entry points ─────────────────────────────────────────

    /// `pm_request_idle`.
    pub fn request_idle(self: &Arc<Self>) -> Result<RpmOk, RpmError> {
        self.request(Request::Idle, RpmFlags::NONE)
    }
    /// `pm_request_resume`.
    pub fn request_resume(self: &Arc<Self>) -> Result<RpmOk, RpmError> {
        self.request(Request::Resume, RpmFlags::NONE)
    }
    /// `pm_request_autosuspend`: mark last busy and queue an autosuspend.
    pub fn request_autosuspend(self: &Arc<Self>) -> Result<RpmOk, RpmError> {
        self.mark_last_busy();
        self.request(Request::Autosuspend, RpmFlags::AUTO)
    }
    /// `pm_runtime_idle`.
    pub async fn idle(self: &Arc<Self>) -> Result<RpmOk, RpmError> {
        self.rpm_idle(RpmFlags::NONE).await
    }
    /// `pm_runtime_suspend`.
    pub async fn suspend(self: &Arc<Self>) -> Result<RpmOk, RpmError> {
        self.rpm_suspend(RpmFlags::NONE).await
    }
    /// `pm_runtime_autosuspend`: `pm_runtime_mark_last_busy` + suspend with
    /// `RPM_AUTO`.
    pub async fn autosuspend(self: &Arc<Self>) -> Result<RpmOk, RpmError> {
        self.mark_last_busy();
        self.rpm_suspend(RpmFlags::AUTO).await
    }
    /// `pm_runtime_resume`.
    pub async fn resume(self: &Arc<Self>) -> Result<RpmOk, RpmError> {
        self.rpm_resume(RpmFlags::NONE).await
    }
    /// `pm_runtime_autosuspend_expiration`: the future expiry in ns, or 0.
    pub fn autosuspend_expiration(&self) -> u64 {
        let now = self.env.now_ns();
        Self::expiration(&self.inner.lock(), now)
    }
    fn expiration(i: &Inner, now: u64) -> u64 {
        if !i.use_autosuspend || i.autosuspend_delay_ms < 0 {
            return 0;
        }
        let expires = i
            .last_busy_ns
            .saturating_add(i.autosuspend_delay_ms as u64 * 1_000_000);
        if expires > now {
            expires
        } else {
            0
        }
    }

    /// An `RPM_ASYNC` request: the synchronous checks of `rpm_idle`,
    /// `rpm_suspend` or `rpm_resume`, then a queued `pm_runtime_work`.
    fn request(self: &Arc<Self>, request: Request, flags: RpmFlags) -> Result<RpmOk, RpmError> {
        let now = self.env.now_ns();
        let mut d = Deferred::default();
        let result = {
            let mut i = self.inner.lock();
            match request {
                Request::Idle => Self::idle_async(&mut i, flags, now, &mut d),
                Request::Suspend | Request::Autosuspend => Self::suspend_async(
                    &mut i,
                    if request == Request::Autosuspend {
                        flags.union(RpmFlags::AUTO)
                    } else {
                        flags
                    },
                    now,
                    &mut d,
                ),
                Request::Resume => Self::resume_async(&mut i, &mut d),
                Request::None => Ok(RpmOk::Done),
            }
        };
        self.apply(d);
        result
    }
    fn apply(self: &Arc<Self>, d: Deferred) {
        d.wake.into_iter().for_each(Waker::wake);
        if d.queue_work {
            self.env.queue_work(self.clone());
        }
        if let Some(expires) = d.arm_timer {
            self.env.arm_timer(self.clone(), expires);
        }
    }
    fn queue(i: &mut Inner, request: Request, d: &mut Deferred) {
        i.request = request;
        if !i.request_pending {
            i.request_pending = true;
            d.queue_work = true;
        }
    }
    /// `pm_runtime_cancel_pending` (the timer is deactivated by clearing
    /// `timer_expires`; a fired timer then finds nothing to do).
    fn cancel_pending(i: &mut Inner) {
        i.timer_expires = 0;
        i.timer_autosuspends = false;
        i.request = Request::None;
    }
    /// `rpm_check_suspend_allowed`.
    fn check_suspend_allowed(i: &Inner) -> Result<RpmOk, RpmError> {
        if i.runtime_error.is_some() {
            Err(RpmError::Invalid)
        } else if i.disable_depth > 0 {
            Err(RpmError::Access)
        } else if i.usage_count > 0 {
            Err(RpmError::Again)
        } else if !i.ignore_children && i.child_count > 0 {
            Err(RpmError::Busy)
        } else if (i.deferred_resume && i.status == RpmStatus::Suspending)
            || (i.request_pending && i.request == Request::Resume)
        {
            Err(RpmError::Again)
        } else if i.status == RpmStatus::Suspended {
            Ok(RpmOk::Already)
        } else {
            Ok(RpmOk::Done)
        }
    }
    /// The checks at the top of `rpm_idle`. `Ok(None)`: proceed.
    fn idle_checks(i: &Inner, flags: RpmFlags) -> Result<Option<RpmOk>, RpmError> {
        match Self::check_suspend_allowed(i)? {
            RpmOk::Already if flags.contains(RpmFlags::GET_PUT) => return Ok(Some(RpmOk::Already)),
            _ => {}
        }
        if i.status != RpmStatus::Active {
            return Err(RpmError::Again);
        }
        if i.request_pending && i.request > Request::Idle {
            return Err(RpmError::Again);
        }
        if i.idle_notification {
            return Err(RpmError::InProgress);
        }
        Ok(None)
    }
    fn idle_async(
        i: &mut Inner,
        flags: RpmFlags,
        now: u64,
        d: &mut Deferred,
    ) -> Result<RpmOk, RpmError> {
        if let Some(ok) = Self::idle_checks(i, flags)? {
            return Ok(ok);
        }
        i.request = Request::None;
        if i.no_callbacks {
            // rpm_idle "assume success" falls through to rpm_suspend.
            return Self::suspend_async(i, flags.union(RpmFlags::AUTO), now, d);
        }
        Self::queue(i, Request::Idle, d);
        Ok(RpmOk::Queued)
    }
    fn suspend_async(
        i: &mut Inner,
        flags: RpmFlags,
        now: u64,
        d: &mut Deferred,
    ) -> Result<RpmOk, RpmError> {
        let allowed = Self::check_suspend_allowed(i)?;
        if allowed == RpmOk::Already {
            return Ok(RpmOk::Already);
        }
        if flags.contains(RpmFlags::AUTO) && i.status != RpmStatus::Suspending {
            let expires = Self::expiration(i, now);
            if expires != 0 {
                Self::arm(i, expires, d);
                return Ok(RpmOk::Queued);
            }
        }
        if i.status == RpmStatus::Suspending {
            return Err(RpmError::InProgress);
        }
        Self::cancel_pending(i);
        Self::queue(
            i,
            if flags.contains(RpmFlags::AUTO) {
                Request::Autosuspend
            } else {
                Request::Suspend
            },
            d,
        );
        Ok(RpmOk::Queued)
    }
    fn resume_async(i: &mut Inner, d: &mut Deferred) -> Result<RpmOk, RpmError> {
        if i.runtime_error.is_some() {
            return Err(RpmError::Invalid);
        }
        if i.disable_depth > 0 {
            return if i.status == RpmStatus::Active {
                Ok(RpmOk::Already)
            } else {
                Err(RpmError::Access)
            };
        }
        i.request = Request::None;
        if !i.timer_autosuspends {
            i.timer_expires = 0;
        }
        match i.status {
            RpmStatus::Active => Ok(RpmOk::Already),
            RpmStatus::Suspending => {
                i.deferred_resume = true;
                Ok(RpmOk::Queued)
            }
            RpmStatus::Resuming => Err(RpmError::InProgress),
            RpmStatus::Suspended => {
                Self::queue(i, Request::Resume, d);
                Ok(RpmOk::Queued)
            }
        }
    }
    /// Arm the autosuspend timer at `expires` unless it already expires no
    /// later (the rpm_suspend optimization).
    fn arm(i: &mut Inner, expires: u64, d: &mut Deferred) {
        i.request = Request::None;
        if !(i.timer_expires != 0 && i.timer_expires <= expires) {
            i.timer_expires = expires;
            d.arm_timer = Some(expires);
        }
        i.timer_autosuspends = true;
    }

    // ── Work and timer ───────────────────────────────────────────────

    /// `pm_runtime_work`: carry out the pending request.
    pub async fn run_work(self: &Arc<Self>) {
        let request = {
            let mut i = self.inner.lock();
            if !i.request_pending {
                return;
            }
            let r = i.request;
            i.request = Request::None;
            i.request_pending = false;
            r
        };
        let _ = match request {
            Request::None => return,
            Request::Idle => self.rpm_idle(RpmFlags::NOWAIT).await,
            Request::Suspend => self.rpm_suspend(RpmFlags::NOWAIT).await,
            Request::Autosuspend => {
                self.rpm_suspend(RpmFlags::NOWAIT.union(RpmFlags::AUTO))
                    .await
            }
            Request::Resume => self.rpm_resume(RpmFlags::NOWAIT).await,
        };
    }
    /// `pm_suspend_timer_fn`: if the armed expiry has passed, queue the
    /// (auto)suspend. Early or cancelled firings do nothing.
    pub fn timer_fn(self: &Arc<Self>) {
        let now = self.env.now_ns();
        let mut d = Deferred::default();
        {
            let mut i = self.inner.lock();
            let expires = i.timer_expires;
            if expires == 0 || expires > now {
                return;
            }
            i.timer_expires = 0;
            let flags = if i.timer_autosuspends {
                RpmFlags::AUTO
            } else {
                RpmFlags::NONE
            };
            let _ = Self::suspend_async(&mut i, flags, now, &mut d);
        }
        self.apply(d);
    }

    // ── Core transitions ─────────────────────────────────────────────

    /// `rpm_idle` (synchronous form; `RPM_ASYNC` goes through `request`).
    async fn rpm_idle(self: &Arc<Self>, flags: RpmFlags) -> Result<RpmOk, RpmError> {
        if flags.contains(RpmFlags::ASYNC) {
            return self.request(Request::Idle, flags);
        }
        let callback = {
            let mut i = self.inner.lock();
            if let Some(ok) = Self::idle_checks(&i, flags)? {
                return Ok(ok);
            }
            i.request = Request::None;
            if i.no_callbacks {
                None
            } else {
                i.idle_notification = true;
                self.ops.clone()
            }
        };
        if let Some(ops) = callback {
            let guard = Notification(self);
            let result = ops.runtime_idle().await;
            drop(guard);
            result?;
        }
        self.rpm_suspend(flags.union(RpmFlags::AUTO)).await
    }

    /// `rpm_suspend`.
    fn rpm_suspend<'a>(
        self: &'a Arc<Self>,
        flags: RpmFlags,
    ) -> Pin<Box<dyn Future<Output = Result<RpmOk, RpmError>> + Send + 'a>> {
        Box::pin(async move {
            if flags.contains(RpmFlags::ASYNC) {
                return self.request(Request::Suspend, flags);
            }
            loop {
                let now = self.env.now_ns();
                let mut d = Deferred::default();
                enum Next {
                    Out(Result<RpmOk, RpmError>),
                    Wait,
                    Callback(Option<Arc<dyn RuntimePmOps>>),
                }
                let next = {
                    let mut i = self.inner.lock();
                    match Self::check_suspend_allowed(&i) {
                        Err(e) => Next::Out(Err(e)),
                        Ok(_) if i.status == RpmStatus::Resuming => Next::Out(Err(RpmError::Again)),
                        Ok(RpmOk::Already) => Next::Out(Ok(RpmOk::Already)),
                        Ok(_) => {
                            let expires = if flags.contains(RpmFlags::AUTO)
                                && i.status != RpmStatus::Suspending
                            {
                                Self::expiration(&i, now)
                            } else {
                                0
                            };
                            if expires != 0 {
                                Self::arm(&mut i, expires, &mut d);
                                Next::Out(Ok(RpmOk::Queued))
                            } else {
                                Self::cancel_pending(&mut i);
                                if i.status == RpmStatus::Suspending {
                                    if flags.contains(RpmFlags::NOWAIT) {
                                        Next::Out(Err(RpmError::InProgress))
                                    } else {
                                        Next::Wait
                                    }
                                } else {
                                    i.status = RpmStatus::Suspending;
                                    Next::Callback(if i.no_callbacks {
                                        None
                                    } else {
                                        self.ops.clone()
                                    })
                                }
                            }
                        }
                    }
                };
                self.apply(d);
                let ops = match next {
                    Next::Out(result) => return result,
                    Next::Wait => {
                        self.wait_transition().await;
                        continue;
                    }
                    Next::Callback(ops) => ops,
                };
                let guard = Transition(self);
                let result = match &ops {
                    Some(ops) => map_callback(ops.runtime_suspend().await),
                    None => Ok(()),
                };
                core::mem::forget(guard);
                match result {
                    Ok(()) => return self.suspended_ok().await,
                    Err(error) => {
                        let retry = {
                            let mut i = self.inner.lock();
                            i.status = RpmStatus::Active;
                            i.deferred_resume = false;
                            if !error.is_transient() {
                                i.runtime_error = Some(error);
                            }
                            let wake = core::mem::take(&mut i.waiters);
                            let retry = i.runtime_error.is_none()
                                && flags.contains(RpmFlags::AUTO)
                                && Self::expiration(&i, self.env.now_ns()) != 0;
                            if !retry {
                                Self::cancel_pending(&mut i);
                            }
                            drop(i);
                            wake.into_iter().for_each(Waker::wake);
                            retry
                        };
                        if retry {
                            continue;
                        }
                        return Err(error);
                    }
                }
            }
        })
    }
    /// The `no_callback:` tail of `rpm_suspend`.
    async fn suspended_ok(self: &Arc<Self>) -> Result<RpmOk, RpmError> {
        let (deferred, parent) = {
            let mut i = self.inner.lock();
            i.status = RpmStatus::Suspended;
            i.suspends += 1;
            i.timer_expires = 0;
            let mut parent = None;
            if i.counted_in_parent {
                if let Some(p) = &self.parent {
                    let mut pi = p.inner.lock();
                    pi.child_count = pi.child_count.saturating_sub(1);
                    parent = (!pi.ignore_children).then(|| p.clone());
                }
                i.counted_in_parent = false;
            }
            let deferred = core::mem::replace(&mut i.deferred_resume, false);
            let wake = core::mem::take(&mut i.waiters);
            drop(i);
            wake.into_iter().for_each(Waker::wake);
            (deferred, parent)
        };
        if deferred {
            let _ = self.rpm_resume(RpmFlags::NONE).await;
            return Err(RpmError::Again);
        }
        if let Some(parent) = parent {
            let _ = parent.request(Request::Idle, RpmFlags::NONE);
        }
        Ok(RpmOk::Done)
    }

    /// `rpm_resume`.
    fn rpm_resume<'a>(
        self: &'a Arc<Self>,
        flags: RpmFlags,
    ) -> Pin<Box<dyn Future<Output = Result<RpmOk, RpmError>> + Send + 'a>> {
        Box::pin(async move {
            if flags.contains(RpmFlags::ASYNC) {
                return self.request(Request::Resume, flags);
            }
            // The parent reference this call took (released at `out:`).
            let mut parent_ref: Option<Arc<RuntimePmDevice>> = None;
            let result = loop {
                enum Next {
                    Out(Result<RpmOk, RpmError>),
                    Wait,
                    ResumeParent(Arc<RuntimePmDevice>),
                    Callback(Option<Arc<dyn RuntimePmOps>>),
                }
                let next = {
                    let mut i = self.inner.lock();
                    if i.runtime_error.is_some() {
                        Next::Out(Err(RpmError::Invalid))
                    } else if i.disable_depth > 0 {
                        Next::Out(if i.status == RpmStatus::Active {
                            Ok(RpmOk::Already)
                        } else {
                            Err(RpmError::Access)
                        })
                    } else {
                        i.request = Request::None;
                        if !i.timer_autosuspends {
                            i.timer_expires = 0;
                        }
                        match i.status {
                            RpmStatus::Active => Next::Out(Ok(RpmOk::Already)),
                            RpmStatus::Resuming | RpmStatus::Suspending
                                if flags.contains(RpmFlags::NOWAIT) =>
                            {
                                if i.status == RpmStatus::Suspending {
                                    i.deferred_resume = true;
                                }
                                Next::Out(Err(RpmError::InProgress))
                            }
                            RpmStatus::Resuming | RpmStatus::Suspending => Next::Wait,
                            RpmStatus::Suspended => match (&self.parent, &parent_ref) {
                                (Some(p), None) => Next::ResumeParent(p.clone()),
                                _ => {
                                    i.status = RpmStatus::Resuming;
                                    Next::Callback(if i.no_callbacks {
                                        None
                                    } else {
                                        self.ops.clone()
                                    })
                                }
                            },
                        }
                    }
                };
                let ops = match next {
                    Next::Out(result) => break result,
                    Next::Wait => {
                        self.wait_transition().await;
                        continue;
                    }
                    Next::ResumeParent(parent) => {
                        parent.get_noresume();
                        parent_ref = Some(parent.clone());
                        let resume = {
                            let p = parent.inner.lock();
                            p.disable_depth == 0 && !p.ignore_children
                        };
                        if resume {
                            let _ = parent.rpm_resume(RpmFlags::NONE).await;
                            if parent.status() != RpmStatus::Active {
                                break Err(RpmError::Busy);
                            }
                        }
                        continue;
                    }
                    Next::Callback(ops) => ops,
                };
                let guard = Transition(self);
                let result = match &ops {
                    Some(ops) => map_callback(ops.runtime_resume().await),
                    None => Ok(()),
                };
                core::mem::forget(guard);
                let now = self.env.now_ns();
                let wake = {
                    let mut i = self.inner.lock();
                    match result {
                        Ok(()) => {
                            i.status = RpmStatus::Active;
                            i.resumes += 1;
                            i.last_busy_ns = now;
                            if let Some(p) = &parent_ref {
                                p.inner.lock().child_count += 1;
                                i.counted_in_parent = true;
                            }
                        }
                        Err(error) => {
                            i.status = RpmStatus::Suspended;
                            if !error.is_transient() {
                                i.runtime_error = Some(error);
                            }
                            Self::cancel_pending(&mut i);
                        }
                    }
                    core::mem::take(&mut i.waiters)
                };
                wake.into_iter().for_each(Waker::wake);
                if result.is_ok() {
                    let _ = self.request(Request::Idle, RpmFlags::NONE);
                }
                break result.map(|()| RpmOk::Done);
            };
            if let Some(parent) = parent_ref {
                let _ = parent.put();
            }
            result
        })
    }

    /// Park until the device is not mid-transition (or has a sticky error).
    fn wait_transition(&self) -> WaitTransition<'_> {
        WaitTransition(self)
    }
}

/// Linux converts a callback's `-EACCES` (reserved for "disabled") into
/// `-EAGAIN`.
fn map_callback(result: Result<(), RpmError>) -> Result<(), RpmError> {
    match result {
        Err(RpmError::Access) => Err(RpmError::Again),
        other => other,
    }
}

/// Clears `idle_notification` and wakes waiters when the idle callback ends
/// (also when its future is dropped).
struct Notification<'a>(&'a RuntimePmDevice);
impl Drop for Notification<'_> {
    fn drop(&mut self) {
        let wake = {
            let mut i = self.0.inner.lock();
            i.idle_notification = false;
            core::mem::take(&mut i.waiters)
        };
        wake.into_iter().for_each(Waker::wake);
    }
}

/// Dropped only when the transition's future is cancelled mid-callback
/// (forgotten on completion): record the sticky error and wake waiters.
struct Transition<'a>(&'a RuntimePmDevice);
impl Drop for Transition<'_> {
    fn drop(&mut self) {
        let wake = {
            let mut i = self.0.inner.lock();
            i.runtime_error = Some(RpmError::Cancelled);
            core::mem::take(&mut i.waiters)
        };
        wake.into_iter().for_each(Waker::wake);
    }
}

struct WaitTransition<'a>(&'a RuntimePmDevice);
impl Future for WaitTransition<'_> {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut i = self.0.inner.lock();
        if i.runtime_error.is_some()
            || !matches!(i.status, RpmStatus::Resuming | RpmStatus::Suspending)
        {
            return Poll::Ready(());
        }
        if !i.waiters.iter().any(|w| w.will_wake(cx.waker())) {
            i.waiters.push(cx.waker().clone());
        }
        Poll::Pending
    }
}

/// RAII form of `pm_runtime_get_sync` … `pm_runtime_put_autosuspend`
/// (Linux `guard(pm_runtime_active_auto)`): created by [`active_auto`],
/// dropping it marks the device busy and drops the reference.
#[derive(Debug)]
pub struct RpmActiveRef {
    dev: Arc<RuntimePmDevice>,
}
impl RpmActiveRef {
    pub fn device(&self) -> &Arc<RuntimePmDevice> {
        &self.dev
    }
}
impl Drop for RpmActiveRef {
    fn drop(&mut self) {
        let _ = self.dev.put_autosuspend();
    }
}
/// Take a reference, resume, and return the guard with the resume result;
/// the guard holds the reference either way (as `amdgpu_drm_ioctl`, which
/// puts after a failed `pm_runtime_get_sync`).
pub async fn active_auto(dev: &Arc<RuntimePmDevice>) -> (RpmActiveRef, Result<RpmOk, RpmError>) {
    let result = dev.get_sync().await;
    (RpmActiveRef { dev: dev.clone() }, result)
}

// ── Test environment ─────────────────────────────────────────────────

/// A deterministic [`RpmEnv`]: a fake clock advanced by the test and queues
/// of work items and timers that run only when the test asks.
pub struct ManualEnv {
    inner: IrqSafeSpinLock<ManualInner>,
}
#[derive(Default)]
struct ManualInner {
    now_ns: u64,
    work: Vec<Arc<RuntimePmDevice>>,
    timers: Vec<(u64, Arc<RuntimePmDevice>)>,
}
impl fmt::Debug for ManualEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let i = self.inner.lock();
        f.debug_struct("ManualEnv")
            .field("now_ns", &i.now_ns)
            .field("work", &i.work.len())
            .field("timers", &i.timers.len())
            .finish()
    }
}
impl ManualEnv {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: IrqSafeSpinLock::new(ManualInner::default()),
        })
    }
    pub fn advance_ms(&self, ms: u64) {
        self.inner.lock().now_ns += ms * 1_000_000;
    }
    pub fn now_ms(&self) -> u64 {
        self.inner.lock().now_ns / 1_000_000
    }
    /// Queued work items.
    pub fn pending_work(&self) -> usize {
        self.inner.lock().work.len()
    }
    /// Armed timers (fired or not).
    pub fn armed_timers(&self) -> usize {
        self.inner.lock().timers.len()
    }
    /// Fire due timers and drain queued work until nothing is left to do
    /// at the current fake time. Returns the number of items run.
    pub async fn run_pending(&self) -> usize {
        let mut ran = 0;
        loop {
            let (timer, work) = {
                let mut i = self.inner.lock();
                let now = i.now_ns;
                let timer = i
                    .timers
                    .iter()
                    .position(|(at, _)| *at <= now)
                    .map(|k| i.timers.remove(k).1);
                let work = if timer.is_none() && !i.work.is_empty() {
                    Some(i.work.remove(0))
                } else {
                    None
                };
                (timer, work)
            };
            match (timer, work) {
                (Some(dev), _) => dev.timer_fn(),
                (None, Some(dev)) => dev.run_work().await,
                (None, None) => return ran,
            }
            ran += 1;
        }
    }
}
impl RpmEnv for ManualEnv {
    fn now_ns(&self) -> u64 {
        self.inner.lock().now_ns
    }
    fn queue_work(&self, dev: Arc<RuntimePmDevice>) {
        self.inner.lock().work.push(dev);
    }
    fn arm_timer(&self, dev: Arc<RuntimePmDevice>, expires_ns: u64) {
        self.inner.lock().timers.push((expires_ns, dev));
    }
}
