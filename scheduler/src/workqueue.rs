//! Workqueues — Linux `kernel/workqueue.c` (concurrency-managed workqueues).
//!
//! A [`WorkStruct`] is a deferred function call. [`queue_work`] puts it on a
//! worker pool; a pool worker — an executor task — runs it in task context,
//! where it may allocate and, for async work, sleep. A [`DelayedWork`] is a
//! work plus a timer-wheel `timer_list` that queues it when it expires.
//!
//! * **Pools.** Every CPU has a normal and a high-priority pool whose
//!   workers are pinned to it; one unbound pool's workers run anywhere. A
//!   workqueue ([`Workqueue`], `struct workqueue_struct`) is bound (work runs
//!   on the queueing CPU's pool) or `WQ_UNBOUND`. The system workqueues
//!   (`system_wq`, `system_highpri_wq`, `system_long_wq`,
//!   `system_unbound_wq`, `system_power_efficient_wq`) exist from boot.
//! * **Concurrency management.** A pool counts its workers that are
//!   executing and not asleep (`nr_running`). Synchronous work never sleeps:
//!   it runs to completion on its worker, as a Linux work that does not
//!   block. Async work is a future; when it returns `Pending` its worker is
//!   asleep (`wq_worker_sleeping`) and, if the pool has queued work and no
//!   running worker left, a new worker is created (`kick_pool` /
//!   `create_worker`), so one sleeping work never stalls the pool. Queueing
//!   onto a pool with no running worker creates one, or, from interrupt
//!   context, arms the pool's manager timer to create it on the next jiffy.
//!   Where NARF cannot follow Linux: idle workers are not kept (a worker
//!   exits when its pool's worklist is empty, where Linux keeps it for
//!   `IDLE_WORKER_TIMEOUT`), because a parked task would keep its CPU's
//!   executor from ever draining; a synchronous work that spins holds its
//!   worker's CPU just as a kthread spinning with preemption off would — the
//!   executor does not preempt a polled task to run a sibling worker; and
//!   the high-priority pools run at the default task priority.
//! * **`max_active`** bounds the works of one workqueue executing at once;
//!   the rest wait on the workqueue's inactive list in queue order. An
//!   ordered workqueue ([`alloc_ordered_workqueue`]) is unbound with
//!   `max_active = 1`.
//! * **`WQ_MEM_RECLAIM`** workqueues have a rescuer. When a pool needs
//!   another worker but is at its worker limit (Linux: worker creation
//!   failed under memory pressure), it sends its queued works of
//!   rescuer-backed workqueues to their rescuers (`send_mayday`), which run
//!   them, so reclaim-path work keeps making progress past a pool full of
//!   sleeping workers. NARF's task creation does not fail, so the rescuer is
//!   a task started on the mayday (and exiting when done) rather than a
//!   thread created with the workqueue.
//! * **Cancel and flush.** [`cancel_work_sync`] / [`cancel_delayed_work_sync`]
//!   take the work off its timer or worklist (`try_to_grab_pending`) and wait
//!   out a running instance; [`flush_work`] waits until the last queued
//!   instance has finished. The wheel never touches a work after its
//!   function returned, so a work function may free its work: completion is
//!   tracked by the pool (`busy_hash`), by address and queue sequence.
//!
//! `queue_work` and `queue_delayed_work` neither allocate nor block: they are
//! callable from timer callbacks and interrupt handlers.
//!
//! Lock order: workqueue lock → pool lock. Busy and flush bookkeeping is
//! under the pool lock; flush waiters under their own lock, taken alone.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::future::Future;
use core::pin::Pin;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};

use narf_lib::percpu::MAX_CPUS;
use narf_lib::sync::IrqSafeSpinLock;
use narf_time::timer::{self as wheel, TimerList, TimerRef};

use crate::{Affinity, CpuId, TaskSpec};

/// A sleeping (async) work's future.
pub type WorkFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// What a work runs (`work_func_t`).
#[derive(Copy, Clone)]
pub enum WorkFn {
    /// Runs to completion without sleeping.
    Sync(fn(WorkRef)),
    /// May sleep: its worker counts as asleep while the future is pending.
    Async(fn(WorkRef) -> WorkFuture),
}

impl core::fmt::Debug for WorkFn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            WorkFn::Sync(_) => "Sync",
            WorkFn::Async(_) => "Async",
        })
    }
}

/// The work being run, as handed to its function. A pointer, not a borrow:
/// the function may free the work (the pool never touches it afterwards).
#[derive(Copy, Clone, Debug)]
pub struct WorkRef(*const WorkStruct);

// SAFETY: a `WorkStruct` is `Sync`; the owner keeps it alive while it is
// queued or running (queue contract), which is all a `WorkRef` is used for.
unsafe impl Send for WorkRef {}
// SAFETY: as above.
unsafe impl Sync for WorkRef {}

impl WorkRef {
    /// The work. Valid until the work function frees it.
    pub fn work(&self) -> &WorkStruct {
        // SAFETY: queue contract (see the type doc).
        unsafe { &*self.0 }
    }

    /// Raw pointer, for `container_of`.
    pub fn as_ptr(&self) -> *const WorkStruct {
        self.0
    }

    /// The enclosing [`DelayedWork`] (`to_delayed_work`).
    ///
    /// # Safety
    /// The work must be the `work` field of a `DelayedWork`.
    pub unsafe fn delayed(&self) -> &DelayedWork {
        // SAFETY: `work` is the first field of the repr(C) `DelayedWork`.
        unsafe { &*(self.0 as *const DelayedWork) }
    }
}

/// `WORK_STRUCT_PENDING`: queued, or on its way (timer, transfer).
const PENDING: u32 = 1 << 0;
/// Linked into a pool worklist (`work.pool`).
const ON_POOL: u32 = 1 << 1;
/// Linked into its workqueue's inactive list (`max_active` reached).
const INACTIVE: u32 = 1 << 2;
/// Linked into its workqueue's rescuer list.
const ON_RESCUER: u32 = 1 << 3;
/// A canceler owns `PENDING`; queueing fails until it is done.
const CANCELING: u32 = 1 << 4;

/// `struct work_struct`. Caller-owned; must stay at its address while
/// pending or running and must not be freed before [`cancel_work_sync`]
/// returned (or by its own function).
#[repr(C)]
pub struct WorkStruct {
    next: UnsafeCell<*mut WorkStruct>,
    prev: UnsafeCell<*mut WorkStruct>,
    func: WorkFn,
    flags: AtomicU32,
    /// Pool whose list holds it, or the one it will run on.
    pool: AtomicPtr<Pool>,
    /// Workqueue it was last queued on.
    wq: AtomicPtr<Workqueue>,
    /// Times it went idle → pending (flush target).
    queued_seq: AtomicU64,
}

// SAFETY: the links are touched only under the lock of the list holding the
// work (named by `flags` + `pool` / `wq`); everything else is atomic.
unsafe impl Sync for WorkStruct {}
// SAFETY: as above.
unsafe impl Send for WorkStruct {}

impl core::fmt::Debug for WorkStruct {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WorkStruct")
            .field("func", &self.func)
            .field("flags", &self.flags.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl WorkStruct {
    /// `INIT_WORK`.
    pub const fn new(func: WorkFn) -> Self {
        Self {
            next: UnsafeCell::new(ptr::null_mut()),
            prev: UnsafeCell::new(ptr::null_mut()),
            func,
            flags: AtomicU32::new(0),
            pool: AtomicPtr::new(ptr::null_mut()),
            wq: AtomicPtr::new(ptr::null_mut()),
            queued_seq: AtomicU64::new(0),
        }
    }

    /// `work_pending`.
    pub fn is_pending(&self) -> bool {
        self.flags.load(Ordering::Acquire) & PENDING != 0
    }

    fn me(&self) -> *mut WorkStruct {
        self as *const WorkStruct as *mut WorkStruct
    }
}

// ── intrusive work lists (lock of the owner held) ───────────────────────

struct WorkList {
    head: *mut WorkStruct,
    tail: *mut WorkStruct,
    len: usize,
}

impl WorkList {
    const fn new() -> Self {
        Self {
            head: ptr::null_mut(),
            tail: ptr::null_mut(),
            len: 0,
        }
    }

    /// # Safety
    /// `w` is unlinked and stays put while linked; the list's lock is held.
    unsafe fn push_back(&mut self, w: &WorkStruct) {
        let me = w.me();
        // SAFETY: caller contract.
        unsafe {
            *w.next.get() = ptr::null_mut();
            *w.prev.get() = self.tail;
            if self.tail.is_null() {
                self.head = me;
            } else {
                *(*self.tail).next.get() = me;
            }
        }
        self.tail = me;
        self.len += 1;
    }

    /// # Safety
    /// `w` is linked into this list; its lock is held.
    unsafe fn unlink(&mut self, w: &WorkStruct) {
        // SAFETY: caller contract.
        unsafe {
            let (n, p) = (*w.next.get(), *w.prev.get());
            if p.is_null() {
                self.head = n;
            } else {
                *(*p).next.get() = n;
            }
            if n.is_null() {
                self.tail = p;
            } else {
                *(*n).prev.get() = p;
            }
            *w.next.get() = ptr::null_mut();
            *w.prev.get() = ptr::null_mut();
        }
        self.len -= 1;
    }

    fn pop_front(&mut self) -> Option<&'static WorkStruct> {
        if self.head.is_null() {
            return None;
        }
        // SAFETY: linked works are live (queue contract), lock held.
        let w = unsafe { &*self.head };
        // SAFETY: `w` is linked here.
        unsafe { self.unlink(w) };
        Some(w)
    }
}

// SAFETY: raw work pointers guarded by the owner's lock.
unsafe impl Send for WorkList {}

// ── workqueues ──────────────────────────────────────────────────────────

/// `WQ_UNBOUND`: run on the unbound pool, any CPU.
pub const WQ_UNBOUND: u32 = 1 << 1;
/// `WQ_FREEZABLE` (accepted; NARF has no freezer yet).
pub const WQ_FREEZABLE: u32 = 1 << 2;
/// `WQ_MEM_RECLAIM`: has a rescuer; may be used on the reclaim path.
pub const WQ_MEM_RECLAIM: u32 = 1 << 3;
/// `WQ_HIGHPRI`: bound work runs on the CPU's high-priority pool.
pub const WQ_HIGHPRI: u32 = 1 << 4;
/// `WQ_POWER_EFFICIENT`: unbound (NARF always prefers power efficiency).
pub const WQ_POWER_EFFICIENT: u32 = 1 << 7;
/// `WQ_DFL_ACTIVE`.
pub const WQ_DFL_ACTIVE: usize = 256;

struct WqInner {
    nr_active: usize,
    inactive: WorkList,
}

/// `struct workqueue_struct`. Created once and never freed.
pub struct Workqueue {
    name: &'static str,
    flags: u32,
    max_active: usize,
    inner: IrqSafeSpinLock<WqInner>,
    rescuer: Option<Rescuer>,
}

impl core::fmt::Debug for Workqueue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Workqueue")
            .field("name", &self.name)
            .field("flags", &self.flags)
            .field("max_active", &self.max_active)
            .finish_non_exhaustive()
    }
}

struct Rescuer {
    list: IrqSafeSpinLock<WorkList>,
    /// The rescuer task is running (it clears this under `list`'s lock
    /// when it finds the list empty, and exits).
    running: AtomicBool,
}

/// `alloc_workqueue(name, flags, max_active)` (0 → `WQ_DFL_ACTIVE`). A
/// `WQ_MEM_RECLAIM` workqueue spawns its rescuer here. Task context.
pub fn alloc_workqueue(name: &'static str, flags: u32, max_active: usize) -> &'static Workqueue {
    let flags = if flags & WQ_POWER_EFFICIENT != 0 {
        flags | WQ_UNBOUND
    } else {
        flags
    };
    let wq: &'static Workqueue = Box::leak(Box::new(Workqueue {
        name,
        flags,
        max_active: if max_active == 0 {
            WQ_DFL_ACTIVE
        } else {
            max_active
        },
        inner: IrqSafeSpinLock::new(WqInner {
            nr_active: 0,
            inactive: WorkList::new(),
        }),
        rescuer: (flags & WQ_MEM_RECLAIM != 0).then(|| Rescuer {
            list: IrqSafeSpinLock::new(WorkList::new()),
            running: AtomicBool::new(false),
        }),
    }));
    wq
}

/// `alloc_ordered_workqueue`: one work at a time, in queue order.
pub fn alloc_ordered_workqueue(name: &'static str, flags: u32) -> &'static Workqueue {
    alloc_workqueue(name, flags | WQ_UNBOUND, 1)
}

impl Workqueue {
    /// The workqueue's name.
    pub fn name(&self) -> &'static str {
        self.name
    }
}

// ── pools ───────────────────────────────────────────────────────────────

/// Workers a pool may have; past this a pool sends mayday to rescuers.
pub const MAX_WORKERS_PER_POOL: usize = 64;

struct PoolInner {
    worklist: WorkList,
    nr_workers: usize,
    /// Workers spawned that have not reached their loop yet.
    nr_starting: usize,
    nr_running: usize,
    /// `busy_hash`: works executing on this pool, with the queue sequence of
    /// the instance (compared by address only; never dereferenced).
    busy: Vec<(usize, u64)>,
}

/// `struct worker_pool`.
#[repr(C)]
pub struct Pool {
    /// First field (the callback recovers the pool from it): `mayday_timer`
    /// / the manager's wake — fires when work was queued (possibly from
    /// interrupt context) on a pool with no worker to take it, and creates
    /// one, or past the limit sends mayday.
    mayday_timer: TimerList,
    cpu: Option<u32>,
    highpri: bool,
    inner: IrqSafeSpinLock<PoolInner>,
    /// Works run (diagnostic).
    nr_done: AtomicU64,
}

/// `MAYDAY_INTERVAL`: re-check a starved pool every 100 ms.
const MAYDAY_INTERVAL_JIFFIES: u64 = 100;

fn pool_mayday_fn(r: TimerRef) {
    // SAFETY: only pools use this callback; the timer is the first field of
    // the repr(C) `Pool`, and pools are leaked.
    let pool: &'static Pool = unsafe { &*(r.as_ptr() as *const Pool) };
    worker_needed(pool);
    let starved = {
        let g = pool.inner.lock();
        g.worklist.len != 0 && g.nr_running == 0 && g.nr_starting == 0
    };
    if starved {
        // SAFETY: the timer lives in a leaked pool.
        unsafe {
            wheel::mod_timer(
                &pool.mayday_timer,
                wheel::jiffies() + MAYDAY_INTERVAL_JIFFIES,
            )
        };
    }
}

/// Queued work found no worker: wake the manager on the next jiffy.
fn arm_mayday(pool: &'static Pool) {
    if !pool.mayday_timer.is_pending() {
        // SAFETY: the timer lives in a leaked pool.
        unsafe { wheel::mod_timer(&pool.mayday_timer, wheel::jiffies() + 1) };
    }
}

impl core::fmt::Debug for Pool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pool")
            .field("cpu", &self.cpu)
            .field("highpri", &self.highpri)
            .finish_non_exhaustive()
    }
}

static CPU_POOLS: [[AtomicPtr<Pool>; 2]; MAX_CPUS] =
    [const { [const { AtomicPtr::new(ptr::null_mut()) }; 2] }; MAX_CPUS];
static UNBOUND_POOL: AtomicPtr<Pool> = AtomicPtr::new(ptr::null_mut());

fn new_pool(cpu: Option<u32>, highpri: bool) -> &'static Pool {
    Box::leak(Box::new(Pool {
        mayday_timer: TimerList::new(
            pool_mayday_fn,
            if cpu.is_some() {
                wheel::TIMER_PINNED
            } else {
                0
            },
        ),
        cpu,
        highpri,
        inner: IrqSafeSpinLock::new(PoolInner {
            worklist: WorkList::new(),
            nr_workers: 0,
            nr_starting: 0,
            nr_running: 0,
            busy: Vec::new(),
        }),
        nr_done: AtomicU64::new(0),
    }))
}

fn publish(slot: &AtomicPtr<Pool>, cpu: Option<u32>, highpri: bool) -> &'static Pool {
    let p = slot.load(Ordering::Acquire);
    if !p.is_null() {
        // SAFETY: pools are leaked and never freed.
        return unsafe { &*p };
    }
    let fresh = new_pool(cpu, highpri);
    match slot.compare_exchange(
        ptr::null_mut(),
        fresh as *const Pool as *mut Pool,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => fresh,
        // SAFETY: as above. (The losing pool stays leaked: a cold path.)
        Err(p) => unsafe { &*p },
    }
}

/// `workqueue_init` for `cpu`: its two pools (workers come with work).
/// Task context (the scheduler's CPU startup, and boot for the unbound pool).
pub fn workqueue_prepare_cpu(cpu: usize) {
    if cpu >= MAX_CPUS {
        return;
    }
    publish(&CPU_POOLS[cpu][0], Some(cpu as u32), false);
    publish(&CPU_POOLS[cpu][1], Some(cpu as u32), true);
    publish(&UNBOUND_POOL, None, false);
}

fn pool_for(wq: &Workqueue, cpu: usize) -> Option<&'static Pool> {
    let slot = if wq.flags & WQ_UNBOUND != 0 {
        &UNBOUND_POOL
    } else {
        &CPU_POOLS[cpu.min(MAX_CPUS - 1)][usize::from(wq.flags & WQ_HIGHPRI != 0)]
    };
    let p = slot.load(Ordering::Acquire);
    if !p.is_null() {
        // SAFETY: pools are leaked and never freed.
        return Some(unsafe { &*p });
    }
    // First use on this CPU outside boot: create it unless that would
    // allocate in interrupt context; then fall back to the unbound pool.
    if !narf_lib::context::in_irq() {
        workqueue_prepare_cpu(cpu.min(MAX_CPUS - 1));
        let p = slot.load(Ordering::Acquire);
        // SAFETY: as above.
        return (!p.is_null()).then(|| unsafe { &*p });
    }
    let p = UNBOUND_POOL.load(Ordering::Acquire);
    // SAFETY: as above.
    (!p.is_null()).then(|| unsafe { &*p })
}

/// `create_worker`: spawn a worker task for `pool` (task context).
fn create_worker(pool: &'static Pool) {
    {
        let mut g = pool.inner.lock();
        g.nr_workers += 1;
        g.nr_starting += 1;
    }
    let spec = match pool.cpu {
        Some(cpu) => TaskSpec {
            affinity: Affinity::pinned(CpuId(cpu)),
            ..TaskSpec::kernel_any()
        },
        None => TaskSpec::kernel_any(),
    };
    crate::spawn_with_spec(worker_main(pool), spec);
}

/// `kick_pool` / `need_more_worker`: whether the pool has queued work and
/// no worker running or starting to take it (all asleep or gone).
fn kick_pool(g: &mut PoolInner) -> bool {
    g.worklist.len != 0 && g.nr_running == 0 && g.nr_starting == 0
}

/// Queued work found no worker: create one now, or — in interrupt context,
/// which may not allocate — from the manager timer on the next jiffy.
fn need_worker(pool: &'static Pool) {
    if narf_lib::context::in_irq() {
        arm_mayday(pool);
    } else {
        worker_needed(pool);
    }
}

// ── queueing ────────────────────────────────────────────────────────────

/// Insert pending `w` for execution on `pool` (`__queue_work` →
/// `insert_work`), or park it on `wq`'s inactive list past `max_active`.
fn insert_work(wq: &'static Workqueue, pool: &'static Pool, w: &WorkStruct) {
    w.pool
        .store(pool as *const Pool as *mut Pool, Ordering::Release);
    w.wq.store(wq as *const Workqueue as *mut Workqueue, Ordering::Release);
    let mut wg = wq.inner.lock();
    if wg.nr_active >= wq.max_active {
        // SAFETY: pending and unlinked, owned by this queueing; kept in place
        // by the queue contract.
        unsafe { wg.inactive.push_back(w) };
        w.flags.fetch_or(INACTIVE, Ordering::AcqRel);
        return;
    }
    wg.nr_active += 1;
    let need = {
        let mut pg = pool.inner.lock();
        // SAFETY: as above.
        unsafe { pg.worklist.push_back(w) };
        w.flags.fetch_or(ON_POOL, Ordering::AcqRel);
        kick_pool(&mut pg)
    };
    drop(wg);
    if need {
        need_worker(pool);
    }
}

/// `queue_work_on(cpu, wq, work)`: queue on `cpu`'s pool (the unbound pool
/// for an unbound workqueue). Returns false if it was already pending.
/// Neither allocates nor blocks once the pools exist.
///
/// # Safety
/// `w` must stay at its address and not be freed until it is neither
/// pending nor running ([`cancel_work_sync`]), or by its own function.
pub unsafe fn queue_work_on(cpu: usize, wq: &'static Workqueue, w: &WorkStruct) -> bool {
    let prev = w.flags.fetch_or(PENDING, Ordering::AcqRel);
    if prev & PENDING != 0 {
        return false;
    }
    w.queued_seq.fetch_add(1, Ordering::AcqRel);
    let Some(pool) = pool_for(wq, cpu) else {
        // No pool can exist yet (interrupt context before boot set them up).
        w.flags.fetch_and(!PENDING, Ordering::AcqRel);
        return false;
    };
    insert_work(wq, pool, w);
    true
}

/// `queue_work`: queue on this CPU's pool.
///
/// # Safety
/// As for [`queue_work_on`].
pub unsafe fn queue_work(wq: &'static Workqueue, w: &WorkStruct) -> bool {
    // SAFETY: caller contract.
    unsafe { queue_work_on(narf_lib::percpu::current_cpu(), wq, w) }
}

/// `schedule_work`: [`queue_work`] on `system_wq`.
///
/// # Safety
/// As for [`queue_work_on`].
pub unsafe fn schedule_work(w: &WorkStruct) -> bool {
    // SAFETY: caller contract.
    unsafe { queue_work(system_wq(), w) }
}

// ── delayed work ────────────────────────────────────────────────────────

/// `struct delayed_work`: a work and the timer that queues it.
#[repr(C)]
pub struct DelayedWork {
    /// First field: a `WorkRef` of it is a `DelayedWork` pointer.
    pub work: WorkStruct,
    timer: TimerList,
    target_wq: AtomicPtr<Workqueue>,
    /// CPU to queue on (`usize::MAX`: the CPU the timer fires on).
    cpu: AtomicUsize,
}

impl core::fmt::Debug for DelayedWork {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DelayedWork")
            .field("work", &self.work)
            .finish_non_exhaustive()
    }
}

const WORK_CPU_UNBOUND: usize = usize::MAX;

impl DelayedWork {
    /// `INIT_DELAYED_WORK` (`deferrable`: `INIT_DEFERRABLE_WORK`, whose
    /// timer never wakes an idle CPU).
    pub const fn new(func: WorkFn, deferrable: bool) -> Self {
        Self {
            work: WorkStruct::new(func),
            timer: TimerList::new(
                delayed_work_timer_fn,
                if deferrable {
                    wheel::TIMER_DEFERRABLE
                } else {
                    0
                },
            ),
            target_wq: AtomicPtr::new(ptr::null_mut()),
            cpu: AtomicUsize::new(WORK_CPU_UNBOUND),
        }
    }

    /// `delayed_work_pending`.
    pub fn is_pending(&self) -> bool {
        self.work.is_pending()
    }
}

/// `delayed_work_timer_fn`: the delay passed; queue the work.
fn delayed_work_timer_fn(r: TimerRef) {
    // SAFETY: only `DelayedWork` timers use this callback; `timer` follows
    // `work` in the repr(C) struct, so step back to the struct.
    let dw = unsafe {
        &*((r.as_ptr() as *const u8).sub(core::mem::offset_of!(DelayedWork, timer))
            as *const DelayedWork)
    };
    let wq = dw.target_wq.load(Ordering::Acquire);
    if wq.is_null() {
        return;
    }
    // SAFETY: workqueues are leaked and never freed.
    let wq: &'static Workqueue = unsafe { &*wq };
    let cpu = match dw.cpu.load(Ordering::Acquire) {
        WORK_CPU_UNBOUND => narf_lib::percpu::current_cpu(),
        c => c,
    };
    match pool_for(wq, cpu) {
        Some(pool) => insert_work(wq, pool, &dw.work),
        None => {
            dw.work.flags.fetch_and(!PENDING, Ordering::AcqRel);
        }
    }
}

/// `__queue_delayed_work`: `PENDING` already owned by the caller.
fn start_delayed(cpu: usize, wq: &'static Workqueue, dw: &DelayedWork, delay_jiffies: u64) {
    dw.target_wq
        .store(wq as *const Workqueue as *mut Workqueue, Ordering::Release);
    dw.cpu.store(cpu, Ordering::Release);
    if delay_jiffies == 0 {
        let qcpu = if cpu == WORK_CPU_UNBOUND {
            narf_lib::percpu::current_cpu()
        } else {
            cpu
        };
        match pool_for(wq, qcpu) {
            Some(pool) => insert_work(wq, pool, &dw.work),
            None => {
                dw.work.flags.fetch_and(!PENDING, Ordering::AcqRel);
            }
        }
        return;
    }
    let expires = wheel::jiffies() + delay_jiffies;
    // SAFETY: the timer lives in the caller-owned `DelayedWork`, kept in
    // place by the queue contract.
    unsafe {
        if cpu == WORK_CPU_UNBOUND {
            wheel::mod_timer(&dw.timer, expires);
        } else {
            wheel::add_timer_on(&dw.timer, expires, cpu);
        }
    }
}

/// `queue_delayed_work_on`: queue `dw` after `delay_jiffies`. Returns false
/// if it was already pending (its delay is left as it was).
///
/// # Safety
/// As for [`queue_work_on`], for the whole `DelayedWork`.
pub unsafe fn queue_delayed_work_on(
    cpu: usize,
    wq: &'static Workqueue,
    dw: &DelayedWork,
    delay_jiffies: u64,
) -> bool {
    if dw.work.flags.fetch_or(PENDING, Ordering::AcqRel) & PENDING != 0 {
        return false;
    }
    dw.work.queued_seq.fetch_add(1, Ordering::AcqRel);
    start_delayed(cpu, wq, dw, delay_jiffies);
    true
}

/// `queue_delayed_work`: on whichever CPU the timer fires.
///
/// # Safety
/// As for [`queue_delayed_work_on`].
pub unsafe fn queue_delayed_work(
    wq: &'static Workqueue,
    dw: &DelayedWork,
    delay_jiffies: u64,
) -> bool {
    // SAFETY: caller contract.
    unsafe { queue_delayed_work_on(WORK_CPU_UNBOUND, wq, dw, delay_jiffies) }
}

/// `schedule_delayed_work`: on `system_wq`.
///
/// # Safety
/// As for [`queue_delayed_work_on`].
pub unsafe fn schedule_delayed_work(dw: &DelayedWork, delay_jiffies: u64) -> bool {
    // SAFETY: caller contract.
    unsafe { queue_delayed_work(system_wq(), dw, delay_jiffies) }
}

/// `mod_delayed_work_on`: (re)queue `dw` to run `delay_jiffies` from now,
/// whether or not it was pending. Returns whether it was pending.
///
/// # Safety
/// As for [`queue_delayed_work_on`].
pub unsafe fn mod_delayed_work_on(
    cpu: usize,
    wq: &'static Workqueue,
    dw: &DelayedWork,
    delay_jiffies: u64,
) -> bool {
    let was = loop {
        match try_to_grab_pending(&dw.work, Some(&dw.timer)) {
            Grab::Grabbed(was) => break was,
            Grab::Canceling => return false,
            Grab::Retry => core::hint::spin_loop(),
        }
    };
    if !was {
        dw.work.queued_seq.fetch_add(1, Ordering::AcqRel);
    }
    start_delayed(cpu, wq, dw, delay_jiffies);
    was
}

/// `mod_delayed_work` on whichever CPU the timer fires.
///
/// # Safety
/// As for [`queue_delayed_work_on`].
pub unsafe fn mod_delayed_work(
    wq: &'static Workqueue,
    dw: &DelayedWork,
    delay_jiffies: u64,
) -> bool {
    // SAFETY: caller contract.
    unsafe { mod_delayed_work_on(WORK_CPU_UNBOUND, wq, dw, delay_jiffies) }
}

// ── grabbing, cancel, flush ─────────────────────────────────────────────

enum Grab {
    /// The caller owns `PENDING` now; the bool says whether the work was
    /// queued (or its timer armed) before.
    Grabbed(bool),
    /// Another canceler owns it.
    Canceling,
    /// In transit (a timer callback queueing it); try again.
    Retry,
}

/// `try_to_grab_pending`: take the work off its timer or list, leaving
/// `PENDING` owned by the caller.
fn try_to_grab_pending(w: &WorkStruct, timer: Option<&TimerList>) -> Grab {
    if let Some(t) = timer {
        if wheel::del_timer(t) {
            // The armed timer owned PENDING; now the caller does.
            return Grab::Grabbed(true);
        }
    }
    if w.flags.fetch_or(PENDING, Ordering::AcqRel) & PENDING == 0 {
        return Grab::Grabbed(false);
    }
    if w.flags.load(Ordering::Acquire) & CANCELING != 0 {
        return Grab::Canceling;
    }
    let wq = w.wq.load(Ordering::Acquire);
    let pool = w.pool.load(Ordering::Acquire);
    if wq.is_null() || pool.is_null() {
        return Grab::Retry;
    }
    // SAFETY: workqueues and pools are leaked and never freed.
    let (wq, pool): (&'static Workqueue, &'static Pool) = unsafe { (&*wq, &*pool) };
    let mut wg = wq.inner.lock();
    let f = w.flags.load(Ordering::Acquire);
    if f & INACTIVE != 0 {
        // SAFETY: INACTIVE under this lock ⇒ linked on the inactive list.
        unsafe { wg.inactive.unlink(w) };
        w.flags.fetch_and(!INACTIVE, Ordering::AcqRel);
        return Grab::Grabbed(true);
    }
    if f & ON_RESCUER != 0 {
        if let Some(r) = wq.rescuer.as_ref() {
            let mut rl = r.list.lock();
            if w.flags.load(Ordering::Acquire) & ON_RESCUER != 0 {
                // SAFETY: ON_RESCUER under the rescuer lock ⇒ linked there.
                unsafe { rl.unlink(w) };
                w.flags.fetch_and(!ON_RESCUER, Ordering::AcqRel);
                wg.nr_active -= 1;
                activate_inactive(&mut wg);
                return Grab::Grabbed(true);
            }
        }
        return Grab::Retry;
    }
    let mut pg = pool.inner.lock();
    if w.flags.load(Ordering::Acquire) & ON_POOL != 0 {
        // SAFETY: ON_POOL under the pool lock ⇒ linked on its worklist.
        unsafe { pg.worklist.unlink(w) };
        w.flags.fetch_and(!ON_POOL, Ordering::AcqRel);
        drop(pg);
        wg.nr_active -= 1;
        activate_inactive(&mut wg);
        return Grab::Grabbed(true);
    }
    Grab::Retry
}

/// One inactive work becomes active, if `max_active` allows
/// (`pwq_activate_first_inactive`). Workqueue lock held.
fn activate_inactive(wg: &mut WqInner) {
    // `max_active` is checked by the caller's accounting: called right
    // after an active slot was released.
    let Some(w) = wg.inactive.pop_front() else {
        return;
    };
    w.flags.fetch_and(!INACTIVE, Ordering::AcqRel);
    let pool = w.pool.load(Ordering::Acquire);
    if pool.is_null() {
        return;
    }
    // SAFETY: pools are leaked.
    let pool: &'static Pool = unsafe { &*pool };
    wg.nr_active += 1;
    let need_worker = {
        let mut pg = pool.inner.lock();
        // SAFETY: just unlinked; still pending and owned by its queueing.
        unsafe { pg.worklist.push_back(w) };
        w.flags.fetch_or(ON_POOL, Ordering::AcqRel);
        kick_pool(&mut pg)
    };
    if need_worker {
        // The workqueue lock is held: no worker is created under it; the
        // manager timer does on the next jiffy.
        arm_mayday(pool);
    }
}

/// Whether an instance of `w` queued at or before `seq` is executing on
/// any pool.
fn running_upto(w: &WorkStruct, seq: u64) -> bool {
    let addr = w as *const WorkStruct as usize;
    let check = |slot: &AtomicPtr<Pool>| {
        let p = slot.load(Ordering::Acquire);
        // SAFETY: pools are leaked.
        !p.is_null()
            && unsafe { &*p }
                .inner
                .lock()
                .busy
                .iter()
                .any(|&(a, s)| a == addr && s <= seq)
    };
    check(&UNBOUND_POOL) || CPU_POOLS.iter().any(|p| check(&p[0]) || check(&p[1]))
}

/// Flush waiters, woken whenever a work finishes.
static FLUSH_WAITERS: IrqSafeSpinLock<Vec<Waker>> = IrqSafeSpinLock::new(Vec::new());
static NR_FLUSH_WAITERS: AtomicUsize = AtomicUsize::new(0);

fn wake_flushers() {
    if NR_FLUSH_WAITERS.load(Ordering::Acquire) == 0 {
        return;
    }
    let ws = core::mem::take(&mut *FLUSH_WAITERS.lock());
    for w in ws {
        w.wake();
    }
}

/// Resolves once `done` holds; re-checked whenever any work finishes.
struct WaitUntil<F: FnMut() -> bool>(F);

impl<F: FnMut() -> bool + Unpin> Future for WaitUntil<F> {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if (self.0)() {
            return Poll::Ready(());
        }
        NR_FLUSH_WAITERS.fetch_add(1, Ordering::AcqRel);
        FLUSH_WAITERS.lock().push(cx.waker().clone());
        NR_FLUSH_WAITERS.fetch_sub(1, Ordering::AcqRel);
        // Re-check after registering: a completion in between woke nobody.
        if (self.0)() {
            return Poll::Ready(());
        }
        Poll::Pending
    }
}

/// Whether the instance queued at `seq` (and all before it) has finished.
fn flushed(w: &WorkStruct, seq: u64) -> bool {
    let pending_old = w.is_pending() && w.queued_seq.load(Ordering::Acquire) <= seq;
    !pending_old && !running_upto(w, seq)
}

/// `flush_work`: wait until the last queued instance of `w` has finished.
/// Returns whether there was one to wait for.
pub async fn flush_work(w: &WorkStruct) -> bool {
    let seq = w.queued_seq.load(Ordering::Acquire);
    if flushed(w, seq) {
        return false;
    }
    WaitUntil(|| flushed(w, seq)).await;
    true
}

/// `__cancel_work(work, WORK_CANCEL_SYNC)` for `w` with optional timer.
async fn cancel_sync(w: &WorkStruct, timer: Option<&TimerList>) -> bool {
    let was = loop {
        match try_to_grab_pending(w, timer) {
            Grab::Grabbed(was) => break was,
            // Another canceler: wait for it, then grab ourselves.
            Grab::Canceling | Grab::Retry => crate::yield_now().await,
        }
    };
    w.flags.fetch_or(CANCELING, Ordering::AcqRel);
    // Wait out every running instance.
    let seq = w.queued_seq.load(Ordering::Acquire);
    WaitUntil(|| !running_upto(w, seq)).await;
    w.flags.fetch_and(!(CANCELING | PENDING), Ordering::AcqRel);
    wake_flushers();
    was
}

/// `cancel_work_sync`: take `w` off its worklist and wait for a running
/// instance. Returns whether it was pending.
pub async fn cancel_work_sync(w: &WorkStruct) -> bool {
    cancel_sync(w, None).await
}

/// `cancel_delayed_work_sync`.
pub async fn cancel_delayed_work_sync(dw: &DelayedWork) -> bool {
    cancel_sync(&dw.work, Some(&dw.timer)).await
}

/// `cancel_delayed_work`: take it off its timer or worklist without
/// waiting for a running instance. Returns whether it was pending.
pub fn cancel_delayed_work(dw: &DelayedWork) -> bool {
    loop {
        match try_to_grab_pending(&dw.work, Some(&dw.timer)) {
            Grab::Grabbed(was) => {
                dw.work.flags.fetch_and(!PENDING, Ordering::AcqRel);
                wake_flushers();
                return was;
            }
            Grab::Canceling => return false,
            Grab::Retry => core::hint::spin_loop(),
        }
    }
}

/// [`cancel_work_sync`] for synchronous callers outside an executor poll
/// (teardown paths): spins with executor rounds until done.
pub fn cancel_work_sync_blocking(w: &WorkStruct) -> bool {
    drive(cancel_work_sync(w))
}

/// [`cancel_delayed_work_sync`] for synchronous callers (see
/// [`cancel_work_sync_blocking`]).
pub fn cancel_delayed_work_sync_blocking(dw: &DelayedWork) -> bool {
    drive(cancel_delayed_work_sync(dw))
}

/// [`flush_work`] for synchronous callers.
pub fn flush_work_blocking(w: &WorkStruct) -> bool {
    drive(flush_work(w))
}

/// Poll `f` to completion, running executor rounds (the workers) between
/// polls so the work being waited for can finish on this CPU too.
fn drive<F: Future>(f: F) -> F::Output {
    let mut f = core::pin::pin!(f);
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        // A nested executor round: it runs this CPU's workers (and expires
        // its timers), whose completion `f` is waiting for.
        let _ = crate::poll_one_round_nested();
        core::hint::spin_loop();
    }
}

// ── workers ─────────────────────────────────────────────────────────────

/// Runs an async work, keeping the pool's `nr_running` honest across its
/// sleeps (`wq_worker_sleeping` / `wq_worker_running`).
struct Tracked {
    fut: WorkFuture,
    pool: &'static Pool,
    asleep: bool,
}

impl Future for Tracked {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let pool = self.pool;
        if self.asleep {
            pool.inner.lock().nr_running += 1;
            self.asleep = false;
        }
        match self.fut.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(()),
            Poll::Pending => {
                self.asleep = true;
                let need_worker = {
                    let mut g = pool.inner.lock();
                    g.nr_running -= 1;
                    kick_pool(&mut g)
                };
                if need_worker {
                    worker_needed(pool);
                }
                Poll::Pending
            }
        }
    }
}

/// The pool has work and no worker to run it: create one (`create_worker`),
/// or past the limit send its rescuer-backed work to the rescuers
/// (`send_mayday`). Task or timer context.
fn worker_needed(pool: &'static Pool) {
    let (at_limit, starting) = {
        let g = pool.inner.lock();
        (g.nr_workers >= MAX_WORKERS_PER_POOL, g.nr_starting != 0)
    };
    if starting {
        // One is on its way and will take the work.
        return;
    }
    if !at_limit {
        create_worker(pool);
        return;
    }
    send_mayday(pool);
}

/// `send_mayday`: move this pool's queued works of `WQ_MEM_RECLAIM`
/// workqueues to their rescuers.
fn send_mayday(pool: &'static Pool) {
    let mut moved: Vec<&'static WorkStruct> = Vec::new();
    {
        let mut g = pool.inner.lock();
        let mut cur = g.worklist.head;
        while !cur.is_null() {
            // SAFETY: linked works are live; pool lock held.
            let w = unsafe { &*cur };
            // SAFETY: as above.
            cur = unsafe { *w.next.get() };
            let wq = w.wq.load(Ordering::Acquire);
            // SAFETY: workqueues are leaked.
            if !wq.is_null() && unsafe { &*wq }.rescuer.is_some() {
                // SAFETY: ON_POOL here.
                unsafe { g.worklist.unlink(w) };
                w.flags.fetch_and(!ON_POOL, Ordering::AcqRel);
                moved.push(w);
            }
        }
    }
    for w in moved {
        // SAFETY: as above.
        let wq: &'static Workqueue = unsafe { &*w.wq.load(Ordering::Acquire) };
        let Some(r) = wq.rescuer.as_ref() else {
            continue;
        };
        // SAFETY: just unlinked; still pending.
        unsafe { r.list.lock().push_back(w) };
        w.flags.fetch_or(ON_RESCUER, Ordering::AcqRel);
        MAYDAYS.fetch_add(1, Ordering::Relaxed);
        // `wake_up_process(wq->rescuer)`: start it unless it is running (a
        // running rescuer takes the work before it exits).
        if !r.running.swap(true, Ordering::AcqRel) {
            crate::spawn_with_spec(rescuer_main(wq), TaskSpec::kernel_any());
        }
    }
}

static MAYDAYS: AtomicU64 = AtomicU64::new(0);

/// Works handed to rescuers since boot (diagnostic, tests).
pub fn maydays() -> u64 {
    MAYDAYS.load(Ordering::Relaxed)
}

/// Run one dequeued work on `pool` (shared by workers and rescuers).
async fn process_one(pool: &'static Pool, w: &'static WorkStruct) {
    let addr = w as *const WorkStruct as usize;
    let seq = w.queued_seq.load(Ordering::Acquire);
    let wq: Option<&'static Workqueue> = {
        let p = w.wq.load(Ordering::Acquire);
        // SAFETY: workqueues are leaked and never freed.
        (!p.is_null()).then(|| unsafe { &*p })
    };
    pool.inner.lock().busy.push((addr, seq));
    // `set_work_pool_and_clear_pending`: from here the work may requeue
    // itself, and may free itself — nothing below reads `w`.
    w.flags.fetch_and(!PENDING, Ordering::AcqRel);
    let func = w.func;
    let r = WorkRef(addr as *const WorkStruct);
    match func {
        WorkFn::Sync(f) => f(r),
        WorkFn::Async(f) => {
            Tracked {
                fut: f(r),
                pool,
                asleep: false,
            }
            .await
        }
    }
    {
        let mut g = pool.inner.lock();
        if let Some(pos) = g.busy.iter().position(|&(a, s)| a == addr && s == seq) {
            g.busy.swap_remove(pos);
        }
    }
    pool.nr_done.fetch_add(1, Ordering::Relaxed);
    if let Some(wq) = wq {
        let mut wg = wq.inner.lock();
        wg.nr_active -= 1;
        activate_inactive(&mut wg);
    }
    wake_flushers();
}

/// `worker_thread`. Runs works while the pool has any, then exits: an idle
/// worker parked for ever would keep this CPU's executor from ever draining
/// (the in-kernel test harness drains it), so idle workers are not kept —
/// Linux keeps them for `IDLE_WORKER_TIMEOUT`. The next queueing creates a
/// worker again.
async fn worker_main(pool: &'static Pool) {
    {
        let mut g = pool.inner.lock();
        g.nr_starting -= 1;
        g.nr_running += 1;
    }
    loop {
        let w = {
            let mut g = pool.inner.lock();
            if let Some(w) = g.worklist.pop_front() {
                w.flags.fetch_and(!ON_POOL, Ordering::AcqRel);
                w
            } else {
                // Under the pool lock: a queueing after this sees one
                // worker fewer and creates one.
                g.nr_running -= 1;
                g.nr_workers -= 1;
                return;
            }
        };
        process_one(pool, w).await;
        // Let the CPU's other tasks run between works. This worker still
        // counts as running: queued work waits for it rather than for a new
        // worker.
        crate::yield_now().await;
    }
}

/// `rescuer_thread` for `wq`: runs the works sent to it, then exits (it is
/// started again by the next mayday).
async fn rescuer_main(wq: &'static Workqueue) {
    let Some(r) = wq.rescuer.as_ref() else { return };
    loop {
        let next = {
            let mut list = r.list.lock();
            let w = list.pop_front();
            if w.is_none() {
                // Under the list lock: a mayday after this starts another.
                r.running.store(false, Ordering::Release);
            }
            w
        };
        let Some(w) = next else { return };
        w.flags.fetch_and(!ON_RESCUER, Ordering::AcqRel);
        let pool: Option<&'static Pool> = {
            let p = w.pool.load(Ordering::Acquire);
            // SAFETY: pools are leaked.
            (!p.is_null()).then(|| unsafe { &*p })
        };
        let Some(pool) = pool else { continue };
        pool.inner.lock().nr_running += 1;
        process_one(pool, w).await;
        pool.inner.lock().nr_running -= 1;
    }
}

// ── system workqueues ───────────────────────────────────────────────────

static SYSTEM_WQ: AtomicPtr<Workqueue> = AtomicPtr::new(ptr::null_mut());
static SYSTEM_HIGHPRI_WQ: AtomicPtr<Workqueue> = AtomicPtr::new(ptr::null_mut());
static SYSTEM_LONG_WQ: AtomicPtr<Workqueue> = AtomicPtr::new(ptr::null_mut());
static SYSTEM_UNBOUND_WQ: AtomicPtr<Workqueue> = AtomicPtr::new(ptr::null_mut());
static SYSTEM_POWER_EFFICIENT_WQ: AtomicPtr<Workqueue> = AtomicPtr::new(ptr::null_mut());

fn system(slot: &AtomicPtr<Workqueue>, name: &'static str, flags: u32) -> &'static Workqueue {
    let p = slot.load(Ordering::Acquire);
    if !p.is_null() {
        // SAFETY: workqueues are leaked.
        return unsafe { &*p };
    }
    let fresh = alloc_workqueue(name, flags, 0);
    match slot.compare_exchange(
        ptr::null_mut(),
        fresh as *const Workqueue as *mut Workqueue,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => fresh,
        // SAFETY: as above.
        Err(p) => unsafe { &*p },
    }
}

/// `system_wq`.
pub fn system_wq() -> &'static Workqueue {
    system(&SYSTEM_WQ, "events", 0)
}

/// `system_highpri_wq`.
pub fn system_highpri_wq() -> &'static Workqueue {
    system(&SYSTEM_HIGHPRI_WQ, "events_highpri", WQ_HIGHPRI)
}

/// `system_long_wq`.
pub fn system_long_wq() -> &'static Workqueue {
    system(&SYSTEM_LONG_WQ, "events_long", 0)
}

/// `system_unbound_wq`.
pub fn system_unbound_wq() -> &'static Workqueue {
    system(&SYSTEM_UNBOUND_WQ, "events_unbound", WQ_UNBOUND)
}

/// `system_power_efficient_wq`.
pub fn system_power_efficient_wq() -> &'static Workqueue {
    system(
        &SYSTEM_POWER_EFFICIENT_WQ,
        "events_power_efficient",
        WQ_POWER_EFFICIENT,
    )
}

/// `workqueue_init`: the boot CPU's pools and the system workqueues (task
/// context, after the executor is up).
pub fn workqueue_init() {
    workqueue_prepare_cpu(narf_lib::percpu::current_cpu());
    let _ = (
        system_wq(),
        system_highpri_wq(),
        system_long_wq(),
        system_unbound_wq(),
        system_power_efficient_wq(),
    );
}

/// Forget every pool and system workqueue (their worker tasks were just
/// dropped by `__reset_queues_for_test`); the next use creates fresh ones.
/// The old pools and workqueues stay allocated.
#[doc(hidden)]
pub fn __reset_for_test() {
    for p in &CPU_POOLS {
        p[0].store(ptr::null_mut(), Ordering::Release);
        p[1].store(ptr::null_mut(), Ordering::Release);
    }
    UNBOUND_POOL.store(ptr::null_mut(), Ordering::Release);
    for w in [
        &SYSTEM_WQ,
        &SYSTEM_HIGHPRI_WQ,
        &SYSTEM_LONG_WQ,
        &SYSTEM_UNBOUND_WQ,
        &SYSTEM_POWER_EFFICIENT_WQ,
    ] {
        w.store(ptr::null_mut(), Ordering::Release);
    }
}

/// Workers of `cpu`'s normal pool (`None`: the unbound pool) (tests).
#[doc(hidden)]
pub fn __pool_workers(cpu: Option<usize>) -> usize {
    let slot = match cpu {
        Some(c) => &CPU_POOLS[c.min(MAX_CPUS - 1)][0],
        None => &UNBOUND_POOL,
    };
    let p = slot.load(Ordering::Acquire);
    // SAFETY: pools are leaked.
    (!p.is_null())
        .then(|| unsafe { &*p }.inner.lock().nr_workers)
        .unwrap_or(0)
}
