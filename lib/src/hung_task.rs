//! Uninterruptible kernel waits — Linux's `TASK_UNINTERRUPTIBLE` for async
//! kernel code, so the hung-task detector (`kernel/hung_task.c`
//! `check_hung_uninterruptible_tasks`) can see a kernel task, not only a
//! user task parked in a system call.
//!
//! A NARF kernel task has no sleep state: it is a future that returned
//! `Pending`. What it waits on is known only to the future it awaited, so
//! the waits Linux performs uninterruptibly record themselves here — an
//! async [`crate::mutex::Mutex`] waiter (Linux `mutex_lock`), a btrfs
//! transaction join or close (`wait_current_trans`,
//! `btrfs_commit_transaction`). A [`BlockedWait`] held by the waiting
//! future claims one slot of a fixed table on its first `Pending` and
//! releases it when the wait ends (`Ready`) or the future is dropped.
//!
//! The table is fixed-size and lock-free: claiming a slot is one
//! compare-exchange per slot tried, on the wait's slow path only; a wait
//! that finds the table full is counted ([`overflowed`]) and not tracked.
//! A reader ([`for_each_blocked`]) never blocks a waiter and allocates
//! nothing, so the stall watchdog can scan it from a timer interrupt.
//!
//! The scheduler installs the identity and clock hooks ([`set_hooks`]);
//! before it does, nothing is recorded.

use core::panic::Location;
use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};

/// What kind of wait a slot records: a name for the report and a label for
/// its kind-specific detail value.
#[derive(Debug)]
pub struct WaitKind {
    /// `mutex`, `btrfs txn join`, …
    pub name: &'static str,
    /// What [`BlockedInfo::detail`] is (`waiter`, `closer`, …).
    pub detail: &'static str,
}

/// An async [`crate::mutex::Mutex`] waiter; the detail is its waiter id.
pub static MUTEX: WaitKind = WaitKind {
    name: "mutex",
    detail: "waiter",
};

/// Slots in the table: more simultaneous uninterruptible kernel waits than
/// this are counted, not tracked.
pub const MAX_BLOCKED: usize = 256;

const NO_SLOT: u16 = u16::MAX;

/// One recorded wait. `owner == 0` is a free slot; `since_ns == 0` is a
/// slot being claimed or released, which readers skip.
#[repr(align(64))]
struct Slot {
    owner: AtomicU64,
    since_ns: AtomicU64,
    kind: AtomicPtr<WaitKind>,
    site: AtomicPtr<Location<'static>>,
    object: AtomicUsize,
    detail: AtomicU64,
}

static SLOTS: [Slot; MAX_BLOCKED] = [const {
    Slot {
        owner: AtomicU64::new(0),
        since_ns: AtomicU64::new(0),
        kind: AtomicPtr::new(core::ptr::null_mut()),
        site: AtomicPtr::new(core::ptr::null_mut()),
        object: AtomicUsize::new(0),
        detail: AtomicU64::new(0),
    }
}; MAX_BLOCKED];

static OVERFLOWED: AtomicU64 = AtomicU64::new(0);
static CURRENT_TASK_HOOK: AtomicUsize = AtomicUsize::new(0);
static NOW_NS_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install the hooks: `current_task` names the task being polled on this
/// CPU (0 outside any task), `now_ns` reads the monotonic clock. Both run
/// on a wait's slow path in any context and must not block or allocate.
pub fn set_hooks(current_task: fn() -> u64, now_ns: fn() -> u64) {
    CURRENT_TASK_HOOK.store(current_task as usize, Ordering::Release);
    NOW_NS_HOOK.store(now_ns as usize, Ordering::Release);
}

fn hook(slot: &AtomicUsize) -> Option<fn() -> u64> {
    match slot.load(Ordering::Acquire) {
        0 => None,
        // SAFETY: only `set_hooks` stores these slots, from `fn() -> u64`.
        f => Some(unsafe { core::mem::transmute::<usize, fn() -> u64>(f) }),
    }
}

/// The waiting task's identity: its scheduler task id, or — where there is
/// no task (a `block_on` bridge, an initcall) — the CPU with the top bit
/// set, never 0 and never a task's.
fn owner() -> u64 {
    let task = hook(&CURRENT_TASK_HOOK).map_or(0, |f| f());
    if task != 0 {
        task
    } else {
        (1 << 63) | crate::percpu::current_cpu() as u64
    }
}

/// Whether `owner` (a [`BlockedInfo::owner`]) names a CPU rather than a
/// task: the wait ran outside any scheduler task.
pub const fn owner_is_anonymous(owner: u64) -> bool {
    owner & (1 << 63) != 0
}

/// One future's uninterruptible wait. Hold it in the waiting future, call
/// [`Self::block`] on every `Pending` and [`Self::wake`] when the wait
/// ends; dropping it ends the wait too.
#[derive(Debug)]
pub struct BlockedWait {
    slot: u16,
}

impl BlockedWait {
    /// Not waiting.
    pub const fn new() -> Self {
        Self { slot: NO_SLOT }
    }

    /// The future is about to return `Pending` on `object` (the lock or
    /// gate's address), from the call at `site`. The first call records the
    /// wait and its start; later ones (re-polls of the same wait) only
    /// refresh `detail`.
    #[inline]
    pub fn block(
        &mut self,
        kind: &'static WaitKind,
        site: &'static Location<'static>,
        object: usize,
        detail: u64,
    ) {
        if let Some(slot) = SLOTS.get(self.slot as usize) {
            slot.detail.store(detail, Ordering::Relaxed);
            return;
        }
        self.claim(kind, site, object, detail);
    }

    #[cold]
    #[inline(never)]
    fn claim(
        &mut self,
        kind: &'static WaitKind,
        site: &'static Location<'static>,
        object: usize,
        detail: u64,
    ) {
        let Some(now_ns) = hook(&NOW_NS_HOOK) else {
            return;
        };
        let owner = owner();
        for (index, slot) in SLOTS.iter().enumerate() {
            if slot
                .owner
                .compare_exchange(0, owner, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                continue;
            }
            slot.kind
                .store(core::ptr::from_ref(kind).cast_mut(), Ordering::Relaxed);
            slot.site
                .store(core::ptr::from_ref(site).cast_mut(), Ordering::Relaxed);
            slot.object.store(object, Ordering::Relaxed);
            slot.detail.store(detail, Ordering::Relaxed);
            // Published last: a reader takes a slot only once this is set.
            slot.since_ns.store(now_ns().max(1), Ordering::Release);
            self.slot = index as u16;
            return;
        }
        OVERFLOWED.fetch_add(1, Ordering::Relaxed);
    }

    /// The wait is over (the future is returning `Ready`).
    #[inline]
    pub fn wake(&mut self) {
        let Some(slot) = SLOTS.get(self.slot as usize) else {
            return;
        };
        slot.since_ns.store(0, Ordering::Relaxed);
        slot.owner.store(0, Ordering::Release);
        self.slot = NO_SLOT;
    }

    /// Whether a wait is recorded.
    pub const fn is_blocked(&self) -> bool {
        self.slot != NO_SLOT
    }
}

impl Default for BlockedWait {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for BlockedWait {
    fn drop(&mut self) {
        self.wake();
    }
}

/// One recorded wait, as [`for_each_blocked`] read it.
#[derive(Copy, Clone, Debug)]
pub struct BlockedInfo {
    /// The waiting task's scheduler id (see [`owner_is_anonymous`]).
    pub owner: u64,
    /// Monotonic ns at which the wait began.
    pub since_ns: u64,
    pub kind: &'static WaitKind,
    /// The call that is waiting (`lock()`, `join()`, …).
    pub site: Option<&'static Location<'static>>,
    /// Address of the lock or gate.
    pub object: usize,
    /// Kind-specific ([`WaitKind::detail`]).
    pub detail: u64,
}

/// Call `f` for every recorded wait. Lock-free and allocation-free; a slot
/// changing hands while it is read is skipped, so a wait that began or
/// ended during the scan may be missed, never misreported.
pub fn for_each_blocked(mut f: impl FnMut(&BlockedInfo)) {
    for slot in &SLOTS {
        let owner = slot.owner.load(Ordering::Acquire);
        let since_ns = slot.since_ns.load(Ordering::Acquire);
        if owner == 0 || since_ns == 0 {
            continue;
        }
        let kind = slot.kind.load(Ordering::Relaxed);
        let site = slot.site.load(Ordering::Relaxed);
        let object = slot.object.load(Ordering::Relaxed);
        let detail = slot.detail.load(Ordering::Relaxed);
        if slot.since_ns.load(Ordering::Acquire) != since_ns
            || slot.owner.load(Ordering::Relaxed) != owner
            || kind.is_null()
        {
            continue;
        }
        // SAFETY: `kind` and `site` are only ever stored from `&'static`
        // references (`BlockedWait::claim`), and `kind` was checked non-null.
        let (kind, site) = unsafe { (&*kind, site.cast_const().as_ref()) };
        f(&BlockedInfo {
            owner,
            since_ns,
            kind,
            site,
            object,
            detail,
        });
    }
}

/// Waits that found the table full and were not tracked.
pub fn overflowed() -> u64 {
    OVERFLOWED.load(Ordering::Relaxed)
}
