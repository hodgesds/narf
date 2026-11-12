//! Timer migration hierarchy — Linux `kernel/time/timer_migration.c`.
//!
//! An idle CPU should not wake for its unpinned (`BASE_GLOBAL`) wheel
//! timers while another CPU is awake anyway. CPUs are the leaves of a tree
//! of groups of at most [`TMIGR_CHILDREN_PER_GROUP`] children built from the
//! topology: level 0 groups CPUs sharing a last-level cache, level 1 groups
//! those by package/NUMA node, level 2 fans in by eight, and level 3 is the
//! single root.
//!
//! * Each group tracks which children are active and names one active child
//!   its **migrator**. A CPU entering tickless idle
//!   ([`tmigr_cpu_deactivate`]) clears its bit; if it was the migrator,
//!   another active child takes over, and only when none is left does the
//!   group go inactive in its parent, and so on up (`tmigr_inactive_up`).
//! * An idle CPU's next global timer is an event in its group's queue; an
//!   inactive group's first event is an event in its parent's queue,
//!   carrying the CPU it belongs to (`tmigr_update_events`). So each group
//!   holds the earliest global timer of every idle subtree below it.
//! * A migrator expires them: its timer softirq ([`handle_remote`], Linux
//!   `tmigr_handle_remote`) walks up the groups it is migrator of (or that
//!   have none) and, for every due event, runs that idle CPU's global base
//!   here (`timer_expire_remote`) and requeues the CPU's next one. The idle
//!   CPU stays asleep. An active CPU's next event includes the first event
//!   of each group it migrates for ([`global_next_for`]).
//! * The **last** CPU to go idle — its walk leaves the root inactive — gets
//!   the root's first event back (`tmc->wakeup`) and wakes for it.
//! * Leaving idle ([`tmigr_cpu_activate`]) sets the bit again and, in a group
//!   without a migrator, takes the role and continues up; its own event
//!   leaves the queue (an active CPU handles its own timers).
//!
//! A CPU that is not part of the hierarchy (never registered by
//! [`tmigr_cpu_online`]) counts as active and handles its own timers.
//!
//! Units: jiffies; `u64::MAX` is "no event".
//!
//! Locking: a CPU's `tmc` lock, then group locks bottom-up. A walk that
//! carries a child group's first event into its parent holds the child's
//! lock while it takes the parent's (Linux `tmigr_update_events`), so a
//! concurrent walk can never overwrite a parent with an older view of the
//! child. Linux keeps the active/migrator state in a lock-free atomic with a
//! sequence count; NARF updates it under the group lock, which the event
//! update takes anyway, and mirrors it into atomics for the lock-free reads.
//! Timer base locks are never held across any of these.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicU8, Ordering};

use narf_lib::percpu::MAX_CPUS;
use narf_lib::sync::{IrqSafeSpinLock, IrqSafeSpinLockGuard};

use crate::timerqueue::{TimerQueueHead, TimerQueueNode};

/// No event.
const NONE: u64 = u64::MAX;

/// `TMIGR_CHILDREN_PER_GROUP`.
pub const TMIGR_CHILDREN_PER_GROUP: usize = 8;
/// `TMIGR_NONE`: no migrator (the group is inactive).
const TMIGR_NONE: u8 = 0xFF;
/// Levels: last-level cache, package/node, fan-in, root. Eight children per
/// group over four levels reach a single root for up to 8^4 CPUs.
const LVL_LLC: u8 = 0;
const LVL_ROOT: u8 = 3;
const _: () = assert!(MAX_CPUS <= 4096);

/// `struct tmigr_event`: the earliest global timer of a CPU or of an idle
/// group, queued in the parent group's queue (guarded by that lock).
#[repr(C)]
struct TmigrEvent {
    node: UnsafeCell<TimerQueueNode>,
    /// CPU the timer belongs to (`evt->cpu`).
    cpu: AtomicU32,
    queued: AtomicBool,
}

impl TmigrEvent {
    const fn new() -> Self {
        Self {
            node: UnsafeCell::new(TimerQueueNode::new()),
            cpu: AtomicU32::new(0),
            queued: AtomicBool::new(false),
        }
    }

    fn node_ptr(&self) -> *mut TimerQueueNode {
        self.node.get()
    }

    /// `container_of(node, struct tmigr_event, nextevt)`: `node` is the
    /// first field of a `repr(C)` struct.
    fn from_node(n: *mut TimerQueueNode) -> *const TmigrEvent {
        n as *const TmigrEvent
    }
}

struct GroupState {
    events: TimerQueueHead,
    /// Active children (bit per child slot).
    active: u8,
    /// The migrator child's bit, or `TMIGR_NONE`.
    migrator: u8,
    num_children: u8,
}

// SAFETY: the raw event pointers are guarded by the group lock.
unsafe impl Send for GroupState {}

/// `struct tmigr_group`. Groups are leaked once created and never freed.
pub struct TmigrGroup {
    state: IrqSafeSpinLock<GroupState>,
    parent: AtomicPtr<TmigrGroup>,
    /// This group's event in the parent's queue (parent's lock).
    groupevt: TmigrEvent,
    /// This group's bit in its parent.
    groupmask: AtomicU8,
    level: u8,
    /// Topology key the group was built for (LLC id, node id, or 0).
    key: u64,
    /// Lock-free mirrors of the migrator and the first event.
    migrator: AtomicU8,
    next_expiry: AtomicU64,
}

impl core::fmt::Debug for TmigrGroup {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TmigrGroup")
            .field("level", &self.level)
            .field("key", &self.key)
            .field("migrator", &self.migrator.load(Ordering::Relaxed))
            .field("next_expiry", &self.next_expiry.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

// SAFETY: `groupevt` is touched only under the parent's lock; everything else
// is atomic or behind `state`'s lock.
unsafe impl Sync for TmigrGroup {}
// SAFETY: as above.
unsafe impl Send for TmigrGroup {}

type GGuard = IrqSafeSpinLockGuard<'static, GroupState>;

impl TmigrGroup {
    fn new(level: u8, key: u64) -> &'static TmigrGroup {
        Box::leak(Box::new(TmigrGroup {
            state: IrqSafeSpinLock::new(GroupState {
                events: TimerQueueHead::new(),
                active: 0,
                migrator: TMIGR_NONE,
                num_children: 0,
            }),
            parent: AtomicPtr::new(ptr::null_mut()),
            groupevt: TmigrEvent::new(),
            groupmask: AtomicU8::new(0),
            level,
            key,
            migrator: AtomicU8::new(TMIGR_NONE),
            next_expiry: AtomicU64::new(NONE),
        }))
    }

    fn parent(&self) -> Option<&'static TmigrGroup> {
        let p = self.parent.load(Ordering::Acquire);
        // SAFETY: groups are leaked and never freed.
        (!p.is_null()).then(|| unsafe { &*p })
    }

    fn lock(&'static self) -> GGuard {
        self.state.lock()
    }
}

/// First event of a group's queue: (expiry, cpu); `NONE` if empty.
fn first_event(g: &GroupState) -> (u64, u32) {
    let n = g.events.first();
    if n.is_null() {
        return (NONE, 0);
    }
    // SAFETY: linked events live in leaked groups / CPUs and are guarded by
    // this group's lock, which the caller holds.
    let (exp, e) = unsafe { ((*n).expires, &*TmigrEvent::from_node(n)) };
    (exp, e.cpu.load(Ordering::Relaxed))
}

/// Put `evt` in `g`'s queue at `exp` for `cpu`, or take it out (`NONE`).
fn requeue(g: &mut GroupState, evt: &TmigrEvent, exp: u64, cpu: u32) {
    if evt.queued.load(Ordering::Relaxed) {
        // SAFETY: queued ⇒ linked into `g.events`, under this lock.
        let _ = unsafe { g.events.remove(evt.node_ptr()) };
        evt.queued.store(false, Ordering::Relaxed);
    }
    if exp != NONE {
        // SAFETY: unlinked, owned under this lock; events never move (they
        // live in leaked groups / CPUs).
        unsafe {
            (*evt.node_ptr()).expires = exp;
            evt.cpu.store(cpu, Ordering::Relaxed);
            let _ = g.events.add(evt.node_ptr());
        }
        evt.queued.store(true, Ordering::Relaxed);
    }
}

fn publish(group: &TmigrGroup, g: &GroupState) {
    group.migrator.store(g.migrator, Ordering::Release);
    group.next_expiry.store(first_event(g).0, Ordering::Release);
}

struct CpuState {
    online: bool,
    idle: bool,
    /// A migrator is expiring this CPU's global base.
    remote: bool,
}

/// `struct tmigr_cpu`. Leaked once created.
pub struct TmigrCpu {
    cpu: u32,
    state: IrqSafeSpinLock<CpuState>,
    cpuevt: TmigrEvent,
    group: &'static TmigrGroup,
    groupmask: u8,
    /// Event this CPU must wake for while idle (`tmc->wakeup`).
    wakeup: AtomicU64,
    idle: AtomicBool,
}

impl core::fmt::Debug for TmigrCpu {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TmigrCpu")
            .field("cpu", &self.cpu)
            .field("idle", &self.idle.load(Ordering::Relaxed))
            .field("wakeup", &self.wakeup.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

// SAFETY: `cpuevt` is touched only under its group's lock; the rest is atomic
// or behind `state`.
unsafe impl Sync for TmigrCpu {}
// SAFETY: as above.
unsafe impl Send for TmigrCpu {}

/// One migration hierarchy. The kernel's is [`static@TMIGR`]; tests build
/// private ones over CPU indices that never came online.
pub struct Tmigr {
    cpus: [AtomicPtr<TmigrCpu>; MAX_CPUS],
    /// Every group, for find-or-create when a CPU comes online.
    groups: IrqSafeSpinLock<Vec<&'static TmigrGroup>>,
    root: AtomicPtr<TmigrGroup>,
}

impl core::fmt::Debug for Tmigr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tmigr").finish_non_exhaustive()
    }
}

impl Default for Tmigr {
    fn default() -> Self {
        Self::new()
    }
}

/// The kernel's hierarchy.
pub static TMIGR: Tmigr = Tmigr::new();

impl Tmigr {
    /// An empty hierarchy.
    pub const fn new() -> Self {
        Self {
            cpus: [const { AtomicPtr::new(ptr::null_mut()) }; MAX_CPUS],
            groups: IrqSafeSpinLock::new(Vec::new()),
            root: AtomicPtr::new(ptr::null_mut()),
        }
    }

    fn tmc(&self, cpu: usize) -> Option<&'static TmigrCpu> {
        let p = self.cpus.get(cpu)?.load(Ordering::Acquire);
        // SAFETY: CPUs are leaked on publication and never freed.
        (!p.is_null()).then(|| unsafe { &*p })
    }

    /// A group of `level` for `keys[level]` with a free child slot (one is
    /// taken), created and linked under its own parent if none has room.
    /// Returns the group and the child's bit in it. `groups` lock held.
    fn group_for(
        &self,
        groups: &mut Vec<&'static TmigrGroup>,
        level: u8,
        keys: &[u64; 4],
    ) -> (&'static TmigrGroup, u8) {
        let key = keys[level as usize];
        for &g in groups.iter() {
            if g.level == level && g.key == key {
                let mut st = g.lock();
                if (st.num_children as usize) < TMIGR_CHILDREN_PER_GROUP {
                    let slot = st.num_children;
                    st.num_children += 1;
                    return (g, 1 << slot);
                }
            }
        }
        let g = TmigrGroup::new(level, key);
        groups.push(g);
        if level < LVL_ROOT {
            let (parent, mask) = self.group_for(groups, level + 1, keys);
            g.groupmask.store(mask, Ordering::Relaxed);
            g.parent
                .store(parent as *const TmigrGroup as *mut _, Ordering::Release);
        } else {
            self.root
                .store(g as *const TmigrGroup as *mut _, Ordering::Release);
        }
        g.lock().num_children = 1;
        (g, 1)
    }

    /// `tmigr_cpu_prepare` + `tmigr_cpu_online`: add `cpu` — grouped with
    /// the CPUs of the same `llc` (last-level cache id), and those groups by
    /// `node` (package / NUMA node) — and mark it active. Allocates: task
    /// context. A CPU already present just comes back online.
    pub fn cpu_online(&self, cpu: usize, llc: Option<u64>, node: Option<u32>) {
        if cpu >= MAX_CPUS {
            return;
        }
        if self.tmc(cpu).is_none() {
            let mut groups = self.groups.lock();
            if self.tmc(cpu).is_none() {
                // Unknown cache topology: neighbouring CPU numbers share.
                let llc_key = llc.unwrap_or((1 << 63) | (cpu / TMIGR_CHILDREN_PER_GROUP) as u64);
                let keys = [llc_key, node.map_or(0, u64::from), 0, 0];
                let (group, mask) = self.group_for(&mut groups, LVL_LLC, &keys);
                let tmc = Box::leak(Box::new(TmigrCpu {
                    cpu: cpu as u32,
                    state: IrqSafeSpinLock::new(CpuState {
                        online: false,
                        idle: true,
                        remote: false,
                    }),
                    cpuevt: TmigrEvent::new(),
                    group,
                    groupmask: mask,
                    wakeup: AtomicU64::new(NONE),
                    idle: AtomicBool::new(true),
                }));
                self.cpus[cpu].store(tmc, Ordering::Release);
            }
        }
        if let Some(tmc) = self.tmc(cpu) {
            tmc.state.lock().online = true;
            self.activate(cpu);
        }
    }

    /// `tmigr_cpu_offline`: `cpu` leaves the hierarchy (its timers move to
    /// another CPU at `timers_dead_cpu`); its event goes, and its group hands
    /// the migrator role on.
    pub fn cpu_offline(&self, cpu: usize) {
        let Some(tmc) = self.tmc(cpu) else { return };
        let mut st = tmc.state.lock();
        st.idle = true;
        tmc.idle.store(true, Ordering::Release);
        let _ = Self::walk_inactive(tmc, NONE);
        tmc.wakeup.store(NONE, Ordering::Release);
        st.online = false;
    }

    /// `tmigr_cpu_activate`: `cpu` left idle; it handles its own timers and,
    /// in a group without a migrator, becomes it (`tmigr_active_up`).
    pub fn activate(&self, cpu: usize) {
        let Some(tmc) = self.tmc(cpu) else { return };
        let mut st = tmc.state.lock();
        if !st.idle || !st.online {
            return;
        }
        st.idle = false;
        tmc.idle.store(false, Ordering::Release);
        tmc.wakeup.store(NONE, Ordering::Release);
        let mut group = tmc.group;
        let mut childmask = tmc.groupmask;
        let mut child_evt = &tmc.cpuevt;
        loop {
            let mut g = group.lock();
            // An active child handles its own events.
            requeue(&mut g, child_evt, NONE, 0);
            let was_inactive = g.migrator == TMIGR_NONE;
            g.active |= childmask;
            if was_inactive {
                g.migrator = childmask;
            }
            publish(group, &g);
            drop(g);
            if !was_inactive {
                break;
            }
            let Some(parent) = group.parent() else { break };
            childmask = group.groupmask.load(Ordering::Relaxed);
            child_evt = &group.groupevt;
            group = parent;
        }
        drop(st);
    }

    /// `tmigr_cpu_deactivate`, and `tmigr_new_timer` when already idle:
    /// `cpu` idles with its next global timer at jiffy `nextexp`. Returns
    /// what it must still wake for — the root's first event if its walk left
    /// the root inactive (it was the last active CPU), else `NONE` — or
    /// `None` if `cpu` is not in the hierarchy (it wakes for its own).
    pub fn deactivate(&self, cpu: usize, nextexp: u64) -> Option<u64> {
        let tmc = self.tmc(cpu)?;
        let mut st = tmc.state.lock();
        if !st.online {
            return None;
        }
        st.idle = true;
        tmc.idle.store(true, Ordering::Release);
        let wake = Self::walk_inactive(tmc, nextexp);
        tmc.wakeup.store(wake, Ordering::Release);
        drop(st);
        Some(wake)
    }

    /// Walk up from idle `tmc` with its next global event `nextexp`
    /// (`tmigr_inactive_up` + `tmigr_update_events`): requeue the event,
    /// hand the migrator role on, and continue while groups are left without
    /// a migrator. Returns the root's first event if the walk reached an
    /// inactive root, else `NONE`. `tmc`'s lock is held.
    fn walk_inactive(tmc: &'static TmigrCpu, nextexp: u64) -> u64 {
        let mut group = tmc.group;
        let mut childmask = tmc.groupmask;
        let mut g = group.lock();
        requeue(&mut g, &tmc.cpuevt, nextexp, tmc.cpu);
        loop {
            g.active &= !childmask;
            if g.migrator == childmask {
                g.migrator = if g.active != 0 {
                    1 << g.active.trailing_zeros()
                } else {
                    TMIGR_NONE
                };
            }
            publish(group, &g);
            if g.migrator != TMIGR_NONE {
                // Still active: its migrator handles the events here.
                return NONE;
            }
            let (first, first_cpu) = first_event(&g);
            let Some(parent) = group.parent() else {
                // The root is inactive: the caller is (or stands in for) the
                // last active CPU and wakes for the first global timer.
                return first;
            };
            // Hand over hand: the child's view goes up while its lock is
            // held, so no walk can overwrite the parent with an older view.
            let mut pg = parent.lock();
            requeue(&mut pg, &group.groupevt, first, first_cpu);
            drop(g);
            childmask = group.groupmask.load(Ordering::Relaxed);
            group = parent;
            g = pg;
        }
    }

    /// Whether `cpu` is active (not deactivated). A CPU outside the
    /// hierarchy counts as active: it handles its own timers.
    pub fn cpu_active(&self, cpu: usize) -> bool {
        self.tmc(cpu)
            .is_none_or(|t| !t.idle.load(Ordering::Acquire))
    }

    /// The migration part of `cpu`'s next event (jiffies, `NONE` none):
    /// - outside the hierarchy: its own global timers;
    /// - active: its own, and the first event of every group it migrates
    ///   for (it is that group's migrator, or the group has none);
    /// - idle: `tmc->wakeup` — the root's first event if it was the last CPU
    ///   to go idle, else nothing (a migrator runs its global timers).
    pub fn global_next_for(&self, cpu: usize) -> u64 {
        let own = crate::timer::global_next(cpu);
        let Some(tmc) = self.tmc(cpu) else {
            return own;
        };
        if tmc.idle.load(Ordering::Acquire) {
            return tmc.wakeup.load(Ordering::Acquire);
        }
        let mut next = own;
        let mut group = tmc.group;
        let mut childmask = tmc.groupmask;
        loop {
            let m = group.migrator.load(Ordering::Acquire);
            if m != childmask && m != TMIGR_NONE {
                return next;
            }
            next = next.min(group.next_expiry.load(Ordering::Acquire));
            let Some(parent) = group.parent() else {
                return next;
            };
            childmask = group.groupmask.load(Ordering::Relaxed);
            group = parent;
        }
    }

    /// `tmigr_requires_handle_remote`: lock-free "a remote expiry is due"
    /// for `cpu`'s softirq at jiffy `now`.
    pub fn requires_handle_remote(&self, cpu: usize, now: u64) -> bool {
        let Some(tmc) = self.tmc(cpu) else {
            return false;
        };
        if tmc.idle.load(Ordering::Acquire) {
            return tmc.wakeup.load(Ordering::Acquire) <= now;
        }
        let mut group = tmc.group;
        let mut childmask = tmc.groupmask;
        loop {
            let m = group.migrator.load(Ordering::Acquire);
            if m != childmask && m != TMIGR_NONE {
                return false;
            }
            if group.next_expiry.load(Ordering::Acquire) <= now {
                return true;
            }
            let Some(parent) = group.parent() else {
                return false;
            };
            childmask = group.groupmask.load(Ordering::Relaxed);
            group = parent;
        }
    }

    /// `tmigr_handle_remote`: from `cpu`'s timer softirq at jiffy `now`,
    /// expire the due global timers of idle CPUs in every group `cpu` is
    /// migrator of (or that has none) up the tree. Returns the callbacks
    /// run.
    pub fn handle_remote(&self, cpu: usize, now: u64) -> u64 {
        let Some(tmc) = self.tmc(cpu) else { return 0 };
        if !self.requires_handle_remote(cpu, now) {
            return 0;
        }
        let mut ran = 0;
        let mut group = tmc.group;
        let mut childmask = tmc.groupmask;
        let mut firstexp = NONE;
        loop {
            // `tmigr_check_migrator`.
            let m = group.migrator.load(Ordering::Acquire);
            if m != childmask && m != TMIGR_NONE {
                break;
            }
            loop {
                let mut g = group.lock();
                let (exp, remote) = first_event(&g);
                if exp > now {
                    firstexp = exp;
                    break;
                }
                // `tmigr_next_expired_groupevt`: pop it; handling the CPU
                // requeues that CPU's next event up the tree.
                let n = g.events.first();
                // SAFETY: the queue is non-empty (`exp != NONE`); linked
                // events are live.
                let evt = unsafe { &*TmigrEvent::from_node(n) };
                requeue(&mut g, evt, NONE, 0);
                publish(group, &g);
                drop(g);
                ran += self.handle_remote_cpu(remote as usize);
            }
            let Some(parent) = group.parent() else { break };
            childmask = group.groupmask.load(Ordering::Relaxed);
            group = parent;
        }
        if tmc.idle.load(Ordering::Acquire) {
            tmc.wakeup.store(firstexp, Ordering::Release);
        }
        ran
    }

    /// `tmigr_handle_remote_cpu`: run idle `cpu`'s due global timers here and
    /// requeue its next one. Returns the callbacks run.
    fn handle_remote_cpu(&self, cpu: usize) -> u64 {
        let Some(tmc) = self.tmc(cpu) else { return 0 };
        {
            let mut st = tmc.state.lock();
            // Active: it handles its own. Remote: another migrator is at it.
            if !st.online || st.remote || !st.idle {
                return 0;
            }
            st.remote = true;
        }
        let ran = crate::timer::expire_remote_global(cpu);
        let next = crate::timer::global_next(cpu);
        let mut st = tmc.state.lock();
        if st.idle {
            let _ = Self::walk_inactive(tmc, next);
        }
        st.remote = false;
        ran
    }

    /// Whether `cpu` is the migrator of its level-0 group (tests).
    pub fn is_group_migrator(&self, cpu: usize) -> bool {
        self.tmc(cpu)
            .is_some_and(|t| t.group.migrator.load(Ordering::Acquire) == t.groupmask)
    }

    /// Level-0 group of `cpu`, as an opaque identity (tests: who shares).
    pub fn group_id(&self, cpu: usize) -> Option<usize> {
        Some(self.tmc(cpu)?.group as *const TmigrGroup as usize)
    }

    /// Depth from `cpu` to the root (tests).
    pub fn depth(&self, cpu: usize) -> usize {
        let Some(t) = self.tmc(cpu) else { return 0 };
        let mut d = 1;
        let mut g = t.group;
        while let Some(p) = g.parent() {
            d += 1;
            g = p;
        }
        d
    }

    /// The root's first event (diagnostics, tests).
    pub fn root_next_expiry(&self) -> u64 {
        let r = self.root.load(Ordering::Acquire);
        if r.is_null() {
            return NONE;
        }
        // SAFETY: groups are leaked.
        unsafe { (*r).next_expiry.load(Ordering::Acquire) }
    }

    /// Bitmap of idle CPUs (diagnostics, tests).
    pub fn idle_mask(&self) -> u64 {
        (0..MAX_CPUS.min(64))
            .filter(|&c| self.tmc(c).is_some_and(|t| t.idle.load(Ordering::Acquire)))
            .fold(0, |m, c| m | 1 << c)
    }

    /// Check every group: queue shape, and migrator ⇔ some child active
    /// (test-only).
    #[doc(hidden)]
    pub fn __validate(&self) -> Result<usize, &'static str> {
        let groups = self.groups.lock();
        let mut n = 0;
        for &g in groups.iter() {
            let st = g.lock();
            // SAFETY: the group lock is held.
            n += unsafe { st.events.__validate()? };
            if st.migrator != TMIGR_NONE && st.active & st.migrator == 0 {
                return Err("a group's migrator is not one of its active children");
            }
            if (st.migrator == TMIGR_NONE) != (st.active == 0) {
                return Err("a group with active children has no migrator");
            }
        }
        Ok(n)
    }
}

#[inline]
fn this_cpu() -> usize {
    narf_lib::percpu::current_cpu().min(MAX_CPUS - 1)
}

/// `tmigr_cpu_online` for the kernel's hierarchy (the scheduler calls it on
/// each CPU at startup, with its cache and node identity).
pub fn tmigr_cpu_online(cpu: usize, llc: Option<u64>, node: Option<u32>) {
    TMIGR.cpu_online(cpu, llc, node);
}

/// `tmigr_cpu_offline` for the kernel's hierarchy.
pub fn tmigr_cpu_offline(cpu: usize) {
    TMIGR.cpu_offline(cpu);
}

/// `tmigr_cpu_deactivate`: this CPU enters tickless idle; its global timers
/// go to the hierarchy.
pub fn tmigr_cpu_deactivate() {
    let cpu = this_cpu();
    let _ = TMIGR.deactivate(cpu, crate::timer::global_next(cpu));
}

/// `tmigr_cpu_activate`: this CPU leaves idle. Cheap when already active.
pub fn tmigr_cpu_activate() {
    let cpu = this_cpu();
    if !TMIGR.cpu_active(cpu) {
        TMIGR.activate(cpu);
    }
}

/// Whether `cpu` is active (not in tickless idle).
#[inline]
pub fn cpu_active(cpu: usize) -> bool {
    TMIGR.cpu_active(cpu)
}

/// The global-timer part of `cpu`'s next event (jiffies; `u64::MAX` none),
/// for `get_next_timer_interrupt`. See [`Tmigr::global_next_for`].
pub fn global_next_for(cpu: usize) -> u64 {
    TMIGR.global_next_for(cpu)
}

/// `tmigr_requires_handle_remote` for this CPU.
pub fn requires_handle_remote() -> bool {
    TMIGR.requires_handle_remote(this_cpu(), crate::timer::jiffies())
}

/// `tmigr_handle_remote` for this CPU (timer softirq). Returns callbacks
/// run.
pub(crate) fn handle_remote() -> u64 {
    TMIGR.handle_remote(this_cpu(), crate::timer::jiffies())
}

/// Test-only: the idle bitmap of the kernel's hierarchy.
#[doc(hidden)]
pub fn __test_idle_mask() -> u64 {
    TMIGR.idle_mask()
}
