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
//!   without a migrator, takes the role and continues up (`tmigr_active_up`).
//!   Its queued events are not dequeued: they are marked `ignore`d and
//!   dropped lazily by whoever next looks at the queue under its lock.
//!
//! A CPU that is not part of the hierarchy (never registered by
//! [`tmigr_cpu_online`]) counts as active and handles its own timers.
//!
//! Units: jiffies; `u64::MAX` is "no event".
//!
//! Locking, as Linux: a group's active children, migrator and a sequence
//! count are one atomic word (`union tmigr_state`) changed only by
//! compare-and-exchange, so activation takes no lock at all and an
//! inactive walk takes a group lock only for the event update. Event queues
//! are under their group's lock; an event update that carries a child
//! group's first event into its parent holds the child's lock, then the
//! parent's (`tmigr_update_events`), and re-reads the child's state there:
//! a child that went active meanwhile is left alone. A CPU's `tmc` lock is
//! held across its own walks and its remote expiry; it is taken before any
//! group lock. Timer base locks are never held across any of these.

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

/// `union tmigr_state`: active children, the migrator child (or
/// `TMIGR_NONE`) and a sequence count bumped by every change, so a
/// compare-and-exchange never succeeds on a state that changed and changed
/// back.
#[derive(Clone, Copy, PartialEq, Eq)]
struct MigrState {
    active: u8,
    migrator: u8,
    seq: u16,
}

impl MigrState {
    const INITIAL: MigrState = MigrState {
        active: 0,
        migrator: TMIGR_NONE,
        seq: 0,
    };

    const fn pack(self) -> u32 {
        self.active as u32 | (self.migrator as u32) << 8 | (self.seq as u32) << 16
    }

    const fn unpack(v: u32) -> Self {
        MigrState {
            active: v as u8,
            migrator: (v >> 8) as u8,
            seq: (v >> 16) as u16,
        }
    }
}

/// `struct tmigr_event`: the earliest global timer of a CPU or of an idle
/// group, queued in the parent group's queue (guarded by that lock).
#[repr(C)]
struct TmigrEvent {
    node: UnsafeCell<TimerQueueNode>,
    /// CPU the timer belongs to (`evt->cpu`).
    cpu: AtomicU32,
    queued: AtomicBool,
    /// `evt->ignore`: the owner is active (or has no event); a queued
    /// event is skipped and dropped by the next look at the queue.
    ignore: AtomicBool,
}

impl TmigrEvent {
    const fn new() -> Self {
        Self {
            node: UnsafeCell::new(TimerQueueNode::new()),
            cpu: AtomicU32::new(0),
            queued: AtomicBool::new(false),
            ignore: AtomicBool::new(true),
        }
    }

    fn node_ptr(&self) -> *mut TimerQueueNode {
        self.node.get()
    }

    /// The queued expiry. Written only by holders of the queue's group
    /// lock, which (for a CPU's event) also hold that CPU's `tmc` lock.
    fn expires(&self) -> u64 {
        // SAFETY: see above; the caller holds one of those locks.
        unsafe { (*self.node_ptr()).expires }
    }

    /// `container_of(node, struct tmigr_event, nextevt)`: `node` is the
    /// first field of a `repr(C)` struct.
    fn from_node(n: *mut TimerQueueNode) -> *const TmigrEvent {
        n as *const TmigrEvent
    }
}

struct GroupState {
    events: TimerQueueHead,
    num_children: u8,
}

// SAFETY: the raw event pointers are guarded by the group lock.
unsafe impl Send for GroupState {}

/// `struct tmigr_group`. Groups are leaked once created and never freed.
pub struct TmigrGroup {
    state: IrqSafeSpinLock<GroupState>,
    /// `group->migr_state` ([`MigrState`] packed).
    migr_state: AtomicU32,
    parent: AtomicPtr<TmigrGroup>,
    /// This group's event in the parent's queue (parent's lock).
    groupevt: TmigrEvent,
    /// This group's bit in its parent.
    groupmask: AtomicU8,
    level: u8,
    /// Topology key the group was built for (LLC id, node id, or 0).
    key: u64,
    /// `group->next_expiry`: the first event, written under the lock and
    /// read lock-free (it may be stale-early: an ignored event).
    next_expiry: AtomicU64,
}

impl core::fmt::Debug for TmigrGroup {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = self.migr();
        f.debug_struct("TmigrGroup")
            .field("level", &self.level)
            .field("key", &self.key)
            .field("active", &s.active)
            .field("migrator", &s.migrator)
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
                num_children: 0,
            }),
            migr_state: AtomicU32::new(MigrState::INITIAL.pack()),
            parent: AtomicPtr::new(ptr::null_mut()),
            groupevt: TmigrEvent::new(),
            groupmask: AtomicU8::new(0),
            level,
            key,
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

    fn migr(&self) -> MigrState {
        MigrState::unpack(self.migr_state.load(Ordering::Acquire))
    }

    /// `tmigr_check_migrator`: `childmask` is this group's migrator, or it
    /// has none.
    fn check_migrator(&self, childmask: u8) -> bool {
        let m = self.migr().migrator;
        m == childmask || m == TMIGR_NONE
    }

    /// `tmigr_next_groupevt`: the first event not to be ignored; ignored
    /// ones in front of it leave the queue. Updates `next_expiry`. Lock
    /// held.
    fn next_groupevt(&self, g: &mut GroupState) -> Option<&'static TmigrEvent> {
        loop {
            let n = g.events.first();
            if n.is_null() {
                self.next_expiry.store(NONE, Ordering::Release);
                return None;
            }
            // SAFETY: linked events live in leaked groups / CPUs and are
            // guarded by this group's lock, which the caller holds.
            let evt: &'static TmigrEvent = unsafe { &*TmigrEvent::from_node(n) };
            if !evt.ignore.load(Ordering::Acquire) {
                self.next_expiry.store(evt.expires(), Ordering::Release);
                return Some(evt);
            }
            dequeue(g, evt);
        }
    }

    /// `tmigr_next_expired_groupevt`: pop the first event if due at `now`,
    /// marking it ignored (it is no longer queued). Lock held.
    fn next_expired_groupevt(&self, g: &mut GroupState, now: u64) -> Option<&'static TmigrEvent> {
        let evt = self.next_groupevt(g)?;
        if evt.expires() > now {
            return None;
        }
        dequeue(g, evt);
        evt.ignore.store(true, Ordering::Release);
        let _ = self.next_groupevt(g);
        Some(evt)
    }
}

/// Take `evt` out of `g`'s queue if it is queued there. Lock held.
fn dequeue(g: &mut GroupState, evt: &TmigrEvent) {
    if evt.queued.load(Ordering::Relaxed) {
        // SAFETY: queued ⇒ linked into `g.events`, under this lock.
        let _ = unsafe { g.events.remove(evt.node_ptr()) };
        evt.queued.store(false, Ordering::Relaxed);
    }
}

/// Queue unqueued `evt` in `g` at `exp` for `cpu`. Lock held.
fn enqueue(g: &mut GroupState, evt: &TmigrEvent, exp: u64, cpu: u32) {
    // SAFETY: unlinked, owned under this lock; events never move (they live
    // in leaked groups / CPUs).
    unsafe {
        (*evt.node_ptr()).expires = exp;
        evt.cpu.store(cpu, Ordering::Relaxed);
        let _ = g.events.add(evt.node_ptr());
    }
    evt.queued.store(true, Ordering::Relaxed);
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

// SAFETY: `cpuevt`'s node is touched only under its group's lock; the rest is
// atomic or behind `state`.
unsafe impl Sync for TmigrCpu {}
// SAFETY: as above.
unsafe impl Send for TmigrCpu {}

/// `struct tmigr_walk`: what a walk up the hierarchy carries.
struct Walk {
    /// The CPU's next global event (CPU level only).
    nextexp: u64,
    /// The root's first event, when the walk left the root inactive.
    firstexp: u64,
    /// The CPU's event and CPU number.
    evt: &'static TmigrEvent,
    cpu: u32,
    /// The current child's bit in the group being walked.
    childmask: u8,
    /// The walk follows a remote expiry (`tmigr_handle_remote_cpu`).
    remote: bool,
}

/// `tmigr_active_up`: `childmask` went active in `group`. Lock-free.
/// Returns whether the walk is done (the group already had a migrator).
fn active_up(group: &TmigrGroup, childmask: u8) -> bool {
    let mut cur = group.migr_state.load(Ordering::Acquire);
    let done = loop {
        let mut s = MigrState::unpack(cur);
        let mut done = true;
        if s.migrator == TMIGR_NONE {
            s.migrator = childmask;
            done = false;
        }
        s.active |= childmask;
        s.seq = s.seq.wrapping_add(1);
        match group
            .migr_state
            .compare_exchange(cur, s.pack(), Ordering::SeqCst, Ordering::Acquire)
        {
            Ok(_) => break done,
            Err(now) => cur = now,
        }
    };
    // Active (again): its event in the parent, if still queued, is stale.
    group.groupevt.ignore.store(true, Ordering::SeqCst);
    done
}

/// `tmigr_inactive_up`: the child (`child`, or the CPU when `None`) went
/// inactive in `group`: clear its bit (unless a child group went active
/// again meanwhile) and hand the migrator role on, then update the events.
/// Returns whether the walk is done (the group still has a migrator).
fn inactive_up(
    group: &'static TmigrGroup,
    child: Option<&'static TmigrGroup>,
    w: &mut Walk,
) -> bool {
    let childmask = w.childmask;
    let mut cur = group.migr_state.load(Ordering::Acquire);
    let done = loop {
        let child_active = child.is_some_and(|c| c.migr().active != 0);
        let mut s = MigrState::unpack(cur);
        let mut done = true;
        if !child_active {
            s.active &= !childmask;
            if s.migrator == childmask {
                if s.active != 0 {
                    s.migrator = 1 << s.active.trailing_zeros();
                } else {
                    s.migrator = TMIGR_NONE;
                    done = false;
                }
            }
        }
        s.seq = s.seq.wrapping_add(1);
        match group
            .migr_state
            .compare_exchange(cur, s.pack(), Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => break done,
            Err(now) => cur = now,
        }
    };
    w.remote = false;
    let _ = update_events(group, child, w);
    done
}

/// `tmigr_update_events`: carry the child's first event into `group`'s
/// queue — the CPU's `w.nextexp`, or the child group's first event — and,
/// at an inactive root, report the first event of all. Returns whether a
/// walk of event updates is done.
fn update_events(
    group: &'static TmigrGroup,
    child: Option<&'static TmigrGroup>,
    w: &mut Walk,
) -> bool {
    let mut done = false;
    let (_child_guard, mut g, evt, nextexp, cpu, ignore) = match child {
        Some(child) => {
            // Child, then parent: no walk can carry an older view of the
            // child up while this one holds the child's lock.
            let mut cg = child.lock();
            let g = group.lock();
            let first = child.next_groupevt(&mut cg);
            let (nextexp, cpu) =
                first.map_or((NONE, 0), |e| (e.expires(), e.cpu.load(Ordering::Relaxed)));
            let ignore = nextexp == NONE;
            // Store, then read the state (both SeqCst), against
            // `active_up`'s state CAS, then store: whichever order they
            // interleave in, an active child's event ends up ignored.
            child.groupevt.ignore.store(ignore, Ordering::SeqCst);
            if MigrState::unpack(child.migr_state.load(Ordering::SeqCst)).active != 0 {
                // It went active: its migrator handles its events.
                child.groupevt.ignore.store(true, Ordering::SeqCst);
                return true;
            }
            (Some(cg), g, &child.groupevt, nextexp, cpu, ignore)
        }
        None => {
            let ignore = w.evt.ignore.load(Ordering::Acquire);
            // Without a remote expiry before, the next level's walk takes
            // an ignored CPU event out (it re-reads this group).
            if ignore && !w.remote && group.parent().is_some() {
                return true;
            }
            (None, group.lock(), w.evt, w.nextexp, w.cpu, ignore)
        }
    };
    let gs = group.migr();
    let unchanged = evt.queued.load(Ordering::Relaxed) && evt.expires() == nextexp && !ignore;
    if unchanged {
        evt.cpu.store(cpu, Ordering::Relaxed);
    } else {
        dequeue(&mut g, evt);
        if ignore {
            // Nothing to carry up unless a remote expiry took an event out
            // of an inactive group (it must be recomputed up the tree).
            if !w.remote || gs.active != 0 {
                done = true;
            }
        } else {
            enqueue(&mut g, evt, nextexp, cpu);
        }
    }
    let first = group.next_groupevt(&mut g);
    if group.parent().is_none() && gs.migrator == TMIGR_NONE {
        done = true;
        if !w.remote {
            w.firstexp = first.map_or(NONE, |e| e.expires());
        }
    }
    done
}

/// One hierarchy. The kernel's is [`static@TMIGR`]; tests build private
/// ones over CPU indices that never came online.
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
        if !st.online {
            return;
        }
        if st.idle {
            // As after a remote expiry: recompute every inactive group up
            // the tree, so none keeps an event of an offline CPU.
            let _ = Self::walk_new_timer(tmc, NONE, true);
        } else {
            st.idle = true;
            tmc.idle.store(true, Ordering::Release);
            let _ = Self::walk_inactive(tmc, NONE);
        }
        tmc.wakeup.store(NONE, Ordering::Release);
        st.online = false;
    }

    /// `tmigr_cpu_activate`: `cpu` left idle; it handles its own timers and,
    /// in a group without a migrator, becomes it (`tmigr_active_up`). No
    /// group lock: its queued events are only marked ignored.
    pub fn activate(&self, cpu: usize) {
        let Some(tmc) = self.tmc(cpu) else { return };
        let mut st = tmc.state.lock();
        if !st.idle || !st.online {
            return;
        }
        st.idle = false;
        tmc.idle.store(false, Ordering::Release);
        tmc.cpuevt.ignore.store(true, Ordering::Release);
        tmc.wakeup.store(NONE, Ordering::Release);
        let mut group = tmc.group;
        let mut childmask = tmc.groupmask;
        while !active_up(group, childmask) {
            let Some(parent) = group.parent() else { break };
            childmask = group.groupmask.load(Ordering::Relaxed);
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
        let wake = if st.idle {
            if st.remote {
                // The migrator expiring us requeues our next event.
                return Some(tmc.wakeup.load(Ordering::Acquire));
            }
            Self::walk_new_timer(tmc, nextexp, false)
        } else {
            st.idle = true;
            tmc.idle.store(true, Ordering::Release);
            Self::walk_inactive(tmc, nextexp)
        };
        tmc.wakeup.store(wake, Ordering::Release);
        drop(st);
        Some(wake)
    }

    /// `__tmigr_cpu_deactivate`: walk `tmigr_inactive_up` from `tmc` with
    /// its next global event. Returns the root's first event if the walk
    /// left the root inactive, else `NONE`. `tmc`'s lock is held.
    fn walk_inactive(tmc: &'static TmigrCpu, nextexp: u64) -> u64 {
        tmc.cpuevt.ignore.store(nextexp == NONE, Ordering::Release);
        let mut w = Walk {
            nextexp,
            firstexp: NONE,
            evt: &tmc.cpuevt,
            cpu: tmc.cpu,
            childmask: tmc.groupmask,
            remote: false,
        };
        let mut group = tmc.group;
        let mut child = None;
        while !inactive_up(group, child, &mut w) {
            let Some(parent) = group.parent() else { break };
            w.childmask = group.groupmask.load(Ordering::Relaxed);
            child = Some(group);
            group = parent;
        }
        w.firstexp
    }

    /// `tmigr_new_timer_up` walk from idle `tmc`: requeue its next global
    /// event (after a remote expiry when `remote`) up through inactive
    /// groups. Returns the root's first event as [`Self::walk_inactive`].
    /// `tmc`'s lock is held.
    fn walk_new_timer(tmc: &'static TmigrCpu, nextexp: u64, remote: bool) -> u64 {
        tmc.cpuevt.ignore.store(nextexp == NONE, Ordering::Release);
        let mut w = Walk {
            nextexp,
            firstexp: NONE,
            evt: &tmc.cpuevt,
            cpu: tmc.cpu,
            childmask: tmc.groupmask,
            remote,
        };
        let mut group = tmc.group;
        let mut child = None;
        while !update_events(group, child, &mut w) {
            let Some(parent) = group.parent() else { break };
            w.childmask = group.groupmask.load(Ordering::Relaxed);
            child = Some(group);
            group = parent;
        }
        w.firstexp
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
            if !group.check_migrator(childmask) {
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
            if !group.check_migrator(childmask) {
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
        let reached_root = 'up: loop {
            // `tmigr_handle_remote_up`.
            loop {
                if !group.check_migrator(childmask) {
                    break 'up false;
                }
                let mut g = group.lock();
                match group.next_expired_groupevt(&mut g, now) {
                    Some(evt) => {
                        let remote = evt.cpu.load(Ordering::Relaxed);
                        drop(g);
                        ran += self.handle_remote_cpu(remote as usize, now);
                    }
                    None => {
                        firstexp = group.next_expiry.load(Ordering::Acquire);
                        break;
                    }
                }
            }
            let Some(parent) = group.parent() else {
                break 'up true;
            };
            childmask = group.groupmask.load(Ordering::Relaxed);
            group = parent;
        };
        let st = tmc.state.lock();
        if st.idle {
            // Still the hierarchy's last idle CPU: wake for its first event.
            let wake = if reached_root { firstexp } else { NONE };
            tmc.wakeup.store(wake, Ordering::Release);
        }
        drop(st);
        ran
    }

    /// `tmigr_handle_remote_cpu`: run idle `cpu`'s due global timers here and
    /// requeue its next one. Returns the callbacks run.
    fn handle_remote_cpu(&self, cpu: usize, now: u64) -> u64 {
        let Some(tmc) = self.tmc(cpu) else { return 0 };
        {
            let mut st = tmc.state.lock();
            // Active (ignored event): it handles its own. Remote: another
            // migrator is at it. Not due: its event moved meanwhile.
            if !st.online
                || st.remote
                || !st.idle
                || tmc.cpuevt.ignore.load(Ordering::Acquire)
                || now < tmc.cpuevt.expires()
            {
                return 0;
            }
            st.remote = true;
            tmc.wakeup.store(NONE, Ordering::Release);
        }
        let ran = crate::timer::expire_remote_global(cpu);
        let mut st = tmc.state.lock();
        if st.online && st.idle {
            // Even with no next timer: the walk recomputes the inactive
            // groups this expiry took an event out of.
            let next = crate::timer::global_next(cpu);
            let _ = Self::walk_new_timer(tmc, next, true);
        }
        st.remote = false;
        ran
    }

    /// Whether `cpu` is the migrator of its level-0 group (tests).
    pub fn is_group_migrator(&self, cpu: usize) -> bool {
        self.tmc(cpu)
            .is_some_and(|t| t.group.migr().migrator == t.groupmask)
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

    /// Check every group of a quiescent hierarchy: queue shape, and
    /// migrator ⇔ some child active (test-only).
    #[doc(hidden)]
    pub fn __validate(&self) -> Result<usize, &'static str> {
        let groups = self.groups.lock();
        let mut n = 0;
        for &g in groups.iter() {
            let st = g.lock();
            // SAFETY: the group lock is held.
            n += unsafe { st.events.__validate()? };
            let s = g.migr();
            if s.migrator != TMIGR_NONE && s.active & s.migrator == 0 {
                return Err("a group's migrator is not one of its active children");
            }
            if (s.migrator == TMIGR_NONE) != (s.active == 0) {
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
