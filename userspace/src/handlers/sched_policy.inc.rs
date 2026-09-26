// ── Scheduling policy state (kernel/sched/syscalls.c) ──────────────────
//
// The policy half of Linux's `task_struct` — `policy`, `rt_priority`,
// `sched_reset_on_fork`, the `dl` reservation and the fair-class
// `se.slice` — as a sparse per-TaskId side table.
//
// The cooperative executor does not route on it: real placement is the
// cap-gated CpuBudget / `SchedClass` surface. What this table buys is the
// ABI. Every `sched_*` syscall validates against it in the order
// `__sched_setscheduler` does, so a Linux program sees the same answers —
// and above all the same errnos — it would on Linux. Before it existed,
// `sched_getscheduler` hard-coded SCHED_OTHER, `sched_setscheduler`
// accepted a NULL param and never checked a priority, and `sched_getattr`
// replayed whatever bytes `sched_setattr` last stored.
//
// Nice is deliberately NOT here. It stays in NICE_TABLE, which
// getpriority/setpriority own; `sched_setattr` writes through to it the way
// `__setscheduler_params` writes `static_prio`.
//
// Configuration this models, where Linux's answer is config-dependent:
//   * !CONFIG_UCLAMP_TASK   — util-clamp requests are -EOPNOTSUPP.
//   * !CONFIG_SCHED_CLASS_EXT — SCHED_EXT is not a valid policy to SET
//                              (the priority-range query still knows it).
//   * !CONFIG_RT_GROUP_SCHED — no per-cgroup RT runtime refusal.
//   * CONFIG_HZ = 100        — matches NARF's USER_HZ; only the fair-class
//                              `sched_rr_get_interval` rounding sees it.
//   * One root domain spanning every online CPU, default DL bandwidth
//     (`sched_rt_runtime_us` 950000 / `sched_rt_period_us` 1000000).

const SCHED_OTHER: i32 = 0;
const SCHED_FIFO: i32 = 1;
const SCHED_RR: i32 = 2;
const SCHED_BATCH: i32 = 3;
const SCHED_IDLE: i32 = 5;
/// `include/uapi/linux/sched.h`. SCHED_DEADLINE is only reachable through
/// `sched_setattr` (a `sched_param` cannot carry its runtime/deadline/period,
/// so `sched_setscheduler` fails `__checkparam_dl`); SCHED_EXT needs
/// CONFIG_SCHED_CLASS_EXT. Both are still *recognised* by the
/// priority-range query below.
const SCHED_DEADLINE: i32 = 6;
const SCHED_EXT: i32 = 7;
/// `kernel/sched/sched.h` — "keep the current policy" sentinel that
/// `sched_setparam` and `SCHED_FLAG_KEEP_POLICY` pass down.
const SETPARAM_POLICY: i32 = -1;
/// `include/uapi/linux/sched.h` — the legacy flag ORed into a
/// `sched_setscheduler` policy and back into `sched_getscheduler`'s answer.
const SCHED_RESET_ON_FORK: i32 = 0x4000_0000;
/// `include/linux/sched/prio.h`.
const MAX_RT_PRIO: u32 = 100;

/// `include/uapi/linux/sched.h` `SCHED_FLAG_*`.
const SCHED_FLAG_RESET_ON_FORK: u64 = 0x01;
const SCHED_FLAG_RECLAIM: u64 = 0x02;
const SCHED_FLAG_DL_OVERRUN: u64 = 0x04;
const SCHED_FLAG_KEEP_POLICY: u64 = 0x08;
const SCHED_FLAG_KEEP_PARAMS: u64 = 0x10;
/// `SCHED_FLAG_UTIL_CLAMP_MIN | SCHED_FLAG_UTIL_CLAMP_MAX`.
const SCHED_FLAG_UTIL_CLAMP: u64 = 0x20 | 0x40;
/// `SCHED_FLAG_ALL` — every flag the ABI defines. A flag outside this is a
/// caller expecting something no kernel does.
const SCHED_FLAG_ALL: u64 = SCHED_FLAG_RESET_ON_FORK
    | SCHED_FLAG_RECLAIM
    | SCHED_FLAG_DL_OVERRUN
    | SCHED_FLAG_KEEP_POLICY
    | SCHED_FLAG_KEEP_PARAMS
    | SCHED_FLAG_UTIL_CLAMP;
/// `kernel/sched/sched.h` — kernel-internal (schedutil worker threads).
/// `__sched_setscheduler` lets it past the flag mask and then refuses it
/// from userspace AFTER the permission check, which fixes the errno order.
const SCHED_FLAG_SUGOV: u64 = 0x1000_0000;
/// `kernel/sched/sched.h` — the flags a deadline entity keeps.
const SCHED_DL_FLAGS: u64 = SCHED_FLAG_RECLAIM | SCHED_FLAG_DL_OVERRUN | SCHED_FLAG_SUGOV;

/// `SCHED_ATTR_SIZE_VER0` (`include/uapi/linux/sched/types.h:7`) — the first
/// published `struct sched_attr`, and the largest NARF knows.
///
/// Linux's current `sizeof(struct sched_attr)` is `SCHED_ATTR_SIZE_VER1`
/// (56): VER1 added `sched_util_min`/`sched_util_max`, which need uclamp
/// support in the scheduler. NARF has none, so it reports VER0 — which is
/// not a shortfall in the ABI but a legitimate configuration of it. A
/// modern caller passing 56 bytes with those fields ZERO is accepted
/// (`copy_struct_from_user` ignores a zero tail); one that actually sets
/// them gets -E2BIG, which is exactly what a pre-VER1 kernel answers and is
/// how the caller learns to stop asking.
const SCHED_ATTR_SIZE_VER0: usize = 48;
/// `SCHED_ATTR_SIZE_VER1` — named so the `SCHED_FLAG_UTIL_CLAMP` rule can
/// cite the size it requires.
const SCHED_ATTR_SIZE_VER1: usize = 56;
/// The largest `sched_attr` this kernel understands.
const SCHED_ATTR_SIZE: usize = SCHED_ATTR_SIZE_VER0;

/// `include/uapi/asm-generic/resource.h`.
const RLIMIT_RTPRIO: usize = 14;

/// CONFIG_HZ this model rounds `sched_rr_get_interval` to (see the header).
const SCHED_HZ: u64 = 100;
/// `include/linux/sched/rt.h::RR_TIMESLICE` — `100 * HZ / 1000` jiffies,
/// i.e. 100 ms at any HZ that divides it.
const SCHED_RR_TIMESLICE_NS: u64 = 100_000_000;

/// `kernel/sched/deadline.c` defaults: `sysctl_sched_dl_period_max` is
/// `1 << 22` µs, `sysctl_sched_dl_period_min` is 100 µs.
const DL_PERIOD_MAX_NS: u64 = (1u64 << 22) * 1000;
const DL_PERIOD_MIN_NS: u64 = 100 * 1000;
/// `kernel/sched/sched.h::DL_SCALE`.
const DL_SCALE: u32 = 10;
/// `kernel/sched/sched.h::BW_SHIFT`.
const BW_SHIFT: u32 = 20;
/// `dl_b->bw` = `to_ratio(global_rt_period(), global_rt_runtime())` with the
/// default 950000 / 1000000 µs split.
const DL_DEFAULT_BW: u64 = (950_000_000u64 << BW_SHIFT) / 1_000_000_000;

/// The scheduling half of one task's `task_struct`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct SchedState {
    policy: i32,
    rt_priority: u32,
    reset_on_fork: bool,
    dl_runtime: u64,
    dl_deadline: u64,
    dl_period: u64,
    dl_flags: u64,
    /// `se.custom_slice ? se.slice : 0` — a fair-class slice the task asked
    /// for through `sched_setattr`. Zero means the system base slice.
    custom_slice: u64,
}

impl SchedState {
    /// A fresh task: SCHED_NORMAL, no RT priority, no reservation.
    const DEFAULT: Self = Self {
        policy: SCHED_OTHER,
        rt_priority: 0,
        reset_on_fork: false,
        dl_runtime: 0,
        dl_deadline: 0,
        dl_period: 0,
        dl_flags: 0,
        custom_slice: 0,
    };
}

/// Sparse: an absent row is [`SchedState::DEFAULT`].
static SCHED_STATE_TABLE: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, SchedState>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);
/// Exact count of rows, so the all-default case (every fork of a task that
/// never touched its policy) skips the IRQ-disabling lock entirely — the
/// same shape as NICE_CUSTOM_ROWS.
static SCHED_STATE_ROWS: AtomicUsize = AtomicUsize::new(0);

pub fn sched_param_init() {
    *SCHED_STATE_TABLE.lock() = Some(BTreeMap::new());
    SCHED_STATE_ROWS.store(0, Ordering::Release);
}

#[doc(hidden)]
pub fn __test_sched_param_reset() {
    sched_param_init();
}

fn read_sched_state(task: u64) -> SchedState {
    if SCHED_STATE_ROWS.load(Ordering::Acquire) == 0 {
        return SchedState::DEFAULT;
    }
    SCHED_STATE_TABLE
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task).copied())
        .unwrap_or(SchedState::DEFAULT)
}

fn write_sched_state(task: u64, state: SchedState) {
    let mut g = SCHED_STATE_TABLE.lock();
    let m = g.get_or_insert_with(BTreeMap::new);
    if state == SchedState::DEFAULT {
        if m.remove(&task).is_some() {
            SCHED_STATE_ROWS.fetch_sub(1, Ordering::Release);
        }
    } else if m.insert(task, state).is_none() {
        // Publish the row before lock-free readers may consult the map.
        SCHED_STATE_ROWS.fetch_add(1, Ordering::Release);
    }
}

/// Exit-time teardown, called from `release_task_tables`.
fn sched_state_release(task: u64) {
    if SCHED_STATE_ROWS.load(Ordering::Acquire) == 0 {
        return;
    }
    if let Some(m) = SCHED_STATE_TABLE.lock().as_mut() {
        if m.remove(&task).is_some() {
            SCHED_STATE_ROWS.fetch_sub(1, Ordering::Release);
        }
    }
}

#[doc(hidden)]
/// Test-only: make `task` SCHED_FIFO at `val` (or SCHED_OTHER for 0).
///
/// Lets a test give a task a DISTINGUISHABLE `sched_priority` without
/// running it through `sched_setscheduler`'s privilege checks, so tests
/// about pid-namespace translation stay about the translation.
pub fn __test_set_sched_param(task: u64, val: i32) {
    let mut st = read_sched_state(task);
    if val == 0 {
        st.policy = SCHED_OTHER;
        st.rt_priority = 0;
    } else {
        st.policy = SCHED_FIFO;
        st.rt_priority = val as u32;
    }
    write_sched_state(task, st);
}

#[doc(hidden)]
/// Test-only: the policy word `sched_getscheduler` would report for `task`.
pub fn __test_sched_policy_of(task: u64) -> i32 {
    let st = read_sched_state(task);
    st.policy
        | if st.reset_on_fork {
            SCHED_RESET_ON_FORK
        } else {
            0
        }
}

#[doc(hidden)]
/// Test-only: drive the fork-time inheritance directly between two ids.
pub fn __test_sched_fork(parent: u64, child: u64) {
    sched_fork(parent, child);
}

#[doc(hidden)]
/// Test-only: would `fork()` from `parent` be refused by `sched_fork`?
pub fn __test_sched_fork_denied(parent: u64) -> bool {
    sched_fork_denied(parent)
}

// `kernel/sched/sched.h` policy predicates.
fn idle_policy(policy: i32) -> bool {
    policy == SCHED_IDLE
}
/// `normal_policy() || SCHED_BATCH` — without CONFIG_SCHED_CLASS_EXT.
/// Note SCHED_IDLE is NOT a fair policy here, even though it runs in the
/// fair class: `__setscheduler_params` only writes `static_prio` for these.
fn fair_policy(policy: i32) -> bool {
    policy == SCHED_OTHER || policy == SCHED_BATCH
}
fn rt_policy(policy: i32) -> bool {
    policy == SCHED_FIFO || policy == SCHED_RR
}
fn dl_policy(policy: i32) -> bool {
    policy == SCHED_DEADLINE
}
fn valid_policy(policy: i32) -> bool {
    idle_policy(policy) || fair_policy(policy) || rt_policy(policy) || dl_policy(policy)
}

/// `kernel/sched/syscalls.c::SYSCALL_DEFINE1(sched_get_priority_max)`.
///
/// ```text
/// int ret = -EINVAL;
/// switch (policy) {
/// case SCHED_FIFO: case SCHED_RR:  ret = MAX_RT_PRIO-1; break;   /* 99 */
/// case SCHED_DEADLINE: case SCHED_NORMAL: case SCHED_BATCH:
/// case SCHED_IDLE: case SCHED_EXT: ret = 0; break;
/// }
/// return ret;
/// ```
///
/// Linux's version is a bare switch with NO capability or admission check,
/// so SCHED_DEADLINE/SCHED_EXT report a range here even though
/// `sched_setscheduler` refuses them. Reporting EINVAL for those two made
/// a libc probing the range before choosing a policy conclude the kernel
/// was too old to know the constant at all.
fn priority_max_for_policy(policy: i32) -> Option<i64> {
    match policy {
        SCHED_OTHER | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE | SCHED_EXT => Some(0),
        SCHED_FIFO | SCHED_RR => Some(i64::from(MAX_RT_PRIO) - 1),
        _ => None,
    }
}

/// `kernel/sched/syscalls.c::SYSCALL_DEFINE1(sched_get_priority_min)` — the
/// same switch, returning 1 for the two real-time policies.
fn priority_min_for_policy(policy: i32) -> Option<i64> {
    match policy {
        SCHED_OTHER | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE | SCHED_EXT => Some(0),
        SCHED_FIFO | SCHED_RR => Some(1),
        _ => None,
    }
}

/// `find_process_by_pid(pid)` — `pid ? find_task_by_vpid(pid) : current`.
///
/// The pid is resolved in the CALLER's pid namespace. `proc_pid_to_tid`
/// falls back to the identity mapping for an unregistered pid, so the
/// registry lookup is what makes a pid that names nothing come back `None`
/// (→ -ESRCH) instead of silently addressing a phantom row. The caller
/// itself always resolves, even in syscall-unit fixtures that never
/// populate the task registry.
///
/// Callers reject `pid < 0` with -EINVAL themselves where Linux does; the
/// affinity pair, which does not, gets `None` here.
fn find_process_by_pid(pid: i32) -> Option<u64> {
    let caller = current_task_id();
    if pid == 0 {
        return Some(caller);
    }
    if pid < 0 {
        return None;
    }
    let outer = accept_pid_from(caller, pid as u64)?;
    let task = proc_pid_to_tid(outer);
    if task == caller || crate::task::task_get(task).is_some() {
        Some(task)
    } else {
        None
    }
}

/// `sysctl_sched_base_slice`: 0.75 ms scaled by `1 + ilog2(min(cpus, 8))`
/// (SCHED_TUNABLESCALING_LOG, recomputed as CPUs come and go).
fn sched_base_slice_ns() -> u64 {
    let cpus = narf_scheduler::online_cpu_set()
        .bits()
        .count_ones()
        .clamp(1, 8);
    750_000 * (1 + u64::from(cpus.ilog2()))
}

/// `p->se.slice`.
fn task_slice_ns(state: &SchedState) -> u64 {
    if state.custom_slice != 0 {
        state.custom_slice
    } else {
        sched_base_slice_ns()
    }
}

/// `kernel/sched/sched.h::to_ratio(period, runtime)`.
fn dl_to_ratio(period: u64, runtime: u64) -> u64 {
    if period == 0 {
        return 0;
    }
    ((u128::from(runtime) << BW_SHIFT) / u128::from(period)) as u64
}

/// The kernel-side `struct sched_attr`, VER0 layout:
///
/// ```text
/// u32 size; u32 sched_policy; u64 sched_flags; s32 sched_nice;
/// u32 sched_priority; u64 sched_runtime, sched_deadline, sched_period;
/// ```
#[derive(Clone, Copy, Default)]
struct SchedAttr {
    size: u32,
    /// `__u32` on the wire; signed here because `(int)sched_policy < 0` and
    /// `SETPARAM_POLICY` are both meaningful.
    policy: i32,
    flags: u64,
    nice: i32,
    priority: u32,
    runtime: u64,
    deadline: u64,
    period: u64,
}

impl SchedAttr {
    fn from_bytes(b: &[u8; SCHED_ATTR_SIZE]) -> Self {
        let u32_at = |o: usize| u32::from_ne_bytes(b[o..o + 4].try_into().unwrap());
        let u64_at = |o: usize| u64::from_ne_bytes(b[o..o + 8].try_into().unwrap());
        Self {
            size: u32_at(0),
            policy: u32_at(4) as i32,
            flags: u64_at(8),
            nice: u32_at(16) as i32,
            priority: u32_at(20),
            runtime: u64_at(24),
            deadline: u64_at(32),
            period: u64_at(40),
        }
    }

    fn to_bytes(self) -> [u8; SCHED_ATTR_SIZE] {
        let mut b = [0u8; SCHED_ATTR_SIZE];
        b[0..4].copy_from_slice(&self.size.to_ne_bytes());
        b[4..8].copy_from_slice(&self.policy.to_ne_bytes());
        b[8..16].copy_from_slice(&self.flags.to_ne_bytes());
        b[16..20].copy_from_slice(&self.nice.to_ne_bytes());
        b[20..24].copy_from_slice(&self.priority.to_ne_bytes());
        b[24..32].copy_from_slice(&self.runtime.to_ne_bytes());
        b[32..40].copy_from_slice(&self.deadline.to_ne_bytes());
        b[40..48].copy_from_slice(&self.period.to_ne_bytes());
        b
    }
}

/// `kernel/sched/syscalls.c::get_params(p, attr)` — the task's current
/// parameters, as `sched_getattr` and `SCHED_FLAG_KEEP_PARAMS` see them.
fn sched_get_params(task: u64, state: &SchedState, attr: &mut SchedAttr) {
    if dl_policy(state.policy) {
        // `__getparam_dl`.
        attr.priority = state.rt_priority;
        attr.runtime = state.dl_runtime;
        attr.deadline = state.dl_deadline;
        attr.period = state.dl_period;
        attr.flags &= !SCHED_DL_FLAGS;
        attr.flags |= state.dl_flags;
    } else if rt_policy(state.policy) {
        attr.priority = state.rt_priority;
    } else {
        attr.nice = read_nice(process_state_key(task));
        attr.runtime = task_slice_ns(state);
    }
}

/// `kernel/sched/deadline.c::__checkparam_dl`.
fn sched_checkparam_dl(attr: &SchedAttr) -> bool {
    // Special dl tasks don't actually use any parameter.
    if attr.flags & SCHED_FLAG_SUGOV != 0 {
        return true;
    }
    if attr.deadline == 0 {
        return false;
    }
    // "Since we truncate DL_SCALE bits, make sure we're at least that big."
    if attr.runtime < (1u64 << DL_SCALE) {
        return false;
    }
    // The MSB is reserved for wrap-around arithmetic.
    if attr.deadline & (1u64 << 63) != 0 || attr.period & (1u64 << 63) != 0 {
        return false;
    }
    let period = if attr.period == 0 {
        attr.deadline
    } else {
        attr.period
    };
    // runtime <= deadline <= period (if period != 0)
    if period < attr.deadline || attr.deadline < attr.runtime {
        return false;
    }
    (DL_PERIOD_MIN_NS..=DL_PERIOD_MAX_NS).contains(&period)
}

/// `kernel/sched/deadline.c::dl_param_changed`.
fn sched_dl_param_changed(state: &SchedState, attr: &SchedAttr) -> bool {
    state.dl_runtime != attr.runtime
        || state.dl_deadline != attr.deadline
        || state.dl_period != attr.period
        || state.dl_flags != (attr.flags & SCHED_DL_FLAGS)
}

/// `kernel/sched/deadline.c::sched_dl_overflow` — `true` means the
/// admission test FAILED (-EBUSY).
///
/// One root domain spanning every online CPU, so `dl_b->total_bw` is the
/// sum over every SCHED_DEADLINE row and the capacity is
/// `cap_scale(dl_b->bw, cpus << SCHED_CAPACITY_SHIFT)` = `bw * cpus`.
fn sched_dl_overflow(state: &SchedState, policy: i32, attr: &SchedAttr) -> bool {
    let period = if attr.period != 0 {
        attr.period
    } else {
        attr.deadline
    };
    let new_bw = if dl_policy(policy) {
        dl_to_ratio(period, attr.runtime)
    } else {
        0
    };
    let old_bw = if dl_policy(state.policy) {
        dl_to_ratio(state.dl_period, state.dl_runtime)
    } else {
        0
    };
    // "!deadline task may carry old deadline bandwidth"
    if new_bw == old_bw && dl_policy(state.policy) {
        return false;
    }
    let cpus = u64::from(narf_scheduler::online_cpu_set().bits().count_ones().max(1));
    let capacity = DL_DEFAULT_BW * cpus;
    let total_bw: u64 = SCHED_STATE_TABLE
        .lock()
        .as_ref()
        .map(|m| {
            m.values()
                .filter(|st| dl_policy(st.policy))
                .map(|st| dl_to_ratio(st.dl_period, st.dl_runtime))
                .sum()
        })
        .unwrap_or(0);
    // `__dl_overflow`: `cap_scale(dl_b->bw, cap) < total_bw - old_bw + new_bw`.
    let overflows = |old: u64| capacity < total_bw - old + new_bw;
    match (dl_policy(policy), dl_policy(state.policy)) {
        // Entering SCHED_DEADLINE.
        (true, false) => overflows(0),
        // Changing an existing reservation.
        (true, true) => overflows(old_bw),
        // Leaving SCHED_DEADLINE always succeeds.
        (false, true) => false,
        // `err = -1` falls through when neither side is a deadline policy;
        // callers only ask when one is.
        (false, false) => true,
    }
}

/// `kernel/sched/syscalls.c::is_nice_reduction` — may `task` hold `nice`
/// under its own RLIMIT_NICE?
fn is_nice_reduction(task: u64, nice: i32) -> bool {
    // `nice_to_rlimit(nice) = 20 - nice`, i.e. [19, -20] → [1, 40].
    let nice_rlim = (20 - i64::from(nice)) as u64;
    let ceiling = read_rlimit(task, RLIMIT_NICE).map(|l| l.cur).unwrap_or(0);
    nice_rlim <= ceiling
}

/// `kernel/sched/syscalls.c::check_same_owner` — the caller's EFFECTIVE uid
/// against the target's real or effective uid.
fn sched_check_same_owner(task: u64) -> bool {
    let me = read_uidgid(current_task_id()).euid;
    let them = read_uidgid(task);
    me == them.euid || me == them.uid
}

/// `kernel/sched/syscalls.c::user_check_sched_setscheduler`.
///
/// Every refusal funnels through `req_priv`, which is `capable()` — the
/// INITIAL user namespace — not `ns_capable` over the target: unlike
/// setpriority, a container root cannot raise scheduling class.
fn sched_user_check(
    task: u64,
    state: &SchedState,
    attr: &SchedAttr,
    policy: i32,
    reset_on_fork: bool,
) -> Result<(), i64> {
    let req_priv = || {
        if capable(CAP_SYS_NICE) {
            Ok(())
        } else {
            Err(EPERM)
        }
    };
    let nice_now = read_nice(process_state_key(task));

    if fair_policy(policy) && attr.nice < nice_now && !is_nice_reduction(task, attr.nice) {
        return req_priv();
    }
    if rt_policy(policy) {
        let rlim_rtprio = read_rlimit(task, RLIMIT_RTPRIO).map(|l| l.cur).unwrap_or(0);
        // Can't set/change the rt policy:
        if policy != state.policy && rlim_rtprio == 0 {
            return req_priv();
        }
        // Can't increase priority:
        if attr.priority > state.rt_priority && u64::from(attr.priority) > rlim_rtprio {
            return req_priv();
        }
    }
    // "Can't set/change SCHED_DEADLINE policy at all for now".
    if dl_policy(policy) {
        return req_priv();
    }
    // Treat SCHED_IDLE as nice 20: leaving it needs RLIMIT_NICE headroom
    // for the nice the task would resume at.
    if idle_policy(state.policy) && !idle_policy(policy) && !is_nice_reduction(task, nice_now) {
        return req_priv();
    }
    // Can't change other user's priorities:
    if !sched_check_same_owner(task) {
        return req_priv();
    }
    // Normal users shall not reset the sched_reset_on_fork flag:
    if state.reset_on_fork && !reset_on_fork {
        return req_priv();
    }
    Ok(())
}

/// `kernel/sched/syscalls.c::__sched_setscheduler(p, attr, user = true, ..)`
/// — the one validator every setter funnels into, in Linux's order.
///
/// `attr.policy == SETPARAM_POLICY` keeps the task's current policy (and
/// its `reset_on_fork`), which is how `sched_setparam` and
/// `SCHED_FLAG_KEEP_POLICY` arrive here.
fn sched_setscheduler_checked(task: u64, attr: &SchedAttr) -> Result<(), i64> {
    let state = read_sched_state(task);
    let (policy, reset_on_fork) = if attr.policy < 0 {
        (state.policy, state.reset_on_fork)
    } else {
        if !valid_policy(attr.policy) {
            return Err(EINVAL);
        }
        (attr.policy, attr.flags & SCHED_FLAG_RESET_ON_FORK != 0)
    };
    if attr.flags & !(SCHED_FLAG_ALL | SCHED_FLAG_SUGOV) != 0 {
        return Err(EINVAL);
    }
    // "Valid priorities for SCHED_FIFO and SCHED_RR are 1..MAX_RT_PRIO-1,
    // valid priority for SCHED_NORMAL, SCHED_BATCH and SCHED_IDLE is 0."
    // `sched_priority` is unsigned here, so a negative `sched_param` value
    // lands above the bound and is refused by the same test.
    if attr.priority > MAX_RT_PRIO - 1 {
        return Err(EINVAL);
    }
    if (dl_policy(policy) && !sched_checkparam_dl(attr))
        || (rt_policy(policy) != (attr.priority != 0))
    {
        return Err(EINVAL);
    }
    sched_user_check(task, &state, attr, policy, reset_on_fork)?;
    if attr.flags & SCHED_FLAG_SUGOV != 0 {
        return Err(EINVAL);
    }
    // `uclamp_validate` without CONFIG_UCLAMP_TASK.
    if attr.flags & SCHED_FLAG_UTIL_CLAMP != 0 {
        return Err(EOPNOTSUPP);
    }

    // "If not changing anything there's no need to proceed further, but
    // store a possible modification of reset_on_fork."
    if policy == state.policy {
        let changed = if fair_policy(policy) {
            attr.nice != read_nice(process_state_key(task)) || attr.runtime != task_slice_ns(&state)
        } else if rt_policy(policy) {
            attr.priority != state.rt_priority
        } else if dl_policy(policy) {
            sched_dl_param_changed(&state, attr)
        } else {
            false
        };
        if !changed {
            write_sched_state(
                task,
                SchedState {
                    reset_on_fork,
                    ..state
                },
            );
            return Ok(());
        }
    }

    // `change:` — the admission checks only a real change pays for.
    if dl_policy(policy) {
        // "Don't allow tasks with an affinity mask smaller than the entire
        // root_domain to become SCHED_DEADLINE."
        let span = narf_scheduler::online_cpu_set().bits();
        if span & !task_cpus_allowed(task) != 0 {
            return Err(EPERM);
        }
    }
    if (dl_policy(policy) || dl_policy(state.policy)) && sched_dl_overflow(&state, policy, attr) {
        return Err(EBUSY);
    }

    // `__setscheduler_params`.
    let mut next = SchedState {
        policy,
        reset_on_fork,
        rt_priority: attr.priority,
        ..state
    };
    if dl_policy(policy) {
        next.dl_runtime = attr.runtime;
        next.dl_deadline = attr.deadline;
        next.dl_period = if attr.period != 0 {
            attr.period
        } else {
            attr.deadline
        };
        next.dl_flags = attr.flags & SCHED_DL_FLAGS;
    } else {
        next.dl_runtime = 0;
        next.dl_deadline = 0;
        next.dl_period = 0;
        next.dl_flags = 0;
        if fair_policy(policy) {
            let _ = write_nice(process_state_key(task), attr.nice);
            next.custom_slice = if attr.runtime != 0 {
                // NSEC_PER_MSEC/10 ..= NSEC_PER_MSEC*100.
                attr.runtime.clamp(100_000, 100_000_000)
            } else {
                0
            };
        }
    }
    write_sched_state(task, next);
    Ok(())
}

/// The `sched_attr` a `sched_param`-shaped setter builds —
/// `_sched_setscheduler`:
///
/// ```text
/// struct sched_attr attr = {
///         .sched_policy   = policy,
///         .sched_priority = param->sched_priority,
///         .sched_nice     = PRIO_TO_NICE(p->static_prio),
/// };
/// if (p->se.custom_slice) attr.sched_runtime = p->se.slice;
/// if ((policy != SETPARAM_POLICY) && (policy & SCHED_RESET_ON_FORK)) {
///         attr.sched_flags |= SCHED_FLAG_RESET_ON_FORK;
///         policy &= ~SCHED_RESET_ON_FORK;
///         attr.sched_policy = policy;
/// }
/// ```
fn sched_param_attr(task: u64, policy: i32, priority: i32) -> SchedAttr {
    let state = read_sched_state(task);
    let mut attr = SchedAttr {
        policy,
        priority: priority as u32,
        nice: read_nice(process_state_key(task)),
        runtime: state.custom_slice,
        ..SchedAttr::default()
    };
    if policy != SETPARAM_POLICY && policy & SCHED_RESET_ON_FORK != 0 {
        attr.flags |= SCHED_FLAG_RESET_ON_FORK;
        attr.policy = policy & !SCHED_RESET_ON_FORK;
    }
    attr
}

/// `do_sched_setscheduler(pid, policy, param)` — the shared body of
/// `sched_setscheduler` and `sched_setparam`:
///
/// ```text
/// if (unlikely(!param || pid < 0))                     return -EINVAL;
/// if (copy_from_user(&lparam, param, sizeof(...)))     return -EFAULT;
/// CLASS(find_get_task, p)(pid); if (!p)                return -ESRCH;
/// return sched_setscheduler(p, policy, &lparam);
/// ```
fn do_sched_setscheduler(pid: i32, policy: i32, param: u64) -> Result<(), i64> {
    if param == 0 || pid < 0 {
        return Err(EINVAL);
    }
    let mut buf = [0u8; 4];
    // SAFETY: copy_from_user range-validates and SMAP-brackets the 4-byte
    // `struct sched_param` read.
    if unsafe { copy_from_user(&mut buf, param) }.is_err() {
        return Err(EFAULT);
    }
    let task = find_process_by_pid(pid).ok_or(ESRCH)?;
    let attr = sched_param_attr(task, policy, i32::from_ne_bytes(buf));
    sched_setscheduler_checked(task, &attr)
}

/// `sched_fork`'s refusal: a SCHED_DEADLINE task may not fork unless it
/// asked for `reset_on_fork` — `if (dl_prio(p->prio)) return -EAGAIN;`
/// runs after the reset, so only a reservation that would be DUPLICATED is
/// refused.
fn sched_fork_denied(parent: u64) -> bool {
    let st = read_sched_state(parent);
    dl_policy(st.policy) && !st.reset_on_fork
}

/// `kernel/sched/core.c::sched_fork` inheritance: the child copies the
/// parent's policy, priority and nice — unless `reset_on_fork` is set, in
/// which case an RT/DL parent's child restarts as SCHED_NORMAL at nice 0,
/// a fair parent's child loses only a negative nice and any custom slice,
/// and the flag itself is consumed.
///
/// Nice lives in NICE_TABLE keyed by PROCESS, so a CLONE_THREAD child
/// already shares it; only a new process copies it. (Linux's per-thread
/// reset of a negative nice on a CLONE_THREAD child therefore cannot be
/// represented and is skipped.)
fn sched_fork(parent: u64, child: u64) {
    let parent_key = process_state_key(parent);
    let child_key = process_state_key(child);
    let mut nice = read_nice(parent_key);
    let mut st = read_sched_state(parent);
    if st.reset_on_fork {
        if dl_policy(st.policy) || rt_policy(st.policy) {
            st = SchedState::DEFAULT;
            nice = 0;
        } else if nice < 0 {
            nice = 0;
        }
        st.custom_slice = 0;
        st.reset_on_fork = false;
    }
    if st != SchedState::DEFAULT {
        write_sched_state(child, st);
    }
    if child_key != parent_key && nice != 0 {
        let _ = write_nice(child_key, nice);
    }
}
