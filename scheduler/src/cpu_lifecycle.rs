//! CPU hot-plug / take-offline surface.
//!
//! Spec: `scheduler/specification/spec.md` §3.5. Stage-4 scope: a
//! cap-gated control surface that records per-CPU online/offline
//! state so Stage-4's SMP executor can refuse to dispatch to an
//! offline CPU, and `power/` can suspend / resume an individual core.
//! The startup-IPI / `PSCI CPU_ON` / migrate-queued-tasks mechanics
//! live in `arch/` + `scheduler/` internals respectively and are
//! wired at the SMP-multi-queue integration point — until that
//! lands, the state machine here is correct-by-construction but not
//! load-bearing.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use narf_capabilities::{Cap, CapError, CapKind, CapType, NoopOp};

use crate::affinity::CpuId;
use crate::policy::{self, CpuState};

/// Cap-type marker for the CPU hot-plug surface. `Cap<CpuLifecycle,
/// narf_capabilities::Invoke>` is the authority required by
/// `cpu_bring_up` / `cpu_take_offline`; distinct from
/// `Cap<CpuAffinity, _>` so an audit can tell "may change CPU
/// affinity of tasks" apart from "may park/unpark a CPU".
#[derive(Copy, Clone, Debug)]
pub struct CpuLifecycle;

impl CapType for CpuLifecycle {
    const KIND: CapKind = CapKind::CpuLifecycle;
}

/// Online-state bitmap. Bit `i` set = CPU `i` is currently online.
/// Capped at 64 CPUs — same ceiling as `CpuSet`.
static ONLINE_MASK: AtomicU64 = AtomicU64::new(1); // CPU 0 always starts online
static DRAIN_QUIESCED: [AtomicBool; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicBool::new(false) }; narf_lib::percpu::MAX_CPUS];

/// Target-CPU acknowledgement that its executor is between polls and will not
/// select more work until the lifecycle state returns to Active.
pub(crate) fn acknowledge_drain(cpu: usize) {
    if let Some(ack) = DRAIN_QUIESCED.get(cpu) {
        ack.store(true, Ordering::Release);
    }
}

/// Errors returned by the CPU lifecycle surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HotPlugError {
    /// Authority cap was revoked.
    AuthorityRevoked,
    /// CPU id is outside the 0..=63 supported range.
    OutOfRange,
    /// CPU is already in the requested state.
    NoChange,
    /// A running or pinned task prevents a lossless queue drain.
    Busy,
}

impl From<CapError> for HotPlugError {
    fn from(_: CapError) -> Self {
        HotPlugError::AuthorityRevoked
    }
}

/// Is `cpu` currently online?
#[inline]
pub fn cpu_online(cpu: CpuId) -> bool {
    let id = cpu.0;
    if id >= 64 {
        return false;
    }
    ONLINE_MASK.load(Ordering::Acquire) & (1u64 << id) != 0
}

/// Count of currently-online CPUs.
#[inline]
pub fn online_count() -> u32 {
    ONLINE_MASK.load(Ordering::Acquire).count_ones()
}

/// Bring `cpu` online. Cap-gated; idempotent on already-online cores.
///
/// Stage-4 structural — the real bring-up (INIT-SIPI-SIPI on x86_64,
/// `PSCI CPU_ON` on aarch64) happens in `arch/`; this surface
/// records the logical online state the dispatcher / `power/`
/// consult.
pub fn cpu_bring_up(
    cpu: CpuId,
    cap: &Cap<CpuLifecycle, narf_capabilities::Invoke>,
) -> Result<(), HotPlugError> {
    cap.invoke(NoopOp)?;
    let id = cpu.0;
    if id >= 64 {
        return Err(HotPlugError::OutOfRange);
    }
    // The target must have prepared its own counter during physical bring-up.
    // Never publish an unsupported CPU into an instruction-quantum policy.
    #[cfg(feature = "instruction-quantum")]
    if crate::active_quantum_unit() == crate::QuantumUnit::Instructions
        && !crate::instructions::cpu_available(id as usize)
    {
        return Err(HotPlugError::Busy);
    }
    let bit = 1u64 << id;
    let prev = ONLINE_MASK.fetch_or(bit, Ordering::AcqRel);
    if prev & bit != 0 {
        Err(HotPlugError::NoChange)
    } else {
        if let Some(ack) = DRAIN_QUIESCED.get(id as usize) {
            ack.store(false, Ordering::Release);
        }
        policy::notify_cpu_state(cpu, CpuState::Starting, None);
        policy::notify_cpu_state(cpu, CpuState::Active, None);
        crate::resched_remote(id);
        Ok(())
    }
}

/// Take `cpu` offline. Cap-gated; idempotent on already-offline cores.
pub fn cpu_take_offline(
    cpu: CpuId,
    cap: &Cap<CpuLifecycle, narf_capabilities::Invoke>,
) -> Result<(), HotPlugError> {
    cap.invoke(NoopOp)?;
    let id = cpu.0;
    if id >= 64 {
        return Err(HotPlugError::OutOfRange);
    }
    // CPU 0 is the bootstrap CPU — its offline path is a suspend
    // step, not a normal operation. Refuse outright in Stage-4 until
    // the suspend path is designed end-to-end.
    if id == 0 {
        return Err(HotPlugError::OutOfRange);
    }
    let bit = 1u64 << id;
    if ONLINE_MASK.load(Ordering::Acquire) & bit == 0 {
        return Err(HotPlugError::NoChange);
    }
    if id as usize == narf_lib::percpu::current_cpu() {
        return Err(HotPlugError::Busy);
    }
    DRAIN_QUIESCED[id as usize].store(false, Ordering::Release);
    policy::notify_cpu_state(cpu, CpuState::Draining, None);
    crate::resched_remote(id);

    // A logically-created CPU in a UP test has no executor to acknowledge.
    // A physical online CPU must cross the between-polls barrier before its
    // queue can be inspected or moved. Bound the wait so a non-preemptible or
    // wedged target fails closed as Busy instead of hanging hotplug forever.
    let physical = narf_lib::smp::is_online(id);
    let deadline = narf_time::now_cycles().saturating_add(narf_time::ns_to_cycles(100_000_000));
    while physical && !DRAIN_QUIESCED[id as usize].load(Ordering::Acquire) {
        if narf_time::now_cycles() >= deadline {
            policy::notify_cpu_state(cpu, CpuState::Active, None);
            return Err(HotPlugError::Busy);
        }
        core::hint::spin_loop();
    }
    if crate::cpu_running_task(cpu) || !crate::drain_cpu_queue(cpu) {
        policy::notify_cpu_state(cpu, CpuState::Active, None);
        return Err(HotPlugError::Busy);
    }
    ONLINE_MASK.fetch_and(!bit, Ordering::AcqRel);
    // `hrtimers_cpu_dying`: its queue is gone, so are its timers — every
    // hrtimer still queued on the CPU's base moves to this CPU's base.
    narf_time::hrtimer::hrtimers_cpu_dying(id as usize);
    // `tmigr_cpu_offline`: it leaves the timer-migration hierarchy (its
    // group hands the migrator role on), then `timers_dead_cpu` moves its
    // timer-wheel timers here too.
    narf_time::timer_migration::tmigr_cpu_offline(id as usize);
    narf_time::timer::timers_dead_cpu(id as usize);
    policy::notify_cpu_state(cpu, CpuState::Offline, None);
    Ok(())
}

/// Hibernation's `freeze_secondary_cpus`, without a hot-unplug: stop
/// `cpu`'s executor between polls and keep it there. Its run queue stays
/// as it is, pinned work (per-CPU workers, NAPI) included. Nothing is
/// migrated, so nothing needs a CPU-offline callback.
///
/// A parked CPU is either let go again ([`cpu_unpark`]), or stopped
/// ([`stop_parked`]) and later restarted ([`restart_parked`]). A restarted
/// CPU's executor starts from the top and picks its queue back up. Any
/// online CPU but the caller's may be parked. Cap-gated.
pub fn cpu_park(
    cpu: CpuId,
    cap: &Cap<CpuLifecycle, narf_capabilities::Invoke>,
) -> Result<(), HotPlugError> {
    cap.invoke(NoopOp)?;
    let id = cpu.0;
    if id as usize >= narf_lib::percpu::MAX_CPUS {
        return Err(HotPlugError::OutOfRange);
    }
    if id as usize == narf_lib::percpu::current_cpu() {
        return Err(HotPlugError::Busy);
    }
    if !narf_lib::smp::is_online(id) {
        return Err(HotPlugError::NoChange);
    }
    DRAIN_QUIESCED[id as usize].store(false, Ordering::Release);
    policy::notify_cpu_state(cpu, CpuState::Draining, None);
    crate::resched_remote(id);
    // The same between-polls barrier `cpu_take_offline` waits for, bounded
    // so a wedged CPU fails as Busy rather than hanging the caller.
    let deadline = narf_time::now_cycles().saturating_add(narf_time::ns_to_cycles(100_000_000));
    while !DRAIN_QUIESCED[id as usize].load(Ordering::Acquire) {
        if narf_time::now_cycles() >= deadline {
            policy::notify_cpu_state(cpu, CpuState::Active, None);
            crate::resched_remote(id);
            return Err(HotPlugError::Busy);
        }
        core::hint::spin_loop();
    }
    Ok(())
}

/// Let a [`cpu_park`]ed CPU that was never stopped run again.
pub fn cpu_unpark(
    cpu: CpuId,
    cap: &Cap<CpuLifecycle, narf_capabilities::Invoke>,
) -> Result<(), HotPlugError> {
    cap.invoke(NoopOp)?;
    if cpu.0 as usize >= narf_lib::percpu::MAX_CPUS {
        return Err(HotPlugError::OutOfRange);
    }
    policy::notify_cpu_state(cpu, CpuState::Active, None);
    crate::resched_remote(cpu.0);
    Ok(())
}

/// How the architecture stops and restarts a CPU: INIT and
/// INIT-SIPI-SIPI on x86_64. The boot code installs them once it has
/// started the secondary CPUs.
#[derive(Clone, Copy, Debug)]
pub struct PhysicalHooks {
    /// Stop a parked CPU wherever it is, and mark it offline.
    pub stop: unsafe fn(u32),
    /// Start a stopped CPU again; `true` once it is online.
    pub restart: unsafe fn(u32) -> bool,
}

static PHYSICAL: narf_lib::sync::IrqSafeSpinLock<Option<PhysicalHooks>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Install the architecture's stop and restart.
pub fn set_physical_hooks(hooks: PhysicalHooks) {
    *PHYSICAL.lock() = Some(hooks);
}

/// Stop a parked CPU. `false` without physical hooks: it stays parked.
///
/// # Safety
/// `cpu` is [`cpu_park`]ed: between polls, holding no lock and running no
/// task, so stopping it loses nothing.
pub unsafe fn stop_parked(cpu: CpuId) -> bool {
    let Some(hooks) = *PHYSICAL.lock() else {
        return false;
    };
    // SAFETY: the caller's contract.
    unsafe { (hooks.stop)(cpu.0) };
    true
}

/// Restart a stopped CPU; `true` once it is online again, its executor
/// running its queue.
///
/// # Safety
/// `cpu` was [`stop_parked`], in this kernel or in the one an image was
/// taken from.
pub unsafe fn restart_parked(cpu: CpuId) -> bool {
    let Some(hooks) = *PHYSICAL.lock() else {
        return false;
    };
    // SAFETY: the caller's contract.
    unsafe { (hooks.restart)(cpu.0) }
}

/// Test helper: reset online-mask to boot state (CPU 0 only).
#[doc(hidden)]
pub fn __test_reset_online_mask() {
    ONLINE_MASK.store(1, Ordering::Release);
    for ack in &DRAIN_QUIESCED {
        ack.store(false, Ordering::Release);
    }
    policy::__reset_cpu_states_for_test();
}
