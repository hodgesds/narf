//! CPU idle selection, residency feedback, and hardware entry.

use super::{CState, CStateIdx, IdleGovernor, Power, PowerError};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use narf_capabilities::{Cap, Grant};
use narf_lib::sync::IrqSafeSpinLock;

pub const MAX_IDLE_STATES: usize = 16;
const MAX_CPUS: usize = narf_lib::percpu::MAX_CPUS;

/// Facts provided by the executor, in the same counter domain as the timer wheel.
#[derive(Clone, Copy, Debug)]
pub struct IdleHints {
    pub cpu: usize,
    pub now_cycles: u64,
    pub next_deadline_cycles: Option<u64>,
}

/// Governor inputs after applying per-CPU history and the wake-latency constraint.
#[derive(Clone, Copy, Debug)]
pub struct IdleContext {
    pub cpu: usize,
    pub deadline_us: u64,
    pub predicted_idle_us: u64,
    pub latency_limit_us: u64,
}

/// A governor recommends a state and whether the periodic scheduler tick may stop.
#[derive(Clone, Copy, Debug)]
pub struct IdleDecision {
    pub state: CStateIdx,
    pub stop_tick: bool,
}

/// Architecture entry parameters. Firmware discovery supplies exact hints/ports;
/// an ACPI state number is never translated into an invented MWAIT encoding.
#[derive(Clone, Copy, Debug)]
pub enum IdleEntry {
    Poll,
    Halt,
    Mwait {
        hint: u32,
    },
    SystemIo {
        port: u16,
        acpi_type: u8,
    },
    /// Registered kernel callback; must accept and return with IRQs masked and
    /// preserve the pending-interrupt wake condition. Registration is cap-gated.
    Callback(fn()),
}

#[derive(Clone, Copy, Debug)]
pub struct IdleState {
    pub id: u8,
    pub exit_latency_us: u32,
    pub target_residency_us: u32,
    pub entry: IdleEntry,
}

const POLL: IdleState = IdleState {
    id: 0,
    exit_latency_us: 0,
    target_residency_us: 0,
    entry: IdleEntry::Poll,
};
const HALT: IdleState = IdleState {
    id: 1,
    exit_latency_us: 1,
    target_residency_us: 2,
    entry: IdleEntry::Halt,
};

/// Selected and revalidated before the executor's final wake check. The value
/// owns no locks or borrowed registry data across hardware idle entry.
#[derive(Clone, Copy, Debug)]
pub struct IdlePlan {
    state: IdleState,
    stop_tick: bool,
    generation: u64,
    cpu: usize,
}

impl IdlePlan {
    pub fn state(&self) -> IdleState {
        self.state
    }
    pub fn stop_tick(&self) -> bool {
        self.stop_tick
    }
}

impl Default for IdlePlan {
    fn default() -> Self {
        Self {
            state: HALT,
            stop_tick: true,
            generation: 0,
            cpu: usize::MAX,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct IdleStats {
    pub entries: u64,
    pub residency_cycles: u64,
    pub last_state: u8,
    pub predicted_idle_us: u64,
}

struct CpuIdle {
    generation: u64,
    states: [IdleState; MAX_IDLE_STATES],
    len: usize,
    stats: IdleStats,
    latency_limit_us: u64,
}
impl CpuIdle {
    const fn new() -> Self {
        Self {
            generation: 0,
            states: [POLL; MAX_IDLE_STATES],
            len: 0,
            stats: IdleStats {
                entries: 0,
                residency_cycles: 0,
                last_state: 0,
                predicted_idle_us: 0,
            },
            latency_limit_us: u64::MAX,
        }
    }
}
#[repr(align(64))]
struct CpuSlot(IrqSafeSpinLock<CpuIdle>);
static CPUS: [CpuSlot; MAX_CPUS] =
    [const { CpuSlot(IrqSafeSpinLock::new(CpuIdle::new())) }; MAX_CPUS];

struct CachedGovernor {
    generation: u64,
    governor: Option<Arc<dyn IdleGovernor>>,
}
#[repr(align(64))]
struct GovernorSlot(IrqSafeSpinLock<CachedGovernor>);
static GOVERNORS: [GovernorSlot; MAX_CPUS] = [const {
    GovernorSlot(IrqSafeSpinLock::new(CachedGovernor {
        generation: 0,
        governor: None,
    }))
}; MAX_CPUS];
pub(super) static POLICY_GENERATION: AtomicU64 = AtomicU64::new(1);
pub(super) static STATE_GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
struct FirmwareStates {
    apic_id: u32,
    states: [IdleState; MAX_IDLE_STATES],
    len: usize,
}
static FIRMWARE: IrqSafeSpinLock<alloc::vec::Vec<FirmwareStates>> =
    IrqSafeSpinLock::new(alloc::vec::Vec::new());

/// Boot/cold-path firmware publication, keyed by hardware APIC identity, not
/// namespace enumeration order. Unsupported entries are filtered on the CPU
/// that would execute them before they become governor candidates.
pub fn register_firmware_states(
    cap: &Cap<Power, Grant>,
    apic_id: u32,
    states: &[IdleState],
) -> Result<(), PowerError> {
    cap.check_live()?;
    if states.len() > MAX_IDLE_STATES {
        return Err(PowerError::NoMatchingState);
    }
    let mut entry = FirmwareStates {
        apic_id,
        states: [POLL; MAX_IDLE_STATES],
        len: states.len(),
    };
    entry.states[..states.len()].copy_from_slice(states);
    let mut table = FIRMWARE.lock();
    if let Some(old) = table.iter_mut().find(|s| s.apic_id == apic_id) {
        *old = entry;
    } else {
        if table.len() == MAX_CPUS {
            return Err(PowerError::NoMatchingState);
        }
        table.push(entry);
    }
    STATE_GENERATION.fetch_add(1, Ordering::Release);
    Ok(())
}

pub fn set_idle_latency_limit(
    cap: &Cap<Power, Grant>,
    cpu: usize,
    limit_us: u64,
) -> Result<(), PowerError> {
    cap.check_live()?;
    let slot = CPUS.get(cpu).ok_or(PowerError::NoMatchingState)?;
    slot.0.lock().latency_limit_us = limit_us;
    STATE_GENERATION.fetch_add(1, Ordering::Release);
    Ok(())
}

pub fn idle_stats(cpu: usize) -> Option<IdleStats> {
    CPUS.get(cpu).map(|slot| slot.0.lock().stats)
}

fn refresh_states(cpu: usize) {
    let generation = STATE_GENERATION.load(Ordering::Acquire);
    if CPUS[cpu].0.lock().generation == generation {
        return;
    }
    let mut states = [POLL; MAX_IDLE_STATES];
    states[1] = HALT;
    let mut len = 2;
    // Legacy registered callbacks remain supported, including BPF-visible IDs.
    {
        let registered = super::CSTATES.lock();
        for state in registered
            .iter()
            .filter(|s| s.id > 1)
            .take(MAX_IDLE_STATES - 2)
        {
            states[len] = IdleState {
                id: state.id,
                exit_latency_us: state.exit_latency_us,
                target_residency_us: state.target_residency_us,
                entry: IdleEntry::Callback(state.entry),
            };
            len += 1;
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        let caps = super::x86::CpuIdleCaps::probe();
        let firmware = FIRMWARE
            .lock()
            .iter()
            .find(|entry| entry.apic_id == caps.apic_id)
            .copied();
        if let Some(firmware) = firmware {
            for state in &firmware.states[..firmware.len] {
                if len == MAX_IDLE_STATES {
                    break;
                }
                if state.id == 0 || !caps.supports(state.entry) {
                    continue;
                }
                if state.id == 1 {
                    states[1] = *state;
                    continue;
                }
                if states[..len].iter().any(|s| s.id == state.id) {
                    continue;
                }
                states[len] = *state;
                len += 1;
            }
        }
    }
    states[..len].sort_unstable_by_key(|s| (s.target_residency_us, s.exit_latency_us, s.id));
    let mut current = CPUS[cpu].0.lock();
    current.states = states;
    current.len = len;
    current.generation = generation;
}

fn with_governor<R>(cpu: usize, f: impl FnOnce(Option<&dyn IdleGovernor>) -> R) -> R {
    // Refresh only after a cold policy replacement. The steady path neither
    // locks a global slot nor changes a shared Arc reference count.
    let generation = POLICY_GENERATION.load(Ordering::Acquire);
    let stale = GOVERNORS[cpu].0.lock().generation != generation;
    if stale {
        let (generation, next) = {
            let slot = super::IDLE_GOVERNOR.lock();
            (
                POLICY_GENERATION.load(Ordering::Acquire),
                slot.as_ref().map(|s| s.governor.clone()),
            )
        };
        let old = {
            let mut slot = GOVERNORS[cpu].0.lock();
            slot.generation = generation;
            core::mem::replace(&mut slot.governor, next)
        };
        drop(old);
    }
    let slot = GOVERNORS[cpu].0.lock();
    f(slot.governor.as_deref())
}

pub fn prepare_idle(hints: IdleHints) -> IdlePlan {
    if hints.cpu >= MAX_CPUS || hints.cpu != narf_lib::percpu::current_cpu() {
        return IdlePlan::default();
    }
    refresh_states(hints.cpu);
    let (states, len, history, latency, generation) = {
        let state = CPUS[hints.cpu].0.lock();
        (
            state.states,
            state.len,
            state.stats,
            state.latency_limit_us,
            state.generation,
        )
    };
    let deadline_us = hints.next_deadline_cycles.map_or(u64::MAX, |deadline| {
        narf_time::cycles_to_ns(deadline.saturating_sub(hints.now_cycles)) / 1_000
    });
    let predicted = if history.entries == 0 {
        deadline_us
    } else {
        history.predicted_idle_us.min(deadline_us)
    };
    let context = IdleContext {
        cpu: hints.cpu,
        deadline_us,
        predicted_idle_us: predicted,
        latency_limit_us: latency.min(deadline_us),
    };
    let decision = with_governor(hints.cpu, |governor| {
        governor.map_or(
            IdleDecision {
                state: CStateIdx(1),
                stop_tick: true,
            },
            |g| g.select(&context, &states[..len]),
        )
    });
    let fits = |s: &&IdleState| {
        u64::from(s.exit_latency_us) <= context.latency_limit_us
            && (s.id <= 1 || u64::from(s.target_residency_us) <= predicted)
    };
    let chosen = states[..len]
        .iter()
        .filter(fits)
        .find(|s| s.id == decision.state.0)
        // An inaccurate short-idle prediction must not trap the CPU in an
        // unbounded polling loop. C1 remains a fallback if the latency limit fits.
        .or_else(|| states[..len].iter().filter(fits).find(|s| s.id == 1))
        .copied()
        .unwrap_or(POLL);
    IdlePlan {
        state: chosen,
        stop_tick: decision.stop_tick,
        generation,
        cpu: hints.cpu,
    }
}

/// Enter a previously validated plan after the scheduler has published halted,
/// fenced, and rechecked all wake sources. No lock or policy callback spans idle.
///
/// # Safety
/// Must execute on the CPU that prepared the plan, with IRQs masked, outside
/// any task poll/RCU read section, and with a live clockevent for its deadlines.
/// Returns with IRQs masked. `true` means a hardware idle state was entered.
pub unsafe fn enter_idle(plan: IdlePlan) -> bool {
    if plan.cpu != narf_lib::percpu::current_cpu()
        || plan.generation != STATE_GENERATION.load(Ordering::Acquire)
    {
        return false;
    }
    match plan.state.entry {
        IdleEntry::Poll => {
            core::hint::spin_loop();
            false
        }
        IdleEntry::Halt => {
            // SAFETY: the caller owns the wake handshake and IRQ state.
            unsafe { narf_arch::idle_halt_then_disable() };
            true
        }
        IdleEntry::Callback(entry) => {
            entry();
            true
        }
        #[cfg(target_arch = "x86_64")]
        entry => {
            // SAFETY: refresh_states validated this CPU's driver capabilities.
            unsafe { super::x86::enter(entry) };
            true
        }
        #[cfg(not(target_arch = "x86_64"))]
        _ => {
            // SAFETY: unsupported architecture falls back to its normal idle.
            unsafe { narf_arch::idle_halt_then_disable() };
            true
        }
    }
}

/// Feed measured residency back after IRQs have been restored. History and
/// telemetry are CPU-local; no shared accounting write occurs per wake.
pub fn reflect_idle(cpu: usize, plan: IdlePlan, elapsed_cycles: u64) {
    if cpu >= MAX_CPUS || matches!(plan.state.entry, IdleEntry::Poll) {
        return;
    }
    let sample = narf_time::cycles_to_ns(elapsed_cycles) / 1_000;
    {
        let mut current = CPUS[cpu].0.lock();
        let old = current.stats.predicted_idle_us;
        current.stats.predicted_idle_us = if current.stats.entries == 0 {
            sample
        } else if sample >= old {
            old.saturating_add((sample - old) / 8)
        } else {
            old - (old - sample) / 8
        };
        current.stats.entries = current.stats.entries.saturating_add(1);
        current.stats.residency_cycles = current
            .stats
            .residency_cycles
            .saturating_add(elapsed_cycles);
        current.stats.last_state = plan.state.id;
    }
    with_governor(cpu, |governor| {
        if let Some(governor) = governor {
            governor.reflect(cpu, CStateIdx(plan.state.id), sample);
        }
    });
}

pub(super) fn reset() {
    FIRMWARE.lock().clear();
    for cpu in &CPUS {
        *cpu.0.lock() = CpuIdle::new();
    }
    STATE_GENERATION.fetch_add(1, Ordering::Release);
}

impl From<CState> for IdleState {
    fn from(state: CState) -> Self {
        Self {
            id: state.id,
            exit_latency_us: state.exit_latency_us,
            target_residency_us: state.target_residency_us,
            entry: IdleEntry::Callback(state.entry),
        }
    }
}

#[cfg(feature = "kernel-test")]
fn idle_rejects_remote_capability_discovery() -> narf_kernel_test::TestResult {
    super::init();
    let peer = (narf_lib::percpu::current_cpu() + 1) % MAX_CPUS;
    let _ = prepare_idle(IdleHints {
        cpu: peer,
        now_cycles: 0,
        next_deadline_cycles: None,
    });
    if CPUS[peer].0.lock().generation != 0 {
        return narf_kernel_test::TestResult::Fail(
            "local CPUID populated a remote CPU's state cache",
        );
    }
    narf_kernel_test::TestResult::Pass
}
#[cfg(feature = "kernel-test")]
narf_kernel_test::kernel_test_in!("power/idle", idle_rejects_remote_capability_discovery);
