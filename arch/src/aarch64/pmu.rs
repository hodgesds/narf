//! Arm PMUv3 cycle-counter backend.
//!
//! The architectural cycle counter is CPU-private and represented by bit 31
//! in PMCNTEN*, PMINTEN*, and PMOVS*. This first backend intentionally admits
//! only cycles; programmable event mappings land separately.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use super::sysreg;

const MAX_CPUS: usize = narf_lib::percpu::MAX_CPUS;
const CYCLE_BIT: u64 = 1 << 31;
const MIN_SAMPLE_PERIOD: u64 = 10_000;
static ALLOCATED: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];
static PROGRAMMABLE_ALLOCATED: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];
static PROGRAMMABLE_PERIOD: [[AtomicU64; 31]; MAX_CPUS] =
    [const { [const { AtomicU64::new(0) }; 31] }; MAX_CPUS];
static PERIOD: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
static LAST_OVERFLOW_PERIOD: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CycleCounter {
    pub cpu: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgrammableCounter {
    pub cpu: u16,
    pub idx: u8,
    pub event: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PmuError {
    NoPmu,
    NoFreeCounter,
    WrongCpu,
    InvalidPeriod,
    UnsupportedEvent,
}

pub fn available() -> bool {
    // ID_AA64DFR0_EL1.PMUVer values 0 and 0xf mean absent/unimplemented.
    // SAFETY: ID_AA64DFR0_EL1 is an EL1 feature-identification register.
    let version = ((unsafe { sysreg::read_id_aa64dfr0_el1() } >> 8) & 0xf) as u8;
    version != 0 && version != 0xf
}

pub const fn minimum_sample_period() -> u64 {
    MIN_SAMPLE_PERIOD
}

/// Number of architectural programmable event counters implemented.
pub fn programmable_counter_count() -> u8 {
    if !available() {
        return 0;
    }
    // SAFETY: availability above proves an implemented EL1 PMUv3 interface.
    (((unsafe { sysreg::read_pmcr_el0() } >> 11) & 0x1f) as u8).min(31)
}

pub fn event_supported(event: u16) -> bool {
    match event {
        // SAFETY: PMCEID registers are read-only PMUv3 discovery registers.
        0..=31 => (unsafe { sysreg::read_pmceid0_el0() } & (1u64 << event)) != 0,
        // SAFETY: PMCEID registers are read-only PMUv3 discovery registers.
        32..=63 => (unsafe { sysreg::read_pmceid1_el0() } & (1u64 << (event - 32))) != 0,
        _ => false,
    }
}

/// Allocate and type one current-CPU programmable event counter.
///
/// # Safety
/// EL1, pinned to the current CPU until release.
pub unsafe fn alloc_programmable(event: u16) -> Result<ProgrammableCounter, PmuError> {
    if !event_supported(event) {
        return Err(PmuError::UnsupportedEvent);
    }
    let count = programmable_counter_count();
    if count == 0 {
        return Err(PmuError::NoPmu);
    }
    let cpu = narf_lib::percpu::current_cpu();
    if cpu >= MAX_CPUS {
        return Err(PmuError::WrongCpu);
    }
    let slots = &PROGRAMMABLE_ALLOCATED[cpu];
    let mut old = slots.load(Ordering::Acquire);
    let idx = loop {
        let free = (!old) & ((1u32 << count) - 1);
        if free == 0 {
            return Err(PmuError::NoFreeCounter);
        }
        let idx = free.trailing_zeros() as u8;
        match slots.compare_exchange_weak(
            old,
            old | (1u32 << idx),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => break idx,
            Err(now) => old = now,
        }
    };
    // SAFETY: the allocation bit grants exclusive access to this current-CPU
    // selector and PMUv3 defines the low 16 PMXEVTYPER bits as the event code.
    unsafe {
        let mut pmcr = sysreg::read_pmcr_el0();
        pmcr |= 1;
        sysreg::write_pmcr_el0(pmcr);
        select_programmable(idx);
        sysreg::write_pmcntenclr_el0(1u64 << idx);
        sysreg::write_pmintenclr_el1(1u64 << idx);
        sysreg::write_pmovsclr_el0(1u64 << idx);
        sysreg::write_pmxevtyper_el0(event as u64);
        sysreg::write_pmxevcntr_el0(0);
    }
    Ok(ProgrammableCounter {
        cpu: cpu as u16,
        idx,
        event,
    })
}

/// Read a live 32-bit architectural programmable counter.
///
/// # Safety
/// `counter` is live and owned by the current CPU.
pub unsafe fn read_programmable(counter: &ProgrammableCounter) -> Result<u64, PmuError> {
    check_programmable(counter)?;
    // SAFETY: validated current-CPU ownership; PMSELR is synchronized by the
    // typed write wrapper before PMXEVCNTR is read.
    unsafe { select_programmable(counter.idx) };
    // SAFETY: the selected programmable counter is live and current-CPU-owned.
    Ok(unsafe { sysreg::read_pmxevcntr_el0() } & u32::MAX as u64)
}

/// Enable counting without overflow interrupts.
///
/// # Safety
/// `counter` is live and owned by the current CPU.
pub unsafe fn start_programmable(counter: &ProgrammableCounter) -> Result<(), PmuError> {
    check_programmable(counter)?;
    // SAFETY: validation above proves exclusive current-CPU counter ownership.
    unsafe { sysreg::write_pmcntenset_el0(1u64 << counter.idx) };
    Ok(())
}

/// Stop a programmable counter while retaining ownership.
///
/// # Safety
/// `counter` is live and owned by the current CPU.
pub unsafe fn pause_programmable(counter: &ProgrammableCounter) -> Result<(), PmuError> {
    check_programmable(counter)?;
    let bit = 1u64 << counter.idx;
    // SAFETY: validation above proves exclusive current-CPU counter ownership.
    unsafe {
        sysreg::write_pmcntenclr_el0(bit);
        sysreg::write_pmintenclr_el1(bit);
        sysreg::write_pmovsclr_el0(bit);
    }
    Ok(())
}

/// Preload and arm interrupt-on-overflow sampling on a 32-bit event counter.
///
/// # Safety
/// `counter` is live and owned by the current CPU; its firmware PPI is routed.
pub unsafe fn arm_programmable(counter: &ProgrammableCounter, period: u64) -> Result<(), PmuError> {
    check_programmable(counter)?;
    if !(MIN_SAMPLE_PERIOD..=u32::MAX as u64).contains(&period) {
        return Err(PmuError::InvalidPeriod);
    }
    let bit = 1u64 << counter.idx;
    // SAFETY: validation and the caller contract establish current-CPU
    // ownership and a routed PMU interrupt.
    unsafe {
        sysreg::write_pmcntenclr_el0(bit);
        sysreg::write_pmintenclr_el1(bit);
        sysreg::write_pmovsclr_el0(bit);
        select_programmable(counter.idx);
        sysreg::write_pmxevcntr_el0((0u32.wrapping_sub(period as u32)) as u64);
        sysreg::write_pmintenset_el1(bit);
        sysreg::write_pmcntenset_el0(bit);
    }
    PROGRAMMABLE_PERIOD[counter.cpu as usize][counter.idx as usize]
        .store(period, Ordering::Release);
    Ok(())
}

/// Acknowledge and synchronously re-arm all owned programmable overflows.
///
/// Returns a physical-counter bitmap (bit N corresponds to PMEVCNTRN).
///
/// # Safety
/// Called from the firmware-routed PMU PPI on the current CPU.
pub unsafe fn handle_programmable_overflows() -> u32 {
    let cpu = narf_lib::percpu::current_cpu();
    if cpu >= MAX_CPUS {
        return 0;
    }
    let allocated = PROGRAMMABLE_ALLOCATED[cpu].load(Ordering::Acquire);
    if allocated == 0 {
        return 0;
    }
    let implemented = programmable_counter_count();
    let implemented_mask = if implemented == 0 {
        0
    } else {
        (1u32 << implemented) - 1
    };
    // SAFETY: the caller is the current CPU's routed PMU interrupt handler.
    let pending = (unsafe { sysreg::read_pmovsclr_el0() } as u32) & implemented_mask & allocated;
    for idx in 0..implemented {
        let bit = 1u32 << idx;
        if pending & bit == 0 {
            continue;
        }
        let period = PROGRAMMABLE_PERIOD[cpu][idx as usize].load(Ordering::Acquire);
        // SAFETY: `pending` is restricted to counters allocated on this CPU.
        unsafe {
            sysreg::write_pmcntenclr_el0(bit as u64);
            sysreg::write_pmovsclr_el0(bit as u64);
            if period != 0 {
                select_programmable(idx);
                sysreg::write_pmxevcntr_el0((0u32.wrapping_sub(period as u32)) as u64);
                sysreg::write_pmcntenset_el0(bit as u64);
            }
        }
    }
    pending
}

/// Release a current-CPU programmable counter.
///
/// # Safety
/// `counter` is live and owned by the current CPU.
pub unsafe fn release_programmable(counter: ProgrammableCounter) -> Result<(), PmuError> {
    check_programmable(&counter)?;
    // SAFETY: validation above proves the counter is live and current-CPU-owned.
    unsafe { pause_programmable(&counter)? };
    PROGRAMMABLE_ALLOCATED[counter.cpu as usize]
        .fetch_and(!(1u32 << counter.idx), Ordering::Release);
    PROGRAMMABLE_PERIOD[counter.cpu as usize][counter.idx as usize].store(0, Ordering::Release);
    Ok(())
}

/// Allocate this CPU's architectural cycle counter.
///
/// # Safety
/// EL1, pinned to the current CPU until release.
pub unsafe fn alloc_cycle_counter() -> Result<CycleCounter, PmuError> {
    if !available() {
        return Err(PmuError::NoPmu);
    }
    let cpu = narf_lib::percpu::current_cpu();
    if cpu >= MAX_CPUS
        || ALLOCATED[cpu]
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
    {
        return Err(PmuError::NoFreeCounter);
    }
    // SAFETY: current-CPU PMUv3 ownership established above.
    unsafe {
        let mut pmcr = sysreg::read_pmcr_el0();
        pmcr = (pmcr | (1 << 6) | 1) & !(1 << 3); // LC + E; clear /64 divider.
        sysreg::write_pmcr_el0(pmcr);
        // Count at both EL0 and EL1. Firmware is permitted to leave filter
        // exclusions behind; perf owns the counter while allocated.
        sysreg::write_pmccfiltr_el0(0);
        sysreg::write_pmcntenclr_el0(CYCLE_BIT);
        sysreg::write_pmintenclr_el1(CYCLE_BIT);
        sysreg::write_pmovsclr_el0(CYCLE_BIT);
    }
    Ok(CycleCounter { cpu: cpu as u16 })
}

/// Read a live current-CPU cycle counter.
///
/// # Safety
/// `counter` is live and owned by the current CPU.
pub unsafe fn read(counter: &CycleCounter) -> Result<u64, PmuError> {
    check_cpu(counter)?;
    // SAFETY: validated live current-CPU counter.
    Ok(unsafe { sysreg::read_pmccntr_el0() })
}

/// Enable cycle counting without overflow interrupts.
///
/// # Safety
/// `counter` is live and owned by the current CPU.
pub unsafe fn start(counter: &CycleCounter) -> Result<(), PmuError> {
    check_cpu(counter)?;
    // SAFETY: validation above proves exclusive current-CPU cycle-counter ownership.
    unsafe { sysreg::write_pmcntenset_el0(CYCLE_BIT) };
    Ok(())
}

/// Preload and arm interrupt-on-overflow sampling.
///
/// # Safety
/// `counter` is live and owned by the current CPU; its firmware PPI is routed.
pub unsafe fn arm_sampling(counter: &CycleCounter, period: u64) -> Result<(), PmuError> {
    check_cpu(counter)?;
    if period < MIN_SAMPLE_PERIOD {
        return Err(PmuError::InvalidPeriod);
    }
    let cpu = counter.cpu as usize;
    // SAFETY: validated current-CPU PMUv3 ownership.
    unsafe {
        sysreg::write_pmcntenclr_el0(CYCLE_BIT);
        sysreg::write_pmintenclr_el1(CYCLE_BIT);
        sysreg::write_pmovsclr_el0(CYCLE_BIT);
        sysreg::write_pmccntr_el0(0u64.wrapping_sub(period));
        sysreg::write_pmintenset_el1(CYCLE_BIT);
        sysreg::write_pmcntenset_el0(CYCLE_BIT);
    }
    PERIOD[cpu].store(period, Ordering::Release);
    Ok(())
}

/// Stop sampling while retaining ownership.
///
/// # Safety
/// `counter` is live and owned by the current CPU.
pub unsafe fn pause_sampling(counter: &CycleCounter) -> Result<(), PmuError> {
    check_cpu(counter)?;
    // SAFETY: validated current-CPU PMUv3 ownership.
    unsafe {
        sysreg::write_pmcntenclr_el0(CYCLE_BIT);
        sysreg::write_pmintenclr_el1(CYCLE_BIT);
        sysreg::write_pmovsclr_el0(CYCLE_BIT);
    }
    Ok(())
}

/// Acknowledge and synchronously re-arm a cycle-counter overflow.
///
/// # Safety
/// Called from the firmware-routed PMU PPI on the current CPU.
pub unsafe fn handle_sampling_overflow() -> bool {
    let cpu = narf_lib::percpu::current_cpu();
    if cpu >= MAX_CPUS {
        return false;
    }
    // SAFETY: the caller is the current CPU's routed PMU interrupt handler.
    if unsafe { sysreg::read_pmovsclr_el0() } & CYCLE_BIT == 0 {
        return false;
    }
    let period = PERIOD[cpu].load(Ordering::Acquire);
    // SAFETY: PMU PPI proves current-CPU overflow context.
    unsafe {
        sysreg::write_pmcntenclr_el0(CYCLE_BIT);
        sysreg::write_pmovsclr_el0(CYCLE_BIT);
        sysreg::write_pmccntr_el0(0u64.wrapping_sub(period));
        sysreg::write_pmcntenset_el0(CYCLE_BIT);
    }
    LAST_OVERFLOW_PERIOD[cpu].store(period, Ordering::Release);
    true
}

pub fn last_overflow_period(cpu: usize) -> u64 {
    LAST_OVERFLOW_PERIOD
        .get(cpu)
        .map_or(0, |period| period.load(Ordering::Acquire))
}

pub fn programmable_period(cpu: usize, counter: usize) -> u64 {
    PROGRAMMABLE_PERIOD
        .get(cpu)
        .and_then(|periods| periods.get(counter))
        .map_or(0, |period| period.load(Ordering::Acquire))
}

pub fn update_sampling_period(counter: &CycleCounter, period: u64) {
    if period != 0 {
        PERIOD[counter.cpu as usize].store(period, Ordering::Release);
    }
}

pub fn update_programmable_period(counter: &ProgrammableCounter, period: u64) {
    if period != 0 && period <= u32::MAX as u64 {
        PROGRAMMABLE_PERIOD[counter.cpu as usize][counter.idx as usize]
            .store(period, Ordering::Release);
    }
}

/// Release a current-CPU counter.
///
/// # Safety
/// `counter` is live and owned by the current CPU.
pub unsafe fn release(counter: CycleCounter) -> Result<(), PmuError> {
    check_cpu(&counter)?;
    // SAFETY: validated current-CPU PMUv3 ownership.
    unsafe { pause_sampling(&counter)? };
    PERIOD[counter.cpu as usize].store(0, Ordering::Release);
    ALLOCATED[counter.cpu as usize].store(false, Ordering::Release);
    Ok(())
}

fn check_cpu(counter: &CycleCounter) -> Result<(), PmuError> {
    let cpu = narf_lib::percpu::current_cpu();
    if counter.cpu as usize != cpu || cpu >= MAX_CPUS || !ALLOCATED[cpu].load(Ordering::Acquire) {
        Err(PmuError::WrongCpu)
    } else {
        Ok(())
    }
}

unsafe fn select_programmable(idx: u8) {
    // SAFETY: caller guarantees `idx` names an implemented current-CPU counter.
    unsafe { sysreg::write_pmselr_el0(idx as u64) };
}

fn check_programmable(counter: &ProgrammableCounter) -> Result<(), PmuError> {
    let cpu = narf_lib::percpu::current_cpu();
    let bit = 1u32 << counter.idx;
    if counter.cpu as usize != cpu
        || cpu >= MAX_CPUS
        || counter.idx >= programmable_counter_count()
        || PROGRAMMABLE_ALLOCATED[cpu].load(Ordering::Acquire) & bit == 0
    {
        Err(PmuError::WrongCpu)
    } else {
        Ok(())
    }
}
