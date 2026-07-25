//! Arm PMUv3 cycle-counter backend.
//!
//! The architectural cycle counter is CPU-private and represented by bit 31
//! in PMCNTEN*, PMINTEN*, and PMOVS*. This first backend intentionally admits
//! only cycles; programmable event mappings land separately.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::sysreg;

const MAX_CPUS: usize = narf_lib::percpu::MAX_CPUS;
const CYCLE_BIT: u64 = 1 << 31;
static ALLOCATED: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];
static PERIOD: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
static LAST_OVERFLOW_PERIOD: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CycleCounter {
    pub cpu: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PmuError {
    NoPmu,
    NoFreeCounter,
    WrongCpu,
    InvalidPeriod,
}

pub fn available() -> bool {
    // ID_AA64DFR0_EL1.PMUVer values 0 and 0xf mean absent/unimplemented.
    let version = ((unsafe { sysreg::read_id_aa64dfr0_el1() } >> 8) & 0xf) as u8;
    version != 0 && version != 0xf
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

/// Preload and arm interrupt-on-overflow sampling.
///
/// # Safety
/// `counter` is live and owned by the current CPU; its firmware PPI is routed.
pub unsafe fn arm_sampling(counter: &CycleCounter, period: u64) -> Result<(), PmuError> {
    check_cpu(counter)?;
    if period == 0 {
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
    if cpu >= MAX_CPUS || unsafe { sysreg::read_pmovsclr_el0() } & CYCLE_BIT == 0 {
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
