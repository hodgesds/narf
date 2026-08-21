//! Realtime bandwidth admission owned by the scheduler core.
//!
//! A policy may rank `SchedClass::Realtime`, but only this module can attach a
//! reservation to a task. Reservations are deliberately CPU-pinned: moving a
//! live RT reservation requires a future transactional migration API, rather
//! than temporarily overcommitting either run queue.

use core::sync::atomic::{AtomicU64, Ordering};

use narf_capabilities::{Cap, Spend};

use crate::affinity::CpuId;
use crate::budget::{CpuBudget, ExhaustionPolicy, ResourceBudget};

/// Leave five percent for hard IRQs and non-RT kernel progress.
pub const RT_CPU_LIMIT_PPM: u64 = 950_000;
const ADMISSION_DOMAINS: usize = 256;

static CPU_RESERVED_PPM: [AtomicU64; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; narf_lib::percpu::MAX_CPUS];
static SYSTEM_RESERVED_PPM: AtomicU64 = AtomicU64::new(0);
// Indexed by the CpuBudget capability object. A collision only rejects extra
// work; it can never admit excess bandwidth.
static DOMAIN_RESERVED_PPM: [AtomicU64; ADMISSION_DOMAINS] =
    [const { AtomicU64::new(0) }; ADMISSION_DOMAINS];

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    AuthorityRevoked,
    InvalidContract,
    CpuOffline,
    CpuBandwidthExceeded,
    SystemBandwidthExceeded,
    DomainBandwidthExceeded,
}

/// Read-only utilization snapshot for control-plane diagnostics.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RealtimeBandwidth {
    pub cpu_reserved_ppm: u64,
    pub system_reserved_ppm: u64,
    pub system_limit_ppm: u64,
}

pub fn realtime_bandwidth(cpu: CpuId) -> RealtimeBandwidth {
    let cpu_reserved_ppm = CPU_RESERVED_PPM
        .get(cpu.0 as usize)
        .map(|value| value.load(Ordering::Acquire))
        .unwrap_or(0);
    let online = narf_lib::smp::online_bitmap().count_ones().max(1) as u64;
    RealtimeBandwidth {
        cpu_reserved_ppm,
        system_reserved_ppm: SYSTEM_RESERVED_PPM.load(Ordering::Acquire),
        system_limit_ppm: RT_CPU_LIMIT_PPM.saturating_mul(online),
    }
}

fn add_bounded(cell: &AtomicU64, amount: u64, limit: u64) -> bool {
    cell.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        current.checked_add(amount).filter(|next| *next <= limit)
    })
    .is_ok()
}

fn utilization_ppm(budget: &ResourceBudget) -> Option<u64> {
    let period = budget.period?;
    if !period.is_valid()
        || period.exhaustion != ExhaustionPolicy::Strict
        || budget.deadline_cycles.is_none()
    {
        return None;
    }
    let numerator = (period.runtime_cycles as u128).saturating_mul(1_000_000);
    let denominator = period.period_cycles as u128;
    let rounded_up = numerator
        .saturating_add(denominator.saturating_sub(1))
        .checked_div(denominator)?;
    u64::try_from(rounded_up).ok().filter(|ppm| *ppm > 0)
}

/// Core-owned reservation guard stored in `TaskSlot`.
#[derive(Debug)]
pub(crate) struct RealtimeReservation {
    cpu: usize,
    domain: usize,
    ppm: u64,
}

impl RealtimeReservation {
    pub(crate) const fn cpu(&self) -> CpuId {
        CpuId(self.cpu as u32)
    }
}

impl Drop for RealtimeReservation {
    fn drop(&mut self) {
        CPU_RESERVED_PPM[self.cpu].fetch_sub(self.ppm, Ordering::AcqRel);
        SYSTEM_RESERVED_PPM.fetch_sub(self.ppm, Ordering::AcqRel);
        DOMAIN_RESERVED_PPM[self.domain].fetch_sub(self.ppm, Ordering::AcqRel);
    }
}

pub(crate) fn reserve(
    authority: &Cap<CpuBudget, Spend>,
    cpu: CpuId,
    budget: &ResourceBudget,
) -> Result<RealtimeReservation, AdmissionError> {
    authority
        .check_live()
        .map_err(|_| AdmissionError::AuthorityRevoked)?;
    let ppm = utilization_ppm(budget).ok_or(AdmissionError::InvalidContract)?;
    let cpu_index = cpu.0 as usize;
    if cpu_index >= narf_lib::percpu::MAX_CPUS || !narf_lib::smp::is_online(cpu.0) {
        return Err(AdmissionError::CpuOffline);
    }
    let domain = authority.slot().index as usize % ADMISSION_DOMAINS;
    if !add_bounded(&DOMAIN_RESERVED_PPM[domain], ppm, RT_CPU_LIMIT_PPM) {
        return Err(AdmissionError::DomainBandwidthExceeded);
    }
    let online = narf_lib::smp::online_bitmap().count_ones().max(1) as u64;
    if !add_bounded(
        &SYSTEM_RESERVED_PPM,
        ppm,
        RT_CPU_LIMIT_PPM.saturating_mul(online),
    ) {
        DOMAIN_RESERVED_PPM[domain].fetch_sub(ppm, Ordering::AcqRel);
        return Err(AdmissionError::SystemBandwidthExceeded);
    }
    if !add_bounded(&CPU_RESERVED_PPM[cpu_index], ppm, RT_CPU_LIMIT_PPM) {
        SYSTEM_RESERVED_PPM.fetch_sub(ppm, Ordering::AcqRel);
        DOMAIN_RESERVED_PPM[domain].fetch_sub(ppm, Ordering::AcqRel);
        return Err(AdmissionError::CpuBandwidthExceeded);
    }
    // Close revocation between the first check and publication. Releasing the
    // guard rolls all three counters back on failure.
    let reservation = RealtimeReservation {
        cpu: cpu_index,
        domain,
        ppm,
    };
    if authority.check_live().is_err() {
        drop(reservation);
        return Err(AdmissionError::AuthorityRevoked);
    }
    Ok(reservation)
}
