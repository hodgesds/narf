//! narf-power — CPU idle states + DVFS governors + per-driver runtime PM.
//!
//! Spec: `power/specification/spec.md`. Stage 2 lands C-state registration
//! and a simple deepest-fits idle governor. Stage 3 (this crate's first
//! real shape) adds the DVFS governor framework, three built-in
//! governors, and the per-driver runtime-PM trait + registry.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod suspend;
pub mod thermal;

#[cfg(target_arch = "x86_64")]
pub mod idle;
#[cfg(target_arch = "x86_64")]
pub mod pstate;
#[cfg(target_arch = "x86_64")]
pub mod rapl;

mod tests;

pub use suspend::{SuspendError, SuspendPhase};
pub use thermal::{Thermal, ThermalError, ThermalEvent, ThermalState, ThermalZone};

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant};
use narf_lib::sync::IrqSafeSpinLock;

// ── PowerError ──────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PowerError {
    AuthorityRevoked,
    DuplicateCState,
    NoMatchingState,
    GovernorMissing,
}

impl From<CapError> for PowerError {
    fn from(_: CapError) -> Self {
        PowerError::AuthorityRevoked
    }
}

// ── Cap marker types ────────────────────────────────────────────────

#[derive(Copy, Clone, Debug)]
pub struct Power;
impl CapType for Power {
    const KIND: CapKind = CapKind::Power;
}

#[derive(Copy, Clone, Debug)]
pub struct Governor;
impl CapType for Governor {
    const KIND: CapKind = CapKind::Governor;
}

#[derive(Copy, Clone, Debug)]
pub struct DevicePm;
impl CapType for DevicePm {
    const KIND: CapKind = CapKind::DevicePm;
}

// ── FreqHint ────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FreqHint(pub u32);

impl CapType for FreqHint {
    const KIND: CapKind = CapKind::FreqHint;
}

impl FreqHint {
    pub const MAX: FreqHint = FreqHint(3000);
    pub const MIN: FreqHint = FreqHint(800);
    #[inline] pub const fn mhz(self) -> u32 { self.0 }
}

// ── C-state ─────────────────────────────────────────────────────────

#[derive(Copy, Clone)]
pub struct CState {
    pub id: u8,
    pub exit_latency_us: u32,
    pub power_draw_mw: u32,
    pub entry: fn(),
}

impl core::fmt::Debug for CState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CState")
            .field("id", &self.id)
            .field("exit_latency_us", &self.exit_latency_us)
            .field("power_draw_mw", &self.power_draw_mw)
            .finish_non_exhaustive()
    }
}

static CSTATES: IrqSafeSpinLock<Vec<CState>> = IrqSafeSpinLock::new(Vec::new());

pub fn register_cstate(cap: &Cap<Power, Grant>, state: CState) -> Result<(), PowerError> {
    cap.check_live()?;
    let mut t = CSTATES.lock();
    if t.iter().any(|s| s.id == state.id) {
        return Err(PowerError::DuplicateCState);
    }
    t.push(state);
    t.sort_by_key(|s| s.id);
    Ok(())
}

pub fn cstate_count() -> usize { CSTATES.lock().len() }
pub fn cstates() -> Vec<CState> { CSTATES.lock().clone() }

pub fn select_idle_state() -> Result<CState, PowerError> {
    let t = CSTATES.lock();
    let mut best: Option<CState> = None;
    for s in t.iter() {
        if s.exit_latency_us <= 1000 {
            best = Some(*s);
        }
    }
    best.ok_or(PowerError::NoMatchingState)
}

pub fn idle_loop() {
    if let Ok(state) = select_idle_state() {
        (state.entry)();
    } else {
        narf_arch::halt_until_irq();
    }
}

// ── Power Source ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerSourceType {
    Battery,
    AcAdaptor,
}

pub trait PowerSource: Send + Sync {
    fn source_type(&self) -> PowerSourceType;
    fn capacity_percent(&self) -> u8;
    fn is_charging(&self) -> bool;
    fn name(&self) -> &'static str;
}

static SOURCES: IrqSafeSpinLock<Vec<Arc<dyn PowerSource>>> = IrqSafeSpinLock::new(Vec::new());

pub fn register_source(source: Arc<dyn PowerSource>) {
    SOURCES.lock().push(source);
}

pub fn list_sources() -> Vec<Arc<dyn PowerSource>> {
    SOURCES.lock().clone()
}

// ── Governor framework ──────────────────────────────────────────────

pub trait GovernorPolicy: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn select_freq(&self, load_permille: u16) -> FreqHint;
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Performance;
impl GovernorPolicy for Performance {
    fn name(&self) -> &'static str { "performance" }
    fn select_freq(&self, _load_permille: u16) -> FreqHint { FreqHint::MAX }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Powersave;
impl GovernorPolicy for Powersave {
    fn name(&self) -> &'static str { "powersave" }
    fn select_freq(&self, _load_permille: u16) -> FreqHint { FreqHint::MIN }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct OnDemand;
impl GovernorPolicy for OnDemand {
    fn name(&self) -> &'static str { "ondemand" }
    fn select_freq(&self, load_permille: u16) -> FreqHint {
        if load_permille > 500 { FreqHint::MAX } else { FreqHint::MIN }
    }
}
