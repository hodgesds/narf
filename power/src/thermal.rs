//! Thermal zones + throttling.
//!
//! Spec: `power/specification/spec.md` (Stage-4 deliverable per
//! ROADMAP). A `ThermalZone` groups a sensor + its critical
//! temperature + an optional hysteresis band, and emits
//! `ThermalEvent`s when the sensor crosses those thresholds. The
//! idle-governor / DVFS path can subscribe to events and reduce
//! clock frequency or park cores before the hardware's own
//! protection trips.
//!
//! Stage-4 scope here:
//! - Data types + registry. No real sensor plumbing — `arch/`
//!   exposes per-platform thermal MSRs / `tz` DT nodes in later
//!   work.
//! - Synchronous `read_temp(zone)` / `record_temp(zone, milli_c)`
//!   surface so drivers can poke sensed temperatures in.
//! - Event subscribers are a fixed-size array; each installs an
//!   `on_event` callback. `u32` id is monotonic.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};

use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant, NoopOp};
use narf_lib::sync::IrqSafeSpinLock;

/// Cap-type marker for the thermal control surface.
/// `Cap<Thermal, Grant>` authorises zone registration + subscriber
/// install; revocation stops further mutations without tearing down
/// the registry.
#[derive(Copy, Clone, Debug)]
pub struct Thermal;

impl CapType for Thermal {
    const KIND: CapKind = CapKind::Governor;  // Re-use until a dedicated CapKind lands.
}

/// Thermal threshold crossing event.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ThermalEvent {
    /// Zone crossed into the warning band.
    Warm       { zone: u32, milli_c: i32 },
    /// Zone crossed into the critical band — callers should throttle
    /// or park the affected device.
    Critical   { zone: u32, milli_c: i32 },
    /// Zone returned under the warning band.
    Normal     { zone: u32, milli_c: i32 },
}

/// One registered thermal zone. Temperatures are in millidegrees C.
#[derive(Debug)]
pub struct ThermalZone {
    pub id:          u32,
    pub name:        String,
    pub warn_milli:  i32,
    pub crit_milli:  i32,
    temp_milli:      AtomicI32,
}

impl ThermalZone {
    #[inline]
    pub fn temp(&self) -> i32 { self.temp_milli.load(Ordering::Relaxed) }

    /// Classify the current temperature against `warn_milli` and
    /// `crit_milli`. `Normal` is below `warn_milli`.
    #[inline]
    pub fn state(&self) -> ThermalState {
        let t = self.temp();
        if t >= self.crit_milli { ThermalState::Critical }
        else if t >= self.warn_milli { ThermalState::Warm }
        else { ThermalState::Normal }
    }
}

/// Hysteresis band classifier.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ThermalState { Normal, Warm, Critical }

type Subscriber = Box<dyn Fn(&ThermalEvent) + Send + Sync + 'static>;

struct Registry {
    zones:       Vec<ThermalZone>,
    subscribers: Vec<Subscriber>,
}

impl core::fmt::Debug for Registry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Registry")
            .field("zones",       &self.zones.len())
            .field("subscribers", &self.subscribers.len())
            .finish()
    }
}

static REG: IrqSafeSpinLock<Option<Registry>> = IrqSafeSpinLock::new(None);

/// Errors from the thermal surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ThermalError {
    AuthorityRevoked,
    NotInitialised,
    UnknownZone,
}

impl From<CapError> for ThermalError {
    fn from(_: CapError) -> Self { ThermalError::AuthorityRevoked }
}

/// Initialise the thermal registry. Safe to call more than once —
/// re-initialisation clears the zone + subscriber tables.
pub fn init() {
    *REG.lock() = Some(Registry { zones: Vec::new(), subscribers: Vec::new() });
}

/// Register a new zone. Returns its id.
pub fn register_zone(
    cap:  &Cap<Thermal, Grant>,
    name: &str,
    warn_milli: i32,
    crit_milli: i32,
) -> Result<u32, ThermalError> {
    cap.invoke(NoopOp)?;
    let mut r = REG.lock();
    let reg = r.as_mut().ok_or(ThermalError::NotInitialised)?;
    let id = reg.zones.len() as u32;
    reg.zones.push(ThermalZone {
        id,
        name: String::from(name),
        warn_milli,
        crit_milli,
        temp_milli: AtomicI32::new(0),
    });
    Ok(id)
}

/// Install a subscriber for thermal events.
pub fn subscribe<F>(cap: &Cap<Thermal, Grant>, cb: F) -> Result<(), ThermalError>
where F: Fn(&ThermalEvent) + Send + Sync + 'static {
    cap.invoke(NoopOp)?;
    let mut r = REG.lock();
    let reg = r.as_mut().ok_or(ThermalError::NotInitialised)?;
    reg.subscribers.push(Box::new(cb));
    Ok(())
}

/// Record a temperature reading on `zone`; synchronously emit any
/// state-crossing events to subscribers. Designed to be called from
/// a driver's periodic sensor poll or an IRQ handler — cheap and
/// non-blocking when the new reading stays in the same band as the
/// previous one.
pub fn record_temp(zone: u32, milli_c: i32) -> Result<ThermalState, ThermalError> {
    let r = REG.lock();
    let reg = r.as_ref().ok_or(ThermalError::NotInitialised)?;
    let z = reg.zones.get(zone as usize).ok_or(ThermalError::UnknownZone)?;

    let prev_state = z.state();
    z.temp_milli.store(milli_c, Ordering::Relaxed);
    let new_state = z.state();

    if new_state != prev_state {
        let event = match new_state {
            ThermalState::Normal   => ThermalEvent::Normal   { zone, milli_c },
            ThermalState::Warm     => ThermalEvent::Warm     { zone, milli_c },
            ThermalState::Critical => ThermalEvent::Critical { zone, milli_c },
        };
        for cb in &reg.subscribers {
            cb(&event);
        }
    }

    Ok(new_state)
}

/// Read a zone's current temperature.
pub fn read_temp(zone: u32) -> Result<i32, ThermalError> {
    let r = REG.lock();
    let reg = r.as_ref().ok_or(ThermalError::NotInitialised)?;
    let z = reg.zones.get(zone as usize).ok_or(ThermalError::UnknownZone)?;
    Ok(z.temp())
}

/// Count of registered zones.
pub fn zone_count() -> usize {
    REG.lock().as_ref().map(|r| r.zones.len()).unwrap_or(0)
}

/// Test helper: reset registry to empty.
#[doc(hidden)]
pub fn __test_reset() { *REG.lock() = None; }
