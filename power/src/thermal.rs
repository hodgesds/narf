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

use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant, NoopOp, Read, Write};
use narf_event_bus::{
    create_topic, lookup_topic, PublishError, Publisher as BusPublisher, Subscriber as BusSubscriber,
    TopicRegistry,
};
use narf_lib::sync::IrqSafeSpinLock;

/// Cap-type marker for the thermal control surface.
/// `Cap<Thermal, Grant>` authorises zone registration + subscriber
/// install; revocation stops further mutations without tearing down
/// the registry.
#[derive(Copy, Clone, Debug)]
pub struct Thermal;

impl CapType for Thermal {
    const KIND: CapKind = CapKind::Governor; // Re-use until a dedicated CapKind lands.
}

/// Thermal threshold crossing event.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ThermalEvent {
    /// Zone crossed into the warning band.
    Warm { zone: u32, milli_c: i32 },
    /// Zone crossed into the critical band — callers should throttle
    /// or park the affected device.
    Critical { zone: u32, milli_c: i32 },
    /// Zone returned under the warning band.
    Normal { zone: u32, milli_c: i32 },
}

/// One registered thermal zone. Temperatures are in millidegrees C.
#[derive(Debug)]
pub struct ThermalZone {
    pub id: u32,
    pub name: String,
    pub warn_milli: i32,
    pub crit_milli: i32,
    temp_milli: AtomicI32,
}

impl ThermalZone {
    #[inline]
    pub fn temp(&self) -> i32 {
        self.temp_milli.load(Ordering::Relaxed)
    }

    /// Classify the current temperature against `warn_milli` and
    /// `crit_milli`. `Normal` is below `warn_milli`.
    #[inline]
    pub fn state(&self) -> ThermalState {
        let t = self.temp();
        if t >= self.crit_milli {
            ThermalState::Critical
        } else if t >= self.warn_milli {
            ThermalState::Warm
        } else {
            ThermalState::Normal
        }
    }
}

/// Hysteresis band classifier.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ThermalState {
    Normal,
    Warm,
    Critical,
}

/// A device that can reduce system temperature (Fan, Throttle, etc.).
pub trait CoolingDevice: Send + Sync + core::fmt::Debug {
    fn name(&self) -> &'static str;
    /// Set the cooling level (0 = off, 255 = max).
    fn set_level(&self, level: u8);
}

/// Topic name for thermal events. Reserved-root `power.` namespace
/// — only kernel can mint. Phase 1 ships a single per-system topic;
/// per-zone topics (`power.thermal.<zone>`) land when wildcards
/// arrive in Phase 2.
pub const TOPIC: &str = "power.thermal";

/// Ring capacity. Thermal crossings are rare (human-perceptible
/// scale); 64 slots covers any reasonable burst at boot.
pub const CAPACITY: usize = 64;

struct Registry {
    zones: Vec<ThermalZone>,
    /// Bus publisher; minted at `init()` time. Replaces the old
    /// `subscribers: Vec<Box<dyn Fn(&ThermalEvent)>>` callback list.
    publisher: Option<BusPublisher<ThermalEvent>>,
    cooling_devices: Vec<alloc::sync::Arc<dyn CoolingDevice>>,
    /// Active-cooling governor. When set, each thermal-event dispatch
    /// computes a level via the policy and drives every cooling
    /// device under the same lock that fired the event — no lock
    /// reentry from a subscriber callback is required.
    policy: Option<Box<dyn CoolingPolicy>>,
}

impl core::fmt::Debug for Registry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Registry")
            .field("zones", &self.zones.len())
            .field("publisher", &self.publisher.is_some())
            .field("cooling_devices", &self.cooling_devices.len())
            .field("policy", &self.policy.is_some())
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
    fn from(_: CapError) -> Self {
        ThermalError::AuthorityRevoked
    }
}

/// Initialise the thermal registry. Safe to call more than once —
/// re-initialisation clears the zone tables, mints a fresh bus
/// publisher for `power.thermal`, and installs the default
/// `StepPolicy` active-cooling governor.
pub fn init() {
    narf_event_bus::init();
    let reg_cap: Cap<TopicRegistry, Write> = Cap::bootstrap();
    let publisher = match create_topic::<ThermalEvent>(&reg_cap, TOPIC, CAPACITY) {
        Ok((_id, p)) => Some(p),
        // NameTaken happens on `init()` re-entry (the bus topic
        // remains live across resets); not a fatal failure.
        Err(_) => None,
    };
    *REG.lock() = Some(Registry {
        zones: Vec::new(),
        publisher,
        cooling_devices: Vec::new(),
        policy: Some(Box::new(StepPolicy)),
    });
}

/// Register a new cooling device.
pub fn register_cooling_device(
    cap: &Cap<Thermal, Grant>,
    dev: alloc::sync::Arc<dyn CoolingDevice>,
) -> Result<(), ThermalError> {
    cap.invoke(NoopOp)?;
    let mut r = REG.lock();
    let reg = r.as_mut().ok_or(ThermalError::NotInitialised)?;
    reg.cooling_devices.push(dev);
    Ok(())
}

/// Set cooling level for all registered devices.
pub fn set_cooling_level(level: u8) -> Result<(), ThermalError> {
    let r = REG.lock();
    let reg = r.as_ref().ok_or(ThermalError::NotInitialised)?;
    for dev in &reg.cooling_devices {
        dev.set_level(level);
    }
    Ok(())
}

/// Register a new zone. Returns its id.
pub fn register_zone(
    cap: &Cap<Thermal, Grant>,
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

/// Mint a fresh `Subscriber<ThermalEvent>` for the `power.thermal`
/// topic. Replaces the old callback-list `subscribe(cap, cb)`. The
/// caller drains in its own async task via
/// `Subscriber::next().await`.
pub fn subscribe(reg: &Cap<TopicRegistry, Read>) -> Result<BusSubscriber<ThermalEvent>, ThermalError> {
    lookup_topic::<ThermalEvent>(reg, TOPIC).map_err(|_| ThermalError::NotInitialised)
}

/// Record a temperature reading on `zone`; synchronously emit any
/// state-crossing events to subscribers. Designed to be called from
/// a driver's periodic sensor poll or an IRQ handler — cheap and
/// non-blocking when the new reading stays in the same band as the
/// previous one.
pub fn record_temp(zone: u32, milli_c: i32) -> Result<ThermalState, ThermalError> {
    let r = REG.lock();
    let reg = r.as_ref().ok_or(ThermalError::NotInitialised)?;
    let z = reg
        .zones
        .get(zone as usize)
        .ok_or(ThermalError::UnknownZone)?;

    let prev_state = z.state();
    z.temp_milli.store(milli_c, Ordering::Relaxed);
    let new_state = z.state();

    if new_state != prev_state {
        let event = match new_state {
            ThermalState::Normal => ThermalEvent::Normal { zone, milli_c },
            ThermalState::Warm => ThermalEvent::Warm { zone, milli_c },
            ThermalState::Critical => ThermalEvent::Critical { zone, milli_c },
        };
        // Publish onto the bus topic. Wait-free; never blocks; a
        // slow subscriber sees a `Gapped` signal on its next
        // `recv()` rather than slowing the producer.
        if let Some(p) = reg.publisher.as_ref() {
            match p.publish(event) {
                Ok(_) | Err(PublishError::CapRevoked) | Err(PublishError::NoArena) => {}
            }
        }
        // Drive the active-cooling governor inline. Walking
        // `cooling_devices` under the lock we already hold avoids any
        // reentrant-lock hazard a subscriber-based hook would create.
        if let Some(policy) = reg.policy.as_ref() {
            let level = policy.level_for(&event);
            for dev in &reg.cooling_devices {
                dev.set_level(level);
            }
        }
    }

    Ok(new_state)
}

/// Read a zone's current temperature.
pub fn read_temp(zone: u32) -> Result<i32, ThermalError> {
    let r = REG.lock();
    let reg = r.as_ref().ok_or(ThermalError::NotInitialised)?;
    let z = reg
        .zones
        .get(zone as usize)
        .ok_or(ThermalError::UnknownZone)?;
    Ok(z.temp())
}

/// Count of registered zones.
pub fn zone_count() -> usize {
    REG.lock().as_ref().map(|r| r.zones.len()).unwrap_or(0)
}

/// Snapshot every registered zone for diagnostic display. Returns
/// `(name, milli_c, state)` per zone — owned strings so the
/// caller doesn't have to hold the registry lock across rendering.
pub fn zones_snapshot() -> Vec<(String, i32, ThermalState)> {
    let r = REG.lock();
    match r.as_ref() {
        Some(reg) => reg
            .zones
            .iter()
            .map(|z| (z.name.clone(), z.temp(), z.state()))
            .collect(),
        None => Vec::new(),
    }
}

/// Test helper: reset registry to empty.
#[doc(hidden)]
pub fn __test_reset() {
    *REG.lock() = None;
    narf_event_bus::__registry_reset_for_test();
}

// ── Active-cooling governor ─────────────────────────────────────────
//
// A thermal-event subscriber that drives `set_cooling_level` based on
// the zone's hysteresis band. Spec §11.3 (passive cooling) leaves the
// mapping policy-defined; this is the conservative default we want for
// laptop bringup:
//
//   Normal   → 0   (fans off, save battery + audible noise)
//   Warm     → 128 (~50% — quiet but moving air)
//   Critical → 255 (max — preserve hardware)
//
// Drop-in replacements live behind `install_active_cooling`; once a
// per-zone or per-device policy lands the default is one variant of
// `CoolingPolicy`.

/// Cooling policy: maps a `ThermalEvent` to a 0..=255 cooling level.
pub trait CoolingPolicy: Send + Sync + 'static {
    fn level_for(&self, event: &ThermalEvent) -> u8;
}

/// Three-step policy used as the boot default.
#[derive(Copy, Clone, Debug, Default)]
pub struct StepPolicy;

impl CoolingPolicy for StepPolicy {
    fn level_for(&self, event: &ThermalEvent) -> u8 {
        match event {
            ThermalEvent::Normal { .. } => 0,
            ThermalEvent::Warm { .. } => 128,
            ThermalEvent::Critical { .. } => 255,
        }
    }
}

/// Install `policy` as the active-cooling governor. Every thermal
/// state-crossing event runs the policy under the registry lock and
/// drives every registered cooling device to the resulting level.
/// Replaces any previously-installed policy.
pub fn install_active_cooling<P: CoolingPolicy>(
    cap: &Cap<Thermal, Grant>,
    policy: P,
) -> Result<(), ThermalError> {
    cap.invoke(NoopOp)?;
    let mut r = REG.lock();
    let reg = r.as_mut().ok_or(ThermalError::NotInitialised)?;
    reg.policy = Some(Box::new(policy));
    Ok(())
}

/// Whether an active-cooling policy is installed.
pub fn has_active_cooling() -> bool {
    REG.lock()
        .as_ref()
        .map(|r| r.policy.is_some())
        .unwrap_or(false)
}
