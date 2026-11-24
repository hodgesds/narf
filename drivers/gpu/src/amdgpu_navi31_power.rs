//! Navi31 runtime power state. The last telemetry sample, the board limits,
//! throttling/protection reporting and the Linux amdgpu hwmon ABI
//! (amdgpu_pm.c `hwmon_attributes`) from that sample. Fan control stays
//! automatic: smu_v13_0_0_ppt.c provides no fan-mode or PWM setters, so
//! `pwm1`/`pwm1_enable` are read-only as in Linux.
//!
//! Unlike Navi48 this module spawns no refresh monitor and owns no
//! platform singleton: live SMU telemetry waits on lane 2 (#2464) and the
//! platform run loop on lane 1 (#2459). Until they land, `seed` publishes
//! the board limits and the hwmon node, and the snapshot carries no sample;
//! `thermal_alert`/`hw_ctf_alert` are the interrupt side, confirmed against
//! the IRQ alone because no sample exists to read yet. `power1_cap` is
//! validated by [`power_cap_request`] but not writable until the platform
//! can apply it, so hwmon publishes read-only.
use crate::amdgpu_smu_navi31_telemetry::{Limits, Telemetry, CRIT_HYST_MILLI, THROTTLERS};
use alloc::{string::String, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use narf_filesystem::FsError;
use narf_lib::sync::IrqSafeSpinLock;
static GENERATION: AtomicU64 = AtomicU64::new(0);

#[path = "amdgpu_navi31_thermal.rs"]
pub mod thermal;

/// Linux's delayed SW CTF confirmation and the `ms_until_forced` of the
/// hardware-protection power-off. Power-off never runs from an IH or SMU
/// call frame.
pub const SWCTF_DELAY_MS: u64 = 50;
pub const FORCED_POWEROFF_MS: u64 = 10_000;
static HOT_NOTIFIED: AtomicBool = AtomicBool::new(false);
static HW_CTF_NOTIFIED: AtomicBool = AtomicBool::new(false);
static ALERTS: AlertSlots = AlertSlots(AtomicU64::new(0));
struct AlertSlots(AtomicU64);
struct AlertLease<'a> {
    slots: &'a AlertSlots,
    token: u64,
}
impl AlertSlots {
    fn claim(&self, generation: u64) -> Option<AlertLease<'_>> {
        let token = generation.wrapping_add(1).max(1);
        self.0
            .compare_exchange(0, token, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        Some(AlertLease { slots: self, token })
    }
    fn cancel(&self) {
        self.0.store(0, Ordering::Release);
    }
}
impl Drop for AlertLease<'_> {
    fn drop(&mut self) {
        // An old task cannot clear a newer owner's pending alert.
        let _ = self
            .slots
            .0
            .compare_exchange(self.token, 0, Ordering::AcqRel, Ordering::Acquire);
    }
}
async fn alert_delay<'a>(
    lease: AlertLease<'a>,
    delay: impl core::future::Future<Output = ()>,
) -> AlertLease<'a> {
    delay.await;
    lease
}
/// The retained thermal IRQ controller captured a high-threshold event.
/// One task per owner waits 50 ms, then orders the protection shutdown.
/// No live sample exists yet to confirm against (no platform singleton),
/// so the IRQ itself is the evidence: a known thermal-high IRQ is
/// fail-safe if its confirmation cannot read the sensor.
pub fn thermal_alert(limit: u16) {
    if limit == 0 {
        return;
    }
    let generation = GENERATION.load(Ordering::Acquire);
    let Some(lease) = ALERTS.claim(generation) else {
        return;
    };
    narf_scheduler::spawn(async move {
        let _lease = alert_delay(
            lease,
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(SWCTF_DELAY_MS).as_instant()),
        )
        .await;
        if GENERATION.load(Ordering::Acquire) != generation {
            return;
        }
        if !HOT_NOTIFIED.swap(true, Ordering::AcqRel) {
            narf_power::orderly::hw_protection_shutdown(
                "RX 7000 GPU software critical temperature",
                FORCED_POWEROFF_MS,
            );
        }
    });
}
/// The retained thermal IRQ controller captured a GPIO19 hardware CTF: the
/// fault already happened, so the shutdown is ordered at once — still off
/// the IH frame, via the executor — and only once per owner generation.
pub fn hw_ctf_alert() {
    let generation = GENERATION.load(Ordering::Acquire);
    if HW_CTF_NOTIFIED.swap(true, Ordering::AcqRel) {
        return;
    }
    narf_scheduler::spawn(async move {
        if GENERATION.load(Ordering::Acquire) != generation {
            return;
        }
        narf_power::orderly::hw_protection_shutdown(
            "RX 7000 GPU hardware critical temperature",
            FORCED_POWEROFF_MS,
        );
    });
}

/// A telemetry refresh failure, as the future SMU owner will report it.
/// The owner (lane 2, #2464) replaces this with its own error type when it
/// lands; until then refreshes only fail closed, never with a live error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshError {
    Rejected(u32),
    DeviceGone,
}

/// Last telemetry state, published to diagnostics and hwmon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// Most recent successful sample; retained across a rejected refresh.
    pub telemetry: Option<Telemetry>,
    pub limits: Option<Limits>,
    /// Every protection running after boot is still running in `telemetry`.
    pub protected: bool,
    /// Error of the latest refresh, cleared by the next success.
    pub error: Option<RefreshError>,
    pub samples: u64,
}

/// One owner-serialized refresh, as returned by the platform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    pub telemetry: Result<Telemetry, RefreshError>,
    pub limits: Option<Limits>,
    pub protected: bool,
}

static SNAPSHOT: IrqSafeSpinLock<Option<Snapshot>> = IrqSafeSpinLock::new(None);

pub fn snapshot() -> Option<Snapshot> {
    *SNAPSHOT.lock()
}

/// Notable transitions between two snapshots, for the console.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Events {
    /// Throttlers that started limiting since the previous sample.
    pub started: u32,
    /// Throttlers that stopped limiting.
    pub stopped: u32,
    pub protection_lost: bool,
    /// Hotspot reached `software_shutdown_temp` (Linux would power off).
    pub software_shutdown: bool,
    /// The first failed refresh after a success (or at start).
    pub failed: Option<RefreshError>,
}

/// Fold one refresh into the published state.
pub fn update(previous: Option<Snapshot>, sample: Sample) -> (Snapshot, Events) {
    let mut events = Events::default();
    let old = previous.and_then(|p| p.telemetry);
    let telemetry = sample.telemetry.ok().or(old);
    let error = sample.telemetry.err();
    // A failed refresh proves nothing new about protection; keep the last.
    let protected = match sample.telemetry {
        Ok(_) => sample.protected,
        Err(_) => previous.is_some_and(|p| p.protected),
    };
    if let (Ok(new), Some(limits)) = (sample.telemetry, sample.limits) {
        let was = old.is_some_and(|t| limits.software_shutdown(&t.metrics));
        events.software_shutdown = limits.software_shutdown(&new.metrics) && !was;
    }
    if let Ok(new) = sample.telemetry {
        let before = old.map_or(0, |t| t.metrics.throttlers);
        events.started = new.metrics.throttlers & !before;
        events.stopped = before & !new.metrics.throttlers;
        events.protection_lost =
            !sample.protected && previous.is_none_or(|p| p.protected || p.telemetry.is_none());
    }
    if error.is_some() && previous.is_none_or(|p| p.error.is_none()) {
        events.failed = error;
    }
    let snapshot = Snapshot {
        telemetry,
        limits: sample.limits,
        protected,
        error,
        samples: previous.map_or(0, |p| p.samples) + u64::from(error.is_none()),
    };
    (snapshot, events)
}

// TODO(narf): unused until the platform run loop lands (#2459) — it calls
// `report` after each `update`, as Navi48's monitor does.
#[allow(dead_code)]
fn throttler_names(mask: u32) -> String {
    let names: Vec<&str> = THROTTLERS
        .iter()
        .enumerate()
        .filter(|(i, _)| mask & (1 << i) != 0)
        .map(|(_, n)| *n)
        .collect();
    names.join(",")
}

// TODO(narf): unused until the platform run loop lands (#2459) — it calls
// `report` after each `update`, as Navi48's monitor does.
#[allow(dead_code)]
fn report(snapshot: &Snapshot, events: Events) {
    use core::fmt::Write;
    let mut w = narf_console::Writer;
    if events.started != 0 {
        let _ = writeln!(
            w,
            "amdgpu: navi31 PMFW throttling: {}",
            throttler_names(events.started)
        );
    }
    if events.stopped != 0 {
        let _ = writeln!(
            w,
            "amdgpu: navi31 PMFW throttling ended: {}",
            throttler_names(events.stopped)
        );
    }
    if events.protection_lost {
        let enabled = snapshot.telemetry.map_or(0, |t| t.enabled);
        let _ = writeln!(
            w,
            "amdgpu: navi31 PMFW protection feature stopped (running {enabled:#x})"
        );
    }
    if events.software_shutdown {
        let hotspot = snapshot.telemetry.map_or(0, |t| t.metrics.hotspot_milli);
        let _ = writeln!(
            w,
            "amdgpu: navi31 EMERGENCY: hotspot {} mC at software shutdown temperature",
            hotspot
        );
    }
    if let Some(error) = events.failed {
        let _ = writeln!(w, "amdgpu: navi31 PMFW telemetry failed: {error:?}");
    }
}

/// Linux amdgpu hwmon attribute names, filtered as `hwmon_attributes_visible`
/// does for a fan-equipped (or fanless) SMU 13.0.0 dGPU (no RPM setters).
pub fn attributes(fan: bool) -> Vec<&'static str> {
    let mut names = crate::amdgpu_hwmon::attributes(fan, false);
    names.extend_from_slice(&["power1_cap_min", "power1_cap_max"]);
    names
}

/// A `power1_cap` write in microwatts, as amdgpu_hwmon_set_power_cap: the
/// watt value must lie in the board's non-overdrive range (smu_set_ppt_limit
/// -EINVAL otherwise; 0 there means the default only for the default limit
/// type, which hwmon does not use). Pure validation: the platform that
/// applies it does not exist yet, so no store is registered for it.
pub fn power_cap_request(limits: Option<Limits>, bytes: &[u8]) -> Result<u32, FsError> {
    let microwatts = crate::amdgpu_hwmon::parse_u32(bytes).ok_or(FsError::InvalidData)?;
    let watts = microwatts / 1_000_000;
    let limits = limits.ok_or(FsError::NoDevice)?;
    if watts < limits.ppt_min_w || watts > limits.ppt_max_w || watts == 0 {
        return Err(FsError::InvalidData);
    }
    Ok(watts)
}

fn reading(snapshot: Option<&Snapshot>) -> crate::amdgpu_hwmon::Reading {
    let t = snapshot.and_then(|s| s.telemetry);
    let l = snapshot.and_then(|s| s.limits);
    let m = t.map(|t| t.metrics);
    crate::amdgpu_hwmon::Reading {
        temp: [
            m.map(|m| m.edge_milli),
            m.map(|m| m.hotspot_milli),
            m.map(|m| m.mem_milli),
        ],
        crit: [
            l.map(|l| l.edge_crit_milli),
            l.map(|l| l.hotspot_crit_milli),
            l.map(|l| l.mem_crit_milli),
        ],
        crit_hyst: [l.map(|_| CRIT_HYST_MILLI); 3],
        emergency: [
            l.map(|l| l.edge_emergency_milli),
            l.map(|l| l.hotspot_emergency_milli),
            l.map(|l| l.mem_emergency_milli),
        ],
        pwm: m.map(|m| m.fan_pwm),
        fan_rpm: m.map(|m| m.fan_rpm),
        fan_max_rpm: l.and_then(|l| l.fan_max_rpm),
        vddgfx_mv: m.map(|m| m.vddgfx_mv),
        vddsoc_mv: m.and_then(|m| m.vddsoc_mv),
        power_average_w: m.map(|m| m.socket_power_w.into()),
        power_input_w: m.and_then(|m| crate::amdgpu_info_stats::latest_power_w(m.socket_power_w)),
        power_cap_w: t.map(|t| t.ppt_limit_w),
        power_cap_default_w: l.map(|l| l.ppt_default_w.into()),
        power_cap_min_w: l.map(|l| l.ppt_min_w),
        power_cap_max_w: l.map(|l| l.ppt_max_w),
        // sclk is METRICS_AVERAGE_GFXCLK, mclk METRICS_CURR_UCLK.
        sclk_mhz: m.map(|m| m.gfx_mhz.into()),
        mclk_mhz: m.map(|m| m.uclk_mhz),
    }
}

/// One attribute's sysfs text. Values needing telemetry or board limits read
/// empty (an error to lm-sensors) until available, never as a fake zero.
pub fn show(snapshot: Option<&Snapshot>, name: &str) -> String {
    crate::amdgpu_hwmon::show(&reading(snapshot), name)
}

/// Publish `/sys/class/hwmon/hwmon<N>` (first free N) named `amdgpu`.
/// Read-only until the platform can apply `power1_cap` writes.
pub fn publish(limits: Option<Limits>) {
    crate::amdgpu_hwmon::publish(
        attributes(limits.is_some_and(|l| l.fan_max_rpm.is_some())),
        |name| show(snapshot().as_ref(), name),
    );
}

/// Seed limits and publish hwmon. Call once, after the retained boot
/// succeeded. No refresh monitor is spawned: live telemetry waits on the
/// SMU owner (#2464) and the platform run loop (#2459).
pub fn seed(limits: Option<Limits>) {
    {
        let mut published = SNAPSHOT.lock();
        if published.is_some() {
            return;
        }
        *published = Some(Snapshot {
            telemetry: None,
            limits,
            protected: false,
            error: None,
            samples: 0,
        });
    }
    publish(limits);
}

/// Stop the old telemetry producer before reset, including one that already
/// sampled and is waiting to publish. Recovery creates exactly one successor.
pub fn stop() {
    GENERATION.fetch_add(1, Ordering::AcqRel);
    ALERTS.cancel();
    HOT_NOTIFIED.store(false, Ordering::Release);
    HW_CTF_NOTIFIED.store(false, Ordering::Release);
    if let Some(snapshot) = SNAPSHOT.lock().as_mut() {
        snapshot.protected = false;
        snapshot.error = Some(RefreshError::DeviceGone);
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi31_power_tests.rs"]
mod tests;
