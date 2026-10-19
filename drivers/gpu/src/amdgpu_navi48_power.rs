//! Navi48 runtime power monitor. A task refreshes PMFW telemetry through the
//! retained SMU owner (Linux caches the same metrics table for sysfs reads),
//! reports throttling, lost protection and software-CTF temperatures, and
//! serves the Linux amdgpu hwmon ABI (amdgpu_pm.c `hwmon_attributes`) from the
//! last sample. Fan control stays automatic: smu_v14_0_2_ppt.c provides no
//! fan-mode or PWM setters, so `pwm1`/`pwm1_enable` are read-only as in Linux.
//! Nothing here changes clocks, limits or protection.
use crate::amdgpu_smu_navi48 as smu;
use crate::amdgpu_smu_navi48_telemetry::{Limits, Telemetry, CRIT_HYST_MILLI, THROTTLERS};
use alloc::{string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use narf_lib::sync::IrqSafeSpinLock;
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// Refresh period; also hwmon's natural update granularity.
pub const POLL_MS: u64 = 1000;

/// Last telemetry state, published to diagnostics and hwmon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// Most recent successful sample; retained across a rejected refresh.
    pub telemetry: Option<Telemetry>,
    pub limits: Option<Limits>,
    /// Every protection running after boot is still running in `telemetry`.
    pub protected: bool,
    pub gfx_level: smu::GfxLevel,
    /// Error of the latest refresh, cleared by the next success.
    pub error: Option<smu::Error>,
    pub samples: u64,
}

/// One owner-serialized refresh, as returned by the platform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    pub telemetry: Result<Telemetry, smu::Error>,
    pub limits: Option<Limits>,
    pub protected: bool,
    pub gfx_level: smu::GfxLevel,
}

static SNAPSHOT: IrqSafeSpinLock<Option<Snapshot>> = IrqSafeSpinLock::new(None);

pub fn snapshot() -> Option<Snapshot> {
    *SNAPSHOT.lock()
}

/// Notable transitions between two snapshots, for the console.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Events {
    /// Throttlers that started limiting since the previous sample.
    pub started: u32,
    /// Throttlers that stopped limiting.
    pub stopped: u32,
    pub protection_lost: bool,
    /// Hotspot reached `software_shutdown_temp` (Linux would power off).
    pub software_shutdown: bool,
    /// The first failed refresh after a success (or at start).
    pub failed: Option<smu::Error>,
}

/// Fold one refresh into the published state.
pub(crate) fn update(previous: Option<Snapshot>, sample: Sample) -> (Snapshot, Events) {
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
        gfx_level: sample.gfx_level,
        error,
        samples: previous.map_or(0, |p| p.samples) + u64::from(error.is_none()),
    };
    (snapshot, events)
}

fn throttler_names(mask: u32) -> String {
    let names: Vec<&str> = THROTTLERS
        .iter()
        .enumerate()
        .filter(|(i, _)| mask & (1 << i) != 0)
        .map(|(_, n)| *n)
        .collect();
    names.join(",")
}

fn report(snapshot: &Snapshot, events: Events) {
    use core::fmt::Write;
    let mut w = narf_console::Writer;
    if events.started != 0 {
        let _ = writeln!(
            w,
            "amdgpu: navi48 PMFW throttling: {}",
            throttler_names(events.started)
        );
    }
    if events.stopped != 0 {
        let _ = writeln!(
            w,
            "amdgpu: navi48 PMFW throttling ended: {}",
            throttler_names(events.stopped)
        );
    }
    if events.protection_lost {
        let enabled = snapshot.telemetry.map_or(0, |t| t.enabled);
        let _ = writeln!(
            w,
            "amdgpu: navi48 PMFW protection feature stopped (running {enabled:#x})"
        );
    }
    if events.software_shutdown {
        // Linux schedules orderly_poweroff() from its THM interrupt; narf has
        // no such policy yet. PMFW's hardware CTF still protects the board.
        let hotspot = snapshot.telemetry.map_or(0, |t| t.metrics.hotspot_milli);
        let _ = writeln!(
            w,
            "amdgpu: navi48 EMERGENCY: hotspot {} mC at software shutdown temperature",
            hotspot
        );
    }
    if let Some(error) = events.failed {
        let _ = writeln!(w, "amdgpu: navi48 PMFW telemetry failed: {error:?}");
    }
}

/// Poll until a terminal SMU failure. Each refresh holds the platform owner
/// only for its mailbox commands.
async fn monitor(generation: u64) {
    loop {
        if GENERATION.load(Ordering::Acquire) != generation {
            return;
        }
        let sample = match crate::amdgpu_navi48_platform::power_sample().await {
            Ok(sample) => sample,
            Err(_) => return, // owner absent or boot not complete
        };
        let terminal = matches!(
            sample.telemetry,
            Err(e) if !matches!(e, smu::Error::Rejected(_))
        );
        let (snapshot, events) = {
            let mut published = SNAPSHOT.lock();
            if GENERATION.load(Ordering::Acquire) != generation {
                return;
            }
            let (snapshot, events) = update(*published, sample);
            *published = Some(snapshot);
            (snapshot, events)
        };
        report(&snapshot, events);
        if terminal {
            return;
        }
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(POLL_MS).as_instant()).await;
    }
}

/// Linux amdgpu hwmon attribute names, filtered as `hwmon_attributes_visible`
/// does for a fan-equipped (or fanless) SMU14.0.2 dGPU (no RPM setters).
pub(crate) fn attributes(fan: bool) -> Vec<&'static str> {
    crate::amdgpu_hwmon::attributes(fan, false)
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
        power_average_w: m.map(|m| m.socket_power_w.into()),
        power_cap_w: t.map(|t| t.ppt_limit_w),
        power_cap_default_w: l.map(|l| l.ppt_default_w.into()),
        // sclk is METRICS_AVERAGE_GFXCLK, mclk METRICS_CURR_UCLK.
        sclk_mhz: m.map(|m| m.gfx_mhz.into()),
        mclk_mhz: m.map(|m| m.uclk_mhz),
    }
}

/// One attribute's sysfs text. Values needing telemetry or board limits read
/// empty (an error to lm-sensors) until available, never as a fake zero.
pub(crate) fn show(snapshot: Option<&Snapshot>, name: &str) -> String {
    crate::amdgpu_hwmon::show(&reading(snapshot), name)
}

/// Publish `/sys/class/hwmon/hwmon<N>` (first free N) named `amdgpu`.
pub(crate) fn publish(limits: Option<Limits>) {
    crate::amdgpu_hwmon::publish(
        attributes(limits.is_some_and(|l| l.fan_max_rpm.is_some())),
        |name| show(snapshot().as_ref(), name),
    );
}

/// Seed limits, publish hwmon and start the monitor. Call once, after the
/// retained boot succeeded.
pub(crate) fn start(limits: Option<Limits>, gfx_level: smu::GfxLevel) {
    {
        let mut published = SNAPSHOT.lock();
        if published.is_some() {
            return;
        }
        *published = Some(Snapshot {
            telemetry: None,
            limits,
            protected: false,
            gfx_level,
            error: None,
            samples: 0,
        });
    }
    publish(limits);
    narf_scheduler::spawn(monitor(GENERATION.load(Ordering::Acquire)));
}

/// Stop the old telemetry producer before reset, including one that already
/// sampled and is waiting to publish. Recovery creates exactly one successor.
pub(crate) fn stop() {
    GENERATION.fetch_add(1, Ordering::AcqRel);
    if let Some(snapshot) = SNAPSHOT.lock().as_mut() {
        snapshot.protected = false;
        snapshot.error = Some(smu::Error::DeviceGone);
    }
}
pub(crate) fn restart(limits: Option<Limits>, gfx_level: smu::GfxLevel) {
    let generation = GENERATION.fetch_add(1, Ordering::AcqRel) + 1;
    *SNAPSHOT.lock() = Some(Snapshot {
        telemetry: None,
        limits,
        protected: false,
        gfx_level,
        error: None,
        samples: 0,
    });
    // The original boot already published hwmon; do not register a second node.
    narf_scheduler::spawn(monitor(generation));
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_power_tests.rs"]
mod tests;
