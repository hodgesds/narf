//! Navi22 runtime power monitor. A task refreshes PMFW telemetry through the
//! retained SMU owner (Linux caches the same metrics table for sysfs reads),
//! reports throttling, lost protection and hotspot excursions, and serves the
//! Linux amdgpu hwmon ABI (amdgpu_pm.c) from the last sample through the
//! shared [`crate::amdgpu_hwmon`] node. Fan control stays automatic (PMFW
//! FAN_CONTROL); NARF exposes none of sienna_cichlid's fan or power-limit
//! setters, so every attribute is read-only. Nothing here changes clocks,
//! limits or protection. Thermal shutdown policy lives in
//! `amdgpu_navi22_thermal`, driven by the THM/CTF interrupts as in Linux.
use crate::amdgpu_smu_navi22 as smu;
use crate::amdgpu_smu_navi22_telemetry::{Limits, Telemetry, CRIT_HYST_MILLI, THROTTLERS};
use alloc::{string::String, vec::Vec};
use narf_lib::sync::IrqSafeSpinLock;

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
    /// `smu->default_power_limit`: the first PMFW limit read after boot.
    pub ppt_default_w: Option<u32>,
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
}

static SNAPSHOT: IrqSafeSpinLock<Option<Snapshot>> = IrqSafeSpinLock::new(None);
/// Bumped by `restart`, so a monitor of a replaced owner exits.
static EPOCH: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub fn snapshot() -> Option<Snapshot> {
    *SNAPSHOT.lock()
}

/// Notable transitions between two snapshots, for the console.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Events {
    pub started: u32,
    pub stopped: u32,
    pub protection_lost: bool,
    /// Hotspot reached `software_shutdown_temp`. Logged only: the shutdown
    /// decision is the THM L2H interrupt's, as in Linux.
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
    let hot = |t: Option<Telemetry>, l: &Limits| {
        t.is_some_and(|t| {
            l.software_shutdown_c != 0 && l.software_shutdown(Some(t.metrics.hotspot_milli))
        })
    };
    if let (Ok(new), Some(limits)) = (sample.telemetry, sample.limits) {
        events.software_shutdown = hot(Some(new), &limits) && !hot(old, &limits);
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
        ppt_default_w: previous
            .and_then(|p| p.ppt_default_w)
            .or(sample.telemetry.ok().map(|t| t.ppt_limit_w)),
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
            "amdgpu: navi22 PMFW throttling: {}",
            throttler_names(events.started)
        );
    }
    if events.stopped != 0 {
        let _ = writeln!(
            w,
            "amdgpu: navi22 PMFW throttling ended: {}",
            throttler_names(events.stopped)
        );
    }
    if events.protection_lost {
        let enabled = snapshot.telemetry.map_or(0, |t| t.enabled);
        let _ = writeln!(
            w,
            "amdgpu: navi22 PMFW protection feature stopped (running {enabled:#x})"
        );
    }
    if events.software_shutdown {
        let hotspot = snapshot.telemetry.map_or(0, |t| t.metrics.hotspot_milli);
        let _ = writeln!(
            w,
            "amdgpu: navi22 EMERGENCY: hotspot {hotspot} mC at software shutdown temperature"
        );
    }
    if let Some(error) = events.failed {
        let _ = writeln!(w, "amdgpu: navi22 PMFW telemetry failed: {error:?}");
    }
}

/// Fold one sample into the published snapshot and log transitions.
pub(crate) fn publish_sample(sample: Sample) -> Snapshot {
    let (snapshot, events) = {
        let mut published = SNAPSHOT.lock();
        let (snapshot, events) = update(*published, sample);
        *published = Some(snapshot);
        (snapshot, events)
    };
    report(&snapshot, events);
    snapshot
}

/// Poll until a terminal SMU failure or a restart. Each refresh holds the
/// platform owner only for its mailbox commands.
pub(crate) async fn monitor(epoch: u64) {
    use core::sync::atomic::Ordering;
    loop {
        if EPOCH.load(Ordering::Acquire) != epoch {
            return;
        }
        let sample = match crate::amdgpu_navi22_platform::power_sample().await {
            Ok(sample) => sample,
            Err(_) => return, // owner absent, recovering or boot not complete
        };
        if EPOCH.load(Ordering::Acquire) != epoch {
            return;
        }
        let terminal = matches!(
            sample.telemetry,
            Err(e) if !matches!(e, smu::Error::Rejected(_))
        );
        publish_sample(sample);
        if terminal {
            return;
        }
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(POLL_MS).as_instant()).await;
    }
}

/// Linux amdgpu hwmon attribute names for an SMU11 dGPU: SMU11 has RPM
/// setters, so `fan1_target`/`fan1_enable` are visible with a fan.
pub(crate) fn attributes(fan: bool) -> Vec<&'static str> {
    crate::amdgpu_hwmon::attributes(fan, true)
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
        pwm: t.and_then(|t| t.fan_pwm),
        fan_rpm: m.map(|m| m.fan_rpm),
        fan_max_rpm: l.and_then(|l| l.fan_max_rpm),
        vddgfx_mv: t.map(|t| t.vddgfx_mv),
        power_average_w: m.map(|m| m.socket_power_w.into()),
        power_cap_w: t.map(|t| t.ppt_limit_w),
        power_cap_default_w: snapshot
            .and_then(|s| s.ppt_default_w)
            .or(l.map(|l| l.ppt_table_w.into())),
        // sclk is METRICS_AVERAGE_GFXCLK, mclk METRICS_CURR_UCLK.
        sclk_mhz: m.map(|m| m.gfx_mhz.into()),
        mclk_mhz: m.map(|m| m.uclk_mhz),
    }
}

/// One attribute's sysfs text; empty until telemetry/limits exist.
pub(crate) fn show(snapshot: Option<&Snapshot>, name: &str) -> String {
    crate::amdgpu_hwmon::show(&reading(snapshot), name)
}

static PUBLISHED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Seed limits, publish hwmon once and start a monitor for the current
/// owner. A recovered owner calls this again: the hwmon node persists and
/// the previous monitor exits on the epoch change.
pub(crate) fn start(limits: Option<Limits>) {
    use core::sync::atomic::Ordering;
    let epoch = EPOCH.fetch_add(1, Ordering::AcqRel) + 1;
    {
        let mut published = SNAPSHOT.lock();
        *published = Some(Snapshot {
            telemetry: None,
            limits,
            protected: false,
            ppt_default_w: published.and_then(|p| p.ppt_default_w),
            error: None,
            samples: 0,
        });
    }
    if !PUBLISHED.swap(true, Ordering::AcqRel) {
        crate::amdgpu_hwmon::publish(
            attributes(limits.is_some_and(|l| l.fan_max_rpm.is_some())),
            |name| show(snapshot().as_ref(), name),
        );
    }
    narf_scheduler::spawn(monitor(epoch));
}

/// Stop the current monitor (recovery quiesce or device loss); hwmon keeps
/// the last sample and reports `error`.
pub(crate) fn stop(error: Option<smu::Error>) {
    use core::sync::atomic::Ordering;
    EPOCH.fetch_add(1, Ordering::AcqRel);
    if let Some(snapshot) = SNAPSHOT.lock().as_mut() {
        if error.is_some() {
            snapshot.error = error;
        }
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi22_power_tests.rs"]
mod tests;
