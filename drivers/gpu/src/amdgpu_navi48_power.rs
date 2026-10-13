//! Navi48 runtime power monitor. A task refreshes PMFW telemetry through the
//! retained SMU owner (Linux caches the same metrics table for sysfs reads),
//! reports throttling, lost protection and software-CTF temperatures, and
//! serves the Linux amdgpu hwmon ABI (amdgpu_pm.c `hwmon_attributes`) from the
//! last sample. Fan control stays automatic: smu_v14_0_2_ppt.c provides no
//! fan-mode or PWM setters, so `pwm1`/`pwm1_enable` are read-only as in Linux.
//! Nothing here changes clocks, limits or protection.
use crate::amdgpu_smu_navi48 as smu;
use crate::amdgpu_smu_navi48_telemetry::{Limits, Telemetry, CRIT_HYST_MILLI, THROTTLERS};
use alloc::{format, string::String, vec::Vec};
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
pub(crate) async fn monitor() {
    loop {
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
/// does for a fan-equipped (or fanless) SMU14.0.2 dGPU. `power1_input` and
/// the overdrive-dependent `power1_cap_{min,max}` are not provided.
pub(crate) fn attributes(fan: bool) -> Vec<&'static str> {
    let mut names = Vec::new();
    for t in [
        [
            "temp1_input",
            "temp1_label",
            "temp1_crit",
            "temp1_crit_hyst",
            "temp1_emergency",
        ],
        [
            "temp2_input",
            "temp2_label",
            "temp2_crit",
            "temp2_crit_hyst",
            "temp2_emergency",
        ],
        [
            "temp3_input",
            "temp3_label",
            "temp3_crit",
            "temp3_crit_hyst",
            "temp3_emergency",
        ],
    ] {
        names.extend_from_slice(&t);
    }
    if fan {
        names.extend_from_slice(&[
            "pwm1",
            "pwm1_enable",
            "pwm1_min",
            "pwm1_max",
            "fan1_input",
            "fan1_min",
            "fan1_max",
        ]);
    }
    names.extend_from_slice(&[
        "in0_input",
        "in0_label",
        "power1_average",
        "power1_cap",
        "power1_cap_default",
        "power1_label",
        "freq1_input",
        "freq1_label",
        "freq2_input",
        "freq2_label",
    ]);
    names
}

/// One attribute's sysfs text. Values needing telemetry or board limits read
/// empty (an error to lm-sensors) until available, never as a fake zero.
pub(crate) fn show(snapshot: Option<&Snapshot>, name: &str) -> String {
    let t = snapshot.and_then(|s| s.telemetry);
    let l = snapshot.and_then(|s| s.limits);
    let m = t.map(|t| t.metrics);
    let value: Option<i64> = match name {
        "temp1_label" => return "edge\n".into(),
        "temp2_label" => return "junction\n".into(),
        "temp3_label" => return "mem\n".into(),
        "in0_label" => return "vddgfx\n".into(),
        "power1_label" => return "PPT\n".into(),
        "freq1_label" => return "sclk\n".into(),
        "freq2_label" => return "mclk\n".into(),
        // amdgpu_hwmon_get_pwm1_{min,max}; SMU reports MIN_FAN_RPM as zero;
        // automatic control is AMD_FAN_CTRL_AUTO, hwmon mode 2.
        "pwm1_min" | "fan1_min" => Some(0),
        "pwm1_max" => Some(255),
        "pwm1_enable" => Some(2),
        "temp1_input" => m.map(|m| m.edge_milli.into()),
        "temp2_input" => m.map(|m| m.hotspot_milli.into()),
        "temp3_input" => m.map(|m| m.mem_milli.into()),
        "temp1_crit" => l.map(|l| l.edge_crit_milli.into()),
        "temp2_crit" => l.map(|l| l.hotspot_crit_milli.into()),
        "temp3_crit" => l.map(|l| l.mem_crit_milli.into()),
        "temp1_crit_hyst" | "temp2_crit_hyst" | "temp3_crit_hyst" => {
            l.map(|_| CRIT_HYST_MILLI.into())
        }
        "temp1_emergency" => l.map(|l| l.edge_emergency_milli.into()),
        "temp2_emergency" => l.map(|l| l.hotspot_emergency_milli.into()),
        "temp3_emergency" => l.map(|l| l.mem_emergency_milli.into()),
        "pwm1" => m.map(|m| m.fan_pwm.into()),
        "fan1_input" => m.map(|m| m.fan_rpm.into()),
        "fan1_max" => l.and_then(|l| l.fan_max_rpm).map(Into::into),
        "in0_input" => m.map(|m| m.vddgfx_mv.into()),
        // Microwatts, from PMFW watts.
        "power1_average" => m.map(|m| i64::from(m.socket_power_w) * 1_000_000),
        "power1_cap" => t.map(|t| i64::from(t.ppt_limit_w) * 1_000_000),
        "power1_cap_default" => l.map(|l| i64::from(l.ppt_default_w) * 1_000_000),
        // Hz: sclk is METRICS_AVERAGE_GFXCLK, mclk METRICS_CURR_UCLK.
        "freq1_input" => m.map(|m| i64::from(m.gfx_mhz) * 1_000_000),
        "freq2_input" => m.map(|m| i64::from(m.uclk_mhz) * 1_000_000),
        _ => None,
    };
    value.map_or_else(String::new, |v| format!("{v}\n"))
}

/// Publish `/sys/class/hwmon/hwmon<N>` (first free N) named `amdgpu`.
pub(crate) fn publish(limits: Option<Limits>) {
    use narf_filesystem::sysfs::{class_device_register, class_register, kobject_add_attr};
    let class = class_register("hwmon");
    let taken = class.child_names();
    let index = (0..).find(|i| !taken.iter().any(|n| *n == format!("hwmon{i}")));
    let Some(index) = index else { return };
    let node = class_device_register(class, &format!("hwmon{index}"));
    kobject_add_attr(&node, "name", || "amdgpu\n".into());
    // Linux hwmon class devices have no device node, so no DEVNAME/MAJOR.
    narf_filesystem::sysfs::kobject_add_uevent_attr(&node, String::new());
    for name in attributes(limits.is_some_and(|l| l.fan_max_rpm.is_some())) {
        kobject_add_attr(&node, name, move || show(snapshot().as_ref(), name));
    }
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
    narf_scheduler::spawn(monitor());
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_power_tests.rs"]
mod tests;
