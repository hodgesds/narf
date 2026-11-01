//! Navi48 runtime power monitor. A task refreshes PMFW telemetry through the
//! retained SMU owner (Linux caches the same metrics table for sysfs reads),
//! reports throttling, lost protection and software-CTF temperatures, and
//! serves the Linux amdgpu hwmon ABI (amdgpu_pm.c `hwmon_attributes`) from the
//! last sample. Fan control stays automatic: smu_v14_0_2_ppt.c provides no
//! fan-mode or PWM setters, so `pwm1`/`pwm1_enable` are read-only as in Linux.
//! `power1_cap` is writable (amdgpu_hwmon_set_power_cap: microwatts to watts,
//! checked against `power1_cap_{min,max}`). Factory workload controls below
//! change only the selected heuristics and previously admitted sleep bits.
use crate::amdgpu_smu_navi48 as smu;
use crate::amdgpu_smu_navi48_telemetry::{Limits, Telemetry, CRIT_HYST_MILLI, THROTTLERS};
use alloc::{string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use narf_filesystem::FsError;
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};
static GENERATION: AtomicU64 = AtomicU64::new(0);
static GFX_ULV_ALLOWED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(true);
static DCF_SLEEP_ALLOWED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(true);
/// Boot policy, before native ownership is constructed.
pub fn set_extra_sleep(gfx_ulv: bool, dcf_sleep: bool) {
    GFX_ULV_ALLOWED.store(gfx_ulv, Ordering::Release);
    DCF_SLEEP_ALLOWED.store(dcf_sleep, Ordering::Release);
}
pub(crate) fn gfx_ulv_requested() -> bool {
    GFX_ULV_ALLOWED.load(Ordering::Acquire)
}
pub(crate) fn dcf_sleep_requested() -> bool {
    DCF_SLEEP_ALLOWED.load(Ordering::Acquire)
}
#[path = "amdgpu_navi48_thermal.rs"]
pub mod thermal;

/// Linux's delayed SW CTF confirmation and the existing orderly worker's
/// bounded sync budget. Power-off never runs from an IH or SMU call frame.
pub const SWCTF_DELAY_MS: u64 = 50;
pub const FORCED_POWEROFF_MS: u64 = 10_000;
static HOT_NOTIFIED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
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
/// Decide only from a fresh reading. A known thermal-high IRQ is fail-safe
/// if its confirmation cannot read the sensor; unavailable periodic data
/// alone is not evidence of a trip and never clears a hot-episode latch.
fn thermal_trip(
    notified: &core::sync::atomic::AtomicBool,
    sample: Option<&Sample>,
    irq_limit: Option<u16>,
) -> bool {
    let fresh = sample.and_then(|s| s.telemetry.as_ref().ok());
    let limit = irq_limit
        .or_else(|| sample.and_then(|s| s.limits).map(|l| l.software_shutdown_c))
        .filter(|&l| l != 0);
    let hot = match (fresh, limit) {
        (Some(t), Some(limit)) => t.metrics.hotspot_milli / 1000 >= i32::from(limit),
        _ if irq_limit.is_some() => true,
        _ => return false,
    };
    if !hot {
        notified.store(false, Ordering::Release);
        return false;
    }
    !notified.swap(true, Ordering::AcqRel)
}
/// Called inside the platform OWNER critical section that supplied sample.
/// Stop/restart change GENERATION under that same owner: a stale sensor
/// read can never request shutdown after a reset/PM successor is published.
fn thermal_trip_if_current(
    owner: &AtomicU64,
    generation: u64,
    notified: &core::sync::atomic::AtomicBool,
    sample: Option<&Sample>,
    irq_limit: Option<u16>,
) -> bool {
    owner.load(Ordering::Acquire) == generation && thermal_trip(notified, sample, irq_limit)
}
fn observe_thermal(generation: u64, sample: Option<&Sample>, irq_limit: Option<u16>) {
    if thermal_trip_if_current(&GENERATION, generation, &HOT_NOTIFIED, sample, irq_limit) {
        narf_power::orderly::hw_protection_shutdown(
            "RX 9000 GPU software critical temperature",
            FORCED_POWEROFF_MS,
        );
    }
}
/// The retained thermal IRQ controller captured a high-threshold event.
/// One task per owner waits 50 ms, then confirms under OWNER. No IRQ-safe
/// lock is held while it waits or requests the orderly worker.
pub(crate) fn thermal_alert(limit: u16) {
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
        crate::amdgpu_navi48_platform::power_sample_with(|sample| {
            observe_thermal(generation, sample.as_ref().ok(), Some(limit));
        })
        .await;
    });
}

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
    pub profile: smu::PowerProfile,
    pub coefficients: Option<smu::ProfileCoefficients>,
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
    pub profile: smu::PowerProfile,
    pub coefficients: Option<smu::ProfileCoefficients>,
}

static SNAPSHOT: IrqSafeSpinLock<Option<Snapshot>> = IrqSafeSpinLock::new(None);

pub fn snapshot() -> Option<Snapshot> {
    *SNAPSHOT.lock()
}

/// Serializes queued sysfs changes without holding an IRQ-safe lock.
static LEVEL_CONTROL: Mutex<()> = Mutex::new(());
static LEVEL_REQUEST: AtomicU64 = AtomicU64::new(0);

/// Linux performance-level spellings with a native GFXCLK implementation.
pub fn parse_level(text: &str) -> Result<smu::GfxLevel, FsError> {
    match text.trim() {
        "auto" => Ok(smu::GfxLevel::Auto),
        "low" => Ok(smu::GfxLevel::Low),
        "high" => Ok(smu::GfxLevel::High),
        "manual" | "profile_standard" | "profile_min_sclk" | "profile_min_mclk"
        | "profile_peak" | "profile_exit" | "perf_determinism" => Err(FsError::Unsupported),
        _ => Err(FsError::InvalidData),
    }
}
fn level_name(snapshot: Option<Snapshot>) -> &'static str {
    match snapshot.map(|s| s.gfx_level) {
        Some(smu::GfxLevel::Low) => "low",
        Some(smu::GfxLevel::High) => "high",
        _ => "auto",
    }
}
/// Last successfully applied GFXCLK level; no mailbox exchange on a read.
pub fn level() -> &'static str {
    level_name(snapshot())
}
fn controls_live(snapshot: Option<Snapshot>) -> bool {
    snapshot.is_some_and(|s| s.error.is_none_or(|e| matches!(e, smu::Error::Rejected(_))))
}
/// Caller holds OWNER, excluding stop/restart and stale read publication.
pub(crate) fn level_owner_current(generation: u64) -> bool {
    GENERATION.load(Ordering::Acquire) == generation && controls_live(snapshot())
}
/// Publish only after PMFW accepted both bounds, while OWNER is retained.
pub(crate) fn applied_level(level: smu::GfxLevel) {
    if let Some(snapshot) = SNAPSHOT.lock().as_mut() {
        snapshot.gfx_level = level;
    }
}
async fn run_level_request<E>(
    serial: &Mutex<()>,
    latest: &AtomicU64,
    request: u64,
    apply: impl core::future::Future<Output = Result<(), E>>,
) -> Option<Result<(), E>> {
    let _serial = serial.lock().await;
    if latest.load(Ordering::Acquire) != request {
        return None;
    }
    Some(apply.await)
}
/// Validate synchronously, then serialize with other writes on the executor.
/// A later pending write supersedes an earlier one; reset/PM owner changes
/// refuse old queued requests before any clock write. Readback changes only
/// after the retained SMU owner accepted the new GFXCLK bounds.
pub fn request_level(text: &str) -> Result<(), FsError> {
    let level = parse_level(text)?;
    let generation = GENERATION.load(Ordering::Acquire);
    if !controls_live(snapshot()) {
        return Err(FsError::NoDevice);
    }
    let request = LEVEL_REQUEST.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
    narf_scheduler::spawn(async move {
        let result = run_level_request(
            &LEVEL_CONTROL,
            &LEVEL_REQUEST,
            request,
            crate::amdgpu_navi48_platform::set_gfx_level_current(level, generation),
        )
        .await;
        if let Some(Err(error)) = result {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: rdna4 performance level {level:?} failed: {error:?}"
            );
        }
    });
    Ok(())
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
        profile: sample.profile,
        coefficients: sample.coefficients,
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
        // The fresh sample already requested the orderly protection worker
        // under OWNER. Keep console evidence separate from that decision.
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
        let published = crate::amdgpu_navi48_platform::power_sample_with(|result| {
            let sample = result.ok()?;
            if GENERATION.load(Ordering::Acquire) != generation {
                return None;
            }
            observe_thermal(generation, Some(&sample), None);
            let terminal =
                matches!(sample.telemetry, Err(e) if !matches!(e, smu::Error::Rejected(_)));
            let mut published = SNAPSHOT.lock();
            let (snapshot, events) = update(*published, sample);
            *published = Some(snapshot);
            Some((snapshot, events, terminal))
        })
        .await;
        let Some((snapshot, events, terminal)) = published else {
            return;
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
    let mut names = crate::amdgpu_hwmon::attributes(fan, false);
    names.extend_from_slice(&["power1_cap_min", "power1_cap_max"]);
    names
}

/// A `power1_cap` write in microwatts, as amdgpu_hwmon_set_power_cap: the
/// watt value must lie in the board's non-overdrive range (smu_set_ppt_limit
/// -EINVAL otherwise; 0 there means the default only for the default limit
/// type, which hwmon does not use).
pub(crate) fn power_cap_request(limits: Option<Limits>, bytes: &[u8]) -> Result<u32, FsError> {
    let microwatts = crate::amdgpu_hwmon::parse_u32(bytes).ok_or(FsError::InvalidData)?;
    let watts = microwatts / 1_000_000;
    let limits = limits.ok_or(FsError::NoDevice)?;
    if watts < limits.ppt_min_w || watts > limits.ppt_max_w || watts == 0 {
        return Err(FsError::InvalidData);
    }
    Ok(watts)
}
fn store(name: &'static str, bytes: &[u8]) -> Result<(), FsError> {
    if name != "power1_cap" {
        return Err(FsError::OperationNotPermitted);
    }
    let watts = power_cap_request(snapshot().and_then(|s| s.limits), bytes)?;
    // sysfs stores run in a syscall; the SMU exchange needs the async
    // platform owner, so apply on the executor and report through the next
    // telemetry sample (power1_cap reads PMFW's GetPptLimit).
    narf_scheduler::spawn(async move {
        if let Err(e) = crate::amdgpu_navi48_platform::set_power_cap(watts).await {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi48 power1_cap {watts} W refused: {e:?}"
            );
        }
    });
    Ok(())
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
pub(crate) fn show(snapshot: Option<&Snapshot>, name: &str) -> String {
    crate::amdgpu_hwmon::show(&reading(snapshot), name)
}

/// Publish `/sys/class/hwmon/hwmon<N>` (first free N) named `amdgpu`.
pub(crate) fn publish(limits: Option<Limits>) {
    crate::amdgpu_hwmon::publish_writable(
        attributes(limits.is_some_and(|l| l.fan_max_rpm.is_some())),
        |name| show(snapshot().as_ref(), name),
        &["power1_cap"],
        store,
    );
}

/// Seed limits, publish hwmon and start the monitor. Call once, after the
/// retained boot succeeded.
pub(crate) fn start(limits: Option<Limits>, gfx_level: smu::GfxLevel, profile: smu::PowerProfile) {
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
            profile,
            coefficients: None,
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
    ALERTS.cancel();
    if let Some(snapshot) = SNAPSHOT.lock().as_mut() {
        snapshot.protected = false;
        snapshot.error = Some(smu::Error::DeviceGone);
    }
}
pub(crate) fn restart(
    limits: Option<Limits>,
    gfx_level: smu::GfxLevel,
    profile: smu::PowerProfile,
) {
    let generation = GENERATION.fetch_add(1, Ordering::AcqRel) + 1;
    ALERTS.cancel();
    *SNAPSHOT.lock() = Some(Snapshot {
        telemetry: None,
        limits,
        protected: false,
        gfx_level,
        profile,
        coefficients: None,
        error: None,
        samples: 0,
    });
    // The original boot already published hwmon; do not register a second node.
    narf_scheduler::spawn(monitor(generation));
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_power_tests.rs"]
mod tests;

#[path = "amdgpu_navi48_profile.rs"]
mod profile;
pub(crate) use profile::{applied as applied_profile, ProfileRequest};
pub use profile::{profiles, request_profile};
