//! Navi22 SMU11 thermal and SMU-to-driver interrupts, as Linux
//! `smu_v11_0_register_irq_handler` / `smu_v11_0_irq_process`:
//!
//! - THM (0x0f) src 0, DIG_THERM_L2H: the ASIC crossed DIG_THERM_INTH
//!   (`software_shutdown_temp`). After `AMDGPU_SWCTF_EXTRA_DELAY` (50 ms) the
//!   hotspot is re-read; at or above the limit — or when it cannot be read or
//!   the board has no limit — `smu_swctf_delayed_work_handler` requests an
//!   orderly power-off.
//! - THM src 1, DIG_THERM_H2L: logged as "under temperature range".
//! - ROM_SMUIO (0x16) src 83, GPIO19 hardware CTF: logged and an immediate
//!   orderly power-off, as `orderly_poweroff(true)`.
//! - MP1 (0x1f) src 0xfe, SMU-to-driver: `INT_ACK` first, then context
//!   AC (3) / DC (4) re-arm AC/DC delivery (`ReenableAcDcInterrupt`), thermal
//!   throttling (7) increments the throttle counter (sienna_cichlid has no
//!   `log_thermal_throttling_event`), others are ignored.
//!
//! NARF has no userspace `poweroff` helper or filesystem write-back, so the
//! orderly path reduces to Linux's forced fallback: log, then
//! `narf_power::system::power_off()` (ACPI S5 / PSCI SYSTEM_OFF). PMFW's own
//! hardware CTF remains the last line of protection. Fan stays automatic.
use crate::amdgpu_ih_navi22::{source, Handle, Iv, Source, Subscription};
use crate::amdgpu_smu_navi22::{self as smu, Limits};
use core::sync::atomic::{AtomicU64, Ordering};
use narf_lib::sync::IrqSafeSpinLock;

/// `AMDGPU_SWCTF_EXTRA_DELAY`.
pub const SWCTF_DELAY_MS: u64 = 50;
// SMU_IH_INTERRUPT_CONTEXT_ID_* (smu_cmn.h).
pub const CONTEXT_AC: u32 = 0x3;
pub const CONTEXT_DC: u32 = 0x4;
pub const CONTEXT_THERMAL_THROTTLING: u32 = 0x7;
/// Every source `smu_v11_0_register_irq_handler` adds.
pub const SOURCES: [Source; 4] = [
    source::THERMAL_HIGH,
    source::THERMAL_LOW,
    source::THERMAL_CTF,
    source::SMU_TO_DRIVER,
];

/// Why the platform is being powered off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shutdown {
    /// GPIO19 hardware critical temperature fault.
    HardwareCtf,
    /// L2H alert confirmed after the SW CTF delay; the hotspot reading in
    /// millidegrees when one was available.
    SoftwareCtf { hotspot_milli: Option<i32> },
}

/// What one IV asks for, decided without I/O.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// Wait `SWCTF_DELAY_MS`, re-read the hotspot and maybe shut down.
    ConfirmSoftwareCtf,
    UnderTemperature,
    UnknownThermal(u8),
    PowerOff(Shutdown),
    /// Acknowledge, then handle the context id.
    SmuToDriver(u32),
    Ignore,
}
pub(crate) fn classify(iv: &Iv) -> Action {
    let from = iv.source();
    if from.client == source::client::THM {
        return match iv.src {
            0 => Action::ConfirmSoftwareCtf,
            1 => Action::UnderTemperature,
            other => Action::UnknownThermal(other),
        };
    }
    if from.client == source::client::ROM_SMUIO {
        // Linux treats any routed ROM_SMUIO IV (only GPIO19 is registered)
        // as the hardware CTF.
        return Action::PowerOff(Shutdown::HardwareCtf);
    }
    if from == source::SMU_TO_DRIVER {
        return Action::SmuToDriver(iv.src_data[0]);
    }
    Action::Ignore
}

/// Observable counters and the escalation, for diagnostics and tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Status {
    pub armed: Option<smu::Alert>,
    pub over_temperature: u64,
    pub under_temperature: u64,
    pub hardware_ctf: u64,
    pub smu_to_driver: u64,
    /// `smu->throttle_int_counter`.
    pub throttling: u64,
    pub ac: Option<bool>,
    pub last_error: Option<smu::Error>,
    pub shutdown: Option<Shutdown>,
}
static STATUS: IrqSafeSpinLock<Status> = IrqSafeSpinLock::new(Status {
    armed: None,
    over_temperature: 0,
    under_temperature: 0,
    hardware_ctf: 0,
    smu_to_driver: 0,
    throttling: 0,
    ac: None,
    last_error: None,
    shutdown: None,
});
static EPOCH: AtomicU64 = AtomicU64::new(0);
pub fn status() -> Status {
    *STATUS.lock()
}

/// Effects the handler needs; production uses the retained owner.
pub(crate) trait Platform {
    /// A fresh hotspot reading in millidegrees (the SW CTF re-check).
    async fn hotspot(&mut self) -> Option<i32>;
    fn limits(&self) -> Option<Limits>;
    /// `MP1_SMN_IH_SW_INT_CTRL.INT_ACK`.
    fn ack(&mut self) -> Result<(), smu::Error>;
    /// `smu_v11_0_interrupt_work`: ReenableAcDcInterrupt via the mailbox.
    async fn reenable_acdc(&mut self) -> Result<(), smu::Error>;
    async fn delay_ms(&mut self, ms: u64);
    /// Never returns in production.
    fn power_off(&mut self, reason: Shutdown);
}

fn log(args: core::fmt::Arguments<'_>) {
    use core::fmt::Write;
    let _ = writeln!(narf_console::Writer, "amdgpu: navi22 {args}");
}

/// Handle one IV exactly as `smu_v11_0_irq_process` does.
pub(crate) async fn handle<P: Platform>(platform: &mut P, iv: &Iv) -> Action {
    let action = classify(iv);
    match action {
        Action::ConfirmSoftwareCtf => {
            STATUS.lock().over_temperature += 1;
            platform.delay_ms(SWCTF_DELAY_MS).await;
            let hotspot = platform.hotspot().await;
            let emergency = platform
                .limits()
                .is_none_or(|limits| limits.software_shutdown(hotspot));
            if emergency {
                log(format_args!(
                    "ERROR: GPU over temperature range (SW CTF) detected, hotspot {hotspot:?} mC"
                ));
                log(format_args!(
                    "ERROR: System is going to shutdown due to GPU SW CTF!"
                ));
                let reason = Shutdown::SoftwareCtf {
                    hotspot_milli: hotspot,
                };
                STATUS.lock().shutdown = Some(reason);
                platform.power_off(reason);
            }
        }
        Action::UnderTemperature => {
            STATUS.lock().under_temperature += 1;
            log(format_args!("ERROR: GPU under temperature range detected"));
        }
        Action::UnknownThermal(src) => {
            log(format_args!(
                "ERROR: GPU under temperature range unknown src id ({src})"
            ));
        }
        Action::PowerOff(reason) => {
            {
                let mut status = STATUS.lock();
                status.hardware_ctf += 1;
                status.shutdown = Some(reason);
            }
            log(format_args!(
                "ERROR: GPU HW Critical Temperature Fault(aka CTF) detected!"
            ));
            log(format_args!(
                "ERROR: System is going to shutdown due to GPU HW CTF!"
            ));
            platform.power_off(reason);
        }
        Action::SmuToDriver(context) => {
            STATUS.lock().smu_to_driver += 1;
            if let Err(error) = platform.ack() {
                STATUS.lock().last_error = Some(error);
            }
            match context {
                CONTEXT_AC | CONTEXT_DC => {
                    STATUS.lock().ac = Some(context == CONTEXT_AC);
                    if let Err(error) = platform.reenable_acdc().await {
                        STATUS.lock().last_error = Some(error);
                        log(format_args!("Ack AC/DC interrupt Failed! {error:?}"));
                    }
                }
                CONTEXT_THERMAL_THROTTLING => STATUS.lock().throttling += 1,
                _ => {}
            }
        }
        Action::Ignore => {}
    }
    action
}

struct Hardware {
    ack: smu::InterruptAck,
    limits: Option<Limits>,
}
impl Platform for Hardware {
    async fn hotspot(&mut self) -> Option<i32> {
        let sample = crate::amdgpu_navi22_platform::power_sample().await.ok()?;
        let telemetry = sample.telemetry.ok()?;
        crate::amdgpu_navi22_power::publish_sample(sample);
        Some(telemetry.metrics.hotspot_milli)
    }
    fn limits(&self) -> Option<Limits> {
        self.limits
    }
    fn ack(&mut self) -> Result<(), smu::Error> {
        self.ack.ack()
    }
    async fn reenable_acdc(&mut self) -> Result<(), smu::Error> {
        crate::amdgpu_navi22_platform::reenable_acdc().await
    }
    async fn delay_ms(&mut self, ms: u64) {
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(ms).as_instant()).await;
    }
    fn power_off(&mut self, _reason: Shutdown) {
        narf_power::system::power_off();
    }
}

/// Claim every SMU11 source before the alert is armed, so no IV raised by
/// the enable is dispatched to nobody.
pub(crate) fn subscribe(
    ih: &Handle,
) -> Result<alloc::vec::Vec<Subscription>, crate::amdgpu_ih_navi22::Error> {
    let mut subscriptions = alloc::vec::Vec::new();
    for from in SOURCES {
        subscriptions.push(ih.subscribe(from)?);
    }
    Ok(subscriptions)
}

/// One task per source after `Smu::enable_thermal_alert`; a terminal IH
/// error (device loss, recovery quiesce) or a newer epoch ends each task.
pub(crate) fn spawn(
    subscriptions: alloc::vec::Vec<Subscription>,
    alert: smu::Alert,
    ack: smu::InterruptAck,
    limits: Option<Limits>,
) {
    let epoch = EPOCH.fetch_add(1, Ordering::AcqRel) + 1;
    STATUS.lock().armed = Some(alert);
    for mut subscription in subscriptions {
        let mut hw = Hardware { ack, limits };
        narf_scheduler::spawn(async move {
            loop {
                match subscription.wait().await {
                    Ok(iv) if EPOCH.load(Ordering::Acquire) == epoch => {
                        handle(&mut hw, &iv).await;
                    }
                    Ok(_) | Err(_) => return,
                }
            }
        });
    }
}

/// Recovery quiesce: the current tasks end at their next IV; their IH
/// subscriptions close with the old ring.
pub(crate) fn stop() {
    EPOCH.fetch_add(1, Ordering::AcqRel);
    STATUS.lock().armed = None;
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi22_thermal_tests.rs"]
mod tests;
