// SPDX-License-Identifier: GPL-2.0-or-later
//! PCI identification and retained asynchronous DMA-backed BMI bootstrap.
//! Probe disables inherited bus mastering, validates the per-chip BAR
//! windows and wakes the target. The boot task owns reset/CE7 target
//! configuration, CE0/CE1 BMI and calibrated firmware/BDF/OTP preparation.
//! Retained runtime CEs and HTC are activated only after calibrated image
//! preparation. WMI/HTT initialization and interface registration remain open.

#![allow(dead_code)]

use alloc::vec::Vec;
use core::fmt::Write as _;

use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;
use narf_time::Deadline;

use super::hw::*;

/// Retained PCI identity and the asynchronous boot transport's result.
pub struct Ath10kDevice {
    address: narf_bus::BusAddr,
    /// BAR0 MMIO window.
    pub mmio_bar0: MmioRegion,
    /// Decoded hardware family.
    pub hw_rev: HwRev,
    /// Raw 32-bit `SOC_CHIP_ID` register value.
    pub chip_id_raw: u32,
    /// Decoded chip-id-rev (the 4-bit field at bits [11:8]).
    pub chip_id_rev: u32,
    /// PCI device id we matched on.
    pub device_id: u16,
    /// PCI vendor id we matched on.
    pub vendor_id: u16,
    /// Published only after a real DMA-backed BMI target-info response.
    pub target_info: Option<super::bmi::TargetInfo>,
    /// Last boot failure; identification alone never implies a live WLAN.
    pub boot_error: Option<super::bmi::BmiError>,
    /// ROM-side calibrated image download; firmware is not yet activated.
    pub firmware_prepared: Option<FirmwarePrepared>,
    /// Firmware/profile/BDF/OTP failure after a successful BMI identity.
    pub firmware_error: Option<super::firmware::Error>,
    /// Real HTC endpoint negotiation, never station/interface admission.
    pub htc_ready: Option<HtcReady>,
    /// Runtime transport or HTC failure after ROM preparation.
    pub runtime_error: Option<super::control::Error>,
    /// Correlated service-ready/INIT/READY completed, with retained host DMA.
    pub wmi_ready: Option<super::wmi_boot::Ready>,
    pub wmi_error: Option<super::wmi_boot::Error>,
    /// Negotiated HTT with retained RX/fragment memory; station still closed.
    pub htt_ready: Option<super::htt_runtime::Ready>,
    pub htt_error: Option<super::htt_runtime::Error>,
    /// Real retained vdev/passive channel setup; no station or carrier.
    pub scan_ready: Option<super::wmi_runtime::ScanReady>,
    pub scan_error: Option<super::wmi_runtime::Error>,
    /// Native vdev START and peer-map prerequisites, never association or link.
    pub station_prepared: Option<super::wmi_runtime::PeerPrepared>,
    pub station_error: Option<super::wmi_runtime::Error>,
}

#[derive(Clone, Copy, Debug)]
pub struct FirmwarePrepared {
    pub directory: &'static str,
    pub api: u8,
    pub wmi_operations: u32,
    pub htt_operations: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct HtcReady {
    pub wmi_endpoint: u8,
    pub htt_endpoint: u8,
    pub credit_size: u16,
}

impl core::fmt::Debug for Ath10kDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ath10kDevice")
            .field("hw_rev", &self.hw_rev)
            .field("chip_id_raw", &format_args!("{:#010x}", self.chip_id_raw))
            .field("chip_id_rev", &self.chip_id_rev)
            .field("vendor_id", &format_args!("{:#06x}", self.vendor_id))
            .field("device_id", &format_args!("{:#06x}", self.device_id))
            .finish_non_exhaustive()
    }
}

/// Errors raised by the Stage 0 bring-up path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// `map_bar(device, 0)` failed. Most likely the BAR isn't
    /// implemented at all (wrong device) or the cap-list claim raced
    /// another driver.
    Bar0MapFailed,
    /// `SOC_CHIP_ID` read returned the all-FF "device gone" sentinel
    /// — the part isn't really there.
    DeviceGone,
    /// Global-reset never released within the deadline.
    ResetTimeout,
    /// The PCI ID matches AR9462, which is ath9k's territory; ath10k
    /// shouldn't bind it. Surfaced explicitly rather than silently
    /// succeeding so the probe trace shows what happened.
    LegacyChipRejected,
    /// The mapped BAR cannot cover this family's register windows.
    BadBar,
    /// The target's PCI-local RTC did not reach its awake state.
    WakeTimeout,
}

/// All-FF sentinel for a 32-bit MMIO read on absent silicon.
const READ_GONE_U32: u32 = 0xFFFF_FFFF;

/// Single-instance live device. Same shape as `rtw88` — laptops only
/// ship one ath10k radio, so single-instance is fine for now.
static CONTROLLER: IrqSafeSpinLock<Option<Ath10kDevice>> = IrqSafeSpinLock::new(None);

// The boot session retains its PCI authority, awake target and all DMA
// allocations. Future firmware/runtime work takes this async mutex, never
// an IRQ-disabling controller guard, while awaiting CE completions.
struct BootSession {
    bmi: super::bmi::Bmi<super::boot::PciBoot>,
    image: super::firmware::Image,
    profile: super::profile::Profile,
}
struct RuntimeSession {
    htc: super::control::Session<super::boot::PciBoot>,
    image: super::firmware::Image,
    profile: super::profile::Profile,
}
struct WmiSession {
    wmi: super::wmi_boot::Runtime<super::boot::PciBoot>,
    image: super::firmware::Image,
    profile: super::profile::Profile,
}
struct HttSession {
    htt: super::htt_runtime::Runtime<super::boot::PciBoot>,
    image: super::firmware::Image,
    profile: super::profile::Profile,
}
struct RadioSession {
    quarantine: alloc::sync::Arc<core::sync::atomic::AtomicBool>,
    radio:
        alloc::sync::Arc<narf_lib::mutex::Mutex<super::wmi_runtime::Radio<super::boot::PciBoot>>>,
    image: super::firmware::Image,
    profile: super::profile::Profile,
}
enum DriverSession {
    Boot(BootSession),
    Runtime(RuntimeSession),
    Wmi(WmiSession),
    Htt(HttSession),
    Radio(alloc::boxed::Box<RadioSession>),
}
static SESSION: narf_lib::mutex::Mutex<Option<DriverSession>> = narf_lib::mutex::Mutex::new(None);
static RECOVERY_ATTEMPTS: IrqSafeSpinLock<u8> = IrqSafeSpinLock::new(0);

fn live_radio(
    session: &mut Option<DriverSession>,
) -> Result<&mut RadioSession, super::wmi_runtime::Error> {
    match session {
        Some(DriverSession::Radio(owner))
            if !owner.quarantine.load(core::sync::atomic::Ordering::Acquire) =>
        {
            Ok(owner)
        }
        _ => Err(super::wmi_runtime::Error::Failed),
    }
}

pub(in crate::ath10k) async fn retire_radio<'a, T>(
    radio: &'a alloc::sync::Arc<narf_lib::mutex::Mutex<super::wmi_runtime::Radio<T>>>,
    quarantine: &core::sync::atomic::AtomicBool,
    retire_host: impl Fn(),
) -> narf_lib::mutex::MutexGuard<'a, super::wmi_runtime::Radio<T>>
where
    T: super::control::Hif + super::wmi_boot::HostMemory + super::htt_runtime::HttMemory,
{
    // Quarantine survives cancellation while a current controller owns Radio.
    quarantine.store(true, core::sync::atomic::Ordering::Release);
    retire_host();
    let mut radio = radio.lock().await;
    radio.fail_station_data();
    // A previous wait_publish may have held Radio and published after our first
    // lookup. This lookup under its lock fences that final old publication.
    retire_host();
    radio
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryError {
    Busy,
    Exhausted,
    Transport(super::bmi::BmiError),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryScheduled {
    pub attempt: u8,
}

static RESTART: super::restart::Gate = super::restart::Gate::new();
static LAST_RECOVERY: IrqSafeSpinLock<Option<super::restart::Outcome>> = IrqSafeSpinLock::new(None);

/// Firmware crash reported by the PCIe owner's service (Linux
/// `ath10k_pci_fw_dump_work` -> `ath10k_core_start_recovery`). One supervisor
/// runs at a time; it drives [`recover`] and records the outcome.
pub(in crate::ath10k) fn firmware_crashed() {
    if !RESTART.request() {
        return;
    }
    let _ = writeln!(
        narf_console::Writer,
        "  ath10k: firmware crashed (count {}), restarting",
        RESTART.crashes()
    );
    narf_scheduler::spawn(async {
        let delay = super::restart::BUSY_DELAY_MS * 1_000_000;
        let outcome = super::restart::supervise(
            recover,
            || narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(delay)),
            super::restart::BUSY_RETRIES,
        )
        .await;
        let _ = writeln!(
            narf_console::Writer,
            "  ath10k: automatic recovery {:?}",
            outcome
        );
        *LAST_RECOVERY.lock() = Some(outcome);
        RESTART.complete();
    });
}

/// Firmware crashes observed this boot (`fw_crash_counter`).
pub fn firmware_crash_count() -> u32 {
    RESTART.crashes()
}

/// Outcome of the most recent automatic recovery, if any.
pub fn last_automatic_recovery() -> Option<super::restart::Outcome> {
    *LAST_RECOVERY.lock()
}

/// Schedule fresh chip reset, authenticated ROM provisioning and a new runtime
/// interface. Three attempts per boot bound permanently pinned old DMA.
/// Success reports scheduling, not readiness, RF quiescence or DMA reclamation.
pub async fn recover() -> Result<RecoveryScheduled, RecoveryError> {
    let mut session = SESSION.lock().await;
    let owner = session.as_mut().ok_or(RecoveryError::Busy)?;
    let attempt = {
        let mut attempts = RECOVERY_ATTEMPTS.lock();
        if *attempts >= 3 {
            return Err(RecoveryError::Exhausted);
        }
        *attempts += 1;
        *attempts
    };
    let restart = retire_owner(owner)
        .await
        .map_err(RecoveryError::Transport)?;
    // A retired transport's Drop performs no hardware access and preserves all
    // old mappings. A late old firmware/CE write can only hit permanently pinned DMA.
    *session = None;
    let revision = clear_generation().ok_or(RecoveryError::Busy)?;
    narf_scheduler::spawn(boot_task(
        restart.device,
        restart.cap,
        restart.mmio,
        restart.hardware,
        revision,
    ));
    Ok(RecoveryScheduled { attempt })
}

/// Retire whichever generation the session holds (host interface first for
/// a radio), with the DMA-stop proof of `boot/recovery.rs`.
async fn retire_owner(
    owner: &mut DriverSession,
) -> Result<super::boot::Restart, super::bmi::BmiError> {
    match owner {
        DriverSession::Boot(owner) => owner.bmi.transport.retire_for_restart(),
        DriverSession::Runtime(owner) => owner.htc.transport.retire_for_restart(),
        DriverSession::Wmi(owner) => owner.wmi.htc.transport.retire_for_restart(),
        DriverSession::Htt(owner) => owner.htt.wmi.htc.transport.retire_for_restart(),
        DriverSession::Radio(owner) => {
            let mut radio = retire_radio(&owner.radio, &owner.quarantine, || {
                super::interface::retire(&owner.radio);
            })
            .await;
            radio.htt.wmi.htc.transport.retire_for_restart()
        }
    }
}

static PARKED: IrqSafeSpinLock<Option<(super::boot::Restart, u32)>> = IrqSafeSpinLock::new(None);
static SUSPEND_PINNED: IrqSafeSpinLock<u8> = IrqSafeSpinLock::new(0);

/// System suspend without WoWLAN (`pm.rs`): retire the live generation and
/// park the function identity for [`resume`]. A refusal leaves it usable.
pub async fn suspend() -> Result<(), super::pm::SuspendError> {
    let mut session = SESSION.lock().await;
    let facts = super::pm::Facts {
        device: CONTROLLER.lock().is_some(),
        session: session.is_some(),
        restarting: RESTART.restarting(),
        pinned: *SUSPEND_PINNED.lock(),
    };
    if super::pm::plan(facts)? == super::pm::Plan::Nothing {
        return Ok(());
    }
    let owner = session.as_mut().ok_or(super::pm::SuspendError::Busy)?;
    let parked = retire_owner(owner)
        .await
        .map_err(super::pm::SuspendError::Failed)?;
    *session = None;
    if !parked.reclaimable {
        *SUSPEND_PINNED.lock() += 1;
    }
    let revision = clear_generation().ok_or(super::pm::SuspendError::Busy)?;
    *PARKED.lock() = Some((parked, revision));
    let _ = writeln!(
        narf_console::Writer,
        "  ath10k: suspended (generation retired)"
    );
    Ok(())
}

/// `ath10k_pci_resume` + `ath10k_start`: clear config 0x41 and schedule a
/// fresh-ROM boot of the parked function. `false` when nothing was parked.
pub fn resume() -> bool {
    let Some((parked, revision)) = PARKED.lock().take() else {
        return false;
    };
    let (cap, device) = (parked.cap, parked.device);
    let read =
        crate::qualcomm_pci::invoke(&cap, || narf_bus::pci::read_config32(&cap, &device, 0x40));
    if let Ok(Ok(value)) = read {
        if let Some(cleared) = super::pm::retry_timeout(value) {
            let _ = crate::qualcomm_pci::invoke(&cap, || {
                narf_bus::pci::write_config32(&cap, &device, 0x40, cleared)
            });
        }
    }
    narf_scheduler::spawn(boot_task(
        parked.device,
        parked.cap,
        parked.mmio,
        parked.hardware,
        revision,
    ));
    true
}

/// Clear per-generation controller facts; returns the chip revision.
fn clear_generation() -> Option<u32> {
    let mut controller = CONTROLLER.lock();
    let controller = controller.as_mut()?;
    controller.target_info = None;
    controller.boot_error = None;
    controller.firmware_prepared = None;
    controller.firmware_error = None;
    controller.htc_ready = None;
    controller.runtime_error = None;
    controller.wmi_ready = None;
    controller.wmi_error = None;
    controller.htt_ready = None;
    controller.htt_error = None;
    controller.scan_ready = None;
    controller.scan_error = None;
    controller.station_prepared = None;
    controller.station_error = None;
    Some(controller.chip_id_rev)
}

async fn activate_runtime(
    mut boot: BootSession,
    hardware: HwRev,
) -> (DriverSession, Result<HtcReady, super::control::Error>) {
    let handoff = async {
        boot.bmi.transport.prepare_hif()?;
        boot.bmi.done().await
    }
    .await;
    if let Err(error) = handoff {
        return (DriverSession::Boot(boot), Err(error.into()));
    }
    let mut runtime = RuntimeSession {
        htc: super::control::Session::new(boot.bmi.transport, hardware),
        image: boot.image,
        profile: boot.profile,
    };
    let ready = runtime.htc.start().await.map(|()| HtcReady {
        wmi_endpoint: runtime.htc.wmi,
        htt_endpoint: runtime.htc.htt,
        credit_size: runtime.htc.credit_size,
    });
    (DriverSession::Runtime(runtime), ready)
}

async fn initialize_wmi(
    owner: DriverSession,
    hardware: HwRev,
) -> (
    DriverSession,
    Result<super::wmi_boot::Ready, super::wmi_boot::Error>,
) {
    let DriverSession::Runtime(runtime) = owner else {
        return (owner, Err(super::wmi_boot::Error::Failed));
    };
    let dialect = match super::wmi_boot::Dialect::from_version(runtime.image.wmi) {
        Ok(dialect) => dialect,
        Err(error) => return (DriverSession::Runtime(runtime), Err(error)),
    };
    let mut owner = WmiSession {
        wmi: super::wmi_boot::Runtime::new(runtime.htc, dialect, hardware, runtime.image.features),
        image: runtime.image,
        profile: runtime.profile,
    };
    let result = owner.wmi.start().await;
    (DriverSession::Wmi(owner), result)
}

/// PCI driver match registration. One entry per supported device id,
/// each with a unique `name` so the bus registry doesn't collapse them.
pub fn register_pci_driver() {
    for &(vendor, device) in ALL_PCI_MATCHES {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(vendor, device),
            kind: narf_bus::MatchKind::VendorDevice { vendor, device },
            probe,
        });
    }
}

async fn initialize_htt(
    owner: DriverSession,
    hardware: HwRev,
) -> (
    DriverSession,
    Result<super::htt_runtime::Ready, super::htt_runtime::Error>,
) {
    let DriverSession::Wmi(wmi) = owner else {
        return (owner, Err(super::htt_runtime::Error::Failed));
    };
    let config = match super::htt_runtime::Config::new(
        hardware,
        wmi.image.wmi,
        wmi.image.htt,
        wmi.image.features,
    ) {
        Ok(config) => config,
        Err(error) => return (DriverSession::Wmi(wmi), Err(error)),
    };
    let mut runtime = HttSession {
        htt: super::htt_runtime::Runtime::new(wmi.wmi, config),
        image: wmi.image,
        profile: wmi.profile,
    };
    let ready = runtime.htt.start().await;
    (DriverSession::Htt(runtime), ready)
}

async fn initialize_radio(
    owner: DriverSession,
) -> (
    DriverSession,
    Result<super::wmi_runtime::ScanReady, super::wmi_runtime::Error>,
) {
    let DriverSession::Htt(htt) = owner else {
        return (owner, Err(super::wmi_runtime::Error::Failed));
    };
    let dialect = match super::wmi_boot::Dialect::from_version(htt.image.wmi) {
        Ok(dialect) => dialect,
        Err(error) => {
            return (
                DriverSession::Htt(htt),
                Err(super::wmi_runtime::Error::Wmi(error)),
            )
        }
    };
    let mut radio = super::wmi_runtime::Radio::new(htt.htt, dialect, htt.image.features);
    let result = radio.start_from_hardware().await;
    let owner = RadioSession {
        quarantine: alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false)),
        radio: alloc::sync::Arc::new(narf_lib::mutex::Mutex::new(radio)),
        image: htt.image,
        profile: htt.profile,
    };
    (DriverSession::Radio(alloc::boxed::Box::new(owner)), result)
}

/// Receive-only native scan over the retained HTC/WMI/HTT owner. The caller
/// supplies centre frequencies in MHz from the configured hardware channels.
/// This diagnostic API grants neither station TX nor interface registration.
/// Dropping this future closes further operations until a full owned reset.
pub async fn scan_passive(
    frequencies: &[u16],
) -> Result<super::wmi_runtime::ScanReport, super::wmi_runtime::Error> {
    let mut session = SESSION.lock().await;
    let owner = live_radio(&mut session)?;
    let mut radio = owner.radio.lock().await;
    let result = radio.passive_scan(frequencies).await;
    if let Err(error) = &result {
        if let Some(controller) = CONTROLLER.lock().as_mut() {
            controller.scan_error = Some(*error);
        }
    }
    result
}

/// Probe up to sixteen explicit SSIDs (including an empty wildcard) on the
/// initial 2.4-GHz legacy profile. Authenticated current host policy and the
/// immutable factory CTL constrain every probe; prepared peers stay exclusive.
/// Cancellation/failure closes the retained owner until verified full reset.
pub async fn scan_active(
    frequencies: &[u16],
    ssids: &[Vec<u8>],
) -> Result<super::wmi_runtime::ScanReport, super::wmi_runtime::Error> {
    scan_active_with_ies(frequencies, ssids, &[]).await
}

/// Active scan with up to 256 bytes of complete caller probe IEs. Firmware
/// generates SSID/rates; those elements cannot be duplicated by the caller.
/// Probe content changes neither channel/power permission nor station admission.
pub async fn scan_active_with_ies(
    frequencies: &[u16],
    ssids: &[Vec<u8>],
    extra_ies: &[u8],
) -> Result<super::wmi_runtime::ScanReport, super::wmi_runtime::Error> {
    use super::wmi_runtime::Error;
    super::wmi_runtime::validate_probe_ies(extra_ies)?;
    let domain = narf_wireless::reg::db::ensure_domain().map_err(|_| Error::Unsupported)?;
    let mut session = SESSION.lock().await;
    let owner = live_radio(&mut session)?;
    let mut radio = owner.radio.lock().await;
    let plan = radio
        .prepare_active_scan(frequencies, ssids, &domain)?
        .with_extra_ies(extra_ies)?;
    let result = radio
        .active_scan(plan, || {
            narf_wireless::reg::db::get_domain().ok_or(Error::Unsupported)
        })
        .await;
    if let Err(error) = &result {
        if let Some(controller) = CONTROLLER.lock().as_mut() {
            controller.scan_error = Some(*error);
        }
    }
    result
}

/// Prepare the selected legacy/HT20/qualified HT40 context for a BSS from
/// a completed native scan, constrained by the installed authenticated host
/// regulatory policy and immutable EEPROM CTL. This sends no MLME/data frame,
/// installs no keys and publishes no interface or carrier. Ambiguous firmware
/// progress or cancellation retains the nested DMA owner until full reset.
pub async fn prepare_station(
    bssid: [u8; 6],
    frequency: u16,
) -> Result<super::wmi_runtime::PeerPrepared, super::wmi_runtime::Error> {
    let domain = narf_wireless::reg::db::ensure_domain()
        .map_err(|_| super::wmi_runtime::Error::Unsupported)?;
    let mut session = SESSION.lock().await;
    let owner = live_radio(&mut session)?;
    let quarantine = owner.quarantine.clone();
    let mut radio = owner.radio.lock().await;
    let permission = radio.station_permission(&domain, bssid, frequency)?;
    let validate = || current_station(permission, &quarantine);
    let result = radio
        .prepare_station_checked(&domain, bssid, frequency, &validate)
        .await;
    if result.is_err() {
        radio.fail_station_data();
    }
    if let Some(controller) = CONTROLLER.lock().as_mut() {
        controller.station_prepared = radio.prepared_peer();
        if let Err(error) = &result {
            controller.station_error = Some(*error);
        }
    }
    result
}

/// Exchange the initial Open-System Authentication, then Association Request,
/// over the retained native firmware/CE owner. The peer must already have been
/// prepared from a completed scan under installed host policy. Returns the
/// matching raw peer response; no firmware association, keys, NIC or controlled
/// port is claimed by this transport prerequisite. Cancellation retains DMA
/// and closes the radio until full reset.
pub async fn exchange_initial_management(
    frame: &[u8],
) -> Result<alloc::vec::Vec<u8>, super::wmi_runtime::Error> {
    let domain = narf_wireless::reg::db::ensure_domain()
        .map_err(|_| super::wmi_runtime::Error::Unsupported)?;
    let mut session = SESSION.lock().await;
    let owner = live_radio(&mut session)?;
    let quarantine = owner.quarantine.clone();
    let mut radio = owner.radio.lock().await;
    let permission = radio.retained_station_permission()?;
    let validate = || current_station(permission, &quarantine);
    let result = super::wmi_runtime::checked_policy(
        radio.exchange_initial_management(&domain, frame),
        &validate,
    )
    .await;
    if result.is_err() {
        radio.fail_station_data();
    }
    if let Some(controller) = CONTROLLER.lock().as_mut() {
        controller.station_prepared = radio.prepared_peer();
        if let Err(error) = &result {
            controller.station_error = Some(*error);
        }
    }
    result
}

/// Exchange checked legacy Open/WPA2 association and submit native peer/vdev
/// state on the already prepared physical peer. No key, port or NIC is granted.
pub async fn associate_station(
    ssid: &[u8],
    security: narf_wireless::association::SecurityMode,
    sme_ies: &[u8],
) -> Result<super::wmi_runtime::StationAssociated, super::wmi_runtime::Error> {
    let domain = narf_wireless::reg::db::ensure_domain()
        .map_err(|_| super::wmi_runtime::Error::Unsupported)?;
    let mut session = SESSION.lock().await;
    let owner = live_radio(&mut session)?;
    let quarantine = owner.quarantine.clone();
    let mut radio = owner.radio.lock().await;
    let permission = radio.retained_station_permission()?;
    let validate = || current_station(permission, &quarantine);
    let result = radio
        .associate_station_checked(&domain, ssid, security, sme_ies, &validate)
        .await;
    if result.is_err() {
        radio.fail_station_data();
    }
    if let Some(controller) = CONTROLLER.lock().as_mut() {
        controller.station_prepared = radio.prepared_peer();
        if let Err(error) = &result {
            controller.station_error = Some(*error);
        }
    }
    result
}

/// Retire the current peer and stop its station vdev with native firmware
/// correlation. This closes the retained radio permanently even on success;
/// its DMA and firmware resources still need the future full reset owner.
pub async fn disconnect_station(
) -> Result<super::wmi_runtime::StationDisconnected, super::wmi_runtime::Error> {
    let mut session = SESSION.lock().await;
    let owner = live_radio(&mut session)?;
    let mut radio = owner.radio.lock().await;
    let result = radio.disconnect_station().await;
    if let Some(controller) = CONTROLLER.lock().as_mut() {
        controller.station_prepared = radio.prepared_peer();
        if let Err(error) = &result {
            controller.station_error = Some(*error);
        }
    }
    result
}

/// Start retained Open/software-CCMP data after checked native association.
/// This grants no netdev; the caller must keep polling the retained owner.
pub async fn start_station_data(
    pmk: Option<&[u8; 32]>,
) -> Result<super::wmi_runtime::StationLink, super::wmi_runtime::Error> {
    let domain = narf_wireless::reg::db::ensure_domain()
        .map_err(|_| super::wmi_runtime::Error::Unsupported)?;
    let mut session = SESSION.lock().await;
    let owner = live_radio(&mut session)?;
    let mut radio = owner.radio.lock().await;
    let permission = radio.retained_station_permission()?;
    let quarantine = owner.quarantine.clone();
    let validate = || current_station(permission, &quarantine);
    radio
        .start_data_with_nonce_checked(
            &domain,
            pmk,
            || {
                let mut bytes = [0; 32];
                narf_crypto::try_fill_random_bytes(&mut bytes)
                    .ok()
                    .map(|()| bytes)
            },
            &validate,
        )
        .await
}

/// Submit native RTS/CTS intent only after draining the actual current packet
/// owner. Success is CE submission/current-prefix proof, not a firmware/RF ACK.
pub async fn set_station_protection(
    request: super::wmi_runtime::StationProtection,
) -> Result<super::wmi_runtime::StationProtection, super::wmi_runtime::Error> {
    let mut session = SESSION.lock().await;
    let owner = live_radio(&mut session)?;
    let quarantine = owner.quarantine.clone();
    let mut radio = owner.radio.lock().await;
    radio
        .set_station_protection(request, || {
            if quarantine.load(core::sync::atomic::Ordering::Acquire) {
                return Err(super::wmi_runtime::Error::Failed);
            }
            narf_wireless::reg::db::ensure_domain()
                .map_err(|_| super::wmi_runtime::Error::Unsupported)
        })
        .await
}

/// Submit Ethernet through the same retained RAW-mode data owner. The ID is
/// an HTT publication identity, never a fabricated firmware delivery receipt.
pub async fn transmit_ethernet(bytes: &[u8]) -> Result<u16, super::wmi_runtime::Error> {
    let domain = narf_wireless::reg::db::ensure_domain()
        .map_err(|_| super::wmi_runtime::Error::Unsupported)?;
    let mut session = SESSION.lock().await;
    let owner = live_radio(&mut session)?;
    let quarantine = owner.quarantine.clone();
    let mut radio = owner.radio.lock().await;
    let permission = radio.retained_station_permission()?;
    let validate = || current_station(permission, &quarantine);
    let result =
        super::wmi_runtime::checked_policy(radio.transmit_ethernet(&domain, bytes), &validate)
            .await;
    if result.is_err() {
        radio.fail_station_data();
    }
    result
}

/// Drive actual peer/completion/RAW RX and return admitted Ethernet only after
/// receive quiescence. This API is async; it is not a synchronous netdev hook.
pub async fn poll_ethernet(
) -> Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, super::wmi_runtime::Error> {
    let domain = narf_wireless::reg::db::ensure_domain()
        .map_err(|_| super::wmi_runtime::Error::Unsupported)?;
    let mut session = SESSION.lock().await;
    let owner = live_radio(&mut session)?;
    let quarantine = owner.quarantine.clone();
    let mut radio = owner.radio.lock().await;
    let permission = radio.retained_station_permission()?;
    let validate = || current_station(permission, &quarantine);
    let result = super::wmi_runtime::checked_policy(radio.poll_ethernet(&domain), &validate).await;
    if result.is_err() {
        radio.fail_station_data();
    }
    result
}

fn current_station(
    permission: super::regulatory::Permission,
    quarantine: &core::sync::atomic::AtomicBool,
) -> Result<(), super::wmi_runtime::Error> {
    if quarantine.load(core::sync::atomic::Ordering::Acquire) {
        return Err(super::wmi_runtime::Error::Failed);
    }
    let domain = narf_wireless::reg::db::ensure_domain()
        .map_err(|_| super::wmi_runtime::Error::Unsupported)?;
    permission.check(&domain)
}

/// Human-readable driver name keyed on the matched `(vendor, device)`.
/// Used as `PciMatch.name` + `BoundDriver.name`. Must be a `'static`
/// string — the bus registry stores it by reference.
pub const fn name_for(vendor: u16, device: u16) -> &'static str {
    match (vendor, device) {
        (ATHEROS_VENDOR, QCA988X_DEVICE_ID) => "ath10k-qca988x",
        (UBNT_VENDOR, QCA988X_UBNT_DEVICE_ID) => "ath10k-qca988x-ubnt",
        (ATHEROS_VENDOR, QCA9887_DEVICE_ID) => "ath10k-qca9887",
        (ATHEROS_VENDOR, QCA6174_DEVICE_ID) => "ath10k-qca6174",
        (ATHEROS_VENDOR, QCA6164_DEVICE_ID) => "ath10k-qca6164",
        (ATHEROS_VENDOR, QCA99X0_DEVICE_ID) => "ath10k-qca99x0",
        (ATHEROS_VENDOR, QCA9888_DEVICE_ID) => "ath10k-qca9888",
        (ATHEROS_VENDOR, QCA9984_DEVICE_ID) => "ath10k-qca9984",
        (ATHEROS_VENDOR, QCA9377_DEVICE_ID) => "ath10k-qca9377",
        (ATHEROS_VENDOR, AR9462_DEVICE_ID) => "ath10k-ar9462-reject",
        _ => "ath10k",
    }
}

/// Probe entry called by `narf-bus::driver_match` when a matching
/// `(vendor, device)` pair surfaces.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    // Resolve hw_rev from the PCI ID first so we can refuse AR9462
    // before doing any MMIO.
    let hw_rev = match HwRev::from_pci_id(device.id.vendor, device.id.device) {
        Some(HwRev::Ar9462Legacy) => {
            let _ = writeln!(
                narf_console::Writer,
                "  ath10k: AR9462 (168c:0034) is ath9k territory, skipping"
            );
            return Err(narf_bus::ProbeError::NotForThisDriver);
        }
        Some(r) => r,
        None => return Err(narf_bus::ProbeError::NotForThisDriver),
    };

    // Verify inherited DMA is parked before any MMIO. An additional
    // matched radio is parked with memory decode off, never reported bound.
    let owner = CONTROLLER
        .lock()
        .as_ref()
        .map(|controller| controller.address);
    let occupied = owner.is_some();
    crate::qualcomm_pci::park(&device, &cap, false, owner)?;
    if occupied {
        return Err(narf_bus::ProbeError::Other(
            "ath10k singleton already owns another radio",
        ));
    }

    // SAFETY: bus dispatch hands us exclusive BusDeviceCap authority
    // for this device's cfg + BARs for the lifetime of this call.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let result = unsafe { bring_up(&device, &cap, hw_rev) };
    let dev = match result {
        Ok(d) => d,
        Err(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "  ath10k: bring_up failed for {} ({:04x}:{:04x}): {:?}",
                hw_rev.short_name(),
                device.id.vendor,
                device.id.device,
                e,
            );
            return Err(narf_bus::ProbeError::BadDevice);
        }
    };

    // Log the bind. Mirrors iwlwifi's preamble — single-line summary
    // so dmesg stays readable.
    let _ = writeln!(
        narf_console::Writer,
        "  ath10k: probed {} ({:04x}:{:04x}, chip_id={:#010x} rev={})",
        hw_rev.short_name(),
        dev.vendor_id,
        dev.device_id,
        dev.chip_id_raw,
        dev.chip_id_rev,
    );
    // Exact profile selection needs the asynchronous BMI target version.
    let _ = writeln!(
        narf_console::Writer,
        "  ath10k:   firmware required at /firmware/ath10k/{}/",
        hw_rev.short_name(),
    );

    let mmio = dev.mmio_bar0;
    let revision = dev.chip_id_rev;
    let vid = dev.vendor_id;
    let did = dev.device_id;
    *CONTROLLER.lock() = Some(dev);

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(vid, did)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(vid),
        pci_did: Some(did),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    narf_scheduler::spawn(boot_task(device, cap, mmio, hw_rev, revision));

    Ok(())
}

/// Map and wake the device and read the fuse-backed chip identity.
/// No reset or DMA starts until the asynchronous boot owner takes over.
///
/// # Safety
/// Caller owns the device's BARs exclusively.
pub unsafe fn bring_up(
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
    hw_rev: HwRev,
) -> Result<Ath10kDevice, ProbeError> {
    crate::qualcomm_pci::invoke(cap, || {
        // SAFETY: forwarded exclusive BAR/config ownership. The actual
        // mapping, wake and identity accesses stay inside this invocation.
        unsafe { bring_up_live(device, cap, hw_rev) }
    })
    .map_err(|_| ProbeError::DeviceGone)?
}

unsafe fn bring_up_live(
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
    hw_rev: HwRev,
) -> Result<Ath10kDevice, ProbeError> {
    // SAFETY: caller-asserted BAR exclusivity.
    let mmio_bar0 = crate::qualcomm_pci::map_bar_control(device, cap, 0)
        .map_err(|_| ProbeError::Bar0MapFailed)?;

    let registers = hw_rev.registers().ok_or(ProbeError::LegacyChipRejected)?;
    let required = (registers.pcie_local + 12)
        .max(registers.chip_id + 4)
        .max(registers.soc_core + 24)
        .max(registers.ce_base(registers.ce_count - 1).unwrap() + 0x54);
    if mmio_bar0.len < required {
        return Err(ProbeError::BadBar);
    }
    // Force the target awake before accessing the RTC/CE windows. The
    // register offsets are relative to the per-chip PCI-local window.
    // SAFETY: probe owns the BAR and the bounds above cover this wake register.
    unsafe {
        mmio_bar0.write32(registers.pcie_local + PCIE_SOC_WAKE_ADDRESS, 1);
    }
    let on = if hw_rev == HwRev::Qca99x0 { 7 } else { 3 };
    let mut gone = false;
    let awake = narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: the BAR bounds above cover PCI-local RTC state.
            let state = unsafe { mmio_bar0.read32(registers.pcie_local + RTC_STATE_ADDRESS) };
            if state == u32::MAX {
                gone = true;
                return true;
            }
            state & RTC_STATE_V_MASK == on
        },
        Deadline::after_ms(30),
    );
    if gone {
        return Err(ProbeError::DeviceGone);
    }
    if !awake {
        return Err(ProbeError::WakeTimeout);
    }

    // Presence test — the first read of any BAR0
    // register returns all-FF if the device dropped off the link.
    // `SOC_CHIP_ID` is always present; pick it.
    let chip_id_off = soc_chip_id_address(hw_rev);
    // SAFETY: the selected full BAR-relative offset was checked above.
    let pre_reset_chip_id = unsafe { mmio_bar0.read32(chip_id_off) };
    if pre_reset_chip_id == READ_GONE_U32 {
        return Err(ProbeError::DeviceGone);
    }

    // Re-read the fuse-backed value for the operator-visible log.
    // SAFETY: same.
    let chip_id_raw = unsafe { mmio_bar0.read32(chip_id_off) };
    if chip_id_raw == READ_GONE_U32 {
        return Err(ProbeError::DeviceGone);
    }
    let rev = chip_id_rev(chip_id_raw);

    Ok(Ath10kDevice {
        address: device.addr,
        mmio_bar0,
        hw_rev,
        chip_id_raw,
        chip_id_rev: rev,
        vendor_id: device.id.vendor,
        device_id: device.id.device,
        target_info: None,
        boot_error: None,
        firmware_prepared: None,
        firmware_error: None,
        htc_ready: None,
        runtime_error: None,
        wmi_ready: None,
        wmi_error: None,
        htt_ready: None,
        htt_error: None,
        scan_ready: None,
        scan_error: None,
        station_prepared: None,
        station_error: None,
    })
}

async fn boot_task(
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    mmio: MmioRegion,
    hw: HwRev,
    revision: u32,
) {
    let result = async {
        let mut transport = super::boot::PciBoot::new(device, cap, mmio, hw)?;
        transport.power_up(revision).await?;
        let mut bmi = super::bmi::Bmi::new(transport);
        let info = bmi.target_info().await?;
        Ok::<_, super::bmi::BmiError>((bmi, info))
    }
    .await;
    match result {
        Ok((mut bmi, info)) => {
            if let Some(controller) = CONTROLLER.lock().as_mut() {
                controller.target_info = Some(info);
            }
            let prepared = async {
                let profile = super::profile::Profile::select(device.id.device, info.version)
                    .ok_or(super::firmware::Error::Unsupported)?;
                let mut files = super::firmware::RegistryFiles::wait_authority().await?;
                bmi.transport.bind_sources(files.source());
                let image = super::firmware::Image::wait_load(&mut files, profile).await?;
                let identity = super::firmware::Identity {
                    vendor: device.id.vendor,
                    device: device.id.device,
                    subsystem_vendor: device.id.subsystem_vendor,
                    subsystem_device: device.id.subsystem_id,
                };
                let variant = crate::ath11k::board::check_smbios().bdf_ext;
                let variant = core::str::from_utf8(&variant)
                    .map_err(|_| super::firmware::Error::Unsupported)?;
                super::firmware::prepare(&mut bmi, &mut files, profile, identity, variant, &image)
                    .await?;
                files.seal()?;
                let status = FirmwarePrepared {
                    directory: profile.directory,
                    api: image.api,
                    wmi_operations: image.wmi,
                    htt_operations: image.htt,
                };
                let boot = BootSession {
                    bmi,
                    image,
                    profile,
                };
                Ok::<_, super::firmware::Error>((boot, status))
            }
            .await;
            match prepared {
                Ok((boot, status)) => {
                    if let Some(controller) = CONTROLLER.lock().as_mut() {
                        controller.firmware_prepared = Some(status);
                    }
                    let _ = writeln!(
                        narf_console::Writer,
                        "  ath10k: {} api {} WMI {} HTT {} calibrated image downloaded",
                        status.directory,
                        status.api,
                        status.wmi_operations,
                        status.htt_operations
                    );
                    let (owner, ready) = activate_runtime(boot, hw).await;
                    match ready {
                        Ok(ready) => {
                            if let Some(controller) = CONTROLLER.lock().as_mut() {
                                controller.htc_ready = Some(ready);
                            }
                            let _ = writeln!(
                                narf_console::Writer,
                                "  ath10k: HTC WMI endpoint {} HTT endpoint {} ready",
                                ready.wmi_endpoint,
                                ready.htt_endpoint
                            );
                            let (owner, result) = initialize_wmi(owner, hw).await;
                            match result {
                                Ok(ready) => {
                                    if let Some(controller) = CONTROLLER.lock().as_mut() {
                                        controller.wmi_ready = Some(ready);
                                    }
                                    let (owner, result) = initialize_htt(owner, hw).await;
                                    match result {
                                        Ok(ready) => {
                                            if let Some(controller) = CONTROLLER.lock().as_mut() {
                                                controller.htt_ready = Some(ready);
                                            }
                                            let _=writeln!(narf_console::Writer,"  ath10k: HTT {}.{} with retained packet DMA; station registration pending",ready.major,ready.minor);
                                            let (owner, result) = initialize_radio(owner).await;
                                            let radio = match (&owner, &result) {
                                                (DriverSession::Radio(radio), Ok(_)) => Some((
                                                    radio.radio.clone(),
                                                    radio.quarantine.clone(),
                                                )),
                                                _ => None,
                                            };
                                            // Publish stage facts before exposing the owner to
                                            // recover(); an old task must not overwrite a new
                                            // generation's cleared diagnostics after retirement.
                                            if let Some(controller) = CONTROLLER.lock().as_mut() {
                                                match &result {
                                                    Ok(ready) => {
                                                        controller.scan_ready = Some(*ready)
                                                    }
                                                    Err(error) => {
                                                        controller.scan_error = Some(*error)
                                                    }
                                                }
                                            }
                                            *SESSION.lock().await = Some(owner);
                                            match result {
                                                Ok(ready) => {
                                                    let _=writeln!(narf_console::Writer,"  ath10k: retained passive scan vdev with {} receive-only channels; station closed",ready.channels);
                                                    if let Some((radio, quarantine)) = radio {
                                                        match super::interface::wait_publish(
                                                            radio, quarantine,
                                                        )
                                                        .await
                                                        {
                                                            Ok(_) => {
                                                                let _ = writeln!(narf_console::Writer,"  ath10k: retained legacy RAW station interface registered, carrier closed");
                                                            }
                                                            Err(error) => {
                                                                let _ = writeln!(narf_console::Writer,"  ath10k: station interface admission: {:?}",error);
                                                            }
                                                        }
                                                    }
                                                }
                                                Err(error) => {
                                                    let _=writeln!(narf_console::Writer,"  ath10k: retained passive scan setup failed: {:?}",error);
                                                }
                                            }
                                        }
                                        Err(error) => {
                                            if let Some(controller) = CONTROLLER.lock().as_mut() {
                                                controller.htt_error = Some(error);
                                            }
                                            *SESSION.lock().await = Some(owner);
                                            let _ = writeln!(
                                                narf_console::Writer,
                                                "  ath10k: retained HTT setup failed: {:?}",
                                                error
                                            );
                                        }
                                    }
                                }
                                Err(error) => {
                                    if let Some(controller) = CONTROLLER.lock().as_mut() {
                                        controller.wmi_error = Some(error);
                                    }
                                    *SESSION.lock().await = Some(owner);
                                    let _ = writeln!(
                                        narf_console::Writer,
                                        "  ath10k: retained WMI initialization failed: {:?}",
                                        error
                                    );
                                }
                            }
                        }
                        Err(error) => {
                            if let Some(controller) = CONTROLLER.lock().as_mut() {
                                controller.runtime_error = Some(error);
                            }
                            *SESSION.lock().await = Some(owner);
                            let _ = writeln!(
                                narf_console::Writer,
                                "  ath10k: retained runtime activation failed: {:?}",
                                error
                            );
                        }
                    }
                }
                Err(error) => {
                    if let Some(controller) = CONTROLLER.lock().as_mut() {
                        controller.firmware_error = Some(error.clone());
                    }
                    let _ = writeln!(
                        narf_console::Writer,
                        "  ath10k: firmware/BDF/OTP preparation failed: {:?}",
                        error
                    );
                }
            }
        }
        Err(error) => {
            if let Some(controller) = CONTROLLER.lock().as_mut() {
                controller.boot_error = Some(error);
            }
            let _ = writeln!(
                narf_console::Writer,
                "  ath10k: BMI bootstrap failed: {:?}",
                error
            );
        }
    }
}

/// Test helper — `true` if the static slot has a bound device.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Borrow the bound controller. Returns `None` if probe hasn't run.
pub fn with_controller<R>(f: impl FnOnce(&Ath10kDevice) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

/// Test-only reset of the bound slot.
#[cfg(any(test, feature = "kernel-test"))]
pub fn __reset_for_test() {
    *CONTROLLER.lock() = None;
}
