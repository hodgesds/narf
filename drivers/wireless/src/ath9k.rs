// SPDX-License-Identifier: GPL-2.0-or-later
//! AR9285 reset/EEPROM, inactive INI/PLL/RF and signed-policy calibration.
//! Linux ath9k is the reference. The one-shot channel1 analog/AGC/IQ owner
//! retains partial attempts through native DMA, host RSNA and station service.

use alloc::sync::Arc;
use core::fmt::Write as _;
use narf_bus::{BusAddr, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};

mod calibration;
mod descriptor;
mod ht;
mod identity;
mod initvals;
mod interface;
mod irq;
mod mac;
mod packet;
mod packet_native;
mod phy;
mod rates;
mod rx_ba;
mod station;
mod tx_ba;
pub use calibration::{Report as RadioCalibration, State as RadioState};
pub use ht::Request as Ht20QualificationRequest;
pub use identity::{BringUpError, Identity, EEPROM_4K_BYTES};
pub use phy::Prepared as BasebandPrepared;
pub use rx_ba::Request as RxBaQualificationRequest;
pub use tx_ba::Request as TxBaQualificationRequest;

const ATHEROS_PCI_VENDOR: u16 = 0x168c;
const ATHEROS_AR9285_DEVICE: u16 = 0x002b;
/// AR2427 (`hw.h::AR2427_DEVID_PCIE`): AR9285 silicon with 802.11n bonded
/// out. Linux `hw.c::ath9k_hw_init` accepts it with the AR9285 reset/EEPROM
/// path and `ath9k_hw_fill_cap_info` clears `ATH9K_HW_CAP_HT` for this ID.
const ATHEROS_AR2427_DEVICE: u16 = 0x002c;
/// (PCI device, unique bus-match name, bound-driver name).
const DEVICES: [(u16, &str, &str); 2] = [
    (ATHEROS_AR9285_DEVICE, "ath9k", "ath9k-ar9285"),
    (ATHEROS_AR2427_DEVICE, "ath9k-ar2427", "ath9k-ar2427"),
];

/// Exact AR9285-silicon PCI functions; only 0x002b may reach any HT owner.
pub(crate) fn ar9285_silicon(id: &narf_bus::DeviceId) -> bool {
    id.vendor == ATHEROS_PCI_VENDOR && DEVICES.iter().any(|(device, _, _)| *device == id.device)
}

/// Retained identity, calibration and the same native MAC/packet/station owner.
#[derive(Debug)]
pub struct Ath9k {
    _mmio: MmioRegion,
    _device: BusDevice,
    _cap: Cap<BusDeviceCap, Write>,
    pub identity: Identity,
    pub baseband: BasebandPrepared,
    calibration: [u8; EEPROM_4K_BYTES],
    radio: calibration::Calibration,
    station: Option<RetainedRadio>,
    packet_attempted: bool,
}

impl Ath9k {
    /// Factual sender-BA qualification request; no emission or agreement grant.
    pub fn tx_ba_qualification_request(&self) -> Result<TxBaQualificationRequest, BringUpError> {
        self.station
            .as_ref()
            .and_then(|r| r.try_lock())
            .and_then(|r| r.tx_ba_request())
            .ok_or(BringUpError::BadState)
    }
    /// Optional recipient-BA request from the same current HT source/owner.
    pub fn rx_ba_qualification_request(&self) -> Result<RxBaQualificationRequest, BringUpError> {
        self.station
            .as_ref()
            .and_then(|radio| radio.try_lock())
            .and_then(|radio| radio.rx_ba_request())
            .ok_or(BringUpError::BadState)
    }
    /// Exact optional measured qualification request; this is no RF grant.
    pub fn ht20_qualification_request(&self) -> Result<Ht20QualificationRequest, BringUpError> {
        ht::Facts::new(
            self._device,
            self.identity,
            self.baseband,
            self.radio.report().ok_or(BringUpError::BadState)?,
            &self.calibration,
        )
        .map(|facts| facts.request())
    }
    pub fn calibration(&self) -> &[u8; EEPROM_4K_BYTES] {
        &self.calibration
    }
    pub fn radio_state(&self) -> RadioState {
        self.radio.state()
    }
    pub fn radio_calibration(&self) -> Option<RadioCalibration> {
        self.radio.report()
    }
}

type NativeRadio = station::Radio<packet_native::Native, station::NativeEnvironment>;
type RetainedRadio = Arc<Mutex<NativeRadio>>;

struct Retained {
    state: Mutex<Ath9k>,
}
static CLAIMED_ADDRESS: IrqSafeSpinLock<Option<BusAddr>> = IrqSafeSpinLock::new(None);
static CONTROLLER: IrqSafeSpinLock<Option<Arc<Retained>>> = IrqSafeSpinLock::new(None);

pub fn with_controller<R>(callback: impl FnOnce(&Ath9k) -> R) -> Option<R> {
    let owner = { CONTROLLER.lock().clone() }?;
    let controller = owner.state.try_lock()?;
    Some(callback(&controller))
}

/// Continue the same retained calibration/MAC/packet owner through native NIC
/// publication. Missing policy may be provisioned before calibration begins;
/// a completed calibration receipt can continue only before packet preparation
/// starts. Partial/failed calibration or packet work is never replayed.
pub async fn calibrate_radio() -> Result<RadioCalibration, BringUpError> {
    let owner = { CONTROLLER.lock().clone() }.ok_or(BringUpError::BadState)?;
    initialize_owner(&owner).await
}
async fn initialize_owner(owner: &Retained) -> Result<RadioCalibration, BringUpError> {
    let report = {
        let controller = owner.state.lock().await;
        match controller.radio.state() {
            RadioState::New if !controller.packet_attempted => None,
            RadioState::Ready if !controller.packet_attempted => controller.radio.report(),
            _ => return Err(BringUpError::BadState),
        }
    };
    let report = match report {
        Some(report) => report,
        None => calibrate_owner(owner).await?,
    };
    if narf_net::trusted_net_authority().is_none() {
        return Err(BringUpError::Policy);
    }
    let station = prepare_packets(owner).await.map_err(|error| {
        let _ = writeln!(
            narf_console::Writer,
            "ath9k: native packet preparation closed: {:?}",
            error
        );
        BringUpError::BadState
    })?;
    interface::publish(station).map_err(|error| {
        let _ = writeln!(
            narf_console::Writer,
            "ath9k: native station publication closed: {:?}",
            error
        );
        BringUpError::BadState
    })?;
    Ok(report)
}

pub(crate) async fn drive_scheduled<Step, StepFut, Wait, WaitFut>(
    max_attempts: usize,
    mut step: Step,
    mut wait: Wait,
) -> Result<RadioCalibration, BringUpError>
where
    Step: FnMut() -> StepFut,
    StepFut: core::future::Future<Output = Result<RadioCalibration, BringUpError>>,
    Wait: FnMut() -> WaitFut,
    WaitFut: core::future::Future<Output = ()>,
{
    let mut last_err = BringUpError::Policy;
    for attempt in 0..max_attempts {
        if attempt > 0 {
            wait().await;
        }
        match step().await {
            Ok(report) => return Ok(report),
            Err(BringUpError::Policy) => {
                last_err = BringUpError::Policy;
            }
            Err(err) => return Err(err),
        }
    }
    Err(last_err)
}
async fn calibrate_owner(owner: &Retained) -> Result<RadioCalibration, BringUpError> {
    let domain = narf_wireless::reg::db::ensure_domain().map_err(|_| BringUpError::Policy)?;
    let permission = calibration::Permission::from_domain(&domain)?;
    let mut controller = owner.state.try_lock().ok_or(BringUpError::BadState)?;
    let command = identity::invoke(&controller._cap, || {
        narf_bus::pci::read_command(&controller._cap, &controller._device)
    })
    .map_err(|_| BringUpError::DeviceGone)?
    .map_err(|_| BringUpError::DeviceGone)?;
    let mask = narf_bus::pci::cmd::BUS_MASTER
        | narf_bus::pci::cmd::MEM_SPACE
        | narf_bus::pci::cmd::INTX_DISABLE;
    if command & mask != (narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::INTX_DISABLE) {
        return Err(BringUpError::BadState);
    }
    let mut io = identity::Registers::new(controller._mmio, controller._cap);
    let image = controller.calibration;
    let xe2 = controller.baseband.xe2_gain;
    // SAFETY: the retained native probe identified this single-chain AR9285,
    // completed full INI/modal/detector preparation, and never allocated or
    // published packet DMA. Current PCI parking was verified above; an async
    // mutex, rather than an IRQ-disabling guard, serializes the full attempt.
    unsafe { controller.radio.run(&mut io, &image, permission, xe2).await }
}

async fn prepare_packets(owner: &Retained) -> Result<RetainedRadio, packet::Error> {
    let mut controller = owner.state.lock().await;
    if controller.packet_attempted || controller.station.is_some() {
        return Err(packet::Error::State);
    }
    let report = controller.radio.report().ok_or(packet::Error::State)?;
    if controller.radio.state() != RadioState::Ready {
        return Err(packet::Error::State);
    }
    // Retain the attempt before any MAC mutation. Even an allocation error
    // cannot reconstruct another transport over partially configured hardware.
    controller.packet_attempted = true;
    // SAFETY: same retained sole function/cap/BAR/factory image as the exact
    // successful calibration; this async mutex serializes all native access.
    let mut native = unsafe {
        packet_native::Native::new(
            controller._device,
            controller._cap,
            controller._mmio,
            report,
            &controller.calibration,
        )
    }?;
    if let Ok(facts) = ht::Facts::new(
        controller._device,
        controller.identity,
        controller.baseband,
        report,
        &controller.calibration,
    ) {
        // Optional qualification is resolved before any new live HT program.
        // Missing/invalid external measurements preserve the legacy profile.
        native.qualify_ht(facts);
    }
    mac::prepare(&native, &controller.calibration, controller.identity.mac)?;
    // Optional MSI (Linux `ath9k_use_msi`); without it the owner stays polled.
    let _ = native.arm_msi();
    // SAFETY: factory calibration and complete parked MAC/key-cache/queue
    // preparation succeeded on this same non-cloneable native adapter. Probe
    // never published packet DMA; prepare allocates but does not start DMA.
    let packet = unsafe { packet::Packet::prepare(native, controller.identity.mac) }?;
    let station = Arc::new(Mutex::new(station::Radio::new(
        packet,
        controller.identity.mac,
        report.noise_dbm,
        station::NativeEnvironment,
    )));
    // The exact native owner is retained before packet start or NIC exposure.
    // Interface/control/drain callers clone only this same Arc.
    controller.station = Some(station.clone());
    Ok(station)
}

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if !ar9285_silicon(&device.id) {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    // Reserve the address before any hardware access, including an attempt
    // that fails part-way through native reset/EEPROM preparation. Concurrent
    // dispatch cannot replace the retained singleton or replay uncertain state.
    let owner = {
        let mut claimed = CLAIMED_ADDRESS.lock();
        let previous = *claimed;
        if previous.is_none() {
            *claimed = Some(device.addr);
        }
        previous
    };
    let occupied = owner.is_some();
    crate::qualcomm_pci::park(&device, &cap, false, owner)?;
    if occupied {
        return Err(narf_bus::ProbeError::Other(
            "ath9k singleton already owns another radio",
        ));
    }
    let mmio = crate::qualcomm_pci::map_bar_control(&device, &cap, 0)?;
    if mmio.len < phy::REQUIRED_BAR {
        return Err(narf_bus::ProbeError::BadDevice);
    }
    let (identity, calibration) = identity::read(mmio, cap).map_err(|error| {
        let _ = writeln!(
            narf_console::Writer,
            "  ath9k: AR9285 identification failed: {:?}",
            error
        );
        narf_bus::ProbeError::BadDevice
    })?;
    let baseband = phy::program(mmio, cap, &calibration).map_err(|error| {
        let _ = writeln!(
            narf_console::Writer,
            "  ath9k: AR9285 baseband preparation failed: {:?}",
            error
        );
        narf_bus::ProbeError::BadDevice
    })?;
    let _ = writeln!(
        narf_console::Writer,
        "  ath9k: AR9285 rev {} MAC {:02x?}, EEPROM {:#x}; INI/PLL/RF registers prepared, calibration and packet runtime pending",
        identity.revision,
        identity.mac,
        identity.eeprom_version
    );
    let vendor = device.id.vendor;
    let device_id = device.id.device;
    let retained = Arc::new(Retained {
        state: Mutex::new(Ath9k {
            _mmio: mmio,
            _device: device,
            _cap: cap,
            identity,
            baseband,
            calibration,
            radio: calibration::Calibration::default(),
            station: None,
            packet_attempted: false,
        }),
    });
    *CONTROLLER.lock() = Some(retained.clone());
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(
            DEVICES
                .iter()
                .find(|(device, _, _)| *device == device_id)
                .map_or("ath9k", |(_, _, name)| *name),
        ),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(vendor),
        pci_did: Some(device_id),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });
    narf_scheduler::spawn(async move {
        match drive_scheduled(
            120,
            || initialize_owner(&retained),
            || narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(500_000_000)),
        )
        .await
        {
            Ok(report) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "ath9k: channel1 native station published: IQ {}/{} PA {:?} NF {} dBm",
                    report.iq_i,
                    report.iq_q,
                    report.pa_offset,
                    report.measured_noise_dbm
                );
            }
            Err(error) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "ath9k: channel1 calibration closed: {:?}",
                    error
                );
            }
        }
    });
    Ok(())
}

pub fn register() {
    for (device, name, _) in DEVICES {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name,
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: ATHEROS_PCI_VENDOR,
                device,
            },
            probe,
        });
    }
}
