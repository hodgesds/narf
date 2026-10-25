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
mod identity;
mod initvals;
mod interface;
mod mac;
mod packet;
mod packet_native;
mod phy;
mod station;
pub use calibration::{Report as RadioCalibration, State as RadioState};
pub use identity::{BringUpError, Identity, EEPROM_4K_BYTES};
pub use phy::Prepared as BasebandPrepared;

const ATHEROS_PCI_VENDOR: u16 = 0x168c;
const ATHEROS_AR9285_DEVICE: u16 = 0x002b;

/// Retained hardware identity and calibration bytes. No netdev or packet
/// DMA is enabled until the MAC/PHY and soft-MAC runtime are implemented.
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
    let native = unsafe {
        packet_native::Native::new(
            controller._device,
            controller._cap,
            controller._mmio,
            report,
            &controller.calibration,
        )
    }?;
    mac::prepare(&native, &controller.calibration, controller.identity.mac)?;
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
    if device.id.vendor != ATHEROS_PCI_VENDOR || device.id.device != ATHEROS_AR9285_DEVICE {
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
        name: alloc::string::String::from("ath9k-ar9285"),
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
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "ath9k",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: ATHEROS_PCI_VENDOR,
            device: ATHEROS_AR9285_DEVICE,
        },
        probe,
    });
}
