// SPDX-License-Identifier: GPL-2.0-or-later
//! AR9285 reset/EEPROM, inactive INI/PLL/RF and signed-policy calibration.
//! Linux ath9k is the reference. The one-shot selected-channel analog/AGC/IQ owner
//! retains partial attempts through native DMA, host RSNA and station service.

use alloc::sync::Arc;
use core::fmt::Write as _;
use narf_bus::{BusAddr, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};

mod admission;
mod ar5008_owner;
mod ar9003;
mod ar9280_owner;
mod ar9287_owner;
mod ar9300_owner;
mod calibration;
mod channel_width;
mod channels;
mod chips;
mod descriptor;
mod ht;
mod ht40;
mod identity;
mod idle;
mod initvals;
mod initvals_ar5008;
mod initvals_ar9280;
mod initvals_ar9287;
mod interface;
mod irq;
mod mac;
mod packet;
mod packet_native;
mod pcie_pm;
mod periodic;
mod phy;
mod ps;
mod qos;
mod rates;
mod rx_ba;
mod station;
mod tx_ba;
pub use calibration::{Report as RadioCalibration, State as RadioState};
pub use ht::Request as Ht20QualificationRequest;
pub use ht40::Request as Ht40QualificationRequest;
pub use identity::{BringUpError, Identity, EEPROM_4K_BYTES};
pub use idle::{
    set as set_idle_full_sleep, status as idle_full_sleep_status, wake_use as acquire_idle_wake,
    Error as IdlePowerError, State as IdlePowerState, Status as IdlePowerStatus,
    WakeGuard as IdleWakeGuard,
};
pub use periodic::Request as PeriodicCalibrationRequest;
pub use phy::Prepared as BasebandPrepared;
pub use ps::Request as PowerSaveQualificationRequest;
pub use qos::Request as QosQualificationRequest;
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
    wide: Option<Arc<ht40::Grant>>,
    wide_report: Option<calibration::wide::WideReport>,
    station: Option<RetainedRadio>,
    /// Pins this original physical generation against idle FULL_SLEEP until
    /// its actual native DMA owner has reached terminal retirement.
    station_use: Option<IdleWakeGuard>,
    packet_attempted: bool,
    /// Physical generation; bumped by each successful reset.
    generation: u32,
    /// A retired generation could not prove DMA quiescence: its mappings stay
    /// pinned and the function may still master, so no successor may start.
    pinned: bool,
    /// System suspend parked the chip in FULL_SLEEP; only resume reopens it.
    suspended: bool,
    /// Device-local D0 workarounds were enabled by upstream ASPM policy.
    /// Retain the matching D3 obligation if platform policy later changes.
    pcie_aspm: bool,
}

impl Ath9k {
    /// Factual optional complete-program calibration request; this metadata
    /// grants no periodic writes, emission, clock or board measurement claim.
    pub fn periodic_calibration_request(&self) -> Result<PeriodicCalibrationRequest, BringUpError> {
        self.station
            .as_ref()
            .and_then(|radio| radio.try_lock())
            .and_then(|radio| radio.periodic_request())
            .ok_or(BringUpError::BadState)
    }
    /// Factual four-AC/eight-TID QoS request; no emission grant.
    pub fn qos_qualification_request(&self) -> Result<QosQualificationRequest, BringUpError> {
        self.station
            .as_ref()
            .and_then(|r| r.try_lock())
            .and_then(|r| r.qos_request())
            .ok_or(BringUpError::BadState)
    }
    /// Factual sender-BA qualification request; no emission or agreement grant.
    pub fn tx_ba_qualification_request(&self) -> Result<TxBaQualificationRequest, BringUpError> {
        self.station
            .as_ref()
            .and_then(|r| r.try_lock())
            .and_then(|r| r.tx_ba_request())
            .ok_or(BringUpError::BadState)
    }
    /// Factual bounded variable-member sender request; v4 is distinct from
    /// accepted two-member records and grants no emission or agreement.
    pub fn tx_aggregate_qualification_request(
        &self,
    ) -> Result<TxBaQualificationRequest, BringUpError> {
        self.station
            .as_ref()
            .and_then(|radio| radio.try_lock())
            .and_then(|radio| radio.tx_aggregate_request())
            .ok_or(BringUpError::BadState)
    }
    /// Factual optional NETWORK_SLEEP full-program request; no power-state
    /// transition, AP notice or key authority is granted by this metadata.
    pub fn power_save_qualification_request(
        &self,
    ) -> Result<PowerSaveQualificationRequest, BringUpError> {
        self.station
            .as_ref()
            .and_then(|radio| radio.try_lock())
            .and_then(|radio| radio.ps_request())
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
    /// Factual full20/40 request for one exact extension; no RF grant.
    pub fn ht40_qualification_request(
        &self,
        secondary: u8,
    ) -> Result<Ht40QualificationRequest, BringUpError> {
        if let Some(grant) = &self.wide {
            return if grant.geometry().secondary() == Some(secondary) {
                Ok(grant.request())
            } else {
                Err(BringUpError::Policy)
            };
        }
        let primary = ((self.baseband.reference_frequency - 2407) / 5) as u8;
        let width = if secondary == primary.checked_add(4).ok_or(BringUpError::Policy)? {
            channel_width::Width::FortyAbove
        } else if primary >= 5 && secondary == primary - 4 {
            channel_width::Width::FortyBelow
        } else {
            return Err(BringUpError::Policy);
        };
        let geometry = channel_width::Geometry::new(primary, width)?;
        let base = self
            .station
            .as_ref()
            .and_then(|r| r.try_lock())
            .and_then(|r| r.ht_grant())
            .ok_or(BringUpError::BadState)?;
        ht40::Facts::new(
            self._device,
            self.identity,
            self.baseband,
            self.radio.report().ok_or(BringUpError::BadState)?,
            &self.calibration,
            base,
            geometry,
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
    pub fn generation(&self) -> u32 {
        self.generation
    }
}

type NativeRadio = station::Radio<
    packet_native::Native,
    station::NativeEnvironment,
    station::Dispatch<packet_native::Native>,
>;
type RetainedRadio = Arc<Mutex<NativeRadio>>;

struct Retained {
    state: Mutex<Ath9k>,
    idle: Arc<idle::Owner>,
    /// Set by device removal before its teardown waits for the state lock;
    /// every later initialization or reset of this owner fails closed.
    removed: core::sync::atomic::AtomicBool,
}
static CLAIMED_ADDRESS: IrqSafeSpinLock<Option<BusAddr>> = IrqSafeSpinLock::new(None);
static CONTROLLER: IrqSafeSpinLock<Option<Arc<Retained>>> = IrqSafeSpinLock::new(None);
/// Serialize whole physical initialize/reset/retune generations. No IRQ
/// disabling guard spans calibration or packet-retirement waits.
static CONTROL: Mutex<()> = Mutex::new(());

pub fn with_controller<R>(callback: impl FnOnce(&Ath9k) -> R) -> Option<R> {
    let owner = { CONTROLLER.lock().clone() }?;
    let controller = owner.state.try_lock()?;
    Some(callback(&controller))
}

fn wide_qualification(
    base: Arc<ht::Grant>,
    geometry: channel_width::Geometry,
    generation: u32,
) -> Result<Option<Arc<ht40::Grant>>, station::Error> {
    let owner = CONTROLLER.lock().clone().ok_or(station::Error::State)?;
    let controller = owner.state.try_lock().ok_or(station::Error::Busy)?;
    if controller.generation != generation
        || controller.baseband.geometry.is_wide()
        || owner.removed.load(core::sync::atomic::Ordering::Acquire)
    {
        return Err(station::Error::State);
    }
    let facts = ht40::Facts::new(
        controller._device,
        controller.identity,
        controller.baseband,
        controller.radio.report().ok_or(station::Error::State)?,
        &controller.calibration,
        base,
        geometry,
    )
    .map_err(|_| station::Error::Profile)?;
    Ok(ht40::Source::Registered.load(facts).ok())
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
    let _use = owner
        .idle
        .use_awake(false)
        .map_err(|_| BringUpError::BadState)?;
    let _control = CONTROL.lock().await;
    initialize_owner_inner(owner).await
}
async fn initialize_owner_inner(owner: &Retained) -> Result<RadioCalibration, BringUpError> {
    let report = {
        let controller = owner.state.lock().await;
        if owner.removed.load(core::sync::atomic::Ordering::Acquire)
            || controller.pinned
            || controller.suspended
            || !owner.idle.can_initialize()
        {
            return Err(BringUpError::DeviceGone);
        }
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
    let mut controller = owner.state.try_lock().ok_or(BringUpError::BadState)?;
    let frequency = controller.baseband.reference_frequency;
    if controller.baseband.geometry.is_wide() {
        let grant = controller.wide.clone().ok_or(BringUpError::Policy)?;
        let host = channel_width::Permission::from_domain(&domain, controller.baseband.geometry)?;
        grant.check().map_err(|_| BringUpError::Policy)?;
        if host.ceiling < grant.budget() {
            return Err(BringUpError::Policy);
        }
        // Keep the exact qualified program even if host policy is relaxed;
        // fresh permission proves this lower selected budget is still valid.
        let permission = channel_width::Permission {
            ceiling: grant.budget(),
            ..host
        };
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
        let aspm = controller.pcie_aspm;
        pcie_pm::configure(
            &mut io,
            aspm,
            xe2 && controller.identity.revision >= 2,
            false,
        )?;
        let actual = {
            // SAFETY: current H3 preflight covers this exact full40 program;
            // old DMA was proven stopped and complete40 PHY preparation ran.
            let future = unsafe {
                calibration::wide::run(&mut controller.radio, &mut io, &image, permission, xe2)
            };
            let mut future = core::pin::pin!(future);
            core::future::poll_fn(|cx| {
                if narf_wireless::reg::db::snapshot()
                    .is_none_or(|domain| !permission.current_in(&domain))
                {
                    return core::task::Poll::Ready(Err(BringUpError::Policy));
                }
                grant
                    .invoke(|| Ok(core::future::Future::poll(future.as_mut(), cx)))
                    .unwrap_or(core::task::Poll::Ready(Err(BringUpError::Policy)))
            })
            .await?
        };
        grant
            .accept(actual)
            .map_err(|_| BringUpError::BadCalibration)?;
        controller.wide_report = Some(actual);
        return Ok(actual.report);
    }
    let permission = calibration::Permission::from_domain_at(&domain, frequency)?;
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
    let aspm = controller.pcie_aspm;
    pcie_pm::configure(
        &mut io,
        aspm,
        xe2 && controller.identity.revision >= 2,
        false,
    )?;
    // SAFETY: the retained native probe identified this single-chain AR9285,
    // completed full INI/modal/detector preparation, and never allocated or
    // published packet DMA. Current PCI parking was verified above; an async
    // mutex, rather than an IRQ-disabling guard, serializes the full attempt.
    let future = unsafe { controller.radio.run(&mut io, &image, permission, xe2) };
    if frequency == 2412 {
        future.await
    } else {
        let mut future = core::pin::pin!(future);
        core::future::poll_fn(|cx| {
            if narf_wireless::reg::db::snapshot().is_none_or(|d| !permission.current_in(&d)) {
                return core::task::Poll::Ready(Err(BringUpError::Policy));
            }
            core::future::Future::poll(future.as_mut(), cx)
        })
        .await
    }
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
    let native = if controller.baseband.geometry.is_wide() {
        let grant = controller.wide.clone().ok_or(packet::Error::State)?;
        let actual = controller.wide_report.ok_or(packet::Error::State)?;
        // SAFETY: same sole calibrated function, checked full40 receipt and
        // current source; no native packet DMA was allocated or published.
        unsafe {
            packet_native::Native::new_wide(
                controller._device,
                controller._cap,
                controller._mmio,
                &controller.calibration,
                grant,
                actual,
            )
        }?
    } else {
        // SAFETY: the unchanged complete20 preparation/calibration contract.
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
            native.qualify_ht(facts);
        }
        native
    };
    mac::prepare(&native, &controller.calibration, controller.identity.mac)?;
    // Optional MSI (Linux `ath9k_use_msi`); without it the owner stays polled.
    let _ = native.arm_msi();
    // SAFETY: factory calibration and complete parked MAC/key-cache/queue
    // preparation succeeded on this same non-cloneable native adapter. Probe
    // never published packet DMA; prepare allocates but does not start DMA.
    let packet = unsafe { packet::Packet::prepare(native, controller.identity.mac) }?;
    let station_use = owner
        .idle
        .use_awake(true)
        .map_err(|_| packet::Error::State)?;
    let station = Arc::new(Mutex::new(station::Radio::new(
        packet.into(),
        controller.identity.mac,
        report.noise_dbm,
        station::NativeEnvironment {
            generation: controller.generation,
        },
    )));
    // The exact native owner is retained before packet start or NIC exposure.
    // Interface/control/drain callers clone only this same Arc.
    controller.station = Some(station.clone());
    controller.station_use = Some(station_use);
    Ok(station)
}

/// Retire the current station generation: withdraw its interface, stop the
/// packet owner and require the Linux-sequenced DMA-stop proof. An owner
/// that never published a station has nothing to reclaim.
async fn retire_generation(controller: &mut Ath9k) -> bool {
    let Some(station) = controller.station.take() else {
        return true;
    };
    let reclaimed = idle::retire_station(&station, &mut controller.station_use, || {
        interface::retire(&station);
    })
    .await;
    if !reclaimed {
        controller.pinned = true;
    }
    reclaimed
}

/// Native generation reset (Linux `ath_reset` / `ath9k_hw_reset` with
/// `AR_RTC` power-on + warm reset): retire the old generation, and only after
/// its DMA was proven quiescent cold-reset the same function, re-read and
/// require the identical factory EEPROM image and identity, reprogram the
/// INI/PLL/RF tables and calibrate and publish a fresh station generation.
pub async fn reset_radio() -> Result<RadioCalibration, BringUpError> {
    let owner = { CONTROLLER.lock().clone() }.ok_or(BringUpError::BadState)?;
    reset_owner(&owner).await
}
async fn reset_owner(owner: &Retained) -> Result<RadioCalibration, BringUpError> {
    reset_owner_at(owner, None, None).await
}
async fn reset_owner_at(
    owner: &Retained,
    selected: Option<u16>,
    expected: Option<u32>,
) -> Result<RadioCalibration, BringUpError> {
    let selected = selected
        .map(channel_width::Geometry::from_frequency)
        .transpose()?;
    reset_owner_geometry(owner, selected, expected, None).await
}
async fn reset_owner_geometry(
    owner: &Retained,
    selected: Option<channel_width::Geometry>,
    expected: Option<u32>,
    wide: Option<Arc<ht40::Grant>>,
) -> Result<RadioCalibration, BringUpError> {
    let _use = owner
        .idle
        .use_awake(false)
        .map_err(|_| BringUpError::BadState)?;
    let _control = CONTROL.lock().await;
    let geometry = {
        let controller = owner.state.lock().await;
        if expected.is_some_and(|generation| generation != controller.generation) {
            return Err(BringUpError::BadState);
        }
        // Recovery/resume deliberately return to a new actual20 generation;
        // association and keys are already lost at this full reset boundary.
        let geometry = selected.unwrap_or(controller.baseband.geometry.twenty());
        if selected.is_some() && !geometry.is_wide() {
            let domain =
                narf_wireless::reg::db::ensure_domain().map_err(|_| BringUpError::Policy)?;
            let permission = calibration::Permission::from_domain_at(&domain, geometry.control())?;
            phy::rates::checked_plan_at(
                &controller.calibration,
                geometry.control(),
                permission.budget(),
            )?;
        }
        geometry
    };
    let result = reset_owner_geometry_inner(owner, geometry, wide).await;
    if geometry.is_wide() && result.is_err() {
        // CONTROL still belongs to this exact accepted request. This cannot
        // retune a different-generation request or bypass pinned DMA. The
        // original H3 grant never substitutes a20 hardware receipt.
        return reset_owner_geometry_inner(owner, geometry.twenty(), None).await;
    }
    result
}
async fn reset_owner_geometry_inner(
    owner: &Retained,
    geometry: channel_width::Geometry,
    wide: Option<Arc<ht40::Grant>>,
) -> Result<RadioCalibration, BringUpError> {
    {
        let mut controller = owner.state.lock().await;
        if owner.removed.load(core::sync::atomic::Ordering::Acquire)
            || controller.pinned
            || controller.suspended
        {
            return Err(BringUpError::DeviceGone);
        }
        let frequency = geometry.control();
        if geometry.is_wide() {
            let grant = wide.as_ref().ok_or(BringUpError::Policy)?;
            if grant.geometry() != geometry {
                return Err(BringUpError::Policy);
            }
            grant.check().map_err(|_| BringUpError::Policy)?;
            phy::rates::wide::wide_plan(&controller.calibration, geometry, grant.budget())?;
        } else {
            // Current target policy is checked before retiring a public
            // request and again before analog activation. Recovery still
            // retires a failed old generation even when its policy is gone.
            phy::rates::checked_plan_at(&controller.calibration, frequency, 40)?;
        }
        if !retire_generation(&mut controller).await {
            return Err(BringUpError::BadState);
        }
        let command = identity::invoke(&controller._cap, || {
            narf_bus::pci::read_command(&controller._cap, &controller._device)
        })
        .map_err(|_| BringUpError::DeviceGone)?
        .map_err(|_| BringUpError::DeviceGone)?;
        if command == u16::MAX || command & narf_bus::pci::cmd::BUS_MASTER != 0 {
            controller.pinned = true;
            return Err(BringUpError::BadState);
        }
        // From here the old calibration/packet state is gone regardless of
        // outcome; a failed reset leaves a fresh, un-calibrated owner.
        controller.radio = calibration::Calibration::default();
        controller.wide = wide.clone();
        controller.wide_report = None;
        controller.packet_attempted = true;
        let (identity, image) = identity::read(controller._mmio, controller._cap)?;
        if identity != controller.identity || image != controller.calibration {
            return Err(BringUpError::BadIdentity);
        }
        controller.baseband = if let Some(grant) = &wide {
            grant
                .invoke(|| {
                    phy::program_geometry(controller._mmio, controller._cap, &image, geometry)
                        .map_err(|_| packet::Error::State)
                })
                .map_err(|_| BringUpError::Policy)?
        } else {
            phy::program_at(controller._mmio, controller._cap, &image, frequency)?
        };
        controller.pcie_aspm = pcie_pm::restore(
            &controller._device,
            controller._cap,
            controller._mmio,
            controller.baseband.xe2_gain && controller.identity.revision >= 2,
        )?;
        controller.generation = controller
            .generation
            .checked_add(1)
            .ok_or(BringUpError::BadState)?;
        controller.packet_attempted = false;
    }
    initialize_owner_inner(owner).await
}

/// Rejoin supervisor: once a published station generation is terminal
/// (disassociation, link loss, fatal interrupt or failed DMA), reset into a
/// fresh generation so the radio can be joined again. A generation whose DMA
/// stop could not be proven stays pinned and is never followed.
async fn supervise(owner: Arc<Retained>) {
    let mut failures = 0u32;
    loop {
        core::future::poll_fn(|cx| {
            channels::poll(cx);
            idle::poll(cx);
            core::task::Poll::Ready(())
        })
        .await;
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(500_000_000)).await;
        if owner.removed.load(core::sync::atomic::Ordering::Acquire) {
            return;
        }
        let terminal = {
            let Some(controller) = owner.state.try_lock() else {
                continue;
            };
            if controller.pinned {
                return;
            }
            if !owner.idle.operational() {
                continue;
            }
            controller
                .station
                .as_ref()
                .and_then(|s| s.try_lock().map(|r| r.terminal()))
                .unwrap_or(false)
        };
        if !terminal {
            continue;
        }
        match reset_owner(&owner).await {
            Ok(_) => {
                failures = 0;
                let generation = owner.state.lock().await.generation;
                let _ = writeln!(
                    narf_console::Writer,
                    "ath9k: station generation {} published after reset",
                    generation
                );
            }
            Err(error) => {
                failures += 1;
                let _ = writeln!(
                    narf_console::Writer,
                    "ath9k: generation reset closed: {:?}",
                    error
                );
                // Bounded retries; a pinned or removed owner never resets.
                if failures >= 3
                    || matches!(error, BringUpError::DeviceGone | BringUpError::BadState)
                {
                    return;
                }
            }
        }
    }
}

/// `pci.c::ath_pci_suspend`. The station generation is retired first (as
/// mac80211 stops interfaces before PCI suspend), its DMA-stop proof is
/// required, then the chip is disabled and forced into FULL_SLEEP. A held
/// owner lock reports Busy so the orchestrator aborts; unproven DMA pins the
/// owner and fails suspend rather than powering down a mastering device.
fn pm_suspend() -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    use narf_power::device_pm::DeviceSuspendError;
    let _control = CONTROL.try_lock().ok_or(DeviceSuspendError::Busy)?;
    let Some(owner) = CONTROLLER.lock().clone() else {
        return Ok(());
    };
    if owner.removed.load(core::sync::atomic::Ordering::Acquire) {
        return Ok(());
    }
    let mut controller = owner.state.try_lock().ok_or(DeviceSuspendError::Busy)?;
    if controller.pinned {
        return Err(DeviceSuspendError::DriverError);
    }
    if let Some(station) = controller.station.clone() {
        let mut radio = station.try_lock().ok_or(DeviceSuspendError::Busy)?;
        if !owner
            .idle
            .system_block(u32::from(controller.station_use.is_some()))
        {
            return Err(DeviceSuspendError::Busy);
        }
        interface::retire(&station);
        if !radio.retire() {
            controller.pinned = true;
            return Err(DeviceSuspendError::DriverError);
        }
    } else if !owner.idle.system_block(0) {
        return Err(DeviceSuspendError::Busy);
    }
    controller.station = None;
    controller.station_use = None;
    controller.radio = calibration::Calibration::default();
    // Blocks initialization until resume re-identifies the chip.
    controller.packet_attempted = true;
    controller.suspended = true;
    let aspm = controller.pcie_aspm;
    identity::sleep(
        controller._mmio,
        controller._cap,
        aspm.then_some(controller.baseband.xe2_gain && controller.identity.revision >= 2),
    )
    .map_err(|_| DeviceSuspendError::DriverError)
}

/// `pci.c::ath_pci_resume`: re-disable PCI RETRY_TIMEOUT (config 0x41) that
/// suspend reset, then a generation reset (power-on reset, identical EEPROM,
/// INI/PLL/RF, calibration) republishes the station.
fn pm_resume() -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    use narf_power::device_pm::DeviceSuspendError;
    let Some(owner) = CONTROLLER.lock().clone() else {
        return Ok(());
    };
    {
        let mut controller = owner.state.try_lock().ok_or(DeviceSuspendError::Busy)?;
        if !controller.suspended {
            return Ok(());
        }
        let (cap, device) = (controller._cap, controller._device);
        let value = identity::invoke(&cap, || narf_bus::pci::read_config32(&cap, &device, 0x40))
            .map_err(|_| DeviceSuspendError::DriverError)?
            .map_err(|_| DeviceSuspendError::DriverError)?;
        if value & 0xff00 != 0 {
            identity::invoke(&cap, || {
                narf_bus::pci::write_config32(&cap, &device, 0x40, value & 0xffff_00ff)
            })
            .map_err(|_| DeviceSuspendError::DriverError)?
            .map_err(|_| DeviceSuspendError::DriverError)?;
        }
        controller.suspended = false;
    }
    narf_scheduler::spawn(async move {
        if let Err(error) = idle::system_resume(&owner).await {
            let _ = writeln!(
                narf_console::Writer,
                "ath9k: resume reset closed: {:?}",
                error
            );
        }
    });
    Ok(())
}

/// Linux `ath_pci_remove`: mark the owner removed before waiting, withdraw
/// the interface, stop and reclaim DMA, and only then release the singleton
/// address so a later probe can bind. An unproven stop keeps it reserved.
fn remove(device: BusDevice, _cap: Cap<BusDeviceCap, Write>) {
    let owner = { CONTROLLER.lock().clone() };
    let Some(owner) = owner else {
        return;
    };
    owner
        .removed
        .store(true, core::sync::atomic::Ordering::Release);
    owner.idle.block(true);
    narf_scheduler::spawn(async move {
        let _control = CONTROL.lock().await;
        let mut controller = owner.state.lock().await;
        if controller._device.addr != device.addr {
            return;
        }
        let reclaimed = retire_generation(&mut controller).await && !controller.pinned;
        // ieee80211_unregister_hw: the netdev leaves with the device.
        interface::unpublish();
        drop(controller);
        let mut retained = CONTROLLER.lock();
        if retained.as_ref().is_some_and(|r| Arc::ptr_eq(r, &owner)) {
            *retained = None;
        }
        drop(retained);
        if reclaimed {
            let mut claimed = CLAIMED_ADDRESS.lock();
            if *claimed == Some(device.addr) {
                *claimed = None;
            }
        }
        let _ = writeln!(
            narf_console::Writer,
            "ath9k: removed; DMA {}",
            if reclaimed {
                "reclaimed"
            } else {
                "pinned, address quarantined"
            }
        );
    });
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
    let pcie_aspm = pcie_pm::restore(
        &device,
        cap,
        mmio,
        baseband.xe2_gain && identity.revision >= 2,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
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
            wide: None,
            wide_report: None,
            station: None,
            station_use: None,
            packet_attempted: false,
            generation: 0,
            pinned: false,
            suspended: false,
            pcie_aspm,
        }),
        removed: core::sync::atomic::AtomicBool::new(false),
        idle: idle::Owner::new(),
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
                supervise(retained.clone()).await;
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
        narf_bus::register_pci_remove(name, remove);
    }
    for (device, name) in ar9287_owner::DEVICES {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name,
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: ATHEROS_PCI_VENDOR,
                device,
            },
            probe: ar9287_owner::probe,
        });
        narf_bus::register_pci_remove(name, ar9287_owner::remove);
    }
    for (device, name) in ar9280_owner::DEVICES {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name,
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: ATHEROS_PCI_VENDOR,
                device,
            },
            probe: ar9280_owner::probe,
        });
        narf_bus::register_pci_remove(name, ar9280_owner::remove);
    }
    for (device, name) in ar9300_owner::DEVICES {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name,
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: ATHEROS_PCI_VENDOR,
                device,
            },
            probe: ar9300_owner::probe,
        });
        narf_bus::register_pci_remove(name, ar9300_owner::remove);
    }
    for (device, name) in ar5008_owner::DEVICES {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name,
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: ATHEROS_PCI_VENDOR,
                device,
            },
            probe: ar5008_owner::probe,
        });
        narf_bus::register_pci_remove(name, ar5008_owner::remove);
    }
    narf_power::device_pm::register_device_pm("ath9k", pm_suspend, pm_resume);
    narf_power::device_pm::register_device_pm(
        "ath9k-ar9287",
        ar9287_owner::pm_suspend,
        ar9287_owner::pm_resume,
    );
    narf_power::device_pm::register_device_pm(
        "ath9k-ar9280",
        ar9280_owner::pm_suspend,
        ar9280_owner::pm_resume,
    );
    narf_power::device_pm::register_device_pm(
        "ath9k-ar9300",
        ar9300_owner::pm_suspend,
        ar9300_owner::pm_resume,
    );
    narf_power::device_pm::register_device_pm(
        "ath9k-ar5008",
        ar5008_owner::pm_suspend,
        ar5008_owner::pm_resume,
    );
}
