// SPDX-License-Identifier: GPL-2.0-or-later
//! AR9287 (`0x002d`/`0x002e`) probe and fixed-primary legacy station owner.
//!
//! `pci.c::ath_pci_probe` → `hw.c::ath9k_hw_init` order: the chip is
//! identified through its own revision and `ar9287_eeprom` map, prepared
//! inactive for the 20 MHz primary (`phy::ar9287::prepare`), and admitted
//! only by a signer-verified `N87A` board record bound to that exact map,
//! preparation and open-loop power plan. Calibration
//! (`calibration::ar9287`) runs under `Grant::ceiling`; the same native
//! MAC/packet/station/interface owners as AR9285 then carry a two-chain,
//! async-FIFO profile. An unprovisioned or foreign record leaves the chip
//! parked and unadmitted. Retuning, HT and generation reset stay AR9285-only.
use super::{
    admission, calibration, chips::Chip, identity, interface, mac, packet, packet_native, phy,
    station, BringUpError, RetainedRadio, CLAIMED_ADDRESS,
};
use alloc::{boxed::Box, sync::Arc};
use core::fmt::Write as _;
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};

/// The primary the signed record and calibration bind (channel 1).
const PRIMARY: u16 = 2412;
/// `ath9k.h::ATH_LONG_CALINTERVAL` (30 s) of `link.c::ath_ani_calibrate`.
const LONG_CAL_NS: u64 = 30_000_000_000;
/// (PCI device, unique bus-match name). `hw.h::AR9287_DEVID_PCI` and
/// `AR9287_DEVID_PCIE`.
pub(super) const DEVICES: [(u16, &str); 2] = [(0x002d, "ath9k-ar9287"), (0x002e, "ath9k-ar9287e")];

struct Owner {
    mmio: MmioRegion,
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    identity: identity::Identity,
    image: Box<[u8]>,
    profile: mac::Profile,
    grant: Arc<admission::Grant>,
    radio: calibration::ar9287::Calibration,
    station: Option<RetainedRadio>,
    attempted: bool,
    removed: bool,
    /// Retirement could not prove DMA stopped; the address stays reserved.
    pinned: bool,
}
static OWNER: IrqSafeSpinLock<Option<Arc<Mutex<Owner>>>> = IrqSafeSpinLock::new(None);

fn matches(id: &narf_bus::DeviceId) -> bool {
    id.vendor == 0x168c
        && DEVICES.iter().any(|(device, _)| *device == id.device)
        && Chip::for_device(id.device) == Some(Chip::Ar9287)
}

fn bad(stage: &str, error: BringUpError) -> narf_bus::ProbeError {
    let _ = writeln!(
        narf_console::Writer,
        "  ath9k: AR9287 {} failed: {:?}",
        stage,
        error
    );
    narf_bus::ProbeError::BadDevice
}

pub(super) fn probe(
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    if !matches(&device.id) {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    // Same singleton reservation as AR9285, before any hardware access.
    let previous = {
        let mut claimed = CLAIMED_ADDRESS.lock();
        let previous = *claimed;
        if previous.is_none() {
            *claimed = Some(device.addr);
        }
        previous
    };
    let occupied = previous.is_some();
    crate::qualcomm_pci::park(&device, &cap, false, previous)?;
    if occupied {
        return Err(narf_bus::ProbeError::Other(
            "ath9k singleton already owns another radio",
        ));
    }
    let mmio = crate::qualcomm_pci::map_bar_control(&device, &cap, 0)?;
    if mmio.len < phy::REQUIRED_BAR {
        return Err(narf_bus::ProbeError::BadDevice);
    }
    let mut io = identity::Registers::new(mmio, cap);
    let (revision, identity, image) =
        identity::identify_chip(&mut io, Chip::Ar9287).map_err(|e| bad("identification", e))?;
    let prepared = phy::ar9287::prepare(&mut io, &revision, &identity, &image, PRIMARY)
        .map_err(|e| bad("baseband preparation", e))?;
    let facts = admission::Facts::new(&device.id, &revision, &identity, &prepared, &image, PRIMARY)
        .map_err(|e| bad("admission facts", e))?;
    let request = facts.request();
    let grant = match admission::Source::Registered.load(facts) {
        Ok(grant) => grant,
        Err(_) => {
            // Unprovisioned or foreign record: stay parked and unadmitted.
            let _ = identity::disable_and_sleep(&mut io);
            let _ = writeln!(
                narf_console::Writer,
                "  ath9k: AR9287 MAC {:02x?} unadmitted; signed board record {} absent or invalid",
                identity.mac,
                request.filename
            );
            return Err(narf_bus::ProbeError::Other(
                "ath9k AR9287 board admission record absent or invalid",
            ));
        }
    };
    let profile = mac::Profile::ar9287(
        identity.rx_chainmask,
        identity.tx_chainmask,
        revision.ar9287_async_fifo(),
    );
    let _ = writeln!(
        narf_console::Writer,
        "  ath9k: AR9287 rev {} MAC {:02x?}, EEPROM {:#x}, chains {:#x}/{:#x}; admitted, calibration pending",
        revision.mac_rev,
        identity.mac,
        identity.eeprom_version,
        identity.rx_chainmask,
        identity.tx_chainmask
    );
    let (vendor, device_id) = (device.id.vendor, device.id.device);
    let owner = Arc::new(Mutex::new(Owner {
        mmio,
        device,
        cap,
        identity,
        image,
        profile,
        grant,
        radio: calibration::ar9287::Calibration::default(),
        station: None,
        attempted: false,
        removed: false,
        pinned: false,
    }));
    *OWNER.lock() = Some(owner.clone());
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("ath9k-ar9287"),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(vendor),
        pci_did: Some(device_id),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });
    narf_scheduler::spawn(async move {
        let mut result = Err(BringUpError::Policy);
        for attempt in 0..120 {
            if attempt > 0 {
                narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(500_000_000)).await;
            }
            result = initialize(&owner).await;
            if !matches!(result, Err(BringUpError::Policy)) {
                break;
            }
        }
        match result {
            Ok(report) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "ath9k: AR9287 channel1 native station published: IQ {:?} NF {:?} dBm",
                    report.iq,
                    report.measured_noise_dbm
                );
                supervise(owner).await;
            }
            Err(error) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "ath9k: AR9287 channel1 bring-up closed: {:?}",
                    error
                );
            }
        }
    });
    Ok(())
}

/// Calibrate under the signed ceiling, then compose the native owners.
async fn initialize(owner: &Mutex<Owner>) -> Result<calibration::ar9287::Report, BringUpError> {
    let domain = narf_wireless::reg::db::ensure_domain().map_err(|_| BringUpError::Policy)?;
    if narf_net::trusted_net_authority().is_none() {
        return Err(BringUpError::Policy);
    }
    let mut o = owner.lock().await;
    if o.removed || o.attempted || o.radio.state() != calibration::State::New {
        return Err(BringUpError::BadState);
    }
    let host = calibration::Permission::from_domain_at(&domain, PRIMARY)?;
    let grant = o.grant.clone();
    let permission = host.with_ceiling(grant.invoke(|| Ok(grant.ceiling(host.budget())))?);
    let command = identity::invoke(&o.cap, || narf_bus::pci::read_command(&o.cap, &o.device))
        .map_err(|_| BringUpError::DeviceGone)?
        .map_err(|_| BringUpError::DeviceGone)?;
    let mask = narf_bus::pci::cmd::BUS_MASTER
        | narf_bus::pci::cmd::MEM_SPACE
        | narf_bus::pci::cmd::INTX_DISABLE;
    if command & mask != (narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::INTX_DISABLE) {
        return Err(BringUpError::BadState);
    }
    let mut io = identity::Registers::new(o.mmio, o.cap);
    let image = o.image.clone();
    let rx = o.identity.rx_chainmask;
    let report = {
        // SAFETY: probe identified this AR9287 and ran its complete inactive
        // preparation for PRIMARY; PCI parking was verified above and no
        // packet DMA exists. The async mutex serializes the whole attempt.
        let future = unsafe { o.radio.run(&mut io, &image, rx, permission) };
        let mut future = core::pin::pin!(future);
        core::future::poll_fn(|cx| {
            if narf_wireless::reg::db::snapshot().is_none_or(|d| !permission.current_in(&d)) {
                return core::task::Poll::Ready(Err(BringUpError::Policy));
            }
            grant
                .invoke(|| Ok(core::future::Future::poll(future.as_mut(), cx)))
                .unwrap_or(core::task::Poll::Ready(Err(BringUpError::Policy)))
        })
        .await?
    };
    // The attempt is retained before any MAC mutation.
    o.attempted = true;
    let station = compose(&mut o, report).map_err(|error| {
        let _ = writeln!(
            narf_console::Writer,
            "ath9k: AR9287 native station composition closed: {:?}",
            error
        );
        BringUpError::BadState
    })?;
    drop(o);
    interface::publish(station).map_err(|error| {
        let _ = writeln!(
            narf_console::Writer,
            "ath9k: AR9287 native station publication closed: {:?}",
            error
        );
        BringUpError::BadState
    })?;
    Ok(report)
}

fn compose(
    o: &mut Owner,
    report: calibration::ar9287::Report,
) -> Result<RetainedRadio, packet::Error> {
    let noise = report.noise_dbm[0].ok_or(packet::Error::State)?;
    let mac = o.identity.mac;
    // SAFETY: same sole calibrated AR9287 function, cap and BAR; the signed
    // grant bounded calibration and no packet DMA was published.
    let native = unsafe {
        packet_native::Native::new_ar9287(
            o.device,
            o.cap,
            o.mmio,
            report,
            o.grant.clone(),
            &o.image,
            o.profile,
        )
    }?;
    mac::prepare_chip(&native, &o.image, mac, o.profile)?;
    let _ = native.arm_msi();
    // SAFETY: complete parked MAC/key-cache/queue preparation succeeded on
    // this same non-cloneable native adapter; prepare does not start DMA.
    let packet = unsafe { packet::Packet::prepare(native, mac) }?;
    // Generation 0 is never a retained AR9285 controller generation: any
    // retune or HT40 request fails closed in `channels`.
    let station = Arc::new(Mutex::new(station::Radio::new(
        packet,
        mac,
        noise,
        station::NativeEnvironment { generation: 0 },
    )));
    o.station = Some(station.clone());
    Ok(station)
}

/// `link.c::ath_ani_calibrate` long-calibration cadence for the live
/// station: `ar9002_hw_calibrate(longcal)` runs
/// `ar9287_hw_olc_temp_compensation` (PA offset calibration is AR9285/AR9271
/// only; ADC DC is an HT40 per-calibration and this owner is 20 MHz).
async fn supervise(owner: Arc<Mutex<Owner>>) {
    loop {
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(LONG_CAL_NS)).await;
        let station = {
            let o = owner.lock().await;
            if o.removed || o.pinned {
                return;
            }
            match o.station.clone() {
                Some(station) => station,
                None => return,
            }
        };
        let mut radio = station.lock().await;
        if radio.terminal() {
            let _ = writeln!(
                narf_console::Writer,
                "ath9k: AR9287 station closed; no generation reset on this profile"
            );
            return;
        }
        match radio.long_calibration() {
            Ok(_) | Err(station::Error::Transport(packet::Error::Busy)) => {}
            Err(error) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "ath9k: AR9287 long calibration closed: {:?}",
                    error
                );
            }
        }
    }
}

/// `ath_pci_remove`: withdraw, stop and reclaim DMA, then release the
/// singleton address; an unproven stop keeps it reserved.
pub(super) fn remove(device: BusDevice, _cap: Cap<BusDeviceCap, Write>) {
    let Some(owner) = OWNER.lock().clone() else {
        return;
    };
    narf_scheduler::spawn(async move {
        let mut o = owner.lock().await;
        if o.device.addr != device.addr {
            return;
        }
        o.removed = true;
        let reclaimed = retire(&mut o).await;
        drop(o);
        let mut retained = OWNER.lock();
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
            "ath9k: AR9287 removed; DMA {}",
            if reclaimed {
                "reclaimed"
            } else {
                "pinned, address quarantined"
            }
        );
    });
}

async fn retire(o: &mut Owner) -> bool {
    let Some(station) = o.station.take() else {
        return !o.pinned;
    };
    interface::retire(&station);
    let reclaimed = station.lock().await.retire();
    if !reclaimed {
        o.pinned = true;
    }
    reclaimed
}

/// `ath_pci_suspend`: retire the station and its DMA, then FULL_SLEEP. This
/// profile has no resume republish; the radio stays parked until reprobe.
pub(super) fn pm_suspend() -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    use narf_power::device_pm::DeviceSuspendError;
    let Some(owner) = OWNER.lock().clone() else {
        return Ok(());
    };
    let mut o = owner.try_lock().ok_or(DeviceSuspendError::Busy)?;
    if o.removed {
        return Ok(());
    }
    if o.pinned {
        return Err(DeviceSuspendError::DriverError);
    }
    if let Some(station) = o.station.clone() {
        let mut radio = station.try_lock().ok_or(DeviceSuspendError::Busy)?;
        interface::retire(&station);
        if !radio.retire() {
            o.pinned = true;
            return Err(DeviceSuspendError::DriverError);
        }
    }
    o.station = None;
    // No later initialization reuses this calibration or generation.
    o.attempted = true;
    identity::sleep(o.mmio, o.cap, None).map_err(|_| DeviceSuspendError::DriverError)
}

/// Nothing is republished on resume; the parked owner stays closed.
pub(super) fn pm_resume() -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    Ok(())
}
