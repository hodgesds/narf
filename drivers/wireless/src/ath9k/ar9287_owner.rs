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
//! parked and unadmitted.
//!
//! Cold retunes (multi-channel scans, joins to another channel) follow the
//! AR9285 generation protocol (`ath9k.md` §3.5): the target channel's own
//! signed `N87A` record is loaded before the old generation is retired, the
//! retired generation's DMA stop is proven, then the same function is
//! power-on/warm-reset (`hw.c::ath9k_hw_reset`), its revision, identity and
//! factory map must match, and `phy::ar9287::prepare`, the open-loop power
//! plan and calibration repeat at the target before a fresh station
//! generation is published. The same reset follows a terminal generation
//! and system resume. HT stays AR9285-only.
use super::{
    admission, calibration,
    chips::{Chip, Revision},
    identity, interface, mac, packet, packet_native, phy, station, BringUpError, RetainedRadio,
    CLAIMED_ADDRESS, CONTROL,
};
use alloc::{boxed::Box, sync::Arc};
use core::fmt::Write as _;
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};

/// The initial primary the signed record and calibration bind (channel 1).
const PRIMARY: u16 = 2412;
/// Terminal-generation and calibration-timer poll interval (the AR9285
/// supervisor's); `calibration::ar9287::Periodic` owns the Linux
/// `ath_ani_calibrate` intervals.
const SUPERVISE_NS: u64 = 500_000_000;
/// (PCI device, unique bus-match name). `hw.h::AR9287_DEVID_PCI` and
/// `AR9287_DEVID_PCIE`.
pub(super) const DEVICES: [(u16, &str); 2] = [(0x002d, "ath9k-ar9287"), (0x002e, "ath9k-ar9287e")];

pub(super) struct Owner {
    mmio: MmioRegion,
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    revision: Revision,
    identity: identity::Identity,
    image: Box<[u8]>,
    profile: mac::Profile,
    /// Inactive preparation of the current physical generation.
    prepared: phy::ar9287::Prepared,
    /// Primary of the current generation; its record is `grant`.
    primary: u16,
    grant: Arc<admission::Grant>,
    radio: calibration::ar9287::Calibration,
    station: Option<RetainedRadio>,
    attempted: bool,
    /// Physical generation; bumped by each successful cold reset.
    generation: u32,
    removed: bool,
    /// System suspend parked the chip in FULL_SLEEP; only resume reopens it.
    suspended: bool,
    /// Retirement could not prove DMA stopped; the address stays reserved.
    pinned: bool,
}
pub(super) type Shared = Arc<Mutex<Owner>>;
static OWNER: IrqSafeSpinLock<Option<Shared>> = IrqSafeSpinLock::new(None);

/// The preparation `phy::ar9287::prepare` produces at `frequency` for this
/// owner: the INI row count depends only on the AR9287 1.1+ tables.
fn prepared_at(o: &Owner, frequency: u16) -> Result<phy::ar9287::Prepared, BringUpError> {
    Ok(phy::ar9287::Prepared {
        geometry: super::channel_width::Geometry::from_frequency(frequency)?,
        ini_writes: o.prepared.ini_writes,
    })
}

/// The signed `N87A` record keyed to `frequency` (its identity binds the
/// channel, its open-loop plan and the shared map/preparation).
fn record(o: &Owner, frequency: u16) -> Result<Arc<admission::Grant>, BringUpError> {
    let prepared = prepared_at(o, frequency)?;
    let facts = admission::Facts::new(
        &o.device.id,
        &o.revision,
        &o.identity,
        &prepared,
        &o.image,
        frequency,
    )?;
    admission::Source::Registered.load(facts)
}

/// Channels 1..=13 with a factory open-loop plan and a verified record.
fn admitted_mask(o: &Owner) -> u16 {
    (1..=13u16)
        .filter(|channel| record(o, 2407 + 5 * channel).is_ok())
        .fold(1 << ((o.primary - 2412) / 5), |mask, channel| {
            mask | 1 << (channel - 1)
        })
}

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
        revision,
        identity,
        image,
        profile,
        prepared,
        primary: PRIMARY,
        grant,
        radio: calibration::ar9287::Calibration::default(),
        station: None,
        attempted: false,
        generation: 0,
        removed: false,
        suspended: false,
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
            result = {
                let _control = CONTROL.lock().await;
                initialize(&owner).await
            };
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
    let host = calibration::Permission::from_domain_at(&domain, o.primary)?;
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
        // SAFETY: probe or the last cold reset identified this AR9287 and ran
        // its complete inactive preparation for `primary`; PCI parking was verified above and no
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
    let channel_mask = admitted_mask(o);
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
            channel_mask,
        )
    }?;
    mac::prepare_chip(&native, &o.image, mac, o.profile)?;
    let _ = native.arm_msi();
    // SAFETY: complete parked MAC/key-cache/queue preparation succeeded on
    // this same non-cloneable native adapter; prepare does not start DMA.
    let packet = unsafe { packet::Packet::prepare(native, mac) }?;
    // `channels` routes this generation's retunes to `transition`; HT40
    // requests fail closed (no AR9287 HT owner).
    let station = Arc::new(Mutex::new(station::Radio::new(
        packet.into(),
        mac,
        noise,
        station::NativeEnvironment {
            generation: o.generation,
        },
    )));
    o.station = Some(station.clone());
    Ok(station)
}

/// Driver-owned cold transition for `channels`: the retained AR9287 owner
/// is cold-reset to `frequency` only while `generation` is still current.
pub(super) fn transition(
    frequency: u16,
    generation: u32,
) -> Option<impl core::future::Future<Output = Result<(), BringUpError>> + Send + 'static> {
    let owner = OWNER.lock().clone()?;
    Some(async move {
        reset(&owner, Some(frequency), Some(generation))
            .await
            .map(|_| ())
    })
}

/// Cold generation reset (Linux `ath_reset` / `ath9k_hw_reset` with the
/// `AR_RTC` power-on + warm reset of `ath9k_hw_set_reset_reg`): `selected`
/// retunes to another primary, `None` repeats the current one (recovery
/// and resume). The target's signed record and host permission are proven
/// before the old generation is retired; its DMA stop must then be proven
/// and bus mastering must be off before the function is reset. Revision,
/// identity and the factory map must match the probe, the inactive
/// preparation must equal the record's, and calibration plus composition
/// publish a fresh generation. A failed reset leaves a fresh, un-calibrated
/// owner; old station authorities never reopen.
async fn reset(
    owner: &Mutex<Owner>,
    selected: Option<u16>,
    expected: Option<u32>,
) -> Result<calibration::ar9287::Report, BringUpError> {
    let _control = CONTROL.lock().await;
    {
        let mut o = owner.lock().await;
        if o.removed || o.pinned || o.suspended {
            return Err(BringUpError::DeviceGone);
        }
        if expected.is_some_and(|generation| generation != o.generation) {
            return Err(BringUpError::BadState);
        }
        let target = selected.unwrap_or(o.primary);
        if selected.is_some() {
            let domain =
                narf_wireless::reg::db::ensure_domain().map_err(|_| BringUpError::Policy)?;
            calibration::Permission::from_domain_at(&domain, target)?;
        }
        // An absent, unsigned or foreign record for the target never
        // retires the current generation.
        let grant = record(&o, target)?;
        if !retire(&mut o).await {
            return Err(BringUpError::BadState);
        }
        let command = identity::invoke(&o.cap, || narf_bus::pci::read_command(&o.cap, &o.device))
            .map_err(|_| BringUpError::DeviceGone)?
            .map_err(|_| BringUpError::DeviceGone)?;
        if command == u16::MAX || command & narf_bus::pci::cmd::BUS_MASTER != 0 {
            o.pinned = true;
            return Err(BringUpError::BadState);
        }
        // From here the old calibration/packet state is gone regardless of
        // outcome.
        o.radio = calibration::ar9287::Calibration::default();
        o.attempted = true;
        let mut io = identity::Registers::new(o.mmio, o.cap);
        let (revision, identity, image) = identity::identify_chip(&mut io, Chip::Ar9287)?;
        if revision != o.revision || identity != o.identity || image != o.image {
            return Err(BringUpError::BadIdentity);
        }
        let prepared = phy::ar9287::prepare(&mut io, &revision, &identity, &image, target)?;
        if prepared != prepared_at(&o, target)? {
            return Err(BringUpError::BadState);
        }
        o.prepared = prepared;
        o.primary = target;
        o.grant = grant;
        o.generation = o.generation.checked_add(1).ok_or(BringUpError::BadState)?;
        o.attempted = false;
    }
    initialize(owner).await
}

/// Rejoin supervisor and `link.c::ath_ani_calibrate` cadence. A terminal station generation (disassociation, link loss, fatal
/// interrupt or failed DMA) is followed by a cold generation reset into a
/// fresh passive station, exactly as the AR9285 supervisor does; a pinned
/// or removed owner is never followed. Every tick the live station runs the
/// due `ar9002_hw_calibrate` steps: short IQ per-calibrations while not
/// `caldone`, the 20 min `ath9k_hw_reset_calvalid` restart, and every
/// `ATH_LONG_CALINTERVAL` the NF history/load/restart plus
/// `ar9287_hw_olc_temp_compensation` (PA offset calibration is
/// AR9285/AR9271 only; ADC DC is an HT40 per-calibration and this owner is
/// 20 MHz). A failed calibration closes the generation, which is then reset.
async fn supervise(owner: Shared) {
    let mut failures = 0u32;
    loop {
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(SUPERVISE_NS)).await;
        let station = {
            let o = owner.lock().await;
            if o.removed || o.pinned {
                return;
            }
            if o.suspended {
                continue;
            }
            match o.station.clone() {
                Some(station) => station,
                None => continue,
            }
        };
        let terminal = {
            let Some(mut radio) = station.try_lock() else {
                continue;
            };
            if radio.terminal() {
                true
            } else {
                // The native periodic owner decides which of the long,
                // short and restart calibrations are due at this tick.
                match radio.long_calibration() {
                    Ok(_) | Err(station::Error::Transport(packet::Error::Busy)) => {}
                    Err(error) => {
                        // The generation is now closed; the next tick resets.
                        let _ = writeln!(
                            narf_console::Writer,
                            "ath9k: AR9287 periodic calibration closed: {:?}",
                            error
                        );
                    }
                }
                false
            }
        };
        if !terminal {
            continue;
        }
        drop(station);
        match reset(&owner, None, None).await {
            Ok(_) => {
                failures = 0;
                let generation = owner.lock().await.generation;
                let _ = writeln!(
                    narf_console::Writer,
                    "ath9k: AR9287 station generation {} published after reset",
                    generation
                );
            }
            Err(error) => {
                failures += 1;
                let _ = writeln!(
                    narf_console::Writer,
                    "ath9k: AR9287 generation reset closed: {:?}",
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

/// `ath_pci_remove`: withdraw, stop and reclaim DMA, then release the
/// singleton address; an unproven stop keeps it reserved.
pub(super) fn remove(device: BusDevice, _cap: Cap<BusDeviceCap, Write>) {
    let Some(owner) = OWNER.lock().clone() else {
        return;
    };
    narf_scheduler::spawn(async move {
        let _control = CONTROL.lock().await;
        let mut o = owner.lock().await;
        if o.device.addr != device.addr {
            return;
        }
        o.removed = true;
        let reclaimed = retire(&mut o).await;
        // ieee80211_unregister_hw: the netdev leaves with the device.
        interface::unpublish();
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

/// `ath_pci_suspend`: retire the station and its DMA, then FULL_SLEEP. A
/// generation reset in flight holds `CONTROL` and reports Busy.
pub(super) fn pm_suspend() -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    use narf_power::device_pm::DeviceSuspendError;
    let _control = CONTROL.try_lock().ok_or(DeviceSuspendError::Busy)?;
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
    // No later initialization reuses this calibration or generation; only
    // resume's generation reset re-identifies the chip.
    o.radio = calibration::ar9287::Calibration::default();
    o.attempted = true;
    o.suspended = true;
    identity::sleep(o.mmio, o.cap, None).map_err(|_| DeviceSuspendError::DriverError)
}

/// `pci.c::ath_pci_resume`: re-disable PCI RETRY_TIMEOUT (config 0x41) that
/// suspend reset, then a generation reset (power-on reset, identical
/// revision/identity/map, INI/PLL/RF and board values, AR9287 TX power,
/// calibration) republishes the station at the retained primary.
pub(super) fn pm_resume() -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    use narf_power::device_pm::DeviceSuspendError;
    let Some(owner) = OWNER.lock().clone() else {
        return Ok(());
    };
    {
        let mut o = owner.try_lock().ok_or(DeviceSuspendError::Busy)?;
        if !o.suspended || o.removed {
            return Ok(());
        }
        let (cap, device) = (o.cap, o.device);
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
        o.suspended = false;
    }
    narf_scheduler::spawn(async move {
        if let Err(error) = reset(&owner, None, None).await {
            let _ = writeln!(
                narf_console::Writer,
                "ath9k: AR9287 resume reset closed: {:?}",
                error
            );
        }
    });
    Ok(())
}
