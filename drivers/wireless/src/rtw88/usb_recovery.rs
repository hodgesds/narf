// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821CU USB operating reset, rejoin, runtime idle (IPS) and system
//! sleep over the asynchronous EP0/bulk backend.
//!
//! Linux 7.3-rc4 rtw88 recovers USB and PCI through the same HCI-agnostic
//! core: `main.c::rtw_fw_recovery_work` (`__fw_recovery_work` resets keys,
//! stations and vifs, then `ps.c::rtw_enter_ips` -> `rtw_core_stop` +
//! `rtw_power_off`) followed by `ieee80211_restart_hw` -> `rtw_ops_start`
//! -> `rtw_core_start` (`rtw_power_on`, firmware download, MAC/PHY init)
//! and mac80211's reconfiguration. IPS (`rtw_enter_ips`/`rtw_leave_ips`)
//! is that same stop/power-off/start pair. `usb.c::rtw_usb_disconnect`'s
//! `usb_reset_device` is removal-only and is not on any of these paths.
//!
//! Here, as `operating_reset.rs`/`rejoin.rs`/`system_pm_native.rs` do for
//! PCI: the original station is withdrawn for rebind (name/ifindex kept),
//! its owner retired with the actual bulk-receipt stop
//! (`operating_reset::retire`), the card powered off over EP0
//! (`usb::Registers::power_off`), then a fresh generation powers on, re-reads
//! the factory map (MAC must match), republishes under the kept name and
//! earns every stage again through the host-keyed (`rtw8821cu-*`) records.
//! No old station, key, peer or calibration receipt is replayed; rejoin
//! associates explicitly through `rejoin::associate_fresh` with the
//! caller's fresh credentials. An unprovisioned RTL8821CU stays unadmitted.
//!
//! System sleep: `rtw_8821cu_driver` has no `.suspend`/`.resume`, so the
//! Linux USB core (`usb/core/driver.c::usb_suspend` ->
//! `unbind_no_pm_drivers_interfaces` -> `usb_forced_unbind_intf`) unbinds
//! the driver before the device suspends and `usb_resume_complete` ->
//! `rebind_marked_interfaces` probes it fresh after resume. The park below
//! is that forced unbind (card off, owner retired) and the resume a fresh
//! generation. Linux sets `wiphy->wowlan` from `chip->wowlan_stub` for every
//! HCI (`main.c::rtw_register_hw`), so `rtw_ops_suspend` may arm WoW first,
//! but the forced unbind's `rtw_usb_disconnect` -> `usb_reset_device` then
//! resets the function: no armed WoW state survives a USB system suspend.
//! This tree advertises no C21 WoW (`wow::support` is C22-only on PCI too),
//! so the USB station never arms one.
//!
//! A failed park/unpark leaves the slot bound with its shell withdrawn
//! (fail closed); unbind or a replug starts over.
use super::{
    operating_reset::{self, Error, Retired},
    rejoin,
    runtime_idle::RuntimeIdle,
    system_pm_worker::{self, Control, Phase},
    usb_driver::{self, Generation, Origin},
};
use crate::rtl8xxxu::firmware_transport::UsbControl;
use alloc::{boxed::Box, sync::Arc};
use narf_drivers_usb::device::USBDevice;
use narf_power::device_pm::DevicePmError;
use narf_time::Deadline;
use narf_wireless::AssociateRequest;

type Station = super::interface::Device<usb_driver::Backend>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Mode {
    /// `rtw_fw_recovery_work` + `ieee80211_restart_hw` of an operating station.
    Reset,
    /// `rtw_enter_ips` of the unassociated passive station.
    Idle,
    /// The USB core's forced unbind for system sleep (any stage).
    System,
}

/// A retired, powered-off original generation awaiting its fresh one.
pub(super) struct Parked {
    device: Arc<USBDevice>,
    old: Arc<Station>,
    origin: Origin,
    name: &'static str,
    operating: bool,
    _retired: Retired,
}

/// Withdraw, retire and power off the slot's current generation. The caller
/// holds the slot's provisioning lock.
pub(super) async fn park(slot_id: u8, mode: Mode) -> Result<Parked, Error> {
    let current = usb_driver::current(slot_id).ok_or(Error::State)?;
    let (station, lifecycle) = (current.station, current.lifecycle);
    if lifecycle.removed() || station.withdrawn() {
        return Err(Error::State);
    }
    let operating = lifecycle.status().stage == super::firmware_lifecycle::Stage::StationReady;
    match mode {
        Mode::Reset if !operating => return Err(Error::State),
        // `idle_claim` freezes passive/unassociated eligibility under the
        // owner mutex and closes the admission, as PCI IPS does.
        Mode::Idle => station
            .idle_claim(|| Ok(()))
            .await
            .map_err(|_| Error::State)?,
        _ => {}
    }
    station.withdraw_for_rebind().map_err(|_| Error::State)?;
    let retired = operating_reset::retire(&station, &lifecycle).await?;
    let name = station.rebound_name().ok_or(Error::Publication)?;
    if !usb_driver::is_current(&current.device, &station) {
        return Err(Error::Removed);
    }
    super::usb::Registers::for_chip(UsbControl::new(current.device.clone()), current.origin.did)
        .map_err(|_| Error::Power)?
        .power_off()
        .await
        .map_err(|_| Error::Power)?;
    Ok(Parked {
        device: current.device,
        old: station,
        origin: current.origin,
        name,
        operating,
        _retired: retired,
    })
}

/// Power the parked function on and publish the fresh generation.
pub(super) async fn unpark(parked: Parked) -> Result<Generation, Error> {
    if !usb_driver::is_current(&parked.device, &parked.old) {
        return Err(Error::Removed);
    }
    let (backend, factory) = usb_driver::power_up(&parked.device, &parked.origin).await?;
    Generation::publish(
        &parked.device,
        Some(&parked.old),
        parked.name,
        factory,
        backend,
    )
    .map_err(|_| Error::Removed)
}

async fn restart(slot_id: u8) -> Result<Generation, Error> {
    let lock = usb_driver::provisioning(slot_id).ok_or(Error::State)?;
    let _provision = lock.lock().await;
    let parked = park(slot_id, Mode::Reset).await?;
    unpark(parked).await
}

/// `operating_reset::reset_function` for the RTL8821CU on USB `slot_id`:
/// retire the operating generation and start a fresh cold one, provisioned
/// in the background (`pci.rs::schedule_owner`). Success grants no
/// association or key replay.
pub async fn reset_usb(slot_id: u8) -> Result<(), Error> {
    let generation = restart(slot_id).await?;
    narf_scheduler::spawn(async move {
        let _ = generation.drive().await;
    });
    Ok(())
}

/// `rejoin::rejoin_function` for USB: reset, provision the fresh generation
/// once, then associate explicitly with the supplied Open/WPA2 BSS.
/// Credentials zeroize on cancellation.
pub async fn rejoin_usb(slot_id: u8, request: AssociateRequest) -> Result<(), rejoin::Error> {
    let pending = rejoin::Pending::new(request)?;
    let generation = restart(slot_id).await.map_err(rejoin::Error::Reset)?;
    let device = generation.station.clone();
    if let Err(error) = generation.provision_once().await {
        device.cancel_control();
        return Err(rejoin::Error::Provision(error));
    }
    let lock = usb_driver::provisioning(slot_id).ok_or(rejoin::Error::Generation)?;
    let _provision = lock.lock().await;
    rejoin::associate_fresh(&device, pending, || generation.current()).await
}

/// Durable USB PM worker (`system_pm_native::Native` counterpart).
pub(super) struct Native {
    slot_id: u8,
    mode: Mode,
}
pub(super) fn system(slot_id: u8) -> Native {
    Native {
        slot_id,
        mode: Mode::System,
    }
}
#[async_trait::async_trait]
impl system_pm_worker::Backend for Native {
    /// `None`: nothing was bound to park (system sleep of a withdrawn slot).
    type Parked = Option<Parked>;
    async fn prepare(&mut self) -> Result<Option<Parked>, DevicePmError> {
        let lock = usb_driver::provisioning(self.slot_id).ok_or(DevicePmError::Busy)?;
        let _provision = lock.try_lock().ok_or(DevicePmError::Busy)?;
        if self.mode == Mode::System
            && usb_driver::current(self.slot_id)
                .is_none_or(|c| c.station.withdrawn() || c.lifecycle.removed())
        {
            return Ok(None);
        }
        park(self.slot_id, self.mode)
            .await
            .map(Some)
            .map_err(|error| match error {
                Error::State => DevicePmError::Busy,
                Error::Unsupported => DevicePmError::NotImplemented,
                _ => DevicePmError::DriverError,
            })
    }
    async fn resume(&mut self, parked: Option<Parked>) -> Result<(), DevicePmError> {
        let Some(parked) = parked else {
            return Ok(());
        };
        let operating = parked.operating;
        let lock = usb_driver::provisioning(self.slot_id).ok_or(DevicePmError::DriverError)?;
        let generation = {
            let _provision = lock.lock().await;
            unpark(parked)
                .await
                .map_err(|_| DevicePmError::DriverError)?
        };
        match generation.provision_once().await {
            Ok(()) => Ok(()),
            // `system_pm_native::resume_cold`: a station that was not
            // operating before the park keeps retrying its missing
            // firmware/records rather than inventing them.
            Err(_) if !operating && generation.retryable() => {
                narf_scheduler::spawn(async move {
                    let _ = generation.drive().await;
                });
                Ok(())
            }
            Err(_) => {
                generation.abort().await;
                Err(DevicePmError::DriverError)
            }
        }
    }
}

async fn pause() {
    narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
}

/// `runtime_idle::idle_function` for the RTL8821CU on USB `slot_id`: enter
/// IPS (card off) on the actual unassociated passive station; the returned
/// handle's `resume` (or drop) powers a fresh generation on and provisions
/// it. Poll from normal executor context (not `block_on`).
pub async fn idle_usb(slot_id: u8) -> Result<RuntimeIdle, DevicePmError> {
    if usb_driver::current(slot_id).is_none() {
        return Err(DevicePmError::Busy);
    }
    let control = Control::new();
    let idle = RuntimeIdle::new(control.clone());
    narf_scheduler::spawn(system_pm_worker::run(
        Native {
            slot_id,
            mode: Mode::Idle,
        },
        control.clone(),
    ));
    let deadline = Deadline::after_ms(10_000);
    loop {
        match control.phase() {
            Phase::Suspended => return Ok(idle),
            Phase::Failed => return Err(control.error()),
            _ if deadline.expired() => return Err(DevicePmError::Busy),
            _ => pause().await,
        }
    }
}
