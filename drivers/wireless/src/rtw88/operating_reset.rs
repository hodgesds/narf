// SPDX-License-Identifier: GPL-2.0-or-later
//! Original PCI function recovery using Linux rtw88's card-disable/enable
//! sequence, after native producer withdrawal and an actual DMA idle proof.
use super::{firmware_lifecycle::Stage, functions::ResetClaim, pci::Rtw88Device};
use narf_bus::{BusAddr, BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
/// Only actual original endpoint/callback retirement and native DMA proof
/// can create this one-shot precondition for the card power transition.
pub(super) struct Retired(());
pub(super) async fn retire<I: super::firmware_transport::Io + 'static>(
    interface: &alloc::sync::Arc<super::interface::Device<I>>,
    lifecycle: &super::firmware_lifecycle::Lifecycle<I>,
) -> Result<Retired, Error> {
    if !core::ptr::eq(interface.lifecycle.as_ref(), lifecycle) {
        return Err(Error::Identity);
    }
    if !lifecycle.claim_retirement() {
        return Err(Error::State);
    }
    interface.withdraw();
    interface.wait_withdrawn().await;
    if !lifecycle.remove().await {
        return Err(Error::UnprovenDma);
    }
    Ok(Retired(()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    State,
    Access,
    Removed,
    UnprovenDma,
    Power,
    Identity,
    Publication,
}
/// Retained at the original cold probe, never supplied by a reset caller.
#[derive(Clone, Copy)]
pub(super) struct Origin {
    device: BusDevice,
    authority: Cap<BusDeviceCap, Write>,
}
impl Origin {
    pub(super) fn new(device: BusDevice, authority: Cap<BusDeviceCap, Write>) -> Self {
        Self { device, authority }
    }
    fn current(&self, owner: &Rtw88Device) -> Result<(), Error> {
        if owner.bus_addr != self.device.addr || owner.device_id != self.device.id.device {
            return Err(Error::Identity);
        }
        let actual = super::pci_park::invoke(&self.authority, || {
            narf_bus::pci::read_config32(&self.authority, &self.device, 0)
        })
        .map_err(|_| Error::Access)?
        .map_err(|_| Error::Access)?;
        if actual != u32::from(self.device.id.vendor) | (u32::from(self.device.id.device) << 16) {
            return Err(Error::Identity);
        }
        Ok(())
    }
}
/// Retire the old generation and create a fresh cold firmware shell. Success
/// grants no association or credential/key replay: normal provisioning must
/// earn fresh firmware, hardware-report, calibration and policy receipts.
/// A failed/cancelled reset retains the BDF reservation in quarantine.
pub async fn reset_function(address: BusAddr) -> Result<(), Error> {
    reset_owner(address, false, true).await.map(|_| ())
}
pub(super) async fn reset_owner(
    address: BusAddr,
    rebind: bool,
    schedule: bool,
) -> Result<alloc::sync::Arc<Rtw88Device>, Error> {
    let old = super::functions::get(address).ok_or(Error::State)?;
    let _provision = old.provisioning.lock().await;
    let origin = old.reset_origin.ok_or(Error::Unsupported)?;
    let lifecycle = old
        .firmware
        .as_ref()
        .map(|f| f.lifecycle())
        .or_else(|| old.sibling.as_ref().map(|s| s.lifecycle()))
        .ok_or(Error::Unsupported)?;
    if lifecycle.status().stage != Stage::StationReady || old.interface.is_none() {
        return Err(Error::State);
    }
    origin.current(&old)?;
    let claim = ResetClaim::acquire(&old).map_err(|_| Error::State)?;
    let interface = old.interface.as_ref().ok_or(Error::Unsupported)?;
    if rebind {
        interface.withdraw_for_rebind().map_err(|_| Error::State)?;
    }
    // withdraw closes the original Admission synchronously, then waits for
    // unlocked native RX/stack callbacks before unregistering its endpoint.
    // The original lifecycle owns every old DMA allocation until quiescence.
    let retired = retire(interface, &lifecycle).await?;
    let name = if rebind {
        Some(interface.rebound_name().ok_or(Error::Publication)?)
    } else {
        None
    };
    claim.current().map_err(|_| Error::Removed)?;
    origin.current(&old)?;
    // SAFETY: this exact original BDF remains reserved by claim. The old
    // endpoint/callbacks and firmware/DMA owner have retired with real native
    // idle receipts. No other old/new config, ring, IRQ or reset producer runs.
    let fresh = unsafe {
        super::pci::bring_up_reset(&origin.device, &origin.authority, retired, &claim, name)
    }
    .map_err(|_| Error::Power)?;
    if fresh.mac != old.mac || fresh.device_id != old.device_id || fresh.bus_addr != old.bus_addr {
        return Err(Error::Identity);
    }
    origin.current(&old)?;
    claim.current().map_err(|_| Error::Removed)?;
    let fresh = alloc::sync::Arc::new(fresh);
    let interface = fresh.interface.as_ref().ok_or(Error::Unsupported)?;
    if super::interface::publish(interface.clone()).is_err() {
        interface.withdraw();
        return Err(Error::Publication);
    }
    // No await lies between this final original function/removal check and
    // generation publication. Hot removal makes claim.publish fail closed.
    if claim.publish(fresh.clone()).is_err() {
        interface.withdraw();
        return Err(Error::Removed);
    }
    if schedule {
        super::pci::schedule_owner(fresh.clone());
    }
    Ok(fresh)
}
