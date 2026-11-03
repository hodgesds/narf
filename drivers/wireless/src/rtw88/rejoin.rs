// SPDX-License-Identifier: GPL-2.0-or-later
//! Explicit fresh credentials over a confirmed reset and preserved netdev.
use super::{firmware_transport::Io, interface::Device};
use alloc::{sync::Arc, vec};
use narf_net::Interface;
use narf_wireless::{
    AssociateRequest, ScanRequest, SecurityConfig, WirelessError, WirelessNetIface,
};
use zeroize::Zeroizing;
#[derive(Debug)]
pub enum Error {
    Reset(super::operating_reset::Error),
    Provision(super::FirmwareError),
    Wireless(WirelessError),
    Generation,
}
pub(super) struct Pending {
    request: AssociateRequest,
    key: Option<Zeroizing<[u8; 32]>>,
}
impl Pending {
    pub(super) fn new(mut request: AssociateRequest) -> Result<Self, Error> {
        let key = match core::mem::replace(&mut request.security, SecurityConfig::Open) {
            SecurityConfig::Open => None,
            SecurityConfig::Wpa2 { psk } => Some(Zeroizing::new(psk)),
            SecurityConfig::Wpa3 { password } => {
                let _password = Zeroizing::new(password);
                return Err(Error::Wireless(WirelessError::NotSupported));
            }
            _ => return Err(Error::Wireless(WirelessError::NotSupported)),
        };
        // The rebound interface admits only signed per-channel primaries.
        if super::channel_policy::frequency(request.channel.min(255) as u8).map(u32::from)
            != Some(request.frequency_mhz)
            || request.ssid.is_empty()
            || request.ssid.len() > 32
            || request.bssid == [0; 6]
            || request.bssid[0] & 1 != 0
        {
            return Err(Error::Wireless(WirelessError::InvalidArgs));
        }
        Ok(Self { request, key })
    }
    fn take(mut self) -> AssociateRequest {
        if let Some(key) = self.key.take() {
            self.request.security = SecurityConfig::Wpa2 { psk: *key };
        }
        self.request
    }
}
pub(super) struct Attempt<I: Io + 'static> {
    device: Arc<Device<I>>,
    armed: bool,
}
impl<I: Io + 'static> Attempt<I> {
    fn new(device: Arc<Device<I>>) -> Self {
        Self {
            device,
            armed: true,
        }
    }
}
impl<I: Io + 'static> Drop for Attempt<I> {
    fn drop(&mut self) {
        if self.armed {
            self.device.cancel_control();
        }
    }
}
/// Bind the caller's BSS to this exact fresh generation, using its own scan,
/// native handshake and final current source receipts. No old peer/key replay.
pub(super) async fn associate_fresh<I: Io + 'static>(
    device: &Arc<Device<I>>,
    pending: Pending,
    current: impl Fn() -> bool,
) -> Result<(), Error> {
    if !current() {
        return Err(Error::Generation);
    }
    let mut attempt = Attempt::new(device.clone());
    let snapshot = narf_net::iface::lookup(device.name()).ok_or(Error::Generation)?;
    if snapshot.mac != device.mac() {
        return Err(Error::Generation);
    }
    let up = narf_net::iface::OpenStopEvent::observe(&snapshot)
        .filter(|event| event.up())
        .ok_or(Error::Generation)?;
    let host = up.native_identity().ok_or(Error::Generation)?;
    {
        let mut retained = device.lifecycle.retained.lock().await;
        if !current() || !up.current() {
            return Err(Error::Generation);
        }
        retained
            .as_mut()
            .ok_or(Error::Generation)?
            .bind_host(host)
            .map_err(Error::Provision)?;
    }
    let request = &pending.request;
    let seen = device
        .scan(ScanRequest {
            ssids: vec![request.ssid.clone()],
            frequencies_mhz: vec![request.frequency_mhz],
            channels: vec![request.channel],
            active: false,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: Some(1),
            duration_mandatory: false,
            extra_ies: vec![],
        })
        .await
        .map_err(Error::Wireless)?;
    if !current()
        || !up.current()
        || !seen.iter().any(|bss| {
            bss.bssid == request.bssid
                && bss.ssid == request.ssid
                && bss.frequency_mhz == request.frequency_mhz
        })
    {
        return Err(Error::Generation);
    }
    device
        .associate(pending.take())
        .await
        .map_err(Error::Wireless)?;
    if !current() || !up.current() || !device.link_up() {
        return Err(Error::Generation);
    }
    attempt.armed = false;
    Ok(())
}
/// Recover the exact function/netdev, earn fresh provisioning, then explicitly
/// associate with the supplied Open/WPA2 BSS. Credentials zeroize on cancellation.
pub async fn rejoin_function(
    address: narf_bus::BusAddr,
    request: AssociateRequest,
) -> Result<(), Error> {
    let pending = Pending::new(request)?;
    let fresh = super::operating_reset::reset_owner(address, true, false)
        .await
        .map_err(Error::Reset)?;
    let device = fresh.interface.as_ref().ok_or(Error::Generation)?;
    let mut attempt = Attempt::new(device.clone());
    super::pci::provision_owner(&fresh)
        .await
        .map_err(Error::Provision)?;
    let _provision = fresh.provisioning.lock().await;
    associate_fresh(device, pending, || {
        super::functions::get(address).is_some_and(|current| Arc::ptr_eq(&current, &fresh))
    })
    .await?;
    attempt.armed = false;
    Ok(())
}
