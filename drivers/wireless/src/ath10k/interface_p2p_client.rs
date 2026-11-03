// SPDX-License-Identifier: GPL-2.0-or-later
//! The P2P client netdev (`NL80211_IFTYPE_P2P_CLIENT`, iftype 8) of the
//! ath10k radio.
//!
//! Linux 7.3-rc4: cfg80211 `NEW_INTERFACE` registers the netdev
//! (`ieee80211_if_add`) and opening it runs `mac.c::ath10k_add_interface`,
//! which creates the STA/P2P_CLI vdev; `DEL_INTERFACE`
//! (`ieee80211_if_remove`) disassociates and `ath10k_remove_interface`
//! deletes the vdev. Here `new_virtual_interface` registers a second
//! [`Device`] with its own rings, generation and service worker; the worker
//! creates the client vdev (`Radio::start_p2p_client`) before any station
//! path may run and deletes it (`Radio::stop_p2p_client`) after DEL made
//! the netdev undiscoverable. Every station path of this netdev holds the
//! radio through a client `StationGuard`, so prepare, association, keys,
//! scan and data run on the client vdev and its station slot, and the HTT
//! demultiplexing parks the home netdev's events in the home slot.
//!
//! A vdev whose station was associated cannot be deleted cleanly: station
//! retirement keeps the radio failed until a whole-device reset (as for the
//! home netdev), so that DEL ends in radio recovery.
use super::*;

/// `NL80211_IFTYPE_P2P_CLIENT`.
pub(super) const IFTYPE: u32 = 8;

/// The P2P client netdev of the current radio generation, from
/// NEW_INTERFACE until its vdev is deleted or the generation retires. At
/// most one exists (the radio has one client slot).
static CLIENT: IrqSafeSpinLock<Option<Arc<Native>>> = IrqSafeSpinLock::new(None);

pub(super) fn current() -> Option<Arc<Native>> {
    CLIENT.lock().clone()
}

fn of(radio: &Arc<Mutex<Radio<super::super::boot::PciBoot>>>) -> Option<Arc<Native>> {
    CLIENT
        .lock()
        .as_ref()
        .filter(|client| Arc::ptr_eq(&client.radio, radio))
        .cloned()
}

/// Wake this radio's P2P client worker (the home worker's vector turn).
pub(super) fn kick_for(radio: &Arc<Mutex<Radio<super::super::boot::PciBoot>>>) {
    if let Some(client) = of(radio) {
        client.kick();
    }
}

/// Generation retirement: the client netdev ends with its radio
/// generation; recovery does not recreate it (userspace re-forms the group).
pub(super) fn retire(radio: &Arc<Mutex<Radio<super::super::boot::PciBoot>>>) {
    let client = {
        let mut slot = CLIENT.lock();
        if slot
            .as_ref()
            .is_some_and(|client| Arc::ptr_eq(&client.radio, radio))
        {
            slot.take()
        } else {
            None
        }
    };
    if let Some(client) = client {
        client.retire_client_host();
    }
}

fn forget(device: &Arc<Native>) {
    let mut slot = CLIENT.lock();
    if slot.as_ref().is_some_and(|c| Arc::ptr_eq(c, device)) {
        *slot = None;
    }
}

/// The P2P Interface Address when NEW_INTERFACE names none: distinct from
/// the netdev address and from the default P2P Device Address
/// (`brcmfmac/p2p.c::brcmf_p2p_generate_bss_mac`: the device address with
/// the locally administered bit, byte 4 XOR 0x80).
fn interface_address(primary: [u8; 6]) -> [u8; 6] {
    let mut address = primary;
    address[0] |= 0x02;
    address[4] ^= 0x80;
    address
}

impl Native {
    /// `NEW_INTERFACE` for iftype 8 on the home netdev. The netdev is
    /// published now; its worker creates the vdev, and until then the
    /// station paths are `Busy`.
    pub(super) fn new_p2p_client(
        &self,
        name: &str,
        iftype: u32,
        mac: Option<[u8; 6]>,
    ) -> Result<Arc<dyn WirelessNetIface>, WirelessError> {
        if !p2p_wdev::P2P_ADVERTISED || !self.p2p_capable || self.client || iftype != IFTYPE {
            return Err(WirelessError::NotSupported);
        }
        if self.closed.load(Ordering::Acquire) || self.retired.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        // The AP replaces the managed station vdev and is not sibling-aware.
        if self.mode.load(Ordering::Acquire) != 2 {
            return Err(WirelessError::Busy);
        }
        if name.is_empty() || name.len() > 15 || name.as_bytes().contains(&0) {
            return Err(WirelessError::InvalidArgs);
        }
        let device_mac = self.p2p_wdev().map(|wdev| Interface::mac(wdev.as_ref()));
        let address = mac.unwrap_or_else(|| interface_address(self.mac));
        if address == [0; 6]
            || address[0] & 1 != 0
            || address == self.mac
            || Some(address) == device_mac
        {
            return Err(WirelessError::InvalidArgs);
        }
        if narf_net::iface::lookup(name).is_some()
            || narf_wireless::registry::list()
                .iter()
                .any(|iface| iface.name() == name)
        {
            return Err(WirelessError::Busy);
        }
        active_for(&self.radio)
            .filter(|active| core::ptr::eq(active.as_ref(), self))
            .ok_or(WirelessError::Denied)?;
        let authority = narf_net::trusted_net_authority()
            .and_then(|cap| cap.derive().ok())
            .ok_or(WirelessError::Denied)?;
        let mut slot = CLIENT.lock();
        // `ath10k_tlv_if_limit` admits two P2P clients; this radio owns one
        // client slot.
        if slot.is_some() {
            return Err(WirelessError::Busy);
        }
        let (features, delivered) = {
            let radio = self.radio.try_lock().ok_or(WirelessError::Busy)?;
            if radio.p2p_client_vdev().is_some() || radio.ap_exists() {
                return Err(WirelessError::Busy);
            }
            (
                RadioFeatures::observed(&radio),
                radio.htt.wmi.htc.transport.interrupt().1,
            )
        };
        // Station only: no AP, ROC/offchannel FRAME, WoW or P2P_DEVICE
        // child on the client netdev.
        let features = RadioFeatures {
            ap: false,
            ap_uapsd: false,
            offchannel_tx: false,
            wowlan: None,
            p2p: false,
            ..features
        };
        let mut device = Device::with_policy(
            name,
            address,
            self.radio.clone(),
            self.policy.duplicate(),
            features,
            self.frequencies.clone(),
        );
        device.client = true;
        device.wiphy = self.wiphy;
        let device = Arc::new(device);
        let registration = narf_net::registry()
            .register(&authority, Registered(device.clone()))
            .map_err(|error| match error {
                narf_net::RegisterError::DuplicateName => WirelessError::Busy,
                narf_net::RegisterError::AuthorityRevoked => WirelessError::Denied,
            })?;
        *device.net_registration.lock() = Some(registration);
        narf_net::iface::register_with_context(name, address, device.generation, send);
        narf_net::iface::set_link_state(name, false);
        narf_net::iface::set_link_metadata(name, false, None, None);
        narf_wireless::registry::register(device.clone());
        let signal = super::super::irq::Signal::new();
        *device.wake.lock() = Some(signal.clone());
        *slot = Some(device.clone());
        drop(slot);
        narf_scheduler::spawn(serve(device.clone(), signal, delivered));
        Ok(device)
    }

    /// `DEL_INTERFACE` on the client netdev: undiscoverable now; the worker
    /// deletes the vdev and only then frees the client slot.
    pub(super) fn delete_p2p_client(&self) -> Result<(), WirelessError> {
        if !self.client {
            return Err(WirelessError::NotSupported);
        }
        if self.retired.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        if self.deleting.swap(true, Ordering::AcqRel) {
            return Err(WirelessError::Busy);
        }
        narf_wireless::reconnect::forget(&self.name);
        self.close();
        self.unpublish_client();
        self.kick();
        Ok(())
    }

    fn unpublish_client(&self) {
        narf_wireless::registry::unregister(&self.name);
        narf_net::registry().unregister(&self.name);
        narf_net::iface::unregister(&self.name);
    }

    fn retire_client_host(&self) {
        {
            let _publication = self.publication.lock();
            if self.retired.load(Ordering::Acquire) {
                return;
            }
            self.closed.store(true, Ordering::Release);
            self.publish_link(None);
            self.retired.store(true, Ordering::Release);
        }
        self.kick();
        if let Some(mut state) = self.state.try_lock() {
            state.clear();
        }
        // A deleted netdev is already unpublished; its name may be reused.
        if !self.deleting.swap(true, Ordering::AcqRel) {
            self.unpublish_client();
        }
    }

    /// `ath10k_add_interface` for the client vif.
    async fn create_client_vdev(&self) -> Result<u8, Error> {
        let mut radio = self.radio.lock().await;
        let validate = || {
            if self.closed.load(Ordering::Acquire) || self.retired.load(Ordering::Acquire) {
                Err(Error::Failed)
            } else {
                Ok(())
            }
        };
        validate()?;
        radio.start_p2p_client(self.mac, &validate).await
    }

    /// `ieee80211_if_remove` -> `ath10k_remove_interface`: disassociate a
    /// still-joined client (best effort deauthentication), then delete the
    /// vdev. `Err` leaves the radio for recovery.
    async fn retire_client_vdev(&self) -> Result<(), Error> {
        let validate = || {
            if self.retired.load(Ordering::Acquire) {
                Err(Error::Failed)
            } else {
                Ok(())
            }
        };
        {
            let Some(mut station) = wmi_runtime::StationGuard::new(self.radio.lock().await, true)
            else {
                return Ok(());
            };
            validate()?;
            station.retire_station_receive();
            if station.prepared_peer().is_some() {
                station.disconnect_station().await?;
            }
        }
        let mut radio = self.radio.lock().await;
        validate()?;
        if radio.p2p_client_vdev().is_none() {
            return Ok(());
        }
        radio.stop_p2p_client(&validate).await
    }
}

/// The client netdev's NAPI-equivalent service worker: vdev creation, then
/// data drains woken by its own TX kicks and the home worker's vector turns
/// (bounded backstop), then ordered vdev retirement after DEL.
async fn serve(device: Arc<Native>, signal: Arc<super::super::irq::Signal>, delivered: bool) {
    if let Err(cause) = device.create_client_vdev().await {
        device.close();
        if !device.deleting.swap(true, Ordering::AcqRel) {
            device.unpublish_client();
        }
        forget(&device);
        // A refusal publishes nothing; an ambiguous VDEV_CREATE leaves the
        // radio failed for recovery.
        if !matches!(cause, Error::Unsupported) && !device.retired.load(Ordering::Acquire) {
            super::super::pci::scan_cleanup_failed(device.radio.clone());
        }
        return;
    }
    loop {
        if device.retired.load(Ordering::Acquire) {
            // The vdev ends with the radio generation.
            break;
        }
        if device.deleting.load(Ordering::Acquire) {
            if device.retire_client_vdev().await.is_err() && !device.retired.load(Ordering::Acquire)
            {
                super::super::pci::scan_cleanup_failed(device.radio.clone());
            }
            break;
        }
        let seen = signal.count();
        let mut progressed = false;
        if !device.closed.load(Ordering::Acquire) {
            progressed = device.drain();
            let _ = device.flush_management().await;
            let _ = device.apply_power_save().await;
        }
        if device.cleanup_failed_scan().await.is_err() {
            // Failed station or scan cleanup: whole-radio recovery retires
            // this netdev with the generation.
            super::super::pci::scan_cleanup_failed(device.radio.clone());
            break;
        }
        if progressed {
            narf_scheduler::yield_now().await;
            continue;
        }
        let ms = super::super::irq::fallback_ms(delivered);
        let timer = narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(ms * 1_000_000));
        signal.wait(seen, core::pin::pin!(timer)).await;
    }
    forget(&device);
}
