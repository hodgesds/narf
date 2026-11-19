// SPDX-License-Identifier: GPL-2.0-or-later
//! The P2P GO netdev (`NL80211_IFTYPE_P2P_GO`, iftype 9) of the ath10k
//! radio.
//!
//! Linux 7.3-rc4: cfg80211 `NEW_INTERFACE` registers the netdev
//! (`ieee80211_if_add`); `START_AP` on it runs `mac.c::ath10k_add_interface`
//! for `NL80211_IFTYPE_P2P_GO` (an AP-type vdev with subtype P2P_GO) and the
//! beacon/BSS setup; `DEL_INTERFACE` (`ieee80211_if_remove`) stops the AP
//! (`ieee80211_stop_ap`) and `ath10k_remove_interface` deletes the vdev.
//! Here `new_virtual_interface` registers a second [`Device`] marked GO
//! (`Device::go`, AP mode from birth) with its own rings, generation and
//! service worker. Its AP controls run `Radio::go_start` on its own vdev
//! beside the managed vdev and the station slots; `ap_cleanup` on the GO
//! session deletes that vdev. The home netdev's worker kicks this worker on
//! every vector turn (events routed to the GO session, see
//! `Session::claims`).
use super::*;

/// `NL80211_IFTYPE_P2P_GO`.
pub(super) const IFTYPE: u32 = 9;

/// The P2P GO netdev of the current radio generation, from NEW_INTERFACE
/// until its session is torn down after DEL or the generation retires. At
/// most one exists (the radio owns one AP session).
static GO: IrqSafeSpinLock<Option<Arc<Native>>> = IrqSafeSpinLock::new(None);

pub(super) fn current() -> Option<Arc<Native>> {
    GO.lock().clone()
}

pub(super) fn of(radio: &Arc<Mutex<Radio<super::super::boot::PciBoot>>>) -> Option<Arc<Native>> {
    GO.lock()
        .as_ref()
        .filter(|go| Arc::ptr_eq(&go.radio, radio))
        .cloned()
}

/// Wake this radio's GO worker (the home worker's vector turn).
pub(super) fn kick_for(radio: &Arc<Mutex<Radio<super::super::boot::PciBoot>>>) {
    if let Some(go) = of(radio) {
        go.kick();
    }
}

/// Generation retirement: the GO netdev ends with its radio generation;
/// recovery does not recreate it (userspace re-forms the group).
pub(super) fn retire(radio: &Arc<Mutex<Radio<super::super::boot::PciBoot>>>) {
    let go = {
        let mut slot = GO.lock();
        if slot
            .as_ref()
            .is_some_and(|go| Arc::ptr_eq(&go.radio, radio))
        {
            slot.take()
        } else {
            None
        }
    };
    if let Some(go) = go {
        go.retire_virtual_host();
    }
}

fn forget(device: &Arc<Native>) {
    let mut slot = GO.lock();
    if slot.as_ref().is_some_and(|go| Arc::ptr_eq(go, device)) {
        *slot = None;
    }
}

impl Native {
    /// `NEW_INTERFACE` for iftype 9 on the home netdev. The netdev is
    /// published in AP mode without a vdev; `START_AP` creates it
    /// (`Radio::go_start`).
    pub(super) fn new_p2p_go(
        &self,
        name: &str,
        iftype: u32,
        mac: Option<[u8; 6]>,
    ) -> Result<Arc<dyn WirelessNetIface>, WirelessError> {
        if !p2p_wdev::P2P_ADVERTISED
            || !self.p2p_capable
            || !self.ap_capable
            || self.client
            || self.go
            || iftype != IFTYPE
        {
            return Err(WirelessError::NotSupported);
        }
        if self.closed.load(Ordering::Acquire) || self.retired.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        // The managed netdev's AP replaces the managed station vdev and is
        // not sibling-aware: the radio has one AP session.
        if self.mode.load(Ordering::Acquire) != 2 {
            return Err(WirelessError::Busy);
        }
        if name.is_empty() || name.len() > 15 || name.as_bytes().contains(&0) {
            return Err(WirelessError::InvalidArgs);
        }
        let device_mac = self.p2p_wdev().map(|wdev| Interface::mac(wdev.as_ref()));
        let client_mac = p2p_client::current()
            .filter(|client| Arc::ptr_eq(&client.radio, &self.radio))
            .map(|client| client.mac);
        // The P2P Interface Address: the requested one, else the derivation
        // of `brcmfmac/p2p.c::brcmf_p2p_generate_bss_mac` (also the client's
        // default; a collision with a present client is refused and
        // userspace names an address, as wpa_supplicant does for groups).
        let address = mac.unwrap_or_else(|| p2p_client::interface_address(self.mac));
        if address == [0; 6]
            || address[0] & 1 != 0
            || address == self.mac
            || Some(address) == device_mac
            || Some(address) == client_mac
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
        let mut slot = GO.lock();
        // `ath10k_tlv_if_limit` admits two AP/P2P_CLIENT/P2P_GO vifs; this
        // radio owns one AP session.
        if slot.is_some() {
            return Err(WirelessError::Busy);
        }
        let (features, delivered) = {
            let radio = self.radio.try_lock().ok_or(WirelessError::Busy)?;
            if radio.ap_exists() || !radio.p2p_supported() {
                return Err(WirelessError::Busy);
            }
            (
                RadioFeatures::observed(&radio),
                radio.htt.wmi.htc.transport.interrupt().1,
            )
        };
        if !features.ap {
            return Err(WirelessError::NotSupported);
        }
        // AP only: no station power save, ROC/offchannel FRAME, WoW or
        // P2P_DEVICE child on the GO netdev.
        let features = RadioFeatures {
            power_save: false,
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
        device.go = true;
        device.mode = AtomicU8::new(3);
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
        *device.ap_host.wake.signal.lock() = Some(signal.clone());
        *slot = Some(device.clone());
        drop(slot);
        narf_scheduler::spawn(serve(device.clone(), signal, delivered));
        Ok(device)
    }

    /// `DEL_INTERFACE` on the GO netdev: undiscoverable now; the worker
    /// stops the GO (vdev delete) and only then frees the GO slot.
    pub(super) fn delete_p2p_go(&self) -> Result<(), WirelessError> {
        if !self.go {
            return Err(WirelessError::NotSupported);
        }
        if self.retired.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        if self.deleting.swap(true, Ordering::AcqRel) {
            return Err(WirelessError::Busy);
        }
        self.close();
        self.unpublish_virtual();
        self.kick();
        Ok(())
    }

    /// One GO worker cleanup turn: an abandoned or closed GO session is torn
    /// down on its own vdev (`ap_cleanup` -> VDEV_DELETE); the same netdev
    /// may then start a new group under a fresh control generation.
    async fn go_cleanup_step(&self) -> Result<(), Error> {
        let mut radio = if self.closed.load(Ordering::Acquire) {
            self.radio.lock().await
        } else {
            let Some(radio) = self.radio.try_lock() else {
                return Ok(());
            };
            radio
        };
        if self.retired.load(Ordering::Acquire) {
            return Ok(());
        }
        radio.ap_prune_staging();
        if !(radio.ap_exists() && radio.ap_is_go()) {
            return Ok(());
        }
        if !self.closed.load(Ordering::Acquire) && !radio.ap_abandoned() {
            return Ok(());
        }
        self.close();
        self.state.lock().await.clear();
        radio
            .ap_cleanup(&|| {
                if self.retired.load(Ordering::Acquire) {
                    Err(Error::Failed)
                } else {
                    Ok(())
                }
            })
            .await?;
        drop(radio);
        if !self.deleting.load(Ordering::Acquire) {
            self.ap_cleanup_complete()?;
        }
        self.ap_retire_metadata();
        Ok(())
    }
}

/// The GO netdev's service worker: AP drains woken by its own TX kicks, its
/// AP waker and the home worker's vector turns (bounded backstop); after DEL
/// the GO session (if any) is stopped and its vdev deleted.
async fn serve(device: Arc<Native>, signal: Arc<super::super::irq::Signal>, delivered: bool) {
    loop {
        if device.retired.load(Ordering::Acquire) {
            // The vdev ends with the radio generation.
            break;
        }
        let seen = signal.count();
        let mut progressed = false;
        if !device.closed.load(Ordering::Acquire) {
            progressed = device.drain();
        }
        if device.go_cleanup_step().await.is_err() {
            // A failed GO teardown (missing/foreign receipt, timeout):
            // whole-radio recovery retires this netdev with the generation.
            if !device.retired.load(Ordering::Acquire) {
                super::super::pci::scan_cleanup_failed(device.radio.clone());
            }
            break;
        }
        if device.deleting.load(Ordering::Acquire) {
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
