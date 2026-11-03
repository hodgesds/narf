// SPDX-License-Identifier: GPL-2.0-or-later
//! Control-only nl80211 P2P_DEVICE WDEV (iftype 10) of the ath10k netdev.
//!
//! Linux 7.3-rc4: cfg80211 `NEW_INTERFACE` for P2P_DEVICE creates only the
//! wdev (`ieee80211_if_add`); `START_P2P_DEVICE` opens it
//! (`ieee80211_start_p2p_device` -> `ieee80211_do_open` ->
//! `drv_add_interface` = `mac.c::ath10k_add_interface`, which creates the
//! STA/P2P_DEV vdev) and `STOP_P2P_DEVICE` removes the vdev again
//! (`ath10k_remove_interface`). ROC (`ath10k_remain_on_channel`) and FRAME
//! (`ieee80211_mgmt_tx` offchannel) run on that vdev with the wdev address;
//! management registrations (`ieee80211_default_mgmt_stypes` for
//! P2P_DEVICE: Action and Probe Request) are per wdev.
//!
//! The wdev has no Ethernet entry, IFINDEX, UP state or data rings. Every
//! native command is serialized under the netdev's `Radio` mutex and its
//! ROC is serviced by the netdev worker; this module binds the source/event
//! authorities to the wdev itself.
use super::offchannel::Side;
use super::*;
use core::num::NonZeroU64;
use narf_capabilities::{Cap, Write};
use narf_wireless::{
    ap_control::{
        ApControlReservation, RadioControlAuthority, RadioControlRetirement,
        RadioEmissionAuthority, RadioInterfaceIdentity,
    },
    MgmtTxRequest, WirelessIfaceInfo,
};

/// Whether the P2P_DEVICE WDEV is offered through nl80211. It stays false
/// until the P2P client/GO roles and their advertisement land
/// (`drivers/wireless/specification/ath10k.md` §3.8).
pub(super) const P2P_ADVERTISED: bool = false;
/// The P2P Wildcard SSID (`P2P_WILDCARD_SSID` in wpa_supplicant).
const P2P_WILDCARD_SSID: &[u8] = b"DIRECT-";
/// `1 << NL80211_IFTYPE_P2P_DEVICE`: the only async control iftype.
pub(super) const CONTROL_IFTYPES: u32 = 1 << 10;

#[derive(Clone, Copy, Debug)]
struct Registration {
    net: Cap<narf_net::NetIface, Write>,
    wdev: narf_wireless::registry::ControlWdev,
}

/// The control-only P2P_DEVICE wdev of one ath10k netdev generation.
pub(in crate::ath10k) struct P2pWdev {
    name: String,
    /// The P2P Device Address (`vif->addr`, the vdev's own address).
    mac: [u8; 6],
    namespace: u64,
    parent_name: String,
    parent_epoch: u64,
    parent: alloc::sync::Weak<Native>,
    info: WirelessIfaceInfo,
    subscriptions: Arc<wmi_runtime::offchannel::Subscriptions>,
    registration: IrqSafeSpinLock<Option<Registration>>,
    /// The START_P2P_DEVICE request's identity while the vdev exists.
    started: IrqSafeSpinLock<Option<RadioInterfaceIdentity>>,
    /// IEs of the last WDEV scan's BSSes (`scan_information_elements`).
    scan_ies: IrqSafeSpinLock<Vec<([u8; 6], Vec<u8>)>>,
    rx: IrqSafeSpinLock<Option<narf_ipc::Consumer<Frame, RX_RING_N>>>,
    tx: IrqSafeSpinLock<Option<narf_ipc::Producer<Frame, TX_RING_N>>>,
}

impl core::fmt::Debug for P2pWdev {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ath10kP2pDevice")
            .field("name", &self.name)
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

struct Observed;
impl narf_capabilities::CapOp<narf_net::NetIface, Write> for Observed {
    type Output = ();
    fn execute(
        self,
        _: &Cap<narf_net::NetIface, Write>,
    ) -> Result<(), narf_capabilities::CapError> {
        Ok(())
    }
}

#[derive(Debug)]
struct Registered(Arc<P2pWdev>);

/// `cfg80211` P2P_DEVICE address rule: the requested address, else the
/// netdev address with the locally administered bit (as Linux userspace
/// and `brcmf_p2p_generate_bss_mac` derive it).
fn device_address(primary: [u8; 6], requested: Option<[u8; 6]>) -> [u8; 6] {
    requested.unwrap_or_else(|| {
        let mut mac = primary;
        mac[0] |= 0x02;
        mac
    })
}

impl Native {
    pub(super) fn p2p_wdev(&self) -> Option<Arc<P2pWdev>> {
        self.p2p_wdev.lock().clone()
    }
    /// Software-only withdrawal of the wdev metadata (netdev close/retire,
    /// unpublished NEW); the vdev itself ends with the radio generation.
    fn withdraw_p2p_wdev(&self) {
        let wdev = { self.p2p_wdev.lock().take() };
        if let Some(wdev) = wdev {
            wdev.withdraw();
        }
    }
    pub(super) async fn new_p2p_wdev(
        &self,
        authority: &RadioControlAuthority,
        name: &str,
        iftype: u32,
        mac: Option<[u8; 6]>,
    ) -> Result<Arc<dyn WirelessNetIface>, WirelessError> {
        if !P2P_ADVERTISED || !self.p2p_capable || iftype != 10 {
            return Err(WirelessError::NotSupported);
        }
        authority.check_for(self)?;
        if !authority.has_reservation()
            || self.closed.load(Ordering::Acquire)
            || self.retired.load(Ordering::Acquire)
        {
            return Err(WirelessError::Denied);
        }
        if name.is_empty() || name.len() > 15 || name.as_bytes().contains(&0) {
            return Err(WirelessError::InvalidArgs);
        }
        if mac.is_some_and(|mac| mac == [0; 6] || mac[0] & 1 != 0 || mac == self.mac) {
            return Err(WirelessError::InvalidArgs);
        }
        let this = Arc::downgrade(
            &active_for(&self.radio)
                .filter(|active| core::ptr::eq(active.as_ref(), self))
                .ok_or(WirelessError::Denied)?,
        );
        let parent: Arc<dyn WirelessNetIface> = narf_wireless::registry::list()
            .into_iter()
            .find(|iface| {
                core::ptr::eq(
                    Arc::as_ptr(iface).cast::<()>(),
                    core::ptr::from_ref(self).cast::<()>(),
                )
            })
            .ok_or(WirelessError::Denied)?;
        let metadata = narf_net::iface::lookup(&self.name).ok_or(WirelessError::Denied)?;
        if metadata.ownership_epoch == 0 {
            return Err(WirelessError::Denied);
        }
        let parent_cap = (*self.net_registration.lock()).ok_or(WirelessError::Denied)?;
        let grant = narf_net::trusted_net_authority().ok_or(WirelessError::Denied)?;
        // `ath10k_tlv_if_comb`: at most one P2P_DEVICE (`-EBUSY`).
        if self.p2p_wdev.lock().is_some() {
            return Err(WirelessError::Busy);
        }
        let address = device_address(self.mac, mac);
        let mut info = self.get_wireless_info();
        info.base_name = name.into();
        info.base_mac = address;
        info.modes = narf_wireless::iface::WirelessModes::empty();
        let wdev = Arc::new(P2pWdev {
            name: name.into(),
            mac: address,
            namespace: metadata.net_ns_id,
            parent_name: self.name.clone(),
            parent_epoch: metadata.ownership_epoch,
            parent: this,
            info,
            subscriptions: Arc::new(wmi_runtime::offchannel::Subscriptions::with_probe_request(
                true,
            )),
            registration: IrqSafeSpinLock::new(None),
            started: IrqSafeSpinLock::new(None),
            scan_ies: IrqSafeSpinLock::new(Vec::new()),
            rx: IrqSafeSpinLock::new(None),
            tx: IrqSafeSpinLock::new(None),
        });
        {
            let mut slot = self.p2p_wdev.lock();
            if slot.is_some() {
                return Err(WirelessError::Busy);
            }
            *slot = Some(wdev.clone());
        }
        if let Err(e) = wdev.publish(authority, &parent, &grant, &parent_cap) {
            self.withdraw_p2p_wdev();
            return Err(e);
        }
        Ok(wdev)
    }
}

impl Native {
    /// `mac.c::ath10k_hw_scan` on the started P2P_DEVICE vif (P2P search:
    /// wpa_supplicant `p2p_find` scans the social channels from the P2P
    /// device with the `DIRECT-` SSID and its P2P/WSC IEs). The request is
    /// validated as the netdev's; the WMI scan runs on the P2P_DEVICE vdev
    /// (`Radio::p2p_device_scan`). A ROC in flight, a prepared/associated
    /// station peer or an AP on the managed vdev is `Busy` before any
    /// publication; an ambiguous native failure closes the netdev as its
    /// own scans do.
    async fn p2p_device_scan(
        &self,
        mut request: ScanRequest,
    ) -> Result<Vec<wmi_runtime::ScanBss>, WirelessError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        let (mut frequencies, implicit) = self.scan_frequencies(&mut request)?;
        let mut radio = self.radio.lock().await;
        if radio.p2p_device_vdev().is_none() {
            return Err(WirelessError::HardwareError);
        }
        if radio.roc_active()
            || radio.prepared_peer().is_some()
            || radio.station_link().is_some()
            || radio.ap_exists() && !radio.ap_is_go()
        {
            return Err(WirelessError::Busy);
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        let domain = self.policy.current().map_err(error)?;
        if implicit {
            frequencies.retain(|f| {
                wmi_runtime::receive_permission(&domain, &[*f]).is_ok()
                    && (!request.active || radio.active_frequency_allowed(&domain, *f))
            });
        }
        wmi_runtime::receive_permission(&domain, &frequencies).map_err(error)?;
        let plan = if request.active {
            Some(
                radio
                    .prepare_active_scan(&frequencies, &request.ssids, &domain)
                    .and_then(|plan| plan.with_extra_ies(&request.extra_ies))
                    .map_err(error)?,
            )
        } else {
            None
        };
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        let report = radio
            .p2p_device_scan(plan, &frequencies, || {
                if self.closed.load(Ordering::Acquire) {
                    return Err(Error::Failed);
                }
                self.policy.current()
            })
            .await
            .map_err(error)?;
        attempt.armed = false;
        Ok(report
            .bss
            .into_iter()
            .filter(|b| {
                request.ssids.is_empty()
                    || request.ssids.iter().any(|s| {
                        // The P2P Wildcard SSID `DIRECT-` matches every
                        // P2P SSID (Wi-Fi P2P 3.1.2.1.1); others are exact.
                        s.is_empty()
                            || *s == b.ssid
                            || (s.as_slice() == P2P_WILDCARD_SSID
                                && b.ssid.starts_with(P2P_WILDCARD_SSID))
                    })
            })
            .collect())
    }
}

impl P2pWdev {
    fn publish(
        self: &Arc<Self>,
        authority: &RadioControlAuthority,
        parent: &Arc<dyn WirelessNetIface>,
        grant: &Cap<narf_net::NetIface, narf_capabilities::Grant>,
        parent_cap: &Cap<narf_net::NetIface, Write>,
    ) -> Result<(), WirelessError> {
        let net = narf_net::registry()
            .register_control_child(grant, parent_cap, Registered(self.clone()))
            .map_err(|e| match e {
                narf_net::ControlRegisterError::AuthorityRevoked => WirelessError::Denied,
                narf_net::ControlRegisterError::DuplicateName => WirelessError::Busy,
                narf_net::ControlRegisterError::NotControl => WirelessError::InvalidArgs,
            })?;
        let iface: Arc<dyn WirelessNetIface> = self.clone();
        let wdev = match narf_wireless::registry::register_control(parent, iface.clone()) {
            Ok(wdev) => wdev,
            Err(_) => {
                narf_net::registry().unregister_for_handle(&net);
                return Err(WirelessError::Busy);
            }
        };
        *self.registration.lock() = Some(Registration { net, wdev });
        authority.check_for(parent.as_ref())?;
        self.current()?;
        authority.retain_control_child(&iface, &net)
    }

    /// The parent netdev generation, its ownership/namespace and this exact
    /// registration are all current.
    fn current(&self) -> Result<Arc<Native>, WirelessError> {
        let parent = self.parent.upgrade().ok_or(WirelessError::Denied)?;
        let registered = { *self.registration.lock() };
        let listed = parent
            .p2p_wdev
            .lock()
            .as_ref()
            .is_some_and(|wdev| core::ptr::eq(Arc::as_ptr(wdev), self));
        if parent.closed.load(Ordering::Acquire)
            || parent.retired.load(Ordering::Acquire)
            || !listed
            || narf_net::iface::lookup(&self.parent_name).is_none_or(|metadata| {
                metadata.ownership_epoch != self.parent_epoch
                    || metadata.net_ns_id != self.namespace
            })
            || !registered
                .is_some_and(|r| r.net.invoke(Observed).is_ok() && r.wdev.current_for(self))
        {
            return Err(WirelessError::Denied);
        }
        Ok(parent)
    }

    fn request_current(
        &self,
        authority: &RadioControlAuthority,
    ) -> Result<Arc<Native>, WirelessError> {
        let parent = self.current()?;
        authority.check_for(self)?;
        authority.require_mode(10)?;
        if !authority.has_reservation() {
            return Err(WirelessError::Denied);
        }
        Ok(parent)
    }

    fn started(&self) -> bool {
        let identity = { self.started.lock().clone() };
        self.current().is_ok() && identity.is_some_and(|identity| identity.check_for(self).is_ok())
    }

    /// The control emission of this wdev's START request. Only the actual
    /// child Write registration can mint it (`native_control_emission_for`).
    fn emission(
        &self,
        authority: &RadioControlAuthority,
    ) -> Result<RadioEmissionAuthority, WirelessError> {
        if !self.started() {
            return Err(WirelessError::NotSupported);
        }
        let net = self
            .registration
            .lock()
            .as_ref()
            .map(|r| r.net)
            .ok_or(WirelessError::Denied)?;
        authority.native_control_emission_for(self, &net)
    }

    /// Whether a ROC owner's emission is still this wdev's current one.
    pub(super) fn owns_emission(&self, emission: &RadioEmissionAuthority) -> bool {
        self.started()
            && self
                .radio_control_generation()
                .is_some_and(|generation| emission.matches_mode(self, 10, generation))
    }

    fn side(&self) -> Side<'_> {
        Side {
            iface: self,
            subscriptions: self.subscriptions.clone(),
            p2p_device: true,
        }
    }

    /// Software-only exact-registration cleanup.
    pub(super) fn withdraw(&self) {
        self.subscriptions.invalidate();
        let registration = { self.registration.lock().take() };
        if let Some(registration) = registration {
            narf_wireless::registry::unregister_control(registration.wdev, self);
            narf_net::registry().unregister_for_handle(&registration.net);
        }
        let started = { self.started.lock().take() };
        drop(started);
    }

    /// `ath10k_remove_interface` for the P2P_DEVICE vdev: an outstanding
    /// ROC on it ends first (mac80211 `ieee80211_roc_purge`).
    async fn stop_native(&self, parent: &Native) -> Result<(), WirelessError> {
        for _ in 0..65536 {
            let on_device = {
                let mut radio = parent.radio.lock().await;
                if radio.p2p_device_vdev().is_none() {
                    return Ok(());
                }
                let on = radio.roc_on_p2p_device();
                if on {
                    if let Some(receipt) = radio.roc_receipt() {
                        let _ = radio.roc_cancel(receipt.cookie);
                    }
                }
                on
            };
            if !on_device {
                break;
            }
            parent.kick();
            parent.service_offchannel().await?;
            narf_scheduler::yield_now().await;
        }
        let mut radio = parent.radio.lock().await;
        if radio.roc_on_p2p_device() {
            return Err(WirelessError::Timeout);
        }
        let mut attempt = Attempt {
            device: parent,
            armed: true,
        };
        radio
            .stop_p2p_device(&|| {
                if parent.closed.load(Ordering::Acquire) {
                    Err(Error::Failed)
                } else {
                    Ok(())
                }
            })
            .await
            .map_err(error)?;
        attempt.armed = false;
        Ok(())
    }
}

impl Interface for P2pWdev {
    fn name(&self) -> &str {
        &self.name
    }
    fn mac(&self) -> [u8; 6] {
        self.mac
    }
    fn mtu(&self) -> u32 {
        0
    }
    fn link_up(&self) -> bool {
        false
    }
    fn control_namespace(&self) -> Option<u64> {
        Some(self.namespace)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<narf_ipc::Consumer<Frame, RX_RING_N>>> {
        &self.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<narf_ipc::Producer<Frame, TX_RING_N>>> {
        &self.tx
    }
}

impl Interface for Registered {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn mac(&self) -> [u8; 6] {
        self.0.mac()
    }
    fn mtu(&self) -> u32 {
        0
    }
    fn link_up(&self) -> bool {
        false
    }
    fn control_namespace(&self) -> Option<u64> {
        self.0.control_namespace()
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<narf_ipc::Consumer<Frame, RX_RING_N>>> {
        self.0.rx_ring()
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<narf_ipc::Producer<Frame, TX_RING_N>>> {
        self.0.tx_ring()
    }
}

#[async_trait::async_trait]
impl WirelessNetIface for P2pWdev {
    fn wiphy_id(&self) -> u64 {
        self.parent.upgrade().map_or(0, |parent| parent.wiphy_id())
    }
    fn current_iftype(&self) -> u32 {
        10
    }
    fn get_wireless_info(&self) -> WirelessIfaceInfo {
        use narf_wireless::iface::{HwCaps, WirelessBand};
        let caps = &self.info.hw_caps;
        WirelessIfaceInfo {
            base_name: self.name.clone(),
            base_mac: self.mac,
            bands: self
                .info
                .bands
                .iter()
                .map(|band| WirelessBand {
                    freq_mhz: band.freq_mhz,
                    channels: band.channels.clone(),
                })
                .collect(),
            modes: narf_wireless::iface::WirelessModes::empty(),
            hw_caps: HwCaps {
                ht_supported: caps.ht_supported,
                vht_supported: caps.vht_supported,
                he_supported: caps.he_supported,
                eht_supported: caps.eht_supported,
            },
        }
    }
    fn radio_control_generation(&self) -> Option<NonZeroU64> {
        self.current().ok().and_then(|_| NonZeroU64::new(1))
    }
    /// The netdev's lease: every native command shares its `Radio`.
    fn reserve_radio_control(
        &self,
    ) -> Result<Option<Arc<dyn ApControlReservation>>, WirelessError> {
        self.current()?.reserve_control()
    }
    fn async_control_interfaces(&self) -> bool {
        true
    }
    fn async_control_iftypes(&self) -> u32 {
        CONTROL_IFTYPES
    }
    fn async_p2p_device_control(&self) -> bool {
        true
    }
    fn async_roc_control(&self) -> bool {
        true
    }
    fn async_p2p_management_rx_control(&self) -> bool {
        true
    }
    fn async_p2p_management_tx_control(&self) -> bool {
        self.parent
            .upgrade()
            .is_some_and(|parent| parent.offchannel_tx)
    }
    fn supports_offchannel_mgmt_tx(&self) -> bool {
        self.async_p2p_management_tx_control()
    }
    fn max_remain_on_channel_duration_ms(&self) -> u32 {
        wmi_runtime::offchannel::MAX_DURATION
    }
    fn p2p_interface_types(&self) -> Vec<u32> {
        alloc::vec![10]
    }
    /// The netdev's `max_scan_ssids` / `max_scan_ie_len` (one wiphy).
    fn max_scan_ssids(&self) -> u8 {
        wmi_runtime::MAX_SCAN_SSIDS as u8
    }
    fn max_scan_ie_len(&self) -> u16 {
        wmi_runtime::MAX_SCAN_IE_LEN
    }
    fn async_p2p_device_scan_control(&self) -> bool {
        true
    }
    /// `ath10k_hw_scan` on the P2P_DEVICE vif. mac80211 refuses a scan on
    /// a P2P_DEVICE that is not running (`ieee80211_sdata_running`); here
    /// an unstarted wdev has no vdev and gets `HardwareError` (`-EIO`).
    async fn p2p_device_scan_async(
        &self,
        authority: &RadioControlAuthority,
        request: ScanRequest,
    ) -> Result<Vec<BssInfo>, WirelessError> {
        let parent = self.request_current(authority)?;
        if !self.started() {
            return Err(WirelessError::HardwareError);
        }
        let results = parent.p2p_device_scan(request).await?;
        self.request_current(authority)?;
        let mut bsses = Vec::with_capacity(results.len());
        let mut ies = Vec::with_capacity(results.len());
        for mut bss in results {
            ies.push((bss.bssid, core::mem::take(&mut bss.information_elements)));
            bsses.push(bss_info(bss));
        }
        let replaced = core::mem::replace(&mut *self.scan_ies.lock(), ies);
        drop(replaced);
        Ok(bsses)
    }
    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.scan_ies
            .lock()
            .iter()
            .find(|(address, _)| *address == bssid)
            .map(|(_, elements)| elements.clone())
    }
    /// `ieee80211_start_p2p_device` -> `ath10k_add_interface`: the
    /// P2P_DEV vdev with the wdev address.
    async fn start_p2p_device_async(
        &self,
        authority: &RadioControlAuthority,
    ) -> Result<(), WirelessError> {
        let parent = self.request_current(authority)?;
        if self.started() {
            return Err(WirelessError::Busy);
        }
        let identity = authority.identity()?;
        {
            let mut radio = parent.radio.lock().await;
            let mut attempt = Attempt {
                device: &*parent,
                armed: true,
            };
            let result = radio
                .start_p2p_device(self.mac, &|| {
                    if parent.closed.load(Ordering::Acquire) || self.current().is_err() {
                        Err(Error::Failed)
                    } else {
                        Ok(())
                    }
                })
                .await;
            match result {
                Ok(_) => attempt.armed = false,
                // Refused before any publication: the radio is unchanged.
                Err(Error::Unsupported) => {
                    attempt.armed = false;
                    return Err(WirelessError::Busy);
                }
                Err(cause) => return Err(error(cause)),
            }
        }
        identity.check_for(self)?;
        *self.started.lock() = Some(identity);
        Ok(())
    }
    /// `ieee80211_stop_p2p_device` -> `ath10k_remove_interface`.
    async fn stop_p2p_device_async(
        &self,
        authority: &RadioControlAuthority,
    ) -> Result<(), WirelessError> {
        let parent = self.request_current(authority)?;
        let result = self.stop_native(&parent).await;
        let started = { self.started.lock().take() };
        drop(started);
        result
    }
    async fn remain_on_channel_async(
        &self,
        authority: &RadioControlAuthority,
        cookie: u64,
        frequency_mhz: u32,
        duration_ms: u32,
    ) -> Result<(), WirelessError> {
        let parent = self.request_current(authority)?;
        let emission = self.emission(authority)?;
        parent
            .start_offchannel_on(
                self.side(),
                authority,
                emission,
                cookie,
                frequency_mhz,
                duration_ms,
            )
            .await
    }
    async fn cancel_remain_on_channel_async(
        &self,
        authority: &RadioControlAuthority,
        cookie: u64,
    ) -> Result<(), WirelessError> {
        let parent = self.request_current(authority)?;
        let emission = self.emission(authority)?;
        parent
            .cancel_offchannel_on(true, authority, emission, cookie)
            .await
    }
    /// `ieee80211_mgmt_tx` on the P2P_DEVICE: Public Action frames and
    /// directed Probe Responses on (or in a private) ROC of its vdev.
    async fn mgmt_tx_radio_async(
        &self,
        authority: &RadioControlAuthority,
        cookie: u64,
        request: MgmtTxRequest,
    ) -> Result<bool, WirelessError> {
        let parent = self.request_current(authority)?;
        if !parent.offchannel_tx {
            return Err(WirelessError::NotSupported);
        }
        let emission = self.emission(authority)?;
        parent
            .transmit_offchannel_on(self.side(), authority, emission, cookie, request)
            .await
    }
    /// `NL80211_CMD_REGISTER_FRAME` on the wdev (Action / Probe Request).
    async fn register_mgmt_frame_radio_async(
        &self,
        authority: &RadioControlAuthority,
        frame_type: u16,
        prefix: &[u8],
    ) -> Result<(), i32> {
        let parent = self.request_current(authority).map_err(|_| 1)?;
        // Registration is metadata and may precede START; it binds to the
        // wdev's registration, not to an RF owner.
        let net = self.registration.lock().as_ref().map(|r| r.net).ok_or(1)?;
        let emission = authority
            .native_control_emission_for(self, &net)
            .map_err(|_| 1)?;
        parent
            .register_offchannel_frame_on(self.side(), authority, emission, frame_type, prefix)
            .await
    }
    fn release_control_metadata(&self) {
        if let Some(parent) = self.parent.upgrade() {
            let mut slot = parent.p2p_wdev.lock();
            if slot
                .as_ref()
                .is_some_and(|wdev| core::ptr::eq(Arc::as_ptr(wdev), self))
            {
                *slot = None;
            }
        }
        self.withdraw();
    }
    /// `ieee80211_del_iface`: a started device is stopped (vdev deleted)
    /// before the typed retirement receipt.
    async fn delete_control_interface_async(
        &self,
        authority: &RadioControlAuthority,
    ) -> Result<RadioControlRetirement, WirelessError> {
        let parent = self.request_current(authority)?;
        self.stop_native(&parent).await?;
        let started = { self.started.lock().take() };
        drop(started);
        let net = self
            .registration
            .lock()
            .as_ref()
            .map(|r| r.net)
            .ok_or(WirelessError::Denied)?;
        authority.retire_control(&net)
    }
    async fn scan(&self, _: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        Err(WirelessError::NotSupported)
    }
    async fn associate(&self, _: AssociateRequest) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
    async fn disassociate(&self) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
    async fn set_config(&self, _: WirelessConfig) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
}
