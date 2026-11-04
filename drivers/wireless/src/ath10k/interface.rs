// SPDX-License-Identifier: GPL-2.0-or-later
//! One retained legacy RAW station shared by async control and bounded native
//! packet drains. DHCP never depends on a worker, executor poll or block_on.
use super::{
    control::Hif,
    htt_runtime::HttMemory,
    wmi_boot::HostMemory,
    wmi_runtime::{self, Radio},
};
use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};
use narf_wireless::{
    AssociateRequest, BssInfo, ScanRequest, SecurityConfig, WirelessConfig, WirelessError,
    WirelessNetIface,
};
type Error = wmi_runtime::Error;
use wmi_runtime::receive_permission;
#[path = "interface_ap.rs"]
mod ap;
#[cfg(any(test, feature = "kernel-test"))]
pub(in crate::ath10k) use ap::Operation as ApOperation;
#[path = "interface_offchannel.rs"]
mod offchannel;
#[path = "interface_p2p_client.rs"]
pub(super) mod p2p_client;
#[path = "interface_p2p_go.rs"]
pub(super) mod p2p_go;
#[path = "interface_p2p.rs"]
pub(super) mod p2p_wdev;
#[path = "interface_wow.rs"]
pub(super) mod wowlan;
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
enum Policy {
    Installed,
    #[cfg(any(test, feature = "kernel-test"))]
    Model(Arc<dyn Fn() -> Option<narf_wireless::reg::RegulatoryDomain> + Send + Sync>),
}
impl Policy {
    /// The same policy source for a sibling netdev of this radio.
    fn duplicate(&self) -> Self {
        match self {
            Self::Installed => Self::Installed,
            #[cfg(any(test, feature = "kernel-test"))]
            Self::Model(current) => Self::Model(current.clone()),
        }
    }
    fn current(&self) -> Result<narf_wireless::reg::RegulatoryDomain, Error> {
        match self {
            Self::Installed => narf_wireless::reg::db::get_domain(),
            #[cfg(any(test, feature = "kernel-test"))]
            Self::Model(current) => current(),
        }
        .ok_or(Error::Unsupported)
    }
}
struct State {
    rx: narf_ipc::Producer<Frame, RX_RING_N>,
    tx: narf_ipc::Consumer<Frame, TX_RING_N>,
    pending: Option<Frame>,
    pending_ap: Option<wmi_runtime::ap::Capture>,
}
struct ReceiveBatch {
    permission: super::regulatory::Permission,
    source: Option<super::firmware_source::Source>,
    scan_policy: Option<Arc<wmi_runtime::ScanPolicy>>,
    coexistence: (Arc<AtomicU64>, u64),
    frames: Vec<Vec<u8>>,
}
#[cfg(any(test, feature = "kernel-test"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReceivePoint {
    AfterFrameAllocation,
    BeforeCallbackAdmission,
}
#[cfg(any(test, feature = "kernel-test"))]
type ReceiveHook = Arc<dyn Fn(ReceivePoint) + Send + Sync>;
#[derive(Clone, Copy)]
pub(super) struct RadioFeatures {
    power_save: bool,
    ap: bool,
    ap_uapsd: bool,
    ht: Option<[u8; 26]>,
    ht40: Option<[u8; 26]>,
    vht: Option<[u8; 12]>,
    offchannel_tx: bool,
    wowlan: Option<narf_wireless::WowlanSupport>,
    decap: wmi_runtime::wow::Decap,
    p2p: bool,
    /// Wiphy P2P advertisement facts; virtual netdevs inherit the home's.
    combinations: wmi_runtime::CombinationFacts,
}
impl RadioFeatures {
    fn observed<T: Hif + HostMemory + HttMemory>(radio: &Radio<T>) -> Self {
        Self {
            power_save: radio.power_save_supported(),
            ap: radio.ap_supported(),
            ap_uapsd: radio.ap_uapsd(),
            offchannel_tx: radio.offchannel_action_supported(),
            ht: radio.ht_capabilities(),
            ht40: radio.ht40_capabilities(),
            vht: radio.vht_capabilities(),
            wowlan: radio.wowlan_support(),
            decap: radio.wow_decap(),
            p2p: radio.p2p_supported(),
            combinations: radio.combination_facts(),
        }
    }
}
impl State {
    fn clear(&mut self) {
        self.pending = None;
        self.pending_ap = None;
        for _ in 0..TX_RING_N {
            if !matches!(self.tx.try_recv(), Ok(Some(_))) {
                break;
            }
        }
    }
}
pub(super) struct Device<T: Hif + HostMemory + HttMemory> {
    pub(super) radio: Arc<Mutex<Radio<T>>>,
    state: Mutex<State>,
    name: String,
    generation: u64,
    ps_supported: bool,
    ap_capable: bool,
    ap_uapsd: bool,
    mode: AtomicU8,
    mode_generation: AtomicU64,
    ap_host: ap::Host,
    wow: wowlan::Host,

    offchannel_tx: bool,
    radio_control: Arc<narf_wireless::ap_control::ExclusiveControl>,
    management_subscriptions: Arc<wmi_runtime::offchannel::Subscriptions>,
    ht_capabilities: Option<[u8; 26]>,
    ht40_capabilities: Option<[u8; 26]>,
    vht_capabilities: Option<[u8; 12]>,
    ps_request: AtomicU8,
    frequencies: Vec<u16>,
    mac: [u8; 6],
    policy: Policy,
    up: AtomicBool,
    closed: AtomicBool,
    retired: AtomicBool,
    publication: IrqSafeSpinLock<()>,
    #[cfg(any(test, feature = "kernel-test"))]
    close_on_progress: AtomicBool,
    #[cfg(any(test, feature = "kernel-test"))]
    receive_hook: IrqSafeSpinLock<Option<ReceiveHook>>,
    bssid: AtomicU64,
    rx: IrqSafeSpinLock<Option<narf_ipc::Consumer<Frame, RX_RING_N>>>,
    tx: IrqSafeSpinLock<Option<narf_ipc::Producer<Frame, TX_RING_N>>>,
    /// Owner interrupt signal shared with the service worker.
    wake: IrqSafeSpinLock<Option<Arc<super::irq::Signal>>>,
    /// TLV firmware without NO_P2P (`Radio::p2p_supported`).
    p2p_capable: bool,
    /// The netdev's registry Write cap: parent of control-only children.
    net_registration: IrqSafeSpinLock<
        Option<narf_capabilities::Cap<narf_net::NetIface, narf_capabilities::Write>>,
    >,
    /// The control-only P2P_DEVICE wdev (`interface_p2p.rs`).
    p2p_wdev: IrqSafeSpinLock<Option<Arc<p2p_wdev::P2pWdev>>>,
    /// This netdev is the P2P client (iftype 8, `interface_p2p_client.rs`):
    /// its station paths run on the client slot (`StationGuard`).
    client: bool,
    /// This netdev is the P2P GO (iftype 9): its AP START runs on its own
    /// AP/P2P_GO vdev with its own address (`Radio::go_start`) beside the
    /// managed vdev instead of replacing it.
    go: bool,
    /// nl80211 wiphy identity: the home netdev's for a P2P client.
    wiphy: u64,
    /// The wiphy's P2P advertisement facts (shared by the virtual netdevs).
    combinations: wmi_runtime::CombinationFacts,
    /// DEL_INTERFACE accepted; the worker retires the client vdev.
    deleting: AtomicBool,
}
impl<T: Hif + HostMemory + HttMemory> core::fmt::Debug for Device<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ath10kDevice")
            .field("name", &self.name)
            .field("up", &self.up)
            .finish_non_exhaustive()
    }
}
struct Attempt<'a> {
    device: &'a dyn HostClose,
    armed: bool,
}
trait HostClose: Sync {
    fn close(&self);
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.device.close();
        }
    }
}
impl<T: Hif + HostMemory + HttMemory + Send + 'static> HostClose for Device<T> {
    fn close(&self) {
        self.management_subscriptions.invalidate();
        let wdev = { self.p2p_wdev.lock().take() };
        if let Some(wdev) = wdev {
            wdev.withdraw();
        }
        {
            let _publication = self.publication.lock();
            self.closed.store(true, Ordering::Release);
            self.publish_link(None);
        }
        self.kick();
    }
}
impl<T: Hif + HostMemory + HttMemory + Send + 'static> Device<T> {
    pub(super) fn new(
        name: &str,
        mac: [u8; 6],
        radio: Arc<Mutex<Radio<T>>>,
        features: RadioFeatures,
        frequencies: Vec<u16>,
    ) -> Self {
        Self::with_policy(name, mac, radio, Policy::Installed, features, frequencies)
    }
    /// Test fixture: this device's AP controls own a GO vdev.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn into_go_for_test(mut self) -> Self {
        self.go = true;
        self.mode = AtomicU8::new(3);
        self
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn for_test(
        name: &str,
        mac: [u8; 6],
        radio: Arc<Mutex<Radio<T>>>,
        current: impl Fn() -> Option<narf_wireless::reg::RegulatoryDomain> + Send + Sync + 'static,
    ) -> Self {
        let features = radio
            .try_lock()
            .map(|radio| RadioFeatures::observed(&radio))
            .unwrap_or(RadioFeatures {
                power_save: false,
                ap: false,
                ap_uapsd: false,
                offchannel_tx: false,
                ht: None,
                ht40: None,
                vht: None,
                wowlan: None,
                decap: wmi_runtime::wow::Decap::Raw,
                p2p: false,
                combinations: wmi_runtime::CombinationFacts::NONE,
            });
        let frequencies = radio
            .try_lock()
            .map(|radio| radio.configured_channels().to_vec())
            .unwrap_or_default();
        Self::with_policy(
            name,
            mac,
            radio,
            Policy::Model(Arc::new(current)),
            features,
            frequencies,
        )
    }
    fn with_policy(
        name: &str,
        mac: [u8; 6],
        radio: Arc<Mutex<Radio<T>>>,
        policy: Policy,
        features: RadioFeatures,
        frequencies: Vec<u16>,
    ) -> Self {
        let (rx, consumer) = narf_ipc::channel();
        let (producer, tx) = narf_ipc::channel();
        Self {
            radio,
            state: Mutex::new(State {
                rx,
                tx,
                pending: None,
                pending_ap: None,
            }),
            name: name.into(),
            ps_supported: features.power_save,
            ap_capable: features.ap,
            ap_uapsd: features.ap_uapsd,
            mode: AtomicU8::new(2),
            mode_generation: AtomicU64::new(1),
            ap_host: ap::Host::new(),
            wow: wowlan::Host::new(features.wowlan, features.decap),

            offchannel_tx: features.offchannel_tx,
            radio_control: Arc::new(narf_wireless::ap_control::ExclusiveControl::new()),
            management_subscriptions: Arc::new(wmi_runtime::offchannel::Subscriptions::new()),
            ht_capabilities: features.ht,
            ht40_capabilities: features.ht40,
            vht_capabilities: features.vht,
            frequencies,
            // Submit the advertised awake default before first carrier.
            ps_request: AtomicU8::new(u8::from(features.power_save)),
            generation: NEXT_GENERATION
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                    value.checked_add(1)
                })
                .expect("ath10k interface generations exhausted"),
            mac,
            policy,
            up: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            retired: AtomicBool::new(false),
            publication: IrqSafeSpinLock::new(()),
            #[cfg(any(test, feature = "kernel-test"))]
            close_on_progress: AtomicBool::new(false),
            #[cfg(any(test, feature = "kernel-test"))]
            receive_hook: IrqSafeSpinLock::new(None),
            bssid: AtomicU64::new(0),
            rx: IrqSafeSpinLock::new(Some(consumer)),
            tx: IrqSafeSpinLock::new(Some(producer)),
            wake: IrqSafeSpinLock::new(None),
            p2p_capable: features.p2p,
            net_registration: IrqSafeSpinLock::new(None),
            p2p_wdev: IrqSafeSpinLock::new(None),
            client: false,
            go: false,
            wiphy: name_wiphy_id(name),
            combinations: features.combinations,
            deleting: AtomicBool::new(false),
        }
    }
    /// The wiphy advertises P2P (and the home netdev offers its virtual
    /// interfaces): TLV firmware without NO_P2P.
    fn p2p_advertised(&self) -> bool {
        p2p_wdev::P2P_ADVERTISED && self.combinations.p2p()
    }
    /// The radio's AP session exists and belongs to this netdev: a GO
    /// session to the GO netdev, the managed AP to the home netdev.
    fn owns_ap(&self, radio: &Radio<T>) -> bool {
        radio.ap_exists() && radio.ap_is_go() == self.go
    }
    /// The radio with this netdev's station slot current (the P2P client's
    /// inside its scope), if this owner's slot exists.
    fn try_station(&self) -> Option<wmi_runtime::StationGuard<'_, T>> {
        wmi_runtime::StationGuard::new(self.radio.try_lock()?, self.client)
    }
    /// As `try_station`, waiting for the radio; a P2P client without its
    /// vdev (not yet created or being deleted) is `Busy`.
    async fn station(&self) -> Result<wmi_runtime::StationGuard<'_, T>, WirelessError> {
        wmi_runtime::StationGuard::new(self.radio.lock().await, self.client)
            .ok_or(WirelessError::Busy)
    }
    pub(super) fn reserve_control(
        &self,
    ) -> Result<Option<Arc<dyn narf_wireless::ap_control::ApControlReservation>>, WirelessError>
    {
        if self.closed.load(Ordering::Acquire) || self.retired.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        self.radio_control.try_reserve().map(Some)
    }
    /// Kick the service worker (host TX / power-save request).
    fn kick(&self) {
        let wake = self.wake.lock().clone();
        if let Some(wake) = wake {
            wake.raise();
        }
    }
    /// The real worker retains cancellation cleanup after the public scan
    /// future has gone away. The radio mutex excludes live scan/recovery;
    /// retire_host closes this path before a successor may touch hardware.
    pub(super) async fn cleanup_failed_scan(&self) -> Result<bool, Error> {
        let radio = if self.closed.load(Ordering::Acquire) {
            self.radio.lock().await
        } else {
            let Some(radio) = self.radio.try_lock() else {
                return Ok(false);
            };
            radio
        };
        let Some(mut radio) = wmi_runtime::StationGuard::new(radio, self.client) else {
            return Ok(false);
        };
        if self.retired.load(Ordering::Acquire) {
            return Ok(false);
        }
        // The sibling netdev's scan or ROC is that netdev's to clean up.
        if radio.scan_on_sibling() {
            return Ok(false);
        }
        if !self.client {
            radio.ap_prune_staging();
        }
        // A GO session is the GO netdev's worker's to tear down.
        if !self.client && radio.ap_exists() && !radio.ap_is_go() {
            if !self.closed.load(Ordering::Acquire) && !radio.ap_abandoned() {
                return Ok(false);
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
            self.ap_cleanup_complete()?;
            drop(radio);
            self.ap_retire_metadata();
            // The same physical worker services a later explicitly admitted
            // BSS. Its old control generation and copied native owner stay
            // retired; failed/uncertain terminal cleanup takes PCI recovery.
            return Ok(false);
        }
        if self.closed.load(Ordering::Acquire) && !self.client {
            radio.ap_retire_staging();
        }
        if !radio.scan_in_progress() {
            if radio.failed_station_pending() {
                self.close();
                radio.retire_station_receive();
                self.state.lock().await.clear();
                return Err(Error::Failed);
            }
            return Ok(false);
        }
        if self.closed.load(Ordering::Acquire) {
            radio.fail_station_data();
        }
        if !radio.failed_scan_pending() {
            return Ok(false);
        }
        self.close();
        radio.retire_station_receive();
        self.state.lock().await.clear();
        radio
            .abort_failed_scan(&|| {
                if self.retired.load(Ordering::Acquire) {
                    Err(Error::Failed)
                } else {
                    Ok(())
                }
            })
            .await?;
        Ok(true)
    }
    /// One production-used cleanup decision. Only a proven AP teardown may
    /// reopen this same physical worker; old station/scan closure terminates.
    pub(in crate::ath10k) async fn cleanup_worker_step(&self) -> Result<bool, Error> {
        let terminal = self.cleanup_failed_scan().await?;
        Ok(terminal || self.closed.load(Ordering::Acquire) || self.retired.load(Ordering::Acquire))
    }
    fn link(&self, peer: Option<[u8; 6]>) {
        let _publication = self.publication.lock();
        self.publish_link(peer);
    }
    // Caller holds publication; close and a previously sampled peer can never
    // interleave their BSSID/carrier/netdev metadata writes.
    fn publish_link(&self, peer: Option<[u8; 6]>) {
        if self.retired.load(Ordering::Acquire) {
            return;
        }
        let peer = peer.filter(|_| !self.closed.load(Ordering::Acquire));
        let mut packed = [0; 8];
        if let Some(peer) = peer {
            packed[..6].copy_from_slice(&peer);
            packed[7] = 1;
        }
        self.bssid
            .store(u64::from_le_bytes(packed), Ordering::Release);
        let up = peer.is_some();
        let was = self.up.swap(up, Ordering::AcqRel);
        // Physical carrier preserves operator-controlled IFF_UP and never
        // invokes an administrative open/stop hook under retained locks.
        narf_net::iface::set_link_metadata(&self.name, up, None, None);
        if was && !up && self.mode.load(Ordering::Acquire) == 2 {
            narf_wireless::nl80211::notify_disconnect(&self.name, 1, false);
        }
    }
    pub(super) fn enqueue(&self, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
        if self.closed.load(Ordering::Acquire)
            || !self.up.load(Ordering::Acquire)
            || !(if self.mode.load(Ordering::Acquire) == 3 {
                ap::ethernet(bytes)
            } else {
                admitted(bytes, self.mac)
            })
            || meta.csum_l4.is_some()
            || meta.tso_mss.is_some()
            || meta.vlan_tag.is_some()
        {
            return Err(());
        }
        let memory = narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
            .map_err(|_| ())?;
        let mut frame = Frame::new(memory, bytes.len() as u32);
        frame.payload_mut().copy_from_slice(bytes);
        frame.set_tx_meta(meta);
        self.tx
            .lock()
            .as_mut()
            .ok_or(())?
            .try_send(frame)
            .map_err(|_| ())?;
        self.kick();
        Ok(())
    }
    pub(super) fn enqueue_generation(
        &self,
        generation: u64,
        bytes: &[u8],
        meta: narf_net::TxMeta,
    ) -> Result<(), ()> {
        if generation != self.generation {
            return Err(());
        }
        self.enqueue(bytes, meta)
    }
    pub(super) fn phy_capabilities(
        &self,
        band: u32,
    ) -> Option<narf_wireless::iface::PhyCapabilities> {
        if self.mode.load(Ordering::Acquire) == 3 {
            return None;
        }
        if !self
            .frequencies
            .iter()
            .any(|frequency| band == 2400 && *frequency < 3000 || band == 5000 && *frequency > 3000)
        {
            return None;
        }
        Some(narf_wireless::iface::PhyCapabilities {
            ht: if band == 5000 {
                self.ht40_capabilities?
            } else {
                self.ht_capabilities?
            },
            vht: if band == 5000 {
                self.vht_capabilities
            } else {
                None
            },
        })
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn management_subscriptions_for_test(
        &self,
    ) -> Arc<wmi_runtime::offchannel::Subscriptions> {
        self.management_subscriptions.clone()
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn radio_generation_for_test(&self) -> Option<core::num::NonZeroU64> {
        if self.closed.load(Ordering::Acquire) || self.retired.load(Ordering::Acquire) {
            None
        } else {
            core::num::NonZeroU64::new(self.mode_generation.load(Ordering::Acquire))
        }
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn generation_for_test(&self) -> u64 {
        self.generation
    }
    pub(super) fn retire_host(&self) {
        self.management_subscriptions.invalidate();
        let wdev = { self.p2p_wdev.lock().take() };
        if let Some(wdev) = wdev {
            wdev.withdraw();
        }
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
        narf_wireless::registry::unregister(&self.name);
        narf_net::registry().unregister(&self.name);
        // Keep the netdev for the next generation (mac80211
        // `ieee80211_restart_hw` never unregisters it): the name is reserved
        // atomically with removal, so no other wlan%d allocation can take it,
        // and ifindex/admin state/addresses survive a `rebind_name`.
        if !narf_net::iface::retire_for_rebind(&self.name) {
            narf_net::iface::reserve_name(&self.name);
        }
    }
    pub(super) fn name(&self) -> &str {
        &self.name
    }
    pub(super) fn request_power_save(&self, enabled: bool) -> Result<(), i32> {
        if self.mode.load(Ordering::Acquire) == 3 {
            return Err(-95);
        }
        if !self.ps_supported {
            return Err(-95);
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(-19);
        }
        self.ps_request
            .store(if enabled { 2 } else { 1 }, Ordering::Release);
        self.kick();
        Ok(())
    }
    /// Send a queued protected SA Query Response (PMF) produced by the
    /// synchronous drain; a failure closes the link like other data faults.
    pub(super) async fn flush_management(&self) -> Result<(), WirelessError> {
        if self.mode.load(Ordering::Acquire) == 3 {
            return Ok(());
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        let Some(mut radio) = self.try_station() else {
            return Ok(());
        };
        if radio.roc_active() {
            return Ok(());
        }
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        let result = match self.policy.current() {
            Ok(domain) => {
                wmi_runtime::checked_policy(radio.flush_station_management(&domain), &|| {
                    if self.closed.load(Ordering::Acquire) {
                        return Err(Error::Failed);
                    }
                    let now = self.policy.current()?;
                    if now.country_code != domain.country_code || now.rules != domain.rules {
                        return Err(Error::Unsupported);
                    }
                    Ok(())
                })
                .await
            }
            Err(cause) => Err(cause),
        };
        if let Err(cause) = result {
            radio.fail_station_data();
            return Err(error(cause));
        }
        attempt.armed = false;
        Ok(())
    }
    pub(super) async fn apply_power_save(&self) -> Result<(), WirelessError> {
        if self.mode.load(Ordering::Acquire) == 3 {
            return Ok(());
        }
        let request = self.ps_request.load(Ordering::Acquire);
        if request == 0 {
            return Ok(());
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        let Some(mut radio) = self.try_station() else {
            return Ok(());
        };
        // Firmware owns scan power-save dwell. Keep an operator PS request
        // queued until the matched scan terminal and home inventory restore.
        if radio.scan_in_progress() {
            return Ok(());
        }
        let enabled = request == 2;
        if radio.station_link().is_none() {
            return Ok(());
        }
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        if let Err(cause) = self
            .policy
            .current()
            .and_then(|domain| radio.check_data_policy(&domain))
        {
            radio.fail_station_data();
            return Err(error(cause));
        }
        if radio.submitted_power_save() == Some(enabled) {
            attempt.armed = false;
            return Ok(());
        }
        let result = radio
            .set_station_power_save(enabled, || {
                if self.closed.load(Ordering::Acquire) {
                    return Err(Error::Failed);
                }
                self.policy.current()
            })
            .await;
        if let Err(cause) = result {
            radio.fail_station_data();
            return Err(error(cause));
        }
        attempt.armed = false;
        Ok(())
    }
    fn progress(&self) -> Option<ReceiveBatch> {
        let mut radio = self.try_station()?;
        let mut state = self.state.try_lock()?;
        if self.closed.load(Ordering::Acquire) {
            // Host closure precedes the control path's async mutex acquire.
            // A worker here must not poison an otherwise healthy radio before
            // that path can send native DOWN/DELETE/STOP.
            radio.retire_station_receive();
            state.clear();
            return None;
        }
        #[cfg(any(test, feature = "kernel-test"))]
        if self.close_on_progress.swap(false, Ordering::AcqRel) {
            self.close();
        }
        let result = {
            // Serialize actual native publication with host close, including
            // EAPOL generated by RX progress. No await or stack callback is here.
            let _publication = self.publication.lock();
            if self.closed.load(Ordering::Acquire) {
                radio.retire_station_receive();
                state.clear();
                return None;
            }
            if radio.roc_active() {
                return None;
            }
            (|| {
                if !radio.has_station_data() {
                    // Only an actual opted-in physical host-vote owner gets
                    // passive maintenance. No peer/data owner or publication
                    // is inferred from a PM defer or an empty receive prefix.
                    // The radio's host vote belongs to the home netdev.
                    if !self.client {
                        radio.poll_passive_host_idle()?;
                    }
                    return Ok(None);
                }
                // Sampling under the publication gate precedes consuming any
                // host TX or publishing generated security replies to native
                // DMA. A changed ceiling must match the programmed channel.
                let domain = self.policy.current()?;
                let frames = radio.poll_ethernet_now(&domain)?;
                // A later event in this drain may have started a rekey after
                // earlier data was decoded. Neither those buffered frames nor
                // host TX can bypass the port's final current state.
                let domain = self.policy.current()?;
                radio.check_data_policy(&domain)?;
                let Some(permission) = radio.data_permission() else {
                    // An established authenticated rekey temporarily closes
                    // DATA, not the still-associated physical carrier. Initial
                    // authorization is published only by associate's receipt.
                    return Ok(None);
                };
                let source = radio.htt.wmi.htc.transport.current_sources();
                super::firmware_source::invoke(source.as_ref(), || {
                    self.publish_link(radio.station_link().map(|link| link.bssid))
                })
                .map_err(|_| Error::Failed)?;
                if state.pending.is_none() {
                    for _ in 0..16 {
                        let Ok(Some(frame)) = state.tx.try_recv() else {
                            break;
                        };
                        if admitted(frame.payload(), self.mac)
                            && frame.tx_meta().csum_l4.is_none()
                            && frame.tx_meta().tso_mss.is_none()
                            && frame.tx_meta().vlan_tag.is_none()
                        {
                            state.pending = Some(frame);
                            break;
                        }
                    }
                }
                if let Some(frame) = state.pending.as_ref() {
                    match radio.begin_ethernet(&domain, frame.payload()) {
                        Ok(_) => state.pending = None,
                        Err(Error::Htt(super::htt_runtime::Error::Busy)) => {}
                        Err(error) => return Err(error),
                    }
                }
                for bytes in &frames {
                    if let Ok(memory) =
                        narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
                    {
                        let mut frame = Frame::new(memory, bytes.len() as u32);
                        frame.payload_mut().copy_from_slice(bytes);
                        #[cfg(any(test, feature = "kernel-test"))]
                        self.receive_point_for_test(ReceivePoint::AfterFrameAllocation);
                        radio.check_data_policy(&self.policy.current()?)?;
                        if radio.data_permission().as_ref() != Some(&permission) {
                            return Ok(None);
                        }
                        super::firmware_source::invoke(source.as_ref(), || {
                            permission.check(&self.policy.current()?)?;
                            let _ = state.rx.try_send(frame);
                            Ok::<_, Error>(())
                        })
                        .map_err(|_| Error::Failed)??;
                    }
                }
                Ok(Some(ReceiveBatch {
                    permission,
                    source,
                    scan_policy: radio.scan_policy(),
                    coexistence: radio.coexistence_capture(),
                    frames,
                }))
            })()
        };
        match result {
            Ok(batch) => {
                if self.closed.load(Ordering::Acquire) {
                    None
                } else {
                    batch
                }
            }
            Err(_) => {
                radio.fail_station_data();
                state.clear();
                self.close();
                None
            }
        }
    }
    pub(super) fn drain(&self) -> bool {
        if self.mode.load(Ordering::Acquire) == 3 {
            return self.ap_drain();
        }
        let Some(batch) = self.progress() else {
            return false;
        };
        if self.closed.load(Ordering::Acquire) {
            return false;
        }
        let progressed = !batch.frames.is_empty();
        for mut frame in batch.frames {
            // Release the native owner before calling the network stack: an
            // ARP/ND reply may re-enter this same interface synchronously.
            #[cfg(any(test, feature = "kernel-test"))]
            self.receive_point_for_test(ReceivePoint::BeforeCallbackAdmission);
            let admission: Result<bool, Error> = (|| {
                if self.closed.load(Ordering::Acquire) {
                    return Ok(false);
                }
                let Some(radio) = self.try_station() else {
                    return Ok(false);
                };
                radio.check_data_policy(&self.policy.current()?)?;
                Ok(radio.data_permission().as_ref() == Some(&batch.permission))
            })();
            match admission {
                Ok(true) => {}
                Ok(false) => break,
                Err(_) => {
                    self.close();
                    break;
                }
            }
            let published = super::firmware_source::invoke(batch.source.as_ref(), || {
                let domain = self.policy.current()?;
                batch.permission.check(&domain)?;
                if let Some(scan) = &batch.scan_policy {
                    scan.check(&domain)?;
                }
                if self.closed.load(Ordering::Acquire) {
                    return Err(Error::Failed);
                }
                if batch.coexistence.0.load(Ordering::Acquire) != batch.coexistence.1 {
                    return Ok(());
                }
                narf_net::iface::on_rx_frame_from(&self.name, &mut frame);
                Ok::<_, Error>(())
            });
            if !matches!(published, Ok(Ok(()))) {
                self.close();
                break;
            }
        }
        progressed
    }
    /// Validate a scan request against this radio and resolve its channel
    /// list (`implicit`: every supported frequency, filtered later by the
    /// current regulatory domain).
    pub(super) fn scan_frequencies(
        &self,
        request: &mut ScanRequest,
    ) -> Result<(Vec<u16>, bool), WirelessError> {
        if request.random_mac.is_some()
            || request.colocated_6ghz
            || request.duration_tu.is_some()
            || request.duration_mandatory
            || (!request.active && !request.extra_ies.is_empty())
            || request.ssids.len() > wmi_runtime::MAX_SCAN_SSIDS
            || request.ssids.iter().any(|s| s.len() > 32)
        {
            return Err(WirelessError::NotSupported);
        }
        wmi_runtime::validate_probe_ies(&request.extra_ies).map_err(|err| match err {
            Error::Malformed => WirelessError::InvalidArgs,
            err => error(err),
        })?;
        if request.active && request.ssids.is_empty() {
            request
                .ssids
                .try_reserve(1)
                .map_err(|_| error(Error::NoMemory))?;
            request.ssids.push(Vec::new());
        }
        let implicit = request.frequencies_mhz.is_empty() && request.channels.is_empty();
        let frequencies = if !request.frequencies_mhz.is_empty() {
            request
                .frequencies_mhz
                .iter()
                .map(|f| u16::try_from(*f).map_err(|_| WirelessError::InvalidArgs))
                .collect::<Result<Vec<_>, _>>()?
        } else if !request.channels.is_empty() {
            request
                .channels
                .iter()
                .map(|ch| {
                    u8::try_from(*ch)
                        .ok()
                        .and_then(narf_wireless::association::channel::frequency)
                        .and_then(|f| u16::try_from(f).ok())
                        .ok_or(WirelessError::InvalidArgs)
                })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            self.frequencies.clone()
        };
        if frequencies.is_empty()
            || frequencies.iter().any(|f| {
                !super::regulatory::Permission::station_frequency(*f)
                    || !self.frequencies.contains(f)
            })
        {
            return Err(WirelessError::NotSupported);
        }
        Ok((frequencies, implicit))
    }
    pub(super) async fn scan(
        &self,
        mut request: ScanRequest,
    ) -> Result<Vec<BssInfo>, WirelessError> {
        if self.mode.load(Ordering::Acquire) != 2 {
            return Err(WirelessError::NotSupported);
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        let (mut frequencies, implicit) = self.scan_frequencies(&mut request)?;
        let mut radio = self.station().await?;
        if radio.roc_active() {
            return Err(WirelessError::Busy);
        }
        if radio.prepared_peer().is_some() && radio.station_link().is_none() {
            return Err(WirelessError::Busy);
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        let domain = self.policy.current().map_err(error)?;
        if implicit {
            frequencies.retain(|f| {
                receive_permission(&domain, &[*f]).is_ok()
                    && (!request.active || radio.active_frequency_allowed(&domain, *f))
            });
        }
        receive_permission(&domain, &frequencies).map_err(error)?;
        let associated = radio.station_link().is_some();
        // The associated dwell owner is the managed vdev's only.
        if self.client && associated {
            return Err(WirelessError::Busy);
        }
        let active = if request.active {
            Some(
                radio
                    .prepare_active_scan(&frequencies, &request.ssids, &domain)
                    .and_then(|plan| plan.with_extra_ies(&request.extra_ies))
                    .map_err(error)?,
            )
        } else if associated {
            Some(
                radio
                    .prepare_associated_passive_scan(&frequencies, &domain)
                    .map_err(error)?,
            )
        } else {
            None
        };
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        let current = || {
            if self.closed.load(Ordering::Acquire) {
                return Err(Error::Failed);
            }
            self.policy.current()
        };
        let report = if associated {
            radio
                .begin_associated_scan(active.ok_or(WirelessError::HardwareError)?, current)
                .await
                .map_err(|cause| {
                    radio.fail_station_data();
                    error(cause)
                })?;
            // Dwell owns receipts in Radio, not this mutex guard. The same
            // normal data path can now transmit queued host packets and
            // publish RX to the stack with all owner locks released.
            drop(radio);
            self.kick();
            loop {
                current().map_err(error)?;
                self.drain();
                {
                    let mut radio = self.station().await?;
                    if radio
                        .associated_scan_complete(&current().map_err(error)?)
                        .map_err(error)?
                    {
                        break radio.finish_associated_scan(current).await.map_err(error);
                    }
                }
                narf_scheduler::yield_now().await;
            }
        } else if let Some(plan) = active {
            radio.active_scan(plan, current).await.map_err(error)
        } else {
            radio
                .passive_scan_current(&frequencies, current)
                .await
                .map_err(error)
        }?;
        let result = report
            .bss
            .into_iter()
            .filter(|b| {
                request.ssids.is_empty()
                    || request.ssids.iter().any(|s| s.is_empty() || *s == b.ssid)
            })
            .map(bss_info)
            .collect();
        attempt.armed = false;
        Ok(result)
    }
    pub(super) async fn associate(&self, request: AssociateRequest) -> Result<(), WirelessError> {
        self.associate_inner(request, || {
            let mut nonce = [0; 32];
            narf_crypto::try_fill_random_bytes(&mut nonce)
                .ok()
                .map(|()| nonce)
        })
        .await
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) async fn associate_for_test(
        &self,
        request: AssociateRequest,
        nonce: [u8; 32],
    ) -> Result<(), WirelessError> {
        self.associate_inner(request, || Some(nonce)).await
    }
    async fn associate_inner(
        &self,
        request: AssociateRequest,
        nonce: impl FnMut() -> Option<[u8; 32]>,
    ) -> Result<(), WirelessError> {
        // wpa_supplicant's network block for this connection, kept for a
        // recovered generation once the association completes.
        let profile = narf_wireless::reconnect::Profile::capture(&request);
        if self.mode.load(Ordering::Acquire) != 2 {
            return Err(WirelessError::NotSupported);
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        if self.up.load(Ordering::Acquire) {
            return Err(WirelessError::Busy);
        }
        if u16::try_from(request.frequency_mhz).ok().is_none_or(|f| {
            !super::regulatory::Permission::station_frequency(f) || !self.frequencies.contains(&f)
        }) || narf_wireless::association::channel::from_frequency(request.frequency_mhz)
            .map(u32::from)
            != Some(request.channel)
        {
            return Err(WirelessError::NotSupported);
        }
        // WPA3-Personal runs host SAE and PMF; its PMK comes from SAE.
        let (mode, pmk, password) = match &request.security {
            SecurityConfig::Open => (narf_wireless::association::SecurityMode::Open, None, None),
            SecurityConfig::Wpa2 { psk } => (
                narf_wireless::association::SecurityMode::Wpa2Psk,
                Some(zeroize::Zeroizing::new(*psk)),
                None,
            ),
            SecurityConfig::Wpa3 { password } if !password.is_empty() => (
                narf_wireless::association::SecurityMode::Wpa3Sae {
                    pwe: narf_wireless::association::SaePwe::Both,
                },
                None,
                Some(zeroize::Zeroizing::new(password.clone())),
            ),
            _ => return Err(WirelessError::NotSupported),
        };
        let mut radio = self.station().await?;
        if radio.roc_active() {
            return Err(WirelessError::Busy);
        }
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        self.state.lock().await.clear();
        if self.closed.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        let domain = self.policy.current().map_err(error)?;
        // OBSS may select an actual40 or actual20 owner. Complete that
        // receive-only preflight before capturing the immutable occupied
        // permission used by every subsequent native association wait.
        radio
            .prepare_coexistence(
                &domain,
                request.bssid,
                request.frequency_mhz as u16,
                &|| {
                    if self.closed.load(Ordering::Acquire) {
                        return Err(Error::Failed);
                    }
                    let current = self.policy.current()?;
                    if current.country_code != domain.country_code || current.rules != domain.rules
                    {
                        return Err(Error::Unsupported);
                    }
                    Ok(())
                },
            )
            .await
            .map_err(error)?;
        let permission = radio
            .station_permission(&domain, request.bssid, request.frequency_mhz as u16)
            .map_err(error)?;
        let validate = || {
            if self.closed.load(Ordering::Acquire) {
                return Err(Error::Failed);
            }
            permission.check(&self.policy.current()?)
        };
        wmi_runtime::checked_policy(
            radio.prepare_station_checked(
                &domain,
                request.bssid,
                request.frequency_mhz as u16,
                &validate,
            ),
            &validate,
        )
        .await
        .map_err(error)?;
        match password.as_deref() {
            Some(password) => {
                wmi_runtime::checked_policy(
                    radio.associate_station_sae_checked(
                        &domain,
                        &request.ssid,
                        password,
                        &request.ie,
                        &validate,
                    ),
                    &validate,
                )
                .await
            }
            None => {
                wmi_runtime::checked_policy(
                    radio.associate_station_checked(
                        &domain,
                        &request.ssid,
                        mode,
                        &request.ie,
                        &validate,
                    ),
                    &validate,
                )
                .await
            }
        }
        .map_err(error)?;
        let link = wmi_runtime::checked_policy(
            radio.start_data_with_nonce_checked(&domain, pmk.as_deref(), nonce, &validate),
            &validate,
        )
        .await
        .map_err(error)?;
        let domain = self.policy.current().map_err(error)?;
        radio.check_data_policy(&domain).map_err(error)?;
        let ps_request = self.ps_request.load(Ordering::Acquire);
        if ps_request != 0 {
            let result = radio
                .set_station_power_save(ps_request == 2, || {
                    if self.closed.load(Ordering::Acquire) {
                        return Err(Error::Failed);
                    }
                    self.policy.current()
                })
                .await;
            if let Err(cause) = result {
                radio.fail_station_data();
                return Err(error(cause));
            }
        }
        if self.closed.load(Ordering::Acquire) {
            radio.fail_station_data();
            return Err(WirelessError::HardwareError);
        }
        radio
            .check_data_policy(&self.policy.current().map_err(error)?)
            .map_err(error)?;
        let source = radio.htt.wmi.htc.transport.current_sources();
        super::firmware_source::invoke(source.as_ref(), || self.link(Some(link.bssid)))
            .map_err(|_| WirelessError::HardwareError)?;
        attempt.armed = false;
        match profile {
            Some(profile) => {
                narf_wireless::reconnect::retain(&self.name, self.reconnect_owner(), profile)
            }
            None => narf_wireless::reconnect::forget(&self.name),
        }
        Ok(())
    }
    /// Reconnect a rebound generation from the profile its predecessor
    /// retained: Linux `ieee80211_sta_restart` reports the connection lost
    /// after a hardware restart the driver cannot reconfigure, and
    /// wpa_supplicant scans for and re-associates to the same network with
    /// the retained PSK/SAE password and a fresh RSNA. One attempt; the
    /// profile is retained again only by a completed association. `false`
    /// when nothing was retained or the operator left the netdev down.
    pub(super) async fn replay_retained(&self) -> Result<bool, WirelessError> {
        self.replay_retained_inner(|| {
            let mut nonce = [0; 32];
            narf_crypto::try_fill_random_bytes(&mut nonce)
                .ok()
                .map(|()| nonce)
        })
        .await
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) async fn replay_retained_for_test(
        &self,
        nonce: [u8; 32],
    ) -> Result<bool, WirelessError> {
        self.replay_retained_inner(|| Some(nonce)).await
    }
    async fn replay_retained_inner(
        &self,
        nonce: impl FnMut() -> Option<[u8; 32]>,
    ) -> Result<bool, WirelessError> {
        let Some(profile) = narf_wireless::reconnect::take(&self.name, self.reconnect_owner())
        else {
            return Ok(false);
        };
        if !narf_net::iface::lookup(&self.name).is_some_and(|i| i.link_up) {
            // wpa_supplicant does not connect a down interface; keep the
            // block for a later generation.
            narf_wireless::reconnect::retain(&self.name, self.reconnect_owner(), profile);
            return Ok(false);
        }
        let found = self
            .scan(ScanRequest {
                ssids: alloc::vec![profile.ssid().to_vec()],
                frequencies_mhz: alloc::vec![profile.frequency_mhz()],
                channels: alloc::vec![profile.channel()],
                active: false,
                random_mac: None,
                colocated_6ghz: false,
                duration_tu: None,
                duration_mandatory: false,
                extra_ies: Vec::new(),
            })
            .await?;
        if !found.iter().any(|bss| {
            bss.bssid == profile.bssid()
                && bss.frequency_mhz == profile.frequency_mhz()
                && bss.ssid == profile.ssid()
        }) {
            return Err(WirelessError::Timeout);
        }
        self.associate_inner(profile.request(), nonce).await?;
        Ok(true)
    }
    /// This radio's identity for its retained network block.
    pub(super) fn reconnect_owner(&self) -> narf_wireless::reconnect::Owner {
        reconnect_owner(self.mac)
    }
    pub(super) async fn disassociate(&self) -> Result<(), WirelessError> {
        if self.mode.load(Ordering::Acquire) != 2 {
            return Err(WirelessError::NotSupported);
        }
        // An operator disconnect ends the network block's automatic reuse.
        narf_wireless::reconnect::forget(&self.name);
        self.close();
        let mut radio = self.station().await?;
        self.state.lock().await.clear();
        if self.retired.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        if radio.scan_in_progress() {
            // The retained worker owns exact scan STOP and subsequent vdev
            // teardown. Never submit DELETE while firmware still scans, or
            // move its continuation into this cancellable public waiter.
            radio.fail_station_data();
            self.kick();
            return Err(WirelessError::Busy);
        }
        if radio.station_retired() {
            return Ok(());
        }
        radio.disconnect_station().await.map(|_| ()).map_err(error)
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn close_before_lock_for_test(&self) {
        self.close();
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn close_mid_progress_for_test(&self) {
        self.close_on_progress.store(true, Ordering::Release);
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn set_receive_hook_for_test(
        &self,
        hook: impl Fn(ReceivePoint) + Send + Sync + 'static,
    ) {
        *self.receive_hook.lock() = Some(Arc::new(hook));
    }
    #[cfg(any(test, feature = "kernel-test"))]
    fn receive_point_for_test(&self, point: ReceivePoint) {
        let hook = { self.receive_hook.lock().clone() };
        if let Some(hook) = hook {
            hook(point);
        }
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn callback_locks_available_for_test(&self) -> bool {
        self.radio.try_lock().is_some()
            && self.state.try_lock().is_some()
            && self.publication.try_lock().is_some()
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn stale_link_after_close_for_test(&self, peer: [u8; 6]) {
        self.close();
        self.link(Some(peer));
    }
}
fn admitted(bytes: &[u8], own: [u8; 6]) -> bool {
    (14..=1514).contains(&bytes.len())
        && bytes[6..12] == own
        && bytes[..6] != [0; 6]
        && u16::from_be_bytes([bytes[12], bytes[13]]) >= 0x600
        && !matches!(
            u16::from_be_bytes([bytes[12], bytes[13]]),
            0x888e | 0x80f3 | 0x8137
        )
}
fn error(value: Error) -> WirelessError {
    match value {
        Error::Unsupported => WirelessError::NotSupported,
        Error::Timeout => WirelessError::Timeout,
        Error::Htt(super::htt_runtime::Error::Busy) => WirelessError::Busy,
        _ => WirelessError::HardwareError,
    }
}
impl<T: Hif + HostMemory + HttMemory + Send + 'static> Interface for Device<T> {
    fn name(&self) -> &str {
        &self.name
    }
    fn mac(&self) -> [u8; 6] {
        self.mac
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        !self.closed.load(Ordering::Acquire) && self.up.load(Ordering::Acquire)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<narf_ipc::Consumer<Frame, RX_RING_N>>> {
        &self.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<narf_ipc::Producer<Frame, TX_RING_N>>> {
        &self.tx
    }
}
pub(super) type Native = Device<super::boot::PciBoot>;
/// The nl80211 view of one scan-report BSS.
pub(super) fn bss_info(b: wmi_runtime::ScanBss) -> BssInfo {
    let secured = b.capability & 16 != 0;
    BssInfo {
        bssid: b.bssid,
        ssid: b.ssid,
        channel: narf_wireless::association::channel::from_frequency(u32::from(b.frequency))
            .map(u32::from)
            .unwrap_or(0),
        frequency_mhz: u32::from(b.frequency),
        rssi: i8::MIN,
        security: if secured {
            narf_wireless::scan::BssSecurity::Wpa2
        } else {
            narf_wireless::scan::BssSecurity::Open
        },
    }
}
/// `WirelessNetIface::wiphy_id`'s default for a netdev name (FNV-1a), kept
/// as the home netdev's identity and inherited by its P2P client netdev.
fn name_wiphy_id(name: &str) -> u64 {
    name.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}
/// ath10k's reconnect identity: the family and the radio's permanent MAC
/// (firmware/OTP `SERVICE_READY` address), unchanged across recovery.
fn reconnect_owner(mac: [u8; 6]) -> narf_wireless::reconnect::Owner {
    narf_wireless::reconnect::Owner {
        family: "ath10k",
        permanent_mac: mac,
    }
}
static ACTIVE: IrqSafeSpinLock<Option<Arc<Native>>> = IrqSafeSpinLock::new(None);
/// The interface name retired by the last recovery/suspend generation.
static REBIND: IrqSafeSpinLock<Option<String>> = IrqSafeSpinLock::new(None);
/// Record the retired generation's name for the next publication.
pub(super) fn remember_rebind(name: &str) {
    *REBIND.lock() = Some(String::from(name));
}
/// The next generation's name: the retired `wlan%d` while
/// `narf_net::iface::rebind_name` still holds it, else a fresh one. The
/// flag reports a rebind, whose restored operator state is kept.
pub(super) fn generation_name() -> (&'static str, bool) {
    match REBIND
        .lock()
        .take()
        .and_then(|name| narf_net::iface::rebind_name(&name))
    {
        Some(name) => (name, true),
        None => (narf_net::iface::reserve_name("wlan%d"), false),
    }
}
fn send(generation: u64, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let active = ACTIVE.lock().clone();
    let device = match active.filter(|d| d.generation == generation) {
        Some(device) => device,
        None => p2p_client::current()
            .filter(|d| d.generation == generation)
            .or_else(p2p_go::current)
            .ok_or(())?,
    };
    device.enqueue_generation(generation, bytes, meta)
}
/// Remove only this physical generation. Its retired name remains reserved so
/// late old-owner carrier updates cannot address a new driver's registration.
pub(super) fn retire(radio: &Arc<Mutex<Radio<super::boot::PciBoot>>>) {
    let mut active = ACTIVE.lock();
    let Some(device) = active.as_ref().filter(|d| Arc::ptr_eq(&d.radio, radio)) else {
        return;
    };
    let device = device.clone();
    *active = None;
    drop(active);
    p2p_client::retire(radio);
    p2p_go::retire(radio);
    device.retire_host();
    remember_rebind(device.name());
}
/// The published station of exactly this radio generation, if any.
pub(super) fn active_for(radio: &Arc<Mutex<Radio<super::boot::PciBoot>>>) -> Option<Arc<Native>> {
    ACTIVE
        .lock()
        .as_ref()
        .filter(|d| Arc::ptr_eq(&d.radio, radio))
        .cloned()
}
fn drain() -> bool {
    let device = ACTIVE.lock().clone();
    let home = device.is_some_and(|d| d.drain());
    let client = p2p_client::current().is_some_and(|d| d.drain());
    let go = p2p_go::current().is_some_and(|d| d.drain());
    home || client || go
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Admission {
    Ready,
    PendingAssets,
}
pub(super) fn classify_domain_admission(
    result: Result<narf_wireless::reg::RegulatoryDomain, narf_wireless::reg::policy::Error>,
    has_loader_authority: bool,
) -> Result<Admission, Error> {
    match result {
        Ok(_) => Ok(Admission::Ready),
        Err(narf_wireless::reg::policy::Error::Firmware(
            narf_firmware::FirmwareError::NotFound,
        )) => Ok(Admission::PendingAssets),
        Err(narf_wireless::reg::policy::Error::Authority) if !has_loader_authority => {
            Ok(Admission::PendingAssets)
        }
        Err(_) => Err(Error::Unsupported),
    }
}
fn check_admission() -> Result<Admission, Error> {
    if classify_domain_admission(
        narf_wireless::reg::db::ensure_domain(),
        narf_firmware::trusted_loader_authority().is_some(),
    )? == Admission::PendingAssets
    {
        return Ok(Admission::PendingAssets);
    }
    let Some(root) = narf_net::trusted_net_authority() else {
        return Ok(Admission::PendingAssets);
    };
    root.derive::<narf_capabilities::Write>()
        .map_err(|_| Error::Unsupported)?;
    Ok(Admission::Ready)
}
fn publish_with_mac(
    radio: Arc<Mutex<Radio<super::boot::PciBoot>>>,
    mac: [u8; 6],
    quarantine: &AtomicBool,
    features: RadioFeatures,
    frequencies: Vec<u16>,
    wake: (Arc<super::irq::Signal>, bool),
) -> Result<Arc<Native>, Error> {
    narf_wireless::reg::db::ensure_domain().map_err(|_| Error::Unsupported)?;
    let authority = narf_net::trusted_net_authority()
        .and_then(|cap| cap.derive().ok())
        .ok_or(Error::Unsupported)?;
    let mut active = ACTIVE.lock();
    admit_generation(quarantine, || {
        if active.is_some() {
            return Err(Error::Failed);
        }
        let (name, rebound) = generation_name();
        let device = Arc::new(Device::new(name, mac, radio, features, frequencies));
        let registration = narf_net::registry()
            .register(&authority, Registered(device.clone()))
            .map_err(|_| Error::Unsupported)?;
        *device.net_registration.lock() = Some(registration);
        *active = Some(device.clone());
        narf_net::iface::register_with_context(name, mac, device.generation, send);
        if !rebound {
            // A rebound netdev keeps the operator's IFF_UP across recovery.
            narf_net::iface::set_link_state(name, false);
        }
        narf_net::iface::set_link_metadata(name, false, None, None);
        narf_net::iface::install_rx_drain(drain);
        narf_wireless::registry::register(device.clone());
        if rebound && narf_wireless::reconnect::retained(name, reconnect_owner(mac)) {
            let replay = device.clone();
            narf_scheduler::spawn(async move {
                let _ = replay.replay_retained().await;
            });
        }
        let (signal, delivered) = wake;
        *device.wake.lock() = Some(signal.clone());
        *device.ap_host.wake.signal.lock() = Some(signal.clone());
        let worker = device.clone();
        // NAPI-equivalent service: wait for a CE/firmware vector, a host TX
        // or power-save kick, or the bounded backstop; re-run at once while
        // a drain made progress (Linux `napi_schedule` when work remains).
        narf_scheduler::spawn(async move {
            loop {
                if worker.service_offchannel().await.is_err() {
                    super::pci::scan_cleanup_failed(worker.radio.clone());
                    break;
                }
                match worker.cleanup_worker_step().await {
                    Ok(false) => {}
                    Ok(true) => break,
                    Err(_) => {
                        super::pci::scan_cleanup_failed(worker.radio.clone());
                        break;
                    }
                }
                let seen = signal.count();
                // One vector serves both netdevs: events this drain parks in
                // the P2P client slot are that netdev's worker's to deliver.
                p2p_client::kick_for(&worker.radio);
                p2p_go::kick_for(&worker.radio);
                let progressed = worker.drain();
                let _ = worker.flush_management().await;
                let _ = worker.apply_power_save().await;
                if progressed {
                    narf_scheduler::yield_now().await;
                    continue;
                }
                let ms = super::irq::fallback_ms(delivered);
                let timer = narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(ms * 1_000_000));
                signal.wait(seen, core::pin::pin!(timer)).await;
            }
        });
        Ok(device)
    })
}
/// Called under ACTIVE for the entire registration transaction, so retirement
/// either prevents publication or observes its complete registered generation.
pub(super) fn admit_generation<R>(
    quarantine: &AtomicBool,
    publish: impl FnOnce() -> Result<R, Error>,
) -> Result<R, Error> {
    if quarantine.load(Ordering::Acquire) {
        return Err(Error::Failed);
    }
    publish()
}
pub(super) fn publish(
    radio: Arc<Mutex<Radio<super::boot::PciBoot>>>,
    quarantine: Arc<AtomicBool>,
) -> Result<Arc<Native>, Error> {
    let r = radio.try_lock().ok_or(Error::Failed)?;
    let mac = r.station_publishable()?;
    let source = r.htt.wmi.htc.transport.current_sources();
    let result = super::firmware_source::invoke(source.as_ref(), || {
        publish_with_mac(
            radio.clone(),
            mac,
            &quarantine,
            RadioFeatures::observed(&r),
            r.configured_channels()
                .iter()
                .copied()
                .filter(|f| super::regulatory::Permission::station_frequency(*f))
                .collect(),
            r.htt.wmi.htc.transport.interrupt(),
        )
    })
    .map_err(|_| Error::Failed)?;
    drop(r);
    result
}
pub(super) async fn wait_publish(
    radio: Arc<Mutex<Radio<super::boot::PciBoot>>>,
    quarantine: Arc<AtomicBool>,
) -> Result<Arc<Native>, Error> {
    loop {
        if quarantine.load(Ordering::Acquire) {
            return Err(Error::Failed);
        }
        {
            let r = radio.lock().await;
            r.station_publishable()?;
        }
        if ACTIVE.lock().is_some() {
            return Err(Error::Failed);
        }
        match check_admission()? {
            Admission::Ready => {
                let r = radio.lock().await;
                let mac = r.station_publishable()?;
                let source = r.htt.wmi.htc.transport.current_sources();
                let result = super::firmware_source::invoke(source.as_ref(), || {
                    publish_with_mac(
                        radio.clone(),
                        mac,
                        &quarantine,
                        RadioFeatures::observed(&r),
                        r.configured_channels()
                            .iter()
                            .copied()
                            .filter(|f| super::regulatory::Permission::station_frequency(*f))
                            .collect(),
                        r.htt.wmi.htc.transport.interrupt(),
                    )
                })
                .map_err(|_| Error::Failed)?;
                drop(r);
                return result;
            }
            Admission::PendingAssets => super::firmware::staging_pause().await,
        }
    }
}
#[async_trait::async_trait]
impl WirelessNetIface for Native {
    fn ap_station_macs(&self) -> Vec<[u8; 6]> {
        if self.closed.load(Ordering::Acquire) || self.mode.load(Ordering::Acquire) != 3 {
            return Vec::new();
        }
        let Some(radio) = self.radio.try_lock() else {
            return Vec::new();
        };
        if !self.owns_ap(&radio) {
            return Vec::new();
        }
        let source = radio.htt.wmi.htc.transport.current_sources();
        super::firmware_source::invoke(source.as_ref(), || radio.ap_clients())
            .ok()
            .and_then(Result::ok)
            .unwrap_or_default()
    }
    fn ap_station_info(&self, peer: [u8; 6]) -> Option<narf_wireless::StationInfo> {
        self.ap_station_macs()
            .contains(&peer)
            .then_some(narf_wireless::StationInfo::default())
    }
    fn supports_ap(&self) -> bool {
        self.ap_capable
    }
    fn supports_ap_uapsd(&self) -> bool {
        self.ap_capable && self.ap_uapsd
    }
    fn max_ap_assoc_sta(&self) -> u32 {
        if self.ap_capable {
            8
        } else {
            0
        }
    }
    fn supports_ap_userspace_mlme(&self) -> bool {
        self.ap_capable
    }
    fn supports_ap_authenticator(&self) -> bool {
        self.ap_capable
    }
    fn supports_ap_key_sequence(&self) -> bool {
        self.ap_capable
    }
    fn supports_control_port_tx_status(&self) -> bool {
        self.ap_capable
    }
    fn supports_control_port_no_preauth(&self) -> bool {
        self.ap_capable
    }
    fn wiphy_id(&self) -> u64 {
        self.wiphy
    }
    fn current_iftype(&self) -> u32 {
        if self.client {
            return p2p_client::IFTYPE;
        }
        self.ap_iftype()
    }
    fn set_iftype(&self, mode: u32) -> Result<(), WirelessError> {
        if self.client {
            return if mode == p2p_client::IFTYPE {
                Ok(())
            } else {
                Err(WirelessError::NotSupported)
            };
        }
        self.ap_set_iftype(mode)
    }
    fn ap_control_generation(&self) -> Option<core::num::NonZeroU64> {
        self.ap_generation()
    }
    fn reserve_ap_control(
        &self,
    ) -> Result<Option<Arc<dyn narf_wireless::ap_control::ApControlReservation>>, WirelessError>
    {
        self.reserve_control()
    }
    async fn start_ap_with_settings_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        config: narf_wireless::ApConfig,
        settings: narf_wireless::ApStartSettings,
    ) -> Result<(), WirelessError> {
        self.ap_control(
            authority,
            ap::Operation::Start(Box::new(config), Box::new(settings)),
        )
        .await
        .map(|_| ())
    }
    async fn start_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        config: narf_wireless::ApConfig,
    ) -> Result<(), WirelessError> {
        self.start_ap_with_settings_async(
            authority,
            config,
            narf_wireless::ApStartSettings::default(),
        )
        .await
    }
    async fn stop_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
    ) -> Result<(), WirelessError> {
        self.ap_control(authority, ap::Operation::Stop)
            .await
            .map(|_| ())
    }
    async fn set_beacon_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        head: Option<Vec<u8>>,
        tail: Option<Vec<u8>>,
        probe: Option<Vec<u8>>,
    ) -> Result<(), WirelessError> {
        self.ap_control(authority, ap::Operation::Beacon(head, tail, probe))
            .await
            .map(|_| ())
    }
    async fn add_station_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        station: narf_wireless::StationConfig,
    ) -> Result<(), WirelessError> {
        self.ap_control(authority, ap::Operation::Add(station))
            .await
            .map(|_| ())
    }
    async fn set_station_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        station: narf_wireless::StationConfig,
    ) -> Result<(), WirelessError> {
        self.ap_control(authority, ap::Operation::Set(station))
            .await
            .map(|_| ())
    }
    async fn del_station_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        peer: Option<[u8; 6]>,
        _reason: u16,
    ) -> Result<(), WirelessError> {
        // DEL_STATION removes native ownership. A reason-bearing on-air
        // deauthentication is separately submitted through actual FRAME TX.
        self.ap_control(authority, ap::Operation::Delete(peer))
            .await
            .map(|_| ())
    }
    async fn add_key_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        key: narf_wireless::OwnedKey,
    ) -> Result<(), i32> {
        self.ap_control(authority, ap::Operation::Key(key))
            .await
            .map(|_| ())
            .map_err(ap::errno)
    }
    async fn del_key_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        index: u8,
        pairwise: bool,
        peer: Option<[u8; 6]>,
    ) -> Result<(), i32> {
        self.ap_control(authority, ap::Operation::DeleteKey(index, pairwise, peer))
            .await
            .map(|_| ())
            .map_err(ap::errno)
    }
    async fn key_sequence_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        index: u8,
        pairwise: bool,
        peer: Option<[u8; 6]>,
    ) -> Result<narf_wireless::KeySequence, i32> {
        self.ap_sequence(authority, index, pairwise, peer).await
    }
    async fn default_key_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        index: u8,
        unicast: bool,
        multicast: bool,
        management: bool,
        beacon: bool,
    ) -> Result<(), i32> {
        self.ap_control(
            authority,
            ap::Operation::DefaultKey(index, (unicast, multicast, management, beacon)),
        )
        .await
        .map(|_| ())
        .map_err(ap::errno)
    }
    async fn tx_control_port_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        request: narf_wireless::ControlPortTxRequest,
    ) -> Result<bool, i32> {
        self.ap_control(authority, ap::Operation::Control(request))
            .await
            .map_err(ap::errno)
    }
    async fn mgmt_tx_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        _cookie: u64,
        request: narf_wireless::MgmtTxRequest,
    ) -> Result<bool, WirelessError> {
        self.ap_control(authority, ap::Operation::Management(request))
            .await
    }
    async fn register_mgmt_frame_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        frame_type: u16,
        prefix: Vec<u8>,
    ) -> Result<(), WirelessError> {
        self.ap_register(authority, frame_type, prefix).await
    }
    fn radio_control_generation(&self) -> Option<core::num::NonZeroU64> {
        if self.closed.load(Ordering::Acquire) || self.retired.load(Ordering::Acquire) {
            None
        } else {
            core::num::NonZeroU64::new(self.mode_generation.load(Ordering::Acquire))
        }
    }
    fn reserve_radio_control(
        &self,
    ) -> Result<Option<Arc<dyn narf_wireless::ap_control::ApControlReservation>>, WirelessError>
    {
        self.reserve_control()
    }
    /// ROC and offchannel FRAME run on the home netdev or the P2P_DEVICE
    /// wdev; the P2P client and GO netdevs have no ROC owner.
    fn async_roc_control(&self) -> bool {
        !self.client && !self.go
    }
    /// The control-only P2P_DEVICE wdev (async) and the P2P client netdev
    /// (`new_virtual_interface`) are this radio's virtual interfaces.
    fn supports_virtual_interfaces(&self) -> bool {
        p2p_wdev::P2P_ADVERTISED && self.p2p_capable
    }
    /// `ath10k_mac_register`: P2P_CLIENT and P2P_GO (netdevs) and
    /// P2P_DEVICE (control-only wdev) for TLV firmware without NO_P2P.
    fn p2p_interface_types(&self) -> Vec<u32> {
        if self.p2p_advertised() {
            alloc::vec![p2p_client::IFTYPE, p2p_go::IFTYPE, 10]
        } else {
            Vec::new()
        }
    }
    /// `ath10k_tlv_if_comb`, or `ath10k_tlv_qcs_if_comb` once adaptive QCS
    /// was enabled (`p2p_combinations`); none without P2P.
    fn interface_combinations(&self) -> Vec<narf_wireless::InterfaceCombination> {
        if self.p2p_advertised() {
            self.combinations.combinations()
        } else {
            Vec::new()
        }
    }
    fn new_virtual_interface(
        &self,
        name: &str,
        iftype: u32,
        mac: Option<[u8; 6]>,
    ) -> Result<Arc<dyn WirelessNetIface>, WirelessError> {
        if iftype == p2p_go::IFTYPE {
            return self.new_p2p_go(name, iftype, mac);
        }
        self.new_p2p_client(name, iftype, mac)
    }
    fn delete_virtual_interface(&self) -> Result<(), WirelessError> {
        if self.go {
            return self.delete_p2p_go();
        }
        self.delete_p2p_client()
    }
    fn async_control_interfaces(&self) -> bool {
        self.supports_virtual_interfaces()
    }
    fn async_control_iftypes(&self) -> u32 {
        p2p_wdev::CONTROL_IFTYPES
    }
    async fn new_control_interface_async(
        &self,
        authority: &narf_wireless::ap_control::RadioControlAuthority,
        name: &str,
        iftype: u32,
        mac: Option<[u8; 6]>,
    ) -> Result<Arc<dyn WirelessNetIface>, WirelessError> {
        self.new_p2p_wdev(authority, name, iftype, mac).await
    }
    fn max_remain_on_channel_duration_ms(&self) -> u32 {
        wmi_runtime::offchannel::MAX_DURATION
    }
    fn supports_offchannel_mgmt_tx(&self) -> bool {
        self.offchannel_tx
    }
    fn async_radio_management_tx_control(&self) -> bool {
        self.offchannel_tx
    }
    fn async_radio_management_rx_control(&self) -> bool {
        !self.client && !self.go
    }
    async fn register_mgmt_frame_radio_async(
        &self,
        authority: &narf_wireless::ap_control::RadioControlAuthority,
        frame_type: u16,
        prefix: &[u8],
    ) -> Result<(), i32> {
        if self.client || self.go {
            return Err(-95);
        }
        self.register_offchannel_frame(authority, frame_type, prefix)
            .await
    }
    async fn remain_on_channel_async(
        &self,
        authority: &narf_wireless::ap_control::RadioControlAuthority,
        cookie: u64,
        frequency: u32,
        duration: u32,
    ) -> Result<(), WirelessError> {
        if self.client || self.go {
            return Err(WirelessError::NotSupported);
        }
        self.start_offchannel(authority, cookie, frequency, duration)
            .await
    }
    async fn cancel_remain_on_channel_async(
        &self,
        authority: &narf_wireless::ap_control::RadioControlAuthority,
        cookie: u64,
    ) -> Result<(), WirelessError> {
        if self.client || self.go {
            return Err(WirelessError::NotSupported);
        }
        self.cancel_offchannel(authority, cookie).await
    }
    async fn mgmt_tx_radio_async(
        &self,
        authority: &narf_wireless::ap_control::RadioControlAuthority,
        cookie: u64,
        request: narf_wireless::MgmtTxRequest,
    ) -> Result<bool, WirelessError> {
        if self.client || self.go {
            return Err(WirelessError::NotSupported);
        }
        self.transmit_offchannel(authority, cookie, request).await
    }
    fn phy_capabilities(&self, band: u32) -> Option<narf_wireless::iface::PhyCapabilities> {
        Device::phy_capabilities(self, band)
    }
    fn wowlan_support(&self) -> Option<narf_wireless::WowlanSupport> {
        Device::wowlan_support(self)
    }
    fn set_wowlan(&self, config: Option<narf_wireless::WowlanConfig>) -> Result<(), i32> {
        Device::set_wowlan(self, config)
    }
    fn wowlan_config(&self) -> Option<narf_wireless::WowlanConfig> {
        Device::wowlan_config(self)
    }
    fn power_save_default(&self) -> Option<bool> {
        (self.ps_supported && self.mode.load(Ordering::Acquire) == 2).then_some(false)
    }
    fn set_power_save(&self, enabled: bool) -> Result<(), i32> {
        self.request_power_save(enabled)
    }
    fn max_scan_ssids(&self) -> u8 {
        wmi_runtime::MAX_SCAN_SSIDS as u8
    }
    fn max_scan_ie_len(&self) -> u16 {
        wmi_runtime::MAX_SCAN_IE_LEN
    }
    fn supports_handshake_offload(&self) -> bool {
        true
    }
    fn reports_disconnect_events(&self) -> bool {
        true
    }
    fn connected_bssid(&self) -> Option<[u8; 6]> {
        if self.closed.load(Ordering::Acquire) || self.mode.load(Ordering::Acquire) != 2 {
            return None;
        }
        let b = self.bssid.load(Ordering::Acquire).to_le_bytes();
        (b[7] != 0 && !self.closed.load(Ordering::Acquire)).then(|| b[..6].try_into().unwrap())
    }
    fn cipher_suites(&self) -> &'static [u32] {
        &[0x000fac04]
    }
    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.radio.try_lock()?.information_elements(bssid)
    }
    fn get_wireless_info(&self) -> narf_wireless::WirelessIfaceInfo {
        use narf_wireless::iface::*;
        WirelessIfaceInfo {
            base_name: self.name.clone(),
            base_mac: self.mac,
            bands: [2400, 5000]
                .into_iter()
                .filter_map(|band| {
                    let channels: Vec<u32> = self
                        .frequencies
                        .iter()
                        .copied()
                        .filter(|f| {
                            super::regulatory::Permission::station_frequency(*f)
                                && (*f < 3000) == (band == 2400)
                        })
                        .filter_map(|f| {
                            narf_wireless::association::channel::from_frequency(u32::from(f))
                                .map(u32::from)
                        })
                        .collect();
                    (!channels.is_empty()).then_some(WirelessBand {
                        freq_mhz: band,
                        channels,
                    })
                })
                .collect(),
            modes: WirelessModes::STATION
                | if self.ap_capable {
                    WirelessModes::AP
                } else {
                    WirelessModes::empty()
                }
                | if self.p2p_advertised() {
                    WirelessModes::P2P
                } else {
                    WirelessModes::empty()
                },
            hw_caps: HwCaps {
                ht_supported: self.mode.load(Ordering::Acquire) == 2
                    && self.ht_capabilities.is_some(),
                vht_supported: self.mode.load(Ordering::Acquire) == 2
                    && self.vht_capabilities.is_some(),
                he_supported: false,
                eht_supported: false,
            },
        }
    }
    async fn scan(&self, r: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        Device::scan(self, r).await
    }
    async fn associate(&self, r: AssociateRequest) -> Result<(), WirelessError> {
        Device::associate(self, r).await
    }
    async fn disassociate(&self) -> Result<(), WirelessError> {
        Device::disassociate(self).await
    }
    async fn set_config(&self, _: WirelessConfig) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
}
struct Registered(Arc<Native>);
impl Interface for Registered {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn mac(&self) -> [u8; 6] {
        self.0.mac()
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        self.0.link_up()
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<narf_ipc::Consumer<Frame, RX_RING_N>>> {
        self.0.rx_ring()
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<narf_ipc::Producer<Frame, TX_RING_N>>> {
        self.0.tx_ring()
    }
}
