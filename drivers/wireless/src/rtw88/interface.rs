// SPDX-License-Identifier: GPL-2.0-or-later
//! One registered RTL8821CE/RTL8822CE shell and retained owner for control and packet
//! progress. Synchronous stack drains never wait for another executor task.
use super::{
    firmware_lifecycle::Lifecycle,
    firmware_transport::Io,
    station::{self, Environment},
    station_control::Admission,
};
use alloc::{boxed::Box, collections::VecDeque, string::String, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};
use narf_wireless::{
    AssociateRequest, BssInfo, ScanRequest, SecurityConfig, WirelessConfig, WirelessError,
    WirelessNetIface,
};
use zeroize::Zeroizing;
type Error = station::Error;
const EINVAL: i32 = 22;
const EBUSY: i32 = 16;
const ENODEV: i32 = 19;
struct Rings {
    rx: narf_ipc::Producer<Frame, RX_RING_N>,
    tx: narf_ipc::Consumer<Frame, TX_RING_N>,
    pending: Option<Frame>,
    batch: VecDeque<Frame>,
}
impl Rings {
    fn clear(&mut self) {
        self.pending = None;
        self.batch.clear();
        for _ in 0..TX_RING_N {
            if !matches!(self.tx.try_recv(), Ok(Some(_))) {
                break;
            }
        }
    }
}
pub(super) struct Device<I: Io> {
    pub(super) lifecycle: Arc<Lifecycle<I>>,
    environment: Arc<dyn Environment>,
    admission: Admission,
    rings: Mutex<Rings>,
    name: String,
    local: [u8; 6],
    published: AtomicBool,
    withdrawn: AtomicBool,
    activating: AtomicBool,
    admitted: AtomicBool,
    up: AtomicBool,
    port: AtomicBool,
    rts_capable: AtomicBool,
    rts: AtomicU32,
    bssid: AtomicU64,
    ht_capability: IrqSafeSpinLock<Option<[u8; 26]>>,
    receive_generation: AtomicU64,
    metadata: IrqSafeSpinLock<()>,
    rx: IrqSafeSpinLock<Option<narf_ipc::Consumer<Frame, RX_RING_N>>>,
    tx: IrqSafeSpinLock<Option<narf_ipc::Producer<Frame, TX_RING_N>>>,
}
impl<I: Io> core::fmt::Debug for Device<I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw88Device")
            .field("name", &self.name)
            .field("admitted", &self.admitted)
            .field("up", &self.up)
            .finish_non_exhaustive()
    }
}
trait Close: Sync {
    fn close(&self);
}
struct Attempt<'a> {
    device: &'a dyn Close,
    armed: bool,
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.device.close();
        }
    }
}
impl<I: Io + 'static> Close for Device<I> {
    fn close(&self) {
        self.admission.close();
        self.clear_receive();
        self.link(None, false);
    }
}
impl<I: Io + 'static> Device<I> {
    fn clear_receive(&self) {
        if let Some(rx) = self.rx.lock().as_mut() {
            for _ in 0..RX_RING_N {
                if !matches!(rx.try_recv(), Ok(Some(_))) {
                    break;
                }
            }
        }
    }
    pub(super) fn new(
        name: &str,
        local: [u8; 6],
        lifecycle: Arc<Lifecycle<I>>,
        environment: Arc<dyn Environment>,
    ) -> Self {
        let (rx, consumer) = narf_ipc::channel();
        let (producer, tx) = narf_ipc::channel();
        Self {
            lifecycle,
            environment,
            admission: Admission::new(),
            rings: Mutex::new(Rings {
                rx,
                tx,
                pending: None,
                batch: VecDeque::new(),
            }),
            name: name.into(),
            local,
            published: AtomicBool::new(false),
            withdrawn: AtomicBool::new(false),
            activating: AtomicBool::new(false),
            admitted: AtomicBool::new(false),
            up: AtomicBool::new(false),
            port: AtomicBool::new(false),
            rts_capable: AtomicBool::new(false),
            rts: AtomicU32::new(u32::MAX),
            bssid: AtomicU64::new(0),
            ht_capability: IrqSafeSpinLock::new(None),
            receive_generation: AtomicU64::new(0),
            metadata: IrqSafeSpinLock::new(()),
            rx: IrqSafeSpinLock::new(Some(consumer)),
            tx: IrqSafeSpinLock::new(Some(producer)),
        }
    }
    pub(super) fn closed(&self) -> bool {
        self.admission.closed()
    }
    /// Removal (`rtw_unregister_hw` in `rtw_pci_remove`): close every
    /// control and packet path, drop the link and withdraw the registered
    /// netdev, wireless and stack endpoints. The owner itself is torn down
    /// by `Lifecycle::remove`.
    pub(super) fn withdraw(self: &Arc<Self>) {
        if self.withdrawn.swap(true, Ordering::AcqRel) {
            return;
        }
        self.close();
        if let Some(mut rings) = self.rings.try_lock() {
            rings.clear();
        }
        if !self.published.swap(false, Ordering::AcqRel) {
            return;
        }
        {
            let mut active = ACTIVE.lock();
            let this = Arc::as_ptr(self) as *const ();
            if active
                .as_ref()
                .is_some_and(|a| Arc::as_ptr(a) as *const () == this)
            {
                *active = None;
            }
        }
        narf_wireless::registry::unregister(&self.name);
        narf_net::registry().unregister(&self.name);
        narf_net::iface::unregister(&self.name);
        CLAIMED.store(false, Ordering::Release);
    }
    pub(super) fn withdrawn(&self) -> bool {
        self.withdrawn.load(Ordering::Acquire)
    }
    pub(super) fn admission(&self) -> Admission {
        self.admission.clone()
    }
    /// Linux `rtw_watch_dog_work`: one dynamic-mechanism period under the
    /// retained owner mutex. A failed period closes the shell.
    pub(super) async fn watchdog(&self) -> bool {
        if self.closed() || !self.admitted.load(Ordering::Acquire) {
            return false;
        }
        match self.lifecycle.watchdog().await {
            Ok(ran) => ran,
            Err(_) => {
                self.close();
                false
            }
        }
    }
    pub(super) async fn activate(&self) -> Result<(), Error> {
        if !self.published.load(Ordering::Acquire) || self.closed() {
            return Err(Error::State);
        }
        self.activating
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::State)?;
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        self.lifecycle
            .start_station(self.environment.clone(), self.admission.clone())
            .await?;
        let (authority, ht) = {
            let mut retained = self.lifecycle.retained.lock().await;
            let owner = retained.as_mut().ok_or(Error::State)?;
            (owner.station_publication()?, owner.station_ht_capability())
        };
        self.admission.run(|| {
            authority.invoke(|| {
                self.admitted.store(true, Ordering::Release);
                *self.ht_capability.lock() = ht;
                Ok(())
            })
        })?;
        attempt.armed = false;
        Ok(())
    }
    fn link(&self, peer: Option<[u8; 6]>, port: bool) {
        let _metadata = self.metadata.lock();
        if peer.is_none() {
            self.rts_capable.store(false, Ordering::Release);
        }
        let peer = peer.filter(|_| !self.closed());
        let mut packed = [0; 8];
        if let Some(peer) = peer {
            packed[..6].copy_from_slice(&peer);
            packed[7] = 1;
        }
        self.bssid
            .store(u64::from_le_bytes(packed), Ordering::Release);
        self.port.store(peer.is_some() && port, Ordering::Release);
        let up = peer.is_some();
        let was = self.up.swap(up, Ordering::AcqRel);
        // Physical carrier is independent of administrative IFF_UP. In
        // particular, do not invoke ndo_open/ndo_stop under retained locks.
        narf_net::iface::set_link_metadata(&self.name, up, None, None);
        if was && !up {
            narf_wireless::nl80211::notify_disconnect(&self.name, 1, false);
        }
    }
    fn publish_link(
        &self,
        owner: &mut super::firmware_transport::Owner<I>,
    ) -> Result<super::publication::Publication, Error> {
        let peer = owner.station_peer();
        let port = owner.station_receive_open();
        let rts = owner.station_rts_threshold();
        let authority = owner.station_publication()?;
        let generation = self.admission.receive_generation();
        self.admission.run(|| {
            authority.invoke(|| {
                if self.receive_generation.swap(generation, Ordering::AcqRel) != generation {
                    self.clear_receive();
                }
                self.link(peer, port);
                self.rts.store(rts.unwrap_or(u32::MAX), Ordering::Release);
                self.rts_capable
                    .store(rts.is_some() && peer.is_some(), Ordering::Release);
                Ok(())
            })
        })?;
        Ok(authority)
    }
    fn control_ready(&self) -> Result<(), WirelessError> {
        if self.closed() {
            Err(WirelessError::HardwareError)
        } else if !self.admitted.load(Ordering::Acquire) {
            Err(WirelessError::Busy)
        } else {
            Ok(())
        }
    }
    pub(super) fn enqueue(&self, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
        if !self.admitted.load(Ordering::Acquire)
            || self.closed()
            || !self.up.load(Ordering::Acquire)
            || !self.port.load(Ordering::Acquire)
            || !station::admitted(bytes, self.local)
            || !offloads(meta)
        {
            return Err(());
        }
        let mut storage = self.lifecycle.retained.try_lock().ok_or(())?;
        let owner = storage.as_mut().ok_or(())?;
        let authority = owner.station_check();
        if authority.is_err() {
            self.close();
            if !self.admission.teardown_pending() {
                let _ = owner.station_stop();
            }
            return Err(());
        }
        if !owner.station_ready() {
            return Err(());
        }
        let result = self.admission.run(|| {
            let memory = narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
                .map_err(|_| super::firmware_transport::Error::Memory)?;
            let mut frame = Frame::new(memory, bytes.len() as u32);
            frame.payload_mut().copy_from_slice(bytes);
            frame.set_tx_meta(meta);
            // Re-sample the retained PCI/calibration/policy authority at
            // queue publication, after allocation and the initial check.
            // Native DMA publication independently checks again.
            let authority = owner
                .station_publication()
                .map_err(|_| super::firmware_transport::Error::Access)?;
            // Outer failure is current authority/PCI loss. Keep the inner
            // ring-full result retryable without confusing the two classes.
            authority
                .invoke(|| {
                    let mut slot = self.tx.lock();
                    Ok(match slot.as_mut() {
                        Some(ring) => ring
                            .try_send(frame)
                            .map_err(|_| super::firmware_transport::Error::State),
                        None => Err(super::firmware_transport::Error::State),
                    })
                })
                .map_err(|_| super::firmware_transport::Error::Access)?
        });
        if result == Err(super::firmware_transport::Error::Access) {
            self.close();
            if !self.admission.teardown_pending() {
                let _ = owner.station_stop();
            }
        }
        result.map_err(|_| ())
    }
    fn progress(&self) -> Vec<(Vec<u8>, super::publication::Publication)> {
        let Some(mut storage) = self.lifecycle.retained.try_lock() else {
            return Vec::new();
        };
        let Some(owner) = storage.as_mut() else {
            return Vec::new();
        };
        let Some(mut rings) = self.rings.try_lock() else {
            return Vec::new();
        };
        if self.closed() {
            rings.clear();
            self.link(None, false);
            if !self.admission.teardown_pending() {
                let _ = owner.station_stop();
            }
            return Vec::new();
        }
        if !self.admitted.load(Ordering::Acquire) {
            return Vec::new();
        }
        let result = (|| -> Result<Vec<(Vec<u8>, super::publication::Publication)>, Error> {
            let frames = owner.station_poll()?;
            self.publish_link(owner)?;
            if self.closed() {
                rings.clear();
                return Ok(Vec::new());
            }
            if owner.station_peer().is_none() {
                rings.clear();
                return Ok(Vec::new());
            }
            if rings.pending.is_none() {
                rings.pending = rings.batch.pop_front();
            }
            if rings.pending.is_none() {
                for _ in 0..16 {
                    let Ok(Some(frame)) = rings.tx.try_recv() else {
                        break;
                    };
                    if station::admitted(frame.payload(), self.local) && offloads(frame.tx_meta()) {
                        rings.pending = Some(frame);
                        break;
                    }
                }
            }
            if owner.station_ready() {
                if owner.station_batch_active() && rings.pending.is_some() {
                    let capacity = owner.station_batch_capacity();
                    for _ in 0..16 {
                        if rings.batch.len() + 1 >= capacity {
                            break;
                        }
                        let Ok(Some(frame)) = rings.tx.try_recv() else {
                            break;
                        };
                        if station::admitted(frame.payload(), self.local)
                            && offloads(frame.tx_meta())
                        {
                            rings.batch.push_back(frame);
                        }
                    }
                    let mut frames = Vec::new();
                    if let Some(first) = rings.pending.as_ref() {
                        frames.push(first.payload());
                    }
                    frames.extend(
                        rings
                            .batch
                            .iter()
                            .take(capacity.saturating_sub(1))
                            .map(Frame::payload),
                    );
                    match owner.station_send_batch(&frames) {
                        Ok(count) => {
                            if count == 0 || count > frames.len() {
                                return Err(Error::State);
                            }
                            rings.pending = None;
                            for _ in 1..count {
                                rings.batch.pop_front();
                            }
                        }
                        Err(Error::Busy)
                        | Err(Error::Transport(super::packet_core::Error::Busy)) => {}
                        Err(error) => return Err(error),
                    }
                } else if let Some(frame) = rings.pending.as_ref() {
                    match owner.station_send(frame.payload()) {
                        Ok(()) => rings.pending = None,
                        Err(Error::Busy)
                        | Err(Error::Transport(super::packet_core::Error::Busy)) => {}
                        Err(error) => return Err(error),
                    }
                }
            }
            let authority = self.publish_link(owner)?;
            self.admission.run(|| {
                for bytes in &frames {
                    if let Ok(memory) =
                        narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
                    {
                        let mut frame = Frame::new(memory, bytes.len() as u32);
                        frame.payload_mut().copy_from_slice(bytes);
                        authority.invoke(|| {
                            let _ = rings.rx.try_send(frame);
                            Ok(())
                        })?;
                    }
                }
                Ok(())
            })?;
            Ok(frames
                .into_iter()
                .map(|frame| (frame, authority.clone()))
                .collect())
        })();
        match result {
            Ok(frames) => {
                if self.closed() {
                    rings.clear();
                    Vec::new()
                } else {
                    frames
                }
            }
            Err(_) => {
                rings.clear();
                self.close();
                if !self.admission.teardown_pending() {
                    let _ = owner.station_stop();
                }
                Vec::new()
            }
        }
    }
    pub(super) fn drain(&self) -> bool {
        let frames = self.progress();
        let progressed = !frames.is_empty();
        // All retained-owner/ring/admission guards have dropped before the
        // stack can synchronously answer ARP/ND through this enqueue callback.
        for (mut frame, authority) in frames {
            if self.closed() {
                break;
            }
            if !authority.current() {
                continue;
            }
            // A previous callback may have reentered native progress and
            // changed the key/port epoch. Refresh the actual retained owner,
            // then release it before the callback (ARP/ND may enqueue/drain).
            let ready = {
                let Some(mut storage) = self.lifecycle.retained.try_lock() else {
                    continue;
                };
                let Some(owner) = storage.as_mut() else {
                    continue;
                };
                if owner.station_check().is_err() {
                    self.close();
                    if !self.admission.teardown_pending() {
                        let _ = owner.station_stop();
                    }
                    false
                } else {
                    owner.station_receive_open()
                }
            };
            if !ready || !authority.current() {
                continue;
            }
            if authority
                .invoke(|| {
                    if self.closed() || !self.port.load(Ordering::Acquire) || !authority.current() {
                        return Err(super::firmware_transport::Error::State);
                    }
                    narf_net::iface::on_rx_frame_from(&self.name, &mut frame);
                    Ok(())
                })
                .is_err()
            {
                if !authority.current() {
                    continue;
                }
                self.close();
                let _ = self.progress();
                break;
            }
        }
        progressed
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn admit_for_test(&self) {
        self.published.store(true, Ordering::Release);
    }
}
fn offloads(meta: narf_net::TxMeta) -> bool {
    meta.csum_l4.is_none() && meta.tso_mss.is_none() && meta.vlan_tag.is_none()
}
fn error(error: Error) -> WirelessError {
    match error {
        Error::Busy | Error::State => WirelessError::Busy,
        Error::Profile | Error::Management(_) => WirelessError::InvalidArgs,
        Error::Timeout => WirelessError::Timeout,
        Error::Entropy => WirelessError::NotSupported,
        _ => WirelessError::HardwareError,
    }
}
impl<I: Io + 'static> Interface for Device<I> {
    fn name(&self) -> &str {
        &self.name
    }
    fn mac(&self) -> [u8; 6] {
        self.local
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        self.admitted.load(Ordering::Acquire) && !self.closed() && self.up.load(Ordering::Acquire)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<narf_ipc::Consumer<Frame, RX_RING_N>>> {
        &self.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<narf_ipc::Producer<Frame, TX_RING_N>>> {
        &self.tx
    }
}
#[async_trait::async_trait]
impl<I: Io + 'static> WirelessNetIface for Device<I> {
    fn rts_threshold(&self) -> Option<u32> {
        (!self.closed() && self.rts_capable.load(Ordering::Acquire))
            .then(|| self.rts.load(Ordering::Acquire))
    }
    fn set_rts_threshold(&self, value: u32) -> Result<(), i32> {
        if value != u32::MAX && value > 2347 {
            return Err(EINVAL);
        }
        if self.closed() {
            return Err(ENODEV);
        }
        let mut storage = self.lifecycle.retained.try_lock().ok_or(EBUSY)?;
        let owner = storage.as_mut().ok_or(EBUSY)?;
        let result = owner.station_set_rts_threshold(value);
        match result {
            Ok(()) => {
                let current = owner.station_rts_threshold();
                self.rts
                    .store(current.unwrap_or(u32::MAX), Ordering::Release);
                self.rts_capable.store(current.is_some(), Ordering::Release);
                Ok(())
            }
            Err(Error::Busy | Error::State) => Err(EBUSY),
            Err(Error::Profile | Error::Native(super::firmware_transport::Error::Unsupported)) => {
                Err(narf_wireless::EOPNOTSUPP)
            }
            Err(_) => {
                self.close();
                Err(ENODEV)
            }
        }
    }
    fn supports_handshake_offload(&self) -> bool {
        true
    }
    fn reports_disconnect_events(&self) -> bool {
        true
    }
    /// Linux `main.c::rtw_register_hw` sets `NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR`.
    fn supports_scan_random_mac(&self) -> bool {
        true
    }
    fn supports_scan_dwell(&self) -> bool {
        true
    }
    fn max_scan_ssids(&self) -> u8 {
        super::scan::MAX_SSIDS
    }
    fn max_scan_ie_len(&self) -> u16 {
        super::scan::MAX_EXTRA_IES
    }
    fn connected_bssid(&self) -> Option<[u8; 6]> {
        if !self.link_up() {
            return None;
        }
        let bytes = self.bssid.load(Ordering::Acquire).to_le_bytes();
        (bytes[7] != 0).then(|| bytes[..6].try_into().unwrap())
    }
    fn cipher_suites(&self) -> &'static [u32] {
        &[0x000fac04]
    }
    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.lifecycle
            .retained
            .try_lock()?
            .as_ref()?
            .station_information_elements(bssid)
    }
    fn get_wireless_info(&self) -> narf_wireless::WirelessIfaceInfo {
        use narf_wireless::iface::*;
        WirelessIfaceInfo {
            base_name: self.name.clone(),
            base_mac: self.local,
            bands: vec![WirelessBand {
                freq_mhz: 2400,
                channels: vec![1],
            }],
            modes: WirelessModes::STATION,
            hw_caps: HwCaps {
                ht_supported: self.ht_capability.lock().is_some(),
                vht_supported: false,
                he_supported: false,
                eht_supported: false,
            },
        }
    }
    fn phy_capabilities(&self, band: u32) -> Option<narf_wireless::iface::PhyCapabilities> {
        if band != 2400 {
            return None;
        }
        Some(narf_wireless::iface::PhyCapabilities {
            ht: (*self.ht_capability.lock())?,
            vht: None,
        })
    }
    async fn scan(&self, request: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        let plan = super::scan::plan(&request, self.local)?;
        self.control_ready()?;
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        let mut storage = self.lifecycle.retained.lock().await;
        self.control_ready()?;
        let owner = storage.as_mut().ok_or(WirelessError::Busy)?;
        if owner.station_phase() != Some(station::Phase::Passive) {
            attempt.armed = false;
            return Err(WirelessError::Busy);
        }
        let result = owner
            .station_scan(plan.dwell_ms, &plan.probes, plan.address)
            .await;
        attempt.armed = false;
        if result.is_err() {
            self.close();
            if !self.admission.teardown_pending() {
                let _ = owner.station_stop();
            }
        }
        let result = result.map_err(error)?;
        if self.closed() {
            self.link(None, false);
            return Err(WirelessError::HardwareError);
        }
        Ok(result
            .into_iter()
            .filter(|c| {
                request.ssids.is_empty()
                    || request
                        .ssids
                        .iter()
                        .any(|s| s.is_empty() || *s == c.bss.ssid)
            })
            .map(|c| BssInfo {
                bssid: c.bss.bssid,
                ssid: c.bss.ssid,
                channel: 1,
                frequency_mhz: 2412,
                rssi: i8::MIN,
                security: if c.ap_rsne.is_some() {
                    narf_wireless::scan::BssSecurity::Wpa2
                } else if c.bss.capability & 16 != 0 {
                    narf_wireless::scan::BssSecurity::Wep
                } else {
                    narf_wireless::scan::BssSecurity::Open
                },
            })
            .collect())
    }
    async fn associate(&self, request: AssociateRequest) -> Result<(), WirelessError> {
        self.control_ready()?;
        if request.channel != 1 || request.frequency_mhz != 2412 {
            return Err(WirelessError::NotSupported);
        }
        let pmk = match request.security {
            SecurityConfig::Open => None,
            SecurityConfig::Wpa2 { psk } => Some(Zeroizing::new(psk)),
            _ => return Err(WirelessError::NotSupported),
        };
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        let mut storage = self.lifecycle.retained.lock().await;
        self.control_ready()?;
        let owner = storage.as_mut().ok_or(WirelessError::Busy)?;
        if owner.station_phase() != Some(station::Phase::Passive) {
            attempt.armed = false;
            return Err(WirelessError::Busy);
        }
        {
            self.rings.lock().await.clear();
        }
        let result = owner
            .station_associate(request.bssid, &request.ssid, pmk, &request.ie)
            .await;
        #[cfg(feature = "kernel-test")]
        if let Err(error) = &result {
            narf_console::klog!(
                "RTW native association failed {:?}, phase {:?}, peer {:?}\n",
                error,
                owner.station_phase(),
                owner.station_peer()
            );
        }
        attempt.armed = false;
        if self.closed() {
            self.link(None, false);
            return Err(WirelessError::HardwareError);
        }
        if self.publish_link(owner).is_err() {
            self.close();
            if !self.admission.teardown_pending() {
                let _ = owner.station_stop();
            }
            return Err(WirelessError::HardwareError);
        }
        result.map_err(error)
    }
    async fn disassociate(&self) -> Result<(), WirelessError> {
        let _disconnect = self
            .admission
            .begin_disconnect()
            .map_err(|_| WirelessError::Busy)?;
        self.close(); // metadata is down before the retained mutex can await.
        let mut storage = self.lifecycle.retained.lock().await;
        {
            self.rings.lock().await.clear();
        }
        let result = match storage.as_mut() {
            Some(owner) if owner.station_phase().is_some() => {
                owner.station_disconnect().await.map_err(error)
            }
            _ => Ok(()),
        };
        self.link(None, false);
        result
    }
    async fn set_config(&self, config: WirelessConfig) -> Result<(), WirelessError> {
        self.control_ready()?;
        if config.channel != 1 || config.tx_power_dbm.is_some() {
            return Err(WirelessError::NotSupported);
        }
        let mut storage = self.lifecycle.retained.lock().await;
        self.control_ready()?;
        let owner = storage.as_mut().ok_or(WirelessError::Busy)?;
        let result = owner.station_check();
        if result.is_err() {
            self.close();
            if !self.admission.teardown_pending() {
                let _ = owner.station_stop();
            }
        }
        result.map_err(error)
    }
}
pub(super) type Native = Device<super::pci_firmware::Transport>;
trait Endpoint: Send + Sync {
    fn send(&self, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()>;
    fn drain(&self) -> bool;
}
impl<I: Io + 'static> Endpoint for Device<I> {
    fn send(&self, b: &[u8], m: narf_net::TxMeta) -> Result<(), ()> {
        self.enqueue(b, m)
    }
    fn drain(&self) -> bool {
        Device::drain(self)
    }
}
static ACTIVE: IrqSafeSpinLock<Option<Arc<dyn Endpoint>>> = IrqSafeSpinLock::new(None);
static CLAIMED: AtomicBool = AtomicBool::new(false);
fn send(bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let device = ACTIVE.lock().clone().ok_or(())?;
    device.send(bytes, meta)
}
fn drain() -> bool {
    let device = ACTIVE.lock().clone();
    device.is_some_and(|d| d.drain())
}
pub(super) fn publish(device: Arc<Native>) -> Result<(), Error> {
    let driver = match device.lifecycle.device_id() {
        0xc821 => "rtw8821ce",
        0xc822 => "rtw8822ce",
        _ => return Err(Error::State),
    };
    let authority = narf_net::trusted_net_authority()
        .and_then(|cap| cap.derive().ok())
        .ok_or(Error::Profile)?;
    CLAIMED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| Error::State)?;
    narf_net::registry()
        .register(&authority, Registered(device.clone()))
        .map_err(|_| Error::Profile)?;
    narf_net::iface::register(&device.name, device.local, send);
    narf_net::iface::set_driver_info(&device.name, driver, None, String::new());
    narf_net::iface::set_offloads(&device.name, narf_net::OffloadCapabilities::default());
    device.link(None, false);
    *ACTIVE.lock() = Some(device.clone());
    narf_net::iface::install_rx_drain(drain);
    narf_wireless::registry::register(device.clone());
    device.published.store(true, Ordering::Release);
    narf_scheduler::spawn(async move {
        let mut ticks = 0u32;
        while !device.withdrawn() {
            device.drain();
            ticks = ticks.wrapping_add(1);
            // The station rate-limits itself to the source 2s period.
            if ticks % 250 == 0 {
                device.watchdog().await;
            }
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
        }
    });
    Ok(())
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

#[cfg(any(test, feature = "kernel-test"))]
#[path = "interface_tests.rs"]
mod tests;
