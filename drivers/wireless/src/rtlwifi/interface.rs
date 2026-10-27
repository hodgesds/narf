// SPDX-License-Identifier: GPL-2.0-or-later
//! One shared native EE view for async wireless control and synchronous stack
//! drains. No executor task is needed to complete DHCP/native packet receipts.
use super::{
    efuse::Factory,
    prepare::{
        packet::Port,
        station::{self, Environment},
        Memory, Phase, Prepared,
    },
};
use alloc::{boxed::Box, string::String, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};
use narf_wireless::{
    AssociateRequest, BssInfo, ScanRequest, SecurityConfig, WirelessConfig, WirelessError,
    WirelessNetIface,
};
use zeroize::Zeroizing;
type Error = station::Error;
struct EndpointState {
    rx: narf_ipc::Producer<Frame, RX_RING_N>,
    tx: narf_ipc::Consumer<Frame, TX_RING_N>,
    pending: Option<Frame>,
    epoch: u64,
}
struct Received {
    bytes: Vec<u8>,
    publication: Arc<station::Publication>,
}
impl EndpointState {
    fn clear(&mut self) {
        self.pending = None;
        for _ in 0..TX_RING_N {
            if !matches!(self.tx.try_recv(), Ok(Some(_))) {
                break;
            }
        }
    }
}
pub(crate) struct Device<I: Port<Buffer = M>, M: Memory, E: Environment> {
    pub(super) prepared: Arc<Mutex<Option<Prepared<I, M>>>>,
    state: Mutex<EndpointState>,
    factory: Arc<Factory>,
    environment: E,
    name: String,
    published: AtomicBool,
    admission: Arc<station::Admission>,
    up: AtomicBool,
    bssid: AtomicU64,
    ht: AtomicBool,
    rx: Arc<IrqSafeSpinLock<Option<narf_ipc::Consumer<Frame, RX_RING_N>>>>,
    tx: IrqSafeSpinLock<Option<narf_ipc::Producer<Frame, TX_RING_N>>>,
}
impl<I: Port<Buffer = M>, M: Memory, E: Environment> core::fmt::Debug for Device<I, M, E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8188eeDevice")
            .field("name", &self.name)
            .field("up", &self.up)
            .finish_non_exhaustive()
    }
}
struct Attempt<'a> {
    device: &'a dyn Close,
    owner: Option<Arc<AtomicBool>>,
    armed: bool,
}
trait Close: Sync {
    fn close(&self);
    fn request_abort(&self);
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if self.armed {
            if let Some(owner) = &self.owner {
                owner.store(true, Ordering::Release);
            }
            self.device.request_abort();
        }
    }
}
impl<I: Port<Buffer = M> + 'static, M: Memory + 'static, E: Environment + 'static> Close
    for Device<I, M, E>
{
    fn close(&self) {
        self.commit_close(self.admission.publication.lock());
    }
    fn request_abort(&self) {
        self.admission.abort.store(true, Ordering::Release);
        self.close();
    }
}
impl<I: Port<Buffer = M> + 'static, M: Memory + 'static, E: Environment + 'static> Device<I, M, E> {
    fn commit_close(&self, _publication: narf_lib::sync::IrqSafeSpinLockGuard<'_, ()>) {
        self.admission.closed.store(true, Ordering::Release);
        self.ht.store(false, Ordering::Release);
        *self.rx.lock() = None;
        self.update_link(None);
    }
    pub(super) fn new(
        name: &str,
        prepared: Arc<Mutex<Option<Prepared<I, M>>>>,
        factory: Arc<Factory>,
        environment: E,
    ) -> Self {
        let admission = environment
            .admission()
            .cloned()
            .unwrap_or_else(|| Arc::new(station::Admission::new()));
        let (rx, consumer) = narf_ipc::channel();
        let (producer, tx) = narf_ipc::channel();
        Self {
            prepared,
            state: Mutex::new(EndpointState {
                rx,
                tx,
                pending: None,
                epoch: 0,
            }),
            factory,
            environment,
            name: name.into(),
            published: AtomicBool::new(false),
            admission,
            up: AtomicBool::new(false),
            bssid: AtomicU64::new(0),
            ht: AtomicBool::new(false),
            rx: Arc::new(IrqSafeSpinLock::new(Some(consumer))),
            tx: IrqSafeSpinLock::new(Some(producer)),
        }
    }
    fn update_link(&self, peer: Option<[u8; 6]>) {
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
        if was && !up {
            narf_wireless::nl80211::notify_disconnect(&self.name, 1, false);
        }
    }
    fn link(&self, peer: Option<[u8; 6]>) {
        let _publication = self.admission.publication.lock();
        self.update_link(peer.filter(|_| !self.admission.closed.load(Ordering::Acquire)));
    }
    async fn ready(&self, owner: &mut Prepared<I, M>) -> Result<(), Error> {
        if self.admission.closed.load(Ordering::Acquire) || !self.published.load(Ordering::Acquire)
        {
            return Err(Error::State);
        }
        if matches!(
            owner.phase(),
            Phase::RadioConfigured | Phase::ChannelConfigured
        ) {
            let calibration = super::channel_power::Calibration::load_registered(&self.factory)
                .map_err(|_| Error::Profile)?;
            let domain = self.environment.domain()?;
            let permission = calibration
                .permission(&domain, 1)
                .map_err(|_| Error::Profile)?;
            owner.configure_channel(permission).await?;
            owner.configure_mac(&self.factory)?;
            owner.stage_station_calibration(calibration, &domain)?;
        }
        if owner.phase() == Phase::MacConfigured && !owner.station_calibration_present() {
            let calibration = super::channel_power::Calibration::load_registered(&self.factory)
                .map_err(|_| Error::Profile)?;
            owner.stage_station_calibration(calibration, &self.environment.domain()?)?;
        }
        if owner.station_phase() == station::Phase::Dormant {
            let rx = self.rx.clone();
            owner.station_receive_retirement(Arc::new(move || {
                *rx.lock() = None;
            }));
            if let Err(e) = owner.prepare_station_ht(&self.environment) {
                if owner.phase() == Phase::Failed || owner.station_ht_capability().is_some() {
                    owner.abort_station();
                    self.close();
                }
                return Err(e);
            }
            self.ht
                .store(owner.station_ht_capability().is_some(), Ordering::Release);
            owner.start_station_service(&self.environment).await?;
        }
        if owner.station_phase() == station::Phase::Failed {
            return Err(Error::State);
        }
        Ok(())
    }
    pub(super) fn enqueue(&self, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
        if self.admission.closed.load(Ordering::Acquire)
            || !self.up.load(Ordering::Acquire)
            || !admitted(bytes, self.factory.mac)
            || !offloads(meta)
        {
            return Err(());
        }
        let publication = {
            let owner = self.prepared.try_lock().ok_or(())?;
            let owner = owner.as_ref().ok_or(())?;
            if owner.station_peer().is_none() {
                return Err(());
            }
            owner
                .station_publication_token(&self.environment)
                .map_err(|_| {
                    self.request_abort();
                })?
        };
        let buffer = narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
            .map_err(|_| ())?;
        let mut frame = Frame::new(buffer, bytes.len() as u32);
        frame.payload_mut().copy_from_slice(bytes);
        frame.set_tx_meta(meta);
        let result = self.environment.domain().and_then(|domain| {
            publication.invoke(&domain, || {
                Ok(self
                    .tx
                    .lock()
                    .as_mut()
                    .ok_or(())
                    .and_then(|tx| tx.try_send(frame).map_err(|_| ())))
            })
        });
        match result {
            Ok(Some(result)) => result,
            Ok(None) => Err(()),
            Err(_) => {
                self.request_abort();
                Err(())
            }
        }
    }
    fn progress(&self) -> Vec<Received> {
        let Some(mut storage) = self.prepared.try_lock() else {
            return Vec::new();
        };
        let Some(owner) = storage.as_mut() else {
            return Vec::new();
        };
        let Some(mut state) = self.state.try_lock() else {
            return Vec::new();
        };
        if self.admission.closed.load(Ordering::Acquire) {
            state.clear();
            if self.admission.abort.load(Ordering::Acquire)
                || owner.station_phase() == station::Phase::Failed
            {
                owner.abort_station();
            }
            return Vec::new();
        }
        if !matches!(
            owner.station_phase(),
            station::Phase::Passive | station::Phase::Open | station::Phase::Failed
        ) {
            return Vec::new();
        }
        let result: Result<Vec<Received>, Error> = (|| {
            let frames = owner.progress_station(&self.environment)?;
            owner.station_publication(&self.environment, || {
                self.link(owner.station_peer());
                Ok(())
            })?;
            let (_, epoch) = owner.station_receive_epoch();
            if state.epoch != epoch {
                let (producer, consumer) = narf_ipc::channel();
                state.rx = producer;
                *self.rx.lock() = Some(consumer);
                state.epoch = epoch;
            }
            if self.admission.closed.load(Ordering::Acquire) {
                state.clear();
                return Ok(Vec::new());
            }
            if owner.station_peer().is_none() {
                state.clear();
                return Ok(Vec::new());
            }
            if state.pending.is_none() {
                for _ in 0..16 {
                    let Ok(Some(frame)) = state.tx.try_recv() else {
                        break;
                    };
                    if admitted(frame.payload(), self.factory.mac) && offloads(frame.tx_meta()) {
                        state.pending = Some(frame);
                        break;
                    }
                }
            }
            if owner.station_transmit_ready() && !self.admission.closed.load(Ordering::Acquire) {
                if let Some(frame) = state.pending.take() {
                    owner.send_station_ethernet(frame.payload(), &self.environment)?;
                }
            }
            if self.admission.closed.load(Ordering::Acquire) {
                state.clear();
                return Ok(Vec::new());
            }
            let publication = Arc::new(owner.station_publication_token(&self.environment)?);
            if !owner.station_receive_open() {
                return Ok(Vec::new());
            }
            for bytes in &frames {
                if let Ok(buffer) =
                    narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
                {
                    let mut frame = Frame::new(buffer, bytes.len() as u32);
                    frame.payload_mut().copy_from_slice(bytes);
                    publication.invoke(&self.environment.domain()?, || {
                        let _ = state.rx.try_send(frame);
                        Ok(())
                    })?;
                }
            }
            Ok(frames
                .into_iter()
                .map(|bytes| Received {
                    bytes,
                    publication: publication.clone(),
                })
                .collect())
        })();
        match result {
            Ok(frames) => frames,
            Err(_) => {
                owner.abort_station();
                state.clear();
                self.close();
                Vec::new()
            }
        }
    }
    pub(super) fn drain(&self) -> bool {
        // Every owner/state guard has dropped before stack dispatch; ARP/ND
        // can synchronously re-enter this device's enqueue callback.
        let frames = self.progress();
        let progressed = !frames.is_empty();
        for frame in frames {
            if self.admission.closed.load(Ordering::Acquire) || !frame.publication.current() {
                break;
            }
            // The retained owner proves the current controlled port; only an
            // owned epoch/source/PCI token survives into the unlocked callback.
            let allowed = {
                let Some(storage) = self.prepared.try_lock() else {
                    break;
                };
                storage.as_ref().is_some_and(|owner| {
                    owner.station_receive_open() && frame.publication.current()
                })
            };
            if !allowed {
                break;
            }
            let mut bytes = frame.bytes;
            let result = self.environment.domain().and_then(|domain| {
                frame.publication.invoke(&domain, || {
                    if !self.admission.closed.load(Ordering::Acquire) {
                        narf_net::iface::on_rx_frame_from(&self.name, &mut bytes);
                    }
                    Ok(())
                })
            });
            if result.is_err() {
                self.request_abort();
                break;
            }
        }
        progressed
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn admit_for_test(&self) {
        self.published.store(true, Ordering::Release);
    }
}
fn admitted(bytes: &[u8], own: [u8; 6]) -> bool {
    (14..=1514).contains(&bytes.len())
        && bytes[6..12] == own
        && bytes[..6] != [0; 6]
        && u16::from_be_bytes([bytes[12], bytes[13]]) >= 0x600
        && !matches!(&bytes[12..14], [0x88, 0x8e] | [0x80, 0xf3] | [0x81, 0x37])
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
impl<I: Port<Buffer = M> + 'static, M: Memory + 'static, E: Environment + 'static> Interface
    for Device<I, M, E>
{
    fn name(&self) -> &str {
        &self.name
    }
    fn mac(&self) -> [u8; 6] {
        self.factory.mac
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        !self.admission.closed.load(Ordering::Acquire) && self.up.load(Ordering::Acquire)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<narf_ipc::Consumer<Frame, RX_RING_N>>> {
        &self.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<narf_ipc::Producer<Frame, TX_RING_N>>> {
        &self.tx
    }
}
#[async_trait::async_trait]
impl<I: Port<Buffer = M> + 'static, M: Memory + 'static, E: Environment + 'static> WirelessNetIface
    for Device<I, M, E>
{
    fn supports_handshake_offload(&self) -> bool {
        true
    }
    fn reports_disconnect_events(&self) -> bool {
        true
    }
    fn supports_scan_dwell(&self) -> bool {
        true
    }
    fn connected_bssid(&self) -> Option<[u8; 6]> {
        if self.admission.closed.load(Ordering::Acquire) {
            return None;
        }
        let bytes = self.bssid.load(Ordering::Acquire).to_le_bytes();
        (bytes[7] != 0).then(|| bytes[..6].try_into().unwrap())
    }
    fn cipher_suites(&self) -> &'static [u32] {
        &[0x000fac04]
    }
    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.prepared
            .try_lock()?
            .as_ref()?
            .station_candidates(self.environment.now_ms())
            .into_iter()
            .find(|candidate| candidate.bss.bssid == bssid)
            .map(|candidate| candidate.bss.information_elements)
    }
    fn get_wireless_info(&self) -> narf_wireless::WirelessIfaceInfo {
        use narf_wireless::iface::*;
        WirelessIfaceInfo {
            base_name: self.name.clone(),
            base_mac: self.factory.mac,
            bands: vec![WirelessBand {
                freq_mhz: 2400,
                channels: vec![1],
            }],
            modes: WirelessModes::STATION,
            hw_caps: HwCaps {
                ht_supported: self.ht.load(Ordering::Acquire),
                vht_supported: false,
                he_supported: false,
                eht_supported: false,
            },
        }
    }
    fn phy_capabilities(&self, band: u32) -> Option<narf_wireless::iface::PhyCapabilities> {
        (band == 2400 && self.ht.load(Ordering::Acquire)).then(|| {
            narf_wireless::iface::PhyCapabilities {
                ht: narf_wireless::association::phy::LocalHt::siso20(false, false)
                    .capability_body(),
                vht: None,
            }
        })
    }
    async fn scan(&self, request: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        let dwell = scan_dwell(&request)?;
        if self.admission.closed.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        let mut storage = self.prepared.lock().await;
        let owner = storage
            .as_mut()
            .ok_or(if self.environment.preparation_failed() {
                WirelessError::HardwareError
            } else {
                WirelessError::Busy
            })?;
        self.ready(owner).await.map_err(error)?;
        if owner.station_phase() != station::Phase::Passive {
            return Err(WirelessError::Busy);
        }
        let mut attempt = Attempt {
            device: self,
            owner: Some(owner.station_cancellation()),
            armed: true,
        };
        let deadline = self.environment.now_ms().saturating_add(dwell);
        let result = async {
            loop {
                owner.progress_station(&self.environment)?;
                if self.environment.now_ms() >= deadline {
                    break;
                }
                self.environment.pause().await;
            }
            Ok::<_, Error>(
                owner
                    .station_candidates(self.environment.now_ms())
                    .into_iter()
                    .filter(|candidate| {
                        request.ssids.is_empty()
                            || request
                                .ssids
                                .iter()
                                .any(|ssid| ssid.is_empty() || *ssid == candidate.bss.ssid)
                    })
                    .map(|candidate| BssInfo {
                        bssid: candidate.bss.bssid,
                        ssid: candidate.bss.ssid,
                        channel: 1,
                        frequency_mhz: 2412,
                        rssi: i8::MIN,
                        security: if candidate.rsne.is_some() {
                            narf_wireless::scan::BssSecurity::Wpa2
                        } else if candidate.bss.capability & 16 != 0 {
                            narf_wireless::scan::BssSecurity::Wep
                        } else {
                            narf_wireless::scan::BssSecurity::Open
                        },
                    })
                    .collect(),
            )
        }
        .await;
        attempt.armed = false;
        if result.is_err() {
            owner.abort_station();
            self.close();
        }
        result.map_err(error)
    }
    async fn associate(&self, request: AssociateRequest) -> Result<(), WirelessError> {
        if self.admission.closed.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        if request.channel != 1 || request.frequency_mhz != 2412 {
            return Err(WirelessError::NotSupported);
        }
        let (mode, pmk) = match request.security {
            SecurityConfig::Open => (narf_wireless::association::SecurityMode::Open, None),
            SecurityConfig::Wpa2 { psk } => (
                narf_wireless::association::SecurityMode::Wpa2Psk,
                Some(Zeroizing::new(psk)),
            ),
            _ => return Err(WirelessError::NotSupported),
        };
        let mut storage = self.prepared.lock().await;
        let owner = storage.as_mut().ok_or(WirelessError::Busy)?;
        self.ready(owner).await.map_err(error)?;
        if owner.station_phase() != station::Phase::Passive {
            return Err(WirelessError::Busy);
        }
        self.state.lock().await.clear();
        let mut attempt = Attempt {
            device: self,
            owner: Some(owner.station_cancellation()),
            armed: true,
        };
        let result = owner
            .connect_station(
                request.bssid,
                &request.ssid,
                mode,
                pmk,
                &request.ie,
                &self.environment,
            )
            .await;
        attempt.armed = false;
        if self.admission.closed.load(Ordering::Acquire) {
            owner.abort_station();
            return Err(WirelessError::HardwareError);
        }
        if result.is_err() && owner.station_phase() == station::Phase::Failed {
            self.close();
        }
        if result.is_ok() {
            if let Err(e) = owner.station_publication(&self.environment, || {
                self.link(owner.station_peer());
                Ok(())
            }) {
                owner.abort_station();
                self.close();
                return Err(error(e));
            }
        } else {
            self.link(owner.station_peer());
        }
        result.map_err(error)
    }
    async fn disassociate(&self) -> Result<(), WirelessError> {
        self.close();
        let mut attempt = Attempt {
            device: self,
            owner: None,
            armed: true,
        };
        let mut storage = self.prepared.lock().await;
        self.state.lock().await.clear();
        self.close();
        let owner = storage.as_mut().ok_or(WirelessError::Busy)?;
        let result = owner.disconnect_station().await.map_err(error);
        attempt.armed = false;
        result
    }
    async fn set_config(&self, config: WirelessConfig) -> Result<(), WirelessError> {
        if config.channel == 1 && config.tx_power_dbm.is_none() {
            Ok(())
        } else {
            Err(WirelessError::NotSupported)
        }
    }
}
fn scan_dwell(request: &ScanRequest) -> Result<u64, WirelessError> {
    if request.active
        || request.random_mac.is_some()
        || request.colocated_6ghz
        || !request.extra_ies.is_empty()
        || request
            .frequencies_mhz
            .iter()
            .any(|frequency| *frequency != 2412)
        || request.frequencies_mhz.is_empty()
            && request.channels.iter().any(|channel| *channel != 1)
        || request.ssids.len() > 32
        || request.ssids.iter().any(|ssid| ssid.len() > 32)
    {
        return Err(WirelessError::NotSupported);
    }
    match request.duration_tu {
        Some(duration @ 1..=1000) => Ok((u64::from(duration) * 1024).div_ceil(1000)),
        Some(_) => Err(WirelessError::InvalidArgs),
        None if request.duration_mandatory => Err(WirelessError::InvalidArgs),
        None => Ok(200),
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub(super) mod publication_test {
    use super::*;
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Waker},
    };

    pub(in crate::rtlwifi) async fn paused_publisher_then_close<
        I: Port<Buffer = M> + 'static,
        M: Memory + 'static,
        E: Environment + 'static,
    >(
        device: &Device<I, M, E>,
    ) -> Result<(), &'static str> {
        let publication = device.admission.publication.lock();
        let peer = device
            .connected_bssid()
            .ok_or("EE paused publisher lacks carrier")?;
        let mut close = pin!(core::future::poll_fn(|cx| {
            if let Some(publication) = device.admission.publication.try_lock() {
                device.commit_close(publication);
                core::task::Poll::Ready(())
            } else {
                cx.waker().wake_by_ref();
                core::task::Poll::Pending
            }
        }));
        if close
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return Err("EE close bypassed paused publisher gate");
        }
        // Complete the already-entered peer decision and all metadata writes
        // before permitting the exact production close commit to run.
        device.update_link(Some(peer));
        drop(publication);
        close.await;
        device.link(Some(peer));
        if device.link_up()
            || device.connected_bssid().is_some()
            || narf_net::iface::lookup(device.name())
                .is_none_or(|iface| !iface.link_up || iface.carrier)
        {
            return Err("EE paused publisher survived completed close");
        }
        Ok(())
    }

    pub(in crate::rtlwifi) async fn disconnect_after_old_publication<
        I: Port<Buffer = M> + 'static,
        M: Memory + 'static,
        E: Environment + 'static,
    >(
        device: &Device<I, M, E>,
        peer: [u8; 6],
    ) -> Result<(), &'static str> {
        let storage = device.prepared.try_lock().ok_or("EE fixture owner busy")?;
        if storage.as_ref().and_then(Prepared::station_peer) != Some(peer) {
            return Err("EE fixture lacks previous native station");
        }
        let mut disconnect = pin!(device.disassociate());
        if disconnect
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
            || device.link_up()
            || device.connected_bssid().is_some()
        {
            return Err("EE disconnect failed to close before waiting for native owner");
        }
        // Replay precisely progress()'s already-entered stale publication.
        device.link(storage.as_ref().and_then(Prepared::station_peer));
        if device.link_up()
            || device.connected_bssid().is_some()
            || narf_net::iface::lookup(device.name())
                .is_none_or(|iface| iface.carrier || !iface.link_up)
        {
            return Err("EE stale native publisher reopened closed station");
        }
        drop(storage);
        disconnect
            .await
            .map_err(|_| "EE interleaved native disconnect failed")
    }
}

pub(super) struct NativeEnvironment {
    admission: Arc<station::Admission>,
    firmware: Arc<super::firmware_transport::Owner<super::firmware_native::PciIo>>,
}
/// Live station work consumes only the current installation. The explicit
/// native preparation boundary owns signed-policy bootstrap.
pub(super) fn installed_domain(
    snapshot: Option<Arc<narf_wireless::reg::RegulatoryDomain>>,
) -> Result<narf_wireless::reg::RegulatoryDomain, Error> {
    snapshot
        .map(|domain| domain.as_ref().clone())
        .ok_or(Error::Profile)
}
impl NativeEnvironment {
    pub(super) fn new(
        firmware: Arc<super::firmware_transport::Owner<super::firmware_native::PciIo>>,
    ) -> Self {
        Self {
            firmware,
            admission: Arc::new(station::Admission::new()),
        }
    }
}
impl Environment for NativeEnvironment {
    fn ht20(
        &self,
        base: Arc<super::channel_power::Calibration>,
    ) -> Result<Option<Arc<super::ht::Grant>>, Error> {
        super::ht::Grant::registered(base, self.firmware.identity().ok_or(Error::State)?)
            .map_err(Error::Radio)
    }
    fn admission(&self) -> Option<&Arc<station::Admission>> {
        Some(&self.admission)
    }
    fn now_ms(&self) -> u64 {
        narf_time::wall::monotonic_ns() / 1_000_000
    }
    fn fresh_nonce(&self) -> Option<[u8; 32]> {
        let mut bytes = [0; 32];
        narf_crypto::try_fill_random_bytes(&mut bytes)
            .ok()
            .map(|()| bytes)
    }
    fn domain(&self) -> Result<narf_wireless::reg::RegulatoryDomain, Error> {
        installed_domain(narf_wireless::reg::db::snapshot())
    }
    async fn pause(&self) {
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
    }
    fn preparation_failed(&self) -> bool {
        self.firmware.status().stage == super::firmware_transport::Stage::Failed
    }
}
pub(super) type Native = Device<
    super::firmware_transport::PacketIo<super::firmware_native::PciIo>,
    super::prepare_native::Coherent,
    NativeEnvironment,
>;
trait Endpoint: Send + Sync {
    fn send(&self, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()>;
    fn drain(&self) -> bool;
}
impl<I: Port<Buffer = M> + 'static, M: Memory + 'static, E: Environment + 'static> Endpoint
    for Device<I, M, E>
{
    fn send(&self, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
        self.enqueue(bytes, meta)
    }
    fn drain(&self) -> bool {
        Device::drain(self)
    }
}
static ACTIVE: IrqSafeSpinLock<Option<Arc<dyn Endpoint>>> = IrqSafeSpinLock::new(None);
static CLAIMED: AtomicBool = AtomicBool::new(false);
fn send(bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let owner = ACTIVE.lock().clone().ok_or(())?;
    owner.send(bytes, meta)
}
fn drain() -> bool {
    let owner = ACTIVE.lock().clone();
    owner.is_some_and(|owner| owner.drain())
}
pub(super) fn publish(device: Arc<Native>) -> Result<(), Error> {
    let authority = narf_net::trusted_net_authority()
        .and_then(|cap| cap.derive().ok())
        .ok_or(Error::Profile)?;
    CLAIMED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| Error::State)?;
    narf_net::registry()
        .register(&authority, Registered(device.clone()))
        .map_err(|_| Error::Profile)?;
    *ACTIVE.lock() = Some(device.clone());
    narf_net::iface::register(&device.name, device.factory.mac, send);
    device.link(None);
    device.published.store(true, Ordering::Release);
    narf_net::iface::install_rx_drain(drain);
    narf_wireless::registry::register(device.clone());
    narf_scheduler::spawn(async move {
        loop {
            device.drain();
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
