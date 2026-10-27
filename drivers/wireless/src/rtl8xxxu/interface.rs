//! Channel1 legacy station publication over one retained native USB owner.
//! Signed board qualification and deployment policy precede any publication.
use super::{
    firmware_transport::{ControlIo, Owner as Firmware, UsbControl},
    management_runtime::{Candidate, SecurityMode},
    packet_transport::{Io as PacketIo, UsbIo},
    power_policy,
    receive_runtime::{Permission as ReceivePermission, Receiver},
    service_runtime::{self, Environment, Service},
};
use alloc::{boxed::Box, string::String, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use narf_ipc::{Consumer, Producer};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};
use narf_wireless::{
    AssociateRequest, BssInfo, ScanRequest, SecurityConfig, WirelessConfig, WirelessError,
    WirelessNetIface,
};
use zeroize::Zeroizing;
#[derive(Debug)]
pub struct NativeEnvironment;
impl Environment for NativeEnvironment {
    fn now_ms(&self) -> u64 {
        narf_time::wall::monotonic_ns() / 1_000_000
    }
    fn fresh_nonce(&self) -> Result<[u8; 32], service_runtime::Error> {
        let mut nonce = [0; 32];
        narf_crypto::try_fill_random_bytes(&mut nonce)
            .map_err(|_| service_runtime::Error::Entropy)?;
        Ok(nonce)
    }
    async fn pause(&self) {
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
    }
}
struct State<C: ControlIo, B: PacketIo, E: Environment> {
    service: Service<C, B, E>,
    rx: Producer<Frame, RX_RING_N>,
    tx: Consumer<Frame, TX_RING_N>,
    pending: Option<Frame>,
    epoch: u64,
}
struct Delivery {
    frames: Vec<Vec<u8>>,
    epoch: Arc<AtomicU64>,
    generation: u64,
    authority: super::receive_runtime::Authority,
}
impl<C: ControlIo, B: PacketIo, E: Environment> State<C, B, E> {
    fn clear_transmit(&mut self) {
        self.pending = None;
        for _ in 0..TX_RING_N {
            if !matches!(self.tx.try_recv(), Ok(Some(_))) {
                break;
            }
        }
    }
    fn progress(&mut self) -> Result<Vec<Vec<u8>>, service_runtime::Error> {
        let frames = match self.service.poll() {
            Ok(frames) => frames,
            Err(error) => {
                self.clear_transmit();
                return Err(error);
            }
        };
        if self.service.connected_peer().is_none() {
            self.clear_transmit();
            return Ok(frames);
        }
        if self.pending.is_none() {
            for _ in 0..16 {
                let Ok(Some(frame)) = self.tx.try_recv() else {
                    break;
                };
                if transmit_admitted(frame.payload(), self.service.local())
                    && offloads_admitted(frame.tx_meta())
                {
                    self.pending = Some(frame);
                    break;
                }
            }
        }
        if self.service.transmit_ready() {
            if let Some(pending) = self.pending.take() {
                if let Err(error) = self.service.transmit(pending.payload()) {
                    self.clear_transmit();
                    return Err(error);
                }
            }
        }
        Ok(frames)
    }
}
pub struct Device<C: ControlIo, B: PacketIo, E: Environment> {
    state: Mutex<State<C, B, E>>,
    name: String,
    mac: [u8; 6],
    up: AtomicBool,
    bssid: AtomicU64,
    closed: AtomicBool,
    failed: Arc<AtomicBool>,
    ht: bool,
    rx: Arc<IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>>,
    tx: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}
impl<C: ControlIo, B: PacketIo, E: Environment> core::fmt::Debug for Device<C, B, E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8188euDevice")
            .field("name", &self.name)
            .field("mac", &self.mac)
            .finish_non_exhaustive()
    }
}
impl<C: ControlIo, B: PacketIo, E: Environment> Device<C, B, E> {
    pub(super) fn new(name: &str, mut service: Service<C, B, E>) -> Self {
        let mac = service.local();
        let (rx, rx_consumer) = narf_ipc::channel();
        let (tx_producer, tx) = narf_ipc::channel();
        let rx_consumer = Arc::new(IrqSafeSpinLock::new(Some(rx_consumer)));
        let retire = rx_consumer.clone();
        service.set_retirement(Arc::new(move || {
            *retire.lock() = None;
        }));
        let failed = service.close_flag();
        let ht = service.ht_enabled();
        Self {
            state: Mutex::new(State {
                service,
                rx,
                tx,
                pending: None,
                epoch: 0,
            }),
            name: name.into(),
            mac,
            up: AtomicBool::new(false),
            bssid: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            failed,
            ht,
            rx: rx_consumer,
            tx: IrqSafeSpinLock::new(Some(tx_producer)),
        }
    }
    fn link(&self, peer: Option<[u8; 6]>) {
        let peer = peer.filter(|_| {
            !self.closed.load(Ordering::Acquire) && !self.failed.load(Ordering::Acquire)
        });
        let mut packed = [0; 8];
        if let Some(peer) = peer {
            packed[..6].copy_from_slice(&peer);
            packed[7] = 1;
        }
        self.bssid
            .store(u64::from_le_bytes(packed), Ordering::Release);
        let up = peer.is_some();
        let was_up = self.up.swap(up, Ordering::AcqRel);
        // Physical carrier preserves operator-controlled IFF_UP and never
        // invokes an administrative open/stop hook under retained locks.
        narf_net::iface::set_link_metadata(&self.name, up, None, None);
        if was_up && !up {
            narf_wireless::nl80211::notify_disconnect(&self.name, 1, false);
        }
    }
    /// Locks are released before stack dispatch: ARP/ND may immediately call
    /// the same device's transmit callback from this synchronous drain.
    pub(super) fn progress(&self) -> Vec<Vec<u8>> {
        self.progress_batch()
            .map(|batch| batch.frames)
            .unwrap_or_default()
    }
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.failed.store(true, Ordering::Release);
        *self.rx.lock() = None;
        self.link(None);
    }
    fn refresh_receive(&self, state: &mut State<C, B, E>) {
        if let Some((_, generation)) = state.service.receive_epoch() {
            if state.epoch != generation {
                let (producer, consumer) = narf_ipc::channel();
                state.rx = producer;
                *self.rx.lock() = Some(consumer);
                state.epoch = generation;
            }
        }
    }
    fn progress_batch(&self) -> Option<Delivery> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        let mut state = self.state.try_lock()?;
        let frames = match state.progress() {
            Ok(frames) => frames,
            Err(_) => {
                self.close();
                return None;
            }
        };
        let authority = match state.service.current() {
            Ok(p) => p,
            Err(_) => {
                self.close();
                return None;
            }
        };
        if authority
            .invoke(|| self.link(state.service.connected_peer()))
            .is_err()
        {
            self.close();
            return None;
        }
        let (epoch, generation) = state.service.receive_epoch()?;
        self.refresh_receive(&mut state);
        if !state.service.receive_open() {
            return None;
        }
        for bytes in &frames {
            if let Ok(buffer) =
                narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
            {
                let mut frame = Frame::new(buffer, bytes.len() as u32);
                frame.payload_mut().copy_from_slice(bytes);
                if authority
                    .invoke(|| {
                        if !self.closed.load(Ordering::Acquire)
                            && !self.failed.load(Ordering::Acquire)
                            && epoch.load(Ordering::Acquire) == generation
                        {
                            let _ = state.rx.try_send(frame);
                        }
                    })
                    .is_err()
                {
                    self.close();
                    return None;
                }
            }
        }
        Some(Delivery {
            frames,
            epoch,
            generation,
            authority,
        })
    }
    pub(super) fn enqueue(&self, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
        if !self.up.load(Ordering::Acquire)
            || self.closed.load(Ordering::Acquire)
            || self.failed.load(Ordering::Acquire)
            || !transmit_admitted(bytes, self.mac)
            || !offloads_admitted(meta)
        {
            return Err(());
        }
        let (authority, epoch, generation) = {
            let state = self.state.try_lock().ok_or(())?;
            if !state.service.receive_open() {
                return Err(());
            }
            let authority = state.service.current().map_err(|_| self.close())?;
            let (epoch, generation) = state.service.receive_epoch().ok_or(())?;
            (authority, epoch, generation)
        };
        let buffer = narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
            .map_err(|_| ())?;
        let mut frame = Frame::new(buffer, bytes.len() as u32);
        frame.payload_mut().copy_from_slice(bytes);
        frame.set_tx_meta(meta);
        authority
            .invoke(|| {
                if self.closed.load(Ordering::Acquire)
                    || self.failed.load(Ordering::Acquire)
                    || epoch.load(Ordering::Acquire) != generation
                {
                    return Err(());
                }
                self.tx
                    .lock()
                    .as_mut()
                    .ok_or(())?
                    .try_send(frame)
                    .map_err(|_| ())
            })
            .map_err(|_| self.close())?
    }
    pub(super) fn drain(&self) -> bool {
        self.dispatch_with(|frame| narf_net::iface::on_rx_frame_from(&self.name, frame))
    }
    pub(super) fn dispatch_with(&self, mut callback: impl FnMut(&mut [u8])) -> bool {
        let Some(batch) = self.progress_batch() else {
            return false;
        };
        let mut progress = false;
        for mut frame in batch.frames {
            let Some(state) = self.state.try_lock() else {
                break;
            };
            let current = state
                .service
                .receive_epoch()
                .is_some_and(|(epoch, generation)| {
                    Arc::ptr_eq(&epoch, &batch.epoch) && generation == batch.generation
                })
                && state.service.receive_open();
            if !current {
                break;
            }
            if state.service.current().is_err() {
                self.close();
                break;
            }
            drop(state);
            // No owner/ring/admission lock survives into a reentrant stack callback.
            let result = batch.authority.invoke(|| {
                if self.closed.load(Ordering::Acquire)
                    || self.failed.load(Ordering::Acquire)
                    || batch.epoch.load(Ordering::Acquire) != batch.generation
                {
                    return false;
                }
                callback(&mut frame);
                true
            });
            match result {
                Ok(delivered) => progress |= delivered,
                Err(_) => {
                    self.close();
                    break;
                }
            }
        }
        progress
    }
}
trait Endpoint: Send + Sync {
    fn send(&self, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()>;
    fn drain(&self) -> bool;
}
impl<C: ControlIo + 'static, B: PacketIo + 'static, E: Environment + 'static> Endpoint
    for Device<C, B, E>
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
    let active = ACTIVE.lock().clone().ok_or(())?;
    active.send(bytes, meta)
}
fn drain() -> bool {
    let active = ACTIVE.lock().clone();
    active.is_some_and(|owner| owner.drain())
}
fn authenticated_domain() -> Result<narf_wireless::reg::RegulatoryDomain, service_runtime::Error> {
    // This profile requires a fresh signed deployment artifact per attach;
    // preserve that stronger contract instead of consulting the shared cache.
    narf_wireless::reg::policy::load().map_err(|_| service_runtime::Error::Profile)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Admission {
    Ready,
    PendingAssets,
}
pub(super) fn classify_attach_admission(
    has_net_authority: bool,
    has_loader_authority: bool,
    domain: Result<narf_wireless::reg::RegulatoryDomain, narf_wireless::reg::policy::Error>,
    calibration: Result<power_policy::Calibration, power_policy::Error>,
) -> Result<Admission, service_runtime::Error> {
    let domain = match domain {
        Ok(_) => true,
        Err(narf_wireless::reg::policy::Error::Firmware(
            narf_firmware::FirmwareError::NotFound,
        )) => false,
        Err(narf_wireless::reg::policy::Error::Authority) if !has_loader_authority => false,
        Err(_) => return Err(service_runtime::Error::Profile),
    };
    let calibration = match calibration {
        Ok(_) => true,
        Err(power_policy::Error::Firmware(narf_firmware::FirmwareError::NotFound)) => false,
        Err(power_policy::Error::Firmware(narf_firmware::FirmwareError::AuthorityRevoked))
            if !has_loader_authority =>
        {
            false
        }
        Err(_) => return Err(service_runtime::Error::Profile),
    };
    if has_net_authority && domain && calibration {
        Ok(Admission::Ready)
    } else {
        Ok(Admission::PendingAssets)
    }
}
pub async fn wait_attach(
    firmware: Arc<Firmware<UsbControl>>,
) -> Result<Arc<Device<UsbControl, UsbIo, NativeEnvironment>>, service_runtime::Error> {
    loop {
        if firmware.status().stage != super::firmware_transport::Stage::RadioReady
            || firmware.calibration().is_none()
            || CLAIMED.load(Ordering::Acquire)
        {
            return Err(service_runtime::Error::State);
        }
        let factory = firmware.factory().ok_or(service_runtime::Error::State)?;
        let (vid, pid) = firmware
            .usb_identity()
            .ok_or(service_runtime::Error::State)?;
        let has_loader = narf_firmware::trusted_loader_authority().is_some();
        let has_net = narf_net::trusted_net_authority().is_some();
        match classify_attach_admission(
            has_net,
            has_loader,
            narf_wireless::reg::policy::load(),
            power_policy::Calibration::load_registered(factory, vid, pid),
        )? {
            Admission::Ready => return attach(firmware).await,
            Admission::PendingAssets => {
                narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(500_000_000)).await;
            }
        }
    }
}
/// Publish only after actual firmware/IQK, signed board-power data and signed
/// deployment policy have admitted this exact device. No real curve is shipped.
/// The initial profile retains one association per firmware claim; reset and
/// broader channel/rate profiles remain separate explicit software stages.
pub async fn attach(
    firmware: Arc<Firmware<UsbControl>>,
) -> Result<Arc<Device<UsbControl, UsbIo, NativeEnvironment>>, service_runtime::Error> {
    if firmware.status().stage != super::firmware_transport::Stage::RadioReady
        || firmware.calibration().is_none()
    {
        return Err(service_runtime::Error::State);
    }
    let usb = firmware.usb_device();
    let authority = narf_net::trusted_net_authority()
        .and_then(|cap| cap.derive().ok())
        .ok_or(service_runtime::Error::Profile)?;
    let domain = authenticated_domain()?;
    let factory = firmware.factory().ok_or(service_runtime::Error::State)?;
    let (vid, pid) = firmware
        .usb_identity()
        .ok_or(service_runtime::Error::State)?;
    let calibration = power_policy::Calibration::load_registered(factory, vid, pid)
        .map_err(|_| service_runtime::Error::Profile)?;
    let power = calibration
        .permission(&domain, 1)
        .map_err(|_| service_runtime::Error::Profile)?;
    let receive = ReceivePermission::from_domain(&domain).map_err(service_runtime::Error::Radio)?;
    let profile = Receiver::<UsbControl, UsbIo>::resolve_profile(&firmware, power)
        .map_err(service_runtime::Error::Radio)?;
    // Reserve the singleton before claiming firmware or posting persistent RX.
    // A failed/cancelled claim is terminal; a new software object cannot retry.
    CLAIMED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| service_runtime::Error::State)?;
    let mut receiver =
        Receiver::new(firmware, UsbIo::new(usb), receive).map_err(service_runtime::Error::Radio)?;
    receiver
        .prepare_profile(profile)
        .await
        .map_err(service_runtime::Error::Radio)?;
    let service = Service::start(receiver, power, NativeEnvironment).await?;
    let name = narf_net::iface::reserve_name("wlan%d");
    let device = Arc::new(Device::new(name, service));
    narf_net::registry()
        .register(&authority, Registered(device.clone()))
        .map_err(|_| service_runtime::Error::Profile)?;
    *ACTIVE.lock() = Some(device.clone());
    narf_net::iface::register(name, device.mac, send);
    narf_net::iface::set_link_state(name, false);
    narf_net::iface::install_rx_drain(drain);
    narf_wireless::registry::register(device.clone());
    let worker = device.clone();
    narf_scheduler::spawn(async move {
        loop {
            worker.drain();
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
        }
    });
    Ok(device)
}
impl<C: ControlIo + 'static, B: PacketIo + 'static, E: Environment + 'static> Interface
    for Device<C, B, E>
{
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
        self.up.load(Ordering::Acquire)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx
    }
}
#[async_trait::async_trait]
impl<C: ControlIo + 'static, B: PacketIo + 'static, E: Environment + 'static> WirelessNetIface
    for Device<C, B, E>
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
        let packed = self.bssid.load(Ordering::Acquire).to_le_bytes();
        (packed[7] != 0).then(|| packed[..6].try_into().unwrap())
    }
    fn cipher_suites(&self) -> &'static [u32] {
        &[0x000fac04]
    }
    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.state
            .try_lock()?
            .service
            .candidates()
            .into_iter()
            .find(|b| b.bssid() == bssid)
            .map(|b| b.information_elements().to_vec())
    }
    fn get_wireless_info(&self) -> narf_wireless::WirelessIfaceInfo {
        use narf_wireless::iface::*;
        WirelessIfaceInfo {
            base_name: self.name.clone(),
            base_mac: self.mac,
            bands: vec![WirelessBand {
                freq_mhz: 2400,
                channels: vec![1],
            }],
            modes: WirelessModes::STATION,
            hw_caps: HwCaps {
                ht_supported: self.ht && !self.closed.load(Ordering::Acquire),
                vht_supported: false,
                he_supported: false,
                eht_supported: false,
            },
        }
    }
    fn phy_capabilities(&self, band: u32) -> Option<narf_wireless::iface::PhyCapabilities> {
        (band == 2400 && self.ht && !self.closed.load(Ordering::Acquire)).then(|| {
            narf_wireless::iface::PhyCapabilities {
                ht: narf_wireless::association::phy::LocalHt::siso20(false, false)
                    .capability_body(),
                vht: None,
            }
        })
    }
    async fn scan(&self, request: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        let dwell = validate_scan(&request)?;
        let mut state = self.state.lock().await;
        if state.service.phase() != service_runtime::Phase::Passive {
            return Err(WirelessError::Busy);
        }
        let deadline = narf_time::Deadline::after_ms(dwell);
        // Own native poll drives USB completions while this logical owner is
        // held. No IRQ-safe guard, executor bridge or worker dependency exists.
        loop {
            state.service.poll().map_err(wireless_error)?;
            if deadline.expired() {
                break;
            }
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
        }
        Ok(state
            .service
            .candidates()
            .into_iter()
            .filter(|b| {
                request.ssids.is_empty()
                    || request
                        .ssids
                        .iter()
                        .any(|ssid| ssid.is_empty() || ssid == b.ssid())
            })
            .map(bss_info)
            .collect())
    }
    async fn associate(&self, request: AssociateRequest) -> Result<(), WirelessError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        if request.frequency_mhz != 2412 || request.channel != 1 {
            return Err(WirelessError::NotSupported);
        }
        let (mode, pmk) = match request.security {
            SecurityConfig::Open => (SecurityMode::Open, None),
            SecurityConfig::Wpa2 { psk } => (SecurityMode::Wpa2Psk, Some(Zeroizing::new(psk))),
            _ => return Err(WirelessError::NotSupported),
        };
        let mut state = self.state.lock().await;
        if state.service.phase() != service_runtime::Phase::Passive {
            return Err(WirelessError::Busy);
        }
        state.clear_transmit();
        let result = state
            .service
            .connect(request.bssid, &request.ssid, mode, pmk, &request.ie)
            .await;
        if result.is_ok() {
            self.refresh_receive(&mut state);
            match state.service.current().and_then(|authority| {
                authority
                    .invoke(|| self.link(state.service.connected_peer()))
                    .map_err(service_runtime::Error::Radio)
            }) {
                Ok(()) => (),
                Err(_) => {
                    self.close();
                    return Err(WirelessError::HardwareError);
                }
            }
        } else {
            self.close();
        }
        result.map_err(wireless_error)
    }
    async fn disassociate(&self) -> Result<(), WirelessError> {
        self.closed.store(true, Ordering::Release);
        *self.rx.lock() = None;
        self.link(None);
        let mut state = self.state.lock().await;
        // A previous association/progress owner may have published up while
        // this caller waited. Serialize the final close with those publishers.
        self.link(None);
        state.clear_transmit();
        state.service.disconnect().await.map_err(wireless_error)
    }
    async fn set_config(&self, cfg: WirelessConfig) -> Result<(), WirelessError> {
        if cfg.channel == 1 && cfg.tx_power_dbm.is_none() {
            Ok(())
        } else {
            Err(WirelessError::NotSupported)
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub(super) mod publication_test {
    use super::*;
    use core::{future::Future, pin::pin, task::Context};

    /// The composed USB fixture supplies the joined production service. Keep
    /// private state access here rather than exposing it to sibling fixtures.
    pub(in crate::rtl8xxxu) async fn disconnect_after_old_publication<
        C: ControlIo + 'static,
        B: PacketIo + 'static,
        E: Environment + 'static,
    >(
        device: &Device<C, B, E>,
        peer: [u8; 6],
    ) -> Result<(), &'static str> {
        let state = device.state.try_lock().ok_or("EU fixture state busy")?;
        let mut disconnect = pin!(device.disassociate());
        if disconnect
            .as_mut()
            .poll(&mut Context::from_waker(core::task::Waker::noop()))
            .is_ready()
            || device.link_up()
            || device.connected_bssid().is_some()
        {
            return Err("EU disconnect did not close before waiting for state");
        }
        if state.service.connected_peer() != Some(peer) {
            return Err("EU fixture lacks the previous authorized publisher");
        }
        // The same publication as progress(), still under its state guard.
        device.link(state.service.connected_peer());
        if device.link_up() || device.connected_bssid().is_some() {
            return Err("EU terminal publication fence admitted the old publisher");
        }
        drop(state);
        disconnect
            .await
            .map_err(|_| "EU interleaved USB disconnect")
    }
}
fn validate_scan(request: &ScanRequest) -> Result<u64, WirelessError> {
    if request.active
        || request.random_mac.is_some()
        || request.colocated_6ghz
        || !request.extra_ies.is_empty()
        || request.frequencies_mhz.iter().any(|&f| f != 2412)
        || request.frequencies_mhz.is_empty() && request.channels.iter().any(|&c| c != 1)
        || request.ssids.iter().any(|s| s.len() > 32)
        || request.ssids.len() > 32
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
fn bss_info(b: Candidate) -> BssInfo {
    let security = if b.ap_rsne().is_some() {
        narf_wireless::scan::BssSecurity::Wpa2
    } else if b.capability() & 0x10 != 0 {
        narf_wireless::scan::BssSecurity::Wep
    } else {
        narf_wireless::scan::BssSecurity::Open
    };
    BssInfo {
        bssid: b.bssid(),
        ssid: b.ssid().to_vec(),
        frequency_mhz: 2412,
        channel: 1,
        rssi: i8::MIN,
        security,
    }
}
fn offloads_admitted(meta: narf_net::TxMeta) -> bool {
    meta.csum_l4.is_none() && meta.tso_mss.is_none() && meta.vlan_tag.is_none()
}
fn transmit_admitted(bytes: &[u8], own: [u8; 6]) -> bool {
    (14..=1514).contains(&bytes.len())
        && bytes[6..12] == own
        && bytes[..6] != [0; 6]
        && u16::from_be_bytes([bytes[12], bytes[13]]) >= 0x600
        && !matches!(&bytes[12..14], [0x88, 0x8e] | [0x80, 0xf3] | [0x81, 0x37])
}
fn wireless_error(error: service_runtime::Error) -> WirelessError {
    match error {
        service_runtime::Error::State => WirelessError::Busy,
        service_runtime::Error::Profile | service_runtime::Error::Management(_) => {
            WirelessError::InvalidArgs
        }
        service_runtime::Error::Entropy => WirelessError::NotSupported,
        service_runtime::Error::Station(super::station_runtime::Error::Timeout) => {
            WirelessError::Timeout
        }
        _ => WirelessError::HardwareError,
    }
}
struct Registered<C: ControlIo, B: PacketIo, E: Environment>(Arc<Device<C, B, E>>);
impl<C: ControlIo + 'static, B: PacketIo + 'static, E: Environment + 'static> Interface
    for Registered<C, B, E>
{
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
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        self.0.rx_ring()
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        self.0.tx_ring()
    }
}
