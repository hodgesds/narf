// SPDX-License-Identifier: GPL-2.0-or-later
//! One registered RTL8852B shell and retained owner for control and packet
//! progress. Synchronous stack drains never wait for another executor task.
use super::{
    station::Io,
    station::{self, Environment},
    station_control::Admission,
    station_lifecycle::Lifecycle,
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
struct Rings {
    rx: narf_ipc::Producer<Frame, RX_RING_N>,
    tx: narf_ipc::Consumer<Frame, TX_RING_N>,
    pending: Option<Frame>,
    /// Per-AC host backlog in `qos::Ac` order (VO, VI, BE, BK).
    backlog: [alloc::collections::VecDeque<Frame>; 4],
}
/// Frames pulled from the stack ring into the per-AC backlog per pass.
const BACKLOG: usize = 16;
impl Rings {
    /// Strict-priority service (all-AC program): refill the bounded backlog
    /// from the stack ring, then hand out the oldest frame of the highest
    /// non-empty AC. Without the program every frame is BE (FIFO).
    fn next(&mut self, local: [u8; 6], qos_all: bool) -> Option<Frame> {
        let mut queued: usize = self.backlog.iter().map(|q| q.len()).sum();
        while queued < BACKLOG {
            let Ok(Some(frame)) = self.tx.try_recv() else {
                break;
            };
            if !station::admitted(frame.payload(), local) || !offloads(frame.tx_meta()) {
                continue;
            }
            let ac = if qos_all {
                super::qos::Ac::of(super::qos::classify(frame.payload()))
            } else {
                super::qos::Ac::BestEffort
            };
            self.backlog[ac as usize].push_back(frame);
            queued += 1;
        }
        super::qos::Ac::ORDER
            .iter()
            .find_map(|ac| self.backlog[*ac as usize].pop_front())
    }
    fn clear(&mut self) {
        self.pending = None;
        for queue in &mut self.backlog {
            queue.clear();
        }
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
    activating: AtomicBool,
    admitted: AtomicBool,
    up: AtomicBool,
    port: AtomicBool,
    bssid: AtomicU64,
    metadata: IrqSafeSpinLock<()>,
    rx: IrqSafeSpinLock<Option<narf_ipc::Consumer<Frame, RX_RING_N>>>,
    tx: IrqSafeSpinLock<Option<narf_ipc::Producer<Frame, TX_RING_N>>>,
    /// MSI deliveries and TX kicks wake the drain worker through this line.
    line: Arc<super::irq::Line>,
    interrupts: AtomicBool,
}
/// Polled-mode worker period (no MSI binding).
const POLL_MS: u64 = 1;
/// Interrupt-mode safety period. Station timers (authentication/association
/// retries, EAPOL timeouts) are millisecond-granular host state; RX/RPQ
/// progress itself is interrupt-driven.
const IRQ_FALLBACK_MS: u64 = 10;
impl<I: Io> core::fmt::Debug for Device<I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw8852bDevice")
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
        self.link(None, false);
    }
}
impl<I: Io + 'static> Device<I> {
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
                backlog: Default::default(),
            }),
            name: name.into(),
            local,
            published: AtomicBool::new(false),
            activating: AtomicBool::new(false),
            admitted: AtomicBool::new(false),
            up: AtomicBool::new(false),
            port: AtomicBool::new(false),
            bssid: AtomicU64::new(0),
            metadata: IrqSafeSpinLock::new(()),
            rx: IrqSafeSpinLock::new(Some(consumer)),
            tx: IrqSafeSpinLock::new(Some(producer)),
            line: super::irq::Line::new(),
            interrupts: AtomicBool::new(false),
        }
    }
    /// Bind MSI delivery to this shell's worker after the station started.
    /// On failure the worker keeps its polled period.
    pub(super) async fn arm_interrupts(&self) -> Result<u8, Error> {
        let mut storage = self.lifecycle.retained.lock().await;
        if self.closed() {
            return Err(Error::State);
        }
        let owner = storage.as_mut().ok_or(Error::State)?;
        let vector = owner.station_irq(&self.line)?;
        self.interrupts.store(true, Ordering::Release);
        self.line.raise();
        Ok(vector)
    }
    /// Live AP EDCA updates need awaited H2C receipts, so the worker applies
    /// them outside the synchronous drain.
    pub(super) async fn apply_edca(&self) {
        let pending = self
            .lifecycle
            .retained
            .try_lock()
            .and_then(|owner| owner.as_ref().map(|o| o.station_edca_pending()))
            .unwrap_or(false);
        if !pending || self.closed() {
            return;
        }
        let mut storage = self.lifecycle.retained.lock().await;
        let Some(owner) = storage.as_mut() else {
            return;
        };
        if owner.station_apply_edca().await.is_err() {
            self.close();
            if !self.admission.teardown_pending() {
                let _ = owner.station_stop();
            }
        }
    }
    pub(super) fn interrupts(&self) -> bool {
        self.interrupts.load(Ordering::Acquire) && !self.closed()
    }
    pub(super) fn line(&self) -> &Arc<super::irq::Line> {
        &self.line
    }
    /// One worker period: drain, then sleep until an MSI/TX kick or the
    /// mode's fallback period.
    pub(super) async fn service_once(&self) {
        let seen = self.line.raised();
        self.drain();
        self.apply_edca().await;
        let period = if self.interrupts() {
            IRQ_FALLBACK_MS
        } else {
            POLL_MS
        };
        let _ =
            narf_time::timeout(narf_time::Deadline::after_ms(period), self.line.wait(seen)).await;
    }
    pub(super) fn closed(&self) -> bool {
        self.admission.closed()
    }
    pub(super) fn admission(&self) -> Admission {
        self.admission.clone()
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
        self.admission.run(|| {
            self.admitted.store(true, Ordering::Release);
            Ok(())
        })?;
        attempt.armed = false;
        Ok(())
    }
    fn link(&self, peer: Option<[u8; 6]>, port: bool) {
        let _metadata = self.metadata.lock();
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
                .map_err(|_| super::power::Error::Access)?;
            let mut frame = Frame::new(memory, bytes.len() as u32);
            frame.payload_mut().copy_from_slice(bytes);
            frame.set_tx_meta(meta);
            // Re-sample the retained PCI/calibration/policy authority at
            // queue publication, after allocation and the initial check.
            // Native DMA publication independently checks again.
            owner
                .station_check()
                .map_err(|_| super::power::Error::Access)?;
            self.tx
                .lock()
                .as_mut()
                .ok_or(super::power::Error::Terminal)?
                .try_send(frame)
                .map_err(|_| super::power::Error::Terminal)
        });
        if result.is_ok() {
            self.line.raise();
        }
        if result == Err(super::power::Error::Access) {
            self.close();
            if !self.admission.teardown_pending() {
                let _ = owner.station_stop();
            }
        }
        result.map_err(|_| ())
    }
    fn progress(&self) -> Vec<Vec<u8>> {
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
            self.interrupts.store(false, Ordering::Release);
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
        let result = (|| -> Result<Vec<Vec<u8>>, Error> {
            let frames = owner.station_poll()?;
            self.link(owner.station_peer(), owner.station_ready());
            if self.closed() {
                rings.clear();
                return Ok(Vec::new());
            }
            if owner.station_peer().is_none() {
                rings.clear();
                return Ok(frames);
            }
            if rings.pending.is_none() {
                rings.pending = rings.next(self.local, owner.station_qos_all());
            }
            if owner.station_ready() {
                if let Some(frame) = rings.pending.as_ref() {
                    match owner.station_send(frame.payload()) {
                        Ok(()) => rings.pending = None,
                        Err(Error::Busy)
                        | Err(Error::Transport(super::packet_core::Error::Busy)) => {}
                        Err(error) => return Err(error),
                    }
                }
            }
            self.link(owner.station_peer(), owner.station_ready());
            self.admission.run(|| {
                for bytes in &frames {
                    if let Ok(memory) =
                        narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
                    {
                        let mut frame = Frame::new(memory, bytes.len() as u32);
                        frame.payload_mut().copy_from_slice(bytes);
                        let _ = rings.rx.try_send(frame);
                    }
                }
                Ok(())
            })?;
            Ok(frames)
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
        for mut frame in frames {
            if self.closed() {
                break;
            }
            narf_net::iface::on_rx_frame_from(&self.name, &mut frame);
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
                ht_supported: false,
                vht_supported: false,
                he_supported: false,
                eht_supported: false,
            },
        }
    }
    async fn scan(&self, request: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        let dwell = scan_dwell(&request)?;
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
        let result = owner.station_scan(dwell).await;
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
        attempt.armed = false;
        if self.closed() {
            self.link(None, false);
            return Err(WirelessError::HardwareError);
        }
        self.link(owner.station_peer(), owner.station_ready());
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
fn scan_dwell(request: &ScanRequest) -> Result<u64, WirelessError> {
    if request.active
        || request.random_mac.is_some()
        || request.colocated_6ghz
        || !request.extra_ies.is_empty()
        || request.frequencies_mhz.iter().any(|f| *f != 2412)
        || request.channels.iter().any(|ch| *ch != 1)
        || request.ssids.len() > 32
        || request.ssids.iter().any(|s| s.len() > 32)
    {
        return Err(WirelessError::NotSupported);
    }
    match request.duration_tu {
        Some(n @ 1..=1000) => Ok((u64::from(n) * 1024).div_ceil(1000)),
        Some(_) => Err(WirelessError::InvalidArgs),
        None if request.duration_mandatory => Err(WirelessError::InvalidArgs),
        None => Ok(200),
    }
}
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
pub(super) fn publish<I: Io + 'static>(device: Arc<Device<I>>) -> Result<(), Error> {
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
    narf_net::iface::set_driver_info(&device.name, "rtw8852b", None, String::new());
    narf_net::iface::set_offloads(&device.name, narf_net::OffloadCapabilities::default());
    device.link(None, false);
    *ACTIVE.lock() = Some(device.clone());
    narf_net::iface::install_rx_drain(drain);
    narf_wireless::registry::register(device.clone());
    device.published.store(true, Ordering::Release);
    narf_scheduler::spawn(async move {
        loop {
            device.service_once().await;
        }
    });
    Ok(())
}
struct Registered<I: Io>(Arc<Device<I>>);
impl<I: Io + 'static> Interface for Registered<I> {
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
