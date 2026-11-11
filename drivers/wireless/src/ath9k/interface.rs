// SPDX-License-Identifier: GPL-2.0-or-later
//! One shared retained AR9285 station for async control and synchronous stack
//! progress. The radio supplies the actual DMA/host-close publication gate.
use super::{
    packet::{Packet, Port},
    station::{self, Engine, Environment, Phase, Radio},
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
#[cfg(feature = "kernel-test")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReceivePoint {
    AfterFrameAllocation,
    BeforeCallbackAdmission,
}
#[cfg(feature = "kernel-test")]
type ReceiveHook = Arc<dyn Fn(ReceivePoint) + Send + Sync>;
struct State {
    rx: narf_ipc::Producer<Frame, RX_RING_N>,
    tx: narf_ipc::Consumer<Frame, TX_RING_N>,
    /// Per-TID software queues (`ath_tx_queue_tid`); TID0 FIFO without N85Q.
    pending: super::qos::Scheduler<Frame>,
}
impl State {
    fn clear(&mut self) {
        self.pending.clear();
        for _ in 0..TX_RING_N {
            if !matches!(self.tx.try_recv(), Ok(Some(_))) {
                break;
            }
        }
    }
}
/// The netdev's TX/RX Narf-Rings and per-TID software queues. A bound
/// generation borrows its netdev's rings, so a consumer that took the RX
/// ring (or a producer of the TX ring) keeps working across generations.
pub(super) struct Rings {
    state: Mutex<State>,
    rx: IrqSafeSpinLock<Option<narf_ipc::Consumer<Frame, RX_RING_N>>>,
    tx: IrqSafeSpinLock<Option<narf_ipc::Producer<Frame, TX_RING_N>>>,
}
impl Rings {
    fn new() -> Arc<Self> {
        let (rx, consumer) = narf_ipc::channel();
        let (producer, tx) = narf_ipc::channel();
        Arc::new(Self {
            state: Mutex::new(State {
                rx,
                tx,
                pending: super::qos::Scheduler::default(),
            }),
            rx: IrqSafeSpinLock::new(Some(consumer)),
            tx: IrqSafeSpinLock::new(Some(producer)),
        })
    }
    fn clear_rx(&self) {
        if let Some(rx) = self.rx.lock().as_mut() {
            for _ in 0..RX_RING_N {
                if !matches!(rx.try_recv(), Ok(Some(_))) {
                    break;
                }
            }
        }
    }
}
/// The generation check of one netdev (replacing name reservation): every
/// attach and detach advances `serial`, and a generation publishes under
/// the netdev name (carrier, disconnect events, ring and RX delivery) only
/// while its token is still the serial. Carrier publication and the
/// advance serialize on `order`, so no carrier sample of a detached
/// generation lands after its detach returned.
pub(super) struct Seat {
    serial: AtomicU64,
    order: IrqSafeSpinLock<()>,
}
impl Seat {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            serial: AtomicU64::new(0),
            order: IrqSafeSpinLock::new(()),
        })
    }
    fn advance(&self) -> u64 {
        let _order = self.order.lock();
        self.serial.fetch_add(1, Ordering::AcqRel) + 1
    }
}
pub(super) struct Device<P: Port, E: Environment, K: Engine = Packet<P>> {
    pub(super) radio: Arc<Mutex<Radio<P, E, K>>>,
    rings: Arc<Rings>,
    /// The netdev this generation is bound to and its token; `None` for a
    /// standalone generation that owns its name and rings.
    seat: Option<(Arc<Seat>, u64)>,
    /// Copied scan output only; never an association/key/calibration authority.
    scan_ies: IrqSafeSpinLock<Vec<([u8; 6], Vec<u8>)>>,
    name: String,
    own: [u8; 6],
    admitted: AtomicBool,
    closed: Arc<AtomicBool>,
    publication: Arc<IrqSafeSpinLock<()>>,
    up: AtomicBool,
    bssid: AtomicU64,
    epoch: AtomicU64,
    #[cfg(feature = "kernel-test")]
    receive_hook: IrqSafeSpinLock<Option<ReceiveHook>>,
}
impl<P: Port, E: Environment, K: Engine> core::fmt::Debug for Device<P, E, K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ar9285Device")
            .field("name", &self.name)
            .field("up", &self.up)
            .finish_non_exhaustive()
    }
}
trait HostClose: Sync {
    fn close(&self);
}
struct Attempt<'a> {
    device: &'a dyn HostClose,
    armed: bool,
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.device.close();
        }
    }
}
impl<P: Port + Send + 'static, E: Environment + 'static, K: Engine + Send + 'static> HostClose
    for Device<P, E, K>
{
    fn close(&self) {
        let _publication = self.publication.lock();
        self.closed.store(true, Ordering::Release);
        self.publish_link(None);
        self.clear_rx();
    }
}
impl<P: Port + Send + 'static, E: Environment + 'static, K: Engine + Send + 'static>
    Device<P, E, K>
{
    /// A standalone generation owning its own name and rings.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn new(name: &str, radio: Arc<Mutex<Radio<P, E, K>>>) -> Result<Self, Error> {
        Self::with(name, radio, Rings::new(), None)
    }
    fn with(
        name: &str,
        radio: Arc<Mutex<Radio<P, E, K>>>,
        rings: Arc<Rings>,
        seat: Option<(Arc<Seat>, u64)>,
    ) -> Result<Self, Error> {
        let (own, closed, publication) = {
            let owner = radio.try_lock().ok_or(Error::Busy)?;
            (owner.local(), owner.closed(), owner.publication())
        };
        Ok(Self {
            radio,
            rings,
            seat,
            scan_ies: IrqSafeSpinLock::new(Vec::new()),
            name: name.into(),
            own,
            admitted: AtomicBool::new(false),
            closed,
            publication,
            up: AtomicBool::new(false),
            bssid: AtomicU64::new(0),
            epoch: AtomicU64::new(0),
            #[cfg(feature = "kernel-test")]
            receive_hook: IrqSafeSpinLock::new(None),
        })
    }
    /// Whether this generation still owns its netdev (always for a
    /// standalone one). A detached generation never addresses the name,
    /// rings or carrier of its successor.
    pub(super) fn current(&self) -> bool {
        self.seat
            .as_ref()
            .is_none_or(|(seat, token)| seat.serial.load(Ordering::Acquire) == *token)
    }
    fn clear_state(&self, state: &mut State) {
        if self.current() {
            state.clear();
        }
    }
    fn publish_link(&self, peer: Option<[u8; 6]>) {
        let _order = self.seat.as_ref().map(|(seat, _)| seat.order.lock());
        if !self.current() {
            return;
        }
        let mut packed = [0; 8];
        if let Some(peer) = peer {
            packed[..6].copy_from_slice(&peer);
            packed[7] = 1;
        }
        self.bssid
            .store(u64::from_le_bytes(packed), Ordering::Release);
        let up = peer.is_some();
        let previous = self.up.swap(up, Ordering::AcqRel);
        // Physical carrier preserves operator-controlled IFF_UP and never
        // invokes an administrative open/stop hook under retained locks.
        narf_net::iface::set_link_metadata(&self.name, up, None, None);
        if previous && !up {
            narf_wireless::nl80211::notify_disconnect(&self.name, 1, false);
        }
    }
    fn link(&self, peer: Option<[u8; 6]>) {
        let _publication = self.publication.lock();
        self.publish_link(peer.filter(|_| !self.closed.load(Ordering::Acquire)));
    }
    fn start(&self, radio: &mut Radio<P, E, K>) -> Result<(), Error> {
        if !self.admitted.load(Ordering::Acquire) || self.closed.load(Ordering::Acquire) {
            return Err(Error::State);
        }
        // Radio gates actual descriptor publication internally; wrapping it
        // in the same publication lock here would re-enter that lock.
        if radio.phase() == Phase::Prepared {
            if let Err(error) = radio.start() {
                self.close();
                let _ = radio.stop();
                return Err(error);
            }
        }
        if radio.phase() != Phase::Passive {
            return Err(Error::Busy);
        }
        Ok(())
    }
    async fn scan_current(&self, request: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        let dwell = scan_dwell(&request)?;
        let mut radio = self.radio.lock().await;
        let frequency = radio.frequency_mhz();
        let channel = radio.channel();
        if request.frequencies_mhz != [u32::from(frequency)] {
            return Err(WirelessError::InvalidArgs);
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        if !matches!(radio.phase(), Phase::Prepared | Phase::Passive) {
            return Err(WirelessError::Busy);
        }
        self.start(&mut radio).map_err(wireless)?;
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        let result = if request.active {
            radio.active_scan_for(dwell, &request.ssids).await
        } else {
            radio.scan_for(dwell).await
        };
        attempt.armed = false;
        if result.is_err() {
            self.close();
            let _ = radio.stop();
        }
        result
            .map(|list| {
                list.into_iter()
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
                        frequency_mhz: u32::from(frequency),
                        channel: u32::from(channel),
                        rssi: candidate.bss.signal_dbm.unwrap_or(i8::MIN),
                        security: if candidate.ap_rsne.is_some() {
                            narf_wireless::scan::BssSecurity::Wpa2
                        } else if candidate.bss.capability & 16 != 0 {
                            narf_wireless::scan::BssSecurity::Wep
                        } else {
                            narf_wireless::scan::BssSecurity::Open
                        },
                    })
                    .collect()
            })
            .map_err(wireless)
    }
    async fn associate_inner(
        &self,
        request: AssociateRequest,
        force_twenty: bool,
    ) -> Result<(), WirelessError> {
        if !matches!(
            &request.security,
            SecurityConfig::Open | SecurityConfig::Wpa2 { .. }
        ) {
            return Err(WirelessError::NotSupported);
        }
        let frequency = super::channels::frequency(request.channel).map_err(wireless)?;
        if request.frequency_mhz != u32::from(frequency) {
            return Err(WirelessError::InvalidArgs);
        }
        let current = {
            let radio = self.radio.lock().await;
            if self.closed.load(Ordering::Acquire) {
                return Err(WirelessError::HardwareError);
            }
            if radio.frequency_mhz() == frequency
                && !matches!(radio.phase(), Phase::Prepared | Phase::Passive)
            {
                return Err(WirelessError::Busy);
            }
            radio.frequency_mhz()
        };
        if current != frequency {
            let successor = self
                .retune_channel(frequency)
                .map_err(wireless)?
                .await
                .map_err(wireless)?;
            // A BSS from a retired generation cannot authorize a new join.
            let found = successor
                .scan(ScanRequest {
                    ssids: vec![request.ssid.clone()],
                    frequencies_mhz: vec![u32::from(frequency)],
                    channels: vec![request.channel],
                    active: true,
                    random_mac: None,
                    colocated_6ghz: false,
                    duration_tu: None,
                    duration_mandatory: false,
                    extra_ies: Vec::new(),
                })
                .await?;
            if !found.iter().any(|bss| {
                bss.bssid == request.bssid
                    && bss.ssid == request.ssid
                    && bss.frequency_mhz == request.frequency_mhz
            }) {
                return Err(WirelessError::InvalidArgs);
            }
            return successor.associate_profile(request, force_twenty).await;
        }
        if !force_twenty {
            let transition = {
                let radio = self.radio.lock().await;
                if let Some(grant) = radio.preferred_width(request.bssid).map_err(wireless)? {
                    Some(
                        radio
                            .retune_width(grant.geometry(), Some(grant))
                            .ok_or(WirelessError::NotSupported)?,
                    )
                } else {
                    None
                }
            };
            if let Some(transition) = transition {
                let successor = transition.await.map_err(wireless)?;
                discover(successor.as_ref(), &request).await?;
                let actual = successor.channel_geometry().ok_or(WirelessError::Busy)?;
                return successor
                    .associate_profile(request, !actual.is_wide())
                    .await;
            }
        }
        let pmk = match &request.security {
            SecurityConfig::Open => None,
            SecurityConfig::Wpa2 { psk } => Some(Zeroizing::new(*psk)),
            _ => return Err(WirelessError::NotSupported),
        };
        let mut radio = self.radio.lock().await;
        self.start(&mut radio).map_err(wireless)?;
        {
            let mut state = self.rings.state.lock().await;
            self.clear_state(&mut state);
        }
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        let result = radio
            .associate_mode(request.bssid, &request.ssid, pmk, &request.ie, force_twenty)
            .await;
        attempt.armed = false;
        if result == Err(Error::WidthFallback) && radio.geometry().is_wide() {
            // Capture the exact physical owner's continuation before releasing
            // Radio. Native reset cannot poll while this mutex remains held.
            let transition = radio
                .retune_width(radio.geometry().twenty(), None)
                .ok_or(WirelessError::NotSupported)?;
            self.close();
            let _ = radio.stop();
            drop(radio);
            let successor = transition.await.map_err(wireless)?;
            if successor
                .channel_geometry()
                .is_none_or(|geometry| geometry.is_wide())
            {
                return Err(WirelessError::HardwareError);
            }
            discover(successor.as_ref(), &request).await?;
            return successor.associate_profile(request, true).await;
        }
        if self.closed.load(Ordering::Acquire) || radio.phase() == Phase::Failed {
            self.close();
            let _ = radio.stop();
            return Err(result.err().map_or(WirelessError::HardwareError, wireless));
        }
        self.link(radio.peer());
        result.map_err(wireless)
    }
    fn scan_metadata(&self, list: &[BssInfo], owner: &dyn WirelessNetIface) {
        for candidate in list {
            if let Some(ies) = owner.scan_information_elements(candidate.bssid) {
                let mut saved = self.scan_ies.lock();
                if let Some(old) = saved.iter_mut().find(|old| old.0 == candidate.bssid) {
                    old.1 = ies;
                } else if saved.len() < 128 {
                    saved.push((candidate.bssid, ies));
                }
            }
        }
    }
    pub(super) fn enqueue(&self, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
        if self.closed.load(Ordering::Acquire)
            || !self.current()
            || !self.up.load(Ordering::Acquire)
            || !station::admitted(bytes, self.own)
            || !offloads(meta)
        {
            return Err(());
        }
        if !self.permission(None) {
            return Err(());
        }
        let buffer = narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
            .map_err(|_| ())?;
        let mut frame = Frame::new(buffer, bytes.len() as u32);
        frame.payload_mut().copy_from_slice(bytes);
        frame.set_tx_meta(meta);
        if !self.permission(None) {
            return Err(());
        }
        self.rings
            .tx
            .lock()
            .as_mut()
            .ok_or(())?
            .try_send(frame)
            .map_err(|_| ())?;
        // Interrupt-driven service sleeps until a vector fires; stack TX is
        // the other wake source.
        if let Some(signal) = self.radio.try_lock().and_then(|r| r.interrupt()) {
            signal.raise();
        }
        Ok(())
    }
    fn clear_rx(&self) {
        if self.current() {
            self.rings.clear_rx();
        }
    }
    fn permission(&self, epoch: Option<u64>) -> bool {
        let Some(mut radio) = self.radio.try_lock() else {
            return false;
        };
        let token = epoch.unwrap_or_else(|| radio.receive_epoch());
        match radio.current_receive(token) {
            Ok(open) => open && !self.closed.load(Ordering::Acquire),
            Err(_) => {
                self.close();
                let _ = radio.stop();
                self.clear_rx();
                false
            }
        }
    }
    fn progress(&self) -> (u64, Vec<Vec<u8>>) {
        let Some(mut radio) = self.radio.try_lock() else {
            return (0, Vec::new());
        };
        let Some(mut state) = self.rings.state.try_lock() else {
            return (0, Vec::new());
        };
        if !self.current() {
            // Detached: its successor owns the shared rings and carrier.
            self.closed.store(true, Ordering::Release);
            let _ = radio.stop();
            return (0, Vec::new());
        }
        if self.closed.load(Ordering::Acquire) {
            self.clear_state(&mut state);
            let _ = radio.stop();
            self.link(None);
            self.clear_rx();
            return (0, Vec::new());
        }
        if !matches!(radio.phase(), Phase::Passive | Phase::Open | Phase::Failed) {
            return (0, Vec::new());
        }
        // ATH_OP_HW_RESET: TX queues stay stopped and nothing is polled
        // until the owner's in-place reset completes; the link and the
        // shared rings stay as they are.
        if radio.reset_pending().is_some() {
            return (0, Vec::new());
        }
        let result: Result<Vec<Vec<u8>>, Error> = (|| {
            let frames = radio.poll()?;
            self.link(radio.peer());
            let epoch = radio.receive_epoch();
            if self.epoch.swap(epoch, Ordering::AcqRel) != epoch {
                self.clear_rx();
            }
            if self.closed.load(Ordering::Acquire) {
                self.clear_state(&mut state);
                return Ok(Vec::new());
            }
            if radio.peer().is_none() {
                self.clear_state(&mut state);
                return Ok(frames);
            }
            if !radio.current_receive(epoch)? {
                self.clear_state(&mut state);
                self.clear_rx();
                return Ok(Vec::new());
            }
            // Classify into per-TID queues; the total stays within one TID's
            // bound, so the IPC ring keeps backpressure and nothing drops.
            for _ in 0..16 {
                if state.pending.len() >= super::qos::PER_TID {
                    break;
                }
                let Ok(Some(frame)) = state.tx.try_recv() else {
                    break;
                };
                if station::admitted(frame.payload(), self.own) && offloads(frame.tx_meta()) {
                    let tid = radio.transmit_tid(frame.payload());
                    let _ = state.pending.push(tid, frame);
                }
            }
            if radio.ready() {
                if let Some((tid, frame)) = state.pending.pop() {
                    // Form only an already available, source-qualified prefix.
                    // Sizing precedes all shared QoS SN/CCMP PN reservations.
                    let count = if tid == 0
                        && radio.can_aggregate()
                        && radio.transmit_tid(frame.payload()) == 0
                    {
                        let available: Vec<&[u8]> = core::iter::once(frame.payload())
                            .chain(state.pending.tid_prefix(0).map(|next| next.payload()))
                            .take(super::tx_ba::MAX_MEMBERS)
                            .collect();
                        radio.aggregate_count(&available)?
                    } else {
                        1
                    };
                    if count >= 2 {
                        let mut members = vec![frame];
                        for _ in 1..count {
                            members.push(state.pending.pop_tid(0).ok_or(station::Error::State)?);
                        }
                        let originals: Vec<&[u8]> =
                            members.iter().map(|member| member.payload()).collect();
                        radio.send_aggregate(&originals)?;
                    } else {
                        radio.send(frame.payload())?;
                    }
                }
            }
            if self.closed.load(Ordering::Acquire) {
                self.clear_state(&mut state);
                return Ok(Vec::new());
            }
            for bytes in &frames {
                if !radio.current_receive(epoch)? {
                    self.clear_rx();
                    return Ok(Vec::new());
                }
                if let Ok(buffer) =
                    narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
                {
                    let mut frame = Frame::new(buffer, bytes.len() as u32);
                    frame.payload_mut().copy_from_slice(bytes);
                    #[cfg(feature = "kernel-test")]
                    self.receive_hook(ReceivePoint::AfterFrameAllocation);
                    if !radio.current_receive(epoch)? {
                        self.clear_rx();
                        return Ok(Vec::new());
                    }
                    let _ = state.rx.try_send(frame);
                }
            }
            Ok(frames)
        })();
        match result {
            Ok(frames) => (radio.receive_epoch(), frames),
            // The failure queued an in-place reset; the generation stays.
            Err(_) if radio.reset_pending().is_some() => (0, Vec::new()),
            Err(_) => {
                self.close();
                let _ = radio.stop();
                self.clear_state(&mut state);
                self.clear_rx();
                (0, Vec::new())
            }
        }
    }
    /// Host-side retirement of this generation (see [`retire`]). A bound
    /// generation is detached from its netdev, which stays registered under
    /// the same name and ifindex: carrier drops (with the disconnect event
    /// while still current), the seat advances so no late publication of
    /// this generation reaches the next one, and the shared rings are
    /// cleared. A standalone generation leaves every registry and keeps its
    /// name reserved instead.
    pub(super) fn retire_host(&self) {
        self.close();
        if let Some((seat, _)) = &self.seat {
            seat.advance();
            if let Some(mut state) = self.rings.state.try_lock() {
                state.clear();
            }
            self.rings.clear_rx();
            return;
        }
        if let Some(mut state) = self.rings.state.try_lock() {
            state.clear();
        }
        narf_wireless::registry::unregister(&self.name);
        narf_net::registry().unregister(&self.name);
        // Reserve while still registered so no other wlan%d allocation can
        // take the name between unregister and reservation.
        narf_net::iface::reserve_name(&self.name);
        narf_net::iface::unregister(&self.name);
    }
    pub(super) fn drain(&self) -> bool {
        let (epoch, frames) = self.progress();
        let progress = !frames.is_empty();
        // Stack dispatch can synchronously send ARP/ND; both async guards are
        // gone and no publication lock survives into stack/reentrant enqueue.
        if !self.closed.load(Ordering::Acquire) {
            for mut frame in frames {
                #[cfg(feature = "kernel-test")]
                self.receive_hook(ReceivePoint::BeforeCallbackAdmission);
                if !self.permission(Some(epoch)) {
                    if self.epoch.load(Ordering::Acquire) == epoch {
                        self.clear_rx();
                    }
                    break;
                }
                if !self.current() {
                    break;
                }
                narf_net::iface::on_rx_frame_from(&self.name, &mut frame);
            }
        }
        // Native checks/copy/callback admission may have woken a dozing
        // owner after Radio::poll. Restore only after all reentrant stack
        // work, with the same pending/control/RX-idle/source predicates.
        if !self.closed.load(Ordering::Acquire) {
            if let Some(mut radio) = self.radio.try_lock() {
                if radio.restore_power_save().is_err() {
                    self.close();
                    self.clear_rx();
                }
            }
        }
        progress
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn admit_for_test(&self) {
        self.admitted.store(true, Ordering::Release);
    }
    #[cfg(feature = "kernel-test")]
    fn receive_hook(&self, point: ReceivePoint) {
        let hook = { self.receive_hook.lock().clone() };
        if let Some(h) = hook {
            h(point);
        }
    }
}
fn offloads(meta: narf_net::TxMeta) -> bool {
    meta.csum_l4.is_none() && meta.tso_mss.is_none() && meta.vlan_tag.is_none()
}
fn wireless(error: Error) -> WirelessError {
    match error {
        Error::State | Error::Busy => WirelessError::Busy,
        Error::Profile | Error::Management(_) => WirelessError::InvalidArgs,
        Error::Timeout => WirelessError::Timeout,
        Error::Entropy => WirelessError::NotSupported,
        _ => WirelessError::HardwareError,
    }
}
impl<P: Port + Send + 'static, E: Environment + 'static, K: Engine + Send + 'static> Interface
    for Device<P, E, K>
{
    fn name(&self) -> &str {
        &self.name
    }
    fn mac(&self) -> [u8; 6] {
        self.own
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        !self.closed.load(Ordering::Acquire) && self.up.load(Ordering::Acquire)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<narf_ipc::Consumer<Frame, RX_RING_N>>> {
        &self.rings.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<narf_ipc::Producer<Frame, TX_RING_N>>> {
        &self.rings.tx
    }
}
#[async_trait::async_trait]
impl<P: Port + Send + 'static, E: Environment + 'static, K: Engine + Send + 'static>
    WirelessNetIface for Device<P, E, K>
{
    fn power_save_default(&self) -> Option<bool> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        self.radio.try_lock()?.power_save()
    }
    fn set_power_save(&self, enabled: bool) -> Result<(), i32> {
        if self.closed.load(Ordering::Acquire) {
            return Err(-5);
        }
        let mut radio = self.radio.try_lock().ok_or(-16)?;
        radio.set_power_save(enabled).map_err(|error| match error {
            Error::Profile => -95,
            Error::Busy => -16,
            _ => -5,
        })
    }
    fn max_scan_ssids(&self) -> u8 {
        4
    }
    fn max_scan_ie_len(&self) -> u16 {
        0
    }
    fn supports_handshake_offload(&self) -> bool {
        true
    }
    fn reports_disconnect_events(&self) -> bool {
        true
    }
    fn supports_scan_dwell(&self) -> bool {
        true
    }
    fn cipher_suites(&self) -> &'static [u32] {
        &[0x000fac04]
    }
    fn connected_bssid(&self) -> Option<[u8; 6]> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        let peer = self.bssid.load(Ordering::Acquire).to_le_bytes();
        (peer[7] != 0).then(|| peer[..6].try_into().unwrap())
    }
    fn scan_information_elements(&self, peer: [u8; 6]) -> Option<Vec<u8>> {
        if let Some(ies) = self
            .scan_ies
            .lock()
            .iter()
            .find(|entry| entry.0 == peer)
            .map(|entry| entry.1.clone())
        {
            return Some(ies);
        }
        self.radio.try_lock()?.information_elements(peer)
    }
    fn get_wireless_info(&self) -> narf_wireless::WirelessIfaceInfo {
        use narf_wireless::iface::*;
        WirelessIfaceInfo {
            base_name: self.name.clone(),
            base_mac: self.own,
            bands: {
                // The 2.4 GHz band, then 5 GHz only for a radio whose mask
                // (AR9280) admits a 5 GHz primary.
                let channels = |five: bool| {
                    self.radio.try_lock().map_or_else(Vec::new, |radio| {
                        (0..super::channels::CHANNEL_BITS)
                            .filter(|bit| radio.channel_mask() & (1 << bit) != 0)
                            .filter_map(super::channels::bit_frequency)
                            .filter(|frequency| {
                                (*frequency >= 5000) == five && permitted(*frequency)
                            })
                            .filter_map(|frequency| {
                                super::channels::channel(frequency).ok().map(u32::from)
                            })
                            .collect::<Vec<_>>()
                    })
                };
                let mut bands = vec![WirelessBand {
                    freq_mhz: 2400,
                    channels: channels(false),
                }];
                let five = channels(true);
                if !five.is_empty() {
                    bands.push(WirelessBand {
                        freq_mhz: 5000,
                        channels: five,
                    });
                }
                bands
            },
            modes: WirelessModes::STATION,
            hw_caps: HwCaps {
                ht_supported: self
                    .radio
                    .try_lock()
                    .and_then(|radio| radio.ht_grant())
                    .is_some_and(|grant| grant.check().is_ok()),
                vht_supported: false,
                he_supported: false,
                eht_supported: false,
            },
        }
    }
    async fn scan(&self, request: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        scan_dwell(&request)?;
        let (original, mask) = {
            let radio = self.radio.lock().await;
            if self.closed.load(Ordering::Acquire) {
                return Err(WirelessError::HardwareError);
            }
            if !matches!(radio.phase(), Phase::Prepared | Phase::Passive) {
                return Err(WirelessError::Busy);
            }
            (radio.frequency_mhz(), radio.channel_mask())
        };
        let frequencies = scan_frequencies(&request, mask)?;
        self.scan_ies.lock().clear();
        let mut owner: Option<super::channels::Successor> = None;
        let mut operating = original;
        let mut output: Vec<BssInfo> = Vec::new();
        for frequency in frequencies {
            if operating != frequency {
                let transition = match &owner {
                    Some(device) => device.retune_channel(frequency),
                    None => self.retune_channel(frequency),
                }
                .map_err(wireless)?;
                owner = Some(transition.await.map_err(wireless)?);
                operating = frequency;
            }
            let result = match &owner {
                Some(device) => device.scan(one_scan(&request, frequency)).await,
                None => self.scan_current(one_scan(&request, frequency)).await,
            };
            let list = result?;
            match &owner {
                Some(device) => self.scan_metadata(&list, device.as_ref()),
                None => self.scan_metadata(&list, self),
            }
            for candidate in list {
                if let Some(old) = output.iter_mut().find(|old| {
                    old.bssid == candidate.bssid && old.frequency_mhz == candidate.frequency_mhz
                }) {
                    *old = candidate;
                } else {
                    output.push(candidate);
                }
            }
        }
        // The initial interface remains terminal after the first cold retune.
        // Restore RF by another real generation, never reopening old tokens.
        if operating != original {
            owner
                .as_ref()
                .ok_or(WirelessError::HardwareError)?
                .retune_channel(original)
                .map_err(wireless)?
                .await
                .map_err(wireless)?;
        }
        Ok(output)
    }
    async fn associate(&self, request: AssociateRequest) -> Result<(), WirelessError> {
        self.associate_inner(request, false).await
    }
    async fn disassociate(&self) -> Result<(), WirelessError> {
        self.close();
        let mut radio = self.radio.lock().await;
        {
            let mut state = self.rings.state.lock().await;
            self.clear_state(&mut state);
        }
        self.link(None);
        radio.stop().map_err(wireless)
    }
    async fn set_config(&self, config: WirelessConfig) -> Result<(), WirelessError> {
        if config.tx_power_dbm.is_some() {
            return Err(WirelessError::NotSupported);
        }
        let frequency = super::channels::frequency(config.channel).map_err(wireless)?;
        {
            let radio = self.radio.lock().await;
            if self.closed.load(Ordering::Acquire) {
                return Err(WirelessError::HardwareError);
            }
            if radio.frequency_mhz() == frequency {
                return Ok(());
            }
        }
        self.retune_channel(frequency)
            .map_err(wireless)?
            .await
            .map_err(wireless)?;
        Ok(())
    }
}
/// Private continuation carrying the actual next driver generation.
#[async_trait::async_trait]
pub(super) trait ChannelIface: WirelessNetIface {
    fn channel_geometry(&self) -> Option<super::channel_width::Geometry>;
    async fn associate_profile(
        &self,
        request: AssociateRequest,
        force_twenty: bool,
    ) -> Result<(), WirelessError>;
    fn retune_channel(&self, frequency: u16) -> Result<super::channels::Transition, Error>;
}
#[async_trait::async_trait]
impl<P: Port + Send + 'static, E: Environment + 'static, K: Engine + Send + 'static> ChannelIface
    for Device<P, E, K>
{
    fn channel_geometry(&self) -> Option<super::channel_width::Geometry> {
        self.radio.try_lock().map(|radio| radio.geometry())
    }
    async fn associate_profile(
        &self,
        request: AssociateRequest,
        force_twenty: bool,
    ) -> Result<(), WirelessError> {
        self.associate_inner(request, force_twenty).await
    }
    fn retune_channel(&self, frequency: u16) -> Result<super::channels::Transition, Error> {
        super::channels::channel(frequency)?;
        let radio = self.radio.try_lock().ok_or(Error::Busy)?;
        if self.closed.load(Ordering::Acquire)
            || !self.admitted.load(Ordering::Acquire)
            || !matches!(
                radio.phase(),
                Phase::Prepared | Phase::Passive | Phase::Open
            )
        {
            return Err(Error::State);
        }
        if !super::channels::admits(radio.channel_mask(), frequency) || !permitted(frequency) {
            return Err(Error::Profile);
        }
        radio.retune(frequency).ok_or(Error::Profile)
    }
}
async fn discover(
    device: &dyn ChannelIface,
    request: &AssociateRequest,
) -> Result<(), WirelessError> {
    let found = device
        .scan(ScanRequest {
            ssids: vec![request.ssid.clone()],
            frequencies_mhz: vec![request.frequency_mhz],
            channels: vec![request.channel],
            active: true,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: None,
            duration_mandatory: false,
            extra_ies: Vec::new(),
        })
        .await?;
    if !found.iter().any(|bss| {
        bss.bssid == request.bssid
            && bss.ssid == request.ssid
            && bss.frequency_mhz == request.frequency_mhz
    }) {
        return Err(WirelessError::InvalidArgs);
    }
    Ok(())
}
fn permitted(frequency: u16) -> bool {
    narf_wireless::reg::db::snapshot().is_some_and(|domain| {
        // Dual-band span rule (DFS / NO_IR / indoor refuse); a 5 GHz
        // frequency is only reachable through an AR9280 mask.
        super::calibration::Permission::from_domain_dual(&domain, frequency).is_ok()
    })
}
fn one_scan(request: &ScanRequest, frequency: u16) -> ScanRequest {
    ScanRequest {
        ssids: request.ssids.clone(),
        frequencies_mhz: vec![u32::from(frequency)],
        channels: vec![u32::from(super::channels::channel(frequency).unwrap_or(0))],
        active: request.active,
        random_mac: request.random_mac,
        colocated_6ghz: request.colocated_6ghz,
        duration_tu: request.duration_tu,
        duration_mandatory: request.duration_mandatory,
        extra_ies: request.extra_ies.clone(),
    }
}
fn scan_frequencies(request: &ScanRequest, mask: u64) -> Result<Vec<u16>, WirelessError> {
    let explicit = !request.frequencies_mhz.is_empty() || !request.channels.is_empty();
    let selected = if !request.frequencies_mhz.is_empty() {
        request
            .frequencies_mhz
            .iter()
            .map(|f| u16::try_from(*f).map_err(|_| WirelessError::InvalidArgs))
            .collect::<Result<Vec<_>, _>>()?
    } else if !request.channels.is_empty() {
        request
            .channels
            .iter()
            .map(|ch| super::channels::frequency(*ch).map_err(wireless))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        (0..super::channels::CHANNEL_BITS)
            .filter(|bit| mask & (1 << bit) != 0)
            .filter_map(super::channels::bit_frequency)
            .collect()
    };
    let mut output = Vec::new();
    for frequency in selected {
        super::channels::channel(frequency).map_err(wireless)?;
        // Retain the original channel1-only selector behavior. The native
        // Port still checks current policy on every actual RF/DMA operation.
        let reference = mask == 1 && frequency == 2412;
        if !super::channels::admits(mask, frequency) || !reference && !permitted(frequency) {
            if explicit {
                return Err(WirelessError::NotSupported);
            }
            continue;
        }
        if !output.contains(&frequency) {
            output.push(frequency);
        }
    }
    if output.is_empty() {
        return Err(WirelessError::NotSupported);
    }
    Ok(output)
}
fn scan_dwell(request: &ScanRequest) -> Result<u64, WirelessError> {
    if request.random_mac.is_some()
        || request.colocated_6ghz
        || !request.extra_ies.is_empty()
        || request.ssids.len() > if request.active { 4 } else { 32 }
        || request.ssids.iter().any(|ssid| ssid.len() > 32)
    {
        return Err(WirelessError::NotSupported);
    }
    match request.duration_tu {
        Some(duration @ 1..=1000) => Ok((u64::from(duration) * 1024).div_ceil(1000)),
        Some(_) => Err(WirelessError::InvalidArgs),
        None if request.duration_mandatory => Err(WirelessError::InvalidArgs),
        None => Ok(300),
    }
}
/// Housekeeping period while MSI delivery drives RX/TX completion.
const HOUSEKEEPING_NS: u64 = 20_000_000;
/// How long a control request waits for the netdev's next generation
/// (a generation reset, idle wake or resume republishing the radio).
const ATTACH_WAIT_NS: u64 = 10_000_000_000;
/// Leave-idle hook run before every netdev control request (mac80211
/// clearing `IEEE80211_CONF_IDLE`). Its result is a counted use held for the
/// request, so idle cannot be entered under it.
pub(super) type Activity = fn() -> Waking;
/// The hook's future: the counted use (if any) to hold for the request.
pub(super) type Waking =
    core::pin::Pin<Box<dyn core::future::Future<Output = Option<Box<dyn Send>>> + Send>>;
/// One control request in flight; its end restarts the quiet window.
struct Busy<'a> {
    busy: &'a AtomicU64,
    quiet_since: &'a AtomicU64,
}
impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.quiet_since
            .store(narf_time::monotonic_ns(), Ordering::Release);
        self.busy.fetch_sub(1, Ordering::AcqRel);
    }
}
/// One netdev across station generations. Linux keeps the `net_device`
/// (and `ieee80211_hw`) across `main.c::ath_reset`, mac80211 idle
/// (`IEEE80211_CONF_IDLE`) and `ath9k_suspend`/`ath_pci_suspend`; here
/// every one of those is still a generation reset that retires the station
/// owner, so the netdev keeps its name, ifindex, MAC and rings and swaps
/// the radio generation behind them. The stale-publisher guard is the
/// [`Seat`] token: a detached generation can no longer address the name.
pub(super) struct Netdev<P: Port, E: Environment, K: Engine = Packet<P>> {
    name: &'static str,
    own: [u8; 6],
    rings: Arc<Rings>,
    seat: Arc<Seat>,
    current: IrqSafeSpinLock<Option<Arc<Device<P, E, K>>>>,
    /// The last attached generation's band/HT facts, served while detached.
    info: IrqSafeSpinLock<Option<narf_wireless::WirelessIfaceInfo>>,
    /// Scan IEs gathered by the generation(s) a scan ran on.
    scan_ies: IrqSafeSpinLock<Vec<([u8; 6], Vec<u8>)>>,
    removed: AtomicBool,
    activity: Option<Activity>,
    /// Control requests in flight and the end of the last one: the
    /// "not scanning/connecting" half of the idle predicate.
    busy: AtomicU64,
    quiet_since: AtomicU64,
}
fn copy_info(info: &narf_wireless::WirelessIfaceInfo) -> narf_wireless::WirelessIfaceInfo {
    use narf_wireless::iface::*;
    WirelessIfaceInfo {
        base_name: info.base_name.clone(),
        base_mac: info.base_mac,
        bands: info
            .bands
            .iter()
            .map(|band| WirelessBand {
                freq_mhz: band.freq_mhz,
                channels: band.channels.clone(),
            })
            .collect(),
        modes: info.modes,
        hw_caps: HwCaps {
            ht_supported: info.hw_caps.ht_supported,
            vht_supported: info.hw_caps.vht_supported,
            he_supported: info.hw_caps.he_supported,
            eht_supported: info.hw_caps.eht_supported,
        },
    }
}
impl<P: Port + Send + 'static, E: Environment + 'static, K: Engine + Send + 'static>
    Netdev<P, E, K>
{
    pub(super) fn new(name: &'static str, own: [u8; 6], activity: Option<Activity>) -> Arc<Self> {
        Arc::new(Self {
            name,
            own,
            rings: Rings::new(),
            seat: Seat::new(),
            current: IrqSafeSpinLock::new(None),
            info: IrqSafeSpinLock::new(None),
            scan_ies: IrqSafeSpinLock::new(Vec::new()),
            removed: AtomicBool::new(false),
            activity,
            busy: AtomicU64::new(0),
            quiet_since: AtomicU64::new(narf_time::monotonic_ns()),
        })
    }
    /// No control request is in flight and none ended within `ns`.
    pub(super) fn quiet_for(&self, ns: u64) -> bool {
        self.busy.load(Ordering::Acquire) == 0
            && narf_time::monotonic_ns().saturating_sub(self.quiet_since.load(Ordering::Acquire))
                >= ns
    }
    /// Begin a control request: count it, leave idle through the activity
    /// hook (holding its use for the request), then the current generation.
    async fn control(
        &self,
    ) -> Result<(Arc<Device<P, E, K>>, Busy<'_>, Option<Box<dyn Send>>), WirelessError> {
        self.busy.fetch_add(1, Ordering::AcqRel);
        let busy = Busy {
            busy: &self.busy,
            quiet_since: &self.quiet_since,
        };
        let wake = match self.activity {
            Some(activity) => activity().await,
            None => None,
        };
        let device = self.wait_generation().await?;
        Ok((device, busy, wake))
    }
    /// The attached generation, if any.
    pub(super) fn generation(&self) -> Option<Arc<Device<P, E, K>>> {
        self.current.lock().clone()
    }
    /// Bind the next generation (same MAC) to this netdev. Refused while a
    /// generation is still attached or after removal.
    pub(super) fn attach(
        &self,
        radio: Arc<Mutex<Radio<P, E, K>>>,
    ) -> Result<Arc<Device<P, E, K>>, Error> {
        let device = {
            let mut current = self.current.lock();
            if current.is_some() || self.removed.load(Ordering::Acquire) {
                return Err(Error::State);
            }
            let token = self.seat.advance();
            let device = Arc::new(Device::with(
                self.name,
                radio,
                self.rings.clone(),
                Some((self.seat.clone(), token)),
            )?);
            if device.own != self.own {
                self.seat.advance();
                return Err(Error::Profile);
            }
            *current = Some(device.clone());
            device
        };
        self.quiet_since
            .store(narf_time::monotonic_ns(), Ordering::Release);
        let info = device.get_wireless_info();
        *self.info.lock() = Some(info);
        Ok(device)
    }
    /// Detach the generation that owns `radio` (see [`Device::retire_host`]);
    /// the netdev stays registered. Returns the detached generation.
    pub(super) fn detach(
        &self,
        radio: &Arc<Mutex<Radio<P, E, K>>>,
    ) -> Option<Arc<Device<P, E, K>>> {
        let device = {
            let mut current = self.current.lock();
            match current.as_ref() {
                Some(device) if Arc::ptr_eq(&device.radio, radio) => current.take(),
                _ => None,
            }
        }?;
        device.retire_host();
        Some(device)
    }
    /// Device removal (`ieee80211_unregister_hw`): detach any generation
    /// and leave every registry. The seat advances, so no generation of
    /// this netdev can address a later holder of the name.
    pub(super) fn unregister(&self) {
        self.removed.store(true, Ordering::Release);
        let device = self.current.lock().take();
        if let Some(device) = device {
            device.retire_host();
        }
        self.seat.advance();
        narf_wireless::registry::unregister(self.name);
        narf_net::registry().unregister(self.name);
        narf_net::iface::unregister(self.name);
    }
    /// The current generation, waiting for a reset/wake/resume in flight to
    /// attach the next one.
    async fn wait_generation(&self) -> Result<Arc<Device<P, E, K>>, WirelessError> {
        let deadline = narf_time::monotonic_ns().saturating_add(ATTACH_WAIT_NS);
        loop {
            if let Some(device) = self.generation() {
                return Ok(device);
            }
            if self.removed.load(Ordering::Acquire) {
                return Err(WirelessError::HardwareError);
            }
            if narf_time::monotonic_ns() >= deadline {
                return Err(WirelessError::Busy);
            }
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(20_000_000)).await;
        }
    }
}
impl<P: Port + Send + 'static, E: Environment + 'static, K: Engine + Send + 'static> Interface
    for Netdev<P, E, K>
{
    fn name(&self) -> &str {
        self.name
    }
    fn mac(&self) -> [u8; 6] {
        self.own
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        self.generation().is_some_and(|device| device.link_up())
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<narf_ipc::Consumer<Frame, RX_RING_N>>> {
        &self.rings.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<narf_ipc::Producer<Frame, TX_RING_N>>> {
        &self.rings.tx
    }
}
#[async_trait::async_trait]
impl<P: Port + Send + 'static, E: Environment + 'static, K: Engine + Send + 'static>
    WirelessNetIface for Netdev<P, E, K>
{
    fn power_save_default(&self) -> Option<bool> {
        self.generation()?.power_save_default()
    }
    fn set_power_save(&self, enabled: bool) -> Result<(), i32> {
        self.generation().ok_or(-16)?.set_power_save(enabled)
    }
    fn max_scan_ssids(&self) -> u8 {
        4
    }
    fn max_scan_ie_len(&self) -> u16 {
        0
    }
    fn supports_handshake_offload(&self) -> bool {
        true
    }
    fn reports_disconnect_events(&self) -> bool {
        true
    }
    fn supports_scan_dwell(&self) -> bool {
        true
    }
    fn cipher_suites(&self) -> &'static [u32] {
        &[0x000fac04]
    }
    fn connected_bssid(&self) -> Option<[u8; 6]> {
        self.generation()?.connected_bssid()
    }
    fn scan_information_elements(&self, peer: [u8; 6]) -> Option<Vec<u8>> {
        if let Some(ies) = self
            .scan_ies
            .lock()
            .iter()
            .find(|entry| entry.0 == peer)
            .map(|entry| entry.1.clone())
        {
            return Some(ies);
        }
        self.generation()?.scan_information_elements(peer)
    }
    fn get_wireless_info(&self) -> narf_wireless::WirelessIfaceInfo {
        if let Some(device) = self.generation() {
            let info = device.get_wireless_info();
            *self.info.lock() = Some(copy_info(&info));
            return info;
        }
        self.info.lock().as_ref().map_or_else(
            || narf_wireless::WirelessIfaceInfo {
                base_name: self.name.into(),
                base_mac: self.own,
                bands: Vec::new(),
                modes: narf_wireless::iface::WirelessModes::STATION,
                hw_caps: narf_wireless::iface::HwCaps {
                    ht_supported: false,
                    vht_supported: false,
                    he_supported: false,
                    eht_supported: false,
                },
            },
            copy_info,
        )
    }
    async fn scan(&self, request: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        let (device, _busy, _wake) = self.control().await?;
        // The generation the scan started on gathers every visited
        // channel's IEs, including those of retune successors.
        let list = device.scan(request).await?;
        let mut saved = self.scan_ies.lock();
        saved.clear();
        for candidate in &list {
            if let Some(ies) = device.scan_information_elements(candidate.bssid) {
                if saved.len() < 128 {
                    saved.push((candidate.bssid, ies));
                }
            }
        }
        Ok(list)
    }
    async fn associate(&self, request: AssociateRequest) -> Result<(), WirelessError> {
        let (device, _busy, _wake) = self.control().await?;
        device.associate(request).await
    }
    async fn disassociate(&self) -> Result<(), WirelessError> {
        match self.generation() {
            Some(device) => device.disassociate().await,
            None => Ok(()),
        }
    }
    async fn set_config(&self, config: WirelessConfig) -> Result<(), WirelessError> {
        let (device, _busy, _wake) = self.control().await?;
        device.set_config(config).await
    }
}
pub(super) type Native = Device<
    super::packet_native::Native,
    station::NativeEnvironment,
    station::Dispatch<super::packet_native::Native>,
>;
type NativeNetdev = Netdev<
    super::packet_native::Native,
    station::NativeEnvironment,
    station::Dispatch<super::packet_native::Native>,
>;
/// The single published ath9k netdev (one bound function at a time).
static NETDEV: IrqSafeSpinLock<Option<Arc<NativeNetdev>>> = IrqSafeSpinLock::new(None);
fn send(bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let device = current().ok_or(())?;
    device.enqueue(bytes, meta)
}
fn drain() -> bool {
    current().is_some_and(|device| device.drain())
}
/// Caller has retained this exact Radio Arc in Ath9k before any packet start.
/// The first generation creates and registers the netdev (`wlan%d`); every
/// later generation of the same MAC attaches to it under the same name.
pub(super) fn publish(radio: super::RetainedRadio) -> Result<Arc<Native>, Error> {
    let authority = narf_net::trusted_net_authority()
        .and_then(|cap| cap.derive().ok())
        .ok_or(Error::Profile)?;
    let own = radio.try_lock().ok_or(Error::Busy)?.local();
    let (netdev, fresh) = {
        let mut slot = NETDEV.lock();
        match slot.as_ref() {
            Some(netdev) if netdev.own == own => (netdev.clone(), false),
            Some(_) => return Err(Error::State),
            None => {
                let netdev = NativeNetdev::new(
                    narf_net::iface::reserve_name("wlan%d"),
                    own,
                    Some(leave_idle),
                );
                *slot = Some(netdev.clone());
                (netdev, true)
            }
        }
    };
    if fresh {
        if narf_net::registry()
            .register(&authority, Registered(netdev.clone()))
            .is_err()
        {
            *NETDEV.lock() = None;
            return Err(Error::Profile);
        }
        narf_net::iface::register(netdev.name, own, send);
        narf_wireless::registry::register(netdev.clone());
        narf_net::iface::install_rx_drain(drain);
    }
    let device = netdev.attach(radio)?;
    device.link(None);
    device.admitted.store(true, Ordering::Release);
    {
        let mut radio = device.radio.try_lock().ok_or(Error::Busy)?;
        device.start(&mut radio)?;
    }
    let worker = device.clone();
    narf_scheduler::spawn(async move {
        loop {
            // Snapshot before servicing so a vector raised mid-pass is seen.
            let signal = worker.radio.try_lock().and_then(|r| r.interrupt());
            let seen = signal.as_ref().map(|s| s.count());
            worker.drain();
            if worker.closed.load(Ordering::Acquire) || !worker.current() {
                // One more pass already stopped and parked the radio.
                worker.drain();
                break;
            }
            match (signal, seen) {
                (Some(signal), Some(seen)) => {
                    // MLME/RSNA deadlines are millisecond timers; the slow
                    // housekeeping tick replaces 1 ms polling.
                    let tick = Box::pin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
                        HOUSEKEEPING_NS,
                    )));
                    signal.wait(seen, tick).await;
                }
                _ => {
                    narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
                }
            }
        }
    });
    Ok(device)
}
/// [`Activity`] of the published netdev: the original controller's
/// leave-idle wake (a no-op `None` for the other owners).
fn leave_idle() -> Waking {
    Box::pin(async {
        super::idle::activity()
            .await
            .map(|guard| Box::new(guard) as Box<dyn Send>)
    })
}
/// Whether the published netdev had no control request in flight or
/// ending within `ns` (false without a netdev).
pub(super) fn quiet_for(ns: u64) -> bool {
    NETDEV
        .lock()
        .clone()
        .is_some_and(|netdev| netdev.quiet_for(ns))
}
/// The generation currently attached to the published netdev.
pub(super) fn current() -> Option<Arc<Native>> {
    let netdev = NETDEV.lock().clone()?;
    netdev.generation()
}
/// Detach only the generation that owns `radio`: carrier and rings close
/// and the seat advances, so a late old publisher cannot address its
/// successor; the netdev keeps its name and ifindex. Returns whether that
/// generation was attached.
pub(super) fn retire(radio: &super::RetainedRadio) -> bool {
    let Some(netdev) = NETDEV.lock().clone() else {
        return false;
    };
    netdev.detach(radio).is_some()
}
/// Device removal: unregister the netdev (after the owner retired its
/// generation).
pub(super) fn unpublish() {
    let netdev = NETDEV.lock().take();
    if let Some(netdev) = netdev {
        netdev.unregister();
    }
}
struct Registered(Arc<NativeNetdev>);
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

#[cfg(feature = "kernel-test")]
#[path = "interface_tests.rs"]
mod tests;

#[cfg(feature = "kernel-test")]
#[path = "interface_channel_tests.rs"]
mod channel_tests;

#[cfg(feature = "kernel-test")]
#[path = "interface_ht40_tests.rs"]
mod ht40_tests;

#[cfg(feature = "kernel-test")]
#[path = "interface_netdev_tests.rs"]
mod netdev_tests;
