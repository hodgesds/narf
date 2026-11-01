// SPDX-License-Identifier: GPL-2.0-or-later
//! One shared retained AR9285 station for async control and synchronous stack
//! progress. The radio supplies the actual DMA/host-close publication gate.
use super::{
    packet::Port,
    station::{self, Environment, Phase, Radio},
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
pub(super) struct Device<P: Port, E: Environment> {
    pub(super) radio: Arc<Mutex<Radio<P, E>>>,
    state: Mutex<State>,
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
    rx: IrqSafeSpinLock<Option<narf_ipc::Consumer<Frame, RX_RING_N>>>,
    tx: IrqSafeSpinLock<Option<narf_ipc::Producer<Frame, TX_RING_N>>>,
}
impl<P: Port, E: Environment> core::fmt::Debug for Device<P, E> {
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
impl<P: Port + Send + 'static, E: Environment + 'static> HostClose for Device<P, E> {
    fn close(&self) {
        let _publication = self.publication.lock();
        self.closed.store(true, Ordering::Release);
        self.publish_link(None);
        self.clear_rx();
    }
}
impl<P: Port + Send + 'static, E: Environment + 'static> Device<P, E> {
    pub(super) fn new(name: &str, radio: Arc<Mutex<Radio<P, E>>>) -> Result<Self, Error> {
        let (own, closed, publication) = {
            let owner = radio.try_lock().ok_or(Error::Busy)?;
            (owner.local(), owner.closed(), owner.publication())
        };
        let (rx, consumer) = narf_ipc::channel();
        let (producer, tx) = narf_ipc::channel();
        Ok(Self {
            radio,
            scan_ies: IrqSafeSpinLock::new(Vec::new()),
            state: Mutex::new(State {
                rx,
                tx,
                pending: super::qos::Scheduler::default(),
            }),
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
            rx: IrqSafeSpinLock::new(Some(consumer)),
            tx: IrqSafeSpinLock::new(Some(producer)),
        })
    }
    fn publish_link(&self, peer: Option<[u8; 6]>) {
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
    fn start(&self, radio: &mut Radio<P, E>) -> Result<(), Error> {
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
        self.state.lock().await.clear();
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
        self.tx
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
        if let Some(rx) = self.rx.lock().as_mut() {
            for _ in 0..RX_RING_N {
                if !matches!(rx.try_recv(), Ok(Some(_))) {
                    break;
                }
            }
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
        let Some(mut state) = self.state.try_lock() else {
            return (0, Vec::new());
        };
        if self.closed.load(Ordering::Acquire) {
            state.clear();
            let _ = radio.stop();
            self.link(None);
            self.clear_rx();
            return (0, Vec::new());
        }
        if !matches!(radio.phase(), Phase::Passive | Phase::Open | Phase::Failed) {
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
                state.clear();
                return Ok(Vec::new());
            }
            if radio.peer().is_none() {
                state.clear();
                return Ok(frames);
            }
            if !radio.current_receive(epoch)? {
                state.clear();
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
                    // The measured two-MPDU sender aggregates BE/TID0 only.
                    // Frames queued before N85Q activation are re-classified.
                    let mut second = None;
                    if tid == 0 && radio.can_aggregate() && radio.transmit_tid(frame.payload()) == 0
                    {
                        if let Some(next) = state.pending.pop_tid(0) {
                            let now = radio.transmit_tid(next.payload());
                            if now == 0 {
                                second = Some(next);
                            } else {
                                let _ = state.pending.push(now, next);
                            }
                        }
                    }
                    if let Some(second) = second {
                        radio.send_pair(frame.payload(), second.payload())?;
                    } else {
                        radio.send(frame.payload())?;
                    }
                }
            }
            if self.closed.load(Ordering::Acquire) {
                state.clear();
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
            Err(_) => {
                self.close();
                let _ = radio.stop();
                state.clear();
                self.clear_rx();
                (0, Vec::new())
            }
        }
    }
    /// Host-side retirement of this generation (see [`retire`]).
    pub(super) fn retire_host(&self) {
        self.close();
        if let Some(mut state) = self.state.try_lock() {
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
                narf_net::iface::on_rx_frame_from(&self.name, &mut frame);
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
impl<P: Port + Send + 'static, E: Environment + 'static> Interface for Device<P, E> {
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
        &self.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<narf_ipc::Producer<Frame, TX_RING_N>>> {
        &self.tx
    }
}
#[async_trait::async_trait]
impl<P: Port + Send + 'static, E: Environment + 'static> WirelessNetIface for Device<P, E> {
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
            bands: vec![WirelessBand {
                freq_mhz: 2400,
                channels: self.radio.try_lock().map_or_else(Vec::new, |radio| {
                    (1..=13)
                        .filter(|channel| {
                            radio.channel_mask() & (1 << (channel - 1)) != 0
                                && permitted(2407 + 5 * *channel as u16)
                        })
                        .collect()
                }),
            }],
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
        self.state.lock().await.clear();
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
impl<P: Port + Send + 'static, E: Environment + 'static> ChannelIface for Device<P, E> {
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
        let channel = super::channels::channel(frequency)?;
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
        if radio.channel_mask() & (1 << (channel - 1)) == 0 || !permitted(frequency) {
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
        super::calibration::Permission::from_domain_at(&domain, frequency).is_ok()
    })
}
fn one_scan(request: &ScanRequest, frequency: u16) -> ScanRequest {
    ScanRequest {
        ssids: request.ssids.clone(),
        frequencies_mhz: vec![u32::from(frequency)],
        channels: vec![u32::from((frequency - 2407) / 5)],
        active: request.active,
        random_mac: request.random_mac,
        colocated_6ghz: request.colocated_6ghz,
        duration_tu: request.duration_tu,
        duration_mandatory: request.duration_mandatory,
        extra_ies: request.extra_ies.clone(),
    }
}
fn scan_frequencies(request: &ScanRequest, mask: u16) -> Result<Vec<u16>, WirelessError> {
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
        (1..=13)
            .filter(|ch| mask & (1 << (ch - 1)) != 0)
            .map(|ch| 2407 + ch * 5)
            .collect()
    };
    let mut output = Vec::new();
    for frequency in selected {
        let channel = super::channels::channel(frequency).map_err(wireless)?;
        // Retain the original channel1-only selector behavior. The native
        // Port still checks current policy on every actual RF/DMA operation.
        let reference = mask == 1 && frequency == 2412;
        if mask & (1 << (channel - 1)) == 0 || !reference && !permitted(frequency) {
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
pub(super) type Native = Device<super::packet_native::Native, station::NativeEnvironment>;
trait Endpoint: Send + Sync {
    fn enqueue(&self, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()>;
    fn drain(&self) -> bool;
}
impl<P: Port + Send + 'static, E: Environment + 'static> Endpoint for Device<P, E> {
    fn enqueue(&self, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
        Device::enqueue(self, bytes, meta)
    }
    fn drain(&self) -> bool {
        Device::drain(self)
    }
}
static ACTIVE: IrqSafeSpinLock<Option<Arc<dyn Endpoint>>> = IrqSafeSpinLock::new(None);
/// The concrete published generation, for retirement by radio identity.
static CURRENT: IrqSafeSpinLock<Option<Arc<Native>>> = IrqSafeSpinLock::new(None);
static CLAIMED: AtomicBool = AtomicBool::new(false);
fn send(bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let device = ACTIVE.lock().clone().ok_or(())?;
    device.enqueue(bytes, meta)
}
fn drain() -> bool {
    let device = ACTIVE.lock().clone();
    device.is_some_and(|device| device.drain())
}
/// Caller has retained this exact Radio Arc in Ath9k before any packet start.
pub(super) fn publish(radio: super::RetainedRadio) -> Result<Arc<Native>, Error> {
    let authority = narf_net::trusted_net_authority()
        .and_then(|cap| cap.derive().ok())
        .ok_or(Error::Profile)?;
    CLAIMED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| Error::State)?;
    let device = Arc::new(Device::new(narf_net::iface::reserve_name("wlan%d"), radio)?);
    narf_net::registry()
        .register(&authority, Registered(device.clone()))
        .map_err(|_| Error::Profile)?;
    *ACTIVE.lock() = Some(device.clone());
    *CURRENT.lock() = Some(device.clone());
    narf_net::iface::register(device.name(), device.own, send);
    device.link(None);
    device.admitted.store(true, Ordering::Release);
    {
        let mut radio = device.radio.try_lock().ok_or(Error::Busy)?;
        device.start(&mut radio)?;
    }
    narf_wireless::registry::register(device.clone());
    narf_net::iface::install_rx_drain(drain);
    let worker = device.clone();
    narf_scheduler::spawn(async move {
        loop {
            // Snapshot before servicing so a vector raised mid-pass is seen.
            let signal = worker.radio.try_lock().and_then(|r| r.interrupt());
            let seen = signal.as_ref().map(|s| s.count());
            worker.drain();
            if worker.closed.load(Ordering::Acquire) {
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
pub(super) fn current() -> Option<Arc<Native>> {
    CURRENT.lock().clone()
}
/// Withdraw only the generation that owns `radio`: close carrier and rings,
/// leave every registry, and keep the retired name reserved so a late old
/// publisher cannot address a successor. Returns whether it was published.
pub(super) fn retire(radio: &super::RetainedRadio) -> bool {
    let device = {
        let mut current = CURRENT.lock();
        match current.as_ref() {
            Some(device) if Arc::ptr_eq(&device.radio, radio) => current.take(),
            _ => None,
        }
    };
    let Some(device) = device else {
        return false;
    };
    *ACTIVE.lock() = None;
    device.retire_host();
    CLAIMED.store(false, Ordering::Release);
    true
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

#[cfg(feature = "kernel-test")]
#[path = "interface_tests.rs"]
mod tests;

#[cfg(feature = "kernel-test")]
#[path = "interface_channel_tests.rs"]
mod channel_tests;

#[cfg(feature = "kernel-test")]
#[path = "interface_ht40_tests.rs"]
mod ht40_tests;
