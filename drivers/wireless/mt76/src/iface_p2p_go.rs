//! Concurrent P2P GO group netdev (`NL80211_CMD_NEW_INTERFACE` with
//! `NL80211_IFTYPE_P2P_GO`), beside the home station on the same radio.
//!
//! Linux: `ieee80211_if_add` registers the netdev; `mt7921_add_interface`
//! and `mt7921_start_ap` publish its own OMAC/BSS/BMC/beacon on the shared
//! chanctx and `mt7921_stop_ap` and `mt7921_remove_interface` retire them.
//! NEW publishes the netdev, wiphy registration and vif slot synchronously
//! with carrier down and reserves the native GO owner (no command). The AP
//! control requests (START_AP, beacon, stations, keys, management and
//! control-port TX, frame registration) are bound to this netdev's own
//! `ApControlAuthority` (mode 9, this netdev's generation and reservation)
//! and run under the parent's control mutex on the native GO owner
//! (`go_link`), never on the physical interface's AP owner. START publishes
//! carrier only after the native START and port opening; STOP and DEL
//! retire the native GO without a radio reset. The parent worker runs one
//! `step_boot_go_network` per turn.
use super::*;
use crate::mt7921::firmware_transport::{self as transport, boot_ap, State};
use crate::mt7921::vif_slots::Allocation;
use alloc::sync::Weak;
use core::num::NonZeroU64;
use core::sync::atomic::AtomicU8;
use narf_wireless::ap_control::{ApControlAuthority, ApEventAuthority, ApInterfaceIdentity};

const LIVE: u8 = 0;
const REMOVING: u8 = 1;
const GONE: u8 = 2;

static NEXT_COOKIE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
struct Registration {
    frame_type: u16,
    prefix: Vec<u8>,
    source: ApEventAuthority,
}
#[derive(Debug, Default)]
struct Host {
    identity: Option<ApInterfaceIdentity>,
    metadata: Option<narf_net::iface::NetIfaceSnapshot>,
    control: Option<(narf_wireless::ControlPort, ApEventAuthority)>,
    registrations: Vec<Registration>,
}

#[derive(Debug)]
pub(crate) struct P2pGoIface {
    name: String,
    mac: [u8; 6],
    cookie: u64,
    parent: Weak<Mt76Iface>,
    physical: u64,
    allocation: Allocation,
    phase: AtomicU8,
    /// AP control generation of this netdev; DEL retires every authority.
    generation: AtomicU64,
    serial: Arc<narf_wireless::ap_control::ExclusiveControl>,
    /// A native START succeeded and has not been retired.
    native: AtomicBool,
    /// Host publication of a started GO (carrier, rings, identity).
    started: AtomicBool,
    /// The native GO must be stopped from the worker.
    stop_needed: AtomicBool,
    host: IrqSafeSpinLock<Host>,
    receive_epoch: AtomicU64,
    rx_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
    rx_prod: IrqSafeSpinLock<Option<Producer<Frame, RX_RING_N>>>,
    tx_cons: IrqSafeSpinLock<Option<Consumer<Frame, TX_RING_N>>>,
    pending_tx: IrqSafeSpinLock<Option<Frame>>,
}

impl Mt76Iface {
    /// Legacy synchronous NEW for a P2P GO group netdev. One concurrent
    /// group netdev (client or GO), only beside a home station role.
    pub(super) fn new_p2p_go(
        &self,
        name: &str,
        mac: Option<[u8; 6]>,
    ) -> Result<Arc<P2pGoIface>, WirelessError> {
        if self.p2p_profile.is_none() {
            return Err(WirelessError::NotSupported);
        }
        if name.is_empty()
            || name.len() > 15
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            return Err(WirelessError::InvalidArgs);
        }
        let parent = ACTIVE
            .lock()
            .as_ref()
            .filter(|active| core::ptr::eq(active.as_ref(), self))
            .cloned()
            .ok_or(WirelessError::Denied)?;
        let _control = self.control.try_lock().ok_or(WirelessError::Busy)?;
        if !self.station_role()
            || self.sleeping.load(Ordering::Acquire)
            || self.ap_owned.load(Ordering::Acquire)
            || self.monitor_started.load(Ordering::Acquire)
            || self.p2p_group.lock().is_some()
            || self.p2p_go.lock().is_some()
        {
            return Err(WirelessError::Busy);
        }
        let device = { self.p2p_device.lock().as_ref().map(|device| device.mac()) };
        let mac = match mac {
            Some(mac) => mac,
            None => crate::mt7921::vif_slots::mac_candidates(self.mac())
                .into_iter()
                .find(|candidate| *candidate != self.mac() && Some(*candidate) != device)
                .ok_or(WirelessError::Busy)?,
        };
        if mac == [0; 6] || mac[0] & 1 != 0 || mac == self.mac() || Some(mac) == device {
            return Err(WirelessError::InvalidArgs);
        }
        if narf_net::iface::lookup(name).is_some()
            || narf_wireless::registry::list()
                .iter()
                .any(|iface| iface.name() == name)
        {
            return Err(WirelessError::Busy);
        }
        let authority = narf_net::trusted_net_authority()
            .and_then(|cap| cap.derive().ok())
            .ok_or(WirelessError::Denied)?;
        let allocation = self.vif_slots.lock().reserve().map_err(map_error)?;
        // The native GO owner: vif and address only, no command.
        if let Err(error) = transport::open_boot_go(allocation.vif(), mac) {
            self.vif_slots.lock().release_retired(allocation);
            return Err(map_error(error));
        }
        let go = Arc::new(P2pGoIface {
            name: name.into(),
            mac,
            cookie: NEXT_COOKIE.fetch_add(1, Ordering::Relaxed),
            parent: Arc::downgrade(&parent),
            physical: self.wiphy_id(),
            allocation,
            phase: AtomicU8::new(LIVE),
            generation: AtomicU64::new(1),
            serial: Arc::new(narf_wireless::ap_control::ExclusiveControl::new()),
            native: AtomicBool::new(false),
            started: AtomicBool::new(false),
            stop_needed: AtomicBool::new(false),
            host: IrqSafeSpinLock::new(Host::default()),
            receive_epoch: AtomicU64::new(0),
            rx_ring: IrqSafeSpinLock::new(None),
            tx_ring: IrqSafeSpinLock::new(None),
            rx_prod: IrqSafeSpinLock::new(None),
            tx_cons: IrqSafeSpinLock::new(None),
            pending_tx: IrqSafeSpinLock::new(None),
        });
        if let Err(error) = narf_net::registry().register(&authority, Registered(go.clone())) {
            let _ = transport::close_boot_go();
            self.vif_slots.lock().release_retired(allocation);
            return Err(match error {
                narf_net::RegisterError::DuplicateName => WirelessError::Busy,
                narf_net::RegisterError::AuthorityRevoked => WirelessError::Denied,
            });
        }
        narf_net::iface::register_with_context(name, mac, go.cookie, send_go);
        publish_link(name, false);
        *self.p2p_go.lock() = Some(go.clone());
        narf_wireless::registry::register(go.clone());
        Ok(go)
    }

    /// Parent removal: withdraw the GO netdev. Native resources end with
    /// the radio generation.
    pub(super) fn withdraw_p2p_go(&self) {
        let go = { self.p2p_go.lock().take() };
        if let Some(go) = go {
            go.unpublish();
            go.phase.store(GONE, Ordering::Release);
            go.native.store(false, Ordering::Release);
            self.vif_slots.lock().release_retired(go.allocation);
        }
    }

    /// One worker turn for the GO netdev: ordered native retirement after
    /// DEL, a pending STOP after a lost host identity, then one data step.
    pub(crate) async fn poll_p2p_go(&self) {
        let go = { self.p2p_go.lock().clone() };
        let Some(go) = go else {
            return;
        };
        if go.phase.load(Ordering::Acquire) == REMOVING {
            let Some(_control) = self.control.try_lock() else {
                return;
            };
            if go.retire_native().await.is_ok() {
                go.phase.store(GONE, Ordering::Release);
                self.vif_slots.lock().release_retired(go.allocation);
                let mut slot = self.p2p_go.lock();
                if slot.as_ref().is_some_and(|g| Arc::ptr_eq(g, &go)) {
                    *slot = None;
                }
            }
            return;
        }
        if go.started.load(Ordering::Acquire) && !go.host_current() {
            go.close_host();
        }
        if go.stop_needed.load(Ordering::Acquire) {
            let Some(_control) = self.control.try_lock() else {
                return;
            };
            let _ = go.stop_native().await;
            return;
        }
        let _ = go.drain_network();
    }
}

impl P2pGoIface {
    /// The parent while this exact GO netdev is its published child.
    fn current(&self) -> Result<Arc<Mt76Iface>, WirelessError> {
        let parent = self.parent.upgrade().ok_or(WirelessError::Denied)?;
        let physical = {
            ACTIVE
                .lock()
                .as_ref()
                .is_some_and(|active| Arc::ptr_eq(active, &parent))
        };
        let child = {
            parent
                .p2p_go
                .lock()
                .as_ref()
                .is_some_and(|go| core::ptr::eq(go.as_ref(), self))
        };
        let slot = { parent.vif_slots.lock().current(self.allocation) };
        if !physical
            || !child
            || !slot
            || self.phase.load(Ordering::Acquire) != LIVE
            || parent.sleeping.load(Ordering::Acquire)
        {
            return Err(WirelessError::Denied);
        }
        Ok(parent)
    }
    /// The AP control request is this netdev's current GO authority.
    fn request_current(&self, authority: &ApControlAuthority) -> Result<(), WirelessError> {
        self.current()?;
        authority.check_for(self)?;
        if authority.mode() != 9 {
            return Err(WirelessError::Denied);
        }
        Ok(())
    }
    fn host_current(&self) -> bool {
        if !self.started.load(Ordering::Acquire) || self.current().is_err() {
            return false;
        }
        let identity = self.host.lock().identity.clone();
        identity.is_some_and(|identity| identity.check_for(self).is_ok())
    }

    fn unpublish(&self) {
        self.close_host();
        self.generation.fetch_add(1, Ordering::AcqRel);
        narf_wireless::registry::unregister(&self.name);
        narf_net::registry().unregister(&self.name);
        narf_net::iface::unregister(&self.name);
    }
    fn retire_rings(&self) {
        self.receive_epoch.store(0, Ordering::Release);
        *self.pending_tx.lock() = None;
        *self.tx_ring.lock() = None;
        *self.rx_ring.lock() = None;
        *self.tx_cons.lock() = None;
        *self.rx_prod.lock() = None;
    }
    fn open_rings(&self, epoch: u64) {
        let (tx_prod, tx_cons) = narf_ipc::channel::<Frame, TX_RING_N>();
        let (rx_prod, rx_cons) = narf_ipc::channel::<Frame, RX_RING_N>();
        *self.tx_ring.lock() = Some(tx_prod);
        *self.tx_cons.lock() = Some(tx_cons);
        *self.rx_ring.lock() = Some(rx_cons);
        *self.rx_prod.lock() = Some(rx_prod);
        self.receive_epoch.store(epoch, Ordering::Release);
    }
    /// Close carrier and the host rings; a started native GO is stopped by
    /// the worker (`stop_native`).
    fn close_host(&self) {
        let was_started = self.started.swap(false, Ordering::AcqRel);
        let metadata = {
            let mut host = self.host.lock();
            host.identity = None;
            host.control = None;
            host.metadata.take()
        };
        self.retire_rings();
        if let Some(snapshot) = metadata {
            narf_net::iface::withdraw_link_metadata_for(&snapshot);
        }
        if was_started || self.native.load(Ordering::Acquire) {
            self.stop_needed.store(true, Ordering::Release);
        }
    }
    /// Requires the parent's control mutex. A stale owner (a verified reset
    /// already retired it) counts as stopped.
    async fn stop_native(&self) -> Result<(), WirelessError> {
        match transport::stop_boot_go().await {
            Ok(()) | Err(transport::Error::Bounds | transport::Error::DeviceGone) => {
                self.native.store(false, Ordering::Release);
                self.stop_needed.store(false, Ordering::Release);
                Ok(())
            }
            Err(error) => Err(map_error(error)),
        }
    }
    /// Ordered native retirement after DEL: STOP (`mt7921_stop_ap`, peer
    /// removal, `mt792x_remove_interface`), then release the GO owner. A
    /// failed GO role stays retained until verified recovery.
    async fn retire_native(&self) -> Result<(), WirelessError> {
        match transport::boot_go_state() {
            None => return Ok(()),
            Some((vif, _)) if vif != self.allocation.vif() => return Ok(()),
            Some((_, State::Failed { .. } | State::Running(_))) => return Err(WirelessError::Busy),
            Some((_, State::AccessPoint { .. })) => self.stop_native().await?,
            Some(_) => {}
        }
        match transport::close_boot_go() {
            Ok(()) | Err(transport::Error::Bounds | transport::Error::DeviceGone) => Ok(()),
            Err(error) => Err(map_error(error)),
        }
    }

    fn next_tx(&self) -> Option<Frame> {
        let mut slot = self.tx_cons.lock();
        let consumer = slot.as_mut()?;
        for _ in 0..16 {
            let frame = consumer.try_recv().ok().flatten()?;
            if self.transmit_admitted(frame.payload()) {
                return Some(frame);
            }
        }
        None
    }
    /// Ordinary data only: EAPOL (and pre-auth unless no_preauth) belongs to
    /// the control port.
    fn transmit_admitted(&self, frame: &[u8]) -> bool {
        if !(14..=1514).contains(&frame.len()) || frame[6..12] != self.mac {
            return false;
        }
        let proto = u16::from_be_bytes([frame[12], frame[13]]);
        let no_preauth = self
            .host
            .lock()
            .control
            .as_ref()
            .is_some_and(|(control, _)| control.no_preauth);
        proto >= 0x600 && proto != 0x888e && (proto != 0x88c7 || no_preauth)
    }
    fn receive_current(&self, epoch: u64) -> Result<bool, WirelessError> {
        if !self.host_current() || epoch == 0 {
            return Ok(false);
        }
        transport::boot_go_receive_current(epoch).map_err(map_error)
    }
    /// A new receive epoch retires frames queued for an older one.
    fn ensure_receive_epoch(&self, epoch: u64) {
        if self.receive_epoch.load(Ordering::Acquire) != epoch {
            let (producer, consumer) = narf_ipc::channel::<Frame, RX_RING_N>();
            *self.rx_ring.lock() = Some(consumer);
            *self.rx_prod.lock() = Some(producer);
            self.receive_epoch.store(epoch, Ordering::Release);
        }
    }

    /// One bounded GO data step (`step_boot_go_network`); each copy and
    /// event is published only while the GO is receive-current for the
    /// batch epoch.
    fn drain_network(&self) -> Result<bool, WirelessError> {
        if !self.host_current() {
            return Ok(false);
        }
        let result = {
            let mut pending = self.pending_tx.lock();
            if pending.is_none() {
                *pending = self.next_tx();
            }
            let result = transport::step_boot_go_network(pending.as_ref().map(Frame::payload));
            if result.as_ref().is_ok_and(|(step, _)| step.transmitted) {
                *pending = None;
            }
            result
        };
        let (step, events) = match result {
            Ok(step) => step,
            Err(transport::Error::Busy) => return Ok(false),
            Err(error) => {
                self.close_host();
                return Err(map_error(error));
            }
        };
        let progress = step.transmitted || !step.received.is_empty() || !events.is_empty();
        deliver_received_batch(
            step,
            |epoch| self.receive_current(epoch),
            |data| narf_net::iface::on_rx_frame_from(&self.name, data),
            |data, epoch| {
                let Ok(mut buffer) =
                    narf_io::alloc_coherent(data.len(), narf_lib::id::DomainId::DRIVER_0)
                else {
                    return Ok(());
                };
                buffer.as_mut_slice()[..data.len()].copy_from_slice(&data);
                let frame = Frame::new(buffer, data.len() as u32);
                if self.receive_current(epoch)? {
                    self.ensure_receive_epoch(epoch);
                    if let Some(producer) = self.rx_prod.lock().as_mut() {
                        let _ = producer.try_send(frame);
                    }
                }
                Ok(())
            },
        )?;
        for event in events {
            self.deliver_event(event)?;
        }
        Ok(progress)
    }
    /// Registered management frames and control-port PDUs of this GO, to
    /// this netdev's own event sources only.
    fn deliver_event(
        &self,
        event: crate::mt7921::firmware_transport::ApRxEvent,
    ) -> Result<(), WirelessError> {
        use crate::mt7921::firmware_transport::ApEvent;
        if !self.receive_current(event.epoch)? {
            return Ok(());
        }
        match event.event {
            ApEvent::Management {
                frequency_mhz,
                signal_dbm,
                frame,
            } => {
                if frame.len() < 24 {
                    return Ok(());
                }
                let frame_type = u16::from_le_bytes([frame[0], frame[1]]) & 0x00fc;
                let sources: Vec<_> = self
                    .host
                    .lock()
                    .registrations
                    .iter()
                    .filter(|r| r.frame_type == frame_type && frame[24..].starts_with(&r.prefix))
                    .map(|r| r.source.clone())
                    .collect();
                for source in sources {
                    if !self.receive_current(event.epoch)? {
                        break;
                    }
                    if source.check_for(self).is_ok() {
                        let _ = source.management_received(frequency_mhz, signal_dbm, &frame);
                    }
                }
            }
            ApEvent::Control {
                peer,
                ethertype,
                pdu,
                unencrypted,
            } => {
                let control = self.host.lock().control.clone();
                if let Some((control, source)) = control {
                    if control.enabled
                        && control.over_nl80211
                        && (ethertype == control.ethertype
                            || ethertype == 0x88c7 && !control.no_preauth)
                        && self.receive_current(event.epoch)?
                        && source.check_for(self).is_ok()
                    {
                        let _ = source.control_received(peer, ethertype, &pdu, unencrypted);
                    }
                }
            }
        }
        Ok(())
    }

    fn enqueue(&self, bytes: &[u8]) -> Result<(), ()> {
        if !self.transmit_admitted(bytes) || !self.host_current() {
            return Err(());
        }
        let mut buffer = narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
            .map_err(|_| ())?;
        buffer.as_mut_slice()[..bytes.len()].copy_from_slice(bytes);
        self.tx_ring
            .lock()
            .as_mut()
            .ok_or(())?
            .try_send(Frame::new(buffer, bytes.len() as u32))
            .map_err(|_| ())
    }

    /// START_AP: native GO START on the GO vif, then host publication
    /// (identity, rings, carrier). A host publication failure stops the
    /// native GO again.
    async fn start(
        &self,
        authority: &ApControlAuthority,
        config: narf_wireless::ApConfig,
        settings: narf_wireless::ApStartSettings,
    ) -> Result<(), WirelessError> {
        let parent = self.current()?;
        let _control = parent.control.lock().await;
        self.request_current(authority)?;
        if !parent.station_role() || self.started.load(Ordering::Acquire) {
            return Err(WirelessError::Busy);
        }
        if self.stop_needed.load(Ordering::Acquire) {
            self.stop_native().await?;
        }
        // A verified reset retired the native GO owner with the home link;
        // this live netdev reserves it again (`mt7921_add_interface` after
        // `ieee80211_reconfig`).
        if transport::boot_go_state().is_none() {
            transport::open_boot_go(self.allocation.vif(), self.mac).map_err(map_error)?;
        }
        let control = settings.control_port;
        let epoch = transport::start_boot_go(Arc::new(authority.clone()), config, settings)
            .await
            .map_err(map_error)?;
        self.native.store(true, Ordering::Release);
        let publication = (|| {
            self.request_current(authority)?;
            let identity = authority.identity()?;
            identity.check_for(self)?;
            let source = if control.enabled && control.over_nl80211 {
                Some((control, authority.event_authority()?))
            } else {
                None
            };
            let snapshot = identity.metadata_snapshot()?;
            self.open_rings(epoch);
            {
                let mut host = self.host.lock();
                host.identity = Some(identity);
                host.metadata = Some(snapshot.clone());
                host.control = source;
            }
            self.started.store(true, Ordering::Release);
            if !narf_net::iface::set_link_metadata_for(&snapshot, true, None, None) {
                return Err(WirelessError::Denied);
            }
            self.request_current(authority)
        })();
        if let Err(error) = publication {
            self.close_host();
            let _ = self.stop_native().await;
            return Err(error);
        }
        Ok(())
    }
    async fn stop(&self, authority: &ApControlAuthority) -> Result<(), WirelessError> {
        let parent = self.current()?;
        let _control = parent.control.lock().await;
        self.request_current(authority)?;
        self.close_host();
        if !self.stop_needed.load(Ordering::Acquire) {
            return Ok(());
        }
        self.stop_native().await
    }
    async fn request(
        &self,
        authority: &ApControlAuthority,
        request: boot_ap::Request,
    ) -> Result<boot_ap::Reply, WirelessError> {
        let parent = self.current()?;
        let _control = parent.control.lock().await;
        self.request_current(authority)?;
        if !self.host_current() {
            return Err(WirelessError::Busy);
        }
        let reply = transport::boot_go_request(Arc::new(authority.clone()), request).await;
        if matches!(
            transport::boot_go_state(),
            Some((_, State::Failed { .. } | State::Running(_)))
        ) {
            // A failed GO role closes carrier; verified recovery retires it.
            self.close_host();
        }
        let reply = reply.map_err(map_error)?;
        self.request_current(authority)?;
        Ok(reply)
    }
}

fn send_go(cookie: u64, bytes: &[u8], _: narf_net::TxMeta) -> Result<(), ()> {
    let parent = ACTIVE.lock().clone().ok_or(())?;
    let go = parent
        .p2p_go
        .lock()
        .as_ref()
        .filter(|go| go.cookie == cookie)
        .cloned()
        .ok_or(())?;
    go.enqueue(bytes)
}

fn map_error(error: transport::Error) -> WirelessError {
    use transport::Error;
    match error {
        Error::Bounds => WirelessError::InvalidArgs,
        Error::UnsupportedFirmware => WirelessError::NotSupported,
        Error::Busy => WirelessError::Busy,
        Error::Timeout => WirelessError::Timeout,
        Error::Authority | Error::DeviceGone | Error::Cancelled => WirelessError::Denied,
        _ => WirelessError::HardwareError,
    }
}
fn errno(error: WirelessError) -> i32 {
    match error {
        WirelessError::InvalidArgs => -22,
        WirelessError::NotSupported => -95,
        WirelessError::Busy => -16,
        WirelessError::Denied => -1,
        WirelessError::Timeout => -110,
        _ => -5,
    }
}

impl Interface for P2pGoIface {
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
        self.host_current()
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx_ring
    }
}

struct Registered(Arc<P2pGoIface>);
impl Interface for Registered {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn mac(&self) -> [u8; 6] {
        self.0.mac
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        self.0.host_current()
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.0.rx_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.0.tx_ring
    }
}

#[async_trait]
impl WirelessNetIface for P2pGoIface {
    fn wiphy_id(&self) -> u64 {
        self.physical
    }
    fn current_iftype(&self) -> u32 {
        9
    }
    fn get_wireless_info(&self) -> WirelessIfaceInfo {
        let mut info = self
            .parent
            .upgrade()
            .map(|parent| parent.get_wireless_info())
            .unwrap_or(WirelessIfaceInfo {
                base_name: self.name.clone(),
                base_mac: self.mac,
                bands: Vec::new(),
                modes: WirelessModes::empty(),
                hw_caps: HwCaps {
                    ht_supported: false,
                    vht_supported: false,
                    he_supported: false,
                    eht_supported: false,
                },
            });
        info.base_name = self.name.clone();
        info.base_mac = self.mac;
        info.modes = WirelessModes::AP;
        info
    }
    fn phy_capabilities(&self, band_mhz: u32) -> Option<narf_wireless::iface::PhyCapabilities> {
        self.parent.upgrade()?.phy_capabilities(band_mhz)
    }
    /// DEL (`ieee80211_if_remove`): the netdev disappears now; the parent
    /// worker stops the native GO before the vif slot is reused.
    fn delete_virtual_interface(&self) -> Result<(), WirelessError> {
        self.current()?;
        if self
            .phase
            .compare_exchange(LIVE, REMOVING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(WirelessError::Busy);
        }
        self.unpublish();
        Ok(())
    }
    /// A GO netdev neither scans nor joins (mac80211 rejects station
    /// operations on an AP vif).
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
    fn supports_ap(&self) -> bool {
        true
    }
    fn supports_ap_userspace_mlme(&self) -> bool {
        true
    }
    fn supports_ap_authenticator(&self) -> bool {
        true
    }
    fn supports_control_port_no_preauth(&self) -> bool {
        true
    }
    fn supports_control_port_tx_status(&self) -> bool {
        true
    }
    fn ap_station_macs(&self) -> Vec<[u8; 6]> {
        if self.host_current() {
            transport::boot_go_stations()
        } else {
            Vec::new()
        }
    }
    fn ap_station_info(&self, peer: [u8; 6]) -> Option<narf_wireless::StationInfo> {
        self.ap_station_macs()
            .contains(&peer)
            .then(narf_wireless::StationInfo::default)
    }
    fn ap_control_generation(&self) -> Option<NonZeroU64> {
        NonZeroU64::new(self.generation.load(Ordering::Acquire))
    }
    fn reserve_ap_control(
        &self,
    ) -> Result<Option<Arc<dyn narf_wireless::ap_control::ApControlReservation>>, WirelessError>
    {
        self.serial.try_reserve().map(Some)
    }
    async fn start_ap_with_settings_async(
        &self,
        authority: &ApControlAuthority,
        config: narf_wireless::ApConfig,
        settings: narf_wireless::ApStartSettings,
    ) -> Result<(), WirelessError> {
        self.start(authority, config, settings).await
    }
    async fn stop_ap_async(&self, authority: &ApControlAuthority) -> Result<(), WirelessError> {
        self.stop(authority).await
    }
    async fn set_beacon_async(
        &self,
        authority: &ApControlAuthority,
        head: Option<Vec<u8>>,
        tail: Option<Vec<u8>>,
        probe: Option<Vec<u8>>,
    ) -> Result<(), WirelessError> {
        self.request(authority, boot_ap::Request::Beacon(head, tail, probe))
            .await
            .map(|_| ())
    }
    async fn add_station_async(
        &self,
        authority: &ApControlAuthority,
        config: narf_wireless::StationConfig,
    ) -> Result<(), WirelessError> {
        self.request(authority, boot_ap::Request::AddStation(config))
            .await
            .map(|_| ())
    }
    async fn set_station_async(
        &self,
        authority: &ApControlAuthority,
        config: narf_wireless::StationConfig,
    ) -> Result<(), WirelessError> {
        self.request(authority, boot_ap::Request::SetStation(config))
            .await
            .map(|_| ())
    }
    async fn del_station_async(
        &self,
        authority: &ApControlAuthority,
        peer: Option<[u8; 6]>,
        _reason: u16,
    ) -> Result<(), WirelessError> {
        self.request(authority, boot_ap::Request::DelStation(peer))
            .await
            .map(|_| ())
    }
    async fn add_key_ap_async(
        &self,
        authority: &ApControlAuthority,
        key: narf_wireless::OwnedKey,
    ) -> Result<(), i32> {
        self.request(authority, boot_ap::Request::AddKey(key))
            .await
            .map(|_| ())
            .map_err(errno)
    }
    async fn del_key_ap_async(
        &self,
        authority: &ApControlAuthority,
        index: u8,
        pairwise: bool,
        peer: Option<[u8; 6]>,
    ) -> Result<(), i32> {
        self.request(authority, boot_ap::Request::DelKey(index, pairwise, peer))
            .await
            .map(|_| ())
            .map_err(errno)
    }
    async fn default_key_ap_async(
        &self,
        authority: &ApControlAuthority,
        index: u8,
        _unicast: bool,
        multicast: bool,
        management: bool,
        beacon: bool,
    ) -> Result<(), i32> {
        // GTK only, as on the physical AP (`Mt76Iface::ap_default_key`).
        if !multicast || management || beacon {
            return Err(-95);
        }
        self.request(authority, boot_ap::Request::DefaultKey(index))
            .await
            .map(|_| ())
            .map_err(errno)
    }
    async fn mgmt_tx_ap_async(
        &self,
        authority: &ApControlAuthority,
        _cookie: u64,
        request: narf_wireless::MgmtTxRequest,
    ) -> Result<bool, WirelessError> {
        match self
            .request(authority, boot_ap::Request::Management(request))
            .await?
        {
            boot_ap::Reply::Ack(ack) => Ok(ack),
            boot_ap::Reply::Done => Err(WirelessError::HardwareError),
        }
    }
    async fn register_mgmt_frame_ap_async(
        &self,
        authority: &ApControlAuthority,
        frame_type: u16,
        prefix: Vec<u8>,
    ) -> Result<(), WirelessError> {
        self.request_current(authority)?;
        // Only management subtypes the native GO RX owner actually emits.
        if frame_type & !0x00f0 != 0
            || !matches!(frame_type >> 4, 0 | 2 | 4 | 11 | 10 | 12 | 13)
            || prefix.len() > 256
        {
            return Err(WirelessError::NotSupported);
        }
        let source = authority.event_authority()?;
        let previous = self.host.lock().registrations.clone();
        let mut current: Vec<_> = previous
            .into_iter()
            .filter(|r| r.source.registration_current().is_ok())
            .collect();
        let refusal = if current.len() >= 64
            || current
                .iter()
                .any(|r| r.frame_type == frame_type && r.prefix == prefix)
        {
            Some(WirelessError::Busy)
        } else {
            None
        };
        if refusal.is_none() {
            current.push(Registration {
                frame_type,
                prefix,
                source,
            });
        }
        self.host.lock().registrations = current;
        self.request_current(authority)?;
        refusal.map_or(Ok(()), Err)
    }
    async fn tx_control_port_ap_async(
        &self,
        authority: &ApControlAuthority,
        request: narf_wireless::ControlPortTxRequest,
    ) -> Result<bool, i32> {
        match self
            .request(authority, boot_ap::Request::Control(request))
            .await
            .map_err(errno)?
        {
            boot_ap::Reply::Ack(ack) => Ok(ack),
            boot_ap::Reply::Done => Err(-5),
        }
    }
}
