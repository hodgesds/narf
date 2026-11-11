//! Concurrent P2P-client group netdev (`NL80211_CMD_NEW_INTERFACE` with
//! `NL80211_IFTYPE_P2P_CLIENT`), beside the home station on the same radio.
//!
//! Linux: `ieee80211_if_add` registers the netdev, `ieee80211_do_open` ->
//! `mt7921_add_interface` publishes its own OMAC/BSS (`mt76_connac_mcu_uni_add_dev`)
//! and `mt7921_remove_interface` retires it. Here the metadata (netdev,
//! wiphy registration, vif slot) is published synchronously by NEW; the
//! native group vif (DEV_INFO then BSS on the reserved vif, group peer WCID)
//! opens on the first join under the parent's control mutex. DEL withdraws
//! the netdev at once and the parent's worker retires the native owner in
//! order (`disassociate_boot_group`, then `stop_boot_group_link`) before the
//! vif slot is reused. A reset/recovery that already retired the native
//! group owner is observed as a stale link (`Bounds`/`DeviceGone`).
use super::*;
use crate::mt7921::firmware_transport::{self as transport, State};
use crate::mt7921::vif_slots::{Allocation, Link};
use alloc::sync::Weak;
use core::sync::atomic::AtomicU8;

/// Published netdev; the native group vif may or may not be open.
const LIVE: u8 = 0;
/// Netdev withdrawn; native retirement pending in the parent worker.
const REMOVING: u8 = 1;
/// Native owner and vif slot retired.
const GONE: u8 = 2;

static NEXT_COOKIE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub(crate) struct P2pGroupIface {
    name: String,
    mac: [u8; 6],
    cookie: u64,
    parent: Weak<Mt76Iface>,
    physical: u64,
    allocation: Allocation,
    phase: AtomicU8,
    /// The native group link once DEV_INFO/BSS were acknowledged.
    link: IrqSafeSpinLock<Option<Link>>,
    associated_bssid: IrqSafeSpinLock<Option<[u8; 6]>>,
    teardown_needed: AtomicBool,
    receive_epoch: AtomicU64,
    rx_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
    rx_prod: IrqSafeSpinLock<Option<Producer<Frame, RX_RING_N>>>,
    tx_cons: IrqSafeSpinLock<Option<Consumer<Frame, TX_RING_N>>>,
    pending_tx: IrqSafeSpinLock<Option<Frame>>,
}

impl Mt76Iface {
    /// Legacy synchronous NEW for a P2P-client group netdev. One group link
    /// at a time, only beside a home station role (`if_comb_chanctx_base`
    /// admits two STATION|P2P_CLIENT; NARF keeps them on one channel).
    pub(super) fn new_p2p_group(
        &self,
        name: &str,
        iftype: u32,
        mac: Option<[u8; 6]>,
    ) -> Result<Arc<P2pGroupIface>, WirelessError> {
        if iftype != 8 {
            return Err(WirelessError::NotSupported);
        }
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
        // mt792x_config_mac_addr_list: a default address distinct from the
        // physical and P2P-device addresses.
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
        let group = Arc::new(P2pGroupIface {
            name: name.into(),
            mac,
            cookie: NEXT_COOKIE.fetch_add(1, Ordering::Relaxed),
            parent: Arc::downgrade(&parent),
            physical: self.wiphy_id(),
            allocation,
            phase: AtomicU8::new(LIVE),
            link: IrqSafeSpinLock::new(None),
            associated_bssid: IrqSafeSpinLock::new(None),
            teardown_needed: AtomicBool::new(false),
            receive_epoch: AtomicU64::new(0),
            rx_ring: IrqSafeSpinLock::new(None),
            tx_ring: IrqSafeSpinLock::new(None),
            rx_prod: IrqSafeSpinLock::new(None),
            tx_cons: IrqSafeSpinLock::new(None),
            pending_tx: IrqSafeSpinLock::new(None),
        });
        if let Err(error) = narf_net::registry().register(&authority, Registered(group.clone())) {
            self.vif_slots.lock().release_retired(allocation);
            return Err(match error {
                narf_net::RegisterError::DuplicateName => WirelessError::Busy,
                narf_net::RegisterError::AuthorityRevoked => WirelessError::Denied,
            });
        }
        narf_net::iface::register_with_context(name, mac, group.cookie, send_group);
        publish_link(name, false);
        *self.p2p_group.lock() = Some(group.clone());
        narf_wireless::registry::register(group.clone());
        Ok(group)
    }

    /// Parent removal (`ieee80211_remove_interfaces`): withdraw the group
    /// netdev. Native resources end with the radio generation.
    pub(super) fn withdraw_p2p_group(&self) {
        let group = { self.p2p_group.lock().take() };
        if let Some(group) = group {
            group.unpublish();
            group.phase.store(GONE, Ordering::Release);
            *group.link.lock() = None;
            self.vif_slots.lock().release_retired(group.allocation);
        }
    }

    /// One worker turn for the group netdev: ordered native retirement after
    /// DEL, deferred teardown after a lost link, then one data step.
    pub(crate) async fn poll_p2p_group(&self) {
        let group = { self.p2p_group.lock().clone() };
        let Some(group) = group else {
            return;
        };
        if group.phase.load(Ordering::Acquire) == REMOVING {
            let Some(_control) = self.control.try_lock() else {
                return;
            };
            if group.retire_native().await.is_ok() {
                group.phase.store(GONE, Ordering::Release);
                self.vif_slots.lock().release_retired(group.allocation);
                let mut slot = self.p2p_group.lock();
                if slot.as_ref().is_some_and(|g| Arc::ptr_eq(g, &group)) {
                    *slot = None;
                }
            }
            return;
        }
        if group.teardown_needed.load(Ordering::Acquire) {
            let Some(_control) = self.control.try_lock() else {
                return;
            };
            let _ = group.finish_teardown().await;
            return;
        }
        let _ = group.drain_network();
    }
}

impl P2pGroupIface {
    /// The parent while this exact group netdev is its published child.
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
                .p2p_group
                .lock()
                .as_ref()
                .is_some_and(|group| core::ptr::eq(group.as_ref(), self))
        };
        let slot = { parent.vif_slots.lock().current(self.allocation) };
        if !physical || !child || !slot || self.phase.load(Ordering::Acquire) != LIVE {
            return Err(WirelessError::Denied);
        }
        Ok(parent)
    }

    fn unpublish(&self) {
        self.clear_link();
        narf_wireless::registry::unregister(&self.name);
        narf_net::registry().unregister(&self.name);
        narf_net::iface::unregister(&self.name);
    }

    fn clear_link(&self) {
        let was_up = self.associated_bssid.lock().take().is_some();
        self.receive_epoch.store(0, Ordering::Release);
        *self.pending_tx.lock() = None;
        *self.tx_ring.lock() = None;
        *self.rx_ring.lock() = None;
        *self.tx_cons.lock() = None;
        *self.rx_prod.lock() = None;
        if was_up {
            publish_link(&self.name, false);
        }
    }

    /// A failed data step: close carrier now, leave natively from the
    /// worker under the control mutex (the home `lose_link` analogue).
    fn lose_link(&self) {
        let connected = self.associated_bssid.lock().is_some();
        if connected {
            self.teardown_needed.store(true, Ordering::Release);
        }
        self.clear_link();
        if connected {
            narf_wireless::nl80211::notify_disconnect(&self.name, 1, false);
        }
    }

    /// Requires the parent's control mutex.
    async fn finish_teardown(&self) -> Result<(), WirelessError> {
        if !self.teardown_needed.load(Ordering::Acquire) {
            return Ok(());
        }
        let link = { *self.link.lock() };
        let Some(link) = link else {
            self.teardown_needed.store(false, Ordering::Release);
            return Ok(());
        };
        match transport::disassociate_boot_group(link).await {
            // A stale link: reset/recovery already retired the group owner.
            Ok(()) | Err(transport::Error::Bounds | transport::Error::DeviceGone) => {
                self.teardown_needed.store(false, Ordering::Release);
                Ok(())
            }
            Err(error) => Err(map_error(error)),
        }
    }

    /// Ordered native retirement after DEL (`mt7921_remove_interface`):
    /// leave an association, then BSS and DEV_INFO disable and WCID free.
    /// A failed group role stays retained until verified recovery.
    async fn retire_native(&self) -> Result<(), WirelessError> {
        let link = { *self.link.lock() };
        let Some(link) = link else {
            return Ok(());
        };
        if let Some((current, state)) = transport::boot_group_link() {
            if current == link {
                match state {
                    State::Associated { .. } => {
                        match transport::disassociate_boot_group(link).await {
                            Ok(()) => {}
                            Err(transport::Error::Bounds | transport::Error::DeviceGone) => {
                                *self.link.lock() = None;
                                return Ok(());
                            }
                            Err(error) => return Err(map_error(error)),
                        }
                    }
                    State::Failed { .. } | State::Running(_) => {
                        return Err(WirelessError::Busy);
                    }
                    _ => {}
                }
            }
        }
        match transport::stop_boot_group_link(link).await {
            Ok(()) | Err(transport::Error::Bounds | transport::Error::DeviceGone) => {
                *self.link.lock() = None;
                Ok(())
            }
            Err(error) => Err(map_error(error)),
        }
    }

    /// Open the native group vif on first use (`mt7921_add_interface`).
    /// Requires the parent's control mutex.
    async fn ensure_native(&self) -> Result<Link, WirelessError> {
        if let Some(link) = *self.link.lock() {
            return Ok(link);
        }
        let link = transport::start_boot_group_link(self.allocation.vif(), self.mac)
            .await
            .map_err(map_error)?;
        *self.link.lock() = Some(link);
        Ok(link)
    }

    fn link_up(&self) -> bool {
        self.associated_bssid.lock().is_some()
    }

    fn next_tx(&self) -> Option<Frame> {
        let mut slot = self.tx_cons.lock();
        let consumer = slot.as_mut()?;
        for _ in 0..16 {
            let frame = consumer.try_recv().ok().flatten()?;
            if transmit_admitted(frame.payload(), self.mac) {
                return Some(frame);
            }
        }
        None
    }

    fn receive_current(&self, link: Link, epoch: u64) -> Result<bool, WirelessError> {
        if !self.link_up() || self.phase.load(Ordering::Acquire) != LIVE {
            return Ok(false);
        }
        transport::boot_group_receive_current(link, epoch).map_err(|_| {
            self.lose_link();
            WirelessError::HardwareError
        })
    }

    /// A new receive owner epoch retires frames queued for an older one.
    fn ensure_receive_epoch(&self, epoch: u64) {
        if self.receive_epoch.load(Ordering::Acquire) != epoch {
            let (producer, consumer) = narf_ipc::channel::<Frame, RX_RING_N>();
            *self.rx_ring.lock() = Some(consumer);
            *self.rx_prod.lock() = Some(producer);
            self.receive_epoch.store(epoch, Ordering::Release);
        }
    }

    /// One bounded group data step (`step_boot_group_network`). Each copy is
    /// published only while `boot_group_receive_current` still holds for
    /// the epoch that produced the batch.
    fn drain_network(&self) -> Result<bool, WirelessError> {
        if !self.link_up() || self.phase.load(Ordering::Acquire) != LIVE {
            return Ok(false);
        }
        let link = { *self.link.lock() };
        let Some(link) = link else {
            return Ok(false);
        };
        let result = {
            let mut pending = self.pending_tx.lock();
            if pending.is_none() {
                *pending = self.next_tx();
            }
            let result =
                transport::step_boot_group_network(link, pending.as_ref().map(Frame::payload));
            if result.as_ref().is_ok_and(|step| step.transmitted) {
                *pending = None;
            }
            result
        };
        let step = match result {
            Ok(step) => step,
            Err(transport::Error::Busy) => return Ok(false),
            Err(_) => {
                self.lose_link();
                return Err(WirelessError::HardwareError);
            }
        };
        let progress = step.transmitted || !step.received.is_empty();
        deliver_received_batch(
            step,
            |epoch| self.receive_current(link, epoch),
            |data| narf_net::iface::on_rx_frame_from(&self.name, data),
            |data, epoch| {
                let Ok(mut buffer) =
                    narf_io::alloc_coherent(data.len(), narf_lib::id::DomainId::DRIVER_0)
                else {
                    return Ok(());
                };
                buffer.as_mut_slice()[..data.len()].copy_from_slice(&data);
                let frame = Frame::new(buffer, data.len() as u32);
                if self.receive_current(link, epoch)? {
                    self.ensure_receive_epoch(epoch);
                    if let Some(producer) = self.rx_prod.lock().as_mut() {
                        let _ = producer.try_send(frame);
                    }
                }
                Ok(())
            },
        )?;
        Ok(progress)
    }

    fn enqueue(&self, bytes: &[u8]) -> Result<(), ()> {
        if !transmit_admitted(bytes, self.mac)
            || !self.link_up()
            || self.phase.load(Ordering::Acquire) != LIVE
        {
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
}

fn send_group(cookie: u64, bytes: &[u8], _: narf_net::TxMeta) -> Result<(), ()> {
    let parent = ACTIVE.lock().clone().ok_or(())?;
    let group = parent
        .p2p_group
        .lock()
        .as_ref()
        .filter(|group| group.cookie == cookie)
        .cloned()
        .ok_or(())?;
    group.enqueue(bytes)
}

fn map_error(error: transport::Error) -> WirelessError {
    use transport::Error;
    match error {
        Error::Bounds => WirelessError::InvalidArgs,
        Error::Busy => WirelessError::Busy,
        Error::Timeout => WirelessError::Timeout,
        Error::Authority | Error::DeviceGone => WirelessError::Denied,
        _ => WirelessError::HardwareError,
    }
}

impl Interface for P2pGroupIface {
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
        P2pGroupIface::link_up(self)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx_ring
    }
}

struct Registered(Arc<P2pGroupIface>);
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
        self.0.link_up()
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.0.rx_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.0.tx_ring
    }
}

#[async_trait]
impl WirelessNetIface for P2pGroupIface {
    fn wiphy_id(&self) -> u64 {
        self.physical
    }
    fn current_iftype(&self) -> u32 {
        8
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
        info.modes = WirelessModes::STATION;
        info
    }
    fn phy_capabilities(&self, band_mhz: u32) -> Option<narf_wireless::iface::PhyCapabilities> {
        self.parent.upgrade()?.phy_capabilities(band_mhz)
    }
    fn max_scan_ssids(&self) -> u8 {
        4
    }
    fn max_scan_ie_len(&self) -> u16 {
        transport::MAX_SCAN_IE_LEN
    }
    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.parent.upgrade()?.scan_information_elements(bssid)
    }
    fn connected_bssid(&self) -> Option<[u8; 6]> {
        *self.associated_bssid.lock()
    }
    fn supports_handshake_offload(&self) -> bool {
        true
    }
    /// DEL (`ieee80211_if_remove`): the netdev disappears now; the parent
    /// worker retires the native owner before the vif slot is reused.
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
    /// The radio scans once for every station owner: one scan engine, one
    /// result cache (`mt76_connac_mcu_hw_scan` on the scanning vif).
    async fn scan(&self, request: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        let parent = self.current()?;
        parent.scan(request).await
    }
    async fn associate(&self, mut request: AssociateRequest) -> Result<(), WirelessError> {
        let parent = self.current()?;
        let six = parent.validate_join(&request)?;
        // The group link never takes a 6 GHz grant: the CLC power type is
        // device-wide (`mt7921_regd_set_6ghz_power_type`).
        if six {
            return Err(WirelessError::NotSupported);
        }
        let _control = parent.control.lock().await;
        self.current()?;
        if !parent.station_role() || parent.sleeping.load(Ordering::Acquire) {
            return Err(WirelessError::Busy);
        }
        self.finish_teardown().await?;
        if self.link_up() {
            return Err(WirelessError::Busy);
        }
        let security =
            core::mem::replace(&mut request.security, narf_wireless::SecurityConfig::Open);
        // A P2P client never follows its GO onto a radar/NO_IR channel.
        let (bss, security, _) = parent.resolve_join(&request, security, six, false)?;
        let link = self.ensure_native().await?;
        transport::associate_boot_group(link, &bss, &request.ssid, security, &request.ie, true)
            .await
            .map_err(map_error)?;
        if self.current().is_err() {
            // DEL raced the join: the worker leaves and retires natively.
            return Err(WirelessError::Denied);
        }
        let (tx_prod, tx_cons) = narf_ipc::channel::<Frame, TX_RING_N>();
        let (rx_prod, rx_cons) = narf_ipc::channel::<Frame, RX_RING_N>();
        *self.tx_ring.lock() = Some(tx_prod);
        *self.rx_ring.lock() = Some(rx_cons);
        *self.tx_cons.lock() = Some(tx_cons);
        *self.rx_prod.lock() = Some(rx_prod);
        self.receive_epoch.store(0, Ordering::Release);
        *self.associated_bssid.lock() = Some(request.bssid);
        publish_link(&self.name, true);
        Ok(())
    }
    async fn disassociate(&self) -> Result<(), WirelessError> {
        let parent = self.current()?;
        let _control = parent.control.lock().await;
        self.finish_teardown().await?;
        if !self.link_up() {
            return Ok(());
        }
        self.teardown_needed.store(true, Ordering::Release);
        self.clear_link();
        self.finish_teardown().await
    }
    async fn set_config(&self, _: WirelessConfig) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
}
