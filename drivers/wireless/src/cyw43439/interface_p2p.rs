// SPDX-License-Identifier: GPL-2.0-or-later
//! Control-only Fullmac P2P_DEVICE WDEV (Linux `p2p.c`
//! `brcmf_p2p_add_vif` / `brcmf_p2p_create_p2pdev` /
//! `brcmf_p2p_start_device` / `brcmf_p2p_stop_device` /
//! `brcmf_p2p_remain_on_channel` / `brcmf_p2p_del_vif`, `cfg80211.c`
//! `brcmf_cfg80211_mgmt_tx` / `brcmf_cfg80211_update_mgmt_frame_registrations`).
//!
//! A [`P2pWdev`] has no Ethernet entry, IFINDEX, UP state or frame rings.
//! Linux creates the discovery bsscfg inside `add_virtual_intf`, so the
//! native `vif_owner::create_p2p_device` runs before the WDEV metadata is
//! published, and `DEL_INTERFACE` removes it (`brcmf_p2p_del_vif`) before
//! the typed retirement receipt. The discovery owner
//! (`brcmfmac::p2p::Device`) lives in the primary's `State`, so every
//! firmware command is serialized with the primary's station, AP and
//! secondary-interface work; the primary worker drains its events and hands
//! the resulting notices here.
//!
//! Events: `NL80211_CMD_REMAIN_ON_CHANNEL` readiness is reported right after
//! the firmware accepted the LISTEN state (Linux reports
//! `cfg80211_ready_on_channel` after `brcmf_p2p_discover_listen` returns),
//! and its expiry on `BRCMF_E_P2P_DISC_LISTEN_COMPLETE` or cancel, each to
//! the exact ROC source. Received action frames and P2P probe requests go
//! to the matching registered management-frame source
//! (`cfg80211_rx_mgmt`), only while the device is started.
use super::super::{wireless_error, Device, Fullmac, State};
use super::{primary, Roles};
use crate::brcmfmac::{p2p::Notice, p2p_wire, vif_owner::Owner};
use crate::cyw43439::{fullmac::Family, ioctl::Direction, runtime::Error};
use alloc::{
    boxed::Box,
    string::String,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::num::NonZeroU64;
use narf_capabilities::{Cap, Write};
use narf_ipc::{Consumer, Producer};
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};
use narf_wireless::{
    ap_control::{
        ApControlReservation, RadioControlAuthority, RadioControlRetirement, RadioEventAuthority,
        RadioInterfaceIdentity,
    },
    AssociateRequest, BssInfo, MgmtTxRequest, ScanRequest, WirelessConfig, WirelessError,
    WirelessIfaceInfo, WirelessNetIface,
};

/// Whether the P2P_DEVICE WDEV and the P2P_CLIENT/GO netdevs are offered
/// through nl80211 (still only when the booted firmware's `cap` has `p2p`,
/// `brcmf_setup_ifmodes`; `drivers/wireless/specification/brcmfmac.md`).
pub(in crate::cyw43439) const P2P_ADVERTISED: bool = true;
/// `wiphy->max_remain_on_channel_duration` (`brcmf_setup_wiphy`).
const MAX_ROC_MS: u32 = 5000;
/// `BRCMF_C_GET_CHANNEL`.
const GET_CHANNEL: u32 = 29;
/// `IEEE80211_STYPE_ACTION` / `IEEE80211_STYPE_PROBE_REQ`: the RX subtypes
/// of `brcmf_txrx_stypes[NL80211_IFTYPE_P2P_DEVICE]`.
const STYPE_ACTION: u16 = 0x00d0;
const STYPE_PROBE_REQ: u16 = 0x0040;
/// Bound of retained management-frame registrations.
const MAX_FILTERS: usize = 16;
const EPERM: i32 = 1;
const ENOSPC: i32 = 28;
const EINVAL: i32 = 22;
const EALREADY: i32 = 114;

/// The published WDEV of each family (one primary per family).
static WDEVS: IrqSafeSpinLock<Vec<Arc<P2pWdev>>> = IrqSafeSpinLock::new(Vec::new());

/// One discovery-owner operation under the primary state mutex.
pub(in crate::cyw43439) enum Operation {
    /// `brcmf_p2p_create_p2pdev` with the P2P Device Address.
    Create([u8; 6]),
    /// `brcmf_p2p_del_vif` for the device.
    Delete,
    Start,
    Stop,
    Listen {
        cookie: u64,
        frequency_mhz: u32,
        duration_ms: u32,
    },
    CancelListen,
    /// `brcmf_cfg80211_mgmt_tx` action branch.
    Action {
        frame: Vec<u8>,
        frequency_mhz: u32,
        wait_ms: u32,
        cookie: u64,
    },
    /// `brcmf_cfg80211_mgmt_tx` probe-response branch: the frame's
    /// vendor IEs become the discovery vif's PRBRSP `vndr_ie` set.
    ProbeResponse(Vec<u8>),
    /// `vif->mgmt_rx_reg` action / probe-request bits.
    Registrations {
        action: bool,
        probe_req: bool,
    },
}

/// Result of one [`Operation`]: the action-frame ACK and every notice the
/// discovery owner queued meanwhile.
#[derive(Default)]
pub(in crate::cyw43439) struct Outcome {
    acked: bool,
    notices: Vec<Notice>,
}

impl<R: Fullmac + 'static> Device<R> {
    /// The booted firmware has `p2p` and a secondary-interface owner, and
    /// the WDEV is offered.
    pub(in crate::cyw43439) fn p2p_device_enabled(&self) -> bool {
        P2P_ADVERTISED
            && R::VIF_DEMUX
            && self
                .lifecycle
                .p2p
                .load(core::sync::atomic::Ordering::Acquire)
    }

    pub(super) async fn p2p_device_operation(
        &self,
        operation: Operation,
    ) -> Result<Outcome, WirelessError> {
        let mut state = self.state.lock().await;
        if self.withdrawn() {
            return Err(WirelessError::HardwareError);
        }
        let State {
            station, vif, p2p, ..
        } = &mut *state;
        let owner = vif.as_mut().ok_or(WirelessError::NotSupported)?;
        let runtime = &mut station.runtime;
        let mut outcome = Outcome::default();
        match operation {
            Operation::Create(address) => {
                if p2p.is_some() {
                    // `-ENOSPC`: one discovery vif per wiphy.
                    return Err(WirelessError::Busy);
                }
                let entry = owner
                    .create_p2p_device(runtime, address)
                    .await
                    .map_err(wireless_error)?;
                *p2p = Some(crate::brcmfmac::p2p::Device::new(entry));
            }
            Operation::Delete => {
                // A device already removed (an earlier DEL whose IF DEL
                // wait failed still dropped the host entry) is retired.
                if let Some(device) = p2p.take() {
                    outcome.notices = device
                        .delete(runtime, owner)
                        .await
                        .map_err(wireless_error)?;
                }
                return Ok(outcome);
            }
            Operation::Start => {
                let device = p2p.as_mut().ok_or(WirelessError::NotSupported)?;
                device.start(runtime).await.map_err(wireless_error)?;
            }
            Operation::Stop => {
                let device = p2p.as_mut().ok_or(WirelessError::NotSupported)?;
                device.stop(runtime).await.map_err(wireless_error)?;
                // The SCAN state ends a listen in firmware without a
                // LISTEN_COMPLETE; report its expiry rather than orphan
                // the ROC cookie (Linux leaves it to cfg80211 teardown).
                if device.listening().is_some() {
                    device
                        .cancel_remain_on_channel(runtime)
                        .await
                        .map_err(wireless_error)?;
                }
            }
            Operation::Listen {
                cookie,
                frequency_mhz,
                duration_ms,
            } => {
                let device = p2p.as_mut().ok_or(WirelessError::NotSupported)?;
                if !device.ready() {
                    return Err(WirelessError::Busy);
                }
                device
                    .remain_on_channel(runtime, cookie, frequency_mhz, duration_ms)
                    .await
                    .map_err(wireless_error)?;
            }
            Operation::CancelListen => {
                let device = p2p.as_mut().ok_or(WirelessError::NotSupported)?;
                device
                    .cancel_remain_on_channel(runtime)
                    .await
                    .map_err(wireless_error)?;
            }
            Operation::Action {
                frame,
                frequency_mhz,
                wait_ms,
                cookie,
            } => {
                let device = p2p.as_mut().ok_or(WirelessError::NotSupported)?;
                if !device.ready() {
                    return Err(WirelessError::Busy);
                }
                let channel = if frequency_mhz != 0 {
                    u32::from(
                        p2p_wire::frequency_channel(frequency_mhz)
                            .ok_or(WirelessError::InvalidArgs)?,
                    )
                } else {
                    current_channel(runtime, device.entry().ifidx)
                        .await
                        .map_err(wireless_error)?
                };
                outcome.acked = device
                    .send_action_frame(runtime, owner, &frame, channel, wait_ms, cookie)
                    .await
                    .map_err(wireless_error)?;
            }
            Operation::ProbeResponse(ies) => {
                let device = p2p.as_mut().ok_or(WirelessError::NotSupported)?;
                device
                    .set_mgmt_ie(runtime, p2p_wire::VNDR_IE_PRBRSP_FLAG, &ies)
                    .await
                    .map_err(wireless_error)?;
                // `cfg80211_mgmt_tx_status(..., true)`: the firmware sends
                // its own probe responses carrying these IEs.
                outcome.acked = true;
            }
            Operation::Registrations { action, probe_req } => {
                let device = p2p.as_mut().ok_or(WirelessError::NotSupported)?;
                device.set_registrations(action, probe_req);
            }
        }
        if let Some(device) = p2p.as_mut() {
            while let Some(notice) = device.pop_notice() {
                outcome.notices.push(notice);
            }
        }
        Ok(outcome)
    }
}

/// `BRCMF_C_GET_CHANNEL` on the discovery interface (`hw_channel`, the
/// first word of `struct channel_info_le`).
async fn current_channel<R: Fullmac>(runtime: &mut R, ifidx: u8) -> Result<u32, Error> {
    let reply = runtime
        .command_vif(ifidx, Direction::Get, GET_CHANNEL, &[0; 12], 12)
        .await?;
    let word = reply.get(..4).ok_or(Error::Malformed)?;
    Ok(u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
}

/// One primary-worker pass of the discovery owner (its `fweh` handlers).
/// A full notice queue is a stalled consumer: the transport fail-stops, as
/// for every other bounded event queue of this owner.
pub(super) async fn service<R: Fullmac>(
    runtime: &mut R,
    owner: &mut Owner,
    device: &mut crate::brcmfmac::p2p::Device,
    notices: &mut Vec<Notice>,
) {
    while let Some(notice) = device.pop_notice() {
        notices.push(notice);
    }
    if let Err(Error::EventOverflow) = device.service(runtime, owner).await {
        runtime.fail();
    }
    while let Some(notice) = device.pop_notice() {
        notices.push(notice);
    }
}

/// Hand worker notices to the family's WDEV (outside every driver lock).
pub(super) fn deliver(family: Family, notices: Vec<Notice>) {
    if notices.is_empty() {
        return;
    }
    let wdev = WDEVS
        .lock()
        .iter()
        .find(|wdev| wdev.family == family)
        .cloned();
    if let Some(wdev) = wdev {
        for notice in notices {
            wdev.notice(notice);
        }
    }
}

/// `p2p->conn_int_addr` (`brcmf_p2p_generate_bss_mac`): derived from the
/// P2P Device Address of the family's WDEV, or, without one, from the
/// address `brcmf_p2p_create_p2pdev` would generate for the primary.
pub(super) fn connection_address(
    family: Family,
    primary: [u8; 6],
) -> Result<[u8; 6], WirelessError> {
    let device = WDEVS
        .lock()
        .iter()
        .find(|wdev| wdev.family == family)
        .map(|wdev| wdev.mac);
    let mut random = [0; 6];
    if device.is_none() && primary[0] & 0x02 != 0 {
        narf_crypto::try_fill_random_bytes(&mut random)
            .map_err(|_| WirelessError::HardwareError)?;
    }
    Ok(p2p_wire::generate_bss_mac(primary, device, random).connection)
}

/// The primary's generation ended (`brcmf_detach`): its native discovery
/// bsscfg ended with it, so only the host metadata is withdrawn.
pub(super) fn withdraw_family(family: Family) {
    let retired: Vec<Arc<P2pWdev>> = {
        let mut wdevs = WDEVS.lock();
        let (retired, kept): (Vec<_>, Vec<_>) = core::mem::take(&mut *wdevs)
            .into_iter()
            .partition(|wdev| wdev.family == family);
        *wdevs = kept;
        retired
    };
    for wdev in retired {
        wdev.withdraw();
    }
}

/// `brcmf_cfg80211_add_iface` for `NL80211_IFTYPE_P2P_DEVICE`: the native
/// discovery bsscfg first (`brcmf_p2p_create_p2pdev`), then the WDEV
/// metadata under the actual parent registration and the creating source.
pub(in crate::cyw43439) async fn create<R: Fullmac + 'static>(
    device: &Device<R>,
    authority: &RadioControlAuthority,
    name: &str,
    mac: Option<[u8; 6]>,
) -> Result<Arc<dyn WirelessNetIface>, WirelessError> {
    authority.check_for(device)?;
    if !authority.has_reservation() {
        return Err(WirelessError::Denied);
    }
    if name.is_empty() || name.len() > 15 || name.as_bytes().contains(&0) {
        return Err(WirelessError::InvalidArgs);
    }
    if mac.is_some_and(|mac| mac == [0; 6] || mac[0] & 1 != 0 || mac == device.mac) {
        return Err(WirelessError::InvalidArgs);
    }
    let this = core::ptr::from_ref(device).cast::<()>() as usize;
    let parent: Arc<dyn WirelessNetIface> = narf_wireless::registry::list()
        .into_iter()
        .find(|iface| Arc::as_ptr(iface).cast::<()>() as usize == this)
        .ok_or(WirelessError::Denied)?;
    let roles = primary(device.wiphy_id())
        .filter(|roles| Arc::as_ptr(roles).cast::<()>() as usize == this)
        .ok_or(WirelessError::Denied)?;
    let metadata = narf_net::iface::lookup(device.name()).ok_or(WirelessError::Denied)?;
    if metadata.ownership_epoch == 0 {
        return Err(WirelessError::Denied);
    }
    let parent_cap = (*device.lifecycle.registration.lock()).ok_or(WirelessError::Denied)?;
    let grant = narf_net::trusted_net_authority().ok_or(WirelessError::Denied)?;
    if WDEVS.lock().iter().any(|wdev| wdev.family == R::FAMILY) {
        return Err(WirelessError::Busy);
    }
    // brcmf_p2p_generate_bss_mac: the requested address, else the primary
    // with the locally administered bit, else (an already locally
    // administered primary) a random one.
    let mut random = [0; 6];
    if mac.is_none() && device.mac[0] & 0x02 != 0 {
        narf_crypto::try_fill_random_bytes(&mut random)
            .map_err(|_| WirelessError::HardwareError)?;
    }
    let address = p2p_wire::generate_bss_mac(device.mac, mac, random).device;
    device
        .p2p_device_operation(Operation::Create(address))
        .await?;
    let mut info = device.get_wireless_info();
    info.base_name = name.into();
    info.base_mac = address;
    info.modes = narf_wireless::iface::WirelessModes::empty();
    let wdev = Arc::new(P2pWdev {
        name: name.into(),
        family: R::FAMILY,
        namespace: metadata.net_ns_id,
        mac: address,
        wiphy: device.wiphy_id(),
        primary_name: device.name().into(),
        parent_epoch: metadata.ownership_epoch,
        parent: Arc::downgrade(&roles),
        info,
        registration: IrqSafeSpinLock::new(None),
        started: IrqSafeSpinLock::new(None),
        listens: IrqSafeSpinLock::new(Vec::new()),
        filters: IrqSafeSpinLock::new(Vec::new()),
        rx: IrqSafeSpinLock::new(None),
        tx: IrqSafeSpinLock::new(None),
    });
    let published = wdev.publish(authority, &parent, &grant, &parent_cap);
    if let Err(error) = published {
        // Unpublished: the native discovery bsscfg goes again.
        let _ = device.p2p_device_operation(Operation::Delete).await;
        return Err(error);
    }
    Ok(wdev)
}

#[derive(Clone, Copy, Debug)]
struct Registration {
    net: Cap<narf_net::NetIface, Write>,
    wdev: narf_wireless::registry::ControlWdev,
}

/// One reported listen and its exact ROC source.
#[derive(Clone, Debug)]
struct Listen {
    cookie: u64,
    frequency_mhz: u32,
    duration_ms: u32,
    source: RadioEventAuthority,
}

/// One `NL80211_CMD_REGISTER_FRAME` subscription.
#[derive(Clone, Debug)]
struct Filter {
    frame_type: u16,
    prefix: Vec<u8>,
    source: RadioEventAuthority,
}

/// The control-only P2P_DEVICE WDEV of one Fullmac primary.
pub struct P2pWdev {
    name: String,
    family: Family,
    namespace: u64,
    /// The P2P Device Address (`p2p_da_override`).
    mac: [u8; 6],
    wiphy: u64,
    primary_name: String,
    parent_epoch: u64,
    parent: Weak<dyn Roles>,
    info: WirelessIfaceInfo,
    registration: IrqSafeSpinLock<Option<Registration>>,
    /// `BRCMF_VIF_STATUS_READY` with the START request's identity.
    started: IrqSafeSpinLock<Option<RadioInterfaceIdentity>>,
    listens: IrqSafeSpinLock<Vec<Listen>>,
    filters: IrqSafeSpinLock<Vec<Filter>>,
    rx: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}

impl core::fmt::Debug for P2pWdev {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FullmacP2pDevice")
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
            .map_err(|error| match error {
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
        WDEVS.lock().push(self.clone());
        let published = (|| {
            authority.check_for(parent.as_ref())?;
            self.current()?;
            authority.retain_control_child(&iface, &net)
        })();
        if published.is_err() {
            self.withdraw();
        }
        published
    }

    /// The parent, its netdev ownership/namespace and this exact
    /// registration are all current.
    fn current(&self) -> Result<Arc<dyn Roles>, WirelessError> {
        let parent = self.parent.upgrade().ok_or(WirelessError::Denied)?;
        let registered = { *self.registration.lock() };
        let listed = WDEVS
            .lock()
            .iter()
            .any(|wdev| core::ptr::eq(Arc::as_ptr(wdev), self));
        if !parent.p2p_parent_live()
            || !listed
            || narf_net::iface::lookup(&self.primary_name).is_none_or(|metadata| {
                metadata.ownership_epoch != self.parent_epoch
                    || metadata.net_ns_id != self.namespace
            })
            || !registered.is_some_and(|registration| {
                registration.net.invoke(Observed).is_ok() && registration.wdev.current_for(self)
            })
        {
            return Err(WirelessError::Denied);
        }
        Ok(parent)
    }

    fn request_current(
        &self,
        authority: &RadioControlAuthority,
    ) -> Result<Arc<dyn Roles>, WirelessError> {
        let parent = self.current()?;
        authority.check_for(self)?;
        authority.require_mode(10)?;
        Ok(parent)
    }

    fn started(&self) -> bool {
        let identity = { self.started.lock().clone() };
        self.current().is_ok() && identity.is_some_and(|identity| identity.check_for(self).is_ok())
    }

    /// Software-only exact-registration cleanup.
    fn withdraw(&self) {
        let registration = { self.registration.lock().take() };
        if let Some(registration) = registration {
            narf_wireless::registry::unregister_control(registration.wdev, self);
            narf_net::registry().unregister_for_handle(&registration.net);
        }
        WDEVS
            .lock()
            .retain(|wdev| !core::ptr::eq(Arc::as_ptr(wdev), self));
        let started = { self.started.lock().take() };
        let listens = core::mem::take(&mut *self.listens.lock());
        let filters = core::mem::take(&mut *self.filters.lock());
        // Source destructors never run under a driver lock.
        drop((started, listens, filters));
    }

    /// Report notices queued by an operation the caller ran.
    fn notices(&self, notices: Vec<Notice>) {
        for notice in notices {
            self.notice(notice);
        }
    }

    fn notice(&self, notice: Notice) {
        match notice {
            Notice::RocExpired { cookie, .. } => {
                let listen = {
                    let mut listens = self.listens.lock();
                    listens
                        .iter()
                        .position(|listen| listen.cookie == cookie)
                        .map(|index| listens.remove(index))
                };
                if let Some(listen) = listen {
                    let _ = listen.source.roc_expired(
                        listen.cookie,
                        listen.frequency_mhz,
                        listen.duration_ms,
                    );
                }
            }
            Notice::Rx {
                frequency_mhz,
                frame,
            } => {
                if !self.started() || frame.len() < p2p_wire::MGMT_HDR_LEN {
                    return;
                }
                let frame_type = u16::from(frame[0] & 0xfc);
                let body = &frame[p2p_wire::MGMT_HDR_LEN..];
                let receiver = {
                    self.filters
                        .lock()
                        .iter()
                        .find(|filter| {
                            filter.frame_type == frame_type && body.starts_with(&filter.prefix)
                        })
                        .map(|filter| filter.source.clone())
                };
                if let Some(source) = receiver {
                    if source.registration_current().is_ok() {
                        let _ = source.management_received(frequency_mhz, None, &frame);
                    }
                }
            }
        }
    }

    /// `brcmf_cfg80211_update_mgmt_frame_registrations`: the union of the
    /// current subscriptions is the discovery vif's `mgmt_rx_reg`.
    async fn sync_registrations(&self, parent: &Arc<dyn Roles>) -> Result<(), WirelessError> {
        let (action, probe_req) = {
            let mut filters = self.filters.lock();
            filters.retain(|filter| filter.source.registration_current().is_ok());
            (
                filters
                    .iter()
                    .any(|filter| filter.frame_type == STYPE_ACTION),
                filters
                    .iter()
                    .any(|filter| filter.frame_type == STYPE_PROBE_REQ),
            )
        };
        parent
            .p2p_device(Operation::Registrations { action, probe_req })
            .await
            .map(|_| ())
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
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
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
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        self.0.rx_ring()
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        self.0.tx_ring()
    }
}

#[async_trait::async_trait]
impl WirelessNetIface for P2pWdev {
    fn wiphy_id(&self) -> u64 {
        self.wiphy
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
    fn reserve_radio_control(
        &self,
    ) -> Result<Option<Arc<dyn ApControlReservation>>, WirelessError> {
        self.current()?.p2p_reserve()
    }
    fn async_control_interfaces(&self) -> bool {
        true
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
        true
    }
    /// `WIPHY_FLAG_OFFCHAN_TX` (`brcmf_setup_wiphy`).
    fn supports_offchannel_mgmt_tx(&self) -> bool {
        true
    }
    fn max_remain_on_channel_duration_ms(&self) -> u32 {
        MAX_ROC_MS
    }
    fn p2p_interface_types(&self) -> Vec<u32> {
        alloc::vec![10]
    }
    /// `brcmf_p2p_start_device` (`brcmf_p2p_enable_discovery`, READY).
    async fn start_p2p_device_async(
        &self,
        authority: &RadioControlAuthority,
    ) -> Result<(), WirelessError> {
        let parent = self.request_current(authority)?;
        parent.p2p_device(Operation::Start).await?;
        let identity = authority.identity()?;
        identity.check_for(self)?;
        *self.started.lock() = Some(identity);
        Ok(())
    }
    /// `brcmf_p2p_stop_device` (discovery SCAN, READY cleared).
    async fn stop_p2p_device_async(
        &self,
        authority: &RadioControlAuthority,
    ) -> Result<(), WirelessError> {
        let parent = self.request_current(authority)?;
        let outcome = parent.p2p_device(Operation::Stop).await;
        let started = { self.started.lock().take() };
        drop(started);
        self.notices(outcome?.notices);
        Ok(())
    }
    /// `brcmf_p2p_remain_on_channel`: ready once the firmware accepted the
    /// LISTEN state; a listen still running is re-reported under the new
    /// cookie (Linux's cookie WAR), so it replaces the old record.
    async fn remain_on_channel_async(
        &self,
        authority: &RadioControlAuthority,
        cookie: u64,
        frequency_mhz: u32,
        duration_ms: u32,
    ) -> Result<(), WirelessError> {
        let parent = self.request_current(authority)?;
        if !self.started() {
            return Err(WirelessError::Busy);
        }
        if duration_ms == 0 || duration_ms > MAX_ROC_MS {
            return Err(WirelessError::InvalidArgs);
        }
        let source = authority.event_authority()?;
        let outcome = parent
            .p2p_device(Operation::Listen {
                cookie,
                frequency_mhz,
                duration_ms,
            })
            .await?;
        let replaced = {
            let mut listens = self.listens.lock();
            core::mem::replace(
                &mut *listens,
                alloc::vec![Listen {
                    cookie,
                    frequency_mhz,
                    duration_ms,
                    source: source.clone(),
                }],
            )
        };
        drop(replaced);
        source.roc_ready(cookie, frequency_mhz, duration_ms)?;
        self.notices(outcome.notices);
        Ok(())
    }
    /// `brcmf_p2p_cancel_remain_on_channel`.
    async fn cancel_remain_on_channel_async(
        &self,
        authority: &RadioControlAuthority,
        cookie: u64,
    ) -> Result<(), WirelessError> {
        let parent = self.request_current(authority)?;
        if !self
            .listens
            .lock()
            .iter()
            .any(|listen| listen.cookie == cookie)
        {
            return Err(WirelessError::InvalidArgs);
        }
        let outcome = parent.p2p_device(Operation::CancelListen).await?;
        self.notices(outcome.notices);
        Ok(())
    }
    /// `brcmf_cfg80211_mgmt_tx` on the P2P_DEVICE: action frames go
    /// through `brcmf_p2p_send_action_frame`; a probe response installs
    /// its vendor IEs as the discovery vif's PRBRSP set and reports ACK
    /// (Linux's probe-response branch); other subtypes are refused.
    async fn mgmt_tx_radio_async(
        &self,
        authority: &RadioControlAuthority,
        cookie: u64,
        request: MgmtTxRequest,
    ) -> Result<bool, WirelessError> {
        let parent = self.request_current(authority)?;
        if !self.started() {
            return Err(WirelessError::NotSupported);
        }
        if p2p_wire::is_probe_resp(&request.frame) {
            // `DOT11_MGMT_HDR_LEN + DOT11_BCN_PRB_FIXED_LEN`.
            let ies = request
                .frame
                .get(p2p_wire::MGMT_HDR_LEN + 12..)
                .ok_or(WirelessError::InvalidArgs)?
                .to_vec();
            let outcome = parent.p2p_device(Operation::ProbeResponse(ies)).await?;
            self.notices(outcome.notices);
            self.request_current(authority)?;
            return Ok(outcome.acked);
        }
        if !p2p_wire::is_action(&request.frame) {
            return Err(WirelessError::NotSupported);
        }
        if request.frame.len() > p2p_wire::ACTION_FRAME_SIZE + p2p_wire::MGMT_HDR_LEN {
            return Err(WirelessError::InvalidArgs);
        }
        let outcome = parent
            .p2p_device(Operation::Action {
                frame: request.frame,
                frequency_mhz: request.frequency_mhz,
                wait_ms: request.duration,
                cookie,
            })
            .await?;
        let acked = outcome.acked;
        self.notices(outcome.notices);
        self.request_current(authority)?;
        Ok(acked)
    }
    /// `NL80211_CMD_REGISTER_FRAME` on the WDEV: action and probe-request
    /// subtypes only (`brcmf_txrx_stypes`), no overlapping prefix per
    /// subtype (cfg80211 `-EALREADY`).
    async fn register_mgmt_frame_radio_async(
        &self,
        authority: &RadioControlAuthority,
        frame_type: u16,
        prefix: &[u8],
    ) -> Result<(), i32> {
        let parent = self.request_current(authority).map_err(|_| EPERM)?;
        if !matches!(frame_type, STYPE_ACTION | STYPE_PROBE_REQ) {
            return Err(EINVAL);
        }
        let source = authority.event_authority().map_err(|_| EPERM)?;
        let stale = {
            let mut filters = self.filters.lock();
            let (kept, stale): (Vec<Filter>, Vec<Filter>) = core::mem::take(&mut *filters)
                .into_iter()
                .partition(|filter| filter.source.registration_current().is_ok());
            *filters = kept;
            if filters
                .iter()
                .filter(|filter| filter.frame_type == frame_type)
                .any(|filter| {
                    let length = core::cmp::min(filter.prefix.len(), prefix.len());
                    filter.prefix[..length] == prefix[..length]
                })
            {
                return Err(EALREADY);
            }
            if filters.len() == MAX_FILTERS {
                return Err(ENOSPC);
            }
            filters.push(Filter {
                frame_type,
                prefix: prefix.to_vec(),
                source,
            });
            stale
        };
        drop(stale);
        self.sync_registrations(&parent).await.map_err(|_| EPERM)
    }
    fn release_control_metadata(&self) {
        self.withdraw();
    }
    /// `brcmf_p2p_del_vif` for the device: cancel the listen, deinit
    /// discovery, wait for the IF DEL; only then the retirement receipt.
    async fn delete_control_interface_async(
        &self,
        authority: &RadioControlAuthority,
    ) -> Result<RadioControlRetirement, WirelessError> {
        let parent = self.request_current(authority)?;
        let outcome = parent.p2p_device(Operation::Delete).await?;
        self.notices(outcome.notices);
        let started = { self.started.lock().take() };
        drop(started);
        let net = self
            .registration
            .lock()
            .as_ref()
            .map(|registration| registration.net)
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
