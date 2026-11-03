// SPDX-License-Identifier: GPL-2.0-or-later
//! Secondary Fullmac netdev owner (Linux `core.c` `brcmf_add_if` /
//! `brcmf_net_attach` / `brcmf_remove_interface`, `cfg80211.c`
//! `brcmf_apsta_add_vif` / `brcmf_cfg80211_del_apsta_iface`).
//!
//! A [`VifDevice`] is one additional firmware interface (ifidx 1..16) of a
//! booted SDIO-BCDC or PCIe-msgbuf owner. It is a host shell only: the
//! primary [`Device`]'s receive worker is the sole runtime user. Under the
//! primary state mutex it runs the `vif_owner::Owner` interface
//! create/remove commands, consumes `BRCMF_E_IF` (unsolicited DEL retires
//! the shell, `fweh` default `brcmf_remove_interface`), and pumps
//! `pop_vif_data`/`send_vif_data` for live shells whose carrier is up.
//!
//! Linux creates the firmware interface inside the synchronous cfg80211
//! `add_virtual_intf` (1500 ms wait) and registers the netdev afterwards.
//! nl80211 `NEW_INTERFACE` here is synchronous and may not wait on the bus,
//! so the shell is published first with its carrier down and the worker
//! issues the native create; the IF ADD address then replaces the
//! provisional MAC, and a refused or timed-out create unpublishes it.
//! `DEL_INTERFACE` hides the netdev at once (as for every other
//! hide-now/firmware-later vdev in this tree); the worker then issues
//! `interface_remove` and retires the ifidx's transport resources.
//!
//! A STA shell owns a persistent secondary [`Station`] ([`Secondary`]),
//! parked over `vif_bsscfg::Parked` and rebound to a
//! `vif_bsscfg::Bsscfg` for each scan/join/disconnect (under the primary
//! state mutex, through [`Roles`]) and for each worker pass (`poll`). Its
//! correlated `set_link` peer is the shell carrier. An AP shell has no
//! per-bsscfg AP owner yet and keeps refusing every role operation.

use super::{wireless_error, Device, Fullmac, State};
use crate::brcmfmac::{
    vif_bsscfg::{Bsscfg, Link, Parked},
    vif_owner::{Owner, Role},
    vif_wire::{self, Entry},
};
use crate::cyw43439::station::Station;
use crate::cyw43439::{fullmac::Family, ioctl::Direction, runtime::Error};
use alloc::{
    boxed::Box,
    string::String,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use narf_ipc::{Consumer, Producer};
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};
use narf_wireless::{
    AssociateRequest, BssInfo, ScanRequest, WirelessConfig, WirelessError, WirelessIfaceInfo,
    WirelessNetIface,
};

/// Bound of the `cap` reply (`brcmf_feat_firmware_capabilities`
/// `caps[MAX_CAPS_BUFFER_SIZE]`, 768 bytes).
const CAP_LEN: usize = 768;
/// Frames moved per shell per worker pass.
const PUMP_BUDGET: usize = 32;

/// Shell lifecycle (one transport generation).
const CREATING: u8 = 0;
const LIVE: u8 = 1;
/// Hidden by `DEL_INTERFACE`; the worker issues `interface_remove`.
const REMOVING: u8 = 2;
/// Hidden; the worker polls `vif_close` until the ifidx owns nothing.
const CLOSING: u8 = 3;
const GONE: u8 = 4;

/// Every published secondary shell, across both families.
static SHELLS: IrqSafeSpinLock<Vec<Arc<VifDevice>>> = IrqSafeSpinLock::new(Vec::new());
static NEXT_COOKIE: AtomicU64 = AtomicU64::new(1);

/// Persistent secondary station role of one live STA shell (`struct
/// brcmf_cfg80211_vif` of a `NL80211_IFTYPE_STATION` additional interface).
pub(super) struct Secondary<R: Fullmac> {
    cookie: u64,
    link: Link,
    /// `None` only while an operation holds it rebound, or after such an
    /// operation was cancelled mid-flight (the role is then retired).
    station: Option<Station<Parked<R>>>,
}

/// Type-erased primary role entry points for the non-generic shell.
#[async_trait::async_trait]
pub(super) trait Roles: Send + Sync {
    fn wiphy(&self) -> u64;
    async fn vif_scan(
        &self,
        cookie: u64,
        request: ScanRequest,
    ) -> Result<Vec<BssInfo>, WirelessError>;
    /// Returns the correlated link peer after the join.
    async fn vif_associate(
        &self,
        cookie: u64,
        request: AssociateRequest,
    ) -> Result<Option<[u8; 6]>, WirelessError>;
    async fn vif_disassociate(&self, cookie: u64) -> Result<(), WirelessError>;
}

/// Published primaries, for a shell to reach its wiphy's role owner.
static PRIMARIES: IrqSafeSpinLock<Vec<Weak<dyn Roles>>> = IrqSafeSpinLock::new(Vec::new());

pub(super) fn register_primary<R: Fullmac + 'static>(device: &Arc<Device<R>>) {
    let weak: Weak<dyn Roles> = Arc::downgrade(device) as Weak<dyn Roles>;
    let mut primaries = PRIMARIES.lock();
    primaries.retain(|primary| primary.strong_count() > 0);
    primaries.push(weak);
}

fn primary(wiphy: u64) -> Option<Arc<dyn Roles>> {
    PRIMARIES
        .lock()
        .iter()
        .filter_map(Weak::upgrade)
        .find(|primary| primary.wiphy() == wiphy)
}

/// Rebind a parked secondary station onto its bsscfg adapter for `$body`
/// (`|$station| ...`), then park it again. A missing owner, slot or parked
/// station is `Error::Failed`.
macro_rules! with_secondary {
    ($state:expr, $cookie:expr, |$station:ident| $body:expr) => {{
        let State {
            station: primary,
            vif,
            secondaries,
            ..
        } = &mut *$state;
        match (
            vif.as_mut(),
            secondaries.iter_mut().find(|slot| slot.cookie == $cookie),
        ) {
            (Some(owner), Some(slot)) => match slot.station.take() {
                Some(parked) => {
                    let adapter = Bsscfg::new(&mut primary.runtime, owner, &mut slot.link);
                    let (mut $station, rest) = parked.rebind(adapter);
                    let result = $body;
                    let (parked, _) = $station.rebind(rest);
                    slot.station = Some(parked);
                    result
                }
                None => Err(Error::Failed),
            },
            _ => Err(Error::Failed),
        }
    }};
}

/// One worker pass of a secondary station: its link lifecycle (`poll`
/// consumes only this bsscfg's events). Returns the correlated peer.
fn secondary_poll<R: Fullmac>(
    runtime: &mut R,
    owner: &mut Owner,
    slot: &mut Secondary<R>,
) -> Option<[u8; 6]> {
    let parked = slot.station.take()?;
    let (mut bound, rest) = parked.rebind(Bsscfg::new(runtime, owner, &mut slot.link));
    let _ = bound.poll();
    let (parked, _) = bound.rebind(rest);
    slot.station = Some(parked);
    slot.link.peer()
}

/// `brcmf_cfg80211_add_iface` role attach after the IF ADD: a STA shell
/// gets its secondary station with the per-interface dcmds issued on its
/// own ifidx; an AP shell has no per-bsscfg owner (it stays refusing).
async fn attach_role<R: Fullmac>(
    runtime: &mut R,
    owner: &mut Owner,
    secondaries: &mut Vec<Secondary<R>>,
    shell: &VifDevice,
    entry: Entry,
    template: Option<Station<Parked<R>>>,
) -> bool {
    if shell.role == Role::Ap {
        return true;
    }
    let Some(mut parked) = template else {
        return false;
    };
    parked.mac = entry.mac;
    let mut link = Link::new(entry);
    let (mut bound, rest) = parked.rebind(Bsscfg::new(runtime, owner, &mut link));
    let configured = bound.configure_secondary().await.is_ok();
    let (parked, _) = bound.rebind(rest);
    if configured {
        secondaries.push(Secondary {
            cookie: shell.cookie,
            link,
            station: Some(parked),
        });
    }
    configured
}

/// `brcmf_feat_attach`: the composition features of the booted firmware,
/// from the actual `cap` token list. `None` when the transport has no
/// secondary demux or the firmware refuses `cap`.
pub(super) async fn discover<R: Fullmac>(
    runtime: &mut R,
    primary_mac: [u8; 6],
) -> Result<Option<Owner>, Error> {
    if !R::VIF_DEMUX {
        return Ok(None);
    }
    // feature.c brcmf_fwcap_map; the MBSS exclusion is per chip.
    let chip = match R::FAMILY {
        Family::Sdio => 43439,
        Family::Pcie => 43602,
    };
    let reply = match runtime
        .command(Direction::Get, 262, b"cap\0", CAP_LEN)
        .await
    {
        Ok(reply) => reply,
        Err(Error::Firmware(_) | Error::Unsupported) => return Ok(None),
        Err(error) => return Err(error),
    };
    match vif_wire::features(&reply, CAP_LEN, chip) {
        Ok(features) => Ok(Some(Owner::new(primary_mac, features))),
        Err(Error::Malformed) => Ok(None),
        Err(error) => Err(error),
    }
}

/// One secondary netdev/wdev. Not generic: the primary owns the runtime.
pub struct VifDevice {
    name: String,
    family: Family,
    wiphy: u64,
    role: Role,
    /// Caller address for a STA (Linux honours it for STA only).
    requested: Option<[u8; 6]>,
    cookie: u64,
    mac: AtomicU64,
    phase: AtomicU8,
    entry: IrqSafeSpinLock<Option<Entry>>,
    info: WirelessIfaceInfo,
    up: AtomicBool,
    closing: AtomicBool,
    epoch: AtomicU64,
    publication: IrqSafeSpinLock<()>,
    rx: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
    /// Worker side of the rings.
    rx_producer: IrqSafeSpinLock<Option<Producer<Frame, RX_RING_N>>>,
    tx_consumer: IrqSafeSpinLock<Option<Consumer<Frame, TX_RING_N>>>,
    pending: IrqSafeSpinLock<Option<Frame>>,
}

impl core::fmt::Debug for VifDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FullmacVif")
            .field("name", &self.name)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

fn pack(mac: [u8; 6]) -> u64 {
    let mut packed = [0; 8];
    packed[..6].copy_from_slice(&mac);
    u64::from_le_bytes(packed)
}

impl VifDevice {
    fn phase(&self) -> u8 {
        self.phase.load(Ordering::Acquire)
    }
    /// Firmware interface, once its IF ADD arrived.
    fn entry(&self) -> Option<Entry> {
        *self.entry.lock()
    }
    fn drop_queued(&self) {
        self.pending.lock().take();
        if let Some(tx) = self.tx_consumer.lock().as_mut() {
            for _ in 0..TX_RING_N {
                if !matches!(tx.try_recv(), Ok(Some(_))) {
                    break;
                }
            }
        }
        if let Some(rx) = self.rx.lock().as_mut() {
            for _ in 0..RX_RING_N {
                if !matches!(rx.try_recv(), Ok(Some(_))) {
                    break;
                }
            }
        }
    }
    /// `brcmf_remove_interface` host side: close admission and withdraw
    /// every publication (`unregister_netdev`; the name is not retained for
    /// a rebind: a secondary interface is not recreated by a reset).
    fn unpublish(&self) {
        {
            let _publication = self.publication.lock();
            self.closing.store(true, Ordering::Release);
            self.epoch.fetch_add(1, Ordering::AcqRel);
            if self.up.swap(false, Ordering::AcqRel) {
                narf_net::iface::set_link_metadata(&self.name, false, None, None);
            }
        }
        self.drop_queued();
        narf_wireless::registry::unregister(&self.name);
        narf_net::registry().unregister(&self.name);
        narf_net::iface::unregister(&self.name);
    }
    /// Carrier follows the secondary station's correlated link only.
    fn set_carrier(&self, peer: Option<[u8; 6]>) {
        let (was_up, up) = {
            let _publication = self.publication.lock();
            let up = peer.is_some() && !self.closing.load(Ordering::Acquire);
            let was_up = self.up.swap(up, Ordering::AcqRel);
            if was_up != up {
                self.epoch.fetch_add(1, Ordering::AcqRel);
                narf_net::iface::set_link_metadata(&self.name, up, None, None);
            }
            (was_up, up)
        };
        if was_up && !up {
            self.drop_queued();
            narf_wireless::nl80211::notify_disconnect(&self.name, 1, false);
        }
    }
    /// A live STA shell (role operations are refused otherwise).
    fn station_role(&self) -> Result<Arc<dyn Roles>, WirelessError> {
        if self.role != Role::Station
            || self.phase() != LIVE
            || self.closing.load(Ordering::Acquire)
        {
            return Err(WirelessError::NotSupported);
        }
        primary(self.wiphy).ok_or(WirelessError::HardwareError)
    }
    fn finish(self: &Arc<Self>) {
        self.phase.store(GONE, Ordering::Release);
        SHELLS.lock().retain(|shell| !Arc::ptr_eq(shell, self));
    }
    fn enqueue(&self, bytes: &[u8]) -> Result<(), ()> {
        let mac = self.mac();
        if !self.up.load(Ordering::Acquire) || !super::transmit_admitted(bytes, mac) {
            return Err(());
        }
        let epoch = self.epoch.load(Ordering::Acquire);
        let buffer = narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
            .map_err(|_| ())?;
        let mut frame = Frame::new(buffer, bytes.len() as u32);
        frame.payload_mut().copy_from_slice(bytes);
        let _publication = self.publication.lock();
        if self.closing.load(Ordering::Acquire)
            || !self.up.load(Ordering::Acquire)
            || self.epoch.load(Ordering::Acquire) != epoch
        {
            return Err(());
        }
        self.tx
            .lock()
            .as_mut()
            .ok_or(())?
            .try_send(frame)
            .map_err(|_| ())
    }
}

fn send_vif(cookie: u64, bytes: &[u8], _: narf_net::TxMeta) -> Result<(), ()> {
    let shell = SHELLS
        .lock()
        .iter()
        .find(|shell| shell.cookie == cookie)
        .cloned()
        .ok_or(())?;
    shell.enqueue(bytes)
}

fn shells(family: Family) -> Vec<Arc<VifDevice>> {
    SHELLS
        .lock()
        .iter()
        .filter(|shell| shell.family == family)
        .cloned()
        .collect()
}

/// Withdraw every shell of `family` with its primary (`brcmf_detach`
/// removes all interfaces). Native resources end with the generation.
pub(super) fn withdraw_family(family: Family) {
    for shell in shells(family) {
        shell.unpublish();
        shell.finish();
    }
}

fn role_of(iftype: u32) -> Option<Role> {
    match iftype {
        2 => Some(Role::Station),
        3 => Some(Role::Ap),
        _ => None,
    }
}

impl<R: Fullmac + 'static> Device<R> {
    /// Whether the booted firmware's `cap` admits any additional STA/AP
    /// interface beside the primary (`brcmf_setup_ifmodes`).
    pub(super) fn vif_composable(&self) -> bool {
        self.state.try_lock().is_some_and(|state| {
            state
                .vif
                .as_ref()
                .is_some_and(|owner| owner.can_add(Role::Station) || owner.can_add(Role::Ap))
        })
    }

    /// `brcmf_cfg80211_add_iface` admission and `brcmf_net_attach`
    /// publication; the native create is the worker's (module docs).
    pub(super) fn vif_new(
        &self,
        name: &str,
        iftype: u32,
        mac: Option<[u8; 6]>,
    ) -> Result<Arc<VifDevice>, WirelessError> {
        let role = role_of(iftype).ok_or(WirelessError::NotSupported)?;
        if self.withdrawn() || self.closing.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        if name.is_empty()
            || name.len() > 15
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            return Err(WirelessError::InvalidArgs);
        }
        let primary_mac = self.mac;
        {
            let state = self.state.try_lock().ok_or(WirelessError::Busy)?;
            let owner = state.vif.as_ref().ok_or(WirelessError::NotSupported)?;
            // One native create in flight at a time (`vif_event` is single).
            if shells(R::FAMILY)
                .iter()
                .any(|shell| matches!(shell.phase(), CREATING | REMOVING))
            {
                return Err(WirelessError::Busy);
            }
            if !owner.can_add(role) {
                return Err(WirelessError::Busy);
            }
        }
        let requested = mac.filter(|_| role == Role::Station);
        // Provisional address until the IF ADD names the actual one.
        let provisional = requested.unwrap_or_else(|| vif_wire::vif_mac(primary_mac, &mut 0));
        let authority = narf_net::trusted_net_authority()
            .and_then(|cap| cap.derive().ok())
            .ok_or(WirelessError::Denied)?;
        let mut info = self.get_wireless_info();
        info.base_name = name.into();
        info.base_mac = provisional;
        info.modes = match role {
            Role::Station => narf_wireless::iface::WirelessModes::STATION,
            Role::Ap => narf_wireless::iface::WirelessModes::AP,
        };
        let (rx_producer, rx_consumer) = narf_ipc::channel();
        let (tx_producer, tx_consumer) = narf_ipc::channel();
        let shell = Arc::new(VifDevice {
            name: name.into(),
            family: R::FAMILY,
            wiphy: self.wiphy_id(),
            role,
            requested,
            cookie: NEXT_COOKIE.fetch_add(1, Ordering::Relaxed),
            mac: AtomicU64::new(pack(provisional)),
            phase: AtomicU8::new(CREATING),
            entry: IrqSafeSpinLock::new(None),
            info,
            up: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            epoch: AtomicU64::new(0),
            publication: IrqSafeSpinLock::new(()),
            rx: IrqSafeSpinLock::new(Some(rx_consumer)),
            tx: IrqSafeSpinLock::new(Some(tx_producer)),
            rx_producer: IrqSafeSpinLock::new(Some(rx_producer)),
            tx_consumer: IrqSafeSpinLock::new(Some(tx_consumer)),
            pending: IrqSafeSpinLock::new(None),
        });
        if narf_net::iface::lookup(name).is_some()
            || narf_wireless::registry::list()
                .iter()
                .any(|iface| iface.name() == name)
        {
            return Err(WirelessError::Busy);
        }
        narf_net::registry()
            .register(&authority, Registered(shell.clone()))
            .map_err(|error| match error {
                narf_net::RegisterError::DuplicateName => WirelessError::Busy,
                narf_net::RegisterError::AuthorityRevoked => WirelessError::Denied,
            })?;
        SHELLS.lock().push(shell.clone());
        narf_net::iface::register_with_context(name, provisional, shell.cookie, send_vif);
        narf_net::iface::set_link_state(name, false);
        narf_wireless::registry::register(shell.clone());
        Ok(shell)
    }

    /// The primary worker's secondary pass: IF events, pending native
    /// create/remove, retirement and the live shells' data pump.
    pub(super) async fn vif_worker(&self) {
        if !R::VIF_DEMUX {
            return;
        }
        let pending = shells(R::FAMILY);
        let mut delivered: Vec<(Arc<VifDevice>, Vec<u8>)> = Vec::new();
        {
            let Some(mut state) = self.state.try_lock() else {
                return;
            };
            let State {
                station,
                vif,
                secondaries,
                ..
            } = &mut *state;
            let Some(owner) = vif.as_mut() else {
                return;
            };
            // Role state of a STA shell whose native create runs this pass
            // (one create is in flight at a time).
            let mut template = pending
                .iter()
                .any(|shell| shell.phase() == CREATING && shell.role == Role::Station)
                .then(|| station.secondary([0; 6]));
            let runtime = &mut station.runtime;
            if owner.service(runtime).is_err() {
                // A bounded event queue overflowed: fail closed.
                runtime.fail();
            }
            while let Some(retired) = owner.pop_retired() {
                for shell in pending.iter() {
                    if shell.entry() == Some(retired) && shell.phase() == LIVE {
                        shell.unpublish();
                        shell.phase.store(CLOSING, Ordering::Release);
                    }
                }
            }
            for shell in pending.iter() {
                match shell.phase() {
                    CREATING => {
                        match owner.create(runtime, shell.role, shell.requested).await {
                            Ok(entry) => {
                                *shell.entry.lock() = Some(entry);
                                // brcmf_add_if: ifp->mac_addr from the event.
                                shell.mac.store(pack(entry.mac), Ordering::Release);
                                narf_net::iface::set_mac(&shell.name, entry.mac);
                                if runtime.vif_open(entry.ifidx).is_ok()
                                    && attach_role(
                                        runtime,
                                        owner,
                                        secondaries,
                                        shell,
                                        entry,
                                        template.take(),
                                    )
                                    .await
                                {
                                    shell.phase.store(LIVE, Ordering::Release);
                                } else {
                                    shell.unpublish();
                                    shell.phase.store(REMOVING, Ordering::Release);
                                }
                            }
                            Err(_) => {
                                shell.unpublish();
                                shell.finish();
                            }
                        }
                    }
                    REMOVING => {
                        let Some(entry) = shell.entry() else {
                            shell.finish();
                            continue;
                        };
                        // brcmf_cfg80211_del_apsta_iface. A refused or
                        // unanswered remove keeps the firmware bsscfg counted
                        // by the owner; the host side still closes its data.
                        if owner.remove(runtime, entry).await.is_ok() {
                            shell.finish();
                        } else {
                            shell.phase.store(CLOSING, Ordering::Release);
                        }
                    }
                    CLOSING => {
                        let ifidx = shell.entry().map(|entry| entry.ifidx);
                        match ifidx.map(|ifidx| runtime.vif_close(ifidx)) {
                            Some(Ok(false)) => {}
                            Some(Err(_)) => {
                                runtime.fail();
                                shell.finish();
                            }
                            _ => shell.finish(),
                        }
                    }
                    LIVE => {
                        let Some(entry) = shell.entry() else {
                            continue;
                        };
                        if shell.role == Role::Station {
                            let slot = secondaries
                                .iter_mut()
                                .find(|slot| slot.cookie == shell.cookie);
                            let (peer, lost) = match slot {
                                Some(slot) => {
                                    let peer = secondary_poll(runtime, owner, slot);
                                    (peer, slot.link.failed() || slot.station.is_none())
                                }
                                None => (None, true),
                            };
                            shell.set_carrier(peer);
                            if lost && owner.registry().by_bsscfgidx(entry.bsscfgidx) == Some(entry)
                            {
                                // A fail-stopped role retires its interface
                                // (an IF DEL already retires it otherwise).
                                shell.unpublish();
                                shell.phase.store(REMOVING, Ordering::Release);
                                continue;
                            }
                        }
                        let up = shell.up.load(Ordering::Acquire);
                        for _ in 0..PUMP_BUDGET {
                            let Some(frame) = runtime.pop_vif_data(entry.ifidx) else {
                                break;
                            };
                            if up && super::receive_admitted(&frame, shell.mac()) {
                                delivered.push((shell.clone(), frame));
                            }
                        }
                        if up {
                            vif_transmit(runtime, shell, entry.ifidx);
                        }
                    }
                    _ => {}
                }
            }
            // A role ends with its shell (`brcmf_remove_interface`).
            secondaries.retain(|slot| {
                pending
                    .iter()
                    .any(|shell| shell.cookie == slot.cookie && shell.phase() == LIVE)
            });
        }
        // No state or ring guard survives the stack callback.
        for (shell, mut bytes) in delivered {
            let epoch = shell.epoch.load(Ordering::Acquire);
            let frame = narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
                .ok()
                .map(|buffer| {
                    let mut frame = Frame::new(buffer, bytes.len() as u32);
                    frame.payload_mut().copy_from_slice(&bytes);
                    frame
                });
            {
                let _publication = shell.publication.lock();
                if !shell.up.load(Ordering::Acquire) || shell.epoch.load(Ordering::Acquire) != epoch
                {
                    continue;
                }
                if let (Some(frame), Some(rx)) = (frame, shell.rx_producer.lock().as_mut()) {
                    let _ = rx.try_send(frame);
                }
            }
            narf_net::iface::on_rx_frame_from(&shell.name, &mut bytes);
        }
    }
}

#[async_trait::async_trait]
impl<R: Fullmac + 'static> Roles for Device<R> {
    fn wiphy(&self) -> u64 {
        narf_wireless::WirelessNetIface::wiphy_id(self)
    }
    async fn vif_scan(
        &self,
        cookie: u64,
        request: ScanRequest,
    ) -> Result<Vec<BssInfo>, WirelessError> {
        let mut state = self.state.lock().await;
        if self.withdrawn() || !matches!(self.ap_mode(), 2 | 3) {
            return Err(WirelessError::NotSupported);
        }
        with_secondary!(state, cookie, |station| station.scan(request).await)
            .map_err(wireless_error)
    }
    async fn vif_associate(
        &self,
        cookie: u64,
        request: AssociateRequest,
    ) -> Result<Option<[u8; 6]>, WirelessError> {
        let mut state = self.state.lock().await;
        if self.withdrawn() || !matches!(self.ap_mode(), 2 | 3) {
            return Err(WirelessError::NotSupported);
        }
        let result = with_secondary!(state, cookie, |station| {
            if station.idle() {
                station.associate(request).await
            } else {
                Err(Error::Busy)
            }
        });
        result.map_err(wireless_error)?;
        Ok(state
            .secondaries
            .iter()
            .find(|slot| slot.cookie == cookie)
            .and_then(|slot| slot.link.peer()))
    }
    async fn vif_disassociate(&self, cookie: u64) -> Result<(), WirelessError> {
        let mut state = self.state.lock().await;
        with_secondary!(state, cookie, |station| station.disconnect().await).map_err(wireless_error)
    }
}

/// One TX step for a live shell: retain a credit-blocked frame, drop a
/// failed one (the transport fail-stops itself on a fatal error).
fn vif_transmit<R: Fullmac>(runtime: &mut R, shell: &VifDevice, ifidx: u8) {
    let mut pending = shell.pending.lock();
    for _ in 0..PUMP_BUDGET {
        if pending.is_none() {
            let next = shell
                .tx_consumer
                .lock()
                .as_mut()
                .and_then(|tx| tx.try_recv().ok().flatten());
            match next {
                Some(frame) if super::transmit_admitted(frame.payload(), shell.mac()) => {
                    *pending = Some(frame);
                }
                Some(_) => continue,
                None => return,
            }
        }
        let Some(frame) = pending.as_ref() else {
            return;
        };
        // brcmf_netdev_start_xmit: cfg80211_classify8021d.
        let priority = crate::ath11k::tx_hdr::classify8021d(frame.payload());
        match runtime.send_vif_data(ifidx, frame.payload(), priority) {
            Err(Error::Busy) => return,
            _ => *pending = None,
        }
    }
}

struct Registered(Arc<VifDevice>);

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
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        self.0.rx_ring()
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        self.0.tx_ring()
    }
}

impl Interface for VifDevice {
    fn name(&self) -> &str {
        &self.name
    }
    fn mac(&self) -> [u8; 6] {
        let bytes = self.mac.load(Ordering::Acquire).to_le_bytes();
        [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]]
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
impl WirelessNetIface for VifDevice {
    fn wiphy_id(&self) -> u64 {
        self.wiphy
    }
    fn current_iftype(&self) -> u32 {
        match self.role {
            Role::Station => 2,
            Role::Ap => 3,
        }
    }
    fn get_wireless_info(&self) -> WirelessIfaceInfo {
        use narf_wireless::iface::{HwCaps, WirelessBand};
        let caps = &self.info.hw_caps;
        WirelessIfaceInfo {
            base_name: self.name.clone(),
            base_mac: self.mac(),
            bands: self
                .info
                .bands
                .iter()
                .map(|band| WirelessBand {
                    freq_mhz: band.freq_mhz,
                    channels: band.channels.clone(),
                })
                .collect(),
            modes: self.info.modes,
            hw_caps: HwCaps {
                ht_supported: caps.ht_supported,
                vht_supported: caps.vht_supported,
                he_supported: caps.he_supported,
                eht_supported: caps.eht_supported,
            },
        }
    }
    /// `brcmf_cfg80211_del_iface`: hide now, remove natively in the worker.
    fn delete_virtual_interface(&self) -> Result<(), WirelessError> {
        let shell = SHELLS
            .lock()
            .iter()
            .find(|shell| core::ptr::eq(Arc::as_ptr(shell), self))
            .cloned()
            .ok_or(WirelessError::NotSupported)?;
        match shell
            .phase
            .compare_exchange(LIVE, REMOVING, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {}
            // A create still in flight is completed and then removed.
            Err(CREATING) => return Err(WirelessError::Busy),
            Err(_) => return Err(WirelessError::NotSupported),
        }
        shell.unpublish();
        Ok(())
    }
    // A STA shell drives its own secondary station (`Roles`); an AP shell
    // has no per-bsscfg AP owner and refuses rather than aliasing the
    // primary bsscfg.
    async fn scan(&self, request: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        self.station_role()?.vif_scan(self.cookie, request).await
    }
    async fn associate(&self, request: AssociateRequest) -> Result<(), WirelessError> {
        let peer = self
            .station_role()?
            .vif_associate(self.cookie, request)
            .await?;
        self.set_carrier(peer);
        Ok(())
    }
    async fn disassociate(&self) -> Result<(), WirelessError> {
        let roles = self.station_role()?;
        self.set_carrier(None);
        roles.vif_disassociate(self.cookie).await
    }
    async fn set_config(&self, _: WirelessConfig) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
}
