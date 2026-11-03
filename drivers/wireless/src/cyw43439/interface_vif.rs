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
//! correlated `set_link` peer is the shell carrier. An AP shell owns a
//! secondary-bsscfg firmware-SME AP (`interface_vif_ap.rs`): the same
//! parked station rebound to the adapter carries a `brcmfmac::ap::Session`
//! in the secondary scope, and AP control reaches it through [`Roles`].

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

#[path = "interface_p2p.rs"]
mod p2p_device;
#[path = "interface_vif_ap.rs"]
mod vif_ap;
pub(super) use p2p_device::create as p2p_device_create;

/// Some secondary bsscfg runs a firmware-SME AP. The primary AP Program
/// (device-wide DOWN/apsta/PHY modes) must not start beside it.
pub(super) fn secondary_ap_running<R: Fullmac>(secondaries: &[Secondary<R>]) -> bool {
    secondaries.iter().any(|slot| slot.ap.is_some())
}

/// Persistent secondary station role of one live STA shell (`struct
/// brcmf_cfg80211_vif` of a `NL80211_IFTYPE_STATION` additional interface).
pub(super) struct Secondary<R: Fullmac> {
    cookie: u64,
    link: Link,
    /// `None` only while an operation holds it rebound, or after such an
    /// operation was cancelled mid-flight (the role is then retired).
    station: Option<Station<Parked<R>>>,
    /// AP shell: its secondary-bsscfg firmware-SME AP between START/STOP.
    ap: Option<Box<crate::brcmfmac::ap::Session>>,
    ap_tx: vif_ap::PendingTx,
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
    /// AP control of an AP shell (`brcmf_cfg80211_start_ap` etc. on its
    /// secondary `ifp`).
    async fn vif_ap_control(
        &self,
        shell: Arc<VifDevice>,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        operation: vif_ap::Operation,
    ) -> Result<bool, WirelessError>;
    /// The P2P discovery bsscfg owner of the control-only P2P_DEVICE WDEV
    /// (`interface_p2p.rs`), under the primary state mutex.
    async fn p2p_device(
        &self,
        operation: p2p_device::Operation,
    ) -> Result<p2p_device::Outcome, WirelessError>;
    /// The AP serialization lease the P2P_DEVICE shares with its primary.
    fn p2p_reserve(
        &self,
    ) -> Result<Option<Arc<dyn narf_wireless::ap_control::ApControlReservation>>, WirelessError>;
    /// The primary is published and its transport generation current.
    fn p2p_parent_live(&self) -> bool;
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
/// own ifidx; an AP shell gets the same parked role state (Linux issues no
/// dcmd for an AP vif before `start_ap`) and its AP host becomes capable
/// when the transport has per-ifidx AP owners.
async fn attach_role<R: Fullmac>(
    runtime: &mut R,
    owner: &mut Owner,
    secondaries: &mut Vec<Secondary<R>>,
    shell: &VifDevice,
    entry: Entry,
    template: Option<Station<Parked<R>>>,
) -> bool {
    let Some(mut parked) = template else {
        return false;
    };
    parked.mac = entry.mac;
    let mut link = Link::new(entry);
    if ap_like(shell.role) {
        if !R::SECONDARY_AP {
            return false;
        }
        secondaries.push(Secondary {
            cookie: shell.cookie,
            link,
            station: Some(parked),
            ap: None,
            ap_tx: None,
        });
        shell.ap.mode.store(3, Ordering::Release);
        // A P2P GO starts its BSS with `bss` enable on the connection
        // bsscfg (`brcmf_cfg80211_start_ap` P2P_GO branch, `Scope::Go`).
        shell.ap.capable.store(true, Ordering::Release);
        return true;
    }
    let (mut bound, rest) = parked.rebind(Bsscfg::new(runtime, owner, &mut link));
    let configured = bound.configure_secondary().await.is_ok();
    let (parked, _) = bound.rebind(rest);
    if configured {
        secondaries.push(Secondary {
            cookie: shell.cookie,
            link,
            station: Some(parked),
            ap: None,
            ap_tx: None,
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
    /// AP shell host state (mode generation, control, staging, events).
    ap: super::ap::Host,
    /// Last AP data generation whose queued frames are current.
    ap_data: AtomicU64,
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
        self.ap.retire();
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
        if !station_like(self.role) || self.phase() != LIVE || self.closing.load(Ordering::Acquire)
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
    p2p_device::withdraw_family(family);
}

fn role_of(iftype: u32) -> Option<Role> {
    match iftype {
        2 => Some(Role::Station),
        3 => Some(Role::Ap),
        // `brcmf_p2p_add_vif` CLIENT/GO connection bsscfgs.
        8 if p2p_device::P2P_ADVERTISED => Some(Role::P2pClient),
        9 if p2p_device::P2P_ADVERTISED => Some(Role::P2pGo),
        _ => None,
    }
}

/// A STA-shaped shell (secondary station role on its bsscfg).
fn station_like(role: Role) -> bool {
    matches!(role, Role::Station | Role::P2pClient)
}

/// An AP-shaped shell (secondary-bsscfg AP owner).
fn ap_like(role: Role) -> bool {
    matches!(role, Role::Ap | Role::P2pGo)
}

/// A `p2p_ifadd` connection bsscfg (`create_p2p`/`remove_p2p`).
fn p2p_connection(role: Role) -> bool {
    matches!(role, Role::P2pClient | Role::P2pGo)
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

    /// `brcmf_setup_ifmodes` combinations for the STA/AP roles this driver
    /// creates, from the booted firmware's `cap` tokens (the same rules as
    /// `vif_owner::admits`). Without `p2p`, combo0 is one STA + one AP on
    /// one channel. With `p2p` (RSDB unparsed, treated absent) combo0 is
    /// `1 + mchan` STAs on `1 + mchan` channels and the P2P combination is
    /// one STA + one AP on one channel; the P2P iftype limits are left out
    /// (no P2P role here), so a combo0 of a single STA is not listed
    /// (cfg80211 needs `max_interfaces >= 2`). The `mbss` multi-AP
    /// combination is not advertised: `vif->mbss` is not implemented and
    /// only one AP may run.
    pub(super) fn vif_combinations(&self) -> Vec<narf_wireless::InterfaceCombination> {
        use narf_wireless::{InterfaceCombination, InterfaceTypeLimit};
        let Some(features) = self
            .state
            .try_lock()
            .and_then(|state| state.vif.as_ref().map(|owner| owner.features()))
        else {
            return Vec::new();
        };
        let combination = |limits: &[(u32, u32)], channels: u32| InterfaceCombination {
            limits: limits
                .iter()
                .map(|&(max, iftype)| InterfaceTypeLimit {
                    max,
                    iftypes: alloc::vec![iftype],
                })
                .collect(),
            max_interfaces: limits.iter().map(|&(max, _)| max).sum(),
            max_channels: channels,
            sta_ap_beacon_interval_match: false,
            beacon_interval_min_gcd: None,
            radar_detect_widths: None,
        };
        if !features.p2p {
            return alloc::vec![combination(&[(1, 2), (1, 3)], 1)];
        }
        let mut combinations = Vec::new();
        if features.mchan {
            combinations.push(combination(&[(2, 2)], 2));
        }
        combinations.push(combination(&[(1, 2), (1, 3)], 1));
        combinations
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
        // Linux honours the caller address for a STA only; a P2P
        // connection bsscfg uses `conn_int_addr` (`brcmf_p2p_add_vif`).
        let requested = if p2p_connection(role) {
            Some(p2p_device::connection_address(R::FAMILY, primary_mac)?)
        } else {
            mac.filter(|_| role == Role::Station)
        };
        // Provisional address until the IF ADD names the actual one.
        let provisional = requested.unwrap_or_else(|| vif_wire::vif_mac(primary_mac, &mut 0));
        let authority = narf_net::trusted_net_authority()
            .and_then(|cap| cap.derive().ok())
            .ok_or(WirelessError::Denied)?;
        let mut info = self.get_wireless_info();
        info.base_name = name.into();
        info.base_mac = provisional;
        info.modes = match role {
            Role::Station | Role::P2pClient | Role::P2pDevice => {
                narf_wireless::iface::WirelessModes::STATION
            }
            Role::Ap | Role::P2pGo => narf_wireless::iface::WirelessModes::AP,
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
            ap: super::ap::Host::new(),
            ap_data: AtomicU64::new(0),
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
        let mut ap_delivered: Vec<vif_ap::Delivery> = Vec::new();
        let mut p2p_notices: Vec<crate::brcmfmac::p2p::Notice> = Vec::new();
        {
            let Some(mut state) = self.state.try_lock() else {
                return;
            };
            let State {
                station,
                vif,
                secondaries,
                p2p,
                ..
            } = &mut *state;
            let Some(owner) = vif.as_mut() else {
                return;
            };
            // Role state of a STA shell whose native create runs this pass
            // (one create is in flight at a time).
            let mut template = pending
                .iter()
                .any(|shell| shell.phase() == CREATING)
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
                        let created = match (p2p_connection(shell.role), shell.requested) {
                            (true, Some(address)) => {
                                owner.create_p2p(runtime, shell.role, address).await
                            }
                            (true, None) => Err(Error::Malformed),
                            (false, _) => owner.create(runtime, shell.role, shell.requested).await,
                        };
                        match created {
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
                        // brcmf_cfg80211_del_ap_iface: a running AP is
                        // stopped on its bsscfg before the interface goes.
                        if let Some(slot) = secondaries
                            .iter_mut()
                            .find(|slot| slot.cookie == shell.cookie && slot.ap.is_some())
                        {
                            vif_ap::secondary_ap_stop(runtime, owner, slot).await;
                        }
                        // brcmf_cfg80211_del_apsta_iface. A refused or
                        // unanswered remove keeps the firmware bsscfg counted
                        // by the owner; the host side still closes its data.
                        // brcmf_p2p_del_vif for CLIENT/GO (`p2p_ifdis`,
                        // `p2p_ifdel`, IF DEL, ifidx retirement); a GO's
                        // AP owner retires its flows first.
                        let removed = if p2p_connection(shell.role) {
                            if shell.role == Role::P2pGo {
                                match runtime.ap_leave_on(entry.ifidx) {
                                    // Still retiring: the next pass retries.
                                    Ok(false) => continue,
                                    Ok(true) | Err(Error::Unsupported) => {}
                                    Err(_) => {
                                        runtime.fail();
                                        shell.finish();
                                        continue;
                                    }
                                }
                            }
                            owner.remove_p2p(runtime, entry).await.is_ok()
                        } else {
                            owner.remove(runtime, entry).await.is_ok()
                        };
                        if removed {
                            shell.finish();
                        } else {
                            shell.phase.store(CLOSING, Ordering::Release);
                        }
                    }
                    CLOSING => {
                        let ifidx = shell.entry().map(|entry| entry.ifidx);
                        // A secondary AP owner first retires its own
                        // flows/TX terminals (the bsscfg is gone).
                        if ap_like(shell.role) {
                            match ifidx.map(|ifidx| runtime.ap_leave_on(ifidx)) {
                                Some(Ok(false)) => continue,
                                // No per-ifidx AP owner on this family
                                // (`!SECONDARY_AP`): nothing to retire.
                                Some(Err(Error::Unsupported)) => {}
                                Some(Err(_)) => {
                                    runtime.fail();
                                    shell.finish();
                                    continue;
                                }
                                _ => {}
                            }
                        }
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
                        if station_like(shell.role) {
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
                        if ap_like(shell.role) {
                            // The AP Session owns this ifidx's data.
                            let alive = match secondaries
                                .iter_mut()
                                .find(|slot| slot.cookie == shell.cookie)
                            {
                                Some(slot) => {
                                    vif_ap::secondary_ap_pass(
                                        runtime,
                                        owner,
                                        slot,
                                        shell,
                                        &mut ap_delivered,
                                    )
                                    .await
                                }
                                None => false,
                            };
                            if !alive
                                && owner.registry().by_bsscfgidx(entry.bsscfgidx) == Some(entry)
                            {
                                shell.unpublish();
                                shell.phase.store(REMOVING, Ordering::Release);
                            } else if !alive {
                                shell.unpublish();
                                shell.phase.store(CLOSING, Ordering::Release);
                            }
                            continue;
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
            // The P2P discovery bsscfg's `fweh` handlers (listen complete,
            // action-frame RX, P2P probe requests).
            if let Some(device) = p2p.as_mut() {
                p2p_device::service(runtime, owner, device, &mut p2p_notices).await;
            }
        }
        p2p_device::deliver(R::FAMILY, p2p_notices);
        // No state or ring guard survives the stack callback.
        self.secondary_ap_deliver(ap_delivered);
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
    async fn vif_ap_control(
        &self,
        shell: Arc<VifDevice>,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        operation: vif_ap::Operation,
    ) -> Result<bool, WirelessError> {
        self.secondary_ap_control(&shell, authority, operation)
            .await
    }
    async fn p2p_device(
        &self,
        operation: p2p_device::Operation,
    ) -> Result<p2p_device::Outcome, WirelessError> {
        self.p2p_device_operation(operation).await
    }
    fn p2p_reserve(
        &self,
    ) -> Result<Option<Arc<dyn narf_wireless::ap_control::ApControlReservation>>, WirelessError>
    {
        narf_wireless::WirelessNetIface::reserve_radio_control(self)
    }
    fn p2p_parent_live(&self) -> bool {
        !self.withdrawn() && !self.closing.load(Ordering::Acquire) && self.p2p_device_enabled()
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
            Role::P2pClient => 8,
            Role::P2pGo => 9,
            Role::P2pDevice => 10,
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
    // An AP shell: firmware-SME AP on its own bsscfg (`vif_ap`).
    fn supports_ap(&self) -> bool {
        self.ap_capable()
    }
    fn supports_ap_userspace_mlme(&self) -> bool {
        false
    }
    fn supports_ap_authenticator(&self) -> bool {
        self.ap_capable()
    }
    fn ap_sme_capabilities(&self) -> Option<u32> {
        self.ap_capable().then_some(0)
    }
    fn max_ap_assoc_sta(&self) -> u32 {
        if self.ap_capable() {
            8
        } else {
            0
        }
    }
    fn ap_control_generation(&self) -> Option<core::num::NonZeroU64> {
        self.ap_generation()
    }
    fn reserve_ap_control(
        &self,
    ) -> Result<Option<Arc<dyn narf_wireless::ap_control::ApControlReservation>>, WirelessError>
    {
        if !self.ap_capable() {
            return Err(WirelessError::NotSupported);
        }
        self.ap.control.try_reserve().map(Some)
    }
    async fn start_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        config: narf_wireless::ApConfig,
    ) -> Result<(), WirelessError> {
        self.start_ap_with_settings_async(
            authority,
            config,
            narf_wireless::ApStartSettings::default(),
        )
        .await
    }
    async fn start_ap_with_settings_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        config: narf_wireless::ApConfig,
        settings: narf_wireless::ApStartSettings,
    ) -> Result<(), WirelessError> {
        self.ap_operation(
            authority,
            vif_ap::Operation::Start(Box::new(config), Box::new(settings)),
        )
        .await
        .map(|_| ())
    }
    async fn stop_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
    ) -> Result<(), WirelessError> {
        self.ap_operation(authority, vif_ap::Operation::Stop)
            .await
            .map(|_| ())
    }
    async fn set_beacon_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        head: Option<Vec<u8>>,
        tail: Option<Vec<u8>>,
        probe: Option<Vec<u8>>,
    ) -> Result<(), WirelessError> {
        self.ap_operation(authority, vif_ap::Operation::Beacon(head, tail, probe))
            .await
            .map(|_| ())
    }
    async fn set_station_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        station: narf_wireless::StationConfig,
    ) -> Result<(), WirelessError> {
        self.ap_operation(authority, vif_ap::Operation::Set(station))
            .await
            .map(|_| ())
    }
    async fn del_station_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        peer: Option<[u8; 6]>,
        reason: u16,
    ) -> Result<(), WirelessError> {
        self.ap_operation(authority, vif_ap::Operation::Delete(peer, reason))
            .await
            .map(|_| ())
    }
    async fn add_key_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        key: narf_wireless::OwnedKey,
    ) -> Result<(), i32> {
        self.ap_operation(authority, vif_ap::Operation::Key(key))
            .await
            .map(|_| ())
            .map_err(super::ap::errno)
    }
    async fn del_key_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        index: u8,
        pairwise: bool,
        peer: Option<[u8; 6]>,
    ) -> Result<(), i32> {
        self.ap_operation(
            authority,
            vif_ap::Operation::DeleteKey(index, pairwise, peer),
        )
        .await
        .map(|_| ())
        .map_err(super::ap::errno)
    }
    async fn default_key_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        index: u8,
        unicast: bool,
        multicast: bool,
        management: bool,
        beacon: bool,
    ) -> Result<(), i32> {
        self.ap_operation(
            authority,
            vif_ap::Operation::DefaultKey(index, (unicast, multicast, management, beacon)),
        )
        .await
        .map(|_| ())
        .map_err(super::ap::errno)
    }
    async fn tx_control_port_ap_async(
        &self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        request: narf_wireless::ControlPortTxRequest,
    ) -> Result<bool, i32> {
        self.ap_operation(authority, vif_ap::Operation::Control(request))
            .await
            .map_err(super::ap::errno)
    }
}
