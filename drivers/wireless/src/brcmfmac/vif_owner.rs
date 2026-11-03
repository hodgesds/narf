// SPDX-License-Identifier: GPL-2.0-or-later
//! Secondary firmware-interface command owner: `interface_create` /
//! `interface_remove` that wait on the native `BRCMF_E_IF` event, plus the
//! host `fweh` dispatcher for secondary-bsscfg events.
//!
//! Linux 7.3-rc4 sources mirrored here:
//! - `cfg80211.c::brcmf_apsta_add_vif` (arm the vif event, request the
//!   interface, `brcmf_cfg80211_wait_vif_event(BRCMF_E_IF_ADD,
//!   BRCMF_VIF_EVENT_TIMEOUT)`, disarm);
//! - `cfg80211.c::brcmf_cfg80211_request_{sta,ap}_if` (v1, v2, bsscfg
//!   version query, v3 and, for AP only, the legacy `bsscfg:ssid` fallback);
//! - `cfg80211.c::brcmf_cfg80211_del_apsta_iface` (bsscfg
//!   `interface_remove` on the vif's ifp, wait for `BRCMF_E_IF_DEL`);
//! - `cfg80211.c::brcmf_vif_add_validate` + `brcmf_setup_ifmodes` interface
//!   combinations (without RSDB, which NARF does not parse);
//! - `fweh.c::brcmf_fweh_handle_if_event` (unsolicited DEL removes the
//!   interface; ADD over a stale entry detaches it) and the per-bsscfg
//!   dispatch of every other event (`iflist[emsg.bsscfgidx]`).
//!
//! The owner grants no data authority: a created interface's transport
//! data path stays closed until its role owner calls `Fullmac::vif_open`.
use super::vif_wire::{
    self, classify, CreateKind, Disposition, Entry, Features, IfAction, IfEvent, Registry, E_IF,
    MAX_IFS,
};
use crate::cyw43439::{
    fullmac::Fullmac,
    ioctl::Direction,
    runtime::{Error, Event},
};
use alloc::{collections::VecDeque, vec::Vec};

/// `cfg80211.h` `BRCMF_VIF_EVENT_TIMEOUT` (1500 ms).
pub const VIF_EVENT_TIMEOUT_MS: u64 = 1500;
const GET_VAR: u32 = super::fwil::BRCMF_C_GET_VAR;
const SET_VAR: u32 = 263;
/// Bound for retained secondary per-bsscfg events.
pub const EVENT_DEPTH: usize = 32;

/// Interface type of one bsscfg for combination accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Station,
    Ap,
}
impl Role {
    fn kind(self) -> CreateKind {
        match self {
            Self::Station => CreateKind::Station,
            Self::Ap => CreateKind::Ap,
        }
    }
}

/// `cfg80211_check_combinations` over the `brcmf_setup_ifmodes` table
/// (RSDB absent). `stations`/`aps` include the requested interface.
/// Monitor interfaces are not counted: none is created through this owner.
pub fn admits(features: Features, stations: u8, aps: u8) -> bool {
    let mon = u8::from(features.monitor_flag);
    let total = stations.saturating_add(aps);
    let combo0 = if features.p2p {
        // c0: STA <= 1 + mchan, P2P limits, no AP entry.
        stations <= 1 + u8::from(features.mchan) && aps == 0 && total <= 3 + mon
    } else {
        stations <= 1 && aps <= 1 && total <= 2 + mon
    };
    let p2p = features.p2p && stations <= 1 && aps <= 1 && total <= 4;
    let mbss = features.mbss && stations == 0 && aps <= 4 && total <= 4 + mon;
    combo0 || p2p || mbss
}

/// Outcome the armed waiter observed (`vif_event_equals`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Observed {
    Added(Entry),
    Removed(Entry),
}

/// Host-side secondary interface registry and IF-event command owner for
/// one transport generation. A new generation needs a new owner.
#[derive(Debug)]
pub struct Owner {
    registry: Registry,
    features: Features,
    primary_mac: [u8; 6],
    mac_idx: u8,
    primary_role: Role,
    roles: [Option<Role>; MAX_IFS as usize],
    armed: Option<IfAction>,
    observed: Option<Observed>,
    /// Entries detached by firmware without a waiting request (stale ADD
    /// replacement or unsolicited DEL); their owners must retire them.
    retired: VecDeque<Entry>,
    events: VecDeque<(u64, Event)>,
}

impl Owner {
    pub fn new(primary_mac: [u8; 6], features: Features) -> Self {
        Self {
            registry: Registry::new(primary_mac),
            features,
            primary_mac,
            mac_idx: 0,
            primary_role: Role::Station,
            roles: [None; MAX_IFS as usize],
            armed: None,
            observed: None,
            retired: VecDeque::new(),
            events: VecDeque::new(),
        }
    }
    pub fn features(&self) -> Features {
        self.features
    }
    /// Primary interface type (STA unless the primary AP owner runs).
    pub fn set_primary_role(&mut self, role: Role) {
        self.primary_role = role;
    }
    pub fn registry(&self) -> &Registry {
        &self.registry
    }
    /// `cfg80211.c::brcmf_vif_change_validate`: whether the primary may
    /// change to `role` beside the live secondary interfaces (combinations
    /// are checked only when another interface exists).
    pub fn can_change_primary(&self, role: Role) -> bool {
        let (mut stations, mut aps) = (u8::from(role == Role::Station), u8::from(role == Role::Ap));
        let mut concurrent = false;
        for current in self.roles.iter().flatten() {
            concurrent = true;
            match current {
                Role::Station => stations += 1,
                Role::Ap => aps += 1,
            }
        }
        !concurrent || admits(self.features, stations, aps)
    }
    /// Whether an additional interface of `role` fits a combination now.
    pub fn can_add(&self, role: Role) -> bool {
        let mut stations = u8::from(self.primary_role == Role::Station);
        let mut aps = u8::from(self.primary_role == Role::Ap);
        for current in self.roles.iter().flatten() {
            match current {
                Role::Station => stations += 1,
                Role::Ap => aps += 1,
            }
        }
        match role {
            Role::Station => stations += 1,
            Role::Ap => aps += 1,
        }
        admits(self.features, stations, aps)
    }
    pub fn pop_retired(&mut self) -> Option<Entry> {
        self.retired.pop_front()
    }
    /// Secondary event for the live entry `entry` (same generation).
    pub fn pop_event(&mut self, entry: &Entry) -> Option<Event> {
        let position = self.events.iter().position(|(generation, event)| {
            *generation == entry.generation && event.header.bsscfg_idx == entry.bsscfgidx
        })?;
        self.events.remove(position).map(|(_, event)| event)
    }
    /// Retained (not yet popped) events of the live entry `entry`.
    pub fn events_for<'a>(&'a self, entry: &'a Entry) -> impl Iterator<Item = &'a Event> + 'a {
        self.events
            .iter()
            .filter(move |(generation, event)| {
                *generation == entry.generation && event.header.bsscfg_idx == entry.bsscfgidx
            })
            .map(|(_, event)| event)
    }
    fn live(&self) -> bool {
        self.roles.iter().any(Option::is_some)
    }

    fn retire(&mut self, entry: Entry) {
        self.roles[entry.bsscfgidx as usize] = None;
        self.events
            .retain(|(generation, _)| *generation != entry.generation);
    }

    /// Consume secondary records (`fweh.c` event worker). IF events update
    /// the registry; other events are kept for their live bsscfg entry.
    pub fn service<R: Fullmac>(&mut self, runtime: &mut R) -> Result<(), Error> {
        while let Some(event) = runtime.pop_vif_event() {
            let header = event.header;
            if header.event_type != E_IF {
                let Some(entry) = self.registry.by_bsscfgidx(header.bsscfg_idx) else {
                    continue;
                };
                if entry.bsscfgidx == 0 || self.roles[entry.bsscfgidx as usize].is_none() {
                    continue;
                }
                if self.events.len() == EVENT_DEPTH {
                    return Err(Error::EventOverflow);
                }
                self.events.push_back((entry.generation, event));
                continue;
            }
            let Ok(parsed) = IfEvent::parse(header.event_type, header.datalen, &event.payload)
            else {
                continue;
            };
            let Disposition::Apply { event, p2p_device } = classify(parsed, false) else {
                continue;
            };
            match self.registry.apply(event, p2p_device, header.source_mac) {
                vif_wire::Applied::Added(entry) => {
                    if self.armed == Some(IfAction::Add) {
                        self.observed = Some(Observed::Added(entry));
                    }
                }
                vif_wire::Applied::Replaced { old, new } => {
                    self.retire(old);
                    self.retired.push_back(old);
                    if self.armed == Some(IfAction::Add) {
                        self.observed = Some(Observed::Added(new));
                    }
                }
                vif_wire::Applied::Removed(entry) => {
                    self.retire(entry);
                    if self.armed == Some(IfAction::Del) {
                        self.observed = Some(Observed::Removed(entry));
                    } else {
                        // fweh default handling: brcmf_remove_interface.
                        self.retired.push_back(entry);
                    }
                }
                vif_wire::Applied::Changed(_) | vif_wire::Applied::Ignored => {}
            }
        }
        Ok(())
    }

    async fn wait<R: Fullmac>(&mut self, runtime: &mut R) -> Result<Observed, Error> {
        let deadline = narf_time::Deadline::after_ms(VIF_EVENT_TIMEOUT_MS);
        loop {
            runtime.poll()?;
            self.service(runtime)?;
            if let Some(observed) = self.observed.take() {
                return Ok(observed);
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
        }
    }

    /// `brcmf_apsta_add_vif`: request a STA or AP interface and wait for
    /// its native IF ADD. The entry's MAC is the event address.
    pub async fn create<R: Fullmac>(
        &mut self,
        runtime: &mut R,
        role: Role,
        mac: Option<[u8; 6]>,
    ) -> Result<Entry, Error> {
        if !R::VIF_DEMUX {
            return Err(Error::Unsupported);
        }
        if self.armed.is_some() {
            return Err(Error::Busy);
        }
        if !self.can_add(role) {
            return Err(Error::Unsupported);
        }
        runtime.vif_listen(true);
        self.armed = Some(IfAction::Add);
        self.observed = None;
        let result: Result<Entry, Error> = async {
            self.request(runtime, role, mac).await?;
            match self.wait(runtime).await? {
                Observed::Added(entry) if !entry.p2p_device && entry.bsscfgidx != 0 => Ok(entry),
                _ => Err(Error::Malformed),
            }
        }
        .await;
        self.armed = None;
        self.observed = None;
        match result {
            Ok(entry) => {
                self.roles[entry.bsscfgidx as usize] = Some(role);
                Ok(entry)
            }
            Err(error) => {
                if !self.live() {
                    runtime.vif_listen(false);
                }
                Err(error)
            }
        }
    }

    /// `brcmf_cfg80211_request_{sta,ap}_if`.
    async fn request<R: Fullmac>(
        &mut self,
        runtime: &mut R,
        role: Role,
        mac: Option<[u8; 6]>,
    ) -> Result<(), Error> {
        let kind = role.kind();
        // A caller MAC is honoured for STA only, as in Linux.
        let next_mac = |owner: &mut Self| match (role, mac) {
            (Role::Station, Some(mac)) if mac != [0; 6] => mac,
            _ => vif_wire::vif_mac(owner.primary_mac, &mut owner.mac_idx),
        };
        let v1 = vif_wire::interface_create_v1(kind, next_mac(self));
        if accepted(get(runtime, b"interface_create", &v1).await)? {
            return Ok(());
        }
        let v2 = vif_wire::interface_create_v2(kind, next_mac(self));
        if accepted(get(runtime, b"interface_create", &v2).await)? {
            return Ok(());
        }
        let version = match get(runtime, b"interface_create", &[0; 4]).await {
            Ok(reply) if reply.len() >= 4 => {
                Some(u32::from_le_bytes([reply[0], reply[1], reply[2], reply[3]]))
            }
            Ok(_) => return Err(Error::Malformed),
            Err(Error::Firmware(_)) => None,
            Err(error) => return Err(error),
        };
        if version.is_none() {
            return Err(Error::Unsupported);
        }
        if version == Some(3) {
            let v3 = vif_wire::interface_create_v3(kind, next_mac(self));
            if accepted(get(runtime, b"interface_create", &v3).await)? {
                return Ok(());
            }
        }
        if role == Role::Station {
            return Err(Error::Unsupported);
        }
        // AP-only legacy MBSS path: plain `bsscfg:ssid` on bsscfg 0.
        let bsscfgidx = self.registry.first_free_bsscfgidx().ok_or(Error::Busy)?;
        let ssid = vif_wire::mbss_ssid(bsscfgidx)?;
        let input = vif_wire::bsscfg_iovar(0, b"bsscfg:ssid", &ssid)?;
        runtime
            .command(Direction::Set, SET_VAR, &input, input.len())
            .await
            .map(|_| ())
    }

    /// `brcmf_cfg80211_del_apsta_iface`: the caller has closed the
    /// interface's role and data first. Waits for the IF DEL, then for the
    /// transport to retire every native resource of the ifidx.
    pub async fn remove<R: Fullmac>(&mut self, runtime: &mut R, entry: Entry) -> Result<(), Error> {
        if self.armed.is_some() {
            return Err(Error::Busy);
        }
        if self.registry.by_bsscfgidx(entry.bsscfgidx) != Some(entry) || entry.bsscfgidx == 0 {
            return Err(Error::Authority);
        }
        self.armed = Some(IfAction::Del);
        self.observed = None;
        let result: Result<(), Error> = async {
            let input = vif_wire::bsscfg_iovar(entry.bsscfgidx, b"interface_remove", &[])?;
            runtime
                .command_vif(entry.ifidx, Direction::Set, SET_VAR, &input, input.len())
                .await?;
            match self.wait(runtime).await? {
                Observed::Removed(removed) if removed == entry => Ok(()),
                _ => Err(Error::Malformed),
            }
        }
        .await;
        self.armed = None;
        self.observed = None;
        result?;
        let deadline = narf_time::Deadline::after_ms(2000);
        while !runtime.vif_close(entry.ifidx)? {
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
        }
        if !self.live() {
            runtime.vif_listen(false);
        }
        Ok(())
    }
}

/// `brcmf_fil_iovar_data_get` on the primary interface.
async fn get<R: Fullmac>(runtime: &mut R, name: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    let input = vif_wire::bsscfg_iovar(0, name, data)?;
    runtime
        .command(Direction::Get, GET_VAR, &input, input.len())
        .await
}

/// A firmware refusal moves to the next request version, as in Linux; a
/// transport failure ends the request.
fn accepted(result: Result<Vec<u8>, Error>) -> Result<bool, Error> {
    match result {
        Ok(_) => Ok(true),
        Err(Error::Firmware(_)) => Ok(false),
        Err(error) => Err(error),
    }
}
