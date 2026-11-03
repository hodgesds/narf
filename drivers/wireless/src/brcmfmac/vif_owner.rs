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
use super::event_mask::{self, Need};
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
    /// Non-netdev P2P device (discovery) bsscfg (`p2p.c` `P2PAPI_BSSCFG_DEVICE`).
    P2pDevice,
    /// `NL80211_IFTYPE_P2P_CLIENT` connection bsscfg (`p2p_ifadd` CLIENT).
    P2pClient,
    /// `NL80211_IFTYPE_P2P_GO` connection bsscfg (`p2p_ifadd` GO).
    P2pGo,
}
impl Role {
    fn kind(self) -> CreateKind {
        match self {
            Self::Ap | Self::P2pGo => CreateKind::Ap,
            _ => CreateKind::Station,
        }
    }
}

/// Interface counts of one candidate set (requested interface included).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Counts {
    pub stations: u8,
    pub aps: u8,
    pub p2p_devices: u8,
    pub p2p_clients: u8,
    pub p2p_gos: u8,
}
impl Counts {
    pub fn add(&mut self, role: Role) {
        let slot = match role {
            Role::Station => &mut self.stations,
            Role::Ap => &mut self.aps,
            Role::P2pDevice => &mut self.p2p_devices,
            Role::P2pClient => &mut self.p2p_clients,
            Role::P2pGo => &mut self.p2p_gos,
        };
        *slot = slot.saturating_add(1);
    }
    fn total(self) -> u8 {
        self.stations
            .saturating_add(self.aps)
            .saturating_add(self.p2p_devices)
            .saturating_add(self.p2p_clients)
            .saturating_add(self.p2p_gos)
    }
}

/// `cfg80211_check_combinations` over the `brcmf_setup_ifmodes` table
/// (RSDB absent). `stations`/`aps` include the requested interface.
/// Monitor interfaces are not counted: none is created through this owner.
pub fn admits(features: Features, stations: u8, aps: u8) -> bool {
    admits_counts(
        features,
        Counts {
            stations,
            aps,
            ..Counts::default()
        },
    )
}

/// [`admits`] with the P2P iftypes: combo0 with `p2p` adds P2P_DEVICE <= 1
/// and P2P_CLIENT|P2P_GO <= 1 (`max_interfaces` = its limit count); the P2P
/// combination is STA 1, AP 1, P2P_CLIENT 1, P2P_DEVICE 1 (max 4). Without
/// `p2p` no P2P iftype exists (`interface_modes` lacks them).
pub fn admits_counts(features: Features, counts: Counts) -> bool {
    let p2p_roles = counts.p2p_devices + counts.p2p_clients + counts.p2p_gos;
    if !features.p2p && p2p_roles != 0 {
        return false;
    }
    let mon = u8::from(features.monitor_flag);
    let total = counts.total();
    let Counts {
        stations,
        aps,
        p2p_devices,
        p2p_clients,
        p2p_gos,
    } = counts;
    let combo0 = if features.p2p {
        // c0 limits: STA (1 + mchan), [MONITOR], P2P_DEVICE 1,
        // P2P_CLIENT|P2P_GO 1; max_interfaces = number of limits.
        stations <= 1 + u8::from(features.mchan)
            && aps == 0
            && p2p_devices <= 1
            && p2p_clients + p2p_gos <= 1
            && total <= 3 + mon
    } else {
        stations <= 1 && aps <= 1 && total <= 2 + mon
    };
    let p2p = features.p2p
        && stations <= 1
        && aps <= 1
        && p2p_clients <= 1
        && p2p_gos == 0
        && p2p_devices <= 1
        && total <= 4;
    let mbss = features.mbss && p2p_roles == 0 && stations == 0 && aps <= 4 && total <= 4 + mon;
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
    /// `fweh->p2pdev_setup_ongoing` (`brcmf_fweh_p2pdev_setup`).
    p2pdev_setup: bool,
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
            p2pdev_setup: false,
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
        let mut counts = Counts::default();
        counts.add(role);
        let mut concurrent = false;
        for current in self.roles.iter().flatten() {
            concurrent = true;
            counts.add(*current);
        }
        !concurrent || admits_counts(self.features, counts)
    }
    /// Whether an additional interface of `role` fits a combination now.
    pub fn can_add(&self, role: Role) -> bool {
        let mut counts = Counts::default();
        counts.add(self.primary_role);
        for current in self.roles.iter().flatten() {
            counts.add(*current);
        }
        counts.add(role);
        admits_counts(self.features, counts)
    }
    /// The live role of secondary bsscfg `bsscfgidx`.
    pub fn role(&self, bsscfgidx: u8) -> Option<Role> {
        *self.roles.get(bsscfgidx as usize)?
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
            let Disposition::Apply { event, p2p_device } = classify(parsed, self.p2pdev_setup)
            else {
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
        if !matches!(role, Role::Station | Role::Ap) || !self.can_add(role) {
            return Err(Error::Unsupported);
        }
        runtime.vif_listen(true);
        self.armed = Some(IfAction::Add);
        self.observed = None;
        let result: Result<Entry, Error> = async {
            listen_events(runtime).await?;
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
                    // The firmware mask keeps BRCMF_E_IF until the next
                    // writer; only the registry's need is withdrawn.
                    runtime.events_compose(Need::Interfaces, [0; event_mask::LEN]);
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
        // The removed interface's role owner no longer consumes events;
        // the union drops its bits at the next `event_msgs` write.
        runtime.events_compose(Need::Secondary(entry.ifidx), [0; event_mask::LEN]);
        if !self.live() {
            runtime.vif_listen(false);
            runtime.events_compose(Need::Interfaces, [0; event_mask::LEN]);
        }
        Ok(())
    }
}

impl Owner {
    /// `p2p.c::brcmf_p2p_create_p2pdev` from `brcmf_p2p_set_firmware` on:
    /// `BRCMF_C_DOWN`, `apsta 1`, `BRCMF_C_UP`, `p2p_disc 0`,
    /// `p2p_da_override` (their results are not checked, as in Linux),
    /// then with the vif event armed and `p2pdev_setup_ongoing` set,
    /// `p2p_disc 1` and the wait for the NOIF IF ADD of the discovery
    /// bsscfg, verified against the `p2p_dev` iovar. The entry carries no
    /// data mapping; `device` is the P2P Device Address.
    pub async fn create_p2p_device<R: Fullmac>(
        &mut self,
        runtime: &mut R,
        device: [u8; 6],
    ) -> Result<Entry, Error> {
        if !R::VIF_DEMUX {
            return Err(Error::Unsupported);
        }
        if self.armed.is_some() || self.roles.contains(&Some(Role::P2pDevice)) {
            // `-ENOSPC` for a second discovery vif.
            return Err(Error::Busy);
        }
        if !self.can_add(Role::P2pDevice) {
            return Err(Error::Unsupported);
        }
        if device == self.primary_mac || device == [0; 6] {
            // "discovery vif must be different from primary interface".
            return Err(Error::Malformed);
        }
        // brcmf_p2p_set_firmware.
        firmware_result(set_cmd(runtime, super::fwil::BRCMF_C_DOWN, 1).await)?;
        firmware_result(set_plain(runtime, b"apsta", &1u32.to_le_bytes()).await)?;
        firmware_result(set_cmd(runtime, super::fwil::BRCMF_C_UP, 1).await)?;
        firmware_result(set_plain(runtime, b"p2p_disc", &0u32.to_le_bytes()).await)?;
        firmware_result(set_plain(runtime, b"p2p_da_override", &device).await)?;
        runtime.vif_listen(true);
        self.armed = Some(IfAction::Add);
        self.observed = None;
        self.p2pdev_setup = true;
        let result: Result<Entry, Error> = async {
            listen_events(runtime).await?;
            set_plain(runtime, b"p2p_disc", &1u32.to_le_bytes()).await?;
            match self.wait(runtime).await? {
                Observed::Added(entry) if entry.p2p_device && entry.bsscfgidx != 0 => Ok(entry),
                _ => Err(Error::Malformed),
            }
        }
        .await;
        self.armed = None;
        self.observed = None;
        self.p2pdev_setup = false;
        let entry = match result {
            Ok(entry) => entry,
            Err(error) => {
                self.withdraw_listener(runtime);
                return Err(error);
            }
        };
        self.roles[entry.bsscfgidx as usize] = Some(Role::P2pDevice);
        // "verify bsscfg index for P2P discovery" (Linux only WARNs; NARF
        // refuses an unverified discovery bsscfg and disables it again).
        let verified = match get(runtime, b"p2p_dev", &[0; 4]).await {
            Ok(reply) if reply.len() >= 4 => {
                u32::from_le_bytes([reply[0], reply[1], reply[2], reply[3]])
                    == u32::from(entry.bsscfgidx)
            }
            Ok(_) => false,
            Err(Error::Firmware(_)) => false,
            Err(error) => return Err(error),
        };
        if !verified {
            let _ = self.remove_p2p_device(runtime, entry).await;
            return Err(Error::Malformed);
        }
        Ok(entry)
    }

    /// `p2p.c::brcmf_p2p_del_vif` for the device: `brcmf_p2p_deinit_discovery`
    /// (`p2p_state` SCAN on the discovery bsscfg, `p2p_disc 0` on the
    /// primary) and the wait for its IF DEL. The caller cancelled any
    /// listen first (`brcmf_p2p_cancel_remain_on_channel`). A missing IF
    /// DEL still removes the host entry, as `brcmf_remove_interface` runs
    /// regardless in Linux.
    pub async fn remove_p2p_device<R: Fullmac>(
        &mut self,
        runtime: &mut R,
        entry: Entry,
    ) -> Result<(), Error> {
        if self.armed.is_some() {
            return Err(Error::Busy);
        }
        if self.registry.by_bsscfgidx(entry.bsscfgidx) != Some(entry) || !entry.p2p_device {
            return Err(Error::Authority);
        }
        self.armed = Some(IfAction::Del);
        self.observed = None;
        let result: Result<(), Error> = async {
            let state = super::p2p_wire::disc_state(super::p2p_wire::DiscState::Scan, 0, 0);
            let input = vif_wire::bsscfg_iovar(entry.bsscfgidx, b"p2p_state", &state)?;
            firmware_result(
                runtime
                    .command_vif(entry.ifidx, Direction::Set, SET_VAR, &input, input.len())
                    .await,
            )?;
            firmware_result(set_plain(runtime, b"p2p_disc", &0u32.to_le_bytes()).await)?;
            match self.wait(runtime).await? {
                Observed::Removed(removed) if removed == entry => Ok(()),
                _ => Err(Error::Malformed),
            }
        }
        .await;
        self.armed = None;
        self.observed = None;
        if result.is_err() && self.registry.by_bsscfgidx(entry.bsscfgidx) == Some(entry) {
            // brcmf_remove_interface after a timed-out wait.
            let _ = self.registry.apply(
                IfEvent {
                    ifidx: entry.ifidx,
                    action: IfAction::Del,
                    flags: vif_wire::IF_FLAG_NOIF,
                    bsscfgidx: entry.bsscfgidx,
                    role: vif_wire::IfRole::Station,
                },
                true,
                entry.mac,
            );
            self.retire(entry);
        }
        runtime.events_compose(Need::Secondary(entry.ifidx), [0; event_mask::LEN]);
        self.withdraw_listener(runtime);
        result
    }

    /// `p2p.c::brcmf_p2p_add_vif` for CLIENT/GO: `p2p_ifadd` on the primary
    /// (`brcmf_p2p_request_p2p_if`: connection address, type and the
    /// current chanspec from `brcmf_p2p_get_current_chanspec`), the IF ADD
    /// wait, then `roam_off 1` and for a GO `BRCMF_C_SET_SCB_TIMEOUT`.
    pub async fn create_p2p<R: Fullmac>(
        &mut self,
        runtime: &mut R,
        role: Role,
        address: [u8; 6],
    ) -> Result<Entry, Error> {
        let kind = match role {
            Role::P2pClient => super::p2p_wire::P2pIfType::Client,
            Role::P2pGo => super::p2p_wire::P2pIfType::Go,
            _ => return Err(Error::Unsupported),
        };
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
            listen_events(runtime).await?;
            let chanspec = current_chanspec(runtime).await?;
            let request = super::p2p_wire::p2p_if(address, kind, chanspec);
            set_plain(runtime, b"p2p_ifadd", &request).await?;
            match self.wait(runtime).await? {
                Observed::Added(entry) if !entry.p2p_device && entry.bsscfgidx != 0 => Ok(entry),
                _ => Err(Error::Malformed),
            }
        }
        .await;
        self.armed = None;
        self.observed = None;
        let entry = match result {
            Ok(entry) => entry,
            Err(error) => {
                self.withdraw_listener(runtime);
                return Err(error);
            }
        };
        self.roles[entry.bsscfgidx as usize] = Some(role);
        // Results ignored, as in brcmf_p2p_add_vif.
        let input = vif_wire::bsscfg_iovar(0, b"roam_off", &1u32.to_le_bytes())?;
        firmware_result(
            runtime
                .command_vif(entry.ifidx, Direction::Set, SET_VAR, &input, input.len())
                .await,
        )?;
        if role == Role::P2pGo {
            let value = super::p2p_wire::SCB_TIMEOUT_VALUE.to_le_bytes();
            firmware_result(
                runtime
                    .command_vif(entry.ifidx, Direction::Set, SET_SCB_TIMEOUT, &value, 4)
                    .await,
            )?;
        }
        Ok(entry)
    }

    /// `p2p.c::brcmf_p2p_del_vif` for CLIENT/GO after the role stopped:
    /// GO `p2p_ifdis` (then `BRCMF_P2P_DISABLE_TIMEOUT` for the disable),
    /// `p2p_ifdel` with the interface address on the primary, the IF DEL
    /// wait and the transport retirement of the ifidx.
    pub async fn remove_p2p<R: Fullmac>(
        &mut self,
        runtime: &mut R,
        entry: Entry,
    ) -> Result<(), Error> {
        let role = self.role(entry.bsscfgidx);
        if !matches!(role, Some(Role::P2pClient | Role::P2pGo)) {
            return Err(Error::Authority);
        }
        if self.armed.is_some() {
            return Err(Error::Busy);
        }
        if self.registry.by_bsscfgidx(entry.bsscfgidx) != Some(entry) {
            return Err(Error::Authority);
        }
        self.armed = Some(IfAction::Del);
        self.observed = None;
        let result: Result<(), Error> = async {
            if role == Some(Role::P2pGo)
                && firmware_result(set_plain(runtime, b"p2p_ifdis", &entry.mac).await)?
            {
                // wait_for_completion_timeout(&cfg->vif_disabled,
                // BRCMF_P2P_DISABLE_TIMEOUT): completed by the GO bsscfg's
                // BRCMF_E_LINK with BRCMF_E_REASON_LINK_BSSCFG_DIS
                // (`brcmf_notify_connect_status_ap`); the timeout is not an
                // error. Other events of the stopped role are dropped.
                let deadline = narf_time::Deadline::after_ms(super::p2p_wire::DISABLE_TIMEOUT_MS);
                'disable: while !deadline.expired() {
                    runtime.poll()?;
                    self.service(runtime)?;
                    while let Some(event) = self.pop_event(&entry) {
                        if event.header.event_type == E_LINK
                            && event.header.reason == REASON_LINK_BSSCFG_DIS
                        {
                            break 'disable;
                        }
                    }
                    if self.registry.by_bsscfgidx(entry.bsscfgidx) != Some(entry) {
                        break;
                    }
                    narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
                }
            }
            set_plain(runtime, b"p2p_ifdel", &entry.mac).await?;
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
        runtime.events_compose(Need::Secondary(entry.ifidx), [0; event_mask::LEN]);
        self.withdraw_listener(runtime);
        Ok(())
    }

    fn withdraw_listener<R: Fullmac>(&mut self, runtime: &mut R) {
        if !self.live() {
            runtime.vif_listen(false);
            runtime.events_compose(Need::Interfaces, [0; event_mask::LEN]);
        }
    }
}

/// `BRCMF_C_SET_SCB_TIMEOUT`.
const SET_SCB_TIMEOUT: u32 = 158;
/// `BRCMF_E_LINK` / `BRCMF_E_REASON_LINK_BSSCFG_DIS`.
const E_LINK: u32 = 16;
const REASON_LINK_BSSCFG_DIS: u32 = 4;

/// `brcmf_p2p_get_current_chanspec`: the primary's BSS chanspec when it is
/// associated (`BRCMF_C_GET_BSSID` + `BRCMF_C_GET_BSS_INFO`), otherwise
/// `BRCMF_P2P_TEMP_CHAN` (11) at 20 MHz.
pub async fn current_chanspec<R: Fullmac>(runtime: &mut R) -> Result<u16, Error> {
    let fallback = super::p2p_wire::chanspec20(11).ok_or(Error::Malformed)?;
    match runtime
        .command(Direction::Get, super::fwil::BRCMF_C_GET_BSSID, &[0; 6], 6)
        .await
    {
        Ok(_) => {}
        Err(Error::Firmware(_)) => return Ok(fallback),
        Err(error) => return Err(error),
    }
    match runtime
        .command(
            Direction::Get,
            super::fwil::BRCMF_C_GET_BSS_INFO,
            &2048u32.to_le_bytes(),
            2048,
        )
        .await
    {
        // buf + 4 is `struct brcmf_bss_info_le`; chanspec at offset 72.
        Ok(reply) if reply.len() >= 78 => Ok(u16::from_le_bytes([reply[76], reply[77]])),
        Ok(_) | Err(Error::Firmware(_)) => Ok(fallback),
        Err(error) => Err(error),
    }
}

/// A firmware refusal is reported as `Ok(false)` (Linux ignores or logs
/// these results); transport failures end the operation.
fn firmware_result<T>(result: Result<T, Error>) -> Result<bool, Error> {
    match result {
        Ok(_) => Ok(true),
        Err(Error::Firmware(_)) => Ok(false),
        Err(error) => Err(error),
    }
}

/// `brcmf_fil_iovar_data_set` on the primary interface.
async fn set_plain<R: Fullmac>(runtime: &mut R, name: &[u8], data: &[u8]) -> Result<(), Error> {
    let input = vif_wire::bsscfg_iovar(0, name, data)?;
    runtime
        .command(Direction::Set, SET_VAR, &input, input.len())
        .await
        .map(|_| ())
}

/// `brcmf_fil_cmd_int_set` on the primary interface.
async fn set_cmd<R: Fullmac>(runtime: &mut R, command: u32, value: u32) -> Result<(), Error> {
    runtime
        .command(Direction::Set, command, &value.to_le_bytes(), 4)
        .await
        .map(|_| ())
}

/// `brcmf_fweh_activate_events` always enables `BRCMF_E_IF`; here the
/// registry declares it while it listens, and the union is written only
/// when it adds the bit. Withdrawal records the need without a write.
async fn listen_events<R: Fullmac>(runtime: &mut R) -> Result<(), Error> {
    let mask = runtime.events_compose(Need::Interfaces, event_mask::mask(&[E_IF as usize]));
    if runtime.events_current() == Some(mask) {
        return Ok(());
    }
    let input = vif_wire::bsscfg_iovar(0, b"event_msgs", &mask)?;
    runtime
        .command(Direction::Set, SET_VAR, &input, input.len())
        .await?;
    runtime.events_written(mask);
    Ok(())
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
