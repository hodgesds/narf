//! Actual P2P MAC1/link1 ownership: Sc/Bz ROCv6/AUX or API89
//! PHY1/active-link/BCAST/SESSION2, with count-qualified TID16.
//! No public role is advertised by this module alone. The parent adapter
//! must prove an idle native owner and keep the original control child.
use super::super::{
    native_band::{Band, Channel},
    p2p_host::Request,
    p2p_owner::{Capture, Epoch, Gate, Grant, Publication},
    p2p_wire::{self, Abi, Activity as RocActivity, Duration, Target},
};
use super::*;
use alloc::{boxed::Box, collections::VecDeque, sync::Arc};

const MAC: u32 = 1;
const LINK: u32 = 1;
const TID: u8 = 16; // IWL_MAX_TID_COUNT, actual Linux AUX management queue.
const MAX_MS: u32 = 5000;

#[derive(Default)]
pub(super) struct State {
    pub(super) gate: Option<Arc<Gate>>,
    session: Option<Box<Session>>,
    counts: (Option<u8>, Option<u8>),
    retired: Vec<Arc<Request>>,
    gen2: Option<Box<super::super::p2p_gen2_wire::Adapter>>,
}
struct Session {
    abi: Abi,
    broadcast_mfp: bool,
    own: [u8; 6],
    start: Arc<Request>,
    epoch: Epoch,
    grant: Option<Box<Lease>>,
    events: VecDeque<Event>,
    sequence: u16,
    aux_station: u8,
}
struct Lease {
    cookie: u64,
    channel: Channel,
    duration_ms: u32,
    deadline: u64,
    activity: RocActivity,
    request: Arc<Request>,
    grant: Grant,
    queue: Option<u16>,
    queue_published: bool,
    aux_published: bool,
    add_published: bool,
    closing: bool,
    policy: Option<super::super::mld_policy::Fence>,
    public: bool,
    phy_published: bool,
    link_bound: bool,
    native_ended: bool,
}
pub(in crate::iwlwifi) enum Kind {
    Ready,
    Expired,
    Management { rssi: i8, frame: Vec<u8> },
}
pub(in crate::iwlwifi) struct Event {
    pub kind: Kind,
    pub cookie: u64,
    pub frequency: u32,
    pub duration_ms: u32,
    pub receiver: Arc<Request>,
    pub start: Arc<Request>,
    pub origin: Arc<Request>,
    pub capture: Capture,
    pub publication: Option<Publication>,
    pub policy: Option<super::super::mld_policy::Fence>,
}
impl State {
    pub(super) fn metadata(
        &mut self,
        api: &super::super::firmware_api::FirmwareApi<'_>,
    ) -> Result<(), &'static str> {
        if self.session.is_some() {
            return Err("P2P executable counts changed under a live native owner");
        }
        self.counts = (api.num_stations, api.num_links);
        Ok(())
    }
    pub(super) fn new(api: &super::super::firmware_api::FirmwareApi<'_>) -> Self {
        Self {
            gate: None,
            session: None,
            counts: (api.num_stations, api.num_links),
            retired: Vec::new(),
            gen2: None,
        }
    }
    pub(super) fn copy_grant(&self) -> Option<Publication> {
        self.session
            .as_ref()?
            .grant
            .as_ref()
            .and_then(|lease| lease.grant.current().then(|| lease.grant.publication()))
    }
    /// Called by Hardware::poll at the actual RFH copy boundary, before any
    /// station candidate/cache, key PN or reorder consumer can adopt a frame.
    /// `copied` was captured before this drain; START parsed in this batch
    /// cannot retrospectively admit an earlier/batched management copy.
    pub(super) fn observe(
        &mut self,
        packet: &Packet,
        copied: Option<&Publication>,
    ) -> Result<bool, &'static str> {
        let Some(session) = &mut self.session else {
            return Ok(false);
        };
        let Some(lease) = &mut session.grant else {
            return Ok(false);
        };
        if packet.header.group_id == p2p_wire::GROUP
            && packet.header.cmd
                == if session.abi == Abi::Roc6 {
                    p2p_wire::ROC_NOTIFICATION
                } else {
                    p2p_wire::SESSION_NOTIFICATION
                }
        {
            if packet.receive_queue != 0 || packet.header.sequence & 0x8000 == 0 {
                return Ok(true);
            }
            let notification = match session.abi {
                Abi::Roc6 => Abi::Roc6.roc_notification(lease.activity, &packet.payload)?,
                Abi::Session1 | Abi::Session2 => session.abi.session_notification(
                    if session.abi == Abi::Session1 {
                        Target::Mac(MAC as u8)
                    } else {
                        Target::Link(LINK as u8)
                    },
                    lease.activity,
                    &packet.payload,
                )?,
            };
            if lease.closing || !lease.grant.capture.current() {
                return Ok(true);
            }
            if notification.started && notification.success {
                lease.request.check()?;
                session.start.check()?;
                if !lease.grant.started() {
                    lease
                        .grant
                        .native_start(Duration::from_ms(lease.duration_ms)?.microseconds())?;
                    if lease.public {
                        session.events.push_back(Event {
                            kind: Kind::Ready,
                            cookie: lease.cookie,
                            frequency: lease.channel.frequency(),
                            duration_ms: lease.duration_ms,
                            receiver: lease.request.clone(),
                            start: session.start.clone(),
                            origin: lease.request.clone(),
                            capture: lease.grant.capture.clone(),
                            publication: Some(lease.grant.publication()),
                            policy: lease.policy.clone(),
                        });
                    }
                }
            } else {
                // Failed START still needs synchronous REMOVE; END still
                // needs real queue/STA retirement before EXPIRED or reuse.
                lease.grant.close();
                lease.closing = true;
                lease.native_ended = matches!(session.abi, Abi::Session1 | Abi::Session2);
            }
            return Ok(true);
        }
        if packet.header.group_id != 0 || packet.header.cmd != 0xc1 || packet.receive_queue != 0 {
            return Ok(false);
        }
        let mpdu = if session.abi == Abi::Session1 {
            // API77 API59 descriptor4 is Qu48. Its low nibble is the
            // original MAC ID, not an MLD firmware-link identity.
            super::super::scan_api::mpdu_gen2(&packet.payload)
        } else {
            super::super::scan_api::mpdu(&packet.payload)
        };
        let Some(mpdu) = mpdu else {
            return Ok(false);
        };
        let f = mpdu.frame;
        if f.len() < 24
            || f[0] & 15 != 0
            || f[1] & 0xc7 != 0
            || f[22] & 15 != 0
            || f[10] & 1 != 0
            || f[10..16] == [0; 6]
            || f[4..10] != session.own && f[4..10] != [255; 6]
        {
            return Ok(false);
        }
        if lease.closing
            || !lease.grant.current()
            || copied.is_none_or(|copy| !copy.current() || !copy.capture.same(&lease.grant.capture))
            || mpdu.channel != lease.channel.number
            || mpdu.raw_band != lease.channel.band as u8
            || mpdu.raw_fw_link
                != if session.abi == Abi::Session1 {
                    MAC as u8
                } else {
                    LINK as u8
                }
        {
            return Ok(f[4..10] == session.own);
        }
        session.start.check()?;
        lease.request.check()?;
        let Some(body) = mpdu.body(24, 0) else {
            return Ok(true);
        };
        if session.events.len() >= 64 {
            return Err("P2P copied native event ownership overflow");
        }
        let mut frame = f[..24].to_vec();
        frame.extend_from_slice(body);
        session.events.push_back(Event {
            kind: Kind::Management {
                rssi: mpdu.rssi,
                frame,
            },
            cookie: lease.cookie,
            frequency: lease.channel.frequency(),
            duration_ms: lease.duration_ms,
            receiver: lease.request.clone(),
            start: session.start.clone(),
            origin: lease.request.clone(),
            capture: lease.grant.capture.clone(),
            publication: Some(lease.grant.publication()),
            policy: lease.policy.clone(),
        });
        Ok(f[4..10] == session.own)
    }
    pub(super) fn reset_after_dma_stop(&mut self) {
        if let Some(session) = &mut self.session {
            if let Some(lease) = &session.grant {
                lease.grant.close();
            }
            let _ = session.epoch.advance();
            session.events.clear();
            self.retired.push(session.start.clone());
            if let Some(lease) = &session.grant {
                self.retired.push(lease.request.clone())
            }
        }
        self.gate = None;
        self.session = None;
    }
    pub(super) fn deny(&mut self) {
        if let Some(session) = &mut self.session {
            if let Some(lease) = &session.grant {
                lease.grant.close();
            }
            let _ = session.epoch.advance();
            session.events.clear();
        }
    }
}
impl Drop for State {
    fn drop(&mut self) {
        // This retires host copies only. Hardware's ManuallyDrop DMA owner
        // stays retained unless its independent stop proof succeeded.
        self.deny();
    }
}
impl Hardware {
    /// The actual FW_NUM_STATIONS/FW_NUM_LINKS facts bounding MLD firmware
    /// link/station ids (Linux mld.h `IWL_MLD_ALLOC_FN`). Linux allocates
    /// every vif's link and station ids from the one device-wide
    /// `fw_id_to_bss_conf`/`fw_id_to_link_sta` pool, so a live P2P DEVICE
    /// session's FW link1 and its last-station aux id stay claimed here and
    /// a further MLD link can never alias them.
    pub(in crate::iwlwifi) fn mld_fw_ids(
        &self,
    ) -> Result<super::super::sc_mlo::FwIds, &'static str> {
        let mut ids = super::super::sc_mlo::FwIds::new(self.p2p.counts.1, self.p2p.counts.0)?;
        if let Some(session) = &self.p2p.session {
            ids.claim(LINK as u8, session.aux_station)?;
        }
        Ok(ids)
    }

    /// PHY context ids for a further MLD link: PHY0 is the association
    /// link's, and a live P2P DEVICE session holds PHY1 (Linux shares
    /// `used_phy_ids` across vifs, `iwl_mld_allocate_fw_phy_id`).
    pub(in crate::iwlwifi) fn mld_phy_ids(&self) -> super::super::sc_mlo::PhyIds {
        let mut ids = super::super::sc_mlo::PhyIds::station();
        if self.p2p.session.is_some() {
            ids.claim(session::PHY as u8);
        }
        ids
    }

    /// A credit wait polls only one64-descriptor RFH batch. Consume the
    /// actual already-completed fallback prefix before native publication,
    /// including an END beyond that budget. A moving/full prefix remains a
    /// denial after this bounded attempt. Retain the original Frame gate
    /// across every poll; an internal lifecycle change cannot replace it.
    pub(in crate::iwlwifi) fn check_p2p_tx_publication(&mut self) -> Result<(), &'static str> {
        if !self.p2p_started() {
            return Ok(());
        }
        let gate = self.p2p.gate.clone().ok_or("P2P original TX gate absent")?;
        gate.transmission()?;
        for _ in 0..=RX_DEPTH / 64 {
            if !self.has_pending_rx() {
                return gate.transmission();
            }
            self.poll()?;
            gate.transmission()?;
        }
        if self.has_pending_rx() {
            return Err("P2P completed RX prefix kept moving before TX publication");
        }
        gate.transmission()
    }
    pub(in crate::iwlwifi) fn retain_gen2_p2p_adapter(
        &mut self,
        api: &super::super::firmware_api::FirmwareApi<'_>,
        nvm: &super::super::station_api::Nvm,
    ) {
        self.p2p.gen2 = super::super::p2p_gen2_wire::Adapter::read(api, nvm)
            .ok()
            .map(Box::new);
    }
    pub(in crate::iwlwifi) fn p2p_gen2_selected(&self) -> bool {
        self.p2p.gen2.is_some()
    }
    pub(super) fn p2p_gen2_prefix(&self) -> bool {
        self.p2p.gen2.is_some()
            && self.p2p.gate.is_none()
            && self.p2p.session.as_ref().is_some_and(|session| {
                session.abi == Abi::Session1
                    && session.grant.as_ref().is_some_and(|lease| lease.closing)
            })
    }
    pub(in crate::iwlwifi) fn p2p_operation(
        &mut self,
        request: Arc<Request>,
    ) -> Result<(), &'static str> {
        let session = self
            .p2p
            .session
            .as_ref()
            .ok_or("P2P original native START absent")?;
        session.start.check()?;
        request.check()?;
        if !session.start.same_receiver(&request) {
            return Err("P2P operation belongs to another original child");
        }
        self.p2p.gate = Some(Gate::new(session.start.clone(), Some(request), None));
        Ok(())
    }
    pub(in crate::iwlwifi) fn p2p_started(&self) -> bool {
        self.p2p.session.is_some()
    }
    pub(in crate::iwlwifi) fn p2p_same_receiver(&self, request: &Request) -> bool {
        self.p2p
            .session
            .as_ref()
            .is_some_and(|session| session.start.same_receiver(request))
    }
    pub(in crate::iwlwifi) fn p2p_supported(
        &self,
        api: &super::super::firmware_api::FirmwareApi<'_>,
    ) -> bool {
        let adapter = match Abi::read(api) {
            Ok(Abi::Roc6) => {
                self.uses_mld_station_protocol()
                    && [(3, 8, 3), (3, 9, 8)]
                        .into_iter()
                        .all(|(g, c, v)| self.command_version(g, c) == Some(v))
                    && matches!(self.command_version(3, 0xb), None | Some(1 | 99))
            }
            Ok(Abi::Session2) => {
                self.is_mvm89()
                    && [(3, 8, 2), (3, 9, 2), (1, 8, 4), (5, 8, 2)]
                        .into_iter()
                        .all(|(g, c, v)| self.command_version(g, c) == Some(v))
            }
            Ok(Abi::Session1) => self.p2p.gen2.is_some(),
            _ => false,
        };
        adapter && self.band_in_rx_supported()
            && matches!(self.command_version(1,0x1c),Some(9..=11))
            && self.versions == api.commands
            && self.p2p.counts == (api.num_stations, api.num_links)
            && matches!(api.num_stations, Some(2..=16))
            && matches!(api.num_links, Some(2..=4))
            && [(5,0x17,3),(1,0x1e,2)]
                .into_iter().all(|(g,c,v)| self.command_version(g,c)==Some(v))
            // Linux sends these fixed structs without inventory lookups.
            && matches!(self.command_version(3,0xc),None|Some(1|99))
    }
    pub(in crate::iwlwifi) async fn p2p_start_native(
        &mut self,
        api: &super::super::firmware_api::FirmwareApi<'_>,
        request: Arc<Request>,
    ) -> Result<(), &'static str> {
        // P2P owns FW link1/PHY1 by fixed id; an active further MLD link
        // may hold either, so the shared pool refuses the overlap.
        if self.p2p_started()
            || !self.p2p_supported(api)
            || self.failed
            || !self.resources.data.is_empty()
            || self
                .mld_link
                .as_ref()
                .is_some_and(|binding| binding.secondary().is_some())
        {
            return Err("P2P START requires its actual idle native adapter");
        }
        request.check()?;
        let own = request.own();
        self.p2p.gate = Some(Gate::new(request.clone(), None, None));
        self.p2p.session = Some(Box::new(Session {
            abi: Abi::read(api)?,
            broadcast_mfp: api.has_capability(109),
            own,
            start: request,
            epoch: Epoch::default(),
            grant: None,
            events: VecDeque::new(),
            sequence: 0,
            // The original station0 and FW-link0 remain reserved. The
            // separate last actual station is never inferred from mask width.
            aux_station: api.num_stations.ok_or("P2P actual station count absent")? - 1,
        }));
        self.prepare_receive_queues().await?;
        let mut mac = [0; 52];
        boot_context::put32(&mut mac, 0, MAC);
        boot_context::put32(&mut mac, 4, 1);
        boot_context::put32(&mut mac, 8, 6);
        mac[12..18].copy_from_slice(&own);
        boot_context::put32(&mut mac, 20, 2); // CONTROL_AND_MGMT, no extended GO discovery.
        super::super::ap_session::command(self, 3, 8, &mac).await?;
        let mut link = super::super::station_api::link(1, own, false, 1, 0, 1);
        boot_context::put32(&mut link, 4, LINK);
        boot_context::put32(&mut link, 8, MAC);
        boot_context::put32(&mut link, 36, 0); // P2P never advertises CCK basics.
        super::super::ap_session::command(self, 3, 9, &link).await
    }
    #[allow(clippy::too_many_arguments)]
    pub(in crate::iwlwifi) async fn p2p_begin_native(
        &mut self,
        request: Arc<Request>,
        policy: &super::super::mld_policy::Source,
        channel: Channel,
        nvm_channels: &[u8],
        rx_chains: u32,
        qualification: Option<super::super::mvm_boot::P2pPreparation>,
        cookie: u64,
        duration_ms: u32,
        activity: RocActivity,
        public: bool,
    ) -> Result<(), &'static str> {
        if cookie == 0
            || !(10..=MAX_MS).contains(&duration_ms)
            || channel.band == Band::Six
            || channel.number == 14
            || channel.index().is_none()
            || !nvm_channels.contains(&channel.number)
            || self.p2p.session.as_ref().is_none_or(|s| s.grant.is_some())
        {
            return Err("P2P ROC lacks original NVM/finite idle grant geometry");
        }
        let duration = Duration::from_ms(duration_ms)?;
        let session = self
            .p2p
            .session
            .as_mut()
            .ok_or("P2P device is not natively started")?;
        session.start.check()?;
        request.check()?;
        if !session.start.same_receiver(&request) {
            return Err("P2P ROC belongs to another live control child");
        }
        let own = session.own;
        let aux_station = session.aux_station;
        self.p2p.gate = Some(Gate::new(
            session.start.clone(),
            Some(request.clone()),
            None,
        ));
        session.grant = Some(Box::new(Lease {
            cookie,
            channel,
            duration_ms,
            deadline: narf_time::wall::monotonic_ns()
                .saturating_add((u64::from(duration_ms) + 2500) * 1_000_000),
            activity,
            request,
            grant: Grant::pending(session.epoch.advance()?),
            queue: None,
            queue_published: false,
            aux_published: false,
            add_published: false,
            closing: false,
            policy: None,
            public,
            phy_published: false,
            link_bound: false,
            native_ended: false,
        }));
        let abi = self.p2p.session.as_ref().unwrap().abi;
        let program = if abi == Abi::Session1 {
            let prepared = qualification.ok_or("API77 P2P original tag8 preparation absent")?;
            if prepared.own != own || prepared.channel != channel {
                return Err("API77 P2P tag8 belongs to another actual child/channel");
            }
            let domain = policy.snapshot()?;
            self.install_rf_policy(super::super::mld_policy::Authority::Transaction(
                policy
                    .transaction(&domain)?
                    .with_mvm_p2p(prepared.power.clone())?,
            ))?;
            let program = super::super::mld_policy::Program::new_mvm_p2p(
                &domain,
                prepared.firmware,
                channel.number,
                prepared.power.clone(),
                prepared.ibss,
                self.rf_policy_validity()?,
            )?;
            prepared.plan.apply(self).await?;
            program.emission_ready()?;
            self.install_rf_policy(super::super::mld_policy::Authority::Station(
                policy.bind(program.clone())?,
            ))?;
            program
        } else {
            if qualification.is_some() {
                return Err("P2P legacy tag8 cannot replace an API89/Sc/Bz power owner");
            }
            let domain = policy.snapshot()?;
            if super::super::connection::host_channel_power(&domain, channel.number, true).is_none()
            {
                return Err("P2P current host policy forbids active radiation");
            }
            self.install_rf_policy(super::super::mld_policy::Authority::Transaction(
                policy.transaction(&domain)?,
            ))?;
            let mcc =
                super::super::connection::regulatory_channels_in_domain(self, &domain).await?;
            let power = super::super::connection::channel_power(
                &domain,
                channel.number,
                &mcc.channels,
                true,
            )
            .ok_or("P2P native MCC/host ACTIVE/non-radar permission absent")?;
            let program = super::super::mld_policy::Program::new(
                &domain,
                mcc,
                channel.number,
                0,
                channel.number,
                power,
                None,
                self.rf_policy_validity()?,
            )?
            .with_ap()?;
            self.install_rf_policy(super::super::mld_policy::Authority::Station(
                policy.bind(program.clone())?,
            ))?;
            self.ensure_platform_power().await?;
            let mut body = super::super::station_api::tx_power(
                self.command_version(1, 0x9f)
                    .ok_or("P2P TX power ABI absent")?,
                power,
            )?;
            // ROCv6 AUX has no serving-link power owner. SESSION2's separate
            // PHY1/link1 must also stay below this actual SET_DEVICE ceiling;
            // neither path may target station0 with a SET_LINK command.
            // The idle-primary restriction makes this conservative across all
            // physical emissions; current host/MCC/SAR remain independent proofs.
            boot_context::put32(&mut body, 0, 1);
            super::super::ap_session::command(self, 1, 0x9f, &body).await?;
            program
        };
        match abi {
            Abi::Roc6 => {
                let mut aux = [0; 16];
                boot_context::put32(&mut aux, 0, u32::from(aux_station));
                self.p2p
                    .session
                    .as_mut()
                    .unwrap()
                    .grant
                    .as_mut()
                    .unwrap()
                    .aux_published = true;
                super::super::ap_session::command(self, 3, 0xb, &aux).await?;
            }
            Abi::Session1 | Abi::Session2 => self.p2p_prepare_session(channel, rx_chains).await?,
        }
        self.p2p
            .session
            .as_mut()
            .unwrap()
            .grant
            .as_mut()
            .unwrap()
            .queue_published = true;
        let queue = self.allocate_tx(aux_station, TID).await?;
        let lease = self.p2p.session.as_mut().unwrap().grant.as_mut().unwrap();
        lease.queue = Some(queue);
        lease.policy = Some(policy.bind(program)?);
        lease.deadline = narf_time::wall::monotonic_ns()
            .saturating_add((u64::from(duration_ms) + 2500) * 1_000_000);
        lease.add_published = true;
        // START may be copied while this ACK is held; observe() opens only
        // from that exact native notification, never this command receipt.
        match abi {
            Abi::Roc6 => {
                super::super::ap_session::command(
                    self,
                    3,
                    p2p_wire::ROC,
                    &abi.roc_add(activity, aux_station, channel, own, duration)?,
                )
                .await
            }
            Abi::Session1 | Abi::Session2 => {
                super::super::ap_session::command(
                    self,
                    3,
                    p2p_wire::SESSION,
                    &abi.session_add(
                        if abi == Abi::Session1 {
                            Target::Mac(MAC as u8)
                        } else {
                            Target::Link(LINK as u8)
                        },
                        activity,
                        duration,
                    )?,
                )
                .await
            }
        }
    }
    pub(in crate::iwlwifi) fn p2p_needs_retirement(&self) -> bool {
        self.p2p.session.as_ref().is_some_and(|s| {
            s.start.check().is_err()
                || s.grant.as_ref().is_some_and(|l| {
                    l.closing
                        || l.request.check().is_err()
                        || l.grant.started() && !l.grant.current()
                        || narf_time::wall::monotonic_ns() >= l.deadline
                })
        })
    }
    pub(in crate::iwlwifi) fn p2p_take_events(&mut self) -> Vec<Event> {
        self.p2p
            .session
            .as_mut()
            .map_or_else(Vec::new, |s| s.events.drain(..).collect())
    }
    pub(in crate::iwlwifi) fn p2p_take_retired(&mut self) -> Vec<Arc<Request>> {
        // Request holds the original event sink. Defer its final Arc drop
        // until the retained frontend releases both State and Work guards.
        core::mem::take(&mut self.p2p.retired)
    }
    /// STOP/REMOVE is non-emitting. Close copies/TX first, then detach the
    /// original emitting request so its revocation cannot forbid cleanup.
    /// A missing/ambiguous receipt retains Hardware allocations; the parent
    /// must then drive its existing physical reset/BME-off stop owner.
    pub(in crate::iwlwifi) async fn p2p_retire_native(
        &mut self,
        stop: bool,
    ) -> Result<Vec<Event>, &'static str> {
        let Some(session) = self.p2p.session.as_mut() else {
            return Ok(Vec::new());
        };
        let capture = session.epoch.advance()?;
        let aux_station = session.aux_station;
        let abi = session.abi;
        let own = session.own;
        if let Some(lease) = &mut session.grant {
            lease.grant.close();
            lease.closing = true;
        }
        session.events.clear();
        self.p2p.gate = None;
        self.clear_rf_policy();
        if self.failed {
            return Err("P2P uncertain native owner requires physical reset");
        }
        if let Some(lease) = self.p2p.session.as_ref().unwrap().grant.as_ref() {
            if lease.queue_published && lease.queue.is_none() {
                return Err("P2P uncertain native queue allocation requires physical reset");
            }
            if lease.add_published && !lease.native_ended {
                match abi {
                    Abi::Roc6 => {
                        super::super::ap_session::command(
                            self,
                            3,
                            p2p_wire::ROC,
                            &abi.roc_remove(lease.activity)?,
                        )
                        .await?
                    }
                    Abi::Session1 | Abi::Session2 => {
                        super::super::ap_session::command(
                            self,
                            3,
                            p2p_wire::SESSION,
                            &abi.session_remove(
                                if abi == Abi::Session1 {
                                    Target::Mac(MAC as u8)
                                } else {
                                    Target::Link(LINK as u8)
                                },
                                lease.activity,
                            )?,
                        )
                        .await?
                    }
                }
            }
            // Synchronous REMOVE forbids future notifications of this ROC.
            // All real RFH markers retire the already-captured prefix before
            // an identical activity ID can be admitted to a fresh lease.
            self.close_receive_epoch()?;
            self.synchronize_receive_epoch().await?;
            let (queue, aux) = {
                let lease = self.p2p.session.as_ref().unwrap().grant.as_ref().unwrap();
                (lease.queue, lease.aux_published)
            };
            if let Some(queue) = queue {
                self.ap_flush_station(aux_station).await?;
                self.remove_idle_tx(queue, aux_station, TID).await?;
            }
            if aux {
                if abi == Abi::Session1 {
                    let body = self
                        .p2p
                        .gen2
                        .as_ref()
                        .ok_or("P2P original API77 station adapter absent")?
                        .remove();
                    super::super::ap_session::command(self, 1, 0x19, &body).await?;
                } else {
                    self.ap_remove_peer(aux_station).await?;
                }
            }
            if matches!(abi, Abi::Session1 | Abi::Session2) {
                let channel = self
                    .p2p
                    .session
                    .as_ref()
                    .unwrap()
                    .grant
                    .as_ref()
                    .unwrap()
                    .channel;
                self.p2p_unlink_session(own, channel).await?;
            }
        }
        let session = self.p2p.session.as_mut().unwrap();
        let lease = session.grant.take();
        if let Some(lease) = &lease {
            self.p2p.retired.push(lease.request.clone())
        }
        let event = lease.filter(|lease| lease.public).map(|lease| Event {
            kind: Kind::Expired,
            cookie: lease.cookie,
            frequency: lease.channel.frequency(),
            duration_ms: lease.duration_ms,
            receiver: lease.request.clone(),
            start: session.start.clone(),
            origin: lease.request,
            capture,
            publication: None,
            policy: None,
        });
        let own = session.own;
        if stop {
            self.p2p.retired.push(session.start.clone());
            let mut link = super::super::station_api::link(3, own, false, 1, 0, 1);
            boot_context::put32(&mut link, 4, LINK);
            boot_context::put32(&mut link, 8, MAC);
            boot_context::put32(&mut link, 36, 0); // P2P REMOVE keeps CCK basics absent.
            super::super::ap_session::command(self, 3, 9, &link).await?;
            let mut mac = [0; 52];
            boot_context::put32(&mut mac, 0, MAC);
            boot_context::put32(&mut mac, 4, 3);
            boot_context::put32(&mut mac, 8, 6);
            mac[12..18].copy_from_slice(&own);
            boot_context::put32(&mut mac, 20, 2);
            super::super::ap_session::command(self, 3, 8, &mac).await?;
            self.p2p.session = None;
        } else {
            self.p2p.gate = Some(Gate::new(
                self.p2p.session.as_ref().unwrap().start.clone(),
                None,
                None,
            ));
        }
        Ok(event.into_iter().collect())
    }
    pub(in crate::iwlwifi) fn p2p_granted(&self, frequency: u32) -> bool {
        self.p2p
            .session
            .as_ref()
            .and_then(|s| s.grant.as_ref())
            .is_some_and(|l| !l.closing && l.channel.frequency() == frequency && l.grant.current())
    }
    pub(in crate::iwlwifi) fn p2p_cookie(&self) -> Option<u64> {
        Some(self.p2p.session.as_ref()?.grant.as_ref()?.cookie)
    }
    pub(in crate::iwlwifi) fn p2p_frequency(&self) -> Option<u32> {
        Some(
            self.p2p
                .session
                .as_ref()?
                .grant
                .as_ref()?
                .channel
                .frequency(),
        )
    }
    pub(in crate::iwlwifi) fn p2p_start_retired(&self) -> bool {
        self.p2p
            .session
            .as_ref()
            .is_some_and(|s| s.start.check().is_err())
    }
    pub(in crate::iwlwifi) async fn p2p_transmit_native(
        &mut self,
        request: Arc<Request>,
        frequency: u32,
        frame: &[u8],
        antenna: u32,
    ) -> Result<bool, &'static str> {
        let session = self
            .p2p
            .session
            .as_mut()
            .ok_or("P2P native device absent")?;
        let lease = session
            .grant
            .as_ref()
            .ok_or("P2P FRAME has no native ROC owner")?;
        if !session.start.same_receiver(&request) {
            return Err("P2P FRAME belongs to another live control child");
        }
        if !matches!(antenna, 1 | 2)
            || frame.len() < 24
            || frame.len() > 4095
            || !matches!(frame[0], 0x40 | 0xd0)
            || frame[1] & 0xc7 != 0
            || frame[10..16] != session.own
            || frame[22] & 15 != 0
            || frequency != lease.channel.frequency()
            || lease.closing
            || !lease.grant.current()
        {
            return Err("P2P FRAME lacks exact current native grant/management identity");
        }
        let queue = lease
            .queue
            .ok_or("P2P native AUX queue lacks allocation receipt")?;
        self.p2p.gate = Some(Gate::frame(
            session.start.clone(),
            request,
            lease.request.clone(),
            lease.grant.publication(),
        ));
        let mut frame = frame.to_vec();
        frame[22..24].copy_from_slice(&((session.sequence & 4095) << 4).to_le_bytes());
        session.sequence = (session.sequence + 1) & 4095;
        // Linux P2P is no-CCK even in2.4GHz. Actual admitted Sc/Bz ratev3
        // uses OFDM6 legacy index0 +modulationbit8 +actual single TX chain.
        let rate = (antenna << 14) | if session.abi == Abi::Roc6 { 0x100 } else { 13 };
        let result = self.transmit_ap(queue, &frame, 24, Some(rate), false).await;
        if let Some(session) = self.p2p.session.as_ref() {
            self.p2p.gate = Some(Gate::new(
                session.start.clone(),
                session.grant.as_ref().map(|l| l.request.clone()),
                None,
            ));
        }
        match result {
            Ok(()) => Ok(true),
            Err(TX_FAILED) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

#[path = "runtime_p2p_session.rs"]
mod session;
