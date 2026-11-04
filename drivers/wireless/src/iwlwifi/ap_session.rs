//! Retained AP MAC/link, multi-peer TVQM/key and userspace-SME owner.
//! Native protocol adapters grant no AP role without this complete owner.
use super::{
    ap_wire::{self, Plan},
    boot_context::{put32, put64},
    runtime::Hardware,
};
use alloc::{sync::Arc, vec, vec::Vec};
use narf_lib::sync::IrqSafeSpinLock;
use narf_wireless::{
    ApStartSettings, ControlPortTxRequest, KeyParams, P2pGoPowerSave, StationConfig,
};

pub(super) struct Peer {
    pub id: u8,
    pub config: StationConfig,
    pub queues: [u16; 4],
    pub management: u16,
    pub authorized: bool,
    key: Option<Key>,
    pn: [u64; 17],
    management_pn: u64,
}
#[derive(Clone, Copy)]
struct Key {
    id: u8,
    station: u8,
    flags: u32,
    digest: [u8; 32],
    floor: u64,
    software: bool,
}

pub(super) struct Session {
    pub plan: Plan,
    pub proof: Arc<super::ap_owner::Owner>,
    pub program: super::mld_policy::Program,
    pub settings: ApStartSettings,
    /// Version counter for the driver-owned GO NoA attribute: 0 at GO
    /// start, +1 per live power-save update. Ordinary AP sessions
    /// never use it (their plans refuse `p2p_go`).
    pub go_noa_index: u8,
    pub peers: Vec<Peer>,
    pub epoch: u64,
    data_epoch: super::ap_owner::DataEpoch,
    own: [u8; 6],
    chains: u32,
    bcast: u16,
    mcast: u16,
    sequence: u16,
    groups: Vec<Key>,
    bip: Vec<bip::Key>,
    go_gtk: Vec<super::p2p_go_key::Gtk>,
    latest_gtk: Option<u8>,
    latest_igtk: Option<u8>,
    default_gtk: Option<u8>,
    default_igtk: Option<u8>,
    history: Arc<IrqSafeSpinLock<super::sc_security::KeyHistory>>,
    qualification: Option<alloc::boxed::Box<super::mvm_boot::ApPreparedPower>>,
}
pub(super) fn supported(hw: &Hardware) -> bool {
    let tuple = if hw.is_mvm89() {
        [(3, 8, 2), (3, 9, 2), (1, 8, 4), (1, 0x91, 13), (5, 0xf, 4)]
    } else if hw.uses_mld_station_protocol() {
        [(3, 8, 3), (3, 9, 8), (1, 8, 6), (1, 0x91, 14), (5, 0xf, 6)]
    } else {
        return false;
    };
    tuple
        .into_iter()
        .all(|(g, c, v)| hw.command_version(g, c) == Some(v))
        && hw.command_version(5, 0x18) == Some(1)
        && hw.command_version(5, 0x17) == Some(3)
        && hw.command_version(1, 0x1e) == Some(2)
}
impl Session {
    #[allow(clippy::too_many_arguments)]
    pub async fn prepare(
        hw: &mut Hardware,
        plan: Plan,
        settings: ApStartSettings,
        own: [u8; 6],
        chains: u32,
        policy: &super::mld_policy::Source,
        proof: Arc<super::ap_owner::Owner>,
        history: Arc<IrqSafeSpinLock<super::sc_security::KeyHistory>>,
        request: Arc<super::ap_owner::Request>,
    ) -> Result<Self, &'static str> {
        if !supported(hw) {
            return Err("actual native AP command consumer unsupported");
        }
        proof.check()?;
        let domain = policy.snapshot()?;
        if super::connection::host_channel_power(&domain, plan.channel.number, true).is_none() {
            return Err("AP signed host policy forbids initial radiation");
        }
        hw.clear_rf_policy();
        hw.ap_request(Some(request))?;
        hw.install_rf_policy(super::mld_policy::Authority::Transaction(
            policy.transaction(&domain)?,
        ))?;
        let mcc = super::connection::regulatory_channels_in_domain(hw, &domain).await?;
        let power =
            super::connection::channel_power(&domain, plan.channel.number, &mcc.channels, true)
                .ok_or("AP native MCC/host ACTIVE/non-radar permission absent")?;
        let program = super::mld_policy::Program::new(
            &domain,
            mcc,
            plan.channel.number,
            0,
            plan.channel.number,
            power,
            None,
            hw.rf_policy_validity()?,
        )?
        .with_ap()?;
        let program = if let Some(go) = plan.go {
            program.with_go(go.binding(own, plan.channel))?
        } else {
            program
        };
        hw.install_rf_policy(super::mld_policy::Authority::Station(
            policy.bind(program.clone())?,
        ))?;
        Self::prepare_native(
            hw, plan, settings, own, chains, proof, history, program, None,
        )
        .await
    }
    #[allow(clippy::too_many_arguments)]
    pub(in crate::iwlwifi) async fn prepare_native(
        hw: &mut Hardware,
        plan: Plan,
        settings: ApStartSettings,
        own: [u8; 6],
        chains: u32,
        proof: Arc<super::ap_owner::Owner>,
        history: Arc<IrqSafeSpinLock<super::sc_security::KeyHistory>>,
        program: super::mld_policy::Program,
        power: Option<alloc::boxed::Box<super::mvm_boot::ApPowerPlan>>,
    ) -> Result<Self, &'static str> {
        if hw.ap_legacy_selected() != power.is_some() {
            return Err("AP native adapter lacks exact role-qualified power owner");
        }
        hw.source_fence()?.invoke(|| Ok(()))?;
        hw.install_ap_owner(proof.clone())?;
        let epoch = hw.close_receive_epoch()?;
        hw.prepare_receive_queues().await?;
        // Replace the ordinary inactive default, never relabel a live STA.
        command(
            hw,
            3,
            9,
            &super::station_api::link(3, own, false, plan.channel.number, 0, 1),
        )
        .await?;
        command(hw, 3, 8, &super::station_api::mac(3, own, None)).await?;
        if let Some(identity) = plan.go {
            // This is a real old-role cutoff, not an empty software queue.
            // Capture the exact pending GO before publishing its new MAC so
            // NoA copied during the ADD ACK wait cannot be lost or backfilled.
            retire_epoch(hw, &[], own, plan.channel).await?;
            hw.begin_go_capture(identity, own, proof.clone())?;
        }
        command(hw, 3, 8, &ap_wire::mac(1, own, false)).await?;
        command(
            hw,
            3,
            9,
            &super::station_api::link(1, own, false, plan.channel.number, 0, 1),
        )
        .await?;
        hw.ap_phy(&super::station_api::phy_channel(1, plan.channel))
            .await?;
        let qualification = if let Some(power) = power {
            Some(alloc::boxed::Box::new(power.apply(hw).await?))
        } else {
            None
        };
        program.emission_ready()?;
        command(hw, 3, 9, &plan.link(own, true)).await?;
        if qualification.is_none() {
            hw.ensure_platform_power().await?;
            let power = super::station_api::tx_power(
                hw.command_version(1, 0x9f)
                    .ok_or("AP native TX power ABI absent")?,
                program.power(),
            )?;
            command(hw, 1, 0x9f, &power).await?;
        }
        hw.ap_peer(&ap_wire::internal(ap_wire::MCAST, 2)).await?;
        let mcast = hw.allocate_tx(ap_wire::MCAST, 0).await?;
        hw.ap_peer(&ap_wire::internal(ap_wire::BCAST, 1)).await?;
        let bcast = hw.allocate_tx(ap_wire::BCAST, 15).await?;
        open_epoch(hw, epoch, &[], own, plan.channel).await?;
        if plan.go.is_some() {
            hw.finish_go_capture()?;
        }
        proof.check()?;
        hw.source_fence()?.invoke(|| Ok(()))?;
        Ok(Self {
            plan,
            proof,
            program,
            settings,
            go_noa_index: 0,
            peers: Vec::new(),
            epoch,
            data_epoch: Default::default(),
            own,
            chains,
            bcast,
            mcast,
            sequence: 0,
            groups: Vec::new(),
            bip: Vec::new(),
            go_gtk: Vec::new(),
            latest_gtk: None,
            latest_igtk: None,
            default_gtk: None,
            default_igtk: None,
            history,
            qualification,
        })
    }
    pub(super) fn data_publication(&self) -> super::ap_owner::DataPublication {
        self.data_epoch.publication()
    }
    /// The original retained owner must install any early group keys first.
    /// No native beacon publication occurs during prepare/early-key staging.
    pub async fn enable_beacon(&self, hw: &mut Hardware) -> Result<(), &'static str> {
        self.current()?;
        let version = hw
            .command_version(1, 0x91)
            .ok_or("AP beacon ABI vanished")?;
        let body = self.plan.beacon_command(version)?;
        command(hw, 1, 0x91, &body).await?;
        self.current()?;
        hw.source_fence()?.invoke(|| Ok(()))
    }
    pub async fn beacon(
        &mut self,
        hw: &mut Hardware,
        head: Option<Vec<u8>>,
        tail: Option<Vec<u8>>,
        probe: Option<Vec<u8>>,
    ) -> Result<(), &'static str> {
        self.current()?;
        let mut config = self.plan.config.clone();
        if let Some(head) = head {
            config.beacon_head = head;
        }
        if let Some(tail) = tail {
            config.beacon_tail = tail;
        }
        if let Some(probe) = probe {
            config.probe_resp = Some(probe);
        }
        let plan = if self.plan.go.is_some() {
            Plan::new_go(config, &self.settings, self.own, self.go_noa_index)?
        } else {
            Plan::new(config, &self.settings, self.own)?
        };
        self.install_plan(hw, plan).await
    }
    /// Shared beacon-template install tail: identity/security/channel/
    /// basic-rate stability, template + link re-send, plan commit.
    async fn install_plan(&mut self, hw: &mut Hardware, plan: Plan) -> Result<(), &'static str> {
        if plan.go != self.plan.go {
            return Err("GO device identity change needs a fresh native role owner");
        }
        if plan.rsn != self.plan.rsn
            || plan.channel != self.plan.channel
            || plan.rates.basic != self.plan.rates.basic
        {
            return Err("AP security/channel/basic-rate change needs a new BSS owner");
        }
        let version = hw.command_version(1, 0x91).ok_or("AP beacon ABI changed")?;
        let template = plan.beacon_command(version)?;
        command(hw, 1, 0x91, &template).await?;
        command(hw, 3, 9, &plan.link(self.own, true)).await?;
        self.current()?;
        self.plan = plan;
        Ok(())
    }
    /// Live GO CTWindow/OPPPS update (the
    /// `set_p2p_go_power_save_ap_async` native contract). `None`
    /// fields preserve the live value, per `P2pGoPowerSave` semantics;
    /// `Some(0)`/`Some(false)` reset. Bumps the NoA index and
    /// re-sends the beacon template through the same install path as
    /// `beacon()`. Refuses non-GO sessions: the ordinary AP plan
    /// refuses `p2p_go` outright. Settings/index commit only after
    /// the template install succeeds, so a failed send leaves the
    /// session advertising its previous schedule.
    pub async fn set_go_power_save(
        &mut self,
        hw: &mut Hardware,
        settings: P2pGoPowerSave,
    ) -> Result<(), &'static str> {
        self.current()?;
        if self.plan.go.is_none() {
            return Err("GO power save needs an actual GO session");
        }
        settings
            .validate()
            .map_err(|_| "GO power-save CTWindow exceeds 127")?;
        let current = self.settings.p2p_go.unwrap_or_default();
        let merged = P2pGoPowerSave {
            ctwindow_tu: settings.ctwindow_tu.or(current.ctwindow_tu),
            opportunistic: settings.opportunistic.or(current.opportunistic),
        };
        let mut next_settings = self.settings.clone();
        next_settings.p2p_go = Some(merged);
        let next_index = self.go_noa_index.wrapping_add(1);
        let plan = Plan::new_go(
            self.plan.config.clone(),
            &next_settings,
            self.own,
            next_index,
        )?;
        self.install_plan(hw, plan).await?;
        self.settings = next_settings;
        self.go_noa_index = next_index;
        Ok(())
    }
    pub fn current(&self) -> Result<(), &'static str> {
        self.proof.check()?;
        self.program.emission_ready()?;
        if self.program.go_binding()
            != self
                .plan
                .go
                .map(|go| go.binding(self.own, self.plan.channel))
        {
            return Err("AP/GO native program differs from original physical role");
        }
        // The retained actual record and native power receipt owner lives
        // with this Session; its current cap/host ceiling is in Program.
        if let Some(qualification) = &self.qualification {
            if if self.plan.go.is_some() {
                !qualification.is_go()
            } else {
                !qualification.is_ap()
            } {
                return Err("AP session inherited another emitting qualification");
            }
        }
        Ok(())
    }
    pub fn ready_peer(&self, peer: &Peer) -> bool {
        !self.plan.secure()
            || peer.key.is_some()
                && self.default_installed(false)
                && (!peer.config.mfp.unwrap_or(false) || self.default_installed(true))
    }
    fn group_installed(&self, id: u8, management: bool) -> bool {
        self.groups.iter().any(|key| {
            key.id == id
                && key.station
                    == if management {
                        ap_wire::BCAST
                    } else {
                        ap_wire::MCAST
                    }
                && if management {
                    matches!(id, 4 | 5)
                        && (!key.software || self.bip.iter().any(|key| key.id() == id))
                } else {
                    id <= 3
                        && (!key.software
                            || self.plan.go.is_some() && self.go_gtk.iter().any(|gtk| gtk.id == id))
                }
        })
    }
    fn default_installed(&self, management: bool) -> bool {
        let (selected, latest) = if management {
            (self.default_igtk, self.latest_igtk)
        } else {
            (self.default_gtk, self.latest_gtk)
        };
        selected.is_some_and(|id| latest == Some(id) && self.group_installed(id, management))
    }
    pub async fn add_peer(
        &mut self,
        hw: &mut Hardware,
        mut config: StationConfig,
    ) -> Result<(), &'static str> {
        self.current()?;
        if self
            .peers
            .iter()
            .any(|p| p.config.mac == config.mac || p.config.aid == config.aid)
        {
            return Err("AP duplicate peer/AID");
        }
        let id = (ap_wire::FIRST_PEER..ap_wire::FIRST_PEER + ap_wire::MAX_PEERS as u8)
            .find(|id| !self.peers.iter().any(|p| p.id == *id))
            .ok_or("AP station table full")?;
        let authorized = config
            .authorized
            .unwrap_or(!self.settings.control_port.enabled);
        if authorized && self.plan.secure() {
            return Err("AP secure peer has no native PTK receipt");
        }
        config.authorized = Some(authorized);
        self.validate_peer(&config)?;
        let body = ap_wire::peer(id, &config)?;
        let rates = self.peer_rates(&config)?;
        let mut tlc = rates.tlc(6, self.chains)?;
        put32(&mut tlc, 0, 1u32 << id);
        if authorized {
            // An initially authorized Open peer also changes admission from
            // absent/denied. Do not adopt DATA queued before host admission.
            self.epoch = hw.close_receive_epoch()?;
        }
        hw.ap_peer(&body).await?;
        let mut queues = [0; 4];
        for (i, &tid) in super::qos::TIDS.iter().enumerate() {
            queues[i] = hw.allocate_tx(id, tid).await?;
        }
        let management = hw.allocate_tx(id, 15).await?;
        hw.ap_tlc(&tlc, id).await?;
        command(hw, 3, 8, &ap_wire::mac(2, self.own, true)).await?;
        self.current()?;
        self.peers.push(Peer {
            id,
            config,
            queues,
            management,
            authorized: false,
            key: None,
            pn: [0; 17],
            management_pn: 0,
        });
        if authorized {
            open_epoch(hw, self.epoch, &self.peers, self.own, self.plan.channel).await?;
            self.current()?;
            self.peers.last_mut().unwrap().authorized = true;
        }
        Ok(())
    }
    fn validate_peer(&self, c: &StationConfig) -> Result<(), &'static str> {
        if self.plan.pmf_required() && !c.mfp.unwrap_or(false)
            || c.mfp.unwrap_or(false)
                && self
                    .plan
                    .rsn
                    .as_ref()
                    .is_none_or(|r| r.rsn_capabilities & 0x80 == 0)
            || c.uapsd_queues.unwrap_or(0) != 0 && !c.wme.unwrap_or(false)
        {
            return Err("AP peer PMF/UAPSD facts disagree with requested BSS");
        }
        Ok(())
    }
    fn peer_rates(&self, c: &StationConfig) -> Result<super::rates::Rates, &'static str> {
        if c.supported_rates.is_empty() || c.supported_rates.len() > 32 {
            return Err("AP peer rates absent/oversized");
        }
        let mut ies = vec![1, c.supported_rates.len() as u8];
        ies.extend_from_slice(&c.supported_rates);
        let mut rates = super::rates::Rates::parse(&ies, self.plan.channel.number)?;
        rates.supported &= self.plan.rates.supported;
        if rates.supported & self.plan.rates.basic != self.plan.rates.basic {
            return Err("AP peer omitted BSS basic rate");
        }
        rates.basic = self.plan.rates.basic;
        Ok(rates)
    }
    pub async fn set_peer(
        &mut self,
        hw: &mut Hardware,
        mut c: StationConfig,
    ) -> Result<(), &'static str> {
        self.current()?;
        let index = self
            .peers
            .iter()
            .position(|p| p.config.mac == c.mac)
            .ok_or("AP peer not present")?;
        let old = &self.peers[index];
        if c.aid == 0 {
            c.aid = old.config.aid;
        }
        if c.listen_interval == 0 {
            c.listen_interval = old.config.listen_interval;
        }
        if c.supported_rates.is_empty() {
            c.supported_rates = old.config.supported_rates.clone();
        }
        if c.wme.is_none() {
            c.wme = old.config.wme;
        }
        if c.mfp.is_none() {
            c.mfp = old.config.mfp;
        }
        if c.uapsd_queues.is_none() {
            c.uapsd_queues = old.config.uapsd_queues;
        }
        if c.uapsd_max_sp.is_none() {
            c.uapsd_max_sp = old.config.uapsd_max_sp;
        }
        if c.mfp != old.config.mfp && old.key.is_some() {
            return Err("AP PMF mode change needs a fresh peer/key owner");
        }
        let authorized = c.authorized.unwrap_or(old.authorized);
        c.authorized = Some(authorized);
        if authorized && !self.ready_peer(old) {
            return Err("AP authorization lacks actual native key/default receipts");
        }
        self.validate_peer(&c)?;
        let body = ap_wire::peer(old.id, &c)?;
        let rates = self.peer_rates(&c)?;
        let mut tlc = rates.tlc(6, self.chains)?;
        put32(&mut tlc, 0, 1u32 << old.id);
        let authorization_change = authorized != old.authorized;
        if authorization_change {
            // STA/TLC receipts do not delimit packets already in RFH or
            // copied for publication. Deny both old copies and new capture
            // before either native wait, without replacing any key/PN owner.
            self.epoch = hw.close_receive_epoch()?;
            self.peers[index].authorized = false;
        }
        hw.ap_peer(&body).await?;
        hw.ap_tlc(&tlc, self.peers[index].id).await?;
        if authorization_change {
            open_epoch(hw, self.epoch, &self.peers, self.own, self.plan.channel).await?;
        }
        self.current()?;
        self.peers[index].config = c;
        self.peers[index].authorized = authorized;
        Ok(())
    }
    pub async fn remove_peer(
        &mut self,
        hw: &mut Hardware,
        mac: [u8; 6],
    ) -> Result<(), &'static str> {
        let index = self
            .peers
            .iter()
            .position(|p| p.config.mac == mac)
            .ok_or("AP peer not present")?;
        self.peers[index].authorized = false;
        self.epoch = hw.close_receive_epoch()?;
        let peer = &self.peers[index];
        hw.ap_flush_station(peer.id).await?;
        if let Some(key) = peer.key {
            remove_key(hw, key).await?;
        }
        hw.remove_tx(peer.management, peer.id, 15).await?;
        for (i, &queue) in peer.queues.iter().enumerate() {
            hw.remove_tx(queue, peer.id, super::qos::TIDS[i]).await?;
        }
        hw.ap_remove_peer(peer.id).await?;
        self.peers.remove(index);
        open_epoch(hw, self.epoch, &self.peers, self.own, self.plan.channel).await?;
        command(hw, 3, 8, &ap_wire::mac(2, self.own, !self.peers.is_empty())).await
    }
    pub async fn key(&mut self, hw: &mut Hardware, p: &KeyParams) -> Result<(), &'static str> {
        self.current()?;
        if p.key.len() != 16 || !self.plan.secure() || (!p.seq.is_empty() && p.seq.len() != 6) {
            return Err("AP key material/cipher/RSC contract invalid");
        }
        let floor = if p.seq.is_empty() {
            0
        } else {
            u64::from_le_bytes([
                p.seq[0], p.seq[1], p.seq[2], p.seq[3], p.seq[4], p.seq[5], 0, 0,
            ])
        };
        let peer = if p.pairwise {
            Some(
                self.peers
                    .iter()
                    .position(|x| Some(x.config.mac) == p.peer)
                    .ok_or("AP PTK names no actual peer")?,
            )
        } else {
            None
        };
        let igtk = !p.pairwise && matches!(p.idx, 4 | 5);
        if igtk
            && self
                .plan
                .rsn
                .as_ref()
                .is_none_or(|r| r.rsn_capabilities & 0x80 == 0)
        {
            return Err("AP IGTK has no advertised PMF capability");
        }
        if p.pairwise && (p.idx != 0 || p.cipher != narf_wireless::CIPHER_SUITE_CCMP)
            || !p.pairwise
                && (p.peer.is_some()
                    || p.idx > 5
                    || p.cipher
                        != if igtk {
                            narf_wireless::CIPHER_SUITE_AES_CMAC
                        } else {
                            narf_wireless::CIPHER_SUITE_CCMP
                        })
            || p.default_mgmt && !igtk
        {
            return Err("AP key identity/cipher has no native role");
        }
        let station = peer.map_or(if igtk { ap_wire::BCAST } else { ap_wire::MCAST }, |i| {
            self.peers[i].id
        });
        let pmf = peer.is_some_and(|i| self.peers[i].config.mfp.unwrap_or(false));
        let material: &[u8; 16] = p.key.as_slice().try_into().unwrap();
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(material);
        let digest = hash.finalize();
        let old = peer.and_then(|i| self.peers[i].key).or_else(|| {
            self.groups
                .iter()
                .find(|k| k.id == p.idx && k.station == station)
                .copied()
        });
        if old.is_some_and(|k| k.digest == digest) {
            if self.plan.go.is_some() && peer.is_none() {
                if igtk {
                    if let Some(key) = self.bip.iter_mut().find(|key| key.id() == p.idx) {
                        key.raise_floor(floor);
                    }
                } else if let Some(key) = self.go_gtk.iter_mut().find(|key| key.id == p.idx) {
                    key.raise_floor(floor);
                }
            }
            if let Some(i) = peer {
                for pn in &mut self.peers[i].pn {
                    *pn = (*pn).max(floor);
                }
            }
            if p.default_mgmt {
                self.default_key(p.idx, false, false, true, false)?;
            }
            hw.source_fence()?.invoke(|| Ok(()))?;
            return Ok(());
        }
        let authorized = peer.is_some_and(|i| self.peers[i].authorized);
        self.history.lock().reserve([Some(material), None, None])?;
        self.epoch = hw.close_receive_epoch()?;
        if let Some(i) = peer {
            self.peers[i].authorized = false;
        } else if igtk {
            self.default_igtk = None;
        } else {
            self.default_gtk = None;
        }
        hw.ap_flush_station(station).await?;
        if let Some(old) = old {
            remove_key(hw, old).await?;
        }
        let mut body =
            super::sc_security::key_command(p.idx, !p.pairwise, pmf, Some(material), floor)?;
        put32(&mut body[..], 4, 1u32 << station);
        let flags = u32::from_le_bytes(body[12..16].try_into().unwrap()) & !8; // AP group is TX, never station NO_TX.
        put32(&mut body[..], 12, flags);
        put64(&mut body[..], 72, 0);
        let host_gtk = self.plan.go.is_some() && peer.is_none() && !igtk;
        let software = peer.is_none() && (self.plan.go.is_some() || igtk && hw.ap_software_bip());
        let gtk = if host_gtk {
            Some(super::p2p_go_key::Gtk::new(
                p.idx, *material, self.own, floor,
            )?)
        } else {
            None
        };
        let bip = if software && igtk {
            // Linux chooses host CMAC on this actual capability profile.
            // The exact native flush/RX/source prefix still owns transition;
            // no fabricated empty SEC_KEY receipt promotes a host IGTK.
            let key = bip::Key::new(p.idx, *material)?;
            Some(if self.plan.go.is_some() {
                key.with_floor(floor)?
            } else {
                key
            })
        } else if host_gtk {
            None
        } else {
            command(hw, 5, 0x18, &body[..]).await?;
            None
        };
        open_epoch(hw, self.epoch, &self.peers, self.own, self.plan.channel).await?;
        self.current()?;
        let key = Key {
            id: p.idx,
            station,
            flags,
            digest,
            floor,
            software,
        };
        if let Some(i) = peer {
            self.peers[i].key = Some(key);
            self.peers[i].pn = [floor; 17];
            self.peers[i].management_pn = 0;
            self.peers[i].authorized = authorized;
        } else {
            self.bip.retain(|key| key.id() != p.idx);
            self.go_gtk.retain(|key| key.id != p.idx);
            if let Some(key) = gtk {
                self.go_gtk.push(key);
            }
            if let Some(key) = bip {
                self.bip.push(key);
            }
            self.groups
                .retain(|k| k.id != p.idx || k.station != station);
            self.groups.push(key);
            if igtk {
                self.latest_igtk = Some(p.idx);
                if p.default_mgmt {
                    self.default_igtk = Some(p.idx);
                }
            } else {
                self.latest_gtk = Some(p.idx);
            }
        }
        Ok(())
    }
    pub async fn delete_key(
        &mut self,
        hw: &mut Hardware,
        id: u8,
        pairwise: bool,
        peer: Option<[u8; 6]>,
    ) -> Result<(), &'static str> {
        self.current()?;
        // Invalid DEL_KEY is a pure refusal. In particular, looking up a
        // wrong index must not consume an installed PTK or close live RX.
        if pairwise {
            if !self
                .peers
                .iter()
                .any(|p| Some(p.config.mac) == peer && p.key.is_some_and(|key| key.id == id))
            {
                return Err("AP PTK not installed for exact peer/index");
            }
        } else if peer.is_some() || !self.groups.iter().any(|key| key.id == id) {
            return Err("AP GTK/IGTK not installed for exact group/index");
        }
        self.epoch = hw.close_receive_epoch()?;
        if pairwise {
            let p = self
                .peers
                .iter_mut()
                .find(|p| Some(p.config.mac) == peer)
                .ok_or("AP removed PTK peer absent")?;
            p.authorized = false;
            let key = p
                .key
                .take()
                .filter(|k| k.id == id)
                .ok_or("AP PTK not installed")?;
            hw.ap_flush_station(p.id).await?;
            remove_key(hw, key).await?;
        } else {
            let index = self
                .groups
                .iter()
                .position(|k| k.id == id)
                .ok_or("AP GTK/IGTK not installed")?;
            let key = self.groups.remove(index);
            hw.ap_flush_station(key.station).await?;
            remove_key(hw, key).await?;
            self.bip.retain(|key| key.id() != id);
            self.go_gtk.retain(|key| key.id != id);
            if self.default_gtk == Some(id) {
                self.default_gtk = None;
            }
            if self.default_igtk == Some(id) {
                self.default_igtk = None;
            }
            if self.latest_gtk == Some(id) {
                self.latest_gtk = None;
            }
            if self.latest_igtk == Some(id) {
                self.latest_igtk = None;
            }
        }
        open_epoch(hw, self.epoch, &self.peers, self.own, self.plan.channel).await
    }
    pub(in crate::iwlwifi) fn protect_go_group(
        &mut self,
        frame: &mut Vec<u8>,
        header: usize,
    ) -> Result<(), &'static str> {
        self.current()?;
        if self.plan.go.is_none()
            || !self.peers.iter().any(|peer| peer.authorized)
            || !self.default_installed(false)
        {
            return Err("GO host group has no current key/port owner");
        }
        let id = self.default_gtk.ok_or("GO host GTK default absent")?;
        self.go_gtk
            .iter_mut()
            .find(|key| key.id == id)
            .ok_or("GO host GTK owner absent")?
            .protect(frame, header)
    }
    pub(in crate::iwlwifi) fn protect_host_bip(
        &mut self,
        frame: &mut Vec<u8>,
    ) -> Result<(), &'static str> {
        self.current()?;
        if !self.default_installed(true) {
            return Err("AP host IGTK default owner absent");
        }
        let id = self.default_igtk.ok_or("AP host IGTK default absent")?;
        self.bip
            .iter_mut()
            .find(|key| key.id() == id)
            .ok_or("AP host BIP key absent")?
            .protect(frame, self.own)
    }
    pub fn key_sequence(
        &self,
        id: u8,
        pairwise: bool,
        peer: Option<[u8; 6]>,
    ) -> Result<narf_wireless::KeySequence, i32> {
        self.current().map_err(|_| 1)?;
        if self.plan.go.is_none() || pairwise || peer.is_some() {
            return Err(95);
        }
        if !self.groups.iter().any(|key| key.id == id && key.software) {
            return Err(2);
        }
        if id <= 3 {
            let gtk = self.go_gtk.iter().find(|key| key.id == id).ok_or(2)?;
            Ok(narf_wireless::KeySequence {
                cipher: narf_wireless::CIPHER_SUITE_CCMP,
                seq: gtk.sequence(),
            })
        } else {
            let igtk = self.bip.iter().find(|key| key.id() == id).ok_or(2)?;
            Ok(narf_wireless::KeySequence {
                cipher: narf_wireless::CIPHER_SUITE_AES_CMAC,
                seq: igtk.sequence(),
            })
        }
    }
    pub fn default_key(
        &mut self,
        id: u8,
        unicast: bool,
        multicast: bool,
        management: bool,
        beacon: bool,
    ) -> Result<(), &'static str> {
        self.current()?;
        if unicast || beacon || multicast == management {
            return Err("AP default key has no exact native TX role");
        }
        if management {
            if self.latest_igtk != Some(id) || !self.group_installed(id, true) {
                return Err("AP IGTK rollback cannot reset or infer native TX PN");
            }
            self.default_igtk = Some(id);
        } else {
            if self.latest_gtk != Some(id) || !self.group_installed(id, false) {
                return Err("AP GTK rollback cannot reset or infer native TX PN");
            }
            self.default_gtk = Some(id);
        }
        Ok(())
    }
    pub async fn control(
        &mut self,
        hw: &mut Hardware,
        r: &ControlPortTxRequest,
    ) -> Result<bool, &'static str> {
        self.current()?;
        let peer = self
            .peers
            .iter()
            .find(|p| p.config.mac == r.dest)
            .ok_or("AP control port peer absent")?;
        let configured = r.ethertype == self.settings.control_port.ethertype;
        if !self.settings.control_port.enabled
            || !configured && r.ethertype != narf_wireless::ETH_P_PREAUTH
            || r.pdu().is_empty()
            || r.pdu().len() > 1500
        {
            return Err("AP control PDU differs from actual SME contract");
        }
        // Preauthentication is accepted by CONTROL_PORT_FRAME, but does
        // not inherit EAPOL's unauthorized-port or configured plaintext
        // exception. no_preauth only chooses the RX delivery endpoint.
        if !configured && !peer.authorized {
            return Err("AP preauthentication requires an authorized ordinary peer");
        }
        let encrypt = !r.no_encrypt
            && if configured {
                !self.settings.control_port.no_encrypt
            } else {
                self.plan.secure()
            };
        if encrypt && peer.key.is_none() {
            return Err("AP protected control PDU lacks PTK receipt");
        }
        let mut ethernet = Vec::new();
        ethernet.extend_from_slice(&r.dest);
        ethernet.extend_from_slice(&self.own);
        ethernet.extend_from_slice(&r.ethertype.to_be_bytes());
        ethernet.extend_from_slice(r.pdu());
        let (frame, header) = ap_wire::ethernet_qos_from_ap(
            self.own,
            self.sequence,
            &ethernet,
            encrypt,
            peer.config.wme.unwrap_or(false).then_some(0),
        )
        .ok_or("AP control frame invalid")?;
        self.sequence = self.sequence.wrapping_add(1);
        match hw
            .transmit_ap(peer.queues[1], &frame, header, None, encrypt)
            .await
        {
            Ok(()) => Ok(true),
            Err(super::runtime::TX_FAILED) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

pub(super) async fn command(
    hw: &mut Hardware,
    g: u8,
    c: u8,
    body: &[u8],
) -> Result<(), &'static str> {
    let receipt = hw.command(g, c, body).await?;
    if !receipt.payload.is_empty() {
        return Err("AP native command receipt has unexpected payload");
    }
    Ok(())
}
async fn remove_key(hw: &mut Hardware, key: Key) -> Result<(), &'static str> {
    if key.software {
        return hw.source_fence()?.invoke(|| Ok(()));
    }
    let mut body = zeroize::Zeroizing::new([0; 80]);
    put32(&mut body[..], 0, 3);
    put32(&mut body[..], 4, 1u32 << key.station);
    put32(&mut body[..], 8, u32::from(key.id));
    put32(&mut body[..], 12, key.flags);
    command(hw, 5, 0x18, &body[..]).await
}
async fn open_epoch(
    hw: &mut Hardware,
    epoch: u64,
    peers: &[Peer],
    own: [u8; 6],
    channel: super::native_band::Channel,
) -> Result<(), &'static str> {
    retire_epoch(hw, peers, own, channel).await?;
    hw.commit_receive_epoch(epoch)
}
async fn retire_epoch(
    hw: &mut Hardware,
    peers: &[Peer],
    own: [u8; 6],
    channel: super::native_band::Channel,
) -> Result<(), &'static str> {
    for packet in hw.synchronize_receive_epoch().await? {
        if packet.receive_queue != 0 || packet.header.group_id != 0 || packet.header.cmd != 0xc1 {
            continue;
        }
        let Some(mpdu) = hw.ap_mpdu(&packet.payload) else {
            continue;
        };
        let f = mpdu.frame;
        if f.len() < 26
            || !matches!(f[0], 0xa0 | 0xc0)
            || f[1] & 0x87 != 0
            || f[4..10] != own
            || hw.band_in_rx_supported() && mpdu.raw_band != channel.band as u8
            || super::native_band::Channel::received(
                mpdu.channel,
                mpdu.raw_band,
                hw.band_in_rx_supported(),
            ) != Some(channel)
        {
            continue;
        }
        let Some(peer) = peers
            .iter()
            .find(|p| f[10..16] == p.config.mac && f[16..22] == own)
        else {
            continue;
        };
        if mpdu.status & 4 != 0 && ((mpdu.status >> 24) & 31) != u32::from(peer.id) {
            continue;
        }
        let protected = peer.key.is_some() && peer.config.mfp.unwrap_or(false);
        if protected {
            if f[1] & 0x40 == 0 || mpdu.status & 0x7c0 != 0x240 {
                continue;
            }
            let Some(iv) = f.get(24..32) else {
                continue;
            };
            let Ok((pn, id)) = narf_wireless::ccmp::decode_ccmp_header(iv.try_into().unwrap())
            else {
                continue;
            };
            if id != 0 || pn <= peer.management_pn || mpdu.body(24, 8).is_none_or(|b| b.len() < 2) {
                continue;
            }
        } else if f[1] & 0x40 != 0 || mpdu.body(24, 0).is_none_or(|b| b.len() < 2) {
            continue;
        }
        return Err(
            "AP authenticated peer loss crossed native key/port prefix; retire before publication",
        );
    }
    Ok(())
}

#[path = "ap_packet.rs"]
pub(super) mod packet;

#[path = "ap_bip.rs"]
mod bip;
