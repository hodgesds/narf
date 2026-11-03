//! One actual physical/FW link for a negotiated non-AP MLD. Linux
//! mld/{iface,link,sta,rx}.c and mac-cfg.h keep spec and FW ids distinct.
//! Each physical link has its own `LinkOwner`; this binding installs only
//! the association link and grants neither a new radio nor extra links.
use super::{boot_context::put32, native_band::Channel, runtime::Hardware, scan_api::Mpdu};
use alloc::{sync::Arc, vec::Vec};
use narf_wireless::association::mlo::{BasicMultiLink, Context, Local};

/// Linux fw/api/mac-cfg.h IWL_FW_MAX_ACTIVE_LINKS_NUM: the station MLD
/// firmware contract has at most two concurrently active links (EMLSR).
pub(super) const MAX_ACTIVE_LINKS: usize = 2;

/// Linux fw/api/phy-ctxt.h NUM_PHY_CTX: firmware PHY context ids.
pub(super) const NUM_PHY_CTX: u8 = 3;

/// PHY context id allocation (Linux mld/phy.c `iwl_mld_allocate_fw_phy_id`,
/// lowest clear bit of `used_phy_ids`). The retained station producer's
/// association-link context is PHY0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PhyIds {
    used: u8,
}
impl PhyIds {
    pub fn station() -> Self {
        Self { used: 1 }
    }
    pub fn allocate(&mut self) -> Result<u8, &'static str> {
        let id = (0..NUM_PHY_CTX)
            .find(|id| self.used & (1 << id) == 0)
            .ok_or("native MLD PHY context ids exhausted")?;
        self.used |= 1 << id;
        Ok(id)
    }
    pub fn release(&mut self, id: u8) {
        self.used &= !(1u8 << (id & 7));
    }
    /// Mark an id another owner already holds.
    pub fn claim(&mut self, id: u8) {
        if id < NUM_PHY_CTX {
            self.used |= 1 << id;
        }
    }
}

/// One physical link's distinct firmware ownership, mirroring Linux
/// mld/link.h `iwl_mld_link` (fw_id, spec link id, channel context) plus
/// its `iwl_mld_link_sta` fw_id. Every per-link PHY/LINK/STA command, RX
/// admission and beacon proof is resolved through exactly one owner; a
/// spec id or raw firmware link never aliases another owner's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct LinkOwner {
    pub spec_link: u8,
    pub fw_link: u8,
    pub station: u8,
    pub channel: Channel,
    pub own_link: [u8; 6],
    pub peer_link: [u8; 6],
}
impl LinkOwner {
    fn owns(&self, mpdu: &Mpdu<'_>) -> bool {
        mpdu.raw_fw_link == self.fw_link
            && mpdu.raw_band == self.channel.band as u8
            && mpdu.channel == self.channel.number
            && (mpdu.status & 4 == 0 || (mpdu.status >> 24) & 31 == u32::from(self.station))
            // A logical unicast data header cannot invent a physical link.
            // Firmware must identify the owned STA before translation is used.
            && !(mpdu.frame.len() >= 16
                && mpdu.frame[0] & 12 == 8
                && mpdu.frame[4]&1==0
                && mpdu.status & 4 == 0)
    }
}

/// Firmware link/station id allocation bounded by the actual
/// IWL_UCODE_TLV_FW_NUM_LINKS/NUM_STATIONS facts (Linux mld.h
/// IWL_MLD_ALLOC_FN). Allocation is deterministic lowest-free, equivalent
/// to Linux with IWL_MLD_DIS_RANDOM_FW_ID; the retained station producer
/// keeps FWlink0/STA0 for the association link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FwIds {
    links: u8,
    stations: u8,
    used_links: u16,
    used_stations: u32,
}
impl FwIds {
    pub fn new(num_links: Option<u8>, num_stations: Option<u8>) -> Result<Self, &'static str> {
        let links = num_links.ok_or("native MLD firmware link count absent")?;
        // iwl-drv.c defaults ucode_capa.num_stations to IWL_STATION_COUNT_MAX
        // and leaves num_links zero when the TLV is absent.
        let stations = num_stations.unwrap_or(16);
        // Linux mld.h: fw_id_to_bss_conf[IWL_FW_MAX_LINKS=4] and
        // fw_id_to_link_sta[IWL_STATION_COUNT_MAX=16] bound the TLVs.
        if !(1..=4).contains(&links) || !(1..=16).contains(&stations) {
            return Err("native MLD firmware link/station count invalid");
        }
        Ok(Self {
            links,
            stations,
            used_links: 0,
            used_stations: 0,
        })
    }
    pub fn claim(&mut self, fw_link: u8, station: u8) -> Result<(), &'static str> {
        if fw_link >= self.links
            || station >= self.stations
            || self.used_links & (1 << fw_link) != 0
            || self.used_stations & (1 << station) != 0
        {
            return Err("native MLD firmware link/station id unavailable");
        }
        self.used_links |= 1 << fw_link;
        self.used_stations |= 1 << station;
        Ok(())
    }
    pub fn allocate(&mut self) -> Result<(u8, u8), &'static str> {
        let link = (0..self.links)
            .find(|id| self.used_links & (1 << id) == 0)
            .ok_or("native MLD firmware link ids exhausted")?;
        let station = (0..self.stations)
            .find(|id| self.used_stations & (1 << id) == 0)
            .ok_or("native MLD firmware station ids exhausted")?;
        self.claim(link, station)?;
        Ok((link, station))
    }
    pub fn release(&mut self, fw_link: u8, station: u8) {
        self.used_links &= !(1u16 << (fw_link & 15));
        self.used_stations &= !(1u32 << (station & 31));
    }
}

#[derive(Clone)]
pub(super) struct Binding {
    pub context: Context,
    /// The association (default) link owner, never removed while bound.
    primary: LinkOwner,
    /// Additional active owners; installed only by a complete
    /// multiple-active-link setup (none exists yet).
    secondary: [Option<LinkOwner>; MAX_ACTIVE_LINKS - 1],
    auth: Vec<u8>,
    request: Vec<u8>,
}
impl Binding {
    pub fn new(
        context: Context,
        channel: Channel,
        own_link: [u8; 6],
        peer_link: [u8; 6],
    ) -> Result<Arc<Self>, &'static str> {
        if context.own_link() != own_link
            || context.peer_link() != peer_link
            || context.link_id() >= 15
        {
            return Err("native MLD context changed physical link identity");
        }
        let own = Local::single_link(context.own_mld())
            .map_err(|_| "native MLD local address invalid")?;
        Ok(Arc::new(Self {
            context,
            primary: LinkOwner {
                spec_link: context.link_id(),
                channel,
                // The retained station producer owns exactly FWlink0/STA0.
                // AP spec ids may be any0..15 and never select a native queue.
                fw_link: 0,
                station: 0,
                own_link,
                peer_link,
            },
            secondary: [None; MAX_ACTIVE_LINKS - 1],
            auth: own.authentication_element(),
            request: own.request_element(),
        }))
    }
    /// The association link owner (Linux `mld_vif->deflink` analogue).
    pub fn primary(&self) -> &LinkOwner {
        &self.primary
    }
    pub fn owners(&self) -> impl Iterator<Item = &LinkOwner> {
        core::iter::once(&self.primary).chain(self.secondary.iter().flatten())
    }
    pub fn active_links(&self) -> u16 {
        self.owners()
            .fold(0, |mask, link| mask | 1 << link.spec_link)
    }
    /// The further active link, if a complete activation installed one.
    pub fn secondary(&self) -> Option<&LinkOwner> {
        self.secondary.iter().flatten().next()
    }
    /// Linux mld/sta.c `iwl_mld_fw_sta_id_mask`: every active link STA of
    /// the AP MLD. Queues, the pairwise key and BAIDs span this mask.
    pub fn sta_mask(&self) -> u32 {
        self.owners().fold(0, |mask, link| mask | 1 << link.station)
    }
    /// A copy with `owner` as the further active link. Every per-link
    /// identity (spec link, FW link, FW STA, physical own/peer address)
    /// must be distinct from the association link and from the MLD
    /// addresses, so no lookup can alias two owners.
    pub fn with_secondary(&self, owner: LinkOwner) -> Result<Arc<Self>, &'static str> {
        let primary = self.primary;
        let unicast = |mac: [u8; 6]| mac[0] & 1 == 0 && mac != [0; 6];
        if self.secondary().is_some()
            || owner.spec_link >= 15
            || owner.station >= 32
            || owner.spec_link == primary.spec_link
            || owner.fw_link == primary.fw_link
            || owner.station == primary.station
            || !unicast(owner.own_link)
            || !unicast(owner.peer_link)
            || [primary.own_link, primary.peer_link, self.context.own_mld()]
                .contains(&owner.own_link)
            || [primary.own_link, primary.peer_link, self.context.peer_mld()]
                .contains(&owner.peer_link)
        {
            return Err("native MLD further link identity aliases an owner");
        }
        let mut next = self.clone();
        next.secondary[0] = Some(owner);
        Ok(Arc::new(next))
    }
    /// A copy with only the association link active.
    pub fn without_secondary(&self) -> Arc<Self> {
        let mut next = self.clone();
        next.secondary = [None; MAX_ACTIVE_LINKS - 1];
        Arc::new(next)
    }
    fn owner_of(&self, mpdu: &Mpdu<'_>) -> Option<&LinkOwner> {
        self.owners().find(|link| link.owns(mpdu))
    }
    pub fn apply_mac(&self, body: &mut [u8; 52]) {
        body[12..18].copy_from_slice(&self.context.own_mld());
        // Required before AP STA ADD, not only after association response.
        body[24] = 1;
        body[26] = 1;
    }
    pub fn apply_link(&self, body: &mut [u8; 208]) {
        apply_link_owner(self.primary(), body);
    }
    pub fn apply_peer(&self, body: &mut [u8; 104]) {
        apply_peer_owner(&self.context, self.primary(), body);
    }
    pub fn authentication_element(&self) -> &[u8] {
        &self.auth
    }
    pub fn request_element(&self) -> &[u8] {
        &self.request
    }
    /// Linux mld/mac80211.c projects explicit-link management before TX;
    /// SAE/MLD key identity is unchanged by these physical radio addresses.
    pub fn project_management(&self, frame: &mut [u8]) {
        let link = self.primary();
        frame[4..10].copy_from_slice(&link.peer_link);
        frame[10..16].copy_from_slice(&link.own_link);
        frame[16..22].copy_from_slice(&link.peer_link);
    }
    /// The spec link id of the owner that received `mpdu` (iwl mld
    /// `iwl_mld_rx_fill_status` link_id from the firmware link).
    pub fn receiving_link(&self, mpdu: &Mpdu<'_>) -> Option<u8> {
        self.owner_of(mpdu).map(|link| link.spec_link)
    }
    pub fn owns_mpdu(&self, mpdu: &Mpdu<'_>) -> bool {
        self.owner_of(mpdu).is_some()
    }
    pub fn data_addresses(&self, mpdu: &Mpdu<'_>) -> Option<([u8; 6], [u8; 6])> {
        let link = self.owner_of(mpdu)?;
        if mpdu.frame.len() < 24 {
            return None;
        }
        let frame = mpdu.frame;
        let translated = frame[0] & 12 == 8 && frame[4] & 1 == 0;
        let (own, peer) = if translated {
            (self.context.own_mld(), self.context.peer_mld())
        } else {
            (link.own_link, link.peer_link)
        };
        if frame[10..16] == peer && (frame[4..10] == own || frame[4] & 1 != 0) {
            return Some((own, peer));
        }
        None
    }
    pub fn management_header(&self, mpdu: &Mpdu<'_>) -> bool {
        let Some(link) = self.owner_of(mpdu) else {
            return false;
        };
        let frame = mpdu.frame;
        frame.len() >= 24
            && frame[4..10] == link.own_link
            && frame[10..16] == link.peer_link
            && frame[16..22] == link.peer_link
    }
    pub fn confirm_beacon(&self, ies: &[u8]) -> Result<(), &'static str> {
        self.confirm_link_beacon(self.primary(), ies)
    }
    fn confirm_link_beacon(&self, link: &LinkOwner, ies: &[u8]) -> Result<(), &'static str> {
        let actual = BasicMultiLink::from_ies(ies)
            .map_err(|_| "native MLD bound beacon omitted valid Basic ML facts")?;
        if actual.address() != self.context.peer_mld() || actual.link_id() != Some(link.spec_link) {
            return Err("native MLD bound peer/spec link changed");
        }
        Ok(())
    }
    /// Beacon/probe-response proof routed through the owner that received
    /// it: each link's beacons must name the AP MLD and that link's own
    /// spec link id (Linux mlme.c `ieee80211_rx_mgmt_beacon` per link).
    pub fn confirm_mpdu_beacon(&self, mpdu: &Mpdu<'_>) -> Result<(), &'static str> {
        let Some(link) = self.owner_of(mpdu) else {
            return Ok(());
        };
        let frame = mpdu.frame;
        if frame.len() >= 36
            && matches!(frame[0], 0x80 | 0x50)
            && frame[10..16] == link.peer_link
            && frame[16..22] == link.peer_link
        {
            self.confirm_link_beacon(
                link,
                mpdu.body(24, 0)
                    .and_then(|body| body.get(12..))
                    .ok_or("native MLD bound beacon body invalid")?,
            )?;
        }
        Ok(())
    }
    pub fn check_pending(&self, hw: &super::runtime::Hardware) -> Result<(), &'static str> {
        for packet in &hw.notifications {
            if packet.receive_queue != 0 || packet.header.group_id != 0 || packet.header.cmd != 0xc1
            {
                continue;
            }
            if let Some(mpdu) = super::scan_api::mpdu(&packet.payload) {
                self.confirm_mpdu_beacon(&mpdu)?;
            }
        }
        Ok(())
    }
}

/// LINK_CONFIGv8 per-link identity: fw link id, physical own address and
/// the ADD-time spec_link_id byte166 (Linux mld/link.c
/// iwl_mld_add_link_to_fw).
pub(super) fn apply_link_owner(link: &LinkOwner, body: &mut [u8; 208]) {
    put32(body, 4, u32::from(link.fw_link));
    body[16..22].copy_from_slice(&link.own_link);
    body[166] = link.spec_link;
}

/// STA_CONFIGv2 per-link station: one fw STA id per link STA (Linux
/// mld/sta.c iwl_mld_add_link_sta) with the shared peer MLD address.
pub(super) fn apply_peer_owner(context: &Context, link: &LinkOwner, body: &mut [u8; 104]) {
    put32(body, 0, u32::from(link.station));
    put32(body, 4, u32::from(link.fw_link));
    body[8..14].copy_from_slice(&context.peer_mld());
    body[16..22].copy_from_slice(&link.peer_link);
}

/// Only source-qualified EHT callers opt into MLD. A BSS may advertise
/// MLD while serving a legacy owner; no enum alone upgrades that owner.
pub(super) fn local(eht: bool, ies: &[u8], own: [u8; 6]) -> Result<Option<Local>, &'static str> {
    if !eht {
        return Ok(None);
    }
    let mut rest = ies;
    while !rest.is_empty() {
        let len = usize::from(*rest.get(1).ok_or("short native MLD IE")?);
        let body = rest.get(2..2 + len).ok_or("short native MLD IE extent")?;
        if rest[0] == 255 && body.first() == Some(&107) {
            return Local::single_link(own)
                .map(Some)
                .map_err(|_| "native MLD own address invalid");
        }
        rest = &rest[2 + len..];
    }
    Ok(None)
}

/// Linux fw/api/mac-cfg.h `iwl_link_ctx_modify_flags`.
const LINK_MODIFY_ACTIVE: u32 = 1 << 0;
const LINK_MODIFY_RATES_INFO: u32 = 1 << 1;

/// The actual per-link firmware facts for a further link. The caller
/// builds `phy`, `link` and `peer` from that link's own accepted BSS and
/// per-STA profile with the same station_api builders as the association
/// link; this module only owns identity, ordering and STA masks.
pub(super) struct FurtherLink {
    pub owner: LinkOwner,
    pub phy_id: u8,
    /// PHY_CONTEXT ADD canonical body (station_api::phy_channel).
    pub phy: [u8; 32],
    /// LINK_CONFIG body carrying the link's rates/QoS/timing facts.
    pub link: [u8; 208],
    /// STA_CONFIG body carrying the link STA's negotiated PHY facts.
    pub peer: [u8; 104],
    /// REDUCE_TX_POWER (SET_LINK) body for this link's FW id, from its own
    /// host/AP power limit (Linux mld/power.c `iwl_mld_set_tx_power`).
    pub power: Vec<u8>,
}

/// A per-link group key delivered for that link by the MLO 4-way/group
/// handshake (GTK 1..3, IGTK 4/5, BIGTK 6/7) and its RX PN floor.
pub(super) struct LinkKey<'a> {
    pub id: u8,
    pub key: &'a [u8; 16],
    pub rx_pn: u64,
}

/// SEC_KEY_CMD v1 MODIFY (Linux mld/key.c `iwl_mld_update_sta_key_iter`):
/// only the pairwise key (link_id < 0) follows the STA mask.
pub(super) fn pairwise_key_modify(old: u32, new: u32, pmf: bool) -> [u8; 80] {
    let mut body = [0; 80];
    put32(&mut body, 0, 2); // FW_CTXT_ACTION_MODIFY
    put32(&mut body, 4, old);
    put32(&mut body, 8, new);
    put32(&mut body, 12, 0);
    put32(&mut body, 16, super::sc_security::key_flags(0, false, pmf));
    body
}

/// RX_BAID_ALLOCATION_CONFIG v2 MODIFY (Linux mld/agg.c
/// `iwl_mld_update_sta_baids`): reorder ownership is per MLD station, so
/// each BAID moves to the new STA mask with its TID.
pub(super) fn baid_modify(old: u32, new: u32, tid: u8) -> [u8; 16] {
    let mut body = [0; 16];
    put32(&mut body, 0, 1); // IWL_RX_BAID_ACTION_MODIFY
    put32(&mut body, 4, old);
    put32(&mut body, 8, new);
    put32(&mut body, 12, u32::from(tid));
    body
}

/// Add one further active link, in the order mac80211
/// `_ieee80211_set_active_links` drives iwl mld:
/// `iwl_mld_change_vif_links` (LINK ADD, inactive, spec link id) ->
/// `iwl_mld_add_chanctx`/`iwl_mld_assign_vif_chanctx` (PHY ADD, LINK
/// MODIFY RATES_INFO with the PHY; a station link cannot activate before
/// its link STA) -> `iwl_mld_update_link_stas` (link STA ADD, then
/// `iwl_mld_update_sta_resources`: queues, pairwise key, BAIDs to the
/// widened mask, then `iwl_mld_activate_link`) ->
/// `ieee80211_key_switch_links` (that link's GTK/IGTK/BIGTK on its STA).
/// The caller has quiesced TX. A failure after the first device-visible
/// command leaves firmware ownership unknown and fails the device.
pub(super) async fn activate_further_link(
    hw: &mut Hardware,
    binding: &Binding,
    further: &FurtherLink,
    pairwise_pmf: Option<bool>,
    baid_tids: &[u8],
    group: &[LinkKey<'_>],
) -> Result<Arc<Binding>, &'static str> {
    let next = binding.with_secondary(further.owner)?;
    if further.phy_id >= NUM_PHY_CTX
        || group.iter().any(|key| !(1..=7).contains(&key.id))
        || baid_tids.iter().any(|&tid| tid >= 8)
    {
        return Err("native MLD further link resources invalid");
    }
    let result =
        further_link_commands(hw, binding, &next, further, pairwise_pmf, baid_tids, group).await;
    if result.is_err() {
        hw.fail();
    }
    result.map(|()| next)
}

async fn further_link_commands(
    hw: &mut Hardware,
    binding: &Binding,
    next: &Binding,
    further: &FurtherLink,
    pairwise_pmf: Option<bool>,
    baid_tids: &[u8],
    group: &[LinkKey<'_>],
) -> Result<(), &'static str> {
    let owner = &further.owner;
    let (old, new) = (binding.sta_mask(), next.sta_mask());
    let mut link = further.link;
    apply_link_owner(owner, &mut link);
    put32(&mut link, 0, 1); // FW_CTXT_ACTION_ADD
    put32(&mut link, 12, u32::MAX);
    put32(&mut link, 24, 0);
    put32(&mut link, 28, 0);
    hw.command(3, 9, &link).await?;
    let mut phy = further.phy;
    put32(&mut phy, 0, u32::from(further.phy_id));
    put32(&mut phy, 4, 1);
    hw.station_phy(&phy, owner.channel.number).await?;
    put32(&mut link, 0, 2); // FW_CTXT_ACTION_MODIFY
    put32(&mut link, 12, u32::from(further.phy_id));
    put32(&mut link, 24, LINK_MODIFY_RATES_INFO);
    hw.command(3, 9, &link).await?;
    // BSS_CHANGED_TXPOWER follows the channel assignment, before the link
    // can become active or transmit.
    if further.power.get(4..8) != Some(&u32::from(owner.fw_link).to_le_bytes()[..]) {
        return Err("native MLD further link power names another link");
    }
    hw.command(1, 0x9f, &further.power).await?;
    let mut peer = further.peer;
    apply_peer_owner(&binding.context, owner, &mut peer);
    hw.station_peer(&peer).await?;
    hw.modify_tx_station_mask(old, new).await?;
    if let Some(pmf) = pairwise_pmf {
        hw.command(5, 0x18, &pairwise_key_modify(old, new, pmf))
            .await?;
    }
    for &tid in baid_tids {
        hw.command(5, 0x16, &baid_modify(old, new, tid)).await?;
    }
    put32(&mut link, 24, LINK_MODIFY_ACTIVE);
    put32(&mut link, 28, 1);
    hw.command(3, 9, &link).await?;
    for key in group {
        let body = super::sc_security::key_command_for(
            1 << owner.station,
            key.id,
            true,
            false,
            Some(key.key),
            key.rx_pn,
        )?;
        if !hw.command(5, 0x18, &body[..]).await?.payload.is_empty() {
            return Err("unexpected native per-link key receipt");
        }
    }
    Ok(())
}

/// Remove the further active link, the inverse mac80211
/// `_ieee80211_set_active_links` order: release the channel
/// (`iwl_mld_unassign_vif_chanctx` -> `iwl_mld_deactivate_link`, then
/// `iwl_mld_remove_chanctx` PHY REMOVE) -> `ieee80211_key_switch_links`
/// removes that link's group keys -> `iwl_mld_update_link_stas` narrows
/// queues/pairwise key/BAIDs before STA_REMOVE -> `iwl_mld_remove_link`
/// LINK REMOVE. TX must be quiesced; a failure fails the device.
pub(super) async fn deactivate_further_link(
    hw: &mut Hardware,
    binding: &Binding,
    further: &FurtherLink,
    pairwise_pmf: Option<bool>,
    baid_tids: &[u8],
    group_ids: &[u8],
) -> Result<Arc<Binding>, &'static str> {
    if binding.secondary() != Some(&further.owner)
        || group_ids.iter().any(|id| !(1..=7).contains(id))
    {
        return Err("native MLD further link removal does not name the active owner");
    }
    let next = binding.without_secondary();
    let result = remove_link_commands(
        hw,
        binding,
        &next,
        further,
        pairwise_pmf,
        baid_tids,
        group_ids,
    )
    .await;
    if result.is_err() {
        hw.fail();
    }
    result.map(|()| next)
}

async fn remove_link_commands(
    hw: &mut Hardware,
    binding: &Binding,
    next: &Binding,
    further: &FurtherLink,
    pairwise_pmf: Option<bool>,
    baid_tids: &[u8],
    group_ids: &[u8],
) -> Result<(), &'static str> {
    let owner = &further.owner;
    let (old, new) = (binding.sta_mask(), next.sta_mask());
    let mut link = further.link;
    apply_link_owner(owner, &mut link);
    put32(&mut link, 0, 2);
    put32(&mut link, 12, u32::from(further.phy_id));
    put32(&mut link, 24, LINK_MODIFY_ACTIVE);
    put32(&mut link, 28, 0);
    hw.command(3, 9, &link).await?;
    let mut phy = further.phy;
    put32(&mut phy, 0, u32::from(further.phy_id));
    put32(&mut phy, 4, 3); // FW_CTXT_ACTION_REMOVE
    hw.station_phy(&phy, owner.channel.number).await?;
    for &id in group_ids {
        let body =
            super::sc_security::key_command_for(1 << owner.station, id, true, false, None, 0)?;
        if !hw.command(5, 0x18, &body[..]).await?.payload.is_empty() {
            return Err("unexpected native per-link key-removal receipt");
        }
    }
    hw.modify_tx_station_mask(old, new).await?;
    if let Some(pmf) = pairwise_pmf {
        hw.command(5, 0x18, &pairwise_key_modify(old, new, pmf))
            .await?;
    }
    for &tid in baid_tids {
        hw.command(5, 0x16, &baid_modify(old, new, tid)).await?;
    }
    let mut remove = [0; 4];
    put32(&mut remove, 0, u32::from(owner.station));
    hw.command(3, 0xc, &remove).await?;
    let mut gone = [0; 208];
    put32(&mut gone, 0, 3);
    put32(&mut gone, 4, u32::from(owner.fw_link));
    put32(&mut gone, 12, u32::MAX);
    gone[166] = owner.spec_link;
    hw.command(3, 9, &gone).await?;
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "sc_mlo_link_tests.rs"]
mod link_tests;
