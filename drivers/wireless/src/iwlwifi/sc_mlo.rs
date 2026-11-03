//! One actual physical/FW link for a negotiated non-AP MLD. Linux
//! mld/{iface,link,sta,rx}.c and mac-cfg.h keep spec and FW ids distinct.
//! Each physical link has its own `LinkOwner`; this binding installs only
//! the association link and grants neither a new radio nor extra links.
use super::{boot_context::put32, native_band::Channel, scan_api::Mpdu};
use alloc::{sync::Arc, vec::Vec};
use narf_wireless::association::mlo::{BasicMultiLink, Context, Local};

/// Linux fw/api/mac-cfg.h IWL_FW_MAX_ACTIVE_LINKS_NUM: the station MLD
/// firmware contract has at most two concurrently active links (EMLSR).
pub(super) const MAX_ACTIVE_LINKS: usize = 2;

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
    pub fn check_pending(&self, hw: &super::runtime::Hardware) -> Result<(), &'static str> {
        for packet in &hw.notifications {
            if packet.receive_queue != 0 || packet.header.group_id != 0 || packet.header.cmd != 0xc1
            {
                continue;
            }
            let Some(mpdu) = super::scan_api::mpdu(&packet.payload) else {
                continue;
            };
            let frame = mpdu.frame;
            let Some(link) = self.owner_of(&mpdu) else {
                continue;
            };
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
