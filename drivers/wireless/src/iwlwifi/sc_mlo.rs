//! One actual physical/FW link for a negotiated non-AP MLD. Linux
//! mld/{iface,link,sta,rx}.c and mac-cfg.h keep spec and FW ids distinct.
//! This binding grants neither a new radio nor additional active links.
use super::{boot_context::put32, native_band::Channel, scan_api::Mpdu};
use alloc::{sync::Arc, vec::Vec};
use narf_wireless::association::mlo::{BasicMultiLink, Context, Local};

pub(super) struct Binding {
    pub context: Context,
    channel: Channel,
    fw_link: u8,
    station: u8,
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
            channel,
            // The retained station producer owns exactly FWlink0/STA0.
            // AP spec ids may be any0..15 and never select a native queue.
            fw_link: 0,
            station: 0,
            auth: own.authentication_element(),
            request: own.request_element(),
        }))
    }
    pub fn apply_mac(&self, body: &mut [u8; 52]) {
        body[12..18].copy_from_slice(&self.context.own_mld());
        // Required before AP STA ADD, not only after association response.
        body[24] = 1;
        body[26] = 1;
    }
    pub fn apply_link(&self, body: &mut [u8; 208]) {
        put32(body, 4, u32::from(self.fw_link));
        body[16..22].copy_from_slice(&self.context.own_link());
        body[166] = self.context.link_id();
    }
    pub fn apply_peer(&self, body: &mut [u8; 104]) {
        put32(body, 0, u32::from(self.station));
        put32(body, 4, u32::from(self.fw_link));
        body[8..14].copy_from_slice(&self.context.peer_mld());
        body[16..22].copy_from_slice(&self.context.peer_link());
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
        frame[4..10].copy_from_slice(&self.context.peer_link());
        frame[10..16].copy_from_slice(&self.context.own_link());
        frame[16..22].copy_from_slice(&self.context.peer_link());
    }
    pub fn owns_mpdu(&self, mpdu: &Mpdu<'_>) -> bool {
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
    pub fn data_addresses(&self, mpdu: &Mpdu<'_>) -> Option<([u8; 6], [u8; 6])> {
        if !self.owns_mpdu(mpdu) || mpdu.frame.len() < 24 {
            return None;
        }
        let frame = mpdu.frame;
        let translated = frame[0] & 12 == 8 && frame[4] & 1 == 0;
        let (own, peer) = if translated {
            (self.context.own_mld(), self.context.peer_mld())
        } else {
            (self.context.own_link(), self.context.peer_link())
        };
        if frame[10..16] == peer && (frame[4..10] == own || frame[4] & 1 != 0) {
            return Some((own, peer));
        }
        None
    }
    pub fn management_header(&self, mpdu: &Mpdu<'_>) -> bool {
        if !self.owns_mpdu(mpdu) || mpdu.frame.len() < 24 {
            return false;
        }
        let frame = mpdu.frame;
        frame[4..10] == self.context.own_link()
            && frame[10..16] == self.context.peer_link()
            && frame[16..22] == self.context.peer_link()
    }
    pub fn confirm_beacon(&self, ies: &[u8]) -> Result<(), &'static str> {
        let actual = BasicMultiLink::from_ies(ies)
            .map_err(|_| "native MLD bound beacon omitted valid Basic ML facts")?;
        if actual.address() != self.context.peer_mld()
            || actual.link_id() != Some(self.context.link_id())
        {
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
            if self.owns_mpdu(&mpdu)
                && frame.len() >= 36
                && matches!(frame[0], 0x80 | 0x50)
                && frame[10..16] == self.context.peer_link()
                && frame[16..22] == self.context.peer_link()
            {
                self.confirm_beacon(
                    mpdu.body(24, 0)
                        .and_then(|body| body.get(12..))
                        .ok_or("native MLD bound beacon body invalid")?,
                )?;
            }
        }
        Ok(())
    }
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
