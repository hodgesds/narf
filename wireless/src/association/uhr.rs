// SPDX-License-Identifier: GPL-2.0-or-later
//! UHR (IEEE P802.11bn, draft D1.3) Capabilities/Operation facts and
//! admission on top of EHT.
//!
//! IEEE 802.11bn is an unapproved draft amendment; the layout follows
//! P802.11bn_D1.3 9.4.2.353 (UHR Operation, element ID extension 151) and
//! 9.4.2.354 (UHR Capabilities, extension 152) exactly as Linux
//! include/linux/ieee80211-uhr.h encodes them (`ieee80211_uhr_capa_size_ok`,
//! `ieee80211_uhr_oper_size_ok`, NPCA/DPS/P-EDCA/DBE parameter fields).
//! Admission mirrors mac80211 mlme.c `ieee80211_determine_ap_chan`
//! (`check_uhr`): UHR needs EHT, a UHR Operation element and a Basic
//! Multi-Link element (UHR operation is defined for MLDs), the UHR
//! Capabilities element outside beacons, a consistent NPCA configuration
//! (`cfg80211_chandef_add_npca` / `cfg80211_chandef_npca_valid`) and
//! consistent DBE parameters. Because a UHR association is an MLD
//! association, the single-link `JoinPlan` never negotiates UHR; a native
//! owner whose firmware associates as a non-AP MLD opts in with
//! `LocalUhr::for_mld_association` on the `Offer::from_elements` path.
use super::eht::EhtNegotiation;
use super::phy::Width;
use super::Error;
use alloc::vec::Vec;

/// Element ID extension of UHR Operation (P802.11bn D1.3; Linux
/// `WLAN_EID_EXT_UHR_OPER`).
pub const EXT_UHR_OPERATION: u8 = 151;
/// Element ID extension of UHR Capabilities (`WLAN_EID_EXT_UHR_CAPA`).
pub const EXT_UHR_CAPABILITIES: u8 = 152;
/// Element ID extension of the Multi-Link element
/// (`WLAN_EID_EXT_EHT_MULTI_LINK`, IEEE802.11be-2024 9.4.2.321).
pub const EXT_MULTI_LINK: u8 = 107;

const MAC0_NPCA: u8 = 0x10;
const MAC1_DBE: u8 = 0x04;
const DBE_CAP_160: u8 = 0x08;
const DBE_CAP_320: u8 = 0x10;
const OP_NPCA_ENA: u16 = 0x0002;
const OP_DBE_BW: u16 = 0x0070;
const OP_DPS_PRES: u16 = 0x0100;
const OP_NPCA_PRES: u16 = 0x0200;
const OP_PEDCA_PRES: u16 = 0x0400;
const OP_DBE_PRES: u16 = 0x0800;
const NPCA_BITMAP_PRES: u32 = 0x0080_0000;
const DBE_BITMAP_PRES: u8 = 0x08;

/// A parsed UHR Capabilities body (after the extension ID).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UhrCapability {
    mac: [u8; 6],
    phy: u32,
    dbe: Option<(u8, [u8; 6], u8)>,
}
impl UhrCapability {
    /// Exact `ieee80211_uhr_capa_size_ok`: a non-AP STA never carries DBE
    /// Capability Parameters; an AP with DBE support carries the DBE octet
    /// plus one EHT-MCS map per 160/320 presence bit.
    pub fn parse(body: &[u8], from_ap: bool) -> Result<Self, Error> {
        if body.len() < 11 {
            return Err(Error::InvalidBss);
        }
        let mac: [u8; 6] = body[..6].try_into().map_err(|_| Error::InvalidBss)?;
        let phy = u32::from_le_bytes([body[6], body[7], body[8], body[9]]);
        let mut at = 11;
        let mut dbe = None;
        if from_ap && mac[1] & MAC1_DBE != 0 {
            let cap = *body.get(at).ok_or(Error::InvalidBss)?;
            at += 1;
            let maps = usize::from(cap & DBE_CAP_160 != 0) + usize::from(cap & DBE_CAP_320 != 0);
            let set = body.get(at..at + 3 * maps).ok_or(Error::InvalidBss)?;
            let mut copy = [0; 6];
            copy[..set.len()].copy_from_slice(set);
            dbe = Some((cap, copy, set.len() as u8));
            at += 3 * maps;
        }
        if at != body.len() {
            return Err(Error::InvalidBss);
        }
        Ok(Self { mac, phy, dbe })
    }
    pub fn mac_capability(&self) -> [u8; 6] {
        self.mac
    }
    pub fn phy_capability(&self) -> u32 {
        self.phy
    }
    /// DBE Capability Parameters octet (AP only).
    pub fn dbe_capability(&self) -> Option<u8> {
        self.dbe.map(|(cap, _, _)| cap)
    }
    pub fn npca(&self) -> bool {
        self.mac[0] & MAC0_NPCA != 0
    }
    pub fn dbe(&self) -> bool {
        self.mac[1] & MAC1_DBE != 0
    }
    /// The body including the extension-ID octet.
    pub fn body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(19);
        out.push(EXT_UHR_CAPABILITIES);
        out.extend_from_slice(&self.mac);
        out.extend_from_slice(&self.phy.to_le_bytes());
        out.push(0);
        if let Some((cap, set, len)) = self.dbe {
            out.push(cap);
            out.extend_from_slice(&set[..usize::from(len)]);
        }
        out
    }
}

/// A parsed UHR Operation body (after the extension ID).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UhrOperation {
    params: u16,
    basic: [u8; 4],
    dps: Option<u32>,
    npca: Option<(u32, Option<u16>)>,
    pedca: Option<[u8; 3]>,
    dbe: Option<(u8, Option<u16>)>,
}
impl UhrOperation {
    /// Exact `ieee80211_uhr_oper_size_ok` length.
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let field = |at: usize, len: usize| body.get(at..at + len).ok_or(Error::InvalidBss);
        let head = field(0, 6)?;
        let params = u16::from_le_bytes([head[0], head[1]]);
        let basic = [head[2], head[3], head[4], head[5]];
        let mut at = 6;
        let mut value = Self {
            params,
            basic,
            dps: None,
            npca: None,
            pedca: None,
            dbe: None,
        };
        if params & OP_DPS_PRES != 0 {
            let b = field(at, 4)?;
            value.dps = Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
            at += 4;
        }
        if params & OP_NPCA_PRES != 0 {
            let b = field(at, 4)?;
            let npca = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            at += 4;
            let bitmap = if npca & NPCA_BITMAP_PRES != 0 {
                let b = field(at, 2)?;
                at += 2;
                Some(u16::from_le_bytes([b[0], b[1]]))
            } else {
                None
            };
            value.npca = Some((npca, bitmap));
        }
        if params & OP_PEDCA_PRES != 0 {
            let b = field(at, 3)?;
            value.pedca = Some([b[0], b[1], b[2]]);
            at += 3;
        }
        if params & OP_DBE_PRES != 0 {
            let dbe = field(at, 1)?[0];
            at += 1;
            let bitmap = if dbe & DBE_BITMAP_PRES != 0 {
                let b = field(at, 2)?;
                at += 2;
                Some(u16::from_le_bytes([b[0], b[1]]))
            } else {
                None
            };
            value.dbe = Some((dbe, bitmap));
        }
        if at != body.len() {
            return Err(Error::InvalidBss);
        }
        Ok(value)
    }
    pub fn params(&self) -> u16 {
        self.params
    }
    /// Basic UHR-MCS And NSS Set (EHT 20MHz-only form).
    pub fn basic_mcs_nss(&self) -> [u8; 4] {
        self.basic
    }
    pub fn dps_parameters(&self) -> Option<u32> {
        self.dps
    }
    /// NPCA parameters when NPCA is present *and enabled*
    /// (`ieee80211_uhr_npca_info`).
    pub fn npca_parameters(&self) -> Option<(u32, Option<u16>)> {
        self.npca.filter(|_| self.params & OP_NPCA_ENA != 0)
    }
    pub fn pedca_parameters(&self) -> Option<[u8; 3]> {
        self.pedca
    }
    pub fn dbe_parameters(&self) -> Option<(u8, Option<u16>)> {
        self.dbe
    }
}

/// Local UHR implementation facts (station-iftype UHR MAC/PHY octets).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalUhr {
    cap: UhrCapability,
    mld: bool,
}
impl LocalUhr {
    /// The UHR PHY reserved octet is emitted as zero; a non-AP STA carries
    /// no DBE Capability Parameters.
    pub fn new(mac: [u8; 6], phy: u32) -> Self {
        Self {
            cap: UhrCapability {
                mac,
                phy,
                dbe: None,
            },
            mld: false,
        }
    }
    /// The native owner (e.g. MLO firmware) associates as a non-AP MLD
    /// and owns the Basic Multi-Link element, MLD addressing and MLO key
    /// delivery. Only then can UHR be admitted, and only on the
    /// `Offer::from_elements` path; `JoinPlan` builds single-link requests.
    pub fn for_mld_association(mut self) -> Self {
        self.mld = true;
        self
    }
    pub fn mld_association(&self) -> bool {
        self.mld
    }
    pub fn capability_body(&self) -> Vec<u8> {
        self.cap.body()
    }
}

/// UHR facts for an admitted MLD association.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UhrNegotiation {
    local: LocalUhr,
    peer: Option<UhrCapability>,
    operation: UhrOperation,
    npca_channel: Option<u8>,
}
impl UhrNegotiation {
    pub fn peer_capability(&self) -> Option<&UhrCapability> {
        self.peer.as_ref()
    }
    pub fn operation(&self) -> &UhrOperation {
        &self.operation
    }
    /// The NPCA primary channel when both sides support NPCA and the AP
    /// enables it (mac80211 applies the NPCA chandef only then).
    pub fn npca_channel(&self) -> Option<u8> {
        self.npca_channel
    }
    pub fn local_capability(&self) -> Vec<u8> {
        self.local.capability_body()
    }
}

/// `check_uhr`. `beacon` relaxes only the UHR Capabilities requirement.
/// `channels` are the selected occupied 20MHz channels in ascending order.
#[allow(clippy::too_many_arguments)]
pub(super) fn negotiate(
    local: Option<LocalUhr>,
    cap: Option<UhrCapability>,
    op: Option<UhrOperation>,
    ml_basic: bool,
    eht: Option<&EhtNegotiation>,
    width: Width,
    discontiguous: bool,
    primary: u8,
    channels: &[u8],
    beacon: bool,
) -> Option<UhrNegotiation> {
    let (local, operation) = (local?, op?);
    if !local.mld || eht.is_none() || !ml_basic {
        return None;
    }
    if !beacon && cap.is_none() {
        return None;
    }
    let mut npca_channel = None;
    if let (Some(peer), Some((npca, bitmap))) = (cap, operation.npca_parameters()) {
        if !peer.npca() {
            return None;
        }
        // cfg80211_chandef_add_npca: 80/160(/320) only; offset within the
        // BSS; npca_valid: opposite half from the primary. Punctured NPCA
        // channels are not represented by this plan.
        if !matches!(width, Width::Eighty | Width::OneSixty)
            || discontiguous
            || bitmap.is_some_and(|b| b != 0)
        {
            return None;
        }
        let channel = *channels.get((npca & 0x0f) as usize)?;
        let half = channels.len() / 2;
        let primary_upper = channels.iter().position(|c| *c == primary)? >= half;
        let npca_upper = (npca & 0x0f) as usize >= half;
        if primary_upper == npca_upper {
            return None;
        }
        if local.cap.npca() {
            npca_channel = Some(channel);
        }
    }
    if let Some((dbe, _)) = operation.dbe {
        let peer = cap?;
        let cap_bw = peer.dbe_capability()? & 0x07;
        let op_bw = dbe & 0x07;
        if (operation.params & OP_DBE_BW) >> 4 != u16::from(op_bw)
            || !(1..=5).contains(&op_bw)
            || !(1..=4).contains(&cap_bw)
            || op_bw.min(4) > cap_bw
        {
            return None;
        }
        // DBE widening (cfg80211_chandef_add_dbe) is not applied: the
        // selected channel remains the non-DBE BSS channel.
    }
    Some(UhrNegotiation {
        local,
        peer: cap,
        operation,
        npca_channel,
    })
}

/// A Basic Multi-Link element (type 0) with a self-consistent Common Info
/// length (`ieee80211_mle_size_ok`'s outer bound).
pub(super) fn basic_multi_link(body: &[u8]) -> Result<bool, Error> {
    if body.len() < 3 {
        return Err(Error::InvalidBss);
    }
    if body[0] & 0x07 != 0 {
        return Ok(false);
    }
    let common = usize::from(body[2]);
    if common < 7 || 2 + common > body.len() {
        return Err(Error::InvalidBss);
    }
    Ok(true)
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "uhr_tests.rs"]
mod tests;
