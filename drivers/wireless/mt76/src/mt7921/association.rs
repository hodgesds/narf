//! MT76 CONNAC2 station records plus the shared IEEE management plan.
//! Firmware layouts follow Linux ecd997b0189a mt76_connac_mcu.{c,h}.
use super::firmware_transport::ScanBss;
use alloc::{vec, vec::Vec};
use narf_wireless::association::JoinPlan as ManagementPlan;
pub use narf_wireless::association::{validate_sme_ies, Error, Phase, SecurityMode};
#[cfg(any(test, feature = "builtin"))]
use narf_wireless::rsn::{self, RsnIe, Suite};
#[cfg(any(test, feature = "builtin"))]
const RATES: [u8; 12] = [2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108];

#[path = "wmm.rs"]
pub(crate) mod wmm;

/// CONNAC2 legacy TX rate, selected from the AP's validated basic rates.
/// Linux mt76_rates: OFDM hardware indices are deliberately not linear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LegacyRate(u16);

impl LegacyRate {
    pub(crate) const ONE_MBPS: Self = Self(0);

    fn lowest(basic: u16) -> Self {
        const HARDWARE: [u16; 12] = [0, 1, 2, 3, 75, 79, 74, 78, 73, 77, 72, 76];
        // CCK precedes OFDM in the bitmap: 11Mbps has a lower bit than
        // 6Mbps. Select the lowest actual rate, not the lowest set bit.
        let index = (0..RATES.len())
            .filter(|index| basic & (1 << index) != 0)
            .min_by_key(|index| RATES[*index])
            .expect("shared plan has a nonempty validated basic-rate set");
        Self(HARDWARE[index])
    }

    pub(crate) fn hardware(self) -> u16 {
        self.0
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Security {
    Open,
    Wpa2Psk { psk: [u8; 32] },
}
impl core::fmt::Debug for Security {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(if self.is_wpa2() {
            "Wpa2Psk { .. }"
        } else {
            "Open"
        })
    }
}
impl Security {
    #[inline]
    pub fn is_wpa2(&self) -> bool {
        matches!(self, Self::Wpa2Psk { .. })
    }
}
/// Retains MT76 record inputs; all IEEE frame preparation/transitions are
/// delegated to the common plan, which stores no firmware/hardware state.
#[derive(Debug)]
pub struct JoinPlan {
    common: ManagementPlan,
    peer: [u8; 6],
    channel: u8,
    security: SecurityMode,
    wmm: Option<wmm::Parameters>,
    wmm_association: Vec<u8>,
    ht20: Option<super::ht20::Profile>,
}
impl core::ops::Deref for JoinPlan {
    type Target = ManagementPlan;
    fn deref(&self) -> &Self::Target {
        &self.common
    }
}
fn unicast(address: [u8; 6]) -> bool {
    address != [0; 6] && address[0] & 1 == 0
}
fn tlv(bytes: &mut Vec<u8>, id: u16, len: usize) -> usize {
    let offset = bytes.len();
    bytes.resize(offset + len, 0);
    bytes[offset..offset + 2].copy_from_slice(&id.to_le_bytes());
    bytes[offset + 2..offset + 4].copy_from_slice(&(len as u16).to_le_bytes());
    offset
}
#[cfg(any(test, feature = "builtin"))]
fn ies(
    mut bytes: &[u8],
    mut visit: impl FnMut(u8, &[u8]) -> Result<(), Error>,
) -> Result<(), Error> {
    while !bytes.is_empty() {
        let head = bytes.get(..2).ok_or(Error::InvalidBss)?;
        let len = usize::from(head[1]);
        let body = bytes.get(2..2 + len).ok_or(Error::InvalidBss)?;
        visit(head[0], body)?;
        bytes = &bytes[2 + len..];
    }
    Ok(())
}
#[cfg(any(test, feature = "builtin"))]
fn management(subtype: u8, own: [u8; 6], peer: [u8; 6]) -> Vec<u8> {
    let mut frame = vec![0; 24];
    frame[0] = subtype;
    frame[4..10].copy_from_slice(&peer);
    frame[10..16].copy_from_slice(&own);
    frame[16..22].copy_from_slice(&peer);
    frame
}
impl JoinPlan {
    pub fn prepare(
        bss: &ScanBss,
        own: [u8; 6],
        ssid: &[u8],
        security: Security,
    ) -> Result<Self, Error> {
        let mode = if security.is_wpa2() {
            SecurityMode::Wpa2Psk
        } else {
            SecurityMode::Open
        };
        let common = ManagementPlan::prepare(bss, own, ssid, mode)?;
        let wmm = wmm::Parameters::parse(&bss.information_elements)?;
        Ok(Self {
            common,
            peer: bss.bssid,
            channel: bss.channel,
            security: mode,
            wmm,
            wmm_association: Vec::new(),
            ht20: None,
        })
    }
    pub(crate) fn management_rate(&self) -> LegacyRate {
        LegacyRate::lowest(self.common.legacy_rates().1)
    }
    pub(crate) fn offer_ht20(
        &mut self,
        info: super::firmware_transport::RadioInfo,
        bss: &ScanBss,
    ) -> Result<(), super::firmware_transport::Error> {
        if self.wmm.is_none() || !info.capabilities.phy.ht {
            return Ok(());
        }
        let mut ies = bss.information_elements.as_slice();
        let mut offered = false;
        while !ies.is_empty() {
            let end = 2 + usize::from(ies[1]); // common/WMM preparation validated extents
            offered |= matches!(ies[0], 45 | 61);
            ies = &ies[end..];
        }
        if offered {
            self.ht20 = Some(super::ht20::Profile::prepare(info, bss)?);
        }
        Ok(())
    }
    pub(crate) fn ht20(&self) -> Option<super::ht20::Profile> {
        self.ht20
    }
    pub fn start_authentication(&mut self) -> Result<&[u8], Error> {
        self.common.start_authentication()
    }
    pub fn authentication_response(&mut self, bytes: &[u8]) -> Result<Option<&[u8]>, Error> {
        let Some(request) = self.common.authentication_response(bytes)? else {
            return Ok(None);
        };
        if self.wmm.is_none() {
            return Ok(Some(request));
        }
        self.wmm_association.clear();
        self.wmm_association.extend_from_slice(request);
        if self.ht20.is_some() {
            self.wmm_association
                .extend_from_slice(&super::ht20::Profile::request_ie());
        }
        self.wmm_association.extend_from_slice(&wmm::INFORMATION);
        Ok(Some(&self.wmm_association))
    }
    pub fn association_response(&mut self, bytes: &[u8]) -> Result<Option<u16>, Error> {
        let Some(aid) = self.common.association_response(bytes)? else {
            return Ok(None);
        };
        if self.wmm.is_some() {
            // Common receipt already bound peer, subtype, status, AID and
            // legacy rates. An unrelated frame cannot change QoS admission.
            match bytes.get(30..).map(wmm::Parameters::parse) {
                Some(Ok(Some(parameters))) => self.wmm = Some(parameters),
                _ => {
                    self.cancel();
                    return Err(Error::Protocol);
                }
            }
        }
        if self.ht20.is_some() {
            match super::ht20::Profile::parse(&bytes[30..], self.channel) {
                Ok(profile) => self.ht20 = Some(profile),
                Err(_) => {
                    self.cancel();
                    return Err(Error::Protocol);
                }
            }
        }
        Ok(Some(aid))
    }
    pub fn cancel(&mut self) {
        self.wmm = None;
        self.ht20 = None;
        self.wmm_association.clear();
        self.common.cancel();
    }
    pub(crate) fn wmm(&self) -> Option<wmm::Parameters> {
        self.wmm
    }
    pub(crate) fn append_sme_ies(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.common.append_sme_ies(bytes)
    }
    /// Initial unencrypted AP record: CONN_STATE_CONNECT, never PORT_SECURE.
    /// Native RX remains enabled so later EAPOL processing sees full MPDUs.
    pub fn peer_record(&self, aid: u16, associated: bool) -> Result<Vec<u8>, Error> {
        if aid > 2007 || associated && aid == 0 {
            return Err(Error::Protocol);
        }
        if self.phase() == Phase::Failed
            || associated && self.phase() != (Phase::Associated { aid })
        {
            return Err(Error::Busy);
        }
        if !associated && aid != 0 {
            return Err(Error::Protocol);
        }
        let mut out = vec![0u8; 8];
        out[1] = 1;
        out[2] = 5;
        out[4] = 1; // WCID 1, five TLVs, append
        let basic = tlv(&mut out, 0, 20);
        out[basic + 4..basic + 8].copy_from_slice(&0x10002u32.to_le_bytes());
        out[basic + 8] = if associated && !self.security.is_wpa2() {
            2
        } else {
            1
        };
        out[basic + 9] = u8::from(associated && self.wmm.is_some());
        out[basic + 10..basic + 12].copy_from_slice(&aid.to_le_bytes());
        out[basic + 12..basic + 18].copy_from_slice(&self.peer);
        out[basic + 18..basic + 20]
            .copy_from_slice(&(if associated { 1u16 } else { 3 }).to_le_bytes());
        let phy = tlv(&mut out, 0x15, 12);
        let five = super::channel::band(self.channel) == Some(super::channel::Band::Ghz5);
        let (rates, basic) = self.common.legacy_rates();
        let basic_rates = if five { basic >> 4 } else { basic };
        out[phy + 4..phy + 6].copy_from_slice(&basic_rates.to_le_bytes());
        out[phy + 6] = if five { 8 } else { 3 }; // OFDM / HR-DSSS | ERP.
        let ra = tlv(&mut out, 1, 16);
        out[ra + 4..ra + 6].copy_from_slice(&((rates & 15) | ((rates >> 4) << 6)).to_le_bytes());
        let state = tlv(&mut out, 7, 12);
        out[state + 8] = if associated { 2 } else { 1 }; // MLME state, independent of port authorization.
        let wtbl = tlv(&mut out, 13, 12); // outer TLV + eight-byte WTBL request
        out[wtbl + 4] = 1;
        out[wtbl + 5] = 1;
        out[wtbl + 6] = 3;
        let generic = tlv(&mut out, 0, 20);
        out[generic + 4..generic + 10].copy_from_slice(&self.peer);
        out[generic + 13] = u8::from(associated && self.wmm.is_some());
        out[generic + 16..generic + 18].copy_from_slice(&aid.to_le_bytes());
        let rx = tlv(&mut out, 1, 12);
        out[rx + 5..rx + 8].fill(1); // RCA1, RCA2, RV
        let trans = tlv(&mut out, 6, 8);
        out[trans + 4] = 1;
        out[trans + 6] = 1; // to-DS, no RX translation
        let length = (out.len() - wtbl) as u16;
        out[wtbl + 2..wtbl + 4].copy_from_slice(&length.to_le_bytes());
        if let Some(profile) = self.ht20.filter(|_| associated) {
            out[phy + 6] |= 1 << 4; // PHY_TYPE_BIT_HT, without VHT/HE.
            out[phy + 7] = profile.ampdu();
            out[ra + 6] = profile.transmit_mcs();
            let ht = tlv(&mut out, 2, 12); // nested WTBL_HT.
            out[ht + 4] = 1;
            out[ht + 6] = profile.ampdu() & 3;
            out[ht + 7] = profile.ampdu() >> 2;
            let smps = tlv(&mut out, 13, 8); // nested WTBL_SMPS.
            out[smps + 4] = u8::from(profile.dynamic_smps());
            out[wtbl + 6] = 5;
            let length = (out.len() - wtbl) as u16;
            out[wtbl + 2..wtbl + 4].copy_from_slice(&length.to_le_bytes());
            let ht = tlv(&mut out, 9, 8); // top-level STA_REC_HT.
            out[ht + 4..ht + 6].copy_from_slice(&profile.peer_capability().to_le_bytes());
            out[2] += 1;
        }
        Ok(out)
    }

    /// Emits a completed station record for WCID 1 containing CCMP-128
    /// key installation and CONN_STATE_PORT_SECURE.
    pub fn secure_peer_record(&self, aid: u16, key: &[u8]) -> Result<Vec<u8>, Error> {
        if !self.security.is_wpa2() || key.len() != 16 {
            return Err(Error::UnsupportedSecurity);
        }
        let mut out = self.peer_record(aid, true)?;
        out[16] = 2; // STA_REC_BASIC.CONN_STATE_PORT_SECURE
        out[64] = 2; // STA_REC_STATE.CONN_STATE_PORT_SECURE
        out[2] += 1; // 6 TLVs
        let sec = tlv(&mut out, 0x12, 44);
        out[sec + 4] = 1; // cmd = SET_KEY
        out[sec + 5] = 1; // n_cipher = 1
        out[sec + 8] = 6; // cipher_id = MCU_CIPHER_AES_CCMP (6)
        out[sec + 9] = 36; // cipher_len
        out[sec + 10] = 0; // key_id = 0
        out[sec + 11] = 16; // key_len = 16
        out[sec + 12..sec + 28].copy_from_slice(key);
        Ok(out)
    }
}
/// The VIF's BMC WCID (19), used for received group keys. Linux uses the
/// station's AP address for this record, not a fabricated multicast peer.
pub fn group_record(peer: [u8; 6], aid: u16) -> Result<Vec<u8>, Error> {
    if !unicast(peer) || !(1..=2007).contains(&aid) {
        return Err(Error::InvalidBss);
    }
    let mut out = vec![0; 8];
    out[1] = 19;
    out[2] = 1;
    out[4] = 1;
    out[5] = 0xe; // VIF/BMC MUAR, not a peer station's OMAC.
    let wtbl = tlv(&mut out, 13, 12);
    out[wtbl + 4..wtbl + 8].copy_from_slice(&[19, 1, 3, 0]);
    let generic = tlv(&mut out, 0, 20);
    out[generic + 4..generic + 10].copy_from_slice(&peer);
    out[generic + 10] = 0xe;
    let rx = tlv(&mut out, 1, 12);
    out[rx + 5..rx + 8].fill(1);
    let trans = tlv(&mut out, 6, 8);
    out[trans + 4..trans + 7].copy_from_slice(&[1, 0, 1]);
    out[wtbl + 2..wtbl + 4].copy_from_slice(&52u16.to_le_bytes());
    Ok(out)
}

/// Install/remove one CCMP-128 key without replaying the peer/WTBL state.
/// WCID 1 is pairwise key zero; WCID 19 holds the VIF's indexed GTKs.
pub fn key_record(wcid: u8, key_id: u8, key: Option<&[u8]>) -> Result<Vec<u8>, Error> {
    if !matches!(wcid, 1 | 19)
        || key_id > 3
        || wcid == 1 && key_id != 0
        || key.is_some_and(|key| key.len() != 16)
    {
        return Err(Error::UnsupportedSecurity);
    }
    let mut out = vec![0; 8];
    out[1] = wcid;
    out[2] = 1;
    out[4] = 1;
    out[5] = if wcid == 19 { 0xe } else { 0 };
    let sec = tlv(&mut out, 0x12, if key.is_some() { 44 } else { 8 });
    if let Some(key) = key {
        out[sec + 4] = 1;
        out[sec + 5] = 1;
        out[sec + 8..sec + 12].copy_from_slice(&[6, 36, key_id, 16]);
        out[sec + 12..sec + 28].copy_from_slice(key);
    }
    Ok(out)
}

/// Update the active single legacy BSS from the negotiated scan identity.
pub fn bss_record(bss: &ScanBss, connected: bool) -> Result<Vec<u8>, Error> {
    if !unicast(bss.bssid)
        || super::channel::band(bss.channel).is_none()
        || bss.beacon_interval == 0
    {
        return Err(Error::InvalidBss);
    }
    let mut out = vec![0; 36];
    out[6..8].copy_from_slice(&32u16.to_le_bytes());
    out[8] = 1; // Keep the station BSS active when disconnected.
    out[12..16].copy_from_slice(&0x10001u32.to_le_bytes());
    out[16] = u8::from(!connected);
    out[18..24].copy_from_slice(&bss.bssid);
    out[24..26].copy_from_slice(&19u16.to_le_bytes());
    out[26..28].copy_from_slice(&bss.beacon_interval.to_le_bytes());
    let five = super::channel::band(bss.channel) == Some(super::channel::Band::Ghz5);
    out[29] = if five { 1 } else { 6 }; // PHY_MODE_A / PHY_MODE_B | PHY_MODE_G.
    out[30..32].copy_from_slice(&19u16.to_le_bytes());
    out[32..34].copy_from_slice(&(if five { 8u16 } else { 3 }).to_le_bytes());
    Ok(out)
}

/// Linux mt76_connac_mcu_uni_add_bss appends UNI_BSS_INFO_QBSS to
/// BASIC. Set and retire BSS QoS explicitly, independently of peer WTBL.
pub(crate) fn bss_record_qos(bss: &ScanBss, connected: bool, qos: bool) -> Result<Vec<u8>, Error> {
    let mut out = bss_record(bss, connected)?;
    let qbss = tlv(&mut out, 15, 8);
    out[qbss + 4] = u8::from(connected && qos);
    Ok(out)
}
pub(crate) fn bss_record_ht20(bss: &ScanBss, qos: bool, ht: bool) -> Result<Vec<u8>, Error> {
    let mut out = bss_record_qos(bss, true, qos)?;
    if ht {
        out[29] |= if bss.channel > 14 { 1 << 4 } else { 1 << 3 };
    }
    Ok(out)
}

/// A 20 MHz station transmission authorized by the installed host policy.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TxPermission {
    pub country: [u8; 2],
    pub power_dbm: i8,
    channel: u8,
}

impl TxPermission {
    pub fn from_domain(domain: &narf_wireless::reg::RegulatoryDomain, channel: u8) -> Option<Self> {
        use narf_wireless::reg::RegFlags;
        if !domain.country_code.iter().all(u8::is_ascii_uppercase) {
            return None;
        }
        let center = super::channel::frequency(channel)?;
        let overlaps = |rule: &&narf_wireless::reg::RegRule| {
            rule.freq_start_mhz < center + 10 && center - 10 < rule.freq_end_mhz
        };
        // A permissive wide rule cannot erase a restrictive overlapping rule.
        if domain.rules.iter().filter(overlaps).any(|rule| {
            rule.flags.intersects(RegFlags::DFS | RegFlags::NO_IR) || rule.max_bandwidth_mhz < 20
        }) {
            return None;
        }
        if !domain.rules.iter().any(|rule| {
            rule.freq_start_mhz <= center - 10
                && center + 10 <= rule.freq_end_mhz
                && rule.max_bandwidth_mhz >= 20
        }) {
            return None;
        }
        let power_dbm = domain
            .rules
            .iter()
            .filter(overlaps)
            .map(|rule| rule.max_power_dbm)
            .min()?;
        // Signed half-dBm table entries must be representable. This profile
        // transmits on one chain, so no multi-stream EIRP addition is needed.
        if !(-64..=63).contains(&power_dbm) {
            return None;
        }
        Some(Self {
            country: domain.country_code,
            power_dbm,
            channel,
        })
    }

    pub fn permits(self, channel: u8) -> bool {
        self.channel == channel
    }

    pub(crate) fn current(self, domain: &narf_wireless::reg::RegulatoryDomain) -> bool {
        Self::from_domain(domain, self.channel)
            .is_some_and(|now| now.country == self.country && now.power_dbm >= self.power_dbm)
    }

    pub fn rate_limits(self) -> Vec<u8> {
        let channel = self.channel;
        // Linux mt76_connac_tx_power_limit_tlv (44 bytes), followed by one
        // channel + 161 signed half-dBm rate limits. Firmware's calibration
        // and CLC limits still constrain this additional host ceiling.
        let mut bytes = vec![0; 44 + 162];
        bytes[4..7].copy_from_slice(&[
            1,
            super::channel::band(channel).map_or(0, |band| band.scan_tag()),
            1,
        ]); // n_chan, band, last_msg
        bytes[8..10].copy_from_slice(&self.country);
        bytes[44] = channel;
        bytes[45..].fill(self.power_dbm.saturating_mul(2) as u8);
        bytes
    }
}

/// Disconnect station record: CONN_STATE_DISCONNECT for WCID 1.
pub fn disconnect_record(peer: [u8; 6]) -> Vec<u8> {
    let mut out = vec![0u8; 8];
    out[1] = 1;
    out[2] = 2; // Two TLVs: basic + state
    out[4] = 1; // WCID 1
    let basic = tlv(&mut out, 0, 20);
    out[basic + 4..basic + 8].copy_from_slice(&0x10002u32.to_le_bytes());
    out[basic + 8] = 0;
    out[basic + 12..basic + 18].copy_from_slice(&peer);
    out[basic + 18..basic + 20].copy_from_slice(&1u16.to_le_bytes());
    let wtbl = tlv(&mut out, 13, 12);
    out[wtbl + 4..wtbl + 6].copy_from_slice(&[1, 1]); // RESET_AND_SET, no nested TLVs.
    out
}

pub fn group_disconnect_record() -> Vec<u8> {
    let mut out = vec![0; 8];
    out[1] = 19;
    out[2] = 1;
    out[4] = 1;
    out[5] = 0xe;
    let wtbl = tlv(&mut out, 13, 12);
    out[wtbl + 4..wtbl + 6].copy_from_slice(&[19, 1]);
    out
}

#[cfg(any(test, feature = "builtin"))]
#[path = "association_tests.rs"]
mod tests;
