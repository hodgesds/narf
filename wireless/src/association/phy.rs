// SPDX-License-Identifier: GPL-2.0-or-later
//! Bounded HT/VHT facts and directional station negotiation. These profiles
//! describe implementation limits; they grant no radio, key, BA or port rights.
//! Wire definitions: Linux include/linux/ieee80211-{ht,vht}.h, mac80211/{ht,vht}.c.
use super::eht::{self, EhtCapability, EhtNegotiation, EhtOperation, LocalEht};
use super::he::{self, HeCapability, HeNegotiation, HeOperation, LocalHe};
use super::{channel, ies, Error};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HtWidth {
    Twenty,
    TwentyForty,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HtGi {
    pub rx20: bool,
    pub tx20: bool,
    pub rx40: bool,
    pub tx40: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Width {
    Twenty,
    Forty,
    Eighty,
    OneSixty,
}

/// Local encoding supports equal-modulation MCS0..31, optional directional LDPC
/// and one-stream RX STBC, no TX STBC,
/// HT-control, beamforming or optional large A-MSDU. RX/TX must include
/// mandatory MCS0..7 (IEEE20.3.5; Linux ath10k/mac.c peer HT-rate check).
/// An optional subset bounds TX selection without changing capability IEs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalHt {
    rx: [u8; 10],
    tx: [u8; 10],
    tx_selection: [u8; 10],
    width: HtWidth,
    gi: HtGi,
    factor: u8,
    density: u8,
    rx_ldpc: bool,
    tx_ldpc: bool,
    rx_stbc: bool,
    rx_greenfield: bool,
    tx_greenfield: bool,
    tx_stbc: bool,
}
impl LocalHt {
    pub fn new(
        rx: [u8; 10],
        tx: [u8; 10],
        width: HtWidth,
        gi: HtGi,
        ampdu_factor: u8,
        mpdu_density: u8,
    ) -> Result<Self, Error> {
        if rx[0] != 255
            || tx[0] != 255
            || rx[4..].iter().chain(&tx[4..]).any(|v| *v != 0)
            || ampdu_factor > 3
            || mpdu_density > 7
            || width == HtWidth::Twenty && (gi.rx40 || gi.tx40)
        {
            return Err(Error::UnsupportedRates);
        }
        Ok(Self {
            rx,
            tx,
            tx_selection: tx,
            width,
            gi,
            factor: ampdu_factor,
            density: mpdu_density,
            rx_ldpc: false,
            tx_ldpc: false,
            rx_stbc: false,
            rx_greenfield: false,
            tx_greenfield: false,
            tx_stbc: false,
        })
    }
    pub fn siso20(rx_sgi20: bool, tx_sgi20: bool) -> Self {
        Self {
            rx: [255, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            tx: [255, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            tx_selection: [255, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            width: HtWidth::Twenty,
            gi: HtGi {
                rx20: rx_sgi20,
                tx20: tx_sgi20,
                rx40: false,
                tx40: false,
            },
            factor: 0,
            density: 0,
            rx_ldpc: false,
            tx_ldpc: false,
            rx_stbc: false,
            rx_greenfield: false,
            tx_greenfield: false,
            tx_stbc: false,
        }
    }
    /// Advertised LDPC is a local RX promise. TX coding additionally needs
    /// the bound AP's RX support; neither boolean grants native authority.
    pub fn with_ldpc(mut self, rx: bool, tx: bool) -> Self {
        self.rx_ldpc = rx;
        self.tx_ldpc = tx;
        self
    }
    /// Promise reception of one STBC data stream; TX STBC stays absent.
    pub fn with_rx_stbc(mut self, enabled: bool) -> Self {
        self.rx_stbc = enabled;
        self
    }
    /// HT greenfield RX is a local decoder promise. TX also requires the
    /// original offer and bound peer's greenfield receive capability.
    pub fn with_greenfield(mut self, rx: bool, tx: bool) -> Self {
        self.rx_greenfield = rx;
        self.tx_greenfield = tx;
        self
    }
    /// Advertise HT Capability Information bit7 (Tx STBC, IEEE802.11-2020
    /// 9.4.2.55.2): the native transmitter can send STBC PPDUs (19.3.11.9.2).
    /// Use additionally requires the bound peer's Rx STBC field in both the
    /// original offer and the response, as Linux mac80211/ht.c copies peer
    /// Rx STBC only when the local Tx STBC bit is set. Defaults off.
    pub fn with_tx_stbc(mut self, enabled: bool) -> Self {
        self.tx_stbc = enabled;
        self
    }
    /// Bound TX rate selection to a subset of actual implemented TX support.
    /// This expresses policy facts only; native power/radio proofs remain
    /// mandatory at every enabling/publication boundary.
    pub fn with_tx_selection(mut self, mask: [u8; 10]) -> Result<Self, Error> {
        if mask.iter().all(|v| *v == 0)
            || mask
                .iter()
                .zip(self.tx)
                .any(|(selected, actual)| selected & !actual != 0)
        {
            return Err(Error::UnsupportedRates);
        }
        self.tx_selection = mask;
        Ok(self)
    }
    pub fn capability_body(&self) -> [u8; 26] {
        let mut body = [0; 26];
        let cap: u16 = 0x000c // SMPS disabled; optional features are explicit below.
            | u16::from(self.rx_ldpc)
            | (u16::from(self.rx_greenfield) << 4)
            | (u16::from(self.tx_stbc) << 7)
            | (u16::from(self.rx_stbc) << 8)
            | if self.width == HtWidth::TwentyForty { 2 } else { 0 }
            | if self.gi.rx20 { 0x20 } else { 0 }
            | if self.gi.rx40 { 0x40 } else { 0 };
        body[..2].copy_from_slice(&cap.to_le_bytes());
        body[2] = self.factor | self.density << 2;
        body[3..13].copy_from_slice(&self.rx);
        body[15] = 1;
        if self.rx != self.tx {
            let streams = self.tx[..4].iter().rposition(|v| *v != 0).unwrap_or(0);
            body[15] |= 2 | (streams as u8) << 2;
        }
        body
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalVht {
    rx: u16,
    tx: u16,
    rx_sgi: bool,
    tx_sgi: bool,
    factor: u8,
    rx_ldpc: bool,
    tx_ldpc: bool,
    rx_stbc: bool,
    width160: bool,
    rx_sgi160: bool,
    tx_sgi160: bool,
    tx_stbc: bool,
    width80p80: bool,
    ext_nss_bw: bool,
    beamforming: VhtBeamforming,
}

/// Local VHT beamforming roles (IEEE802.11-2020 9.4.2.157.2, 21.3.11.11;
/// Linux include/linux/ieee80211-vht.h). Each value is a native sounding
/// feedback/steering implementation fact; it grants no radio authority.
/// - `su_beamformee_sts`: SU beamformee, maximum NDP space-time streams the
///   receiver can estimate (2..=8); advertised as bits12 and13..15.
/// - `su_beamformer_sounding`: SU beamformer, number of sounding dimensions
///   (2..=8); advertised as bits11 and16..18.
/// - `mu_beamformee`: MU beamformee (bit20); requires SU beamformee.
///
/// MU beamformer (bit19) is AP-only and is never advertised by a station.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VhtBeamforming {
    pub su_beamformee_sts: Option<u8>,
    pub su_beamformer_sounding: Option<u8>,
    pub mu_beamformee: bool,
}
impl VhtBeamforming {
    fn bits(self) -> u32 {
        let mut cap = 0;
        if let Some(sts) = self.su_beamformee_sts {
            cap |= 1 << 12 | u32::from(sts - 1) << 13;
        }
        if let Some(dims) = self.su_beamformer_sounding {
            cap |= 1 << 11 | u32::from(dims - 1) << 16;
        }
        if self.mu_beamformee {
            cap |= 1 << 20;
        }
        cap
    }
}
impl LocalVht {
    pub fn new(
        rx_map: u16,
        tx_map: u16,
        rx_sgi80: bool,
        tx_sgi80: bool,
        ampdu_exponent: u8,
    ) -> Result<Self, Error> {
        if !map_has_rates(rx_map) || !map_has_rates(tx_map) || ampdu_exponent > 7 {
            return Err(Error::UnsupportedRates);
        }
        Ok(Self {
            rx: rx_map,
            tx: tx_map,
            rx_sgi: rx_sgi80,
            tx_sgi: tx_sgi80,
            factor: ampdu_exponent,
            rx_ldpc: false,
            tx_ldpc: false,
            rx_stbc: false,
            width160: false,
            rx_sgi160: false,
            tx_sgi160: false,
            tx_stbc: false,
            width80p80: false,
            ext_nss_bw: false,
            beamforming: VhtBeamforming::default(),
        })
    }
    /// VHT Capabilities Information bit7 (Tx STBC). Use also needs the peer's
    /// Rx STBC field (bits8..10) in the offer and response. Defaults off.
    pub fn with_tx_stbc(mut self, enabled: bool) -> Self {
        self.tx_stbc = enabled;
        self
    }
    /// Advertise the checked local beamforming roles. Negotiated use needs
    /// the complementary peer role (mac80211/vht.c
    /// ieee80211_vht_cap_ie_to_sta_vht_cap) and the request advertisement is
    /// narrowed to the AP's roles as mac80211/mlme.c ieee80211_add_vht_ie
    /// does. The native owner must answer NDPA/NDP sounding with compressed
    /// feedback (beamformee) or steer with received feedback (beamformer),
    /// and must keep at most one MU-MIMO association.
    pub fn with_beamforming(mut self, beamforming: VhtBeamforming) -> Result<Self, Error> {
        let range = |v: Option<u8>| v.is_none_or(|v| (2..=8).contains(&v));
        if !range(beamforming.su_beamformee_sts)
            || !range(beamforming.su_beamformer_sounding)
            || beamforming.mu_beamformee && beamforming.su_beamformee_sts.is_none()
        {
            return Err(Error::UnsupportedRates);
        }
        self.beamforming = beamforming;
        Ok(self)
    }
    /// Opt into discontiguous 80+80 in addition to contiguous160 (Supported
    /// Channel Width Set2, IEEE802.11-2020 Table 9-272). Selected 80+80
    /// reports `Width::OneSixty` (the VHT-SIG-A CBW160/80+80 value) with
    /// `Offer/Negotiated::discontiguous()` and both segment centers; only an
    /// owner that programs two frequency segments may opt in.
    pub fn with_80p80(mut self, rx_sgi160: bool, tx_sgi160: bool) -> Self {
        self = self.with_160mhz(rx_sgi160, tx_sgi160);
        self.width80p80 = true;
        self
    }
    /// Declare VHT Extended NSS BW Capable (VHT Supported MCS and NSS Set
    /// bit61, IEEE802.11-2020 9.4.2.157.3), Linux's
    /// IEEE80211_HW_SUPPORTS_VHT_EXT_NSS_BW. The station then interprets the
    /// AP's Extended NSS BW Support field (Table 9-272) for160/80+80 support
    /// and NSS limits, and the HT Operation CCFS2 where that table directs,
    /// exactly as cfg80211 ieee80211_get_vht_max_nss and mac80211
    /// ieee80211_chandef_vht_oper do. Without it the AP's field is read as0.
    /// Local Extended NSS BW Support stays0 (full NSS at every width).
    pub fn with_extended_nss_bw(mut self, enabled: bool) -> Self {
        self.ext_nss_bw = enabled;
        self
    }
    pub fn with_ldpc(mut self, rx: bool, tx: bool) -> Self {
        self.rx_ldpc = rx;
        self.tx_ldpc = tx;
        self
    }
    pub fn with_rx_stbc(mut self, enabled: bool) -> Self {
        self.rx_stbc = enabled;
        self
    }
    /// Enable contiguous160; 80+80 and Extended NSS BW need their own opt-ins.
    pub fn with_160mhz(mut self, rx_sgi160: bool, tx_sgi160: bool) -> Self {
        self.width160 = true;
        self.rx_sgi160 = rx_sgi160;
        self.tx_sgi160 = tx_sgi160;
        self
    }
    pub fn capability_body(&self) -> [u8; 12] {
        let mut body = [0; 12];
        let cap = (u32::from(self.factor) << 23)
            | (u32::from(self.rx_ldpc) << 4)
            | (u32::from(self.rx_stbc) << 8)
            | (u32::from(self.width160 && !self.width80p80) << 2)
            | (u32::from(self.width80p80) << 3)
            | (u32::from(self.rx_sgi160) << 6)
            | (u32::from(self.tx_stbc) << 7)
            | self.beamforming.bits()
            | if self.rx_sgi { 1 << 5 } else { 0 };
        body[..4].copy_from_slice(&cap.to_le_bytes());
        body[4..6].copy_from_slice(&self.rx.to_le_bytes());
        body[8..10].copy_from_slice(&self.tx.to_le_bytes());
        if self.ext_nss_bw {
            body[11] |= 0x20; // VHT Extended NSS BW Capable (bit13).
        }
        body
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalPhy {
    ht: LocalHt,
    vht: Option<LocalVht>,
    he: Option<LocalHe>,
    eht: Option<LocalEht>,
}
impl LocalPhy {
    pub fn ht20(local: LocalHt) -> Result<Self, Error> {
        if local.width != HtWidth::Twenty {
            return Err(Error::UnsupportedRates);
        }
        Ok(Self {
            ht: local,
            vht: None,
            he: None,
            eht: None,
        })
    }
    pub fn ht40(local: LocalHt) -> Result<Self, Error> {
        if local.width != HtWidth::TwentyForty {
            return Err(Error::UnsupportedRates);
        }
        Ok(Self {
            ht: local,
            vht: None,
            he: None,
            eht: None,
        })
    }
    pub fn vht80(ht: LocalHt, vht: LocalVht) -> Result<Self, Error> {
        if ht.width != HtWidth::TwentyForty || vht.width160 {
            return Err(Error::UnsupportedRates);
        }
        Ok(Self {
            ht,
            vht: Some(vht),
            he: None,
            eht: None,
        })
    }
    pub fn vht160(ht: LocalHt, vht: LocalVht) -> Result<Self, Error> {
        if ht.width != HtWidth::TwentyForty || !vht.width160 {
            return Err(Error::UnsupportedRates);
        }
        Ok(Self {
            ht,
            vht: Some(vht),
            he: None,
            eht: None,
        })
    }
    /// Opt into HE (IEEE802.11ax) on top of this HT/VHT profile. On 5GHz
    /// HE is negotiated only together with VHT (an HE STA in 5GHz is a VHT
    /// STA, IEEE802.11ax-2021 26.17.1; mac80211 ieee80211_determine_ap_chan).
    /// An HE160 promise needs the VHT160 opt-in, since the HE width never
    /// exceeds the HT/VHT-selected channel.
    pub fn with_he(mut self, he: LocalHe) -> Result<Self, Error> {
        if he.width160() && !self.vht.is_some_and(|v| v.width160) {
            return Err(Error::UnsupportedRates);
        }
        self.he = Some(he);
        Ok(self)
    }
    pub fn he(&self) -> Option<&LocalHe> {
        self.he.as_ref()
    }
    /// Opt into non-MLO EHT (IEEE802.11be-2024) on top of `with_he`. The
    /// EHT-MCS/NSS set form must match the local HE Channel Width Set
    /// (`ieee80211_eht_mcs_nss_size`), and a160MHz set requires HE160.
    pub fn with_eht(mut self, eht: LocalEht) -> Result<Self, Error> {
        let he = self.he.ok_or(Error::UnsupportedRates)?;
        if !eht.matches_he(he.capability().phy_capability()[0]) {
            return Err(Error::UnsupportedRates);
        }
        self.eht = Some(eht);
        Ok(self)
    }
    pub fn eht(&self) -> Option<&LocalEht> {
        self.eht.as_ref()
    }
}

/// Fixed-size copies of the complete original element stream's PHY bodies.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ApElements {
    ht_cap: Option<[u8; 26]>,
    ht_op: Option<[u8; 22]>,
    vht_cap: Option<[u8; 12]>,
    vht_op: Option<[u8; 5]>,
    he_cap: Option<HeCapability>,
    he_op: Option<HeOperation>,
    eht_cap: Option<EhtCapability>,
    eht_op: Option<EhtOperation>,
}
impl ApElements {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 2048 {
            return Err(Error::InvalidBss);
        }
        let mut value = Self::default();
        let mut rates = [false; 2];
        // The EHT Capabilities extent depends on the HE Capabilities.
        let mut eht_cap: Option<([u8; 64], usize)> = None;
        ies(bytes, |id, body| {
            match id {
                45 => singleton(&mut value.ht_cap, body)?,
                61 => singleton(&mut value.ht_op, body)?,
                191 => singleton(&mut value.vht_cap, body)?,
                192 => singleton(&mut value.vht_op, body)?,
                255 => match body.split_first() {
                    None => return Err(Error::InvalidBss),
                    Some((&he::EXT_HE_CAPABILITIES, rest)) => {
                        if value.he_cap.is_some() {
                            return Err(Error::InvalidBss);
                        }
                        value.he_cap = Some(HeCapability::parse(rest)?);
                    }
                    Some((&he::EXT_HE_OPERATION, rest)) => {
                        if value.he_op.is_some() {
                            return Err(Error::InvalidBss);
                        }
                        value.he_op = Some(HeOperation::parse(rest)?);
                    }
                    Some((&eht::EXT_EHT_CAPABILITIES, rest)) => {
                        if eht_cap.is_some() || rest.len() > 64 {
                            return Err(Error::InvalidBss);
                        }
                        let mut copy = [0; 64];
                        copy[..rest.len()].copy_from_slice(rest);
                        eht_cap = Some((copy, rest.len()));
                    }
                    Some((&eht::EXT_EHT_OPERATION, rest)) => {
                        if value.eht_op.is_some() {
                            return Err(Error::InvalidBss);
                        }
                        value.eht_op = Some(EhtOperation::parse(rest)?);
                    }
                    _ => {}
                },
                1 | 50 => {
                    let index = usize::from(id == 50);
                    if rates[index] || body.is_empty() || id == 1 && body.len() > 8 {
                        return Err(Error::InvalidBss);
                    }
                    rates[index] = true;
                }
                _ => {}
            }
            Ok(())
        })?;
        if value.ht_cap.is_some() != value.ht_op.is_some()
            || value.vht_cap.is_some() != value.vht_op.is_some()
            || value.vht_cap.is_some() && value.ht_cap.is_none()
            || value.he_cap.is_some() != value.he_op.is_some()
            || value.he_cap.is_some() && value.ht_cap.is_none()
            || eht_cap.is_some() != value.eht_op.is_some()
            || eht_cap.is_some() && value.he_cap.is_none()
        {
            return Err(Error::InvalidBss);
        }
        if let (Some((body, len)), Some(he)) = (eht_cap, value.he_cap) {
            value.eht_cap = Some(EhtCapability::parse(
                &body[..len],
                he.phy_capability()[0],
                true,
            )?);
        }
        if let Some(cap) = value.ht_cap {
            if le16(&cap[..2]) & 0x2000 != 0
                || le16(&cap[..2]) & 0x000c == 0x0008
                || cap[2] & 0xe0 != 0
                || cap[12] & 0xe0 != 0
                || le16(&cap[13..15]) & !0x03ff != 0
                || cap[15] & 0xe0 != 0
                || cap[16..19].iter().any(|v| *v != 0)
            {
                return Err(Error::InvalidBss);
            }
        }
        if let Some(op) = value.ht_op {
            if op[1] & 3 == 2 || op[15] & 0xe0 != 0 || op[16..].iter().any(|v| *v != 0) {
                return Err(Error::InvalidBss);
            }
        }
        if let Some(cap) = value.vht_cap {
            let info = le32(&cap[..4]);
            if info & 3 == 3 || info & 12 == 12 || le16(&cap[10..12]) & 0xc000 != 0 {
                return Err(Error::InvalidBss);
            }
        }
        Ok(value)
    }
    pub fn ht_capability(&self) -> Option<[u8; 26]> {
        self.ht_cap
    }
    pub fn ht_operation(&self) -> Option<[u8; 22]> {
        self.ht_op
    }
    pub fn vht_capability(&self) -> Option<[u8; 12]> {
        self.vht_cap
    }
    pub fn vht_operation(&self) -> Option<[u8; 5]> {
        self.vht_op
    }
    pub fn he_capability(&self) -> Option<&HeCapability> {
        self.he_cap.as_ref()
    }
    pub fn he_operation(&self) -> Option<&HeOperation> {
        self.he_op.as_ref()
    }
    pub fn eht_capability(&self) -> Option<&EhtCapability> {
        self.eht_cap.as_ref()
    }
    pub fn eht_operation(&self) -> Option<&EhtOperation> {
        self.eht_op.as_ref()
    }
}
fn singleton<const N: usize>(slot: &mut Option<[u8; N]>, body: &[u8]) -> Result<(), Error> {
    if slot.is_some() {
        return Err(Error::InvalidBss);
    }
    *slot = Some(body.try_into().map_err(|_| Error::InvalidBss)?);
    Ok(())
}
fn le16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}
fn le32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HtOperation {
    body: [u8; 22],
    secondary: Option<u8>,
}
impl HtOperation {
    pub fn primary(&self) -> u8 {
        self.body[0]
    }
    pub fn secondary(&self) -> Option<u8> {
        self.secondary
    }
    pub fn protection(&self) -> u8 {
        self.body[2] & 3
    }
    pub fn body(&self) -> [u8; 22] {
        self.body
    }
    fn parse(body: [u8; 22], primary: u8) -> Result<Self, Error> {
        if body[0] != primary || channel::band(primary).is_none() {
            return Err(Error::InvalidBss);
        }
        let secondary = match body[1] & 3 {
            0 => None,
            1 => Some(primary.checked_add(4).ok_or(Error::InvalidBss)?),
            3 => Some(primary.checked_sub(4).ok_or(Error::InvalidBss)?),
            _ => return Err(Error::InvalidBss),
        };
        if let Some(second) = secondary {
            let center = (u16::from(primary) + u16::from(second)) / 2;
            let valid = match channel::band(primary) {
                Some(channel::Band::Ghz2) => channel::band(second) == Some(channel::Band::Ghz2),
                Some(channel::Band::Ghz5) => [
                    38, 46, 54, 62, 102, 110, 118, 126, 134, 142, 151, 159, 167, 175,
                ]
                .contains(&center),
                None => false,
            };
            if !valid || body[1] & 4 == 0 {
                return Err(Error::InvalidBss);
            }
        } else if body[1] & 4 != 0 {
            return Err(Error::InvalidBss);
        }
        Ok(Self { body, secondary })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HtNegotiation {
    local: LocalHt,
    tx: [u8; 10],
    peer: [u8; 26],
    operation: HtOperation,
    basic: [u8; 10],
}
impl HtNegotiation {
    pub fn rx_greenfield(&self) -> bool {
        self.local.rx_greenfield
    }
    pub fn tx_greenfield(&self) -> bool {
        self.local.tx_greenfield && self.peer_capability() & 16 != 0
    }
    pub fn rx_stbc(&self) -> bool {
        self.local.rx_stbc
    }
    /// Local Tx STBC and the bound peer's nonzero Rx STBC field (bits8..9).
    pub fn tx_stbc(&self) -> bool {
        self.local.tx_stbc && self.peer_rx_stbc_streams() != 0
    }
    /// Peer Rx STBC field: the number of spatial streams it can receive
    /// with STBC (0 = none, 1..3).
    pub fn peer_rx_stbc_streams(&self) -> u8 {
        (self.peer_capability() >> 8 & 3) as u8
    }
    pub fn rx_ldpc(&self) -> bool {
        self.local.rx_ldpc
    }
    pub fn tx_ldpc(&self) -> bool {
        self.local.tx_ldpc && self.peer_capability() & 1 != 0
    }
    pub fn tx_mcs(&self) -> [u8; 10] {
        self.tx
    }
    pub fn rx_mcs(&self) -> [u8; 10] {
        self.local.rx
    }
    pub fn peer_rx_mcs(&self) -> [u8; 10] {
        self.peer[3..13].try_into().unwrap()
    }
    pub fn tx_sgi20(&self) -> bool {
        self.local.gi.tx20 && self.peer_capability() & 0x20 != 0
    }
    pub fn rx_sgi20(&self) -> bool {
        self.local.gi.rx20
    }
    pub fn tx_sgi40(&self) -> bool {
        self.local.gi.tx40 && self.peer_capability() & 0x40 != 0
    }
    pub fn rx_sgi40(&self) -> bool {
        self.local.gi.rx40
    }
    pub fn peer_capability(&self) -> u16 {
        le16(&self.peer[..2])
    }
    pub fn peer_capability_body(&self) -> [u8; 26] {
        self.peer
    }
    pub fn peer_ampdu_factor(&self) -> u8 {
        self.peer[2] & 3
    }
    pub fn peer_mpdu_density(&self) -> u8 {
        self.peer[2] >> 2 & 7
    }
    pub fn peer_tx_params(&self) -> u8 {
        self.peer[15]
    }
    pub fn operation(&self) -> &HtOperation {
        &self.operation
    }
    pub fn local_capability(&self) -> [u8; 26] {
        self.local.capability_body()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VhtNegotiation {
    local: LocalVht,
    tx: u16,
    peer: [u8; 12],
    operation: [u8; 5],
    basic: u16,
}
impl VhtNegotiation {
    pub fn rx_sgi160(&self) -> bool {
        self.local.rx_sgi160
    }
    pub fn tx_sgi160(&self) -> bool {
        self.local.tx_sgi160 && self.peer_capability() & 0x40 != 0
    }
    pub fn rx_stbc(&self) -> bool {
        self.local.rx_stbc
    }
    pub fn rx_ldpc(&self) -> bool {
        self.local.rx_ldpc
    }
    pub fn tx_ldpc(&self) -> bool {
        self.local.tx_ldpc && self.peer_capability() & (1 << 4) != 0
    }
    /// Local Tx STBC and the peer's nonzero Rx STBC field (bits8..10).
    pub fn tx_stbc(&self) -> bool {
        self.local.tx_stbc && self.peer_capability() >> 8 & 7 != 0
    }
    /// Local SU beamformee and the AP's SU Beamformer Capable bit11: the AP
    /// may sound this station and steer with its feedback.
    pub fn su_beamformee(&self) -> bool {
        self.local.beamforming.su_beamformee_sts.is_some() && self.peer_capability() & 1 << 11 != 0
    }
    /// Local SU beamformer and the AP's SU Beamformee Capable bit12.
    pub fn su_beamformer(&self) -> bool {
        self.local.beamforming.su_beamformer_sounding.is_some()
            && self.peer_capability() & 1 << 12 != 0
    }
    /// SU beamformee plus local MU beamformee and the AP's MU Beamformer bit19.
    pub fn mu_beamformee(&self) -> bool {
        self.su_beamformee()
            && self.local.beamforming.mu_beamformee
            && self.peer_capability() & 1 << 19 != 0
    }
    /// The AP's sounding dimensions when it is an SU beamformer.
    pub fn peer_sounding_dimensions(&self) -> Option<u8> {
        (self.peer_capability() & 1 << 11 != 0)
            .then_some((self.peer_capability() >> 16 & 7) as u8 + 1)
    }
    /// The AP's beamformee STS when it is an SU beamformee.
    pub fn peer_beamformee_sts(&self) -> Option<u8> {
        (self.peer_capability() & 1 << 12 != 0)
            .then_some((self.peer_capability() >> 13 & 7) as u8 + 1)
    }
    pub fn rx_mcs_map(&self) -> u16 {
        self.local.rx
    }
    pub fn tx_mcs_map(&self) -> u16 {
        self.tx
    }
    pub fn peer_rx_mcs_map(&self) -> u16 {
        le16(&self.peer[4..6])
    }
    pub fn peer_tx_mcs_map(&self) -> u16 {
        le16(&self.peer[8..10])
    }
    pub fn peer_capability(&self) -> u32 {
        le32(&self.peer[..4])
    }
    pub fn peer_capability_body(&self) -> [u8; 12] {
        self.peer
    }
    pub fn rx_sgi80(&self) -> bool {
        self.local.rx_sgi
    }
    pub fn tx_sgi80(&self) -> bool {
        self.local.tx_sgi && self.peer_capability() & 0x20 != 0
    }
    pub fn operation_body(&self) -> [u8; 5] {
        self.operation
    }
    pub fn local_capability(&self) -> [u8; 12] {
        self.local.capability_body()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Selection {
    local: LocalPhy,
    ht: HtNegotiation,
    vht: Option<VhtNegotiation>,
    he: Option<HeNegotiation>,
    eht: Option<EhtNegotiation>,
    width: Width,
    center: u8,
    channels: [u8; 8],
    count: usize,
    /// Second 80MHz segment center of a discontiguous 80+80 selection.
    center2: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Offer(Selection);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Negotiated(Selection);
macro_rules! selection_accessors {
    () => {
        pub fn ht(&self) -> &HtNegotiation {
            &self.0.ht
        }
        pub fn vht(&self) -> Option<&VhtNegotiation> {
            self.0.vht.as_ref()
        }
        /// HE facts when both sides negotiated HE on this channel.
        pub fn he(&self) -> Option<&HeNegotiation> {
            self.0.he.as_ref()
        }
        /// Non-MLO EHT facts when negotiated on top of HE.
        pub fn eht(&self) -> Option<&EhtNegotiation> {
            self.0.eht.as_ref()
        }
        pub fn width(&self) -> Width {
            self.0.width
        }
        pub fn center_channel(&self) -> u8 {
            self.0.center
        }
        pub fn occupied_channels(&self) -> &[u8] {
            &self.0.channels[..self.0.count]
        }
        /// True for an opted-in 80+80 selection. `width()` then reports
        /// `OneSixty` (VHT-SIG-A CBW160/80+80), `center_channel()` is the
        /// primary80 segment center and `secondary_center_channel()` the
        /// other segment; `occupied_channels()` lists all eight channels.
        pub fn discontiguous(&self) -> bool {
            self.0.center2 != 0
        }
        pub fn secondary_center_channel(&self) -> Option<u8> {
            (self.0.center2 != 0).then_some(self.0.center2)
        }
    };
}
impl Offer {
    selection_accessors!();
    /// Select factual PHY limits from a complete native AP IE snapshot.
    /// Rate element validation and mandatory HT/VHT selectors are derived
    /// internally. The caller retains peer, SSID, security and native channel
    /// ownership; this parser grants no association or transmit authority.
    pub fn from_elements(
        local: LocalPhy,
        bytes: &[u8],
        primary: u8,
    ) -> Result<Option<Self>, Error> {
        Self::prepare(local, bytes, primary, element_selectors(bytes, primary)?)
    }
    /// Intersect a native association-response IE snapshot with this offer.
    /// The caller must already prove the actual response's peer/status and
    /// native completion. This does not build or authenticate a response.
    pub fn response_elements(&self, bytes: &[u8]) -> Result<Negotiated, Error> {
        self.response(
            bytes,
            element_selectors(bytes, self.0.ht.operation.primary())?,
        )
    }
    pub(super) fn prepare(
        local: LocalPhy,
        bytes: &[u8],
        primary: u8,
        selectors: u8,
    ) -> Result<Option<Self>, Error> {
        let ap = ApElements::parse(bytes)?;
        if ap.ht_cap.is_none() {
            if selectors & super::SEL_PHY != 0 {
                return Err(Error::UnsupportedRates);
            }
            return Ok(None);
        }
        let selected = select(local, ap, primary)?;
        check_selectors(selectors, &selected)?;
        Ok(Some(Self(selected)))
    }
    pub(super) fn response(&self, bytes: &[u8], selectors: u8) -> Result<Negotiated, Error> {
        let mut next = select(
            self.0.local,
            ApElements::parse(bytes)?,
            self.0.ht.operation.primary(),
        )?;
        check_selectors(selectors, &next)?;
        // An HE offer requires HE in the response and vice versa (mac80211
        // ieee80211_assoc_config_link: "HE AP is missing HE capability/operation").
        match (self.0.he.as_ref(), next.he.as_mut()) {
            (Some(old), Some(new)) => new.narrow_to(old)?,
            (None, None) => {}
            _ => return Err(Error::UnsupportedRates),
        }
        match (self.0.eht.as_ref(), next.eht.as_mut()) {
            (Some(old), Some(new)) => new.narrow_to(old)?,
            (None, None) => {}
            _ => return Err(Error::UnsupportedRates),
        }
        if self.0.vht.is_some() != next.vht.is_some()
            || next.channels[..next.count]
                .iter()
                .any(|ch| !self.occupied_channels().contains(ch))
        {
            return Err(Error::UnsupportedRates);
        }
        for i in 0..10 {
            next.ht.tx[i] &= self.0.ht.tx[i];
            next.ht.basic[i] |= self.0.ht.basic[i];
        }
        if next.ht.tx.iter().all(|v| *v == 0) {
            return Err(Error::UnsupportedRates);
        }
        // A response cannot restore a transmit GI omitted by the scan offer.
        next.ht.local.gi.tx20 &= self.0.ht.tx_sgi20();
        next.ht.local.gi.tx40 &= self.0.ht.tx_sgi40();
        next.ht.local.tx_ldpc &= self.0.ht.tx_ldpc();
        next.ht.local.tx_greenfield &= self.0.ht.tx_greenfield();
        next.ht.local.tx_stbc &= self.0.ht.tx_stbc();
        if let (Some(old), Some(new)) = (self.0.vht, next.vht.as_mut()) {
            new.tx = intersect_maps(new.tx, old.tx);
            new.local.tx_sgi &= old.tx_sgi80();
            new.local.tx_sgi160 &= old.tx_sgi160();
            new.local.tx_ldpc &= old.tx_ldpc();
            new.local.tx_stbc &= old.tx_stbc();
            if !old.su_beamformee() {
                new.local.beamforming.su_beamformee_sts = None;
                new.local.beamforming.mu_beamformee = false;
            }
            new.local.beamforming.mu_beamformee &= old.mu_beamformee();
            if !old.su_beamformer() {
                new.local.beamforming.su_beamformer_sounding = None;
            }
            if !map_has_rates(new.tx)
                || !supports_map(new.tx, old.basic)
                || !supports_map(new.local.rx, old.basic)
            {
                return Err(Error::UnsupportedRates);
            }
        }
        Ok(Negotiated(next))
    }
    pub(super) fn append_capabilities(&self, bytes: &mut alloc::vec::Vec<u8>) {
        bytes.extend_from_slice(&[45, 26]);
        bytes.extend_from_slice(&self.0.local.ht.capability_body());
        if self.0.vht.is_some() {
            bytes.extend_from_slice(&[191, 12]);
            bytes.extend_from_slice(&self.advertised_vht_capability());
        }
        if let (Some(_), Some(local)) = (self.0.he, self.0.local.he) {
            // mac80211 ieee80211_add_he_ie: only when HE was negotiated.
            let body = local.capability_body();
            bytes.extend_from_slice(&[255, body.len() as u8]);
            bytes.extend_from_slice(&body);
        }
        if let (Some(_), Some(local)) = (self.0.eht, self.0.local.eht) {
            // mac80211 ieee80211_put_eht_cap: only when EHT was negotiated.
            let body = local.capability_body();
            bytes.extend_from_slice(&[255, body.len() as u8]);
            bytes.extend_from_slice(&body);
        }
    }
}
impl Offer {
    /// The VHT Capabilities body actually sent in the association request:
    /// the local body narrowed to the scanned AP's beamforming roles, as
    /// Linux mac80211/mlme.c ieee80211_add_vht_ie does ("some APs get
    /// confused if our capabilities are better than theirs"): no SU/MU
    /// beamformee without an AP SU beamformer and no MU beamformee without
    /// an AP MU beamformer.
    pub fn advertised_vht_capability(&self) -> [u8; 12] {
        let Some(local) = self.0.local.vht else {
            return [0; 12];
        };
        let mut body = local.capability_body();
        let Some(vht) = self.0.vht else {
            return body;
        };
        let ap = vht.peer_capability();
        let mut cap = le32(&body[..4]);
        if ap & 1 << 11 == 0 {
            cap &= !(1 << 12 | 7 << 13 | 1 << 20);
        } else if ap & 1 << 19 == 0 {
            cap &= !(1 << 20);
        }
        body[..4].copy_from_slice(&cap.to_le_bytes());
        body
    }
}
impl Negotiated {
    selection_accessors!();
}

fn element_selectors(bytes: &[u8], primary: u8) -> Result<u8, Error> {
    let band = channel::band(primary).ok_or(Error::InvalidBss)?;
    if bytes.len() > 2048 {
        return Err(Error::InvalidBss);
    }
    let mut rates = super::RateElements {
        allowed: super::SEL_PHY,
        ..Default::default()
    };
    super::ies(bytes, |id, body| rates.observe(id, body))?;
    if !rates.supported
        || rates.rates == 0
        || rates.basic == 0
        || band == channel::Band::Ghz5 && rates.basic & 15 != 0
    {
        return Err(Error::UnsupportedRates);
    }
    Ok(rates.selectors)
}

/// Every mandatory PHY membership selector needs that PHY negotiated
/// (mac80211 ieee80211_determine_chan_mode `sta_selectors` subset check).
/// HT is implied by any selection; EHT/UHR stay unsupported here.
fn check_selectors(selectors: u8, selection: &Selection) -> Result<(), Error> {
    let mut supported = super::SEL_HT;
    if selection.vht.is_some() {
        supported |= super::SEL_VHT;
    }
    if selection.he.is_some() {
        supported |= super::SEL_HE;
    }
    if selection.eht.is_some() {
        supported |= super::SEL_EHT;
    }
    if selectors & super::SEL_PHY & !supported != 0 {
        return Err(Error::UnsupportedRates);
    }
    Ok(())
}
fn select(local: LocalPhy, ap: ApElements, primary: u8) -> Result<Selection, Error> {
    let cap = ap.ht_cap.ok_or(Error::UnsupportedRates)?;
    let op = HtOperation::parse(ap.ht_op.ok_or(Error::UnsupportedRates)?, primary)?;
    if op.secondary.is_some() && le16(&cap[..2]) & 2 == 0 {
        return Err(Error::InvalidBss);
    }
    let mut tx = [0; 10];
    let mut basic = [0; 10];
    for i in 0..10 {
        tx[i] = local.ht.tx_selection[i] & cap[3 + i];
        basic[i] = op.body[6 + i];
        if basic[i] & !local.ht.rx[i] != 0 {
            return Err(Error::UnsupportedRates);
        }
    }
    if tx.iter().all(|v| *v == 0) {
        return Err(Error::UnsupportedRates);
    }
    let mut selected = Selection {
        local,
        ht: HtNegotiation {
            local: local.ht,
            tx,
            peer: cap,
            operation: op,
            basic,
        },
        vht: None,
        he: None,
        eht: None,
        width: Width::Twenty,
        center: primary,
        channels: [primary, 0, 0, 0, 0, 0, 0, 0],
        count: 1,
        center2: 0,
    };
    if local.ht.width == HtWidth::TwentyForty && le16(&cap[..2]) & 2 != 0 {
        if let Some(second) = op.secondary {
            selected.width = Width::Forty;
            selected.center = ((u16::from(primary) + u16::from(second)) / 2) as u8;
            selected.channels = [primary.min(second), primary.max(second), 0, 0, 0, 0, 0, 0];
            selected.count = 2;
        }
    }
    if let (Some(local_vht), Some(peer), Some(operation)) = (local.vht, ap.vht_cap, ap.vht_op) {
        if channel::band(primary) != Some(channel::Band::Ghz5) {
            return Err(Error::UnsupportedRates);
        }
        let peer_info = le32(&peer[..4]);
        let supp = (peer_info >> 2) & 3;
        // IEEE802.11-2020 Table 9-272: only an Extended-NSS-BW-capable
        // station interprets a capable AP's Extended NSS BW Support field;
        // otherwise it reads as0 (cfg80211 ieee80211_get_vht_max_nss).
        let ext = if local_vht.ext_nss_bw && le16(&peer[10..12]) & (1 << 13) != 0 {
            peer_info >> 30
        } else {
            0
        };
        if supp == 2 && matches!(ext, 1 | 2) {
            // Reserved Table 9-272 combination.
            return Err(Error::UnsupportedRates);
        }
        let support_160 = matches!(supp, 1 | 2) || supp == 0 && ext != 0;
        let support_80p80 = supp == 2 || supp == 1 && ext != 0 || supp == 0 && ext >= 2;
        let mut tx = intersect_maps(local_vht.tx, le16(&peer[4..6]));
        let basic = le16(&operation[3..5]);
        if !map_has_rates(tx) || !supports_map(tx, basic) || !supports_map(local_vht.rx, basic) {
            return Err(Error::UnsupportedRates);
        }
        let ccfs0 = operation[1];
        // mac80211 ieee80211_chandef_vht_oper: with Extended NSS BW the
        // second segment may be carried in HT Operation CCFS2 (operation
        // mode bits5..12, IEEE802.11-2020 9.4.2.56).
        let ccfs2 = (le16(&op.body[2..4]) >> 5) as u8;
        let ccf1 = match (supp, ext) {
            (_, 0) => operation[2],
            (0, _) => ccfs2,
            (1, 1 | 2) if operation[2] == 0 => ccfs2,
            _ => operation[2],
        };
        let discontiguous = match operation[0] {
            0 => {
                if operation[2] != 0 || operation[1] != 0 && operation[1] != selected.center {
                    return Err(Error::InvalidBss);
                }
                None
            }
            1 if ccf1 == 0 => {
                let (channels, _) = eighty(ccfs0, primary, selected.width, op.secondary)?;
                selected.width = Width::Eighty;
                selected.center = ccfs0;
                selected.channels[..4].copy_from_slice(&channels);
                selected.count = 4;
                None
            }
            1 if ccf1.abs_diff(ccfs0) > 8 => Some(ccf1),
            3 => Some(operation[2]),
            1 | 2 => {
                // Deprecated width2 uses the contiguous160 center in seg0;
                // revised width1 uses primary80 seg0 and full160 seg1 (or,
                // with Extended NSS BW, CCFS2).
                let center = if operation[0] == 2 {
                    if operation[2] != 0 {
                        return Err(Error::UnsupportedRates);
                    }
                    operation[1]
                } else {
                    ccf1
                };
                if !support_160
                    || selected.width != Width::Forty
                    || ![50, 114, 163].contains(&center)
                {
                    return Err(Error::UnsupportedRates);
                }
                let first = center - 14;
                let channels = core::array::from_fn(|i| first + i as u8 * 4);
                let index = channels
                    .iter()
                    .position(|ch| *ch == primary)
                    .ok_or(Error::InvalidBss)?;
                if op.secondary != Some(channels[index ^ 1])
                    || operation[0] == 1
                        && operation[1] != if index < 4 { center - 8 } else { center + 8 }
                    || channels
                        .iter()
                        .any(|ch| channel::band(*ch) != Some(channel::Band::Ghz5))
                {
                    return Err(Error::InvalidBss);
                }
                if local_vht.width160 {
                    selected.width = Width::OneSixty;
                    selected.center = center;
                    selected.channels = channels;
                    selected.count = 8;
                    tx = limit_nss(tx, peer_max_nss(&peer, true, supp, ext));
                } else {
                    // A narrower local station may use the primary80 half
                    // of a real contiguous160 BSS, without advertising160.
                    let start = if index < 4 { 0 } else { 4 };
                    selected.width = Width::Eighty;
                    selected.center = if index < 4 { center - 8 } else { center + 8 };
                    selected.channels[..4].copy_from_slice(&channels[start..start + 4]);
                    selected.count = 4;
                }
                None
            }
            _ => return Err(Error::UnsupportedRates),
        };
        if let Some(second) = discontiguous {
            // 80+80 (Table 9-274): seg0 is the primary80 center, seg1 another
            // canonical80 center that is neither overlapping nor adjacent
            // (adjacent segments form a contiguous160, cfg80211_chandef_valid).
            let (channels, _) = eighty(ccfs0, primary, selected.width, op.secondary)?;
            if !support_80p80
                || ![42, 58, 106, 122, 138, 155, 171].contains(&second)
                || second.abs_diff(ccfs0) <= 16
            {
                return Err(Error::UnsupportedRates);
            }
            selected.center = ccfs0;
            selected.channels[..4].copy_from_slice(&channels);
            selected.count = 4;
            if local_vht.width80p80 {
                let low = ccfs0.min(second);
                let high = ccfs0.max(second);
                selected.width = Width::OneSixty;
                selected.center2 = second;
                selected.channels = core::array::from_fn(|i| {
                    let center = if i < 4 { low } else { high };
                    center - 6 + (i % 4) as u8 * 4
                });
                selected.count = 8;
                tx = limit_nss(tx, peer_max_nss(&peer, false, supp, ext));
            } else {
                // Like a narrower station on a160 BSS, use the primary80.
                selected.width = Width::Eighty;
            }
        }
        if !map_has_rates(tx) || !supports_map(tx, basic) {
            return Err(Error::UnsupportedRates);
        }
        selected.vht = Some(VhtNegotiation {
            local: local_vht,
            tx,
            peer,
            operation,
            basic,
        });
    }
    selected.he = he::negotiate(
        local.he,
        ap.he_cap,
        ap.he_op,
        primary,
        ap.vht_op,
        selected.vht.is_some(),
        selected.width,
        selected.center2 != 0,
    )?;
    let primary80 = if selected.width == Width::OneSixty && selected.center2 == 0 {
        if primary < selected.center {
            selected.center - 8
        } else {
            selected.center + 8
        }
    } else {
        selected.center
    };
    selected.eht = eht::negotiate(
        local.eht,
        ap.eht_cap,
        ap.eht_op,
        selected.he.as_ref(),
        selected.width,
        selected.center,
        primary80,
        selected.center2 != 0,
    )?;
    Ok(selected)
}
/// Primary80 constituents of a canonical80 center and the primary's index.
fn eighty(
    center: u8,
    primary: u8,
    width: Width,
    secondary: Option<u8>,
) -> Result<([u8; 4], usize), Error> {
    if ![42, 58, 106, 122, 138, 155, 171].contains(&center) || width != Width::Forty {
        return Err(Error::UnsupportedRates);
    }
    let channels = [center - 6, center - 2, center + 2, center + 6];
    let index = channels
        .iter()
        .position(|ch| *ch == primary)
        .ok_or(Error::InvalidBss)?;
    if secondary != Some(channels[index ^ 1]) {
        return Err(Error::InvalidBss);
    }
    Ok((channels, index))
}
/// The AP's maximum receive NSS at160 (`contiguous`) or 80+80, from its RX
/// MCS map and Table 9-272, as cfg80211 ieee80211_get_vht_max_nss computes
/// it for MCS0..7. `ext` is already0 unless both sides are capable. Values
/// above the map maximum are irrelevant here: the result only truncates.
fn peer_max_nss(peer: &[u8; 12], contiguous: bool, supp: u32, ext: u32) -> u8 {
    let map = le16(&peer[4..6]);
    let max = (0..8u8)
        .rev()
        .find(|n| map >> (n * 2) & 3 != 3)
        .map_or(0, |n| n + 1);
    match (contiguous, supp, ext) {
        (true, 0, 1 | 2) => max / 2,
        (true, 0, 3) => 3 * max / 4,
        (false, 0, 1) | (false, 1, 0) => 0,
        (false, 0, 2) | (false, 1, 1) => max / 2,
        (false, 0, 3) | (false, 1, 2) => 3 * max / 4,
        _ => max,
    }
}
/// Mark every NSS above `nss` unsupported (encoding3).
fn limit_nss(map: u16, nss: u8) -> u16 {
    (nss..8).fold(map, |map, n| map | 3 << (n * 2))
}
fn map_has_rates(map: u16) -> bool {
    map & 3 != 3
}
/// Per-NSS intersection. Encoding3 is absence, not a higher MCS ceiling.
pub fn intersect_maps(left: u16, right: u16) -> u16 {
    let mut result = 0;
    for n in 0..8 {
        let (a, b) = (left >> (n * 2) & 3, right >> (n * 2) & 3);
        result |= (if a == 3 || b == 3 { 3 } else { a.min(b) }) << (n * 2);
    }
    result
}
fn supports_map(local: u16, required: u16) -> bool {
    (0..8).all(|n| {
        let (have, need) = (local >> (n * 2) & 3, required >> (n * 2) & 3);
        need == 3 || have != 3 && have >= need
    })
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "phy_tests.rs"]
mod tests;
