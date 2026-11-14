//! The operating channel width of an associated station as it follows its
//! AP: the width an announced channel switch names (mac80211 spectmgmt.c
//! `ieee80211_parse_ch_switch_ie`), the width the AP's operation elements
//! name afterwards (mlme.c `ieee80211_config_bw`), the connection's width
//! limit and the downgrade to a width the policy allows
//! (`ieee80211_chandef_downgrade`). 2.4/5 GHz only.
use super::association::ChannelSwitch;
use super::channel::{self, Band};
use super::cmd::{CH_BW_160, CH_BW_20, CH_BW_40, CH_BW_80};
use alloc::vec::Vec;
use narf_wireless::association::phy::ApElements;

/// A 2.4/5 GHz channel definition: primary channel, CMD_CBW width and
/// centre channel (cfg80211 `cfg80211_chan_def`, contiguous only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Chandef {
    pub primary: u8,
    pub width: u8,
    pub center: u8,
}

impl Chandef {
    pub(crate) fn twenty(primary: u8) -> Option<Self> {
        channel::band(primary)?;
        Some(Self {
            primary,
            width: CH_BW_20,
            center: primary,
        })
    }
    /// HT40 with the secondary 20 MHz channel above (offset 1) or below (3)
    /// the primary (HT Operation / Secondary Channel Offset encoding).
    pub(crate) fn forty(primary: u8, offset: u8) -> Option<Self> {
        let secondary = match offset {
            1 => primary.checked_add(4)?,
            3 => primary.checked_sub(4)?,
            _ => return None,
        };
        Self::with_secondary(primary, secondary)
    }
    fn with_secondary(primary: u8, secondary: u8) -> Option<Self> {
        let band = channel::band(primary)?;
        if channel::band(secondary)? != band || primary.abs_diff(secondary) != 4 {
            return None;
        }
        if band == Band::Ghz5
            && !channel::CHANNELS_5GHZ
                .chunks_exact(2)
                .any(|pair| pair.contains(&primary) && pair.contains(&secondary))
        {
            return None;
        }
        Some(Self {
            primary,
            width: CH_BW_40,
            center: ((u16::from(primary) + u16::from(secondary)) / 2) as u8,
        })
    }
    pub(crate) fn eighty(primary: u8, center: u8) -> Option<Self> {
        channel::block80(primary, center)?;
        Some(Self {
            primary,
            width: CH_BW_80,
            center,
        })
    }
    pub(crate) fn one_sixty(primary: u8, center: u8) -> Option<Self> {
        channel::block160(primary, center)?;
        Some(Self {
            primary,
            width: CH_BW_160,
            center,
        })
    }
    /// The 20 MHz channel paired with the primary in its 40 MHz half.
    pub(crate) fn secondary(self) -> Option<u8> {
        match self.width {
            CH_BW_40 => (2 * u16::from(self.center))
                .checked_sub(u16::from(self.primary))
                .and_then(|secondary| u8::try_from(secondary).ok()),
            CH_BW_80 => {
                let channels = channel::block80(self.primary, self.center)?;
                let index = channels.iter().position(|&ch| ch == self.primary)?;
                Some(channels[index ^ 1])
            }
            CH_BW_160 => {
                let channels = channel::block160(self.primary, self.center)?;
                let index = channels.iter().position(|&ch| ch == self.primary)?;
                Some(channels[index ^ 1])
            }
            _ => None,
        }
    }
    /// The centre of the primary 80 MHz of a 160 MHz channel.
    fn primary80(self) -> u8 {
        if self.primary < self.center {
            self.center - 8
        } else {
            self.center + 8
        }
    }
    /// mac80211 `ieee80211_chandef_downgrade`: 160 to its primary 80, 80 to
    /// its primary 40, 40 to the primary 20.
    pub(crate) fn downgrade(self) -> Self {
        let narrower = match self.width {
            CH_BW_160 => Self::eighty(self.primary, self.primary80()),
            CH_BW_80 => self
                .secondary()
                .and_then(|secondary| Self::with_secondary(self.primary, secondary)),
            _ => Self::twenty(self.primary),
        };
        narrower.unwrap_or(Self {
            primary: self.primary,
            width: CH_BW_20,
            center: self.primary,
        })
    }
    /// Downgraded until it is no wider than `limit`.
    pub(crate) fn limited(mut self, limit: u8) -> Self {
        while self.width > limit {
            self = self.downgrade();
        }
        self
    }
    /// cfg80211 `cfg80211_chandef_compatible`: the narrower is the wider's
    /// own primary part.
    pub(crate) fn compatible(self, other: Self) -> bool {
        self.limited(other.width) == other.limited(self.width)
    }
}

/// The band an ECSA operating class names (cfg80211
/// `ieee80211_operating_class_to_band`).
pub(crate) fn class_band(class: u8) -> Option<Band> {
    match class {
        81..=84 => Some(Band::Ghz2),
        112 | 115..=130 => Some(Band::Ghz5),
        131..=137 => Some(Band::Ghz6),
        _ => None,
    }
}

/// cfg80211 `ieee80211_operating_class_to_chandef` for 2.4/5 GHz: the
/// channel width an operating class implies for `primary` (none for 80+80,
/// whose second segment the class does not give).
pub(crate) fn class_chandef(class: u8, primary: u8) -> Option<Chandef> {
    let frequency = channel::frequency(primary)?;
    let base = if frequency >= 5745 { 5745 } else { 5180 };
    let offset = frequency.saturating_sub(base) / 20;
    let offset = (offset & 7) as u8;
    match class {
        81 | 82 | 115 | 118 | 121 | 124 | 125 => Chandef::twenty(primary),
        83 | 116 | 119 | 122 | 126 => Chandef::forty(primary, 1),
        84 | 117 | 120 | 123 | 127 => Chandef::forty(primary, 3),
        128 => Chandef::eighty(primary, (primary + 6).checked_sub((offset & 3) * 4)?),
        129 => Chandef::one_sixty(primary, (primary + 14).checked_sub(offset * 4)?),
        _ => None,
    }
}

/// mac80211 `wbcs_elem_to_chandef`: the Wide Bandwidth Channel Switch
/// element's width (0: 40, 1: 80, or 160 by the revised two-segment
/// encoding, 2: deprecated 160, 3: deprecated 80+80) and centre segments.
/// CONNAC2 has no 80+80, so an 80+80 switch keeps its primary 80.
fn wide_chandef(primary: u8, [width, ccfs0, ccfs1]: [u8; 3]) -> Option<Chandef> {
    match width {
        1 if ccfs1 != 0 && ccfs0.abs_diff(ccfs1) == 8 => Chandef::one_sixty(primary, ccfs1),
        1 | 3 => Chandef::eighty(primary, ccfs0),
        2 => Chandef::one_sixty(primary, ccfs0),
        _ => Chandef::with_secondary(
            primary,
            u8::try_from((2 * u16::from(ccfs0)).checked_sub(u16::from(primary))?).ok()?,
        ),
    }
}

/// The band of an announced switch's channel: the ECSA operating class's
/// when it names one, else the channel number's.
pub(crate) fn switch_band(switch: &ChannelSwitch) -> Option<Band> {
    match switch.operating_class.and_then(class_band) {
        Some(band) => Some(band),
        None => channel::band(switch.channel),
    }
}

/// The channel an announced switch moves the BSS to (the AP's chandef)
/// and the one this station uses there, no wider than `limit` (mac80211
/// `ieee80211_parse_ch_switch_ie`). `vht` is a VHT connection: only it
/// reads the Wide Bandwidth Channel Switch element. `None` is a switch
/// with inconsistent channel data, which ends the link.
pub(crate) fn switch_target(
    switch: &ChannelSwitch,
    limit: u8,
    vht: bool,
) -> Option<(Chandef, Chandef)> {
    let primary = switch.channel;
    if switch_band(switch)? != channel::band(primary)? {
        return None;
    }
    // Below HT40 the offset and wide elements are ignored; without the
    // Secondary Channel Offset an HT connection takes 20 MHz.
    let (offset, wide) = if limit < CH_BW_40 {
        (None, None)
    } else {
        (switch.secondary_offset, switch.wide.filter(|_| vht))
    };
    let oper = match offset {
        Some(offset @ (1 | 3)) => Chandef::forty(primary, offset)?,
        _ => Chandef::twenty(primary)?,
    };
    if limit < CH_BW_40 {
        return Some((oper, oper));
    }
    let Some(ap) = wide
        .and_then(|wide| wide_chandef(primary, wide))
        .or_else(|| {
            switch
                .operating_class
                .and_then(|c| class_chandef(c, primary))
        })
    else {
        return Some((oper, oper));
    };
    // validate_chandef_by_ht_vht_oper: an HT connection reads it as HT.
    let ap = if vht { ap } else { ap.limited(CH_BW_40) };
    let used = ap.limited(limit);
    used.compatible(oper).then_some((ap, used))
}

/// The AP's operating channel from its HT and VHT Operation elements
/// (mac80211 `ieee80211_determine_ap_chan`: `ieee80211_chandef_ht_oper`
/// and `ieee80211_chandef_vht_oper`, with the Extended NSS BW CCFS2 in
/// the HT Operation). `None` when they are inconsistent: mac80211 then
/// reads the AP as a different mode and disconnects.
pub(crate) fn ap_chandef(ap: &ApElements, primary: u8) -> Option<Chandef> {
    let Some(ht) = ap.ht_operation() else {
        return Chandef::twenty(primary);
    };
    if ht[0] != primary {
        return None;
    }
    let forty = match ht[1] & 3 {
        0 => Chandef::twenty(primary)?,
        offset => {
            // A 40 MHz BSS needs the AP's own 20/40 capability.
            if ap.ht_capability().is_none_or(|cap| cap[0] & 2 == 0) {
                return None;
            }
            Chandef::forty(primary, offset)?
        }
    };
    let Some(vht) = ap.vht_operation() else {
        return Some(forty);
    };
    let (ccfs0, ccfs1) = (vht[1], vht[2]);
    let ccfs2 = (u16::from_le_bytes([ht[2], ht[3]]) >> 5) as u8;
    let wide = match vht[0] {
        0 => return Some(forty),
        1 if ccfs1 != 0 && ccfs0.abs_diff(ccfs1) == 8 => Chandef::one_sixty(primary, ccfs1),
        1 if ccfs1 == 0 && ccfs2 != 0 && ccfs0.abs_diff(ccfs2) == 8 => {
            Chandef::one_sixty(primary, ccfs2)
        }
        1 | 3 => Chandef::eighty(primary, ccfs0),
        2 => Chandef::one_sixty(primary, ccfs0),
        _ => None,
    }?;
    (forty.width == CH_BW_40 && wide.secondary() == forty.secondary()).then_some(wide)
}

/// The AP's HT Operation with the width fields cleared: the secondary
/// channel offset, the STA channel width and the CCFS2 bits.
fn ht_static(operation: [u8; 22]) -> [u8; 22] {
    let mut operation = super::ht20::static_operation(operation);
    operation[1] &= !7;
    operation[2] &= !0xe0;
    operation[3] &= !0x1f;
    operation
}

/// The AP's PHY facts are unchanged apart from the channel width (and the
/// dynamic HT protection bits): a width change mac80211 follows
/// (`ieee80211_config_bw`) rather than a new PHY mode.
pub(crate) fn width_only_change(bound: &ApElements, current: &ApElements) -> bool {
    bound.ht_capability() == current.ht_capability()
        && bound.vht_capability() == current.vht_capability()
        && bound.ht_operation().map(ht_static) == current.ht_operation().map(ht_static)
        && bound.vht_operation().map(|op| [op[3], op[4]])
            == current.vht_operation().map(|op| [op[3], op[4]])
}

/// A Beacon / Probe Response's PHY elements against the bound ones.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BeaconPhy {
    Same,
    /// Only the channel width changed, to a consistent channel: the
    /// station follows it.
    Width(alloc::boxed::Box<ApElements>),
    /// Anything else, an inconsistent operation included: the link ends.
    Changed,
}

pub(crate) fn beacon_phy(bound: &ApElements, ies: &[u8]) -> BeaconPhy {
    match ApElements::parse(ies) {
        Ok(current) if super::ht20::same_ap_phy(bound, &current) => BeaconPhy::Same,
        Ok(current)
            if width_only_change(bound, &current)
                && current
                    .ht_operation()
                    .is_some_and(|op| ap_chandef(&current, op[0]).is_some()) =>
        {
            BeaconPhy::Width(alloc::boxed::Box::new(current))
        }
        _ => BeaconPhy::Changed,
    }
}

/// The BSS's elements describing `def` as its channel: DS Parameter Set,
/// HT Operation (primary, secondary offset, STA channel width, no CCFS2)
/// and VHT Operation (the revised 80/160 encoding), in the AP's HE
/// Operation's VHT Operation Information too. Every other element is kept.
pub(crate) fn describe(ies: &[u8], def: Chandef) -> Option<Vec<u8>> {
    let vht = match def.width {
        CH_BW_80 => [1, def.center, 0],
        CH_BW_160 => [1, def.primary80(), def.center],
        _ => [0, def.center, 0],
    };
    let mut out = Vec::with_capacity(ies.len());
    let mut rest = ies;
    while !rest.is_empty() {
        let len = usize::from(*rest.get(1)?);
        let element = rest.get(..2 + len)?;
        let start = out.len();
        out.extend_from_slice(element);
        let body = &mut out[start + 2..];
        match (element[0], len) {
            (3, 1) => body[0] = def.primary,
            (61, 22) => {
                body[0] = def.primary;
                body[1] &= !7;
                if def.width != CH_BW_20 {
                    body[1] |= 4 | if def.secondary()? > def.primary { 1 } else { 3 };
                }
                body[2] &= !0xe0;
                body[3] &= !0x1f;
            }
            (192, 5) => body[..3].copy_from_slice(&vht),
            // HE Operation (extension 36) with VHT Operation Information
            // Present (parameters bit 14).
            (255, 10..) if body[0] == 36 && body[2] & 0x40 != 0 => {
                body[7..10].copy_from_slice(&vht);
            }
            _ => {}
        }
        rest = &rest[2 + len..];
    }
    Some(out)
}

/// UNI_BSS_INFO_RLM for `def` (`mt76_connac_mcu_uni_set_chctx`, which
/// `mt7921_csa_work` and `mt7921_change_chanctx` send).
pub(crate) fn rlm(def: Chandef, tx_streams: u8, chains: u8) -> [u8; 20] {
    let mut bytes = [0u8; 20];
    bytes[4..8].copy_from_slice(&[2, 0, 16, 0]);
    bytes[8] = def.primary;
    bytes[9] = def.center;
    bytes[11] = def.width;
    bytes[12] = tx_streams;
    bytes[13] = chains;
    bytes[14] = 1;
    bytes[15] = if def.width != CH_BW_20 { 4 } else { 0 };
    bytes[16] = match def.primary.cmp(&def.center) {
        core::cmp::Ordering::Less => 1,
        core::cmp::Ordering::Greater => 3,
        core::cmp::Ordering::Equal => 0,
    };
    bytes[17] = channel::band(def.primary).map_or(0, Band::nl80211);
    bytes
}
