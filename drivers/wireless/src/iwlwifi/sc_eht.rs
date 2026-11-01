// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Bounded single-link EHT on the admitted MLD core103 owner. Source facts
//! follow Linux rf-{fm,wh}.c, pcie/drv.c, fw/pnvm.c and mld/{sta,tlc,rx}.c.
//! No320MHz, puncturing, MLO, beamforming or extra-LTF promise is made.
use super::boot_context::{put16, put32};
use narf_wireless::association::{
    eht::{EhtCapability, EhtNegotiation, EhtOperation, LocalEht},
    he::HeCapability,
    phy::Width,
};

/// Actual boot identity, including the complete ALIVE SKU selected by PNVM.
/// There is no NVM11be SKU bit: Linux enables EHT from the RF configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Source {
    revision: u32,
    radio: u32,
    device: u16,
    subsystem: u16,
    sku: [u32; 3],
    pub reduced: bool,
    pub bandwidth_limit: u16,
}
impl Source {
    pub fn matches(self, device: u16, subsystem: u16, revision: u32, radio: u32) -> bool {
        (self.device, self.subsystem, self.revision, self.radio)
            == (device, subsystem, revision, radio)
            && self.bandwidth_limit >= 160
            && self.reduced == (((radio >> 12) & 0xfff) == 0x112 && self.sku[0] & (1 << 25) != 0)
    }
    pub fn boot(
        device: u16,
        subsystem: u16,
        revision: u32,
        radio: u32,
        parsed: &super::ParsedUcode<'_>,
        alive: &[u8],
    ) -> Result<Option<Self>, &'static str> {
        if super::gen2_profile::firmware_api(parsed) != 103 {
            return Ok(None);
        }
        let (mac, step, rf, rf_step) = (
            (revision >> 4) & 0xfff,
            revision & 15,
            (radio >> 12) & 0xfff,
            (radio >> 8) & 15,
        );
        let native = matches!(
            (mac, step, device),
            (0x48, 0, 0x6e70 | 0x9327 | 0xd240 | 0xd340 | 0xe340 | 0xe440)
                | (0x46 | 0x4b, 1, 0x272b | 0x7740 | 0x4d40 | 0xa840)
        );
        if !native
            || radio & (1 << 28) != 0
            || !matches!((rf, rf_step), (0x112, 1 | 2) | (0x113, 1))
            || mac != 0x48 && rf == 0x112 && rf_step != 2
            || rf == 0x113 && matches!(subsystem, 0x0514 | 0x4514)
        {
            return Ok(None);
        }
        let expected = match parsed.api.versions(0, 1).map(|v| v.1) {
            Some(7) => 144,
            Some(8) => 152,
            _ => return Err("EHT actual ALIVE contract absent"),
        };
        if alive.len() != expected || alive[..2] != 0xcafeu16.to_le_bytes() {
            return Err("EHT actual ALIVE extent/status invalid");
        }
        let sku = core::array::from_fn(|i| {
            u32::from_le_bytes(alive[116 + i * 4..120 + i * 4].try_into().unwrap())
        });
        if sku != [0; 3] {
            super::pnvm::select(
                parsed.api.pnvm.ok_or("EHT actual PNVM source absent")?,
                sku,
                mac as u16,
                rf as u16,
            )?;
        }
        Ok(Some(Self {
            revision,
            radio,
            device,
            subsystem,
            sku,
            reduced: rf == 0x112 && sku[0] & (1 << 25) != 0,
            bandwidth_limit: if matches!(
                subsystem,
                0x1771 | 0x1772 | 0x1791 | 0x1792 | 0x1775 | 0x1776
            ) || device == 0x272b && matches!(subsystem, 0x1773 | 0x1774)
            {
                320 // More-specific actual full-bandwidth Killer match.
            } else if subsystem & 0x0200 != 0
                || matches!(subsystem, 0x1730 | 0x1731 | 0x1735 | 0x1736)
            {
                160
            } else {
                320
            },
        }))
    }
}

/// Conservative native promises common to full and reduced FM/WH SKUs:
/// MCS0..11, at most two streams, no320 or optional EHT beamforming/LTF.
pub(super) fn local(
    phy: super::ht_vht::Local,
    channel: Option<u8>,
) -> Result<LocalEht, &'static str> {
    if !phy.eht || !phy.he || phy.native_rates != 3 {
        return Err("native EHT RF/HE/rates facts absent");
    }
    let nss = phy.rx_streams | (phy.tx_streams << 4);
    let mut capability = [0; 9];
    capability[5] = 0x20; // Actual supported common nominal packet padding16us.
    let result = if channel.is_none() {
        LocalEht::twenty_only([0; 2], capability, [nss, nss, nss, 0])
    } else {
        LocalEht::new([0; 2], capability, [nss, nss, 0])
    }
    .map_err(|_| "native EHT local maps invalid")?;
    if channel.is_some_and(|primary| primary > 14) && phy.supports160() {
        result
            .with_160mhz([nss, nss, 0])
            .map_err(|_| "native EHT160 local maps invalid")
    } else {
        Ok(result)
    }
}

#[derive(Debug)]
pub(super) struct Profile {
    pub negotiation: EhtNegotiation,
    tx: [[u32; 3]; 2],
    rx: [[u8; 4]; 2],
    extension: [[[u8; 2]; 5]; 2],
    rx_coding: u32,
}
impl Profile {
    #[inline(never)]
    pub fn new(
        negotiation: EhtNegotiation,
        original: &EhtNegotiation,
        he: &super::sc_he::Profile,
        static_smps: bool,
    ) -> Result<alloc::sync::Arc<Self>, &'static str> {
        if negotiation.width320() || negotiation.width() != he.negotiation.width() {
            return Err("native EHT span differs from retained HE/PHY owner");
        }
        let local = negotiation.local_capability();
        let local = EhtCapability::parse(&local[1..], he.negotiation.local_capability()[7], false)
            .map_err(|_| "native retained EHT local capability invalid")?;
        let peer = negotiation.peer_capability();
        let mut tx = [[0; 3]; 2];
        let mut rx = [[0; 4]; 2];
        let ranges = |cap: &EhtCapability, wide: bool| -> [u8; 4] {
            let set = cap.mcs_nss();
            if set.len() == 4 {
                return set.try_into().unwrap();
            }
            let at = if wide { 3 } else { 0 };
            if set.len() < at + 3 {
                return [0; 4];
            }
            [set[at], set[at], set[at + 1], set[at + 2]]
        };
        for slot in 0..=usize::from(negotiation.width() == Width::OneSixty) {
            let ours = ranges(&local, slot == 1);
            let theirs = ranges(peer, slot == 1);
            let offered = ranges(original.peer_capability(), slot == 1);
            rx[slot] = ours.map(|nss| nss & 15);
            for (range, mask) in [0xff, 0x300, 0xc00, 0x3000].into_iter().enumerate() {
                let streams = (ours[range] >> 4)
                    .min(theirs[range] & 15)
                    .min(offered[range] & 15)
                    .min(
                        if slot == usize::from(negotiation.width() == Width::OneSixty) {
                            negotiation.tx_max_nss()[range]
                        } else {
                            2
                        },
                    )
                    .min(2);
                for (stream, rates) in tx.iter_mut().enumerate().take(usize::from(streams)) {
                    if stream == 0 || !static_smps {
                        rates[slot] |= mask;
                    }
                }
            }
        }
        if tx[0][0] & 0xff != 0xff {
            return Err("native EHT no usable directional MCS0..7");
        }
        let extension = packet_extension(peer, he.negotiation.peer_capability());
        Ok(alloc::sync::Arc::new(Self {
            negotiation,
            tx,
            rx,
            extension,
            rx_coding: u32::from(he.negotiation.rx_ldpc()) << 16
                | u32::from(he.negotiation.rx_stbc()) << 17,
        }))
    }
    pub fn apply_sta(&self, bytes: &mut [u8; 104]) {
        let factor = u32::from_le_bytes(bytes[60..64].try_into().unwrap());
        put32(
            bytes,
            60,
            (factor + u32::from(self.negotiation.peer_capability().mac_capability()[1] & 1)).min(9),
        );
        put32(bytes, 40, u32::from(self.tx[1].iter().any(|&map| map != 0)));
        for (stream, widths) in self.extension.iter().enumerate() {
            for (width, pair) in widths.iter().enumerate() {
                let at = 72 + (stream * 5 + width) * 2;
                bytes[at..at + 2].copy_from_slice(pair);
            }
        }
    }
    /// MAC_CONFIGv3 wifi_gen uses byte-sized fields: HE at24, EHT at26.
    /// Linux mld/iface.c derives these from response-bound station facts.
    pub fn apply_mac(&self, bytes: &mut [u8; 52]) {
        bytes[26] = 1;
    }
    pub fn apply_tlc(&self, bytes: &mut [u8; 44]) {
        bytes[9] = 4; // IWL_TLC_MNG_MODE_EHT, not a HE capability alias.
        bytes[11] = 0;
        // Linux retains the actual negotiated HE coding flags for EHT.
        // No extra-LTF or other optional EHT flag is added here.
        let flags = u16::from_le_bytes(bytes[12..14].try_into().unwrap()) & 3;
        put16(bytes, 12, flags);
        for (stream, widths) in self.tx.iter().enumerate() {
            for (width, &map) in widths.iter().enumerate() {
                put32(bytes, 16 + stream * 12 + width * 4, map);
            }
        }
    }
    /// Original native v3 word, checked before PN/BA/reorder ownership.
    pub fn admits_rx_rate(&self, rate: u32) -> bool {
        if (rate >> 8) & 7 != 5 {
            return false;
        }
        let width = (rate >> 11) & 7;
        let maximum = match self.negotiation.width() {
            Width::Twenty => 0,
            Width::Forty => 1,
            Width::Eighty => 2,
            Width::OneSixty => 3,
        };
        let mcs = rate & 31;
        let range = match mcs {
            0..=7 => 0,
            8..=9 => 1,
            10..=11 => 2,
            12..=13 => 3,
            _ => return false,
        };
        let slot = usize::from(width == 3);
        let nss = 1 + ((rate >> 5) & 1);
        let kind = (rate >> 23) & 3;
        let gi = (rate >> 20) & 7;
        width <= maximum
            && nss <= u32::from(self.rx[slot][range])
            && (rate & (1 << 17) == 0 || nss == 1)
            && (mcs < 10 || rate & (1 << 16) != 0)
            && kind != 1
            && gi <= if kind == 3 { 2 } else { 3 }
            && (gi != 2 || kind == 3)
            && rate & (0xc0 | ((15 << 16) & !self.rx_coding) | (7 << 25) | (15 << 28)) == 0
    }
    pub fn matches(&self, ies: &[u8], he: &HeCapability) -> bool {
        matches(&self.negotiation, ies, he)
    }
}
pub(super) fn matches(negotiation: &EhtNegotiation, ies: &[u8], he: &HeCapability) -> bool {
    let (mut capability, mut operation) = (None, None);
    let mut rest = ies;
    while !rest.is_empty() {
        let Some((&id, tail)) = rest.split_first() else {
            return false;
        };
        let Some((&length, tail)) = tail.split_first() else {
            return false;
        };
        let Some(body) = tail.get(..usize::from(length)) else {
            return false;
        };
        if id == 255 {
            match body.first() {
                Some(108) => {
                    if capability.is_some() {
                        return false;
                    }
                    capability =
                        EhtCapability::parse(&body[1..], he.phy_capability()[0], true).ok();
                    if capability.is_none() {
                        return false;
                    }
                }
                Some(106) => {
                    if operation.is_some() {
                        return false;
                    }
                    operation = EhtOperation::parse(&body[1..]).ok();
                    if operation.is_none() {
                        return false;
                    }
                }
                _ => {}
            }
        }
        rest = &tail[usize::from(length)..];
    }
    capability.as_ref() == Some(negotiation.peer_capability())
        && operation.as_ref() == Some(negotiation.operation())
}

/// Linux EHT PPE inheritance differs from HE: absent RU widths inherit
/// the last thresholds; absent EHT PPE inherits HE and nominal4096QAM pad.
fn packet_extension(peer: &EhtCapability, he: &HeCapability) -> [[[u8; 2]; 5]; 2] {
    let nominal = (peer.phy_capability()[5] >> 4) & 3;
    let ppe = peer.ppe_thresholds();
    let eht = !ppe.is_empty();
    let ppe = if eht { ppe } else { he.ppe_thresholds() };
    if ppe.is_empty() {
        let pair = match nominal {
            0 => [7, 7],
            1 => [0, 7],
            _ => [7, 0],
        };
        return [[pair; 5]; 2];
    }
    let (streams, bitmap, mut bit) = if eht {
        let header = u16::from_le_bytes(ppe[..2].try_into().unwrap());
        (usize::from((header & 15) + 1).min(2), (header >> 4) & 31, 9)
    } else {
        (
            usize::from((ppe[0] & 7) + 1).min(2),
            u16::from(ppe[0] >> 3) & 15,
            7,
        )
    };
    let field = |at: usize| -> u8 {
        (0..3).fold(0, |value, n| {
            value | ((ppe[(at + n) / 8] >> ((at + n) % 8)) & 1) << n
        })
    };
    let mut result = [[[7; 2]; 5]; 2];
    for widths in result.iter_mut().take(streams) {
        let mut previous = [7; 2];
        for (width, pair) in widths.iter_mut().enumerate() {
            if bitmap & (1 << width) != 0 {
                previous = [field(bit + 3), field(bit)];
                bit += 6;
            }
            *pair = previous;
        }
    }
    if !eht {
        for widths in &mut result {
            for pair in widths {
                if nominal > 1 && pair[1] == 7 {
                    pair[1] = 6;
                } else if nominal == 1 && *pair == [7, 7] {
                    pair[0] = 6;
                }
            }
        }
    }
    result
}
