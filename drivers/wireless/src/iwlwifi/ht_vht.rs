//! HT/VHT station negotiation. Wire layouts follow Linux ieee80211.h and
//! iwlwifi mld/{tlc,sta,link}.c, fw/api/{rs,phy-ctxt,mac-cfg}.h.

use super::boot_context::{put16, put32};
use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_wireless::iface::PhyCapabilities;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Local {
    pub ht: bool,
    pub vht: bool,
    pub he: bool,
    pub tx_streams: u8,
    pub rx_streams: u8,
    /// Raw, valid 5GHz NVM_CHANNEL_160MHZ facts in station_api's channel
    /// order. A SKU bit or later MCC response cannot create these facts.
    pub(super) width160_channels: u64,
    /// Actual complete native rate-consumer namespace, selected after NVM
    /// parsing from the retained firmware metadata (zero means not proved).
    pub(super) native_rates: u8,
}

impl Local {
    pub fn from_nvm(sku: u32, tx: u32, rx: u32) -> Self {
        let limit = if sku & (1 << 5) != 0 { 1 } else { 2 };
        Self {
            ht: sku & 4 != 0,
            vht: sku & 12 == 12,
            he: sku & 20 == 20,
            tx_streams: tx.count_ones().min(limit) as u8,
            rx_streams: rx.count_ones().min(limit) as u8,
            width160_channels: 0,
            native_rates: 0,
        }
    }

    pub(super) fn with_nvm_channels(mut self, flags: &[u32]) -> Self {
        self.width160_channels = flags
            .iter()
            .take(51)
            .enumerate()
            .fold(0, |mask, (i, flags)| {
                mask | if i >= 14 && flags & (1 | (1 << 11)) == (1 | (1 << 11)) {
                    1u64 << i
                } else {
                    0
                }
            });
        self
    }

    pub(super) fn supports160(self) -> bool {
        self.vht && self.width160_channels != 0 && matches!(self.native_rates, 2 | 3)
    }

    pub(super) fn permits160(self, center: u8) -> bool {
        self.supports160()
            && [50, 114, 163].contains(&center)
            && [-14i16, -10, -6, -2, 2, 6, 10, 14]
                .into_iter()
                .all(|offset| {
                    u8::try_from(i16::from(center) + offset)
                        .ok()
                        .and_then(super::station_api::channel_index)
                        .is_some_and(|index| self.width160_channels & (1u64 << index) != 0)
                })
    }

    pub fn capabilities(self, band: u32) -> Option<PhyCapabilities> {
        if !matches!(band, 2400 | 5000) || !self.ht || self.tx_streams == 0 || self.rx_streams == 0
        {
            return None;
        }
        let mut ht = [0; 26];
        // 20/40 MHz, SMPS disabled, SGI20/40. No greenfield, beamforming,
        // delayed BA or 7935-byte A-MSDUs. Minimum MPDU spacing is 2us.
        put16(&mut ht, 0, 0x6e);
        ht[2] = 3 | (4 << 2);
        ht[3..3 + self.rx_streams as usize].fill(0xff);
        ht[15] = 1;
        if self.rx_streams != self.tx_streams {
            ht[15] |= 2 | ((self.tx_streams - 1) << 2);
        }
        let vht = (self.vht && band == 5000).then(|| {
            let mut vht = [0; 12];
            // Linux derives contiguous160 from actual NVM channel flags.
            // 80+80 remains absent; full per-span proof is still required.
            put32(
                &mut vht,
                0,
                (1 << 5)
                    | (3 << 23)
                    | if self.supports160() {
                        (1 << 2) | (1 << 6)
                    } else {
                        0
                    },
            );
            put16(&mut vht, 4, mcs_map(self.rx_streams));
            put16(&mut vht, 8, mcs_map(self.tx_streams));
            if self.supports160() {
                vht[11] |= 0x20; // VHT Extended NSS BW Capable, not a wider local NSS promise.
            }
            vht
        });
        Some(PhyCapabilities { ht, vht })
    }
}

fn mcs_map(streams: u8) -> u16 {
    let mut map = u16::MAX;
    for stream in 0..streams {
        map = (map & !(3 << (2 * stream))) | (2 << (2 * stream));
    }
    map
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Negotiated {
    /// TLC mode: legacy=0, HT=1, VHT=2.
    pub mode: u8,
    /// TLC/PHY bandwidth: 20=0, 40=1, 80=2, contiguous160=3.
    pub width: u8,
    pub center: u8,
    pub sgi: u8,
    pub mcs: [u16; 2],
    pub flags: u16,
    pub dynamic_smps: bool,
    pub ampdu_exp: u8,
    pub density: u8,
    pub protection: u32,
    pub(super) wide: Option<WideVht>,
}

/// The original shared offer and actual response-refined VHT facts. The
/// H2E parsing fact comes only from the already selected security plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct WideVht {
    // Selection retains the shared HE/EHT/UHR local and response facts too.
    // Keep that immutable snapshot out of every ordinary connection/future.
    offer: Arc<narf_wireless::association::phy::Offer>,
    vht: narf_wireless::association::phy::VhtNegotiation,
    center: u8,
    h2e: bool,
}

impl WideVht {
    // Only the wide path needs the full shared selection on its call stack.
    #[inline(never)]
    fn new(offer: &narf_wireless::association::phy::Offer, h2e: bool) -> Self {
        Self {
            vht: *offer.vht().unwrap(),
            center: offer.center_channel(),
            offer: Arc::new(*offer),
            h2e,
        }
    }

    #[inline(never)]
    fn confirm(&self, ies: &[u8]) -> Result<Option<Self>, &'static str> {
        let confirmed = self
            .offer
            .response_elements_with_sae_h2e(ies, self.h2e)
            .map_err(|_| "native160 response did not confirm the original PHY offer")?;
        Ok(
            (confirmed.width() == narf_wireless::association::phy::Width::OneSixty
                && !confirmed.discontiguous())
            .then(|| Self {
                vht: *confirmed.vht().unwrap(),
                center: confirmed.center_channel(),
                offer: Arc::clone(&self.offer),
                h2e: self.h2e,
            }),
        )
    }
}

/// Return singleton IEs and reject truncated or ambiguous capability data.
fn element(ies: &[u8], id: u8, size: usize) -> Result<Option<&[u8]>, &'static str> {
    let mut rest = ies;
    let mut found = None;
    while !rest.is_empty() {
        if rest.len() < 2 || rest[1] as usize > rest.len() - 2 {
            return Err("truncated PHY IE");
        }
        let body = &rest[2..2 + rest[1] as usize];
        if rest[0] == id {
            if found.is_some() || body.len() != size {
                return Err("invalid or duplicate PHY IE");
            }
            found = Some(body);
        }
        rest = &rest[2 + rest[1] as usize..];
    }
    Ok(found)
}

impl Negotiated {
    /// Association responses can omit operation IEs already received in
    /// beacons. Capabilities must be confirmed by the response itself.
    pub fn confirm(
        &self,
        mut local: Local,
        beacon: &[u8],
        reply: &[u8],
        channel: u8,
        wmm: bool,
    ) -> Result<Self, &'static str> {
        local.ht &= self.mode >= 1;
        local.vht &= self.mode >= 2;
        let mut ies = reply.to_vec();
        for (id, size) in [(61, 22), (192, 5)] {
            if element(reply, id, size)?.is_none() {
                if let Some(body) = element(beacon, id, size)? {
                    ies.extend_from_slice(&[id, size as u8]);
                    ies.extend_from_slice(body);
                }
            }
        }
        let wide = if let Some(old) = &self.wide {
            old.confirm(&ies)?
        } else {
            None
        };
        Self::parse_inner(
            local,
            &ies,
            channel,
            wmm,
            |width, center| width <= self.width && (width < self.width || center == self.center),
            wide,
        )
    }

    pub fn parse(
        local: Local,
        ies: &[u8],
        channel: u8,
        wmm: bool,
        permitted: impl Fn(u8, u8) -> bool,
    ) -> Result<Self, &'static str> {
        Self::parse_inner(local, ies, channel, wmm, permitted, None)
    }

    pub(super) fn parse_with_offer(
        local: Local,
        ies: &[u8],
        channel: u8,
        wmm: bool,
        permitted: impl Fn(u8, u8) -> bool,
        offer: Option<(&narf_wireless::association::phy::Offer, bool)>,
    ) -> Result<Self, &'static str> {
        let wide = offer.and_then(|(offer, h2e)| {
            (offer.width() == narf_wireless::association::phy::Width::OneSixty
                && !offer.discontiguous())
            .then(|| WideVht::new(offer, h2e))
        });
        Self::parse_inner(local, ies, channel, wmm, permitted, wide)
    }

    fn parse_inner(
        local: Local,
        ies: &[u8],
        channel: u8,
        wmm: bool,
        permitted: impl Fn(u8, u8) -> bool,
        wide: Option<WideVht>,
    ) -> Result<Self, &'static str> {
        let ht = element(ies, 45, 26)?;
        let operation = element(ies, 61, 22)?;
        let vht = element(ies, 191, 12)?;
        let vht_op = element(ies, 192, 5)?;
        let erp = element(ies, 42, 1)?;
        let mut result = Self {
            center: channel,
            protection: u32::from(channel <= 14 && erp.is_some_and(|erp| erp[0] & 2 != 0)),
            ..Self::default()
        };
        if !local.ht || !wmm || channel == 14 || ht.is_none() {
            return Ok(result);
        }
        let ht = ht.unwrap();
        let op = operation.ok_or("HT AP has no operation IE")?;
        if op[0] != channel {
            return Err("HT primary channel disagrees with received channel");
        }
        // Basic HT MCS entries are mandatory for every station in this BSS.
        for (index, &required) in op[6..].iter().enumerate() {
            let ours = if index < local.rx_streams as usize {
                0xff
            } else {
                0
            };
            if required & !ours != 0 {
                return Err("AP requires unsupported HT basic MCS");
            }
        }
        let cap = u16::from_le_bytes(ht[..2].try_into().unwrap());
        let smps = (cap >> 2) & 3;
        if smps == 2 {
            return Err("reserved HT SMPS mode");
        }
        let streams = if smps == 0 { 1 } else { local.tx_streams };
        result.mode = 1;
        result.dynamic_smps = smps == 1;
        result.mcs = [
            u16::from(ht[3]),
            if streams > 1 { u16::from(ht[4]) } else { 0 },
        ];
        if result.mcs[0] == 0 {
            return Err("AP has no common HT MCS");
        }
        result.sgi = u8::from(cap & (1 << 5) != 0);
        result.ampdu_exp = ht[2] & 3;
        result.density = (ht[2] >> 2) & 7;
        result.flags = if cap & 1 != 0 { 2 } else { 0 }; // TX LDPC
        let ht_protection = op[2] & 3;
        if cap & 2 != 0 && op[1] & 4 != 0 {
            let center = match op[1] & 3 {
                1 => channel.checked_add(2),
                3 => channel.checked_sub(2),
                _ => None,
            };
            if let Some(center) = center.filter(|&center| permitted(1, center)) {
                result.width = 1;
                result.center = center;
                if cap & (1 << 6) != 0 {
                    result.sgi |= 2;
                }
            }
        }
        if local.vht && channel > 14 {
            if let Some(vht) = vht {
                let op = vht_op.ok_or("VHT AP has no operation IE")?;
                let cap = u32::from_le_bytes(vht[..4].try_into().unwrap());
                let rx = u16::from_le_bytes(vht[4..6].try_into().unwrap());
                let tx = u16::from_le_bytes(vht[8..10].try_into().unwrap());
                if tx & 3 == 3 {
                    return Err("AP has no VHT transmit MCS");
                }
                let basic = u16::from_le_bytes(op[3..5].try_into().unwrap());
                for nss in 0..8 {
                    let required = (basic >> (2 * nss)) & 3;
                    if required != 3 && nss >= local.rx_streams {
                        return Err("AP requires unsupported VHT basic NSS");
                    }
                }
                if op[0] > 3 {
                    return Err("invalid VHT operation width");
                }
                // On wider BSSs use their primary 80 MHz segment. Older
                // 160 MHz operation encoding names the 160 MHz center.
                let center = if op[0] == 2 {
                    if channel < op[1] {
                        op[1].checked_sub(8)
                    } else {
                        op[1].checked_add(8)
                    }
                } else {
                    Some(op[1])
                };
                if result.width == 1 && op[0] != 0 {
                    if let Some(center) = center.filter(|&center| {
                        [2, 6].contains(&channel.abs_diff(center)) && permitted(2, center)
                    }) {
                        result.width = 2;
                        result.center = center;
                        if cap & (1 << 5) != 0 {
                            result.sgi |= 4;
                        }
                    }
                }
                result.mode = 2;
                result.mcs = [0; 2];
                for nss in 0..streams.min(2) as usize {
                    let bits = match (rx >> (2 * nss)) & 3 {
                        0 => 0xff,
                        1 => 0x1ff,
                        2 => 0x3ff,
                        _ => 0,
                    };
                    result.mcs[nss] = if result.width == 0 {
                        bits & !0x200
                    } else {
                        bits
                    };
                }
                if result.mcs[0] == 0 {
                    return Err("AP has no common VHT MCS");
                }
                result.flags = if cap & (1 << 4) != 0 { 2 } else { 0 };
                result.ampdu_exp = ((cap >> 23) & 7) as u8;
                if result.width == 2 {
                    if let Some(wide) = wide
                        .filter(|wide| local.permits160(wide.center) && permitted(3, wide.center))
                    {
                        result.width = 3;
                        result.center = wide.center;
                        result.sgi |= u8::from(wide.vht.tx_sgi160()) << 3;
                        result.wide = Some(wide);
                    }
                }
            }
        }
        if matches!(ht_protection, 1 | 3) || (ht_protection == 2 && result.width != 0) {
            // LINK_PROT_FLG_HT_PROT | LINK_PROT_FLG_FAT_PROT, as in mld/link.c.
            result.protection |= 6;
        }
        Ok(result)
    }

    pub fn association_ies(&self, local: Local, channel: u8) -> Vec<u8> {
        let mut ies = Vec::new();
        if self.mode == 0 {
            return ies;
        }
        let mut caps = local
            .capabilities(if channel > 14 { 5000 } else { 2400 })
            .unwrap();
        if self.width == 0 {
            caps.ht[0] &= !(2 | 0x40); // HT20-only station on a wider AP
        }
        ies.extend_from_slice(&[45, 26]);
        ies.extend_from_slice(&caps.ht);
        if self.mode == 2 {
            ies.extend_from_slice(&[191, 12]);
            ies.extend_from_slice(&caps.vht.unwrap());
            // Operating Mode Notification IE: restrict the AP's TX width
            // and RX NSS when our policy or antenna count is narrower.
            ies.extend_from_slice(&[199, 1, self.width | ((local.rx_streams - 1) << 4)]);
        }
        ies
    }

    pub fn apply_tlc(&self, body: &mut [u8; 44]) {
        body[8] = self.width;
        body[9] = self.mode;
        body[11] = self.sgi;
        put16(body, 12, self.flags);
        put32(body, 16, self.mcs[0] as u32);
        put32(body, 28, self.mcs[1] as u32);
        if let Some(wide) = &self.wide {
            for nss in 0..2 {
                let map = wide.vht.tx_mcs_map();
                let bits = match (map >> (2 * nss)) & 3 {
                    0 => 0xff,
                    1 => 0x1ff,
                    2 => 0x3ff,
                    _ => 0,
                };
                put32(
                    body,
                    20 + nss * 12,
                    if self.mcs[nss] == 0 { 0 } else { bits },
                );
            }
        }
        if self.mode != 0 {
            put16(body, 40, 3839);
        }
    }

    pub fn apply_peer(&self, body: &mut [u8; 104], aid: u16) {
        put32(body, 28, aid as u32);
        put32(body, 40, u32::from(self.mcs[1] != 0));
        put32(body, 44, u32::from(self.dynamic_smps));
        put32(body, 56, self.density as u32);
        put32(body, 60, self.ampdu_exp as u32);
    }

    pub fn apply_link(&self, body: &mut [u8; 208]) {
        put32(body, 52, self.protection);
        if self.mode != 0 {
            let qos = u32::from_le_bytes(body[56..60].try_into().unwrap());
            put32(body, 56, qos | 2); // MAC_QOS_FLG_TGN
        }
    }

    pub fn apply_phy(&self, body: &mut [u8; 32], primary: u8) {
        body[13] = self.width;
        let distance = primary.abs_diff(self.center);
        body[14] = if self.width == 0 {
            0
        } else {
            (distance.saturating_sub(2) / 4) | if primary > self.center { 4 } else { 0 }
        };
        body[28] = body[14] ^ 4;
    }

    /// Before CCMP/reorder mutation, bound the new native160 profile's
    /// legacy HT/VHT fallback PPDUs by the actual local RX promise. HE has
    /// its separate response-bound HE map and coding check.
    pub(super) fn admits_wide_rx(&self, local: Local, rate: u32) -> bool {
        if self.width != 3 {
            return true;
        }
        let format = (rate >> 8) & 7;
        if format <= 1 || format == 4 {
            return true;
        }
        if !matches!(format, 2 | 3) || !matches!(local.native_rates, 2 | 3) {
            return false;
        }
        let nss = (rate >> if local.native_rates == 3 { 5 } else { 4 }) & 1;
        let mcs = rate & if local.native_rates == 3 { 31 } else { 15 };
        let width = (rate >> 11) & 7;
        let gi = (rate >> 20) & 7;
        let reserved = if local.native_rates == 3 { 0xc0 } else { 0xe0 };
        nss < u32::from(local.rx_streams)
            && mcs <= if format == 2 { 7 } else { 9 }
            && width <= if format == 2 { 1 } else { 3 }
            && gi <= 1
            && rate & (reserved | (15 << 16) | (1 << 25) | (1 << 26)) == 0
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "ht_vht_tests.rs"]
mod tests;
