// SPDX-License-Identifier: GPL-2.0-or-later
//! Typed response-bound SISO HT20/5GHz HT40 and 5GHz VHT20/40/80. Linux
//! mac.c's get_ht_cap advertises20/40 with HT, and each GI from its distinct
//! SERVICE_READY bit; ath10k_create_vht_cap builds the VHT element.
use super::{station::plan_error, Error, ScanBss};
use crate::ath10k::wmi_boot::Capabilities;
use narf_wireless::association::{
    self,
    phy::{intersect_maps, ApElements, HtGi, HtWidth, LocalHt, LocalPhy, LocalVht, Offer, Width},
    Bss, JoinPlan, SecurityMode,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Profile {
    pub(super) capabilities: u16,
    pub(super) ampdu: u8,
    pub(super) mcs: u8,
    pub(super) short_gi: bool,
    receive_sgi20: bool,
    receive_sgi40: bool,
    receive_ldpc: bool,
    receive_stbc: bool,
    /// Native PEER_ASSOC `WMI_PEER_LDPC`: the bound AP receives LDPC and the
    /// local firmware capability permits encoding it.
    pub(super) transmit_ldpc: bool,
    /// The bound AP transmits one-stream STBC that our advertised RX accepts.
    pub(super) peer_tx_stbc: bool,
    pub(super) center: u16,
    pub(super) secondary: Option<u16>,
    /// Negotiated VHT facts; `None` for an HT-only profile.
    pub(super) vht: Option<Vht>,
    local: LocalPhy,
    offered: Offer,
}
/// Requested local PHY: the HT20/HT40 profiles, or VHT (HT20/40 plus a
/// VHT80-capable element) that only a 5GHz 80 MHz-qualified BSS reaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phy {
    Ht20,
    Ht40,
    Vht,
}
/// Linux `mac.c::ath10k_peer_assoc_h_vht` facts for PEER_ASSOC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Vht {
    /// `peer_vht_caps`: the AP's VHT Capabilities Information masked by our
    /// own as mac80211 `vht.c::ieee80211_vht_cap_ie_to_sta_vht_cap` does.
    pub(super) capabilities: u32,
    /// The AP's Maximum A-MPDU Length Exponent (bits23..25).
    pub(super) factor: u8,
    /// `wmi_vht_rate_set`: rx = what the AP receives (its RX map narrowed by
    /// our TX map), tx = what the AP transmits (its TX map narrowed by our
    /// RX map), each with the AP's highest-rate field.
    pub(super) rx_max: u16,
    pub(super) rx_mcs: u16,
    pub(super) tx_max: u16,
    pub(super) tx_mcs: u16,
    /// Occupied VHT80 (`WMI_PEER_80MHZ`, `MODE_11AC_VHT80`).
    pub(super) eighty: bool,
    receive_sgi80: bool,
    receive_ldpc: bool,
    receive_stbc: bool,
    /// Our one-stream RX map (low two bits: 0/1/2 = MCS0-7/8/9).
    receive_map: u16,
}
pub(super) fn supported(caps: &Capabilities) -> bool {
    caps.ht & 1 != 0 && (1..=4).contains(&caps.rf_chains)
}
/// Linux `mac.c::ath10k_get_ht_cap` coding facts from SERVICE_READY
/// `ht_cap_info`: IEEE LDPC_CODING follows `WMI_HT_CAP_LDPC` (0x0040) or the
/// pair `WMI_HT_CAP_RX_LDPC` (0x1000) and `WMI_HT_CAP_TX_LDPC` (0x2000); a
/// lone directional bit is not advertised. RX STBC follows the nonzero
/// `WMI_HT_CAP_RX_STBC` field (0x0030); this one-stream profile promises only
/// one STBC stream. TX STBC needs `cfg_tx_chainmask > 1`, which this SISO
/// profile never selects, so it stays absent.
pub(super) fn ldpc(caps: &Capabilities) -> bool {
    caps.ht & 0x40 != 0 || caps.ht & 0x3000 == 0x3000
}
pub(super) fn rx_stbc(caps: &Capabilities) -> bool {
    caps.ht & 0x30 != 0
}
/// VHT is offered only when SERVICE_READY reports a nonzero
/// `vht_cap_info`; Linux `ath10k_create_vht_cap` copies that word into the
/// VHT element. A firmware reporting none has no VHT fact to advertise.
pub(super) fn vht_supported(caps: &Capabilities) -> bool {
    supported(caps) && caps.vht != 0
}
/// Linux `mac.c::ath10k_create_vht_cap` for this SISO profile: one-stream
/// MCS0-9 RX/TX maps (`IEEE80211_VHT_MCS_SUPPORT_0_9` for chain0 only),
/// SGI80 (0x20), RX LDPC (0x10), RX STBC (0x300) and the A-MPDU exponent
/// (bits23..25) from `vht_cap_info`. TX STBC is cleared because
/// `cfg_tx_chainmask <= 1`; beamforming roles need a sounding owner this
/// driver lacks, and 160/80+80 are not offered (see vht160).
fn local_vht(caps: &Capabilities) -> Result<LocalVht, association::Error> {
    let coding = caps.vht & 0x10 != 0;
    Ok(LocalVht::new(
        0xfffe,
        0xfffe,
        caps.vht & 0x20 != 0,
        caps.vht & 0x20 != 0,
        ((caps.vht >> 23) & 7) as u8,
    )?
    .with_ldpc(coding, coding)
    .with_rx_stbc(caps.vht & 0x300 != 0))
}
pub(super) fn vht_capability(caps: &Capabilities) -> Option<[u8; 12]> {
    if !vht_supported(caps) {
        return None;
    }
    local_vht(caps).ok().map(|v| v.capability_body())
}
fn local_ht(caps: &Capabilities, forty: bool) -> Result<LocalHt, association::Error> {
    let mask = [255, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let coding = ldpc(caps);
    Ok(LocalHt::new(
        mask,
        mask,
        if forty {
            HtWidth::TwentyForty
        } else {
            HtWidth::Twenty
        },
        HtGi {
            rx20: caps.ht & 2 != 0,
            tx20: caps.ht & 2 != 0,
            rx40: forty && caps.ht & 0x800 != 0,
            tx40: forty && caps.ht & 0x800 != 0,
        },
        0,
        6,
    )?
    // One native LDPC capability bit: firmware decodes LDPC (our RX
    // promise) and may encode it toward a peer that advertises LDPC.
    .with_ldpc(coding, coding)
    .with_rx_stbc(rx_stbc(caps)))
}
fn local(caps: &Capabilities, phy: Phy) -> Result<LocalPhy, Error> {
    let ht = local_ht(caps, phy != Phy::Ht20).map_err(plan_error)?;
    match phy {
        Phy::Ht20 => LocalPhy::ht20(ht),
        Phy::Ht40 => LocalPhy::ht40(ht),
        Phy::Vht => LocalPhy::vht80(ht, local_vht(caps).map_err(plan_error)?),
    }
    .map_err(plan_error)
}
pub(super) fn capability(caps: &Capabilities, forty: bool) -> Option<[u8; 26]> {
    if !supported(caps) {
        return None;
    }
    local_ht(caps, forty).ok().map(|p| p.capability_body())
}
pub(super) fn bss(cached: &ScanBss) -> Result<Bss, Error> {
    Ok(Bss {
        bssid: cached.bssid,
        ssid: cached.ssid.clone(),
        channel: association::channel::from_frequency(u32::from(cached.frequency))
            .ok_or(Error::Unsupported)?,
        band: None,
        signal_dbm: None,
        capability: cached.capability,
        beacon_interval: cached.beacon_interval,
        information_elements: cached.information_elements.clone(),
    })
}
impl Profile {
    pub(super) fn offer(
        caps: &Capabilities,
        cached: &ScanBss,
        own: [u8; 6],
        phy: Phy,
    ) -> Result<Option<Self>, Error> {
        let bss = bss(cached)?;
        ApElements::parse(&bss.information_elements).map_err(plan_error)?;
        let wmm = narf_wireless::wmm::Parameters::parse(&bss.information_elements)
            .map_err(|_| Error::Malformed)?;
        if !supported(caps)
            || wmm.is_none_or(|p| p.ac[0].admission_control)
            || phy == Phy::Vht && (!vht_supported(caps) || cached.frequency < 3000)
        {
            return Ok(None);
        }
        let local = local(caps, phy)?;
        let mode = if bss.capability & 16 != 0 {
            SecurityMode::Wpa2Psk
        } else {
            SecurityMode::Open
        };
        let plan =
            JoinPlan::prepare_with_phy(&bss, own, &bss.ssid, mode, local).map_err(plan_error)?;
        let Some(offered) = plan.offered_phy().copied() else {
            return Ok(None);
        };
        let h = offered.ht();
        // Center indices38/46/151/159 are not valid20MHz primaries, so
        // channel::frequency (a primary inventory) deliberately rejects them.
        let center = (if cached.frequency < 3000 { 2407 } else { 5000 })
            + 5 * u16::from(offered.center_channel());
        let secondary = match offered.width() {
            Width::Forty => offered
                .occupied_channels()
                .iter()
                .find(|c| **c != bss.channel)
                .and_then(|c| association::channel::frequency(*c))
                .map(|f| f as u16),
            // VHT80: the HT40 pair inside the segment (HT Operation).
            Width::Eighty => offered
                .ht()
                .operation()
                .secondary()
                .and_then(association::channel::frequency)
                .map(|f| f as u16),
            _ => None,
        };
        if !matches!(offered.width(), Width::Twenty | Width::Forty)
            && !(offered.width() == Width::Eighty && offered.vht().is_some() && secondary.is_some())
        {
            return Err(Error::Unsupported);
        }
        Ok(Some(Self {
            capabilities: native_capabilities(h, offered.width()),
            ampdu: h.peer_ampdu_factor() | h.peer_mpdu_density() << 2,
            mcs: h.tx_mcs()[0],
            short_gi: h.tx_sgi20() || offered.width() != Width::Twenty && h.tx_sgi40(),
            receive_sgi20: h.rx_sgi20(),
            receive_sgi40: offered.width() != Width::Twenty && h.rx_sgi40(),
            receive_ldpc: h.rx_ldpc(),
            receive_stbc: h.rx_stbc(),
            transmit_ldpc: h.tx_ldpc(),
            peer_tx_stbc: peer_tx_stbc(h),
            center,
            secondary,
            vht: offered.vht().map(|v| vht(v, offered.width())),
            local,
            offered,
        }))
    }
    pub(super) fn local(self) -> LocalPhy {
        self.local
    }
    pub(super) fn protection_required(self) -> bool {
        self.offered.ht().operation().protection() != 0
    }
    pub(super) fn response(mut self, plan: &JoinPlan) -> Result<Self, Error> {
        let n = plan.negotiated_phy().ok_or(Error::Unsupported)?;
        // No unproved live VDEV restart: a response cannot silently change
        // the geometry whose native START and occupied power are retained.
        if n.width() != self.offered.width()
            || n.center_channel() != self.offered.center_channel()
            || n.occupied_channels() != self.offered.occupied_channels()
            || self.secondary.is_some()
                && n.ht().operation().protection() != self.offered.ht().operation().protection()
        {
            return Err(Error::Unsupported);
        }
        self.capabilities = native_capabilities(n.ht(), n.width());
        self.ampdu = n.ht().peer_ampdu_factor() | n.ht().peer_mpdu_density() << 2;
        self.mcs = n.ht().tx_mcs()[0];
        self.short_gi = n.ht().tx_sgi20() || n.width() != Width::Twenty && n.ht().tx_sgi40();
        self.receive_sgi20 = n.ht().rx_sgi20();
        self.receive_sgi40 = n.width() != Width::Twenty && n.ht().rx_sgi40();
        self.receive_ldpc = n.ht().rx_ldpc();
        self.receive_stbc = n.ht().rx_stbc();
        self.transmit_ldpc = n.ht().tx_ldpc();
        self.peer_tx_stbc = peer_tx_stbc(n.ht());
        // The shared intersection already refuses a response that drops or
        // adds VHT relative to the offer; rebind the narrowed facts.
        if n.vht().is_some() != self.vht.is_some() {
            return Err(Error::Unsupported);
        }
        self.vht = n.vht().map(|v| vht(v, n.width()));
        Ok(self)
    }
    /// Linux `ath10k_peer_assoc_h_ht` peer flags beyond HT/BW40: LDPC
    /// (0x10000) from the masked peer LDPC bit and STBC (0x8000) whenever a
    /// masked STBC direction remains. Identical in all six dialect maps.
    /// `ath10k_peer_assoc_h_vht` adds `WMI_PEER_VHT` (0x0200_0000) and, for
    /// an 80 MHz peer, `WMI_PEER_80MHZ` (0x0400_0000): equal in every map.
    pub(super) fn peer_flags(self) -> u32 {
        (if self.transmit_ldpc { 0x1_0000 } else { 0 })
            | if self.peer_tx_stbc { 0x8000 } else { 0 }
            | self
                .vht
                .map_or(0, |v| 0x0200_0000 | if v.eighty { 0x0400_0000 } else { 0 })
    }
    /// `peer_max_mpdu`: the HT factor, raised by a larger VHT exponent as
    /// Linux `ath10k_peer_assoc_h_vht` does (`max(ht, 2^(13+exp)-1)`).
    pub(super) fn max_mpdu(self) -> u32 {
        let ht = (1u32 << (13 + (self.ampdu & 3))) - 1;
        self.vht
            .map_or(ht, |v| ht.max((1u32 << (13 + u32::from(v.factor))) - 1))
    }
    /// Native RC flags: HT (0x08), CW40 (0x02), SGI (0x04) and
    /// `WMI_RC_TX_STBC_FLAG` (0x20) for a peer transmitting STBC. Peer RX
    /// STBC (`WMI_RC_RX_STBC_FLAG`, 0xc0) needs our absent TX STBC.
    pub(super) fn rate_caps(self) -> u32 {
        8 | if self.short_gi { 4 } else { 0 }
            | if self.secondary.is_some() { 2 } else { 0 }
            | if self.peer_tx_stbc { 0x20 } else { 0 }
    }
    /// PEER_ASSOC `peer_phymode` (Linux `ath10k_peer_assoc_h_phymode`): a
    /// VHT peer is `MODE_11AC_VHT20/40/80` (8/9/10) by its bandwidth.
    pub(super) fn mode(self, frequency: u16) -> u32 {
        match self.vht {
            Some(v) if v.eighty => 10,
            Some(_) if self.secondary.is_some() => 9,
            Some(_) => 8,
            None => self.start_mode(frequency),
        }
    }
    /// VDEV_START channel mode: Linux `mac.c::chan_to_phymode` maps the
    /// chandef width only, so 5GHz 20/40 stay `MODE_11NA_HT20/HT40` (4/6)
    /// for a VHT peer and only 80 MHz selects `MODE_11AC_VHT80` (10).
    pub(super) fn start_mode(self, frequency: u16) -> u32 {
        if self.vht.is_some_and(|v| v.eighty) {
            10
        } else if self.secondary.is_some() {
            6
        } else if frequency < 3000 {
            5
        } else {
            4
        }
    }
    /// VDEV_START/inventory channel permission: `WMI_CHAN_FLAG_ALLOW_HT`
    /// (bit11) and, for a VHT profile, `WMI_CHAN_FLAG_ALLOW_VHT` (bit12).
    pub(super) fn channel_flags(self) -> u32 {
        (1 << 11) | if self.vht.is_some() { 1 << 12 } else { 0 }
    }
    pub(super) fn density(self) -> u32 {
        match (self.ampdu >> 2) & 7 {
            0 => 0,
            1..=3 => 1,
            n => 1 << (n - 3),
        }
    }
    pub(super) fn matches_beacon(self, ies: &[u8]) -> bool {
        ApElements::parse(ies).is_ok_and(|p| {
            p.ht_capability() == Some(self.offered.ht().peer_capability_body())
                && p.ht_operation() == Some(self.offered.ht().operation().body())
                // An HT-only profile never bound the AP's VHT elements.
                && self.offered.vht().is_none_or(|v| {
                    p.vht_capability() == Some(v.peer_capability_body())
                        && p.vht_operation() == Some(v.operation_body())
                })
        })
    }
    pub(super) fn accepts(self, descriptor: &[u8]) -> bool {
        if descriptor.len() < 116 {
            return false;
        }
        let word = |at| u32::from_le_bytes(descriptor[at..at + 4].try_into().unwrap());
        match word(104) >> 24 {
            4 => true,
            8 | 9 => {
                let sig = word(108);
                // HT-SIG2 bits4..5 carry STBC (N_STS - N_SS) and bit6 the
                // FEC (LDPC) coding. Each needs our advertised RX promise;
                // only one STBC stream is ever promised.
                let sig2 = word(112);
                let stbc = sig2 >> 4 & 3;
                descriptor[103] & 1 == 0
                    && (stbc == 0 || stbc == 1 && self.receive_stbc)
                    && (sig2 & 0x40 == 0 || self.receive_ldpc)
                    && sig & 0x7f < 8
                    && (sig & 0x80 == 0 || self.secondary.is_some())
                    && (word(112) & 0x80 == 0
                        || if sig & 0x80 == 0 {
                            self.receive_sgi20
                        } else {
                            self.receive_sgi40
                        })
            }
            // HTT_RX_VHT (0x0c); HTT_RX_VHT_WITH_TXBF (0x0d) needs a
            // beamformee role this profile never advertises.
            12 => self.vht.is_some_and(|v| {
                // Linux htt_rx.c::ath10k_htt_rx_h_rates: VHT-SIG-A1 in
                // info2 (bw bits0..1, STBC bit3, group id bits4..9, SU NSTS
                // bits10..12) and VHT-SIG-A2 in info3 (SGI bit0, LDPC bit2,
                // MCS bits4..7). Only SU group ids 0/63 carry our stream.
                let a1 = word(108);
                let a2 = word(112);
                let stbc = a1 >> 3 & 1 != 0;
                let nsts = a1 >> 10 & 7;
                let sgi = a2 & 1 != 0;
                descriptor[103] & 1 == 0
                    && matches!(a1 >> 4 & 0x3f, 0 | 63)
                    && if stbc {
                        nsts == 1 && v.receive_stbc
                    } else {
                        nsts == 0
                    }
                    && (a2 & 4 == 0 || v.receive_ldpc)
                    && v.receive_map & 3 != 3
                    && a2 >> 4 & 15 <= 7 + u32::from(v.receive_map & 3)
                    && match a1 & 3 {
                        0 => !sgi || self.receive_sgi20,
                        1 => self.secondary.is_some() && (!sgi || self.receive_sgi40),
                        2 => v.eighty && (!sgi || v.receive_sgi80),
                        _ => false,
                    }
            }),
            _ => false,
        }
    }
}

/// Bind negotiated VHT into native PEER_ASSOC facts. mac80211
/// `ieee80211_vht_cap_ie_to_sta_vht_cap` keeps RX LDPC, TXOP PS, +HTC-VHT,
/// the A-MPDU exponent, link adaptation and antenna-pattern bits as-is; MPDU
/// length is the minimum (ours is 3895, field 0); SGI80 is symmetric; the
/// peer's RX STBC needs our absent TX STBC and its TX STBC our RX STBC
/// promise; beamforming roles need ours (none) and 160/80+80 our width.
fn vht(v: &association::phy::VhtNegotiation, width: Width) -> Vht {
    let peer = v.peer_capability();
    let body = v.peer_capability_body();
    let kept = 0x10 | 0x0020_0000 | 0x0040_0000 | 0x0380_0000 | 0x0c00_0000 | 0x3000_0000;
    Vht {
        capabilities: (peer & kept)
            | if v.tx_sgi80() { 0x20 } else { 0 }
            | if v.rx_stbc() && peer & 0x80 != 0 {
                0x80
            } else {
                0
            },
        factor: (peer >> 23 & 7) as u8,
        rx_max: u16::from_le_bytes([body[6], body[7]]) & 0x1fff,
        rx_mcs: v.tx_mcs_map(),
        tx_max: u16::from_le_bytes([body[10], body[11]]) & 0x1fff,
        tx_mcs: intersect_maps(v.peer_tx_mcs_map(), v.rx_mcs_map()),
        eighty: width == Width::Eighty,
        receive_sgi80: v.rx_sgi80(),
        receive_ldpc: v.rx_ldpc(),
        receive_stbc: v.rx_stbc(),
        receive_map: v.rx_mcs_map(),
    }
}

fn peer_tx_stbc(h: &association::phy::HtNegotiation) -> bool {
    h.rx_stbc() && h.peer_capability() & 0x80 != 0
}

fn native_capabilities(h: &association::phy::HtNegotiation, width: Width) -> u16 {
    // mac80211/ht.c::ieee80211_ht_cap_ie_to_sta_ht_cap masks peer width/GI
    // by our capability before ath10k_peer_assoc_h_ht programs peer_ht_caps.
    // The single native RC_SGI flag permits both widths: these individual
    // bits must retain original-offer/response/local TX bounds, including
    // SGI40-only hardware falling back to20MHz. Original AP facts remain
    // unmodified in `offered`; local RX GI promises are separate above.
    // LDPC is masked by our capability like width/GI. STBC is asymmetric:
    // without local TX STBC the peer's RX STBC field (0x0300) is cleared, and
    // the peer's TX STBC (0x0080) survives only with our RX STBC promise.
    (h.peer_capability() & !0x3e3)
        | if h.tx_ldpc() { 1 } else { 0 }
        | if peer_tx_stbc(h) { 0x80 } else { 0 }
        | if width != Width::Twenty { 2 } else { 0 }
        | if h.tx_sgi20() { 0x20 } else { 0 }
        | if width != Width::Twenty && h.tx_sgi40() {
            0x40
        } else {
            0
        }
}
