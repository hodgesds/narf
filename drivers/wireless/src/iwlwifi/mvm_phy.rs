//! Retained optional native MVM PHY/QoS facts. This is distinct from the
//! Gen3 MLD payload encoders; all radio authority remains with signed power.
use super::super::boot_context::{put16, put32};
use super::power::{feature, Emission};
use alloc::{collections::VecDeque, vec::Vec};
use narf_wireless::association::{
    phy::{LocalHt, LocalPhy, LocalVht},
    Bss, JoinPlan, SecurityMode,
};
use narf_wireless::wmm::Parameters;

#[derive(Default)]
pub(super) struct Context {
    pub offered: Option<Parameters>,
    pub negotiated: Option<Profile>,
    pub actions: VecDeque<Vec<u8>>,
    pub ba: super::ba::Context,
    /// Extra tag5 feature bits selected by an actual signed program
    /// (never BA/NESTED_BA, which the BA context owns).
    pub features: u16,
    /// Extra tag5 bits the selected offer could use (`QOS_TIDS` on WMM,
    /// `TX_LDPC`/`TX_STBC` when the observed AP and NVM permit them).
    pub available: u16,
    /// Secondary channel of the observed AP's 20/40MHz operation, when
    /// `HT40` is available for this offer.
    pub secondary: Option<u8>,
    /// Primary channel of the selected offer.
    pub primary: u8,
    /// Center channel of the observed AP's 80MHz VHT operation, when `VHT`
    /// is available for this offer.
    pub vht_center: Option<u8>,
    /// Center channel of the observed AP's contiguous 160MHz operation,
    /// when `WIDTH_160` is available for this offer.
    pub vht160_center: Option<u8>,
}
/// An occupied 40MHz (`width` 1) or 80MHz (`width` 2) channel, by center
/// channel number; the width code is `IWL_PHY_CHANNEL_MODE40/80`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::iwlwifi) struct Span {
    pub center: u8,
    pub width: u8,
}
impl Span {
    pub fn mhz(self) -> u32 {
        20 << self.width
    }
    /// Every 20MHz subchannel, ascending.
    pub fn channels(self) -> Option<Vec<u8>> {
        let offsets: &[i16] = match self.width {
            1 => &[-2, 2],
            2 => &[-6, -2, 2, 6],
            3 => &[-14, -10, -6, -2, 2, 6, 10, 14],
            _ => return None,
        };
        let mut out = Vec::new();
        for offset in offsets {
            let channel = u8::try_from(i16::from(self.center) + offset).ok()?;
            if channel == 0 || channel == 14 || (channel <= 14) != (self.center <= 14) {
                return None;
            }
            out.push(channel);
        }
        Some(out)
    }
    /// `iwl_mvm_get_ctrl_pos` (Linux v7.2 `mvm/phy-ctxt.c`) for `primary`.
    pub fn control_position(self, primary: u8) -> u8 {
        let offset = 5 * (i32::from(primary) - i32::from(self.center));
        if offset == 0 {
            return 0;
        }
        let distance = ((offset.unsigned_abs() - 10) / 20) as u8;
        (distance & 3) | ((distance & 4) << 1) | if offset > 0 { 4 } else { 0 }
    }
}
impl Context {
    /// The occupied span once a signed `HT40` (40MHz) or `VHT` (80MHz)
    /// program is granted.
    pub fn span(&self) -> Option<Span> {
        if self.features & feature::WIDTH_160 != 0 {
            if let Some(center) = self.vht160_center {
                return Some(Span { center, width: 3 });
            }
        }
        if self.features & feature::VHT != 0 {
            if let Some(center) = self.vht_center {
                return Some(Span { center, width: 2 });
            }
        }
        let secondary = self
            .secondary
            .filter(|_| self.features & feature::HT40 != 0)?;
        Some(Span {
            center: ((u16::from(self.primary) + u16::from(secondary)) / 2) as u8,
            width: 1,
        })
    }
    pub fn emission(&self) -> Emission {
        if self.features != 0 {
            let mut bits = self.features;
            if self.ba.selected {
                bits |= feature::BA;
            }
            if self.ba.nested_selected {
                bits |= feature::NESTED_BA;
            }
            return Emission::Features(bits);
        }
        if self.ba.nested_selected {
            Emission::Ht20NestedBa
        } else if self.ba.selected {
            Emission::Ht20Ba
        } else if self.offered.is_some() {
            Emission::Ht20
        } else {
            Emission::Legacy
        }
    }
    pub fn confirm(&mut self, plan: &JoinPlan, response_ies: &[u8]) -> Result<(), &'static str> {
        if self.offered.is_none() {
            self.negotiated = None;
            return Ok(());
        }
        let wmm =
            parameters(response_ies)?.ok_or("MVM association response omitted negotiated WMM")?;
        let mut profile = Profile {
            wmm,
            ht: false,
            tx_mcs: 0,
            tx_mcs2: 0,
            rx_nss2: false,
            tx_sgi: false,
            rx_sgi: false,
            rx_ldpc: false,
            rx_stbc: false,
            tx_ldpc: false,
            tx_stbc: false,
            width40: false,
            tx_sgi40: false,
            rx_sgi40: false,
            width80: false,
            vht: false,
            vht_tx_map: 0xffff,
            tx_sgi80: false,
            rx_sgi80: false,
            width160: false,
            tx_sgi160: false,
            rx_sgi160: false,
            vht_operation: [0; 5],
            protection: 0,
            dynamic_smps: false,
            ampdu_exp: 0,
            density: 0,
            operation: [0; 22],
        };
        if let Some(phy) = plan.negotiated_phy() {
            let ht = phy.ht();
            // The PHY context was prepared with the BSS width before
            // authentication; the response must select exactly that width.
            use narf_wireless::association::phy::Width;
            let expected = match self.span() {
                Some(span) => {
                    if span.channels().as_deref() != Some(phy.occupied_channels()) {
                        return Err("MVM response changed the prepared wide span");
                    }
                    match span.width {
                        3 => Width::OneSixty,
                        2 => Width::Eighty,
                        _ => Width::Forty,
                    }
                }
                None => Width::Twenty,
            };
            if phy.width() != expected || phy.discontiguous() {
                return Err("MVM HT response selected a width other than the prepared PHY");
            }
            profile.width40 = expected != Width::Twenty;
            profile.width80 = matches!(expected, Width::Eighty | Width::OneSixty);
            profile.width160 = expected == Width::OneSixty;
            if let Some(vht) = phy.vht() {
                if !profile.width80 {
                    return Err("MVM VHT negotiated without its 80MHz program");
                }
                // A static-SMPS peer receives one stream (max_nss = 1).
                let mut map = vht.tx_mcs_map();
                if (ht.peer_capability() >> 2) & 3 == 0 {
                    map |= 0xfffc;
                }
                profile.vht = true;
                profile.vht_tx_map = map;
                profile.tx_sgi80 = vht.tx_sgi80();
                profile.rx_sgi80 = vht.rx_sgi80();
                profile.tx_sgi160 = profile.width160 && vht.tx_sgi160();
                profile.rx_sgi160 = profile.width160 && vht.rx_sgi160();
                profile.vht_operation = vht.operation_body();
            } else if profile.width80 {
                return Err("MVM 80MHz program without negotiated VHT");
            }
            profile.tx_sgi40 = profile.width40 && ht.tx_sgi40();
            profile.rx_sgi40 = profile.width40 && ht.rx_sgi40();
            profile.ht = true;
            profile.tx_mcs = ht.tx_mcs()[0];
            // MCS 8..15 only with a granted NSS2 program (the local TX
            // mask) toward a peer that receives them; a static-SMPS peer
            // receives one stream (iwl_mvm_sta_send_to_fw SMPS_STATIC).
            profile.rx_nss2 = self.features & feature::NSS2 != 0;
            profile.tx_mcs2 = if (ht.peer_capability() >> 2) & 3 == 0 {
                0
            } else {
                ht.tx_mcs()[1]
            };
            profile.tx_sgi = ht.tx_sgi20();
            profile.rx_sgi = ht.rx_sgi20();
            profile.rx_ldpc = ht.rx_ldpc();
            profile.rx_stbc = ht.rx_stbc();
            // The shared negotiation requires the local TX opt-in (only a
            // granted tag5 bit sets it) and the peer's RX capability in
            // both the offer and the response.
            profile.tx_ldpc = ht.tx_ldpc();
            profile.tx_stbc = ht.tx_stbc();
            profile.dynamic_smps = (ht.peer_capability() >> 2) & 3 == 1;
            profile.ampdu_exp = ht.peer_ampdu_factor();
            profile.density = ht.peer_mpdu_density();
            profile.protection = if matches!(ht.operation().protection(), 1 | 3) {
                6
            } else {
                0
            };
            profile.operation = ht.operation().body();
        }
        self.negotiated = Some(profile);
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Profile {
    pub wmm: Parameters,
    pub ht: bool,
    pub tx_mcs: u8,
    /// Negotiated HT MCS 8..15 toward the peer (granted `NSS2` only).
    pub tx_mcs2: u8,
    /// The local MCS 8..15 receive promise of a granted `NSS2` program.
    pub rx_nss2: bool,
    pub tx_sgi: bool,
    pub rx_sgi: bool,
    /// Local HT receive-coding promises from [`local_ht`].
    pub rx_ldpc: bool,
    pub rx_stbc: bool,
    /// TX coding granted by a tag5 program and negotiated with the peer.
    pub tx_ldpc: bool,
    pub tx_stbc: bool,
    /// Granted `HT40` operation on the negotiated 40MHz channel.
    pub width40: bool,
    pub tx_sgi40: bool,
    pub rx_sgi40: bool,
    /// Granted `VHT` operation on the negotiated 80MHz channel.
    pub width80: bool,
    pub vht: bool,
    /// Negotiated VHT TX MCS map (two bits per stream, 3 = none).
    pub vht_tx_map: u16,
    pub tx_sgi80: bool,
    pub rx_sgi80: bool,
    /// Granted `WIDTH_160` operation on the negotiated contiguous 160MHz
    /// channel.
    pub width160: bool,
    pub tx_sgi160: bool,
    pub rx_sgi160: bool,
    pub vht_operation: [u8; 5],
    pub protection: u32,
    pub dynamic_smps: bool,
    pub ampdu_exp: u8,
    pub density: u8,
    pub operation: [u8; 22],
}
/// The native Gen2 HT20/SISO capability: SGI20, RX LDPC and one RX STBC
/// stream (Linux iwl-nvm-utils.c::iwl_init_ht_hw_capab with rf-hr/rf-jf
/// `ht_params = { .stbc = true, .ldpc = true }`). These are receive
/// promises only: TX STBC needs a second TX chain and TX LDPC the TLC
/// LDPC flag; this single-stream emitting profile uses neither.
pub(in crate::iwlwifi) fn local_ht() -> LocalHt {
    local_ht_for(0)
}
/// [`local_ht`] plus the TX coding a granted tag5 program adds: TX LDPC
/// (a local transmit choice; the advertised LDPC bit stays the RX promise)
/// and TX STBC, which also sets the HT Tx STBC bit as Linux
/// `iwl_init_ht_hw_capab` does for more than one TX chain.
pub(in crate::iwlwifi) fn local_ht_for(features: u16) -> LocalHt {
    // iwl_init_ht_hw_capab: rx_mask[1] = 0xff with two RX chains (NSS2);
    // an ht40_bands band adds SUP_WIDTH_20_40 and SGI_40 next to SGI_20.
    let wide = features & feature::HT40 != 0;
    let mut mcs = [0; 10];
    mcs[0] = 255;
    if features & feature::NSS2 != 0 {
        mcs[1] = 255;
    }
    let gi = narf_wireless::association::phy::HtGi {
        rx20: true,
        tx20: true,
        rx40: wide,
        tx40: wide,
    };
    let width = if wide {
        narf_wireless::association::phy::HtWidth::TwentyForty
    } else {
        narf_wireless::association::phy::HtWidth::Twenty
    };
    let base =
        LocalHt::new(mcs, mcs, width, gi, 0, 0).unwrap_or_else(|_| LocalHt::siso20(true, true));
    base.with_ldpc(true, features & feature::TX_LDPC != 0)
        .with_rx_stbc(true)
        .with_tx_stbc(features & feature::TX_STBC != 0)
}
/// The native Gen2 VHT capability of a granted `VHT` program
/// (`iwl_init_vht_hw_capab`): SGI80, RX LDPC, one RX STBC stream and MCS
/// 0..9 on one stream, or two with `NSS2`. TX LDPC/STBC follow their bits.
pub(in crate::iwlwifi) fn local_vht_for(features: u16) -> LocalVht {
    let map = if features & feature::NSS2 != 0 {
        0xfffa
    } else {
        0xfffe
    };
    let vht = LocalVht::new(map, map, true, true, 0).unwrap_or_else(|_| unreachable!());
    // iwl_init_vht_hw_capab: SUPP_CHAN_WIDTH_160MHZ | SHORT_GI_160 when an
    // NVM channel carries NVM_CHANNEL_160MHZ (vht160_supported).
    let vht = if features & feature::WIDTH_160 != 0 {
        vht.with_160mhz(true, true)
    } else {
        vht
    };
    vht.with_ldpc(true, features & feature::TX_LDPC != 0)
        .with_rx_stbc(true)
        .with_tx_stbc(features & feature::TX_STBC != 0)
}
pub(super) fn parameters(ies: &[u8]) -> Result<Option<Parameters>, &'static str> {
    let parsed = Parameters::parse(ies).map_err(|_| "MVM malformed WMM parameters")?;
    if let Some(p) = parsed {
        if p.ac[0].admission_control {
            return Err("MVM BE requires unsupported admission control");
        }
        for ac in &p.ac {
            ac.txop
                .checked_mul(32)
                .ok_or("MVM EDCA TXOP exceeds native16-bit field")?;
        }
    }
    Ok(parsed)
}
impl Profile {
    pub fn matches_beacon(&self, ies: &[u8]) -> bool {
        if parameters(ies) != Ok(Some(self.wmm)) {
            return false;
        }
        if !self.ht {
            return true;
        }
        let Ok(ap) = narf_wireless::association::phy::ApElements::parse(ies) else {
            return false;
        };
        let (Some(cap), Some(op)) = (ap.ht_capability(), ap.ht_operation()) else {
            return false;
        };
        op == self.operation
            && cap[3] & self.tx_mcs == self.tx_mcs
            && cap[4] & self.tx_mcs2 == self.tx_mcs2
            && (self.tx_mcs2 == 0 || (u16::from_le_bytes([cap[0], cap[1]]) >> 2) & 3 != 0)
            && (!self.tx_sgi || cap[0] & 32 != 0)
            && cap[2] & 3 == self.ampdu_exp
            && (cap[2] >> 2) & 7 == self.density
            && ((u16::from_le_bytes([cap[0], cap[1]]) >> 2) & 3 == 1) == self.dynamic_smps
            && (!self.tx_ldpc || cap[0] & 1 != 0)
            && (!self.tx_stbc || cap[1] & 3 != 0)
            && (!self.width40 || cap[0] & 2 != 0)
            && (!self.tx_sgi40 || cap[0] & 64 != 0)
            && (!self.vht
                || ap.vht_operation() == Some(self.vht_operation)
                    && ap.vht_capability().is_some_and(|v| {
                        let rx = u16::from_le_bytes([v[4], v[5]]);
                        narf_wireless::association::phy::intersect_maps(self.vht_tx_map, rx)
                            == self.vht_tx_map
                            && (!self.tx_sgi80 || v[0] & 32 != 0)
                            && (!self.width160 || matches!((v[0] >> 2) & 3, 1 | 2))
                            && (!self.tx_sgi160 || v[0] & 64 != 0)
                    }))
    }
    pub fn edca(&self, local: [u8; 6]) -> [u8; 208] {
        let mut out = [0; 208];
        put32(&mut out, 0, 2);
        out[16..22].copy_from_slice(&local);
        put32(&mut out, 24, 8);
        put32(&mut out, 56, 1 | if self.ht { 2 } else { 0 });
        for (index, aci) in [1, 0, 2, 3].into_iter().enumerate() {
            let ac = self.wmm.ac[aci];
            let at = 60 + index * 8;
            put16(&mut out, at, ac.cw_min());
            put16(&mut out, at + 2, ac.cw_max());
            out[at + 4] = ac.aifsn;
            out[at + 5] = 1 << (index + 1);
            put16(&mut out, at + 6, ac.txop * 32);
        }
        out
    }
    pub fn peer(&self, aid: u16) -> [u8; 48] {
        let mut out = super::auth::disable_tx(true);
        put16(&mut out, 2, u16::MAX); // every TX aggregation TID stays disabled
        put16(&mut out, 36, aid);
        out[17] = 2 | 4; // TID_DISABLE_TX + UAPSD_ACS; no trigger/delivery ACs
        out[46] = 128;
        out[47] = 0;
        let mask = (1 << 4) | (1 << 17) | (15 << 19) | (7 << 23) | (3 << 26) | (3 << 28);
        put32(&mut out, 24, mask);
        put32(
            &mut out,
            20,
            (1 << 4)
                // STA_FLG_FAT_EN_40MHZ; iwl_mvm_sta_send_to_fw ORs FAT_EN_80
                // and falls through to FAT_EN_40 for an 80MHz peer (3 << 26).
                | (u32::from(self.width40) << 26)
                | (u32::from(self.width80) << 27)
                | (u32::from(self.tx_mcs2 != 0) << 28) // STA_FLG_MIMO_EN_MIMO2
                | if self.ht {
                    (u32::from(self.dynamic_smps) << 17)
                        | (u32::from(self.ampdu_exp) << 19)
                        | (u32::from(self.density) << 23)
                } else {
                    0
                },
        );
        out
    }
    pub fn tlc(&self, version: u8, rates: u16, chains: u8) -> Result<Vec<u8>, &'static str> {
        let length = match version {
            2 => 24,
            3 | 4 => 28,
            _ => return Err("unsupported MVM PHY TLC API"),
        };
        let mut out = alloc::vec![0;length];
        // rs_fw_bw_from_sta_bw: IWL_TLC_MNG_CH_WIDTH_40MHZ.
        out[4] = if self.width160 {
            3
        } else if self.width80 {
            2
        } else {
            u8::from(self.width40)
        };
        // IWL_TLC_MNG_MODE_HT (1) / IWL_TLC_MNG_MODE_VHT (2).
        out[5] = if self.vht { 2 } else { u8::from(self.ht) };
        out[6] = chains;
        // rs_fw_get_config_flags: STBC bit0, LDPC bit1.
        put16(
            &mut out,
            8,
            u16::from(self.tx_stbc) | u16::from(self.tx_ldpc) << 1,
        );
        put16(&mut out, 10, rates);
        put16(&mut out, 12, u16::from(self.tx_mcs));
        // rs_fw_set_supp_rates: ht_rates[IWL_TLC_NSS_2][IWL_TLC_MCS_PER_BW_80]
        // follows the NSS1 row of 2 (v2/v3) or 3 (v4) per-width entries.
        put16(
            &mut out,
            if version == 4 { 18 } else { 16 },
            u16::from(self.tx_mcs2),
        );
        // v2/3 SGI byte22; v4 byte7. A-MSDU and all NSS2/width>20 rates0.
        // rs_fw_sgi_cw_support: BIT(20MHz) | BIT(40MHz).
        out[if version == 4 { 7 } else { 22 }] = u8::from(self.tx_sgi)
            | u8::from(self.tx_sgi40) << 1
            | u8::from(self.tx_sgi80) << 2
            | u8::from(self.tx_sgi160) << 3;
        if self.vht {
            // rs_fw_vht_set_enabled_rates: per stream BIT(highest + 1) - 1,
            // from the (intersected) peer receive map; MCS9 is invalid at
            // 20MHz only, and this program is always 80MHz.
            // The 160MHz entry (IWL_TLC_MCS_PER_BW_160) repeats the 80MHz one
            // when the peer supports 160MHz at that NSS (no Extended NSS BW
            // here, so ieee80211_get_vht_max_nss gives every stream).
            let row = if version == 4 { 6 } else { 4 };
            for stream in 0..2 {
                let at = 12 + row * stream;
                let highest = match (self.vht_tx_map >> (2 * stream)) & 3 {
                    0 => 7,
                    1 => 8,
                    2 => 9,
                    _ => {
                        put16(&mut out, at, 0);
                        continue;
                    }
                };
                put16(&mut out, at, (1u16 << (highest + 1)) - 1);
                if self.width160 {
                    put16(&mut out, at + 2, (1u16 << (highest + 1)) - 1);
                }
            }
        }
        Ok(out)
    }
    pub fn rx_rate(&self, payload: &[u8]) -> bool {
        let Some(raw) = payload.get(28..32) else {
            return false;
        };
        let r = u32::from_le_bytes(raw.try_into().unwrap());
        // rates-v2 (fw/api/rs.h RATE_MCS_LDPC_POS 16, RATE_MCS_STBC_POS 17):
        // accepted only as the receive coding this station advertised.
        let coding = (u32::from(self.rx_ldpc) << 16) | (u32::from(self.rx_stbc) << 17);
        // RATE_MCS_CHAN_WIDTH (bits 11..13): 20MHz, or 40MHz on a granted
        // HT40 channel; SGI is accepted per the advertised width.
        let wide = (r >> 11) & 7;
        let sgi = match wide {
            1 => self.rx_sgi40,
            2 => self.rx_sgi80,
            3 => self.rx_sgi160,
            _ => self.rx_sgi,
        };
        if self.vht && (r >> 8) & 7 == 3 {
            // VHT: MCS 0..9 (bits 0..3), NSS2 only under the local promise.
            return (wide <= 2 || self.width160 && wide == 3)
                && r & 15 <= 9
                && r & ((0xe0 | (u32::from(!self.rx_nss2) << 4))
                    | ((15 << 16) & !coding)
                    | (3 << 23))
                    == 0
                && ((r >> 20) & 7 == 0 || sgi && (r >> 20) & 7 == 1);
        }
        self.ht
            && (r >> 8) & 7 == 2
            && (wide == 0 || self.width40 && wide == 1)
            && r & ((0xf8 & !(u32::from(self.rx_nss2) << 4)) | ((15 << 16) & !coding) | (3 << 23))
                == 0
            && ((r >> 20) & 7 == 0 || sgi && (r >> 20) & 7 == 1)
    }
}
impl super::Owner {
    pub(super) fn receive_phy_action(
        &mut self,
        mpdu: &super::super::scan_api::Mpdu<'_>,
        local: [u8; 6],
        peer: [u8; 6],
    ) -> bool {
        if !self.power.phy.negotiated.is_some_and(|p| p.ht) {
            return false;
        }
        let f = mpdu.frame;
        if f.len() < 24
            || f[0] != 0xd0
            || f[1] & 0xc7 != 0
            || f[22] & 15 != 0
            || mpdu.amsdu
            || f[4..10] != local
            || f[10..16] != peer
            || f[16..22] != peer
        {
            return false;
        }
        let Some(body) = mpdu.body(24, 0).filter(|b| b.first() == Some(&3)) else {
            return false;
        };
        if self.capture_ba_action(body) {
            return true;
        }
        if body.len() != 9 || body[..2] != [3, 0] {
            return true;
        }
        let parameters = u16::from_le_bytes([body[3], body[4]]);
        let tid = (parameters >> 2) & 15;
        if tid > 7 || self.power.phy.actions.len() >= 4 {
            return true;
        }
        let data = self
            .power
            .prepared
            .as_mut()
            .unwrap()
            .mlme
            .data
            .as_mut()
            .unwrap();
        let response = [3, 1, body[2], 37, 0, ((tid << 2) | 2) as u8, 0, 0, 0];
        let frame =
            super::super::frame_api::management(0xd0, local, peer, data.sequence, &response);
        data.sequence = data.sequence.wrapping_add(1) & 4095;
        self.power.phy.actions.push_back(frame);
        true
    }
    pub(super) async fn service_phy_actions(
        &mut self,
        policy: &mut impl FnMut() -> Result<narf_wireless::reg::RegulatoryDomain, &'static str>,
    ) -> Result<(), &'static str> {
        if self.power.phy.actions.is_empty() {
            return Ok(());
        }
        if self.phase != super::Phase::DataPrepared {
            return Err("MVM action owner not ready");
        }
        let queue = self
            .prepared_management_queue()
            .ok_or("MVM decline queue absent")?;
        self.cancel_data_partial();
        self.phase = super::Phase::TransmittingData;
        let result = async {
            let data = self
                .power
                .prepared
                .as_ref()
                .unwrap()
                .mlme
                .data
                .as_ref()
                .unwrap();
            let rates = super::super::rates::Rates {
                supported: data.status.supported_rates,
                basic: data.status.basic_rates,
            };
            let nvm = self.nvm.as_ref().unwrap();
            let rate = rates.management_rate(nvm.tx_chains & nvm.tx_chains.wrapping_neg());
            for _ in 0..4 {
                let Some(frame) = self.power.phy.actions.pop_front() else {
                    break;
                };
                self.fresh_data_policy(policy).await?;
                self.qualified_management_transmit(queue, &frame, rate, policy)
                    .await?;
            }
            self.check_link_power(&policy()?)
        }
        .await;
        match result {
            Ok(()) => {
                self.phase = super::Phase::DataPrepared;
                Ok(())
            }
            Err(e) => self.data_failed(e),
        }
    }
    pub(super) fn local_ht20(&self) -> Result<LocalPhy, &'static str> {
        if !self.supports_native_ht20() {
            return Err("MVM native HT20 contract unavailable");
        }
        let local = local_ht_for(self.power.phy.features);
        if self.power.phy.features & feature::WIDTH_160 != 0 {
            LocalPhy::vht160(local, local_vht_for(self.power.phy.features))
        } else if self.power.phy.features & feature::VHT != 0 {
            LocalPhy::vht80(local, local_vht_for(self.power.phy.features))
        } else if self.power.phy.features & feature::HT40 != 0 {
            LocalPhy::ht40(local)
        } else {
            LocalPhy::ht20(local)
        }
        .map_err(|_| "MVM local HT profile invalid")
    }
    pub(super) fn station_plan(
        &self,
        bss: &Bss,
        ssid: &[u8],
        security: SecurityMode,
        elements: &[u8],
        selected: bool,
    ) -> Result<JoinPlan, &'static str> {
        let local = self.mac.ok_or("MVM station MAC absent")?;
        let mut plan = if selected {
            JoinPlan::prepare_with_phy(bss, local, ssid, security, self.local_ht20()?)
        } else {
            JoinPlan::prepare(bss, local, ssid, security)
        }
        .map_err(|_| "unsupported MVM native station offer")?;
        plan.append_sme_ies(elements)
            .map_err(|_| "unsupported MVM native SME elements")?;
        Ok(plan)
    }
    pub(in crate::iwlwifi) fn select_station_offer(
        &mut self,
        bssid: [u8; 6],
        ssid: &[u8],
        channel: u8,
        elements: &[u8],
        mode: SecurityMode,
    ) -> Result<(), &'static str> {
        if self.phase != super::Phase::Configured {
            return Err("MVM offer requires configured owner");
        }
        let b = self
            .beacons
            .iter()
            .find(|b| b.bssid == bssid && b.channel == channel && b.ssid == ssid)
            .ok_or("MVM station BSS not observed")?;
        let bss = Bss {
            bssid,
            ssid: b.ssid.clone(),
            channel,
            signal_dbm: None,
            capability: b.capabilities,
            beacon_interval: b.interval,
            information_elements: b.information_elements.clone(),
        };
        let wmm = parameters(&bss.information_elements)?;
        let selected = wmm.is_some() && channel != 14 && self.supports_native_ht20();
        self.station_plan(&bss, ssid, mode, elements, selected)?;
        let ba = selected
            && narf_wireless::association::phy::ApElements::parse(&bss.information_elements)
                .is_ok_and(|p| p.ht_capability().is_some())
            && self.supports_native_ba();
        let ap_ht = narf_wireless::association::phy::ApElements::parse(&bss.information_elements)
            .ok()
            .and_then(|p| p.ht_capability());
        let chains = self.nvm.as_ref().map_or(0, |n| n.tx_chains);
        let mut available = 0;
        let secondary = if selected {
            self.ht40_secondary(&bss, ap_ht)
        } else {
            None
        };
        if secondary.is_some() {
            available |= feature::HT40;
        }
        if selected && self.nss2_available(ap_ht) {
            available |= feature::NSS2;
        }
        let vht_center = secondary.and_then(|s| self.vht80_center(&bss, s));
        if vht_center.is_some() {
            available |= feature::VHT;
        }
        let vht160_center = vht_center.and_then(|c| self.vht160_center(&bss, c));
        if vht160_center.is_some() {
            available |= feature::WIDTH_160;
        }
        if selected {
            available |= feature::QOS_TIDS;
            if let Some(cap) = ap_ht {
                // rs_fw_get_config_flags: LDPC to an LDPC-capable peer;
                // STBC needs more than one valid TX antenna and peer Rx STBC.
                if cap[0] & 1 != 0 {
                    available |= feature::TX_LDPC;
                }
                if chains.count_ones() > 1 && cap[1] & 3 != 0 {
                    available |= feature::TX_STBC;
                }
            }
        }
        self.power.phy = Context {
            offered: if selected { wmm } else { None },
            available,
            secondary,
            primary: channel,
            vht_center,
            vht160_center,
            ..Context::default()
        };
        self.power.phy.ba.selected = ba;
        Ok(())
    }
    /// The secondary channel of an observed 20/40MHz BSS this NVM can
    /// operate (mac80211 `ieee80211_determine_ap_chan` from HT Operation;
    /// AP Supported Channel Width Set; Linux 22000 `ht40_bands` cover 2.4
    /// and 5GHz, and NVM_CHANNEL_40MHZ must mark both subchannels).
    fn ht40_secondary(&self, bss: &Bss, ap_cap: Option<[u8; 26]>) -> Option<u8> {
        let ap =
            narf_wireless::association::phy::ApElements::parse(&bss.information_elements).ok()?;
        let op = ap.ht_operation()?;
        if ap_cap?[0] & 2 == 0 || op[0] != bss.channel || op[1] & 4 == 0 {
            return None;
        }
        let secondary = match op[1] & 3 {
            1 => bss.channel.checked_add(4)?,
            3 => bss.channel.checked_sub(4)?,
            _ => return None,
        };
        let nvm = self.nvm.as_ref()?;
        let permissions = self
            .scan
            .permissions
            .as_ref()
            .or(self.power.nvm_permissions.as_ref())?;
        let wide = |ch: u8| {
            super::super::station_api::channel_index(ch)
                .and_then(|index| permissions.get(index))
                .is_some_and(|flags| flags & 0x201 == 0x201)
        };
        (nvm.channels.contains(&secondary)
            && bss.channel != 14
            && secondary != 14
            && (bss.channel <= 14) == (secondary <= 14)
            && wide(bss.channel)
            && wide(secondary))
        .then_some(secondary)
    }
    /// Two streams need two NVM TX/RX streams and chains (no MIMO-disable
    /// SKU), an AP receiving MCS 8..15 and an AP not in static SMPS.
    fn nss2_available(&self, ap_cap: Option<[u8; 26]>) -> bool {
        let (Some(nvm), Some(cap)) = (self.nvm.as_ref(), ap_cap) else {
            return false;
        };
        nvm.phy.tx_streams >= 2
            && nvm.phy.rx_streams >= 2
            && nvm.tx_chains.count_ones() >= 2
            && nvm.rx_chains.count_ones() >= 2
            && cap[4] != 0
            && (u16::from_le_bytes([cap[0], cap[1]]) >> 2) & 3 != 0
    }
    /// The center of an observed 80MHz VHT BSS on 5GHz this NVM can operate
    /// (mac80211 `ieee80211_chandef_vht_oper`: VHT Operation width 1 with
    /// CCFS0 the 80MHz center and no second segment). The NVM must report
    /// VHT and mark all four subchannels VALID | NVM_CHANNEL_80MHZ.
    fn vht80_center(&self, bss: &Bss, secondary: u8) -> Option<u8> {
        let ap =
            narf_wireless::association::phy::ApElements::parse(&bss.information_elements).ok()?;
        let (Some(_), Some(op)) = (ap.vht_capability(), ap.vht_operation()) else {
            return None;
        };
        let nvm = self.nvm.as_ref()?;
        // A contiguous 160MHz BSS (CCFS1 the 160MHz center, eight
        // channels from CCFS0) still offers its primary 80MHz.
        if bss.channel <= 14
            || !nvm.phy.vht
            || op[0] != 1
            || op[2] != 0 && (!matches!(op[2], 50 | 114 | 163) || op[1].abs_diff(op[2]) != 8)
        {
            return None;
        }
        let span = Span {
            center: op[1],
            width: 2,
        };
        let channels = span.channels()?;
        if ![42, 58, 106, 122, 138, 155].contains(&op[1])
            || !channels.contains(&bss.channel)
            || !channels.contains(&secondary)
        {
            return None;
        }
        let permissions = self
            .scan
            .permissions
            .as_ref()
            .or(self.power.nvm_permissions.as_ref())?;
        channels
            .iter()
            .all(|&ch| {
                nvm.channels.contains(&ch)
                    && super::super::station_api::channel_index(ch)
                        .and_then(|index| permissions.get(index))
                        .is_some_and(|flags| flags & 0x401 == 0x401)
            })
            .then_some(op[1])
    }
    /// The 160MHz center of an observed contiguous VHT160 BSS around the
    /// selected 80MHz block (VHT Operation width 1, CCFS1 the 160MHz center
    /// eight channels from CCFS0; mac80211 `ieee80211_chandef_vht_oper`).
    /// The AP must advertise 160MHz support and every subchannel
    /// VALID | NVM_CHANNEL_160MHZ (bit 11).
    fn vht160_center(&self, bss: &Bss, center80: u8) -> Option<u8> {
        let ap =
            narf_wireless::association::phy::ApElements::parse(&bss.information_elements).ok()?;
        let (Some(cap), Some(op)) = (ap.vht_capability(), ap.vht_operation()) else {
            return None;
        };
        if !matches!((cap[0] >> 2) & 3, 1 | 2)
            || op[0] != 1
            || op[1] != center80
            || !matches!(op[2], 50 | 114 | 163)
            || op[1].abs_diff(op[2]) != 8
        {
            return None;
        }
        let nvm = self.nvm.as_ref()?;
        let permissions = self
            .scan
            .permissions
            .as_ref()
            .or(self.power.nvm_permissions.as_ref())?;
        Span {
            center: op[2],
            width: 3,
        }
        .channels()?
        .iter()
        .all(|&ch| {
            nvm.channels.contains(&ch)
                && super::super::station_api::channel_index(ch)
                    .and_then(|index| permissions.get(index))
                    .is_some_and(|flags| flags & 0x801 == 0x801)
        })
        .then_some(op[2])
    }
    /// Drop `HT40` from the offer when the current host policy does not
    /// permit the whole 40MHz span; mac80211 then keeps the 20MHz chandef
    /// (`ieee80211_chandef_downgrade`).
    pub(in crate::iwlwifi) fn restrict_offer(
        &mut self,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) {
        let phy = &mut self.power.phy;
        if let Some(center) = phy.vht160_center {
            let span = Span { center, width: 3 };
            if super::power::span_power(domain, phy.primary, Some(span)).is_none() {
                phy.vht160_center = None;
                phy.available &= !feature::WIDTH_160;
            }
        }
        if let Some(center) = phy.vht_center {
            let span = Span { center, width: 2 };
            if super::power::span_power(domain, phy.primary, Some(span)).is_none() {
                phy.vht_center = None;
                phy.vht160_center = None;
                phy.available &= !(feature::VHT | feature::WIDTH_160);
            }
        }
        if let Some(secondary) = phy.secondary {
            let span = Span {
                center: ((u16::from(phy.primary) + u16::from(secondary)) / 2) as u8,
                width: 1,
            };
            if super::power::span_power(domain, phy.primary, Some(span)).is_none() {
                // VHT80 is built on the HT 20/40 profile and goes with it.
                phy.secondary = None;
                phy.vht_center = None;
                phy.vht160_center = None;
                phy.available &= !(feature::HT40 | feature::VHT | feature::WIDTH_160);
            }
        }
    }
    pub(in crate::iwlwifi) fn station_power_request(
        &mut self,
    ) -> Result<super::PowerRequest, &'static str> {
        self.transmit_power_request_for(self.power.phy.emission())
    }
    pub(in crate::iwlwifi) fn nested_ba_offer(&self) -> bool {
        self.power.phy.ba.selected && self.supports_native_ba()
    }
    /// Selection requires the actual signed tag4 asset, not a caller feature
    /// flag. Native BA/API4/TLC43 capability and the selected HT offer remain
    /// prerequisites; station_join parses the same retained asset again.
    pub(in crate::iwlwifi) fn select_nested_power(
        &mut self,
        source: &crate::firmware_asset::Asset,
        binding: [u8; 32],
    ) -> Result<(), &'static str> {
        if self.phase != super::Phase::Configured
            || !self.power.phy.ba.selected
            || !self.supports_native_ba()
        {
            return Err("MVM nested BA requires selected native HT/BA profile");
        }
        super::power::validate_record(
            source,
            binding,
            self.mac.ok_or("MVM nested BA MAC absent")?,
            Emission::Ht20NestedBa,
        )?;
        self.power.phy.ba.nested_selected = true;
        Ok(())
    }
    /// The tag5 feature set this offer would emit with per-TID QoS queues:
    /// WMM/HT20 selected, plus the BA bit when the BA profile is selected.
    pub(in crate::iwlwifi) fn feature_offer(&self) -> Option<u16> {
        self.feature_offers()
            .into_iter()
            .find(|bits| bits & !(feature::BA | feature::NESTED_BA) == feature::QOS_TIDS)
    }
    /// Every tag5 set this offer could emit, widest first: each non-empty
    /// subset of the available bits, plus BA when the BA profile is
    /// selected. Each set names its own signed program.
    pub(in crate::iwlwifi) fn feature_offers(&self) -> Vec<u16> {
        if self.phase != super::Phase::Configured || self.power.phy.offered.is_none() {
            return Vec::new();
        }
        let ba = if self.power.phy.ba.selected {
            feature::BA
        } else {
            0
        };
        let available = self.power.phy.available;
        let mut sets: Vec<u16> = (1..=available)
            .filter(|bits| bits & !available == 0)
            // VHT80 is built on the HT 20/40 profile.
            .filter(|bits| bits & feature::VHT == 0 || bits & feature::HT40 != 0)
            .filter(|bits| bits & feature::WIDTH_160 == 0 || bits & feature::VHT != 0)
            .map(|bits| bits | ba)
            .collect();
        sets.sort_by_key(|bits| core::cmp::Reverse(bits.count_ones()));
        sets
    }
    /// Selection requires the actual signed tag5 asset for exactly `bits`.
    pub(in crate::iwlwifi) fn select_feature_power(
        &mut self,
        source: &crate::firmware_asset::Asset,
        binding: [u8; 32],
        bits: u16,
    ) -> Result<(), &'static str> {
        if !self.feature_offers().contains(&bits) {
            return Err("MVM feature program differs from the selected offer");
        }
        super::power::validate_record(
            source,
            binding,
            self.mac.ok_or("MVM feature program MAC absent")?,
            Emission::Features(bits),
        )?;
        self.power.phy.features = bits & !(feature::BA | feature::NESTED_BA);
        Ok(())
    }
    pub(in crate::iwlwifi) fn supports_native_ht20(&self) -> bool {
        self.nvm
            .as_ref()
            .is_some_and(|n| n.phy.ht && n.phy.tx_streams != 0 && n.phy.rx_streams != 0)
            && self.hardware.version(1, 0x18) == Some((12, 2))
            && self.hardware.version(5, 0x17) == Some((3, 2))
            && self.hardware.version(0, 0x1c).is_some_and(|v| v.0 == 9)
            && self
                .hardware
                .version(1, 0x1c)
                .is_some_and(|v| matches!(v.1, 6..=8))
            && self.hardware.version(0, 0xc1).is_some_and(|v| v.1 == 4)
            && self.hardware.version(5, 0xf7).is_some_and(|v| v.1 == 3)
            && self
                .hardware
                .version(5, 15)
                .is_some_and(|v| matches!(v.0, 2..=4))
            && super::super::parse_ucode(&self.firmware).is_ok_and(|p| p.api.has_capability(43))
    }
}
