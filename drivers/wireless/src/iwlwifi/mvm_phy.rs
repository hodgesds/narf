//! Retained optional native MVM PHY/QoS facts. This is distinct from the
//! Gen3 MLD payload encoders; all radio authority remains with signed power.
use super::super::boot_context::{put16, put32};
use super::power::{feature, Emission};
use alloc::{collections::VecDeque, vec::Vec};
use narf_wireless::association::{
    phy::{LocalHt, LocalPhy},
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
}
impl Context {
    /// The 40MHz secondary channel once a signed `HT40` program is granted.
    pub fn span(&self) -> Option<u8> {
        self.secondary
            .filter(|_| self.features & feature::HT40 != 0)
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
            tx_sgi: false,
            rx_sgi: false,
            rx_ldpc: false,
            rx_stbc: false,
            tx_ldpc: false,
            tx_stbc: false,
            width40: false,
            tx_sgi40: false,
            rx_sgi40: false,
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
            let expected = match self.span() {
                Some(secondary) => {
                    let mut span = [ht.operation().primary(), secondary];
                    span.sort_unstable();
                    if phy.occupied_channels() != span {
                        return Err("MVM HT40 response changed the prepared 40MHz span");
                    }
                    narf_wireless::association::phy::Width::Forty
                }
                None => narf_wireless::association::phy::Width::Twenty,
            };
            if phy.width() != expected {
                return Err("MVM HT response selected a width other than the prepared PHY");
            }
            profile.width40 = expected == narf_wireless::association::phy::Width::Forty;
            profile.tx_sgi40 = profile.width40 && ht.tx_sgi40();
            profile.rx_sgi40 = profile.width40 && ht.rx_sgi40();
            profile.ht = true;
            profile.tx_mcs = ht.tx_mcs()[0];
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
    let base = if features & feature::HT40 != 0 {
        // iwl_init_ht_hw_capab for an ht40_bands band: SUP_WIDTH_20_40 and
        // SGI_40 next to SGI_20.
        let mut mcs = [0; 10];
        mcs[0] = 255;
        let gi = narf_wireless::association::phy::HtGi {
            rx20: true,
            tx20: true,
            rx40: true,
            tx40: true,
        };
        LocalHt::new(
            mcs,
            mcs,
            narf_wireless::association::phy::HtWidth::TwentyForty,
            gi,
            0,
            0,
        )
        .unwrap_or_else(|_| LocalHt::siso20(true, true))
    } else {
        LocalHt::siso20(true, true)
    };
    base.with_ldpc(true, features & feature::TX_LDPC != 0)
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
            && (!self.tx_sgi || cap[0] & 32 != 0)
            && cap[2] & 3 == self.ampdu_exp
            && (cap[2] >> 2) & 7 == self.density
            && ((u16::from_le_bytes([cap[0], cap[1]]) >> 2) & 3 == 1) == self.dynamic_smps
            && (!self.tx_ldpc || cap[0] & 1 != 0)
            && (!self.tx_stbc || cap[1] & 3 != 0)
            && (!self.width40 || cap[0] & 2 != 0)
            && (!self.tx_sgi40 || cap[0] & 64 != 0)
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
                | (u32::from(self.width40) << 26) // STA_FLG_FAT_EN_40MHZ
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
        out[4] = u8::from(self.width40);
        out[5] = u8::from(self.ht);
        out[6] = chains;
        // rs_fw_get_config_flags: STBC bit0, LDPC bit1.
        put16(
            &mut out,
            8,
            u16::from(self.tx_stbc) | u16::from(self.tx_ldpc) << 1,
        );
        put16(&mut out, 10, rates);
        put16(&mut out, 12, u16::from(self.tx_mcs));
        // v2/3 SGI byte22; v4 byte7. A-MSDU and all NSS2/width>20 rates0.
        // rs_fw_sgi_cw_support: BIT(20MHz) | BIT(40MHz).
        out[if version == 4 { 7 } else { 22 }] =
            u8::from(self.tx_sgi) | u8::from(self.tx_sgi40) << 1;
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
        let sgi = if wide == 1 {
            self.rx_sgi40
        } else {
            self.rx_sgi
        };
        self.ht
            && (r >> 8) & 7 == 2
            && (wide == 0 || self.width40 && wide == 1)
            && r & (0xf8 | ((15 << 16) & !coding) | (3 << 23)) == 0
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
        if self.power.phy.features & feature::HT40 != 0 {
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
    /// Drop `HT40` from the offer when the current host policy does not
    /// permit the whole 40MHz span; mac80211 then keeps the 20MHz chandef
    /// (`ieee80211_chandef_downgrade`).
    pub(in crate::iwlwifi) fn restrict_offer(
        &mut self,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) {
        if let Some(secondary) = self.power.phy.secondary {
            if super::power::span_power(domain, self.power.phy.primary, Some(secondary)).is_none() {
                self.power.phy.secondary = None;
                self.power.phy.available &= !feature::HT40;
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
