// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Native HE station context, LINK_CONFIG and TLC facts. Layouts follow
//! Linux iwlwifi fw/api/{mac,mac-cfg,rs}.h and mvm/{mac80211,link,rs-fw}.c.
//! A negotiated profile supplies no measured-program or radio authority.
use super::super::boot_context::{put16, put32};
use super::power::feature;
use alloc::vec::Vec;
use narf_wireless::association::{
    he::{HeNegotiation, LocalHe},
    phy::ApElements,
};

/// A bounded subset of iwl-nvm-parse.c's station iftype HE capabilities:
/// one/two qualified streams, MCS0..7, no TWT/fragmentation/beamforming,
/// with hardware RX LDPC/STBC and the HE-variant HT Control field.
pub(super) fn local(features: u16, primary: u8) -> Result<LocalHe, &'static str> {
    let mut phy = [0; 11];
    phy[0] = if primary <= 14 {
        u8::from(features & feature::HT40 != 0) << 1
    } else {
        u8::from(features & feature::VHT != 0) << 2
    };
    phy[1] = 0x10 | 0x20; // class A, RX LDPC
    phy[2] = 2
        | 8
        | if features & feature::TX_STBC != 0 {
            4
        } else {
            0
        };
    phy[7] = 4; // HE SU/MU 4xLTF + 0.8us GI
    phy[8] = 1; // HE ER SU 4xLTF + 0.8us GI
    phy[9] = 0x30; // full-band SU using MU with either SIG-B compression
    let map = if features & feature::NSS2 != 0 {
        0xfff0
    } else {
        0xfffc
    };
    let profile = LocalHe::new([1, 0, 0x20, 0, 0, 0], phy, map, map)
        .map_err(|_| "invalid native MVM local HE facts")?;
    if features & feature::WIDTH_160 != 0 {
        profile
            .with_160mhz(map, map)
            .map_err(|_| "invalid MVM HE160 facts")
    } else {
        Ok(profile)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Profile {
    pub negotiation: HeNegotiation,
    pub tx_map: u16,
    /// ACI-indexed three-byte source records, not firmware AC order.
    mu_edca: Option<[[u8; 3]; 4]>,
    uora: Option<u8>,
}
impl Profile {
    pub fn new(
        negotiation: HeNegotiation,
        ies: &[u8],
        single_stream: bool,
    ) -> Result<Self, &'static str> {
        let (mu_edca, uora) = optional_elements(ies)?;
        let tx_map = negotiation.tx_mcs_map() | if single_stream { 0xfffc } else { 0 };
        Ok(Self {
            negotiation,
            tx_map,
            mu_edca,
            uora,
        })
    }
    pub fn matches(&self, ies: &[u8]) -> bool {
        ApElements::parse(ies).is_ok_and(|ap| {
            ap.he_capability() == Some(self.negotiation.peer_capability())
                && ap.he_operation() == Some(self.negotiation.operation())
        }) && optional_elements(ies) == Ok((self.mu_edca, self.uora))
    }
    fn backoff(&self) -> [u8; 32] {
        let mut bytes = [0; 32];
        if let Some(records) = self.mu_edca {
            for (index, aci) in [1, 0, 2, 3].into_iter().enumerate() {
                let record = records[aci];
                let at = index * 8;
                put16(&mut bytes, at, u16::from(record[1] & 15));
                put16(&mut bytes, at + 2, u16::from(record[1] >> 4));
                put16(&mut bytes, at + 4, u16::from(record[0] & 15));
                put16(&mut bytes, at + 6, u16::from(record[2]));
            }
        }
        bytes
    }
    /// Legacy-ADD_STA companion, STA_CONTEXT_DOT11AX_API_S versions1..3.
    pub fn context(&self, version: u8) -> Result<Vec<u8>, &'static str> {
        let width_slots = match version {
            1 | 2 => 4,
            3 => 5,
            _ => return Err("unsupported MVM HE context version"),
        };
        let extent = match version {
            1 => 80,
            2 => 88,
            _ => 92,
        };
        let mut bytes = alloc::vec![0; extent];
        bytes[1] = 1; // No multi-TID TX aggregation.
        let op = self.negotiation.operation();
        let mac = self.negotiation.peer_capability().mac_capability();
        let mut flags = (1 << 8) | (1 << 13); // valid PPE; NIC not ACK-enabled
        flags |= u32::from(op.bss_color_disabled()) << 5;
        flags |= u32::from(op.partial_bss_color()) << 6;
        flags |= u32::from(mac[2] & 0x20 != 0) << 7;
        flags |= u32::from(mac[2] & 0x80 != 0) << 11;
        flags |= u32::from(self.uora.is_some()) << 9;
        flags |= u32::from(self.mu_edca.is_some()) << 12;
        put32(&mut bytes, 4, flags);
        let link_adapt = u8::from(mac[1] & 0x80 != 0) | ((mac[2] & 1) << 1);
        let htc = u32::from(mac[0] & 1)
            | if link_adapt >= 2 {
                u32::from(link_adapt) << 1
            } else {
                0
            }
            | (u32::from(mac[2] & 8 != 0) << 4)
            | (u32::from(mac[3] & 2 != 0) << 5)
            | (u32::from(mac[4] & 4 != 0) << 6);
        put32(&mut bytes, 16, htc);
        let extension = packet_extension(self.negotiation.peer_capability());
        for (stream, thresholds) in extension.iter().enumerate() {
            for (width, pair) in thresholds.iter().enumerate().take(width_slots) {
                let at = 24 + (stream * width_slots + width) * 2;
                bytes[at..at + 2].copy_from_slice(pair);
            }
        }
        let at = 24 + 2 * width_slots * 2;
        bytes[at] = op.bss_color();
        bytes[at + 1] = op.default_pe_duration();
        put16(&mut bytes, at + 2, op.txop_rts_threshold());
        if let Some(range) = self.uora {
            bytes[at + 4] = range & 7;
            bytes[at + 5] = (range >> 3) & 7;
        }
        bytes[at + 8..at + 40].copy_from_slice(&self.backoff());
        Ok(bytes)
    }
    /// LINK_CONTEXT_CONFIG_CMD_API_S_VER_1, already associated link0.
    pub fn apply_link(&self, bytes: &mut [u8; 208]) {
        let mask = u32::from_le_bytes(bytes[24..28].try_into().unwrap()) | (1 << 5) | (1 << 6);
        put32(bytes, 24, mask);
        let op = self.negotiation.operation();
        bytes[100] = op.default_pe_duration();
        if let Some(range) = self.uora {
            bytes[101] = range & 7;
            bytes[102] = (range >> 3) & 7;
        }
        bytes[104..136].copy_from_slice(&self.backoff());
        put16(bytes, 146, op.txop_rts_threshold());
        let flags = u32::from(op.bss_color_disabled()) | (u32::from(self.mu_edca.is_some()) << 1);
        put32(bytes, 148, flags);
        put32(bytes, 152, 3);
        bytes[165] = op.bss_color();
        bytes[167] = u8::from(self.negotiation.peer_capability().mac_capability()[5] & 0x80 != 0);
    }
}

type MuEdca = Option<[[u8; 3]; 4]>;
fn optional_elements(mut ies: &[u8]) -> Result<(MuEdca, Option<u8>), &'static str> {
    let mut mu = None;
    let mut uora = None;
    while !ies.is_empty() {
        if ies.len() < 2 || ies.len() < 2 + usize::from(ies[1]) {
            return Err("truncated MVM HE information element");
        }
        let body = &ies[2..2 + usize::from(ies[1])];
        if ies[0] == 255 {
            match body.first() {
                Some(37) => {
                    if body.len() != 2
                        || uora.is_some()
                        || body[1] & 0xc0 != 0
                        || body[1] & 7 > (body[1] >> 3) & 7
                    {
                        return Err("invalid MVM UORA parameters");
                    }
                    uora = Some(body[1]);
                }
                Some(38) => {
                    if body.len() != 14 || mu.is_some() {
                        return Err("invalid MVM MU EDCA extent");
                    }
                    let mut records = [[0; 3]; 4];
                    let mut seen = 0;
                    for record in body[2..].chunks_exact(3) {
                        let aci = usize::from((record[0] >> 5) & 3);
                        if seen & (1 << aci) != 0
                            || record[0] & 0x90 != 0
                            || record[1] & 15 > record[1] >> 4
                        {
                            return Err("invalid MVM MU EDCA AC record");
                        }
                        seen |= 1 << aci;
                        records[aci].copy_from_slice(record);
                    }
                    mu = Some(records);
                }
                _ => {}
            }
        }
        ies = &ies[2 + usize::from(ies[1])..];
    }
    Ok((mu, uora))
}

/// Linux iwl_mvm_parse_ppe: [NSS][RU bandwidth][PPET8, PPET16]. HE
/// does not inherit a missing RU's thresholds from an earlier bandwidth.
fn packet_extension(peer: &narf_wireless::association::he::HeCapability) -> [[[u8; 2]; 5]; 2] {
    let mut result = [[[7; 2]; 5]; 2];
    let ppe = peer.ppe_thresholds();
    if let Some(header) = ppe.first() {
        let streams = usize::from((header & 7) + 1).min(2);
        let mut bit = 7;
        let field = |at: usize| -> u8 {
            (0..3).fold(0, |value, n| {
                value | ((ppe[(at + n) / 8] >> ((at + n) % 8)) & 1) << n
            })
        };
        for stream in result.iter_mut().take(streams) {
            for (width, threshold) in stream.iter_mut().enumerate().take(4) {
                if header & (1 << (3 + width)) != 0 {
                    *threshold = [field(bit + 3), field(bit)];
                    bit += 6;
                }
            }
        }
    } else {
        let pair = match peer.phy_capability()[9] >> 6 {
            1 => [0, 7],
            2 => [7, 0],
            _ => [7, 7],
        };
        result = [[pair; 5]; 2];
    }
    result
}

impl super::Owner {
    pub(super) fn he_context_version(&self) -> Option<u8> {
        let parsed = super::super::parse_ucode(&self.firmware).ok()?;
        let version = self.hardware.version(5, 7)?.0;
        if !matches!(version, 1..=3) {
            return None;
        }
        // IWL_UCODE_TLV_API_MBSSID_HE (52) is the source's v2 opt-in.
        Some(if parsed.api.api_changes[1] & (1 << 20) == 0 {
            1
        } else {
            version
        })
    }
    pub(super) fn supports_native_he(&self) -> bool {
        self.supports_native_he_contract() && self.scan_he_permitted()
    }
    pub(in crate::iwlwifi) fn supports_native_he_contract(&self) -> bool {
        self.supports_native_ht20()
            && self.nvm.as_ref().is_some_and(|nvm| nvm.he)
            && self.he_context_version().is_some()
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_wireless::association::{
        phy::{LocalHt, LocalPhy},
        Bss, JoinPlan, SecurityMode,
    };
    fn negotiated(extra: &[u8]) -> Result<Profile, &'static str> {
        let local = local(0, 1)?;
        let ht = LocalHt::siso20(true, true);
        let mut ies = alloc::vec![0, 1, b'n', 1, 1, 0x82, 45, 26];
        ies.extend_from_slice(&ht.capability_body());
        ies.extend_from_slice(&[61, 22]);
        let mut op = [0; 22];
        op[0] = 1;
        op[6] = 1;
        ies.extend_from_slice(&op);
        let body = local.capability_body();
        ies.extend_from_slice(&[255, body.len() as u8]);
        ies.extend_from_slice(&body);
        ies.extend_from_slice(&[255, 7, 36, 0xf2, 0x3f, 0, 7, 0xfc, 0xff]);
        ies.extend_from_slice(extra);
        let bss = Bss {
            bssid: [2; 6],
            ssid: alloc::vec![b'n'],
            channel: 1,
            band: None,
            signal_dbm: None,
            capability: 1,
            beacon_interval: 100,
            information_elements: ies.clone(),
        };
        let phy = LocalPhy::ht20(ht)
            .map_err(|_| "HE codec HT")?
            .with_he(local)
            .map_err(|_| "HE codec local")?;
        let plan = JoinPlan::prepare_with_phy(&bss, [4; 6], b"n", SecurityMode::Open, phy)
            .map_err(|_| "HE codec plan")?;
        let negotiated = plan
            .offered_phy()
            .ok_or("HE codec offer")?
            .response_elements(&ies)
            .map_err(|_| "HE codec response")?;
        Profile::new(*negotiated.he().ok_or("HE codec negotiation")?, &ies, false)
    }
    fn smoke_mvm_he_context_versions_ppe_and_mu_edca_source_geometry() -> TestResult {
        (|| {
            let extra = [
                255, 2, 37, 0x2c, 255, 14, 38, 0, 3, 0xa4, 8, 0x27, 0xa4, 9, 0x42, 0x43, 10, 0x62,
                0x32, 11,
            ];
            let profile = negotiated(&extra)?;
            for (version, offset, mask, length) in [(4, 6, 1u32 << 10, 20), (8, 8, 1u32 << 13, 24)]
            {
                let mut mcc = alloc::vec![0;length];
                if !super::super::scan::mcc_he_permitted(version, &mcc) {
                    return Err("HE source MCC allow profile rejected");
                }
                for (at, byte) in
                    mask.to_le_bytes()
                        .iter()
                        .enumerate()
                        .take(if version == 4 { 2 } else { 4 })
                {
                    mcc[offset + at] = *byte;
                }
                if super::super::scan::mcc_he_permitted(version, &mcc) {
                    return Err("HE MCC global prohibition ignored");
                }
            }
            if super::super::scan::mcc_he_permitted(3, &[0; 16]) {
                return Err("legacy MCC byte inferred HE authority");
            }
            for (version, length, operation) in [(1, 80, 40), (2, 88, 40), (3, 92, 44)] {
                let bytes = profile.context(version)?;
                if bytes.len() != length
                    || bytes[operation..operation + 8] != [7, 2, 0xff, 3, 4, 5, 0, 0]
                    || bytes[operation + 8..operation + 24]
                        != [4, 0, 10, 0, 7, 0, 9, 0, 4, 0, 10, 0, 3, 0, 8, 0]
                    || bytes[24..operation].iter().any(|v| *v != 7)
                    || bytes[4..8] != [0x80, 0x33, 0, 0]
                {
                    return Err("HE context version/PPE/MU EDCA/UORA native geometry");
                }
            }
            if profile.context(0).is_ok()
                || profile.context(4).is_ok()
                || optional_elements(&[255, 2, 37, 0x07]).is_ok()
                || optional_elements(&[255, 2, 37, 0x2c, 255, 2, 37, 0x2c]).is_ok()
            {
                return Err("HE context accepted unknown ABI or malformed optional parameters");
            }
            let mut body = local(0, 1)?.capability_body()[1..].to_vec();
            body[12] |= 0x80;
            body.extend_from_slice(&[0x61, 0x1c, 0xc7, 0x71]);
            let peer = narf_wireless::association::he::HeCapability::parse(&body)
                .map_err(|_| "HE source PPE vector")?;
            let ppe = packet_extension(&peer);
            if ppe != [[[7, 7], [7, 7], [7, 0], [7, 0], [7, 7]]; 2] {
                return Err("HE PPE cross-byte low/high order or RU placement");
            }
            Ok(())
        })()
        .map_or_else(TestResult::Fail, |()| TestResult::Pass)
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/gen2/he",
        smoke_mvm_he_context_versions_ppe_and_mu_edca_source_geometry
    );
}
