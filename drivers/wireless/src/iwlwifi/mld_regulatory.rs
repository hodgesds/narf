// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! MCC v8 facts and mac80211's regulatory EDCA intersection.
use alloc::sync::Arc;
use narf_wireless::reg::{RegulatoryDomain, WmmRule};

#[derive(Clone)]
pub(super) struct Mcc {
    pub channels: Arc<[u32]>,
    pub country: [u8; 2],
    pub etsi_5ghz: bool,
    pub he_allowed: bool,
    pub eht_allowed: bool,
    pub widths: super::gen3_wire::Widths,
}
impl Mcc {
    /// API77 MVM reply geometry is source-selected independently of its
    /// raw channel permission bits. This deliberately promises legacy20.
    pub fn parse_mvm(version: u8, bytes: &[u8]) -> Result<Self, &'static str> {
        let (header, count_at, geo) = match version {
            3 => (16, 12, 8),
            4 => (20, 16, 10),
            8 => (24, 20, 14),
            _ => return Err("MVM AP MCC response ABI unsupported"),
        };
        if bytes.len() < header {
            return Err("MVM AP MCC reply truncated");
        }
        let country = u16::from_le_bytes(bytes[4..6].try_into().unwrap()).to_be_bytes();
        let count = u32::from_le_bytes(bytes[count_at..count_at + 4].try_into().unwrap()) as usize;
        if u32::from_le_bytes(bytes[..4].try_into().unwrap()) > 1
            || count == 0
            || count > 110
            || bytes.len() != header + 4 * count
            || country != *b"00" && !country.iter().all(u8::is_ascii_uppercase)
        {
            return Err("MVM AP MCC current status/country/count invalid");
        }
        Ok(Self {
            country,
            channels: bytes[header..]
                .chunks_exact(4)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                .collect::<alloc::vec::Vec<_>>()
                .into(),
            etsi_5ghz: u16::from_le_bytes(bytes[geo..geo + 2].try_into().unwrap()) & 1 != 0,
            he_allowed: false,
            eht_allowed: false,
            widths: super::gen3_wire::Widths {
                forty: false,
                eighty: false,
                one_sixty: false,
                three_twenty: false,
            },
        })
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        Self::parse_version(8, bytes)
    }
    pub fn parse_version(version: u8, bytes: &[u8]) -> Result<Self, &'static str> {
        let native = super::gen3_wire::Mcc::parse(version, bytes)?;
        Ok(Self {
            channels: native.channels,
            country: native.country,
            etsi_5ghz: native.etsi_5ghz,
            he_allowed: native.he,
            eht_allowed: native.eht,
            widths: native.widths,
        })
    }
    /// Linux iwl_parse_nvm_mcc_info's GEO_WMM_ETSI_5GHZ_INFO and
    /// ieee80211_regulatory_limit_wmm_params: raise contention floors and
    /// cap TXOP; AP parameters cannot widen the regulatory access profile.
    pub fn limit_qos(
        &self,
        domain: &RegulatoryDomain,
        primary: u8,
        width: u8,
        center: u8,
        qos: Option<super::qos::Parameters>,
    ) -> Option<super::qos::Parameters> {
        self.limit_qos_band(
            domain,
            if primary <= 14 {
                super::native_band::Band::Two
            } else {
                super::native_band::Band::Five
            },
            primary,
            width,
            center,
            qos,
        )
    }
    pub fn limit_qos_band(
        &self,
        domain: &RegulatoryDomain,
        band: super::native_band::Band,
        primary: u8,
        width: u8,
        center: u8,
        mut qos: Option<super::qos::Parameters>,
    ) -> Option<super::qos::Parameters> {
        let Some(parameters) = qos.as_mut() else {
            return qos;
        };
        let frequency = if band == super::native_band::Band::Six {
            5950 + 5 * u32::from(center)
        } else if primary == 14 {
            2484
        } else {
            (if primary <= 14 { 2407 } else { 5000 }) + 5 * u32::from(center)
        };
        let half = (20u32 << width) / 2;
        let mut apply = |floor: &WmmRule| {
            for (firmware_ac, linux_ac) in [3, 2, 1, 0].into_iter().enumerate() {
                let required = floor.client[linux_ac];
                let configured = &mut parameters.ac[firmware_ac];
                configured.cw_min = configured.cw_min.max(required.cw_min);
                configured.cw_max = configured.cw_max.max(required.cw_max);
                configured.aifs = configured.aifs.max(required.aifsn);
                configured.txop_us = configured.txop_us.min(required.cot_us / 32 * 32);
            }
        };
        if self.etsi_5ghz && band == super::native_band::Band::Five {
            apply(&WmmRule::ETSI);
        }
        for rule in domain.rules.iter().filter(|r| {
            r.freq_start_mhz < frequency + half && r.freq_end_mhz > frequency.saturating_sub(half)
        }) {
            if let Some(floor) = rule.wmm_rule() {
                apply(&floor);
            }
        }
        qos
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn smoke_iwl_mld_mcc_country_geo_and_native_edca_intersection() -> TestResult {
        (|| {
            let mut bytes = alloc::vec![0;28];
            bytes[4..6].copy_from_slice(&u16::from_be_bytes(*b"DE").to_le_bytes());
            bytes[14] = 1;
            bytes[20] = 1;
            bytes[24] = 13;
            let mcc = Mcc::parse(&bytes)?;
            let domain = RegulatoryDomain {
                country_code: *b"US",
                rules: Vec::new(),
            };
            let mut offered = super::super::qos::Parameters::default();
            offered.ac[3].aifs = 1;
            offered.ac[3].txop_us = 8160;
            offered.ac[1].cw_min = 3;
            let limited = mcc.limit_qos(&domain, 36, 0, 36, Some(offered)).unwrap();
            if mcc.country != *b"DE"
                || mcc.channels.as_ref() != [13]
                || limited.ac[3].aifs != 2
                || limited.ac[3].txop_us != 1984
                || limited.ac[1].cw_min != 15
                || mcc.limit_qos(&domain, 1, 0, 1, Some(offered)) != Some(offered)
            {
                return Err("MCC applied country/geo or source EDCA intersection");
            }
            bytes[4..6].fill(0);
            if Mcc::parse(&bytes).is_ok() {
                return Err("MCC absent applied country admitted");
            }
            Ok(())
        })()
        .map_or_else(TestResult::Fail, |()| TestResult::Pass)
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/policy",
        smoke_iwl_mld_mcc_country_geo_and_native_edca_intersection
    );
}
