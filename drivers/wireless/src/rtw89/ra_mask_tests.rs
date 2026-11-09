// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Fixture tests for RA v1 mask computation. Expected masks
//! are hand-computed from the Linux `phy.c` algorithm and
//! `phy.h` bit positions, never by calling the computation
//! under test. The command-word test decodes the words
//! from the `fw.h` positions, never via `build_ra_v1`'s
//! own field layout beyond the documented word map.

use super::ra_mask::*;
use super::station_8922a::Band;
use narf_kernel_test::{kernel_test_in, TestResult};

/// Legacy-only 2.4 GHz station: CCK + OFDM rates, no
/// HT/VHT/HE/EHT. Strong RSSI (raw 200 -> halved 100 ->
/// no floor level -> all-ones floor, the Linux quirk).
fn legacy_caps() -> StationCaps {
    StationCaps {
        band: Band::Ghz2,
        width_mhz: 20,
        supp_rates: 0xFF5,
        ht: None,
        vht: None,
        he: None,
        eht: None,
        rx_nss: 1,
        tx_nss: 2,
        rssi: 200,
        no_mcs_12_13: true,
        er_cap: false,
    }
}

fn smoke_rtw89_ra_mask_legacy() -> TestResult {
    let Ok(c) = compute(&legacy_caps()) else {
        return TestResult::Fail("ra mask legacy rejects");
    };
    // mode CCK|OFDM = 3; legacy-only trim keeps OFDM|SUBCCK
    // (0xFF0|0x5 = 0xFF5); floor all-ones; recover no-op.
    if c.mask != 0xFF5 || c.mode != 3 || c.bw_cap != 0 || c.ss_num != 0 || c.sgi {
        return TestResult::Fail("ra mask legacy values");
    }
    if c.fix_giltf_en || c.dcm || c.partial_bw_er {
        return TestResult::Fail("ra mask legacy sets HE/EHT fields");
    }
    // Weak RSSI (raw 70 -> halved 35 -> level 1 floor
    // 0xFFFF...FFF0) clears the CCK bits, keeps OFDM.
    let mut weak = legacy_caps();
    weak.rssi = 70;
    let Ok(c) = compute(&weak) else {
        return TestResult::Fail("ra mask weak rssi rejects");
    };
    if c.mask != 0xFF0 {
        return TestResult::Fail("ra mask rssi floor level 1");
    }
    // CCK-only mode skips the floor entirely (Linux
    // `mode != CCK` guard): even weak RSSI keeps 0x5.
    let mut cck = legacy_caps();
    cck.supp_rates = 0x5;
    cck.rssi = 70;
    let Ok(c) = compute(&cck) else {
        return TestResult::Fail("ra mask cck-only rejects");
    };
    if c.mask != 0x5 || c.mode != 1 {
        return TestResult::Fail("ra mask cck-only skips floor");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_ra_mask_legacy);

fn smoke_rtw89_ra_mask_ht() -> TestResult {
    let mut caps = legacy_caps();
    caps.supp_rates = 0xFF0;
    caps.ht = Some(HtCaps {
        rx_mask: [0xFF, 0xFF, 0, 0],
        sgi20: true,
        sgi40: false,
        rx_stbc: true,
        ldpc: false,
    });
    caps.rx_nss = 2;
    let Ok(c) = compute(&caps) else {
        return TestResult::Fail("ra mask ht rejects");
    };
    // mode HT|OFDM = 6. Raw: HT 1SS/2SS full MCS0-7
    // (0xFF<<12 | 0xFF<<24) + legacy 0xFF0. Trim: cap =
    // HT_1SS|HT_2SS (bits 12..31) + SUBOFDM bit 4, so the
    // legacy part collapses to bit 4 only.
    // 0xFF000000 | 0xFF000 | 0x10 = 0xFF0FF010.
    if c.mask != 0xFF0F_F010 || c.mode != 6 || c.bw_cap != 0 {
        return TestResult::Fail("ra mask ht values");
    }
    if !c.sgi || !c.stbc || c.ldpc || c.ss_num != 1 {
        return TestResult::Fail("ra mask ht params");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_ra_mask_ht);

fn smoke_rtw89_ra_mask_vht() -> TestResult {
    let mut caps = legacy_caps();
    caps.band = Band::Ghz5;
    caps.width_mhz = 80;
    caps.supp_rates = 0xFF;
    caps.vht = Some(VhtCaps {
        rx_mcs_map: 0xAAAA,
        sgi80: true,
        sgi160: false,
        rx_stbc: false,
        rx_ldpc: true,
    });
    caps.rx_nss = 2;
    let Ok(c) = compute(&caps) else {
        return TestResult::Fail("ra mask vht rejects");
    };
    // mode VHT|OFDM = 10. Raw VHT: 0x3FF at 12/24/36/48
    // (all groups cap 2, MCS9). Trim: VHT_1SS|VHT_2SS
    // (bits 12..21, 24..33) + SUBOFDM bit 4; legacy
    // 0xFF<<4 = 0xFF0 collapses to bit 4.
    // 0x3FF000000 | 0x3FF000 | 0x10 = 0x3FF3FF010.
    if c.mask != 0x3FF3FF010 || c.mode != 10 || c.bw_cap != 2 {
        return TestResult::Fail("ra mask vht values");
    }
    if !c.sgi || c.stbc || !c.ldpc || c.ss_num != 1 {
        return TestResult::Fail("ra mask vht params");
    }
    // 20 MHz VHT uses highest MCS8, not MCS9: 0x1FF groups.
    let mut narrow = caps;
    narrow.width_mhz = 20;
    let Ok(c) = compute(&narrow) else {
        return TestResult::Fail("ra mask vht20 rejects");
    };
    if c.mask != 0x1FF1FF010 || c.bw_cap != 0 {
        return TestResult::Fail("ra mask vht20 highest mcs8");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_ra_mask_vht);

fn smoke_rtw89_ra_mask_he() -> TestResult {
    let mut caps = legacy_caps();
    caps.band = Band::Ghz5;
    caps.width_mhz = 160;
    caps.supp_rates = 0xFF;
    caps.he = Some(HeCaps {
        rx_mcs_80: 0xFFFF,
        rx_mcs_160: 0x0000,
        rx_mcs_80p80: 0xAAAA,
        has_80p80: true,
        stbc_under_80: true,
        ldpc_in_payload: true,
        dcm_16qam: true,
        partial_bw_er: true,
    });
    caps.rx_nss = 2;
    let Ok(c) = compute(&caps) else {
        return TestResult::Fail("ra mask he rejects");
    };
    // 160 MHz + 80+80 advertised -> 80+80 map 0xAAAA
    // (all groups cap 2, MCS11): 0xFFF at 12/24/36/48.
    // (The 80 map is all-cap-3 = nothing, and the 160
    // map is all-cap-0 = 0xFF groups, so either wrong
    // selection gives a different mask.) Trim: HE_1SS|
    // HE_2SS (bits 12..23, 24..35) + SUBOFDM bit 4.
    // 0xFFF000000 | 0xFFF000 | 0x10 = 0xFFFFF0010.
    if c.mask != 0xF_FFFF0010 || c.mode != 18 || c.bw_cap != 3 {
        return TestResult::Fail("ra mask he 80p80 values");
    }
    if c.sgi || !c.stbc || !c.ldpc || !c.dcm || !c.partial_bw_er {
        return TestResult::Fail("ra mask he params");
    }
    if !c.fix_giltf_en || c.fix_giltf != 3 {
        return TestResult::Fail("ra mask he giltf");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_ra_mask_he);

/// The EHT test station: 5 GHz, 80 MHz, EHT caps with
/// group0 RX NSS 2 and group1 RX NSS 1 on the 80 table.
fn eht_station() -> StationCaps {
    let mut caps = legacy_caps();
    caps.band = Band::Ghz5;
    caps.width_mhz = 80;
    caps.supp_rates = 0xFF;
    caps.eht = Some(EhtCaps {
        bw_80: [0x22, 0x11, 0x00],
        bw_160: [0; 3],
        bw_320: [0; 3],
        only_20mhz: [0; 4],
        ap_20mhz_only: false,
    });
    caps.rx_nss = 2;
    caps
}

fn smoke_rtw89_ra_mask_eht() -> TestResult {
    let caps = eht_station();
    let Ok(c) = compute(&caps) else {
        return TestResult::Fail("ra mask eht rejects");
    };
    // mode EHT|OFDM = 34. Raw EHT: group0 NSS2 ->
    // GENMASK(9,0) at shifts 12, 28 (bits 12..21,
    // 28..37); group1 NSS1 -> GENMASK(11,0) at shift 12
    // (bits 12..23). Union: bits 12..23 + 28..37.
    // Trim (8922A no_mcs_12_13 -> MCS0_11 tables):
    // cap = bits 12..23 + 28..39 + SUBOFDM bit 4, so
    // the EHT part survives whole and legacy 0xFF0
    // collapses to bit 4.
    // 0x3FF0000000 | 0xFFF000 | 0x10 = 0x3FF0FFF010.
    if c.mask != 0x3FF0FFF010 || c.mode != 34 || c.bw_cap != 2 {
        return TestResult::Fail("ra mask eht values");
    }
    if !c.fix_giltf_en || c.fix_giltf != 3 || c.ss_num != 1 {
        return TestResult::Fail("ra mask eht params");
    }
    // NSS4 group: shifts 12/28/44/60 push bits past 63;
    // the u64 shift drops them, and the trim drops the
    // 44..53 and 60..63 residue (no MCS0_11 table covers
    // those bits). Only bits 12..21, 28..37, and legacy
    // bit 4 survive.
    let mut wide = eht_station();
    wide.eht = Some(EhtCaps {
        bw_80: [0x04, 0x00, 0x00],
        bw_160: [0; 3],
        bw_320: [0; 3],
        only_20mhz: [0; 4],
        ap_20mhz_only: false,
    });
    let Ok(c) = compute(&wide) else {
        return TestResult::Fail("ra mask eht nss4 rejects");
    };
    if c.mask != 0x3FF3FF010 {
        return TestResult::Fail("ra mask eht nss4 trim");
    }
    // EHT beats HE in the else-if chain: with both caps,
    // the HE map must not contribute.
    let mut both = eht_station();
    both.he = Some(HeCaps {
        rx_mcs_80: 0xAAAA,
        rx_mcs_160: 0xAAAA,
        rx_mcs_80p80: 0xAAAA,
        has_80p80: false,
        stbc_under_80: false,
        ldpc_in_payload: false,
        dcm_16qam: false,
        partial_bw_er: false,
    });
    let Ok(c) = compute(&both) else {
        return TestResult::Fail("ra mask eht+he rejects");
    };
    if c.mask != 0x3FF0FFF010 || c.mode != 34 {
        return TestResult::Fail("ra mask eht wins over he");
    }
    // Rejections: zero NSS, zero TX NSS, bad width,
    // EHT nibble above 4.
    let mut bad = eht_station();
    bad.rx_nss = 0;
    if compute(&bad).is_ok() {
        return TestResult::Fail("ra mask accepts zero rx nss");
    }
    let mut bad = eht_station();
    bad.tx_nss = 0;
    if compute(&bad).is_ok() {
        return TestResult::Fail("ra mask accepts zero tx nss");
    }
    let mut bad = eht_station();
    bad.width_mhz = 60;
    if compute(&bad).is_ok() {
        return TestResult::Fail("ra mask accepts bad width");
    }
    let mut bad = eht_station();
    bad.eht = Some(EhtCaps {
        bw_80: [0x55, 0x00, 0x00],
        bw_160: [0; 3],
        bw_320: [0; 3],
        only_20mhz: [0; 4],
        ap_20mhz_only: false,
    });
    if compute(&bad).is_ok() {
        return TestResult::Fail("ra mask accepts nss nibble 5");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_ra_mask_eht);

fn smoke_rtw89_ra_mask_build() -> TestResult {
    // Same EHT station as the compute test, via build():
    // words decoded from the fw.h positions.
    let mut caps = legacy_caps();
    caps.band = Band::Ghz5;
    caps.width_mhz = 80;
    caps.supp_rates = 0xFF;
    caps.eht = Some(EhtCaps {
        bw_80: [0x22, 0x11, 0x00],
        bw_160: [0; 3],
        bw_320: [0; 3],
        only_20mhz: [0; 4],
        ap_20mhz_only: false,
    });
    caps.rx_nss = 2;
    let Ok(words) = build(&caps, 0x2A, 0, false, false) else {
        return TestResult::Fail("ra mask build rejects");
    };
    // mask 0x3FF0FFF010: w1 = low 32 = 0xF0FFF010,
    // w2 = bits 32..62 = 0x3F. mode 34: w0 mode field
    // (5 bits) keeps 34 & 0x1F = 2 -> bits 1..5 = 4;
    // bw 2 -> bits 6..7 = 0x80; mac 0x2A -> 0x2A00;
    // ss 1 -> bit 24. w0 = 0x1002A84.
    // w3: fix_en bit 11 (0x800) | fix 3 << 12 (0x3000)
    // | band 1 << 29 (0x20000000) = 0x20003800.
    // w4: mode_eht 34 (0x22) | bw_eht 2 << 8 (0x200)
    // = 0x222; w5 = 0 (no upper mask in Linux).
    if words[0] != 0x0100_2A84
        || words[1] != 0xF0FF_F010
        || words[2] != 0x3F
        || words[3] != 0x2000_3800
        || words[4] != 0x222
        || words[5] != 0
    {
        return TestResult::Fail("ra mask build words");
    }
    // Update flags land in w0 bits 30/31.
    let Ok(words) = build(&caps, 0x2A, 0, true, true) else {
        return TestResult::Fail("ra mask build upd rejects");
    };
    if words[0] != (0x0100_2A84 | 0xC000_0000) {
        return TestResult::Fail("ra mask build upd bits");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_ra_mask_build);
