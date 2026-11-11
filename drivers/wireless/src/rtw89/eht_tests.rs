// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixture tests for RTL8922A EHT width programming and PHY programs.
//! Expected values are Linux literals (`rtw8922a.c` / `reg.h` @
//! cbbddb6), written out in the test, never read from the module
//! under test — except where the test independently recomputes a
//! positioned value from a field value plus its mask.

use super::eht::*;
use super::irq::Regs;
use super::power;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

struct Fake {
    regs: Vec<(u32, u32)>,
}

impl Fake {
    fn new() -> Self {
        Self { regs: Vec::new() }
    }
    fn set(&mut self, addr: u32, val: u32) {
        if let Some(slot) = self.regs.iter_mut().find(|(a, _)| *a == addr) {
            slot.1 = val;
        } else {
            self.regs.push((addr, val));
        }
    }
    fn get(&self, addr: u32) -> u32 {
        self.regs
            .iter()
            .find(|(a, _)| *a == addr)
            .map(|(_, v)| *v)
            .unwrap_or(0)
    }
}

impl Regs for Fake {
    fn read32(&mut self, address: u32) -> Result<u32, power::Error> {
        Ok(self.get(address))
    }
    fn write32(&mut self, address: u32, value: u32) -> Result<(), power::Error> {
        self.set(address, value);
        Ok(())
    }
}

fn smoke_rtw89_eht_width_tables() -> TestResult {
    // Widths in MHz.
    if Width::Mhz20.mhz() != 20
        || Width::Mhz40.mhz() != 40
        || Width::Mhz80.mhz() != 80
        || Width::Mhz160.mhz() != 160
        || Width::Mhz320.mhz() != 320
    {
        return TestResult::Fail("EHT width MHz table wrong");
    }
    // RFMOD: 20->0, 40->1, 80->2, 160->3, 320->None (no Linux arm).
    if rfmod_value(Width::Mhz20) != Some(0)
        || rfmod_value(Width::Mhz40) != Some(1)
        || rfmod_value(Width::Mhz80) != Some(2)
        || rfmod_value(Width::Mhz160) != Some(3)
        || rfmod_value(Width::Mhz320).is_some()
    {
        return TestResult::Fail("EHT RFMOD table wrong");
    }
    if R_BE_WMAC_RFMOD != 0x10010
        || B_BE_WMAC_RFMOD_MASK != 0x7
        || R_BE_TX_SUB_BAND_VALUE != 0x10088
    {
        return TestResult::Fail("EHT RFMOD register/mask wrong");
    }
    // SIFS pairs: 20 -> (0x3f, 0x3e); 40/80/160/320 -> (0x41, 0x41).
    if sifs_values(Width::Mhz20) != (0x3F, 0x3E)
        || sifs_values(Width::Mhz40) != (0x41, 0x41)
        || sifs_values(Width::Mhz80) != (0x41, 0x41)
        || sifs_values(Width::Mhz160) != (0x41, 0x41)
        || sifs_values(Width::Mhz320) != (0x41, 0x41)
    {
        return TestResult::Fail("EHT SIFS table wrong");
    }
    if R_BE_PREBKF_CFG_1 != 0x1033C
        || B_BE_SIFS_MACTXEN_T1_MASK != 0x7F
        || R_BE_MUEDCA_EN != 0x10370
        || B_BE_SIFS_MACTXEN_TB_T1_MASK != (0x7F << 16)
    {
        return TestResult::Fail("EHT SIFS register/mask wrong");
    }
    // CFGCH codes 0..4 and fields positioned in bits 12..10.
    if cfgch_bw_code(Width::Mhz20) != 0
        || cfgch_bw_code(Width::Mhz40) != 1
        || cfgch_bw_code(Width::Mhz80) != 2
        || cfgch_bw_code(Width::Mhz160) != 3
        || cfgch_bw_code(Width::Mhz320) != 4
        || RR_CFGCH_BW_V2 != (0x7 << 10)
        || cfgch_bw_field(Width::Mhz320) != (4 << 10)
        || cfgch_bw_field(Width::Mhz80) != (2 << 10)
    {
        return TestResult::Fail("EHT CFGCH table wrong");
    }
    // BB class: <=40 narrow, >=80 wide.
    if bb_bw_class(Width::Mhz20) != BbBwClass::Narrow20_40
        || bb_bw_class(Width::Mhz40) != BbBwClass::Narrow20_40
        || bb_bw_class(Width::Mhz80) != BbBwClass::Wide80_160_320
        || bb_bw_class(Width::Mhz160) != BbBwClass::Wide80_160_320
        || bb_bw_class(Width::Mhz320) != BbBwClass::Wide80_160_320
    {
        return TestResult::Fail("EHT BB class table wrong");
    }
    TestResult::Pass
}

fn smoke_rtw89_eht_bb_postinit_program() -> TestResult {
    // Register addresses and masks, from reg.h, independent of the
    // module's program table.
    if R_SLOPE != 0x6B6C
        || B_EHT_RATE_TH != (0xF << 28)
        || R_BEDGE != 0x6BFC
        || B_EHT_MCS14 != (1 << 31)
        || R_BEDGE2 != 0x6C00
        || B_EHT_MCS15 != (1 << 31)
        || R_BEDGE3 != 0x6C04
        || B_EHTTB_EN != (1 << 15)
    {
        return TestResult::Fail("EHT bb_postinit register/mask wrong");
    }
    // Masking-defeating case: preseed every target register with all
    // bits set, so a whole-register write (instead of a masked write)
    // would be visible, and a wrong field position would be visible.
    let mut io = Fake::new();
    io.set(R_SLOPE, u32::MAX);
    io.set(R_BEDGE, u32::MAX);
    io.set(R_BEDGE2, u32::MAX);
    io.set(R_BEDGE3, u32::MAX);
    if apply_program(&mut io, &BB_POSTINIT_EHT).is_err() {
        return TestResult::Fail("EHT bb_postinit apply failed");
    }
    // Field values positioned from Linux: rate threshold 0xA in bits
    // 31..28; MCS14/MCS15 bits set; EHTTB bit cleared.
    if io.get(R_SLOPE) != (0xA << 28) | 0x0FFF_FFFF
        || io.get(R_BEDGE) != u32::MAX
        || io.get(R_BEDGE2) != u32::MAX
        || io.get(R_BEDGE3) != u32::MAX & !(1 << 15)
    {
        return TestResult::Fail("EHT bb_postinit apply wrong");
    }
    // Zero-start case: only the programmed fields appear.
    let mut io = Fake::new();
    if apply_program(&mut io, &BB_POSTINIT_EHT).is_err() {
        return TestResult::Fail("EHT bb_postinit apply failed");
    }
    if io.get(R_SLOPE) != (0xA << 28)
        || io.get(R_BEDGE) != (1 << 31)
        || io.get(R_BEDGE2) != (1 << 31)
        || io.get(R_BEDGE3) != 0
    {
        return TestResult::Fail("EHT bb_postinit zero-start wrong");
    }
    TestResult::Pass
}

fn smoke_rtw89_eht_rx_nss_program() -> TestResult {
    if R_BRK_EHT != 0x0474
        || B_RXEHT_NSS_MAX != (0x7 << 2)
        || R_BRK_RXEHT != 0x0478
        || B_RXEHTTB_NSS_MAX != (0x7 << 14)
        || B_RXEHT_N_USER_MAX != (0xFF << 24)
        || HE_N_USER_MAX_8922A != 4
    {
        return TestResult::Fail("EHT rx_nss register/mask wrong");
    }
    // Rejected counts mirror Linux's -EINVAL arm.
    if rx_nss_eht_program(0).is_some() || rx_nss_eht_program(3).is_some() {
        return TestResult::Fail("EHT rx_nss rejects wrong counts");
    }
    // 1 stream: NSS fields 0, user max 4.
    let mut io = Fake::new();
    let prog = rx_nss_eht_program(1).unwrap();
    if apply_program(&mut io, &prog).is_err() {
        return TestResult::Fail("EHT rx_nss(1) apply failed");
    }
    if io.get(R_BRK_EHT) != 0 || io.get(R_BRK_RXEHT) != (4 << 24) {
        return TestResult::Fail("EHT rx_nss(1) wrong");
    }
    // 2 streams: NSS fields 1 (positioned), user max 4.
    let mut io = Fake::new();
    let prog = rx_nss_eht_program(2).unwrap();
    if apply_program(&mut io, &prog).is_err() {
        return TestResult::Fail("EHT rx_nss(2) apply failed");
    }
    if io.get(R_BRK_EHT) != (1 << 2) || io.get(R_BRK_RXEHT) != (1 << 14) | (4 << 24) {
        return TestResult::Fail("EHT rx_nss(2) wrong");
    }
    TestResult::Pass
}

fn smoke_rtw89_eht_operation_profile() -> TestResult {
    if !EHT_8922A.width_320 || EHT_8922A.max_mpdu_len != 7991 {
        return TestResult::Fail("EHT operation profile wrong");
    }
    if R_CNT_EHT_CRC != 0x2F00 || B_CNT_EHT_CRC_OK != 0xFFFF || B_CNT_EHT_CRC_ERR != (0xFFFF << 16)
    {
        return TestResult::Fail("EHT CRC counter block wrong");
    }
    TestResult::Pass
}

fn smoke_rtw89_eht_cap_8922ae() -> TestResult {
    // 8922AE variant, independently computed from
    // `rtw89_init_eht_cap` + `ieee80211-eht.h` (see the module docs):
    // MAC cap0 = 7991-enc(1) << 6 = 0x40; PHY cap0 = NDP(0x08) |
    // SU_BEAMFORMEE(0x40) | (sts-1 bit0 -> 0x80) = 0xC8; PHY cap1 =
    // (sts-1 bits 2:1 -> 0x03) | (sts-1 -> 0x1C) = 0x1F; PHY cap3 =
    // 0x08|0x10|0x20|0x40 = 0x78; PHY cap4 = 0x04 | (MAX_NC 1 -> 0x10)
    // = 0x14; PHY cap5 = 20US(3) -> 0x30. MCS/NSS val = rx2 | tx2<<4
    // = 0x22; mcs13 = 0 because the variant gates MCS 12/13 off.
    let cap = match eht_cap(EHT_CAP_8922AE_INPUTS) {
        Some(cap) => cap,
        None => return TestResult::Fail("EHT cap 8922AE unexpectedly None"),
    };
    if cap.mac_cap_info != [0x40, 0x00] {
        return TestResult::Fail("EHT cap 8922AE MAC cap bytes wrong");
    }
    if cap.phy_cap_info != [0xC8, 0x1F, 0x00, 0x78, 0x14, 0x30, 0x00, 0x00, 0x00] {
        return TestResult::Fail("EHT cap 8922AE PHY cap bytes wrong");
    }
    if cap.mcs_nss_80.mcs9 != 0x22
        || cap.mcs_nss_80.mcs11 != 0x22
        || cap.mcs_nss_80.mcs13 != 0x00
        || cap.mcs_nss_160.mcs9 != 0x22
        || cap.mcs_nss_160.mcs11 != 0x22
        || cap.mcs_nss_160.mcs13 != 0x00
    {
        return TestResult::Fail("EHT cap 8922AE 80/160 MCS maps wrong");
    }
    // Discriminating case: step 1's width programming carries a 320MHz
    // arm, but the advertised capability must NOT carry 320MHz MCS —
    // the chip's support_bandwidths has no 320 bit, so Linux's gate
    // leaves the 320 entries unset. Programming != advertisement.
    if cap.mcs_nss_320.mcs9 != 0 || cap.mcs_nss_320.mcs11 != 0 || cap.mcs_nss_320.mcs13 != 0 {
        return TestResult::Fail("EHT cap 8922AE must not advertise 320MHz MCS");
    }
    TestResult::Pass
}

fn smoke_rtw89_eht_cap_gates() -> TestResult {
    let base = EHT_CAP_8922AE_INPUTS;
    // EHT gated off by firmware phycap -> no capability at all.
    if eht_cap(EhtCapInputs {
        no_eht: true,
        ..base
    })
    .is_some()
    {
        return TestResult::Fail("EHT cap must be None when no_eht");
    }
    // MCS 12/13 allowed -> mcs13 carries the same NSS byte.
    let allowed = match eht_cap(EhtCapInputs {
        no_mcs_12_13: false,
        ..base
    }) {
        Some(cap) => cap,
        None => return TestResult::Fail("EHT cap MCS-allowed unexpectedly None"),
    };
    if allowed.mcs_nss_80.mcs13 != 0x22 || allowed.mcs_nss_160.mcs13 != 0x22 {
        return TestResult::Fail("EHT cap mcs13 must carry val when allowed");
    }
    // 320 gate needs BOTH 6GHz and the bandwidth bit: 6GHz + bit opens
    // it (320 MCS = 0x22/0x22/0x00, PHY0 gains 0x02 -> 0xCA, PHY1 gains
    // 0xE0 -> 0xFF); 5GHz + bit leaves it shut.
    let wide = match eht_cap(EhtCapInputs {
        six_ghz: true,
        support_320mhz_bandwidth: true,
        ..base
    }) {
        Some(cap) => cap,
        None => return TestResult::Fail("EHT cap 320-gate unexpectedly None"),
    };
    if wide.mcs_nss_320.mcs9 != 0x22
        || wide.mcs_nss_320.mcs11 != 0x22
        || wide.mcs_nss_320.mcs13 != 0x00
        || wide.phy_cap_info[0] != 0xCA
        || wide.phy_cap_info[1] != 0xFF
    {
        return TestResult::Fail("EHT cap 320 gate wrong on 6GHz");
    }
    let not_wide = match eht_cap(EhtCapInputs {
        six_ghz: false,
        support_320mhz_bandwidth: true,
        ..base
    }) {
        Some(cap) => cap,
        None => return TestResult::Fail("EHT cap 5GHz+320bit unexpectedly None"),
    };
    if not_wide.mcs_nss_320.mcs9 != 0
        || not_wide.mcs_nss_320.mcs11 != 0
        || not_wide.mcs_nss_320.mcs13 != 0
        || not_wide.phy_cap_info[0] != 0xC8
        || not_wide.phy_cap_info[1] != 0x1F
    {
        return TestResult::Fail("EHT cap 320 gate must stay shut off 6GHz");
    }
    // NSS encode path: 1/1 streams -> 0x11, not 0x22.
    let one = match eht_cap(EhtCapInputs {
        rx_nss: 1,
        tx_nss: 1,
        no_mcs_12_13: false,
        ..base
    }) {
        Some(cap) => cap,
        None => return TestResult::Fail("EHT cap 1SS unexpectedly None"),
    };
    if one.mcs_nss_80.mcs9 != 0x11 || one.mcs_nss_80.mcs13 != 0x11 {
        return TestResult::Fail("EHT cap NSS encode wrong for 1SS");
    }
    // Unmapped MPDU length fails closed, never advertises a wrong cap.
    if eht_cap(EhtCapInputs {
        max_mpdu_len: 5000,
        ..base
    })
    .is_some()
    {
        return TestResult::Fail("EHT cap must be None for unknown MPDU len");
    }
    // Band-independence for this chip: 2.4/5/6GHz agree because the
    // 320 gate can never open without the bandwidth bit.
    let g = match eht_cap(EhtCapInputs {
        six_ghz: true,
        ..base
    }) {
        Some(cap) => cap,
        None => return TestResult::Fail("EHT cap 6GHz variant unexpectedly None"),
    };
    if g != eht_cap(base).unwrap() {
        return TestResult::Fail("EHT cap 8922AE must be band-independent");
    }
    TestResult::Pass
}

fn smoke_rtw89_eht_station_facet() -> TestResult {
    let facet = match EhtStation::new_8922ae() {
        Some(facet) => facet,
        None => return TestResult::Fail("EHT station facet unexpectedly None"),
    };
    // Capability matches the pinned 8922AE values (spot-check: the
    // full byte tables are pinned in smoke_rtw89_eht_cap_8922ae).
    if facet.cap.mac_cap_info != [0x40, 0x00] || facet.cap.mcs_nss_80.mcs13 != 0x00 {
        return TestResult::Fail("EHT station facet capability wrong");
    }
    // Fail-closed defaults: no TX EHT override programmed.
    if facet.nltf_switch || facet.nltf != 0 || facet.ul_eht_usr_pres {
        return TestResult::Fail("EHT station facet defaults must be off");
    }
    if facet.txwd_info_eht() != Some((0, 0)) {
        return TestResult::Fail("EHT station facet default info must be (0, 0)");
    }
    // Negotiated values flow through to the info dwords.
    let negotiated = EhtStation {
        nltf_switch: true,
        nltf: 2,
        ul_eht_usr_pres: true,
        ..facet
    };
    if negotiated.txwd_info_eht() != Some((0x50_0000, 0x1_0000)) {
        return TestResult::Fail("EHT station facet info dwords wrong");
    }
    // Out-of-range NLTF fails closed, never truncated.
    let bad = EhtStation { nltf: 4, ..facet };
    if bad.txwd_info_eht().is_some() {
        return TestResult::Fail("EHT station facet must reject NLTF > 3");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_eht_width_tables);
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_eht_bb_postinit_program
);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_eht_rx_nss_program);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_eht_operation_profile);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_eht_cap_8922ae);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_eht_cap_gates);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_eht_station_facet);

fn smoke_rtw89_8922a_eht_txsb_sub_band_value() -> TestResult {
    // Hand-evaluated `rtw89_phy_get_txsb` (phy.c:875) cases.
    let cases: [(Width, u8, u8, Width, Option<u8>); 9] = [
        (Width::Mhz20, 36, 36, Width::Mhz20, Some(0)),
        (Width::Mhz40, 40, 38, Width::Mhz20, Some(1)),
        (Width::Mhz80, 36, 42, Width::Mhz20, Some(0)),
        (Width::Mhz80, 48, 42, Width::Mhz20, Some(3)),
        (Width::Mhz160, 60, 50, Width::Mhz20, Some(6)),
        (Width::Mhz160, 60, 50, Width::Mhz40, Some(2)),
        (Width::Mhz320, 61, 31, Width::Mhz20, Some(15)),
        (Width::Mhz320, 61, 31, Width::Mhz80, Some(3)),
        // Primary below the channel: Linux u8 math would wrap.
        (Width::Mhz80, 30, 42, Width::Mhz20, None),
    ];
    for (cbw, pri, central, dbw, want) in cases {
        if get_txsb(cbw, pri, central, dbw) != want {
            return TestResult::Fail("rtw89_phy_get_txsb transcription drift");
        }
    }
    // `rtw8922a_set_channel_mac` TX_SUB_BAND_VALUE words:
    // TXSB20 [3:0], TXSB40 [7:4], TXSB80 [11:8], PRI20 bitmap [31:16].
    let words: [(Width, u8, u8, u32); 6] = [
        (Width::Mhz20, 36, 36, 0x0001_0000),
        (Width::Mhz40, 40, 38, 0x0002_0001),
        (Width::Mhz80, 36, 42, 0x0001_0000),
        (Width::Mhz80, 48, 42, 0x0008_0013),
        (Width::Mhz160, 60, 50, 0x0040_0126),
        // 320 takes the Linux default arm: no TXSB fields, bitmap bit 0.
        (Width::Mhz320, 61, 31, 0x0001_0000),
    ];
    for (width, pri, central, want) in words {
        if tx_sub_band_value(width, pri, central) != Some(want) {
            return TestResult::Fail("TX_SUB_BAND_VALUE word wrong");
        }
    }
    if tx_sub_band_value(Width::Mhz80, 30, 42).is_some() {
        return TestResult::Fail("out-of-channel primary must be refused");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_8922a_eht_txsb_sub_band_value
);
