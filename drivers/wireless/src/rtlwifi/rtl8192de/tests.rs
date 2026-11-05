// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE dual-MAC model tests (software models only; no device,
//! firmware execution, station chain or RF acceptance is implied).

use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn check(cond: bool, msg: &str) -> TestResult {
    if cond {
        TestResult::Pass
    } else {
        TestResult::Fail(msg)
    }
}

/// PROM mode selection: PCI bit 3 of `EEPROM_MAC_FUNCTION`, USB bit 0
/// of `EEPROM_ENDPOINT_SETTING` (inverted).
fn smoke_rtl8192de_mode_from_prom() -> TestResult {
    let mut pci_single = [0u8; 0x20];
    pci_single[EEPROM_MAC_FUNCTION] = 0x08;
    let mut pci_dual = [0u8; 0x20];
    pci_dual[EEPROM_MAC_FUNCTION] = 0x00;
    let mut usb_single = [0u8; 0x20];
    usb_single[EEPROM_ENDPOINT_SETTING] = 0x00;
    let mut usb_dual = [0u8; 0x20];
    usb_dual[EEPROM_ENDPOINT_SETTING] = 0x01;
    check(
        mode_from_prom(Interface::Pci, &pci_single) == Some(MacPhyMode::SingleMacSinglePhy)
            && mode_from_prom(Interface::Pci, &pci_dual) == Some(MacPhyMode::DualMacDualPhy)
            && mode_from_prom(Interface::Usb, &usb_single) == Some(MacPhyMode::SingleMacSinglePhy)
            && mode_from_prom(Interface::Usb, &usb_dual) == Some(MacPhyMode::DualMacDualPhy)
            && mode_from_prom(Interface::Pci, &[0u8; 0x08]).is_none(),
        "PROM mode selection",
    )
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_mode_from_prom
);

/// PHY-control words: PCI base `0xf0` plus mode bits; USB clears bits
/// 0–2 of the current value first (current `0xff` proves the clear).
fn smoke_rtl8192de_phy_ctrl_words() -> TestResult {
    check(
        phy_ctrl_word_pci(MacPhyMode::DualMacDualPhy) == 0xf3
            && phy_ctrl_word_pci(MacPhyMode::SingleMacSinglePhy) == 0xf4
            && phy_ctrl_word_pci(MacPhyMode::DualMacSinglePhy) == 0xf1
            && phy_ctrl_word_usb(MacPhyMode::DualMacDualPhy, 0xff) == 0xfb
            && phy_ctrl_word_usb(MacPhyMode::SingleMacSinglePhy, 0xff) == 0xfc
            && phy_ctrl_word_usb(MacPhyMode::DualMacSinglePhy, 0xff) == 0xf9,
        "PHY-control words",
    )
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_phy_ctrl_words
);

/// Mode info: single/dual-single are 2T2R on both bands from 2.4 GHz;
/// dual-dual is 1T1R with MAC0 on 5 GHz and MAC1 on 2.4 GHz.
fn smoke_rtl8192de_mode_info() -> TestResult {
    let single = mode_info(MacPhyMode::SingleMacSinglePhy, 1);
    let dual_single = mode_info(MacPhyMode::DualMacSinglePhy, 0);
    let mac0 = mode_info(MacPhyMode::DualMacDualPhy, 0);
    let mac1 = mode_info(MacPhyMode::DualMacDualPhy, 1);
    check(
        single.rf_type == RfType::TwoT2R
            && single.bandset == BandSet::OnBoth
            && single.current_band == Band::On2Ghz
            && dual_single.rf_type == RfType::TwoT2R
            && dual_single.bandset == BandSet::OnBoth
            && dual_single.current_band == Band::On2Ghz
            && mac0.rf_type == RfType::OneT1R
            && mac0.bandset == BandSet::On5Ghz
            && mac0.current_band == Band::On5Ghz
            && mac1.rf_type == RfType::OneT1R
            && mac1.bandset == BandSet::On2Ghz
            && mac1.current_band == Band::On2Ghz,
        "mode info",
    )
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_mode_info
);

/// AMPDU-factor bases, sw consequences (dual modes disable 8K A-MSDU
/// and cap RX at 4096; single leaves both alone), default channels,
/// and MAX_AGGR_NUM (`0x0B` single, `0x07` dual).
fn smoke_rtl8192de_ampdu_sw_aggr() -> TestResult {
    let single = sw_consequences(MacPhyMode::SingleMacSinglePhy, Band::On2Ghz);
    let dual5 = sw_consequences(MacPhyMode::DualMacDualPhy, Band::On5Ghz);
    let dual_single = sw_consequences(MacPhyMode::DualMacSinglePhy, Band::On2Ghz);
    check(
        ampdu_factor_base(MacPhyMode::DualMacDualPhy) == 0xb9726641
            && ampdu_factor_base(MacPhyMode::DualMacSinglePhy) == 0x66626641
            && ampdu_factor_base(MacPhyMode::SingleMacSinglePhy) == 0xb972a841
            && !single.disable_amsdu_8k
            && single.rxbuffersize.is_none()
            && single.default_channel == 1
            && dual5.disable_amsdu_8k
            && dual5.rxbuffersize == Some(4096)
            && dual5.default_channel == 36
            && dual_single.disable_amsdu_8k
            && dual_single.rxbuffersize == Some(4096)
            && dual_single.default_channel == 1
            && max_aggr_num(MacPhyMode::SingleMacSinglePhy) == 0x0b
            && max_aggr_num(MacPhyMode::DualMacDualPhy) == 0x07
            && max_aggr_num(MacPhyMode::DualMacSinglePhy) == 0x07,
        "AMPDU/sw/aggr",
    )
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_ampdu_sw_aggr
);

/// AGC selection: MAC0 always the combined table (either band — pinned
/// on both bands); MAC1 the 2G table on 2.4 GHz, the 5G table on 5 GHz.
/// Spot values are Linux literals from `table.c`.
fn smoke_rtl8192de_agc_selection() -> TestResult {
    let mac0_2g = agc_table(0, Band::On2Ghz);
    let mac0_5g = agc_table(0, Band::On5Ghz);
    let mac1_2g = agc_table(1, Band::On2Ghz);
    let mac1_5g = agc_table(1, Band::On5Ghz);
    check(
        core::ptr::eq(mac0_2g, &tables::AGCTAB[..])
            && core::ptr::eq(mac0_5g, &tables::AGCTAB[..])
            && core::ptr::eq(mac1_2g, &tables::AGCTAB_2G[..])
            && core::ptr::eq(mac1_5g, &tables::AGCTAB_5G[..])
            && tables::AGCTAB.len() == 386
            && tables::AGCTAB_2G.len() == 194
            && tables::AGCTAB_5G.len() == 194
            && tables::AGCTAB_5G[0] == 0xc78
            && tables::AGCTAB_5G[1] == 0x7b000001,
        "AGC selection",
    )
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_agc_selection
);

/// RF selection: plain 2T tables by default, per-path internal-PA
/// tables when the EFUSE flag is set; the DMDP swap fires only for a
/// radio-B text load on path A.
fn smoke_rtl8192de_radio_selection() -> TestResult {
    let (a, b) = radio_tables([false, false]);
    let (a_pa, b_plain) = radio_tables([true, false]);
    let (a_plain, b_pa) = radio_tables([false, true]);
    check(
        core::ptr::eq(a, &tables::RADIOA_2T[..])
            && core::ptr::eq(b, &tables::RADIOB_2T[..])
            && core::ptr::eq(a_pa, &tables::RADIOA_2T_INT_PA[..])
            && core::ptr::eq(b_plain, &tables::RADIOB_2T[..])
            && core::ptr::eq(a_plain, &tables::RADIOA_2T[..])
            && core::ptr::eq(b_pa, &tables::RADIOB_2T_INT_PA[..])
            && tables::RADIOA_2T.len() == 378
            && tables::RADIOB_2T.len() == 384
            && dmdp_swapped(RfContent::RadioBTxt, RfPath::A)
            && !dmdp_swapped(RfContent::RadioATxt, RfPath::A)
            && !dmdp_swapped(RfContent::RadioBTxt, RfPath::B),
        "RF selection",
    )
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_radio_selection
);

/// Table inventory: all 10 lengths from `table.h`, plus spot values
/// written out as Linux literals (PHY_REG head, PHY_REG_PG head).
fn smoke_rtl8192de_table_inventory() -> TestResult {
    check(
        tables::PHY_REG_2T.len() == 380
            && tables::PHY_REG_PG.len() == 624
            && tables::RADIOA_2T_INT_PA.len() == 378
            && tables::RADIOB_2T_INT_PA.len() == 384
            && tables::MAC_2T.len() == 160
            && tables::PHY_REG_2T[0] == 0x024
            && tables::PHY_REG_2T[1] == 0x0011800d
            && tables::PHY_REG_PG[0] == 0xe00
            && tables::PHY_REG_PG[1] == 0xffffffff
            && tables::PHY_REG_PG[2] == 0x07090c0c
            && core::ptr::eq(mac_table(), &tables::MAC_2T[..])
            && core::ptr::eq(phy_reg_table(), &tables::PHY_REG_2T[..])
            && core::ptr::eq(phy_reg_pg_table(), &tables::PHY_REG_PG[..]),
        "table inventory",
    )
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_table_inventory
);
