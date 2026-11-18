// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8922A set_channel owner: the `rtw8922a_set_channel_mac` register
//! program plus the channel-set composition that gives
//! `Prepared8922a::set_txpwr` its first live caller.
//!
//! Linux order (`__rtw89_set_channel`, core.c:576..606,
//! torvalds/linux @ 05441d6), for the parts this owner programs:
//!
//! 1. `rtw89_chip_set_channel_prepare` — the help-enter bracket
//!    (`rtw8922a_set_channel_help(enter)`, rtw8922a.c:2321:
//!    DBCC-only pre-set BB/RF, then `hal_reset` enter: stop
//!    scheduler TX, PPDU status off, DFS off, TSSI-continue off,
//!    ADC off, 40 us, BB-reset off). NOT programmed here: no BE
//!    transcription of the bracket exists yet (see remainders).
//! 2. `chip->ops->set_channel` = `rtw8922a_set_channel_mac` +
//!    `rtw8922a_set_channel_bb` + `rtw8922a_set_channel_rf`
//!    (rtw8922a.c:2232..2241). This owner programs the MAC leg
//!    (`set_channel_mac_program`, rtw8922a.c:1048..1145) and the
//!    BB leg (`set_channel_bb_program`, rtw8922a.c:2179..2198,
//!    minus the two gain sub-legs — see remainders) synchronously
//!    over the BAR2 register port; the RF leg
//!    (`program_set_channel_rf`, rtw8922a_rfk.c:103) is an async
//!    `rfk::Interface` owner in this file, because the RF writes
//!    carry 100 us sleeps and the sync owner has no RF transport
//!    (see below).
//! 3. `chip->ops->set_txpwr` (`rtw8922a_set_txpwr`,
//!    rtw8922a.c:2540) — driven by
//!    `Prepared8922a::set_channel` immediately after the MAC+BB
//!    program, the first live caller of
//!    `Prepared8922a::set_txpwr`.
//! 4. `rtw89_chip_set_channel_done` — the help-exit bracket. NOT
//!    programmed here (same remainder as step 1).
//! 5. On the first programmed channel or a band change
//!    (`!entity_active || band_changed`, core.c:599..602):
//!    `rtw89_btc_ntfy_switch_band` + `rtw89_chip_rfk_band_changed`
//!    (`rtw8922a_rfk_band_changed`, the TSSI SCAN offload,
//!    rtw8922a.c:2412). This owner records the band change in
//!    `SetChannelOutcome::band_changed`; the SCAN offload and the
//!    full `rtw8922a_rfk_channel` (rtw8922a.c:2388) run on the
//!    async path (`rfk::be_channel::Channel`), which needs a
//!    native BE `Interface` (H2C send + C2H report wait) that
//!    does not exist on the 8922A path yet — a follow-up, not
//!    invented here.
//!
//! What this owner deliberately does NOT program (each a grounded
//! absence with its Linux site, for follow-up lanes):
//! - The two gain sub-legs of `rtw8922a_ctrl_ch`
//!   (rtw8922a.c:1508..1515): `rtw8922a_set_gain`
//!   (`rtw8922a_set_lna_tia_gain` :1316 + `rtw8922a_set_rpl_gain`
//!   :1271, both paths) and `rtw8922a_set_rx_gain_normal`
//!   (:1451..1464, both paths). Both consume per-device calibration
//!   state no BE owner produces yet: `rtwdev->bb_gain.be`
//!   (`struct rtw89_phy_bb_gain_info_be`, decoded by
//!   `rtw89_phy_config_bb_gain_be`, phy_be.c:398, from the chip
//!   BB-gain tables + efuse `rfe_type`) and
//!   `rtwdev->efuse_gain.offset[]` + `offset_valid`. In-tree only
//!   the AX decoder exists (`rtw89_phy_config_bb_gain_ax`,
//!   consumed by `radio_gain::Gain` for the 8851B/8852C lanes);
//!   there is no BE gain owner, so the BB program writes no gain
//!   word — inventing one would be fabrication. The gain writes
//!   are pinned absent by the BB tests (the LNA/TIA/RPL registers
//!   stay untouched after a channel program).
//! - The RF leg inside the sync `Prepared8922a::set_channel`:
//!   `program_set_channel_rf` exists and is fixture-validated,
//!   but the sync owner cannot drive it — it needs 100 us sleeps
//!   (`fsleep(100)`, rtw8922a_rfk.c:82) and an RF transport, and
//!   the only RF transports in-tree are async (`rfk::Interface`,
//!   implemented natively only for the B/C adapters in
//!   `command_native.rs`; no native BE `Interface` exists on the
//!   8922A path yet). Wiring the RF leg into a station-path caller
//!   needs that native BE `Interface` plus an async set-channel
//!   entry point — the same missing piece as the async channel
//!   RFK, not built here.
//! - The help enter/exit bracket (`rtw8922a_set_channel_help`,
//!   rtw8922a.c:2321..2340, incl. `hal_reset` :2297 and the
//!   DBCC-only pre/post BB/RF steps, which are no-ops without
//!   DBCC).
//! - The BTC switch-band notify (`rtw89_btc_ntfy_switch_band`,
//!   core.c:599): no BE coexistence owner exists yet.
//!
//! A refused `set_channel` writes nothing when the refusal
//! happens before the MAC program (unknown station, geometry
//! mismatch, unbuildable MAC program). A `set_txpwr` refusal
//! AFTER the MAC+BB program leaves the MAC+BB registers on the
//! new channel with the old power program: the owner records no
//! channel, so a retry re-programs the MAC+BB idempotently before
//! retrying power (see `Prepared8922a::set_channel`).
//!
//! The RF leg mirrors Linux's partial-write behaviour: an
//! `INV_RF_DATA` word is checked per (path, register) immediately
//! before that register's write (rtw8922a_rfk.c:70..84), so a
//! failure on path B leaves path A's words programmed; a retry
//! re-programs from the top.

use super::eht::{
    self, ProgramEntry, Width as EhtWidth, B_BE_SIFS_MACTXEN_T1_MASK, B_BE_SIFS_MACTXEN_TB_T1_MASK,
    B_BE_WMAC_RFMOD_MASK, R_BE_MUEDCA_EN, R_BE_PREBKF_CFG_1, R_BE_TX_SUB_BAND_VALUE,
    R_BE_WMAC_RFMOD,
};
use super::irq::Regs;
use super::operating_channel_c::{Band, Profile, Width};
use super::{power, rfk};
use alloc::vec::Vec;

/// `R_BE_TXRATE_CHK` (`reg.h:7203`); the C1 alias is `0x14828`.
pub(super) const R_BE_TXRATE_CHK: u32 = 0x10828;
/// `B_BE_BAND_MODE` (`reg.h:7209`): BIT(4).
pub(super) const B_BE_BAND_MODE: u32 = 1 << 4;
/// `B_BE_CHECK_CCK_EN` (`reg.h:7212`): BIT(0).
pub(super) const B_BE_CHECK_CCK_EN: u32 = 1 << 0;
/// `B_BE_RTS_LIMIT_IN_OFDM6` (`reg.h:7211`): BIT(1).
pub(super) const B_BE_RTS_LIMIT_IN_OFDM6: u32 = 1 << 1;
/// The three `R_BE_TXRATE_CHK` bits `rtw8922a_set_channel_mac`
/// touches (cleared, then the band arm set).
const TXRATE_CHK_MASK: u32 = B_BE_BAND_MODE | B_BE_CHECK_CCK_EN | B_BE_RTS_LIMIT_IN_OFDM6;

/// The shared width as the BE EHT width tables read it. 320 MHz
/// has no arm: Linux's `support_bandwidths` stops at 160 MHz
/// (`rtw8922a.c:3209`), so no 8922A channel ever reaches the
/// 320 MHz arm, and `eht::rfmod_value` claims no value for it.
fn eht_width(width: Width) -> Option<EhtWidth> {
    match width {
        Width::Mhz20 => Some(EhtWidth::Mhz20),
        Width::Mhz40 => Some(EhtWidth::Mhz40),
        Width::Mhz80 => Some(EhtWidth::Mhz80),
        Width::Mhz160 => Some(EhtWidth::Mhz160),
        Width::Mhz320 => None,
    }
}

/// The `R_BE_TXRATE_CHK` band arm (`rtw8922a.c:1114..1120`):
/// 2.4 GHz sets `B_BE_BAND_MODE`; 5/6 GHz set
/// `B_BE_CHECK_CCK_EN | B_BE_RTS_LIMIT_IN_OFDM6`. Positioned
/// into [`TXRATE_CHK_MASK`].
const fn txrate_chk(band: Band) -> u32 {
    match band {
        Band::Ghz2 => B_BE_BAND_MODE,
        Band::Ghz5 | Band::Ghz6 => B_BE_CHECK_CCK_EN | B_BE_RTS_LIMIT_IN_OFDM6,
    }
}

/// The `rtw8922a_set_channel_mac` program
/// (`rtw8922a.c:1048..1145`, MAC_0) for `profile`, in Linux
/// program order: RFMOD, the `R_BE_TX_SUB_BAND_VALUE` word, the
/// `R_BE_TXRATE_CHK` band arm, then the SIFS MACTXEN pair.
/// Values are positioned into their masks, in the crate's
/// `eht::apply_program` convention. `None` when the width has
/// no BE arm (320 MHz) or the TX-sub-band word cannot be built
/// for the primary/center pair.
pub(super) fn set_channel_mac_program(profile: Profile) -> Option<[ProgramEntry; 5]> {
    let width = eht_width(profile.width())?;
    let rfmod = eht::rfmod_value(width)?;
    let txsb = eht::tx_sub_band_value(width, profile.primary(), profile.center())?;
    let (sifs, sifs_tb) = eht::sifs_values(width);
    Some([
        (R_BE_WMAC_RFMOD, B_BE_WMAC_RFMOD_MASK, rfmod),
        (R_BE_TX_SUB_BAND_VALUE, u32::MAX, txsb),
        (R_BE_TXRATE_CHK, TXRATE_CHK_MASK, txrate_chk(profile.band())),
        (R_BE_PREBKF_CFG_1, B_BE_SIFS_MACTXEN_T1_MASK, sifs),
        (R_BE_MUEDCA_EN, B_BE_SIFS_MACTXEN_TB_T1_MASK, sifs_tb << 16),
    ])
}

/// Apply one masked program entry with the `prepared_8922a`
/// `modify32` convention (field value already positioned into
/// `mask`; full-mask writes skip the read). A `u32::MAX` read
/// is a gone device (`power::Error::Gone`).
fn apply_entry(
    regs: &mut impl Regs,
    address: u32,
    mask: u32,
    value: u32,
) -> Result<(), rfk::Error> {
    let expected = if mask == u32::MAX {
        value
    } else {
        let old = regs.read32(address)?;
        if old == u32::MAX {
            return Err(power::Error::Gone.into());
        }
        (old & !mask) | (value & mask)
    };
    regs.write32(address, expected)?;
    Ok(())
}

/// Read back one applied entry: the written bits must read as
/// written (a `u32::MAX` read is a gone device).
fn verify_entry(
    regs: &mut impl Regs,
    address: u32,
    mask: u32,
    value: u32,
) -> Result<(), rfk::Error> {
    let actual = regs.read32(address)?;
    if actual == u32::MAX || actual & mask != value & mask {
        return Err(power::Error::Access.into());
    }
    Ok(())
}

/// Build the `rtw8922a_set_channel_mac` program for `profile`
/// and apply it, read back, over the BAR2 register port.
/// `Err(Policy)` when the program cannot be built for the
/// profile; `Err(Register(..))` on a register failure (a
/// partially applied program is left behind — the caller
/// records no channel and retries from the top).
pub(super) fn program_set_channel_mac(
    regs: &mut impl Regs,
    profile: Profile,
) -> Result<(), rfk::Error> {
    let program = set_channel_mac_program(profile).ok_or(rfk::Error::Policy)?;
    for &(address, mask, value) in &program {
        apply_entry(regs, address, mask, value)?;
    }
    for &(address, mask, value) in &program {
        verify_entry(regs, address, mask, value)?;
    }
    Ok(())
}

// ── `rtw8922a_set_channel_bb` (rtw8922a.c:2179..2198) ─────────────
//
// The BB leg runs in Linux order: `ctrl_sco_cck` (2.4 GHz only),
// `ctrl_ch`, `ctrl_bw`, `ctrl_cck_en`, `spur_elimination`, the
// `R_RSTB_ASYNC` write, then the `rtw8922a_tssi_reset` pulse.
// The two gain sub-legs of `ctrl_ch` are NOT programmed here
// (no BE gain owner exists yet — see the module header).
// Every address is the BE PHY window (`0x20000 + CR`, PHY_0
// without DBCC, as in `radio_power_be`); values are positioned
// into their masks, in this file's `apply_entry` convention.

/// BE PHY register aperture offset (phy.c `rtw89_phy_write32*`).
const PHY: u32 = 0x20000;

/// `R_BK_FC0INV` (`reg.h:10023`).
const R_BK_FC0INV: u32 = 0x6758;
/// `B_BK_FC0INV` (`reg.h:10024`): GENMASK(18, 0).
const B_BK_FC0INV: u32 = 0x7_ffff;
/// `R_CCK_FC0INV` (`reg.h:10025`).
const R_CCK_FC0INV: u32 = 0x675c;
/// `B_CCK_FC0INV` (`reg.h:10026`): GENMASK(18, 0).
const B_CCK_FC0INV: u32 = 0x7_ffff;
/// `R_BT_RXBY_WBADC_A` (`reg.h:9496`): `ctrl_ch` `band_sel[0]`
/// (rtw8922a.c:1494).
const R_BAND_SEL_A: u32 = 0x4160;
/// `R_BT_RXBY_WBADC_B` (`reg.h:9557`): `ctrl_ch` `band_sel[1]`.
const R_BAND_SEL_B: u32 = 0x4560;
/// `ctrl_ch` band-select bit (rtw8922a.c:1505..1507): BIT(26).
const B_BAND_SEL: u32 = 1 << 26;
/// `R_FC0` (`reg.h:10035`).
const R_FC0: u32 = 0x6b4c;
/// `B_FC0` (`reg.h:10037`): GENMASK(12, 0).
const B_FC0: u32 = 0x1fff;
/// `R_FC0INV_SBW` (`reg.h:10038`).
const R_FC0INV_SBW: u32 = 0x6b50;
/// `B_FC0_INV` (`reg.h:10042`): GENMASK(6, 0).
const B_FC0_INV: u32 = 0x7f;
/// `B_SMALLBW` (`reg.h:10039`): GENMASK(31, 30).
const B_SMALLBW: u32 = 0xc000_0000;
/// `B_BW40_2XFFT` (`reg.h:10036`): BIT(31).
const B_BW40_2XFFT: u32 = 1 << 31;
/// `R_PCOEFF01..EF` (`reg.h:10002..10017`, step 4).
const R_PCOEFF: [u32; 8] = [
    0x6684, 0x6688, 0x668c, 0x6690, 0x6694, 0x6698, 0x669c, 0x66a0,
];
/// `B_PCOEFF01..EF` (`reg.h:10003..10017`): GENMASK(23, 0).
const B_PCOEFF: u32 = 0xff_ffff;
/// `R_MAC_PIN_SEL` (`reg.h:8925`).
const R_MAC_PIN_SEL: u32 = 0x0734;
/// `B_CH_IDX_SEG0` (`reg.h:8927`): GENMASK(23, 16).
const B_CH_IDX_SEG0: u32 = 0x00ff_0000;
/// `R_ANT_CHBW` (`reg.h:10043`).
const R_ANT_CHBW: u32 = 0x6b54;
/// `B_CHBW_BW` (`reg.h:10045`): GENMASK(14, 12).
const B_CHBW_BW: u32 = 0x7000;
/// `B_CHBW_PRICH` (`reg.h:10046`): GENMASK(11, 8).
const B_CHBW_PRICH: u32 = 0x0f00;
/// `R_DAC_CLK` (`reg.h:9993`).
const R_DAC_CLK: u32 = 0x625c;
/// `B_DAC_CLK` (`reg.h:9994`): GENMASK(31, 30).
const B_DAC_CLK: u32 = 0xc000_0000;
/// `R_GAIN_MAP0` (`reg.h:10509`).
const R_GAIN_MAP0: u32 = 0xe44c;
/// `B_GAIN_MAP0_EN` (`reg.h:10510`): BIT(0).
const B_GAIN_MAP0_EN: u32 = 1;
/// `R_GAIN_MAP1` (`reg.h:10511`).
const R_GAIN_MAP1: u32 = 0xe54c;
/// `B_GAIN_MAP1_EN` (`reg.h:10512`): BIT(0).
const B_GAIN_MAP1_EN: u32 = 1;
/// `R_RXCCA_BE1` (`reg.h:8906`).
const R_RXCCA_BE1: u32 = 0x0520;
/// `B_RXCCA_BE1_DIS` (`reg.h:8907`): BIT(0).
const B_RXCCA_BE1_DIS: u32 = 1;
/// `R_UPD_CLK_ADC` (`reg.h:8908`).
const R_UPD_CLK_ADC: u32 = 0x0700;
/// `B_ENABLE_CCK` (`reg.h:8912`): BIT(5).
const B_ENABLE_CCK: u32 = 1 << 5;
/// `R_PD_ARBITER_OFF` (`reg.h:9062`).
const R_PD_ARBITER_OFF: u32 = 0x0c80;
/// `B_PD_ARBITER_OFF` (`reg.h:9063`): BIT(31).
const B_PD_ARBITER_OFF: u32 = 1 << 31;
/// `R_S0S1_CSI_WGT` (`reg.h:9824`).
const R_S0S1_CSI_WGT: u32 = 0x4d34;
/// `B_S0S1_CSI_WGT_EN` (`reg.h:9825`): BIT(0).
const B_S0S1_CSI_WGT_EN: u32 = 1;
/// `rtw8922a_nbi_reg_def` (rtw8922a.c:1625..1639): path A
/// notch1/notch2, path B notch1/notch2.
const NBI: [(u32, u32); 2] = [(0x41a0, 0x41ac), (0x45a0, 0x45ac)];
/// `notch1_en` / `notch2_en` mask in the NBI table: BIT(12).
const B_NBI_EN: u32 = 1 << 12;
/// `R_RSTB_ASYNC` (`reg.h:8913`).
const R_RSTB_ASYNC: u32 = 0x0704;
/// `B_RSTB_ASYNC_ALL` (`reg.h:8915`): BIT(1).
const B_RSTB_ASYNC_ALL: u32 = 1 << 1;
/// `R_TXPWR_RSTA` (`reg.h:10523`).
const R_TXPWR_RSTA: u32 = 0xe60c;
/// `B_TXPWR_RSTA` (`reg.h:10524`): BIT(16).
const B_TXPWR_RSTA: u32 = 1 << 16;
/// `R_TXPWR_RSTB` (`reg.h:10542`).
const R_TXPWR_RSTB: u32 = 0xe70c;
/// `B_TXPWR_RSTB` (`reg.h:10543`): BIT(16).
const B_TXPWR_RSTB: u32 = 1 << 16;

/// `rtw8922a_sco_barker_threshold[14]` (rtw8922a.c:1139..1142).
const SCO_BARKER: [u32; 14] = [
    0x1fe4f, 0x1ff5e, 0x2006c, 0x2017b, 0x2028a, 0x20399, 0x204a8, 0x205b6, 0x206c5, 0x207d4,
    0x208e3, 0x209f2, 0x20b00, 0x20d8a,
];
/// `rtw8922a_sco_cck_threshold[14]` (rtw8922a.c:1144..1147).
const SCO_CCK: [u32; 14] = [
    0x2bdac, 0x2bf21, 0x2c095, 0x2c209, 0x2c37e, 0x2c4f2, 0x2c666, 0x2c7db, 0x2c94f, 0x2cac3,
    0x2cc38, 0x2cdac, 0x2cf21, 0x2d29e,
];
/// `rtw8922a_set_cck_parameters` channel-14 set
/// (rtw8922a.c:1469..1477): `R_PCOEFF01..EF`.
const PCOEFF_CH14: [u32; 8] = [
    0x3b13ff, 0x1c42de, 0xfdb0ad, 0xf60f6e, 0xfd8f92, 0x02d011, 0x01c02c, 0xfff00a,
];
/// `rtw8922a_set_cck_parameters` non-14 set
/// (rtw8922a.c:1478..1487): `R_PCOEFF01..EF`.
const PCOEFF: [u32; 8] = [
    0x3a63ca, 0x2a833f, 0x1491f8, 0x03c0b0, 0xfccff1, 0xfccfc3, 0xfebfdc, 0xffdff7,
];

/// Position `value` into `mask` (the `apply_entry` convention).
const fn pos(mask: u32, value: u32) -> u32 {
    (value << mask.trailing_zeros()) & mask
}

/// The `rtw8922a_set_channel_bb` program
/// (rtw8922a.c:2179..2198, PHY_0 without DBCC) for `profile`,
/// in Linux program order. `None` when the width has no arm
/// (320 MHz: `ctrl_bw`'s `default:` arm programs no CHBW field,
/// and the MAC leg already refuses it) or the 2.4 GHz primary
/// is outside the SCO tables (unreachable for a constructed
/// `Profile`, which admits 2.4 GHz primaries 1..=14 only).
///
/// `ctrl_ch`'s gain sub-legs are deliberately absent (see the
/// module header): the program carries the band-select, FC0 +
/// SCO-inverse, CCK pulse coefficients (2.4 GHz), and channel
/// index only. `spur_elimination` carries only its live arms:
/// `rtw8922a_spur_freq` returns 0 unconditionally
/// (rtw8922a.c:1601..1605), so the CSI tone is disabled and both
/// NBI notches are disabled on both paths.
pub(super) fn set_channel_bb_program(profile: Profile) -> Option<Vec<ProgramEntry>> {
    let width = profile.width();
    if width == Width::Mhz320 {
        return None;
    }
    let band_2g = profile.band() == Band::Ghz2;
    let mut program = Vec::new();
    // `rtw8922a_ctrl_sco_cck` (rtw8922a.c:1149..1168):
    // `ch_element = primary_ch - 1`; -EINVAL outside 1..=14.
    if band_2g {
        let element = profile.primary().checked_sub(1)? as usize;
        let (barker, cck) = (*SCO_BARKER.get(element)?, *SCO_CCK.get(element)?);
        program.push((PHY + R_BK_FC0INV, B_BK_FC0INV, barker));
        program.push((PHY + R_CCK_FC0INV, B_CCK_FC0INV, cck));
    }
    // `rtw8922a_ctrl_ch` (rtw8922a.c:1490..1528), minus the gain
    // sub-legs (`rtw8922a_set_gain` :1508..1509 and
    // `rtw8922a_set_rx_gain_normal` :1514..1515).
    let is_2g = u32::from(band_2g);
    program.push((PHY + R_BAND_SEL_A, B_BAND_SEL, pos(B_BAND_SEL, is_2g)));
    program.push((PHY + R_BAND_SEL_B, B_BAND_SEL, pos(B_BAND_SEL, is_2g)));
    let (fc, sco) = profile.sco_fc0();
    program.push((PHY + R_FC0, B_FC0, fc));
    program.push((PHY + R_FC0INV_SBW, B_FC0_INV, sco));
    if band_2g {
        let coefficients = if profile.center() == 14 {
            PCOEFF_CH14
        } else {
            PCOEFF
        };
        for (address, value) in R_PCOEFF.into_iter().zip(coefficients) {
            program.push((PHY + address, B_PCOEFF, value));
        }
    }
    program.push((
        PHY + R_MAC_PIN_SEL,
        B_CH_IDX_SEG0,
        pos(B_CH_IDX_SEG0, u32::from(profile.chan_idx())),
    ));
    // `rtw8922a_ctrl_bw` (rtw8922a.c:1529..1600): the 20/40/80/160
    // arms (5/10 MHz have no `Width` arm; 320 MHz is refused
    // above). `B_SMALLBW` is 0 for 20/40/80/160; the gain-map
    // enable is 1 for 80/160, 0 below.
    let (bw, gain_map_en) = match width {
        Width::Mhz20 => (0, 0),
        Width::Mhz40 => (1, 0),
        Width::Mhz80 => (2, 1),
        Width::Mhz160 => (3, 1),
        Width::Mhz320 => return None,
    };
    program.push((PHY + R_ANT_CHBW, B_CHBW_BW, pos(B_CHBW_BW, bw)));
    program.push((PHY + R_FC0INV_SBW, B_SMALLBW, 0));
    program.push((
        PHY + R_ANT_CHBW,
        B_CHBW_PRICH,
        pos(B_CHBW_PRICH, u32::from(profile.pri_sb_idx())),
    ));
    program.push((PHY + R_DAC_CLK, B_DAC_CLK, pos(B_DAC_CLK, 1)));
    program.push((PHY + R_GAIN_MAP0, B_GAIN_MAP0_EN, gain_map_en));
    program.push((PHY + R_GAIN_MAP1, B_GAIN_MAP1_EN, gain_map_en));
    program.push((
        PHY + R_FC0,
        B_BW40_2XFFT,
        pos(B_BW40_2XFFT, u32::from(width == Width::Mhz40)),
    ));
    // `rtw8922a_ctrl_cck_en` (rtw8922a.c:2163..2178).
    let cck = u32::from(band_2g);
    program.push((PHY + R_RXCCA_BE1, B_RXCCA_BE1_DIS, 1 - cck));
    program.push((PHY + R_UPD_CLK_ADC, B_ENABLE_CCK, pos(B_ENABLE_CCK, cck)));
    program.push((
        PHY + R_PD_ARBITER_OFF,
        B_PD_ARBITER_OFF,
        pos(B_PD_ARBITER_OFF, 1 - cck),
    ));
    // `rtw8922a_spur_elimination` (rtw8922a.c:1718..1724): the
    // CSI tone disable plus the NBI notch disables on both paths
    // (the spur-frequency arms are dead: `rtw8922a_spur_freq`
    // always returns 0).
    program.push((PHY + R_S0S1_CSI_WGT, B_S0S1_CSI_WGT_EN, 0));
    for (notch1, notch2) in NBI {
        program.push((PHY + notch1, B_NBI_EN, 0));
        program.push((PHY + notch2, B_NBI_EN, 0));
    }
    // The `R_RSTB_ASYNC` write (rtw8922a.c:2195).
    program.push((PHY + R_RSTB_ASYNC, B_RSTB_ASYNC_ALL, B_RSTB_ASYNC_ALL));
    // `rtw8922a_tssi_reset` (rtw8922a.c:1961..1978), non-MLO arm
    // (single-link; the `MLO_1_PLUS_1_1RF` branch is the MLO
    // lane's): pulse `R_TXPWR_RSTA` then `R_TXPWR_RSTB` 0 -> 1.
    // Same four entries as `radio_power_be::tssi_reset_program`.
    program.push((PHY + R_TXPWR_RSTA, B_TXPWR_RSTA, 0));
    program.push((PHY + R_TXPWR_RSTA, B_TXPWR_RSTA, B_TXPWR_RSTA));
    program.push((PHY + R_TXPWR_RSTB, B_TXPWR_RSTB, 0));
    program.push((PHY + R_TXPWR_RSTB, B_TXPWR_RSTB, B_TXPWR_RSTB));
    Some(program)
}

/// Complete both source ctrl_ch gain sub-legs from actual retained BE gain
/// tables and the factory RF logical map. This is a pure program; it does not
/// install a channel/calibration receipt or bypass the separate help/RFK owner.
pub(super) fn set_channel_bb_program_with_gain(
    profile: Profile,
    gain: &super::radio_gain_be::Gain,
    calibration: &super::factory_be::Calibration,
) -> Option<Vec<ProgramEntry>> {
    let original = set_channel_bb_program(profile)?;
    let mut out = Vec::new();
    let ctrl = if profile.band() == Band::Ghz2 { 2 } else { 0 };
    out.extend_from_slice(&original[..ctrl]);
    for (address, mask, value) in gain.channel_program(profile).ok()? {
        out.push((PHY + address, mask, pos(mask, value)));
    }
    // Source set_gain(A/B) precedes band-select(A/B), then factory normal
    // RX gain(A/B), followed by FC0/SCO and the rest of the same BB program.
    out.extend_from_slice(&original[ctrl..ctrl + 2]);
    for (address, mask, value) in calibration.rx_gain_program(profile) {
        out.push((PHY + address, mask, pos(mask, value)));
    }
    out.extend_from_slice(&original[ctrl + 2..]);
    Some(out)
}

pub(super) fn program_set_channel_bb_with_gain(
    regs: &mut impl Regs,
    profile: Profile,
    gain: &super::radio_gain_be::Gain,
    calibration: &super::factory_be::Calibration,
) -> Result<(), rfk::Error> {
    let program =
        set_channel_bb_program_with_gain(profile, gain, calibration).ok_or(rfk::Error::Policy)?;
    for &(address, mask, value) in &program {
        apply_entry(regs, address, mask, value)?;
    }
    verify_program(regs, &program)
}

/// Read back the final state of a program whose addresses
/// repeat: entries are folded per address (later and
/// overlapping writes win, as on hardware — the
/// `rtw8922a_tssi_reset` 0 -> 1 pulse folds to 1) and each
/// address is read once. Same folding as
/// `channel_c::verify`, in this file's positioned-value
/// convention.
fn verify_program(regs: &mut impl Regs, program: &[ProgramEntry]) -> Result<(), rfk::Error> {
    let mut known: Vec<(u32, u32, u32)> = Vec::new();
    for &(address, mask, value) in program {
        let bits = value & mask;
        match known.iter_mut().find(|entry| entry.0 == address) {
            Some(entry) => {
                entry.1 |= mask;
                entry.2 = (entry.2 & !mask) | bits;
            }
            None => known.push((address, mask, bits)),
        }
    }
    for (address, mask, expected) in known {
        let actual = regs.read32(address)?;
        if actual == u32::MAX || actual & mask != expected {
            return Err(power::Error::Access.into());
        }
    }
    Ok(())
}

/// Build the `rtw8922a_set_channel_bb` program for `profile`
/// and apply it, read back, over the BAR2 register port.
/// `Err(Policy)` when the program cannot be built for the
/// profile; `Err(Register(..))` on a register failure (a
/// partially applied program is left behind — the caller
/// records no channel and retries from the top).
pub(super) fn program_set_channel_bb(
    regs: &mut impl Regs,
    profile: Profile,
) -> Result<(), rfk::Error> {
    let program = set_channel_bb_program(profile).ok_or(rfk::Error::Policy)?;
    for &(address, mask, value) in &program {
        apply_entry(regs, address, mask, value)?;
    }
    verify_program(regs, &program)
}

// ── `rtw8922a_set_channel_rf` (rtw8922a_rfk.c:103) ────────────────
//
// `rtw8922a_set_channel_rf` is `rtw8922a_ctl_band_ch_bw`
// (rtw8922a_rfk.c:35..101): read the RF `RR_CFGCH` words on both
// paths, clear the band/BW/channel fields, OR in the
// `rtw8922a_chan_to_rf18_val` word, write both words back on both
// paths with a 100 us sleep after each write, then — on CHIP_CAV
// only — the path-A LUT writes. The RF transport is async
// (`rfk::Interface`), so this leg is an async owner function,
// not part of the sync `program_set_channel_*` pair above.

/// `RR_CFGCH` (`reg.h:8603`): the indirect RF config word.
const RR_CFGCH: u32 = 0x18;
/// `RR_CFGCH_V1` (`reg.h:8604`): the direct RF config word.
const RR_CFGCH_V1: u32 = 0x10018;
/// `RR_CFGCH_BAND1` (`reg.h:8605`): GENMASK(17, 16).
const RR_CFGCH_BAND1: u32 = 0x3_0000;
/// `RR_CFGCH_BW_V2` (`reg.h:8617`): GENMASK(12, 10).
const RR_CFGCH_BW_V2: u32 = 0x1c00;
/// `RR_CFGCH_BAND0` (`reg.h:8613`): GENMASK(9, 8).
const RR_CFGCH_BAND0: u32 = 0x0300;
/// `RR_CFGCH_CH` (`reg.h:8624`): GENMASK(7, 0).
const RR_CFGCH_CH: u32 = 0x00ff;
/// `RFREG_MASK` (`core.h:48`): the 20-bit RF register mask.
const RFREG_MASK: u32 = 0xf_ffff;
/// `INV_RF_DATA`: a failed RF read (channel_rf/regs.rs).
const INV_RF_DATA: u32 = 0xffff_ffff;
/// `RR_LUTWE` (`reg.h:8830`).
const RR_LUTWE: u32 = 0xef;
/// `RR_LUTWA` (`reg.h:8649`).
const RR_LUTWA: u32 = 0x33;
/// `RR_LUTWD1` (`reg.h:8653`).
const RR_LUTWD1: u32 = 0x3e;
/// `RR_LUTWD0` (`reg.h:8654`).
const RR_LUTWD0: u32 = 0x3f;
/// `CHIP_CAV` (`core.h:202`, `enum rtw89_chip_cv`): cut A.
/// The RF LUT tail runs on CAV only; `chip_version` is the
/// retained `hal->cv` (`Prepared8922a::chip_version`).
const CHIP_CAV: u8 = 0;
/// The two RF config addresses, in Linux's read/write order.
const RF_ADDR: [u32; 2] = [RR_CFGCH, RR_CFGCH_V1];
/// `fsleep(100)` after each CFGCH write (rtw8922a_rfk.c:82), in us.
const CFGCH_SLEEP_US: u64 = 100;

/// The `rtw8922a_chan_to_rf18_val` word
/// (rtw8922a.c:2680..2714) for `profile`: the center channel in
/// `RR_CFGCH_CH`, the band bits (`CFGCH_BAND1_5G`/`BAND0_5G` =
/// 1/1, `CFGCH_BAND1_6G`/`BAND0_6G` = 3/0, `reg.h:8607..8616`),
/// and the bandwidth bits in `RR_CFGCH_BW_V2`
/// (`CFGCH_BW_V2_40M/80M/160M` = 1/2/3, `reg.h:8619..8621`).
/// `None` for 320 MHz (Linux encodes 4, but no 8922A channel
/// reaches the RF leg at 320 MHz: the MAC leg refuses it and no
/// station can hold it).
pub(super) fn set_channel_rf_value(profile: Profile) -> Option<u32> {
    let mut value = u32::from(profile.center());
    value |= match profile.band() {
        Band::Ghz2 => 0,
        Band::Ghz5 => pos(RR_CFGCH_BAND1, 1) | pos(RR_CFGCH_BAND0, 1),
        Band::Ghz6 => pos(RR_CFGCH_BAND1, 3),
    };
    value |= match profile.width() {
        Width::Mhz20 => 0,
        Width::Mhz40 => pos(RR_CFGCH_BW_V2, 1),
        Width::Mhz80 => pos(RR_CFGCH_BW_V2, 2),
        Width::Mhz160 => pos(RR_CFGCH_BW_V2, 3),
        Width::Mhz320 => return None,
    };
    Some(value)
}

/// Async RF access for the BE channel RF leg: admit before
/// every access (the `channel_rf::Access` pattern), raw RF
/// words (an `INV_RF_DATA` read is returned to the caller,
/// which checks it where Linux checks it — not mapped here).
struct RfAccess<'a, I>(&'a mut I);

impl<I: rfk::Interface> RfAccess<'_, I> {
    async fn read(&mut self, path: u8, address: u32) -> Result<u32, rfk::Error> {
        self.0.admit()?;
        self.0.rf_read(path, address, RFREG_MASK).await
    }
    async fn write(&mut self, path: u8, address: u32, value: u32) -> Result<(), rfk::Error> {
        self.0.admit()?;
        self.0.rf_write(path, address, RFREG_MASK, value).await
    }
    async fn delay(&mut self, us: u64) -> Result<(), rfk::Error> {
        self.0.admit()?;
        self.0.delay_us(us).await;
        self.0.admit()
    }
}

/// Program `rtw8922a_set_channel_rf` for `profile` on PHY_0
/// without DBCC (`kpath` RF_AB, `synpath` RF_PATH_A — the
/// non-MLO `default:` arms of `rtw89_phy_get_kpath` /
/// `rtw89_phy_get_syn_sel`, phy.c:8884..8952): read both CFGCH
/// words on both paths, read the syn-path word (an `INV_RF_DATA`
/// there refuses before any write), then per (path, register)
/// check the stored word for `INV_RF_DATA`, clear the
/// band/BW/channel fields, OR in the RF word, write it back,
/// and sleep 100 us. On CHIP_CAV (`chip_version == 0`) only,
/// the path-A LUT tail follows (2.4 GHz `RR_LUTWD1` 0x0c990,
/// 5/6 GHz 0x0c190). The written CFGCH words are read back.
/// `Err(Policy)` for 320 MHz; `Err(Register(Gone))` on an
/// `INV_RF_DATA` word; `Err(Register(Access))` on a read-back
/// mismatch. A failure part-way leaves Linux's partial writes
/// behind; a retry re-programs from the top.
///
/// # Safety
/// Actual RTL8922A PHY_0 with completed BE tables and RFK init,
/// inside the channel-help window, with exclusive radio
/// ownership and a current channel grant for `profile`.
/// `chip_version` is the retained `hal->cv`.
pub(super) async unsafe fn program_set_channel_rf(
    io: &mut impl rfk::Interface,
    profile: Profile,
    chip_version: u8,
) -> Result<(), rfk::Error> {
    let value = set_channel_rf_value(profile).ok_or(rfk::Error::Policy)?;
    let mut access = RfAccess(io);
    let mut stored = [[0u32; 2]; 2];
    for path in 0..2u8 {
        for (i, address) in RF_ADDR.into_iter().enumerate() {
            stored[path as usize][i] = access.read(path, address).await?;
        }
    }
    if access.read(0, RR_CFGCH).await? == INV_RF_DATA {
        return Err(power::Error::Gone.into());
    }
    const CLEAR: u32 = RR_CFGCH_BAND1 | RR_CFGCH_BW_V2 | RR_CFGCH_BAND0 | RR_CFGCH_CH;
    for path in 0..2u8 {
        for (i, address) in RF_ADDR.into_iter().enumerate() {
            let old = stored[path as usize][i];
            if old == INV_RF_DATA {
                return Err(power::Error::Gone.into());
            }
            let new = (old & !CLEAR) | value;
            stored[path as usize][i] = new;
            access.write(path, address, new).await?;
            access.delay(CFGCH_SLEEP_US).await?;
        }
    }
    if chip_version == CHIP_CAV {
        // CAV-only LUT tail (rtw8922a_rfk.c:87..101), path A.
        let lutwd1 = if profile.band() == Band::Ghz2 {
            0x0c990
        } else {
            0x0c190
        };
        for (address, word) in [
            (RR_LUTWE, 0x80000),
            (RR_LUTWA, 0x00003),
            (RR_LUTWD1, lutwd1),
            (RR_LUTWD0, 0xebe38),
            (RR_LUTWE, 0x00000),
        ] {
            access.write(0, address, word).await?;
        }
    }
    for path in 0..2u8 {
        for (i, address) in RF_ADDR.into_iter().enumerate() {
            let actual = access.read(path, address).await?;
            if actual == INV_RF_DATA {
                return Err(power::Error::Gone.into());
            }
            if actual != stored[path as usize][i] {
                return Err(power::Error::Access.into());
            }
        }
    }
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "channel_be_tests.rs"]
mod tests;
