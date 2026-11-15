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
//!    (`set_channel_mac_program`, rtw8922a.c:1048..1145) only.
//! 3. `chip->ops->set_txpwr` (`rtw8922a_set_txpwr`,
//!    rtw8922a.c:2540) — driven by
//!    `Prepared8922a::set_channel` immediately after the MAC
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
//! - `rtw8922a_set_channel_bb` (rtw8922a.c:2179..2198):
//!   `ctrl_sco_cck` (:1149), `ctrl_ch` (:1490), `ctrl_bw`
//!   (:1529), `ctrl_cck_en` (:2163), `spur_elimination` (:1718),
//!   the `R_RSTB_ASYNC` write and the `rtw8922a_tssi_reset`
//!   pulse (:1961).
//! - `rtw8922a_set_channel_rf` (rtw8922a_rfk.c:103).
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
//! AFTER the MAC program leaves the MAC registers on the new
//! channel with the old power program: the owner records no
//! channel, so a retry re-programs the MAC idempotently before
//! retrying power (see `Prepared8922a::set_channel`).

use super::eht::{
    self, ProgramEntry, Width as EhtWidth, B_BE_SIFS_MACTXEN_T1_MASK, B_BE_SIFS_MACTXEN_TB_T1_MASK,
    B_BE_WMAC_RFMOD_MASK, R_BE_MUEDCA_EN, R_BE_PREBKF_CFG_1, R_BE_TX_SUB_BAND_VALUE,
    R_BE_WMAC_RFMOD,
};
use super::irq::Regs;
use super::operating_channel_c::{Band, Profile, Width};
use super::{power, rfk};

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

#[cfg(any(test, feature = "kernel-test"))]
#[path = "channel_be_tests.rs"]
mod tests;
