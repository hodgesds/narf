// SPDX-License-Identifier: GPL-2.0-or-later
//! The AR9003 (EDMA) ath9k generation, kept separate from the AR5008/AR9002
//! profiles in `chips.rs` so their register traces stay byte-identical.
//!
//! This module is the identity foundation of `ar9300_enablement`
//! (AR9380/AR9390, PCIe `0x0030`): the `AR_SREV` decode and `AR_SREV_9300`
//! power-on sequence of `hw.c::__ath9k_hw_init`, the compressed
//! EEPROM/OTP restore of `ar9003_eeprom.c` and the `ar9003_hw.c` INI
//! selection, plus the `ar9003_phy.c` 20 MHz channel preparation with
//! `ath9k_hw_ar9300_set_board_values` and `ath9k_hw_ar9300_set_txpower`
//! (`phy`, `board`, `power`). No device is matched by `register()` from
//! here: `ar9300_owner` composes the native station path and registers
//! the device.
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

pub(super) mod board;
pub(super) mod btcoex;
pub(super) mod calib;
pub(super) mod edma;
pub(super) mod eeprom;
pub(super) mod ini;
pub(super) mod initvals;
pub(super) mod initvals_ar9462;
pub(super) mod initvals_ar9485;
pub(super) mod initvals_ar9565;
pub(super) mod initvals_ar9580;
pub(super) mod irq;
pub(super) mod mac;
pub(super) mod mci;
pub(super) mod packet;
pub(super) mod phy;
pub(super) mod power;
pub(super) mod templates;

use super::identity::{BringUpError, RegisterIo};

/// `hw.h::ATH9K_HW_CAP_MCI` (`BIT(15)`): the chip carries the MCI
/// Bluetooth-coexistence engine (AR9462/AR9565 unless the OTP
/// 4.9 GHz disable is set; see `fill_cap_info`).
pub(super) const HW_CAP_MCI: u32 = 1 << 15;
/// `reg.h::AR_ENT_OTP`: the OTP word holding the `ent_mode` bits.
pub(super) const AR_ENT_OTP: u64 = 0x40d8;
/// `reg.h::AR_ENT_OTP_49GHZ_DISABLE`: `ent_mode` bit clearing the MCI
/// capability.
pub(super) const AR_ENT_OTP_49GHZ_DISABLE: u32 = 0x0010_0000;
/// `reg.h::AR_SREV_VERSION_9300`.
pub(super) const AR_SREV_VERSION_9300: u32 = 0x1c0;
/// `reg.h::AR_SREV_REVISION_9300_22`.
pub(super) const AR_SREV_REVISION_9300_22: u8 = 3;
/// `reg.h::AR_SREV_VERSION_9580`: the AR9580 shares the AR9300 macVersion.
pub(super) const AR_SREV_VERSION_9580: u32 = 0x1c0;
/// `reg.h::AR_SREV_VERSION_9462`: the AR9462 has its own macVersion, so
/// no macRev split against the AR9300/AR9580 is needed.
pub(super) const AR_SREV_VERSION_9462: u32 = 0x280;
/// `reg.h::AR_SREV_REVISION_9462_20` (2.0 tables).
pub(super) const AR_SREV_REVISION_9462_20: u8 = 2;
/// `reg.h::AR_SREV_REVISION_9462_21` (2.1 tables).
pub(super) const AR_SREV_REVISION_9462_21: u8 = 3;
/// `reg.h::AR_SREV_VERSION_9565`: the AR9565 has its own macVersion, so
/// no macRev split against the AR9300/AR9580 is needed.
pub(super) const AR_SREV_VERSION_9565: u32 = 0x2c0;
/// `reg.h::AR_SREV_REVISION_9565_11` (1.1 tables).
pub(super) const AR_SREV_REVISION_9565_11: u8 = 2;
/// `reg.h::AR_SREV_REVISION_9580_10`: `AR_SREV_9580` is macRev >= 4.
pub(super) const AR_SREV_REVISION_9580_10: u8 = 4;
/// `reg.h::AR_SREV_VERSION_9485`.
pub(super) const AR_SREV_VERSION_9485: u32 = 0x240;
/// `reg.h::AR_SREV_REVISION_9485_11`: `AR_SREV_9485_11_OR_LATER` is
/// macRev >= 1; no 1.0 tables exist anywhere in the Linux ath9k tree.
pub(super) const AR_SREV_REVISION_9485_11: u8 = 1;

const AR_CFG: u64 = 0x0014;
const AR_CFG_HALT_REQ: u32 = 0x0800;
const AR_CFG_HALT_ACK: u32 = 0x1000;
const AR_RC: u64 = 0x4000;
const AR_WA: u64 = 0x4004;
const AR_WA_D3_L1_DISABLE: u32 = 1 << 14;
const AR_WA_ASPM_TIMER_BASED_DISABLE: u32 = 1 << 17;
const AR_SREV: u64 = 0x4020;
const AR_SREV_TYPE2_HOST_MODE: u32 = 0x2000;
const AR_INTR_SYNC_CAUSE: u64 = 0x4028;
const AR_INTR_SYNC_ENABLE: u64 = 0x402c;
const AR_INTR_SYNC_TIMEOUTS: u32 = 0x2000 | 0x1000;
const AR_RC_HOSTIF: u32 = 0x0100;
const AR_RTC_RC: u64 = 0x7000;
const AR_RTC_RESET: u64 = 0x7040;
const AR_RTC_STATUS: u64 = 0x7044;
const AR_RTC_STATUS_ON: u32 = 2;
const AR_RTC_STATUS_SHUTDOWN: u32 = 1;
const AR_RTC_FORCE_WAKE: u64 = 0x704c;
const AR_RTC_FORCE_WAKE_EN: u32 = 1;
const AR_RTC_FORCE_WAKE_ON_INT: u32 = 2;
const AR_RTC_PLL_CONTROL: u64 = 0x7014;
const AR_RTC_SLEEP_CLK: u64 = 0x7048;
const AR_RTC_FORCE_DERIVED_CLK: u32 = 0x2;
const AR_RTC_RESET_EN: u32 = 0x1;
/// `hw.h::RTC_PLL_SETTLE_DELAY` (µs).
const RTC_PLL_SETTLE_DELAY: u64 = 100;
const AR_STA_ID1: u64 = 0x8004;
const AR_STA_ID1_PWR_SAV: u32 = 0x0004_0000;
const AR_PHY_CHIP_ID: u64 = 0x9818;
/// `hw.h::AH_WAIT_TIMEOUT` (µs).
const AH_WAIT_TIMEOUT: u64 = 100_000;
/// `hw.h::POWER_UP_TIME` (µs).
const POWER_UP_TIME: u32 = 10_000;

/// The AR9003 parts this generation module knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Chip {
    /// AR9380/AR9390 PCIe (`0x0030`, `hw.h::AR9300_DEVID_PCIE`): three
    /// chains (`hw.c::ath9k_hw_fill_cap_info` chip_chainmask 7).
    Ar9300,
    /// AR9580 PCIe (`0x0033`, `hw.h::AR9300_DEVID_AR9580`): three chains.
    /// Linux tells it from an AR9300 only by `AR_SREV_9580` (macVersion
    /// 0x1c0, macRev >= `AR_SREV_REVISION_9580_10`); `AR_SREV_9300` is
    /// true for it as well, so every AR9300 branch keyed on the macVersion
    /// applies, and only the `ar9003_hw.c` INI/gain selection (checked for
    /// `AR_SREV_9580` before the AR9300 default) differs.
    Ar9580,
    /// AR9462 PCIe (`0x0034`, `hw.h::AR9300_DEVID_AR9462`): two chains
    /// (`hw.c::ath9k_hw_fill_cap_info` chip_chainmask 3). Unlike the
    /// AR9580 it has its own macVersion (`AR_SREV_VERSION_9462` 0x280),
    /// so no macRev split against the AR9300 is needed; shipped silicon
    /// is 2.0 (`AR_SREV_REVISION_9462_20`) and 2.1
    /// (`AR_SREV_REVISION_9462_21`) only — the 1.0 tables were removed
    /// from Linux as unavailable silicon.
    Ar9462,
    /// AR9565 PCIe (`0x0036`, `hw.h::AR9300_DEVID_AR9565`): one chain
    /// (`hw.c::ath9k_hw_fill_cap_info` chip_chainmask 1, grouped with
    /// the AR9485/AR9285/AR9330). It has its own macVersion
    /// (`AR_SREV_VERSION_9565` 0x2c0), so no macRev split against the
    /// AR9300 is needed; shipped silicon is 1.0 (macRev 0), 1.0.1
    /// (macRev 1) and 1.1 (macRev 2, `AR_SREV_REVISION_9565_11`) — the
    /// 1.1 tables own only the radio postamble, the rest aliases 1.0.
    Ar9565,
    /// AR9485 PCIe (`0x0032`, `hw.h::AR9300_DEVID_AR9485_PCIE`) and
    /// AR1111 (`0x0037`, `hw.h::AR9485_DEVID_AR1111`): one chain. Linux
    /// keys everything off `AR_SREV_9485` (macVersion 0x240), so one
    /// variant covers both device IDs; the `ar9485_1_1` INI set is the
    /// `AR_SREV_9485_11_OR_LATER` branch's.
    Ar9485,
}

impl Chip {
    /// `pci.c::ath_pci_id_table` device IDs of this generation.
    pub fn for_device(device: u16) -> Option<Self> {
        match device {
            0x0030 => Some(Self::Ar9300),
            0x0033 => Some(Self::Ar9580),
            0x0034 => Some(Self::Ar9462),
            0x0036 => Some(Self::Ar9565),
            0x0032 | 0x0037 => Some(Self::Ar9485),
            _ => None,
        }
    }

    pub fn mac_version(self) -> u32 {
        match self {
            Self::Ar9300 => AR_SREV_VERSION_9300,
            Self::Ar9580 => AR_SREV_VERSION_9580,
            Self::Ar9462 => AR_SREV_VERSION_9462,
            Self::Ar9565 => AR_SREV_VERSION_9565,
            Self::Ar9485 => AR_SREV_VERSION_9485,
        }
    }

    /// The part name used in logs and record labels.
    pub fn name(self) -> &'static str {
        match self {
            Self::Ar9300 => "AR9300",
            Self::Ar9580 => "AR9580",
            Self::Ar9462 => "AR9462",
            Self::Ar9565 => "AR9565",
            Self::Ar9485 => "AR9485",
        }
    }

    /// `ath9k_hw_fill_cap_info`'s `chip_chainmask`.
    pub fn chip_chainmask(self) -> u8 {
        match self {
            Self::Ar9300 | Self::Ar9580 => 0x7,
            Self::Ar9462 => 0x3,
            Self::Ar9565 => 0x1,
            Self::Ar9485 => 0x1,
        }
    }
}

/// The decoded `AR_SREV` facts of an AR9003 part.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Revision {
    pub chip: Chip,
    pub mac_rev: u8,
    /// `ah->is_pciexpress`: `AR_SREV_TYPE2_HOST_MODE` clear.
    pub pcie: bool,
}

impl Revision {
    /// `hw.c::ath9k_hw_read_revisions` for the `AR_SREV_ID == 0xff` format
    /// (`(srev & AR_SREV_VERSION2) >> AR_SREV_TYPE2_S`, `AR_SREV_REVISION2`).
    /// Only the silicon of `expected` is accepted; the legacy format
    /// cannot carry an AR9003 version. macVersion 0x1c0 is an AR9580 from
    /// macRev `AR_SREV_REVISION_9580_10` on (`AR_SREV_9580`), so an AR9300
    /// requires a lower macRev and an AR9580 at least that one: Linux would
    /// silently run the other chip's tables on a mismatched device ID.
    /// An AR9462 (macVersion 0x280) is accepted only at macRev 2 (2.0) or
    /// 3 (2.1): no 1.0 tables exist in Linux anymore. An AR9565
    /// (macVersion 0x2c0) carries no macRev restriction: Linux's 9565
    /// branches cover every macRev — `AR_SREV_9565_11_OR_LATER`
    /// (macRev >= 2) selects the 1.1 set, anything else the 1.0 set —
    /// so shipped 1.0 (macRev 0), 1.0.1 (macRev 1) and 1.1 (macRev 2)
    /// silicon is all accepted, with the 1.1 set from macRev 2 on.
    /// macVersion 0x240 is an AR9485 only from macRev
    /// `AR_SREV_REVISION_9485_11` on (`AR_SREV_9485_11_OR_LATER`); 1.0
    /// has no Linux tables and is refused.
    pub fn decode(srev: u32, expected: Chip) -> Option<Self> {
        if srev == u32::MAX || srev & 0xff != 0xff {
            return None;
        }
        if (srev & 0xfffc_0000) >> 12 != expected.mac_version() {
            return None;
        }
        let mac_rev = ((srev >> 8) & 0xf) as u8;
        if expected == Chip::Ar9462
            && mac_rev != AR_SREV_REVISION_9462_20
            && mac_rev != AR_SREV_REVISION_9462_21
        {
            return None;
        }
        let ar9580 = mac_rev >= AR_SREV_REVISION_9580_10;
        if ar9580 != (expected == Chip::Ar9580) {
            return None;
        }
        if expected == Chip::Ar9485 && mac_rev < AR_SREV_REVISION_9485_11 {
            return None;
        }
        Some(Self {
            chip: expected,
            mac_rev,
            pcie: srev & AR_SREV_TYPE2_HOST_MODE == 0,
        })
    }

    /// `AR_SREV_9300_22`.
    pub fn ar9300_22(&self) -> bool {
        self.chip == Chip::Ar9300 && self.mac_rev == AR_SREV_REVISION_9300_22
    }

    /// `AR_SREV_9580`.
    pub fn ar9580(&self) -> bool {
        self.chip == Chip::Ar9580
    }

    /// `AR_SREV_9462_21`.
    pub fn ar9462_21(&self) -> bool {
        self.chip == Chip::Ar9462 && self.mac_rev == AR_SREV_REVISION_9462_21
    }

    /// `AR_SREV_9565_11_OR_LATER`.
    pub fn ar9565_11_or_later(&self) -> bool {
        self.chip == Chip::Ar9565 && self.mac_rev >= AR_SREV_REVISION_9565_11
    }
    /// `AR_SREV_9485_11_OR_LATER` (`decode` guarantees macRev >= 1).
    pub fn ar9485_11(&self) -> bool {
        self.chip == Chip::Ar9485
    }
}

/// The facts `__ath9k_hw_init` establishes before the EEPROM is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PoweredOn {
    pub revision: Revision,
    /// `ah->WARegVal`: `AR_WA` with `AR_WA_D3_L1_DISABLE` and
    /// `AR_WA_ASPM_TIMER_BASED_DISABLE` set.
    pub wa: u32,
    /// `ah->hw_version.phyRev` (`AR_PHY_CHIP_ID`).
    pub phy_rev: u32,
}

/// `REG_RMW(ah, register, set, clear)`: always one read and one write.
pub(super) fn rmw(
    io: &mut impl RegisterIo,
    register: u64,
    clear: u32,
    set: u32,
) -> Result<(), BringUpError> {
    let value = io.read32(register);
    if value == u32::MAX || !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    io.write32(register, (value & !clear) | set);
    Ok(())
}

/// `REG_RMW_FIELD`: `((value << shift) & mask)` under `mask`.
pub(super) fn field(
    io: &mut impl RegisterIo,
    register: u64,
    mask: u32,
    shift: u32,
    value: u32,
) -> Result<(), BringUpError> {
    rmw(io, register, mask, value.wrapping_shl(shift) & mask)
}

fn wa_write(io: &mut impl RegisterIo, wa: u32) {
    io.write32(AR_WA, wa);
    io.delay_us(10);
}

/// `hw.c::ath9k_hw_set_reset` for an AR9300: `AR_WA`, force wake, the
/// AR9300 `AR_RC_HOSTIF` recovery after a local/RADM timeout (no
/// `AR_RC_AHB`), the AR9300/AR9580 DMA halt around the `AR_RTC_RC` write,
/// 50 µs, and `AR_RTC_RC` release.
pub(super) fn set_reset(io: &mut impl RegisterIo, wa: u32, cold: bool) -> Result<(), BringUpError> {
    wa_write(io, wa);
    io.write32(
        AR_RTC_FORCE_WAKE,
        AR_RTC_FORCE_WAKE_EN | AR_RTC_FORCE_WAKE_ON_INT,
    );
    let cause = io.read32(AR_INTR_SYNC_CAUSE);
    if cause == u32::MAX {
        return Err(BringUpError::DeviceGone);
    }
    if cause & AR_INTR_SYNC_TIMEOUTS != 0 {
        io.write32(AR_INTR_SYNC_ENABLE, 0);
        io.write32(AR_RC, AR_RC_HOSTIF);
    }
    let cfg = io.read32(AR_CFG);
    if cfg == u32::MAX {
        return Err(BringUpError::DeviceGone);
    }
    io.write32(AR_CFG, cfg | AR_CFG_HALT_REQ);
    // Linux ignores a missing HALT_ACK and proceeds with the reset.
    if let Err(BringUpError::DeviceGone) = io.wait_us(
        AR_CFG,
        AR_CFG_HALT_ACK,
        AR_CFG_HALT_ACK,
        20 * AH_WAIT_TIMEOUT,
    ) {
        return Err(BringUpError::DeviceGone);
    }
    let cfg = io.read32(AR_CFG);
    if cfg == u32::MAX {
        return Err(BringUpError::DeviceGone);
    }
    io.write32(AR_CFG, cfg & !AR_CFG_HALT_REQ);
    io.write32(AR_RTC_RC, if cold { 3 } else { 1 });
    io.delay_us(50);
    io.write32(AR_RTC_RC, 0);
    io.wait_us(AR_RTC_RC, 3, 0, AH_WAIT_TIMEOUT)?;
    io.write32(AR_RC, 0);
    Ok(())
}

/// `hw.c::ath9k_hw_set_reset_reg(ATH9K_RESET_COLD | ATH9K_RESET_WARM)`
/// once `ah->reset_power_on` holds (after `identify`): `AR_WA`, force wake,
/// then `ath9k_hw_set_reset`.
pub(super) fn reset_reg(io: &mut impl RegisterIo, wa: u32, cold: bool) -> Result<(), BringUpError> {
    wa_write(io, wa);
    io.write32(
        AR_RTC_FORCE_WAKE,
        AR_RTC_FORCE_WAKE_EN | AR_RTC_FORCE_WAKE_ON_INT,
    );
    set_reset(io, wa, cold)
}

/// `AR_SREV` decoded for `expected` (`ath9k_hw_read_revisions`).
pub(super) fn revision(io: &mut impl RegisterIo, expected: Chip) -> Result<Revision, BringUpError> {
    let srev = io.read32(AR_SREV);
    if srev == u32::MAX || !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    Revision::decode(srev, expected).ok_or(BringUpError::UnsupportedRevision)
}

/// `hw.c::ath9k_hw_init_pll(ah, NULL)` for an AR9300:
/// `ar9003_hw_compute_pll_control` (REFDIV 5, DIV 0x2c), the
/// `RTC_PLL_SETTLE_DELAY` and `AR_RTC_FORCE_DERIVED_CLK`.
fn init_pll(io: &mut impl RegisterIo) {
    io.write32(AR_RTC_PLL_CONTROL, (5 << 10) | 0x2c);
    io.delay_us(RTC_PLL_SETTLE_DELAY);
    io.write32(AR_RTC_SLEEP_CLK, AR_RTC_FORCE_DERIVED_CLK);
}

/// `hw.c::ath9k_set_power_sleep` for an AR9300 without MCI: set
/// `AR_STA_ID1_PWR_SAV`, clear `AR_RTC_FORCE_WAKE_EN` (no `AR_RC` write
/// on `AR_SREV_9300_20_OR_LATER`), clear `AR_RTC_RESET_EN` (active-low
/// shutdown) and write `AR_WA` without `AR_WA_D3_L1_DISABLE`.
fn full_sleep(io: &mut impl RegisterIo, wa: u32) -> Result<(), BringUpError> {
    rmw(io, AR_STA_ID1, 0, AR_STA_ID1_PWR_SAV)?;
    rmw(io, AR_RTC_FORCE_WAKE, AR_RTC_FORCE_WAKE_EN, 0)?;
    rmw(io, AR_RTC_RESET, AR_RTC_RESET_EN, 0)?;
    io.delay_us(2);
    io.write32(AR_WA, wa & !AR_WA_D3_L1_DISABLE);
    Ok(())
}

/// `pci.c::ath_pci_suspend` on an awake AR9300: `ath9k_hw_disable` (its
/// `ath9k_hw_setpower(AWAKE)` is a no-op on an awake chip, then the COLD
/// `ath9k_hw_set_reset_reg` and `ath9k_hw_init_pll`) followed by
/// `ath9k_hw_setpower(ATH9K_PM_FULL_SLEEP)`.
pub(super) fn disable_and_sleep(io: &mut impl RegisterIo, wa: u32) -> Result<(), BringUpError> {
    reset_reg(io, wa, true)?;
    init_pll(io);
    full_sleep(io, wa)?;
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    Ok(())
}

/// `hw.c::ath9k_hw_set_reset_reg(ATH9K_RESET_POWER_ON)` →
/// `ath9k_hw_set_reset_power_on` for an AR9300 (no `AR_RC_AHB` toggles),
/// finished by the WARM `ath9k_hw_set_reset`.
pub(super) fn power_on(io: &mut impl RegisterIo, wa: u32) -> Result<(), BringUpError> {
    wa_write(io, wa);
    io.write32(
        AR_RTC_FORCE_WAKE,
        AR_RTC_FORCE_WAKE_EN | AR_RTC_FORCE_WAKE_ON_INT,
    );
    wa_write(io, wa);
    io.write32(
        AR_RTC_FORCE_WAKE,
        AR_RTC_FORCE_WAKE_EN | AR_RTC_FORCE_WAKE_ON_INT,
    );
    io.write32(AR_RTC_RESET, 0);
    io.delay_us(2);
    io.write32(AR_RTC_RESET, 1);
    io.wait_us(AR_RTC_STATUS, 0xf, AR_RTC_STATUS_ON, AH_WAIT_TIMEOUT)?;
    set_reset(io, wa, false)
}

/// `hw.c::ath9k_hw_set_power_awake` for an AR9300 (no MCI): `AR_WA`, a
/// power-on reset only when the RTC reports SHUTDOWN (the AR9003 path does
/// not reprogram the PLL here), force wake, the `POWER_UP_TIME / 50` poll and
/// `AR_STA_ID1_PWR_SAV` clear. (The MCI power-awake LNA workaround is
/// `mci::set_power_awake`.)
pub(super) fn set_power_awake(io: &mut impl RegisterIo, wa: u32) -> Result<(), BringUpError> {
    wa_write(io, wa);
    let status = io.read32(AR_RTC_STATUS);
    if status == u32::MAX {
        return Err(BringUpError::DeviceGone);
    }
    if status & 0xf == AR_RTC_STATUS_SHUTDOWN {
        power_on(io, wa)?;
    }
    force_wake(io)?;
    io.delay_us(50);
    let mut awake = false;
    for _ in 0..POWER_UP_TIME / 50 {
        let status = io.read32(AR_RTC_STATUS);
        if status == u32::MAX {
            return Err(BringUpError::DeviceGone);
        }
        if status & 0xf == AR_RTC_STATUS_ON {
            awake = true;
            break;
        }
        io.delay_us(50);
        force_wake(io)?;
    }
    if !awake {
        return Err(BringUpError::Timeout);
    }
    let sta = io.read32(AR_STA_ID1);
    if sta == u32::MAX {
        return Err(BringUpError::DeviceGone);
    }
    io.write32(AR_STA_ID1, sta & !AR_STA_ID1_PWR_SAV);
    Ok(())
}

fn force_wake(io: &mut impl RegisterIo) -> Result<(), BringUpError> {
    let value = io.read32(AR_RTC_FORCE_WAKE);
    if value == u32::MAX {
        return Err(BringUpError::DeviceGone);
    }
    io.write32(AR_RTC_FORCE_WAKE, value | AR_RTC_FORCE_WAKE_EN);
    Ok(())
}

/// `__ath9k_hw_init` up to `ath9k_hw_post_init` for an AR9003 part: the
/// revision is checked against `expected` before the first write, then
/// `AR_WA` is latched, the power-on reset runs, the chip is woken and
/// `AR_PHY_CHIP_ID` read. `ath9k_hw_disablepcie` is a no-op for every
/// non-AR5416 part, so a host-mode strap is only recorded.
pub(super) fn power_on_chip(
    io: &mut impl RegisterIo,
    expected: Chip,
) -> Result<PoweredOn, BringUpError> {
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    let srev = io.read32(AR_SREV);
    if srev == u32::MAX {
        return Err(BringUpError::DeviceGone);
    }
    let revision = Revision::decode(srev, expected).ok_or(BringUpError::UnsupportedRevision)?;
    let wa = io.read32(AR_WA);
    if wa == u32::MAX {
        return Err(BringUpError::DeviceGone);
    }
    let wa = wa | AR_WA_D3_L1_DISABLE | AR_WA_ASPM_TIMER_BASED_DISABLE;
    power_on(io, wa)?;
    set_power_awake(io, wa)?;
    let phy_rev = io.read32(AR_PHY_CHIP_ID);
    if phy_rev == u32::MAX || !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    Ok(PoweredOn {
        revision,
        wa,
        phy_rev,
    })
}

/// A complete AR9003 identification: power-on facts, the restored map and
/// the identity decoded from it.
#[derive(Debug)]
pub(super) struct Identified {
    pub powered: PoweredOn,
    pub restored: eeprom::Restored,
    pub identity: eeprom::Identity,
    /// The `AR_ENT_OTP` word (`hw.c::ath9k_hw_fill_cap_info`).
    pub ent_mode: u32,
    /// The capability word from `fill_cap_info` (so far only
    /// `HW_CAP_MCI`).
    pub hw_caps: u32,
}

/// `hw.c::ath9k_hw_fill_cap_info`'s MCI capability, as a pure function
/// for testing: AR9462/AR9565 carry MCI unless `ent_mode` has the OTP
/// 4.9 GHz disable set. (Linux also reads `ent_mode` as `0x3BDA000`
/// for the AR9561, which has no in-tree variant.)
pub(super) fn fill_cap_info(chip: Chip, ent_mode: u32) -> u32 {
    let mut hw_caps = 0u32;
    if (chip == Chip::Ar9462 || chip == Chip::Ar9565) && ent_mode & AR_ENT_OTP_49GHZ_DISABLE == 0 {
        hw_caps |= HW_CAP_MCI;
    }
    hw_caps
}

/// `ath9k_hw_init` for an AR9003 PCI device: device/silicon match before
/// any write, `power_on_chip`, then `ath9k_hw_eeprom_init`
/// (`ar9300_eeprom_restore_internal`) and the `ath9k_hw_fill_cap_info`
/// chain masks. Nothing is admitted by this.
pub(super) fn identify(io: &mut impl RegisterIo, device: u16) -> Result<Identified, BringUpError> {
    let chip = Chip::for_device(device).ok_or(BringUpError::UnsupportedRevision)?;
    let powered = power_on_chip(io, chip)?;
    let restored = eeprom::restore(&mut eeprom::Nvram::new(io), eeprom::Limits::for_chip(chip))?;
    let identity = eeprom::Identity::decode(chip, &restored)?;
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    // Every in-tree AR9003 part satisfies `AR_SREV_9300_20_OR_LATER`
    // (macVersion >= 0x1c0), so `ent_mode` is the `AR_ENT_OTP` word.
    let ent_mode = io.read32(AR_ENT_OTP);
    let hw_caps = fill_cap_info(chip, ent_mode);
    Ok(Identified {
        powered,
        restored,
        identity,
        ent_mode,
        hw_caps,
    })
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;
