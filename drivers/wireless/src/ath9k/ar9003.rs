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
//! here: a chip without a complete native station path is never claimed.
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

pub(super) mod board;
pub(super) mod calib;
pub(super) mod edma;
pub(super) mod eeprom;
pub(super) mod ini;
pub(super) mod initvals;
pub(super) mod irq;
pub(super) mod mac;
pub(super) mod packet;
pub(super) mod phy;
pub(super) mod power;
pub(super) mod templates;

use super::identity::{BringUpError, RegisterIo};

/// `reg.h::AR_SREV_VERSION_9300`.
pub(super) const AR_SREV_VERSION_9300: u32 = 0x1c0;
/// `reg.h::AR_SREV_REVISION_9300_22`.
pub(super) const AR_SREV_REVISION_9300_22: u8 = 3;

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
}

impl Chip {
    /// `pci.c::ath_pci_id_table` device IDs of this generation.
    pub fn for_device(device: u16) -> Option<Self> {
        match device {
            0x0030 => Some(Self::Ar9300),
            _ => None,
        }
    }

    pub fn mac_version(self) -> u32 {
        match self {
            Self::Ar9300 => AR_SREV_VERSION_9300,
        }
    }

    /// `ath9k_hw_fill_cap_info`'s `chip_chainmask`.
    pub fn chip_chainmask(self) -> u8 {
        match self {
            Self::Ar9300 => 0x7,
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
    /// Only the macVersion of `expected` is accepted; the legacy format
    /// cannot carry an AR9003 version.
    pub fn decode(srev: u32, expected: Chip) -> Option<Self> {
        if srev == u32::MAX || srev & 0xff != 0xff {
            return None;
        }
        if (srev & 0xfffc_0000) >> 12 != expected.mac_version() {
            return None;
        }
        Some(Self {
            chip: expected,
            mac_rev: ((srev >> 8) & 0xf) as u8,
            pcie: srev & AR_SREV_TYPE2_HOST_MODE == 0,
        })
    }

    /// `AR_SREV_9300_22`.
    pub fn ar9300_22(&self) -> bool {
        self.chip == Chip::Ar9300 && self.mac_rev == AR_SREV_REVISION_9300_22
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
/// `AR_STA_ID1_PWR_SAV` clear.
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
    Ok(Identified {
        powered,
        restored,
        identity,
    })
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;
