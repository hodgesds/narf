// SPDX-License-Identifier: GPL-2.0-or-later
//! PCIe SerDes power-save for the AR9003 family: `hw.c`'s
//! `ah->config.pll_pwrsave` resolution, `ar9003_hw.c`'s
//! `ar9003_hw_init_mode_regs` SerDes selection on it, and
//! `ar9003_hw_configpcipowersave` (`ath9k_start`'s "Reset SERDES
//! registers" and `ath9k_stop`'s park).
//!
//! `pll_pwrsave` is a bitfield (`hw.h::AR_PCIE_PLL_PWRSAVE_*`):
//! CONTROL (bit 0) gates the SerDes power-save programming, ON_D3
//! (bit 1) the awake→sleep array and ON_D0 (bit 2) the sleep→awake
//! array. `init.c::ath9k_init_pcoem_platform` defaults it to 1 and
//! clears it to 0 for the `ATH9K_PCI_NO_PLL_PWRSAVE` AR9485
//! subsystems; `hw.c::ath9k_hw_init_config` then forces it to 7 for
//! AR9462/AR9565 — after the platform default, before
//! `ar9003_hw_attach_ops` runs `ar9003_hw_init_mode_regs`, so the
//! selection below sees the final value.
//!
//! Selection (`ar9003_hw_init_mode_regs`, Linux @ cbbddb6):
//! - AR9300: both slots unconditionally the
//!   `ar9300PciePhy_pll_on_clkreq_disable_L1_2p2` table (no
//!   `pll_pwrsave` gate); AR9580: no SerDes arrays at all.
//! - AR9485: CONTROL set programs the
//!   `ar9485_1_1_pll_on_cdr_on_clkreq_disable_L1` table in both slots,
//!   CONTROL clear the `ar9485_1_1_pcie_phy_clkreq_disable_L1` table.
//! - AR9462/AR9565: each slot is the `pciephy_clkreq_disable_L1` table
//!   only when CONTROL and its ON_D3 (awake) / ON_D0 (low-power) bit
//!   are both set, and stays unset (empty) otherwise; there is no
//!   `pll_on_cdr_on` table for either chip.
//!
//! Programming (`ar9003_hw_configpcipowersave(ah, power_off)`): the
//! AR9462 L1-entry-latency fix (`0x570c`, from the PCI config `0x70c`
//! word `ath_pci_aspm_init` reads), then on restore only
//! `AR_PCIE_PM_CTRL_ENA` (`0x4014` bit 19) and the latched `AR_WA`
//! word, then the selected array as plain register writes — the
//! awake array when powering off, the low-power array on restore.
//! Nothing here is ASPM-gated (Linux calls it unconditionally from
//! `ath9k_start`; the resume call in `pci.c` is the ASPM-gated one
//! and is subsumed by the start call on this owner's resume path).
//! The SerDes rows (`0x18c00/0x18c04/0x18c08`) are disjoint from every
//! INI array `phy::prepare` programs, so this step never disturbs a
//! preparation or its admission facts.
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use super::{ini::Tables, rmw, Chip, Revision};
use crate::ath9k::identity::{BringUpError, RegisterIo};

/// `hw.h::AR_PCIE_PLL_PWRSAVE_CONTROL`.
const CONTROL: u8 = 0x1;
/// `hw.h::AR_PCIE_PLL_PWRSAVE_ON_D3`.
const ON_D3: u8 = 0x2;
/// `hw.h::AR_PCIE_PLL_PWRSAVE_ON_D0`.
const ON_D0: u8 = 0x4;

/// `reg.h::AR_PCIE_PM_CTRL` for a non-AR9340 part.
const AR_PCIE_PM_CTRL: u64 = 0x4014;
/// `reg.h::AR_PCIE_PM_CTRL_ENA` (bit 19, force the PCIe core into L1).
const AR_PCIE_PM_CTRL_ENA: u32 = 0x0008_0000;
/// `reg.h::AR_WA` for a non-AR9340 part.
const AR_WA: u64 = 0x4004;
/// The register `ar9003_hw_configpcipowersave` writes the AR9462
/// L1-entry-latency fix to.
const ASPM_L1_FIX_REG: u64 = 0x570c;

/// `pci.c::ath_pci_id_table`: the AR9485 (`0x0032`) subsystems whose
/// `driver_data` carries `ATH9K_PCI_NO_PLL_PWRSAVE` ("AR9485 cards
/// with PLL power-save disabled by default"), as
/// (subsystem vendor, subsystem device). Subvendor IDs are
/// `include/linux/pci_ids.h`: AZWAVE `0x1a3b`, ASKEY `0x1c56`/`0x144f`,
/// LITEON `0x11ad`, FOXCONN `0x105b`, XAVI `0x1b9a`, ASUSTEK `0x1043`.
/// No AR9462/AR9565/AR9580/AR1111 entry carries the flag, and no
/// AR9485 entry carries `ATH9K_PCI_WOW` (that flag is AR9462-only).
const NO_PLL_PWRSAVE: [(u16, u16); 17] = [
    (0x1a3b, 0x2c97),
    (0x1a3b, 0x2100),
    (0x1c56, 0x4001),
    (0x11ad, 0x6627),
    (0x11ad, 0x6628),
    (0x105b, 0xe04e),
    (0x105b, 0xe04f),
    (0x144f, 0x7197),
    (0x1b9a, 0x2000),
    (0x1b9a, 0x2001),
    (0x1a3b, 0x1186),
    (0x1a3b, 0x1f86),
    (0x1a3b, 0x1195),
    (0x1a3b, 0x1f95),
    (0x1b9a, 0x1c00),
    (0x1b9a, 0x1c01),
    (0x1043, 0x850d),
];

/// `ah->config.pll_pwrsave`: the resolved SerDes power-save bitfield.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct PllPwrsave(u8);

impl PllPwrsave {
    /// The `__ath9k_hw_init` resolution order: the platform default
    /// (1, or 0 for a `NO_PLL_PWRSAVE` AR9485 subsystem), then the
    /// `ath9k_hw_init_config` force to 7 for AR9462/AR9565. For the
    /// AR9300/AR9580 the value is resolved the same way but never
    /// selects anything (unconditional / no SerDes arrays).
    pub fn resolve(chip: Chip, subvendor: u16, subdevice: u16) -> Self {
        match chip {
            Chip::Ar9462 | Chip::Ar9565 => Self(CONTROL | ON_D3 | ON_D0),
            Chip::Ar9485 if NO_PLL_PWRSAVE.contains(&(subvendor, subdevice)) => Self(0),
            _ => Self(CONTROL),
        }
    }

    /// `AR_PCIE_PLL_PWRSAVE_CONTROL`: SerDes power-save programming
    /// is enabled at all.
    pub fn control(self) -> bool {
        self.0 & CONTROL != 0
    }

    /// `AR_PCIE_PLL_PWRSAVE_ON_D3`: the awake→sleep array is
    /// programmed (AR9462/AR9565 `iniPcieSerdes` slot).
    pub fn on_d3(self) -> bool {
        self.0 & ON_D3 != 0
    }

    /// `AR_PCIE_PLL_PWRSAVE_ON_D0`: the sleep→awake array is
    /// programmed (AR9462/AR9565 `iniPcieSerdesLowPower` slot).
    pub fn on_d0(self) -> bool {
        self.0 & ON_D0 != 0
    }

    /// The raw bitfield, for the selection matrix smoke.
    pub fn bits(self) -> u8 {
        self.0
    }

    /// Test-only construction from a raw bitfield (unknown bits are
    /// dropped); production code only ever sees `resolve`'s output.
    #[cfg(any(test, feature = "kernel-test"))]
    pub fn from_bits(bits: u8) -> Self {
        Self(bits & (CONTROL | ON_D3 | ON_D0))
    }
}

/// `ar9003_hw_configpcipowersave(ah, power_off)` for `revision`'s
/// selected `tables`: the AR9462 L1-entry-latency fix from the PCI
/// config `0x70c` word (`aspm_l1_fix`, 0 when the read failed or the
/// chip is not an AR9462), then on restore `AR_PCIE_PM_CTRL_ENA`
/// and the latched `wa` word, then the selected SerDes array — the
/// awake array when powering off, the low-power array on restore.
/// A revoked authority refuses before the first write.
pub(in crate::ath9k) fn configure(
    io: &mut impl RegisterIo,
    revision: &Revision,
    tables: &Tables,
    power_off: bool,
    wa: u32,
    aspm_l1_fix: u32,
) -> Result<(), BringUpError> {
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    if revision.chip == Chip::Ar9462 && (aspm_l1_fix & 0xff00_0000) == 0x1700_0000 {
        io.write32(ASPM_L1_FIX_REG, (aspm_l1_fix & 0x00ff_ffff) | 0x2700_0000);
    }
    if !power_off {
        rmw(io, AR_PCIE_PM_CTRL, 0, AR_PCIE_PM_CTRL_ENA)?;
        io.write32(AR_WA, wa);
    }
    let array = if power_off {
        tables.pcie_serdes
    } else {
        tables.pcie_serdes_low_power
    };
    for row in array {
        io.write32(u64::from(row[0]), row[1]);
    }
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::super::ini::{RxGain, Tables, TxGain};
    use super::*;
    use alloc::{collections::BTreeMap, vec, vec::Vec};
    use narf_kernel_test::{kernel_test_in, TestResult};

    #[derive(Debug, PartialEq, Eq)]
    enum Op {
        Read(u64),
        Write(u64, u32),
    }
    #[derive(Default)]
    struct Model {
        registers: BTreeMap<u64, u32>,
        ops: Vec<Op>,
        revoked: bool,
    }
    impl RegisterIo for Model {
        fn authorized(&self) -> bool {
            !self.revoked
        }
        fn read32(&mut self, offset: u64) -> u32 {
            self.ops.push(Op::Read(offset));
            *self.registers.get(&offset).unwrap_or(&0)
        }
        fn write32(&mut self, offset: u64, value: u32) {
            self.ops.push(Op::Write(offset, value));
            self.registers.insert(offset, value);
        }
        fn delay_us(&mut self, _us: u64) {}
    }

    fn make_tables(serdes: &'static [[u32; 2]], low_power: &'static [[u32; 2]]) -> Tables {
        Tables {
            mac_core: &[],
            mac_post: &[],
            bb_pre: &[],
            bb_core: &[],
            bb_post: &[],
            radio_core: &[],
            radio_post: &[],
            radio_post_sys2ant: &[],
            radio_post_allmodes: &[],
            soc_pre: &[],
            soc_post: &[],
            rx_gain: &[],
            tx_gain: &[],
            rxgain_bb_core: &[],
            rxgain_bb_postamble: &[],
            rxgain_xlna: &[],
            pcie_serdes: serdes,
            pcie_serdes_low_power: low_power,
            fast_clock: &[],
            cck_fir_japan_2484: &[],
            dfs: &[],
            tx_gain_kind: TxGain::LowestObDb,
            rx_gain_kind: RxGain::Common,
        }
    }

    fn smoke_ath9k_ar9003_serdes_pll_pwrsave_resolution() -> TestResult {
        // hw.c forces 7 for AR9462/AR9565 whatever the subsystem is.
        for chip in [Chip::Ar9462, Chip::Ar9565] {
            if PllPwrsave::resolve(chip, 0x1a3b, 0x2c97).bits() != 7
                || PllPwrsave::resolve(chip, 0, 0).bits() != 7
            {
                return TestResult::Fail("AR9462/AR9565 pll_pwrsave is not 7");
            }
        }
        // Every NO_PLL_PWRSAVE AR9485 subsystem resolves to 0; any
        // other AR9485 subsystem (and a bare device ID) to 1.
        for &(subvendor, subdevice) in &NO_PLL_PWRSAVE {
            if PllPwrsave::resolve(Chip::Ar9485, subvendor, subdevice).bits() != 0 {
                return TestResult::Fail("NO_PLL_PWRSAVE AR9485 subsystem not resolved to 0");
            }
        }
        if NO_PLL_PWRSAVE.len() != 17 {
            return TestResult::Fail("NO_PLL_PWRSAVE table lost a pci.c entry");
        }
        for (subvendor, subdevice) in [(0x1a3b, 0x2086), (0x168c, 0x3119), (0x10cf, 0x147c), (0, 0)]
        {
            if PllPwrsave::resolve(Chip::Ar9485, subvendor, subdevice).bits() != 1 {
                return TestResult::Fail("ordinary AR9485 pll_pwrsave is not 1");
            }
        }
        // The value is resolved the same way for the other chips but
        // never selects anything there.
        for chip in [Chip::Ar9300, Chip::Ar9580] {
            if PllPwrsave::resolve(chip, 0x1a3b, 0x2c97).bits() != 1 {
                return TestResult::Fail("AR9300/AR9580 pll_pwrsave is not the default 1");
            }
        }
        TestResult::Pass
    }

    fn smoke_ath9k_ar9003_serdes_configpcipowersave_sequence() -> TestResult {
        let revision = Revision {
            chip: Chip::Ar9462,
            mac_rev: 2,
            pcie: true,
        };
        let awake: &[[u32; 2]] = &[[0x0001_8c00, 0x1821_3ede], [0x0001_8c04, 0x0008_01d8]];
        let low: &[[u32; 2]] = &[[0x0001_8c00, 0x1801_265e], [0x0001_8c08, 0x0000_080c]];
        let tables = make_tables(awake, low);
        // Restore: the L1 fix (0x70c word 0x17xxxxxx), PM_CTRL_ENA,
        // the latched WA word, then the low-power array in order.
        let mut model = Model::default();
        model.registers.insert(AR_PCIE_PM_CTRL, 0x1234);
        if configure(
            &mut model,
            &revision,
            &tables,
            false,
            0x004a_05cb,
            0x1700_0011,
        )
        .is_err()
            || model.ops
                != vec![
                    Op::Write(ASPM_L1_FIX_REG, 0x2700_0011),
                    Op::Read(AR_PCIE_PM_CTRL),
                    Op::Write(AR_PCIE_PM_CTRL, 0x0008_1234),
                    Op::Write(AR_WA, 0x004a_05cb),
                    Op::Write(0x18c00, 0x1801_265e),
                    Op::Write(0x18c08, 0x0000_080c),
                ]
        {
            return TestResult::Fail("AR9462 restore SerDes sequence differs from ar9003_hw.c");
        }
        // Power-off: the L1 fix, then the awake array only — no
        // PM_CTRL/WA writes on the power-off path.
        model.ops.clear();
        if configure(
            &mut model,
            &revision,
            &tables,
            true,
            0x004a_05cb,
            0x1700_0011,
        )
        .is_err()
            || model.ops
                != vec![
                    Op::Write(ASPM_L1_FIX_REG, 0x2700_0011),
                    Op::Write(0x18c00, 0x1821_3ede),
                    Op::Write(0x18c04, 0x0008_01d8),
                ]
        {
            return TestResult::Fail("AR9462 power-off SerDes sequence differs from ar9003_hw.c");
        }
        // A 0x70c word outside the 0x17xxxxxx range writes nothing to
        // 0x570c, and a non-AR9462 chip never writes it either.
        model.ops.clear();
        if configure(
            &mut model,
            &revision,
            &tables,
            false,
            0x004a_05cb,
            0x2700_0011,
        )
        .is_err()
            || model
                .ops
                .iter()
                .any(|op| matches!(op, Op::Write(0x570c, _)))
        {
            return TestResult::Fail("L1 fix fired without the 0x17xxxxxx config word");
        }
        let other = Revision {
            chip: Chip::Ar9485,
            ..revision
        };
        model.ops.clear();
        if configure(&mut model, &other, &tables, false, 0x004a_05cb, 0x1700_0011).is_err()
            || model
                .ops
                .iter()
                .any(|op| matches!(op, Op::Write(0x570c, _)))
        {
            return TestResult::Fail("L1 fix fired for a non-AR9462 chip");
        }
        // Empty slots write nothing but still restore PM_CTRL/WA.
        let empty = make_tables(&[], &[]);
        model.ops.clear();
        model.registers.insert(AR_PCIE_PM_CTRL, 0);
        if configure(&mut model, &other, &empty, false, 0x004a_05cb, 0).is_err()
            || model.ops
                != vec![
                    Op::Read(AR_PCIE_PM_CTRL),
                    Op::Write(AR_PCIE_PM_CTRL, AR_PCIE_PM_CTRL_ENA),
                    Op::Write(AR_WA, 0x004a_05cb),
                ]
        {
            return TestResult::Fail("empty SerDes slots broke the restore path");
        }
        let mut revoked = Model {
            revoked: true,
            ..Model::default()
        };
        if configure(&mut revoked, &revision, &tables, false, 0, 0) != Err(BringUpError::DeviceGone)
            || !revoked.ops.is_empty()
        {
            return TestResult::Fail("revoked SerDes authority touched registers");
        }
        TestResult::Pass
    }

    kernel_test_in!(
        "drivers/wireless/ath9k/ar9003/serdes",
        smoke_ath9k_ar9003_serdes_pll_pwrsave_resolution
    );
    kernel_test_in!(
        "drivers/wireless/ath9k/ar9003/serdes",
        smoke_ath9k_ar9003_serdes_configpcipowersave_sequence
    );
}
