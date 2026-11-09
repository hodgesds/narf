// SPDX-License-Identifier: GPL-2.0-or-later
//! `ar9003_hw.c::ar9003_hw_init_mode_regs` + `ar9003_hw_init_mode_gain_regs`
//! for the AR9300: the 2p2 MAC/BB/radio/SoC core and postamble arrays, the
//! PCIe SerDes, fast clock, Japan 2484 CCK FIR and DFS tables, then the TX
//! and RX gain tables the EEPROM `txrxgain` nibbles select. The AR9580
//! (`AR_SREV_9580`) takes the `ar9580_1p0_initvals.h` set instead, and the
//! AR9462 (`AR_SREV_9462`) the `ar9462_2p0`/`ar9462_2p1` set (2.1 owns only
//! its MAC core, baseband postamble and SoC preamble; the rest aliases
//! 2.0). The AR9565 (`AR_SREV_9565`) takes the `ar9565_1p0`/
//! `ar9565_1p1` set (1.1 owns only its radio postamble; the rest aliases
//! 1.0).
//! AR9485 (`AR_SREV_9485_11_OR_LATER`) the `ar9485_1_1` set.

use super::initvals::*;
use super::initvals_ar9462::*;
use super::initvals_ar9485::*;
use super::initvals_ar9565::*;
use super::initvals_ar9580::*;
use super::{eeprom::Identity, serdes::PllPwrsave, Chip, Revision};

/// Which `ar9003_tx_gain_table_mode*` table applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) enum TxGain {
    LowestObDb,
    HighObDb,
    LowObDb,
    HighPower,
    MixedObDb,
    Type5,
    /// `ar9580_1p0_type6_tx_gain_table` (AR9580 only).
    Type6,
    /// `ar9485Modes_green_ob_db_tx_gain_1_1` (AR9485 only).
    GreenObDb,
    /// `ar9485Modes_green_spur_ob_db_tx_gain_1_1` (AR9485 only).
    GreenSpurObDb,
}

/// Which `ar9003_rx_gain_table_mode*` table applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) enum RxGain {
    Common,
    WithoutXlna,
    /// `ar9462_2p0_common_mixed_rx_gain` (AR9462 mode 2, CUS217 mix LNA),
    /// plus the mix baseband core/postamble overrides and the 5G-XLNA
    /// array below.
    Mixed,
    /// `ar9462_2p0_common_5g_xlna_only_rxgain` (AR9462 mode 3, an alias of
    /// the mixed table) plus the 5G-XLNA array below.
    FiveGXlnaOnly,
}

/// The arrays `ah->ini*` point at after `ar9003_hw_init_mode_regs` and
/// `ar9003_hw_init_mode_gain_regs` for an AR9300.
#[derive(Clone, Copy, Debug)]
pub(in crate::ath9k) struct Tables {
    pub mac_core: &'static [[u32; 2]],
    pub mac_post: &'static [[u32; 5]],
    /// The BB pre array (`ar9485_1_1`): only the AR9485 programs one.
    pub bb_pre: &'static [[u32; 2]],
    pub bb_core: &'static [[u32; 2]],
    pub bb_post: &'static [[u32; 5]],
    pub radio_core: &'static [[u32; 2]],
    pub radio_post: &'static [[u32; 5]],
    /// `ar9003_phy.c` programs this at `ATH_INI_POST` only for
    /// `AR_SREV_9462_20_OR_LATER` (`ini_radio_post_sys2ant`); empty for
    /// the AR9300/AR9580, which Linux does not program it for.
    pub radio_post_sys2ant: &'static [[u32; 5]],
    /// The allmodes radio postamble (`ar9485_1_1_radio_postamble`): only
    /// the AR9485 programs one; the five-column `radio_post` is empty
    /// for it.
    pub radio_post_allmodes: &'static [[u32; 2]],
    pub soc_pre: &'static [[u32; 2]],
    pub soc_post: &'static [[u32; 5]],
    pub rx_gain: &'static [[u32; 2]],
    pub tx_gain: &'static [[u32; 5]],
    /// `ar9003_phy.c` writes these RX-gain overrides after the main INI
    /// arrays, only for AR9462 RX modes 2 (baseband core at column 1 and
    /// postamble at the modes column) and 2/3 (XLNA array at the modes
    /// column); empty for every other chip and mode.
    pub rxgain_bb_core: &'static [[u32; 2]],
    pub rxgain_bb_postamble: &'static [[u32; 5]],
    pub rxgain_xlna: &'static [[u32; 5]],
    pub pcie_serdes: &'static [[u32; 2]],
    pub pcie_serdes_low_power: &'static [[u32; 2]],
    pub fast_clock: &'static [[u32; 3]],
    pub cck_fir_japan_2484: &'static [[u32; 2]],
    pub dfs: &'static [[u32; 3]],
    pub tx_gain_kind: TxGain,
    pub rx_gain_kind: RxGain,
}

impl Tables {
    /// `ar9003_hw_init_mode_regs` + `ar9003_hw_init_mode_gain_regs` for
    /// the decoded silicon: `AR_SREV_9580` is tested before the AR9300
    /// default branch. `pll_pwrsave` is `__ath9k_hw_init`'s resolved
    /// `ah->config.pll_pwrsave`; it selects the PCIe SerDes arrays
    /// (see `super::serdes`): the AR9485 table swap and the
    /// AR9462/AR9565 slot presence. The AR9300's SerDes table is
    /// unconditional and the AR9580 has none, so neither reads it.
    pub fn for_revision(revision: &Revision, identity: &Identity, pll_pwrsave: PllPwrsave) -> Self {
        match revision.chip {
            Chip::Ar9300 => Self::ar9300(revision, identity),
            Chip::Ar9580 => Self::ar9580(identity),
            Chip::Ar9462 => Self::ar9462(revision, identity, pll_pwrsave),
            Chip::Ar9565 => Self::ar9565(revision, identity, pll_pwrsave),
            Chip::Ar9485 => Self::ar9485(identity, pll_pwrsave),
        }
    }

    /// `ar9003_hw_init_mode_regs`' AR9300 (final `else`) branch, then
    /// `ar9003_tx_gain_table_apply` (index `>= 8` is mode 0; modes 6/7 have
    /// no AR9300 table and mode 5 only `AR_SREV_9300_22`, so those keep the
    /// lowest-ob/db default; `tx_gain_buffalo` is never set in Linux) and
    /// `ar9003_rx_gain_table_apply` (modes 2/3 are AR9462-only and keep the
    /// common default).
    pub fn ar9300(revision: &Revision, identity: &Identity) -> Self {
        let (tx_gain, tx_gain_kind) = match identity.tx_gain {
            1 => (AR9300_MODES_HIGH_OB_DB_TX_GAIN_TABLE_2P2, TxGain::HighObDb),
            2 => (AR9300_MODES_LOW_OB_DB_TX_GAIN_TABLE_2P2, TxGain::LowObDb),
            3 => (AR9300_MODES_HIGH_POWER_TX_GAIN_TABLE_2P2, TxGain::HighPower),
            4 => (
                AR9300_MODES_MIXED_OB_DB_TX_GAIN_TABLE_2P2,
                TxGain::MixedObDb,
            ),
            5 if revision.ar9300_22() => (AR9300_MODES_TYPE5_TX_GAIN_TABLE_2P2, TxGain::Type5),
            _ => (
                AR9300_MODES_LOWEST_OB_DB_TX_GAIN_TABLE_2P2,
                TxGain::LowestObDb,
            ),
        };
        let (rx_gain, rx_gain_kind) = match identity.rx_gain {
            1 => (AR9300_COMMON_WO_XLNA_RX_GAIN_TABLE_2P2, RxGain::WithoutXlna),
            _ => (AR9300_COMMON_RX_GAIN_TABLE_2P2, RxGain::Common),
        };
        Self {
            mac_core: AR9300_2P2_MAC_CORE,
            mac_post: AR9300_2P2_MAC_POSTAMBLE,
            bb_pre: &[],
            bb_core: AR9300_2P2_BASEBAND_CORE,
            bb_post: AR9300_2P2_BASEBAND_POSTAMBLE,
            radio_core: AR9300_2P2_RADIO_CORE,
            radio_post: AR9300_2P2_RADIO_POSTAMBLE,
            radio_post_sys2ant: &[],
            radio_post_allmodes: &[],
            soc_pre: AR9300_2P2_SOC_PREAMBLE,
            soc_post: AR9300_2P2_SOC_POSTAMBLE,
            rx_gain,
            tx_gain,
            rxgain_bb_core: &[],
            rxgain_bb_postamble: &[],
            rxgain_xlna: &[],
            pcie_serdes: AR9300_PCIE_PHY_PLL_ON_CLKREQ_DISABLE_L1_2P2,
            pcie_serdes_low_power: AR9300_PCIE_PHY_PLL_ON_CLKREQ_DISABLE_L1_2P2,
            fast_clock: AR9300_MODES_FAST_CLOCK_2P2,
            cck_fir_japan_2484: AR9300_2P2_BASEBAND_CORE_TXFIR_COEFF_JAPAN_2484,
            dfs: AR9300_2P2_BASEBAND_POSTAMBLE_DFS_CHANNEL,
            tx_gain_kind,
            rx_gain_kind,
        }
    }

    /// `ar9003_hw_init_mode_regs`' `AR_SREV_9580` branch (no PCIe SerDes
    /// arrays: `iniPcieSerdes`/`iniPcieSerdesLowPower` stay empty; RX
    /// `ar9580_1p0_rx_gain_table`, TX `ar9580_1p0_low_ob_db_tx_gain_table`
    /// as the defaults), then `ar9003_tx_gain_table_apply` (index `>= 8`
    /// is mode 0; every mode 0..6 has an `AR_SREV_9580` table, mode 7 has
    /// none and keeps the low-ob/db default; `AR_SREV_9300_22` is false
    /// for macRev >= 4) and `ar9003_rx_gain_table_apply` (mode 1 is
    /// `ar9580_1p0_wo_xlna_rx_gain_table`; modes 2/3 are AR9462-only and
    /// keep the default).
    pub fn ar9580(identity: &Identity) -> Self {
        let (tx_gain, tx_gain_kind) = match identity.tx_gain {
            1 => (AR9580_1P0_HIGH_OB_DB_TX_GAIN_TABLE, TxGain::HighObDb),
            2 => (AR9580_1P0_LOW_OB_DB_TX_GAIN_TABLE, TxGain::LowObDb),
            3 => (AR9580_1P0_HIGH_POWER_TX_GAIN_TABLE, TxGain::HighPower),
            4 => (AR9580_1P0_MIXED_OB_DB_TX_GAIN_TABLE, TxGain::MixedObDb),
            5 => (AR9580_1P0_TYPE5_TX_GAIN_TABLE, TxGain::Type5),
            6 => (AR9580_1P0_TYPE6_TX_GAIN_TABLE, TxGain::Type6),
            7 => (AR9580_1P0_LOW_OB_DB_TX_GAIN_TABLE, TxGain::LowObDb),
            _ => (AR9580_1P0_LOWEST_OB_DB_TX_GAIN_TABLE, TxGain::LowestObDb),
        };
        let (rx_gain, rx_gain_kind) = match identity.rx_gain {
            1 => (AR9580_1P0_WO_XLNA_RX_GAIN_TABLE, RxGain::WithoutXlna),
            _ => (AR9580_1P0_RX_GAIN_TABLE, RxGain::Common),
        };
        Self {
            mac_core: AR9580_1P0_MAC_CORE,
            mac_post: AR9580_1P0_MAC_POSTAMBLE,
            bb_pre: &[],
            bb_core: AR9580_1P0_BASEBAND_CORE,
            bb_post: AR9580_1P0_BASEBAND_POSTAMBLE,
            radio_core: AR9580_1P0_RADIO_CORE,
            radio_post: AR9580_1P0_RADIO_POSTAMBLE,
            radio_post_sys2ant: &[],
            radio_post_allmodes: &[],
            soc_pre: AR9580_1P0_SOC_PREAMBLE,
            soc_post: AR9580_1P0_SOC_POSTAMBLE,
            rx_gain,
            tx_gain,
            rxgain_bb_core: &[],
            rxgain_bb_postamble: &[],
            rxgain_xlna: &[],
            pcie_serdes: &[],
            pcie_serdes_low_power: &[],
            fast_clock: AR9580_1P0_MODES_FAST_CLOCK,
            cck_fir_japan_2484: AR9580_1P0_BASEBAND_CORE_TXFIR_COEFF_JAPAN_2484,
            dfs: AR9580_1P0_BASEBAND_POSTAMBLE_DFS_CHANNEL,
            tx_gain_kind,
            rx_gain_kind,
        }
    }

    /// `ar9003_hw_init_mode_regs`' `AR_SREV_9462_21` (2.1) and
    /// `AR_SREV_9462_20` (2.0) branches, then `ar9003_tx_gain_table_apply`
    /// (index `>= 8` is mode 0; modes 2 and 3 have no AR9462 table and
    /// fall through to the AR9300 2p2 low-ob/db and high-power tables;
    /// modes 5/6/7 have no table at all and keep the mode-0 low-ob/db
    /// default) and `ar9003_rx_gain_table_apply` (mode 1 is the AR9300
    /// 2p2 wo-XLNA table; mode 2 is the mixed table with the mix
    /// baseband core/postamble overrides and the 5G-XLNA array; mode 3
    /// is the 5G-XLNA-only table — an alias of the mixed table — with
    /// the 5G-XLNA array; index `>= 4` keeps the common default).
    /// Linux sets no `ini_dfs` for the AR9462, so `dfs` stays empty.
    /// The PCIe SerDes slots are the `pciephy_clkreq_disable_L1`
    /// table only when `pll_pwrsave` enables them (awake on
    /// `CONTROL + ON_D3`, low-power on `CONTROL + ON_D0`); with the resolved
    /// default 7 both are set.
    pub fn ar9462(revision: &Revision, identity: &Identity, pll_pwrsave: PllPwrsave) -> Self {
        // 2.1 owns only its MAC core, baseband postamble and SoC
        // preamble; every other 2.1 name aliases the 2.0 table. The
        // branch names the 2.1 tables throughout, as the Linux 2.1
        // branch does, so every `2P1` constant is used.
        let (
            mac_core,
            mac_post,
            bb_core,
            bb_post,
            radio_core,
            radio_post,
            radio_post_sys2ant,
            soc_pre,
            soc_post,
            common_rx,
            wo_rx,
            mixed_rx,
            xlna_only_rx,
            low_tx,
            high_tx,
            mix_tx,
            mix_core,
            mix_post,
            xlna,
            fast_clock,
            txfir,
        ) = if revision.ar9462_21() {
            (
                AR9462_2P1_MAC_CORE,
                AR9462_2P1_MAC_POSTAMBLE,
                AR9462_2P1_BASEBAND_CORE,
                AR9462_2P1_BASEBAND_POSTAMBLE,
                AR9462_2P1_RADIO_CORE,
                AR9462_2P1_RADIO_POSTAMBLE,
                AR9462_2P1_RADIO_POSTAMBLE_SYS2ANT,
                AR9462_2P1_SOC_PREAMBLE,
                AR9462_2P1_SOC_POSTAMBLE,
                AR9462_2P1_COMMON_RX_GAIN,
                AR9462_2P1_COMMON_WO_XLNA_RX_GAIN,
                AR9462_2P1_COMMON_MIXED_RX_GAIN,
                AR9462_2P1_COMMON_5G_XLNA_ONLY_RXGAIN,
                AR9462_2P1_MODES_LOW_OB_DB_TX_GAIN,
                AR9462_2P1_MODES_HIGH_OB_DB_TX_GAIN,
                AR9462_2P1_MODES_MIX_OB_DB_TX_GAIN,
                AR9462_2P1_BASEBAND_CORE_MIX_RXGAIN,
                AR9462_2P1_BASEBAND_POSTAMBLE_MIX_RXGAIN,
                AR9462_2P1_BASEBAND_POSTAMBLE_5G_XLNA,
                AR9462_2P1_MODES_FAST_CLOCK,
                AR9462_2P1_BASEBAND_CORE_TXFIR_COEFF_JAPAN_2484,
            )
        } else {
            (
                AR9462_2P0_MAC_CORE,
                AR9462_2P0_MAC_POSTAMBLE,
                AR9462_2P0_BASEBAND_CORE,
                AR9462_2P0_BASEBAND_POSTAMBLE,
                AR9462_2P0_RADIO_CORE,
                AR9462_2P0_RADIO_POSTAMBLE,
                AR9462_2P0_RADIO_POSTAMBLE_SYS2ANT,
                AR9462_2P0_SOC_PREAMBLE,
                AR9462_2P0_SOC_POSTAMBLE,
                AR9462_2P0_COMMON_RX_GAIN,
                AR9462_2P0_COMMON_WO_XLNA_RX_GAIN,
                AR9462_2P0_COMMON_MIXED_RX_GAIN,
                AR9462_2P0_COMMON_5G_XLNA_ONLY_RXGAIN,
                AR9462_2P0_MODES_LOW_OB_DB_TX_GAIN,
                AR9462_2P0_MODES_HIGH_OB_DB_TX_GAIN,
                AR9462_2P0_MODES_MIX_OB_DB_TX_GAIN,
                AR9462_2P0_BASEBAND_CORE_MIX_RXGAIN,
                AR9462_2P0_BASEBAND_POSTAMBLE_MIX_RXGAIN,
                AR9462_2P0_BASEBAND_POSTAMBLE_5G_XLNA,
                AR9462_2P0_MODES_FAST_CLOCK,
                AR9462_2P0_BASEBAND_CORE_TXFIR_COEFF_JAPAN_2484,
            )
        };
        // The SerDes slots are the `pciephy_clkreq_disable_L1` table
        // only when `pll_pwrsave` enables them (awake on CONTROL +
        // ON_D3, low-power on CONTROL + ON_D0); with the resolved
        // default 7 both are set, with 0 both stay unset. The 2.1
        // table `#define`-aliases the 2.0 table, so the revision only
        // picks which name is spelled.
        let serdes_table = if revision.ar9462_21() {
            AR9462_2P1_PCIEPHY_CLKREQ_DISABLE_L1
        } else {
            AR9462_2P0_PCIEPHY_CLKREQ_DISABLE_L1
        };
        let (serdes, serdes_low_power) = (
            if pll_pwrsave.control() && pll_pwrsave.on_d3() {
                serdes_table
            } else {
                &[][..]
            },
            if pll_pwrsave.control() && pll_pwrsave.on_d0() {
                serdes_table
            } else {
                &[][..]
            },
        );
        let (tx_gain, tx_gain_kind) = match identity.tx_gain {
            1 => (high_tx, TxGain::HighObDb),
            2 => (AR9300_MODES_LOW_OB_DB_TX_GAIN_TABLE_2P2, TxGain::LowObDb),
            3 => (AR9300_MODES_HIGH_POWER_TX_GAIN_TABLE_2P2, TxGain::HighPower),
            4 => (mix_tx, TxGain::MixedObDb),
            _ => (low_tx, TxGain::LowestObDb),
        };
        let (rx_gain, rx_gain_kind, rxgain_bb_core, rxgain_bb_postamble, rxgain_xlna) =
            match identity.rx_gain {
                1 => (wo_rx, RxGain::WithoutXlna, &[][..], &[][..], &[][..]),
                2 => (mixed_rx, RxGain::Mixed, mix_core, mix_post, xlna),
                3 => (xlna_only_rx, RxGain::FiveGXlnaOnly, &[][..], &[][..], xlna),
                _ => (common_rx, RxGain::Common, &[][..], &[][..], &[][..]),
            };
        Self {
            mac_core,
            mac_post,
            bb_pre: &[],
            bb_core,
            bb_post,
            radio_core,
            radio_post,
            radio_post_sys2ant,
            radio_post_allmodes: &[],
            soc_pre,
            soc_post,
            rx_gain,
            tx_gain,
            rxgain_bb_core,
            rxgain_bb_postamble,
            rxgain_xlna,
            pcie_serdes: serdes,
            pcie_serdes_low_power: serdes_low_power,
            fast_clock,
            cck_fir_japan_2484: txfir,
            dfs: &[],
            tx_gain_kind,
            rx_gain_kind,
        }
    }

    /// `ar9003_hw_init_mode_regs`' `AR_SREV_9565_11_OR_LATER` (1.1) and
    /// `AR_SREV_9565` (1.0) branches, then `ar9003_tx_gain_table_apply`
    /// (index `>= 8` is mode 0; modes 0/2 are the 9565 low-ob/db table,
    /// mode 1 the high-ob/db table, mode 3 the high-power table, mode 4
    /// falls through to the AR9300 2p2 mixed-ob/db table, and modes 5/6/7
    /// have no 9565 arm and no default, so they keep the mode-regs
    /// lowest-ob/db value — which is the low-ob/db table by `#define` —
    /// and the same low-ob/db table is the mode-0 selection) and
    /// `ar9003_rx_gain_table_apply` (mode 1 is the 9565 wo-XLNA table;
    /// modes 2/3 are AR9462-only and keep the common default). The 1.1
    /// set differs from 1.0 only in its radio postamble (every other 1.1
    /// name `#define`-aliases its 1.0 table), so only that array is
    /// selected on `ar9565_11_or_later`; the gain tables are the 1.0
    /// constants for both revisions. Linux sets no `ini_dfs` for the
    /// AR9565, so `dfs` stays empty. The PCIe SerDes slots are the
    /// `pciephy_clkreq_disable_L1` table only when `pll_pwrsave`
    /// enables them (awake on CONTROL + ON_D3, low-power on CONTROL
    /// + ON_D0); with the resolved default 7 both are set.
    pub fn ar9565(revision: &Revision, identity: &Identity, pll_pwrsave: PllPwrsave) -> Self {
        let radio_post = if revision.ar9565_11_or_later() {
            AR9565_1P1_RADIO_POSTAMBLE
        } else {
            AR9565_1P0_RADIO_POSTAMBLE
        };
        let (tx_gain, tx_gain_kind) = match identity.tx_gain {
            1 => (AR9565_1P0_MODES_HIGH_OB_DB_TX_GAIN_TABLE, TxGain::HighObDb),
            2 => (AR9565_1P0_MODES_LOW_OB_DB_TX_GAIN_TABLE, TxGain::LowObDb),
            3 => (AR9565_1P0_MODES_HIGH_POWER_TX_GAIN_TABLE, TxGain::HighPower),
            4 => (
                AR9300_MODES_MIXED_OB_DB_TX_GAIN_TABLE_2P2,
                TxGain::MixedObDb,
            ),
            _ => (AR9565_1P0_MODES_LOW_OB_DB_TX_GAIN_TABLE, TxGain::LowObDb),
        };
        let (rx_gain, rx_gain_kind) = match identity.rx_gain {
            1 => (AR9565_1P0_COMMON_WO_XLNA_RX_GAIN_TABLE, RxGain::WithoutXlna),
            _ => (AR9565_1P0_COMMON_RX_GAIN_TABLE, RxGain::Common),
        };
        // Same SerDes gating as the AR9462: each slot is the
        // `pciephy_clkreq_disable_L1` table only when `pll_pwrsave`
        // enables it. The 1.1 table `#define`-aliases the 1.0 table.
        let (serdes, serdes_low_power) = (
            if pll_pwrsave.control() && pll_pwrsave.on_d3() {
                AR9565_1P0_PCIEPHY_CLKREQ_DISABLE_L1
            } else {
                &[][..]
            },
            if pll_pwrsave.control() && pll_pwrsave.on_d0() {
                AR9565_1P0_PCIEPHY_CLKREQ_DISABLE_L1
            } else {
                &[][..]
            },
        );
        Self {
            mac_core: AR9565_1P0_MAC_CORE,
            mac_post: AR9565_1P0_MAC_POSTAMBLE,
            bb_pre: &[],
            bb_core: AR9565_1P0_BASEBAND_CORE,
            bb_post: AR9565_1P0_BASEBAND_POSTAMBLE,
            radio_core: AR9565_1P0_RADIO_CORE,
            radio_post,
            radio_post_sys2ant: &[],
            radio_post_allmodes: &[],
            soc_pre: AR9565_1P0_SOC_PREAMBLE,
            soc_post: AR9565_1P0_SOC_POSTAMBLE,
            rx_gain,
            tx_gain,
            rxgain_bb_core: &[],
            rxgain_bb_postamble: &[],
            rxgain_xlna: &[],
            pcie_serdes: serdes,
            pcie_serdes_low_power: serdes_low_power,
            fast_clock: AR9565_1P0_MODES_FAST_CLOCK,
            cck_fir_japan_2484: AR9565_1P0_BASEBAND_CORE_TXFIR_COEFF_JAPAN_2484,
            dfs: &[],
            tx_gain_kind,
            rx_gain_kind,
        }
    }

    /// `ar9003_hw_init_mode_regs`' `AR_SREV_9485_11_OR_LATER` branch: the
    /// 1.1 MAC/BB/radio/SoC arrays (BB pre, allmodes radio postamble, no
    /// SoC postamble, no fast clock, no DFS), the Japan 2484 CCK FIR
    /// alias of the AR9300 2p2 table, and the SerDes tables selected on
    /// `pll_pwrsave`: CONTROL set programs the
    /// `pll_on_cdr_on_clkreq_disable_L1` table in both slots, CONTROL
    /// clear the `pcie_phy_clkreq_disable_L1` table. Then
    /// `ar9003_tx_gain_table_apply` (index `>= 8` is mode 0; mode 4 has
    /// no 9485 arm and falls through to the AR9300 2p2 mixed table; mode
    /// 7 sets nothing for non-9340, so it keeps the mode-0 lowest-ob/db
    /// default, which is the low-ob/db table) and
    /// `ar9003_rx_gain_table_apply` (mode 1 is the wo-XLNA table; modes
    /// 2/3 are AR9462-only and keep the wo-XLNA default; index `>= 4`
    /// keeps the common default).
    pub fn ar9485(identity: &Identity, pll_pwrsave: PllPwrsave) -> Self {
        let (tx_gain, tx_gain_kind) = match identity.tx_gain {
            1 => (AR9485MODES_HIGH_OB_DB_TX_GAIN_1_1, TxGain::HighObDb),
            2 => (AR9485MODES_LOW_OB_DB_TX_GAIN_1_1, TxGain::LowObDb),
            3 => (AR9485MODES_HIGH_POWER_TX_GAIN_1_1, TxGain::HighPower),
            4 => (
                AR9300_MODES_MIXED_OB_DB_TX_GAIN_TABLE_2P2,
                TxGain::MixedObDb,
            ),
            5 => (AR9485MODES_GREEN_OB_DB_TX_GAIN_1_1, TxGain::GreenObDb),
            6 => (
                AR9485MODES_GREEN_SPUR_OB_DB_TX_GAIN_1_1,
                TxGain::GreenSpurObDb,
            ),
            _ => (AR9485MODES_LOW_OB_DB_TX_GAIN_1_1, TxGain::LowestObDb),
        };
        let (rx_gain, rx_gain_kind) = match identity.rx_gain {
            1..=3 => (AR9485COMMON_WO_XLNA_RX_GAIN_1_1, RxGain::WithoutXlna),
            _ => (AR9485_COMMON_RX_GAIN_1_1, RxGain::Common),
        };
        // SerDes selection on `pll_pwrsave`: CONTROL set is the
        // `pll_on_cdr_on` table in both slots (the resolved default
        // for a plain AR9485 card), CONTROL clear the `clkreq` table
        // (the `ATH9K_PCI_NO_PLL_PWRSAVE` subsystems).
        let (serdes, serdes_low_power) = if pll_pwrsave.control() {
            (
                AR9485_1_1_PLL_ON_CDR_ON_CLKREQ_DISABLE_L1,
                AR9485_1_1_PLL_ON_CDR_ON_CLKREQ_DISABLE_L1,
            )
        } else {
            (
                AR9485_1_1_PCIE_PHY_CLKREQ_DISABLE_L1,
                AR9485_1_1_PCIE_PHY_CLKREQ_DISABLE_L1,
            )
        };
        Self {
            mac_core: AR9485_1_1_MAC_CORE,
            mac_post: AR9485_1_1_MAC_POSTAMBLE,
            bb_pre: AR9485_1_1,
            bb_core: AR9485_1_1_BASEBAND_CORE,
            bb_post: AR9485_1_1_BASEBAND_POSTAMBLE,
            radio_core: AR9485_1_1_RADIO_CORE,
            radio_post: &[],
            radio_post_sys2ant: &[],
            radio_post_allmodes: AR9485_1_1_RADIO_POSTAMBLE,
            soc_pre: AR9485_1_1_SOC_PREAMBLE,
            soc_post: &[],
            rx_gain,
            tx_gain,
            rxgain_bb_core: &[],
            rxgain_bb_postamble: &[],
            rxgain_xlna: &[],
            pcie_serdes: serdes,
            pcie_serdes_low_power: serdes_low_power,
            fast_clock: &[],
            cck_fir_japan_2484: AR9300_2P2_BASEBAND_CORE_TXFIR_COEFF_JAPAN_2484,
            dfs: &[],
            tx_gain_kind,
            rx_gain_kind,
        }
    }
}
