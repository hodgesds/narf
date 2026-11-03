// SPDX-License-Identifier: GPL-2.0-or-later
//! `ar9003_hw.c::ar9003_hw_init_mode_regs` + `ar9003_hw_init_mode_gain_regs`
//! for the AR9300: the 2p2 MAC/BB/radio/SoC core and postamble arrays, the
//! PCIe SerDes, fast clock, Japan 2484 CCK FIR and DFS tables, then the TX
//! and RX gain tables the EEPROM `txrxgain` nibbles select.

use super::initvals::*;
use super::{eeprom::Identity, Revision};

/// Which `ar9003_tx_gain_table_mode*` table applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) enum TxGain {
    LowestObDb,
    HighObDb,
    LowObDb,
    HighPower,
    MixedObDb,
    Type5,
}

/// Which `ar9003_rx_gain_table_mode*` table applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) enum RxGain {
    Common,
    WithoutXlna,
}

/// The arrays `ah->ini*` point at after `ar9003_hw_init_mode_regs` and
/// `ar9003_hw_init_mode_gain_regs` for an AR9300.
#[derive(Clone, Copy, Debug)]
pub(in crate::ath9k) struct Tables {
    pub mac_core: &'static [[u32; 2]],
    pub mac_post: &'static [[u32; 5]],
    pub bb_core: &'static [[u32; 2]],
    pub bb_post: &'static [[u32; 5]],
    pub radio_core: &'static [[u32; 2]],
    pub radio_post: &'static [[u32; 5]],
    pub soc_pre: &'static [[u32; 2]],
    pub soc_post: &'static [[u32; 5]],
    pub rx_gain: &'static [[u32; 2]],
    pub tx_gain: &'static [[u32; 5]],
    pub pcie_serdes: &'static [[u32; 2]],
    pub pcie_serdes_low_power: &'static [[u32; 2]],
    pub fast_clock: &'static [[u32; 3]],
    pub cck_fir_japan_2484: &'static [[u32; 2]],
    pub dfs: &'static [[u32; 3]],
    pub tx_gain_kind: TxGain,
    pub rx_gain_kind: RxGain,
}

impl Tables {
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
            bb_core: AR9300_2P2_BASEBAND_CORE,
            bb_post: AR9300_2P2_BASEBAND_POSTAMBLE,
            radio_core: AR9300_2P2_RADIO_CORE,
            radio_post: AR9300_2P2_RADIO_POSTAMBLE,
            soc_pre: AR9300_2P2_SOC_PREAMBLE,
            soc_post: AR9300_2P2_SOC_POSTAMBLE,
            rx_gain,
            tx_gain,
            pcie_serdes: AR9300_PCIE_PHY_PLL_ON_CLKREQ_DISABLE_L1_2P2,
            pcie_serdes_low_power: AR9300_PCIE_PHY_PLL_ON_CLKREQ_DISABLE_L1_2P2,
            fast_clock: AR9300_MODES_FAST_CLOCK_2P2,
            cck_fir_japan_2484: AR9300_2P2_BASEBAND_CORE_TXFIR_COEFF_JAPAN_2484,
            dfs: AR9300_2P2_BASEBAND_POSTAMBLE_DFS_CHANNEL,
            tx_gain_kind,
            rx_gain_kind,
        }
    }
}
