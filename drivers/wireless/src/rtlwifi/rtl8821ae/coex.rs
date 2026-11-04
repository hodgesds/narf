// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821AE Bluetooth-coexistence owner (pass 1).
//!
//! Linux `rtl8821ae/btc.c::rtl8821ae_btc_init` wraps the same coexist
//! core as the 8723B algorithms; the full-algorithm form in NARF is the
//! 8723BE owner (`rtl8723be/coex.rs`), which is the TSV `bt_coexistence`
//! row's scope and is deliberately untouched here. This module is the
//! 8821AE pass-1 form: admission of BT-strapped boards, the LPS gate,
//! and the TDMA decision matrix (`btcoex::pattern_for`). A
//! per-traffic-class 8821A algorithm (a `halbtc8821a1ant`/`2ant`
//! equivalent with its own TDMA tables) does not exist in-tree and is
//! future work; the matrix's three coarse patterns (Wi-Fi-only,
//! BT-only, shared 50/50) are the bring-up policy `btcoex.rs` already
//! carries for combo silicon.
//!
//! Board facts, all grounded (see `Owner::bind`):
//! - `bt_exist` from the `REG_MULTI_FUNC_CTRL` BIT(18) strap
//!   (`prepare::RTL8821AE_BT_FUNCTION`), read in
//!   `configure_rtl8821ae_mac`; the owner is only constructed for
//!   strapped boards.
//! - Single antenna: the 8821AE station is 1T1R (rtlwifi.md's 8821AE
//!   rate-mask section describes a "2.4 GHz B/G/N 1T1R station"), so
//!   `ant_num` is 1 and the antenna sits at the main port (the same
//!   default `BtCoexist::bind` applies to `btdm_ant_pos`).
//! - `package_type` 0: "RTL8821AE never sets `package_type`"
//!   (`rtl8821ae/headerfile.rs`), so the bind's non-TFBGA branch
//!   applies.
//! - `rfe_type` 0: never set, as for the 8723BE binding.
//! - PCI interface; chip type `Rtl8821` (`btc::ChipType`).
//!
//! LPS control: while the decision matrix yields `BtOnly` (BT owns the
//! shared antenna outright), firmware LPS enter is held off — the
//! station's `ae_enter_leisure` returns `Ok` with `leisure` still false
//! instead of handing the radio to firmware LPS. `Shared` and
//! `WifiOnly` allow LPS enter (Wi-Fi still holds timeslices, or the
//! antenna). BT state has no producer yet (no BT host stack is wired
//! in NARF); the owner starts at `BtState::Idle` and `notify_bt` is
//! the hook the BT stack will drive. Wi-Fi state likewise starts
//! `Idle`; `notify_wifi` is the hook the station's assoc/scan
//! transitions will drive.

use crate::rtlwifi::btcoex::btc::{BtCoexist, ChipInterface, ChipType, HwPg};
use crate::rtlwifi::btcoex::{pattern_for, BtState, TdmaPattern, WifiState};

/// The 8821AE coexistence owner: bound `btc_coexist` state plus the
/// current Wi-Fi/BT states the decision matrix reads.
#[derive(Debug)]
pub struct Owner {
    /// `struct btc_coexist` state, bound from the 8821AE board facts.
    pub btc: BtCoexist,
    wifi: WifiState,
    bt: BtState,
}

impl Owner {
    /// Bind the owner for a BT-strapped 8821AE board (board facts per
    /// the module documentation).
    pub fn bind() -> Self {
        Self {
            btc: BtCoexist::bind(HwPg {
                bt_exist: true,
                ant_num: 1,
                single_ant_path: 0,
                chip_type: ChipType::Rtl8821,
                package_type: 0,
                rfe_type: 0,
                interface: ChipInterface::Pci,
            }),
            wifi: WifiState::Idle,
            bt: BtState::Idle,
        }
    }

    /// Current TDMA pattern from the decision matrix.
    pub fn pattern(&self) -> TdmaPattern {
        pattern_for(self.wifi, self.bt)
    }

    /// Whether firmware LPS enter is allowed: held off only while BT
    /// owns the shared antenna outright (`BtOnly`).
    pub fn lps_allowed(&self) -> bool {
        self.pattern() != TdmaPattern::BtOnly
    }

    /// Wi-Fi state transition (assoc/scan hook; no producer wired yet).
    pub fn notify_wifi(&mut self, wifi: WifiState) {
        self.wifi = wifi;
    }

    /// BT state transition (BT-stack hook; no producer wired yet).
    pub fn notify_bt(&mut self, bt: BtState) {
        self.bt = bt;
    }
}
