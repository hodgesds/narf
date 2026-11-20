// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821AE retained Bluetooth-coexistence owner.
//!
//! The original coarse matrix/LPS policy remains available without N21C.
//! Full source one/two-antenna algorithms live in btcoex/b8821a{1,2}ant;
//! native activation additionally needs a complete actual BT patch/build
//! observation and the separately measured current coex_program::Program.
//! Both modes keep the original board/controller/mailbox histories.
//!
//! Board facts, all grounded (see `Owner::bind`):
//! - `bt_exist` from the `REG_MULTI_FUNC_CTRL` BIT(18) strap
//!   (`prepare::RTL8821AE_BT_FUNCTION`), read in
//!   `configure_rtl8821ae_mac`; the owner is only constructed for
//!   strapped boards.
//! - Antenna algorithm: actual factory EFUSE0xc3 BIT0 selects ANT_X1(1)
//!   or ANT_X2(0), as `_rtl8821ae_read_bt_coexist_info_from_hwpg` does.
//!   Wi-Fi RF stream count does not establish the shared BT antenna count.
//!   `BtCoexist::bind` applies the source's default main/aux position.
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
use alloc::sync::Arc;

/// The 8821AE coexistence owner: bound `btc_coexist` state plus the
/// current Wi-Fi/BT states the decision matrix reads.
#[derive(Debug)]
pub struct Owner {
    /// `struct btc_coexist` state, bound from the 8821AE board facts.
    pub btc: BtCoexist,
    wifi: WifiState,
    bt: BtState,
    pub(in crate::rtlwifi) factory: Option<Arc<crate::rtlwifi::efuse::Factory>>,
    pub(in crate::rtlwifi) full: Option<super::coex_dispatch::Dispatch>,
    pub(in crate::rtlwifi) program: Option<Arc<super::coex_program::Program>>,
    pub(in crate::rtlwifi) probed: bool,
}

impl Owner {
    /// Bind the owner for a BT-strapped 8821AE board (board facts per
    /// the module documentation).
    pub fn bind(antenna_setting: u8) -> Self {
        Self {
            btc: BtCoexist::bind(HwPg {
                bt_exist: true,
                ant_num: if antenna_setting & 1 != 0 { 1 } else { 2 },
                single_ant_path: 0,
                chip_type: ChipType::Rtl8821,
                package_type: 0,
                rfe_type: 0,
                interface: ChipInterface::Pci,
            }),
            wifi: WifiState::Idle,
            bt: BtState::Idle,
            factory: None,
            full: None,
            program: None,
            probed: false,
        }
    }

    /// The already identity-checked factory snapshot from the retained MAC
    /// continuation, including the raw antenna byte. This is metadata, not
    /// a new independent controller, permission or replacement authority.
    pub(crate) fn bind_factory(factory: &crate::rtlwifi::efuse::Factory) -> Self {
        let mut owner = Self::bind(factory.logical[0xc3]);
        owner.factory = Some(Arc::new(factory.clone()));
        owner
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
