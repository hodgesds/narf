// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192EE conditional table walkers (`rtl8192ee/phy.c`).
//!
//! The 8192EE tables use `_check_condition` (not the `_rtl8821ae_check_positive`
//! two-word form): one condition word per branch, with the board type in
//! `[7:0]`, the interface mask in `[15:8]` (`0x07` = any) and the platform
//! mask in `[23:16]` (`0x0F` = any) tested against `rtlhal->interface`
//! (`INTF_PCI` = 0) and `_platform = 0x08`; `0xCDCDCDCD` (else) is always
//! true. `walk` is the exact `phy_config_bb_with_hdr_file` /
//! `rtl92ee_phy_config_rf_with_headerfile` index arithmetic, including the
//! `i -= 2` re-examination of the terminator pair after a discarded branch.
//! `bb_action` / `rf_action` are `_rtl92ee_config_bb_reg` /
//! `_rtl92ee_config_rf_reg` without the hardware access.

/// Branch terminators (`v2` of a condition row).
pub const BRANCH_END: u32 = 0xdead;
pub const BRANCH_ELSE: u32 = 0xcdcd;
pub const BRANCH_ELSE_IF: u32 = 0xcdef;
/// Condition rows start at this value; data rows are below it.
pub const CONDITION_ROW: u32 = 0xcdcd_cdcd;
/// `rtlhal->interface` for this PCIe driver (`enum intf_type` `INTF_PCI`).
pub const INTF_PCI: u32 = 0;
/// `_check_condition`'s `_platform` (`SupportPlatform`).
pub const PLATFORM: u32 = 0x08;

/// The `_check_condition` inputs (`rtlefuse->board_type`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Condition {
    pub board_type: u8,
}

impl Condition {
    /// From the factory facts (`adapter::Adapter::board_type`, incl.
    /// `ODM_BOARD_BT`).
    pub fn from_adapter(adapter: &super::adapter::Adapter) -> Self {
        Self {
            board_type: adapter.board_type,
        }
    }

    /// `_check_condition`. The interface test is kept literally although
    /// `INTF_PCI` is 0 (only the `0x07` wildcard passes it).
    #[allow(clippy::bad_bit_mask)]
    pub fn check(&self, condition: u32) -> bool {
        if condition == CONDITION_ROW {
            return true;
        }
        let board = condition & 0xff;
        if u32::from(self.board_type) != board && board != 0xff {
            return false;
        }
        let interface = (condition >> 8) & 0xff;
        if INTF_PCI & interface == 0 && interface != 0x07 {
            return false;
        }
        let platform = (condition >> 16) & 0xff;
        if PLATFORM & platform == 0 && platform != 0x0f {
            return false;
        }
        true
    }
}

fn terminator(v2: u32) -> bool {
    matches!(v2, BRANCH_END | BRANCH_ELSE_IF | BRANCH_ELSE)
}

/// Apply every selected `(addr, data)` row of a `[[u32; 2]]` table in Linux
/// order. Errors from `apply` stop the walk.
pub fn walk<E>(
    rows: &[[u32; 2]],
    condition: &Condition,
    mut apply: impl FnMut(u32, u32) -> Result<(), E>,
) -> Result<(), E> {
    let n = rows.len();
    let mut p = 0;
    while p < n {
        let [v1, _] = rows[p];
        if v1 < CONDITION_ROW {
            apply(rows[p][0], rows[p][1])?;
            p += 1;
            continue;
        }
        // "to protect READ_NEXT_PAIR not overrun".
        if p + 1 >= n {
            break;
        }
        if !condition.check(v1) {
            p += 1;
            while !terminator(rows[p][1]) && p + 1 < n {
                p += 1;
            }
            // `i -= 2` then the loop's `i += 2`: the terminator row is
            // examined again as the next condition.
        } else {
            p += 1;
            while !terminator(rows[p][1]) && p + 1 < n {
                apply(rows[p][0], rows[p][1])?;
                p += 1;
            }
            while rows[p][1] != BRANCH_END && p + 1 < n {
                p += 1;
            }
            p += 1;
        }
    }
    Ok(())
}

/// One `_rtl92ee_config_bb_reg` row: a delay marker or a dword BB write,
/// each followed by Linux's `udelay(1)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BbAction {
    DelayUs(u32),
    Write { addr: u16, data: u32 },
}

pub fn bb_action(addr: u32, data: u32) -> BbAction {
    match addr {
        0xfe => BbAction::DelayUs(50_000),
        0xfd => BbAction::DelayUs(5_000),
        0xfc => BbAction::DelayUs(1_000),
        0xfb => BbAction::DelayUs(50),
        0xfa => BbAction::DelayUs(5),
        0xf9 => BbAction::DelayUs(1),
        _ => BbAction::Write {
            addr: addr as u16,
            data,
        },
    }
}

/// One `_rtl92ee_config_rf_reg` row. `Write` rows are followed by
/// `udelay(1)`; `0xb6` re-writes until `[19:8]` reads back and `0xb2` until
/// the whole value reads back (each at most six retries, the latter with
/// an RF `0x18 = 0x0fc07` write per retry).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RfAction {
    DelayUs(u32),
    Write { addr: u8, data: u32 },
}

pub fn rf_action(addr: u32, data: u32) -> RfAction {
    match addr {
        0xfe | 0xffe => RfAction::DelayUs(50_000),
        _ => RfAction::Write {
            addr: addr as u8,
            data,
        },
    }
}
