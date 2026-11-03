//! RTL8723BU Bluetooth/WiFi coexistence exactly as Linux rtl8xxxu runs it.
//!
//! The 8723BU shares one 2.4 GHz antenna between WiFi and the on-die BT
//! controller. Linux rtl8xxxu has no vendor `halbtc` engine: firmware reports
//! BT state with `C2H_8723B_BT_INFO`, and `rtl8xxxu_c2hcmd_callback` runs
//! `rtl8723bu_update_bt_link_info`, then `rtl8723bu_handle_bt_inquiry` (BT
//! inquiry/page) or `rtl8723bu_handle_bt_info`, each of which programs one
//! `rtl8723bu_set_ps_tdma` H2C and one `rtl8723bu_set_coex_with_type` table.
//!
//! Linux references (GPL-2.0-or-later, Linux 7.3-rc4):
//! - `rtl8xxxu/core.c::{rtl8723bu_set_coex_with_type,
//!   rtl8723bu_update_bt_link_info, rtl8xxxu_is_assoc,
//!   rtl8723bu_handle_bt_inquiry, rtl8723bu_handle_bt_info,
//!   rtl8xxxu_c2hcmd_callback, rtl8723bu_set_ps_tdma}`
//! - `rtl8xxxu/rtl8xxxu.h::{struct rtl8723bu_c2h, struct rtl8xxxu_btcoex,
//!   BT_INFO_8723B_1ANT_B_*, enum _BT_8723B_1ANT_STATUS}`
//!
//! Linux quirks kept verbatim: `a2dp_only` is never set (the "A2DP only"
//! test in `update_bt_link_info` rewrites `has_a2dp` instead), so the
//! `a2dp_only` branch of `handle_bt_info` is unreachable; the inquiry and
//! ACL-SCO statuses are never assigned; an unknown table type writes
//! nothing.

use super::firmware_transport::{ControlIo, Error, Owner};

/// `C2H_8723B_BT_INFO`.
pub const C2H_BT_INFO: u8 = 9;
/// `BT_INFO_8723B_1ANT_B_*`.
pub const BT_INFO_FTP: u8 = 1 << 7;
pub const BT_INFO_A2DP: u8 = 1 << 6;
pub const BT_INFO_HID: u8 = 1 << 5;
pub const BT_INFO_SCO_BUSY: u8 = 1 << 4;
pub const BT_INFO_ACL_BUSY: u8 = 1 << 3;
pub const BT_INFO_INQ_PAGE: u8 = 1 << 2;
pub const BT_INFO_SCO_ESCO: u8 = 1 << 1;
pub const BT_INFO_CONNECTION: u8 = 1 << 0;

/// `REG_BT_COEX_TABLE1..4`.
pub const REG_BT_COEX_TABLE1: u16 = 0x06c0;
pub const REG_BT_COEX_TABLE2: u16 = 0x06c4;
pub const REG_BT_COEX_TABLE3: u16 = 0x06c8;
pub const REG_BT_COEX_TABLE4: u16 = 0x06cc;
/// BT high-priority TX (`[15:0]`) / RX (`[31:16]`) counters read by
/// `rtl8723bu_handle_bt_info`.
pub const REG_BT_HIGH_PRIO: u16 = 0x0770;

/// `enum _BT_8723B_1ANT_STATUS` values `update_bt_link_info` assigns.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum BtStatus {
    #[default]
    NonConnectedIdle,
    ConnectedIdle,
    AclBusy,
    ScoBusy,
    /// `BT_8723B_1ANT_STATUS_MAX` (connected, no recognised activity).
    Max,
}

/// `struct rtl8xxxu_btcoex` (zero-initialised in `priv`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Coex {
    pub bt_status: BtStatus,
    pub bt_busy: bool,
    pub has_sco: bool,
    pub has_a2dp: bool,
    pub has_hid: bool,
    pub has_pan: bool,
    pub hid_only: bool,
    pub a2dp_only: bool,
    pub c2h_bt_inquiry: bool,
}

/// One coexistence programming step: `rtl8723bu_set_ps_tdma(tdma)` then
/// `rtl8723bu_set_coex_with_type(coex_type)`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Action {
    pub tdma: [u8; 5],
    pub coex_type: u8,
}

const TDMA_WIFI: [u8; 5] = [0x08, 0x00, 0x00, 0x00, 0x00];

/// `rtl8723bu_set_coex_with_type`: `(TABLE1, TABLE2, TABLE3)`; TABLE4 is
/// always `0x03`. Types outside 0..=7 write nothing (`None`).
pub fn coex_table(coex_type: u8) -> Option<(u32, u32, u32)> {
    let (t1, t2) = match coex_type {
        0 => (0x5555_5555, 0x5555_5555),
        1 | 3 => (0x5555_5555, 0x5a5a_5a5a),
        2 => (0x5a5a_5a5a, 0x5a5a_5a5a),
        4 => (0x5a5a_5a5a, 0xaaaa_5a5a),
        5 => (0x5a5a_5a5a, 0xaa5a_5a5a),
        6 => (0x5555_5555, 0xaaaa_aaaa),
        7 => (0xaaaa_aaaa, 0xaaaa_aaaa),
        _ => return None,
    };
    Some((t1, t2, 0x00ff_ffff))
}

/// The `bt_info` byte of a `C2H_8723B_BT_INFO` record (`struct
/// rtl8723bu_c2h`: id, seq, then `response_source`, `bt_info`, ...). `None`
/// for another id or a body too short to carry it.
pub fn bt_info(id: u8, payload: &[u8]) -> Option<u8> {
    (id == C2H_BT_INFO)
        .then(|| payload.get(1).copied())
        .flatten()
}

impl Coex {
    /// `rtl8723bu_update_bt_link_info`.
    pub fn update_link_info(&mut self, bt_info: u8) {
        self.c2h_bt_inquiry = bt_info & BT_INFO_INQ_PAGE != 0;
        if bt_info & BT_INFO_CONNECTION == 0 {
            self.bt_status = BtStatus::NonConnectedIdle;
            self.has_sco = false;
            self.has_hid = false;
            self.has_pan = false;
            self.has_a2dp = false;
        } else {
            self.bt_status = if bt_info & 0x1f == BT_INFO_CONNECTION {
                BtStatus::ConnectedIdle
            } else if bt_info & (BT_INFO_SCO_ESCO | BT_INFO_SCO_BUSY) != 0 {
                BtStatus::ScoBusy
            } else if bt_info & BT_INFO_ACL_BUSY != 0 {
                BtStatus::AclBusy
            } else {
                BtStatus::Max
            };
            self.has_pan = bt_info & BT_INFO_FTP != 0;
            self.has_a2dp = bt_info & BT_INFO_A2DP != 0;
            self.has_hid = bt_info & BT_INFO_HID != 0;
            self.has_sco = bt_info & BT_INFO_SCO_ESCO != 0;
        }
        self.hid_only = !self.has_a2dp && !self.has_sco && !self.has_pan && self.has_hid;
        // Linux writes has_a2dp here, not a2dp_only.
        self.has_a2dp = !self.has_sco && !self.has_pan && !self.has_hid && self.has_a2dp;
        self.bt_busy = matches!(self.bt_status, BtStatus::ScoBusy | BtStatus::AclBusy);
    }

    /// `rtl8723bu_handle_bt_inquiry`.
    pub fn inquiry_action(&self, assoc: bool) -> Action {
        if !assoc {
            Action {
                tdma: TDMA_WIFI,
                coex_type: 0,
            }
        } else if self.has_sco || self.has_hid || self.has_a2dp {
            Action {
                tdma: [0x61, 0x35, 0x03, 0x11, 0x11],
                coex_type: 4,
            }
        } else if self.has_pan {
            Action {
                tdma: [0x61, 0x3f, 0x03, 0x11, 0x11],
                coex_type: 4,
            }
        } else {
            Action {
                tdma: TDMA_WIFI,
                coex_type: 7,
            }
        }
    }

    /// `rtl8723bu_handle_bt_info`; `high_prio` is the `0x770` read Linux
    /// makes only while associated.
    pub fn info_action(&self, assoc: bool, high_prio: u32) -> Action {
        if !assoc {
            return Action {
                tdma: TDMA_WIFI,
                coex_type: 0,
            };
        }
        let (tdma, coex_type) = if self.bt_busy {
            if self.hid_only {
                ([0x61, 0x20, 0x03, 0x11, 0x11], 5)
            } else if self.a2dp_only {
                ([0x61, 0x35, 0x03, 0x11, 0x11], 4)
            } else if self.has_a2dp && self.has_pan {
                // Linux: `(a2dp && pan) || (hid && a2dp && pan)`, the same
                // predicate.
                ([0x51, 0x21, 0x03, 0x10, 0x10], 4)
            } else if self.has_hid && self.has_a2dp {
                ([0x51, 0x21, 0x03, 0x10, 0x10], 3)
            } else {
                ([0x61, 0x35, 0x03, 0x11, 0x11], 4)
            }
        } else {
            let tx = high_prio & 0xffff;
            let rx = high_prio >> 16;
            (TDMA_WIFI, if tx + rx <= 60 { 2 } else { 7 })
        };
        Action { tdma, coex_type }
    }
}

impl<I: ControlIo> Owner<I> {
    /// `rtl8723bu_set_ps_tdma` then `rtl8723bu_set_coex_with_type`.
    pub(super) async fn apply_coex_8723b(&self, action: Action) -> Result<(), Error> {
        super::rtl8723b_power::set_ps_tdma(self, action.tdma).await?;
        if let Some((t1, t2, t3)) = coex_table(action.coex_type) {
            self.write32(REG_BT_COEX_TABLE1, t1).await?;
            self.write32(REG_BT_COEX_TABLE2, t2).await?;
            self.write32(REG_BT_COEX_TABLE3, t3).await?;
            self.write8(REG_BT_COEX_TABLE4, 0x03).await?;
        }
        Ok(())
    }

    /// The `C2H_8723B_BT_INFO` case of `rtl8xxxu_c2hcmd_callback`: update
    /// the link info, then the inquiry or the info policy. `assoc` is
    /// `rtl8xxxu_is_assoc` for the owner's station interface. Returns the
    /// programmed action.
    pub(super) async fn handle_bt_info_8723b(
        &self,
        coex: &mut Coex,
        bt_info: u8,
        assoc: bool,
    ) -> Result<Action, Error> {
        coex.update_link_info(bt_info);
        let action = if coex.c2h_bt_inquiry {
            coex.inquiry_action(assoc)
        } else {
            let high_prio = if assoc {
                self.read32(REG_BT_HIGH_PRIO).await?
            } else {
                0
            };
            coex.info_action(assoc, high_prio)
        };
        self.apply_coex_8723b(action).await?;
        Ok(action)
    }
}

impl<I: ControlIo> Owner<I> {
    /// `rtl8xxxu_c2hcmd_callback` BT-info dispatch for one parsed gen2 C2H
    /// record: a `C2H_8723B_BT_INFO` carrying its `bt_info` byte runs
    /// `handle_bt_info_8723b`; RA reports and every other id are left to the
    /// caller (`None`), as are BT-info bodies too short to carry the byte.
    pub(super) async fn c2h_bt_8723b(
        &self,
        coex: &mut Coex,
        record: &super::rtl8192e_packet::C2h,
        assoc: bool,
    ) -> Result<Option<Action>, Error> {
        let super::rtl8192e_packet::C2h::Other { id, payload, .. } = record else {
            return Ok(None);
        };
        match bt_info(*id, payload) {
            Some(info) => Ok(Some(self.handle_bt_info_8723b(coex, info, assoc).await?)),
            None => Ok(None),
        }
    }
}
