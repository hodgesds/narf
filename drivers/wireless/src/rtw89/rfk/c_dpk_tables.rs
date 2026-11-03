// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852C DPK register programs, generated verbatim from Linux
//! rtw8852c_rfk_table.c (`Entry(kind, path, address, mask, data)`).
use super::super::Entry;

/// rtw8852c_rfk_table.c `rtw8852c_dpk_kip_pwr_clk_on_defs`.
pub(super) const DPK_KIP_PWR_CLK_ON_DEFS: [Entry; 2] = [
    Entry(1, 0, 0x8008, 0xffff_ffff, 0x80),
    Entry(1, 0, 0x8088, 0xffff_ffff, 0x807f_030a),
];
/// rtw8852c_rfk_table.c `rtw8852c_dpk_kip_pwr_clk_off_defs`.
pub(super) const DPK_KIP_PWR_CLK_OFF_DEFS: [Entry; 3] = [
    Entry(1, 0, 0x8008, 0xffff_ffff, 0x0),
    Entry(1, 0, 0x8088, 0xffff_ffff, 0x8000_0000),
    Entry(1, 0, 0x80f4, 0x0004_0000, 0x1),
];
/// rtw8852c_rfk_table.c `rtw8852c_dpk_mdpd_order0_defs`.
pub(super) const DPK_MDPD_ORDER0_DEFS: [Entry; 4] = [
    Entry(1, 0, 0x80a0, 0x3, 0x0),
    Entry(1, 0, 0x809c, 0x600, 0x2),
    Entry(1, 0, 0x80a0, 0x1f00, 0x4),
    Entry(1, 0, 0x8070, 0x7000_0000, 0x1),
];
/// rtw8852c_rfk_table.c `rtw8852c_dpk_mdpd_order1_defs`.
pub(super) const DPK_MDPD_ORDER1_DEFS: [Entry; 4] = [
    Entry(1, 0, 0x80a0, 0x3, 0x1),
    Entry(1, 0, 0x809c, 0x600, 0x1),
    Entry(1, 0, 0x80a0, 0x1f00, 0x0),
    Entry(1, 0, 0x8070, 0x7000_0000, 0x0),
];
/// rtw8852c_rfk_table.c `rtw8852c_dpk_mdpd_order2_defs`.
pub(super) const DPK_MDPD_ORDER2_DEFS: [Entry; 4] = [
    Entry(1, 0, 0x80a0, 0x3, 0x2),
    Entry(1, 0, 0x809c, 0x600, 0x0),
    Entry(1, 0, 0x80a0, 0x1f00, 0x0),
    Entry(1, 0, 0x8070, 0x7000_0000, 0x0),
];
/// rtw8852c_rfk_table.c `rtw8852c_dpk_mdpd_order3_defs`.
pub(super) const DPK_MDPD_ORDER3_DEFS: [Entry; 4] = [
    Entry(1, 0, 0x80a0, 0x3, 0x3),
    Entry(1, 0, 0x809c, 0x600, 0x3),
    Entry(1, 0, 0x80a0, 0x1f00, 0x4),
    Entry(1, 0, 0x8070, 0x7000_0000, 0x1),
];
