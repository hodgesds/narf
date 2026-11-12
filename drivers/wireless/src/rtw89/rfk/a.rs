// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852A `rtw8852a_rfk_init` (rtw8852a.c): `rtw8852a_rck`,
//! `rtw8852a_dack` (`_dac_cal`: AFE init, table-driven ADDCK, DACK) and
//! `rtw8852a_rx_dck(PHY_0, is_afe = true)` from rtw8852a_rfk.c, for the
//! non-DBCC PHY_0 (`_kpath` = RF_AB). Linux only logs RCK/ADDCK/DACK/RXDCK
//! poll timeouts; NARF fails the attempt closed instead.
//!
//! The A flow differs from the B core in `rfk.rs`: no `_drck` and no
//! `R_AX_PHYREG_SET` write in `_dac_cal`, `RR_MOD` goes 0x30001 then
//! 0x40001 (B uses 0x337e1), ADDCK/DACK are driven by the
//! `rtw8852a_rfk_table.c` def tables below, and the initial RX DCK is the
//! AFE variant with the ANAPAR dance (both `rtw8852a_rfk_init` and
//! `rtw8852a_rfk_channel` call `rtw8852a_rx_dck` with `is_afe = true`).
//! The BTC ONESHOT notifications inside `_dac_cal`/`_set_rx_dck` return
//! without I/O for DACK/RXDCK (coex.c `rtw89_btc_ntfy_wl_rfk`), so only
//! the outer START/STOP are emitted, as in `c.rs`.
use super::{power, Access, Entry, Error, Interface, Kind, State};

// RF registers/fields (reg.h) not already shared with the B core.
const RFREG_MASK: u32 = 0xfffff;
const RR_MOD: u32 = 0x00;
const RR_MOD_MASK: u32 = 0xf0000;
const RR_MOD_V_RX: u32 = 0x3;
const RR_MODOPT: u32 = 0x01;
const RR_RSV1: u32 = 0x05;
const RR_RSV1_RST: u32 = 1;
const RR_RCKC: u32 = 0x1b;
const RR_RCKC_CA: u32 = 0x7c00;
const RR_RCKS: u32 = 0x1c;
const RR_RCKO: u32 = 0x1d;
const RR_RCKO_OFF: u32 = 0x3e00;
const RR_RFC: u32 = 0xf0;
const RR_RFC_CKEN: u32 = 1 << 1;
const RR_DCK: u32 = 0x92;
const RR_DCK_LV: u32 = 1;
const RR_DCK_FINE: u32 = 1 << 1;
const RR_DCK1: u32 = 0x93;
const RR_DCK1_SEL: u32 = 1 << 3;
const RR_DCK2: u32 = 0x94;
const RR_DCK2_CYCLE: u32 = 0xfc;

// BB registers (reg.h), PHY-relative.
const R_ANAPAR_PW15: u32 = 0x30c;
const B_ANAPAR_PW15_H: u32 = 0xf000000;
const R_ANAPAR: u32 = 0x32c;
const B_ANAPAR_ADCCLK: u32 = 1 << 30;
const B_ANAPAR_FLTRST: u32 = 1 << 22;
const B_ANAPAR_CRXBB: u32 = 0x70000;
const R_P0_RXCK: u32 = 0x12a0;
const B_P0_RXCK_ON: u32 = 1 << 19;
const B_P0_RXCK_VAL: u32 = 0x70000;
const R_P0_NRBW: u32 = 0x12b8;
const B_P0_NRBW_DBG: u32 = 1 << 30;
const R_P1_DBGMOD: u32 = 0x32b8;
const B_P1_DBGMOD_ON: u32 = 1 << 30;
const R_S0_RXDC: u32 = 0x12d4;
const B_S0_RXDC_I: u32 = 0x3ff0000;
const B_S0_RXDC_Q: u32 = 0xfc000000;
const R_S0_RXDC2: u32 = 0x12d8;
const B_S0_RXDC2_SEL: u32 = 0x300;
const B_S0_RXDC2_AVG: u32 = 0xc0;
const B_S0_RXDC2_MEN: u32 = 0x30;
const B_S0_RXDC2_Q2: u32 = 0xf;
const R_S1_RXDC: u32 = 0x32d4;
const B_S1_RXDC_I: u32 = 0x3ff0000;
const B_S1_RXDC_Q: u32 = 0xfc000000;
const R_S1_RXDC2: u32 = 0x32d8;
const B_S1_RXDC2_SEL: u32 = 0x300;
const B_S1_RXDC2_EN: u32 = 0x30;
const B_S1_RXDC2_Q2: u32 = 0xf;
const R_S0_ADDCK: u32 = 0x1e00;
const B_S0_ADDCK_Q: u32 = 0xffc00;
const B_S0_ADDCK_I: u32 = 0x3ff;
const R_S1_ADDCK: u32 = 0x3e00;
const B_S1_ADDCK_Q: u32 = 0xffc00;
const B_S1_ADDCK_I: u32 = 0x3ff;
const R_DBG32_D: u32 = 0x1730;
const R_P0_TSSI_TRK: u32 = 0x5818;
const B_P0_TSSI_TRK_EN: u32 = 1 << 30;
const R_S0_DACKI: u32 = 0x5e00;
const B_S0_DACKI_AR: u32 = 0xf0000000;
const B_S0_DACKI_EN: u32 = 1 << 3;
const R_S0_DACKI2: u32 = 0x5e30;
const B_S0_DACKI2_K: u32 = 0x3ff000;
const R_S0_DACKI7: u32 = 0x5e44;
const B_S0_DACKI7_K: u32 = 0xff00;
const R_S0_DACKI8: u32 = 0x5e48;
const B_S0_DACKI8_K: u32 = 0xff00;
const R_S0_DACKQ: u32 = 0x5e50;
const B_S0_DACKQ_AR: u32 = 0xf0000000;
const B_S0_DACKQ_EN: u32 = 1 << 3;
const R_S0_DACKQ2: u32 = 0x5e80;
const B_S0_DACKQ2_K: u32 = 0x3ff000;
const R_S0_DACKQ7: u32 = 0x5e94;
const B_S0_DACKQ7_K: u32 = 0xff00;
const R_S0_DACKQ8: u32 = 0x5e98;
const B_S0_DACKQ8_K: u32 = 0xff00;
const R_S1_DACKI: u32 = 0x7e00;
const B_S1_DACKI_AR: u32 = 0xf0000000;
const B_S1_DACKI_EN: u32 = 1 << 3;
const R_S1_DACKI2: u32 = 0x7e30;
const B_S1_DACKI2_K: u32 = 0x3ff000;
const R_S1_DACKI7: u32 = 0x7e44;
// reg.h names this mask `B_S1_DACKI_K`, not `B_S1_DACKI7_K`.
const B_S1_DACKI_K: u32 = 0xff00;
const R_S1_DACKI8: u32 = 0x7e48;
const B_S1_DACKI8_K: u32 = 0xff00;
const R_S1_DACKQ: u32 = 0x7e50;
const B_S1_DACKQ_AR: u32 = 0xf0000000;
const B_S1_DACKQ_EN: u32 = 1 << 3;
const R_S1_DACKQ2: u32 = 0x7e80;
const B_S1_DACKQ2_K: u32 = 0x3ff000;
const R_S1_DACKQ7: u32 = 0x7e94;
const B_S1_DACKQ7_K: u32 = 0xff00;
const R_S1_DACKQ8: u32 = 0x7e98;
const B_S1_DACKQ8_K: u32 = 0xff00;
// DACK MSBK done-status offsets: Linux polls these raw (no reg.h name).
const R_S0_DACK_MSBK_I: u32 = 0x5e28;
const R_S0_DACK_MSBK_Q: u32 = 0x5e78;
const R_S1_DACK_MSBK_I: u32 = 0x7e28;
const R_S1_DACK_MSBK_Q: u32 = 0x7e78;
// `_dack_reload_by_path` target bases: Linux writes these raw (no reg.h
// name); slot order is msbk[12..16], [8..12], [4..8], [0..4], then
// `(biask << 22) | (dadck << 14)`.
const R_DACK_RELOAD_MSBK: u32 = 0x5e14;
const R_DACK_RELOAD_BIAS: u32 = 0x5e24;

// Init-flow def tables, verbatim from Linux
// `drivers/net/wireless/realtek/rtw89/rtw8852a_rfk_table.c` at torvalds/linux
// 067c5c24cef23d913b67eaaf71ae67e7169a6620 (SHA256
// 67f363254b5c6849d2a490a4f1fe90d24a65151eced5aa177fa85448cd95bc5d):
// 21 tables, 150 entries. Entry kinds follow `Access::table`: 0 RF write,
// 1 BB write, 2 BB set bits, 3 BB clear bits, 4 delay. The A `CHECK_ADDC`
// tables use WC/WS for their first two entries where B uses WM; the A
// `AFE_INIT` table is WS/WC-only.
#[rustfmt::skip]
/// Linux `rtw8852a_rfk_table.c` `rtw8852a_rfk_afe_init_defs`.
const AFE_INIT: &[Entry] = &[
Entry(3,0,0x12ec,0x8000,0x0),Entry(2,0,0x12ec,0x8000,0x0),Entry(3,0,0x5e00,0x1,0x0),
Entry(2,0,0x5e00,0x1,0x0),Entry(3,0,0x32ec,0x8000,0x0),Entry(2,0,0x32ec,0x8000,0x0),
Entry(3,0,0x7e00,0x1,0x0),Entry(2,0,0x7e00,0x1,0x0),
];
#[rustfmt::skip]
/// Linux `rtw8852a_rfk_table.c` `rtw8852a_rfk_addck_reset_defs_a`.
const ADDCK_RESET_A: &[Entry] = &[
Entry(3,0,0x12d8,0x30,0x0),Entry(3,0,0x32d8,0x30,0x0),Entry(2,0,0x12b8,0x40000000,0x0),
Entry(3,0,0x32c,0x40000000,0x0),Entry(3,0,0x32c,0x400000,0x0),Entry(2,0,0x32c,0x400000,0x0),
Entry(2,0,0x30c,0xf000000,0x0),Entry(3,0,0x32c,0x10000,0x0),Entry(2,0,0x12dc,0x2,0x0),
Entry(1,0,0x30c,0xf000000,0x3),
];
#[rustfmt::skip]
/// Linux `rtw8852a_rfk_table.c` `rtw8852a_rfk_addck_trigger_defs_a`.
const ADDCK_TRIGGER_A: &[Entry] = &[
Entry(2,0,0x12d8,0xc0,0x0),Entry(2,0,0x12d8,0x800,0x0),Entry(3,0,0x12d8,0x800,0x0),
Entry(4,0,0x0,0x0,0x1),Entry(1,0,0x12d8,0x300,0x1),
];
#[rustfmt::skip]
/// Linux `rtw8852a_rfk_table.c` `rtw8852a_rfk_addck_restore_defs_a`.
const ADDCK_RESTORE_A: &[Entry] = &[
Entry(3,0,0x12dc,0x2,0x0),Entry(2,0,0x32c,0x10000,0x0),Entry(1,0,0x30c,0xf000000,0xc),
Entry(2,0,0x32c,0x40000000,0x0),Entry(3,0,0x12b8,0x40000000,0x0),
];
#[rustfmt::skip]
/// Linux `rtw8852a_rfk_table.c` `rtw8852a_rfk_addck_reset_defs_b`.
const ADDCK_RESET_B: &[Entry] = &[
Entry(2,0,0x32b8,0x40000000,0x0),Entry(3,0,0x32c,0x40000000,0x0),Entry(3,0,0x32c,0x400000,0x0),
Entry(2,0,0x32c,0x400000,0x0),Entry(2,0,0x30c,0xf000000,0x0),Entry(3,0,0x32c,0x10000,0x0),
Entry(2,0,0x32dc,0x2,0x0),Entry(1,0,0x30c,0xf000000,0x3),
];
#[rustfmt::skip]
/// Linux `rtw8852a_rfk_table.c` `rtw8852a_rfk_addck_trigger_defs_b`.
const ADDCK_TRIGGER_B: &[Entry] = &[
Entry(2,0,0x32d8,0xc0,0x0),Entry(2,0,0x32d8,0x800,0x0),Entry(3,0,0x32d8,0x800,0x0),
Entry(4,0,0x0,0x0,0x1),Entry(1,0,0x32d8,0x300,0x1),
];
#[rustfmt::skip]
/// Linux `rtw8852a_rfk_table.c` `rtw8852a_rfk_addck_restore_defs_b`.
const ADDCK_RESTORE_B: &[Entry] = &[
Entry(3,0,0x32dc,0x2,0x0),Entry(2,0,0x32c,0x10000,0x0),Entry(1,0,0x30c,0xf000000,0xc),
Entry(2,0,0x32c,0x40000000,0x0),Entry(3,0,0x32b8,0x40000000,0x0),
];
#[rustfmt::skip]
/// Linux `rtw8852a_rfk_table.c` `rtw8852a_rfk_check_addc_defs_a`.
const CHECK_ADDC_A: &[Entry] = &[
Entry(3,0,0x20f4,0x1000000,0x0),Entry(2,0,0x20f8,0x80000000,0x0),Entry(1,0,0x20f0,0xff0000,0x1),
Entry(1,0,0x20f0,0xf00,0x2),Entry(3,0,0x20f0,0xf,0x0),Entry(1,0,0x20f0,0xc0,0x2),
];
#[rustfmt::skip]
/// Linux `rtw8852a_rfk_table.c` `rtw8852a_rfk_check_addc_defs_b`.
const CHECK_ADDC_B: &[Entry] = &[
Entry(3,0,0x20f4,0x1000000,0x0),Entry(2,0,0x20f8,0x80000000,0x0),Entry(1,0,0x20f0,0xff0000,0x1),
Entry(1,0,0x20f0,0xf00,0x2),Entry(3,0,0x20f0,0xf,0x0),Entry(1,0,0x20f0,0xc0,0x3),
];
#[rustfmt::skip]
/// Linux `rtw8852a_rfk_table.c` `rtw8852a_rfk_check_dadc_defs_f_a`.
const CHECK_DADC_F_A: &[Entry] = &[
Entry(3,0,0x32c,0x40000000,0x0),Entry(2,0,0x30c,0xf000000,0x0),Entry(1,0,0x30c,0xf000000,0x3),
Entry(3,0,0x32c,0x10000,0x0),Entry(2,0,0x12dc,0x1,0x0),Entry(2,0,0x12e8,0x4,0x0),
Entry(0,0,0x8f,0x2000,0x1),
];
#[rustfmt::skip]
/// Linux `rtw8852a_rfk_table.c` `rtw8852a_rfk_check_dadc_defs_r_a`.
const CHECK_DADC_R_A: &[Entry] = &[
Entry(3,0,0x12dc,0x1,0x0),Entry(3,0,0x12e8,0x4,0x0),Entry(0,0,0x8f,0x2000,0x0),
Entry(1,0,0x32c,0x10000,0x1),
];
#[rustfmt::skip]
/// Linux `rtw8852a_rfk_table.c` `rtw8852a_rfk_check_dadc_defs_f_b`.
const CHECK_DADC_F_B: &[Entry] = &[
Entry(3,0,0x32c,0x40000000,0x0),Entry(2,0,0x30c,0xf000000,0x0),Entry(1,0,0x30c,0xf000000,0x3),
Entry(3,0,0x32c,0x10000,0x0),Entry(2,0,0x32dc,0x1,0x0),Entry(2,0,0x32e8,0x4,0x0),
Entry(0,1,0x8f,0x2000,0x1),
];
#[rustfmt::skip]
/// Linux `rtw8852a_rfk_table.c` `rtw8852a_rfk_check_dadc_defs_r_b`.
const CHECK_DADC_R_B: &[Entry] = &[
Entry(3,0,0x32dc,0x1,0x0),Entry(3,0,0x32e8,0x4,0x0),Entry(0,1,0x8f,0x2000,0x0),
Entry(1,0,0x32c,0x10000,0x1),
];
#[rustfmt::skip]
/// Linux `rtw8852a_rfk_table.c` `rtw8852a_rfk_dack_defs_f_a`.
const DACK_F_A: &[Entry] = &[
Entry(2,0,0x5e00,0x8,0x0),Entry(3,0,0x5e10,0x80000000,0x0),Entry(2,0,0x5e50,0x8,0x0),
Entry(3,0,0x5e60,0x80000000,0x0),Entry(2,0,0x12a0,0x8000,0x0),Entry(1,0,0x12a0,0x7000,0x3),
Entry(2,0,0x12b8,0x40000000,0x0),Entry(2,0,0x30c,0x10000000,0x0),Entry(3,0,0x32c,0x80000000,0x0),
Entry(2,0,0x12e0,0x10000,0x0),Entry(2,0,0x12e4,0xc000000,0x0),Entry(1,0,0x5e00,0x3ff0000,0x30),
Entry(1,0,0x5e50,0x3ff0000,0x30),Entry(3,0,0x5e00,0xc000000,0x0),Entry(3,0,0x5e50,0xc000000,0x0),
Entry(3,0,0x5e0c,0x8,0x0),Entry(3,0,0x5e5c,0x8,0x0),Entry(2,0,0x5e0c,0x1,0x0),
Entry(2,0,0x5e5c,0x1,0x0),Entry(4,0,0x0,0x0,0x1),
];
#[rustfmt::skip]
/// Linux `rtw8852a_rfk_table.c` `rtw8852a_rfk_dack_defs_m_a`.
const DACK_M_A: &[Entry] = &[
Entry(3,0,0x12e4,0xc000000,0x0),Entry(2,0,0x5e0c,0x8,0x0),Entry(2,0,0x5e5c,0x8,0x0),
Entry(4,0,0x0,0x0,0x1),
];
#[rustfmt::skip]
/// Linux `rtw8852a_rfk_table.c` `rtw8852a_rfk_dack_defs_r_a`.
const DACK_R_A: &[Entry] = &[
Entry(3,0,0x5e0c,0x1,0x0),Entry(3,0,0x5e5c,0x1,0x0),Entry(3,0,0x12e0,0x10000,0x0),
Entry(3,0,0x12a0,0x8000,0x0),Entry(2,0,0x12a0,0x7000,0x0),
];
#[rustfmt::skip]
/// Linux `rtw8852a_rfk_table.c` `rtw8852a_rfk_dack_defs_f_b`.
const DACK_F_B: &[Entry] = &[
Entry(2,0,0x7e00,0x8,0x0),Entry(3,0,0x7e10,0x80000000,0x0),Entry(2,0,0x7e50,0x8,0x0),
Entry(3,0,0x7e60,0x80000000,0x0),Entry(2,0,0x32a0,0x8000,0x0),Entry(1,0,0x32a0,0x7000,0x3),
Entry(2,0,0x32b8,0x40000000,0x0),Entry(2,0,0x30c,0x10000000,0x0),Entry(3,0,0x32c,0x80000000,0x0),
Entry(2,0,0x32e0,0x10000,0x0),Entry(2,0,0x32e4,0xc000000,0x0),Entry(1,0,0x7e00,0x3ff0000,0x30),
Entry(1,0,0x7e50,0x3ff0000,0x30),Entry(3,0,0x7e00,0xc000000,0x0),Entry(3,0,0x7e50,0xc000000,0x0),
Entry(3,0,0x7e0c,0x8,0x0),Entry(3,0,0x7e5c,0x8,0x0),Entry(2,0,0x7e0c,0x1,0x0),
Entry(2,0,0x7e5c,0x1,0x0),Entry(4,0,0x0,0x0,0x1),
];
#[rustfmt::skip]
/// Linux `rtw8852a_rfk_table.c` `rtw8852a_rfk_dack_defs_m_b`.
const DACK_M_B: &[Entry] = &[
Entry(3,0,0x32e4,0xc000000,0x0),Entry(1,0,0x7e0c,0x8,0x1),Entry(1,0,0x7e5c,0x8,0x1),
Entry(4,0,0x0,0x0,0x1),
];
#[rustfmt::skip]
/// Linux `rtw8852a_rfk_table.c` `rtw8852a_rfk_dack_defs_r_b`.
const DACK_R_B: &[Entry] = &[
Entry(3,0,0x7e0c,0x1,0x0),Entry(3,0,0x7e5c,0x1,0x0),Entry(3,0,0x32e0,0x10000,0x0),
Entry(3,0,0x32a0,0x8000,0x0),Entry(2,0,0x32a0,0x7000,0x0),
];
#[rustfmt::skip]
/// Linux `rtw8852a_rfk_table.c` `rtw8852a_rfk_dack_reload_defs_a`.
const DACK_RELOAD_A: &[Entry] = &[
Entry(2,0,0x5e00,0x8,0x0),Entry(2,0,0x5e50,0x8,0x0),Entry(2,0,0x5e10,0x80000000,0x0),
Entry(2,0,0x5e60,0x80000000,0x0),Entry(3,0,0x5e00,0x8,0x0),Entry(3,0,0x5e50,0x8,0x0),
];
#[rustfmt::skip]
/// Linux `rtw8852a_rfk_table.c` `rtw8852a_rfk_dack_reload_defs_b`.
const DACK_RELOAD_B: &[Entry] = &[
Entry(2,0,0x7e00,0x8,0x0),Entry(2,0,0x7e50,0x8,0x0),Entry(2,0,0x7e10,0x80000000,0x0),
Entry(2,0,0x7e60,0x80000000,0x0),Entry(3,0,0x7e00,0x8,0x0),Entry(3,0,0x7e50,0x8,0x0),
];

/// `rtw89_dack_info` / RCK values retained by one A `rfk_init`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in super::super) struct Results {
    /// `msbk_d[path][index][16]`.
    pub msbk: [[[u8; 16]; 2]; 2],
    /// `biask_d[path][index]`.
    pub biask: [[u16; 2]; 2],
    /// `dadck_d[path][index]`.
    pub dadck: [[u8; 2]; 2],
    /// `addck_d[path][index]`.
    pub addck: [[u16; 2]; 2],
    /// RR_RCKC `RR_RCKC_CA` result per path.
    pub rck: [u32; 2],
}

/// One retained RTL8852A `rfk_init` attempt.
#[derive(Default)]
pub(in super::super) struct Init {
    state: State,
    results: Results,
}

impl<I: Interface> Access<'_, I> {
    /// `_rck`: trigger 0x240, poll `RR_RCKS` bit 3 at 2us/20us, then the
    /// A-only tail: `RR_RCKO_OFF` = 4 and `RR_RFC_CKEN` 1 then 0.
    async fn a_rck(&mut self, path: u8) -> Result<u32, Error> {
        let saved = self.rr(path, RR_RSV1, RFREG_MASK).await?;
        self.wr(path, RR_RSV1, RR_RSV1_RST, 0).await?;
        self.wr(path, RR_MOD, RR_MOD_MASK, RR_MOD_V_RX).await?;
        self.wr(path, RR_RCKC, RFREG_MASK, 0x240).await?;
        // read_poll_timeout_atomic(rtw89_read_rf, ..., 2, 20, path, 0x1c, BIT(3)).
        let start = self.0.now_us();
        loop {
            if self.rr(path, RR_RCKS, 1 << 3).await? != 0 {
                break;
            }
            if self.0.now_us().saturating_sub(start) >= 20 {
                return Err(power::Error::Timeout.into());
            }
            self.delay(2).await?;
        }
        let value = self.rr(path, RR_RCKC, RR_RCKC_CA).await?;
        self.wr(path, RR_RCKC, RFREG_MASK, value).await?;
        // RCK_ADC_OFFSET.
        self.wr(path, RR_RCKO, RR_RCKO_OFF, 0x4).await?;
        self.wr(path, RR_RFC, RR_RFC_CKEN, 1).await?;
        self.wr(path, RR_RFC, RR_RFC_CKEN, 0).await?;
        self.wr(path, RR_RSV1, RFREG_MASK, saved).await?;
        Ok(value)
    }
    /// `_check_addc`: the per-path def table, then ADDC_T_AVG = 100 reads
    /// of `R_DBG32_D`. Linux only logs the averaged signed I/Q values, so
    /// the samples are discarded here; the acquisition itself is finite,
    /// not a completion spin.
    async fn a_check_addc(&mut self, path: u8) -> Result<(), Error> {
        self.table(if path == 0 {
            CHECK_ADDC_A
        } else {
            CHECK_ADDC_B
        })
        .await?;
        for _ in 0..100 {
            self.bb(R_DBG32_D, u32::MAX)?;
        }
        Ok(())
    }
    /// `_addck`: reset, check, trigger, 1us/10000us done poll, check,
    /// restore per path. (Backup/reload are separate `_dac_cal` steps.)
    async fn a_addck(&mut self) -> Result<(), Error> {
        self.table(ADDCK_RESET_A).await?;
        self.a_check_addc(0).await?;
        self.table(ADDCK_TRIGGER_A).await?;
        self.poll(R_S0_ADDCK, 1, 1, 10_000).await?;
        self.a_check_addc(0).await?;
        self.table(ADDCK_RESTORE_A).await?;
        self.table(ADDCK_RESET_B).await?;
        self.a_check_addc(1).await?;
        self.table(ADDCK_TRIGGER_B).await?;
        self.poll(R_S1_ADDCK, 1, 1, 10_000).await?;
        self.a_check_addc(1).await?;
        self.table(ADDCK_RESTORE_B).await
    }
    /// `_addck_backup`: clear `RXDC2_SEL`, then read Q then I per path.
    fn a_addck_backup(&mut self, results: &mut Results) -> Result<(), Error> {
        self.wm(R_S0_RXDC2, B_S0_RXDC2_SEL, 0)?;
        results.addck[0][0] = self.bb(R_S0_ADDCK, B_S0_ADDCK_Q)? as u16;
        results.addck[0][1] = self.bb(R_S0_ADDCK, B_S0_ADDCK_I)? as u16;
        self.wm(R_S1_RXDC2, B_S1_RXDC2_SEL, 0)?;
        results.addck[1][0] = self.bb(R_S1_ADDCK, B_S1_ADDCK_Q)? as u16;
        results.addck[1][1] = self.bb(R_S1_ADDCK, B_S1_ADDCK_I)? as u16;
        Ok(())
    }
    /// `_addck_reload`: `RXDC_I` = Q, `RXDC2_Q2` = I >> 6, `RXDC_Q` =
    /// I & 0x3f, then `write32_set(RXDC2, MEN/EN)`. `wm` shifts the field
    /// value into the mask, so the set-all-bits field value is 3, not 1.
    fn a_addck_reload(&mut self, results: &Results) -> Result<(), Error> {
        self.wm(R_S0_RXDC, B_S0_RXDC_I, u32::from(results.addck[0][0]))?;
        self.wm(
            R_S0_RXDC2,
            B_S0_RXDC2_Q2,
            u32::from(results.addck[0][1] >> 6),
        )?;
        self.wm(
            R_S0_RXDC,
            B_S0_RXDC_Q,
            u32::from(results.addck[0][1] & 0x3f),
        )?;
        self.wm(R_S0_RXDC2, B_S0_RXDC2_MEN, 3)?;
        self.wm(R_S1_RXDC, B_S1_RXDC_I, u32::from(results.addck[1][0]))?;
        self.wm(
            R_S1_RXDC2,
            B_S1_RXDC2_Q2,
            u32::from(results.addck[1][1] >> 6),
        )?;
        self.wm(
            R_S1_RXDC,
            B_S1_RXDC_Q,
            u32::from(results.addck[1][1] & 0x3f),
        )?;
        self.wm(R_S1_RXDC2, B_S1_RXDC2_EN, 3)
    }
    /// `_check_dadc`: F table, `_check_addc`, R table.
    async fn a_check_dadc(&mut self, path: u8) -> Result<(), Error> {
        self.table(if path == 0 {
            CHECK_DADC_F_A
        } else {
            CHECK_DADC_F_B
        })
        .await?;
        self.a_check_addc(path).await?;
        self.table(if path == 0 {
            CHECK_DADC_R_A
        } else {
            CHECK_DADC_R_B
        })
        .await
    }
    /// `_dack_backup_s0` / `_dack_backup_s1`: enable, walk the 16 MSBK
    /// addresses, read bias, read DADCK as `(u8)read - 8`.
    fn a_dack_backup(&mut self, path: u8, results: &mut Results) -> Result<(), Error> {
        let p = usize::from(path);
        if path == 0 {
            self.wm(R_S0_DACKI, B_S0_DACKI_EN, 1)?;
            self.wm(R_S0_DACKQ, B_S0_DACKQ_EN, 1)?;
            self.wm(R_P0_NRBW, B_P0_NRBW_DBG, 1)?;
            for i in 0..16u32 {
                self.wm(R_S0_DACKI, B_S0_DACKI_AR, i)?;
                results.msbk[p][0][i as usize] = self.bb(R_S0_DACKI7, B_S0_DACKI7_K)? as u8;
                self.wm(R_S0_DACKQ, B_S0_DACKQ_AR, i)?;
                results.msbk[p][1][i as usize] = self.bb(R_S0_DACKQ7, B_S0_DACKQ7_K)? as u8;
            }
            results.biask[p] = [
                self.bb(R_S0_DACKI2, B_S0_DACKI2_K)? as u16,
                self.bb(R_S0_DACKQ2, B_S0_DACKQ2_K)? as u16,
            ];
            results.dadck[p] = [
                (self.bb(R_S0_DACKI8, B_S0_DACKI8_K)? as u8).wrapping_sub(8),
                (self.bb(R_S0_DACKQ8, B_S0_DACKQ8_K)? as u8).wrapping_sub(8),
            ];
        } else {
            self.wm(R_S1_DACKI, B_S1_DACKI_EN, 1)?;
            self.wm(R_S1_DACKQ, B_S1_DACKQ_EN, 1)?;
            self.wm(R_P1_DBGMOD, B_P1_DBGMOD_ON, 1)?;
            for i in 0..16u32 {
                self.wm(R_S1_DACKI, B_S1_DACKI_AR, i)?;
                results.msbk[p][0][i as usize] = self.bb(R_S1_DACKI7, B_S1_DACKI_K)? as u8;
                self.wm(R_S1_DACKQ, B_S1_DACKQ_AR, i)?;
                results.msbk[p][1][i as usize] = self.bb(R_S1_DACKQ7, B_S1_DACKQ7_K)? as u8;
            }
            results.biask[p] = [
                self.bb(R_S1_DACKI2, B_S1_DACKI2_K)? as u16,
                self.bb(R_S1_DACKQ2, B_S1_DACKQ2_K)? as u16,
            ];
            results.dadck[p] = [
                (self.bb(R_S1_DACKI8, B_S1_DACKI8_K)? as u8).wrapping_sub(8),
                (self.bb(R_S1_DACKQ8, B_S1_DACKQ8_K)? as u8).wrapping_sub(8),
            ];
        }
        Ok(())
    }
    /// `_dack_reload_by_path(path, index)`: `idx_offset` 0/0x50,
    /// `path_offset` 0/0x2000, four MSBK words then the bias/DADCK word.
    fn a_dack_reload_by_path(
        &mut self,
        path: u8,
        index: usize,
        results: &Results,
    ) -> Result<(), Error> {
        let idx_offset = if index == 0 { 0 } else { 0x50 };
        let path_offset = if path == 0 { 0 } else { 0x2000 };
        let offset = idx_offset + path_offset;
        let p = usize::from(path);
        let msbk = &results.msbk[p][index];
        for (slot, first) in [12usize, 8, 4, 0].into_iter().enumerate() {
            let value = u32::from_le_bytes([
                msbk[first],
                msbk[first + 1],
                msbk[first + 2],
                msbk[first + 3],
            ]);
            self.0.admit()?;
            self.0.write32(
                0x10000 + R_DACK_RELOAD_MSBK + offset + 4 * slot as u32,
                value,
            )?;
        }
        let value =
            (u32::from(results.biask[p][index]) << 22) | (u32::from(results.dadck[p][index]) << 14);
        self.0.admit()?;
        self.0
            .write32(0x10000 + R_DACK_RELOAD_BIAS + offset, value)?;
        Ok(())
    }
    /// `_dack_reload`: both indices, then the per-path reload def table.
    async fn a_dack_reload(&mut self, path: u8, results: &Results) -> Result<(), Error> {
        for index in 0..2usize {
            self.a_dack_reload_by_path(path, index, results)?;
        }
        self.table(if path == 0 {
            DACK_RELOAD_A
        } else {
            DACK_RELOAD_B
        })
        .await
    }
    /// `_dack_s0` / `_dack_s1`: F table, both MSBK polls, M table, both
    /// DADCK polls, R table, `_check_dadc`, backup, reload, DBG clear.
    /// Linux `ret |=` runs the second poll even if the first timed out
    /// and only logs; NARF fails closed on the first, strictly earlier.
    async fn a_dack_path(&mut self, path: u8, results: &mut Results) -> Result<(), Error> {
        let (f, m, r, msbk_i, msbk_q, dadck_i, dadck_q, nrbw, dbg) = if path == 0 {
            (
                DACK_F_A,
                DACK_M_A,
                DACK_R_A,
                R_S0_DACK_MSBK_I,
                R_S0_DACK_MSBK_Q,
                R_S0_DACKI8,
                R_S0_DACKQ8,
                R_P0_NRBW,
                B_P0_NRBW_DBG,
            )
        } else {
            (
                DACK_F_B,
                DACK_M_B,
                DACK_R_B,
                R_S1_DACK_MSBK_I,
                R_S1_DACK_MSBK_Q,
                R_S1_DACKI8,
                R_S1_DACKQ8,
                R_P1_DBGMOD,
                B_P1_DBGMOD_ON,
            )
        };
        self.table(f).await?;
        self.poll(msbk_i, 1 << 15, 1, 10_000).await?;
        self.poll(msbk_q, 1 << 15, 1, 10_000).await?;
        self.table(m).await?;
        self.poll(dadck_i, 1 << 17, 1, 10_000).await?;
        self.poll(dadck_q, 1 << 17, 1, 10_000).await?;
        self.table(r).await?;
        self.a_check_dadc(path).await?;
        self.a_dack_backup(path, results)?;
        self.a_dack_reload(path, results).await?;
        self.wm(nrbw, dbg, 0)
    }
    /// `_dac_cal`: no `_drck`, no `R_AX_PHYREG_SET` (unlike B); AFE init,
    /// `RR_MOD` 0x30001, ADDCK + backup + reload, `RR_MOD` 0x40001 and
    /// `RR_MODOPT` 0, DACK both paths, restore `RR_MOD`/`RR_RSV1`.
    async fn a_dac(&mut self, results: &mut Results) -> Result<(), Error> {
        let saved = [
            self.rr(0, RR_MOD, RFREG_MASK).await?,
            self.rr(1, RR_MOD, RFREG_MASK).await?,
        ];
        self.table(AFE_INIT).await?;
        self.wr(0, RR_RSV1, RR_RSV1_RST, 0).await?;
        self.wr(1, RR_RSV1, RR_RSV1_RST, 0).await?;
        self.wr(0, RR_MOD, RFREG_MASK, 0x30001).await?;
        self.wr(1, RR_MOD, RFREG_MASK, 0x30001).await?;
        self.a_addck().await?;
        self.a_addck_backup(results)?;
        self.a_addck_reload(results)?;
        self.wr(0, RR_MOD, RFREG_MASK, 0x40001).await?;
        self.wr(1, RR_MOD, RFREG_MASK, 0x40001).await?;
        self.wr(0, RR_MODOPT, RFREG_MASK, 0).await?;
        self.wr(1, RR_MODOPT, RFREG_MASK, 0).await?;
        self.a_dack_path(0, results).await?;
        self.a_dack_path(1, results).await?;
        self.wr(0, RR_MOD, RFREG_MASK, saved[0]).await?;
        self.wr(1, RR_MOD, RFREG_MASK, saved[1]).await?;
        self.wr(0, RR_RSV1, RR_RSV1_RST, 1).await?;
        self.wr(1, RR_RSV1, RR_RSV1_RST, 1).await
    }
    /// `_set_rx_dck(phy, path, is_afe)`: the AFE variant sets DBG/RXCK/
    /// RXDC2/ANAPAR, drives `RR_DCK2` cycle 0x3f and `RR_DCK1_SEL` =
    /// `is_afe`, toggles `RR_DCK_LV` 0 -> 1, sleeps 600us, toggles back,
    /// and restores the full saved RXCK word. The RFC variant
    /// (`is_afe = false`) skips the AFE setup/restore.
    async fn a_set_rx_dck(&mut self, path: u8, is_afe: bool) -> Result<(), Error> {
        let rxck = R_P0_RXCK + (u32::from(path) << 13);
        let nrbw = R_P0_NRBW + (u32::from(path) << 13);
        let rxdc2 = R_S0_RXDC2 + (u32::from(path) << 13);
        let ori_val = self.bb(rxck, u32::MAX)?;
        if is_afe {
            self.wm(nrbw, B_P0_NRBW_DBG, 1)?;
            self.wm(rxck, B_P0_RXCK_ON, 1)?;
            self.wm(rxck, B_P0_RXCK_VAL, 0x3)?;
            // write32_set: the whole MEN/AVG field is set, so the field
            // value is 3, not 1 (wm shifts the field value into the mask).
            self.wm(rxdc2, B_S0_RXDC2_MEN, 3)?;
            self.wm(rxdc2, B_S0_RXDC2_AVG, 3)?;
            self.wm(R_ANAPAR_PW15, B_ANAPAR_PW15_H, 0x3)?;
            self.wm(R_ANAPAR, B_ANAPAR_ADCCLK, 0)?;
            self.wm(R_ANAPAR, B_ANAPAR_FLTRST, 0)?;
            self.wm(R_ANAPAR, B_ANAPAR_FLTRST, 1)?;
            self.wm(R_ANAPAR, B_ANAPAR_CRXBB, 0x1)?;
        }
        self.wr(path, RR_DCK2, RR_DCK2_CYCLE, 0x3f).await?;
        self.wr(path, RR_DCK1, RR_DCK1_SEL, u32::from(is_afe))
            .await?;
        self.wr(path, RR_DCK, RR_DCK_LV, 0).await?;
        self.wr(path, RR_DCK, RR_DCK_LV, 1).await?;
        self.delay(600).await?;
        self.wr(path, RR_DCK, RR_DCK_LV, 0).await?;
        if is_afe {
            self.wm(nrbw, B_P0_NRBW_DBG, 0)?;
            self.0.admit()?;
            self.0.write32(0x10000 + rxck, ori_val)?;
        }
        Ok(())
    }
    /// `_rx_dck(PHY_0, is_afe)`: non-DBCC `_kpath` = RF_AB, both paths,
    /// with the per-path TSSI pause and the saved DCK fine tune.
    async fn a_rx_dck(&mut self, tssi_mode: [bool; 2], is_afe: bool) -> Result<(), Error> {
        for path in 0..2u8 {
            let saved = self.rr(path, RR_RSV1, RFREG_MASK).await?;
            let tune = self.rr(path, RR_DCK, RR_DCK_FINE).await?;
            let trk = R_P0_TSSI_TRK + (u32::from(path) << 13);
            if tssi_mode[usize::from(path)] {
                self.wm(trk, B_P0_TSSI_TRK_EN, 1)?;
            }
            self.wr(path, RR_RSV1, RR_RSV1_RST, 0).await?;
            self.wr(path, RR_DCK, RR_DCK_FINE, 0).await?;
            self.wr(path, RR_MOD, RR_MOD_MASK, RR_MOD_V_RX).await?;
            self.a_set_rx_dck(path, is_afe).await?;
            self.wr(path, RR_DCK, RR_DCK_FINE, tune).await?;
            self.wr(path, RR_RSV1, RFREG_MASK, saved).await?;
            if tssi_mode[usize::from(path)] {
                self.wm(trk, B_P0_TSSI_TRK_EN, 0)?;
            }
        }
        Ok(())
    }
    /// `rtw8852a_rx_dck`: BTC RXDCK START, stop_sch_tx (pause),
    /// `_wait_rx_mode` per path (poll `RR_MOD` != 2, 2us/5000us), the RX
    /// DCK itself, resume, BTC STOP.
    async fn a_channel_rxdck(&mut self, tssi_mode: [bool; 2], is_afe: bool) -> Result<(), Error> {
        self.0.admit()?;
        self.0.begin(Kind::Rxdck).await?;
        let saved = self.0.pause().await?;
        for path in 0..2u8 {
            let start = self.0.now_us();
            loop {
                if self.rr(path, RR_MOD, RR_MOD_MASK).await? != 2 {
                    break;
                }
                if self.0.now_us().saturating_sub(start) >= 5000 {
                    return Err(power::Error::Timeout.into());
                }
                self.delay(2).await?;
            }
        }
        self.a_rx_dck(tssi_mode, is_afe).await?;
        self.0.resume(saved).await?;
        self.0.end(Kind::Rxdck).await?;
        Ok(())
    }
}

impl Init {
    pub fn state(&self) -> State {
        self.state
    }
    pub fn results(&self) -> Option<&Results> {
        (self.state == State::BasicCalibrated).then_some(&self.results)
    }
    /// rtw8852a.c `rtw8852a_rfk_init`: `is_tssi_mode[A/B] = false`, RCK A
    /// then B, DACK bracketed by `BTC_WRFKT_DACK` START/STOP, then the
    /// AFE initial RX DCK (bracketed by `BTC_WRFKT_RXDCK` START/STOP with
    /// the scheduler pause, as `rtw8852a_rx_dck` does).
    ///
    /// # Safety
    /// Actual RTL8852A PHY0 (non-DBCC), completed A factory/BB/RF/NCTL
    /// tables; current admission is enforced by Interface before every
    /// access. No concurrent reset/PHY/PM/packet owner; the outer attempt
    /// closes and retains DMA on cancellation or failure.
    pub async unsafe fn prepare(&mut self, io: &mut impl Interface) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        self.state = State::Calibrating;
        io.admit()?;
        let mut access = Access(io);
        for path in 0..2 {
            self.results.rck[usize::from(path)] = access.a_rck(path).await?;
        }
        access.0.admit()?;
        access.0.begin(Kind::Dack).await?;
        access.a_dac(&mut self.results).await?;
        access.0.end(Kind::Dack).await?;
        access.a_channel_rxdck([false; 2], true).await?;
        self.state = State::BasicCalibrated;
        Ok(())
    }
}

/// Fresh one-shot channel RXDCK, distinct from the earlier RF-init occurrence.
#[derive(Default)]
pub(in super::super) struct ChannelRxDck {
    state: State,
}
impl ChannelRxDck {
    pub fn state(&self) -> State {
        self.state
    }
    /// The `rtw8852a_rx_dck(phy_idx, is_afe = true)` of
    /// `rtw8852a_rfk_channel`, after `rtw89_btc_ntfy_conn_rfk(true)`.
    ///
    /// # Safety
    /// Same retained RTL8852A owner after a completed [`Init`] and
    /// channel program; `tssi_mode` must be the actual retained TSSI state.
    pub async unsafe fn prepare(
        &mut self,
        io: &mut impl Interface,
        tssi_mode: bool,
    ) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        self.state = State::Calibrating;
        Access(io).a_channel_rxdck([tssi_mode; 2], true).await?;
        self.state = State::BasicCalibrated;
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "a_tests.rs"]
mod tests;
