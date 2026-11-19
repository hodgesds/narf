// SPDX-License-Identifier: GPL-2.0-or-later
//! Wi-Fi/Bluetooth coexistence state machine (`coex`, continuation tag `K`).
//!
//! Port of Linux rtw88 `coex.c` for the admitted RTL8821CE (C21) and
//! RTL8822CE (C22) bases: `rtw_coex_power_on_setting`,
//! `__rtw_coex_init_hw_config`, the IPS/LPS/scan/switch-band/connect/
//! media-status notifications, `rtw_coex_bt_info_notify` (C2H 0x09),
//! `rtw_coex_bt_hid_info_notify` (C2H 0x45), the BT MP info response
//! (C2H 0x0b), `rtw_coex_wl_fwdbginfo_notify` (C2H 0x27),
//! `rtw_coex_run_coex` with every action, the delayed works and the
//! watchdog hooks (`rtw_coex_wl_status_check`,
//! `rtw_coex_wl_status_change_notify`, `rtw_coex_query_bt_hid_list`), plus
//! the per-chip hooks and tables of `rtw8821c.c` / `rtw8822c.c`
//! (`coex_cfg_init`, `coex_cfg_ant_switch`, `coex_cfg_gnt_fix`,
//! `coex_cfg_gnt_debug`, `coex_cfg_rfe_type`, `coex_cfg_wl_tx_power`,
//! `coex_cfg_wl_rx_gain`, `table_{sant,nsant}`, `tdma_{sant,nsant}`,
//! `rf_para_{tx,rx}`, RSSI steps, AFH spans).
//!
//! Nothing here runs without a separately signed `N2xK` continuation. Its
//! payload names the efuse antenna facts it was measured on (`share_ant`
//! from `bt_setting` bit0, `rfe_option`, `btcoex` from `rf_board_option`,
//! exactly as `main.c::rtw_parse_efuse_map`/`rtw_chip_efuse_info_setup`
//! derive them) and the coexistence families the board was qualified for.
//! A record whose facts differ from the retained efuse never binds; an
//! action needing a family the record does not carry is refused
//! ([`Error::Unsupported`]) and the station restores the base program.
//!
//! Every hardware register this owner touches is backed up on first write
//! and restored, in reverse order, when the owner is unbound or fails
//! ([`Coex::restore`]). H2C commands are returned to the caller, which
//! sends them through the retained mailbox under the same authority.
use super::dm::Authority;
use super::firmware_transport::{enclosed, Error, Io};
use super::qualification::{Kind, PAYLOAD};
use alloc::vec::Vec;

/// PTA/scoreboard/antenna-path program: power-on/init, WL-only/BT-off,
/// not-connected, all-off, coexistence tables and TDMA *off*.
pub(super) const PTA: u8 = 1 << 0;
/// PS-TDMA (H2C 0x60 with TDMA on) and the BT-profile actions using it.
pub(super) const TDMA: u8 = 1 << 1;
/// Non-shared-antenna freerun and every RF parameter set other than the
/// normal one (`wl_rf_para_{tx,rx}[1..]`: WL TX power decrease level, WL RX
/// low gain, BT TX power decrease and BT LNA constraint).
pub(super) const FREERUN: u8 = 1 << 2;
/// Pure-5GHz action (`rtw_coex_action_wl_under5g`).
pub(super) const BAND5: u8 = 1 << 3;
/// RTL8822C coexistence-driven 1SS (`rtw_coex_mimo_ps`, `wl_mimo_ps_support`).
pub(super) const MIMO_PS: u8 = 1 << 4;
const C21_MODES: u8 = PTA | TDMA | FREERUN | BAND5;
const C22_MODES: u8 = PTA | TDMA | FREERUN | BAND5 | MIMO_PS;
/// The watchdog period (`RTW_WATCH_DOG_DELAY_TIME`).
pub(super) const PERIOD_MS: u64 = 2000;
/// `rtw8822c.c::rtw8822c_config_trx_mode(rtwdev, BB_PATH_A, BB_PATH_A,
/// false)` as `(register, field mask, 1SS value, bb_reset after)` in source
/// order: ORITXCODE/ORITXCODE2, `config_cck_rx_path(A)`,
/// `config_ofdm_rx_path(A)`, `config_cck_tx_path(A)`,
/// `config_ofdm_tx_path(A)`.
const TRX_1SS: &[(u16, u32, u32, bool)] = &[
    (0x1800, 0x000f_ffff, 0x33312, false),
    (0x4100, 0x000f_ffff, 0x11111, false),
    (0x1a2c, 0x0006_0000, 0, false),
    (0x1a2c, 0x0060_0000, 0, false),
    (0x1a04, 0x0f00_0000, 0, false),
    (0x1d30, 0x0000_0300, 0, false),
    (0x1d30, 0x0060_0000, 0, false),
    (0x0c44, 1 << 17, 0, false),
    (0x0c54, 1 << 20, 0, false),
    (0x0c38, 1 << 24, 0, false),
    (0x0824, 0x0f00_0000, 1, false),
    (0x0824, 0x000f_0000, 1, false),
    (0x1a04, 0xf000_0000, 8, true),
    (0x0820, 0x0000_00ff, 0x11, false),
    (0x1e2c, 0x0000_00ff, 0, true),
];

pub(super) static KIND: Kind = Kind {
    tag: b'K',
    stem: "coex",
    source: SOURCE,
    admit,
};
const SOURCE: &[u8] = b"Linux rtw88 v6.12 coex.c: power_on_setting 02|=3 ant POWERON table1 ff1a=0 gnt_debug; init_hw_config kt_ver f1[7:4] slot_extend h2c69 0c, \
550 bit3, rfe_type, set_init, wlpri 3/4/27, ant INIT|WONLY scbd aa ACTIVE|ONOFF|bit15, table1 tdma0 query h2c61; ips/lps/scan/switchband/connect/media notify, \
bt_info c2h09 src iqk/scbd/h2c60/wlfw/rsp/act len7 lb2/lb3/hb0..3, hid c2h45 list/a mtk46 ps/xb, mp c2h0b scan_type op2d lna op32 h2c67, fwdbg c2h27 08 ccklock, \
run_coex 5g/bt_disabled/native_lps/game_hid/whql/relink/inquiry/idle/linkscan/connected algo hfp/hid/a2dp/pan/a2dp_hid/a2dp_pan/pan_hid/a2dp_pan_hid freerun, \
mimo_ps 2GFREE, gnt_fix, limited_wl 45e bit3 426 0f 42a 0808 430 1000000 434 4030201 455 20, tdma h2c60 timer h2c69 0b c1/01/tbtt, toggle 0d/07, \
tables 6c0/6c4/6c8 f0ffffff, wl_ch_info h2c66 24/36, bt_pwr h2c62, ignore h2c63, ltecoex 1700/1704/1708 38 a0 a4 gnt c000/0c00/3000/0300, ctrl owner 73 bit2, \
8821c init 550/790/778/40/4c6/762/6cf ant switch 4c/cb4/67 rfe 0..15 rssi{101,45,101,40}/{101x4} ratio; \
8822c init +4fc rf b01 40000 gnt_fix rf b01 1c32/1c39/1c3b/4160/1860/1ca7 rx_gain rf de/1d 22/36 20/00 rssi{60,50,44,30}/{8,15,20,25} dbm; delayed works 1/6/15/5/12/4/2/3/3s; \
mimo_ps 8822c rtw_set_txrx_1ss config_trx_mode(A,A) 1800=33312 4100=11111 1a2c[18:17][22:21]=0 1a04[27:24]=0 1d30[9:8][22:21]=0 c44[17] c54[20] c38[24]=0 824=1/1 1a04[31:28]=8 bb_reset 820=11 1e2c[7:0]=0 bb_reset bb_reset toggle_igi, exit restores the fields; RA 1SS mask, STBC off, SMPS static/disabled action";

fn admit(did: u16, p: &[u8; PAYLOAD]) -> bool {
    record(did, p).is_some()
}

/// The signed qualification envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Record {
    pub(super) modes: u8,
    pub(super) share_ant: bool,
    pub(super) rfe: u8,
    pub(super) btcoex: bool,
}

pub(super) fn record(did: u16, p: &[u8; PAYLOAD]) -> Option<Record> {
    let allowed = match did {
        0xc821 => C21_MODES,
        0xc822 => C22_MODES,
        _ => return None,
    };
    let r = Record {
        modes: p[0],
        share_ant: p[1] == 1,
        rfe: p[2],
        btcoex: p[3] == 1,
    };
    if r.modes & PTA == 0
        || r.modes & !allowed != 0
        || p[1] > 1
        || p[3] > 1
        // A WL-only board stops the mechanism after init (stop_dm).
        || (!r.btcoex && r.modes != PTA)
        || p[4..].iter().any(|&v| v != 0)
    {
        return None;
    }
    Some(r)
}

/// Retained efuse antenna facts (`rtw_efuse`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Facts {
    pub(super) did: u16,
    /// `efuse.rfe_option`.
    pub(super) rfe: u8,
    /// Raw `rf_board_option` byte (0xff when erased).
    pub(super) board_option: u8,
    /// Raw `bt_setting` byte.
    pub(super) bt_setting: u8,
}
impl Facts {
    fn c22(&self) -> bool {
        self.did == 0xc822
    }
    /// `main.c`: `if (efuse->bt_setting & BIT(0)) efuse->share_ant = true`.
    pub(super) fn share_ant(&self) -> bool {
        self.bt_setting & 1 != 0
    }
    /// `efuse->btcoex = (rf_board_option & 0xe0) == 0x20` after the
    /// erased-value normalisation to 0.
    pub(super) fn btcoex(&self) -> bool {
        let o = if self.board_option == 0xff {
            0
        } else {
            self.board_option
        };
        o & 0xe0 == 0x20
    }
    /// The record must have been qualified on exactly these facts.
    pub(super) fn qualifies(&self, r: &Record) -> bool {
        r.share_ant == self.share_ant() && r.rfe == self.rfe && r.btcoex == self.btcoex()
    }
}

struct Chip {
    table_sant: &'static [(u32, u32)],
    table_nsant: &'static [(u32, u32)],
    tdma_sant: &'static [[u8; 5]],
    tdma_nsant: &'static [[u8; 5]],
    wl_rssi_step: [u8; 4],
    bt_rssi_step: [u8; 4],
    /// (wl_pwr_dec_lvl, bt_pwr_dec_lvl, wl_low_gain_en, bt_lna_lvl)
    rf_tx: &'static [(u8, u8, bool, u8)],
    rf_rx: &'static [(u8, u8, bool, u8)],
    new_scbd10_def: bool,
    ble_hid_profile_support: bool,
    bt_rssi_ratio: bool,
}

// rtw8821c.c
const TABLE_SANT_8821C: [(u32, u32); 38] = [
    (0x55555555, 0x55555555),
    (0x55555555, 0x55555555),
    (0x66555555, 0x66555555),
    (0xaaaaaaaa, 0xaaaaaaaa),
    (0x5a5a5a5a, 0x5a5a5a5a),
    (0xfafafafa, 0xfafafafa),
    (0x6a5a5555, 0xaaaaaaaa),
    (0x6a5a56aa, 0x6a5a56aa),
    (0x6a5a5a5a, 0x6a5a5a5a),
    (0x66555555, 0x5a5a5a5a),
    (0x66555555, 0x6a5a5a5a),
    (0x66555555, 0xaaaaaaaa),
    (0x66555555, 0x6a5a5aaa),
    (0x66555555, 0x6aaa6aaa),
    (0x66555555, 0x6a5a5aaa),
    (0x66555555, 0xaaaaaaaa),
    (0xffff55ff, 0xfafafafa),
    (0xffff55ff, 0x6afa5afa),
    (0xaaffffaa, 0xfafafafa),
    (0xaa5555aa, 0x5a5a5a5a),
    (0xaa5555aa, 0x6a5a5a5a),
    (0xaa5555aa, 0xaaaaaaaa),
    (0xffffffff, 0x55555555),
    (0xffffffff, 0x5a5a5a5a),
    (0xffffffff, 0x5a5a5a5a),
    (0xffffffff, 0x5a5a5aaa),
    (0x55555555, 0x5a5a5a5a),
    (0x55555555, 0xaaaaaaaa),
    (0x66555555, 0x6a5a6a5a),
    (0x66556655, 0x66556655),
    (0x66556aaa, 0x6a5a6aaa),
    (0xffffffff, 0x5aaa5aaa),
    (0x56555555, 0x5a5a5aaa),
    (0xdaffdaff, 0xdaffdaff),
    (0xddffddff, 0xddffddff),
    (0xe5555555, 0xe5555555),
    (0xea5a5a5a, 0xea5a5a5a),
    (0xea6a6a6a, 0xea6a6a6a),
];
const TABLE_NSANT_8821C: [(u32, u32); 24] = [
    (0xffffffff, 0xffffffff),
    (0xffff55ff, 0xfafafafa),
    (0x66555555, 0x66555555),
    (0xaaaaaaaa, 0xaaaaaaaa),
    (0x5a5a5a5a, 0x5a5a5a5a),
    (0xffffffff, 0xffffffff),
    (0x5afa5afa, 0x5afa5afa),
    (0x55555555, 0xfafafafa),
    (0x66555555, 0xfafafafa),
    (0x66555555, 0x5a5a5a5a),
    (0x66555555, 0x6a5a5a5a),
    (0x66555555, 0xaaaaaaaa),
    (0xffff55ff, 0xfafafafa),
    (0xffff55ff, 0x5afa5afa),
    (0xffff55ff, 0xaaaaaaaa),
    (0xffff55ff, 0xffff55ff),
    (0xaaffffaa, 0x5afa5afa),
    (0xaaffffaa, 0xaaaaaaaa),
    (0xffffffff, 0xfafafafa),
    (0xffff55ff, 0xfafafafa),
    (0xffffffff, 0xaaaaaaaa),
    (0xffff55ff, 0x5afa5afa),
    (0xffff55ff, 0x5afa5afa),
    (0x55ff55ff, 0x55ff55ff),
];
const TDMA_SANT_8821C: [[u8; 5]; 28] = [
    [0x00, 0x00, 0x00, 0x00, 0x00],
    [0x61, 0x45, 0x03, 0x11, 0x11],
    [0x61, 0x3a, 0x03, 0x11, 0x11],
    [0x61, 0x35, 0x03, 0x11, 0x11],
    [0x61, 0x20, 0x03, 0x11, 0x11],
    [0x61, 0x3a, 0x03, 0x11, 0x11],
    [0x61, 0x45, 0x03, 0x11, 0x10],
    [0x61, 0x35, 0x03, 0x11, 0x10],
    [0x61, 0x30, 0x03, 0x11, 0x10],
    [0x61, 0x20, 0x03, 0x11, 0x10],
    [0x61, 0x10, 0x03, 0x11, 0x10],
    [0x61, 0x08, 0x03, 0x11, 0x15],
    [0x61, 0x08, 0x03, 0x10, 0x14],
    [0x51, 0x08, 0x03, 0x10, 0x54],
    [0x51, 0x08, 0x03, 0x10, 0x55],
    [0x51, 0x08, 0x07, 0x10, 0x54],
    [0x51, 0x45, 0x03, 0x10, 0x50],
    [0x51, 0x3a, 0x03, 0x11, 0x50],
    [0x51, 0x30, 0x03, 0x10, 0x50],
    [0x51, 0x21, 0x03, 0x10, 0x50],
    [0x51, 0x10, 0x03, 0x10, 0x50],
    [0x51, 0x4a, 0x03, 0x10, 0x50],
    [0x51, 0x08, 0x03, 0x30, 0x54],
    [0x55, 0x08, 0x03, 0x10, 0x54],
    [0x65, 0x10, 0x03, 0x11, 0x10],
    [0x51, 0x10, 0x03, 0x10, 0x51],
    [0x51, 0x21, 0x03, 0x10, 0x50],
    [0x61, 0x08, 0x03, 0x11, 0x11],
];
const TDMA_NSANT_8821C: [[u8; 5]; 22] = [
    [0x00, 0x00, 0x00, 0x40, 0x00],
    [0x61, 0x45, 0x03, 0x11, 0x11],
    [0x61, 0x25, 0x03, 0x11, 0x11],
    [0x61, 0x35, 0x03, 0x11, 0x11],
    [0x61, 0x20, 0x03, 0x11, 0x11],
    [0x61, 0x10, 0x03, 0x11, 0x11],
    [0x61, 0x45, 0x03, 0x11, 0x10],
    [0x61, 0x30, 0x03, 0x11, 0x10],
    [0x61, 0x30, 0x03, 0x11, 0x10],
    [0x61, 0x20, 0x03, 0x11, 0x10],
    [0x61, 0x10, 0x03, 0x11, 0x10],
    [0x61, 0x10, 0x03, 0x11, 0x11],
    [0x61, 0x08, 0x03, 0x10, 0x14],
    [0x51, 0x08, 0x03, 0x10, 0x54],
    [0x51, 0x08, 0x03, 0x10, 0x55],
    [0x51, 0x08, 0x07, 0x10, 0x54],
    [0x51, 0x45, 0x03, 0x10, 0x50],
    [0x51, 0x3a, 0x03, 0x10, 0x50],
    [0x51, 0x30, 0x03, 0x10, 0x50],
    [0x51, 0x21, 0x03, 0x10, 0x50],
    [0x51, 0x21, 0x03, 0x10, 0x50],
    [0x51, 0x10, 0x03, 0x10, 0x50],
];
const RF_TX_8821C: [(u8, u8, bool, u8); 6] = [
    (0, 0, false, 7),
    (0, 20, false, 7),
    (8, 17, true, 4),
    (7, 18, true, 4),
    (6, 19, true, 4),
    (5, 20, true, 4),
];
const RF_RX_8821C: [(u8, u8, bool, u8); 6] = [
    (0, 0, false, 7),
    (0, 20, false, 7),
    (3, 24, true, 5),
    (2, 26, true, 5),
    (1, 27, true, 5),
    (0, 28, true, 5),
];
// rtw8822c.c
const TABLE_SANT_8822C: [(u32, u32); 38] = [
    (0xffffffff, 0xffffffff),
    (0x55555555, 0x55555555),
    (0x66555555, 0x66555555),
    (0xaaaaaaaa, 0xaaaaaaaa),
    (0x5a5a5a5a, 0x5a5a5a5a),
    (0xfafafafa, 0xfafafafa),
    (0x6a5a5555, 0xaaaaaaaa),
    (0x6a5a56aa, 0x6a5a56aa),
    (0x6a5a5a5a, 0x6a5a5a5a),
    (0x66555555, 0x5a5a5a5a),
    (0x66555555, 0x6a5a5a5a),
    (0x66555555, 0x6a5a5aaa),
    (0x66555555, 0x5a5a5aaa),
    (0x66555555, 0x6aaa5aaa),
    (0x66555555, 0xaaaa5aaa),
    (0x66555555, 0xaaaaaaaa),
    (0xffff55ff, 0xfafafafa),
    (0xffff55ff, 0x6afa5afa),
    (0xaaffffaa, 0xfafafafa),
    (0xaa5555aa, 0x5a5a5a5a),
    (0xaa5555aa, 0x6a5a5a5a),
    (0xaa5555aa, 0xaaaaaaaa),
    (0xffffffff, 0x5a5a5a5a),
    (0xffffffff, 0x5a5a5a5a),
    (0xffffffff, 0x55555555),
    (0xffffffff, 0x5a5a5aaa),
    (0x55555555, 0x5a5a5a5a),
    (0x55555555, 0xaaaaaaaa),
    (0x55555555, 0x6a5a6a5a),
    (0x66556655, 0x66556655),
    (0x66556aaa, 0x6a5a6aaa),
    (0xffffffff, 0x5aaa5aaa),
    (0x56555555, 0x5a5a5aaa),
    (0xdaffdaff, 0xdaffdaff),
    (0xddffddff, 0xddffddff),
    (0xe5555555, 0xe5555555),
    (0xea5a5a5a, 0xea5a5a5a),
    (0xea6a6a6a, 0xea6a6a6a),
];
const TABLE_NSANT_8822C: [(u32, u32); 24] = [
    (0xffffffff, 0xffffffff),
    (0x55555555, 0x55555555),
    (0x66555555, 0x66555555),
    (0xaaaaaaaa, 0xaaaaaaaa),
    (0x5a5a5a5a, 0x5a5a5a5a),
    (0xfafafafa, 0xfafafafa),
    (0x5afa5afa, 0x5afa5afa),
    (0x55555555, 0xfafafafa),
    (0x66555555, 0xfafafafa),
    (0x66555555, 0x5a5a5a5a),
    (0x66555555, 0x6a5a5a5a),
    (0x66555555, 0xaaaaaaaa),
    (0xffff55ff, 0xfafafafa),
    (0xffff55ff, 0x5afa5afa),
    (0xffff55ff, 0xaaaaaaaa),
    (0xffff55ff, 0xffff55ff),
    (0xaaffffaa, 0x5afa5afa),
    (0xaaffffaa, 0xaaaaaaaa),
    (0xffffffff, 0xfafafafa),
    (0xffffffff, 0x5afa5afa),
    (0xffffffff, 0xaaaaaaaa),
    (0x55ff55ff, 0x5afa5afa),
    (0x55ff55ff, 0xaaaaaaaa),
    (0x55ff55ff, 0x55ff55ff),
];
const TDMA_SANT_8822C: [[u8; 5]; 28] = [
    [0x00, 0x00, 0x00, 0x00, 0x00],
    [0x61, 0x45, 0x03, 0x11, 0x11],
    [0x61, 0x3a, 0x03, 0x11, 0x11],
    [0x61, 0x30, 0x03, 0x11, 0x11],
    [0x61, 0x20, 0x03, 0x11, 0x11],
    [0x61, 0x10, 0x03, 0x11, 0x11],
    [0x61, 0x45, 0x03, 0x11, 0x10],
    [0x61, 0x3a, 0x03, 0x11, 0x10],
    [0x61, 0x30, 0x03, 0x11, 0x10],
    [0x61, 0x20, 0x03, 0x11, 0x10],
    [0x61, 0x10, 0x03, 0x11, 0x10],
    [0x61, 0x08, 0x03, 0x11, 0x14],
    [0x61, 0x08, 0x03, 0x10, 0x14],
    [0x51, 0x08, 0x03, 0x10, 0x54],
    [0x51, 0x08, 0x03, 0x10, 0x55],
    [0x51, 0x08, 0x07, 0x10, 0x54],
    [0x51, 0x45, 0x03, 0x10, 0x50],
    [0x51, 0x3a, 0x03, 0x10, 0x50],
    [0x51, 0x30, 0x03, 0x10, 0x50],
    [0x51, 0x20, 0x03, 0x10, 0x50],
    [0x51, 0x10, 0x03, 0x10, 0x50],
    [0x51, 0x4a, 0x03, 0x10, 0x50],
    [0x51, 0x0c, 0x03, 0x10, 0x54],
    [0x55, 0x08, 0x03, 0x10, 0x54],
    [0x65, 0x10, 0x03, 0x11, 0x10],
    [0x51, 0x10, 0x03, 0x10, 0x51],
    [0x51, 0x08, 0x03, 0x10, 0x50],
    [0x61, 0x08, 0x03, 0x11, 0x11],
];
const TDMA_NSANT_8822C: [[u8; 5]; 22] = [
    [0x00, 0x00, 0x00, 0x00, 0x00],
    [0x61, 0x45, 0x03, 0x11, 0x11],
    [0x61, 0x3a, 0x03, 0x11, 0x11],
    [0x61, 0x30, 0x03, 0x11, 0x11],
    [0x61, 0x20, 0x03, 0x11, 0x11],
    [0x61, 0x10, 0x03, 0x11, 0x11],
    [0x61, 0x45, 0x03, 0x11, 0x10],
    [0x61, 0x3a, 0x03, 0x11, 0x10],
    [0x61, 0x30, 0x03, 0x11, 0x10],
    [0x61, 0x20, 0x03, 0x11, 0x10],
    [0x61, 0x10, 0x03, 0x11, 0x10],
    [0x61, 0x08, 0x03, 0x11, 0x14],
    [0x61, 0x08, 0x03, 0x10, 0x14],
    [0x51, 0x08, 0x03, 0x10, 0x54],
    [0x51, 0x08, 0x03, 0x10, 0x55],
    [0x51, 0x08, 0x07, 0x10, 0x54],
    [0x51, 0x45, 0x03, 0x10, 0x50],
    [0x51, 0x3a, 0x03, 0x10, 0x50],
    [0x51, 0x30, 0x03, 0x10, 0x50],
    [0x51, 0x20, 0x03, 0x10, 0x50],
    [0x51, 0x10, 0x03, 0x10, 0x50],
    [0x51, 0x08, 0x03, 0x10, 0x50],
];
const RF_TX_8822C: [(u8, u8, bool, u8); 7] = [
    (0, 0, false, 7),
    (0, 16, false, 7),
    (8, 17, true, 4),
    (7, 18, true, 4),
    (6, 19, true, 4),
    (5, 20, true, 4),
    (0, 21, true, 4),
];
const RF_RX_8822C: [(u8, u8, bool, u8); 7] = [
    (0, 0, false, 7),
    (0, 16, false, 7),
    (3, 24, true, 5),
    (2, 26, true, 5),
    (1, 27, true, 5),
    (0, 28, true, 5),
    (0, 28, true, 5),
];
static C21: Chip = Chip {
    table_sant: &TABLE_SANT_8821C,
    table_nsant: &TABLE_NSANT_8821C,
    tdma_sant: &TDMA_SANT_8821C,
    tdma_nsant: &TDMA_NSANT_8821C,
    wl_rssi_step: [101, 45, 101, 40],
    bt_rssi_step: [101, 101, 101, 101],
    rf_tx: &RF_TX_8821C,
    rf_rx: &RF_RX_8821C,
    new_scbd10_def: false,
    ble_hid_profile_support: false,
    bt_rssi_ratio: true,
};
static C22: Chip = Chip {
    table_sant: &TABLE_SANT_8822C,
    table_nsant: &TABLE_NSANT_8822C,
    tdma_sant: &TDMA_SANT_8822C,
    tdma_nsant: &TDMA_NSANT_8822C,
    wl_rssi_step: [60, 50, 44, 30],
    bt_rssi_step: [8, 15, 20, 25],
    rf_tx: &RF_TX_8822C,
    rf_rx: &RF_RX_8822C,
    new_scbd10_def: true,
    ble_hid_profile_support: true,
    bt_rssi_ratio: false,
};
const RSSI_TOLERANCE: u8 = 2;
const BT_AFH_SPAN_BW20: u8 = 0x24;
const BT_AFH_SPAN_BW40: u8 = 0x36;

// coex.h / main.h
const SCBD_ACTIVE: u16 = 1 << 0;
const SCBD_ONOFF: u16 = 1 << 1;
const SCBD_SCAN: u16 = 1 << 2;
const SCBD_RXGAIN: u16 = 1 << 4;
const SCBD_BT_RFK: u16 = 1 << 5;
const SCBD_WLBUSY: u16 = 1 << 6;
const SCBD_TDMA: u16 = 1 << 9;
const SCBD_FIX2M: u16 = 1 << 10;
const SCBD_ALL: u16 = 0xffff;
const BT_INT_EN: u16 = 1 << 15;
const INFO_FTP: u8 = 1 << 7;
const INFO_A2DP: u8 = 1 << 6;
const INFO_HID: u8 = 1 << 5;
const INFO_SCO_BUSY: u8 = 1 << 4;
const INFO_ACL_BUSY: u8 = 1 << 3;
const INFO_INQ_PAGE: u8 = 1 << 2;
const INFO_SCO_ESCO: u8 = 1 << 1;
const INFO_CONNECTION: u8 = 1 << 0;
const BTINFO_LENGTH: usize = 7;
const HIDINFO_LIST: u8 = 0;
const HIDINFO_A: u8 = 1;
const HIDINFO_NOTCON: u8 = 0xff;
const BLE_HANDLE_THRS: u8 = 0x10;
const HIDINFO_MTK: u8 = 0x46;
const GAMEHID_CNT: u32 = 800;
const TDMA_4SLOT: u32 = 1 << 8;
const WL_SLOT_TOGGLE: u32 = 0x5a5a5aaa;
const CCK_2: u8 = 0x1;
/// `DESC_RATE5_5M`: Linux never updates `wl_rx_rate`/`wl_rts_rx_rate` after
/// `rtw_coex_init_coex_var`.
const DESC_RATE5_5M: u8 = 0x02;
const COEX_RFK_WAIT: u32 = 600 / 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rssi {
    High,
    Low,
    StayHigh,
    StayLow,
}
impl Rssi {
    fn high(self) -> bool {
        matches!(self, Rssi::High | Rssi::StayHigh)
    }
    /// `rtw_coex_next_rssi_state`.
    fn next(self, rssi: u8, thresh: u8) -> Self {
        if matches!(self, Rssi::Low | Rssi::StayLow) {
            if u16::from(rssi) >= u16::from(thresh) + u16::from(RSSI_TOLERANCE) {
                Rssi::High
            } else {
                Rssi::StayLow
            }
        } else if rssi < thresh {
            Rssi::Low
        } else {
            Rssi::StayHigh
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BtStatus {
    NconIdle,
    ConIdle,
    InqPage,
    AclBusy,
    ScoBusy,
    AclScoBusy,
    Max,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WlMode {
    TwoG1Port,
    FiveG,
    TwoGFree,
    Max,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Reason {
    Scan2gStart,
    Scan5gStart,
    ScanFinish,
    Switchband2g,
    Switchband5g,
    Con2gStart,
    Con5gStart,
    Con2gFinish,
    Con5gFinish,
    Media2g,
    Media5g,
    MediaDiscon,
    BtInfo,
    Lps,
    WlStatus,
    BtStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ant {
    Init,
    WOnly,
    WOff,
    TwoG,
    FiveG,
    PowerOn,
    TwoGFreerun,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ctrl {
    Bbsw = 0,
    Pta = 1,
    Bt = 4,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pos {
    Bt = 0,
    Wlg = 1,
    Wla = 2,
    NoCare = 3,
    WlgBt = 4,
}

/// `rtw_coex_rfe`.
#[derive(Clone, Copy, Debug, Default)]
struct Rfe {
    ant_switch_exist: bool,
    ant_switch_polarity: bool,
    wlg_at_btg: bool,
}

#[derive(Clone, Copy, Debug, Default)]
struct Hid {
    handle: u8,
    vendor: u8,
    name: [u8; 3],
    completed: bool,
    game: bool,
}

/// Delayed works, as absolute deadlines in ms.
#[derive(Clone, Copy, Debug, Default)]
struct Works {
    bt_relink: Option<u64>,
    bt_reenable: Option<u64>,
    defreeze: Option<u64>,
    wl_remain: Option<u64>,
    bt_remain: Option<u64>,
    wl_connecting: Option<u64>,
    multi_link_remain: Option<u64>,
    ccklock: Option<u64>,
}

/// `rtw_coex_stat` + `rtw_coex_dm` + the `rtw_coex` flags this port uses.
#[derive(Clone, Debug)]
struct Stat {
    bt_disabled: bool,
    bt_disabled_pre: bool,
    bt_pan_exist: bool,
    bt_a2dp_exist: bool,
    bt_hid_exist: bool,
    bt_hfp_exist: bool,
    bt_profile_num: u8,
    bt_whck_test: bool,
    bt_inq_page: bool,
    bt_inq_remain: bool,
    bt_page: bool,
    bt_ble_exist: bool,
    bt_ble_hid_exist: bool,
    bt_ble_scan_en: bool,
    bt_ble_scan_type: u8,
    bt_setup_link: bool,
    bt_multi_link: bool,
    bt_multi_link_pre: bool,
    bt_multi_link_remain: bool,
    bt_a2dp_active: bool,
    bt_a2dp_sink: bool,
    bt_slave: bool,
    bt_hid_slot: u8,
    bt_hid_pair_num: u8,
    bt_418_hid_exist: bool,
    bt_game_hid_exist: bool,
    bt_reenable: bool,
    bt_iqk_state: u8,
    bt_rssi: u8,
    bt_info: [u8; 6],
    cnt_bt_infoupdate: u32,
    hi_pri_tx: u32,
    hi_pri_rx: u32,
    lo_pri_tx: u32,
    lo_pri_rx: u32,
    bt_ctr_ok: bool,
    wl_connected: bool,
    wl_gl_busy: bool,
    wl_tput_tx: bool,
    wl_linkscan_proc: bool,
    wl_hi_pri_task1: bool,
    wl_hi_pri_task2: bool,
    wl_connecting: bool,
    wl_under_lps: bool,
    wl_under_ips: bool,
    wl_force_lps_ctrl: bool,
    wl_coex_mode: WlMode,
    wl_noisy_level: u8,
    cnt_noisy: [u8; 3],
    cnt_scanap: u32,
    cnt_5ms_noextend: u32,
    wl_slot_extend: bool,
    wl_cck_lock: bool,
    wl_cck_lock_pre: bool,
    wl_fw_dbg_info: [u8; 8],
    wl_fw_dbg_info_pre: [u8; 8],
    wl_beacon_interval: u16,
    tdma_timer_base: u8,
    wl_slot_toggle: bool,
    wl_slot_toggle_change: bool,
    wl_mimo_ps: bool,
    wl_tx_limit_en: bool,
    wl_ampdu_limit_en: bool,
    darfrc: u32,
    darfrch: u32,
    retry_limit: u16,
    ampdu_max_time: u8,
    score_board: u16,
    kt_ver: u8,
    gnt_workaround_state: WlMode,
    // rtw_coex_dm
    reason: Reason,
    bt_status: BtStatus,
    wl_rssi_state: [Rssi; 4],
    bt_rssi_state: [Rssi; 4],
    cur_ps_tdma_on: bool,
    cur_ps_tdma: u8,
    cur_ant_pos: Ant,
    cur_bt_pwr_lvl: u8,
    cur_bt_lna_lvl: u8,
    cur_wl_rx_low_gain_en: bool,
    cur_switch_status: u32,
    ps_tdma_para: [u8; 5],
    // rtw_coex
    under_5g: bool,
    freeze: bool,
    freerun: bool,
    stop_dm: bool,
    hid: [Hid; 4],
    hid_list: [u8; 8],
}
impl Stat {
    /// `rtw_coex_init_coex_var`.
    fn new() -> Self {
        Self {
            bt_disabled: false,
            bt_disabled_pre: false,
            bt_pan_exist: false,
            bt_a2dp_exist: false,
            bt_hid_exist: false,
            bt_hfp_exist: false,
            bt_profile_num: 0,
            bt_whck_test: false,
            bt_inq_page: false,
            bt_inq_remain: false,
            bt_page: false,
            bt_ble_exist: false,
            bt_ble_hid_exist: false,
            bt_ble_scan_en: false,
            bt_ble_scan_type: 0,
            bt_setup_link: false,
            bt_multi_link: false,
            bt_multi_link_pre: false,
            bt_multi_link_remain: false,
            bt_a2dp_active: false,
            bt_a2dp_sink: false,
            bt_slave: false,
            bt_hid_slot: 0,
            bt_hid_pair_num: 0,
            bt_418_hid_exist: false,
            bt_game_hid_exist: false,
            bt_reenable: false,
            bt_iqk_state: 0,
            bt_rssi: 0,
            bt_info: [0; 6],
            cnt_bt_infoupdate: 0,
            hi_pri_tx: 0,
            hi_pri_rx: 0,
            lo_pri_tx: 0,
            lo_pri_rx: 0,
            bt_ctr_ok: false,
            wl_connected: false,
            wl_gl_busy: false,
            wl_tput_tx: true,
            wl_linkscan_proc: false,
            wl_hi_pri_task1: false,
            wl_hi_pri_task2: false,
            wl_connecting: false,
            wl_under_lps: false,
            wl_under_ips: false,
            wl_force_lps_ctrl: false,
            wl_coex_mode: WlMode::Max,
            wl_noisy_level: 0,
            cnt_noisy: [0; 3],
            cnt_scanap: 0,
            cnt_5ms_noextend: 0,
            wl_slot_extend: false,
            wl_cck_lock: false,
            wl_cck_lock_pre: false,
            wl_fw_dbg_info: [0; 8],
            wl_fw_dbg_info_pre: [0; 8],
            wl_beacon_interval: 0,
            tdma_timer_base: 0,
            wl_slot_toggle: false,
            wl_slot_toggle_change: false,
            wl_mimo_ps: false,
            wl_tx_limit_en: false,
            wl_ampdu_limit_en: false,
            darfrc: 0,
            darfrch: 0,
            retry_limit: 0,
            ampdu_max_time: 0,
            score_board: 0,
            kt_ver: 0,
            gnt_workaround_state: WlMode::TwoG1Port,
            reason: Reason::Scan2gStart,
            bt_status: BtStatus::NconIdle,
            wl_rssi_state: [Rssi::Low; 4],
            bt_rssi_state: [Rssi::Low; 4],
            cur_ps_tdma_on: false,
            cur_ps_tdma: 0,
            cur_ant_pos: Ant::Init,
            cur_bt_pwr_lvl: 0,
            cur_bt_lna_lvl: 0,
            cur_wl_rx_low_gain_en: false,
            cur_switch_status: 0,
            ps_tdma_para: [0; 5],
            under_5g: false,
            freeze: false,
            freerun: false,
            stop_dm: false,
            hid: [Hid::default(); 4],
            hid_list: [0; 8],
        }
    }
}

/// One backed-up hardware value, restored in reverse order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Saved {
    Mac8(u16, u8),
    Mac16(u16, u16),
    Mac32(u16, u32),
    Rf(u8, u8, u32),
    Lte(u16, u32),
}
impl Saved {
    fn key(&self) -> (u8, u16) {
        match *self {
            Saved::Mac8(a, _) => (0, a),
            Saved::Mac16(a, _) => (1, a),
            Saved::Mac32(a, _) => (2, a),
            Saved::Rf(p, a, _) => (3 + p, u16::from(a)),
            Saved::Lte(a, _) => (5, a),
        }
    }
}

/// The station's view of the link at a coex call.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Link {
    pub(super) now: u64,
    pub(super) connected: bool,
    pub(super) scanning: bool,
    pub(super) band5: bool,
    pub(super) channel: u8,
    /// `hal.current_band_width` (0 = 20MHz, 1 = 40MHz, 2 = 80MHz).
    pub(super) width: u8,
    /// N2xD `dm_info.min_rssi`, if the dynamic mechanism is bound.
    pub(super) rssi: Option<u8>,
    /// The bound T originator owns `RETRY_LIMIT`/`AMPDU_MAX_TIME_V1` and
    /// already holds the coex-limited values there.
    pub(super) t_owns_retry: bool,
}

/// One watchdog period's traffic (`rtw_watch_dog_work`).
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Traffic {
    pub(super) tx_cnt: u32,
    pub(super) rx_cnt: u32,
    pub(super) tx_bytes: u64,
    pub(super) rx_bytes: u64,
}

/// The coexistence owner bound to one station.
pub(super) struct Coex {
    record: Record,
    facts: Facts,
    chip: &'static Chip,
    rfe: Rfe,
    s: Stat,
    works: Works,
    saved: Vec<Saved>,
    h2c: Vec<[u8; 8]>,
    tdma_sent: bool,
    ch_info_sent: bool,
    mp_seq: u8,
    mp_pending: Option<u8>,
    link: Link,
    busy_flag: bool,
    tx_tp: u64,
    rx_tp: u64,
    initialized: bool,
    /// Requested `hal.txrx_1ss` (`rtw_coex_mimo_ps`), consumed by the caller.
    txrx_1ss: bool,
    /// Pre-1SS values of the [`TRX_1SS`] fields while
    /// `rtw8822c_config_trx_mode(A, A)` is in effect (empty otherwise).
    trx_saved: Vec<u32>,
}

const MAGIC_SDIO_CTRL3: u16 = 0x73;

impl Coex {
    /// None if the record was not qualified on these exact efuse facts.
    pub(super) fn new(record: Record, facts: Facts) -> Option<Self> {
        if !facts.qualifies(&record) {
            return None;
        }
        Some(Self {
            record,
            facts,
            chip: if facts.c22() { &C22 } else { &C21 },
            rfe: Rfe::default(),
            s: Stat::new(),
            works: Works::default(),
            saved: Vec::new(),
            h2c: Vec::new(),
            tdma_sent: false,
            ch_info_sent: false,
            mp_seq: 0,
            mp_pending: None,
            link: Link::default(),
            busy_flag: false,
            tx_tp: 0,
            rx_tp: 0,
            initialized: false,
            txrx_1ss: false,
            trx_saved: Vec::new(),
        })
    }
    #[cfg(feature = "kernel-test")]
    pub(super) fn record(&self) -> Record {
        self.record
    }
    pub(super) fn initialized(&self) -> bool {
        self.initialized
    }
    /// `coex_stat.wl_force_lps_ctrl`: PS-TDMA forces LPS off
    /// (`COEX_PSTDMA_FORCE_LPSOFF` on both chips).
    pub(super) fn forces_lps_off(&self) -> bool {
        self.s.wl_force_lps_ctrl
    }
    pub(super) fn txrx_1ss(&self) -> bool {
        self.txrx_1ss
    }
    /// Test hook: `rtw_coex_mimo_ps(force, state)` as `rtw_coex_run_coex`
    /// calls it on leaving or entering `COEX_WLINK_2GFREE`.
    #[cfg(feature = "kernel-test")]
    pub(super) fn mimo_ps_for_test(&mut self, force: bool, state: bool) {
        self.mimo_ps(force, state);
    }
    /// The hardware currently runs `config_trx_mode(A, A)` (`hal.txrx_1ss`).
    pub(super) fn trx_1ss(&self) -> bool {
        !self.trx_saved.is_empty()
    }
    #[cfg(feature = "kernel-test")]
    pub(super) fn bt_status(&self) -> BtStatus {
        self.s.bt_status
    }
    #[cfg(feature = "kernel-test")]
    pub(super) fn wl_mode(&self) -> WlMode {
        self.s.wl_coex_mode
    }
    #[cfg(feature = "kernel-test")]
    pub(super) fn tdma_state(&self) -> (bool, u8, [u8; 5]) {
        (
            self.s.cur_ps_tdma_on,
            self.s.cur_ps_tdma,
            self.s.ps_tdma_para,
        )
    }
    #[cfg(feature = "kernel-test")]
    pub(super) fn bt_disabled(&self) -> bool {
        self.s.bt_disabled
    }
    #[cfg(feature = "kernel-test")]
    pub(super) fn freeze(&self) -> bool {
        self.s.freeze
    }
    fn share(&self) -> bool {
        self.facts.share_ant()
    }
    fn need(&self, mode: u8) -> Result<(), Error> {
        if self.record.modes & mode == mode {
            Ok(())
        } else {
            Err(Error::Unsupported)
        }
    }
    fn take(&mut self) -> Vec<[u8; 8]> {
        core::mem::take(&mut self.h2c)
    }
    fn send(&mut self, cmd: [u8; 8]) {
        self.h2c.push(cmd);
    }

    // ---- register access with first-write backup ----
    fn remember(&mut self, s: Saved) {
        if !self.saved.iter().any(|x| x.key() == s.key()) {
            self.saved.push(s);
        }
    }
    fn known(&self, key: (u8, u16)) -> bool {
        self.saved.iter().any(|x| x.key() == key)
    }
    async fn r8(io: &mut impl Io, auth: &impl Authority, a: u16) -> Result<u8, Error> {
        enclosed(|op| auth.run(op), io.read8(a)).await
    }
    async fn r16(io: &mut impl Io, auth: &impl Authority, a: u16) -> Result<u16, Error> {
        enclosed(|op| auth.run(op), io.read16(a)).await
    }
    /// Raw dword read: `0xffffffff` is a valid coexistence table value.
    async fn r32(io: &mut impl Io, auth: &impl Authority, a: u16) -> Result<u32, Error> {
        enclosed(|op| auth.run(op), io.read32(a)).await
    }
    async fn w8(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        a: u16,
        v: u8,
    ) -> Result<(), Error> {
        if !self.known((0, a)) {
            let old = Self::r8(io, auth, a).await?;
            self.remember(Saved::Mac8(a, old));
        }
        enclosed(|op| auth.run(op), io.write8(a, v)).await
    }
    async fn w16(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        a: u16,
        v: u16,
    ) -> Result<(), Error> {
        if !self.known((1, a)) {
            let old = Self::r16(io, auth, a).await?;
            self.remember(Saved::Mac16(a, old));
        }
        enclosed(|op| auth.run(op), io.write16(a, v)).await
    }
    async fn w32(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        a: u16,
        v: u32,
    ) -> Result<(), Error> {
        if !self.known((2, a)) {
            let old = Self::r32(io, auth, a).await?;
            self.remember(Saved::Mac32(a, old));
        }
        enclosed(|op| auth.run(op), io.write32(a, v)).await
    }
    /// `rtw_write8_mask`.
    async fn m8(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        a: u16,
        mask: u8,
        v: u8,
    ) -> Result<(), Error> {
        let old = Self::r8(io, auth, a).await?;
        let sh = mask.trailing_zeros();
        self.w8(io, auth, a, old & !mask | (v << sh) & mask).await
    }
    async fn set8(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        a: u16,
        bits: u8,
    ) -> Result<(), Error> {
        let old = Self::r8(io, auth, a).await?;
        self.w8(io, auth, a, old | bits).await
    }
    async fn clr8(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        a: u16,
        bits: u8,
    ) -> Result<(), Error> {
        let old = Self::r8(io, auth, a).await?;
        self.w8(io, auth, a, old & !bits).await
    }
    async fn m32(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        a: u16,
        mask: u32,
        v: u32,
    ) -> Result<(), Error> {
        let old = Self::r32(io, auth, a).await?;
        let sh = mask.trailing_zeros();
        self.w32(io, auth, a, old & !mask | (v << sh) & mask).await
    }
    async fn rf(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        path: u8,
        addr: u8,
        v: u32,
    ) -> Result<(), Error> {
        if !self.known((3 + path, u16::from(addr))) {
            let old = enclosed(|op| auth.run(op), super::radio::rf_read(io, path, addr)).await?;
            self.remember(Saved::Rf(path, addr, old));
        }
        enclosed(
            |op| auth.run(op),
            super::radio::rf(io, path, addr, 0xfffff, v),
        )
        .await
    }
    /// `util.c::check_hw_ready` on `LTECOEX_READY`: 1000 reads 10us apart.
    async fn lte_ready(io: &mut impl Io, auth: &impl Authority) -> Result<(), Error> {
        for _ in 0..1000 {
            if Self::r32(io, auth, 0x1700).await? & (1 << 29) != 0 {
                return Ok(());
            }
            io.delay_us(10).await;
        }
        Err(Error::Timeout)
    }
    /// `util.c::ltecoex_read_reg`.
    async fn lte_read(io: &mut impl Io, auth: &impl Authority, off: u16) -> Result<u32, Error> {
        Self::lte_ready(io, auth).await?;
        enclosed(|op| auth.run(op), async {
            io.write32(0x1700, 0x800f_0000 | u32::from(off)).await?;
            io.read32(0x1708).await
        })
        .await
    }
    async fn lte_raw_write(
        io: &mut impl Io,
        auth: &impl Authority,
        off: u16,
        v: u32,
    ) -> Result<(), Error> {
        Self::lte_ready(io, auth).await?;
        enclosed(|op| auth.run(op), async {
            io.write32(0x1704, v).await?;
            io.write32(0x1700, 0xc00f_0000 | u32::from(off)).await
        })
        .await
    }
    /// `rtw_coex_write_indirect_reg`.
    async fn lte_mask(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        off: u16,
        mask: u32,
        v: u32,
    ) -> Result<(), Error> {
        let old = Self::lte_read(io, auth, off).await?;
        self.remember(Saved::Lte(off, old));
        let sh = mask.trailing_zeros();
        Self::lte_raw_write(io, auth, off, old & !mask | (v << sh) & mask).await
    }

    /// Restore every backed-up register (reverse order) and return the
    /// firmware to TDMA off / no WL channel info. Runs under the base gate.
    pub(super) async fn restore(
        &mut self,
        io: &mut impl Io,
        base: &impl Authority,
    ) -> Result<Vec<[u8; 8]>, Error> {
        let mut h2c = Vec::new();
        if self.tdma_sent {
            h2c.push([0x60, 0, 0, 0, 0, 0, 0, 0]);
            self.tdma_sent = false;
        }
        if self.ch_info_sent {
            h2c.push([0x66, 0, 0, 0, 0, 0, 0, 0]);
            self.ch_info_sent = false;
        }
        if self.trx_1ss() {
            let saved = self.trx_saved.clone();
            Self::trx_program(io, base, &saved).await?;
            self.trx_saved.clear();
        }
        while let Some(s) = self.saved.pop() {
            match s {
                Saved::Mac8(a, v) => enclosed(|op| base.run(op), io.write8(a, v)).await?,
                Saved::Mac16(a, v) => enclosed(|op| base.run(op), io.write16(a, v)).await?,
                Saved::Mac32(a, v) => enclosed(|op| base.run(op), io.write32(a, v)).await?,
                Saved::Rf(p, a, v) => {
                    enclosed(|op| base.run(op), super::radio::rf(io, p, a, 0xfffff, v)).await?
                }
                Saved::Lte(a, v) => Self::lte_raw_write(io, base, a, v).await?,
            }
        }
        self.initialized = false;
        self.txrx_1ss = false;
        self.h2c.clear();
        Ok(h2c)
    }

    // ---- scoreboard / priority ----
    /// `rtw_coex_write_scbd`.
    async fn write_scbd(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        bitpos: u16,
        set: bool,
    ) -> Result<(), Error> {
        let mut val = 0x2 | self.s.score_board;
        if !self.chip.new_scbd10_def && bitpos & SCBD_FIX2M != 0 {
            if set {
                val &= !SCBD_FIX2M;
            } else {
                val |= SCBD_FIX2M;
            }
        } else if set {
            val |= bitpos;
        } else {
            val &= !bitpos;
        }
        if val != self.s.score_board {
            self.s.score_board = val;
            self.w16(io, auth, 0xaa, val | BT_INT_EN).await?;
        }
        Ok(())
    }
    async fn read_scbd(io: &mut impl Io, auth: &impl Authority) -> Result<u16, Error> {
        Ok(Self::r16(io, auth, 0xaa).await? & !BT_INT_EN)
    }
    async fn wl_pri_mask(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        bitmap: u8,
        data: u8,
    ) -> Result<(), Error> {
        let addr = 0x6cc + u16::from(bitmap / 8);
        self.m8(io, auth, addr, 1 << (bitmap % 8), data).await
    }

    // ---- firmware commands ----
    fn h2c69(&mut self, op: u8, d: [u8; 5]) {
        self.send([0x69, op, d[0], d[1], d[2], d[3], d[4], 0]);
    }
    fn query_bt_info(&mut self) {
        if !self.s.bt_disabled {
            self.send([0x61, 1, 0, 0, 0, 0, 0, 0]);
        }
    }
    fn mp_request(&mut self, op: u8, para1: u8) {
        self.mp_seq = (self.mp_seq + 1) & 0xf;
        self.mp_pending = Some(op);
        self.send([0x67, self.mp_seq << 4, op, para1, 0, 0, 0, 0]);
    }
    fn wl_slot_extend(&mut self, enable: bool) {
        if !enable {
            self.s.cnt_5ms_noextend = 0;
        }
        self.s.wl_slot_extend = enable;
        self.h2c69(0xc, [if enable { 0x0 } else { 0x1 }, 0, 0, 0, 0]);
    }
    /// `rtw_coex_wl_ccklock_action`.
    fn wl_ccklock_action(&mut self) {
        if self.s.stop_dm {
            return;
        }
        if self.s.tdma_timer_base == 3 && self.s.wl_slot_extend {
            self.wl_slot_extend(false);
            return;
        }
        // wl_cck_lock_ever is never set in Linux.
        if self.s.wl_slot_extend && self.s.wl_force_lps_ctrl {
            if self.s.wl_fw_dbg_info[7] <= 5 {
                self.s.cnt_5ms_noextend += 1;
            } else {
                self.s.cnt_5ms_noextend = 0;
            }
            if self.s.cnt_5ms_noextend == 7 {
                self.wl_slot_extend(false);
            }
        } else if !self.s.wl_slot_extend && self.s.wl_cck_lock {
            self.wl_slot_extend(true);
        }
    }
    /// `rtw_coex_wl_ccklock_detect`.
    fn wl_ccklock_detect(&mut self) {
        if !matches!(self.s.wl_coex_mode, WlMode::TwoG1Port | WlMode::TwoGFree) {
            return;
        }
        if self.s.bt_status == BtStatus::InqPage || self.s.bt_setup_link {
            self.s.wl_cck_lock = false;
            self.s.wl_cck_lock_pre = false;
            return;
        }
        let cck_rate = DESC_RATE5_5M <= CCK_2;
        self.s.wl_cck_lock = self.s.wl_connected
            && self.s.wl_gl_busy
            && self.s.wl_rssi_state[3].high()
            && matches!(
                self.s.bt_status,
                BtStatus::AclBusy | BtStatus::AclScoBusy | BtStatus::ScoBusy
            )
            && cck_rate;
        if self.s.wl_cck_lock && !self.s.wl_cck_lock_pre {
            self.works.ccklock = Some(self.link.now + 3000);
        }
        self.s.wl_cck_lock_pre = self.s.wl_cck_lock;
    }
    /// `rtw_coex_tdma_timer_base`.
    fn tdma_timer_base(&mut self, ty: u8) {
        if self.s.tdma_timer_base == ty {
            return;
        }
        self.s.tdma_timer_base = ty;
        let tbtt = self.s.wl_beacon_interval;
        let para1 = if ty == 3 && tbtt < 120 {
            0xc1
        } else if tbtt < 80 && tbtt > 0 {
            let mut times = 100 / tbtt;
            if 100 % tbtt != 0 {
                times += 1;
            }
            (times as u8) & 0x3f
        } else if tbtt >= 180 {
            let mut times = tbtt / 100;
            if tbtt % 100 <= 80 {
                times -= 1;
            }
            (times as u8) & 0x3f | 0x80
        } else {
            0x1
        };
        self.h2c69(0xb, [para1, 0, 0, 0, 0]);
        if self.s.tdma_timer_base == 3 {
            self.wl_ccklock_action();
        }
    }

    // ---- monitors ----
    /// `rtw_coex_monitor_bt_ctr`.
    async fn monitor_bt_ctr(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
    ) -> Result<(), Error> {
        let a = Self::r32(io, auth, 0x770).await?;
        self.s.hi_pri_tx = a & 0xffff;
        self.s.hi_pri_rx = a >> 16;
        let b = Self::r32(io, auth, 0x774).await?;
        self.s.lo_pri_tx = b & 0xffff;
        self.s.lo_pri_rx = b >> 16;
        // BIT_R_GRANTALL_WLMASK | BIT_STATIS_BT_EN
        self.w8(io, auth, 0x76e, (1 << 3) | (1 << 2)).await?;
        let s = &self.s;
        self.s.bt_ctr_ok = !(s.wl_under_lps
            || s.wl_under_ips
            || (s.hi_pri_rx > 60000
                && s.hi_pri_tx == 60000
                && s.lo_pri_rx > 60000
                && s.lo_pri_tx == 60000));
        Ok(())
    }
    /// `rtw_coex_monitor_bt_enable` (`scbd_support` on both chips).
    async fn monitor_bt_enable(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
    ) -> Result<(), Error> {
        let disabled = Self::read_scbd(io, auth).await? & SCBD_ONOFF == 0;
        if self.s.bt_disabled != disabled {
            self.s.bt_disabled = disabled;
            self.s.bt_ble_scan_type = 0;
            self.s.cur_bt_lna_lvl = 0;
            if !disabled {
                self.s.bt_reenable = true;
                self.works.bt_reenable = Some(self.link.now + 15000);
            } else {
                self.s.bt_reenable = false;
            }
        }
        Ok(())
    }
    /// `rtw_coex_wl_noisy_detect` (`cnt_cck` from `dm_info` false-alarm
    /// statistics; without the N2xD statistics owner it is zero).
    fn wl_noisy_detect(&mut self, cnt_cck: u32) {
        if self.s.wl_gl_busy {
            return;
        }
        let (bump, other) = if cnt_cck > 250 {
            (2, [0, 1])
        } else if cnt_cck < 100 {
            (0, [1, 2])
        } else {
            (1, [0, 2])
        };
        if self.s.cnt_noisy[bump] < 5 {
            self.s.cnt_noisy[bump] += 1;
        }
        if self.s.cnt_noisy[bump] == 5 {
            self.s.cnt_noisy[other[0]] = 0;
            self.s.cnt_noisy[other[1]] = 0;
        }
        self.s.wl_noisy_level = if self.s.cnt_noisy[2] == 5 {
            2
        } else if self.s.cnt_noisy[1] == 5 {
            1
        } else {
            0
        };
    }
    /// `rtw_coex_update_wl_link_info`.
    async fn update_wl_link_info(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        reason: Reason,
    ) -> Result<(), Error> {
        self.s.wl_connected = self.link.connected;
        let busy = self.busy_flag;
        if busy != self.s.wl_gl_busy {
            if busy {
                self.s.wl_gl_busy = true;
            } else {
                self.works.wl_remain = Some(self.link.now + 12000);
            }
        }
        self.s.wl_tput_tx = self.tx_tp > self.rx_tp;
        self.s.wl_linkscan_proc = self.link.scanning
            || matches!(
                reason,
                Reason::Con2gStart | Reason::Scan2gStart | Reason::Switchband2g
            );
        self.wl_noisy_detect(0);
        let rssi = self.link.rssi.unwrap_or(0);
        for i in 0..4 {
            self.s.wl_rssi_state[i] = self.s.wl_rssi_state[i].next(rssi, self.chip.wl_rssi_step[i]);
        }
        let scan = self.s.wl_linkscan_proc
            || self.s.wl_hi_pri_task1
            || self.s.wl_hi_pri_task2
            || self.s.wl_gl_busy;
        self.write_scbd(io, auth, SCBD_SCAN, scan).await?;
        self.s.under_5g = match reason {
            Reason::Scan5gStart | Reason::Switchband5g | Reason::Con5gStart => true,
            Reason::Scan2gStart | Reason::Switchband2g | Reason::Con2gStart => false,
            _ => self.link.band5,
        };
        Ok(())
    }
    /// `rtw_coex_update_bt_link_info`.
    fn update_bt_link_info(&mut self) {
        for i in 0..4 {
            self.s.bt_rssi_state[i] =
                self.s.bt_rssi_state[i].next(self.s.bt_rssi, self.chip.bt_rssi_step[i]);
        }
        if self.s.bt_ble_scan_en && self.s.cnt_bt_infoupdate % 3 == 0 {
            // rtw_coex_get_bt_scan_type: the C2H 0x0b reply updates the
            // scan type when it arrives (see `mp_info`).
            self.mp_request(0x2d, 0);
        }
        let lb2 = self.s.bt_info[0];
        self.s.bt_profile_num = 0;
        if lb2 & INFO_CONNECTION == 0 {
            self.s.bt_pan_exist = false;
            self.s.bt_a2dp_exist = false;
            self.s.bt_hid_exist = false;
            self.s.bt_hfp_exist = false;
        } else {
            self.s.bt_pan_exist = lb2 & INFO_FTP != 0;
            self.s.bt_a2dp_exist = lb2 & INFO_A2DP != 0;
            self.s.bt_hid_exist = lb2 & INFO_HID != 0;
            self.s.bt_hfp_exist = lb2 & INFO_SCO_ESCO != 0;
            self.s.bt_profile_num = [INFO_FTP, INFO_A2DP, INFO_HID, INFO_SCO_ESCO]
                .iter()
                .filter(|&&b| lb2 & b != 0)
                .count() as u8;
        }
        self.s.bt_status = if lb2 & INFO_INQ_PAGE != 0 {
            BtStatus::InqPage
        } else if lb2 & INFO_CONNECTION == 0 {
            self.s.bt_multi_link_remain = false;
            BtStatus::NconIdle
        } else if lb2 == INFO_CONNECTION {
            BtStatus::ConIdle
        } else if lb2 & (INFO_SCO_ESCO | INFO_SCO_BUSY) != 0 {
            if lb2 & INFO_ACL_BUSY != 0 {
                BtStatus::AclScoBusy
            } else {
                BtStatus::ScoBusy
            }
        } else if lb2 & INFO_ACL_BUSY != 0 {
            BtStatus::AclBusy
        } else {
            BtStatus::Max
        };
        self.s.cnt_bt_infoupdate = self.s.cnt_bt_infoupdate.wrapping_add(1);
    }
    /// `rtw_coex_update_wl_ch_info` (no 5GHz AFH map: `afh_5g_num == 1`).
    fn update_wl_ch_info(&mut self, connect: bool) {
        let mut ch = if connect { self.link.channel } else { 0 };
        let mut bw = self.link.width;
        let mut link = 0;
        if ch == 0 || (self.share() && ch <= 14 && self.s.wl_coex_mode != WlMode::TwoGFree) {
            ch = 0;
            bw = 0;
        } else if ch <= 14 {
            link = 1;
            bw = if self.link.width == 1 {
                BT_AFH_SPAN_BW40
            } else {
                BT_AFH_SPAN_BW20
            };
        }
        // 5GHz: afh_5g_num == 1 on both chips, so Linux leaves link 0, the
        // channel and the raw bandwidth index.
        self.ch_info_sent |= link != 0 || ch != 0;
        self.send([0x66, link, ch, bw, 0, 0, 0, 0]);
    }
    fn set_bt_tx_power(&mut self, lvl: u8) {
        if lvl == self.s.cur_bt_pwr_lvl {
            return;
        }
        self.s.cur_bt_pwr_lvl = lvl;
        self.send([0x62, 0u8.wrapping_sub(lvl), 0, 0, 0, 0, 0, 0]);
    }
    async fn set_bt_rx_gain(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        lvl: u8,
    ) -> Result<(), Error> {
        if lvl == self.s.cur_bt_lna_lvl {
            return Ok(());
        }
        self.s.cur_bt_lna_lvl = lvl;
        if lvl < 7 {
            self.mp_request(0x32, lvl);
            self.write_scbd(io, auth, SCBD_RXGAIN, true).await
        } else {
            self.write_scbd(io, auth, SCBD_RXGAIN, false).await
        }
    }
    /// `coex_cfg_wl_rx_gain` (C22 only touches RF; C21 is empty).
    async fn set_wl_rx_gain(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        low: bool,
    ) -> Result<(), Error> {
        if !self.facts.c22() || low == self.s.cur_wl_rx_low_gain_en {
            return Ok(());
        }
        self.s.cur_wl_rx_low_gain_en = low;
        let (rckd, rck) = if low { (0x22, 0x36) } else { (0x20, 0x0) };
        for path in 0..2 {
            self.rf(io, auth, path, 0xde, rckd).await?;
            self.rf(io, auth, path, 0x1d, rck).await?;
        }
        Ok(())
    }
    /// `rtw_coex_set_rf_para`.
    async fn set_rf_para(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        tx: bool,
        level: usize,
    ) -> Result<(), Error> {
        let table = if tx { self.chip.rf_tx } else { self.chip.rf_rx };
        let (wl_pwr, bt_pwr, low_gain, lna) = table[level.min(table.len() - 1)];
        let offset = if self.s.freerun && self.s.cnt_scanap <= 5 {
            3
        } else {
            0
        };
        if level != 0 || offset != 0 {
            self.need(FREERUN)?;
        }
        // coex_cfg_wl_tx_power only records `wl_pwr` on both chips: there
        // is no WL TX power register write to port.
        let _ = wl_pwr;
        self.set_bt_tx_power(bt_pwr + offset);
        self.set_wl_rx_gain(io, auth, low_gain).await?;
        self.set_bt_rx_gain(io, auth, lna).await
    }

    // ---- antenna / GNT ----
    async fn ctrl_owner(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        wifi: bool,
    ) -> Result<(), Error> {
        // BIT_LTE_MUX_CTRL_PATH >> 24; no btg_reg on 8821c/8822c.
        if wifi {
            self.set8(io, auth, MAGIC_SDIO_CTRL3, 1 << 2).await
        } else {
            self.clr8(io, auth, MAGIC_SDIO_CTRL3, 1 << 2).await
        }
    }
    async fn gnt_bt(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        st: u8,
    ) -> Result<(), Error> {
        self.lte_mask(io, auth, 0x38, 0xc000, u32::from(st)).await?;
        self.lte_mask(io, auth, 0x38, 0x0c00, u32::from(st)).await
    }
    async fn gnt_wl(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        st: u8,
    ) -> Result<(), Error> {
        self.lte_mask(io, auth, 0x38, 0x3000, u32::from(st)).await?;
        self.lte_mask(io, auth, 0x38, 0x0300, u32::from(st)).await
    }
    /// `rtw_coex_check_rfk`.
    async fn check_rfk(&mut self, io: &mut impl Io, auth: &impl Authority) -> Result<(), Error> {
        if !self.rfe.wlg_at_btg || self.s.bt_iqk_state == 0xff {
            return Ok(());
        }
        let mut cnt = 0;
        loop {
            let btk = Self::read_scbd(io, auth).await? & SCBD_BT_RFK != 0;
            let wlk = Self::r8(io, auth, 0x49c).await? & 1 != 0;
            if !btk && !wlk {
                break;
            }
            io.delay_us(10_000).await;
            cnt += 1;
            if cnt >= COEX_RFK_WAIT {
                break;
            }
        }
        if cnt >= COEX_RFK_WAIT {
            self.s.bt_iqk_state = 0xff;
        }
        Ok(())
    }
    /// `rtw_coex_set_ant_path`.
    async fn set_ant_path(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        force: bool,
        phase: Ant,
    ) -> Result<(), Error> {
        if !force && self.s.cur_ant_pos == phase {
            return Ok(());
        }
        self.s.cur_ant_pos = phase;
        self.check_rfk(io, auth).await?;
        const HW_PTA: u8 = 0;
        const SW_LOW: u8 = 1;
        const SW_HIGH: u8 = 3;
        let (ctrl, pos) = match phase {
            Ant::PowerOn => {
                let wifi = self.s.bt_disabled;
                self.ctrl_owner(io, auth, wifi).await?;
                (Ctrl::Bbsw, Pos::Bt)
            }
            Ant::Init => {
                if self.s.bt_disabled {
                    self.gnt_bt(io, auth, SW_LOW).await?;
                    self.gnt_wl(io, auth, SW_HIGH).await?;
                } else {
                    self.gnt_bt(io, auth, SW_HIGH).await?;
                    self.gnt_wl(io, auth, SW_LOW).await?;
                }
                self.ctrl_owner(io, auth, true).await?;
                (Ctrl::Bbsw, Pos::Bt)
            }
            Ant::WOnly => {
                self.gnt_bt(io, auth, SW_LOW).await?;
                self.gnt_wl(io, auth, SW_HIGH).await?;
                self.ctrl_owner(io, auth, true).await?;
                (Ctrl::Bbsw, Pos::Wlg)
            }
            Ant::WOff => {
                self.ctrl_owner(io, auth, false).await?;
                (Ctrl::Bt, Pos::NoCare)
            }
            Ant::TwoG => {
                self.gnt_bt(io, auth, HW_PTA).await?;
                self.gnt_wl(io, auth, HW_PTA).await?;
                self.ctrl_owner(io, auth, true).await?;
                (Ctrl::Pta, Pos::NoCare)
            }
            Ant::FiveG => {
                self.gnt_bt(io, auth, HW_PTA).await?;
                self.gnt_wl(io, auth, SW_HIGH).await?;
                self.ctrl_owner(io, auth, true).await?;
                (Ctrl::Bbsw, Pos::Wla)
            }
            Ant::TwoGFreerun => {
                self.gnt_bt(io, auth, HW_PTA).await?;
                self.gnt_wl(io, auth, SW_HIGH).await?;
                self.ctrl_owner(io, auth, true).await?;
                (Ctrl::Bbsw, Pos::WlgBt)
            }
        };
        if self.rfe.ant_switch_exist {
            self.ant_switch(io, auth, ctrl, pos).await?;
        }
        Ok(())
    }
    /// `rtw8821c_coex_cfg_ant_switch` (8822c has no antenna switch).
    async fn ant_switch(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        mut ctrl: Ctrl,
        mut pos: Pos,
    ) -> Result<(), Error> {
        let status = (ctrl as u32) << 8 | pos as u32;
        if status == self.s.cur_switch_status {
            return Ok(());
        }
        if self.rfe.wlg_at_btg {
            ctrl = Ctrl::Bbsw;
            pos = if self.rfe.ant_switch_polarity {
                Pos::Wla
            } else {
                Pos::WlgBt
            };
        }
        self.s.cur_switch_status = status;
        let inv = self.rfe.ant_switch_polarity;
        const DPDT_SEL_EN: u32 = 1 << 23;
        const DPDT_WL_SEL: u32 = 1 << 24;
        let led = Self::r32(io, auth, 0x4c).await?;
        match ctrl {
            Ctrl::Bbsw | Ctrl::Pta => {
                self.w32(io, auth, 0x4c, (led & !DPDT_SEL_EN) | DPDT_WL_SEL)
                    .await?;
                let pin = if ctrl == Ctrl::Pta { 0x66 } else { 0x77 };
                self.m8(io, auth, 0xcb4, 0xff, pin).await?;
                let regval = if ctrl == Ctrl::Pta {
                    if inv {
                        1
                    } else {
                        2
                    }
                } else if pos == Pos::WlgBt {
                    if self.rfe_module() != 0x4 && self.rfe_module() != 0x2 {
                        3
                    } else if inv {
                        1
                    } else {
                        2
                    }
                } else if pos == Pos::Wlg {
                    if inv {
                        1
                    } else {
                        2
                    }
                } else if inv {
                    2
                } else {
                    1
                };
                self.m32(io, auth, 0xcb4, 0xf000_0000, regval).await?;
            }
            Ctrl::Bt => {
                self.w32(io, auth, 0x4c, led & !(DPDT_SEL_EN | DPDT_WL_SEL))
                    .await?;
            }
        }
        // REG_CTRL_TYPE 0x67 BIT_CTRL_TYPE1|2
        if ctrl == Ctrl::Bt {
            self.clr8(io, auth, 0x67, (1 << 5) | (1 << 4)).await
        } else {
            self.set8(io, auth, 0x67, (1 << 5) | (1 << 4)).await
        }
    }
    fn rfe_module(&self) -> u8 {
        self.facts.rfe
    }
    /// `coex_cfg_rfe_type`.
    async fn set_rfe_type(&mut self, io: &mut impl Io, auth: &impl Authority) -> Result<(), Error> {
        if self.facts.c22() {
            self.rfe = Rfe {
                ant_switch_exist: false,
                ant_switch_polarity: false,
                wlg_at_btg: self.share(),
            };
            // disable LTE coex in wifi side
            self.lte_mask(io, auth, 0x38, 1 << 7, 0).await?;
            self.lte_mask(io, auth, 0xa0, 0xffff, 0xffff).await?;
            self.lte_mask(io, auth, 0xa4, 0xffff, 0xffff).await?;
        } else {
            let mut r = Rfe {
                ant_switch_exist: true,
                ant_switch_polarity: false,
                wlg_at_btg: false,
            };
            match self.facts.rfe {
                2 | 10 | 7 | 15 => r.wlg_at_btg = true,
                3 | 11 => r.ant_switch_polarity = true,
                4 | 12 => {
                    r.wlg_at_btg = true;
                    r.ant_switch_polarity = true;
                }
                5 | 13 | 6 | 14 => r.ant_switch_exist = false,
                _ => {}
            }
            self.rfe = r;
        }
        Ok(())
    }
    /// `coex_cfg_init`.
    async fn set_init(&mut self, io: &mut impl Io, auth: &impl Authority) -> Result<(), Error> {
        self.set8(io, auth, 0x550, 1 << 3).await?;
        self.m8(io, auth, 0x790, 0x3f, 0x5).await?;
        self.w8(io, auth, 0x778, 0x1).await?;
        let mux = Self::r32(io, auth, 0x40).await?;
        self.w32(io, auth, 0x40, mux | (1 << 5)).await?;
        let mux = Self::r32(io, auth, 0x40).await?;
        self.w32(io, auth, 0x40, mux | (1 << 9)).await?;
        self.set8(io, auth, 0x4c6, 1 << 4).await?;
        self.clr8(io, auth, 0x4c6, 1 << 5).await?;
        let v2 = Self::r16(io, auth, 0x762).await?;
        self.w16(io, auth, 0x762, v2 | (1 << 12)).await?;
        if self.facts.c22() {
            self.clr8(io, auth, 0x4fc, 0x3).await?;
            self.rf(io, auth, 1, 0x01, 0x40000).await?;
        } else {
            self.m8(io, auth, 0x6cf, 1 << 3, 1).await?;
        }
        Ok(())
    }
    /// `coex_cfg_gnt_debug`.
    async fn gnt_debug(&mut self, io: &mut impl Io, auth: &impl Authority) -> Result<(), Error> {
        if self.facts.c22() {
            self.m8(io, auth, 0x66, 1 << 4, 0).await?;
            self.m8(io, auth, 0x67, 1 << 0, 0).await?;
            self.m8(io, auth, 0x42, 1 << 3, 0).await?;
            self.m8(io, auth, 0x65, 1 << 7, 0).await?;
            self.m8(io, auth, MAGIC_SDIO_CTRL3, 1 << 3, 0).await
        } else {
            let pad = Self::r32(io, auth, 0x64).await?;
            self.w32(io, auth, 0x64, pad & !((1 << 20) | (1 << 24) | (1 << 15)))
                .await?;
            let mux = Self::r32(io, auth, 0x40).await?;
            self.w32(io, auth, 0x40, mux & !(1 << 19)).await?;
            let sdio = Self::r32(io, auth, 0x70).await?;
            self.w32(io, auth, 0x70, sdio & !((1 << 18) | (1 << 27)))
                .await
        }
    }
    /// `rtw8822c_coex_cfg_gnt_fix` (8821c's is empty).
    async fn gnt_fix(&mut self, io: &mut impl Io, auth: &impl Authority) -> Result<(), Error> {
        if !self.facts.c22() || self.s.gnt_workaround_state == self.s.wl_coex_mode {
            return Ok(());
        }
        self.s.gnt_workaround_state = self.s.wl_coex_mode;
        let mut rf1 = if (self.s.kt_ver == 0 && self.s.under_5g) || self.s.freerun {
            0x40021
        } else {
            0x40000
        };
        if self.share() {
            rf1 |= 1 << 13;
        }
        self.rf(io, auth, 1, 0x1, rf1).await?;
        let free = self.s.wl_coex_mode == WlMode::TwoGFree;
        if free {
            self.m8(io, auth, 0x1c32, 1 << 6, 0).await?;
        } else {
            self.m8(io, auth, 0x1c32, 1 << 6, 1).await?;
            self.m8(io, auth, 0x1c39, 1 << 4, 0).await?;
            self.m8(io, auth, 0x1c3b, 1 << 4, 1).await?;
        }
        self.m8(io, auth, 0x4160, 1 << 3, 1).await?;
        if free {
            self.m8(io, auth, 0x1860, 1 << 3, 1).await?;
            self.m8(io, auth, 0x1ca7, 1 << 3, 1).await?;
        } else if self.s.wl_coex_mode == WlMode::FiveG || self.s.under_5g || !self.share() {
            if self.s.kt_ver >= 3 {
                self.m8(io, auth, 0x1860, 1 << 3, 0).await?;
                self.m8(io, auth, 0x1ca7, 1 << 3, 1).await?;
            } else {
                self.m8(io, auth, 0x1860, 1 << 3, 1).await?;
            }
        } else {
            self.m8(io, auth, 0x1860, 1 << 3, 0).await?;
            if self.s.kt_ver >= 3 {
                self.m8(io, auth, 0x1ca7, 1 << 3, 0).await?;
            }
        }
        Ok(())
    }

    // ---- tables / TDMA ----
    fn table_wl(&self, case: u8) -> u32 {
        let t = if self.share() {
            self.chip.table_sant
        } else {
            self.chip.table_nsant
        };
        t.get(usize::from(case)).map_or(0x5a5a5a5a, |e| e.1)
    }
    fn toggle_table_a(&mut self, case: u8) {
        let w = self.table_wl(case).to_le_bytes();
        self.h2c69(0xd, [0x1, w[0], w[1], w[2], w[3]]);
    }
    fn toggle_table_b(&mut self, interval: u8, table: u32) {
        let w = table.to_le_bytes();
        self.h2c69(0x7, [interval, w[0], w[1], w[2], w[3]]);
    }
    /// `rtw_coex_set_table`.
    async fn set_table(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        force: bool,
        t0: u32,
        t1: u32,
    ) -> Result<(), Error> {
        if !force
            && self.s.reason != Reason::Lps
            && Self::r32(io, auth, 0x6c0).await? == t0
            && Self::r32(io, auth, 0x6c4).await? == t1
        {
            return Ok(());
        }
        self.w32(io, auth, 0x6c0, t0).await?;
        self.w32(io, auth, 0x6c4, t1).await?;
        self.w32(io, auth, 0x6c8, 0xf0ff_ffff).await
    }
    /// `rtw_coex_table`.
    async fn table(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        force: bool,
        case: u8,
    ) -> Result<(), Error> {
        let idx = if self.share() {
            case
        } else {
            case.wrapping_sub(100)
        };
        let t = if self.share() {
            self.chip.table_sant
        } else {
            self.chip.table_nsant
        };
        if let Some(&(bt, wl)) = t.get(usize::from(idx)) {
            self.set_table(io, auth, force, bt, wl).await?;
        }
        if self.s.wl_slot_toggle_change {
            self.toggle_table_a(idx);
        }
        Ok(())
    }
    /// `rtw_coex_set_tdma` (no AP mode; `COEX_PSTDMA_FORCE_LPSOFF`).
    fn set_tdma(&mut self, p: [u8; 5]) {
        if (p[0] & (1 << 4) != 0 && p[0] & (1 << 5) == 0) || self.s.wl_coex_mode == WlMode::TwoGFree
        {
            // COEX_PS_LPS_OFF: no LPS owner is active (lps_conf.mode 0),
            // so there is nothing to leave and no TDMA-zero pre-command.
            self.s.wl_force_lps_ctrl = true;
        } else {
            self.s.wl_force_lps_ctrl = false;
        }
        self.s.ps_tdma_para = p;
        self.tdma_sent |= p != [0; 5];
        self.send([0x60, p[0], p[1], p[2], p[3], p[4], 0, 0]);
        if p[0] & (1 << 2) != 0 {
            self.s.wl_slot_toggle = true;
            self.s.wl_slot_toggle_change = false;
        } else {
            self.s.wl_slot_toggle_change = self.s.wl_slot_toggle;
            self.s.wl_slot_toggle = false;
        }
    }
    /// `rtw_coex_tdma`.
    async fn tdma(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        force: bool,
        tcase: u32,
    ) -> Result<(), Error> {
        self.tdma_timer_base(if tcase & TDMA_4SLOT != 0 { 3 } else { 0 });
        let ty = (tcase & 0xff) as u8;
        let on = !(ty == 0 || ty == 100);
        if on {
            self.need(TDMA)?;
        }
        if !force && on == self.s.cur_ps_tdma_on && ty == self.s.cur_ps_tdma {
            return Ok(());
        }
        let busy = self.busy_flag;
        let tdma_scbd =
            !((self.s.bt_a2dp_exist && (self.s.bt_inq_remain || self.s.bt_multi_link)) || !busy);
        self.write_scbd(io, auth, SCBD_TDMA, tdma_scbd).await?;
        self.s.cur_ps_tdma_on = on;
        self.s.cur_ps_tdma = ty;
        let (t, n) = if self.share() {
            (self.chip.tdma_sant, ty)
        } else {
            (self.chip.tdma_nsant, ty.wrapping_sub(100))
        };
        if let Some(&p) = t.get(usize::from(n)) {
            self.set_tdma(p);
        }
        Ok(())
    }
    async fn apply(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        table: u8,
        tdma: u32,
    ) -> Result<(), Error> {
        self.table(io, auth, false, table).await?;
        self.tdma(io, auth, false, tdma).await
    }
    fn st(&self, sant: (u8, u32), nsant: (u8, u32)) -> (u8, u32) {
        if self.share() {
            sant
        } else {
            nsant
        }
    }

    // ---- actions ----
    async fn action_all_off(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
    ) -> Result<(), Error> {
        self.set_rf_para(io, auth, false, 0).await?;
        let (t, d) = self.st((2, 0), (100, 100));
        self.apply(io, auth, t, d).await
    }
    async fn action_freerun(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
    ) -> Result<(), Error> {
        if self.share() {
            return Ok(());
        }
        self.need(FREERUN)?;
        self.s.freerun = true;
        self.update_wl_ch_info(true);
        self.set_ant_path(io, auth, false, Ant::TwoGFreerun).await?;
        self.write_scbd(io, auth, SCBD_FIX2M, false).await?;
        let r = &self.s.wl_rssi_state;
        let level = if r[0].high() {
            2
        } else if r[1].high() {
            3
        } else if r[2].high() {
            4
        } else {
            5
        };
        let level = level.min(self.chip.rf_tx.len() - 1);
        let tx = self.s.wl_tput_tx;
        self.set_rf_para(io, auth, tx, level).await?;
        self.apply(io, auth, 100, 100).await
    }
    async fn normal(&mut self, io: &mut impl Io, auth: &impl Authority) -> Result<(), Error> {
        self.set_ant_path(io, auth, false, Ant::TwoG).await?;
        self.set_rf_para(io, auth, false, 0).await
    }
    async fn action_whql(&mut self, io: &mut impl Io, auth: &impl Authority) -> Result<(), Error> {
        self.normal(io, auth).await?;
        let (t, d) = self.st((2, 0), (100, 100));
        self.apply(io, auth, t, d).await
    }
    async fn action_relink(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
    ) -> Result<(), Error> {
        self.normal(io, auth).await?;
        let s = &self.s;
        let (t, d) = if self.share() {
            if s.wl_gl_busy {
                let slot = if s.bt_hid_exist && s.bt_profile_num == 1 {
                    TDMA_4SLOT
                } else {
                    0
                };
                (26, 20 | slot)
            } else {
                (1, 0)
            }
        } else {
            (if s.wl_gl_busy { 115 } else { 100 }, 100)
        };
        self.apply(io, auth, t, d).await
    }
    async fn action_bt_idle(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
    ) -> Result<(), Error> {
        self.set_rf_para(io, auth, false, 0).await?;
        // ant_switch_with_bt is false on both chips: no freerun shortcut.
        self.set_ant_path(io, auth, false, Ant::TwoG).await?;
        let s = &self.s;
        let (t, d) = if self.share() {
            if !s.wl_gl_busy {
                (10, 3)
            } else if s.bt_status == BtStatus::NconIdle {
                (
                    11,
                    if s.lo_pri_rx + s.lo_pri_tx > 250 {
                        17
                    } else {
                        7
                    },
                )
            } else {
                (12, 7)
            }
        } else if !s.wl_gl_busy {
            (112, 104)
        } else if s.bt_ble_scan_type & 0x2 != 0 && s.bt_status == BtStatus::NconIdle {
            (114, 103)
        } else {
            (112, 103)
        };
        self.apply(io, auth, t, d).await
    }
    async fn action_inquiry(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
    ) -> Result<(), Error> {
        self.normal(io, auth).await?;
        let s = &self.s;
        let hi = s.wl_linkscan_proc || s.wl_hi_pri_task1 || s.wl_hi_pri_task2;
        let (t, d) = if self.share() {
            if hi {
                let d = if s.bt_profile_num > 0 {
                    10
                } else if s.wl_hi_pri_task1 {
                    6
                } else if !s.bt_page {
                    8
                } else {
                    9
                };
                (15, d)
            } else if s.wl_gl_busy {
                if s.bt_profile_num == 0 {
                    (12, 18)
                } else if s.bt_profile_num == 1 && !s.bt_a2dp_exist {
                    (12, 20 | TDMA_4SLOT)
                } else {
                    (12, 26 | TDMA_4SLOT)
                }
            } else if s.wl_connected {
                (9, 27)
            } else {
                (1, 0)
            }
        } else if hi {
            let d = if s.bt_profile_num > 0 {
                110
            } else if s.wl_hi_pri_task1 {
                106
            } else if !s.bt_page {
                108
            } else {
                109
            };
            (114, d)
        } else if s.wl_gl_busy {
            (114, 121)
        } else {
            (101, 100)
        };
        self.apply(io, auth, t, d).await
    }
    async fn action_game_hid(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
    ) -> Result<(), Error> {
        self.set_ant_path(io, auth, false, Ant::TwoG).await?;
        let (t, d);
        if self.share() {
            self.s.wl_coex_mode = WlMode::TwoGFree;
            let s = &self.s;
            t = if s.bt_whck_test {
                2
            } else if s.wl_linkscan_proc || s.bt_hid_exist {
                33
            } else if s.bt_setup_link || s.bt_inq_page {
                0
            } else if s.bt_a2dp_exist {
                34
            } else {
                33
            };
            d = 0;
        } else {
            d = if self.s.wl_rssi_state[1].high() {
                112
            } else {
                113
            };
            t = 121;
        }
        if self.s.wl_coex_mode == WlMode::TwoGFree {
            let tx = self.s.wl_tput_tx;
            self.set_rf_para(io, auth, tx, if tx { 6 } else { 5 })
                .await?;
        } else {
            self.set_rf_para(io, auth, false, 0).await?;
        }
        self.apply(io, auth, t, d).await
    }
    async fn action_hfp(&mut self, io: &mut impl Io, auth: &impl Authority) -> Result<(), Error> {
        self.normal(io, auth).await?;
        let (t, d) = if self.share() {
            (10, 5)
        } else if self.s.bt_multi_link {
            (112, 117)
        } else {
            (105, 100)
        };
        self.apply(io, auth, t, d).await
    }
    async fn action_hid(&mut self, io: &mut impl Io, auth: &impl Authority) -> Result<(), Error> {
        self.normal(io, auth).await?;
        let s = &self.s;
        let ctr_hi = s.bt_ctr_ok && s.lo_pri_rx + s.lo_pri_tx > 360;
        let mut toggle = false;
        let (t, d) = if self.share() {
            if s.bt_ble_exist {
                if s.cnt_scanap > 5 {
                    (26, 2)
                } else {
                    (27, 9)
                }
            } else if s.bt_a2dp_active {
                (9, 18)
            } else if s.bt_profile_num == 1
                && s.bt_multi_link
                && (ctr_hi || s.bt_slave || s.bt_multi_link_remain)
            {
                let rx3 = DESC_RATE5_5M <= 3;
                (if s.wl_gl_busy && rx3 { 13 } else { 12 }, 26)
            } else if s.bt_418_hid_exist && s.wl_gl_busy {
                toggle = true;
                (32, 27 | TDMA_4SLOT)
            } else if s.bt_ble_hid_exist && s.wl_gl_busy {
                (36, 0)
            } else {
                (9, 9)
            }
        } else if s.bt_ble_exist {
            if s.cnt_scanap > 5 {
                (121, 102)
            } else {
                (122, 109)
            }
        } else if s.bt_a2dp_active {
            (113, 118)
        } else {
            (113, 104)
        };
        self.table(io, auth, false, t).await?;
        if toggle {
            self.toggle_table_a(t);
            self.toggle_table_b(1, WL_SLOT_TOGGLE);
        }
        self.tdma(io, auth, false, d).await
    }
    async fn action_a2dp(&mut self, io: &mut impl Io, auth: &impl Authority) -> Result<(), Error> {
        self.normal(io, auth).await?;
        let s = &self.s;
        let (t, d) = if self.share() {
            (
                if s.wl_gl_busy && s.wl_noisy_level == 0 {
                    12
                } else {
                    9
                },
                if s.wl_connecting || !s.wl_gl_busy {
                    14
                } else {
                    13
                },
            )
        } else {
            (112, if s.wl_rssi_state[1].high() { 112 } else { 113 })
        };
        self.apply(io, auth, t, d | TDMA_4SLOT).await
    }
    async fn action_a2dpsink(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
    ) -> Result<(), Error> {
        self.normal(io, auth).await?;
        let (t, d) = if self.share() {
            (28, if self.s.wl_gl_busy { 20 } else { 26 })
        } else {
            (119, 120)
        };
        self.apply(io, auth, t, d).await
    }
    async fn action_pan(&mut self, io: &mut impl Io, auth: &impl Authority) -> Result<(), Error> {
        self.normal(io, auth).await?;
        let s = &self.s;
        let (t, d) = if self.share() {
            (
                if s.wl_gl_busy && s.wl_noisy_level == 0 {
                    14
                } else {
                    10
                },
                if s.wl_gl_busy { 17 } else { 20 },
            )
        } else {
            (112, if s.wl_gl_busy { 117 } else { 119 })
        };
        self.apply(io, auth, t, d).await
    }
    async fn action_a2dp_hid(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
    ) -> Result<(), Error> {
        self.normal(io, auth).await?;
        let s = &self.s;
        let mut interval = 0;
        let mut toggle = false;
        let (t, d) = if self.share() {
            let t = if s.bt_ble_exist {
                26
            } else {
                if s.bt_418_hid_exist {
                    interval = 1;
                }
                9
            };
            let d = if s.wl_connecting || !s.wl_gl_busy {
                14
            } else if s.bt_418_hid_exist {
                toggle = true;
                23
            } else {
                13
            };
            (t, d)
        } else {
            (
                if s.bt_ble_exist { 121 } else { 113 },
                if s.wl_rssi_state[1].high() { 112 } else { 113 },
            )
        };
        self.table(io, auth, false, t).await?;
        if toggle {
            self.toggle_table_a(t);
            self.toggle_table_b(interval, WL_SLOT_TOGGLE);
        }
        self.tdma(io, auth, false, d | TDMA_4SLOT).await
    }
    async fn action_a2dp_pan(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
    ) -> Result<(), Error> {
        self.normal(io, auth).await?;
        let s = &self.s;
        let (t, d) = if self.share() {
            (
                if s.wl_gl_busy && s.wl_noisy_level == 0 {
                    14
                } else {
                    10
                },
                if s.wl_gl_busy { 15 } else { 20 },
            )
        } else {
            (112, if s.wl_gl_busy { 115 } else { 120 })
        };
        self.set_rf_para(io, auth, false, 0).await?;
        self.apply(io, auth, t, d).await
    }
    async fn action_pan_hid(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
    ) -> Result<(), Error> {
        self.normal(io, auth).await?;
        let busy = self.s.wl_gl_busy;
        let (t, d) = if self.share() {
            (9, if busy { 18 } else { 19 })
        } else {
            (113, if busy { 117 } else { 119 })
        };
        self.apply(io, auth, t, d).await
    }
    async fn action_a2dp_pan_hid(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
    ) -> Result<(), Error> {
        self.normal(io, auth).await?;
        let busy = self.s.wl_gl_busy;
        let (t, d) = if self.share() {
            (10, if busy { 15 } else { 20 })
        } else {
            (113, if busy { 115 } else { 120 })
        };
        self.apply(io, auth, t, d).await
    }
    async fn action_under5g(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
    ) -> Result<(), Error> {
        self.need(BAND5)?;
        self.set_ant_path(io, auth, true, Ant::FiveG).await?;
        self.set_rf_para(io, auth, false, 0).await?;
        self.write_scbd(io, auth, SCBD_FIX2M, false).await?;
        if self.s.bt_game_hid_exist && self.s.wl_linkscan_proc {
            self.s.wl_coex_mode = WlMode::TwoGFree;
        }
        let (t, d) = self.st((0, 0), (100, 100));
        self.apply(io, auth, t, d).await
    }
    async fn action_wl_only(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
    ) -> Result<(), Error> {
        self.normal(io, auth).await?;
        let (t, d) = self.st((2, 0), (100, 100));
        self.apply(io, auth, t, d).await
    }
    async fn action_native_lps(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
    ) -> Result<(), Error> {
        if self.s.under_5g {
            return Ok(());
        }
        self.set_ant_path(io, auth, false, Ant::TwoG).await?;
        let (t, d) = self.st((28, 0), (100, 100));
        if self.s.bt_game_hid_exist {
            self.s.wl_coex_mode = WlMode::TwoGFree;
            let tx = self.s.wl_tput_tx;
            self.set_rf_para(io, auth, tx, if tx { 6 } else { 5 })
                .await?;
        } else {
            self.set_rf_para(io, auth, false, 0).await?;
        }
        self.apply(io, auth, t, d).await
    }
    async fn action_linkscan(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
    ) -> Result<(), Error> {
        self.normal(io, auth).await?;
        let s = &self.s;
        let (t, d) = if self.share() {
            if s.bt_a2dp_exist {
                (if s.wl_gl_busy { 26 } else { 9 }, 11 | TDMA_4SLOT)
            } else {
                (9, 7)
            }
        } else if s.bt_a2dp_exist {
            (112, 111 | TDMA_4SLOT)
        } else {
            (112, 107)
        };
        self.apply(io, auth, t, d).await
    }
    async fn action_not_connected(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
    ) -> Result<(), Error> {
        self.normal(io, auth).await?;
        let (t, d) = self.st((1, 0), (100, 100));
        self.apply(io, auth, t, d).await
    }
    /// `rtw_coex_freerun_check` (`ant_distance` 10).
    fn freerun_check(&self) -> bool {
        let s = &self.s;
        if s.bt_disabled || self.share() || !s.wl_gl_busy {
            return false;
        }
        if s.bt_hid_pair_num >= 2 {
            return true;
        }
        if s.wl_rssi_state[1].high() && s.bt_rssi_state[0].high() {
            return true;
        }
        let bt = if s.wl_tput_tx {
            s.bt_rssi_state[0]
        } else {
            s.bt_rssi_state[1]
        };
        s.wl_rssi_state[3].high() && bt.high() && s.cnt_scanap <= 5
    }
    async fn action_connected(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
    ) -> Result<(), Error> {
        let s = &self.s;
        let map = u8::from(s.bt_hfp_exist)
            | u8::from(s.bt_hid_exist) << 1
            | u8::from(s.bt_a2dp_exist) << 2
            | u8::from(s.bt_pan_exist) << 3;
        // rtw_coex_algorithm
        const HFP: u8 = 1;
        const HID: u8 = 2;
        const A2DP: u8 = 4;
        const PAN: u8 = 8;
        match map {
            HFP => self.action_hfp(io, auth).await,
            HID | 3 => {
                if self.freerun_check() {
                    self.action_freerun(io, auth).await
                } else {
                    self.action_hid(io, auth).await
                }
            }
            5..=7 => self.a2dp_hid_or_freerun(io, auth).await,
            9..=11 => self.action_pan_hid(io, auth).await,
            13..=15 => self.action_a2dp_pan_hid(io, auth).await,
            PAN => self.action_pan(io, auth).await,
            12 => self.action_a2dp_pan(io, auth).await,
            A2DP => {
                if self.s.bt_multi_link {
                    if self.s.bt_hid_pair_num > 0 {
                        self.a2dp_hid_or_freerun(io, auth).await
                    } else {
                        self.action_a2dp_pan(io, auth).await
                    }
                } else if self.freerun_check() {
                    self.action_freerun(io, auth).await
                } else if self.s.bt_a2dp_sink {
                    self.action_a2dpsink(io, auth).await
                } else {
                    self.action_a2dp(io, auth).await
                }
            }
            _ => self.action_bt_idle(io, auth).await,
        }
    }
    async fn a2dp_hid_or_freerun(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
    ) -> Result<(), Error> {
        if self.freerun_check() {
            self.action_freerun(io, auth).await
        } else {
            self.action_a2dp_hid(io, auth).await
        }
    }

    /// `rtw_coex_run_coex`.
    async fn run(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        reason: Reason,
    ) -> Result<(), Error> {
        self.s.reason = reason;
        self.update_wl_link_info(io, auth, reason).await?;
        self.monitor_bt_enable(io, auth).await?;
        if self.s.stop_dm || self.s.wl_under_ips {
            return Ok(());
        }
        if self.s.freeze && reason == Reason::BtInfo && !self.s.bt_setup_link {
            return Ok(());
        }
        self.s.freerun = false;
        if self.s.under_5g {
            self.s.wl_coex_mode = WlMode::FiveG;
            self.action_under5g(io, auth).await?;
        } else {
            self.s.wl_coex_mode = WlMode::TwoG1Port;
            let s = &self.s;
            if s.bt_disabled {
                if !s.wl_connected {
                    self.action_not_connected(io, auth).await?;
                } else {
                    self.action_wl_only(io, auth).await?;
                }
            } else if s.wl_under_lps && !s.wl_force_lps_ctrl {
                self.action_native_lps(io, auth).await?;
            } else if s.bt_game_hid_exist && s.wl_connected {
                self.action_game_hid(io, auth).await?;
            } else if s.bt_whck_test {
                self.action_whql(io, auth).await?;
            } else if s.bt_setup_link {
                self.action_relink(io, auth).await?;
            } else if s.bt_inq_page {
                self.action_inquiry(io, auth).await?;
            } else if matches!(s.bt_status, BtStatus::NconIdle | BtStatus::ConIdle)
                && s.wl_connected
            {
                self.action_bt_idle(io, auth).await?;
            } else if s.wl_linkscan_proc && !s.freerun {
                self.action_linkscan(io, auth).await?;
            } else if s.wl_connected {
                self.action_connected(io, auth).await?;
            } else {
                self.action_not_connected(io, auth).await?;
            }
        }
        // exit: wl_mimo_ps_support (8822c) only when the record carries it.
        if self.facts.c22() && self.record.modes & MIMO_PS != 0 {
            let free = self.s.wl_coex_mode == WlMode::TwoGFree;
            let force = free && reason == Reason::Media2g;
            self.mimo_ps(force, free);
        } else if self.s.wl_coex_mode == WlMode::TwoGFree {
            // 2GFREE without coexistence-driven 1SS was not qualified.
            return Err(Error::Unsupported);
        }
        self.gnt_fix(io, auth).await?;
        self.limited_wl(io, auth).await
    }
    /// `rtw_coex_mimo_ps`: the caller applies `rtw_set_txrx_1ss`.
    fn mimo_ps(&mut self, force: bool, state: bool) {
        if !force && state == self.s.wl_mimo_ps {
            return;
        }
        self.s.wl_mimo_ps = state;
        self.txrx_1ss = state;
        let connected = self.s.wl_connected;
        self.update_wl_ch_info(connected);
    }
    /// `main.c::rtw_set_txrx_1ss` hardware half for the requested state:
    /// `rtw8822c_config_trx_mode(BB_PATH_A, BB_PATH_A, false)` on entry,
    /// and on exit the exact pre-entry fields (Linux reprograms
    /// `hal.antenna_tx/rx`, which is the retained base program). Returns
    /// whether the hardware state changed. The caller applies the RA mask,
    /// STBC and SMPS halves.
    pub(super) async fn config_trx(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
    ) -> Result<bool, Error> {
        if self.txrx_1ss == self.trx_1ss() {
            return Ok(false);
        }
        if self.txrx_1ss {
            if !self.facts.c22() {
                return Err(Error::Unsupported);
            }
            self.need(MIMO_PS)?;
            let mut saved = Vec::with_capacity(TRX_1SS.len());
            for &(reg, mask, _, _) in TRX_1SS {
                let v = enclosed(|op| auth.run(op), super::radio::read(io, reg)).await?;
                saved.push((v & mask) >> mask.trailing_zeros());
            }
            // Retained before the first write so a failure restores them.
            self.trx_saved = saved;
            let values: Vec<u32> = TRX_1SS.iter().map(|t| t.2).collect();
            Self::trx_program(io, auth, &values).await?;
        } else {
            // Cleared only once the base fields are back, so a failure here
            // still restores them under the base gate.
            let saved = self.trx_saved.clone();
            Self::trx_program(io, auth, &saved).await?;
            self.trx_saved.clear();
        }
        Ok(true)
    }
    /// `rtw8822c_config_trx_mode` order over [`TRX_1SS`] with `values`:
    /// `config_cck_tx_path`/`config_ofdm_tx_path` each end in `bb_reset`,
    /// `config_tx_path` adds one more, then `rtw8822c_toggle_igi`.
    async fn trx_program(
        io: &mut impl Io,
        auth: &impl Authority,
        values: &[u32],
    ) -> Result<(), Error> {
        if values.len() != TRX_1SS.len() {
            return Err(Error::State);
        }
        for (&(reg, mask, _, reset), &v) in TRX_1SS.iter().zip(values) {
            enclosed(|op| auth.run(op), async {
                super::radio::mask(io, reg, mask, v).await?;
                if reset {
                    super::radio::bb_reset(io).await?;
                }
                Ok(())
            })
            .await?;
        }
        enclosed(|op| auth.run(op), async {
            super::radio::bb_reset(io).await?;
            super::radio::toggle_igi(io).await
        })
        .await
    }
    /// `rtw_coex_limited_wl` / `rtw_coex_limited_tx`.
    async fn limited_wl(&mut self, io: &mut impl Io, auth: &impl Authority) -> Result<(), Error> {
        let on = !self.s.under_5g && self.s.bt_status != BtStatus::NconIdle;
        if self.s.wl_tx_limit_en == on && self.s.wl_ampdu_limit_en == on {
            return Ok(());
        }
        let t_owns = self.link.t_owns_retry;
        if !self.s.wl_tx_limit_en {
            self.s.darfrc = Self::r32(io, auth, 0x430).await?;
            self.s.darfrch = Self::r32(io, auth, 0x434).await?;
            self.s.retry_limit = Self::r16(io, auth, 0x42a).await?;
        }
        if !self.s.wl_ampdu_limit_en {
            self.s.ampdu_max_time = Self::r8(io, auth, 0x455).await?;
        }
        self.s.wl_tx_limit_en = on;
        self.s.wl_ampdu_limit_en = on;
        if on {
            self.set8(io, auth, 0x45e, 1 << 3).await?;
            self.set8(io, auth, 0x426, 0xf).await?;
            if !t_owns {
                self.w16(io, auth, 0x42a, 0x0808).await?;
            }
            self.w32(io, auth, 0x430, 0x0100_0000).await?;
            self.w32(io, auth, 0x434, 0x0403_0201).await?;
            if !t_owns {
                self.w8(io, auth, 0x455, 0x20).await?;
            }
        } else {
            self.clr8(io, auth, 0x45e, 1 << 3).await?;
            self.clr8(io, auth, 0x426, 0xf).await?;
            if !t_owns {
                let r = self.s.retry_limit;
                self.w16(io, auth, 0x42a, r).await?;
            }
            let (a, b) = (self.s.darfrc, self.s.darfrch);
            self.w32(io, auth, 0x430, a).await?;
            self.w32(io, auth, 0x434, b).await?;
            if !t_owns {
                let m = self.s.ampdu_max_time;
                self.w8(io, auth, 0x455, m).await?;
            }
        }
        Ok(())
    }

    /// `__rtw_coex_init_hw_config`.
    async fn init_hw(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        wifi_only: bool,
    ) -> Result<(), Error> {
        // rtw_coex_init_coex_var clears coex_dm/coex_stat only.
        let (under_5g, freerun) = (self.s.under_5g, self.s.freerun);
        self.s = Stat::new();
        self.s.under_5g = under_5g;
        self.s.freerun = freerun;
        self.s.kt_ver = Self::r8(io, auth, 0xf1).await? >> 4;
        self.monitor_bt_enable(io, auth).await?;
        let ext = self.s.wl_slot_extend;
        self.wl_slot_extend(ext);
        self.set8(io, auth, 0x550, 1 << 3).await?;
        self.set_rfe_type(io, auth).await?;
        self.set_init(io, auth).await?;
        self.wl_pri_mask(io, auth, 3, 1).await?;
        self.wl_pri_mask(io, auth, 4, 1).await?;
        self.wl_pri_mask(io, auth, 27, 1).await?;
        if wifi_only {
            self.set_ant_path(io, auth, true, Ant::WOnly).await?;
            self.write_scbd(io, auth, SCBD_ACTIVE | SCBD_ONOFF, true)
                .await?;
            self.s.stop_dm = true;
        } else {
            self.set_ant_path(io, auth, true, Ant::Init).await?;
            self.write_scbd(io, auth, SCBD_ACTIVE | SCBD_ONOFF, true)
                .await?;
            self.s.stop_dm = false;
            self.s.freeze = true;
        }
        self.table(io, auth, true, 1).await?;
        self.tdma(io, auth, true, 0).await?;
        self.query_bt_info();
        Ok(())
    }

    /// `rtw_power_on`: `rtw_coex_power_on_setting` then
    /// `rtw_coex_init_hw_config(!efuse.btcoex)`.
    pub(super) async fn start(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        link: Link,
    ) -> Result<Vec<[u8; 8]>, Error> {
        self.link = link;
        self.s.stop_dm = true;
        self.set8(io, auth, 0x02, (1 << 1) | (1 << 0)).await?;
        self.monitor_bt_enable(io, auth).await?;
        self.set_rfe_type(io, auth).await?;
        self.set_ant_path(io, auth, true, Ant::PowerOn).await?;
        self.table(io, auth, true, 1).await?;
        self.w8(io, auth, 0xff1a, 0).await?;
        self.gnt_debug(io, auth).await?;
        let wifi_only = !self.facts.btcoex();
        self.init_hw(io, auth, wifi_only).await?;
        self.initialized = true;
        Ok(self.take())
    }
    /// `rtw_coex_ips_notify`.
    pub(super) async fn ips(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        link: Link,
        enter: bool,
    ) -> Result<Vec<[u8; 8]>, Error> {
        self.link = link;
        if self.s.stop_dm {
            return Ok(self.take());
        }
        if enter {
            self.s.wl_under_ips = true;
            self.write_scbd(io, auth, SCBD_ALL, false).await?;
            self.set_ant_path(io, auth, true, Ant::WOff).await?;
            self.action_all_off(io, auth).await?;
        } else {
            self.write_scbd(io, auth, SCBD_ACTIVE | SCBD_ONOFF, true)
                .await?;
            self.init_hw(io, auth, false).await?;
            self.s.wl_under_ips = false;
        }
        Ok(self.take())
    }
    /// `rtw_coex_lps_notify`.
    pub(super) async fn lps(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        link: Link,
        enable: bool,
    ) -> Result<Vec<[u8; 8]>, Error> {
        self.link = link;
        if self.s.stop_dm {
            return Ok(self.take());
        }
        if enable {
            self.s.wl_under_lps = true;
            if self.s.wl_force_lps_ctrl {
                self.write_scbd(io, auth, SCBD_ACTIVE, true).await?;
            } else {
                self.write_scbd(io, auth, SCBD_ACTIVE, false).await?;
                self.write_scbd(io, auth, SCBD_WLBUSY, false).await?;
                self.run(io, auth, Reason::Lps).await?;
            }
        } else {
            self.s.wl_under_lps = false;
            self.write_scbd(io, auth, SCBD_ACTIVE, true).await?;
            if !self.s.wl_force_lps_ctrl {
                self.query_bt_info();
            }
            self.run(io, auth, Reason::Lps).await?;
        }
        Ok(self.take())
    }
    /// `rtw_coex_scan_notify` (`start`: Some(band5) or None for finish).
    pub(super) async fn scan(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        link: Link,
        start: Option<bool>,
    ) -> Result<Vec<[u8; 8]>, Error> {
        self.link = link;
        if self.s.stop_dm {
            return Ok(self.take());
        }
        self.scan_inner(io, auth, start).await?;
        Ok(self.take())
    }
    async fn scan_inner(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        start: Option<bool>,
    ) -> Result<(), Error> {
        self.s.freeze = false;
        self.write_scbd(io, auth, SCBD_ACTIVE | SCBD_ONOFF, true)
            .await?;
        match start {
            Some(true) => {
                self.need(BAND5)?;
                self.set_ant_path(io, auth, true, Ant::FiveG).await?;
                self.run(io, auth, Reason::Scan5gStart).await
            }
            Some(false) => {
                self.s.wl_hi_pri_task2 = true;
                self.set_ant_path(io, auth, true, Ant::TwoG).await?;
                self.run(io, auth, Reason::Scan2gStart).await
            }
            None => {
                self.s.cnt_scanap = 30;
                self.s.wl_hi_pri_task2 = false;
                self.run(io, auth, Reason::ScanFinish).await
            }
        }
    }
    /// `rtw_coex_switchband_notify` (`main.c::rtw_set_channel` on a band
    /// change; a 2.4GHz switch outside scan runs `COEX_SCAN_START_2G`).
    pub(super) async fn switchband(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        link: Link,
        to5g: bool,
        for_scan: bool,
    ) -> Result<Vec<[u8; 8]>, Error> {
        self.link = link;
        if self.s.stop_dm {
            return Ok(self.take());
        }
        if to5g {
            self.run(io, auth, Reason::Switchband5g).await?;
        } else if !for_scan {
            self.run(io, auth, Reason::Switchband2g).await?;
        } else {
            self.scan_inner(io, auth, Some(false)).await?;
        }
        Ok(self.take())
    }
    /// `rtw_coex_connect_notify` (`start`: true at `mgd_prepare_tx`,
    /// false at association).
    pub(super) async fn connect(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        link: Link,
        start: bool,
    ) -> Result<Vec<[u8; 8]>, Error> {
        self.link = link;
        if self.s.stop_dm {
            return Ok(self.take());
        }
        self.write_scbd(io, auth, SCBD_ACTIVE | SCBD_ONOFF, true)
            .await?;
        let band5 = link.band5;
        match (band5, start) {
            (true, true) => {
                self.need(BAND5)?;
                self.set_ant_path(io, auth, true, Ant::FiveG).await?;
                self.run(io, auth, Reason::Con5gStart).await?;
            }
            (true, false) => {
                self.need(BAND5)?;
                self.set_ant_path(io, auth, true, Ant::FiveG).await?;
                self.run(io, auth, Reason::Con5gFinish).await?;
            }
            (false, true) => {
                self.s.wl_hi_pri_task1 = true;
                self.s.wl_connecting = true;
                self.works.wl_connecting = Some(link.now + 2000);
                self.set_ant_path(io, auth, true, Ant::TwoG).await?;
                self.run(io, auth, Reason::Con2gStart).await?;
                self.s.freeze = true;
                self.works.defreeze = Some(link.now + 5000);
            }
            (false, false) => {
                self.s.wl_hi_pri_task1 = false;
                self.s.freeze = false;
                self.s.wl_connecting = false;
                self.run(io, auth, Reason::Con2gFinish).await?;
            }
        }
        Ok(self.take())
    }
    /// `rtw_coex_media_status_notify` plus the `bss_info_changed` beacon
    /// interval (`coex_stat->wl_beacon_interval`).
    pub(super) async fn media(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        link: Link,
        connect: bool,
        beacon_interval: u16,
    ) -> Result<Vec<[u8; 8]>, Error> {
        self.link = link;
        if self.s.stop_dm {
            return Ok(self.take());
        }
        if connect && link.band5 {
            self.need(BAND5)?;
            self.write_scbd(io, auth, SCBD_ACTIVE, true).await?;
            self.set_ant_path(io, auth, true, Ant::FiveG).await?;
            self.run(io, auth, Reason::Media5g).await?;
        } else if connect {
            self.s.wl_connecting = false;
            self.write_scbd(io, auth, SCBD_ACTIVE, true).await?;
            self.set_ant_path(io, auth, true, Ant::TwoG).await?;
            self.wl_pri_mask(io, auth, 28, 1).await?;
            self.run(io, auth, Reason::Media2g).await?;
        } else {
            self.wl_pri_mask(io, auth, 28, 0).await?;
            self.run(io, auth, Reason::MediaDiscon).await?;
        }
        self.update_wl_ch_info(connect);
        // mac80211.c handles BSS_CHANGED_BEACON_INT after BSS_CHANGED_ASSOC.
        if connect {
            self.s.wl_beacon_interval = beacon_interval;
        }
        Ok(self.take())
    }

    /// Route one firmware C2H (`[id, seq, payload..]`). Returns true when
    /// it was a coexistence event.
    pub(super) async fn c2h(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        link: Link,
        body: &[u8],
    ) -> Result<Option<Vec<[u8; 8]>>, Error> {
        if body.len() < 3 {
            return Ok(None);
        }
        self.link = link;
        let p = &body[2..];
        match body[0] {
            0x09 => self.bt_info(io, auth, p).await?,
            0x45 => self.hid_info(io, auth, p).await?,
            0x0b => self.mp_info(p),
            0x27 => self.fwdbg(p),
            _ => return Ok(None),
        }
        Ok(Some(self.take()))
    }
    /// `rtw_coex_info_response` + the requester's parse. Linux waits 10ms
    /// for the reply; here the reply is applied when it arrives.
    fn mp_info(&mut self, p: &[u8]) {
        if p.first() != Some(&1) || p.len() < 4 {
            return;
        }
        if self.mp_pending.take() == Some(0x2d) {
            self.s.bt_ble_scan_type = p[3];
        }
    }
    fn fwdbg(&mut self, p: &[u8]) {
        if p.len() < 8 || p[0] != 0x08 {
            return;
        }
        for (i, &v) in p.iter().enumerate().take(8).skip(1) {
            let pre = self.s.wl_fw_dbg_info_pre[i];
            self.s.wl_fw_dbg_info[i] = if v >= pre { v - pre } else { 255 - pre + v };
            self.s.wl_fw_dbg_info_pre[i] = v;
        }
        self.wl_ccklock_action();
        self.wl_ccklock_detect();
    }
    /// `rtw_coex_bt_info_notify`.
    async fn bt_info(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        buf: &[u8],
    ) -> Result<(), Error> {
        let src = buf[0] & 0xf;
        if src >= 6 {
            return Ok(());
        }
        match src {
            3 => {
                if let Some(&v) = buf.get(1) {
                    self.s.bt_iqk_state = v;
                }
                return Ok(());
            }
            4 => {
                self.monitor_bt_enable(io, auth).await?;
                if self.s.bt_disabled != self.s.bt_disabled_pre {
                    self.s.bt_disabled_pre = self.s.bt_disabled;
                    self.run(io, auth, Reason::BtInfo).await?;
                }
                return Ok(());
            }
            5 => return Ok(()),
            0 => {
                self.update_bt_link_info();
                return Ok(());
            }
            _ => {
                if self.s.bt_disabled {
                    self.s.bt_disabled = false;
                    self.s.bt_reenable = true;
                    self.works.bt_reenable = Some(self.link.now + 15000);
                }
            }
        }
        if buf.len() != BTINFO_LENGTH {
            return Ok(());
        }
        let info: [u8; 6] = [buf[1], buf[2], buf[3], buf[4], buf[5], buf[6]];
        if info == self.s.bt_info {
            return Ok(());
        }
        self.s.bt_info = info;
        let [lb2, lb3, hb0, hb1, hb2, hb3] = info;
        self.s.bt_whck_test = lb2 == 0xff;
        let inq_page = lb2 & (1 << 2) != 0;
        if inq_page != self.s.bt_inq_page {
            self.works.bt_remain = None;
            self.s.bt_inq_page = inq_page;
            if inq_page {
                self.s.bt_inq_remain = true;
            } else {
                self.works.bt_remain = Some(self.link.now + 4000);
            }
        }
        if self.chip.ble_hid_profile_support {
            if lb2 & (1 << 5) != 0 {
                self.s.bt_ble_hid_exist = hb1 & 1 != 0;
                self.s.bt_ble_exist = false;
            } else if hb1 & 1 != 0 {
                self.s.bt_ble_hid_exist = false;
                self.s.bt_ble_exist = true;
            } else {
                self.s.bt_ble_hid_exist = false;
                self.s.bt_ble_exist = false;
            }
        } else if hb1 & 1 != 0 {
            let s = &self.s;
            let hid = s.bt_hid_slot == 1 && s.hi_pri_rx + 100 < s.hi_pri_tx && s.hi_pri_rx < 100;
            self.s.bt_ble_hid_exist = hid;
            self.s.bt_ble_exist = !hid;
        } else {
            self.s.bt_ble_hid_exist = false;
            self.s.bt_ble_exist = false;
        }
        self.s.bt_page = lb3 & (1 << 7) != 0;
        self.s.bt_rssi = if self.chip.bt_rssi_ratio {
            hb0.wrapping_mul(2).wrapping_add(10)
        } else if hb0 <= 127 {
            100
        } else if 256 - u16::from(hb0) <= 100 {
            (100 - (256 - u16::from(hb0))) as u8
        } else {
            0
        };
        if hb1 & (1 << 2) != 0 {
            self.s.bt_setup_link = true;
            let delay = if self.s.bt_reenable { 6000 } else { 1000 };
            self.works.bt_relink = Some(self.link.now + delay);
        }
        self.s.bt_ble_scan_en = hb1 & (1 << 5) != 0;
        self.s.bt_multi_link = hb1 & (1 << 7) != 0;
        if !self.s.bt_multi_link && self.s.bt_multi_link_pre {
            self.s.bt_multi_link_remain = true;
            self.works.multi_link_remain = Some(self.link.now + 3000);
        }
        self.s.bt_multi_link_pre = self.s.bt_multi_link;
        if hb1 & (1 << 1) != 0 {
            let c = self.s.wl_connected;
            self.update_wl_ch_info(c);
        }
        if hb1 & (1 << 3) != 0 && hb1 & (1 << 2) == 0 && !self.s.stop_dm {
            // rtw_coex_ignore_wlan_act(false)
            self.send([0x63, 0, 0, 0, 0, 0, 0, 0]);
        }
        self.s.bt_a2dp_active = hb2 & (1 << 2) != 0;
        self.s.bt_slave = hb2 & (1 << 3) != 0;
        self.s.bt_hid_slot = (hb2 & 0x30) >> 4;
        self.s.bt_hid_pair_num = (hb2 & 0xc0) >> 6;
        if self.s.bt_hid_pair_num > 0 && self.s.bt_hid_slot >= 2 {
            self.s.bt_418_hid_exist = true;
        } else if self.s.bt_hid_pair_num == 0 || self.s.bt_hid_slot == 1 {
            self.s.bt_418_hid_exist = false;
        }
        self.s.bt_a2dp_sink = hb3 & (1 << 7) != 0;
        self.update_bt_link_info();
        self.run(io, auth, Reason::BtInfo).await
    }
    fn hid_supported(&self) -> bool {
        self.facts.c22() && self.record.modes & MIMO_PS != 0
    }
    /// `rtw_coex_bt_hid_info_notify`.
    async fn hid_info(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        buf: &[u8],
    ) -> Result<(), Error> {
        if buf.len() < 3 {
            return Ok(());
        }
        let sub = buf[2];
        if !self.hid_supported() && (sub == HIDINFO_LIST || sub == HIDINFO_A) {
            return Ok(());
        }
        match sub {
            HIDINFO_LIST if buf.len() >= 8 => {
                let list: [u8; 8] = buf[..8].try_into().map_err(|_| Error::Unsupported)?;
                if list == self.s.hid_list {
                    return Ok(());
                }
                self.s.hid_list = list;
                self.s.hid = [Hid::default(); 4];
                for i in 0..4 {
                    let h = list[4 + i];
                    if h != HIDINFO_NOTCON && h != 0 {
                        self.s.hid[i].handle = h;
                    }
                }
            }
            HIDINFO_A if buf.len() >= 8 => {
                let handle = buf[3];
                if let Some(h) = self.s.hid.iter_mut().find(|h| h.handle == handle) {
                    h.vendor = buf[4];
                    h.name = [buf[5], buf[6], buf[7]];
                    h.completed = true;
                }
            }
            _ => {}
        }
        let mut games = 0;
        for h in self.s.hid.iter_mut() {
            if !h.completed
                || h.handle == HIDINFO_NOTCON
                || h.handle == 0
                || h.handle >= BLE_HANDLE_THRS
            {
                h.game = false;
                continue;
            }
            h.game = h.vendor == HIDINFO_MTK
                && (h.name == [0x57, 0x69, 0x72] || h.name == [0x58, 0x62, 0x6f]);
            if h.game {
                games += 1;
            }
        }
        let game = games > 0;
        if game != self.s.bt_game_hid_exist {
            self.s.bt_game_hid_exist = game;
            self.run(io, auth, Reason::BtStatus).await?;
        }
        Ok(())
    }
    /// `rtw_coex_query_bt_hid_list`.
    fn query_bt_hid_list(&mut self) {
        let s = &self.s;
        if !self.hid_supported() || s.wl_under_ips || (s.wl_under_lps && !s.wl_force_lps_ctrl) {
            return;
        }
        let busy_link =
            s.bt_info[0] & INFO_CONNECTION != 0 && s.hi_pri_tx + s.hi_pri_rx > GAMEHID_CNT;
        if !(s.bt_hid_exist || busy_link) {
            return;
        }
        self.send([0x73, HIDINFO_LIST, 0, 0, 0, 0, 0, 0]);
        let pending: Vec<u8> = self
            .s
            .hid
            .iter()
            .filter(|h| {
                !(h.handle == 0
                    || h.handle == HIDINFO_NOTCON
                    || h.handle >= BLE_HANDLE_THRS
                    || h.completed)
            })
            .map(|h| h.handle)
            .collect();
        for handle in pending {
            self.send([0x73, HIDINFO_A, handle, 0, 0, 0, 0, 0]);
        }
    }

    /// Fire due delayed works (`rtw_coex_*_work`).
    async fn works(&mut self, io: &mut impl Io, auth: &impl Authority) -> Result<(), Error> {
        let now = self.link.now;
        let due = |w: &mut Option<u64>| -> bool {
            if w.is_some_and(|d| now >= d) {
                *w = None;
                true
            } else {
                false
            }
        };
        if due(&mut self.works.bt_reenable) {
            self.s.bt_reenable = false;
        }
        if due(&mut self.works.multi_link_remain) {
            self.s.bt_multi_link_remain = false;
        }
        if due(&mut self.works.ccklock) {
            self.s.wl_cck_lock = false;
        }
        if due(&mut self.works.bt_relink) {
            self.s.bt_setup_link = false;
            self.run(io, auth, Reason::WlStatus).await?;
        }
        if due(&mut self.works.defreeze) {
            self.s.freeze = false;
            self.s.wl_hi_pri_task1 = false;
            self.run(io, auth, Reason::WlStatus).await?;
        }
        if due(&mut self.works.wl_remain) {
            self.s.wl_gl_busy = self.busy_flag;
            self.run(io, auth, Reason::WlStatus).await?;
        }
        if due(&mut self.works.bt_remain) {
            self.s.bt_inq_remain = self.s.bt_inq_page;
            self.run(io, auth, Reason::BtStatus).await?;
        }
        if due(&mut self.works.wl_connecting) {
            self.s.wl_connecting = false;
            self.run(io, auth, Reason::WlStatus).await?;
        }
        Ok(())
    }
    /// Delayed works only (between watchdog periods).
    pub(super) async fn poll(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        link: Link,
    ) -> Result<Vec<[u8; 8]>, Error> {
        self.link = link;
        if !self.s.stop_dm {
            self.works(io, auth).await?;
        }
        Ok(self.take())
    }
    /// The coexistence part of one `rtw_watch_dog_work` period.
    pub(super) async fn watchdog(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        link: Link,
        traffic: Traffic,
    ) -> Result<Vec<[u8; 8]>, Error> {
        self.link = link;
        let prev = self.busy_flag;
        self.busy_flag = traffic.tx_cnt > 100 || traffic.rx_cnt > 100;
        // DECLARE_EWMA(tp, 10, 2) over unicast Mbps (RTW_TP_SHIFT 18).
        let ewma = |avg: &mut u64, v: u64| {
            let v = (v >> 18).min(u64::from(u32::MAX)) << 10;
            *avg = if *avg == 0 { v } else { (*avg + v) >> 1 };
        };
        ewma(&mut self.tx_tp, traffic.tx_bytes);
        ewma(&mut self.rx_tp, traffic.rx_bytes);
        if self.s.stop_dm {
            return Ok(self.take());
        }
        if prev != self.busy_flag {
            self.run(io, auth, Reason::WlStatus).await?;
        }
        if !link.scanning {
            if !((self.s.wl_under_lps && !self.s.wl_force_lps_ctrl) || self.s.wl_under_ips) {
                self.monitor_bt_ctr(io, auth).await?;
            }
            self.query_bt_hid_list();
        }
        self.works(io, auth).await?;
        Ok(self.take())
    }
}
