// SPDX-License-Identifier: GPL-2.0-or-later
//! Literal RTL8821A two-antenna source-program cases over the actual Ctx/Hal
//! boundary. Register/H2C models supply no physical coexistence qualification.
use super::super::{btc::*, tests::FakeHal};
use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
fn board() -> BtCoexist {
    BtCoexist::bind(HwPg {
        bt_exist: true,
        ant_num: 2,
        single_ant_path: 0,
        chip_type: ChipType::Rtl8821,
        package_type: 0,
        rfe_type: 0,
        interface: ChipInterface::Pci,
    })
}
fn run<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    for _ in 0..1024 {
        if let Poll::Ready(v) = f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            return v;
        }
    }
    panic!("bounded RTL8821A two-antenna source fixture did not complete");
}
fn seed(hal: &mut FakeHal, reg: u16, value: u32) {
    for (i, b) in value.to_le_bytes().iter().enumerate() {
        hal.regs.insert(reg + i as u16, *b);
    }
}
fn commands(hal: &FakeHal, id: u8) -> Vec<Vec<u8>> {
    hal.h2c
        .iter()
        .filter(|(i, _)| *i == id)
        .map(|(_, b)| b.clone())
        .collect()
}
fn high(b: &mut BtCoexist, a: &mut B8821a2Ant) {
    b.wifi.station_linked = true;
    b.wifi.busy = true;
    b.wifi.undec_sm_pwdb = 80;
    a.sta.bt_rssi = 60;
}

fn smoke_8821a2ant_native_init_preload_and_media_literals() -> TestResult {
    let mut b = board();
    let mut h = FakeHal::default();
    let mut a = B8821a2Ant::new();
    seed(&mut h, 0x4c, 0x00800011);
    h.regs.insert(0x790, 0xe0);
    if run(Ctx::new(&mut b, &mut h).init_hw_config(&mut a)).is_err()
        || !b.initialized
        || b.auto_report_2ant
        || h.last(0x4c) != Some(0x01000011)
        || h.last(0x974) != Some(0x3ff)
        || h.last(0x790) != Some(0xc5)
        || h.last(0xcb7) != Some(0x10)
        || h.last(0x6c8) != Some(0xffffff)
        || h.last(0x76e) != Some(4)
        || h.last(0x778) != Some(3)
        || h.get(0x40, 1) & 0x20 == 0
        || !h.h2c.contains(&(0x65, vec![1, 1]))
        || h.h2c.iter().any(|(id, _)| matches!(*id, 0x68 | 0x61))
    {
        return TestResult::Fail("8821A2Ant init borrowed antenna/report or RF program");
    }
    if run(a.pre_load_firmware(&mut Ctx::new(&mut b, &mut h))).is_err() || h.last(0x384) != Some(4)
    {
        return TestResult::Fail("8821A2Ant PCI preload");
    }
    b.board_info.single_ant_path = 1;
    if run(a.pre_load_firmware(&mut Ctx::new(&mut b, &mut h))).is_err() || h.last(0x384) != Some(5)
    {
        return TestResult::Fail("8821A2Ant inverse preload");
    }
    b.wifi.current_channel = 6;
    b.wifi.ap_num = 99;
    if run(a.media_status_notify(&mut Ctx::new(&mut b, &mut h), Media::Connect)).is_err()
        || h.h2c.last() != Some(&(0x66, vec![1, 6, 0x30]))
    {
        return TestResult::Fail("8821A2Ant source unqueried AP count was replaced");
    }
    b.wifi.current_channel = 36;
    if run(a.media_status_notify(&mut Ctx::new(&mut b, &mut h), Media::Connect)).is_err()
        || h.h2c.last() != Some(&(0x66, vec![0, 0, 0]))
    {
        return TestResult::Fail("8821A2Ant 5GHz channel report");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_8821a2ant_native_init_preload_and_media_literals
);

fn smoke_8821a2ant_literal_tdma_rssi_cache_and_no_modifiers() -> TestResult {
    let mut b = board();
    let mut h = FakeHal::default();
    let mut a = B8821a2Ant::new();
    high(&mut b, &mut a);
    // The switch's distinct literal rows, including the 8821A-only23..26/123..126.
    for (k, e) in [
        (1, [0xe3, 0x3c, 3, 0xf1, 0x90]),
        (2, [0xe3, 0x2d, 3, 0xf1, 0x90]),
        (3, [0xe3, 0x1c, 3, 0xf1, 0x90]),
        (4, [0xe3, 0x10, 3, 0xf1, 0x90]),
        (5, [0xe3, 0x3c, 3, 0x70, 0x90]),
        (6, [0xe3, 0x2d, 3, 0x70, 0x90]),
        (7, [0xe3, 0x1c, 3, 0x70, 0x90]),
        (8, [0xa3, 0x10, 3, 0x70, 0x90]),
        (16, [0xe3, 0x10, 3, 0x70, 0x90]),
        (17, [0xa3, 0x2f, 0x2f, 0x60, 0x90]),
        (18, [0xe3, 5, 5, 0xe1, 0x90]),
        (19, [0xe3, 0x25, 0x25, 0xe1, 0x90]),
        (20, [0xe3, 0x25, 0x25, 0x60, 0x90]),
        (21, [0xe3, 0x15, 3, 0x70, 0x90]),
        (22, [0xe3, 0x35, 3, 0x71, 0x11]),
        (23, [0xe3, 0x1e, 3, 0xf0, 0x14]),
        (24, [0xd3, 0x3c, 3, 0x70, 0x50]),
        (25, [0xe3, 0x14, 3, 0xf1, 0x90]),
        (26, [0xe3, 0x30, 3, 0xf1, 0x90]),
        (101, [0xd3, 0x3a, 3, 0x70, 0x50]),
        (102, [0xd3, 0x2d, 3, 0x70, 0x50]),
        (103, [0xd3, 0x1c, 3, 0x70, 0x50]),
        (104, [0xd3, 0x10, 3, 0x70, 0x50]),
        (113, [0xe3, 0x3c, 3, 0x70, 0x90]),
        (123, [0xd3, 0x1c, 3, 0x70, 0x54]),
        (125, [0xd3, 0x14, 3, 0x70, 0x50]),
        (126, [0xd3, 0x30, 3, 0x70, 0x50]),
    ] {
        if run(a.ps_tdma(&mut Ctx::new(&mut b, &mut h), true, true, k)).is_err()
            || h.h2c.last() != Some(&(0x60, e.to_vec()))
        {
            return TestResult::Fail("8821A2Ant literal TDMA row");
        }
    }
    b.wifi.undec_sm_pwdb = 20;
    b.wifi.ap_num = 80;
    b.wifi.ap_mode = true;
    b.bt_link_info.slave_role = true;
    if run(a.ps_tdma(&mut Ctx::new(&mut b, &mut h), true, true, 23)).is_err()
        || a.dm.cur_ps_tdma != 123
        || h.h2c.last() != Some(&(0x60, vec![0xd3, 0x1c, 3, 0x70, 0x54]))
    {
        return TestResult::Fail("8821A2Ant RSSI translation or borrowed TDMA modifier");
    }
    let n = h.h2c.len();
    if run(a.ps_tdma(&mut Ctx::new(&mut b, &mut h), false, true, 23)).is_err() || h.h2c.len() != n {
        return TestResult::Fail("8821A2Ant translated TDMA cache");
    }
    if run(a.ps_tdma(&mut Ctx::new(&mut b, &mut h), false, false, 1)).is_err()
        || h.h2c.last() != Some(&(0x60, vec![0, 0, 0, 0x48, 0]))
        || a.dm.cur_ps_tdma != 1
    {
        return TestResult::Fail("8821A2Ant off type incorrectly translated");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_8821a2ant_literal_tdma_rssi_cache_and_no_modifiers
);

fn smoke_8821a2ant_profile_matrix_preserves_sco_hid_pan_differences() -> TestResult {
    // (algorithm, high-RSSI table/type, low-RSSI table/type).
    for (kind, th, dh, tl, dl) in [
        (CoexAlgo::Sco, 17, 0, 17, 0),
        (CoexAlgo::Hid, 2, 24, 2, 124),
        (CoexAlgo::A2dp, 7, 23, 13, 123),
        (CoexAlgo::A2dpPanHs, 7, 6, 13, 106),
        (CoexAlgo::PanEdr, 10, 26, 13, 126),
        (CoexAlgo::PanHs, 7, 1, 7, 1),
        (CoexAlgo::PanEdrA2dp, 12, 3, 13, 107),
        (CoexAlgo::HidA2dpPanEdr, 7, 11, 14, 115),
        (CoexAlgo::HidA2dp, 14, 23, 14, 123),
    ] {
        for low in [false, true] {
            let mut b = board();
            let mut h = FakeHal::default();
            let mut a = B8821a2Ant::new();
            high(&mut b, &mut a);
            b.bt_link_info.sco_only = true;
            a.dm.auto_tdma_adjust = true;
            if low {
                b.wifi.undec_sm_pwdb = 20;
                a.sta.bt_rssi = 20;
                a.sta.pre_bt_rssi_state = RssiState::Low;
            }
            let mut cx = Ctx::new(&mut b, &mut h);
            let result = match kind {
                CoexAlgo::Sco => run(a.action_sco(&mut cx)),
                CoexAlgo::Hid => run(a.action_hid(&mut cx)),
                CoexAlgo::A2dp => run(a.action_a2dp(&mut cx)),
                CoexAlgo::A2dpPanHs => run(a.action_a2dp_pan_hs(&mut cx)),
                CoexAlgo::PanEdr => run(a.action_pan_edr(&mut cx)),
                CoexAlgo::PanHs => run(a.action_pan_hs(&mut cx)),
                CoexAlgo::PanEdrA2dp => run(a.action_pan_edr_a2dp(&mut cx)),
                CoexAlgo::HidA2dpPanEdr => run(a.action_hid_a2dp_pan_edr(&mut cx)),
                _ => run(a.action_hid_a2dp(&mut cx)),
            };
            if result.is_err()
                || a.sta.coex_table_type != if low { tl } else { th }
                || a.dm.cur_ps_tdma != if low { dl } else { dh }
                || h.rf.iter().any(|(path, _, _, _)| *path != BTC_RF_A)
                || a.dm.pre_low_penalty_ra
                    != matches!(
                        kind,
                        CoexAlgo::Sco | CoexAlgo::Hid | CoexAlgo::HidA2dpPanEdr | CoexAlgo::HidA2dp
                    )
                || a.dm.pre_dac_swing_on != (kind == CoexAlgo::Sco)
                || (a.dm.pre_low_penalty_ra
                    && !h.h2c.contains(&(0x69, vec![6, 1, 0, 0xf5, 0xa0, 0xa0])))
            {
                return TestResult::Fail("8821A2Ant native profile table/type/SW/RF matrix");
            }
        }
    }
    // PAN+HID directly programs the shorter table without RF, limited RX or LPS.
    let mut b = board();
    let mut h = FakeHal::default();
    let mut a = B8821a2Ant::new();
    high(&mut b, &mut a);
    a.sta.coex_table_type = 16;
    b.bt_info.bt_ctrl_lps = true;
    b.bt_info.bt_lps_on = true;
    b.wifi.chan_bw = ChanBw::Ht20_40;
    if run(a.action_pan_edr_hid(&mut Ctx::new(&mut b, &mut h))).is_err()
        || a.sta.coex_table_type != 16
        || h.last(0x6c8) != Some(0xffff)
        || h.last(0x6c0) != Some(0x55ff55ff)
        || h.last(0x6c4) != Some(0x5a5f5a5f)
        || !h.rf.is_empty()
        || !h.lps.is_empty()
        || !h.ampdu.is_empty()
        || !b.bt_info.bt_lps_on
        || a.dm.cur_fw_dac_swing_lvl != 3
        || a.dm.cur_ps_tdma != 10
    {
        return TestResult::Fail("8821A2Ant PAN+HID borrowed a different profile's RF/LPS/table");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_8821a2ant_profile_matrix_preserves_sco_hid_pan_differences
);

fn smoke_8821a2ant_complete_algorithm_profile_and_hs_matrix() -> TestResult {
    use CoexAlgo::*;
    let nohs = [
        Undefined,
        Sco,
        Hid,
        Sco,
        PanEdr,
        Sco,
        PanEdrHid,
        Sco,
        A2dp,
        Sco,
        HidA2dp,
        Sco,
        PanEdrA2dp,
        Sco,
        HidA2dpPanEdr,
        Sco,
    ];
    let hs = [
        Undefined, Sco, Hid, Sco, PanHs, Sco, Hid, Sco, A2dp, Sco, HidA2dp, Sco, A2dpPanHs, Sco,
        HidA2dp, Undefined,
    ];
    for mask in 0..16 {
        let mut l = BtLinkInfo {
            bt_link_exist: true,
            sco_exist: mask & 1 != 0,
            hid_exist: mask & 2 != 0,
            pan_exist: mask & 4 != 0,
            a2dp_exist: mask & 8 != 0,
            ..BtLinkInfo::default()
        };
        if action_algorithm(&l, false) != nohs[mask] || action_algorithm(&l, true) != hs[mask] {
            return TestResult::Fail("8821A2Ant exact SCO/profile/HS algorithm selection");
        }
        l.bt_link_exist = false;
        if action_algorithm(&l, false) != Undefined {
            return TestResult::Fail("8821A2Ant disconnected profiles selected");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_8821a2ant_complete_algorithm_profile_and_hs_matrix
);

fn smoke_8821a2ant_bool_power_and_partial_cache_commit() -> TestResult {
    let mut b = board();
    let mut h = FakeHal::default();
    let mut a = B8821a2Ant::new();
    high(&mut b, &mut a);
    if run(a.dec_bt_pwr(&mut Ctx::new(&mut b, &mut h), false, 4)).is_err()
        || h.h2c.last() != Some(&(0x62, vec![1]))
    {
        return TestResult::Fail("8821A2Ant bool power conversion");
    }
    let n = h.h2c.len();
    if run(a.dec_bt_pwr(&mut Ctx::new(&mut b, &mut h), false, 2)).is_err() || h.h2c.len() != n {
        return TestResult::Fail("8821A2Ant bool cache differed for source2/4");
    }
    h.deny_h2c = Some(0x62);
    if run(a.dec_bt_pwr(&mut Ctx::new(&mut b, &mut h), false, 0)).is_ok()
        || !a.dm.pre_dec_bt_pwr_lvl
        || a.dm.cur_dec_bt_pwr_lvl
    {
        return TestResult::Fail("8821A2Ant denied BT power committed cached state");
    }
    h.deny_h2c = Some(0x60);
    if run(a.ps_tdma(&mut Ctx::new(&mut b, &mut h), false, true, 23)).is_ok()
        || a.dm.pre_ps_tdma_on
        || a.dm.pre_ps_tdma != 0
        || a.dm.cur_ps_tdma != 23
    {
        return TestResult::Fail("8821A2Ant denied TDMA committed cached state");
    }
    h.deny_h2c = None;
    h.deny_write = Some(0x6c8);
    if a.coex_table_with_type(&mut Ctx::new(&mut b, &mut h), false, 16)
        .is_ok()
        || h.last(0x6c0) != Some(0x5fdf5fdf)
        || h.last(0x6c4) != Some(0x5fdb5fdb)
        || a.dm.pre_val0x6c0 != 0
        || a.dm.cur_val0x6c0 != 0x5fdf5fdf
        || h.last(0x6cc).is_some()
    {
        return TestResult::Fail("8821A2Ant partial table published cache or later write");
    }
    h.deny_write = Some(0xc5b);
    h.regs.insert(0xc5b, 0xc1);
    if run(a.dac_swing(&mut Ctx::new(&mut b, &mut h), false, true, 0x106)).is_ok()
        || a.dm.pre_dac_swing_on
        || a.dm.pre_dac_swing_lvl != 0
        || h.delays != 1
    {
        return TestResult::Fail("8821A2Ant denied DAC committed cached state");
    }
    h.deny_write = None;
    if run(a.dac_swing(&mut Ctx::new(&mut b, &mut h), false, true, 0x106)).is_err()
        || h.last(0xc5b) != Some(0xcd)
        || h.writes.last().map(|w| w.2) != Some(1)
        || a.dm.pre_dac_swing_lvl != 0x106
    {
        return TestResult::Fail("8821A2Ant DAC byte cast/mask or retry");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_8821a2ant_bool_power_and_partial_cache_commit
);

fn smoke_8821a2ant_bt_reports_bound_rows_mask_repair_and_inferred_hid() -> TestResult {
    let mut b = board();
    let mut h = FakeHal::default();
    let mut a = B8821a2Ant::new();
    b.manual_control = true;
    a.sta.c2h_bt_info_req_sent = true;
    if run(a.bt_info_notify(&mut Ctx::new(&mut b, &mut h), &[0xff; 20])).is_err()
        || a.sta.bt_info_c2h[0] != [0xff; 10]
        || a.sta.bt_info_c2h_cnt[0] != 1
        || a.sta.c2h_bt_info_req_sent
        || a.sta.bt_link_exist
        || !h.h2c.is_empty()
    {
        return TestResult::Fail("8821A2Ant manual report storage/source/bounds");
    }
    b.manual_control = false;
    b.wifi.station_linked = true;
    b.wifi.current_channel = 11;
    a.sta.under_ips = true;
    a.sta.high_priority_tx = 100;
    a.sta.high_priority_rx = 60;
    h.mp.push(MpReport::new(&[1, 0, 0, 0]));
    h.mp.push(MpReport::new(&[1, 0, 0, 0]));
    if run(a.bt_info_notify(&mut Ctx::new(&mut b, &mut h), &[1, 1, 0x43, 25, 10])).is_err()
        || !a.sta.bt_tx_rx_mask
        || !b.bt_info.bt_tx_rx_mask
        || a.sta.bt_retry_cnt != 3
        || a.sta.bt_rssi != 60
        || !a.sta.hid_exist
        || !b.bt_link_info.hid_only
        || a.dm.bt_status != BtStatus::ConIdle
        || b.bt_info.bt_busy
        || a.dm.limited_dig
        || !h
            .h2c
            .contains(&(0x67, vec![0, BT_OP_WRITE_REG_VALUE, 1, 0]))
        || !h
            .h2c
            .contains(&(0x67, vec![0, BT_OP_WRITE_REG_ADDR, 0, 0x3c]))
        || !h.h2c.contains(&(0x66, vec![1, 11, 0x30]))
        || !h.h2c.contains(&(0x63, vec![0]))
        || h.h2c.iter().any(|(id, _)| *id == 0x68)
    {
        return TestResult::Fail("8821A2Ant mask repair/channel reset/HID/status source semantics");
    }
    // Local bt_info becomes0 although source row2..4 remain from the prior report.
    if run(a.bt_info_notify(&mut Ctx::new(&mut b, &mut h), &[1])).is_err()
        || a.sta.bt_info_c2h[1][1..5] != [1, 0x43, 25, 10]
        || a.sta.bt_rssi != 60
        || a.sta.bt_link_exist
        || a.dm.bt_status != BtStatus::Idle
    {
        return TestResult::Fail("8821A2Ant short C2H row tails or local info semantics");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_8821a2ant_bt_reports_bound_rows_mask_repair_and_inferred_hid
);

fn smoke_8821a2ant_periodical_report_polarity_and_counter_history() -> TestResult {
    let mut b = board();
    let mut h = FakeHal::default();
    let mut a = B8821a2Ant::new();
    b.auto_report_2ant = true;
    seed(&mut h, 0x770, 0x00020001);
    for _ in 0..8 {
        if run(a.periodical(&mut Ctx::new(&mut b, &mut h))).is_err() {
            return TestResult::Fail("8821A2Ant periodical query");
        }
    }
    if commands(&h, 0x61) != vec![vec![1]; 8]
        || a.sta.dis_ver_info_cnt != 6
        || a.sta.high_priority_tx != 0
        || h.last(0x76e).is_some()
        || h.writes.iter().filter(|(r, _, _)| *r == 0xcb7).count() != 1
        || h.last(0xcb7) != Some(0x10)
    {
        return TestResult::Fail("8821A2Ant auto-report polarity/third-period antenna");
    }
    b.auto_report_2ant = false;
    a.sta.under_ips = true;
    seed(&mut h, 0x774, (951 << 16) | 17);
    if run(a.periodical(&mut Ctx::new(&mut b, &mut h))).is_err()
        || a.sta.high_priority_tx != 1
        || a.sta.high_priority_rx != 2
        || a.sta.low_priority_tx != 17
        || a.sta.low_priority_rx != 951
        || b.bt_link_info.slave_role
        || h.last(0x76e) != Some(12)
        || commands(&h, 0x61).len() != 8
        || h.last(0xf16) != Some(0)
    {
        return TestResult::Fail("8821A2Ant non-auto counter/IPS source behavior");
    }
    a.sta.under_ips = false;
    a.monitor_bt_ctr(&mut Ctx::new(&mut b, &mut h)).unwrap();
    if !b.bt_link_info.slave_role {
        return TestResult::Fail("8821A2Ant native slave-role counters");
    }
    // Default source statics are true, and the RSSI observer is slot3.
    b.wifi.station_linked = true;
    b.wifi.busy = true;
    b.wifi.in_4way = true;
    a.st.pre_bt_hs_on = false;
    b.wifi.undec_sm_pwdb = 20;
    if !a.is_wifi_status_changed(&mut Ctx::new(&mut b, &mut h))
        || a.sta.pre_wifi_rssi_state[3] != RssiState::Low
        || a.sta.pre_wifi_rssi_state[0] != RssiState::High
    {
        return TestResult::Fail("8821A2Ant status observer RSSI identity");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_8821a2ant_periodical_report_polarity_and_counter_history
);

fn smoke_8821a2ant_adaptive_flag_retry_and_instance_history() -> TestResult {
    let mut b = board();
    let mut h = FakeHal::default();
    let mut a = B8821a2Ant::new();
    high(&mut b, &mut a);
    a.dm.auto_tdma_adjust = true;
    if run(a.tdma_duration_adjust(&mut Ctx::new(&mut b, &mut h), false, false, 1)).is_err()
        || a.dm.auto_tdma_adjust
        || a.dm.ps_tdma_du_adj_type != 1
        || a.st.m != 1
        || a.st.n != 3
        || a.st.wait_count != 0
    {
        return TestResult::Fail("8821A2Ant reversed first-adjust flag");
    }
    a.sta.low_priority_tx = 5000;
    a.sta.low_priority_rx = 5000;
    for _ in 0..3 {
        if run(a.tdma_duration_adjust(&mut Ctx::new(&mut b, &mut h), false, false, 1)).is_err() {
            return TestResult::Fail("8821A2Ant zero retry adjust");
        }
    }
    if a.dm.cur_ps_tdma != 71 || a.dm.ps_tdma_du_adj_type != 71 || a.st.dn != 0 || a.st.n != 3 {
        return TestResult::Fail("8821A2Ant borrowed counter-based retry increment");
    }
    a.sta.bt_retry_cnt = 2;
    for _ in 0..2 {
        if run(a.tdma_duration_adjust(&mut Ctx::new(&mut b, &mut h), false, false, 1)).is_err() {
            return TestResult::Fail("8821A2Ant retry adjust");
        }
    }
    if a.dm.cur_ps_tdma != 1 || a.st.m != 2 || a.st.n != 6 {
        return TestResult::Fail("8821A2Ant literal71-to1 down transition");
    }
    let other = B8821a2Ant::new();
    if other.st.up != 0
        || other.st.m != 0
        || !other.st.pre_wifi_busy
        || !other.st.pre_under_4way
        || !other.st.pre_bt_hs_on
    {
        return TestResult::Fail("8821A2Ant history leaked across owners");
    }
    // Common idle primes the inverted flag; an algorithm change clears it.
    b.wifi.station_linked = false;
    if run(a.run_coexist_mechanism(&mut Ctx::new(&mut b, &mut h))).is_err()
        || !a.dm.auto_tdma_adjust
    {
        return TestResult::Fail("8821A2Ant common idle did not prime source adjustment");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_8821a2ant_adaptive_flag_retry_and_instance_history
);

fn smoke_8821a2ant_5g_before_ips_manual_and_source_noop_notifications() -> TestResult {
    let mut b = board();
    let mut h = FakeHal::default();
    let mut a = B8821a2Ant::new();
    b.wifi.under_5g = true;
    a.sta.under_ips = true;
    b.manual_control = true;
    if run(a.run_coexist_mechanism(&mut Ctx::new(&mut b, &mut h))).is_err()
        || !h.writes.is_empty()
        || !h.h2c.is_empty()
    {
        return TestResult::Fail("8821A2Ant manual program emitted");
    }
    b.manual_control = false;
    if run(a.run_coexist_mechanism(&mut Ctx::new(&mut b, &mut h))).is_err()
        || h.last(0x6c0) != Some(0x55555555)
        || !h.h2c.contains(&(0x63, vec![1]))
        || !h.rf.is_empty()
    {
        return TestResult::Fail("8821A2Ant 5GHz priority or source all-off RF effect");
    }
    let state = a.clone();
    let writes = h.writes.len();
    let cmds = h.h2c.len();
    let rf = h.rf.len();
    if run(a.power_on_setting(&mut Ctx::new(&mut b, &mut h))).is_err()
        || run(a.scan_notify(&mut Ctx::new(&mut b, &mut h), Scan::Start)).is_err()
        || run(a.connect_notify(&mut Ctx::new(&mut b, &mut h), Associate::Start)).is_err()
        || run(a.special_packet_notify(&mut Ctx::new(&mut b, &mut h), Packet::Dhcp)).is_err()
        || run(a.pnp_notify(&mut Ctx::new(&mut b, &mut h), Pnp::Sleep)).is_err()
        || a.dm != state.dm
        || a.sta != state.sta
        || a.st != state.st
        || h.writes.len() != writes
        || h.h2c.len() != cmds
        || h.rf.len() != rf
    {
        return TestResult::Fail("8821A2Ant source log-only notify changed state/hardware");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_8821a2ant_5g_before_ips_manual_and_source_noop_notifications
);

fn smoke_8821a2ant_ips_wake_and_firmware_specific_grant_bt() -> TestResult {
    for (version, h2c) in [(0x17, false), (0x18, true)] {
        let mut b = board();
        let mut h = FakeHal::default();
        let mut a = B8821a2Ant::new();
        b.wifi.fw_version = version;
        h.regs.insert(0x67, 0xff);
        if run(a.ips_notify(&mut Ctx::new(&mut b, &mut h), Ips::Enter)).is_err()
            || !a.sta.under_ips
            || h.rf != vec![(BTC_RF_A, 1, 0xfffff, 0x780)]
            || h.last(0x67).is_some()
            || h.h2c.contains(&(0x6e, vec![1])) != h2c
            || (!h2c && h.last(0x765) != Some(0x18))
        {
            return TestResult::Fail("8821A2Ant firmware-specific GNT_BT / source RF sleep");
        }
        if run(a.ips_notify(&mut Ctx::new(&mut b, &mut h), Ips::Leave)).is_err()
            || a.sta.under_ips
            || h.h2c.last() != Some(&(0x61, vec![1]))
            || b.auto_report_2ant
        {
            return TestResult::Fail("8821A2Ant actual wake init/query ordering");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_8821a2ant_ips_wake_and_firmware_specific_grant_bt
);

fn smoke_8821a2ant_rssi_hysteresis_sco_width_and_idle_dac_order() -> TestResult {
    for (pre, value, want) in [
        (RssiState::Low, 43, RssiState::StayLow),
        (RssiState::Low, 44, RssiState::High),
        (RssiState::High, 42, RssiState::StayHigh),
        (RssiState::High, 41, RssiState::Low),
    ] {
        if rssi_state(pre, value, 2, 42, 0) != want || rssi_state(pre, value, 3, 46, 37) != pre {
            return TestResult::Fail("8821A2Ant RSSI tolerance/reversed source thresholds");
        }
    }
    for (mode, bw, only, table) in [
        (WifiMode::G, ChanBw::Ht20, true, 2),
        (WifiMode::N, ChanBw::Ht20_40, true, 8),
        (WifiMode::N, ChanBw::Ht20, false, 12),
    ] {
        let mut b = board();
        let mut h = FakeHal::default();
        let mut a = B8821a2Ant::new();
        high(&mut b, &mut a);
        b.wifi.mode = mode;
        b.wifi.chan_bw = bw;
        b.bt_link_info.sco_only = only;
        if run(a.action_sco(&mut Ctx::new(&mut b, &mut h))).is_err()
            || a.sta.coex_table_type != table
        {
            return TestResult::Fail("8821A2Ant SCO exact legacy/HT40/non-only table");
        }
    }
    let mut b = board();
    let mut h = FakeHal::default();
    let mut a = B8821a2Ant::new();
    high(&mut b, &mut a);
    a.sta.pan_exist = true;
    if run(a.action_wifi_idle_process(&mut Ctx::new(&mut b, &mut h))) != Ok(true)
        || h.writes
            .iter()
            .filter(|(r, _, _)| *r == 0xc5b)
            .map(|(_, v, _)| *v)
            .collect::<Vec<_>>()
            != vec![12, 48]
        || a.dm.pre_dac_swing_on
        || a.dm.pre_dac_swing_lvl != 0x18
    {
        return TestResult::Fail("8821A2Ant idle source DAC-on6 then DAC-off18 order");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/btcoex",
    smoke_8821a2ant_rssi_hysteresis_sco_width_and_idle_dac_order
);
