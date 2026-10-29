use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use core::task::{Context, Poll, Waker};
use narf_kernel_test::{kernel_test_in, TestResult};

/// The fake completes every await immediately.
fn ready<T>(future: impl core::future::Future<Output = T>) -> T {
    let mut future = core::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("track fake future pending"),
    }
}

/// Register file that refuses anything outside `REGISTERS`.
#[derive(Default)]
struct Fake {
    regs: BTreeMap<u32, u32>,
    unsupported: bool,
    cck_pd: bool,
    profile: Option<Profile>,
    crystal: Vec<u8>,
}
impl Hw for Fake {
    fn read(&mut self, address: u32) -> Result<u32, power::Error> {
        if self.unsupported {
            return Err(power::Error::Unsupported);
        }
        if !REGISTERS.contains(&address) {
            return Err(power::Error::Access);
        }
        Ok(*self.regs.get(&address).unwrap_or(&0))
    }
    fn write(&mut self, address: u32, value: u32) -> Result<(), power::Error> {
        if !REGISTERS.contains(&address) {
            return Err(power::Error::Access);
        }
        self.regs.insert(address, value);
        Ok(())
    }
    fn profile(&mut self) -> Result<Profile, power::Error> {
        if self.unsupported {
            return Err(power::Error::Unsupported);
        }
        Ok(self.profile.unwrap_or(Profile {
            cck_pd: self.cck_pd,
            crystal_cap: 40,
            crystal_lower: 1,
            crystal_upper: 104,
        }))
    }
    async fn crystal(&mut self, cap: u8) -> Result<u8, power::Error> {
        self.crystal.push(cap);
        Ok(cap)
    }
}
impl Fake {
    fn get(&self, address: u32, mask: u32) -> u32 {
        field(*self.regs.get(&address).unwrap_or(&0), mask)
    }
}

fn smoke_rtw89_track_edcca_threshold_matches_linux() -> TestResult {
    // rtw89_phy_edcca_get_thre_by_rssi: unlinked is EDCCA_MAX; linked is
    // rssi_min/2 - 110 + 128 - 3, floored at EDCCA_TH_L2H_LB.
    for (rssi, expected) in [
        (None, 249),
        (Some(0), 66),
        (Some(100), 66),
        (Some(102), 66),
        (Some(104), 67),
        (Some(140), 85),
        (Some(255), 142),
    ] {
        if edcca_threshold(rssi) != expected {
            return TestResult::Fail(
                "EDCCA threshold differs from rtw89_phy_edcca_get_thre_by_rssi",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_track_edcca_threshold_matches_linux
);

fn smoke_rtw89_track_rssi_ewma_matches_linux() -> TestResult {
    // DECLARE_EWMA(rssi, 10, 16): the first sample seeds, then 15/16 decay.
    let mut rssi = Rssi::default();
    rssi.add(160);
    if rssi.read() != 160 {
        return TestResult::Fail("first EWMA sample does not seed the average");
    }
    rssi.add(0);
    // ((160<<10)*15 + 0) >> 4 = 153600 -> 150
    if rssi.read() != 150 {
        return TestResult::Fail("EWMA weight differs from ewma_rssi_add");
    }
    for _ in 0..200 {
        rssi.add(80);
    }
    if !(80..=81).contains(&rssi.read()) {
        return TestResult::Fail("EWMA does not converge to a steady sample");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_track_rssi_ewma_matches_linux
);

fn smoke_rtw89_track_ifs_clm_arithmetic_matches_linux() -> TestResult {
    // rtw89_phy_ccx_ms_to_period_unit(1900): quotient 28 -> 32 us unit.
    if ccx_period_unit(1900) != (59375, 3) || ccx_period_unit(100) != (25000, 0) {
        return TestResult::Fail("CCX period/unit differs from rtw89_phy_ccx_ms_to_period_unit");
    }
    // rtw89_phy_ifs_clm_th_update_check at the 32 us unit: 64/256/1024/4096 us.
    if ifs_thresholds(3) != [(0, 2), (3, 8), (9, 32), (33, 128)] {
        return TestResult::Fail("IFS-CLM thresholds differ from Linux");
    }
    // rtw89_phy_ccx_get_report: rounded ratio, saturated below score.
    if ccx_report(2969, 1000, 59375) != 50
        || ccx_report(70000, 1000, 59375) != 999
        || ccx_report(5, 1000, 0) != 0
    {
        return TestResult::Fail("CCX report ratio differs from rtw89_phy_ccx_get_report");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_track_ifs_clm_arithmetic_matches_linux
);

fn smoke_rtw89_track_dig_pd_threshold_matches_linux() -> TestResult {
    let mut dig = Dig::default();
    // Unlinked: igi_rssi 22, igi_fa_rssi clamps up to 12; PD 0; CCK -11-110.
    let expected = DigOutput {
        pd: 0,
        cck_pd: (-121i32) as u32,
        sdagc_follow_pagc: false,
    };
    if dig.step(None, 0) != expected {
        return TestResult::Fail("unlinked DIG differs from Linux");
    }
    // First connected at rssi 160: igi_rssi 80 seeds igi_fa_rssi.
    let quiet = DigOutput {
        pd: 24,
        cck_pd: (-53i32) as u32,
        sdagc_follow_pagc: false,
    };
    if dig.step(Some(160), 0) != quiet {
        return TestResult::Fail("first-connected DIG differs from Linux");
    }
    // Noisy (FA >= 88 permil): +6 per period up to dyn_igi_max 90; the PD
    // bound stays at igi_rssi, SDAGC follows PAGC above it.
    let noisy = DigOutput {
        sdagc_follow_pagc: true,
        ..quiet
    };
    if dig.step(Some(160), 100) != noisy || dig.igi_fa_rssi != 86 {
        return TestResult::Fail("noisy DIG offset differs from Linux");
    }
    if dig.step(Some(160), 100) != noisy || dig.igi_fa_rssi != 90 || dig.fa_rssi_ofst != 12 {
        return TestResult::Fail("DIG does not clamp at dyn_igi_max");
    }
    // Quiet again: level0 backs the offset off by 2.
    dig.step(Some(160), 0);
    if dig.fa_rssi_ofst != 10 {
        return TestResult::Fail("quiet DIG offset does not decay");
    }
    // Disconnect: no-link thresholds, igi_rssi 22 reseeds, the decayed
    // offset 8 lifts igi_fa_rssi to 30: CCK 22-23-110, SDAGC follows.
    let disconnected = DigOutput {
        pd: 0,
        cck_pd: (-111i32) as u32,
        sdagc_follow_pagc: true,
    };
    if dig.step(None, 0) != disconnected || dig.fa_th != FA_TH_NOLINK {
        return TestResult::Fail("first-disconnected DIG differs from Linux");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_track_dig_pd_threshold_matches_linux
);

fn smoke_rtw89_track_work_programs_registers_like_linux() -> TestResult {
    let peer = Some([2, 0, 0, 0, 0, 1]);
    let mut hw = Fake {
        cck_pd: true,
        ..Fake::default()
    };
    let mut track = Tracker::default();
    if ready(track.run(&mut hw, 0, None, false)).is_err() {
        return TestResult::Fail("first track period failed");
    }
    // rtw89_core_start half: PPDU status to host, CCX and IFS-CLM init.
    if hw.get(R_AX_PPDU_STAT, u32::MAX) != 0x2b
        || hw.get(R_AX_HW_RPT_FWD, B_AX_FWD_PPDU_STAT_MASK) != 1
        || hw.get(R_CCX, 0x77) != 0x7
        || hw.get(R_IFS_COUNTER, B_IFS_COLLECT_EN) != 1
        || hw.get(R_IFS_COUNTER, B_IFS_CLM_PERIOD_MSK) != 59375
        || hw.get(R_IFS_COUNTER, B_IFS_CLM_COUNTER_UNIT_MSK) != 3
        || hw.get(R_IFS_COUNTER, B_IFS_COUNTER_CLR_MSK) != 1
    {
        return TestResult::Fail("PPDU status / environment monitor init differs");
    }
    for (address, (low, high)) in R_IFS_T.into_iter().zip(ifs_thresholds(3)) {
        if hw.get(address, B_IFS_TH_LOW_MSK) != u32::from(low)
            || hw.get(address, B_IFS_TH_HIGH_MSK) != u32::from(high)
            || hw.get(address, B_IFS_EN_MSK) != 1
        {
            return TestResult::Fail("IFS-CLM threshold registers differ");
        }
    }
    if hw.get(R_SEG0R_PD_V1, B_SEG0R_PD_LOWER_BOUND_MSK) != 0
        || hw.get(R_SEG0R_PD_V1, B_SEG0R_PD_SPATIAL_REUSE_EN_MSK_V1) != 1
        || hw.get(R_BMODE_PDTH_V1, B_BMODE_PDTH_LOWER_BOUND_MSK_V1) != 0x87
        || hw.get(R_BMODE_PDTH_EN_V1, B_BMODE_PDTH_LIMIT_EN_MSK_V1) != 1
        || hw.get(R_SEG0R_EDCCA_LVL_V1, u32::MAX) != 0xf900_f9f9
    {
        return TestResult::Fail("unlinked DIG/EDCCA registers differ");
    }
    // Not due yet; scanning skips; then a linked, noisy period.
    hw.regs.insert(R_SEG0R_EDCCA_LVL_V1, 0);
    if ready(track.run(&mut hw, 1999, peer, false)).is_err()
        || hw.get(R_SEG0R_EDCCA_LVL_V1, 0xff) != 0
    {
        return TestResult::Fail("track work ran before its period");
    }
    track.sample(peer, 160);
    if ready(track.run(&mut hw, 2000, peer, true)).is_err()
        || hw.get(R_SEG0R_EDCCA_LVL_V1, 0xff) != 0
    {
        return TestResult::Fail("track work ran while scanning");
    }
    hw.regs.insert(R_IFSCNT, B_IFSCNT_DONE_MSK);
    hw.regs.insert(R_IFS_CLM_FA, (2969 << 16) | 2969);
    if ready(track.run(&mut hw, 2000, peer, false)).is_err() {
        return TestResult::Fail("linked track period failed");
    }
    if hw.get(R_SEG0R_PD_V1, B_SEG0R_PD_LOWER_BOUND_MSK) != 24
        || R_PAGCUGC.iter().any(|&r| hw.get(r, B_PAGCUGC_EN_MSK) != 1)
        || hw.get(R_SEG0R_EDCCA_LVL_V1, 0xff) != 95
    {
        return TestResult::Fail("linked noisy DIG/EDCCA registers differ");
    }
    // A new peer restarts the RSSI average.
    track.sample(Some([2, 0, 0, 0, 0, 2]), 100);
    if track.rssi() != 100 {
        return TestResult::Fail("new peer kept the previous RSSI average");
    }
    // An owner without the hook reports Unsupported (station disables).
    let mut none = Fake {
        unsupported: true,
        ..Fake::default()
    };
    if ready(Tracker::default().run(&mut none, 0, None, false)) != Err(power::Error::Unsupported) {
        return TestResult::Fail("missing owner hook not reported as Unsupported");
    }
    track.disable();
    hw.regs.clear();
    if ready(track.run(&mut hw, 100_000, None, false)).is_err() || !hw.regs.is_empty() {
        return TestResult::Fail("disabled tracking still programs hardware");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_track_work_programs_registers_like_linux
);

fn smoke_rtw89_track_cfo_crystal_and_dcfo_match_linux() -> TestResult {
    let mut hw = Fake::default();
    let mut cfo = Cfo::default();
    cfo.init(hw.profile().unwrap());
    // Unlinked at the default capacitor: rtw89_phy_cfo_reset writes nothing.
    if ready(cfo.dm(&mut hw, false)).is_err() || !hw.crystal.is_empty() {
        return TestResult::Fail("unlinked CFO reset touched the crystal");
    }
    // Linked, +100 average: enable adjust, step +3, DCFO fine-tuned.
    for _ in 0..10 {
        cfo.sample(100);
    }
    if ready(cfo.dm(&mut hw, true)).is_err()
        || hw.crystal != [43]
        || hw.get(R_DCFO_COMP_S0, B_DCFO_COMP_S0_MSK) != 150
    {
        return TestResult::Fail("CFO +100 differs from rtw89_phy_cfo_dm");
    }
    // No new packets: nothing happens.
    if ready(cfo.dm(&mut hw, true)).is_err() || hw.crystal.len() != 1 {
        return TestResult::Fail("CFO dm acted without packets");
    }
    // -20 average while adjusting: step -1, DCFO -19 (12-bit).
    for _ in 0..5 {
        cfo.sample(-20);
    }
    if ready(cfo.dm(&mut hw, true)).is_err()
        || hw.crystal != [43, 42]
        || hw.get(R_DCFO_COMP_S0, B_DCFO_COMP_S0_MSK) != (-19i32 as u32) & 0xfff
    {
        return TestResult::Fail("CFO -20 differs from rtw89_phy_cfo_dm");
    }
    // Disconnected: one step back toward the default.
    if ready(cfo.dm(&mut hw, false)).is_err() || hw.crystal != [43, 42, 41] {
        return TestResult::Fail("CFO reset does not step toward the default");
    }
    // Divergence lock at the bound: reset instead of adjusting.
    let mut hw = Fake {
        profile: Some(Profile {
            cck_pd: false,
            crystal_cap: 40,
            crystal_lower: 39,
            crystal_upper: 41,
        }),
        ..Fake::default()
    };
    let mut cfo = Cfo::default();
    cfo.init(hw.profile().unwrap());
    cfo.sample(400);
    let _ = ready(cfo.dm(&mut hw, true));
    cfo.sample(400);
    if ready(cfo.dm(&mut hw, true)).is_err() || hw.crystal != [43, 42] || !cfo.lock {
        return TestResult::Fail("CFO divergence lock differs from Linux");
    }
    // Throughput state machine: enhance at >= 100 Mbps arms the timer.
    let mut cfo = Cfo::default();
    if cfo.track(150) || cfo.state != CfoState::Enhance || !cfo.timer {
        return TestResult::Fail("CFO enhance state not entered");
    }
    if cfo.track(60) || !cfo.track(40) || cfo.state != CfoState::Normal {
        return TestResult::Fail("CFO enhance state does not fall back");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_track_cfo_crystal_and_dcfo_match_linux
);

fn smoke_rtw89_track_cfo_timer_follows_tx_throughput() -> TestResult {
    let peer = Some([2, 0, 0, 0, 0, 1]);
    let mut hw = Fake::default();
    let mut track = Tracker::default();
    // 100 Mbps over 2 s (rtw89_bytes_to_mbps: bytes >> 18).
    track.transmitted(100 << 18);
    if ready(track.run(&mut hw, 0, peer, false)).is_err() || track.tx_throughput() != 100 {
        return TestResult::Fail("TX throughput differs from rtw89_traffic_stats_calc");
    }
    if !track.cfo().timer || !track.due(250) || track.due(249) {
        return TestResult::Fail("enhanced CFO timer not armed at 250 ms");
    }
    for _ in 0..4 {
        track.sample_cfo(peer, 100);
    }
    if ready(track.run(&mut hw, 250, peer, false)).is_err() || hw.crystal != [43] {
        return TestResult::Fail("enhanced CFO work did not run rtw89_phy_cfo_dm");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_track_cfo_timer_follows_tx_throughput
);
