//! Native fixtures for the per-hop 8b/10b LTTPR training against a scripted
//! link of LTTPRs and a DPRX. Every expected access and train-set byte is
//! derived from Linux 7.4 `intel_dp_link_training.c`
//! (`intel_dp_link_train_all_phys`, `intel_dp_link_train_phy`,
//! `intel_dp_get_lane_adjust_vswing_preemph`, `intel_dp_phy_voltage_max`)
//! and `drm_dp_helper.c` (`drm_dp_dpcd_read_phy_link_status`,
//! `__read_delay`), not recorded from this code.
extern crate alloc;

use super::*;
use crate::dp_aux::{AuxCommand, AuxRequest, AuxResponse, AuxStatus};
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

/// A link of PHYs answering DPCD reads from `regs`; the status of the PHY
/// whose base is in `slow` reports clock recovery only from its second
/// status read on (asking for swing 3 / pre-emphasis 0 on every lane), the
/// others report CR, channel EQ, symbol lock and interlane alignment.
struct Link {
    regs: BTreeMap<u32, u8>,
    writes: Vec<(u32, Vec<u8>)>,
    slow: Option<u32>,
    slow_reads: u32,
}

impl Link {
    fn new(slow: Option<u32>) -> Self {
        let mut regs = BTreeMap::new();
        // DPRX and LTTPR1/LTTPR2 status: CR, EQ, symbol lock, aligned.
        for base in [0x202u32, 0xf_0030, 0xf_0080] {
            regs.insert(base, 0x77);
            regs.insert(base + 1, 0x77);
            regs.insert(base + 2, 0x01);
        }
        Self {
            regs,
            writes: Vec::new(),
            slow,
            slow_reads: 0,
        }
    }
    fn read(&mut self, address: u32) -> u8 {
        if let Some(base) = self.slow {
            let off = address.wrapping_sub(base);
            if off < 5 {
                if off == 0 {
                    self.slow_reads += 1;
                }
                let done = self.slow_reads >= 2;
                // LTTPR layout: lane status 0..1, align 2, adjust 3..4.
                return match off {
                    0 | 1 if done => 0x77,
                    0 | 1 => 0x00,
                    2 if done => 0x01,
                    3 | 4 => 0x33,
                    _ => 0,
                };
            }
        }
        self.regs.get(&address).copied().unwrap_or(0)
    }
    fn writes_to(&self, base: u32) -> Vec<Vec<u8>> {
        self.writes
            .iter()
            .filter(|&(a, _)| *a == base)
            .map(|(_, d)| d.clone())
            .collect()
    }
}

impl AuxChannel for Link {
    fn transact<'b>(
        &mut self,
        req: &AuxRequest<'_>,
        reply: &'b mut [u8],
    ) -> Result<AuxResponse<'b>, AuxError> {
        match req.cmd {
            AuxCommand::NativeWrite => {
                self.writes.push((req.address, req.data.to_vec()));
                Ok(AuxResponse {
                    status: AuxStatus::Ack,
                    data: &reply[..0],
                })
            }
            AuxCommand::NativeRead => {
                let n = req.data.len();
                for i in 0..n {
                    reply[1 + i] = self.read(req.address + i as u32);
                }
                Ok(AuxResponse {
                    status: AuxStatus::Ack,
                    data: &reply[1..1 + n],
                })
            }
            _ => Err(AuxError::UnknownStatus),
        }
    }
}

struct Sleeps(u64, Vec<u64>);

impl Clock for Sleeps {
    fn now_us(&mut self) -> u64 {
        self.0
    }
    fn sleep_us(&mut self, us: u64) {
        self.0 += us;
        self.1.push(us);
    }
}

/// Two LTTPRs in non-transparent mode; LTTPR2 (`DP_PHY_LTTPR(1)`, the one
/// the source feeds) transmits without swing level 3 or pre-emphasis level
/// 3 (`DP_TRANSMITTER_CAPABILITY_PHY_REPEATER` 0), LTTPR1 with both.
fn two_lttprs(lanes: u8) -> Dp14Link {
    let mut lttpr = LttprInit {
        count: 2,
        ..LttprInit::default()
    };
    lttpr.phy_caps[0] = [0, 0x03, 0];
    lttpr.phy_caps[1] = [0, 0x00, 0];
    Dp14Link {
        lanes,
        dprx_rev: 0x14,
        dprx_cr_delay_us: 100,
        dprx_eq_delay_us: 400,
        dprx_eq_pattern: 3 | DP_LINK_SCRAMBLING_DISABLE,
        lttpr,
    }
}

/// `intel_dp_link_train_all_phys` through two LTTPRs: LTTPR2 first at its
/// registers (0xf0060: TPS1 without scrambling, then the LTTPR's TPS4,
/// then disabled), LTTPR1 (0xf0010) the same, then the DPRX (0x102: TPS1,
/// its TPS3 without scrambling, disabled). LTTPR1 asks for swing 3 on its
/// first status read; its transmitter is LTTPR2, which has no swing level
/// 3 (`intel_dp_lttpr_voltage_max`), so the train set is swing 2 with
/// `DP_TRAIN_MAX_SWING_REACHED` (0x06) at `DP_TRAINING_LANE0_SET_PHY_REPEATER1`
/// and carried into its TPS4. The delays are 100 us for clock recovery and
/// 400 us for channel equalization on every PHY (`__read_delay`: LTTPR CR
/// fixed, a zero `DP_TRAINING_AUX_RD_INTERVAL_PHY_REPEATER`, the DPRX's
/// caps). The returned levels are LTTPR2's (the source-fed hop): zero.
fn smoke_uhbr_lttpr_per_hop_order_and_far_hop_maxima() -> TestResult {
    let mut aux = Link::new(Some(DP_LANE0_1_STATUS_PHY_REPEATER1));
    let mut clock = Sleeps(0, Vec::new());
    let link = two_lttprs(2);
    let levels = match train_all_phys(&mut aux, &mut clock, &link) {
        Ok(levels) => levels,
        Err(_) => return TestResult::Fail("the link must train hop by hop"),
    };
    let patterns: Vec<(u32, u8)> = aux
        .writes
        .iter()
        .filter(|(a, _)| matches!(*a, 0x102 | 0xf_0010 | 0xf_0060))
        .map(|(a, d)| (*a, d[0]))
        .collect();
    let want = vec![
        (0xf_0060, 0x21),
        (0xf_0060, 0x07),
        (0xf_0060, 0x00),
        (0xf_0010, 0x21),
        (0xf_0010, 0x07),
        (0xf_0010, 0x00),
        (0x102, 0x21),
        (0x102, 0x23),
        (0x102, 0x00),
    ];
    if patterns != want {
        return TestResult::Fail("LTTPR2, then LTTPR1, then the DPRX, each disabled after");
    }
    if aux.writes_to(0xf_0011) != [vec![0x06, 0x06]]
        || aux.writes_to(0xf_0010)[1] != [0x07, 0x06, 0x06]
        || aux.writes_to(0xf_0060)[0] != [0x21, 0, 0]
    {
        return TestResult::Fail("LTTPR1 behind LTTPR2 is capped at swing 2 (max reached)");
    }
    if clock.1 != [100, 400, 100, 100, 400, 100, 400] {
        return TestResult::Fail("100 us CR and 400 us EQ delays, one more CR poll on LTTPR1");
    }
    if levels != VSwingPe::default() {
        return TestResult::Fail("the source keeps LTTPR2's levels");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dp_uhbr",
    smoke_uhbr_lttpr_per_hop_order_and_far_hop_maxima
);

/// `intel_dp_get_lane_adjust_vswing_preemph` against the PHY's maxima: the
/// hop the source feeds takes the source's (swing 3, pre-emphasis 3,
/// `intel_ddi_dp_voltage_max` / `_preemph_max`), so a request of swing 3 is
/// 3 | `DP_TRAIN_MAX_SWING_REACHED` (0x07); a far hop behind a repeater
/// without levels 3 caps swing 3 at 2 (0x06) and pre-emphasis 3 at 2 with
/// `DP_TRAIN_MAX_PRE_EMPHASIS_REACHED` (0x30), the swing then limited to
/// `dp_voltage_max(2)` = 1 (0x31); swing 1 / pre-emphasis 1 is 0x09 on
/// either. Lanes past the lane count repeat the last lane's request.
/// `drm_dp_dpcd_read_phy_link_status` puts an LTTPR's adjust requests after a
/// zero `DP_SINK_STATUS` slot.
fn smoke_uhbr_lttpr_adjust_train_maxima() -> TestResult {
    let link = two_lttprs(1);
    let status = |adjust: u8| [0u8, 0, 0, 0, adjust, adjust];
    let cases = [
        (Phy::Lttpr(1), 0x03, 0x07),
        (Phy::Lttpr(0), 0x03, 0x06),
        (Phy::Lttpr(0), 0x0f, 0x31),
        (Phy::Lttpr(1), 0x05, 0x09),
        (Phy::Lttpr(0), 0x05, 0x09),
    ];
    for (phy, adjust, want) in cases {
        let mut set = [0u8; 4];
        if !get_adjust_train(&link, phy, &status(adjust), &mut set) || set != [want; 4] {
            return TestResult::Fail("the train set follows the PHY's drive maxima");
        }
    }
    let mut aux = Link::new(None);
    aux.regs.insert(0xf_0030, 0x11);
    aux.regs.insert(0xf_0031, 0x22);
    aux.regs.insert(0xf_0032, 0x81);
    aux.regs.insert(0xf_0033, 0x44);
    aux.regs.insert(0xf_0034, 0x55);
    if read_phy_link_status(&mut aux, Phy::Lttpr(0)) != Ok([0x11, 0x22, 0x81, 0, 0x44, 0x55]) {
        return TestResult::Fail("an LTTPR's status skips the DP_SINK_STATUS slot");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dp_uhbr",
    smoke_uhbr_lttpr_adjust_train_maxima
);

/// A hop that never recovers its clock fails the link at that hop: LTTPR2
/// keeps asking for the same levels, so `intel_dp_link_training_clock_recovery`
/// gives up after the same voltage five times; its pattern is disabled, no
/// farther hop or the DPRX is trained, and the DPRX's pattern is disabled.
fn smoke_uhbr_lttpr_failed_hop_stops_the_link() -> TestResult {
    let mut aux = Link::new(None);
    aux.regs.insert(0xf_0080, 0x00);
    aux.regs.insert(0xf_0081, 0x00);
    let mut clock = Sleeps(0, Vec::new());
    match train_all_phys(&mut aux, &mut clock, &two_lttprs(2)) {
        Err(HopError {
            phy: Phy::Lttpr(1),
            failure: HopFailure::SameVoltage,
        }) => {}
        _ => return TestResult::Fail("LTTPR2's clock recovery must fail on the same voltage"),
    }
    let patterns: Vec<(u32, u8)> = aux
        .writes
        .iter()
        .filter(|(a, _)| matches!(*a, 0x102 | 0xf_0010 | 0xf_0060))
        .map(|(a, d)| (*a, d[0]))
        .collect();
    if patterns != [(0xf_0060, 0x21), (0xf_0060, 0x00), (0x102, 0x00)] {
        return TestResult::Fail("the failed hop and the DPRX are disabled, nothing else trains");
    }
    // The first status read plus four same-voltage updates.
    if clock.1.len() != 5 {
        return TestResult::Fail("five clock recovery polls before giving up");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dp_uhbr",
    smoke_uhbr_lttpr_failed_hop_stops_the_link
);
