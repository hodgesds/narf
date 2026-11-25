//! DCN 3.2 DisplayPort MST over 128b/132b on the HPO: the source half of
//! an MST link — its VC payload table and per-stream VC rate — as Linux's
//! `dcn31_hpo_dp_link_enc_update_stream_allocation_table` and
//! `dcn31_hpo_dp_link_enc_set_throttled_vcp_size` (which DCN 3.2 reuses)
//! drive the DPHY SYM32 registers of the HPO link encoder:
//!
//! - the table: one SAT_VC row per stream (source = HPO stream encoder
//!   id, slots = time slots), SAT_UPDATE = 1 (update with trigger), then
//!   up to 200 polls 100 us apart for SAT_UPDATE_PENDING to clear. There
//!   is no 16-MTP keepout on the HPO path — Linux's comment says so.
//! - the rate: the stream's average time slots per MTP in 31.32 fixed
//!   point, split X = floor, Y = ceil(frac * 2^25) with the carry into X
//!   when Y rounds up, written to VC_RATE_CNTL of the stream encoder's
//!   row, then up to 10 polls 1 us apart for RATE_UPDATE_PENDING.
//!
//! The sink side is the shared [`crate::dp_mst_mgr`], and the session is
//! the shared [`crate::amdgpu_dcn30_mst::Link`], driven with an
//! [`HpoSource`] — the same add/remove flow as the DIO, only the source
//! half differs. The DIO's 8b/10b MST (DP_MSE_SAT, VC rate Y in 1/2^26)
//! is the already-landed [`crate::amdgpu_dcn30_mst::Source`]; the HPO
//! registers are identical in layout on 3.2.0 (`dcn_3_2_0_offset.h`).
//!
//! The link encoder is bound at construction: the VC-rate registers live
//! in the link encoder's DPHY block, not the frontend's, so a source
//! belongs to one link encoder (0..1). [`MstSource::allocation`] and
//! [`MstSource::vc_rate`] still take the transmitter / frontend the
//! session passes; a transmitter that is not this source's link is
//! refused.

use crate::amdgpu_dcn30_mst::{Allocation, MstSource};
use crate::amdgpu_dcn30_takeover::Regs;
use crate::amdgpu_dml::Timing;
use crate::amdgpu_navi22_modeset::Error;

/// HPO DP link encoder stride: SYM321 (0x3794) − SYM320 (0x36c0).
const LINK_STRIDE: u64 = 0xD4;
/// DPHY SYM32 registers of link encoder 0, at DCN base index 2.
const STATUS: u64 = 0x36c1;
const SAT_UPDATE: u64 = 0x36c4;
const VC_RATE_CNTL0: u64 = 0x36c5;
const SAT_VC0: u64 = 0x36cb;
/// `DP_DPHY_SYM32_STATUS__RATE_UPDATE_PENDING` / `SAT_UPDATE_PENDING`.
const RATE_UPDATE_PENDING: u32 = 1 << 12;
const SAT_UPDATE_PENDING: u32 = 1 << 16;
/// `DP_DPHY_SYM32_SAT_UPDATE__SAT_UPDATE`: 1 is update with trigger.
const SAT_UPDATE_TRIGGER: u32 = 1;
/// `DP_SAT_UPDATE_MAX_RETRY`, 100 us apart (best 109 us, worst 868 us).
const SAT_UPDATE_RETRIES: u32 = 200;
const SAT_UPDATE_WAIT_US: u64 = 100;
/// RATE_UPDATE_PENDING wait: 1 us apart, 10 polls.
const RATE_UPDATE_RETRIES: u32 = 10;
const RATE_UPDATE_WAIT_US: u64 = 1;
/// Streams the HPO SAT holds: four HPO DP stream encoders.
pub const MAX_STREAMS: usize = 4;
/// `DP_MST_TOTAL_SLOTS` (64) less the MTP header slot.
pub const SLOTS: u8 = 63;
/// VC-rate X field: 7 bits at shift 25 (`STREAM_VC_RATE_X_MASK`
/// 0xFE000000); Y is 25 bits (`STREAM_VC_RATE_Y_MASK` 0x01FFFFFF).
const VC_RATE_X_MAX: u32 = 0x7f;
const VC_RATE_Y_MAX: u32 = (1 << 25) - 1;

async fn sleep_us(us: u64) {
    narf_time::SleepUntil::new(narf_time::Deadline::after_us(us).as_instant()).await;
}

/// The MST source half of one HPO link encoder.
#[derive(Clone, Copy, Debug)]
pub struct HpoSource {
    regs: Regs,
    dcn2: u64,
    link: u8,
}

impl HpoSource {
    /// Bind link encoder `link` (0..1). The VC-rate registers live in
    /// this encoder's DPHY block.
    ///
    /// Consumed only by the kernel-test suite below, which clippy's
    /// lib/test configs do not enable; do not delete — this is the
    /// owner's constructor, wired by the modeset lane that lands the
    /// 3.2 MST path.
    #[allow(dead_code)]
    pub(crate) fn new(regs: Regs, dcn2: u64, link: u8) -> Self {
        Self { regs, dcn2, link }
    }

    fn reg(&self, r: u64) -> u64 {
        self.dcn2 + (r + u64::from(self.link) * LINK_STRIDE) * 4
    }
}

impl MstSource for HpoSource {
    async fn allocation(&mut self, transmitter: u8, table: &[Allocation]) -> Result<(), Error> {
        if transmitter != self.link || table.len() > MAX_STREAMS {
            return Err(Error::Invalid);
        }
        if table
            .iter()
            .any(|a| a.stream >= MAX_STREAMS as u8 || a.slots > SLOTS)
        {
            return Err(Error::Invalid);
        }
        let row = |n: usize| {
            table.get(n).map_or(0, |a| {
                u32::from(a.stream) & 0x7 | (u32::from(a.slots) & 0x3f) << 8
            })
        };
        for n in 0..MAX_STREAMS {
            self.regs
                .update(self.reg(SAT_VC0 + n as u64), 0x3f07, row(n))?;
        }
        self.regs
            .update(self.reg(SAT_UPDATE), 1, SAT_UPDATE_TRIGGER)?;
        for _ in 0..SAT_UPDATE_RETRIES {
            sleep_us(SAT_UPDATE_WAIT_US).await;
            if self.regs.read(self.reg(STATUS))? & SAT_UPDATE_PENDING == 0 {
                break;
            }
        }
        Ok(())
    }

    async fn vc_rate(&mut self, fe: u8, rate: (u32, u32)) -> Result<(), Error> {
        let (x, y) = rate;
        if fe >= MAX_STREAMS as u8 || x > VC_RATE_X_MAX || y > VC_RATE_Y_MAX {
            return Err(Error::Invalid);
        }
        self.regs
            .write(self.reg(VC_RATE_CNTL0 + u64::from(fe)), y | x << 25)?;
        for _ in 0..RATE_UPDATE_RETRIES {
            sleep_us(RATE_UPDATE_WAIT_US).await;
            if self.regs.read(self.reg(STATUS))? & RATE_UPDATE_PENDING == 0 {
                break;
            }
        }
        Ok(())
    }
}

/// The PBN, time slots and VC rate of an 8-bpc RGB stream at `pixel_khz` on
/// a 128b/132b link of `link_kbps` (the trained UHBR link's
/// `dp_link_bandwidth_kbps`: rate × lanes × 0.9641): the stream bandwidth
/// with the 128b/132b pixel-to-symbol padding over a 64th of the link's,
/// as the DCN 4.0.1 `uhbr_mst_rate` computes it. Returns (pbn, slots,
/// (x, y)) with Y in 1/2^25. None past 63 slots.
pub fn budget_uhbr(t: &Timing, bpc: u32, link_kbps: u128) -> Option<(u16, u8, (u32, u32))> {
    // `dc_bandwidth_in_kbps_from_timing` with
    // `apply_128b_132b_stream_overhead`: pad the line to whole symbols.
    let mut kbps = u128::from(t.pixel_clock_khz) * u128::from(bpc) * 3;
    let bits = u128::from(t.h_active) * u128::from(bpc) * 3;
    if bits != 0 {
        kbps = (kbps * bits.div_ceil(128) * 128).div_ceil(bits);
    }
    // One PBN is 54/8 Mbps; the link carries 64 slots per MTP.
    let pbn = kbps * 64 / (54 * 8 * 1000);
    if pbn == 0 || pbn > u128::from(u16::MAX) || link_kbps == 0 {
        return None;
    }
    // Average time slots per MTP: the stream's PBN over the link's PBN
    // per slot (link / 64 slots / 6750 kbps per PBN).
    let (num, den) = (kbps * 64, link_kbps);
    let slots = num.div_ceil(den);
    if slots == 0 || slots > u128::from(SLOTS) {
        return None;
    }
    let mut x = (num / den) as u32;
    let mut y = ((num % den) * (1 << 25)).div_ceil(den) as u32;
    if y == 1 << 25 {
        x += 1;
        y = 0;
    }
    if x > VC_RATE_X_MAX {
        return None;
    }
    Some((pbn as u16, slots as u8, (x, y)))
}

/// `dp_link_bandwidth_kbps` for 128b/132b: the link rate in 10 Mbps units
/// × lanes, less the 128b/132b overhead (0.9641, as the DCN 4.0.1
/// `link_kbps` computes it).
pub fn uhbr_link_kbps(link_rate_10mbps: u32, lanes: u8) -> u128 {
    u128::from(link_rate_10mbps) * 10_000 * u128::from(lanes) / 10_000 * 9641
}

#[cfg(feature = "kernel-test")]
pub(crate) mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn fake() -> (Regs, crate::amdgpu_navi22_modeset_model::Bench) {
        use crate::amdgpu_navi22_modeset_model::Bench;
        let bench = Bench::new();
        let regs = Regs {
            window: crate::amdgpu_reg_window::Window::new(bench.gpu.regs),
            authority: narf_capabilities::Cap::bootstrap(),
        };
        (regs, bench)
    }

    fn dcn32_hpo_mst_allocation_writes_sat_rows() -> TestResult {
        use crate::amdgpu_navi22_modeset_model::d2;
        let (regs, bench) = fake();
        let mut source = HpoSource::new(regs, u64::from(d2(0)) * 4, 0);
        let table = [
            Allocation {
                stream: 0,
                slots: 10,
            },
            Allocation {
                stream: 2,
                slots: 20,
            },
        ];
        if narf_scheduler::block_on_spin(source.allocation(0, &table)).is_err() {
            return TestResult::Fail("DCN32 HPO MST allocation failed");
        }
        // Rows 0/1 carry the streams; rows 2/3 are cleared; SAT_UPDATE
        // fired with trigger; the STATUS pending bits read clear.
        let at = |reg: u64| bench.get(d2(0) + reg as u32);
        if at(SAT_VC0) != 10 << 8
            || at(SAT_VC0 + 1) != 2 | 20 << 8
            || at(SAT_VC0 + 2) != 0
            || at(SAT_VC0 + 3) != 0
            || at(SAT_UPDATE) & 1 != 1
        {
            return TestResult::Fail("DCN32 HPO MST SAT rows wrong");
        }
        // The wrong transmitter is refused, as is a stream past 3.
        if narf_scheduler::block_on_spin(source.allocation(1, &table)).is_ok()
            || narf_scheduler::block_on_spin(source.allocation(
                0,
                &[Allocation {
                    stream: 4,
                    slots: 1,
                }],
            ))
            .is_ok()
        {
            return TestResult::Fail("DCN32 HPO MST accepted a bad allocation");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn32-mst",
        dcn32_hpo_mst_allocation_writes_sat_rows
    );

    fn dcn32_hpo_mst_vc_rate_splits_fixed31_32() -> TestResult {
        use crate::amdgpu_navi22_modeset_model::d2;
        let (regs, bench) = fake();
        let mut source = HpoSource::new(regs, u64::from(d2(0)) * 4, 1);
        // Stream encoder 2 on link 1: VC_RATE_CNTL2 at 0x3799 + 2, X = 13
        // at shift 25, Y = 0x1234567.
        if narf_scheduler::block_on_spin(source.vc_rate(2, (13, 0x1234567))).is_err() {
            return TestResult::Fail("DCN32 HPO MST VC rate failed");
        }
        let at = |reg: u64| bench.get(d2(0) + reg as u32);
        if at(VC_RATE_CNTL0 + 2 + LINK_STRIDE) != 0x1234567 | 13 << 25 {
            return TestResult::Fail("DCN32 HPO MST VC rate register wrong");
        }
        if narf_scheduler::block_on_spin(source.vc_rate(4, (1, 0))).is_ok()
            || narf_scheduler::block_on_spin(source.vc_rate(0, (0x80, 0))).is_ok()
            || narf_scheduler::block_on_spin(source.vc_rate(0, (0, 1 << 25))).is_ok()
        {
            return TestResult::Fail("DCN32 HPO MST accepted a bad VC rate");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn32-mst",
        dcn32_hpo_mst_vc_rate_splits_fixed31_32
    );

    fn dcn32_hpo_mst_budget_uhbr() -> TestResult {
        let t = Timing {
            pixel_clock_khz: 148_500,
            h_active: 1920,
            h_total: 2200,
            h_front_porch: 88,
            h_sync_width: 44,
            v_active: 1080,
            v_total: 1125,
            v_front_porch: 4,
            v_sync_width: 5,
            h_sync_positive: true,
            v_sync_positive: true,
        };
        // UHBR10 x4: 10 Gbps/lane * 4 * 0.9641 = 38.564 Gbps.
        let link = uhbr_link_kbps(1000, 4);
        if link != 38_564_000 {
            return TestResult::Fail("DCN32 UHBR link bandwidth wrong");
        }
        let Some((pbn, slots, (x, y))) = budget_uhbr(&t, 8, link) else {
            return TestResult::Fail("1080p60 does not fit UHBR10 x4");
        };
        // PBN = stream kbps / 6750 (no SSC overhead in the UHBR math);
        // slots = ceil(kbps * 64 / link); X.Y = avg slots per MTP.
        if pbn != 528 || slots != 6 || x != 5 || y == 0 {
            return TestResult::Fail("DCN32 UHBR MST PBN/slots/VC rate wrong");
        }
        // 4K60 at 594 MHz needs more than 63 slots at UHBR10 x1.
        let uhd = Timing {
            pixel_clock_khz: 594_000,
            h_active: 3840,
            h_total: 4400,
            ..t
        };
        if budget_uhbr(&uhd, 8, uhbr_link_kbps(1000, 1)).is_some() {
            return TestResult::Fail("DCN32 UHBR MST admitted an over-link stream");
        }
        let _ = (pbn, slots, x, y);
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/dcn32-mst", dcn32_hpo_mst_budget_uhbr);
}
