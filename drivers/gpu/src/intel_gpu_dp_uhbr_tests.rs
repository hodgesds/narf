//! Native fixtures for the 128b/132b link layer against scripted DP 2.0
//! sinks. Every expected sequence and number is derived from Linux 7.4
//! (`intel_dp_link_training.c`, `drm_dp_helper.c`, `intel_dp.c`,
//! `intel_dp_mst.c`, `intel_display.c`), not recorded from this code.
extern crate alloc;

use super::*;
use crate::dp_aux::{AuxCommand, AuxRequest, AuxResponse, AuxStatus};
use alloc::vec;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use narf_kernel_test::{kernel_test_in, TestResult};

/// One observable step: a DPCD access, a source change or a sleep.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Ev {
    Read(u32, usize),
    Write(u32, Vec<u8>),
    Pattern(SourcePattern),
    Presets([u8; 4]),
    Sleep(u64),
}

/// A virtual microsecond clock that advances only by sleeps.
struct VClock<'a> {
    now: Cell<u64>,
    log: &'a RefCell<Vec<Ev>>,
}

impl Clock for VClock<'_> {
    fn now_us(&mut self) -> u64 {
        self.now.get()
    }
    fn sleep_us(&mut self, us: u64) {
        self.now.set(self.now.get() + us);
        self.log.borrow_mut().push(Ev::Sleep(us));
    }
}

/// The source: logs each pattern and preset change, failing on demand.
struct Source<'a> {
    log: &'a RefCell<Vec<Ev>>,
    fail_pattern: Option<SourcePattern>,
}

impl UhbrSource for Source<'_> {
    type Error = &'static str;
    fn pattern(&mut self, pattern: SourcePattern) -> Result<(), &'static str> {
        self.log.borrow_mut().push(Ev::Pattern(pattern));
        if self.fail_pattern == Some(pattern) {
            return Err("source pattern failed");
        }
        Ok(())
    }
    fn presets(&mut self, presets: &[u8; 4]) -> Result<(), &'static str> {
        self.log.borrow_mut().push(Ev::Presets(*presets));
        Ok(())
    }
}

/// A DP 2.0 sink: a DPCD byte image, a scripted sequence of link statuses
/// (each 0x202 six-byte read takes the next; the last repeats) and a count
/// of intra-hop reads that still report the indication.
struct Dp20Sink<'a> {
    log: &'a RefCell<Vec<Ev>>,
    dpcd: Vec<(u32, u8)>,
    statuses: Vec<[u8; 6]>,
    next_status: usize,
    intra_hop_reads: u32,
    nack_reads: Vec<u32>,
}

impl<'a> Dp20Sink<'a> {
    fn new(log: &'a RefCell<Vec<Ev>>, statuses: Vec<[u8; 6]>) -> Self {
        Self {
            log,
            dpcd: Vec::new(),
            statuses,
            next_status: 0,
            intra_hop_reads: 0,
            nack_reads: Vec::new(),
        }
    }
    fn set(&mut self, addr: u32, bytes: &[u8]) {
        for (i, b) in bytes.iter().enumerate() {
            let a = addr + i as u32;
            self.dpcd.retain(|(x, _)| *x != a);
            self.dpcd.push((a, *b));
        }
    }
    fn byte(&self, addr: u32) -> u8 {
        self.dpcd
            .iter()
            .find(|(a, _)| *a == addr)
            .map_or(0, |(_, b)| *b)
    }
}

impl AuxChannel for Dp20Sink<'_> {
    fn transact<'b>(
        &mut self,
        req: &AuxRequest<'_>,
        reply: &'b mut [u8],
    ) -> Result<AuxResponse<'b>, AuxError> {
        match req.cmd {
            AuxCommand::NativeWrite => {
                self.log
                    .borrow_mut()
                    .push(Ev::Write(req.address, req.data.to_vec()));
                let data = req.data.to_vec();
                self.set(req.address, &data);
                if req.address == DP_PAYLOAD_TABLE_UPDATE_STATUS {
                    // Write-1-to-clear (DP 1.2 MST payload table status).
                    self.set(DP_PAYLOAD_TABLE_UPDATE_STATUS, &[0]);
                }
                reply[0] = 0;
                Ok(AuxResponse {
                    status: AuxStatus::Ack,
                    data: &reply[..0],
                })
            }
            AuxCommand::NativeRead => {
                let n = req.data.len();
                self.log.borrow_mut().push(Ev::Read(req.address, n));
                if self.nack_reads.contains(&req.address) {
                    return Ok(AuxResponse {
                        status: AuxStatus::Nack,
                        data: &reply[..0],
                    });
                }
                reply[0] = 0;
                if req.address == DP_LANE0_1_STATUS && n == LINK_STATUS_SIZE {
                    let i = self.next_status.min(self.statuses.len() - 1);
                    self.next_status += 1;
                    reply[1..7].copy_from_slice(&self.statuses[i]);
                } else if req.address == DP_SINK_STATUS {
                    reply[1] = if self.intra_hop_reads > 0 {
                        self.intra_hop_reads -= 1;
                        DP_INTRA_HOP_AUX_REPLY_INDICATION
                    } else {
                        0
                    };
                } else {
                    for i in 0..n {
                        reply[1 + i] = self.byte(req.address + i as u32);
                    }
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

const ALIGN: u8 = DP_INTERLANE_ALIGN_DONE;
const EQ_ALIGN: u8 = DP_128B132B_DPRX_EQ_INTERLANE_ALIGN_DONE;
const CDS_ALIGN: u8 = DP_128B132B_DPRX_CDS_INTERLANE_ALIGN_DONE;
const LS: u32 = DP_LANE0_1_STATUS;

/// `intel_dp_128b132b_link_train` on two lanes against a DP 2.0 sink:
/// the intra-hop poll (500 us apart), 128b/132b TPS1 with zeroed presets,
/// `drm_dp_128b132b_read_aux_rd_interval` (0x02: 3 units of 2 ms), the
/// initial TX FFE request, TPS2, one EQ retry with the new presets (the
/// interval re-read just before them), LANEx_EQ_DONE, the
/// EQ-interlane-align poll (2 ms), `DP_TRAINING_PATTERN_2_CDS` with its
/// CDS-interlane-align and symbol-lock poll, then the pattern disable; the
/// source level and pattern always precede the matching DPCD write, and
/// lanes past the lane count take the last lane's preset.
fn smoke_uhbr_128b132b_training_sequence() -> TestResult {
    let log = RefCell::new(Vec::new());
    let statuses = vec![
        // Initial TX FFE request: lane 0 preset 3, lane 1 preset 5.
        [0x00, 0x00, 0x00, 0x00, 0x53, 0x00],
        // EQ poll 1: not done, request 6 / 7.
        [0x00, 0x00, 0x00, 0x00, 0x76, 0x00],
        // EQ poll 2: both lanes CHANNEL_EQ_DONE + interlane align.
        [0x22, 0x00, ALIGN, 0x00, 0x76, 0x00],
        // Interlane-align poll: not yet, then EQ interlane align done.
        [0x22, 0x00, ALIGN, 0x00, 0x76, 0x00],
        [0x22, 0x00, ALIGN | EQ_ALIGN, 0x00, 0x76, 0x00],
        // CDS: aligned but not CDS-aligned, then CDS + symbol lock.
        [0x22, 0x00, ALIGN | EQ_ALIGN, 0x00, 0x76, 0x00],
        [0x66, 0x00, ALIGN | EQ_ALIGN | CDS_ALIGN, 0x00, 0x76, 0x00],
    ];
    let mut sink = Dp20Sink::new(&log, statuses);
    sink.set(DP_128B132B_TRAINING_AUX_RD_INTERVAL, &[0x02]);
    sink.intra_hop_reads = 2;
    let mut source = Source {
        log: &log,
        fail_pattern: None,
    };
    let mut clock = VClock {
        now: Cell::new(0),
        log: &log,
    };
    let presets = match train(&mut sink, &mut source, &mut clock, 2, 0) {
        Ok(presets) => presets,
        Err(_) => return TestResult::Fail("the scripted DP 2.0 sink must train"),
    };
    if presets != [6, 7, 7, 7] {
        return TestResult::Fail("trained presets must be the last request, clamped per lane");
    }
    let rd = DP_128B132B_TRAINING_AUX_RD_INTERVAL;
    let want = vec![
        Ev::Read(DP_SINK_STATUS, 1),
        Ev::Sleep(500),
        Ev::Read(DP_SINK_STATUS, 1),
        Ev::Sleep(500),
        Ev::Read(DP_SINK_STATUS, 1),
        // intel_dp_reset_link_train(TPS1).
        Ev::Presets([0; 4]),
        Ev::Pattern(SourcePattern::Tps1),
        Ev::Write(DP_TRAINING_PATTERN_SET, vec![DP_TRAINING_PATTERN_1, 0, 0]),
        Ev::Read(rd, 1),
        Ev::Read(LS, 6),
        Ev::Presets([3, 5, 5, 5]),
        Ev::Write(DP_TRAINING_LANE0_SET, vec![3, 5]),
        Ev::Pattern(SourcePattern::Tps2),
        Ev::Write(DP_TRAINING_PATTERN_SET, vec![DP_TRAINING_PATTERN_2, 3, 5]),
        // EQ try 1.
        Ev::Sleep(6_000),
        Ev::Read(LS, 6),
        Ev::Read(rd, 1),
        Ev::Presets([6, 7, 7, 7]),
        Ev::Write(DP_TRAINING_LANE0_SET, vec![6, 7]),
        // EQ try 2: LANEx_EQ_DONE.
        Ev::Sleep(6_000),
        Ev::Read(LS, 6),
        // EQ interlane align.
        Ev::Read(LS, 6),
        Ev::Sleep(2_000),
        Ev::Read(LS, 6),
        // LANEx_CDS_DONE.
        Ev::Write(DP_TRAINING_PATTERN_SET, vec![DP_TRAINING_PATTERN_2_CDS]),
        Ev::Sleep(2_000),
        Ev::Read(LS, 6),
        Ev::Sleep(2_000),
        Ev::Read(LS, 6),
        Ev::Write(DP_TRAINING_PATTERN_SET, vec![DP_TRAINING_PATTERN_DISABLE]),
    ];
    if *log.borrow() != want {
        return TestResult::Fail("128b/132b training sequence differs from Linux");
    }
    // intel_dp_stop_link_train: normal pattern, then intra-hop clear.
    log.borrow_mut().clear();
    if stop_train(&mut sink, &mut source, &mut clock) != Ok(true)
        || *log.borrow()
            != vec![
                Ev::Pattern(SourcePattern::Normal),
                Ev::Read(DP_SINK_STATUS, 1),
            ]
    {
        return TestResult::Fail("stop must set the normal pattern, then see intra-hop clear");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dp_uhbr",
    smoke_uhbr_128b132b_training_sequence
);

/// Every failed 128b/132b training leaves the source at TPS2 and disables
/// `DP_TRAINING_PATTERN_SET` (`intel_dp_128b132b_link_train`'s `out:`): a
/// stuck intra-hop indication (1002 reads 500 us apart: the read after the
/// 500 ms deadline still decides) never starts TPS1, `DP_128B132B_LT_FAILED`
/// ends LANEx_EQ, a CDS that never aligns ends after its 20 ms budget with
/// no LTTPR, and an EQ that never completes ends after 20 tries.
fn smoke_uhbr_training_failures_leave_tps2_and_disable() -> TestResult {
    let tail = |log: &RefCell<Vec<Ev>>| {
        let log = log.borrow();
        log.len() >= 2
            && log[log.len() - 2..]
                == [
                    Ev::Pattern(SourcePattern::Tps2),
                    Ev::Write(DP_TRAINING_PATTERN_SET, vec![DP_TRAINING_PATTERN_DISABLE]),
                ]
    };
    // Intra-hop never clears.
    let log = RefCell::new(Vec::new());
    let mut sink = Dp20Sink::new(&log, vec![[0; 6]]);
    sink.intra_hop_reads = u32::MAX;
    let mut source = Source {
        log: &log,
        fail_pattern: None,
    };
    let mut clock = VClock {
        now: Cell::new(0),
        log: &log,
    };
    let result = train(&mut sink, &mut source, &mut clock, 4, 0);
    let reads = log
        .borrow()
        .iter()
        .filter(|e| **e == Ev::Read(DP_SINK_STATUS, 1))
        .count();
    if result != Err(TrainError::Link(TrainFailure::IntraHop))
        || reads != 1002
        || log
            .borrow()
            .iter()
            .any(|e| *e == Ev::Pattern(SourcePattern::Tps1))
        || !tail(&log)
    {
        return TestResult::Fail("a stuck intra-hop must fail before TPS1, ending at TPS2");
    }
    // LT_FAILED at the first EQ poll.
    let log = RefCell::new(Vec::new());
    let mut sink = Dp20Sink::new(
        &log,
        vec![[0, 0, 0, 0, 0, 0], [0, 0, DP_128B132B_LT_FAILED, 0, 0, 0]],
    );
    let mut source = Source {
        log: &log,
        fail_pattern: None,
    };
    let mut clock = VClock {
        now: Cell::new(0),
        log: &log,
    };
    if train(&mut sink, &mut source, &mut clock, 1, 0)
        != Err(TrainError::Link(TrainFailure::LtFailed))
        || !tail(&log)
    {
        return TestResult::Fail("DP_128B132B_LT_FAILED must end LANEx_EQ");
    }
    // CDS never aligns: (0 + 1) * 20 ms, polled 2 ms apart.
    let log = RefCell::new(Vec::new());
    let eq = [0x22, 0x22, ALIGN | EQ_ALIGN, 0, 0, 0];
    let mut sink = Dp20Sink::new(&log, vec![[0; 6], eq]);
    let mut source = Source {
        log: &log,
        fail_pattern: None,
    };
    let mut clock = VClock {
        now: Cell::new(0),
        log: &log,
    };
    let before = clock.now.get();
    if train(&mut sink, &mut source, &mut clock, 4, 0)
        != Err(TrainError::Link(TrainFailure::CdsTimeout))
        || !tail(&log)
    {
        return TestResult::Fail("an unaligned CDS must time out");
    }
    // The CDS loop sleeps 2 ms twelve times: the deadline sample at 22 ms
    // is the first past the 20 ms budget, and its read is the last.
    let cds_sleeps = {
        let log = log.borrow();
        let start = log
            .iter()
            .position(|e| *e == Ev::Write(DP_TRAINING_PATTERN_SET, vec![DP_TRAINING_PATTERN_2_CDS]))
            .unwrap_or(0);
        log[start..]
            .iter()
            .filter(|e| **e == Ev::Sleep(2_000))
            .count()
    };
    if cds_sleeps != 12 || clock.now.get() <= before {
        return TestResult::Fail("the CDS budget must be (lttpr + 1) * 20 ms of 2 ms polls");
    }
    // EQ never completes: 20 tries of the interval.
    let log = RefCell::new(Vec::new());
    let mut sink = Dp20Sink::new(&log, vec![[0; 6]]);
    sink.set(DP_128B132B_TRAINING_AUX_RD_INTERVAL, &[0x80]);
    let mut source = Source {
        log: &log,
        fail_pattern: None,
    };
    let mut clock = VClock {
        now: Cell::new(0),
        log: &log,
    };
    let polls = |log: &RefCell<Vec<Ev>>| {
        log.borrow()
            .iter()
            .filter(|e| **e == Ev::Read(LS, 6))
            .count()
    };
    if train(&mut sink, &mut source, &mut clock, 2, 0)
        != Err(TrainError::Link(TrainFailure::EqMaxTries))
        || polls(&log) != 21
        || !tail(&log)
    {
        return TestResult::Fail("EQ must give up after its 20 tries (1 ms interval)");
    }
    // A source that cannot leave TPS1 still disables the sink's pattern.
    let log = RefCell::new(Vec::new());
    let mut sink = Dp20Sink::new(&log, vec![[0; 6]]);
    let mut source = Source {
        log: &log,
        fail_pattern: Some(SourcePattern::Tps2),
    };
    let mut clock = VClock {
        now: Cell::new(0),
        log: &log,
    };
    if train(&mut sink, &mut source, &mut clock, 4, 0)
        != Err(TrainError::Source("source pattern failed"))
        || log.borrow().last()
            != Some(&Ev::Write(
                DP_TRAINING_PATTERN_SET,
                vec![DP_TRAINING_PATTERN_DISABLE],
            ))
    {
        return TestResult::Fail("a source failure must still disable the sink's pattern");
    }
    if train(&mut sink, &mut source, &mut clock, 3, 0)
        != Err(TrainError::Link(TrainFailure::LaneCount))
    {
        return TestResult::Fail("three lanes are not a DP lane count");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dp_uhbr",
    smoke_uhbr_training_failures_leave_tps2_and_disable
);

/// `intel_dp_link_training_set_mode` + `intel_dp_link_training_set_bw` on a
/// UHBR link, and the DPCD side of the 128b/132b SST payload
/// (`drm_dp_dpcd_write_payload(aux, 1, 0, tu)` and
/// `drm_dp_dpcd_poll_act_handled`).
fn smoke_uhbr_prepare_and_payload_dpcd() -> TestResult {
    let log = RefCell::new(Vec::new());
    let mut sink = Dp20Sink::new(&log, vec![[0; 6]]);
    if prepare(&mut sink, UhbrRate::Uhbr20, 4, true).is_err()
        || *log.borrow()
            != vec![
                Ev::Write(DP_DOWNSPREAD_CTRL, vec![0x00, DP_SET_ANSI_128B132B]),
                Ev::Write(0x100, vec![0x02, 4 | DP_POST_LT_ADJ_REQ_GRANTED]),
            ]
    {
        return TestResult::Fail("UHBR prepare must set 128b/132b coding before the rate");
    }
    log.borrow_mut().clear();
    if prepare(&mut sink, UhbrRate::Uhbr10, 2, false).is_err()
        || log.borrow()[1] != Ev::Write(0x100, vec![0x01, 2])
    {
        return TestResult::Fail("UHBR10 is DP_LINK_BW_10 with no enhanced framing");
    }
    // The payload table updates on the third read (two 10 ms sleeps).
    log.borrow_mut().clear();
    sink.set(DP_PAYLOAD_TABLE_UPDATE_STATUS, &[0]);
    let mut clock = VClock {
        now: Cell::new(0),
        log: &log,
    };
    // The DPRX updates its table on the third status read, then its ACT.
    struct Updating<'a, 'b>(&'b mut Dp20Sink<'a>, u32);
    impl AuxChannel for Updating<'_, '_> {
        fn transact<'c>(
            &mut self,
            req: &AuxRequest<'_>,
            reply: &'c mut [u8],
        ) -> Result<AuxResponse<'c>, AuxError> {
            if req.cmd == AuxCommand::NativeRead && req.address == DP_PAYLOAD_TABLE_UPDATE_STATUS {
                self.1 += 1;
                if self.1 == 3 {
                    self.0
                        .set(DP_PAYLOAD_TABLE_UPDATE_STATUS, &[DP_PAYLOAD_TABLE_UPDATED]);
                }
                if self.1 == 4 {
                    self.0
                        .set(DP_PAYLOAD_TABLE_UPDATE_STATUS, &[DP_PAYLOAD_ACT_HANDLED]);
                }
            }
            self.0.transact(req, reply)
        }
    }
    let mut aux = Updating(&mut sink, 0);
    if !write_payload(&mut aux, &mut clock, 1, 0, 48) || !poll_act_handled(&mut aux, &mut clock) {
        return TestResult::Fail("the payload must be acknowledged, then its ACT");
    }
    let status = DP_PAYLOAD_TABLE_UPDATE_STATUS;
    let want = vec![
        Ev::Write(status, vec![DP_PAYLOAD_TABLE_UPDATED]),
        Ev::Write(DP_PAYLOAD_ALLOCATE_SET, vec![1, 0, 48]),
        Ev::Read(status, 1),
        Ev::Sleep(10_000),
        Ev::Read(status, 1),
        Ev::Sleep(10_000),
        Ev::Read(status, 1),
        Ev::Read(status, 1),
    ];
    if *log.borrow() != want {
        return TestResult::Fail("payload DPCD sequence differs from drm_dp_dpcd_write_payload");
    }
    // A table that never updates gives up after 20 reads.
    let log = RefCell::new(Vec::new());
    let mut sink = Dp20Sink::new(&log, vec![[0; 6]]);
    let mut clock = VClock {
        now: Cell::new(0),
        log: &log,
    };
    let reads = |log: &RefCell<Vec<Ev>>| {
        log.borrow()
            .iter()
            .filter(|e| **e == Ev::Read(status, 1))
            .count()
    };
    if write_payload(&mut sink, &mut clock, 1, 0, 0) || reads(&log) != 20 {
        return TestResult::Fail("an unacknowledged payload must fail after 20 reads");
    }
    // No ACT within 3000 ms (200 us polls; the post-deadline read decides).
    log.borrow_mut().clear();
    let start = clock.now.get();
    if poll_act_handled(&mut sink, &mut clock) || clock.now.get() - start != 3_000_200 {
        return TestResult::Fail("a missing ACT must time out at the 3 s default");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dp_uhbr",
    smoke_uhbr_prepare_and_payload_dpcd
);

/// `intel_dp_set_dpcd_sink_rates` for 128b/132b: the rates need
/// `DP_CAP_ANSI_128B132B`; an LTTPR with 128b/132b masks them, one without
/// (or below revision 2.0) clears them; a failed LTTPR read is no LTTPR.
/// `mtl_rates` / `mtl_max_source_rate` for the source.
fn smoke_uhbr_sink_and_source_rates() -> TestResult {
    let log = RefCell::new(Vec::new());
    let mut raw = [0u8; 16];
    raw[0] = 0x14;
    raw[2] = 4 | DP_POST_LT_ADJ_REQ_SUPPORTED;
    let mut sink = Dp20Sink::new(&log, vec![[0; 6]]);
    sink.set(
        DP_128B132B_SUPPORTED_LINK_RATES,
        &[DP_UHBR10 | DP_UHBR20 | DP_UHBR13_5],
    );
    // Without DP_CAP_ANSI_128B132B nothing past the caps is read.
    match read_sink(&mut sink, &raw) {
        Ok(caps) if caps.rates == 0 && caps.post_lt_adj_req && log.borrow().is_empty() => {}
        _ => return TestResult::Fail("an 8b/10b-only sink reports no UHBR rate"),
    }
    raw[DP_MAIN_LINK_CHANNEL_CODING] = DP_CAP_ANSI_128B132B;
    match read_sink(&mut sink, &raw) {
        Ok(caps) if caps.rates == DP_UHBR10 | DP_UHBR13_5 | DP_UHBR20 && !caps.lttpr => {}
        _ => return TestResult::Fail("a direct DP 2.0 sink reports its rates"),
    }
    // One LTTPR (count 0x80) at revision 2.0 carrying UHBR10 only.
    sink.set(
        DP_LTTPR_COMMON_CAPS,
        &[0x20, 0x1e, 0x80, 0x55, 4, 0, 1, DP_UHBR10],
    );
    match read_sink(&mut sink, &raw) {
        Ok(caps) if caps.rates == DP_UHBR10 && caps.lttpr => {}
        _ => return TestResult::Fail("a 128b/132b LTTPR must mask the rates"),
    }
    sink.set(DP_LTTPR_COMMON_CAPS, &[0x14, 0x1e, 0x40, 0x55, 4, 0, 1, 7]);
    match read_sink(&mut sink, &raw) {
        Ok(caps) if caps.rates == 0 && caps.lttpr => {}
        _ => return TestResult::Fail("a pre-2.0 LTTPR must clear the UHBR rates"),
    }
    sink.nack_reads.push(DP_LTTPR_COMMON_CAPS);
    match read_sink(&mut sink, &raw) {
        Ok(caps) if caps.rates == DP_UHBR10 | DP_UHBR13_5 | DP_UHBR20 && !caps.lttpr => {}
        _ => return TestResult::Fail("a failed LTTPR read is Linux's zeroed caps"),
    }
    if lttpr_count(&[0, 0, 0x80, 0, 0, 0, 0, 0]) != Some(1)
        || lttpr_count(&[0, 0, 0x01, 0, 0, 0, 0, 0]) != Some(8)
        || lttpr_count(&[0, 0, 0x03, 0, 0, 0, 0, 0]).is_some()
    {
        return TestResult::Fail("drm_dp_lttpr_count decode wrong");
    }
    // Source: C20/LT ports on display 14/20/30/35 reach UHBR10 and UHBR20
    // (mtl_rates has no 1350000); C10 and Wildcat Lake stop at HBR3.
    for ip in [
        DisplayIp::Xelpdp,
        DisplayIp::Xe2Lpd,
        DisplayIp::Xe3Lpd,
        DisplayIp::NovaLakeS,
    ] {
        if source_rates(ip, false) != DP_UHBR10 | DP_UHBR20 || source_rates(ip, true) != 0 {
            return TestResult::Fail("display 14+ C20/LT source rates are UHBR10 and UHBR20");
        }
    }
    if source_rates(DisplayIp::WildcatLake, false) != 0 {
        return TestResult::Fail("Wildcat Lake caps at HBR3");
    }
    for (rate, bw, bit, symbol) in [
        (UhbrRate::Uhbr10, 0x01, DP_UHBR10, 312_500),
        (UhbrRate::Uhbr13_5, 0x04, DP_UHBR13_5, 421_875),
        (UhbrRate::Uhbr20, 0x02, DP_UHBR20, 625_000),
    ] {
        if rate.link_bw() != bw
            || rate.rate_bit() != bit
            || rate.symbol_clock_khz() != symbol
            || UhbrRate::from_link_rate(rate.link_rate()) != Some(rate)
        {
            return TestResult::Fail("UHBR rate codes wrong");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dp_uhbr",
    smoke_uhbr_sink_and_source_rates
);

fn mode(pclk: u32, h: u16, htotal: u16, v: u16, vtotal: u16) -> Mode {
    Mode {
        pixel_clock_khz: pclk,
        h_active: h,
        h_total: htotal,
        h_sync_start: h + 8,
        h_sync_end: h + 40,
        v_active: v,
        v_total: vtotal,
        v_sync_start: v + 3,
        v_sync_end: v + 8,
        h_sync_positive: true,
        v_sync_positive: true,
    }
}

/// `intel_dp_compute_link_config_wide` over the 8b/10b and UHBR common
/// rates, then `intel_dp_mtp_tu_compute_config` and
/// `intel_link_compute_m_n` at the 32-bit symbol clock. Expected values
/// are Linux's formulas evaluated by hand:
///
/// - 3840x2160@60 (594 MHz, htotal 4400) on two lanes: HBR3 x2 carries
///   1620000 kBps, the mode needs 1782000 at 24 bpp, so UHBR10 x2
///   (2417750) wins at 24 bpp before any 18 bpp 8b/10b link;
///   `data_m = 1782000`, `tu = DIV_ROUND_UP(1782000 * 64, 2417750) = 48`,
///   `DATA_M = TU_SIZE(48) | 0x5e579e`, `DATA_N = 0x800000`,
///   `LINK_M/N = 594000 / 312500` scaled to N 0x80000 = 0xf34d6 / 0x80000.
/// - The same mode at UHBR20 x1 (the only UHBR20 sink): `LINK_M` 0x79a6b.
/// - 1366x768 (85.5 MHz, htotal 1792) at UHBR10 x1: the MST alignment to
///   four symbol cycles makes the overhead 1003417 ppm, `data_m` 257377,
///   `tu` 16, `DATA_M = TU_SIZE(16) | 0x1b4082`.
fn smoke_uhbr_link_choice_and_mn() -> TestResult {
    let uhd = mode(594_000, 3840, 4400, 2160, 2250);
    let two = dsc::LinkLimits::standard(810_000, 2);
    if link_required(2, 594_000, 3840, 384) != 1_782_000
        || max_link_data_rate(UhbrRate::Uhbr10, 2) != 2_417_750
        || max_link_data_rate(UhbrRate::Uhbr20, 4) != 9_671_000
    {
        return TestResult::Fail("UHBR bandwidth helpers differ from drm_dp_helper");
    }
    let link = match wide_link(&two, DP_UHBR10 | DP_UHBR20, &uhd, 24) {
        WideLink::Uhbr(link) => link,
        _ => return TestResult::Fail("4K60 on two lanes must take UHBR10 x2 at 24 bpp"),
    };
    if link
        != (UhbrLink {
            rate: UhbrRate::Uhbr10,
            lanes: 2,
            pipe_bpp: 24,
        })
    {
        return TestResult::Fail("wrong UHBR link for 4K60 on two lanes");
    }
    match mtp_tu(&link, &uhd) {
        Some(s)
            if s.tu == 48 && s.m_n == [(47 << 25) | 0x5e_579e, 0x80_0000, 0xf_34d6, 0x8_0000] => {}
        _ => return TestResult::Fail("UHBR10 x2 M/N/TU differ from Linux"),
    }
    // Only UHBR20 in common: UHBR20 x1 already carries it.
    let link20 = match wide_link(&two, DP_UHBR20, &uhd, 24) {
        WideLink::Uhbr(link) if link.rate == UhbrRate::Uhbr20 && link.lanes == 1 => link,
        _ => return TestResult::Fail("UHBR20 x1 must win when it is the only UHBR rate"),
    };
    match mtp_tu(&link20, &uhd) {
        Some(s) if s.tu == 48 && s.m_n[2] == 0x7_9a6b && s.m_n[3] == 0x8_0000 => {}
        _ => return TestResult::Fail("UHBR20 link M/N must use the 625 MHz symbol clock"),
    }
    // A mode HBR3 carries never takes UHBR. Without a UHBR rate 4K60 drops
    // to 18 bpp on HBR3 x2 (1336500 <= 1620000 kBps); a 6 bpc EDID takes
    // that before any UHBR rate; 4K120 (2673000 kBps at 18 bpp) fits
    // nothing uncompressed on two 8b/10b lanes.
    let uhd120 = mode(1_188_000, 3840, 4400, 2160, 2250);
    if wide_link(
        &two,
        DP_UHBR10 | DP_UHBR20,
        &mode(148_500, 1920, 2200, 1080, 1125),
        24,
    ) != WideLink::EightTenB
        || wide_link(&two, 0, &uhd, 24) != WideLink::EightTenB
        || wide_link(&two, DP_UHBR10, &uhd, 18) != WideLink::EightTenB
        || wide_link(&two, 0, &uhd120, 24) != WideLink::None
    {
        return TestResult::Fail("8b/10b first at each bpp, UHBR only past it");
    }
    let small = mode(85_500, 1366, 1792, 768, 798);
    let one = UhbrLink {
        rate: UhbrRate::Uhbr10,
        lanes: 1,
        pipe_bpp: 24,
    };
    match mtp_tu(&one, &small) {
        Some(s) if s.tu == 16 && s.m_n[0] == (15 << 25) | 0x1b_4082 && s.m_n[1] == 0x80_0000 => {}
        _ => return TestResult::Fail("one-lane MST alignment must shape data M and TU"),
    }
    // A stream wider than 64 slots refuses (Linux then needs DSC).
    let wide = mode(2_376_000, 7680, 9000, 4320, 4400);
    if mtp_tu(&one, &wide).is_some() {
        return TestResult::Fail("more than 64 time slots must refuse");
    }
    if min_hblank(&uhd, 24) != 3 {
        return TestResult::Fail("display-30 128b/132b MIN_HBLANK is at most 3");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dp_uhbr",
    smoke_uhbr_link_choice_and_mn
);
