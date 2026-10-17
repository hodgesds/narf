use super::*;
use alloc::{collections::VecDeque, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    Write(u8, u8),
    Pattern([u8; 4]),
    Ffe(u8),
}
/// An SCDC sink: registers, and LTP requests it raises one per
/// FLT_Update.
struct Sink {
    regs: [u8; 256],
    requests: VecDeque<[u8; 2]>,
    events: Vec<Event>,
    delays: Vec<u64>,
    ffe: u8,
    fail: Option<u8>,
}
impl Sink {
    fn new(requests: &[[u8; 4]]) -> Self {
        let mut regs = [0u8; 256];
        regs[usize::from(SINK_VERSION)] = 1;
        regs[usize::from(STATUS_FLAGS_0)] = 0x40;
        Self {
            regs,
            requests: requests
                .iter()
                .map(|l| [l[0] | l[1] << 4, l[2] | l[3] << 4])
                .collect(),
            events: Vec::new(),
            delays: Vec::new(),
            ffe: 0,
            fail: None,
        }
    }
}
impl FrlTrainer for Sink {
    type Error = ();
    async fn scdc_read(&mut self, offset: u8) -> Result<u8, ()> {
        if self.fail == Some(offset) {
            return Err(());
        }
        // Training underway: each poll of Update_0 raises the next request.
        if offset == UPDATE_0 && self.regs[usize::from(CONFIG_1)] != 0 {
            if let Some(req) = self.requests.pop_front() {
                self.regs[usize::from(LTP_REQ)] = req[0];
                self.regs[usize::from(LTP_REQ) + 1] = req[1];
                self.regs[usize::from(UPDATE_0)] |= 0x20;
            }
        }
        Ok(self.regs[usize::from(offset)])
    }
    async fn scdc_write(&mut self, offset: u8, value: u8) -> Result<(), ()> {
        self.events.push(Event::Write(offset, value));
        if offset == UPDATE_0 {
            self.regs[usize::from(offset)] &= !value; // write 1 to clear
        } else {
            self.regs[usize::from(offset)] = value;
        }
        Ok(())
    }
    fn pattern(&mut self, patterns: [u8; 4]) -> Result<(), ()> {
        if self.fail == Some(0xfe) {
            return Err(());
        }
        self.events.push(Event::Pattern(patterns));
        Ok(())
    }
    async fn ffe(&mut self, lane_set: u8) -> Result<(), ()> {
        if self.fail == Some(0xff) {
            return Err(());
        }
        self.ffe = lane_set & 3;
        self.events.push(Event::Ffe(lane_set));
        Ok(())
    }
    async fn delay(&mut self, us: u64) {
        self.delays.push(us);
    }
}
impl FrlStatusIo for Sink {
    fn current_ffe(&mut self) -> Result<u8, ()> {
        Ok(self.ffe)
    }
}
fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}

/// LTS:1-3 as Linux: Source_Version for a version-1 sink, FLT_Ready, FFE
/// level 0, the rate with three FFE levels, each requested LTP set as
/// LTP minus one (lane 3 kept at LTP1 on three lanes), success when every
/// lane asks for 0; a 0xE request steps the FFE on the next update and
/// keeps the previous patterns; 0xF asks for a lower rate.
fn frl_training_follows_linux_lts() -> TestResult {
    let mut s = Sink::new(&[[2, 2, 2, 2], [0, 0, 0, 0]]);
    if run(train(&mut s, 6, 4)) != Ok(FrlTraining::Success) {
        return TestResult::Fail("4-lane success");
    }
    let want = vec![
        Event::Write(SOURCE_VERSION, 1),
        Event::Ffe(0),
        Event::Write(CONFIG_1, 0x36),
        Event::Write(UPDATE_0, 0x20),
        Event::Pattern([1, 1, 1, 1]),
        Event::Write(UPDATE_0, 0x20),
    ];
    if s.events != want || s.delays.iter().any(|&d| d != 2000) {
        panic!("4-lane sequence {:?}", s.events);
    }
    // Three lanes: lane 3's request is ignored and kept at LTP1.
    let mut s = Sink::new(&[[4, 4, 4, 9], [0, 0, 0, 7]]);
    if run(train(&mut s, 2, 3)) != Ok(FrlTraining::Success)
        || !s.events.contains(&Event::Pattern([3, 3, 3, 0]))
        || !s.events.contains(&Event::Write(CONFIG_1, 0x32))
    {
        return TestResult::Fail("3-lane training");
    }
    // FFE step: the patterns stay, the next update programs level 1.
    let mut s = Sink::new(&[[2, 2, 2, 2], [0xe, 2, 2, 2], [3, 3, 3, 3], [0, 0, 0, 0]]);
    let r = run(train(&mut s, 6, 4));
    let patterns: Vec<_> = s
        .events
        .iter()
        .filter(|e| matches!(e, Event::Pattern(_) | Event::Ffe(_)))
        .cloned()
        .collect();
    // LTP3 on a lane skips the pattern update (not FLT_no_timeout).
    if r != Ok(FrlTraining::Success)
        || patterns
            != [
                Event::Ffe(0),
                Event::Pattern([1, 1, 1, 1]),
                Event::Pattern([1, 1, 1, 1]),
                Event::Ffe(1),
            ]
    {
        panic!("FFE step {patterns:?}");
    }
    let mut s = Sink::new(&[[2, 2, 0xf, 2]]);
    if run(train(&mut s, 6, 4)) != Ok(FrlTraining::LowerRate) {
        return TestResult::Fail("lower rate");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/frl-training", frl_training_follows_linux_lts);

/// No FLT_Ready: a timeout after 105 polls; four tries 200 ms apart then
/// fallback. Sink_Version 0: fallback at once. A link setting left by an
/// earlier try is cleared first. FLT_Update never set: the rate is
/// withdrawn after 105 polls.
fn frl_training_times_out_and_falls_back_like_linux() -> TestResult {
    let mut s = Sink::new(&[]);
    s.regs[usize::from(STATUS_FLAGS_0)] = 0;
    s.regs[usize::from(CONFIG_1)] = 0x33;
    if run(train_with_retries(&mut s, 6, 4)) != Ok(FrlTraining::Fallback) {
        return TestResult::Fail("retries");
    }
    let retries = s.delays.iter().filter(|&&d| d == 200_000).count();
    let polls = s.delays.iter().filter(|&&d| d == 2000).count();
    if retries != 3 || polls != 4 * 105 || s.events.first() != Some(&Event::Write(CONFIG_1, 0)) {
        return TestResult::Fail("timeout cadence");
    }
    let mut s = Sink::new(&[]);
    s.regs[usize::from(SINK_VERSION)] = 0;
    if run(train_with_retries(&mut s, 6, 4)) != Ok(FrlTraining::Fallback) || !s.events.is_empty() {
        return TestResult::Fail("Sink_Version 0");
    }
    let mut s = Sink::new(&[]);
    if run(train(&mut s, 5, 4)) != Ok(FrlTraining::Timeout)
        || s.events.last() != Some(&Event::Write(CONFIG_1, 0))
    {
        return TestResult::Fail("FLT_Update timeout");
    }
    // LTS:P: FRL_Start acknowledged.
    let mut s = Sink::new(&[]);
    s.regs[usize::from(UPDATE_0)] = 0x10;
    if run(poll_start(&mut s)).is_err() || s.events != [Event::Write(UPDATE_0, 0x10)] {
        return TestResult::Fail("FRL_Start");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/frl-training",
    frl_training_times_out_and_falls_back_like_linux
);

/// W1C acknowledgements must follow completed source work and preserve
/// unrelated flags. No-timeout tests keep their patterns, while ordinary
/// requests remain pending until the caller retires and retrains the link.
fn frl_live_status_handles_tests_and_retrain() -> TestResult {
    let mut s = Sink::new(&[]);
    s.regs[UPDATE_0 as usize] = 0x81;
    assert_eq!(run(poll_status(&mut s)), Ok(false));
    assert!(s.events.is_empty());
    s.regs[UPDATE_0 as usize] |= FRL_START;
    assert_eq!(run(poll_status(&mut s)), Ok(false));
    assert_eq!(s.events, [Event::Write(UPDATE_0, FRL_START)]);
    assert_eq!(s.regs[UPDATE_0 as usize], 0x81);

    // All FFE levels, wrap 3 -> 0, and all Source_Test only-flags.
    for (test, flags) in [(0, 0), (2, 0x40), (4, 0x20), (8, 0x60)] {
        for level in 0..4 {
            let mut s = Sink::new(&[]);
            s.ffe = level;
            s.regs[SOURCE_TEST as usize] = test;
            s.regs[UPDATE_0 as usize] = 0x81 | FRL_START | FLT_UPDATE | SOURCE_TEST_UPDATE;
            s.regs[LTP_REQ as usize] = 0x3e;
            s.regs[LTP_REQ as usize + 1] = 0x84;
            assert_eq!(run(poll_status(&mut s)), Ok(false));
            let ffe = flags | ((level + 1) & 3);
            assert_eq!(
                s.events,
                [
                    Event::Write(UPDATE_0, FRL_START),
                    Event::Pattern([0xd, 0xf, 3, 7]),
                    Event::Ffe(ffe),
                    Event::Write(UPDATE_0, FLT_UPDATE),
                    Event::Ffe(ffe),
                    Event::Write(UPDATE_0, SOURCE_TEST_UPDATE),
                ]
            );
            assert_eq!(s.regs[UPDATE_0 as usize], 0x81);
        }
    }
    for test in [0, FLT_NO_TIMEOUT] {
        let mut s = Sink::new(&[]);
        s.regs[SOURCE_TEST as usize] = test;
        s.regs[UPDATE_0 as usize] = FLT_UPDATE;
        s.regs[LTP_REQ as usize] = 0x30;
        s.regs[LTP_REQ as usize + 1] = 0xf1;
        assert_eq!(run(poll_status(&mut s)), Ok(test == 0));
        assert_eq!(
            s.events[0],
            Event::Pattern([0xff, if test == 0 { 0xf } else { 2 }, 0, 0xe])
        );
        assert_eq!(
            s.regs[UPDATE_0 as usize],
            if test == 0 { FLT_UPDATE } else { 0 }
        );
        assert_eq!(s.events.len(), if test == 0 { 1 } else { 2 });
    }
    // A Source_Test_Update alone preserves the current FFE level.
    let mut s = Sink::new(&[]);
    s.ffe = 2;
    s.regs[SOURCE_TEST as usize] = 4;
    s.regs[UPDATE_0 as usize] = SOURCE_TEST_UPDATE;
    assert_eq!(run(poll_status(&mut s)), Ok(false));
    assert_eq!(
        s.events,
        [Event::Ffe(0x22), Event::Write(UPDATE_0, SOURCE_TEST_UPDATE)]
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/frl-training",
    frl_live_status_handles_tests_and_retrain
);

fn frl_live_status_preserves_failed_requests() -> TestResult {
    for fail in [SOURCE_TEST, UPDATE_0, LTP_REQ, LTP_REQ + 1, 0xfe, 0xff] {
        let mut s = Sink::new(&[]);
        s.regs[UPDATE_0 as usize] = FLT_UPDATE | SOURCE_TEST_UPDATE;
        s.regs[LTP_REQ as usize] = 0xee;
        s.fail = Some(fail);
        assert_eq!(run(poll_status(&mut s)), Err(()));
        assert_eq!(s.regs[UPDATE_0 as usize], FLT_UPDATE | SOURCE_TEST_UPDATE);
        assert!(!s
            .events
            .iter()
            .any(|e| matches!(e, Event::Write(UPDATE_0, _))));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/frl-training",
    frl_live_status_preserves_failed_requests
);
