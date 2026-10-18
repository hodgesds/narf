//! AUX/sink-model tests of the DCN3.0 DP link layer against Linux DC's
//! sequences (capabilities and LTTPR modes, TPS selection, CR/EQ with
//! adjust requests, post-LT adjust, hop-by-hop repeaters, retries,
//! verification fallback, link-loss parsing).
use super::*;
use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Ev {
    Read(u32, usize),
    Write(u32, Vec<u8>),
    Timeout(u32),
    Delay(u64),
    Enable(DpLink),
    Pattern(Tps),
    Video,
    Drive(u8, u8),
    Disable,
}
type Log = Arc<IrqSafeSpinLock<Vec<Ev>>>;

/// A DP sink (with an optional repeater chain) at the far end of AUX.
struct Sink {
    log: Log,
    regs: BTreeMap<u32, u8>,
    caps: [u8; 16],
    ext: Option<[u8; 16]>,
    feature: u8,
    lttpr: Option<[u8; 10]>,
    intervals: [u8; 8],
    /// Rates where clock recovery never locks.
    cr_bad_rates: Vec<u8>,
    /// Lanes at and above this index never lock clock recovery.
    cr_lanes: u8,
    /// Clock recovery needs at least this swing; requested until reached.
    need_swing: u8,
    /// (rate, lanes) where equalization never locks.
    eq_bad: Vec<(u8, u8)>,
    /// Pre-emphasis the sink requests during EQ.
    eq_pre: u8,
    /// A post-LT adjust request (swing, pre) the sink holds while idle.
    post_req: Option<(u8, u8)>,
    trained: bool,
    lost: bool,
    irq_vector: u8,
    connected: bool,
    gone: bool,
}
impl Sink {
    fn new(log: Log) -> Self {
        let mut caps = [0u8; 16];
        caps[0] = 0x12;
        caps[1] = HBR2;
        caps[2] = 0x80 | 4;
        Self {
            log,
            regs: BTreeMap::new(),
            caps,
            ext: None,
            feature: 0,
            lttpr: None,
            intervals: [0; 8],
            cr_bad_rates: Vec::new(),
            cr_lanes: 4,
            need_swing: 0,
            eq_bad: Vec::new(),
            eq_pre: 0,
            post_req: None,
            trained: false,
            lost: false,
            irq_vector: 0,
            connected: true,
            gone: false,
        }
    }
    fn reg(&self, at: u32) -> u8 {
        *self.regs.get(&at).unwrap_or(&0)
    }
    /// Lane status in the sink layout for `hop` (0: DPRX).
    fn status(&mut self, hop: u8) -> [u8; 6] {
        let off = if hop == 0 {
            0
        } else {
            0x50 * u32::from(hop - 1)
        };
        let (pattern_at, lane_at) = if hop == 0 {
            (0x102, 0x103)
        } else {
            (0xf0010 + off, 0xf0011 + off)
        };
        let pattern = self.reg(pattern_at) & 0xf;
        let rate = self.reg(0x100);
        let lanes = self.reg(0x101) & 0x1f;
        let set = self.reg(lane_at);
        let swing = set & 3;
        let cr = |lane: u8| {
            lane < self.cr_lanes && !self.cr_bad_rates.contains(&rate) && swing >= self.need_swing
        };
        let pre = (set >> 3) & 3;
        let eq_ok =
            (0..lanes).all(cr) && pre >= self.eq_pre && !self.eq_bad.contains(&(rate, lanes));
        let mut s = [0u8; 6];
        let put =
            |s: &mut [u8; 6], lane: u8, v: u8| s[usize::from(lane / 2)] |= v << (4 * (lane % 2));
        let mut request = (self.need_swing.max(swing), 0);
        match pattern {
            1 => {
                for l in 0..lanes {
                    put(&mut s, l, u8::from(cr(l)));
                }
            }
            2 | 3 | 7 => {
                request.1 = self.eq_pre;
                for l in 0..lanes {
                    put(&mut s, l, if eq_ok { 7 } else { u8::from(cr(l)) });
                }
                if eq_ok {
                    s[2] |= 1;
                    if hop == 0 {
                        self.trained = true;
                    }
                }
            }
            _ if hop == 0 && self.trained && !self.lost => {
                for l in 0..lanes {
                    put(&mut s, l, 7);
                }
                s[2] |= 1;
                if let Some((ps, pp)) = self.post_req {
                    request = (ps, pp);
                    if set & 0x1b != ps | pp << 3 {
                        s[2] |= 2;
                    }
                }
            }
            _ => {}
        }
        let nib = request.0 | request.1 << 2;
        s[4] = nib | nib << 4;
        s[5] = nib | nib << 4;
        s
    }
    fn byte(&mut self, at: u32) -> Result<u8, Error> {
        Ok(match at {
            0x000..=0x00f => self.caps[at as usize],
            0x2200..=0x220f => self.ext.ok_or(Error::Aux)?[(at - 0x2200) as usize],
            0x2210 => self.feature,
            0xf0000..=0xf0009 => self.lttpr.ok_or(Error::Aux)?[(at - 0xf0000) as usize],
            0x200 | 0x2002 => 1,
            0x201 | 0x2003 => self.irq_vector,
            0x202..=0x207 => self.status(0)[(at - 0x202) as usize],
            0x200c..=0x200e => self.status(0)[(at - 0x200c) as usize],
            0x600 => *self.regs.get(&0x600).unwrap_or(&1),
            a if (0xf0020..0xf0020 + 0x50 * 8).contains(&a) && (a - 0xf0020) % 0x50 == 0 => {
                self.intervals[((a - 0xf0020) / 0x50) as usize]
            }
            a if (0xf0030..0xf0030 + 0x50 * 8).contains(&a) && (a - 0xf0030) % 0x50 < 6 => {
                let hop = ((a - 0xf0030) / 0x50) as u8 + 1;
                let s = self.status(hop);
                [s[0], s[1], s[2], s[4], s[5], 0][((a - 0xf0030) % 0x50) as usize]
            }
            _ => 0,
        })
    }
}
impl crate::amdgpu_dcn30_dp::Aux for Sink {
    async fn read(&mut self, address: u32, data: &mut [u8]) -> Result<(), Error> {
        self.log.lock().push(Ev::Read(address, data.len()));
        if self.gone {
            return Err(Error::Aux);
        }
        for (i, b) in data.iter_mut().enumerate() {
            *b = self.byte(address + i as u32)?;
        }
        Ok(())
    }
    async fn write(&mut self, address: u32, data: &[u8]) -> Result<(), Error> {
        self.log.lock().push(Ev::Write(address, data.to_vec()));
        if self.gone {
            return Err(Error::Aux);
        }
        if address == 0x100 {
            self.trained = false;
        }
        for (i, &b) in data.iter().enumerate() {
            self.regs.insert(address + i as u32, b);
        }
        Ok(())
    }
    async fn set_timeout_us(&mut self, us: u32) -> Result<(), Error> {
        self.log.lock().push(Ev::Timeout(us));
        Ok(())
    }
    async fn connected(&mut self) -> bool {
        self.connected
    }
    async fn delay_us(&mut self, us: u64) {
        self.log.lock().push(Ev::Delay(us));
    }
}

/// The DIO source, logged in the same order as the AUX traffic.
struct Src(Log);
impl Source for Src {
    fn enable(&mut self, link: DpLink) -> Result<(), Error> {
        self.0.lock().push(Ev::Enable(link));
        Ok(())
    }
    fn pattern(&mut self, tps: Tps) -> Result<(), Error> {
        self.0.lock().push(Ev::Pattern(tps));
        Ok(())
    }
    fn video(&mut self) -> Result<(), Error> {
        self.0.lock().push(Ev::Video);
        Ok(())
    }
    fn drive(&mut self, _: DpLink, swing: u8, pre: u8) -> Result<(), Error> {
        self.0.lock().push(Ev::Drive(swing, pre));
        Ok(())
    }
    fn disable(&mut self) -> Result<(), Error> {
        self.0.lock().push(Ev::Disable);
        Ok(())
    }
}

fn bench() -> (Log, Sink, Src) {
    let log: Log = Arc::new(IrqSafeSpinLock::new(Vec::new()));
    (log.clone(), Sink::new(log.clone()), Src(log))
}
fn run<T>(f: impl core::future::Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}
fn writes(log: &Log, at: u32) -> Vec<Vec<u8>> {
    log.lock()
        .iter()
        .filter_map(|e| match e {
            Ev::Write(a, d) if *a == at => Some(d.clone()),
            _ => None,
        })
        .collect()
}
fn position(log: &[Ev], from: usize, pred: impl Fn(&Ev) -> bool) -> Option<usize> {
    log[from..].iter().position(pred).map(|i| i + from)
}
fn link(rate: u8, lanes: u8) -> DpLink {
    DpLink { rate, lanes }
}

fn navi22_dp_caps_follow_retrieve_link_cap_and_lttpr_policy() -> TestResult {
    // Not VBIOS-aware: no LTTPR read at all, wake-up read, default timeout.
    let (log, mut sink, _) = bench();
    sink.lttpr = Some([0x14, HBR, 0x80, 0x55, 2, 0, 0, 0, 0, 0]);
    let caps = run(retrieve_caps(&mut sink, VbiosLttpr::default())).unwrap();
    {
        let l = log.lock();
        if l.iter().any(|e| matches!(e, Ev::Read(0xf0000, _)))
            || caps.lttpr.is_some()
            || caps.mode != LttprMode::NonLttpr
            || l.first() != Some(&Ev::Timeout(AUX_TIMEOUT_LTTPR_US))
            || !l.contains(&Ev::Read(0x600, 1))
            || !l.contains(&Ev::Timeout(AUX_TIMEOUT_DEFAULT_US))
        {
            return TestResult::Fail("non-aware VBIOS probed LTTPR or kept the LTTPR timeout");
        }
    }
    // Aware, transparent: mode 0x55 and the echoed count, LTTPR timeout kept,
    // and a DPCD 1.4 chain bounds the link (rate and lanes).
    for (enable, mode) in [
        (false, LttprMode::Transparent),
        (true, LttprMode::NonTransparent),
    ] {
        let (log, mut sink, _) = bench();
        sink.lttpr = Some([0x14, HBR, 0x80, 0, 2, 0, 0, 0, 0, 0]);
        let vbios = VbiosLttpr {
            aware: true,
            enable,
        };
        let caps = run(retrieve_caps(&mut sink, vbios)).unwrap();
        if caps.mode != mode
            || writes(&log, 0xf0003) != [vec![0x55]]
            || writes(&log, 0xf000a) != [vec![0x80]]
            || log.lock().contains(&Ev::Timeout(AUX_TIMEOUT_DEFAULT_US))
            || caps.max_link() != Some(link(HBR, 2))
        {
            return TestResult::Fail("LTTPR mode, echo or chain bound");
        }
    }
    // A repeater block below revision 1.4 does not bound the link.
    let (_, mut sink, _) = bench();
    sink.lttpr = Some([0x13, RBR, 0x80, 0, 1, 0, 0, 0, 0, 0]);
    let vbios = VbiosLttpr {
        aware: true,
        enable: false,
    };
    let caps = run(retrieve_caps(&mut sink, vbios)).unwrap();
    if caps.lttpr.is_none() || caps.max_link() != Some(link(HBR2, 4)) {
        return TestResult::Fail("pre-1.4 LTTPR caps bounded the link");
    }
    // Extended receiver caps replace the base field; the feature list is
    // read only with them; HBR3 is the encoder's ceiling.
    let (log, mut sink, _) = bench();
    sink.caps[0] = 0x12;
    sink.caps[14] = 0x80;
    let mut ext = sink.caps;
    ext[0] = 0x14;
    ext[1] = 0x1e;
    sink.ext = Some(ext);
    sink.feature = 0x0a;
    let caps = run(retrieve_caps(&mut sink, VbiosLttpr::default())).unwrap();
    if caps.rev() != 0x14
        || caps.max_link() != Some(link(HBR3, 4))
        || caps.dprx_feature != 0x0a
        || !log.lock().contains(&Ev::Read(0x2210, 1))
    {
        return TestResult::Fail("extended receiver caps / feature list");
    }
    let (log, mut sink, _) = bench();
    let caps = run(retrieve_caps(&mut sink, VbiosLttpr::default())).unwrap();
    if caps.dprx_feature != 0 || log.lock().contains(&Ev::Read(0x2210, 1)) {
        return TestResult::Fail("feature list read without extended caps");
    }
    // A non-standard MAX_LINK_RATE floors to a standard one; no lanes refuses.
    let mut c = Caps::from_dpcd(sink.caps);
    c.dpcd[1] = 0x0c;
    if c.max_link() != Some(link(HBR, 4)) {
        return TestResult::Fail("get_link_rate_from_max_link_bw");
    }
    let (_, mut sink, _) = bench();
    sink.caps[2] = 0x80;
    if run(retrieve_caps(&mut sink, VbiosLttpr::default())) != Err(Error::NoSink) {
        return TestResult::Fail("zero lanes accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-dp",
    navi22_dp_caps_follow_retrieve_link_cap_and_lttpr_policy
);

/// The EQ pattern follows the sink's TPS3/TPS4 support, never the rate.
fn navi22_dp_eq_pattern_follows_sink_capability() -> TestResult {
    for (byte2, byte3, tps, set) in [
        (0x84, 0x80, Tps::Tps4, 0x07),
        (0xc4, 0x00, Tps::Tps3, 0x23),
        (0x84, 0x00, Tps::Tps2, 0x22),
    ] {
        let (log, mut sink, mut src) = bench();
        sink.caps[1] = RBR;
        sink.caps[2] = byte2;
        sink.caps[3] = byte3;
        let caps = Caps::from_dpcd(sink.caps);
        if caps.eq_pattern() != tps {
            return TestResult::Fail("decide_eq_training_pattern");
        }
        if run(train_with_retries(&mut sink, &mut src, &caps, link(RBR, 4))) != Ok(link(RBR, 4)) {
            return TestResult::Fail("RBR training");
        }
        let eq = writes(&log, 0x102)
            .into_iter()
            .find(|w| w.len() == 5 && w[0] != 0x21);
        if eq.map(|w| w[0]) != Some(set) || !log.lock().contains(&Ev::Pattern(tps)) {
            return TestResult::Fail("EQ pattern at RBR");
        }
        // TPS4 is scrambled: no SCRAMBLING_DISABLE.
        let lanes = writes(&log, 0x101);
        if lanes.first().map(|w| w[0]) != Some(4 | 0x80) {
            return TestResult::Fail("LANE_COUNT_SET enhanced framing");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-dp",
    navi22_dp_eq_pattern_follows_sink_capability
);

/// dpcd_set_link_settings, the CR burst and lane-set rewrites, adjust
/// requests (common maximum, PE capped by VS, max-reached bits), EQ, exit.
fn navi22_dp_training_follows_8b_10b_sequences_and_adjust_requests() -> TestResult {
    let (log, mut sink, mut src) = bench();
    sink.need_swing = 2;
    sink.eq_pre = 1;
    let caps = Caps::from_dpcd(sink.caps);
    if run(train_with_retries(
        &mut sink,
        &mut src,
        &caps,
        link(HBR2, 4),
    )) != Ok(link(HBR2, 4))
    {
        return TestResult::Fail("training failed");
    }
    let l = log.lock().clone();
    let at = |pred: &dyn Fn(&Ev) -> bool, from| position(&l, from, pred);
    let order = (|| {
        let a = at(&|e| *e == Ev::Enable(link(HBR2, 4)), 0)?;
        let a = at(&|e| *e == Ev::Write(0x600, vec![1]), a)?;
        let a = at(&|e| *e == Ev::Write(0x102, vec![0]), a)?;
        let a = at(&|e| *e == Ev::Write(0x108, vec![1]), a)?;
        let a = at(&|e| *e == Ev::Write(0x107, vec![0x10]), a)?;
        let a = at(&|e| *e == Ev::Write(0x101, vec![0x84]), a)?;
        let a = at(&|e| *e == Ev::Write(0x100, vec![HBR2]), a)?;
        let a = at(&|e| *e == Ev::Pattern(Tps::Tps1), a)?;
        let a = at(&|e| *e == Ev::Drive(0, 0), a)?;
        let a = at(&|e| *e == Ev::Write(0x102, vec![0x21, 0, 0, 0, 0]), a)?;
        // The sink asks for swing 2: drive and the lane-set rewrite follow.
        let a = at(&|e| *e == Ev::Drive(2, 0), a)?;
        let a = at(&|e| *e == Ev::Write(0x103, vec![2; 4]), a)?;
        let a = at(&|e| *e == Ev::Pattern(Tps::Tps2), a)?;
        let a = at(&|e| *e == Ev::Write(0x102, vec![0x22, 2, 2, 2, 2]), a)?;
        // EQ requests pre-emphasis 1 on top.
        let a = at(&|e| *e == Ev::Drive(2, 1), a)?;
        let a = at(&|e| *e == Ev::Write(0x103, vec![2 | 1 << 3; 4]), a)?;
        let a = at(&|e| *e == Ev::Write(0x102, vec![0]), a)?;
        let a = at(&|e| *e == Ev::Video, a)?;
        // No POST_LT_ADJ_REQ: 5 ms of idle, then the link-loss check.
        let a = at(&|e| *e == Ev::Delay(5000), a)?;
        at(&|e| *e == Ev::Read(0x200, 6), a)
    })();
    if order.is_none() {
        return TestResult::Fail("8b/10b training order");
    }
    // The CR interval: DPCD 1.2 with TRAINING_AUX_RD_INTERVAL 0 is 100 us,
    // EQ 400 us; a nonzero interval is 4 ms units for both.
    if !l.contains(&Ev::Delay(100)) || !l.contains(&Ev::Delay(400)) {
        return TestResult::Fail("default read intervals");
    }
    // Lane-set encoding: max-swing at VS3, max-pre only at PE3.
    let lt = |swing, pre| Training {
        link: link(HBR2, 4),
        mode: LttprMode::NonLttpr,
        repeaters: 0,
        eq: Tps::Tps2,
        cr_us: 0,
        eq_us: 0,
        intervals: [0; 8],
        post_lt_adj_granted: false,
        swing,
        pre,
    };
    if lt(3, 0).lane_set() != 0x07 || lt(1, 2).lane_set() != 0x11 || lt(0, 3).lane_set() != 0x38 {
        return TestResult::Fail("dp_hw_to_dpcd_lane_settings");
    }
    // The highest request across lanes, PE capped by VS.
    let mut t = lt(0, 0);
    decide_lane_settings(&mut t, &[0, 0, 0, 0, 0x0e | 0x10, 0x01 << 4]);
    if (t.swing, t.pre) != (2, 1) {
        return TestResult::Fail("maximize_lane_settings");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-dp",
    navi22_dp_training_follows_8b_10b_sequences_and_adjust_requests
);

/// POST_LT_ADJ_REQ: granted below TPS4 for a capable sink, honoured after
/// training, then LANE_COUNT_SET without the grant; never with TPS4.
fn navi22_dp_post_lt_adjust_request_is_honoured() -> TestResult {
    let (log, mut sink, mut src) = bench();
    sink.caps[2] = 0x80 | 0x40 | 0x20 | 4;
    sink.post_req = Some((1, 1));
    let caps = Caps::from_dpcd(sink.caps);
    if run(train_with_retries(&mut sink, &mut src, &caps, link(HBR, 4))) != Ok(link(HBR, 4)) {
        return TestResult::Fail("training failed");
    }
    let l = log.lock().clone();
    let lanes = writes(&log, 0x101);
    let video = position(&l, 0, |e| *e == Ev::Video);
    let redrive = video.and_then(|v| position(&l, v, |e| *e == Ev::Drive(1, 1)));
    let rewrite = redrive.and_then(|r| position(&l, r, |e| *e == Ev::Write(0x103, vec![0x09; 4])));
    if lanes != [vec![0xa4], vec![0x84]] || rewrite.is_none() {
        return TestResult::Fail("post-LT adjust sequence");
    }
    if l[video.unwrap()..].contains(&Ev::Delay(5000)) {
        return TestResult::Fail("post-LT path also waited for link loss");
    }
    // TPS4: no grant, the 5 ms check instead.
    let (log, mut sink, mut src) = bench();
    sink.caps[2] = 0x80 | 0x20 | 4;
    sink.caps[3] = 0x80;
    let caps = Caps::from_dpcd(sink.caps);
    run(train_with_retries(&mut sink, &mut src, &caps, link(HBR, 4))).unwrap();
    if writes(&log, 0x101) != [vec![0x84]] || !log.lock().contains(&Ev::Delay(5000)) {
        return TestResult::Fail("TPS4 granted POST_LT_ADJ_REQ");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-dp",
    navi22_dp_post_lt_adjust_request_is_honoured
);

/// Non-transparent LTTPRs: farthest repeater first (from the source: the
/// highest id), each told training is done, TPS4 at its own interval, the
/// source drive changed only for the hop next to it; then the sink.
fn navi22_dp_non_transparent_repeaters_train_hop_by_hop() -> TestResult {
    let (log, mut sink, mut src) = bench();
    sink.lttpr = Some([0x14, HBR2, 0x40, 0, 4, 0, 0, 0, 0, 0]);
    sink.intervals = [1, 2, 0, 0, 0, 0, 0, 0];
    sink.need_swing = 1;
    let vbios = VbiosLttpr {
        aware: true,
        enable: true,
    };
    let caps = run(retrieve_caps(&mut sink, vbios)).unwrap();
    if caps.mode != LttprMode::NonTransparent || caps.lttpr.map(|r| r.count) != Some(2) {
        return TestResult::Fail("two-repeater chain");
    }
    log.lock().clear();
    if run(train_with_retries(
        &mut sink,
        &mut src,
        &caps,
        link(HBR2, 4),
    )) != Ok(link(HBR2, 4))
    {
        return TestResult::Fail("training failed");
    }
    let l = log.lock().clone();
    let at = |pred: &dyn Fn(&Ev) -> bool, from| position(&l, from, pred);
    let r2 = 0xf0010 + 0x50;
    let order = (|| {
        let a = at(&|e| *e == Ev::Write(0xf0003, vec![0x55]), 0)?;
        let a = at(&|e| *e == Ev::Write(0xf0003, vec![0xaa]), a)?;
        let a = at(&|e| *e == Ev::Read(0xf0070, 1), a)?;
        let a = at(&|e| *e == Ev::Read(0xf0020, 1), a)?;
        // Repeater 2 (next to the source): TPS1, its drive request honoured.
        let a = at(&|e| *e == Ev::Write(r2, vec![0x21, 0, 0, 0, 0]), a)?;
        let a = at(&|e| *e == Ev::Drive(1, 0), a)?;
        let a = at(&|e| *e == Ev::Write(r2, vec![0x07, 1, 1, 1, 1]), a)?;
        // Its EQ interval (8 ms).
        let a = at(&|e| *e == Ev::Delay(8000), a)?;
        let a = at(&|e| *e == Ev::Write(r2, vec![0]), a)?;
        // Repeater 1, lane settings back at level 0, then TPS4 at 4 ms.
        let a = at(&|e| *e == Ev::Write(0xf0010, vec![0x21, 0, 0, 0, 0]), a)?;
        let a = at(&|e| *e == Ev::Write(0xf0010, vec![0x07, 1, 1, 1, 1]), a)?;
        let a = at(&|e| *e == Ev::Delay(4000), a)?;
        let a = at(&|e| *e == Ev::Write(0xf0010, vec![0]), a)?;
        let a = at(&|e| *e == Ev::Write(0x102, vec![0x21, 0, 0, 0, 0]), a)?;
        at(&|e| *e == Ev::Write(0x102, vec![0]), a)
    })();
    if order.is_none() {
        return TestResult::Fail("hop-by-hop order");
    }
    // The source drive changed only while repeater 2 trained.
    let r1 = position(&l, 0, |e| *e == Ev::Write(0xf0010, vec![0x21, 0, 0, 0, 0])).unwrap();
    if l[r1..]
        .iter()
        .any(|e| matches!(e, Ev::Drive(s, _) if *s != 0))
    {
        return TestResult::Fail("source drive changed for a far hop");
    }
    // Transparent mode: one 0x55, the sink trained directly.
    let (log, mut sink, mut src) = bench();
    sink.lttpr = Some([0x14, HBR2, 0x80, 0, 4, 0, 0, 0, 0, 0]);
    let vbios = VbiosLttpr {
        aware: true,
        enable: false,
    };
    let caps = run(retrieve_caps(&mut sink, vbios)).unwrap();
    log.lock().clear();
    run(train_with_retries(
        &mut sink,
        &mut src,
        &caps,
        link(HBR2, 4),
    ))
    .unwrap();
    if writes(&log, 0xf0003) != [vec![0x55]] || !writes(&log, 0xf0010).is_empty() {
        return TestResult::Fail("transparent LTTPR mode");
    }
    // DPCD 1.1 behind an LTTPR: the mandatory 16 ms interval.
    let mut c = caps;
    c.dpcd[0] = 0x11;
    let (_, mut sink, _) = bench();
    let t = run(decide_training(&mut sink, &c, link(HBR2, 4)));
    if (t.cr_us, t.eq_us) != (16000, 16000) {
        return TestResult::Fail("default LTTPR read interval");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-dp",
    navi22_dp_non_transparent_repeaters_train_hop_by_hop
);

/// decide_fallback_link_setting: CR failures drop the rate first, EQ
/// failures the lanes first (then the rate, lowering the maximum).
fn navi22_dp_fallback_follows_decide_fallback_link_setting() -> TestResult {
    let step = |max: DpLink, cur: DpLink, o| {
        let (mut m, mut c) = (max, cur);
        decide_fallback(&mut m, &mut c, o).then_some((m, c))
    };
    let max = link(HBR2, 4);
    let cases = [
        (max, Outcome::CrFailLane0, Some((max, link(HBR, 4)))),
        (
            link(RBR, 4),
            Outcome::CrFailLane1,
            Some((max, link(HBR2, 1))),
        ),
        (
            link(RBR, 4),
            Outcome::CrFailLane23,
            Some((max, link(HBR2, 2))),
        ),
        (link(RBR, 4), Outcome::CrFailLane0, None),
        (link(RBR, 1), Outcome::CrFailLane0, None),
        (max, Outcome::EqFailEq, Some((max, link(HBR2, 2)))),
        (
            link(HBR2, 1),
            Outcome::EqFailEq,
            Some((link(HBR, 4), link(HBR, 4))),
        ),
        (max, Outcome::EqFailCrPartial, Some((max, link(HBR2, 2)))),
        (
            link(HBR2, 2),
            Outcome::EqFailCr,
            Some((link(HBR, 4), link(HBR, 4))),
        ),
        (link(RBR, 1), Outcome::EqFailEq, None),
        (max, Outcome::LinkLoss, None),
    ];
    for (cur, outcome, want) in cases {
        if step(max, cur, outcome) != want {
            return TestResult::Fail("fallback step");
        }
    }
    // Verification: EQ fails at HBR2 x4 → HBR2 x2 trains (lanes first).
    let (log, mut sink, mut src) = bench();
    sink.eq_bad = vec![(HBR2, 4)];
    let caps = Caps::from_dpcd(sink.caps);
    let v = run(verify_link_cap(&mut sink, &mut src, &caps)).unwrap();
    if v.link != link(HBR2, 2) || v.clean {
        return TestResult::Fail("EQ fallback verification");
    }
    let enables: Vec<_> = log
        .lock()
        .iter()
        .filter_map(|e| match e {
            Ev::Enable(l) => Some(*l),
            _ => None,
        })
        .collect();
    // Two verification rounds (the first had a failure): each EQ-fails
    // x4, then trains x2; every attempt disables the link afterwards.
    if enables != [link(HBR2, 4), link(HBR2, 2), link(HBR2, 4), link(HBR2, 2)]
        || log.lock().iter().filter(|e| **e == Ev::Disable).count() != 4
    {
        return TestResult::Fail("verification attempts");
    }
    // CR fails at HBR2 → HBR x4 (rate first).
    let (_, mut sink, mut src) = bench();
    sink.cr_bad_rates = vec![HBR2];
    let caps = Caps::from_dpcd(sink.caps);
    let v = run(verify_link_cap(&mut sink, &mut src, &caps)).unwrap();
    if v.link != link(HBR, 4) {
        return TestResult::Fail("CR fallback verification");
    }
    // A clean sink verifies at its maximum in one pass.
    let (_, mut sink, mut src) = bench();
    let caps = Caps::from_dpcd(sink.caps);
    let v = run(verify_link_cap(&mut sink, &mut src, &caps)).unwrap();
    if v != (Verified {
        link: link(HBR2, 4),
        clean: true,
        failures: 0,
    }) {
        return TestResult::Fail("clean verification");
    }
    // Nothing trains: the fail-safe link.
    let (_, mut sink, mut src) = bench();
    sink.cr_bad_rates = vec![RBR, HBR, HBR2];
    let v = run(verify_link_cap(&mut sink, &mut src, &caps)).unwrap();
    if v.link != FAIL_SAFE || v.clean {
        return TestResult::Fail("fail-safe link");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-dp",
    navi22_dp_fallback_follows_decide_fallback_link_setting
);

/// A commit trains its own setting four times, PHY off between attempts
/// (D3 first), the delay growing by 50 ms; the last failure keeps it on.
fn navi22_dp_commit_retries_without_fallback() -> TestResult {
    let (log, mut sink, mut src) = bench();
    sink.eq_bad = vec![(HBR, 2)];
    let caps = Caps::from_dpcd(sink.caps);
    let result = run(train_with_retries(&mut sink, &mut src, &caps, link(HBR, 2)));
    if result != Err(Error::Training(Lt::Equalization)) {
        return TestResult::Fail("EQ failure result");
    }
    let l = log.lock().clone();
    let enables = l.iter().filter(|e| **e == Ev::Enable(link(HBR, 2))).count();
    let disables = l.iter().filter(|e| **e == Ev::Disable).count();
    let delays: Vec<_> = l
        .iter()
        .filter_map(|e| match e {
            Ev::Delay(us) if *us >= 50_000 => Some(*us),
            _ => None,
        })
        .collect();
    if enables != 4 || disables != 3 || delays != [100_000, 150_000, 200_000] {
        return TestResult::Fail("retry count, disables or delays");
    }
    if writes(&log, 0x600).iter().filter(|w| **w == [2]).count() != 3 {
        return TestResult::Fail("D3 before each disable");
    }
    // A sink that disappears aborts at once: source off, no D3.
    let (log, mut sink, mut src) = bench();
    sink.gone = true;
    sink.connected = false;
    let caps = Caps::from_dpcd(sink.caps);
    if run(train_with_retries(&mut sink, &mut src, &caps, link(HBR, 2))) != Err(Error::Aux) {
        return TestResult::Fail("transport failure not an abort");
    }
    let l = log.lock().clone();
    if l.iter().filter(|e| **e == Ev::Disable).count() != 1
        || l.iter()
            .any(|e| matches!(e, Ev::Write(0x600, d) if d == &[2]))
    {
        return TestResult::Fail("abort cleanup");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-dp",
    navi22_dp_commit_retries_without_fallback
);

/// decide_dp_link_settings (lanes first) and dp_validate_mode_timing.
fn navi22_dp_stream_link_is_the_least_that_carries_it() -> TestResult {
    let v = link(HBR2, 4);
    let cases = [
        (148_500, Some(link(RBR, 4))),
        (25_175, Some(link(RBR, 1))),
        (297_000, Some(link(HBR, 4))),
        (594_000, Some(link(HBR2, 4))),
        (800_000, None),
    ];
    for (pixel, want) in cases {
        if decide_link_settings(v, pixel, 24) != want {
            return TestResult::Fail("decide_dp_link_settings");
        }
    }
    if decide_link_settings(link(HBR, 2), 148_500, 24) != Some(link(HBR, 2))
        || decide_link_settings(link(HBR, 2), 297_000, 24).is_some()
    {
        return TestResult::Fail("bounded by the verified link");
    }
    if !mode_fits(FAIL_SAFE, 640, 480, 25_175, 24)
        || mode_fits(FAIL_SAFE, 1920, 1080, 148_500, 24)
        || !mode_fits(link(HBR, 4), 1920, 1080, 148_500, 24)
        || mode_fits(link(HBR, 4), 3840, 2160, 594_000, 24)
    {
        return TestResult::Fail("dp_validate_mode_timing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-dp",
    navi22_dp_stream_link_is_the_least_that_carries_it
);

/// HPD-RX: link loss needs D0; DPCD 1.4 reads the ESI block; an automated
/// test is acknowledged; no link, no loss.
fn navi22_dp_short_pulse_parses_link_loss() -> TestResult {
    for rev in [0x12, 0x14] {
        let (log, mut sink, mut src) = bench();
        sink.caps[0] = rev;
        let caps = Caps::from_dpcd(sink.caps);
        run(train_with_retries(
            &mut sink,
            &mut src,
            &caps,
            link(HBR2, 4),
        ))
        .unwrap();
        if run(handle_hpd_rx_irq(&mut sink, rev, 4)) != Ok(RxEvent::None) {
            return TestResult::Fail("healthy link reported lost");
        }
        sink.lost = true;
        match run(handle_hpd_rx_irq(&mut sink, rev, 4)) {
            Ok(RxEvent::LinkLoss(_)) => {}
            _ => return TestResult::Fail("link loss missed"),
        }
        let block = if rev < 0x14 { (0x200, 6) } else { (0x2002, 14) };
        if !log.lock().contains(&Ev::Read(block.0, block.1)) {
            return TestResult::Fail("HPD-RX IRQ data block");
        }
        // A sink in D3 is not a link loss.
        sink.regs.insert(0x600, 2);
        if run(handle_hpd_rx_irq(&mut sink, rev, 4)) != Ok(RxEvent::None) {
            return TestResult::Fail("D3 sink retrained");
        }
        if run(handle_hpd_rx_irq(&mut sink, rev, 0)) != Ok(RxEvent::None) {
            return TestResult::Fail("loss without a link");
        }
        sink.irq_vector = 0x02;
        if run(handle_hpd_rx_irq(&mut sink, rev, 4)) != Ok(RxEvent::AutomatedTest)
            || writes(&log, 0x201) != [vec![0x02]]
        {
            return TestResult::Fail("automated test request");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-dp",
    navi22_dp_short_pulse_parses_link_loss
);
