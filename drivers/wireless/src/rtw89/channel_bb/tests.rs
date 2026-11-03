use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
struct Model {
    bytes: Vec<u8>,
    hash: u64,
    count: u32,
    operations: usize,
    fail: Option<usize>,
    denied: bool,
    ignore: bool,
    gone: bool,
    pending: bool,
    now: u64,
}
impl Model {
    fn new(seed: u8, rx: u8) -> Self {
        let mut result = Self {
            bytes: vec![seed; 0x20000],
            hash: 14695981039346656037,
            count: 0,
            operations: 0,
            fail: None,
            denied: false,
            ignore: false,
            gone: false,
            pending: false,
            now: 0,
        };
        let a = (0x10000 + R_CHBW_MOD_V1) as usize;
        let old = u32::from_le_bytes(result.bytes[a..a + 4].try_into().unwrap());
        result.bytes[a..a + 4].copy_from_slice(
            &((old & !B_ANT_RX_SEG0) | bits(B_ANT_RX_SEG0, i32::from(rx))).to_le_bytes(),
        );
        result
    }
    fn access(&mut self) -> Result<(), power::Error> {
        let n = self.operations;
        self.operations += 1;
        if self.fail == Some(n) {
            Err(power::Error::Access)
        } else {
            Ok(())
        }
    }
    fn record(&mut self, words: [u32; 3]) {
        self.count += 1;
        for word in words {
            for byte in word.to_le_bytes() {
                self.hash ^= u64::from(byte);
                self.hash = self.hash.wrapping_mul(1099511628211);
            }
        }
    }
}
impl Io for Model {
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        self.access()?;
        Ok(self.bytes[a as usize])
    }
    fn read16(&mut self, _: u32) -> Result<u16, power::Error> {
        Err(power::Error::Access)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.access()?;
        if self.gone {
            return Ok(u32::MAX);
        }
        Ok(u32::from_le_bytes(
            self.bytes[a as usize..a as usize + 4].try_into().unwrap(),
        ))
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), power::Error> {
        self.access()?;
        if !self.ignore {
            self.bytes[a as usize] = v;
        }
        self.record([1, a, u32::from(v)]);
        Ok(())
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.access()?;
        if !self.ignore {
            self.bytes[a as usize..a as usize + 4].copy_from_slice(&v.to_le_bytes());
        }
        self.record([4, a, v]);
        Ok(())
    }
    fn now_us(&self) -> u64 {
        self.now
    }
    async fn delay_us(&mut self, u: u64) {
        if self.pending {
            core::future::pending::<()>().await;
        }
        self.now += u;
        self.record([8, u as u32, 0]);
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl Interface for Model {
    fn admit(&mut self) -> Result<(), Error> {
        if self.denied {
            Err(Error::Policy)
        } else {
            Ok(())
        }
    }
}
fn inputs(flags: u8) -> (Gain, Calibration) {
    let mut g = Gain::default();
    let mut c = Calibration {
        thermal: [0; 2],
        tssi_cck: [[0; 6]; 2],
        tssi_mcs: [[0; 19]; 2],
        tssi_trim: [[0; 8]; 2],
        trim_programmed: false,
        thermal_trim: [0; 2],
        thermal_programmed: false,
        pa_bias: [0; 2],
        pa_programmed: false,
        gain_offset: [[0; 5]; 2],
        offset_valid: flags & 2 != 0,
        gain_comp: [[0; 5]; 2],
        comp_valid: flags & 1 != 0,
    };
    for p in 0..2 {
        for i in 0..7 {
            g.lna[0][p][i] = (if p != 0 { 13 } else { -9 }) - i as i8 * 5;
        }
        for i in 0..2 {
            g.tia[0][p][i] = (if p != 0 { 35 } else { -42 }) + i as i8;
        }
        g.rpl20[0][p] = -7 + p as i8;
        for i in 0..9 {
            g.rpl40[0][p][i] = (if p != 0 { 5 } else { -6 }) + i as i8 * 3;
        }
        for i in 0..13 {
            g.rpl80[0][p][i] = (if p != 0 { -1 } else { 2 }) - i as i8 * 4;
        }
        c.gain_offset[p][0] = if p != 0 { 7 } else { -8 };
        c.gain_offset[p][1] = if p != 0 { -7 } else { 6 };
        c.gain_comp[p][0] = if p != 0 { 7 } else { -8 };
    }
    (g, c)
}
fn ready<T>(f: impl Future<Output = T>) -> Option<T> {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}
fn smoke_rtw89_b_channel_bb_signed_gain_and_rpl_match_frozen_references() -> TestResult {
    for &(seed, rx, flags, count, hash) in CASES {
        let mut io = Model::new(seed, rx);
        let mut owner = Channel::default();
        let (g, c) = inputs(flags);
        // SAFETY: exact inert B MAC/BB word model and explicit private factory/gain inputs.
        let r = ready(unsafe { owner.prepare(&mut io, &g, &c, [-91, 101]) });
        if r != Some(Ok(()))
            || owner.state() != State::Configured
            || io.count != count
            || io.hash != hash
        {
            return TestResult::Fail(
                "B channel1 MAC/BB signed gains differ from the frozen reference",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_channel_bb_signed_gain_and_rpl_match_frozen_references
);
fn smoke_rtw89_b_channel_bb_error_cancel_and_readback_keep_attempt_terminal() -> TestResult {
    let (g, c) = inputs(3);
    let mut baseline = Model::new(0xa5, 3);
    let mut owner = Channel::default();
    // SAFETY: complete inert baseline only, no native owner or active transmitter.
    if ready(unsafe { owner.prepare(&mut baseline, &g, &c, [-91, 101]) }) != Some(Ok(())) {
        return TestResult::Fail("BB channel baseline");
    }
    for fail in 0..baseline.operations {
        let mut io = Model::new(0xa5, 3);
        io.fail = Some(fail);
        let mut owner = Channel::default();
        // SAFETY: inject each actual MMIO access error into exclusively owned words.
        let result = ready(unsafe { owner.prepare(&mut io, &g, &c, [-91, 101]) });
        if !matches!(result, Some(Err(_))) || owner.state() != State::Preparing {
            return TestResult::Fail("partial BB channel produced readiness");
        }
        let n = io.operations;
        // SAFETY: failed owner must refuse all replay before touching the model.
        if ready(unsafe { owner.prepare(&mut io, &g, &c, [-91, 101]) })
            != Some(Err(Error::Terminal))
            || io.operations != n
        {
            return TestResult::Fail("BB channel attempt replayed");
        }
    }
    for variant in 0..4 {
        let mut io = Model::new(0xa5, 3);
        let mut owner = Channel::default();
        match variant {
            0 => io.pending = true,
            1 => io.ignore = true,
            2 => io.denied = true,
            _ => io.gone = true,
        }
        // SAFETY: every variant must prevent a complete real readback/qualified attempt.
        let r = ready(unsafe { owner.prepare(&mut io, &g, &c, [-91, 101]) });
        if (variant == 0 && r.is_some())
            || (variant != 0 && !matches!(r, Some(Err(_))))
            || owner.state() != State::Preparing
        {
            return TestResult::Fail("cancelled/ignored/denied BB channel became ready");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_channel_bb_error_cancel_and_readback_keep_attempt_terminal
);
fn field(io: &Model, address: u32, mask: u32) -> u32 {
    let a = (0x10000 + address) as usize;
    (u32::from_le_bytes(io.bytes[a..a + 4].try_into().unwrap()) & mask) >> mask.trailing_zeros()
}
/// Linux rtw8852b_common.c `__rtw8852bx_set_channel_bb` for each typed primary:
/// `rtw8852bx_ctrl_sco_cck`, `rtw8852bx_sco_mapping`, CCK TXFIR and
/// `rtw89_encode_chan_idx` (2.4GHz base0 | primary), with critical readback.
fn smoke_rtw89_b_channel_bb_programs_and_reads_back_each_actual_primary() -> TestResult {
    use narf_wireless::association::channel::Band;
    const SCO: [(u8, u32, u32, u32); 6] = [
        (1, 0x1cfea, 0x27de3, 109),
        (2, 0x1d0e1, 0x27f35, 108),
        (6, 0x1d4b9, 0x2847f, 108),
        (7, 0x1d5b0, 0x285d2, 107),
        (11, 0x1d988, 0x28b1c, 106),
        (13, 0x1db75, 0x28dc1, 106),
    ];
    let (g, c) = inputs(3);
    let mut initial = Model::new(0xa5, 3);
    let mut owner = Channel::default();
    // SAFETY: inert exact channel1 baseline for the shared source order.
    if ready(unsafe { owner.prepare(&mut initial, &g, &c, [-91, 101]) }) != Some(Ok(())) {
        return TestResult::Fail("BB channel1 baseline");
    }
    for primary in 1..=13u8 {
        let Some(profile) = Profile::new(Band::Ghz2, primary) else {
            return TestResult::Fail("typed2.4GHz primary refused");
        };
        let mut io = Model::new(0xa5, 3);
        let mut owner = Channel::default();
        // SAFETY: inert exclusively owned MAC/BB words; no native caller or grant.
        let r = ready(unsafe { owner.prepare_for_channel(&mut io, &g, &c, [-91, 101], profile) });
        if r != Some(Ok(())) || owner.state() != State::Configured {
            return TestResult::Fail("noninitial primary failed BB programming/readback");
        }
        if field(&io, R_MAC_PIN_SEL, B_CH_IDX_SEG0) != u32::from(primary)
            || field(&io, R_TXFIR0, B_TXFIR_C01) != 0x3d23ff
            || io.count != initial.count
            || (primary == 1) != (io.hash == initial.hash)
        {
            return TestResult::Fail("BB channel index/FIR/write stream differs from source");
        }
        if let Some(&(_, barker, cck, comp)) = SCO.iter().find(|row| row.0 == primary) {
            if field(&io, R_RXSCOBC, B_RXSCOBC_TH) != barker
                || field(&io, R_RXSCOCCK, B_RXSCOCCK_TH) != cck
                || field(&io, R_FC0_BW_V1, B_FC0_BW_INV) != comp
            {
                return TestResult::Fail("BB SCO thresholds/compensation differ from Linux");
            }
        }
        // A model that drops writes must never satisfy the primary readback.
        let mut io = Model::new(0xa5, 3);
        io.ignore = true;
        let mut owner = Channel::default();
        // SAFETY: inert model that ignores writes; readback must refuse readiness.
        let r = ready(unsafe { owner.prepare_for_channel(&mut io, &g, &c, [-91, 101], profile) });
        if !matches!(r, Some(Err(_))) || owner.state() != State::Preparing {
            return TestResult::Fail("ignored primary programming became ready");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_channel_bb_programs_and_reads_back_each_actual_primary
);
