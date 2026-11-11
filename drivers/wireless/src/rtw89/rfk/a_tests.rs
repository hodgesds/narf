use super::super::power::Io;
use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

/// Private RTL8852A MAC/BB/RF register model: ADDCK/DACK done bits read as
/// set unless `stuck` (BB offset, or 0x100000 + RF).
struct Model {
    words: Vec<u32>,
    rf: [Vec<u32>; 2],
    trace: Vec<(u8, u32, u32)>,
    now: u64,
    stuck: Option<u32>,
}
impl Model {
    fn new() -> Self {
        Self {
            words: vec![0; 0x20000 / 4],
            rf: core::array::from_fn(|_| vec![0; 0x100]),
            trace: Vec::new(),
            now: 0,
            stuck: None,
        }
    }
    fn word(&self, address: u32) -> u32 {
        self.words[(0x10000 + address) as usize / 4]
    }
}
impl Io for Model {
    fn read8(&mut self, _: u32) -> Result<u8, power::Error> {
        Err(power::Error::Access)
    }
    fn read16(&mut self, _: u32) -> Result<u16, power::Error> {
        Err(power::Error::Access)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        let mut v = self.words[a as usize / 4];
        if a < 0x10000 {
            return Ok(v);
        }
        let r = a - 0x10000;
        match r {
            // ADDCK done BIT(0); Q [19:10] = 0x2ab, I [9:0] = 0x155.
            0x1e00 | 0x3e00 => v = (0x2ab << 10) | 0x155,
            // DACK MSBK done BIT(15).
            0x5e28 | 0x5e78 | 0x7e28 | 0x7e78 => v |= 1 << 15,
            // DACK DADCK done BIT(17) plus the K field the backup reads:
            // I = 0x89 - 8 = 0x81, Q = 0x8a - 8 = 0x82.
            0x5e48 | 0x7e48 => v = (0x89 << 8) | (1 << 17),
            0x5e98 | 0x7e98 => v = (0x8a << 8) | (1 << 17),
            // DACK MSBK streams follow the AR selector in DACKI/DACKQ:
            // I = 0x5c + i, Q = 0x80 + i.
            0x5e44 => v = (0x5c + ((self.word(0x5e00) >> 28) & 0xf)) << 8,
            0x5e94 => v = (0x80 + ((self.word(0x5e50) >> 28) & 0xf)) << 8,
            0x7e44 => v = (0x5c + ((self.word(0x7e00) >> 28) & 0xf)) << 8,
            0x7e94 => v = (0x80 + ((self.word(0x7e50) >> 28) & 0xf)) << 8,
            // DACK bias K [21:12]: I = 0x48, Q = 0x6c.
            0x5e30 | 0x7e30 => v = 0x48 << 12,
            0x5e80 | 0x7e80 => v = 0x6c << 12,
            _ => {}
        }
        if self.stuck == Some(r) {
            v = 0;
        }
        Ok(v)
    }
    fn write8(&mut self, _: u32, _: u8) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.words[a as usize / 4] = v;
        self.trace.push((4, a, v));
        Ok(())
    }
    fn now_us(&self) -> u64 {
        self.now
    }
    async fn delay_us(&mut self, us: u64) {
        self.now += us;
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl Interface for Model {
    fn admit(&mut self) -> Result<(), Error> {
        Ok(())
    }
    async fn rf_read(&mut self, path: u8, address: u32, mask: u32) -> Result<u32, Error> {
        let mut value = self.rf[usize::from(path)][(address & 0xff) as usize];
        match address {
            0x1c => value |= 8,
            0x1b if value == 0x240 => value |= 0x4800,
            _ => {}
        }
        if self.stuck == Some(0x100000 + address) {
            value = 0;
        }
        Ok((value & mask) >> mask.trailing_zeros())
    }
    async fn rf_write(
        &mut self,
        path: u8,
        address: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), Error> {
        let slot = &mut self.rf[usize::from(path)][(address & 0xff) as usize];
        *slot = (*slot & !mask) | ((value << mask.trailing_zeros()) & mask);
        self.trace.push((16 + path, address, value));
        Ok(())
    }
    async fn begin(&mut self, kind: Kind) -> Result<(), Error> {
        self.trace.push((48, kind as u32, 0));
        Ok(())
    }
    async fn end(&mut self, kind: Kind) -> Result<(), Error> {
        self.trace.push((48, kind as u32, 1));
        Ok(())
    }
    async fn pause(&mut self) -> Result<u32, Error> {
        self.trace.push((56, 0, 0));
        Ok(0)
    }
    async fn resume(&mut self, _: u32) -> Result<(), Error> {
        self.trace.push((60, 0, 0));
        Ok(())
    }
}
fn ready<T>(f: impl Future<Output = T>) -> Option<T> {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

/// rtw8852a.c `rtw8852a_rfk_init`: RCK, table-driven `_dac_cal` (AFE init,
/// ADDCK + backup/reload, DACK + backup/reload, no DRCK, `RR_MOD`
/// 0x30001 -> 0x40001) and the AFE initial RX DCK.
fn smoke_rtw89_a_rfk_init_rck_dack_rxdck_follow_rtw8852a() -> TestResult {
    let mut io = Model::new();
    let mut init = Init::default();
    // SAFETY: private inert register/RF model; no hardware or DMA.
    if ready(unsafe { init.prepare(&mut io) }) != Some(Ok(()))
        || init.state() != State::BasicCalibrated
    {
        return TestResult::Fail("RTL8852A rfk_init did not complete on a ready model");
    }
    let Some(r) = init.results().cloned() else {
        return TestResult::Fail("RTL8852A rfk_init published no results");
    };
    if r.rck != [0x12, 0x12] || r.addck != [[0x2ab, 0x155], [0x2ab, 0x155]] {
        return TestResult::Fail("RTL8852A RCK/ADDCK results differ");
    }
    for path in 0..2 {
        for i in 0..16 {
            if r.msbk[path][0][i] != 0x5c + i as u8 || r.msbk[path][1][i] != 0x80 + i as u8 {
                return TestResult::Fail(
                    "RTL8852A DACK MSBK backup differs from the selector stream",
                );
            }
        }
    }
    if r.biask != [[0x48, 0x6c], [0x48, 0x6c]] || r.dadck != [[0x81, 0x82], [0x81, 0x82]] {
        return TestResult::Fail("RTL8852A DACK bias / DADCK differs");
    }
    // `_dack_reload_by_path`: msbk[12..16] LE, then (biask << 22) |
    // (dadck << 14); index 1 is offset 0x50, path B offset 0x2000.
    if io.word(0x5e14) != 0x6b6a_6968
        || io.word(0x5e24) != 0x1220_4000
        || io.word(0x5e64) != 0x8f8e_8d8c
        || io.word(0x5e74) != 0x1b20_8000
        || io.word(0x7e14) != 0x6b6a_6968
        || io.word(0x7e24) != 0x1220_4000
    {
        return TestResult::Fail("RTL8852A DACK reload words differ");
    }
    // `_addck_reload`: RXDC = (Q << 16) | ((I & 0x3f) << 26) = 0x56ab0000;
    // RXDC2 keeps the trigger table's AVG 0xc0, plus Q2 0x5 and MEN 0x30.
    if io.word(0x12d4) != 0x56ab_0000
        || io.word(0x12d8) != 0xf5
        || io.word(0x32d4) != 0x56ab_0000
        || io.word(0x32d8) != 0xf5
    {
        return TestResult::Fail("RTL8852A ADDCK reload differs");
    }
    // `_rck` tail: RCKO_OFF 4, RFC_CKEN 1 then 0, both paths; `RR_MOD`
    // 0x30001 then 0x40001, both paths.
    for path in [16u8, 17] {
        if !io.trace.contains(&(path, 0x1d, 0x4))
            || !io.trace.contains(&(path, 0xf0, 0x1))
            || !io.trace.contains(&(path, 0xf0, 0x0))
            || !io.trace.contains(&(path, 0x00, 0x30001))
            || !io.trace.contains(&(path, 0x00, 0x40001))
        {
            return TestResult::Fail("RTL8852A RCK tail / MOD sequence differs");
        }
    }
    // No DRCK and no PHYREG_SET: the A `_dac_cal` has neither, unlike B.
    if io
        .trace
        .iter()
        .any(|t| t.0 == 4 && (t.1 == 0x1c0c4 || t.1 == 0x1c0cc))
        || io.trace.contains(&(4, 0x8040, 15))
    {
        return TestResult::Fail("RTL8852A dac_cal touched DRCK or PHYREG_SET");
    }
    // AFE RX DCK: DCK2 cycle 0x3f, DCK1_SEL = is_afe, full RXCK restore
    // to the word the DACK tables left (0x7000: the R-table WS of the
    // TXCK_VAL field), not zero.
    if !io.trace.contains(&(16, 0x94, 0x3f))
        || !io.trace.contains(&(16, 0x93, 0x1))
        || !io.trace.contains(&(17, 0x94, 0x3f))
        || !io.trace.contains(&(17, 0x93, 0x1))
        || io.word(0x12a0) != 0x7000
        || io.word(0x32a0) != 0x7000
    {
        return TestResult::Fail("RTL8852A AFE RX DCK differs");
    }
    // DACK is bracketed once; the initial RX DCK is bracketed with the
    // TX pause. The ONESHOT notifications inside `_dac_cal`/`_set_rx_dck`
    // emit no I/O.
    let order: Vec<_> = io.trace.iter().filter(|t| t.0 >= 48).copied().collect();
    if order
        != [
            (48, Kind::Dack as u32, 0),
            (48, Kind::Dack as u32, 1),
            (48, Kind::Rxdck as u32, 0),
            (56, 0, 0),
            (60, 0, 0),
            (48, Kind::Rxdck as u32, 1),
        ]
    {
        return TestResult::Fail("RTL8852A RFK BTC/TX-pause bracket differs");
    }
    // A stuck done bit fails closed and the owner is terminal.
    for stuck in [0x1e00, 0x3e00, 0x5e28, 0x5e48, 0x7e28, 0x100000 + 0x1c] {
        let mut io = Model::new();
        io.stuck = Some(stuck);
        let mut init = Init::default();
        // SAFETY: private inert register/RF model; no hardware or DMA.
        let first = ready(unsafe { init.prepare(&mut io) });
        // SAFETY: same inert model; the failed owner must refuse a replay.
        let replay = ready(unsafe { init.prepare(&mut io) });
        if first != Some(Err(Error::Register(power::Error::Timeout)))
            || init.results().is_some()
            || replay != Some(Err(Error::Terminal))
        {
            return TestResult::Fail("stuck RTL8852A RFK poll did not fail closed");
        }
    }
    // Channel RX DCK with TSSI mode pauses and restores TSSI tracking on
    // both paths.
    let mut io = Model::new();
    let mut rxdck = ChannelRxDck::default();
    // SAFETY: private inert register/RF model; no hardware or DMA.
    if ready(unsafe { rxdck.prepare(&mut io, true) }) != Some(Ok(()))
        || !io.trace.contains(&(4, 0x15818, 1 << 30))
        || !io.trace.contains(&(4, 0x17818, 1 << 30))
        || io.word(0x5818) & (1 << 30) != 0
        || io.word(0x7818) & (1 << 30) != 0
    {
        return TestResult::Fail("RTL8852A channel RX DCK TSSI pause differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_a_rfk_init_rck_dack_rxdck_follow_rtw8852a
);
