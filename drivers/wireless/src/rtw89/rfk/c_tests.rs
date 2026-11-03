use super::super::power::Io;
use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

/// Private RTL8852C BB/RF register model: DACK/ADDCK/DRCK/RCK/RXDCK done
/// bits read as set unless `stuck`; RX DCK TIA samples come from `tia`.
struct Model {
    words: Vec<u32>,
    rf: [Vec<u32>; 2],
    /// `tia[path][dck address] = (i, q)` 7-bit samples.
    tia: [[(u32, u32); 32]; 2],
    trace: Vec<(u8, u32, u32)>,
    now: u64,
    stuck: Option<u32>,
}
impl Model {
    fn new() -> Self {
        let mut tia = [[(0x40, 0x40); 32]; 2];
        // Path A gain 0xc: I drifts 0x20 from the 0x40 baseline (> th 10),
        // Q stays within it; path B odd 0x1d: Q drifts.
        tia[0][0xc] = (0x60, 0x44);
        tia[1][0x1d] = (0x40, 0x10);
        Self {
            words: vec![0; 0x20000 / 4],
            rf: core::array::from_fn(|_| vec![0; 0x100]),
            tia,
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
        let r = a - 0x10000;
        let mut v = self.words[a as usize / 4];
        match r {
            0xc0c8 => v = (0x15 << 15) | 8,
            0xc0fc => v = (0x2ab << 10) | 0x155,
            0xc1fc => v = (0x0f0 << 10) | 0x30f,
            0xc040 | 0xc064 | 0xc140 | 0xc164 => v |= 1 << 31,
            0xc05c | 0xc080 | 0xc15c | 0xc180 => {
                let select = match r {
                    0xc05c => 0xc000,
                    0xc080 => 0xc020,
                    0xc15c => 0xc100,
                    _ => 0xc120,
                };
                v = (((r & 0xff) + ((self.word(select) >> 1) & 15)) << 24) | 4;
            }
            0xc048 | 0xc06c | 0xc148 | 0xc16c => v = (r & 0x3ff) << 2,
            0xc060 | 0xc084 | 0xc160 | 0xc184 => v = ((r & 0xff) + 1) << 24,
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
        let p = usize::from(path);
        let mut value = self.rf[p][address as usize];
        match address {
            0x1c => value |= 8,
            0x1b if value == 0x240 => value |= 0x4800,
            0x93 => value |= 1 << 5,
            0x95 => value |= 1 << 3,
            _ => {}
        }
        let selected = ((self.rf[p][0] >> 10) & 0x1f) as usize;
        if address == 0x92 {
            value = (value & !0xfe00) | (self.tia[p][selected].0 << 9);
        }
        if address == 0x93 {
            value = (value & !0xfe00) | (self.tia[p][selected].1 << 9);
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
        let p = usize::from(path);
        let old = self.rf[p][address as usize];
        self.rf[p][address as usize] = (old & !mask) | ((value << mask.trailing_zeros()) & mask);
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
fn smoke_rtw89_c_rfk_init_rck_dack_rxdck_follow_rtw8852c() -> TestResult {
    let mut io = Model::new();
    let mut init = Init::default();
    // SAFETY: private inert register/RF model; no hardware or DMA.
    if ready(unsafe { init.prepare(&mut io) }) != Some(Ok(()))
        || init.state() != State::BasicCalibrated
    {
        return TestResult::Fail("C rfk_init did not complete on a ready model");
    }
    let Some(r) = init.results() else {
        return TestResult::Fail("C rfk_init published no results");
    };
    // `_addck_backup`: A0 = [19:10], A1 = [9:0].
    if r.addck != [[0x2ab, 0x155], [0x0f0, 0x30f]] || r.rck != [0x12; 2] || !r.dpk_enable {
        return TestResult::Fail("C ADDCK/RCK/DPK-init results differ from Linux");
    }
    // `_dack_backup_s0/s1`: msbk[i] follows the 0xc000/0xc020/0xc100/0xc120 selector.
    for i in 0..16 {
        if r.msbk[0][0][i] != 0x5c + i as u8
            || r.msbk[0][1][i] != 0x80 + i as u8
            || r.msbk[1][0][i] != 0x5c + i as u8
            || r.msbk[1][1][i] != 0x80 + i as u8
        {
            return TestResult::Fail("C DACK MSBK backup differs from the selector stream");
        }
    }
    if r.biask != [[0x048, 0x06c], [0x148, 0x16c]] || r.dadck != [[0x61, 0x85], [0x61, 0x85]] {
        return TestResult::Fail("C DACK bias/DADCK backup differs");
    }
    // `_addck_reload`: RL1 = addck[path][0], RL0 = addck[path][1], RLS = 3.
    if io.word(0xc0f8) != (3 << 28) | (0x2ab << 18) | (0x155 << 8)
        || io.word(0xc1f8) != (3 << 28) | (0x0f0 << 18) | (0x30f << 8)
    {
        return TestResult::Fail("C ADDCK reload words differ");
    }
    // `_dack_reload_by_path(B, 1)`: offset 0x14 + 0x28; msbk 3..0 at 0xc20c.
    let b1 = &r.msbk[1][1];
    if io.word(0xc200 + 0x3c + 0xc) != u32::from_le_bytes([b1[0], b1[1], b1[2], b1[3]])
        || io.word(0xc200 + 0x3c) != u32::from_le_bytes([b1[12], b1[13], b1[14], b1[15]])
        || io.word(0xc210 + 0x3c) != (0x16c << 22) | (0x85 << 14) | 1
    {
        return TestResult::Fail("C DACK reload words differ from _dack_reload_by_path");
    }
    // RCK A before B, DACK bracketed by START/STOP, no RXDCK notification.
    let notes: Vec<_> = io.trace.iter().filter(|t| t.0 >= 48).copied().collect();
    if notes != [(48, Kind::Dack as u32, 0), (48, Kind::Dack as u32, 1)] {
        return TestResult::Fail("C rfk_init coexistence notifications differ from Linux");
    }
    let rck: Vec<u8> = io
        .trace
        .iter()
        .filter(|t| t.0 >= 16 && t.0 < 18 && t.1 == 0x1b && t.2 == 0x240)
        .map(|t| t.0 - 16)
        .collect();
    if rck != [0, 1] {
        return TestResult::Fail("C RCK trigger order is not A then B");
    }
    // `_rx_dck_recover`: path A 0xc I over th -> I takes the 0x40 baseline
    // (0x40 >> 1 = 0x20), Q kept (0x44 >> 1); path B 0x1d Q over th.
    let rewrites: Vec<_> = io
        .trace
        .iter()
        .filter(|t| t.1 == 0x3f || t.1 == 0x33)
        .copied()
        .collect();
    if rewrites
        != [
            (16, 0x33, 0xc),
            (16, 0x3f, (0x22 << 6) | 0x20),
            (16, 0x3f, (0x22 << 6) | 0x20),
            (17, 0x33, 0x1d),
            (17, 0x3f, (0x20 << 6) | 0x20),
            (17, 0x3f, (0x20 << 6) | 0x20),
        ]
    {
        return TestResult::Fail("C RX DCK recovery rewrites differ from _rx_dck_value_rewrite");
    }
    // Stuck DACK S1 done bit and stuck RX DCK done fail closed.
    for stuck in [0xc164, 0x100093, 0x10001c, 0xc0c8, 0xc1fc] {
        let mut io = Model::new();
        io.stuck = Some(stuck);
        let mut init = Init::default();
        // SAFETY: private inert model.
        let result = ready(unsafe { init.prepare(&mut io) });
        if result != Some(Err(Error::Register(power::Error::Timeout))) || init.results().is_some() {
            return TestResult::Fail("C rfk_init timeout did not fail closed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_c_rfk_init_rck_dack_rxdck_follow_rtw8852c
);
