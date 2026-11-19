use super::super::super::operating_channel::Profile;
use super::super::power::Io;
use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wireless::association::channel::Band;

/// Private RTL8851B BB/RF model for DPK and tracking: NCTL one-shots
/// complete, `R_RPT_COM` answers per `R_KIP_RPT1` selector, RF done/lock
/// bits read as set. `stuck` zeroes one BB offset.
struct Model {
    words: Vec<u32>,
    rf: Vec<u32>,
    trace: Vec<(u8, u32, u32)>,
    now: u64,
    pending: bool,
    corv: u32,
    stuck: Option<u32>,
}
impl Model {
    fn new() -> Self {
        let mut m = Self {
            words: vec![0; 0x20000 / 4],
            rf: vec![0; 0x200],
            trace: Vec::new(),
            now: 0,
            pending: false,
            corv: 0xc8,
            stuck: None,
        };
        // KSET raw 2 (cur_k_set 1), TH 32; K-set 1 para: ther 30, txagc 0x15.
        m.set(0x81fc, (2 << 29) | 0x20);
        m.set(0x8194, (30 << 26) | (0x15 << 10));
        m
    }
    fn word(&self, address: u32) -> u32 {
        self.words[(0x10000 + address) as usize / 4]
    }
    fn set(&mut self, address: u32, value: u32) {
        self.words[(0x10000 + address) as usize / 4] = value;
    }
    fn slot(address: u32) -> usize {
        ((address & 0xff) | (((address >> 16) & 1) << 8)) as usize
    }
    fn shots(&self, id: u32) -> usize {
        self.trace
            .iter()
            .filter(|t| **t == (4, 0x18000, (id << 8) | 0x19))
            .count()
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
        if a >= 0x10000 {
            let r = a - 0x10000;
            if r == 0xbff8 {
                v = 0x55;
            } else if r == 0x80fc {
                v = if self.pending {
                    0x8000
                } else {
                    match (self.word(0x80d4) >> 16) & 0x3f {
                        0 => (0x5a0 << 16) | (self.corv << 8) | 0x10,
                        9 => (5 << 16) | 3,
                        6 if self.word(0x80c0) >> 24 == 0x1f => 0x0180_0120,
                        6 => 0x0200_0120,
                        _ => 0,
                    }
                };
            }
            if self.stuck == Some(r) {
                v = 0;
            }
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
        if a == 0x18000 {
            self.pending = true;
        } else if a == 0x18010 {
            self.pending = false;
        }
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
        if path != 0 {
            return Err(Error::Policy);
        }
        let mut value = self.rf[Model::slot(address)];
        match address {
            0xd0 => value |= 1 << 16,
            0xc9 => value |= 0x3,
            0x92 => value |= 1 << 8,
            0xc5 => value |= 0x8000,
            // RR_TM_VAL [6:1] = 40.
            0x42 => value = (value & !0x7e) | (40 << 1),
            _ => {}
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
        if path != 0 {
            return Err(Error::Policy);
        }
        let slot = &mut self.rf[Model::slot(address)];
        *slot = (*slot & !mask) | ((value << mask.trailing_zeros()) & mask);
        self.trace.push((16, address, value));
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

/// rtw8851b_rfk.c `rtw8851b_dpk(PHY_0)`: one-shot stream, AGC to
/// SET_TX_GAIN, `_dpk_on` (order/MEN/gs), Linux's swapped `bp.ch`/`bp.bw`
/// feeding `_dpk_tpg_sel` / RR_BTC_TXBB, KIP/RF backup reload, TSSI
/// pause bracket and the sync-failure / stuck-NCTL arms.
fn smoke_rtw89_n51_dpk_agc_on_and_restore_follow_rtw8851b() -> TestResult {
    let (Some(a36), Some(g2)) = (Profile::new(Band::Ghz5, 36), Profile::new(Band::Ghz2, 2)) else {
        return TestResult::Fail("RTL8851B DPK test profiles refused");
    };
    let mut io = Model::new();
    io.set(0xc0ec, 0x1234_5678);
    io.rf[0xde] = 0x5_a5a5;
    let mut dpk = Dpk::default();
    // SAFETY: private inert register/RF model; no hardware or DMA.
    if ready(unsafe { dpk.run(&mut io, a36, true) }) != Some(Ok(())) {
        return TestResult::Fail("RTL8851B 5GHz DPK did not complete on a ready model");
    }
    let Some(p) = dpk.results().copied() else {
        return TestResult::Fail("RTL8851B DPK published no result");
    };
    if p.failed
        || p.path_ok != 0x2
        || p.cur_k_set != 1
        || p.ther_dpk != 30
        || p.txagc_dpk != 0x15
        || p.gs != 0x5b
        || p.band != 1
        || p.ch != 0
        || p.bw != 36
        || dpk.version != 0x11
    {
        return TestResult::Fail("RTL8851B DPK path result differs");
    }
    // KIP_PRESET, TXAGC (initial + gain loss), RXAGC, GAIN_LOSS, MDPK_IDL,
    // 5GHz LBK_RXIQK, KIP_RESTORE; DGain 0x5a0 needs no SYNC.
    if io.shots(0x28) != 1
        || io.shots(0x29) != 2
        || io.shots(0x2a) != 1
        || io.shots(0x2c) != 1
        || io.shots(0x2d) != 1
        || io.shots(0x06) != 1
        || io.shots(0x31) != 1
        || io.shots(0x2b) != 0
    {
        return TestResult::Fail("RTL8851B DPK one-shot stream differs");
    }
    // DPD_CH0A: SEL 1, ORDER (5,3,1) -> 6, MEN = path_ok.
    let ch0a = io.word(0x81bc);
    if (ch0a >> 8) & 0x3f != 1 || (ch0a >> 24) & 7 != 6 || ch0a >> 28 != 2 {
        return TestResult::Fail("RTL8851B DPK DPD_CH0A differs");
    }
    // bp.bw = channel 36 -> the 20MHz TPG row; TXBB = (36 + 1) & 7.
    if !io.trace.contains(&(4, 0x18068, 0xf9f0_07d0)) || !io.trace.contains(&(16, 0x1a, 5)) {
        return TestResult::Fail("RTL8851B DPK TPG/TXBB do not follow Linux bp.bw");
    }
    // SET_TX_GAIN: RXBB += gl_idx 2; MDPD order 0 (5,3,1) parameters.
    if io.word(0x80a0) & 0x1f03 != 0x0300 || (io.word(0x8070) >> 28) & 7 != 1 {
        return TestResult::Fail("RTL8851B DPK MDPD order parameters differ");
    }
    if io.word(0xc0ec) != 0x1234_5678
        || io.rf[0xde] != 0x5_a5a5
        || io.word(0x8088) != 0x8000_0000
        || io.word(0x8008) != 0
        || io.word(0x80f4) & (1 << 18) == 0
        || !io.trace.contains(&(4, 0x15818, 1 << 30))
        || io.word(0x5818) & (1 << 30) != 0
        || io.word(0x4730) & (1 << 31) == 0
        || io.word(0x581c) & (1 << 20) == 0
    {
        return TestResult::Fail("RTL8851B DPK restore / TSSI bracket differs");
    }
    if io.trace.first() != Some(&(48, Kind::Dpk as u32, 0))
        || io.trace.last() != Some(&(48, Kind::Dpk as u32, 1))
    {
        return TestResult::Fail("RTL8851B DPK not bracketed by BTC DPK START/STOP");
    }
    // 2.4GHz channel 2: Linux's bp.bw == 2 selects the 80MHz TPG row and
    // the RXIQC bypass replaces LBK RXIQK.
    let mut io = Model::new();
    let mut dpk = Dpk::default();
    // SAFETY: as above.
    if ready(unsafe { dpk.run(&mut io, g2, false) }) != Some(Ok(()))
        || !io.trace.contains(&(4, 0x18068, 0xffe0_fa00))
        || io.shots(0x06) != 0
        || !io.trace.contains(&(4, 0x1813c, 0x4000_0002))
        || io.trace.contains(&(4, 0x15818, 1 << 30))
    {
        return TestResult::Fail("RTL8851B 2.4GHz DPK TPG / RXIQC bypass differs");
    }
    // Sync failure (corr_val < 170): completed, MDPD off.
    let mut io = Model::new();
    io.corv = 0x20;
    let mut dpk = Dpk::default();
    // SAFETY: as above.
    if ready(unsafe { dpk.run(&mut io, a36, false) }) != Some(Ok(()))
        || dpk.results().map(|p| (p.failed, p.path_ok)) != Some((true, 0))
        || io.word(0x81bc) >> 28 != 0
        || io.shots(0x2d) != 0
    {
        return TestResult::Fail("RTL8851B DPK sync failure did not bypass MDPD");
    }
    // A stuck NCTL fails closed with no result.
    let mut io = Model::new();
    io.stuck = Some(0xbff8);
    let mut dpk = Dpk::default();
    // SAFETY: as above.
    if !matches!(ready(unsafe { dpk.run(&mut io, a36, false) }), Some(Err(_)))
        || dpk.results().is_some()
    {
        return TestResult::Fail("stuck RTL8851B DPK one-shot did not fail closed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_n51_dpk_agc_on_and_restore_follow_rtw8851b
);

/// rtw8851b.c `rtw8851b_rfk_track`: thermal update (TSSI-mode BB source),
/// `_dpk_track` PWSF (`0x78 - (cur - ther_dpk) * 2 / 3`) and
/// `rtw8851b_lck_track` AACK + LCK at `RTW8851B_LCK_TH`.
fn smoke_rtw89_n51_rfk_track_dpk_pwsf_and_lck_follow_rtw8851b() -> TestResult {
    let Some(a36) = Profile::new(Band::Ghz5, 36) else {
        return TestResult::Fail("RTL8851B track test profile refused");
    };
    let mut io = Model::new();
    let mut dpk = Dpk::default();
    let mut track = Track::new(&InitResults::default());
    // SAFETY: private inert register/RF model; no hardware or DMA.
    if ready(unsafe { track.step(&mut io, &dpk, true) }) != Some(Err(Error::Policy)) {
        return TestResult::Fail("RTL8851B track ran without a completed DPK");
    }
    let mut track = Track::new(&InitResults::default());
    // SAFETY: as above.
    if ready(unsafe { dpk.run(&mut io, a36, true) }) != Some(Ok(())) {
        return TestResult::Fail("RTL8851B DPK for tracking did not complete");
    }
    // TSSI thermal 40, TXAGC RF 0x10; RPT_PER TH 32 vs ther_dpk 30.
    io.set(0x1c10, 40 << 24);
    io.set(0x1c60, 0x10);
    // SAFETY: as above.
    if ready(unsafe { track.step(&mut io, &dpk, true) }) != Some(Ok(())) {
        return TestResult::Fail("RTL8851B rfk_track did not complete");
    }
    if track.average() != 40
        || track.last_pwsf != Some(0x77)
        || (io.word(0x81b4) >> 18) & 0x1ff != 0x77
        || track.lck_count != 1
        || track.aack != Some(([3; 4], 0))
    {
        return TestResult::Fail("RTL8851B DPK track / LCK track differs");
    }
    // Same thermal: no LCK; IDL_DN set: no PWSF write.
    io.set(0x80dc, 1 << 31);
    // SAFETY: as above.
    if ready(unsafe { track.step(&mut io, &dpk, true) }) != Some(Ok(()))
        || track.lck_count != 1
        || track.last_pwsf.is_some()
    {
        return TestResult::Fail("RTL8851B track re-ran LCK or wrote PWSF with IDL_DN");
    }
    // Non-TSSI thermal: RR_TM trigger 1/0/1 then RR_TM_VAL.
    let before = io.trace.len();
    // SAFETY: as above.
    if ready(unsafe { track.step(&mut io, &dpk, false) }) != Some(Ok(()))
        || io.trace[before..]
            .iter()
            .filter(|t| t.0 == 16 && t.1 == 0x42)
            .count()
            != 3
    {
        return TestResult::Fail("RTL8851B RF thermal trigger differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_n51_rfk_track_dpk_pwsf_and_lck_follow_rtw8851b
);
