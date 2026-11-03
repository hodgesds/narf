use super::super::power::Io;
use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

/// Private RTL8851B MAC/BB/RF register model: DRCK/ADDCK/DACK/RCK/AACK/RX
/// DCK done bits read as set unless `stuck` (BB offset, or 0x100000 + RF).
struct Model {
    words: Vec<u32>,
    rf: [Vec<u32>; 2],
    trace: Vec<(u8, u32, u32)>,
    now: u64,
    stuck: Option<u32>,
    /// BB offset and bits OR-ed into every read of it.
    or: Option<(u32, u32)>,
}
impl Model {
    fn new() -> Self {
        Self {
            words: vec![0; 0x20000 / 4],
            rf: core::array::from_fn(|_| vec![0; 0x100]),
            trace: Vec::new(),
            now: 0,
            stuck: None,
            or: None,
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
            // DRCK: POL BIT(3), rck_d [14:10] = 0x15.
            0xc0c8 => v = (0x15 << 10) | 8,
            // ADDCK/DADCK done BIT(0); A0 [19:10], A1 [9:0], DC [15:4].
            0xc0fc => v = (0x2ab << 10) | 0x155,
            0xc040 | 0xc064 => v |= 1 << 31,
            0xc05c | 0xc080 => {
                let select = if r == 0xc05c { 0xc000 } else { 0xc020 };
                v = (((r & 0xff) + ((self.word(select) >> 1) & 15)) << 24) | 4;
            }
            0xc048 | 0xc06c => v = (r & 0x3ff) << 2,
            0xc060 | 0xc084 => v = ((r & 0xff) + 1) << 24,
            // IQK NCTL done byte and R_RPT_COM ready.
            0xbff8 => v = 0x55,
            0x80fc => v |= 0x8000,
            _ => {}
        }
        if let Some((offset, bits)) = self.or {
            if offset == r {
                v |= bits;
            }
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
            0xd0 => value |= 1 << 16,
            0xc9 => value |= 0x3,
            0x92 => value |= (1 << 8) | (0x5 << 16),
            0x93 => value |= 0xa << 16,
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

/// rtw8851b.c `rtw8851b_rfk_init`: by-rate DPD, AACK, RCK, S0-only DACK
/// (`_dac_cal` + `_new_dadck`) and the notified RX DCK, path A only.
fn smoke_rtw89_n51_rfk_init_aack_rck_dack_rxdck_follow_rtw8851b() -> TestResult {
    let mut io = Model::new();
    let mut init = Init::default();
    // SAFETY: private inert register/RF model; no hardware or DMA.
    if ready(unsafe { init.prepare(&mut io) }) != Some(Ok(()))
        || init.state() != State::BasicCalibrated
    {
        return TestResult::Fail("RTL8851B rfk_init did not complete on a ready model");
    }
    let Some(r) = init.results().cloned() else {
        return TestResult::Fail("RTL8851B rfk_init published no results");
    };
    // rtw8851b_by_rate_dpd: MAC 0xd230 [17:0] = 0x21861.
    if io.words[0xd230 / 4] & 0x3_ffff != 0x21861 {
        return TestResult::Fail("RTL8851B by-rate DPD differs");
    }
    if r.rck != 0x12 || r.aack_rek != 0 || r.aack_ib != [3; 4] || r.addck != [0x2ab, 0x155] {
        return TestResult::Fail("RTL8851B RCK/AACK/ADDCK results differ");
    }
    for i in 0..16 {
        if r.msbk[0][i] != 0x5c + i as u8 || r.msbk[1][i] != 0x80 + i as u8 {
            return TestResult::Fail("RTL8851B DACK MSBK backup differs from the selector stream");
        }
    }
    // _new_dadck: DC = 0xad5 -> sext -1323 -> 0x80 + 7938 = 0x1f82 -> u8 0x82.
    if r.biask != [0x048, 0x06c] || r.dadck != [0x82, 0x82] {
        return TestResult::Fail("RTL8851B DACK bias / new DADCK differs");
    }
    if io.word(0xc210) != (0x48 << 22) | (0x82 << 14) | 1
        || io.word(0xc224) != (0x6c << 22) | (0x82 << 14) | 1
        || io.word(0xc0f8) != (3 << 28) | (0x2ab << 18) | (0x155 << 8)
        || io.word(0xc0c4) & 0x1f != 0x15
        || io.word(0x12b8) & (1 << 30) != 0
    {
        return TestResult::Fail("RTL8851B DACK reload / DADCK / ADDCK reload differs");
    }
    // _rxbb_ofst_swap: LUTWA = RF_RX, LUTWD0 = (q << 4) | i = 0xa5.
    if !io.trace.contains(&(16, 0x33, 0x3)) || !io.trace.contains(&(16, 0x3f, 0xa5)) {
        return TestResult::Fail("RTL8851B RX DCK offset swap differs");
    }
    // Path B is never touched; DACK is un-notified; RX DCK is bracketed.
    if io.trace.iter().any(|t| t.0 == 17) || io.trace.contains(&(48, Kind::Dack as u32, 0)) {
        return TestResult::Fail("RTL8851B rfk_init touched path B or notified DACK");
    }
    let order: Vec<_> = io.trace.iter().filter(|t| t.0 >= 48).copied().collect();
    if order
        != [
            (48, Kind::Rxdck as u32, 0),
            (56, 0, 0),
            (60, 0, 0),
            (48, Kind::Rxdck as u32, 1),
        ]
    {
        return TestResult::Fail("RTL8851B RX DCK BTC/TX-pause bracket differs");
    }
    // A stuck done bit fails closed and the owner is terminal.
    for stuck in [
        0xc0c8,
        0xc0fc,
        0xc040,
        0x100000 + 0xd0,
        0x100000 + 0x1c,
        0x100000 + 0x92,
    ] {
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
            return TestResult::Fail("stuck RTL8851B RFK poll did not fail closed");
        }
    }
    // Channel RX DCK with TSSI mode pauses and restores TSSI tracking.
    let mut io = Model::new();
    let mut rxdck = ChannelRxDck::default();
    // SAFETY: private inert register/RF model; no hardware or DMA.
    if ready(unsafe { rxdck.prepare(&mut io, true) }) != Some(Ok(()))
        || !io.trace.contains(&(4, 0x15818, 1 << 30))
        || io.word(0x5818) & (1 << 30) != 0
    {
        return TestResult::Fail("RTL8851B channel RX DCK TSSI pause differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_n51_rfk_init_aack_rck_dack_rxdck_follow_rtw8851b
);

/// rtw8851b_rfk.c `rtw8851b_iqk(PHY_0)`: path-A wideband `_doiqk` with
/// the 2/5GHz LOK grams, TX/RX group selections, `_iqk_sram` on an RX
/// failure, restore and BB/RF backup restore.
fn smoke_rtw89_n51_iqk_lok_group_select_and_restore_follow_rtw8851b() -> TestResult {
    use super::super::super::operating_channel::{Profile, Width};
    use super::super::n51_iqk::Iqk;
    use narf_wireless::association::channel::Band;
    let shots = |io: &Model, command: u32| {
        io.trace
            .iter()
            .filter(|t| **t == (4, 0x18000, command))
            .count()
    };
    let Some(g1) = Profile::new(Band::Ghz2, 1) else {
        return TestResult::Fail("channel 1 profile refused");
    };
    let mut io = Model::new();
    io.words[(0x10000 + 0xc0d4) / 4] = 0x1234_5678;
    io.rf[0][0xde] = 0x5_a5a5;
    let mut iqk = Iqk::default();
    // SAFETY: private inert register/RF model; no hardware or DMA.
    if ready(unsafe { iqk.run(&mut io, g1) }) != Some(Ok(())) {
        return TestResult::Fail("RTL8851B 2.4GHz IQK did not complete on a ready model");
    }
    let Some(path) = iqk.results().copied() else {
        return TestResult::Fail("RTL8851B IQK published no result");
    };
    if path.tx_fail || path.rx_fail || path.lok_fail || !path.is_wb_txiqk {
        return TestResult::Fail("RTL8851B IQK result flags differ on a passing model");
    }
    if iqk.times != 1 || iqk.version != 0x14 {
        return TestResult::Fail("RTL8851B IQK times/version differ");
    }
    // 20MHz: TXK 0x819, RXK 0xc19, NBTXK 0x419, NBRXK 0x619, RXAGC 0x719,
    // LOK coarse 0x119 / fine 0x319 (ten grams each), restore 0x1219.
    if shots(&io, 0x119) != 10
        || shots(&io, 0x319) != 10
        || shots(&io, 0x419) != 1
        || shots(&io, 0x819) != 1
        || shots(&io, 0x719) != 4
        || shots(&io, 0x619) != 4
        || shots(&io, 0xc19) != 4
        || shots(&io, 0x1219) != 1
    {
        return TestResult::Fail("RTL8851B 2.4GHz IQK one-shot command stream differs");
    }
    if io.word(0xc0d4) != 0x1234_5678
        || io.rf[0][0xde] != 0x5_a5a5
        || io.word(0x8138) != 0x4000_0000
        || io.word(0x813c) != 0x4000_0000
        || io.word(0x8088) != 0x8000_0000
        || io.word(0x810c) != 0
    {
        return TestResult::Fail("RTL8851B IQK restore / wideband CFIR differs");
    }
    if io.trace.iter().any(|t| t.0 == 17) {
        return TestResult::Fail("RTL8851B IQK touched RF path B");
    }
    let order: Vec<_> = io.trace.iter().filter(|t| t.0 >= 48).copied().collect();
    if order
        != [
            (48, Kind::Iqk as u32, 0),
            (56, 0, 0),
            (48, Kind::IqkPath as u32, 0),
            (48, Kind::IqkPath as u32, 1),
            (60, 0, 0),
            (48, Kind::Iqk as u32, 1),
        ]
    {
        return TestResult::Fail("RTL8851B IQK BTC/TX-pause bracket differs");
    }
    // 5GHz 80MHz with B_NCTL_RPT_FLG set: narrowband fallback, SRAM dump,
    // RXCFIR clear and the 0x17/0x37 LUT bracket.
    let Some(a80) = Profile::new_5ghz(36, Width::Mhz80) else {
        return TestResult::Fail("channel 36/80 profile refused");
    };
    let mut io = Model::new();
    io.or = Some((0x8008, 1 << 26));
    let mut iqk = Iqk::default();
    // SAFETY: private inert register/RF model; no hardware or DMA.
    if ready(unsafe { iqk.run(&mut io, a80) }) != Some(Ok(())) {
        return TestResult::Fail("RTL8851B 5GHz IQK did not complete on a ready model");
    }
    let Some(path) = iqk.results().copied() else {
        return TestResult::Fail("RTL8851B 5GHz IQK published no result");
    };
    if !path.tx_fail || !path.rx_fail || path.is_wb_txiqk {
        return TestResult::Fail("RTL8851B IQK group failure was not recorded");
    }
    // 80MHz: TXK 0xa19 (two groups), RXK 0xe19 (four groups).
    if shots(&io, 0xa19) != 2 || shots(&io, 0xe19) != 4 || shots(&io, 0x419) != 2 {
        return TestResult::Fail("RTL8851B 5GHz IQK one-shot command stream differs");
    }
    if !io.trace.contains(&(4, 0x180d8, 0x1009f))
        || !io.trace.contains(&(16, 0x3f, 0x17))
        || !io.trace.contains(&(16, 0x3f, 0x37))
        || io.word(0x810c) != 0x3333_2222
        || io.word(0x813c) != path.nb_rxcfir | 2
        || io.word(0x8138) != path.nb_txcfir | 2
    {
        return TestResult::Fail("RTL8851B 5GHz IQK fallback / SRAM / LUT bracket differs");
    }
    // 160MHz is refused before any access; a stuck NCTL fails closed.
    if let Some(c160) = Profile::new_5ghz_160(36) {
        let mut io = Model::new();
        // SAFETY: private inert register/RF model; no hardware or DMA.
        if ready(unsafe { Iqk::default().run(&mut io, c160) }) != Some(Err(Error::Policy))
            || !io.trace.is_empty()
        {
            return TestResult::Fail("RTL8851B IQK accepted 160MHz");
        }
    }
    let mut io = Model::new();
    io.stuck = Some(0xbff8);
    let mut iqk = Iqk::default();
    // SAFETY: private inert register/RF model; no hardware or DMA.
    if ready(unsafe { iqk.run(&mut io, g1) }) != Some(Err(Error::Register(power::Error::Timeout)))
        || iqk.results().is_some()
    {
        return TestResult::Fail("stuck RTL8851B IQK NCTL did not fail closed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_n51_iqk_lok_group_select_and_restore_follow_rtw8851b
);

/// rtw8851b_rfk.c `rtw8851b_tssi(PHY_0)` / `rtw8851b_tssi_scan` /
/// `rtw8851b_tssi_default_txagc`: path-A tables, TXPWR_TRK thermal rows
/// (RTL8851B 2/5GHz bitmap), enable and the factory DE values.
fn smoke_rtw89_n51_tssi_tmeter_de_and_enable_follow_rtw8851b() -> TestResult {
    use super::super::super::factory_51::Calibration;
    use super::super::super::operating_channel::{Profile, Width};
    use super::super::n51_tssi::{Tracking, Tssi};
    use narf_wireless::association::channel::Band;
    // Bitmap 0xfff0 (no 6G): types 4..=7 three rows, 8..=15 one row each;
    // every byte of row r is r.
    let mut element = vec![0xf0, 0xff, 0, 0, 0, 0, 0, 0];
    for row in 0..20u8 {
        element.extend(core::iter::repeat_n(row, 30));
    }
    let Ok(tracking) = Tracking::parse(&element) else {
        return TestResult::Fail("RTL8851B TXPWR_TRK element refused");
    };
    let mut missing = element.clone();
    missing[1] = 0x7f;
    if Tracking::parse(&missing).is_ok() || Tracking::parse(&element[..8 + 19 * 30]).is_ok() {
        return TestResult::Fail("RTL8851B TXPWR_TRK accepted a missing type or short element");
    }
    let mut cal = Calibration {
        thermal: 0x20,
        tssi_cck: [5, 0, 0, 0, 0, 0],
        tssi_mcs: [0; 19],
        tssi_trim: [-3, 0, 0, 0, 0, 0, 0, 0],
        trim_programmed: true,
        thermal_trim: 0,
        thermal_programmed: false,
        pa_bias: 0,
        pa_programmed: false,
        gain_offset: [0; 5],
        offset_valid: false,
        gain_comp: [0; 5],
        comp_valid: false,
        adc_td: 0,
    };
    cal.tssi_mcs[0] = 10;
    cal.tssi_mcs[5] = -5;
    cal.tssi_mcs[6] = -2;
    let Some(g1) = Profile::new(Band::Ghz2, 1) else {
        return TestResult::Fail("channel 1 profile refused");
    };
    let mut io = Model::new();
    let mut tssi = Tssi::default();
    // SAFETY: private inert register/RF model; no hardware or DMA.
    if ready(unsafe { tssi.run(&mut io, g1, &cal, &tracking) }) != Some(Ok(())) {
        return TestResult::Fail("RTL8851B TSSI did not complete on a ready model");
    }
    let Some(r) = tssi.results().cloned() else {
        return TestResult::Fail("RTL8851B TSSI published no result");
    };
    // 2.4GHz: down = 2GA_N (row 14), up = 2GA_P (row 15).
    if r.thermal[0] != 0xf2f2_f2f2
        || r.thermal[15] != 0x0f0f_0f0f
        || io.word(0x5c00) != 0xf2f2_f2f2
        || io.word(0x5c3c) != 0x0f0f_0f0f
        || (io.word(0x5810) >> 10) & 0x3f != 0x20
    {
        return TestResult::Fail("RTL8851B TSSI 2.4GHz thermal table differs");
    }
    // CCK 5 + trim -3 = 2; MCS 10 + -3 = 7.
    if r.de != [2, 7]
        || (io.word(0x5858) >> 12) & 0x3ff != 2
        || (io.word(0x5830) >> 12) & 0x3ff != 7
        || !r.tssi_mode
        || io.word(0x5818) & 0xff != 0xc0
        || io.word(0x5818) & (1 << 28) == 0
        || io.word(0x5820) & (1 << 31) == 0
        || io.rf[0][0x55] & (1 << 7) == 0
    {
        return TestResult::Fail("RTL8851B TSSI DE / enable differs");
    }
    let order: Vec<_> = io.trace.iter().filter(|t| t.0 >= 48).copied().collect();
    if order != [(48, Kind::IqkPath as u32, 0), (48, Kind::IqkPath as u32, 1)]
        || io.trace.iter().any(|t| t.0 == 17)
    {
        return TestResult::Fail("RTL8851B TSSI ONESHOT bracket or path B differs");
    }
    // Band-change scan at 5GHz ch36/80 (center 42): 5GA rows [0], the
    // TSSI_EXTRA (mcs[5] + mcs[6]) / 2 = -3, trim group 2 = 0.
    let Some(a80) = Profile::new_5ghz(36, Width::Mhz80) else {
        return TestResult::Fail("channel 36/80 profile refused");
    };
    let mut io = Model::new();
    let mut tssi = Tssi::default();
    // SAFETY: private inert register/RF model; no hardware or DMA.
    if ready(unsafe { tssi.scan(&mut io, a80, &cal, &tracking) }) != Some(Ok(())) {
        return TestResult::Fail("RTL8851B TSSI scan did not complete");
    }
    let Some(r) = tssi.results().cloned() else {
        return TestResult::Fail("RTL8851B TSSI scan published no result");
    };
    if r.thermal[0] != 0xfafa_fafa
        || r.thermal[15] != 0x0909_0909
        || r.de[1] != -3
        || (io.word(0x5838) >> 12) & 0x3ff != 0x3fd
        || io.trace.iter().any(|t| t.0 >= 48)
    {
        return TestResult::Fail("RTL8851B TSSI scan 5GHz rows / extra-group DE differ");
    }
    // Erased thermal: TMETER/RFCTM 32 and zero offsets.
    cal.thermal = 0xff;
    let mut io = Model::new();
    io.words[(0x10000 + 0x5c00) / 4] = 0x1234;
    let mut tssi = Tssi::default();
    // SAFETY: private inert register/RF model; no hardware or DMA.
    if ready(unsafe { tssi.run(&mut io, g1, &cal, &tracking) }) != Some(Ok(()))
        || io.word(0x5c00) != 0
        || (io.word(0x5810) >> 10) & 0x3f != 32
    {
        return TestResult::Fail("RTL8851B TSSI erased-thermal path differs");
    }
    // Scan end reprograms OFT 0xc0 with the OFT_EN toggle; scan start is
    // I/O-free.
    let mut io = Model::new();
    // SAFETY: private inert register/RF model; no hardware or DMA.
    let start = ready(unsafe { Tssi::scan_notify(&mut io, true) });
    let quiet = io.trace.is_empty();
    // SAFETY: same inert model.
    let end = ready(unsafe { Tssi::scan_notify(&mut io, false) });
    if start != Some(Ok(())) || !quiet || end != Some(Ok(())) || io.word(0x5818) != 0x1000_00c0 {
        return TestResult::Fail("RTL8851B TSSI scan-end default TXAGC differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_n51_tssi_tmeter_de_and_enable_follow_rtw8851b
);
