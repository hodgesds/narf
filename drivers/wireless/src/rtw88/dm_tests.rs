// SPDX-License-Identifier: GPL-2.0-or-later
//! Native dm watchdog regressions against a byte-addressed register model.
//! Expected register values are authored from the cited Linux sources.
use super::dm::{self, Authority, Facts, Period, Sample, Tracker};
use super::firmware_transport::{Error, Io};
use super::packet_format::DataProfile;
use alloc::{boxed::Box, vec, vec::Vec};
use core::{
    cell::Cell,
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Regs {
    mem: Vec<u8>,
    writes: Vec<(u16, u32)>,
    delays: u64,
}
impl Regs {
    fn new() -> Self {
        Self {
            mem: vec![0; 0x10000],
            writes: Vec::new(),
            delays: 0,
        }
    }
    fn get(&self, r: u16) -> u32 {
        let r = usize::from(r);
        u32::from_le_bytes(self.mem[r..r + 4].try_into().unwrap())
    }
    fn set(&mut self, r: u16, v: u32) {
        let r = usize::from(r);
        self.mem[r..r + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn wrote(&self, r: u16) -> bool {
        self.writes.iter().any(|(a, _)| *a == r)
    }
}
#[async_trait::async_trait]
// SAFETY: test model with no DMA or hardware.
unsafe impl Io for Regs {
    fn claim_pristine(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn read8(&mut self, r: u16) -> Result<u8, Error> {
        Ok(self.mem[usize::from(r)])
    }
    fn read16(&mut self, r: u16) -> Result<u16, Error> {
        let r = usize::from(r);
        Ok(u16::from_le_bytes([self.mem[r], self.mem[r + 1]]))
    }
    fn read32(&mut self, r: u16) -> Result<u32, Error> {
        Ok(self.get(r))
    }
    fn write8(&mut self, r: u16, v: u8) -> Result<(), Error> {
        self.mem[usize::from(r)] = v;
        self.writes.push((r, u32::from(v)));
        Ok(())
    }
    fn write16(&mut self, r: u16, v: u16) -> Result<(), Error> {
        let a = usize::from(r);
        self.mem[a..a + 2].copy_from_slice(&v.to_le_bytes());
        self.writes.push((r, u32::from(v)));
        Ok(())
    }
    fn write32(&mut self, r: u16, v: u32) -> Result<(), Error> {
        self.set(r, v);
        self.writes.push((r, v));
        Ok(())
    }
    async fn reserved_page(&mut self, _: &[u8]) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    async fn lte_backup(&mut self) -> Result<u32, Error> {
        Err(Error::Unsupported)
    }
    async fn lte_restore(&mut self, _: u32) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    async fn finish_dma(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    async fn delay_us(&mut self, us: u64) {
        self.delays += us;
    }
}
struct Auth(Cell<bool>);
impl Authority for Auth {
    fn run<T>(&self, op: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        if self.0.get() {
            op()
        } else {
            Err(Error::Access)
        }
    }
}
fn run<T>(f: impl Future<Output = T>) -> T {
    let mut f = Box::pin(f);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}
fn payload(enabled: u16, dig_max: u8, pd: u8, xtal: u8, up: u8, down: u8) -> [u8; 64] {
    let mut p = [0; 64];
    p[..2].copy_from_slice(&enabled.to_le_bytes());
    p[2] = dig_max;
    p[3] = pd;
    p[4] = xtal;
    p[5] = up;
    p[6] = down;
    p[7] = 10;
    p[8] = 50;
    p
}
const ALL: u16 = dm::DIG | dm::CCK_PD | dm::RA | dm::PATH_DIV | dm::CFO | dm::PWR_TRACK | dm::EDCCA;
fn c22_facts() -> Facts {
    Facts {
        did: 0xc822,
        rfe: 0,
        crystal: 0x40,
        thermal: [30, 30],
        power_track_type: 0,
        cck_gi: [10, 20],
    }
}
fn c22_regs() -> Regs {
    let mut r = Regs::new();
    r.set(0x1d70, 0x1c1c);
    r.set(0x84c, (168 << 16) | (161 << 24));
    r.set(0x440, 0x15f);
    r.set(0x1c3c, 2);
    r.set(0x2d04, 400 << 16);
    r.set(0x2d08, 400);
    r.set(0x1ac8, 0x0a0a);
    r.set(0x1ad0, 5 | (5 << 5));
    r.set(0x1040, (0x40 | (0x40 << 7)) << 10);
    r.set(0x2, 1);
    r
}
fn period(linked: bool) -> Period {
    Period {
        linked,
        profile: DataProfile {
            rates: 0x15f & 0xfff,
            qos: true,
            mcs: 0xff,
            sgi: false,
            ldpc: false,
            stbc: false,
            acs: 0,
            fallback: false,
        },
        tx_bytes: 0,
        rx_bytes: 0,
        country: *b"US",
    }
}
fn strong(t: &mut Tracker, n: usize, rssi: u8) {
    for _ in 0..n {
        t.observe(Sample {
            rssi,
            path_rssi: [Some(rssi), Some(rssi.saturating_sub(10))],
            cfo_tail: Some([20, 20]),
            rate: 12,
        });
    }
}

fn smoke_rtw88_dm_payload_admission_per_chip() -> TestResult {
    let ok = payload(ALL, 0x40, 4, 8, 8, 8);
    if dm::bounds(0xc822, &ok).is_none() {
        return TestResult::Fail("C22 full dm payload refused");
    }
    if dm::bounds(0xc821, &ok).is_some() {
        return TestResult::Fail("C21 admitted C22-only path/CFO/power/EDCCA mechanisms");
    }
    if dm::bounds(
        0xc821,
        &payload(dm::DIG | dm::CCK_PD | dm::RA, 0x1c, 2, 0, 0, 0),
    )
    .is_none()
    {
        return TestResult::Fail("C21 DIG/CCK-PD/RA payload refused");
    }
    let mut bad = vec![
        payload(0, 0x40, 4, 8, 8, 8),
        payload(ALL, 0x5b, 4, 8, 8, 8),
        payload(ALL, 0x1f, 4, 8, 8, 8),
        payload(ALL, 0x40, 5, 8, 8, 8),
        payload(ALL | 1 << 7, 0x40, 4, 8, 8, 8),
    ];
    let mut t = ok;
    t[7] = 51;
    bad.push(t);
    let mut z = ok;
    z[63] = 1;
    bad.push(z);
    if bad.iter().any(|p| dm::bounds(0xc822, p).is_some()) || dm::bounds(0xb822, &ok).is_some() {
        return TestResult::Fail("out-of-envelope or unknown-chip dm payload admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/dm_engine",
    smoke_rtw88_dm_payload_admission_per_chip
);

fn smoke_rtw88_dm_c22_dig_cck_pd_edcca_and_counters() -> TestResult {
    let b = dm::bounds(
        0xc822,
        &payload(dm::DIG | dm::CCK_PD | dm::EDCCA, 0x30, 2, 0, 0, 0),
    )
    .unwrap();
    let mut t = Tracker::new(b, c22_facts());
    let mut io = c22_regs();
    let auth = Auth(Cell::new(true));
    strong(&mut t, 20, 20);
    // Linked, FA 800 > 750, rssi20: igi = 0x1c + 6 - 2 = 0x20 within [0x20, 0x2f].
    if run(t.tick(&mut io, &auth, period(true))).is_err() {
        return TestResult::Fail("C22 linked dm tick failed");
    }
    let igi = io.get(0x1d70);
    if igi & 0x7f != 0x20 || (igi >> 8) & 0x7f != 0x20 || t.igi() != 0x20 {
        return TestResult::Fail("C22 DIG did not write source boundary IGI on both paths");
    }
    // Counter resets: 1a2c CCK/OFDM FA reset to 2, 1eb4 pulse cleared, 1d2c gating set.
    if (io.get(0x1a2c) >> 12) & 0xf != 0b1010
        || io.get(0x1eb4) & (1 << 25) != 0
        || io.get(0x1d2c) & (1 << 31) == 0
    {
        return TestResult::Fail("C22 false-alarm counter reset sequence");
    }
    // EDCCA normal: l2h=max(0x20+8,48)=48, h2l=40, +0x80.
    if io.get(0x84c) >> 16 != (176 | (168 << 8)) {
        return TestResult::Fail("C22 normal EDCCA thresholds");
    }
    // Keep raising false alarms: DIG may never exceed the signed bound 0x30.
    for _ in 0..12 {
        io.set(0x2d04, 2000 << 16);
        strong(&mut t, 4, 80);
        let _ = run(t.tick(&mut io, &auth, period(true)));
    }
    if t.igi() > 0x30 || io.get(0x1d70) & 0x7f > 0x30 {
        return TestResult::Fail("DIG exceeded the qualified upper bound");
    }
    // ETSI adaptivity uses 45 and igi+12.
    let mut p = period(true);
    p.country = *b"DE";
    let _ = run(t.tick(&mut io, &auth, p));
    let l2h = (io.get(0x84c) >> 16) & 0xff;
    let expect = (i32::from(t.igi()) + 12).min(45) + 0x80;
    if l2h as i32 != expect || ((io.get(0x84c) >> 24) as i32) != expect - 7 {
        return TestResult::Fail("ETSI EDCCA adaptivity thresholds");
    }
    // CCK PD bounded to level2: linked igi>0x24 -> lv2 (pd +4, cs +2).
    if t.pd_level() > 2 {
        return TestResult::Fail("CCK PD above qualified level");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/dm_engine",
    smoke_rtw88_dm_c22_dig_cck_pd_edcca_and_counters
);

fn smoke_rtw88_dm_cck_pd_source_deltas_and_restore() -> TestResult {
    let b = dm::bounds(0xc822, &payload(dm::DIG | dm::CCK_PD, 0x5a, 4, 0, 0, 0)).unwrap();
    let mut t = Tracker::new(b, c22_facts());
    let mut io = c22_regs();
    let auth = Auth(Cell::new(true));
    io.set(0x2d04, 0);
    io.set(0x2d08, 0);
    // Unlinked with no CCK FA: level0 equals initial; no PD write.
    let _ = run(t.tick(&mut io, &auth, period(false)));
    if io.wrote(0x1ac8) {
        return TestResult::Fail("CCK PD rewrote an unchanged level");
    }
    // Unlinked, cck_fa_avg=(0*3+5000)/4 > 1000 -> level1: pd +2, cs +2.
    io.set(0x1a5c, 5000);
    let _ = run(t.tick(&mut io, &auth, period(false)));
    if io.get(0x1ac8) & 0xff != 0x0c || io.get(0x1ad0) & 0x1f != 7 || t.pd_level() != 1 {
        return TestResult::Fail("8822c CCK PD level1 source delta");
    }
    let r = run(t.restore(&mut io, &auth));
    if r.is_err() || io.get(0x1ac8) & 0xff != 0x0a || io.get(0x1ad0) & 0x1f != 5 {
        return TestResult::Fail("CCK PD restore did not reverse the source delta");
    }
    if io.get(0x1d70) & 0x7f7f != 0x1c1c {
        return TestResult::Fail("restore did not return the base IGI");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/dm_engine",
    smoke_rtw88_dm_cck_pd_source_deltas_and_restore
);

fn smoke_rtw88_dm_ra_rrsr_h2c_and_c2h_report() -> TestResult {
    let b = dm::bounds(0xc822, &payload(dm::RA, 0x40, 0, 0, 0, 0)).unwrap();
    let mut t = Tracker::new(b, c22_facts());
    let mut io = c22_regs();
    let auth = Auth(Cell::new(true));
    strong(&mut t, 10, 30);
    if !t.c2h(&[0x0c, 7, 13 | 0x80, 0, 0, 0, 0, 0, 0]) || t.c2h(&[0x0c, 7, 13]) {
        return TestResult::Fail("C2H RA report length/id gating");
    }
    let h2c = match run(t.tick(&mut io, &auth, period(true))) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("RA tick failed"),
    };
    // RSSI monitor, WL PHY info, then RA refresh on watchdog count0.
    if h2c.len() != 3 || h2c[0][0] != 0x42 || h2c[0][3] != 30 || h2c[1][0] != 0x58 {
        return TestResult::Fail("RSSI monitor/WL PHY H2C layout");
    }
    if h2c[1][4] != 13 {
        return TestResult::Fail("WL PHY info lacks the reported TX rate");
    }
    // rssi30 -> level1 (20<30<34+3): mask fff0 drops CCK; HT kept; NO_UPDATE|DIS_PT.
    let ra = h2c[2];
    let mask = u32::from_le_bytes(ra[4..8].try_into().unwrap());
    if ra[0] != 0x40
        || ra[3] != 0x48
        || mask & 0xf != 0
        || mask >> 12 != 0xff
        || mask & 0x150 != 0x150
    {
        return TestResult::Fail("RA_INFO refresh rate mask/no-update encoding");
    }
    // RRSR: init 0x15f & genmask(order(MCS1)=2+4-1) = 0x1f.
    if io.get(0x440) != 0x15f & 0x3f {
        return TestResult::Fail("RRSR not narrowed to the RA-reported rate");
    }
    // Next three periods: no RA refresh (watch_dog_cnt & 3).
    for _ in 0..3 {
        if run(t.tick(&mut io, &auth, period(true)))
            .map(|h| h.iter().any(|w| w[0] == 0x40))
            .unwrap_or(true)
        {
            return TestResult::Fail("RA refresh outside every fourth period");
        }
    }
    if run(t.restore(&mut io, &auth)).is_err() || io.get(0x440) != 0x15f {
        return TestResult::Fail("restore did not return the qualified RRSR");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/dm_engine",
    smoke_rtw88_dm_ra_rrsr_h2c_and_c2h_report
);

fn smoke_rtw88_dm_path_div_cfo_window_and_bt_reset() -> TestResult {
    let b = dm::bounds(0xc822, &payload(dm::PATH_DIV | dm::CFO, 0x40, 0, 2, 0, 0)).unwrap();
    let mut t = Tracker::new(b, c22_facts());
    let mut io = c22_regs();
    let auth = Auth(Cell::new(true));
    // Path B stronger -> switch 1SS TX to B: 1a04=4, 820=0x32, 1e2c=0400.
    for _ in 0..5 {
        t.observe(Sample {
            rssi: 40,
            path_rssi: [Some(30), Some(50)],
            cfo_tail: Some([40, 40]),
            rate: 12,
        });
    }
    let _ = run(t.tick(&mut io, &auth, period(true)));
    if t.tx_path() != 2
        || io.get(0x1a04) >> 28 != 4
        || io.get(0x820) & 0xff != 0x32
        || io.get(0x1e2c) & 0xffff != 0x0400
    {
        return TestResult::Fail("8822c TX path diversity did not select path B");
    }
    // CFO: tail 40 -> 100kHz > 10 -> crystal +1 each period, clamped to window 2.
    for _ in 0..5 {
        t.observe(Sample {
            rssi: 40,
            path_rssi: [Some(30), Some(50)],
            cfo_tail: Some([40, 40]),
            rate: 12,
        });
        let _ = run(t.tick(&mut io, &auth, period(true)));
    }
    let x = (io.get(0x1040) >> 10) & 0x7f;
    if t.crystal() != 0x42 || x != 0x42 || (io.get(0x1040) >> 17) & 0x7f != 0x42 {
        return TestResult::Fail("CFO crystal outside the qualified window or wrong XCAP layout");
    }
    // BT enabled (scoreboard ONOFF) returns crystal to factory.
    io.set(0xa8, 2 << 16);
    t.observe(Sample {
        rssi: 40,
        path_rssi: [None, None],
        cfo_tail: Some([40, 40]),
        rate: 12,
    });
    let _ = run(t.tick(&mut io, &auth, period(true)));
    if t.crystal() != 0x40 {
        return TestResult::Fail("CFO kept adjusting while BT is enabled");
    }
    if run(t.restore(&mut io, &auth)).is_err()
        || io.get(0x1a04) >> 28 != 8
        || io.get(0x820) & 0xff != 0x11
    {
        return TestResult::Fail("restore did not return path A TX");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/dm_engine",
    smoke_rtw88_dm_path_div_cfo_window_and_bt_reset
);

fn smoke_rtw88_dm_power_tracking_trigger_clamp_and_envelope() -> TestResult {
    let b = dm::bounds(0xc822, &payload(dm::PWR_TRACK, 0x40, 0, 0, 3, 3)).unwrap();
    let mut t = Tracker::new(b, c22_facts());
    let mut io = c22_regs();
    let auth = Auth(Cell::new(true));
    // Period 1 triggers RF42 bit19 1/0/1 on both paths, no power write.
    let _ = run(t.tick(&mut io, &auth, period(true)));
    if io.wrote(0x18a0) || !io.wrote(0x3c00 + 0x42 * 4) || !io.wrote(0x4c00 + 0x42 * 4) {
        return TestResult::Fail("power tracking trigger phase");
    }
    // Thermal 40 vs efuse 30: delta 10 -> CCK A p[10]=9, clamped to +3.
    io.set(0x3c00 + 0x42 * 4, 40 << 1);
    io.set(0x4c00 + 0x42 * 4, 40 << 1);
    let _ = run(t.tick(&mut io, &auth, period(true)));
    if t.delta_power() != [3, 3] || io.get(0x18a0) & 0x7f != 3 || io.get(0x41a0) & 0x7f != 3 {
        return TestResult::Fail("power tracking delta not clamped to the signed envelope");
    }
    // Thermal moved >= 8 from thermal_k: LCK ran (RF cc pulse).
    if !io.wrote(0x3c00 + 0xcc * 4) {
        return TestResult::Fail("LCK not run after an 8-step thermal move");
    }
    // Out of measured thermal envelope -> Prerequisite.
    let _ = run(t.tick(&mut io, &auth, period(true)));
    io.set(0x3c00 + 0x42 * 4, 60 << 1);
    if run(t.tick(&mut io, &auth, period(true))) != Err(Error::Prerequisite) {
        return TestResult::Fail("thermal outside the measured envelope accepted");
    }
    if run(t.restore(&mut io, &auth)).is_err() || io.get(0x18a0) & 0x7f != 0 {
        return TestResult::Fail("restore kept a power-tracking delta");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/dm_engine",
    smoke_rtw88_dm_power_tracking_trigger_clamp_and_envelope
);

fn smoke_rtw88_dm_revoked_authority_writes_nothing() -> TestResult {
    let b = dm::bounds(0xc822, &payload(ALL, 0x40, 4, 4, 4, 4)).unwrap();
    let mut t = Tracker::new(b, c22_facts());
    let mut io = c22_regs();
    let auth = Auth(Cell::new(false));
    if run(t.tick(&mut io, &auth, period(true))) != Err(Error::Access) || !io.writes.is_empty() {
        return TestResult::Fail("revoked dm authority reached registers");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/dm_engine",
    smoke_rtw88_dm_revoked_authority_writes_nothing
);

fn smoke_rtw88_dm_c21_counters_dig_and_cck_pd() -> TestResult {
    let facts = Facts {
        did: 0xc821,
        rfe: 0,
        crystal: 0x20,
        thermal: [30, 0xff],
        power_track_type: 0,
        cck_gi: [0, 0],
    };
    let b = dm::bounds(0xc821, &payload(dm::DIG | dm::CCK_PD, 0x40, 4, 0, 0, 0)).unwrap();
    let mut t = Tracker::new(b, facts);
    let mut io = Regs::new();
    io.set(0xc50, 0x1c);
    io.set(0x808, 1 << 28);
    io.mem[0xaaa] = 6;
    io.mem[0xf48] = 0x20;
    io.mem[0xf49] = 0x03; // 800 OFDM FA
    io.mem[0xa5c] = 0xd0;
    io.mem[0xa5d] = 0x07; // 2000 CCK FA
    let auth = Auth(Cell::new(true));
    strong(&mut t, 10, 70);
    if run(t.tick(&mut io, &auth, period(true))).is_err() {
        return TestResult::Fail("C21 dm tick failed");
    }
    // FA 2800 > 750: 0x1c+4-2=0x1e, linked bound >= rssi(70)... lower clamp mid 0x40.
    if io.get(0xc50) & 0x7f != u32::from(t.igi()) || t.igi() < 0x1c {
        return TestResult::Fail("C21 DIG register mismatch");
    }
    // Counter reset pulses: 9a4 bit17 cleared, a2c bit15 set, b58 bit0 cleared.
    if io.get(0x9a4) & (1 << 17) != 0 || io.get(0xa2c) & (1 << 15) == 0 || io.get(0xb58) & 1 != 0 {
        return TestResult::Fail("8821c false-alarm reset sequence");
    }
    // Linked igi 0x40 > 0x38, rssi > 32 -> lv4: a08 pd=13, aa8 cs=6+8.
    if t.igi() != 0x40 || (io.get(0xa08) >> 16) & 0x3f != 13 || (io.get(0xaa8) >> 16) & 0x1f != 14 {
        return TestResult::Fail("8821c DIG bound or CCK PD level4 programming");
    }
    if io.wrote(0x1d70) || io.wrote(0x84c) || io.wrote(0x1040) {
        return TestResult::Fail("C21 touched C22-only registers");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/dm_engine",
    smoke_rtw88_dm_c21_counters_dig_and_cck_pd
);

fn smoke_rtw88_dm_phy_status_rssi_and_cfo_decode() -> TestResult {
    // 8822c page1: PWDB A=0x46 (-40dBm), B=0x3c (-50dBm), CFO tails 5/-3.
    let mut s = [0u8; 32];
    s[0] = 1;
    s[1] = 0x46;
    s[2] = 0x3c;
    s[20] = 5;
    s[21] = (-3i8) as u8;
    let Some(x) = dm::sample(&c22_facts(), 12, &s) else {
        return TestResult::Fail("8822c page1 sample refused");
    };
    if x.path_rssi != [Some(60), Some(50)]
        || x.cfo_tail != Some([5, -3])
        || x.rssi < 50
        || x.rssi > 60
    {
        return TestResult::Fail("8822c page1 RSSI/CFO decode");
    }
    // 8821c page0 CCK: lna_h=0 lna_l=2 -> -6dBm, vga 7 -> -20dBm -> rssi 80.
    let mut c = [0u8; 32];
    c[13] = (2 << 5) | 7;
    let f = Facts {
        did: 0xc821,
        rfe: 0,
        crystal: 0,
        thermal: [0xff; 2],
        power_track_type: 0,
        cck_gi: [0; 2],
    };
    if dm::sample(&f, 0, &c).map(|s| s.rssi) != Some(80) {
        return TestResult::Fail("8821c CCK LNA/VGA power decode");
    }
    if dm::rf_power_2_rssi(&[-110]) != 1 || dm::rf_power_2_rssi(&[0]) != 96 {
        return TestResult::Fail("rf_power_2_rssi saturation");
    }
    let mut bad = [0u8; 32];
    bad[0] = 2;
    if dm::sample(&f, 0, &bad).is_some() {
        return TestResult::Fail("unknown PHY-status page decoded");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/dm_engine",
    smoke_rtw88_dm_phy_status_rssi_and_cfo_decode
);
