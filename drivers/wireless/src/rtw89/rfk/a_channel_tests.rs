use super::super::super::{
    operating_channel_c::{Band, Width},
    power::{self, Io},
};
use super::super::Kind;
use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

/// Private RTL8852A MAC/BB/RF register model for the channel RFK: the
/// NCTL done byte reads 0x55 unless `stuck`; R_RPT_COM answers from
/// the KIP RPT1 selector and the DPK CFG3 byte 3; RR_TXMO reads
/// COI/COQ 0x10 unless `lok_fail` (both cores 0, so the LOK
/// fine-tune check fails).
struct Model {
    words: Vec<u32>,
    rf: [Vec<u32>; 2],
    trace: Vec<(u8, u32, u32)>,
    now: u64,
    stuck: Option<u32>,
    lok_fail: bool,
}
impl Model {
    fn new() -> Self {
        Self {
            words: vec![0; 0x20000 / 4],
            rf: core::array::from_fn(|_| vec![0; 0x100]),
            trace: Vec::new(),
            now: 0,
            stuck: None,
            lok_fail: false,
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
            // NCTL done byte 0 (IQK/DPK one-shot poll).
            0xbff8 => v = 0x55,
            // R_RPT_COM: SEL from R_KIP_RPT1 bits 21:16, CFG3 byte 3
            // from R_DPK_CFG3 bits 31:24. SEL 0: CORV 200 (pass),
            // CORI 0, DCI 1000 (dgain mapping 0), SYNERR 0. SEL 9:
            // DC I/Q 100 (pass). SEL 6: gain-loss index 3 in bits 7:4
            // and the PAS sums (val1 256/304, val2 512/560, so the
            // PAS check fails and the AGC settles by gain loss).
            0x80fc => {
                let sel = (self.word(0x80d4) >> 16) & 0x3f;
                let cfg3b3 = (self.word(0x80c0) >> 24) & 0xff;
                v = match (sel, cfg3b3) {
                    (0, _) => 0x03e8_c800,
                    (9, _) => 0x0064_0064,
                    (6, 0x1f) => 0x0200_0230,
                    (6, _) => 0x0100_0130,
                    _ => 0,
                };
            }
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
        if address == 0x58 {
            // RR_TXMO: COI/COQ 0x10 (LOK fine-tune passes), or 0.
            value = if self.lok_fail { 0 } else { 0x84000 };
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

/// TXPWR_TRK element bytes: LE bitmap 0xffff, 4 header bytes, then
/// 36 rows x 30 bytes, all 0x02.
fn tracking_fixture() -> Tracking {
    let mut bytes = vec![0u8; 1088];
    bytes[0] = 0xff;
    bytes[1] = 0xff;
    for slot in bytes.iter_mut().skip(8) {
        *slot = 0x02;
    }
    Tracking::parse(&bytes).expect("fixture TXPWR_TRK parses")
}

fn calibration_fixture() -> Calibration {
    Calibration {
        thermal: [0x20, 0x20],
        tssi_cck: [[1; 6]; 2],
        tssi_mcs: [[2; 19]; 2],
        tssi_trim: [[0; 8]; 2],
        trim_programmed: true,
        thermal_trim: [0; 2],
        thermal_programmed: false,
        pa_bias: [0; 2],
        pa_programmed: false,
    }
}

/// rtw8852a.c `rtw8852a_rfk_channel(PHY_0)` on channel 1 / 20MHz:
/// RX DCK, IQK, TSSI, DPK end to end, with the Kind brackets in
/// Linux order and the per-owner results retained.
fn smoke_rtw89_a_channel_rfk_iqk_dpk_tssi_follow_rtw8852a() -> TestResult {
    let mut io = Model::new();
    let mut channel = Channel::default();
    let calibration = calibration_fixture();
    let tracking = tracking_fixture();
    // SAFETY: private inert register/RF model; no hardware or DMA.
    if ready(unsafe {
        channel.rfk_channel(
            &mut io,
            Profile::INITIAL,
            &ChannelInputs {
                calibration: &calibration,
                tracking: &tracking,
                cut: 0,
                thermal: [0x20, 0x20],
                epa: [false, false],
            },
        )
    }) != Some(Ok(()))
        || channel.state() != State::Calibrated
        || channel.calibrated() != Some(Profile::INITIAL)
        || channel.tssi_mode() != [true, true]
    {
        return TestResult::Fail("RTL8852A channel RFK did not complete on a ready model");
    }
    // IQK: wideband TX group-select on both paths, narrowband RX on
    // 2G (nb_rxcfir is the debug RXIQC read OR 0x2), no LOK failure.
    let Some(iqk) = channel.iqk().results() else {
        return TestResult::Fail("RTL8852A channel RFK published no IQK results");
    };
    for path in iqk {
        if path.lok_fail
            || path.tx_fail
            || path.rx_fail
            || !path.is_wb_txiqk
            || path.is_wb_rxiqk
            || path.nb_txcfir != 0x4000_0000
            || path.nb_rxcfir != 0x2
        {
            return TestResult::Fail("RTL8852A IQK results differ on channel 1");
        }
    }
    if channel.iqk().times() != 2 {
        return TestResult::Fail("RTL8852A IQK did not run once per path");
    }
    // DPK: AGC settles by gain loss (0x38 - 3), both paths OK, the
    // DPK-time thermal retained, DPD_CH0A byte 3 = 0x07 (enabled).
    let Some(dpk) = channel.dpk().results() else {
        return TestResult::Fail("RTL8852A channel RFK published no DPK results");
    };
    for path in dpk {
        if !path.path_ok || path.txagc_dpk != 0x35 || path.ther_dpk != 0x20 {
            return TestResult::Fail("RTL8852A DPK results differ on channel 1");
        }
    }
    if channel.dpk().bypassed() || io.word(0x81bc) != 0x075b_5b5b || io.word(0x82bc) != 0x075b_5b5b
    {
        return TestResult::Fail("RTL8852A DPK enable words differ on channel 1");
    }
    // TSSI: DE (CCK 1, MCS 2) from the factory snapshot, thermal words
    // 0xFEFEFEFE (down, negated) then 0x02020202 (up) at both bases.
    let Some(tssi) = channel.tssi().results() else {
        return TestResult::Fail("RTL8852A channel RFK published no TSSI results");
    };
    if tssi.de != [[1, 2], [1, 2]]
        || tssi.base_thermal != [0x20, 0x20]
        || tssi.tracking_check != [false, false]
        || tssi.extra_ofst != [0, 0]
    {
        return TestResult::Fail("RTL8852A TSSI results differ on channel 1");
    }
    for base in [0x5c00, 0x7c00] {
        for i in 0..8 {
            if io.word(base + 4 * i) != 0xfefe_fefe {
                return TestResult::Fail("RTL8852A TSSI down thermal words differ");
            }
        }
        for i in 8..16 {
            if io.word(base + 4 * i) != 0x0202_0202 {
                return TestResult::Fail("RTL8852A TSSI up thermal words differ");
            }
        }
    }
    // Kind brackets in Linux order: RXDCK, IQK (with per-path
    // brackets), TSSI, DPK, each with its TX pause.
    let order: Vec<_> = io.trace.iter().filter(|t| t.0 >= 48).copied().collect();
    if order
        != [
            (48, Kind::Rxdck as u32, 0),
            (56, 0, 0),
            (60, 0, 0),
            (48, Kind::Rxdck as u32, 1),
            (48, Kind::Iqk as u32, 0),
            (56, 0, 0),
            (48, Kind::IqkPath as u32, 0),
            (48, Kind::IqkPath as u32, 1),
            (48, Kind::IqkPath as u32, 0),
            (48, Kind::IqkPath as u32, 1),
            (60, 0, 0),
            (48, Kind::Iqk as u32, 1),
            (48, Kind::Tssi as u32, 0),
            (48, Kind::Tssi as u32, 1),
            (48, Kind::Dpk as u32, 0),
            (56, 0, 0),
            (60, 0, 0),
            (48, Kind::Dpk as u32, 1),
        ]
    {
        return TestResult::Fail("RTL8852A channel RFK bracket order differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_a_channel_rfk_iqk_dpk_tssi_follow_rtw8852a
);

/// Same flow on 5GHz 80MHz (primary 36, center 42, subband 1):
/// wideband RX group-select, the LBK RXIQK path in the DPK AGC, and
/// the 5G_1 PAK program.
fn smoke_rtw89_a_channel_rfk_5ghz_80mhz_follow_rtw8852a() -> TestResult {
    let Some(profile) = Profile::new_wide(Band::Ghz5, 36, Width::Mhz80) else {
        return TestResult::Fail("5GHz 80MHz profile did not build");
    };
    if profile.center() != 42 || profile.subband() != 1 {
        return TestResult::Fail("5GHz 80MHz profile geometry differs");
    }
    let mut io = Model::new();
    let mut channel = Channel::default();
    let calibration = calibration_fixture();
    let tracking = tracking_fixture();
    // SAFETY: private inert register/RF model; no hardware or DMA.
    if ready(unsafe {
        channel.rfk_channel(
            &mut io,
            profile,
            &ChannelInputs {
                calibration: &calibration,
                tracking: &tracking,
                cut: 0,
                thermal: [0x20, 0x20],
                epa: [false, false],
            },
        )
    }) != Some(Ok(()))
        || channel.state() != State::Calibrated
    {
        return TestResult::Fail("RTL8852A channel RFK did not complete on 5GHz 80MHz");
    }
    let Some(iqk) = channel.iqk().results() else {
        return TestResult::Fail("RTL8852A 5GHz channel RFK published no IQK results");
    };
    for path in iqk {
        if path.lok_fail || !path.is_wb_txiqk || !path.is_wb_rxiqk {
            return TestResult::Fail("RTL8852A IQK is not wideband on 5GHz 80MHz");
        }
    }
    let Some(dpk) = channel.dpk().results() else {
        return TestResult::Fail("RTL8852A 5GHz channel RFK published no DPK results");
    };
    for path in dpk {
        if !path.path_ok || path.txagc_dpk != 0x35 || path.bw != Width::Mhz80 {
            return TestResult::Fail("RTL8852A DPK results differ on 5GHz 80MHz");
        }
    }
    // The LBK RXIQK one-shot ran (NCTL_CFG command 0x619: LBK_RXIQK
    // 0x06, path A) and the 5G_1 PAK tables ran on both paths.
    if !io
        .trace
        .iter()
        .any(|t| t.0 == 4 && t.1 == 0x1_8000 && t.2 == 0x619)
        || !io
            .trace
            .iter()
            .any(|t| t.0 == 4 && t.1 == 0x1_8000 && t.2 == 0x629)
    {
        return TestResult::Fail("RTL8852A DPK LBK RXIQK one-shot did not run");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_a_channel_rfk_5ghz_80mhz_follow_rtw8852a
);

/// A stuck NCTL done bit fails closed with a timeout and the owner
/// refuses a replay.
fn smoke_rtw89_a_channel_rfk_stuck_done_fails_closed() -> TestResult {
    let mut io = Model::new();
    io.stuck = Some(0xbff8);
    let mut channel = Channel::default();
    let calibration = calibration_fixture();
    let tracking = tracking_fixture();
    // SAFETY: private inert register/RF model; no hardware or DMA.
    let first = ready(unsafe {
        channel.rfk_channel(
            &mut io,
            Profile::INITIAL,
            &ChannelInputs {
                calibration: &calibration,
                tracking: &tracking,
                cut: 0,
                thermal: [0x20, 0x20],
                epa: [false, false],
            },
        )
    });
    // SAFETY: same inert model; the failed owner must refuse a replay.
    let replay = ready(unsafe {
        channel.rfk_channel(
            &mut io,
            Profile::INITIAL,
            &ChannelInputs {
                calibration: &calibration,
                tracking: &tracking,
                cut: 0,
                thermal: [0x20, 0x20],
                epa: [false, false],
            },
        )
    });
    if first != Some(Err(Error::Register(power::Error::Timeout)))
        || channel.state() != State::Busy
        || channel.calibrated().is_some()
        || replay != Some(Err(Error::Terminal))
    {
        return TestResult::Fail("stuck RTL8852A channel RFK poll did not fail closed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_a_channel_rfk_stuck_done_fails_closed
);

/// With an external PA on 2G, DPK is force-bypassed: no main run,
/// DPD_CH0A byte 3 stays 0x06 (disabled), `bypassed` is retained.
fn smoke_rtw89_a_channel_rfk_dpk_bypass_epa_2g() -> TestResult {
    let mut io = Model::new();
    let mut channel = Channel::default();
    let calibration = calibration_fixture();
    let tracking = tracking_fixture();
    // SAFETY: private inert register/RF model; no hardware or DMA.
    if ready(unsafe {
        channel.rfk_channel(
            &mut io,
            Profile::INITIAL,
            &ChannelInputs {
                calibration: &calibration,
                tracking: &tracking,
                cut: 0,
                thermal: [0x20, 0x20],
                epa: [true, false],
            },
        )
    }) != Some(Ok(()))
        || channel.state() != State::Calibrated
    {
        return TestResult::Fail("RTL8852A channel RFK did not complete with EPA on 2G");
    }
    let Some(dpk) = channel.dpk().results() else {
        return TestResult::Fail("RTL8852A bypassed DPK published no results");
    };
    if !channel.dpk().bypassed()
        || dpk.iter().any(|path| path.path_ok)
        || io.word(0x81bc) != 0x0600_0000
        || io.word(0x82bc) != 0x0600_0000
    {
        return TestResult::Fail("RTL8852A DPK bypass differs with EPA on 2G");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_a_channel_rfk_dpk_bypass_epa_2g
);

/// The band-change TSSI scan runs without I/O before calibration and
/// re-runs the TSSI program after it; track is a no-op until
/// `_tssi_high_power` lands (`tracking_check` stays false).
fn smoke_rtw89_a_channel_rfk_tssi_scan_and_track() -> TestResult {
    let mut io = Model::new();
    let mut channel = Channel::default();
    let calibration = calibration_fixture();
    let tracking = tracking_fixture();
    let Some(profile) = Profile::new_wide(Band::Ghz5, 36, Width::Mhz80) else {
        return TestResult::Fail("5GHz 80MHz profile did not build");
    };
    // SAFETY: private inert register/RF model; no hardware or DMA.
    if ready(unsafe { channel.scan(&mut io, profile, &calibration, &tracking, [0x20, 0x20]) })
        != Some(Ok(false))
        || !io.trace.is_empty()
    {
        return TestResult::Fail("RTL8852A TSSI scan ran before calibration");
    }
    // SAFETY: private inert register/RF model; no hardware or DMA.
    if ready(unsafe {
        channel.rfk_channel(
            &mut io,
            Profile::INITIAL,
            &ChannelInputs {
                calibration: &calibration,
                tracking: &tracking,
                cut: 0,
                thermal: [0x20, 0x20],
                epa: [false, false],
            },
        )
    }) != Some(Ok(()))
    {
        return TestResult::Fail("RTL8852A channel RFK did not complete for the scan test");
    }
    io.trace.clear();
    // SAFETY: private inert register/RF model; no hardware or DMA.
    if ready(unsafe { channel.scan(&mut io, profile, &calibration, &tracking, [0x21, 0x21]) })
        != Some(Ok(true))
        || channel.tssi().results().map(|r| r.base_thermal) != Some([0x21, 0x21])
    {
        return TestResult::Fail("RTL8852A TSSI scan did not run after calibration");
    }
    // SAFETY: private inert register/RF model; no hardware or DMA.
    if ready(unsafe { channel.track(&mut io, [0x22, 0x22]) }) != Some(Ok(()))
        || channel.tssi().results().map(|r| r.extra_ofst) != Some([0, 0])
    {
        return TestResult::Fail("RTL8852A TSSI track wrote offsets before high_power");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_a_channel_rfk_tssi_scan_and_track
);

/// A LOK fine-tune failure on both paths refuses the channel RFK.
fn smoke_rtw89_a_channel_rfk_lok_failure_refuses() -> TestResult {
    let mut io = Model::new();
    io.lok_fail = true;
    let mut channel = Channel::default();
    let calibration = calibration_fixture();
    let tracking = tracking_fixture();
    // SAFETY: private inert register/RF model; no hardware or DMA.
    if ready(unsafe {
        channel.rfk_channel(
            &mut io,
            Profile::INITIAL,
            &ChannelInputs {
                calibration: &calibration,
                tracking: &tracking,
                cut: 0,
                thermal: [0x20, 0x20],
                epa: [false, false],
            },
        )
    }) != Some(Err(Error::Terminal))
        || channel.state() != State::Busy
        || channel.calibrated().is_some()
        || channel.iqk().results().is_some()
    {
        return TestResult::Fail("RTL8852A LOK failure did not refuse the channel RFK");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_a_channel_rfk_lok_failure_refuses
);

/// 6GHz is not an 8852A band: the channel RFK refuses it with a
/// policy error (after the RX DCK, in IQK) and the owner stays busy.
fn smoke_rtw89_a_channel_rfk_6ghz_refused() -> TestResult {
    let Some(profile) = Profile::new_wide(Band::Ghz6, 5, Width::Mhz20) else {
        return TestResult::Fail("6GHz 20MHz profile did not build");
    };
    let mut io = Model::new();
    let mut channel = Channel::default();
    let calibration = calibration_fixture();
    let tracking = tracking_fixture();
    // SAFETY: private inert register/RF model; no hardware or DMA.
    if ready(unsafe {
        channel.rfk_channel(
            &mut io,
            profile,
            &ChannelInputs {
                calibration: &calibration,
                tracking: &tracking,
                cut: 0,
                thermal: [0x20, 0x20],
                epa: [false, false],
            },
        )
    }) != Some(Err(Error::Policy))
        || channel.state() != State::Busy
    {
        return TestResult::Fail("RTL8852A channel RFK did not refuse 6GHz");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_a_channel_rfk_6ghz_refused
);
