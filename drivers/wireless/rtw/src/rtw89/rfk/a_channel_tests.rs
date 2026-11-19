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
    stall_pre_tx: bool,
    fail_pre_tx: bool,
    denied: bool,
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
            stall_pre_tx: false,
            fail_pre_tx: false,
            denied: false,
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
        // Independent source actor: the real A PMAC start/period/count
        // produces observations only during its actual15ms enabled window.
        if us == 15_000 && self.word(0x09c4) & 0x10 != 0 {
            if self.stall_pre_tx {
                core::future::pending::<()>().await;
            }
            if self.fail_pre_tx {
                self.denied = true;
            }
            self.words[0x11a40 / 4] = self.word(0x1a40).wrapping_add(3);
            self.words[0x11c60 / 4] = 0x1200_0000;
            self.words[0x13c60 / 4] = 0x3400_0000;
        }
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl Interface for Model {
    fn admit(&mut self) -> Result<(), Error> {
        if self.denied {
            Err(power::Error::Access.into())
        } else {
            Ok(())
        }
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
/// RX DCK, IQK, partial TSSI and DPK, with the Kind brackets in
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
                tail: None,
            },
        )
    }) != Some(Ok(Outcome::PartialTssi))
        || channel.state() != State::PartialTssi
        || channel.calibrated().is_some()
        || channel.partial_programmed() != Some(Profile::INITIAL)
        || channel.tssi_mode() != [true, true]
    {
        return TestResult::Fail("RTL8852A partial RFK did not program on a ready model");
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
                tail: None,
            },
        )
    }) != Some(Ok(Outcome::PartialTssi))
        || channel.state() != State::PartialTssi
    {
        return TestResult::Fail("RTL8852A partial RFK did not program on 5GHz 80MHz");
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
                tail: None,
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
                tail: None,
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
                tail: None,
            },
        )
    }) != Some(Ok(Outcome::PartialTssi))
        || channel.state() != State::PartialTssi
    {
        return TestResult::Fail("RTL8852A partial RFK did not program with EPA on 2G");
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
        return TestResult::Fail("RTL8852A TSSI scan ran before programming");
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
                tail: None,
            },
        )
    }) != Some(Ok(Outcome::PartialTssi))
    {
        return TestResult::Fail("RTL8852A partial RFK did not program for the scan test");
    }
    io.trace.clear();
    // SAFETY: private inert register/RF model; no hardware or DMA.
    if ready(unsafe { channel.scan(&mut io, profile, &calibration, &tracking, [0x21, 0x21]) })
        != Some(Ok(true))
        || channel.tssi().results().map(|r| r.base_thermal) != Some([0x21, 0x21])
    {
        return TestResult::Fail("RTL8852A TSSI scan did not run after partial programming");
    }
    let before = io.trace.clone();
    // SAFETY: private inert partial model; full tracking must refuse before
    // even DPK I/O, because high_power/pre_tx have never completed.
    if ready(unsafe { channel.track(&mut io, [0x22, 0x22]) }) != Some(Err(Error::Terminal))
        || io.trace != before
        || channel.calibrated().is_some()
        || channel.state() != State::PartialTssi
        || channel.tssi().results().map(|r| r.extra_ofst) != Some([0, 0])
    {
        return TestResult::Fail("RTL8852A partial TSSI minted calibration/tracking");
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
                tail: None,
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
                tail: None,
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

fn smoke_rtw8852a_full_tssi_tail_retains_source_pmac_receipts_and_full_rfk() -> TestResult {
    for (profile, mcs, ofdm, expected_power, tracking_enabled) in [
        (Profile::INITIAL, 60, 36, 72, false),
        (Profile::INITIAL, 80, 37, 68, true),
        (
            Profile::new_wide(Band::Ghz5, 36, Width::Mhz80).unwrap(),
            80,
            -6,
            -12,
            false,
        ),
    ] {
        let mut io = Model::new();
        io.words[0x11a40 / 4] = 7;
        let mut channel = Channel::default();
        let calibration = calibration_fixture();
        let tracking = tracking_fixture();
        // SAFETY: private inert source actor supplies literal PMAC counter
        // and TXAGC observations; no physical RF or native grant is created.
        let outcome = ready(unsafe {
            channel.rfk_channel(
                &mut io,
                profile,
                &ChannelInputs {
                    calibration: &calibration,
                    tracking: &tracking,
                    cut: 0,
                    thermal: [32, 33],
                    epa: [false, false],
                    tail: Some(tail::Inputs::fixture(profile, mcs, ofdm)),
                },
            )
        });
        let Some(receipt) = channel.tssi().complete() else {
            return TestResult::Fail("full A tail receipt absent");
        };
        if outcome != Some(Ok(Outcome::Calibrated))
            || channel.calibrated() != Some(profile)
            || receipt.before != 7
            || receipt.after != 10
            || receipt.count != 3
            || receipt.power != expected_power
            || receipt.default_txagc != [Some(0x12), Some(0x34)]
            || channel.tssi().results().map(|r| r.tracking_check) != Some([tracking_enabled; 2])
            || io.word(0x09c4) & 0x10 != 0
            || io.word(0x0980) & 0x10001 != 0
            || io.word(0x09a4) & 0x1041c != 0
            || io.word(0x09c8) != 20
            || (io.word(0x09c4) >> 8) != 5000
            || !io.trace.contains(&(4, 0x14530, 0x4e1f3e81))
            || !io
                .trace
                .iter()
                .any(|t| t.0 == 4 && t.1 == 0x178dc && t.2 & 0xc0000000 == 0x40000000)
            || !io
                .trace
                .iter()
                .any(|t| t.0 == 4 && t.1 == 0x178dc && t.2 & 0xc0000000 == 0xc0000000)
        {
            return TestResult::Fail("A full source pre-TX power/path/pulse/receipt differs");
        }
        // The source writes MAC_SEL for PHY0 and PHY1 onto PHY0 in SCC.
        let duplicate = io
            .trace
            .windows(2)
            .any(|w| w[0].0 == 4 && w[0].1 == 0x109a4 && w[0] == w[1] && w[0].2 & 0x1c == 0x1c);
        if !duplicate {
            return TestResult::Fail("A non-DBCC PHY1 duplicate MAC_SEL write elided");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_full_tssi_tail_retains_source_pmac_receipts_and_full_rfk
);

fn smoke_rtw8852a_full_tssi_tail_failure_or_drop_cannot_publish_calibration() -> TestResult {
    for cancelled in [false, true] {
        let mut io = Model::new();
        io.stall_pre_tx = cancelled;
        io.fail_pre_tx = !cancelled;
        let mut channel = Channel::default();
        let calibration = calibration_fixture();
        let tracking = tracking_fixture();
        // SAFETY: source-only model; cancellation/error occurs inside actual
        // production15ms wait, with PMAC still owned by the retained channel.
        let outcome = ready(unsafe {
            channel.rfk_channel(
                &mut io,
                Profile::INITIAL,
                &ChannelInputs {
                    calibration: &calibration,
                    tracking: &tracking,
                    cut: 0,
                    thermal: [32, 33],
                    epa: [false, false],
                    tail: Some(tail::Inputs::fixture(Profile::INITIAL, 60, 36)),
                },
            )
        });
        if outcome
            != if cancelled {
                None
            } else {
                Some(Err(Error::Register(power::Error::Access)))
            }
            || channel.state() != State::Busy
            || channel.calibrated().is_some()
            || channel.tssi().complete().is_some()
            || channel.tssi().results().is_some()
            || io.word(0x09c4) & 0x10 == 0
        {
            return TestResult::Fail("uncertain A autonomous PMAC fabricated full completion");
        }
        let before = io.trace.clone();
        // SAFETY: same retained Busy owner must refuse retry before effects.
        if ready(unsafe {
            channel.rfk_channel(
                &mut io,
                Profile::INITIAL,
                &ChannelInputs {
                    calibration: &calibration,
                    tracking: &tracking,
                    cut: 0,
                    thermal: [32, 33],
                    epa: [false, false],
                    tail: Some(tail::Inputs::fixture(Profile::INITIAL, 60, 36)),
                },
            )
        }) != Some(Err(Error::Terminal))
            || io.trace != before
        {
            return TestResult::Fail("A cancelled full channel owner revived");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_full_tssi_tail_failure_or_drop_cannot_publish_calibration
);

fn smoke_rtw8852a_tracking_requires_only_actual_supported_band_rows() -> TestResult {
    // Firmware bitmap0xfff0: four5G types*three rows + eight2G types.
    let mut bytes = vec![0; 608];
    bytes[..4].copy_from_slice(&0xfff0u32.to_le_bytes());
    let mut offset = 8;
    for kind in 4..16u8 {
        let count = if kind < 8 { 3 } else { 1 };
        for _ in 0..count {
            bytes[offset..offset + 30].fill(kind);
            offset += 30;
        }
    }
    let Ok(track) = Tracking::parse(&bytes) else {
        return TestResult::Fail("A parser demanded unsupported6G rows");
    };
    if track.rows(0, 0) != (&[11; 30], &[10; 30])
        || track.rows(0, 1) != (&[9; 30], &[8; 30])
        || track.rows(4, 0) != (&[7; 30], &[6; 30])
        || track.rows(4, 1) != (&[5; 30], &[4; 30])
        || Tracking::parse(&bytes[..607]).is_ok()
    {
        return TestResult::Fail("A supported-band source row selection/truncation differs");
    }
    bytes[1] &= !0x10; // mandatory source2G CCK row12, even though OFDM uses10/11.
    if Tracking::parse(&bytes).is_ok() {
        return TestResult::Fail("A accepted missing mandatory source tracking row");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_tracking_requires_only_actual_supported_band_rows
);
