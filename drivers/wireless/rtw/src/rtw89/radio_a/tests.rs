use super::*;
use crate::rtw89::{
    factory::Identity,
    mac::ChipId,
    phy_operating,
    power::{self, Io},
    radio_table::Pair,
    rfk,
};
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

/// Private RTL8852A MAC/BB/RF register model: the `rfk::a` model plus the
/// crystal array `phy_operating` needs. ADDCK/DACK done bits read as set
/// unless `stuck` (BB offset, or 0x100000 + RF).
struct Model {
    words: Vec<u32>,
    rf: [Vec<u32>; 2],
    xtal: [u8; 256],
    trace: Vec<(u8, u32, u32)>,
    now: u64,
    stuck: Option<u32>,
    stall_delay: Option<u64>,
}
impl Model {
    fn new() -> Self {
        Self {
            words: vec![0; 0x20000 / 4],
            rf: core::array::from_fn(|_| vec![0; 0x100]),
            xtal: [0; 256],
            trace: Vec::new(),
            now: 0,
            stuck: None,
            stall_delay: None,
        }
    }
    fn word(&self, address: u32) -> u32 {
        self.words[(0x10000 + address) as usize / 4]
    }
}
impl Io for Model {
    fn read8(&mut self, address: u32) -> Result<u8, power::Error> {
        Ok((self.words[address as usize / 4] >> ((address & 3) * 8)) as u8)
    }
    fn read16(&mut self, address: u32) -> Result<u16, power::Error> {
        Ok((self.words[address as usize / 4] >> ((address & 3) * 8)) as u16)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        let mut v = self.words[a as usize / 4];
        if a < 0x10000 {
            return Ok(v);
        }
        let r = a - 0x10000;
        match r {
            0xbff8 => v = 0x55,
            0x80fc => {
                let sel = (self.word(0x80d4) >> 16) & 0x3f;
                let cfg = (self.word(0x80c0) >> 24) & 0xff;
                v = match (sel, cfg) {
                    (0, _) => 0x03e8_c800,
                    (9, _) => 0x0064_0064,
                    (6, 0x1f) => 0x0200_0230,
                    (6, _) => 0x0100_0130,
                    _ => 0,
                };
            }
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
    fn write8(&mut self, address: u32, value: u8) -> Result<(), power::Error> {
        let shift = (address & 3) * 8;
        let word = &mut self.words[address as usize / 4];
        *word = (*word & !(0xff << shift)) | (u32::from(value) << shift);
        self.trace.push((1, address, u32::from(value)));
        Ok(())
    }
    fn write16(&mut self, address: u32, value: u16) -> Result<(), power::Error> {
        let shift = (address & 3) * 8;
        let word = &mut self.words[address as usize / 4];
        *word = (*word & !(0xffff << shift)) | (u32::from(value) << shift);
        self.trace.push((2, address, u32::from(value)));
        Ok(())
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
        if self.stall_delay == Some(us) {
            core::future::pending::<()>().await;
        }
        self.now += us;
        if us == 15_000 && self.word(0x09c4) & 0x10 != 0 {
            self.words[0x11a40 / 4] = self.word(0x1a40).wrapping_add(3);
            self.words[0x11c60 / 4] = 0x1200_0000;
            self.words[0x13c60 / 4] = 0x3400_0000;
        }
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl rfk::Interface for Model {
    fn admit(&mut self) -> Result<(), rfk::Error> {
        Ok(())
    }
    async fn rf_read(&mut self, path: u8, address: u32, mask: u32) -> Result<u32, rfk::Error> {
        let mut value = self.rf[usize::from(path)][(address & 0xff) as usize];
        match address {
            0x58 => value = 0x84000,
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
    ) -> Result<(), rfk::Error> {
        let slot = &mut self.rf[usize::from(path)][(address & 0xff) as usize];
        *slot = (*slot & !mask) | ((value << mask.trailing_zeros()) & mask);
        self.trace.push((16 + path, address, value));
        Ok(())
    }
    async fn begin(&mut self, kind: rfk::Kind) -> Result<(), rfk::Error> {
        self.trace.push((48, kind as u32, 0));
        Ok(())
    }
    async fn end(&mut self, kind: rfk::Kind) -> Result<(), rfk::Error> {
        self.trace.push((48, kind as u32, 1));
        Ok(())
    }
    async fn pause(&mut self) -> Result<u32, rfk::Error> {
        self.trace.push((56, 0, 0));
        Ok(0)
    }
    async fn resume(&mut self, _: u32) -> Result<(), rfk::Error> {
        self.trace.push((60, 0, 0));
        Ok(())
    }
}
impl phy_operating::Interface for Model {
    fn admit(&mut self) -> Result<(), rfk::Error> {
        Ok(())
    }
    async fn xtal_write(&mut self, a: u8, v: u8, m: u8) -> Result<(), rfk::Error> {
        self.xtal[usize::from(a)] = (self.xtal[usize::from(a)] & !m) | (v & m);
        self.trace.push((8, u32::from(a), u32::from(v)));
        Ok(())
    }
    async fn xtal_read(&mut self, a: u8) -> Result<u8, rfk::Error> {
        self.trace
            .push((9, u32::from(a), u32::from(self.xtal[usize::from(a)])));
        Ok(self.xtal[usize::from(a)])
    }
}
fn ready<T>(f: impl Future<Output = T>) -> Option<T> {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}
fn identity() -> Identity {
    crate::rtw89::station_control::tests::factory_with_chip(ChipId::Rtl8852A, false)
        .identity()
        .expect("rtw8852a test identity")
}
fn calibration() -> factory_a::Calibration {
    factory_a::Calibration {
        thermal: [0x0b, 0x1e],
        tssi_cck: [[0; 6]; 2],
        tssi_mcs: [[0; 19]; 2],
        tssi_trim: [[0; 8]; 2],
        trim_programmed: false,
        thermal_trim: [0x0b, 0x1e],
        thermal_programmed: true,
        pa_bias: [0x5a, 0x3c],
        pa_programmed: true,
    }
}

/// `rtw8852a_power_trim` is the pure tail of the owner recipe:
/// `__thm_setting` (0x1f mask, not C's 0x0e) then PA bias TXG/TXA.
/// Raw 0x1e retains bit4 through the shift, producing 0xf rather than 0x7.
fn smoke_rtw89_a_power_trim_writes_follow_rtw8852a() -> TestResult {
    let writes = power_trim_writes(&calibration());
    if writes
        != vec![
            (0, 0x43, 0xf_0000, 0xd),
            (1, 0x43, 0xf_0000, 0xf),
            (0, 0x60, 0xf000, 0xa),
            (0, 0x60, 0xf_0000, 0x5),
            (1, 0x60, 0xf000, 0xc),
            (1, 0x60, 0xf_0000, 0x3),
        ]
    {
        return TestResult::Fail("RTL8852A power trim writes differ");
    }
    let unprogrammed = factory_a::Calibration {
        thermal_programmed: false,
        pa_programmed: false,
        ..calibration()
    };
    if !power_trim_writes(&unprogrammed).is_empty() {
        return TestResult::Fail("RTL8852A unprogrammed trim writes are not empty");
    }
    TestResult::Pass
}

/// End to end through the fixture: bb_sethw + DM sub-inits + NCTL, then
/// RFK init + set_txpwr_ctrl + power trim; the owner lands Ready with
/// epoch 1 and still no channel (the set_channel lane follows #2098).
fn smoke_rtw89_a_owner_prepare_controls_then_prepare() -> TestResult {
    let mut io = Model::new();
    io.words[0x18080 / 4] = 4;
    let mut operating = phy_operating::Operating::default();
    let mut radio = Radio::default();
    let id = identity();
    // SAFETY: private inert register/RF model; no hardware or DMA.
    let controls = ready(unsafe {
        radio.prepare_controls(&mut io, &mut operating, id, &[Pair(0x8040, 0x12345)])
    });
    if controls != Some(Ok(())) || radio.state() != State::New {
        return TestResult::Fail("RTL8852A prepare_controls did not complete");
    }
    if operating.state() != phy_operating::State::Prepared {
        return TestResult::Fail("RTL8852A DM sub-inits did not prepare");
    }
    let cap = id.xtal() & 0x7f;
    if io.words[0x0280 / 4] & 0x00ff_fc00 != ((u32::from(cap) << 17) | (u32::from(cap) << 10))
        || io.trace.iter().any(|event| event.0 == 8)
        || io.word(0x0c08) & (1 << 18) == 0
        || io.word(0x0c14) & 0x30000 != 0x30000
        || (id.cut() <= 1
            && (operating.a_gains().is_none()
                || (io.word(0x4668) >> 24) & 7 != 6
                || (io.word(0x473c) >> 24) & 7 != 6
                || (io.word(0x4674) >> 17) & 1 != 1
                || (io.word(0x4748) >> 17) & 1 != 1
                || (io.word(0x4658) >> 5) & 31 != 31
                || (io.word(0x472c) >> 5) & 31 != 31))
    {
        return TestResult::Fail("A retained environment/gain init or direct XTAL source differs");
    }
    if io.words[0x10dc0 / 4] != 0x864f_a000
        || io.words[0x14404 / 4] != 0x7c00
        || io.words[0x10c60 / 4] != 3
        || io.words[0x18040 / 4] != 0x12345
    {
        return TestResult::Fail("RTL8852A bb_sethw / DM / NCTL words differ");
    }
    let calibration = calibration();
    // SAFETY: same private model directly after prepare_controls.
    let prepared = ready(unsafe {
        radio.prepare(
            &mut io,
            Inputs {
                calibration: &calibration,
            },
        )
    });
    if prepared != Some(Ok(()))
        || radio.state() != State::Ready
        || radio.epoch() != 1
        || radio.channel().is_some()
    {
        return TestResult::Fail("RTL8852A prepare did not land Ready with epoch 1");
    }
    if radio.init().state() != rfk::State::BasicCalibrated {
        return TestResult::Fail("RTL8852A RFK init did not calibrate");
    }
    // `rtw8852a_set_txpwr_ctrl` = `rtw8852a_set_txpwr_ref`: R_AX_PWR_RATE_CTRL
    // cleared, the four 0x5804.. reference words set.
    if io.words[0xd200 / 4] != 0
        || io.words[0x15804 / 4] != 0x02b2_7000
        || io.words[0x17804 / 4] != 0x02b2_7000
        || io.words[0x15808 / 4] != 0x02b2_7000
        || io.words[0x17808 / 4] != 0x02b2_7000
    {
        return TestResult::Fail("RTL8852A set_txpwr_ctrl reference words differ");
    }
    // Power trim landed in the RF pages: TM2 OFF then BIASA TXG/TXA.
    if io.rf[0][0x43] != 0xd0000
        || io.rf[1][0x43] != 0xf0000
        || io.rf[0][0x60] != 0x5a000
        || io.rf[1][0x60] != 0x3c000
    {
        return TestResult::Fail("RTL8852A power trim RF words differ");
    }
    io.rf[0][0x42] = 22 << 1;
    io.rf[1][0x42] = 42 << 1;
    let plan = crate::rtw89::channel_a::tests::power_plan(
        crate::rtw89::operating_channel::Profile::INITIAL,
    );
    // SAFETY: same exclusively owned inert source model after its actual
    // init, with no ordinary packet/TSSI/PM producer or calibration claim.
    let programmed = ready(unsafe {
        radio.program_channel(
            &mut io,
            crate::rtw89::operating_channel::Profile::INITIAL,
            &plan,
        )
    });
    if programmed != Some(Ok(()))
        || radio.epoch() != 2
        || radio.programmed_channel() != Some(crate::rtw89::operating_channel::Profile::INITIAL)
        || radio.channel().is_some()
        || radio.fem() != factory_a::Fem::from_identity(id)
        || radio.observations()
            != Some(observations::Snapshot {
                sample: [22, 42],
                average: [22, 42],
                last_thermal_max: 42,
            })
    {
        return TestResult::Fail(
            "A programmed channel did not retain actual FEM/live sensor facts",
        );
    }
    let mut track_bytes = vec![2; 608];
    track_bytes[..8].copy_from_slice(&[0xf0, 0xff, 0, 0, 0, 0, 0, 0]);
    let tracking = rfk::a_tssi::Tracking::parse(&track_bytes).unwrap();
    // SAFETY: same retained inert A radio, actual modeled FEM/live thermal
    // after channel programming, exact source-tail actor, no station grants.
    let completed = ready(unsafe {
        radio.complete_channel(
            &mut io,
            ChannelInputs {
                calibration: &calibration,
                tracking: &tracking,
                tail: rfk::a_tssi::tail::Inputs::fixture(
                    crate::rtw89::operating_channel_c::Profile::INITIAL,
                    60,
                    36,
                ),
            },
        )
    });
    if completed != Some(Ok(()))
        || radio.epoch() != 3
        || radio.channel() != Some(crate::rtw89::operating_channel::Profile::INITIAL)
        || radio.channel_rfk().tssi().complete().map(|r| r.count) != Some(3)
    {
        return TestResult::Fail("A retained source radio composed no actual complete RFK receipt");
    }
    // A second prepare on the same (now Ready) owner is terminal. (Prepare
    // before controls is not: like the C/51 owners, `prepare` runs from
    // `New` and the controls-first order is the native caller's contract.)
    // SAFETY: same private model; the owner is Ready, so this must fail terminally.
    let again = ready(unsafe {
        radio.prepare(
            &mut io,
            Inputs {
                calibration: &calibration,
            },
        )
    });
    if again != Some(Err(rfk::Error::Terminal)) {
        return TestResult::Fail("RTL8852A double prepare is not terminal");
    }
    // Retunes retain the original RFK/TSSI/DPK and source EWMA owners.
    // First stay in-band, then cross to a genuine 5GHz/80MHz source plan.
    for (profile, epoch, thermal) in [
        (
            crate::rtw89::operating_channel::Profile::from_primary(6).unwrap(),
            4,
            [30, 0],
        ),
        (
            crate::rtw89::operating_channel::Profile::new_5ghz(
                36,
                crate::rtw89::operating_channel::Width::Mhz80,
            )
            .unwrap(),
            5,
            [34, 46],
        ),
    ] {
        let plan = crate::rtw89::channel_a::tests::power_plan(profile);
        io.words[0x11c10 / 4] = thermal[0] << 24;
        io.words[0x13c10 / 4] = thermal[1] << 24;
        let old_counter = io.word(0x1a40);
        // SAFETY: same retained inert source model after completed TSSI;
        // exact target plan/thermal actor, no ordinary producer exists.
        if ready(unsafe {
            radio.retune(
                &mut io,
                profile,
                &plan,
                ChannelInputs {
                    calibration: &calibration,
                    tracking: &tracking,
                    tail: rfk::a_tssi::tail::Inputs::fixture(plan.channel(), 60, 36),
                },
            )
        }) != Some(Ok(()))
            || radio.channel() != Some(profile)
            || radio.epoch() != epoch
            || radio.channel_rfk().tssi_mode() != [true, true]
            || radio
                .channel_rfk()
                .tssi()
                .complete()
                .map(|r| (r.before, r.after, r.count))
                != Some((old_counter as u16, old_counter.wrapping_add(3) as u16, 3))
        {
            return TestResult::Fail(
                "A retune lost retained RFK/TSSI history or fresh PMAC receipt",
            );
        }
    }
    if radio.observations().map(|s| s.average) != Some([26, 43]) {
        return TestResult::Fail("A retune replaced source EWMA history");
    }
    let target = crate::rtw89::operating_channel::Profile::from_primary(11).unwrap();
    let plan = crate::rtw89::channel_a::tests::power_plan(target);
    io.stall_delay = Some(40);
    // SAFETY: drop actual retained source operation in the channel help wait.
    if ready(unsafe {
        radio.retune(
            &mut io,
            target,
            &plan,
            ChannelInputs {
                calibration: &calibration,
                tracking: &tracking,
                tail: rfk::a_tssi::tail::Inputs::fixture(plan.channel(), 60, 36),
            },
        )
    })
    .is_some()
        || radio.state() != State::Preparing
        || radio.channel().is_some()
        || radio.epoch() != 5
        || radio.channel.state() != crate::rtw89::channel_a::State::Busy
    {
        return TestResult::Fail("A dropped retune published old/new channel or reset owner");
    }
    let before = io.trace.len();
    // SAFETY: same uncertain retained owner must refuse any new effect.
    if ready(unsafe {
        radio.retune(
            &mut io,
            target,
            &plan,
            ChannelInputs {
                calibration: &calibration,
                tracking: &tracking,
                tail: rfk::a_tssi::tail::Inputs::fixture(plan.channel(), 60, 36),
            },
        )
    }) != Some(Err(rfk::Error::Terminal))
        || io.trace.len() != before
    {
        return TestResult::Fail("A dropped retained retune replayed failed source owner");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_a_power_trim_writes_follow_rtw8852a
);
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_a_owner_prepare_controls_then_prepare
);
