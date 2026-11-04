use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Model {
    words: Vec<u32>,
    writes: Vec<u32>,
    ignore: Option<u32>,
}
impl Model {
    fn new(seed: u32) -> Self {
        Self {
            words: vec![seed; 0x20000 / 4],
            writes: Vec::new(),
            ignore: None,
        }
    }
    fn word(&self, address: u32) -> u32 {
        self.words[address as usize / 4]
    }
    fn field(&self, address: u32, mask: u32) -> u32 {
        (self.word(address) & mask) >> mask.trailing_zeros()
    }
}
impl Io for Model {
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        Ok(self.words[a as usize / 4].to_le_bytes()[a as usize % 4])
    }
    fn read16(&mut self, _: u32) -> Result<u16, power::Error> {
        Err(power::Error::Access)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        Ok(self.words[a as usize / 4])
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), power::Error> {
        self.writes.push(a);
        if self.ignore != Some(a) {
            let mut bytes = self.words[a as usize / 4].to_le_bytes();
            bytes[a as usize % 4] = v;
            self.words[a as usize / 4] = u32::from_le_bytes(bytes);
        }
        Ok(())
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.writes.push(a);
        if self.ignore != Some(a) {
            self.words[a as usize / 4] = v;
        }
        Ok(())
    }
    fn now_us(&self) -> u64 {
        0
    }
    async fn delay_us(&mut self, _: u64) {}
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
fn ready<T>(f: impl core::future::Future<Output = T>) -> Option<T> {
    let mut f = core::pin::pin!(f);
    match f.as_mut().poll(&mut core::task::Context::from_waker(
        core::task::Waker::noop(),
    )) {
        core::task::Poll::Ready(v) => Some(v),
        core::task::Poll::Pending => None,
    }
}
fn calibration(offset_valid: bool, comp_valid: bool, adc_td: u8) -> factory_51::Calibration {
    factory_51::Calibration {
        thermal: 0,
        tssi_cck: [0; 6],
        tssi_mcs: [0; 19],
        tssi_trim: [0; 8],
        trim_programmed: false,
        thermal_trim: 0,
        thermal_programmed: false,
        pa_bias: 0,
        pa_programmed: false,
        gain_offset: [3, -2, 1, 0, 0],
        offset_valid,
        gain_comp: [5, -1, 0, 2, 0],
        comp_valid,
        adc_td,
    }
}
fn gain() -> Gain {
    let mut gain = Gain::default();
    for band in 0..8 {
        for path in 0..2 {
            for i in 0..7 {
                gain.lna[band][path][i] = (band * 16 + path * 8 + i) as i8 - 20;
            }
            for i in 0..2 {
                gain.tia[band][path][i] = (band * 4 + path * 2 + i) as i8 - 3;
            }
            gain.rpl20[band][path] = (band + path) as i8 - 2;
            for i in 0..9 {
                gain.rpl40[band][path][i] = (band + path * 3 + i) as i8 - 4;
            }
            for i in 0..13 {
                gain.rpl80[band][path][i] = (band + path * 5 + i) as i8 - 6;
            }
        }
    }
    gain
}

/// rtw8851b.c `rtw8851b_set_channel_mac`, `rtw8851b_ctrl_ch`
/// (single-path gain error/offset/RPL comp) and `rtw8851b_ctrl_bw` with
/// the `adc_td` ADC BW select.
fn smoke_rtw89_n51_channel_mac_ctrl_ch_and_bw_follow_rtw8851b() -> TestResult {
    let gain = gain();
    let cal = calibration(true, true, 0x11);
    let inputs = Inputs {
        gain: &gain,
        calibration: &cal,
        bases: [-8, 12],
    };
    let mut io = Model::new(0x5a5a_5a5a);
    // SAFETY: private inert register model; no hardware.
    if ready(unsafe { program(&mut io, Profile::INITIAL, &inputs) }) != Some(Ok(())) {
        return TestResult::Fail("RTL8851B channel-1 program failed on a ready model");
    }
    // 20MHz: RFMOD 0, TXSC 0, BAND_MODE only.
    if io.word(0xc088) != 0 || io.word(0xc010) & 3 != 0 || io.word(0xc628) & 0x13 != 0x10 {
        return TestResult::Fail("RTL8851B set_channel_mac 2.4GHz/20MHz differs");
    }
    // SCO element 0, band select 1, sco_mapping(1) = 109, FIR flat set.
    if io.field(0x123b0, 0x7ffff) != 0x1cfea
        || io.field(0x123b4, 0x7ffff) != 0x27de3
        || io.field(0x14738, 1 << 17) != 1
        || io.field(0x149c0, 0x7f) != 109
        || io.field(0x12300, 0xff_ffff) != 0x3d23ff
        || io.field(0x12314, 0xff_ffff) != 0xfaef92
    {
        return TestResult::Fail("RTL8851B ctrl_ch SCO/band/FIR differs");
    }
    // Gain error path A, 2G registers only; no path-B 0x475c writes.
    if io.field(0x14678, 0xff_0000) != (-20i8) as u8 as u32
        || io.field(0x14680, 0xff00_0000) != (-2i8) as u8 as u32
        || io.writes.contains(&0x1475c)
    {
        return TestResult::Fail("RTL8851B gain error differs from rtw8851b_set_gain_error");
    }
    // comp[2G] 5 << 2 = 20; ofdm = 2 (offset[1] = -2): -((2 << 2) + (-8 >> 2)) = -6;
    // RPL bias (2 << 4) - 8 = 24, rssi (2 << 4) + 12 = 44; CCK -3:
    // (-3 << 3) + (-8 >> 1) = -28 -> 0x64.
    if io.field(0x14acc, 0xff) != 20
        || io.field(0x14694, 0xff_0000) != 0xfa
        || io.field(0x149b0, 0xff) != 24
        || io.field(0x14a00, 0xff) != 44
        || io.field(0x123ac, 0x7f) != 0x64
    {
        return TestResult::Fail("RTL8851B gain offset differs from rtw8851b_set_gain_offset");
    }
    // RPL comp path A band 0: rpl20 -2, rpl40 -4/-3/-2, rpl80 -6/-5/../+4.
    if io.field(0x149b0, 0xff00) != 0xfe
        || io.field(0x14a00, 0xff00_0000) != 0xfd
        || io.word(0x149b4) != 0x04fb_fafe
        || io.word(0x14a08) != 0x03fe_fdfc
    {
        return TestResult::Fail("RTL8851B RPL comp differs from rtw8851b_set_rxsc_rpl_comp");
    }
    // ctrl_bw 20MHz + bw_setting(adc_td 0x11 -> 5).
    if io.field(0x149c0, 0xc000_0000) != 0
        || io.field(0x149c4, 0xf00) != 0
        || io.field(0x1c0d8, 0x1e0) != 5
        || io.field(0x1c0ec, 0x6000) != 2
        || io.field(0x1c0e4, 0x30) != 2
        || io.field(0x112a0, 0xff80_0000) != 0x92
        || io.writes.contains(&0x1237c)
    {
        return TestResult::Fail("RTL8851B ctrl_bw / bw_setting differs");
    }
    // 5GHz 80MHz (primary 36, center 42): no SCO/CCK RPL offset, 5G gain
    // registers, RFMOD 2, TXRATE_CHK CCK check, DCIM_FR 0, default ADC 4.
    let Some(wide) = Profile::new_5ghz(36, Width::Mhz80) else {
        return TestResult::Fail("5GHz 80MHz profile refused");
    };
    let cal = calibration(true, false, 0x19);
    let inputs = Inputs {
        gain: &gain,
        calibration: &cal,
        bases: [-8, 12],
    };
    let mut io = Model::new(0);
    // SAFETY: private inert register model; no hardware.
    if ready(unsafe { program(&mut io, wide, &inputs) }) != Some(Ok(()))
        || io.word(0xc010) & 3 != 2
        || io.word(0xc628) & 0x13 != 0x3
        || io.writes.contains(&0x123b0)
        || io.writes.contains(&0x123ac)
        || io.writes.contains(&0x14acc)
        || io.field(0x14738, 1 << 17) != 0
        || io.field(0x145dc, 0xff_0000) != (16 - 20i8) as u8 as u32
        || io.field(0x149c0, 0xc000_0000) != 2
        || io.field(0x149c4, 0xf00) != u32::from(wide.pri_ch_idx())
        || io.field(0x1c0ec, 0x6000) != 0
        || io.field(0x1c0d8, 0x1e0) != 4
    {
        return TestResult::Fail("RTL8851B 5GHz/80MHz channel program differs");
    }
    // 160MHz never writes.
    if let Some(c160) = Profile::new_5ghz_160(36) {
        let mut io = Model::new(0);
        // SAFETY: private inert register model; no hardware.
        if ready(unsafe { program(&mut io, c160, &inputs) }) != Some(Err(power::Error::Unsupported))
            || !io.writes.is_empty()
        {
            return TestResult::Fail("RTL8851B 160MHz was programmed");
        }
    }
    // Ignored writes fail closed.
    for address in [0xc088, 0x149c0, 0x14678, 0x10734, 0x11200] {
        let mut io = Model::new(0x5a5a_5a5a);
        io.ignore = Some(address);
        // SAFETY: private inert register model; no hardware.
        if ready(unsafe { program(&mut io, Profile::INITIAL, &inputs) }) == Some(Ok(())) {
            return TestResult::Fail("ignored RTL8851B channel write returned success");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_n51_channel_mac_ctrl_ch_and_bw_follow_rtw8851b
);

/// rtw8851b.c `rtw8851b_set_channel_bb` tail: CCK enable, NBI/CSI spur
/// (5280/5760 only), 5GHz BT-share release, channel index, 5M mask
/// (threshold 5), CFR edge channels and the S0-only `bb_reset_all`.
fn smoke_rtw89_n51_set_channel_bb_tail_follows_rtw8851b() -> TestResult {
    // 2.4GHz ch1/20: no spur, CCK on, CFR edge values.
    let tail = tail_fields(Profile::INITIAL);
    let mut io = Model::new(0x0101_0101);
    for &(a, m, v) in &tail {
        if modify(&mut io, a, m, v).is_err() {
            return TestResult::Fail("model write failed");
        }
    }
    if io.field(0x12344, 1 << 31) != 0
        || io.field(0x10c80, 1 << 31) != 0
        || io.field(0x10700, 1 << 5) != 1
        || io.field(0x146e4, 0x1000) != 0
        || io.field(0x147a4, 0x1000) != 0
        || io.field(0x142c8, 1 << 23) != 0
        || io.field(0x10734, 0xff_0000) != 1
        || io.field(0x146f8, 1 << 12) != 0
        || io.field(0x14b30, 0x3ff) != 0xf8
        || io.field(0x14b30, 0xffc00) != 0x120
        || io.field(0x14b3c, 0xf_0000) != 0x3
        || tail.iter().any(|f| f.0 == PHY + 0x4420)
    {
        return TestResult::Fail("RTL8851B 2.4GHz ch1 BB tail differs");
    }
    // 5GHz 80MHz primary 153 (center 155): spur 5760 vs 5775 -> CSI
    // round_closest(-15e6 / 78125) = -192 -> 1856; NBI -48 mod 256 = 208.
    let Some(wide) = Profile::new_5ghz(153, Width::Mhz80) else {
        return TestResult::Fail("5GHz 80MHz primary 153 refused");
    };
    let tail = tail_fields(wide);
    let mut io = Model::new(0xffff_fffe);
    for &(a, m, v) in &tail {
        if modify(&mut io, a, m, v).is_err() {
            return TestResult::Fail("model write failed");
        }
    }
    if io.field(0x12344, 1 << 31) != 1
        || io.field(0x10700, 1 << 5) != 0
        || io.field(0x142b0, 0x7ff) != 1856
        || io.field(0x142c8, 1 << 23) != 1
        || io.field(0x146e4, 0xff) != 208
        || io.field(0x146e4, 0x1000) != 1
        || io.field(0x147a4, 0x1000) != 0
        || io.field(0x14738, 1 << 19) != 0
        || io.field(0x14738, 1 << 22) != 0
        || io.field(0x10c6c, 1 << 21) != 0
        || io.field(0x14b30, 0x3ff) != 0x120
        || io.field(0x10734, 0xff_0000) != u32::from(wide.chan_idx())
    {
        return TestResult::Fail("RTL8851B 5GHz/80MHz BB tail differs");
    }
    // 2.4GHz HT40 primary 1 above: LOWER primary -> 5M mask low, TH 5.
    let Some(ht40) = Profile::new_2ghz_40(1, true) else {
        return TestResult::Fail("2.4GHz HT40 refused");
    };
    let tail = tail_fields(ht40);
    if !tail.contains(&(PHY + 0x46f8, 0x3f, 0x5))
        || !tail.contains(&(PHY + 0x46f8, 1 << 6, 1))
        || !tail.contains(&(PHY + 0x4440, 1 << 31, 1))
        || tail
            .iter()
            .any(|f| f.0 == PHY + 0x4d10 || f.0 == PHY + 0x3200)
    {
        return TestResult::Fail("RTL8851B 5M mask differs from rtw8851b_5m_mask");
    }
    if RESET_ALL
        .0
        .iter()
        .chain(&RESET_ALL.1)
        .any(|f| f.0 == PHY + 0x3200)
    {
        return TestResult::Fail("RTL8851B bb_reset_all touched the S1 HW-SI trigger");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_n51_set_channel_bb_tail_follows_rtw8851b
);
