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
fn calibration(
    offset: [[i8; factory_c::GAIN_OFFSET_NR]; 2],
    valid: bool,
) -> factory_c::Calibration {
    factory_c::Calibration {
        thermal: [0; 2],
        tssi_cck: [[0; 6]; 2],
        tssi_mcs: [[0; 19]; 2],
        tssi_6g_mcs: [[0; 32]; 2],
        tssi_trim: [[0; 8]; 2],
        tssi_trim_6g: [[0; 16]; 2],
        trim_programmed: false,
        thermal_trim: [0; 2],
        thermal_programmed: false,
        pa_bias: [0; 2],
        pa_programmed: false,
        gain_offset: offset,
        offset_valid: valid,
    }
}
fn gain() -> Gain {
    let mut gain = Gain::default();
    for band in 0..8 {
        for path in 0..2 {
            for i in 0..7 {
                let v = (band * 16 + path * 8 + i) as i8 - 20;
                gain.lna[band][path][i] = v;
                gain.bypass[band][path][i] = v + 1;
                gain.lna_op1db[band][path][i] = v + 2;
            }
            for i in 0..8 {
                gain.tia_op1db[band][path][i] = (band * 16 + path * 8 + i) as i8 - 30;
            }
            for i in 0..2 {
                gain.tia[band][path][i] = (band * 4 + path * 2 + i) as i8 - 3;
            }
        }
    }
    gain
}
fn smoke_rtw89_c_channel_mac_and_ctrl_ch_follow_rtw8852c() -> TestResult {
    let gain = gain();
    let mut offset = [[0i8; factory_c::GAIN_OFFSET_NR]; 2];
    offset[0][0] = 3; // 2G CCK, path A
    offset[0][1] = -2; // 2G OFDM, path A
    offset[1][1] = 40; // 2G OFDM, path B (clamped RPL)
    let cal = calibration(offset, true);
    let inputs = Inputs {
        gain: &gain,
        calibration: &cal,
        offset_base: -8,
    };
    let profile = Profile::INITIAL;
    let mut io = Model::new(0x5a5a_5a5a);
    // SAFETY: private inert register model; no hardware.
    if unsafe { program(&mut io, profile, &inputs) }.is_err() {
        return TestResult::Fail("C channel-1 MAC/ctrl_ch programming failed on a ready model");
    }
    let field = |io: &Model, a: u32, m: u32| (io.word(a) & m) >> m.trailing_zeros();
    // set_channel_mac: 20MHz RFMOD 0, TXSC 0, BAND_MODE only.
    if io.word(0xc088) != 0 || io.word(0xc010) & 3 != 0 || io.word(0xc628) & 0x13 != 0x10 {
        return TestResult::Fail("C set_channel_mac 2.4GHz/20MHz differs from Linux");
    }
    // ctrl_sco_cck(1, 1, 20): element 0; FC0 2412, DIV_ROUND_CLOSEST(2^18, 2412) = 109.
    if field(&io, 0x14a1c, 0x7ffff) != 0x1fe4f
        || field(&io, 0x14a20, 0x7ffff) != 0x2bdac
        || field(&io, 0x14e30, 0x1fff) != 2412
        || field(&io, 0x14974, 0x7f) != 109
        || field(&io, 0x145bc, 0xff_ffff) != 0x3d23ff
        || field(&io, 0x10734, 0xff_0000) != 1
        || field(&io, 0x14738, 1 << 17) != 1
        || field(&io, 0x14aa4, 1 << 17) != 1
        || field(&io, 0x14970, 2) != 0
        || field(&io, 0x14974, 0xc000_0000) != 0
        || field(&io, 0x1c0d8, 0x1e0) != 0xf
        || field(&io, 0x1c1d4, 0x0c00_0000) != 3
        || field(&io, 0x10c9c, 0xf_f000) != 0xff
        || field(&io, 0x1c0e4, 0x30) != 2
    {
        return TestResult::Fail("C ctrl_ch SCO/FC0/PCOEFF/band select differs from Linux");
    }
    // 2G gain error: path A LNA0 at gain_g 0x4678 [23:16] = lna[0][0][0] = -20,
    // bypass LNA0 at 0x4bb8 [31:24], TIA1 at 0x4680 [31:24]; no op1db writes.
    if field(&io, 0x14678, 0xff_0000) != (-20i8) as u8 as u32
        || field(&io, 0x14bb8, 0xff00_0000) != (-19i8) as u8 as u32
        || field(&io, 0x14680, 0xff00_0000) != (-2i8) as u8 as u32
        || field(&io, 0x1475c, 0xff_0000) != (-12i8) as u8 as u32
        || io.writes.contains(&0x14668)
    {
        return TestResult::Fail("C 2.4GHz gain error differs from rtw8852c_set_gain_error");
    }
    // gain offset: R_RPL_OFST is shared, so path B's CCK write wins:
    // clamp((-0 << 3) + (-8 >> 1)) = -4 -> 0x7c (path A wrote -28 first).
    // OFDM q0 = 2: -((2 << 2) + (-8 >> 2)) = -6; RPL 2 << 4 = 32.
    // Path B: q0 = -40: -((-160) - 2) = 162 -> 127; RPL clamp(-640) = -128.
    if field(&io, 0x12340, 0x7f00) != 0x7c
        || field(&io, 0x14694, 0xff_0000) != 0xfa
        || field(&io, 0x14778, 0xff_0000) != 0x7f
        || field(&io, 0x14e0c, 0xff00) != 32
        || field(&io, 0x14e2c, 0xff) != 32
        || field(&io, 0x14e0c, 0xff_0000) != 0x80
        || field(&io, 0x14e2c, 0xff00) != 0x80
    {
        return TestResult::Fail("C gain offset differs from rtw8852c_set_gain_offset");
    }
    // 5GHz 80MHz (ch 42, primary 36): op1db written, no CCK/RPL_OFST, A band
    // select clear, 80MHz MAC program.
    let Some(wide) = Profile::new_wide(Band::Ghz5, 36, Width::Mhz80) else {
        return TestResult::Fail("5GHz 80MHz profile refused");
    };
    let mut io = Model::new(0);
    // SAFETY: private inert register model; no hardware.
    if unsafe { program(&mut io, wide, &inputs) }.is_err()
        || io.word(0xc010) & 3 != 2
        || io.word(0xc628) & 0x13 != 0x3
        || io.writes.contains(&0x14a1c)
        || io.writes.contains(&0x12340)
        || io.writes.contains(&0x145bc)
        || field(&io, 0x14738, 1 << 17) != 0
        || field(&io, 0x14668, 0xff) != (-20i8 + 16 + 2) as u8 as u32
        || field(&io, 0x14674, 0xff00_0000) != (16 - 30 + 7i8) as u8 as u32
        || field(&io, 0x14e30, 0x1fff) != 5210
        || field(&io, 0x14974, 0xc000_0000) != 2
        || field(&io, 0x14978, 0xf00) != u32::from(wide.pri_ch_idx())
        || field(&io, 0x1c1d8, 0x1e0) != 0xd
        || field(&io, 0x10c9c, 0xf_f000) != 0
        || field(&io, 0x14e30, 1 << 26) != 0
    {
        return TestResult::Fail("C 5GHz/80MHz MAC/ctrl_ch differs from Linux");
    }
    // Invalid efuse offsets skip rtw8852c_set_gain_offset entirely.
    let cal = calibration(offset, false);
    let inputs = Inputs {
        gain: &gain,
        calibration: &cal,
        offset_base: -8,
    };
    if ctrl_fields(profile, &inputs)
        .iter()
        .any(|f| matches!(f.0, 0x12340 | 0x14694 | 0x14778 | 0x14e0c | 0x14e2c))
    {
        return TestResult::Fail("invalid gain offset still programmed");
    }
    // Ignored writes fail closed.
    for address in [0xc088, 0x14e30, 0x14678, 0x10734] {
        let mut io = Model::new(0x5a5a_5a5a);
        io.ignore = Some(address);
        // SAFETY: private inert register model; no hardware.
        if unsafe { program(&mut io, profile, &inputs) }.is_ok() {
            return TestResult::Fail("ignored C channel write returned success");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_c_channel_mac_and_ctrl_ch_follow_rtw8852c
);
