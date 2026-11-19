use super::super::Kind;
use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

/// Private BB word + RF register model for the C channel RF program.
struct Model {
    words: Vec<u32>,
    rf: [Vec<u32>; 2],
    trace: Vec<(u8, u32, u32)>,
}
impl Model {
    fn new() -> Self {
        Self {
            words: vec![0; 0x20000 / 4],
            rf: core::array::from_fn(|_| vec![0; 0x200]),
            trace: Vec::new(),
        }
    }
}
fn rf_index(address: u32) -> usize {
    if address >= 0x10000 {
        0x100 + (address & 0xff) as usize
    } else {
        address as usize
    }
}
impl power::Io for Model {
    fn read8(&mut self, _: u32) -> Result<u8, power::Error> {
        Err(power::Error::Access)
    }
    fn read16(&mut self, _: u32) -> Result<u16, power::Error> {
        Err(power::Error::Access)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        Ok(self.words[a as usize / 4])
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
        0
    }
    async fn delay_us(&mut self, us: u64) {
        self.trace.push((8, us as u32, 0));
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
        let value = self.rf[usize::from(path)][rf_index(address)];
        Ok((value & mask) >> mask.trailing_zeros())
    }
    async fn rf_write(
        &mut self,
        path: u8,
        address: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), Error> {
        let slot = &mut self.rf[usize::from(path)][rf_index(address)];
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
        Ok(0)
    }
    async fn resume(&mut self, _: u32) -> Result<(), Error> {
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

fn smoke_rtw89_c_set_channel_rf_and_help_follow_rtw8852c() -> TestResult {
    // 5GHz 80MHz primary 36 (center 42): BAND1/BAND0 = 5G (1/1), BW 80M = 1.
    let Some(wide) = Profile::new_wide(Band::Ghz5, 36, Width::Mhz80) else {
        return TestResult::Fail("5GHz 80MHz profile refused");
    };
    let old = 0x7_3fff;
    let expected =
        (old & !(0x3_0000 | 0x300 | 0xff | 0xc00)) | 42 | (1 << 16) | (1 << 8) | (1 << 10);
    for cav in [false, true] {
        let mut io = Model::new();
        for p in 0..2 {
            io.rf[p][0x18] = old;
            io.rf[p][0x118] = old;
        }
        io.rf[0][0x18] = old ^ 0x2_0000;
        let a18 = (io.rf[0][0x18] & !(0x3_0000 | 0x300 | 0xff | 0xc00))
            | 42
            | (1 << 16)
            | (1 << 8)
            | (1 << 10);
        // SAFETY: private inert register/RF model; no hardware.
        if ready(Access(&mut io).c_set_channel_rf(wide, cav)) != Some(Ok(())) {
            return TestResult::Fail("C set_channel_rf failed on a ready model");
        }
        let b18 = if cav { a18 } else { expected };
        if io.rf[0][0x18] != a18
            || io.rf[0][0x118] != expected
            || io.rf[1][0x18] != b18
            || io.rf[1][0x118] != expected
        {
            return TestResult::Fail("C RF18 channel/band/BW differs from _ch_setting/_bw_setting");
        }
        // _bw_setting 80MHz: CFCH_BW0 = 2, CFCH_BW1 = 0xd on both paths.
        let w = |a: u32| io.words[(0x10000 + a) as usize / 4];
        if (w(0xc0d4) >> 26) & 3 != 2
            || (w(0xc1d4) >> 26) & 3 != 2
            || (w(0xc0d8) >> 5) & 0xf != 0xd
            || (w(0xc1d8) >> 5) & 0xf != 0xd
        {
            return TestResult::Fail("C CFCH BW fields differ from _bw_setting");
        }
        // _rxbb_bw: LUT 0xb, TIA EBW 2; the RTXBW window is closed again.
        for p in 0..2 {
            if io.rf[p][0x3f] & 0x3f != 0xb
                || (io.rf[p][0x8f] >> 5) & 3 != 2
                || io.rf[p][0xee] & 4 != 0
                || io.rf[p][0x33] & 0x1f != 0xa
            {
                return TestResult::Fail("C RXBB/TIA bandwidth differs from _rxbb_bw");
            }
        }
        // CAV path B: RR_APK mode 3 and the RF18 copy are only on CAV.
        if ((io.rf[1][0x19] >> 4) & 3 == 3) != cav {
            return TestResult::Fail("C CAV path-B RF18 copy differs from _ctrl_bw");
        }
    }
    // 160MHz: BW 0, CFCH 1/0xb, LUT 0x3, EBW 0. 320MHz: Linux
    // `_bw_setting` clears the RF18 BW bits (0) and writes no CFCH
    // pair; `_set_rxbb_bw` falls to the 0x3 default and `_set_tia_bw`
    // to EBW 2.
    if bw_setting(Width::Mhz160) != (0, Some((1, 0xb)))
        || rxbb_bw(Width::Mhz160) != (0x3, 0)
        || bw_setting(Width::Mhz320) != (0, None)
        || rxbb_bw(Width::Mhz320) != (0x3, 2)
    {
        return TestResult::Fail("C 160/320MHz RF bandwidth constants differ");
    }
    // 6GHz ch 37 (20MHz): BAND1 = 3, BAND0 = 0.
    let Some(six) = Profile::new20(Band::Ghz6, 37) else {
        return TestResult::Fail("6GHz ch37 refused");
    };
    if rf18_channel(0xf_ffff, six) != (0xf_ffff & !0x3_03ff) | 0x3_0000 | 37 {
        return TestResult::Fail("C 6GHz RF18 band bits differ from _ch_setting");
    }
    // set_channel_help: enter ends with RSTB_ASYNC low after the 1us hold,
    // exit releases CCA only on 2.4GHz.
    if HELP_ENTER[13] != Step::Write(0x1_0704, 2, 0)
        || HELP_ENTER[7] != Step::Delay(40)
        || help_exit_reset(Band::Ghz5).contains(&Step::Write(0x1_2320, 1, 0))
        || !help_exit_reset(Band::Ghz2).contains(&Step::Write(0x1_2320, 1, 0))
    {
        return TestResult::Fail("C set_channel_help steps differ from Linux");
    }
    // rf_ntfy_mcc V0: 6GHz 160MHz center 15 -> {15, 0, 2, 0, 15, 2}.
    let Some(wide6) = Profile::new_wide(Band::Ghz6, 29, Width::Mhz160) else {
        return TestResult::Fail("6GHz 160MHz refused");
    };
    let mut want = [0u8; 24];
    want[0] = 15;
    want[8] = 2;
    want[16] = 15;
    want[20] = 2;
    if mccch_v0(wide6) != want {
        return TestResult::Fail("C RF_GET_MCCCH V0 body differs from rtw89_fw_h2c_rf_ntfy_mcc");
    }
    // A fresh owner has no programmed or calibrated channel and no TSSI mode.
    let channel = Channel::default();
    if channel.state() != State::New
        || channel.calibrated().is_some()
        || channel.tssi_mode() != [false; 2]
        || channel.dpk().results().is_some()
    {
        return TestResult::Fail("fresh C channel owner is not New");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_c_set_channel_rf_and_help_follow_rtw8852c
);
