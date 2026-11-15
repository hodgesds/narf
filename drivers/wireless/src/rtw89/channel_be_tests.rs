use super::super::operating_channel_c::{Band, Profile, Width};
use super::*;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

/// Fixture register bank implementing [`Regs`]: reads default
/// to 0, writes land verbatim.
struct Model {
    regs32: BTreeMap<u32, u32>,
}

impl Model {
    fn new() -> Self {
        Self {
            regs32: BTreeMap::new(),
        }
    }

    fn with32(mut self, addr: u32, value: u32) -> Self {
        self.regs32.insert(addr, value);
        self
    }
}

impl Regs for Model {
    fn read32(&mut self, address: u32) -> Result<u32, power::Error> {
        Ok(*self.regs32.get(&address).unwrap_or(&0))
    }

    fn write32(&mut self, address: u32, value: u32) -> Result<(), power::Error> {
        self.regs32.insert(address, value);
        Ok(())
    }
}

fn smoke_rtw89_be_set_channel_mac_programs_widths() -> TestResult {
    // (profile, RFMOD, TXSB word, TXRATE_CHK, SIFS, SIFS_TB),
    // hand-evaluated from `rtw8922a_set_channel_mac`
    // (rtw8922a.c:1048..1145) over the `eht` width tables.
    let mut cases: Vec<(Profile, u32, u32, u32, u32, u32)> = Vec::new();
    let Some(p) = Profile::new20(Band::Ghz2, 1) else {
        return TestResult::Fail("2.4GHz ch1 profile refused");
    };
    cases.push((p, 0, 0x0001_0000, 0x10, 0x3F, 0x3E));
    let Some(p) = Profile::new20(Band::Ghz5, 36) else {
        return TestResult::Fail("5GHz ch36 profile refused");
    };
    cases.push((p, 0, 0x0001_0000, 0x03, 0x3F, 0x3E));
    let Some(p) = Profile::new20(Band::Ghz6, 37) else {
        return TestResult::Fail("6GHz ch37 profile refused");
    };
    cases.push((p, 0, 0x0001_0000, 0x03, 0x3F, 0x3E));
    let Some(p) = Profile::new_2ghz_40(1, true) else {
        return TestResult::Fail("2.4GHz HT40 profile refused");
    };
    cases.push((p, 1, 0x0001_0000, 0x10, 0x41, 0x41));
    let Some(p) = Profile::new_wide(Band::Ghz5, 36, Width::Mhz80) else {
        return TestResult::Fail("5GHz 80MHz profile refused");
    };
    cases.push((p, 2, 0x0001_0000, 0x03, 0x41, 0x41));
    let Some(p) = Profile::new_wide(Band::Ghz5, 48, Width::Mhz80) else {
        return TestResult::Fail("5GHz 80MHz upper profile refused");
    };
    cases.push((p, 2, 0x0008_0013, 0x03, 0x41, 0x41));
    let Some(p) = Profile::new_wide(Band::Ghz5, 60, Width::Mhz160) else {
        return TestResult::Fail("5GHz 160MHz profile refused");
    };
    cases.push((p, 3, 0x0040_0126, 0x03, 0x41, 0x41));
    // Lowest primary of a 160MHz channel: the TXSB40 index
    // truncates to 0 (C integer promotion in
    // `rtw89_phy_get_txsb`, phy.c:875), not a refusal.
    let Some(p) = Profile::new_wide(Band::Ghz5, 36, Width::Mhz160) else {
        return TestResult::Fail("5GHz 160MHz lowest profile refused");
    };
    cases.push((p, 3, 0x0001_0000, 0x03, 0x41, 0x41));
    for (profile, rfmod, txsb, chk, sifs, sifs_tb) in cases {
        let mut regs = Model::new();
        if program_set_channel_mac(&mut regs, profile).is_err() {
            return TestResult::Fail("set_channel_mac program refused");
        }
        if regs.regs32.get(&R_BE_WMAC_RFMOD) != Some(&rfmod)
            || regs.regs32.get(&R_BE_TX_SUB_BAND_VALUE) != Some(&txsb)
            || regs.regs32.get(&R_BE_TXRATE_CHK) != Some(&chk)
            || regs.regs32.get(&R_BE_PREBKF_CFG_1) != Some(&sifs)
            || regs.regs32.get(&R_BE_MUEDCA_EN) != Some(&(sifs_tb << 16))
        {
            return TestResult::Fail("set_channel_mac words differ from rtw8922a_set_channel_mac");
        }
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_be_set_channel_mac_programs_widths
);

fn smoke_rtw89_be_set_channel_mac_refusals() -> TestResult {
    // 320 MHz has no BE arm (Linux `support_bandwidths` stops
    // at 160 MHz): the program refuses and writes nothing.
    let Some(p320) = Profile::new_6ghz_320(33, 63) else {
        return TestResult::Fail("6GHz 320MHz profile refused");
    };
    let mut regs = Model::new();
    if program_set_channel_mac(&mut regs, p320) != Err(rfk::Error::Policy)
        || !regs.regs32.is_empty()
    {
        return TestResult::Fail("320MHz set_channel_mac did not refuse cleanly");
    }
    // Partial-mask writes merge into existing register contents
    // (read-modify-write), they do not clobber neighbouring
    // fields; the full-word TXSB write replaces its register.
    let Some(p) = Profile::new20(Band::Ghz2, 1) else {
        return TestResult::Fail("2.4GHz ch1 profile refused");
    };
    let mut seeded = Model::new()
        .with32(R_BE_WMAC_RFMOD, 0xFFFF_FFF7)
        .with32(R_BE_TX_SUB_BAND_VALUE, 0xFFFF_FFFF)
        .with32(R_BE_TXRATE_CHK, 0xFFFF_FFEC)
        .with32(R_BE_PREBKF_CFG_1, 0xFFFF_FF80)
        .with32(R_BE_MUEDCA_EN, 0xFF80_FFFF);
    if program_set_channel_mac(&mut seeded, p).is_err() {
        return TestResult::Fail("seeded set_channel_mac refused");
    }
    if seeded.regs32.get(&R_BE_WMAC_RFMOD) != Some(&0xFFFF_FFF0)
        || seeded.regs32.get(&R_BE_TX_SUB_BAND_VALUE) != Some(&0x0001_0000)
        || seeded.regs32.get(&R_BE_TXRATE_CHK) != Some(&0xFFFF_FFFC)
        || seeded.regs32.get(&R_BE_PREBKF_CFG_1) != Some(&0xFFFF_FFBF)
        || seeded.regs32.get(&R_BE_MUEDCA_EN) != Some(&0xFFBE_FFFF)
    {
        return TestResult::Fail("set_channel_mac partial-mask merge differs");
    }
    // A gone device (`u32::MAX` read) refuses before any write
    // lands past the failing entry: RFMOD is the first entry, so
    // nothing is written at all.
    let mut gone = Model::new().with32(R_BE_WMAC_RFMOD, u32::MAX);
    if program_set_channel_mac(&mut gone, p) != Err(rfk::Error::Register(power::Error::Gone))
        || gone.regs32.len() != 1
    {
        return TestResult::Fail("gone-device set_channel_mac did not refuse cleanly");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_be_set_channel_mac_refusals
);

/// BE PHY window base for the BB assertions below.
const BB_PHY: u32 = 0x20000;

fn smoke_rtw89_be_set_channel_bb_programs_widths() -> TestResult {
    // 2.4 GHz 20 MHz ch1: SCO tables element 0, band-select 2G,
    // FC0 2412 / SCO 109, non-14 CCK pulse coefficients,
    // chan_idx 1, BW 20 (BW 0, gain-map off, 2xFFT off), CCK
    // on (RXCCA_DIS 0, ENABLE_CCK 1, PD arbiter on), spur
    // disables, RSTB_ASYNC 1, TSSI RSTA/RSTB pulsed to 1.
    let Some(p) = Profile::new20(Band::Ghz2, 1) else {
        return TestResult::Fail("2.4GHz ch1 profile refused");
    };
    let mut regs = Model::new();
    if program_set_channel_bb(&mut regs, p).is_err() {
        return TestResult::Fail("2.4GHz ch1 set_channel_bb refused");
    }
    let w = |addr: u32| regs.regs32.get(&(BB_PHY + addr)).copied();
    if w(0x6758) != Some(0x1fe4f)
        || w(0x675c) != Some(0x2bdac)
        || w(0x4160) != Some(0x0400_0000)
        || w(0x4560) != Some(0x0400_0000)
        || w(0x6b4c) != Some(2412)
        || w(0x6b50) != Some(109)
        || w(0x6684) != Some(0x3a63ca)
        || w(0x6688) != Some(0x2a833f)
        || w(0x668c) != Some(0x1491f8)
        || w(0x6690) != Some(0x03c0b0)
        || w(0x6694) != Some(0xfccff1)
        || w(0x6698) != Some(0xfccfc3)
        || w(0x669c) != Some(0xfebfdc)
        || w(0x66a0) != Some(0xffdff7)
        || w(0x0734) != Some(0x0001_0000)
        || w(0x6b54) != Some(0)
        || w(0x625c) != Some(0x4000_0000)
        || w(0xe44c) != Some(0)
        || w(0xe54c) != Some(0)
        || w(0x0520) != Some(0)
        || w(0x0700) != Some(0x20)
        || w(0x0c80) != Some(0)
        || w(0x4d34) != Some(0)
        || w(0x41a0) != Some(0)
        || w(0x41ac) != Some(0)
        || w(0x45a0) != Some(0)
        || w(0x45ac) != Some(0)
        || w(0x0704) != Some(0x2)
        || w(0xe60c) != Some(0x0001_0000)
        || w(0xe70c) != Some(0x0001_0000)
    {
        return TestResult::Fail(
            "2.4GHz ch1 set_channel_bb words differ from rtw8922a_set_channel_bb",
        );
    }
    // The gain sub-legs write nothing: no BE gain owner exists
    // yet, so the LNA/TIA/RPL/op1db registers stay untouched.
    if regs.regs32.contains_key(&(BB_PHY + 0x409c))
        || regs.regs32.contains_key(&(BB_PHY + 0x4054))
        || regs.regs32.contains_key(&(BB_PHY + 0x41e8))
        || regs.regs32.contains_key(&(BB_PHY + 0x40ac))
    {
        return TestResult::Fail("set_channel_bb wrote gain words without a BE gain owner");
    }
    // 2.4 GHz 20 MHz ch14: SCO tables element 13, channel-14
    // CCK pulse coefficients, FC0 2484 / SCO 106, chan_idx 14.
    let Some(p) = Profile::new20(Band::Ghz2, 14) else {
        return TestResult::Fail("2.4GHz ch14 profile refused");
    };
    let mut regs = Model::new();
    if program_set_channel_bb(&mut regs, p).is_err() {
        return TestResult::Fail("2.4GHz ch14 set_channel_bb refused");
    }
    let w = |addr: u32| regs.regs32.get(&(BB_PHY + addr)).copied();
    if w(0x6758) != Some(0x20d8a)
        || w(0x675c) != Some(0x2d29e)
        || w(0x6b4c) != Some(2484)
        || w(0x6b50) != Some(106)
        || w(0x6684) != Some(0x3b13ff)
        || w(0x6688) != Some(0x1c42de)
        || w(0x668c) != Some(0xfdb0ad)
        || w(0x6690) != Some(0xf60f6e)
        || w(0x6694) != Some(0xfd8f92)
        || w(0x6698) != Some(0x02d011)
        || w(0x669c) != Some(0x01c02c)
        || w(0x66a0) != Some(0xfff00a)
        || w(0x0734) != Some(0x000e_0000)
    {
        return TestResult::Fail("2.4GHz ch14 set_channel_bb words differ");
    }
    // 2.4 GHz HT40 primary 1 (center 3): SCO tables follow the
    // primary, FC0 2422 / SCO 108, BW 1, PRICH 0, 2xFFT on.
    let Some(p) = Profile::new_2ghz_40(1, true) else {
        return TestResult::Fail("2.4GHz HT40 profile refused");
    };
    let mut regs = Model::new();
    if program_set_channel_bb(&mut regs, p).is_err() {
        return TestResult::Fail("2.4GHz HT40 set_channel_bb refused");
    }
    let w = |addr: u32| regs.regs32.get(&(BB_PHY + addr)).copied();
    if w(0x6758) != Some(0x1fe4f)
        || w(0x675c) != Some(0x2bdac)
        || w(0x6b4c) != Some(0x8000_0976)
        || w(0x6b50) != Some(108)
        || w(0x6b54) != Some(0x1000)
        || w(0x0734) != Some(0x0001_0000)
    {
        return TestResult::Fail("2.4GHz HT40 set_channel_bb words differ");
    }
    // 5 GHz 20 MHz ch36: no SCO/CCK words, band-select 5G,
    // FC0 5180 / SCO 51, chan_idx 0x20, CCK off (RXCCA_DIS 1,
    // ENABLE_CCK 0, PD arbiter off 1).
    let Some(p) = Profile::new20(Band::Ghz5, 36) else {
        return TestResult::Fail("5GHz ch36 profile refused");
    };
    let mut regs = Model::new();
    if program_set_channel_bb(&mut regs, p).is_err() {
        return TestResult::Fail("5GHz ch36 set_channel_bb refused");
    }
    let w = |addr: u32| regs.regs32.get(&(BB_PHY + addr)).copied();
    if regs.regs32.contains_key(&(BB_PHY + 0x6758))
        || regs.regs32.contains_key(&(BB_PHY + 0x675c))
        || regs.regs32.contains_key(&(BB_PHY + 0x6684))
        || w(0x4160) != Some(0)
        || w(0x4560) != Some(0)
        || w(0x6b4c) != Some(5180)
        || w(0x6b50) != Some(51)
        || w(0x0734) != Some(0x0020_0000)
        || w(0x6b54) != Some(0)
        || w(0x0520) != Some(1)
        || w(0x0700) != Some(0)
        || w(0x0c80) != Some(0x8000_0000)
        || w(0x0704) != Some(0x2)
        || w(0xe60c) != Some(0x0001_0000)
        || w(0xe70c) != Some(0x0001_0000)
    {
        return TestResult::Fail("5GHz ch36 set_channel_bb words differ");
    }
    // 5 GHz 80 MHz primary 36 (center 42): FC0 5210 / SCO 50,
    // BW 2, PRICH 0, gain-map on.
    let Some(p) = Profile::new_wide(Band::Ghz5, 36, Width::Mhz80) else {
        return TestResult::Fail("5GHz 80MHz profile refused");
    };
    let mut regs = Model::new();
    if program_set_channel_bb(&mut regs, p).is_err() {
        return TestResult::Fail("5GHz 80MHz set_channel_bb refused");
    }
    let w = |addr: u32| regs.regs32.get(&(BB_PHY + addr)).copied();
    if w(0x6b4c) != Some(5210)
        || w(0x6b50) != Some(50)
        || w(0x6b54) != Some(0x2000)
        || w(0xe44c) != Some(1)
        || w(0xe54c) != Some(1)
        || w(0x0734) != Some(0x0020_0000)
    {
        return TestResult::Fail("5GHz 80MHz set_channel_bb words differ");
    }
    // 6 GHz 160 MHz primary 37 (center 47): FC0 6185 / SCO 42,
    // BW 3, PRICH 1, gain-map on, chan_idx 0x82.
    let Some(p) = Profile::new_wide(Band::Ghz6, 37, Width::Mhz160) else {
        return TestResult::Fail("6GHz 160MHz profile refused");
    };
    let mut regs = Model::new();
    if program_set_channel_bb(&mut regs, p).is_err() {
        return TestResult::Fail("6GHz 160MHz set_channel_bb refused");
    }
    let w = |addr: u32| regs.regs32.get(&(BB_PHY + addr)).copied();
    if w(0x6b4c) != Some(6185)
        || w(0x6b50) != Some(42)
        || w(0x6b54) != Some(0x3100)
        || w(0xe44c) != Some(1)
        || w(0xe54c) != Some(1)
        || w(0x0734) != Some(0x0082_0000)
        || w(0x4160) != Some(0)
        || w(0x0520) != Some(1)
    {
        return TestResult::Fail("6GHz 160MHz set_channel_bb words differ");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_be_set_channel_bb_programs_widths
);

fn smoke_rtw89_be_set_channel_bb_refusals() -> TestResult {
    // 320 MHz has no `ctrl_bw` arm (and the MAC leg refuses it
    // first): the program refuses and writes nothing.
    let Some(p320) = Profile::new_6ghz_320(33, 63) else {
        return TestResult::Fail("6GHz 320MHz profile refused");
    };
    let mut regs = Model::new();
    if program_set_channel_bb(&mut regs, p320) != Err(rfk::Error::Policy) || !regs.regs32.is_empty()
    {
        return TestResult::Fail("320MHz set_channel_bb did not refuse cleanly");
    }
    // Partial-mask writes merge into existing register contents
    // (read-modify-write), they do not clobber neighbouring
    // fields: FC0 keeps its high bits, ANT_CHBW keeps its
    // untouched fields, RXCCA_DIS sets bit 0 only.
    let Some(p) = Profile::new_wide(Band::Ghz5, 36, Width::Mhz80) else {
        return TestResult::Fail("5GHz 80MHz profile refused");
    };
    let mut seeded = Model::new()
        .with32(BB_PHY + 0x6b4c, 0xFFFF_F000)
        .with32(BB_PHY + 0x6b54, 0xFFFF_0FFF)
        .with32(BB_PHY + 0x0520, 0xFFFF_FFFE);
    if program_set_channel_bb(&mut seeded, p).is_err() {
        return TestResult::Fail("seeded set_channel_bb refused");
    }
    if seeded.regs32.get(&(BB_PHY + 0x6b4c)) != Some(&0x7FFF_F45A)
        || seeded.regs32.get(&(BB_PHY + 0x6b54)) != Some(&0xFFFF_20FF)
        || seeded.regs32.get(&(BB_PHY + 0x0520)) != Some(&0xFFFF_FFFF)
    {
        return TestResult::Fail("set_channel_bb partial-mask merge differs");
    }
    // A gone device (`u32::MAX` read) refuses before any write
    // lands past the failing entry: for 5 GHz the first entry is
    // the path-A band-select, so nothing is written at all.
    let mut gone = Model::new().with32(BB_PHY + 0x4160, u32::MAX);
    if program_set_channel_bb(&mut gone, p) != Err(rfk::Error::Register(power::Error::Gone))
        || gone.regs32.len() != 1
    {
        return TestResult::Fail("gone-device set_channel_bb did not refuse cleanly");
    }
    // For 2.4 GHz the first entry is the SCO barker word.
    let Some(p2) = Profile::new20(Band::Ghz2, 1) else {
        return TestResult::Fail("2.4GHz ch1 profile refused");
    };
    let mut gone2 = Model::new().with32(BB_PHY + 0x6758, u32::MAX);
    if program_set_channel_bb(&mut gone2, p2) != Err(rfk::Error::Register(power::Error::Gone))
        || gone2.regs32.len() != 1
    {
        return TestResult::Fail("gone-device 2.4GHz set_channel_bb did not refuse cleanly");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_be_set_channel_bb_refusals
);

/// Fake `rfk::Interface` for the BE RF leg: sparse RF slots per
/// path, an `INV_RF_DATA` list, a write-drop list (the read-back
/// check fails for dropped writes), and a delay log.
struct RfModel {
    rf: BTreeMap<(u8, u32), u32>,
    inv: Vec<(u8, u32)>,
    drop: Vec<(u8, u32)>,
    writes: Vec<(u8, u32, u32)>,
    delays: Vec<u64>,
    now: u64,
}

impl RfModel {
    fn new() -> Self {
        Self {
            rf: BTreeMap::new(),
            inv: Vec::new(),
            drop: Vec::new(),
            writes: Vec::new(),
            delays: Vec::new(),
            now: 0,
        }
    }

    fn with_rf(mut self, path: u8, address: u32, value: u32) -> Self {
        self.rf.insert((path, address), value);
        self
    }

    fn with_inv(mut self, path: u8, address: u32) -> Self {
        self.inv.push((path, address));
        self
    }

    fn with_drop(mut self, path: u8, address: u32) -> Self {
        self.drop.push((path, address));
        self
    }
}

impl power::Io for RfModel {
    fn read8(&mut self, _: u32) -> Result<u8, power::Error> {
        Err(power::Error::Access)
    }
    fn read16(&mut self, _: u32) -> Result<u16, power::Error> {
        Err(power::Error::Access)
    }
    fn read32(&mut self, _: u32) -> Result<u32, power::Error> {
        Err(power::Error::Access)
    }
    fn write8(&mut self, _: u32, _: u8) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn write32(&mut self, _: u32, _: u32) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn now_us(&self) -> u64 {
        self.now
    }
    async fn delay_us(&mut self, us: u64) {
        self.delays.push(us);
        self.now += us;
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}

impl rfk::Interface for RfModel {
    fn admit(&mut self) -> Result<(), rfk::Error> {
        Ok(())
    }
    async fn rf_read(&mut self, path: u8, address: u32, mask: u32) -> Result<u32, rfk::Error> {
        if self.inv.contains(&(path, address)) {
            return Ok(INV_RF_DATA);
        }
        let value = self.rf.get(&(path, address)).copied().unwrap_or(0);
        Ok((value & mask) >> mask.trailing_zeros())
    }
    async fn rf_write(
        &mut self,
        path: u8,
        address: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), rfk::Error> {
        self.writes.push((path, address, value));
        if self.drop.contains(&(path, address)) {
            return Ok(());
        }
        let slot = self.rf.entry((path, address)).or_insert(0);
        *slot = (*slot & !mask) | ((value << mask.trailing_zeros()) & mask);
        Ok(())
    }
    async fn begin(&mut self, _: rfk::Kind) -> Result<(), rfk::Error> {
        Ok(())
    }
    async fn end(&mut self, _: rfk::Kind) -> Result<(), rfk::Error> {
        Ok(())
    }
    async fn pause(&mut self) -> Result<u32, rfk::Error> {
        Ok(0)
    }
    async fn resume(&mut self, _: u32) -> Result<(), rfk::Error> {
        Ok(())
    }
}

/// Drive an RF-leg future to completion on a noop waker: the
/// fake's RF access and delays never pend.
fn drive<T>(future: impl core::future::Future<Output = T>) -> Option<T> {
    use core::{
        pin::pin,
        task::{Context, Poll, Waker},
    };
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => Some(value),
        Poll::Pending => None,
    }
}

fn smoke_rtw89_be_set_channel_rf_values() -> TestResult {
    // `rtw8922a_chan_to_rf18_val` (rtw8922a.c:2680..2714):
    // center channel in RR_CFGCH_CH, band bits, BW_V2 bits.
    let mut cases: Vec<(Profile, u32)> = Vec::new();
    let Some(p) = Profile::new20(Band::Ghz2, 1) else {
        return TestResult::Fail("2.4GHz ch1 profile refused");
    };
    cases.push((p, 0x0000_0001));
    let Some(p) = Profile::new20(Band::Ghz5, 36) else {
        return TestResult::Fail("5GHz ch36 profile refused");
    };
    cases.push((p, 0x0001_0124));
    let Some(p) = Profile::new_wide(Band::Ghz5, 36, Width::Mhz80) else {
        return TestResult::Fail("5GHz 80MHz profile refused");
    };
    cases.push((p, 0x0001_092a));
    let Some(p) = Profile::new20(Band::Ghz6, 37) else {
        return TestResult::Fail("6GHz ch37 profile refused");
    };
    cases.push((p, 0x0003_0025));
    let Some(p) = Profile::new_wide(Band::Ghz6, 37, Width::Mhz160) else {
        return TestResult::Fail("6GHz 160MHz profile refused");
    };
    cases.push((p, 0x0003_0c2f));
    let Some(p) = Profile::new_2ghz_40(1, true) else {
        return TestResult::Fail("2.4GHz HT40 profile refused");
    };
    cases.push((p, 0x0000_0403));
    for (profile, expected) in cases {
        if set_channel_rf_value(profile) != Some(expected) {
            return TestResult::Fail("set_channel_rf word differs from rtw8922a_chan_to_rf18_val");
        }
    }
    // 320 MHz has no RF-leg arm (Linux encodes 4, but no 8922A
    // channel reaches the RF leg at 320 MHz).
    let Some(p320) = Profile::new_6ghz_320(33, 63) else {
        return TestResult::Fail("6GHz 320MHz profile refused");
    };
    if set_channel_rf_value(p320).is_some() {
        return TestResult::Fail("320MHz set_channel_rf value was built");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_be_set_channel_rf_values
);

fn smoke_rtw89_be_set_channel_rf_programs_words() -> TestResult {
    // 5 GHz 80 MHz primary 36 (center 42, RF word 0x1092a) on
    // CBV (`chip_version` 1: no LUT tail): both CFGCH words on
    // both paths keep their untouched fields and take the RF
    // word, with exactly four 100 us sleeps and no LUT writes.
    let Some(p) = Profile::new_wide(Band::Ghz5, 36, Width::Mhz80) else {
        return TestResult::Fail("5GHz 80MHz profile refused");
    };
    let mut model = RfModel::new()
        .with_rf(0, 0x18, 0x40000)
        .with_rf(0, 0x10018, 0x00000)
        .with_rf(1, 0x18, 0x00001)
        .with_rf(1, 0x10018, 0xFFFFF);
    // SAFETY: fixture-only RF model: inert RAM, no hardware,
    // exclusive ownership; the RF leg contract holds vacuously.
    let outcome = drive(unsafe { program_set_channel_rf(&mut model, p, 1) });
    if outcome != Some(Ok(())) {
        return TestResult::Fail("5GHz 80MHz set_channel_rf refused");
    }
    if model.rf.get(&(0, 0x18)) != Some(&0x5092a)
        || model.rf.get(&(0, 0x10018)) != Some(&0x1092a)
        || model.rf.get(&(1, 0x18)) != Some(&0x1092a)
        || model.rf.get(&(1, 0x10018)) != Some(&0xde92a)
        || model.delays != [100, 100, 100, 100]
        || model.writes.len() != 4
    {
        return TestResult::Fail(
            "5GHz 80MHz set_channel_rf words differ from rtw8922a_ctl_band_ch_bw",
        );
    }
    // CAV (`chip_version` 0): the path-A LUT tail follows the
    // CFGCH writes — 2.4 GHz takes LUTWD1 0x0c990.
    let Some(p2) = Profile::new20(Band::Ghz2, 1) else {
        return TestResult::Fail("2.4GHz ch1 profile refused");
    };
    let mut model = RfModel::new();
    // SAFETY: fixture-only RF model: inert RAM, no hardware,
    // exclusive ownership; the RF leg contract holds vacuously.
    let outcome = drive(unsafe { program_set_channel_rf(&mut model, p2, 0) });
    if outcome != Some(Ok(())) {
        return TestResult::Fail("2.4GHz CAV set_channel_rf refused");
    }
    if model.rf.get(&(0, 0x18)) != Some(&0x1)
        || model.rf.get(&(1, 0x10018)) != Some(&0x1)
        || model.delays != [100, 100, 100, 100]
        || model.writes.len() != 9
        || model.writes[4..]
            != [
                (0, 0xef, 0x80000),
                (0, 0x33, 0x00003),
                (0, 0x3e, 0x0c990),
                (0, 0x3f, 0xebe38),
                (0, 0xef, 0x00000),
            ]
    {
        return TestResult::Fail("2.4GHz CAV set_channel_rf LUT tail differs");
    }
    // CAV on 5 GHz takes LUTWD1 0x0c190.
    let mut model = RfModel::new();
    // SAFETY: fixture-only RF model: inert RAM, no hardware,
    // exclusive ownership; the RF leg contract holds vacuously.
    let outcome = drive(unsafe { program_set_channel_rf(&mut model, p, 0) });
    if outcome != Some(Ok(())) {
        return TestResult::Fail("5GHz CAV set_channel_rf refused");
    }
    if model.writes.len() != 9 || model.writes[6] != (0, 0x3e, 0x0c190) {
        return TestResult::Fail("5GHz CAV set_channel_rf LUTWD1 differs");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_be_set_channel_rf_programs_words
);

fn smoke_rtw89_be_set_channel_rf_refusals() -> TestResult {
    // 320 MHz refuses before any RF access: no reads, writes,
    // or sleeps.
    let Some(p320) = Profile::new_6ghz_320(33, 63) else {
        return TestResult::Fail("6GHz 320MHz profile refused");
    };
    let mut model = RfModel::new();
    // SAFETY: fixture-only RF model: inert RAM, no hardware,
    // exclusive ownership; the RF leg contract holds vacuously.
    let outcome = drive(unsafe { program_set_channel_rf(&mut model, p320, 1) });
    if outcome != Some(Err(rfk::Error::Policy))
        || !model.writes.is_empty()
        || !model.delays.is_empty()
    {
        return TestResult::Fail("320MHz set_channel_rf did not refuse cleanly");
    }
    // An INV_RF_DATA syn-path word refuses before any write.
    let Some(p) = Profile::new20(Band::Ghz5, 36) else {
        return TestResult::Fail("5GHz ch36 profile refused");
    };
    let mut model = RfModel::new().with_inv(0, 0x18);
    // SAFETY: fixture-only RF model: inert RAM, no hardware,
    // exclusive ownership; the RF leg contract holds vacuously.
    let outcome = drive(unsafe { program_set_channel_rf(&mut model, p, 1) });
    if outcome != Some(Err(rfk::Error::Register(power::Error::Gone)))
        || !model.writes.is_empty()
        || !model.delays.is_empty()
    {
        return TestResult::Fail("INV syn-path set_channel_rf did not refuse cleanly");
    }
    // An INV_RF_DATA word on path B's direct register is checked
    // in the write loop, after path A's words and path B's
    // indirect word landed: Linux's partial-write behaviour.
    let mut model = RfModel::new().with_inv(1, 0x10018);
    // SAFETY: fixture-only RF model: inert RAM, no hardware,
    // exclusive ownership; the RF leg contract holds vacuously.
    let outcome = drive(unsafe { program_set_channel_rf(&mut model, p, 1) });
    if outcome != Some(Err(rfk::Error::Register(power::Error::Gone)))
        || model.writes.len() != 3
        || model.writes[0].0 != 0
        || model.writes[1].0 != 0
        || model.writes[2] != (1, 0x18, 0x10124)
        || model.delays != [100, 100, 100]
        || model.rf.contains_key(&(1, 0x10018))
    {
        return TestResult::Fail("INV path-B set_channel_rf did not keep Linux's partial writes");
    }
    // A dropped write fails the read-back check.
    let mut model = RfModel::new().with_drop(1, 0x10018);
    // SAFETY: fixture-only RF model: inert RAM, no hardware,
    // exclusive ownership; the RF leg contract holds vacuously.
    let outcome = drive(unsafe { program_set_channel_rf(&mut model, p, 1) });
    if outcome != Some(Err(rfk::Error::Register(power::Error::Access))) {
        return TestResult::Fail("dropped-write set_channel_rf passed its read-back");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_be_set_channel_rf_refusals
);
