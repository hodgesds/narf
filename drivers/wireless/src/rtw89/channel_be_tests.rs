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
