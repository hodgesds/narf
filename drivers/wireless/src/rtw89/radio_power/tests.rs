use super::super::power::{self, Io};
use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
struct Model {
    bytes: Vec<u8>,
    hash: u64,
    count: u32,
    operations: usize,
    fail: Option<usize>,
    denied: bool,
    ignore: bool,
    gone: bool,
    pending: bool,
    now: u64,
}
impl Model {
    fn new(seed: u8, _rx: u8) -> Self {
        Self {
            bytes: vec![seed; 0x20000],
            hash: 14695981039346656037,
            count: 0,
            operations: 0,
            fail: None,
            denied: false,
            ignore: false,
            gone: false,
            pending: false,
            now: 0,
        }
    }
    fn access(&mut self) -> Result<(), power::Error> {
        let n = self.operations;
        self.operations += 1;
        if self.fail == Some(n) {
            Err(power::Error::Access)
        } else {
            Ok(())
        }
    }
    fn record(&mut self, words: [u32; 3]) {
        self.count += 1;
        for word in words {
            for byte in word.to_le_bytes() {
                self.hash ^= u64::from(byte);
                self.hash = self.hash.wrapping_mul(1099511628211);
            }
        }
    }
}
impl Io for Model {
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        self.access()?;
        Ok(self.bytes[a as usize])
    }
    fn read16(&mut self, _: u32) -> Result<u16, power::Error> {
        Err(power::Error::Access)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.access()?;
        if self.gone {
            return Ok(u32::MAX);
        }
        Ok(u32::from_le_bytes(
            self.bytes[a as usize..a as usize + 4].try_into().unwrap(),
        ))
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), power::Error> {
        self.access()?;
        if !self.ignore {
            self.bytes[a as usize] = v;
        }
        self.record([1, a, u32::from(v)]);
        Ok(())
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.access()?;
        if !self.ignore {
            self.bytes[a as usize..a as usize + 4].copy_from_slice(&v.to_le_bytes());
        }
        self.record([4, a, v]);
        Ok(())
    }
    fn now_us(&self) -> u64 {
        self.now
    }
    async fn delay_us(&mut self, u: u64) {
        if self.pending {
            core::future::pending::<()>().await;
        }
        self.now += u;
        self.record([8, u as u32, 0]);
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl Interface for Model {
    fn admit(&mut self) -> Result<(), Error> {
        if self.denied {
            Err(Error::Policy)
        } else {
            Ok(())
        }
    }
    async fn rf_read(&mut self, _: u8, _: u32, _: u32) -> Result<u32, Error> {
        Err(Error::Table)
    }
    async fn rf_write(&mut self, _: u8, _: u32, _: u32, _: u32) -> Result<(), Error> {
        Err(Error::Table)
    }
    async fn begin(&mut self, _: super::super::rfk::Kind) -> Result<(), Error> {
        Err(Error::Table)
    }
    async fn end(&mut self, _: super::super::rfk::Kind) -> Result<(), Error> {
        Err(Error::Table)
    }
    async fn pause(&mut self) -> Result<u32, Error> {
        self.access()?;
        let saved = u32::from_le_bytes(self.bytes[0xc348..0xc34c].try_into().unwrap()) & 65535;
        self.record([32, 0, saved]);
        Ok(saved)
    }
    async fn resume(&mut self, saved: u32) -> Result<(), Error> {
        self.access()?;
        self.record([64, 0, saved]);
        Ok(())
    }
}

fn plan(negative: bool, sharp: u8) -> Plan {
    let mut p = defaults::DEFAULT;
    for (i, v) in p.byrate.iter_mut().enumerate() {
        *v = if negative {
            -((i * 3 % 120) as i8)
        } else {
            80 - (i % 20) as i8
        };
    }
    p.offset = [-16, -7, 2, 15, 0];
    for n in 0..2 {
        for i in 0..8 {
            p.limits[n][i] = if negative {
                -11 - i as i8 * 3 - n as i8
            } else {
                40 + i as i8 * 2 + n as i8
            };
        }
        for i in 0..3 {
            p.ru[n][i] = if negative {
                -7 - i as i8 * 3 - n as i8
            } else {
                28 + i as i8 * 2 + n as i8
            };
        }
    }
    p.shape = [sharp, if sharp != 0 { 3 } else { 0 }];
    p
}
fn smoke_rtw89_b_power_source_units_and_full_pages_match_frozen_references() -> TestResult {
    for &(seed, negative, sharp, count, hash) in CASES {
        let mut io = Model::new(seed, 0);
        let mut owner = Power::default();
        // SAFETY: exact inert B words and explicitly private power configuration only.
        let r = unsafe { owner.prepare(&mut io, &plan(negative, sharp)) };
        if r != Ok(()) || owner.state() != State::Configured || io.count != count || io.hash != hash
        {
            return TestResult::Fail(
                "B source power units/pages/shape/reference differ from the frozen reference",
            );
        }
    }
    let mut baseline = Model::new(0xa5, 0);
    let mut owner = Power::default();
    // SAFETY: finite inert power baseline, no hardware or emission grant.
    if unsafe { owner.prepare(&mut baseline, &plan(true, 1)) } != Ok(()) {
        return TestResult::Fail("power baseline");
    }
    for fail in 0..baseline.operations {
        let mut io = Model::new(0xa5, 0);
        io.fail = Some(fail);
        let mut owner = Power::default();
        // SAFETY: inject every actual access failure into owned words.
        if unsafe { owner.prepare(&mut io, &plan(true, 1)) }.is_ok()
            || owner.state() != State::Preparing
        {
            return TestResult::Fail("partial source power completed");
        }
        let n = io.operations;
        // SAFETY: one partial attempt must reject before touching the model.
        if unsafe { owner.prepare(&mut io, &plan(true, 1)) } != Err(Error::Terminal)
            || io.operations != n
        {
            return TestResult::Fail("source power replayed");
        }
    }
    for variant in 0..3 {
        let mut io = Model::new(0xa5, 0);
        let mut owner = Power::default();
        match variant {
            0 => io.ignore = true,
            1 => io.denied = true,
            _ => io.gone = true,
        };
        // SAFETY: ignored controls or denied current authority cannot earn completion.
        if unsafe { owner.prepare(&mut io, &plan(true, 1)) }.is_ok()
            || owner.state() != State::Preparing
        {
            return TestResult::Fail("unverified power controls completed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_power_source_units_and_full_pages_match_frozen_references
);
fn element(id: u32, rfe: u8, size: u8, entries: &[u8]) -> Element {
    let mut bytes = vec![0, 0, rfe, size];
    bytes.extend_from_slice(&((entries.len() / usize::from(size)) as u32).to_le_bytes());
    bytes.extend_from_slice(entries);
    Element {
        id,
        version: [0; 4],
        bytes,
    }
}
fn smoke_rtw89_b_power_rfe_selection_signed_decoding_and_invalid_override_fail_closed() -> TestResult
{
    let a = element(9, 0, 9, &[0, 0, 0, 0, 4, 0xf9, 0xfe, 1, 6]);
    let b = element(9, 11, 9, &[0, 0, 0, 0, 4, 0xe1, 0xe5, 0xfd, 3]);
    let c = element(9, 0, 9, &[0, 0, 0, 0, 4, 20, 24, 28, 32]);
    let d = element(9, 11, 11, &[0, 0, 0, 0, 4, 0xa1, 0xc1, 0xe1, 0xf1, 0, 0]);
    let elements = [a, b, c, d];
    let exact = Plan::from_elements(&elements, 11).unwrap();
    let default = Plan::from_elements(&elements, 7).unwrap();
    if exact.byrate[..4] != [-95, -63, -31, -15]
        || default.byrate[..4] != [20, 24, 28, 32]
        || exact.byrate[4..] != [0; 40]
        || exact.offset != [0; 5]
    {
        return TestResult::Fail("power RFE last-match/default/legacy zero extension changed");
    }
    let lmt = element(10, 0, 7, &[0, 1, 2, 1, 0, 0, 0xf9]);
    let ru = element(13, 0, 5, &[2, 1, 0, 0, 0xf5]);
    let shape = element(16, 0, 4, &[0, 1, 0, 3]);
    let p = Plan::from_elements(&[lmt, ru, shape], 1).unwrap();
    if p.limits[1][7] != -7 || p.ru[1][2] != -11 || p.shape != [0, 3] {
        return TestResult::Fail("signed source limit/RU/shape decode changed");
    }
    for bad in 0..8 {
        let mut e = element(9, 0, 11, &[0, 0, 0, 0, 4, 80, 80, 80, 80, 0, 0]);
        match bad {
            0 => e.bytes.pop().map(|_| ()).unwrap(),
            1 => e.bytes[0] = 1,
            2 => e.bytes[3] = 0,
            3 => e.bytes[8] = 3,
            4 => e.bytes[10] = 8,
            5 => e.bytes[11] = 4,
            6 => e.bytes[17] = 5,
            _ => {
                e.bytes[3] = 12;
                e.bytes.push(1);
            }
        }
        if Plan::from_elements(&[e], 1).is_ok() {
            return TestResult::Fail("malformed present power override fell back");
        }
    }
    if Plan::from_elements(&[], 255).is_ok()
        || Plan::from_elements(&[], 1).unwrap() != defaults::DEFAULT
    {
        return TestResult::Fail("power missing-only exact B fallback");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_power_rfe_selection_signed_decoding_and_invalid_override_fail_closed
);
