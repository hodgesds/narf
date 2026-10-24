use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
struct Model {
    bytes: Vec<u8>,
    writes: Vec<(u32, u32, u32)>,
    operations: usize,
    fail: Option<usize>,
    ignore: Option<u32>,
}
impl Model {
    fn new(seed: u8) -> Self {
        Self {
            bytes: vec![seed; 0x20000],
            writes: Vec::new(),
            operations: 0,
            fail: None,
            ignore: None,
        }
    }
    fn access(&mut self) -> Result<(), Error> {
        let n = self.operations;
        self.operations += 1;
        if self.fail == Some(n) {
            Err(Error::Access)
        } else {
            Ok(())
        }
    }
    fn read(&mut self, a: u32, n: usize) -> Result<u32, Error> {
        self.access()?;
        let mut b = [0; 4];
        b[..n].copy_from_slice(&self.bytes[a as usize..a as usize + n]);
        Ok(u32::from_le_bytes(b))
    }
    fn write(&mut self, a: u32, n: usize, v: u32) -> Result<(), Error> {
        self.access()?;
        self.writes.push((n as u32, a, v));
        if self.ignore != Some(a) {
            self.bytes[a as usize..a as usize + n].copy_from_slice(&v.to_le_bytes()[..n]);
        }
        Ok(())
    }
    fn hash(&self) -> u64 {
        let mut h = 14695981039346656037u64;
        for &(kind, a, v) in &self.writes {
            for word in [kind, a, v] {
                for byte in word.to_le_bytes() {
                    h ^= u64::from(byte);
                    h = h.wrapping_mul(1099511628211);
                }
            }
        }
        h
    }
}
impl Io for Model {
    fn read8(&mut self, a: u32) -> Result<u8, Error> {
        Ok(self.read(a, 1)? as u8)
    }
    fn read16(&mut self, a: u32) -> Result<u16, Error> {
        Ok(self.read(a, 2)? as u16)
    }
    fn read32(&mut self, a: u32) -> Result<u32, Error> {
        self.read(a, 4)
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), Error> {
        self.write(a, 1, u32::from(v))
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), Error> {
        self.write(a, 2, u32::from(v))
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), Error> {
        self.write(a, 4, v)
    }
    fn now_us(&self) -> u64 {
        0
    }
    async fn delay_us(&mut self, _: u64) {}
    async fn read_ecv(&mut self) -> Result<Option<u8>, Error> {
        Err(Error::Unsupported)
    }
}
fn close(io: &mut Model) -> Result<(), Error> {
    let engine = engines(io);
    let clock = clocks(io);
    engine.and(clock)
}
fn smoke_rtw89_b_terminal_engine_and_clock_controls_match_original_linux_c() -> TestResult {
    for &(seed, count, hash) in CASES {
        let mut io = Model::new(seed);
        if close(&mut io) != Ok(()) || io.writes.len() != count as usize || io.hash() != hash {
            return TestResult::Fail(
                "B PMAC/NCTL/clock closure differs from original C widths/order",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_terminal_engine_and_clock_controls_match_original_linux_c
);
fn smoke_rtw89_b_terminal_closure_continues_after_fault_and_checks_ignored_controls() -> TestResult
{
    let mut baseline = Model::new(0xa5);
    if close(&mut baseline) != Ok(()) {
        return TestResult::Fail("terminal closure baseline");
    }
    for fail in 0..baseline.operations {
        let mut io = Model::new(0xa5);
        io.fail = Some(fail);
        if close(&mut io).is_ok() {
            return TestResult::Fail("failed terminal control returned successful closure");
        }
        if fail == 0 && !io.writes.iter().any(|&(_, a, _)| a == R_AX_SYS_FUNC_EN) {
            return TestResult::Fail("independent BB reset skipped after first stop failure");
        }
    }
    for address in [
        0x10000 + R_PMAC_TX_PRD,
        0x10000 + R_PMAC_GNT,
        0x10000 + R_NCTL_N1,
        0x10000 + R_KIP_SYSCFG,
        R_AX_WLRF_CTRL,
        R_AX_SYS_FUNC_EN,
    ] {
        let mut io = Model::new(0xa5);
        io.ignore = Some(address);
        let a = (0x10000 + R_PMAC_TX_PRD) as usize;
        io.bytes[a] |= 0x11;
        let a = R_AX_WLRF_CTRL as usize;
        let v = u32::from_le_bytes(io.bytes[a..a + 4].try_into().unwrap()) | B_AX_AFC_AFEDIG;
        io.bytes[a..a + 4].copy_from_slice(&v.to_le_bytes());
        if close(&mut io).is_ok() {
            return TestResult::Fail("ignored radio stop control claimed closure");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_terminal_closure_continues_after_fault_and_checks_ignored_controls
);
