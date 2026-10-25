use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
struct Case {
    operation: u8,
    address: u16,
    speed: u8,
    seed: u8,
    result: u16,
    trace: &'static [(u8, u32, u32)],
}
include!("golden.rs");
struct Model {
    regs: Vec<u8>,
    config: Vec<u8>,
    rac: [[u16; 32]; 4],
    trace: Vec<(u8, u32, u32)>,
    now: u64,
    operations: usize,
    fail: Option<usize>,
    stuck: bool,
    pending: bool,
    gone: bool,
}
impl Model {
    fn new(seed: u8) -> Self {
        let mut m = Self {
            regs: vec![seed; 65536],
            config: vec![seed; 4096],
            rac: [[u16::from(seed) * 257; 32]; 4],
            trace: Vec::new(),
            now: 0,
            operations: 0,
            fail: None,
            stuck: false,
            pending: false,
            gone: false,
        };
        let cfg = m.word(0x10a0) & !0x300;
        m.regs[0x10a0..0x10a2].copy_from_slice(&cfg.to_le_bytes());
        m.regs[0x1092] = 0;
        m
    }
    fn access(&mut self) -> Result<(), Error> {
        let at = self.operations;
        self.operations += 1;
        if self.fail == Some(at) {
            Err(Error::Access)
        } else {
            Ok(())
        }
    }
    fn word(&self, a: usize) -> u16 {
        u16::from_le_bytes(self.regs[a..a + 2].try_into().unwrap())
    }
}
impl Io for Model {
    fn read8(&mut self, a: u32) -> Result<u8, Error> {
        self.access()?;
        let a = a as usize;
        if a == 0x1092 {
            if self.gone {
                return Ok(255);
            }
            let flag = self.regs[a];
            if flag != 0 && !self.stuck {
                let f = self.word(0x1090);
                if flag & 1 != 0 {
                    let byte = (f >> 12).trailing_zeros() as usize;
                    self.config[usize::from(f & 0xffc) + byte] = self.regs[0x1094 + byte];
                }
                if flag & 2 != 0 {
                    self.regs[0x1098..0x109c].copy_from_slice(
                        &self.config[usize::from(f & 0xffc)..usize::from(f & 0xffc) + 4],
                    );
                }
                self.regs[a] = 0;
            }
        }
        Ok(self.regs[a])
    }
    fn read16(&mut self, a: u32) -> Result<u16, Error> {
        self.access()?;
        let a = a as usize;
        let mut value = self.word(a);
        if a == 0x10a0 {
            if self.gone {
                return Ok(65535);
            }
            if value & 0x300 != 0 && !self.stuck {
                let (page, reg) = (usize::from((value >> 12) & 3), usize::from(value & 31));
                if value & 0x100 != 0 {
                    self.rac[page][reg] = self.word(0x10a4);
                }
                if value & 0x200 != 0 {
                    self.regs[0x10a6..0x10a8].copy_from_slice(&self.rac[page][reg].to_le_bytes());
                }
                value &= !0x300;
                self.regs[a..a + 2].copy_from_slice(&value.to_le_bytes());
            }
        }
        Ok(value)
    }
    fn read32(&mut self, _: u32) -> Result<u32, Error> {
        Err(Error::Unsupported)
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), Error> {
        self.access()?;
        self.trace.push((8, a, u32::from(v)));
        self.regs[a as usize] = v;
        Ok(())
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), Error> {
        self.access()?;
        self.trace.push((16, a, u32::from(v)));
        self.regs[a as usize..a as usize + 2].copy_from_slice(&v.to_le_bytes());
        Ok(())
    }
    fn write32(&mut self, _: u32, _: u32) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn now_us(&self) -> u64 {
        self.now
    }
    async fn delay_us(&mut self, us: u64) {
        if self.pending {
            core::future::pending::<()>().await;
        }
        self.now += us;
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, Error> {
        Err(Error::Unsupported)
    }
}
async fn operation(owner: &mut Access, m: &mut Model, c: &Case) -> Result<u16, Error> {
    let generation = if c.speed == 0 {
        Generation::One
    } else {
        Generation::Two
    };
    match c.operation {
        0 => {
            owner
                .read_phy(m, ChipId::Rtl8852B, generation, c.address as u8)
                .await
        }
        1 => owner
            .write_phy(m, ChipId::Rtl8852B, generation, c.address as u8, 0x5ac3)
            .await
            .map(|_| 0),
        2 => owner
            .modify_phy(m, ChipId::Rtl8852B, generation, c.address as u8, 0xf0, 0xb)
            .await
            .map(|_| 0),
        3 => owner
            .read_dbi(m, ChipId::Rtl8852B, c.address)
            .await
            .map(u16::from),
        _ => owner
            .write_dbi(m, ChipId::Rtl8852B, c.address, 0x5a)
            .await
            .map(|_| 0),
    }
}
fn once<T>(f: impl Future<Output = T>) -> Option<T> {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}
fn smoke_rtw89_pcie_phy_and_dbi_match_reference_traces() -> TestResult {
    for c in CASES {
        let mut owner = Access::default();
        let mut m = Model::new(c.seed);
        if once(operation(&mut owner, &mut m, c)) != Some(Ok(c.result))
            || m.trace != c.trace
            || owner.terminal
        {
            return TestResult::Fail("Linux MDIO page/width/mask or DBI byte-enable trace");
        }
        let total = m.operations;
        for fail in 0..total {
            let mut owner = Access::default();
            let mut m = Model::new(c.seed);
            m.fail = Some(fail);
            if once(operation(&mut owner, &mut m, c)) != Some(Err(Error::Access)) || !owner.terminal
            {
                return TestResult::Fail("uncertain PCIe PHY/DBI access reopened owner");
            }
            let accesses = m.operations;
            if once(operation(&mut owner, &mut m, c)) != Some(Err(Error::Terminal))
                || m.operations != accesses
            {
                return TestResult::Fail("failed PHY/DBI owner accessed registers again");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_pcie_phy_and_dbi_match_reference_traces
);

fn smoke_rtw89_pcie_phy_cancel_timeout_gone_and_unknown_request() -> TestResult {
    for op in [0, 1, 2, 3, 4] {
        let case = Case {
            operation: op,
            address: 1,
            speed: 1,
            seed: 0,
            result: 0,
            trace: &[],
        };
        let mut owner = Access::default();
        let mut m = Model::new(0);
        m.stuck = true;
        if once(operation(&mut owner, &mut m, &case)) != Some(Err(Error::Timeout))
            || !owner.terminal
            || m.now != if op < 3 { 2000 } else { 200 }
        {
            return TestResult::Fail("MDIO/DBI timeout accepted or budget changed");
        }
        let mut owner = Access::default();
        let mut m = Model::new(0);
        m.stuck = true;
        m.pending = true;
        if once(operation(&mut owner, &mut m, &case)).is_some() || !owner.terminal {
            return TestResult::Fail("cancelled controller request lost persistent exclusion");
        }
        let writes = m.trace.len();
        let mut replacement = Access::default();
        if once(operation(&mut replacement, &mut m, &case)) != Some(Err(Error::Terminal))
            || m.trace.len() != writes
        {
            return TestResult::Fail("fresh software object overwrote an unknown active request");
        }
        let mut owner = Access::default();
        let mut m = Model::new(0);
        m.gone = true;
        if once(operation(&mut owner, &mut m, &case)) != Some(Err(Error::Gone))
            || !m.trace.is_empty()
        {
            return TestResult::Fail("all-ones controller accepted data/address publication");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_pcie_phy_cancel_timeout_gone_and_unknown_request
);

fn smoke_rtw89_direct_rac_and_invalid_inputs_have_exact_extents() -> TestResult {
    for generation in [Generation::One, Generation::Two] {
        let base = if generation == Generation::One {
            0x3800
        } else {
            0x3880
        };
        let mut owner = Access::default();
        let mut m = Model::new(0);
        if once(owner.write_phy(&mut m, ChipId::Rtl8852C, generation, 63, 65535)) != Some(Ok(()))
            || m.trace != [(16, base + 126, 65535)]
            || once(owner.read_phy(&mut m, ChipId::Rtl8852C, generation, 63)) != Some(Ok(65535))
            || once(owner.modify_phy(&mut m, ChipId::Rtl8852C, generation, 63, 0xf0, 3))
                != Some(Ok(()))
            || m.word(base as usize + 126) != 0xff3f
        {
            return TestResult::Fail("C direct RAC generation/address/opaque16-bit data");
        }
    }
    let mut owner = Access::default();
    let mut m = Model::new(0);
    if once(owner.read_phy(&mut m, ChipId::Rtl8852B, Generation::One, 64))
        != Some(Err(Error::Access))
        || once(owner.modify_phy(&mut m, ChipId::Rtl8852B, Generation::One, 1, 0, 0))
            != Some(Err(Error::Access))
        || once(owner.modify_phy(&mut m, ChipId::Rtl8852B, Generation::One, 1, 0xa, 2))
            != Some(Err(Error::Access))
        || once(owner.read_dbi(&mut m, ChipId::Rtl8852C, 1)) != Some(Err(Error::Unsupported))
        || once(owner.write_dbi(&mut m, ChipId::Rtl8852B, 4096, 1)) != Some(Err(Error::Access))
        || once(owner.read_phy(&mut m, ChipId::Rtl8922A, Generation::One, 0))
            != Some(Err(Error::Unsupported))
        || m.operations != 0
        || owner.terminal
    {
        return TestResult::Fail("unsupported or aliasing PHY/DBI request touched hardware");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_direct_rac_and_invalid_inputs_have_exact_extents
);
