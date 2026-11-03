// SPDX-License-Identifier: GPL-2.0-or-later
//! SU beamformee programs against a byte-addressed register model.
//! Expected values are authored from Linux `bf.c` / `rtw8822c.c`.
use super::super::firmware_transport::{Error, Io};
use super::{enable_su, phy_init, readback, remove_su, Bfee};
use alloc::{boxed::Box, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Regs {
    mem: Vec<u8>,
}
impl Regs {
    fn new() -> Self {
        Self {
            mem: vec![0; 0x10000],
        }
    }
    fn get(&self, r: u16) -> u32 {
        let r = usize::from(r);
        u32::from_le_bytes(self.mem[r..r + 4].try_into().unwrap())
    }
    fn set(&mut self, r: u16, v: u32) {
        let r = usize::from(r);
        self.mem[r..r + 4].copy_from_slice(&v.to_le_bytes());
    }
}
#[async_trait::async_trait]
// SAFETY: test model with no DMA or hardware.
unsafe impl Io for Regs {
    fn claim_pristine(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn read8(&mut self, r: u16) -> Result<u8, Error> {
        Ok(self.mem[usize::from(r)])
    }
    fn read16(&mut self, r: u16) -> Result<u16, Error> {
        let r = usize::from(r);
        Ok(u16::from_le_bytes([self.mem[r], self.mem[r + 1]]))
    }
    fn read32(&mut self, r: u16) -> Result<u32, Error> {
        Ok(self.get(r))
    }
    fn write8(&mut self, r: u16, v: u8) -> Result<(), Error> {
        self.mem[usize::from(r)] = v;
        Ok(())
    }
    fn write16(&mut self, r: u16, v: u16) -> Result<(), Error> {
        let a = usize::from(r);
        self.mem[a..a + 2].copy_from_slice(&v.to_le_bytes());
        Ok(())
    }
    fn write32(&mut self, r: u16, v: u32) -> Result<(), Error> {
        self.set(r, v);
        Ok(())
    }
    async fn reserved_page(&mut self, _: &[u8]) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    async fn lte_backup(&mut self) -> Result<u32, Error> {
        Err(Error::Unsupported)
    }
    async fn lte_restore(&mut self, _: u32) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    async fn finish_dma(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    async fn delay_us(&mut self, _: u64) {}
}

const AP: [u8; 6] = [2, 0x11, 0x22, 0x33, 0x44, 0x55];

fn smoke_rtw88_bf_phy_init_and_su_bfee_program() -> TestResult {
    let mut r = Regs::new();
    // Prior MU state the source init must clear/replace.
    r.set(0x14c0, 0x0000_f0bf);
    r.set(0x6dc, 0x3f00_1000);
    if phy_init(&mut r).is_err() {
        return TestResult::Fail("rtw_bf_phy_init readback");
    }
    // P1 wait bit16, retry limit 0xa at 15:12, MU MIMO bit7 and table
    // valid 5:0 cleared; option 0x70; NDPA rate 0x10; CSI rate 6M.
    if r.get(0x14c0) != 0x0001_a000
        || r.mem[0x167c] != 0x70
        || r.get(0x1680) & 0xffff != 0
        || r.get(0x42c) != 1 << 30
        || r.mem[0x45f] != 0x10
        || r.get(0x6dc) != 0x0400_1000
    {
        return TestResult::Fail("rtw_bf_phy_init words");
    }
    // AP with 2 sounding dimensions (field 1); C22 nc 1, C21 nc 0.
    let (Some(c22), Some(c21)) = (Bfee::su(0xc822, AP, 2), Bfee::su(0xc821, AP, 2)) else {
        return TestResult::Fail("SU bfee refused");
    };
    if c22.csi_param() != 0x0d09
        || c21.csi_param() != 0x0d08
        || Bfee::su(0xb822, AP, 2).is_some()
        || Bfee::su(0xc822, AP, 0).is_some()
    {
        return TestResult::Fail("csi_param (coef 3, codebook 1, nr, nc) or chip gate");
    }
    r.mem[0x718] = 0x40;
    if enable_su(&mut r, 0xc822, c22).is_err() {
        return TestResult::Fail("C22 SU enable readback");
    }
    if r.mem[0x718] != 0xdb
        || r.mem[0x6e4..0x6ea] != AP
        || r.get(0x6f4) & 0xffff != 0x0d09
        || r.mem[0x71b] != 0x70
        || r.get(0x6dc) & (1 << 30 | 1 << 12) != 1 << 30
        || r.get(0x1678) != 0x550
    {
        return TestResult::Fail("rtw8822c_bf_enable_bfee_su words");
    }
    if remove_su(&mut r).is_err()
        || r.mem[0x718] != 0xd8
        || r.mem[0x6e4..0x6ea] != [0; 6]
        || r.get(0x6f4) & 0xffff != 0
        || readback(&mut r, 0xc822, c22).is_ok()
    {
        return TestResult::Fail("rtw_bf_remove_bfee_su");
    }
    let mut r = Regs::new();
    if enable_su(&mut r, 0xc821, c21).is_err() || r.get(0x1678) != 0 || r.get(0x6dc) != 0 {
        return TestResult::Fail("C21 uses the generic SU path only");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/rtw88/bf",
    smoke_rtw88_bf_phy_init_and_su_bfee_program
);
