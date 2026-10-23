use super::efuse::{decode_map, read_mac_with, EfuseError, Io};
use super::mac::{ChipId, B_AX_EF_RDY, R_AX_EFUSE_CTRL, R_AX_EFUSE_CTRL_1};
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

struct Model {
    regs: [u8; 256],
    raw: [u8; 1216],
    ctrl: u32,
    busy: bool,
    stalled: bool,
    writes: Vec<(u64, usize, u32)>,
    delays: Vec<u64>,
    physical_reads: usize,
}
impl Model {
    fn new() -> Self {
        let mut raw = [0xff; 1216];
        raw[..4].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        raw[4..12].copy_from_slice(&[8, 8, 2, 0xe0, 0x4c, 1, 2, 3]);
        let mut regs = [0; 256];
        regs[0..2].copy_from_slice(&0x0120u16.to_le_bytes());
        regs[0xcc] = 0x80;
        regs[R_AX_EFUSE_CTRL_1 as usize + 1] = 3;
        Self {
            regs,
            raw,
            ctrl: 0,
            busy: false,
            stalled: false,
            writes: Vec::new(),
            delays: Vec::new(),
            physical_reads: 0,
        }
    }
    fn iso(&self) -> u16 {
        u16::from_le_bytes([self.regs[0], self.regs[1]])
    }
}
impl Io for Model {
    fn read8(&mut self, a: u64) -> u8 {
        self.regs[a as usize]
    }
    fn write8(&mut self, a: u64, v: u8) {
        self.regs[a as usize] = v;
        self.writes.push((a, 1, v as u32));
    }
    fn read16(&mut self, a: u64) -> u16 {
        u16::from_le_bytes([self.regs[a as usize], self.regs[a as usize + 1]])
    }
    fn write16(&mut self, a: u64, v: u16) {
        self.regs[a as usize..a as usize + 2].copy_from_slice(&v.to_le_bytes());
        self.writes.push((a, 2, v as u32));
    }
    fn read32(&mut self, a: u64) -> u32 {
        if a == R_AX_EFUSE_CTRL {
            if self.busy || self.stalled {
                self.busy = false;
                return self.ctrl;
            }
            self.physical_reads += 1;
            return self.ctrl | B_AX_EF_RDY | self.raw[(self.ctrl >> 16) as usize] as u32;
        }
        u32::from_le_bytes(self.regs[a as usize..a as usize + 4].try_into().unwrap())
    }
    fn write32(&mut self, a: u64, v: u32) {
        self.writes.push((a, 4, v));
        if a == R_AX_EFUSE_CTRL {
            self.ctrl = v;
            self.busy = true;
        } else {
            self.regs[a as usize..a as usize + 4].copy_from_slice(&v.to_le_bytes());
        }
    }
    fn delay_us(&mut self, us: u64) {
        self.delays.push(us);
    }
}

fn smoke_rtw89_ax_factory_mac_and_power_lifecycle() -> TestResult {
    for (chip, cut) in [
        (ChipId::Rtl8852A, 0),
        (ChipId::Rtl8852B, 0),
        (ChipId::Rtl8852B, 1),
        (ChipId::Rtl8852C, 0),
        (ChipId::Rtl8851B, 0),
    ] {
        let mut model = Model::new();
        if read_mac_with(&mut model, chip, cut) != Ok([2, 0xe0, 0x4c, 1, 2, 3])
            || model.physical_reads != 1216
        {
            return TestResult::Fail(
                "rtw89 did not decode AX logical PCI MAC from the full physical map",
            );
        }
        let physical: Vec<_> = model
            .writes
            .iter()
            .filter(|&&(addr, _, _)| addr == R_AX_EFUSE_CTRL)
            .collect();
        if physical.len() != 1216
            || physical
                .iter()
                .enumerate()
                .any(|(addr, &&(_, width, value))| width != 4 || value != (addr as u32) << 16)
        {
            return TestResult::Fail("rtw89 physical read trigger/address or access width wrong");
        }
        if chip == ChipId::Rtl8852A {
            if model.regs[R_AX_EFUSE_CTRL_1 as usize + 1] != 0 || !model.delays.is_empty() {
                return TestResult::Fail(
                    "rtw89 8852A failed bank selection or used another chip's power cut",
                );
            }
        } else if model.iso() != 0x120 || model.regs[0xcc] != 0x80 || model.delays != [1000, 1000] {
            return TestResult::Fail(
                "rtw89 AX EFUSE power cut was not unwound with required delays",
            );
        }
        let burst = model
            .writes
            .iter()
            .any(|&(a, _, v)| a == R_AX_EFUSE_CTRL_1 && v & (1 << 19) != 0);
        if burst != (chip == ChipId::Rtl8852B && cut == 0)
            || model.regs[R_AX_EFUSE_CTRL_1 as usize + 2] & (1 << 3) != 0
        {
            return TestResult::Fail("rtw89 8852B CAV burst mode selection/cleanup wrong");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_ax_factory_mac_and_power_lifecycle
);

fn smoke_rtw89_ax_efuse_truncation_and_bounds() -> TestResult {
    let mut logical = [0; 1536];
    for raw in [
        &[0, 0, 0, 0, 8, 8, 2, 3, 0, 0, 0, 0][..], // Three words enabled, only one present.
        &[0, 0, 0, 0, 0xf, 0xe, 2, 3, 0, 0, 0, 0][..], // Block 240 exceeds 8852A map.
        &[0, 0, 0, 0, 8, 0, 0, 0, 0][..],          // Header reaches the security tail.
    ] {
        if decode_map(raw, &mut logical) != Err(EfuseError::MalformedMap) {
            return TestResult::Fail("rtw89 accepted truncated/outside AX logical EFUSE record");
        }
    }
    let mut model = Model::new();
    model.raw[12..16].copy_from_slice(&[8, 0xe, 4, 5]);
    if read_mac_with(&mut model, ChipId::Rtl8852A, 0) != Ok([4, 5, 0x4c, 1, 2, 3]) {
        return TestResult::Fail("rtw89 later EFUSE word did not override earlier programming");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_ax_efuse_truncation_and_bounds
);

fn smoke_rtw89_ax_efuse_failure_cleanup_and_be_rejection() -> TestResult {
    let mut model = Model::new();
    if read_mac_with(&mut model, ChipId::Rtl8922A, 0) != Err(EfuseError::UnsupportedChip)
        || !model.writes.is_empty()
        || model.physical_reads != 0
    {
        return TestResult::Fail("rtw89 applied AX EFUSE protocol to BE silicon");
    }
    model.stalled = true;
    if read_mac_with(&mut model, ChipId::Rtl8852B, 0) != Err(EfuseError::Timeout)
        || model.iso() != 0x120
        || model.regs[0xcc] != 0x80
        || model.delays != [1000, 1000]
        || model.regs[R_AX_EFUSE_CTRL_1 as usize + 2] & (1 << 3) != 0
    {
        return TestResult::Fail("rtw89 EFUSE timeout leaked power cut/write mask/burst mode");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_ax_efuse_failure_cleanup_and_be_rejection
);
