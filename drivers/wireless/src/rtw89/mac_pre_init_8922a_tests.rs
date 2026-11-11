// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Fixture tests for the RTL8922A MAC pre-init owner. Expected
//! words are computed in the test from the Linux `reg.h` / `mac.h`
//! bit positions and the `rtw8922a.c` / `mac_be.c` step order, never
//! by calling the code under test — so a shift error in production
//! cannot be masked by the same error in the fixture.
//!
//! The fixture `Model` emulates the hardware side effects Linux's
//! polls wait for (XTAL-SI command completion, `APFM_OFFMAC`
//! self-clear, LPS→ON transition); each emulation is flagged and
//! documented where it is enabled, and the timeout tests run with
//! the emulation off.

use super::mac_pre_init_8922a::*;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

/// Fixture register bank implementing [`Regs`], with
/// hardware-emulation switches for the status transitions the
/// polls wait on.
struct Model {
    regs32: BTreeMap<u32, u32>,
    regs8: BTreeMap<u32, u8>,
    /// XTAL-SI read values by offset (`XTAL_SI_CV`, `CHIP_ID_*`).
    xtal_values: BTreeMap<u8, u8>,
    /// When false, reads of `R_BE_WLAN_XTAL_SI_CTRL` keep the
    /// `CMD_POLL` bit set: the XTAL-SI command never completes.
    xtal_completes: bool,
    /// Last XTAL-SI command offset, for read emulation.
    last_xtal_offset: u8,
    /// Last XTAL-SI command was a read.
    last_xtal_read: bool,
    /// When true, reads of `R_BE_SYS_PW_CTRL` report
    /// `APFM_OFFMAC` clear: the MAC turned off by itself after
    /// the trigger write.
    offmac_clears: bool,
    /// When true, reads of `R_BE_IC_PWR_STATE` report `MAC_ON`
    /// once `FORCE_LEAVE_LPS` is set: the MAC left LPS.
    lps_to_on: bool,
    /// XTAL-SI command words written, in order.
    xtal_cmds: Vec<u32>,
    /// A write to `R_BE_SYS_PW_CTRL` carried `APFM_OFFMAC` (the
    /// trigger the `offmac_clears` emulation hides from reads).
    offmac_written: bool,
}

impl Model {
    fn new() -> Self {
        Self {
            regs32: BTreeMap::new(),
            regs8: BTreeMap::new(),
            xtal_values: BTreeMap::new(),
            xtal_completes: true,
            last_xtal_offset: 0,
            last_xtal_read: false,
            offmac_clears: false,
            lps_to_on: false,
            xtal_cmds: Vec::new(),
            offmac_written: false,
        }
    }

    fn with32(mut self, addr: u32, value: u32) -> Self {
        self.regs32.insert(addr, value);
        self
    }

    fn with_xtal(mut self, offset: u8, value: u8) -> Self {
        self.xtal_values.insert(offset, value);
        self
    }
}

impl Regs for Model {
    fn read8(&mut self, address: u32) -> u8 {
        *self.regs8.get(&address).unwrap_or(&0)
    }

    fn read32(&mut self, address: u32) -> u32 {
        if address == R_BE_WLAN_XTAL_SI_CTRL {
            let mut v = *self.regs32.get(&address).unwrap_or(&0);
            if self.xtal_completes {
                v &= !B_BE_WL_XTAL_SI_CMD_POLL;
            }
            if self.last_xtal_read {
                // The read data is the seeded XTAL value for the
                // offset the command addressed.
                let data = *self.xtal_values.get(&self.last_xtal_offset).unwrap_or(&0);
                v = (v & !B_BE_WL_XTAL_SI_DATA_MASK) | ((data as u32) << 8);
            }
            return v;
        }
        if address == R_BE_SYS_PW_CTRL && self.offmac_clears {
            return *self.regs32.get(&address).unwrap_or(&0) & !B_BE_APFM_OFFMAC;
        }
        if address == R_BE_IC_PWR_STATE && self.lps_to_on {
            let wllps = *self.regs32.get(&R_BE_WLLPS_CTRL).unwrap_or(&0);
            if wllps & B_BE_FORCE_LEAVE_LPS != 0 {
                let v = *self.regs32.get(&address).unwrap_or(&0);
                return (v & !B_BE_WLMAC_PWR_STE_MASK)
                    | (MAC_AX_MAC_ON << B_BE_WLMAC_PWR_STE_SHIFT);
            }
        }
        *self.regs32.get(&address).unwrap_or(&0)
    }

    fn write8(&mut self, address: u32, value: u8) {
        self.regs8.insert(address, value);
    }

    fn write32(&mut self, address: u32, value: u32) {
        if address == R_BE_SYS_PW_CTRL && value & B_BE_APFM_OFFMAC != 0 {
            self.offmac_written = true;
        }
        if address == R_BE_WLAN_XTAL_SI_CTRL {
            self.xtal_cmds.push(value);
            self.last_xtal_offset = (value & B_BE_WL_XTAL_SI_ADDR_MASK) as u8;
            self.last_xtal_read = (value & B_BE_WL_XTAL_SI_MODE_MASK) >> 24 == XTAL_SI_NORMAL_READ;
        }
        self.regs32.insert(address, value);
    }
}

fn smoke_rtw89_mac_pre_init_xtal_si() -> TestResult {
    // Write command word, from the mac_be.c:413 field layout:
    // ADDR (7:0) | DATA (15:8) | BITMASK (23:16) | MODE (25:24) |
    // CHIPID (30:28) = 0 | CMD_POLL (31).
    let mut m = Model::new();
    if write_xtal_si(&mut m, 0xE0, 0x02, 0x02).is_err() {
        return TestResult::Fail("XTAL-SI write timed out with completion emulated");
    }
    let cmd = match m.xtal_cmds.first() {
        Some(cmd) => *cmd,
        None => return TestResult::Fail("XTAL-SI write issued no command"),
    };
    let want: u32 = 0xE0 | (0x02 << 8) | (0x02 << 16) | (1 << 31);
    if cmd != want {
        return TestResult::Fail("XTAL-SI write command word wrong");
    }
    // Timeout path: the command never completes.
    let mut m = Model::new();
    m.xtal_completes = false;
    if write_xtal_si(&mut m, 0xE0, 0x02, 0x02).is_ok() {
        return TestResult::Fail("XTAL-SI write must time out when CMD_POLL never clears");
    }
    // Read path: the seeded value comes back in the DATA field.
    let mut m = Model::new().with_xtal(0x41, 0x5A);
    match read_xtal_si(&mut m, 0x41) {
        Ok(0x5A) => {}
        _ => return TestResult::Fail("XTAL-SI read did not return the seeded value"),
    }
    let cmd = match m.xtal_cmds.first() {
        Some(cmd) => *cmd,
        None => return TestResult::Fail("XTAL-SI read issued no command"),
    };
    let want: u32 = 0x41 | (0x01 << 24) | (1 << 31);
    if cmd != want {
        return TestResult::Fail("XTAL-SI read command word wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_mac_pre_init_xtal_si);

fn smoke_rtw89_mac_pre_init_chip_ver() -> TestResult {
    // cid 0x79 (CID7090), acv 3, aid 0x1234, cv passed through.
    let mut m = Model::new()
        .with32(R_BE_SYS_CHIPINFO, 0x79)
        .with_xtal(XTAL_SI_CV, 0x03)
        .with_xtal(XTAL_SI_CHIP_ID_L, 0x34)
        .with_xtal(XTAL_SI_CHIP_ID_H, 0x12);
    let ver = match read_chip_ver(&mut m, 1) {
        Ok(ver) => ver,
        Err(_) => return TestResult::Fail("read_chip_ver failed with completion emulated"),
    };
    if ver.cv != 1 || ver.cid != Cid::Cid7090 || ver.acv != 3 || ver.aid != 0x1234 {
        return TestResult::Fail("HalChipVer fields wrong");
    }
    // Unknown cid byte is retained, not forced into a known variant.
    let mut m = Model::new()
        .with32(R_BE_SYS_CHIPINFO, 0xAB)
        .with_xtal(XTAL_SI_CV, 0x00)
        .with_xtal(XTAL_SI_CHIP_ID_L, 0x00)
        .with_xtal(XTAL_SI_CHIP_ID_H, 0x00);
    match read_chip_ver(&mut m, 0) {
        Ok(ver) if ver.cid == Cid::Unknown(0xAB) && ver.cid.raw() == 0xAB => {}
        _ => return TestResult::Fail("unknown cid byte must round-trip as Unknown"),
    }
    // Cid decode of the known values.
    if Cid::from_raw(0x74) != Cid::Cid7025 || Cid::from_raw(0x79) != Cid::Cid7090 {
        return TestResult::Fail("known cid bytes decode wrong");
    }
    // Completion-timeout decision (pci.c:4392): only CID7090 keeps
    // the timeout enabled (for an 8922D); every other cid disables it.
    if !completion_timeout_disabled_for_8922d(Cid::Cid7025)
        || completion_timeout_disabled_for_8922d(Cid::Cid7090)
        || !completion_timeout_disabled_for_8922d(Cid::Unknown(0xAB))
    {
        return TestResult::Fail("completion-timeout decision wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_mac_pre_init_chip_ver);

fn smoke_rtw89_mac_pre_init_reset_off() -> TestResult {
    // MAC_OFF: FSM idle (low 9 bits 0), power state field 0.
    let mut m = Model::new()
        .with32(R_BE_SYSON_FSM_MON, 0)
        .with32(R_BE_IC_PWR_STATE, 0)
        // Both IO enables (bits 24, 28) set; the IO / backup-restore
        // status bits (26, 27, 31) idle so the mac_be.c polls pass.
        .with32(R_BE_HCI_OPT_CTRL, 0x13FF_FFFF)
        .with32(R_BE_SYS_PW_CTRL, B_BE_EN_WLON | B_BE_APFM_SWLPS);
    if reset_pwr_state(&mut m).is_err() {
        return TestResult::Fail("reset_pwr_state (MAC_OFF) failed");
    }
    // FSM write: (0 & MASK) | SET.
    if m.regs32.get(&R_BE_SYSON_FSM_MON) != Some(&0x4000000) {
        return TestResult::Fail("FSM monitor write wrong");
    }
    // HAXIDMA + WLAN IO enables cleared; EN_WLON + SWLPS cleared.
    let hci = *m.regs32.get(&R_BE_HCI_OPT_CTRL).unwrap_or(&0);
    if hci & (B_BE_HAXIDMA_IO_EN | B_BE_HCI_WLAN_IO_EN) != 0 {
        return TestResult::Fail("MAC_OFF reset must clear both IO enables");
    }
    let pw = *m.regs32.get(&R_BE_SYS_PW_CTRL).unwrap_or(&0);
    if pw & (B_BE_EN_WLON | B_BE_APFM_SWLPS) != 0 {
        return TestResult::Fail("MAC_OFF reset must clear EN_WLON and SWLPS");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_mac_pre_init_reset_off);

fn smoke_rtw89_mac_pre_init_reset_on_lps() -> TestResult {
    // MAC_ON: state field 1; the OFFMAC self-clear is emulated.
    let mut m = Model::new()
        .with32(R_BE_SYSON_FSM_MON, 0)
        .with32(R_BE_IC_PWR_STATE, 1 << 8)
        .with32(R_BE_HCI_OPT_CTRL, 0)
        .with32(R_BE_SYS_PW_CTRL, 0);
    m.offmac_clears = true;
    if reset_pwr_state(&mut m).is_err() {
        return TestResult::Fail("reset_pwr_state (MAC_ON) failed");
    }
    // EN_WLON set then cleared by the branch tail; SWLPS cleared.
    let pw = *m.regs32.get(&R_BE_SYS_PW_CTRL).unwrap_or(&0);
    if pw & (B_BE_EN_WLON | B_BE_APFM_SWLPS) != 0 {
        return TestResult::Fail("MAC_ON reset must end with EN_WLON/SWLPS clear");
    }
    // The OFFMAC trigger was written; the emulated self-clear hides
    // it from the read-modify-write tail, so the stored word lacks it.
    if !m.offmac_written {
        return TestResult::Fail("MAC_ON reset must set APFM_OFFMAC");
    }
    // MAC_LPS: state field 2; LPS->ON + OFFMAC-clear emulated.
    let mut m = Model::new()
        .with32(R_BE_SYSON_FSM_MON, 0)
        .with32(R_BE_IC_PWR_STATE, 2 << 8)
        .with32(R_BE_HCI_OPT_CTRL, 0)
        .with32(R_BE_SYS_PW_CTRL, 0)
        .with32(R_BE_WLLPS_CTRL, 0);
    m.offmac_clears = true;
    m.lps_to_on = true;
    if reset_pwr_state(&mut m).is_err() {
        return TestResult::Fail("reset_pwr_state (MAC_LPS) failed");
    }
    // FORCE_LEAVE_LPS set then cleared by the branch tail.
    let wllps = *m.regs32.get(&R_BE_WLLPS_CTRL).unwrap_or(&0);
    if wllps & B_BE_FORCE_LEAVE_LPS != 0 {
        return TestResult::Fail("MAC_LPS reset must end with FORCE_LEAVE_LPS clear");
    }
    // Unknown state (field 3): fall-through Ok, only the FSM write.
    let mut m = Model::new()
        .with32(R_BE_SYSON_FSM_MON, 0)
        .with32(R_BE_IC_PWR_STATE, 3 << 8)
        .with32(R_BE_HCI_OPT_CTRL, 0x1234_5678);
    if reset_pwr_state(&mut m).is_err() {
        return TestResult::Fail("reset_pwr_state (unknown state) must fall through Ok");
    }
    if m.regs32.get(&R_BE_HCI_OPT_CTRL) != Some(&0x1234_5678) {
        return TestResult::Fail("unknown-state reset must not touch HCI_OPT_CTRL");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_mac_pre_init_reset_on_lps
);

fn smoke_rtw89_mac_pre_init_tail() -> TestResult {
    // PCIe + non-CAV: full tail. Status bits pre-seeded so the
    // HAXIDMA/WLAN-IO polls pass on the first read.
    let mut m = Model::new()
        .with32(R_BE_HCI_OPT_CTRL, B_BE_HAXIDMA_IO_ST | B_BE_HCI_WLAN_IO_ST)
        .with32(R_BE_SYS_ADIE_PAD_PWR_CTRL, 0)
        .with32(R_BE_DMAC_FUNC_EN, 0)
        .with32(R_BE_CMAC_SHARE_FUNC_EN, 0)
        .with32(R_BE_CMAC_FUNC_EN, 0)
        .with32(R_BE_FEN_RST_ENABLE, 0);
    if power_on_tail(&mut m, true, 1).is_err() {
        return TestResult::Fail("power_on_tail (PCIe, cv=1) failed");
    }
    // AFE clock-monitor clear, ANAPAR LDO ports set, ADDA ISO clear.
    if m.regs32.get(&R_BE_AFE_ON_CTRL1).unwrap_or(&0) & B_BE_REG_CK_MON_CK960M_EN != 0 {
        return TestResult::Fail("tail must clear CK960M_EN");
    }
    if m.regs8.get(&R_BE_ANAPAR_POW_MAC).unwrap_or(&0)
        & (B_BE_POW_PC_LDO_PORT0 | B_BE_POW_PC_LDO_PORT1)
        != B_BE_POW_PC_LDO_PORT0 | B_BE_POW_PC_LDO_PORT1
    {
        return TestResult::Fail("tail must set both ANAPAR LDO ports");
    }
    if m.regs32.get(&R_BE_FEN_RST_ENABLE).unwrap_or(&0)
        & (B_BE_R_SYM_ISO_ADDA_P02PP | B_BE_R_SYM_ISO_ADDA_P12PP)
        != 0
    {
        return TestResult::Fail("tail must clear both ADDA ISO bits (checked pre-FEN set)");
    }
    if m.regs8.get(&R_BE_PLATFORM_ENABLE).unwrap_or(&0) & B_BE_PLATFORM_EN == 0 {
        return TestResult::Fail("tail must set PLATFORM_EN");
    }
    // PCIe arms: HAXIDMA + WLAN IO enables set, IBX force clear.
    let hci = *m.regs32.get(&R_BE_HCI_OPT_CTRL).unwrap_or(&0);
    if hci & (B_BE_HAXIDMA_IO_EN | B_BE_HCI_WLAN_IO_EN) != B_BE_HAXIDMA_IO_EN | B_BE_HCI_WLAN_IO_EN
    {
        return TestResult::Fail("tail must set both HCI IO enables");
    }
    if m.regs32.get(&R_BE_SYS_SDIO_CTRL).unwrap_or(&0) & B_BE_PCIE_FORCE_IBX_EN != 0 {
        return TestResult::Fail("tail must clear PCIE_FORCE_IBX_EN");
    }
    // ADIE pad power: both RFC pad bits set.
    let pad = *m.regs32.get(&R_BE_SYS_ADIE_PAD_PWR_CTRL).unwrap_or(&0);
    if pad & (B_BE_SYM_PADPDN_WL_RFC1_1P3 | B_BE_SYM_PADPDN_WL_RFC0_1P3)
        != B_BE_SYM_PADPDN_WL_RFC1_1P3 | B_BE_SYM_PADPDN_WL_RFC0_1P3
    {
        return TestResult::Fail("tail must set both ADIE pad-power bits");
    }
    // XTAL-SI program: 16 writes (rtw8922a_pwr_on_func), first
    // (PLL,0x02,0x02), last (SRAM_CTRL,0,SRAM_DIS=0x02).
    if m.xtal_cmds.len() != 16 {
        return TestResult::Fail("tail must issue exactly 16 XTAL-SI writes");
    }
    let first = m.xtal_cmds[0];
    if first != 0xE0 | (0x02 << 8) | (0x02 << 16) | (1 << 31) {
        return TestResult::Fail("first XTAL-SI write must be (PLL,0x02,0x02)");
    }
    let last = m.xtal_cmds[15];
    if last != 0xA1 | (0x02 << 16) | (1 << 31) {
        return TestResult::Fail("last XTAL-SI write must be (SRAM_CTRL,0,0x02)");
    }
    // CV-conditional ISO sequence ran (cv=1 != CAV): write-mask
    // set then cleared, ISO_EB2CORE set, EV2EF bits cleared.
    if m.regs32.get(&R_BE_PMC_DBG_CTRL2).unwrap_or(&0) & B_BE_SYSON_DIS_PMCR_BE_WRMSK != 0 {
        return TestResult::Fail("ISO sequence must end with the write-mask clear");
    }
    let iso = *m.regs32.get(&R_BE_SYS_ISO_CTRL).unwrap_or(&0);
    if iso & B_BE_ISO_EB2CORE == 0 || iso & (B_BE_PWC_EV2EF_B | B_BE_PWC_EV2EF_S) != 0 {
        return TestResult::Fail("ISO sequence end state wrong");
    }
    // DMAC function enables, computed from the Linux bit list
    // (rtw8922a.c:606..615) + PCIe LTR_CTL_EN.
    let want_dmac: u32 = (1 << 30)
        | (1 << 29)
        | (1 << 28)
        | (1 << 27)
        | (1 << 26)
        | (1 << 25)
        | (1 << 24)
        | (1 << 23)
        | (1 << 22)
        | (1 << 21)
        | (1 << 20)
        | (1 << 19)
        | (1 << 18)
        | (1 << 17)
        | (1 << 16)
        | (1 << 14)
        | (1 << 11)
        | (1 << 10)
        | (1 << 9)
        | (1 << 8)
        | (1 << 7);
    if m.regs32.get(&R_BE_DMAC_FUNC_EN) != Some(&want_dmac) {
        return TestResult::Fail("DMAC function-enable value wrong");
    }
    if m.regs32.get(&R_BE_CMAC_SHARE_FUNC_EN) != Some(&((1 << 30) | (1 << 2) | (1 << 1) | (1 << 0)))
    {
        return TestResult::Fail("CMAC share function-enable value wrong");
    }
    let want_cmac: u32 = (1 << 30)
        | (1 << 29)
        | (1 << 28)
        | (1 << 8)
        | (1 << 7)
        | (1 << 6)
        | (1 << 5)
        | (1 << 4)
        | (1 << 3)
        | (1 << 2)
        | (1 << 1)
        | (1 << 0);
    if m.regs32.get(&R_BE_CMAC_FUNC_EN) != Some(&want_cmac) {
        return TestResult::Fail("CMAC function-enable value wrong");
    }
    if m.regs32.get(&R_BE_FEN_RST_ENABLE).unwrap_or(&0)
        & (B_BE_FEN_BB_IP_RSTN | B_BE_FEN_BBPLAT_RSTB)
        != B_BE_FEN_BB_IP_RSTN | B_BE_FEN_BBPLAT_RSTB
    {
        return TestResult::Fail("tail must set both FEN reset bits");
    }
    // CAV (cv=0): the ISO sequence is skipped entirely.
    let mut m = Model::new().with32(R_BE_HCI_OPT_CTRL, B_BE_HAXIDMA_IO_ST | B_BE_HCI_WLAN_IO_ST);
    if power_on_tail(&mut m, true, 0).is_err() {
        return TestResult::Fail("power_on_tail (PCIe, cv=0) failed");
    }
    if m.regs32.contains_key(&R_BE_PMC_DBG_CTRL2) || m.regs32.contains_key(&R_BE_SYS_ISO_CTRL) {
        return TestResult::Fail("CAV tail must skip the ISO sequence");
    }
    // Non-PCIe: no HAXIDMA enable, no LTR_CTL_EN, no SDIO clear.
    let mut m = Model::new().with32(R_BE_HCI_OPT_CTRL, B_BE_HCI_WLAN_IO_ST);
    if power_on_tail(&mut m, false, 1).is_err() {
        return TestResult::Fail("power_on_tail (non-PCIe) failed");
    }
    let hci = *m.regs32.get(&R_BE_HCI_OPT_CTRL).unwrap_or(&0);
    if hci & B_BE_HAXIDMA_IO_EN != 0 {
        return TestResult::Fail("non-PCIe tail must not enable HAXIDMA IO");
    }
    if m.regs32.get(&R_BE_DMAC_FUNC_EN).unwrap_or(&0) & B_BE_LTR_CTL_EN != 0 {
        return TestResult::Fail("non-PCIe tail must not set LTR_CTL_EN");
    }
    if m.regs32.contains_key(&R_BE_SYS_SDIO_CTRL) {
        return TestResult::Fail("non-PCIe tail must not touch SYS_SDIO_CTRL");
    }
    // Timeout path: HAXIDMA status never asserts.
    let mut m = Model::new().with32(R_BE_HCI_OPT_CTRL, 0);
    if power_on_tail(&mut m, true, 1).is_ok() {
        return TestResult::Fail("tail must time out when HAXIDMA_IO_ST never asserts");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_mac_pre_init_tail);
