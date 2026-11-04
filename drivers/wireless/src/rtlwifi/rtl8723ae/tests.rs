// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723AE retained-runtime foundation tests (software models only; no
//! device, firmware execution, BT coexistence or RF acceptance is implied).

use super::*;
use crate::rtlwifi::firmware_transport::{Error as FwError, Io};
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
use version::Version;

// ── chip version ──────────────────────────────────────────────────────────

pub(crate) fn version(sys_cfg: u32) -> Option<Version> {
    Version::from_registers(sys_cfg, || 0, || 0).ok()
}

/// `_rtl8723e_read_chip_version`: `NORMAL_CHIP | CHIP_8723`, UMC vendor
/// and cut, ROM version from `REG_GPIO_OUTSTS[31:28] >> 20`, polarity from
/// `REG_MULTI_FUNC_CTRL[1]`; test chips and non-BT parts are refused.
fn smoke_rtl8723ae_chip_version_and_firmware_names() -> TestResult {
    use version::*;
    let umc_b = BT_FUNC | VENDOR_ID | (1 << 12);
    match Version::from_registers(umc_b, || 0x3000_0000, || WL_HWPDN_SL) {
        Ok(v)
            if v.raw() == 0x1389
                && v.is_umc_b_cut()
                && !v.is_umc_a_cut()
                && v.polarity() == Polarity::HighActive
                && v.firmware() == FW_UMC_B => {}
        _ => return TestResult::Fail("UMC B-cut version / rtl8723fw_B.bin"),
    }
    match Version::from_registers(BT_FUNC | VENDOR_ID, || 0, || 0) {
        Ok(v)
            if v.raw() == 0x0089
                && v.is_umc_a_cut()
                && v.polarity() == Polarity::LowActive
                && v.firmware() == FW_NORMAL => {}
        _ => {
            return TestResult::Fail("UMC A-cut version (VERSION_NORMAL_UMC_CHIP_8723_1T1R_A_CUT)")
        }
    }
    // Non-UMC: the cut nibble is not carried.
    match Version::from_registers(BT_FUNC | (1 << 12), || 0, || 0) {
        Ok(v) if v.raw() == 0x0009 && !v.is_umc() && v.firmware() == FW_NORMAL => {}
        _ => return TestResult::Fail("non-UMC version"),
    }
    if Version::from_registers(TRP_VAUX_EN | BT_FUNC | VENDOR_ID, || 0, || 0)
        != Err(Error::TestChip)
        || Version::from_registers(VENDOR_ID, || 0, || 0) != Err(Error::NotSeries)
    {
        return TestResult::Fail("test chip / non-8723 series admitted");
    }
    if FW_NORMAL != "rtlwifi/rtl8723fw.bin" || FW_UMC_B != "rtlwifi/rtl8723fw_B.bin" {
        return TestResult::Fail("rtl8723ae fw_name");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_chip_version_and_firmware_names
);

// ── adapter facts ─────────────────────────────────────────────────────────

/// A synthetic provisioned map (not any board's values).
pub(crate) fn provisioned() -> Vec<u8> {
    let mut map = vec![0xffu8; adapter::HWSET_MAX_SIZE];
    map[0..2].copy_from_slice(&0x8129u16.to_le_bytes());
    map[0x67..0x6d].copy_from_slice(&[0x00, 0xe0, 0x4c, 0x87, 0x23, 0xae]);
    map[0x49..0x4b].copy_from_slice(&0x10ecu16.to_le_bytes());
    map[0x4b..0x4d].copy_from_slice(&0x8176u16.to_le_bytes());
    map[0x4d..0x4f].copy_from_slice(&0x103cu16.to_le_bytes());
    map[0x4f..0x51].copy_from_slice(&0x1629u16.to_le_bytes());
    map[0x28] = 0x20;
    map[0x30..0x32].copy_from_slice(&[0x01, 0x00]);
    map[0x2e] = 0x31;
    map
}

/// `_rtl8723e_read_adapter_info` through `rtl_get_hwinfo` (8723AE
/// offsets), `rtl8723e_read_bt_coexist_info_from_hwpg` and the OEM rule;
/// unprovisioned maps are refused.
fn smoke_rtl8723ae_adapter_facts_bt_and_oem() -> TestResult {
    use adapter::*;
    let Some(v) = version(version::BT_FUNC | version::VENDOR_ID) else {
        return TestResult::Fail("version");
    };
    let map = provisioned();
    let ok = CR9346_AUTOLOAD_OK;
    let a = match Adapter::from_hardware(v, ok, MULTI_BT_FUNC_EN, &map) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("provisioned map refused"),
    };
    if a.mac != [0x00, 0xe0, 0x4c, 0x87, 0x23, 0xae]
        || a.vid != 0x10ec
        || a.did != 0x8176
        || a.eeprom_channel_plan != 0x20
        || a.eeprom_version != 1
        || !a.bt.coexistence
        || a.bt.kind != BT_RTL8723A
        || a.bt.ant_num != AntNum::X1
        || a.bt.ant_isolation != 1
        || a.bt.radio_shared != 1
        || a.oem != Oem::Hp
        || a.hwinfo[..] != map[..]
    {
        return TestResult::Fail("8723AE adapter facts");
    }
    if oem(0, 0x8178, 0x1043, 0x8486) != Oem::EdimaxAsus
        || oem(0, 0x8176, 0x10ec, 0x9196) != Oem::Clevo
        || oem(0, 0x8176, 0x10ec, 0x9199) != Oem::Default
        || oem(0, 0x8176, 0x10ec, 0x6178) != Oem::Toshiba
        || oem(0x0d, 0, 0, 0) != Oem::Qmi
        || oem(0xfe, 0x8176, 0x1025, 0) != Oem::Default
    {
        return TestResult::Fail("_rtl8723e_read_adapter_info OEM switch");
    }
    let mut bad = map.clone();
    bad[0] = 0;
    if Adapter::from_hardware(v, ok, 0, &bad).is_ok()
        || Adapter::from_hardware(v, 0, 0, &map).is_ok()
        || Adapter::from_hardware(v, ok | CR9346_EEPROM, 0, &map).is_ok()
        || Adapter::from_hardware(v, ok, 0, &map[..0x80]).is_ok()
    {
        return TestResult::Fail("unprovisioned map admitted");
    }
    if efuse_test_wifi_sel(0x1234_0300) != 0x1234_0000 {
        return TestResult::Fail("EFUSE_WIFI_SEL_0");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_adapter_facts_bt_and_oem
);

// ── firmware image ────────────────────────────────────────────────────────

fn image(payload: usize) -> Vec<u8> {
    let mut b = vec![0u8; fw::HEADER + payload];
    b[0..2].copy_from_slice(&0x2302u16.to_le_bytes());
    b[4..6].copy_from_slice(&21u16.to_le_bytes());
    b[12..14].copy_from_slice(&(payload as u16).to_le_bytes());
    b
}

/// `is_fw_header` (`0x2300`), exact RAM-code length and `max_fw_size`.
fn smoke_rtl8723ae_firmware_header_geometry() -> TestResult {
    match fw::parse(&image(0x59b4)) {
        Ok((info, body)) if info.version == 21 && body.len() == 0x59b4 => {}
        _ => return TestResult::Fail("linux-firmware B-cut geometry refused"),
    }
    let mut wrong = image(0x100);
    wrong[0] = 0x01;
    wrong[1] = 0x53;
    let mut short = image(0x100);
    short[12] = 0xff;
    if fw::parse(&wrong).is_ok()
        || fw::parse(&short).is_ok()
        || fw::parse(&image(fw::MAX_PAYLOAD + 1)).is_ok()
        || fw::parse(&image(0)).is_ok()
        || fw::parse(&image(fw::MAX_PAYLOAD)).is_err()
    {
        return TestResult::Fail("8723AE header rule");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_firmware_header_geometry
);

// ── firmware download model ───────────────────────────────────────────────

struct FwModel {
    regs: Vec<u8>,
    pages: Vec<Vec<u8>>,
    writes: Vec<(u16, u32, u8)>,
    /// The 8051 honours `REG_HMETFR + 3 = 0x20` by dropping its enable.
    honours_reset: bool,
    checksum: bool,
    start: bool,
    checksum_reads: u32,
    wintini_reads: u32,
    reset_reads: u32,
    /// ePHY register 0x1e as committed through the MDIO window.
    ephy: Option<u16>,
}
#[derive(Clone)]
struct FwFake(Arc<IrqSafeSpinLock<FwModel>>);
#[async_trait::async_trait]
impl Io for FwFake {
    fn read8(&self, reg: u16) -> Result<u8, FwError> {
        let mut g = self.0.lock();
        if reg == fw::REG_SYS_FUNC_EN + 1 {
            g.reset_reads += 1;
        }
        Ok(g.regs[usize::from(reg)])
    }
    fn read32(&self, reg: u16) -> Result<u32, FwError> {
        let mut g = self.0.lock();
        let r = usize::from(reg);
        let mut v = u32::from_le_bytes([g.regs[r], g.regs[r + 1], g.regs[r + 2], g.regs[r + 3]]);
        if reg == fw::REG_MCUFWDL {
            if v & fw::MCUFWDL_RDY == 0 {
                g.checksum_reads += 1;
            } else {
                g.wintini_reads += 1;
            }
            if g.checksum && v & 1 == 0 && !g.pages.is_empty() {
                v |= fw::FWDL_CHKSUM_RPT;
            }
            if v & fw::MCUFWDL_RDY != 0 && g.start {
                v |= fw::WINTINI_RDY;
            }
        }
        Ok(v)
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), FwError> {
        let mut g = self.0.lock();
        g.writes.push((reg, u32::from(value), 1));
        g.regs[usize::from(reg)] = value;
        if reg == fw::REG_HMETFR + 3 && value == 0x20 && g.honours_reset {
            g.regs[usize::from(fw::REG_SYS_FUNC_EN) + 1] &= !4;
        }
        Ok(())
    }
    fn write16(&self, reg: u16, value: u16) -> Result<(), FwError> {
        let mut g = self.0.lock();
        g.writes.push((reg, u32::from(value), 2));
        let r = usize::from(reg);
        g.regs[r..r + 2].copy_from_slice(&value.to_le_bytes());
        // MDIO window: 0x3e commits the 0x354 data, 0x5e reads it to 0x356.
        match (reg, value) {
            (0x358, 0x3e) => g.ephy = Some(u16::from_le_bytes([g.regs[0x354], g.regs[0x355]])),
            (0x358, 0x5e) => {
                if let Some(v) = g.ephy {
                    g.regs[0x356..0x358].copy_from_slice(&v.to_le_bytes());
                }
            }
            _ => {}
        }
        Ok(())
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), FwError> {
        let mut g = self.0.lock();
        g.writes.push((reg, value, 4));
        let r = usize::from(reg);
        g.regs[r..r + 4].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }
    fn write_bytes(&self, reg: u16, bytes: &[u8]) -> Result<(), FwError> {
        let mut g = self.0.lock();
        let page = usize::from(g.regs[usize::from(fw::REG_MCUFWDL) + 2] & 7);
        while g.pages.len() <= page {
            g.pages.push(Vec::new());
        }
        let at = usize::from(reg - 0x1000);
        let p = &mut g.pages[page];
        if p.len() < at + bytes.len() {
            p.resize(at + bytes.len(), 0xee);
        }
        p[at..at + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
    async fn delay_us(&self, _micros: u64) {}
}

fn fw_fake(checksum: bool, start: bool, running: bool, honours_reset: bool) -> FwFake {
    let mut regs = vec![0u8; 0x2000];
    if running {
        regs[usize::from(fw::REG_MCUFWDL)] = fw::RAM_DL_SEL;
    }
    regs[usize::from(fw::REG_SYS_FUNC_EN) + 1] = 0x04;
    regs[0xf0..0xf4].copy_from_slice(&(version::BT_FUNC | version::VENDOR_ID).to_le_bytes());
    FwFake(Arc::new(IrqSafeSpinLock::new(FwModel {
        regs,
        pages: Vec::new(),
        writes: Vec::new(),
        honours_reset,
        checksum,
        start,
        checksum_reads: 0,
        wintini_reads: 0,
        reset_reads: 0,
        ephy: None,
    })))
}

/// `rtl8723_download_fw(hw, false, 1000)`: running-image
/// `rtl8723ae_firmware_selfreset` (HMETFR request, BIT2 wait, forced clear)
/// and `MCUFWDL = 0`, enable + download gate, `rtl_fill_dummy`, close, 999
/// undelayed checksum reads, `MCUFWDL_RDY` with no 8051 reset, then
/// `WINTINI_RDY` over 1001 reads.
fn smoke_rtl8723ae_firmware_paged_download() -> TestResult {
    let payload: Vec<u8> = (0..(5 * fw::PAGE + 5)).map(|i| i as u8).collect();
    let io = fw_fake(true, true, true, true);
    if narf_scheduler::block_on(fw::download(&io, &payload)).is_err() {
        return TestResult::Fail("8723AE model download failed");
    }
    let g = io.0.lock();
    if g.pages.len() != 6
        || g.pages[0][..] != payload[..fw::PAGE]
        || g.pages[5][..5] != payload[5 * fw::PAGE..]
        || g.pages[5][5..] != [0, 0, 0]
    {
        return TestResult::Fail("page contents / rtl_fill_dummy pad");
    }
    let request = g
        .writes
        .iter()
        .position(|w| *w == (fw::REG_HMETFR + 3, 0x20, 1));
    let zero = g.writes.iter().position(|w| *w == (fw::REG_MCUFWDL, 0, 1));
    match (request, zero) {
        (Some(r), Some(z)) if r < z => {}
        _ => return TestResult::Fail("8723AE self-reset before MCUFWDL = 0"),
    }
    if g.writes
        .iter()
        .filter(|w| w.0 == fw::REG_HMETFR + 3)
        .count()
        != 1
        || g.regs[usize::from(fw::REG_SYS_FUNC_EN) + 1] & 4 == 0
        || g.regs[usize::from(fw::REG_MCUFWDL)] & 1 != 0
        || !g.writes.contains(&(fw::REG_MCUFWDL + 1, 0, 1))
    {
        return TestResult::Fail("8051 enable / download gate close / no post-handshake reset");
    }
    drop(g);
    // An 8051 that ignores the request: 100 reads, then the forced clear.
    let deaf = fw_fake(true, true, false, false);
    if narf_scheduler::block_on(fw::selfreset(&deaf)).is_err()
        || deaf.0.lock().reset_reads != 101
        || deaf.0.lock().regs[usize::from(fw::REG_SYS_FUNC_EN) + 1] & 4 != 0
    {
        return TestResult::Fail("rtl8723ae_firmware_selfreset delay exhaustion");
    }
    let stuck = fw_fake(false, true, false, true);
    if narf_scheduler::block_on(fw::download(&stuck, &payload)) != Err(FwError::Checksum)
        || stuck.0.lock().checksum_reads != fw::POLL_COUNT - 1
    {
        return TestResult::Fail("rtl8723_fw_free_to_go checksum poll");
    }
    let dead = fw_fake(true, false, false, true);
    if narf_scheduler::block_on(fw::download(&dead, &payload)) != Err(FwError::Start)
        || dead.0.lock().wintini_reads != fw::POLL_COUNT + 1
    {
        return TestResult::Fail("rtl8723_fw_free_to_go WINTINI poll");
    }
    if narf_scheduler::block_on(fw::download(&stuck, &[])) != Err(FwError::Image)
        || narf_scheduler::block_on(fw::download(&stuck, &vec![0; fw::MAX_PAYLOAD + 1]))
            != Err(FwError::Image)
    {
        return TestResult::Fail("empty / oversized payload downloaded");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_firmware_paged_download
);

/// `_rtl8712e_init_mac` after the enable flow: `PCIE_CTRL+2[4]`, `0x369[7]`
/// and the ePHY MDIO round with word-width writes; 100 failed rounds fail.
fn smoke_rtl8723ae_init_mac_post_flow_ephy() -> TestResult {
    let io = fw_fake(true, true, false, true);
    if narf_scheduler::block_on(power::post_flow(&io)).is_err() {
        return TestResult::Fail("post_flow failed with ePHY readback");
    }
    {
        let g = io.0.lock();
        let words: Vec<(u16, u32)> = g
            .writes
            .iter()
            .filter(|w| w.2 == 2)
            .map(|w| (w.0, w.1))
            .collect();
        if words
            != [
                (0x358, 0x5e),
                (0x356, 0xc280),
                (0x354, 0xc290),
                (0x358, 0x3e),
                (0x358, 0x5e),
            ]
            || g.regs[0x302] & 0x10 == 0
            || g.regs[0x369] & 0x80 == 0
        {
            return TestResult::Fail("ePHY round / PCIe and eMAC bits");
        }
    }
    // An ePHY whose readback never matches: 100 rounds, then failure.
    let bad = fw_fake(true, true, false, true);
    struct Stale(FwFake);
    #[async_trait::async_trait]
    impl Io for Stale {
        fn read8(&self, reg: u16) -> Result<u8, FwError> {
            if reg == 0x356 || reg == 0x357 {
                return Ok(0);
            }
            self.0.read8(reg)
        }
        fn read32(&self, reg: u16) -> Result<u32, FwError> {
            self.0.read32(reg)
        }
        fn write8(&self, reg: u16, value: u8) -> Result<(), FwError> {
            self.0.write8(reg, value)
        }
        fn write16(&self, reg: u16, value: u16) -> Result<(), FwError> {
            self.0.write16(reg, value)
        }
        fn write32(&self, reg: u16, value: u32) -> Result<(), FwError> {
            self.0.write32(reg, value)
        }
        fn write_bytes(&self, reg: u16, bytes: &[u8]) -> Result<(), FwError> {
            self.0.write_bytes(reg, bytes)
        }
        async fn delay_us(&self, _micros: u64) {}
    }
    let stale = Stale(bad.clone());
    if narf_scheduler::block_on(power::post_flow(&stale)) != Err(FwError::Gate)
        || bad
            .0
            .lock()
            .writes
            .iter()
            .filter(|w| *w == &(0x354, 0xc290, 2))
            .count()
            != 100
    {
        return TestResult::Fail("ePHY failure after 100 rounds");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_init_mac_post_flow_ephy
);
