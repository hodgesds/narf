// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723BE retained-runtime foundation tests (software models only; no
//! device, firmware execution, BT coexistence or RF acceptance is implied).

use super::*;
use crate::rtlwifi::firmware_transport::{Error as FwError, Io};
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
use version::Version;

// ── chip version ──────────────────────────────────────────────────────────

/// `_rtl8723be_read_chip_version`: `CHIP_8723B | NORMAL_CHIP | cut`, SMIC
/// from `EXT_VENDOR_ID == 1`; a part without `CHIP_8723B` is refused.
fn smoke_rtl8723be_chip_version_and_firmware_names() -> TestResult {
    use version::*;
    // (sys_cfg1, sys_cfg, raw, cut, smic)
    let ok: [(u32, u32, u16, u8, bool); 4] = [
        (CHIP_8723B, 0, 0x000e, 0, false),
        (CHIP_8723B | 0x01, 1 << 12, 0x100e, 1, false),
        (CHIP_8723B, (1 << 18) | (2 << 12), 0x210e, 2, true),
        (CHIP_8723B, 2 << 18, 0x000e, 0, false),
    ];
    for (sys_cfg1, sys_cfg, raw, cut, smic) in ok {
        match Version::from_registers(sys_cfg1, sys_cfg) {
            Ok(v) if v.raw() == raw && v.cut() == cut && v.is_smic() == smic => {}
            _ => return TestResult::Fail("8723BE version derivation"),
        }
    }
    for sys_cfg1 in [0, 1 << 1, 1 << 2] {
        if Version::from_registers(sys_cfg1, 0) != Err(Error::Unknown) {
            return TestResult::Fail("non-8723B SYS_CFG1 admitted");
        }
    }
    if Version::firmware_names() != [FW_NORMAL, FW_NORMAL_ALT]
        || FW_NORMAL != "rtlwifi/rtl8723befw_36.bin"
        || FW_NORMAL_ALT != "rtlwifi/rtl8723befw.bin"
    {
        return TestResult::Fail("rtl8723be fw_name / alt_fw_name");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_chip_version_and_firmware_names
);

// ── adapter facts ─────────────────────────────────────────────────────────

fn provisioned() -> Vec<u8> {
    let mut map = vec![0xffu8; adapter::HWSET_MAX_SIZE];
    map[0..2].copy_from_slice(&0x8129u16.to_le_bytes());
    map[0xd0..0xd6].copy_from_slice(&[0x00, 0xe0, 0x4c, 0x87, 0x23, 0xbe]);
    map[0xd6..0xd8].copy_from_slice(&0x10ecu16.to_le_bytes());
    map[0xd8..0xda].copy_from_slice(&0xb723u16.to_le_bytes());
    map[0xda..0xdc].copy_from_slice(&0x103cu16.to_le_bytes());
    map[0xdc..0xde].copy_from_slice(&0x1629u16.to_le_bytes());
    map[0xb8] = 0x20;
    map[0xb9] = 0x22;
    map[0xba] = 0x1a;
    map[0xc1] = 0xf9;
    map[0xc3] = 0x41;
    map[0xc5] = 0x00;
    map
}

/// `_rtl8723be_read_adapter_info` with the BT/antenna facts of
/// `rtl8723be_read_bt_coexist_info_from_hwpg`, the thermal/regulatory/
/// crystal default rules, package type and the unprovisioned refusals.
fn smoke_rtl8723be_adapter_facts_bt_antenna_and_defaults() -> TestResult {
    use adapter::*;
    let v = match Version::from_registers(version::CHIP_8723B, 0) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("version"),
    };
    let map = provisioned();
    let ok = CR9346_AUTOLOAD_OK;
    let a = match Adapter::from_hardware(v, ok, MULTI_BT_FUNC_EN, &map, 0x06) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("provisioned map refused"),
    };
    if a.mac != [0x00, 0xe0, 0x4c, 0x87, 0x23, 0xbe]
        || a.did != 0xb723
        || a.crystal_cap != 0x22
        || a.thermal_meter != 0x1a
        || a.thermal_ignore
        || a.regulatory != 1
        || !a.bt_coexist
        || a.ant_num != AntNum::X1
        || a.single_ant_path != AntPath::Aux
        || a.board_type != ODM_BOARD_BT
        || a.package_type != 1
        // The 0x8176/0x8178 OEM branches never match an 0xb723 map.
        || a.oem != Oem::Default
    {
        return TestResult::Fail("8723BE adapter facts");
    }
    let mut two = map.clone();
    two[0xc3] = 0x00;
    two[0xb9] = 0xff;
    two[0xba] = 0xff;
    two[0xc1] = 0xff;
    two[0xc5] = 0x04;
    match Adapter::from_hardware(v, ok, 0, &two, 0) {
        Ok(a)
            if !a.bt_coexist
                && a.board_type == 0
                && a.ant_num == AntNum::X2
                && a.single_ant_path == AntPath::Main
                && a.crystal_cap == 0x20
                && a.thermal_meter == DEFAULT_THERMAL_METER
                && a.thermal_ignore
                && a.regulatory == 0
                && a.package_type == 0
                && a.oem == Oem::Toshiba => {}
        _ => return TestResult::Fail("ANT_X2 / 0xff defaults / Toshiba CID"),
    }
    if [(4, 4), (5, 2), (7, 3), (0xfc, 4), (3, 0)]
        .iter()
        .any(|&(b, t)| package_type(b) != t)
    {
        return TestResult::Fail("_rtl8723be_read_package_type mapping");
    }
    let mut no_id = map.clone();
    no_id[0] = 0;
    if Adapter::from_hardware(v, ok | CR9346_EEPROM, 0, &map, 0) != Err(Error::Unprovisioned)
        || Adapter::from_hardware(v, 0, 0, &map, 0) != Err(Error::Unprovisioned)
        || Adapter::from_hardware(v, ok, 0, &no_id, 0) != Err(Error::Unprovisioned)
        || Adapter::from_hardware(v, ok, 0, &map[..256], 0) != Err(Error::Unprovisioned)
    {
        return TestResult::Fail("EEPROM boot / autoload fail / no ID / short map admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_adapter_facts_bt_antenna_and_defaults
);

// ── firmware header ───────────────────────────────────────────────────────

/// First 16 header bytes of the linux-firmware `rtl8723befw_36.bin`.
const HDR: [u8; 16] = [
    0x01, 0x53, 0x10, 0x00, 0x24, 0x00, 0x00, 0x00, 0x06, 0x24, 0x16, 0x28, 0xf2, 0x7b, 0x00, 0x00,
];
const TOTAL: usize = 31762;

fn image(total: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; total];
    bytes[..16].copy_from_slice(&HDR);
    bytes
}

fn smoke_rtl8723be_firmware_header_geometry() -> TestResult {
    let normal = image(TOTAL);
    match fw::parse(&normal) {
        Ok((n, p)) if n.version == 0x24 && n.subversion == 0 && p.len() == TOTAL - 32 => {}
        _ => return TestResult::Fail("real rtl8723befw_36.bin header rejected"),
    }
    // rtl8723befw.bin: version 0x0f, subversion 0x11, RAM code 0x77fa.
    let mut alt = image(30746);
    alt[4] = 0x0f;
    alt[6] = 0x11;
    alt[12..14].copy_from_slice(&0x77fau16.to_le_bytes());
    match fw::parse(&alt) {
        Ok((n, _)) if n.version == 0x0f && n.subversion == 0x11 => {}
        _ => return TestResult::Fail("real rtl8723befw.bin header rejected"),
    }
    let mut bad = normal.clone();
    bad[12] ^= 1;
    let mut e1 = normal.clone();
    e1[..2].copy_from_slice(&[0xe1, 0x88]);
    let mut ae = normal.clone();
    ae[..2].copy_from_slice(&[0x01, 0x23]);
    if fw::parse(&bad).is_ok()
        || fw::parse(&e1).is_ok()
        || fw::parse(&ae).is_ok()
        || fw::parse(&normal[..32]).is_ok()
    {
        return TestResult::Fail("bad extent / 88E / 8723A signature / header-only admitted");
    }
    let mut big = image(fw::MAX_FILE + 4);
    big[12..14].copy_from_slice(&((fw::MAX_FILE + 4 - 32) as u16).to_le_bytes());
    if fw::parse(&big).is_ok() {
        return TestResult::Fail("image above max_fw_size admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_firmware_header_geometry
);

// ── firmware download model ───────────────────────────────────────────────

struct FwModel {
    regs: Vec<u8>,
    pages: Vec<Vec<u8>>,
    writes: Vec<(u16, u32, u8)>,
    /// 8051 resets observed (`SYS_FUNC_EN+1` BIT2 falling edges).
    resets: u32,
    checksum: bool,
    start: bool,
    checksum_reads: u32,
    wintini_reads: u32,
}
#[derive(Clone)]
struct FwFake(Arc<IrqSafeSpinLock<FwModel>>);
#[async_trait::async_trait]
impl Io for FwFake {
    fn read8(&self, reg: u16) -> Result<u8, FwError> {
        Ok(self.0.lock().regs[usize::from(reg)])
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
            if g.checksum && v & u32::from(fw::MCUFWDL_EN) == 0 && !g.pages.is_empty() {
                v |= fw::FWDL_CHKSUM_RPT;
            }
            // The modelled 8051 boots only after the post-handshake reset.
            if v & fw::MCUFWDL_RDY != 0 && g.start && g.resets >= 1 {
                v |= fw::WINTINI_RDY;
            }
        }
        Ok(v)
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), FwError> {
        let mut g = self.0.lock();
        g.writes.push((reg, u32::from(value), 1));
        let r = usize::from(reg);
        if reg == fw::REG_SYS_FUNC_EN + 1 && g.regs[r] & 4 != 0 && value & 4 == 0 {
            g.resets += 1;
        }
        g.regs[r] = value;
        Ok(())
    }
    fn write16(&self, reg: u16, value: u16) -> Result<(), FwError> {
        let mut g = self.0.lock();
        g.writes.push((reg, u32::from(value), 2));
        let r = usize::from(reg);
        g.regs[r..r + 2].copy_from_slice(&value.to_le_bytes());
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

fn fw_fake(checksum: bool, start: bool, running: bool) -> FwFake {
    let mut regs = vec![0u8; 0x2000];
    if running {
        regs[usize::from(fw::REG_MCUFWDL)] = fw::RAM_DL_SEL;
    }
    regs[usize::from(fw::REG_SYS_FUNC_EN) + 1] = 0x04;
    regs[usize::from(fw::REG_RSV_CTRL) + 1] = 0x01;
    regs[0xfc..0x100].copy_from_slice(&version::CHIP_8723B.to_le_bytes());
    regs[0xf0] = 0x80;
    FwFake(Arc::new(IrqSafeSpinLock::new(FwModel {
        regs,
        pages: Vec::new(),
        writes: Vec::new(),
        resets: 0,
        checksum,
        start,
        checksum_reads: 0,
        wintini_reads: 0,
    })))
}

/// `rtl8723_download_fw(hw, true, 6000)`: running-image self-reset and
/// `MCUFWDL = 0`, 8051 enable + download gate, eight-page bound,
/// `rtl_fill_dummy`, close, 5999 undelayed checksum reads, `MCUFWDL_RDY`,
/// the 8723BE 8051 reset, then `WINTINI_RDY` over 6001 reads.
fn smoke_rtl8723be_firmware_paged_download() -> TestResult {
    let payload: Vec<u8> = (0..(7 * fw::PAGE + 5)).map(|i| i as u8).collect();
    let io = fw_fake(true, true, true);
    if narf_scheduler::block_on(fw::download(&io, &payload)).is_err() {
        return TestResult::Fail("8723BE model download failed");
    }
    let g = io.0.lock();
    if g.pages.len() != 8
        || g.pages[0][..] != payload[..fw::PAGE]
        || g.pages[6][..] != payload[6 * fw::PAGE..7 * fw::PAGE]
        || g.pages[7][..5] != payload[7 * fw::PAGE..]
        || g.pages[7][5..] != [0, 0, 0]
    {
        return TestResult::Fail("page contents / rtl_fill_dummy pad");
    }
    // Running image: reset + MCUFWDL = 0 before the gate opens; the second
    // reset follows the MCUFWDL_RDY handshake.
    let mcu_zero = g.writes.iter().position(|w| *w == (fw::REG_MCUFWDL, 0, 1));
    let rdy = g
        .writes
        .iter()
        .position(|w| w.0 == fw::REG_MCUFWDL && w.2 == 4 && w.1 & fw::MCUFWDL_RDY != 0);
    let rsv_low: Vec<usize> = g
        .writes
        .iter()
        .enumerate()
        .filter(|(_, w)| w.0 == fw::REG_RSV_CTRL + 1 && w.1 & 1 == 0)
        .map(|(i, _)| i)
        .collect();
    match (mcu_zero, rdy, rsv_low.as_slice()) {
        (Some(z), Some(r), [a, b]) if *a < z && r < *b => {}
        _ => return TestResult::Fail("self-reset placement (running image / post-handshake)"),
    }
    if g.resets != 2
        || g.regs[usize::from(fw::REG_SYS_FUNC_EN) + 1] & 4 == 0
        || g.regs[usize::from(fw::REG_RSV_CTRL) + 1] & 1 == 0
        || g.regs[usize::from(fw::REG_MCUFWDL)] & fw::MCUFWDL_EN != 0
        || !g.writes.contains(&(fw::REG_MCUFWDL + 1, 0, 1))
    {
        return TestResult::Fail("8051 reset / CPU enable / download gate close");
    }
    drop(g);
    let stuck = fw_fake(false, true, false);
    if narf_scheduler::block_on(fw::download(&stuck, &payload)) != Err(FwError::Checksum)
        || stuck.0.lock().checksum_reads != fw::POLL_COUNT - 1
    {
        return TestResult::Fail("rtl8723_fw_free_to_go checksum poll");
    }
    let dead = fw_fake(true, false, false);
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
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_firmware_paged_download
);

/// The retained firmware owner admits RTL8723BE with its own header rule,
/// identifies the chip, closes the CR packet gates, clears
/// `REG_SYS_CFG[7]` and downloads; a part without `CHIP_8723B` is refused
/// before any write.
fn smoke_rtl8723be_retained_firmware_owner_profile() -> TestResult {
    use crate::rtlwifi::firmware_transport::{parse, Owner, Stage};
    use crate::rtlwifi::regs::{RTL_DEV_8188EE, RTL_DEV_8192EE, RTL_DEV_8723AE, RTL_DEV_8723BE};
    let normal = image(TOTAL);
    if parse(RTL_DEV_8723BE, &normal).is_err()
        || parse(RTL_DEV_8723AE, &normal).is_ok()
        || parse(RTL_DEV_8188EE, &normal).is_ok()
        || parse(RTL_DEV_8192EE, &normal).is_ok()
    {
        return TestResult::Fail("per-profile header dispatch");
    }
    let io = fw_fake(true, true, false);
    io.0.lock().regs[0x100] = 0xff;
    let owner = Owner::new(io.clone(), RTL_DEV_8723BE);
    let info = match narf_scheduler::block_on(owner.initialize(&normal)) {
        Ok(info) => info,
        Err(_) => return TestResult::Fail("8723BE owner download failed"),
    };
    let g = io.0.lock();
    let prefix: Vec<(u16, u32, u8)> = g.writes.iter().copied().take(2).collect();
    if prefix[..] != [(0x100, 0x30, 1), (0xf0, 0x00, 1)] {
        return TestResult::Fail("CR gates / SYS_CFG[7] order");
    }
    if info.payload != TOTAL - 32
        || owner.status().stage != Stage::Ready
        || owner.identity().is_none()
        || g.pages.len() != 8
    {
        return TestResult::Fail("8723BE owner gates / download");
    }
    drop(g);
    let foreign = fw_fake(true, true, false);
    foreign.0.lock().regs[0xfc..0x100].copy_from_slice(&[0; 4]);
    let rejected = Owner::new(foreign.clone(), RTL_DEV_8723BE);
    if narf_scheduler::block_on(rejected.initialize(&normal)) != Err(FwError::Unsupported)
        || rejected.status().stage != Stage::Failed
        || !foreign.0.lock().writes.is_empty()
    {
        return TestResult::Fail("non-8723B part admitted or written");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_retained_firmware_owner_profile
);
