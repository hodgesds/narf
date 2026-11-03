// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192EE retained-runtime foundation tests (software models only; no
//! device, firmware execution or RF acceptance is implied).

use super::*;
use crate::rtlwifi::firmware_transport::{Error as FwError, Io};
use crate::rtlwifi::power::*;
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

// ── pwrseq ────────────────────────────────────────────────────────────────

/// (registers, ordered writes)
type PwrState = (Vec<u8>, Vec<(u16, u8)>);
struct PwrModel(IrqSafeSpinLock<PwrState>);
impl crate::rtlwifi::power::Io for PwrModel {
    fn read8(&self, offset: u16) -> Result<u8, PwrSeqError> {
        Ok(self.0.lock().0[usize::from(offset)])
    }
    fn write8(&self, offset: u16, value: u8) -> Result<(), PwrSeqError> {
        let mut g = self.0.lock();
        // The modelled power FSM completes 0x04[0] requests immediately.
        g.0[usize::from(offset)] = if offset == 5 { value & !1 } else { value };
        g.1.push((offset, value));
        Ok(())
    }
    fn delay_us(&self, _micros: u64) {}
}

fn pwr_model(sys_cfg1_byte3: u8) -> PwrModel {
    let mut regs = vec![0u8; 0x100];
    regs[6] = 0x02; // power ready
    regs[0x1c] = 0xff;
    regs[0x28] = 0xff;
    regs[0x78] = 0xff;
    regs[0x79] = 0xff;
    regs[0x7a] = 0xff;
    regs[0xf3] = sys_cfg1_byte3;
    PwrModel(IrqSafeSpinLock::new((regs, Vec::new())))
}

/// `_rtl92ee_init_mac` prefix (RSV_CTRL, SYS_CFG1[24] crystal selection, AFE
/// bits) precedes the exact `RTL8192E_NIC_ENABLE_FLOW`.
fn smoke_rtl8192ee_init_mac_prefix_and_enable_flow() -> TestResult {
    let did = crate::rtlwifi::regs::RTL_DEV_8192EE;
    let model = pwr_model(0);
    if power_on_with(&model, did).is_err() {
        return TestResult::Fail("8192EE enable flow failed on a ready model");
    }
    let g = model.0.lock();
    let prefix: Vec<(u16, u8)> = g.1.iter().copied().take(8).collect();
    let want = [
        (0x1c, 0x00),
        (0x16, 0x50),
        (0x7c, 0x83),
        (0x28, 0xfb),
        (0x78, 0x7f),
        (0x79, 0xfc),
        (0x28, 0xbb),
        (0x7a, 0xdf),
    ];
    if prefix[..] != want[..] {
        return TestResult::Fail("8192EE init_mac prefix order / masks");
    }
    // CardDis->CardEmu then CardEmu->Act: 0x05 writes, 0x06[0] WLON release.
    if g.1[8] != (0x05, 0x00) || g.0[6] & 1 == 0 || !g.1.contains(&(0x05, 0x01)) {
        return TestResult::Fail("8192EE NIC enable flow rows");
    }
    drop(g);
    let model = pwr_model(1);
    if power_on_with(&model, did).is_err() {
        return TestResult::Fail("8192EE enable flow with SYS_CFG1[24]");
    }
    let g = model.0.lock();
    if g.1[1] != (0x7c, 0xc3) || g.1.iter().any(|w| w.0 == 0x16) {
        return TestResult::Fail("SYS_CFG1[24] must select 0x7c=0xc3 without 0x16");
    }
    if RTL8192EE_PWR_ON.as_ptr() != pwrseq::RTL8192E_CARD_ENABLE_FLOW.as_ptr() {
        return TestResult::Fail("8192EE power table is not the generated enable flow");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ee",
    smoke_rtl8192ee_init_mac_prefix_and_enable_flow
);

fn smoke_rtl8192ee_all_flows_pci_mac_and_terminated() -> TestResult {
    let flows: [&[WlanPwrCfg]; 7] = [
        pwrseq::RTL8192E_CARD_ENABLE_FLOW,
        pwrseq::RTL8192E_CARD_DISABLE_FLOW,
        pwrseq::RTL8192E_SUSPEND_FLOW,
        pwrseq::RTL8192E_RESUME_FLOW,
        pwrseq::RTL8192E_RADIO_OFF_FLOW,
        pwrseq::RTL8192E_ENTER_LPS_FLOW,
        pwrseq::RTL8192E_LEAVE_LPS_FLOW,
    ];
    for flow in flows {
        let (last, rows) = match flow.split_last() {
            Some(v) => v,
            None => return TestResult::Fail("empty 8192E flow"),
        };
        if last.cmd() != PWR_CMD_END
            || rows.iter().any(|r| {
                r.cmd() == PWR_CMD_END
                    || r.intf() & PWR_INTF_PCI_MSK == 0
                    || r.base() != PWR_BASEADDR_MAC
            })
        {
            return TestResult::Fail("8192E flow row not PCI/MAC or END misplaced");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ee",
    smoke_rtl8192ee_all_flows_pci_mac_and_terminated
);

// ── firmware ──────────────────────────────────────────────────────────────

/// First 32 bytes of linux-firmware `rtlwifi/rtl8192eefw.bin` (a link to
/// `rtl8192eu_nic.bin`, sha256
/// b15bc955fba2fc3abc093affe62c9f7284a0b84d4f13f8ce55366488dc9aad8b, 32286
/// bytes). Bodies are zero-filled: parser geometry only.
const HDR: [u8; 32] = [
    0xe1, 0x92, 0x10, 0x00, 0x23, 0x00, 0x07, 0x00, 0x11, 0x10, 0x10, 0x46, 0xfe, 0x7d, 0x00, 0x00,
    0x0c, 0x5a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const TOTAL: usize = 32286;

fn image(total: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; total];
    bytes[..32].copy_from_slice(&HDR);
    bytes
}

fn smoke_rtl8192ee_firmware_header_geometry() -> TestResult {
    let normal = image(TOTAL);
    match fw::parse(&normal) {
        Ok((n, p)) if n.version == 0x23 && n.subversion == 7 && p.len() == TOTAL - 32 => {}
        _ => return TestResult::Fail("real 8192EE header rejected"),
    }
    let mut bad = normal.clone();
    bad[12] ^= 1;
    let mut e1 = normal.clone();
    e1[0] = 0xe1;
    e1[1] = 0x88;
    let mut ae = normal.clone();
    ae[0] = 0x01;
    ae[1] = 0x21;
    if fw::parse(&bad).is_ok()
        || fw::parse(&e1).is_ok()
        || fw::parse(&ae).is_ok()
        || fw::parse(&normal[..32]).is_ok()
    {
        return TestResult::Fail("bad extent / 88E / 8821 signature / header-only admitted");
    }
    let mut big = image(32 + fw::MAX_PAYLOAD + 4);
    let len = (fw::MAX_PAYLOAD + 4) as u16;
    big[12..14].copy_from_slice(&len.to_le_bytes());
    if fw::parse(&big).is_ok() || fw::FW_NORMAL != "rtlwifi/rtl8192eefw.bin" {
        return TestResult::Fail("oversize image / filename");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ee",
    smoke_rtl8192ee_firmware_header_geometry
);

struct FwModel {
    regs: Vec<u8>,
    pages: Vec<Vec<u8>>,
    resets: u32,
    checksum: bool,
    checksum_reads: u32,
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
            }
            if g.checksum && v & u32::from(fw::MCUFWDL_EN) == 0 && !g.pages.is_empty() {
                v |= fw::FWDL_CHKSUM_RPT;
            }
            if v & fw::MCUFWDL_RDY != 0 && g.resets > 0 {
                v |= fw::WINTINI_RDY;
            }
        }
        Ok(v)
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), FwError> {
        let mut g = self.0.lock();
        if reg == fw::REG_RSV_CTRL + 1 && value & 1 != 0 && g.regs[usize::from(reg)] & 1 == 0 {
            g.resets += 1;
        }
        g.regs[usize::from(reg)] = value;
        Ok(())
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), FwError> {
        let mut g = self.0.lock();
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

fn fw_fake(checksum: bool) -> FwFake {
    let mut regs = vec![0u8; 0x2000];
    regs[usize::from(fw::REG_RSV_CTRL) + 1] = 1;
    regs[usize::from(fw::REG_MCUFWDL)] = fw::RAM_DL_SEL;
    FwFake(Arc::new(IrqSafeSpinLock::new(FwModel {
        regs,
        pages: Vec::new(),
        resets: 0,
        checksum,
        checksum_reads: 0,
    })))
}

fn smoke_rtl8192ee_firmware_paged_download_and_selfreset() -> TestResult {
    let payload: Vec<u8> = (0..(2 * fw::PAGE + 5)).map(|i| i as u8).collect();
    let io = fw_fake(true);
    if narf_scheduler::block_on(fw::download(&io, &payload, true)).is_err() {
        return TestResult::Fail("8192EE model download failed");
    }
    let g = io.0.lock();
    if g.pages.len() != 3
        || g.pages[0][..] != payload[..fw::PAGE]
        || g.pages[1][..] != payload[fw::PAGE..2 * fw::PAGE]
        || g.pages[2][..5] != payload[2 * fw::PAGE..]
        || g.pages[2][5..] != [0, 0, 0]
    {
        return TestResult::Fail("page contents / rtl_fill_dummy pad");
    }
    // One reset to stop the running RAM image, one in fw_free_to_go.
    if g.resets != 2 || g.regs[usize::from(fw::REG_MCUFWDL)] & fw::MCUFWDL_EN != 0 {
        return TestResult::Fail("8051 self-reset count / download gate left open");
    }
    drop(g);
    let stuck = fw_fake(false);
    if narf_scheduler::block_on(fw::download(&stuck, &payload, false)) != Err(FwError::Checksum) {
        return TestResult::Fail("missing checksum report accepted");
    }
    // _rtl92ee_fw_free_to_go succeeds only within FW_8192C_POLLING_TIMEOUT_COUNT - 1 reads.
    if stuck.0.lock().checksum_reads != 2999 || stuck.0.lock().resets != 0 {
        return TestResult::Fail("checksum poll count / reset after failed checksum");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ee",
    smoke_rtl8192ee_firmware_paged_download_and_selfreset
);

/// The retained one-shot firmware owner admits the 8192EE profile with its
/// own header rule, clears CR packet gates, applies the `rtl92ee_hw_init`
/// `0x577` / crystal AFE writes before `rtl92ee_download_fw`, never releases
/// the PCIe DMA queue stops, and refuses another family's image.
fn smoke_rtl8192ee_retained_firmware_owner_profile() -> TestResult {
    use crate::rtlwifi::firmware_transport::{parse, Owner, Stage};
    let did = crate::rtlwifi::regs::RTL_DEV_8192EE;
    let normal = image(TOTAL);
    let mut ee = normal.clone();
    ee[..2].copy_from_slice(&[0xe1, 0x88]);
    if parse(did, &normal).is_err()
        || parse(did, &ee).is_ok()
        || parse(crate::rtlwifi::regs::RTL_DEV_8188EE, &normal).is_ok()
        || parse(crate::rtlwifi::regs::RTL_DEV_8821AE, &normal).is_ok()
    {
        return TestResult::Fail("per-profile header dispatch");
    }
    let io = fw_fake(true);
    {
        let mut g = io.0.lock();
        g.regs[0x100] = 0xff;
        g.regs[0x300] = 0xff;
        g.regs[0x301] = 0xff;
    }
    let owner = Owner::new(io.clone(), did);
    let info = match narf_scheduler::block_on(owner.initialize(&normal)) {
        Ok(info) => info,
        Err(_) => return TestResult::Fail("8192EE owner download failed"),
    };
    let g = io.0.lock();
    if info.version != 0x23
        || info.payload != TOTAL - 32
        || owner.status().stage != Stage::Ready
        || owner.identity().is_none()
        || g.regs[0x100] & 0xcf != 0
        || g.regs[0x100] & 0x30 != 0x30
        || g.regs[0x577] != 0x03
        || g.regs[0x78] != 0x2a
        || g.regs[0x79] != 0x00
        || g.regs[0x28] != 0x83
        || g.regs[0x300] != 0xff
        || g.regs[0x301] != 0xff
        || g.resets != 2
        || g.pages.len() != 8
    {
        return TestResult::Fail("8192EE owner gates / AFE / download / DMA stops");
    }
    drop(g);
    if narf_scheduler::block_on(owner.initialize(&normal))
        != Err(crate::rtlwifi::firmware_transport::Error::AlreadyStarted)
    {
        return TestResult::Fail("8192EE owner is not one-shot");
    }
    let rejected = Owner::new(fw_fake(true), did);
    if narf_scheduler::block_on(rejected.initialize(&ee))
        != Err(crate::rtlwifi::firmware_transport::Error::Image)
        || rejected.status().stage != Stage::Failed
    {
        return TestResult::Fail("8188EE image accepted by 8192EE owner");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ee",
    smoke_rtl8192ee_retained_firmware_owner_profile
);

// ── adapter info ──────────────────────────────────────────────────────────

fn provisioned_map() -> Vec<u8> {
    let mut map = vec![0xffu8; 512];
    map[0] = 0x29;
    map[1] = 0x81;
    map[0xd0..0xd6].copy_from_slice(&[0x00, 0xe0, 0x4c, 0x81, 0x92, 0x01]);
    map[0xd8..0xda].copy_from_slice(&0x818bu16.to_le_bytes());
    map[0xda..0xdc].copy_from_slice(&0x10ecu16.to_le_bytes());
    map[0xdc..0xde].copy_from_slice(&0x001bu16.to_le_bytes());
    map
}

fn smoke_rtl8192ee_adapter_info_factory_rules() -> TestResult {
    use adapter::{Adapter, Error, Oem};
    let ok = adapter::CR9346_AUTOLOAD_OK;
    let map = provisioned_map();
    if Adapter::from_hardware(adapter::TRP_VAUX_EN, ok, &map) != Err(Error::TestChip) {
        return TestResult::Fail("test chip admitted");
    }
    if Adapter::from_hardware(0, 0, &map) != Err(Error::Unprovisioned)
        || Adapter::from_hardware(0, ok | adapter::CR9346_EEPROM, &map) != Err(Error::Unprovisioned)
        || Adapter::from_hardware(0, ok, &[0xff; 512]) != Err(Error::Unprovisioned)
        || Adapter::from_hardware(0, ok, &map[..256]) != Err(Error::Unprovisioned)
    {
        return TestResult::Fail("autoload failure / EEPROM boot / missing ID admitted");
    }
    // All-0xff option, crystal and customer id: Linux defaults.
    let a = match Adapter::from_hardware(0, ok, &map) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("provisioned map rejected"),
    };
    if a.mac != [0x00, 0xe0, 0x4c, 0x81, 0x92, 0x01]
        || a.version != adapter::VERSION_NORMAL_CHIP_2T2R
        || a.board_type != 0
        || a.bt_coexist
        || a.crystal_cap != 0x20
        || a.customer_id != 0
        || a.oem != Oem::Lenovo
    {
        return TestResult::Fail("default rules / Lenovo OEM");
    }
    // Board option [7:5] == 1 is the BT-coexist board.
    let mut bt = provisioned_map();
    bt[adapter::EEPROM_RF_BOARD_OPTION] = 0x20;
    bt[adapter::EEPROM_XTAL] = 0x1c;
    bt[0xc5] = 0x04;
    let b = match Adapter::from_hardware(0, ok, &bt) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("BT map rejected at decode"),
    };
    if !b.bt_coexist
        || b.board_type != (1 | adapter::ODM_BOARD_BT)
        || b.crystal_cap != 0x1c
        || b.customer_id != 4
        || b.oem != Oem::Default
    {
        return TestResult::Fail("BT board type / crystal / customer id");
    }
    let mut ext = provisioned_map();
    ext[adapter::EEPROM_RF_BOARD_OPTION] = 0x40;
    match Adapter::from_hardware(0, ok, &ext) {
        Ok(e) if e.board_type == 2 && !e.bt_coexist => {}
        _ => return TestResult::Fail("non-BT board option"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ee",
    smoke_rtl8192ee_adapter_info_factory_rules
);
