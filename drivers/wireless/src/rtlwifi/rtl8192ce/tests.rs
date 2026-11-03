// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192CE-family retained-runtime foundation tests (software models only;
//! no device, firmware execution or RF acceptance is implied).

use super::*;
use crate::rtlwifi::firmware_transport::{Error as FwError, Io};
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
use version::Version;

// ── chip version / RF type ────────────────────────────────────────────────

/// `_rtl92ce_read_chip_version` over SYS_CFG / HPON_FSM, the version
/// predicates and `rtl92c_init_sw_vars` firmware selection.
fn smoke_rtl8192ce_chip_version_rf_type_and_firmware_name() -> TestResult {
    use version::*;
    let bond_1t2r = CHIP_BONDING_92C_1T2R << 22;
    // (sys_cfg, hpon, version, rf, firmware)
    let ok: [(u32, u32, u8, RfType, &str); 6] = [
        (0, 0, 0x10, RfType::T1R1, FW_NORMAL),
        (TYPE_ID, 0, 0x11, RfType::T2R2, FW_NORMAL),
        (VENDOR_ID, 0, 0x30, RfType::T1R1, FW_UMC_A),
        (VENDOR_ID | TYPE_ID, 0, 0x31, RfType::T2R2, FW_NORMAL),
        (1 << 12, 0, 0x70, RfType::T1R1, FW_UMC_B),
        (TYPE_ID | (1 << 12), 0, 0x71, RfType::T2R2, FW_UMC_B),
    ];
    for (sys_cfg, hpon, raw, rf, name) in ok {
        match Version::from_registers(sys_cfg, || hpon) {
            Ok(v) if v.raw() == raw && v.rf_type() == rf && v.firmware() == name => {}
            _ => return TestResult::Fail("qualified 8192CE/8188CE version derivation"),
        }
    }
    // HPON_FSM is consulted only for 92C-serial parts.
    let mut read = false;
    if Version::from_registers(0, || {
        read = true;
        bond_1t2r
    })
    .is_err()
        || read
    {
        return TestResult::Fail("HPON_FSM read for an 88C part");
    }
    let refused: [(u32, u32, Error); 4] = [
        (TRP_VAUX_EN | TYPE_ID, 0, Error::TestChip),
        (TYPE_ID, bond_1t2r, Error::UnqualifiedRfType),
        (VENDOR_ID | TYPE_ID, bond_1t2r, Error::UnqualifiedRfType),
        (2 << 12, 0, Error::UnknownCut),
    ];
    for (sys_cfg, hpon, error) in refused {
        if Version::from_registers(sys_cfg, || hpon) != Err(error) {
            return TestResult::Fail("test chip / 1T2R / unknown cut admitted");
        }
    }
    if RfType::T1R1.paths() != 1 || RfType::T2R2.paths() != 2 {
        return TestResult::Fail("RF path counts");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ce",
    smoke_rtl8192ce_chip_version_rf_type_and_firmware_name
);

// ── firmware header ───────────────────────────────────────────────────────

/// First 16 header bytes of the linux-firmware `rtl8192cfw.bin`.
const HDR: [u8; 16] = [
    0xc1, 0x88, 0x02, 0x05, 0x58, 0x00, 0x02, 0x00, 0x11, 0x23, 0x10, 0x57, 0x20, 0x3f, 0x00, 0x00,
];
const TOTAL: usize = 16192;

fn image(total: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; total];
    bytes[..16].copy_from_slice(&HDR);
    bytes
}

fn smoke_rtl8192ce_firmware_header_geometry() -> TestResult {
    let normal = image(TOTAL);
    match fw::parse(&normal) {
        Ok((n, p)) if n.version == 0x58 && n.subversion == 2 && p.len() == TOTAL - 32 => {}
        _ => return TestResult::Fail("real rtl8192cfw.bin header rejected"),
    }
    // rtl8192cfwU_B.bin: signature 0x88c2, RAM code 0x3fac.
    let mut umc_b = image(16332);
    umc_b[0] = 0xc2;
    umc_b[12..14].copy_from_slice(&0x3facu16.to_le_bytes());
    let mut sig92 = normal.clone();
    sig92[..2].copy_from_slice(&[0xc0, 0x92]);
    if fw::parse(&umc_b).is_err() || fw::parse(&sig92).is_err() {
        return TestResult::Fail("0x88c2 / 0x92c0 signatures rejected");
    }
    let mut bad = normal.clone();
    bad[12] ^= 1;
    let mut e1 = normal.clone();
    e1[0] = 0xe1;
    let mut ee = normal.clone();
    ee[..2].copy_from_slice(&[0xe0, 0x92]);
    if fw::parse(&bad).is_ok()
        || fw::parse(&e1).is_ok()
        || fw::parse(&ee).is_ok()
        || fw::parse(&normal[..32]).is_ok()
    {
        return TestResult::Fail("bad extent / 88E / 92E signature / header-only admitted");
    }
    let mut big = image(fw::MAX_FILE + 4);
    big[12..14].copy_from_slice(&((fw::MAX_FILE + 4 - 32) as u16).to_le_bytes());
    if fw::parse(&big).is_ok() {
        return TestResult::Fail("image above max_fw_size admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ce",
    smoke_rtl8192ce_firmware_header_geometry
);

// ── firmware download model ───────────────────────────────────────────────

struct FwModel {
    regs: Vec<u8>,
    pages: Vec<Vec<u8>>,
    writes: Vec<(u16, u32, u8)>,
    selfresets: u32,
    checksum: bool,
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
            if v & fw::MCUFWDL_RDY != 0 && g.checksum {
                v |= fw::WINTINI_RDY;
            }
        }
        Ok(v)
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), FwError> {
        let mut g = self.0.lock();
        g.writes.push((reg, u32::from(value), 1));
        let mut value = value;
        // The modelled power FSM completes APFM_ONMAC immediately.
        if reg == power::REG_APS_FSMCO + 1 {
            value &= !1;
        }
        // The modelled 8051 honours the self-reset request at once.
        if reg == fw::REG_HMETFR + 3 && value == 0x20 {
            g.selfresets += 1;
            g.regs[usize::from(fw::REG_SYS_FUNC_EN) + 1] &= !4;
        }
        g.regs[usize::from(reg)] = value;
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

fn fw_fake(checksum: bool, sys_cfg: u32) -> FwFake {
    let mut regs = vec![0u8; 0x2000];
    regs[usize::from(fw::REG_MCUFWDL)] = fw::RAM_DL_SEL;
    regs[usize::from(fw::REG_SYS_FUNC_EN) + 1] = 0x04;
    regs[0xf0..0xf4].copy_from_slice(&sys_cfg.to_le_bytes());
    FwFake(Arc::new(IrqSafeSpinLock::new(FwModel {
        regs,
        pages: Vec::new(),
        writes: Vec::new(),
        selfresets: 0,
        checksum,
        checksum_reads: 0,
        wintini_reads: 0,
    })))
}

/// `rtl92c_download_fw` for a normal chip: 8051 enable + download gate,
/// four-page bound, `rtl_fill_dummy`, `MCUFWDL+1 = 0` on close, 99 undelayed
/// checksum reads, `MCUFWDL_RDY` handshake and `WINTINI_RDY`.
fn smoke_rtl8192ce_firmware_paged_download() -> TestResult {
    let payload: Vec<u8> = (0..(3 * fw::PAGE + 5)).map(|i| i as u8).collect();
    let io = fw_fake(true, 0);
    if narf_scheduler::block_on(fw::stop_running(&io)).is_err()
        || narf_scheduler::block_on(fw::download(&io, &payload)).is_err()
    {
        return TestResult::Fail("8192CE model download failed");
    }
    let g = io.0.lock();
    if g.pages.len() != 4
        || g.pages[0][..] != payload[..fw::PAGE]
        || g.pages[2][..] != payload[2 * fw::PAGE..3 * fw::PAGE]
        || g.pages[3][..5] != payload[3 * fw::PAGE..]
        || g.pages[3][5..] != [0, 0, 0]
    {
        return TestResult::Fail("page contents / rtl_fill_dummy pad");
    }
    // A running image is stopped once (selfreset then MCUFWDL = 0) and the
    // download re-enables the 8051 (SYS_FUNC_EN+1 BIT2).
    if g.selfresets != 1
        || g.regs[usize::from(fw::REG_SYS_FUNC_EN) + 1] & 4 == 0
        || g.regs[usize::from(fw::REG_MCUFWDL)] & fw::MCUFWDL_EN != 0
        || !g.writes.contains(&(fw::REG_MCUFWDL + 1, 0, 1))
    {
        return TestResult::Fail("self-reset / CPU enable / download gate close");
    }
    drop(g);
    let stuck = fw_fake(false, 0);
    if narf_scheduler::block_on(fw::download(&stuck, &payload)) != Err(FwError::Checksum) {
        return TestResult::Fail("missing checksum report accepted");
    }
    if stuck.0.lock().checksum_reads != 99 {
        return TestResult::Fail("_rtl92c_fw_free_to_go checksum poll count");
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
    "drivers/wireless/rtlwifi/rtl8192ce",
    smoke_rtl8192ce_firmware_paged_download
);

/// The retained one-shot firmware owner admits the 8192CE family with its own
/// header rule, measures and qualifies the chip version, runs the
/// `_rtl92ce_init_mac` power-on prefix with the exact-width APS_FSMCO word,
/// keeps CR packet gates closed and downloads; a 1T2R bonding is refused
/// before any power write.
fn smoke_rtl8192ce_retained_firmware_owner_profile() -> TestResult {
    use crate::rtlwifi::firmware_transport::{parse, Owner, Stage};
    let did = crate::rtlwifi::regs::RTL_DEV_8192CE;
    let normal = image(TOTAL);
    if parse(did, &normal).is_err()
        || parse(crate::rtlwifi::regs::RTL_DEV_8192CE_ALT, &normal).is_err()
        || parse(crate::rtlwifi::regs::RTL_DEV_8188EE, &normal).is_ok()
        || parse(crate::rtlwifi::regs::RTL_DEV_8192EE, &normal).is_ok()
    {
        return TestResult::Fail("per-profile header dispatch");
    }
    let io = fw_fake(true, version::TYPE_ID);
    io.0.lock().regs[0x100] = 0xff;
    let owner = Owner::new(io.clone(), did);
    let info = match narf_scheduler::block_on(owner.initialize(&normal)) {
        Ok(info) => info,
        Err(_) => return TestResult::Fail("8192CE owner download failed"),
    };
    let g = io.0.lock();
    let prefix: Vec<(u16, u32, u8)> = g.writes.iter().copied().take(7).collect();
    let want = [
        (0x1c, 0x00, 1),
        (0x11, 0x2b, 1),
        (0x24, 0x0f, 1),
        (0x05, 0x01, 1),
        (0x04, 0x1012, 2),
        (0x01, 0x82, 1),
        (0x100, 0x30, 1),
    ];
    if prefix[..] != want[..] {
        return TestResult::Fail("_rtl92ce_init_mac power prefix / CR gates order");
    }
    if info.payload != TOTAL - 32
        || owner.status().stage != Stage::Ready
        || owner.identity().is_none()
        || g.regs[0x100] != 0x30
        || g.pages.len() != 4
    {
        return TestResult::Fail("8192CE owner gates / download");
    }
    drop(g);
    let bonded = fw_fake(true, version::TYPE_ID);
    bonded.0.lock().regs[0xec..0xf0]
        .copy_from_slice(&(version::CHIP_BONDING_92C_1T2R << 22).to_le_bytes());
    let rejected = Owner::new(bonded.clone(), did);
    if narf_scheduler::block_on(rejected.initialize(&normal)) != Err(FwError::Unsupported)
        || rejected.status().stage != Stage::Failed
        || !bonded.0.lock().writes.is_empty()
    {
        return TestResult::Fail("1T2R bonding admitted or powered");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ce",
    smoke_rtl8192ce_retained_firmware_owner_profile
);

// ── adapter info ──────────────────────────────────────────────────────────

fn provisioned_map() -> Vec<u8> {
    let mut map = vec![0xffu8; 128];
    map[0..2].copy_from_slice(&0x8129u16.to_le_bytes());
    map[0x0a..0x0c].copy_from_slice(&0x10ecu16.to_le_bytes());
    map[0x0c..0x0e].copy_from_slice(&0x8176u16.to_le_bytes());
    map[0x0e..0x10].copy_from_slice(&0x103cu16.to_le_bytes());
    map[0x10..0x12].copy_from_slice(&0x1629u16.to_le_bytes());
    map[0x16..0x1c].copy_from_slice(&[0x00, 0xe0, 0x4c, 0x81, 0x76, 0x01]);
    map[0x75] = 0x0a;
    map[0x7e..0x80].copy_from_slice(&[0x03, 0x00]);
    map[0x79] = 0x01; // RF_OPTION1: regulatory 1, no BT
    map[0x7c] = 0x3b; // RF_OPTION4
    map
}

fn smoke_rtl8192ce_adapter_info_factory_rules() -> TestResult {
    use adapter::*;
    let version = match Version::qualify(0x10) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("88C version"),
    };
    let mut map = provisioned_map();
    map[0x7f] = 0x00;
    let a = match Adapter::from_hardware(version, CR9346_AUTOLOAD_OK, &map) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("provisioned 8188CE map refused"),
    };
    let bt = BtInfo {
        coexist: 0,
        kind: 5,
        ant_num: 1,
        ant_isolation: 1,
        radio_shared: 1,
    };
    if a.mac != [0x00, 0xe0, 0x4c, 0x81, 0x76, 0x01]
        || a.vid != 0x10ec
        || a.did != 0x8176
        || a.eeprom_channel_plan != 0x0a
        || a.eeprom_version != 3
        || a.oem != Oem::Hp
        || a.bt_coexistence()
        || a.bt != bt
        || a.hwinfo[..] != map[..]
    {
        return TestResult::Fail("adapter fields / HP OEM rule");
    }
    let mut bt_map = map.clone();
    bt_map[0x79] = 0x21;
    bt_map[0x7f] = 0x04;
    match Adapter::from_hardware(version, CR9346_AUTOLOAD_OK, &bt_map) {
        Ok(a) if a.bt_coexistence() && a.bt.coexist == 1 && a.oem == Oem::Toshiba => {}
        _ => return TestResult::Fail("BT-coexist strap / Toshiba OEM"),
    }
    let mut no_id = map.clone();
    no_id[0] = 0;
    if Adapter::from_hardware(version, CR9346_AUTOLOAD_OK, &no_id) != Err(Error::Unprovisioned)
        || Adapter::from_hardware(version, CR9346_AUTOLOAD_OK | CR9346_EEPROM, &map)
            != Err(Error::Unprovisioned)
        || Adapter::from_hardware(version, 0, &map) != Err(Error::Unprovisioned)
        || Adapter::from_hardware(version, CR9346_AUTOLOAD_OK, &map[..127])
            != Err(Error::Unprovisioned)
    {
        return TestResult::Fail("unprovisioned map admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ce",
    smoke_rtl8192ce_adapter_info_factory_rules
);
