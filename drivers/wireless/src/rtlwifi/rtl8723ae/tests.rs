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

// ── firmware-event mailbox (`rtl8723ae/c2h.rs`) ──────────────────────────

/// Mailbox fake preset: header byte, sequence byte, close byte, body bytes.
fn c2h_fake(header: u8, seq: u8, close: u8, body: &[u8]) -> FwFake {
    let io = fw_fake(false, false, false, false);
    {
        let mut g = io.0.lock();
        g.regs[usize::from(c2h::REG_C2HEVT_MSG_NORMAL)] = header;
        g.regs[usize::from(c2h::REG_C2HEVT_MSG_NORMAL) + 1] = seq;
        g.regs[usize::from(c2h::REG_C2HEVT_CLOSE)] = close;
        for (i, b) in body.iter().enumerate() {
            g.regs[usize::from(c2h::REG_C2HEVT_MSG_NORMAL) + 2 + i] = *b;
        }
    }
    io
}

/// `rtl_8723e_c2h_command_handle` close-byte protocol: already-closed
/// issues no writes and reads no body; not-ready writes `0x00` and reads
/// no body; firmware-closed reads the body, dispatches, and closes.
fn smoke_rtl8723ae_c2h_mailbox_close_protocol() -> TestResult {
    use c2h::*;
    // Already closed: close byte HOST_CLOSE, body bytes present but unread.
    let io = c2h_fake(0x2c, 7, C2H_EVT_HOST_CLOSE, &[0x05, 0x03]);
    if c2h::drain(&io) != Ok(Outcome::AlreadyClosed)
        || !io.0.lock().writes.is_empty()
        || io.0.lock().regs[usize::from(REG_C2HEVT_CLOSE)] != C2H_EVT_HOST_CLOSE
    {
        return TestResult::Fail("8723AE mailbox already-closed branch");
    }
    // Not ready: close byte neither host- nor firmware-closed.
    let io = c2h_fake(0x2c, 7, 0x55, &[0x05, 0x03]);
    if c2h::drain(&io) != Ok(Outcome::NotReady)
        || io.0.lock().writes != vec![(REG_C2HEVT_CLOSE, 0, 1)]
    {
        return TestResult::Fail("8723AE mailbox not-ready branch");
    }
    // Firmware-closed with an ignored id still issues the final close.
    let io = c2h_fake(0x04, 9, C2H_EVT_FW_CLOSE, &[]);
    if c2h::drain(&io) != Ok(Outcome::Dispatched(Event::Ignored { id: C2H_V0_BT_RSSI }))
        || io.0.lock().writes != vec![(REG_C2HEVT_CLOSE, 0, 1)]
    {
        return TestResult::Fail("8723AE mailbox ignored-id close write");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_c2h_mailbox_close_protocol
);

/// BT info dispatch: header nibbles (id low, len high), the
/// `rtl8723e_dm_bt_parse_bt_info` bit decode, and the final close write.
fn smoke_rtl8723ae_c2h_mailbox_bt_info() -> TestResult {
    use c2h::*;
    // Header 0x2c: id 12 (BT_INFO), len 2. Body [0x05, 0x03]: inquiry
    // page (bit 2) + connected (bit 0), retry count 3.
    let io = c2h_fake(0x2c, 7, C2H_EVT_FW_CLOSE, &[0x05, 0x03]);
    match c2h::drain(&io) {
        Ok(Outcome::Dispatched(Event::BtInfo(info)))
            if info.original == 0x05
                && info.retry_cnt == 3
                && info.inquiry_page
                && info.connected => {}
        _ => return TestResult::Fail("8723AE mailbox BT info decode"),
    }
    if io.0.lock().writes != vec![(REG_C2HEVT_CLOSE, 0, 1)] {
        return TestResult::Fail("8723AE mailbox BT info close write");
    }
    // Short body (len 1): retry count stays 0, inquiry set, not connected.
    let io = c2h_fake(0x1c, 0, C2H_EVT_FW_CLOSE, &[0x04]);
    match c2h::drain(&io) {
        Ok(Outcome::Dispatched(Event::BtInfo(info)))
            if info.original == 0x04
                && info.retry_cnt == 0
                && info.inquiry_page
                && !info.connected => {}
        _ => return TestResult::Fail("8723AE mailbox BT info short body"),
    }
    // Empty body (len 0): all-zero info, still closed.
    let io = c2h_fake(0x0c, 0, C2H_EVT_FW_CLOSE, &[]);
    match c2h::drain(&io) {
        Ok(Outcome::Dispatched(Event::BtInfo(info)))
            if info.original == 0
                && info.retry_cnt == 0
                && !info.inquiry_page
                && !info.connected => {}
        _ => return TestResult::Fail("8723AE mailbox BT info empty body"),
    }
    // Operation-mode and unknown ids are consumed without effect.
    for id in [C2H_V0_BT_OP_MODE, 9] {
        let io = c2h_fake(id, 0, C2H_EVT_FW_CLOSE, &[]);
        if c2h::drain(&io) != Ok(Outcome::Dispatched(Event::Ignored { id }))
            || io.0.lock().writes != vec![(REG_C2HEVT_CLOSE, 0, 1)]
        {
            return TestResult::Fail("8723AE mailbox ignored ids");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_c2h_mailbox_bt_info
);

// ── 8723AE coexistence owner (step 2) ───────────────────────────────────

/// `adapter::BtInfo` for a BT-strapped 1-antenna board.
fn coex_bt() -> adapter::BtInfo {
    adapter::BtInfo {
        coexistence: true,
        kind: adapter::BT_RTL8723A,
        ant_num: adapter::AntNum::X1,
        ant_isolation: 0,
        radio_shared: 0,
    }
}

/// `hal_btc.c` BT-info ingestion + the `btc_periodical` trigger:
/// connected → busy + idle cleared + BtOnly decision; disconnected →
/// idle set + WifiOnly; no BT strap → no decision.
fn smoke_rtl8723ae_coex_ingest_and_periodical() -> TestResult {
    use coex::*;
    let mut owner = Owner::bind(&coex_bt());
    if owner.pattern() != crate::rtlwifi::btcoex::TdmaPattern::WifiOnly {
        return TestResult::Fail("8723AE coex initial pattern");
    }
    owner.ingest(&c2h::BtInfo {
        original: 0x05,
        retry_cnt: 3,
        inquiry_page: true,
        connected: true,
    });
    if !owner.bt_busy
        || owner.bt_idle
        || owner.retry_cnt != 3
        || !owner.inquiry_page
        || owner.req_sent
        || owner.cstate & state::BT_IDLE != 0
    {
        return TestResult::Fail("8723AE coex connected ingest");
    }
    if owner.periodical() != Some(crate::rtlwifi::btcoex::TdmaPattern::BtOnly) {
        return TestResult::Fail("8723AE coex connected periodical");
    }
    owner.ingest(&c2h::BtInfo {
        original: 0x00,
        retry_cnt: 0,
        inquiry_page: false,
        connected: false,
    });
    if owner.bt_busy
        || !owner.bt_idle
        || owner.cstate & state::BT_IDLE == 0
        || owner.periodical() != Some(crate::rtlwifi::btcoex::TdmaPattern::WifiOnly)
    {
        return TestResult::Fail("8723AE coex disconnected ingest");
    }
    // Inquiry-only (page, no link) → Inquiry state → BtOnly while idle.
    owner.ingest(&c2h::BtInfo {
        original: 0x04,
        retry_cnt: 1,
        inquiry_page: true,
        connected: false,
    });
    if owner.periodical() != Some(crate::rtlwifi::btcoex::TdmaPattern::BtOnly) {
        return TestResult::Fail("8723AE coex inquiry periodical");
    }
    // A board without the BT strap gets no decision.
    let mut plain = Owner::bind(&adapter::BtInfo {
        coexistence: false,
        ..coex_bt()
    });
    if plain.periodical().is_some() {
        return TestResult::Fail("8723AE coex unstrapped periodical");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_coex_ingest_and_periodical
);

/// `hal_bt_coexist.c` wifi-state bits, RSSI hysteresis (levels 2 and 3,
/// both variants), and state-changed detection.
fn smoke_rtl8723ae_coex_wifi_state_and_rssi() -> TestResult {
    use coex::*;
    let mut owner = Owner::bind(&coex_bt());
    owner.periodical();
    owner.check_wifi_state(&WifiTraffic {
        busy: true,
        tx_busy: true,
        rx_busy: false,
        legacy: false,
        bw40: true,
        bt30: false,
    });
    if owner.cstate & state::WIFI_IDLE != 0
        || owner.cstate & state::WIFI_UPLINK == 0
        || owner.cstate & state::WIFI_DOWNLINK != 0
        || owner.cstate & state::WIFI_HT40 == 0
        || owner.cstate & state::WIFI_HT20 != 0
        || owner.cstate & state::WIFI_LEGACY != 0
        || !owner.is_wifi_up_link()
        || !owner.is_coexist_state_changed()
    {
        return TestResult::Fail("8723AE coex wifi-state bits");
    }
    owner.periodical();
    if owner.is_coexist_state_changed() {
        return TestResult::Fail("8723AE coex state-changed snapshot");
    }
    // Level 2, non-1 variant: High → Low below thresh, Low → High at
    // thresh + tolerance (6).
    if owner.rssi_state(40, 2, 50, 0) != RssiState::Low
        || owner.cstate & state::WIFI_RSSI_LOW == 0
        || owner.cstate & state::WIFI_RSSI_HIGH != 0
    {
        return TestResult::Fail("8723AE coex rssi level-2 low");
    }
    if owner.rssi_state(60, 2, 50, 0) != RssiState::High
        || owner.cstate & state::WIFI_RSSI_HIGH == 0
        || owner.cstate & state::WIFI_RSSI_LOW != 0
    {
        return TestResult::Fail("8723AE coex rssi level-2 high");
    }
    // Level-3 threshold error returns the previous state unchanged.
    if owner.rssi_state(99, 3, 60, 50) != RssiState::High {
        return TestResult::Fail("8723AE coex rssi thresh error");
    }
    // Level 3, _1 variant: High → Medium below thresh1, Medium → High
    // at thresh1 + tolerance.
    if owner.rssi_state1(45, 3, 50, 60) != RssiState::Medium
        || owner.cstate & state::WIFI_RSSI_1_MEDIUM == 0
    {
        return TestResult::Fail("8723AE coex rssi1 level-3 medium");
    }
    if owner.rssi_state1(70, 3, 50, 60) != RssiState::High
        || owner.cstate & state::WIFI_RSSI_1_HIGH == 0
        || owner.cstate & state::WIFI_RSSI_1_MEDIUM != 0
    {
        return TestResult::Fail("8723AE coex rssi1 level-3 high");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_coex_wifi_state_and_rssi
);

/// LSSI write word `rtl8723_phy_rf_serial_write` puts on `0x840`
/// (`RF90_PATH_A` `rf3wire_offset`).
fn lssi_a(reg: u32, value: u32) -> (u16, u32, u8) {
    (0x840, ((reg << 20) | (value & 0xfffff)) & 0x0fff_ffff, 4)
}

/// `hal_bt_coexist.c` DM register writes: AGC tables (all five dwords
/// through the single `0xc78` port, then the RF half — `RF_RX_AGC_HP`
/// x4 and `RF_RX_G1` on path A via LSSI `0x840`), BB back-off `0xc04`,
/// balance H2C `0x0c`, and idempotent all-off.
fn smoke_rtl8723ae_coex_dm_registers() -> TestResult {
    use coex::*;
    let io = fw_fake(false, false, false, false);
    let mut owner = Owner::bind(&coex_bt());
    if owner.agc_table(&io, false).is_err() || owner.bb_back_off(&io, false).is_err() {
        return TestResult::Fail("8723AE coex off writes");
    }
    {
        let g = io.0.lock();
        if g.writes[..10]
            != [
                (REG_AGC_TABLE, 0x641c0001, 4),
                (REG_AGC_TABLE, 0x631d0001, 4),
                (REG_AGC_TABLE, 0x621e0001, 4),
                (REG_AGC_TABLE, 0x611f0001, 4),
                (REG_AGC_TABLE, 0x60200001, 4),
                lssi_a(0x12, 0x32000),
                lssi_a(0x12, 0x71000),
                lssi_a(0x12, 0xb0000),
                lssi_a(0x12, 0xfc000),
                lssi_a(0x1a, 0x30355),
            ]
            || g.writes[10] != (REG_BB_BACKOFF, BB_BACKOFF_OFF, 4)
        {
            return TestResult::Fail("8723AE coex off table bytes");
        }
    }
    if owner.agc_table(&io, true).is_err() || owner.bb_back_off(&io, true).is_err() {
        return TestResult::Fail("8723AE coex on writes");
    }
    if !owner.agc_on {
        return TestResult::Fail("8723AE coex agc on recorded");
    }
    {
        let g = io.0.lock();
        if g.writes[11..21]
            != [
                (REG_AGC_TABLE, 0x4e1c0001, 4),
                (REG_AGC_TABLE, 0x4d1d0001, 4),
                (REG_AGC_TABLE, 0x4c1e0001, 4),
                (REG_AGC_TABLE, 0x4b1f0001, 4),
                (REG_AGC_TABLE, 0x4a200001, 4),
                lssi_a(0x12, 0xdc000),
                lssi_a(0x12, 0x90000),
                lssi_a(0x12, 0x51000),
                lssi_a(0x12, 0x12000),
                lssi_a(0x1a, 0x00355),
            ]
            || g.writes[21] != (REG_BB_BACKOFF, BB_BACKOFF_ON, 4)
        {
            return TestResult::Fail("8723AE coex on table bytes");
        }
    }
    // Balance H2C 0x0c [ms0, ms1, on] through box 0; turning it on
    // clears the firmware all-off flag.
    owner.fw_all_off = true;
    if narf_scheduler::block_on(owner.balance(&io, true, 0x10, 0x20)).is_err()
        || owner.fw_all_off
        || !owner.balance_on
    {
        return TestResult::Fail("8723AE coex balance");
    }
    {
        let g = io.0.lock();
        if g.writes[22..]
            != [
                (REG_HMEBOX_0, u32::from(H2C_BALANCE), 1),
                (REG_HMEBOX_0 + 1, 0x10, 1),
                (REG_HMEBOX_0 + 2, 0x20, 1),
                (REG_HMEBOX_0 + 3, 1, 1),
            ]
        {
            return TestResult::Fail("8723AE coex balance box bytes");
        }
    }
    // All-off: idempotent, runs the grounded SW subset once.
    let before = io.0.lock().writes.len();
    if owner.coex_all_off(&io).is_err()
        || !owner.fw_all_off
        || !owner.sw_all_off
        || !owner.hw_all_off
    {
        return TestResult::Fail("8723AE coex all-off flags");
    }
    let after = io.0.lock().writes.len();
    if after - before != 11 {
        return TestResult::Fail("8723AE coex all-off sw subset writes");
    }
    if owner.coex_all_off(&io).is_err() || io.0.lock().writes.len() != after {
        return TestResult::Fail("8723AE coex all-off idempotence");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_coex_dm_registers
);

// ── 8723AE signed envelopes (step 2) ────────────────────────────────────

/// Test board factory (synthetic values, not any board's).
fn ae_factory() -> crate::rtlwifi::efuse::Factory {
    crate::rtlwifi::efuse::Factory {
        mac: [0x00, 0xe0, 0x4c, 0x87, 0x23, 0xae],
        logical: [0u8; 512],
    }
}

/// A NAPC row: (channel, bandwidth, offset, curve-value fn).
type NapcRow = (u8, u8, u8, fn(u8) -> i16);

/// Build a NAPC envelope from the documented layout (header 96, rows of
/// 388 bytes: channel/band/bandwidth/offset + three 64-entry curves).
/// `rows` are (channel, bandwidth, offset, curve-value fn) for v2, or
/// (channel, 20, 0, fn) for v1. The identity is the board's factory
/// identity; the MAC matches the factory.
fn napc_fixture(version: u16, antenna: i16, qualified: i16, rows: &[NapcRow]) -> Vec<u8> {
    let factory = ae_factory();
    let identity = crate::rtlwifi::radio::factory_identity(&factory);
    let total = 96 + rows.len() * 388;
    let mut bytes = vec![0u8; total];
    bytes[0..4].copy_from_slice(b"NAPC");
    bytes[4..6].copy_from_slice(&version.to_le_bytes());
    bytes[6..8].copy_from_slice(&96u16.to_le_bytes());
    bytes[8..12].copy_from_slice(&(total as u32).to_le_bytes());
    bytes[12..14].copy_from_slice(&0x10ecu16.to_le_bytes());
    bytes[14..16].copy_from_slice(&0x8723u16.to_le_bytes());
    bytes[16..48].copy_from_slice(&identity);
    bytes[48..54].copy_from_slice(&factory.mac);
    bytes[56..58].copy_from_slice(&antenna.to_le_bytes());
    bytes[58..60].copy_from_slice(&qualified.to_le_bytes());
    bytes[60..62].copy_from_slice(&(rows.len() as u16).to_le_bytes());
    bytes[62..64].copy_from_slice(&(if version == 1 { 20u16 } else { 0u16 }).to_le_bytes());
    for (i, (channel, bandwidth, offset, curve)) in rows.iter().enumerate() {
        let row = &mut bytes[96 + i * 388..96 + (i + 1) * 388];
        row[0] = *channel;
        if version == 2 {
            row[1] = 0;
            row[2] = *bandwidth;
            row[3] = *offset;
        }
        for curve_idx in 0..3 {
            for idx in 0..64 {
                let at = 4 + (curve_idx * 64 + idx) * 2;
                row[at..at + 2].copy_from_slice(&curve(idx as u8).to_le_bytes());
            }
        }
    }
    bytes
}

/// Flat rising curves: output `2 * index` quarter dBm, so a 20 dBm
/// ceiling with antenna 0 admits index 40 on every rate.
fn rising(idx: u8) -> i16 {
    i16::from(idx) * 2
}

/// US 2.4 GHz domain: 2402-2472 MHz, 40 MHz, 20 dBm.
fn us_domain() -> narf_wireless::reg::RegulatoryDomain {
    use narf_wireless::reg::*;
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2472,
            max_bandwidth_mhz: 40,
            max_power_dbm: 20,
            flags: RegFlags::empty(),
        }],
    }
}

/// v1 parse + permission (all 20 rates admitted, index 40), tampered
/// variants, and the masking-defeating multi-row v2 case.
fn smoke_rtl8723ae_envelope_parse_and_permission() -> TestResult {
    use envelope::*;
    let factory = ae_factory();
    let domain = us_domain();
    let mut v1_rows = Vec::new();
    for channel in 1..=11u8 {
        v1_rows.push((channel, 20, 0, rising as fn(u8) -> i16));
    }
    let bytes = napc_fixture(1, 0, 256, &v1_rows);
    let cal = match Calibration::from_verified(&bytes, Some([0xabu8; 32]), &factory) {
        Ok(cal) => cal,
        Err(_) => return TestResult::Fail("8723AE envelope v1 parse"),
    };
    if cal.operating_points().count() != 11 || !cal.measures(Operating::twenty(6)) {
        return TestResult::Fail("8723AE envelope v1 rows");
    }
    let perm = match cal.permission(&domain, 6) {
        Ok(perm) => perm,
        Err(_) => return TestResult::Fail("8723AE envelope v1 permission"),
    };
    if perm.channel() != 6
        || perm.eirp_limit_qdbm() != 80
        || perm.admitted_rates() != 0xfffff
        || perm.index(0) != 40
        || perm.index(12) != 40
        || !perm.admits(19)
    {
        return TestResult::Fail("8723AE envelope v1 permission values");
    }
    // Tampered variants fail where verification is required.
    let mut bad = bytes.clone();
    bad[0] = b'X';
    if Calibration::from_verified(&bad, Some([0xabu8; 32]), &factory).is_ok() {
        return TestResult::Fail("8723AE envelope bad magic admitted");
    }
    let mut bad = bytes.clone();
    bad[14..16].copy_from_slice(&0x8821u16.to_le_bytes());
    if Calibration::from_verified(&bad, Some([0xabu8; 32]), &factory).is_ok() {
        return TestResult::Fail("8723AE envelope wrong device admitted");
    }
    if Calibration::from_verified(&bytes, None, &factory).is_ok() {
        return TestResult::Fail("8723AE envelope unsigned admitted");
    }
    let mut bad = bytes.clone();
    bad[16] ^= 0xff;
    if Calibration::from_verified(&bad, Some([0xabu8; 32]), &factory).is_ok() {
        return TestResult::Fail("8723AE envelope identity mismatch admitted");
    }
    // Unordered rows: swap channels 1 and 2.
    let mut bad = bytes.clone();
    bad.swap(96, 96 + 388);
    if Calibration::from_verified(&bad, Some([0xabu8; 32]), &factory).is_ok() {
        return TestResult::Fail("8723AE envelope unordered rows admitted");
    }
    // A channel-12 row has no centre in the admitted plan.
    let mut rows12 = v1_rows.clone();
    rows12.push((12, 20, 0, rising as fn(u8) -> i16));
    if Calibration::from_verified(
        &napc_fixture(1, 0, 256, &rows12),
        Some([0xabu8; 32]),
        &factory,
    )
    .is_ok()
    {
        return TestResult::Fail("8723AE envelope channel 12 admitted");
    }
    // Wholly unmeasured HT curve on channel 6 → the point is refused.
    let mut rows_unmeasured = v1_rows.clone();
    rows_unmeasured[5] = (
        6,
        20,
        0,
        (|idx: u8| {
            // CCK/OFDM rise; HT is filled below by hand.
            let _ = idx;
            0
        }) as fn(u8) -> i16,
    );
    let mut bytes_unmeasured = napc_fixture(1, 0, 256, &rows_unmeasured);
    // Blank the HT curve (third curve) of the channel-6 row.
    let row6 = &mut bytes_unmeasured[96 + 5 * 388..96 + 6 * 388];
    for idx in 0..64 {
        let at = 4 + (2 * 64 + idx) * 2;
        row6[at..at + 2].copy_from_slice(&i16::MAX.to_le_bytes());
    }
    let cal_unmeasured =
        match Calibration::from_verified(&bytes_unmeasured, Some([0xabu8; 32]), &factory) {
            Ok(cal) => cal,
            Err(_) => return TestResult::Fail("8723AE envelope unmeasured parse"),
        };
    if cal_unmeasured.permission(&domain, 6).is_ok() {
        return TestResult::Fail("8723AE envelope unmeasured HT admitted");
    }
    // Masking-defeating v2 case: a 20 MHz row must not satisfy a 40 MHz
    // operating point, and a real 40 MHz row must.
    let v2_only20 = napc_fixture(2, 0, 256, &[(6, 20, 0, rising as fn(u8) -> i16)]);
    let cal20 = match Calibration::from_verified(&v2_only20, Some([0xabu8; 32]), &factory) {
        Ok(cal) => cal,
        Err(_) => return TestResult::Fail("8723AE envelope v2 20-only parse"),
    };
    if cal20
        .permission_for(
            &domain,
            Operating {
                width: Width::W40Above,
                channel: 6,
            },
        )
        .is_ok()
    {
        return TestResult::Fail("8723AE envelope 20 MHz row satisfied 40 MHz");
    }
    let v2_both = napc_fixture(
        2,
        0,
        256,
        &[
            (6, 20, 0, rising as fn(u8) -> i16),
            (6, 40, 1, rising as fn(u8) -> i16),
        ],
    );
    let cal_both = match Calibration::from_verified(&v2_both, Some([0xabu8; 32]), &factory) {
        Ok(cal) => cal,
        Err(_) => return TestResult::Fail("8723AE envelope v2 both parse"),
    };
    if cal_both
        .permission_for(
            &domain,
            Operating {
                width: Width::W40Above,
                channel: 6,
            },
        )
        .is_err()
    {
        return TestResult::Fail("8723AE envelope 40 MHz row refused");
    }
    // A 5 GHz row (band 1) is a format failure on this 2.4 GHz part.
    let mut v2_5g = napc_fixture(2, 0, 256, &[(6, 20, 0, rising as fn(u8) -> i16)]);
    v2_5g[96 + 1] = 1;
    if Calibration::from_verified(&v2_5g, Some([0xabu8; 32]), &factory).is_ok() {
        return TestResult::Fail("8723AE envelope 5 GHz row admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_envelope_parse_and_permission
);

// ── 8723AE packet owner (step 2) ────────────────────────────────────────

/// Admitted permission for 20 MHz channel 6 (from the v1 fixture).
fn ae_permission() -> envelope::Permission {
    let factory = ae_factory();
    let mut rows = Vec::new();
    for channel in 1..=11u8 {
        rows.push((channel, 20, 0, rising as fn(u8) -> i16));
    }
    let bytes = napc_fixture(1, 0, 256, &rows);
    let cal = envelope::Calibration::from_verified(&bytes, Some([0xabu8; 32]), &factory)
        .expect("8723AE packet test fixture");
    cal.permission(&us_domain(), 6)
        .expect("8723AE packet test permission")
}

/// TX descriptor golden values (independent bit math from `trx.h`),
/// admission gates, and RX descriptor decode.
fn smoke_rtl8723ae_packet_admission_and_desc() -> TestResult {
    use packet::*;
    let owner = Owner::admit(
        crate::rtlwifi::firmware_transport::Info {
            version: 1,
            subversion: 0,
            payload: 0,
        },
        ae_permission(),
    );
    let op = envelope::Operating::twenty(6);
    if owner.admit_tx(op, 12).is_err()
        || owner.admit_tx(envelope::Operating::twenty(7), 12).is_ok()
        || owner.admit_tx(op, 20).is_ok()
    {
        return TestResult::Fail("8723AE packet admission gates");
    }
    let tx = TxFrame {
        op,
        class: FrameClass::Data { priority: 0 },
        len: 100,
        buf_phys: 0x1234_5678_9abc_def0,
        rate: 12,
        seq: 0xabc,
        short_gi: true,
        bw40: false,
        tx_sc: 0,
        bmc: false,
        rts: None,
        next_desc: 0,
    };
    let mut slot = [0u32; TX_DESC_DWORDS];
    if owner.fill_tx_slot(&mut slot, &tx).is_err() {
        return TestResult::Fail("8723AE packet fill admitted");
    }
    // DW0: len | offset 32 | lastseg | firstseg | own.
    // DW1: queuesel 0. DW3: seq. DW5: rate | shortgi | fb limits.
    // DW7: buf size. DW8/DW9: buf address low/high.
    if slot[0] != 0x8c20_0064
        || slot[1] != 0
        || slot[3] != 0x0abc_0000
        || slot[5] != 0x0001_ff4c
        || slot[7] != 100
        || slot[8] != 0x9abc_def0
        || slot[9] != 0x1234_5678
        || slot[10] != 0
    {
        return TestResult::Fail("8723AE packet TX descriptor bytes");
    }
    // Beacon class selects QSLT_BEACON (0x10); a refused frame writes
    // nothing.
    let mut beacon = [0u32; TX_DESC_DWORDS];
    let beacon_tx = TxFrame {
        class: FrameClass::Beacon,
        ..tx
    };
    if owner.fill_tx_slot(&mut beacon, &beacon_tx).is_err() || beacon[1] != 0x1000 {
        return TestResult::Fail("8723AE packet beacon queuesel");
    }
    let mut refused = [0u32; TX_DESC_DWORDS];
    let refused_tx = TxFrame {
        op: envelope::Operating::twenty(7),
        ..tx
    };
    if owner.fill_tx_slot(&mut refused, &refused_tx).is_ok() || refused != [0u32; 16] {
        return TestResult::Fail("8723AE packet refused frame wrote");
    }
    if owner
        .fill_tx_slot(&mut refused, &TxFrame { len: 0, ..tx })
        .is_ok()
    {
        return TestResult::Fail("8723AE packet zero length admitted");
    }
    // RX decode golden: len 200, drvinfo 2 (16 bytes), shift 1,
    // PAGGR + FAGGR, rate 12 HT 40 MHz, timestamp + buffer address.
    let d = [
        0x0102_00c8u32,
        0x0000_c000,
        0,
        0x0000_024c,
        0,
        0xdead_beef,
        0x0000_1000,
        0,
    ];
    let rx = decode_rx_desc(&d);
    if rx.hw_owned
        || rx.pkt_len != 200
        || rx.drv_info_bytes != 16
        || rx.shift != 1
        || rx.payload_offset() != 17
        || rx.payload_len() != 183
        || !rx.paggr
        || !rx.first_ampdu
        || rx.rate != 12
        || !rx.ht
        || !rx.bw40
        || rx.cck
        || rx.timestamp_low != 0xdead_beef
        || rx.buf_addr != 0x1000
    {
        return TestResult::Fail("8723AE packet RX decode");
    }
    let mut owned = d;
    owned[0] |= 1 << 31;
    if !decode_rx_desc(&owned).hw_owned {
        return TestResult::Fail("8723AE packet RX own bit");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_packet_admission_and_desc
);

/// Mailbox wiring: `c2h_pending` gates the drain; BT info feeds the
/// coexistence owner and returns the periodical decision.
fn smoke_rtl8723ae_packet_service_c2h() -> TestResult {
    use crate::rtlwifi::irq::{IsrStatus, IMR_C2HCMD};
    use packet::*;
    let mut owner = Owner::admit(
        crate::rtlwifi::firmware_transport::Info {
            version: 1,
            subversion: 0,
            payload: 0,
        },
        ae_permission(),
    );
    let mut coex = coex::Owner::bind(&coex_bt());
    // No interrupt: nothing drained, no writes.
    let idle_io = c2h_fake(0x2c, 7, c2h::C2H_EVT_FW_CLOSE, &[0x05, 0x03]);
    if owner.service_c2h(&idle_io, IsrStatus { hisr: 0, hisre: 0 }, Some(&mut coex))
        != Ok(Service::NotPending)
        || !idle_io.0.lock().writes.is_empty()
    {
        return TestResult::Fail("8723AE packet service not-pending");
    }
    // Pending + BT info: ingested, BtOnly decision (idle Wi-Fi, BT link).
    let io = c2h_fake(0x2c, 7, c2h::C2H_EVT_FW_CLOSE, &[0x05, 0x03]);
    if owner.service_c2h(
        &io,
        IsrStatus {
            hisr: IMR_C2HCMD,
            hisre: 0,
        },
        Some(&mut coex),
    ) != Ok(Service::BtInfo {
        pattern: Some(crate::rtlwifi::btcoex::TdmaPattern::BtOnly),
    }) || !coex.bt_busy
    {
        return TestResult::Fail("8723AE packet service bt-info");
    }
    // Pending + ignored id: consumed without effect.
    let io = c2h_fake(0x04, 9, c2h::C2H_EVT_FW_CLOSE, &[]);
    if owner.service_c2h(
        &io,
        IsrStatus {
            hisr: IMR_C2HCMD,
            hisre: 0,
        },
        Some(&mut coex),
    ) != Ok(Service::Ignored {
        id: c2h::C2H_V0_BT_RSSI,
    }) {
        return TestResult::Fail("8723AE packet service ignored");
    }
    // Pending + already closed: nothing read or written.
    let io = c2h_fake(0x2c, 7, c2h::C2H_EVT_HOST_CLOSE, &[0x05, 0x03]);
    if owner.service_c2h(
        &io,
        IsrStatus {
            hisr: IMR_C2HCMD,
            hisre: 0,
        },
        Some(&mut coex),
    ) != Ok(Service::AlreadyClosed)
        || !io.0.lock().writes.is_empty()
    {
        return TestResult::Fail("8723AE packet service already-closed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_packet_service_c2h
);

// ── shared bt_coexistence mechanism trees (`dm.rs`) ────────────────────

/// Reconstruct H2C fills from a `FwFake` write log. Each fill is
/// `(command id, payload bytes)` in command order: for a BIT(7) id the
/// two extension bytes written immediately before the box, then the box
/// content bytes after the id (short payloads pad the content to three
/// bytes with zeros, matching the box image).
/// Box rotation is irrelevant: fills are detected by box-base writes.
fn dm_h2c_fills(writes: &[(u16, u32, u8)]) -> Vec<(u8, Vec<u8>)> {
    let mut fills = Vec::new();
    let mut i = 0;
    while i < writes.len() {
        let (reg, value, _) = writes[i];
        if (0x01d0..0x01e0).contains(&reg) && (reg - 0x01d0) % 4 == 0 {
            // `_rtl8723e_fill_h2c_command`: BIT(7) marks a 4/5-byte
            // command whose first two bytes were written to the two-byte
            // extension register `0x88 + 2 * box` just before the box.
            let boxnum = (reg - 0x01d0) / 4;
            let ext_base = 0x0088u16 + boxnum * 2;
            let mut payload = Vec::new();
            if value & 0x80 != 0 && i >= 2 {
                for (preg, pvalue, _) in &writes[i - 2..i] {
                    if (ext_base..ext_base + 2).contains(preg) {
                        payload.push(*pvalue as u8);
                    }
                }
            }
            for t in 1..4 {
                if i + t < writes.len() {
                    payload.push(writes[i + t].1 as u8);
                }
            }
            fills.push(((value & 0x7f) as u8, payload));
            i += 4;
        } else {
            i += 1;
        }
    }
    fills
}

/// Find a fill by command id in a reconstructed fill list.
fn dm_find(fills: &[(u8, Vec<u8>)], id: u8) -> Option<&[u8]> {
    fills
        .iter()
        .find(|(i, _)| *i == id)
        .map(|(_, p)| p.as_slice())
}

/// `hal_btc.c` mechanism init + BT-info query: init zeroes the state,
/// reads the RF origins (`RF_RCK1` full mask, `RF_RCK2` `0xf0`) through
/// the path-A LSSI readback, writes `0x76e = 0x04`, `0x778 = 0x03`, PTA
/// on; second init is silent; the query sends H2C `0x38
/// [0x01]` and marks the request sent.
fn smoke_rtl8723ae_dm_mech_init_and_query() -> TestResult {
    use coex::*;
    use dm::*;
    let io = fw_fake(false, false, false, false);
    // Path-A LSSI readback (`0x8a0`; `0x820` BIT(8) clear = SI mode).
    io.0.lock().regs[0x8a0..0x8a4].copy_from_slice(&0x0001_2345u32.to_le_bytes());
    let mut owner = Owner::bind(&coex_bt());
    if narf_scheduler::block_on(owner.mech_init(&io)).is_err() {
        return TestResult::Fail("8723AE dm mech_init error");
    }
    if !owner.mech_init_set
        || owner.rf_origin_1e != Some(0x12345)
        || owner.rf_origin_1f != Some(0x4)
        || owner.cstate != 0
        || owner.saved_btdm != Btdm::default()
    {
        return TestResult::Fail("8723AE dm mech_init state");
    }
    {
        let g = io.0.lock();
        if g.writes.iter().filter(|(r, _, _)| *r == 0x76e).count() != 1
            || !g.writes.contains(&(0x76e, 0x04, 1))
            || !g.writes.contains(&(0x778, 0x03, 1))
            || !g.writes.contains(&(0x40, 0x20, 1))
        {
            return TestResult::Fail("8723AE dm mech_init writes");
        }
    }
    let before = io.0.lock().writes.len();
    if narf_scheduler::block_on(owner.mech_init(&io)).is_err() || io.0.lock().writes.len() != before
    {
        return TestResult::Fail("8723AE dm mech_init idempotent");
    }
    if narf_scheduler::block_on(owner.query_bt_information(&io)).is_err() || !owner.req_sent {
        return TestResult::Fail("8723AE dm query error");
    }
    let fills = dm_h2c_fills(&io.0.lock().writes);
    if dm_find(&fills, 0x38) != Some(&[0x01, 0x00, 0x00][..]) {
        return TestResult::Fail("8723AE dm query H2C 0x38");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_dm_mech_init_and_query
);

/// `hal_btc.c` counter monitor + enable/disable check + counter
/// levels: dword split, LPS modulo reset, dead-read counting to
/// disabled after two, levels 1200/1400/3000, and LEVEL_3 stickiness.
fn smoke_rtl8723ae_dm_counters_and_levels() -> TestResult {
    use coex::*;
    use dm::*;
    let io = fw_fake(false, false, false, false);
    let mut owner = Owner::bind(&coex_bt());
    // Preload: hp 0x0002_0001 (tx 1, rx 2), lp 0x0004_0003 (tx 3, rx 4).
    {
        let mut g = io.0.lock();
        g.regs[0x770..0x774].copy_from_slice(&0x0002_0001u32.to_le_bytes());
        g.regs[0x774..0x778].copy_from_slice(&0x0004_0003u32.to_le_bytes());
    }
    if owner.counters_monitor(&io).is_err()
        || owner.hp_tx != 1
        || owner.hp_rx != 2
        || owner.lp_tx != 3
        || owner.lp_rx != 4
        || owner.bt_active_zero_cnt != 0
    {
        return TestResult::Fail("8723AE dm counters split");
    }
    // LPS counter 2: each counter is reduced modulo 2, then reset.
    owner.lps_counter = 2;
    if owner.counters_monitor(&io).is_err()
        || owner.hp_tx != 1
        || owner.hp_rx != 0
        || owner.lp_tx != 1
        || owner.lp_rx != 0
        || owner.lps_counter != 0
    {
        return TestResult::Fail("8723AE dm counters LPS reset");
    }
    // Enable/disable: two consecutive dead reads disable BT.
    {
        let mut g = io.0.lock();
        g.regs[0x770..0x774].copy_from_slice(&0u32.to_le_bytes());
        g.regs[0x774..0x778].copy_from_slice(&0u32.to_le_bytes());
    }
    if owner.counters_monitor(&io).is_err() {
        return TestResult::Fail("8723AE dm enable monitor error");
    }
    owner.enable_disable_check();
    if owner.cur_bt_disabled || owner.bt_active_zero_cnt != 1 {
        return TestResult::Fail("8723AE dm enable first dead read");
    }
    owner.enable_disable_check();
    if !owner.cur_bt_disabled || owner.bt_active_zero_cnt != 2 {
        return TestResult::Fail("8723AE dm enable second dead read");
    }
    // Alive counters clear the disabled flag and the count.
    {
        let mut g = io.0.lock();
        g.regs[0x770..0x774].copy_from_slice(&0x0001_0001u32.to_le_bytes());
    }
    if owner.counters_monitor(&io).is_err() {
        return TestResult::Fail("8723AE dm enable alive monitor error");
    }
    owner.enable_disable_check();
    if owner.cur_bt_disabled || owner.bt_active_zero_cnt != 0 {
        return TestResult::Fail("8723AE dm enable alive clears");
    }
    // Counter levels and the LEVEL_3 stickiness (Linux omits bit 3
    // from the clear mask, so the bit sticks once set).
    owner.hp_tx = 100;
    owner.hp_rx = 1100;
    owner.lp_tx = 0;
    owner.lp_rx = 0;
    if owner.counter_level() != 1 || owner.cstate_h & CNT_LEVEL_1 == 0 {
        return TestResult::Fail("8723AE dm counter level 1");
    }
    owner.hp_tx = 1500;
    owner.hp_rx = 1500;
    if owner.counter_level() != 3 || owner.cstate_h & CNT_LEVEL_3 == 0 {
        return TestResult::Fail("8723AE dm counter level 3");
    }
    owner.hp_tx = 0;
    owner.hp_rx = 0;
    if owner.counter_level() != 0
        || owner.cstate_h & CNT_LEVEL_3 == 0
        || owner.cstate_h & CNT_LEVEL_0 == 0
    {
        return TestResult::Fail("8723AE dm counter level 3 sticks");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_dm_counters_and_levels
);

/// `hal_btc.c` common action: idle+idle → all-off btdm; Wi-Fi busy +
/// BT idle → low-penalty table `0x5a5aaaaa`/`0xcccc`/`0x3` with dec BT
/// power on a link; BT busy + no link → shrink table
/// `0x55555555`/`0xffff`/`0x3`; BT busy + link → not common.
fn smoke_rtl8723ae_dm_common_action() -> TestResult {
    use coex::*;
    use dm::*;
    let idle = WifiTraffic {
        busy: false,
        tx_busy: false,
        rx_busy: false,
        legacy: false,
        bw40: false,
        bt30: false,
    };
    let busy = WifiTraffic {
        busy: true,
        tx_busy: true,
        rx_busy: false,
        legacy: false,
        bw40: false,
        bt30: false,
    };
    // Idle + idle: all-off btdm, COMMON bit, coex table + PTA on.
    let io = fw_fake(false, false, false, false);
    let mut owner = Owner::bind(&coex_bt());
    if narf_scheduler::block_on(owner.common_action(
        &io,
        MechInputs {
            wifi: idle,
            linked: false,
            pwdb: 60,
            now_ms: 0,
            a_cut: false,
        },
    )) != Ok(true)
        || owner.profile_action != Mech::None
        || owner.saved_btdm != Btdm::all_off()
        || owner.cstate & state::BTINFO_COMMON == 0
    {
        return TestResult::Fail("8723AE dm common idle btdm");
    }
    {
        let g = io.0.lock();
        if !g.writes.contains(&(0x6c0, 0x5a5a_aaaa, 4)) || !g.writes.contains(&(0x40, 0x20, 1)) {
            return TestResult::Fail("8723AE dm common idle writes");
        }
    }
    // Wi-Fi busy + BT idle + link: low-penalty, dec BT power set.
    let io = fw_fake(false, false, false, false);
    let mut owner = Owner::bind(&coex_bt());
    if narf_scheduler::block_on(owner.common_action(
        &io,
        MechInputs {
            wifi: busy,
            linked: true,
            pwdb: 60,
            now_ms: 0,
            a_cut: false,
        },
    )) != Ok(true)
        || owner.saved_btdm.val_0x6c0 != 0x5a5a_aaaa
        || owner.saved_btdm.val_0x6c8 != 0xcccc
        || owner.saved_btdm.val_0x6cc != 0x3
        || !owner.saved_btdm.low_penalty_rate_adaptive
        || !owner.saved_btdm.dec_bt_pwr
        || owner.saved_btdm.rf_rx_lpf_shrink
    {
        return TestResult::Fail("8723AE dm common wifi-busy btdm");
    }
    // BT busy + no link: shrink table, no dec power.
    let io = fw_fake(false, false, false, false);
    let mut owner = Owner::bind(&coex_bt());
    owner.bt_busy = true;
    if narf_scheduler::block_on(owner.common_action(
        &io,
        MechInputs {
            wifi: idle,
            linked: false,
            pwdb: 60,
            now_ms: 0,
            a_cut: false,
        },
    )) != Ok(true)
        || owner.saved_btdm.val_0x6c0 != 0x5555_5555
        || owner.saved_btdm.val_0x6c8 != 0xffff
        || owner.saved_btdm.val_0x6cc != 0x3
        || !owner.saved_btdm.rf_rx_lpf_shrink
        || owner.saved_btdm.dec_bt_pwr
    {
        return TestResult::Fail("8723AE dm common bt-busy btdm");
    }
    // BT busy + link: not common — profile actions take over.
    let io = fw_fake(false, false, false, false);
    let mut owner = Owner::bind(&coex_bt());
    owner.bt_busy = true;
    if narf_scheduler::block_on(owner.common_action(
        &io,
        MechInputs {
            wifi: idle,
            linked: true,
            pwdb: 60,
            now_ms: 0,
            a_cut: false,
        },
    )) != Ok(false)
    {
        return TestResult::Fail("8723AE dm common bt-busy-linked not common");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_dm_common_action
);

/// `hal_btc.c` HID/SCO/eSCO, HT40: PS row by counter level only
/// (level 2 → `[a3,5,5,2,80]`), AGC off, table `0x55555555`.
fn smoke_rtl8723ae_dm_hid_sco_esco_ht40() -> TestResult {
    use coex::*;
    use dm::*;
    let io = fw_fake(false, false, false, false);
    let mut owner = Owner::bind(&adapter::BtInfo {
        coexistence: true,
        kind: adapter::BT_RTL8723A,
        ant_num: adapter::AntNum::X2,
        ant_isolation: 0,
        radio_shared: 0,
    });
    owner.bt_busy = true;
    owner.bt_info_original = 0x20; // HID bit.
    owner.hp_tx = 800;
    owner.hp_rx = 800; // Level 2 (>= 1400).
    let outcome = narf_scheduler::block_on(owner.coexist_2_ant(
        &io,
        MechInputs {
            wifi: WifiTraffic {
                busy: true,
                tx_busy: true,
                rx_busy: false,
                legacy: false,
                bw40: true,
                bt30: false,
            },
            linked: true,
            pwdb: 60,
            now_ms: 0,
            a_cut: false,
        },
    ));
    if outcome != Ok(Mech::HidScoEsco)
        || owner.profile_case != Mech::HidScoEsco
        || owner.profile_action != Mech::HidScoEsco
    {
        return TestResult::Fail("8723AE dm hid ht40 dispatch");
    }
    let fills = dm_h2c_fills(&io.0.lock().writes);
    if dm_find(&fills, 0x3a) != Some(&[0xa3, 0x05, 0x05, 0x02, 0x80][..]) {
        return TestResult::Fail("8723AE dm hid ht40 ps row");
    }
    if owner.saved_btdm.val_0x6c0 != 0x5555_5555 || owner.saved_btdm.agc_table_en {
        return TestResult::Fail("8723AE dm hid ht40 btdm");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_dm_hid_sco_esco_ht40
);

/// `hal_btc.c` HID/SCO/eSCO, HT20: RSSI high → AGC on + `0x883 =
/// 0x40` + byte3 `0x83`; RSSI low → AGC off + byte3 `0x02`; level 1 →
/// row `[a3,a,a,*,80]`.
fn smoke_rtl8723ae_dm_hid_sco_esco_ht20() -> TestResult {
    use coex::*;
    use dm::*;
    let mk = || {
        let mut owner = Owner::bind(&adapter::BtInfo {
            coexistence: true,
            kind: adapter::BT_RTL8723A,
            ant_num: adapter::AntNum::X2,
            ant_isolation: 0,
            radio_shared: 0,
        });
        owner.bt_busy = true;
        owner.bt_info_original = 0x20; // HID bit.
        owner.hp_tx = 600;
        owner.hp_rx = 600; // Level 1 (>= 1200).
        owner
    };
    let wifi = WifiTraffic {
        busy: true,
        tx_busy: true,
        rx_busy: false,
        legacy: false,
        bw40: false,
        bt30: false,
    };
    // RSSI high (60 >= 47) and RSSI-1 high (60 >= 27): byte3 0x83.
    let io = fw_fake(false, false, false, false);
    let mut owner = mk();
    if narf_scheduler::block_on(owner.coexist_2_ant(
        &io,
        MechInputs {
            wifi,
            linked: true,
            pwdb: 60,
            now_ms: 0,
            a_cut: false,
        },
    ))
    .is_err()
    {
        return TestResult::Fail("8723AE dm hid ht20 high error");
    }
    let fills = dm_h2c_fills(&io.0.lock().writes);
    if dm_find(&fills, 0x3a) != Some(&[0xa3, 0x0a, 0x0a, 0x83, 0x80][..])
        || !io.0.lock().writes.contains(&(0x883, 0x40, 1))
        || !owner.saved_btdm.agc_table_en
    {
        return TestResult::Fail("8723AE dm hid ht20 high row");
    }
    // RSSI low (20 < 47) and RSSI-1 low (drive to Low first, then 20
    // stays Low): byte3 0x02, no 0x883 write.
    let io = fw_fake(false, false, false, false);
    let mut owner = mk();
    owner.rssi_state1(20, 2, 27, 0);
    if narf_scheduler::block_on(owner.coexist_2_ant(
        &io,
        MechInputs {
            wifi,
            linked: true,
            pwdb: 20,
            now_ms: 0,
            a_cut: false,
        },
    ))
    .is_err()
    {
        return TestResult::Fail("8723AE dm hid ht20 low error");
    }
    let fills = dm_h2c_fills(&io.0.lock().writes);
    if dm_find(&fills, 0x3a) != Some(&[0xa3, 0x0a, 0x0a, 0x02, 0x80][..])
        || io.0.lock().writes.contains(&(0x883, 0x40, 1))
        || owner.saved_btdm.agc_table_en
    {
        return TestResult::Fail("8723AE dm hid ht20 low row");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_dm_hid_sco_esco_ht20
);

/// `hal_btc.c` FTP/A2DP, HT40: byte3 `0x81` on RSSI high, `0x00` on
/// RSSI low; back-off always on; inquiry/level-3 override forces
/// `[a3,5,5,83,80]`.
fn smoke_rtl8723ae_dm_ftp_a2dp_ht40() -> TestResult {
    use coex::*;
    use dm::*;
    let mk = || {
        let mut owner = Owner::bind(&adapter::BtInfo {
            coexistence: true,
            kind: adapter::BT_RTL8723A,
            ant_num: adapter::AntNum::X2,
            ant_isolation: 0,
            radio_shared: 0,
        });
        owner.bt_busy = true;
        owner.bt_info_original = 0x40; // A2DP bit.
        owner.hp_tx = 800;
        owner.hp_rx = 800; // Level 2.
        owner
    };
    let wifi = WifiTraffic {
        busy: true,
        tx_busy: true,
        rx_busy: false,
        legacy: false,
        bw40: true,
        bt30: false,
    };
    let io = fw_fake(false, false, false, false);
    let mut owner = mk();
    if narf_scheduler::block_on(owner.coexist_2_ant(
        &io,
        MechInputs {
            wifi,
            linked: true,
            pwdb: 60,
            now_ms: 0,
            a_cut: false,
        },
    ))
    .is_err()
    {
        return TestResult::Fail("8723AE dm ftp ht40 high error");
    }
    let fills = dm_h2c_fills(&io.0.lock().writes);
    if dm_find(&fills, 0x3a) != Some(&[0xa3, 0x05, 0x05, 0x81, 0x80][..])
        || !owner.saved_btdm.adc_back_off_on
    {
        return TestResult::Fail("8723AE dm ftp ht40 high row");
    }
    let io = fw_fake(false, false, false, false);
    let mut owner = mk();
    if narf_scheduler::block_on(owner.coexist_2_ant(
        &io,
        MechInputs {
            wifi,
            linked: true,
            pwdb: 20,
            now_ms: 0,
            a_cut: false,
        },
    ))
    .is_err()
    {
        return TestResult::Fail("8723AE dm ftp ht40 low error");
    }
    let fills = dm_h2c_fills(&io.0.lock().writes);
    if dm_find(&fills, 0x3a) != Some(&[0xa3, 0x05, 0x05, 0x00, 0x80][..]) {
        return TestResult::Fail("8723AE dm ftp ht40 low row");
    }
    // Inquiry window open forces the override row even at level 0.
    let io = fw_fake(false, false, false, false);
    let mut owner = mk();
    owner.hp_tx = 0;
    owner.hp_rx = 0;
    owner.ingest(&c2h::BtInfo {
        original: 0x44, // A2DP + INQ_PAGE.
        retry_cnt: 0,
        inquiry_page: true,
        connected: true,
    });
    if narf_scheduler::block_on(owner.coexist_2_ant(
        &io,
        MechInputs {
            wifi,
            linked: true,
            pwdb: 20,
            now_ms: 1000,
            a_cut: false,
        },
    ))
    .is_err()
    {
        return TestResult::Fail("8723AE dm ftp inq error");
    }
    let fills = dm_h2c_fills(&io.0.lock().writes);
    if dm_find(&fills, 0x3a) != Some(&[0xa3, 0x05, 0x05, 0x83, 0x80][..])
        || owner.inq_page_start_ms != Some(1000)
    {
        return TestResult::Fail("8723AE dm ftp inq override row");
    }
    // Ten seconds later the window closes.
    if narf_scheduler::block_on(owner.coexist_2_ant(
        &io,
        MechInputs {
            wifi,
            linked: true,
            pwdb: 20,
            now_ms: 11_000,
            a_cut: false,
        },
    ))
    .is_err()
        || owner.inq_page_start_ms.is_some()
    {
        return TestResult::Fail("8723AE dm ftp inq window closes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_dm_ftp_a2dp_ht40
);

/// `hal_btc.c` dispatch: no profile bits → case None but the
/// HID/SCO/eSCO action still runs (Linux's undefined-case branch);
/// SCO_ESCO bit alone → HID_SCO_ESCO case.
fn smoke_rtl8723ae_dm_dispatch_undefined() -> TestResult {
    use coex::*;
    use dm::*;
    let wifi = WifiTraffic {
        busy: true,
        tx_busy: true,
        rx_busy: false,
        legacy: false,
        bw40: true,
        bt30: false,
    };
    let io = fw_fake(false, false, false, false);
    let mut owner = Owner::bind(&adapter::BtInfo {
        coexistence: true,
        kind: adapter::BT_RTL8723A,
        ant_num: adapter::AntNum::X2,
        ant_isolation: 0,
        radio_shared: 0,
    });
    owner.bt_busy = true;
    owner.bt_info_original = 0x01; // Connection only, no profile.
    if narf_scheduler::block_on(owner.coexist_2_ant(
        &io,
        MechInputs {
            wifi,
            linked: true,
            pwdb: 60,
            now_ms: 0,
            a_cut: false,
        },
    )) != Ok(Mech::None)
        || owner.profile_case != Mech::None
        || owner.profile_action != Mech::None
        || owner.cstate & state::BTINFO_B_HID_SCOESCO == 0
    {
        return TestResult::Fail("8723AE dm dispatch undefined case");
    }
    let fills = dm_h2c_fills(&io.0.lock().writes);
    if dm_find(&fills, 0x3a).is_none() {
        return TestResult::Fail("8723AE dm dispatch undefined runs hid");
    }
    let mut owner = Owner::bind(&adapter::BtInfo {
        coexistence: true,
        kind: adapter::BT_RTL8723A,
        ant_num: adapter::AntNum::X2,
        ant_isolation: 0,
        radio_shared: 0,
    });
    owner.bt_busy = true;
    owner.bt_info_original = 0x02; // SCO_ESCO bit.
    if narf_scheduler::block_on(owner.coexist_2_ant(
        &io,
        MechInputs {
            wifi,
            linked: true,
            pwdb: 60,
            now_ms: 0,
            a_cut: false,
        },
    )) != Ok(Mech::HidScoEsco)
        || owner.profile_case != Mech::HidScoEsco
    {
        return TestResult::Fail("8723AE dm dispatch sco-esco case");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_dm_dispatch_undefined
);

/// `hal_btc.c` all-off sequences: FW order (ignore, 3a, 2-ant-hid,
/// tra-tdma on B-cut, tdma, dac, hid-info, retry, wlan-act, dec-pwr),
/// SW order (AGC off, BB off, penalty, DAC swing), HW order (table,
/// PTA on); combined is FW then SW then HW.
fn smoke_rtl8723ae_dm_all_off_sequences() -> TestResult {
    use coex::*;
    // A-cut: tra_tdma must NOT appear in the FW sequence.
    let io = fw_fake(false, false, false, false);
    let mut owner = Owner::bind(&coex_bt());
    if narf_scheduler::block_on(owner.all_off_fw(&io, true)).is_err() {
        return TestResult::Fail("8723AE dm all_off_fw error");
    }
    let fills = dm_h2c_fills(&io.0.lock().writes);
    let ids: Vec<u8> = fills.iter().map(|(i, _)| *i).collect();
    if ids
        != [
            0x25, 0x3a, 0x15, 0x26, 0x14, 0x29, 0x24, 0x23, 0x22, 0x11, 0x21,
        ]
    {
        return TestResult::Fail("8723AE dm all_off_fw A-cut ids");
    }
    if dm_find(&fills, 0x25) != Some(&[0x00, 0x00, 0x00][..])
        || dm_find(&fills, 0x22) != Some(&[0x10, 0x00, 0x00][..])
        || dm_find(&fills, 0x11) != Some(&[0x10, 0x00, 0x00][..])
        || dm_find(&fills, 0x23) != Some(&[0x02, 0x00, 0x00][..])
    {
        return TestResult::Fail("8723AE dm all_off_fw payloads");
    }
    // B-cut: tra_tdma 0x33 appears between 2-ant-hid and tdma.
    let io = fw_fake(false, false, false, false);
    let mut owner = Owner::bind(&coex_bt());
    if narf_scheduler::block_on(owner.all_off_fw(&io, false)).is_err() {
        return TestResult::Fail("8723AE dm all_off_fw B-cut error");
    }
    let fills = dm_h2c_fills(&io.0.lock().writes);
    let ids: Vec<u8> = fills.iter().map(|(i, _)| *i).collect();
    if ids
        != [
            0x25, 0x3a, 0x15, 0x33, 0x26, 0x14, 0x29, 0x24, 0x23, 0x22, 0x11, 0x21,
        ]
    {
        return TestResult::Fail("8723AE dm all_off_fw B-cut ids");
    }
    // SW: AGC off table, BB off, penalty BIT(0) set + BIT(2) set
    // (normal), DAC swing 0xc0 at 0x880 top byte.
    let io = fw_fake(false, false, false, false);
    let mut owner = Owner::bind(&coex_bt());
    if owner.all_off_sw(&io).is_err() {
        return TestResult::Fail("8723AE dm all_off_sw error");
    }
    {
        let g = io.0.lock();
        if g.writes[..6]
            != [
                (REG_AGC_TABLE, 0x641c0001, 4),
                (REG_AGC_TABLE, 0x631d0001, 4),
                (REG_AGC_TABLE, 0x621e0001, 4),
                (REG_AGC_TABLE, 0x611f0001, 4),
                (REG_AGC_TABLE, 0x60200001, 4),
                lssi_a(0x12, 0x32000),
            ]
            || !g.writes.contains(&(REG_BB_BACKOFF, BB_BACKOFF_OFF, 4))
            || !g.writes.contains(&(0x4fd, 0x05, 1))
            || !g.writes.contains(&(0x880, 0xc000_0000, 4))
        {
            return TestResult::Fail("8723AE dm all_off_sw writes");
        }
        // No origin captured yet: the LPF resume writes nothing to RF 0x1e.
        if g.writes.iter().any(|w| w.0 == 0x840 && (w.1 >> 20) == 0x1e) {
            return TestResult::Fail("8723AE dm LPF resume before origin");
        }
    }
    // LPF corner: shrink writes RF 0x1e = 0xf0ff7; resume restores the
    // origin captured by mech_init.
    owner.rf_origin_1e = Some(0x0abcd);
    owner.sw_all_off = true;
    let before = io.0.lock().writes.len();
    if owner.set_sw_rf_rx_lpf_corner(&io, true).is_err()
        || owner.sw_all_off
        || owner.set_sw_rf_rx_lpf_corner(&io, false).is_err()
        || io.0.lock().writes[before..] != [lssi_a(0x1e, 0xf0ff7), lssi_a(0x1e, 0x0abcd)]
    {
        return TestResult::Fail("8723AE dm LPF corner RF writes");
    }
    // HW: table 0x5a5aaaaa/0xcc/0x3 + PTA on (Linux's HW all-off
    // leaves PTA enabled).
    let io = fw_fake(false, false, false, false);
    let mut owner = Owner::bind(&coex_bt());
    if owner.all_off_hw(&io).is_err() {
        return TestResult::Fail("8723AE dm all_off_hw error");
    }
    {
        let g = io.0.lock();
        if !g.writes.contains(&(0x6c0, 0x5a5a_aaaa, 4))
            || !g.writes.contains(&(0x6c8, 0xcc, 4))
            || !g.writes.contains(&(0x6cc, 0x03, 1))
            || !g.writes.contains(&(0x40, 0x20, 1))
        {
            return TestResult::Fail("8723AE dm all_off_hw writes");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_dm_all_off_sequences
);

/// `hal_btc.c` `set_bt_dm` gates: identical btdm → zero writes;
/// hold → only ignore-wlan-act; all-off btdm → combined sequences;
/// tra_tdma skipped on A-cut, sent on B-cut (setter level).
fn smoke_rtl8723ae_dm_set_bt_dm_gates() -> TestResult {
    use coex::*;
    use dm::*;
    let io = fw_fake(false, false, false, false);
    let mut owner = Owner::bind(&coex_bt());
    // First apply writes; second identical apply writes nothing.
    if narf_scheduler::block_on(owner.set_bt_dm(&io, Btdm::all_off(), false)).is_err() {
        return TestResult::Fail("8723AE dm set_bt_dm first error");
    }
    let before = io.0.lock().writes.len();
    if narf_scheduler::block_on(owner.set_bt_dm(&io, Btdm::all_off(), false)).is_err()
        || io.0.lock().writes.len() != before
    {
        return TestResult::Fail("8723AE dm set_bt_dm dedup");
    }
    // Hold: only the ignore-wlan-act fill.
    let io = fw_fake(false, false, false, false);
    let mut owner = Owner::bind(&coex_bt());
    owner.hold_for_bt_operation = true;
    if narf_scheduler::block_on(owner.set_bt_dm(&io, Btdm::all_off(), false)).is_err() {
        return TestResult::Fail("8723AE dm set_bt_dm hold error");
    }
    let fills = dm_h2c_fills(&io.0.lock().writes);
    if fills.len() != 1 || fills[0].0 != 0x25 || fills[0].1[0] != 0x01 {
        return TestResult::Fail("8723AE dm set_bt_dm hold only ignore");
    }
    // All-off btdm: combined sequences (FW first: ignore 0x25 [0x00];
    // HW last: PTA on).
    let io = fw_fake(false, false, false, false);
    let mut owner = Owner::bind(&coex_bt());
    if narf_scheduler::block_on(owner.set_bt_dm(&io, Btdm::all_off(), false)).is_err() {
        return TestResult::Fail("8723AE dm set_bt_dm all_off error");
    }
    let fills = dm_h2c_fills(&io.0.lock().writes);
    if fills.is_empty() || fills[0].0 != 0x25 || fills[0].1[0] != 0x00 {
        return TestResult::Fail("8723AE dm set_bt_dm all_off fw first");
    }
    if !io.0.lock().writes.contains(&(0x40, 0x20, 1)) {
        return TestResult::Fail("8723AE dm set_bt_dm all_off hw last");
    }
    // Tra-TDMA setter gate.
    let io = fw_fake(false, false, false, false);
    let mut owner = Owner::bind(&coex_bt());
    if narf_scheduler::block_on(owner.set_fw_tra_tdma_ctrl(
        &io,
        true,
        TDMA_2ANT,
        TDMA_NAV_OFF,
        true,
    ))
    .is_err()
        || !io.0.lock().writes.is_empty()
    {
        return TestResult::Fail("8723AE dm tra_tdma A-cut silent");
    }
    if narf_scheduler::block_on(owner.set_fw_tra_tdma_ctrl(
        &io,
        true,
        TDMA_1ANT,
        TDMA_NAV_ON,
        false,
    ))
    .is_err()
    {
        return TestResult::Fail("8723AE dm tra_tdma B-cut error");
    }
    let fills = dm_h2c_fills(&io.0.lock().writes);
    if dm_find(&fills, 0x33) != Some(&[0x03, 0x01, 0x00][..]) {
        return TestResult::Fail("8723AE dm tra_tdma B-cut fill");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_dm_set_bt_dm_gates
);

/// `hal_btc.c` run gates + notifies: no coexistence → ran=false,
/// zero writes; 1-ant → ran=true, action None, no mechanism writes;
/// media-status bytes; turn-off-before-LPS zero + combined.
fn smoke_rtl8723ae_dm_run_gates_and_notifies() -> TestResult {
    use coex::*;
    use dm::*;
    // Fail-closed: coexistence off → nothing runs, nothing written.
    let io = fw_fake(false, false, false, false);
    let mut owner = Owner::bind(&adapter::BtInfo {
        coexistence: false,
        kind: adapter::BT_RTL8723A,
        ant_num: adapter::AntNum::X2,
        ant_isolation: 0,
        radio_shared: 0,
    });
    let wifi = WifiTraffic {
        busy: true,
        tx_busy: true,
        rx_busy: false,
        legacy: false,
        bw40: true,
        bt30: false,
    };
    let outcome = narf_scheduler::block_on(owner.run_mechanism(
        &io,
        MechInputs {
            wifi,
            linked: true,
            pwdb: 60,
            now_ms: 0,
            a_cut: false,
        },
    ));
    if outcome
        != Ok(RunOutcome {
            ran: false,
            action: Mech::None,
        })
        || !io.0.lock().writes.is_empty()
    {
        return TestResult::Fail("8723AE dm run fail-closed");
    }
    // 1-ant: runs, action None, and no set_bt_dm writes — only the
    // query (0x38), init (0x76e/0x778/0x40), and post-watchdog 0x76e.
    let io = fw_fake(false, false, false, false);
    let mut owner = Owner::bind(&coex_bt()); // X1.
    let outcome = narf_scheduler::block_on(owner.run_mechanism(
        &io,
        MechInputs {
            wifi,
            linked: false,
            pwdb: 60,
            now_ms: 0,
            a_cut: false,
        },
    ));
    if outcome
        != Ok(RunOutcome {
            ran: true,
            action: Mech::None,
        })
    {
        return TestResult::Fail("8723AE dm run 1-ant outcome");
    }
    let fills = dm_h2c_fills(&io.0.lock().writes);
    if fills.len() != 1 || fills[0].0 != 0x38 {
        return TestResult::Fail("8723AE dm run 1-ant only query");
    }
    if !io.0.lock().writes.contains(&(0x76e, 0x0c, 1)) {
        return TestResult::Fail("8723AE dm run 1-ant post-watchdog write");
    }
    // Media status: connected + linked + HT40 → [1, ch, 0x30].
    let io = fw_fake(false, false, false, false);
    let mut owner = Owner::bind(&coex_bt());
    if narf_scheduler::block_on(owner.media_status(&io, true, true, 6, true)).is_err() {
        return TestResult::Fail("8723AE dm media error");
    }
    let fills = dm_h2c_fills(&io.0.lock().writes);
    if dm_find(&fills, 0x19) != Some(&[0x01, 0x06, 0x30][..]) {
        return TestResult::Fail("8723AE dm media bytes");
    }
    // Disconnected → [0, 0, 0x20].
    let io = fw_fake(false, false, false, false);
    let mut owner = Owner::bind(&coex_bt());
    if narf_scheduler::block_on(owner.media_status(&io, false, false, 0, false)).is_err() {
        return TestResult::Fail("8723AE dm media disc error");
    }
    let fills = dm_h2c_fills(&io.0.lock().writes);
    if dm_find(&fills, 0x19) != Some(&[0x00, 0x00, 0x20][..]) {
        return TestResult::Fail("8723AE dm media disc bytes");
    }
    // Turn-off-before-LPS: inactive PS + coexistence → zeroed state +
    // combined all-off (FW ignore first, HW PTA on present).
    let io = fw_fake(false, false, false, false);
    let mut owner = Owner::bind(&coex_bt());
    owner.cstate = 0xffff_ffff;
    if narf_scheduler::block_on(owner.turn_off_before_lps(&io, false, true)).is_err()
        || owner.cstate != 0
    {
        return TestResult::Fail("8723AE dm turn_off_lps state");
    }
    let fills = dm_h2c_fills(&io.0.lock().writes);
    if fills.is_empty() || fills[0].0 != 0x25 {
        return TestResult::Fail("8723AE dm turn_off_lps fw first");
    }
    if !io.0.lock().writes.contains(&(0x40, 0x20, 1)) {
        return TestResult::Fail("8723AE dm turn_off_lps hw last");
    }
    // PS not inactive → nothing written, state untouched.
    let io = fw_fake(false, false, false, false);
    let mut owner = Owner::bind(&coex_bt());
    if narf_scheduler::block_on(owner.turn_off_before_lps(&io, false, false)).is_err()
        || !io.0.lock().writes.is_empty()
    {
        return TestResult::Fail("8723AE dm turn_off_lps inactive silent");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_dm_run_gates_and_notifies
);

// ── composed PCI startup admission ────────────────────────────────────────

/// `power::Io` over the firmware fake: the card-enable flow's `0x05[0]`
/// state-transition bit completes in hardware before its next read (as the
/// `power_tests` model does), and `0x06[1]` is the power-ready bit the
/// `0x06` poll waits on. The clear is a model of the hardware transition,
/// not a driver write.
struct PwrIo(FwFake);
impl crate::rtlwifi::power::Io for PwrIo {
    fn read8(&self, offset: u16) -> Result<u8, crate::rtlwifi::power::PwrSeqError> {
        let value = self
            .0
            .read8(offset)
            .map_err(|_| crate::rtlwifi::power::PwrSeqError::Access)?;
        if offset == 5 && value & 1 != 0 {
            self.0 .0.lock().regs[5] &= !1;
        }
        Ok(value)
    }
    fn write8(&self, offset: u16, value: u8) -> Result<(), crate::rtlwifi::power::PwrSeqError> {
        self.0
            .write8(offset, value)
            .map_err(|_| crate::rtlwifi::power::PwrSeqError::Access)
    }
}

/// The probe admission gate for `0x8723`, composed end to end against one
/// target fake: the measured chip version qualifies, the adapter facts
/// decode from the provisioned map with the factory MAC, the exact
/// `rtl8723A_card_enable_flow` runs (`REG_RSV_CTRL = 0` prefix), the
/// firmware owner runs `run_8723ae` (post-flow power segment, CR gates
/// cleared, `rtl8723fw.bin` paged download to `Ready`), and the C2H
/// mailbox delivers a BT-info event the coexistence owner ingests. A test
/// chip, a part without `BT_FUNC`, an unprovisioned map and a wrong-signature
/// image are all refused cleanly, the test chip before any register write.
///
/// Fixture-validated only; nothing here ran on silicon, and the PCI probe
/// path itself (BAR mapping, EFUSE read, `bring_up` retention) is not
/// reachable from this rig — the smoke pins the exact qualification probe
/// re-derives from the same registers and map.
fn smoke_rtl8723ae_pci_startup_admission() -> TestResult {
    use crate::rtlwifi::firmware_transport::{Owner as TransportOwner, Stage};
    use crate::rtlwifi::power::power_on_with;
    use adapter::*;
    // One fake for the whole bring-up, as probe sees one BAR2.
    let io = fw_fake(true, true, true, true);
    {
        let mut g = io.0.lock();
        // Power-ready for the card-enable flow's `0x06[1]` poll.
        g.regs[6] = 0x02;
        // EFUSE autoload OK and the BT strap, as probe reads them.
        g.regs[usize::from(REG_9346CR)] = CR9346_AUTOLOAD_OK;
        g.regs[usize::from(version::REG_MULTI_FUNC_CTRL)
            ..usize::from(version::REG_MULTI_FUNC_CTRL) + 4]
            .copy_from_slice(&MULTI_BT_FUNC_EN.to_le_bytes());
    }
    // (1) Version, read through the fake as probe reads MMIO.
    let sys_cfg = match io.read32(version::REG_SYS_CFG) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("8723AE admission SYS_CFG unreadable"),
    };
    let gpio = match io.read32(version::REG_GPIO_OUTSTS) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("8723AE admission GPIO_OUTSTS unreadable"),
    };
    let multi = match io.read32(version::REG_MULTI_FUNC_CTRL) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("8723AE admission MULTI_FUNC_CTRL unreadable"),
    };
    let cr9346 = match io.read8(REG_9346CR) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("8723AE admission 9346CR unreadable"),
    };
    let qualified = match version::Version::from_registers(sys_cfg, || gpio, || multi) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("8723AE admission version refused"),
    };
    if !qualified.is_umc_a_cut()
        || qualified.firmware() != version::FW_NORMAL
        || qualified.polarity() != version::Polarity::LowActive
    {
        return TestResult::Fail("8723AE admission A-cut version / rtl8723fw.bin");
    }
    // (2) Adapter facts from the provisioned map; the EFUSE MAC is the
    // factory identity probe's `read_factory` returns.
    let map = provisioned();
    let facts = match Adapter::from_hardware(qualified, cr9346, multi, &map) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("8723AE admission adapter facts refused"),
    };
    if facts.mac != [0x00, 0xe0, 0x4c, 0x87, 0x23, 0xae]
        || !facts.bt.coexistence
        || facts.bt.kind != BT_RTL8723A
    {
        return TestResult::Fail("8723AE admission adapter facts / BT strap");
    }
    // (3) Pwrseq: probe's power-on for 0x8723 is the exact
    // `rtl8723A_card_enable_flow` after the `REG_RSV_CTRL = 0` prefix.
    if power_on_with(&PwrIo(io.clone()), super::super::regs::RTL_DEV_8723AE).is_err() {
        return TestResult::Fail("8723AE admission card enable flow failed");
    }
    {
        let g = io.0.lock();
        if g.regs[0x301] != 0
            || g.regs[0x1c] != 0
            || crate::rtlwifi::power::RTL8723AE_PWR_ON.len() != 10
        {
            return TestResult::Fail("8723AE admission enable prefix / flow rows");
        }
    }
    // (4) Power segment + firmware download through the production
    // transport: `run_8723ae` (6 s bound) on the A-cut image.
    let owner = TransportOwner::new(io.clone(), super::super::regs::RTL_DEV_8723AE);
    let bytes = image(0x2d6e);
    let info = match narf_scheduler::block_on(owner.initialize(&bytes)) {
        Ok(info) => info,
        Err(_) => return TestResult::Fail("8723AE admission firmware download failed"),
    };
    if info.version != 21 || info.payload != 0x2d6e || owner.status().stage != Stage::Ready {
        return TestResult::Fail("8723AE admission firmware info / Ready stage");
    }
    {
        let g = io.0.lock();
        // The post-flow ePHY round landed and the paged image reassembles.
        if g.regs[0x302] & 0x10 == 0
            || g.regs[0x369] & 0x80 == 0
            || g.pages.len() != 3
            || g.pages[0][..] != bytes[fw::HEADER..fw::HEADER + fw::PAGE]
            || g.pages[1][..] != bytes[fw::HEADER + fw::PAGE..fw::HEADER + 2 * fw::PAGE]
            || g.pages[2][..0x2d6e - 2 * fw::PAGE] != bytes[fw::HEADER + 2 * fw::PAGE..]
            || g.pages[2][0x2d6e - 2 * fw::PAGE..] != [0, 0]
        {
            return TestResult::Fail("8723AE admission post-flow / paged image");
        }
    }
    // (5) C2H: a firmware-closed BT-info event drains from the mailbox and
    // the coexistence owner bound to the adapter facts ingests it.
    {
        let mut g = io.0.lock();
        g.regs[usize::from(c2h::REG_C2HEVT_MSG_NORMAL)] = 0x2c;
        g.regs[usize::from(c2h::REG_C2HEVT_MSG_NORMAL) + 1] = 7;
        g.regs[usize::from(c2h::REG_C2HEVT_CLOSE)] = c2h::C2H_EVT_FW_CLOSE;
        g.regs[usize::from(c2h::REG_C2HEVT_MSG_NORMAL) + 2] = 0x05;
        g.regs[usize::from(c2h::REG_C2HEVT_MSG_NORMAL) + 3] = 0x03;
    }
    let event = match c2h::drain(&io) {
        Ok(c2h::Outcome::Dispatched(c2h::Event::BtInfo(info))) => info,
        _ => return TestResult::Fail("8723AE admission C2H BT info not dispatched"),
    };
    if !io.0.lock().writes.contains(&(c2h::REG_C2HEVT_CLOSE, 0, 1)) {
        return TestResult::Fail("8723AE admission C2H close write missing");
    }
    let mut coex = coex::Owner::bind(&facts.bt);
    if coex.pattern() != crate::rtlwifi::btcoex::TdmaPattern::WifiOnly {
        return TestResult::Fail("8723AE admission coex initial pattern");
    }
    coex.ingest(&event);
    if coex.periodical() != Some(crate::rtlwifi::btcoex::TdmaPattern::BtOnly) {
        return TestResult::Fail("8723AE admission coex connected periodical");
    }
    // Refusals: a second start, a test chip, a part without BT_FUNC, an
    // unprovisioned map and a wrong-signature image.
    if narf_scheduler::block_on(owner.initialize(&bytes)) != Err(FwError::AlreadyStarted) {
        return TestResult::Fail("8723AE admission second start admitted");
    }
    if version::Version::from_registers(
        version::TRP_VAUX_EN | version::BT_FUNC | version::VENDOR_ID,
        || 0,
        || 0,
    ) != Err(version::Error::TestChip)
        || version::Version::from_registers(version::VENDOR_ID, || 0, || 0)
            != Err(version::Error::NotSeries)
    {
        return TestResult::Fail("8723AE admission test chip / non-series version");
    }
    let test_chip = fw_fake(true, true, true, true);
    {
        let mut g = test_chip.0.lock();
        g.regs[0xf0..0xf4].copy_from_slice(
            &(version::TRP_VAUX_EN | version::BT_FUNC | version::VENDOR_ID).to_le_bytes(),
        );
    }
    let refused = TransportOwner::new(test_chip.clone(), super::super::regs::RTL_DEV_8723AE);
    if narf_scheduler::block_on(refused.initialize(&bytes)) != Err(FwError::Unsupported)
        || !test_chip.0.lock().writes.is_empty()
        || refused.status().stage != Stage::Failed
    {
        return TestResult::Fail("8723AE admission test chip ran the runtime");
    }
    let mut bad = map.clone();
    bad[0] = 0;
    if Adapter::from_hardware(qualified, cr9346, multi, &bad).is_ok()
        || Adapter::from_hardware(qualified, 0, multi, &map).is_ok()
    {
        return TestResult::Fail("8723AE admission unprovisioned map admitted");
    }
    let mut wrong = image(0x100);
    wrong[0] = 0x01;
    wrong[1] = 0x53;
    let bad_image = TransportOwner::new(
        fw_fake(true, true, false, true),
        super::super::regs::RTL_DEV_8723AE,
    );
    if narf_scheduler::block_on(bad_image.initialize(&wrong)) != Err(FwError::Image) {
        return TestResult::Fail("8723AE admission wrong-signature image admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae",
    smoke_rtl8723ae_pci_startup_admission
);
