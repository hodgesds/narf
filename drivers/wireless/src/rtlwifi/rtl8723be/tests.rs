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

// ── descriptors ───────────────────────────────────────────────────────────

/// `rtl8723be_tx_fill_desc` field placement (single buffer, first+last),
/// including the 8723BE-specific choices that differ from RTL8821AE.
fn smoke_rtl8723be_tx_rx_descriptor_layout() -> TestResult {
    use trx::*;
    let p = TxParams {
        pkt_size: 1500,
        queue_sel: QSLT_BE,
        macid: 1,
        rate_id: 4,
        hw_rate: DESC_RATEMCS7,
        use_driver_rate: false,
        use_shortgi: true,
        use_shortpreamble: false,
        bw_40: true,
        packet_bw_40: true,
        ampdu: true,
        ampdu_density: 5,
        qos_data: true,
        seq: 0x123,
        rts_enable: true,
        rts_rate: 0x08,
        rts_sc: 2,
        rts_use_shortpreamble: true,
        buffer_len: 1500,
        buffer_addr: 0x1234_5678,
        ..TxParams::default()
    };
    let d = TxDesc::fill(&p);
    if d.pkt_size() != 1500
        || d.queue_sel() != QSLT_BE
        || d.macid() != 1
        || d.tx_rate() != DESC_RATEMCS7
        || d.data_bw() != 1
        || d.sub_carrier() != 3
        || d.own()
        || d.dw[0] >> 16 & 0xff != HWDESC_HEADER_LEN
        || d.dw[0] & (3 << 26) != 3 << 26
        || (d.dw[3] >> 17) & 0x1f != 0x14
        || d.dw[2] & (1 << 12) == 0
        || (d.dw[2] >> 20) & 7 != 5
        || d.dw[5] & (1 << 4) == 0
        || d.dw[3] & (1 << 12) == 0
        || (d.dw[4] >> 24) & 0x1f != 0x08
        || (d.dw[5] >> 13) & 0xf != 2
        || d.dw[5] & (1 << 12) == 0
        || (d.dw[9] >> 12) & 0xfff != 0x123
        || d.dw[10] != 0x1234_5678
        || d.dw[7] & 0xffff != 1500
        || (d.dw[1] >> 16) & 0x1f != 4
        || d.dw[8] & (1 << 15) != 0
    {
        return TestResult::Fail("8723BE TX descriptor fields");
    }
    // Short GI only above MCS0; 20 MHz packet on a 40 MHz BSS uses
    // cur_40_prime_sc; non-QoS sets HWSEQ_EN.
    let legacy = TxDesc::fill(&TxParams {
        hw_rate: DESC_RATEMCS0,
        use_shortgi: true,
        bw_40: true,
        cur_40_prime_sc: 1,
        ..TxParams::default()
    });
    if legacy.dw[5] & (1 << 4) != 0
        || legacy.data_bw() != 0
        || legacy.sub_carrier() != 1
        || legacy.dw[8] & (1 << 15) == 0
    {
        return TestResult::Fail("short GI threshold / prime SC / HWSEQ_EN");
    }
    let cmd = TxDesc::fill_cmd(64, 0xabc0);
    if cmd.queue_sel() != QSLT_BEACON
        || cmd.tx_rate() != DESC_RATE1M
        || cmd.pkt_size() != 64
        || cmd.dw[3] & (1 << 8) == 0
        || cmd.dw[10] != 0xabc0
    {
        return TestResult::Fail("rtl8723be_tx_fill_cmddesc");
    }
    let mut e = TxDesc::default();
    e.set_next(0xdead_0000);
    if e.dw[12] != 0xdead_0000 || NEXT_DESC_BYTE != 48 {
        return TestResult::Fail("next_desc_address at dword 12");
    }
    let mut rx = [0u32; 8];
    rx_arm(&mut rx, 0x4000, 0x2000, true);
    if RxStatus::parse(&rx).is_some() || rx[6] != 0x4000 || rx[0] & (1 << 30) == 0 {
        return TestResult::Fail("RX arm / OWN");
    }
    rx[0] = 100 | (1 << 16) | (2 << 24) | (1 << 26);
    rx[1] = 3 | (1 << 15);
    rx[2] = 1 << 28;
    rx[3] = 0x0c | (1 << 6);
    rx[4] = (1 << 4) | 1;
    rx[5] = 0x55;
    match RxStatus::parse(&rx) {
        Some(s)
            if s.length == 100
                && s.drvinfo_size == 8
                && s.shift == 2
                && s.physt
                && s.decrypted
                && s.macid == 3
                && s.ampdu
                && s.c2h
                && s.rate == 0x0c
                && s.is_ht
                && s.bw == 1
                && s.short_preamble
                && s.tsfl == 0x55
                && s.payload_offset() == 32 + 8 + 2
                && !s.is_cck() => {}
        _ => return TestResult::Fail("rtl8723be_rx_query_desc fields"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_tx_rx_descriptor_layout
);

// ── LLT and MAC ───────────────────────────────────────────────────────────

struct LltView<'a>(&'a FwFake);
impl llt::Regs for LltView<'_> {
    fn read32(&self, reg: u16) -> Result<u32, FwError> {
        // The modelled LLT engine completes each write at once.
        Ok(self.0.read32(reg)? & !(3 << 30))
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
}

/// `_rtl8723be_llt_table_init`: boundaries, PBP 0x31, 256 links, RQPN last.
fn smoke_rtl8723be_llt_table() -> TestResult {
    let io = fw_fake(true, true, false);
    if llt::init(&LltView(&io)).is_err() {
        return TestResult::Fail("8723BE LLT init failed");
    }
    let g = io.0.lock();
    let links: Vec<u32> = g
        .writes
        .iter()
        .filter(|w| w.0 == llt::REG_LLT_INIT)
        .map(|w| w.1)
        .collect();
    let want: Vec<u32> = llt::links()
        .map(|(a, n)| crate::rtlwifi::rtl8821ae::llt::llt_word(a, n))
        .collect();
    let head: Vec<(u16, u32, u8)> = g.writes.iter().copied().take(7).collect();
    let tail: Vec<(u16, u32, u8)> = g.writes.iter().rev().take(2).copied().collect();
    if links.len() != 256
        || links != want
        || want[243] != crate::rtlwifi::rtl8821ae::llt::llt_word(243, 244)
        || want[244] != crate::rtlwifi::rtl8821ae::llt::llt_word(244, 0xff)
        || want[255] != crate::rtlwifi::rtl8821ae::llt::llt_word(255, 245)
        || head[..]
            != [
                (llt::REG_TRXFF_BNDY, 0x27ff_00f5, 4),
                (llt::REG_TDECTRL + 1, 245, 1),
                (llt::REG_TXPKTBUF_BCNQ_BDNY, 245, 1),
                (llt::REG_TXPKTBUF_MGQ_BDNY, 245, 1),
                (llt::REG_BCNQ1_BDNY, 245, 1),
                (llt::REG_PBP, 0x31, 1),
                (llt::REG_RX_DRVINFO_SZ, 4, 1),
            ]
        || tail[..] != [(llt::REG_RQPN_NPQ, 0, 1), (llt::REG_RQPN, 0x80e4_0808, 4)]
    {
        return TestResult::Fail("_rtl8723be_llt_table_init order / values");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_llt_table
);

/// `_rtl8723be_init_mac` segments, `_rtl8723be_hw_configure` and the RCR
/// trim: the exact values and the `rtl_set_bbreg` board RMWs.
fn smoke_rtl8723be_init_mac_and_hw_configure() -> TestResult {
    let io = fw_fake(true, true, false);
    {
        let mut g = io.0.lock();
        g.regs[usize::from(mac::REG_SYS_CFG) + 3] = 1;
        g.regs[usize::from(mac::REG_GPIO_MUXCFG) + 1] = 0xff;
        g.regs[usize::from(mac::REG_TRXDMA_CTRL)] = 0x0a;
        g.regs[usize::from(mac::REG_RXDMA_CONTROL)] = 0x04;
        g.regs[0x4c..0x50].copy_from_slice(&0x0180_0000u32.to_le_bytes());
        g.regs[0x40] = 0x10;
    }
    let ok = mac::init_mac_pre_cr(&io).is_ok()
        && narf_scheduler::block_on(mac::init_mac_clocks(&io)).is_ok()
        && mac::init_mac_post_llt(&io).is_ok()
        && mac::hw_configure(&io).is_ok();
    if !ok {
        return TestResult::Fail("8723BE MAC init failed");
    }
    let g = io.0.lock();
    let r32 =
        |r: usize| u32::from_le_bytes([g.regs[r], g.regs[r + 1], g.regs[r + 2], g.regs[r + 3]]);
    if g.regs[usize::from(mac::REG_MULTI_FUNC_CTRL)] & 8 == 0
        || g.regs[usize::from(mac::REG_APS_FSMCO)] & 0x10 == 0
        || g.regs[usize::from(mac::REG_HWSEQ_CTRL)] != 0x7f
        || g.regs[0x7c] & 0x40 == 0
        || g.regs[usize::from(mac::REG_SYS_CLKR)] & 8 == 0
        || g.regs[usize::from(mac::REG_GPIO_MUXCFG) + 1] != 0xef
        || r32(usize::from(mac::REG_HISR)) != u32::MAX
        || g.regs[usize::from(mac::REG_FWIMR) + 3] & 0x40 == 0
        || g.regs[usize::from(mac::REG_TRXDMA_CTRL)..usize::from(mac::REG_TRXDMA_CTRL) + 2]
            != 0xf5bbu16.to_le_bytes()
        || r32(usize::from(mac::REG_RCR)) != mac::RCR
        || r32(usize::from(mac::REG_TCR)) != mac::TCR
        || g.regs[usize::from(mac::REG_PCIE_CTRL_REG) + 3] != 0x77
        || g.regs[usize::from(mac::REG_SECONDARY_CCA_CTRL)] != 3
        || r32(0x4c) & (3 << 23) != 2 << 23
        || g.regs[0x40] & 0x18 != 0x08
        || g.regs[0x944] & 3 != 3
        || g.regs[0x930] != 0x77
        || r32(0x38) & (1 << 11) == 0
        || g.regs[usize::from(mac::REG_RXDMA_CONTROL)] & 4 != 0
        || g.regs[0x550] != 0x1d
        || r32(0x460) != 0x0308_6666
        || g.regs[0x4ca] != 0x1f
        || r32(0x448) != 0xffff_f000
    {
        return TestResult::Fail("_rtl8723be_init_mac / hw_configure values");
    }
    // No REG_CR write: the owner keeps the packet gates.
    if g.writes.iter().any(|w| w.0 == 0x100 || w.0 == 0x101) {
        return TestResult::Fail("REG_CR written by the MAC segments");
    }
    drop(g);
    match mac::trim_receive_config(&io) {
        Ok(rcr) if rcr == mac::RCR & !mac::RCR_ACRC32_AICV => {}
        _ => return TestResult::Fail("RCR ACRC32/AICV trim"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_init_mac_and_hw_configure
);

// ── tables / PHY ──────────────────────────────────────────────────────────

/// `table.c` geometry: pair counts, first/last rows and the conditional
/// rows (`0x80002000` / `0x90003000` / `0x90004000` / ELSE / ENDIF).
fn smoke_rtl8723be_tables_verbatim_geometry() -> TestResult {
    use tables::*;
    let cond = |t: &[[u32; 2]]| t.iter().filter(|r| r[0] & 0x8000_0000 != 0).count();
    if PHY_REG.len() != 193
        || PHY_REG[0] != [0x800, 0x8004_0000]
        || PHY_REG[192] != [0x800, 0x8304_0000]
        || PHY_REG_PG.len() != 6
        || PHY_REG_PG[0] != [0, 0, 0, 0x0e08, 0x0000_ff00, 0x0000_3800]
        || PHY_REG_PG[5] != [0, 0, 0, 0x0e14, 0xffff_ffff, 0x2630_3436]
        || RADIOA.len() != 136
        || RADIOA[0] != [0x000, 0x0001_0000]
        || MAC.len() != 103
        || AGCTAB.len() != 131
        || cond(&PHY_REG) != 0
        || cond(&MAC) != 0
        || cond(&AGCTAB) != 0
        || cond(&RADIOA) != 10
        || !RADIOA.contains(&[0x8000_2000, 0])
        || !RADIOA.contains(&[0x4000_0000, 0])
    {
        return TestResult::Fail("8723BE table geometry differs from table.c");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_tables_verbatim_geometry
);

/// `_rtl8723be_check_positive` over the package-type IF / ELSE-IF / ELSE
/// blocks of RADIOA: TFBGA90 (2), TFBGA80 (3) and TFBGA79 (4) select the
/// `0x6F10E` rows, QFN68 / default the ELSE `0x6B04E` rows; the BT board
/// bit and the cut do not take part (cut/board bits are DONTCARE there).
fn smoke_rtl8723be_check_positive_package_selection() -> TestResult {
    use phy::{select, Condition};
    let rf51 = |package_type: u8, board_type: u8| -> Vec<u32> {
        let c = Condition {
            cut: 1,
            package_type,
            board_type,
        };
        select(&tables::RADIOA, &c)
            .filter(|&(a, _)| a == 0x51)
            .map(|(_, d)| d)
            .collect()
    };
    for p in [2, 3, 4] {
        if rf51(p, 0) != [0x6f10e] || rf51(p, 4) != [0x6f10e] {
            return TestResult::Fail("TFBGA package branch");
        }
    }
    for p in [0, 1] {
        if rf51(p, 4) != [0x6b04e] {
            return TestResult::Fail("ELSE branch for QFN68 / default");
        }
    }
    let c = Condition {
        cut: 0,
        package_type: 0,
        board_type: 0,
    };
    // Rows after ENDIF are always selected; condition rows never are.
    let rows: Vec<_> = select(&tables::RADIOA, &c).collect();
    if rows.iter().any(|&(a, _)| a & 0xc000_0000 != 0)
        || !rows.contains(&(0x53, 0))
        || !rows.contains(&(0x73, 0))
        || rows.len() != 136 - 10 - 6 - 3 * 2 * 2
    {
        return TestResult::Fail("8723BE conditional walk");
    }
    // cut / package value checks in cond1[27:24] / [15:12].
    let c = Condition {
        cut: 2,
        package_type: 3,
        board_type: 0,
    };
    if c.positive(0x8100_0000, 0)
        || !c.positive(0x8200_0000, 0)
        || c.positive(0x8000_2000, 0)
        || !c.positive(0x8000_3000, 0)
        || !c.positive(0x8000_0100, 0)
        || c.positive(0x8000_0200, 0)
    {
        return TestResult::Fail("check_positive value / interface checks");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_check_positive_package_selection
);

/// `rtl8723be_hw_init` tail: post-LLT segment, MAC rows + `0x4ca = 0x0b`,
/// RCR trim, BB enable writes, the `0x948` BT antenna write by
/// `single_ant_path`, PHY_REG / AGC dword writes, crystal cap, RF6052 3-wire
/// writes (`(addr << 20) | data` on `0x840`) with the HP extra row, the
/// `RF_CHNLBW` reads, hw_configure, CAM reset and the station address.
fn smoke_rtl8723be_mac_bb_rf_config() -> TestResult {
    let v = match Version::from_registers(version::CHIP_8723B, 0x1000) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("version"),
    };
    let mut map = provisioned();
    map[0xc3] = 0x00; // ANT_X2, ANT_MAIN
    let Ok(mut a) = adapter::Adapter::from_hardware(v, adapter::CR9346_AUTOLOAD_OK, 0, &map, 5)
    else {
        return TestResult::Fail("adapter");
    };
    for hp in [false, true] {
        if hp {
            a.oem = adapter::Oem::Hp;
        }
        let io = fw_fake(true, true, false);
        let radio = match narf_scheduler::block_on(init::configure(&io, &a)) {
            Ok(r) => r,
            Err(_) => return TestResult::Fail("8723BE configure failed"),
        };
        let g = io.0.lock();
        let w = |row: (u16, u32, u8)| g.writes.iter().position(|x| *x == row);
        let rf = |addr: u32, data: u32| w((0x840, (addr << 20) | data, 4));
        let mac0 = tables::MAC[0];
        let phy0 = tables::PHY_REG[0];
        let agc0 = tables::AGCTAB[0];
        let (Some(m0), Some(mac_tail), Some(s948), Some(p0), Some(a0), Some(r0)) = (
            w((mac0[0] as u16, mac0[1] & 0xff, 1)),
            w((0x4ca, 0x0b, 1)),
            w((0x948, 0x280, 4)),
            w((phy0[0] as u16, phy0[1], 4)),
            w((agc0[0] as u16, agc0[1], 4)),
            rf(0x000, 0x1_0000),
        ) else {
            return TestResult::Fail("8723BE PHY rows missing");
        };
        let cap = 0x22u32 | (0x22 << 6);
        let r32 =
            |r: usize| u32::from_le_bytes([g.regs[r], g.regs[r + 1], g.regs[r + 2], g.regs[r + 3]]);
        if !(m0 < mac_tail && mac_tail < s948 && s948 < p0 && p0 < a0 && a0 < r0)
            || rf(0x51, 0x6f10e).is_none()
            || rf(0x51, 0x6b04e).is_some()
            || rf(0x52, 0x7e4bd).is_some() != hp
            || g.regs[0x1f] != 0x07
            || g.regs[0x02] != 0xe3
            || g.regs[0x25] != 0x80
            || r32(0x4c) & (1 << 23) == 0
            || (r32(0x2c) >> 12) & 0xfff != cap
            || r32(0x670) != 0xc000_0000
            || g.regs[0x610..0x616] != [0x00, 0xe0, 0x4c, 0x87, 0x23, 0xbe]
            || radio.receive_config != mac::RCR & !mac::RCR_ACRC32_AICV
            || radio.chnlval != [0x0c00, 0]
        {
            return TestResult::Fail("8723BE MAC/BB/RF configuration values");
        }
    }
    // ANT_AUX moves the antenna to BT with 0x948 = 0.
    map[0xc3] = 0x40;
    let Ok(aux) = adapter::Adapter::from_hardware(v, adapter::CR9346_AUTOLOAD_OK, 0, &map, 5)
    else {
        return TestResult::Fail("adapter");
    };
    let io = fw_fake(true, true, false);
    if narf_scheduler::block_on(init::configure(&io, &aux)).is_err()
        || !io.0.lock().writes.contains(&(0x948, 0, 4))
    {
        return TestResult::Fail("8723BE ANT_AUX 0x948 write");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_mac_bb_rf_config
);
