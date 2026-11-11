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

pub(crate) fn provisioned() -> Vec<u8> {
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
    // Synthetic path-A power area (not any board's values): six CCK
    // bases, five BW40 bases, then bw20/ofdm diff 0xf2 (-1 / +2).
    map[0x10..0x1c].copy_from_slice(&[
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0xf2,
    ]);
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
    let Ok(efuse) = txpower::Efuse::from_logical(&map) else {
        return TestResult::Fail("power area");
    };
    for hp in [false, true] {
        if hp {
            a.oem = adapter::Oem::Hp;
        }
        let io = fw_fake(true, true, false);
        let mut coex = coex::Owner::bind(crate::rtlwifi::btcoex::btc::HwPg::rtl8723be(&a));
        let radio = match narf_scheduler::block_on(init::configure(&io, &a, efuse, &mut coex)) {
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
            // `rtl8723be_phy_bb_config` sets 0x4c[23]; the later
            // `rtl8723be_bt_hw_init` `set_ant_path` clears it again.
            || !g.writes.iter().any(|x| x.0 == 0x4c && x.2 == 4 && x.1 & (1 << 23) != 0)
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
    let mut coex = coex::Owner::bind(crate::rtlwifi::btcoex::btc::HwPg::rtl8723be(&aux));
    if narf_scheduler::block_on(init::configure(&io, &aux, efuse, &mut coex)).is_err()
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

/// `_rtl8723be_phy_set_rfpath_switch`, `_rtl8723be_phy_lc_calibrate(hw,
/// false)` (TX-pause and continuous-TX branches), the 20/40 MHz
/// `rtl8723be_phy_set_bw_mode_callback` + RF6052 bandwidth and the
/// `CMDID_RF_WRITEREG` channel step.
fn smoke_rtl8723be_rfpath_lck_bandwidth_and_channel() -> TestResult {
    use channel::*;
    let rf = |addr: u32, data: u32| (0x840u16, (addr << 20) | data, 4u8);
    let io = fw_fake(true, true, false);
    let ok =
        set_rfpath_switch(&io, true).is_ok() && narf_scheduler::block_on(lc_calibrate(&io)).is_ok();
    if !ok {
        return TestResult::Fail("rfpath / LCK failed");
    }
    {
        let g = io.0.lock();
        let w = |row: (u16, u32, u8)| g.writes.iter().position(|x| *x == row);
        let (Some(s), Some(p), Some(b0), Some(c18), Some(b1), Some(r)) = (
            w((REG_RFPATH_SWITCH, 1, 4)),
            w((REG_TXPAUSE, 0xff, 1)),
            w(rf(0xb0, 0xdfbe0)),
            w(rf(0x18, 0x8c0a)),
            w(rf(0xb0, 0xdffe0)),
            w((REG_TXPAUSE, 0, 1)),
        ) else {
            return TestResult::Fail("8723BE LCK rows missing");
        };
        if !(s < p && p < b0 && b0 < c18 && c18 < b1 && b1 < r)
            || g.writes.iter().any(|x| x.0 == 0xd03)
        {
            return TestResult::Fail("8723BE LCK order (TX-pause branch)");
        }
    }
    // Continuous TX (0xd03[6:4] set): the RF 0x00 save/restore instead.
    let io = fw_fake(true, true, false);
    io.0.lock().regs[0xd03] = 0x75;
    if narf_scheduler::block_on(lc_calibrate(&io)).is_err() {
        return TestResult::Fail("continuous LCK failed");
    }
    {
        let g = io.0.lock();
        if !g.writes.contains(&(0xd03, 0x05, 1))
            || !g.writes.contains(&rf(0x00, 0x10000))
            || g.writes.last() != Some(&rf(0x00, 0))
            || g.writes.iter().any(|x| x.0 == REG_TXPAUSE)
            || !g.writes.contains(&(0xd03, 0x75, 1))
        {
            return TestResult::Fail("8723BE LCK continuous-TX branch");
        }
    }
    let io = fw_fake(true, true, false);
    {
        let mut g = io.0.lock();
        g.regs[usize::from(REG_RRSR) + 2] = 0xff;
        g.regs[usize::from(REG_BWOPMODE)] = 0;
        g.regs[0xa00] = 0x10;
    }
    let mut chnlval = [0x0c00 | 1, 0];
    let ok = narf_scheduler::block_on(set_bw_mode(
        &io,
        true,
        PRIME_CHNL_OFFSET_LOWER,
        &mut chnlval,
    ))
    .is_ok()
        && chnlval[0] == 0x0400 | 1
        && narf_scheduler::block_on(switch_channel_rf(&io, 6, &mut chnlval)).is_ok()
        && chnlval[0] == 0x0400 | 6
        && narf_scheduler::block_on(switch_channel_rf(&io, 15, &mut chnlval)).is_err();
    if !ok {
        return TestResult::Fail("8723BE 40 MHz / channel");
    }
    {
        let g = io.0.lock();
        let r32 =
            |r: usize| u32::from_le_bytes([g.regs[r], g.regs[r + 1], g.regs[r + 2], g.regs[r + 3]]);
        if g.regs[usize::from(REG_BWOPMODE)] & BW_OPMODE_20MHZ != 0
            || g.regs[usize::from(REG_RRSR) + 2] != 0x90 | (1 << 5)
            || r32(0x800) & 1 != 1
            || r32(0x900) & 1 != 1
            || r32(0xa00) & 0x10 != 0
            || (r32(0xd00) >> 10) & 3 != 1
            || (r32(0x818) >> 26) & 3 != 2
            || !g.writes.contains(&rf(0x18, 0x0401))
            || g.writes.last() != Some(&rf(0x18, 0x0406))
        {
            return TestResult::Fail("8723BE 40 MHz register values");
        }
    }
    let io = fw_fake(true, true, false);
    if narf_scheduler::block_on(set_bw_mode(&io, false, 0, &mut chnlval)).is_err()
        || chnlval[0] != 0x0c06
        || io.0.lock().regs[usize::from(REG_BWOPMODE)] & BW_OPMODE_20MHZ == 0
        || io.0.lock().writes.iter().any(|x| x.0 == REG_RRSR + 2)
    {
        return TestResult::Fail("8723BE 20 MHz");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_rfpath_lck_bandwidth_and_channel
);

/// `_rtl8723be_read_power_value_fromprom` path A (4-bit sign extension,
/// `0xff` defaults, the `0x11 == 0xff` refusal), the PHY_REG_PG by-rate
/// store with BCD bases and absolute relative values, the
/// `_rtl8723be_get_txpower_index` sums / regulatory-2 / clamp, and the
/// `_rtl8723be_phy_set_txpower_index` byte lanes.
fn smoke_rtl8723be_txpower_efuse_by_rate_and_level() -> TestResult {
    use txpower::*;
    let mut map = provisioned();
    let Ok(e) = Efuse::from_logical(&map) else {
        return TestResult::Fail("power area refused");
    };
    if e.cck_base != [0x20, 0x21, 0x22, 0x23, 0x24, 0x25]
        || e.bw40_base != [0x18, 0x19, 0x1a, 0x1b, 0x1c]
        || e.ht20_diff != 0xff
        || e.legacy_ht_diff != 0x02
        || e.ht40_diff != 0
        || e.cck(2) != 0x20
        || e.cck(3) != 0x21
        || e.ht40_1s(9) != 0x1a
        || e.ht40_1s(14) != 0x1a
    {
        return TestResult::Fail("8723BE EFUSE power decode");
    }
    map[0x1b] = 0xff;
    map[0x12] = 0xff;
    match Efuse::from_logical(&map) {
        Ok(d) if d.ht20_diff == 2 && d.legacy_ht_diff == 4 && d.cck_base[2] == 0x2d => {}
        _ => return TestResult::Fail("8723BE 0xff power defaults"),
    }
    map[0x11] = 0xff;
    if Efuse::from_logical(&map).is_ok() {
        return TestResult::Fail("autoload-fail power branch admitted");
    }
    let b = ByRate::from_table();
    if b.offset[0][..6]
        != [
            0x0c0e_1010,
            0x0004_080a,
            0x0000_0600,
            0x0002_0400,
            0x0c0e_1012,
            0x0004_080a,
        ]
        || b.offset[1][6..8] != [0, 0]
    {
        return TestResult::Fail("8723BE by-rate store");
    }
    let diffs: Vec<u8> = RATES.iter().map(|r| b.diff(*r)).collect();
    if diffs
        != [
            6, 4, 2, 0, 0x10, 0x10, 0x0e, 0x0c, 0x0a, 8, 4, 0, 0x12, 0x10, 0x0e, 0x0c, 0x0a, 8, 4,
            0,
        ]
    {
        return TestResult::Fail("8723BE by-rate diffs");
    }
    if index(&e, &b, 0, 0, false, 6) != 0x27
        || index(&e, &b, 0, 3, false, 6) != 0x21
        || index(&e, &b, 0, 4, false, 6) != 0x2b
        || index(&e, &b, 0, 11, false, 6) != 0x1b
        || index(&e, &b, 0, 12, false, 6) != 0x2a
        || index(&e, &b, 0, 19, false, 6) != 0x18
        || index(&e, &b, 0, 12, true, 6) != 0x2b
        || index(&e, &b, 2, 12, false, 6) != 0x18
    {
        return TestResult::Fail("8723BE txpower index");
    }
    let mut hot = e;
    hot.bw40_base = [0x3e; 5];
    if index(&hot, &b, 0, 4, false, 6) != MAX_POWER_INDEX {
        return TestResult::Fail("8723BE MAX_POWER_INDEX clamp");
    }
    let io = fw_fake(true, true, false);
    if set_level(&io, &e, &b, 0, false, 6).is_err() {
        return TestResult::Fail("set_level failed");
    }
    let g = io.0.lock();
    let r32 =
        |r: usize| u32::from_le_bytes([g.regs[r], g.regs[r + 1], g.regs[r + 2], g.regs[r + 3]]);
    if r32(0xe08) != 0x2700
        || r32(0x86c) != 0x2123_2500
        || r32(0xe00) != 0x2729_2b2b
        || r32(0xe04) != 0x1b1f_2325
        || r32(0xe10) != 0x2426_282a
        || r32(0xe14) != 0x181c_2022
        || g.writes.iter().any(|w| w.0 == 0xe18 || w.0 == 0xe1c)
    {
        return TestResult::Fail("8723BE TXAGC byte lanes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_txpower_efuse_by_rate_and_level
);

/// `_rtl8723be_phy_simularity_compare` (signed odd entries, tolerance 5,
/// the zero-sum `i == 2` candidate copying entries 0..2, per-section
/// `result[3]` copies) and a full `rtl8723be_phy_iq_calibrate` on the model:
/// `0x948` restored, MAC/ADDA/BB backups reloaded from `t == 1`, tone resets,
/// candidate 0 with an all-zero matrix and no fill.
fn smoke_rtl8723be_iqk_compare_and_full_run() -> TestResult {
    use iqk::*;
    let mut r = [[0u32; 8]; 4];
    r[0] = [0x100, 0x3fe, 0x0f0, 0x005, 0, 0, 0, 0];
    r[1] = [0x102, 0x001, 0x0f3, 0x003, 0, 0, 0, 0];
    if !simularity_compare(&mut r, 0, 1) || r[3] != [0; 8] {
        return TestResult::Fail("similar runs");
    }
    r[1][0] = 0x110;
    if simularity_compare(&mut r, 0, 1) || r[3][..4] != [0, 0, 0x0f0, 0x005] {
        return TestResult::Fail("TX mismatch keeps RX of c1");
    }
    let mut z = [[0u32; 8]; 4];
    z[0] = [0x100, 0x000, 0, 0, 0, 0, 0, 0];
    z[1] = [0x101, 0x000, 0x0f0, 0x000, 0, 0, 0, 0];
    if simularity_compare(&mut z, 0, 1) || z[3][..2] != [0x101, 0] {
        return TestResult::Fail("zero-sum candidate copy");
    }
    let io = fw_fake(true, true, false);
    {
        let mut g = io.0.lock();
        g.regs[0x948..0x94c].copy_from_slice(&0x280u32.to_le_bytes());
        g.regs[0x522] = 0x5a;
        g.regs[0x85c..0x860].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        g.regs[0xc50] = 0x20;
    }
    let report = match narf_scheduler::block_on(calibrate(&io)) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("IQK run failed"),
    };
    let g = io.0.lock();
    let r32 =
        |r: usize| u32::from_le_bytes([g.regs[r], g.regs[r + 1], g.regs[r + 2], g.regs[r + 3]]);
    if report.final_candidate != 0
        || report.matrix != Some([0; 8])
        || report.reg_e94 != 0
        || r32(0x948) != 0x280
        || g.regs[0x522] != 0x5a
        || r32(0x85c) != 0x1234_5678
        || g.regs[0xc50] != 0x20
        || !g.writes.contains(&(0xc50, 0x50, 4))
        || r32(0xe30) != 0x0100_8c00
        || r32(0xe28) != 0
        || !g.writes.contains(&(0x85c, 0x01c0_0014, 4))
        || !g.writes.contains(&(0x948, 0x280, 4))
        || g.writes.iter().any(|w| w.0 == 0xc80 || w.0 == 0xc88)
    {
        return TestResult::Fail("8723BE IQK run restore");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_iqk_compare_and_full_run
);

/// `rtl8723be_hw_init` `ERFON` block: rfpath main, IQK only on `ANT_X2`,
/// LCK, `NAV_UPPER = 235`, the `RXDMA_CONTROL` BIT2 release; `PCIE_CTRL + 1`
/// stays untouched. Then a [`channel::Grant`] bounded by the Linux index
/// and `channel::configure` (TXAGC, RF channel, bandwidth).
fn smoke_rtl8723be_erfon_block_and_channel_grant() -> TestResult {
    let v = match Version::from_registers(version::CHIP_8723B, 0x1000) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("version"),
    };
    let mut map = provisioned();
    let Ok(efuse) = txpower::Efuse::from_logical(&map) else {
        return TestResult::Fail("power area");
    };
    for (c3, iqk) in [(0x00u8, true), (0x01, false)] {
        map[0xc3] = c3;
        let Ok(a) = adapter::Adapter::from_hardware(v, adapter::CR9346_AUTOLOAD_OK, 0, &map, 5)
        else {
            return TestResult::Fail("adapter");
        };
        let io = fw_fake(true, true, false);
        io.0.lock().regs[usize::from(init::REG_RXDMA_CONTROL)] = 0x06;
        let mut coex = coex::Owner::bind(crate::rtlwifi::btcoex::btc::HwPg::rtl8723be(&a));
        let radio = match narf_scheduler::block_on(init::configure(&io, &a, efuse, &mut coex)) {
            Ok(r) => r,
            Err(_) => return TestResult::Fail("8723BE configure failed"),
        };
        let g = io.0.lock();
        let w = |row: (u16, u32, u8)| g.writes.iter().position(|x| *x == row);
        let (Some(mac), Some(path), Some(lck), Some(nav), Some(rx)) = (
            w((0x0615, 0xbe, 1)),
            w((channel::REG_RFPATH_SWITCH, 1, 4)),
            w((0x840, (0xb0 << 20) | 0xdfbe0, 4)),
            w((init::REG_NAV_UPPER, 235, 1)),
            w((init::REG_RXDMA_CONTROL, 0x02, 1)),
        ) else {
            return TestResult::Fail("8723BE ERFON rows missing");
        };
        let iqk_at = w((iqk::RFPGA0_IQK, 0x8080_0000, 4));
        // `rtl8723be_bt_hw_init` (both algorithms set 0x790[5:0] = 5)
        // between the station address and the `ERFON` block.
        let bt_init = g
            .writes
            .iter()
            .position(|x| x.0 == 0x0790 && x.1 & 0x3f == 5);
        if !bt_init.is_some_and(|b| mac < b && b < path)
            || !coex.btc.initialized
            || coex.btc.board_info.btdm_ant_num != if iqk { 2 } else { 1 }
        {
            return TestResult::Fail("8723BE bt_hw_init order / dispatch");
        }
        if !(mac < path && path < lck && lck < nav && nav < rx)
            || iqk_at.is_some() != iqk
            || iqk_at.is_some_and(|i| !(path < i && i < lck))
            || radio.iqk.is_some() != iqk
            || g.writes.iter().any(|x| x.0 == 0x0301)
        {
            return TestResult::Fail("8723BE ERFON order");
        }
    }
    let by_rate = txpower::ByRate::from_table();
    let linux = txpower::linux_indices(&efuse, &by_rate, 0, false, 6);
    let mut over = linux;
    over[4] += 1;
    let id = [7u8; 32];
    if channel::Grant::bounded(id, &efuse, &by_rate, 0, 6, false, 0, over).is_ok()
        || channel::Grant::bounded(id, &efuse, &by_rate, 0, 6, false, 1, linux).is_ok()
        || channel::Grant::bounded(id, &efuse, &by_rate, 0, 2, true, 1, linux).is_ok()
        || channel::Grant::bounded(id, &efuse, &by_rate, 0, 15, false, 0, linux).is_ok()
    {
        return TestResult::Fail("8723BE grant bound");
    }
    let mut low = linux;
    low[4] -= 4;
    let Ok(grant) = channel::Grant::bounded(id, &efuse, &by_rate, 0, 6, false, 0, low) else {
        return TestResult::Fail("8723BE grant refused");
    };
    let io = fw_fake(true, true, false);
    let mut chnlval = [0x0c01, 0];
    if narf_scheduler::block_on(channel::configure(&io, &grant, &mut chnlval)).is_err()
        || chnlval[0] != 0x0c06
    {
        return TestResult::Fail("8723BE channel configure");
    }
    let g = io.0.lock();
    let w = |row: (u16, u32, u8)| g.writes.iter().position(|x| *x == row);
    match (
        w((0x0e00, u32::from(low[4]), 4)),
        w((0x840, (0x18 << 20) | 0x0c06, 4)),
    ) {
        (Some(p), Some(c)) if p < c && g.regs[usize::from(channel::REG_BWOPMODE)] & 4 != 0 => {}
        _ => return TestResult::Fail("8723BE grant TXAGC then channel then BW"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_erfon_block_and_channel_grant
);

// ── H2C / C2H / LPS / RA mask / IRQ / DM / card disable ───────────────────

struct RegLogModel {
    regs: Vec<u8>,
    writes: Vec<(u16, u32, u8)>,
}
struct RegLog(IrqSafeSpinLock<RegLogModel>);
#[async_trait::async_trait]
impl Io for RegLog {
    fn read8(&self, reg: u16) -> Result<u8, FwError> {
        Ok(self.0.lock().regs[usize::from(reg)])
    }
    fn read32(&self, reg: u16) -> Result<u32, FwError> {
        let g = self.0.lock();
        let r = usize::from(reg);
        Ok(u32::from_le_bytes([
            g.regs[r],
            g.regs[r + 1],
            g.regs[r + 2],
            g.regs[r + 3],
        ]))
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), FwError> {
        let mut g = self.0.lock();
        g.writes.push((reg, u32::from(value), 1));
        // The modelled power FSM completes 0x05[1:0] requests immediately.
        g.regs[usize::from(reg)] = if reg == 5 { value & !3 } else { value };
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
    fn write_bytes(&self, _reg: u16, _bytes: &[u8]) -> Result<(), FwError> {
        Err(FwError::Access)
    }
    async fn delay_us(&self, _micros: u64) {}
}
fn reg_log() -> RegLog {
    RegLog(IrqSafeSpinLock::new(RegLogModel {
        regs: vec![0u8; 0x800],
        writes: Vec::new(),
    }))
}

/// `_rtl8723be_fill_h2c_command` box / extension-box writes and box
/// rotation, the HMETFR timeout, `rtl8723be_set_fw_pwrmode_cmd` (no PS
/// gate: the LPS-enter `SETPWRMODE(MAX)` is written; BT LPS control) and
/// `HW_VAR_SET_RPWM` at 0x361.
fn smoke_rtl8723be_h2c_boxes_pwrmode_and_rpwm() -> TestResult {
    use crate::rtlwifi::prepare::Error as PrepError;
    use h2c::*;
    let io = reg_log();
    let mut mb = Mailbox::default();
    if narf_scheduler::block_on(mb.fill(&io, H2C_MSRRPT, &media_status(true))).is_err() {
        return TestResult::Fail("8723BE short H2C refused");
    }
    let short: Vec<_> = io.0.lock().writes.clone();
    if short
        != [
            (0x1d0, 0x01, 1),
            (0x1d1, 0x01, 1),
            (0x1d2, 0, 1),
            (0x1d3, 0, 1),
        ]
        || mb.next_box() != 1
    {
        return TestResult::Fail("8723BE 3-byte box write");
    }
    io.0.lock().writes.clear();
    let enter = narf_scheduler::block_on(fwlps_enter(&io, &mut mb, None));
    // MAX mode: rlbm 1, smart_ps 2, awake 2, RF off, byte5 0x40.
    if enter != Ok([1, 0x21, 2, 0, 0, 0x40, 0]) {
        return TestResult::Fail("8723BE LPS-enter SETPWRMODE");
    }
    {
        let g = io.0.lock();
        let w: Vec<_> = g.writes.iter().map(|w| (w.0, w.1)).collect();
        if w[..4] != [(0x1f4, 0), (0x1f5, 0x40), (0x1f6, 0), (0x1f7, 0)]
            || w[4..8] != [(0x1d4, 0x20), (0x1d5, 1), (0x1d6, 0x21), (0x1d7, 2)]
            || w[8] != (0x361, 0x80)
            || w.len() != 9
        {
            return TestResult::Fail("8723BE ext-box order / RPWM toggle");
        }
    }
    io.0.lock().regs[0x361] = 0x80;
    io.0.lock().writes.clear();
    let leave = narf_scheduler::block_on(fwlps_leave(&io, &mut mb, None));
    if leave != Ok([0, 0x02, 4, 0, FW_PWR_STATE_ACTIVE, 0x40, 0])
        || io.0.lock().writes[0] != (0x361, 0, 1)
    {
        return TestResult::Fail("8723BE LPS-leave RPWM then SETPWRMODE(ACTIVE)");
    }
    let bt = BtLps {
        lps_on: true,
        lps_val: 0x50,
        rpwm_val: 0x04,
    };
    if pwrmode(PsMode::Max, 2, Some(bt)) != [1, 0x00, 2, 0, 0x04, 0x50, 0]
        || pwrmode(
            PsMode::Max,
            2,
            Some(BtLps {
                lps_on: false,
                ..bt
            }),
        ) != [0, 0x02, 4, 0, FW_PWR_STATE_ACTIVE, 0x40, 0]
        || pwrmode(PsMode::Dtim, 2, None) != [1, 0x22, 2, 0, 0, 0x40, 0]
    {
        return TestResult::Fail("8723BE BT-controlled / DTIM pwrmode");
    }
    // Box 3 never read by the firmware: the command is refused and poisons.
    io.0.lock().regs[0x1cc] = 1 << mb.next_box();
    if narf_scheduler::block_on(mb.fill(&io, H2C_RA_MASK, &[0; 7]))
        != Err(PrepError::CommandTimeout)
        || !mb.failed
        || narf_scheduler::block_on(mb.fill(&io, H2C_MSRRPT, &[0; 3])) != Err(PrepError::State)
    {
        return TestResult::Fail("8723BE HMETFR timeout");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_h2c_boxes_pwrmode_and_rpwm
);

/// `rtl8723be_update_hal_rate_mask` (1T1R, `RATR_INX_WIRELESS_NGB` ⇒ ARFR 1
/// at both widths, GB 6, B 8), `rtl8723be_dm_refresh_rate_adaptive_mask`
/// thresholds (low `low2high_rssi_thresh_for_ra40m` = 0) and the
/// `_rtl8723be_query_rxphystatus` PWDB.
fn smoke_rtl8723be_ra_mask_dm_and_rx_pwdb() -> TestResult {
    use crate::rtlwifi::rate_adaptive::{STA_HIGH, STA_INIT, STA_LOW, STA_MIDDLE};
    use h2c::*;
    let n = Peer {
        legacy: 0xfff,
        ht: Some([0xff, 0xff]),
        sgi20: true,
        sgi40: false,
    };
    if rate_mask(&n, false, 0, false) != [0, 0x81, 0x08, 0x05, 0xf0, 0x0f, 0]
        || rate_mask(&n, true, 0, true) != [0, 0x01, 0x01, 0x15, 0xf0, 0x0f, 0]
        || rate_mask(&n, true, 1, true)[3..] != [0, 0, 0x0f, 0]
        || rate_mask(&n, false, 2, true)[3..] != [0, 0xf0, 0x0f, 0]
    {
        return TestResult::Fail("8723BE N rate mask");
    }
    let g = Peer {
        legacy: 0xff5,
        ht: None,
        sgi20: false,
        sgi40: false,
    };
    let b = Peer { legacy: 0xf, ..g };
    if rate_mask(&g, false, 0, true) != [0, ARFR_GB, 0, 0xf5, 0x0f, 0, 0]
        || rate_mask(&b, false, 0, true) != [0, ARFR_B, 0, 0x0d, 0, 0, 0]
        || mask_rates(&rate_mask(&n, true, 0, true)) != Some(0x000f_f015)
        || mask_rates(&[0, ARFR_GB, 0, 0, 0x10, 0, 0]).is_some()
        || mask_rates(&[0, 5, 0, 1, 0, 0, 0]).is_some()
        || mask_rates(&[0, ARFR_NGB, 0, 0, 0, 0x10, 0]).is_some()
    {
        return TestResult::Fail("8723BE legacy rate mask / mask_rates");
    }
    for (rssi, prev, expected) in [
        (51, STA_INIT, Some(STA_HIGH)),
        (1, STA_INIT, Some(STA_MIDDLE)),
        (0, STA_INIT, Some(STA_LOW)),
        (55, STA_MIDDLE, None),
        (56, STA_MIDDLE, Some(STA_HIGH)),
        (5, STA_LOW, None),
        (6, STA_LOW, Some(STA_MIDDLE)),
    ] {
        if dm::ra_state(rssi, prev) != expected {
            return TestResult::Fail("8723BE RA hysteresis");
        }
    }
    let mut phy = [0u8; 8];
    phy[4] = 0x50 << 1; // 0x50 - 110 = -30 dBm ⇒ 70
    for (agc, cck, expected) in [
        (0, false, Some(70)),
        ((6 << 5) | 3, true, Some(60)),  // -34 - 6 = -40
        ((4 << 5) | 10, true, Some(66)), // -14 - 20 = -34
        ((1 << 5) | 2, true, Some(100)), // 6 - 4 = 2
        (31, true, Some(54)),            // 16 - 62 = -46
        (2 << 5, true, Some(100)),       // no case: rx_pwr_all stays 0
    ] {
        phy[5] = agc;
        if dm::rx_pwdb(&phy, cck) != expected {
            return TestResult::Fail("8723BE query_rxphystatus PWDB");
        }
    }
    if dm::rx_pwdb(&phy[..5], false).is_some() {
        return TestResult::Fail("8723BE short PHY status admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_ra_mask_dm_and_rx_pwdb
);

/// `rtl_c2h_content_parsing` for this chip (BT info / MP to coexistence,
/// RA report ignored unread), the `rtl8723be_{enable,disable}_interrupt` /
/// `interrupt_recognized` profile with the HSISR write, and
/// `_rtl8723be_poweroff_adapter` order.
fn smoke_rtl8723be_c2h_irq_and_card_disable() -> TestResult {
    use c2h::*;
    if parse(&[C2H_BT_INFO, 0, 1, 2]) != Ok(Event::BtInfo(&[1, 2]))
        || parse(&[C2H_BT_MP, 0, 9]) != Ok(Event::BtMp(&[9]))
        || parse(&[C2H_RA_RPT, 0]) != Ok(Event::Other(&[]))
        || parse(&[C2H_TX_REPORT, 0, 0x40, 0, 3, 0, 0, 0, 7])
            != Ok(Event::TxReport {
                sn: 7,
                st: 0x40,
                retry: 3,
            })
        || parse(&[C2H_TX_REPORT, 0, 0]) != Err(Error::Truncated)
        || parse(&[0x33]) != Err(Error::Truncated)
    {
        return TestResult::Fail("8723BE C2H dispatch");
    }
    let io = reg_log();
    {
        let mut g = io.0.lock();
        g.regs[0xb4..0xb8].copy_from_slice(&0xffff_ffffu32.to_le_bytes()[..]);
        g.regs[0xb4 + 3] = 0x7f;
        g.regs[0xbc..0xc0].copy_from_slice(&0x0000_0f00u32.to_le_bytes());
        g.regs[0x5c] = 0x05;
    }
    let got = h2c::service_interrupt(&io);
    let mask0 = h2c::IRQ_MASK0;
    let w: Vec<_> = io.0.lock().writes.clone();
    if got != Ok((0x7fff_ffff & mask0, 0x100))
        || w != [
            (0xb0, 0, 4),
            (0xb8, 0, 4),
            (0xb4, 0x7fff_ffff & mask0, 4),
            (0xbc, 0x100, 4),
            (0x5c, 0xc5, 1),
            (0xb0, mask0, 4),
            (0xb8, 0x100, 4),
            (0x58, 0xc0, 4),
        ]
        || mask0 != 0x2000_84ff
    {
        return TestResult::Fail("8723BE interrupt recognition / HSISR / HSIMR");
    }
    let model = |ready_bit: bool| {
        let io = reg_log();
        {
            let mut g = io.0.lock();
            g.regs[0x80] = if ready_bit { 0xc6 } else { 0x46 };
            g.regs[0x1d] = 1;
            g.regs[3] = 0xfc;
        }
        io
    };
    let io = model(true);
    if narf_scheduler::block_on(crate::rtlwifi::power_runtime::disable_rtl8723be(&io, true))
        .is_err()
    {
        return TestResult::Fail("8723BE poweroff failed on an idle model");
    }
    let g = io.0.lock();
    let w: Vec<_> = g.writes.iter().map(|w| (w.0, w.1 as u8)).collect();
    let at = |reg: u16, value: u8| w.iter().position(|&x| x == (reg, value));
    let (Some(lps), Some(fw0), Some(fwdl), Some(rf)) =
        (at(0x553, 0x20), at(0x1d, 0), at(0x80, 0), at(0x1f, 0))
    else {
        return TestResult::Fail("8723BE poweroff write missing");
    };
    if !(lps < fw0 && fw0 < fwdl && fwdl < rf)
        || w.iter().filter(|&&x| x == (3, 0xf8)).count() != 2
        || w.last() != Some(&(0x1c, 0x0e))
        || w[w.len() - 2] != (0x1d, 1)
        || w[w.len() - 3] != (0x1d, 0)
    {
        return TestResult::Fail("8723BE poweroff order / final state");
    }
    drop(g);
    let cold = model(false);
    if narf_scheduler::block_on(crate::rtlwifi::power_runtime::disable_rtl8723be(
        &cold, true,
    ))
    .is_err()
        || cold.0.lock().writes.iter().filter(|w| w.0 == 3).count() != 1
    {
        return TestResult::Fail("8723BE self-reset without MCUFWDL BIT7");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_c2h_irq_and_card_disable
);

// ── Coexistence owner (`rtl8723be/coex.rs`) ───────────────────────────────

struct FakeC2h {
    queue: Vec<Vec<u8>>,
    deferred: Vec<Vec<u8>>,
}
impl btc::C2hSource for FakeC2h {
    fn poll_c2h(
        &mut self,
        out: &mut [u8; btc::C2H_MAX],
    ) -> Result<Option<usize>, crate::rtlwifi::prepare::Error> {
        if self.queue.is_empty() {
            return Ok(None);
        }
        let p = self.queue.remove(0);
        out[..p.len()].copy_from_slice(&p);
        Ok(Some(p.len()))
    }
    fn defer_c2h(&mut self, packet: &[u8]) -> Result<(), crate::rtlwifi::prepare::Error> {
        self.deferred.push(packet.to_vec());
        Ok(())
    }
}

/// The coexistence owner's Linux call sites: `rtl_lps_set_psmode` with the
/// BT-controlled `SETPWRMODE` recorded by `btc_record_pwr_mode` and the
/// `btc_lps_notify` order (`ps.c:368/375`), C2H BT MP / BT info dispatch
/// (`base.c:2313/2319`), the RX-ring `bt_mp_comp` wait deferring other C2H
/// packets, the 2 s watchdog with the 30 s `in_4way` timeout and halt.
fn smoke_rtl8723be_coex_owner_lps_c2h_watchdog_halt() -> TestResult {
    use crate::rtlwifi::btcoex::btc::{ChipInterface, ChipType, HwPg, BT_SEQ_GET_BT_VERSION};
    use btc::BtMpSource;
    let pg = HwPg {
        bt_exist: true,
        ant_num: 2,
        single_ant_path: 0,
        chip_type: ChipType::Rtl8723b,
        package_type: 0,
        rfe_type: 0,
        interface: ChipInterface::Pci,
    };
    let io = reg_log();
    let mut owner = coex::Owner::bind(pg);
    // Not linked: no command, no notify.
    if narf_scheduler::block_on(owner.lps_enter(&io)) != Ok(None) {
        return TestResult::Fail("8723BE coex LPS enter while unlinked");
    }
    owner.lps.linked = true;
    owner.lps.report_linked = true;
    owner.lps.enter_allowed = true;
    owner.btc.bt_info.bt_ctrl_lps = true;
    owner.btc.bt_info.bt_lps_on = true;
    owner.btc.bt_info.lps_val = 0x50;
    owner.btc.bt_info.rpwm_val = 0x04;
    let before = owner.btc.statistics.cnt_lps_notify;
    let enter = narf_scheduler::block_on(owner.lps_enter(&io));
    if enter != Ok(Some([1, 0x00, 2, 0, 0x04, 0x50, 0]))
        || owner.btc.pwr_mode_val[..7] != [1, 0x00, 2, 0, 0x04, 0x50, 0]
        || owner.btc.statistics.cnt_lps_notify != before + 1
        || !owner.algo.two.sta.under_lps
        || owner.lps.active
    {
        return TestResult::Fail("8723BE coex LPS enter (BT form, notify, record)");
    }
    let leave = narf_scheduler::block_on(owner.lps_leave(&io));
    if !matches!(leave, Ok(Some(cmd)) if owner.btc.pwr_mode_val[..7] == cmd)
        || owner.algo.two.sta.under_lps
        || !owner.lps.active
        || narf_scheduler::block_on(owner.lps_leave(&io)) != Ok(None)
    {
        return TestResult::Fail("8723BE coex LPS leave");
    }
    // C2H BT MP outside a wait: `rtl_btc_btmpinfo_notify` only.
    let mp = [
        c2h::C2H_BT_MP,
        0,
        1,
        0,
        BT_SEQ_GET_BT_VERSION << 4,
        0x34,
        0x12,
        7,
    ];
    let mut none = btc::NoC2h;
    if narf_scheduler::block_on(owner.c2h(&io, &mut none, &mp)) != Ok(coex::C2h::Coex)
        || owner.btc.bt_info.bt_real_fw_ver != 0x1234
        || owner.btc.bt_info.bt_fw_ver != 7
    {
        return TestResult::Fail("8723BE coex C2H BT MP");
    }
    let info = [c2h::C2H_BT_INFO, 0, 0, 7, 0, 0, 0, 0, 0];
    let n = owner.btc.statistics.cnt_bt_info_notify;
    if narf_scheduler::block_on(owner.c2h(&io, &mut none, &info)) != Ok(coex::C2h::Coex)
        || owner.btc.statistics.cnt_bt_info_notify != n + 1
        || narf_scheduler::block_on(owner.c2h(&io, &mut none, &[c2h::C2H_RA_RPT, 0, 1]))
            != Ok(coex::C2h::Other)
    {
        return TestResult::Fail("8723BE coex C2H BT info / RA report");
    }
    // `bt_mp_comp` over the RX ring: BT info deferred, MP returned.
    let mut src = FakeC2h {
        queue: vec![info.to_vec(), mp.to_vec()],
        deferred: Vec::new(),
    };
    let got = {
        let mut wait = btc::RxBtMp {
            io: &io,
            source: &mut src,
        };
        narf_scheduler::block_on(wait.next_bt_mp(5))
    };
    if !matches!(got, Ok(Some(r)) if r.body() == &mp[2..]) || src.deferred != [info.to_vec()] {
        return TestResult::Fail("8723BE coex RX bt_mp_comp wait");
    }
    let timeout = {
        let mut wait = btc::RxBtMp {
            io: &io,
            source: &mut src,
        };
        narf_scheduler::block_on(wait.next_bt_mp(3))
    };
    if timeout != Ok(None) {
        return TestResult::Fail("8723BE coex MP wait timeout");
    }
    // Watchdog cadence and the `in_4way` timeout.
    owner.eapol(0);
    let p = owner.btc.statistics.cnt_periodical;
    let run = |owner: &mut coex::Owner, now| {
        narf_scheduler::block_on(owner.watchdog(&io, &mut btc::NoC2h, now))
    };
    if run(&mut owner, 0) != Ok(true)
        || run(&mut owner, 1999) != Ok(false)
        || run(&mut owner, 2000) != Ok(true)
        || owner.btc.statistics.cnt_periodical != p + 2
        || !owner.btc.wifi.in_4way
    {
        return TestResult::Fail("8723BE coex watchdog cadence");
    }
    if run(&mut owner, 30_001) != Ok(true) || owner.btc.wifi.in_4way {
        return TestResult::Fail("8723BE coex watchdog / in_4way");
    }
    if narf_scheduler::block_on(owner.halt(&io)).is_err() || owner.btc.binded {
        return TestResult::Fail("8723BE coex halt unbinds");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_coex_owner_lps_c2h_watchdog_halt
);

// ── Signed envelopes (`rtl8723be/envelope.rs`) ───────────────────────────

/// Test board factory (synthetic values, not any board's).
pub(crate) fn be_factory() -> crate::rtlwifi::efuse::Factory {
    crate::rtlwifi::efuse::Factory {
        mac: [0x00, 0xe0, 0x4c, 0x87, 0x23, 0xbe],
        logical: [0u8; 512],
    }
}

/// A NAPC row: (channel, bandwidth, offset, curve-value fn).
pub(crate) type NapcRow = (u8, u8, u8, fn(u8, u8) -> i16);

/// Build a NAPC envelope from the documented layout (header 96, rows of
/// 388 bytes: channel/band/bandwidth/offset + three 64-entry curves).
/// `rows` are (channel, bandwidth, offset, curve-value fn) for v2, or
/// (channel, 20, 0, fn) for v1. The identity is the board's factory
/// identity; the MAC matches the factory. The curve fn takes the curve
/// index (0 CCK, 1 OFDM, 2 HT) and the TXAGC index.
pub(crate) fn be_napc_fixture(
    version: u16,
    antenna: i16,
    qualified: i16,
    rows: &[NapcRow],
) -> Vec<u8> {
    let factory = be_factory();
    let identity = crate::rtlwifi::radio::factory_identity(&factory);
    let total = 96 + rows.len() * 388;
    let mut bytes = vec![0u8; total];
    bytes[0..4].copy_from_slice(b"NAPC");
    bytes[4..6].copy_from_slice(&version.to_le_bytes());
    bytes[6..8].copy_from_slice(&96u16.to_le_bytes());
    bytes[8..12].copy_from_slice(&(total as u32).to_le_bytes());
    bytes[12..14].copy_from_slice(&0x10ecu16.to_le_bytes());
    bytes[14..16].copy_from_slice(&0xb723u16.to_le_bytes());
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
        for curve_idx in 0..3u8 {
            for idx in 0..64u8 {
                let at = 4 + (usize::from(curve_idx) * 64 + usize::from(idx)) * 2;
                row[at..at + 2].copy_from_slice(&curve(curve_idx, idx).to_le_bytes());
            }
        }
    }
    bytes
}

/// Flat rising curves: output `2 * index` quarter dBm, so a 20 dBm
/// ceiling with antenna 0 admits index 40 on every rate.
pub(crate) fn be_rising(_curve: u8, idx: u8) -> i16 {
    i16::from(idx) * 2
}

/// HT curve unmeasured: MCS rates can never be admitted.
fn be_no_ht(curve: u8, idx: u8) -> i16 {
    if curve == 2 {
        i16::MAX
    } else {
        i16::from(idx) * 2
    }
}

/// US 2.4 GHz domain: 2402-2472 MHz, 40 MHz, 20 dBm.
pub(crate) fn be_us_domain() -> narf_wireless::reg::RegulatoryDomain {
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
/// variants, the masking-defeating multi-row v2 case, and grant minting
/// with the Linux factory-index cap.
fn smoke_rtl8723be_envelope_parse_permission_and_grant() -> TestResult {
    use envelope::*;
    let factory = be_factory();
    let domain = be_us_domain();
    let bytes = be_napc_fixture(1, 0, 80, &[(6, 20, 0, be_rising)]);
    let cal = match Calibration::from_verified(&bytes, Some([0xabu8; 32]), &factory) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("8723BE envelope v1 parse"),
    };
    if !cal.measures(Operating::twenty(6)) || cal.measures(Operating::twenty(7)) {
        return TestResult::Fail("8723BE envelope v1 rows");
    }
    let perm = match cal.permission_for(&domain, Operating::twenty(6)) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("8723BE envelope v1 permission"),
    };
    if perm.admitted_rates() != 0xfffff
        || perm.eirp_limit_qdbm() != 80
        || STATION_RATES.into_iter().any(|r| perm.index(r) != 40)
    {
        return TestResult::Fail("8723BE envelope v1 permission values");
    }
    // Tampered variants: each must be refused.
    let mut bad = bytes.clone();
    bad[0] = b'X';
    if Calibration::from_verified(&bad, Some([0xabu8; 32]), &factory).is_ok() {
        return TestResult::Fail("8723BE envelope bad magic admitted");
    }
    let mut bad = bytes.clone();
    bad[14..16].copy_from_slice(&0x8723u16.to_le_bytes());
    if Calibration::from_verified(&bad, Some([0xabu8; 32]), &factory).is_ok() {
        return TestResult::Fail("8723BE envelope wrong device admitted");
    }
    if Calibration::from_verified(&bytes, None, &factory).is_ok() {
        return TestResult::Fail("8723BE envelope unsigned admitted");
    }
    let mut other = be_factory();
    other.mac[5] = 0xbf;
    if Calibration::from_verified(&bytes, Some([0xabu8; 32]), &other).is_ok() {
        return TestResult::Fail("8723BE envelope identity mismatch admitted");
    }
    // v2: a 5 GHz row is a format failure even after a valid row, and
    // unordered rows are refused.
    let v2 = be_napc_fixture(2, 0, 80, &[(6, 20, 0, be_rising), (36, 20, 0, be_rising)]);
    let mut v2bad = v2.clone();
    v2bad[96 + 388 + 1] = 1;
    if Calibration::from_verified(&v2bad, Some([0xabu8; 32]), &factory).is_ok() {
        return TestResult::Fail("8723BE envelope 5 GHz row admitted");
    }
    let unordered = be_napc_fixture(2, 0, 80, &[(6, 20, 0, be_rising), (5, 20, 0, be_rising)]);
    if Calibration::from_verified(&unordered, Some([0xabu8; 32]), &factory).is_ok() {
        return TestResult::Fail("8723BE envelope unordered rows admitted");
    }
    // An HT-unmeasured board cannot admit the point at all.
    let no_ht = be_napc_fixture(1, 0, 80, &[(6, 20, 0, be_no_ht)]);
    let cal_no_ht = match Calibration::from_verified(&no_ht, Some([0xabu8; 32]), &factory) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("8723BE envelope no-HT parse"),
    };
    if cal_no_ht
        .permission_for(&domain, Operating::twenty(6))
        .is_ok()
    {
        return TestResult::Fail("8723BE envelope unmeasured HT admitted");
    }
    // Grant minting with the factory cap engaged on every rate:
    // crafted EFUSE (CCK bases 0x10, BW40 bases 0x08, zero diffs) with
    // regulatory 2 (by-rate diff skipped) gives Linux indices
    // CCK 16 / OFDM 8 / MCS 8 — all below the measured fit 40.
    let mut map = vec![0u8; 0x20];
    map[0x10..0x16].copy_from_slice(&[0x10; 6]);
    map[0x16..0x1b].copy_from_slice(&[0x08; 5]);
    let efuse = match txpower::Efuse::from_logical(&map) {
        Ok(e) => e,
        Err(_) => return TestResult::Fail("8723BE grant EFUSE"),
    };
    let by_rate = txpower::ByRate::from_table();
    let grant = match cal.grant_for(&domain, &efuse, &by_rate, 2, Operating::twenty(6)) {
        Ok(g) => g,
        Err(_) => return TestResult::Fail("8723BE grant mint"),
    };
    let expected: [u8; 20] = [
        16, 16, 16, 16, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    ];
    if grant.channel() != 6
        || grant.forty()
        || grant.prime_sc() != 0
        || grant.indices() != &expected
        || grant.identity() != crate::rtlwifi::radio::factory_identity(&factory)
    {
        return TestResult::Fail("8723BE grant values / factory cap");
    }
    // 40 MHz grant: primary 3 above → wide channel 5, prime_sc 1.
    let v2cal = be_napc_fixture(
        2,
        0,
        80,
        &[
            (6, 20, 0, be_rising),
            (3, 40, 1, be_rising),
            (9, 40, 2, be_rising),
        ],
    );
    let cal2 = match Calibration::from_verified(&v2cal, Some([0xabu8; 32]), &factory) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("8723BE envelope v2 parse"),
    };
    let op40 = Operating {
        width: Width::W40Above,
        channel: 3,
    };
    let grant40 = match cal2.grant_for(&domain, &efuse, &by_rate, 2, op40) {
        Ok(g) => g,
        Err(_) => return TestResult::Fail("8723BE 40 MHz grant mint"),
    };
    if grant40.channel() != 5 || !grant40.forty() || grant40.prime_sc() != 1 {
        return TestResult::Fail("8723BE 40 MHz grant shape");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_envelope_parse_permission_and_grant
);

// ── Packet owner (`rtl8723be/packet.rs`) ──────────────────────────────────

/// Admitted packet owner for the tests: v1 rising calibration on
/// channel 6, grant from the provisioned test map (regulatory 0).
fn be_packet_owner() -> Option<(packet::Owner, envelope::Permission, channel::Grant)> {
    use envelope::*;
    let factory = be_factory();
    let domain = be_us_domain();
    let bytes = be_napc_fixture(1, 0, 80, &[(6, 20, 0, be_rising)]);
    let cal = Calibration::from_verified(&bytes, Some([0xabu8; 32]), &factory).ok()?;
    let perm = cal.permission_for(&domain, Operating::twenty(6)).ok()?;
    let efuse = txpower::Efuse::from_logical(&provisioned()).ok()?;
    let by_rate = txpower::ByRate::from_table();
    let grant = cal
        .grant_for(&domain, &efuse, &by_rate, 0, Operating::twenty(6))
        .ok()?;
    let info = crate::rtlwifi::firmware_transport::Info {
        version: 0x1234,
        subversion: 0,
        payload: 0,
    };
    let owner = packet::Owner::admit(info, perm, grant).ok()?;
    Some((owner, perm, grant))
}

/// Admission gates, TX descriptor golden bytes (hand-computed from the
/// `trx::TxDesc::fill` rules, not from running the fill), the RTS
/// variant, and refusal-before-write.
fn smoke_rtl8723be_packet_admission_and_desc() -> TestResult {
    use packet::*;
    let Some((owner, perm, grant)) = be_packet_owner() else {
        return TestResult::Fail("8723BE packet owner admit");
    };
    if owner.firmware_version() != 0x1234 || owner.permission() != perm || owner.grant() != grant {
        return TestResult::Fail("8723BE packet owner accessors");
    }
    // Admission mismatch: a grant for another point, or a permission
    // from another board, cannot construct an owner.
    let domain = be_us_domain();
    let factory = be_factory();
    let bytes = be_napc_fixture(1, 0, 80, &[(6, 20, 0, be_rising)]);
    let _cal = match envelope::Calibration::from_verified(&bytes, Some([0xabu8; 32]), &factory) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("8723BE packet cal"),
    };
    let efuse = match txpower::Efuse::from_logical(&provisioned()) {
        Ok(e) => e,
        Err(_) => return TestResult::Fail("8723BE packet EFUSE"),
    };
    let by_rate = txpower::ByRate::from_table();
    // Mint the mismatch as permission on 6 + grant on 6 from another
    // board identity (a grant for channel 7 cannot exist here: the
    // calibration carries no row for 7, so that grant_for fails).
    let mut other = be_factory();
    other.mac[5] = 0xbf;
    let bytes_other = {
        let mut b = be_napc_fixture(1, 0, 80, &[(6, 20, 0, be_rising)]);
        let id = crate::rtlwifi::radio::factory_identity(&other);
        b[16..48].copy_from_slice(&id);
        b[48..54].copy_from_slice(&other.mac);
        b
    };
    let cal_other =
        match envelope::Calibration::from_verified(&bytes_other, Some([0xabu8; 32]), &other) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("8723BE packet cal other"),
        };
    let grant_other =
        match cal_other.grant_for(&domain, &efuse, &by_rate, 0, envelope::Operating::twenty(6)) {
            Ok(g) => g,
            Err(_) => return TestResult::Fail("8723BE packet grant other"),
        };
    let info = crate::rtlwifi::firmware_transport::Info {
        version: 0x1234,
        subversion: 0,
        payload: 0,
    };
    if packet::Owner::admit(info, perm, grant_other).is_ok() {
        return TestResult::Fail("8723BE packet admit mismatch refused");
    }
    let tx = TxFrame {
        op: envelope::Operating::twenty(6),
        class: FrameClass::Data { priority: 0 },
        len: 100,
        buf_addr: 0x4000,
        rate: 12,
        seq: 0x123,
        short: false,
        bmc: false,
        rts: None,
        next_desc: 0x8000,
    };
    let mut slot = trx::TxDesc::default();
    if owner.fill_tx_slot(&mut slot, &tx).is_err() {
        return TestResult::Fail("8723BE packet fill admitted");
    }
    // Golden bytes, hand-computed from `trx::TxDesc::fill`:
    // dw0 = offset 40<<16 | len 100 | firstseg<<27 | lastseg<<26
    // (OWN clear); dw3 = seq<<12 | use_driver_rate<<8; dw4 = rate 12 |
    // 0x1f<<8 | 0xf<<13 (= 0x1ff0c); dw7 = len; dw9 = seq<<12;
    // dw10 = buffer.
    if slot.dw[0] != 0x0c28_0064
        || slot.dw[1] != 0
        || slot.dw[2] != 0
        || slot.dw[3] != 0x0012_3100
        || slot.dw[4] != 0x0001_ff0c
        || slot.dw[5] != 0
        || slot.dw[6] != 0
        || slot.dw[7] != 100
        || slot.dw[8] != 0
        || slot.dw[9] != 0x0012_3000
        || slot.dw[10] != 0x4000
        || slot.dw[12] != 0x8000
        || slot.own()
        || slot.pkt_size() != 100
        || slot.queue_sel() != 0
        || slot.tx_rate() != 12
        || slot.data_bw() != 0
        || slot.sub_carrier() != 0
    {
        return TestResult::Fail("8723BE packet TX descriptor bytes");
    }
    // Beacon queue selector.
    let beacon = TxFrame {
        class: FrameClass::Beacon,
        rate: 0,
        ..tx
    };
    let mut bslot = trx::TxDesc::default();
    if owner.fill_tx_slot(&mut bslot, &beacon).is_err() || bslot.queue_sel() != trx::QSLT_BEACON {
        return TestResult::Fail("8723BE packet beacon queuesel");
    }
    // RTS variant: rts_en bit 12, RTS rate in dw4, SC + short in dw5.
    let rts_tx = TxFrame {
        rts: Some(Rts {
            rts_enable: true,
            cts_enable: false,
            rts_short: true,
            rts_rate: 4,
            rts_sc: 2,
        }),
        ..tx
    };
    let mut rslot = trx::TxDesc::default();
    if owner.fill_tx_slot(&mut rslot, &rts_tx).is_err()
        || rslot.dw[3] != 0x0012_4100
        || rslot.dw[4] != 0x041f_f00c
        || rslot.dw[5] != 0x0000_5000
    {
        return TestResult::Fail("8723BE packet RTS descriptor bytes");
    }
    // Refusal before any byte is written: sentinel slot unchanged.
    let refused = |frame: TxFrame| -> bool {
        let mut s = trx::TxDesc {
            dw: [0xdead_beef; 16],
        };
        if owner.fill_tx_slot(&mut s, &frame).is_ok() {
            return false;
        }
        s.dw == [0xdead_beef; 16]
    };
    if !refused(TxFrame {
        op: envelope::Operating::twenty(7),
        ..tx
    }) || !refused(TxFrame { rate: 20, ..tx })
        || !refused(TxFrame { len: 0, ..tx })
        || !refused(TxFrame { len: 0x10000, ..tx })
    {
        return TestResult::Fail("8723BE packet refused frame wrote");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_packet_admission_and_desc
);

/// RX dispatch: normal frames, hardware-owned slots, C2H BT info / BT
/// MP / TX report through the coexistence owner, and the watchdog /
/// EAPOL delegations.
fn smoke_rtl8723be_packet_rx_c2h_and_notify() -> TestResult {
    use crate::rtlwifi::btcoex::btc::{ChipInterface, ChipType, HwPg, BT_SEQ_GET_BT_VERSION};
    use packet::*;
    let Some((mut owner, _, _)) = be_packet_owner() else {
        return TestResult::Fail("8723BE RX packet owner admit");
    };
    let pg = HwPg {
        bt_exist: true,
        ant_num: 2,
        single_ant_path: 0,
        chip_type: ChipType::Rtl8723b,
        package_type: 0,
        rfe_type: 0,
        interface: ChipInterface::Pci,
    };
    let io = reg_log();
    let mut coex = coex::Owner::bind(pg);
    // Normal frame: length 100 at offset 32.
    let mut buffer = vec![0u8; 200];
    let dw = [100u32, 0, 0, 0, 0, 0, 0, 0];
    let out = narf_scheduler::block_on(owner.service_rx(&io, &mut coex, &dw, &buffer));
    if !matches!(out, Ok(RxOutcome::Frame { status, payload })
        if !status.c2h && status.length == 100 && payload.len() == 100)
        || owner.c2h_queued() != 0
    {
        return TestResult::Fail("8723BE RX normal frame");
    }
    // Hardware-owned slot: not ready.
    let dw_own = [1u32 << 31, 0, 0, 0, 0, 0, 0, 0];
    if narf_scheduler::block_on(owner.service_rx(&io, &mut coex, &dw_own, &buffer))
        != Err(Error::NotReady)
    {
        return TestResult::Fail("8723BE RX own bit");
    }
    // C2H BT info → coexistence notify, consumed, queue drained.
    let info = [c2h::C2H_BT_INFO, 0, 0, 7, 0, 0, 0, 0, 0];
    buffer[32..41].copy_from_slice(&info);
    let dw_c2h = [9u32, 0, 1 << 28, 0, 0, 0, 0, 0];
    let n = coex.btc.statistics.cnt_bt_info_notify;
    if narf_scheduler::block_on(owner.service_rx(&io, &mut coex, &dw_c2h, &buffer))
        != Ok(RxOutcome::Consumed)
        || coex.btc.statistics.cnt_bt_info_notify != n + 1
        || owner.c2h_queued() != 0
    {
        return TestResult::Fail("8723BE RX C2H BT info");
    }
    // C2H BT MP outside a wait → btmpinfo only, consumed.
    let mp = [
        c2h::C2H_BT_MP,
        0,
        1,
        0,
        BT_SEQ_GET_BT_VERSION << 4,
        0x34,
        0x12,
        7,
    ];
    buffer[32..40].copy_from_slice(&mp);
    let dw_mp = [8u32, 0, 1 << 28, 0, 0, 0, 0, 0];
    if narf_scheduler::block_on(owner.service_rx(&io, &mut coex, &dw_mp, &buffer))
        != Ok(RxOutcome::Consumed)
        || coex.btc.bt_info.bt_real_fw_ver != 0x1234
        || coex.btc.bt_info.bt_fw_ver != 7
        || owner.c2h_queued() != 0
    {
        return TestResult::Fail("8723BE RX C2H BT MP");
    }
    // C2H TX report → returned to the caller.
    let rep = [c2h::C2H_TX_REPORT, 0, 0x40, 0, 3, 0, 0, 0, 7];
    buffer[32..41].copy_from_slice(&rep);
    if narf_scheduler::block_on(owner.service_rx(&io, &mut coex, &dw_c2h, &buffer))
        != Ok(RxOutcome::TxReport {
            sn: 7,
            st: 0x40,
            retry: 3,
        })
        || owner.c2h_queued() != 0
    {
        return TestResult::Fail("8723BE RX C2H TX report");
    }
    // EAPOL + watchdog delegations through the packet owner.
    owner.eapol(&mut coex, 0);
    if !coex.btc.wifi.in_4way {
        return TestResult::Fail("8723BE packet eapol delegation");
    }
    if narf_scheduler::block_on(owner.watchdog(&io, &mut coex, 0)) != Ok(true)
        || narf_scheduler::block_on(owner.watchdog(&io, &mut coex, 1999)) != Ok(false)
    {
        return TestResult::Fail("8723BE packet watchdog delegation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_packet_rx_c2h_and_notify
);

// ── station MAC registers / reserved page ─────────────────────────────────

/// `rtl8723be_set_fw_rsvdpagepkt` body over the verbatim `fw.c` initializer,
/// and the `rtl8723be_set_hw_reg` station rows: `HW_VAR_BASIC_RATE` (`| 1`,
/// INIRTS index), `update_channel_access_setting` SIFS 0x0a0a without HT,
/// `HW_VAR_ACK_PREAMBLE` at `REG_TRXPTCL_CTL + 2` BIT(1), and
/// `_rtl8723be_set_media_status` / `set_check_bssid` for the linked station.
fn smoke_rtl8723be_station_registers_and_rsvd_page() -> TestResult {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(&rsvd_page::TEMPLATE);
    let digest = hash.finalize();
    let hex: alloc::string::String = digest.iter().map(|b| alloc::format!("{b:02x}")).collect();
    if hex != rsvd_page::TEMPLATE_SHA256 {
        return TestResult::Fail("8723BE reserved_page_packet digest");
    }
    let own = [0x00, 0xe0, 0x4c, 1, 2, 3];
    let bssid = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    let Some(pages) = rsvd_page::pages(own, bssid, 5) else {
        return TestResult::Fail("8723BE reserved pages refused");
    };
    let ps = rsvd_page::PSPOLL_PG * rsvd_page::PAGE;
    if pages[10..16] != own
        || pages[16..22] != bssid
        || pages[ps + 2..ps + 4] != [5, 0xc0]
        || pages[ps + 10..ps + 16] != own
        || pages[rsvd_page::BT_QOS_NULL_PG * rsvd_page::PAGE + 4..][..6] != bssid
        || rsvd_page::pages(own, bssid, 0).is_some()
    {
        return TestResult::Fail("8723BE reserved page substitutions");
    }
    let io = reg_log();
    if station::basic_rate(0x15f) != (0x15f, 8) || station::basic_rate(0x002) != (0x003, 1) {
        return TestResult::Fail("8723BE HW_VAR_BASIC_RATE");
    }
    io.0.lock().regs[usize::from(station::REG_TRXPTCL_CTL + 2)] = 0xff;
    // ERP-less short-preamble, short-slot capability; legacy station.
    if station::configure_rates(&io, 0xfff, 0x15, 0x420, None, false) != Ok((true, true)) {
        return TestResult::Fail("8723BE configure_rates");
    }
    {
        let g = io.0.lock();
        let r = |a: u16| g.regs[usize::from(a)];
        if r(station::REG_RRSR) != 0x15
            || r(station::REG_INIRTS_RATE_SEL) != 4
            || r(station::REG_SLOT) != 9
            || r(station::REG_SIFS_CTX + 1) != 0x0a
            || r(station::REG_SIFS_TRX + 1) != 0x0a
            || r(station::REG_RESP_SIFS_OFDM) != 0x0e
            || r(station::REG_RESP_SIFS_OFDM + 1) != 0x0e
            || r(station::REG_TRXPTCL_CTL + 2) != 0xff
            || !g.writes.contains(&(station::REG_EDCA_BK_PARAM, 0xa44f, 4))
            || g.writes.iter().any(|w| w.0 == 0x0508)
        {
            return TestResult::Fail("8723BE station access/qos rows");
        }
    }
    let mut receive = station::ReceiveConfig {
        rcr: mac::RCR,
        bcn_ctrl: 0x1f,
    };
    io.0.lock().regs[usize::from(station::MSR)] = 0x0c;
    if station::network_type_station(&io, &mut receive, true).is_err() {
        return TestResult::Fail("8723BE network type");
    }
    let g = io.0.lock();
    if g.regs[usize::from(station::MSR)] != 0x0e
        || g.regs[usize::from(station::REG_BCNTCFG + 1)] != 0x66
        || receive.rcr != mac::RCR | station::RCR_CBSSID_DATA | station::RCR_CBSSID_BCN
        || receive.bcn_ctrl != 0x1f & !(1 << 1) & !(1 << 4)
        || g.regs[usize::from(h2c::REG_BCN_CTRL)] != receive.bcn_ctrl
    {
        return TestResult::Fail("8723BE media status / check BSSID");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_station_registers_and_rsvd_page
);
