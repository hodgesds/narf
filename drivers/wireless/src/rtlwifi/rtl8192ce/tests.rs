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

// ── TRX descriptors ───────────────────────────────────────────────────────

/// `rtl92ce_tx_fill_desc` field positions (`trx.h`) for a 40 MHz HT A-MPDU
/// QoS data frame with RTS/CTS, and the non-QoS fwctrl_lps hardware sequence.
fn smoke_rtl8192ce_tx_descriptor_fields() -> TestResult {
    let p = trx::TxParams {
        pkt_size: 1500,
        queue_sel: trx::QSLT_BE,
        macid: 1,
        rate_id: 0,
        hw_rate: trx::DESC_RATEMCS0 + 7,
        use_driver_rate: true,
        short: true,
        bw_40: true,
        packet_bw_40: true,
        prime_sc: 1,
        ampdu: true,
        ampdu_density: 5,
        sec_type: 3,
        qos_data: true,
        fwctrl_lps: true,
        seq: 0x123,
        multicast: false,
        protection: 1,
        buffer_addr: 0x1234_5000,
    };
    let dw = trx::fill(&p);
    let want0 = 1500 | (32 << 16) | (1 << 26) | (1 << 27);
    let want1 = 1 | (1 << 5) | (u32::from(trx::QSLT_BE) << 8) | (3 << 22);
    let want4 =
        u32::from(trx::DESC_RATE24M) | (1 << 8) | (1 << 12) | (1 << 13) | (3 << 20) | (1 << 25);
    let want5 = 0x13 | (1 << 6) | (0x1f << 8) | (0xf << 13);
    if dw[0] != want0
        || dw[1] != want1
        || dw[2] != 5 << 20
        || dw[3] != 0x123 << 16
        || dw[4] != want4
        || dw[5] != want5
        || dw[6] != 0x14 << 11
        || dw[7] != 1500
        || dw[8] != 0x1234_5000
        || dw[9] != 0
        || trx::own(dw[0])
    {
        return TestResult::Fail("92C TX descriptor field layout");
    }
    // CTS-to-self: RTS_ENABLE clear, HW_RTS + CTS2SELF set; 20 MHz frame in
    // a 40 MHz BSS uses the primary sub-carrier; non-QoS + fwctrl_lps.
    let q = trx::TxParams {
        protection: 2,
        packet_bw_40: false,
        qos_data: false,
        multicast: true,
        ampdu: false,
        ..p
    };
    let dw = trx::fill(&q);
    if dw[4] & (1 << 12) != 0
        || dw[4] & (1 << 13) == 0
        || dw[4] & (1 << 11) == 0
        || (dw[4] >> 20) & 3 != 1
        || dw[4] & (1 << 25) != 0
        || dw[4] & (1 << 7) == 0
        || dw[3] >> 28 != 8
        || dw[0] & (1 << 24) == 0
        || dw[6] != 0
    {
        return TestResult::Fail("CTS-to-self / prime sub-carrier / hwseq / BMC");
    }
    let mut cmd = trx::fill_cmd(256, 0x2000, false);
    if trx::queue_sel(&cmd) != trx::QSLT_BEACON
        || (cmd[1] >> 16) & 0xf != 7
        || trx::pkt_size(&cmd) != 256
        || cmd[7] != 256
        || cmd[4] & (1 << 8) == 0
        || trx::tx_rate(&cmd) != trx::DESC_RATE1M
    {
        return TestResult::Fail("rtl92ce_tx_fill_cmddesc fields");
    }
    trx::set_own(&mut cmd, true);
    if !trx::own(cmd[0]) {
        return TestResult::Fail("TX OWN bit");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ce",
    smoke_rtl8192ce_tx_descriptor_fields
);

fn smoke_rtl8192ce_rx_descriptor_status_and_arm() -> TestResult {
    let mut dw = [0u32; 8];
    trx::rx_arm(&mut dw, 0x4000, 9100, true);
    if dw[6] != 0x4000
        || dw[0] != 9100 | (1 << 30) | (1 << 31)
        || trx::RxStatus::parse(&dw).is_some()
    {
        return TestResult::Fail("RX arm / hardware-owned descriptor parsed");
    }
    dw[0] = 200 | (1 << 14) | (4 << 16) | (2 << 24) | (1 << 26) | (1 << 27);
    dw[1] = (1 << 14) | (1 << 15);
    dw[3] = 0x13 | (1 << 6) | (1 << 8) | (1 << 9);
    dw[5] = 0xdead_beef;
    let s = match trx::RxStatus::parse(&dw) {
        Some(s) => s,
        None => return TestResult::Fail("driver-owned RX descriptor"),
    };
    if s.length != 200
        || !s.crc
        || s.icv
        || s.drvinfo_size != 32
        || s.shift != 2
        || !s.physt
        || s.decrypted
        || !s.ampdu
        || !s.first_ampdu
        || s.rate != 0x13
        || !s.ht
        || !s.short_preamble
        || !s.bw_40
        || s.tsfl != 0xdead_beef
        || s.payload_offset() != 34
        || !s.hw_error()
        || s.is_cck()
    {
        return TestResult::Fail("rtl92ce_rx_query_desc fields");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ce",
    smoke_rtl8192ce_rx_descriptor_status_and_arm
);

/// `_rtl92ce_query_rxphystatus` `rx_pwdb_all`: OFDM `pwdb_all`, CCK
/// `cck_agc_rpt` with and without `cck_highpwr`, the +6 cap and the four
/// offset bands.
fn smoke_rtl8192ce_rx_phy_status_pwdb() -> TestResult {
    let phy = |b4: u8, b5: u8| [0, 0, 0, 0, b4, b5, 0, 0];
    let cases: [(u8, u8, bool, bool, u8); 8] = [
        // (pwdb_all, cck_agc_rpt, cck, highpwr, expected)
        (0x80, 0, false, false, 54),
        (0x80, 0xc4, true, false, 56),
        (0, 0x60, true, false, 62),
        (0, 0x00, true, false, 100),
        (0, 0xfe, true, false, 2),
        (0, 0xde, true, false, 24),
        (0, 0x7f, true, true, 2),
        (0, 0x25, true, true, 84),
    ];
    for (b4, b5, cck, high, want) in cases {
        if trx::rx_pwdb(&phy(b4, b5), cck, high) != Some(want) {
            return TestResult::Fail("92CE PHY-status rx_pwdb_all");
        }
    }
    if trx::rx_pwdb(&[0; 5], false, false).is_some() {
        return TestResult::Fail("short PHY status decoded");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ce",
    smoke_rtl8192ce_rx_phy_status_pwdb
);

// ── LLT / MAC ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    W8(u16, u8),
    W16(u16, u16),
    W32(u16, u32),
}
#[derive(Clone)]
struct MacFake(Arc<IrqSafeSpinLock<(Vec<u8>, Vec<Op>)>>);
impl MacFake {
    fn new() -> Self {
        Self(Arc::new(IrqSafeSpinLock::new((vec![0; 0x800], Vec::new()))))
    }
    fn ops(&self) -> Vec<Op> {
        self.0.lock().1.clone()
    }
}
#[async_trait::async_trait]
impl Io for MacFake {
    fn read8(&self, reg: u16) -> Result<u8, FwError> {
        Ok(self.0.lock().0[usize::from(reg)])
    }
    fn read32(&self, reg: u16) -> Result<u32, FwError> {
        let g = self.0.lock();
        let r = usize::from(reg);
        // The modelled LLT engine completes every write at once.
        let v = u32::from_le_bytes([g.0[r], g.0[r + 1], g.0[r + 2], g.0[r + 3]]);
        Ok(if reg == llt::REG_LLT_INIT {
            v & 0x3fff_ffff
        } else {
            v
        })
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), FwError> {
        let mut g = self.0.lock();
        g.0[usize::from(reg)] = value;
        g.1.push(Op::W8(reg, value));
        Ok(())
    }
    fn write16(&self, reg: u16, value: u16) -> Result<(), FwError> {
        let mut g = self.0.lock();
        let r = usize::from(reg);
        g.0[r..r + 2].copy_from_slice(&value.to_le_bytes());
        g.1.push(Op::W16(reg, value));
        Ok(())
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), FwError> {
        let mut g = self.0.lock();
        let r = usize::from(reg);
        g.0[r..r + 4].copy_from_slice(&value.to_le_bytes());
        g.1.push(Op::W32(reg, value));
        Ok(())
    }
    fn write_bytes(&self, _reg: u16, _bytes: &[u8]) -> Result<(), FwError> {
        Err(FwError::Access)
    }
    async fn delay_us(&self, _micros: u64) {}
}
struct LltView<'a>(&'a MacFake);
impl llt::Regs for LltView<'_> {
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
}

/// `_rtl92ce_llt_table_init` (`LLT_CONFIG == 5`) order, boundary 246 and the
/// 256 LLT links; then the `_rtl92ce_init_mac` remainder per RF type.
fn smoke_rtl8192ce_llt_and_init_mac_remainder() -> TestResult {
    let io = MacFake::new();
    if llt::init(&LltView(&io)).is_err() {
        return TestResult::Fail("LLT init on a completing model");
    }
    let ops = io.ops();
    let head = [
        Op::W16(0x214, 0),
        Op::W32(0x200, 0x80b0_1c29),
        Op::W32(0x114, 0x27ff_00f6),
        Op::W8(0x209, 246),
        Op::W8(0x424, 246),
        Op::W8(0x425, 246),
        Op::W8(0x45d, 246),
        Op::W8(0x104, 0x11),
        Op::W8(0x60f, 4),
    ];
    let links: Vec<u32> = ops[head.len()..]
        .iter()
        .filter_map(|op| match op {
            Op::W32(0x1e0, v) => Some(*v),
            _ => None,
        })
        .collect();
    if ops[..head.len()] != head[..]
        || links.len() != 256
        || links[0] != (1 << 30) | 1
        || links[245] != (1 << 30) | (245 << 8) | 0xff
        || links[246] != (1 << 30) | (246 << 8) | 247
        || links[255] != (1 << 30) | (255 << 8) | 246
        || ops.len() != head.len() + 256
    {
        return TestResult::Fail("92CE LLT order / links");
    }
    for (is_92c, pcie) in [(true, 0x77), (false, 0x22)] {
        let io = MacFake::new();
        io.0.lock().0[usize::from(mac::REG_TRXDMA_CTRL)] = 0x0a;
        if narf_scheduler::block_on(mac::init_mac(&io, is_92c)).is_err() {
            return TestResult::Fail("init_mac remainder on a model");
        }
        let ops = io.ops();
        let want = [
            Op::W32(0x124, u32::MAX),
            Op::W8(0x12c, 0xff),
            Op::W16(0x116, 0x27ff),
            Op::W16(0x10c, 0xf77b),
            Op::W8(0x421, 0x1f),
            Op::W32(0x608, mac::RCR),
            Op::W32(0x604, mac::TCR),
            Op::W8(0x4d0, 0),
            Op::W8(0x303, pcie),
            Op::W32(0x304, 0),
            Op::W8(0x600, 0),
            Op::W32(0x1c0, 0),
        ];
        if ops[..] != want[..] || mac::RCR != 0xf000_6b0e || mac::TCR != 0x3200 {
            return TestResult::Fail("92CE init_mac remainder order / PCIE_CTRL+3 per RF type");
        }
    }
    let io = MacFake::new();
    if mac::hw_configure(&io).is_err() || mac::station_identity(&io, &[2, 0, 0, 0, 0, 1]).is_err() {
        return TestResult::Fail("hw_configure / station identity");
    }
    let ops = io.ops();
    if ops.len() != 31 + 7
        || ops[0] != Op::W8(0x480, 0x8)
        || !ops.contains(&Op::W32(0x458, 0xb972_a841))
        || !ops.contains(&Op::W32(0x460, 0x0008_6666))
        || !ops.contains(&Op::W16(0x420, 0x1f80))
        || ops[31] != Op::W8(0x680, 0)
        || ops[37] != Op::W8(0x615, 1)
    {
        return TestResult::Fail("_rtl92ce_hw_configure / ETHER_ADDR writes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ce",
    smoke_rtl8192ce_llt_and_init_mac_remainder
);

/// The linked-ring profile: 88EE geometry with the 92C next link at dword 10.
fn smoke_rtl8192ce_linked_ring_profile() -> TestResult {
    use crate::rtlwifi::prepare::Chip;
    for did in [0x8178, 0x8176, 0x8177, 0x8191] {
        if Chip::from_device(did) != Some(Chip::Rtl8192ce) {
            return TestResult::Fail("92CE IDs select the 92CE ring profile");
        }
    }
    if Chip::Rtl8192ce.next_desc_offset() != Some(40)
        // The 8192DE has its own linked-ring profile (d619c9ba5), never 92CE's.
        || Chip::from_device(crate::rtlwifi::regs::RTL_DEV_8192DE) != Some(Chip::Rtl8192de)
    {
        return TestResult::Fail("92CE next-descriptor offset / 8192DE excluded");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ce",
    smoke_rtl8192ce_linked_ring_profile
);

// ── tables ────────────────────────────────────────────────────────────────

/// `table.h` lengths and first/last pairs of the generated `table.c` arrays.
fn smoke_rtl8192ce_tables_verbatim_geometry() -> TestResult {
    let lens = [
        tables::PHY_REG_2T.len(),
        tables::PHY_REG_1T.len(),
        tables::PHY_REG_PG.len(),
        tables::RADIOA_2T.len(),
        tables::RADIOB_2T.len(),
        tables::RADIOA_1T.len(),
        tables::RADIOB_1T.len(),
        tables::MAC_2T.len(),
        tables::AGCTAB_2T.len(),
        tables::AGCTAB_1T.len(),
    ];
    if lens != [374, 374, 192, 282, 78, 282, 1, 162, 320, 320] {
        return TestResult::Fail("table.h array lengths");
    }
    // Every (address, value) table is pair-aligned; RADIOB_1T (1 word) is
    // never walked: a 1T1R part has num_total_rfpath = 1.
    let paired = [
        &tables::PHY_REG_2T[..],
        &tables::PHY_REG_1T[..],
        &tables::PHY_REG_PG[..],
        &tables::RADIOA_2T[..],
        &tables::RADIOB_2T[..],
        &tables::RADIOA_1T[..],
        &tables::MAC_2T[..],
        &tables::AGCTAB_2T[..],
        &tables::AGCTAB_1T[..],
    ];
    if paired.iter().any(|t| t.len() % 2 != 0) {
        return TestResult::Fail("odd-length pair table");
    }
    // PHY_REG (incl. the 0x24 AFE row) / AGC rows are MMIO dwords below
    // 0x1000; MAC rows are bytes in the MAC block.
    if tables::PHY_REG_2T
        .chunks(2)
        .chain(tables::AGCTAB_1T.chunks(2))
        .any(|r| r[0] >= 0x1000 || r[0] & 3 != 0)
        || tables::MAC_2T.chunks(2).any(|r| r[0] >= 0x800)
    {
        return TestResult::Fail("table address ranges");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ce",
    smoke_rtl8192ce_tables_verbatim_geometry
);
