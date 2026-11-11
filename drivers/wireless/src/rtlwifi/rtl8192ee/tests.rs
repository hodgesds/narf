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
    // Row-for-row identity (a `static` initialised from another static's
    // slice need not share its address once relocated).
    let rows = |f: &[WlanPwrCfg]| -> Vec<(u16, u8, u8, u8, u8, u8)> {
        f.iter()
            .map(|r| (r.offset, r.cut_msk, r.fab_intf, r.base_cmd, r.msk, r.value))
            .collect()
    };
    if rows(RTL8192EE_PWR_ON) != rows(pwrseq::RTL8192E_CARD_ENABLE_FLOW) {
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

// ── TRX flow ──────────────────────────────────────────────────────────────

fn smoke_rtl8192ee_tx_buffer_descriptor_segments_and_psb() -> TestResult {
    use trx::TxBufferDesc;
    // 216 + 40 = 256 fits one 256-byte page; 217 needs two.
    let one = TxBufferDesc::fill(0x1000_0000, 0x2000_0000, 216);
    let two = TxBufferDesc::fill(0x1000_0040, 0x2000_1000, 217);
    if one.psb() != 1 || two.psb() != 2 {
        return TestResult::Fail("PSB page count");
    }
    if one.dw[0] & 0x3fff != 40
        || one.dw[1] != 0x1000_0000
        || one.dw[2] != 0
        || one.dw[4] != 216
        || one.dw[5] != 0x2000_0000
        || one.dw[6] != 0
        || one.dw[8..].iter().any(|&w| w != 0)
        || one.own()
        || one.frame_addr() != 0x2000_0000
    {
        return TestResult::Fail("segment 0/1 layout or stale segments 2/3");
    }
    let mut beacon = one;
    beacon.set_own();
    if !beacon.own() || trx::TX_BD_SIZE != 64 || trx::RX_BD_SIZE != 16 {
        return TestResult::Fail("beacon OWN / BD sizes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ee",
    smoke_rtl8192ee_tx_buffer_descriptor_segments_and_psb
);

fn smoke_rtl8192ee_tx_descriptor_fields() -> TestResult {
    use trx::{TxDesc, TxParams};
    let d = TxDesc::fill(&TxParams {
        pkt_size: 100,
        queue_sel: trx::QSLT_MGNT,
        macid: 0,
        rate_id: 7,
        hw_rate: trx::DESC_RATE1M,
        use_driver_rate: true,
        disable_fallback: true,
        seq: 0x123,
        multicast: true,
        protection: 1,
        rts_rate: trx::DESC_RATE24M,
        tx_report: Some(0x24),
        buffer_addr: 0x3000_0000,
        ..TxParams::default()
    });
    let w = d.dw;
    if w[0] & 0xffff != 100
        || (w[0] >> 16) & 0xff != 40
        || w[0] & (1 << 24) == 0
        || w[0] & (3 << 26) != 3 << 26
        || w[0] & (1 << 31) != 0
        || (w[1] >> 8) & 0x1f != u32::from(trx::QSLT_MGNT)
        || (w[1] >> 16) & 0x1f != 7
        || w[2] & (1 << 19) == 0
        || w[3] & (1 << 8) == 0
        || w[3] & (1 << 10) == 0
        || w[3] & (1 << 12) == 0
        || w[3] & (1 << 11) != 0
        || (w[4] >> 8) & 0x1f != 0x1f
        || (w[4] >> 13) & 0xf != 0xf
        || (w[4] >> 24) & 0x1f != u32::from(trx::DESC_RATE24M)
        || w[6] & 0xfff != 0x24
        || w[7] & 0xffff != 100
        || (w[9] >> 12) & 0xfff != 0x123
        || w[10] != 0x3000_0000
        || w[12] != 0
    {
        return TestResult::Fail("rtl92ee_tx_fill_desc field placement");
    }
    let ht = TxDesc::fill(&TxParams {
        pkt_size: 1500,
        hw_rate: trx::DESC_RATEMCS0 + 7,
        ampdu: true,
        ampdu_density: 5,
        data_bw: 1,
        sub_carrier: 3,
        sec_type: 3,
        ..TxParams::default()
    });
    if ht.dw[2] & (1 << 12) == 0
        || (ht.dw[3] >> 17) & 0x1f != 0x14
        || (ht.dw[2] >> 20) & 7 != 5
        || (ht.dw[4] >> 5) & 3 != 1
        || ht.dw[5] & 0xf != 3
        || (ht.dw[1] >> 22) & 3 != 3
    {
        return TestResult::Fail("A-MPDU / BW40 / CCMP fields");
    }
    let c = TxDesc::command(1240, 0x4000_0000);
    if c.dw[0] & 0xffff != 1240
        || c.dw[0] & (1 << 31) == 0
        || (c.dw[1] >> 8) & 0x1f != u32::from(trx::QSLT_BEACON)
        || (c.dw[1] >> 16) & 0x1f != 7
        || c.dw[3] & (1 << 8) == 0
        || c.dw[7] & 0xffff != 1240
        || c.dw[10] != 0x4000_0000
    {
        return TestResult::Fail("rtl92ee_tx_fill_cmddesc");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ee",
    smoke_rtl8192ee_tx_descriptor_fields
);

fn smoke_rtl8192ee_rx_buffer_descriptor_and_status() -> TestResult {
    use trx::{RxBufferDesc, RxStatus};
    let bd = RxBufferDesc::prepare(0x5000_0000);
    if bd.dw[0] != 8192 + 24 || bd.dw[1] != 0x5000_0000 || bd.dw[2] != 0 || bd.dma_done() {
        return TestResult::Fail("HW_DESC_RX_PREPARE");
    }
    let done = RxBufferDesc::from_words([(1 << 15) | (1 << 16) | (300 << 16), 0, 0, 0]);
    if !done.dma_done() || !done.first_segment() || !done.last_segment() {
        return TestResult::Fail("BD FS/LS/total length");
    }
    let mut b = [0u8; trx::RX_DESC_SIZE];
    let d0: u32 = 300 | (1 << 14) | (4 << 16) | (2 << 24) | (1 << 26) | (1 << 27);
    b[..4].copy_from_slice(&d0.to_le_bytes());
    b[4..8].copy_from_slice(&((1u32 << 15) | 3).to_le_bytes());
    b[8..12].copy_from_slice(&(1u32 << 28).to_le_bytes());
    b[12..16].copy_from_slice(&((1u32 << 31) | (1 << 30) | 0x13).to_le_bytes());
    b[20..24].copy_from_slice(&0xdead_beefu32.to_le_bytes());
    let s = RxStatus::decode(&b);
    if s.pkt_len != 300
        || !s.crc
        || s.icv
        || s.drvinfo != 32
        || s.shift != 2
        || !s.physt
        || s.decrypted
        || s.macid != 3
        || !s.ampdu
        || !s.c2h
        || s.rate != 0x13
        || s.tsfl != 0xdead_beef
        || s.wake_match != 2
        || s.payload_offset() != 24 + 32 + 2
    {
        return TestResult::Fail("rtl92ee_rx_query_desc decode");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ee",
    smoke_rtl8192ee_rx_buffer_descriptor_and_status
);

fn smoke_rtl8192ee_ring_pointer_arithmetic() -> TestResult {
    use trx::*;
    if fifo_space(0, 0, 512) != 511
        || fifo_space(5, 3, 512) != 1
        || fifo_space(3, 5, 512) != 509
        || available((7 << 16) | 7) != 511
        || tx_points(0xffff_ffff) != (0xfff, 0xfff)
        || rx_points(0xffff_ffff) != (0x7ff, 0x7ff)
    {
        return TestResult::Fail("calc_fifo_space / index decode");
    }
    // wp > rp: [rp, wp) open.
    if tx_desc_closed(2, 5, 3) || !tx_desc_closed(2, 5, 5) || !tx_desc_closed(2, 5, 1) {
        return TestResult::Fail("closed, wp > rp");
    }
    // wp < rp (wrapped): (wp, rp) closed.
    if !tx_desc_closed(5, 2, 3) || tx_desc_closed(5, 2, 6) || tx_desc_closed(5, 2, 2) {
        return TestResult::Fail("closed, wp < rp");
    }
    if tx_desc_closed(4, 4, 4) || !tx_desc_closed(4, 4, 3) {
        return TestResult::Fail("closed, wp == rp");
    }
    if Queue::Beacon.index_register() != REG_BEQ_TXBD_IDX
        || Queue::High.index_register() != REG_HI0Q_TXBD_IDX
        || Queue::Beacon.entries() != 2
        || Queue::Be.entries() != 512
    {
        return TestResult::Fail("queue index map / ring sizes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ee",
    smoke_rtl8192ee_ring_pointer_arithmetic
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    W8(u16, u8),
    W16(u16, u16),
    W32(u16, u32),
}
#[derive(Clone)]
struct MacFake(Arc<IrqSafeSpinLock<(Vec<u8>, Vec<Op>)>>);
#[async_trait::async_trait]
impl Io for MacFake {
    fn read8(&self, reg: u16) -> Result<u8, FwError> {
        Ok(self.0.lock().0[usize::from(reg)])
    }
    fn read32(&self, reg: u16) -> Result<u32, FwError> {
        let g = self.0.lock();
        let r = usize::from(reg);
        Ok(u32::from_le_bytes([
            g.0[r],
            g.0[r + 1],
            g.0[r + 2],
            g.0[r + 3],
        ]))
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

/// `_rtl92ee_init_mac` remainder: no `REG_CR` write, exact LLT boundary
/// sequence, BD ring bases (not TX descriptor rings) and `TXBD_NUM` counts.
fn smoke_rtl8192ee_init_mac_llt_ring_bases_and_bd_counts() -> TestResult {
    let mut regs = vec![0u8; 0x800];
    regs[0x10c] = 0xff;
    regs[0x10d] = 0xff;
    regs[0x41] = 0xff;
    let io = MacFake(Arc::new(IrqSafeSpinLock::new((regs, Vec::new()))));
    let rings = mac::Rings {
        beacon: 0x1000,
        mgnt: 0x2000,
        vo: 0x3000,
        vi: 0x4000,
        be: 0x5000,
        bk: 0x6000,
        high: 0x7000,
        rx: 0x8000,
    };
    if narf_scheduler::block_on(mac::init_mac(&io, &rings)).is_err() {
        return TestResult::Fail("init_mac failed on the model");
    }
    let g = io.0.lock();
    let ops = &g.1;
    if ops.iter().any(|o| {
        matches!(
            o,
            Op::W8(0x100..=0x101, _) | Op::W16(0x100, _) | Op::W32(0x100, _)
        )
    }) {
        return TestResult::Fail("REG_CR opened before the packet owner");
    }
    let llt = [
        Op::W32(mac::REG_RQPN, 0x80e6_0808),
        Op::W8(mac::REG_TRXFF_BNDY, 0xf7),
        Op::W16(mac::REG_TRXFF_BNDY + 2, 0x3cff),
    ];
    let at = match ops.iter().position(|o| *o == llt[0]) {
        Some(at) => at,
        None => return TestResult::Fail("LLT RQPN missing"),
    };
    if ops[at..at + 3] != llt || ops[0] != Op::W8(mac::REG_HWSEQ_CTRL, 0x7f) {
        return TestResult::Fail("LLT / HWSEQ order");
    }
    if g.0[usize::from(mac::REG_AUTO_LLT) + 2] & 1 == 0
        || g.0[0x45d] != 0xf7
        || g.0[usize::from(mac::REG_PBP)] != 0x31
        || g.0[0x41] & 0x10 != 0
        || g.0[8] & 8 == 0
    {
        return TestResult::Fail("auto LLT / boundaries / clocks");
    }
    let word = u16::from_le_bytes([g.0[0x10c], g.0[0x10d]]);
    if word != 0xf5bf
        || !ops.contains(&Op::W32(mac::REG_RCR, 0xf000_710e))
        || !ops.contains(&Op::W32(mac::REG_TCR, 0x8200))
        || !ops.contains(&Op::W16(mac::REG_RXFLTMAP2, 0xffff))
    {
        return TestResult::Fail("TRXDMA_CTRL / RCR / TCR / RXFLTMAP2");
    }
    for (reg, base) in [
        (mac::REG_BCNQ_DESA, 0x1000),
        (mac::REG_MGQ_DESA, 0x2000),
        (mac::REG_VOQ_DESA, 0x3000),
        (mac::REG_VIQ_DESA, 0x4000),
        (mac::REG_BEQ_DESA, 0x5000),
        (mac::REG_BKQ_DESA, 0x6000),
        (mac::REG_HQ0_DESA, 0x7000),
        (mac::REG_RX_DESA, 0x8000),
    ] {
        if !ops.contains(&Op::W32(reg, base)) {
            return TestResult::Fail("BD ring base missing");
        }
    }
    let txbd = ops
        .iter()
        .filter(|o| matches!(o, Op::W16(r, 0x1200) if (0x380..=0x39a).contains(r)))
        .count();
    if txbd != 14
        || !ops.contains(&Op::W16(mac::REG_RX_RXBD_NUM, 0xa200))
        || ops.last() != Some(&Op::W32(mac::REG_TSFTIMER_HCI, 0xffff_ffff))
        || g.0[0x303] != 0xf7
    {
        return TestResult::Fail("TXBD/RXBD counts / TSFTIMER_HCI / PCIE_CTRL+3");
    }
    drop(g);
    if mac::release_cr(&io).is_err() || io.0.lock().1.last() != Some(&Op::W16(mac::REG_CR, 0x2ff)) {
        return TestResult::Fail("deferred CR release");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ee",
    smoke_rtl8192ee_init_mac_llt_ring_bases_and_bd_counts
);

// ── tables / headerfile ───────────────────────────────────────────────────

fn selected(rows: &[[u32; 2]], board: u8) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    let condition = headerfile::Condition { board_type: board };
    headerfile::walk::<()>(rows, &condition, |a, d| {
        out.push((a, d));
        Ok(())
    })
    .unwrap();
    out
}

/// Independent reading of the shipped tables: every `0xFF010718` branch
/// condition names platform `0x01`, which `_check_condition`'s `_platform
/// 0x08` never matches, so only unconditional rows and `else` parts apply.
fn else_only(rows: &[[u32; 2]]) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    let mut emit = true;
    for &[a, d] in rows {
        match (a >= headerfile::CONDITION_ROW, d) {
            (true, 0xabcd) => emit = false,
            (true, 0xcdcd) => emit = true,
            (true, 0xdead) => emit = true,
            (true, _) => panic!("unexpected condition row"),
            (false, _) if emit => out.push((a, d)),
            _ => {}
        }
    }
    out
}

pub(crate) fn smoke_rtl8192ee_tables_and_check_condition_walk() -> TestResult {
    if tables::PHY_REG.len() * 2 != 448
        || tables::PHY_REG_PG.len() * 6 != 168
        || tables::RADIOA.len() * 2 != 238
        || tables::RADIOB.len() * 2 != 198
        || tables::MAC.len() * 2 != 202
        || tables::AGC.len() * 2 != 532
        || tables::SOURCE_SHA256
            != "d3bc9536614b71b471b440e0f770e2651f906f224d2f1f0b70488e3e4807937e"
    {
        return TestResult::Fail("table geometry / source digest");
    }
    let c = |board| headerfile::Condition { board_type: board };
    if c(0x18).check(0xff01_0718)
        || !c(0).check(headerfile::CONDITION_ROW)
        || !c(5).check(0x000f_0705)
        || c(6).check(0x000f_0705)
        || c(5).check(0x000f_0105)
        || !c(9).check(0x000f_07ff)
    {
        return TestResult::Fail("_check_condition board/interface/platform masks");
    }
    for rows in [tables::PHY_REG, tables::AGC, tables::RADIOA, tables::RADIOB] {
        for board in [0, 0x18, 0xff] {
            if selected(rows, board) != else_only(rows) {
                return TestResult::Fail("walk differs from the else-branch reading");
            }
        }
    }
    let phy = selected(tables::PHY_REG, 0);
    if !phy.contains(&(0xc50, 0x0034_0020)) || phy.contains(&(0xc50, 0x0034_0220)) {
        return TestResult::Fail("PHY_REG 0xc50 branch");
    }
    // A discarded branch without `else`: Linux re-examines the DEAD row as a
    // condition and discards forward from it; the last row is then data.
    // Branch rows need `v1 >= 0xcdcdcdcd` (rtl8192ee/phy.c:682); board 5,
    // any interface (0x07), any platform (0x0f).
    let quirk = [
        [0xff0f_0705, 0xabcd],
        [0x800, 1],
        [0xff0f_0705, 0xdead],
        [0x804, 2],
        [0x808, 3],
    ];
    if selected(&quirk, 6) != vec![(0x808, 3)]
        || selected(&quirk, 5) != vec![(0x800, 1), (0x804, 2), (0x808, 3)]
    {
        return TestResult::Fail("terminator re-examination arithmetic");
    }
    if headerfile::bb_action(0xfe, 0) != headerfile::BbAction::DelayUs(50_000)
        || headerfile::bb_action(0xf9, 0) != headerfile::BbAction::DelayUs(1)
        || headerfile::bb_action(0x800, 7)
            != (headerfile::BbAction::Write {
                addr: 0x800,
                data: 7,
            })
        || headerfile::rf_action(0xffe, 0) != headerfile::RfAction::DelayUs(50_000)
    {
        return TestResult::Fail("bb/rf row actions");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ee",
    smoke_rtl8192ee_tables_and_check_condition_walk
);

// ── card disable (`_rtl92ee_poweroff_adapter`) ────────────────────────────

struct OffModel(IrqSafeSpinLock<PwrState>);
#[async_trait::async_trait]
impl Io for OffModel {
    fn read8(&self, reg: u16) -> Result<u8, FwError> {
        Ok(self.0.lock().0[usize::from(reg)])
    }
    fn read32(&self, reg: u16) -> Result<u32, FwError> {
        let g = self.0.lock();
        let r = usize::from(reg);
        Ok(u32::from_le_bytes([
            g.0[r],
            g.0[r + 1],
            g.0[r + 2],
            g.0[r + 3],
        ]))
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), FwError> {
        let mut g = self.0.lock();
        // The modelled power FSM completes 0x05[1:0] requests immediately.
        g.0[usize::from(reg)] = if reg == 5 { value & !3 } else { value };
        g.1.push((reg, value));
        Ok(())
    }
    fn write32(&self, _reg: u16, _value: u32) -> Result<(), FwError> {
        Err(FwError::Access)
    }
    fn write_bytes(&self, _reg: u16, _bytes: &[u8]) -> Result<(), FwError> {
        Err(FwError::Access)
    }
    async fn delay_us(&self, _micros: u64) {}
}

/// `_rtl92ee_poweroff_adapter` order on the rebuild owner's power-down:
/// LPS-enter flow, `REG_RF_CTRL = 0`, firmware self-reset only with
/// MCUFWDL BIT(7) and ready firmware, MCU reset, MCUFWDL 0, disable flow,
/// RSV_CTRL+1 BIT(0) pulse, RSV_CTRL `0x0e`.
fn smoke_rtl8192ee_poweroff_adapter_order() -> TestResult {
    use crate::rtlwifi::power_runtime::disable_rtl8192ee;
    let model = |ready_bit: bool| {
        let mut regs = vec![0u8; 0x800];
        regs[0x80] = if ready_bit { 0xc6 } else { 0x46 };
        regs[0x1d] = 1;
        regs[3] = 0xfc;
        regs[0x1f] = 7;
        OffModel(IrqSafeSpinLock::new((regs, Vec::new())))
    };
    let io = model(true);
    if narf_scheduler::block_on(disable_rtl8192ee(&io, true)).is_err() {
        return TestResult::Fail("8192EE poweroff failed on an idle model");
    }
    let g = io.0.lock();
    let w = &g.1;
    let at = |reg: u16, value: u8| w.iter().position(|&x| x == (reg, value));
    let (Some(rf), Some(fw0), Some(mcu0), Some(fwdl), Some(last)) = (
        at(0x1f, 0),
        at(0x1d, 0),
        w.iter().rposition(|&x| x == (3, 0xf8)),
        at(0x80, 0),
        w.last().copied(),
    ) else {
        return TestResult::Fail("8192EE poweroff write missing");
    };
    let selfreset = w.iter().filter(|&&x| x == (3, 0xfc)).count();
    if !(rf < fw0 && fw0 < mcu0 && mcu0 < fwdl)
        || selfreset != 1
        || last != (0x1c, 0x0e)
        || w[w.len() - 2] != (0x1d, 1)
        || w[w.len() - 3] != (0x1d, 0)
        || g.0[5] & 4 == 0
    {
        return TestResult::Fail("8192EE poweroff order / final state");
    }
    drop(g);
    let cold = model(false);
    if narf_scheduler::block_on(disable_rtl8192ee(&cold, true)).is_err()
        || cold.0.lock().1.contains(&(3, 0xfc))
    {
        return TestResult::Fail("self-reset issued without MCUFWDL BIT7");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtl8192ee_poweroff_adapter_order
);
