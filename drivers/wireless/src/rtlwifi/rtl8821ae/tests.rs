// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821AE retained-runtime foundation tests (software models only; no
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
        // The modelled power FSM completes 0x04[1:0] requests immediately.
        g.0[usize::from(offset)] = if offset == 5 { value & !3 } else { value };
        g.1.push((offset, value));
        Ok(())
    }
    fn delay_us(&self, _micros: u64) {}
}

fn smoke_rtl8821ae_enable_flow_exact_cut_a() -> TestResult {
    let mut regs = vec![0u8; 0x400];
    regs[6] = 0x02; // power ready
    regs[0x301] = 0xff; // PCIe DMA stopped
    let model = PwrModel(IrqSafeSpinLock::new((regs, Vec::new())));
    if power_on_with(&model, crate::rtlwifi::regs::RTL_DEV_8821AE).is_err() {
        return TestResult::Fail("8821AE enable flow failed on a ready model");
    }
    let g = model.0.lock();
    let writes: Vec<u16> = g.1.iter().map(|w| w.0).collect();
    if writes.first() != Some(&0x1c) || writes.contains(&0x7a) || !writes.contains(&0x10) {
        return TestResult::Fail("8821AE prefix / PWR_CUT_A_MSK selection");
    }
    if g.0[0x2e] != 0x82 || g.0[0x301] != 0 || g.0[0x4f] & 1 == 0 || g.0[0x67] & 0x30 != 0x30 {
        return TestResult::Fail("8821AE CardEmu->Active register results");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_enable_flow_exact_cut_a
);

fn smoke_rtl8821ae_all_flows_pci_mac_and_terminated() -> TestResult {
    let flows: [&[WlanPwrCfg]; 7] = [
        pwrseq::RTL8821A_CARD_ENABLE_FLOW,
        pwrseq::RTL8821A_CARD_DISABLE_FLOW,
        pwrseq::RTL8821A_SUSPEND_FLOW,
        pwrseq::RTL8821A_RESUME_FLOW,
        pwrseq::RTL8821A_RADIO_OFF_FLOW,
        pwrseq::RTL8821A_ENTER_LPS_FLOW,
        pwrseq::RTL8821A_LEAVE_LPS_FLOW,
    ];
    for flow in flows {
        let (last, rows) = match flow.split_last() {
            Some(v) => v,
            None => return TestResult::Fail("empty 8821A flow"),
        };
        if last.cmd() != PWR_CMD_END
            || rows.iter().any(|r| {
                r.cmd() == PWR_CMD_END
                    || r.intf() & PWR_INTF_PCI_MSK == 0
                    || r.base() != PWR_BASEADDR_MAC
            })
        {
            return TestResult::Fail("8821A flow row not PCI/MAC or END misplaced");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_all_flows_pci_mac_and_terminated
);

// ── headerfile ────────────────────────────────────────────────────────────

fn provisioned_map() -> Vec<u8> {
    let mut map = vec![0xffu8; 512];
    map[0] = 0x29;
    map[1] = 0x81;
    map
}

fn smoke_rtl8821ae_condition_requires_factory_facts() -> TestResult {
    let map = provisioned_map();
    if headerfile::Condition::from_hardware(headerfile::TRP_VAUX_EN, 0, &map)
        != Err(headerfile::Error::TestChip)
    {
        return TestResult::Fail("test chip admitted");
    }
    if headerfile::Condition::from_hardware(0, 0, &[0xff; 512])
        != Err(headerfile::Error::Unprovisioned)
    {
        return TestResult::Fail("unprovisioned EFUSE admitted");
    }
    let mut ext = provisioned_map();
    ext[0xbc] = 1 << 5 | 1 << 1;
    ext[0xbd] = 0x80;
    ext[0xbf] = 0;
    let c = match headerfile::Condition::from_hardware(0x1000, 1 << 18, &ext) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("provisioned EFUSE rejected"),
    };
    let want = headerfile::ODM_BOARD_EXT_PA
        | headerfile::ODM_BOARD_EXT_PA_5G
        | headerfile::ODM_BOARD_EXT_LNA
        | headerfile::ODM_BOARD_BT;
    if c.cut != 1 || c.board_type != want || c.external_lna_5g {
        return TestResult::Fail("board_type / cut composition");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_condition_requires_factory_facts
);

fn smoke_rtl8821ae_headerfile_if_else_endif() -> TestResult {
    let c = match headerfile::Condition::from_hardware(0, 0, &provisioned_map()) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("default condition"),
    };
    // IF cut==1 (no match) / ELSE / ENDIF, then IF platform (matches).
    let table = [
        [0x800, 1],
        [0x8100_0000, 0],
        [0x804, 2],
        [0xa000_0000, 0],
        [0x808, 3],
        [0xb000_0000, 0],
        [0x80c, 4],
        [0x8004_0000, 0],
        [0x810, 5],
        [0x9100_0000, 0],
        [0x814, 6],
        [0xb000_0000, 0],
    ];
    let mut seen = Vec::new();
    let _ = headerfile::walk::<()>(&table, &c, |a, v| {
        seen.push((a, v));
        Ok(())
    });
    if seen != [(0x800, 1), (0x808, 3), (0x80c, 4), (0x810, 5)] {
        return TestResult::Fail("conditional selection order");
    }
    let mut mac = 0;
    let _ = headerfile::walk::<()>(tables::MAC, &c, |a, _| {
        if a < 0x800 {
            mac += 1;
        }
        Ok(())
    });
    if mac == 0 || headerfile::bb_action(0xfe, 0) != headerfile::BbAction::DelayUs(50_000) {
        return TestResult::Fail("MAC table / BB delay decode");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_headerfile_if_else_endif
);

fn smoke_rtl8821ae_power_limit_rows() -> TestResult {
    use power_limit::*;
    if limit(
        Regulation::Fcc,
        Band::B2g,
        Bandwidth::Bw20,
        Section::Cck,
        1,
        1,
    ) != Some(32)
    {
        return TestResult::Fail("FCC 2.4G CCK ch1 limit");
    }
    if limit(
        Regulation::Mkk,
        Band::B5g,
        Bandwidth::Bw80,
        Section::Vht,
        2,
        155,
    )
    .is_some()
    {
        return TestResult::Fail("unspecified (63) limit admitted");
    }
    if limit(
        Regulation::Fcc,
        Band::B2g,
        Bandwidth::Bw20,
        Section::Cck,
        1,
        200,
    )
    .is_some()
    {
        return TestResult::Fail("absent channel admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_power_limit_rows
);

// ── firmware ──────────────────────────────────────────────────────────────

/// First 32 bytes of linux-firmware `rtlwifi/rtl8821aefw_29.bin`
/// (sha256 11e7ea00504fa2fa6f5216bb59403c4f2f20eec5b676c0add0695db3b0c4a335,
/// 28348 bytes) and `rtl8821aefw_wowlan.bin`
/// (sha256 df6fe0f14f6c7755da351b8d02282dde1c190133c118a5ca9627b6fd87dfd5da,
/// 19858 bytes). Bodies are zero-filled: parser geometry only.
const HDR_29: [u8; 32] = [
    0x01, 0x21, 0x13, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x01, 0x21, 0x17, 0x43, 0x9c, 0x6e, 0x00, 0x00,
    0x3c, 0x1b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const HDR_WOWLAN: [u8; 32] = [
    0x01, 0x21, 0x30, 0x00, 0x14, 0x00, 0x00, 0x00, 0x10, 0x09, 0x10, 0x38, 0x72, 0x4d, 0x00, 0x00,
    0xa4, 0x0b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

fn image(header: &[u8; 32], total: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; total];
    bytes[..32].copy_from_slice(header);
    bytes
}

fn smoke_rtl8821ae_firmware_header_geometry() -> TestResult {
    let normal = image(&HDR_29, 28348);
    let wowlan = image(&HDR_WOWLAN, 19858);
    match (fw::parse(&normal), fw::parse(&wowlan)) {
        (Ok((n, np)), Ok((w, wp)))
            if n.version == 0x1d
                && n.payload == 28316
                && np.len() == 28316
                && w.version == 0x14
                && wp.len() == 19826 => {}
        _ => return TestResult::Fail("real 8821AE headers rejected"),
    }
    let mut bad = normal.clone();
    bad[12] ^= 1;
    let mut e1 = normal.clone();
    e1[0] = 0xe1;
    e1[1] = 0x88;
    if fw::parse(&bad).is_ok() || fw::parse(&e1).is_ok() || fw::parse(&normal[..32]).is_ok() {
        return TestResult::Fail("bad extent / 88E signature / header-only admitted");
    }
    let mut big = image(&HDR_29, 32 + fw::MAX_PAYLOAD + 4);
    let len = (fw::MAX_PAYLOAD + 4) as u16;
    big[12..14].copy_from_slice(&len.to_le_bytes());
    if fw::parse(&big).is_ok()
        || fw::Image::Normal.names() != [fw::FW_NORMAL, fw::FW_NORMAL_ALT]
        || fw::Image::Wowlan.names() != [fw::FW_WOWLAN]
    {
        return TestResult::Fail("oversize image / filename selection");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_firmware_header_geometry
);

struct FwModel {
    regs: Vec<u8>,
    pages: Vec<Vec<u8>>,
    resets: u32,
    checksum: bool,
}
#[derive(Clone)]
struct FwFake(Arc<IrqSafeSpinLock<FwModel>>);
#[async_trait::async_trait]
impl Io for FwFake {
    fn read8(&self, reg: u16) -> Result<u8, FwError> {
        Ok(self.0.lock().regs[usize::from(reg)])
    }
    fn read32(&self, reg: u16) -> Result<u32, FwError> {
        let g = self.0.lock();
        let r = usize::from(reg);
        let mut v = u32::from_le_bytes([g.regs[r], g.regs[r + 1], g.regs[r + 2], g.regs[r + 3]]);
        if reg == fw::REG_MCUFWDL {
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
        // FWDL_CHKSUM_RPT is write-one-to-clear.
        g.regs[usize::from(reg)] = if reg == fw::REG_MCUFWDL {
            value & !4
        } else {
            value
        };
        Ok(())
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), FwError> {
        let mut g = self.0.lock();
        let r = usize::from(reg);
        let value = if reg == fw::REG_MCUFWDL {
            value & !fw::FWDL_CHKSUM_RPT
        } else {
            value
        };
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
    })))
}

fn smoke_rtl8821ae_firmware_paged_download_and_selfreset() -> TestResult {
    let payload: Vec<u8> = (0..(2 * fw::PAGE + 5)).map(|i| i as u8).collect();
    let io = fw_fake(true);
    if narf_scheduler::block_on(fw::download(&io, &payload, true)).is_err() {
        return TestResult::Fail("8821AE model download failed");
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
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_firmware_paged_download_and_selfreset
);

/// The retained one-shot firmware owner admits the 8821AE profile with its
/// own header rule, clears CR packet gates and `REG_SYS_CFG[7]` before the
/// `rtl8821ae_download_fw` sequence, and refuses another family's image.
fn smoke_rtl8821ae_retained_firmware_owner_profile() -> TestResult {
    use crate::rtlwifi::firmware_transport::{parse, Owner, Stage};
    let normal = image(&HDR_29, 28348);
    let mut ee = normal.clone();
    ee[..2].copy_from_slice(&[0xe1, 0x88]);
    if parse(crate::rtlwifi::regs::RTL_DEV_8821AE, &normal).is_err()
        || parse(crate::rtlwifi::regs::RTL_DEV_8821AE, &ee).is_ok()
        || parse(crate::rtlwifi::regs::RTL_DEV_8188EE, &normal).is_ok()
    {
        return TestResult::Fail("per-profile header dispatch");
    }
    let io = fw_fake(true);
    {
        let mut g = io.0.lock();
        g.regs[0x100] = 0xff;
        g.regs[0xf0] = 0xff;
    }
    let owner = Owner::new(io.clone(), crate::rtlwifi::regs::RTL_DEV_8821AE);
    let info = match narf_scheduler::block_on(owner.initialize(&normal)) {
        Ok(info) => info,
        Err(_) => return TestResult::Fail("8821AE owner download failed"),
    };
    let g = io.0.lock();
    if info.version != 0x1d
        || info.payload != 28348 - 32
        || owner.status().stage != Stage::Ready
        || owner.identity().is_none()
        || g.regs[0x100] & 0xcf != 0
        || g.regs[0x100] & 0x30 != 0x30
        || g.regs[0xf0] != 0x7f
        || g.resets != 2
        || g.pages.len() != 7
    {
        return TestResult::Fail("8821AE owner gates / SYS_CFG / download");
    }
    drop(g);
    if narf_scheduler::block_on(owner.initialize(&normal))
        != Err(crate::rtlwifi::firmware_transport::Error::AlreadyStarted)
    {
        return TestResult::Fail("8821AE owner is not one-shot");
    }
    let rejected = Owner::new(fw_fake(true), crate::rtlwifi::regs::RTL_DEV_8821AE);
    if narf_scheduler::block_on(rejected.initialize(&ee))
        != Err(crate::rtlwifi::firmware_transport::Error::Image)
        || rejected.status().stage != Stage::Failed
    {
        return TestResult::Fail("8188EE image accepted by 8821AE owner");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_retained_firmware_owner_profile
);

// ── LLT ───────────────────────────────────────────────────────────────────

struct LltModel(IrqSafeSpinLock<Vec<(u16, u32, u8)>>);
impl llt::Regs for LltModel {
    fn read32(&self, _reg: u16) -> Result<u32, FwError> {
        Ok(0)
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), FwError> {
        self.0.lock().push((reg, value.into(), 1));
        Ok(())
    }
    fn write16(&self, reg: u16, value: u16) -> Result<(), FwError> {
        self.0.lock().push((reg, value.into(), 2));
        Ok(())
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), FwError> {
        self.0.lock().push((reg, value, 4));
        Ok(())
    }
}

fn smoke_rtl8821ae_llt_exact_chain() -> TestResult {
    let links: Vec<(u8, u8)> = llt::links().collect();
    if links.len() != 256
        || links[0] != (0, 1)
        || links[0xf6] != (0xf6, 0xff)
        || links[0xf7] != (0xf7, 0xf8)
        || links[255] != (0xff, 0xf7)
    {
        return TestResult::Fail("LLT link chain");
    }
    let m = LltModel(IrqSafeSpinLock::new(Vec::new()));
    if llt::init(&m).is_err() {
        return TestResult::Fail("LLT init on idle model");
    }
    let ops = m.0.lock();
    if ops.len() != 7 + 256 + 2
        || ops[1] != (0x116, 0x3e7f, 2)
        || ops[7] != (llt::REG_LLT_INIT, 0x4000_0001, 4)
        || ops[ops.len() - 2] != (llt::REG_RQPN, llt::RQPN, 4)
    {
        return TestResult::Fail("LLT init register order / widths");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_llt_exact_chain
);

// ── TRX + C2H ─────────────────────────────────────────────────────────────

fn smoke_rtl8821ae_tx_rx_descriptor_fields() -> TestResult {
    let p = trx::TxParams {
        pkt_size: 1500,
        queue_sel: trx::QSLT_BE,
        macid: 1,
        rate_id: 7,
        hw_rate: trx::DESC_RATEVHT1SS_MCS0 + 7,
        data_bw: 2,
        tx_report: Some(0x24),
        buffer_len: 1540,
        buffer_addr: 0x1234_5000,
        ..Default::default()
    };
    let mut d = trx::TxDesc::fill(&p);
    if d.own()
        || d.pkt_size() != 1500
        || d.macid() != 1
        || d.tx_rate() != 0x33
        || d.data_bw() != 2
        || d.sw_define() != Some(0x24)
        || d.dw[10] != 0x1234_5000
        || d.dw[0] & (3 << 26) != 3 << 26
        || (d.dw[0] >> 16) & 0xff != 40
        || d.dw[8] & (1 << 15) == 0
    {
        return TestResult::Fail("TX descriptor field placement");
    }
    d.set_own(true);
    if !d.own() {
        return TestResult::Fail("TX OWN");
    }
    let mut rx = [0u32; 8];
    trx::rx_arm(&mut rx, 0x8000_0000, 9100, true);
    if trx::RxStatus::parse(&rx).is_some() || rx[0] & (1 << 30) == 0 {
        return TestResult::Fail("armed RX descriptor parsed / EOR");
    }
    let mut done = [0u32; 8];
    done[0] = 64 | 4 << 16 | 1 << 26;
    done[2] = 1 << 28;
    done[3] = u32::from(trx::DESC_RATEVHT2SS_MCS0) | 1 << 31;
    done[4] = 2 << 4;
    let s = match trx::RxStatus::parse(&done) {
        Some(s) => s,
        None => return TestResult::Fail("driver-owned RX descriptor"),
    };
    if !s.c2h
        || s.payload_offset() != 32 + 32
        || s.vht_nss() != 2
        || !s.is_vht()
        || s.bw != 2
        || s.wake_match() != 2
    {
        return TestResult::Fail("RX status decode");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_tx_rx_descriptor_fields
);

fn smoke_rtl8821ae_c2h_tx_and_ra_reports() -> TestResult {
    let tx = [c2h::C2H_TX_REPORT, 0, 0x00, 0, 0x05, 0, 0, 0, 0x24];
    match c2h::parse(&tx) {
        Ok(
            e @ c2h::Event::TxReport {
                sn: 0x24,
                st: 0,
                retry: 5,
            },
        ) if e.acked() == Some(true) => {}
        _ => return TestResult::Fail("V1 TX report"),
    }
    let nack = [c2h::C2H_TX_REPORT, 0, 0x40, 0, 0, 0, 0, 0, 0x24];
    if c2h::parse(&nack).ok().and_then(|e| e.acked()) != Some(false)
        || c2h::parse(&tx[..8]) != Err(c2h::Error::Truncated)
    {
        return TestResult::Fail("TX report NACK / truncation");
    }
    let ra = [c2h::C2H_RA_RPT, 0, 0xc0 | trx::DESC_RATEVHT1SS_MCS0];
    if c2h::parse(&ra)
        != Ok(c2h::Event::RaReport {
            hw_rate: 0x2c,
            mgn_rate: 0x90,
        })
        || c2h::hw_rate_to_mrate(0x0b) != 0x6c
        || c2h::hw_rate_to_mrate(0x13) != 0x87
        || c2h::hw_rate_to_mrate(0x1c) != 0x02
    {
        return TestResult::Fail("RA report / rate mapping");
    }
    let mut st = c2h::TxReportState::default();
    let first = st.next_sn();
    for _ in 0..63 {
        st.next_sn();
    }
    st.record(st.last_sent_sn);
    if first != 4 || st.last_sent_sn != 0 || !st.all_acked() {
        return TestResult::Fail("SW_DEFINE sequence");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_c2h_tx_and_ra_reports
);

// ── Parked hw_init: init_mac remainder, MAC/BB/RF tables, hw_configure ────

/// (registers, ordered writes as (width, reg, value))
type RegState = (Vec<u8>, Vec<(u8, u16, u32)>);
struct RegFake(IrqSafeSpinLock<RegState>);
#[async_trait::async_trait]
impl Io for RegFake {
    fn read8(&self, reg: u16) -> Result<u8, FwError> {
        Ok(self.0.lock().0[usize::from(reg)])
    }
    fn read32(&self, reg: u16) -> Result<u32, FwError> {
        let g = self.0.lock();
        let r = usize::from(reg);
        Ok(u32::from_le_bytes(g.0[r..r + 4].try_into().unwrap()))
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), FwError> {
        let mut g = self.0.lock();
        g.0[usize::from(reg)] = value;
        g.1.push((1, reg, value.into()));
        Ok(())
    }
    fn write16(&self, reg: u16, value: u16) -> Result<(), FwError> {
        let mut g = self.0.lock();
        let r = usize::from(reg);
        g.0[r..r + 2].copy_from_slice(&value.to_le_bytes());
        g.1.push((2, reg, value.into()));
        Ok(())
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), FwError> {
        let mut g = self.0.lock();
        let r = usize::from(reg);
        g.0[r..r + 4].copy_from_slice(&value.to_le_bytes());
        g.1.push((4, reg, value));
        Ok(())
    }
    fn write_bytes(&self, _reg: u16, _bytes: &[u8]) -> Result<(), FwError> {
        Err(FwError::Access)
    }
    async fn delay_us(&self, _micros: u64) {}
}

fn provisioned_logical() -> [u8; 512] {
    let mut map = [0xffu8; 512];
    map[0] = 0x29;
    map[1] = 0x81;
    map[phy::EEPROM_XTAL] = 0x25;
    map[phy::EEPROM_RFE_OPTION] = 0x80;
    map
}

fn smoke_rtl8821ae_parked_hw_init_mac_bb_rf_order() -> TestResult {
    let logical = provisioned_logical();
    let condition = match headerfile::Condition::from_hardware(0x0000_1000, 0, &logical) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("provisioned condition rejected"),
    };
    let mut regs = vec![0u8; 0x1000];
    regs[0x10c] = 0x0a;
    regs[0x286] = 0x04;
    regs[0x002] = 0x01;
    let io = RegFake(IrqSafeSpinLock::new((regs, Vec::new())));
    let mac_addr = [0x00, 0xe0, 0x4c, 0x88, 0x21, 0x01];
    let report =
        match narf_scheduler::block_on(mac::configure(&io, &condition, &logical, &mac_addr)) {
            Ok(r) => r,
            Err(_) => return TestResult::Fail("parked 8821AE hw_init failed on model"),
        };
    let g = io.0.lock();
    let (r, trace) = (&g.0, &g.1);
    let r32 = |at: usize| u32::from_le_bytes(r[at..at + 4].try_into().unwrap());
    if r[0x004] & 0x10 == 0
        || r[0x423] != 0xff
        || r[0x041] & 0x10 != 0
        || u16::from_le_bytes([r[0x10c], r[0x10d]]) != 0xf5ba
        // The MAC table (written after init_mac) rewrites RCR bytes 0x608/9.
        || !trace.contains(&(4, 0x608, mac::RCR))
        || r[0x303] != 0x77
        || r[0x577] != 3
        || r[0x100] != 0
        || r[0x301] != 0
    {
        return TestResult::Fail("init_mac remainder / CR or PCIe DMA touched");
    }
    let bb = trace
        .iter()
        .position(|w| *w == (1, 0x002, 0x41))
        .unwrap_or(usize::MAX);
    if bb == usize::MAX
        || trace.get(bb + 1) != Some(&(1, 0x002, 0x43))
        || trace.get(bb + 2) != Some(&(1, 0x01f, 7))
        || trace.get(bb + 3) != Some(&(1, 0x076, 7))
    {
        return TestResult::Fail("BB enable order (FEN_PCIEA, BB resets, RF_CTRL, OPT_CTRL)");
    }
    let mac_rows = phy::selected(tables::MAC, &condition);
    let first = mac_rows[0];
    if trace
        .iter()
        .position(|w| *w == (1, first.0 as u16, first.1 & 0xff))
        .is_none_or(|at| at > bb)
    {
        return TestResult::Fail("MAC table not written before BB config");
    }
    let rf_rows: Vec<_> = phy::selected(tables::RADIOA, &condition)
        .into_iter()
        .filter(|&(a, _)| a != 0xfe && a != 0xffe)
        .collect();
    let rf_writes: Vec<_> = trace.iter().filter(|w| w.1 == phy::RA_LSSIWRITE).collect();
    if rf_rows.is_empty()
        || rf_writes.len() != rf_rows.len()
        || rf_writes[0].2 != ((rf_rows[0].0 & 0xff) << 20 | (rf_rows[0].1 & 0xfffff)) & 0x0fff_ffff
    {
        return TestResult::Fail("RF path A LSSI writes");
    }
    if (r32(0x2c) >> 12) & 0xfff != 0x25 | (0x25 << 6)
        || report.crystal_cap != 0x25
        || report.rfe_type != 4
    {
        return TestResult::Fail("crystal cap / RFE type");
    }
    if r32(0x440) != 0xfff
        || u16::from_le_bytes([r[0x4ca], r[0x4cb]]) != 0x1f1f
        || r[0x550] != 0x1d
        || r[0x610..0x616] != mac_addr
        || r[0x652] != mac::NAV_UPPER
        || r[0x680] != 0
        || r[0x286] & 4 != 0
    {
        return TestResult::Fail("hw_configure / station identity");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_parked_hw_init_mac_bb_rf_order
);

fn smoke_rtl8821ae_rfe_type_and_crystal_rules() -> TestResult {
    let mut logical = provisioned_logical();
    let base = headerfile::Condition {
        cut: 1,
        board_type: 0,
        external_pa_2g: false,
        external_lna_2g: false,
        external_pa_5g: false,
        external_lna_5g: false,
    };
    let ext = |pa5, lna2, pa2| headerfile::Condition {
        external_lna_5g: true,
        external_pa_5g: pa5,
        external_lna_2g: lna2,
        external_pa_2g: pa2,
        ..base
    };
    let cases = [
        (base, 4),
        (ext(false, false, false), 2),
        (ext(true, false, false), 0),
        (ext(true, true, true), 3),
    ];
    for (condition, expected) in cases {
        if phy::rfe_type(&logical, &condition) != Ok(expected) {
            return TestResult::Fail("BIT7 RFE option decision tree");
        }
    }
    logical[phy::EEPROM_RFE_OPTION] = 0x04;
    // The 4 -> 2 external-amplifier override is RTL8812AE-only.
    if phy::rfe_type(&logical, &ext(true, true, true)) != Ok(4) {
        return TestResult::Fail("8812AE-only RFE override applied");
    }
    logical[phy::EEPROM_XTAL] = 0xff;
    if phy::crystal_cap(&logical) != Ok(0x20) {
        return TestResult::Fail("crystal cap 0xff default");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_rfe_type_and_crystal_rules
);
