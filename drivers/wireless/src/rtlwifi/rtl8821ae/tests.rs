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
    if d.dw[3] & (3 << 11) != 0 || d.dw[4] >> 24 != 0 {
        return TestResult::Fail("protection fields without protection");
    }
    // _rtl_query_protection_mode: RTS/CTS -> RTS_EN only; CTS-to-self ->
    // CTS2SELF only; both at DESC_RATE24M, long preamble.
    let rts = trx::TxDesc::fill(&trx::TxParams { protection: 1, ..p });
    let cts = trx::TxDesc::fill(&trx::TxParams { protection: 2, ..p });
    if rts.dw[3] & (3 << 11) != 1 << 12
        || cts.dw[3] & (3 << 11) != 1 << 11
        || (rts.dw[4] >> 24) & 0x1f != 0x08
        || (cts.dw[4] >> 24) & 0x1f != 0x08
        || rts.dw[5] & (1 << 12) != 0
    {
        return TestResult::Fail("RTS/CTS-to-self descriptor fields");
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
        // (old & 0xf) | 0xF5B1 (rtl8821ae/hw.c:965-968): BIT(0) is always set.
        || u16::from_le_bytes([r[0x10c], r[0x10d]]) != 0xf5bb
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

// ── 2.4 GHz power-by-rate, limits, TX power index, envelope, channel ──────

pub(crate) fn powered_logical(diff: u8, option: u8) -> [u8; 512] {
    let mut map = provisioned_logical();
    map[0x10..0x16].copy_from_slice(&[0x20, 0x21, 0x22, 0x23, 0x24, 0x25]);
    map[0x16..0x1b].copy_from_slice(&[0x28, 0x29, 0x2a, 0x2b, 0x2c]);
    map[0x1b] = diff;
    map[txpower::EEPROM_RF_BOARD_OPTION] = option;
    map[envelope::EEPROM_SWING_2G] = 0x04; // path B decode 1 => -3 dB
    map
}

fn smoke_rtl8821ae_power_by_rate_bases_and_relative() -> TestResult {
    let by_rate = txpower::ByRate::from_table();
    // CCK 0x32343638: base = BCD(11M byte) 32, |x - 32| per byte.
    if by_rate.base[0][..3] != [32, 28, 26] || by_rate.base[0][4] != 24 {
        return TestResult::Fail("PG BCD bases (CCK/OFDM/HT/VHT1SS)");
    }
    if by_rate.offset[0][0] != 0x0002_0406
        || by_rate.offset[0][1] != 0x0808_0a0a
        // VHT1SS MCS8/9 (bytes 0..1) vs VHT1SS base 24; bytes 2..3 vs the
        // never-stored VHT2SS base 0.
        || by_rate.offset[0][9] != 0x0000_0402
    {
        return TestResult::Fail("dBm to Linux relative (absolute difference) values");
    }
    // Limit conversion: CCK channel 1 under WW is min over regulations of
    // (limit - CCK base); VHT 2.4 GHz has no rows and stays MAX_POWER_INDEX.
    let expected = [
        power_limit::Regulation::Fcc,
        power_limit::Regulation::Etsi,
        power_limit::Regulation::Mkk,
    ]
    .iter()
    .filter_map(|r| {
        power_limit::limit(
            *r,
            power_limit::Band::B2g,
            power_limit::Bandwidth::Bw20,
            power_limit::Section::Cck,
            1,
            1,
        )
    })
    .map(|l| l as i8 - 32)
    .min()
    .unwrap_or(63);
    if by_rate.limit(0, 1) != expected || by_rate.limit(30, 1) != 63 {
        return TestResult::Fail("WW limit-to-index conversion");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_power_by_rate_bases_and_relative
);

fn smoke_rtl8821ae_txpower_index_arithmetic() -> TestResult {
    let by_rate = txpower::ByRate::from_table();
    // bw20 diff -1 (0xf), OFDM diff +2; regulatory 2 skips by-rate/limits.
    let factory = match txpower::Factory::from_logical(&powered_logical(0xf2, 2)) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("provisioned factory power rejected"),
    };
    if factory.bw20_diff != -1 || factory.ofdm_diff != 2 || factory.regulatory != 2 {
        return TestResult::Fail("4-bit signed diffs / regulatory selector");
    }
    let idx = |rate, ch| by_rate.index(&factory, rate, ch);
    if idx(0, 1) != Ok(0x20)
        || idx(0, 14) != Ok(0x25)
        || idx(4, 6) != Ok(0x2a + 2)
        || idx(12, 11) != Ok(0x2b - 1)
        || idx(20, 1).is_ok()
        || idx(0, 36).is_ok()
    {
        return TestResult::Fail("regulatory-2 base/diff/channel group selection");
    }
    let factory = txpower::Factory::from_logical(&powered_logical(0x00, 0xff)).unwrap();
    if factory.regulatory != 0 {
        return TestResult::Fail("0xff board option => regulatory 0");
    }
    let expected = 0x20i16 + i16::from(by_rate.by_rate(1, 1, 0));
    if by_rate.index(&factory, 1, 1) != Ok(expected.min(63) as u8) {
        return TestResult::Fail("by-rate offset added to the CCK index");
    }
    let mut map = powered_logical(0, 0);
    map[0x11] = 0xff;
    if txpower::Factory::from_logical(&map).is_ok() {
        return TestResult::Fail("autoload-fail power map admitted with Linux defaults");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_txpower_index_arithmetic
);

pub(crate) fn napc(
    factory: &crate::rtlwifi::efuse::Factory,
    channels: &[u8],
    output: i16,
) -> Vec<u8> {
    let row = 4 + 3 * 64 * 2;
    let total = 96 + channels.len() * row;
    let mut b = vec![0u8; total];
    b[..4].copy_from_slice(b"NAPC");
    b[4..6].copy_from_slice(&1u16.to_le_bytes());
    b[6..8].copy_from_slice(&96u16.to_le_bytes());
    b[8..12].copy_from_slice(&(total as u32).to_le_bytes());
    b[12..14].copy_from_slice(&0x10ecu16.to_le_bytes());
    b[14..16].copy_from_slice(&0x8821u16.to_le_bytes());
    b[16..48].copy_from_slice(&crate::rtlwifi::radio::factory_identity(factory));
    b[48..54].copy_from_slice(&factory.mac);
    b[56..58].copy_from_slice(&8i16.to_le_bytes());
    b[58..60].copy_from_slice(&80i16.to_le_bytes());
    b[60..62].copy_from_slice(&(channels.len() as u16).to_le_bytes());
    b[62..64].copy_from_slice(&20u16.to_le_bytes());
    for (n, ch) in channels.iter().enumerate() {
        let at = 96 + n * row;
        b[at] = *ch;
        for i in 0..192 {
            // Output rises 1 qdBm per index above `output` at index 0.
            let v = output + (i % 64) as i16;
            b[at + 4 + i * 2..at + 6 + i * 2].copy_from_slice(&v.to_le_bytes());
        }
    }
    b
}

fn smoke_rtl8821ae_signed_envelope_admission() -> TestResult {
    let factory = crate::rtlwifi::efuse::Factory {
        mac: [0x00, 0xe0, 0x4c, 0x88, 0x21, 0x02],
        logical: powered_logical(0xf2, 2),
    };
    let bytes = napc(&factory, &[1, 6], 30);
    if envelope::Calibration::from_verified(&bytes, None, &factory).is_ok() {
        return TestResult::Fail("unsigned envelope admitted");
    }
    let mut other = factory.clone();
    other.mac[5] ^= 1;
    if envelope::Calibration::from_verified(&bytes, Some([1; 32]), &other).is_ok() {
        return TestResult::Fail("another board's envelope admitted");
    }
    let cal = match envelope::Calibration::from_verified(&bytes, Some([1; 32]), &factory) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("valid signed envelope rejected"),
    };
    let domain = crate::rtlwifi::channel_power::tests::domain(20);
    let p = match cal.permission(&domain, 1) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("covered channel refused"),
    };
    // EIRP min(80 regulatory, 80 qualified, 80 regd) minus antenna 8 => output
    // <= 72 => index <= 42; Linux CCK ch1 is 0x20 (32) so CCK stays 32 and
    // OFDM/HT (0x2a, 0x27) stay within the bound too.
    if p.index(0) != 0x20 || p.index(4) != 0x2a || p.index(12) != 0x27 || p.swing() != 0x16a {
        return TestResult::Fail("Linux index not kept under a looser envelope");
    }
    let tight = crate::rtlwifi::channel_power::tests::domain(15);
    // 60 - 8 = 52 qdBm => index 22.
    match cal.permission(&tight, 1) {
        Ok(p) if p.index(0) == 22 && p.index(4) == 22 && p.eirp_limit_qdbm() == 60 => {}
        _ => return TestResult::Fail("measured envelope did not lower the index"),
    }
    if cal.permission(&domain, 3).is_ok() || cal.permission(&domain, 12).is_ok() {
        return TestResult::Fail("unmeasured or out-of-plan channel admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_signed_envelope_admission
);

fn smoke_rtl8821ae_ra_mask_rates_within_napc_admission() -> TestResult {
    let factory = crate::rtlwifi::efuse::Factory {
        mac: [0x00, 0xe0, 0x4c, 0x88, 0x21, 0x02],
        logical: powered_logical(0xf2, 2),
    };
    let Ok(cal) =
        envelope::Calibration::from_verified(&napc(&factory, &[6], 30), Some([1; 32]), &factory)
    else {
        return TestResult::Fail("valid signed envelope rejected");
    };
    let Ok(p) = cal.permission(&crate::rtlwifi::channel_power::tests::domain(20), 6) else {
        return TestResult::Fail("covered channel refused");
    };
    let station = txpower::station_rates().fold(0u64, |m, r| m | (1 << r));
    if p.admitted_rates() != station || !p.admits(trx::DESC_RATE24M) || p.admits(20) {
        return TestResult::Fail("admitted set is not exactly the measured station rates");
    }
    let g = h2c::Peer {
        legacy: 0xfff,
        ht: None,
        sgi20: false,
        sgi40: false,
        vht: None,
        sgi80: false,
        five_ghz: false,
    };
    let n = h2c::Peer {
        ht: Some([0xff, 0]),
        ..g
    };
    let gm = h2c::mask_rates(&h2c::rate_mask(&g, false, 0, true));
    let nm = h2c::mask_rates(&h2c::rate_mask(&n, false, 0, true));
    if gm != Some(0xff5) || nm != Some(0xff005) {
        return TestResult::Fail("ratr bitmap not mapped to full-order rates");
    }
    if nm.unwrap() & !p.admitted_rates() != 0 {
        return TestResult::Fail("installed RA mask exceeds the admitted rates");
    }
    // VHT 1SS bits 12..21 are DESC_RATEVHT1SS_MCS0..9 (28..37); 2SS refused.
    let vht = [0, 10, 0, 0x10, 0xf0, 0x3f, 0];
    if h2c::mask_rates(&vht) != Some(0x10 | (0x3ff << 28))
        || h2c::mask_rates(&[0, 10, 0, 0, 0, 0x40, 0]).is_some()
        || h2c::mask_rates(&[0, 1, 0, 0, 0, 0x10, 0]).is_some()
        || h2c::mask_rates(&[0, 6, 0, 0, 0x10, 0, 0]).is_some()
    {
        return TestResult::Fail("VHT/2SS ratr bitmap mapping wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_ra_mask_rates_within_napc_admission
);

/// `NAPC` v2 fixture: rows are (channel, band, bandwidth, offset); curves
/// as [`napc`], with the CCK curve unmeasured on 5 GHz rows and the 1SS
/// curve unmeasured when `ht_unmeasured`.
pub(crate) fn napc_v2(
    factory: &crate::rtlwifi::efuse::Factory,
    rows: &[(u8, u8, u8, u8)],
    output: i16,
    ht_unmeasured: bool,
) -> Vec<u8> {
    let row = 4 + 3 * 64 * 2;
    let mut b = napc(factory, &[], output);
    b[4..6].copy_from_slice(&2u16.to_le_bytes());
    b[60..62].copy_from_slice(&(rows.len() as u16).to_le_bytes());
    b[62..64].copy_from_slice(&0u16.to_le_bytes());
    for (ch, band, bw, offset) in rows {
        let at = b.len();
        b.resize(at + row, 0);
        b[at..at + 4].copy_from_slice(&[*ch, *band, *bw, *offset]);
        for i in 0..192 {
            let unmeasured = (i < 64 && *band == 1) || (i >= 128 && ht_unmeasured);
            let v = if unmeasured {
                i16::MAX
            } else {
                output + (i % 64) as i16
            };
            b[at + 4 + i * 2..at + 6 + i * 2].copy_from_slice(&v.to_le_bytes());
        }
    }
    let total = b.len() as u32;
    b[8..12].copy_from_slice(&total.to_le_bytes());
    b
}

fn smoke_rtl8821ae_napc_v2_rows_bands_widths_and_partial_admission() -> TestResult {
    use envelope::{Band, Operating, Width};
    let factory = crate::rtlwifi::efuse::Factory {
        mac: [0x00, 0xe0, 0x4c, 0x88, 0x21, 0x02],
        logical: powered_logical(0xf2, 2),
    };
    let sign = Some([1; 32]);
    let good = [
        (6, 0, 20, 0),
        (3, 0, 40, 1),
        (9, 0, 40, 2),
        (36, 1, 20, 0),
        (40, 1, 40, 2),
        (149, 1, 80, 0),
    ];
    let Ok(cal) =
        envelope::Calibration::from_verified(&napc_v2(&factory, &good, 30, false), sign, &factory)
    else {
        return TestResult::Fail("valid v2 envelope rejected");
    };
    let op = |band, width, channel| Operating {
        band,
        width,
        channel,
    };
    if !cal.measures(op(Band::B5g, Width::W80, 149))
        || !cal.measures(op(Band::B2g, Width::W40Below, 9))
        || cal.measures(op(Band::B5g, Width::W80, 36))
        || cal.measures(op(Band::B2g, Width::W40Above, 9))
    {
        return TestResult::Fail("v2 rows not keyed by band/width/offset/channel");
    }
    // Center frequencies: 36/80 -> ch42, 144/80 -> ch138, 161/40 below -> 159.
    if op(Band::B5g, Width::W80, 36).center_mhz() != Some(5210)
        || op(Band::B5g, Width::W80, 144).center_mhz() != Some(5690)
        || op(Band::B5g, Width::W40Below, 161).center_mhz() != Some(5795)
        || op(Band::B5g, Width::W80, 165).center_mhz().is_some()
        || op(Band::B5g, Width::W40Above, 40).center_mhz().is_some()
        || op(Band::B2g, Width::W40Above, 8).center_mhz().is_some()
    {
        return TestResult::Fail("operating-point plan wrong");
    }
    let domain = crate::rtlwifi::channel_power::tests::domain(20);
    let Ok(p) = cal.permission(&domain, 6) else {
        return TestResult::Fail("v2 2.4 GHz 20 MHz row refused");
    };
    if p.operating() != Operating::legacy20(6) || p.index(0) == 0 {
        return TestResult::Fail("v2 legacy20 permission wrong");
    }
    // 5 GHz and 2.4 GHz 40 MHz are outside the 20 MHz 2.4 GHz host domain.
    if cal
        .permission_for(&domain, op(Band::B5g, Width::W80, 149))
        .is_ok()
        || cal
            .permission_for(&domain, op(Band::B2g, Width::W40Above, 3))
            .is_ok()
    {
        return TestResult::Fail("unadmitted operating point minted a permission");
    }
    for bad in [
        &[(36, 1, 20, 0), (6, 0, 20, 0)][..], // unordered
        &[(6, 0, 80, 0)],                     // 2.4 GHz 80 MHz
        &[(40, 1, 40, 1)],                    // wrong 5 GHz pairing
        &[(165, 1, 80, 0)],                   // no 80 MHz block
        &[(12, 0, 20, 0)],                    // outside ch1-11
        &[(6, 0, 20, 0), (6, 0, 20, 0)],      // duplicate
    ] {
        if envelope::Calibration::from_verified(&napc_v2(&factory, bad, 30, false), sign, &factory)
            .is_ok()
        {
            return TestResult::Fail("malformed v2 row accepted");
        }
    }
    let mut cck5 = napc_v2(&factory, &[(36, 1, 20, 0)], 30, false);
    cck5[96 + 4..96 + 6].copy_from_slice(&10i16.to_le_bytes());
    let mut header_bw = napc_v2(&factory, &[(6, 0, 20, 0)], 30, false);
    header_bw[62] = 20;
    if envelope::Calibration::from_verified(&cck5, sign, &factory).is_ok()
        || envelope::Calibration::from_verified(&header_bw, sign, &factory).is_ok()
    {
        return TestResult::Fail("5 GHz CCK measurement or v2 header bandwidth accepted");
    }
    // Unmeasured 1SS curve: legacy admitted, HT/VHT stay out of the set, so
    // an HT RA mask is refused by the install check (mask must be a subset).
    let Ok(partial) = envelope::Calibration::from_verified(
        &napc_v2(&factory, &[(6, 0, 20, 0)], 30, true),
        sign,
        &factory,
    ) else {
        return TestResult::Fail("partial v2 envelope rejected");
    };
    let Ok(p) = partial.permission(&domain, 6) else {
        return TestResult::Fail("legacy rates of a partial envelope refused");
    };
    let n = h2c::Peer {
        legacy: 0xfff,
        ht: Some([0xff, 0]),
        sgi20: false,
        sgi40: false,
        vht: None,
        sgi80: false,
        five_ghz: false,
    };
    let mask = h2c::mask_rates(&h2c::rate_mask(&n, false, 0, true)).unwrap_or(0);
    if p.admitted_rates() != 0xfff || p.admits(12) || mask & !p.admitted_rates() == 0 {
        return TestResult::Fail("unmeasured 1SS rates admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_napc_v2_rows_bands_widths_and_partial_admission
);

/// `powered_logical` plus a programmed path-A 5 GHz block: BW40 group bases
/// 0x20..=0x2d, BW20 +1 / OFDM -2 (`0x30`), BW80 -2 (`0x36`).
pub(crate) fn powered_logical_5g(option: u8) -> [u8; 512] {
    let mut map = powered_logical(0xf2, option);
    for (i, b) in map[0x22..0x30].iter_mut().enumerate() {
        *b = 0x20 + i as u8;
    }
    map[0x30] = 0x1e;
    map[0x36] = 0xe0;
    map
}

fn smoke_rtl8821ae_txpower_index_bw40_and_5ghz() -> TestResult {
    use power_limit::{Band, Bandwidth};
    let by_rate = txpower::ByRate::from_table();
    // 5 GHz PG: OFDM base BCD 0x26, HT/VHT1SS base BCD 0x24; relative values.
    if by_rate.base_5g[0] != [26, 24, 0, 24, 0]
        || by_rate.offset_5g[0][1] != 0x0808_0a0a
        || by_rate.offset_5g[0][3] != 0x080a_0c0c
        || by_rate.offset_5g[0][9] != 0x0000_0402
    {
        return TestResult::Fail("5 GHz power-by-rate bases / relative values");
    }
    // Limits: OFDM reads the 20 MHz rows at any width; 5 GHz VHT 1T at
    // 20 MHz has no rows and is cross-referenced from HT 1T (same base 24);
    // 5 GHz HT at 80 MHz reads the (absent) 40 MHz rows at the 80 MHz center.
    if by_rate.limit_at(Band::B5g, Bandwidth::Bw40, 4, 38)
        != by_rate.limit_at(Band::B5g, Bandwidth::Bw20, 4, 38)
        || by_rate.limit_at(Band::B5g, Bandwidth::Bw20, 28, 36) == 63
        || by_rate.limit_at(Band::B5g, Bandwidth::Bw20, 28, 36)
            != by_rate.limit_at(Band::B5g, Bandwidth::Bw20, 12, 36)
        || by_rate.limit_at(Band::B5g, Bandwidth::Bw80, 12, 42) != 63
        || by_rate.limit_at(Band::B5g, Bandwidth::Bw80, 28, 42) == 63
        || by_rate.limit_at(Band::B5g, Bandwidth::Bw20, 12, 37) != 63
    {
        return TestResult::Fail("5 GHz limit selection / cross reference");
    }
    let factory = match txpower::Factory::from_logical(&powered_logical_5g(2)) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("5 GHz factory power rejected"),
    };
    match factory.five_ghz {
        Some(f) if f.bw20_diff == 1 && f.ofdm_diff == -2 && f.bw80_diff == Some(-2) => {}
        _ => return TestResult::Fail("5 GHz diff nibbles"),
    }
    let idx = |band, bw, rate, ch| by_rate.index_at(&factory, band, bw, rate, ch);
    let (b2, b5) = (Band::B2g, Band::B5g);
    let (w20, w40, w80) = (Bandwidth::Bw20, Bandwidth::Bw40, Bandwidth::Bw80);
    // 2.4 GHz 40 MHz at wide channel 3 (group 1): HT has no TX_1S BW40 diff.
    if idx(b2, w40, 0, 3) != Ok(0x21)
        || idx(b2, w40, 4, 3) != Ok(0x29 + 2)
        || idx(b2, w40, 12, 3) != Ok(0x29)
        || idx(b2, w80, 12, 3).is_ok()
    {
        return TestResult::Fail("2.4 GHz BW40 index");
    }
    if idx(b5, w20, 4, 36) != Ok(0x1e)
        || idx(b5, w20, 12, 36) != Ok(0x21)
        || idx(b5, w20, 0, 36).is_ok()
        || idx(b5, w20, 12, 37).is_ok()
        || idx(b5, w40, 12, 38) != Ok(0x20)
        || idx(b5, w40, 12, 46) != Ok(0x21)
        || idx(b5, w40, 4, 46) != Ok(0x1f)
        // 80 MHz: (group 0 + group 1) / 2 - 2; OFDM keeps the 40 MHz base.
        || idx(b5, w80, 12, 42) != Ok(0x1e)
        || idx(b5, w80, 4, 42) != Ok(0x1e)
        || idx(b5, w80, 28, 155) != Ok(0x28)
        || idx(b5, w80, 12, 36).is_ok()
    {
        return TestResult::Fail("5 GHz BW20/40/80 index");
    }
    let mut map = powered_logical_5g(2);
    map[0x36] = 0xff;
    map[0x22 + 3] = 0xff;
    let partial = txpower::Factory::from_logical(&map).unwrap();
    if by_rate.index_at(&partial, b5, w80, 12, 42).is_ok()
        || by_rate.index_at(&partial, b5, w40, 12, 38) != Ok(0x20)
        || by_rate.index_at(&partial, b5, w20, 12, 60).is_ok()
    {
        return TestResult::Fail("unprogrammed 5 GHz group or BW80 diff admitted");
    }
    let mut map = powered_logical_5g(2);
    map[0x30] = 0xff;
    let none = txpower::Factory::from_logical(&map).unwrap();
    if none.five_ghz.is_some() || by_rate.index_at(&none, b5, w20, 4, 36).is_ok() {
        return TestResult::Fail("unprogrammed 5 GHz block admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_txpower_index_bw40_and_5ghz
);

fn smoke_rtl8821ae_napc_v2_permission_bw40_and_5ghz() -> TestResult {
    use envelope::{Band, Operating, Width};
    use narf_wireless::reg::*;
    let factory = crate::rtlwifi::efuse::Factory {
        mac: [0x00, 0xe0, 0x4c, 0x88, 0x21, 0x04],
        logical: powered_logical_5g(2),
    };
    let rows = [
        (1, 0, 40, 1),
        (36, 1, 20, 0),
        (40, 1, 40, 2),
        (36, 1, 80, 0),
    ];
    let Ok(cal) = envelope::Calibration::from_verified(
        &napc_v2(&factory, &rows, 30, false),
        Some([1; 32]),
        &factory,
    ) else {
        return TestResult::Fail("v2 envelope rejected");
    };
    let rule = |start, end, bw| RegRule {
        freq_start_mhz: start,
        freq_end_mhz: end,
        max_bandwidth_mhz: bw,
        max_power_dbm: 20,
        flags: RegFlags::empty(),
    };
    let domain = RegulatoryDomain {
        country_code: *b"US",
        rules: vec![rule(2402, 2472, 40), rule(5170, 5250, 80)],
    };
    let op = |band, width, channel| Operating {
        band,
        width,
        channel,
    };
    // EIRP 80 qdBm - antenna 8 => index <= 42: OFDM's Linux 0x2b is lowered
    // to 42, every other Linux index is kept.
    match cal.permission_for(&domain, op(Band::B2g, Width::W40Above, 1)) {
        Ok(p) if p.index(0) == 0x21 && p.index(4) == 0x2a && p.index(12) == 0x29 => {}
        _ => return TestResult::Fail("2.4 GHz 40 MHz permission"),
    }
    match cal.permission_for(&domain, op(Band::B5g, Width::W20, 36)) {
        Ok(p)
            if p.index(4) == 0x1e
                && p.index(12) == 0x21
                && p.index(0) == 0
                && !p.admits(0)
                && p.admits(4)
                && p.swing() == 0x200 => {}
        _ => return TestResult::Fail("5 GHz 20 MHz permission (no CCK, 5 GHz swing)"),
    }
    match cal.permission_for(&domain, op(Band::B5g, Width::W40Below, 40)) {
        Ok(p) if p.index(12) == 0x20 && p.index(4) == 0x1e => {}
        _ => return TestResult::Fail("5 GHz 40 MHz permission at wide channel 38"),
    }
    match cal.permission_for(&domain, op(Band::B5g, Width::W80, 36)) {
        Ok(p) if p.index(12) == 0x1e && p.index(28) == 0x1e && p.index(4) == 0x1e => {}
        _ => return TestResult::Fail("5 GHz 80 MHz permission at center 42"),
    }
    // No row for 44/80 even though the block is measured from 36.
    if cal
        .permission_for(&domain, op(Band::B5g, Width::W80, 44))
        .is_ok()
    {
        return TestResult::Fail("unmeasured 80 MHz primary admitted");
    }
    // A 5 GHz permission is programmed through the 5 GHz band switch.
    let p = cal
        .permission_for(&domain, op(Band::B5g, Width::W20, 36))
        .unwrap();
    let io = RegFake(IrqSafeSpinLock::new((vec![0u8; 0x1000], Vec::new())));
    if narf_scheduler::block_on(channel::configure(&io, &p, 0)).is_err()
        || (u32::from_le_bytes(io.0.lock().0[0x860..0x864].try_into().unwrap()) >> 17) & 0xfff
            != 0x494
    {
        return TestResult::Fail("5 GHz permission not programmed as 5 GHz 20 MHz");
    }
    // 2.4 GHz 40 MHz, primary 1 + secondary above: wide channel 3, primary
    // is the lower 20 MHz (data SC 2), reg_837 BIT(2) => L1 peak 6.
    let p = cal
        .permission_for(&domain, op(Band::B2g, Width::W40Above, 1))
        .unwrap();
    let mut regs = vec![0u8; 0x1000];
    regs[0x668] = 0x7f;
    regs[0x669] = 0x01;
    regs[0xa00] = 0x10;
    let io = RegFake(IrqSafeSpinLock::new((regs, Vec::new())));
    if narf_scheduler::block_on(channel::configure(&io, &p, 1 << 2)).is_err() {
        return TestResult::Fail("2.4 GHz 40 MHz configure failed on model");
    }
    let g = io.0.lock();
    let (r, trace) = (&g.0, &g.1);
    let r32 = |at: usize| u32::from_le_bytes(r[at..at + 4].try_into().unwrap());
    let lssi: Vec<u32> = trace
        .iter()
        .filter(|w| w.1 == phy::RA_LSSIWRITE)
        .map(|w| w.2)
        .collect();
    if lssi.len() != 3 || lssi[1] & 0xff != 3 || (lssi[2] >> 10) & 3 != 1 {
        return TestResult::Fail("RF 0x18 wide channel 3 / BW40 bits (path A)");
    }
    if u16::from_le_bytes([r[0x668], r[0x669]]) != 0x00ff
        || r[0x483] != 2
        || r32(0x8ac) & 0x0030_03c3 != 0x0030_0201
        || (r32(0x8ac) >> 2) & 0xf != 2
        || r32(0x838) >> 28 != 2
        || r32(0x8c4) & (1 << 30) != 0
        || (r32(0x848) >> 22) & 0xf != 6
        || r32(0xa00) & 0x10 != 0
        || r[0xc2c] != 0x29
    {
        return TestResult::Fail("set_bw_mode(20/40 MHz) effects");
    }
    drop(g);
    let below = cal.permission_for(&domain, op(Band::B2g, Width::W40Below, 9));
    if below.is_ok() {
        return TestResult::Fail("unmeasured 40 MHz row admitted");
    }
    if channel::data_sc(Width::W40Below) != 1 || channel::data_sc(Width::W20) != 0 {
        return TestResult::Fail("secondary channel mapping");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_napc_v2_permission_bw40_and_5ghz
);

fn smoke_rtl8821ae_band_channel_bw20_txagc_order() -> TestResult {
    let factory = crate::rtlwifi::efuse::Factory {
        mac: [0x00, 0xe0, 0x4c, 0x88, 0x21, 0x03],
        logical: powered_logical(0xf2, 2),
    };
    let cal =
        envelope::Calibration::from_verified(&napc(&factory, &[6], 30), Some([1; 32]), &factory)
            .unwrap();
    let p = cal
        .permission(&crate::rtlwifi::channel_power::tests::domain(20), 6)
        .unwrap();
    let mut regs = vec![0u8; 0x1000];
    regs[0x668] = 0xff;
    regs[0x669] = 0x01;
    let io = RegFake(IrqSafeSpinLock::new((regs, Vec::new())));
    if narf_scheduler::block_on(channel::configure(&io, &p, 0)).is_err() {
        return TestResult::Fail("channel configure failed on model");
    }
    let g = io.0.lock();
    let (r, trace) = (&g.0, &g.1);
    let r32 = |at: usize| u32::from_le_bytes(r[at..at + 4].try_into().unwrap());
    if r32(0x808) & 0x3000_0000 != 0x3000_0000
        || r32(0xcb0) & 0xf0f0 != 0x7070
        || (r32(0xc1c) >> 8) & 0xf != 0
        || r32(0xc1c) >> 21 != 0x16a
        || r32(0xe1c) >> 21 != 0x16a
        || (r32(0x80c) >> 4) & 0xf != 1
        || (r32(0xa04) >> 24) & 0xf != 1
        || !trace.contains(&(1, 0x454, 0))
    {
        return TestResult::Fail("switch_wirelessband(2.4G) effects");
    }
    if (r32(0x860) >> 17) & 0xfff != 0x96a {
        return TestResult::Fail("RFC_AREA 2.4 GHz value");
    }
    let lssi: Vec<u32> = trace
        .iter()
        .filter(|w| w.1 == phy::RA_LSSIWRITE)
        .map(|w| w.2)
        .collect();
    if lssi.len() != 3 || lssi[1] != (0x18 << 20 | 6) || lssi[2] & (3 << 10) != 3 << 10 {
        return TestResult::Fail("RF 0x18 band clear, channel byte, BW20 bits (path A)");
    }
    if !trace.iter().any(|w| w.1 == channel::RB_LSSIWRITE) {
        return TestResult::Fail("Linux path-B RF bandwidth write missing");
    }
    if r[0xc20] != p.index(0)
        || r[0xc24] != p.index(4)
        || r[0xc2c] != p.index(12)
        || r[0xc33] != p.index(19)
        || r[0xc3c] != p.index(28)
    {
        return TestResult::Fail("TXAGC bytes not the admitted indices");
    }
    let m7 = i32::from(p.index(19));
    let t = |v: i32| v.max(2) as u32;
    if r32(0xc54) & 0xff_ffff != t(m7 - 10) | t(m7 - 18) << 8 | t(m7 - 24) << 16 {
        return TestResult::Fail("TX power training levels");
    }
    if u16::from_le_bytes([r[0x668], r[0x669]]) != 0x007f
        || r[0x483] != 0
        || r32(0x8ac) & 0x0030_03c3 != 0x0030_0200
        || r32(0x8c4) & (1 << 30) != 0
        || (r32(0x848) >> 22) & 0xf != 8
    {
        return TestResult::Fail("set_bw_mode(20 MHz) effects");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_band_channel_bw20_txagc_order
);

// ── Path-A IQK (`_rtl8821ae_phy_iq_calibrate`) ───────────────────────────

fn iqk_model(d00: u32) -> RegFake {
    let mut regs = vec![0u8; 0x1000];
    for (i, at) in iqk::MACBB_REGS
        .iter()
        .chain(iqk::AFE_REGS.iter())
        .enumerate()
    {
        let at = usize::from(*at);
        regs[at..at + 4].copy_from_slice(&(0x5a00_0000u32 | i as u32).to_le_bytes());
    }
    regs[0xd00..0xd04].copy_from_slice(&d00.to_le_bytes());
    RegFake(IrqSafeSpinLock::new((regs, Vec::new())))
}

fn smoke_rtl8821ae_iqk_fill_and_full_restore() -> TestResult {
    // Every one-shot reports result 0x7f0 (= -16 as signed 11 bits), RX ok.
    let io = iqk_model(0x7f0 << 16);
    let report = match narf_scheduler::block_on(iqk::calibrate(&io, false)) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("IQK failed on model"),
    };
    if report.tx_rounds != 10
        || report.rx_rounds != 10
        || report.tx != (iqk::Fill::Matched { x: -16, y: -16 })
        || report.rx != (iqk::Fill::Matched { x: -16, y: -16 })
    {
        return TestResult::Fail("IQK rounds/averages");
    }
    let g = io.0.lock();
    let (r, trace) = (&g.0, &g.1);
    let r32 = |at: usize| u32::from_le_bytes(r[at..at + 4].try_into().unwrap());
    for (i, at) in iqk::MACBB_REGS
        .iter()
        .chain(iqk::AFE_REGS.iter())
        .enumerate()
    {
        let value = 0x5a00_0000 | i as u32;
        // `_rtl8821ae_iqk_restore_afe` reloads every AFE register on Page C,
        // then (Page C1, 0x82c BIT31 = 1) zeroes 0xc80 / 0xc84 / 0xcb8
        // (rtl8821ae/phy.c:4428-4441). This register model is unpaged, so
        // the AFE reload is checked as the written value.
        let restored = if i >= iqk::MACBB_REGS.len() {
            trace.contains(&(4, *at, value))
        } else {
            r32(usize::from(*at)) == value
        };
        if !restored {
            return TestResult::Fail("backed-up MAC/BB/AFE register not restored");
        }
    }
    if !trace.contains(&(4, 0x82c, 0x5a00_000a)) {
        return TestResult::Fail("0x82c (11th MAC/BB entry) not restored");
    }
    if trace.iter().any(|w| w.1 == 0) {
        return TestResult::Fail("register 0 must never be written");
    }
    if !trace.contains(&(1, 0x522, 0x3f)) || !trace.contains(&(1, 0x808, 0)) {
        return TestResult::Fail("configure_mac TX pause / RX antenna off");
    }
    if r32(0xcd4) & 0x7ff != 0x7f0 || r32(0xccc) & 0x7ff != 0x7f0 {
        return TestResult::Fail("TX IQC fill");
    }
    if r32(0xc10) & 0x3ff != 0x3f8 || (r32(0xc10) >> 16) & 0x3ff != 0x3f8 {
        return TestResult::Fail("RX IQC fill (x>>1, y>>1)");
    }
    // LOK + TX + RX-mode TXK + RX one-shot per round: 4 x 2 writes x 10.
    if trace.iter().filter(|w| w.1 == 0x980).count() != 80 {
        return TestResult::Fail("one-shot count");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_iqk_fill_and_full_restore
);

fn smoke_rtl8821ae_iqk_rx_fail_retries_and_untouched() -> TestResult {
    let io = iqk_model(1 << 11 | 0x10 << 16);
    let report = match narf_scheduler::block_on(iqk::calibrate(&io, false)) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("IQK failed on model"),
    };
    if report.rx_rounds != 0
        || report.rx != iqk::Fill::Untouched
        || report.tx != (iqk::Fill::Matched { x: 0x10, y: 0x10 })
    {
        return TestResult::Fail("RX failure must leave RX IQC untouched");
    }
    let g = io.0.lock();
    // 10 rounds x (LOK + TX + RXK1 + 10 RX retries).
    if g.1.iter().filter(|w| w.1 == 0x980).count() != 10 * 13 * 2 {
        return TestResult::Fail("RX retry count");
    }
    let c10 = u32::from_le_bytes(g.0[0xc10..0xc14].try_into().unwrap());
    if c10 & 0x3ff != 0x100 || (c10 >> 16) & 0x3ff != 0 {
        return TestResult::Fail("RX failure identity write");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_iqk_rx_fail_retries_and_untouched
);

fn smoke_rtl8821ae_iqk_linked_interval_and_agreement() -> TestResult {
    let mut li = iqk::LinkedInterval::default();
    let fired: Vec<bool> = [true, true, true, true, false, true, true]
        .iter()
        .map(|l| li.tick(*l))
        .collect();
    if fired != [false, true, false, false, false, false, true] {
        return TestResult::Fail("IQK must fire on the second linked period only");
    }
    if iqk::agree(&[(0, 0), (10, 10), (12, 8)], 3) != Some((11, 9))
        || iqk::agree(&[(0, 0), (3, 0)], 3).is_some()
        || iqk::agree(&[(0, 0), (3, 0)], 4) != Some((1, 0))
        || iqk::agree(&[(-5, 0), (-6, 0)], 3) != Some((-5, 0))
    {
        return TestResult::Fail("pairwise agreement / truncating average");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_iqk_linked_interval_and_agreement
);

// ── H2C mailbox, commands and interrupt profile ──────────────────────────

fn h2c_model() -> RegFake {
    RegFake(IrqSafeSpinLock::new((vec![0u8; 0x1000], Vec::new())))
}

fn smoke_rtl8821ae_h2c_box_bytes_extension_first_and_rotation() -> TestResult {
    let io = h2c_model();
    let mut mb = h2c::Mailbox::default();
    let ra = [1, 2, 3, 4, 5, 6, 7];
    if narf_scheduler::block_on(mb.fill(&io, h2c::H2C_RA_MASK, &ra)).is_err()
        || narf_scheduler::block_on(mb.fill(&io, h2c::H2C_MSRRPT, &h2c::media_status(true)))
            .is_err()
    {
        return TestResult::Fail("fill failed on idle mailbox");
    }
    let g = io.0.lock();
    let writes: Vec<(u16, u32)> = g.1.iter().map(|w| (w.1, w.2)).collect();
    let expect: [(u16, u32); 12] = [
        (0x1f0, 4),
        (0x1f1, 5),
        (0x1f2, 6),
        (0x1f3, 7),
        (0x1d0, 0x40),
        (0x1d1, 1),
        (0x1d2, 2),
        (0x1d3, 3),
        (0x1d4, 0x01),
        (0x1d5, 1),
        (0x1d6, 0),
        (0x1d7, 0),
    ];
    if writes != expect || g.1.iter().any(|w| w.0 != 1) {
        return TestResult::Fail("byte-wise ext-then-box order or box rotation");
    }
    if mb.next_box() != 2 {
        return TestResult::Fail("last_hmeboxnum");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_h2c_box_bytes_extension_first_and_rotation
);

fn smoke_rtl8821ae_h2c_busy_box_and_powered_off_mac_fail_closed() -> TestResult {
    let io = h2c_model();
    io.0.lock().0[0x1cc] = 1;
    let mut mb = h2c::Mailbox::default();
    if !matches!(
        narf_scheduler::block_on(mb.fill(&io, h2c::H2C_MSRRPT, &[1, 0, 0])),
        Err(crate::rtlwifi::prepare::Error::CommandTimeout)
    ) || !mb.failed
        || !io.0.lock().1.is_empty()
    {
        return TestResult::Fail("busy HMETFR must time out without writing");
    }
    let io = h2c_model();
    {
        let mut g = io.0.lock();
        g.0[0x100] = 0xea;
        g.0[0x210] = 0xea;
    }
    let mut mb = h2c::Mailbox::default();
    if !matches!(
        narf_scheduler::block_on(mb.fill(&io, h2c::H2C_MSRRPT, &[1, 0, 0])),
        Err(crate::rtlwifi::prepare::Error::RadioOff)
    ) || io.0.lock().1 != [(1, 0xff, 0xff)]
    {
        return TestResult::Fail("REG_CR 0xEA path (SYS_CFG1+3 = 0xff, no box write)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_h2c_busy_box_and_powered_off_mac_fail_closed
);

fn smoke_rtl8821ae_h2c_pwrmode_rate_mask_and_lps_order() -> TestResult {
    if h2c::pwrmode(h2c::PsMode::Active) != [0, 0x12, 4, 0, 0x0c, 0x40, 0]
        || h2c::pwrmode(h2c::PsMode::Max) != [1, 0x11, 2, 0, 0, 0x40, 0]
    {
        return TestResult::Fail("SETPWRMODE bytes");
    }
    let g = h2c::Peer {
        legacy: 0x0ff5,
        ht: None,
        sgi20: false,
        sgi40: false,
        vht: None,
        sgi80: false,
        five_ghz: false,
    };
    let b = h2c::Peer {
        legacy: 0x000f,
        ..g
    };
    let n = h2c::Peer {
        legacy: 0x0fff,
        ht: Some([0xff, 0]),
        sgi20: true,
        sgi40: false,
        vht: None,
        sgi80: false,
        five_ghz: false,
    };
    if h2c::rate_mask(&g, false, 0, true) != [0, 6, 0, 0xf5, 0x0f, 0, 0]
        || h2c::rate_mask(&b, false, 0, true) != [0, 8, 0, 0x0d, 0, 0, 0]
        || h2c::rate_mask(&n, false, 0, false) != [0, 0x81, 8, 0x05, 0xf0, 0x0f, 0]
        || h2c::rate_mask(&n, true, 0, true)[3] != 0x15
        || h2c::rate_mask(&n, false, 1, true)[3..] != [0, 0, 0x0f, 0]
    {
        return TestResult::Fail("RA mask payloads");
    }
    let io = h2c_model();
    io.0.lock().0[0x361] = 0x80;
    let mut mb = h2c::Mailbox::default();
    if narf_scheduler::block_on(h2c::fwlps_enter(&io, &mut mb)).is_err()
        || narf_scheduler::block_on(h2c::fwlps_leave(&io, &mut mb)).is_err()
    {
        return TestResult::Fail("LPS enter/leave on model");
    }
    let gl = io.0.lock();
    let rpwm: Vec<(usize, u32)> =
        gl.1.iter()
            .enumerate()
            .filter(|(_, w)| w.1 == 0x361)
            .map(|(i, w)| (i, w.2))
            .collect();
    let first_box = gl.1.iter().position(|w| w.1 == 0x1d0).unwrap_or(usize::MAX);
    // HRPWM bit7 set ⇒ value written unchanged (0), then toggled (0x80).
    if rpwm.len() != 2 || rpwm[0].1 != 0 || rpwm[1].1 != 0x80 || first_box > rpwm[0].0 {
        return TestResult::Fail("enter: PWRMODE then RPWM; leave: RPWM toggle");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_h2c_pwrmode_rate_mask_and_lps_order
);

fn smoke_rtl8821ae_interrupt_profile_masks_and_w1c() -> TestResult {
    let io = h2c_model();
    {
        let mut g = io.0.lock();
        g.0[0xb4..0xb8].copy_from_slice(&0xffff_fffeu32.to_le_bytes());
        g.0[0xbc..0xc0].copy_from_slice(&0x0000_0f00u32.to_le_bytes());
    }
    let (a, b) = match h2c::service_interrupt(&io) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("service failed"),
    };
    if a != h2c::IRQ_MASK0 & 0xffff_fffe || b != 0x300 {
        return TestResult::Fail("recognized bits under irq_mask");
    }
    let g = io.0.lock();
    let w: Vec<(u16, u32)> = g.1.iter().map(|w| (w.1, w.2)).collect();
    if w[..4] != [(0xb0, 0), (0xb8, 0), (0xb4, a), (0xbc, b)]
        || !w.ends_with(&[
            (0xb0, h2c::IRQ_MASK0),
            (0xb8, h2c::IRQ_MASK1),
            (0x58, h2c::SYS_IRQ_MASK),
        ])
        || w.iter().any(|x| x.0 == 0x1af)
    {
        return TestResult::Fail("disable, W1C, clear, enable order (no C2HEVT_CLEAR)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_interrupt_profile_masks_and_w1c
);

fn smoke_rtl8821ae_rcr_settles_after_mac_table_rewrite() -> TestResult {
    let io = h2c_model();
    {
        let mut g = io.0.lock();
        // Hardware RCR after the MAC table's 0x608/0x609 byte rows.
        g.0[0x608..0x60c].copy_from_slice(&0xf400_2a0eu32.to_le_bytes());
    }
    let mut rc = mac::ReceiveConfig::default();
    if rc.set_check_bssid(&io, true).is_err() {
        return TestResult::Fail("check_bssid(true)");
    }
    {
        let g = io.0.lock();
        if u32::from_le_bytes(g.0[0x608..0x60c].try_into().unwrap()) != mac::RCR | 0xc0
            || g.1 != [(4, 0x608, mac::RCR | 0xc0), (1, 0x550, 0)]
        {
            return TestResult::Fail("linked: RCR = receive_config | CBSSID, then BCN_CTRL");
        }
    }
    io.0.lock().1.clear();
    if rc.set_check_bssid(&io, false).is_err()
        || rc.rcr != mac::RCR
        || io.0.lock().1 != [(1, 0x550, 0x10), (4, 0x608, mac::RCR)]
    {
        return TestResult::Fail("unlinked: BCN_CTRL BIT4 first, then RCR without CBSSID");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_rcr_settles_after_mac_table_rewrite
);

/// `_rtl_init_hw_ht_capab` 1T1R body, `BSS_CHANGED_HT` A-MPDU registers and
/// the N-mode RA mask / RATE_ID pairing.
fn smoke_rtl8821ae_ht_capability_timing_and_n_mask() -> TestResult {
    use super::ht;
    // SMPS disabled 0x0c | SGI20 0x20 | MAX_AMSDU 0x800; factor 3, density 7.
    let narrow = ht::capability(false).capability_body();
    if narrow[..3] != [0x2c, 0x08, 3 | 7 << 2] || narrow[3] != 0xff || narrow[7] != 0 {
        return TestResult::Fail("HT20 capability body not the Linux 1T1R form");
    }
    // + SUP_WIDTH_20_40 0x2, SGI_40 0x40, DSSSCCK40 0x1000.
    let wide = ht::capability(true).capability_body();
    if wide[..2] != [0x6e, 0x18] || wide[15] != 1 {
        return TestResult::Fail("HT20/40 capability body not the Linux 1T1R form");
    }
    let io = RegFake(IrqSafeSpinLock::new((vec![0; 0x1000], Vec::new())));
    let mut cfg = 0u8;
    if ht::timing(&io, &mut cfg, 1, 4).is_err() {
        return TestResult::Fail("timing failed");
    }
    // Peer factor 1 lowers the 64K cap; density stays the local 7.
    let expected = vec![
        (1, ht::REG_AMPDU_MIN_SPACE, 0),
        (4, ht::REG_AMPDU_MAX_LENGTH_8812, 0x8000_3fff),
        (1, ht::REG_AMPDU_MIN_SPACE, 7),
    ];
    if io.0.lock().1 != expected || cfg != 7 {
        return TestResult::Fail("BSS_CHANGED_HT register order/values differ");
    }
    io.0.lock().1.clear();
    if ht::timing(&io, &mut cfg, 3, 0).is_err()
        || io.0.lock().1
            != vec![
                (1, ht::REG_AMPDU_MIN_SPACE, 7),
                (4, ht::REG_AMPDU_MAX_LENGTH_8812, 0x8000_ffff),
                (1, ht::REG_AMPDU_MIN_SPACE, 7),
            ]
    {
        return TestResult::Fail("64K factor must program 0xffff | BIT31");
    }
    let n = h2c::Peer {
        legacy: 0xfff,
        ht: Some([0xff, 0]),
        sgi20: true,
        sgi40: false,
        vht: None,
        sgi80: false,
        five_ghz: false,
    };
    let mask = h2c::rate_mask(&n, false, 0, true);
    // RATR_INX_WIRELESS_NGB -> RATEID_IDX_BGN_40M_1SS (1) | SGI.
    if mask != [0, 0x81, 0, 0x05, 0xf0, 0x0f, 0] {
        return TestResult::Fail("HT20 RA mask payload differs from Linux");
    }
    if h2c::mask_rates(&mask) != Some(0x5 | (0xff << 12)) || ht::MCS0_7 != 0xff << 12 {
        return TestResult::Fail("HT mask not mapped onto MCS0-7");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_ht_capability_timing_and_n_mask
);

/// HT40: the station regrants a 40 MHz `NAPC` permission at its own
/// operating point (a 20 MHz-only host rule refuses it), and IQK at 40 MHz
/// restores RF 0x18[11:10] = 1 after every LOK load (`current_chan_bw` 1).
fn smoke_rtl8821ae_ht40_regrant_and_iqk_bandwidth_restore() -> TestResult {
    use crate::rtlwifi::station_power::{Base, Grant};
    use envelope::{Band, Operating, Width};
    use narf_wireless::reg::*;
    let factory = crate::rtlwifi::efuse::Factory {
        mac: [0x00, 0xe0, 0x4c, 0x88, 0x21, 0x05],
        logical: powered_logical_5g(2),
    };
    let Ok(cal) = envelope::Calibration::from_verified(
        &napc_v2(&factory, &[(1, 0, 20, 0), (1, 0, 40, 1)], 30, false),
        Some([1; 32]),
        &factory,
    ) else {
        return TestResult::Fail("v2 envelope rejected");
    };
    let domain = |bw| RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2472,
            max_bandwidth_mhz: bw,
            max_power_dbm: 20,
            flags: RegFlags::empty(),
        }],
    };
    let op = Operating {
        band: Band::B2g,
        width: Width::W40Above,
        channel: 1,
    };
    let Ok(p40) = cal.permission_for(&domain(40), op) else {
        return TestResult::Fail("40 MHz row refused");
    };
    if !super::ht::admitted(&p40) {
        return TestResult::Fail("measured MCS0-7 not admitted at 40 MHz");
    }
    let base = Base::Rtl8821ae(Arc::new(cal));
    if base.regrant(&domain(40), Grant::Rtl8821ae(p40)) != Ok(Grant::Rtl8821ae(p40)) {
        return TestResult::Fail("40 MHz grant not re-derived at its operating point");
    }
    if base.regrant(&domain(20), Grant::Rtl8821ae(p40)).is_ok() {
        return TestResult::Fail("20 MHz-only host rule must refuse the 40 MHz grant");
    }
    let rf18 = |trace: &[(u8, u16, u32)], value: u32| {
        trace
            .iter()
            .filter(|w| w.1 == 0xc90 && (w.2 >> 20) & 0xff == 0x18 && w.2 & 0xc00 == value)
            .count()
    };
    for (width, restores) in [(Width::W20, 0), (Width::W40Above, 10)] {
        let io = iqk_model(0x7f0 << 16);
        if narf_scheduler::block_on(iqk::calibrate_at(&io, false, width)).is_err() {
            return TestResult::Fail("IQK failed on model");
        }
        if rf18(&io.0.lock().1, 0x400) != restores {
            return TestResult::Fail("RF 0x18 bandwidth restore count");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_ht40_regrant_and_iqk_bandwidth_restore
);

/// 80 MHz IQK (`_rtl8821ae_iqk_tx` with `vdf_enable`): three TX tones and
/// three RX-mode TXK + RX IQK tones per round, the post-LOK RF 0x18[11:10]
/// = 0 restore, the `tx_dt`/`rx_dt` arithmetic and the 0xce8 VDF bits.
fn smoke_rtl8821ae_iqk_80mhz_vdf_branch() -> TestResult {
    use envelope::Width;
    // dt arithmetic: y1 - y0 = 1 → 2 * 16 * 10000 / 15708 = 20 → 10.
    if iqk::vdf_dt(0, 1, iqk::TX_DT_DIV) != 10
        || iqk::vdf_dt(0, 1, iqk::RX_DT_DIV) != 12
        || iqk::vdf_dt(1, 0, iqk::TX_DT_DIV) != -10
        || iqk::vdf_dt(5, 5, iqk::RX_DT_DIV) != 0
    {
        return TestResult::Fail("VDF tx_dt / rx_dt arithmetic");
    }
    let io = iqk_model(0x7f0 << 16);
    let report = match narf_scheduler::block_on(iqk::calibrate_at(&io, true, Width::W80)) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("80 MHz IQK failed on model"),
    };
    if report.tx_rounds != 10
        || report.rx_rounds != 10
        || report.tx != (iqk::Fill::Matched { x: -16, y: -16 })
        || report.rx != (iqk::Fill::Matched { x: -16, y: -16 })
    {
        return TestResult::Fail("80 MHz IQK rounds/averages");
    }
    let g = io.0.lock();
    let (r, trace) = (&g.0, &g.1);
    // Per round: LOK + 3 TX tones + 3 x (RXK1 + RX) = 10 one-shots.
    if trace.iter().filter(|w| w.1 == 0x980).count() != 10 * 10 * 2 {
        return TestResult::Fail("80 MHz one-shot count");
    }
    let rf18_bw = trace
        .iter()
        .filter(|w| w.1 == 0xc90 && (w.2 >> 20) & 0xff == 0x18)
        .map(|w| w.2 & 0xc00)
        .collect::<Vec<_>>();
    // LOK at 20 MHz (3) then the 80 MHz restore (0) each round.
    if rf18_bw.len() != 20 || rf18_bw.chunks(2).any(|c| c != [0xc00, 0]) {
        return TestResult::Fail("RF 0x18 80 MHz restore");
    }
    // Equal tone samples: dt = 0; TX VDF left enabled, RX VDF enabled.
    let ce8 = u32::from_le_bytes(r[0xce8..0xcec].try_into().unwrap());
    if ce8 & (1 << 31) == 0 || ce8 & (1 << 30) == 0 || ce8 & 0x3fff_3fff != 0 {
        return TestResult::Fail("0xce8 VDF enables / delay terms");
    }
    for (at, value) in [
        (0xc80, 0x1800_8c38),
        (0xc80, 0x0800_8c38),
        (0xc80, 0x1800_8c20),
    ] {
        if !trace.contains(&(4, at, value)) {
            return TestResult::Fail("VDF tone programming");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_iqk_80mhz_vdf_branch
);

// ── recovery card disable / enable ───────────────────────────────────────

/// Async register model for the native recovery power flows: 0x05[1:0]
/// requests complete immediately; every byte write is logged in order.
struct RebuildPwr(IrqSafeSpinLock<PwrState>);
#[async_trait::async_trait]
impl Io for RebuildPwr {
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

/// `_rtl8821ae_poweroff_adapter` order (LPS enter, firmware self-reset only
/// with MCUFWDL BIT7 + ready firmware, MCU reset, MCUFWDL = 0, NIC disable,
/// RSV_CTRL+1 BIT0 pulse, RSV_CTRL = 0x0e) and the `_rtl8821ae_init_mac`
/// enable prefix with `PWR_CUT_A_MSK` on the recovery owner.
fn smoke_rtl8821ae_recovery_poweroff_and_enable_order() -> TestResult {
    use crate::rtlwifi::power_runtime::{disable_rtl8821ae, enable_rtl8821ae};
    let model = |ready_bit: bool| {
        let mut regs = vec![0u8; 0x800];
        regs[0x80] = if ready_bit { 0xc6 } else { 0x46 };
        regs[0x1d] = 1;
        regs[3] = 0xfc;
        RebuildPwr(IrqSafeSpinLock::new((regs, Vec::new())))
    };
    let io = model(true);
    if narf_scheduler::block_on(disable_rtl8821ae(&io, true)).is_err() {
        return TestResult::Fail("8821AE poweroff failed on an idle model");
    }
    let g = io.0.lock();
    let w = &g.1;
    let at = |reg: u16, value: u8| w.iter().position(|&x| x == (reg, value));
    let (Some(stop), Some(fw0), Some(mcu0), Some(fwdl), Some(last)) = (
        at(0x301, 0xff),
        at(0x1d, 0),
        w.iter().rposition(|&x| x == (3, 0xf8)),
        at(0x80, 0),
        w.last().copied(),
    ) else {
        return TestResult::Fail("8821AE poweroff write missing");
    };
    let selfreset = w.iter().filter(|&&x| x == (3, 0xfc)).count();
    if stop != 0
        || !(fw0 < mcu0 && mcu0 < fwdl)
        || selfreset != 1
        || last != (0x1c, 0x0e)
        || w[w.len() - 2] != (0x1d, 1)
        || w[w.len() - 3] != (0x1d, 0)
        || g.0[5] & 4 == 0
        || g.0[0x1f] != 0
    {
        return TestResult::Fail("8821AE poweroff order / final state");
    }
    drop(g);
    let cold = model(false);
    if narf_scheduler::block_on(disable_rtl8821ae(&cold, true)).is_err()
        || cold.0.lock().1.contains(&(3, 0xfc))
    {
        return TestResult::Fail("self-reset issued without MCUFWDL BIT7");
    }
    let on = model(false);
    on.0.lock().0[6] = 2;
    if narf_scheduler::block_on(enable_rtl8821ae(&on)).is_err() {
        return TestResult::Fail("8821AE recovery enable failed on a ready model");
    }
    let g = on.0.lock();
    if g.1.first() != Some(&(0x1c, 0)) || g.1.iter().any(|w| w.0 == 0x7a) || g.0[0x2e] != 0x82 {
        return TestResult::Fail("8821AE recovery enable prefix / PWR_CUT_A_MSK");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_recovery_poweroff_and_enable_order
);

// ── 5 GHz band switch, channel and 80 MHz bandwidth ──────────────────────

/// `rtl8821ae_phy_switch_wirelessband(BAND_ON_5G)` (8821AE pins, CCK_CHECK,
/// AGC table 1, OFDM-only RX path), `sw_chnl_callback` 5 GHz ranges incl.
/// `RF_APK`, TXAGC without CCK, `set_bw_mode_callback(80)` and the 80 MHz
/// `_rtl8821ae_phy_get_secondary_chnl` from the primary's position.
fn smoke_rtl8821ae_5ghz_band_channel_and_bw80() -> TestResult {
    use envelope::{Band, Operating, Width};
    use narf_wireless::reg::*;
    if channel::data_sc80(0) != Some(0xa4)
        || channel::data_sc80(1) != Some(0xa2)
        || channel::data_sc80(2) != Some(0x91)
        || channel::data_sc80(3) != Some(0x93)
        || channel::data_sc80(4).is_some()
    {
        return TestResult::Fail("80 MHz sub-channel mapping");
    }
    let factory = crate::rtlwifi::efuse::Factory {
        mac: [0x00, 0xe0, 0x4c, 0x88, 0x21, 0x05],
        logical: powered_logical_5g(2),
    };
    let Ok(cal) = envelope::Calibration::from_verified(
        &napc_v2(&factory, &[(36, 1, 20, 0), (36, 1, 80, 0)], 30, false),
        Some([1; 32]),
        &factory,
    ) else {
        return TestResult::Fail("v2 envelope rejected");
    };
    let domain = RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 5170,
            freq_end_mhz: 5250,
            max_bandwidth_mhz: 80,
            max_power_dbm: 20,
            flags: RegFlags::empty(),
        }],
    };
    let run = |width| {
        let p = cal
            .permission_for(
                &domain,
                Operating {
                    band: Band::B5g,
                    width,
                    channel: 36,
                },
            )
            .ok()?;
        let mut regs = vec![0u8; 0x1000];
        regs[0x668] = 0xff;
        regs[0x669] = 0x01;
        regs[0x41a] = 0x30;
        regs[0xc20] = 0x5a;
        let io = RegFake(IrqSafeSpinLock::new((regs, Vec::new())));
        narf_scheduler::block_on(channel::configure(&io, &p, 0)).ok()?;
        Some(io)
    };
    let Some(io) = run(Width::W80) else {
        return TestResult::Fail("5 GHz 80 MHz configure failed on model");
    };
    let g = io.0.lock();
    let (r, trace) = (&g.0, &g.1);
    let r32 = |at: usize| u32::from_le_bytes(r[at..at + 4].try_into().unwrap());
    if r32(0xcb0) & 0xf0f0 != 0x5040
        || (r32(0xc1c) >> 8) & 0xf != 1
        || (r32(0x80c) >> 4) & 0xf != 0
        || (r32(0xa04) >> 24) & 0xf != 0xf
        || !trace.contains(&(1, 0x454, 0x80))
    {
        return TestResult::Fail("switch_wirelessband(5G) effects");
    }
    if (r32(0x860) >> 17) & 0xfff != 0x494 || r[0xc20] != 0x5a {
        return TestResult::Fail("RFC_AREA 5 GHz value / CCK TXAGC written at 5 GHz");
    }
    let lssi: Vec<u32> = trace
        .iter()
        .filter(|w| w.1 == phy::RA_LSSIWRITE)
        .map(|w| w.2)
        .collect();
    // RF 0x18 band (0x101 at ch 36..64), channel byte = center 42, RF_APK.
    if lssi.len() != 4
        || lssi[0] & 0x7_0300 != 0x1_0100
        || lssi[1] & 0xff != 42
        || lssi[2] != (0x63 << 20 | 0x114e9)
        || lssi[3] & (3 << 10) != 0
    {
        return TestResult::Fail("RF 0x18 5 GHz band/channel, RF_APK, BW80 bits");
    }
    if u16::from_le_bytes([r[0x668], r[0x669]]) & 0x0180 != 0x0100
        || r[0x483] != 0xa4
        || r32(0x8ac) & 0x0030_03c3 != 0x0030_0202
        || (r32(0x8ac) >> 2) & 0xf != 4
        || r32(0x838) >> 28 != 4
        || r32(0x8c4) & (1 << 30) == 0
        || (r32(0x848) >> 22) & 0xf != 7
    {
        return TestResult::Fail("set_bw_mode(80 MHz) effects");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_5ghz_band_channel_and_bw80
);

/// 5 GHz station plumbing: plan channels and frequencies, the 5 GHz probe
/// request IEs (`ieee80211_put_preq_ies_band`), WIRELESS_MODE_A / N_5G RA
/// masks (`rtl8821ae_update_hal_rate_mask`, `rtl_mrate_idx_to_arfr_id`),
/// the 5 GHz HT40 pairing and the 5 GHz `configure_rates` (forced short
/// slot, SIFS 0x0e, no CCK).
fn smoke_rtl8821ae_5ghz_station_plan_probe_ra_mask_and_rates() -> TestResult {
    use super::envelope::{station_channel, station_channel_at, station_frequency_mhz};
    if !station_channel(36)
        || !station_channel(165)
        || !station_channel(11)
        || station_channel(12)
        || station_channel(14)
        || station_channel(34)
        || station_channel(169)
        || station_frequency_mhz(36) != Some(5180)
        || station_frequency_mhz(165) != Some(5825)
        || station_frequency_mhz(6) != Some(2437)
        || station_channel_at(5180) != Some(36)
        || station_channel_at(5745) != Some(149)
        || station_channel_at(2462) != Some(11)
        || station_channel_at(2467).is_some()
        || station_channel_at(5185).is_some()
        || station_channel_at(5170).is_some()
    {
        return TestResult::Fail("station channel plan");
    }
    let own = [0x02, 0, 0, 0, 0, 1];
    let Ok(probe) = crate::rtlwifi::probe_scan::request(own, 36, b"ap", None) else {
        return TestResult::Fail("5 GHz probe refused");
    };
    if probe[24..] != [0, 2, b'a', b'p', 1, 8, 12, 18, 24, 36, 48, 72, 96, 108] {
        return TestResult::Fail("5 GHz probe: OFDM rates only, no ERP rates or DS IE");
    }
    if crate::rtlwifi::probe_scan::request(own, 14, b"ap", None).is_ok()
        || crate::rtlwifi::probe_scan::request(own, 38, b"ap", None).is_ok()
    {
        return TestResult::Fail("probe outside the plan");
    }
    let a = h2c::Peer {
        legacy: 0x0ff0,
        ht: None,
        sgi20: false,
        sgi40: false,
        vht: None,
        sgi80: false,
        five_ghz: true,
    };
    let n = h2c::Peer {
        ht: Some([0xff, 0]),
        sgi20: true,
        ..a
    };
    if a.mode() != h2c::WirelessMode::A
        || n.mode() != h2c::WirelessMode::N5
        || h2c::rate_mask(&a, false, 0, true) != [0, 7, 0, 0xf0, 0x0f, 0, 0]
        || h2c::rate_mask(&n, false, 0, true) != [0, 0x85, 0, 0, 0xf0, 0x0f, 0]
        || h2c::rate_mask(&n, true, 0, true) != [0, 0x85, 1, 0x10, 0xf0, 0x0f, 0]
        || h2c::mask_rates(&h2c::rate_mask(&a, false, 0, true)) != Some(0xff0)
        || h2c::mask_rates(&h2c::rate_mask(&n, false, 0, true)) != Some(0xff << 12)
    {
        return TestResult::Fail("WIRELESS_MODE_A / N_5G masks");
    }
    use crate::rtlwifi::ht::Geometry;
    if Geometry::new_5g(36, 40)
        .ok()
        .map(|g| (g.prime(), g.center()))
        != Some((1, 38))
        || Geometry::new_5g(161, 157)
            .ok()
            .map(|g| (g.prime(), g.center()))
            != Some((2, 159))
        || Geometry::new_5g(40, 44).is_ok()
        || Geometry::new_5g(165, 169).is_ok()
        || Geometry::new_5g(144, 149).is_ok()
    {
        return TestResult::Fail("5 GHz HT40 pairing");
    }
    let io = h2c_model();
    // 6/12/24 basic, 6-54 supported; capability without short slot.
    if super::station::configure_rates(&io, 0x0ff0, 0x0150, 0x0001, false, true).is_err() {
        return TestResult::Fail("5 GHz rates refused");
    }
    {
        let g = io.0.lock();
        let at = |reg: u16| g.1.iter().rev().find(|w| w.1 == reg).map(|w| w.2);
        if at(super::station::REG_RRSR) != Some(0x0150)
            || at(super::station::REG_SLOT) != Some(9)
            || at(super::station::REG_SIFS_CTX + 1) != Some(0x0e)
        {
            return TestResult::Fail("5 GHz RRSR / short slot / SIFS");
        }
    }
    let io = h2c_model();
    if super::station::configure_rates(&io, 0x0fff, 0x0151, 0, false, true).is_ok()
        || super::station::configure_rates(&io, 0x0fe0, 0x0140, 0, false, true).is_ok()
        || super::station::configure_rates(&io, 0x0ff0, 0x0150, 0, false, false).is_ok()
    {
        return TestResult::Fail("CCK at 5 GHz / missing 6M / 2.4 GHz without 1M accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_5ghz_station_plan_probe_ra_mask_and_rates
);

/// VHT80 profile pieces: `_rtl_init_hw_vht_capab` (8821AE), the AC_5G
/// `rtl8821ae_update_hal_rate_mask` payload, `_rtl_get_vht_highest_n_rate`,
/// the descriptor-rate order and `rtl8821ae_bw_mapping`/`_sc_mapping` at 80.
fn smoke_rtl8821ae_vht80_capability_ra_mask_and_tx_mapping() -> TestResult {
    use envelope::{Band, Operating, Width};
    let cap = vht::capability().capability_body();
    let info = u32::from_le_bytes([cap[0], cap[1], cap[2], cap[3]]);
    // SHORT_GI_80 | TXSTBC | RXSTBC_1 | A-MPDU exponent 7; no BF/LDPC/160.
    if info != (1 << 5 | 1 << 7 | 1 << 8 | 7 << 23)
        || u16::from_le_bytes([cap[4], cap[5]]) != 0xfffe
        || u16::from_le_bytes([cap[8], cap[9]]) != 0xfffe
    {
        return TestResult::Fail("8821AE VHT capability");
    }
    let peer = h2c::Peer {
        legacy: 0xff0,
        ht: Some([0xff, 0]),
        sgi20: true,
        sgi40: true,
        vht: Some(vht::intersect(vht::MCS_MAP, 0xfffa)),
        sgi80: true,
        five_ghz: true,
    };
    if peer.mode() != h2c::WirelessMode::Ac5 || h2c::vht_bitmap(0xfffa) != 0x3ff | 0x3ff << 10 {
        return TestResult::Fail("AC_5G mode / 2ssvht bitmap");
    }
    // 80 MHz, level 0: 6M + VHT 1SS MCS0-9, VHT_1SS (10) + SGI, bw 2 |
    // vht_eni 1 << 4.
    if h2c::rate_mask_at(&peer, 2, 0, true) != [0, 0x8a, 0x12, 0x10, 0xf0, 0x3f, 0]
        || h2c::mask_rates(&h2c::rate_mask_at(&peer, 2, 0, true)) != Some(0x10 | vht::VHT1SS_ORDER)
    {
        return TestResult::Fail("AC_5G RA mask at 80 MHz");
    }
    // 20 MHz drops MCS9 (BIT21); level 1 / 2 rows; !update_bw BIT(3).
    if h2c::rate_mask_at(&peer, 0, 0, false) != [0, 0x8a, 0x18, 0x10, 0xf0, 0x1f, 0]
        || h2c::rate_mask_at(&peer, 2, 1, true)[3..] != [0, 0x80, 0x3f, 0]
        || h2c::rate_mask_at(&peer, 2, 2, true)[3..] != [0, 0xf0, 0x3f, 0]
    {
        return TestResult::Fail("AC_5G RA mask rows");
    }
    let n8 = h2c::Peer {
        vht: Some(0xfffd),
        ..peer
    };
    if h2c::rate_mask_at(&n8, 2, 0, true)[5] != 0x1f {
        return TestResult::Fail("MCS0-8 peer map");
    }
    if vht::highest_rate(0xfffe) != 0x35
        || vht::highest_rate(0xfffd) != 0x34
        || vht::highest_rate(0xfffc) != 0x33
        || vht::intersect(0xfffe, 0xfffc) != 0xfffc
        || vht::intersect(0xfffe, 0xffff) != 0xffff
    {
        return TestResult::Fail("VHT highest rate / map intersection");
    }
    if vht::order(0x13) != Some(19)
        || vht::order(0x2c) != Some(28)
        || vht::order(0x35) != Some(37)
        || vht::order(0x36).is_some()
        || vht::order(0x1c).is_some()
    {
        return TestResult::Fail("descriptor rate order");
    }
    if vht::data_bw(0x35, false) != 2
        || vht::data_bw(0x13, false) != 1
        || vht::data_bw(0x0b, false) != 0
        || vht::data_bw(0x35, true) != 0
    {
        return TestResult::Fail("80 MHz packet bandwidth");
    }
    // Primary 36 (lowest of 36-48), 44 (upper 40, lower 20), 48 (upperst).
    let op = |channel| Operating {
        band: Band::B5g,
        width: Width::W80,
        channel,
    };
    if vht::sub_carrier(&op(36), 2) != Some(0)
        || vht::sub_carrier(&op(36), 1) != Some(10)
        || vht::sub_carrier(&op(36), 0) != Some(4)
        || vht::sub_carrier(&op(40), 0) != Some(2)
        || vht::sub_carrier(&op(44), 1) != Some(9)
        || vht::sub_carrier(&op(44), 0) != Some(1)
        || vht::sub_carrier(&op(48), 0) != Some(3)
    {
        return TestResult::Fail("80 MHz sub-carrier mapping");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_vht80_capability_ra_mask_and_tx_mapping
);

/// Host API (nl80211 `GET_WIPHY`) capability: `_rtl_init_mac80211` HT on
/// both sbands, VHT on the 5 GHz sband only, each published only for an
/// admitted envelope operating point, with the association-path bodies.
fn smoke_rtl8821ae_host_vht_capability_per_band() -> TestResult {
    use envelope::{Band, Operating, Width};
    use narf_wireless::reg::*;
    use vht::{HOST_HT40_2G, HOST_HT40_5G, HOST_HT_2G, HOST_HT_5G, HOST_VHT_5G};
    let factory = crate::rtlwifi::efuse::Factory {
        mac: [0x00, 0xe0, 0x4c, 0x88, 0x21, 0x04],
        logical: powered_logical_5g(2),
    };
    let rows = [(1, 0, 40, 1), (36, 1, 20, 0), (36, 1, 80, 0)];
    let Ok(cal) = envelope::Calibration::from_verified(
        &napc_v2(&factory, &rows, 30, false),
        Some([1; 32]),
        &factory,
    ) else {
        return TestResult::Fail("v2 envelope rejected");
    };
    if cal.operating_points().count() != rows.len() {
        return TestResult::Fail("operating points of the envelope");
    }
    let rule = |start, end, bw| RegRule {
        freq_start_mhz: start,
        freq_end_mhz: end,
        max_bandwidth_mhz: bw,
        max_power_dbm: 20,
        flags: RegFlags::empty(),
    };
    let both = RegulatoryDomain {
        country_code: *b"US",
        rules: vec![rule(2402, 2472, 40), rule(5170, 5250, 80)],
    };
    let at = |domain: &RegulatoryDomain, band, width, channel| {
        cal.permission_for(
            domain,
            Operating {
                band,
                width,
                channel,
            },
        )
        .ok()
    };
    let mut expect = 0;
    if at(&both, Band::B2g, Width::W40Above, 1).is_some_and(|p| ht::admitted(&p)) {
        expect |= HOST_HT_2G | HOST_HT40_2G;
    }
    if at(&both, Band::B5g, Width::W20, 36).is_some_and(|p| ht::admitted(&p)) {
        expect |= HOST_HT_5G;
    }
    if at(&both, Band::B5g, Width::W80, 36).is_some_and(|p| vht::admitted(&p)) {
        expect |= HOST_HT_5G | HOST_HT40_5G | HOST_VHT_5G;
    }
    if vht::host_capabilities(&cal, &both) != expect {
        return TestResult::Fail("host capability bits differ from admitted points");
    }
    // No 5 GHz rule: no 5 GHz capability at all.
    let low = RegulatoryDomain {
        country_code: *b"US",
        rules: vec![rule(2402, 2472, 40)],
    };
    if vht::host_capabilities(&cal, &low) & (HOST_HT_5G | HOST_HT40_5G | HOST_VHT_5G) != 0 {
        return TestResult::Fail("5 GHz capability without a 5 GHz rule");
    }
    // A 20 MHz-only 5 GHz rule refuses the 80 MHz point: no VHT.
    let narrow = RegulatoryDomain {
        country_code: *b"US",
        rules: vec![rule(2402, 2472, 40), rule(5170, 5250, 20)],
    };
    if vht::host_capabilities(&cal, &narrow) & HOST_VHT_5G != 0 {
        return TestResult::Fail("VHT published without an admitted 80 MHz point");
    }
    // Per-band bodies: the association-path HT/VHT, VHT on 5 GHz only.
    let all = HOST_HT_2G | HOST_HT40_2G | HOST_HT_5G | HOST_HT40_5G | HOST_VHT_5G;
    match vht::host_phy(all, 2400) {
        Some(p) if p.ht == ht::capability(true).capability_body() && p.vht.is_none() => {}
        _ => return TestResult::Fail("2.4 GHz host PHY"),
    }
    match vht::host_phy(all, 5000) {
        Some(p)
            if p.ht == ht::capability(true).capability_body()
                && p.vht == Some(vht::capability().capability_body()) => {}
        _ => return TestResult::Fail("5 GHz host PHY lacks the VHT body"),
    }
    match vht::host_phy(HOST_HT_5G, 5000) {
        Some(p) if p.ht == ht::capability(false).capability_body() && p.vht.is_none() => {}
        _ => return TestResult::Fail("5 GHz HT20-only host PHY"),
    }
    if vht::host_phy(HOST_HT_2G, 5000).is_some()
        || vht::host_phy(HOST_HT_5G | HOST_VHT_5G, 2400).is_some()
        || vht::host_phy(all, 6000).is_some()
    {
        return TestResult::Fail("host PHY on a band without HT");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_host_vht_capability_per_band
);

/// `reserved_page_packet_8821` pages 0..=4 verbatim: Linux spells four
/// bytes of the QoS-Null and BT-QoS-Null pages `0XB2`/`0XB3`; dropping them
/// shifted the BT-QoS-Null frame control and its 40-byte TX descriptor.
fn smoke_rtl8821ae_rsvd_page_template_page_layout() -> TestResult {
    let t = &rsvd_page::TEMPLATE;
    // Each next page's descriptor (pkt_size, offset 40, FIRST/LAST) sits in
    // the preceding page's last 40 bytes.
    for (page, size) in [(1usize, 0x10u8), (2, 0x18), (3, 0x1a), (4, 0x1a), (5, 0x3c)] {
        let at = page * 256 - 40;
        if t[at..at + 4] != [size, 0x00, 0x28, 0x8c] {
            return TestResult::Fail("reserved-page TX descriptor misplaced");
        }
    }
    if t[256..258] != [0xa4, 0x10]
        || t[512..514] != [0x48, 0x01]
        || t[768..770] != [0xc8, 0x01]
        || t[1024..1026] != [0xc8, 0x01]
        || t[1024 + 6..1024 + 10] != [0xb2, 0xa7, 0xb3, 0x6e]
    {
        return TestResult::Fail("reserved-page frame headers shifted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_rsvd_page_template_page_layout
);

/// WoWLAN payloads, pattern translation/CRC and the WKFM CAM writes
/// (`rtl8821ae/fw.c`, `core.c::_rtl_add_wowlan_patterns`,
/// `hw.c::rtl8821ae_add_wowlan_pattern`, `_rtl8821ae_get_wakeup_reason`).
fn smoke_rtl8821ae_wowlan_payloads_patterns_and_wake_reason() -> TestResult {
    use narf_wireless::{WowlanConfig, WowlanPattern};
    if wow::wowlan_mode(true) != [0x87, 0, 0]
        || wow::wowlan_mode(false) != [0x86, 0, 0]
        || wow::remote_wake_ctrl(true) != [1]
        || wow::keep_alive(true) != [0x03, 10, 0]
        || wow::disconnect_decision(true) != [0x03, 30, 3]
        || wow::global_info(wow::AESCCMP_ENCRYPTION, wow::AESCCMP_ENCRYPTION) != [4, 4]
        || wow::aoac_rsvdpage() != [6, 5, 0, 0, 0, 7, 0]
    {
        return TestResult::Fail("WoWLAN H2C payloads");
    }
    let s = wow::support();
    if !s.magic_packet || s.disconnect || s.gtk_rekey || s.max_patterns != 16 {
        return TestResult::Fail("WoWLAN capability");
    }
    // Linux crc16_ccitt + complement, transliterated vectors.
    if wow::pattern_crc(&[0x08, 0x06]) != 0x8d25 || wow::pattern_crc(b"123456789") != 0x7609 {
        return TestResult::Fail("WoL pattern CRC");
    }
    let own = [0x00, 0xe0, 0x4c, 0x88, 0x21, 0x04];
    let mut bytes = vec![0u8; 14];
    bytes[..6].copy_from_slice(&own);
    bytes[12..14].copy_from_slice(&[0x08, 0x06]);
    let pattern = WowlanPattern {
        mask: vec![0xff, 0x3f],
        pattern: bytes,
        offset: 0,
    };
    let t = wow::translate(&pattern, own);
    if t.kind != wow::PatternType::Unicast || t.mask != [0xc0, 0, 0, 0] || t.crc != 0x8d25 {
        return TestResult::Fail("pattern translation");
    }
    let bcast = WowlanPattern {
        pattern: vec![0xff; 14],
        ..pattern.clone()
    };
    if wow::translate(&bcast, own).kind != wow::PatternType::Broadcast {
        return TestResult::Fail("broadcast pattern type");
    }
    if wow::cam_entry(&t, 0)
        != Some((
            wow::REG_PKTBUF_DBG_DATA_L,
            1 << 31 | 1 << 24 | 0x8d25,
            0x0f01,
        ))
        || wow::cam_entry(&t, 1).is_some()
        || wow::cam_entry(&t, 2) != Some((wow::REG_PKTBUF_DBG_DATA_L, 0xc0, 0x0f01))
        || wow::cam_entry(&t, 3) != Some((wow::REG_PKTBUF_DBG_DATA_H, 0, 0xf001))
        || wow::cam_address(0, 0) != 0x3e80 >> 3
        || wow::cam_address(1, 2) != (0x3e80 + 24 + 8) >> 3
    {
        return TestResult::Fail("WKFM CAM entries");
    }
    let config = WowlanConfig {
        magic_packet: true,
        patterns: vec![pattern.clone()],
        ..Default::default()
    };
    if wow::validate(&config).is_err()
        || wow::validate(&WowlanConfig {
            disconnect: true,
            ..config.clone()
        })
        .is_ok()
        || wow::validate(&WowlanConfig {
            patterns: vec![WowlanPattern {
                pattern: vec![0; 12],
                mask: vec![0xff, 0x0f],
                offset: 0,
            }],
            ..config.clone()
        })
        .is_ok()
    {
        return TestResult::Fail("WoWLAN configuration validation");
    }
    // CAM programming: access window opened and closed, 0x698 = count. The
    // modelled RX packet buffer completes each command immediately.
    struct Cam(RegFake);
    #[async_trait::async_trait]
    impl Io for Cam {
        fn read8(&self, reg: u16) -> Result<u8, FwError> {
            self.0.read8(reg)
        }
        fn read32(&self, reg: u16) -> Result<u32, FwError> {
            self.0.read32(reg)
        }
        fn write8(&self, reg: u16, value: u8) -> Result<(), FwError> {
            self.0.write8(reg, value)
        }
        fn write16(&self, reg: u16, value: u16) -> Result<(), FwError> {
            self.0.write16(reg, value)?;
            if reg == wow::REG_RXPKTBUF_CTRL {
                self.0 .0.lock().0[usize::from(reg)] = 0;
            }
            Ok(())
        }
        fn write32(&self, reg: u16, value: u32) -> Result<(), FwError> {
            self.0.write32(reg, value)
        }
        fn write_bytes(&self, reg: u16, bytes: &[u8]) -> Result<(), FwError> {
            self.0.write_bytes(reg, bytes)
        }
        async fn delay_us(&self, _micros: u64) {}
    }
    let io = Cam(RegFake(IrqSafeSpinLock::new((
        vec![0u8; 0x1000],
        Vec::new(),
    ))));
    if narf_scheduler::block_on(wow::program_patterns(&io, &config, own)).is_err() {
        return TestResult::Fail("pattern programming");
    }
    {
        let g = io.0 .0.lock();
        let writes = &g.1;
        let first = (
            1,
            wow::REG_PKT_BUFF_ACCESS_CTRL,
            u32::from(wow::RXPKT_BUF_SELECT),
        );
        let cam_word = (4, wow::REG_PKTBUF_DBG_DATA_L, 1 << 31 | 1 << 24 | 0x8d25);
        if writes.first() != Some(&first)
            || !writes.contains(&cam_word)
            || g.0[usize::from(wow::REG_PKT_BUFF_ACCESS_CTRL)] != 0
            || g.0[usize::from(wow::REG_WKFMCAM_NUM)] != 1
        {
            return TestResult::Fail("pattern CAM access window");
        }
    }
    // A command the buffer never completes is an error, window closed.
    let stuck = RegFake(IrqSafeSpinLock::new((vec![0u8; 0x1000], Vec::new())));
    if narf_scheduler::block_on(wow::program_patterns(&stuck, &config, own)).is_ok()
        || stuck.0.lock().0[usize::from(wow::REG_PKT_BUFF_ACCESS_CTRL)] != 0
    {
        return TestResult::Fail("stuck CAM write accepted");
    }
    // Whole reserved pages: ARP response A1/A2/A3 substituted, 2008 bytes.
    let bssid = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    let Ok(pages) = wow::whole_reserved_pages(own, bssid, 5) else {
        return TestResult::Fail("whole reserved pages");
    };
    let at = 5 * 256;
    if pages.len() != 2008
        || pages[at..at + 4] != [0x08, 0x01, 0x00, 0x00]
        || pages[at + 4..at + 10] != bssid
        || pages[at + 10..at + 16] != own
        || pages[at + 16..at + 22] != bssid
        || pages[..station::RSVD_PAGE_LEN] != station::reserved_pages(own, bssid, 5).unwrap()[..]
    {
        return TestResult::Fail("whole reserved-page layout");
    }
    if wow::wake_reason(0x21) != wow::WakeReason::MagicPacket
        || wow::wake_reason(0x23) != wow::WakeReason::PatternPacket
        || wow::wake_reason(0x10) != wow::WakeReason::ApLost
        || wow::wake_reason(0x55) != wow::WakeReason::Unknown(0x55)
    {
        return TestResult::Fail("wake reason decode");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_wowlan_payloads_patterns_and_wake_reason
);

fn smoke_rtl8821ae_wowlan_card_disable_register_order() -> TestResult {
    let mut regs = vec![0u8; 0x1000];
    regs[0x002] = 0x03;
    regs[0x008] = 0x01;
    regs[0x101] = 0x00;
    regs[0x286] = 0x02; // RXDMA_IDLE
    regs[0x41a] = 0xff;
    regs[0x41b] = 0x07; // TXFF empty
    let io = RegFake(IrqSafeSpinLock::new((regs, Vec::new())));
    // The model never clears _LLT_OP, so the prefix up to the first LLT
    // write is checked and the LLT failure is returned before RQPN.
    if narf_scheduler::block_on(wow::dynamic_rqpn(
        &io,
        wow::WOW_BOUNDARY,
        wow::WOW_NPQ_RQPN,
        wow::WOW_RQPN,
    )) != Err(crate::rtlwifi::prepare::Error::LltTimeout)
    {
        return TestResult::Fail("dynamic_rqpn LLT failure");
    }
    let writes: Vec<(u8, u16, u32)> = io.0.lock().1.clone();
    let expect: [(u8, u16, u32); 16] = [
        (1, 0x301, 0xfe),
        (1, 0x522, 0xff),
        (1, 0x286, 0x06),
        (1, 0x002, 0x02),
        (1, 0x100, 0x00),
        (1, 0x101, 0x00),
        (1, 0x553, 0x20),
        (1, 0x101, 0x02),
        (1, 0x100, 0xff),
        (1, 0x002, 0x03),
        (1, 0x209, 0xe0),
        (1, 0x424, 0xe0),
        (1, 0x425, 0xe0),
        (1, 0x45d, 0xe0),
        (2, 0x114, 0xe0),
        (4, 0x1e0, (1 << 30) | 1),
    ];
    if writes.len() != expect.len() || writes[..] != expect[..] {
        return TestResult::Fail("dynamic_rqpn register order");
    }
    io.0.lock().1.clear();
    if wow::hold_mcu(&io).is_err() || narf_scheduler::block_on(wow::stop_tx_dma(&io)).is_err() {
        return TestResult::Fail("card-disable tail");
    }
    let writes: Vec<(u8, u16, u32)> = io.0.lock().1.clone();
    let expect: [(u8, u16, u32); 5] = [
        (1, 0x005, 0x00),
        (1, 0x008, 0x09),
        (1, 0x01c, 0x20),
        (1, 0x01c, 0x60),
        (1, 0x301, 0xff),
    ];
    if writes[..] != expect[..] {
        return TestResult::Fail("card-disable tail order");
    }
    // RXDMA never idle (the model keeps the written BIT(2) only): the
    // retirement proof fails where Linux only logs.
    if narf_scheduler::block_on(wow::drain_rx_dma(&io)).is_ok() {
        return TestResult::Fail("RX DMA idle proof");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_wowlan_card_disable_register_order
);

// ── Bluetooth coexistence (pass 1) ──────────────────────────────────────

fn smoke_rtl8821ae_coex_bind_facts_pattern_and_lps_gate() -> TestResult {
    use crate::rtlwifi::btcoex::btc::{ChipInterface, ChipType, BTC_ANTENNA_AT_MAIN_PORT};
    use crate::rtlwifi::btcoex::{encode_tdma, BtState, TdmaPattern, WifiState};
    let mut coex = coex::Owner::bind();
    let btc = &coex.btc;
    if !btc.bt_exist
        || btc.board_info.bt_chip_type != ChipType::Rtl8821
        || btc.board_info.pg_ant_num != 1
        || btc.board_info.btdm_ant_num != 1
        || btc.board_info.btdm_ant_pos != BTC_ANTENNA_AT_MAIN_PORT
        || btc.board_info.single_ant_path != 0
        || btc.board_info.tfbga_package
        || btc.board_info.rfe_type != 0
        || btc.chip_interface != ChipInterface::Pci
    {
        return TestResult::Fail("8821AE coex bind facts");
    }
    // Default Idle/Idle yields Wi-Fi-only and allows LPS.
    if coex.pattern() != TdmaPattern::WifiOnly || !coex.lps_allowed() {
        return TestResult::Fail("8821AE coex default pattern/LPS");
    }
    // BT streaming while Wi-Fi is idle yields the antenna to BT and
    // holds LPS off.
    coex.notify_bt(BtState::Streaming);
    if coex.pattern() != TdmaPattern::BtOnly || coex.lps_allowed() {
        return TestResult::Fail("8821AE coex BtOnly holds LPS off");
    }
    // Connected Wi-Fi shares with streaming BT; LPS stays allowed.
    coex.notify_wifi(WifiState::Connected);
    if coex.pattern() != TdmaPattern::Shared || !coex.lps_allowed() {
        return TestResult::Fail("8821AE coex Shared allows LPS");
    }
    // BT inquiry during a scan also shares.
    coex.notify_wifi(WifiState::Scanning);
    coex.notify_bt(BtState::Inquiry);
    if coex.pattern() != TdmaPattern::Shared || !coex.lps_allowed() {
        return TestResult::Fail("8821AE coex scan/inquiry shares");
    }
    // BT idle releases the antenna entirely.
    coex.notify_bt(BtState::Idle);
    if coex.pattern() != TdmaPattern::WifiOnly || !coex.lps_allowed() {
        return TestResult::Fail("8821AE coex BT idle releases");
    }
    // The three coarse TDMA payloads.
    if encode_tdma(TdmaPattern::WifiOnly) != [0, 0, 0, 0, 0]
        || encode_tdma(TdmaPattern::BtOnly) != [0x61, 0, 0, 0, 0]
        || encode_tdma(TdmaPattern::Shared) != [0xE3, 0x12, 0x03, 0x10, 0x90]
    {
        return TestResult::Fail("8821AE coex TDMA payloads");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_coex_bind_facts_pattern_and_lps_gate
);
