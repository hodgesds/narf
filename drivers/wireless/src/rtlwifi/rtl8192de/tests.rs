// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE dual-MAC model tests (software models only; no device,
//! firmware execution, station chain or RF acceptance is implied).

use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn check(cond: bool, msg: &'static str) -> TestResult {
    if cond {
        TestResult::Pass
    } else {
        TestResult::Fail(msg)
    }
}

/// PROM mode selection: PCI bit 3 of `EEPROM_MAC_FUNCTION`, USB bit 0
/// of `EEPROM_ENDPOINT_SETTING` (inverted).
fn smoke_rtl8192de_mode_from_prom() -> TestResult {
    let mut pci_single = [0u8; 0x20];
    pci_single[EEPROM_MAC_FUNCTION] = 0x08;
    let mut pci_dual = [0u8; 0x20];
    pci_dual[EEPROM_MAC_FUNCTION] = 0x00;
    let mut usb_single = [0u8; 0x20];
    usb_single[EEPROM_ENDPOINT_SETTING] = 0x00;
    let mut usb_dual = [0u8; 0x20];
    usb_dual[EEPROM_ENDPOINT_SETTING] = 0x01;
    check(
        mode_from_prom(Interface::Pci, &pci_single) == Some(MacPhyMode::SingleMacSinglePhy)
            && mode_from_prom(Interface::Pci, &pci_dual) == Some(MacPhyMode::DualMacDualPhy)
            && mode_from_prom(Interface::Usb, &usb_single) == Some(MacPhyMode::SingleMacSinglePhy)
            && mode_from_prom(Interface::Usb, &usb_dual) == Some(MacPhyMode::DualMacDualPhy)
            && mode_from_prom(Interface::Pci, &[0u8; 0x08]).is_none(),
        "PROM mode selection",
    )
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_mode_from_prom
);

/// PHY-control words: PCI base `0xf0` plus mode bits; USB clears bits
/// 0–2 of the current value first (current `0xff` proves the clear).
fn smoke_rtl8192de_phy_ctrl_words() -> TestResult {
    check(
        phy_ctrl_word_pci(MacPhyMode::DualMacDualPhy) == 0xf3
            && phy_ctrl_word_pci(MacPhyMode::SingleMacSinglePhy) == 0xf4
            && phy_ctrl_word_pci(MacPhyMode::DualMacSinglePhy) == 0xf1
            && phy_ctrl_word_usb(MacPhyMode::DualMacDualPhy, 0xff) == 0xfb
            && phy_ctrl_word_usb(MacPhyMode::SingleMacSinglePhy, 0xff) == 0xfc
            && phy_ctrl_word_usb(MacPhyMode::DualMacSinglePhy, 0xff) == 0xf9,
        "PHY-control words",
    )
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_phy_ctrl_words
);

/// Mode info: single/dual-single are 2T2R on both bands from 2.4 GHz;
/// dual-dual is 1T1R with MAC0 on 5 GHz and MAC1 on 2.4 GHz.
fn smoke_rtl8192de_mode_info() -> TestResult {
    let single = mode_info(MacPhyMode::SingleMacSinglePhy, 1);
    let dual_single = mode_info(MacPhyMode::DualMacSinglePhy, 0);
    let mac0 = mode_info(MacPhyMode::DualMacDualPhy, 0);
    let mac1 = mode_info(MacPhyMode::DualMacDualPhy, 1);
    check(
        single.rf_type == RfType::TwoT2R
            && single.bandset == BandSet::OnBoth
            && single.current_band == Band::On2Ghz
            && dual_single.rf_type == RfType::TwoT2R
            && dual_single.bandset == BandSet::OnBoth
            && dual_single.current_band == Band::On2Ghz
            && mac0.rf_type == RfType::OneT1R
            && mac0.bandset == BandSet::On5Ghz
            && mac0.current_band == Band::On5Ghz
            && mac1.rf_type == RfType::OneT1R
            && mac1.bandset == BandSet::On2Ghz
            && mac1.current_band == Band::On2Ghz,
        "mode info",
    )
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_mode_info
);

/// AMPDU-factor bases, sw consequences (dual modes disable 8K A-MSDU
/// and cap RX at 4096; single leaves both alone), default channels,
/// and MAX_AGGR_NUM (`0x0B` single, `0x07` dual).
fn smoke_rtl8192de_ampdu_sw_aggr() -> TestResult {
    let single = sw_consequences(MacPhyMode::SingleMacSinglePhy, Band::On2Ghz);
    let dual5 = sw_consequences(MacPhyMode::DualMacDualPhy, Band::On5Ghz);
    let dual_single = sw_consequences(MacPhyMode::DualMacSinglePhy, Band::On2Ghz);
    check(
        ampdu_factor_base(MacPhyMode::DualMacDualPhy) == 0xb9726641
            && ampdu_factor_base(MacPhyMode::DualMacSinglePhy) == 0x66626641
            && ampdu_factor_base(MacPhyMode::SingleMacSinglePhy) == 0xb972a841
            && !single.disable_amsdu_8k
            && single.rxbuffersize.is_none()
            && single.default_channel == 1
            && dual5.disable_amsdu_8k
            && dual5.rxbuffersize == Some(4096)
            && dual5.default_channel == 36
            && dual_single.disable_amsdu_8k
            && dual_single.rxbuffersize == Some(4096)
            && dual_single.default_channel == 1
            && max_aggr_num(MacPhyMode::SingleMacSinglePhy) == 0x0b
            && max_aggr_num(MacPhyMode::DualMacDualPhy) == 0x07
            && max_aggr_num(MacPhyMode::DualMacSinglePhy) == 0x07,
        "AMPDU/sw/aggr",
    )
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_ampdu_sw_aggr
);

/// AGC selection: MAC0 always the combined table (either band — pinned
/// on both bands); MAC1 the 2G table on 2.4 GHz, the 5G table on 5 GHz.
/// Spot values are Linux literals from `table.c`.
fn smoke_rtl8192de_agc_selection() -> TestResult {
    let mac0_2g = agc_table(0, Band::On2Ghz);
    let mac0_5g = agc_table(0, Band::On5Ghz);
    let mac1_2g = agc_table(1, Band::On2Ghz);
    let mac1_5g = agc_table(1, Band::On5Ghz);
    check(
        core::ptr::eq(mac0_2g, &tables::AGCTAB[..])
            && core::ptr::eq(mac0_5g, &tables::AGCTAB[..])
            && core::ptr::eq(mac1_2g, &tables::AGCTAB_2G[..])
            && core::ptr::eq(mac1_5g, &tables::AGCTAB_5G[..])
            && tables::AGCTAB.len() == 386
            && tables::AGCTAB_2G.len() == 194
            && tables::AGCTAB_5G.len() == 194
            && tables::AGCTAB_5G[0] == 0xc78
            && tables::AGCTAB_5G[1] == 0x7b000001,
        "AGC selection",
    )
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_agc_selection
);

/// RF selection: plain 2T tables by default, per-path internal-PA
/// tables when the EFUSE flag is set; the DMDP swap fires only for a
/// radio-B text load on path A.
fn smoke_rtl8192de_radio_selection() -> TestResult {
    let (a, b) = radio_tables([false, false]);
    let (a_pa, b_plain) = radio_tables([true, false]);
    let (a_plain, b_pa) = radio_tables([false, true]);
    check(
        core::ptr::eq(a, &tables::RADIOA_2T[..])
            && core::ptr::eq(b, &tables::RADIOB_2T[..])
            && core::ptr::eq(a_pa, &tables::RADIOA_2T_INT_PA[..])
            && core::ptr::eq(b_plain, &tables::RADIOB_2T[..])
            && core::ptr::eq(a_plain, &tables::RADIOA_2T[..])
            && core::ptr::eq(b_pa, &tables::RADIOB_2T_INT_PA[..])
            && tables::RADIOA_2T.len() == 378
            && tables::RADIOB_2T.len() == 384
            && dmdp_swapped(RfContent::RadioBTxt, RfPath::A)
            && !dmdp_swapped(RfContent::RadioATxt, RfPath::A)
            && !dmdp_swapped(RfContent::RadioBTxt, RfPath::B),
        "RF selection",
    )
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_radio_selection
);

/// Table inventory: all 10 lengths from `table.h`, plus spot values
/// written out as Linux literals (PHY_REG head, PHY_REG_PG head).
fn smoke_rtl8192de_table_inventory() -> TestResult {
    check(
        tables::PHY_REG_2T.len() == 380
            && tables::PHY_REG_PG.len() == 624
            && tables::RADIOA_2T_INT_PA.len() == 378
            && tables::RADIOB_2T_INT_PA.len() == 384
            && tables::MAC_2T.len() == 160
            && tables::PHY_REG_2T[0] == 0x024
            && tables::PHY_REG_2T[1] == 0x0011800d
            && tables::PHY_REG_PG[0] == 0xe00
            && tables::PHY_REG_PG[1] == 0xffffffff
            && tables::PHY_REG_PG[2] == 0x07090c0c
            && core::ptr::eq(mac_table(), &tables::MAC_2T[..])
            && core::ptr::eq(phy_reg_table(), &tables::PHY_REG_2T[..])
            && core::ptr::eq(phy_reg_pg_table(), &tables::PHY_REG_PG[..]),
        "table inventory",
    )
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_table_inventory
);

// ── step 2: firmware, envelope, descriptors, packet ─────────────────────

use super::{envelope, fw, packet, trx};
use crate::rtlwifi::firmware_transport::{Error as FwError, Io};
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use narf_lib::sync::IrqSafeSpinLock;

/// Firmware image bytes for header tests: 32-byte header + body, with
/// the RAM-code size at bytes 12..14.
fn fw_image(signature: u16, version: u16, subversion: u8, body_len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; fw::HEADER + body_len];
    bytes[0..2].copy_from_slice(&signature.to_le_bytes());
    bytes[4..6].copy_from_slice(&version.to_le_bytes());
    bytes[6] = subversion;
    bytes[12..14].copy_from_slice(&(body_len as u16).to_le_bytes());
    bytes
}

/// `IS_FW_HEADER_EXIST` signatures, version/subversion/payload, and
/// the rejection rules (bad signature, truncation, oversize, size
/// mismatch), plus the `firmware_transport` DID dispatch.
fn smoke_rtl8192de_firmware_header_geometry() -> TestResult {
    for signature in [
        0x92c0, 0x92c1, 0x88c0, 0x88cf, 0x92d0, 0x92d1, 0x92d2, 0x92d3,
    ] {
        let bytes = fw_image(signature, 0x1234, 0x56, 100);
        match fw::parse(&bytes) {
            Ok((info, payload))
                if info.version == 0x1234
                    && info.subversion == 0x56
                    && info.payload == 100
                    && payload.len() == 100 => {}
            _ => return TestResult::Fail("8192DE header signature admitted"),
        }
        match crate::rtlwifi::firmware_transport::parse(
            crate::rtlwifi::regs::RTL_DEV_8192DE,
            &bytes,
        ) {
            Ok((info, _)) if info.version == 0x1234 => {}
            _ => return TestResult::Fail("8192DE transport DID dispatch"),
        }
    }
    for signature in [0x92c2, 0x92d4, 0x5300, 0x2300, 0x0000] {
        if fw::parse(&fw_image(signature, 1, 0, 100)).is_ok() {
            return TestResult::Fail("8192DE bad signature admitted");
        }
    }
    let bytes = fw_image(0x92c0, 1, 0, 100);
    for end in [0, 31, 32] {
        if fw::parse(&bytes[..end]).is_ok() {
            return TestResult::Fail("8192DE truncated image admitted");
        }
    }
    if fw::parse(&vec![0u8; fw::MAX_FILE + 1]).is_ok() {
        return TestResult::Fail("8192DE oversized image admitted");
    }
    let mut mismatch = fw_image(0x92c0, 1, 0, 100);
    mismatch[12..14].copy_from_slice(&99u16.to_le_bytes());
    if fw::parse(&mismatch).is_ok() {
        return TestResult::Fail("8192DE RAM-code size mismatch admitted");
    }
    if fw::parse(&[]).is_ok() || fw::parse(&[0u8; fw::HEADER]).is_ok() {
        return TestResult::Fail("8192DE empty image admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_firmware_header_geometry
);

// ── firmware download model ───────────────────────────────────────────────

struct DeFwModel {
    regs: Vec<u8>,
    pages: Vec<Vec<u8>>,
    writes: Vec<(u16, u8)>,
    checksum: bool,
    ready: bool,
    reset_clears: bool,
    wait_finish_after: u32,
    wait_reads: u32,
}

#[derive(Clone)]
struct DeFwFake(Arc<IrqSafeSpinLock<DeFwModel>>);

#[async_trait::async_trait]
impl Io for DeFwFake {
    fn read8(&self, reg: u16) -> Result<u8, FwError> {
        let mut g = self.0.lock();
        if reg == fw::REG_IN_PROCESS && g.wait_finish_after > 0 {
            g.wait_reads += 1;
            if g.wait_reads >= g.wait_finish_after {
                g.regs[usize::from(reg)] &= !fw::IN_PROCESS_BIT;
                g.regs[usize::from(fw::REG_MCUFWDL)] |= fw::MCUFWDL_EN | 0x02;
            }
        }
        // The firmware raises the MAC-ready bit once the image is
        // downloaded and marked ready; `fw_init` polls this byte.
        if (reg == fw::FW_MAC0_READY || reg == fw::FW_MAC1_READY)
            && g.ready
            && g.regs[usize::from(fw::REG_MCUFWDL)] & 0x02 != 0
        {
            return Ok(g.regs[usize::from(reg)] | fw::MAC_READY);
        }
        Ok(g.regs[usize::from(reg)])
    }
    fn read32(&self, reg: u16) -> Result<u32, FwError> {
        let g = self.0.lock();
        let r = usize::from(reg);
        let mut v = u32::from_le_bytes([g.regs[r], g.regs[r + 1], g.regs[r + 2], g.regs[r + 3]]);
        if reg == fw::REG_MCUFWDL
            && g.checksum
            && v & u32::from(fw::MCUFWDL_EN) == 0
            && !g.pages.is_empty()
        {
            v |= fw::FWDL_CHKSUM_RPT;
        }
        Ok(v)
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), FwError> {
        let mut g = self.0.lock();
        g.writes.push((reg, value));
        if reg == fw::REG_HMETFR + 3 && value == 0x20 && g.reset_clears {
            g.regs[usize::from(fw::REG_SYS_FUNC_EN) + 1] &= !fw::SYS_FUNC_EN_CPUEN;
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

fn de_fw_fake(checksum: bool, ready: bool, running: bool) -> DeFwFake {
    let mut regs = vec![0u8; 0x2000];
    if running {
        regs[usize::from(fw::REG_MCUFWDL)] = fw::RAM_DL_SEL;
    }
    regs[usize::from(fw::REG_SYS_FUNC_EN) + 1] = fw::SYS_FUNC_EN_CPUEN;
    DeFwFake(Arc::new(IrqSafeSpinLock::new(DeFwModel {
        regs,
        pages: Vec::new(),
        writes: Vec::new(),
        checksum,
        ready,
        reset_clears: true,
        wait_finish_after: 0,
        wait_reads: 0,
    })))
}

/// `rtl92d_download_fw`: running-image self-reset and `MCUFWDL = 0`,
/// 8051 enable + download gate, eight-page bound, `rtl_fill_dummy`,
/// close, checksum handshake, `MCUFWDL_RDY`, firmware-ready poll, and
/// the dual-MAC coordination (already-downloaded, wait-then-finish,
/// stuck-wait deadline, checksum/ready failures with the flag cleared).
fn smoke_rtl8192de_firmware_paged_download() -> TestResult {
    let payload: Vec<u8> = (0..(fw::PAGE + 5)).map(|i| i as u8).collect();
    let io = de_fw_fake(true, true, true);
    if narf_scheduler::block_on(fw::download(&io, &payload)).is_err() {
        return TestResult::Fail("8192DE model download failed");
    }
    let g = io.0.lock();
    if g.pages.len() != 2
        || g.pages[0] != payload[..fw::PAGE]
        || g.pages[1].len() != 8
        || g.pages[1][..5] != payload[fw::PAGE..]
        || g.pages[1][5..] != [0, 0, 0]
        || !g.writes.contains(&(fw::REG_HMETFR + 3, 0x20))
        || !g.writes.contains(&(fw::REG_MCUFWDL, 0))
        || g.regs[usize::from(fw::REG_IN_PROCESS)] & fw::IN_PROCESS_BIT != 0
        || g.regs[usize::from(fw::REG_MCUFWDL)] & 0x02 == 0
        || g.regs[usize::from(fw::REG_MCUFWDL)] & fw::MCUFWDL_EN != 0
    {
        return TestResult::Fail("8192DE download pages / gates / flag");
    }
    drop(g);
    // Already downloaded: no page writes, firmware-ready poll only.
    let downloaded = de_fw_fake(true, true, false);
    downloaded.0.lock().regs[usize::from(fw::REG_MCUFWDL)] |= 0x02;
    if narf_scheduler::block_on(fw::download(&downloaded, &payload)).is_err()
        || !downloaded.0.lock().pages.is_empty()
    {
        return TestResult::Fail("8192DE already-downloaded short-circuit");
    }
    // Other function finishes mid-wait: no download, ready poll only.
    let waiting = de_fw_fake(true, true, false);
    waiting.0.lock().regs[usize::from(fw::REG_IN_PROCESS)] |= fw::IN_PROCESS_BIT;
    waiting.0.lock().wait_finish_after = 3;
    if narf_scheduler::block_on(fw::download(&waiting, &payload)).is_err()
        || !waiting.0.lock().pages.is_empty()
    {
        return TestResult::Fail("8192DE dual-MAC wait-then-finish");
    }
    // Other function never finishes: deadline, flag never taken.
    let stuck = de_fw_fake(true, true, false);
    stuck.0.lock().regs[usize::from(fw::REG_IN_PROCESS)] |= fw::IN_PROCESS_BIT;
    if narf_scheduler::block_on(fw::download(&stuck, &payload)) != Err(FwError::Deadline) {
        return TestResult::Fail("8192DE stuck dual-MAC wait admitted");
    }
    // No checksum report: checksum error, flag cleared.
    let no_checksum = de_fw_fake(false, true, false);
    if narf_scheduler::block_on(fw::download(&no_checksum, &payload)) != Err(FwError::Checksum)
        || no_checksum.0.lock().regs[usize::from(fw::REG_IN_PROCESS)] & fw::IN_PROCESS_BIT != 0
    {
        return TestResult::Fail("8192DE checksum failure / flag leak");
    }
    // Firmware never ready: start error, flag cleared.
    let no_ready = de_fw_fake(true, false, false);
    if narf_scheduler::block_on(fw::download(&no_ready, &payload)) != Err(FwError::Start)
        || no_ready.0.lock().regs[usize::from(fw::REG_IN_PROCESS)] & fw::IN_PROCESS_BIT != 0
    {
        return TestResult::Fail("8192DE ready failure / flag leak");
    }
    // 8051 reset stuck: start error, flag cleared.
    let stuck_reset = de_fw_fake(true, true, true);
    stuck_reset.0.lock().reset_clears = false;
    if narf_scheduler::block_on(fw::download(&stuck_reset, &payload)) != Err(FwError::Start)
        || stuck_reset.0.lock().regs[usize::from(fw::REG_IN_PROCESS)] & fw::IN_PROCESS_BIT != 0
    {
        return TestResult::Fail("8192DE self-reset failure / flag leak");
    }
    if narf_scheduler::block_on(fw::download(&de_fw_fake(true, true, false), &[]))
        != Err(FwError::Image)
        || narf_scheduler::block_on(fw::download(
            &de_fw_fake(true, true, false),
            &vec![0; fw::MAX_PAYLOAD + 1],
        )) != Err(FwError::Image)
    {
        return TestResult::Fail("8192DE empty / oversized payload downloaded");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_firmware_paged_download
);

/// `trx.rs` fill: the 92D layout (rate dword 5, buffer dword 8, link
/// dword 10), the 5 GHz rate floor, the dual-dual MCS7 short-GI rule,
/// AMPDU 0x14, the RTS override without driver rate, the LPS hwseq
/// rule, bandwidth / sub-carrier selection, the `useramask` rate-id /
/// MAC-id rule, and the command descriptor.
fn smoke_rtl8192de_trx_fill() -> TestResult {
    let base = trx::TxParams {
        pkt_size: 100,
        queue_sel: trx::QSLT_BE,
        macid: 3,
        rate_id: 5,
        hw_rate: trx::DESC_RATEMCS7,
        use_driver_rate: true,
        disable_fallback: false,
        use_shortgi: false,
        use_shortpreamble: false,
        bw_40: true,
        packet_bw_40: true,
        cur_40_prime_sc: 1,
        ampdu: true,
        ampdu_density: 5,
        sec_type: 0,
        qos_data: true,
        seq: 0xabc,
        rts_enable: true,
        cts_enable: false,
        rts_rate: 0x08,
        rts_sc: 2,
        rts_stbc: true,
        rts_use_shortpreamble: false,
        rts_use_shortgi: true,
        buffer_len: 100,
        buffer_addr: 0xdead_0000,
        band_5g: false,
        dual_mac_dual_phy: true,
        fwctrl_lps: false,
        rdg_en: true,
        spe_rpt: false,
        sw_define: 0,
    };
    let d = trx::TxDesc::fill(&base);
    if d.own()
        || d.pkt_size() != 100
        || d.queue_sel() != trx::QSLT_BE
        || d.macid() != 3
        || d.tx_rate() != trx::DESC_RATEMCS7
        || d.data_bw() != 1
        || d.sub_carrier() != 3
        || d.buffer_addr() != 0xdead_0000
        || d.dw[5] & (1 << 6) == 0
        || d.dw[1] & (1 << 5) == 0
        || (d.dw[6] >> 11) & 0x1f != 0x14
        || (d.dw[3] >> 16) & 0xfff != 0xabc
        || d.dw[4] & (1 << 12) == 0
        || d.dw[4] & (1 << 13) == 0
        || d.dw[4] & 0x1f != 0x08
        || (d.dw[4] >> 30) & 0x3 != 1
        || d.dw[2] & (1 << 17) != 0
        || d.dw[1] & (1 << 7) == 0
        || d.dw[0] & (1 << 25) == 0
    {
        return TestResult::Fail("8192DE TX fill fields");
    }
    // 5 GHz floor: data and RTS rates below 6M rise to 6M.
    let g = trx::TxDesc::fill(&trx::TxParams {
        hw_rate: trx::DESC_RATE1M,
        rts_rate: trx::DESC_RATE1M,
        band_5g: true,
        ..base
    });
    if g.tx_rate() != trx::DESC_RATE6M || g.dw[4] & 0x1f != trx::DESC_RATE6M as u32 {
        return TestResult::Fail("8192DE 5 GHz rate floor");
    }
    // No driver rate: RTS rate is forced to 0x08 after the TCB value.
    let nodrv = trx::TxDesc::fill(&trx::TxParams {
        use_driver_rate: false,
        rts_rate: 0x0b,
        ..base
    });
    if nodrv.dw[4] & 0x1f != 0x08 {
        return TestResult::Fail("8192DE RTS override without driver rate");
    }
    // Non-QoS + firmware LPS: hwseq enable + packet id 8 (over 0).
    let lps = trx::TxDesc::fill(&trx::TxParams {
        qos_data: false,
        fwctrl_lps: true,
        ..base
    });
    if lps.dw[4] & (1 << 7) == 0 || (lps.dw[3] >> 28) & 0xf != 8 {
        return TestResult::Fail("8192DE LPS hwseq rule");
    }
    // 20 MHz: bandwidth 0, sub-carrier 0 regardless of prime.
    let narrow = trx::TxDesc::fill(&trx::TxParams {
        bw_40: false,
        cur_40_prime_sc: 2,
        ..base
    });
    if narrow.data_bw() != 0 || narrow.sub_carrier() != 0 {
        return TestResult::Fail("8192DE 20 MHz bandwidth fields");
    }
    // 40 MHz packet on a 20 MHz station: sub-carrier is the prime.
    let prime = trx::TxDesc::fill(&trx::TxParams {
        packet_bw_40: false,
        cur_40_prime_sc: 2,
        ..base
    });
    if prime.data_bw() != 0 || prime.sub_carrier() != 2 {
        return TestResult::Fail("8192DE 40 MHz prime sub-carrier");
    }
    if trx::rate_id_macid(true, 2, 5) != (2, 5) || trx::rate_id_macid(false, 2, 5) != (0x0e, 2) {
        return TestResult::Fail("8192DE rate-id / MAC-id rule");
    }
    let mut cmd = trx::TxDesc::fill_cmd(128, 0x1000_0000, false, false);
    if cmd.queue_sel() != trx::QSLT_BEACON
        || cmd.tx_rate() != trx::DESC_RATE1M
        || cmd.macid() != trx::CMD_MACID
        || cmd.buffer_addr() != 0x1000_0000
        || cmd.own()
    {
        return TestResult::Fail("8192DE command descriptor");
    }
    let cmd5 = trx::TxDesc::fill_cmd(128, 0x1000_0000, true, true);
    if cmd5.tx_rate() != trx::DESC_RATE6M
        || cmd5.dw[4] & (1 << 7) == 0
        || (cmd5.dw[3] >> 28) & 0xf != 8
    {
        return TestResult::Fail("8192DE 5 GHz / LPS command descriptor");
    }
    cmd.set_next(0x2000_0000);
    if cmd.dw[10] != 0x2000_0000 {
        return TestResult::Fail("8192DE ring link word");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_trx_fill
);

/// `trx.rs` RX decode: OWN refusal, every query field, the
/// software-decrypt + encryption-type rule, payload offset, hardware
/// error, and re-arm.
fn smoke_rtl8192de_trx_rx_status() -> TestResult {
    let mut dw = [0u32; 8];
    dw[0] |= 1 << 31;
    if trx::RxStatus::parse(&dw).is_some() {
        return TestResult::Fail("8192DE hardware-owned RX admitted");
    }
    dw = [0u32; 8];
    dw[0] |= 1500 | (1 << 14) | (2 << 16) | (1 << 24) | (1 << 26);
    dw[1] |= (1 << 14) | (1 << 15);
    dw[3] |= 0x13 | (1 << 6) | (1 << 8) | (1 << 9);
    dw[5] = 0x1234_5678;
    dw[6] = 0x4000_0000;
    let status = match trx::RxStatus::parse(&dw) {
        Some(s) => s,
        None => return TestResult::Fail("8192DE RX parse failed"),
    };
    if status.length != 1500
        || !status.crc
        || status.icv
        || status.drvinfo_size != 2 * trx::RX_DRV_INFO_SIZE_UNIT
        || status.shift != 1
        || !status.physt
        || status.decrypted
        || status.rate != 0x13
        || !status.short_preamble
        || !status.ampdu
        || !status.first_ampdu
        || status.bw != 1
        || !status.is_ht
        || status.tsfl != 0x1234_5678
        || status.payload_offset() != 32 + 16 + 1
        || !status.hw_error()
        || status.is_cck()
    {
        return TestResult::Fail("8192DE RX status fields");
    }
    // Decrypted only when not software-decrypted AND encrypted.
    dw[0] |= 4 << 20;
    let decrypted = trx::RxStatus::parse(&dw).unwrap();
    if !decrypted.decrypted {
        return TestResult::Fail("8192DE RX decrypted rule");
    }
    dw[0] |= 1 << 27;
    if trx::RxStatus::parse(&dw).unwrap().decrypted {
        return TestResult::Fail("8192DE RX software-decrypt rule");
    }
    let mut arm = [0u32; 8];
    trx::rx_arm(&mut arm, 0x4000_0000, 1536, true);
    if arm[6] != 0x4000_0000
        || arm[0] & 0x3fff != 1536
        || arm[0] & (1 << 30) == 0
        || arm[0] & (1 << 31) == 0
    {
        return TestResult::Fail("8192DE RX re-arm");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_trx_rx_status
);

// ── signed envelopes ──────────────────────────────────────────────────────

/// Test board factory (synthetic values, not any board's).
fn de_factory() -> crate::rtlwifi::efuse::Factory {
    crate::rtlwifi::efuse::Factory {
        mac: [0x00, 0xe0, 0x4c, 0x81, 0x92, 0xde],
        logical: [0u8; 512],
    }
}

/// A NAPC v2 row: (channel, bandwidth, offset, curve-value fn).
type NapcRowV2 = (u8, u8, u8, fn(u8, u8) -> i16);
/// A NAPC v3 row: (channel, band, bandwidth, offset, curve-value fn).
type NapcRowV3 = (u8, u8, u8, u8, fn(u8, u8, u8) -> i16);

/// Build a NAPC envelope from the documented layout (header 96, rows of
/// 388 bytes: channel/band/bandwidth/offset + three 64-entry curves).
/// `rows` are (channel, bandwidth, offset, curve-value fn) for v2, or
/// (channel, 20, 0, fn) for v1.
fn de_napc_fixture(version: u16, antenna: i16, qualified: i16, rows: &[NapcRowV2]) -> Vec<u8> {
    let factory = de_factory();
    let identity = crate::rtlwifi::radio::factory_identity(&factory);
    let total = 96 + rows.len() * 388;
    let mut bytes = vec![0u8; total];
    bytes[0..4].copy_from_slice(b"NAPC");
    bytes[4..6].copy_from_slice(&version.to_le_bytes());
    bytes[6..8].copy_from_slice(&96u16.to_le_bytes());
    bytes[8..12].copy_from_slice(&(total as u32).to_le_bytes());
    bytes[12..14].copy_from_slice(&0x10ecu16.to_le_bytes());
    bytes[14..16].copy_from_slice(&0x8193u16.to_le_bytes());
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
fn de_rising(_curve: u8, idx: u8) -> i16 {
    i16::from(idx) * 2
}

/// HT curve unmeasured: MCS rates can never be admitted.
fn de_no_ht(curve: u8, idx: u8) -> i16 {
    if curve == 2 {
        i16::MAX
    } else {
        i16::from(idx) * 2
    }
}

/// US 2.4 GHz domain: 2402-2472 MHz, 40 MHz, 20 dBm.
fn de_us_domain() -> narf_wireless::reg::RegulatoryDomain {
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

/// US 5 GHz domain: UNII-1/2/3 blocks, 80 MHz, 30 dBm (no flags, so
/// no DFS rule overlaps the test spans).
fn de_us_5g_domain() -> narf_wireless::reg::RegulatoryDomain {
    use narf_wireless::reg::*;
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![
            RegRule {
                freq_start_mhz: 5140,
                freq_end_mhz: 5360,
                max_bandwidth_mhz: 80,
                max_power_dbm: 30,
                flags: RegFlags::empty(),
            },
            RegRule {
                freq_start_mhz: 5460,
                freq_end_mhz: 5860,
                max_bandwidth_mhz: 80,
                max_power_dbm: 30,
                flags: RegFlags::empty(),
            },
        ],
    }
}

/// Build a v3 NAPC envelope from the documented layout (header 96,
/// rows of 516 bytes: channel/band/bandwidth/offset + four 64-entry
/// curves). `rows` are (channel, band, bandwidth, offset, curve fn)
/// with the curve fn taking (band, curve, index).
fn de_napc_v3_fixture(antenna: i16, qualified: i16, rows: &[NapcRowV3]) -> Vec<u8> {
    let factory = de_factory();
    let identity = crate::rtlwifi::radio::factory_identity(&factory);
    let total = 96 + rows.len() * 516;
    let mut bytes = vec![0u8; total];
    bytes[0..4].copy_from_slice(b"NAPC");
    bytes[4..6].copy_from_slice(&3u16.to_le_bytes());
    bytes[6..8].copy_from_slice(&96u16.to_le_bytes());
    bytes[8..12].copy_from_slice(&(total as u32).to_le_bytes());
    bytes[12..14].copy_from_slice(&0x10ecu16.to_le_bytes());
    bytes[14..16].copy_from_slice(&0x8193u16.to_le_bytes());
    bytes[16..48].copy_from_slice(&identity);
    bytes[48..54].copy_from_slice(&factory.mac);
    bytes[56..58].copy_from_slice(&antenna.to_le_bytes());
    bytes[58..60].copy_from_slice(&qualified.to_le_bytes());
    bytes[60..62].copy_from_slice(&(rows.len() as u16).to_le_bytes());
    for (i, (channel, band, bandwidth, offset, curve)) in rows.iter().enumerate() {
        let row = &mut bytes[96 + i * 516..96 + (i + 1) * 516];
        row[0] = *channel;
        row[1] = *band;
        row[2] = *bandwidth;
        row[3] = *offset;
        for curve_idx in 0..4u8 {
            for idx in 0..64u8 {
                let at = 4 + (usize::from(curve_idx) * 64 + usize::from(idx)) * 2;
                row[at..at + 2].copy_from_slice(&curve(*band, curve_idx, idx).to_le_bytes());
            }
        }
    }
    bytes
}

/// Flat rising curves on every family: output `2 * index` quarter
/// dBm, so an 80 qdBm ceiling with antenna 0 admits index 40 on
/// every rate. On 5 GHz rows the CCK curve (family 0) is unmeasured,
/// as the format requires.
fn de_v3_rising(band: u8, curve: u8, idx: u8) -> i16 {
    if band == 1 && curve == 0 {
        i16::MAX
    } else {
        i16::from(idx) * 2
    }
}

/// 2SS curve unmeasured: MCS8-15 can never be admitted, while every
/// other rate stays measured (5 GHz CCK still unmeasured).
fn de_v3_no_2ss(band: u8, curve: u8, idx: u8) -> i16 {
    if curve == 3 || (band == 1 && curve == 0) {
        i16::MAX
    } else {
        i16::from(idx) * 2
    }
}

/// 5 GHz CCK curve measured: a format violation on 5 GHz rows.
fn de_v3_cck_5g(_band: u8, _curve: u8, idx: u8) -> i16 {
    i16::from(idx) * 2
}

/// v1 parse + permission (all 20 rates admitted, index 40), tampered
/// variants, the 5 GHz row refusal, unordered rows, unmeasured HT,
/// and the v2 40 MHz point.
fn smoke_rtl8192de_envelope_parse_permission() -> TestResult {
    use envelope::*;
    let factory = de_factory();
    let domain = de_us_domain();
    let bytes = de_napc_fixture(1, 0, 80, &[(6, 20, 0, de_rising)]);
    let cal = match Calibration::from_verified(&bytes, Some([0xabu8; 32]), &factory) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("8192DE envelope v1 parse"),
    };
    if cal.operating_points().count() != 1 || !cal.measures(Operating::twenty(6)) {
        return TestResult::Fail("8192DE envelope v1 rows");
    }
    let permission = match cal.permission_for(&domain, Operating::twenty(6)) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("8192DE envelope v1 permission"),
    };
    if permission.channel() != 6
        || permission.admitted_rates() != 0xfffff
        || (0..20u8).any(|r| permission.index(r) != 40 || !permission.admits(r))
        || permission.admits(20)
        || permission.eirp_limit_qdbm() != 80
    {
        return TestResult::Fail("8192DE envelope v1 permission values");
    }
    let mut bad = bytes.clone();
    bad[0] = b'X';
    if Calibration::from_verified(&bad, Some([0xabu8; 32]), &factory).is_ok() {
        return TestResult::Fail("8192DE envelope bad magic admitted");
    }
    let mut wrong_device = bytes.clone();
    wrong_device[14..16].copy_from_slice(&0xb723u16.to_le_bytes());
    if Calibration::from_verified(&wrong_device, Some([0xabu8; 32]), &factory).is_ok() {
        return TestResult::Fail("8192DE envelope wrong device admitted");
    }
    if Calibration::from_verified(&bytes, None, &factory).is_ok() {
        return TestResult::Fail("8192DE envelope unsigned admitted");
    }
    let other = crate::rtlwifi::efuse::Factory {
        mac: [0x00, 0xe0, 0x4c, 0x81, 0x92, 0xdf],
        logical: [0u8; 512],
    };
    if Calibration::from_verified(&bytes, Some([0xabu8; 32]), &other).is_ok() {
        return TestResult::Fail("8192DE envelope identity mismatch admitted");
    }
    // A 5 GHz row (band byte 1) is a format failure in v2 (v2 is
    // 2.4 GHz-only; v3 admits band-1 rows — see the v3 test below).
    let mut banded = de_napc_fixture(2, 0, 80, &[(6, 20, 0, de_rising)]);
    banded[96 + 1] = 1;
    if Calibration::from_verified(&banded, Some([0xabu8; 32]), &factory).is_ok() {
        return TestResult::Fail("8192DE envelope 5 GHz row admitted");
    }
    let unordered = de_napc_fixture(2, 0, 80, &[(6, 40, 1, de_rising), (6, 20, 0, de_rising)]);
    if Calibration::from_verified(&unordered, Some([0xabu8; 32]), &factory).is_ok() {
        return TestResult::Fail("8192DE envelope unordered rows admitted");
    }
    let no_ht = de_napc_fixture(1, 0, 80, &[(6, 20, 0, de_no_ht)]);
    let cal_no_ht = match Calibration::from_verified(&no_ht, Some([0xabu8; 32]), &factory) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("8192DE envelope no-HT parse"),
    };
    if cal_no_ht
        .permission_for(&domain, Operating::twenty(6))
        .is_ok()
    {
        return TestResult::Fail("8192DE envelope unmeasured HT admitted");
    }
    let v2 = de_napc_fixture(2, 0, 80, &[(6, 20, 0, de_rising), (6, 40, 1, de_rising)]);
    let cal_v2 = match Calibration::from_verified(&v2, Some([0xabu8; 32]), &factory) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("8192DE envelope v2 parse"),
    };
    let wide = Operating {
        width: Width::W40Above,
        channel: 6,
    };
    if !wide.forty() || wide.prime_sc() != 1 || wide.center_mhz() != Some(2447) {
        return TestResult::Fail("8192DE envelope 40 MHz point shape");
    }
    match cal_v2.permission_for(&domain, wide) {
        Ok(p) if p.admitted_rates() == 0xfffff => {}
        _ => return TestResult::Fail("8192DE envelope v2 40 MHz permission"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_envelope_parse_permission
);

/// NAPC v3: 5 GHz rows + 2SS HT rates end to end — v3 parse, band
/// ordering, CCK-on-5GHz refusal, v2 5 GHz refusal, 5 GHz 20/40 MHz
/// permissions (CCK refused, MCS8-15 admitted), DFS refusal, the
/// two-stream gate on both RF types, and the ARFR MCS8-15 bits.
fn smoke_rtl8192de_envelope_v3_5ghz_two_stream() -> TestResult {
    use envelope::*;
    let factory = de_factory();
    let domain5 = de_us_5g_domain();
    let rows: &[NapcRowV3] = &[
        (6, 0, 20, 0, de_v3_rising),
        (36, 1, 20, 0, de_v3_rising),
        (40, 1, 20, 0, de_v3_rising),
        (165, 1, 20, 0, de_v3_rising),
        (36, 1, 40, 1, de_v3_rising),
        (40, 1, 40, 2, de_v3_rising),
    ];
    let bytes = de_napc_v3_fixture(0, 80, rows);
    let cal = match Calibration::from_verified(&bytes, Some([0xabu8; 32]), &factory) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("8192DE envelope v3 parse"),
    };
    if cal.operating_points().count() != 6
        || !cal.measures(Operating::twenty(36))
        || !cal.measures(Operating {
            width: Width::W40Above,
            channel: 36,
        })
    {
        return TestResult::Fail("8192DE envelope v3 rows");
    }
    if Operating::twenty(36).center_mhz() != Some(5180)
        || (Operating {
            width: Width::W40Above,
            channel: 36,
        })
        .center_mhz()
            != Some(5190)
        || (Operating {
            width: Width::W40Below,
            channel: 40,
        })
        .center_mhz()
            != Some(5190)
        || Operating::twenty(165).center_mhz() != Some(5825)
        || (Operating {
            width: Width::W40Above,
            channel: 165,
        })
        .center_mhz()
        .is_some()
        || (Operating {
            width: Width::W40Below,
            channel: 36,
        })
        .center_mhz()
        .is_some()
        || !station_channel(36)
        || !station_channel(38)
        || !station_channel(165)
        || station_channel(34)
        || station_frequency_mhz(36) != Some(5180)
        || station_channel_at(5180) != Some(36)
        || station_channel_at(5825) != Some(165)
    {
        return TestResult::Fail("8192DE envelope 5 GHz plan shape");
    }
    // 5 GHz 20 MHz: OFDM + MCS0-7 + MCS8-15 admitted (bits 4..27),
    // CCK refused, index 40, EIRP 80 (30 dBm rules, qualified 80).
    let p5 = match cal.permission_for(&domain5, Operating::twenty(36)) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("8192DE envelope 5 GHz permission"),
    };
    if p5.admitted_rates() != 0x0fff_fff0
        || p5.eirp_limit_qdbm() != 80
        || (0..4u8).any(|r| p5.admits(r))
        || (4..28u8).any(|r| !p5.admits(r) || p5.index(r) != 40)
    {
        return TestResult::Fail("8192DE envelope 5 GHz permission values");
    }
    // 5 GHz 40 MHz above (36) and below (40): same admission.
    for op in [
        Operating {
            width: Width::W40Above,
            channel: 36,
        },
        Operating {
            width: Width::W40Below,
            channel: 40,
        },
    ] {
        match cal.permission_for(&domain5, op) {
            Ok(p) if p.admitted_rates() == 0x0fff_fff0 && p.eirp_limit_qdbm() == 80 => {}
            _ => return TestResult::Fail("8192DE envelope 5 GHz 40 MHz permission"),
        }
    }
    // 2.4 GHz from the same v3 file: all 28 rates admitted.
    match cal.permission_for(&de_us_domain(), Operating::twenty(6)) {
        Ok(p) if p.admitted_rates() == 0x0fff_ffff && p.eirp_limit_qdbm() == 80 => {}
        _ => return TestResult::Fail("8192DE envelope v3 2.4 GHz permission"),
    }
    // Two-stream gate: 2T2R only, even with every 2SS rate measured.
    if !ht::admitted(&p5)
        || !ht::two_stream(&p5, RfType::TwoT2R)
        || ht::two_stream(&p5, RfType::OneT1R)
    {
        return TestResult::Fail("8192DE two-stream gate");
    }
    // Unmeasured 2SS curve: permission still mints (2SS never
    // required), MCS8-15 unadmitted, two-stream refused.
    let no_2ss = de_napc_v3_fixture(0, 80, &[(36, 1, 20, 0, de_v3_no_2ss)]);
    let cal_no_2ss = match Calibration::from_verified(&no_2ss, Some([0xabu8; 32]), &factory) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("8192DE envelope v3 no-2SS parse"),
    };
    match cal_no_2ss.permission_for(&domain5, Operating::twenty(36)) {
        Ok(p)
            if p.admitted_rates() == 0xfff0
                && ht::admitted(&p)
                && !ht::two_stream(&p, RfType::TwoT2R) => {}
        _ => return TestResult::Fail("8192DE envelope unmeasured 2SS admitted"),
    }
    // A measured CCK curve on a 5 GHz row is a format failure.
    let cck_5g = de_napc_v3_fixture(0, 80, &[(36, 1, 20, 0, de_v3_cck_5g)]);
    if Calibration::from_verified(&cck_5g, Some([0xabu8; 32]), &factory).is_ok() {
        return TestResult::Fail("8192DE envelope measured 5 GHz CCK admitted");
    }
    // A 5 GHz primary in a v2 file is a format failure even with the
    // band byte clear (v2 is 2.4 GHz-only).
    let v2_5g = de_napc_fixture(2, 0, 80, &[(36, 20, 0, de_rising)]);
    if Calibration::from_verified(&v2_5g, Some([0xabu8; 32]), &factory).is_ok() {
        return TestResult::Fail("8192DE envelope v2 5 GHz primary admitted");
    }
    // Band-1 rows before band-0 rows violate strict ordering.
    let unordered = de_napc_v3_fixture(
        0,
        80,
        &[(36, 1, 20, 0, de_v3_rising), (6, 0, 20, 0, de_v3_rising)],
    );
    if Calibration::from_verified(&unordered, Some([0xabu8; 32]), &factory).is_ok() {
        return TestResult::Fail("8192DE envelope v3 unordered bands admitted");
    }
    // A flagged (DFS) rule overlapping the span refuses the point.
    {
        use narf_wireless::reg::*;
        let mut dfs = de_us_5g_domain();
        dfs.rules[0].flags = RegFlags::DFS;
        if cal.permission_for(&dfs, Operating::twenty(36)).is_ok() {
            return TestResult::Fail("8192DE envelope DFS rule admitted");
        }
    }
    // ARFR: MCS8-15 bits present on 2T2R, absent on 1T1R.
    let sta = rate::StaRates {
        supp_rates: [0, 0xfff],
        mcs_rx_mask: [0xff, 0xff],
        mode: rate::WirelessMode::N5g,
        ht_enable: true,
        bw40: false,
        sgi20: false,
        sgi40: false,
    };
    let v2t = rate::rate_table_value(&sta, Band::On5Ghz, RfType::TwoT2R);
    let v1t = rate::rate_table_value(&sta, Band::On5Ghz, RfType::OneT1R);
    if v2t & (0xff << 20) != 0x0f00_0000 || v1t & (0xff << 20) != 0 {
        return TestResult::Fail("8192DE ARFR MCS8-15 bits");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_envelope_v3_5ghz_two_stream
);

/// Packet owner: firmware `Info` + envelope `Permission` admission,
/// TX fill fields, refusal rules, and RX decode.
fn smoke_rtl8192de_packet_admission_and_fill() -> TestResult {
    use envelope::*;
    use packet::*;
    let factory = de_factory();
    let domain = de_us_domain();
    let bytes = de_napc_fixture(1, 0, 80, &[(6, 20, 0, de_rising)]);
    let cal = match Calibration::from_verified(&bytes, Some([0xabu8; 32]), &factory) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("8192DE packet envelope parse"),
    };
    let permission = match cal.permission_for(&domain, Operating::twenty(6)) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("8192DE packet permission"),
    };
    let mut owner = Owner::admit(
        crate::rtlwifi::firmware_transport::Info {
            version: 0x1234,
            subversion: 0x56,
            payload: 100,
        },
        permission,
    );
    if owner.firmware_version() != 0x1234 {
        return TestResult::Fail("8192DE packet firmware version");
    }
    let mut slot = trx::TxDesc::default();
    let frame = TxFrame {
        op: Operating::twenty(6),
        class: FrameClass::Data { priority: 3 },
        len: 100,
        buf_addr: 0x3000_0000,
        rate: 12,
        seq: 0x42,
        short: false,
        rts: None,
        next_desc: 0x4000_0000,
        mode: rate::WirelessMode::N24g,
        cipher: KeyCipher::None,
        ampdu_density: None,
        adaptive: false,
        eapol: false,
        nullfunc: false,
        rdg_en: false,
    };
    if owner.fill_tx_slot(&mut slot, &frame).is_err()
        || slot.own()
        || slot.pkt_size() != 100
        || slot.queue_sel() != 3
        || slot.tx_rate() != 12
        || slot.buffer_addr() != 0x3000_0000
        || slot.dw[10] != 0x4000_0000
    {
        return TestResult::Fail("8192DE packet TX fill");
    }
    let wrong_op = TxFrame {
        op: Operating::twenty(7),
        ..frame
    };
    if owner.fill_tx_slot(&mut slot, &wrong_op) != Err(Error::NotAdmitted) {
        return TestResult::Fail("8192DE packet wrong operating point admitted");
    }
    let wrong_rate = TxFrame { rate: 20, ..frame };
    if owner.fill_tx_slot(&mut slot, &wrong_rate) != Err(Error::NotAdmitted) {
        return TestResult::Fail("8192DE packet unadmitted rate admitted");
    }
    let empty = TxFrame { len: 0, ..frame };
    if owner.fill_tx_slot(&mut slot, &empty) != Err(Error::Frame) {
        return TestResult::Fail("8192DE packet empty frame admitted");
    }
    let huge = TxFrame {
        len: 0x1_0000,
        ..frame
    };
    if owner.fill_tx_slot(&mut slot, &huge) != Err(Error::Frame) {
        return TestResult::Fail("8192DE packet oversized frame admitted");
    }
    let mut dw = [0u32; 8];
    dw[0] |= 1 << 31;
    if owner.service_rx(&dw, &[0u8; 64]) != Err(Error::NotReady) {
        return TestResult::Fail("8192DE packet hardware-owned RX serviced");
    }
    dw = [0u32; 8];
    dw[0] |= 10 | (1 << 16);
    let buffer = [0xabu8; 64];
    match owner.service_rx(&dw, &buffer) {
        Ok(rx) if rx.status.length == 10 && rx.payload == &buffer[32 + 8..32 + 8 + 10] => {}
        _ => return TestResult::Fail("8192DE packet RX decode"),
    }
    if owner.service_rx(&dw, &[0u8; 16]) != Err(Error::Frame) {
        return TestResult::Fail("8192DE packet short RX buffer admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_packet_admission_and_fill
);

// ── step 3: power-on + LLT + MAC init model ───────────────────────────────

struct DeMacModel {
    regs: Vec<u8>,
    llt_writes: u32,
    llt_stuck: bool,
    apfm_clear_after: u32,
    apfm_reads: u32,
    poip_clear_after: u32,
    poip_reads: u32,
    apsd_set_after: u32,
    apsd_reads: u32,
    /// Physical EFUSE bytes (`REG_EFUSE_CTRL` protocol model: the
    /// address latched by `CTRL+1`/`CTRL+2` reads back the byte at
    /// that address with `VALID` set). The address space is 10-bit
    /// (`0x000`–`0x3FF` — Linux's `read_efuse_byte` writes
    /// `(address >> 8) & 0x03` into `CTRL+2`), so this is 1024
    /// bytes even though the logical content length
    /// (`EFUSE_REAL_CONTENT_LEN`) is 512: the chip-version word
    /// lives at the top of the physical space (`0x3FE`/`0x3FF`).
    efuse: [u8; 1024],
    efuse_addr: u16,
    delays: u64,
    delay_us_total: u64,
    /// 3-wire RF register-file model, armed only by the LC tests (see
    /// `de_mac_rf_set`): `phy::rf_read`/`rf_write` go through the BB
    /// HSSI/LSSI registers, so the fake decodes the serial word and
    /// stages per-offset RF values into the path readback register.
    /// Unarmed, the flat staged bytes rule exactly as before.
    rf_model: bool,
    rf_regs: [[u32; 256]; 2],
    rf_present: [[bool; 256]; 2],
    rf_g6_set_after: [u32; 2],
    rf_g6_reads: [u32; 2],
}

#[derive(Clone)]
struct DeMacFake(Arc<IrqSafeSpinLock<DeMacModel>>);

#[async_trait::async_trait]
impl Io for DeMacFake {
    fn read8(&self, reg: u16) -> Result<u8, FwError> {
        let mut g = self.0.lock();
        if reg == power::REG_APS_FSMCO + 1 {
            g.apfm_reads += 1;
            if g.apfm_reads >= g.apfm_clear_after {
                g.regs[usize::from(reg)] &= !1;
            }
        }
        if reg == power::REG_POWER_OFF_IN_PROCESS {
            g.poip_reads += 1;
            if g.poip_reads >= g.poip_clear_after {
                g.regs[usize::from(reg)] &= !power::POWER_OFF_IN_PROCESS;
            }
        }
        if reg == mac::REG_APSD_CTRL {
            g.apsd_reads += 1;
            if g.apsd_reads >= g.apsd_set_after {
                g.regs[usize::from(reg)] |= 1 << 7;
            }
        }
        Ok(g.regs[usize::from(reg)])
    }
    fn read32(&self, reg: u16) -> Result<u32, FwError> {
        let g = self.0.lock();
        if reg == version::REG_EFUSE_CTRL {
            // Hardware completes the byte read: `VALID` set, the
            // latched physical byte as the low byte.
            return Ok(u32::from(g.efuse[usize::from(g.efuse_addr)]) | version::EFUSE_CTRL_VALID);
        }
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
        if reg == version::REG_EFUSE_CTRL + 1 {
            g.efuse_addr = (g.efuse_addr & 0x300) | u16::from(value);
        } else if reg == version::REG_EFUSE_CTRL + 2 {
            g.efuse_addr = (g.efuse_addr & 0xff) | ((u16::from(value) & 3) << 8);
        }
        g.regs[usize::from(reg)] = value;
        Ok(())
    }
    fn write16(&self, reg: u16, value: u16) -> Result<(), FwError> {
        let mut g = self.0.lock();
        let r = usize::from(reg);
        g.regs[r..r + 2].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), FwError> {
        let mut g = self.0.lock();
        let r = usize::from(reg);
        g.regs[r..r + 4].copy_from_slice(&value.to_le_bytes());
        if reg == llt::REG_LLT_INIT {
            g.llt_writes += 1;
            if !g.llt_stuck {
                // Hardware completes the write: op field reads back
                // NO_ACTIVE.
                g.regs[r + 3] &= !0xc0;
            }
        }
        if g.rf_model {
            match reg {
                0x840 => rf_record(&mut g, 0, value),
                0x844 => rf_record(&mut g, 1, value),
                0x824 => rf_stage(&mut g, 0, value),
                0x82c => rf_stage(&mut g, 1, value),
                _ => {}
            }
        }
        Ok(())
    }
    fn write_bytes(&self, _reg: u16, _bytes: &[u8]) -> Result<(), FwError> {
        Err(FwError::Access)
    }
    async fn delay_us(&self, micros: u64) {
        let mut g = self.0.lock();
        g.delays += 1;
        g.delay_us_total += micros;
    }
}

fn de_mac_fake() -> DeMacFake {
    DeMacFake(Arc::new(IrqSafeSpinLock::new(DeMacModel {
        regs: vec![0u8; 0x2000],
        llt_writes: 0,
        llt_stuck: false,
        apfm_clear_after: 3,
        apfm_reads: 0,
        poip_clear_after: 3,
        poip_reads: 0,
        apsd_set_after: 2,
        apsd_reads: 0,
        efuse: [0xffu8; 1024],
        efuse_addr: 0,
        delays: 0,
        delay_us_total: 0,
        rf_model: false,
        rf_regs: [[0; 256]; 2],
        rf_present: [[false; 256]; 2],
        rf_g6_set_after: [u32::MAX; 2],
        rf_g6_reads: [0; 2],
    })))
}

/// 3-wire serial write word (`phy::rf_write`): `(offset << 20) |
/// (data & 0xfffff)`. Records the RF register file for the path.
fn rf_record(g: &mut DeMacModel, path: usize, word: u32) {
    let offset = ((word >> 20) & 0xff) as usize;
    g.rf_regs[path][offset] = word & 0x000f_ffff;
    g.rf_present[path][offset] = true;
}

/// 3-wire serial read command (`phy::rf_read`): `(offset << 23) |
/// BLSSIREADEDGE`. Only the command write (edge set, nonzero offset)
/// stages the modeled value into the path's readback register; the
/// edge-low / edge-high framing writes carry a zero offset field and
/// are ignored, so an RF_AC (offset 0) read never clobbers the
/// readback. The RF_SYN_G6 poll bit sets once `rf_g6_set_after`
/// stagings have happened (`u32::MAX` = never, the timeout path).
fn rf_stage(g: &mut DeMacModel, path: usize, value: u32) {
    const BLSSIREADEDGE: u32 = 0x8000_0000;
    if value & BLSSIREADEDGE == 0 {
        return;
    }
    let offset = ((value >> 23) & 0x7f) as usize;
    if offset == 0 || !g.rf_present[path][offset] {
        return;
    }
    let mut staged = g.rf_regs[path][offset];
    if offset as u32 == lck::RF_SYN_G6 {
        g.rf_g6_reads[path] += 1;
        if g.rf_g6_reads[path] >= g.rf_g6_set_after[path] {
            staged |= 1 << 11;
        }
    }
    // Readback register: 0x8a0/0x8a4, or 0x8b8/0x8bc when the path's
    // HSSI parameter-1 PI bit (bit 8) is set.
    let para1 = if path == 0 { 0x820 } else { 0x828 };
    let pi = u32::from_le_bytes([
        g.regs[para1],
        g.regs[para1 + 1],
        g.regs[para1 + 2],
        g.regs[para1 + 3],
    ]) & (1 << 8)
        != 0;
    let rb = if path == 0 {
        if pi {
            0x8b8
        } else {
            0x8a0
        }
    } else if pi {
        0x8bc
    } else {
        0x8a4
    };
    g.regs[rb..rb + 4].copy_from_slice(&staged.to_le_bytes());
}

/// Arm the RF model and program one modeled RF register for a path.
fn de_mac_rf_set(io: &DeMacFake, path: usize, offset: u32, value: u32) {
    let mut g = io.0.lock();
    g.rf_model = true;
    g.rf_regs[path][offset as usize & 0xff] = value;
    g.rf_present[path][offset as usize & 0xff] = true;
}

/// Read back a modeled RF register for a path (0 when never written).
fn de_mac_rf_get(io: &DeMacFake, path: usize, offset: u32) -> u32 {
    io.0.lock().rf_regs[path][offset as usize & 0xff]
}

/// Arm the RF model and set after how many RF_SYN_G6 stagings the
/// BIT(11) poll bit sets for a path (`u32::MAX` = never).
fn de_mac_rf_set_g6_after(io: &DeMacFake, path: usize, after: u32) {
    let mut g = io.0.lock();
    g.rf_model = true;
    g.rf_g6_set_after[path] = after;
}

/// (`delay_us` calls, total delayed µs) observed so far.
fn de_mac_delays(io: &DeMacFake) -> (u64, u64) {
    let g = io.0.lock();
    (g.delays, g.delay_us_total)
}

fn de_mac_read8(io: &DeMacFake, reg: u16) -> u8 {
    io.0.lock().regs[usize::from(reg)]
}

fn de_mac_read16(io: &DeMacFake, reg: u16) -> u16 {
    let g = io.0.lock();
    u16::from_le_bytes([g.regs[usize::from(reg)], g.regs[usize::from(reg) + 1]])
}

fn de_mac_read32(io: &DeMacFake, reg: u16) -> u32 {
    let g = io.0.lock();
    let r = usize::from(reg);
    u32::from_le_bytes([g.regs[r], g.regs[r + 1], g.regs[r + 2], g.regs[r + 3]])
}

/// `rtl92d_phy_set_poweron` + the `_rtl92de_init_mac` power prefix,
/// single MAC on 2.4 GHz: band bit and MAC-ON land on `REG_MAC0`, the
/// V11 resume writes land, `REG_CR` ends at `0x2ff`, DMA stop clears.
fn smoke_rtl8192de_power_on_single() -> TestResult {
    let io = de_mac_fake();
    if narf_scheduler::block_on(power::power_on(
        &io,
        MacPhyMode::SingleMacSinglePhy,
        0,
        Band::On2Ghz,
    ))
    .is_err()
    {
        return TestResult::Fail("8192DE single power-on failed");
    }
    let g = io.0.lock();
    check(
        g.regs[usize::from(power::REG_MAC0)] == power::MAC0_ON | (1 << 1)
            && g.regs[usize::from(power::REG_MAC1)] == 0
            && g.regs[usize::from(power::REG_RSV_CTRL)] == 0
            && g.regs[usize::from(power::REG_LDOA15_CTRL)] == 0x05
            && g.regs[usize::from(power::REG_SPS0_CTRL)] == 0x2b
            && g.regs[usize::from(power::REG_AFE_XTAL_CTRL)] == 0x0f
            && u16::from_le_bytes([g.regs[0x04], g.regs[0x05]]) == 0x1012
            && g.regs[usize::from(power::REG_SYS_ISO_CTRL) + 1] == 0x82
            && u16::from_le_bytes([g.regs[0x100], g.regs[0x101]]) == 0x2ff
            && g.regs[usize::from(power::REG_PCIE_CTRL_REG) + 1] == 0,
        "8192DE single power-on registers",
    )
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_power_on_single
);

/// Dual MAC1 on 5 GHz: the band bit clears and `MAC1_ON` lands on
/// `REG_MAC1`, and the power-off-in-process wait observes the other
/// function finishing.
fn smoke_rtl8192de_power_on_dual_mac1() -> TestResult {
    let io = de_mac_fake();
    io.0.lock().regs[usize::from(power::REG_POWER_OFF_IN_PROCESS)] = power::POWER_OFF_IN_PROCESS;
    if narf_scheduler::block_on(power::power_on(
        &io,
        MacPhyMode::DualMacDualPhy,
        1,
        Band::On5Ghz,
    ))
    .is_err()
    {
        return TestResult::Fail("8192DE dual MAC1 power-on failed");
    }
    let g = io.0.lock();
    check(
        g.regs[usize::from(power::REG_MAC1)] == power::MAC1_ON
            && g.regs[usize::from(power::REG_MAC0)] == 0
            && g.poip_reads >= 3
            && g.regs[usize::from(power::REG_POWER_OFF_IN_PROCESS)] & power::POWER_OFF_IN_PROCESS
                == 0,
        "8192DE dual MAC1 power-on registers",
    )
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_power_on_dual_mac1
);

/// Failure paths: a stuck `APFM_ONMAC` is a gate error; a stuck
/// power-off-in-process wait is a deadline error.
fn smoke_rtl8192de_power_on_failures() -> TestResult {
    let stuck_apfm = de_mac_fake();
    stuck_apfm.0.lock().apfm_clear_after = u32::MAX;
    if narf_scheduler::block_on(power::power_on(
        &stuck_apfm,
        MacPhyMode::SingleMacSinglePhy,
        0,
        Band::On2Ghz,
    )) != Err(FwError::Gate)
    {
        return TestResult::Fail("8192DE stuck APFM_ONMAC admitted");
    }
    let stuck_poip = de_mac_fake();
    stuck_poip.0.lock().regs[usize::from(power::REG_POWER_OFF_IN_PROCESS)] =
        power::POWER_OFF_IN_PROCESS;
    stuck_poip.0.lock().poip_clear_after = u32::MAX;
    if narf_scheduler::block_on(power::power_on(
        &stuck_poip,
        MacPhyMode::DualMacDualPhy,
        0,
        Band::On5Ghz,
    )) != Err(FwError::Deadline)
    {
        return TestResult::Fail("8192DE stuck power-off wait admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_power_on_failures
);

/// LLT geometry per mode: single writes boundary 246 / max page 255 /
/// RQPN `0x80bf0d29` with 256 links; dual writes 123 / 127 /
/// `0x80750005` with 128 links; `REG_TRXFF_BNDY` keeps the live high
/// word; PBP `0x11`, RX driver-info size 4.
fn smoke_rtl8192de_llt_geometry() -> TestResult {
    let single = de_mac_fake();
    single.0.lock().regs[usize::from(llt::REG_TRXFF_BNDY) + 2] = 0x27;
    if llt::init(&single, MacPhyMode::SingleMacSinglePhy).is_err() {
        return TestResult::Fail("8192DE single LLT failed");
    }
    let g = single.0.lock();
    let single_ok = g.llt_writes == 256
        && u32::from_le_bytes([g.regs[0x200], g.regs[0x201], g.regs[0x202], g.regs[0x203]])
            == 0x80bf_0d29
        && u32::from_le_bytes([g.regs[0x114], g.regs[0x115], g.regs[0x116], g.regs[0x117]])
            == 0x0027_00f6
        && g.regs[usize::from(llt::REG_RQPN_NPQ)] == 0
        && g.regs[usize::from(llt::REG_TDECTRL) + 1] == 246
        && g.regs[usize::from(llt::REG_TXPKTBUF_BCNQ_BDNY)] == 246
        && g.regs[usize::from(llt::REG_TXPKTBUF_MGQ_BDNY)] == 246
        && g.regs[usize::from(llt::REG_LBK_BF_HD)] == 246
        && g.regs[usize::from(llt::REG_PBP)] == 0x11
        && g.regs[usize::from(llt::REG_RX_DRVINFO_SZ)] == 0x4;
    drop(g);
    if !single_ok {
        return TestResult::Fail("8192DE single LLT registers");
    }
    let dual = de_mac_fake();
    dual.0.lock().regs[usize::from(llt::REG_TRXFF_BNDY) + 2] = 0x13;
    if llt::init(&dual, MacPhyMode::DualMacDualPhy).is_err() {
        return TestResult::Fail("8192DE dual LLT failed");
    }
    let g = dual.0.lock();
    if g.llt_writes != 128
        || u32::from_le_bytes([g.regs[0x200], g.regs[0x201], g.regs[0x202], g.regs[0x203]])
            != 0x8075_0005
        || u32::from_le_bytes([g.regs[0x114], g.regs[0x115], g.regs[0x116], g.regs[0x117]])
            != 0x0013_007b
    {
        return TestResult::Fail("8192DE dual LLT registers");
    }
    drop(g);
    let stuck = de_mac_fake();
    stuck.0.lock().llt_stuck = true;
    if llt::init(&stuck, MacPhyMode::SingleMacSinglePhy) != Err(FwError::Deadline) {
        return TestResult::Fail("8192DE stuck LLT admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_llt_geometry
);

/// `rtl92d_phy_config_maccoexist_rfpage` per mode: DMC, RX packet
/// limit and the TRX FIFO boundary high word.
fn smoke_rtl8192de_maccoexist_rfpage() -> TestResult {
    let single = de_mac_fake();
    if mac::maccoexist_rfpage(&single, MacPhyMode::SingleMacSinglePhy).is_err() {
        return TestResult::Fail("8192DE single maccoexist page");
    }
    let g = single.0.lock();
    let single_ok = g.regs[usize::from(mac::REG_DMC)] == 0x00
        && g.regs[usize::from(mac::REG_RX_PKT_LIMIT)] == 0x10
        && u16::from_le_bytes([g.regs[0x116], g.regs[0x117]]) == 0x27ff;
    drop(g);
    if !single_ok {
        return TestResult::Fail("8192DE single maccoexist page");
    }
    let dual_single = de_mac_fake();
    if mac::maccoexist_rfpage(&dual_single, MacPhyMode::DualMacSinglePhy).is_err() {
        return TestResult::Fail("8192DE dual-single maccoexist page");
    }
    let g = dual_single.0.lock();
    let dual_single_ok = g.regs[usize::from(mac::REG_DMC)] == 0xf8
        && g.regs[usize::from(mac::REG_RX_PKT_LIMIT)] == 0x08
        && u16::from_le_bytes([g.regs[0x116], g.regs[0x117]]) == 0x13ff;
    drop(g);
    if !dual_single_ok {
        return TestResult::Fail("8192DE dual-single maccoexist page");
    }
    let dual = de_mac_fake();
    if mac::maccoexist_rfpage(&dual, MacPhyMode::DualMacDualPhy).is_err() {
        return TestResult::Fail("8192DE dual-dual maccoexist page");
    }
    let g = dual.0.lock();
    let dual_ok = g.regs[usize::from(mac::REG_DMC)] == 0x00
        && g.regs[usize::from(mac::REG_RX_PKT_LIMIT)] == 0x08
        && u16::from_le_bytes([g.regs[0x116], g.regs[0x117]]) == 0x13ff;
    drop(g);
    if !dual_ok {
        return TestResult::Fail("8192DE dual-dual maccoexist page");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_maccoexist_rfpage
);

/// End-to-end step 3 for dual-dual MAC0 on 5 GHz: power-on, LLT,
/// MAC init, HW configure, interrupt enable/disable, RCR trim, CAM
/// reset and station identity — the full register state Linux's
/// `_rtl92de_init_mac` + `_rtl92de_hw_configure` leave behind, minus
/// the descriptor bases (deferred to `Prepared`) and the PHY/BB/RF
/// steps (later lanes).
fn smoke_rtl8192de_mac_init_end_to_end() -> TestResult {
    let io = de_mac_fake();
    io.0.lock().regs[usize::from(power::REG_POWER_OFF_IN_PROCESS)] = power::POWER_OFF_IN_PROCESS;
    io.0.lock().regs[usize::from(llt::REG_TRXFF_BNDY) + 2] = 0x27;
    if narf_scheduler::block_on(power::power_on(
        &io,
        MacPhyMode::DualMacDualPhy,
        0,
        Band::On5Ghz,
    ))
    .is_err()
    {
        return TestResult::Fail("8192DE e2e power-on failed");
    }
    if llt::init(&io, MacPhyMode::DualMacDualPhy).is_err() {
        return TestResult::Fail("8192DE e2e LLT failed");
    }
    if narf_scheduler::block_on(mac::init_mac(&io, MacPhyMode::DualMacDualPhy)).is_err() {
        return TestResult::Fail("8192DE e2e init_mac failed");
    }
    if mac::hw_configure(&io, MacPhyMode::DualMacDualPhy).is_err() {
        return TestResult::Fail("8192DE e2e hw_configure failed");
    }
    // Snapshot the byte-wide registers under one lock, then check the
    // word/dword registers through the helpers (which lock themselves).
    let g = io.0.lock();
    let hisre = g.regs[usize::from(mac::REG_HISRE)];
    let fwhw_txq_hi = g.regs[usize::from(mac::REG_FWHW_TXQ_CTRL) + 1];
    let reg_4d0 = g.regs[0x04d0];
    let pcie_3 = g.regs[usize::from(mac::REG_PCIE_CTRL_REG) + 3];
    let apsd = g.regs[usize::from(mac::REG_APSD_CTRL)];
    let inirts = g.regs[usize::from(mac::REG_INIRTS_RATE_SEL)];
    let bwopmode = g.regs[usize::from(mac::REG_BWOPMODE)];
    let slot = g.regs[usize::from(mac::REG_SLOT)];
    let ampdu_min_space = g.regs[usize::from(mac::REG_AMPDU_MIN_SPACE)];
    let hwseq = g.regs[usize::from(mac::REG_HWSEQ_CTRL)];
    let atimwnd = g.regs[usize::from(mac::REG_ATIMWND)];
    let bcn_max_err = g.regs[usize::from(mac::REG_BCN_MAX_ERR)];
    let bcn_ctrl = g.regs[usize::from(mac::REG_BCN_CTRL)];
    let tbtt_prohibit_1 = g.regs[usize::from(mac::REG_TBTT_PROHIBIT) + 1];
    let pifs = g.regs[usize::from(mac::REG_PIFS)];
    let aggr_break = g.regs[usize::from(mac::REG_AGGR_BREAK_TIME)];
    let ackto = g.regs[usize::from(mac::REG_ACKTO)];
    drop(g);
    if de_mac_read32(&io, mac::REG_HISR) != u32::MAX
        || hisre != 0xff
        || de_mac_read16(&io, mac::REG_TRXDMA_CTRL) != 0xf771
        || fwhw_txq_hi != 0x1f
        || de_mac_read16(&io, mac::REG_FWHW_TXQ_CTRL) != 0x1f80
        || de_mac_read32(&io, mac::REG_RCR) != mac::RCR
        || de_mac_read32(&io, mac::REG_TCR) != mac::TCR
        || reg_4d0 != 0
        || pcie_3 != mac::PCIE_CTRL_REG_3
        || de_mac_read32(&io, mac::REG_INT_MIG) != 0
        || apsd & (1 << 6) != 0
        || de_mac_read32(&io, mac::REG_MCUTST_1) != 0
        || inirts != 0x8
        || bwopmode != mac::BWOPMODE_20MHZ
        || de_mac_read32(&io, mac::REG_RRSR) != mac::RRSR
        || slot != 0x09
        || ampdu_min_space != 0
        || de_mac_read16(&io, mac::REG_RL) != 0x0707
        || de_mac_read32(&io, mac::REG_BAR_MODE_CTRL) != 0x0201_2802
        || hwseq != 0xff
        || de_mac_read32(&io, mac::REG_DARFRC) != 0x0100_0000
        || de_mac_read32(&io, mac::REG_DARFRC + 4) != 0x0706_0504
        || de_mac_read32(&io, mac::REG_RARFRC) != 0x0100_0000
        || de_mac_read32(&io, mac::REG_RARFRC + 4) != 0x0706_0504
        || de_mac_read32(&io, mac::REG_AGGLEN_LMT) != 0xb972_6641
        || atimwnd != 0x2
        || bcn_max_err != 0x0a
        || bcn_ctrl != 0x1f
        || tbtt_prohibit_1 != 0xff
        || pifs != 0x1c
        || aggr_break != 0x16
        || de_mac_read16(&io, mac::REG_NAV_PROT_LEN) != 0x0020
        || de_mac_read16(&io, mac::REG_FAST_EDCA_CTRL) != 0x6666
        || ackto != 0x40
        || de_mac_read16(&io, mac::REG_SPEC_SIFS) != 0x1010
        || de_mac_read16(&io, mac::REG_MAC_SPEC_SIFS) != 0x1010
        || de_mac_read16(&io, mac::REG_SIFS_CTX) != 0x1010
        || de_mac_read16(&io, mac::REG_SIFS_TRX) != 0x1010
        || de_mac_read32(&io, mac::REG_MAR) != u32::MAX
        || de_mac_read32(&io, mac::REG_MAR + 4) != u32::MAX
    {
        return TestResult::Fail("8192DE e2e MAC registers");
    }
    if mac::enable_interrupt(&io).is_err()
        || de_mac_read32(&io, mac::REG_HIMR) != mac::IRQ_MASK.0
        || de_mac_read32(&io, mac::REG_HIMRE) != mac::IRQ_MASK.1
        || mac::disable_interrupt(&io).is_err()
        || de_mac_read32(&io, mac::REG_HIMR) != 0
        || de_mac_read32(&io, mac::REG_HIMRE) != 0
    {
        return TestResult::Fail("8192DE e2e interrupt masks");
    }
    match mac::trim_receive_config(&io) {
        Ok(rcr) if rcr == mac::RCR & !mac::RCR_ACRC32_AICV => {}
        _ => return TestResult::Fail("8192DE e2e RCR trim"),
    }
    if mac::cam_reset(&io).is_err()
        || de_mac_read32(&io, mac::REG_CAMCMD) != mac::CAM_RESET
        || mac::station_identity(&io, &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]).is_err()
    {
        return TestResult::Fail("8192DE e2e CAM / station identity");
    }
    let g = io.0.lock();
    let identity_ok = g.regs[usize::from(mac::REG_SECCFG)] == 0
        && g.regs[usize::from(mac::REG_MACID)] == 0x00
        && g.regs[usize::from(mac::REG_MACID) + 5] == 0x55;
    drop(g);
    if !identity_ok {
        return TestResult::Fail("8192DE e2e CAM / station identity");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_mac_init_end_to_end
);

/// The `REG_APSD_CTRL` BIT(7) poll proceeds after 200 reads even when
/// the bit never sets, exactly as Linux does — it is not a failure.
fn smoke_rtl8192de_apsd_poll_proceeds() -> TestResult {
    let io = de_mac_fake();
    io.0.lock().apsd_set_after = u32::MAX;
    if narf_scheduler::block_on(mac::init_mac(&io, MacPhyMode::SingleMacSinglePhy)).is_err()
        || io.0.lock().apsd_reads != 201
    {
        return TestResult::Fail("8192DE APSD poll did not proceed after 200 reads");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_apsd_poll_proceeds
);

// ── step 4: station chains, bands/HT/QoS/lifecycle, TX-power, factory table ─

use super::{channel, h2c, lifecycle, phy, rate, station, txpower};
use crate::rtlwifi::prepare::Error as PrepError;

/// Channel groups, right-channel places and IQK places, derived from
/// the Linux `channel_plan` / `rtl92d_set_channel_access` tables
/// (`rtl8192d/phy_common.h`, `rtl8192de/phy.c`).
fn smoke_rtl8192de_channel_places() -> TestResult {
    let groups: [(u8, usize); 15] = [
        (0, 0),
        (2, 0),
        (3, 1),
        (8, 1),
        (9, 2),
        (13, 2),
        (14, 3),
        (20, 4),
        (28, 5),
        (29, 6),
        (42, 7),
        (49, 8),
        (50, 9),
        (55, 10),
        (58, 11),
    ];
    for (index, group) in groups {
        if channel::chnlgroup_fromarray(index) != group {
            return TestResult::Fail("8192DE channel group by array index");
        }
    }
    for (index, group) in [(0u8, 0usize), (9, 2), (14, 6), (29, 7), (50, 8)] {
        if channel::chnlgroup_bypg(index) != group {
            return TestResult::Fail("8192DE channel group by PG");
        }
    }
    for (chnl, place) in [(1u8, 1u8), (14, 14), (36, 15), (165, 59)] {
        if channel::rightchnlplace(chnl) != place {
            return TestResult::Fail("8192DE right channel place");
        }
    }
    if channel::rightchnlplace(0) != 0 || channel::rightchnlplace(166) != 0 {
        return TestResult::Fail("8192DE unknown channel place");
    }
    for (chnl, place) in [(1u8, 0u8), (36, 1), (64, 15), (165, 45)] {
        if channel::iqk_place(chnl) != place {
            return TestResult::Fail("8192DE IQK place");
        }
    }
    if channel::iqk_place(0) != 0 || channel::iqk_place(100) != 0 {
        return TestResult::Fail("8192DE IQK place for unknown channel");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_channel_places
);

/// `Operating` wide-channel derivation and validation, incl. the
/// 2.4 GHz edge (channel 1, 40 MHz minus is invalid) and the 5 GHz
/// edge (channel 165, 40 MHz plus is invalid).
fn smoke_rtl8192de_operating() -> TestResult {
    let ok = [
        (
            1u8,
            channel::ChannelType::Ht20,
            1u8,
            channel::PRIME_CHNL_OFFSET_DONT_CARE,
        ),
        (
            6,
            channel::ChannelType::Ht40Plus,
            8,
            channel::PRIME_CHNL_OFFSET_LOWER,
        ),
        (
            6,
            channel::ChannelType::Ht40Minus,
            4,
            channel::PRIME_CHNL_OFFSET_UPPER,
        ),
        (
            36,
            channel::ChannelType::Ht40Plus,
            38,
            channel::PRIME_CHNL_OFFSET_LOWER,
        ),
        (
            100,
            channel::ChannelType::Ht40Minus,
            98,
            channel::PRIME_CHNL_OFFSET_UPPER,
        ),
    ];
    for (channel, ht, wide, prime) in ok {
        match channel::Operating::new(channel, ht) {
            Ok(op) if op.wide == wide && op.prime_sc == prime => {}
            _ => return TestResult::Fail("8192DE operating wide channel"),
        }
    }
    for (channel, ht) in [
        (0u8, channel::ChannelType::Ht20),
        (1, channel::ChannelType::Ht40Minus),
        (13, channel::ChannelType::Ht40Plus),
        (165, channel::ChannelType::Ht40Plus),
        (166, channel::ChannelType::Ht20),
    ] {
        if channel::Operating::new(channel, ht).is_ok() {
            return TestResult::Fail("8192DE invalid operating admitted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_operating
);

/// The DE factory table: `PgStore::from_pg` walks the step-1
/// `tables::PHY_REG_PG` triples into `mcs_offset[13][16]`; the expected
/// group count and the first group's first slot are re-derived here by
/// scanning the table bytes directly (not from `PgStore`).
fn smoke_rtl8192de_pg_factory_walk() -> TestResult {
    let table = super::tables::PHY_REG_PG;
    let mut expected_groups = 0u8;
    let mut first_slot: Option<u32> = None;
    for triple in table.chunks_exact(3) {
        if triple[0] == u32::from(phy::RTXAGC_B_MCS15_MCS12) {
            expected_groups = expected_groups.saturating_add(1);
        }
        if triple[0] == u32::from(phy::RTXAGC_A_RATE18_06) && first_slot.is_none() {
            first_slot = Some(triple[2]);
        }
    }
    let store = match phy::PgStore::from_pg(&table) {
        Ok(store) => store,
        Err(_) => return TestResult::Fail("8192DE factory table walk failed"),
    };
    if store.pwrgroup_cnt != expected_groups
        || expected_groups == 0
        || store.mcs_offset[0][0] != first_slot.unwrap_or(0)
    {
        return TestResult::Fail("8192DE factory table group count / first slot");
    }
    // A truncated tail is ignored, not an error.
    let truncated = &table[..table.len() - 1];
    if phy::PgStore::from_pg(truncated).is_err() {
        return TestResult::Fail("8192DE factory table truncated tail rejected");
    }
    // 14 groups' worth of slot-13 rows overflow the 13-group store.
    let mut overflow: Vec<u32> = Vec::with_capacity(14 * 3);
    for _ in 0..14 {
        overflow.extend_from_slice(&[
            u32::from(phy::RTXAGC_B_MCS15_MCS12),
            0xffff_ffff,
            0x0101_0101,
        ]);
    }
    if phy::PgStore::from_pg(&overflow).is_ok() {
        return TestResult::Fail("8192DE factory table group overflow admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_pg_factory_walk
);

/// EFUSE decode: the autoload-fail defaults, the normal branch with
/// 0xFF fallbacks, the 5 GHz TSSI bit packing, and the short-map
/// rejection.
fn smoke_rtl8192de_efuse_decode() -> TestResult {
    // Autoload failure: every factory byte is the 0x2C default on
    // 2.4 GHz, 0x22 on 5 GHz; regulatory 0, thermal 0x12.
    let fail = match txpower::Efuse::from_hwinfo(&[0u8; 256], true, false) {
        Ok(efuse) => efuse,
        Err(_) => return TestResult::Fail("8192DE autoload-fail decode"),
    };
    if fail.cck[0][0] != 0x2c
        || fail.cck[1][2] != 0x2c
        || fail.ht40_1s[0][14] != 0x22
        || fail.ht40_1s[1][14] != 0x22
        || fail.regulatory != 0
        || fail.thermalmeter != 0x12
        || fail.txpwr_fromeprom
    {
        return TestResult::Fail("8192DE autoload-fail defaults");
    }
    // Normal branch: known bytes at the factory offsets.
    let mut hw = [0u8; 256];
    hw[0x61] = 0x20;
    hw[0x62] = 0x21;
    hw[0x63] = 0x22;
    hw[0x64] = 0x23;
    hw[0x65] = 0x24;
    hw[0x66] = 0x25;
    hw[0x67] = 0x30;
    hw[0x68] = 0x31;
    hw[0x69] = 0x32;
    hw[0x6a] = 0x33;
    hw[0x6d] = 0x21;
    hw[0xc4] = 0x02;
    hw[0xc3] = 0x10;
    hw[0xbd] = 0x05;
    hw[0xbc] = 0x01;
    hw[0xbe] = 0x2a;
    hw[0xbf] = 0x15;
    hw[0xc0] = 0xe4;
    hw[0xc1] = 0x6b;
    hw[0xc2] = 0x93;
    hw[0xc9] = 0xff;
    hw[0xcc] = 0xab;
    let efuse = match txpower::Efuse::from_hwinfo(&hw, false, false) {
        Ok(efuse) => efuse,
        Err(_) => return TestResult::Fail("8192DE normal EFUSE decode"),
    };
    if efuse.cck[0][0] != 0x20
        || efuse.cck[0][1] != 0x21
        || efuse.cck[0][2] != 0x22
        || efuse.cck[1][0] != 0x23
        || efuse.cck[1][1] != 0x24
        || efuse.cck[1][2] != 0x25
        || efuse.ht40_1s[0][0] != 0x30
        || efuse.ht40_1s[1][0] != 0x33
        || efuse.ht40_2s[0][0] != 0x30 - 1
        || efuse.ht40_2s[1][0] != 0x33 - 2
        || efuse.regulatory != 2
        || efuse.thermalmeter != 0x10
        || efuse.crystalcap != 0x05
        || efuse.delta_iqk != 4
        || efuse.delta_lck != 4
        || efuse.tssi_a[0] != 0x2a
        || efuse.tssi_b[0] != 0x15
        || efuse.tssi_a[1] != 0x24
        || efuse.tssi_b[1] != 0x2f
        || efuse.tssi_a[2] != 0x36
        || efuse.tssi_b[2] != 0x24
        || efuse.eeprom_c9 != 0
        || efuse.eeprom_cc != 0xab
        || !efuse.txpwr_fromeprom
    {
        return TestResult::Fail("8192DE normal EFUSE values");
    }
    // 0xFF in a factory byte falls back to the 0x2C default.
    hw[0x61] = 0xff;
    let efuse = match txpower::Efuse::from_hwinfo(&hw, false, false) {
        Ok(efuse) => efuse,
        Err(_) => return TestResult::Fail("8192DE 0xFF fallback decode"),
    };
    if efuse.cck[0][0] != 0x2c {
        return TestResult::Fail("8192DE 0xFF factory fallback");
    }
    // A short map is rejected, never partially decoded.
    if txpower::Efuse::from_hwinfo(&[0u8; 0xcc], false, false).is_ok() {
        return TestResult::Fail("8192DE short EFUSE map admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_efuse_decode
);

/// A zeroed `PgStore` (all factory diffs zero) so `set_level` writes
/// exactly the EFUSE base levels into the AGC registers.
fn zero_pg() -> phy::PgStore {
    phy::PgStore {
        mcs_offset: [[0; 16]; 13],
        pwrgroup_cnt: 13,
    }
}

/// EFUSE map for the `set_level` register tests: channel 6 (group 1)
/// CCK 0x20/0x21, OFDM 0x30/0x31, 5 GHz channel 36 (group 3) OFDM
/// 0x28, regulatory 0.
fn level_hwinfo() -> [u8; 256] {
    let mut hw = [0u8; 256];
    hw[0x62] = 0x20;
    hw[0x65] = 0x21;
    hw[0x68] = 0x30;
    hw[0x6b] = 0x31;
    hw[0x7c] = 0x28;
    hw
}

/// `set_level` on 2.4 GHz: the CCK AGC words, the OFDM/MCS AGC words
/// (incl. the 0xc90/0xc98 tail), the returned `PowerLevels`, and the
/// `linux_indices` agreement — including the CCK 11M path-A byte at
/// bits 24–31 of 0x86c that the 92CE port zeroes.
fn smoke_rtl8192de_set_level_24g() -> TestResult {
    let efuse = match txpower::Efuse::from_hwinfo(&level_hwinfo(), false, false) {
        Ok(efuse) => efuse,
        Err(_) => return TestResult::Fail("8192DE level EFUSE decode"),
    };
    let io = de_mac_fake();
    let levels = match txpower::set_level(
        &io,
        &efuse,
        super::RfType::TwoT2R,
        &zero_pg(),
        6,
        super::Band::On2Ghz,
        false,
        false,
    ) {
        Ok(levels) => levels,
        Err(_) => return TestResult::Fail("8192DE set_level 2.4G"),
    };
    if levels.cck != [0x20, 0x21]
        || levels.ofdm != [0x30, 0x31]
        || levels.current != Some((0x20, 0x30))
        || !levels.from_eeprom
    {
        return TestResult::Fail("8192DE set_level 2.4G returned levels");
    }
    if de_mac_read32(&io, 0x86c) != 0x2020_2021
        || de_mac_read32(&io, 0x838) != 0x2121_2100
        || de_mac_read32(&io, 0xe00) != 0x3030_3030
        || de_mac_read32(&io, 0xe10) != 0x3030_3030
        || de_mac_read32(&io, 0xe1c) != 0x3030_3030
        || de_mac_read32(&io, 0xc90) != 0x28
        || de_mac_read32(&io, 0xc91) != 0x20
        || de_mac_read32(&io, 0xc92) != 0x1a
    {
        return TestResult::Fail("8192DE set_level 2.4G AGC registers");
    }
    // `linux_indices` agrees with the registers the driver wrote.
    let indices = match txpower::linux_indices(
        &efuse,
        super::RfType::TwoT2R,
        &zero_pg(),
        6,
        super::Band::On2Ghz,
        false,
    ) {
        Ok(indices) => indices,
        Err(_) => return TestResult::Fail("8192DE linux_indices"),
    };
    if indices[0][1] != 0x20
        || indices[0][3] != 0x20
        || indices[1][0] != 0x21
        || indices[1][3] != 0x21
        || indices[0][3] != ((de_mac_read32(&io, 0x86c) >> 24) & 0xff) as u8
    {
        return TestResult::Fail("8192DE linux_indices / register agreement");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_set_level_24g
);

/// `set_level` on 5 GHz: no CCK words are written, the OFDM words
/// come from the 5 GHz factory group, and the returned current level
/// has no CCK component.
fn smoke_rtl8192de_set_level_5g() -> TestResult {
    let efuse = match txpower::Efuse::from_hwinfo(&level_hwinfo(), false, false) {
        Ok(efuse) => efuse,
        Err(_) => return TestResult::Fail("8192DE level EFUSE decode"),
    };
    let io = de_mac_fake();
    let levels = match txpower::set_level(
        &io,
        &efuse,
        super::RfType::TwoT2R,
        &zero_pg(),
        36,
        super::Band::On5Ghz,
        false,
        false,
    ) {
        Ok(levels) => levels,
        Err(_) => return TestResult::Fail("8192DE set_level 5G"),
    };
    if levels.cck != [0, 0]
        || levels.ofdm != [0x28, 0x00]
        || levels.current.is_some()
        || de_mac_read32(&io, 0x86c) != 0
        || de_mac_read32(&io, 0xe00) != 0x2828_2828
    {
        return TestResult::Fail("8192DE set_level 5G registers");
    }
    // Autoload-fail EFUSE writes nothing.
    let fail = match txpower::Efuse::from_hwinfo(&[0u8; 256], true, false) {
        Ok(efuse) => efuse,
        Err(_) => return TestResult::Fail("8192DE autoload-fail decode"),
    };
    let io = de_mac_fake();
    if txpower::set_level(
        &io,
        &fail,
        super::RfType::TwoT2R,
        &zero_pg(),
        6,
        super::Band::On2Ghz,
        false,
        false,
    )
    .is_err()
        || de_mac_read32(&io, 0x86c) != 0
        || de_mac_read32(&io, 0xe00) != 0
    {
        return TestResult::Fail("8192DE autoload-fail set_level wrote");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_set_level_5g
);

/// The regulatory writeval branches: regulatory 1 reads the
/// `mcs_offset` group for the channel (and falls back to the bare base
/// when the factory table is not fully loaded); regulatory 3 clamps
/// each byte to the HT20 group limit before adding the base.
fn smoke_rtl8192de_writeval_regulatory() -> TestResult {
    let mut hw = level_hwinfo();
    hw[0xc4] = 0x01;
    let efuse = match txpower::Efuse::from_hwinfo(&hw, false, false) {
        Ok(efuse) => efuse,
        Err(_) => return TestResult::Fail("8192DE regulatory EFUSE decode"),
    };
    // Channel 6, 20 MHz: group 2, index 0.
    let mut pg = zero_pg();
    pg.mcs_offset[2][0] = 0x0101_0101;
    let io = de_mac_fake();
    if txpower::set_level(
        &io,
        &efuse,
        super::RfType::TwoT2R,
        &pg,
        6,
        super::Band::On2Ghz,
        false,
        false,
    )
    .is_err()
        || de_mac_read32(&io, 0xe00) != 0x3131_3131
    {
        return TestResult::Fail("8192DE regulatory 1 writeval");
    }
    // Fewer than 13 groups loaded: the group write is discarded.
    pg.pwrgroup_cnt = 5;
    let io = de_mac_fake();
    if txpower::set_level(
        &io,
        &efuse,
        super::RfType::TwoT2R,
        &pg,
        6,
        super::Band::On2Ghz,
        false,
        false,
    )
    .is_err()
        || de_mac_read32(&io, 0xe00) != 0x3030_3030
    {
        return TestResult::Fail("8192DE regulatory 1 partial group fallback");
    }
    // Regulatory 3: 0x3f diffs clamp to the 0x0f HT20 limit.
    let mut hw = level_hwinfo();
    hw[0xc4] = 0x03;
    hw[0x7a] = 0x0f;
    let efuse = match txpower::Efuse::from_hwinfo(&hw, false, false) {
        Ok(efuse) => efuse,
        Err(_) => return TestResult::Fail("8192DE regulatory 3 EFUSE decode"),
    };
    let mut pg = zero_pg();
    pg.mcs_offset[0][0] = 0x3f3f_3f3f;
    let io = de_mac_fake();
    if txpower::set_level(
        &io,
        &efuse,
        super::RfType::TwoT2R,
        &pg,
        6,
        super::Band::On2Ghz,
        false,
        false,
    )
    .is_err()
        || de_mac_read32(&io, 0xe00) != 0x3f3f_3f3f
    {
        return TestResult::Fail("8192DE regulatory 3 clamp");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_writeval_regulatory
);

/// The station rate table: B/G/N/A mode masks, the 1T1R/2T2R masks
/// and the short-GI BIT(28), plus the `REG_ARFR0` write.
fn smoke_rtl8192de_rate_table() -> TestResult {
    let cases = [
        (
            rate::StaRates {
                supp_rates: [0x000f, 0],
                mcs_rx_mask: [0, 0],
                mode: rate::WirelessMode::B,
                ht_enable: false,
                bw40: false,
                sgi20: false,
                sgi40: false,
            },
            super::Band::On2Ghz,
            super::RfType::TwoT2R,
            0x000d,
        ),
        (
            rate::StaRates {
                supp_rates: [0x0fff, 0],
                mcs_rx_mask: [0, 0],
                mode: rate::WirelessMode::G,
                ht_enable: false,
                bw40: false,
                sgi20: false,
                sgi40: false,
            },
            super::Band::On2Ghz,
            super::RfType::TwoT2R,
            0x0ff5,
        ),
        (
            rate::StaRates {
                supp_rates: [0x0fff, 0],
                mcs_rx_mask: [0xff, 0xff],
                mode: rate::WirelessMode::N24g,
                ht_enable: true,
                bw40: false,
                sgi20: false,
                sgi40: false,
            },
            super::Band::On2Ghz,
            super::RfType::TwoT2R,
            0x0f0f_f005,
        ),
        (
            rate::StaRates {
                supp_rates: [0x0fff, 0],
                mcs_rx_mask: [0x7f, 0],
                mode: rate::WirelessMode::N24g,
                ht_enable: true,
                bw40: false,
                sgi20: true,
                sgi40: false,
            },
            super::Band::On2Ghz,
            super::RfType::OneT1R,
            0x1007_f005,
        ),
        (
            rate::StaRates {
                supp_rates: [0, 0x00ff],
                mcs_rx_mask: [0, 0],
                mode: rate::WirelessMode::A,
                ht_enable: false,
                bw40: false,
                sgi20: false,
                sgi40: false,
            },
            super::Band::On5Ghz,
            super::RfType::TwoT2R,
            0x0ff0,
        ),
    ];
    for (sta, band, rf_type, expected) in cases {
        if rate::rate_table_value(&sta, band, rf_type) != expected {
            return TestResult::Fail("8192DE rate table value");
        }
    }
    let io = de_mac_fake();
    let sta = rate::StaRates {
        supp_rates: [0x0fff, 0],
        mcs_rx_mask: [0xff, 0xff],
        mode: rate::WirelessMode::N24g,
        ht_enable: true,
        bw40: false,
        sgi20: false,
        sgi40: false,
    };
    if rate::update_hal_rate_table(&io, &sta, super::Band::On2Ghz, super::RfType::TwoT2R).is_err()
        || de_mac_read32(&io, rate::REG_ARFR0) != 0x0f0f_f005
    {
        return TestResult::Fail("8192DE rate table write");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_rate_table
);

/// The H2C mailbox: RF-off drop, 1-byte and 5-byte box layouts,
/// box rotation, the never-drained timeout, and bad lengths.
fn smoke_rtl8192de_h2c_mailbox() -> TestResult {
    // RF off: dropped without a write.
    let io = de_mac_fake();
    let mut mailbox = h2c::Mailbox::new();
    if narf_scheduler::block_on(mailbox.fill(&io, 2, &[1], false)).is_err()
        || mailbox.last_hmeboxnum != 0
        || de_mac_read32(&io, h2c::REG_HMEBOX_0) != 0
    {
        return TestResult::Fail("8192DE H2C RF-off drop");
    }
    // 1-byte command in box 0.
    if narf_scheduler::block_on(mailbox.fill(&io, 2, &[h2c::MEDIA_CONNECT], true)).is_err()
        || mailbox.last_hmeboxnum != 1
        || de_mac_read8(&io, h2c::REG_HMEBOX_0) != 2
        || de_mac_read8(&io, h2c::REG_HMEBOX_0 + 1) != 1
        || de_mac_read8(&io, h2c::REG_HMEBOX_0 + 2) != 0
        || de_mac_read8(&io, h2c::REG_HMEBOX_0 + 3) != 0
    {
        return TestResult::Fail("8192DE H2C 1-byte box");
    }
    // 5-byte command in box 1: first two bytes in the extension box,
    // id with BIT(7) set in the box.
    let cmd = [0xaa, 0xbb, 0xcc, 0xdd, 0xee];
    if narf_scheduler::block_on(mailbox.fill(&io, 6, &cmd, true)).is_err()
        || mailbox.last_hmeboxnum != 2
        || de_mac_read8(&io, h2c::REG_HMEBOX_EXT_0 + 2) != 0xaa
        || de_mac_read8(&io, h2c::REG_HMEBOX_EXT_0 + 3) != 0xbb
        || de_mac_read8(&io, h2c::REG_HMEBOX_0 + 4) != 0x86
        || de_mac_read8(&io, h2c::REG_HMEBOX_0 + 5) != 0xcc
        || de_mac_read8(&io, h2c::REG_HMEBOX_0 + 6) != 0xdd
        || de_mac_read8(&io, h2c::REG_HMEBOX_0 + 7) != 0xee
    {
        return TestResult::Fail("8192DE H2C 5-byte box");
    }
    // Rotation: box 3 wraps back to box 0.
    mailbox.last_hmeboxnum = 3;
    if narf_scheduler::block_on(mailbox.fill(&io, 2, &[0], true)).is_err()
        || mailbox.last_hmeboxnum != 0
    {
        return TestResult::Fail("8192DE H2C box rotation");
    }
    // A box the firmware never drains times out.
    let io = de_mac_fake();
    let mut mailbox = h2c::Mailbox::new();
    io.0.lock().regs[usize::from(h2c::REG_HMETFR)] = 0x01;
    match narf_scheduler::block_on(mailbox.fill(&io, 2, &[1], true)) {
        Err(PrepError::CommandTimeout) => {}
        _ => return TestResult::Fail("8192DE H2C undrained box admitted"),
    }
    // Lengths outside 1..=5 are refused.
    let io = de_mac_fake();
    let mut mailbox = h2c::Mailbox::new();
    if narf_scheduler::block_on(mailbox.fill(&io, 2, &[], true)).is_ok()
        || narf_scheduler::block_on(mailbox.fill(&io, 2, &[0; 6], true)).is_ok()
    {
        return TestResult::Fail("8192DE H2C bad length admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_h2c_mailbox
);

/// Station chains: media status, check-BSSID (incl. the RF-off
/// no-op), BSSID, basic rate, AID, retry limit, TSF reset.
fn smoke_rtl8192de_station_chains() -> TestResult {
    let io = de_mac_fake();
    let mut bcn = station::BcnCtrl::default();
    let mut rcr = mac::RCR;
    if station::set_network_type(
        &io,
        &mut rcr,
        &mut bcn,
        station::MediaKind::Station,
        true,
        true,
    )
    .is_err()
        || de_mac_read8(&io, station::REG_MSR) != station::MSR_INFRA
        || de_mac_read8(&io, station::REG_BCNTCFG + 1) != 0x66
        || de_mac_read8(&io, mac::REG_BCN_CTRL) != 0x0d
        || de_mac_read32(&io, mac::REG_RCR) != mac::RCR | 0xc0
        || rcr != mac::RCR | 0xc0
        || de_mac_read8(&io, mac::REG_BCN_MAX_ERR) != 0xff
        || de_mac_read8(&io, mac::REG_TBTT_PROHIBIT + 1) != 0x64
    {
        return TestResult::Fail("8192DE station network type");
    }
    // Uncheck: BIT(4) back on, RCR CBSSID bits cleared.
    if station::set_check_bssid(&io, &mut rcr, &mut bcn, false, true).is_err()
        || de_mac_read8(&io, mac::REG_BCN_CTRL) != 0x1d
        || de_mac_read32(&io, mac::REG_RCR) != mac::RCR
        || rcr != mac::RCR
    {
        return TestResult::Fail("8192DE station uncheck BSSID");
    }
    // RF off: no register or cache change at all.
    let before = de_mac_read32(&io, mac::REG_RCR);
    if station::set_check_bssid(&io, &mut rcr, &mut bcn, true, false).is_err()
        || de_mac_read32(&io, mac::REG_RCR) != before
        || rcr != before
        || de_mac_read8(&io, mac::REG_BCN_CTRL) != 0x1d
    {
        return TestResult::Fail("8192DE station RF-off check BSSID");
    }
    if station::set_bssid(&io, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]).is_err()
        || de_mac_read8(&io, station::REG_BSSID) != 0x00
        || de_mac_read8(&io, station::REG_BSSID + 5) != 0x55
    {
        return TestResult::Fail("8192DE station BSSID");
    }
    // Basic rate: the Cisco rule and the highest-bit index; the
    // firmware-version gate on INIRTS_RATE_SEL.
    if station::basic_rate(0x15f, false) != (0x15f, 8)
        || station::basic_rate(0x002, true) != (0x003, 1)
        || station::basic_rate(0x150, true) != (0x150, 8)
    {
        return TestResult::Fail("8192DE station basic rate");
    }
    if station::set_basic_rate(&io, 0x15f, false, 0x0f).is_err()
        || de_mac_read8(&io, mac::REG_RRSR) != 0x5f
        || de_mac_read8(&io, mac::REG_RRSR + 1) != 0x01
        || de_mac_read8(&io, mac::REG_INIRTS_RATE_SEL) != 8
    {
        return TestResult::Fail("8192DE station set basic rate");
    }
    let io = de_mac_fake();
    if station::set_basic_rate(&io, 0x15f, false, 0x0e).is_err()
        || de_mac_read8(&io, mac::REG_INIRTS_RATE_SEL) != 0
    {
        return TestResult::Fail("8192DE station basic rate fw gate");
    }
    // AID keeps the top two bits of REG_BCN_PSR_RPT.
    let io = de_mac_fake();
    io.0.lock().regs[usize::from(station::REG_BCN_PSR_RPT)] = 0xff;
    io.0.lock().regs[usize::from(station::REG_BCN_PSR_RPT) + 1] = 0xff;
    if station::set_aid(&io, 0x1234).is_err()
        || de_mac_read16(&io, station::REG_BCN_PSR_RPT) != 0xd234
    {
        return TestResult::Fail("8192DE station AID");
    }
    if station::set_retry_limit(&io, 0x07).is_err()
        || de_mac_read16(&io, mac::REG_RL) != 0x0707
        || station::dual_tsf_rst(&io).is_err()
        || de_mac_read8(&io, station::REG_DUAL_TSF_RST) != 0x03
    {
        return TestResult::Fail("8192DE station retry limit / TSF reset");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_station_chains
);

/// QoS / HT rows: AMPDU min space and factor (incl. the factor > 3
/// no-op), short-GI density, ACM control (incl. the refused AC_BK),
/// channel access, ACK preamble, ERP changes and the full
/// `configure_rates` chain.
fn smoke_rtl8192de_qos_ht() -> TestResult {
    let io = de_mac_fake();
    if station::ampdu_min_space(&io, 0, 5).unwrap_or(0xff) != 5
        || de_mac_read8(&io, mac::REG_AMPDU_MIN_SPACE) != 5
        || station::ampdu_min_space(&io, 5, 8).unwrap_or(0xff) != 5
        || de_mac_read8(&io, mac::REG_AMPDU_MIN_SPACE) != 5
    {
        return TestResult::Fail("8192DE AMPDU min space");
    }
    if station::shortgi_density(&io, 0x02, 3).unwrap_or(0xff) != 0x1a
        || de_mac_read8(&io, mac::REG_AMPDU_MIN_SPACE) != 0x1a
    {
        return TestResult::Fail("8192DE short-GI density");
    }
    let io = de_mac_fake();
    // Factor 0 clamps every nibble above 4 (base 0xb972a841).
    match station::ampdu_factor(&io, super::MacPhyMode::SingleMacSinglePhy, 0) {
        Ok(Some(0x4442_4441)) => {}
        _ => return TestResult::Fail("8192DE AMPDU factor clamp"),
    }
    if de_mac_read32(&io, mac::REG_AGGLEN_LMT) != 0x4442_4441 {
        return TestResult::Fail("8192DE AMPDU factor write");
    }
    // Factor 2 allows nibbles up to 0xf: the base word is unchanged.
    match station::ampdu_factor(&io, super::MacPhyMode::SingleMacSinglePhy, 2) {
        Ok(Some(0xb972_a841)) => {}
        _ => return TestResult::Fail("8192DE AMPDU factor no-op"),
    }
    if station::ampdu_factor(&io, super::MacPhyMode::SingleMacSinglePhy, 4)
        .unwrap_or(Some(0))
        .is_some()
    {
        return TestResult::Fail("8192DE AMPDU factor > 3");
    }
    if station::acm_ctrl_value(0x00, true, true, station::AC_VO) != Ok(0x08)
        || station::acm_ctrl_value(0x0b, true, false, station::AC_BE) != Ok(0x09)
        || station::acm_ctrl_value(0x00, false, true, station::AC_VI) != Ok(0x05)
        || station::acm_ctrl_value(0x00, true, true, station::AC_BK).is_ok()
    {
        return TestResult::Fail("8192DE ACM control value");
    }
    if station::acm_ctrl(&io, 0x00, true, true, station::AC_VO).is_err()
        || de_mac_read8(&io, station::REG_ACMHWCTRL) != 0x08
        || !station::edca_turbo_init()
    {
        return TestResult::Fail("8192DE ACM control write / EDCA turbo");
    }
    let io = de_mac_fake();
    if station::channel_access(&io, 9, true).is_err()
        || de_mac_read8(&io, mac::REG_SLOT) != 9
        || de_mac_read16(&io, station::REG_RESP_SIFS_OFDM) != 0x1010
        || station::channel_access(&io, 20, false).is_err()
        || de_mac_read16(&io, station::REG_RESP_SIFS_OFDM) != 0x0e0e
    {
        return TestResult::Fail("8192DE channel access SIFS");
    }
    if station::ack_preamble(&io, 1, true).is_err() || de_mac_read8(&io, mac::REG_RRSR + 2) != 0xa0
    {
        return TestResult::Fail("8192DE ACK preamble");
    }
    let io = de_mac_fake();
    if station::erp_changed(&io, (false, false), (true, true), 0).is_err()
        || de_mac_read8(&io, mac::REG_RRSR + 2) != 0x80
        || de_mac_read8(&io, mac::REG_SLOT) != 9
        || station::erp_changed(&io, (true, true), (true, true), 0).is_err()
        || de_mac_read8(&io, mac::REG_RRSR + 2) != 0x80
    {
        return TestResult::Fail("8192DE ERP change");
    }
    // Full chain: rates 0x00ff / basic 0x000f, capability 0x0420
    // (short preamble + short slot), HT off, firmware 0x0f.
    let io = de_mac_fake();
    if station::configure_rates(
        &io,
        station::RateConfig {
            rates: 0x00ff,
            basic: 0x000f,
            capability: 0x0420,
            erp: None,
            ht: false,
            prime_sc: 0,
            fw_version: 0x0f,
            cisco: false,
        },
    )
    .is_err()
        || de_mac_read8(&io, mac::REG_RRSR) != 0x5f
        || de_mac_read8(&io, mac::REG_RRSR + 1) != 0x00
        || de_mac_read8(&io, mac::REG_INIRTS_RATE_SEL) != 6
        || de_mac_read8(&io, mac::REG_SLOT) != 9
        || de_mac_read16(&io, station::REG_RESP_SIFS_OFDM) != 0x0e0e
        || de_mac_read8(&io, mac::REG_RRSR + 2) != 0x80
    {
        return TestResult::Fail("8192DE configure_rates chain");
    }
    // 1 Mb/s must be in both sets.
    if station::configure_rates(
        &io,
        station::RateConfig {
            rates: 0x00fe,
            basic: 0x000f,
            capability: 0x0420,
            erp: None,
            ht: false,
            prime_sc: 0,
            fw_version: 0x0f,
            cisco: false,
        },
    )
    .is_ok()
    {
        return TestResult::Fail("8192DE configure_rates missing 1M admitted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtlwifi/rtl8192de", smoke_rtl8192de_qos_ht);

/// TSF, interrupt mask, beacon registers, suspend/resume and the
/// join-bss report (incl. the register dance and the RF-off drop).
fn smoke_rtl8192de_tsf_interrupt_beacon() -> TestResult {
    let io = de_mac_fake();
    {
        let mut g = io.0.lock();
        g.regs[usize::from(station::REG_TSFTR)..usize::from(station::REG_TSFTR) + 4]
            .copy_from_slice(&0x5566_7788u32.to_le_bytes());
        g.regs[usize::from(station::REG_TSFTR) + 4..usize::from(station::REG_TSFTR) + 8]
            .copy_from_slice(&0x1122_3344u32.to_le_bytes());
    }
    if station::read_tsf(&io).unwrap_or(0) != 0x1122_3344_5566_7788 {
        return TestResult::Fail("8192DE TSF read");
    }
    let mut bcn = station::BcnCtrl::default();
    if station::correct_tsf(&io, &mut bcn, 0x1122_3344_5566_7788, false).is_err()
        || de_mac_read8(&io, mac::REG_BCN_CTRL) != 0x1f
        || de_mac_read32(&io, station::REG_TSFTR) != 0x5566_7788
        || de_mac_read32(&io, station::REG_TSFTR + 4) != 0x1122_3344
    {
        return TestResult::Fail("8192DE TSF correct");
    }
    // IBSS: stop/resume TX beacon around the TSF write.
    io.0.lock().regs[usize::from(mac::REG_FWHW_TXQ_CTRL) + 2] = 0x40;
    if station::correct_tsf(&io, &mut bcn, 0x0000_0000_0000_0001, true).is_err()
        || de_mac_read8(&io, mac::REG_FWHW_TXQ_CTRL + 2) != 0x40
        || de_mac_read8(&io, mac::REG_BCN_MAX_ERR) != 0x0a
        || de_mac_read8(&io, mac::REG_TBTT_PROHIBIT + 1) != 0xff
    {
        return TestResult::Fail("8192DE IBSS TSF correct");
    }
    let io = de_mac_fake();
    if !station::int_migration(&io, true).unwrap_or(false)
        || de_mac_read32(&io, mac::REG_INT_MIG) != 0xfe00_0fa0
        || station::int_migration(&io, false).unwrap_or(true)
        || de_mac_read32(&io, mac::REG_INT_MIG) != 0
    {
        return TestResult::Fail("8192DE interrupt migration");
    }
    let mut mask = mac::IRQ_MASK;
    if station::update_interrupt_mask(&io, &mut mask, 0x8000, 0x100).is_err()
        || mask != (0x9a7f, 0x300)
        || de_mac_read32(&io, mac::REG_HIMR) != 0x9a7f
        || de_mac_read32(&io, mac::REG_HIMRE) != 0x300
    {
        return TestResult::Fail("8192DE interrupt mask update");
    }
    let mut mask = mac::IRQ_MASK;
    if station::int_ac(&io, &mut mask, true).is_err()
        || mask.0 != 0x1b61
        || de_mac_read32(&io, mac::REG_HIMR) != 0x1b61
        || station::int_ac(&io, &mut mask, false).is_err()
        || mask.0 != 0x1b7f
    {
        return TestResult::Fail("8192DE interrupt AC toggle");
    }
    if !station::fwlps_rf_on(false, 0)
        || station::fwlps_rf_on(true, 0x0007_0000)
        || !station::fwlps_rf_on(true, 0)
    {
        return TestResult::Fail("8192DE FWLPS RF-on read");
    }
    let io = de_mac_fake();
    if station::set_beacon_related_registers(&io, 100, true).is_err()
        || de_mac_read32(&io, mac::REG_HIMR) != 0
        || de_mac_read16(&io, mac::REG_ATIMWND) != 2
        || de_mac_read16(&io, station::REG_BCN_INTERVAL) != 100
        || de_mac_read16(&io, station::REG_BCNTCFG) != 0x660f
        || de_mac_read8(&io, station::REG_RXTSF_OFFSET_CCK) != 0x20
        || de_mac_read8(&io, station::REG_RXTSF_OFFSET_OFDM) != 0x30
        || de_mac_read8(&io, 0x0606) != 0x30
    {
        return TestResult::Fail("8192DE beacon related registers");
    }
    if station::set_beacon_interval(&io, mac::IRQ_MASK, 200).is_err()
        || de_mac_read16(&io, station::REG_BCN_INTERVAL) != 200
        || de_mac_read32(&io, mac::REG_HIMR) != mac::IRQ_MASK.0
        || de_mac_read32(&io, mac::REG_HIMRE) != mac::IRQ_MASK.1
    {
        return TestResult::Fail("8192DE beacon interval");
    }
    io.0.lock().regs[usize::from(station::REG_MAC_PHY_CTRL_NORMAL)] = 0xab;
    match station::suspend(&io) {
        Ok(0xab) => {}
        _ => return TestResult::Fail("8192DE suspend save"),
    }
    io.0.lock().regs[usize::from(station::REG_MAC_PHY_CTRL_NORMAL)] = 0x00;
    if station::resume(&io, 0xab).is_err()
        || de_mac_read8(&io, station::REG_MAC_PHY_CTRL_NORMAL) != 0xab
    {
        return TestResult::Fail("8192DE resume restore");
    }
    // Join-bss connect: the AID write, the CR/BCN dance with the TXQ
    // BIT(6) restore, the reserved-page upload (patched pages, beacon
    // descriptor 0 with OWN, the beacon doorbell, the H2C_RSVDPAGE
    // location in box 0), then the H2C report in box 1.
    let io = de_mac_fake();
    io.0.lock().regs[usize::from(power::REG_CR) + 1] = 0x55;
    io.0.lock().regs[usize::from(mac::REG_FWHW_TXQ_CTRL) + 2] = 0x40;
    let mut bcn = station::BcnCtrl::default();
    let mut mailbox = h2c::Mailbox::new();
    let mut desc = trx::TxDesc::default();
    desc.set_next(0x2000_0000);
    let mut packet = [0u8; rsvd_page::LEN];
    let own = [0x02, 0, 0, 0, 0, 1];
    let bssid = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let expected = match rsvd_page::pages(own, bssid, 0x0007) {
        Ok(pages) => pages,
        Err(_) => return TestResult::Fail("8192DE reserved pages for join"),
    };
    if narf_scheduler::block_on(station::join_bss_report(
        &io,
        &mut mailbox,
        &mut bcn,
        0x0007,
        h2c::MEDIA_CONNECT,
        true,
        rsvd_page::Upload {
            desc: &mut desc,
            packet: &mut packet,
            buffer_addr: 0x1000_0000,
            own,
            bssid,
            band_5g: false,
            fwctrl_lps: false,
        },
    ))
    .is_err()
        || de_mac_read16(&io, station::REG_BCN_PSR_RPT) != 0x0007
        || de_mac_read8(&io, power::REG_CR + 1) != 0x54
        || de_mac_read8(&io, mac::REG_BCN_CTRL) != 0x0f
        || de_mac_read8(&io, mac::REG_FWHW_TXQ_CTRL + 2) != 0x40
        || de_mac_read16(&io, mac::REG_PCIE_CTRL_REG) != 0x10
        || packet != expected
        || !desc.own()
        || desc.queue_sel() != trx::QSLT_BEACON
        || desc.pkt_size() != 768
        || desc.buffer_addr() != 0x1000_0000
        || desc.dw[10] != 0x2000_0000
        || de_mac_read8(&io, h2c::REG_HMEBOX_0) != h2c::H2C_RSVDPAGE
        || de_mac_read8(&io, h2c::REG_HMEBOX_0 + 1) != 4
        || de_mac_read8(&io, h2c::REG_HMEBOX_0 + 2) != 2
        || de_mac_read8(&io, h2c::REG_HMEBOX_0 + 3) != 3
        || de_mac_read8(&io, h2c::REG_HMEBOX_0 + 4) != h2c::H2C_JOINBSSRPT
        || de_mac_read8(&io, h2c::REG_HMEBOX_0 + 5) != 1
        || mailbox.last_hmeboxnum != 2
    {
        return TestResult::Fail("8192DE join-bss connect");
    }
    // Disconnect: no register dance and no upload, report byte 0.
    let io = de_mac_fake();
    let mut bcn = station::BcnCtrl::default();
    let mut mailbox = h2c::Mailbox::new();
    let mut desc = trx::TxDesc::default();
    let mut packet = [0u8; rsvd_page::LEN];
    if narf_scheduler::block_on(station::join_bss_report(
        &io,
        &mut mailbox,
        &mut bcn,
        0,
        h2c::MEDIA_DISCONNECT,
        true,
        rsvd_page::Upload {
            desc: &mut desc,
            packet: &mut packet,
            buffer_addr: 0x1000_0000,
            own: [0x02, 0, 0, 0, 0, 1],
            bssid: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            band_5g: false,
            fwctrl_lps: false,
        },
    ))
    .is_err()
        || de_mac_read16(&io, station::REG_BCN_PSR_RPT) != 0
        || de_mac_read8(&io, h2c::REG_HMEBOX_0 + 1) != 0
        || mailbox.last_hmeboxnum != 1
        || desc.own()
        || packet != [0u8; rsvd_page::LEN]
        || de_mac_read16(&io, mac::REG_PCIE_CTRL_REG) != 0
    {
        return TestResult::Fail("8192DE join-bss disconnect");
    }
    // RF off: the upload still runs (Linux uploads unconditionally on
    // connect) but both H2C sends are dropped.
    let io = de_mac_fake();
    let mut bcn = station::BcnCtrl::default();
    let mut mailbox = h2c::Mailbox::new();
    let mut desc = trx::TxDesc::default();
    let mut packet = [0u8; rsvd_page::LEN];
    let own = [0x02, 0, 0, 0, 0, 1];
    let bssid = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let expected = match rsvd_page::pages(own, bssid, 0x0007) {
        Ok(pages) => pages,
        Err(_) => return TestResult::Fail("8192DE reserved pages for RF-off join"),
    };
    if narf_scheduler::block_on(station::join_bss_report(
        &io,
        &mut mailbox,
        &mut bcn,
        0x0007,
        h2c::MEDIA_CONNECT,
        false,
        rsvd_page::Upload {
            desc: &mut desc,
            packet: &mut packet,
            buffer_addr: 0x1000_0000,
            own,
            bssid,
            band_5g: false,
            fwctrl_lps: false,
        },
    ))
    .is_err()
        || mailbox.last_hmeboxnum != 0
        || de_mac_read8(&io, h2c::REG_HMEBOX_0) != 0
        || packet != expected
        || !desc.own()
        || de_mac_read16(&io, mac::REG_PCIE_CTRL_REG) != 0x10
    {
        return TestResult::Fail("8192DE join-bss RF-off drop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_tsf_interrupt_beacon
);

/// `rsvd_page`: the template is verbatim (SHA-256, page heads), `pages`
/// substitutes only the Linux fields, the location is `[4, 2, 3]`, the
/// command descriptor is `fill_cmd` + OWN with the ring link kept, the
/// doorbell is `REG_PCIE_CTRL_REG` word `BIT(4)`, and a bad AID refuses
/// the upload before any register write.
fn smoke_rtl8192de_rsvd_page_template_and_upload() -> TestResult {
    use super::rsvd_page as rp;
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(&rp::TEMPLATE);
    let digest = hash.finalize();
    let mut hex = [0u8; 64];
    for (i, b) in digest.iter().enumerate() {
        hex[2 * i] = b"0123456789abcdef"[usize::from(b >> 4)];
        hex[2 * i + 1] = b"0123456789abcdef"[usize::from(b & 15)];
    }
    if hex[..] != *rp::TEMPLATE_SHA256.as_bytes() {
        return TestResult::Fail("template digest");
    }
    let heads = [0, 2 * 128, 3 * 128, 4 * 128].map(|at| rp::TEMPLATE[at]);
    if heads != [0x80, 0xa4, 0x48, 0x50] {
        return TestResult::Fail("page frame-control layout");
    }
    let own = [2, 0, 0, 0, 0, 1];
    let bssid = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let pages = match rp::pages(own, bssid, 5) {
        Ok(pages) => pages,
        Err(_) => return TestResult::Fail("valid AID refused"),
    };
    if pages[10..16] != own
        || pages[16..22] != bssid
        || pages[258..260] != [0x05, 0xc0]
        || pages[260..266] != bssid
        || pages[266..272] != own
    {
        return TestResult::Fail("beacon / PS-Poll substitution");
    }
    for page in [3, 4] {
        let at = page * 128;
        if pages[at + 4..at + 10] != bssid
            || pages[at + 10..at + 16] != own
            || pages[at + 16..at + 22] != bssid
        {
            return TestResult::Fail("Null / probe-response A1-A3");
        }
    }
    // Only the Linux fields change; the page-1 tail and the whole of
    // page 5 are untouched template bytes.
    let mut changed = 0;
    for (a, b) in pages.iter().zip(rp::TEMPLATE.iter()) {
        changed += usize::from(a != b);
    }
    if changed > 12 + 14 + 18 + 18
        || pages[224..256] != rp::TEMPLATE[224..256]
        || pages[640..768] != rp::TEMPLATE[640..768]
        || rp::pages(own, bssid, 0).is_ok()
        || rp::pages(own, bssid, 2008).is_ok()
    {
        return TestResult::Fail("only Linux fields change / AID bound");
    }
    if rp::RSVDPAGE_LOCATION != [4, 2, 3] || h2c::H2C_RSVDPAGE != 3 {
        return TestResult::Fail("location command");
    }
    // Command descriptor: beacon queue, 1M, rate id 7, MAC id 0,
    // 768-byte buffer, OWN published, ring link kept.
    let mut desc = trx::TxDesc::default();
    desc.set_next(0x2000_0000);
    rp::fill_cmd_desc(&mut desc, 0x1000_0000, false, false);
    if !desc.own()
        || desc.queue_sel() != trx::QSLT_BEACON
        || desc.tx_rate() != trx::DESC_RATE1M
        || desc.macid() != trx::CMD_MACID
        || desc.pkt_size() != 768
        || desc.buffer_addr() != 0x1000_0000
        || desc.dw[10] != 0x2000_0000
    {
        return TestResult::Fail("command descriptor");
    }
    // 5 GHz: 6M; firmware LPS: hwseq enable + packet id 8.
    let mut desc5 = trx::TxDesc::default();
    rp::fill_cmd_desc(&mut desc5, 0x1000_0000, true, true);
    if desc5.tx_rate() != trx::DESC_RATE6M
        || desc5.dw[4] & (1 << 7) == 0
        || (desc5.dw[3] >> 28) & 0xf != 8
    {
        return TestResult::Fail("5 GHz / LPS command descriptor");
    }
    // Doorbell + bad-AID refusal before any register write.
    let io = de_mac_fake();
    if rp::tx_polling(&io).is_err() || de_mac_read16(&io, mac::REG_PCIE_CTRL_REG) != 0x10 {
        return TestResult::Fail("beacon doorbell");
    }
    let io = de_mac_fake();
    let mut mailbox = h2c::Mailbox::new();
    let mut desc = trx::TxDesc::default();
    let mut packet = [0u8; rp::LEN];
    if narf_scheduler::block_on(rp::set_fw_rsvdpagepkt(
        &io,
        &mut mailbox,
        rp::Upload {
            desc: &mut desc,
            packet: &mut packet,
            buffer_addr: 0x1000_0000,
            own,
            bssid,
            band_5g: false,
            fwctrl_lps: false,
        },
        0,
        true,
    )) != Err(crate::rtlwifi::prepare::Error::Packet)
        || desc.own()
        || packet != [0u8; rp::LEN]
        || de_mac_read16(&io, mac::REG_PCIE_CTRL_REG) != 0
        || mailbox.last_hmeboxnum != 0
    {
        return TestResult::Fail("bad AID admitted a partial upload");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_rsvd_page_template_and_upload
);

/// Lifecycle: `SwVars` defaults per mode/band, ASPM state, the
/// `fwctrl_psmode` mapping and `deinit`.
fn smoke_rtl8192de_lifecycle() -> TestResult {
    let params = lifecycle::ModParams::default();
    if params.sw_crypto
        || !params.inactiveps
        || !params.swctrl_lps
        || params.fwctrl_lps
        || params.aspm_support != 1
    {
        return TestResult::Fail("8192DE module params");
    }
    let vars = lifecycle::SwVars::new(
        super::Band::On5Ghz,
        super::MacPhyMode::DualMacDualPhy,
        params,
    );
    if vars.current_channel != 36
        || !vars.disable_amsdu_8k
        || vars.rxbuffersize != Some(4096)
        || vars.transmit_config != mac::TCR
        || vars.receive_config != mac::RCR
        || vars.irq_mask != mac::IRQ_MASK
        || vars.reg_fwctrl_lps != 3
        || vars.reg_max_lps_awakeintvl != 5
        || vars.fwctrl_psmode != Some(lifecycle::FwPsMode::Dtim)
        || vars.earlymode_enable
        || vars.max_fw_size != 0x8000
        || !vars.firmware_allocated
        || vars.aspm.const_pci_aspm != 3
        || vars.aspm.const_devicepci_aspm_setting != 0x03
        || vars.aspm.const_hostpci_aspm_setting != 0x02
        || vars.aspm.const_hwsw_rfoff_d3 != 0
        || vars.aspm.const_support_pciaspm != 1
    {
        return TestResult::Fail("8192DE SwVars dual 5G");
    }
    let vars = lifecycle::SwVars::new(
        super::Band::On2Ghz,
        super::MacPhyMode::SingleMacSinglePhy,
        params,
    );
    if vars.current_channel != 1 || vars.disable_amsdu_8k || vars.rxbuffersize.is_some() {
        return TestResult::Fail("8192DE SwVars single 2.4G");
    }
    let mut vars = vars;
    vars.waitq_depths[3] = 5;
    vars.deinit();
    if vars.firmware_allocated || vars.waitq_depths != [0; 8] {
        return TestResult::Fail("8192DE SwVars deinit");
    }
    if lifecycle::fw_ps_mode(1) != Some(lifecycle::FwPsMode::Min)
        || lifecycle::fw_ps_mode(2) != Some(lifecycle::FwPsMode::Max)
        || lifecycle::fw_ps_mode(3) != Some(lifecycle::FwPsMode::Dtim)
        || lifecycle::fw_ps_mode(0).is_some()
        || lifecycle::fw_ps_mode(4).is_some()
    {
        return TestResult::Fail("8192DE fw PS mode mapping");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_lifecycle
);

/// BB/RF access: `set_bb`/`get_bb` masking, the 3-wire serial read
/// and write, `set_rf` merging and its zero-mask no-op, the DBI
/// cross-function path, the other-PHY enable/powerdown, and the AGC
/// table walk.
fn smoke_rtl8192de_phy_access() -> TestResult {
    let io = de_mac_fake();
    if phy::set_bb(&io, 0x800, 0x1, 1).is_err() || de_mac_read32(&io, 0x800) != 1 {
        return TestResult::Fail("8192DE set_bb bit");
    }
    if phy::set_bb(&io, 0x800, 0xff00, 0xab).is_err() || de_mac_read32(&io, 0x800) != 0xab01 {
        return TestResult::Fail("8192DE set_bb byte");
    }
    if phy::get_bb(&io, 0x800, 0xff00).unwrap_or(0) != 0xab {
        return TestResult::Fail("8192DE get_bb byte");
    }
    if phy::rf_write(&io, phy::Path::A, 0x18, 0x12345).is_err()
        || de_mac_read32(&io, 0x840) != 0x181_2345
    {
        return TestResult::Fail("8192DE RF 3-wire write");
    }
    io.0.lock().regs[0x8a0..0x8a4].copy_from_slice(&0x54321u32.to_le_bytes());
    match narf_scheduler::block_on(phy::rf_read(&io, phy::Path::A, 0x18)) {
        Ok(0x54321) => {}
        _ => return TestResult::Fail("8192DE RF 3-wire read"),
    }
    if de_mac_read32(&io, 0x824) != 0x8000_0000 {
        return TestResult::Fail("8192DE RF 3-wire read edge");
    }
    io.0.lock().regs[0x8a0..0x8a4].copy_from_slice(&0x400u32.to_le_bytes());
    if narf_scheduler::block_on(phy::set_rf(&io, phy::Path::A, 0x18, 0xc00, 1)).is_err()
        || de_mac_read32(&io, 0x840) != 0x180_0400
    {
        return TestResult::Fail("8192DE set_rf merge");
    }
    io.0.lock().regs[0x840..0x844].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    if narf_scheduler::block_on(phy::set_rf(&io, phy::Path::A, 0x18, 0, 1)).is_err()
        || de_mac_read32(&io, 0x840) != 0x1234_5678
    {
        return TestResult::Fail("8192DE set_rf zero mask wrote");
    }
    if super::RfType::OneT1R.paths() != 1
        || super::RfType::TwoT2R.paths() != 2
        || super::RfType::TwoT2R.rf_paths().len() != 2
    {
        return TestResult::Fail("8192DE RF path count");
    }
    // DBI: read returns the RDATA dword; write lands WDATA + CTRL/FLAG.
    let io = de_mac_fake();
    io.0.lock().regs[0x34c..0x350].copy_from_slice(&0x1122_3344u32.to_le_bytes());
    match narf_scheduler::block_on(phy::read_dword_dbi(&io, 0x888, 0x08)) {
        Ok(0x1122_3344) => {}
        _ => return TestResult::Fail("8192DE DBI read"),
    }
    if de_mac_read16(&io, phy::REG_DBI_CTRL) != 0x888
        || de_mac_read8(&io, phy::REG_DBI_FLAG) != 0x0a
    {
        return TestResult::Fail("8192DE DBI read control");
    }
    if phy::write_dword_dbi(&io, 0x888, 0xaabb_ccdd, 0x08).is_err()
        || de_mac_read16(&io, phy::REG_DBI_CTRL) != 0xf888
        || de_mac_read32(&io, phy::REG_DBI_WDATA) != 0xaabb_ccdd
        || de_mac_read8(&io, phy::REG_DBI_FLAG) != 0x09
    {
        return TestResult::Fail("8192DE DBI write");
    }
    // Other-PHY enable: MAC off → ISO bits set over DBI; MAC on → no-op.
    let io = de_mac_fake();
    match narf_scheduler::block_on(phy::enable_anotherphy(&io, false)) {
        Ok(true) => {}
        _ => return TestResult::Fail("8192DE enable another PHY"),
    }
    if de_mac_read32(&io, phy::REG_DBI_WDATA) != 0x2003_0000
        || de_mac_read16(&io, phy::REG_DBI_CTRL) != 0xf000
    {
        return TestResult::Fail("8192DE enable another PHY DBI");
    }
    io.0.lock().regs[usize::from(super::power::REG_MAC0)] = super::power::MAC0_ON;
    io.0.lock().regs[0x348..0x34c].copy_from_slice(&0u32.to_le_bytes());
    match narf_scheduler::block_on(phy::enable_anotherphy(&io, false)) {
        Ok(false) => {}
        _ => return TestResult::Fail("8192DE enable another PHY on MAC"),
    }
    if de_mac_read32(&io, phy::REG_DBI_WDATA) != 0 {
        return TestResult::Fail("8192DE enable another PHY wrote on MAC");
    }
    // Powerdown: MAC off → DBI write of zero at the LSSI parameter;
    // MAC on → no-op.
    let io = de_mac_fake();
    if narf_scheduler::block_on(phy::powerdown_anotherphy(&io, false)).is_err()
        || de_mac_read16(&io, phy::REG_DBI_CTRL) != 0xf840
        || de_mac_read32(&io, phy::REG_DBI_WDATA) != 0
    {
        return TestResult::Fail("8192DE powerdown another PHY");
    }
    io.0.lock().regs[usize::from(super::power::REG_MAC0)] = super::power::MAC0_ON;
    io.0.lock().regs[0x350..0x352].copy_from_slice(&0u16.to_le_bytes());
    if narf_scheduler::block_on(phy::powerdown_anotherphy(&io, false)).is_err()
        || de_mac_read16(&io, phy::REG_DBI_CTRL) != 0
    {
        return TestResult::Fail("8192DE powerdown another PHY wrote on MAC");
    }
    // AGC table walk: pairs land, an odd tail is ignored.
    let io = de_mac_fake();
    if narf_scheduler::block_on(phy::agc_table_walk(&io, &[0x800, 1, 0x804, 2])).is_err()
        || de_mac_read32(&io, 0x800) != 1
        || de_mac_read32(&io, 0x804) != 2
    {
        return TestResult::Fail("8192DE AGC table walk");
    }
    let io = de_mac_fake();
    if narf_scheduler::block_on(phy::agc_table_walk(&io, &[0x800, 1, 0x804])).is_err()
        || de_mac_read32(&io, 0x800) != 1
        || de_mac_read32(&io, 0x804) != 0
    {
        return TestResult::Fail("8192DE AGC table walk tail");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_phy_access
);

/// Bandwidth mode: the 20 MHz rows (BWOPMODE, RFMOD, ANALOGPARAMETER2,
/// the RF bandwidth write) and the 40 MHz rows (prime-sc sideband,
/// LSTF, the 0x818 selector).
fn smoke_rtl8192de_bw_mode() -> TestResult {
    let io = de_mac_fake();
    let mut chnlval = [0x1234_5606u32; 2];
    if narf_scheduler::block_on(channel::set_bw_mode(
        &io,
        super::Band::On2Ghz,
        false,
        channel::PRIME_CHNL_OFFSET_DONT_CARE,
        super::RfType::TwoT2R,
        &mut chnlval,
    ))
    .is_err()
        || de_mac_read8(&io, mac::REG_BWOPMODE) != mac::BWOPMODE_20MHZ
        || de_mac_read32(&io, 0x800) != 0
        || de_mac_read32(&io, 0x900) != 0
        || de_mac_read32(&io, phy::RFPGA0_ANALOGPARAMETER2) != 0xc00
        || chnlval != [0x1234_5606, 0x1234_5606]
        || de_mac_read32(&io, 0x840) != 0x180_0400
        || de_mac_read32(&io, 0x844) != 0x180_0400
    {
        return TestResult::Fail("8192DE 20 MHz bandwidth mode");
    }
    let io = de_mac_fake();
    let mut chnlval = [0x1234_5606u32; 2];
    if narf_scheduler::block_on(channel::set_bw_mode(
        &io,
        super::Band::On2Ghz,
        true,
        channel::PRIME_CHNL_OFFSET_LOWER,
        super::RfType::TwoT2R,
        &mut chnlval,
    ))
    .is_err()
        || de_mac_read8(&io, mac::REG_BWOPMODE) != 0
        || de_mac_read8(&io, mac::REG_RRSR + 2) != 0x20
        || de_mac_read32(&io, 0x800) != 1
        || de_mac_read32(&io, 0x900) != 1
        || de_mac_read32(&io, phy::RCCK0_SYSTEM) != 0
        || de_mac_read32(&io, phy::ROFDM1_LSTF) != 0x400
        || de_mac_read32(&io, phy::RFPGA0_ANALOGPARAMETER2) != 0
        || de_mac_read32(&io, 0x818) != 0x0800_0000
        || chnlval != [0x1234_5206, 0x1234_5206]
        || de_mac_read32(&io, 0x840) != 0x180_0000
    {
        return TestResult::Fail("8192DE 40 MHz bandwidth mode");
    }
    // The RF channel-value word: 2.4 GHz clears the band bits, 5 GHz
    // sets them (plus BIT(18) above channel 99).
    if channel::rfreg_chnlval(6, false, 0x1234_5600) != 0x1234_5606
        || channel::rfreg_chnlval(36, true, 0x1234_5600) != 0x1235_5724
        || channel::rfreg_chnlval(149, true, 0x1234_5600) != 0x1239_5795
    {
        return TestResult::Fail("8192DE RF channel value");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_bw_mode
);

/// End-to-end `configure`: 2.4 GHz channel 6 HT20 (TX power + RF
/// channel write + 20 MHz mode), the 5 GHz band switch from a
/// 2.4 GHz start, and the band guards that refuse a switch.
fn smoke_rtl8192de_configure_end_to_end() -> TestResult {
    let efuse = match txpower::Efuse::from_hwinfo(&level_hwinfo(), false, false) {
        Ok(efuse) => efuse,
        Err(_) => return TestResult::Fail("8192DE configure EFUSE decode"),
    };
    let pg = zero_pg();
    let io = de_mac_fake();
    let mut band = super::Band::On2Ghz;
    let mut bandset = super::BandSet::OnBoth;
    let mut chnlval = [0x1234_5600u32; 2];
    let mut iqk = calib::IqkMatrix::new();
    let op = match channel::Operating::new(6, channel::ChannelType::Ht20) {
        Ok(op) => op,
        Err(_) => return TestResult::Fail("8192DE configure operating"),
    };
    let outcome = match narf_scheduler::block_on(channel::configure(
        &io,
        &efuse,
        &pg,
        super::RfType::TwoT2R,
        super::MacPhyMode::SingleMacSinglePhy,
        0,
        &mut band,
        &mut bandset,
        true,
        &op,
        &mut chnlval,
        &mut iqk,
        false,
    )) {
        Ok(outcome) => outcome,
        Err(_) => return TestResult::Fail("8192DE configure 2.4G"),
    };
    if !outcome.switched
        || band != super::Band::On2Ghz
        || bandset != super::BandSet::OnBoth
        || chnlval != [0x1234_5606, 0x1234_5606]
        || de_mac_read8(&io, mac::REG_BWOPMODE) != mac::BWOPMODE_20MHZ
        || de_mac_read32(&io, phy::RFPGA0_ANALOGPARAMETER2) != 0xc00
        || de_mac_read32(&io, 0xe00) != 0x3030_3030
        || de_mac_read32(&io, 0x86c) != 0x2020_2021
    {
        return TestResult::Fail("8192DE configure 2.4G registers");
    }
    // 5 GHz from a 2.4 GHz start: the band switch runs, the MAC band
    // bit clears, the BB/RF rows land, then TX power + 20 MHz mode.
    let io = de_mac_fake();
    io.0.lock().regs[usize::from(super::power::REG_MAC0)] = super::power::MAC0_ON;
    let mut band = super::Band::On2Ghz;
    let mut bandset = super::BandSet::OnBoth;
    let mut chnlval = [0x1234_5600u32; 2];
    let mut iqk = calib::IqkMatrix::new();
    let op = match channel::Operating::new(36, channel::ChannelType::Ht20) {
        Ok(op) => op,
        Err(_) => return TestResult::Fail("8192DE configure operating 5G"),
    };
    let outcome = match narf_scheduler::block_on(channel::configure(
        &io,
        &efuse,
        &pg,
        super::RfType::TwoT2R,
        super::MacPhyMode::SingleMacSinglePhy,
        0,
        &mut band,
        &mut bandset,
        true,
        &op,
        &mut chnlval,
        &mut iqk,
        false,
    )) {
        Ok(outcome) => outcome,
        Err(_) => return TestResult::Fail("8192DE configure 5G"),
    };
    if !outcome.switched
        || band != super::Band::On5Ghz
        || bandset != super::BandSet::OnBoth
        || outcome.rf3c != Some([0, 0])
        || chnlval != [0x0001_0524, 0x0001_0524]
        || de_mac_read8(&io, super::power::REG_MAC0) != super::power::MAC0_ON
        || de_mac_read32(&io, phy::RFPGA0_XAB_RFPARAMETER) != 0x0001_8001
        || de_mac_read32(&io, phy::ROFDM0_TRXPATHENABLE) != 0x33
        || de_mac_read32(&io, phy::ROFDM1_TRXPATHENABLE) != 0x03
        || de_mac_read32(&io, phy::ROFDM0_XARXIQIMBALANCE) != 0x4000_0100
        || de_mac_read32(&io, phy::ROFDM0_XATXIQIMBALANCE) != 0x2000_0080
        || de_mac_read8(&io, mac::REG_BWOPMODE) != mac::BWOPMODE_20MHZ
        || de_mac_read32(&io, 0xe00) != 0x2828_2828
    {
        return TestResult::Fail("8192DE configure 5G registers");
    }
    // Band guards refuse: 5 GHz band with a 2.4 GHz channel, and
    // 2.4 GHz band with a 5 GHz channel (bandset pinned, no trigger).
    let io = de_mac_fake();
    let mut band = super::Band::On5Ghz;
    let mut bandset = super::BandSet::On5Ghz;
    let mut chnlval = [0x1234_5600u32; 2];
    let mut iqk = calib::IqkMatrix::new();
    let outcome = match narf_scheduler::block_on(channel::switch_channel(
        &io,
        &efuse,
        &pg,
        super::RfType::TwoT2R,
        super::MacPhyMode::SingleMacSinglePhy,
        0,
        &mut band,
        &mut bandset,
        true,
        6,
        false,
        &mut chnlval,
        &mut iqk,
        false,
    )) {
        Ok(outcome) => outcome,
        Err(_) => return TestResult::Fail("8192DE band guard 5G"),
    };
    if outcome.switched || chnlval != [0x1234_5600, 0x1234_5600] {
        return TestResult::Fail("8192DE band guard 5G admitted");
    }
    let mut band = super::Band::On2Ghz;
    let mut bandset = super::BandSet::On2Ghz;
    let mut chnlval = [0x1234_5600u32; 2];
    let outcome = match narf_scheduler::block_on(channel::switch_channel(
        &io,
        &efuse,
        &pg,
        super::RfType::TwoT2R,
        super::MacPhyMode::SingleMacSinglePhy,
        0,
        &mut band,
        &mut bandset,
        true,
        36,
        false,
        &mut chnlval,
        &mut iqk,
        false,
    )) {
        Ok(outcome) => outcome,
        Err(_) => return TestResult::Fail("8192DE band guard 2.4G"),
    };
    if outcome.switched || chnlval != [0x1234_5600, 0x1234_5600] {
        return TestResult::Fail("8192DE band guard 2.4G admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_configure_end_to_end
);

/// `rtl92d_dm_init`: DM type by driver, DIG init at `0x20` with the
/// 92D receive-gain override (`0x32` / `0x20`), dynamic TX power
/// enabled at NORMAL, EDCA turbo clear, rate-adaptive mask at INIT
/// with `useramask`, TX-power tracking armed.
fn smoke_rtl8192de_dm_init() -> TestResult {
    let dm = dm::Dm::new();
    check(
        dm.dm_type == dm::DM_TYPE_BYDRIVER
            && dm.dm_initialgain_enable
            && dm.dig.dig_enable_flag
            && dm.dig.dig_ext_port_stage == dm::DIG_EXT_PORT_STAGE_MAX
            && dm.dig.cur_igvalue == 0x20
            && dm.dig.pre_igvalue == 0
            && dm.dig.cur_sta_cstate == dm::DIG_STA_DISCONNECT
            && dm.dig.curmultista_cstate == dm::DIG_MULTISTA_DISCONNECT
            && dm.dig.rssi_lowthresh == dm::DM_DIG_THRESH_LOW
            && dm.dig.rssi_highthresh == dm::DM_DIG_THRESH_HIGH
            && dm.dig.fa_lowthresh == dm::DM_FALSEALARM_THRESH_LOW
            && dm.dig.fa_highthresh == dm::DM_FALSEALARM_THRESH_HIGH
            && dm.dig.rx_gain_max == dm::DM_DIG_FA_UPPER
            && dm.dig.rx_gain_min == dm::DM_DIG_FA_LOWER
            && dm.dig.back_val == dm::DM_DIG_BACKOFF_DEFAULT
            && dm.dig.back_range_max == dm::DM_DIG_BACKOFF_MAX
            && dm.dig.back_range_min == dm::DM_DIG_BACKOFF_MIN
            && dm.dig.pre_cck_cca_thres == 0xff
            && dm.dig.cur_cck_cca_thres == 0x83
            && dm.dig.forbidden_igi == dm::DM_DIG_MIN
            && dm.dig.dig_min_0 == 0x25
            && dm.dig.dig_min_1 == 0x25
            && dm.dig.bt30_cur_igi == 0x32
            && dm.dig.pre_cck_pd_state == dm::CCK_PD_STAGE_MAX
            && dm.dig.cur_cck_pd_state == dm::CCK_PD_STAGE_LOWRSSI
            && dm.dynamic_txpower.enable
            && dm.dynamic_txpower.last_dtp_lvl == dm::TXHIGHPWRLEVEL_NORMAL
            && dm.dynamic_txpower.highpower_lvl == dm::TXHIGHPWRLEVEL_NORMAL
            && !dm.edca_turbo.current_turbo_edca
            && !dm.edca_turbo.is_any_nonbepkts
            && !dm.edca_turbo.is_cur_rdlstate
            && dm.rate_adaptive.ratr_state == dm::DM_RATR_STA_INIT
            && dm.rate_adaptive.pre_ratr_state == dm::DM_RATR_STA_INIT
            && dm.rate_adaptive.useramask
            && dm.txpower_tracking.tracking
            && !dm.txpower_tracking.trackinginit
            && dm.txpower_tracking.track_control,
        "8192DE DM init state",
    )
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_dm_init
);

/// The `rtl92de_hw_init` early-mode block: `0x605` always gains
/// `0x30` (other bits preserved); enabled adds `0x1f` to `0x4d0`,
/// `0x80` to `0x4d3`, and `0x40` to `0x605`.
fn smoke_rtl8192de_early_mode() -> TestResult {
    let io = de_mac_fake();
    io.0.lock().regs[0x605] = 0x05;
    if mac::early_mode(&io, false).is_err() {
        return TestResult::Fail("8192DE early-mode off failed");
    }
    if de_mac_read8(&io, 0x605) != 0x35
        || de_mac_read8(&io, mac::REG_EARLYMODE_CTRL) != 0
        || de_mac_read8(&io, mac::REG_EARLYMODE_CTRL + 3) != 0
    {
        return TestResult::Fail("8192DE early-mode off registers");
    }
    let io = de_mac_fake();
    if mac::early_mode(&io, true).is_err() {
        return TestResult::Fail("8192DE early-mode on failed");
    }
    check(
        de_mac_read8(&io, 0x605) == 0x70
            && de_mac_read8(&io, mac::REG_EARLYMODE_CTRL) == 0x1f
            && de_mac_read8(&io, mac::REG_EARLYMODE_CTRL + 3) == 0x80,
        "8192DE early-mode on registers",
    )
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_early_mode
);

/// The ASPM back-door write: `0x34b` / `0x350` / `0x352` land in
/// both branches; `0x349` is `0x1b` with the back door supported
/// (`const_support_pciaspm` 1) and `0x03` otherwise.
fn smoke_rtl8192de_aspm_back_door() -> TestResult {
    let io = de_mac_fake();
    if mac::enable_aspm_back_door(&io, true).is_err() {
        return TestResult::Fail("8192DE ASPM back-door on failed");
    }
    if de_mac_read8(&io, 0x34b) != 0x93
        || de_mac_read16(&io, 0x350) != 0x2718
        || de_mac_read8(&io, 0x352) != 0x01
        || de_mac_read8(&io, 0x349) != 0x1b
    {
        return TestResult::Fail("8192DE ASPM back-door on registers");
    }
    let io = de_mac_fake();
    if mac::enable_aspm_back_door(&io, false).is_err() {
        return TestResult::Fail("8192DE ASPM back-door off failed");
    }
    check(
        de_mac_read8(&io, 0x34b) == 0x93
            && de_mac_read16(&io, 0x350) == 0x2718
            && de_mac_read8(&io, 0x352) == 0x01
            && de_mac_read8(&io, 0x349) == 0x03
            && lifecycle::AspmVars::new(1).support_backdoor()
            && !lifecycle::AspmVars::new(0).support_backdoor()
            && !lifecycle::AspmVars::new(2).support_backdoor(),
        "8192DE ASPM back-door off registers",
    )
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_aspm_back_door
);

/// `rtl92de_enable_hw_security_config`: software crypto writes
/// nothing (`REG_CR + 1` and `REG_SECCFG` stay 0); hardware security
/// writes `REG_CR + 1 = 0x02` and the `SECCFG` value (`0xCF` with a
/// default key, `0xCC` without).
fn smoke_rtl8192de_hw_security() -> TestResult {
    let io = de_mac_fake();
    let sw = mac::HwSecurity {
        sw_crypto: true,
        use_sw_sec: false,
        use_defaultkey: true,
    };
    if mac::enable_hw_security_config(&io, sw).is_err() {
        return TestResult::Fail("8192DE HW security sw failed");
    }
    if de_mac_read8(&io, super::power::REG_CR + 1) != 0 || de_mac_read8(&io, mac::REG_SECCFG) != 0 {
        return TestResult::Fail("8192DE HW security sw wrote");
    }
    let io = de_mac_fake();
    let sw_sec = mac::HwSecurity {
        sw_crypto: false,
        use_sw_sec: true,
        use_defaultkey: false,
    };
    if mac::enable_hw_security_config(&io, sw_sec).is_err()
        || de_mac_read8(&io, super::power::REG_CR + 1) != 0
        || de_mac_read8(&io, mac::REG_SECCFG) != 0
    {
        return TestResult::Fail("8192DE HW security use_sw_sec wrote");
    }
    let io = de_mac_fake();
    let hw_default = mac::HwSecurity {
        sw_crypto: false,
        use_sw_sec: false,
        use_defaultkey: true,
    };
    if mac::enable_hw_security_config(&io, hw_default).is_err() {
        return TestResult::Fail("8192DE HW security hw failed");
    }
    if de_mac_read8(&io, super::power::REG_CR + 1) != 0x02
        || de_mac_read8(&io, mac::REG_SECCFG) != 0xcf
    {
        return TestResult::Fail("8192DE HW security default-key registers");
    }
    let io = de_mac_fake();
    let hw = mac::HwSecurity {
        sw_crypto: false,
        use_sw_sec: false,
        use_defaultkey: false,
    };
    if mac::enable_hw_security_config(&io, hw).is_err() {
        return TestResult::Fail("8192DE HW security hw no-key failed");
    }
    check(
        de_mac_read8(&io, super::power::REG_CR + 1) == 0x02
            && de_mac_read8(&io, mac::REG_SECCFG) == 0xcc,
        "8192DE HW security no-key registers",
    )
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_hw_security
);

/// IQK matrix reset: all 46 places hold the `0x100` / `0` pattern,
/// none done; `reset()` restores a mutated place.
fn smoke_rtl8192de_iqk_reset() -> TestResult {
    let mut matrix = calib::IqkMatrix::new();
    if matrix.settings.len() != calib::IQK_MATRIX_SETTINGS_NUM
        || matrix.need_iqk
        || matrix.load_imrandiqk_setting_for2g
        || matrix.settings[0] != calib::IqkSetting::reset()
        || matrix.settings[45] != calib::IqkSetting::reset()
    {
        return TestResult::Fail("8192DE IQK reset state");
    }
    matrix.settings[0].value[0] = 0x42;
    matrix.settings[0].iqk_done = true;
    matrix.reset();
    check(
        matrix.settings[0] == calib::IqkSetting::reset(),
        "8192DE IQK reset restores",
    )
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_iqk_reset
);

/// IQK reload on 5 GHz channel 36 (place 1), single-PHY, interface 0:
/// with all result words `0x100` and the TX-imbalance words at
/// `0x4000_0000`, the TX words land (`0xc80` / `0xc88`), the
/// 5 GHz `+3` on the path-B Y word shows up in `0xc88` bits 16-21,
/// the RX words land (`0xc14` / `0xc1c`, `0xca0` / `0xc78`), and
/// `need_iqk` clears.
fn smoke_rtl8192de_iqk_reload_5g() -> TestResult {
    let io = de_mac_fake();
    io.0.lock().regs[0xc80..0xc84].copy_from_slice(&0x4000_0000u32.to_le_bytes());
    io.0.lock().regs[0xc88..0xc8c].copy_from_slice(&0x4000_0000u32.to_le_bytes());
    let mut matrix = calib::IqkMatrix::new();
    matrix.need_iqk = true;
    matrix.settings[1].value = [0x100; 8];
    let ctx = calib::IqkContext {
        single_phy: true,
        mode: super::MacPhyMode::SingleMacSinglePhy,
        interface_index: 0,
        band: super::Band::On5Ghz,
    };
    if calib::reload_iqk_setting(&io, 36, &mut matrix, &ctx).is_err() {
        return TestResult::Fail("8192DE IQK reload 5G failed");
    }
    check(
        de_mac_read32(&io, phy::ROFDM0_XATXIQIMBALANCE) == 0x4000_0100
            && de_mac_read32(&io, phy::ROFDM0_XBTXIQIMBALANCE) == 0x4003_0100
            && de_mac_read32(&io, phy::ROFDM0_XCTXAFE) == 0x4000_0000
            && de_mac_read32(&io, phy::ROFDM0_XDTXAFE) == 0x4000_0000
            && de_mac_read32(&io, phy::ROFDM0_ECCATHRESHOLD) == 0
            && de_mac_read32(&io, phy::ROFDM0_XARXIQIMBALANCE) == 0x100
            && de_mac_read32(&io, phy::ROFDM0_XBRXIQIMBALANCE) == 0x100
            && de_mac_read32(&io, 0xca0) == 0x4000_0000
            && de_mac_read32(&io, phy::ROFDM0_AGCRSSITABLE) == 0x4000
            && !matrix.need_iqk,
        "8192DE IQK reload 5G registers",
    )
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_iqk_reload_5g
);

/// IQK reload guards: a 2.4 GHz place does not load once the IMR
/// reload has run; an all-zero place loads nothing; `txonly`
/// (`value[2] == 0`) skips the RX part while the TX part lands; and
/// a dual-MAC (non-single-PHY) switch never fills path B.
fn smoke_rtl8192de_iqk_reload_guards() -> TestResult {
    // 2.4 GHz, IMR already loaded: no writes, `need_iqk` still clears.
    let io = de_mac_fake();
    io.0.lock().regs[0xc80..0xc84].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    let mut matrix = calib::IqkMatrix::new();
    matrix.need_iqk = true;
    matrix.load_imrandiqk_setting_for2g = true;
    let ctx = calib::IqkContext {
        single_phy: true,
        mode: super::MacPhyMode::SingleMacSinglePhy,
        interface_index: 0,
        band: super::Band::On2Ghz,
    };
    if calib::reload_iqk_setting(&io, 6, &mut matrix, &ctx).is_err() {
        return TestResult::Fail("8192DE IQK reload 2G skip failed");
    }
    if de_mac_read32(&io, phy::ROFDM0_XATXIQIMBALANCE) != 0x1234_5678 || matrix.need_iqk {
        return TestResult::Fail("8192DE IQK reload 2G skip wrote");
    }
    // All-zero place: no writes on either path.
    let io = de_mac_fake();
    io.0.lock().regs[0xc80..0xc84].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    io.0.lock().regs[0xc88..0xc8c].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    let mut matrix = calib::IqkMatrix::new();
    matrix.settings[0].value = [0; 8];
    if calib::reload_iqk_setting(&io, 6, &mut matrix, &ctx).is_err() {
        return TestResult::Fail("8192DE IQK reload zero failed");
    }
    if de_mac_read32(&io, phy::ROFDM0_XATXIQIMBALANCE) != 0x1234_5678
        || de_mac_read32(&io, phy::ROFDM0_XBTXIQIMBALANCE) != 0x1234_5678
    {
        return TestResult::Fail("8192DE IQK reload zero wrote");
    }
    // TX-only: the TX word lands, the RX words stay clear, path B
    // (value[4] == 0) never runs.
    let io = de_mac_fake();
    io.0.lock().regs[0xc80..0xc84].copy_from_slice(&0x4000_0000u32.to_le_bytes());
    io.0.lock().regs[0xc88..0xc8c].copy_from_slice(&0x4000_0000u32.to_le_bytes());
    let mut matrix = calib::IqkMatrix::new();
    matrix.settings[0].value = [0x100, 0x100, 0, 0x100, 0, 0, 0, 0];
    if calib::reload_iqk_setting(&io, 6, &mut matrix, &ctx).is_err() {
        return TestResult::Fail("8192DE IQK reload txonly failed");
    }
    if de_mac_read32(&io, phy::ROFDM0_XATXIQIMBALANCE) != 0x4000_0100
        || de_mac_read32(&io, phy::ROFDM0_XARXIQIMBALANCE) != 0
        || de_mac_read32(&io, 0xca0) != 0
        || de_mac_read32(&io, phy::ROFDM0_XBTXIQIMBALANCE) != 0x4000_0000
    {
        return TestResult::Fail("8192DE IQK reload txonly registers");
    }
    // Dual-MAC (not single-PHY): path B never fills even with a
    // stored path-B matrix.
    let io = de_mac_fake();
    io.0.lock().regs[0xc80..0xc84].copy_from_slice(&0x4000_0000u32.to_le_bytes());
    io.0.lock().regs[0xc88..0xc8c].copy_from_slice(&0x4000_0000u32.to_le_bytes());
    let mut matrix = calib::IqkMatrix::new();
    matrix.settings[1].value = [0x100; 8];
    let dual = calib::IqkContext {
        single_phy: false,
        mode: super::MacPhyMode::DualMacDualPhy,
        interface_index: 0,
        band: super::Band::On5Ghz,
    };
    if calib::reload_iqk_setting(&io, 36, &mut matrix, &dual).is_err() {
        return TestResult::Fail("8192DE IQK reload dual failed");
    }
    check(
        de_mac_read32(&io, phy::ROFDM0_XATXIQIMBALANCE) == 0x4000_0100
            && de_mac_read32(&io, phy::ROFDM0_XBTXIQIMBALANCE) == 0x4000_0000,
        "8192DE IQK reload dual registers",
    )
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_iqk_reload_guards
);

/// IQK place selection: channel 36 loads place 1 (a stored place-0
/// matrix alone does nothing), and channel 165 loads place 45.
fn smoke_rtl8192de_iqk_reload_places() -> TestResult {
    let io = de_mac_fake();
    io.0.lock().regs[0xc80..0xc84].copy_from_slice(&0x4000_0000u32.to_le_bytes());
    let mut matrix = calib::IqkMatrix::new();
    matrix.settings[0].value = [0x100; 8];
    // Place 1 holds nothing (the reset pattern would still fill, so
    // it is zeroed outright): the reload must not fall back to
    // place 0.
    matrix.settings[1].value = [0; 8];
    let ctx = calib::IqkContext {
        single_phy: true,
        mode: super::MacPhyMode::SingleMacSinglePhy,
        interface_index: 0,
        band: super::Band::On5Ghz,
    };
    if calib::reload_iqk_setting(&io, 36, &mut matrix, &ctx).is_err() {
        return TestResult::Fail("8192DE IQK reload place 1 failed");
    }
    if de_mac_read32(&io, phy::ROFDM0_XATXIQIMBALANCE) != 0x4000_0000 {
        return TestResult::Fail("8192DE IQK reload place 1 used place 0");
    }
    let io = de_mac_fake();
    io.0.lock().regs[0xc80..0xc84].copy_from_slice(&0x4000_0000u32.to_le_bytes());
    let mut matrix = calib::IqkMatrix::new();
    matrix.settings[45].value = [0x100; 8];
    if calib::reload_iqk_setting(&io, 165, &mut matrix, &ctx).is_err() {
        return TestResult::Fail("8192DE IQK reload place 45 failed");
    }
    check(
        de_mac_read32(&io, phy::ROFDM0_XATXIQIMBALANCE) == 0x4000_0100,
        "8192DE IQK reload place 45 registers",
    )
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_iqk_reload_places
);

/// 5 GHz native admission: a dual-dual MAC0 function admits the
/// 5 GHz plan and no 2.4 GHz channel; MAC1 admits 2.4 GHz 1–11 and
/// no 5 GHz channel; single functions admit both bands; channels
/// outside the station plan (12, 34) admit nowhere.
fn smoke_rtl8192de_native_channel() -> TestResult {
    use super::MacPhyMode::*;
    check(
        super::native_channel(36, DualMacDualPhy, 0)
            && super::native_channel(165, DualMacDualPhy, 0)
            && !super::native_channel(6, DualMacDualPhy, 0)
            && super::native_channel(6, DualMacDualPhy, 1)
            && !super::native_channel(36, DualMacDualPhy, 1)
            && super::native_channel(36, SingleMacSinglePhy, 0)
            && super::native_channel(6, SingleMacSinglePhy, 0)
            && super::native_channel(36, DualMacSinglePhy, 1)
            && super::native_channel(6, DualMacSinglePhy, 1)
            && !super::native_channel(12, DualMacDualPhy, 0)
            && !super::native_channel(12, SingleMacSinglePhy, 0)
            && !super::native_channel(34, DualMacDualPhy, 0),
        "8192DE native channel admission",
    )
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_native_channel
);

// ── remainder (#1865): rate mask, TX report, rate-id/MAC-id, LPS, ───────
// ── card disable/power-off, version qualification, hw_init ───────────────

/// `rtl92de_update_hal_rate_mask` payload vectors (Linux
/// `rtl8192de/hw.c:1873-2006`): B/G/A/N masks, 1T/2T, 40/20 MHz, RSSI
/// levels, SMPS-static, MAC id `aid + 1`, short-GI MAC-id rule, and
/// the wide default mask.
fn smoke_rtl8192de_rate_mask() -> TestResult {
    use h2c::*;
    use rate::WirelessMode;
    let base = Peer {
        mode: WirelessMode::B,
        supp_rates: [0xfff, 0],
        rx_mask: [0, 0],
        sgi20: false,
        sgi40: false,
        mimo_ps_static: false,
        ap_or_adhoc: false,
        aid: 0,
    };
    // B: 0xfff & 0x0d (CCK bit 2 set), index B (6), station MAC id 0.
    let mask = rate_mask(&RateSelection {
        peer: &base,
        rf_type: RfType::TwoT2R,
        band: Band::On2Ghz,
        bw40: false,
        rssi_level: 3,
    });
    if mask.payload != [0x0d, 0x00, 0x00, 0x60, 0x80]
        || mask.ratr_index != RATR_INX_WIRELESS_B
        || mask.mac_id != 0
    {
        return TestResult::Fail("8192DE rate mask B");
    }
    // G, RSSI 1: 0x0f00, index GB (4).
    let g = Peer {
        mode: WirelessMode::G,
        ..base
    };
    let mask = rate_mask(&RateSelection {
        peer: &g,
        rf_type: RfType::TwoT2R,
        band: Band::On2Ghz,
        bw40: false,
        rssi_level: 1,
    });
    if mask.payload != [0x00, 0x0f, 0x00, 0x40, 0x80] || mask.ratr_index != RATR_INX_WIRELESS_GB {
        return TestResult::Fail("8192DE rate mask G rssi1");
    }
    // A on 5 GHz: 5G supp rates shifted, 0x0ff0, index G (5).
    let a = Peer {
        mode: WirelessMode::A,
        supp_rates: [0, 0xfff],
        ..base
    };
    let mask = rate_mask(&RateSelection {
        peer: &a,
        rf_type: RfType::TwoT2R,
        band: Band::On5Ghz,
        bw40: false,
        rssi_level: 3,
    });
    if mask.payload != [0xf0, 0x0f, 0x00, 0x50, 0x80] || mask.ratr_index != RATR_INX_WIRELESS_G {
        return TestResult::Fail("8192DE rate mask A");
    }
    // N 2.4 GHz, 2T2R, 40 MHz, RSSI 3, short GI: 0x0f0f_f015,
    // index NGB (0), MAC id 0 with the short-GI bit.
    let n = Peer {
        mode: WirelessMode::N24g,
        supp_rates: [0xfff, 0],
        rx_mask: [0xff, 0xff],
        sgi40: true,
        ..base
    };
    let mask = rate_mask(&RateSelection {
        peer: &n,
        rf_type: RfType::TwoT2R,
        band: Band::On2Ghz,
        bw40: true,
        rssi_level: 3,
    });
    if mask.payload != [0x15, 0xf0, 0x0f, 0x0f, 0xa0]
        || mask.ratr_index != RATR_INX_WIRELESS_NGB
        || mask.mac_id != 0
    {
        return TestResult::Fail("8192DE rate mask N 2T 40M");
    }
    // N with SMPS static, RSSI 2: 0x0007_f000.
    let smps = Peer {
        mimo_ps_static: true,
        ..n
    };
    let mask = rate_mask(&RateSelection {
        peer: &smps,
        rf_type: RfType::TwoT2R,
        band: Band::On2Ghz,
        bw40: true,
        rssi_level: 2,
    });
    if mask.payload != [0x00, 0xf0, 0x07, 0x00, 0x80] || mask.ratr_index != RATR_INX_WIRELESS_NGB {
        return TestResult::Fail("8192DE rate mask N SMPS static");
    }
    // N 5 GHz, 1T1R, 20 MHz, RSSI 1: 0x000f_0000, index NG (1).
    let n5 = Peer {
        mode: WirelessMode::N5g,
        supp_rates: [0, 0xfff],
        rx_mask: [0xff, 0xff],
        ..base
    };
    let mask = rate_mask(&RateSelection {
        peer: &n5,
        rf_type: RfType::OneT1R,
        band: Band::On5Ghz,
        bw40: false,
        rssi_level: 1,
    });
    if mask.payload != [0x00, 0x00, 0x0f, 0x10, 0x80] || mask.ratr_index != RATR_INX_WIRELESS_NG {
        return TestResult::Fail("8192DE rate mask N5 1T 20M");
    }
    // AP peer, aid 2: MAC id 3, short GI forced off.
    let ap = Peer {
        ap_or_adhoc: true,
        aid: 2,
        ..n
    };
    let mask = rate_mask(&RateSelection {
        peer: &ap,
        rf_type: RfType::TwoT2R,
        band: Band::On2Ghz,
        bw40: true,
        rssi_level: 3,
    });
    if mask.payload[4] != 0x83 || mask.mac_id != 3 {
        return TestResult::Fail("8192DE rate mask AP macid");
    }
    // Unknown mode: the wide default mask, index NGB (0).
    let unknown = Peer {
        mode: WirelessMode::Unknown,
        ..n
    };
    let mask = rate_mask(&RateSelection {
        peer: &unknown,
        rf_type: RfType::TwoT2R,
        band: Band::On2Ghz,
        bw40: true,
        rssi_level: 3,
    });
    if mask.payload != [0xff, 0xf0, 0x0f, 0x0f, 0xa0] || mask.ratr_index != RATR_INX_WIRELESS_NGB {
        return TestResult::Fail("8192DE rate mask unknown");
    }
    TestResult::Pass
}

/// LC tables + `calc_curvindex`: table lengths and spot values (the
/// generator/checker pair verifies every entry against Linux v6.1),
/// the 5 GHz legality list, the nearest-count rule on a synthetic
/// case (first minimum wins), the skip-keeps-prior-value rule on 5 GHz,
/// and the reload-path selection.
fn smoke_rtl8192de_lck_tables() -> TestResult {
    if lck::TARGETCHNL_5G.len() != 221
        || lck::TARGETCHNL_2G.len() != 14
        || lck::CHANNEL_5G.len() != 49
        || lck::TARGETCHNL_5G[0] != 25141
        || lck::TARGETCHNL_5G[220] != 25166
        || lck::TARGETCHNL_2G[0] != 26084
        || lck::TARGETCHNL_2G[13] != 25328
        || lck::CHANNEL_5G[0] != 36
        || lck::CHANNEL_5G[48] != 177
    {
        return TestResult::Fail("8192DE LCK tables");
    }
    if !lck::is_legal_5g_channel(36)
        || !lck::is_legal_5g_channel(165)
        || !lck::is_legal_5g_channel(177)
        || !lck::is_legal_5g_channel(142)
        || lck::is_legal_5g_channel(1)
        || lck::is_legal_5g_channel(14)
        || lck::is_legal_5g_channel(35)
    {
        return TestResult::Fail("8192DE LCK 5G legality");
    }
    // Synthetic nearest-count: target 100 is equidistant (10) from
    // counts 90 (j=0) and 110 (j=1) — first minimum wins; target 200
    // is equidistant (10) from 190 (j=2) and 210 (j=3) — j=2 wins.
    let mut counts = [0xffffu32; lck::CV_CURVE_CNT * 2];
    counts[0] = 90;
    counts[1] = 110;
    counts[2] = 190;
    counts[3] = 210;
    let mut index = [0u32; 2];
    lck::calc_curvindex(&[100, 200], &counts, false, &mut index);
    if index != [0, 2] {
        return TestResult::Fail("8192DE LCK curveindex nearest");
    }
    // 5 GHz skip: channels 1-2 are illegal, so the slots keep their
    // prior values.
    let mut index = [99u32; 2];
    lck::calc_curvindex(&[25141, 25116], &counts, true, &mut index);
    if index != [99, 99] {
        return TestResult::Fail("8192DE LCK curveindex 5G skip");
    }
    if lck::reload_path(super::Band::On5Ghz, super::RfType::OneT1R) != phy::Path::A
        || lck::reload_path(super::Band::On2Ghz, super::RfType::TwoT2R) != phy::Path::B
        || lck::reload_path(super::Band::On2Ghz, super::RfType::OneT1R) != phy::Path::A
    {
        return TestResult::Fail("8192DE LCK reload path");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_rate_mask
);

/// The H2C rate-mask send: the admitted gate refuses an empty mask
/// and any unadmitted rate, and a fully admitted mask lands in the
/// mailbox as `H2C_RA_MASK` with the 5-byte payload; RF off drops
/// the send without a write.
fn smoke_rtl8192de_rate_mask_send() -> TestResult {
    use h2c::*;
    use rate::WirelessMode;
    let peer = Peer {
        mode: WirelessMode::N24g,
        supp_rates: [0xfff, 0],
        rx_mask: [0xff, 0xff],
        sgi20: false,
        sgi40: true,
        mimo_ps_static: false,
        ap_or_adhoc: false,
        aid: 0,
    };
    // Empty mask: no supported rates at all.
    let io = de_mac_fake();
    let mut mailbox = Mailbox::new();
    let empty = Peer {
        supp_rates: [0, 0],
        rx_mask: [0, 0],
        ..peer
    };
    match narf_scheduler::block_on(update_hal_rate_mask(
        &mut mailbox,
        &io,
        &RateSelection {
            peer: &empty,
            rf_type: RfType::TwoT2R,
            band: Band::On2Ghz,
            bw40: true,
            rssi_level: 3,
        },
        0x0fff_ffff,
        true,
    )) {
        Err(PrepError::Power(_)) => {}
        _ => return TestResult::Fail("8192DE rate mask empty admitted"),
    }
    // Unadmitted rate: the 2T 40 MHz mask names rates outside 0xfff.
    let io = de_mac_fake();
    let mut mailbox = Mailbox::new();
    match narf_scheduler::block_on(update_hal_rate_mask(
        &mut mailbox,
        &io,
        &RateSelection {
            peer: &peer,
            rf_type: RfType::TwoT2R,
            band: Band::On2Ghz,
            bw40: true,
            rssi_level: 3,
        },
        0x0000_0fff,
        true,
    )) {
        Err(PrepError::Power(_)) => {}
        _ => return TestResult::Fail("8192DE rate mask unadmitted admitted"),
    }
    // Fully admitted: the 5-byte payload lands in box 0
    // (`H2C_RA_MASK` with BIT(7) set, then the payload bytes).
    let io = de_mac_fake();
    let mut mailbox = Mailbox::new();
    let mask = match narf_scheduler::block_on(update_hal_rate_mask(
        &mut mailbox,
        &io,
        &RateSelection {
            peer: &peer,
            rf_type: RfType::TwoT2R,
            band: Band::On2Ghz,
            bw40: true,
            rssi_level: 3,
        },
        0x0fff_ffff,
        true,
    )) {
        Ok(mask) => mask,
        Err(_) => return TestResult::Fail("8192DE rate mask send failed"),
    };
    if mask.payload != [0x15, 0xf0, 0x0f, 0x0f, 0xa0]
        || mailbox.last_hmeboxnum != 1
        || de_mac_read8(&io, REG_HMEBOX_EXT_0 + 2) != 0x15
        || de_mac_read8(&io, REG_HMEBOX_EXT_0 + 3) != 0xf0
        || de_mac_read8(&io, REG_HMEBOX_0 + 4) != 0x86
        || de_mac_read8(&io, REG_HMEBOX_0 + 5) != 0x0f
        || de_mac_read8(&io, REG_HMEBOX_0 + 6) != 0x0f
        || de_mac_read8(&io, REG_HMEBOX_0 + 7) != 0xa0
    {
        return TestResult::Fail("8192DE rate mask mailbox bytes");
    }
    // RF off: dropped without a write.
    let io = de_mac_fake();
    let mut mailbox = Mailbox::new();
    if narf_scheduler::block_on(update_hal_rate_mask(
        &mut mailbox,
        &io,
        &RateSelection {
            peer: &peer,
            rf_type: RfType::TwoT2R,
            band: Band::On2Ghz,
            bw40: true,
            rssi_level: 3,
        },
        0x0fff_ffff,
        false,
    ))
    .is_err()
        || mailbox.last_hmeboxnum != 0
        || de_mac_read32(&io, REG_HMEBOX_0) != 0
    {
        return TestResult::Fail("8192DE rate mask RF-off drop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_rate_mask_send
);

/// A packet owner on channel 6 for the TX-report / rate-id tests
/// (same envelope fixture as the packet admission test).
fn de_tx_owner() -> Option<packet::Owner> {
    use envelope::*;
    let factory = de_factory();
    let domain = de_us_domain();
    let bytes = de_napc_fixture(1, 0, 80, &[(6, 20, 0, de_rising)]);
    let cal = Calibration::from_verified(&bytes, Some([0xabu8; 32]), &factory).ok()?;
    let permission = cal.permission_for(&domain, Operating::twenty(6)).ok()?;
    Some(packet::Owner::admit(
        crate::rtlwifi::firmware_transport::Info {
            version: 0x1234,
            subversion: 0x56,
            payload: 100,
        },
        permission,
    ))
}

/// TX-report frames (EAPOL / nullfunc): `SPE_RPT` (dword 2 bit 19)
/// plus the `SW_DEFINE` sequence `(++sn & 0x3f) << 2`; ordinary data
/// carries neither. `sectype`: none 0, WEP/TKIP 1, CCMP 3.
fn smoke_rtl8192de_tx_report_and_sectype() -> TestResult {
    use packet::*;
    let Some(mut owner) = de_tx_owner() else {
        return TestResult::Fail("8192DE TX report owner");
    };
    let frame = TxFrame {
        op: envelope::Operating::twenty(6),
        class: FrameClass::Data { priority: 3 },
        len: 100,
        buf_addr: 0x3000_0000,
        rate: 12,
        seq: 0x42,
        short: false,
        rts: None,
        next_desc: 0x4000_0000,
        mode: rate::WirelessMode::N24g,
        cipher: KeyCipher::None,
        ampdu_density: None,
        adaptive: false,
        eapol: false,
        nullfunc: false,
        rdg_en: false,
    };
    // Ordinary data: no report bits.
    let mut slot = trx::TxDesc::default();
    if owner.fill_tx_slot(&mut slot, &frame).is_err()
        || slot.dw[2] & (1 << 19) != 0
        || slot.dw[6] & 0xfff != 0
    {
        return TestResult::Fail("8192DE TX report ordinary data");
    }
    // EAPOL: report with sn 4, then 8.
    let mut slot = trx::TxDesc::default();
    if owner
        .fill_tx_slot(
            &mut slot,
            &TxFrame {
                eapol: true,
                ..frame
            },
        )
        .is_err()
        || slot.dw[2] & (1 << 19) == 0
        || slot.dw[6] & 0xfff != 4
    {
        return TestResult::Fail("8192DE TX report EAPOL first");
    }
    let mut slot = trx::TxDesc::default();
    if owner
        .fill_tx_slot(
            &mut slot,
            &TxFrame {
                eapol: true,
                ..frame
            },
        )
        .is_err()
        || slot.dw[6] & 0xfff != 8
    {
        return TestResult::Fail("8192DE TX report EAPOL second");
    }
    // Nullfunc: report with sn 12.
    let mut slot = trx::TxDesc::default();
    if owner
        .fill_tx_slot(
            &mut slot,
            &TxFrame {
                nullfunc: true,
                ..frame
            },
        )
        .is_err()
        || slot.dw[2] & (1 << 19) == 0
        || slot.dw[6] & 0xfff != 12
    {
        return TestResult::Fail("8192DE TX report nullfunc");
    }
    // Sectype mapping on the same frame shape.
    for (cipher, sectype) in [
        (KeyCipher::None, 0u32),
        (KeyCipher::Wep, 1),
        (KeyCipher::Tkip, 1),
        (KeyCipher::Ccmp, 3),
    ] {
        let mut slot = trx::TxDesc::default();
        if owner
            .fill_tx_slot(&mut slot, &TxFrame { cipher, ..frame })
            .is_err()
            || (slot.dw[1] >> 22) & 3 != sectype
        {
            return TestResult::Fail("8192DE TX sectype");
        }
    }
    // The report helpers agree with the descriptor bits.
    if !wants_tx_report(true, false)
        || !wants_tx_report(false, true)
        || wants_tx_report(false, false)
        || ETH_P_PAE != 0x888e
    {
        return TestResult::Fail("8192DE TX report predicate");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_tx_report_and_sectype
);

/// Rate-id / MAC-id: a data frame under an installed AP link takes
/// the link's index and MAC id with the driver rate; an adaptive
/// frame takes the firmware rate; management takes MC (7) with MAC
/// id 0. AMPDU density, RDG and the LPS hwseq rule ride the same
/// descriptor fields; the mode fallback covers stations.
fn smoke_rtl8192de_rate_id_macid() -> TestResult {
    use h2c::*;
    use packet::*;
    use rate::WirelessMode;
    if rate_index_for_mode(WirelessMode::N24g) != RATR_INX_WIRELESS_NGB
        || rate_index_for_mode(WirelessMode::N5g) != RATR_INX_WIRELESS_NG
        || rate_index_for_mode(WirelessMode::G) != RATR_INX_WIRELESS_GB
        || rate_index_for_mode(WirelessMode::B) != RATR_INX_WIRELESS_B
        || rate_index_for_mode(WirelessMode::A) != RATR_INX_WIRELESS_G
        || rate_index_for_mode(WirelessMode::Unknown) != RATR_INX_WIRELESS_NGB
    {
        return TestResult::Fail("8192DE rate index mode fallback");
    }
    let Some(mut owner) = de_tx_owner() else {
        return TestResult::Fail("8192DE rate-id owner");
    };
    // AP link: N 2.4 GHz peer, aid 2 → MAC id 3, index NGB (0).
    let peer = Peer {
        mode: WirelessMode::N24g,
        supp_rates: [0xfff, 0],
        rx_mask: [0xff, 0xff],
        sgi20: false,
        sgi40: false,
        mimo_ps_static: false,
        ap_or_adhoc: true,
        aid: 2,
    };
    let mask = rate_mask(&RateSelection {
        peer: &peer,
        rf_type: RfType::TwoT2R,
        band: Band::On2Ghz,
        bw40: false,
        rssi_level: 3,
    });
    owner.install_rate_mask(mask, WirelessMode::N24g, 5, false);
    let Some(link) = owner.link() else {
        return TestResult::Fail("8192DE rate-id link missing");
    };
    if link.ratr_index != RATR_INX_WIRELESS_NGB || link.mac_id != 3 || link.ampdu_density != 5 {
        return TestResult::Fail("8192DE rate-id link values");
    }
    let frame = TxFrame {
        op: envelope::Operating::twenty(6),
        class: FrameClass::Data { priority: 3 },
        len: 100,
        buf_addr: 0x3000_0000,
        rate: 12,
        seq: 0x42,
        short: false,
        rts: None,
        next_desc: 0x4000_0000,
        mode: WirelessMode::N24g,
        cipher: KeyCipher::None,
        ampdu_density: Some(5),
        adaptive: false,
        eapol: false,
        nullfunc: false,
        rdg_en: false,
    };
    // Data, non-adaptive: link index/MAC id, driver rate (dw4 bit 8),
    // AMPDU bit + density 5.
    let mut slot = trx::TxDesc::default();
    if owner.fill_tx_slot(&mut slot, &frame).is_err()
        || (slot.dw[1] >> 16) & 0xf != 0
        || slot.macid() != 3
        || slot.dw[4] & (1 << 8) == 0
        || slot.dw[1] & (1 << 5) == 0
        || (slot.dw[2] >> 20) & 7 != 5
    {
        return TestResult::Fail("8192DE rate-id data link");
    }
    // Data, adaptive: firmware rate (dw4 bit 8 clear), same ids.
    let mut slot = trx::TxDesc::default();
    if owner
        .fill_tx_slot(
            &mut slot,
            &TxFrame {
                adaptive: true,
                ..frame
            },
        )
        .is_err()
        || (slot.dw[1] >> 16) & 0xf != 0
        || slot.macid() != 3
        || slot.dw[4] & (1 << 8) != 0
    {
        return TestResult::Fail("8192DE rate-id adaptive data");
    }
    // Management: MC (7), MAC id 0, driver rate.
    let mut slot = trx::TxDesc::default();
    if owner
        .fill_tx_slot(
            &mut slot,
            &TxFrame {
                class: FrameClass::Mgmt,
                ..frame
            },
        )
        .is_err()
        || (slot.dw[1] >> 16) & 0xf != u32::from(RATR_INX_WIRELESS_MC)
        || slot.macid() != 0
        || slot.dw[4] & (1 << 8) == 0
    {
        return TestResult::Fail("8192DE rate-id management");
    }
    // RDG on QoS data: dw1 bit 7 + dw0 bit 25.
    let mut slot = trx::TxDesc::default();
    if owner
        .fill_tx_slot(
            &mut slot,
            &TxFrame {
                rdg_en: true,
                ..frame
            },
        )
        .is_err()
        || slot.dw[1] & (1 << 7) == 0
        || slot.dw[0] & (1 << 25) == 0
    {
        return TestResult::Fail("8192DE rate-id RDG");
    }
    // LPS hwseq on a non-QoS frame under an fwctrl_lps link: dw4
    // bit 7 + pkt id 8.
    owner.install_rate_mask(mask, WirelessMode::N24g, 5, true);
    let mut slot = trx::TxDesc::default();
    if owner
        .fill_tx_slot(
            &mut slot,
            &TxFrame {
                class: FrameClass::Mgmt,
                ..frame
            },
        )
        .is_err()
        || slot.dw[4] & (1 << 7) == 0
        || (slot.dw[3] >> 28) & 0xf != u32::from(trx::LPS_PKT_ID)
    {
        return TestResult::Fail("8192DE rate-id LPS hwseq");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_rate_id_macid
);

/// LPS RPWM: enter (`0x02`, RF off) and leave (`0x0c`, RF on) fill
/// `H2C_PWRM` with the one-byte payload; the `pwrmode` record is
/// `[mode, 1, 5]`; RF off drops the send.
fn smoke_rtl8192de_lps_rpwm() -> TestResult {
    use h2c::*;
    if pwrmode(FW_PS_ACTIVE_MODE) != [0, 1, MAX_LPS_AWAKE_INTERVAL]
        || pwrmode(FW_PS_DTIM_MODE) != [3, 1, MAX_LPS_AWAKE_INTERVAL]
    {
        return TestResult::Fail("8192DE LPS pwrmode payload");
    }
    let io = de_mac_fake();
    let mut mailbox = Mailbox::new();
    if narf_scheduler::block_on(enter_leisure(&mut mailbox, &io, true)).is_err()
        || mailbox.last_hmeboxnum != 1
        || de_mac_read8(&io, REG_HMEBOX_0) != H2C_PWRM
        || de_mac_read8(&io, REG_HMEBOX_0 + 1) != 0x02
    {
        return TestResult::Fail("8192DE LPS enter RPWM");
    }
    let io = de_mac_fake();
    let mut mailbox = Mailbox::new();
    if narf_scheduler::block_on(leave_leisure(&mut mailbox, &io, true)).is_err()
        || mailbox.last_hmeboxnum != 1
        || de_mac_read8(&io, REG_HMEBOX_0) != H2C_PWRM
        || de_mac_read8(&io, REG_HMEBOX_0 + 1) != 0x0c
    {
        return TestResult::Fail("8192DE LPS leave RPWM");
    }
    let io = de_mac_fake();
    let mut mailbox = Mailbox::new();
    if narf_scheduler::block_on(enter_leisure(&mut mailbox, &io, false)).is_err()
        || mailbox.last_hmeboxnum != 0
    {
        return TestResult::Fail("8192DE LPS RF-off drop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_lps_rpwm
);

/// Card disable / power-off: single-MAC powers off (DMA stop, RF
/// off, `SYS_FUNC_EN` `0xE2`, second DMA stop, `CR` 0, power-off
/// sequence); dual-MAC with the other MAC still on refuses to power
/// off; `check_poweroff` clears the MAC-ON bit and marks the
/// in-process bit only when the other MAC is off.
fn smoke_rtl8192de_card_disable() -> TestResult {
    use power::*;
    // Single MAC, MAC0 on: full disable powers off.
    let io = de_mac_fake();
    io.0.lock().regs[usize::from(REG_MAC0)] |= MAC0_ON;
    let mut bcn = station::BcnCtrl::default();
    match narf_scheduler::block_on(card_disable(
        &io,
        MacPhyMode::SingleMacSinglePhy,
        0,
        &mut bcn,
    )) {
        Ok(true) => {}
        _ => return TestResult::Fail("8192DE card disable single refused"),
    }
    if de_mac_read8(&io, REG_PCIE_CTRL_REG + 1) != 0xff
        || de_mac_read8(&io, fw::REG_SYS_FUNC_EN) != 0xe2
        || de_mac_read8(&io, REG_CR) != 0x00
        || de_mac_read8(&io, REG_MAC0) & MAC0_ON != 0
        || de_mac_read16(&io, REG_GPIO_IO_SEL) != 0x0790
        || de_mac_read8(&io, phy::REG_AFE_PLL_CTRL) != 0x80
    {
        return TestResult::Fail("8192DE card disable single trace");
    }
    // Dual MAC, other MAC still on: no power-off.
    let io = de_mac_fake();
    io.0.lock().regs[usize::from(REG_MAC1)] |= MAC1_ON;
    let mut bcn = station::BcnCtrl::default();
    match narf_scheduler::block_on(card_disable(&io, MacPhyMode::DualMacDualPhy, 0, &mut bcn)) {
        Ok(false) => {}
        _ => return TestResult::Fail("8192DE card disable dual other-on"),
    }
    if de_mac_read8(&io, phy::REG_AFE_PLL_CTRL) != 0x00 {
        return TestResult::Fail("8192DE card disable dual powered off");
    }
    // `check_poweroff` units.
    let io = de_mac_fake();
    io.0.lock().regs[usize::from(REG_MAC0)] |= MAC0_ON;
    match check_poweroff(&io, MacPhyMode::SingleMacSinglePhy, 0) {
        Ok(true) => {}
        _ => return TestResult::Fail("8192DE check poweroff single"),
    }
    if de_mac_read8(&io, REG_MAC0) & MAC0_ON != 0 {
        return TestResult::Fail("8192DE check poweroff single bit");
    }
    let io = de_mac_fake();
    io.0.lock().regs[usize::from(REG_MAC0)] |= MAC0_ON;
    io.0.lock().regs[usize::from(REG_MAC1)] |= MAC1_ON;
    match check_poweroff(&io, MacPhyMode::DualMacDualPhy, 0) {
        Ok(false) => {}
        _ => return TestResult::Fail("8192DE check poweroff dual other-on"),
    }
    let io = de_mac_fake();
    io.0.lock().regs[usize::from(REG_MAC0)] |= MAC0_ON;
    match check_poweroff(&io, MacPhyMode::DualMacDualPhy, 0) {
        Ok(true) => {}
        _ => return TestResult::Fail("8192DE check poweroff dual other-off"),
    }
    if de_mac_read8(&io, REG_POWER_OFF_IN_PROCESS) & POWER_OFF_IN_PROCESS == 0 {
        return TestResult::Fail("8192DE check poweroff in-process bit");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_lck_tables
);

/// LC curve counts for the end-to-end tests. Path A (5 GHz) counts
/// make the odd slots win: odd value `(0xc0ee0 & 0xfffe0) >> 5` =
/// 24703, even value 0, so every 5 GHz target (21007-25679) lands on
/// an odd index (first odd slot, j=1). Path B counts are all zero, so
/// the even slot j=0 wins everywhere.
fn lck_curve_counts(io: &DeMacFake) {
    de_mac_rf_set(io, 0, lck::RF_LCK_CURVE_CNT_LO, 0x000c_0ee0);
    de_mac_rf_set(io, 0, lck::RF_LCK_CURVE_CNT_HI, 0x0000_0000);
    de_mac_rf_set(io, 1, lck::RF_LCK_CURVE_CNT_LO, 0x0000_0000);
    de_mac_rf_set(io, 1, lck::RF_LCK_CURVE_CNT_HI, 0x0000_0000);
}

/// End-to-end `_rtl92d_phy_lc_calibrate_sw` on the packet-TX case
/// (`0xd03` clear): 2 paths, the SYN_G6 poll setting on the 3rd
/// staging (100 ms each), curve-index computation (5 GHz odd slot,
/// 2.4 GHz even slot), and the full restore (RF modes, `0xd03` /
/// TXPAUSE, ANALOGPARAMETER4, SYN_G7 BIT(17) set, CHNLBW bit clear,
/// SYN_G4 reload for channel 36).
fn smoke_rtl8192de_lc_calibrate_sw() -> TestResult {
    let io = de_mac_fake();
    io.0.lock().regs[usize::from(lck::ROFDM0_XAAGCCORE1)] = 0xa5;
    io.0.lock().regs[usize::from(lck::ROFDM0_XBAGCCORE1)] = 0x5a;
    de_mac_rf_set(&io, 0, lck::RF_SYN_G6, 0);
    de_mac_rf_set(&io, 1, lck::RF_SYN_G6, 0);
    de_mac_rf_set_g6_after(&io, 0, 3);
    de_mac_rf_set_g6_after(&io, 1, 3);
    lck_curve_counts(&io);
    let mut lck_state = lck::Lck::new();
    let cfg = lck::LcConfig {
        rf_type: super::RfType::TwoT2R,
        mode: super::MacPhyMode::SingleMacSinglePhy,
        interface_index: 0,
        current_channel: 36,
        band: super::Band::On5Ghz,
        init_ready: true,
        act_scanning: false,
    };
    let outcome = match narf_scheduler::block_on(lck::lc_calibrate_sw(&io, &mut lck_state, &cfg)) {
        Ok(outcome) => outcome,
        Err(_) => return TestResult::Fail("8192DE LC calibrate sw"),
    };
    if outcome.path_count != 2
        || outcome.poll_ms != [100, 100]
        || outcome.poll_timed_out != [false, false]
        || outcome.scan_wait_us != 0
        || lck_state.in_progress
        || lck_state.curveindex_5g[35] != 1
        || lck_state.curveindex_2g[0] != 0
    {
        return TestResult::Fail("8192DE LC calibrate outcome");
    }
    if de_mac_read8(&io, lck::REG_TXPAUSE) != 0x00
        || de_mac_read32(&io, phy::RFPGA0_ANALOGPARAMETER4) & 0x00f0_0000 != 0
        || de_mac_read8(&io, lck::ROFDM0_XAAGCCORE1) != 0xa5
        || de_mac_read8(&io, lck::ROFDM0_XBAGCCORE1) != 0x5a
    {
        return TestResult::Fail("8192DE LC calibrate restore");
    }
    if de_mac_rf_get(&io, 0, lck::RF_SYN_G7) & (1 << 17) == 0
        || de_mac_rf_get(&io, 1, lck::RF_SYN_G7) & (1 << 17) == 0
        || de_mac_rf_get(&io, 0, phy::RF_CHNLBW) & lck::CHNLBW_LC_BEGIN != 0
        || de_mac_rf_get(&io, 1, phy::RF_CHNLBW) & lck::CHNLBW_LC_BEGIN != 0
        || de_mac_rf_get(&io, 0, lck::RF_LCK_CURVE_SEL) != 63
        || de_mac_rf_get(&io, 1, lck::RF_LCK_CURVE_SEL) != 63
        || de_mac_rf_get(&io, 0, lck::RF_SYN_G4) != 0x800
    {
        return TestResult::Fail("8192DE LC calibrate RF state");
    }
    // Exact delay accounting: per path 200 RF reads (3 delays each)
    // + 2 poll delays; plus 1 reload RF read. 400 reads x 120 µs +
    // 4 x 50 ms + 120 µs = 248120 µs over 1207 calls.
    if de_mac_delays(&io) != (1207, 248_120) {
        return TestResult::Fail("8192DE LC calibrate delays");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_lc_calibrate_sw
);

/// End-to-end `rtl92d_phy_lc_calibrate` on the continuous-TX case
/// (`0xd03` = `0x70`): 1 path, scan wait (2000 µs), the SYN_G6 poll
/// timing out (850 ms), `init_ready` false skipping the LC-begin RF
/// writes, and the `0xd03` restore.
fn smoke_rtl8192de_lc_calibrate() -> TestResult {
    let io = de_mac_fake();
    io.0.lock().regs[usize::from(lck::REG_CONT_TX)] = 0x70;
    io.0.lock().regs[usize::from(lck::ROFDM0_XAAGCCORE1)] = 0x33;
    de_mac_rf_set(&io, 0, lck::RF_SYN_G6, 0);
    lck_curve_counts(&io);
    let mut lck_state = lck::Lck::new();
    let cfg = lck::LcConfig {
        rf_type: super::RfType::OneT1R,
        mode: super::MacPhyMode::SingleMacSinglePhy,
        interface_index: 1,
        current_channel: 1,
        band: super::Band::On2Ghz,
        init_ready: false,
        act_scanning: true,
    };
    let outcome = match narf_scheduler::block_on(lck::lc_calibrate(&io, &mut lck_state, &cfg)) {
        Ok(outcome) => outcome,
        Err(_) => return TestResult::Fail("8192DE LC calibrate"),
    };
    if outcome.path_count != 1
        || outcome.poll_ms != [850, 0]
        || outcome.poll_timed_out != [true, false]
        || outcome.scan_wait_us != 2000
        || lck_state.in_progress
        || lck_state.curveindex_2g[0] != 1
    {
        return TestResult::Fail("8192DE LC calibrate timeout outcome");
    }
    if de_mac_read8(&io, lck::REG_CONT_TX) != 0x70
        || de_mac_read8(&io, lck::REG_TXPAUSE) != 0x00
        || de_mac_read32(&io, phy::RFPGA0_ANALOGPARAMETER4) & 0x00f0_0000 != 0
        || de_mac_read8(&io, lck::ROFDM0_XAAGCCORE1) != 0x33
        || de_mac_rf_get(&io, 0, lck::RF_SYN_G7) != 0x20000
        || de_mac_rf_get(&io, 0, phy::RF_CHNLBW) != 0
        || de_mac_rf_get(&io, 0, lck::RF_SYN_G4) != 0x800
    {
        return TestResult::Fail("8192DE LC calibrate timeout state");
    }
    // 40 scan delays + 213 RF reads (3 delays each) + 17 poll delays
    // + 1 reload RF read: 699 calls, 877680 µs.
    if de_mac_delays(&io) != (699, 877_680) {
        return TestResult::Fail("8192DE LC calibrate timeout delays");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_lc_calibrate
);

/// `_rtl92d_phy_reload_lck_setting` directly: 5 GHz / 2.4 GHz path
/// selection, the SYN_G4 merge (`curve << 11`), the dual-dual other-PHY
/// enable + RF-env save/restore + powerdown, and the bad-channel
/// refusals.
fn smoke_rtl8192de_reload_lck_setting() -> TestResult {
    // 5 GHz channel 36, single mode: path A, curve 42.
    let io = de_mac_fake();
    let mut lck_state = lck::Lck::new();
    lck_state.curveindex_5g[35] = 42;
    if narf_scheduler::block_on(lck::reload_lck_setting(
        &io,
        &lck_state,
        super::Band::On5Ghz,
        super::RfType::TwoT2R,
        super::MacPhyMode::SingleMacSinglePhy,
        0,
        36,
    ))
    .is_err()
        || de_mac_rf_get(&io, 0, lck::RF_SYN_G4) != 42 << 11
        || de_mac_rf_get(&io, 1, lck::RF_SYN_G4) != 0
    {
        return TestResult::Fail("8192DE reload LCK 5G");
    }
    // 2.4 GHz channel 1, single-PHY (2T2R): path B, curve 7.
    let io = de_mac_fake();
    let mut lck_state = lck::Lck::new();
    lck_state.curveindex_2g[0] = 7;
    if narf_scheduler::block_on(lck::reload_lck_setting(
        &io,
        &lck_state,
        super::Band::On2Ghz,
        super::RfType::TwoT2R,
        super::MacPhyMode::SingleMacSinglePhy,
        0,
        1,
    ))
    .is_err()
        || de_mac_rf_get(&io, 1, lck::RF_SYN_G4) != 7 << 11
        || de_mac_rf_get(&io, 0, lck::RF_SYN_G4) != 0
    {
        return TestResult::Fail("8192DE reload LCK 2G single");
    }
    // 2.4 GHz channel 1, dual (1T1R): path A, curve 7.
    let io = de_mac_fake();
    if narf_scheduler::block_on(lck::reload_lck_setting(
        &io,
        &lck_state,
        super::Band::On2Ghz,
        super::RfType::OneT1R,
        super::MacPhyMode::SingleMacSinglePhy,
        0,
        1,
    ))
    .is_err()
        || de_mac_rf_get(&io, 0, lck::RF_SYN_G4) != 7 << 11
    {
        return TestResult::Fail("8192DE reload LCK 2G dual");
    }
    // Dual-dual 5 GHz on MAC1: the other-PHY enable runs (DBI powerdown
    // lands last, CTRL 0xf840), the RF-env enable sets bits 20+4 of
    // 0x860, and the SYN_G4 write still lands.
    let io = de_mac_fake();
    lck_state.curveindex_5g[35] = 42;
    if narf_scheduler::block_on(lck::reload_lck_setting(
        &io,
        &lck_state,
        super::Band::On5Ghz,
        super::RfType::OneT1R,
        super::MacPhyMode::DualMacDualPhy,
        1,
        36,
    ))
    .is_err()
        || de_mac_rf_get(&io, 0, lck::RF_SYN_G4) != 42 << 11
        || de_mac_read16(&io, phy::REG_DBI_CTRL) != 0xf840
        || de_mac_read32(&io, 0x860) != 0x0010_0010
    {
        return TestResult::Fail("8192DE reload LCK dual-dual");
    }
    // Bad channels are refused: 0, and past the band table.
    let io = de_mac_fake();
    if narf_scheduler::block_on(lck::reload_lck_setting(
        &io,
        &lck_state,
        super::Band::On2Ghz,
        super::RfType::TwoT2R,
        super::MacPhyMode::SingleMacSinglePhy,
        0,
        0,
    ))
    .is_ok()
        || narf_scheduler::block_on(lck::reload_lck_setting(
            &io,
            &lck_state,
            super::Band::On2Ghz,
            super::RfType::TwoT2R,
            super::MacPhyMode::SingleMacSinglePhy,
            0,
            15,
        ))
        .is_ok()
    {
        return TestResult::Fail("8192DE reload LCK bad channel admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_card_disable
);

/// Version qualification: the EFUSE chip-version word decodes to
/// C (`0xAA55`), D (`0x9966`), E (`0xCC33`) or D for anything else;
/// `REG_9346CR` BIT(5) is the autoload-OK flag; `REG_SYS_CFG`
/// bits 19:16 clear means a test chip.
fn smoke_rtl8192de_version_cut() -> TestResult {
    let io = de_mac_fake();
    for (high, low, cut) in [
        (0xaa, 0x55, version::Cut::C),
        (0x99, 0x66, version::Cut::D),
        (0xcc, 0x33, version::Cut::E),
        (0x12, 0x34, version::Cut::D),
    ] {
        io.0.lock().efuse[0x3fe] = high;
        io.0.lock().efuse[0x3ff] = low;
        match narf_scheduler::block_on(version::read_cut(&io)) {
            Ok(found) if found == cut => {}
            _ => return TestResult::Fail("8192DE version cut decode"),
        }
    }
    if !version::Cut::D.d_or_e_cut()
        || !version::Cut::E.d_or_e_cut()
        || version::Cut::C.d_or_e_cut()
    {
        return TestResult::Fail("8192DE version d_or_e_cut");
    }
    io.0.lock().regs[usize::from(version::REG_9346CR)] = 0x20;
    match version::autoload_failed(&io) {
        Ok(false) => {}
        _ => return TestResult::Fail("8192DE version autoload ok"),
    }
    io.0.lock().regs[usize::from(version::REG_9346CR)] = 0x00;
    match version::autoload_failed(&io) {
        Ok(true) => {}
        _ => return TestResult::Fail("8192DE version autoload fail"),
    }
    match version::is_test_chip(&io) {
        Ok(true) => {}
        _ => return TestResult::Fail("8192DE version test chip"),
    }
    io.0.lock().regs[usize::from(version::REG_SYS_CFG) + 2] = 0x01;
    match version::is_test_chip(&io) {
        Ok(false) => {}
        _ => return TestResult::Fail("8192DE version normal chip"),
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_reload_lck_setting
);

/// `wait_dualphy_rf_ready` (hw.c:1002-1024): BIT(11) setting on the
/// 5th staging returns ready; never setting times out after 10000
/// polls.
fn smoke_rtl8192de_wait_dualphy_rf_ready() -> TestResult {
    let io = de_mac_fake();
    de_mac_rf_set(&io, 0, lck::RF_SYN_G6, 0);
    de_mac_rf_set_g6_after(&io, 0, 5);
    match narf_scheduler::block_on(lck::wait_dualphy_rf_ready(&io)) {
        Ok(true) => {}
        _ => return TestResult::Fail("8192DE dual-PHY RF ready"),
    }
    // 5 iterations x (1 poll delay + 1 RF read x 3 delays) = 20
    // calls, 5 x 50 µs + 5 x 120 µs = 850 µs.
    if de_mac_delays(&io) != (20, 850) {
        return TestResult::Fail("8192DE dual-PHY RF ready delays");
    }
    let io = de_mac_fake();
    de_mac_rf_set(&io, 0, lck::RF_SYN_G6, 0);
    match narf_scheduler::block_on(lck::wait_dualphy_rf_ready(&io)) {
        Ok(false) => {}
        _ => return TestResult::Fail("8192DE dual-PHY RF timeout"),
    }
    if de_mac_delays(&io) != (40_000, 1_700_000) {
        return TestResult::Fail("8192DE dual-PHY RF timeout delays");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_version_cut
);

/// The `rtl92de_hw_init` orchestrator on a single-MAC 2.4 GHz
/// function: power-on, MAC/BB/RF tail, TX-power level at channel 1,
/// and the radio report (mode, band, RF type, RF on, PG store).
fn smoke_rtl8192de_hw_init() -> TestResult {
    let efuse = match txpower::Efuse::from_hwinfo(&level_hwinfo(), false, false) {
        Ok(efuse) => efuse,
        Err(_) => return TestResult::Fail("8192DE hw_init efuse"),
    };
    let io = de_mac_fake();
    let radio = match narf_scheduler::block_on(init::configure(
        &io,
        &init::Params {
            mode: MacPhyMode::SingleMacSinglePhy,
            interface_index: 0,
            band: Band::On2Ghz,
            mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            efuse,
            rf_type: RfType::TwoT2R,
            channel: 1,
            bw40: false,
            autoload_fail: false,
        },
    )) {
        Ok(radio) => radio,
        Err(_) => return TestResult::Fail("8192DE hw_init configure"),
    };
    if radio.mode != MacPhyMode::SingleMacSinglePhy
        || radio.band != Band::On2Ghz
        || radio.rf_type != RfType::TwoT2R
        || !radio.rf_on
        || radio.pg.is_none()
    {
        return TestResult::Fail("8192DE hw_init radio report");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_wait_dualphy_rf_ready
);

/// Channel-switch LCK wait: a set `lck_inprogress` snapshot waits the
/// full 1000 ms bound (20 x 50 ms delays) before the switch still
/// proceeds; a clear snapshot adds no wait.
fn smoke_rtl8192de_switch_channel_lck_wait() -> TestResult {
    let efuse = match txpower::Efuse::from_hwinfo(&level_hwinfo(), false, false) {
        Ok(efuse) => efuse,
        Err(_) => return TestResult::Fail("8192DE LCK wait EFUSE decode"),
    };
    let pg = zero_pg();
    let run = |lck: bool| -> Option<(bool, u64, u64)> {
        let io = de_mac_fake();
        let mut band = super::Band::On2Ghz;
        let mut bandset = super::BandSet::OnBoth;
        let mut chnlval = [0x1234_5600u32; 2];
        // Fresh matrix per run: `switch_channel` reloads the stored
        // matrix for the new channel, and the matrix is reset before
        // any switch (`rtl92de_hw_init`).
        let mut iqk = calib::IqkMatrix::new();
        let outcome = narf_scheduler::block_on(channel::switch_channel(
            &io,
            &efuse,
            &pg,
            super::RfType::TwoT2R,
            super::MacPhyMode::SingleMacSinglePhy,
            0,
            &mut band,
            &mut bandset,
            true,
            6,
            false,
            &mut chnlval,
            &mut iqk,
            lck,
        ))
        .ok()?;
        let (delays, total) = de_mac_delays(&io);
        Some((outcome.switched, delays, total))
    };
    let (switched_clear, delays_clear, total_clear) = match run(false) {
        Some(v) => v,
        None => return TestResult::Fail("8192DE LCK wait clear run"),
    };
    let (switched_set, delays_set, total_set) = match run(true) {
        Some(v) => v,
        None => return TestResult::Fail("8192DE LCK wait set run"),
    };
    if !switched_clear
        || !switched_set
        || delays_set - delays_clear != 20
        || total_set - total_clear != 1_000_000
    {
        return TestResult::Fail("8192DE LCK wait bound");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_hw_init
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_switch_channel_lck_wait
);
