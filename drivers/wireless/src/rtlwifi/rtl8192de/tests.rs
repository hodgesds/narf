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
    if fw::parse(&[]).is_ok() || fw::parse(&vec![0u8; fw::HEADER]).is_ok() {
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
                g.regs[usize::from(fw::REG_MCUFWDL)] |= fw::MCUFWDL_EN as u8 | 0x02;
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

/// Build a NAPC envelope from the documented layout (header 96, rows of
/// 388 bytes: channel/band/bandwidth/offset + three 64-entry curves).
/// `rows` are (channel, bandwidth, offset, curve-value fn) for v2, or
/// (channel, 20, 0, fn) for v1.
fn de_napc_fixture(
    version: u16,
    antenna: i16,
    qualified: i16,
    rows: &[(u8, u8, u8, fn(u8, u8) -> i16)],
) -> Vec<u8> {
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
    // A 5 GHz row (band byte 1) is a format failure in step 2.
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
    let owner = Owner::admit(
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
        let r = usize::from(reg);
        Ok(u32::from_le_bytes([
            g.regs[r],
            g.regs[r + 1],
            g.regs[r + 2],
            g.regs[r + 3],
        ]))
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), FwError> {
        self.0.lock().regs[usize::from(reg)] = value;
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
        Ok(())
    }
    fn write_bytes(&self, _reg: u16, _bytes: &[u8]) -> Result<(), FwError> {
        Err(FwError::Access)
    }
    async fn delay_us(&self, _micros: u64) {}
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
    })))
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
