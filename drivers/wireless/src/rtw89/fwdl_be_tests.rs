// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Fixture tests for the RTL8922A firmware-download preparation
//! (`fwdl_be`). Expected words are written from the Linux `reg.h`
//! literals and the `mac_be.c` / `rtw8922a.c` step order, not by
//! calling the code under test.

use super::fwdl_be::*;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Default)]
struct Model {
    regs32: BTreeMap<u32, u32>,
    regs16: BTreeMap<u32, u16>,
    writes: Vec<(u32, u32)>,
    /// DLE INI_STATUS reads report both ready bits.
    dle_ready: bool,
}

impl Model {
    fn with(mut self, addr: u32, value: u32) -> Self {
        self.regs32.insert(addr, value);
        self
    }
    fn get(&self, addr: u32) -> u32 {
        *self.regs32.get(&addr).unwrap_or(&0)
    }
}

impl Regs for Model {
    fn read16(&mut self, address: u32) -> u16 {
        *self.regs16.get(&address).unwrap_or(&0)
    }
    fn read32(&mut self, address: u32) -> u32 {
        if self.dle_ready && (address == 0x8D00 || address == 0x9100) {
            return 0b11;
        }
        self.get(address)
    }
    fn write16(&mut self, address: u32, value: u16) {
        self.regs16.insert(address, value);
    }
    fn write32(&mut self, address: u32, value: u32) {
        self.writes.push((address, value));
        self.regs32.insert(address, value);
    }
}

fn smoke_rtw89_8922a_fwdl_be_mac_func_en() -> TestResult {
    // CMAC0_FEN (bit 16) set, CMAC1_FEN clear; ISO_CMAC02PP (bit 24) set.
    let mut m = Model::default().with(0x0084, (1 << 16) | (1 << 24));
    mac_func_en(&mut m);
    if m.get(0x0024) != 0x1f00_0000 {
        return TestResult::Fail("AFE_CTRL1 must gain WLCMAC0_ALL_EN (bits 24..28)");
    }
    if m.get(0x0084) != 1 << 16 {
        return TestResult::Fail("FEN_RST_ENABLE must drop ISO_CMAC02PP and keep CMAC0_FEN");
    }
    if m.get(0x10004) != 0x4000_01ff || m.get(0x10000) != 0xf000_01ff {
        return TestResult::Fail("band-0 CK_EN / CMAC_FUNC_EN set masks wrong");
    }
    if m.regs32.contains_key(&0x14000) || m.regs32.contains_key(&0x14004) {
        return TestResult::Fail("band 1 touched without CMAC1_FEN");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_8922a_fwdl_be_mac_func_en
);

fn smoke_rtw89_8922a_fwdl_be_partial_init_dlfw() -> TestResult {
    let cfg = &DLE_DLFW_8922A_PCIE;
    // 64*3328 + 128*2928 + 2048 == fifo_size 589824.
    if dle_used_size(cfg) != 589_824 {
        return TestResult::Fail("DLFW DLE table does not cover the 8922A FIFO");
    }
    let mut m = Model {
        dle_ready: true,
        ..Model::default()
    }
    .with(0xB010, 0xffff_ffff)
    .with(0xB700, 0b1001);
    if partial_init(&mut m).is_err() {
        return TestResult::Fail("partial_init refused with DLE ready emulated");
    }
    if m.get(0x7880) & 0b11 != 0b11 {
        return TestResult::Fail("HCI TX/RX DMA not enabled");
    }
    // bb_preinit: DMAC_SYS_CR32B[15:0] = 0x7FF9; BB-MCU CR writes at +0x30000.
    if m.get(0x842C) & 0xffff != 0x7FF9 {
        return TestResult::Fail("BB preinit DMAC_SYS_CR32B wrong");
    }
    if m.get(0x6820 + 0x30000) != 0xFFFF_FFFF || m.get(0x6818 + 0x30000) != 0x0478_C009 {
        return TestResult::Fail("BB-MCU CR init not written through the 0x30000 window");
    }
    // FEN_RST_ENABLE after preinit: BB_IP_RSTN (bit1) = 1, BBPLAT (bit0) = 0, BOOT_RDY0 (bit2) = 0.
    if m.get(0x0084) & 0b111 != 0b010 {
        return TestResult::Fail("BB preinit reset sequence end state wrong");
    }
    if m.get(0xB010) & 0x7fff != 0 || m.get(0x8420) & (1 << 12) == 0 {
        return TestResult::Fail("dmac_func_pre_en did not clear TX stop / set addr mode");
    }
    // WDE: page sel 64 (0), bound 0, free pages (lnk) 0.
    if m.get(0x8C08) != 0 {
        return TestResult::Fail("WDE_PKTBUF_CFG wrong");
    }
    // PLE: page sel 128 (1), bound 212992/8192 = 26, free pages 2928.
    if m.get(0x9008) != 1 | (26 << 8) | (2928 << 16) {
        return TestResult::Fail("PLE_PKTBUF_CFG wrong");
    }
    // WDE Q1 = ext SCC wcpu min 6 / max 6; PLE Q2 (c2h) 32, Q3 (h2c) 256, Q10 (cpu_io) 1.
    if m.get(0x8C44) != 6 | (6 << 16) || m.get(0x8C40) != 0 {
        return TestResult::Fail("WDE quota wrong");
    }
    if m.get(0x9048) != 32 | (32 << 16)
        || m.get(0x904C) != 256 | (256 << 16)
        || m.get(0x9068) != 1 | (1 << 16)
    {
        return TestResult::Fail("PLE quota wrong");
    }
    if m.regs32.contains_key(&0x9074) {
        return TestResult::Fail("8922A must not program PLE QTA13 (snrpt)");
    }
    if m.get(0x8400) & ((1 << 26) | (1 << 23)) != (1 << 26) | (1 << 23) {
        return TestResult::Fail("DLE WDE/PLE not re-enabled");
    }
    // HFC: FC_EN off, CH12_EN on; CH_PAGE_CTRL keeps only 256 & 0x3f = 0.
    if m.get(0xB700) != 1 << 3 || m.get(0xB704) != 0 {
        return TestResult::Fail("HFC DLFW h2c-only config wrong");
    }
    // No DLE ready: bounded timeout.
    let mut m = Model::default();
    if dle_init_dlfw(&mut m) != Err(Error::PollTimeout) {
        return TestResult::Fail("DLE init must time out without INI_RDY");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_8922a_fwdl_be_partial_init_dlfw
);

fn smoke_rtw89_8922a_fwdl_be_wcpu_control() -> TestResult {
    // RUN_ENV (bits 31:30) survives disable; everything else clears.
    let mut m = Model::default()
        .with(0x01E0, 0xC000_0F0F)
        .with(0x0088, 1 << 1)
        .with(0x016C, 0x55)
        .with(0x01F4, 0x66);
    disable_cpu(&mut m);
    if m.get(0x01E0) != 0xC000_0000 {
        return TestResult::Fail("disable_cpu must keep only RUN_ENV");
    }
    if m.get(0x0088) != (1 << 11) | (1 << 1) || m.get(0x0888) & 1 == 0 {
        return TestResult::Fail("disable_cpu platform/DCPU enables wrong");
    }
    if m.get(0x016C) != 0 {
        return TestResult::Fail("disable_cpu must clear HALT_C2H");
    }
    m.regs32.insert(0x016C, 0x77);
    m.regs16.insert(0x01E6, 0xfff8 | 0b101);
    m.regs32.insert(0x0040, 1 << 19);
    let residue = enable_wcpu(&mut m, 0, true);
    if residue.halt_c2h != 0x77 || residue.udm1 != 0x66 {
        return TestResult::Fail("pre-boot AON residue not reported");
    }
    let ctrl = m.get(0x01E0);
    if ctrl & ((1 << 9) | (1 << 11)) != (1 << 9) | (1 << 11) {
        return TestResult::Fail("WLANCPU/BBMCU0 FWDL_EN not set");
    }
    if m.get(0x0088) != 1 << 1 {
        return TestResult::Fail("wcpu_on must end with WCPU_EN set and HOLD_AFTER_RESET clear");
    }
    if m.regs16.get(&0x01E6) != Some(&0xfff8) {
        return TestResult::Fail("BOOT_REASON low 3 bits must carry the reason");
    }
    if m.get(0x0040) != 0 || m.get(0x0008) & (1 << 14) == 0 || m.get(0x01A4) != 1 << 21 {
        return TestResult::Fail("boot mode / CPU clock / HISR0 HALT_C2H ack wrong");
    }
    // FWDL preconfig: DELAY_COUNT_VALID (bit 15) and the count [14:0] clear.
    let mut m = Model::default().with(0x0188, 0xffff_ffff);
    fwdl_preconfig(&mut m);
    if m.get(0x0188) != 0xffff_0000 {
        return TestResult::Fail("fwdl_preconfig must clear bits 15..0 only");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_8922a_fwdl_be_wcpu_control
);

fn smoke_rtw89_8922a_fwdl_be_status() -> TestResult {
    // FWDL_EN still set, raw status 3 -> WCPU_FW_INIT_RDY.
    let mut m = Model::default().with(0x01E0, (1 << 9) | (3 << 26));
    if fwdl_status(&mut m, CheckType::FreeRtos) != FwdlStatus::WcpuFwInitReady {
        return TestResult::Fail("raw 3 must map to WCPU_FW_INIT_RDY");
    }
    if check_ready(&mut m, CheckType::FreeRtos).is_err() {
        return TestResult::Fail("check_ready refused an init-ready status");
    }
    // WCPU done is the FWDL_EN bit clearing, whatever the status field says.
    let mut m = Model::default().with(0x01E0, 4 << 26);
    if fwdl_status(&mut m, CheckType::Wcpu) != FwdlStatus::WcpuFwInitReady {
        return TestResult::Fail("cleared WLANCPU_FWDL_EN must pass WCPU check");
    }
    // Checksum failure (raw 4) is terminal.
    let mut m = Model::default().with(0x01E0, (1 << 9) | (4 << 26));
    if check_ready(&mut m, CheckType::Wcpu) != Err(Error::Firmware(FwdlStatus::ChecksumFail)) {
        return TestResult::Fail("checksum failure must be reported");
    }
    for (raw, want) in [
        (5u32, FwdlStatus::SecurityFail),
        (6, FwdlStatus::SecurityFail),
        (7, FwdlStatus::CvNotMatch),
        (2, FwdlStatus::WcpuFwdlReady),
        (12, FwdlStatus::Raw(12)),
    ] {
        let mut m = Model::default().with(0x01E0, (1 << 9) | (raw << 26));
        if fwdl_status(&mut m, CheckType::Wcpu) != want {
            return TestResult::Fail("fwdl_status_map drift");
        }
    }
    // Path ready: H2C is bit 1, DLFW bit 0.
    let mut m = Model::default().with(0x01E0, 1 << 1);
    if check_path_ready(&mut m, true).is_err() {
        return TestResult::Fail("H2C path ready not seen");
    }
    let mut m = Model::default().with(0x01E0, 1 << 1);
    if check_path_ready(&mut m, false) != Err(Error::PollTimeout) {
        return TestResult::Fail("DLFW path ready must wait for bit 0");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_8922a_fwdl_be_status);

// ── Download sequence (`fw.c:1701..2025`) ──────────────────────────

struct Image(Vec<u8>);
impl crate::rtw89::prepared::Files for Image {
    fn load(&mut self, _: &'static str) -> Result<Vec<u8>, crate::rtw89::fw::FwError> {
        Ok(self.0.clone())
    }
}

/// One-section v1 BE image (fw.h v1 layout: 48-byte base, 16-byte
/// descriptor; W3 bits 31:24 version, W6 bits 15:8 section count,
/// W7 bits 15:0 part size), secure boot off.
fn plan(part: u16, len: usize, fill: u8) -> crate::rtw89::download_plan::DownloadPlan {
    use crate::rtw89::efuse_be::SecureInfo;
    use crate::rtw89::mac::ChipId;
    use crate::rtw89::secure::{Blacklist, Fuses};
    let mut image = alloc::vec![0u8; 64];
    image[12..16].copy_from_slice(&(1u32 << 24).to_le_bytes());
    image[24..28].copy_from_slice(&(1u32 << 8).to_le_bytes());
    image[28..30].copy_from_slice(&part.to_le_bytes());
    image[48..52].copy_from_slice(&0x0020_0000u32.to_le_bytes());
    image[52..56].copy_from_slice(&(len as u32).to_le_bytes());
    image.extend(core::iter::repeat_n(fill, len));
    let prepared = crate::rtw89::prepared::load(&mut Image(image), ChipId::Rtl8922A, 1).unwrap();
    crate::rtw89::download_plan::DownloadPlan::new(
        prepared,
        Fuses::from_be(ChipId::Rtl8922A, SecureInfo::disabled()),
        Blacklist::upstream(ChipId::Rtl8922A),
    )
    .unwrap()
}

/// CH12 port fixture: the chip consumes instantly — both path-ready
/// bits read set, every FWDL_EN bit reads cleared (download done),
/// and the status field reads WCPU_FW_INIT_RDY (3) for FreeRTOS.
struct PortModel {
    m: Model,
    submits: Vec<(usize, bool, u8)>,
    refuse: bool,
    attempts: usize,
}

impl Regs for PortModel {
    fn read16(&mut self, address: u32) -> u16 {
        self.m.read16(address)
    }
    fn read32(&mut self, address: u32) -> u32 {
        let v = self.m.read32(address);
        if address == 0x01E0 {
            return (v & !((1 << 9) | (1 << 11)) & !(0xf << 26)) | 0b11 | (3 << 26);
        }
        v
    }
    fn write16(&mut self, address: u32, value: u16) {
        self.m.write16(address, value);
    }
    fn write32(&mut self, address: u32, value: u32) {
        self.m.write32(address, value);
    }
}

impl Port for PortModel {
    fn submit(&mut self, buf: &[u8], fwdl: bool) -> Result<(), Error> {
        self.attempts += 1;
        if self.refuse {
            return Err(Error::Transport);
        }
        self.submits.push((buf.len(), fwdl, buf[buf.len() - 1]));
        Ok(())
    }
}

fn smoke_rtw89_8922a_fwdl_be_download_sequence() -> TestResult {
    let normal = plan(128, 300, 0xA1);
    let bb = plan(100, 150, 0xB2);
    let mut port = PortModel {
        m: Model::default(),
        submits: Vec::new(),
        refuse: false,
        attempts: 0,
    };
    let normal_suit = Suit {
        plan: &normal,
        check: CheckType::Wcpu,
        malloc_info: true,
    };
    let bb_suit = [Suit {
        plan: &bb,
        check: CheckType::Bb0,
        malloc_info: false,
    }];
    if download(&mut port, &normal_suit, &bb_suit).is_err() {
        return TestResult::Fail("download refused a ready chip");
    }
    // FWHDR_DL (8-byte FWCMD header + 48 + 16) as H2C, then the
    // section in part-size packets as FWDL; then the BBMCU0 suit.
    let want = [
        (72usize, false, 0u8),
        (128, true, 0xA1),
        (128, true, 0xA1),
        (44, true, 0xA1),
        (72, false, 0),
        (100, true, 0xB2),
        (50, true, 0xB2),
    ];
    if port.submits.len() != want.len() {
        return TestResult::Fail("wrong CH12 packet count");
    }
    for (got, want) in port.submits.iter().zip(want.iter()) {
        if got.0 != want.0 || got.1 != want.1 || (want.1 && got.2 != want.2) {
            return TestResult::Fail("CH12 packet order/type/length drift");
        }
    }
    // 8922A NORMAL suit writes SECURE_BOOT_MALLOC_INFO (0x184) =
    // 0x20248000 exactly once; BBMCU0 does not.
    let malloc = port
        .m
        .writes
        .iter()
        .filter(|&&(a, v)| a == 0x0184 && v == 0x2024_8000)
        .count();
    if malloc != 1 {
        return TestResult::Fail("SECURE_BOOT_MALLOC_INFO must be written once");
    }
    // enable_wcpu asked for the BB-MCU download too (bit 11 set
    // in a WCPU_FW_CTRL write).
    if !port
        .m
        .writes
        .iter()
        .any(|&(a, v)| a == 0x01E0 && v & (1 << 11) != 0)
    {
        return TestResult::Fail("BBMCU0_FWDL_EN not requested");
    }
    // A refusing transport is retried five times (fw.c:2014).
    let mut port = PortModel {
        m: Model::default(),
        submits: Vec::new(),
        refuse: true,
        attempts: 0,
    };
    if download(&mut port, &normal_suit, &bb_suit) != Err(Error::Transport) {
        return TestResult::Fail("transport refusal must surface");
    }
    if port.attempts != 5 {
        return TestResult::Fail("download must retry exactly five times");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_8922a_fwdl_be_download_sequence
);
