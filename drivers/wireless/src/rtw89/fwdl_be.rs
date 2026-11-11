// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8922A (BE) firmware-download preparation and WCPU control.
//!
//! The register programs Linux runs between the power-on and the first
//! FWHDR_DL H2C on a BE chip, plus the WCPU status reads that gate each
//! download step. This is the BE half of `firmware_boot.rs` (which owns
//! the AX `disable_cpu`/`enable_cpu`/path-ready/initialized polls) and
//! of `fifo.rs` (the AX DLFW DLE/HFC carve):
//!
//! 1. [`mac_func_en`] — `rtw89_mac_preinit` tail
//!    (`mac_be.c:934 mac_func_en_be`): on 8922A `dmac_func_en_be` and
//!    `cmac_share_func_en_be` are no-ops; the per-band CMAC power +
//!    function enable runs for every band whose `CMACx_FEN` is set.
//! 2. [`partial_init`] — `rtw89_mac_partial_init` (`mac.c:4307`) up to
//!    the hci `mac_pre_init` hook: `rtw89_mac_ctrl_hci_dma_trx(true)`,
//!    `rtw8922a_bb_preinit(PHY_0)` (8922A has `bbmcu_nr = 1`, so
//!    `include_bb` is true, `mac.c:4362`), then
//!    `rtw89_mac_dmac_pre_init` (`mac.c`): `hci_func_en_be`,
//!    `dmac_func_pre_en_be`, `rtw89_mac_dle_init(RTW89_QTA_DLFW,
//!    RTW89_QTA_SCC)` and `rtw89_mac_hfc_init(reset, !en, h2c_en)`.
//!    The hci `mac_pre_init` (`pci_be.c rtw89_pci_ops_mac_pre_init_be`)
//!    is `Prepared8922a`'s DMA owner and is not repeated here.
//! 3. [`fwdl_preconfig`] — `rtw89_mac_fwdl_preconfig_be`.
//! 4. [`disable_cpu`] / [`enable_wcpu`] — `rtw89_mac_disable_cpu_be`,
//!    `rtw89_mac_fwdl_enable_wcpu_be` (`set_cpu_en` + `wcpu_on`).
//! 5. [`check_path_ready`], [`fwdl_status`], [`check_ready`] —
//!    `rtw89_fwdl_check_path_ready_be`, `fwdl_get_status_be`,
//!    `rtw89_fw_check_rdy` (`fw.c:106`).
//! 6. [`download`] / [`download_once`] / [`download_suit`] —
//!    `rtw89_fw_download` / `__rtw89_fw_download` /
//!    `rtw89_fw_download_suit` (`fw.c:1701..2025`) over a CH12
//!    [`Port`]. Synchronous like Linux's process-context download:
//!    the polls are bounded read counts and the one `mdelay(5)` is a
//!    responsive spin.
//!
//! Only the PCIe DLE/HFC tables are transcribed (`rtw8922a_dle_mem_pcie`
//! / `rtw8922a_hfc_param_ini_pcie`, `rtw8922a.c:50/178`); the USB/SDIO
//! arms of `dmac_func_pre_en_be` are not reachable from this driver.
//!
//! Polls are bounded read counts derived from the Linux
//! `read_poll_timeout` interval/timeout pairs (1 us interval), the
//! `mac_pre_init_8922a` convention, so fixtures can pre-seed status.
//!
//! ## References (GPL-2.0, linux-7.2 `drivers/net/wireless/realtek/rtw89`)
//!
//! - `mac_be.c:202..410` — `hfc_func_en_be`, `dle_func_en_be`,
//!   `dle_clk_en_be`, `dle_mix_cfg_be`, `chk_dle_rdy_be`,
//!   `wde_quota_cfg_be`, `ple_quota_cfg_be`, `rtw89_mac_hci_func_en_be`,
//!   `rtw89_mac_dmac_func_pre_en_be`.
//! - `mac_be.c:603..767` — CPU disable / FWDL preconfig / `wcpu_on` /
//!   status map / path ready.
//! - `mac_be.c:804..900` — `cmac_pwr_en_be`, `cmac_func_en_be`.
//! - `mac.c:1194 rtw89_mac_hfc_init`, `mac.c:2274 rtw89_mac_dle_init`,
//!   `mac.c:2041 dle_used_size`, `mac.c:1719..1897 rtw89_mac_size`.
//! - `rtw8922a.c:1747..1818` — `bb_mcu0_init_reg`,
//!   `rtw8922a_bbmcu_cr_init`, `rtw8922a_bb_preinit`; `phy.h:804
//!   rtw89_bbmcu_write32` (`RTW89_BBMCU_ADDR_OFFSET` 0x30000).
//! - `fw.h:9 enum rtw89_fw_dl_status`, `fw.h:5280 FWDL_WAIT_CNT`.
//! - `reg.h` — every `R_BE_*` / `B_BE_*` below, cited per constant.

use narf_scheduler::responsive_spin_until;
use narf_time::Deadline;

use super::download_plan::{self, DownloadPlan};

/// Register port for the BE SYS/DMAC/BB-MCU block. 16-bit accesses are
/// needed for `R_BE_BOOT_REASON` (`rtw89_write16_mask`). Production
/// wiring supplies `prepared_8922a::MmioRegs`; fixtures supply a map.
pub(super) trait Regs {
    fn read16(&mut self, address: u32) -> u16;
    fn read32(&mut self, address: u32) -> u32;
    fn write16(&mut self, address: u32, value: u16);
    fn write32(&mut self, address: u32, value: u32);
}

/// Failures. Each mirrors a Linux error return; registers already
/// written stay written (Linux behaves the same).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    /// A bounded poll exhausted its attempts (`-ETIMEDOUT`).
    PollTimeout,
    /// The DLE table does not cover the chip FIFO exactly
    /// (`dle_used_size != dle_expected_used_size`, `-EINVAL`).
    DleSize,
    /// `rtw89_fw_check_rdy` saw a terminal firmware status.
    Firmware(FwdlStatus),
    /// The download plan could not produce a header or chunk.
    Plan(download_plan::Error),
    /// The CH12 transport refused a packet (`rtw89_h2c_tx` error:
    /// no free TXBD, DMA allocation, rings not programmed).
    Transport,
}

// ── Registers (`reg.h`) ─────────────────────────────────────────────

/// `R_BE_SYS_CLK_CTRL`. `reg.h:3856`.
pub(super) const R_BE_SYS_CLK_CTRL: u32 = 0x0008;
/// `B_BE_CPU_CLK_EN`. `reg.h:3857`.
pub(super) const B_BE_CPU_CLK_EN: u32 = 1 << 14;
/// `R_BE_AFE_CTRL1`. `reg.h:3958`.
pub(super) const R_BE_AFE_CTRL1: u32 = 0x0024;
/// `B_BE_R_SYM_WLCMAC0_ALL_EN` = `WLCMAC0_{PC,P1..P4}_PC_EN`, bits 24..28.
/// `reg.h:3959..3968`.
pub(super) const B_BE_R_SYM_WLCMAC0_ALL_EN: u32 = 0x1f << 24;
/// `B_BE_R_SYM_WLCMAC1_ALL_EN` = `WLCMAC1_{PC,P1..P4}_PC_EN`, bits 0..4.
/// `reg.h:3985..3994`.
pub(super) const B_BE_R_SYM_WLCMAC1_ALL_EN: u32 = 0x1f;
/// `R_BE_GPIO_MUXCFG`. `reg.h:4005`.
pub(super) const R_BE_GPIO_MUXCFG: u32 = 0x0040;
/// `B_BE_BOOT_MODE`. `reg.h:4010`.
pub(super) const B_BE_BOOT_MODE: u32 = 1 << 19;
/// `R_BE_FEN_RST_ENABLE`. `reg.h:4135`.
pub(super) const R_BE_FEN_RST_ENABLE: u32 = 0x0084;
/// `B_BE_R_SYM_ISO_CMAC12PP`. `reg.h:4138`.
pub(super) const B_BE_R_SYM_ISO_CMAC12PP: u32 = 1 << 25;
/// `B_BE_R_SYM_ISO_CMAC02PP`. `reg.h:4139`.
pub(super) const B_BE_R_SYM_ISO_CMAC02PP: u32 = 1 << 24;
/// `B_BE_CMAC1_FEN`. `reg.h:4144`.
pub(super) const B_BE_CMAC1_FEN: u32 = 1 << 17;
/// `B_BE_CMAC0_FEN`. `reg.h:4145`.
pub(super) const B_BE_CMAC0_FEN: u32 = 1 << 16;
/// `B_BE_BOOT_RDY0`. `reg.h:4153`.
pub(super) const B_BE_BOOT_RDY0: u32 = 1 << 2;
/// `B_BE_FEN_BB_IP_RSTN`. `reg.h:4154`.
pub(super) const B_BE_FEN_BB_IP_RSTN: u32 = 1 << 1;
/// `B_BE_FEN_BBPLAT_RSTB`. `reg.h:4155`.
pub(super) const B_BE_FEN_BBPLAT_RSTB: u32 = 1 << 0;
/// `R_BE_PLATFORM_ENABLE`. `reg.h:4157`.
pub(super) const R_BE_PLATFORM_ENABLE: u32 = 0x0088;
/// `B_BE_HOLD_AFTER_RESET`. `reg.h:4158`.
pub(super) const B_BE_HOLD_AFTER_RESET: u32 = 1 << 11;
/// `B_BE_WCPU_EN`. `reg.h:4167`.
pub(super) const B_BE_WCPU_EN: u32 = 1 << 1;
/// `R_BE_MEM_PWR_CTRL`. `reg.h:4278`.
pub(super) const R_BE_MEM_PWR_CTRL: u32 = 0x00D0;
/// `B_BE_MEM_BBMCU0_DS_V1`. `reg.h:4292`.
pub(super) const B_BE_MEM_BBMCU0_DS_V1: u32 = 1 << 17;
/// `R_BE_HALT_H2C_CTRL`. `reg.h:4335`.
pub(super) const R_BE_HALT_H2C_CTRL: u32 = 0x0160;
/// `R_BE_HALT_C2H_CTRL`. `reg.h:4338`.
pub(super) const R_BE_HALT_C2H_CTRL: u32 = 0x0164;
/// `R_BE_HALT_H2C`. `reg.h:4341`.
pub(super) const R_BE_HALT_H2C: u32 = 0x0168;
/// `R_BE_HALT_C2H`. `reg.h:4344`.
pub(super) const R_BE_HALT_C2H: u32 = 0x016C;
/// `R_BE_SYS_CFG5`. `reg.h:4348`.
pub(super) const R_BE_SYS_CFG5: u32 = 0x0170;
/// `B_BE_WDT_WAKE_PCIE_EN`. `reg.h:4351`.
pub(super) const B_BE_WDT_WAKE_PCIE_EN: u32 = 1 << 10;
/// `B_BE_WDT_WAKE_USB_EN`. `reg.h:4352`.
pub(super) const B_BE_WDT_WAKE_USB_EN: u32 = 1 << 9;
/// `R_BE_SECURE_BOOT_MALLOC_INFO`. `reg.h:4357`.
pub(super) const R_BE_SECURE_BOOT_MALLOC_INFO: u32 = 0x0184;
/// `R_BE_FW_AUTO_CAL_DELAY`. `reg.h:4359`.
pub(super) const R_BE_FW_AUTO_CAL_DELAY: u32 = 0x0188;
/// `B_BE_WCPU_FW_DELAY_COUNT_VALID`. `reg.h:4360`.
pub(super) const B_BE_WCPU_FW_DELAY_COUNT_VALID: u32 = 1 << 15;
/// `B_BE_WCPU_FW_DELAY_COUNT_MASK` = GENMASK(14, 0). `reg.h:4361`.
pub(super) const B_BE_WCPU_FW_DELAY_COUNT_MASK: u32 = 0x7fff;
/// `R_BE_HISR0`. `reg.h:4503`.
pub(super) const R_BE_HISR0: u32 = 0x01A4;
/// `B_BE_HALT_C2H_INT`. `reg.h:4507`.
pub(super) const B_BE_HALT_C2H_INT: u32 = 1 << 21;
/// `R_BE_WCPU_FW_CTRL`. `reg.h:4530`.
pub(super) const R_BE_WCPU_FW_CTRL: u32 = 0x01E0;
/// `B_BE_RUN_ENV_MASK` = GENMASK(31, 30). `reg.h:4531`.
pub(super) const B_BE_RUN_ENV_MASK: u32 = 0b11 << 30;
/// `B_BE_WCPU_FWDL_STATUS_MASK` = GENMASK(29, 26). `reg.h:4532`.
pub(super) const B_BE_WCPU_FWDL_STATUS_MASK: u32 = 0xf << 26;
/// `B_BE_WDT_PLT_RST_EN`. `reg.h:4533`.
pub(super) const B_BE_WDT_PLT_RST_EN: u32 = 1 << 17;
/// `B_BE_BBMCU1_FWDL_EN`. `reg.h:4537`.
pub(super) const B_BE_BBMCU1_FWDL_EN: u32 = 1 << 12;
/// `B_BE_BBMCU0_FWDL_EN`. `reg.h:4538`.
pub(super) const B_BE_BBMCU0_FWDL_EN: u32 = 1 << 11;
/// `B_BE_DATACPU_FWDL_EN`. `reg.h:4539`.
pub(super) const B_BE_DATACPU_FWDL_EN: u32 = 1 << 10;
/// `B_BE_WLANCPU_FWDL_EN`. `reg.h:4540`.
pub(super) const B_BE_WLANCPU_FWDL_EN: u32 = 1 << 9;
/// `B_BE_WCPU_ROM_CUT_GET`. `reg.h:4541`.
pub(super) const B_BE_WCPU_ROM_CUT_GET: u32 = 1 << 8;
/// `B_BE_H2C_PATH_RDY`. `reg.h:4544`.
pub(super) const B_BE_H2C_PATH_RDY: u32 = 1 << 1;
/// `B_BE_DLFW_PATH_RDY`. `reg.h:4545`.
pub(super) const B_BE_DLFW_PATH_RDY: u32 = 1 << 0;
/// `R_BE_BOOT_REASON`. `reg.h:4547`.
pub(super) const R_BE_BOOT_REASON: u32 = 0x01E6;
/// `B_BE_BOOT_REASON_MASK` = GENMASK(2, 0). `reg.h:4548`.
pub(super) const B_BE_BOOT_REASON_MASK: u16 = 0b111;
/// `R_BE_UDM0`. `reg.h:4554`.
pub(super) const R_BE_UDM0: u32 = 0x01F0;
/// `R_BE_UDM1`. `reg.h:4566`.
pub(super) const R_BE_UDM1: u32 = 0x01F4;
/// `R_BE_UDM2`. `reg.h:4573`.
pub(super) const R_BE_UDM2: u32 = 0x01F8;
/// `R_BE_DCPU_PLATFORM_ENABLE`. `reg.h:4701`.
pub(super) const R_BE_DCPU_PLATFORM_ENABLE: u32 = 0x0888;
/// `B_BE_DCPU_PLATFORM_EN`. `reg.h:4708`.
pub(super) const B_BE_DCPU_PLATFORM_EN: u32 = 1 << 0;
/// `R_BE_HCI_FUNC_EN` (8922A `hci_func_en_addr`). `reg.h:4861`.
pub(super) const R_BE_HCI_FUNC_EN: u32 = 0x7880;
/// `B_BE_HCI_RXDMA_EN`. `reg.h:4864`.
pub(super) const B_BE_HCI_RXDMA_EN: u32 = 1 << 1;
/// `B_BE_HCI_TXDMA_EN`. `reg.h:4865`.
pub(super) const B_BE_HCI_TXDMA_EN: u32 = 1 << 0;
/// `R_BE_BOOT_DBG`. `reg.h:4867`.
pub(super) const R_BE_BOOT_DBG: u32 = 0x78F0;
/// `R_BE_DMAC_FUNC_EN`. `reg.h`; also `mac_pre_init_8922a`.
pub(super) const R_BE_DMAC_FUNC_EN: u32 = 0x8400;
/// `B_BE_DLE_WDE_EN`. `reg.h`; also `mac_pre_init_8922a`.
pub(super) const B_BE_DLE_WDE_EN: u32 = 1 << 26;
/// `B_BE_DLE_PLE_EN`. `reg.h`; also `mac_pre_init_8922a`.
pub(super) const B_BE_DLE_PLE_EN: u32 = 1 << 23;
/// `R_BE_DMAC_CLK_EN`. `reg.h:4899`.
pub(super) const R_BE_DMAC_CLK_EN: u32 = 0x8404;
/// `B_BE_DLE_WDE_CLK_EN`. `reg.h:4904`.
pub(super) const B_BE_DLE_WDE_CLK_EN: u32 = 1 << 26;
/// `B_BE_DLE_PLE_CLK_EN`. `reg.h:4907`.
pub(super) const B_BE_DLE_PLE_CLK_EN: u32 = 1 << 23;
/// `R_BE_DMAC_TABLE_CTRL`. `reg.h:4945`.
pub(super) const R_BE_DMAC_TABLE_CTRL: u32 = 0x8420;
/// `B_BE_DMAC_ADDR_MODE`. `reg.h:4948`.
pub(super) const B_BE_DMAC_ADDR_MODE: u32 = 1 << 12;
/// `R_BE_DMAC_SYS_CR32B`. `reg.h:4958`.
pub(super) const R_BE_DMAC_SYS_CR32B: u32 = 0x842C;
/// `B_BE_DMAC_BB_PHY0_MASK` = GENMASK(15, 0). `reg.h:4960`.
pub(super) const B_BE_DMAC_BB_PHY0_MASK: u32 = 0xffff;
/// `R_BE_WDE_PKTBUF_CFG`. `reg.h:5464`.
pub(super) const R_BE_WDE_PKTBUF_CFG: u32 = 0x8C08;
/// `R_BE_WDE_QTA0_CFG`; QTA1..4 follow at +4. `reg.h:5560..5578`.
pub(super) const R_BE_WDE_QTA0_CFG: u32 = 0x8C40;
/// `R_AX_WDE_INI_STATUS` (shared by BE, `chk_dle_rdy_be`). `reg.h:1386`.
pub(super) const R_AX_WDE_INI_STATUS: u32 = 0x8D00;
/// `R_BE_PLE_PKTBUF_CFG`. `reg.h:5585`.
pub(super) const R_BE_PLE_PKTBUF_CFG: u32 = 0x9008;
/// `R_BE_PLE_QTA0_CFG`; QTA1..12 follow at +4. `reg.h:5681..5731`.
pub(super) const R_BE_PLE_QTA0_CFG: u32 = 0x9040;
/// `R_AX_PLE_INI_STATUS` (shared by BE). `reg.h:1594`.
pub(super) const R_AX_PLE_INI_STATUS: u32 = 0x9100;
/// `WDE_MGN_INI_RDY` / `PLE_MGN_INI_RDY` = Q_MGN | BUF_MGN (bits 1, 0).
/// `reg.h:1389/1597`.
pub(super) const DLE_MGN_INI_RDY: u32 = 0b11;
/// `R_BE_HAXI_INIT_CFG1`. `reg.h:6283`.
pub(super) const R_BE_HAXI_INIT_CFG1: u32 = 0xB000;
/// `B_BE_DMA_MODE_MASK` = GENMASK(10, 8). `reg.h:6293`.
pub(super) const B_BE_DMA_MODE_MASK: u32 = 0b111 << 8;
/// `S_BE_DMA_MOD_PCIE_NO_DATA_CPU`. `reg.h:6294`.
pub(super) const S_BE_DMA_MOD_PCIE_NO_DATA_CPU: u32 = 0;
/// `R_BE_HAXI_DMA_STOP1`. `reg.h:6305`.
pub(super) const R_BE_HAXI_DMA_STOP1: u32 = 0xB010;
/// `B_BE_TX_STOP1_MASK` = `STOP_CH0..CH14`. `reg.h:6322`.
pub(super) const B_BE_TX_STOP1_MASK: u32 = 0x7fff;
/// `R_BE_HCI_FC_CTRL`. `reg.h:6372`.
pub(super) const R_BE_HCI_FC_CTRL: u32 = 0xB700;
/// `B_BE_HCI_FC_CH12_EN`. `reg.h:6380`.
pub(super) const B_BE_HCI_FC_CH12_EN: u32 = 1 << 3;
/// `B_BE_HCI_FC_EN`. `reg.h:6382`.
pub(super) const B_BE_HCI_FC_EN: u32 = 1 << 0;
/// `R_BE_CH_PAGE_CTRL`. `reg.h:6384`.
pub(super) const R_BE_CH_PAGE_CTRL: u32 = 0xB704;
/// `B_BE_PREC_PAGE_CH12_V1_MASK` = GENMASK(21, 16). `reg.h:6385`.
pub(super) const B_BE_PREC_PAGE_CH12_V1_MASK: u32 = 0x3f << 16;
/// `R_BE_CMAC_FUNC_EN` (band 0; band 1 is `_C1` 0x14000). `reg.h:6555`.
pub(super) const R_BE_CMAC_FUNC_EN: u32 = 0x10000;
/// `B_BE_CMAC_FUNC_EN_SET`: CRPRT(31) EN(30) TXEN(29) RXEN(28)
/// TXTIME(8) RESP_PKTCTL(7) SIGB(6) PHYINTF(5) CMAC_DMA(4) PTCLTOP(3)
/// SCHEDULER(2) TMAC(1) RMAC(0). `reg.h:6581`.
pub(super) const B_BE_CMAC_FUNC_EN_SET: u32 = 0xf000_01ff;
/// `R_BE_CK_EN` (band 0; band 1 is `_C1` 0x14004). `reg.h:6587`.
pub(super) const R_BE_CK_EN: u32 = 0x10004;
/// `B_BE_CK_EN_SET`: CMAC_CKEN(30) TXTIME(8) RESP_PKTCTL(7) SIGB(6)
/// PHYINTF(5) CMAC_DMA(4) PTCLTOP(3) SCHEDULER(2) TMAC(1) RMAC(0).
/// `reg.h:6601`.
pub(super) const B_BE_CK_EN_SET: u32 = 0x4000_01ff;
/// `RTW89_MAC_BE_BAND_REG_OFFSET` (`rtw89_mac_reg_by_idx` band 1).
/// `mac.h`.
pub(super) const BAND_REG_OFFSET: u32 = 0x4000;
/// `RTW89_BBMCU_ADDR_OFFSET`. `phy.h:10`.
pub(super) const BBMCU_ADDR_OFFSET: u32 = 0x30000;

/// `SECURE_BOOT_MALLOC_INFO` value for 8922A NORMAL/WOWLAN suits
/// (`fw.c rtw89_fw_download_suit`).
pub(super) const SECURE_BOOT_MALLOC_INFO_8922A: u32 = 0x2024_8000;

// ── Poll bounds (1 us interval, Linux timeouts) ─────────────────────

/// `rtw89_fwdl_check_path_ready_be`: 1 us × 1 000 000.
pub(super) const PATH_READY_ATTEMPTS: u32 = 1_000_000;
/// `rtw89_fw_check_rdy`: 1 us × `FWDL_WAIT_CNT` (400 000).
pub(super) const FW_READY_ATTEMPTS: u32 = 400_000;
/// `chk_dle_rdy_be`: 1 us × 2000.
pub(super) const DLE_READY_ATTEMPTS: u32 = 2000;

// ── Firmware download status (`fw.h:9`, `mac_be.c:709`) ─────────────

/// `enum rtw89_fw_dl_status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FwdlStatus {
    Initial,
    Ongoing,
    ChecksumFail,
    SecurityFail,
    CvNotMatch,
    Reserved,
    WcpuFwdlReady,
    WcpuFwInitReady,
    /// A raw status beyond the Linux map (returned unmapped there).
    Raw(u8),
}

/// `fwdl_status_map` (`mac_be.c:709`): raw `WCPU_FWDL_STATUS` → status.
fn map_status(raw: u8) -> FwdlStatus {
    match raw {
        0 => FwdlStatus::Initial,
        1 => FwdlStatus::Ongoing,
        2 => FwdlStatus::WcpuFwdlReady,
        3 => FwdlStatus::WcpuFwInitReady,
        4 => FwdlStatus::ChecksumFail,
        5 | 6 => FwdlStatus::SecurityFail,
        7 => FwdlStatus::CvNotMatch,
        8 | 9 => FwdlStatus::Reserved,
        other => FwdlStatus::Raw(other),
    }
}

/// `enum rtw89_fwdl_check_type` (`core.h:4880`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Each variant is the `RTW89_FWDL_CHECK_*_DONE` of that CPU.
pub(super) enum CheckType {
    FreeRtos,
    Wcpu,
    Dcpu,
    Bb0,
    Bb1,
}

// ── DLE / HFC tables (`mac.c:1719..1897`, `rtw8922a.c`) ─────────────

/// `struct rtw89_dle_size` (`core.h:4118`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DleSize {
    pub(super) pge_size: u16,
    pub(super) lnk_pge_num: u16,
    pub(super) unlnk_pge_num: u16,
    pub(super) srt_ofst: u32,
}

/// `struct rtw89_wde_quota` (`core.h:4126`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct WdeQuota {
    pub(super) hif: u16,
    pub(super) wcpu: u16,
    pub(super) pkt_in: u16,
    pub(super) cpu_io: u16,
}

/// `struct rtw89_ple_quota` (`core.h:4134`), the 13 fields 8922A
/// programs (`snrpt` is 8922D-only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PleQuota(pub(super) [u16; 13]);

/// `struct rtw89_dle_mem` subset used by the BE DLE init.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DleMem {
    pub(super) wde_size: DleSize,
    pub(super) ple_size: DleSize,
    pub(super) wde_min_qt: WdeQuota,
    pub(super) wde_max_qt: WdeQuota,
    pub(super) ple_min_qt: PleQuota,
    pub(super) ple_max_qt: PleQuota,
    /// `rsvd0_size->size` + `rsvd1_size->size`.
    pub(super) rsvd_size: u32,
}

/// `rtw8922a_dle_mem_pcie[RTW89_QTA_DLFW]` (`rtw8922a.c:191`):
/// `wde_size3_v1` {64, 0, 3328, 0}, `ple_size3_v1` {128, 2928, 0, 212992},
/// `wde_qt4` (all 0) min/max, `ple_qt9` {0,0,32,256,0,0,0,0,0,0,1,0,0}
/// min/max, `rsvd0_size0` {212992, 0} + `rsvd1_size0` {587776, 2048}.
pub(super) const DLE_DLFW_8922A_PCIE: DleMem = DleMem {
    wde_size: DleSize {
        pge_size: 64,
        lnk_pge_num: 0,
        unlnk_pge_num: 3328,
        srt_ofst: 0,
    },
    ple_size: DleSize {
        pge_size: 128,
        lnk_pge_num: 2928,
        unlnk_pge_num: 0,
        srt_ofst: 212_992,
    },
    wde_min_qt: WdeQuota {
        hif: 0,
        wcpu: 0,
        pkt_in: 0,
        cpu_io: 0,
    },
    wde_max_qt: WdeQuota {
        hif: 0,
        wcpu: 0,
        pkt_in: 0,
        cpu_io: 0,
    },
    ple_min_qt: PleQuota([0, 0, 32, 256, 0, 0, 0, 0, 0, 0, 1, 0, 0]),
    ple_max_qt: PleQuota([0, 0, 32, 256, 0, 0, 0, 0, 0, 0, 1, 0, 0]),
    rsvd_size: 2048,
};

/// `rtw89_mac_dle_init` passes the ext (SCC) table's `wde_min_qt->wcpu`
/// for DLFW: `rtw8922a_dle_mem_pcie[RTW89_QTA_SCC].wde_min_qt` is
/// `wde_qt0_v1` {3302, 6, 0, 20} (`mac.c:1792`).
pub(super) const EXT_WDE_MIN_QT_WCPU_8922A: u16 = 6;

/// `rtw8922a_chip_info.fifo_size` (`rtw8922a.c:3162`); DLFW subtracts
/// no SCC reserve (`dle_expected_used_size`).
pub(super) const FIFO_SIZE_8922A: u32 = 589_824;

/// `rtw89_mac_size.hfc_prec_cfg_c2.h2c_prec` (`mac.c:1719`), the DLFW
/// precost of `rtw8922a_hfc_param_ini_pcie[RTW89_QTA_DLFW]`.
pub(super) const HFC_DLFW_H2C_PREC: u16 = 256;

/// `rtw8922a.c:1747 bb_mcu0_init_reg` (PHY_0 BB-MCU CR init).
pub(super) const BB_MCU0_INIT_REG: [(u32, u32); 10] = [
    (0x6990, 0x0000_0000),
    (0x6994, 0x0000_0000),
    (0x6998, 0x0000_0000),
    (0x6820, 0xFFFF_FFFE),
    (0x6800, 0xC000_0FFE),
    (0x6808, 0x7654_3210),
    (0x6814, 0xBFBF_B000),
    (0x6818, 0x0478_C009),
    (0x6800, 0xC000_0FFF),
    (0x6820, 0xFFFF_FFFF),
];

// ── Helpers ─────────────────────────────────────────────────────────

fn set32(regs: &mut impl Regs, addr: u32, bits: u32) {
    let v = regs.read32(addr);
    regs.write32(addr, v | bits);
}

fn clr32(regs: &mut impl Regs, addr: u32, bits: u32) {
    let v = regs.read32(addr);
    regs.write32(addr, v & !bits);
}

/// `rtw89_write32_mask`: `value` is the field value (unshifted).
fn mask32(regs: &mut impl Regs, addr: u32, mask: u32, value: u32) {
    let shift = mask.trailing_zeros();
    let v = regs.read32(addr);
    regs.write32(addr, (v & !mask) | ((value << shift) & mask));
}

fn poll(regs: &mut impl Regs, addr: u32, mask: u32, attempts: u32) -> Result<(), Error> {
    for _ in 0..attempts {
        if regs.read32(addr) & mask == mask {
            return Ok(());
        }
    }
    Err(Error::PollTimeout)
}

// ── 1. `rtw89_mac_preinit` tail ─────────────────────────────────────

/// `cmac_pwr_en_be(mac_idx, true)` (`mac_be.c:804`). The caller's
/// power-on cleared `RTW89_FLAG_CMACx_PWR` (`mac.c:1574`), so the
/// enable always runs once per power-on.
fn cmac_pwr_en(regs: &mut impl Regs, band1: bool) {
    let (all, iso, fen) = if band1 {
        (
            B_BE_R_SYM_WLCMAC1_ALL_EN,
            B_BE_R_SYM_ISO_CMAC12PP,
            B_BE_CMAC1_FEN,
        )
    } else {
        (
            B_BE_R_SYM_WLCMAC0_ALL_EN,
            B_BE_R_SYM_ISO_CMAC02PP,
            B_BE_CMAC0_FEN,
        )
    };
    set32(regs, R_BE_AFE_CTRL1, all);
    clr32(regs, R_BE_FEN_RST_ENABLE, iso);
    set32(regs, R_BE_FEN_RST_ENABLE, fen);
}

/// `cmac_func_en_be(mac_idx, true)` (`mac_be.c:860`).
fn cmac_func_en(regs: &mut impl Regs, band1: bool) {
    let off = if band1 { BAND_REG_OFFSET } else { 0 };
    set32(regs, R_BE_CK_EN + off, B_BE_CK_EN_SET);
    set32(regs, R_BE_CMAC_FUNC_EN + off, B_BE_CMAC_FUNC_EN_SET);
}

/// `mac_func_en_be` on 8922A (`mac_be.c:934`): DMAC and CMAC-share
/// enables are 8922A no-ops (the power-on already set them); each band
/// whose `CMACx_FEN` is set gets its CMAC power + function enable.
pub(super) fn mac_func_en(regs: &mut impl Regs) {
    let fen = regs.read32(R_BE_FEN_RST_ENABLE);
    if fen & B_BE_CMAC0_FEN != 0 {
        cmac_pwr_en(regs, false);
        cmac_func_en(regs, false);
    }
    if fen & B_BE_CMAC1_FEN != 0 {
        cmac_pwr_en(regs, true);
        cmac_func_en(regs, true);
    }
}

// ── 2. `rtw89_mac_partial_init` up to the hci hook ──────────────────

/// `rtw8922a_bb_preinit(RTW89_PHY_0)` (`rtw8922a.c:1802`), including
/// `rtw8922a_bbmcu_cr_init` through `rtw89_bbmcu_write32`.
pub(super) fn bb_preinit_phy0(regs: &mut impl Regs) {
    mask32(regs, R_BE_DMAC_SYS_CR32B, B_BE_DMAC_BB_PHY0_MASK, 0x7FF9);
    mask32(regs, R_BE_FEN_RST_ENABLE, B_BE_FEN_BB_IP_RSTN, 0);
    mask32(regs, R_BE_FEN_RST_ENABLE, B_BE_FEN_BBPLAT_RSTB, 0);
    mask32(regs, R_BE_FEN_RST_ENABLE, B_BE_FEN_BB_IP_RSTN, 1);
    // PHY_0: `rdy = 0`.
    mask32(regs, R_BE_FEN_RST_ENABLE, B_BE_BOOT_RDY0, 0);
    mask32(regs, R_BE_MEM_PWR_CTRL, B_BE_MEM_BBMCU0_DS_V1, 0);
    // fsleep(1)
    let _ = responsive_spin_until(|| false, Deadline::after_us(1));
    for (addr, data) in BB_MCU0_INIT_REG {
        // PHY_0: no 0x20000 band offset.
        regs.write32(addr + BBMCU_ADDR_OFFSET, data);
    }
}

/// `rtw89_mac_dmac_func_pre_en_be` (`mac_be.c:375`), PCIe arm.
fn dmac_func_pre_en(regs: &mut impl Regs) {
    let v = regs.read32(R_BE_HAXI_INIT_CFG1);
    let v = (v & !B_BE_DMA_MODE_MASK) | (S_BE_DMA_MOD_PCIE_NO_DATA_CPU << 8);
    regs.write32(R_BE_HAXI_INIT_CFG1, v);
    clr32(regs, R_BE_HAXI_DMA_STOP1, B_BE_TX_STOP1_MASK);
    set32(regs, R_BE_DMAC_TABLE_CTRL, B_BE_DMAC_ADDR_MODE);
}

/// `dle_used_size` (`mac.c:2041`).
pub(super) fn dle_used_size(cfg: &DleMem) -> u32 {
    let w = &cfg.wde_size;
    let p = &cfg.ple_size;
    u32::from(w.pge_size) * (u32::from(w.lnk_pge_num) + u32::from(w.unlnk_pge_num))
        + u32::from(p.pge_size) * (u32::from(p.lnk_pge_num) + u32::from(p.unlnk_pge_num))
        + cfg.rsvd_size
}

/// `dle_mix_cfg_be` (`mac_be.c:239`). Only the page sizes the DLFW
/// table uses (WDE 64, PLE 128) and the BE-valid alternatives are
/// accepted; WDE 256 / PLE 64 are refused like Linux.
fn dle_mix_cfg(regs: &mut impl Regs, cfg: &DleMem) -> Result<(), Error> {
    const DLE_BOUND_UNIT: u32 = 8 * 1024;
    let wde_sel = match cfg.wde_size.pge_size {
        128 => 1,
        256 => return Err(Error::DleSize),
        _ => 0,
    };
    let mut v = regs.read32(R_BE_WDE_PKTBUF_CFG);
    v = (v & !0b11) | wde_sel;
    v = (v & !(0x7f << 8)) | (((cfg.wde_size.srt_ofst / DLE_BOUND_UNIT) << 8) & (0x7f << 8));
    v = (v & !(0x1fff << 16)) | ((u32::from(cfg.wde_size.lnk_pge_num) << 16) & (0x1fff << 16));
    regs.write32(R_BE_WDE_PKTBUF_CFG, v);

    let ple_sel = match cfg.ple_size.pge_size {
        128 => 1,
        256 => 2,
        _ => return Err(Error::DleSize),
    };
    let mut v = regs.read32(R_BE_PLE_PKTBUF_CFG);
    v = (v & !0b11) | ple_sel;
    v = (v & !(0x7f << 8)) | (((cfg.ple_size.srt_ofst / DLE_BOUND_UNIT) << 8) & (0x7f << 8));
    v = (v & !(0x1fff << 16)) | ((u32::from(cfg.ple_size.lnk_pge_num) << 16) & (0x1fff << 16));
    regs.write32(R_BE_PLE_PKTBUF_CFG, v);
    Ok(())
}

/// `SET_QUOTA_VAL`: MIN in [11:0], MAX in [27:16] of QTA`idx`_CFG.
fn quota(regs: &mut impl Regs, base: u32, idx: u32, min: u16, max: u16) {
    let v = (u32::from(min) & 0xfff) | ((u32::from(max) & 0xfff) << 16);
    regs.write32(base + 4 * idx, v);
}

/// `wde_quota_cfg_be` + `ple_quota_cfg_be` (`mac_be.c:326/343`).
fn dle_quota_cfg(regs: &mut impl Regs, cfg: &DleMem, ext_wde_min_qt_wcpu: u16) {
    let (min, max) = (&cfg.wde_min_qt, &cfg.wde_max_qt);
    let min_wcpu = ext_wde_min_qt_wcpu;
    let max_wcpu = core::cmp::max(max.wcpu, min_wcpu);
    quota(regs, R_BE_WDE_QTA0_CFG, 0, min.hif, max.hif);
    quota(regs, R_BE_WDE_QTA0_CFG, 1, min_wcpu, max_wcpu);
    quota(regs, R_BE_WDE_QTA0_CFG, 2, 0, 0);
    quota(regs, R_BE_WDE_QTA0_CFG, 3, min.pkt_in, max.pkt_in);
    quota(regs, R_BE_WDE_QTA0_CFG, 4, min.cpu_io, max.cpu_io);
    // 8922A returns before the 8922D-only `snrpt` (QTA13).
    for idx in 0..13 {
        quota(
            regs,
            R_BE_PLE_QTA0_CFG,
            idx as u32,
            cfg.ple_min_qt.0[idx],
            cfg.ple_max_qt.0[idx],
        );
    }
}

/// `rtw89_mac_dle_init(RTW89_QTA_DLFW, RTW89_QTA_SCC)` (`mac.c:2274`)
/// with the BE ops. The `check_mac_en` gate is the caller's power-on
/// (`RTW89_FLAG_DMAC_FUNC`, `mac.c:1564`).
pub(super) fn dle_init_dlfw(regs: &mut impl Regs) -> Result<(), Error> {
    let cfg = &DLE_DLFW_8922A_PCIE;
    if dle_used_size(cfg) != FIFO_SIZE_8922A {
        clr32(regs, R_BE_DMAC_FUNC_EN, B_BE_DLE_WDE_EN | B_BE_DLE_PLE_EN);
        return Err(Error::DleSize);
    }
    clr32(regs, R_BE_DMAC_FUNC_EN, B_BE_DLE_WDE_EN | B_BE_DLE_PLE_EN);
    // `dle_clk_en_be(true)` — 8922A only.
    set32(
        regs,
        R_BE_DMAC_CLK_EN,
        B_BE_DLE_WDE_CLK_EN | B_BE_DLE_PLE_CLK_EN,
    );
    if let Err(e) = dle_mix_cfg(regs, cfg) {
        clr32(regs, R_BE_DMAC_FUNC_EN, B_BE_DLE_WDE_EN | B_BE_DLE_PLE_EN);
        return Err(e);
    }
    dle_quota_cfg(regs, cfg, EXT_WDE_MIN_QT_WCPU_8922A);
    set32(regs, R_BE_DMAC_FUNC_EN, B_BE_DLE_WDE_EN | B_BE_DLE_PLE_EN);
    poll(
        regs,
        R_AX_WDE_INI_STATUS,
        DLE_MGN_INI_RDY,
        DLE_READY_ATTEMPTS,
    )?;
    poll(
        regs,
        R_AX_PLE_INI_STATUS,
        DLE_MGN_INI_RDY,
        DLE_READY_ATTEMPTS,
    )
}

/// `hfc_func_en_be(en, h2c_en)` (`mac_be.c:202`).
fn hfc_func_en(regs: &mut impl Regs, en: bool, h2c_en: bool) {
    let mut v = regs.read32(R_BE_HCI_FC_CTRL);
    v = if en {
        v | B_BE_HCI_FC_EN
    } else {
        v & !B_BE_HCI_FC_EN
    };
    v = if h2c_en {
        v | B_BE_HCI_FC_CH12_EN
    } else {
        v & !B_BE_HCI_FC_CH12_EN
    };
    regs.write32(R_BE_HCI_FC_CTRL, v);
}

/// `rtw89_mac_hfc_init(rtwdev, true, false, true)` for DLFW
/// (`mac.c:1194`): reset the param to the DLFW entry, disable, then the
/// `!en && h2c_en` short path — `hfc_h2c_cfg_be` (a plain write of
/// `CH_PAGE_CTRL` holding only the CH12 precost) and
/// `hfc_func_en_be(false, true)`.
///
/// `u32_encode_bits(256, GENMASK(21, 16))` keeps only the low 6 bits of
/// the 256-page precost, so Linux writes 0 here; the masking is kept
/// literally rather than "fixed".
pub(super) fn hfc_init_dlfw(regs: &mut impl Regs) {
    hfc_func_en(regs, false, false);
    let prec = (u32::from(HFC_DLFW_H2C_PREC) << 16) & B_BE_PREC_PAGE_CH12_V1_MASK;
    regs.write32(R_BE_CH_PAGE_CTRL, prec);
    hfc_func_en(regs, false, true);
}

/// `rtw89_mac_partial_init` up to (not including) the hci
/// `mac_pre_init` hook, for 8922A over PCIe (`include_bb` true).
pub(super) fn partial_init(regs: &mut impl Regs) -> Result<(), Error> {
    // rtw89_mac_ctrl_hci_dma_trx(true)
    set32(
        regs,
        R_BE_HCI_FUNC_EN,
        B_BE_HCI_TXDMA_EN | B_BE_HCI_RXDMA_EN,
    );
    bb_preinit_phy0(regs);
    // rtw89_mac_dmac_pre_init
    set32(
        regs,
        R_BE_HCI_FUNC_EN,
        B_BE_HCI_TXDMA_EN | B_BE_HCI_RXDMA_EN,
    );
    dmac_func_pre_en(regs);
    dle_init_dlfw(regs)?;
    hfc_init_dlfw(regs);
    Ok(())
}

// ── 3./4. FWDL preconfig and WCPU control ───────────────────────────

/// `rtw89_mac_fwdl_preconfig_be` (`mac_be.c:625`).
pub(super) fn fwdl_preconfig(regs: &mut impl Regs) {
    clr32(regs, R_BE_FW_AUTO_CAL_DELAY, B_BE_WCPU_FW_DELAY_COUNT_VALID);
    mask32(
        regs,
        R_BE_FW_AUTO_CAL_DELAY,
        B_BE_WCPU_FW_DELAY_COUNT_MASK,
        0,
    );
}

/// `rtw89_mac_disable_cpu_be` (`mac_be.c:603`), 8922A arm.
pub(super) fn disable_cpu(regs: &mut impl Regs) {
    clr32(regs, R_BE_PLATFORM_ENABLE, B_BE_WCPU_EN);
    set32(regs, R_BE_PLATFORM_ENABLE, B_BE_HOLD_AFTER_RESET);
    set32(regs, R_BE_PLATFORM_ENABLE, B_BE_WCPU_EN);
    let v = regs.read32(R_BE_WCPU_FW_CTRL) & B_BE_RUN_ENV_MASK;
    regs.write32(R_BE_WCPU_FW_CTRL, v);
    set32(regs, R_BE_DCPU_PLATFORM_ENABLE, B_BE_DCPU_PLATFORM_EN);
    regs.write32(R_BE_UDM0, 0);
    regs.write32(R_BE_HALT_C2H, 0);
    regs.write32(R_BE_UDM2, 0);
}

/// Non-empty AON L2 debug registers Linux only warns about before boot
/// (`wcpu_on`): (`HALT_C2H`, `UDM1`, `UDM2`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct BootResidue {
    pub(super) halt_c2h: u32,
    pub(super) udm1: u32,
    pub(super) udm2: u32,
}

/// `rtw89_mac_fwdl_enable_wcpu_be(boot_reason, dlfw = true,
/// include_bb)` (`mac_be.c:700`): `set_cpu_en` then `wcpu_on`. With
/// `dlfw` true `wcpu_on` does not wait for FreeRTOS (the download
/// does). Returns the pre-boot residue Linux logs.
pub(super) fn enable_wcpu(regs: &mut impl Regs, boot_reason: u8, include_bb: bool) -> BootResidue {
    let mut set = B_BE_WLANCPU_FWDL_EN;
    if include_bb {
        set |= B_BE_BBMCU0_FWDL_EN;
    }
    set32(regs, R_BE_WCPU_FW_CTRL, set);

    let residue = BootResidue {
        halt_c2h: regs.read32(R_BE_HALT_C2H),
        udm1: regs.read32(R_BE_UDM1),
        udm2: regs.read32(R_BE_UDM2),
    };
    regs.write32(R_BE_UDM1, 0);
    regs.write32(R_BE_UDM2, 0);
    regs.write32(R_BE_BOOT_DBG, 0);
    regs.write32(R_BE_HALT_H2C, 0);
    regs.write32(R_BE_HALT_C2H, 0);
    regs.write32(R_BE_HALT_H2C_CTRL, 0);
    regs.write32(R_BE_HALT_C2H_CTRL, 0);
    let _ = regs.read32(R_BE_HISR0);
    regs.write32(R_BE_HISR0, B_BE_HALT_C2H_INT);

    set32(regs, R_BE_SYS_CLK_CTRL, B_BE_CPU_CLK_EN);
    clr32(
        regs,
        R_BE_SYS_CFG5,
        B_BE_WDT_WAKE_PCIE_EN | B_BE_WDT_WAKE_USB_EN,
    );
    clr32(
        regs,
        R_BE_WCPU_FW_CTRL,
        B_BE_WDT_PLT_RST_EN | B_BE_WCPU_ROM_CUT_GET,
    );
    regs.write32(R_BE_SECURE_BOOT_MALLOC_INFO, 0);
    clr32(regs, R_BE_GPIO_MUXCFG, B_BE_BOOT_MODE);
    // 8922A does not set B_BE_HOST_EXIST.
    let reason = regs.read16(R_BE_BOOT_REASON);
    regs.write16(
        R_BE_BOOT_REASON,
        (reason & !B_BE_BOOT_REASON_MASK) | (u16::from(boot_reason) & B_BE_BOOT_REASON_MASK),
    );
    clr32(regs, R_BE_PLATFORM_ENABLE, B_BE_WCPU_EN);
    clr32(regs, R_BE_PLATFORM_ENABLE, B_BE_HOLD_AFTER_RESET);
    set32(regs, R_BE_PLATFORM_ENABLE, B_BE_WCPU_EN);
    residue
}

// ── 5. Status reads ─────────────────────────────────────────────────

/// `rtw89_fwdl_check_path_ready_be(h2c_or_fwdl)` (`mac_be.c:757`).
/// `h2c` true waits for `H2C_PATH_RDY`, false for `DLFW_PATH_RDY`.
pub(super) fn check_path_ready(regs: &mut impl Regs, h2c: bool) -> Result<(), Error> {
    let bit = if h2c {
        B_BE_H2C_PATH_RDY
    } else {
        B_BE_DLFW_PATH_RDY
    };
    for _ in 0..PATH_READY_ATTEMPTS {
        if regs.read32(R_BE_WCPU_FW_CTRL) & bit != 0 {
            return Ok(());
        }
    }
    Err(Error::PollTimeout)
}

/// `fwdl_get_status_be(type)` (`mac_be.c:722`).
pub(super) fn fwdl_status(regs: &mut impl Regs, check: CheckType) -> FwdlStatus {
    let v = regs.read32(R_BE_WCPU_FW_CTRL);
    let pass = match check {
        CheckType::Wcpu => v & B_BE_WLANCPU_FWDL_EN == 0,
        CheckType::Dcpu => v & B_BE_DATACPU_FWDL_EN == 0,
        CheckType::Bb0 => v & B_BE_BBMCU0_FWDL_EN == 0,
        CheckType::Bb1 => v & B_BE_BBMCU1_FWDL_EN == 0,
        CheckType::FreeRtos => false,
    };
    if pass {
        return FwdlStatus::WcpuFwInitReady;
    }
    map_status(((v & B_BE_WCPU_FWDL_STATUS_MASK) >> 26) as u8)
}

/// `rtw89_fw_check_rdy(type)` (`fw.c:106`): poll until
/// `WCPU_FW_INIT_RDY`; on timeout the last status decides the error
/// (checksum / security / CV mismatch are terminal `-EINVAL`, any other
/// is `-EBUSY`, reported here as a timeout).
pub(super) fn check_ready(regs: &mut impl Regs, check: CheckType) -> Result<(), Error> {
    let mut last = FwdlStatus::Initial;
    for _ in 0..FW_READY_ATTEMPTS {
        last = fwdl_status(regs, check);
        if last == FwdlStatus::WcpuFwInitReady {
            return Ok(());
        }
    }
    match last {
        FwdlStatus::ChecksumFail | FwdlStatus::SecurityFail | FwdlStatus::CvNotMatch => {
            Err(Error::Firmware(last))
        }
        _ => Err(Error::PollTimeout),
    }
}

// ── 6. Download sequence (`fw.c:1701..2025`) ────────────────────────

/// CH12 transport for the download (`rtw89_h2c_tx`, `core.c:1336`)
/// together with the register port the sequence polls. Production
/// supplies `pci::FwdlPort` (the `Rtw89Device` CH12 submit +
/// BAR2); fixtures record the packets.
pub(super) trait Port: Regs {
    /// Submit one FWHDR_DL command (`fwdl = false`, RPKT type H2C)
    /// or one raw section packet (`fwdl = true`, RPKT type FWDL).
    /// A refusal (no free CH12 TXBD, DMA allocation) aborts this
    /// attempt, as `rtw89_h2c_tx` failing does in Linux.
    fn submit(&mut self, buf: &[u8], fwdl: bool) -> Result<(), Error>;
}

/// One firmware suit to download: the fuse-selected plan and the
/// ready check its download ends with
/// (`rtw89_fw_get_fwdl_chk_type_from_suit`, `fw.c:1846`).
pub(super) struct Suit<'a> {
    pub(super) plan: &'a DownloadPlan,
    pub(super) check: CheckType,
    /// 8922A writes `SECURE_BOOT_MALLOC_INFO` before NORMAL and
    /// WOWLAN suits only (`rtw89_fw_download_suit`, `fw.c:1943`).
    pub(super) malloc_info: bool,
}

/// `rtw89_fw_download` retry count (`fw.c:2014`).
pub(super) const DOWNLOAD_RETRIES: usize = 5;

/// `rtw89_fw_download_suit` (`fw.c:1928`) on BE: the IDMEM
/// share-mode write is AX-only (`mac_be.c:3301` sets the hook
/// NULL), so it is skipped; then the 8922A malloc-info word, H2C
/// path ready, the FWHDR_DL header (`rtw89_fw_download_hdr`), DLFW
/// path ready, the HALT H2C/C2H control clear, every section in
/// `part_size` packets (`__rtw89_fw_download_main`), and the
/// suit's ready check (BE only, `rtw89_fw_download_main`).
pub(super) fn download_suit(port: &mut impl Port, suit: &Suit<'_>) -> Result<(), Error> {
    if suit.malloc_info {
        port.write32(R_BE_SECURE_BOOT_MALLOC_INFO, SECURE_BOOT_MALLOC_INFO_8922A);
    }
    check_path_ready(port, true)?;
    // `rtw89_h2c_pkt_set_hdr_fwdl` stamps `fw.h2c_seq`, which
    // `__rtw89_fw_download` resets to 0 and nothing advances
    // before the download completes.
    let header = suit.plan.header_command(0).map_err(Error::Plan)?;
    port.submit(&header, false)?;
    check_path_ready(port, false)?;
    port.write32(R_BE_HALT_H2C_CTRL, 0);
    port.write32(R_BE_HALT_C2H_CTRL, 0);
    let part = suit.plan.part_size();
    for section in 0..suit.plan.section_count() {
        let len = suit
            .plan
            .section_len(section)
            .ok_or(Error::Plan(download_plan::Error::SectionGeometry))?;
        let mut offset = 0;
        while offset < len {
            let chunk = suit.plan.chunk(section, offset).map_err(Error::Plan)?;
            port.submit(&chunk, true)?;
            offset += part;
        }
    }
    check_ready(port, suit.check)
}

/// One `__rtw89_fw_download(type, include_bb)` attempt
/// (`fw.c:1966`): CPU disable, WCPU enable in download mode
/// (`boot_reason` 0, BB-MCU download enabled when BB suits
/// follow), the normal suit, each BB-MCU suit, then `mdelay(5)`
/// and the FreeRTOS ready check.
pub(super) fn download_once(
    port: &mut impl Port,
    normal: &Suit<'_>,
    bbmcu: &[Suit<'_>],
) -> Result<BootResidue, Error> {
    disable_cpu(port);
    let residue = enable_wcpu(port, 0, !bbmcu.is_empty());
    download_suit(port, normal)?;
    for suit in bbmcu {
        download_suit(port, suit)?;
    }
    let _ = responsive_spin_until(|| false, Deadline::after_ms(5));
    check_ready(port, CheckType::FreeRtos)?;
    Ok(residue)
}

/// `rtw89_fw_download` (`fw.c:2008`): up to five attempts of
/// [`download_once`]; the last attempt's error is returned.
pub(super) fn download(
    port: &mut impl Port,
    normal: &Suit<'_>,
    bbmcu: &[Suit<'_>],
) -> Result<BootResidue, Error> {
    let mut last = Error::PollTimeout;
    for _ in 0..DOWNLOAD_RETRIES {
        match download_once(port, normal, bbmcu) {
            Ok(residue) => return Ok(residue),
            Err(error) => last = error,
        }
    }
    Err(last)
}
