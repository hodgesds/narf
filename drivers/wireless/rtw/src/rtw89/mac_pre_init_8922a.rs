// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8922A MAC pre-init owner: the full `pwr_on_func` tail, the
//! MAC-reset power-state machine, the BE XTAL-SI accessor, and the
//! chip-version (`cid`) retention.
//!
//! This closes the hole `mac.rs` `baseline_power_on_be` and
//! `prepared_8922a.rs` step 2 both name: the head of Linux
//! `rtw8922a_pwr_on_func` (`rtw8922a.c:475..~502`) is transcribed
//! there; the tail (`rtw8922a.c:503..634`) is transcribed here as
//! [`power_on_tail`], and the reset state machine Linux runs
//! *before* it on every power-on (`rtw89_mac_power_switch`,
//! `mac.c:1548` → `rtw89_mac_reset_pwr_state_be`, `mac_be.c:474`)
//! is [`reset_pwr_state`]. Together they are the mac_pre_init
//! owner: `pci::bring_up` runs reset → tail after the head and
//! before the factory (EFUSE) read, matching Linux's
//! power-switch-then-efuse order.
//!
//! Polls are bounded attempt counts derived from Linux's
//! `read_poll_timeout` interval/timeout pairs (the `dma_8922a`
//! pattern), not wall-clock deadlines, so fixtures can pre-seed
//! the status bits and pass instantly. The one exception is the
//! `mdelay(1)` in the CV-conditional ISO sequence, kept as a
//! 1 ms spin (`responsive_spin_until(|| false, ...)`).
//!
//! ## References (all GPL-2.0, torvalds/linux @ cbbddb6)
//!
//! - `rtw8922a.c:475..634` — `rtw8922a_pwr_on_func`.
//! - `mac_be.c:413..471` — `rtw89_mac_write_xtal_si_be` /
//!   `rtw89_mac_read_xtal_si_be`.
//! - `mac_be.c:474..602` — `rtw89_mac_reset_pwr_state_be`.
//! - `core.c:7126..7168` — `rtw89_read_chip_ver` (`hal->cid`,
//!   `hal->acv`, `hal->aid`).
//! - `pci.c:4386..4400` — `rtw89_pci_cpl_timeout_cfg`
//!   (8922D + CID7090 keeps the completion timeout enabled).
//! - `reg.h` — every `R_BE_*` / `B_BE_*` value below, cited
//!   per constant. `mac.h:1680..1730` — the `XTAL_SI_*` offsets.
//! - `core.h:183..185` — `enum rtw89_core_chip_cid`.
//! - `core.h:201..209` — `enum rtw89_cv` (`CHIP_CAV` = 0).

use narf_scheduler::responsive_spin_until;
use narf_time::Deadline;

// `R_BE_SYS_PW_CTRL` / `R_BE_WLLPS_CTRL` live in `mac.rs` as u64
// BAR offsets; this module's port takes u32 addresses (the
// `dma_be::Regs` convention), so the three values it needs are
// restated here in u32 form with the same Linux citations.

/// `R_BE_SYS_PW_CTRL`. `reg.h:3830`.
pub(super) const R_BE_SYS_PW_CTRL: u32 = 0x0004;
/// `B_BE_EN_WLON` — bit 16. `reg.h:3846`.
pub(super) const B_BE_EN_WLON: u32 = 1 << 16;
/// `B_BE_APFM_SWLPS` — bit 10. `reg.h:3852`.
pub(super) const B_BE_APFM_SWLPS: u32 = 1 << 10;
/// `R_BE_WLLPS_CTRL`. `reg.h:4172`.
pub(super) const R_BE_WLLPS_CTRL: u32 = 0x0090;

/// Register port for the BE SYS/PMU block. Production wiring
/// supplies BAR-backed reads/writes (`MmioRegs`); fixtures supply
/// a map. Mirrors the `dma_be::Regs` split, extended with byte
/// accesses: the tail writes two byte registers
/// (`R_BE_ANAPAR_POW_MAC`, `R_BE_PLATFORM_ENABLE`).
pub(super) trait Regs {
    /// 8-bit MMIO read.
    fn read8(&mut self, address: u32) -> u8;
    /// 32-bit MMIO read.
    fn read32(&mut self, address: u32) -> u32;
    /// 8-bit MMIO write.
    fn write8(&mut self, address: u32, value: u8);
    /// 32-bit MMIO write.
    fn write32(&mut self, address: u32, value: u32);
}

/// Failures. Every variant is a refusal; a refused call leaves
/// the registers it already wrote behind (Linux behaves the same
/// — a failed power-on aborts the probe), so the caller must not
/// retry blindly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    /// A bounded poll exhausted its attempts (Linux
    /// `read_poll_timeout` returned `-ETIMEDOUT`).
    PollTimeout,
}

// ── Tail registers / bits (`reg.h`) ─────────────────────────────────

/// `R_BE_AFE_ON_CTRL1`. `reg.h:4647`.
pub(super) const R_BE_AFE_ON_CTRL1: u32 = 0x0244;
/// `B_BE_REG_CK_MON_CK960M_EN` — bit 28. `reg.h:4649`.
pub(super) const B_BE_REG_CK_MON_CK960M_EN: u32 = 1 << 28;
/// `R_BE_ANAPAR_POW_MAC`. `reg.h:3907`.
pub(super) const R_BE_ANAPAR_POW_MAC: u32 = 0x0016;
/// `B_BE_POW_PC_LDO_PORT0` — bit 2. `reg.h:3909`.
pub(super) const B_BE_POW_PC_LDO_PORT0: u8 = 1 << 2;
/// `B_BE_POW_PC_LDO_PORT1` — bit 3. `reg.h:3908`.
pub(super) const B_BE_POW_PC_LDO_PORT1: u8 = 1 << 3;
/// `R_BE_FEN_RST_ENABLE`. `reg.h:4137`.
pub(super) const R_BE_FEN_RST_ENABLE: u32 = 0x0084;
/// `B_BE_R_SYM_ISO_ADDA_P02PP` — bit 20. `reg.h:4145`.
pub(super) const B_BE_R_SYM_ISO_ADDA_P02PP: u32 = 1 << 20;
/// `B_BE_R_SYM_ISO_ADDA_P12PP` — bit 21. `reg.h:4144`.
pub(super) const B_BE_R_SYM_ISO_ADDA_P12PP: u32 = 1 << 21;
/// `B_BE_FEN_BB_IP_RSTN` — bit 1. `reg.h:4156`.
pub(super) const B_BE_FEN_BB_IP_RSTN: u32 = 1 << 1;
/// `B_BE_FEN_BBPLAT_RSTB` — bit 0. `reg.h:4157`.
pub(super) const B_BE_FEN_BBPLAT_RSTB: u32 = 1 << 0;
/// `R_BE_PLATFORM_ENABLE` — top-level enable. `reg.h:4159`
/// (same offset as `mac.rs`).
pub(super) const R_BE_PLATFORM_ENABLE: u32 = 0x0088;
/// `B_BE_PLATFORM_EN` — bit 0. `reg.h:4170`.
pub(super) const B_BE_PLATFORM_EN: u8 = 1 << 0;
/// `R_BE_HCI_OPT_CTRL`. `reg.h:4084`.
pub(super) const R_BE_HCI_OPT_CTRL: u32 = 0x0074;
/// `B_BE_HAXIDMA_IO_EN` — bit 24. `reg.h:4089`.
pub(super) const B_BE_HAXIDMA_IO_EN: u32 = 1 << 24;
/// `B_BE_HAXIDMA_IO_ST` — bit 27. `reg.h:4087`.
pub(super) const B_BE_HAXIDMA_IO_ST: u32 = 1 << 27;
/// `B_BE_HAXIDMA_BACKUP_RESTORE_ST` — bit 26. `reg.h:4088`.
pub(super) const B_BE_HAXIDMA_BACKUP_RESTORE_ST: u32 = 1 << 26;
/// `B_BE_HCI_WLAN_IO_EN` — bit 28. `reg.h:4086`.
pub(super) const B_BE_HCI_WLAN_IO_EN: u32 = 1 << 28;
/// `B_BE_HCI_WLAN_IO_ST` — bit 31. `reg.h:4085`.
pub(super) const B_BE_HCI_WLAN_IO_ST: u32 = 1 << 31;
/// `R_BE_SYS_SDIO_CTRL`. `reg.h:4057`.
pub(super) const R_BE_SYS_SDIO_CTRL: u32 = 0x0070;
/// `B_BE_PCIE_FORCE_IBX_EN` — bit 12. `reg.h:4070`.
pub(super) const B_BE_PCIE_FORCE_IBX_EN: u32 = 1 << 12;
/// `R_BE_SYS_ADIE_PAD_PWR_CTRL`. `reg.h:3913`.
pub(super) const R_BE_SYS_ADIE_PAD_PWR_CTRL: u32 = 0x0018;
/// `B_BE_SYM_PADPDN_WL_RFC1_1P3` — bit 6. `reg.h:3914`.
pub(super) const B_BE_SYM_PADPDN_WL_RFC1_1P3: u32 = 1 << 6;
/// `B_BE_SYM_PADPDN_WL_RFC0_1P3` — bit 5. `reg.h:3915`.
pub(super) const B_BE_SYM_PADPDN_WL_RFC0_1P3: u32 = 1 << 5;
/// `R_BE_PMC_DBG_CTRL2`. `reg.h:4267`.
pub(super) const R_BE_PMC_DBG_CTRL2: u32 = 0x00CC;
/// `B_BE_SYSON_DIS_PMCR_BE_WRMSK` — bit 2. `reg.h:4277`.
pub(super) const B_BE_SYSON_DIS_PMCR_BE_WRMSK: u32 = 1 << 2;
/// `R_BE_SYS_ISO_CTRL`. `reg.h:3813`.
pub(super) const R_BE_SYS_ISO_CTRL: u32 = 0x0000;
/// `B_BE_ISO_EB2CORE` — bit 8. `reg.h:3821`.
pub(super) const B_BE_ISO_EB2CORE: u32 = 1 << 8;
/// `B_BE_PWC_EV2EF_B` — bit 15. `reg.h:3814`.
pub(super) const B_BE_PWC_EV2EF_B: u32 = 1 << 15;
/// `B_BE_PWC_EV2EF_S` — bit 14. `reg.h:3815`.
pub(super) const B_BE_PWC_EV2EF_S: u32 = 1 << 14;
/// `R_BE_DMAC_FUNC_EN`. `reg.h:4893`.
pub(super) const R_BE_DMAC_FUNC_EN: u32 = 0x8400;
/// `B_BE_MAC_FUNC_EN` — bit 30. `reg.h:4895`.
pub(super) const B_BE_MAC_FUNC_EN: u32 = 1 << 30;
/// `B_BE_DMAC_FUNC_EN` — bit 29. `reg.h:4896`.
pub(super) const B_BE_DMAC_FUNC_EN: u32 = 1 << 29;
/// `B_BE_MPDU_PROC_EN` — bit 28. `reg.h:4897`.
pub(super) const B_BE_MPDU_PROC_EN: u32 = 1 << 28;
/// `B_BE_WD_RLS_EN` — bit 27. `reg.h:4898`.
pub(super) const B_BE_WD_RLS_EN: u32 = 1 << 27;
/// `B_BE_DLE_WDE_EN` — bit 26. `reg.h:4899`.
pub(super) const B_BE_DLE_WDE_EN: u32 = 1 << 26;
/// `B_BE_TXPKT_CTRL_EN` — bit 25. `reg.h:4900`.
pub(super) const B_BE_TXPKT_CTRL_EN: u32 = 1 << 25;
/// `B_BE_STA_SCH_EN` — bit 24. `reg.h:4901`.
pub(super) const B_BE_STA_SCH_EN: u32 = 1 << 24;
/// `B_BE_DLE_PLE_EN` — bit 23. `reg.h:4902`.
pub(super) const B_BE_DLE_PLE_EN: u32 = 1 << 23;
/// `B_BE_PKT_BUF_EN` — bit 22. `reg.h:4903`.
pub(super) const B_BE_PKT_BUF_EN: u32 = 1 << 22;
/// `B_BE_DMAC_TBL_EN` — bit 21. `reg.h:4904`.
pub(super) const B_BE_DMAC_TBL_EN: u32 = 1 << 21;
/// `B_BE_PKT_IN_EN` — bit 20. `reg.h:4905`.
pub(super) const B_BE_PKT_IN_EN: u32 = 1 << 20;
/// `B_BE_DLE_CPUIO_EN` — bit 19. `reg.h:4906`.
pub(super) const B_BE_DLE_CPUIO_EN: u32 = 1 << 19;
/// `B_BE_DISPATCHER_EN` — bit 18. `reg.h:4907`.
pub(super) const B_BE_DISPATCHER_EN: u32 = 1 << 18;
/// `B_BE_BBRPT_EN` — bit 17. `reg.h:4908`.
pub(super) const B_BE_BBRPT_EN: u32 = 1 << 17;
/// `B_BE_MAC_SEC_EN` — bit 16. `reg.h:4909`.
pub(super) const B_BE_MAC_SEC_EN: u32 = 1 << 16;
/// `B_BE_H_AXIDMA_EN` — bit 14. `reg.h:4911`.
pub(super) const B_BE_H_AXIDMA_EN: u32 = 1 << 14;
/// `B_BE_DMAC_MLO_EN` — bit 11. `reg.h:4912`.
pub(super) const B_BE_DMAC_MLO_EN: u32 = 1 << 11;
/// `B_BE_PLRLS_EN` — bit 10. `reg.h:4913`.
pub(super) const B_BE_PLRLS_EN: u32 = 1 << 10;
/// `B_BE_P_AXIDMA_EN` — bit 9. `reg.h:4914`.
pub(super) const B_BE_P_AXIDMA_EN: u32 = 1 << 9;
/// `B_BE_DLE_DATACPUIO_EN` — bit 8. `reg.h:4915`.
pub(super) const B_BE_DLE_DATACPUIO_EN: u32 = 1 << 8;
/// `B_BE_LTR_CTL_EN` — bit 7, PCIe only. `reg.h:4916`.
pub(super) const B_BE_LTR_CTL_EN: u32 = 1 << 7;
/// `R_BE_CMAC_SHARE_FUNC_EN`. `reg.h:6452`.
pub(super) const R_BE_CMAC_SHARE_FUNC_EN: u32 = 0x0E000;
/// `B_BE_CMAC_SHARE_EN` — bit 30. `reg.h:6454`.
pub(super) const B_BE_CMAC_SHARE_EN: u32 = 1 << 30;
/// `B_BE_RESPBA_EN` — bit 2. `reg.h:6458`.
pub(super) const B_BE_RESPBA_EN: u32 = 1 << 2;
/// `B_BE_ADDRSRCH_EN` — bit 1. `reg.h:6459`.
pub(super) const B_BE_ADDRSRCH_EN: u32 = 1 << 1;
/// `B_BE_BTCOEX_EN` — bit 0. `reg.h:6460`.
pub(super) const B_BE_BTCOEX_EN: u32 = 1 << 0;
/// `R_BE_CMAC_FUNC_EN`. `reg.h:6574`.
pub(super) const R_BE_CMAC_FUNC_EN: u32 = 0x10000;
/// `B_BE_CMAC_EN` — bit 30. `reg.h:6577`.
pub(super) const B_BE_CMAC_EN: u32 = 1 << 30;
/// `B_BE_CMAC_TXEN` — bit 29. `reg.h:6578`.
pub(super) const B_BE_CMAC_TXEN: u32 = 1 << 29;
/// `B_BE_CMAC_RXEN` — bit 28. `reg.h:6579`.
pub(super) const B_BE_CMAC_RXEN: u32 = 1 << 28;
/// `B_BE_TXTIME_EN` — bit 8. `reg.h:6591`.
pub(super) const B_BE_TXTIME_EN: u32 = 1 << 8;
/// `B_BE_RESP_PKTCTL_EN` — bit 7. `reg.h:6592`.
pub(super) const B_BE_RESP_PKTCTL_EN: u32 = 1 << 7;
/// `B_BE_SIGB_EN` — bit 6. `reg.h:6593`.
pub(super) const B_BE_SIGB_EN: u32 = 1 << 6;
/// `B_BE_PHYINTF_EN` — bit 5. `reg.h:6594`.
pub(super) const B_BE_PHYINTF_EN: u32 = 1 << 5;
/// `B_BE_CMAC_DMA_EN` — bit 4. `reg.h:6595`.
pub(super) const B_BE_CMAC_DMA_EN: u32 = 1 << 4;
/// `B_BE_PTCLTOP_EN` — bit 3. `reg.h:6596`.
pub(super) const B_BE_PTCLTOP_EN: u32 = 1 << 3;
/// `B_BE_SCHEDULER_EN` — bit 2. `reg.h:6597`.
pub(super) const B_BE_SCHEDULER_EN: u32 = 1 << 2;
/// `B_BE_TMAC_EN` — bit 1. `reg.h:6598`.
pub(super) const B_BE_TMAC_EN: u32 = 1 << 1;
/// `B_BE_RMAC_EN` — bit 0. `reg.h:6599`.
pub(super) const B_BE_RMAC_EN: u32 = 1 << 0;

// ── Reset registers / bits (`reg.h`, `mac_be.c`) ────────────────────

/// `R_BE_SYSON_FSM_MON`. `reg.h:4217`.
pub(super) const R_BE_SYSON_FSM_MON: u32 = 0x00A0;
/// `WLAN_FSM_MASK` — 0xFFFFFF. `reg.h:4228`.
pub(super) const WLAN_FSM_MASK: u32 = 0xFFFFFF;
/// `WLAN_FSM_SET` — 0x4000000. `reg.h:4229`.
pub(super) const WLAN_FSM_SET: u32 = 0x4000000;
/// `WLAN_FSM_STATE_MASK` — 0x1FF. `reg.h:4230`.
pub(super) const WLAN_FSM_STATE_MASK: u32 = 0x1FF;
/// `WLAN_FSM_IDLE` — 0. `reg.h:4231`.
pub(super) const WLAN_FSM_IDLE: u32 = 0;
/// `R_BE_IC_PWR_STATE`. `reg.h:4707`.
pub(super) const R_BE_IC_PWR_STATE: u32 = 0x03F0;
/// `B_BE_WLMAC_PWR_STE_MASK` — `GENMASK(9, 8)`. `reg.h:4711`.
pub(super) const B_BE_WLMAC_PWR_STE_MASK: u32 = 0x300;
/// `B_BE_WLMAC_PWR_STE` field shift (low bit of the mask).
pub(super) const B_BE_WLMAC_PWR_STE_SHIFT: u32 = 8;
/// `MAC_AX_MAC_OFF` — 0. `reg.h:332`.
pub(super) const MAC_AX_MAC_OFF: u32 = 0;
/// `MAC_AX_MAC_ON` — 1. `reg.h:333`.
pub(super) const MAC_AX_MAC_ON: u32 = 1;
/// `MAC_AX_MAC_LPS` — 2. `reg.h:334`.
pub(super) const MAC_AX_MAC_LPS: u32 = 2;
/// `B_BE_APFM_OFFMAC` — bit 9. `reg.h:3853`.
pub(super) const B_BE_APFM_OFFMAC: u32 = 1 << 9;
/// `B_BE_FORCE_LEAVE_LPS` — bit 3 of `R_BE_WLLPS_CTRL`.
/// `reg.h:4189`.
pub(super) const B_BE_FORCE_LEAVE_LPS: u32 = 1 << 3;

// ── XTAL-SI registers / bits ────────────────────────────────────────

/// `R_BE_WLAN_XTAL_SI_CTRL`. `reg.h:4689`.
pub(super) const R_BE_WLAN_XTAL_SI_CTRL: u32 = 0x0270;
/// `B_BE_WL_XTAL_SI_CMD_POLL` — bit 31. `reg.h:4690`.
pub(super) const B_BE_WL_XTAL_SI_CMD_POLL: u32 = 1 << 31;
/// `B_BE_WL_XTAL_SI_CHIPID_MASK` — `GENMASK(30, 28)`.
/// `reg.h:4691`.
pub(super) const B_BE_WL_XTAL_SI_CHIPID_MASK: u32 = 0x7000_0000;
/// `B_BE_WL_XTAL_SI_MODE_MASK` — `GENMASK(25, 24)`.
/// `reg.h:4692`.
pub(super) const B_BE_WL_XTAL_SI_MODE_MASK: u32 = 0x0300_0000;
/// `B_BE_WL_XTAL_SI_BITMASK_MASK` — `GENMASK(23, 16)`.
/// `reg.h:4693`.
pub(super) const B_BE_WL_XTAL_SI_BITMASK_MASK: u32 = 0x00FF_0000;
/// `B_BE_WL_XTAL_SI_DATA_MASK` — `GENMASK(15, 8)`.
/// `reg.h:4694`.
pub(super) const B_BE_WL_XTAL_SI_DATA_MASK: u32 = 0x0000_FF00;
/// `B_BE_WL_XTAL_SI_ADDR_MASK` — `GENMASK(7, 0)`.
/// `reg.h:4695`.
pub(super) const B_BE_WL_XTAL_SI_ADDR_MASK: u32 = 0x0000_00FF;
/// `XTAL_SI_NORMAL_WRITE` — 0x00. `reg.h:276`.
pub(super) const XTAL_SI_NORMAL_WRITE: u32 = 0x00;
/// `XTAL_SI_NORMAL_READ` — 0x01. `reg.h:277`.
pub(super) const XTAL_SI_NORMAL_READ: u32 = 0x01;

/// `XTAL_SI_PLL` — 0xE0. `mac.h:1724`.
pub(super) const XTAL_SI_PLL: u8 = 0xE0;
/// `XTAL_SI_PLL_1` — 0xE1. `mac.h:1725`.
pub(super) const XTAL_SI_PLL_1: u8 = 0xE1;
/// `XTAL_SI_ANAPAR_WL` — 0x90. `mac.h:1711`.
pub(super) const XTAL_SI_ANAPAR_WL: u8 = 0x90;
/// `XTAL_SI_WL_RFC_S0` — 0x80. `mac.h:1705`.
pub(super) const XTAL_SI_WL_RFC_S0: u8 = 0x80;
/// `XTAL_SI_WL_RFC_S1` — 0x81. `mac.h:1708`.
pub(super) const XTAL_SI_WL_RFC_S1: u8 = 0x81;
/// `XTAL_SI_XREF_RF1` — 0x2D. `mac.h:1694`.
pub(super) const XTAL_SI_XREF_RF1: u8 = 0x2D;
/// `XTAL_SI_XREF_RF2` — 0x2E. `mac.h:1695`.
pub(super) const XTAL_SI_XREF_RF2: u8 = 0x2E;
/// `XTAL_SI_SRAM_CTRL` — 0xA1. `mac.h:1720`.
pub(super) const XTAL_SI_SRAM_CTRL: u8 = 0xA1;
/// `XTAL_SI_SRAM_DIS` — `BIT(1)`. `mac.h:1721`.
pub(super) const XTAL_SI_SRAM_DIS: u8 = 1 << 1;
/// `XTAL_SI_CV` — 0x41. `mac.h:1696`.
pub(super) const XTAL_SI_CV: u8 = 0x41;
/// `XTAL_SI_ACV_MASK` — `GENMASK(3, 0)`. `mac.h:1697`.
pub(super) const XTAL_SI_ACV_MASK: u8 = 0x0F;
/// `XTAL_SI_CHIP_ID_L` — 0xFD. `mac.h:1726`.
pub(super) const XTAL_SI_CHIP_ID_L: u8 = 0xFD;
/// `XTAL_SI_CHIP_ID_H` — 0xFE. `mac.h:1727`.
pub(super) const XTAL_SI_CHIP_ID_H: u8 = 0xFE;

// ── Chip-version registers ──────────────────────────────────────────

/// `R_BE_SYS_CHIPINFO`. `reg.h:4316`.
pub(super) const R_BE_SYS_CHIPINFO: u32 = 0x00FC;
/// `B_BE_HW_ID_MASK` — `GENMASK(7, 0)`. `reg.h:4321`.
pub(super) const B_BE_HW_ID_MASK: u32 = 0xFF;
/// `CHIP_CAV` — 0. `core.h:201` (`enum rtw89_cv`).
pub(super) const CHIP_CAV: u8 = 0;

// ── Poll budgets (attempts = Linux timeout / interval) ──────────────

/// Tail HAXIDMA/WLAN-IO polls: Linux 1 ms interval / 3 s timeout
/// (`rtw8922a.c:488..533`).
pub(super) const TAIL_POLL_ATTEMPTS: u32 = 3000;
/// Reset state-machine polls: Linux 1 ms interval / 2 s timeout
/// (`mac_be.c:484..589`).
pub(super) const RESET_POLL_ATTEMPTS: u32 = 2000;
/// XTAL-SI command polls: Linux 50 us interval / 50 ms timeout
/// (`mac_be.c:427..432`, `458..463`).
pub(super) const XTAL_POLL_ATTEMPTS: u32 = 1000;

// ── Helpers ─────────────────────────────────────────────────────────

/// Extract a contiguous field: Linux `rtw89_read32_mask` returns
/// the field value, not the raw masked word (e.g. `cv` from
/// `R_AX_SYS_CFG1` is 0..15, not 0x0000..0xF000).
const fn field(value: u32, mask: u32) -> u32 {
    (value & mask) >> mask.trailing_zeros()
}

fn set32(regs: &mut impl Regs, addr: u32, bits: u32) {
    let v = regs.read32(addr);
    regs.write32(addr, v | bits);
}

fn clr32(regs: &mut impl Regs, addr: u32, bits: u32) {
    let v = regs.read32(addr);
    regs.write32(addr, v & !bits);
}

fn set8(regs: &mut impl Regs, addr: u32, bits: u8) {
    let v = regs.read8(addr);
    regs.write8(addr, v | bits);
}

fn poll(
    regs: &mut impl Regs,
    addr: u32,
    pred: fn(u32) -> bool,
    attempts: u32,
) -> Result<(), Error> {
    for _ in 0..attempts {
        if pred(regs.read32(addr)) {
            return Ok(());
        }
    }
    Err(Error::PollTimeout)
}

// ── XTAL-SI accessor (`mac_be.c:413..471`) ──────────────────────────

/// BE XTAL-SI write: command word + poll for `CMD_POLL` clear.
/// Mirrors `rtw89_mac_write_xtal_si_be` exactly, including the
/// chip-id field forced to 0. A readback mismatch is NOT a
/// failure here, matching Linux (which only warns on it).
pub(super) fn write_xtal_si(
    regs: &mut impl Regs,
    offset: u8,
    value: u8,
    mask: u8,
) -> Result<(), Error> {
    let cmd = ((offset as u32) & B_BE_WL_XTAL_SI_ADDR_MASK)
        | (((value as u32) << 8) & B_BE_WL_XTAL_SI_DATA_MASK)
        | (((mask as u32) << 16) & B_BE_WL_XTAL_SI_BITMASK_MASK)
        | ((XTAL_SI_NORMAL_WRITE << 24) & B_BE_WL_XTAL_SI_MODE_MASK)
        | B_BE_WL_XTAL_SI_CMD_POLL;
    regs.write32(R_BE_WLAN_XTAL_SI_CTRL, cmd);
    poll(
        regs,
        R_BE_WLAN_XTAL_SI_CTRL,
        |v| v & B_BE_WL_XTAL_SI_CMD_POLL == 0,
        XTAL_POLL_ATTEMPTS,
    )
}

/// BE XTAL-SI read: command word + poll, then the DATA field.
/// Mirrors `rtw89_mac_read_xtal_si_be`.
pub(super) fn read_xtal_si(regs: &mut impl Regs, offset: u8) -> Result<u8, Error> {
    let cmd = ((offset as u32) & B_BE_WL_XTAL_SI_ADDR_MASK)
        | ((XTAL_SI_NORMAL_READ << 24) & B_BE_WL_XTAL_SI_MODE_MASK)
        | B_BE_WL_XTAL_SI_CMD_POLL;
    regs.write32(R_BE_WLAN_XTAL_SI_CTRL, cmd);
    poll(
        regs,
        R_BE_WLAN_XTAL_SI_CTRL,
        |v| v & B_BE_WL_XTAL_SI_CMD_POLL == 0,
        XTAL_POLL_ATTEMPTS,
    )?;
    Ok(field(
        regs.read32(R_BE_WLAN_XTAL_SI_CTRL),
        B_BE_WL_XTAL_SI_DATA_MASK,
    ) as u8)
}

// ── Power-on tail (`rtw8922a.c:503..634`) ────────────────────────────

/// The tail of `rtw8922a_pwr_on_func`, run after the head
/// (`mac::baseline_power_on_be`). `is_pcie` selects the PCIe-only
/// arms (HAXIDMA enable/polls, `PCIE_FORCE_IBX_EN` clear,
/// `LTR_CTL_EN`); `cv` is the chip version from
/// `R_AX_SYS_CFG1` (`mac::read_chip_version`) and gates the
/// CV-conditional ISO sequence (skipped on `CHIP_CAV`).
///
/// Step order is Linux's, with the XTAL-SI writes and ADIE
/// pad-power sets interleaved exactly as in the source.
pub(super) fn power_on_tail(regs: &mut impl Regs, is_pcie: bool, cv: u8) -> Result<(), Error> {
    // AFE clock-monitor off, ANAPAR LDO ports on, ADDA ISO clear.
    clr32(regs, R_BE_AFE_ON_CTRL1, B_BE_REG_CK_MON_CK960M_EN);
    set8(
        regs,
        R_BE_ANAPAR_POW_MAC,
        B_BE_POW_PC_LDO_PORT0 | B_BE_POW_PC_LDO_PORT1,
    );
    clr32(
        regs,
        R_BE_FEN_RST_ENABLE,
        B_BE_R_SYM_ISO_ADDA_P02PP | B_BE_R_SYM_ISO_ADDA_P12PP,
    );
    set8(regs, R_BE_PLATFORM_ENABLE, B_BE_PLATFORM_EN);

    if is_pcie {
        set32(regs, R_BE_HCI_OPT_CTRL, B_BE_HAXIDMA_IO_EN);
        poll(
            regs,
            R_BE_HCI_OPT_CTRL,
            |v| v & B_BE_HAXIDMA_IO_ST != 0,
            TAIL_POLL_ATTEMPTS,
        )?;
        poll(
            regs,
            R_BE_HCI_OPT_CTRL,
            |v| v & B_BE_HAXIDMA_BACKUP_RESTORE_ST == 0,
            TAIL_POLL_ATTEMPTS,
        )?;
    }

    set32(regs, R_BE_HCI_OPT_CTRL, B_BE_HCI_WLAN_IO_EN);
    poll(
        regs,
        R_BE_HCI_OPT_CTRL,
        |v| v & B_BE_HCI_WLAN_IO_ST != 0,
        TAIL_POLL_ATTEMPTS,
    )?;

    if is_pcie {
        clr32(regs, R_BE_SYS_SDIO_CTRL, B_BE_PCIE_FORCE_IBX_EN);
    }

    // XTAL-SI program + ADIE pad power, in Linux order.
    write_xtal_si(regs, XTAL_SI_PLL, 0x02, 0x02)?;
    write_xtal_si(regs, XTAL_SI_PLL, 0x01, 0x01)?;
    set32(
        regs,
        R_BE_SYS_ADIE_PAD_PWR_CTRL,
        B_BE_SYM_PADPDN_WL_RFC1_1P3,
    );
    write_xtal_si(regs, XTAL_SI_ANAPAR_WL, 0x40, 0x40)?;
    set32(
        regs,
        R_BE_SYS_ADIE_PAD_PWR_CTRL,
        B_BE_SYM_PADPDN_WL_RFC0_1P3,
    );
    write_xtal_si(regs, XTAL_SI_ANAPAR_WL, 0x20, 0x20)?;
    write_xtal_si(regs, XTAL_SI_ANAPAR_WL, 0x04, 0x04)?;
    write_xtal_si(regs, XTAL_SI_ANAPAR_WL, 0x08, 0x08)?;
    write_xtal_si(regs, XTAL_SI_ANAPAR_WL, 0x00, 0x10)?;
    write_xtal_si(regs, XTAL_SI_WL_RFC_S0, 0xEB, 0xFF)?;
    write_xtal_si(regs, XTAL_SI_WL_RFC_S1, 0xEB, 0xFF)?;
    write_xtal_si(regs, XTAL_SI_ANAPAR_WL, 0x01, 0x01)?;
    write_xtal_si(regs, XTAL_SI_ANAPAR_WL, 0x02, 0x02)?;
    write_xtal_si(regs, XTAL_SI_ANAPAR_WL, 0x00, 0x80)?;
    write_xtal_si(regs, XTAL_SI_XREF_RF1, 0x00, 0x40)?;
    write_xtal_si(regs, XTAL_SI_XREF_RF2, 0x00, 0x40)?;
    write_xtal_si(regs, XTAL_SI_PLL_1, 0x40, 0x60)?;
    write_xtal_si(regs, XTAL_SI_SRAM_CTRL, 0x00, XTAL_SI_SRAM_DIS)?;

    // CV-conditional ISO sequence (`hal->cv != CHIP_CAV`).
    // The `mdelay(1)` between the EV2EF clears is kept.
    if cv != CHIP_CAV {
        set32(regs, R_BE_PMC_DBG_CTRL2, B_BE_SYSON_DIS_PMCR_BE_WRMSK);
        set32(regs, R_BE_SYS_ISO_CTRL, B_BE_ISO_EB2CORE);
        clr32(regs, R_BE_SYS_ISO_CTRL, B_BE_PWC_EV2EF_B);
        let _ = responsive_spin_until(|| false, Deadline::after_ms(1));
        clr32(regs, R_BE_SYS_ISO_CTRL, B_BE_PWC_EV2EF_S);
        clr32(regs, R_BE_PMC_DBG_CTRL2, B_BE_SYSON_DIS_PMCR_BE_WRMSK);
    }

    // DMAC / CMAC function enables.
    let mut dmac = B_BE_MAC_FUNC_EN
        | B_BE_DMAC_FUNC_EN
        | B_BE_MPDU_PROC_EN
        | B_BE_WD_RLS_EN
        | B_BE_DLE_WDE_EN
        | B_BE_TXPKT_CTRL_EN
        | B_BE_STA_SCH_EN
        | B_BE_DLE_PLE_EN
        | B_BE_PKT_BUF_EN
        | B_BE_DMAC_TBL_EN
        | B_BE_PKT_IN_EN
        | B_BE_DLE_CPUIO_EN
        | B_BE_DISPATCHER_EN
        | B_BE_BBRPT_EN
        | B_BE_MAC_SEC_EN
        | B_BE_H_AXIDMA_EN
        | B_BE_DMAC_MLO_EN
        | B_BE_PLRLS_EN
        | B_BE_P_AXIDMA_EN
        | B_BE_DLE_DATACPUIO_EN;
    if is_pcie {
        dmac |= B_BE_LTR_CTL_EN;
    }
    set32(regs, R_BE_DMAC_FUNC_EN, dmac);
    set32(
        regs,
        R_BE_CMAC_SHARE_FUNC_EN,
        B_BE_CMAC_SHARE_EN | B_BE_RESPBA_EN | B_BE_ADDRSRCH_EN | B_BE_BTCOEX_EN,
    );
    set32(
        regs,
        R_BE_CMAC_FUNC_EN,
        B_BE_CMAC_EN
            | B_BE_CMAC_TXEN
            | B_BE_CMAC_RXEN
            | B_BE_SIGB_EN
            | B_BE_PHYINTF_EN
            | B_BE_CMAC_DMA_EN
            | B_BE_PTCLTOP_EN
            | B_BE_SCHEDULER_EN
            | B_BE_TMAC_EN
            | B_BE_RMAC_EN
            | B_BE_TXTIME_EN
            | B_BE_RESP_PKTCTL_EN,
    );
    set32(
        regs,
        R_BE_FEN_RST_ENABLE,
        B_BE_FEN_BB_IP_RSTN | B_BE_FEN_BBPLAT_RSTB,
    );
    Ok(())
}

// ── MAC-reset power state (`mac_be.c:474..602`) ─────────────────────

/// `rtw89_mac_reset_pwr_state_be`: bring the MAC power state to a
/// known idle before `power_on_tail` runs. Linux runs this first
/// inside `rtw89_mac_power_switch(on=true)` (`mac.c:1548`).
///
/// The SYSON FSM is forced to idle, then the branch follows the
/// current MAC state (`MAC_OFF` / `MAC_ON` / `MAC_LPS` from
/// `R_BE_IC_PWR_STATE`). An unrecognized state falls through with
/// `Ok(())`, matching Linux's `if / else if` chain with no final
/// `else`: the tail re-enables the MAC afterwards either way.
pub(super) fn reset_pwr_state(regs: &mut impl Regs) -> Result<(), Error> {
    let fsm = regs.read32(R_BE_SYSON_FSM_MON);
    regs.write32(R_BE_SYSON_FSM_MON, (fsm & WLAN_FSM_MASK) | WLAN_FSM_SET);
    poll(
        regs,
        R_BE_SYSON_FSM_MON,
        |v| field(v, WLAN_FSM_STATE_MASK) == WLAN_FSM_IDLE,
        RESET_POLL_ATTEMPTS,
    )?;

    let state = field(regs.read32(R_BE_IC_PWR_STATE), B_BE_WLMAC_PWR_STE_MASK);
    if state == MAC_AX_MAC_OFF {
        clr32(regs, R_BE_HCI_OPT_CTRL, B_BE_HAXIDMA_IO_EN);
        poll(
            regs,
            R_BE_HCI_OPT_CTRL,
            |v| v & (B_BE_HAXIDMA_IO_ST | B_BE_HAXIDMA_BACKUP_RESTORE_ST) == 0,
            RESET_POLL_ATTEMPTS,
        )?;
        clr32(regs, R_BE_HCI_OPT_CTRL, B_BE_HCI_WLAN_IO_EN);
        poll(
            regs,
            R_BE_HCI_OPT_CTRL,
            |v| v & B_BE_HCI_WLAN_IO_ST == 0,
            RESET_POLL_ATTEMPTS,
        )?;
        clr32(regs, R_BE_SYS_PW_CTRL, B_BE_EN_WLON);
        clr32(regs, R_BE_SYS_PW_CTRL, B_BE_APFM_SWLPS);
    } else if state == MAC_AX_MAC_ON {
        clr32(regs, R_BE_HCI_OPT_CTRL, B_BE_HAXIDMA_IO_EN);
        poll(
            regs,
            R_BE_HCI_OPT_CTRL,
            |v| v & (B_BE_HAXIDMA_IO_ST | B_BE_HAXIDMA_BACKUP_RESTORE_ST) == 0,
            RESET_POLL_ATTEMPTS,
        )?;
        clr32(regs, R_BE_HCI_OPT_CTRL, B_BE_HCI_WLAN_IO_EN);
        poll(
            regs,
            R_BE_HCI_OPT_CTRL,
            |v| v & B_BE_HCI_WLAN_IO_ST == 0,
            RESET_POLL_ATTEMPTS,
        )?;
        set32(regs, R_BE_SYS_PW_CTRL, B_BE_EN_WLON);
        set32(regs, R_BE_SYS_PW_CTRL, B_BE_APFM_OFFMAC);
        poll(
            regs,
            R_BE_SYS_PW_CTRL,
            |v| field(v, B_BE_APFM_OFFMAC) == MAC_AX_MAC_OFF,
            RESET_POLL_ATTEMPTS,
        )?;
        clr32(regs, R_BE_SYS_PW_CTRL, B_BE_EN_WLON);
        clr32(regs, R_BE_SYS_PW_CTRL, B_BE_APFM_SWLPS);
    } else if state == MAC_AX_MAC_LPS {
        clr32(regs, R_BE_HCI_OPT_CTRL, B_BE_HAXIDMA_IO_EN);
        poll(
            regs,
            R_BE_HCI_OPT_CTRL,
            |v| v & (B_BE_HAXIDMA_IO_ST | B_BE_HAXIDMA_BACKUP_RESTORE_ST) == 0,
            RESET_POLL_ATTEMPTS,
        )?;
        clr32(regs, R_BE_HCI_OPT_CTRL, B_BE_HCI_WLAN_IO_EN);
        poll(
            regs,
            R_BE_HCI_OPT_CTRL,
            |v| v & B_BE_HCI_WLAN_IO_ST == 0,
            RESET_POLL_ATTEMPTS,
        )?;
        set32(regs, R_BE_WLLPS_CTRL, B_BE_FORCE_LEAVE_LPS);
        poll(
            regs,
            R_BE_IC_PWR_STATE,
            |v| field(v, B_BE_WLMAC_PWR_STE_MASK) == MAC_AX_MAC_ON,
            RESET_POLL_ATTEMPTS,
        )?;
        set32(regs, R_BE_SYS_PW_CTRL, B_BE_EN_WLON);
        set32(regs, R_BE_SYS_PW_CTRL, B_BE_APFM_OFFMAC);
        poll(
            regs,
            R_BE_SYS_PW_CTRL,
            |v| field(v, B_BE_APFM_OFFMAC) == MAC_AX_MAC_OFF,
            RESET_POLL_ATTEMPTS,
        )?;
        clr32(regs, R_BE_WLLPS_CTRL, B_BE_FORCE_LEAVE_LPS);
        clr32(regs, R_BE_SYS_PW_CTRL, B_BE_EN_WLON);
        clr32(regs, R_BE_SYS_PW_CTRL, B_BE_APFM_SWLPS);
    }
    Ok(())
}

// ── Chip version / `cid` retention (`core.c:7126..7168`) ─────────────

/// `RTL8922D_CID7025` — 0x74. `core.h:184`.
pub(super) const CID_8922D_7025: u8 = 0x74;
/// `RTL8922D_CID7090` — 0x79. `core.h:185`.
pub(super) const CID_8922D_7090: u8 = 0x79;

/// Core chip id (`hal->cid`, `enum rtw89_core_chip_cid`,
/// `core.h:183..185`). Only the two 8922D values are enumerated
/// in Linux; every other raw byte is retained as `Unknown` rather
/// than forced into a known variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cid {
    /// `RTL8922D_CID7025` (0x74).
    Cid7025,
    /// `RTL8922D_CID7090` (0x79).
    Cid7090,
    /// Any other `R_BE_SYS_CHIPINFO` hardware-id byte.
    Unknown(u8),
}

impl Cid {
    /// Decode a raw `B_BE_HW_ID_MASK` byte.
    pub(super) const fn from_raw(raw: u8) -> Self {
        match raw {
            CID_8922D_7025 => Self::Cid7025,
            CID_8922D_7090 => Self::Cid7090,
            other => Self::Unknown(other),
        }
    }

    /// Raw hardware-id byte.
    pub(super) const fn raw(self) -> u8 {
        match self {
            Self::Cid7025 => CID_8922D_7025,
            Self::Cid7090 => CID_8922D_7090,
            Self::Unknown(raw) => raw,
        }
    }
}

/// Retained BE chip version: Linux `struct rtw89_hal` fields
/// `cv` / `cid` / `acv` / `aid` (`core.h:6497` and neighbors),
/// read by `rtw89_read_chip_ver` and kept for the driver's
/// lifetime (PCI completion-timeout config, MAC init branches).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct HalChipVer {
    /// Chip version from `R_AX_SYS_CFG1` (`mac::read_chip_version`).
    pub(super) cv: u8,
    /// Core chip id from `R_BE_SYS_CHIPINFO`.
    pub(super) cid: Cid,
    /// Analog chip version from `XTAL_SI_CV[3:0]`.
    pub(super) acv: u8,
    /// Analog chip id from `XTAL_SI_CHIP_ID_L/H`.
    pub(super) aid: u16,
}

/// Read the BE chip version, mirroring `rtw89_read_chip_ver`
/// (`core.c:7150..7168`): `cid` from `R_BE_SYS_CHIPINFO`
/// `B_BE_HW_ID_MASK`, `acv` from `XTAL_SI_CV`, `aid` from
/// `XTAL_SI_CHIP_ID_L/H`. `cv` is the caller's already-read
/// `R_AX_SYS_CFG1` value (Linux reads it just above, `core.c:7134`).
/// The XTAL-SI reads fail closed on poll timeout.
pub(super) fn read_chip_ver(regs: &mut impl Regs, cv: u8) -> Result<HalChipVer, Error> {
    let cid = Cid::from_raw(field(regs.read32(R_BE_SYS_CHIPINFO), B_BE_HW_ID_MASK) as u8);
    let acv = read_xtal_si(regs, XTAL_SI_CV)? & XTAL_SI_ACV_MASK;
    let aid_lo = read_xtal_si(regs, XTAL_SI_CHIP_ID_L)? as u16;
    let aid_hi = read_xtal_si(regs, XTAL_SI_CHIP_ID_H)? as u16;
    Ok(HalChipVer {
        cv,
        cid,
        acv,
        aid: aid_lo | (aid_hi << 8),
    })
}

/// Completion-timeout disable for an RTL8922D device
/// (`rtw89_pci_cpl_timeout_cfg`, `pci.c:4392`): the timeout is
/// disabled for every chip *except* 8922D with `CID7090`, where
/// it stays enabled. NARF has no 8922D probe yet, so this
/// answers the `cid` half of Linux's
/// `chip_id == RTL8922D && cid == RTL8922D_CID7090` condition;
/// the caller pairs it with its own chip-id check.
pub(super) const fn completion_timeout_disabled_for_8922d(cid: Cid) -> bool {
    !matches!(cid, Cid::Cid7090)
}
