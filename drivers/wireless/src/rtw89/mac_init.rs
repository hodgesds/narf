//! RTW89 MAC init sequence — Stage-5.
//!
//! Mirrors the structure of Linux's `rtw89_mac_init` (`mac.c:4248`) —
//! the entry point that runs after PCIe is up, power-on has completed,
//! and firmware has been downloaded. The Linux sequence is:
//!
//! ```text
//! rtw89_mac_init(rtwdev):
//!   rtw89_mac_partial_init(rtwdev, include_bb)        // 4198
//!     rtw89_mac_ctrl_hci_dma_trx(rtwdev, true)        // 4202
//!     rtw89_chip_bb_preinit(rtwdev)                    // 4210 (if BB-MCU)
//!     rtw89_mac_dmac_pre_init(rtwdev)                  // 4213
//!       chip->mac_def->hci_func_en(rtwdev)             // 4154
//!       chip->mac_def->dmac_func_pre_en(rtwdev)        // 4155
//!       rtw89_mac_dle_init(rtwdev, RTW89_QTA_DLFW, …)  // 4157
//!       rtw89_mac_hfc_init(rtwdev, true, false, true)  // 4163
//!     hci->ops->mac_pre_init(rtwdev)                   // 4217
//!     rtw89_fw_download(rtwdev, RTW89_FW_NORMAL, …)    // 4223
//!   rtw89_chip_enable_bb_rf(rtwdev)                    // 4259
//!     ↳ rtw89_mac_enable_bb_rf (mac.c:4172):
//!       write8_set(R_AX_SYS_FUNC_EN, FEN_BBRSTB | FEN_BB_GLB_RSTN)
//!       write32_set(R_AX_WLRF_CTRL,  WLRF1_CTRL_7|WLRF1_CTRL_1|WLRF_CTRL_7|WLRF_CTRL_1)
//!       write8_set(R_AX_PHYREG_SET, PHYREG_SET_ALL_CYCLE)
//!   chip->mac_def->sys_init(rtwdev)                    // 4263
//!   chip->mac_def->trx_init(rtwdev)                    // 4267
//!   rtw89_mac_feat_init(rtwdev)                        // 4271
//!   hci->ops->mac_post_init(rtwdev)                    // 4275
//!   rtw89_fw_send_all_early_h2c(rtwdev)                // 4281
//!   rtw89_fw_h2c_set_ofld_cfg(rtwdev)                  // 4282
//! ```
//!
//! At this stage we wire up the **register-side** sequence — the BB/RF
//! enable writes + the WLRF init nibble + the PHYREG_SET pulse, plus
//! the "HCI DMA TRX" enable bit toggle. The Linux DLE/HFC init are
//! quota-table-driven; Stage 5 keeps a placeholder for the quota mode
//! that the live FW-downloader (next stage) wires through.
//!
//! ## References (all GPL-2.0)
//!
//! - Linux `rtw89/mac.c:4248` — `rtw89_mac_init`.
//! - Linux `rtw89/mac.c:4172` — `rtw89_mac_enable_bb_rf`.
//! - Linux `rtw89/mac.c:4198` — `rtw89_mac_partial_init`.
//! - Linux `rtw89/mac.c:4149` — `rtw89_mac_dmac_pre_init`.
//! - Linux `rtw89/mac.c:2218` — `rtw89_mac_dle_init` (DMAC FIFO carve).
//! - Linux `rtw89/reg.h:307..312` — `R_AX_WLRF_CTRL` + `B_AX_WLRF_*`.
//! - Linux `rtw89/reg.h:506..507` — `R_AX_PHYREG_SET` + ALL_CYCLE.

#![allow(dead_code)]

use narf_bus::MmioRegion;

use super::mac::{MacError, B_AX_FEN_BBRSTB, B_AX_FEN_BB_GLB_RSTN, R_AX_SYS_FUNC_EN};

/// `R_AX_WLRF_CTRL` — WL-RF control register. `reg.h:307`.
pub const R_AX_WLRF_CTRL: u64 = 0x02F0;
/// `B_AX_WLRF_CTRL_1` — bit 1. `reg.h:312`.
pub const B_AX_WLRF_CTRL_1: u32 = 1 << 1;
/// `B_AX_WLRF_CTRL_7` — bit 7. `reg.h:311`.
pub const B_AX_WLRF_CTRL_7: u32 = 1 << 7;
/// `B_AX_WLRF1_CTRL_1` — bit 9 (`B_AX_WLRF1_CTRL_1`). `reg.h:310`.
pub const B_AX_WLRF1_CTRL_1: u32 = 1 << 9;
/// `B_AX_WLRF1_CTRL_7` — bit 15 (`B_AX_WLRF1_CTRL_7`). `reg.h:309`.
pub const B_AX_WLRF1_CTRL_7: u32 = 1 << 15;

/// Composite mask written by `rtw89_mac_enable_bb_rf` (`mac.c:4176`).
pub const WLRF_ENABLE_MASK: u32 =
    B_AX_WLRF1_CTRL_7 | B_AX_WLRF1_CTRL_1 | B_AX_WLRF_CTRL_7 | B_AX_WLRF_CTRL_1;

/// `R_AX_PHYREG_SET` — PHY register strobe. `reg.h:506`.
pub const R_AX_PHYREG_SET: u64 = 0x8040;
/// `PHYREG_SET_ALL_CYCLE` — value 0x8. `reg.h:507`.
pub const PHYREG_SET_ALL_CYCLE: u8 = 0x8;

/// `R_AX_HCI_FUNC_EN` — HCI function enable. `reg.h:230`.
pub const R_AX_HCI_FUNC_EN: u64 = 0x0028;
/// `B_AX_HCI_TXDMA_EN` — bit 0. Linux `B_AX_HCI_TXDMA_EN`.
pub const B_AX_HCI_TXDMA_EN: u32 = 1 << 0;
/// `B_AX_HCI_RXDMA_EN` — bit 1. Linux `B_AX_HCI_RXDMA_EN`.
pub const B_AX_HCI_RXDMA_EN: u32 = 1 << 1;

/// `R_AX_DMAC_FUNC_EN` — DMAC function enable. `reg.h:247`.
pub const R_AX_DMAC_FUNC_EN: u64 = 0x0210;
/// `B_AX_DMAC_FUNC_EN` — top-level DMAC enable (bit 30).
pub const B_AX_DMAC_FUNC_EN: u32 = 1 << 30;
/// `B_AX_DMAC_CRPRT` — bit 31, "crprt".
pub const B_AX_DMAC_CRPRT: u32 = 1 << 31;
/// `B_AX_DLE_DMAC_EN` — bit 28.
pub const B_AX_DLE_DMAC_EN: u32 = 1 << 28;
/// `B_AX_DMAC_PKT_IN_EN` — bit 27.
pub const B_AX_DMAC_PKT_IN_EN: u32 = 1 << 27;
/// `B_AX_DISPATCHER_EN` — bit 26.
pub const B_AX_DISPATCHER_EN: u32 = 1 << 26;
/// `B_AX_DMAC_TBL_EN` — bit 25.
pub const B_AX_DMAC_TBL_EN: u32 = 1 << 25;
/// `B_AX_DMAC_MIX_EN` — bit 24.
pub const B_AX_DMAC_MIX_EN: u32 = 1 << 24;

/// Composite enable used by `dmac_func_pre_en_ax`. Subset of the bits
/// Linux sets in `chip->mac_def->dmac_func_pre_en` (`mac.c:4155`); the
/// Stage-5 mask covers the dispatcher + DLE + TBL + MIX + top-level
/// enables — enough for the FW downloader to push its first H2C.
pub const DMAC_PRE_EN_MASK: u32 = B_AX_DMAC_FUNC_EN
    | B_AX_DMAC_CRPRT
    | B_AX_DLE_DMAC_EN
    | B_AX_DMAC_PKT_IN_EN
    | B_AX_DISPATCHER_EN
    | B_AX_DMAC_TBL_EN
    | B_AX_DMAC_MIX_EN;

/// `R_AX_CMAC_FUNC_EN` — Channel-MAC function enable. `reg.h:265`.
pub const R_AX_CMAC_FUNC_EN: u64 = 0xC000;
/// `B_AX_CMAC_EN` — bit 30, top-level CMAC enable.
pub const B_AX_CMAC_EN: u32 = 1 << 30;
/// `B_AX_CMAC_FUNC_EN` — same value as `B_AX_CMAC_EN`, alias for the
/// "enable everything in CMAC 0" group write.
pub const B_AX_CMAC_FUNC_EN: u32 = B_AX_CMAC_EN;
/// `B_AX_PHYINTF_EN` — bit 29, PHY interface enable.
pub const B_AX_PHYINTF_EN: u32 = 1 << 29;
/// `B_AX_CMAC_DMA_EN` — bit 28.
pub const B_AX_CMAC_DMA_EN: u32 = 1 << 28;
/// `B_AX_PTCLTOP_EN` — bit 27.
pub const B_AX_PTCLTOP_EN: u32 = 1 << 27;
/// `B_AX_SCHEDULER_EN` — bit 26.
pub const B_AX_SCHEDULER_EN: u32 = 1 << 26;
/// `B_AX_TMAC_EN` — bit 25. TX-MAC.
pub const B_AX_TMAC_EN: u32 = 1 << 25;
/// `B_AX_RMAC_EN` — bit 24. RX-MAC.
pub const B_AX_RMAC_EN: u32 = 1 << 24;

/// Composite CMAC enable; covers TX+RX MAC plus the scheduler / PHY
/// interface / DMA bits the firmware needs alive before sending data.
pub const CMAC_ENABLE_MASK: u32 = B_AX_CMAC_EN
    | B_AX_PHYINTF_EN
    | B_AX_CMAC_DMA_EN
    | B_AX_PTCLTOP_EN
    | B_AX_SCHEDULER_EN
    | B_AX_TMAC_EN
    | B_AX_RMAC_EN;

/// DLE-quota mode hint. `enum rtw89_qta_mode` in `mac.h`. We track
/// just the two values the FW-DL path ever uses.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QtaMode {
    /// `RTW89_QTA_DLFW` — quota table for the "download firmware"
    /// phase. The DLE carve here ensures the H2C FIFO can sink the
    /// upload before the actual MAC quota takes effect.
    DlFw,
    /// `RTW89_QTA_SCC` — single-channel-concurrent (normal operation).
    Scc,
}

// ── Stage-5 entry: bring up MAC registers ──────────────────────────

/// Step 1 of `rtw89_mac_init`: enable the HCI-side TXDMA+RXDMA.
/// Mirrors `rtw89_mac_ctrl_hci_dma_trx(true)` (`mac.c:4202`).
///
/// # Safety
/// Caller owns the BAR2 MMIO + has run baseline_power_on.
pub unsafe fn ctrl_hci_dma_trx(mmio: &MmioRegion, enable: bool) {
    // SAFETY: identity-mapped MMIO.
    unsafe {
        let cur = mmio.read32(R_AX_HCI_FUNC_EN);
        let new = if enable {
            cur | B_AX_HCI_TXDMA_EN | B_AX_HCI_RXDMA_EN
        } else {
            cur & !(B_AX_HCI_TXDMA_EN | B_AX_HCI_RXDMA_EN)
        };
        mmio.write32(R_AX_HCI_FUNC_EN, new);
    }
}

/// Step 2: pre-enable the DMAC functional block. Mirrors the AX
/// chip's `dmac_func_pre_en` (per-chip op pointer used at `mac.c:4155`).
/// This is the all-ones top-of-DMAC group write that brings the
/// dispatcher / DLE / tables / mixed engine online so the H2C FIFO
/// can accept the firmware upload.
///
/// # Safety
/// As above.
pub unsafe fn dmac_func_pre_en(mmio: &MmioRegion) {
    // SAFETY: identity-mapped MMIO.
    unsafe {
        let cur = mmio.read32(R_AX_DMAC_FUNC_EN);
        mmio.write32(R_AX_DMAC_FUNC_EN, cur | DMAC_PRE_EN_MASK);
    }
}

/// Step 3: bring CMAC online. Mirrors the per-chip `sys_init` op
/// (`mac.c:4263`) on the CMAC-side enables. The DMAC-side equivalents
/// live in `dmac_func_pre_en`.
///
/// # Safety
/// Same.
pub unsafe fn cmac_func_en(mmio: &MmioRegion) {
    // SAFETY: identity-mapped MMIO.
    unsafe {
        let cur = mmio.read32(R_AX_CMAC_FUNC_EN);
        mmio.write32(R_AX_CMAC_FUNC_EN, cur | CMAC_ENABLE_MASK);
    }
}

/// Step 4: assert BB reset + global-reset deassert. The first half of
/// `rtw89_mac_enable_bb_rf` (`mac.c:4172`).
///
/// # Safety
/// Same.
pub unsafe fn enable_bb_reset(mmio: &MmioRegion) {
    // SAFETY: identity-mapped MMIO.
    unsafe {
        let cur = mmio.read16(R_AX_SYS_FUNC_EN);
        mmio.write16(
            R_AX_SYS_FUNC_EN,
            cur | B_AX_FEN_BBRSTB | B_AX_FEN_BB_GLB_RSTN,
        );
    }
}

/// Step 5: the WLRF init nibble. Second half of `rtw89_mac_enable_bb_rf`.
///
/// # Safety
/// Same.
pub unsafe fn enable_wlrf(mmio: &MmioRegion) {
    // SAFETY: identity-mapped MMIO.
    unsafe {
        let cur = mmio.read32(R_AX_WLRF_CTRL);
        mmio.write32(R_AX_WLRF_CTRL, cur | WLRF_ENABLE_MASK);
    }
}

/// Step 6: the PHYREG strobe (`PHYREG_SET_ALL_CYCLE`). Final write of
/// `rtw89_mac_enable_bb_rf`.
///
/// # Safety
/// Same.
pub unsafe fn enable_phyreg(mmio: &MmioRegion) {
    // SAFETY: identity-mapped MMIO.
    unsafe {
        let cur = mmio.read8(R_AX_PHYREG_SET);
        mmio.write8(R_AX_PHYREG_SET, cur | PHYREG_SET_ALL_CYCLE);
    }
}

/// Composed "enable BB+RF" — runs steps 4..6 in order. Mirrors
/// `rtw89_mac_enable_bb_rf` exactly.
///
/// # Safety
/// Caller owns BAR2 + power-on has run.
pub unsafe fn enable_bb_rf(mmio: &MmioRegion) -> Result<(), MacError> {
    // SAFETY: forwarded.
    unsafe {
        enable_bb_reset(mmio);
        enable_wlrf(mmio);
        enable_phyreg(mmio);
    }
    Ok(())
}

/// Full Stage-5 MAC-init scaffold. Runs the register-side enables in
/// the same order as `rtw89_mac_init`:
///
/// 1. HCI DMA TRX on (`ctrl_hci_dma_trx(true)`)
/// 2. DMAC pre-enable (`dmac_func_pre_en`)
/// 3. CMAC enable (`cmac_func_en`)
/// 4. BB/RF enable (`enable_bb_rf`)
///
/// DLE/HFC init + firmware download are run by separate stages once
/// the FW-downloader can push bytes through the H2C DMA channel.
///
/// # Safety
/// Caller owns BAR2 + has run `mac::baseline_power_on`.
pub unsafe fn mac_init_register_side(mmio: &MmioRegion) -> Result<(), MacError> {
    // SAFETY: forwarded.
    unsafe {
        ctrl_hci_dma_trx(mmio, true);
        dmac_func_pre_en(mmio);
        cmac_func_en(mmio);
        enable_bb_rf(mmio)?;
    }
    Ok(())
}
