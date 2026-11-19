// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8922A ("BE" generation) PCI DMA control sequence.
//!
//! Mirrors Linux `rtw89/pci_be.c` (torvalds/linux @ cbbddb6):
//! `rtw89_pci_ctrl_wpdma_pcie_be`, `rtw89_pci_ctrl_trxdma_pcie_be`,
//! `rtw89_pci_clr_idx_all_be`, the `rtw89_pci_poll_*_idle_be` predicates,
//! `rtw89_pci_mode_op_be`, `rtw89_pci_rst_bdram_be`,
//! `rtw89_pci_configure_mit_be`, `rtw89_pci_ctrl_txdma_ch_be`,
//! `rtw89_pci_ctrl_txdma_fw_ch_be`, the DMA halves of
//! `rtw89_pci_ops_mac_pre_init_be` / `rtw89_pci_ops_mac_post_init_be`,
//! and `rtw89_pci_ctrl_dma_all` (`pci.c:2114`) as instantiated for
//! 8922A by `rtw8922ae.c` `rtw8922a_pci_info`.
//!
//! Register/bit definitions: `reg.h` (HAXI block) and `pci.h`
//! (TXBD/RXBD pointer, MIT, append-mode pages). This module is
//! 8922A-only: where Linux branches on `chip_id == RTL8922A`
//! (clear-all-idx mask, RX-append read, WDT timeout-select write),
//! the 8922A arm is taken unconditionally.
//!
//! ## Sequences (Linux order; steps outside this module are named)
//!
//! Pre-init DMA portion (`pci_be.c:493`, after `set_io_rcy_be` and
//! the chip patches, which live elsewhere): `wpdma(false)` →
//! `trxdma(Disable, Disable, Disable)` → `clr_idx_all` →
//! [caller polls TX+RX DMA idle] → `mode_op` → [caller runs
//! `rtw89_pci_ops_reset`, i.e. the MAC reset] → `rst_bdram_set` →
//! [caller polls the bound bit clear] → [caller runs debounce,
//! LDO-low-power, PCIe-setting, SER-setting] → `txdma_ch(false)` →
//! `txdma_fw_ch(true)` → `trxdma(Enable, Enable, Enable)`.
//!
//! Post-init DMA portion (`pci_be.c:631`, after the caller's LTR
//! set): `trxdma(Ignore, Ignore, Enable)` → `wpdma(true)` →
//! `txdma_ch(true)` → `txdma_fw_ch(true)` → `configure_mit`.
//! [`post_init_dma`] implements exactly this tail.
//!
//! LV1-reset DMA portion (`pci_be.c:669,687`): stop =
//! `ctrl_dma_all(false)` → [caller polls IO idle; on failure the
//! caller toggles `mac_ctrl_hci_dma_trx` off/on and re-polls];
//! start = [caller toggles `mac_ctrl_hci_dma_trx` off/on] →
//! `clr_idx_all` → `rst_bdram_set` → [caller polls the bound bit
//! clear] → `ctrl_dma_all(true)`.
//!
//! Poll timing (Linux `read_poll_timeout` arguments, the caller's
//! loop): TX/RX DMA idle 10 us interval / 1000 us timeout;
//! BDRAM-bound 50 us / 500000 us; IO idle 10 us / 1000 us.
//!
//! Deliberate difference from Linux: `ctrl_dma_all` here does NOT
//! write the HAXI master-watchdog timeout-select register. Linux's
//! generic `ctrl_dma_io` path never touches it; only the
//! fine-grained `trxdma` io-enable arm does (see [`trxdma`]).

/// Register port for the BE HAXI/DMA block. Production wiring
/// supplies BAR-backed reads/writes; fixtures supply a map.
pub(super) trait Regs {
    /// 32-bit MMIO read.
    fn read32(&mut self, address: u32) -> u32;
    /// 32-bit MMIO write.
    fn write32(&mut self, address: u32, value: u32);
    /// 16-bit MMIO write (RX descriptor-index doorbells).
    fn write16(&mut self, address: u32, value: u16);
}

/// `R_BE_HAXI_INIT_CFG1`. `reg.h:6302`.
pub(super) const INIT_CFG1: u32 = 0xB000;
/// `R_BE_HAXI_DMA_STOP1`. `reg.h:6324`.
pub(super) const DMA_STOP1: u32 = 0xB010;
/// `R_BE_HAXI_MST_WDT_TIMEOUT_SEL_V1`. `reg.h:6354`.
pub(super) const MST_WDT_TIMEOUT_SEL_V1: u32 = 0xB02C;
/// `R_BE_TXBD_RWPTR_CLR1`. `pci.h:1044`.
pub(super) const TXBD_RWPTR_CLR1: u32 = 0xB014;
/// `R_BE_RXBD_RWPTR_CLR1_V1`. `pci.h:1073`.
pub(super) const RXBD_RWPTR_CLR1_V1: u32 = 0xB018;
/// `R_BE_HAXI_DMA_BUSY1`. `pci.h:1081`.
pub(super) const DMA_BUSY1: u32 = 0xB01C;
/// `R_BE_HAXI_EXP_CTRL_V1`. `pci.h:1116`.
pub(super) const EXP_CTRL_V1: u32 = 0xB020;
/// `R_BE_RX_APPEND_MODE`. `pci.h:1040`.
pub(super) const RX_APPEND_MODE: u32 = 0x8920;
/// `R_BE_RXQ0_RXBD_IDX_V1`. `pci.h:836`.
pub(super) const RXQ0_RXBD_IDX_V1: u32 = 0xB160;
/// `R_BE_RPQ0_RXBD_IDX_V1`. `pci.h:837`.
pub(super) const RPQ0_RXBD_IDX_V1: u32 = 0xB164;
/// `R_BE_PCIE_MIT0_TMR`. `pci.h:981`.
pub(super) const PCIE_MIT0_TMR: u32 = 0x3330;
/// `R_BE_PCIE_MIT0_CNT`. `pci.h:989`.
pub(super) const PCIE_MIT0_CNT: u32 = 0x3334;

/// `B_BE_STOP_WPDMA`. `reg.h:6325`.
pub(super) const STOP_WPDMA: u32 = 1 << 31;
/// `B_BE_STOP_CH12` (firmware-command channel). `reg.h:6328`.
pub(super) const STOP_CH12: u32 = 1 << 12;
/// `B_BE_STOP_CH13 | B_BE_STOP_CH14` (always set by
/// `rtw89_pci_ctrl_txdma_ch_be`, both directions). `reg.h:6326,6327`.
pub(super) const STOP_CH13_14: u32 = (1 << 13) | (1 << 14);
/// `B_BE_TX_STOP1_MASK`: CH0..CH14. `reg.h:6341`.
/// (The TX-channel mask Linux ANDs with `dma_stop1.mask` is
/// CH0..CH11; see [`txdma_ch`].)
pub(super) const TX_STOP1_MASK: u32 = 0x7FFF;
/// TX-channel stop mask `rtw89_pci_ctrl_txdma_ch_be` actually
/// clears/sets: CH0..CH11 (`pci_be.c:458`, ANDed with
/// `dma_stop1.mask` = [`TX_STOP1_MASK`], which changes nothing).
pub(super) const TX_CH_MASK: u32 = 0x0FFF;
/// `B_BE_CLR_ALL_IDX_MASK` (8922A arm): CH0..CH14.
/// `pci.h:1060`.
pub(super) const CLR_ALL_IDX_MASK: u32 = 0x7FFF;
/// `B_BE_CLR_RXQ0_IDX | B_BE_CLR_RPQ0_IDX`. `pci.h:1078,1079`.
pub(super) const CLR_RXQ0_RPQ0_IDX: u32 = (1 << 0) | (1 << 1);
/// `B_BE_TXDMA_EN`. `reg.h:6320`.
pub(super) const TXDMA_EN: u32 = 1 << 4;
/// `B_BE_RXDMA_EN`. `reg.h:6319`.
pub(super) const RXDMA_EN: u32 = 1 << 5;
/// `B_BE_STOP_AXI_MST`. `reg.h:6317`.
pub(super) const STOP_AXI_MST: u32 = 1 << 7;
/// `B_BE_HAXI_MST_WDT_TIMEOUT_SEL_MASK`. `reg.h:6355`.
pub(super) const MST_WDT_TIMEOUT_SEL_MASK: u32 = 0x1F;
/// Value Linux writes into the timeout-select field on 8922A
/// io-enable (`pci_be.c:186`).
pub(super) const MST_WDT_TIMEOUT_SEL_8922A: u32 = 4;
/// `DMA_BUSY1_CHECK_BE`: TX channel busy bits CH0..CH14.
/// `pci.h:1107`.
pub(super) const DMA_BUSY1_CHECK_BE: u32 = 0x7FFF;
/// `B_BE_RXQ0_BUSY_V1 | B_BE_RPQ0_BUSY_V1`. `pci.h:1089,1090`.
pub(super) const RX_BUSY_V1: u32 = (1 << 16) | (1 << 17);
/// `B_BE_HAXI_MST_BUSY`. `pci.h:1082`.
pub(super) const HAXI_MST_BUSY: u32 = 1 << 31;
/// `B_BE_SET_BDRAM_BOUND`. `reg.h:6308`.
pub(super) const SET_BDRAM_BOUND: u32 = 1 << 16;
/// `B_BE_CFG_WD_PERIOD_IDLE_MASK`. `reg.h:6303`.
pub(super) const CFG_WD_PERIOD_IDLE_MASK: u32 = 0xF000_0000;
/// `B_BE_CFG_WD_PERIOD_ACTIVE_MASK`. `reg.h:6304`.
pub(super) const CFG_WD_PERIOD_ACTIVE_MASK: u32 = 0x0F00_0000;
/// `B_BE_RXQ_RXBD_MODE_MASK`. `reg.h:6311`.
pub(super) const RXQ_RXBD_MODE_MASK: u32 = 0x1800;
/// `B_BE_MAX_RXDMA_MASK`. `reg.h:6321`.
pub(super) const MAX_RXDMA_MASK: u32 = 0xC;
/// `B_BE_MAX_TXDMA_MASK`. `reg.h:6322`.
pub(super) const MAX_TXDMA_MASK: u32 = 0x3;
/// `B_BE_MAX_TAG_NUM_MASK`. `pci.h:1120`.
pub(super) const MAX_TAG_NUM_MASK: u32 = 0xF;
/// `B_BE_APPEND_LEN_MASK`. `pci.h:1042`.
pub(super) const APPEND_LEN_MASK: u32 = 0xFFFF;
/// `B_BE_PCIE_MIT0_RX_TMR_MASK`. `pci.h:982`.
pub(super) const MIT0_RX_TMR_MASK: u32 = 0x30;
/// `BE_MIT0_TMR_UNIT_1MS`. `pci.h:983`.
pub(super) const MIT0_TMR_UNIT_1MS: u32 = 0;
/// `B_BE_PCIE_RX_MIT0_CNT_MASK`. `pci.h:990`.
pub(super) const RX_MIT0_CNT_MASK: u32 = 0xFF00_0000;
/// `RTW89_PCI_RXBD_NUM_MAX / 2`, clamped to `u8::MAX`
/// (`pci_be.c:623`): 256 / 2 = 128.
pub(super) const MIT0_RX_CNT: u32 = 128;
/// `B_BE_PCIE_RX_MIT0_TMR_CNT_MASK` value Linux writes
/// (`pci_be.c:624`).
pub(super) const MIT0_RX_TMR_CNT: u32 = 2;
/// `B_BE_PCIE_RX_MIT0_TMR_CNT_MASK`. `pci.h:992`.
pub(super) const RX_MIT0_TMR_CNT_MASK: u32 = 0xFF00;

/// One arm of `rtw89_pci_ctrl_trxdma_pcie_be`'s
/// `enum mac_ax_pcie_func_ctrl`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Ctrl {
    /// `MAC_AX_PCIE_ENABLE`.
    Enable,
    /// `MAC_AX_PCIE_DISABLE`.
    Disable,
    /// `MAC_AX_PCIE_IGNORE` (leave the bit alone).
    Ignore,
}

/// RX descriptor-buffer mode (`enum mac_ax_rxbd_mode`,
/// `pci.h:1214`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RxBdMode {
    /// `MAC_AX_RXBD_PKT` = 0; normal RXBD word in
    /// `B_BE_RXQ_RXBD_MODE_MASK`.
    Pkt,
    /// `MAC_AX_RXBD_SEP` = 1; also zeroes the append length.
    Sep,
}

impl RxBdMode {
    /// Linux `PCIE_RXBD_NORM` / `PCIE_RXBD_SEP`
    /// (`pci_be.c:12,13`).
    fn mode_word(self) -> u32 {
        match self {
            RxBdMode::Pkt => 0,
            RxBdMode::Sep => 1,
        }
    }
}

/// `rtw8922a_pci_info` DMA-tuning fields (`rtw8922ae.c:23..29`).
/// Values are the `MAC_AX_*` enum ordinals (`pci.h:1214..1274`),
/// inserted into their masks exactly as Linux's
/// `u32_replace_bits` does (overflow bits are dropped by the mask).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ModeParams {
    /// `rxbd_mode` (`MAC_AX_RXBD_PKT` for 8922AE).
    pub rxbd_mode: RxBdMode,
    /// `tx_burst` (`MAC_AX_TX_BURST_V1_256B` = 2).
    pub tx_burst: u32,
    /// `rx_burst` (`MAC_AX_RX_BURST_V1_128B` = 1).
    pub rx_burst: u32,
    /// `wd_dma_idle_intvl` (`MAC_AX_WD_DMA_INTVL_256NS` = 1).
    pub wd_dma_idle_intvl: u32,
    /// `wd_dma_act_intvl` (`MAC_AX_WD_DMA_INTVL_256NS` = 1).
    pub wd_dma_act_intvl: u32,
    /// `multi_tag_num` (`MAC_AX_TAG_NUM_8` = 7).
    pub multi_tag_num: u32,
}

/// The 8922AE `rtw8922a_pci_info` DMA-tuning values.
pub(super) const MODE_PARAMS_8922AE: ModeParams = ModeParams {
    rxbd_mode: RxBdMode::Pkt,
    tx_burst: 2,
    rx_burst: 1,
    wd_dma_idle_intvl: 1,
    wd_dma_act_intvl: 1,
    multi_tag_num: 7,
};

/// Errors from BE DMA control setup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    /// A ring length of zero cannot seed a descriptor index
    /// (`len - 1` would underflow).
    BadLength,
}

/// `rtw89_pci_ctrl_wpdma_pcie_be`: enable clears
/// `B_BE_STOP_WPDMA`, disable sets it (`pci_be.c:151`).
pub(super) fn wpdma(regs: &mut impl Regs, enable: bool) {
    let cur = regs.read32(DMA_STOP1);
    let next = if enable {
        cur & !STOP_WPDMA
    } else {
        cur | STOP_WPDMA
    };
    regs.write32(DMA_STOP1, next);
}

/// `rtw89_pci_ctrl_trxdma_pcie_be` (`pci_be.c:159`).
/// Enable sets TXDMA/RXDMA and clears `STOP_AXI_MST` on the
/// io arm; disable does the reverse; ignore leaves the bit.
/// The io-enable arm additionally writes the HAXI master-watchdog
/// timeout-select field (8922A-only Linux arm).
pub(super) fn trxdma(regs: &mut impl Regs, tx: Ctrl, rx: Ctrl, io: Ctrl) {
    let mut val = regs.read32(INIT_CFG1);
    match tx {
        Ctrl::Enable => val |= TXDMA_EN,
        Ctrl::Disable => val &= !TXDMA_EN,
        Ctrl::Ignore => {}
    }
    match rx {
        Ctrl::Enable => val |= RXDMA_EN,
        Ctrl::Disable => val &= !RXDMA_EN,
        Ctrl::Ignore => {}
    }
    match io {
        Ctrl::Enable => val &= !STOP_AXI_MST,
        Ctrl::Disable => val |= STOP_AXI_MST,
        Ctrl::Ignore => {}
    }
    regs.write32(INIT_CFG1, val);
    if io == Ctrl::Enable {
        let cur = regs.read32(MST_WDT_TIMEOUT_SEL_V1);
        let next = (cur & !MST_WDT_TIMEOUT_SEL_MASK)
            | (MST_WDT_TIMEOUT_SEL_8922A & MST_WDT_TIMEOUT_SEL_MASK);
        regs.write32(MST_WDT_TIMEOUT_SEL_V1, next);
    }
}

/// `rtw89_pci_ctrl_txdma_ch_be` (`pci_be.c:456`): CH13/CH14
/// stop bits are always set; the CH0..CH11 mask is cleared on
/// enable and set on disable.
pub(super) fn txdma_ch(regs: &mut impl Regs, enable: bool) {
    let cur = regs.read32(DMA_STOP1);
    let mut next = cur | STOP_CH13_14;
    if enable {
        next &= !TX_CH_MASK;
    } else {
        next |= TX_CH_MASK;
    }
    regs.write32(DMA_STOP1, next);
}

/// `rtw89_pci_ctrl_txdma_fw_ch_be` (`pci_be.c:481`): the
/// firmware-command channel CH12 stop bit.
pub(super) fn txdma_fw_ch(regs: &mut impl Regs, enable: bool) {
    let cur = regs.read32(DMA_STOP1);
    let next = if enable {
        cur & !STOP_CH12
    } else {
        cur | STOP_CH12
    };
    regs.write32(DMA_STOP1, next);
}

/// `rtw89_pci_clr_idx_all_be` (`pci_be.c:190`, 8922A arms):
/// clear every TX index, clear RXQ0/RPQ0, then seed both RX
/// doorbells with `len - 1`.
pub(super) fn clr_idx_all(regs: &mut impl Regs, rxq_len: u16, rpq_len: u16) -> Result<(), Error> {
    if rxq_len == 0 || rpq_len == 0 {
        return Err(Error::BadLength);
    }
    regs.write32(TXBD_RWPTR_CLR1, CLR_ALL_IDX_MASK);
    regs.write32(RXBD_RWPTR_CLR1_V1, CLR_RXQ0_RPQ0_IDX);
    regs.write16(RXQ0_RXBD_IDX_V1, rxq_len - 1);
    regs.write16(RPQ0_RXBD_IDX_V1, rpq_len - 1);
    Ok(())
}

/// TX-DMA idle predicate for `rtw89_pci_poll_txdma_ch_idle_be`
/// (`pci_be.c:214`): no `DMA_BUSY1_CHECK_BE` bit set.
pub(super) fn txdma_idle(busy1: u32) -> bool {
    busy1 & DMA_BUSY1_CHECK_BE == 0
}

/// RX-DMA idle predicate for `rtw89_pci_poll_rxdma_ch_idle_be`
/// (`pci_be.c:225`): neither RXQ0 nor RPQ0 busy.
pub(super) fn rxdma_idle(busy1: u32) -> bool {
    busy1 & RX_BUSY_V1 == 0
}

/// IO-idle predicate for `rtw89_pci_poll_io_idle_be`
/// (`pci_be.c:652`): the HAXI master not busy.
pub(super) fn io_idle(busy1: u32) -> bool {
    busy1 & HAXI_MST_BUSY == 0
}

/// `rtw89_pci_mode_op_be` (`pci_be.c:255`): burst sizes,
/// watchdog intervals, tag count into `INIT_CFG1`; RXBD mode
/// (and, for SEP, a zeroed append length) into the RX-append
/// register; tag count into the EXP control register.
/// Field insertion follows Linux's `u32_replace_bits` (mask
/// truncation). The 8922A arm always reads the RX-append register.
pub(super) fn mode_op(regs: &mut impl Regs, params: ModeParams) {
    let mut init_cfg1 = regs.read32(INIT_CFG1);
    let mut rx_append = regs.read32(RX_APPEND_MODE);
    let mut exp_ctrl = regs.read32(EXP_CTRL_V1);

    init_cfg1 = (init_cfg1 & !RXQ_RXBD_MODE_MASK)
        | ((params.rxbd_mode.mode_word() << 11) & RXQ_RXBD_MODE_MASK);
    if params.rxbd_mode == RxBdMode::Sep {
        rx_append &= !APPEND_LEN_MASK;
    }
    init_cfg1 = (init_cfg1 & !MAX_TXDMA_MASK) | (params.tx_burst & MAX_TXDMA_MASK);
    init_cfg1 = (init_cfg1 & !MAX_RXDMA_MASK) | ((params.rx_burst << 2) & MAX_RXDMA_MASK);
    exp_ctrl = (exp_ctrl & !MAX_TAG_NUM_MASK) | (params.multi_tag_num & MAX_TAG_NUM_MASK);
    init_cfg1 = (init_cfg1 & !CFG_WD_PERIOD_IDLE_MASK)
        | ((params.wd_dma_idle_intvl << 28) & CFG_WD_PERIOD_IDLE_MASK);
    init_cfg1 = (init_cfg1 & !CFG_WD_PERIOD_ACTIVE_MASK)
        | ((params.wd_dma_act_intvl << 24) & CFG_WD_PERIOD_ACTIVE_MASK);

    regs.write32(INIT_CFG1, init_cfg1);
    regs.write32(RX_APPEND_MODE, rx_append);
    regs.write32(EXP_CTRL_V1, exp_ctrl);
}

/// `rtw89_pci_rst_bdram_be`, set half (`pci_be.c:295`): raise
/// `B_BE_SET_BDRAM_BOUND`. The caller polls until
/// [`rst_bdram_done`] (Linux: 50 us interval, 500000 us timeout).
pub(super) fn rst_bdram_set(regs: &mut impl Regs) {
    let cur = regs.read32(INIT_CFG1);
    regs.write32(INIT_CFG1, cur | SET_BDRAM_BOUND);
}

/// BDRAM-reset completion predicate: the bound bit cleared.
pub(super) fn rst_bdram_done(init_cfg1: u32) -> bool {
    init_cfg1 & SET_BDRAM_BOUND == 0
}

/// `rtw89_pci_configure_mit_be` (`pci_be.c:616`): 1 ms MIT0
/// timer unit, RX MIT count 128, MIT timer count 2.
pub(super) fn configure_mit(regs: &mut impl Regs) {
    let tmr = regs.read32(PCIE_MIT0_TMR);
    regs.write32(
        PCIE_MIT0_TMR,
        (tmr & !MIT0_RX_TMR_MASK) | (MIT0_TMR_UNIT_1MS << 4),
    );
    let cnt = regs.read32(PCIE_MIT0_CNT);
    let next = (cnt & !RX_MIT0_CNT_MASK) | ((MIT0_RX_CNT << 24) & RX_MIT0_CNT_MASK);
    let next = (next & !RX_MIT0_TMR_CNT_MASK) | ((MIT0_RX_TMR_CNT << 8) & RX_MIT0_TMR_CNT_MASK);
    regs.write32(PCIE_MIT0_CNT, next);
}

/// `rtw89_pci_ctrl_dma_all` for 8922A (`pci.c:2114` with
/// `rtw8922ae.c` `dma_io_stop` / `init_cfg_reg` / `txhci_en_bit` /
/// `rxhci_en_bit`): io arm clears/sets `STOP_AXI_MST`, trx arm
/// sets/clears `TXDMA_EN | RXDMA_EN`. Unlike [`trxdma`]'s
/// io-enable arm, this path never writes the watchdog
/// timeout-select register.
pub(super) fn ctrl_dma_all(regs: &mut impl Regs, enable: bool) {
    let cur = regs.read32(INIT_CFG1);
    let next = if enable {
        (cur & !STOP_AXI_MST) | TXDMA_EN | RXDMA_EN
    } else {
        (cur | STOP_AXI_MST) & !(TXDMA_EN | RXDMA_EN)
    };
    regs.write32(INIT_CFG1, next);
}

/// Post-init DMA tail (`pci_be.c:631`, after the caller's LTR
/// set): `trxdma(Ignore, Ignore, Enable)` → `wpdma(true)` →
/// `txdma_ch(true)` → `txdma_fw_ch(true)` → `configure_mit`.
pub(super) fn post_init_dma(regs: &mut impl Regs) {
    trxdma(regs, Ctrl::Ignore, Ctrl::Ignore, Ctrl::Enable);
    wpdma(regs, true);
    txdma_ch(regs, true);
    txdma_fw_ch(regs, true);
    configure_mit(regs);
}
