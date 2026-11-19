use super::dma_be::*;
use alloc::collections::BTreeMap;
use narf_kernel_test::{kernel_test_in, TestResult};

/// Fixture register bank implementing [`Regs`].
struct Model {
    regs32: BTreeMap<u32, u32>,
    regs16: BTreeMap<u32, u16>,
}

impl Model {
    fn new() -> Self {
        Self {
            regs32: BTreeMap::new(),
            regs16: BTreeMap::new(),
        }
    }

    fn with32(mut self, addr: u32, value: u32) -> Self {
        self.regs32.insert(addr, value);
        self
    }
}

impl Regs for Model {
    fn read32(&mut self, address: u32) -> u32 {
        *self.regs32.get(&address).unwrap_or(&0)
    }

    fn write32(&mut self, address: u32, value: u32) {
        self.regs32.insert(address, value);
    }

    fn write16(&mut self, address: u32, value: u16) {
        self.regs16.insert(address, value);
    }
}

fn smoke_rtw89_dma_be_control_words() -> TestResult {
    // wpdma: enable clears bit 31, disable sets it.
    let mut m = Model::new().with32(DMA_STOP1, 0xFFFF_FFFF);
    wpdma(&mut m, true);
    if m.regs32[&DMA_STOP1] != 0x7FFF_FFFF {
        return TestResult::Fail("wpdma enable clears STOP_WPDMA");
    }
    wpdma(&mut m, false);
    if m.regs32[&DMA_STOP1] != 0xFFFF_FFFF {
        return TestResult::Fail("wpdma disable sets STOP_WPDMA");
    }

    // trxdma enable-all from zero: TXDMA|RXDMA set, STOP_AXI
    // clear, plus the 8922A watchdog timeout-select write of 4.
    let mut m = Model::new().with32(INIT_CFG1, STOP_AXI_MST);
    trxdma(&mut m, Ctrl::Enable, Ctrl::Enable, Ctrl::Enable);
    if m.regs32[&INIT_CFG1] != (TXDMA_EN | RXDMA_EN) {
        return TestResult::Fail("trxdma enable-all word");
    }
    if m.regs32[&MST_WDT_TIMEOUT_SEL_V1] != MST_WDT_TIMEOUT_SEL_8922A {
        return TestResult::Fail("trxdma io-enable watchdog select");
    }
    // Ignore leaves bits alone and writes no watchdog word.
    let mut m = Model::new().with32(INIT_CFG1, TXDMA_EN | RXDMA_EN | STOP_AXI_MST);
    trxdma(&mut m, Ctrl::Ignore, Ctrl::Ignore, Ctrl::Ignore);
    if m.regs32[&INIT_CFG1] != (TXDMA_EN | RXDMA_EN | STOP_AXI_MST)
        || m.regs32.contains_key(&MST_WDT_TIMEOUT_SEL_V1)
    {
        return TestResult::Fail("trxdma ignore is a no-op");
    }
    // Disable-all from the enabled word.
    let mut m = Model::new().with32(INIT_CFG1, TXDMA_EN | RXDMA_EN);
    trxdma(&mut m, Ctrl::Disable, Ctrl::Disable, Ctrl::Disable);
    if m.regs32[&INIT_CFG1] != STOP_AXI_MST {
        return TestResult::Fail("trxdma disable-all word");
    }

    // txdma_ch: enable clears CH0..11 but keeps CH13/CH14 set;
    // disable sets CH0..11 plus CH13/CH14.
    let mut m = Model::new().with32(DMA_STOP1, 0xFFFF_FFFF);
    txdma_ch(&mut m, true);
    if m.regs32[&DMA_STOP1] != 0xFFFF_F000 {
        return TestResult::Fail("txdma_ch enable word");
    }
    let mut m = Model::new().with32(DMA_STOP1, 0);
    txdma_ch(&mut m, false);
    if m.regs32[&DMA_STOP1] != (TX_CH_MASK | STOP_CH13_14) {
        return TestResult::Fail("txdma_ch disable word");
    }

    // txdma_fw_ch: CH12 only.
    let mut m = Model::new().with32(DMA_STOP1, 0xFFFF_FFFF);
    txdma_fw_ch(&mut m, true);
    if m.regs32[&DMA_STOP1] != 0xFFFF_EFFF {
        return TestResult::Fail("txdma_fw_ch enable word");
    }

    // ctrl_dma_all: enable clears STOP_AXI_MST and sets
    // TXDMA|RXDMA; disable reverses; no watchdog write either way.
    let mut m = Model::new().with32(INIT_CFG1, STOP_AXI_MST);
    ctrl_dma_all(&mut m, true);
    if m.regs32[&INIT_CFG1] != (TXDMA_EN | RXDMA_EN)
        || m.regs32.contains_key(&MST_WDT_TIMEOUT_SEL_V1)
    {
        return TestResult::Fail("ctrl_dma_all enable word");
    }
    ctrl_dma_all(&mut m, false);
    if m.regs32[&INIT_CFG1] != STOP_AXI_MST {
        return TestResult::Fail("ctrl_dma_all disable word");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_dma_be_control_words);

fn smoke_rtw89_dma_be_index_and_mode() -> TestResult {
    // clr_idx_all: TX clear mask, RX clear pair, len-1 doorbells.
    let mut m = Model::new();
    if clr_idx_all(&mut m, 256, 128).is_err()
        || m.regs32[&TXBD_RWPTR_CLR1] != CLR_ALL_IDX_MASK
        || m.regs32[&RXBD_RWPTR_CLR1_V1] != CLR_RXQ0_RPQ0_IDX
        || m.regs16[&RXQ0_RXBD_IDX_V1] != 255
        || m.regs16[&RPQ0_RXBD_IDX_V1] != 127
    {
        return TestResult::Fail("clr_idx_all words");
    }
    if clr_idx_all(&mut m, 0, 128).is_ok() || clr_idx_all(&mut m, 256, 0).is_ok() {
        return TestResult::Fail("clr_idx_all rejects zero ring length");
    }

    // mode_op with the 8922AE tuning values from zeroed regs:
    // INIT_CFG1 = wd_idle(1<<28) | wd_act(1<<24) | rx_burst(1<<2)
    //   | tx_burst(2) = 0x11000006; EXP = tag 7; RX_APPEND kept.
    let mut m = Model::new().with32(RX_APPEND_MODE, 0xDEAD_BEEF);
    mode_op(&mut m, MODE_PARAMS_8922AE);
    if m.regs32[&INIT_CFG1] != 0x1100_0006
        || m.regs32[&EXP_CTRL_V1] != 7
        || m.regs32[&RX_APPEND_MODE] != 0xDEAD_BEEF
    {
        return TestResult::Fail("mode_op 8922AE words");
    }
    // SEP mode: RXBD mode bit set and append length zeroed.
    let mut m = Model::new().with32(RX_APPEND_MODE, 0x1234);
    let sep = ModeParams {
        rxbd_mode: RxBdMode::Sep,
        ..MODE_PARAMS_8922AE
    };
    mode_op(&mut m, sep);
    if m.regs32[&INIT_CFG1] & RXQ_RXBD_MODE_MASK != 0x800 || m.regs32[&RX_APPEND_MODE] != 0 {
        return TestResult::Fail("mode_op SEP words");
    }

    // rst_bdram: set bit, predicate clears with it.
    let mut m = Model::new().with32(INIT_CFG1, 0);
    rst_bdram_set(&mut m);
    if m.regs32[&INIT_CFG1] != SET_BDRAM_BOUND || rst_bdram_done(m.regs32[&INIT_CFG1]) {
        return TestResult::Fail("rst_bdram set word");
    }
    if !rst_bdram_done(0) {
        return TestResult::Fail("rst_bdram done predicate");
    }

    // configure_mit from zeroed regs: TMR keeps only cleared
    // timer bits (0), CNT = 128<<24 | 2<<8.
    let mut m = Model::new();
    configure_mit(&mut m);
    if m.regs32[&PCIE_MIT0_TMR] != 0 || m.regs32[&PCIE_MIT0_CNT] != 0x8000_0200 {
        return TestResult::Fail("configure_mit words");
    }
    // MIT timer unit: pre-set timer bits 5:4 are cleared.
    let mut m = Model::new().with32(PCIE_MIT0_TMR, 0xFFFF_FFFF);
    configure_mit(&mut m);
    if m.regs32[&PCIE_MIT0_TMR] != 0xFFFF_FFCF {
        return TestResult::Fail("configure_mit timer mask");
    }

    // Idle predicates.
    if !txdma_idle(0)
        || txdma_idle(0x7FFF)
        || !rxdma_idle(0)
        || rxdma_idle(1 << 16)
        || !io_idle(0)
        || io_idle(1 << 31)
    {
        return TestResult::Fail("dma idle predicates");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_dma_be_index_and_mode);

fn smoke_rtw89_dma_be_post_init_order() -> TestResult {
    // Post-init tail from a stopped block: trxdma io enable
    // clears STOP_AXI_MST (tx/rx arms are IGNORE, so TXDMA_EN
    // and RXDMA_EN stay as the caller left them — here clear)
    // and writes watchdog 4; wpdma enable clears STOP_WPDMA;
    // txdma channels enabled and the FW-command channel kept
    // running (STOP1 keeps every bit except STOP_WPDMA, CH0..CH11
    // and CH12 — `rtw89_pci_ops_mac_post_init_be` ends with
    // `txdma_fw_ch(true)`); MIT programmed.
    let mut m = Model::new()
        .with32(INIT_CFG1, STOP_AXI_MST)
        .with32(DMA_STOP1, 0xFFFF_FFFF);
    post_init_dma(&mut m);
    if m.regs32[&INIT_CFG1] != 0
        || m.regs32[&MST_WDT_TIMEOUT_SEL_V1] != MST_WDT_TIMEOUT_SEL_8922A
        || m.regs32[&DMA_STOP1] != 0x7FFF_E000
        || m.regs32[&PCIE_MIT0_CNT] != 0x8000_0200
    {
        return TestResult::Fail("post_init_dma words");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_dma_be_post_init_order);
