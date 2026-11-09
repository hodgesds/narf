use super::dma::{BE_DMA_ADDR_SET, TXCH_NUM};
use super::dma_8922a::*;
use super::dma_be::{Regs, DMA_BUSY1, INIT_CFG1, STOP_AXI_MST};
use alloc::collections::BTreeMap;
use narf_kernel_test::{kernel_test_in, TestResult};

/// Fixture register bank implementing [`Regs`].
struct Model {
    regs32: BTreeMap<u32, u32>,
    regs16: BTreeMap<u32, u16>,
    /// When set, reads of INIT_CFG1 report the BDRAM bound bit
    /// clear, simulating the hardware completing the reset after
    /// `rst_bdram_set` raised it (the written map value is
    /// untouched, so write-log assertions still see the set).
    bound_clears: bool,
}

impl Model {
    fn new() -> Self {
        Self {
            regs32: BTreeMap::new(),
            regs16: BTreeMap::new(),
            bound_clears: false,
        }
    }

    fn with32(mut self, addr: u32, value: u32) -> Self {
        self.regs32.insert(addr, value);
        self
    }

    fn with_bound_clears(mut self) -> Self {
        self.bound_clears = true;
        self
    }
}

impl Regs for Model {
    fn read32(&mut self, address: u32) -> u32 {
        let value = *self.regs32.get(&address).unwrap_or(&0);
        if self.bound_clears && address == INIT_CFG1 {
            value & !(1 << 16)
        } else {
            value
        }
    }

    fn write32(&mut self, address: u32, value: u32) {
        self.regs32.insert(address, value);
    }

    fn write16(&mut self, address: u32, value: u16) {
        self.regs16.insert(address, value);
    }
}

fn smoke_rtw89_dma_8922a_be_addr_set() -> TestResult {
    // Spot values transcribed from Linux pci.h R_BE_*_V1 (the BE
    // set 8922AE actually uses), not from the in-tree table:
    // CH0, CH12, RXQ, RPQ must all sit in the 0xB pages.
    let tx0 = &BE_DMA_ADDR_SET.tx[0];
    if tx0.idx != 0xB100 || tx0.desa_l != 0xB200 || tx0.desa_h != 0xB204 || tx0.num != 0xB030 {
        return TestResult::Fail("BE CH0 regs wrong");
    }
    let tx12 = &BE_DMA_ADDR_SET.tx[12];
    if tx12.idx != 0xB130 || tx12.desa_l != 0xB260 || tx12.desa_h != 0xB264 || tx12.num != 0xB048 {
        return TestResult::Fail("BE CH12 regs wrong");
    }
    let rxq = &BE_DMA_ADDR_SET.rx[0];
    if rxq.idx != 0xB160 || rxq.desa_l != 0xB300 || rxq.desa_h != 0xB304 || rxq.num != 0xB050 {
        return TestResult::Fail("BE RXQ regs wrong");
    }
    let rpq = &BE_DMA_ADDR_SET.rx[1];
    if rpq.idx != 0xB164 || rpq.desa_l != 0xB308 || rpq.desa_h != 0xB30C || rpq.num != 0xB052 {
        return TestResult::Fail("BE RPQ regs wrong");
    }
    // TYPE2: no per-channel BDRAM_CTRL register anywhere.
    if BE_DMA_ADDR_SET.tx.iter().any(|r| r.bdram != 0) {
        return TestResult::Fail("BE set must carry bdram = 0");
    }
    // Channel stride: consecutive TX idx regs are 4 apart.
    if BE_DMA_ADDR_SET.tx[5].idx != BE_DMA_ADDR_SET.tx[4].idx + 4 {
        return TestResult::Fail("BE TX idx stride wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_dma_8922a_be_addr_set);

fn smoke_rtw89_dma_8922a_program_rings() -> TestResult {
    // TX CH5 at phys 0x1_2345_6780, depth 256.
    let mut m = Model::new();
    if program_tx_ring(&mut m, 5, 0x1_2345_6780, 256).is_err() {
        return TestResult::Fail("program_tx_ring CH5 failed");
    }
    if m.regs16.get(&0xB03A) != Some(&256) {
        return TestResult::Fail("CH5 NUM not written");
    }
    if m.regs32.get(&0xB228) != Some(&0x2345_6780) {
        return TestResult::Fail("CH5 DESA_L not written");
    }
    if m.regs32.get(&0xB22C) != Some(&0x1) {
        return TestResult::Fail("CH5 DESA_H not written");
    }
    // RX RPQ at phys 0x8000, depth 256: NUM + DESA + idx seed 255.
    let mut m = Model::new();
    if program_rx_ring(&mut m, 1, 0x8000, 256).is_err() {
        return TestResult::Fail("program_rx_ring RPQ failed");
    }
    if m.regs16.get(&0xB052) != Some(&256) {
        return TestResult::Fail("RPQ NUM not written");
    }
    if m.regs32.get(&0xB308) != Some(&0x8000) || m.regs32.get(&0xB30C) != Some(&0) {
        return TestResult::Fail("RPQ DESA not written");
    }
    if m.regs16.get(&0xB164) != Some(&255) {
        return TestResult::Fail("RPQ doorbell not seeded len - 1");
    }
    // Refusals: bad channels, zero length, over-maximum length.
    let mut m = Model::new();
    if program_tx_ring(&mut m, 13, 0x1000, 256).is_ok()
        || program_tx_ring(&mut m, 0, 0x1000, 0).is_ok()
        || program_tx_ring(&mut m, 0, 0x1000, 257).is_ok()
        || program_rx_ring(&mut m, 2, 0x1000, 256).is_ok()
    {
        return TestResult::Fail("ring programming accepted a bad input");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_dma_8922a_program_rings
);

fn smoke_rtw89_dma_8922a_reset_and_wp_sel() -> TestResult {
    let tx_phys = [0x1000u64; TXCH_NUM];
    let rx_phys = [0x9000u64, 0xA000u64];
    let mut m = Model::new();
    if reset_trx_rings(&mut m, &tx_phys, &rx_phys, 256, 256).is_err() {
        return TestResult::Fail("reset_trx_rings failed");
    }
    // First TX ring + first RX ring programmed.
    if m.regs16.get(&0xB030) != Some(&256) || m.regs32.get(&0xB200) != Some(&0x1000) {
        return TestResult::Fail("CH0 not programmed by reset");
    }
    if m.regs16.get(&0xB050) != Some(&256)
        || m.regs32.get(&0xB300) != Some(&0x9000)
        || m.regs16.get(&0xB160) != Some(&255)
    {
        return TestResult::Fail("RXQ not programmed by reset");
    }
    // WP-select block: groups pack (i, i+1, i+2, i+3) into bytes.
    if m.regs32.get(&0xB420) != Some(&0x0302_0100)
        || m.regs32.get(&0xB424) != Some(&0x0706_0504)
        || m.regs32.get(&0xB428) != Some(&0x0B0A_0908)
        || m.regs32.get(&0xB42C) != Some(&0x0F0E_0D0C)
    {
        return TestResult::Fail("WP-select words wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_dma_8922a_reset_and_wp_sel
);

fn smoke_rtw89_dma_8922a_pre_init_sequence() -> TestResult {
    // Before-reset from zeroed regs: wpdma(false) sets STOP_WPDMA
    // (bit 31 of DMA_STOP1); trxdma disable sets STOP_AXI_MST and
    // clears TXDMA/RXDMA; clr_idx_all seeds both RX doorbells
    // with 255 and clears all TX indices; polls pass instantly on
    // idle busy words; mode_op programs the 8922AE tuning values.
    let mut m = Model::new();
    if pre_init_dma_before_reset(&mut m, 256, 256).is_err() {
        return TestResult::Fail("pre_init before_reset failed");
    }
    if m.regs32.get(&0xB010) != Some(&(1 << 31)) {
        return TestResult::Fail("wpdma(false) word wrong");
    }
    if m.regs32.get(&0xB014) != Some(&0x7FFF) {
        return TestResult::Fail("clr_idx_all TX clear mask wrong");
    }
    if m.regs32.get(&0xB018) != Some(&0x3) {
        return TestResult::Fail("clr_idx_all RX clear mask wrong");
    }
    if m.regs16.get(&0xB160) != Some(&255) || m.regs16.get(&0xB164) != Some(&255) {
        return TestResult::Fail("clr_idx_all RX doorbell seed wrong");
    }
    // INIT_CFG1: STOP_AXI_MST (0x80, from trxdma disable) survives
    // mode_op; bursts 2 (TX) + 1<<2 (RX) and watchdog intervals
    // 1<<28 (idle) + 1<<24 (active) are added; RXBD mode stays 0.
    if m.regs32.get(&0xB000) != Some(&(0x80 | 2 | 4 | (1 << 28) | (1 << 24))) {
        return TestResult::Fail("mode_op INIT_CFG1 word wrong");
    }
    if m.regs32.get(&0xB020) != Some(&7) {
        return TestResult::Fail("mode_op tag count wrong");
    }
    // After-reset: the fixture clears the bound bit on read, so
    // the poll passes; txdma_ch(false) sets CH0..11 + CH13/14 stop
    // bits, txdma_fw_ch(true) leaves CH12 clear, trxdma enable sets
    // TXDMA/RXDMA and clears STOP_AXI_MST, plus the watchdog
    // select write of 4.
    let mut m = Model::new().with32(INIT_CFG1, 0).with_bound_clears();
    if pre_init_dma_after_reset(&mut m).is_err() {
        return TestResult::Fail("pre_init after_reset failed");
    }
    if m.regs32.get(&INIT_CFG1) != Some(&((1 << 4) | (1 << 5))) {
        return TestResult::Fail("after_reset INIT_CFG1 word wrong");
    }
    if m.regs32.get(&0xB02C) != Some(&4) {
        return TestResult::Fail("after_reset watchdog select wrong");
    }
    if m.regs32.get(&0xB010) != Some(&((1 << 13) | (1 << 14) | 0x0FFF)) {
        return TestResult::Fail("after_reset DMA_STOP1 word wrong");
    }
    // Stuck TX busy never idles: before_reset must time out.
    let mut m = Model::new().with32(DMA_BUSY1, 0x1);
    if pre_init_dma_before_reset(&mut m, 256, 256).is_ok() {
        return TestResult::Fail("stuck TX busy did not time out");
    }
    // Stuck BDRAM bound never clears: after_reset must time out.
    let mut m = Model::new().with32(INIT_CFG1, 1 << 16);
    if pre_init_dma_after_reset(&mut m).is_ok() {
        return TestResult::Fail("stuck BDRAM bound did not time out");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_dma_8922a_pre_init_sequence
);

fn smoke_rtw89_dma_8922a_doorbells() -> TestResult {
    let mut m = Model::new();
    if doorbell_tx(&mut m, 12, 42).is_err() || m.regs16.get(&0xB130) != Some(&42) {
        return TestResult::Fail("CH12 doorbell wrong");
    }
    if doorbell_rx(&mut m, 0, 7).is_err() || m.regs16.get(&0xB160) != Some(&7) {
        return TestResult::Fail("RXQ doorbell wrong");
    }
    // Index readback round-trips the fake's word.
    let mut m = Model::new().with32(0xB108, 0x0012_0034);
    match read_tx_idx(&mut m, 2) {
        Ok(0x0012_0034) => {}
        _ => return TestResult::Fail("TX idx readback wrong"),
    }
    // Refusals: out-of-range channels.
    let mut m = Model::new();
    if doorbell_tx(&mut m, 13, 0).is_ok()
        || doorbell_rx(&mut m, 2, 0).is_ok()
        || read_tx_idx(&mut m, 13).is_ok()
        || read_rx_idx(&mut m, 2).is_ok()
    {
        return TestResult::Fail("doorbell accepted a bad channel");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_dma_8922a_doorbells);

fn smoke_rtw89_dma_8922a_stop() -> TestResult {
    // ctrl_dma_all(false): STOP_AXI set, TXDMA/RXDMA clear; IO
    // idle (HAXI master bit clear) lets the poll pass at once.
    let mut m = Model::new().with32(INIT_CFG1, (1 << 4) | (1 << 5));
    if stop_dma(&mut m).is_err() {
        return TestResult::Fail("stop_dma failed on idle bus");
    }
    if m.regs32.get(&INIT_CFG1) != Some(&(1 << 7)) {
        return TestResult::Fail("stop_dma INIT_CFG1 word wrong");
    }
    // Stuck HAXI master never idles: must time out.
    let mut m = Model::new().with32(DMA_BUSY1, 1 << 31);
    if stop_dma(&mut m).is_ok() {
        return TestResult::Fail("stuck HAXI master did not time out");
    }
    // stop_dma must see the same STOP_AXI_MST bit the sequencer
    // itself set (import cross-check, not a re-derivation).
    if STOP_AXI_MST != (1 << 7) {
        return TestResult::Fail("STOP_AXI_MST constant drifted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_dma_8922a_stop);
