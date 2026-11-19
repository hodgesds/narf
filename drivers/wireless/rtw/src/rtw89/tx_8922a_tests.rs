use super::dma::{TxBd, TXBD_OPT_LS};
use super::dma_be::Regs;
use super::tx_8922a::*;
use alloc::collections::BTreeMap;
use alloc::vec;
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

fn zero_body() -> [u8; 32] {
    [0u8; 32]
}

fn smoke_rtw89_tx_8922a_qsel_map() -> TestResult {
    // Linux generic mapping values (core.c), pinned.
    for (qsel, channel) in [
        (0x00u8, 0u8),
        (0x05, 1),
        (0x0A, 2),
        (0x0F, 3),
        (0x12, 8),
        (0x11, 9),
        (0x1A, 10),
        (0x19, 11),
    ] {
        if channel_for_qsel(qsel) != Ok(channel) {
            return TestResult::Fail("qsel mapping wrong");
        }
    }
    // Unknown values are refused (Linux falls through to ACH0
    // with a warning; we fail closed instead).
    for qsel in [0x10u8, 0x14, 0x1C, 0x1F, 0xFF] {
        if channel_for_qsel(qsel).is_ok() {
            return TestResult::Fail("unknown qsel accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_tx_8922a_qsel_map);

fn smoke_rtw89_tx_8922a_addr_info() -> TestResult {
    // Single entry: len 100 at DMA 0x1_2345_6789.
    // length_opt = 100 | (0x1 << 11) | (1 << 15) [last] = 0x8864.
    let mut out = [0u8; 60];
    let written = match fill_addr_info_v1(&mut out, 100, 0x1_2345_6789) {
        Ok(n) => n,
        Err(_) => return TestResult::Fail("single-entry fill failed"),
    };
    if written != 6 {
        return TestResult::Fail("single-entry byte count wrong");
    }
    if u16::from_le_bytes(out[0..2].try_into().unwrap()) != 0x8864
        || u16::from_le_bytes(out[2..4].try_into().unwrap()) != 0x6789
        || u16::from_le_bytes(out[4..6].try_into().unwrap()) != 0x2345
    {
        return TestResult::Fail("single-entry words wrong");
    }
    // Two entries: 3000 bytes at DMA 0x1000_0000.
    // Entry 0: len 2044, no LS, dma 0x1000_0000.
    // Entry 1: len 956, LS set, dma 0x1000_0000 + 2044 = 0x1000_07FC.
    let mut out = [0u8; 60];
    let written = match fill_addr_info_v1(&mut out, 3000, 0x1000_0000) {
        Ok(n) => n,
        Err(_) => return TestResult::Fail("two-entry fill failed"),
    };
    if written != 12 {
        return TestResult::Fail("two-entry byte count wrong");
    }
    if u16::from_le_bytes(out[0..2].try_into().unwrap()) != 2044
        || u16::from_le_bytes(out[2..4].try_into().unwrap()) != 0x0000
        || u16::from_le_bytes(out[4..6].try_into().unwrap()) != 0x1000
    {
        return TestResult::Fail("first entry words wrong");
    }
    if u16::from_le_bytes(out[6..8].try_into().unwrap()) != (956 | (1 << 15))
        || u16::from_le_bytes(out[8..10].try_into().unwrap()) != 0x07FC
        || u16::from_le_bytes(out[10..12].try_into().unwrap()) != 0x1000
    {
        return TestResult::Fail("second entry words wrong");
    }
    // Refusals: over the 10-entry cap, DMA above 36 bits.
    let mut out = [0u8; 60];
    if fill_addr_info_v1(&mut out, 10 * 2044 + 1, 0x1000).is_ok()
        || fill_addr_info_v1(&mut out, 100, 1 << 36).is_ok()
    {
        return TestResult::Fail("addr-info fill accepted a bad input");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_tx_8922a_addr_info);

fn smoke_rtw89_tx_8922a_header() -> TestResult {
    // Body with WDINFO_EN set must come out cleared; WP seq0
    // carries sequence | VALID; total = 32 + 8 + 6 (100-byte frame).
    let mut body = zero_body();
    body[0..4].copy_from_slice(&(1u32 << 22).to_le_bytes());
    let header = match build_header(&body, 7, 0x20000, 100) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("build_header failed"),
    };
    if header.len() != 46 {
        return TestResult::Fail("header length wrong");
    }
    if u32::from_le_bytes(header[0..4].try_into().unwrap()) & (1 << 22) != 0 {
        return TestResult::Fail("WDINFO_EN not cleared");
    }
    if u16::from_le_bytes(header[32..34].try_into().unwrap()) != (7 | 0x8000) {
        return TestResult::Fail("WP seq0 wrong");
    }
    if header[34..40] != [0u8; 6] {
        return TestResult::Fail("WP seq1..3 not zero");
    }
    if u16::from_le_bytes(header[40..42].try_into().unwrap()) != (100 | (1 << 15)) {
        return TestResult::Fail("addr-info length_opt wrong");
    }
    // Refusals: empty frame, oversize frame, DMA above 36 bits.
    if build_header(&zero_body(), 0, 0x1000, 0).is_ok()
        || build_header(&zero_body(), 0, 0x1000, 0x4000).is_ok()
        || build_header(&zero_body(), 0, 1 << 36, 100).is_ok()
    {
        return TestResult::Fail("build_header accepted a bad input");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_tx_8922a_header);

fn smoke_rtw89_tx_8922a_header_with_info() -> TestResult {
    // With an info block: WDINFO_EN stays set, the 32 info bytes
    // follow the body, WP shifts to offset 64; total =
    // 32 + 32 + 8 + 6 (100-byte frame).
    let mut body = zero_body();
    body[0..4].copy_from_slice(&(1u32 << 22).to_le_bytes());
    let mut info = [0u8; 32];
    info[0] = 0x5A;
    info[16] = 0xA5;
    let header = match build_header_with_info(&body, Some(&info), 7, 0x20000, 100) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("build_header_with_info failed"),
    };
    if header.len() != 78 {
        return TestResult::Fail("info header length wrong");
    }
    if u32::from_le_bytes(header[0..4].try_into().unwrap()) & (1 << 22) == 0 {
        return TestResult::Fail("WDINFO_EN not set with info block");
    }
    if header[32..64] != info {
        return TestResult::Fail("info block bytes wrong");
    }
    if u16::from_le_bytes(header[64..66].try_into().unwrap()) != (7 | 0x8000) {
        return TestResult::Fail("WP seq0 wrong with info block");
    }
    if u16::from_le_bytes(header[72..74].try_into().unwrap()) != (100 | (1 << 15)) {
        return TestResult::Fail("addr-info length_opt wrong with info block");
    }
    // Without an info block the with-info builder matches the
    // plain builder byte for byte.
    let plain = match build_header(&body, 7, 0x20000, 100) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("build_header failed"),
    };
    let no_info = match build_header_with_info(&body, None, 7, 0x20000, 100) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("build_header_with_info(None) failed"),
    };
    if plain != no_info {
        return TestResult::Fail("build_header_with_info(None) must equal build_header");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_tx_8922a_header_with_info
);

fn smoke_rtw89_tx_8922a_submit_cycle() -> TestResult {
    // Channel 2, MACID 5, QSEL 0x02, 100-byte frame.
    let mut tx = match DataTx::new() {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("DataTx::new failed"),
    };
    let mut bd = vec![TxBd::default(); 256];
    let mut regs = Model::new();
    let prepared = match tx.prepare(PrepareArgs {
        channel: 2,
        mac_id: 5,
        qsel: 0x02,
        body: &zero_body(),
        header_dma: 0x20000,
        frame_dma: 0x10000,
        frame_len: 100,
        bd: &mut bd,
    }) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("prepare failed"),
    };
    if prepared.ticket.slot != 0 || prepared.ticket.sequence != 0 {
        return TestResult::Fail("first ticket wrong");
    }
    if prepared.header.len() != 46 {
        return TestResult::Fail("prepared header length wrong");
    }
    // TXBD[0]: header length, LS bit, header DMA 0x20000.
    if bd[0].length != 46 || bd[0].opt != TXBD_OPT_LS || bd[0].dma != 0x20000 {
        return TestResult::Fail("TXBD[0] wrong");
    }
    // Nothing published yet: kicking publishes + doorbells CH2
    // (idx 0xB108) with WP 1.
    let wp = match tx.kick(&mut regs, &prepared) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("kick failed"),
    };
    if wp != 1 || regs.regs16.get(&0xB108) != Some(&1) {
        return TestResult::Fail("kick doorbell wrong");
    }
    // Double kick is refused (slot already published).
    if tx.kick(&mut regs, &prepared).is_ok() {
        return TestResult::Fail("double kick accepted");
    }
    // RPQ release cycle: first the RP read-pointer update (fake
    // reports HW RP 0 — nothing DMA-complete yet), then the
    // Linux-format RPQ record: seq 0, status 1, qsel 0x02,
    // mac 5 → word = (1<<13) | (0x02<<8) | 5 = 0x2205. The
    // completion retires only once both halves arrive: the
    // report alone must NOT complete (dma_done is false until
    // the RP update passes the published slot).
    let mut regs = Model::new();
    regs.regs32.insert(0xB108, 0x0001_0000); // HW RP 1, host WP 0.
    let completed = match tx.observe_rp(&mut regs, 2) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("observe_rp failed"),
    };
    if !completed.is_empty() {
        return TestResult::Fail("RP update completed without a report");
    }
    let record = (1u32 << 13) | (0x02u32 << 8) | 5u32;
    let done = match tx.observe_report(&record.to_le_bytes()) {
        Ok(d) => d,
        Err(_) => return TestResult::Fail("observe_report failed"),
    };
    match done {
        Some(completion) if completion.status == 1 => {}
        _ => return TestResult::Fail("RPQ release did not complete"),
    }
    // Polluted record (bit 31) is refused.
    let polluted = (1u32 << 31) | record;
    if tx.observe_report(&polluted.to_le_bytes()).is_ok() {
        return TestResult::Fail("polluted RPQ record accepted");
    }
    // Prepare refusals: CH12 (H2C-only), MACID 32, FAST qsel,
    // oversize frame, DMA above the field.
    let mut bd = vec![TxBd::default(); 256];
    if tx
        .prepare(PrepareArgs {
            channel: 12,
            mac_id: 5,
            qsel: 0x02,
            body: &zero_body(),
            header_dma: 0x20000,
            frame_dma: 0x10000,
            frame_len: 100,
            bd: &mut bd,
        })
        .is_ok()
        || tx
            .prepare(PrepareArgs {
                channel: 2,
                mac_id: 32,
                qsel: 0x02,
                body: &zero_body(),
                header_dma: 0x20000,
                frame_dma: 0x10000,
                frame_len: 100,
                bd: &mut bd,
            })
            .is_ok()
        || tx
            .prepare(PrepareArgs {
                channel: 2,
                mac_id: 5,
                qsel: 0x14,
                body: &zero_body(),
                header_dma: 0x20000,
                frame_dma: 0x10000,
                frame_len: 100,
                bd: &mut bd,
            })
            .is_ok()
        || tx
            .prepare(PrepareArgs {
                channel: 2,
                mac_id: 5,
                qsel: 0x02,
                body: &zero_body(),
                header_dma: 0x20000,
                frame_dma: 0x10000,
                frame_len: 0x4000,
                bd: &mut bd,
            })
            .is_ok()
        || tx
            .prepare(PrepareArgs {
                channel: 2,
                mac_id: 5,
                qsel: 0x02,
                body: &zero_body(),
                header_dma: 0x20000,
                frame_dma: 1 << 36,
                frame_len: 100,
                bd: &mut bd,
            })
            .is_ok()
    {
        return TestResult::Fail("prepare accepted a bad input");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_tx_8922a_submit_cycle);

fn smoke_rtw89_tx_8922a_h2c() -> TestResult {
    // Depth-4 H2C ring: 3 usable slots (one reserved).
    let mut h2c = match H2cTx::new(4) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("H2cTx::new failed"),
    };
    let mut bd = vec![TxBd::default(); 4];
    let mut regs = Model::new();
    let first = match h2c.prepare_h2c(&mut bd, 0x30000, 64) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("first H2C prepare failed"),
    };
    if first.slot != 0 || first.next_wp != 1 {
        return TestResult::Fail("first H2C prepared values wrong");
    }
    if bd[0].length != 64 || bd[0].opt != TXBD_OPT_LS || bd[0].dma != 0x30000 {
        return TestResult::Fail("H2C TXBD wrong");
    }
    if h2c.kick_h2c(&mut regs, &first) != Ok(1) || regs.regs16.get(&0xB130) != Some(&1) {
        return TestResult::Fail("H2C kick doorbell wrong");
    }
    // Double kick of the same prepared buffer is refused.
    if h2c.kick_h2c(&mut regs, &first).is_ok() {
        return TestResult::Fail("double H2C kick accepted");
    }
    // Fill the ring (slots 1, 2), then the 4th prepare is full.
    for _ in 0..2 {
        let p = match h2c.prepare_h2c(&mut bd, 0x30000, 64) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("H2C fill prepare failed"),
        };
        if h2c.kick_h2c(&mut regs, &p).is_err() {
            return TestResult::Fail("H2C fill kick failed");
        }
    }
    if h2c.prepare_h2c(&mut bd, 0x30000, 64).is_ok() {
        return TestResult::Fail("full H2C ring accepted a prepare");
    }
    // Refusals: bad depths, empty/oversize buffers, DMA too high.
    if H2cTx::new(1).is_ok()
        || H2cTx::new(257).is_ok()
        || h2c.prepare_h2c(&mut bd, 0x30000, 0).is_ok()
        || h2c.prepare_h2c(&mut bd, 1 << 40, 64).is_ok()
    {
        return TestResult::Fail("H2C accepted a bad input");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_tx_8922a_h2c);
