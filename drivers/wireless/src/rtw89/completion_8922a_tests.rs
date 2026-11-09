// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixture tests for the BE C2H completion path (chip-row step 7).
//! Expected values are computed in the test from the Linux
//! `pci.c` / `pci.h` / `core.c` / `fw.c` / `txrx.h` bit positions
//! and ring rules, never from the module under test. Register
//! values are canned MMIO; ring buffers are plain byte vectors
//! standing in for the probe-allocated DMA buffers.

use super::chip_8922a;
use super::completion_8922a::Error as CompletionError;
use super::completion_8922a::*;
use super::dma::{TxBd, TXCH_NUM};
use super::dma_be::Regs;
use super::efuse_be::BeFactory;
use super::fwcmd_8922a::H2cCmd;
use super::irq::Events;
use super::prepared_8922a::Error as PreparedError;
use super::prepared_8922a::*;
use super::rx_packet::Ack;
use super::rx_packet::C2h;
use super::station_8922a::{Band, Request};
use super::tx_8922a::{PrepareArgs, BUFFER_DMA_MASK, DATA_RING_DEPTH, FRAME_DMA_MASK};
use super::txrx_be::{encode_txwd_be, TxwdBeInfo};
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use narf_io::alloc_coherent_masked;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::id::DomainId;

/// Fixture register bank implementing [`Regs`]. Unlike the
/// `prepared_8922a` fixture, a 16-bit doorbell write also updates
/// the low half of the 32-bit idx view, as real MMIO does: the
/// worker re-reads the idx register after doorbells, so the two
/// views must agree.
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

    fn set_idx(&mut self, addr: u32, rp: u16, wp: u16) {
        self.regs32.insert(addr, ((rp as u32) << 16) | wp as u32);
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
        let old = self.regs32.get(&address).copied().unwrap_or(0);
        self.regs32.insert(address, (old & !0xffff) | value as u32);
    }
}

fn factory() -> BeFactory {
    BeFactory {
        mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        rfe_type: 0,
        xtal_cap: 0,
        country: [b'U', b'S'],
        phycap: [0u8; chip_8922a::PHYCAP_SIZE],
        cv: None,
        thermal_k: None,
        secure: super::efuse_be::SecureInfo::disabled(),
    }
}

fn base_req() -> Request<'static> {
    Request {
        peer: [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB],
        band: Band::Ghz5,
        width_mhz: 160,
        primary: 36,
        nss: 2,
        aid: 7,
        port: 0,
        ap_mode: false,
        station_mode: true,
        eht_support: true,
        punctured: 0,
        peer_ies: &[],
        has_he: true,
        mgq_rpt_en: false,
        p2p: false,
        six_ghz: None,
    }
}

/// Build a BE RXD from the Linux `txrx.h` BE_RXD_* positions:
/// dword0 pkt_len bits 13:0, shift 15:14, drv 19:18, hdr 21:20,
/// phy 23:22, type 29:24, long bit 31; dword2 mac_id bits 9:0,
/// seq 27:16, tid 31:28; dword3 from the caller.
#[allow(clippy::too_many_arguments)] // the BE RXD dword fields, one per Linux txrx.h position
fn rxd(
    pkt_type: u8,
    pkt_len: u16,
    shift: u8,
    drv: u8,
    hdr: u8,
    phy: u8,
    mac_id: u16,
    seq: u16,
    tid: u8,
    dw2_extra: u32,
    dw3: u32,
    long: bool,
) -> Vec<u8> {
    let dw0 = (pkt_len as u32 & 0x3fff)
        | ((shift as u32 & 0x3) << 14)
        | ((drv as u32 & 0x3) << 18)
        | ((hdr as u32 & 0x3) << 20)
        | ((phy as u32 & 0x3) << 22)
        | ((pkt_type as u32 & 0x3f) << 24)
        | if long { 1 << 31 } else { 0 };
    let dw2 = (mac_id as u32 & 0x3ff)
        | ((seq as u32 & 0xfff) << 16)
        | ((tid as u32 & 0xf) << 28)
        | dw2_extra;
    let size = if long { 40 } else { 24 };
    let mut out = vec![0u8; size];
    out[0..4].copy_from_slice(&dw0.to_le_bytes());
    out[8..12].copy_from_slice(&dw2.to_le_bytes());
    out[12..16].copy_from_slice(&dw3.to_le_bytes());
    out
}

/// RXBD-info word (`pci.h:1536..1539`): FS bit 15, LS bit 14,
/// write size bits 13:0.
fn info_word(fs: bool, ls: bool, len: usize) -> u32 {
    ((fs as u32) << 15) | ((ls as u32) << 14) | (len as u32 & 0x3fff)
}

/// One RX buffer: [RXBD-info][content...], sized exactly.
fn segment(fs: bool, ls: bool, content: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + content.len());
    buf.extend_from_slice(&info_word(fs, ls, 4 + content.len()).to_le_bytes());
    buf.extend_from_slice(content);
    buf
}

/// One RPQ buffer: [RXBD-info][short RXD][records...]. The RPQ
/// RXD type is not dispatched on in Linux, so it stays 0.
fn rpq_buffer(records: &[[u8; 4]]) -> Vec<u8> {
    let mut content = rxd(
        0,
        (records.len() * 4) as u16,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        false,
    );
    for record in records {
        content.extend_from_slice(record);
    }
    segment(true, true, &content)
}

/// One 4-byte RPQ record (Linux's original format, `parse_report`):
/// POLLUTED bit 31 clear, SEQ bits 30:16, TX_STATUS bits 15:13,
/// QSEL bits 12:8, MACID bits 7:0.
fn record(seq: u16, status: u8, qsel: u8, mac: u8) -> [u8; 4] {
    (((seq as u32 & 0x7fff) << 16)
        | ((status as u32 & 0x7) << 13)
        | ((qsel as u32) << 8)
        | mac as u32)
        .to_le_bytes()
}

/// An owner with rings programmed at `rx_len` and one admitted
/// station (MACID 0). Returns the owner and a fresh register
/// bank holding the programmed ring state.
fn programmed_owner(rx_len: u16) -> Result<(Prepared8922a, Model), &'static str> {
    let mut owner = Prepared8922a::new(factory(), 0).map_err(|_| "new failed")?;
    let mut regs = Model::new();
    let tx_phys: [u64; TXCH_NUM] = core::array::from_fn(|i| 0x1_0000 + (i as u64) * 0x800);
    let rx_phys: [u64; 2] = [0x2_0000, 0x2_1000];
    owner
        .program_rings(&mut regs, &tx_phys, &rx_phys, 256, rx_len)
        .map_err(|_| "program_rings failed")?;
    owner
        .admit_station(&base_req())
        .map_err(|_| "admit_station failed")?;
    Ok((owner, regs))
}

/// `count` empty buffers (the worker only reads the slots the
/// idx register says are ready).
fn empty_buffers(count: usize) -> Vec<Vec<u8>> {
    (0..count).map(|_| Vec::new()).collect()
}

fn refs(bufs: &mut [Vec<u8>]) -> Vec<&mut [u8]> {
    bufs.iter_mut().map(|buf| buf.as_mut_slice()).collect()
}

fn smoke_rtw89_completion_8922a_available() -> TestResult {
    // Eq-is-full seed: wp = len - 1, nothing readable at RP 0.
    if available_be(255, 255, 256) != Ok(0)
        || available_be((1 << 16) | 255, 255, 256) != Ok(1)
        || available_be((255 << 16) | 255, 255, 256) != Ok(255)
    {
        return TestResult::Fail("available_be seed cases wrong");
    }
    // Ring wrap at len 4: wp 3, RP 0..3, then wp 0.
    if available_be(3, 3, 4) != Ok(0)
        || available_be((1 << 16) | 3, 3, 4) != Ok(1)
        || available_be((3 << 16) | 3, 3, 4) != Ok(3)
        || available_be(0, 0, 4) != Ok(3)
        || available_be(2 << 16, 0, 4) != Ok(1)
        || available_be(1 << 16, 0, 4) != Ok(0)
    {
        return TestResult::Fail("available_be wrap cases wrong");
    }
    // Desync: low half not the host WP, RP past the ring, gone
    // device, degenerate depth, WP past the ring.
    if available_be(1 << 16, 255, 256).is_ok()
        || available_be((256 << 16) | 255, 255, 256).is_ok()
        || available_be(u32::MAX, 255, 256).is_ok()
        || available_be(0, 0, 1).is_ok()
        || available_be(0, 256, 256).is_ok()
    {
        return TestResult::Fail("available_be must refuse desync");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_completion_8922a_available
);

fn smoke_rtw89_completion_8922a_routes() -> TestResult {
    let c2h = |category: u8, class: u8, function: u8| C2h {
        category,
        class,
        function,
        bytes: Vec::new(),
    };
    if route_c2h(&c2h(0, 0, 0)) != Route::Test
        || route_c2h(&c2h(1, 0, 0)) != (Route::Mac { class: 0, func: 0 })
        || route_c2h(&c2h(1, 0, 1)) != (Route::Mac { class: 0, func: 1 })
        || route_c2h(&c2h(1, 0x18, 2))
            != (Route::Mac {
                class: 0x18,
                func: 2,
            })
        || route_c2h(&c2h(2, 0x10, 0))
            != (Route::OutsrcBtc {
                class: 0x10,
                func: 0,
            })
        || route_c2h(&c2h(2, 0x17, 3))
            != (Route::OutsrcBtc {
                class: 0x17,
                func: 3,
            })
        || route_c2h(&c2h(2, 0x18, 0))
            != (Route::OutsrcPhy {
                class: 0x18,
                func: 0,
            })
        || route_c2h(&c2h(2, 0x00, 0))
            != (Route::OutsrcPhy {
                class: 0x00,
                func: 0,
            })
        || route_c2h(&c2h(3, 0, 0)) != (Route::UnknownCategory { category: 3 })
        || route_c2h(&c2h(255, 0, 0)) != (Route::UnknownCategory { category: 255 })
    {
        return TestResult::Fail("C2H routing wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_completion_8922a_routes
);

/// Submit one CH0 data frame (MACID 0, QSEL 0) through the
/// Prepared owner and retain its real DMA buffers, returning
/// the wire sequence.
fn submit_frame(owner: &mut Prepared8922a, regs: &mut Model) -> Result<u16, &'static str> {
    let mut body = [0u8; 32];
    if encode_txwd_be(
        &TxwdBeInfo {
            channel: 0,
            qsel: 0,
            mac_id: 0,
            pkt_size: 100,
        },
        &mut body,
    )
    .is_none()
    {
        return Err("encode_txwd_be failed");
    }
    let header_buf = alloc_coherent_masked(MAX_HEADER_BYTES, DomainId::DRIVER_0, BUFFER_DMA_MASK)
        .map_err(|_| "header alloc failed")?;
    let frame_buf = alloc_coherent_masked(100, DomainId::DRIVER_0, FRAME_DMA_MASK)
        .map_err(|_| "frame alloc failed")?;
    let header_dma = header_buf.dma_addr().raw();
    let frame_dma = frame_buf.dma_addr().raw();
    let mut bd = vec![TxBd::default(); DATA_RING_DEPTH as usize];
    let prepared = owner
        .prepare_data(PrepareArgs {
            channel: 0,
            mac_id: 0,
            qsel: 0,
            body: &body,
            header_dma,
            frame_dma,
            frame_len: 100,
            bd: &mut bd,
        })
        .map_err(|_| "prepare_data failed")?;
    let sequence = prepared.ticket.sequence;
    owner.retain_data(header_buf, frame_buf);
    owner
        .kick_data(regs, &prepared)
        .map_err(|_| "kick_data failed")?;
    Ok(sequence)
}

fn smoke_rtw89_completion_8922a_rpq_end_to_end() -> TestResult {
    let (mut owner, mut regs) = match programmed_owner(256) {
        Ok(pair) => pair,
        Err(why) => return TestResult::Fail(why),
    };
    let sequence = match submit_frame(&mut owner, &mut regs) {
        Ok(sequence) => sequence,
        Err(why) => return TestResult::Fail(why),
    };
    if sequence != 0 {
        return TestResult::Fail("first frame sequence must be 0");
    }
    // One RPQ buffer ready (RPQ idx 0xB164: HW RP 1, host WP 255)
    // holding the record for sequence 0, status 1; the TX ring
    // (CH0 idx 0xB100) shows RP 1 so the DMA half is also done.
    let mut rpq = empty_buffers(256);
    rpq[0] = rpq_buffer(&[record(0, 1, 0, 0)]);
    let mut rxq = empty_buffers(256);
    regs.set_idx(0xB164, 1, 255);
    regs.set_idx(0xB100, 1, 1);
    let header_dma = match owner.complete(
        &mut regs,
        Events {
            rpq: true,
            ..Default::default()
        },
        &mut refs(&mut rxq),
        &mut refs(&mut rpq),
        64,
    ) {
        Ok(outcome) => {
            if outcome.tx.len() != 1
                || outcome.tx[0].status != 1
                || outcome.work_done != 1
                || outcome.dropped != 0
                || !outcome.rearm
            {
                return TestResult::Fail("RPQ outcome wrong");
            }
            (outcome.tx[0].header_dma, outcome.tx[0].frame_dma)
        }
        Err(_) => return TestResult::Fail("complete failed"),
    };
    // The retained buffers are freed by the completion: a second
    // release of the same addresses finds nothing, and the RPQ
    // doorbell advanced past slot 0.
    if owner.release_data(header_dma.0, header_dma.1) {
        return TestResult::Fail("retained buffers must be freed by the completion");
    }
    if regs.regs16.get(&0xB164) != Some(&0) {
        return TestResult::Fail("RPQ doorbell must end at slot 0");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_completion_8922a_rpq_end_to_end
);

fn smoke_rtw89_completion_8922a_rxq_wifi() -> TestResult {
    let (mut owner, mut regs) = match programmed_owner(256) {
        Ok(pair) => pair,
        Err(why) => return TestResult::Fail(why),
    };
    // 28-byte frame + 4-byte FCS; short RXD, A1 match, seq 0x123,
    // TID 5. A second buffer carries the same frame under a long
    // RXD (40 bytes, data starts at 44).
    let frame: Vec<u8> = (0..28u8).collect();
    let mut payload = frame.clone();
    payload.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let dw3 = 1 << 10; // A1_MATCH
    let short = rxd(0, 32, 0, 0, 0, 0, 0, 0x123, 5, 0, dw3, false);
    let long = rxd(0, 32, 0, 0, 0, 0, 0, 0x124, 6, 0, dw3, true);
    let mut rxq = empty_buffers(256);
    let mut content = short;
    content.extend_from_slice(&payload);
    rxq[0] = segment(true, true, &content);
    let mut content = long;
    content.extend_from_slice(&payload);
    rxq[1] = segment(true, true, &content);
    let mut rpq = empty_buffers(256);
    regs.set_idx(0xB160, 2, 255);
    let outcome = match owner.complete(
        &mut regs,
        Events {
            rx: true,
            ..Default::default()
        },
        &mut refs(&mut rxq),
        &mut refs(&mut rpq),
        64,
    ) {
        Ok(outcome) => outcome,
        Err(_) => return TestResult::Fail("complete failed"),
    };
    if outcome.frames.len() != 2
        || outcome.frames[0].1 != frame
        || outcome.frames[1].1 != frame
        || outcome.frames[0].0.seq != 0x123
        || outcome.frames[0].0.tid != 5
        || outcome.frames[1].0.seq != 0x124
        || outcome.frames[1].0.tid != 6
        || !outcome.frames[0].0.to_self
        || outcome.frames[0].0.reorder
        || outcome.frames[0].0.ampdu
        || outcome.work_done != 2
        || outcome.dropped != 0
        || !outcome.rearm
    {
        return TestResult::Fail("RXQ WIFI outcome wrong");
    }
    if regs.regs16.get(&0xB160) != Some(&1) {
        return TestResult::Fail("RXQ doorbell must end at slot 1");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_completion_8922a_rxq_wifi
);

fn smoke_rtw89_completion_8922a_rxq_c2h() -> TestResult {
    let (mut owner, mut regs) = match programmed_owner(256) {
        Ok(pair) => pair,
        Err(why) => return TestResult::Fail(why),
    };
    // MAC INFO REC_ACK, sequence 0x42: w0 = cat 1 | class 0 |
    // func 0, w1 = 12, w2 = cat 1 | class 0 | func 0 | seq<<16.
    let mut rec_ack = Vec::new();
    rec_ack.extend_from_slice(&1u32.to_le_bytes());
    rec_ack.extend_from_slice(&12u32.to_le_bytes());
    rec_ack.extend_from_slice(&(1u32 | (0x42 << 16)).to_le_bytes());
    // MAC INFO DONE_ACK, sequence 7, result 0: w0 = cat 1 | func 1,
    // w2 = cat 1 | func 1 | result<<16 | seq<<24.
    let mut done_ack = Vec::new();
    done_ack.extend_from_slice(&0x101u32.to_le_bytes());
    done_ack.extend_from_slice(&12u32.to_le_bytes());
    done_ack.extend_from_slice(&(0x101u32 | (7 << 24)).to_le_bytes());
    let mut rxq = empty_buffers(256);
    let mut content = rxd(10, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, false);
    content.extend_from_slice(&rec_ack);
    rxq[0] = segment(true, true, &content);
    let mut content = rxd(10, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, false);
    content.extend_from_slice(&done_ack);
    rxq[1] = segment(true, true, &content);
    let mut rpq = empty_buffers(256);
    regs.set_idx(0xB160, 2, 255);
    let outcome = match owner.complete(
        &mut regs,
        Events {
            rx: true,
            ..Default::default()
        },
        &mut refs(&mut rxq),
        &mut refs(&mut rpq),
        64,
    ) {
        Ok(outcome) => outcome,
        Err(_) => return TestResult::Fail("complete failed"),
    };
    if outcome.c2h.len() != 2
        || outcome.c2h[0].route != (Route::Mac { class: 0, func: 0 })
        || outcome.c2h[0].c2h.category != 1
        || outcome.c2h[0].c2h.class != 0
        || outcome.c2h[0].c2h.function != 0
        || !matches!(&outcome.c2h[0].ack, Some(ack) if ack.sequence == 0x42 && ack.result.is_none())
        || outcome.c2h[1].route != (Route::Mac { class: 0, func: 1 })
        || !matches!(&outcome.c2h[1].ack, Some(ack) if ack.sequence == 7 && ack.result == Some(0))
        || outcome.work_done != 2
        || outcome.dropped != 0
    {
        return TestResult::Fail("RXQ C2H outcome wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_completion_8922a_rxq_c2h
);

fn smoke_rtw89_completion_8922a_h2c_ack_release() -> TestResult {
    let (mut owner, mut regs) = match programmed_owner(256) {
        Ok(pair) => pair,
        Err(why) => return TestResult::Fail(why),
    };
    // Frame two H2C commands (MAC / class 5 / func 2, 4-byte
    // bodies, both acks) and retain their buffers. Sequences
    // allocate 0 then 1 from the shared allocator.
    let mut framed_bytes = [0u8; 12];
    let (framed0, total0) = match owner.frame_h2c(
        H2cCmd {
            cat: 0x1,
            class: 0x5,
            func: 0x2,
        },
        &[0xAA, 0xBB, 0xCC, 0xDD],
        true,
        true,
        &mut framed_bytes,
    ) {
        Some(framed) => framed,
        None => return TestResult::Fail("frame_h2c for seq 0 failed"),
    };
    let buf0 = match alloc_coherent_masked(total0, DomainId::DRIVER_0, BUFFER_DMA_MASK) {
        Ok(buf) => buf,
        Err(_) => return TestResult::Fail("H2C buffer alloc failed"),
    };
    owner.retain_h2c(framed0, buf0);
    let (framed1, total1) = match owner.frame_h2c(
        H2cCmd {
            cat: 0x1,
            class: 0x5,
            func: 0x2,
        },
        &[0x11, 0x22, 0x33, 0x44],
        true,
        true,
        &mut framed_bytes,
    ) {
        Some(framed) => framed,
        None => return TestResult::Fail("frame_h2c for seq 1 failed"),
    };
    let buf1 = match alloc_coherent_masked(total1, DomainId::DRIVER_0, BUFFER_DMA_MASK) {
        Ok(buf) => buf,
        Err(_) => return TestResult::Fail("H2C buffer alloc failed"),
    };
    owner.retain_h2c(framed1, buf1);
    if framed0.seq != 0 || framed1.seq != 1 {
        return TestResult::Fail("framed sequences must allocate 0 then 1");
    }
    // RXQ buffer 0: MAC INFO DONE_ACK echoing the seq-1 command
    // (w0 = cat 1 | func 1; w1 = 12; w2 = cat 1 | class 5 |
    // func 2 | result 0<<16 | seq 1<<24).
    let mut done_ack1 = Vec::new();
    done_ack1.extend_from_slice(&0x101u32.to_le_bytes());
    done_ack1.extend_from_slice(&12u32.to_le_bytes());
    done_ack1.extend_from_slice(&(0x215u32 | (1u32 << 24)).to_le_bytes());
    // RXQ buffer 1: DONE_ACK for a sequence that was never
    // framed (seq 9) — it must release nothing.
    let mut done_ack9 = Vec::new();
    done_ack9.extend_from_slice(&0x101u32.to_le_bytes());
    done_ack9.extend_from_slice(&12u32.to_le_bytes());
    done_ack9.extend_from_slice(&(0x215u32 | (9u32 << 24)).to_le_bytes());
    let mut rxq = empty_buffers(256);
    let mut content = rxd(10, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, false);
    content.extend_from_slice(&done_ack1);
    rxq[0] = segment(true, true, &content);
    let mut content = rxd(10, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, false);
    content.extend_from_slice(&done_ack9);
    rxq[1] = segment(true, true, &content);
    let mut rpq = empty_buffers(256);
    regs.set_idx(0xB160, 2, 255);
    let outcome = match owner.complete(
        &mut regs,
        Events {
            rx: true,
            ..Default::default()
        },
        &mut refs(&mut rxq),
        &mut refs(&mut rpq),
        64,
    ) {
        Ok(outcome) => outcome,
        Err(_) => return TestResult::Fail("complete failed"),
    };
    if outcome.c2h.len() != 2 || outcome.work_done != 2 {
        return TestResult::Fail("RXQ C2H outcome wrong");
    }
    if outcome.h2c_released.len() != 1
        || outcome.h2c_released[0].framed != framed1
        || outcome.h2c_released[0].result != Some(0)
    {
        return TestResult::Fail("only the seq-1 ack must release, with result 0");
    }
    // The seq-0 buffer survives: a direct release by its ack
    // still finds it, and a repeat finds nothing.
    let ack0 = Ack {
        category: 1,
        class: 5,
        function: 2,
        sequence: 0,
        result: Some(0),
    };
    match owner.release_h2c_by_ack(&ack0) {
        Some(released) if released.framed == framed0 => {}
        _ => return TestResult::Fail("seq-0 buffer must survive complete()"),
    }
    if owner.release_h2c_by_ack(&ack0).is_some() {
        return TestResult::Fail("double release accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_completion_8922a_h2c_ack_release
);

fn smoke_rtw89_completion_8922a_halt() -> TestResult {
    let (mut owner, mut regs) = match programmed_owner(256) {
        Ok(pair) => pair,
        Err(why) => return TestResult::Fail(why),
    };
    let mut rxq = empty_buffers(256);
    let mut rpq = empty_buffers(256);
    regs.set_idx(0xB160, 1, 255);
    regs.set_idx(0xB164, 1, 255);
    let writes_before = regs.regs16.len();
    if owner.complete(
        &mut regs,
        Events {
            halt_c2h: true,
            rx: true,
            rpq: true,
            ..Default::default()
        },
        &mut refs(&mut rxq),
        &mut refs(&mut rpq),
        64,
    ) != Err(PreparedError::Completion(CompletionError::Halted))
    {
        return TestResult::Fail("halt_c2h must fail with Halted");
    }
    if owner.complete(
        &mut regs,
        Events {
            watchdog: true,
            ..Default::default()
        },
        &mut refs(&mut rxq),
        &mut refs(&mut rpq),
        64,
    ) != Err(PreparedError::Completion(CompletionError::Halted))
    {
        return TestResult::Fail("watchdog must fail with Halted");
    }
    // A halted run drains nothing: no doorbell writes at all.
    if regs.regs16.len() != writes_before {
        return TestResult::Fail("halted complete must not touch the rings");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_completion_8922a_halt);

fn smoke_rtw89_completion_8922a_refusals() -> TestResult {
    let mut owner = match Prepared8922a::new(factory(), 0) {
        Ok(owner) => owner,
        Err(_) => return TestResult::Fail("new failed"),
    };
    let mut regs = Model::new();
    let mut rxq = empty_buffers(256);
    let mut rpq = empty_buffers(256);
    // Rings not programmed yet.
    if owner.complete(
        &mut regs,
        Events {
            rx: true,
            ..Default::default()
        },
        &mut refs(&mut rxq),
        &mut refs(&mut rpq),
        64,
    ) != Err(PreparedError::NotProgrammed)
    {
        return TestResult::Fail("complete before program_rings must be NotProgrammed");
    }
    let (mut owner, mut regs) = match programmed_owner(256) {
        Ok(pair) => pair,
        Err(why) => return TestResult::Fail(why),
    };
    if owner.complete(
        &mut regs,
        Events {
            rx: true,
            ..Default::default()
        },
        &mut refs(&mut rxq),
        &mut refs(&mut rpq),
        0,
    ) != Err(PreparedError::Completion(CompletionError::Budget))
        || owner.complete(
            &mut regs,
            Events {
                rx: true,
                ..Default::default()
            },
            &mut refs(&mut rxq),
            &mut refs(&mut rpq),
            257,
        ) != Err(PreparedError::Completion(CompletionError::Budget))
    {
        return TestResult::Fail("budget 0 / 257 must be refused");
    }
    // rx_unavailable is diagnostic: recorded, no error, and an
    // empty drain still rearms.
    match owner.complete(
        &mut regs,
        Events {
            rx_unavailable: true,
            rx: true,
            ..Default::default()
        },
        &mut refs(&mut rxq),
        &mut refs(&mut rpq),
        64,
    ) {
        Ok(outcome) if outcome.rx_unavailable && outcome.work_done == 0 && outcome.rearm => {}
        _ => return TestResult::Fail("rx_unavailable outcome wrong"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_completion_8922a_refusals
);

fn smoke_rtw89_completion_8922a_rxq_drops_and_continues() -> TestResult {
    let (mut owner, mut regs) = match programmed_owner(256) {
        Ok(pair) => pair,
        Err(why) => return TestResult::Fail(why),
    };
    let frame: Vec<u8> = (0..28u8).collect();
    let mut payload = frame.clone();
    payload.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let dw3 = 1 << 10; // A1_MATCH
    let mut rxq = empty_buffers(256);
    // Slot 0: CRC-error WIFI (dropped).
    let mut content = rxd(0, 32, 0, 0, 0, 0, 0, 1, 0, 0, dw3 | (1 << 6), false);
    content.extend_from_slice(&payload);
    rxq[0] = segment(true, true, &content);
    // Slot 1: unknown packet type 7 (dropped).
    let mut content = rxd(7, 32, 0, 0, 0, 0, 0, 2, 0, 0, dw3, false);
    content.extend_from_slice(&payload);
    rxq[1] = segment(true, true, &content);
    // Slot 2: the same good frame (delivered).
    let mut content = rxd(0, 32, 0, 0, 0, 0, 0, 3, 0, 0, dw3, false);
    content.extend_from_slice(&payload);
    rxq[2] = segment(true, true, &content);
    let mut rpq = empty_buffers(256);
    regs.set_idx(0xB160, 3, 255);
    let outcome = match owner.complete(
        &mut regs,
        Events {
            rx: true,
            ..Default::default()
        },
        &mut refs(&mut rxq),
        &mut refs(&mut rpq),
        64,
    ) {
        Ok(outcome) => outcome,
        Err(_) => return TestResult::Fail("complete failed"),
    };
    if outcome.frames.len() != 1
        || outcome.frames[0].1 != frame
        || outcome.frames[0].0.seq != 3
        || outcome.dropped != 2
        || outcome.work_done != 3
    {
        return TestResult::Fail("drop-and-continue outcome wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_completion_8922a_rxq_drops_and_continues
);

fn smoke_rtw89_completion_8922a_rxq_multisegment() -> TestResult {
    let (mut owner, mut regs) = match programmed_owner(256) {
        Ok(pair) => pair,
        Err(why) => return TestResult::Fail(why),
    };
    // 200-byte packet (196-byte frame + 4-byte FCS) split 100/100
    // across two segments.
    let mut packet = vec![0xAAu8; 100];
    packet.extend_from_slice(&[0xBB; 96]);
    packet.extend_from_slice(&[0xCC; 4]);
    let dw3 = 1 << 10; // A1_MATCH
    let mut rxq = empty_buffers(256);
    let mut first = rxd(0, 200, 0, 0, 0, 0, 0, 9, 0, 0, dw3, false);
    first.extend_from_slice(&packet[..100]);
    rxq[0] = segment(true, false, &first);
    rxq[1] = segment(false, true, &packet[100..]);
    let mut rpq = empty_buffers(256);
    regs.set_idx(0xB160, 2, 255);
    let outcome = match owner.complete(
        &mut regs,
        Events {
            rx: true,
            ..Default::default()
        },
        &mut refs(&mut rxq),
        &mut refs(&mut rpq),
        64,
    ) {
        Ok(outcome) => outcome,
        Err(_) => return TestResult::Fail("complete failed"),
    };
    let mut expected = vec![0xAAu8; 100];
    expected.extend_from_slice(&[0xBB; 96]);
    if outcome.frames.len() != 1 || outcome.frames[0].1 != expected || outcome.work_done != 2 {
        return TestResult::Fail("multi-segment outcome wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_completion_8922a_rxq_multisegment
);

fn smoke_rtw89_completion_8922a_rxq_ppdu() -> TestResult {
    let (mut owner, mut regs) = match programmed_owner(256) {
        Ok(pair) => pair,
        Err(why) => return TestResult::Fail(why),
    };
    // PPDU status, phy report present (phy_rpt_sz 1): the 8-byte
    // report follows the RXD and carries RSSI 0x123 in dword0.
    let report = [0x12u8, 0x34, 0x56, 0x78, 0, 0, 0, 0];
    let body: Vec<u8> = (0..16u8).collect();
    let mut content = rxd(1, 16, 0, 0, 0, 1, 3, 0, 0, 0, 0, false);
    content.extend_from_slice(&report);
    content.extend_from_slice(&body);
    let mut rxq = empty_buffers(256);
    rxq[0] = segment(true, true, &content);
    let mut rpq = empty_buffers(256);
    regs.set_idx(0xB160, 1, 255);
    let outcome = match owner.complete(
        &mut regs,
        Events {
            rx: true,
            ..Default::default()
        },
        &mut refs(&mut rxq),
        &mut refs(&mut rpq),
        64,
    ) {
        Ok(outcome) => outcome,
        Err(_) => return TestResult::Fail("complete failed"),
    };
    if outcome.ppdu.len() != 1
        || outcome.ppdu[0].mac_id != 3
        || outcome.ppdu[0].phy_rssi_raw != Some(0x123)
        || outcome.ppdu[0].bytes != body
        || outcome.work_done != 1
    {
        return TestResult::Fail("PPDU outcome wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_completion_8922a_rxq_ppdu
);

fn smoke_rtw89_completion_8922a_rpq_stale_record() -> TestResult {
    let (mut owner, mut regs) = match programmed_owner(256) {
        Ok(pair) => pair,
        Err(why) => return TestResult::Fail(why),
    };
    let sequence = match submit_frame(&mut owner, &mut regs) {
        Ok(sequence) => sequence,
        Err(why) => return TestResult::Fail(why),
    };
    // One RPQ buffer holding a stale record (sequence 9, never
    // submitted), a polluted record (bit 31), then the good
    // record for the submitted frame.
    let mut polluted = record(0, 0, 0, 0);
    polluted[3] |= 0x80;
    let mut rpq = empty_buffers(256);
    rpq[0] = rpq_buffer(&[record(9, 0, 0, 0), polluted, record(sequence, 0, 0, 0)]);
    let mut rxq = empty_buffers(256);
    regs.set_idx(0xB164, 1, 255);
    regs.set_idx(0xB100, 1, 1);
    let outcome = match owner.complete(
        &mut regs,
        Events {
            rpq: true,
            ..Default::default()
        },
        &mut refs(&mut rxq),
        &mut refs(&mut rpq),
        64,
    ) {
        Ok(outcome) => outcome,
        Err(_) => return TestResult::Fail("complete failed"),
    };
    if outcome.tx.len() != 1
        || outcome.tx[0].status != 0
        || outcome.dropped != 2
        || outcome.work_done != 1
    {
        return TestResult::Fail("stale-record outcome wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_completion_8922a_rpq_stale_record
);

fn smoke_rtw89_completion_8922a_budget_and_wrap() -> TestResult {
    // 4-deep rings: the worker starts at WP 3 and wraps past 0.
    let (mut owner, mut regs) = match programmed_owner(4) {
        Ok(pair) => pair,
        Err(why) => return TestResult::Fail(why),
    };
    let frame: Vec<u8> = (0..28u8).collect();
    let mut payload = frame.clone();
    payload.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let dw3 = 1 << 10; // A1_MATCH
    let mut rxq = empty_buffers(4);
    for (slot, seq) in [(0, 1), (1, 2), (2, 3)] {
        let mut content = rxd(0, 32, 0, 0, 0, 0, 0, seq, 0, 0, dw3, false);
        content.extend_from_slice(&payload);
        rxq[slot] = segment(true, true, &content);
    }
    let mut rpq = empty_buffers(4);
    regs.set_idx(0xB160, 3, 3);
    // Budget 2 of 3 ready buffers: work 2, no rearm, the third
    // frame is still queued.
    let outcome = match owner.complete(
        &mut regs,
        Events {
            rx: true,
            ..Default::default()
        },
        &mut refs(&mut rxq),
        &mut refs(&mut rpq),
        2,
    ) {
        Ok(outcome) => outcome,
        Err(_) => return TestResult::Fail("first complete failed"),
    };
    if outcome.frames.len() != 2 || outcome.work_done != 2 || outcome.rearm {
        return TestResult::Fail("budget-capped outcome wrong");
    }
    if regs.regs16.get(&0xB160) != Some(&1) {
        return TestResult::Fail("doorbell must end at slot 1");
    }
    // The idx register still reports RP 3: one buffer remains,
    // across the WP wrap (slot 2 follows WP 1; the next wrap
    // would be slot 3, then 0).
    let outcome = match owner.complete(
        &mut regs,
        Events {
            rx: true,
            ..Default::default()
        },
        &mut refs(&mut rxq),
        &mut refs(&mut rpq),
        2,
    ) {
        Ok(outcome) => outcome,
        Err(_) => return TestResult::Fail("second complete failed"),
    };
    if outcome.frames.len() != 1
        || outcome.frames[0].0.seq != 3
        || outcome.work_done != 1
        || !outcome.rearm
    {
        return TestResult::Fail("wrap drain outcome wrong");
    }
    if regs.regs16.get(&0xB160) != Some(&2) {
        return TestResult::Fail("doorbell must end at slot 2");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_completion_8922a_budget_and_wrap
);
