// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8922A BE C2H completion path (chip-row step 7).
//!
//! The consumer of the classified interrupt events step 6 armed:
//! the NAPI-order worker that drains the RPQ (TX-completion
//! reports) and RXQ (received packets, including C2H firmware
//! messages) rings for an admitted 8922A device, then reports
//! whether the interrupt mask may be re-enabled. It mirrors Linux
//! `rtw89_pci_napi_poll` (`pci.c:4517`):
//!
//! 1. Clear RPQ ISR, poll RPQ DMA (`rtw89_pci_poll_rpq_dma`):
//!    recalc the readable count from the idx register, then
//!    `rtw89_pci_release_tx` walks each RPQ buffer's 4-byte
//!    records (`rtw89_pci_release_tx_skbs`) into TX status.
//! 2. Clear RXQ ISR, poll RXQ DMA (`rtw89_pci_poll_rxq_dma`):
//!    recalc, then `rtw89_pci_rxbd_deliver` assembles FS/LS
//!    segments and `rtw89_core_query_rxdesc` + `rtw89_core_rx`
//!    dispatch by packet type: WIFI to the station, C2H (type 10)
//!    via `rtw89_fw_c2h_irqsafe` into the C2H work queue,
//!    PPDU_STAT into the PHY-status path.
//! 3. When work done is under budget, re-enable interrupts
//!    (`napi_complete_done` + `rtw89_chip_enable_intr`).
//!
//! The v2 interrupt `recognize` step already acknowledged the DMA
//! ISR bits, so this worker does not clear them again. A fatal
//! event (`halt_c2h` / watchdog, `Events::fatal`) ends the run
//! before any drain: a halted firmware's rings are untrustworthy.
//! `rx_unavailable` is diagnostic only in Linux
//! (`rtw89_pci_isr_rxd_unavail` only logs the ring-full condition);
//! this worker records it and drains whatever the rings hold —
//! it performs no re-arm write for it.
//!
//! Ring arithmetic is the eq-is-full form
//! (`rtw8922a_pci_info.rx_ring_eq_is_full = true`,
//! `rtw8922ae.c:35`): the host write pointer is the *last consumed*
//! slot, seeded to `len - 1` by `dma_8922a::program_rx_ring`, and
//! the next slot to consume is `(wp + 1) % len`. The readable
//! count is Linux `rtw89_pci_dma_recalc` (`pci.c:61`):
//! `(cur_rp - (wp + 1)) mod len`, with the idx register's low
//! half echoing the host WP. This differs from the AX
//! `rx_dma::available` formula (host WP = next to consume there).
//!
//! Per-buffer errors (bad RXD, bad segment sequence, bad C2H
//! envelope, stale RPQ record) skip exactly that buffer or
//! record and continue: the readable count is register-driven,
//! so a corrupt buffer cannot desync the ring walk. Only ring
//! desync (idx register inconsistent), a fatal event, or a bad
//! budget fails the whole run. A mid-assembly RXQ packet is
//! dropped when its next segment errors, matching Linux's
//! skip-past-errors delivery.
//!
//! What this worker deliberately does NOT own (later steps):
//! - The MAC / PHY / BTC handlers for routed C2H messages: the
//!   worker parses the envelope and routes by category/class/
//!   function (Linux `fw.c` `rtw89_fw_c2h_cmd_handle`), but the
//!   handlers themselves (RA C2H ceilings, BTC, scan-offload
//!   responses, ...) are separate lanes.
//! - H2C buffer release on C2H acknowledgement: the ack (MAC
//!   INFO REC_ACK / DONE_ACK, `rx_packet::C2h::ack`) is parsed
//!   and surfaced, and the Prepared owner matches it to a
//!   retained buffer by the (category, class, function,
//!   sequence) `fwcmd_8922a` recorded when the buffer was
//!   framed (`Prepared8922a::retain_h2c` / `release_h2c_by_ack`);
//!   an unmatched ack releases nothing.
//! - BlockAck reorder: delivered WIFI frames carry `reorder` /
//!   `seq` / `tid` in their metadata for the future reorder
//!   owner; this worker delivers in arrival order.
//! - A-MSDU deaggregation and RX fragment reassembly: torn
//!   A-MSDU cuts are dropped; reassembly is a separate lane.
//! - MLO multi-link, legacy-mode admission,
//!   the full `pwr_on_func` tail / `mac_pre_init` owner (now
//!   `mac_pre_init_8922a`), `cid` retention (now
//!   `mac_pre_init_8922a::HalChipVer`), AX-path 8922A refusals
//!   (verified already-delivered: see `tx_transport`,
//!   `packet_format`, `packet_core`, `efuse`, `factory`,
//!   `fifo`, `bdram`, `command_queue`, `download_dma`,
//!   `irq::Mask::config`, `station_control::Controller::new`).
//!   (6 GHz admission is done: `station_8922a` TPE + power
//!   program, 20 MHz only; the register-level
//!   `rtw8922a_set_txpwr` program and wide-6 GHz TPE are the
//!   follow-ups.)

use alloc::vec::Vec;

use super::dma::{RXCH_RPQ, RXCH_RXQ};
use super::dma_8922a::{doorbell_rx, read_rx_idx, RXBD_NUM_MAX};
use super::dma_be::Regs;
use super::rx_dma::barrier;
use super::rx_packet::{self, Ack, C2h};
use super::tx_8922a::{DataTx, Retained};
use super::tx_transport::Completion;
use super::txrx_be::{decode_rxd_be, RxdBeInfo};

/// `RTW89_CORE_RX_TYPE_WIFI` (`core.h:227`).
pub(super) const RX_TYPE_WIFI: u8 = 0;
/// `RTW89_CORE_RX_TYPE_PPDU_STAT` (`core.h:228`).
pub(super) const RX_TYPE_PPDU_STAT: u8 = 1;
/// `RTW89_CORE_RX_TYPE_C2H` (`core.h:237`).
pub(super) const RX_TYPE_C2H: u8 = 10;

/// `RTW89_C2H_CAT_TEST` (`fw.h:172`).
pub(super) const C2H_CAT_TEST: u8 = 0;
/// `RTW89_C2H_CAT_MAC` (`fw.h:173`).
pub(super) const C2H_CAT_MAC: u8 = 1;
/// `RTW89_C2H_CAT_OUTSRC` (`fw.h:174`).
pub(super) const C2H_CAT_OUTSRC: u8 = 2;

/// `RTW89_PHY_C2H_CLASS_BTC_MIN` (`phy.h:207`).
pub(super) const C2H_BTC_CLASS_MIN: u8 = 0x10;
/// `RTW89_PHY_C2H_CLASS_BTC_MAX` (`phy.h:208`).
pub(super) const C2H_BTC_CLASS_MAX: u8 = 0x17;

/// RXBD-info first-segment bit (`pci.h:1536`).
const RXBD_INFO_FS: u32 = 1 << 15;
/// RXBD-info last-segment bit (`pci.h:1537`).
const RXBD_INFO_LS: u32 = 1 << 14;
/// RXBD-info write-size mask (`pci.h:1538`, bits 13:0).
const RXBD_INFO_SIZE_MASK: u32 = 0x3fff;

/// BE RXD long-layout bit (`txrx.h:497`, `BE_RXD_LONG_RXD`).
const RXD_D0_LONG: u32 = 1 << 31;
/// `struct rtw89_rxdesc_short_v2` (`core.h:1199`).
const RXD_LEN_SHORT: usize = 24;
/// `struct rtw89_rxdesc_long_v2` (`core.h:1228`).
const RXD_LEN_LONG: usize = 40;
/// One RPQ record: Linux's original 4-byte format
/// (`rtw8922ae.c:39`, `.rpp_fmt_size = sizeof(struct rtw89_pci_rpp_fmt)`).
const RPP_SIZE: usize = 4;
/// PHY-report length that carries the RSSI dword
/// (`core.c` `rtw89_core_query_rxdesc_v2`: 8 bytes).
const PHY_RPT_RSSI_LEN: usize = 8;
/// `BE_RXD_PHY_RSSI` (`txrx.h:592`).
const PHY_RSSI_MASK: u32 = 0xfff;

/// Completion-worker failures. Per-buffer content failures do not
/// produce this error: they skip the buffer or record (see the
/// module docs). Only ring desync, fatal firmware state, a bad
/// budget, or a refused composition fails the run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    /// Idx register inconsistent with the host ring state
    /// (gone device, wrapped RP, low-half WP mismatch, or a TX
    /// read-pointer update past the published slots).
    Index,
    /// Budget zero or above the Linux NAPI maximum (256).
    Budget,
    /// Ring depth outside 2..=256, or a buffer slice count that
    /// does not match the programmed ring depth.
    BadLength,
    /// FS/LS segment sequence error (continuation without a
    /// first segment, or a second first segment).
    Segment,
    /// RXD geometry error (undecodable descriptor, zero packet
    /// length, data start past the segment).
    Descriptor,
    /// Segment size outside the buffer or the assembled length.
    Extent,
    /// C2H envelope error (bad length or malformed MAC INFO ack).
    Firmware,
    /// Firmware halt (`halt_c2h`) or watchdog interrupt: the
    /// rings are untrustworthy, drain nothing.
    Halted,
}

/// Eq-is-full readable count for one BE RX ring, from the idx
/// register word. Mirrors Linux `rtw89_pci_dma_recalc`
/// (`pci.c:61`) for RX rings: the hardware RP is bits 27:16,
/// the host WP is bits 11:0, and the count is
/// `(cur_rp - (wp + 1)) mod len`.
pub(super) fn available_be(index: u32, wp: u16, len: u16) -> Result<u16, Error> {
    if index == u32::MAX || len < 2 || wp >= len {
        return Err(Error::Index);
    }
    let rp = ((index >> 16) & 0xfff) as u16;
    if rp >= len || index & 0xfff != u32::from(wp) {
        return Err(Error::Index);
    }
    Ok((rp + len - wp - 1) % len)
}

/// One RX buffer's RXBD-info header (`pci.h:1536..1539`).
struct RxbdInfo {
    fs: bool,
    ls: bool,
    size: usize,
}

fn rxbd_info(bytes: &[u8]) -> Result<RxbdInfo, Error> {
    let word = u32::from_le_bytes(
        bytes
            .get(..4)
            .ok_or(Error::Extent)?
            .try_into()
            .map_err(|_| Error::Extent)?,
    );
    let size = (word & RXBD_INFO_SIZE_MASK) as usize;
    if !(4..=rx_packet::BUFFER_SIZE).contains(&size) || size > bytes.len() {
        return Err(Error::Extent);
    }
    Ok(RxbdInfo {
        fs: word & RXBD_INFO_FS != 0,
        ls: word & RXBD_INFO_LS != 0,
        size,
    })
}

/// Where one parsed C2H message goes, mirroring Linux `fw.c`
/// `rtw89_fw_c2h_cmd_handle`: TEST is dropped, MAC goes to the
/// MAC handler, OUTSRC splits into BTC (classes 0x10..=0x17)
/// and PHY. An unknown category has no handler anywhere and is
/// dropped; unknown classes/functions inside a known category
/// still route — the future handler refuses or handles them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Route {
    /// `RTW89_C2H_CAT_TEST`: no handler, dropped.
    Test,
    /// `RTW89_C2H_CAT_MAC`, with its class/function.
    Mac { class: u8, func: u8 },
    /// `RTW89_C2H_CAT_OUTSRC`, BTC class range.
    OutsrcBtc { class: u8, func: u8 },
    /// `RTW89_C2H_CAT_OUTSRC`, any other class.
    OutsrcPhy { class: u8, func: u8 },
    /// No such category in `fw.h`: dropped.
    UnknownCategory { category: u8 },
}

/// Linux `fw.c` `rtw89_fw_c2h_cmd_handle` category dispatch.
pub(super) fn route_c2h(c2h: &C2h) -> Route {
    match c2h.category {
        C2H_CAT_TEST => Route::Test,
        C2H_CAT_MAC => Route::Mac {
            class: c2h.class,
            func: c2h.function,
        },
        C2H_CAT_OUTSRC if (C2H_BTC_CLASS_MIN..=C2H_BTC_CLASS_MAX).contains(&c2h.class) => {
            Route::OutsrcBtc {
                class: c2h.class,
                func: c2h.function,
            }
        }
        C2H_CAT_OUTSRC => Route::OutsrcPhy {
            class: c2h.class,
            func: c2h.function,
        },
        category => Route::UnknownCategory { category },
    }
}

/// One routed C2H message: the parsed envelope, its route, and
/// the MAC INFO acknowledgement it carries, if it is one
/// (`rx_packet::C2h::ack`: REC_ACK / DONE_ACK).
#[derive(Debug, PartialEq, Eq)]
pub(super) struct RoutedC2h {
    pub(super) route: Route,
    pub(super) c2h: C2h,
    pub(super) ack: Option<Ack>,
}

impl RoutedC2h {
    fn new(c2h: C2h) -> Self {
        let route = route_c2h(&c2h);
        // `C2h::parse` already validated the ack shape, so this
        // cannot fail for a parsed message.
        let ack = c2h.ack().ok().flatten();
        Self { route, c2h, ack }
    }
}

/// What the worker needs from a delivered WIFI frame: the
/// addressed station, ordering keys for the future reorder
/// owner, and whether the frame is part of an A-MPDU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct WifiMeta {
    /// `RxdBeInfo::mac_id` (`BE_RXD_MAC_ID_V1`).
    pub(super) mac_id: u16,
    /// 802.11 sequence number.
    pub(super) seq: u16,
    /// Traffic identifier.
    pub(super) tid: u8,
    /// Address-1 matched this device.
    pub(super) to_self: bool,
    /// BlockAck reorder applies.
    pub(super) reorder: bool,
    /// Part of an A-MPDU.
    pub(super) ampdu: bool,
}

/// One assembled PPDU status report. The full MAC-info / PHY-IE
/// walk is a later lane; the worker surfaces the bytes plus the
/// PHY-report RSSI when the report was present.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct PpduReport {
    pub(super) mac_id: u16,
    /// Raw `BE_RXD_PHY_RSSI` field, when `phy_rpt_sz` was 1
    /// (one 8-byte PHY report follows the RXD).
    pub(super) phy_rssi_raw: Option<u16>,
    /// Assembled PPDU status bytes.
    pub(super) bytes: Vec<u8>,
}

/// One assembled BE RX packet, after the worker's wire checks.
/// `Dropped` is a well-formed packet no owner takes (unknown
/// type, CRC/ICV error, hardware-decrypted, torn A-MSDU cut).
#[derive(Debug, PartialEq, Eq)]
pub(super) enum BeEvent {
    /// Exactly the native MPDU, after removing only its
    /// four-byte FCS (Linux advertises `RX_INCLUDES_FCS` for
    /// this hardware, `core.c:7499`).
    Wifi(WifiMeta, Vec<u8>),
    Firmware(RoutedC2h),
    Ppdu(PpduReport),
    Dropped,
}

struct BePartial {
    rxd: RxdBeInfo,
    /// Packet-data offset within a first segment (RXBD-info +
    /// shift + driver-info + PHY-report + header-conversion +
    /// RXD), per `rtw89_core_query_rxdesc_v2`.
    data_start: usize,
    phy_rssi_raw: Option<u16>,
    bytes: Vec<u8>,
}

/// FS/LS segment assembly over BE short/long RXDs, mirroring
/// `rx_packet::Assembler::segment` (and Linux
/// `rtw89_pci_rxbd_deliver_skbs` + `rtw89_skb_put_rx_data`):
/// the assembled packet is exactly `pkt_len` bytes starting at
/// `data_start` in the first segment, continuing past the
/// 4-byte RXBD-info header in later segments. A single-segment
/// buffer may carry DMA alignment padding past `pkt_len`.
#[derive(Default)]
pub(super) struct BeAssembler {
    partial: Option<BePartial>,
}

impl BeAssembler {
    pub(super) fn reset(&mut self) {
        self.partial = None;
    }

    pub(super) fn segment(&mut self, bytes: &[u8]) -> Result<Option<BeEvent>, Error> {
        let info = rxbd_info(bytes)?;
        let bytes = &bytes[..info.size];
        if info.fs {
            if self.partial.is_some() {
                return Err(Error::Segment);
            }
            let rxd =
                decode_rxd_be(bytes.get(4..).ok_or(Error::Extent)?).ok_or(Error::Descriptor)?;
            if rxd.pkt_len == 0 {
                return Err(Error::Descriptor);
            }
            let dw0 = u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| Error::Extent)?);
            let rxd_len = if dw0 & RXD_D0_LONG != 0 {
                RXD_LEN_LONG
            } else {
                RXD_LEN_SHORT
            };
            // `rtw89_core_query_rxdesc_v2`: shift is 2-byte units,
            // driver-info and PHY-report are 8-byte units,
            // header-conversion is 16-byte units; packet data
            // starts after the RXD itself.
            let data_start = 4
                + usize::from(rxd.shift) * 2
                + usize::from(rxd.drv_info_sz) * 8
                + usize::from(rxd.phy_rpt_sz) * 8
                + usize::from(rxd.hdr_cnv_sz) * 16
                + rxd_len;
            if data_start > info.size {
                return Err(Error::Extent);
            }
            // The 8-byte PHY report follows the RXD
            // (`query_rxdesc_v2` reads it at `data + 4 + rxd_len`
            // when `phy_rtp_len` is 8 bytes).
            let phy_rssi_raw = if rxd.phy_rpt_sz == 1 {
                let at = 4 + rxd_len;
                bytes
                    .get(at..at + PHY_RPT_RSSI_LEN)
                    .map(|report| {
                        u32::from_le_bytes(report[..4].try_into().unwrap()) & PHY_RSSI_MASK
                    })
                    .map(|value| value as u16)
            } else {
                None
            };
            self.partial = Some(BePartial {
                rxd,
                data_start,
                phy_rssi_raw,
                bytes: Vec::with_capacity(rxd.pkt_len as usize),
            });
        }
        let partial = self.partial.as_mut().ok_or(Error::Segment)?;
        let offset = if info.fs { partial.data_start } else { 4 };
        let payload = bytes.get(offset..).ok_or(Error::Extent)?;
        let remaining = partial.rxd.pkt_len as usize - partial.bytes.len();
        // Single-segment buffers may carry DMA alignment padding.
        // Multi-segment lengths must agree exactly; never borrow
        // beyond write_size.
        let length = if info.fs && info.ls {
            if payload.len() < remaining {
                return Err(Error::Extent);
            }
            remaining
        } else {
            if payload.len() > remaining || (!info.ls && payload.len() == remaining) {
                return Err(Error::Extent);
            }
            payload.len()
        };
        partial.bytes.extend_from_slice(&payload[..length]);
        if !info.ls {
            return Ok(None);
        }
        let BePartial {
            rxd,
            phy_rssi_raw,
            mut bytes,
            ..
        } = self.partial.take().unwrap();
        if bytes.len() != rxd.pkt_len as usize {
            return Err(Error::Extent);
        }
        Ok(Some(match rxd.pkt_type {
            RX_TYPE_WIFI => {
                if rxd.crc32_err || rxd.icv_err || rxd.hw_dec || rxd.amsdu_cut {
                    BeEvent::Dropped
                } else {
                    if bytes.len() < 14 {
                        return Err(Error::Descriptor);
                    }
                    // `RX_INCLUDES_FCS`: strip the trailing FCS.
                    bytes.truncate(bytes.len() - 4);
                    BeEvent::Wifi(
                        WifiMeta {
                            mac_id: rxd.mac_id,
                            seq: rxd.seq,
                            tid: rxd.tid,
                            to_self: rxd.a1_match,
                            reorder: rxd.reorder,
                            ampdu: rxd.ampdu,
                        },
                        bytes,
                    )
                }
            }
            RX_TYPE_PPDU_STAT => BeEvent::Ppdu(PpduReport {
                mac_id: rxd.mac_id,
                phy_rssi_raw,
                bytes,
            }),
            RX_TYPE_C2H => BeEvent::Firmware(RoutedC2h::new(
                C2h::parse(bytes).map_err(|_| Error::Firmware)?,
            )),
            _ => BeEvent::Dropped,
        }))
    }
}

/// One retired data frame: the TX status Linux
/// `rtw89_pci_tx_status` reports (0 = `RTW89_TX_DONE`) plus the
/// retained DMA addresses the caller frees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct TxReceipt {
    pub(super) header_dma: u64,
    pub(super) frame_dma: u64,
    pub(super) status: u8,
}

/// RPQ drain result: one entry per frame whose both halves
/// (TXBD consumption + RPQ report) have now arrived.
#[derive(Debug, Default)]
pub(super) struct RpqOutcome {
    pub(super) completions: Vec<Completion<Retained>>,
    /// Records skipped (stale, conflicting, unpublished, or
    /// for an unknown queue).
    pub(super) dropped_records: u32,
    /// Whole buffers skipped (bad RXBD-info, non-FS/LS, or
    /// undecodable RXD).
    pub(super) dropped_buffers: u32,
    /// RPQ buffers consumed (Linux NAPI work units).
    pub(super) work: usize,
}

/// RXQ drain result.
#[derive(Debug, Default)]
pub(super) struct RxqOutcome {
    pub(super) frames: Vec<(WifiMeta, Vec<u8>)>,
    pub(super) c2h: Vec<RoutedC2h>,
    pub(super) ppdu: Vec<PpduReport>,
    /// Packets dropped (unknown type, wire errors, torn
    /// segments, frames for no admitted station) plus buffers
    /// skipped on content errors.
    pub(super) dropped: u32,
    /// RXQ buffers consumed (Linux NAPI work units).
    pub(super) work: usize,
}

/// One `complete()` run: everything the NAPI-order drain
/// produced, in drain order.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Outcome {
    pub(super) tx: Vec<TxReceipt>,
    pub(super) frames: Vec<(WifiMeta, Vec<u8>)>,
    pub(super) c2h: Vec<RoutedC2h>,
    pub(super) ppdu: Vec<PpduReport>,
    pub(super) dropped: u32,
    /// RPQ + RXQ buffers consumed.
    pub(super) work_done: usize,
    /// `rx_unavailable` was signaled (diagnostic; see the
    /// module docs — no re-arm write follows from it).
    pub(super) rx_unavailable: bool,
    /// Re-enable the interrupt mask: work done is under budget.
    pub(super) rearm: bool,
    /// Retained H2C buffers released by C2H acknowledgements
    /// during this run (`fwcmd_8922a::Released`, in ack order).
    /// Filled by the Prepared owner, not the worker: the worker
    /// routes the acks, the owner matches them to retained
    /// buffers.
    pub(super) h2c_released: Vec<super::fwcmd_8922a::Released>,
}

/// Drain one RPQ buffer's 4-byte records into `data`. The
/// records start at the RXD's packet-data offset (Linux
/// `rtw89_pci_release_tx_skbs`: `offset + rxd_len`, walked in
/// `rpp_fmt_size` steps while a whole record fits in the
/// write size); a trailing partial record is ignored. A bad
/// record is counted and skipped — it cannot corrupt the
/// queue, which matches by (sequence, MACID, QSEL).
fn drain_rpq_buffer(
    bytes: &[u8],
    data: &mut DataTx,
) -> Result<(Vec<Completion<Retained>>, u32), Error> {
    let info = rxbd_info(bytes)?;
    // Linux refuses RP frames without FS+LS
    // (`rtw89_pci_release_tx_skbs`); the buffer is skipped
    // instead of retried forever.
    if !info.fs || !info.ls {
        return Err(Error::Segment);
    }
    let bytes = &bytes[..info.size];
    let rxd = decode_rxd_be(bytes.get(4..).ok_or(Error::Extent)?).ok_or(Error::Descriptor)?;
    let dw0 = u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| Error::Extent)?);
    let rxd_len = if dw0 & RXD_D0_LONG != 0 {
        RXD_LEN_LONG
    } else {
        RXD_LEN_SHORT
    };
    let offset = 4
        + usize::from(rxd.shift) * 2
        + usize::from(rxd.drv_info_sz) * 8
        + usize::from(rxd.phy_rpt_sz) * 8
        + usize::from(rxd.hdr_cnv_sz) * 16
        + rxd_len;
    let mut completions = Vec::new();
    let mut dropped = 0;
    let mut at = offset;
    while at + RPP_SIZE <= info.size {
        match data.observe_report(&bytes[at..at + RPP_SIZE]) {
            Ok(Some(done)) => completions.push(done),
            Ok(None) => {}
            Err(_) => dropped += 1,
        }
        at += RPP_SIZE;
    }
    Ok((completions, dropped))
}

/// The BE completion worker: host-side write pointers and
/// assembly state for the two RX rings. The rings themselves
/// (BD bases, buffers) stay with the probe owner; this worker
/// only walks them.
pub(super) struct Worker {
    rx_wp: u16,
    rpq_wp: u16,
    rx_len: u16,
    rpq_len: u16,
    assembler: BeAssembler,
}

impl Worker {
    /// Empty worker for `rx_len` / `rpq_len`-deep rings. Both
    /// write pointers start at `len - 1`, the eq-is-full seed
    /// `dma_8922a::program_rx_ring` writes to the idx register.
    pub(super) fn new(rx_len: u16, rpq_len: u16) -> Result<Self, Error> {
        if !(2..=RXBD_NUM_MAX).contains(&rx_len) || !(2..=RXBD_NUM_MAX).contains(&rpq_len) {
            return Err(Error::BadLength);
        }
        Ok(Self {
            rx_wp: rx_len - 1,
            rpq_wp: rpq_len - 1,
            rx_len,
            rpq_len,
            assembler: BeAssembler::default(),
        })
    }

    /// Back to the programmed state: seed write pointers, drop
    /// any mid-assembly packet. Called when the rings are
    /// stopped/reset; consumed buffers stay consumed.
    pub(super) fn reset(&mut self) {
        self.rx_wp = self.rx_len - 1;
        self.rpq_wp = self.rpq_len - 1;
        self.assembler.reset();
    }

    /// Drain the RPQ ring: recalc from the idx register, apply
    /// each buffer's records through `DataTx::observe_report`,
    /// then apply the TX-ring read pointers (Linux
    /// `rtw89_pci_reclaim_txbd`: a completion surfaces from
    /// whichever half — RP or report — arrives second). Each
    /// consumed buffer's doorbell is written before moving on,
    /// so the register never disagrees with the host WP.
    pub(super) fn drain_rpq(
        &mut self,
        regs: &mut impl Regs,
        buffers: &mut [&mut [u8]],
        budget: usize,
        data: &mut DataTx,
    ) -> Result<RpqOutcome, Error> {
        if buffers.len() != self.rpq_len as usize {
            return Err(Error::BadLength);
        }
        let index = read_rx_idx(regs, RXCH_RPQ).map_err(|_| Error::Index)?;
        let count = usize::from(available_be(index, self.rpq_wp, self.rpq_len)?).min(budget);
        let mut outcome = RpqOutcome::default();
        for _ in 0..count {
            // Eq-is-full: the next slot to consume is past the
            // host WP (`rtw89_pci_get_rx_skb_idx`).
            let slot = ((self.rpq_wp + 1) % self.rpq_len) as usize;
            let buffer: &mut [u8] = buffers[slot];
            barrier();
            match drain_rpq_buffer(buffer, data) {
                Ok((completions, dropped)) => {
                    outcome.completions.extend(completions);
                    outcome.dropped_records += dropped;
                }
                Err(_) => outcome.dropped_buffers += 1,
            }
            // Clear the stale RXBD-info header before handing
            // this exact buffer back to DMA (mirrors
            // `rx_dma::Ring::poll`).
            if buffer.len() >= 4 {
                buffer[..4].fill(0);
            }
            barrier();
            self.rpq_wp = slot as u16;
            doorbell_rx(regs, RXCH_RPQ, self.rpq_wp).map_err(|_| Error::Index)?;
            outcome.work += 1;
        }
        for channel in 0..12u8 {
            let done = data.observe_rp(regs, channel).map_err(|_| Error::Index)?;
            outcome.completions.extend(done);
        }
        Ok(outcome)
    }

    /// Drain the RXQ ring: recalc from the idx register, assemble
    /// each buffer's segments, and dispatch by packet type.
    /// WIFI frames are admitted only for an `admitted` MACID;
    /// anything else is counted as dropped. Each consumed
    /// buffer's doorbell is written before moving on.
    pub(super) fn drain_rxq(
        &mut self,
        regs: &mut impl Regs,
        buffers: &mut [&mut [u8]],
        budget: usize,
        admitted: &[u8],
    ) -> Result<RxqOutcome, Error> {
        if buffers.len() != self.rx_len as usize {
            return Err(Error::BadLength);
        }
        let index = read_rx_idx(regs, RXCH_RXQ).map_err(|_| Error::Index)?;
        let count = usize::from(available_be(index, self.rx_wp, self.rx_len)?).min(budget);
        let mut outcome = RxqOutcome::default();
        for _ in 0..count {
            let slot = ((self.rx_wp + 1) % self.rx_len) as usize;
            let buffer: &mut [u8] = buffers[slot];
            barrier();
            match self.assembler.segment(buffer) {
                Ok(Some(event)) => match event {
                    BeEvent::Wifi(meta, frame) => {
                        if !meta.to_self
                            || meta.mac_id > u8::MAX as u16
                            || !admitted.contains(&(meta.mac_id as u8))
                        {
                            outcome.dropped += 1;
                        } else {
                            outcome.frames.push((meta, frame));
                        }
                    }
                    BeEvent::Firmware(routed) => outcome.c2h.push(routed),
                    BeEvent::Ppdu(report) => outcome.ppdu.push(report),
                    BeEvent::Dropped => outcome.dropped += 1,
                },
                Ok(None) => {}
                Err(_) => {
                    outcome.dropped += 1;
                    self.assembler.reset();
                }
            }
            if buffer.len() >= 4 {
                buffer[..4].fill(0);
            }
            barrier();
            self.rx_wp = slot as u16;
            doorbell_rx(regs, RXCH_RXQ, self.rx_wp).map_err(|_| Error::Index)?;
            outcome.work += 1;
        }
        Ok(outcome)
    }
}
