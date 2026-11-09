// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8922A BE data + H2C transport (chip-row step 4).
//!
//! The submit half of the 8922A transport lane, mirroring Linux
//! `rtw89/pci.c` `rtw89_pci_txwd_submit` / `__rtw89_pci_tx_kick_off`
//! / `rtw89_pci_parse_rpp` / `rtw89_pci_fill_txaddr_info_v1` and
//! `rtw89_h2c_tx` (`core.c:1381`, ordinary TX submit on CH12 with
//! `RTW89_CORE_TX_TYPE_FWCMD`), all torvalds/linux @ 05441d6,
//! instantiated for 8922AE by `rtw8922a_pci_info`
//! (`rtw8922ae.c:23..77`).
//!
//! Structure mirrors Linux's write/kick split: [`DataTx::prepare`]
//! reserves a queue slot, builds the header bytes, and fills the
//! TXBD — but does NOT publish or ring the doorbell. The caller
//! places the header bytes into header DMA memory and syncs them,
//! then calls [`DataTx::kick`], which publishes and doorbells.
//! Ringing before the header is visible would let the chip read a
//! stale header, so prepare/kick must never be fused. The H2C path
//! ([`H2cTx`]) splits the same way on CH12.
//!
//! Reused, not re-implemented (with the Linux proof in each case):
//! - Queue ownership + RPQ release: [`super::tx_transport::TxQueue`]
//!   and [`super::tx_transport::parse_report`]. 8922A's RPQ format
//!   is Linux's ORIGINAL 4-byte record (`rtw89_pci_parse_rpp`:
//!   POLLUTED bit 31, SEQ 30:16, TX_STATUS 15:13, QSEL 12:8, MACID
//!   7:0) — exactly what `parse_report` decodes. The 8-byte v1
//!   record belongs to other BE chips, not 8922A, so no BE RPQ
//!   parser is written here.
//! - QSEL→channel: Linux's generic `rtw89_core_get_ch_dma`
//!   (`core.c`), identical values to the in-tree AX mapping.
//! - TXBD layout: the same 8-byte `TxBd` (`length`/`opt`/`dma`,
//!   LS bit 14, DMA_HI bits 13:6).
//!
//! Deliberate differences from Linux, all fail-closed:
//! - Unknown QSEL values (including `B0/B1_MGMT_FAST`, 0x14/0x1c)
//!   are refused ([`Error::BadQsel`]); Linux's generic mapper
//!   warns and falls through to ACH0. The in-tree AX transport
//!   already refuses them; BE matches.
//! - MACID is capped at the chip's 32 stations
//!   (`SUPPORT_MACID_NUM`), not the 128 the generic queue allows.
//! - No TXWD_INFO block is built by default: [`build_header`]
//!   clears BODY0 bit 22 (WDINFO_EN) on the caller-supplied v2
//!   body, matching the AX transport's "no info block present"
//!   rule. [`build_header_with_info`] appends a caller-filled
//!   v2 info block (`txrx_be::fill_txwd_info_v2`) and leaves the
//!   bit set, mirroring Linux `rtw89_core_fill_txdesc_v2`'s
//!   `en_wd_info` opt-in.
//! - FWCMD header framing for H2C bodies is the caller's: the
//!   station owner builds CCTL/BA-CAM/RA bodies, and
//!   `fwcmd_8922a::frame_h2c` wraps them (type / category /
//!   class / func / sequence) for this module to move across
//!   CH12.

use alloc::vec::Vec;

use super::dma::{split_idx, RingState, TxBd, TXBD_OPT_LS};
use super::dma_8922a::{doorbell_tx, read_tx_idx};
use super::dma_be::Regs;
use super::tx_transport::{self, Completion, Ticket, TxQueue};

/// TXWD_BODY_V2 size in bytes (`chip_8922a::TXWD_BODY_SIZE`).
pub(super) const TXWD_BODY_V2_SIZE: usize = 32;
/// TXWD_INFO_V2 size in bytes (`chip_8922a::TXWD_INFO_SIZE`).
pub(super) const TXWD_INFO_SIZE: usize = 32;
/// TXWP info block size in bytes (`struct rtw89_pci_tx_wp_info`,
/// 4 × u16).
pub(super) const TXWP_SIZE: usize = 8;
/// `RTW89_PCI_TXWP_VALID` (`pci.h:1474`): seq0 valid bit.
pub(super) const TXWP_VALID: u16 = 1 << 15;
/// BE TXWD packet-size field cap (`BODY2_TXPKTSIZE_MASK`,
/// 14 bits).
pub(super) const MAX_FRAME_LEN: usize = 0x3FFF;
/// Address-info entry size in bytes
/// (`struct rtw89_pci_tx_addr_info_32_v1`: 3 × u16).
pub(super) const ADDR_INFO_ENTRY_SIZE: usize = 6;
/// Maximum frame bytes per address-info entry
/// (`TXADDR_INFO_LENTHG_V1_MAX`, `pci.h`).
pub(super) const ADDR_INFO_MAX_LEN: usize = 2044;
/// Maximum address-info entries (`RTW89_TXADDR_INFO_NR_V1`,
/// `pci.h:1494`).
pub(super) const ADDR_INFO_MAX_NR: usize = 10;
/// Frame DMA must fit the 4-bit HIGH_SEL field of the v1
/// address-info entry: 36-bit DMA addresses only.
pub(super) const FRAME_DMA_MASK: u64 = (1 << 36) - 1;
/// Header/buffer DMA must fit the TXBD's 8-bit DMA_HI field:
/// 40-bit DMA addresses only.
pub(super) const BUFFER_DMA_MASK: u64 = (1 << 40) - 1;
/// Data TX ring depth (Linux allocates `RTW89_PCI_TXBD_NUM_MAX`
/// = 256 for every TX channel).
pub(super) const DATA_RING_DEPTH: u16 = 256;

/// Transport failures. Every variant is a refusal; a refused
/// prepare consumes no queue slot and fills no descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    /// Data channel outside 0..12 (CH12 is H2C-only).
    BadChannel,
    /// QSEL with no DMA channel mapping.
    BadQsel,
    /// MACID at or above the chip's 32 stations.
    BadMacId,
    /// Caller buffer too small, or ring depth out of range.
    BadLength,
    /// Frame length, body size, or header shape invalid.
    BadFrame,
    /// DMA address above the entry's address field.
    BadDma,
    /// No free slot (queue full / ring full).
    Full,
    /// Slot index outside the descriptor slice, or a stale /
    /// double kick.
    BadIndex,
    /// RPQ record polluted, or status out of range.
    StaleReport,
    /// RPQ status conflicts with an earlier report.
    ConflictingReport,
    /// RPQ record for an unpublished slot.
    NotPublished,
    /// Frame needs more address-info entries than the v1 cap.
    TooManyAddrEntries,
}

fn map_tx_error(error: tx_transport::Error) -> Error {
    match error {
        tx_transport::Error::Full => Error::Full,
        tx_transport::Error::BadFrame => Error::BadFrame,
        tx_transport::Error::BadQueue => Error::BadChannel,
        tx_transport::Error::BadIndex => Error::BadIndex,
        tx_transport::Error::StaleReport => Error::StaleReport,
        tx_transport::Error::ConflictingReport => Error::ConflictingReport,
        tx_transport::Error::NotPublished => Error::NotPublished,
        // Authority/NoMemory/BadDma cannot arise from pure queue
        // logic (no allocation, no capability check in these calls).
        _ => Error::BadFrame,
    }
}

/// QSEL→DMA-channel mapping, Linux `rtw89_core_get_ch_dma`
/// (`core.c`): 0..=15 group by access category into ACH0..3,
/// 0x12/0x11/0x1a/0x19 select the management/high-priority
/// channels. Unknown values are refused (see module docs).
pub(super) fn channel_for_qsel(qsel: u8) -> Result<u8, Error> {
    match qsel {
        0..=15 => Ok(qsel % 4),
        0x12 => Ok(8),
        0x11 => Ok(9),
        0x1a => Ok(10),
        0x19 => Ok(11),
        _ => Err(Error::BadQsel),
    }
}

/// Fill v1 address-info entries for one frame, Linux
/// `rtw89_pci_fill_txaddr_info_v1` (`pci.c`): each 6-byte entry
/// carries `length_opt` (length bits 10:0, DMA-high nibble bits
/// 14:11, last-segment bit 15), `dma_low_lsb` (bits 15:0), and
/// `dma_low_msb` (bits 31:16); the DMA cursor advances by the
/// entry length. Returns the bytes written (a multiple of 6).
pub(super) fn fill_addr_info_v1(
    out: &mut [u8],
    total_len: usize,
    dma: u64,
) -> Result<usize, Error> {
    if dma > FRAME_DMA_MASK {
        return Err(Error::BadDma);
    }
    let entries = total_len.div_ceil(ADDR_INFO_MAX_LEN);
    if entries > ADDR_INFO_MAX_NR {
        return Err(Error::TooManyAddrEntries);
    }
    if out.len() < entries * ADDR_INFO_ENTRY_SIZE {
        return Err(Error::BadLength);
    }
    let mut remain = total_len;
    let mut cursor = dma;
    for entry in 0..entries {
        let len = remain.min(ADDR_INFO_MAX_LEN);
        remain -= len;
        let high = ((cursor >> 32) as u16) & 0xF;
        let mut length_opt = (len as u16) & 0x07FF;
        length_opt |= high << 11;
        if remain == 0 {
            length_opt |= 1 << 15;
        }
        let start = entry * ADDR_INFO_ENTRY_SIZE;
        out[start..start + 2].copy_from_slice(&length_opt.to_le_bytes());
        out[start + 2..start + 4].copy_from_slice(&(cursor as u16).to_le_bytes());
        out[start + 4..start + 6].copy_from_slice(&((cursor >> 16) as u16).to_le_bytes());
        cursor += len as u64;
    }
    Ok(entries * ADDR_INFO_ENTRY_SIZE)
}

/// Build the complete header bytes for one data frame: the
/// caller-supplied 32-byte v2 body + the 8-byte WP info block
/// (`seq0 = sequence | VALID`, `seq1..seq3 = 0`) + the v1
/// address-info entries for the frame. The caller places these
/// bytes into header DMA memory and syncs them before kick.
pub(super) fn build_header(
    body: &[u8; TXWD_BODY_V2_SIZE],
    sequence: u16,
    frame_dma: u64,
    frame_len: usize,
) -> Result<Vec<u8>, Error> {
    build_header_with_info(body, None, sequence, frame_dma, frame_len)
}

/// Build the complete header bytes for one data frame with a
/// TXWD_INFO v2 block: the 32-byte v2 body + the 32-byte info
/// block (`txrx_be::fill_txwd_info_v2` output) + the 8-byte WP
/// info block + the v1 address-info entries. With `info` the
/// body's BODY0 bit 22 (WDINFO_EN) is left set so the firmware
/// reads the block that follows; without it the bit is cleared,
/// as in [`build_header`]. Linux `rtw89_core_fill_txdesc_v2`
/// fills the info block only when `desc_info->en_wd_info` is
/// set (`core.c:1870`); the same opt-in applies here.
pub(super) fn build_header_with_info(
    body: &[u8; TXWD_BODY_V2_SIZE],
    info: Option<&[u8; TXWD_INFO_SIZE]>,
    sequence: u16,
    frame_dma: u64,
    frame_len: usize,
) -> Result<Vec<u8>, Error> {
    if frame_len == 0 || frame_len > MAX_FRAME_LEN {
        return Err(Error::BadFrame);
    }
    if frame_dma > FRAME_DMA_MASK {
        return Err(Error::BadDma);
    }
    let mut header = Vec::with_capacity(TXWD_BODY_V2_SIZE + TXWD_INFO_SIZE + TXWP_SIZE + 60);
    let mut dw0 = u32::from_le_bytes(body[0..4].try_into().unwrap());
    match info {
        Some(_) => dw0 |= 1 << 22, // WD_INFO block follows.
        None => dw0 &= !(1 << 22), // No WD_INFO block follows.
    }
    header.extend_from_slice(&dw0.to_le_bytes());
    header.extend_from_slice(&body[4..TXWD_BODY_V2_SIZE]);
    if let Some(info) = info {
        header.extend_from_slice(info);
    }
    header.extend_from_slice(&(sequence | TXWP_VALID).to_le_bytes());
    header.extend_from_slice(&[0u8; 6]);
    let mut addr = [0u8; ADDR_INFO_MAX_NR * ADDR_INFO_ENTRY_SIZE];
    let written = fill_addr_info_v1(&mut addr, frame_len, frame_dma)?;
    header.extend_from_slice(&addr[..written]);
    Ok(header)
}

/// DMA addresses retained by one outstanding data frame until
/// both TXBD consumption and the matching RPQ release retire it
/// (mirrors `tx_transport::TxQueue`'s retention contract).
// The fields are read by the future Prepared-wiring caller, which
// frees the retained DMA addresses after RPQ release; no reader
// exists yet in pass 1 (dead_code is allowed module-wide in rtw89).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Retained {
    /// Header DMA address (TXWD + WP + address-info bytes).
    pub(super) header_dma: u64,
    /// Frame DMA address (referenced by the address-info entries).
    pub(super) frame_dma: u64,
}

/// A prepared-but-unkicked data frame: the queue slot is
/// reserved and the TXBD is filled, but nothing is published
/// and the doorbell is unrung until [`DataTx::kick`].
#[derive(Debug)]
pub(super) struct Prepared {
    /// Queue ticket (slot + wire sequence).
    pub(super) ticket: Ticket,
    /// Data channel (0..12).
    pub(super) channel: u8,
    /// Header bytes for the caller to place into header DMA
    /// memory and sync before kick.
    pub(super) header: Vec<u8>,
}

/// BE data TX owner: one queue per data channel (0..12).
pub(super) struct DataTx {
    queues: Vec<TxQueue<Retained>>,
}

/// Arguments for [`DataTx::prepare`], grouped so the method
/// stays under clippy's argument limit. Field order matches
/// the original parameter order; see `prepare`'s doc comment
/// for what each field means.
#[derive(Debug)]
pub(super) struct PrepareArgs<'a> {
    /// Data channel (0..12).
    pub(super) channel: u8,
    /// Station MACID (0..32).
    pub(super) mac_id: u8,
    /// QSEL selecting the channel (must map to `channel`).
    pub(super) qsel: u8,
    /// Caller-built 32-byte v2 body.
    pub(super) body: &'a [u8; TXWD_BODY_V2_SIZE],
    /// Header DMA address (written into the TXBD).
    pub(super) header_dma: u64,
    /// Frame DMA address (retained until RPQ release).
    pub(super) frame_dma: u64,
    /// Frame length in bytes (1..=MAX_FRAME_LEN).
    pub(super) frame_len: usize,
    /// Channel's descriptor ring slice (indexed by slot).
    pub(super) bd: &'a mut [TxBd],
}

impl DataTx {
    /// Twelve empty 256-deep queues (ACH0..7, CH8..11).
    pub(super) fn new() -> Result<Self, Error> {
        let mut queues = Vec::new();
        for channel in 0..12u8 {
            queues.push(TxQueue::new(channel, DATA_RING_DEPTH).map_err(|_| Error::BadChannel)?);
        }
        Ok(Self { queues })
    }

    /// Reserve a slot, build the header, and fill the TXBD —
    /// without publishing or ringing the doorbell. `args.bd` is the
    /// channel's descriptor ring slice (indexed by slot).
    /// `args.body` is the caller-built 32-byte v2 body (typically
    /// `txrx_be::encode_txwd_be` output for the station). No
    /// TXWD_INFO block follows (BODY0 bit 22 cleared).
    pub(super) fn prepare(&mut self, args: PrepareArgs<'_>) -> Result<Prepared, Error> {
        self.prepare_inner(args, None)
    }

    /// Like [`Self::prepare`], but appends the caller-filled
    /// 32-byte TXWD_INFO v2 block (`txrx_be::fill_txwd_info_v2`
    /// output) after the v2 body and leaves BODY0 bit 22
    /// (WDINFO_EN) set.
    pub(super) fn prepare_with_info(
        &mut self,
        args: PrepareArgs<'_>,
        info: &[u8; TXWD_INFO_SIZE],
    ) -> Result<Prepared, Error> {
        self.prepare_inner(args, Some(info))
    }

    fn prepare_inner(
        &mut self,
        args: PrepareArgs<'_>,
        info: Option<&[u8; TXWD_INFO_SIZE]>,
    ) -> Result<Prepared, Error> {
        if args.channel >= 12 {
            return Err(Error::BadChannel);
        }
        if channel_for_qsel(args.qsel)? != args.channel {
            return Err(Error::BadQsel);
        }
        if args.mac_id >= 32 {
            return Err(Error::BadMacId);
        }
        if args.frame_len == 0 || args.frame_len > MAX_FRAME_LEN {
            return Err(Error::BadFrame);
        }
        if args.frame_dma > FRAME_DMA_MASK || args.header_dma > BUFFER_DMA_MASK {
            return Err(Error::BadDma);
        }
        let queue = self
            .queues
            .get_mut(args.channel as usize)
            .ok_or(Error::BadChannel)?;
        let ticket = queue
            .reserve(
                Retained {
                    header_dma: args.header_dma,
                    frame_dma: args.frame_dma,
                },
                args.mac_id,
                args.qsel,
            )
            .map_err(|(error, _)| map_tx_error(error))?;
        let header = build_header_with_info(
            args.body,
            info,
            ticket.sequence,
            args.frame_dma,
            args.frame_len,
        )?;
        let entry = args
            .bd
            .get_mut(ticket.slot as usize)
            .ok_or(Error::BadIndex)?;
        *entry = TxBd {
            length: header.len() as u16,
            opt: TXBD_OPT_LS,
            ..Default::default()
        };
        entry.set_phys(args.header_dma);
        Ok(Prepared {
            ticket,
            channel: args.channel,
            header,
        })
    }

    /// Publish a prepared frame and ring its doorbell. The
    /// caller must have placed `prepared.header` into header DMA
    /// memory and synced it first. Returns the new host WP.
    pub(super) fn kick(&mut self, regs: &mut impl Regs, prepared: &Prepared) -> Result<u16, Error> {
        let queue = self
            .queues
            .get_mut(prepared.channel as usize)
            .ok_or(Error::BadChannel)?;
        queue.publish(prepared.ticket).map_err(map_tx_error)?;
        let wp = queue.write_pointer();
        doorbell_tx(regs, prepared.channel, wp).map_err(|_| Error::BadChannel)?;
        Ok(wp)
    }

    /// Apply a TX ring read-pointer update: retire every
    /// DMA-complete frame up to `rp`, returning their retained
    /// addresses (the caller frees them only after the matching
    /// RPQ release — see `observe_report`).
    pub(super) fn observe_rp(
        &mut self,
        regs: &mut impl Regs,
        channel: u8,
    ) -> Result<Vec<Completion<Retained>>, Error> {
        let raw = read_tx_idx(regs, channel).map_err(|_| Error::BadChannel)?;
        let (rp, _) = split_idx(raw);
        let queue = self
            .queues
            .get_mut(channel as usize)
            .ok_or(Error::BadChannel)?;
        queue.observe_read_pointer(rp).map_err(map_tx_error)
    }

    /// Apply one RPQ record (Linux's original 4-byte format, via
    /// `tx_transport::parse_report`): retire the matching frame
    /// once its TXBD consumption is also observed. Returns the
    /// completion only when both halves have arrived.
    pub(super) fn observe_report(
        &mut self,
        bytes: &[u8],
    ) -> Result<Option<Completion<Retained>>, Error> {
        let report = tx_transport::parse_report(bytes).map_err(|error| match error {
            tx_transport::Error::BadFrame => Error::BadFrame,
            tx_transport::Error::StaleReport => Error::StaleReport,
            tx_transport::Error::BadQueue => Error::BadQsel,
            _ => Error::BadFrame, // parse_report only yields these three.
        })?;
        let queue = self
            .queues
            .get_mut(report.channel as usize)
            .ok_or(Error::BadChannel)?;
        queue.observe_report(report).map_err(map_tx_error)
    }
}

/// A prepared-but-unkicked H2C buffer on CH12.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct H2cPrepared {
    /// Ring slot the buffer's TXBD occupies.
    pub(super) slot: u16,
    /// Host WP after this buffer is kicked.
    pub(super) next_wp: u16,
}

/// BE H2C owner: the FW-command ring (CH12) with plain-buffer
/// submits. No queue/sequence/RPQ semantics: H2C completions
/// arrive via C2H, not the report queue, so this owner tracks
/// only the ring write pointer.
pub(super) struct H2cTx {
    state: RingState,
}

impl H2cTx {
    /// Empty H2C ring of the given depth (Linux allocates 256
    /// BDs for CH12 like every other TX channel).
    pub(super) fn new(depth: u16) -> Result<Self, Error> {
        if !(2..=256).contains(&depth) {
            return Err(Error::BadLength);
        }
        Ok(Self {
            state: RingState::new(depth),
        })
    }

    /// Fill the TXBD at the current WP for one caller-framed
    /// H2C buffer — without advancing WP or ringing the
    /// doorbell. The caller syncs the buffer before kick.
    pub(super) fn prepare_h2c(
        &mut self,
        bd: &mut [TxBd],
        buf_dma: u64,
        buf_len: usize,
    ) -> Result<H2cPrepared, Error> {
        if self.state.avail() == 0 {
            return Err(Error::Full);
        }
        if buf_len == 0 || buf_len > u16::MAX as usize {
            return Err(Error::BadFrame);
        }
        if buf_dma > BUFFER_DMA_MASK {
            return Err(Error::BadDma);
        }
        let slot = self.state.wp;
        let entry = bd.get_mut(slot as usize).ok_or(Error::BadIndex)?;
        *entry = TxBd {
            length: buf_len as u16,
            opt: TXBD_OPT_LS,
            ..Default::default()
        };
        entry.set_phys(buf_dma);
        let next_wp = ((slot as u32 + 1) % self.state.len as u32) as u16;
        Ok(H2cPrepared { slot, next_wp })
    }

    /// Advance WP past a prepared buffer and ring the CH12
    /// doorbell. A stale or double kick is refused.
    pub(super) fn kick_h2c(
        &mut self,
        regs: &mut impl Regs,
        prepared: &H2cPrepared,
    ) -> Result<u16, Error> {
        if prepared.slot != self.state.wp {
            return Err(Error::BadIndex);
        }
        self.state.advance_wp(1);
        doorbell_tx(regs, 12, self.state.wp).map_err(|_| Error::BadChannel)?;
        Ok(self.state.wp)
    }
}
