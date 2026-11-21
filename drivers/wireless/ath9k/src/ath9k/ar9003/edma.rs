// SPDX-License-Identifier: GPL-2.0-or-later
//! The AR9003 EDMA descriptor formats and queue registers from
//! `ar9003_mac.c`/`ar9003_mac.h`, parallel to (and independent of) the
//! AR9002 `descriptor` path: the 128-byte `ar9003_txc` transmit control
//! (`ar9003_set_txdesc`, `ar9003_calc_ptr_chksum`,
//! `ar9003_hw_set_desc_link`), the 36-byte `ar9003_txs` status ring
//! (`ath9k_hw_setup_statusring`, `ath9k_hw_reset_txstatus_ring`,
//! `ar9003_hw_proc_txdesc`) and the 48-byte `ar9003_rxs` status heading
//! every receive buffer of the high/low priority FIFOs
//! (`ath9k_hw_set_rx_bufsize`, `ath9k_hw_addrxbuf_edma`,
//! `ath9k_hw_process_rxdesc_edma`).
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use crate::ath9k::identity::{BringUpError, RegisterIo};

/// `hw.h::ATHEROS_VENDOR_ID`, the `AR_DescId` of every EDMA descriptor.
const ATHEROS_VENDOR_ID: u32 = 0x168c;
/// `sizeof(struct ar9003_txc)` in words (23 used + 8 pad + info).
pub(in crate::ath9k) const TXC_WORDS: usize = 32;
/// `sizeof(struct ar9003_txs)` in words.
pub(in crate::ath9k) const TXS_WORDS: usize = 9;
/// `sizeof(struct ar9003_rxs)` in bytes; the frame follows it in the buffer.
pub(in crate::ath9k) const RXS_BYTES: usize = 48;
/// `ATH9K_HW_RX_HP_QDEPTH` / `ATH9K_HW_RX_LP_QDEPTH`.
pub(in crate::ath9k) const RX_HP_QDEPTH: usize = 16;
pub(in crate::ath9k) const RX_LP_QDEPTH: usize = 128;

const AR_HP_RXDP: u64 = 0x0074;
const AR_LP_RXDP: u64 = 0x0078;
const AR_DATABUF_SIZE: u64 = 0x0060;
const AR_Q_STATUS_RING_START: u64 = 0x0830;
const AR_Q_STATUS_RING_END: u64 = 0x0834;

/// `ATH9K_TXDESC_*` flags this path encodes.
pub(in crate::ath9k) mod flag {
    pub const NOACK: u32 = 0x0002;
    pub const RTSENA: u32 = 0x0004;
    pub const CTSENA: u32 = 0x0008;
    pub const VEOL: u32 = 0x0020;
    pub const EXT_ONLY: u32 = 0x0040;
    pub const EXT_AND_CTL: u32 = 0x0080;
    pub const VMF: u32 = 0x0100;
    pub const LOWRXCHAIN: u32 = 0x0400;
    pub const LDPC: u32 = 0x0800;
    pub const CLRDMASK: u32 = 0x1000;
}

/// One `ath9k_11n_rate_series` entry (`ATH9K_RATESERIES_*` flags).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::ath9k) struct Series {
    pub tries: u8,
    pub rate: u8,
    pub packet_duration: u16,
    pub chain_select: u8,
    pub rts_cts: bool,
    pub ht40: bool,
    pub half_gi: bool,
    pub stbc: bool,
}

/// `ath_tx_info` for a non-aggregated, unencrypted (`ATH9K_KEY_TYPE_CLEAR`)
/// frame; `keyix` `None` is `ATH9K_TXKEYIX_INVALID`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::ath9k) struct TxInfo {
    pub qcu: u8,
    pub link: u32,
    pub buffers: [(u32, u16); 4],
    pub is_first: bool,
    pub is_last: bool,
    pub pkt_len: u16,
    pub frame_type: u8,
    pub flags: u32,
    pub keyix: Option<u8>,
    pub dur_update: bool,
    pub rates: [Series; 4],
    pub rtscts_rate: u8,
    pub txpower: [u8; 4],
}

fn sum_checksum(words: &[u32; TXC_WORDS]) -> u32 {
    // info + link + data0..3 + ctl3/5/7/9 (C `int`, wrapping).
    let checksum = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        .iter()
        .fold(0u32, |a, &i| a.wrapping_add(words[i]));
    ((checksum & 0xffff) + (checksum >> 16)) & 0xffff
}

/// `ar9003_set_txdesc` for an AR9300 (`desc_len` 0x17, `keytype` clear,
/// `AGGR_BUF_NONE`, PAPRD chain mask 0).
pub(in crate::ath9k) fn tx_control(info: &TxInfo) -> [u32; TXC_WORDS] {
    let mut w = [0u32; TXC_WORDS];
    w[0] =
        (ATHEROS_VENDOR_ID << 16) | (1 << 15) | (1 << 14) | (u32::from(info.qcu & 0xf) << 8) | 0x17;
    w[1] = info.link;
    for (i, &(address, length)) in info.buffers.iter().enumerate() {
        w[2 + 2 * i] = address;
        w[3 + 2 * i] = (u32::from(length) << 16) & 0x0fff_0000;
    }
    w[10] = sum_checksum(&w);
    let r = &info.rates;
    if info.is_first || info.is_last {
        w[13] = r.iter().enumerate().fold(0, |a, (i, s)| {
            a | ((u32::from(s.tries) << (16 + 4 * i)) & (0xf << (16 + 4 * i)))
        }) | if info.dur_update { 0x8000 } else { 0 };
        w[14] = r
            .iter()
            .enumerate()
            .fold(0, |a, (i, s)| a | (u32::from(s.rate) << (8 * i)));
    }
    if !info.is_first {
        w[12] = if info.is_last { 0 } else { 0x1000 }; // AR_TxMore.
        return w;
    }
    let f = info.flags;
    let on = |bit: u32, value: u32| if f & bit != 0 { value } else { 0 };
    w[11] = (u32::from(info.pkt_len) & 0xfff)
        | on(flag::VMF, 0x1000)
        | ((u32::from(info.txpower[0]) << 16) & 0x3f_0000)
        | on(flag::VEOL, 0x80_0000)
        | if info.keyix.is_some() { 0x4000_0000 } else { 0 }
        | on(flag::LOWRXCHAIN, 0x4000)
        | on(flag::CLRDMASK, 0x100_0000)
        | if f & flag::RTSENA != 0 {
            0x40_0000
        } else {
            on(flag::CTSENA, 0x8000_0000)
        };
    w[12] = info.keyix.map_or(0, |k| (u32::from(k) << 13) & 0xf_e000)
        | ((u32::from(info.frame_type) << 20) & 0xf0_0000)
        | on(flag::NOACK, 0x100_0000)
        | on(flag::EXT_ONLY, 0x800_0000)
        | on(flag::EXT_AND_CTL, 0x1000_0000);
    w[17] = on(flag::LDPC, 0x8000_0000);
    let duration = |s: &Series, shift: u32, qual: u32| {
        ((u32::from(s.packet_duration) << shift) & (0x7fff << shift))
            | if s.rts_cts { qual } else { 0 }
    };
    w[15] = duration(&r[0], 0, 0x8000) | duration(&r[1], 16, 0x8000_0000);
    w[16] = duration(&r[2], 0, 0x8000) | duration(&r[3], 16, 0x8000_0000);
    let mut ctl18 = (u32::from(info.rtscts_rate) << 20) & 0x0ff0_0000;
    for (i, s) in r.iter().enumerate() {
        let (ht40, gi, stbc, chain) = [
            (0x1, 0x2, 0x1000_0000, 2),
            (0x20, 0x40, 0x2000_0000, 7),
            (0x400, 0x800, 0x4000_0000, 12),
            (0x8000, 0x1_0000, 0x8000_0000, 17),
        ][i];
        ctl18 |= if s.ht40 { ht40 } else { 0 }
            | if s.half_gi { gi } else { 0 }
            | if s.stbc { stbc } else { 0 }
            | ((u32::from(s.chain_select) << chain) & (0x7 << chain));
    }
    w[18] = ctl18;
    w[19] = 0x2000_0000; // AR_Not_Sounding.
    w[20] = (u32::from(info.txpower[1]) << 24) & 0x3f00_0000;
    w[21] = (u32::from(info.txpower[2]) << 24) & 0x3f00_0000;
    w[22] = (u32::from(info.txpower[3]) << 24) & 0x3f00_0000;
    w
}

/// `ar9003_hw_set_desc_link`: new link, recomputed `AR_TxPtrChkSum`.
pub(in crate::ath9k) fn set_link(words: &mut [u32; TXC_WORDS], link: u32) {
    words[1] = link;
    words[10] = (words[10] & !0xffff) | sum_checksum(words);
}

/// One `ar9003_hw_proc_txdesc` result.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::ath9k) struct TxStatus {
    pub rate_index: u8,
    pub seqnum: u16,
    pub tid: u8,
    pub qid: u8,
    pub desc_id: u16,
    pub tstamp: u32,
    /// `ATH9K_TXERR_XRETRY`/`FILT`/`FIFO`/`XTXOP`/`TIMER_EXPIRED`.
    pub excessive_retries: bool,
    pub filtered: bool,
    pub fifo_underrun: bool,
    pub txop_exceeded: bool,
    pub timer_expired: bool,
    /// `ATH9K_TX_DESC_CFG_ERR`/`DATA_UNDERRUN`/`DELIM_UNDERRUN`.
    pub desc_cfg_err: bool,
    pub data_underrun: bool,
    pub delim_underrun: bool,
    /// `ATH9K_TX_BA` with `ba_low`/`ba_high`.
    pub block_ack: Option<(u32, u32)>,
    pub short_retry: u8,
    pub long_retry: u8,
    pub virtual_retry: u8,
    pub rssi: u8,
    pub rssi_ctl: [u8; 3],
    pub rssi_ext: [u8; 3],
}

impl TxStatus {
    /// Whether Linux calls `ath9k_hw_updatetxtriglevel(ah, true)`.
    pub fn raises_trigger_level(&self) -> bool {
        self.fifo_underrun || self.data_underrun || self.delim_underrun
    }
}

/// The TX status ring (`ah->ts_ring`, `ts_tail`, `ts_size`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct StatusRing {
    pub start: u32,
    pub size: u16,
    pub tail: u16,
}

impl StatusRing {
    /// `ath9k_hw_setup_statusring`: `ts_paddr_end = start + size * 36`;
    /// the caller clears the ring entries (`ath9k_hw_reset_txstatus_ring`)
    /// before this programs `AR_Q_STATUS_RING_START`/`END`.
    pub fn setup(io: &mut impl RegisterIo, start: u32, size: u16) -> Result<Self, BringUpError> {
        let end = u64::from(start) + u64::from(size) * (TXS_WORDS as u64 * 4);
        if size == 0 || start % 4 != 0 || end > u64::from(u32::MAX) {
            return Err(BringUpError::Policy);
        }
        if !io.authorized() {
            return Err(BringUpError::DeviceGone);
        }
        io.write32(AR_Q_STATUS_RING_START, start);
        io.write32(AR_Q_STATUS_RING_END, end as u32);
        if !io.authorized() {
            return Err(BringUpError::DeviceGone);
        }
        Ok(Self {
            start,
            size,
            tail: 0,
        })
    }

    /// `ath9k_hw_reset_txstatus_ring` tail reset (entries cleared by the
    /// owner) and the same `AR_Q_STATUS_RING_*` programming.
    pub fn reset(&mut self, io: &mut impl RegisterIo) -> Result<(), BringUpError> {
        *self = Self::setup(io, self.start, self.size)?;
        Ok(())
    }

    /// `ar9003_hw_proc_txdesc` on the entry at `tail` (`entry` is that
    /// slot): `Ok(None)` while `AR_TxDone` is clear (`-EINPROGRESS`), else
    /// the tail advances and the entry is cleared; an entry without the
    /// Atheros `AR_DescId` and `AR_TxRxDesc` is `Err` (`-EIO`).
    pub fn process(
        &mut self,
        entry: &mut [u32; TXS_WORDS],
    ) -> Result<Option<TxStatus>, BringUpError> {
        let s = *entry;
        if s[8] & 1 == 0 {
            return Ok(None);
        }
        self.tail = (self.tail + 1) % self.size;
        *entry = [0; TXS_WORDS];
        if s[0] >> 16 != ATHEROS_VENDOR_ID || (s[0] >> 15) & 1 != 1 {
            return Err(BringUpError::BadState);
        }
        let byte = |word: u32, shift: u32| (word >> shift) as u8;
        Ok(Some(TxStatus {
            rate_index: ((s[8] >> 21) & 3) as u8,
            seqnum: ((s[8] >> 1) & 0xfff) as u16,
            tid: (s[8] >> 28) as u8,
            qid: ((s[0] >> 8) & 0xf) as u8,
            desc_id: (s[1] >> 16) as u16,
            tstamp: s[4],
            excessive_retries: s[3] & 0x2 != 0,
            filtered: s[3] & 0x8 != 0,
            fifo_underrun: s[3] & 0x4 != 0,
            txop_exceeded: s[8] & 0x2_0000 != 0,
            timer_expired: s[3] & 0x8_0000 != 0,
            desc_cfg_err: s[3] & 0x4_0000 != 0,
            data_underrun: s[3] & 0x2_0000 != 0,
            delim_underrun: s[3] & 0x1_0000 != 0,
            block_ack: (s[2] & 0x4000_0000 != 0).then_some((s[5], s[6])),
            short_retry: ((s[3] >> 4) & 0xf) as u8,
            long_retry: ((s[3] >> 8) & 0xf) as u8,
            virtual_retry: ((s[3] >> 12) & 0xf) as u8,
            rssi: byte(s[7], 24),
            rssi_ctl: [byte(s[2], 0), byte(s[2], 8), byte(s[2], 16)],
            rssi_ext: [byte(s[7], 0), byte(s[7], 8), byte(s[7], 16)],
        }))
    }
}

/// `ath9k_hw_set_rx_bufsize` (`AR_DATABUF_SIZE_MASK` 0xfff).
pub(in crate::ath9k) fn set_rx_bufsize(
    io: &mut impl RegisterIo,
    size: u16,
) -> Result<(), BringUpError> {
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    io.write32(AR_DATABUF_SIZE, u32::from(size) & 0xfff);
    Ok(())
}

/// `ath9k_rx_qtype`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) enum RxQueue {
    High,
    Low,
}

/// `ath9k_hw_addrxbuf_edma`: push one buffer onto a receive FIFO.
pub(in crate::ath9k) fn add_rx_buffer(
    io: &mut impl RegisterIo,
    queue: RxQueue,
    address: u32,
) -> Result<(), BringUpError> {
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    io.write32(
        match queue {
            RxQueue::High => AR_HP_RXDP,
            RxQueue::Low => AR_LP_RXDP,
        },
        address,
    );
    Ok(())
}

/// `ath9k_hw_process_rxdesc_edma`'s `ath_rx_status`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::ath9k) struct RxStatus {
    pub datalen: u16,
    pub tstamp: u32,
    pub rssi: u8,
    pub rssi_ctl: [u8; 3],
    pub rssi_ext: [u8; 3],
    /// `None` is `ATH9K_RXKEYIX_INVALID`.
    pub keyix: Option<u8>,
    pub rate: u8,
    pub more: bool,
    pub first_aggr: bool,
    pub is_aggr: bool,
    pub more_aggr: bool,
    pub antenna: u8,
    pub short_gi: bool,
    pub stbc: bool,
    pub ht40: bool,
    pub evm: [u32; 5],
    /// `ATH9K_RX_DELIM_CRC_PRE`/`_POST`/`ATH9K_RX_DECRYPT_BUSY`.
    pub delim_crc_pre: bool,
    pub delim_crc_post: bool,
    pub decrypt_busy: bool,
    /// `ATH9K_RXERR_CRC`/`DECRYPT`/`MIC`/`KEYMISS`; `phy_error` is
    /// `ATH9K_RXERR_PHY` with `rs_phyerr`.
    pub crc_error: bool,
    pub decrypt_error: bool,
    pub mic_error: bool,
    pub phy_error: Option<u8>,
    pub key_miss: bool,
}

/// Sample the 48-byte receive status at the head of a receive buffer the
/// device may be completing right now. `word(i)` reads little-endian
/// status word `i`; `acquire` is the barrier that pairs with the device's
/// `AR_RxDone` write.
///
/// The device writes the status while the host polls it, so a sample must
/// never pair a set `AR_RxDone` with words of the cleared status the
/// buffer was handed back with. Word 11 carries `AR_RxDone`: it is taken
/// first and as ONE load; words 0..=10 are loaded only after it was seen
/// set, when the whole status is in place. `Ok(None)` means "not
/// completed": nothing else of the status was read. Linux
/// `ath9k_hw_process_rxdesc_edma` tests `status11 & AR_RxDone` before it
/// reads anything else.
///
/// Copying the status in ascending order loaded word 11 LAST, so a status
/// posted during the copy showed the cleared buffer's zero `datalen` and
/// `more` under a set `AR_RxDone`.
pub(in crate::ath9k) fn sample_rx_status<E>(
    mut word: impl FnMut(usize) -> Result<u32, E>,
    acquire: impl FnOnce(),
) -> Result<Option<[u8; RXS_BYTES]>, E> {
    const DONE_WORD: usize = RXS_BYTES / 4 - 1;
    let done = word(DONE_WORD)?;
    if done & 1 == 0 {
        return Ok(None);
    }
    acquire();
    let mut status = [0u8; RXS_BYTES];
    for index in 0..=DONE_WORD {
        let value = if index == DONE_WORD {
            done
        } else {
            word(index)?
        };
        status[4 * index..4 * index + 4].copy_from_slice(&value.to_le_bytes());
    }
    Ok(Some(status))
}

/// `ath9k_hw_process_rxdesc_edma` over the first 48 bytes of a receive
/// buffer (little-endian words): `Ok(None)` while `AR_RxDone` is clear or
/// the descriptor is not a receive status (`-EINPROGRESS`), `Err` for a
/// foreign `AR_DescId` (`-EINVAL`).
pub(in crate::ath9k) fn process_rx(buffer: &[u8]) -> Result<Option<RxStatus>, BringUpError> {
    if buffer.len() < RXS_BYTES {
        return Err(BringUpError::BadLength);
    }
    let w: [u32; 12] =
        core::array::from_fn(|i| u32::from_le_bytes(buffer[4 * i..4 * i + 4].try_into().unwrap()));
    if w[11] & 1 == 0 {
        return Ok(None);
    }
    if w[0] >> 16 != ATHEROS_VENDOR_ID {
        return Err(BringUpError::BadState);
    }
    if w[0] & (0x8000 | 0x4000) != 0 {
        return Ok(None);
    }
    let byte = |word: u32, shift: u32| (word >> shift) as u8;
    let s11 = w[11];
    let mut status = RxStatus {
        datalen: (w[2] & 0xfff) as u16,
        tstamp: w[3],
        rssi: byte(w[5], 24),
        rssi_ctl: [byte(w[1], 0), byte(w[1], 8), byte(w[1], 16)],
        rssi_ext: [byte(w[5], 0), byte(w[5], 8), byte(w[5], 16)],
        keyix: (s11 & 0x100 != 0).then_some(((s11 >> 9) & 0x7f) as u8),
        rate: byte(w[1], 24),
        more: w[2] & 0x1000 != 0,
        first_aggr: s11 & 0x2000_0000 != 0,
        is_aggr: s11 & 0x2_0000 != 0,
        more_aggr: s11 & 0x1_0000 != 0,
        antenna: ((w[4] >> 8) & 0x7) as u8,
        short_gi: w[4] & 1 != 0,
        stbc: w[4] & 0x8 != 0,
        ht40: w[4] & 0x2 != 0,
        evm: [w[6], w[7], w[8], w[9], w[10] & 0xffff],
        delim_crc_pre: s11 & 0x40 != 0,
        delim_crc_post: s11 & 0x4_0000 != 0,
        decrypt_busy: s11 & 0x4000_0000 != 0,
        key_miss: s11 & 0x8000_0000 != 0,
        ..RxStatus::default()
    };
    if s11 & 0x2 == 0 {
        if s11 & 0x4 != 0 {
            status.crc_error = true;
        } else if s11 & 0x8 != 0 {
            status.decrypt_error = true;
        } else if s11 & 0x20 != 0 {
            status.mic_error = true;
        }
        if s11 & 0x10 != 0 {
            let code = byte(s11, 8);
            // ATH9K_PHYERR_OFDM_RESTART (23) on a non-last subframe.
            if !(code == 23 && s11 & 0x4_0000 != 0) {
                status.phy_error = Some(code);
            }
        }
    }
    Ok(Some(status))
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;
