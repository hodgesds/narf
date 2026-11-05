// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE packet owner: TX descriptor fill and RX descriptor query.
//!
//! Linux `rtl92de_tx_fill_desc` / `rtl92d_rx_query_desc` over the
//! `trx.rs` layouts. Descriptor field positions are the `trx.rs` fill
//! rules; every value the fill programs is one Linux sets on the same
//! path.
//!
//! ## Admission (fail-closed)
//!
//! [`Owner`] can only be built from a successful firmware download
//! (`firmware_transport::Info`, obtainable only from `run_8192de`)
//! plus a [`super::envelope::Permission`]. There is no channel grant
//! in step 2: the 8192DE has no in-tree factory table, so — mirroring
//! the 8723AE — admission is firmware `Info` + envelope `Permission`
//! alone. Transmit goes through [`Owner::fill_tx_slot`], which refuses
//! unless the frame's operating point equals the permission's point
//! and the rate is admitted by the permission. 5 GHz frames are
//! refused: the step-2 envelope covers 2.4 GHz only.
//!
//! There is deliberately NO RX C2H dispatch: Linux's 92D RX query has
//! no C2H bit (unlike the 8723BE's `rpt_sel`), and the 8192DE is not a
//! Bluetooth combo part, so there is no coexistence owner to feed and
//! no C2H queue. [`Owner::service_rx`] decodes a delivered RX
//! descriptor and returns the frame; the caller strips the trailing
//! FCS and handles `hw_error` frames.
//!
//! ## Single-segment scope
//!
//! This pass fills single-MPDU descriptors only (`firstseg` +
//! `lastseg`, no fragmentation, no AMPDU aggregation). Multi-segment
//! / AMPDU aggregation, RDG + HTC for QoS data, LPS hardware sequence
//! numbers, encryption `sectype`, TX-report requests, multi-station
//! rate-id / MAC-id, the dual-MAC MCS7 short-GI mode bit and the
//! 5 GHz rate floor are remainders for the station owner (the `trx`
//! fill already implements the floor and the mode rule; this owner
//! passes 2.4 GHz single-station values until the station owner wires
//! the mode). Ring-slot allocation, descriptor-ring base programming,
//! the doorbell, and OWN publication stay with the caller: this
//! module fills a caller-provided [`super::trx::TxDesc`] (OWN left
//! clear) and the future `Prepared::Chip::Rtl8192de` packet path owns
//! the rings. No `Prepared` signature changes in this lane.
//!
//! ## Rate numbering
//!
//! Descriptor `hw_rate` values are the `wifi.h` `DESC_RATE*` codes
//! (1M `0x00` … 54M `0x0b`, MCS0-7 continuing at `0x0c`), which is
//! exactly the envelope's full-order rate numbering (CCK 0..3, OFDM
//! 4..11, HT MCS0-7 12..19) — so
//! [`super::envelope::Permission::admits`] gates the descriptor rate
//! directly.

use super::envelope::{Operating, Permission};
use super::trx::{self, RxStatus, TxDesc, TxParams};
use crate::rtlwifi::firmware_transport::Info;

/// Frame class for the firmware queue-select mapping
/// (`_rtl92de_map_hwqueue_to_fwqueue`: beacon → `QSLT_BEACON`,
/// management / control → `QSLT_MGNT`, data → priority).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameClass {
    /// Beacon frame.
    Beacon,
    /// Management frame.
    Mgmt,
    /// Control frame.
    Ctl,
    /// Data frame with 802.11d priority (TID) 0..7.
    Data {
        /// Traffic identifier / priority.
        priority: u8,
    },
}

impl FrameClass {
    /// Firmware queue selector for the class.
    pub const fn queue_sel(self) -> u8 {
        match self {
            FrameClass::Beacon => trx::QSLT_BEACON,
            FrameClass::Mgmt | FrameClass::Ctl => trx::QSLT_MGNT,
            FrameClass::Data { priority } => priority & 7,
        }
    }
}

/// RTS/CTS parameters for a TX descriptor (`ptcb_desc` RTS fields).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rts {
    /// `rts_enable && !cts_enable` → `rts_en`.
    pub rts_enable: bool,
    /// `rts_enable || cts_enable` → `hwrts_en`.
    pub cts_enable: bool,
    /// Short preamble (legacy RTS rate) / short GI (HT RTS rate):
    /// `trx::TxDesc::fill` selects by the RTS rate, so one flag
    /// covers both.
    pub rts_short: bool,
    /// `rts_rate` (descriptor rate code).
    pub rts_rate: u8,
    /// `rts_sc` (sub-carrier).
    pub rts_sc: u8,
    /// `rts_stbc`.
    pub rts_stbc: bool,
}

/// One single-MPDU TX frame to fill a descriptor for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxFrame {
    /// Operating point the frame transmits on (must equal the
    /// permission's point).
    pub op: Operating,
    /// Frame class (queue selector).
    pub class: FrameClass,
    /// Payload length in bytes (packet size and buffer size).
    pub len: usize,
    /// DMA address of the payload buffer (32-bit; `trx.h` dword 8).
    pub buf_addr: u32,
    /// Descriptor rate code (full-order rate, see the module docs).
    pub rate: u8,
    /// Sequence number (`seq_ctrl >> 4`, 12 bits).
    pub seq: u16,
    /// `use_shortgi || use_shortpreamble` → the short bit.
    pub short: bool,
    /// RTS/CTS parameters, or `None` for no RTS/CTS.
    pub rts: Option<Rts>,
    /// Next descriptor address for the ring link (dword 10); 0
    /// terminates.
    pub next_desc: u32,
}

/// Packet-path error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No firmware admission, no envelope permission, or a
    /// permission mismatch for the operating point / rate.
    NotAdmitted,
    /// Frame length invalid (zero or wider than the 16-bit size
    /// fields), or a descriptor / buffer pair that cannot hold the
    /// payload.
    Frame,
    /// The RX descriptor is still hardware-owned (`RxStatus::parse`
    /// returned `None`); the caller must not service the slot yet.
    NotReady,
}

/// One decoded RX frame: status plus the payload slice (which still
/// carries the trailing FCS; the caller strips it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RxFrame<'a> {
    /// Decoded RX status.
    pub status: RxStatus,
    /// Payload bytes.
    pub payload: &'a [u8],
}

/// The DE packet owner: firmware admission + envelope permission.
#[derive(Debug)]
pub struct Owner {
    /// Firmware download result (proof of admission).
    firmware: Info,
    /// Admitted operating point + rates for this board.
    permission: Permission,
}

impl Owner {
    /// Admit a packet owner: only a successful `run_8192de` result
    /// plus a minted envelope permission can construct one.
    pub fn admit(firmware: Info, permission: Permission) -> Self {
        Self {
            firmware,
            permission,
        }
    }

    /// Firmware version admitted (for logging / diagnostics).
    pub fn firmware_version(&self) -> u16 {
        self.firmware.version
    }

    /// The admitted permission.
    pub fn permission(&self) -> Permission {
        self.permission
    }

    /// Admission gate: the operating point must equal the permission's
    /// point and the rate must be admitted by the permission.
    pub fn admit_tx(&self, op: Operating, rate: u8) -> Result<(), Error> {
        if op != self.permission.operating() || !self.permission.admits(rate) {
            return Err(Error::NotAdmitted);
        }
        Ok(())
    }

    /// Fill a TX descriptor for an admitted frame; refused before
    /// any descriptor byte is written when admission fails or the
    /// length is invalid. OWN is left clear: the caller publishes
    /// the slot after the payload buffer is visible, and sets the
    /// ring link from `tx.next_desc` (written here).
    pub fn fill_tx_slot(&self, slot: &mut TxDesc, tx: &TxFrame) -> Result<(), Error> {
        self.admit_tx(tx.op, tx.rate)?;
        if tx.len == 0 || tx.len > 0xffff {
            return Err(Error::Frame);
        }
        let (rts_enable, cts_enable, rts_rate, rts_sc, rts_short, rts_stbc) = match tx.rts {
            Some(r) => (
                r.rts_enable,
                r.cts_enable,
                r.rts_rate,
                r.rts_sc,
                r.rts_short,
                r.rts_stbc,
            ),
            None => (false, false, 0, 0, false, false),
        };
        let forty = tx.op.forty();
        *slot = TxDesc::fill(&TxParams {
            pkt_size: tx.len as u16,
            queue_sel: tx.class.queue_sel(),
            // Single-station pass 1: no RA mask programmed, so the
            // descriptor rate is driver-chosen (`use_driver_rate`)
            // and the rate id / MAC id are 0.
            macid: 0,
            rate_id: 0,
            hw_rate: tx.rate,
            use_driver_rate: true,
            disable_fallback: false,
            use_shortgi: tx.short,
            use_shortpreamble: tx.short,
            bw_40: forty,
            // The frame transmits on the permission's operating point,
            // so the packet bandwidth always equals the station width.
            packet_bw_40: forty,
            cur_40_prime_sc: tx.op.prime_sc(),
            ampdu: false,
            ampdu_density: 0,
            // No security offload in pass 1.
            sec_type: 0,
            qos_data: matches!(tx.class, FrameClass::Data { .. }),
            seq: tx.seq,
            rts_enable,
            cts_enable,
            rts_rate,
            rts_sc,
            rts_stbc,
            rts_use_shortpreamble: rts_short,
            rts_use_shortgi: rts_short,
            buffer_len: tx.len as u16,
            buffer_addr: tx.buf_addr,
            // Step-2 admission is 2.4 GHz only; the 5 GHz floor and
            // the dual-MAC MCS7 rule live in `trx` for the station
            // owner that will wire the mode.
            band_5g: false,
            dual_mac_dual_phy: false,
            fwctrl_lps: false,
            rdg_en: false,
        });
        slot.set_next(tx.next_desc);
        Ok(())
    }

    /// Decode one delivered RX descriptor from its ring slot (`dw`)
    /// against its buffer. A hardware-owned slot is [`Error::NotReady`].
    /// A short buffer is [`Error::Frame`]. A normal frame is returned
    /// with its payload slice for the caller to deliver (FCS still
    /// attached; `hw_error` frames are the caller's to drop).
    pub fn service_rx<'a>(&self, dw: &[u32; 8], buffer: &'a [u8]) -> Result<RxFrame<'a>, Error> {
        let status = RxStatus::parse(dw).ok_or(Error::NotReady)?;
        let start = status.payload_offset();
        let end = start
            .checked_add(usize::from(status.length))
            .ok_or(Error::Frame)?;
        let payload = buffer.get(start..end).ok_or(Error::Frame)?;
        Ok(RxFrame { status, payload })
    }
}
