// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723AE packet owner: 92CE-style TX descriptor fill, RX descriptor
//! query, and packet-path admission.
//!
//! Linux `rtl8723ae/trx.c` (`rtl8723e_tx_fill_desc`,
//! `rtl8723e_rx_query_desc`) over the `trx.h` `tx_desc_8723e` /
//! `rx_desc_8723e` layouts. Descriptor field positions below are the
//! `trx.h` struct bitfields; every value the fill programs is one
//! Linux sets on the same path.
//!
//! ## Admission (fail-closed)
//!
//! [`Owner`] can only be built from a successful firmware download
//! (`firmware_transport::Info`, obtainable only from `Owner::run_8723ae`)
//! plus a [`super::envelope::Permission`] for the operating point. Transmit
//! goes through [`Owner::fill_tx_slot`], which refuses unless the
//! frame's operating point equals the permission's point and the rate
//! is admitted by the permission. There is deliberately NO per-packet
//! BT rejection: Linux's
//! `rtl8723e_dm_bt_reject_ap_aggregated_packet` is an empty no-op
//! stub, so inventing a per-packet BT gate would be fabrication —
//! coexistence acts through the periodical decision and the DM
//! primitives (`coex.rs`), not per packet.
//!
//! ## Single-segment scope
//!
//! This pass fills single-MPDU descriptors only (`firstseg` +
//! `lastseg`, `morefrag` 0, no AMPDU aggregation, `agg_break` 0,
//! `max_agg_num` 0). Multi-segment / AMPDU aggregation, RDG + HTC for
//! QoS data, LPS hardware sequence numbers, encryption `sectype`, and
//! multi-station rate-id / MAC-id are remainders for the station owner
//! (their Linux values are named in the field docs where they belong).
//! Ring-slot allocation, descriptor-ring base programming and the
//! doorbell stay with the caller: this module fills a caller-provided
//! 16-dword slot, and the future `Prepared::Chip::Rtl8723ae` path owns
//! the rings. No `Prepared` signature changes in this lane (see the
//! census in the PR body).
//!
//! ## Rate numbering
//!
//! Descriptor `txrate` values are the `def.h` `DESC92C_RATE*` enum
//! (1M `0x00` … 54M `0x0b`, MCS0-7 continuing at 12), which is exactly
//! the envelope's full-order rate numbering (CCK 0..3, OFDM 4..11, HT
//! MCS0-7 12..19) — so [`super::envelope::Permission::admits`] gates the
//! descriptor rate directly.

use super::c2h::{self, Event, Outcome};
use super::coex;
use super::envelope::{Operating, Permission};
use crate::rtlwifi::firmware_transport::{Error as FwError, Info, Io};
use crate::rtlwifi::irq::IsrStatus;
use crate::rtlwifi::regs::{QSLT_BEACON, QSLT_MGNT};

/// TX descriptor size in dwords (`trx.h::TX_DESC_SIZE` 64 bytes).
pub const TX_DESC_DWORDS: usize = 16;
/// RX descriptor size in dwords (`trx.h::RX_DESC_SIZE` 32 bytes).
pub const RX_DESC_DWORDS: usize = 8;
/// First-segment descriptor offset (`trx.h::USB_HWDESC_HEADER_LEN` 32),
/// set by Linux for every first segment.
pub const TX_DESC_OFFSET: u32 = 32;
/// Data rate fallback limit (`set_tx_desc_data_rate_fb_limit 0x1F`).
pub const TX_RATE_FB_LIMIT: u32 = 0x1f;
/// RTS rate fallback limit (`set_tx_desc_rts_rate_fb_limit 0xF`).
pub const RTS_RATE_FB_LIMIT: u32 = 0x0f;

/// Frame class for the firmware queue-select mapping
/// (`_rtl8723e_map_hwqueue_to_fwqueue`: beacon → `QSLT_BEACON`,
/// management / control → `QSLT_MGNT`, data → priority).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameClass {
    /// Beacon frame.
    Beacon,
    /// Management frame.
    Mgmt,
    /// Control frame.
    Ctl,
    /// Data frame with 802.1d priority (TID) 0..7.
    Data {
        /// Traffic identifier / priority.
        priority: u8,
    },
}

impl FrameClass {
    /// Firmware queue selector for the class.
    pub const fn queue_sel(self) -> u8 {
        match self {
            FrameClass::Beacon => QSLT_BEACON,
            FrameClass::Mgmt | FrameClass::Ctl => QSLT_MGNT,
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
    /// `cts_enable` → `cts2self`.
    pub rts_stbc: bool,
    /// `rts_rate` (descriptor rate code).
    pub rts_rate: u8,
    /// `rts_sc` (sub-carrier).
    pub rts_sc: u8,
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
    /// DMA address of the payload buffer (low 32 bits → DW8, high 32
    /// bits → DW9).
    pub buf_phys: u64,
    /// Descriptor rate code (full-order rate, see the module docs).
    pub rate: u8,
    /// Sequence number (`seq_ctrl >> 4`, 12 bits).
    pub seq: u16,
    /// `use_shortgi || use_shortpreamble` → DW5 short-GI bit.
    pub short_gi: bool,
    /// 40 MHz data bandwidth (`mac->bw_40` in station mode).
    pub bw40: bool,
    /// TX sub-carrier: 3 when the packet bandwidth is 20/40, else the
    /// current 40 MHz prime sub-carrier.
    pub tx_sc: u8,
    /// Whether the destination address is multicast / broadcast
    /// (`bmc` bit; Linux derives it from the frame DA).
    pub bmc: bool,
    /// RTS/CTS parameters, or `None` for no RTS/CTS.
    pub rts: Option<Rts>,
    /// Next descriptor address for the ring link (DW10); 0 terminates.
    pub next_desc: u32,
}

/// Decoded RX descriptor (`rtl8723e_rx_query_desc`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RxReport {
    /// DW0 OWN bit: true while hardware still owns the slot (not
    /// ready); false once hardware has delivered the frame.
    pub hw_owned: bool,
    /// Packet length (DW0 bits 13..0).
    pub pkt_len: u32,
    /// Driver-info size in bytes (DW0 bits 19..16, unit-scaled × 8).
    pub drv_info_bytes: u32,
    /// Buffer shift (DW0 bits 25..24, masked to 2 bits by Linux).
    pub shift: u32,
    /// ICV error (DW0 bit 15).
    pub icv_error: bool,
    /// CRC32 error (DW0 bit 14).
    pub crc_error: bool,
    /// Hardware error: CRC or ICV error.
    pub hw_error: bool,
    /// Software-decrypted flag (DW0 bit 27); decrypted is its negation.
    pub swdec: bool,
    /// Whether the frame arrived decrypted (`!swdec`; the robust-mgmt
    /// fixup Linux applies after frame parse is the caller's job).
    pub decrypted: bool,
    /// RX MCS / rate code (DW3 bits 5..0).
    pub rate: u8,
    /// Short preamble (DW3 bit 8).
    pub short_preamble: bool,
    /// 40 MHz bandwidth (DW3 bit 9).
    pub bw40: bool,
    /// HT frame (DW3 bit 6).
    pub ht: bool,
    /// CCK rate (`RX_HAL_IS_CCK_RATE` on the rate code).
    pub cck: bool,
    /// Part of an A-MPDU (DW1 PAGGR bit 14).
    pub paggr: bool,
    /// First MPDU of an A-MPDU (DW1 FAGGR bit 15, with PAGGR).
    pub first_ampdu: bool,
    /// PHY status present (DW0 bit 26).
    pub physt: bool,
    /// Low timestamp (DW5).
    pub timestamp_low: u32,
    /// Buffer address (DW6).
    pub buf_addr: u32,
}

impl RxReport {
    /// Payload offset into the buffer: driver info + shift.
    pub const fn payload_offset(self) -> u32 {
        self.drv_info_bytes + self.shift
    }

    /// Payload length: packet length minus the offset, saturating.
    pub const fn payload_len(self) -> u32 {
        self.pkt_len.saturating_sub(self.payload_offset())
    }
}

/// Packet-path error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No firmware admission or no envelope permission for the
    /// operating point / rate.
    NotAdmitted,
    /// Frame length invalid (zero or wider than the 16-bit size fields).
    Frame,
    /// Register access failed while servicing the mailbox.
    Access,
}

impl From<FwError> for Error {
    fn from(_: FwError) -> Self {
        Error::Access
    }
}

/// Outcome of servicing the firmware-event mailbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Service {
    /// `c2h_pending` was clear: nothing drained.
    NotPending,
    /// Mailbox already closed by the host: nothing read or written.
    AlreadyClosed,
    /// Close byte neither host- nor firmware-closed: host close
    /// written, body unread.
    NotReady,
    /// Firmware-closed event with an ignored id, consumed.
    Ignored {
        /// Consumed event id (for logging; Linux drops it).
        id: u8,
    },
    /// Firmware-closed BT info event, ingested into the coexistence
    /// owner (if any) and the periodical decision returned.
    BtInfo {
        /// Matrix decision, or `None` when no coexistence owner is
        /// bound (or the board has no BT function).
        pattern: Option<crate::rtlwifi::btcoex::TdmaPattern>,
    },
}

/// Encode one single-MPDU TX descriptor into `slot` (cleared first, as
/// Linux's `clear_pci_tx_desc_content` does). Field positions are the
/// `trx.h::tx_desc_8723e` bitfields; values are the `tx_fill_desc`
/// assignments for a first + last segment. Returns `Err(Frame)` for a
/// zero length or a length wider than the 16-bit size fields.
pub fn encode_tx_desc(slot: &mut [u32; TX_DESC_DWORDS], tx: &TxFrame) -> Result<(), Error> {
    if tx.len == 0 || tx.len > 0xffff {
        return Err(Error::Frame);
    }
    let len = tx.len as u32;
    slot.fill(0);
    // DW0: pktsize[15:0], offset[23:16], bmc[24], lastseg[26],
    // firstseg[27], own[31]. linip is 0.
    slot[0] = len
        | (TX_DESC_OFFSET << 16)
        | (u32::from(tx.bmc) << 24)
        | (1 << 26)
        | (1 << 27)
        | (1 << 31);
    // DW1: queuesel[12:8], rateid[19:16]. Single-station: macid 0,
    // rateid 0 (no RA mask); sectype 0 (no security offload here).
    slot[1] = u32::from(tx.class.queue_sel()) << 8;
    // DW2: morefrag 0 (last segment), ampdudensity 0 (no AMPDU).
    // DW3: seq[27:16], pktid 0.
    slot[3] = (u32::from(tx.seq) & 0xfff) << 16;
    // DW4: rtsrate[4:0], cts2self[11], rts_en[12], hwrts_en[13],
    // txsc[21:20], txbw[25]. rtsbw is 0; stbc 0.
    let (rts_rate, _rts_sc, cts2self, rts_en, hwrts_en, rts_stbc) = match tx.rts {
        Some(r) => (
            r.rts_rate,
            r.rts_sc,
            r.cts_enable,
            r.rts_enable && !r.cts_enable,
            r.rts_enable || r.cts_enable,
            r.rts_stbc,
        ),
        None => (0, 0, false, false, false, false),
    };
    slot[4] = u32::from(rts_rate & 0x1f)
        | (u32::from(cts2self) << 11)
        | (u32::from(rts_en) << 12)
        | (u32::from(hwrts_en) << 13)
        | (u32::from(tx.tx_sc & 3) << 20)
        | (u32::from(tx.bw40) << 25)
        | (u32::from(rts_stbc) << 30);
    // DW5: txrate[5:0], shortgi[6], txrate_fb_lmt[12:8] 0x1F,
    // rtsrate_fb_lmt[16:13] 0xF, disable_fb 0.
    slot[5] = u32::from(tx.rate & 0x3f)
        | (u32::from(tx.short_gi) << 6)
        | (TX_RATE_FB_LIMIT << 8)
        | (RTS_RATE_FB_LIMIT << 13);
    // DW6: txagca/txagcb 0 (firmware RA domain), maxaggnum 0.
    // DW7: txbuffersize[15:0].
    slot[7] = len;
    // DW8/DW9: buffer address low / high.
    slot[8] = tx.buf_phys as u32;
    slot[9] = (tx.buf_phys >> 32) as u32;
    // DW10: next descriptor address (ring link).
    slot[10] = tx.next_desc;
    Ok(())
}

/// Decode one RX descriptor (`rtl8723e_rx_query_desc` field positions).
pub fn decode_rx_desc(d: &[u32; RX_DESC_DWORDS]) -> RxReport {
    let dw0 = d[0];
    let dw1 = d[1];
    let dw3 = d[3];
    let icv_error = dw0 & (1 << 15) != 0;
    let crc_error = dw0 & (1 << 14) != 0;
    let swdec = dw0 & (1 << 27) != 0;
    let paggr = dw1 & (1 << 14) != 0;
    let faggr = dw1 & (1 << 15) != 0;
    let rate = (dw3 & 0x3f) as u8;
    RxReport {
        hw_owned: dw0 & (1 << 31) != 0,
        pkt_len: dw0 & 0x3fff,
        drv_info_bytes: ((dw0 >> 16) & 0xf) * 8,
        shift: (dw0 >> 24) & 0x03,
        icv_error,
        crc_error,
        hw_error: icv_error || crc_error,
        swdec,
        decrypted: !swdec,
        rate,
        short_preamble: dw3 & (1 << 8) != 0,
        bw40: dw3 & (1 << 9) != 0,
        ht: dw3 & (1 << 6) != 0,
        cck: rate <= 3,
        paggr,
        first_ampdu: paggr && faggr,
        physt: dw0 & (1 << 26) != 0,
        timestamp_low: d[5],
        buf_addr: d[6],
    }
}

/// The AE packet owner: firmware admission + envelope permission. The
/// coexistence owner is held by the station owner and passed to
/// [`Owner::service_c2h`] so the mailbox drain feeds it.
#[derive(Debug)]
pub struct Owner {
    /// Firmware download result (proof of admission).
    firmware: Info,
    /// Admitted operating point + rates for this board.
    permission: Permission,
}

impl Owner {
    /// Admit a packet owner: only a successful `run_8723ae` result plus
    /// a minted envelope permission can construct one.
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

    /// Fill a TX descriptor slot for an admitted frame; refused before
    /// any descriptor byte is written when admission fails.
    pub fn fill_tx_slot(
        &self,
        slot: &mut [u32; TX_DESC_DWORDS],
        tx: &TxFrame,
    ) -> Result<(), Error> {
        self.admit_tx(tx.op, tx.rate)?;
        encode_tx_desc(slot, tx)
    }

    /// The mailbox wiring (step-2 item (a)): when `irq::IsrStatus`
    /// reports `c2h_pending` — the Linux `pci.c` fwevt gate, which is
    /// 8723AE-only — drain the firmware-event mailbox; a BT info event
    /// is ingested into the coexistence owner (if bound) and the
    /// periodical decision returned. Ignored ids are consumed without
    /// effect. Io errors abort with no close write (guaranteed by
    /// `c2h::drain`), so the firmware event is not lost.
    pub fn service_c2h<I: Io>(
        &mut self,
        io: &I,
        isr: IsrStatus,
        coex: Option<&mut coex::Owner>,
    ) -> Result<Service, Error> {
        if !isr.c2h_pending() {
            return Ok(Service::NotPending);
        }
        match c2h::drain(io)? {
            Outcome::AlreadyClosed => Ok(Service::AlreadyClosed),
            Outcome::NotReady => Ok(Service::NotReady),
            Outcome::Dispatched(Event::Ignored { id }) => Ok(Service::Ignored { id }),
            Outcome::Dispatched(Event::BtInfo(info)) => {
                let pattern = match coex {
                    Some(owner) => {
                        owner.ingest(&info);
                        owner.periodical()
                    }
                    None => None,
                };
                Ok(Service::BtInfo { pattern })
            }
        }
    }
}
