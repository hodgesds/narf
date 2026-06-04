//! USB CCID (Chip Card Interface Device) class driver.
//!
//! ## References
//!
//! - **Universal Serial Bus Device Class: Smart Card — CCID**,
//!   Specification for Integrated Circuit(s) Cards Interface Devices,
//!   Revision 1.1, April 22, 2005. USB-IF.
//!   <https://www.usb.org/document-library/smart-card-ccid-version-11>
//!   (Section numbers below cite this document unless noted.)
//! - **ISO/IEC 7816** — Identification cards, integrated circuit cards.
//!   ATR encoding (§T.3.1), T=0 / T=1 framing:
//!   - T=0: ISO/IEC 7816-3:2006 §10 — character-oriented protocol.
//!   - T=1: ISO/IEC 7816-3:2006 §11 — block-oriented protocol.
//!   Framing is handled by the kernel-side `ccid::t0` and `ccid::t1`
//!   sub-modules (see `send_apdu_t0` / `send_apdu_t1`).
//! - **Linux `drivers/usb/class/usbtmc.c`** — GPL-2.0; consulted for
//!   bulk-endpoint configuration pattern (per NARF 2026-05-20 relicense
//!   to GPL-2.0-or-later). We mirror the endpoint-discovery shape but
//!   adapt it to the CCID class.
//!
//! ## Scope
//!
//! 1. Recognise interface (class=0x0B / subclass=0x00 / protocol=0x00).
//! 2. Parse the 54-byte class-specific CCID descriptor (§5.1,
//!    bDescriptorType=0x21) to extract `bNumSlots`, `dwProtocols`,
//!    `dwMaxIFSD`, `dwMaxBaudRate`.
//! 3. Discover Bulk-IN + Bulk-OUT + optional Interrupt-IN endpoints
//!    from the configuration descriptor.
//! 4. Configure those endpoints + issue SET_CONFIGURATION.
//! 5. Expose `power_on` / `power_off` / `send_apdu` against the
//!    addressed slot. Raw-transport path wraps APDU bytes in
//!    `PC_to_RDR_XfrBlock` and unwraps `RDR_to_PC_DataBlock`.
//! 6. `send_apdu_t0` / `send_apdu_t1` provide T=0/T=1 framing so
//!    userspace (pcsc-lite / libccid) doesn't need to deal with CCID
//!    bulk-transport quirks directly.
//!
//! ## Out of scope (deferred)
//!
//! - Secure PIN-entry via CCID `PC_to_RDR_Secure` (0x69) — requires
//!   PIN-pad hardware and a separate threat model review.
//! - Extended APDU reassembly beyond the single-block XfrBlock path.
//! - T=15 / global-interface parameter negotiation, PPS — default-good.

pub mod t0;
pub mod t1;

extern crate alloc;

use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

use crate::xhci::{EndpointConfig, EndpointKind, Xhci};

// ── Class constants ───────────────────────────────────────────────────

/// USB Interface Class for Smart Card (CCID) devices (§4.3 Table 5-1).
pub const CCID_INTERFACE_CLASS: u8 = 0x0B;
/// USB Interface Subclass for CCID (§4.3 Table 5-1).
pub const CCID_INTERFACE_SUBCLASS: u8 = 0x00;
/// USB Interface Protocol for CCID bulk-only transport (§4.3 Table 5-1).
pub const CCID_INTERFACE_PROTOCOL: u8 = 0x00;

/// bDescriptorType for the class-specific CCID descriptor (§5.1).
pub const CCID_DESC_TYPE: u8 = 0x21;

/// Length of the CCID class descriptor, in bytes (§5.1 Table 5-1).
pub const CCID_DESC_LEN: usize = 54;

// ── dwProtocols bit masks (§5.1 Table 5-1) ───────────────────────────

/// dwProtocols bit 0: T=0 supported.
pub const CCID_PROTO_T0: u32 = 1 << 0;
/// dwProtocols bit 1: T=1 supported.
pub const CCID_PROTO_T1: u32 = 1 << 1;

// ── Bulk-OUT message types (host → device, §6.1) ─────────────────────

/// PC_to_RDR_IccPowerOn — power on the ICC, receive ATR (§6.1.1).
pub const PC_TO_RDR_ICC_POWER_ON: u8 = 0x62;
/// PC_to_RDR_IccPowerOff — power off the ICC (§6.1.2).
pub const PC_TO_RDR_ICC_POWER_OFF: u8 = 0x63;
/// PC_to_RDR_GetSlotStatus — query slot status without ICC interaction
/// (§6.1.3).
pub const PC_TO_RDR_GET_SLOT_STATUS: u8 = 0x65;
/// PC_to_RDR_XfrBlock — send an APDU to the ICC (§6.1.4).
pub const PC_TO_RDR_XFR_BLOCK: u8 = 0x6F;

// ── Bulk-IN message types (device → host, §6.2) ──────────────────────

/// RDR_to_PC_DataBlock — ATR or APDU response (§6.2.1).
pub const RDR_TO_PC_DATA_BLOCK: u8 = 0x80;
/// RDR_to_PC_SlotStatus — slot status response (§6.2.2).
pub const RDR_TO_PC_SLOT_STATUS: u8 = 0x81;

/// CCID message header length (§6.1 Table 6-2): bMessageType(1) +
/// dwLength(4) + bSlot(1) + bSeq(1) + abRFU[3] = 10 bytes.
pub const CCID_HDR_LEN: usize = 10;

/// Maximum ATR length: 33 bytes (ISO/IEC 7816-3 §8.2).
pub const ATR_MAX_LEN: usize = 33;

/// Maximum APDU payload we accept from the device per XfrBlock
/// response. The spec maximum is 65536 + CCID_HDR_LEN, but a
/// single-block response is bounded by the Bulk-IN max-packet size;
/// we cap at 4 KiB to prevent malicious device over-allocation.
pub const APDU_MAX_LEN: usize = 4096;

// ── bStatus / bError field decoding (§6.2.6) ─────────────────────────

/// bStatus[1:0] encoding for "command succeeded" (§6.2.6 Table 6-10).
pub const STATUS_SUCCESS: u8 = 0x00;

// ── Standard USB request ──────────────────────────────────────────────

/// USB 2.0 §9.4.7 — SET_CONFIGURATION.
const STD_REQ_SET_CONFIGURATION: u8 = 0x09;

// ── Types ─────────────────────────────────────────────────────────────

/// Parsed content of the 54-byte CCID class-specific descriptor (§5.1).
#[derive(Copy, Clone, Debug)]
pub struct CcidDescriptor {
    /// bcdCCID — class spec version (BCD; e.g. 0x0110 = rev 1.1).
    pub bcd_ccid: u16,
    /// bMaxSlotIndex — highest slot index (0-based; slot count = + 1).
    pub max_slot_index: u8,
    /// bVoltageSupport bit mask (§5.1 Table 5-1):
    ///   bit 0 = 5.0 V, bit 1 = 3.0 V, bit 2 = 1.8 V.
    pub voltage_support: u8,
    /// dwProtocols bit mask — set of T=N protocols supported.
    pub protocols: u32,
    /// dwDefaultClock — default ICC clock frequency (kHz).
    pub default_clock_khz: u32,
    /// dwMaximumClock — maximum clock frequency (kHz).
    pub max_clock_khz: u32,
    /// bNumClockSupported — number of discrete clock frequencies.
    pub num_clocks: u8,
    /// dwDataRate — default ICC I/O data rate (bps).
    pub data_rate_bps: u32,
    /// dwMaxDataRate — maximum data rate (bps).
    pub max_data_rate_bps: u32,
    /// bNumDataRatesSupported — number of discrete data rates.
    pub num_data_rates: u8,
    /// dwMaxIFSD — maximum IFSD for T=1 (§5.1 Table 5-1).
    pub max_ifsd: u32,
    /// dwSynchProtocols — synchronous protocol support bitmask.
    pub synch_protocols: u32,
    /// dwMechanical — mechanical characteristics bitmask.
    pub mechanical: u32,
    /// dwFeatures — optional CCID features bitmask.
    pub features: u32,
    /// dwMaxCCIDMessageLength — maximum CCID message body length.
    pub max_msg_len: u32,
    /// bClassGetResponse — class byte for GET RESPONSE (0xFF = echo).
    pub class_get_response: u8,
    /// bClassEnvelope — class byte for ENVELOPE (0xFF = echo).
    pub class_envelope: u8,
    /// wLcdLayout — LCD layout (rows << 8 | cols; 0 = none).
    pub lcd_layout: u16,
    /// bPINSupport — PIN entry / modification support bitmask.
    pub pin_support: u8,
    /// bMaxCCIDBusySlots — maximum simultaneously busy slots.
    pub max_busy_slots: u8,
}

impl CcidDescriptor {
    /// Decode a 54-byte CCID class descriptor buffer. Returns `None`
    /// if the buffer is shorter than 54 bytes, or if bLength / bDescriptorType
    /// mismatch (§5.1 Table 5-1).
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < CCID_DESC_LEN {
            return None;
        }
        // bLength at +0, bDescriptorType at +1 (§5.1 Table 5-1).
        if buf[0] < CCID_DESC_LEN as u8 || buf[1] != CCID_DESC_TYPE {
            return None;
        }
        let bcd_ccid = u16::from_le_bytes([buf[2], buf[3]]);
        let max_slot_index = buf[4];
        let voltage_support = buf[5];
        let protocols = u32::from_le_bytes([buf[6], buf[7], buf[8], buf[9]]);
        let default_clock_khz = u32::from_le_bytes([buf[10], buf[11], buf[12], buf[13]]);
        let max_clock_khz = u32::from_le_bytes([buf[14], buf[15], buf[16], buf[17]]);
        let num_clocks = buf[18];
        let data_rate_bps = u32::from_le_bytes([buf[19], buf[20], buf[21], buf[22]]);
        let max_data_rate_bps = u32::from_le_bytes([buf[23], buf[24], buf[25], buf[26]]);
        let num_data_rates = buf[27];
        let max_ifsd = u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]);
        let synch_protocols = u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]);
        let mechanical = u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]);
        let features = u32::from_le_bytes([buf[40], buf[41], buf[42], buf[43]]);
        let max_msg_len = u32::from_le_bytes([buf[44], buf[45], buf[46], buf[47]]);
        let class_get_response = buf[48];
        let class_envelope = buf[49];
        let lcd_layout = u16::from_le_bytes([buf[50], buf[51]]);
        let pin_support = buf[52];
        let max_busy_slots = buf[53];
        Some(Self {
            bcd_ccid,
            max_slot_index,
            voltage_support,
            protocols,
            default_clock_khz,
            max_clock_khz,
            num_clocks,
            data_rate_bps,
            max_data_rate_bps,
            num_data_rates,
            max_ifsd,
            synch_protocols,
            mechanical,
            features,
            max_msg_len,
            class_get_response,
            class_envelope,
            lcd_layout,
            pin_support,
            max_busy_slots,
        })
    }
}

/// Discovered CCID bulk endpoints and optional interrupt-IN, plus
/// the configuration-descriptor metadata needed to configure them.
#[derive(Copy, Clone, Debug)]
pub struct CcidEndpoints {
    /// bInterfaceNumber of the CCID interface.
    pub interface: u8,
    /// bConfigurationValue of the configuration containing this
    /// interface (needed for SET_CONFIGURATION).
    pub config_value: u8,
    /// Bulk-IN endpoint.
    pub bulk_in: EndpointConfig,
    /// Bulk-OUT endpoint.
    pub bulk_out: EndpointConfig,
    /// Optional Interrupt-IN endpoint for slot change notifications
    /// (§3.1.3.3). Present on most readers; `None` on some embedded
    /// readers that omit it.
    pub intr_in: Option<EndpointConfig>,
}

/// Error variants for CCID bind / message operations.
#[derive(Copy, Clone, Debug)]
pub enum CcidError {
    /// Configuration descriptor has no CCID interface (0x0B/0x00/0x00).
    NotCcid,
    /// Found a CCID interface but it is missing a required bulk endpoint
    /// (spec requires exactly one Bulk-IN + one Bulk-OUT; §3.1.3).
    EndpointsMissing,
    /// CCID class descriptor absent or too short in configuration blob.
    CcidDescriptorMissing,
    /// xHCI control / bulk transfer error.
    Transfer,
    /// Device returned an unexpected response message type.
    BadResponse,
    /// Device reported a command error in bStatus.bError (§6.2.6).
    CommandError(u8),
    /// Response payload too long for our buffer.
    ResponseTooLong,
}

/// ATR (Answer To Reset) from a freshly powered-on ICC.
#[derive(Debug)]
pub struct Atr {
    /// Raw ATR bytes as received from the ICC (1–33 bytes).
    pub bytes: Vec<u8>,
}

/// A bound CCID smart-card reader.
#[derive(Debug)]
pub struct CcidReader {
    /// xHCI slot ID for this device.
    pub slot_id: u8,
    /// Number of physical card slots (= max_slot_index + 1).
    pub num_slots: u8,
    /// Parsed class-specific CCID descriptor.
    pub descriptor: CcidDescriptor,
    /// Bulk-IN endpoint, used to receive CCID responses.
    pub bulk_in_ep: EndpointConfig,
    /// Bulk-OUT endpoint, used to send CCID commands.
    pub bulk_out_ep: EndpointConfig,
    /// Optional Interrupt-IN endpoint for slot-change events.
    pub intr_in_ep: Option<EndpointConfig>,
    /// Per-slot sequence number counter. Wraps at 255 per §6.1
    /// (bSeq must be unique per command within a slot).
    seq: IrqSafeSpinLock<[u8; 16]>,
}

impl CcidReader {
    /// Increment and return the next sequence number for `slot`.
    fn next_seq(&self, slot: u8) -> u8 {
        let mut g = self.seq.lock();
        let s = slot as usize & 15;
        let n = g[s].wrapping_add(1);
        g[s] = n;
        n
    }

    /// DCI (Device Context Index) for the Bulk-IN endpoint.
    /// §4.8.1: DCI = (ep_num × 2) + 1 for IN.
    fn bulk_in_dci(&self) -> u8 {
        let num = self.bulk_in_ep.ep_addr & 0x0F;
        num * 2 + 1
    }

    /// DCI for the Bulk-OUT endpoint. §4.8.1: DCI = (ep_num × 2) + 0
    /// for OUT.
    fn bulk_out_dci(&self) -> u8 {
        let num = self.bulk_out_ep.ep_addr & 0x0F;
        num * 2
    }

    /// Build the 10-byte CCID message header (§6.1 Table 6-2).
    ///
    /// Layout:
    ///   +0  bMessageType
    ///   +1..+4  dwLength (payload length, LE32)
    ///   +5  bSlot
    ///   +6  bSeq
    ///   +7..+9  abRFU / command-specific bytes (zeroed for generic msgs)
    pub fn build_header(msg_type: u8, payload_len: u32, slot: u8, seq: u8) -> [u8; CCID_HDR_LEN] {
        let mut h = [0u8; CCID_HDR_LEN];
        h[0] = msg_type;
        h[1..5].copy_from_slice(&payload_len.to_le_bytes());
        h[5] = slot;
        h[6] = seq;
        // h[7..10] = abRFU — zero for IccPowerOn / IccPowerOff /
        // GetSlotStatus. XfrBlock caller fills bBWI at +7, wLevelParameter
        // at +8..+9 (§6.1.4 Table 6-7). We zero here; callers override.
        h
    }

    /// Decode a Bulk-IN response header and return (msg_type, payload_len,
    /// slot, seq, bStatus, bError). Returns `CcidError::BadResponse` if
    /// the buffer is shorter than `CCID_HDR_LEN`.
    ///
    /// Layout (§6.2 Table 6-7 / §6.2.6):
    ///   +0  bMessageType
    ///   +1..+4  dwLength (LE32) — payload bytes following the header
    ///   +5  bSlot
    ///   +6  bSeq
    ///   +7  bStatus (bits[1:0]: 00=ok, 01=fail, 10=time-ext)
    ///   +8  bError
    ///   +9  command-specific (e.g. bChainParameter for DataBlock)
    pub fn decode_response_header(buf: &[u8]) -> Result<(u8, u32, u8, u8, u8, u8), CcidError> {
        if buf.len() < CCID_HDR_LEN {
            return Err(CcidError::BadResponse);
        }
        let msg_type = buf[0];
        let payload_len = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
        let slot = buf[5];
        let seq = buf[6];
        let b_status = buf[7];
        let b_error = buf[8];
        Ok((msg_type, payload_len, slot, seq, b_status, b_error))
    }

    /// Power on slot `slot` and return the ICC's Answer-To-Reset.
    ///
    /// Sends `PC_to_RDR_IccPowerOn` (§6.1.1) and decodes the
    /// `RDR_to_PC_DataBlock` (§6.2.1) response. The `bPowerSelect`
    /// byte (abRFU[0]) is set to 0 (automatic voltage negotiation).
    pub async fn power_on(&self, xhci_dev: &Xhci, slot: u8) -> Result<Atr, CcidError> {
        let seq = self.next_seq(slot);
        let mut hdr = Self::build_header(PC_TO_RDR_ICC_POWER_ON, 0, slot, seq);
        // bPowerSelect = 0x00 → automatic (§6.1.1 Table 6-1).
        hdr[7] = 0x00;
        xhci_dev
            .bulk_out(self.slot_id, self.bulk_out_dci(), &hdr)
            .await
            .map_err(|_| CcidError::Transfer)?;

        // Receive the response. The ATR fits in one Bulk-IN transfer.
        let mut resp = alloc::vec![0u8; CCID_HDR_LEN + ATR_MAX_LEN];
        let n = xhci_dev
            .bulk_in(self.slot_id, self.bulk_in_dci(), &mut resp)
            .await
            .map_err(|_| CcidError::Transfer)?;
        if n < CCID_HDR_LEN {
            return Err(CcidError::BadResponse);
        }
        let (msg_type, payload_len, _rslot, _rseq, b_status, b_error) =
            Self::decode_response_header(&resp[..n])?;
        if msg_type != RDR_TO_PC_DATA_BLOCK {
            return Err(CcidError::BadResponse);
        }
        if b_status & 0x03 != STATUS_SUCCESS {
            return Err(CcidError::CommandError(b_error));
        }
        let payload_len = payload_len as usize;
        if payload_len > ATR_MAX_LEN {
            return Err(CcidError::ResponseTooLong);
        }
        let end = CCID_HDR_LEN + payload_len.min(n.saturating_sub(CCID_HDR_LEN));
        Ok(Atr {
            bytes: resp[CCID_HDR_LEN..end].to_vec(),
        })
    }

    /// Power off slot `slot`.
    ///
    /// Sends `PC_to_RDR_IccPowerOff` (§6.1.2) and waits for the
    /// `RDR_to_PC_SlotStatus` (§6.2.2) acknowledgement.
    pub async fn power_off(&self, xhci_dev: &Xhci, slot: u8) -> Result<(), CcidError> {
        let seq = self.next_seq(slot);
        let hdr = Self::build_header(PC_TO_RDR_ICC_POWER_OFF, 0, slot, seq);
        xhci_dev
            .bulk_out(self.slot_id, self.bulk_out_dci(), &hdr)
            .await
            .map_err(|_| CcidError::Transfer)?;

        let mut resp = [0u8; CCID_HDR_LEN];
        let n = xhci_dev
            .bulk_in(self.slot_id, self.bulk_in_dci(), &mut resp)
            .await
            .map_err(|_| CcidError::Transfer)?;
        if n < CCID_HDR_LEN {
            return Err(CcidError::BadResponse);
        }
        let (msg_type, _pl, _rs, _rseq, b_status, b_error) = Self::decode_response_header(&resp)?;
        if msg_type != RDR_TO_PC_SLOT_STATUS {
            return Err(CcidError::BadResponse);
        }
        if b_status & 0x03 != STATUS_SUCCESS {
            return Err(CcidError::CommandError(b_error));
        }
        Ok(())
    }

    /// Send raw payload bytes via `PC_to_RDR_XfrBlock` (§6.1.4) and
    /// return the `RDR_to_PC_DataBlock` (§6.2.1) response payload.
    ///
    /// Internal transport primitive. Called by `send_apdu`,
    /// `send_apdu_t0`, and `send_apdu_t1`.
    ///
    /// bBWI (+7) = 0 (device default). wLevelParameter (+8..+9) = 0
    /// (single APDU, no chaining; CCID spec rev 1.1 §6.1.4 Table 6-7).
    async fn xfr_block_raw(
        &self,
        xhci_dev: &Xhci,
        slot: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, CcidError> {
        let seq = self.next_seq(slot);
        let payload_len = payload.len() as u32;
        let mut msg = alloc::vec![0u8; CCID_HDR_LEN + payload.len()];
        msg[..CCID_HDR_LEN].copy_from_slice(&Self::build_header(
            PC_TO_RDR_XFR_BLOCK,
            payload_len,
            slot,
            seq,
        ));
        msg[CCID_HDR_LEN..].copy_from_slice(payload);
        xhci_dev
            .bulk_out(self.slot_id, self.bulk_out_dci(), &msg)
            .await
            .map_err(|_| CcidError::Transfer)?;

        let mut resp = alloc::vec![0u8; CCID_HDR_LEN + APDU_MAX_LEN];
        let n = xhci_dev
            .bulk_in(self.slot_id, self.bulk_in_dci(), &mut resp)
            .await
            .map_err(|_| CcidError::Transfer)?;
        if n < CCID_HDR_LEN {
            return Err(CcidError::BadResponse);
        }
        let (msg_type, payload_len, _rs, _rseq, b_status, b_error) =
            Self::decode_response_header(&resp[..n])?;
        if msg_type != RDR_TO_PC_DATA_BLOCK {
            return Err(CcidError::BadResponse);
        }
        if b_status & 0x03 != STATUS_SUCCESS {
            return Err(CcidError::CommandError(b_error));
        }
        let payload_len = payload_len as usize;
        if payload_len > APDU_MAX_LEN {
            return Err(CcidError::ResponseTooLong);
        }
        let end = CCID_HDR_LEN + payload_len.min(n.saturating_sub(CCID_HDR_LEN));
        Ok(resp[CCID_HDR_LEN..end].to_vec())
    }

    /// Send an APDU to slot `slot` via `PC_to_RDR_XfrBlock` (§6.1.4)
    /// and return the response from `RDR_to_PC_DataBlock` (§6.2.1).
    ///
    /// Wraps raw APDU bytes without protocol framing. Use
    /// `send_apdu_t0` / `send_apdu_t1` for fully-framed exchanges.
    pub async fn send_apdu(
        &self,
        xhci_dev: &Xhci,
        slot: u8,
        apdu: &[u8],
    ) -> Result<Vec<u8>, CcidError> {
        self.xfr_block_raw(xhci_dev, slot, apdu).await
    }

    // ── T=0 public API ────────────────────────────────────────────────

    /// Send a T=0 APDU to `slot`, handling GET_RESPONSE chaining
    /// (SW1=0x61 per ISO 7816-3 §10.3.3) automatically.
    ///
    /// Returns the full response payload with SW1:SW2 appended as the
    /// final 2 bytes. All DATA bytes from chained GET_RESPONSE calls
    /// are concatenated before the status word.
    ///
    /// ## References
    ///
    /// - ISO/IEC 7816-3:2006 §10.3.3 — T=0 GET_RESPONSE procedure.
    /// - USB CCID spec rev 1.1 §6.1.4 / §6.2.1 — XfrBlock transport.
    pub async fn send_apdu_t0(
        &self,
        xhci_dev: &Xhci,
        slot: u8,
        apdu: &t0::T0Apdu,
    ) -> Result<Vec<u8>, CcidError> {
        let cla = apdu.cla();
        let mut raw_resp = self.xfr_block_raw(xhci_dev, slot, apdu.as_bytes()).await?;

        let mut collected: Vec<u8> = Vec::new();
        let mut iters = 0usize;

        loop {
            let (data, sw1, sw2) = t0::decode_response(&raw_resp)?;
            collected.extend_from_slice(data);

            if sw1 != t0::SW1_GET_RESPONSE || iters >= t0::MAX_GET_RESPONSE_ITERS {
                collected.push(sw1);
                collected.push(sw2);
                return Ok(collected);
            }

            // SW1 = 0x61 → more data; issue GET_RESPONSE(Le=SW2).
            let gr = t0::build_get_response(cla, sw2);
            raw_resp = self.xfr_block_raw(xhci_dev, slot, gr.as_bytes()).await?;
            iters += 1;
        }
    }

    // ── T=1 public API ────────────────────────────────────────────────

    /// Send a complete APDU over T=1 to `slot`.
    ///
    /// Wraps the APDU in a single I-block and handles R-block / S-block
    /// responses per ISO 7816-3 §11.6:
    ///
    /// - **I-block**: normal card response — return INF bytes.
    /// - **R-block NAK**: retransmit the I-block (up to 3 times).
    /// - **S(WTX request)**: respond S(WTX response) and re-poll.
    /// - **S(IFS request)**: respond S(IFS response) and re-poll.
    /// - **S(RESYNCH response)**: reset sequence numbers and retransmit.
    ///
    /// Returns `CcidError::ResponseTooLong` if `apdu` exceeds 254 bytes
    /// (ISO 7816-3 §11.3.1.1 — single-block INF limit).
    ///
    /// ## References
    ///
    /// - ISO/IEC 7816-3:2006 §11.6 — T=1 block-exchange procedure.
    /// - USB CCID spec rev 1.1 §6.1.4 — XfrBlock for T=1.
    pub async fn send_apdu_t1(
        &self,
        xhci_dev: &Xhci,
        slot: u8,
        apdu: &[u8],
    ) -> Result<Vec<u8>, CcidError> {
        if apdu.len() > 254 {
            return Err(CcidError::ResponseTooLong);
        }

        let mut seq = t1::T1SeqState::default();
        const MAX_RETRIES: usize = 3;
        let mut retries = 0usize;

        let ns = seq.next_ns();
        let send_block = t1::T1Block::i_block(ns, apdu);
        let mut current_wire = send_block.encode()?;

        loop {
            let resp_raw = self.xfr_block_raw(xhci_dev, slot, &current_wire).await?;
            let block = t1::T1Block::decode(&resp_raw).map_err(|_| CcidError::BadResponse)?;

            if block.is_iblock() {
                seq.advance_nr();
                return Ok(block.inf);
            }

            if block.is_rblock() {
                if !block.r_error() {
                    // R(ACK): single-block success.
                    return Ok(block.inf);
                }
                // R(NAK): retransmit.
                if retries >= MAX_RETRIES {
                    return Err(CcidError::Transfer);
                }
                retries += 1;
                continue; // current_wire unchanged
            }

            if block.is_sblock() {
                match block.pcb {
                    t1::PCB_SBLOCK_WTX_REQ => {
                        let mult = block.inf.first().copied().unwrap_or(1);
                        current_wire = t1::T1Block::s_wtx_response(mult).encode()?;
                    }
                    t1::PCB_SBLOCK_IFS_REQ => {
                        let ifsd = block.inf.first().copied().unwrap_or(254);
                        current_wire = t1::T1Block::s_ifs_response(ifsd).encode()?;
                    }
                    t1::PCB_SBLOCK_RESYNCH_RESP => {
                        if retries >= MAX_RETRIES {
                            return Err(CcidError::Transfer);
                        }
                        retries += 1;
                        seq.reset();
                        let ns2 = seq.next_ns();
                        current_wire = t1::T1Block::i_block(ns2, apdu).encode()?;
                    }
                    _ => return Err(CcidError::BadResponse),
                }
                continue;
            }

            return Err(CcidError::BadResponse);
        }
    }
}

/// Global registry of bound CCID readers. Append-only — a userland
/// PC/SC daemon attaches by index or slot_id when it loads.
pub static CCID_READERS: IrqSafeSpinLock<Vec<CcidReader>> = IrqSafeSpinLock::new(Vec::new());

/// Return the number of CCID readers currently registered.
pub fn attached_count() -> usize {
    CCID_READERS.lock().len()
}

#[doc(hidden)]
pub fn __reset_ccid_for_test() {
    CCID_READERS.lock().clear();
}

// ── Configuration-descriptor walkers ─────────────────────────────────

/// Walk the configuration descriptor for the first CCID interface
/// (class=0x0B / subclass=0x00 / protocol=0x00). Returns the
/// bInterfaceNumber and the byte offset of the interface descriptor
/// within `cfg`, or `None` if not found.
///
/// USB 2.0 §9.6.5 — Interface Descriptor is 9 bytes, bDescriptorType=4;
/// bInterfaceClass at +5, bInterfaceSubClass at +6, bInterfaceProtocol at +7.
pub fn find_ccid_interface(cfg: &[u8]) -> Option<(u8, usize)> {
    let mut i = 0usize;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        if cfg[i + 1] == 4
            && len >= 9
            && cfg[i + 5] == CCID_INTERFACE_CLASS
            && cfg[i + 6] == CCID_INTERFACE_SUBCLASS
            && cfg[i + 7] == CCID_INTERFACE_PROTOCOL
        {
            return Some((cfg[i + 2], i));
        }
        i += len;
    }
    None
}

/// Scan the descriptors following the CCID interface descriptor for
/// the 54-byte class-specific CCID descriptor (bDescriptorType=0x21)
/// and return it parsed.
///
/// Per §5.1 the CCID descriptor immediately follows the interface
/// descriptor (before any endpoint descriptors).
pub fn find_ccid_class_descriptor(cfg: &[u8], iface_offset: usize) -> Option<CcidDescriptor> {
    let mut i = iface_offset;
    // Skip the interface descriptor itself.
    if i + 2 <= cfg.len() {
        let skip = cfg[i] as usize;
        if skip >= 2 {
            i += skip;
        }
    }
    // Walk subsequent descriptors until we find type 0x21 or hit
    // an interface / endpoint descriptor boundary.
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let dtype = cfg[i + 1];
        // 0x21 = CCID class-specific descriptor (§5.1).
        if dtype == CCID_DESC_TYPE && len >= CCID_DESC_LEN {
            return CcidDescriptor::from_bytes(&cfg[i..i + len]);
        }
        // 0x04 = next interface; 0x05 = endpoint; stop searching.
        if dtype == 0x04 || dtype == 0x05 {
            break;
        }
        i += len;
    }
    None
}

/// Walk descriptors after `iface_offset` collecting bulk-IN, bulk-OUT
/// and optional interrupt-IN endpoints. Stops at the next interface
/// descriptor. Returns `(bulk_in, bulk_out, intr_in)` or
/// `CcidError::EndpointsMissing` if either bulk endpoint is absent.
///
/// USB 2.0 §9.6.6 — Endpoint Descriptor is 7 bytes, bDescriptorType=5;
/// bEndpointAddress at +2, bmAttributes[1:0] at +3
/// (0=control, 1=isoch, 2=bulk, 3=interrupt), wMaxPacketSize LE16 at +4.
pub fn find_ccid_endpoints(cfg: &[u8], iface_offset: usize) -> Result<CcidEndpoints, CcidError> {
    let config_value = if cfg.len() >= 6 { cfg[5] } else { 1 };
    let interface = if iface_offset + 2 < cfg.len() {
        cfg[iface_offset + 2]
    } else {
        0
    };

    let mut bulk_in: Option<EndpointConfig> = None;
    let mut bulk_out: Option<EndpointConfig> = None;
    let mut intr_in: Option<EndpointConfig> = None;

    let mut i = iface_offset;
    // Skip the interface descriptor.
    if i + 2 <= cfg.len() {
        let skip = cfg[i] as usize;
        if skip >= 2 {
            i += skip;
        }
    }
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let dtype = cfg[i + 1];
        if dtype == 0x04 {
            // Hit the next interface — stop.
            break;
        }
        if dtype == 0x05 && len >= 7 {
            let ep_addr = cfg[i + 2];
            let attrs = cfg[i + 3] & 0x03;
            let max_packet = u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]);
            let dir_in = ep_addr & 0x80 != 0;
            match attrs {
                2 /* bulk */ => {
                    let kind = if dir_in {
                        EndpointKind::BulkIn
                    } else {
                        EndpointKind::BulkOut
                    };
                    let ec = EndpointConfig { ep_addr, max_packet, kind };
                    if dir_in && bulk_in.is_none() {
                        bulk_in = Some(ec);
                    } else if !dir_in && bulk_out.is_none() {
                        bulk_out = Some(ec);
                    }
                }
                3 /* interrupt */ if dir_in => {
                    if intr_in.is_none() {
                        intr_in = Some(EndpointConfig {
                            ep_addr,
                            max_packet,
                            kind: EndpointKind::InterruptIn,
                        });
                    }
                }
                _ => {}
            }
        }
        i += len;
    }

    match (bulk_in, bulk_out) {
        (Some(bi), Some(bo)) => Ok(CcidEndpoints {
            interface,
            config_value,
            bulk_in: bi,
            bulk_out: bo,
            intr_in,
        }),
        _ => Err(CcidError::EndpointsMissing),
    }
}

// ── Bind path ─────────────────────────────────────────────────────────

/// Attempt to bind an already-addressed device as a CCID smart-card
/// reader. Returns the index in `CCID_READERS` on success.
///
/// **Slot lifecycle**: does NOT call `disable_slot` on failure. The
/// dispatcher in `attach.rs` owns the slot.
pub async fn try_bind_ccid_already_addressed(
    xhci_dev: &Xhci,
    slot_id: u8,
    cfg: &[u8],
) -> Result<usize, CcidError> {
    // Step 1: find the CCID interface + class descriptor.
    let (iface_num, iface_off) = find_ccid_interface(cfg).ok_or(CcidError::NotCcid)?;
    let desc =
        find_ccid_class_descriptor(cfg, iface_off).ok_or(CcidError::CcidDescriptorMissing)?;
    // Step 2: collect endpoints.
    let eps = find_ccid_endpoints(cfg, iface_off)?;

    // Step 3: SET_CONFIGURATION (USB 2.0 §9.4.7).
    let mut nothing = [0u8; 0];
    xhci_dev
        .control_in(
            slot_id,
            0x00,
            STD_REQ_SET_CONFIGURATION,
            eps.config_value as u16,
            0,
            &mut nothing,
        )
        .await
        .map_err(|_| CcidError::Transfer)?;

    // Step 4: configure xHCI endpoints for the bulk pair (+ intr-IN
    // if present). Mirrors `btusb`'s `configure_endpoints` call shape.
    let mut ep_cfgs: Vec<EndpointConfig> = alloc::vec![eps.bulk_in, eps.bulk_out];
    if let Some(intr) = eps.intr_in {
        ep_cfgs.push(intr);
    }
    xhci_dev
        .configure_endpoints(slot_id, &ep_cfgs)
        .await
        .map_err(|_| CcidError::Transfer)?;

    // Step 5: log + register.
    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "  usb-ccid: reader on slot={} iface={} slots={} proto={:#010x} maxIFSD={}",
            slot_id,
            iface_num,
            desc.max_slot_index + 1,
            desc.protocols,
            desc.max_ifsd,
        );
    }

    let reader = CcidReader {
        slot_id,
        num_slots: desc.max_slot_index.saturating_add(1),
        descriptor: desc,
        bulk_in_ep: eps.bulk_in,
        bulk_out_ep: eps.bulk_out,
        intr_in_ep: eps.intr_in,
        seq: IrqSafeSpinLock::new([0u8; 16]),
    };
    let mut g = CCID_READERS.lock();
    let idx = g.len();
    g.push(reader);
    Ok(idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Smoke 1: CCID descriptor decode — T=0 + T=1 bits ─────────────

    #[test]
    fn ccid_descriptor_decodes_t0_t1_protocols() {
        // Build a minimal 54-byte CCID class descriptor with
        // dwProtocols = T=0 | T=1 (bits 0..1 set).
        let mut buf = [0u8; 54];
        buf[0] = 54; // bLength
        buf[1] = CCID_DESC_TYPE; // bDescriptorType = 0x21
        buf[2] = 0x10; // bcdCCID LSB
        buf[3] = 0x01; // bcdCCID MSB → 0x0110 = rev 1.1
        buf[4] = 0; // bMaxSlotIndex (1 slot)
        buf[5] = 0x07; // bVoltageSupport: 5V+3V+1.8V
                       // dwProtocols: T=0 (bit 0) | T=1 (bit 1).
        buf[6..10].copy_from_slice(&(CCID_PROTO_T0 | CCID_PROTO_T1).to_le_bytes());
        // dwMaxIFSD = 254 (T=1 default, §5.1 Table 5-1).
        buf[28..32].copy_from_slice(&254u32.to_le_bytes());
        // dwMaxCCIDMessageLength = 271 (CCID_HDR_LEN + 261 = max APDU).
        buf[44..48].copy_from_slice(&271u32.to_le_bytes());

        let d = CcidDescriptor::from_bytes(&buf).expect("decode failed");
        assert_eq!(d.bcd_ccid, 0x0110, "bcdCCID should be 0x0110 (rev 1.1)");
        assert_ne!(d.protocols & CCID_PROTO_T0, 0, "T=0 bit should be set");
        assert_ne!(d.protocols & CCID_PROTO_T1, 0, "T=1 bit should be set");
        assert_eq!(d.max_ifsd, 254, "maxIFSD round-trip");
        assert_eq!(d.max_slot_index, 0, "single-slot reader");
    }

    // ── Smoke 2: PC_to_RDR_IccPowerOn header encode ───────────────────

    #[test]
    fn pc_to_rdr_icc_power_on_header_encodes() {
        let hdr = CcidReader::build_header(PC_TO_RDR_ICC_POWER_ON, 0, 0, 0x42);
        assert_eq!(hdr[0], PC_TO_RDR_ICC_POWER_ON, "bMessageType");
        // dwLength = 0 (no payload for IccPowerOn command).
        assert_eq!(&hdr[1..5], &0u32.to_le_bytes(), "dwLength = 0");
        assert_eq!(hdr[5], 0, "bSlot = 0");
        assert_eq!(hdr[6], 0x42, "bSeq = 0x42");
    }

    // ── Smoke 3: RDR_to_PC_DataBlock decode ───────────────────────────

    #[test]
    fn rdr_to_pc_data_block_decodes() {
        // Build a 10-byte DataBlock header with a 4-byte ATR payload.
        let atr_bytes: [u8; 4] = [0x3B, 0x90, 0x11, 0x00];
        let mut buf = alloc::vec![0u8; CCID_HDR_LEN + atr_bytes.len()];
        buf[0] = RDR_TO_PC_DATA_BLOCK;
        buf[1..5].copy_from_slice(&(atr_bytes.len() as u32).to_le_bytes());
        buf[5] = 0; // bSlot
        buf[6] = 0x42; // bSeq
        buf[7] = STATUS_SUCCESS; // bStatus — success
        buf[8] = 0x00; // bError
        buf[9] = 0x00; // bChainParameter
        buf[10..14].copy_from_slice(&atr_bytes);

        let (msg_type, payload_len, slot, seq, b_status, b_error) =
            CcidReader::decode_response_header(&buf).expect("decode header");
        assert_eq!(msg_type, RDR_TO_PC_DATA_BLOCK, "bMessageType");
        assert_eq!(payload_len, 4, "dwLength");
        assert_eq!(slot, 0, "bSlot");
        assert_eq!(seq, 0x42, "bSeq");
        assert_eq!(b_status & 0x03, STATUS_SUCCESS, "bStatus success");
        assert_eq!(b_error, 0, "bError = 0");

        // Confirm ATR payload is accessible at the right offset.
        let payload = &buf[CCID_HDR_LEN..CCID_HDR_LEN + payload_len as usize];
        assert_eq!(payload, &atr_bytes[..], "ATR payload round-trip");
    }

    // ── Smoke 4: Bind path on fake config descriptor ──────────────────

    #[test]
    fn find_ccid_interface_and_endpoints_on_fake_descriptor() {
        // Construct a minimal config descriptor with a CCID interface:
        //   - 9-byte Configuration Descriptor
        //   - 9-byte Interface Descriptor (class=0x0B/0x00/0x00, numEP=3)
        //   - 54-byte CCID Class Descriptor
        //   - 7-byte Bulk-IN Endpoint (EP1 IN)
        //   - 7-byte Bulk-OUT Endpoint (EP1 OUT)
        //   - 7-byte Interrupt-IN Endpoint (EP2 IN)
        // Total = 9 + 9 + 54 + 7 + 7 + 7 = 93 bytes.

        let total: u16 = 93;
        let mut cfg: alloc::vec::Vec<u8> = alloc::vec![0u8; total as usize];

        // Configuration Descriptor (USB 2.0 §9.6.3).
        cfg[0] = 9; // bLength
        cfg[1] = 0x02; // bDescriptorType = Configuration
        cfg[2] = (total & 0xFF) as u8;
        cfg[3] = (total >> 8) as u8;
        cfg[4] = 1; // bNumInterfaces
        cfg[5] = 1; // bConfigurationValue
        cfg[6] = 0; // iConfiguration
        cfg[7] = 0xC0; // bmAttributes
        cfg[8] = 50; // bMaxPower (100 mA)

        // Interface Descriptor at offset 9.
        cfg[9] = 9; // bLength
        cfg[10] = 0x04; // bDescriptorType = Interface
        cfg[11] = 0; // bInterfaceNumber
        cfg[12] = 0; // bAlternateSetting
        cfg[13] = 3; // bNumEndpoints (bulk-IN + bulk-OUT + intr-IN)
        cfg[14] = CCID_INTERFACE_CLASS; // 0x0B
        cfg[15] = CCID_INTERFACE_SUBCLASS; // 0x00
        cfg[16] = CCID_INTERFACE_PROTOCOL; // 0x00
        cfg[17] = 0; // iInterface

        // CCID Class Descriptor at offset 18.
        cfg[18] = 54; // bLength
        cfg[19] = CCID_DESC_TYPE; // 0x21
        cfg[20] = 0x10; // bcdCCID LSB
        cfg[21] = 0x01; // bcdCCID MSB
                        // dwProtocols = T=0 | T=1 at offsets 24..28 (relative to cfg[18]).
                        // Absolute offset = 18 + 6 = 24.
        cfg[24..28].copy_from_slice(&(CCID_PROTO_T0 | CCID_PROTO_T1).to_le_bytes());
        // dwMaxIFSD = 254 at absolute offset 18 + 28 = 46.
        cfg[46..50].copy_from_slice(&254u32.to_le_bytes());
        // dwMaxCCIDMessageLength at 18 + 44 = 62.
        cfg[62..66].copy_from_slice(&271u32.to_le_bytes());

        // Bulk-IN Endpoint (EP1 IN) at offset 72.
        cfg[72] = 7; // bLength
        cfg[73] = 0x05; // bDescriptorType = Endpoint
        cfg[74] = 0x81; // bEndpointAddress: EP1 IN
        cfg[75] = 0x02; // bmAttributes: Bulk
        cfg[76] = 64; // wMaxPacketSize LSB
        cfg[77] = 0; // wMaxPacketSize MSB
        cfg[78] = 0; // bInterval

        // Bulk-OUT Endpoint (EP1 OUT) at offset 79.
        cfg[79] = 7;
        cfg[80] = 0x05;
        cfg[81] = 0x01; // EP1 OUT
        cfg[82] = 0x02; // Bulk
        cfg[83] = 64;
        cfg[84] = 0;
        cfg[85] = 0;

        // Interrupt-IN Endpoint (EP2 IN) at offset 86.
        cfg[86] = 7;
        cfg[87] = 0x05;
        cfg[88] = 0x82; // EP2 IN
        cfg[89] = 0x03; // Interrupt
        cfg[90] = 8; // wMaxPacketSize = 8
        cfg[91] = 0;
        cfg[92] = 8; // bInterval

        // Verify: find_ccid_interface returns (iface=0, offset=9).
        let (iface_num, iface_off) = find_ccid_interface(&cfg).expect("should find CCID interface");
        assert_eq!(iface_num, 0, "bInterfaceNumber");
        assert_eq!(iface_off, 9, "interface offset");

        // Verify: class descriptor parses correctly.
        let desc =
            find_ccid_class_descriptor(&cfg, iface_off).expect("should find CCID class descriptor");
        assert_ne!(desc.protocols & CCID_PROTO_T0, 0, "T=0 supported");
        assert_ne!(desc.protocols & CCID_PROTO_T1, 0, "T=1 supported");
        assert_eq!(desc.max_ifsd, 254, "maxIFSD");

        // Verify: endpoints parse correctly.
        let eps = find_ccid_endpoints(&cfg, iface_off).expect("should find CCID endpoints");
        assert_eq!(eps.bulk_in.ep_addr, 0x81, "bulk-IN addr");
        assert!(
            matches!(eps.bulk_in.kind, EndpointKind::BulkIn),
            "bulk-IN kind"
        );
        assert_eq!(eps.bulk_out.ep_addr, 0x01, "bulk-OUT addr");
        assert!(
            matches!(eps.bulk_out.kind, EndpointKind::BulkOut),
            "bulk-OUT kind"
        );
        assert!(eps.intr_in.is_some(), "intr-IN should be present");
        let intr = eps.intr_in.unwrap();
        assert_eq!(intr.ep_addr, 0x82, "intr-IN addr");
        assert!(
            matches!(intr.kind, EndpointKind::InterruptIn),
            "intr-IN kind"
        );
    }
}
