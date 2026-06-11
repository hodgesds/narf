//! AVRCP — Audio/Video Remote Control Profile (clean-room).
//!
//! Spec sources (public-only):
//! - "Audio/Video Remote Control Profile (AVRCP), Version 1.6.2" —
//!   Bluetooth SIG. §4 (Controller / Target roles), §5.4
//!   (PASS THROUGH command), §6 (browsing channel), §28 (Metadata
//!   AVCTP layer).
//! - "Audio/Video Control Transport Protocol (AVCTP), Version 1.4" —
//!   Bluetooth SIG. §6 (transaction header), §6.2 (single-packet PDU),
//!   §6.3 (fragmented PDU).
//! - "Bluetooth Assigned Numbers" — AVCTP PSM 0x0017 (control) and
//!   0x001B (browsing), Service Class UUID 0x110E (AVRCP) /
//!   0x110C (Target) / 0x110F (Controller).
//! - AV/C Digital Interface Command Set (1394 TA) — referenced for
//!   the PASS THROUGH opcode (0x7C) and the operation_id table; only
//!   the bytes that travel over the AV/C frame are reproduced here.
//!
//! Linux reference consulted (GPL-2.0-or-later, NARF relicense
//! 2026-05-20): BlueZ `profiles/audio/avrcp.c` for the metadata
//! pdu_id table and the PASS THROUGH transition shape.
//!
//! ## AVCTP packet format (§6.2)
//!
//! ```text
//!   byte 0:
//!     bits[7..4] = Transaction Label (0..15)
//!     bits[3..2] = Packet Type
//!                  0b00 Single, 0b01 Start, 0b10 Continue, 0b11 End
//!     bit  [1]   = CR — Command/Response
//!     bit  [0]   = IPID — Invalid Profile Identifier (responses only)
//!   bytes 1..3:
//!     PID (Profile Identifier, big-endian u16) — 0x110E for AVRCP.
//!   bytes 3..N: payload (AV/C frame for AVRCP).
//! ```
//!
//! ## AV/C frame (single-packet PASS THROUGH)
//!
//! ```text
//!   byte 0: Ctype (Command type, low 4 bits) — 0x0 CONTROL, 0x1 STATUS,
//!           0x9 ACCEPTED, 0xA REJECTED, 0xC NOT_IMPLEMENTED.
//!   byte 1: Subunit type (5 bits) | Subunit ID (3 bits) — 0x48 = PANEL.
//!   byte 2: Opcode — 0x7C PASS THROUGH.
//!   byte 3: Operation ID (low 7 bits) | State bit (bit 7: 0 pressed,
//!           1 released).
//!   byte 4: Operation Data Length (typically 0 for play/pause/skip).
//!   bytes 5..N: Operation Data.
//! ```

use alloc::vec::Vec;

// ── L2CAP PSMs (Assigned Numbers) ──────────────────────────────────

/// AVRCP / AVCTP control PSM (§3 / Assigned Numbers).
pub const AVCTP_CONTROL_PSM: u16 = 0x0017;
/// AVRCP browsing PSM (§6.3 / Assigned Numbers).
pub const AVCTP_BROWSING_PSM: u16 = 0x001B;

/// Bluetooth SIG company ID used as the AVRCP "Metadata Transfer"
/// company ID (Assigned Numbers). Carried as a 3-byte big-endian
/// field in the metadata AV/C frame.
pub const BT_SIG_COMPANY_ID: u32 = 0x001958;

/// AVRCP PID (Profile Identifier) — Service Class UUID 0x110E
/// reused as the AVCTP profile identifier (AVRCP §28.2).
pub const AVRCP_PID: u16 = 0x110E;

// ── AVCTP packet type bits (§6.2) ───────────────────────────────────

pub const AVCTP_SINGLE: u8 = 0b00;
pub const AVCTP_START: u8 = 0b01;
pub const AVCTP_CONTINUE: u8 = 0b10;
pub const AVCTP_END: u8 = 0b11;

pub const AVCTP_CR_COMMAND: u8 = 0;
pub const AVCTP_CR_RESPONSE: u8 = 1;

/// One AVCTP packet (without fragmentation handling).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvctpPacket {
    pub transaction_label: u8,
    pub packet_type: u8,
    /// Command (false) vs Response (true).
    pub is_response: bool,
    /// IPID bit (response only) — set when the PID isn't recognised.
    pub ipid: bool,
    pub pid: u16,
    pub payload: Vec<u8>,
}

impl AvctpPacket {
    pub fn encode(&self) -> Vec<u8> {
        let mut header = (self.transaction_label & 0x0F) << 4;
        header |= (self.packet_type & 0x3) << 2;
        if self.is_response {
            header |= 1 << 1;
        }
        if self.ipid {
            header |= 1;
        }
        let mut out = Vec::with_capacity(3 + self.payload.len());
        out.push(header);
        out.extend_from_slice(&self.pid.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 3 {
            return None;
        }
        Some(Self {
            transaction_label: (buf[0] >> 4) & 0x0F,
            packet_type: (buf[0] >> 2) & 0x3,
            is_response: (buf[0] & 0x02) != 0,
            ipid: (buf[0] & 0x01) != 0,
            pid: u16::from_be_bytes([buf[1], buf[2]]),
            payload: buf[3..].to_vec(),
        })
    }
}

// ── AV/C frame: command types (§5.4 / AV/C Digital Interface §7.1) ─

pub const CTYPE_CONTROL: u8 = 0x0;
pub const CTYPE_STATUS: u8 = 0x1;
pub const CTYPE_SPECIFIC_INQUIRY: u8 = 0x2;
pub const CTYPE_NOTIFY: u8 = 0x3;
pub const CTYPE_GENERAL_INQUIRY: u8 = 0x4;
pub const CTYPE_NOT_IMPLEMENTED: u8 = 0x8;
pub const CTYPE_ACCEPTED: u8 = 0x9;
pub const CTYPE_REJECTED: u8 = 0xA;
pub const CTYPE_IN_TRANSITION: u8 = 0xB;
pub const CTYPE_STABLE: u8 = 0xC;
pub const CTYPE_CHANGED: u8 = 0xD;
pub const CTYPE_INTERIM: u8 = 0xF;

// Subunit type/id (§5.4 / AV/C §7.2). For AVRCP we use PANEL (0x09)
// for media keys; the ID is always 0x00 (unit 0).
pub const SUBUNIT_PANEL: u8 = 0x09;
/// Encoded subunit byte = (type<<3) | id. PANEL,0 = 0x48.
pub const SUBUNIT_PANEL_BYTE: u8 = SUBUNIT_PANEL << 3;

// AV/C opcodes (§5.4).
pub const AVC_OPCODE_VENDOR_DEPENDENT: u8 = 0x00;
pub const AVC_OPCODE_UNIT_INFO: u8 = 0x30;
pub const AVC_OPCODE_SUBUNIT_INFO: u8 = 0x31;
pub const AVC_OPCODE_PASS_THROUGH: u8 = 0x7C;

// ── AVRCP PASS THROUGH operation IDs (§4.6.1, table 4.5) ───────────

pub const OP_SELECT: u8 = 0x00;
pub const OP_UP: u8 = 0x01;
pub const OP_DOWN: u8 = 0x02;
pub const OP_LEFT: u8 = 0x03;
pub const OP_RIGHT: u8 = 0x04;
pub const OP_ROOT_MENU: u8 = 0x09;
pub const OP_CONTENTS_MENU: u8 = 0x0B;
pub const OP_FAVORITE_MENU: u8 = 0x0C;
pub const OP_EXIT: u8 = 0x0D;
pub const OP_0: u8 = 0x20;
pub const OP_1: u8 = 0x21;
pub const OP_2: u8 = 0x22;
pub const OP_3: u8 = 0x23;
pub const OP_4: u8 = 0x24;
pub const OP_5: u8 = 0x25;
pub const OP_6: u8 = 0x26;
pub const OP_7: u8 = 0x27;
pub const OP_8: u8 = 0x28;
pub const OP_9: u8 = 0x29;
pub const OP_DOT: u8 = 0x2A;
pub const OP_ENTER: u8 = 0x2B;
pub const OP_CLEAR: u8 = 0x2C;
pub const OP_CHANNEL_UP: u8 = 0x30;
pub const OP_CHANNEL_DOWN: u8 = 0x31;
pub const OP_PREVIOUS_CHANNEL: u8 = 0x32;
pub const OP_SOUND_SELECT: u8 = 0x33;
pub const OP_INPUT_SELECT: u8 = 0x34;
pub const OP_INFO: u8 = 0x35;
pub const OP_HELP: u8 = 0x36;
pub const OP_PAGE_UP: u8 = 0x37;
pub const OP_PAGE_DOWN: u8 = 0x38;
pub const OP_POWER: u8 = 0x40;
pub const OP_VOLUME_UP: u8 = 0x41;
pub const OP_VOLUME_DOWN: u8 = 0x42;
pub const OP_MUTE: u8 = 0x43;
pub const OP_PLAY: u8 = 0x44;
pub const OP_STOP: u8 = 0x45;
pub const OP_PAUSE: u8 = 0x46;
pub const OP_RECORD: u8 = 0x47;
pub const OP_REWIND: u8 = 0x48;
pub const OP_FAST_FORWARD: u8 = 0x49;
pub const OP_EJECT: u8 = 0x4A;
pub const OP_FORWARD: u8 = 0x4B;
pub const OP_BACKWARD: u8 = 0x4C;
pub const OP_ANGLE: u8 = 0x50;
pub const OP_SUBPICTURE: u8 = 0x51;
pub const OP_F1: u8 = 0x71;
pub const OP_F2: u8 = 0x72;
pub const OP_F3: u8 = 0x73;
pub const OP_F4: u8 = 0x74;
pub const OP_F5: u8 = 0x75;
pub const OP_VENDOR_UNIQUE: u8 = 0x7E;

/// State bit in the operation_id byte (§4.6.1.2). Pressed = 0,
/// Released = 1.
pub const PASS_THROUGH_STATE_PRESSED: u8 = 0x00;
pub const PASS_THROUGH_STATE_RELEASED: u8 = 0x80;

// ── PASS THROUGH frame builder ────────────────────────────────────

/// Build a PASS THROUGH command AV/C frame (§4.6.1). The frame is the
/// payload of an AVCTP single-packet command; the caller wraps it in
/// an `AvctpPacket` with `is_response == false`.
pub fn pass_through_frame(operation_id: u8, released: bool) -> Vec<u8> {
    let state = if released {
        PASS_THROUGH_STATE_RELEASED
    } else {
        PASS_THROUGH_STATE_PRESSED
    };
    alloc::vec![
        CTYPE_CONTROL,
        SUBUNIT_PANEL_BYTE,
        AVC_OPCODE_PASS_THROUGH,
        state | (operation_id & 0x7F),
        0x00,
    ]
}

/// One decoded PASS THROUGH frame.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PassThrough {
    pub ctype: u8,
    pub operation_id: u8,
    pub released: bool,
}

impl PassThrough {
    pub fn decode(frame: &[u8]) -> Option<Self> {
        if frame.len() < 5 {
            return None;
        }
        if frame[2] != AVC_OPCODE_PASS_THROUGH {
            return None;
        }
        Some(Self {
            ctype: frame[0] & 0x0F,
            operation_id: frame[3] & 0x7F,
            released: (frame[3] & 0x80) != 0,
        })
    }

    /// Build the response frame (ACCEPTED) that mirrors the request.
    pub fn accept_response(&self) -> Vec<u8> {
        let state = if self.released {
            PASS_THROUGH_STATE_RELEASED
        } else {
            PASS_THROUGH_STATE_PRESSED
        };
        alloc::vec![
            CTYPE_ACCEPTED,
            SUBUNIT_PANEL_BYTE,
            AVC_OPCODE_PASS_THROUGH,
            state | (self.operation_id & 0x7F),
            0x00,
        ]
    }
}

// ── AVRCP Metadata (Vendor Dependent, BT-SIG company ID) ───────────
//
// Metadata commands ride a Vendor Dependent AV/C frame (§28.3) with
// the BT-SIG company ID. The payload layout after the company ID is:
//
//   byte 0: PDU ID
//   byte 1: Packet Type (single / fragment markers)
//   byte 2..3: Parameter Length (big-endian)
//   byte 4..N: parameters

/// Metadata PDU IDs (§28, table 28.1 — subset).
pub const PDU_GET_CAPABILITIES: u8 = 0x10;
pub const PDU_LIST_PLAYER_APP_SETTING_ATTRIBUTES: u8 = 0x11;
pub const PDU_LIST_PLAYER_APP_SETTING_VALUES: u8 = 0x12;
pub const PDU_GET_CURRENT_PLAYER_APP_SETTING_VALUE: u8 = 0x13;
pub const PDU_SET_PLAYER_APP_SETTING_VALUE: u8 = 0x14;
pub const PDU_GET_ELEMENT_ATTRIBUTES: u8 = 0x20;
pub const PDU_GET_PLAY_STATUS: u8 = 0x30;
pub const PDU_REGISTER_NOTIFICATION: u8 = 0x31;
pub const PDU_SET_ABSOLUTE_VOLUME: u8 = 0x50;
pub const PDU_SET_ADDRESSED_PLAYER: u8 = 0x60;
pub const PDU_GET_FOLDER_ITEMS: u8 = 0x71;

/// Notification Event IDs registered for via `REGISTER_NOTIFICATION`
/// (§28.4.2, table 28.10).
pub const EVENT_PLAYBACK_STATUS_CHANGED: u8 = 0x01;
pub const EVENT_TRACK_CHANGED: u8 = 0x02;
pub const EVENT_TRACK_REACHED_END: u8 = 0x03;
pub const EVENT_TRACK_REACHED_START: u8 = 0x04;
pub const EVENT_PLAYBACK_POS_CHANGED: u8 = 0x05;
pub const EVENT_BATT_STATUS_CHANGED: u8 = 0x06;
pub const EVENT_SYSTEM_STATUS_CHANGED: u8 = 0x07;
pub const EVENT_PLAYER_APP_SETTING_CHANGED: u8 = 0x08;
pub const EVENT_NOW_PLAYING_CONTENT_CHANGED: u8 = 0x09;
pub const EVENT_AVAILABLE_PLAYERS_CHANGED: u8 = 0x0A;
pub const EVENT_ADDRESSED_PLAYER_CHANGED: u8 = 0x0B;
pub const EVENT_UIDS_CHANGED: u8 = 0x0C;
pub const EVENT_VOLUME_CHANGED: u8 = 0x0D;

/// Build the inner payload (after the 3-byte BT-SIG company ID inside
/// a Vendor Dependent AV/C frame) for a metadata PDU.
pub fn metadata_pdu(pdu_id: u8, parameters: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + parameters.len());
    out.push(pdu_id);
    out.push(0x00); // Packet Type: 0b00 = single
    let len = parameters.len() as u16;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(parameters);
    out
}

/// Build a complete Vendor Dependent AV/C frame carrying a metadata PDU
/// (§28.3). `ctype` is normally `CTYPE_CONTROL` or `CTYPE_STATUS`.
pub fn vendor_dependent_frame(ctype: u8, pdu_id: u8, parameters: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + parameters.len());
    out.push(ctype & 0x0F);
    out.push(SUBUNIT_PANEL_BYTE);
    out.push(AVC_OPCODE_VENDOR_DEPENDENT);
    // Company ID — big-endian 24-bit.
    out.push(((BT_SIG_COMPANY_ID >> 16) & 0xFF) as u8);
    out.push(((BT_SIG_COMPANY_ID >> 8) & 0xFF) as u8);
    out.push((BT_SIG_COMPANY_ID & 0xFF) as u8);
    out.extend_from_slice(&metadata_pdu(pdu_id, parameters));
    out
}

/// Parse a Vendor Dependent AV/C frame into `(ctype, company_id,
/// pdu_id, params)`. Returns `None` on malformed input.
pub fn parse_vendor_dependent(frame: &[u8]) -> Option<(u8, u32, u8, &[u8])> {
    if frame.len() < 10 {
        return None;
    }
    if frame[2] != AVC_OPCODE_VENDOR_DEPENDENT {
        return None;
    }
    let ctype = frame[0] & 0x0F;
    let cid = ((frame[3] as u32) << 16) | ((frame[4] as u32) << 8) | frame[5] as u32;
    let pdu_id = frame[6];
    // packet_type at frame[7], len BE at frame[8..10].
    let len = u16::from_be_bytes([frame[8], frame[9]]) as usize;
    if frame.len() < 10 + len {
        return None;
    }
    Some((ctype, cid, pdu_id, &frame[10..10 + len]))
}

/// Build a Set Absolute Volume (§28.20) command. `volume` is 0..=0x7F
/// (7-bit, percentage of max).
pub fn set_absolute_volume(volume: u8) -> Vec<u8> {
    vendor_dependent_frame(CTYPE_CONTROL, PDU_SET_ABSOLUTE_VOLUME, &[volume & 0x7F])
}

/// Build a Register Notification command (§28.5).
pub fn register_notification(event_id: u8, playback_interval: u32) -> Vec<u8> {
    let mut p = Vec::with_capacity(5);
    p.push(event_id);
    p.extend_from_slice(&playback_interval.to_be_bytes());
    vendor_dependent_frame(CTYPE_NOTIFY, PDU_REGISTER_NOTIFICATION, &p)
}

/// Convenience: build the AVCTP-wrapped bytes for a media-key press.
pub fn media_key_press(transaction_label: u8, operation_id: u8) -> Vec<u8> {
    AvctpPacket {
        transaction_label,
        packet_type: AVCTP_SINGLE,
        is_response: false,
        ipid: false,
        pid: AVRCP_PID,
        payload: pass_through_frame(operation_id, false),
    }
    .encode()
}

/// Companion to [`media_key_press`] — the release frame, sent ~100 ms
/// later per HFP §4.6.1.4 (press_hold tBPress timeout).
pub fn media_key_release(transaction_label: u8, operation_id: u8) -> Vec<u8> {
    AvctpPacket {
        transaction_label,
        packet_type: AVCTP_SINGLE,
        is_response: false,
        ipid: false,
        pid: AVRCP_PID,
        payload: pass_through_frame(operation_id, true),
    }
    .encode()
}
