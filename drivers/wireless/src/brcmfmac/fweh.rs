//! `brcmfmac` Firmware Event Handler (fweh) — event ring decoder.
//!
//! ## How the firmware ships events to the host
//!
//! When the firmware needs to notify the host of an async event
//! (BRCMF_E_LINK up/down, BRCMF_E_ASSOC complete, BRCMF_E_EAPOL_MSG
//! incoming, etc.) it writes an `MSGBUF_TYPE_WL_EVENT` message to the
//! D2H control-complete ring. The message payload starts with a
//! [`super::msgbuf::WlEvent`] header (24 bytes), then a
//! `brcmf_event` envelope (Ethernet + brcm_ethhdr + brcmf_event_msg_be).
//! The host strips the envelope, decodes the big-endian event header,
//! and dispatches on `event_type`.
//!
//! ## Wire layout
//!
//! The event_msg struct is **big-endian on the wire** — Linux declares
//! it as `brcmf_event_msg_be` with all `__be16` / `__be32` fields:
//!
//!     ethhdr (14 bytes)
//!     brcm_ethhdr (10 bytes)  — subtype, length, version, oui[3],
//!                                usr_subtype
//!     brcmf_event_msg_be (~50 bytes):
//!         version       __be16 @ 24
//!         flags         __be16 @ 26
//!         event_type    __be32 @ 28
//!         status        __be32 @ 32
//!         reason        __be32 @ 36
//!         auth_type     __be32 @ 40
//!         datalen       __be32 @ 44
//!         addr[6]              @ 48
//!         ifname[16]           @ 54
//!         ifidx          u8    @ 70
//!         bsscfgidx      u8    @ 71
//!
//! Total envelope = 14 + 10 + 48 = 72 bytes; event payload (datalen
//! bytes) immediately follows at offset 72.
//!
//! Reference: Linux `brcmfmac/fweh.h::brcmf_event_msg_be` (~L223..L235)
//! and `brcmf_event` (~L244..L248).

#![allow(dead_code)]

use core::convert::TryInto;

// ── Event-code enum (subset) ───────────────────────────────────────
//
// Per Linux `fweh.h::BRCMF_FWEH_EVENT_ENUM_DEFLIST` (~L25..L101). Each
// `BRCMF_ENUM_DEF(id, val)` expands to `BRCMF_E_id = val`. Only the
// codes relevant to assoc/auth/link/eapol/scan are wired here; the
// rest are documented as comments and can be added on demand.

/// SET_SSID — host issued `BRCMF_C_SET_SSID`, firmware acknowledges.
pub const BRCMF_E_SET_SSID: u32 = 0;
/// JOIN — firmware completed a join attempt.
pub const BRCMF_E_JOIN: u32 = 1;
/// AUTH — auth state change.
pub const BRCMF_E_AUTH: u32 = 3;
/// AUTH_IND — auth indication (AP-mode-only).
pub const BRCMF_E_AUTH_IND: u32 = 4;
/// DEAUTH — deauthentication.
pub const BRCMF_E_DEAUTH: u32 = 5;
/// DEAUTH_IND — deauth indication.
pub const BRCMF_E_DEAUTH_IND: u32 = 6;
/// ASSOC — association state change.
pub const BRCMF_E_ASSOC: u32 = 7;
/// ASSOC_IND — association indication.
pub const BRCMF_E_ASSOC_IND: u32 = 8;
/// REASSOC — reassociation.
pub const BRCMF_E_REASSOC: u32 = 9;
/// REASSOC_IND — reassociation indication.
pub const BRCMF_E_REASSOC_IND: u32 = 10;
/// DISASSOC — disassociation.
pub const BRCMF_E_DISASSOC: u32 = 11;
/// DISASSOC_IND — disassociation indication.
pub const BRCMF_E_DISASSOC_IND: u32 = 12;
/// LINK — link-layer state change (up/down).
pub const BRCMF_E_LINK: u32 = 16;
/// MIC_ERROR — MIC failure (replay attack or bad key).
pub const BRCMF_E_MIC_ERROR: u32 = 17;
/// ROAM — roaming event.
pub const BRCMF_E_ROAM: u32 = 19;
/// PMKID_CACHE — PMKID cache update.
pub const BRCMF_E_PMKID_CACHE: u32 = 21;
/// EAPOL_MSG — incoming EAPOL frame (handed up for the 4-way
/// handshake supplicant).
pub const BRCMF_E_EAPOL_MSG: u32 = 25;
/// SCAN_COMPLETE — scan request finished.
pub const BRCMF_E_SCAN_COMPLETE: u32 = 26;
/// PSK_SUP — firmware-side PSK supplicant state change.
pub const BRCMF_E_PSK_SUP: u32 = 46;
/// ESCAN_RESULT — escan result delivery.
pub const BRCMF_E_ESCAN_RESULT: u32 = 69;

// ── Status / flag values (Linux fweh.h ~L113..L143) ────────────────

/// Set in `flags` when LINK event indicates link-up.
pub const BRCMF_EVENT_MSG_LINK: u16 = 0x01;

pub const BRCMF_E_STATUS_SUCCESS: u32 = 0;
pub const BRCMF_E_STATUS_FAIL: u32 = 1;
pub const BRCMF_E_STATUS_TIMEOUT: u32 = 2;
pub const BRCMF_E_STATUS_NO_NETWORKS: u32 = 3;
pub const BRCMF_E_STATUS_ABORT: u32 = 4;
pub const BRCMF_E_STATUS_PARTIAL: u32 = 8;
pub const BRCMF_E_STATUS_NEWSCAN: u32 = 9;
pub const BRCMF_E_STATUS_NEWASSOC: u32 = 10;

/// PSK_SUP `status` — handshake completed successfully.
pub const BRCMF_E_STATUS_FWSUP_COMPLETED: u32 = 6;

// ── EventMsg decoder ──────────────────────────────────────────────

/// Wire size of the brcm Ethernet envelope before the event_msg.
pub const ETH_HDR_SIZE: usize = 14;
/// Wire size of the brcm_ethhdr block immediately after the
/// Ethernet header (subtype + length + version + oui[3] + usr_subtype).
pub const BRCM_ETHHDR_SIZE: usize = 10;
/// Offset within the event_msg_be at which the BE event fields start.
pub const EVENT_BE_OFFSET: usize = ETH_HDR_SIZE + BRCM_ETHHDR_SIZE;
/// Wire size of the brcmf_event_msg_be block: 2+2+4×5 + 6 + 16 + 2 = 48.
pub const EVENT_MSG_BE_SIZE: usize = 2 + 2 + 4 * 5 + 6 + 16 + 2;
/// Total envelope size: ethhdr + brcm_ethhdr + event_msg_be = 72.
pub const EVENT_ENVELOPE_SIZE: usize = ETH_HDR_SIZE + BRCM_ETHHDR_SIZE + EVENT_MSG_BE_SIZE;

/// Decoded firmware event header. Field types match Linux's host-side
/// `struct brcmf_event_msg` (which is the native-endian post-decode
/// form, not the on-wire BE form).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EventMsg {
    pub version: u16,
    pub flags: u16,
    pub event_code: u32,
    pub status: u32,
    pub reason: u32,
    pub auth_type: i32,
    pub datalen: u32,
    pub addr: [u8; 6],
    pub ifidx: u8,
    pub bsscfgidx: u8,
}

impl EventMsg {
    /// Decode the firmware event envelope from a D2H control-complete
    /// payload. Returns `None` if the payload is too short to hold
    /// the full envelope.
    ///
    /// `bytes` must start at the ethhdr; the event payload (length =
    /// `datalen`) lives at `bytes[EVENT_ENVELOPE_SIZE..]`.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < EVENT_ENVELOPE_SIZE {
            return None;
        }
        let s = EVENT_BE_OFFSET;
        // All fields are big-endian on the wire.
        let version = u16::from_be_bytes(bytes[s..s + 2].try_into().ok()?);
        let flags = u16::from_be_bytes(bytes[s + 2..s + 4].try_into().ok()?);
        let event_code = u32::from_be_bytes(bytes[s + 4..s + 8].try_into().ok()?);
        let status = u32::from_be_bytes(bytes[s + 8..s + 12].try_into().ok()?);
        let reason = u32::from_be_bytes(bytes[s + 12..s + 16].try_into().ok()?);
        let auth_type =
            i32::from_be_bytes(bytes[s + 16..s + 20].try_into().ok()?);
        let datalen = u32::from_be_bytes(bytes[s + 20..s + 24].try_into().ok()?);
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&bytes[s + 24..s + 30]);
        // ifname[16] @ +30..46 — present on wire but the high-level
        // host struct doesn't carry it.
        let ifidx = bytes[s + 46];
        let bsscfgidx = bytes[s + 47];
        Some(Self {
            version,
            flags,
            event_code,
            status,
            reason,
            auth_type,
            datalen,
            addr,
            ifidx,
            bsscfgidx,
        })
    }

    /// True iff this event is a LINK-UP transition.
    pub const fn is_link_up(&self) -> bool {
        self.event_code == BRCMF_E_LINK && (self.flags & BRCMF_EVENT_MSG_LINK) != 0
    }

    /// True iff this event is a LINK-DOWN transition.
    pub const fn is_link_down(&self) -> bool {
        self.event_code == BRCMF_E_LINK && (self.flags & BRCMF_EVENT_MSG_LINK) == 0
    }

    /// True iff this event indicates association completed with the
    /// status field equal to BRCMF_E_STATUS_SUCCESS.
    pub const fn is_assoc_success(&self) -> bool {
        (self.event_code == BRCMF_E_ASSOC || self.event_code == BRCMF_E_REASSOC)
            && self.status == BRCMF_E_STATUS_SUCCESS
    }

    /// True iff this event is the WPA2-PSK handshake-completed
    /// notification from the firmware's onboard supplicant.
    pub const fn is_psk_supplicant_done(&self) -> bool {
        self.event_code == BRCMF_E_PSK_SUP && self.status == BRCMF_E_STATUS_FWSUP_COMPLETED
    }
}

// ── EAPOL key frame (IEEE 802.11-2016 §12.7) ───────────────────────
//
// The 4-way handshake exchanges four EAPOL-Key frames between AP and
// STA. The wire format is:
//
//   ethhdr (14)        — destination = AP MAC, source = STA MAC,
//                        ethertype = 0x888E (ETH_P_PAE).
//   EAPOL_HDR (4):     — version u8, type u8, body_len __be16
//   key_descriptor (95):
//       key_type           u8     @ 0   (= 2 for WPA2)
//       key_info           __be16 @ 1
//       key_len            __be16 @ 3
//       replay_counter[8]         @ 5..13
//       key_nonce[32]             @ 13..45
//       key_iv[16]                @ 45..61
//       key_rsc[8]                @ 61..69
//       key_id[8]                 @ 69..77
//       key_mic[16]               @ 77..93
//       key_data_len      __be16  @ 93..95
//       key_data[…]               @ 95..
//
// Total fixed header without key_data = 14 + 4 + 95 = 113 bytes.
//
// Reference: IEEE 802.11-2016 §12.7.2 "EAPOL-Key frames",
// linux-firmware-supplicant `wpa.c` builder.

/// IEEE 802.3 PAE ethertype (`ETH_P_PAE`).
pub const ETH_P_PAE: u16 = 0x888E;

/// EAPOL protocol version (per IEEE 802.1X-2010 — most APs send v2).
pub const EAPOL_VERSION: u8 = 2;

/// EAPOL frame type byte: 3 = EAPOL-Key (the 4-way handshake type).
pub const EAPOL_TYPE_KEY: u8 = 3;

/// Key descriptor type 2 = "RSN Key Descriptor" (WPA2 / 802.11i).
/// Per IEEE 802.11-2016 Figure 12-32.
pub const KEY_DESCRIPTOR_RSN: u8 = 2;

/// Key descriptor type 254 = "WPA Key Descriptor" (legacy WPA1).
pub const KEY_DESCRIPTOR_WPA: u8 = 254;

// Key Information bitfield (IEEE 802.11-2016 §12.7.2 Figure 12-33).

/// Key-info: bit 3 — Pairwise (set for PTK, clear for GTK).
pub const KEY_INFO_PAIRWISE: u16 = 1 << 3;
/// Key-info: bit 6 — Install (M3 sets this to tell STA to install the PTK).
pub const KEY_INFO_INSTALL: u16 = 1 << 6;
/// Key-info: bit 7 — Key ACK (set in M1/M3 by AP, clear in M2/M4).
pub const KEY_INFO_KEY_ACK: u16 = 1 << 7;
/// Key-info: bit 8 — MIC (set in M2/M3/M4 after PTK is derived).
pub const KEY_INFO_KEY_MIC: u16 = 1 << 8;
/// Key-info: bit 9 — Secure (set in M3/M4 after PTK installed).
pub const KEY_INFO_SECURE: u16 = 1 << 9;
/// Key-info: bit 10 — Error (set when MIC validation failed).
pub const KEY_INFO_ERROR: u16 = 1 << 10;
/// Key-info: bit 11 — Request (set in roaming-rekey requests).
pub const KEY_INFO_REQUEST: u16 = 1 << 11;
/// Key-info: bit 12 — Encrypted Key Data (set in M3 if Key Data is
/// AES-wrapped GTK).
pub const KEY_INFO_ENCR_KEY_DATA: u16 = 1 << 12;

/// Key-info: descriptor-version selector for HMAC-SHA-1 + AES.
/// Per Figure 12-33: bits[0..3] = 0b010 = "HMAC-SHA1, AES key wrap".
pub const KEY_INFO_VERSION_HMAC_SHA1_AES: u16 = 2;

/// Wire size of one EAPOL-Key frame (fixed header + 0-byte key_data).
/// = ethhdr 14 + eapol 4 + descriptor fixed 95 = 113.
pub const EAPOL_KEY_FRAME_FIXED_SIZE: usize = 14 + 4 + 95;

/// Builder for an EAPOL-Key frame. Caller provides the per-message
/// fields; the builder encodes the full 113-byte fixed frame plus an
/// optional key_data trailer (RSN IE / KDE / encrypted-GTK).
#[derive(Copy, Clone, Debug)]
pub struct EapolKeyBuilder<'a> {
    /// Destination MAC (peer — AP for STA→AP, STA for AP→STA).
    pub dst_mac: [u8; 6],
    /// Source MAC (us).
    pub src_mac: [u8; 6],
    pub key_descriptor: u8,
    pub key_info: u16,
    pub key_len: u16,
    pub replay_counter: u64,
    pub key_nonce: [u8; 32],
    pub key_iv: [u8; 16],
    pub key_rsc: [u8; 8],
    pub key_mic: [u8; 16],
    pub key_data: &'a [u8],
}

impl<'a> EapolKeyBuilder<'a> {
    /// Encode the EAPOL-Key frame into `out`. Returns the total
    /// number of bytes written, or `None` if `out` is too small.
    ///
    /// The encoded frame is ready to be wrapped in a 802.11 data
    /// frame (or, on a fullmac path, handed to the firmware via
    /// the data ring with the EtherType set to ETH_P_PAE).
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let total = EAPOL_KEY_FRAME_FIXED_SIZE + self.key_data.len();
        if out.len() < total {
            return None;
        }
        // Ethernet header.
        out[0..6].copy_from_slice(&self.dst_mac);
        out[6..12].copy_from_slice(&self.src_mac);
        out[12..14].copy_from_slice(&ETH_P_PAE.to_be_bytes());
        // EAPOL header.
        out[14] = EAPOL_VERSION;
        out[15] = EAPOL_TYPE_KEY;
        let body_len = (95 + self.key_data.len()) as u16;
        out[16..18].copy_from_slice(&body_len.to_be_bytes());
        // Key descriptor.
        out[18] = self.key_descriptor;
        out[19..21].copy_from_slice(&self.key_info.to_be_bytes());
        out[21..23].copy_from_slice(&self.key_len.to_be_bytes());
        out[23..31].copy_from_slice(&self.replay_counter.to_be_bytes());
        out[31..63].copy_from_slice(&self.key_nonce);
        out[63..79].copy_from_slice(&self.key_iv);
        out[79..87].copy_from_slice(&self.key_rsc);
        // key_id[8] = all zero per IEEE 802.11-2016.
        for byte in &mut out[87..95] {
            *byte = 0;
        }
        out[95..111].copy_from_slice(&self.key_mic);
        let key_data_len = self.key_data.len() as u16;
        out[111..113].copy_from_slice(&key_data_len.to_be_bytes());
        if !self.key_data.is_empty() {
            out[113..113 + self.key_data.len()].copy_from_slice(self.key_data);
        }
        Some(total)
    }
}

/// Build the Message-2 EAPOL-Key frame the STA sends to the AP in
/// response to Message-1 of the 4-way handshake.
///
/// M2 carries:
///   - the STA's `SNonce` (random 32-byte challenge),
///   - the RSN IE the STA advertised in its association request
///     (passed as `key_data`),
///   - a MIC over the entire frame keyed with the freshly-derived KCK
///     (caller computes the MIC after building the frame — pass
///     `[0u8; 16]` here and the EAPOL-Key MIC computation in
///     `wpa.rs` fills it in).
///
/// Per IEEE 802.11-2016 §12.7.6.3 "Message 2".
pub fn build_m2<'a>(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    snonce: [u8; 32],
    replay_counter: u64,
    rsn_ie: &'a [u8],
) -> EapolKeyBuilder<'a> {
    EapolKeyBuilder {
        dst_mac,
        src_mac,
        key_descriptor: KEY_DESCRIPTOR_RSN,
        // Pairwise + Key MIC + version=2 (HMAC-SHA-1 + AES).
        key_info: KEY_INFO_PAIRWISE | KEY_INFO_KEY_MIC | KEY_INFO_VERSION_HMAC_SHA1_AES,
        key_len: 0, // M2 carries no key bytes.
        replay_counter,
        key_nonce: snonce,
        key_iv: [0u8; 16],
        key_rsc: [0u8; 8],
        key_mic: [0u8; 16],
        key_data: rsn_ie,
    }
}

/// Build the Message-4 EAPOL-Key frame the STA sends to confirm
/// installation of the PTK. Per IEEE 802.11-2016 §12.7.6.5.
pub fn build_m4(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    replay_counter: u64,
) -> EapolKeyBuilder<'static> {
    EapolKeyBuilder {
        dst_mac,
        src_mac,
        key_descriptor: KEY_DESCRIPTOR_RSN,
        // Pairwise + Key MIC + Secure + version=2.
        key_info: KEY_INFO_PAIRWISE
            | KEY_INFO_KEY_MIC
            | KEY_INFO_SECURE
            | KEY_INFO_VERSION_HMAC_SHA1_AES,
        key_len: 0,
        replay_counter,
        key_nonce: [0u8; 32], // No nonce in M4.
        key_iv: [0u8; 16],
        key_rsc: [0u8; 8],
        key_mic: [0u8; 16],
        key_data: &[],
    }
}
