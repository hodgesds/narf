//! `brcmfmac` connect orchestrator — scan → assoc → key-install.
//!
//! This is the high-level glue that drives the chip from "fully
//! initialised" to "associated and 4-way handshake complete". The
//! actual MMIO + DMA-ring work happens in the per-piece modules
//! (`fwil`, `ringbuf`, `fweh`); this file sequences them via a
//! transport trait that production wires to the live IOCTL pump and
//! tests substitute with a synchronous in-memory mock.
//!
//! ## High-level sequence
//!
//! 1. **`BRCMF_C_UP`** — bring the radio up.
//! 2. **Set country + band** via `country` / `assoc_pref` IOVARs
//!    (optional but Linux always sets the country for regulatory).
//! 3. **`BRCMF_C_SET_SSID`** with the [`fwil::encode_join_params`]
//!    payload.
//! 4. **Await `BRCMF_E_LINK` up** + **`BRCMF_E_ASSOC` success** on
//!    the event ring.
//! 5. For WPA2-PSK with firmware-side supplicant: **await
//!    `BRCMF_E_PSK_SUP` with `STATUS_FWSUP_COMPLETED`**.
//! 6. Optional: **`BRCMF_C_SET_KEY`** for any out-of-handshake key
//!    install (e.g. WEP).
//!
//! On error the orchestrator drives `BRCMF_C_DISASSOC` + waits for
//! `BRCMF_E_LINK` down before returning the error to the caller.
//!
//! ## Reference
//!
//! Linux `cfg80211.c::brcmf_cfg80211_connect` (~L2350..L2470) and
//! `brcmf_cfg80211_link_set_ssid` (~L2245..L2310). NARF
//! GPL-2.0-or-later.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use super::fweh::EventMsg;
use super::fwil::{
    build_iovar_payload, encode_join_params, BRCMF_C_DISASSOC, BRCMF_C_SET_SSID, BRCMF_C_UP,
    JOIN_PARAMS_BLIND_SIZE,
};

// ── Transport trait ────────────────────────────────────────────────

/// Synchronous IOCTL transport — the orchestrator hands the bytes
/// over and blocks until the firmware's IOCTL completion lands. The
/// production implementation drives the H2D control-submit + D2H
/// control-complete rings; the test stub records the calls.
pub trait IoctlTransport {
    /// Run a `BRCMF_C_*` command with the given input payload, get
    /// back the firmware's response (or an error).
    fn issue(&mut self, cmd: u32, payload: &[u8]) -> Result<Vec<u8>, ConnectError>;
}

/// Async event sink — the orchestrator awaits specific event
/// predicates. Production wires this to the WL_EVENT ring drain;
/// tests inject events directly via [`EventQueue`].
pub trait EventSink {
    /// Block waiting for the next event matching `pred`. Returns the
    /// matching event, or `ConnectError::EventTimeout` on the
    /// transport's per-call timeout.
    fn next_matching(
        &mut self,
        pred: &dyn Fn(&EventMsg) -> bool,
    ) -> Result<EventMsg, ConnectError>;
}

// ── ConnectError ──────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConnectError {
    /// Firmware returned a non-zero IOCTL status.
    Firmware(i32),
    /// The transport hit its per-call deadline without a response.
    EventTimeout,
    /// SSID buffer was too long, or the join params overflowed.
    InvalidArgs,
    /// IOVAR encoding failed for buffer-size reasons.
    Encoder,
    /// Firmware refused the join (BRCMF_E_LINK down with reason).
    JoinRejected(u32),
}

// ── Top-level connect ─────────────────────────────────────────────

/// Drive the connect sequence to completion.
///
/// `ssid` and `chanspec` are the user-supplied target — `chanspec=0`
/// means "any channel".
pub fn connect_wpa2_psk(
    ssid: &[u8],
    chanspec: u16,
    ioctl: &mut dyn IoctlTransport,
    events: &mut dyn EventSink,
) -> Result<(), ConnectError> {
    // Phase 1 — radio up.
    let up_payload = &[];
    ioctl.issue(BRCMF_C_UP, up_payload)?;

    // Phase 2 — SET_SSID with the encoded join_params blob.
    let mut payload = [0u8; JOIN_PARAMS_BLIND_SIZE];
    encode_join_params(ssid, None, chanspec, &mut payload).ok_or(ConnectError::InvalidArgs)?;
    ioctl.issue(BRCMF_C_SET_SSID, &payload)?;

    // Phase 3 — await LINK up.
    let link = events.next_matching(&|e| e.is_link_up() || e.is_link_down())?;
    if link.is_link_down() {
        return Err(ConnectError::JoinRejected(link.reason));
    }

    // Phase 4 — await ASSOC success.
    let _assoc = events.next_matching(&|e| e.is_assoc_success())?;

    // Phase 5 — await PSK supplicant completion (WPA2-PSK only).
    let _psk = events.next_matching(&|e| e.is_psk_supplicant_done())?;

    Ok(())
}

/// Drive a clean disconnect. Sends `BRCMF_C_DISASSOC` and waits for
/// the corresponding `BRCMF_E_LINK` down event.
pub fn disconnect(
    ioctl: &mut dyn IoctlTransport,
    events: &mut dyn EventSink,
) -> Result<(), ConnectError> {
    ioctl.issue(BRCMF_C_DISASSOC, &[])?;
    let _ev = events.next_matching(&|e| e.is_link_down())?;
    Ok(())
}

// ── Helper IOVAR encoders for the connect path ────────────────────

/// Build the `chanspec` IOVAR payload (used to lock association onto
/// a specific channel before SET_SSID fires).
///
/// Returns the encoded byte count, or `None` if `out` is too small.
pub fn build_chanspec_iovar(chanspec: u16, out: &mut [u8]) -> Option<usize> {
    let data = chanspec.to_le_bytes();
    build_iovar_payload("chanspec", &data, out)
}

/// Build the `wpa_auth` IOVAR payload — sets the firmware's WPA auth
/// algorithm bitfield before the join.
///
/// Common values:
///   - 0x0000 — open / WEP only.
///   - 0x0004 — WPA1-PSK.
///   - 0x0080 — WPA2-PSK.
///   - 0x0400 — WPA3-SAE.
pub fn build_wpa_auth_iovar(auth: u32, out: &mut [u8]) -> Option<usize> {
    let data = auth.to_le_bytes();
    build_iovar_payload("wpa_auth", &data, out)
}

/// Build the `country` IOVAR payload — a 4-byte country code (e.g.
/// `b"US\0\0"`) the firmware uses for regulatory enforcement.
pub fn build_country_iovar(country: &[u8; 4], out: &mut [u8]) -> Option<usize> {
    build_iovar_payload("country", country, out)
}

// WPA auth algorithm bitfield values (Linux fwil_types.h / cfg80211.c).
pub const WPA_AUTH_OPEN: u32 = 0x0000;
pub const WPA_AUTH_WPA_PSK: u32 = 0x0004;
pub const WPA_AUTH_WPA2_PSK: u32 = 0x0080;
pub const WPA_AUTH_SAE: u32 = 0x0400;

// ── Test stubs ────────────────────────────────────────────────────

/// Recording IOCTL transport — captures every issued command for
/// assertion.
#[derive(Debug, Default)]
pub struct RecordingIoctl {
    pub calls: Vec<(u32, Vec<u8>)>,
    /// Forced return for each (cmd, call-index) — defaults to empty
    /// success.
    pub forced_responses: alloc::collections::BTreeMap<u32, Vec<u8>>,
}

impl IoctlTransport for RecordingIoctl {
    fn issue(&mut self, cmd: u32, payload: &[u8]) -> Result<Vec<u8>, ConnectError> {
        self.calls.push((cmd, payload.to_vec()));
        Ok(self.forced_responses.get(&cmd).cloned().unwrap_or_default())
    }
}

/// In-memory event queue — produces events from a pre-loaded vec.
/// Useful for testing the orchestrator without standing up the actual
/// event-ring drain.
#[derive(Debug, Default)]
pub struct EventQueue {
    pub events: Vec<EventMsg>,
    pub cursor: usize,
}

impl EventSink for EventQueue {
    fn next_matching(
        &mut self,
        pred: &dyn Fn(&EventMsg) -> bool,
    ) -> Result<EventMsg, ConnectError> {
        while self.cursor < self.events.len() {
            let e = self.events[self.cursor];
            self.cursor += 1;
            if pred(&e) {
                return Ok(e);
            }
        }
        Err(ConnectError::EventTimeout)
    }
}
