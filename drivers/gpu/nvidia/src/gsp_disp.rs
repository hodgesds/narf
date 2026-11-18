//! GSP-RM display control calls — the `NV0073_CTRL_CMD_*` layer.
//!
//! On a GSP card the display output path (which connectors exist, are
//! they plugged in, their EDID, DP AUX) is driven by GSP-RM: the host
//! issues `GSP_RM_CONTROL` calls against the display-common object
//! ([`crate::gsp_rm_api::HANDLE_DISP`]). This module builds the request
//! params and parses the replies for the query sequence that enumerates
//! displays and reads their EDID. Grounded against `/usr/src/linux`
//! `rm/r535/nvrm/disp.h`.
//!
//! Each call is sent as a `GSP_RM_CONTROL` RPC via [`crate::gsp_ring`]
//! (built with [`crate::gsp_rm_api::build_rm_control`]); the reply comes
//! back in the same params layout with the output fields filled.
//!
//! Pure CPU work (no hardware), unit-tested.

#![allow(dead_code)]

use alloc::vec::Vec;

use crate::gsp_rm_api::{build_rm_control, HANDLE_DISP};

// ── NV0073_CTRL_CMD_* command ids (verified vs disp.h) ───────────

/// Number of display heads.
pub const CMD_SYSTEM_GET_NUM_HEADS: u32 = 0x0073_0102;
/// Bitmask of all physical display outputs (+ which have DDC).
pub const CMD_SYSTEM_GET_SUPPORTED: u32 = 0x0073_0120;
/// Which of a display mask is currently connected.
pub const CMD_SYSTEM_GET_CONNECT_STATE: u32 = 0x0073_0122;
/// Connector data for a display.
pub const CMD_SPECIFIC_GET_CONNECTOR_DATA: u32 = 0x0073_0250;
/// Output-resource (SOR/DAC) info for a display.
pub const CMD_SPECIFIC_OR_GET_INFO: u32 = 0x0073_028b;
/// Read a display's EDID (up to 2 KiB).
pub const CMD_SPECIFIC_GET_EDID_V2: u32 = 0x0073_0245;
/// Digital-flat-panel info.
pub const CMD_DFP_GET_INFO: u32 = 0x0073_1140;
/// DP AUX channel transaction.
pub const CMD_DP_AUXCH_CTRL: u32 = 0x0073_1341;

/// Max EDID bytes returned by GET_EDID_V2.
pub const EDID_MAX_BYTES: usize = 2048;

/// Wrap a display control as a `GSP_RM_CONTROL` RPC payload targeting
/// the display-common object. The caller sends it as function
/// [`crate::gsp_rm_api::FUNCTION_GSP_RM_CONTROL`].
pub fn disp_control_rpc(h_client: u32, cmd: u32, params: &[u8]) -> Vec<u8> {
    build_rm_control(h_client, HANDLE_DISP, cmd, params)
}

// ── GET_SUPPORTED ────────────────────────────────────────────────

/// `NV0073_CTRL_SYSTEM_GET_SUPPORTED_PARAMS`: subDeviceInstance,
/// displayMask (out), displayMaskDDC (out). 12 bytes.
pub fn get_supported_params() -> [u8; 12] {
    [0u8; 12]
}

/// Parse the GET_SUPPORTED reply → `(displayMask, displayMaskDDC)`.
pub fn parse_supported(reply: &[u8]) -> Option<(u32, u32)> {
    Some((rd32(reply, 4)?, rd32(reply, 8)?))
}

// ── GET_CONNECT_STATE ────────────────────────────────────────────

/// `NV0073_CTRL_SYSTEM_GET_CONNECT_STATE_PARAMS`: subDeviceInstance,
/// flags, displayMask (in: which to probe / out: which connected),
/// retryTimeMs. 16 bytes.
pub fn get_connect_state_params(display_mask: u32) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[8..12].copy_from_slice(&display_mask.to_le_bytes()); // displayMask
    b
}

/// Parse the GET_CONNECT_STATE reply → the connected display bitmask.
pub fn parse_connect_state(reply: &[u8]) -> Option<u32> {
    rd32(reply, 8)
}

// ── GET_EDID_V2 ──────────────────────────────────────────────────

/// Size of `NV0073_CTRL_SPECIFIC_GET_EDID_V2_PARAMS`
/// (subDeviceInstance, displayId, bufferSize, flags, edidBuffer[2048]).
pub const EDID_V2_PARAMS_SIZE: usize = 16 + EDID_MAX_BYTES;

/// Build the GET_EDID_V2 request for `display_id`, with the full 2 KiB
/// return buffer reserved.
pub fn get_edid_v2_params(display_id: u32) -> Vec<u8> {
    let mut b = alloc::vec![0u8; EDID_V2_PARAMS_SIZE];
    b[4..8].copy_from_slice(&display_id.to_le_bytes()); // displayId
    b[8..12].copy_from_slice(&(EDID_MAX_BYTES as u32).to_le_bytes()); // bufferSize
    b
}

/// Parse the GET_EDID_V2 reply → the EDID bytes (bounded by the
/// returned `bufferSize`). The buffer starts at offset 16.
pub fn parse_edid(reply: &[u8]) -> Option<&[u8]> {
    let size = rd32(reply, 8)? as usize;
    let size = size.min(EDID_MAX_BYTES);
    reply.get(16..16 + size)
}

fn rd32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
