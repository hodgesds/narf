//! GSP-RM DisplayPort link-training control calls.
//!
//! On a GSP card the DP output path — AUX transactions, link
//! configuration, and the drive-current/pre-emphasis the PHY uses — is
//! driven through GSP-RM `NV0073_CTRL_CMD_DP_*` controls against the
//! display-common object ([`crate::gsp_rm_api::HANDLE_DISP`]), the same
//! transport as [`crate::gsp_disp`]. This module builds the three
//! controls the r535 driver uses to bring a DP link up:
//!
//! - `DP_AUXCH_CTRL` — a native-AUX read/write (DPCD, EDID over AUX).
//! - `DP_CTRL` — set the link configuration (lane count + link rate,
//!   enhanced framing) and run / skip link training.
//! - `DP_SET_LANE_DATA` — the per-lane drive current + pre-emphasis.
//!
//! Grounded against `/usr/src/linux`
//! `rm/r535/{disp.c,nvrm/disp.h}`.
//!
//! Pure CPU work (no hardware), unit-tested.

#![allow(dead_code)]

use alloc::vec::Vec;

use crate::gsp_disp::disp_control_rpc;

// ── Command ids (verified vs disp.h) ─────────────────────────────

/// DP AUX channel transaction.
pub const CMD_DP_AUXCH_CTRL: u32 = 0x0073_1341;
/// Set DP link configuration / run link training.
pub const CMD_DP_CTRL: u32 = 0x0073_1343;
/// Program per-lane drive current + pre-emphasis.
pub const CMD_DP_SET_LANE_DATA: u32 = 0x0073_1346;

/// Max bytes in one AUX transaction (`NV0073_CTRL_DP_AUXCH_MAX_DATA_SIZE`).
pub const AUXCH_MAX_DATA: usize = 16;
/// Max lanes (`NV0073_CTRL_MAX_LANES`).
pub const MAX_LANES: usize = 8;

// ── DP_CTRL.cmd bitfields ────────────────────────────────────────

/// `SET_LANE_COUNT` (0:0) — program the lane count from `data`.
pub const CMD_SET_LANE_COUNT: u32 = 1 << 0;
/// `SET_LINK_BW` (1:1) — program the link bandwidth from `data`.
pub const CMD_SET_LINK_BW: u32 = 1 << 1;
/// `DISABLE_DOWNSPREAD` (2:2).
pub const CMD_DISABLE_DOWNSPREAD: u32 = 1 << 2;
/// `SET_FORMAT_MODE` (4:4) — 1 = multi-stream (MST).
pub const CMD_SET_FORMAT_MODE_MULTI_STREAM: u32 = 1 << 4;
/// `FAST_LINK_TRAINING` (5:5).
pub const CMD_FAST_LINK_TRAINING: u32 = 1 << 5;
/// `NO_LINK_TRAINING` (6:6) — set config without training.
pub const CMD_NO_LINK_TRAINING: u32 = 1 << 6;
/// `SET_ENHANCED_FRAMING` (7:7).
pub const CMD_SET_ENHANCED_FRAMING: u32 = 1 << 7;

// ── DP_CTRL.data bitfields ───────────────────────────────────────

/// `SET_LANE_COUNT` (4:0) — the DP lane-count code (1/2/4/8).
pub const fn data_lane_count(lanes: u32) -> u32 {
    lanes & 0x1f
}

/// `SET_LINK_BW` (15:8) — the DP link-rate code (see `LINK_BW_*`).
pub const fn data_link_bw(bw_code: u32) -> u32 {
    (bw_code & 0xff) << 8
}

/// `SET_ENHANCED_FRAMING` (18:18).
pub const DATA_ENHANCED_FRAMING: u32 = 1 << 18;

/// `TARGET` (22:19) — 0 = sink; 1.. = LTTPR phy repeaters.
pub const fn data_target(target: u32) -> u32 {
    (target & 0xf) << 19
}

/// DP link-rate codes (`NV0073_CTRL_DP_DATA_SET_LINK_BW_*`), in units of
/// the DPCD LINK_BW_SET byte (rate / 270 MHz × 1.62/… — the raw codes).
pub const LINK_BW_1_62GBPS: u32 = 0x06;
pub const LINK_BW_2_70GBPS: u32 = 0x0a;
pub const LINK_BW_5_40GBPS: u32 = 0x14;
pub const LINK_BW_8_10GBPS: u32 = 0x1e;

// ── DP_SET_LANE_DATA per-lane bitfields ──────────────────────────

/// `PREEMPHASIS` (1:0) and `DRIVECURRENT` (3:2) for one lane.
pub const fn lane_data(drive_current: u32, preemphasis: u32) -> u32 {
    (preemphasis & 0x3) | ((drive_current & 0x3) << 2)
}

// ── AUXCH_CTRL.cmd bitfields ─────────────────────────────────────

/// `REQ_TYPE` (1:0).
pub const AUX_REQ_WRITE: u32 = 0;
pub const AUX_REQ_READ: u32 = 1;
pub const AUX_REQ_WRITE_STATUS: u32 = 2;
/// `I2C_MOT` (2:2) — middle-of-transaction for I2C-over-AUX.
pub const AUX_I2C_MOT: u32 = 1 << 2;
/// `TYPE` (3:3) — 0 = I2C, 1 = native AUX.
pub const AUX_TYPE_AUX: u32 = 1 << 3;

/// Compose an `AUXCH_CTRL.cmd`: native-AUX read or write.
pub const fn aux_cmd(req_type: u32, native_aux: bool) -> u32 {
    (req_type & 0x3) | if native_aux { AUX_TYPE_AUX } else { 0 }
}

// ── DP_CTRL params ───────────────────────────────────────────────

/// `NV0073_CTRL_DP_CTRL_PARAMS` (28 bytes): subDeviceInstance,
/// displayId, cmd, data, err, retryTimeMs, eightLaneDpcdBaseAddr.
pub fn dp_ctrl_params(display_id: u32, cmd: u32, data: u32) -> [u8; 28] {
    let mut b = [0u8; 28];
    b[4..8].copy_from_slice(&display_id.to_le_bytes());
    b[8..12].copy_from_slice(&cmd.to_le_bytes());
    b[12..16].copy_from_slice(&data.to_le_bytes());
    b
}

/// Build a `DP_CTRL` to set the link config and run training for a
/// `lanes`-lane, `bw_code`-rate link (enhanced framing on). `lanes` is
/// the raw DP lane count (1/2/4/8); `bw_code` is a `LINK_BW_*` code.
pub fn set_link_config_params(display_id: u32, lanes: u32, bw_code: u32) -> [u8; 28] {
    let cmd = CMD_SET_LANE_COUNT | CMD_SET_LINK_BW | CMD_SET_ENHANCED_FRAMING;
    let data =
        data_lane_count(lanes) | data_link_bw(bw_code) | DATA_ENHANCED_FRAMING | data_target(0);
    dp_ctrl_params(display_id, cmd, data)
}

/// Parse a `DP_CTRL` reply → `(err, data)`. `err == 0` means the link
/// config / training succeeded; `data` carries the achieved config.
pub fn parse_dp_ctrl(reply: &[u8]) -> Option<(u32, u32)> {
    Some((rd32(reply, 16)?, rd32(reply, 12)?))
}

/// Build the `DP_CTRL` `GSP_RM_CONTROL` RPC payload.
pub fn dp_ctrl_rpc(h_client: u32, params: &[u8]) -> Vec<u8> {
    disp_control_rpc(h_client, CMD_DP_CTRL, params)
}

// ── DP_SET_LANE_DATA params ──────────────────────────────────────

/// `NV0073_CTRL_DP_LANE_DATA_PARAMS` (44 bytes): subDeviceInstance,
/// displayId, numLanes, data[8]. `lanes` holds the per-lane
/// [`lane_data`] codes; only the first `numLanes` entries are used.
pub fn set_lane_data_params(display_id: u32, lanes: &[u32]) -> [u8; 44] {
    let mut b = [0u8; 44];
    let n = lanes.len().min(MAX_LANES);
    b[4..8].copy_from_slice(&display_id.to_le_bytes());
    b[8..12].copy_from_slice(&(n as u32).to_le_bytes());
    for (i, &v) in lanes.iter().take(n).enumerate() {
        let o = 12 + i * 4;
        b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }
    b
}

/// Build the `DP_SET_LANE_DATA` `GSP_RM_CONTROL` RPC payload.
pub fn set_lane_data_rpc(h_client: u32, params: &[u8]) -> Vec<u8> {
    disp_control_rpc(h_client, CMD_DP_SET_LANE_DATA, params)
}

// ── AUXCH_CTRL params ────────────────────────────────────────────

/// `NV0073_CTRL_DP_AUXCH_CTRL_PARAMS` (48 bytes): subDeviceInstance,
/// displayId, bAddrOnly, cmd, addr, data[16], size, replyType,
/// retryTimeMs. For a write, `data` carries the payload; `size` is the
/// DPCD byte count minus one (AUX convention).
pub fn auxch_ctrl_params(display_id: u32, cmd: u32, addr: u32, data: &[u8]) -> [u8; 48] {
    let mut b = [0u8; 48];
    let n = data.len().min(AUXCH_MAX_DATA);
    b[4..8].copy_from_slice(&display_id.to_le_bytes());
    // bAddrOnly @8 = 0 (we always carry an address + size).
    b[12..16].copy_from_slice(&cmd.to_le_bytes());
    b[16..20].copy_from_slice(&addr.to_le_bytes());
    b[20..20 + n].copy_from_slice(&data[..n]);
    // size field is the transaction length minus one.
    let size = (n as u32).saturating_sub(1);
    b[36..40].copy_from_slice(&size.to_le_bytes());
    b
}

/// Build an AUX native read request for `len` bytes at DPCD `addr`.
pub fn aux_read_params(display_id: u32, addr: u32, len: usize) -> [u8; 48] {
    let mut b = [0u8; 48];
    let n = len.clamp(1, AUXCH_MAX_DATA);
    b[4..8].copy_from_slice(&display_id.to_le_bytes());
    b[12..16].copy_from_slice(&aux_cmd(AUX_REQ_READ, true).to_le_bytes());
    b[16..20].copy_from_slice(&addr.to_le_bytes());
    b[36..40].copy_from_slice(&((n as u32) - 1).to_le_bytes());
    b
}

/// Build an AUX native write request of `data` to DPCD `addr`.
pub fn aux_write_params(display_id: u32, addr: u32, data: &[u8]) -> [u8; 48] {
    auxch_ctrl_params(display_id, aux_cmd(AUX_REQ_WRITE, true), addr, data)
}

/// Parse an AUX reply → the returned data (bounded by `size`+1). The
/// `size` field is the byte count minus one; the data starts at
/// offset 20.
pub fn parse_aux_reply(reply: &[u8]) -> Option<&[u8]> {
    let size = (rd32(reply, 36)? as usize)
        .saturating_add(1)
        .min(AUXCH_MAX_DATA);
    reply.get(20..20 + size)
}

/// Build the `DP_AUXCH_CTRL` `GSP_RM_CONTROL` RPC payload.
pub fn auxch_ctrl_rpc(h_client: u32, params: &[u8]) -> Vec<u8> {
    disp_control_rpc(h_client, CMD_DP_AUXCH_CTRL, params)
}

fn rd32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
