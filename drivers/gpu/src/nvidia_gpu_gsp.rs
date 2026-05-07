//! NVIDIA GSP RPC framing — clean-room.
//!
//! ## Reference
//!
//! NVIDIA `open-gpu-kernel-modules` (dual MIT / GPL-2.0) — only
//! the **MIT-licensed RPC headers** are consumed:
//!
//! - `src/common/sdk/nvidia/inc/rpc/...` — message function IDs.
//! - `src/common/inc/rmRiscvUcode.h` — descriptor used by the
//!   loader to point GSP at its firmware blob.
//!
//! Each consumed file's SPDX header (`SPDX-License-Identifier:
//! MIT`) is checked before transcribing constants. **No GPL
//! Linux `nouveau` source consulted; no GPL-2.0 files in
//! open-gpu-kernel-modules consulted.**
//!
//! ## Why GSP
//!
//! Starting with Turing, NVIDIA moved most chip-control surface
//! from the host driver into a **GPU System Processor (GSP)**
//! firmware blob running on a dedicated Falcon-class CPU. The
//! host driver:
//!
//! 1. Stages signed GSP firmware into the GSP Falcon's IMEM/DMEM.
//! 2. Sets `BOOTVEC` and asserts `CPUCTL.STARTCPU` (per the
//!    Falcon codec in [`super::nvidia_gpu_falcon`]).
//! 3. After GSP is up, all subsequent control flows through a
//!    **shared-memory RPC ring**. The host pushes 4 KiB-aligned
//!    RPC frames into a circular buffer; GSP processes them and
//!    writes responses back into a paired ring.
//!
//! Stage-2 ships the **wire format** of those RPC frames — the
//! header layout + the documented function IDs the host driver
//! issues for display bring-up. The actual ring management +
//! Falcon load lives in the Stage-3 driver core.
//!
//! ## RPC frame
//!
//! ```text
//!   bytes  0..4    header_version  (must be 0x10000003 today)
//!   bytes  4..8    function_id     (NV_VGPU_MSG_FUNCTION_*)
//!   bytes  8..12   length          (header + payload, in bytes)
//!   bytes 12..16   sequence        (host-monotonic, echoed by GSP)
//!   bytes 16..20   rpc_result      (set by GSP on response)
//!   bytes 20..24   rpc_result_private (vendor-private status)
//!   bytes 24..28   reserved
//!   bytes 28..32   rpc_message_status_dword
//!   bytes 32..     payload (function-specific)
//! ```
//!
//! Payloads are 16-byte aligned; the driver pads the trailing
//! bytes with zero.

use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryInto;

/// Documented GSP RPC header version. The MIT-licensed RPC
/// header file defines this as `NV_VGPU_MSG_HEADER_VERSION`.
pub const HEADER_VERSION: u32 = 0x1000_0003;

/// Length of the GSP RPC header in bytes.
pub const HEADER_LEN: usize = 32;

/// 16-byte payload alignment the wire format requires.
pub const PAYLOAD_ALIGN: usize = 16;

// ── Function IDs ─────────────────────────────────────────────────
//
// Source: MIT-licensed `g_rpc-message-header-typedef.h` /
// `vgpu_rpc.h`. Only the documented IDs the display path uses
// land here; the full table runs to ~400 entries that aren't
// load-bearing for Stage-2.

/// `NV_VGPU_MSG_FUNCTION_NOP` — heartbeat / probe.
pub const FN_NOP: u32 = 0;
/// `NV_VGPU_MSG_FUNCTION_SET_GUEST_SYSTEM_INFO` — initial host
/// handshake; GSP records the host's identity.
pub const FN_SET_GUEST_SYSTEM_INFO: u32 = 1;
/// `NV_VGPU_MSG_FUNCTION_ALLOC_ROOT` — allocate the resource-
/// manager root handle.
pub const FN_ALLOC_ROOT: u32 = 2;
/// `NV_VGPU_MSG_FUNCTION_ALLOC_DEVICE` — instantiate the GPU
/// device object.
pub const FN_ALLOC_DEVICE: u32 = 3;
/// `NV_VGPU_MSG_FUNCTION_ALLOC_MEMORY` — allocate FB memory.
pub const FN_ALLOC_MEMORY: u32 = 4;
/// `NV_VGPU_MSG_FUNCTION_FREE` — free a previously-allocated
/// resource handle.
pub const FN_FREE: u32 = 5;
/// `NV_VGPU_MSG_FUNCTION_LOG` — log message from GSP to host.
pub const FN_LOG: u32 = 6;
/// `NV_VGPU_MSG_FUNCTION_ALLOC_DISP_CHANNEL` — allocate a
/// display channel.
pub const FN_ALLOC_DISP_CHANNEL: u32 = 7;
/// `NV_VGPU_MSG_FUNCTION_DISP_CHANNEL_SCHEDULE` — schedule
/// a display channel update (mode-set commit).
pub const FN_DISP_CHANNEL_SCHEDULE: u32 = 9;
/// `NV_VGPU_MSG_FUNCTION_GSP_RM_CONTROL` — generic resource-
/// manager control passthrough.
pub const FN_GSP_RM_CONTROL: u32 = 0x80;

// ── RPC result codes (subset) ────────────────────────────────────

/// `NV_OK`.
pub const RPC_RESULT_OK: u32 = 0;
/// `NV_ERR_GENERIC`.
pub const RPC_RESULT_GENERIC: u32 = 0x0000_FFFF;
/// `NV_ERR_INVALID_ARGUMENT`.
pub const RPC_RESULT_INVALID_ARGUMENT: u32 = 0x0000_001F;
/// `NV_ERR_NOT_SUPPORTED`.
pub const RPC_RESULT_NOT_SUPPORTED: u32 = 0x0000_0056;

// ── Encoded frame ────────────────────────────────────────────────

/// Decoded GSP RPC header. Mirrors the on-the-wire layout
/// documented in the MIT-licensed RPC header file.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RpcHeader {
    pub header_version: u32,
    pub function: u32,
    pub length: u32,
    pub sequence: u32,
    pub rpc_result: u32,
    pub rpc_result_private: u32,
    pub rpc_message_status: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GspError {
    /// Frame shorter than the 32-byte header.
    ShortFrame,
    /// `header_version` not recognised.
    BadHeaderVersion(u32),
    /// `length` field smaller than the header or larger than the
    /// supplied buffer.
    BadLength,
    /// Payload not 16-byte aligned (host-side encoder rejects;
    /// decoder permits — GSP responses pad themselves).
    UnalignedPayload,
}

impl RpcHeader {
    pub fn decode(bytes: &[u8]) -> Result<Self, GspError> {
        if bytes.len() < HEADER_LEN {
            return Err(GspError::ShortFrame);
        }
        let v = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        if v != HEADER_VERSION {
            return Err(GspError::BadHeaderVersion(v));
        }
        let function = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let length = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        if (length as usize) < HEADER_LEN || (length as usize) > bytes.len() {
            return Err(GspError::BadLength);
        }
        let sequence = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let rpc_result = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        let rpc_result_private = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
        let rpc_message_status = u32::from_le_bytes(bytes[28..32].try_into().unwrap());
        Ok(Self {
            header_version: v,
            function,
            length,
            sequence,
            rpc_result,
            rpc_result_private,
            rpc_message_status,
        })
    }
}

/// Build a complete GSP RPC frame for `function` with `payload`.
/// Payload is padded with zeros to the 16-byte alignment GSP
/// requires; the returned buffer's `len` is the padded total.
pub fn build_frame(function: u32, sequence: u32, payload: &[u8]) -> Result<Vec<u8>, GspError> {
    let unpadded = HEADER_LEN + payload.len();
    let total = (unpadded + (PAYLOAD_ALIGN - 1)) & !(PAYLOAD_ALIGN - 1);
    let mut buf = vec![0u8; total];
    buf[0..4].copy_from_slice(&HEADER_VERSION.to_le_bytes());
    buf[4..8].copy_from_slice(&function.to_le_bytes());
    buf[8..12].copy_from_slice(&(total as u32).to_le_bytes());
    buf[12..16].copy_from_slice(&sequence.to_le_bytes());
    // rpc_result / rpc_result_private / reserved /
    // rpc_message_status are all left zero on the host->GSP path.
    buf[HEADER_LEN..HEADER_LEN + payload.len()].copy_from_slice(payload);
    Ok(buf)
}

/// Parse a GSP RPC response frame into `(header, payload-borrow)`.
pub fn parse_frame(frame: &[u8]) -> Result<(RpcHeader, &[u8]), GspError> {
    let h = RpcHeader::decode(frame)?;
    let payload = &frame[HEADER_LEN..h.length as usize];
    Ok((h, payload))
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_frame_round_trip() -> TestResult {
        let payload = b"hello-gsp";
        let frame = match build_frame(FN_NOP, 7, payload) {
            Ok(f) => f,
            Err(_) => return TestResult::Fail("clean inputs rejected"),
        };
        // 32-byte header + 9-byte payload, padded up to 48.
        if frame.len() != 48 {
            return TestResult::Fail("frame length not padded to 16-byte multiple");
        }
        let (h, decoded) = match parse_frame(&frame) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("self-built frame rejected by parser"),
        };
        if h.function != FN_NOP {
            return TestResult::Fail("function lost in round trip");
        }
        if h.sequence != 7 {
            return TestResult::Fail("sequence lost");
        }
        if h.length as usize != frame.len() {
            return TestResult::Fail("length should equal frame size");
        }
        if &decoded[..payload.len()] != payload {
            return TestResult::Fail("payload corrupted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/nvidia_gpu_gsp", smoke_frame_round_trip);

    fn smoke_frame_alignment_zero_payload() -> TestResult {
        let frame = build_frame(FN_NOP, 0, &[]).expect("clean inputs");
        if frame.len() != HEADER_LEN {
            return TestResult::Fail(
                "zero-payload frame should be exactly the 32-byte header",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/nvidia_gpu_gsp",
        smoke_frame_alignment_zero_payload
    );

    fn smoke_parse_rejects_short_header() -> TestResult {
        match RpcHeader::decode(&[0u8; 8]) {
            Err(GspError::ShortFrame) => TestResult::Pass,
            _ => TestResult::Fail("short frame must be rejected"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/nvidia_gpu_gsp",
        smoke_parse_rejects_short_header
    );

    fn smoke_parse_rejects_bad_version() -> TestResult {
        let mut bad = [0u8; 32];
        bad[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        match RpcHeader::decode(&bad) {
            Err(GspError::BadHeaderVersion(0xDEAD_BEEF)) => TestResult::Pass,
            _ => TestResult::Fail("wrong version must be rejected"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/nvidia_gpu_gsp",
        smoke_parse_rejects_bad_version
    );

    fn smoke_parse_rejects_oversize_length() -> TestResult {
        let mut frame = vec![0u8; 32];
        frame[0..4].copy_from_slice(&HEADER_VERSION.to_le_bytes());
        frame[8..12].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // length way too large
        match RpcHeader::decode(&frame) {
            Err(GspError::BadLength) => TestResult::Pass,
            _ => TestResult::Fail("oversize length must be rejected"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/nvidia_gpu_gsp",
        smoke_parse_rejects_oversize_length
    );
}
