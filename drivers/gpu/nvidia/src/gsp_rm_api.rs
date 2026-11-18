//! GSP-RM object model over RPC — the post-`INIT_DONE` foundation.
//!
//! Once the GSP firmware is up, the host drives the GPU by allocating
//! RM objects and issuing control calls to them over two RPCs:
//! `GSP_RM_ALLOC` (103) and `GSP_RM_CONTROL` (76). This module builds
//! those payloads and the object hierarchy a display bring-up needs:
//! root client → device → subdevice → display-common → display.
//!
//! Each payload is sent as an ordinary RPC via [`crate::gsp_ring`]
//! (`function` = the ids below, body = the bytes built here), so no new
//! transport is required. Grounded against `/usr/src/linux`
//! `rm/r535/nvrm/{alloc,ctrl,client,device}.h` + `rm/handles.h` +
//! `include/nvif/class.h`.
//!
//! Pure CPU work (no hardware), unit-tested.

#![allow(dead_code)]

use alloc::vec::Vec;

// ── RPC function ids ─────────────────────────────────────────────

/// `NV_VGPU_MSG_FUNCTION_GSP_RM_ALLOC`.
pub const FUNCTION_GSP_RM_ALLOC: u32 = 103;
/// `NV_VGPU_MSG_FUNCTION_GSP_RM_CONTROL`.
pub const FUNCTION_GSP_RM_CONTROL: u32 = 76;

// ── Class codes (include/nvif/class.h) ───────────────────────────

pub const NV01_ROOT: u32 = 0x0;
pub const NV01_DEVICE_0: u32 = 0x80;
pub const NV20_SUBDEVICE_0: u32 = 0x2080;
pub const NV04_DISPLAY_COMMON: u32 = 0x73;
/// Turing display root class.
pub const TU102_DISP: u32 = 0xc570;
/// Turing display core channel (DMA).
pub const TU102_DISP_CORE_CHANNEL_DMA: u32 = 0xc57d;

// ── Canonical object handles (rm/handles.h) ──────────────────────

/// Client handle for RM client `id`: `0xc1d00000 | id`.
pub const fn client_handle(id: u16) -> u32 {
    0xc1d0_0000 | id as u32
}
/// `NVKM_RM_DEVICE`.
pub const HANDLE_DEVICE: u32 = 0xde1d_0000;
/// `NVKM_RM_SUBDEVICE`.
pub const HANDLE_SUBDEVICE: u32 = 0x5d1d_0000;
/// `NVKM_RM_DISP` (the NV04_DISPLAY_COMMON object).
pub const HANDLE_DISP: u32 = 0x0073_0000;

/// Handle for an allocated object of `class` instance `inst`:
/// `(class << 16) | inst` (how display channels + the disp root are
/// named).
pub const fn class_handle(class: u32, inst: u16) -> u32 {
    (class << 16) | inst as u32
}

// ── Generic alloc / control payload builders ─────────────────────

/// `sizeof(rpc_gsp_rm_alloc_v03_00)` header (before `params[]`).
pub const RM_ALLOC_HDR_SIZE: usize = 32;
/// `sizeof(rpc_gsp_rm_control_v03_00)` header (before `params[]`).
pub const RM_CONTROL_HDR_SIZE: usize = 24;

/// Build a `GSP_RM_ALLOC` payload: the 32-byte header
/// (hClient, hParent, hObject, hClass, status=0, paramsSize, flags=0,
/// reserved) followed by the class-specific `params`.
pub fn build_rm_alloc(
    h_client: u32,
    h_parent: u32,
    h_object: u32,
    h_class: u32,
    params: &[u8],
) -> Vec<u8> {
    let mut b = alloc::vec![0u8; RM_ALLOC_HDR_SIZE + params.len()];
    let p = |b: &mut [u8], o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    p(&mut b, 0x00, h_client);
    p(&mut b, 0x04, h_parent);
    p(&mut b, 0x08, h_object);
    p(&mut b, 0x0c, h_class);
    // status @0x10 = 0 (RM fills on return).
    p(&mut b, 0x14, params.len() as u32); // paramsSize
                                          // flags @0x18 = 0, reserved @0x1c = 0.
    b[RM_ALLOC_HDR_SIZE..].copy_from_slice(params);
    b
}

/// Build a `GSP_RM_CONTROL` payload: the 24-byte header
/// (hClient, hObject, cmd, status=0, paramsSize, flags=0) followed by
/// the command-specific `params`.
pub fn build_rm_control(h_client: u32, h_object: u32, cmd: u32, params: &[u8]) -> Vec<u8> {
    let mut b = alloc::vec![0u8; RM_CONTROL_HDR_SIZE + params.len()];
    let p = |b: &mut [u8], o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    p(&mut b, 0x00, h_client);
    p(&mut b, 0x04, h_object);
    p(&mut b, 0x08, cmd);
    // status @0x0c = 0.
    p(&mut b, 0x10, params.len() as u32); // paramsSize
                                          // flags @0x14 = 0.
    b[RM_CONTROL_HDR_SIZE..].copy_from_slice(params);
    b
}

// ── Per-class alloc params ───────────────────────────────────────

/// `NV0000_ALLOC_PARAMETERS` (root client): hClient, processID (~0 =
/// kernel), processName[100]. 108 bytes.
pub fn nv0000_root_params(h_client: u32) -> [u8; 108] {
    let mut b = [0u8; 108];
    b[0..4].copy_from_slice(&h_client.to_le_bytes());
    b[4..8].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // processID = ~0
    b
}

/// `NV0080_ALLOC_PARAMETERS` (device): deviceId 0, hClientShare =
/// client, the rest zero. 56 bytes (u64 fields are 8-aligned).
pub fn nv0080_device_params(h_client_share: u32) -> [u8; 56] {
    let mut b = [0u8; 56];
    // deviceId @0 = 0.
    b[4..8].copy_from_slice(&h_client_share.to_le_bytes()); // hClientShare
    b
}

/// `NV2080_ALLOC_PARAMETERS` (subdevice): subDeviceId 0. 4 bytes.
pub fn nv2080_subdevice_params() -> [u8; 4] {
    [0u8; 4]
}

// ── Object-tree alloc RPC payloads ───────────────────────────────

/// Alloc the root client (`NV01_ROOT`). Self-parented.
pub fn alloc_root_rpc(h_client: u32) -> Vec<u8> {
    build_rm_alloc(
        h_client,
        h_client,
        h_client,
        NV01_ROOT,
        &nv0000_root_params(h_client),
    )
}

/// Alloc the device (`NV01_DEVICE_0`) under the client.
pub fn alloc_device_rpc(h_client: u32) -> Vec<u8> {
    build_rm_alloc(
        h_client,
        h_client,
        HANDLE_DEVICE,
        NV01_DEVICE_0,
        &nv0080_device_params(h_client),
    )
}

/// Alloc the subdevice (`NV20_SUBDEVICE_0`) under the device.
pub fn alloc_subdevice_rpc(h_client: u32) -> Vec<u8> {
    build_rm_alloc(
        h_client,
        HANDLE_DEVICE,
        HANDLE_SUBDEVICE,
        NV20_SUBDEVICE_0,
        &nv2080_subdevice_params(),
    )
}

/// Alloc the display-common object (`NV04_DISPLAY_COMMON`, no params)
/// under the device — the target of all `NV0073_CTRL_CMD_*` calls.
pub fn alloc_disp_common_rpc(h_client: u32) -> Vec<u8> {
    build_rm_alloc(
        h_client,
        HANDLE_DEVICE,
        HANDLE_DISP,
        NV04_DISPLAY_COMMON,
        &[],
    )
}

/// Alloc the display root (`TU102_DISP`, no params) under the device —
/// the parent for display channel allocations.
pub fn alloc_disp_rpc(h_client: u32) -> Vec<u8> {
    build_rm_alloc(
        h_client,
        HANDLE_DEVICE,
        class_handle(TU102_DISP, 0),
        TU102_DISP,
        &[],
    )
}

// ── RM reply parsing ─────────────────────────────────────────────
//
// A GSP_RM_ALLOC / GSP_RM_CONTROL reply comes back in the same header
// layout, with `status` filled by RM and the `params[]` updated in
// place (output fields written). `status == 0` (NV_OK) means success.

/// Byte offset of `status` in a `GSP_RM_CONTROL` reply header.
pub const RM_CONTROL_STATUS_OFFSET: usize = 0x0c;
/// Byte offset of `status` in a `GSP_RM_ALLOC` reply header.
pub const RM_ALLOC_STATUS_OFFSET: usize = 0x10;
/// `NV_OK`.
pub const NV_OK: u32 = 0;

fn rd32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// RM status from a `GSP_RM_CONTROL` reply (`NV_OK` on success).
pub fn rm_control_status(reply: &[u8]) -> Option<u32> {
    rd32(reply, RM_CONTROL_STATUS_OFFSET)
}

/// RM status from a `GSP_RM_ALLOC` reply.
pub fn rm_alloc_status(reply: &[u8]) -> Option<u32> {
    rd32(reply, RM_ALLOC_STATUS_OFFSET)
}

/// The params payload of a `GSP_RM_CONTROL` reply (after the header).
pub fn rm_control_params(reply: &[u8]) -> Option<&[u8]> {
    reply.get(RM_CONTROL_HDR_SIZE..)
}

/// The params payload of a `GSP_RM_ALLOC` reply (after the header).
pub fn rm_alloc_params(reply: &[u8]) -> Option<&[u8]> {
    reply.get(RM_ALLOC_HDR_SIZE..)
}

/// Is `reply` a successful reply to an RPC sent with `function`
/// (ALLOC or CONTROL)? Checks the status field at the function's
/// header offset is `NV_OK`.
pub fn rm_reply_ok(function: u32, reply: &[u8]) -> bool {
    let status = match function {
        FUNCTION_GSP_RM_ALLOC => rm_alloc_status(reply),
        FUNCTION_GSP_RM_CONTROL => rm_control_status(reply),
        _ => return true, // non-RM RPCs carry no RM status
    };
    status == Some(NV_OK)
}
