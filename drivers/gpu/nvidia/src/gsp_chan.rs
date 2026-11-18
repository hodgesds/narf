//! GSP-RM display channel allocation — the bridge to the NvDisplay
//! pushbuffer modeset.
//!
//! On a GSP card a display channel (core / window / cursor) is brought
//! up in two RPCs: register its pushbuffer with GSP against the
//! internal subdevice (`NV2080_CTRL_CMD_INTERNAL_DISPLAY_CHANNEL_
//! PUSHBUFFER`), then allocate the channel object under the display
//! root (`GSP_RM_ALLOC` of the channel class). RM maps the channel's
//! GET/PUT register page at a fixed BAR0 offset; from there the host
//! drives modeset by pushing NvDisplay methods directly (the existing
//! [`crate::disp::nv50`] path). Grounded against `/usr/src/linux`
//! `rm/r535/{disp.c,nvrm/disp.h}` + `include/nvif/class.h`.
//!
//! Pure CPU work (no hardware), unit-tested.

#![allow(dead_code)]

use crate::gsp_rm_api::{build_rm_alloc, build_rm_control, class_handle, TU102_DISP};

// ── Channel classes (Turing) ─────────────────────────────────────

pub const DISP_CORE_CHANNEL_DMA: u32 = 0xc57d;
pub const DISP_WINDOW_CHANNEL_DMA: u32 = 0xc57e;
pub const DISP_WINDOW_IMM_CHANNEL_DMA: u32 = 0xc57b;
pub const DISP_CURSOR: u32 = 0xc57a;

/// Memory address spaces (`disp.h`).
pub const ADDR_SYSMEM: u32 = 1;
pub const ADDR_FBMEM: u32 = 2;

// ── Control / alloc command ids ──────────────────────────────────

/// Register a channel's pushbuffer with GSP (on the internal subdevice).
pub const CMD_INTERNAL_DISPLAY_CHANNEL_PUSHBUFFER: u32 = 0x2080_0a58;
/// Hand GSP the display instance-memory (RAMIN) VRAM address.
pub const CMD_INTERNAL_DISPLAY_WRITE_INST_MEM: u32 = 0x2080_0a49;

// ── Channel user (GET/PUT) MMIO window ───────────────────────────

/// BAR0 offset + size of the channel's GET/PUT register page, keyed on
/// class and head. Cite `r535_chan_user`: core `0x680000` (0x10000);
/// window `0x690000`, wimm `0x6b0000`, cursor `0x6d8000`, each at
/// `head*0x1000` stride (0x1000). This is where [`crate::disp::nv50`]
/// writes PUT.
pub fn channel_user_offset(class: u32, head: u8) -> Option<(u64, u64)> {
    let h = head as u64;
    Some(match class & 0xff {
        0x7d => (0x68_0000, 0x1_0000),
        0x7e => (0x69_0000 + h * 0x1000, 0x1000),
        0x7b => (0x6b_0000 + h * 0x1000, 0x1000),
        0x7a => (0x6d_8000 + h * 0x1000, 0x1000),
        _ => return None,
    })
}

// ── Pushbuffer registration params ───────────────────────────────

/// `NV2080_CTRL_INTERNAL_DISPLAY_CHANNEL_PUSHBUFFER_PARAMS` (40 bytes):
/// addressSpace, physicalAddr, limit (size-1), cacheSnoop, hclass,
/// channelInstance, valid.
pub fn channel_pushbuffer_params(
    addr_space: u32,
    phys: u64,
    limit: u64,
    hclass: u32,
    channel_instance: u32,
    valid: bool,
) -> [u8; 40] {
    let mut b = [0u8; 40];
    let p32 = |b: &mut [u8], o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    let p64 = |b: &mut [u8], o: usize, v: u64| b[o..o + 8].copy_from_slice(&v.to_le_bytes());
    p32(&mut b, 0x00, addr_space);
    // pad @0x04 for the 8-aligned u64 fields.
    p64(&mut b, 0x08, phys);
    p64(&mut b, 0x10, limit);
    // cacheSnoop @0x18 = 0.
    p32(&mut b, 0x1c, hclass);
    p32(&mut b, 0x20, channel_instance);
    b[0x24] = valid as u8;
    b
}

// ── Channel alloc params ─────────────────────────────────────────

/// `NV50VAIO_CHANNELDMA_ALLOCATION_PARAMETERS` (32 bytes):
/// channelInstance, hObjectBuffer, hObjectNotify, offset, pControl
/// (RM fills), flags. Only `channelInstance` is set for the r535 path.
pub fn channeldma_alloc_params(channel_instance: u32) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0..4].copy_from_slice(&channel_instance.to_le_bytes());
    b
}

// ── RPC payload builders ─────────────────────────────────────────

/// Build the pushbuffer-registration `GSP_RM_CONTROL` payload, targeting
/// the **internal** subdevice handle (from `GspStaticConfigInfo`).
#[allow(clippy::too_many_arguments)]
pub fn pushbuffer_rpc(
    h_client: u32,
    h_internal_subdevice: u32,
    addr_space: u32,
    phys: u64,
    limit: u64,
    hclass: u32,
    channel_instance: u32,
    valid: bool,
) -> alloc::vec::Vec<u8> {
    let params =
        channel_pushbuffer_params(addr_space, phys, limit, hclass, channel_instance, valid);
    build_rm_control(
        h_client,
        h_internal_subdevice,
        CMD_INTERNAL_DISPLAY_CHANNEL_PUSHBUFFER,
        &params,
    )
}

/// Build the channel `GSP_RM_ALLOC` payload: the channel object
/// (`(hclass << 16) | inst`) under the display root (`TU102_DISP`).
pub fn alloc_channel_rpc(h_client: u32, hclass: u32, inst: u16) -> alloc::vec::Vec<u8> {
    build_rm_alloc(
        h_client,
        class_handle(TU102_DISP, 0),
        class_handle(hclass, inst),
        hclass,
        &channeldma_alloc_params(inst as u32),
    )
}
