//! virtio-gpu command builders / decoders. Pure-data — no MMIO,
//! no DMA. Wire format from VirtIO 1.2 §5.7.6 (control commands).
//!
//! Every command starts with `virtio_gpu_ctrl_hdr` (24 bytes, §5.7.6.7):
//!   u32 type, u32 flags, u64 fence_id, u32 ctx_id, u32 padding.
//! Builders write the header at offset 0 + the body starting at 24.
//! Decoders parse the body into a typed struct so the round-trip
//! `build → decode → re-build` reproduces the wire bytes.

#![allow(missing_debug_implementations)]

// ── Command types (VirtIO 1.2 §5.7.6) ──────────────────────────────

pub const VIRTIO_GPU_CMD_GET_DISPLAY_INFO:        u32 = 0x0100;
pub const VIRTIO_GPU_CMD_RESOURCE_CREATE_2D:      u32 = 0x0101;
pub const VIRTIO_GPU_CMD_RESOURCE_UNREF:          u32 = 0x0102;
pub const VIRTIO_GPU_CMD_SET_SCANOUT:             u32 = 0x0103;
pub const VIRTIO_GPU_CMD_RESOURCE_FLUSH:          u32 = 0x0104;
pub const VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D:     u32 = 0x0105;
pub const VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;

pub const HDR_LEN: usize = 24;

// ── Header (VirtIO 1.2 §5.7.6.7) ───────────────────────────────────

/// Write the 24-byte ctrl header at offset 0 of `out`.
/// Caller-supplied `flags`, `fence_id`, `ctx_id` — drivers usually
/// pass 0 for all three.
pub fn put_hdr(out: &mut [u8], cmd_type: u32, flags: u32, fence_id: u64, ctx_id: u32) {
    out[0..4].copy_from_slice(&cmd_type.to_le_bytes());
    out[4..8].copy_from_slice(&flags.to_le_bytes());
    out[8..16].copy_from_slice(&fence_id.to_le_bytes());
    out[16..20].copy_from_slice(&ctx_id.to_le_bytes());
    out[20..24].copy_from_slice(&0u32.to_le_bytes()); // padding
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CtrlHdr {
    pub cmd_type: u32,
    pub flags:    u32,
    pub fence_id: u64,
    pub ctx_id:   u32,
}

pub fn read_hdr(buf: &[u8]) -> CtrlHdr {
    CtrlHdr {
        cmd_type: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        flags:    u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        fence_id: u64::from_le_bytes([
            buf[8],  buf[9],  buf[10], buf[11],
            buf[12], buf[13], buf[14], buf[15],
        ]),
        ctx_id:   u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]),
    }
}

// ── GET_DISPLAY_INFO (§5.7.6.8) ────────────────────────────────────
// No body — just the header.

pub const GET_DISPLAY_INFO_LEN: usize = HDR_LEN;

pub fn build_get_display_info(out: &mut [u8]) {
    put_hdr(out, VIRTIO_GPU_CMD_GET_DISPLAY_INFO, 0, 0, 0);
}

// ── RESOURCE_CREATE_2D (§5.7.6.8) ──────────────────────────────────
// Body: u32 resource_id, u32 format, u32 width, u32 height.

pub const RESOURCE_CREATE_2D_BODY: usize = 16;
pub const RESOURCE_CREATE_2D_LEN:  usize = HDR_LEN + RESOURCE_CREATE_2D_BODY;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ResourceCreate2D {
    pub resource_id: u32,
    pub format:      u32,
    pub width:       u32,
    pub height:      u32,
}

pub fn build_resource_create_2d(out: &mut [u8], r: ResourceCreate2D) {
    put_hdr(out, VIRTIO_GPU_CMD_RESOURCE_CREATE_2D, 0, 0, 0);
    out[24..28].copy_from_slice(&r.resource_id.to_le_bytes());
    out[28..32].copy_from_slice(&r.format.to_le_bytes());
    out[32..36].copy_from_slice(&r.width.to_le_bytes());
    out[36..40].copy_from_slice(&r.height.to_le_bytes());
}

pub fn decode_resource_create_2d(buf: &[u8]) -> ResourceCreate2D {
    ResourceCreate2D {
        resource_id: u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]),
        format:      u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]),
        width:       u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]),
        height:      u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]),
    }
}

// ── RESOURCE_ATTACH_BACKING (§5.7.6.8) ─────────────────────────────
// Body: u32 resource_id, u32 nr_entries, then nr_entries × mem_entry
// (u64 addr, u32 length, u32 padding). One entry only here — multi-
// entry support lands when the framebuffer outgrows a single page.

pub const ATTACH_BACKING_ENTRY: usize = 16;
pub const ATTACH_BACKING_BODY:  usize = 8 + ATTACH_BACKING_ENTRY;
pub const ATTACH_BACKING_LEN:   usize = HDR_LEN + ATTACH_BACKING_BODY;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AttachBacking {
    pub resource_id: u32,
    pub addr:        u64,
    pub length:      u32,
}

pub fn build_resource_attach_backing(out: &mut [u8], a: AttachBacking) {
    put_hdr(out, VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING, 0, 0, 0);
    out[24..28].copy_from_slice(&a.resource_id.to_le_bytes());
    out[28..32].copy_from_slice(&1u32.to_le_bytes()); // nr_entries
    out[32..40].copy_from_slice(&a.addr.to_le_bytes());
    out[40..44].copy_from_slice(&a.length.to_le_bytes());
    out[44..48].copy_from_slice(&0u32.to_le_bytes()); // padding
}

pub fn decode_resource_attach_backing(buf: &[u8]) -> AttachBacking {
    AttachBacking {
        resource_id: u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]),
        addr:        u64::from_le_bytes([
            buf[32], buf[33], buf[34], buf[35],
            buf[36], buf[37], buf[38], buf[39],
        ]),
        length:      u32::from_le_bytes([buf[40], buf[41], buf[42], buf[43]]),
    }
}

// ── SET_SCANOUT (§5.7.6.8) ─────────────────────────────────────────
// Body: rect (x,y,w,h: u32 ×4) + scanout_id (u32) + resource_id (u32).

pub const SET_SCANOUT_BODY: usize = 24;
pub const SET_SCANOUT_LEN:  usize = HDR_LEN + SET_SCANOUT_BODY;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SetScanout {
    pub x:           u32,
    pub y:           u32,
    pub width:       u32,
    pub height:      u32,
    pub scanout_id:  u32,
    pub resource_id: u32,
}

pub fn build_set_scanout(out: &mut [u8], s: SetScanout) {
    put_hdr(out, VIRTIO_GPU_CMD_SET_SCANOUT, 0, 0, 0);
    out[24..28].copy_from_slice(&s.x.to_le_bytes());
    out[28..32].copy_from_slice(&s.y.to_le_bytes());
    out[32..36].copy_from_slice(&s.width.to_le_bytes());
    out[36..40].copy_from_slice(&s.height.to_le_bytes());
    out[40..44].copy_from_slice(&s.scanout_id.to_le_bytes());
    out[44..48].copy_from_slice(&s.resource_id.to_le_bytes());
}

pub fn decode_set_scanout(buf: &[u8]) -> SetScanout {
    SetScanout {
        x:           u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]),
        y:           u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]),
        width:       u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]),
        height:      u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]),
        scanout_id:  u32::from_le_bytes([buf[40], buf[41], buf[42], buf[43]]),
        resource_id: u32::from_le_bytes([buf[44], buf[45], buf[46], buf[47]]),
    }
}

// ── TRANSFER_TO_HOST_2D (§5.7.6.8) ─────────────────────────────────
// Body: rect (16) + offset (u64) + resource_id (u32) + padding (u32).

pub const TRANSFER_TO_HOST_2D_BODY: usize = 32;
pub const TRANSFER_TO_HOST_2D_LEN:  usize = HDR_LEN + TRANSFER_TO_HOST_2D_BODY;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TransferToHost2D {
    pub x:           u32,
    pub y:           u32,
    pub width:       u32,
    pub height:      u32,
    pub offset:      u64,
    pub resource_id: u32,
}

pub fn build_transfer_to_host_2d(out: &mut [u8], t: TransferToHost2D) {
    put_hdr(out, VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D, 0, 0, 0);
    out[24..28].copy_from_slice(&t.x.to_le_bytes());
    out[28..32].copy_from_slice(&t.y.to_le_bytes());
    out[32..36].copy_from_slice(&t.width.to_le_bytes());
    out[36..40].copy_from_slice(&t.height.to_le_bytes());
    out[40..48].copy_from_slice(&t.offset.to_le_bytes());
    out[48..52].copy_from_slice(&t.resource_id.to_le_bytes());
    out[52..56].copy_from_slice(&0u32.to_le_bytes()); // padding
}

pub fn decode_transfer_to_host_2d(buf: &[u8]) -> TransferToHost2D {
    TransferToHost2D {
        x:           u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]),
        y:           u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]),
        width:       u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]),
        height:      u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]),
        offset:      u64::from_le_bytes([
            buf[40], buf[41], buf[42], buf[43],
            buf[44], buf[45], buf[46], buf[47],
        ]),
        resource_id: u32::from_le_bytes([buf[48], buf[49], buf[50], buf[51]]),
    }
}

// ── RESOURCE_FLUSH (§5.7.6.8) ──────────────────────────────────────
// Body: rect (16) + resource_id (u32) + padding (u32).

pub const RESOURCE_FLUSH_BODY: usize = 24;
pub const RESOURCE_FLUSH_LEN:  usize = HDR_LEN + RESOURCE_FLUSH_BODY;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ResourceFlush {
    pub x:           u32,
    pub y:           u32,
    pub width:       u32,
    pub height:      u32,
    pub resource_id: u32,
}

pub fn build_resource_flush(out: &mut [u8], r: ResourceFlush) {
    put_hdr(out, VIRTIO_GPU_CMD_RESOURCE_FLUSH, 0, 0, 0);
    out[24..28].copy_from_slice(&r.x.to_le_bytes());
    out[28..32].copy_from_slice(&r.y.to_le_bytes());
    out[32..36].copy_from_slice(&r.width.to_le_bytes());
    out[36..40].copy_from_slice(&r.height.to_le_bytes());
    out[40..44].copy_from_slice(&r.resource_id.to_le_bytes());
    out[44..48].copy_from_slice(&0u32.to_le_bytes()); // padding
}

pub fn decode_resource_flush(buf: &[u8]) -> ResourceFlush {
    ResourceFlush {
        x:           u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]),
        y:           u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]),
        width:       u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]),
        height:      u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]),
        resource_id: u32::from_le_bytes([buf[40], buf[41], buf[42], buf[43]]),
    }
}
