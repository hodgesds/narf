//! Host FIFO — pushbuffer / channel management.
//!
//! ## Reference
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/nvkm/engine/fifo/base.c`**
//!   — generic `nvkm_fifo_*` entry points.
//! - **`drivers/gpu/drm/nouveau/nvkm/engine/fifo/gm200.c`** /
//!   **`gp100.c`** — Maxwell+/Pascal FIFO with USERD per channel.
//! - **`drivers/gpu/drm/nouveau/nvkm/engine/fifo/tu102.c`** —
//!   Turing+ runlist + per-channel doorbell.
//! - **`drivers/gpu/drm/nouveau/nvkm/engine/fifo/runl.c`** — the
//!   shared runlist code.
//!
//! ## Concepts
//!
//! - **Channel** — a host-side queue of work for one engine. The
//!   driver allocates a USERD slot (per-channel state in VRAM/
//!   sysmem), a Channel-Instance memory descriptor, and a
//!   pushbuffer.
//! - **Pushbuffer** — a circular buffer of `(method, data)` words.
//!   The GPU reads it via the FIFO front-end, dispatches each
//!   method to the bound engine.
//! - **Runlist** — list of channels eligible to run, ordered by
//!   priority. The host writes a new runlist + asks the FIFO to
//!   switch.

#![allow(dead_code)]

use crate::chip::ChipFamily;

// ── BAR0 offsets for the host FIFO ───────────────────────────────

/// `NV_PFIFO_INTR_0` — top-level FIFO interrupt status.
pub const PFIFO_INTR_0: u64 = 0x0000_2100;
/// `NV_PFIFO_INTR_EN_0` — top-level FIFO interrupt mask.
pub const PFIFO_INTR_EN_0: u64 = 0x0000_2140;

// ── USERD layout ─────────────────────────────────────────────────
//
// USERD is the per-channel host doorbell + GP_GET / GP_PUT
// pushbuffer-pointer pair. Cited
// `nvkm/engine/fifo/uchan.c::gv100_chan` for the Volta+ layout.
//
// 4 KiB per channel; the channel's `userd` lives at a fixed VRAM
// offset (allocated by the driver) and the FIFO front-end reads
// GP_GET / GP_PUT from there each time it switches to the channel.

/// USERD field offset: `GP_PUT` — host's pushbuffer producer index.
pub const USERD_GP_PUT: u32 = 0x0000_0040;
/// USERD field offset: `GP_GET` — GPU's pushbuffer consumer index.
pub const USERD_GP_GET: u32 = 0x0000_0044;
/// USERD field offset: `REF` — fence reference.
pub const USERD_REF: u32 = 0x0000_0054;

// ── Pushbuffer command encoding ──────────────────────────────────
//
// Pushbuffer entries are 32-bit words. Each "command" header
// encodes:
//
//   bits[15:0]   method (a register address inside the engine's
//                       class)
//   bits[28:16]  size (in words)
//   bits[31:29]  type (0 = SLI inc, 1 = inc, 3 = non-inc, …)
//
// Cite `nvkm/engine/fifo/gpfifo.c` for the canonical encoder.

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PbType {
    /// Header word is followed by `size` data words; each data
    /// word increments the method address by 4 ("incrementing
    /// write").
    Inc = 1,
    /// Header word followed by `size` data words; method address
    /// is constant ("non-incrementing write" — used for streaming
    /// data registers).
    NonInc = 3,
    /// "Immediate data" header — the method address holds the value
    /// directly, no payload.
    Immd = 4,
}

/// Encode a pushbuffer header word.
pub const fn pb_header(method: u16, size: u16, pb_type: PbType) -> u32 {
    let m = (method as u32) & 0xFFFF;
    let s = ((size as u32) & 0x1FFF) << 16;
    let t = (pb_type as u32) << 29;
    m | s | t
}

/// Bytes per USERD slot (4 KiB).
pub const USERD_SIZE: u64 = 4096;

/// A statically-typed channel handle. Stage 1 only models the
/// shape of the bring-up data; live channel allocation happens
/// when the runtime FIFO comes online.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ChannelDesc {
    pub channel_id: u32,
    /// VRAM phys-addr of the USERD slot.
    pub userd_phys: u64,
    /// VRAM phys-addr of the pushbuffer.
    pub pushbuf_phys: u64,
    /// Number of GP entries in the pushbuffer.
    pub pushbuf_entries: u32,
}

/// Per-family channel-count caps used to size USERD pools. Numbers
/// match Nouveau's per-ASIC `*_fifo.func.runl.runqs` arrays
/// (`nvkm/engine/fifo/runl.c`).
pub const fn channel_cap_for(family: ChipFamily) -> u32 {
    match family {
        ChipFamily::Maxwell => 4096,
        ChipFamily::Pascal => 4096,
        ChipFamily::Volta => 4096,
        ChipFamily::Turing => 4096,
        ChipFamily::Ampere => 4096,
        ChipFamily::Ada => 4096,
        _ => 128,
    }
}
