//! Maxwell+ display ("NV50 family") — HEAD/SOR register layout +
//! DP AUX framing + mode-set programming sequence (scaffold).
//!
//! ## Reference
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/dispnv50/disp.c`**
//!   — top-level NV50+ display.
//! - **`drivers/gpu/drm/nouveau/dispnv50/head.c`** + per-ASIC
//!   `head*.c` — HEAD (CRTC) register block per family.
//! - **`drivers/gpu/drm/nouveau/dispnv50/dac507d.c`** /
//!   **`sor507d.c`** / **`sorc37d.c`** — SOR (Serial Output
//!   Resource) per family. SOR drives TMDS / DP / LVDS.
//! - **`drivers/gpu/drm/nouveau/dispnv50/disp.c::nv50_dp_train_*`**
//!   — DP AUX + link-training state machine.
//!
//! ## BAR0 offsets (PDISP block)
//!
//! Per `dev_disp.ref.txt` (Turing manual). HEAD0 base = 0x661000;
//! HEAD-stride is 0x400. SOR0 base = 0x612000; SOR-stride is
//! 0x200.

#![allow(dead_code)]

// ── HEAD (CRTC) register block ───────────────────────────────────

/// HEAD bank base in BAR0. Per `dev_disp.ref.txt::NV_PDISP_HEAD`.
pub const PDISP_HEAD_BASE: u64 = 0x0066_1000;
/// Stride between HEAD instances.
pub const PDISP_HEAD_STRIDE: u64 = 0x0000_0400;

/// HEAD register offsets (within a single HEAD bank).
pub const HEAD_TOTAL: u64 = 0x0000_0040;
pub const HEAD_DISPLAY: u64 = 0x0000_0044;
pub const HEAD_SYNC_END: u64 = 0x0000_0048;
pub const HEAD_BLANK_START: u64 = 0x0000_004C;
pub const HEAD_BLANK_END: u64 = 0x0000_0050;
pub const HEAD_SYNC_START: u64 = 0x0000_0054;
pub const HEAD_PIXEL_CLOCK: u64 = 0x0000_0058;
pub const HEAD_VIEWPORT: u64 = 0x0000_0060;
pub const HEAD_SCANOUT_PB: u64 = 0x0000_0080;

/// Base address of HEAD `n`.
pub const fn head_base(n: u8) -> u64 {
    PDISP_HEAD_BASE + (n as u64) * PDISP_HEAD_STRIDE
}

// ── SOR (Serial Output Resource) ─────────────────────────────────

/// SOR bank base.
pub const PDISP_SOR_BASE: u64 = 0x0061_2000;
/// SOR stride.
pub const PDISP_SOR_STRIDE: u64 = 0x0000_0200;

/// SOR register offsets.
pub const SOR_CTL: u64 = 0x0000_0000;
pub const SOR_DP_AUX_CH_CTL: u64 = 0x0000_0050;
pub const SOR_DP_AUX_CH_DATA: u64 = 0x0000_0054;
pub const SOR_DP_LINK_CTL: u64 = 0x0000_0080;

/// Base address of SOR `n`.
pub const fn sor_base(n: u8) -> u64 {
    PDISP_SOR_BASE + (n as u64) * PDISP_SOR_STRIDE
}

// ── DP AUX ───────────────────────────────────────────────────────
//
// Cite `dispnv50/disp.c::nv50_disp_dp_aux_xfer` for the AUX
// command-frame encoding the driver writes into SOR_DP_AUX_CH_CTL
// before pulsing the start bit.

/// AUX command frame (write).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AuxCommand {
    /// I²C-over-AUX read.
    I2cRead,
    /// I²C-over-AUX write.
    I2cWrite,
    /// Native DPCD read.
    DpcdRead,
    /// Native DPCD write.
    DpcdWrite,
}

impl AuxCommand {
    /// Encoded 4-bit command field per DPCD spec.
    pub const fn code(self) -> u8 {
        match self {
            AuxCommand::I2cWrite => 0x0,
            AuxCommand::I2cRead => 0x1,
            AuxCommand::DpcdWrite => 0x8,
            AuxCommand::DpcdRead => 0x9,
        }
    }
}

// ── AUX status codes (DP spec §3.4.1) ────────────────────────────
//
// Cite VESA DP 1.4 §3.4.1: the AUX reply byte holds a 4-bit
// command + 4-bit data. The reply command field is:
//
//   0x0  AUX_ACK    — native DPCD ack
//   0x1  AUX_NACK   — native DPCD nack
//   0x2  AUX_DEFER  — sink wants the master to retry
//   0x4  I2C_ACK    — I²C-over-AUX ack
//   0x5  I2C_NACK   — I²C-over-AUX nack
//   0x6  I2C_DEFER  — I²C-over-AUX retry
//
// Plus a synthetic 0xFF for "no reply / link timeout".

/// AUX command-reply status (decoded from the reply header byte).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AuxReply {
    /// 0x0 — native DPCD ack.
    Ack,
    /// 0x1 — native DPCD nack.
    Nack,
    /// 0x2 — native DPCD defer; master must retry.
    Defer,
    /// 0x4 — I²C-over-AUX ack.
    I2cAck,
    /// 0x5 — I²C-over-AUX nack.
    I2cNack,
    /// 0x6 — I²C-over-AUX defer.
    I2cDefer,
    /// 0xFF (synthetic) — timeout / no reply.
    Timeout,
    /// Reserved / unknown code.
    Unknown(u8),
}

impl AuxReply {
    /// Decode a 4-bit reply nibble.
    pub const fn from_nibble(n: u8) -> Self {
        match n & 0xF {
            0x0 => AuxReply::Ack,
            0x1 => AuxReply::Nack,
            0x2 => AuxReply::Defer,
            0x4 => AuxReply::I2cAck,
            0x5 => AuxReply::I2cNack,
            0x6 => AuxReply::I2cDefer,
            0xF => AuxReply::Timeout,
            x => AuxReply::Unknown(x),
        }
    }

    /// True when the master should retry the same transaction (DP §3.4.1).
    pub const fn should_retry(self) -> bool {
        matches!(self, AuxReply::Defer | AuxReply::I2cDefer)
    }

    /// True when the reply is a success.
    pub const fn is_ok(self) -> bool {
        matches!(self, AuxReply::Ack | AuxReply::I2cAck)
    }

    /// True when the reply is a sink rejection (no retry).
    pub const fn is_nack(self) -> bool {
        matches!(self, AuxReply::Nack | AuxReply::I2cNack)
    }
}

/// Encode the SOR_DP_AUX_CH_CTL header word.
///
/// Layout (per `dev_disp.ref.txt::NV_PDISP_SOR_DP_AUXCTL` and
/// `nvkm/engine/disp/outp.c`):
///
/// ```text
///   bits[3:0]    command (DPCD r/w, I²C r/w)
///   bits[7:4]    reserved
///   bits[27:8]   20-bit address (only [15:0] used for I²C; 20 bits
///                for native DPCD which is the wider space)
///   bits[31:28]  payload-size-minus-1 (1..16 bytes → 0..15)
/// ```
pub const fn aux_header(cmd: AuxCommand, addr: u32, size: u8) -> u32 {
    let c = (cmd.code() as u32) & 0xF;
    let a = (addr & 0x000F_FFFF) << 8;
    let s = ((size.saturating_sub(1) as u32) & 0xF) << 28;
    c | a | s
}

// ── DP link training ─────────────────────────────────────────────
//
// CR (Clock Recovery) + EQ (Equalization) phases. Cite
// `dispnv50/disp.c::nv50_dp_train_cr` / `nv50_dp_train_eq`.

/// Link training states; `Done` ends the state machine.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LtState {
    StartCr,
    PollCr,
    StartEq,
    PollEq,
    Done,
    Failed,
}

/// Voltage swing / pre-emphasis pair. DP spec encodes them as
/// 2 bits each in DPCD register 0x103/0x104/...; `pre_emph` is
/// always ≤ `voltage` (DP spec rule).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LtLevels {
    pub voltage: u8,
    pub pre_emph: u8,
}

// ── Mode-set sequence ────────────────────────────────────────────
//
// Mode-set is a sequence of register writes against the head /
// SOR. Cite `dispnv50/head*.c::*_head_mode` for the per-family
// sequence (this is the call-site that turns a `drm_display_mode`
// into HEAD register words).

/// Encode HEAD_TOTAL — bits[15:0]=h_total, bits[31:16]=v_total.
pub const fn enc_head_total(mode: &crate::disp::Mode) -> u32 {
    (mode.h_total as u32) | ((mode.v_total as u32) << 16)
}

/// Encode HEAD_DISPLAY — bits[15:0]=h_display, bits[31:16]=v_display.
pub const fn enc_head_display(mode: &crate::disp::Mode) -> u32 {
    (mode.h_display as u32) | ((mode.v_display as u32) << 16)
}

/// Encode HEAD_SYNC_START — h-sync-start / v-sync-start pair.
pub const fn enc_head_sync_start(mode: &crate::disp::Mode) -> u32 {
    (mode.h_sync_start as u32) | ((mode.v_sync_start as u32) << 16)
}

/// Encode HEAD_SYNC_END — h-sync-end / v-sync-end.
pub const fn enc_head_sync_end(mode: &crate::disp::Mode) -> u32 {
    (mode.h_sync_end as u32) | ((mode.v_sync_end as u32) << 16)
}

// ── NV507D method ids (per-HEAD) ────────────────────────────────
//
// Cite `/home/daniel/git/linux/drivers/gpu/drm/nouveau/include/
// nvhw/class/cl507d.h`. Each HEAD has a 0x400 stride; the base
// method below is the HEAD(0) offset.

/// NV507D::UPDATE method — kicks the just-staged HEAD state.
pub const NV507D_UPDATE: u16 = 0x0080;
/// NV507D::HEAD_SET_PIXEL_CLOCK(0) — pixel clock + clock mode.
pub const NV507D_HEAD_SET_PIXEL_CLOCK: u16 = 0x0804;
/// NV507D::HEAD_SET_CONTROL(0) — interlace + scanout structure.
pub const NV507D_HEAD_SET_CONTROL: u16 = 0x0808;
/// NV507D::HEAD_SET_OVERSCAN_COLOR(0).
pub const NV507D_HEAD_SET_OVERSCAN_COLOR: u16 = 0x0810;
/// NV507D::HEAD_SET_RASTER_SIZE(0) — htotal + vtotal.
pub const NV507D_HEAD_SET_RASTER_SIZE: u16 = 0x0814;
/// NV507D::HEAD_SET_RASTER_SYNC_END(0).
pub const NV507D_HEAD_SET_RASTER_SYNC_END: u16 = 0x0818;
/// NV507D::HEAD_SET_RASTER_BLANK_END(0).
pub const NV507D_HEAD_SET_RASTER_BLANK_END: u16 = 0x081C;
/// NV507D::HEAD_SET_RASTER_BLANK_START(0).
pub const NV507D_HEAD_SET_RASTER_BLANK_START: u16 = 0x0820;
/// NV507D::HEAD_SET_OFFSET(0,0) — scanout origin.
pub const NV507D_HEAD_SET_OFFSET: u16 = 0x0860;
/// NV507D::HEAD_SET_CONTEXT_DMA_ISO(0) — scanout DMA-handle.
pub const NV507D_HEAD_SET_CONTEXT_DMA_ISO: u16 = 0x0874;

/// HEAD method stride: each HEAD's method base is `BASE + 0x400 * i`.
pub const NV507D_HEAD_STRIDE: u16 = 0x0400;

/// Compute the method id for `method` on HEAD `i`.
pub const fn head_method(base: u16, i: u8) -> u16 {
    base + (i as u16) * NV507D_HEAD_STRIDE
}

// ── PIXEL_CLOCK field encoding ───────────────────────────────────

/// PIXEL_CLOCK.MODE = CLK_CUSTOM (value 0x2 in bits[23:22]). Cite
/// `cl507d.h::NV507D_HEAD_SET_PIXEL_CLOCK_MODE_CLK_CUSTOM`.
pub const PIXEL_CLOCK_MODE_CLK_CUSTOM: u32 = 0x2 << 22;

/// Encode `HEAD_SET_PIXEL_CLOCK`. Layout:
/// - bits[21:0]:   FREQUENCY (kHz)
/// - bits[23:22]:  MODE (CLK_25 / CLK_28 / CLK_CUSTOM)
/// - bit [24]:     ADJ1000DIV1001
/// - bit [25]:     NOT_DRIVER
pub const fn enc_pixel_clock(khz: u32, custom: bool, ntsc_adj: bool) -> u32 {
    let mut v = khz & 0x003F_FFFF;
    if custom {
        v |= PIXEL_CLOCK_MODE_CLK_CUSTOM;
    }
    if ntsc_adj {
        v |= 1 << 24;
    }
    v
}

/// Encode `HEAD_SET_RASTER_SIZE`. Width in bits[14:0], height in
/// bits[30:16].
pub const fn enc_raster_size(w: u16, h: u16) -> u32 {
    ((w as u32) & 0x7FFF) | (((h as u32) & 0x7FFF) << 16)
}

/// Encode `HEAD_SET_RASTER_SYNC_END`. X=hsync_end, Y=vsync_end.
pub const fn enc_raster_sync_end(x: u16, y: u16) -> u32 {
    ((x as u32) & 0x7FFF) | (((y as u32) & 0x7FFF) << 16)
}

/// Encode `HEAD_SET_RASTER_BLANK_END`. X=h_active_start,
/// Y=v_active_start.
pub const fn enc_raster_blank_end(x: u16, y: u16) -> u32 {
    ((x as u32) & 0x7FFF) | (((y as u32) & 0x7FFF) << 16)
}

/// Encode `HEAD_SET_RASTER_BLANK_START`. X=h_blank_start,
/// Y=v_blank_start.
pub const fn enc_raster_blank_start(x: u16, y: u16) -> u32 {
    ((x as u32) & 0x7FFF) | (((y as u32) & 0x7FFF) << 16)
}

// ── Disp channel doorbell ────────────────────────────────────────
//
// Cite `dispnv50/disp.c::nv50_dmac_kick` — the host stages methods
// in the channel's circular pushbuffer, then writes PUT at offset 0
// of the channel-user MMIO window. The hardware fetches between
// GET (offset 0x4) and PUT and dispatches each method/data pair.
//
// On Maxwell+/Pascal/Volta these channels live in the dispclass
// user window mapped via the channel handle; on Turing+ the same
// shape is preserved (NV507C / NVC37C etc inherit PUT at offset 0).

/// PUT pointer offset (within the disp channel user-MMIO window).
pub const DISP_CHAN_PUT: u64 = 0x0000_0000;
/// GET pointer offset (within the disp channel user-MMIO window).
pub const DISP_CHAN_GET: u64 = 0x0000_0004;

/// Convert a host pushbuffer offset (in bytes) to the raw PUT
/// register value. PUT_PTR occupies bits[11:2] (per cl507c.h); the
/// field-value is the word index, so the raw register reads back
/// `byte_offset & 0xFFC` — i.e. the byte offset clamped into the
/// PUT-pointer field. Cite `cl507c.h::NV507C_PUT_PTR` (bits[11:2]).
pub const fn put_value(byte_offset: u32) -> u32 {
    byte_offset & 0x0000_0FFC
}

/// Ring the doorbell — write the new PUT pointer to the channel
/// user-MMIO window. Caller has already staged the methods into the
/// VRAM-backed pushbuffer.
///
/// # Safety
/// `chan_mmio` is the channel's user-MMIO window (kernel-mapped via
/// `MmioRegion`). `byte_offset` must be a multiple of 4 and lie
/// within the pushbuffer the GPU is configured to read.
pub unsafe fn doorbell_kick(chan_mmio: &narf_driver_runtime::MmioRegion, byte_offset: u32) {
    let v = put_value(byte_offset);
    // SAFETY: caller's responsibility.
    unsafe {
        chan_mmio.write32(DISP_CHAN_PUT, v);
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

// ── Live mode-set sequence (HEAD `i`) ────────────────────────────
//
// Mirrors `dispnv50/head507d.c::head507d_mode` — the canonical NV50
// mode-set: PIXEL_CLOCK + CONTROL + OVERSCAN + RASTER_SIZE +
// SYNC_END + BLANK_END + BLANK_START block, followed by UPDATE on
// the disp core. Stage 2 wires this to live MMIO via a `PbBuilder`.
//
// Why one big method block? NV507D coalesces increments — every
// data word after the first auto-increments the method id by 4,
// so a single PUSH_MTHD/data*N block writes consecutive HEAD
// registers in one fetch.

/// HEAD_SET_CONTROL value for progressive (non-interlaced).
pub const HEAD_CONTROL_PROGRESSIVE: u32 = 0;
/// HEAD_SET_CONTROL value for interlaced.
pub const HEAD_CONTROL_INTERLACED: u32 = 1;

/// Stage the head507d-style mode-set into the pushbuffer. Returns
/// the byte offset of the next free slot in the pushbuffer (so the
/// caller can do a doorbell kick or follow-up with UPDATE).
///
/// Cite `head507d_mode` in dispnv50/head507d.c — the staging order
/// is PIXEL_CLOCK / CONTROL, then OVERSCAN_COLOR / RASTER_SIZE /
/// SYNC_END / BLANK_END / BLANK_START as a single inc-method block.
pub fn stage_head_mode(
    pb: &mut crate::pb::PbBuilder<'_>,
    head: u8,
    mode: &crate::disp::Mode,
) -> Result<(), crate::pb::PbError> {
    let pixel_clock = enc_pixel_clock(mode.clock_khz, true, false);
    let control = if mode.flags.interlaced {
        HEAD_CONTROL_INTERLACED
    } else {
        HEAD_CONTROL_PROGRESSIVE
    };
    // First block: PIXEL_CLOCK then CONTROL (consecutive 0x0804 +
    // 0x0808).
    pb.write_inc(
        head_method(NV507D_HEAD_SET_PIXEL_CLOCK, head),
        &[pixel_clock, control],
    )?;
    // Second block: OVERSCAN_COLOR (0) then RASTER_SIZE +
    // SYNC_END + BLANK_END + BLANK_START — five consecutive words
    // starting at OVERSCAN_COLOR.
    pb.write_inc(
        head_method(NV507D_HEAD_SET_OVERSCAN_COLOR, head),
        &[
            0, // OVERSCAN_COLOR — black
            enc_raster_size(mode.h_total, mode.v_total),
            enc_raster_sync_end(mode.h_sync_end, mode.v_sync_end),
            enc_raster_blank_end(mode.h_total - mode.h_display, mode.v_total - mode.v_display),
            enc_raster_blank_start(mode.h_sync_end, mode.v_sync_end),
        ],
    )?;
    Ok(())
}

/// Stage HEAD scanout bind: `HEAD_SET_OFFSET` + `HEAD_SET_CONTEXT_DMA_ISO`.
/// `fb_offset_bytes` is the VRAM byte offset of the framebuffer;
/// NV507D stores it as `offset >> 8` per `head507d_core_set`.
pub fn stage_head_scanout(
    pb: &mut crate::pb::PbBuilder<'_>,
    head: u8,
    fb_offset_bytes: u64,
    dma_handle: u32,
) -> Result<(), crate::pb::PbError> {
    pb.write_inc(
        head_method(NV507D_HEAD_SET_OFFSET, head),
        &[(fb_offset_bytes >> 8) as u32],
    )?;
    pb.write_inc(
        head_method(NV507D_HEAD_SET_CONTEXT_DMA_ISO, head),
        &[dma_handle],
    )?;
    Ok(())
}

/// Stage the disp-core UPDATE that retires the just-staged HEAD
/// state. Cite `core507d_update` in dispnv50/core507d.c.
pub fn stage_update(
    pb: &mut crate::pb::PbBuilder<'_>,
    interlock: u32,
) -> Result<(), crate::pb::PbError> {
    pb.write_inc(NV507D_UPDATE, &[interlock])
}

// ── Live AUX transfer loop (item 2) ──────────────────────────────
//
// Cite `nvkm/subdev/i2c/auxg94.c::g94_i2c_aux_xfer` —
// `auxg94.c::g94_i2c_aux_xfer` does the canonical
// program-then-wait-then-read sequence:
//
// 1. Wait up to 1 ms for any previous transaction to drain.
// 2. Write the 16-byte payload into the channel's data FIFO (4
//    consecutive 32-bit words at +0x00E4C0).
// 3. Programme CTRL with command + address + size.
// 4. Poll up to 2 ms for the transaction to complete (CTRL bit
//    16 clears).
// 5. Read status (+0x00E4E8). On DEFER (`0x000F_0000 == 0x0008`
//    sub-field) retry up to 32 times with 400 µs back-off.
//
// We model the same shape on top of the SOR DP AUX registers we
// already pinned at the top of this module (SOR_DP_AUX_CH_CTL +
// SOR_DP_AUX_CH_DATA). The actual data window on Maxwell+ is at
// SOR_n base + 0x60 (data) / 0x50 (ctrl); the g94 path uses an
// older single-bank layout we re-use for the bit-shape only.
//
// `AuxLoop` is the pure decision module — given an `AuxReply`
// nibble, decide whether to retry (and how long to wait), or
// surface the result. The caller wires the actual MMIO reads /
// writes; the loop is testable in isolation.

/// Software model of the AUX retry+defer loop. Cite
/// `g94_i2c_aux_xfer` for the 32-retry / 400 µs back-off shape.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AuxLoop {
    /// How many DEFER / I2C_DEFER replies we've seen since the
    /// last fresh transaction. Reset when an ACK / NACK arrives.
    pub retries: u8,
    /// Total max retries before giving up. Nouveau picks 32.
    pub max_retries: u8,
    /// Back-off per retry in microseconds.
    pub back_off_us: u16,
}

impl AuxLoop {
    /// Fresh loop with Nouveau's defaults.
    pub const fn new() -> Self {
        Self {
            retries: 0,
            max_retries: 32,
            back_off_us: 400,
        }
    }

    /// Inspect a fresh reply nibble; tell the caller what to do
    /// next.
    pub fn step(&mut self, reply: AuxReply) -> AuxAction {
        if reply.is_ok() {
            return AuxAction::Done;
        }
        if reply.is_nack() {
            return AuxAction::FatalNack;
        }
        if reply.should_retry() {
            if self.retries >= self.max_retries {
                return AuxAction::ExhaustedRetries;
            }
            self.retries = self.retries.saturating_add(1);
            return AuxAction::Backoff(self.back_off_us);
        }
        if reply == AuxReply::Timeout {
            return AuxAction::Timeout;
        }
        AuxAction::FatalNack
    }
}

impl Default for AuxLoop {
    fn default() -> Self {
        Self::new()
    }
}

/// What the caller should do after consuming a reply nibble.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AuxAction {
    /// Transaction completed — caller can read the data buffer.
    Done,
    /// Sink rejected the transaction; do not retry.
    FatalNack,
    /// Sink said DEFER; sleep `n` µs then retry the same
    /// transaction.
    Backoff(u16),
    /// 32 retries exhausted without ACK. Caller should escalate
    /// to a link reset or drop the transfer.
    ExhaustedRetries,
    /// Hardware never replied (synthetic 0xFF). Caller should
    /// treat the link as down.
    Timeout,
}

// ── Live AUX MMIO sequence (g94-style) ───────────────────────────

/// Maxwell+ AUX CTRL bits per `g94_i2c_aux_xfer`.
pub mod aux_ctrl_bits {
    /// CTRL.RESET — reset the AUX channel state machine.
    pub const RESET: u32 = 0x8000_0000;
    /// CTRL.TRANSACT — start transaction.
    pub const TRANSACT: u32 = 0x0001_0000;
    /// CTRL idle-bit mask. Cite g94_i2c_aux_xfer line "0x03010000".
    pub const IDLE_MASK: u32 = 0x0301_0000;
}

/// AUX-channel programming registers, per `g94_i2c_aux_xfer`.
/// `base` is the per-channel offset (5 0x50 strides, ch 0..15).
pub mod aux_chan_regs {
    /// CTRL register offset within AUX channel.
    pub const CTRL: u64 = 0x00E4E4;
    /// STAT register offset within AUX channel.
    pub const STAT: u64 = 0x00E4E8;
    /// ADDR register offset.
    pub const ADDR: u64 = 0x00E4E0;
    /// Data window: 4 consecutive 32-bit words starting at +0x00E4C0
    /// for the write phase, +0x00E4D0 for read.
    pub const DATA_WR: u64 = 0x00E4C0;
    pub const DATA_RD: u64 = 0x00E4D0;
    /// Stride between AUX channels.
    pub const CH_STRIDE: u64 = 0x50;
}

/// Run one live AUX transaction. Caller owns the BAR0 mapping;
/// `channel` is the AUX channel index (0..15).
///
/// Returns the decoded reply (or Timeout). Caller wires the
/// `AuxLoop` around this for retry / defer.
///
/// # Safety
/// `bar0` covers the AUX channel block at `aux_chan_regs::CTRL +
/// channel * CH_STRIDE`. Exclusive access — concurrent callers
/// against the same channel will race the CTRL register.
pub unsafe fn aux_transact_once(
    bar0: &narf_driver_runtime::MmioRegion,
    channel: u8,
    cmd: AuxCommand,
    addr: u32,
    write_data: &[u8],
    size: u8,
) -> AuxReply {
    let base = (channel as u64) * aux_chan_regs::CH_STRIDE;
    // SAFETY: caller's responsibility.
    unsafe {
        // 1. Wait for prior transaction to drain. Caller-bounded
        //    poll — Nouveau picks 1 ms; we re-use the same shape.
        for _ in 0..1000 {
            let ctrl = bar0.read32(aux_chan_regs::CTRL + base);
            if ctrl & aux_ctrl_bits::IDLE_MASK == 0 {
                break;
            }
            core::hint::spin_loop();
        }
        // 2. Stage the write payload (if any).
        if !matches!(cmd, AuxCommand::I2cRead | AuxCommand::DpcdRead) {
            let mut chunks = [0u32; 4];
            for (i, b) in write_data.iter().take(16).enumerate() {
                let w = i / 4;
                let s = (i % 4) * 8;
                chunks[w] |= (*b as u32) << s;
            }
            for (i, w) in chunks.iter().enumerate() {
                bar0.write32(aux_chan_regs::DATA_WR + base + (i as u64) * 4, *w);
            }
        }
        // 3. Programme CTRL: clear lower fields then set
        //    type/size; the value follows g94_i2c_aux_xfer.
        let mut ctrl = bar0.read32(aux_chan_regs::CTRL + base);
        ctrl &= !0x0001_F1FF;
        ctrl |= (cmd.code() as u32) << 12;
        ctrl |= if size > 0 { (size as u32) - 1 } else { 0x100 };
        bar0.write32(aux_chan_regs::ADDR + base, addr);
        // 4. Pulse start: reset → idle → TRANSACT.
        bar0.write32(aux_chan_regs::CTRL + base, aux_ctrl_bits::RESET | ctrl);
        bar0.write32(aux_chan_regs::CTRL + base, ctrl);
        bar0.write32(aux_chan_regs::CTRL + base, aux_ctrl_bits::TRANSACT | ctrl);
        // 5. Poll up to 2 ms for TRANSACT bit to clear.
        let mut completed = false;
        for _ in 0..2000 {
            let c = bar0.read32(aux_chan_regs::CTRL + base);
            if c & aux_ctrl_bits::TRANSACT == 0 {
                completed = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !completed {
            return AuxReply::Timeout;
        }
        // 6. Read status. The reply code lives in bits[19:16].
        let stat = bar0.read32(aux_chan_regs::STAT + base);
        AuxReply::from_nibble(((stat >> 16) & 0xF) as u8)
    }
}

/// Read up to 16 bytes from the AUX read-data window.
///
/// # Safety
/// Same constraints as `aux_transact_once`. Caller has confirmed
/// the prior transaction was a read and completed without error.
pub unsafe fn aux_read_payload(
    bar0: &narf_driver_runtime::MmioRegion,
    channel: u8,
    out: &mut [u8],
) {
    let base = (channel as u64) * aux_chan_regs::CH_STRIDE;
    // SAFETY: caller's responsibility.
    let mut words = [0u32; 4];
    unsafe {
        for (i, w) in words.iter_mut().enumerate() {
            *w = bar0.read32(aux_chan_regs::DATA_RD + base + (i as u64) * 4);
        }
    }
    for (i, b) in out.iter_mut().take(16).enumerate() {
        let w = i / 4;
        let s = (i % 4) * 8;
        *b = ((words[w] >> s) & 0xFF) as u8;
    }
}

/// Full retried AUX transfer. Mirrors `g94_i2c_aux_xfer` —
/// transact, decode reply, retry on DEFER up to `loop_.max_retries`.
///
/// # Safety
/// As for `aux_transact_once`. Caller owns the channel for the
/// duration of the loop.
pub unsafe fn aux_xfer_retry(
    bar0: &narf_driver_runtime::MmioRegion,
    channel: u8,
    cmd: AuxCommand,
    addr: u32,
    write_data: &[u8],
    read_out: &mut [u8],
    size: u8,
) -> Result<AuxReply, AuxAction> {
    let mut lp = AuxLoop::new();
    loop {
        // SAFETY: caller's responsibility.
        let reply = unsafe { aux_transact_once(bar0, channel, cmd, addr, write_data, size) };
        match lp.step(reply) {
            AuxAction::Done => {
                if matches!(cmd, AuxCommand::I2cRead | AuxCommand::DpcdRead) && !read_out.is_empty()
                {
                    // SAFETY: same as above.
                    unsafe { aux_read_payload(bar0, channel, read_out) };
                }
                return Ok(reply);
            }
            AuxAction::FatalNack => return Ok(reply),
            AuxAction::Backoff(_us) => {
                // Caller may add a real udelay; we re-issue the
                // transaction immediately for tests.
                continue;
            }
            other @ (AuxAction::Timeout | AuxAction::ExhaustedRetries) => {
                return Err(other);
            }
        }
    }
}

/// Full mode-set commit: stage the mode + scanout bind + UPDATE into
/// `pb`, then ring the disp doorbell with the new PUT pointer.
///
/// `chan_mmio` is the disp-core channel's user-MMIO window. The
/// pushbuffer (`pb`) is assumed to be backed by VRAM the GPU is
/// configured to read; the returned `Ok` indicates the doorbell has
/// been kicked and the GPU should latch the new mode on the next
/// scanout boundary.
///
/// # Safety
/// `chan_mmio` is mapped + owned exclusively. `pb_byte_base` is the
/// byte offset within the channel's circular pushbuffer where the
/// just-staged commands start; the GPU's GET pointer must be ≤
/// `pb_byte_base` when this is called.
pub unsafe fn live_commit_head_mode(
    chan_mmio: &narf_driver_runtime::MmioRegion,
    pb: &mut crate::pb::PbBuilder<'_>,
    pb_byte_base: u32,
    head: u8,
    mode: &crate::disp::Mode,
    fb_offset_bytes: u64,
    dma_handle: u32,
) -> Result<u32, crate::pb::PbError> {
    let start = pb.len();
    stage_head_mode(pb, head, mode)?;
    stage_head_scanout(pb, head, fb_offset_bytes, dma_handle)?;
    stage_update(pb, 0)?;
    let end_byte_off = pb_byte_base
        .saturating_add((pb.len() - start) as u32)
        .saturating_add(pb_byte_base.checked_sub(pb_byte_base).unwrap_or(0));
    // The doorbell consumer is the byte position of the *next free
    // word*, not the start. The hardware fetches GET..PUT so PUT
    // must be the byte offset past the last staged word.
    let put_offset = pb_byte_base + pb.len() as u32;
    // SAFETY: caller's responsibility.
    unsafe {
        doorbell_kick(chan_mmio, put_offset);
    }
    let _ = end_byte_off;
    Ok(put_offset)
}
