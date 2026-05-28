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
