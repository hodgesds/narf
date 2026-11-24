//! SMU 13.0.0 (Navi31 / Navi32 / Navi33 discrete, MP1 13.0.0) per-version
//! opcode table.
//!
//! SMU 13.0.0 is the power-management firmware variant shipped on the
//! RDNA3 discrete dies (Navi31 GC 11.0.0, Navi32 GC 11.0.3, Navi33 GC
//! 11.0.2). Its message-id space is completely distinct from SMU 13.0.4
//! (Phoenix) — even messages that exist on both chips carry different
//! numeric ids, and the two generations share no message space.
//!
//! Key differences from SMU 13.0.4 (`amdgpu_smu_v13.rs`):
//!   - Clock soft-min / soft-max are the generic `SetSoftMinByFreq` /
//!     `SetSoftMaxByFreq` messages (0x19 / 0x1A) with a PPCLK clock-id
//!     argument — not the per-clock messages 13.0.4 uses. The PPCLK_*
//!     enum itself is NOT in `smu_v13_0_0_ppsmc.h`, so no by-frequency
//!     range helper is offered here: the clock ids need grounding from
//!     the 13.0.0 pptable / driver-if headers first (DPM lane).
//!   - `AllowGfxOff` / `DisallowGfxOff` are 0x28 / 0x29 (vs 0x19 / 0x1A
//!     on 13.0.4). This is the exact confusion the `amdgpu_dpm.rs`
//!     LINUX-GAP comment documents: the five 13.0.0 ids 0x19–0x1C + 0x24
//!     are correct for 13.0.0 and mean something else on Phoenix.
//!   - There is no `LoadMicrocode` message at all: Linux's
//!     `smu_v13_0_load_microcode` is `#if 0` and the PMFW is PSP-loaded
//!     (`AMDGPU_FW_LOAD_PSP`). Never route `smu_13_0_0.bin` through
//!     `amdgpu_smu::load_pmfw` — its message id 0x02 is `GetSmuVersion`
//!     on 13.0.0.
//!   - `GetSmuVersion` is 0x02 (same id as 13.0.4's `GetPmfwVersion`;
//!     only the name changed; the semantic is identical).
//!   - `PPSMC_Message_Count` is 0x52 (vs 0x31 on 13.0.4).
//!
//! Source: `/drivers/gpu/drm/amd/pm/swsmu/inc/pmfw_if/smu_v13_0_0_ppsmc.h`
//! + `smu_v13_0_0_ppt.c::smu_v13_0_0_message_map`
//!
//! (GPL-2.0-or-later; NARF relicensed 2026-05-20).

use crate::amdgpu_smu::PpsmcMsg;

// ── SMU13.0.0 PPSMC_MSG_* opcode values ────────────────────────────

/// `PPSMC_MSG_TestMessage` — echo/responsiveness check (0x01).
pub const V13_0_0_MSG_TEST: u32 = 0x01;
/// `PPSMC_MSG_GetSmuVersion` — firmware version in ARG (0x02).
/// NOTE: same numeric id as SMU 13.0.4's GetPmfwVersion; semantic is identical.
pub const V13_0_0_MSG_GET_SMU_VERSION: u32 = 0x02;
/// `PPSMC_MSG_GetDriverIfVersion` — driver-IF schema version (0x03).
pub const V13_0_0_MSG_GET_DRIVER_IF: u32 = 0x03;
/// `PPSMC_MSG_SetDriverDramAddrHigh` — DRAM address high 32 bits (0x0E).
pub const V13_0_0_MSG_SET_DRAM_ADDR_HI: u32 = 0x0E;
/// `PPSMC_MSG_SetDriverDramAddrLow` — DRAM address low 32 bits (0x0F).
pub const V13_0_0_MSG_SET_DRAM_ADDR_LO: u32 = 0x0F;
/// `PPSMC_MSG_TransferTableSmu2Dram` — SMU table → host DRAM (0x12).
pub const V13_0_0_MSG_XFER_SMU2DRAM: u32 = 0x12;
/// `PPSMC_MSG_TransferTableDram2Smu` — host DRAM → SMU table (0x13).
pub const V13_0_0_MSG_XFER_DRAM2SMU: u32 = 0x13;
/// `PPSMC_MSG_UseDefaultPPTable` — load the default powerplay table (0x14).
pub const V13_0_0_MSG_USE_DEFAULT_PP_TABLE: u32 = 0x14;
/// `PPSMC_MSG_SetSoftMinByFreq` — soft-min for a clock id (0x19).
/// Argument packs `(freq_mhz << 16) | clk_id`; the PPCLK_* clock ids are
/// not in `smu_v13_0_0_ppsmc.h` (see the module docs).
pub const V13_0_0_MSG_SET_SOFT_MIN_BY_FREQ: u32 = 0x19;
/// `PPSMC_MSG_SetSoftMaxByFreq` — soft-max for a clock id (0x1A).
pub const V13_0_0_MSG_SET_SOFT_MAX_BY_FREQ: u32 = 0x1A;
/// `PPSMC_MSG_SetHardMinByFreq` — hard-min for a clock id (0x1B).
pub const V13_0_0_MSG_SET_HARD_MIN_BY_FREQ: u32 = 0x1B;
/// `PPSMC_MSG_SetHardMaxByFreq` — hard-max for a clock id (0x1C).
pub const V13_0_0_MSG_SET_HARD_MAX_BY_FREQ: u32 = 0x1C;
/// `PPSMC_MSG_GetMinDpmFreq` — lowest DPM-level freq for a clock id (0x1D).
pub const V13_0_0_MSG_GET_MIN_DPM_FREQ: u32 = 0x1D;
/// `PPSMC_MSG_GetMaxDpmFreq` — highest DPM-level freq for a clock id (0x1E).
pub const V13_0_0_MSG_GET_MAX_DPM_FREQ: u32 = 0x1E;
/// `PPSMC_MSG_GetDpmFreqByIndex` — DPM-level → freq map for a clock id (0x1F).
pub const V13_0_0_MSG_GET_DPM_FREQ_BY_INDEX: u32 = 0x1F;
/// `PPSMC_MSG_SetWorkloadMask` — workload hint bitmask (0x24).
pub const V13_0_0_MSG_SET_WORKLOAD_MASK: u32 = 0x24;
/// `PPSMC_MSG_AllowGfxOff` — allow GFXOFF entry (0x28).
/// NOT 0x19: that is `SetSoftMinByFreq` here and `AllowGfxOff` on 13.0.4.
pub const V13_0_0_MSG_ALLOW_GFX_OFF: u32 = 0x28;
/// `PPSMC_MSG_DisallowGfxOff` — disallow GFXOFF entry (0x29).
pub const V13_0_0_MSG_DISALLOW_GFX_OFF: u32 = 0x29;
/// `PPSMC_MSG_PowerUpVcn` — wake VCN (0x2A).
pub const V13_0_0_MSG_POWER_UP_VCN: u32 = 0x2A;
/// `PPSMC_MSG_PowerDownVcn` — power-gate VCN (0x2B).
pub const V13_0_0_MSG_POWER_DOWN_VCN: u32 = 0x2B;
/// `PPSMC_MSG_PowerUpJpeg` — wake JPEG (0x2C).
pub const V13_0_0_MSG_POWER_UP_JPEG: u32 = 0x2C;
/// `PPSMC_MSG_PowerDownJpeg` — power-gate JPEG (0x2D).
pub const V13_0_0_MSG_POWER_DOWN_JPEG: u32 = 0x2D;
/// `PPSMC_MSG_PrepareMp1ForUnload` — quiesce before driver unload (0x2E).
pub const V13_0_0_MSG_PREPARE_MP1_UNLOAD: u32 = 0x2E;
/// `PPSMC_MSG_Mode1Reset` — full GPU reset (0x2F).
pub const V13_0_0_MSG_MODE1_RESET: u32 = 0x2F;

/// `PPSMC_Message_Count` — one past the last message id (0x52).
/// Anything at or above it is not a message.
pub const V13_0_0_MSG_COUNT: u32 = 0x52;

// ── Per-version opcode lookup ───────────────────────────────────────

/// Translate a canonical [`PpsmcMsg`] to its SMU 13.0.0 numeric id.
/// Returns `None` for messages not supported on this version.
///
/// The per-clock variants all return `None`: 13.0.0 has no per-clock
/// messages, only the generic `*ByFreq` set (0x19–0x1F) with a PPCLK
/// clock-id argument, and the clock ids are not grounded yet (see the
/// module docs). Callers that need a clock range must go through the
/// `V13_0_0_MSG_SET_*_BY_FREQ` constants with a grounded clock id.
///
/// References:
/// - `smu_v13_0_0_ppt.c::smu_v13_0_0_message_map` (MSG_MAP table).
/// - `smu_v13_0_0_ppsmc.h` for the numeric ids.
pub fn msg_id(msg: PpsmcMsg) -> Option<u32> {
    match msg {
        PpsmcMsg::TestMessage => Some(V13_0_0_MSG_TEST),
        PpsmcMsg::GetSmuVersion => Some(V13_0_0_MSG_GET_SMU_VERSION),
        PpsmcMsg::GetDriverIfVersion => Some(V13_0_0_MSG_GET_DRIVER_IF),
        PpsmcMsg::AllowGfxOff => Some(V13_0_0_MSG_ALLOW_GFX_OFF),
        PpsmcMsg::DisallowGfxOff => Some(V13_0_0_MSG_DISALLOW_GFX_OFF),
        PpsmcMsg::PrepareMp1ForUnload => Some(V13_0_0_MSG_PREPARE_MP1_UNLOAD),
        PpsmcMsg::SetDriverDramAddrHigh => Some(V13_0_0_MSG_SET_DRAM_ADDR_HI),
        PpsmcMsg::SetDriverDramAddrLow => Some(V13_0_0_MSG_SET_DRAM_ADDR_LO),
        PpsmcMsg::TransferTableSmu2Dram => Some(V13_0_0_MSG_XFER_SMU2DRAM),
        PpsmcMsg::TransferTableDram2Smu => Some(V13_0_0_MSG_XFER_DRAM2SMU),
        // No per-clock messages on 13.0.0 (generic *ByFreq set instead).
        PpsmcMsg::GetGfxclkFrequency
        | PpsmcMsg::GetFclkFrequency
        | PpsmcMsg::SetSoftMinGfxclk
        | PpsmcMsg::SetSoftMaxGfxClk
        | PpsmcMsg::SetHardMinGfxClk
        | PpsmcMsg::SetSoftMinFclk
        | PpsmcMsg::SetSoftMaxFclk
        | PpsmcMsg::SetHardMinFclk
        | PpsmcMsg::SetSoftMinSocclk
        | PpsmcMsg::SetSoftMaxSocclk => None,
        // SMU13 doesn't have a standalone PowerUpGfx (GFX-off is
        // controlled entirely through AllowGfxOff / DisallowGfxOff).
        PpsmcMsg::PowerUpGfx => None,
    }
}
