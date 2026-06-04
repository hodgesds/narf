//! SMU 12.0 (Renoir / Lucienne / Cezanne) per-version opcode table.
//!
//! The PPSMC message-id space is per-silicon-family. SMU 12 (Renoir)
//! defines its own numbering that differs from SMU 13 (Phoenix) even
//! for logically identical operations (e.g. GetSmuVersion is 0x02 on
//! both, but SetSoftMin* live at completely different ids).
//!
//! Source: `/drivers/gpu/drm/amd/pm/swsmu/inc/pmfw_if/smu_v12_0_ppsmc.h`
//! (GPL-2.0-or-later; NARF relicensed 2026-05-20).

use crate::amdgpu_smu::{send_message_get, send_message_void};
use crate::amdgpu_smu::{ClockDomain, PpsmcMsg, SmuError, SmuMmio};

// ── SMU12 PPSMC_MSG_* opcode values ────────────────────────────────
//
// Source: smu_v12_0_ppsmc.h MSG definitions (in order).

/// `PPSMC_MSG_TestMessage` — echo/responsiveness check (0x01).
pub const V12_MSG_TEST: u32 = 0x01;
/// `PPSMC_MSG_GetSmuVersion` — firmware version in ARG after OK (0x02).
pub const V12_MSG_GET_SMU_VERSION: u32 = 0x02;
/// `PPSMC_MSG_GetDriverIfVersion` — driver-IF schema version (0x03).
pub const V12_MSG_GET_DRIVER_IF: u32 = 0x03;
/// `PPSMC_MSG_PowerUpGfx` — wake GFX block (0x06).
pub const V12_MSG_POWER_UP_GFX: u32 = 0x06;
/// `PPSMC_MSG_EnableGfxOff` — gate GFX-off heuristic (0x07).
pub const V12_MSG_ENABLE_GFX_OFF: u32 = 0x07;
/// `PPSMC_MSG_DisableGfxOff` — un-gate GFX-off heuristic (0x08).
pub const V12_MSG_DISABLE_GFX_OFF: u32 = 0x08;
/// `PPSMC_MSG_PowerDownVcn` — power-gate VCN (0x0B).
pub const V12_MSG_POWER_DOWN_VCN: u32 = 0x0B;
/// `PPSMC_MSG_PowerUpVcn` — wake VCN (0x0C).
pub const V12_MSG_POWER_UP_VCN: u32 = 0x0C;
/// `PPSMC_MSG_SetDriverDramAddrHigh` — DRAM address high 32 bits (0x1A).
pub const V12_MSG_SET_DRAM_ADDR_HI: u32 = 0x1A;
/// `PPSMC_MSG_SetDriverDramAddrLow` — DRAM address low 32 bits (0x1B).
pub const V12_MSG_SET_DRAM_ADDR_LO: u32 = 0x1B;
/// `PPSMC_MSG_TransferTableSmu2Dram` — SMU table → host DRAM (0x1C).
pub const V12_MSG_XFER_SMU2DRAM: u32 = 0x1C;
/// `PPSMC_MSG_TransferTableDram2Smu` — host DRAM → SMU table (0x1D).
pub const V12_MSG_XFER_DRAM2SMU: u32 = 0x1D;
/// `PPSMC_MSG_GetGfxclkFrequency` — current GFX clock in MHz (0x2A).
pub const V12_MSG_GET_GFXCLK: u32 = 0x2A;
/// `PPSMC_MSG_GetFclkFrequency` — current FCLK in MHz (0x2B).
pub const V12_MSG_GET_FCLK: u32 = 0x2B;
/// `PPSMC_MSG_GetMinGfxclkFrequency` — minimum GFXCLK DPM level (0x2C).
pub const V12_MSG_GET_MIN_GFXCLK: u32 = 0x2C;
/// `PPSMC_MSG_GetMaxGfxclkFrequency` — maximum GFXCLK DPM level (0x2D).
pub const V12_MSG_GET_MAX_GFXCLK: u32 = 0x2D;
/// `PPSMC_MSG_SetSoftMaxGfxClk` — soft-max GFXCLK in MHz (0x30).
pub const V12_MSG_SET_SOFT_MAX_GFXCLK: u32 = 0x30;
/// `PPSMC_MSG_SetHardMinGfxClk` — hard-min GFXCLK in MHz (0x31).
pub const V12_MSG_SET_HARD_MIN_GFXCLK: u32 = 0x31;
/// `PPSMC_MSG_SetSoftMaxSocclkByFreq` — soft-max SOCCLK in MHz (0x32).
pub const V12_MSG_SET_SOFT_MAX_SOCCLK: u32 = 0x32;
/// `PPSMC_MSG_SetSoftMaxFclkByFreq` — soft-max FCLK in MHz (0x33).
pub const V12_MSG_SET_SOFT_MAX_FCLK: u32 = 0x33;
/// `PPSMC_MSG_PowerGateMmHub` — power-gate MM hub (0x35).
pub const V12_MSG_POWER_GATE_MMHUB: u32 = 0x35;
/// `PPSMC_MSG_SetHardMinFclkByFreq` — hard-min FCLK in MHz (0x3F).
pub const V12_MSG_SET_HARD_MIN_FCLK: u32 = 0x3F;

// ── Per-version opcode lookup ───────────────────────────────────────

/// Translate a canonical [`PpsmcMsg`] to its SMU 12 numeric id.
/// Returns `None` for messages not supported on this version.
///
/// References:
/// - `renoir_ppt.c::renoir_message_map` for the MSG_MAP table.
/// - `smu_v12_0_ppsmc.h` for the numeric ids.
pub fn msg_id(msg: PpsmcMsg) -> Option<u32> {
    match msg {
        PpsmcMsg::TestMessage => Some(V12_MSG_TEST),
        PpsmcMsg::GetSmuVersion => Some(V12_MSG_GET_SMU_VERSION),
        PpsmcMsg::GetDriverIfVersion => Some(V12_MSG_GET_DRIVER_IF),
        PpsmcMsg::GetGfxclkFrequency => Some(V12_MSG_GET_GFXCLK),
        PpsmcMsg::GetFclkFrequency => Some(V12_MSG_GET_FCLK),
        PpsmcMsg::SetSoftMaxGfxClk => Some(V12_MSG_SET_SOFT_MAX_GFXCLK),
        PpsmcMsg::SetHardMinGfxClk => Some(V12_MSG_SET_HARD_MIN_GFXCLK),
        PpsmcMsg::SetSoftMaxSocclk => Some(V12_MSG_SET_SOFT_MAX_SOCCLK),
        PpsmcMsg::SetSoftMaxFclk => Some(V12_MSG_SET_SOFT_MAX_FCLK),
        PpsmcMsg::SetHardMinFclk => Some(V12_MSG_SET_HARD_MIN_FCLK),
        PpsmcMsg::PowerUpGfx => Some(V12_MSG_POWER_UP_GFX),
        PpsmcMsg::AllowGfxOff => Some(V12_MSG_ENABLE_GFX_OFF),
        PpsmcMsg::DisallowGfxOff => Some(V12_MSG_DISABLE_GFX_OFF),
        PpsmcMsg::SetDriverDramAddrHigh => Some(V12_MSG_SET_DRAM_ADDR_HI),
        PpsmcMsg::SetDriverDramAddrLow => Some(V12_MSG_SET_DRAM_ADDR_LO),
        PpsmcMsg::TransferTableSmu2Dram => Some(V12_MSG_XFER_SMU2DRAM),
        PpsmcMsg::TransferTableDram2Smu => Some(V12_MSG_XFER_DRAM2SMU),
        // SMU12 has no soft-min Gfxclk message (it uses SetHardMinGfxClk).
        PpsmcMsg::SetSoftMinGfxclk => None,
        // SMU12 has no soft-min SOCCLK (use hard-min path if needed).
        PpsmcMsg::SetSoftMinSocclk => None,
        // SMU12 has no soft-min FCLK separate message (use SetMinVideoFclkFreq
        // internally, but we don't expose that variant).
        PpsmcMsg::SetSoftMinFclk => None,
        PpsmcMsg::PrepareMp1ForUnload => None,
    }
}

// ── SMU12 clock-domain helpers ──────────────────────────────────────

/// Return the SMU12 PPSMC message id to query the *current* frequency
/// for `domain`, and whether the arg register holds the frequency on
/// return (`true`) or the message has no return value (`false`).
///
/// SMU12 (Renoir) does **not** have a single `GetCurrentClock(clk_id)`
/// message; each clock domain gets its own dedicated GET message.
pub fn get_current_clk_msg(domain: ClockDomain) -> Option<u32> {
    match domain {
        ClockDomain::Gfxclk => Some(V12_MSG_GET_GFXCLK),
        ClockDomain::Fclk => Some(V12_MSG_GET_FCLK),
        // Renoir doesn't expose standalone SOCCLK / UCLK current-freq
        // messages; callers need the shared-table transfer for those.
        ClockDomain::Socclk | ClockDomain::Uclk | ClockDomain::Vclk | ClockDomain::Dclk => None,
    }
}

/// Return the SMU12 message ids for setting soft min / soft max on
/// `domain`. Renoir has per-domain dedicated messages rather than a
/// generic (msg, clk_id_arg) pair.
pub fn set_range_msgs(domain: ClockDomain) -> Option<(u32, u32)> {
    // Returns (set_soft_min_msg, set_soft_max_msg).
    match domain {
        ClockDomain::Gfxclk => {
            // SMU12 uses SetHardMinGfxClk as the effective lower floor;
            // SetSoftMax is the upper cap.
            Some((V12_MSG_SET_HARD_MIN_GFXCLK, V12_MSG_SET_SOFT_MAX_GFXCLK))
        }
        ClockDomain::Fclk => Some((V12_MSG_SET_HARD_MIN_FCLK, V12_MSG_SET_SOFT_MAX_FCLK)),
        ClockDomain::Socclk => {
            // SMU12: SetHardMinSocclkByFreq + SetSoftMaxSocclkByFreq.
            // The hard-min id (0x21) is sourced from smu_v12_0_ppsmc.h.
            Some((0x21, V12_MSG_SET_SOFT_MAX_SOCCLK))
        }
        ClockDomain::Uclk | ClockDomain::Vclk | ClockDomain::Dclk => None,
    }
}

// ── High-level wrappers ─────────────────────────────────────────────

/// Read the current GFXCLK frequency in MHz on SMU12 hardware.
pub fn get_gfxclk_mhz<M: SmuMmio>(mmio: &mut M, mp1_base: u32) -> Result<u32, SmuError> {
    send_message_get(mmio, mp1_base, V12_MSG_GET_GFXCLK, 0)
}

/// Read the current FCLK frequency in MHz on SMU12 hardware.
pub fn get_fclk_mhz<M: SmuMmio>(mmio: &mut M, mp1_base: u32) -> Result<u32, SmuError> {
    send_message_get(mmio, mp1_base, V12_MSG_GET_FCLK, 0)
}

/// Set soft-max GFXCLK to `freq_mhz` on SMU12.
pub fn set_soft_max_gfxclk<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
    freq_mhz: u32,
) -> Result<(), SmuError> {
    send_message_void(mmio, mp1_base, V12_MSG_SET_SOFT_MAX_GFXCLK, freq_mhz)
}

/// Set hard-min GFXCLK to `freq_mhz` on SMU12.
pub fn set_hard_min_gfxclk<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
    freq_mhz: u32,
) -> Result<(), SmuError> {
    send_message_void(mmio, mp1_base, V12_MSG_SET_HARD_MIN_GFXCLK, freq_mhz)
}

/// Set soft-max FCLK to `freq_mhz` on SMU12.
pub fn set_soft_max_fclk<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
    freq_mhz: u32,
) -> Result<(), SmuError> {
    send_message_void(mmio, mp1_base, V12_MSG_SET_SOFT_MAX_FCLK, freq_mhz)
}

/// Set hard-min FCLK to `freq_mhz` on SMU12.
pub fn set_hard_min_fclk<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
    freq_mhz: u32,
) -> Result<(), SmuError> {
    send_message_void(mmio, mp1_base, V12_MSG_SET_HARD_MIN_FCLK, freq_mhz)
}
