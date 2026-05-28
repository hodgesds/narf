//! SMU 13.0.4 (Phoenix / HawkPoint1) per-version opcode table.
//!
//! SMU 13.0.4 is the power-management firmware variant shipped on
//! Phoenix / HawkPoint1 silicon (PCI 1002:1900, Family 0x1A). The
//! message-id space is completely distinct from SMU 12 (Renoir); even
//! messages that exist on both chips carry different numeric ids.
//!
//! Key differences from SMU 12:
//!   - `GetSmuVersion` is `GetPmfwVersion` (same id 0x02 — only the
//!     name changed; the semantic is identical).
//!   - Clock soft-min / soft-max are per-clock messages (not the
//!     generic SetSoftMinByFreq + clk_id arg that Navi-class uses).
//!   - `PrepareMp1ForUnload` exists (0x0C) — absent on SMU12.
//!   - `AllowGfxOff` / `DisallowGfxOff` at 0x19 / 0x1A
//!     (vs 0x07 / 0x08 on SMU12).
//!   - `SetSoftMinGfxclk` (0x09) and `SetSoftMinSocclkByFreq` (0x24)
//!     are separate messages that don't exist on SMU12.
//!
//! Source: `/drivers/gpu/drm/amd/pm/swsmu/inc/pmfw_if/smu_v13_0_4_ppsmc.h`
//! + `smu_v13_0_4_ppt.c::smu_v13_0_4_message_map`
//! (GPL-2.0-or-later; NARF relicensed 2026-05-20).

use crate::amdgpu_smu::{ClockDomain, PpsmcMsg, SmuError, SmuMmio};
use crate::amdgpu_smu::{send_message_get, send_message_void};

// ── SMU13.0.4 PPSMC_MSG_* opcode values ────────────────────────────

/// `PPSMC_MSG_TestMessage` — echo/responsiveness check (0x01).
pub const V13_MSG_TEST: u32 = 0x01;
/// `PPSMC_MSG_GetPmfwVersion` — firmware version in ARG (0x02).
/// NOTE: same numeric id as SMU12's GetSmuVersion; semantic is identical.
pub const V13_MSG_GET_PMFW_VERSION: u32 = 0x02;
/// `PPSMC_MSG_GetDriverIfVersion` — driver-IF schema version (0x03).
pub const V13_MSG_GET_DRIVER_IF: u32 = 0x03;
/// `PPSMC_MSG_PowerDownVcn` — power-gate VCN (0x06).
pub const V13_MSG_POWER_DOWN_VCN: u32 = 0x06;
/// `PPSMC_MSG_PowerUpVcn` — wake VCN (0x07).
pub const V13_MSG_POWER_UP_VCN: u32 = 0x07;
/// `PPSMC_MSG_SetSoftMinGfxclk` — soft-min GFXCLK in MHz (0x09).
pub const V13_MSG_SET_SOFT_MIN_GFXCLK: u32 = 0x09;
/// `PPSMC_MSG_PrepareMp1ForUnload` — quiesce before driver unload (0x0C).
pub const V13_MSG_PREPARE_MP1_UNLOAD: u32 = 0x0C;
/// `PPSMC_MSG_SetDriverDramAddrHigh` — DRAM address high 32 bits (0x0D).
pub const V13_MSG_SET_DRAM_ADDR_HI: u32 = 0x0D;
/// `PPSMC_MSG_SetDriverDramAddrLow` — DRAM address low 32 bits (0x0E).
pub const V13_MSG_SET_DRAM_ADDR_LO: u32 = 0x0E;
/// `PPSMC_MSG_TransferTableSmu2Dram` — SMU table → host DRAM (0x0F).
pub const V13_MSG_XFER_SMU2DRAM: u32 = 0x0F;
/// `PPSMC_MSG_TransferTableDram2Smu` — host DRAM → SMU table (0x10).
pub const V13_MSG_XFER_DRAM2SMU: u32 = 0x10;
/// `PPSMC_MSG_GetGfxclkFrequency` — current GFXCLK in MHz (0x17).
pub const V13_MSG_GET_GFXCLK: u32 = 0x17;
/// `PPSMC_MSG_GetFclkFrequency` — current FCLK in MHz (0x18).
pub const V13_MSG_GET_FCLK: u32 = 0x18;
/// `PPSMC_MSG_AllowGfxOff` — allow GFXOFF entry (0x19).
pub const V13_MSG_ALLOW_GFX_OFF: u32 = 0x19;
/// `PPSMC_MSG_DisallowGfxOff` — disallow GFXOFF entry (0x1A).
pub const V13_MSG_DISALLOW_GFX_OFF: u32 = 0x1A;
/// `PPSMC_MSG_SetSoftMaxGfxClk` — soft-max GFXCLK in MHz (0x1B).
pub const V13_MSG_SET_SOFT_MAX_GFXCLK: u32 = 0x1B;
/// `PPSMC_MSG_SetHardMinGfxClk` — hard-min GFXCLK in MHz (0x1C).
pub const V13_MSG_SET_HARD_MIN_GFXCLK: u32 = 0x1C;
/// `PPSMC_MSG_SetSoftMaxSocclkByFreq` — soft-max SOCCLK in MHz (0x1D).
pub const V13_MSG_SET_SOFT_MAX_SOCCLK: u32 = 0x1D;
/// `PPSMC_MSG_SetSoftMaxFclkByFreq` — soft-max FCLK in MHz (0x1E).
pub const V13_MSG_SET_SOFT_MAX_FCLK: u32 = 0x1E;
/// `PPSMC_MSG_SetHardMinFclkByFreq` — hard-min FCLK in MHz (0x23).
pub const V13_MSG_SET_HARD_MIN_FCLK: u32 = 0x23;
/// `PPSMC_MSG_SetSoftMinSocclkByFreq` — soft-min SOCCLK in MHz (0x24).
pub const V13_MSG_SET_SOFT_MIN_SOCCLK: u32 = 0x24;
/// `PPSMC_MSG_SetHardMinSocclkByFreq` — hard-min SOCCLK in MHz (0x13).
pub const V13_MSG_SET_HARD_MIN_SOCCLK: u32 = 0x13;
/// `PPSMC_MSG_SetSoftMinFclk` — soft-min FCLK in MHz (0x14).
pub const V13_MSG_SET_SOFT_MIN_FCLK: u32 = 0x14;

// ── Per-version opcode lookup ───────────────────────────────────────

/// Translate a canonical [`PpsmcMsg`] to its SMU 13.0.4 numeric id.
/// Returns `None` for messages not supported on this version.
///
/// References:
/// - `smu_v13_0_4_ppt.c::smu_v13_0_4_message_map` (MSG_MAP table).
/// - `smu_v13_0_4_ppsmc.h` for the numeric ids.
pub fn msg_id(msg: PpsmcMsg) -> Option<u32> {
    match msg {
        PpsmcMsg::TestMessage => Some(V13_MSG_TEST),
        PpsmcMsg::GetSmuVersion => Some(V13_MSG_GET_PMFW_VERSION),
        PpsmcMsg::GetDriverIfVersion => Some(V13_MSG_GET_DRIVER_IF),
        PpsmcMsg::GetGfxclkFrequency => Some(V13_MSG_GET_GFXCLK),
        PpsmcMsg::GetFclkFrequency => Some(V13_MSG_GET_FCLK),
        PpsmcMsg::SetSoftMinGfxclk => Some(V13_MSG_SET_SOFT_MIN_GFXCLK),
        PpsmcMsg::SetSoftMaxGfxClk => Some(V13_MSG_SET_SOFT_MAX_GFXCLK),
        PpsmcMsg::SetHardMinGfxClk => Some(V13_MSG_SET_HARD_MIN_GFXCLK),
        PpsmcMsg::SetSoftMinFclk => Some(V13_MSG_SET_SOFT_MIN_FCLK),
        PpsmcMsg::SetSoftMaxFclk => Some(V13_MSG_SET_SOFT_MAX_FCLK),
        PpsmcMsg::SetHardMinFclk => Some(V13_MSG_SET_HARD_MIN_FCLK),
        PpsmcMsg::SetSoftMinSocclk => Some(V13_MSG_SET_SOFT_MIN_SOCCLK),
        PpsmcMsg::SetSoftMaxSocclk => Some(V13_MSG_SET_SOFT_MAX_SOCCLK),
        PpsmcMsg::AllowGfxOff => Some(V13_MSG_ALLOW_GFX_OFF),
        PpsmcMsg::DisallowGfxOff => Some(V13_MSG_DISALLOW_GFX_OFF),
        PpsmcMsg::PrepareMp1ForUnload => Some(V13_MSG_PREPARE_MP1_UNLOAD),
        PpsmcMsg::SetDriverDramAddrHigh => Some(V13_MSG_SET_DRAM_ADDR_HI),
        PpsmcMsg::SetDriverDramAddrLow => Some(V13_MSG_SET_DRAM_ADDR_LO),
        PpsmcMsg::TransferTableSmu2Dram => Some(V13_MSG_XFER_SMU2DRAM),
        PpsmcMsg::TransferTableDram2Smu => Some(V13_MSG_XFER_DRAM2SMU),
        // SMU13 doesn't have a standalone PowerUpGfx (GFX-off is
        // controlled entirely through AllowGfxOff / DisallowGfxOff).
        PpsmcMsg::PowerUpGfx => None,
    }
}

// ── SMU13 clock-domain helpers ──────────────────────────────────────

/// Return the SMU13.0.4 message id to query the current frequency for
/// `domain`, or `None` if queried via the shared-table path instead.
pub fn get_current_clk_msg(domain: ClockDomain) -> Option<u32> {
    match domain {
        ClockDomain::Gfxclk => Some(V13_MSG_GET_GFXCLK),
        ClockDomain::Fclk => Some(V13_MSG_GET_FCLK),
        // SOCCLK, UCLK, VCLK, DCLK — read from the metrics table.
        ClockDomain::Socclk | ClockDomain::Uclk | ClockDomain::Vclk | ClockDomain::Dclk => None,
    }
}

/// Return the SMU13.0.4 message ids for setting soft min / soft max on
/// `domain`. Returns `(set_min_msg, set_max_msg)`.
pub fn set_range_msgs(domain: ClockDomain) -> Option<(u32, u32)> {
    match domain {
        ClockDomain::Gfxclk => Some((V13_MSG_SET_SOFT_MIN_GFXCLK, V13_MSG_SET_SOFT_MAX_GFXCLK)),
        ClockDomain::Fclk => Some((V13_MSG_SET_SOFT_MIN_FCLK, V13_MSG_SET_SOFT_MAX_FCLK)),
        ClockDomain::Socclk => Some((V13_MSG_SET_SOFT_MIN_SOCCLK, V13_MSG_SET_SOFT_MAX_SOCCLK)),
        ClockDomain::Uclk | ClockDomain::Vclk | ClockDomain::Dclk => None,
    }
}

// ── High-level wrappers ─────────────────────────────────────────────

/// Read the current GFXCLK frequency in MHz on SMU13.0.4 hardware.
pub fn get_gfxclk_mhz<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
) -> Result<u32, SmuError> {
    send_message_get(mmio, mp1_base, V13_MSG_GET_GFXCLK, 0)
}

/// Read the current FCLK frequency in MHz on SMU13.0.4 hardware.
pub fn get_fclk_mhz<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
) -> Result<u32, SmuError> {
    send_message_get(mmio, mp1_base, V13_MSG_GET_FCLK, 0)
}

/// Set soft-min GFXCLK to `freq_mhz` on SMU13.0.4.
pub fn set_soft_min_gfxclk<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
    freq_mhz: u32,
) -> Result<(), SmuError> {
    send_message_void(mmio, mp1_base, V13_MSG_SET_SOFT_MIN_GFXCLK, freq_mhz)
}

/// Set soft-max GFXCLK to `freq_mhz` on SMU13.0.4.
pub fn set_soft_max_gfxclk<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
    freq_mhz: u32,
) -> Result<(), SmuError> {
    send_message_void(mmio, mp1_base, V13_MSG_SET_SOFT_MAX_GFXCLK, freq_mhz)
}

/// Set soft-min FCLK to `freq_mhz` on SMU13.0.4.
pub fn set_soft_min_fclk<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
    freq_mhz: u32,
) -> Result<(), SmuError> {
    send_message_void(mmio, mp1_base, V13_MSG_SET_SOFT_MIN_FCLK, freq_mhz)
}

/// Set soft-max FCLK to `freq_mhz` on SMU13.0.4.
pub fn set_soft_max_fclk<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
    freq_mhz: u32,
) -> Result<(), SmuError> {
    send_message_void(mmio, mp1_base, V13_MSG_SET_SOFT_MAX_FCLK, freq_mhz)
}
