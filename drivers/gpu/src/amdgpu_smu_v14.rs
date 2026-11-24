//! SMU 14.0.1 (Strix Point) per-version opcode table.
//!
//! SMU 14.0.1 is the power-management firmware variant shipped on Strix
//! Point silicon (PCI 1002:150E, GFX 11.5.0, DCN 3.5). MP1 14.0.1 uses the
//! v14_0_0 message table: Linux's `amdgpu_discovery.c` MP1 switch maps
//! IP_VERSION(14,0,0/1/2/3/4/5) to `smu_v14_0_ip_block`, and
//! `smu_set_funcs` maps MP1 14.0.0 / 14.0.1 / 14.0.4 / 14.0.5 to
//! `smu_v14_0_0_set_ppt_funcs`, whose `init_msg_ctl` installs
//! `smu_v14_0_0_message_map` from `smu_v14_0_0_ppsmc.h`. There is no
//! 14.0.1 header: the 14.0.1 PMFW speaks the 0_0 table.
//!
//! Key differences from SMU 13.0.4 (Phoenix):
//!   - No generic `PowerUpVcn` / `PowerDownVcn`: VCN and JPEG power are
//!     per-instance only — VCN0 (0x06/0x07), VCN1 (0x04/0x05), JPEG0
//!     (0x21/0x22), JPEG1 (0x26/0x27). VCN1/JPEG1 are power gated by
//!     default, like VCN0/JPEG0.
//!   - `AllowGfxOff` / `DisallowGfxOff` are still 0x19 / 0x1A — but the
//!     0_2 table (MP1 14.0.2/14.0.3, different parts) puts them at
//!     0x28 / 0x29. This module is the 0_0 table only.
//!   - `GetGfxclkFrequency` / `GetFclkFrequency` (0x17 / 0x18 in the
//!     header, named `spare_0x17` / `spare_0x18`) are NOT in
//!     `smu_v14_0_0_message_map`: Linux reads clocks from the metrics
//!     table on v14 instead. `msg_id` returns `None` for both.
//!   - New on v14: UMSCH (0x2D/0x2E), VPE (0x31/0x32), ISP tiles
//!     (0x29/0x2A), MALL power (0x38/0x39), LSDMA (0x34/0x35).
//!
//! Source: `/drivers/gpu/drm/amd/pm/swsmu/inc/pmfw_if/smu_v14_0_0_ppsmc.h`
//! + `smu_v14_0_0_ppt.c::smu_v14_0_0_message_map` (Linux 7.4-rc2).
//!
//! (GPL-2.0-or-later; NARF relicensed 2026-05-20).

use crate::amdgpu_smu::send_message_void;
use crate::amdgpu_smu::{ClockDomain, PpsmcMsg, SmuError, SmuMmio};

// ── SMU14.0.1 PPSMC_MSG_* opcode values ────────────────────────────

/// `PPSMC_MSG_TestMessage` — echo/responsiveness check (0x01).
pub const V14_MSG_TEST: u32 = 0x01;
/// `PPSMC_MSG_GetPmfwVersion` — firmware version in ARG (0x02).
pub const V14_MSG_GET_PMFW_VERSION: u32 = 0x02;
/// `PPSMC_MSG_GetDriverIfVersion` — driver-IF schema version (0x03).
pub const V14_MSG_GET_DRIVER_IF: u32 = 0x03;
/// `PPSMC_MSG_PowerDownVcn1` — power-gate VCN1 (0x04).
pub const V14_MSG_POWER_DOWN_VCN1: u32 = 0x04;
/// `PPSMC_MSG_PowerUpVcn1` — wake VCN1 (0x05). VCN1 is power gated by default.
pub const V14_MSG_POWER_UP_VCN1: u32 = 0x05;
/// `PPSMC_MSG_PowerDownVcn0` — power-gate VCN0 (0x06).
pub const V14_MSG_POWER_DOWN_VCN0: u32 = 0x06;
/// `PPSMC_MSG_PowerUpVcn0` — wake VCN0 (0x07). VCN0 is power gated by default.
pub const V14_MSG_POWER_UP_VCN0: u32 = 0x07;
/// `PPSMC_MSG_SetSoftMinGfxclk` — soft-min GFXCLK in MHz (0x09).
pub const V14_MSG_SET_SOFT_MIN_GFXCLK: u32 = 0x09;
/// `PPSMC_MSG_PrepareMp1ForUnload` — quiesce before driver unload (0x0C).
pub const V14_MSG_PREPARE_MP1_UNLOAD: u32 = 0x0C;
/// `PPSMC_MSG_SetDriverDramAddrHigh` — DRAM address high 32 bits (0x0D).
pub const V14_MSG_SET_DRAM_ADDR_HI: u32 = 0x0D;
/// `PPSMC_MSG_SetDriverDramAddrLow` — DRAM address low 32 bits (0x0E).
pub const V14_MSG_SET_DRAM_ADDR_LO: u32 = 0x0E;
/// `PPSMC_MSG_TransferTableSmu2Dram` — SMU table → host DRAM (0x0F).
pub const V14_MSG_XFER_SMU2DRAM: u32 = 0x0F;
/// `PPSMC_MSG_TransferTableDram2Smu` — host DRAM → SMU table (0x10).
pub const V14_MSG_XFER_DRAM2SMU: u32 = 0x10;
/// `PPSMC_MSG_GfxDeviceDriverReset` — driver-initiated GPU reset (0x11).
/// Argument is a `Mode_Reset_e`: MODE1_RESET = 1, MODE2_RESET = 2.
pub const V14_MSG_GFX_DEVICE_DRIVER_RESET: u32 = 0x11;
/// `PPSMC_MSG_GetEnabledSmuFeatures` — enabled SMU features bitmask (0x12).
pub const V14_MSG_GET_ENABLED_SMU_FEATURES: u32 = 0x12;
/// `PPSMC_MSG_SetHardMinSocclkByFreq` — hard-min SOCCLK in MHz (0x13).
pub const V14_MSG_SET_HARD_MIN_SOCCLK: u32 = 0x13;
/// `PPSMC_MSG_SetSoftMinFclk` — soft-min FCLK in MHz (0x14).
pub const V14_MSG_SET_SOFT_MIN_FCLK: u32 = 0x14;
/// `PPSMC_MSG_AllowGfxOff` — allow GFXOFF entry (0x19).
pub const V14_MSG_ALLOW_GFX_OFF: u32 = 0x19;
/// `PPSMC_MSG_DisallowGfxOff` — disallow GFXOFF entry (0x1A).
pub const V14_MSG_DISALLOW_GFX_OFF: u32 = 0x1A;
/// `PPSMC_MSG_SetSoftMaxGfxClk` — soft-max GFXCLK in MHz (0x1B).
pub const V14_MSG_SET_SOFT_MAX_GFXCLK: u32 = 0x1B;
/// `PPSMC_MSG_SetHardMinGfxClk` — hard-min GFXCLK in MHz (0x1C).
pub const V14_MSG_SET_HARD_MIN_GFXCLK: u32 = 0x1C;
/// `PPSMC_MSG_SetSoftMaxSocclkByFreq` — soft-max SOCCLK in MHz (0x1D).
pub const V14_MSG_SET_SOFT_MAX_SOCCLK: u32 = 0x1D;
/// `PPSMC_MSG_SetSoftMaxFclkByFreq` — soft-max FCLK in MHz (0x1E).
pub const V14_MSG_SET_SOFT_MAX_FCLK: u32 = 0x1E;
/// `PPSMC_MSG_PowerDownJpeg0` — power-gate JPEG0 (0x21).
pub const V14_MSG_POWER_DOWN_JPEG0: u32 = 0x21;
/// `PPSMC_MSG_PowerUpJpeg0` — wake JPEG0 (0x22). JPEG0 is power gated by default.
pub const V14_MSG_POWER_UP_JPEG0: u32 = 0x22;
/// `PPSMC_MSG_SetHardMinFclkByFreq` — hard-min FCLK in MHz (0x23).
pub const V14_MSG_SET_HARD_MIN_FCLK: u32 = 0x23;
/// `PPSMC_MSG_SetSoftMinSocclkByFreq` — soft-min SOCCLK in MHz (0x24).
pub const V14_MSG_SET_SOFT_MIN_SOCCLK: u32 = 0x24;
/// `PPSMC_MSG_PowerDownJpeg1` — power-gate JPEG1 (0x26).
pub const V14_MSG_POWER_DOWN_JPEG1: u32 = 0x26;
/// `PPSMC_MSG_PowerUpJpeg1` — wake JPEG1 (0x27). JPEG1 is power gated by default.
pub const V14_MSG_POWER_UP_JPEG1: u32 = 0x27;
/// `PPSMC_MSG_PowerDownUmsch` — power down VCN0.UMSCH (0x2D).
pub const V14_MSG_POWER_DOWN_UMSCH: u32 = 0x2D;
/// `PPSMC_MSG_PowerUpUmsch` — power up VCN0.UMSCH (0x2E).
pub const V14_MSG_POWER_UP_UMSCH: u32 = 0x2E;
/// `PPSMC_MSG_PowerUpVpe` — power up VPE (0x31).
pub const V14_MSG_POWER_UP_VPE: u32 = 0x31;
/// `PPSMC_MSG_PowerDownVpe` — power down VPE (0x32).
pub const V14_MSG_POWER_DOWN_VPE: u32 = 0x32;

// ── Per-version opcode lookup ───────────────────────────────────────

/// Translate a canonical [`PpsmcMsg`] to its SMU 14.0.1 numeric id.
/// Returns `None` for messages not supported on this version.
///
/// References:
/// - `smu_v14_0_0_ppt.c::smu_v14_0_0_message_map` (MSG_MAP table).
/// - `smu_v14_0_0_ppsmc.h` for the numeric ids.
pub fn msg_id(msg: PpsmcMsg) -> Option<u32> {
    match msg {
        PpsmcMsg::TestMessage => Some(V14_MSG_TEST),
        PpsmcMsg::GetSmuVersion => Some(V14_MSG_GET_PMFW_VERSION),
        PpsmcMsg::GetDriverIfVersion => Some(V14_MSG_GET_DRIVER_IF),
        // 0x17 / 0x18 exist in the header as spares but are NOT in the
        // 0_0 message map: Linux reads GFXCLK / FCLK from the metrics
        // table on v14 instead of asking the firmware.
        PpsmcMsg::GetGfxclkFrequency => None,
        PpsmcMsg::GetFclkFrequency => None,
        PpsmcMsg::SetSoftMinGfxclk => Some(V14_MSG_SET_SOFT_MIN_GFXCLK),
        PpsmcMsg::SetSoftMaxGfxClk => Some(V14_MSG_SET_SOFT_MAX_GFXCLK),
        PpsmcMsg::SetHardMinGfxClk => Some(V14_MSG_SET_HARD_MIN_GFXCLK),
        PpsmcMsg::SetSoftMinFclk => Some(V14_MSG_SET_SOFT_MIN_FCLK),
        PpsmcMsg::SetSoftMaxFclk => Some(V14_MSG_SET_SOFT_MAX_FCLK),
        PpsmcMsg::SetHardMinFclk => Some(V14_MSG_SET_HARD_MIN_FCLK),
        PpsmcMsg::SetSoftMinSocclk => Some(V14_MSG_SET_SOFT_MIN_SOCCLK),
        PpsmcMsg::SetSoftMaxSocclk => Some(V14_MSG_SET_SOFT_MAX_SOCCLK),
        PpsmcMsg::AllowGfxOff => Some(V14_MSG_ALLOW_GFX_OFF),
        PpsmcMsg::DisallowGfxOff => Some(V14_MSG_DISALLOW_GFX_OFF),
        PpsmcMsg::PrepareMp1ForUnload => Some(V14_MSG_PREPARE_MP1_UNLOAD),
        PpsmcMsg::SetDriverDramAddrHigh => Some(V14_MSG_SET_DRAM_ADDR_HI),
        PpsmcMsg::SetDriverDramAddrLow => Some(V14_MSG_SET_DRAM_ADDR_LO),
        PpsmcMsg::TransferTableSmu2Dram => Some(V14_MSG_XFER_SMU2DRAM),
        PpsmcMsg::TransferTableDram2Smu => Some(V14_MSG_XFER_DRAM2SMU),
        // SMU14 doesn't have a standalone PowerUpGfx (GFX-off is
        // controlled entirely through AllowGfxOff / DisallowGfxOff).
        PpsmcMsg::PowerUpGfx => None,
    }
}

// ── Per-instance power messages ─────────────────────────────────────

/// The message id to power `instance` (0 or 1) of VCN up (`up`) or down,
/// or `None` when there is no such instance. v14 has no generic VCN
/// message: instance 0 is 0x07/0x06, instance 1 is 0x05/0x04.
pub fn vcn_power_msg(instance: u8, up: bool) -> Option<u32> {
    match (instance, up) {
        (0, true) => Some(V14_MSG_POWER_UP_VCN0),
        (0, false) => Some(V14_MSG_POWER_DOWN_VCN0),
        (1, true) => Some(V14_MSG_POWER_UP_VCN1),
        (1, false) => Some(V14_MSG_POWER_DOWN_VCN1),
        _ => None,
    }
}

/// The message id to power `instance` (0 or 1) of JPEG up (`up`) or down,
/// or `None` when there is no such instance. Instance 0 is 0x22/0x21,
/// instance 1 is 0x27/0x26.
pub fn jpeg_power_msg(instance: u8, up: bool) -> Option<u32> {
    match (instance, up) {
        (0, true) => Some(V14_MSG_POWER_UP_JPEG0),
        (0, false) => Some(V14_MSG_POWER_DOWN_JPEG0),
        (1, true) => Some(V14_MSG_POWER_UP_JPEG1),
        (1, false) => Some(V14_MSG_POWER_DOWN_JPEG1),
        _ => None,
    }
}

// ── SMU14 clock-domain helpers ──────────────────────────────────────

/// Return the SMU14.0.1 message id to query the current frequency for
/// `domain`, or `None` if queried via the shared-table path instead.
/// On v14 every clock reads from the metrics table: there is no
/// message-id query for any domain.
pub fn get_current_clk_msg(domain: ClockDomain) -> Option<u32> {
    match domain {
        ClockDomain::Gfxclk
        | ClockDomain::Fclk
        | ClockDomain::Socclk
        | ClockDomain::Uclk
        | ClockDomain::Vclk
        | ClockDomain::Dclk => None,
    }
}

/// Return the SMU14.0.1 message ids for setting soft min / soft max on
/// `domain`. Returns `(set_min_msg, set_max_msg)`.
pub fn set_range_msgs(domain: ClockDomain) -> Option<(u32, u32)> {
    match domain {
        ClockDomain::Gfxclk => Some((V14_MSG_SET_SOFT_MIN_GFXCLK, V14_MSG_SET_SOFT_MAX_GFXCLK)),
        ClockDomain::Fclk => Some((V14_MSG_SET_SOFT_MIN_FCLK, V14_MSG_SET_SOFT_MAX_FCLK)),
        ClockDomain::Socclk => Some((V14_MSG_SET_SOFT_MIN_SOCCLK, V14_MSG_SET_SOFT_MAX_SOCCLK)),
        ClockDomain::Uclk | ClockDomain::Vclk | ClockDomain::Dclk => None,
    }
}

// ── High-level wrappers ─────────────────────────────────────────────

/// Set soft-min GFXCLK to `freq_mhz` on SMU14.0.1 hardware.
pub fn set_soft_min_gfxclk<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
    freq_mhz: u32,
) -> Result<(), SmuError> {
    send_message_void(mmio, mp1_base, V14_MSG_SET_SOFT_MIN_GFXCLK, freq_mhz)
}

/// Set soft-max GFXCLK to `freq_mhz` on SMU14.0.1 hardware.
pub fn set_soft_max_gfxclk<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
    freq_mhz: u32,
) -> Result<(), SmuError> {
    send_message_void(mmio, mp1_base, V14_MSG_SET_SOFT_MAX_GFXCLK, freq_mhz)
}

/// Set soft-min FCLK to `freq_mhz` on SMU14.0.1 hardware.
pub fn set_soft_min_fclk<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
    freq_mhz: u32,
) -> Result<(), SmuError> {
    send_message_void(mmio, mp1_base, V14_MSG_SET_SOFT_MIN_FCLK, freq_mhz)
}

/// Set soft-max FCLK to `freq_mhz` on SMU14.0.1 hardware.
pub fn set_soft_max_fclk<M: SmuMmio>(
    mmio: &mut M,
    mp1_base: u32,
    freq_mhz: u32,
) -> Result<(), SmuError> {
    send_message_void(mmio, mp1_base, V14_MSG_SET_SOFT_MAX_FCLK, freq_mhz)
}
