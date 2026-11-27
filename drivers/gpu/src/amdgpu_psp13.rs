//! PSP 13.0.0 firmware set (Navi31, MP0 13.0.0).
//!
//! Linux selects this set in `psp_v13_0.c::psp_v13_0_init_microcode` for
//! `IP_VERSION(13, 0, 0)`: SOS + TA microcode, no TOC (the TOC-loading
//! arm is `IP_VERSION(13, 0, 1|3|5|8|11)` and `14.0.x`). The GC TOC
//! (`gc_11_0_0_toc.bin`) is a separate blob loaded by
//! `gfx_v11_0_init_toc_microcode` and lives in the `NAVI31_FW` multi-load
//! table (`amdgpu.rs`), not here.
//!
//! Names (all `psp_v13_0.c` `MODULE_FIRMWARE`, Linux 7.4-rc2):
//!
//! | blob | loaded by |
//! |------|-----------|
//! | `psp_13_0_0_sos.bin` (+ `_kicker` variant) | `psp_init_sos_microcode` (PSP bootloader path) |
//! | `psp_13_0_0_ta.bin` (+ `_kicker` variant) | `psp_init_ta_microcode` |
//! | `smu_13_0_0.bin` (+ `_kicker` variant) | the PSP, not the driver (see below) |
//!
//! The SMU blob is PSP-loaded on Navi31: Linux's `smu_v13_0_load_microcode`
//! is entirely `#if 0` and returns 0, and `smu_v13_0_init_pptable_microcode`
//! only runs when `adev->firmware.load_type == AMDGPU_FW_LOAD_PSP`. There
//! is no `PPSMC_MSG_LoadMicrocode` in `smu_v13_0_0_ppsmc.h` at all, so the
//! SMU blob must never be routed through `amdgpu_smu::load_pmfw` (whose
//! `PPSMC_MSG_LOAD_MICROCODE_PHOENIX` id 0x02 is `GetSmuVersion` on 13.0.0).
//! The SMU name is tabled here so the PSP boot owner knows which blob the
//! PSP side expects; the MP1-mailbox PMFW sentinel stays Phoenix-only.
//!
//! Kicker selection is GROUNDED (Navi31 SKU firmware lane, tip
//! 00f4141dd): Linux's `amdgpu_is_kicker_fw(adev)` is
//! `amdgpu_ucode.c::kicker_device_list`, exactly
//! `{(0x744B, 0x00), (0x7551, 0xC8)}` — 0x744B (Pro W7900D) at PCI
//! revision 0x00 is the only Navi31 kicker board. The rule is also
//! mirrored in-tree as `amdgpu_rdna4::KICKER_DEVICES` / `is_kicker`
//! (the 0x744B entry there is a firmware-selection kicker, not a
//! probe registration). The selector still takes an explicit
//! `kicker: bool` and the caller owns the rule — the PSP boot owner
//! wires `is_kicker(did, revision)` when it lands — and the Navi31
//! per-DID firmware gate (`navi3_chip_info`) already routes 0x744B
//! to the kicker table (`NAVI31_W7900D_FW`).
//!
//! (GPL-2.0-or-later; NARF relicensed 2026-05-20).

use crate::amdgpu_psp_firmware::{
    PSP13_0_0_SOS, PSP13_0_0_SOS_KICKER, PSP13_0_0_TA, PSP13_0_0_TA_KICKER,
};

/// SMU 13.0.0 PMFW, PSP-loaded (see the module docs). Named in
/// `smu_v13_0.c` `MODULE_FIRMWARE`.
pub const PSP13_0_0_SMU: &str = "amdgpu/smu_13_0_0.bin";
/// SMU 13.0.0 PMFW for an `amdgpu_is_kicker_fw` board.
pub const PSP13_0_0_SMU_KICKER: &str = "amdgpu/smu_13_0_0_kicker.bin";

/// The PSP 13.0.0 firmware set for one Navi31 board: the SOS and TA the
/// PSP loads, plus the SMU PMFW the PSP side expects. All names are
/// Linux's `MODULE_FIRMWARE` strings; the registry opens them by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Psp13FirmwareSet {
    /// `psp_13_0_0_sos[_kicker].bin`.
    pub sos: &'static str,
    /// `psp_13_0_0_ta[_kicker].bin`.
    pub ta: &'static str,
    /// `smu_13_0_0[_kicker].bin` — PSP-loaded, never MP1-mailbox-loaded.
    pub smu: &'static str,
}

impl Psp13FirmwareSet {
    /// Select the set for a board. `kicker` is Linux's
    /// `amdgpu_is_kicker_fw(adev)` branch: `true` takes the `_kicker`
    /// SOS/TA/SMU variants, `false` the base ones. The grounded rule
    /// is `amdgpu_rdna4::is_kicker(did, revision)` — (0x744B, 0x00)
    /// for Navi31 — but the caller owns applying it; the PSP boot
    /// owner wires the rule when it lands.
    pub const fn select(kicker: bool) -> Self {
        if kicker {
            Self {
                sos: PSP13_0_0_SOS_KICKER,
                ta: PSP13_0_0_TA_KICKER,
                smu: PSP13_0_0_SMU_KICKER,
            }
        } else {
            Self {
                sos: PSP13_0_0_SOS,
                ta: PSP13_0_0_TA,
                smu: PSP13_0_0_SMU,
            }
        }
    }
}
