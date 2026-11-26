//! Navi31/32/33 (RDNA3, RX 7000) SDMA 6.0 owner.
//!
//! The discrete-RDNA3 SDMA block: one GFX ring per instance, eight queues
//! per instance, programmed exactly as Linux programs it in
//! `drivers/gpu/drm/amd/amdgpu/sdma_v6_0.c::sdma_v6_0_gfx_resume_instance`.
//! The Phoenix builders in [`crate::amdgpu_sdma`] cover queue 0 of a single
//! instance and leave the watchdog and UTCL1 tuning at reset; this owner
//! covers every (instance, queue) pair and programs the full sequence,
//! including the watchdog, the UTCL1 policy, and the F32 unhalt with its
//! reset-derived value.
//!
//! ## Per-die revisions (firmware-set evidence, not a kernel switch)
//!
//! No `navi31`/`navi32`/`navi33` string exists in the Linux 7.4-rc2 tree:
//! the die↔revision pairing rests on firmware sets, as lane 1 documented
//! (Ubuntu LP#2034103 lists the GC 11.0.3 set — `gc_11_0_3` + `psp_13_0_10`
//! + `sdma_6_0_3` + `smu_13_0_10` + `vcn_4_0_0` — for Navi32 hardware; the
//!   Gentoo AMDGPU firmware table maps NAVI31 → 11.0.0 set, NAVI32 → 11.0.3
//!   set, NAVI33 → 11.0.2 set). What the ref tree *does* confirm is that
//!   `sdma_v6_0.c` handles exactly revisions 6.0.0–6.0.3 (plus 6.1.x) with one
//!   firmware blob per revision (`MODULE_FIRMWARE("amdgpu/sdma_6_0_0.bin")`
//!   through `sdma_6_0_3.bin`, `sdma_v6_0.c:50-53`), and that 6.0.1 is
//!   Phoenix's revision — this owner rejects it.
//!
//! ## Instance count is discovery-driven, never asserted
//!
//! Linux counts SDMA instances from the card's discovery binary — one count
//! per SDMA0/1/2/3 HWID entry (`amdgpu_discovery.c:1954-1967`) — so no
//! per-die instance count exists anywhere in the ref tree to copy. This
//! owner takes the discovered SDMA versions as input
//! ([`Sdma60::from_discovery`]) and validates each one against the die's
//! revision; it never hardcodes how many instances a die has. The only cap
//! is the driver's own addressing: `sdma_v6_0_get_reg_offset` handles
//! instances 0 and 1 only, and the soc21 doorbell table sizes
//! `sdma_engine[2]`, so more than two discovered instances is refused.
//!
//! ## What this owner does not do (integration remainders)
//!
//! * No live MMIO. The ring sequences this owner builds are executed by the
//!   Navi31 platform lane once PSP dispatch works — `initialize()` still
//!   fails closed at `psp_dispatch_one`'s shared GPCOM-ring gap, so no SDMA
//!   stage can execute yet. A dedicated GPCOM-ring lane owns that gap.
//! * No firmware load. The blob names ([`firmware_name_for_revision`]) are
//!   recorded for lane 2/3's PSP/SMU surface; this owner never touches PSP.
//! * No MES queue reset. Linux resets a hung v6.0 queue through MES
//!   (`amdgpu_mes_reset_legacy_queue`) and then re-runs the resume sequence
//!   with the wptr restored (`sdma_v6_0_reset_queue`); [`Sdma60::ring_restore`]
//!   builds only the restore half — the MES half belongs to lane 5/6.
//! * No user queues. Linux arms MES user queues only when the firmware
//!   version clears a per-revision floor (6.0.0 ≥ 27, 6.0.2 ≥ 23, 6.0.3 ≥ 29;
//!   `sdma_v6_0_sw_init`); this owner programs the kernel GFX ring only.
//!
//! Linux references (GPL-2.0-or-later post-relicense):
//! - `drivers/gpu/drm/amd/amdgpu/sdma_v6_0.c`
//! - `drivers/gpu/drm/amd/include/asic_reg/gc/gc_11_0_0_offset.h`
//! - `drivers/gpu/drm/amd/include/asic_reg/gc/gc_11_0_0_sh_mask.h`
//! - `drivers/gpu/drm/amd/include/asic_reg/gc/gc_11_0_0_default.h`
//! - `drivers/gpu/drm/amd/amdgpu/sdma_common.h` (UTCL2 cache-policy enums)
//! - `drivers/gpu/drm/amd/amdgpu/soc21.c` (doorbell range, engine table)
//! - `drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c` (instance counting)

extern crate alloc;

use crate::amdgpu_sdma::{
    SdmaError, SdmaRingInitSequence, SdmaWrite, SDMA6_F32_CNTL_REL,
    SDMA6_QUEUE0_DOORBELL_OFFSET_REL, SDMA6_QUEUE0_DOORBELL_REL, SDMA6_QUEUE0_IB_CNTL_REL,
    SDMA6_QUEUE0_MINOR_PTR_UPDATE_REL, SDMA6_QUEUE0_RB_BASE_HI_REL, SDMA6_QUEUE0_RB_BASE_REL,
    SDMA6_QUEUE0_RB_CNTL_REL, SDMA6_QUEUE0_RB_RPTR_ADDR_HI_REL, SDMA6_QUEUE0_RB_RPTR_ADDR_LO_REL,
    SDMA6_QUEUE0_RB_RPTR_HI_REL, SDMA6_QUEUE0_RB_RPTR_REL, SDMA6_QUEUE0_RB_WPTR_HI_REL,
    SDMA6_QUEUE0_RB_WPTR_POLL_ADDR_HI_REL, SDMA6_QUEUE0_RB_WPTR_POLL_ADDR_LO_REL,
    SDMA6_QUEUE0_RB_WPTR_REL, SDMA_DOORBELL_ENABLE, SDMA_F32_HALT, SDMA_F32_TH1_RESET,
    SDMA_IB_ENABLE, SDMA_MINOR_PTR_UPDATE_ENABLE, SDMA_RB_ENABLE, SDMA_RB_F32_WPTR_POLL_ENABLE,
    SDMA_RB_PRIV, SDMA_RB_RPTR_WRITEBACK_ENABLE, SDMA_RB_SIZE_MAX_LOG2, SDMA_RB_SIZE_SHIFT,
    SDMA_RB_WPTR_POLL_ENABLE,
};

// ── Per-die revisions ──────────────────────────────────────────────

/// A discrete RDNA3 die.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Navi3Die {
    /// GC 11.0.0 — RX 7900 XTX/XT, Pro W7800/W7900 family.
    Navi31,
    /// GC 11.0.3 — RX 7800 XT / 7700 XT, Pro W7700 / V710.
    Navi32,
    /// GC 11.0.2 — RX 7600/7600 XT / 7500 / 7400, Pro W7500.
    Navi33,
}

impl Navi3Die {
    /// The die's GC IP version, as Linux discovers it.
    pub const fn gc_version(self) -> (u8, u8, u8) {
        match self {
            Navi3Die::Navi31 => (11, 0, 0),
            Navi3Die::Navi32 => (11, 0, 3),
            Navi3Die::Navi33 => (11, 0, 2),
        }
    }

    /// The die's SDMA IP version.
    pub const fn sdma_revision(self) -> (u8, u8, u8) {
        match self {
            Navi3Die::Navi31 => (6, 0, 0),
            Navi3Die::Navi32 => (6, 0, 3),
            Navi3Die::Navi33 => (6, 0, 2),
        }
    }
}

/// The die whose GC version is `(major, minor, revision)`, or `None`.
///
/// Keys off GC, not SDMA: the platform lane discovers GC first and routes
/// the SDMA revision from the die.
pub const fn die_for_gc(major: u8, minor: u8, revision: u8) -> Option<Navi3Die> {
    match (major, minor, revision) {
        (11, 0, 0) => Some(Navi3Die::Navi31),
        (11, 0, 3) => Some(Navi3Die::Navi32),
        (11, 0, 2) => Some(Navi3Die::Navi33),
        _ => None,
    }
}

/// The die whose SDMA version is `(major, minor, revision)`, or `None`.
///
/// (6, 0, 1) is Phoenix — deliberately not a Navi3 revision.
pub const fn die_for_sdma_revision(major: u8, minor: u8, revision: u8) -> Option<Navi3Die> {
    match (major, minor, revision) {
        (6, 0, 0) => Some(Navi3Die::Navi31),
        (6, 0, 3) => Some(Navi3Die::Navi32),
        (6, 0, 2) => Some(Navi3Die::Navi33),
        _ => None,
    }
}

/// Whether `(major, minor, revision)` is a discrete-RDNA3 SDMA revision —
/// one `sdma_v6_0.c` handles, and one of the three dies reports.
pub const fn accepts_sdma_revision(major: u8, minor: u8, revision: u8) -> bool {
    die_for_sdma_revision(major, minor, revision).is_some()
}

/// The SDMA microcode blob for `(major, minor, revision)`, or `None`.
///
/// Names are `sdma_v6_0.c`'s own `MODULE_FIRMWARE` lines (`:50-53`):
/// `amdgpu/sdma_6_0_0.bin` … `sdma_6_0_3.bin`. Recorded here for the PSP
/// surface; this owner never loads firmware.
pub const fn firmware_name_for_revision(
    major: u8,
    minor: u8,
    revision: u8,
) -> Option<&'static str> {
    match (major, minor, revision) {
        (6, 0, 0) => Some("amdgpu/sdma_6_0_0.bin"),
        (6, 0, 2) => Some("amdgpu/sdma_6_0_2.bin"),
        (6, 0, 3) => Some("amdgpu/sdma_6_0_3.bin"),
        _ => None,
    }
}

// ── Layout (gc_11_0_0_offset.h / sdma_v6_0.c) ───────────────────────

/// Queues per SDMA v6.0 instance. `sdma_v6_0_detect_hung_queue` scans
/// `q < 8` per instance.
pub const SDMA60_QUEUES_PER_INSTANCE: u32 = 8;
/// Dword stride between adjacent per-queue register banks:
/// `SDMA_V6_0_QUEUE_REG_STRIDE` =
/// `regSDMA0_QUEUE1_RB_CNTL - regSDMA0_QUEUE0_RB_CNTL` = 0xD8 − 0x80.
pub const SDMA60_QUEUE_REG_STRIDE: u32 = 0x58;
/// `SDMA1_REG_OFFSET` (`sdma_v6_0.c:61`): instance 1's per-queue banks sit
/// 0x600 dwords past instance 0's.
pub const SDMA60_SDMA1_REG_OFFSET: u32 = 0x600;
/// `SDMA1_HYP_DEC_REG_OFFSET` (`sdma_v6_0.c:64`): instance 1's HYP_DEC
/// registers (the `SDMA0_F32_CNTL` range) sit 0x20 dwords past instance 0's.
pub const SDMA60_SDMA1_HYP_DEC_REG_OFFSET: u32 = 0x20;
/// `SDMA0_HYP_DEC_REG_START` (`sdma_v6_0.c:62`).
pub const SDMA60_HYP_DEC_START: u32 = 0x5880;
/// `SDMA0_HYP_DEC_REG_END` (`sdma_v6_0.c:63`).
pub const SDMA60_HYP_DEC_END: u32 = 0x589A;
/// Doorbells per SDMA instance: `soc21.c` sets
/// `adev->doorbell_index.sdma_doorbell_range = 20`, and
/// `sdma_v6_0_gfx_resume_instance` hands instance `i` the range
/// `ring->doorbell_index .. + range * num_instances` via NBIO.
pub const SDMA60_DOORBELL_RANGE_PER_INSTANCE: u32 = 20;
/// Most SDMA v6.0 instances Linux ever addresses on GFX11: `sdma_v6_0.c`'s
/// `sdma_v6_0_get_reg_offset` branches only on `instance == 1`, and
/// `soc21.c` sizes the doorbell engine table `sdma_engine[2]`.
pub const SDMA60_MAX_INSTANCES: usize = 2;

// ── Instance-level registers (not in the per-queue bank) ───────────
//
// Dword ids from `gc_11_0_0_offset.h`, byte-scaled like the `SDMA6_*_REL`
// constants in `crate::amdgpu_sdma` (multiply the dword id by 4).

/// `regSDMA0_SEM_WAIT_FAIL_TIMER_CNTL` (0x0022). Linux writes 0 first in
/// `sdma_v6_0_gfx_resume_instance` (bare metal only).
pub const SDMA60_SEM_WAIT_FAIL_TIMER_CNTL_REL: u32 = 0x22 * 4;
/// `regSDMA0_WATCHDOG_CNTL` (0x002e).
pub const SDMA60_WATCHDOG_CNTL_REL: u32 = 0x2E * 4;
/// `regSDMA0_UTCL1_CNTL` (0x003c).
pub const SDMA60_UTCL1_CNTL_REL: u32 = 0x3C * 4;
/// `regSDMA0_UTCL1_PAGE` (0x003f).
pub const SDMA60_UTCL1_PAGE_REL: u32 = 0x3F * 4;
/// `regSDMA0_QUEUE_RESET_REQ` (0x007b) — one bit per queue
/// (`QUEUE0_RESET` bit 0 … `QUEUE7_RESET` bit 7). Linux's v6.0 reset goes
/// through MES, not this register; recorded for the reset lane.
pub const SDMA60_QUEUE_RESET_REQ_REL: u32 = 0x7B * 4;

// ── Field encodings (gc_11_0_0_sh_mask.h) ──────────────────────────

/// `SDMA0_WATCHDOG_CNTL__QUEUE_HANG_COUNT__SHIFT` 0, mask 0xFF — hang
/// count in 100 ms units. Linux writes
/// `max(adev->usec_timeout/100000, 1)`.
pub const SDMA60_WATCHDOG_QUEUE_HANG_COUNT_SHIFT: u32 = 0;
/// `SDMA0_WATCHDOG_CNTL__QUEUE_HANG_COUNT_MASK`.
pub const SDMA60_WATCHDOG_QUEUE_HANG_COUNT_MASK: u32 = 0xFF;
/// `SDMA0_UTCL1_CNTL__RESP_MODE__SHIFT` 9 — Linux programs 3 ("non-copy
/// addresses").
pub const SDMA60_UTCL1_RESP_MODE_SHIFT: u32 = 9;
/// `SDMA0_UTCL1_CNTL__REDO_DELAY__SHIFT` 0 — Linux programs 9.
pub const SDMA60_UTCL1_REDO_DELAY_SHIFT: u32 = 0;
/// `SDMA0_UTCL1_PAGE__RD_L2_POLICY__SHIFT` 12.
pub const SDMA60_UTCL1_RD_L2_POLICY_SHIFT: u32 = 12;
/// `SDMA0_UTCL1_PAGE__WR_L2_POLICY__SHIFT` 14.
pub const SDMA60_UTCL1_WR_L2_POLICY_SHIFT: u32 = 14;
/// `SDMA0_UTCL1_PAGE__LLC_NOALLOC__SHIFT` 24.
pub const SDMA60_UTCL1_LLC_NOALLOC_SHIFT: u32 = 24;
/// `CACHE_READ_POLICY_L2__DEFAULT` (`sdma_common.h`): `NOA` = 2.
pub const SDMA60_CACHE_READ_POLICY_L2_DEFAULT: u32 = 2;
/// `CACHE_WRITE_POLICY_L2__DEFAULT` (`sdma_common.h`): `BYPASS` = 3.
pub const SDMA60_CACHE_WRITE_POLICY_L2_DEFAULT: u32 = 3;

// ── Cold-start values (reset defaults + Linux's field sets) ────────
//
// Linux read-modify-writes WATCHDOG/UTCL1/F32/IB_CNTL. A sequence builder
// emits absolute writes, so each value below is the reset default from
// `gc_11_0_0_default.h` with Linux's field sets applied — i.e. exactly
// what Linux's RMW produces on a cold start out of reset.

/// `regSDMA0_F32_CNTL` cold start: default `0x08084001` with `HALT` (bit 0)
/// and `TH1_RESET` (bit 13) cleared, as `sdma_v6_0_gfx_resume_instance`
/// does. TH1_ENABLE and the TH0/TH1 priorities keep their reset values.
///
/// NOTE: the Phoenix builder writes 0 here, which additionally clears
/// TH1_ENABLE and both priorities. That is a Phoenix-builder deviation
/// from Linux, not fixed by this lane — this owner writes the
/// reset-derived value.
pub const SDMA60_F32_CNTL_COLD_START: u32 = 0x0808_4000;
/// `regSDMA0_UTCL1_CNTL` cold start: default `0x2c000288` with
/// `RESP_MODE` = 3 and `REDO_DELAY` = 9.
pub const SDMA60_UTCL1_CNTL_COLD_START: u32 = 0x2C00_0689;
/// `regSDMA0_UTCL1_PAGE` cold start: default `0x010cec00` with the
/// read/write-policy bits set to their defaults and `LLC_NOALLOC` set.
/// The write reproduces the reset default exactly (the default already
/// carries RD = 2 / WR = 3 / LLC_NOALLOC = 1); it is emitted anyway so the
/// sequence matches Linux's register-for-register.
pub const SDMA60_UTCL1_PAGE_COLD_START: u32 = 0x010C_EC00;
/// `regSDMA0_QUEUE0_IB_CNTL` cold start: default `0x00000100`
/// (`SWITCH_INSIDE_IB`) preserved, `IB_ENABLE` set — what Linux's RMW
/// produces out of reset.
pub const SDMA60_IB_CNTL_COLD_START: u32 = 0x0000_0101;

// ── Errors ─────────────────────────────────────────────────────────

/// Errors building a Navi3 SDMA 6.0 ring sequence or owning an engine.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Navi31SdmaError {
    /// `instance` is not addressable (`sdma_v6_0_get_reg_offset` handles
    /// instances 0 and 1 only).
    BadInstance,
    /// `queue` is not one of the 8 per-instance queues.
    BadQueue,
    /// `watchdog_hang_100ms` is 0 (hang detection off — Linux never
    /// writes 0) or does not fit `QUEUE_HANG_COUNT`'s 8 bits.
    BadWatchdog,
    /// Discovery reported no SDMA instance at all.
    NoInstances,
    /// Discovery reported more than [`SDMA60_MAX_INSTANCES`] instances.
    TooManyInstances,
    /// A discovered SDMA version is not this die's revision.
    RevisionMismatch,
    /// `ring_restore` was called for a queue `ring_init` never programmed.
    NotProgrammed,
    /// `ring_init` was called with `restore_wptr_bytes` set; a cold start
    /// never restores a wptr — use `ring_restore`.
    RestoreInInit,
    /// The shared ring-parameter check failed (size/alignment).
    Ring(SdmaError),
}

impl From<SdmaError> for Navi31SdmaError {
    fn from(e: SdmaError) -> Self {
        Navi31SdmaError::Ring(e)
    }
}

// ── Register addressing ────────────────────────────────────────────

/// Mirror of `sdma_v6_0_get_reg_offset` without the GC base: the dword
/// offset of `internal_offset` on `instance`.
///
/// HYP_DEC registers (`0x5880..=0x589a`, e.g. `F32_CNTL`) live on GC
/// BASE_IDX 1 with a 0x20-per-instance stride; every other register lives
/// on BASE_IDX 0 with instance 1 at `+0x600`.
pub const fn reg_offset(instance: u32, internal_offset: u32) -> u32 {
    if internal_offset >= SDMA60_HYP_DEC_START && internal_offset <= SDMA60_HYP_DEC_END {
        internal_offset + SDMA60_SDMA1_HYP_DEC_REG_OFFSET * instance
    } else if instance == 1 {
        internal_offset + SDMA60_SDMA1_REG_OFFSET
    } else {
        internal_offset
    }
}

/// Byte address of a per-queue register (`QUEUE0_*` byte offset `rel`)
/// for (`instance`, `queue`) off the GC BASE_IDX-0 base.
///
/// `rel` is byte-scaled like every `SDMA6_*_REL` constant; the queue
/// stride and the instance offset are dword ids in the Linux source, so
/// they are converted through [`reg_offset`] here.
fn queue_reg(gc_base: u32, instance: u32, queue: u32, rel: u32) -> u32 {
    gc_base + (rel / 4 + reg_offset(instance, 0) + queue * SDMA60_QUEUE_REG_STRIDE) * 4
}

/// Byte address of an instance-level register (`rel`) for `instance` off
/// the GC BASE_IDX-0 base. No queue stride: SEM/WATCHDOG/UTCL1 are per
/// engine, not per queue.
fn instance_reg(gc_base: u32, instance: u32, rel: u32) -> u32 {
    gc_base + (rel / 4 + reg_offset(instance, 0)) * 4
}

/// Byte address of a HYP_DEC register (`rel`, e.g. `F32_CNTL`) for
/// `instance` off the GC BASE_IDX-1 base.
fn hyp_reg(gc_base_idx1: u32, instance: u32, rel: u32) -> u32 {
    gc_base_idx1 + (rel / 4 + SDMA60_SDMA1_HYP_DEC_REG_OFFSET * instance) * 4
}

// ── Ring-init parameters ───────────────────────────────────────────

/// Parameters for one Navi3 SDMA 6.0 ring bring-up.
///
/// `gc_base` / `gc_base_idx1` are the GC IP block's BASE_IDX-0/1 bases in
/// bytes (`adev->reg_offset[GC_HWIP][0][0]` and `[1]`). `doorbell_index`
/// is the absolute DWORD offset in the doorbell aperture
/// (`ring->doorbell_index = sdma_engine[i] << 1`); the engine bases live
/// in the doorbell header, which is not in the ref tree, so the platform
/// lane supplies the index and this builder only programs it.
#[derive(Copy, Clone, Debug)]
pub struct Navi31RingInit {
    pub gc_base: u32,
    pub gc_base_idx1: u32,
    /// SDMA instance, 0 or 1.
    pub instance: u32,
    /// Queue within the instance, 0..8.
    pub queue: u32,
    pub ring_phys: u64,
    pub ring_size_dw: u32,
    pub doorbell_index: u32,
    /// Bare metal uses the doorbell; SR-IOV VF uses MMIO wptr instead.
    /// Linux programs `DOORBELL_ENABLE` only when `ring->use_doorbell`.
    pub use_doorbell: bool,
    pub rptr_writeback_phys: u64,
    pub wptr_poll_phys: u64,
    /// `WATCHDOG_CNTL.QUEUE_HANG_COUNT` in 100 ms units. Linux writes
    /// `max(usec_timeout/100000, 1)`; 0 is never written.
    pub watchdog_hang_100ms: u32,
    /// `None` = cold start (both pointers zeroed). `Some(bytes)` = reset
    /// restore: RPTR and WPTR resume at `bytes`, as
    /// `sdma_v6_0_gfx_resume_instance(restore = true)` does.
    pub restore_wptr_bytes: Option<u64>,
}

/// Build the SDMA v6.0 ring-init sequence for one (instance, queue) of a
/// Navi3 die — the full `sdma_v6_0_gfx_resume_instance` register-for-
/// register, in Linux's order:
///
///   1. `SEM_WAIT_FAIL_TIMER_CNTL = 0`.
///   2. `RB_CNTL = 0` — stop fetching while the base moves (Phoenix
///      builder's preamble; Linux cold-starts from reset `RB_ENABLE` = 0).
///   3. Zero `RB_RPTR`/`_HI` and `RB_WPTR`/`_HI` (or restore the wptr).
///   4. `RB_WPTR_POLL_ADDR_LO`/`_HI` — the host wptr shadow (`_HI` is the
///      LOWER register id of the pair).
///   5. `RB_RPTR_ADDR_HI`/`_LO` — the rptr writeback target (LO masked
///      `0xFFFFFFFC`).
///   6. `RB_CNTL` with `RB_SIZE`, `RB_PRIV`, `RPTR_WRITEBACK_ENABLE` and
///      `F32_WPTR_POLL_ENABLE`, `WPTR_POLL_ENABLE` left clear.
///   7. `RB_BASE = phys >> 8`, `RB_BASE_HI = phys >> 40`.
///   8. `MINOR_PTR_UPDATE = 1`, then the wptr write.
///   9. `DOORBELL_OFFSET` and `DOORBELL` with `ENABLE` (doorbell path).
///  10. `MINOR_PTR_UPDATE = 0`.
///  11. `WATCHDOG_CNTL` — hang count in 100 ms units.
///  12. `UTCL1_CNTL` — `RESP_MODE` 3, `REDO_DELAY` 9.
///  13. `UTCL1_PAGE` — default cache policies + `LLC_NOALLOC`.
///  14. `F32_CNTL` through the GC BASE_IDX-1 window: `HALT` and
///      `TH1_RESET` cleared — **before** the ring is enabled, as Linux
///      does. (The Phoenix builder writes F32 last, after `RB_ENABLE`;
///      this owner follows Linux's order.)
///  15. `RB_CNTL |= RB_ENABLE`.
///  16. `IB_CNTL` — `IB_ENABLE` with the reset `SWITCH_INSIDE_IB` bit kept.
pub fn build_navi31_sdma6_ring_init(
    p: Navi31RingInit,
) -> Result<SdmaRingInitSequence, Navi31SdmaError> {
    if p.instance > 1 {
        return Err(Navi31SdmaError::BadInstance);
    }
    if p.queue >= SDMA60_QUEUES_PER_INSTANCE {
        return Err(Navi31SdmaError::BadQueue);
    }
    if p.watchdog_hang_100ms == 0 || p.watchdog_hang_100ms > SDMA60_WATCHDOG_QUEUE_HANG_COUNT_MASK {
        return Err(Navi31SdmaError::BadWatchdog);
    }
    if !p.ring_size_dw.is_power_of_two()
        || !(8..=(1 << SDMA_RB_SIZE_MAX_LOG2)).contains(&p.ring_size_dw)
    {
        return Err(Navi31SdmaError::Ring(SdmaError::BadRingSize));
    }
    if p.ring_phys & 0xFF != 0 {
        return Err(Navi31SdmaError::Ring(SdmaError::UnalignedRingPhys));
    }
    if p.rptr_writeback_phys & 0x3 != 0 || p.wptr_poll_phys & 0x3 != 0 {
        return Err(Navi31SdmaError::Ring(SdmaError::UnalignedRptrWriteback));
    }
    let q = |rel: u32| queue_reg(p.gc_base, p.instance, p.queue, rel);
    let inst = |rel: u32| instance_reg(p.gc_base, p.instance, rel);
    let mut seq = SdmaRingInitSequence::default();
    let push = |seq: &mut SdmaRingInitSequence, addr: u32, value: u32| {
        seq.writes.push(SdmaWrite { addr, value });
    };
    // 1. Clear the semaphore-wait-fail timer.
    push(&mut seq, inst(SDMA60_SEM_WAIT_FAIL_TIMER_CNTL_REL), 0);
    // 2. Disable the ring.
    push(&mut seq, q(SDMA6_QUEUE0_RB_CNTL_REL), 0);
    // 3. Reset (or restore) r/wptr. Linux's restore writes `wptr << 2`
    // (dwords to bytes); this builder takes bytes directly.
    let wptr = p.restore_wptr_bytes.unwrap_or(0);
    push(&mut seq, q(SDMA6_QUEUE0_RB_RPTR_REL), wptr as u32);
    push(
        &mut seq,
        q(SDMA6_QUEUE0_RB_RPTR_HI_REL),
        (wptr >> 32) as u32,
    );
    push(&mut seq, q(SDMA6_QUEUE0_RB_WPTR_REL), wptr as u32);
    push(
        &mut seq,
        q(SDMA6_QUEUE0_RB_WPTR_HI_REL),
        (wptr >> 32) as u32,
    );
    // 4. Wptr shadow polling.
    push(
        &mut seq,
        q(SDMA6_QUEUE0_RB_WPTR_POLL_ADDR_LO_REL),
        p.wptr_poll_phys as u32,
    );
    push(
        &mut seq,
        q(SDMA6_QUEUE0_RB_WPTR_POLL_ADDR_HI_REL),
        (p.wptr_poll_phys >> 32) as u32,
    );
    // 5. Rptr writeback target (HI first, as Linux writes it).
    push(
        &mut seq,
        q(SDMA6_QUEUE0_RB_RPTR_ADDR_HI_REL),
        (p.rptr_writeback_phys >> 32) as u32,
    );
    push(
        &mut seq,
        q(SDMA6_QUEUE0_RB_RPTR_ADDR_LO_REL),
        p.rptr_writeback_phys as u32 & 0xFFFF_FFFC,
    );
    // 6. Size + priv + writeback + F32 poll, not yet enabled.
    let log2_size = p.ring_size_dw.trailing_zeros();
    let cntl_no_enable = (log2_size << SDMA_RB_SIZE_SHIFT)
        | SDMA_RB_PRIV
        | SDMA_RB_RPTR_WRITEBACK_ENABLE
        | SDMA_RB_F32_WPTR_POLL_ENABLE;
    debug_assert_eq!(cntl_no_enable & SDMA_RB_WPTR_POLL_ENABLE, 0);
    push(&mut seq, q(SDMA6_QUEUE0_RB_CNTL_REL), cntl_no_enable);
    // 7. Ring base.
    push(
        &mut seq,
        q(SDMA6_QUEUE0_RB_BASE_REL),
        (p.ring_phys >> 8) as u32,
    );
    push(
        &mut seq,
        q(SDMA6_QUEUE0_RB_BASE_HI_REL),
        (p.ring_phys >> 40) as u32,
    );
    // 8. Minor-pointer-update bracket opens.
    push(
        &mut seq,
        q(SDMA6_QUEUE0_MINOR_PTR_UPDATE_REL),
        SDMA_MINOR_PTR_UPDATE_ENABLE,
    );
    push(&mut seq, q(SDMA6_QUEUE0_RB_WPTR_REL), wptr as u32);
    push(
        &mut seq,
        q(SDMA6_QUEUE0_RB_WPTR_HI_REL),
        (wptr >> 32) as u32,
    );
    // 9. Doorbell.
    if p.use_doorbell {
        push(
            &mut seq,
            q(SDMA6_QUEUE0_DOORBELL_OFFSET_REL),
            p.doorbell_index << 2,
        );
        push(&mut seq, q(SDMA6_QUEUE0_DOORBELL_REL), SDMA_DOORBELL_ENABLE);
    } else {
        push(&mut seq, q(SDMA6_QUEUE0_DOORBELL_REL), 0);
    }
    // 10. Bracket closes.
    push(&mut seq, q(SDMA6_QUEUE0_MINOR_PTR_UPDATE_REL), 0);
    // 11. Hang watchdog (100 ms units).
    push(
        &mut seq,
        inst(SDMA60_WATCHDOG_CNTL_REL),
        p.watchdog_hang_100ms << SDMA60_WATCHDOG_QUEUE_HANG_COUNT_SHIFT,
    );
    // 12-13. UTCL1 tuning.
    push(
        &mut seq,
        inst(SDMA60_UTCL1_CNTL_REL),
        SDMA60_UTCL1_CNTL_COLD_START,
    );
    push(
        &mut seq,
        inst(SDMA60_UTCL1_PAGE_REL),
        SDMA60_UTCL1_PAGE_COLD_START,
    );
    // 14. Un-halt the F32 through the OTHER GC window, before enabling.
    push(
        &mut seq,
        hyp_reg(p.gc_base_idx1, p.instance, SDMA6_F32_CNTL_REL),
        SDMA60_F32_CNTL_COLD_START,
    );
    debug_assert_eq!(
        SDMA60_F32_CNTL_COLD_START & (SDMA_F32_HALT | SDMA_F32_TH1_RESET),
        0
    );
    // 15. Enable the ring.
    push(
        &mut seq,
        q(SDMA6_QUEUE0_RB_CNTL_REL),
        cntl_no_enable | SDMA_RB_ENABLE,
    );
    // 16. Enable indirect buffers, keeping the reset SWITCH_INSIDE_IB bit.
    push(
        &mut seq,
        q(SDMA6_QUEUE0_IB_CNTL_REL),
        SDMA60_IB_CNTL_COLD_START,
    );
    debug_assert_eq!(SDMA60_IB_CNTL_COLD_START & SDMA_IB_ENABLE, SDMA_IB_ENABLE);
    Ok(seq)
}

// ── Owner ──────────────────────────────────────────────────────────

/// The Navi3 SDMA 6.0 owner: validates the discovered SDMA revisions
/// against the die, builds ring-init/restore sequences for its instances,
/// and tracks which (instance, queue) pairs are programmed.
///
/// This owner performs no MMIO itself. The platform lane executes the
/// sequences once PSP dispatch works (see the module docs); until then the
/// owner is the validated, fixture-tested description of what the platform
/// lane will program.
#[derive(Debug)]
pub struct Sdma60 {
    die: Navi3Die,
    revision: (u8, u8, u8),
    instances: usize,
    programmed: [[bool; SDMA60_QUEUES_PER_INSTANCE as usize]; SDMA60_MAX_INSTANCES],
}

impl Sdma60 {
    /// Claim the SDMA engines for `die` from IP discovery.
    ///
    /// `sdma_versions` is one `(major, minor, revision)` per discovered
    /// SDMA HWID entry, in instance order. Every entry must equal the
    /// die's revision; at least one instance must exist and at most
    /// [`SDMA60_MAX_INSTANCES`].
    pub fn from_discovery(
        die: Navi3Die,
        sdma_versions: &[(u8, u8, u8)],
    ) -> Result<Self, Navi31SdmaError> {
        if sdma_versions.is_empty() {
            return Err(Navi31SdmaError::NoInstances);
        }
        if sdma_versions.len() > SDMA60_MAX_INSTANCES {
            return Err(Navi31SdmaError::TooManyInstances);
        }
        let revision = die.sdma_revision();
        if sdma_versions.iter().any(|&v| v != revision) {
            return Err(Navi31SdmaError::RevisionMismatch);
        }
        Ok(Self {
            die,
            revision,
            instances: sdma_versions.len(),
            programmed: [[false; SDMA60_QUEUES_PER_INSTANCE as usize]; SDMA60_MAX_INSTANCES],
        })
    }

    /// The die this owner was claimed for.
    pub fn die(&self) -> Navi3Die {
        self.die
    }

    /// The SDMA revision this owner validated (the die's revision).
    pub fn revision(&self) -> (u8, u8, u8) {
        self.revision
    }

    /// Discovered instance count (1..=2).
    pub fn instances(&self) -> usize {
        self.instances
    }

    /// Whether (`instance`, `queue`) was programmed by [`Sdma60::ring_init`]
    /// and not yet restored.
    pub fn is_programmed(&self, instance: usize, queue: usize) -> bool {
        self.programmed
            .get(instance)
            .and_then(|qs| qs.get(queue))
            .copied()
            .unwrap_or(false)
    }

    /// Build the cold-start ring-init sequence for (`params.instance`,
    /// `params.queue`) and record the queue as programmed.
    pub fn ring_init(
        &mut self,
        params: Navi31RingInit,
    ) -> Result<SdmaRingInitSequence, Navi31SdmaError> {
        if params.instance as usize >= self.instances {
            return Err(Navi31SdmaError::BadInstance);
        }
        if params.restore_wptr_bytes.is_some() {
            // A cold start never restores a wptr; use `ring_restore`.
            return Err(Navi31SdmaError::RestoreInInit);
        }
        let seq = build_navi31_sdma6_ring_init(params)?;
        self.programmed[params.instance as usize][params.queue as usize] = true;
        Ok(seq)
    }

    /// Build the reset-restore sequence for a programmed queue: the
    /// `sdma_v6_0_gfx_resume_instance(restore = true)` half of
    /// `sdma_v6_0_reset_queue`. The MES legacy-queue reset that precedes
    /// it in Linux is not built here (lane 5/6 remainder).
    ///
    /// `wptr_bytes` is the software write pointer the engine resumes at.
    pub fn ring_restore(
        &mut self,
        params: Navi31RingInit,
        wptr_bytes: u64,
    ) -> Result<SdmaRingInitSequence, Navi31SdmaError> {
        if params.instance as usize >= self.instances {
            return Err(Navi31SdmaError::BadInstance);
        }
        if !self.is_programmed(params.instance as usize, params.queue as usize) {
            return Err(Navi31SdmaError::NotProgrammed);
        }
        let mut restore = params;
        restore.restore_wptr_bytes = Some(wptr_bytes);
        build_navi31_sdma6_ring_init(restore)
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_sdma_navi31_tests.rs"]
mod tests;
