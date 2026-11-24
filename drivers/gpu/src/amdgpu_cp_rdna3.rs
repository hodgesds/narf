//! RDNA3 (Navi31/32/33) GFX11 CP/RLC/MES bring-up.
//!
//! The per-die CP stage for the 7000 series: which dies use MES-KIQ, the
//! RLC start sequence, the MES KIQ ring's identity and ring test, the MES
//! firmware set per die, and the MES topology the scheduler is told about.
//! Everything here is GC 11.0.x; the Phoenix APU (GC 11.0.1) shares the
//! builders but is not a `Family::Navi3` die and is not named here.
//!
//! ## MES-KIQ vs legacy KIQ — RESOLVED: MES-KIQ
//!
//! `amdgpu_discovery.c::amdgpu_discovery_set_mes_ip_blocks` sets
//! `enable_mes = true; enable_mes_kiq = true` for GC IP_VERSION(11, 0, 0),
//! (11, 0, 2) and (11, 0, 3) — Navi31/33/32 — as it does for every other
//! GFX11/GFX12 die. [`uses_mes_kiq`] is that switch, transcribed. The
//! consequence, in `gfx_v11_0_cp_resume`, is that Navi31 takes the
//! `amdgpu_mes_kiq_hw_init` arm and never the `gfx_v11_0_kiq_resume` arm:
//! the legacy `gfx_v11_0_kiq_init_register` (compute-MQD HQD programming)
//! does not run on this path. The KIQ ring's HQD is instead programmed by
//! `mes_v11_0_queue_init_register` — in-tree as
//! [`crate::amdgpu_mes_hw::build_mes_queue_init_register`] — because
//! `mes_v11_0_queue_init(AMDGPU_MES_KIQ_PIPE)` takes the KIQ ring itself
//! (`&adev->gfx.kiq[0].ring`) as the pipe's ring, and the KIQ ring's
//! coordinate is me 3, pipe 1, queue 0 (`mes_v11_0_kiq_ring_init`), not a
//! MEC coordinate. [`MES_KIQ_RING`] is that identity, and
//! [`kiq_rlc_schedulers_value`] is the `mes_v11_0_kiq_setting` write for it.
//!
//! ## What this module adds, and what it reuses
//!
//! New here: the per-die table ([`CpDie`], [`MesFirmware`]), the MES-KIQ
//! decision, the RLC start ([`build_rlc_start`] — no builder existed),
//! the KIQ ring identity and its ring-test packet
//! ([`build_kiq_ring_test_packet`] — the WRITE_DATA variant; the
//! SET_UCONFIG_REG variant for gfx/compute rings already exists as
//! [`crate::amdgpu_gfx::build_ring_test_packet`]), the ring-test poll
//! decision ([`decide_ring_test`]), and the RDNA3 MES topology
//! ([`RDNA3_TOPOLOGY`]).
//!
//! Reused, not duplicated: `build_gfx11_ring_init` (GFX ring),
//! `cp_compute_enable_value` (MEC enable), `cp_enable` (GFX enable),
//! `build_mes_enable`, `MesQueue::write_mqd` + `queue_init_sequence`
//! (both MES pipes), `build_set_hw_resources`, `build_query_mes_status`,
//! `build_map_queue` with [`crate::amdgpu_compute::RingKind::Mes`] (the
//! `mes_v11_0_kiq_enable_queue` MAP_QUEUES packet that binds the scheduler
//! ring onto the KIQ ring), and `build_preamble` (clearstate). The Navi31
//! ordering of all of them is [`crate::amdgpu_bringup::CP_RESUME_NAVI31`].
//!
//! ## Integration blockers — NOT fixed here
//!
//! * `AmdGpu::initialize()` still fails closed at `psp_dispatch_one`'s
//!   shared GPCOM-ring gap (lane 2's record). The CP stage cannot execute
//!   until PSP dispatch works; the coordinator dispatches a dedicated
//!   GPCOM-ring lane. This module builds sequences and packets, and nothing
//!   calls them yet.
//! * No Navi31 platform/run wiring: lane 1's identity skeleton is draft
//!   PR #2459 (unmerged) and lane 2's PSP/SMU surface is committed but
//!   unpushed (also unmerged). When #2459 merges, this stage wires into
//!   `amdgpu_navi31_platform`'s run loop; until then the wiring is the
//!   integration remainder.
//! * MES blob-to-pipe assignment is UNRESOLVED (flagged, never invented):
//!   [`MesFirmware`] tables the three blobs `mes_v11_0.c` declares per GC
//!   version by filename stem. Which pipe each feeds is decided by the
//!   firmware-request code in `amdgpu_mes.c`, which the ref tree's sparse
//!   checkout does not contain (`amdgpu_mes.c` / `amdgpu_gfx.c` are absent
//!   from `~/workspace/scratch/linux-amd-ref`).
//! * `gfx_v11_0_ring_test_ib` returns 0 early for a MES-KIQ ring ("MES KIQ
//!   fw hasn't indirect buffer support for now"), so the ring test — not
//!   the IB test — is the first hardware proof point for the KIQ ring.
//!
//! ## References (Linux 7.4-rc2, `~/workspace/scratch/linux-amd-ref`)
//!
//! - `drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c::amdgpu_discovery_set_mes_ip_blocks`
//! - `drivers/gpu/drm/amd/amdgpu/gfx_v11_0.c::gfx_v11_0_cp_resume`,
//!   `gfx_v11_0_rlc_start`, `gfx_v11_0_rlc_smu_handshake_cntl`,
//!   `gfx_v11_0_ring_test_ring`, `gfx_v11_0_ring_emit_wreg`,
//!   `gfx11_kiq_map_queues`, `gfx_v11_0_sw_init`
//! - `drivers/gpu/drm/amd/amdgpu/mes_v11_0.c::mes_v11_0_kiq_hw_init`,
//!   `mes_v11_0_kiq_ring_init`, `mes_v11_0_ring_init`,
//!   `mes_v11_0_queue_init`, `mes_v11_0_kiq_enable_queue`
//! - `drivers/gpu/drm/amd/include/asic_reg/gc/gc_11_0_0_offset.h`,
//!   `gc_11_0_0_sh_mask.h`

use crate::amdgpu_gfx::{Gfx11Sequence, RING_TEST_EXPECT, RING_TEST_SEED};
use crate::amdgpu_mes_hw::{rlc_cp_schedulers_value, MesTopology};
use crate::amdgpu_pm4_defs::{packet3, PACKET3_WRITE_DATA};

// ── Per-die identity ───────────────────────────────────────────────

/// The three RDNA3 discrete dies.
///
/// The die↔GC pairing is the corrected one (lane 1, PR #2459): Navi31 is
/// GC 11.0.0, Navi32 is GC 11.0.3, Navi33 is GC 11.0.2. The programme
/// record originally had Navi32/33 swapped; the firmware sets pin the
/// pairing down (Ubuntu LP#2034103, Gentoo firmware table, Mesa
/// `external_rev`), and this module follows lane 1's table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpDie {
    /// GC 11.0.0: RX 7900 XTX/XT/GRE, Radeon Pro W7900/W7800.
    Navi31,
    /// GC 11.0.3: RX 7800 XT / 7700 XT, Radeon Pro W7700/V710.
    Navi32,
    /// GC 11.0.2: RX 7600/7600 XT, Radeon Pro W7500.
    Navi33,
}

/// The three MES blobs `mes_v11_0.c` declares per GC version, by filename
/// stem — `amdgpu/gc_11_0_X_<stem>.bin`.
///
/// The stems are tabled, NOT assigned to pipes: which blob the PSP hands
/// each MES pipe is decided by the firmware-request code in
/// `amdgpu_mes.c`, which the ref tree's sparse checkout does not contain.
/// Do not read a pipe assignment into these field names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MesFirmware {
    /// `gc_11_0_X_mes.bin`.
    pub mes: &'static str,
    /// `gc_11_0_X_mes_2.bin`.
    pub mes_2: &'static str,
    /// `gc_11_0_X_mes1.bin`.
    pub mes1: &'static str,
}

impl CpDie {
    /// The die's discovered GC version.
    pub const fn gc_version(self) -> (u8, u8, u8) {
        match self {
            CpDie::Navi31 => (11, 0, 0),
            CpDie::Navi32 => (11, 0, 3),
            CpDie::Navi33 => (11, 0, 2),
        }
    }

    /// The die's MES firmware set, from `mes_v11_0.c` `MODULE_FIRMWARE`.
    pub const fn mes_firmware(self) -> MesFirmware {
        match self {
            CpDie::Navi31 => MesFirmware {
                mes: "amdgpu/gc_11_0_0_mes.bin",
                mes_2: "amdgpu/gc_11_0_0_mes_2.bin",
                mes1: "amdgpu/gc_11_0_0_mes1.bin",
            },
            CpDie::Navi32 => MesFirmware {
                mes: "amdgpu/gc_11_0_3_mes.bin",
                mes_2: "amdgpu/gc_11_0_3_mes_2.bin",
                mes1: "amdgpu/gc_11_0_3_mes1.bin",
            },
            CpDie::Navi33 => MesFirmware {
                mes: "amdgpu/gc_11_0_2_mes.bin",
                mes_2: "amdgpu/gc_11_0_2_mes_2.bin",
                mes1: "amdgpu/gc_11_0_2_mes1.bin",
            },
        }
    }

    /// The die's name, as the probe logs it.
    pub const fn name(self) -> &'static str {
        match self {
            CpDie::Navi31 => "Navi31",
            CpDie::Navi32 => "Navi32",
            CpDie::Navi33 => "Navi33",
        }
    }
}

/// Whether Linux enables MES-KIQ for this GC version.
///
/// `amdgpu_discovery_set_mes_ip_blocks`: (11, 0, 0..=4), (11, 5, 0..=4),
/// (11, 5, 6), (11, 7, 0..=1) take the `mes_v11_0` block with
/// `enable_mes_kiq = true`; (12, 0, 0..=1) and (12, 1, 0) take the v12
/// blocks with it likewise. Everything else — including GC 11.5.5, which
/// the switch skips — gets neither flag. The three RDNA3 dies are all in
/// the set, which is what resolves the MES-KIQ question for Navi31.
pub const fn uses_mes_kiq(gc: (u8, u8, u8)) -> bool {
    matches!(
        gc,
        (11, 0, 0..=4) | (11, 5, 0..=4) | (11, 5, 6) | (11, 7, 0..=1) | (12, 0, 0..=1) | (12, 1, 0)
    )
}

// ── MES ring identities ────────────────────────────────────────────

/// One MES ring's (me, pipe, queue) coordinate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MesRingCoord {
    pub me: u32,
    pub pipe: u32,
    pub queue: u32,
}

/// The MES scheduler ring: me 3, pipe 0, queue 0
/// (`mes_v11_0_ring_init`).
pub const MES_SCHED_RING: MesRingCoord = MesRingCoord {
    me: 3,
    pipe: 0,
    queue: 0,
};

/// The MES KIQ ring: me 3, pipe 1, queue 0
/// (`mes_v11_0_kiq_ring_init`).
///
/// This is the same ring as `adev->gfx.kiq[0].ring` — the MES KIQ pipe
/// runs on the KIQ ring, which is why `mes_v11_0_queue_init(KIQ_PIPE)`
/// takes it and why the RLC setting below names this coordinate rather
/// than a MEC one. It is NOT the coordinate `amdgpu_gfx_kiq_acquire`
/// would pick on the legacy path; that path does not run when MES-KIQ is
/// enabled.
pub const MES_KIQ_RING: MesRingCoord = MesRingCoord {
    me: 3,
    pipe: 1,
    queue: 0,
};

/// Both MES rings are 1024 dwords (`amdgpu_ring_init(adev, ring, 1024,
/// ...)` in `mes_v11_0_ring_init` and `mes_v11_0_kiq_ring_init`).
pub const MES_RING_DWORDS: u32 = 1024;

/// `mes_v11_0_kiq_setting` for the MES KIQ ring: tell the RLC which
/// queue is the KIQ, via [`rlc_cp_schedulers_value`] with (me 3, pipe 1,
/// queue 0).
pub const fn kiq_rlc_schedulers_value(live: u32) -> u32 {
    rlc_cp_schedulers_value(live, MES_KIQ_RING.me, MES_KIQ_RING.pipe, MES_KIQ_RING.queue)
}

/// A MES ring's doorbell index in the dword space: `mes_ringN << 1`
/// (`mes_v11_0_ring_init`: `mes_ring0 << 1`; `mes_v11_0_kiq_ring_init`:
/// `mes_ring1 << 1`). The `mes_ringN` values themselves come from
/// discovery (`adev->doorbell_index.mes_ring0/1`), not from a constant.
pub const fn mes_doorbell_dw(mes_ring_index: u32) -> u32 {
    mes_ring_index << 1
}

// ── MES topology ───────────────────────────────────────────────────

/// The MES topology for all three RDNA3 dies.
///
/// `gfx_v11_0_sw_init` assigns one arm to GC (11, 0, 0..=4) — Navi31,
/// Phoenix, Navi33, Navi32, Dragon Range alike: `num_me` 1,
/// `num_pipe_per_me` 1 when RS64 is enabled (else 2),
/// `num_queue_per_pipe` 2, `num_mec` 1, `num_pipe_per_mec` 4,
/// `num_queue_per_pipe` 4. `num_gfx_rings` is 1 because "rs64 only
/// supports one gfx pipe". `first_kfd_vmid` 8 is the `gmc_v11_0.c`
/// value with `disable_kq` false, as on Phoenix.
///
/// `num_compute_rings` 8 is `min(amdgpu_gfx_get_num_kcq(), 8)` with the
/// same MEC geometry as Phoenix, so the same value — with one caveat:
/// `amdgpu_gfx_get_num_kcq` lives in `amdgpu_gfx.c`, which the ref tree's
/// sparse checkout does not contain, so the 8 rests on the shared-arm
/// argument rather than a direct read of that function. `num_sdma_instances`
/// 1 is the Phoenix value for the test; the real value comes from the
/// discovery table at runtime (SDMA 6.0 is lane 6's neighbour, not this
/// lane's).
pub const RDNA3_TOPOLOGY: MesTopology = MesTopology {
    num_me: 1,
    num_pipe_per_me: 1,
    num_queue_per_pipe_gfx: 2,
    num_gfx_rings: 1,
    num_mec: 1,
    num_pipe_per_mec: 4,
    num_queue_per_pipe_compute: 4,
    num_compute_rings: 8,
    num_sdma_instances: 1,
    first_kfd_vmid: 8,
    db_start_dw_offset: 0,
};

// ── RLC start ──────────────────────────────────────────────────────

/// `regRLC_CNTL` — GC BASE_IDX 1 (`gc_11_0_0_offset.h`).
pub const RLC_CNTL: u32 = 0x4c00;
/// `regRLC_PG_CNTL` — GC BASE_IDX 1 (`gc_11_0_0_offset.h`).
pub const RLC_PG_CNTL: u32 = 0x4c43;
/// `RLC_CNTL__RLC_ENABLE_F32_MASK` — bit 0 (`gc_11_0_0_sh_mask.h`).
pub const RLC_ENABLE_F32: u32 = 1 << 0;
/// `RLC_PG_CNTL__SMU_HANDSHAKE_DISABLE_MASK` — bit 23
/// (`gc_11_0_0_sh_mask.h`).
pub const RLC_PG_SMU_HANDSHAKE_DISABLE: u32 = 1 << 23;
/// `udelay(50)` at the end of `gfx_v11_0_rlc_start`.
pub const RLC_START_DELAY_US: u32 = 50;

/// `gfx_v11_0_rlc_start` — start the RLC.
///
/// ```text
/// if (!(amdgpu_pp_feature_mask & PP_GFXOFF_MASK))
///     gfx_v11_0_rlc_smu_handshake_cntl(adev, false);   // set RLC_PG_CNTL[23]
/// WREG32_FIELD15_PREREG(GC, 0, RLC_CNTL, RLC_ENABLE_F32, 1);
/// udelay(50);
/// ```
///
/// `gfxoff_enabled` is the `PP_GFXOFF_MASK` bit of the driver's power
/// feature mask, inverted: with GFXOFF off, the RLC/SMU handshake is
/// disabled first (`RLC_PG_CNTL[23] = 1` — "RLC will not issue any message
/// to SMU ... GFXOFF will be disabled"), because the RLC would otherwise
/// wait for handshake acks the SMU never sends. Both writes are
/// read-modify-writes on the caller's live values, as in Linux.
///
/// This is the gfx IP block's `.start` hook
/// (`gfx_v11_0_rlc_funcs.start`), and it precedes the CP resume sequence:
/// `gfx_v11_0_hw_init` resumes the RLC before the CP (`rlc_resume` then
/// `cp_resume`), and the DIRECT-load branch of `rlc_resume` itself runs
/// `.start` before `hw_init` proceeds to the CP. (The core call site that
/// runs `.start` on PSP-load parts lives in `amdgpu_gfx.c`, which the ref
/// tree's sparse checkout does not contain; the RLC-before-CP order is
/// what the tree shows, and this plan follows it — see
/// [`crate::amdgpu_bringup::CP_RESUME_NAVI31`].)
pub fn build_rlc_start(
    gc_base_idx1: u32,
    live_pg_cntl: u32,
    live_cntl: u32,
    gfxoff_enabled: bool,
) -> Gfx11Sequence {
    let mut seq = Gfx11Sequence::default();
    if !gfxoff_enabled {
        seq.write(
            gc_base_idx1,
            RLC_PG_CNTL,
            live_pg_cntl | RLC_PG_SMU_HANDSHAKE_DISABLE,
        );
    }
    seq.write(gc_base_idx1, RLC_CNTL, live_cntl | RLC_ENABLE_F32);
    seq.delay(RLC_START_DELAY_US);
    seq
}

// ── KIQ ring test ──────────────────────────────────────────────────

/// `gfx_v11_0_ring_emit_wreg`'s `cmd` for a KIQ ring: `1 << 16`
/// ("no inc addr"). The GFX ring uses `WRITE_DATA_ENGINE_SEL(1) |
/// WR_CONFIRM` and any other ring `WR_CONFIRM`; the KIQ ring is the
/// only one with this value, which is why it is a named constant rather
/// than a literal in the packet below.
pub const KIQ_WREG_NO_INC_ADDR: u32 = 1 << 16;

/// `gfx_v11_0_ring_test_ring`'s packet for the KIQ ring.
///
/// The gfx/compute rings get `PACKET3(SET_UCONFIG_REG, 1)` from
/// [`crate::amdgpu_gfx::build_ring_test_packet`]; the KIQ ring gets a
/// `PACKET3(WRITE_DATA, 3)` through `gfx_v11_0_ring_emit_wreg`:
///
/// ```text
/// [PACKET3(WRITE_DATA, 3), 1 << 16, scratch, 0, 0xDEADBEEF]
/// ```
///
/// `scratch_dword` is the *resolved* dword address of `SCRATCH_REG0` —
/// [`crate::amdgpu_gfx::ring_test_scratch_dword`] — not the
/// aperture-relative offset the SET_UCONFIG_REG packet carries. The host
/// seeds that register with [`RING_TEST_SEED`](crate::amdgpu_gfx::RING_TEST_SEED)
/// before submitting and polls it for
/// [`RING_TEST_EXPECT`](crate::amdgpu_gfx::RING_TEST_EXPECT); see
/// [`decide_ring_test`].
///
/// This packet is the `mes_v11_0_kiq_enable_queue` proof point: after the
/// scheduler ring is MAP_QUEUES-bound onto the KIQ ring, Linux runs
/// `amdgpu_ring_test_helper(kiq_ring)`, which is this test.
pub fn build_kiq_ring_test_packet(scratch_dword: u32) -> [u32; 5] {
    [
        packet3(PACKET3_WRITE_DATA, 3),
        KIQ_WREG_NO_INC_ADDR,
        scratch_dword,
        0,
        RING_TEST_EXPECT,
    ]
}

/// The verdict of polling `SCRATCH_REG0` after a ring test packet.
///
/// Linux polls up to `adev->usec_timeout`, one microsecond at a time
/// (1 ms sleeps under emulation), and passes on the first read of
/// `0xDEADBEEF`. The seed is what the host wrote before submitting, so
/// a read that is neither the seed nor the expected value means some
/// other writer touched the register — or the register does not exist
/// and reads as all-ones — and must not look like a pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingTestOutcome {
    /// The expected value appeared, after this many polls.
    Pass { polls: usize },
    /// Every poll read the seed: the packet never executed.
    Timeout,
    /// A poll read a value that is neither the seed nor the expected
    /// value. The offending value is carried so the failure names it.
    Corrupted(u32),
}

/// Decide a ring test from the polled `SCRATCH_REG0` values, in order.
///
/// `Pass` on the first [`RING_TEST_EXPECT`](crate::amdgpu_gfx::RING_TEST_EXPECT),
/// `Corrupted` on the first value that is neither the seed nor the
/// expected value, `Timeout` when the reads run out without either.
pub fn decide_ring_test(polls: &[u32]) -> RingTestOutcome {
    for (i, &v) in polls.iter().enumerate() {
        if v == RING_TEST_EXPECT {
            return RingTestOutcome::Pass { polls: i + 1 };
        }
        if v != RING_TEST_SEED {
            return RingTestOutcome::Corrupted(v);
        }
    }
    RingTestOutcome::Timeout
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_cp_rdna3_tests.rs"]
mod tests;
