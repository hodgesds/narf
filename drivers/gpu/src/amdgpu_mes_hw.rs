//! MES hardware bring-up — `mes_v11_0_enable` and the register reads around it.
//!
//! [`crate::amdgpu_mes`] is the MES *protocol*: packets, the ring that carries
//! them, the two-fence submit. None of it can run until the MES processor is
//! out of reset and executing its microcode, and that is a register sequence
//! this module builds.
//!
//! ## Where this sits in bring-up
//!
//! On every GFX11 part `amdgpu_discovery.c` sets both `enable_mes` and
//! `enable_mes_kiq`, so the order is `gfx_v11_0_cp_resume` →
//! `amdgpu_mes_kiq_hw_init` → `mes_v11_0_kiq_hw_init`, which:
//!
//!   1. loads the microcode — on Phoenix the PSP does this, so
//!      `mes_v11_0_load_microcode` is not on the path
//!   2. **`mes_v11_0_enable(adev, true)`** — [`build_mes_enable`]
//!   3. reads the firmware versions — [`fw_version_select`]
//!   4. tells the RLC which queue is the KIQ — [`rlc_cp_schedulers_value`]
//!   5. `mes_v11_0_queue_init(KIQ_PIPE)`, then `mes_v11_0_hw_init` for the
//!      scheduler pipe: `queue_init`, `SET_HW_RSRC`, `QUERY_SCHEDULER_STATUS`
//!
//! Steps 2 through 4 are here. Step 5's packets are in
//! [`crate::amdgpu_mes`]; what is still missing between them is the MES MQD
//! and the host side that drives this, which is recorded at the bottom of this
//! file.
//!
//! ## Everything here is GC BASE_IDX 1
//!
//! `CP_MES_*`, `GRBM_GFX_CNTL` and `RLC_CP_SCHEDULERS` all carry
//! `_BASE_IDX 1` in `gc_11_0_0_offset.h`. A single `gc_base` would address the
//! second window's registers through the first, which is the defect this
//! branch fixed in `read_aperture_layout`, `write_grbm_gfx_index` and the SDMA
//! F32 unhalt. So the base parameter is named `gc_base_idx1` and there is no
//! other.

use crate::amdgpu_gfx::Gfx11Sequence;

// ── Registers (all GC BASE_IDX 1) ─────────────────────────────────

/// `regCP_MES_PRGRM_CNTR_START` — the pipe's entry point, as a **dword**
/// address: `mes_v11_0_enable` writes `uc_start_addr >> 2`.
pub const CP_MES_PRGRM_CNTR_START: u32 = 0x2800;
/// `regCP_MES_PRGRM_CNTR_START_HI`. Not adjacent to the low half — 0x289d
/// against 0x2800 — so this is a pair that has to be looked up, not derived.
pub const CP_MES_PRGRM_CNTR_START_HI: u32 = 0x289D;
/// `regCP_MES_CNTL`.
pub const CP_MES_CNTL: u32 = 0x2807;
/// `regCP_MES_GP3_LO` — read per pipe for that pipe's firmware version.
pub const CP_MES_GP3_LO: u32 = 0x2849;
/// `regCP_MES_MSCRATCH_HI`. **Below** `_LO`: 0x2814 against 0x2815. The same
/// inversion as SDMA's `RB_WPTR_POLL_ADDR_HI`/`_LO`, and the same reason to
/// name both rather than write `LO + 1`.
pub const CP_MES_MSCRATCH_HI: u32 = 0x2814;
/// `regCP_MES_MSCRATCH_LO`.
pub const CP_MES_MSCRATCH_LO: u32 = 0x2815;
/// `regGRBM_GFX_CNTL` — the me/pipe/queue/vmid selector.
pub const GRBM_GFX_CNTL: u32 = 0x0900;
/// `regRLC_CP_SCHEDULERS`.
pub const RLC_CP_SCHEDULERS: u32 = 0x098A;

// ── The HQD registers (all GC BASE_IDX 0) ─────────────────────────
//
// The selector above is window 1 and these are window 0, so
// [`build_mes_queue_init_register`] needs both bases. That is the same split
// `build_gfx11_ring_init` has, and for the same reason.

pub const CP_MQD_BASE_ADDR: u32 = 0x1FA9;
pub const CP_MQD_BASE_ADDR_HI: u32 = 0x1FAA;
pub const CP_HQD_ACTIVE: u32 = 0x1FAB;
pub const CP_HQD_VMID: u32 = 0x1FAC;
pub const CP_HQD_PERSISTENT_STATE: u32 = 0x1FAD;
pub const CP_HQD_PQ_BASE: u32 = 0x1FB1;
pub const CP_HQD_PQ_BASE_HI: u32 = 0x1FB2;
pub const CP_HQD_PQ_RPTR_REPORT_ADDR: u32 = 0x1FB4;
pub const CP_HQD_PQ_RPTR_REPORT_ADDR_HI: u32 = 0x1FB5;
pub const CP_HQD_PQ_WPTR_POLL_ADDR: u32 = 0x1FB6;
pub const CP_HQD_PQ_WPTR_POLL_ADDR_HI: u32 = 0x1FB7;
pub const CP_HQD_PQ_DOORBELL_CONTROL: u32 = 0x1FB8;
pub const CP_HQD_PQ_CONTROL: u32 = 0x1FBA;
/// Not adjacent to the rest: 0x1fcb against the 0x1fa9..0x1fba cluster.
pub const CP_MQD_CONTROL: u32 = 0x1FCB;

/// `CP_HQD_VMID__VMID_MASK`.
pub const HQD_VMID_MASK: u32 = 0x0000_000F;
/// `CP_HQD_PQ_DOORBELL_CONTROL__DOORBELL_EN_MASK`.
pub const HQD_DOORBELL_EN: u32 = 0x4000_0000;
/// `CP_MQD_CONTROL__PRIV_STATE_MASK` — see
/// [`build_mes_queue_init_register`] for why this one is named.
pub const MQD_CONTROL_PRIV_STATE: u32 = 0x0000_0100;

// ── CP_MES_CNTL fields ────────────────────────────────────────────

pub const MES_INVALIDATE_ICACHE: u32 = 1 << 4;
pub const MES_PIPE0_RESET: u32 = 1 << 16;
pub const MES_PIPE1_RESET: u32 = 1 << 17;
pub const MES_PIPE0_ACTIVE: u32 = 1 << 26;
pub const MES_PIPE1_ACTIVE: u32 = 1 << 27;
pub const MES_HALT: u32 = 1 << 30;
pub const MES_STEP: u32 = 1 << 31;

// ── GRBM_GFX_CNTL fields ──────────────────────────────────────────

pub const GRBM_PIPEID_SHIFT: u32 = 0;
pub const GRBM_PIPEID_MASK: u32 = 0x0000_0003;
pub const GRBM_MEID_SHIFT: u32 = 2;
pub const GRBM_MEID_MASK: u32 = 0x0000_000C;
pub const GRBM_VMID_SHIFT: u32 = 4;
pub const GRBM_VMID_MASK: u32 = 0x0000_00F0;
pub const GRBM_QUEUEID_SHIFT: u32 = 8;
pub const GRBM_QUEUEID_MASK: u32 = 0x0000_0700;

/// The MES pipes. `AMDGPU_MES_SCHED_PIPE` is pipe 0 and
/// `AMDGPU_MES_KIQ_PIPE` is pipe 1; `AMDGPU_MAX_MES_PIPES` is 2.
pub const MES_SCHED_PIPE: u32 = 0;
pub const MES_KIQ_PIPE: u32 = 1;
pub const MES_PIPES: u32 = 2;

/// `me` value the MES pipes answer on. Not 0 — the graphics ME is 0 and the
/// MECs are 1 and 2; the MES is **3**, and selecting me 0 would point
/// `CP_MES_PRGRM_CNTR_START` at the graphics engine's view of that offset.
pub const MES_ME_ID: u32 = 3;

/// `udelay(500)` after the pipes are activated, before anything is asked of
/// them. (`amdgpu_emu_mode` waits 100 ms instead; there is no emulation mode
/// here.)
pub const MES_ENABLE_DELAY_US: u32 = 500;

/// `soc21_grbm_select` — the me/pipe/queue/vmid selector value.
///
/// Built from **zero**, which is the part that matters.
/// `gfx_v11_0_cp_gfx_switch_pipe` reads `GRBM_GFX_CNTL` and sets only PIPEID,
/// preserving the rest; `soc21_grbm_select` composes the whole register. Two
/// conventions for one register, and using the read-modify-write form here
/// would leave whatever ME, queue and VMID the previous selection left behind,
/// so the `CP_MES_*` writes would land on some other engine's registers.
pub const fn grbm_select(me: u32, pipe: u32, queue: u32, vmid: u32) -> u32 {
    ((pipe << GRBM_PIPEID_SHIFT) & GRBM_PIPEID_MASK)
        | ((me << GRBM_MEID_SHIFT) & GRBM_MEID_MASK)
        | ((vmid << GRBM_VMID_SHIFT) & GRBM_VMID_MASK)
        | ((queue << GRBM_QUEUEID_SHIFT) & GRBM_QUEUEID_MASK)
}

/// The selector that exposes `pipe`'s `CP_MES_GP3_LO`, which holds that pipe's
/// firmware version.
///
/// `mes_v11_0_get_fw_version` selects each pipe in turn, reads `GP3_LO`, and
/// restores the selection to all-zero afterwards. A read cannot be part of a
/// [`Gfx11Sequence`], so this hands the caller the two selector values and the
/// register id instead of pretending to do the read.
pub const fn fw_version_select(pipe: u32) -> u32 {
    grbm_select(MES_ME_ID, pipe, 0, 0)
}

/// `mes_v11_0_kiq_setting` — tell the RLC which queue is the KIQ.
///
/// `live` is the current `RLC_CP_SCHEDULERS`; its low byte is replaced and
/// bit 7 set. The packing is hand-rolled in Linux rather than done with
/// `REG_SET_FIELD`, so it is transcribed the same way: `me << 5 | pipe << 3 |
/// queue`, then `| 0x80`.
pub const fn rlc_cp_schedulers_value(live: u32, me: u32, pipe: u32, queue: u32) -> u32 {
    (live & 0xffff_ff00) | (me << 5) | (pipe << 3) | queue | 0x80
}

/// `mes_v11_0_enable(adev, true)` — take the MES pipes out of reset, point
/// them at their microcode, and activate them.
///
/// `uc_start_addr` is each pipe's entry point as a byte address;
/// `uc_start_addr[MES_KIQ_PIPE]` is ignored when `kiq_pipe` is false. The
/// register holds the address shifted right by **2** — it counts dwords — so
/// an entry point whose low two bits are set cannot be expressed, and this
/// returns `None` rather than silently rounding the processor's entry point
/// down by up to three bytes.
///
/// `mscratch` is the event-log address (`amdgpu_mes_log_enable`), with
/// `AMDGPU_MES_LOG_BUFFER_SIZE` already added by the caller as Linux adds it.
/// `None` leaves the pair alone, which is the default build.
///
/// ## The two `CP_MES_CNTL` writes are not the same shape
///
/// The first is a **read-modify-write**: it takes `live_cntl` and asserts the
/// pipe resets, leaving every other bit as found. The second is composed from
/// **zero** — so it sets ACTIVE and in the same write clears RESET, HALT and
/// INVALIDATE_ICACHE. Reading-modifying the second would leave the pipe reset
/// asserted alongside its active bit, and the processor would never run. That
/// asymmetry is in `mes_v11_0_enable` and is the only reason `live_cntl` is a
/// parameter at all.
pub fn build_mes_enable(
    gc_base_idx1: u32,
    live_cntl: u32,
    uc_start_addr: [u64; MES_PIPES as usize],
    kiq_pipe: bool,
    mscratch: Option<u64>,
) -> Option<Gfx11Sequence> {
    let mut seq = Gfx11Sequence::default();

    if let Some(addr) = mscratch {
        seq.write(gc_base_idx1, CP_MES_MSCRATCH_LO, addr as u32);
        seq.write(gc_base_idx1, CP_MES_MSCRATCH_HI, (addr >> 32) as u32);
    }

    // Assert the resets, preserving the rest of the live register.
    let mut data = live_cntl | MES_PIPE0_RESET;
    if kiq_pipe {
        data |= MES_PIPE1_RESET;
    } else {
        data &= !MES_PIPE1_RESET;
    }
    seq.write(gc_base_idx1, CP_MES_CNTL, data);

    // Per-pipe entry point, each behind its own me/pipe selection.
    for pipe in 0..MES_PIPES {
        if !kiq_pipe && pipe == MES_KIQ_PIPE {
            continue;
        }
        let start = uc_start_addr[pipe as usize];
        if start & 0x3 != 0 {
            return None;
        }
        let dwords = start >> 2;
        seq.write(
            gc_base_idx1,
            GRBM_GFX_CNTL,
            grbm_select(MES_ME_ID, pipe, 0, 0),
        );
        seq.write(gc_base_idx1, CP_MES_PRGRM_CNTR_START, dwords as u32);
        seq.write(
            gc_base_idx1,
            CP_MES_PRGRM_CNTR_START_HI,
            (dwords >> 32) as u32,
        );
    }
    // Restore the selection. Leaving the MES selected would send the next
    // block's writes to it.
    seq.write(gc_base_idx1, GRBM_GFX_CNTL, grbm_select(0, 0, 0, 0));

    // Unhalt. Composed from zero: see the note above.
    let mut active = MES_PIPE0_ACTIVE;
    if kiq_pipe {
        active |= MES_PIPE1_ACTIVE;
    }
    seq.write(gc_base_idx1, CP_MES_CNTL, active);
    seq.delay(MES_ENABLE_DELAY_US);

    Some(seq)
}

/// `mes_v11_0_enable(adev, false)` — halt the pipes and invalidate their
/// instruction cache.
///
/// One read-modify-write, unlike the enable path's two writes: clearing ACTIVE
/// and setting RESET, HALT and INVALIDATE_ICACHE together is what stops the
/// processor cleanly.
pub fn build_mes_disable(gc_base_idx1: u32, live_cntl: u32, kiq_pipe: bool) -> Gfx11Sequence {
    let mut seq = Gfx11Sequence::default();
    let mut data = live_cntl;
    data &= !(MES_PIPE0_ACTIVE | MES_PIPE1_ACTIVE);
    data |= MES_INVALIDATE_ICACHE | MES_PIPE0_RESET | MES_HALT;
    if kiq_pipe {
        data |= MES_PIPE1_RESET;
    } else {
        data &= !MES_PIPE1_RESET;
    }
    seq.write(gc_base_idx1, CP_MES_CNTL, data);
    seq
}

/// `mes_v11_0_queue_init_register` — push the descriptor into the live HQD
/// registers for `pipe`.
///
/// The MES scheduler's own queue is not mapped by anything; there is no
/// scheduler above it to do that. So the driver writes thirteen of the
/// descriptor's fields straight into the hardware queue-descriptor registers,
/// behind a me-3/pipe selection, and sets `CP_HQD_ACTIVE` itself. That is why
/// [`crate::amdgpu_mqd::mes_mqd_init`] puts a 1 in `cp_hqd_active` where the
/// compute path puts a 0.
///
/// `mqd` is the descriptor as that function returns it; the values come from
/// there rather than from a property struct, so the registers and the
/// descriptor cannot disagree.
///
/// `live_vmid` and `live_doorbell` are the current `CP_HQD_VMID` and
/// `CP_HQD_PQ_DOORBELL_CONTROL`, read after the pipe has been selected. Both
/// are read-modify-written — the first to force VMID to 0, the second to clear
/// `DOORBELL_EN` before the descriptor's own doorbell value is written over
/// it a few steps later. Disabling the doorbell first is what stops a doorbell
/// ring landing while the queue is half-described.
///
/// ## `CP_MQD_CONTROL` is written as a literal zero
///
/// Linux computes it and then does not use it:
///
/// ```text
/// data = RREG32_SOC15(GC, 0, regCP_MQD_CONTROL);
/// data = REG_SET_FIELD(data, CP_MQD_CONTROL, VMID, 0);
/// WREG32_SOC15(GC, 0, regCP_MQD_CONTROL, 0);
/// ```
///
/// The computed `data` is discarded and 0 goes to the register. Since
/// `regCP_MQD_CONTROL_DEFAULT` is 0x00000100 — `PRIV_STATE` — the live
/// register ends up with `PRIV_STATE` **clear**, while the descriptor's own
/// `cp_mqd_control` field holds 0x100. The two disagree, deliberately or not.
///
/// Transcribed as-is, with the same reasoning as the `RPTR_BLOCK_SIZE` double
/// shift in `mes_mqd_init`: this is what every machine running this firmware
/// has had in that register. Writing the descriptor's value instead would be a
/// one-driver divergence in the MQD-privilege state of the scheduler's own
/// queue, which is not a thing to discover on hardware.
pub fn build_mes_queue_init_register(
    gc_base_idx0: u32,
    gc_base_idx1: u32,
    pipe: u32,
    mqd: &[u32; crate::amdgpu_mqd::COMPUTE_MQD_DWORDS],
    live_vmid: u32,
    live_doorbell: u32,
) -> Gfx11Sequence {
    use crate::amdgpu_mqd as m;
    let mut seq = Gfx11Sequence::default();

    // Select me 3, this pipe. Window 1.
    seq.write(
        gc_base_idx1,
        GRBM_GFX_CNTL,
        grbm_select(MES_ME_ID, pipe, 0, 0),
    );

    // VMID 0, preserving IB_VMID and VQID.
    seq.write(gc_base_idx0, CP_HQD_VMID, live_vmid & !HQD_VMID_MASK);
    // Doorbell off while the queue is described.
    seq.write(
        gc_base_idx0,
        CP_HQD_PQ_DOORBELL_CONTROL,
        live_doorbell & !HQD_DOORBELL_EN,
    );

    seq.write(
        gc_base_idx0,
        CP_MQD_BASE_ADDR,
        mqd[m::C_CP_MQD_BASE_ADDR_LO],
    );
    seq.write(
        gc_base_idx0,
        CP_MQD_BASE_ADDR_HI,
        mqd[m::C_CP_MQD_BASE_ADDR_HI],
    );
    // The literal zero. See above.
    seq.write(gc_base_idx0, CP_MQD_CONTROL, 0);

    seq.write(gc_base_idx0, CP_HQD_PQ_BASE, mqd[m::C_CP_HQD_PQ_BASE_LO]);
    seq.write(gc_base_idx0, CP_HQD_PQ_BASE_HI, mqd[m::C_CP_HQD_PQ_BASE_HI]);
    seq.write(
        gc_base_idx0,
        CP_HQD_PQ_RPTR_REPORT_ADDR,
        mqd[m::C_CP_HQD_PQ_RPTR_REPORT_ADDR_LO],
    );
    seq.write(
        gc_base_idx0,
        CP_HQD_PQ_RPTR_REPORT_ADDR_HI,
        mqd[m::C_CP_HQD_PQ_RPTR_REPORT_ADDR_HI],
    );
    seq.write(gc_base_idx0, CP_HQD_PQ_CONTROL, mqd[m::C_CP_HQD_PQ_CONTROL]);
    seq.write(
        gc_base_idx0,
        CP_HQD_PQ_WPTR_POLL_ADDR,
        mqd[m::C_CP_HQD_PQ_WPTR_POLL_ADDR_LO],
    );
    seq.write(
        gc_base_idx0,
        CP_HQD_PQ_WPTR_POLL_ADDR_HI,
        mqd[m::C_CP_HQD_PQ_WPTR_POLL_ADDR_HI],
    );
    // Now the descriptor's doorbell, over the disabled one written above.
    seq.write(
        gc_base_idx0,
        CP_HQD_PQ_DOORBELL_CONTROL,
        mqd[m::C_CP_HQD_PQ_DOORBELL_CONTROL],
    );
    seq.write(
        gc_base_idx0,
        CP_HQD_PERSISTENT_STATE,
        mqd[m::C_CP_HQD_PERSISTENT_STATE],
    );
    // And activate, last.
    seq.write(gc_base_idx0, CP_HQD_ACTIVE, mqd[m::C_CP_HQD_ACTIVE]);

    // Restore the selection.
    seq.write(gc_base_idx1, GRBM_GFX_CNTL, grbm_select(0, 0, 0, 0));
    seq
}

// LINUX-GAP: `mes_v11_0_queue_init_register` is not built. The descriptor
// itself now is — [`crate::amdgpu_mqd::mes_mqd_init`] — but the function that
// pushes thirteen of its fields into the live `CP_HQD_*` registers, behind a
// me-3/pipe selection, is not. It is the MES equivalent of
// `build_gfx11_ring_init` and the same shape; what it needs that this module
// does not yet have is the pipe's ring and writeback allocations, the way
// `GfxContext` holds the graphics ring's.
//
// So nothing here is reachable from a probe yet: this module builds the
// sequences and nothing calls them.

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod smoke_tests {
    use super::*;
    use crate::amdgpu_gfx::GfxStep;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Register ids and field positions, from `gc_11_0_0_offset.h` and
    /// `gc_11_0_0_sh_mask.h`.
    fn smoke_mes_hw_register_table() -> TestResult {
        if (CP_MES_PRGRM_CNTR_START, CP_MES_PRGRM_CNTR_START_HI) != (0x2800, 0x289D) {
            return TestResult::Fail("the entry-point pair is 0x2800 / 0x289d, not adjacent");
        }
        if (CP_MES_CNTL, CP_MES_GP3_LO) != (0x2807, 0x2849) {
            return TestResult::Fail("CP_MES_CNTL 0x2807, CP_MES_GP3_LO 0x2849");
        }
        // The HI is the LOWER id. Deriving one from the other gets this wrong.
        if CP_MES_MSCRATCH_HI >= CP_MES_MSCRATCH_LO {
            return TestResult::Fail("CP_MES_MSCRATCH_HI sits below _LO");
        }
        if (CP_MES_MSCRATCH_HI, CP_MES_MSCRATCH_LO) != (0x2814, 0x2815) {
            return TestResult::Fail("the mscratch pair is 0x2814 / 0x2815");
        }
        if (GRBM_GFX_CNTL, RLC_CP_SCHEDULERS) != (0x0900, 0x098A) {
            return TestResult::Fail("GRBM_GFX_CNTL 0x0900, RLC_CP_SCHEDULERS 0x098a");
        }

        // CP_MES_CNTL: the ACTIVE bits are at 26/27 and HALT at 30, which a
        // one-bit-per-field reading of the struct would not produce.
        let bits = [
            (MES_INVALIDATE_ICACHE, 0x0000_0010u32),
            (MES_PIPE0_RESET, 0x0001_0000),
            (MES_PIPE1_RESET, 0x0002_0000),
            (MES_PIPE0_ACTIVE, 0x0400_0000),
            (MES_PIPE1_ACTIVE, 0x0800_0000),
            (MES_HALT, 0x4000_0000),
            (MES_STEP, 0x8000_0000),
        ];
        for (got, want) in bits {
            if got != want {
                return TestResult::Fail("a CP_MES_CNTL field is at the wrong bit");
            }
        }

        // The MES answers on me 3. me 0 is the graphics ME.
        if MES_ME_ID != 3 || MES_PIPES != 2 || MES_SCHED_PIPE != 0 || MES_KIQ_PIPE != 1 {
            return TestResult::Fail("the MES me id is 3 and it has two pipes");
        }
        if MES_ENABLE_DELAY_US != 500 {
            return TestResult::Fail("mes_v11_0_enable waits 500 us after activating");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/amdgpu/mes_hw", smoke_mes_hw_register_table);

    /// `soc21_grbm_select` composes from zero, and each field is where
    /// `gc_11_0_0_sh_mask.h` puts it.
    fn smoke_mes_hw_grbm_select_composes_from_zero() -> TestResult {
        // PIPEID 0, MEID 2, VMID 4, QUEUEID 8.
        if grbm_select(3, 2, 5, 7) != (2 | (3 << 2) | (7 << 4) | (5 << 8)) {
            return TestResult::Fail("a GRBM_GFX_CNTL field is at the wrong shift");
        }
        // Every field is masked, so an out-of-range argument cannot reach a
        // neighbour: me is two bits, pipe two, vmid four, queue three.
        let all = grbm_select(!0, !0, !0, !0);
        if all != (GRBM_PIPEID_MASK | GRBM_MEID_MASK | GRBM_VMID_MASK | GRBM_QUEUEID_MASK) {
            return TestResult::Fail("the fields are not masked to their own widths");
        }
        // CTXID at 11 and everything above it must stay clear.
        if all & !0x0000_07FF != 0 {
            return TestResult::Fail("the selector must not reach CTXID or above");
        }
        // Selecting the MES scheduler pipe: me 3, pipe 0.
        if fw_version_select(MES_SCHED_PIPE) != 3 << 2 {
            return TestResult::Fail("the sched pipe selector is me 3, pipe 0");
        }
        if fw_version_select(MES_KIQ_PIPE) != (3 << 2) | 1 {
            return TestResult::Fail("the KIQ pipe selector is me 3, pipe 1");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/mes_hw",
        smoke_mes_hw_grbm_select_composes_from_zero
    );

    /// The enable sequence, step for step against `mes_v11_0_enable`.
    ///
    /// The substance is the asymmetry between its two `CP_MES_CNTL` writes: the
    /// first preserves the live register and asserts reset, the second is built
    /// from zero so activating also releases the reset and the halt.
    fn smoke_mes_hw_enable_sequence() -> TestResult {
        const GC1: u32 = 0x0005_0000;
        // A live CNTL with unrelated bits set, so a read-modify-write is
        // distinguishable from a compose-from-zero.
        const LIVE: u32 = MES_HALT | MES_STEP | MES_INVALIDATE_ICACHE;
        const SCHED_UC: u64 = 0x0000_0012_3456_7800;
        const KIQ_UC: u64 = 0x0000_0098_7654_3200;

        let seq = match build_mes_enable(GC1, LIVE, [SCHED_UC, KIQ_UC], true, None) {
            Some(s) => s,
            None => return TestResult::Fail("a well-formed enable was refused"),
        };

        let cntl_writes = seq.writes_to(GC1, CP_MES_CNTL);
        if cntl_writes.len() != 2 {
            return TestResult::Fail("CP_MES_CNTL is written exactly twice");
        }
        // First: live | both resets, everything else preserved.
        if cntl_writes[0] != LIVE | MES_PIPE0_RESET | MES_PIPE1_RESET {
            return TestResult::Fail("the first write must preserve the live register");
        }
        // Second: composed from zero. Nothing but the two ACTIVE bits.
        if cntl_writes[1] != MES_PIPE0_ACTIVE | MES_PIPE1_ACTIVE {
            return TestResult::Fail("the unhalt write must be composed from zero");
        }
        // Which is to say: it clears the reset and the halt it just set. A
        // read-modify-write here leaves the pipe reset and active at once, and
        // the processor never runs.
        if cntl_writes[1] & (MES_PIPE0_RESET | MES_PIPE1_RESET | MES_HALT) != 0 {
            return TestResult::Fail("activating must release the reset and the halt");
        }

        // The entry point is a DWORD address: the byte address over 4.
        let lo = seq.first_write_to(GC1, CP_MES_PRGRM_CNTR_START);
        if lo != Some((SCHED_UC >> 2) as u32) {
            return TestResult::Fail("the entry point is the byte address shifted right by 2");
        }
        if seq.first_write_to(GC1, CP_MES_PRGRM_CNTR_START_HI)
            != Some(((SCHED_UC >> 2) >> 32) as u32)
        {
            return TestResult::Fail("the entry point's high half is wrong");
        }
        // Both pipes were programmed, and the KIQ pipe got the KIQ address.
        let starts = seq.writes_to(GC1, CP_MES_PRGRM_CNTR_START);
        if starts.len() != 2 || starts[1] != (KIQ_UC >> 2) as u32 {
            return TestResult::Fail("each pipe gets its own entry point");
        }

        // Each entry-point write is preceded by a selection naming that pipe,
        // and the selection is restored at the end.
        let selects = seq.writes_to(GC1, GRBM_GFX_CNTL);
        if selects.len() != 3 {
            return TestResult::Fail("two pipe selections and one restore");
        }
        if selects[0] != grbm_select(MES_ME_ID, MES_SCHED_PIPE, 0, 0) {
            return TestResult::Fail("the first selection is me 3, pipe 0");
        }
        if selects[1] != grbm_select(MES_ME_ID, MES_KIQ_PIPE, 0, 0) {
            return TestResult::Fail("the second selection is me 3, pipe 1");
        }
        if selects[2] != 0 {
            return TestResult::Fail("the selection must be restored to zero");
        }
        // Order: the reset, then the selections, then the unhalt, then the wait.
        let first_cntl = seq.index_of_write(GC1, CP_MES_CNTL);
        let first_select = seq.index_of_write(GC1, GRBM_GFX_CNTL);
        match (first_cntl, first_select) {
            (Some(c), Some(s)) if c < s => {}
            _ => return TestResult::Fail("the reset is asserted before the pipes are selected"),
        }
        match seq.steps.last() {
            Some(GfxStep::Delay { us }) if *us == MES_ENABLE_DELAY_US => {}
            _ => return TestResult::Fail("the sequence ends with the 500 us wait"),
        }

        // Without the KIQ pipe: pipe 1 is not programmed, not reset, and not
        // activated.
        let one = match build_mes_enable(GC1, LIVE, [SCHED_UC, KIQ_UC], false, None) {
            Some(s) => s,
            None => return TestResult::Fail("a single-pipe enable was refused"),
        };
        let one_cntl = one.writes_to(GC1, CP_MES_CNTL);
        if one_cntl[0] & MES_PIPE1_RESET != 0 || one_cntl[1] & MES_PIPE1_ACTIVE != 0 {
            return TestResult::Fail("pipe 1 must be untouched when the KIQ pipe is off");
        }
        if one.writes_to(GC1, CP_MES_PRGRM_CNTR_START).len() != 1 {
            return TestResult::Fail("only one pipe's entry point is programmed");
        }
        if one.writes_to(GC1, GRBM_GFX_CNTL).len() != 2 {
            return TestResult::Fail("one selection and one restore");
        }

        // The event log, when enabled, is two writes and the HI is the lower id.
        let logged = match build_mes_enable(
            GC1,
            LIVE,
            [SCHED_UC, KIQ_UC],
            true,
            Some(0x1234_5678_9ABC_DEF0),
        ) {
            Some(s) => s,
            None => return TestResult::Fail("an enable with the log address was refused"),
        };
        if logged.first_write_to(GC1, CP_MES_MSCRATCH_LO) != Some(0x9ABC_DEF0) {
            return TestResult::Fail("the mscratch low half is wrong");
        }
        if logged.first_write_to(GC1, CP_MES_MSCRATCH_HI) != Some(0x1234_5678) {
            return TestResult::Fail("the mscratch high half is wrong");
        }
        if seq.first_write_to(GC1, CP_MES_MSCRATCH_LO).is_some() {
            return TestResult::Fail("without a log address the pair is left alone");
        }

        // An entry point that is not dword-aligned cannot be expressed.
        if build_mes_enable(GC1, LIVE, [SCHED_UC | 2, KIQ_UC], true, None).is_some() {
            return TestResult::Fail("a misaligned entry point must be refused, not rounded");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/amdgpu/mes_hw", smoke_mes_hw_enable_sequence);

    /// The halt path, and the RLC's KIQ pointer.
    fn smoke_mes_hw_disable_and_kiq_setting() -> TestResult {
        const GC1: u32 = 0x0005_0000;
        const LIVE: u32 = MES_PIPE0_ACTIVE | MES_PIPE1_ACTIVE | 0x0000_0002;

        let seq = build_mes_disable(GC1, LIVE, true);
        let w = seq.writes_to(GC1, CP_MES_CNTL);
        if w.len() != 1 {
            return TestResult::Fail("the halt path is one write");
        }
        if w[0] & (MES_PIPE0_ACTIVE | MES_PIPE1_ACTIVE) != 0 {
            return TestResult::Fail("both ACTIVE bits must be cleared");
        }
        let want = MES_INVALIDATE_ICACHE | MES_PIPE0_RESET | MES_PIPE1_RESET | MES_HALT;
        if w[0] & want != want {
            return TestResult::Fail("halt sets the icache invalidate, the resets and HALT");
        }
        // Unrelated live bits survive: this one IS a read-modify-write.
        if w[0] & 0x0000_0002 == 0 {
            return TestResult::Fail("the halt write must preserve unrelated bits");
        }
        if build_mes_disable(GC1, LIVE, false).writes_to(GC1, CP_MES_CNTL)[0] & MES_PIPE1_RESET != 0
        {
            return TestResult::Fail("pipe 1 is not reset when the KIQ pipe is off");
        }

        // `mes_v11_0_kiq_setting`: the low byte is replaced, bit 7 set, and
        // the rest of the register preserved.
        let live = 0xDEAD_BE5A;
        let v = rlc_cp_schedulers_value(live, 1, 2, 3);
        if v & 0xffff_ff00 != live & 0xffff_ff00 {
            return TestResult::Fail("the high three bytes must be preserved");
        }
        if v & 0xff != (1 << 5) | (2 << 3) | 3 | 0x80 {
            return TestResult::Fail("me at 5, pipe at 3, queue at 0, and bit 7 set");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/mes_hw",
        smoke_mes_hw_disable_and_kiq_setting
    );

    /// `mes_v11_0_queue_init_register`, against the descriptor it reads from.
    ///
    /// Two things this has to get right that nothing else checks: the selector
    /// is in GC window **1** while every HQD register is in window **0**, and
    /// the doorbell is written twice — disabled first, then from the
    /// descriptor — in that order.
    fn smoke_mes_hw_queue_init_register() -> TestResult {
        use crate::amdgpu_mqd::{self as m, mes_mqd_init, MqdProp, QueuePriority};
        const GC0: u32 = 0x0003_0000;
        const GC1: u32 = 0x0005_0000;

        let prop = MqdProp {
            mqd_gpu_addr: 0x1_0000_1000,
            hqd_base_gpu_addr: 0x2_0000_0000,
            rptr_gpu_addr: 0x0003_0000_0000,
            wptr_gpu_addr: 0x0004_0000_0000,
            queue_size: 4096,
            doorbell_index: 0x14,
            use_doorbell: true,
            kernel_queue: true,
            tmz_queue: false,
            priority: QueuePriority::Normal,
            shadow_addr: 0,
            gds_bkup_addr: 0,
            csa_addr: 0,
            fence_address: 0,
        };
        let mqd = match mes_mqd_init(&prop, 0x9_0000_0000) {
            Ok(v) => v,
            Err(_) => return TestResult::Fail("the MES descriptor was refused"),
        };

        // Live values with unrelated bits set, so the read-modify-writes are
        // distinguishable from composed ones.
        const LIVE_VMID: u32 = 0x0003_0F05;
        const LIVE_DOORBELL: u32 = HQD_DOORBELL_EN | 0x0000_0040;
        let seq =
            build_mes_queue_init_register(GC0, GC1, MES_SCHED_PIPE, &mqd, LIVE_VMID, LIVE_DOORBELL);

        // The selector is window 1; reading it from window 0 finds nothing.
        if seq.first_write_to(GC0, GRBM_GFX_CNTL).is_some() {
            return TestResult::Fail("the selector must not be addressed through window 0");
        }
        let selects = seq.writes_to(GC1, GRBM_GFX_CNTL);
        if selects.len() != 2 {
            return TestResult::Fail("one selection and one restore");
        }
        if selects[0] != grbm_select(MES_ME_ID, MES_SCHED_PIPE, 0, 0) || selects[1] != 0 {
            return TestResult::Fail("select me 3 / this pipe, then restore to zero");
        }
        // And the HQD registers are window 0, not window 1.
        if seq.first_write_to(GC1, CP_HQD_ACTIVE).is_some() {
            return TestResult::Fail("the HQD registers must not be addressed through window 1");
        }

        // VMID forced to 0 with IB_VMID and VQID preserved.
        match seq.first_write_to(GC0, CP_HQD_VMID) {
            Some(v) if v == LIVE_VMID & !0xF => {}
            _ => return TestResult::Fail("VMID is cleared and the rest of the register kept"),
        }

        // The doorbell is written twice: disabled, then the descriptor's.
        let doorbells = seq.writes_to(GC0, CP_HQD_PQ_DOORBELL_CONTROL);
        if doorbells.len() != 2 {
            return TestResult::Fail("the doorbell register is written twice");
        }
        if doorbells[0] & HQD_DOORBELL_EN != 0 {
            return TestResult::Fail("the first doorbell write must disable it");
        }
        if doorbells[0] & 0x0000_0040 == 0 {
            return TestResult::Fail("the first doorbell write preserves unrelated bits");
        }
        if doorbells[1] != mqd[m::C_CP_HQD_PQ_DOORBELL_CONTROL] {
            return TestResult::Fail("the second doorbell write comes from the descriptor");
        }
        if doorbells[1] & HQD_DOORBELL_EN == 0 {
            return TestResult::Fail("the descriptor's doorbell is enabled");
        }

        // CP_MQD_CONTROL is a literal zero, NOT the descriptor's value. Linux
        // computes it and writes 0; the descriptor holds PRIV_STATE.
        if mqd[m::C_CP_MQD_CONTROL] & MQD_CONTROL_PRIV_STATE == 0 {
            return TestResult::Fail("the descriptor's cp_mqd_control holds PRIV_STATE");
        }
        if seq.first_write_to(GC0, CP_MQD_CONTROL) != Some(0) {
            return TestResult::Fail("CP_MQD_CONTROL is written as a literal zero");
        }

        // Every other value comes from the descriptor, so the registers and
        // the descriptor cannot disagree.
        for (reg, idx) in [
            (CP_MQD_BASE_ADDR, m::C_CP_MQD_BASE_ADDR_LO),
            (CP_MQD_BASE_ADDR_HI, m::C_CP_MQD_BASE_ADDR_HI),
            (CP_HQD_PQ_BASE, m::C_CP_HQD_PQ_BASE_LO),
            (CP_HQD_PQ_BASE_HI, m::C_CP_HQD_PQ_BASE_HI),
            (
                CP_HQD_PQ_RPTR_REPORT_ADDR,
                m::C_CP_HQD_PQ_RPTR_REPORT_ADDR_LO,
            ),
            (
                CP_HQD_PQ_RPTR_REPORT_ADDR_HI,
                m::C_CP_HQD_PQ_RPTR_REPORT_ADDR_HI,
            ),
            (CP_HQD_PQ_CONTROL, m::C_CP_HQD_PQ_CONTROL),
            (CP_HQD_PQ_WPTR_POLL_ADDR, m::C_CP_HQD_PQ_WPTR_POLL_ADDR_LO),
            (
                CP_HQD_PQ_WPTR_POLL_ADDR_HI,
                m::C_CP_HQD_PQ_WPTR_POLL_ADDR_HI,
            ),
            (CP_HQD_PERSISTENT_STATE, m::C_CP_HQD_PERSISTENT_STATE),
            (CP_HQD_ACTIVE, m::C_CP_HQD_ACTIVE),
        ] {
            if seq.first_write_to(GC0, reg) != Some(mqd[idx]) {
                return TestResult::Fail("a register does not carry the descriptor's value");
            }
        }

        // The queue is activated, and activated LAST of the HQD writes — a
        // queue made active before it is described can be read by the CP
        // mid-setup.
        if seq.first_write_to(GC0, CP_HQD_ACTIVE) != Some(1) {
            return TestResult::Fail("the MES queue is activated here");
        }
        let active_at = seq.index_of_write(GC0, CP_HQD_ACTIVE);
        let mut last_hqd = 0usize;
        for reg in [
            CP_MQD_BASE_ADDR,
            CP_HQD_PQ_BASE,
            CP_HQD_PQ_CONTROL,
            CP_HQD_PERSISTENT_STATE,
        ] {
            if let Some(i) = seq.index_of_write(GC0, reg) {
                last_hqd = last_hqd.max(i);
            }
        }
        match active_at {
            Some(i) if i > last_hqd => {}
            _ => return TestResult::Fail("CP_HQD_ACTIVE must be the last HQD write"),
        }
        // And the restore comes after that.
        match (active_at, seq.steps.len()) {
            (Some(i), n) if i + 1 == n - 1 => {}
            _ => return TestResult::Fail("the selection is restored after activating"),
        }

        // The KIQ pipe selects pipe 1 instead.
        let kiq =
            build_mes_queue_init_register(GC0, GC1, MES_KIQ_PIPE, &mqd, LIVE_VMID, LIVE_DOORBELL);
        if kiq.writes_to(GC1, GRBM_GFX_CNTL)[0] != grbm_select(MES_ME_ID, MES_KIQ_PIPE, 0, 0) {
            return TestResult::Fail("the KIQ pipe's sequence selects pipe 1");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/mes_hw",
        smoke_mes_hw_queue_init_register
    );
}
