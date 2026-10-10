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

// ── Firmware version, and what it decides ──────────────────

/// `AMDGPU_MES_VERSION_MASK` — the scheduler version in the low twelve bits
/// of `CP_MES_GP3_LO`.
pub const MES_VERSION_MASK: u32 = 0x0000_0FFF;
/// `AMDGPU_MES_API_VERSION_MASK` and `_SHIFT`.
pub const MES_API_VERSION_MASK: u32 = 0x00FF_F000;
pub const MES_API_VERSION_SHIFT: u32 = 12;
/// `AMDGPU_MES_FEAT_VERSION_MASK`.
pub const MES_FEAT_VERSION_MASK: u32 = 0xFF00_0000;

/// The scheduler version at which `mes_v11_0_late_init` sets
/// `enable_legacy_queue_map`.
///
/// Below it, a kernel ring is registered by writing a `MAP_QUEUES` PM4 packet
/// to the KIQ ring; at or above it, by sending MES `ADD_QUEUE` with
/// `map_legacy_kq`. **Only the second exists in this driver**, so a part
/// reporting an older scheduler has no path to a mapped kernel queue here and
/// must be refused rather than silently sent down a path that does not exist.
pub const MES_LEGACY_QUEUE_MAP_VERSION: u32 = 0x47;

/// The API version at which `mes_v11_0_add_hw_queue` switches `wptr_addr` from
/// `input->wptr_addr` to `input->wptr_mc_addr`.
///
/// Not used by the legacy-kernel-queue mapping, which carries the one address
/// either way — recorded because it is the other thing this register decides.
pub const MES_API_VERSION_WPTR_MC: u32 = 2;

/// One pipe's firmware version word, decoded.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MesVersion {
    pub raw: u32,
    pub version: u32,
    pub api_version: u32,
    pub feature_version: u32,
}

impl MesVersion {
    /// Decode a `CP_MES_GP3_LO` read.
    pub const fn decode(raw: u32) -> Self {
        Self {
            raw,
            version: raw & MES_VERSION_MASK,
            api_version: (raw & MES_API_VERSION_MASK) >> MES_API_VERSION_SHIFT,
            feature_version: (raw & MES_FEAT_VERSION_MASK) >> 24,
        }
    }

    /// Whether a kernel ring is mapped with MES `ADD_QUEUE` rather than the
    /// KIQ's `MAP_QUEUES` packet. See [`MES_LEGACY_QUEUE_MAP_VERSION`].
    pub const fn enable_legacy_queue_map(&self) -> bool {
        self.version >= MES_LEGACY_QUEUE_MAP_VERSION
    }

    /// A zero word is not a version. `CP_MES_GP3_LO` reads zero before the
    /// pipe has run its microcode, so a decode of 0 means "the MES has not
    /// started", not "version 0" — and treating it as a version would read as
    /// an old scheduler and take a path this driver does not implement.
    pub const fn is_running(&self) -> bool {
        self.raw != 0
    }
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

// ── What the scheduler is told about the hardware ─────────────────

/// The pipe and queue topology `amdgpu_mes_init` derives its masks from.
///
/// `build_set_hw_resources` takes the masks ready-made, and nothing computed
/// them. They are not free parameters: each one says which hardware queue
/// slots the scheduler may hand out, and the derivation reserves exactly the
/// slots the driver's own kernel rings occupy. A mask that is too wide lets
/// the scheduler place a user queue on top of a kernel ring; too narrow and it
/// has nowhere to put anything.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MesTopology {
    /// `adev->gfx.me.num_me`.
    pub num_me: u32,
    /// `adev->gfx.me.num_pipe_per_me`.
    pub num_pipe_per_me: u32,
    /// `adev->gfx.me.num_queue_per_pipe`.
    pub num_queue_per_pipe_gfx: u32,
    /// `adev->gfx.num_gfx_rings` — the kernel graphics rings to reserve for.
    pub num_gfx_rings: u32,
    /// `adev->gfx.mec.num_mec`.
    pub num_mec: u32,
    /// `adev->gfx.mec.num_pipe_per_mec`.
    pub num_pipe_per_mec: u32,
    /// `adev->gfx.mec.num_queue_per_pipe`.
    pub num_queue_per_pipe_compute: u32,
    /// `adev->gfx.num_compute_rings`.
    pub num_compute_rings: u32,
    /// `adev->sdma.num_instances`, from the discovery table.
    pub num_sdma_instances: u32,
    /// `adev->vm_manager.first_kfd_vmid` — VMIDs below this are the driver's.
    pub first_kfd_vmid: u32,
    /// `mes->db_start_dw_offset`, the base of the aggregated doorbells.
    pub db_start_dw_offset: u32,
}

/// Phoenix, with the stock module parameters.
///
/// Every value is traced to where `gfx_v11_0_sw_init` sets it for GC
/// IP_VERSION(11, 0, 1):
///
/// ```text
/// num_me                  1
/// num_pipe_per_me         1     rs64_enable is true, so 1 and not 2
/// num_queue_per_pipe_gfx  2
/// num_gfx_rings           1     "rs64 only supports one gfx pipe"
/// num_mec                 1
/// num_pipe_per_mec        4
/// num_queue_per_pipe      4
/// num_compute_rings       8     min(amdgpu_gfx_get_num_kcq() = 8, 8)
/// first_kfd_vmid          8     gmc_v11_0.c:853, disable_kq being false
/// ```
///
/// `disable_kq` is false because `amdgpu_user_queue` defaults to -1, which
/// takes `gfx_v11_0_early_init`'s default arm. The `disable_kq` arm would make
/// `num_gfx_rings` 1 and `num_compute_rings` **0**, which changes both masks —
/// so this is a per-configuration table, not a per-ASIC one, and it says so.
///
/// `num_sdma_instances` is 1 and comes from the discovery table at runtime;
/// it is here as the Phoenix value for the test, not as something to trust.
pub const PHOENIX_TOPOLOGY: MesTopology = MesTopology {
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

/// `mes->sdma_hqd_mask[i] = 0xfc` — a literal in `amdgpu_mes_init`, not
/// derived from anything. Queues 2..7 of each SDMA instance; 0 and 1 are the
/// driver's own.
pub const SDMA_HQD_MASK: u32 = 0xFC;

/// `mes->vmid_mask_mmhub = 0xFF00` — also a literal.
pub const VMID_MASK_MMHUB: u32 = 0xFF00;

/// `amdgpu_mes_get_hqd_mask` — the hardware queue slots on each pipe that the
/// scheduler may use.
///
/// `num_reserved_hqd` kernel rings are spread across `num_pipe` pipes, so
/// `ceil(num_reserved_hqd / num_pipe)` slots per pipe are the driver's and the
/// rest are the scheduler's. The **ceiling** is the part to get right: with 8
/// compute rings over 4 pipes it reserves 2 per pipe, and with 1 graphics ring
/// over 1 pipe it reserves 1 — flooring would reserve nothing whenever the
/// rings do not divide evenly and hand the scheduler a slot a kernel ring is
/// already on.
///
/// Returns 0 for a pipe count of zero, as Linux does, rather than dividing by
/// it.
pub const fn hqd_mask(num_pipe: u32, num_hqd_per_pipe: u32, num_reserved_hqd: u32) -> u32 {
    if num_pipe == 0 {
        return 0;
    }
    let total = ((1u64 << num_hqd_per_pipe) - 1) as u32;
    let per_pipe = num_reserved_hqd.div_ceil(num_pipe);
    let reserved = ((1u64 << per_pipe) - 1) as u32;
    total & !reserved
}

/// Fill the mask and VMID fields of a `SET_HW_RSRC` payload from `topo`,
/// following `amdgpu_mes_init`.
///
/// Leaves everything else — the context addresses, the flags, the GDS size,
/// the IP bases — to the caller, because those are allocations and discovery
/// results rather than topology.
pub fn fill_hw_resources(res: &mut crate::amdgpu_mes::MesHwResources, topo: &MesTopology) {
    // `total_vmid_mask` is 16 bits; everything below `first_kfd_vmid` is
    // reserved for the driver. On Phoenix that leaves VMIDs 8..15, which is
    // the same 0xFF00 the MMHUB mask is a literal for — a coincidence, since
    // one is derived and the other is not.
    let total_vmid_mask: u32 = (1 << 16) - 1;
    let reserved_vmid_mask: u32 = ((1u64 << topo.first_kfd_vmid) - 1) as u32;
    res.vmid_mask_mmhub = VMID_MASK_MMHUB;
    res.vmid_mask_gfxhub = total_vmid_mask & !reserved_vmid_mask;

    let gfx = hqd_mask(
        topo.num_pipe_per_me,
        topo.num_queue_per_pipe_gfx,
        topo.num_gfx_rings,
    );
    let compute = hqd_mask(
        topo.num_pipe_per_mec,
        topo.num_queue_per_pipe_compute,
        topo.num_compute_rings,
    );

    // The same mask goes to every pipe that EXISTS, and the entries past that
    // stay zero. The bounds differ per block, which is the detail a single
    // loop would flatten: gfx is bounded by `num_pipe_per_me * num_me`,
    // compute by `num_pipe_per_mec` ALONE — `amdgpu_mes_init` deliberately
    // stops at one MEC, "to avoid potential issues" with queue resources
    // shared with KFD, even though it computed `num_pipe_per_mec * num_mec`
    // for the warning two lines up.
    let gfx_pipes = (topo.num_pipe_per_me * topo.num_me) as usize;
    for (i, slot) in res.gfx_hqd_mask.iter_mut().enumerate() {
        *slot = if i < gfx_pipes { gfx } else { 0 };
    }
    let compute_pipes = topo.num_pipe_per_mec as usize;
    for (i, slot) in res.compute_hqd_mask.iter_mut().enumerate() {
        *slot = if i < compute_pipes { compute } else { 0 };
    }
    let sdma_pipes = topo.num_sdma_instances as usize;
    for (i, slot) in res.sdma_hqd_mask.iter_mut().enumerate() {
        *slot = if i < sdma_pipes { SDMA_HQD_MASK } else { 0 };
    }

    // `aggregated_doorbells[i] = db_start_dw_offset + i * 2` — two dwords
    // apart, because each is a 64-bit doorbell.
    for (i, slot) in res.aggregated_doorbells.iter_mut().enumerate() {
        *slot = topo.db_start_dw_offset + (i as u32) * 2;
    }
}

// LINUX-GAP: the MES pipe has no ring. Every register sequence and every
// packet `mes_v11_0_hw_init` issues is now expressible — the enable, the
// descriptor, the HQD registers, `SET_HW_RSRC`'s payload, the submit protocol
// in `amdgpu_mes` — but nothing allocates the pipe's own ring, writeback and
// descriptor pages, the way `GfxContext` holds the graphics ring's, and
// nothing allocates the scheduler-context and query-status-fence buffers
// `SET_HW_RSRC` names. So nothing here is reachable from a probe: this module
// builds the sequences and nothing calls them.
//
// LINUX-GAP: `mes_v11_0_get_fw_version` is not performed, only enabled.
// [`fw_version_select`] hands a caller the two selector values and
// [`CP_MES_GP3_LO`] is named, but a read cannot be a [`Gfx11Sequence`] step,
// so the two-step read is the caller's. The scheduler version it returns is
// not cosmetic: `enable_legacy_queue_map` is set from `>= 0x47`, which is what
// decides whether a kernel graphics ring is registered through MES ADD_QUEUE
// or the KIQ's MAP_QUEUES packet — and only the first of those exists here.

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

    /// `amdgpu_mes_get_hqd_mask`, and the Phoenix masks it produces.
    ///
    /// The literals are worked out by hand from `gfx_v11_0_sw_init`'s counts
    /// rather than recomputed, so the test disagrees with the code if the
    /// derivation drifts:
    ///
    /// ```text
    /// gfx:     pipes 1, queues/pipe 2, reserved rings 1
    ///          total     = (1 << 2) - 1            = 0x3
    ///          per_pipe  = ceil(1 / 1)             = 1
    ///          reserved  = (1 << 1) - 1            = 0x1
    ///          mask      = 0x3 & ~0x1              = 0x2
    /// compute: pipes 4, queues/pipe 4, reserved rings 8
    ///          total     = (1 << 4) - 1            = 0xF
    ///          per_pipe  = ceil(8 / 4)             = 2
    ///          reserved  = (1 << 2) - 1            = 0x3
    ///          mask      = 0xF & ~0x3              = 0xC
    /// ```
    fn smoke_mes_hw_resource_masks() -> TestResult {
        use crate::amdgpu_mes::{MesHwResources, AMD_PRIORITY_NUM_LEVELS};

        // The derivation itself.
        if hqd_mask(1, 2, 1) != 0x2 {
            return TestResult::Fail("the graphics mask should be 0x2");
        }
        if hqd_mask(4, 4, 8) != 0xC {
            return TestResult::Fail("the compute mask should be 0xC");
        }
        // No pipes means no mask, not a division by zero.
        if hqd_mask(0, 4, 8) != 0 {
            return TestResult::Fail("a pipe count of zero yields no mask");
        }
        // Nothing reserved means every slot is the scheduler's.
        if hqd_mask(4, 4, 0) != 0xF {
            return TestResult::Fail("with no kernel rings the whole pipe is available");
        }
        // The CEILING. Five rings over four pipes reserves two per pipe, not
        // one: flooring would hand the scheduler a slot a kernel ring is on.
        if hqd_mask(4, 4, 5) != 0xC {
            return TestResult::Fail("rings per pipe must round UP");
        }
        if hqd_mask(4, 4, 4) != 0xE {
            return TestResult::Fail("four rings over four pipes reserves one each");
        }

        // And the whole Phoenix payload.
        let mut res = MesHwResources::default();
        fill_hw_resources(&mut res, &PHOENIX_TOPOLOGY);

        if res.vmid_mask_mmhub != 0xFF00 {
            return TestResult::Fail("vmid_mask_mmhub is the literal 0xFF00");
        }
        // `first_kfd_vmid` is 8, so VMIDs 0..7 are the driver's and 8..15 the
        // scheduler's — which lands on the same value the MMHUB mask is
        // hardcoded to, by coincidence rather than by construction.
        if res.vmid_mask_gfxhub != 0xFF00 {
            return TestResult::Fail("vmid_mask_gfxhub should leave VMIDs 8..15");
        }
        // Which is worth pinning as a derivation, not a literal: a part that
        // reserved a different number of VMIDs would differ here and not in
        // the MMHUB mask.
        let mut shifted = MesHwResources::default();
        fill_hw_resources(
            &mut shifted,
            &MesTopology {
                first_kfd_vmid: 1,
                ..PHOENIX_TOPOLOGY
            },
        );
        if shifted.vmid_mask_gfxhub != 0xFFFE {
            return TestResult::Fail("the gfxhub mask follows first_kfd_vmid");
        }
        if shifted.vmid_mask_mmhub != 0xFF00 {
            return TestResult::Fail("the mmhub mask does not follow it");
        }

        // One graphics pipe gets the mask; the second array entry stays zero.
        if res.gfx_hqd_mask != [0x2, 0] {
            return TestResult::Fail("one graphics pipe exists on Phoenix");
        }
        // Four compute pipes of eight.
        if res.compute_hqd_mask != [0xC, 0xC, 0xC, 0xC, 0, 0, 0, 0] {
            return TestResult::Fail("four compute pipes exist, and four array slots do not");
        }
        // One SDMA instance, and the mask is a literal.
        if res.sdma_hqd_mask != [SDMA_HQD_MASK, 0] || SDMA_HQD_MASK != 0xFC {
            return TestResult::Fail("one SDMA instance, queues 2..7");
        }

        // The aggregated doorbells are two dwords apart because each is a
        // 64-bit doorbell.
        if res.aggregated_doorbells.len() != AMD_PRIORITY_NUM_LEVELS {
            return TestResult::Fail("one aggregated doorbell per priority level");
        }
        for (i, got) in res.aggregated_doorbells.iter().enumerate() {
            if *got != (i as u32) * 2 {
                return TestResult::Fail("the aggregated doorbells step by two dwords");
            }
        }
        let mut based = MesHwResources::default();
        fill_hw_resources(
            &mut based,
            &MesTopology {
                db_start_dw_offset: 0x40,
                ..PHOENIX_TOPOLOGY
            },
        );
        if based.aggregated_doorbells[2] != 0x44 {
            return TestResult::Fail("the aggregated doorbells start at db_start_dw_offset");
        }

        // The `disable_kq` configuration changes BOTH masks, which is why the
        // table is per-configuration: no graphics ring reserved, and no
        // compute rings at all.
        let mut no_kq = MesHwResources::default();
        fill_hw_resources(
            &mut no_kq,
            &MesTopology {
                num_compute_rings: 0,
                ..PHOENIX_TOPOLOGY
            },
        );
        if no_kq.compute_hqd_mask[0] != 0xF {
            return TestResult::Fail("with no kernel compute rings the pipes are all available");
        }
        if no_kq.gfx_hqd_mask[0] != 0x2 {
            return TestResult::Fail("the graphics mask is independent of the compute rings");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/amdgpu/mes_hw", smoke_mes_hw_resource_masks);

    /// `CP_MES_GP3_LO` decoded, and what the version gates.
    ///
    /// The threshold is the point: below 0x47 a kernel ring is mapped with the
    /// KIQ's `MAP_QUEUES` PM4 packet, which this driver does not have at all.
    /// So the version is not a diagnostic — it decides whether bring-up can
    /// proceed, and a misread that lands above the threshold sends the driver
    /// down a path the firmware will not answer.
    fn smoke_mes_hw_version_decode() -> TestResult {
        if (
            MES_VERSION_MASK,
            MES_API_VERSION_MASK,
            MES_FEAT_VERSION_MASK,
        ) != (0x0000_0FFF, 0x00FF_F000, 0xFF00_0000)
        {
            return TestResult::Fail("the three version fields are 12/12/8 bits");
        }
        if MES_API_VERSION_SHIFT != 12 {
            return TestResult::Fail("AMDGPU_MES_API_VERSION_SHIFT is 12");
        }
        // The three fields tile the word exactly, so a value cannot fall
        // between them.
        if MES_VERSION_MASK | MES_API_VERSION_MASK | MES_FEAT_VERSION_MASK != u32::MAX {
            return TestResult::Fail("the version fields must cover the whole word");
        }

        // A word with a distinct value in each field, so a shift error moves
        // a recognisable number.
        let v = MesVersion::decode(0xAB_CDE_047);
        if v.version != 0x047 {
            return TestResult::Fail("the scheduler version is the low twelve bits");
        }
        if v.api_version != 0xCDE {
            return TestResult::Fail("the API version is bits 23:12");
        }
        if v.feature_version != 0xAB {
            return TestResult::Fail("the feature version is the top byte");
        }
        if v.raw != 0xAB_CDE_047 {
            return TestResult::Fail("the raw word is kept");
        }

        // The threshold, and both sides of it.
        if MES_LEGACY_QUEUE_MAP_VERSION != 0x47 {
            return TestResult::Fail("enable_legacy_queue_map turns on at 0x47");
        }
        if !MesVersion::decode(0x47).enable_legacy_queue_map() {
            return TestResult::Fail("0x47 itself enables the legacy mapping");
        }
        if MesVersion::decode(0x46).enable_legacy_queue_map() {
            return TestResult::Fail("0x46 does not");
        }
        // The feature and API fields must not leak into the comparison: a
        // high feature version with an old scheduler is still an old
        // scheduler.
        if MesVersion::decode(0xFF_FFF_046).enable_legacy_queue_map() {
            return TestResult::Fail("only the low twelve bits decide the mapping path");
        }
        if !MesVersion::decode(0x00_000_FFF).enable_legacy_queue_map() {
            return TestResult::Fail("a high scheduler version with no other field set qualifies");
        }

        // Zero is "has not started", not "version 0". Treating it as a
        // version reads as an old scheduler and takes the path this driver
        // does not implement.
        let dead = MesVersion::decode(0);
        if dead.is_running() {
            return TestResult::Fail("a zero word means the MES has not started");
        }
        if dead.enable_legacy_queue_map() {
            return TestResult::Fail("a stopped MES must not look like a mappable one");
        }
        if !MesVersion::decode(1).is_running() {
            return TestResult::Fail("any non-zero word is a started MES");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/amdgpu/mes_hw", smoke_mes_hw_version_decode);
}
