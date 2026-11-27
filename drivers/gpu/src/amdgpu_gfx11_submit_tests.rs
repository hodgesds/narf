//! Fixture tests for the GFX11 submitter: per-die tables, the frame
//! encoder against `gfx_v11_0.c`, fences, context switch, preamble install,
//! and end-to-end submission on a fixture ring backend. No hardware is
//! touched; the backend records emitted words and reports completion when
//! the test says so.

use super::*;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32};
use narf_kernel_test::{kernel_test_in, TestResult};

/// A test layout with distinctive bases, so a wrong window shows up as a
/// wrong dword rather than a right-looking one. The HDP values are test
/// values, not hardware values: the layout is the platform lane's input,
/// and the test pins that the encoder puts the layout's values in the
/// right slots.
fn layout() -> Gfx11Layout {
    Gfx11Layout {
        gc_base: 0,
        gc_base_1: 0xa000,
        oss_base: 0,
        hdp_flush: HdpFlush {
            req: 0x5000,
            done: 0x5004,
            gfx_mask: 0x1,
            compute_mask: 0x4,
        },
        hdp_read_cache_invalidate: Some(0x60d1),
    }
}

fn config(die: Gfx11Die) -> SubmitterConfig {
    SubmitterConfig {
        die,
        layout: layout(),
        inv_engines: [0, 4],
        client_vmids: CLIENT_VMIDS,
        gc: None,
    }
}

/// A Navi31-like discovery geometry: 6 SE x 2 SA x 8 CU = 96 CU, so the
/// GDS wave-id limit is 96 * 32 - 1 = 3071.
fn navi31_gc() -> GcInfo {
    GcInfo {
        num_se: 6,
        num_sa_per_se: 2,
        num_cu_per_sa: 8,
        ..GcInfo::default()
    }
}

/// The ring backend tests drive: records emitted words, answers fences
/// from per-ring slots the test sets. Nothing here pretends to be hardware.
struct FixtureBackend {
    emitted: IrqSafeSpinLock<Vec<(Ring, Vec<u32>)>>,
    fence: [u64; 3],
    vm_fence: [u64; 3],
    completed: [AtomicU32; 3],
    vm_completed: [AtomicU32; 3],
    dark: AtomicBool,
}
impl FixtureBackend {
    fn new() -> Self {
        Self {
            emitted: IrqSafeSpinLock::new(Vec::new()),
            fence: [0x1000_0000, 0x2000_0000, 0],
            vm_fence: [0x1000_1000, 0x2000_1000, 0],
            completed: [const { AtomicU32::new(0) }; 3],
            vm_completed: [const { AtomicU32::new(0) }; 3],
            dark: AtomicBool::new(false),
        }
    }
    fn id(ring: Ring) -> usize {
        match ring {
            Ring::Gfx => 0,
            Ring::Compute => 1,
            Ring::GfxSecondary => 2,
        }
    }
    fn last_emitted(&self, ring: Ring) -> Vec<u32> {
        self.emitted
            .lock()
            .iter()
            .rev()
            .find(|(r, _)| *r == ring)
            .map(|(_, w)| w.clone())
            .unwrap_or_default()
    }
    fn emitted_count(&self, ring: Ring) -> usize {
        self.emitted
            .lock()
            .iter()
            .filter(|(r, _)| *r == ring)
            .count()
    }
    /// Report sequence `seq` complete on `ring` (job fence and VM fence).
    fn complete(&self, ring: Ring, seq: u32) {
        let id = Self::id(ring);
        self.completed[id].store(seq, Ordering::Release);
        self.vm_completed[id].store(seq, Ordering::Release);
    }
    /// The device stops answering: every progress sample fails.
    fn go_dark(&self) {
        self.dark.store(true, Ordering::Release);
    }
}
impl RingBackend for FixtureBackend {
    fn fence_address(&self, ring: Ring) -> Option<u64> {
        match ring {
            Ring::GfxSecondary => None,
            _ => Some(self.fence[Self::id(ring)]),
        }
    }
    fn vm_fence_address(&self, ring: Ring) -> Option<u64> {
        match ring {
            Ring::GfxSecondary => None,
            _ => Some(self.vm_fence[Self::id(ring)]),
        }
    }
    fn emit(&self, ring: Ring, words: &[u32]) -> Result<(), Error> {
        self.emitted.lock().push((ring, words.to_vec()));
        Ok(())
    }
    fn completed(&self, ring: Ring) -> Option<u32> {
        if self.dark.load(Ordering::Acquire) {
            return None;
        }
        Some(self.completed[Self::id(ring)].load(Ordering::Acquire))
    }
    fn vm_completed(&self, ring: Ring) -> Option<u32> {
        if self.dark.load(Ordering::Acquire) {
            return None;
        }
        Some(self.vm_completed[Self::id(ring)].load(Ordering::Acquire))
    }
}

/// A client space with one GTT buffer of `size` bytes mapped R/W/X at
/// `va` (sign-extended, as radeonsi passes it): the `VmState` a submit
/// runs in, with a root page table and a PASID.
fn client_space(card: u32, va: u64, size: u64) -> (crate::amdgpu_gem::GemState, VmState, u32) {
    let amd = |nr: u32| 0xc000_0000 | (0x64 << 8) | (0x40 + nr);
    let gem = crate::amdgpu_gem::GemState::new();
    let mut create = [0u8; 32];
    create[0..8].copy_from_slice(&size.to_le_bytes());
    create[16..24].copy_from_slice(&u64::from(uapi::AMDGPU_GEM_DOMAIN_GTT).to_le_bytes());
    crate::amdgpu_gem::dispatch(
        amd(uapi::DRM_AMDGPU_GEM_CREATE),
        create.as_mut_ptr() as usize,
        &gem,
    )
    .unwrap();
    let handle = u32::from_le_bytes(create[0..4].try_into().unwrap());
    let vm = VmState::for_card(card);
    let mut map = [0u8; 40];
    map[0..4].copy_from_slice(&handle.to_le_bytes());
    map[8..12].copy_from_slice(&uapi::AMDGPU_VA_OP_MAP.to_le_bytes());
    map[12..16].copy_from_slice(&0x0eu32.to_le_bytes());
    map[16..24].copy_from_slice(&va.to_le_bytes());
    map[32..40].copy_from_slice(&size.to_le_bytes());
    crate::amdgpu_vm::dispatch(
        amd(uapi::DRM_AMDGPU_GEM_VA),
        map.as_mut_ptr() as usize,
        &vm,
        &gem,
        None,
    )
    .unwrap();
    (gem, vm, handle)
}

/// Drive a future to completion on the calling thread, as
/// `amdgpu_cs_liveness_tests.rs` does. A closure cannot be generic, and
/// these tests drive both `submit` (`Result<u64, _>`) and `wait`
/// (`Result<bool, _>`).
fn run<F: Future>(f: F) -> F::Output {
    narf_scheduler::block_on_spin(f)
}

fn gfx_submission(ctx_id: u32, va: u64) -> crate::amdgpu_cs::Submission {
    crate::amdgpu_cs::Submission {
        ctx_id,
        ibs: alloc::vec![crate::amdgpu_cs::Ib {
            va_start: va,
            length_dw: 4,
            ip_type: uapi::AMDGPU_HW_IP_GFX,
            ip_instance: 0,
            ring: 0,
            flags: 0,
        }],
        in_syncobjs: Vec::new(),
        out_syncobjs: Vec::new(),
        bo_handles: None,
        dependencies: Vec::new(),
        user_fence: None,
    }
}

fn gfx11_die_table_matches_corrected_pairing() -> TestResult {
    // Lane 1's corrected pairing: Navi31 11.0.0, Navi32 11.0.3, Navi33 11.0.2.
    for (gc, die) in [
        ((11u8, 0u8, 0u8), Gfx11Die::Navi31),
        ((11, 0, 3), Gfx11Die::Navi32),
        ((11, 0, 2), Gfx11Die::Navi33),
    ] {
        if Gfx11Die::from_gc(gc.0, gc.1, gc.2) != Some(die) {
            return TestResult::Fail("a corrected die did not resolve from its GC version");
        }
        if die.gc_version() != gc {
            return TestResult::Fail("a die did not round-trip its GC version");
        }
    }
    // Phoenix GC 11.0.1 is explicitly not an RDNA3 die.
    if Gfx11Die::from_gc(11, 0, 1).is_some() || Gfx11Die::from_gc(12, 0, 1).is_some() {
        return TestResult::Fail("Phoenix or Navi48 resolved as an RDNA3 die");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx11-submit",
    gfx11_die_table_matches_corrected_pairing
);

fn gfx11_gfxhub_tables_are_per_die() -> TestResult {
    // gfxhub_v3_0 (GC 11.0.0 offsets) for Navi31; gfxhub_v3_0_3
    // (GC 11.0.3 offsets, +0x10) for Navi32; Navi33 takes the v3_0 table
    // (gmc_v11_0_set_gfxhub_funcs defaults everything but 11.0.3 to v3_0).
    let n31 = gfxhub_regs(Gfx11Die::Navi31);
    let n32 = gfxhub_regs(Gfx11Die::Navi32);
    let n33 = gfxhub_regs(Gfx11Die::Navi33);
    if n31
        != (GfxHubRegs {
            ptb_lo: 0x16f3,
            inv_req: 0x16ab,
            inv_ack: 0x16bd,
        })
    {
        return TestResult::Fail("Navi31 must take the gfxhub_v3_0 table");
    }
    if n32
        != (GfxHubRegs {
            ptb_lo: 0x1703,
            inv_req: 0x16bb,
            inv_ack: 0x16cd,
        })
    {
        return TestResult::Fail("Navi32 must take the gfxhub_v3_0_3 table");
    }
    if n33 != n31 {
        return TestResult::Fail("Navi33 must share Navi31's gfxhub_v3_0 table");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/gfx11-submit", gfx11_gfxhub_tables_are_per_die);

fn gfx11_invalidate_request_matches_linux_fields() -> TestResult {
    // PER_VMID_INVALIDATE_REQ at 0, L2_PTES/PDE0/PDE1/PDE2/L1_PTES at
    // 0x13..0x17, flush_type 0: (1 << vmid) | 0xF80000.
    for (vmid, want) in [
        (0u8, 0x00f8_0001u32),
        (1, 0x00f8_0002),
        (7, 0x00f8_0080),
        (15, 0x00f8_8000),
    ] {
        if invalidate_request(vmid) != want {
            return TestResult::Fail("the invalidate request for a VMID is wrong");
        }
    }
    // The tile-steering override is 0 on GFX11 (gfx_v11_0_constants_init).
    if TILE_STEERING_OVERRIDE != 0 {
        return TestResult::Fail("the tile-steering override must be 0");
    }
    // The GDS limit is total_cu * 32 - 1, masked to 12 bits.
    if gds_max_wave_id(Some(navi31_gc())) != Some(3071) || gds_max_wave_id(None).is_some() {
        return TestResult::Fail("the GDS wave-id limit does not follow the discovery geometry");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx11-submit",
    gfx11_invalidate_request_matches_linux_fields
);

fn gfx11_release_mem_fence_matches_gfx_v11_0() -> TestResult {
    let fence = release_mem_fence(0x1234_5678_9abc_def0, 0x42);
    // PACKET3(RELEASE_MEM, 6): 0xC0064900.
    if fence[0] != 0xc006_4900 {
        return TestResult::Fail("the fence header must be PACKET3(RELEASE_MEM, 6)");
    }
    // SEQ | GL2_WB | GLM_INV | GLM_WB | CACHE_POLICY(3) | EVENT_TYPE(0x14)
    // | EVENT_INDEX(5): 0x06603514.
    if fence[1] != 0x0660_3514 {
        return TestResult::Fail("the fence GCR does not match gfx_v11_0_ring_emit_fence");
    }
    // DATA_SEL(1) | INT_SEL(2): 0x22000000.
    if fence[2] != 0x2200_0000 {
        return TestResult::Fail("the fence must write 32-bit data with an EOP interrupt");
    }
    if fence[3] != 0x9abc_def0 || fence[4] != 0x1234_5678 || fence[5] != 0x42 {
        return TestResult::Fail("the fence address or sequence landed in the wrong dword");
    }
    if fence[6] != 0 || fence[7] != 0 || fence.len() != 8 {
        return TestResult::Fail("the fence is eight dwords with a zero tail");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx11-submit",
    gfx11_release_mem_fence_matches_gfx_v11_0
);

fn gfx11_context_control_switch_bits() -> TestResult {
    // gfx_v11_0_ring_emit_cntxcntl: load_enable alone without a switch.
    if context_control(false)
        != [
            pm4::packet3(pm4::PACKET3_CONTEXT_CONTROL, 1),
            0x8000_0000,
            0,
        ]
    {
        return TestResult::Fail("CONTEXT_CONTROL without a switch must be load_enable alone");
    }
    // With a switch: load_global_config/uconfig (0x8001), load_cs_sh_regs
    // (0x01000000), load_per_context_state + load_gfx_sh_regs (0x10002).
    if context_control(true)[1] != 0x8101_8003 {
        return TestResult::Fail("CONTEXT_CONTROL with a switch has the wrong load bits");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx11-submit",
    gfx11_context_control_switch_bits
);

fn gfx11_encode_gfx_frame_order() -> TestResult {
    let lay = layout();
    let hub = gfxhub_regs(Gfx11Die::Navi31);
    let ibs = [Ib {
        va: 0x1000,
        dwords: 4,
        flags: 0,
    }];
    let frame = Frame {
        gfx: true,
        engine: 0,
        sync: Some((0xaaaa_0000, 7)),
        flush: Some(VmRef {
            vmid: 3,
            page_table_base: 0x0001_2345_6789_abcd,
            pasid: 5,
            flush: true,
            map_pasid: true,
        }),
        pasid_map: Some((0x3, 5)),
        vm_fence: Some((0xbbbb_0000, 9)),
        vmid: 3,
        context_switch: true,
        gds_max_wave_id: None,
        ibs: &ibs,
        fence: 0xcccc_0000,
        seq: 11,
    };
    let w = match encode_cp(&lay, &hub, &frame) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("a well-formed gfx frame was refused"),
    };
    // 7 (sync) + 5+5 (PTB) + 7 (inv wait) + 2 (PFP_SYNC_ME) + 5 (LUT)
    // + 8 (VM fence) + 7 (HDP flush) + 3 (CONTEXT_CONTROL) + 2 (FRAME start)
    // + 4 (IB) + 2 (FRAME end) + 5 (HDP invalidate) + 8 (fence)
    // + 2 (SWITCH_BUFFER) = 72.
    if w.len() != 72 {
        return TestResult::Fail("a full gfx frame must be 72 dwords");
    }
    let p3 = pm4::packet3;
    // Pipeline sync: WAIT_REG_MEM on the ring fence, function equal.
    if w[0] != p3(pm4::PACKET3_WAIT_REG_MEM, 5) || w[1] != 0x113 || w[2] != 0xaaaa_0000 || w[4] != 7
    {
        return TestResult::Fail("the pipeline sync must open the frame");
    }
    // VM flush: PTB LO/HI for VMID 3 (0x16f3 + 2*3), then the invalidate
    // request wait on engine 0.
    if w[7] != p3(pm4::PACKET3_WRITE_DATA, 3) || w[9] != 0x16f9 || w[11] != 0x6789_abcd {
        return TestResult::Fail("the PTB LO write is wrong");
    }
    if w[14] != 0x16fa || w[16] != 0x0001_2345 {
        return TestResult::Fail("the PTB HI write is wrong");
    }
    if w[17] != p3(pm4::PACKET3_WAIT_REG_MEM, 5)
        || w[18] != 0x143
        || w[19] != 0x16ab
        || w[20] != 0x16bd
        || w[21] != 0x00f8_0008
        || w[22] != 0x8
    {
        return TestResult::Fail("the invalidate wait is wrong");
    }
    // PFP_SYNC_ME, then the PASID LUT write (OSS base + 0 + VMID 3).
    if w[24] != p3(pm4::PACKET3_PFP_SYNC_ME, 0) || w[28] != 0x3 || w[30] != 5 {
        return TestResult::Fail("PFP_SYNC_ME or the PASID map is wrong");
    }
    // VM fence: RELEASE_MEM with sequence 9.
    if w[31] != 0xc006_4900 || w[36] != 9 {
        return TestResult::Fail("the VM fence must follow the PASID map");
    }
    // HDP flush: WAIT_REG_MEM on the layout's req/done with the gfx mask.
    if w[39] != p3(pm4::PACKET3_WAIT_REG_MEM, 5)
        || w[40] != 0x143
        || w[41] != 0x5000
        || w[42] != 0x5004
        || w[43] != 0x1
    {
        return TestResult::Fail("the HDP flush is wrong");
    }
    // CONTEXT_CONTROL with the switch bits, FRAME_CONTROL start.
    if w[46] != p3(pm4::PACKET3_CONTEXT_CONTROL, 1) || w[47] != 0x8101_8003 {
        return TestResult::Fail("the context switch must load the context state");
    }
    if w[49] != p3(pm4::PACKET3_FRAME_CONTROL, 0) || w[50] != 0 {
        return TestResult::Fail("FRAME_CONTROL must open the IBs");
    }
    // The IB: INDIRECT_BUFFER, vmid 3 in the control dword.
    if w[51] != p3(pm4::PACKET3_INDIRECT_BUFFER, 2) || w[52] != 0x1000 || w[54] != 0x0300_0004 {
        return TestResult::Fail("the IB packet is wrong");
    }
    // FRAME_CONTROL end, HDP invalidate, fence, SWITCH_BUFFER.
    if w[55] != p3(pm4::PACKET3_FRAME_CONTROL, 0) || w[56] != (1 << 28) {
        return TestResult::Fail("FRAME_CONTROL must close the IBs");
    }
    if w[57] != p3(pm4::PACKET3_WRITE_DATA, 3) || w[59] != 0x60d1 || w[61] != 1 {
        return TestResult::Fail("the HDP invalidate is wrong");
    }
    if w[62] != 0xc006_4900 || w[67] != 11 {
        return TestResult::Fail("the job fence must carry sequence 11");
    }
    if w[70] != p3(pm4::PACKET3_SWITCH_BUFFER, 0) || w[71] != 0 {
        return TestResult::Fail("SWITCH_BUFFER must close the frame");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/gfx11-submit", gfx11_encode_gfx_frame_order);

fn gfx11_encode_compute_frame_has_no_gfx_packets() -> TestResult {
    let lay = layout();
    let hub = gfxhub_regs(Gfx11Die::Navi31);
    let ibs = [Ib {
        va: 0x2000,
        dwords: 8,
        flags: uapi::AMDGPU_IB_FLAG_RESET_GDS_MAX_WAVE_ID,
    }];
    let frame = Frame {
        gfx: false,
        engine: 4,
        sync: None,
        flush: Some(VmRef {
            vmid: 2,
            page_table_base: 0x1000,
            pasid: 3,
            flush: true,
            map_pasid: false,
        }),
        pasid_map: None,
        vm_fence: None,
        vmid: 2,
        context_switch: false,
        gds_max_wave_id: Some(3071),
        ibs: &ibs,
        fence: 0xdddd_0000,
        seq: 5,
    };
    let w = match encode_cp(&lay, &hub, &frame) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("a well-formed compute frame was refused"),
    };
    let p3 = pm4::packet3;
    // No CONTEXT_CONTROL, FRAME_CONTROL, SWITCH_BUFFER or PFP_SYNC_ME on a
    // compute ring.
    if w.iter().any(|&d| {
        d == p3(pm4::PACKET3_CONTEXT_CONTROL, 1)
            || d == p3(pm4::PACKET3_FRAME_CONTROL, 0)
            || d == p3(pm4::PACKET3_SWITCH_BUFFER, 0)
            || d == p3(pm4::PACKET3_PFP_SYNC_ME, 0)
    }) {
        return TestResult::Fail("a compute frame must not carry gfx-only packets");
    }
    // The GDS reset: SET_CONFIG_REG, GDS_COMPUTE_MAX_WAVE_ID, the limit.
    let Some(at) = w.windows(3).position(|t| {
        t[0] == p3(pm4::PACKET3_SET_CONFIG_REG, 1) && t[1] == GDS_COMPUTE_MAX_WAVE_ID
    }) else {
        return TestResult::Fail("the GDS reset packet is missing");
    };
    if w[at + 2] != 3071 {
        return TestResult::Fail("the GDS reset must carry the discovery limit");
    }
    // The IB: INDIRECT_BUFFER_VALID (1 << 23) set, vmid 2 in the control.
    let Some(ib) = w
        .windows(4)
        .position(|t| t[0] == p3(pm4::PACKET3_INDIRECT_BUFFER, 2))
    else {
        return TestResult::Fail("the compute IB is missing");
    };
    if w[ib + 3] != 8 | (2 << 24) | (1 << 23) {
        return TestResult::Fail("the compute IB control dword is wrong");
    }
    // The HDP flush uses ME (eng_sel 0): WAIT_REG_MEM dword 1 is 0x43.
    let Some(hdp) = w
        .windows(7)
        .position(|t| t[0] == p3(pm4::PACKET3_WAIT_REG_MEM, 5) && t[2] == 0x5000)
    else {
        return TestResult::Fail("the compute HDP flush is missing");
    };
    if w[hdp + 1] != 0x43 || w[hdp + 4] != 0x4 {
        return TestResult::Fail("the compute HDP flush must use ME with the compute mask");
    }
    // A GDS reset without a discovered limit is refused, not guessed.
    let mut no_gds = frame;
    no_gds.gds_max_wave_id = None;
    if encode_cp(&lay, &hub, &no_gds).is_ok() {
        return TestResult::Fail("a GDS reset without a limit must be refused");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx11-submit",
    gfx11_encode_compute_frame_has_no_gfx_packets
);

fn gfx11_encode_skips_flush_and_sync_without_switch() -> TestResult {
    let lay = layout();
    let hub = gfxhub_regs(Gfx11Die::Navi32);
    let ibs = [Ib {
        va: 0x1000,
        dwords: 4,
        flags: 0,
    }];
    let frame = Frame {
        gfx: true,
        engine: 0,
        sync: None,
        flush: None,
        pasid_map: None,
        vm_fence: None,
        vmid: 1,
        context_switch: false,
        gds_max_wave_id: None,
        ibs: &ibs,
        fence: 0xcccc_0000,
        seq: 2,
    };
    let w = match encode_cp(&lay, &hub, &frame) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("a no-flush gfx frame was refused"),
    };
    let p3 = pm4::packet3;
    // No pipeline sync (WAIT_REG_MEM on the fence), no PTB writes, no
    // PASID map, no VM fence: the only WAIT_REG_MEM is the HDP flush.
    let waits = w
        .windows(7)
        .filter(|t| t[0] == p3(pm4::PACKET3_WAIT_REG_MEM, 5))
        .count();
    if waits != 1 {
        return TestResult::Fail("a no-flush frame must wait only for the HDP flush");
    }
    if w.iter().any(|&d| d == 0x1703 || d == 0x1704) {
        return TestResult::Fail("a no-flush frame must not write the Navi32 PTB regs");
    }
    // CONTEXT_CONTROL is still emitted, with load_enable alone.
    let Some(at) = w
        .windows(3)
        .position(|t| t[0] == p3(pm4::PACKET3_CONTEXT_CONTROL, 1))
    else {
        return TestResult::Fail("CONTEXT_CONTROL must still be emitted");
    };
    if w[at + 1] != 0x8000_0000 {
        return TestResult::Fail("no context switch must load nothing extra");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx11-submit",
    gfx11_encode_skips_flush_and_sync_without_switch
);

fn gfx11_encode_mem_sync_packet() -> TestResult {
    let lay = layout();
    let hub = gfxhub_regs(Gfx11Die::Navi31);
    let ibs = [Ib {
        va: 0x1000,
        dwords: 4,
        flags: uapi::AMDGPU_IB_FLAG_EMIT_MEM_SYNC,
    }];
    let frame = Frame {
        gfx: true,
        engine: 0,
        sync: None,
        flush: None,
        pasid_map: None,
        vm_fence: None,
        vmid: 1,
        context_switch: false,
        gds_max_wave_id: None,
        ibs: &ibs,
        fence: 0xcccc_0000,
        seq: 1,
    };
    let w = match encode_cp(&lay, &hub, &frame) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("a mem-sync frame was refused"),
    };
    let p3 = pm4::packet3;
    let Some(at) = w
        .windows(8)
        .position(|t| t[0] == p3(pm4::PACKET3_ACQUIRE_MEM, 6))
    else {
        return TestResult::Fail("the ACQUIRE_MEM packet is missing");
    };
    // gfx_v11_0_emit_mem_sync: coher 0 / 0xffffffff / 0xffffff / 0 / 0,
    // poll 10, GCR 0xC3B1 (GL2_INV|GL2_WB|GLM_INV|GLM_WB|GL1_INV|GLV_INV|
    // GLK_INV|GLI_INV).
    if w[at + 1] != 0
        || w[at + 2] != 0xffff_ffff
        || w[at + 3] != 0x00ff_ffff
        || w[at + 6] != 10
        || w[at + 7] != 0xC3B1
    {
        return TestResult::Fail("the ACQUIRE_MEM packet does not match gfx_v11_0_emit_mem_sync");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/gfx11-submit", gfx11_encode_mem_sync_packet);

fn gfx11_validate_refuses_bad_submissions() -> TestResult {
    let lay = layout();
    let _ = lay;
    let vm = VmRef {
        vmid: 1,
        page_table_base: 0x1000,
        pasid: 1,
        flush: false,
        map_pasid: false,
    };
    let good = [Ib {
        va: 0x1000,
        dwords: 4,
        flags: 0,
    }];
    if validate(Ring::Gfx, vm, &good).is_err() {
        return TestResult::Fail("a well-formed submission was refused");
    }
    let bad_vmid = VmRef { vmid: 0, ..vm };
    let bad_vmid16 = VmRef { vmid: 16, ..vm };
    let empty: [Ib; 0] = [];
    let too_many = [Ib {
        va: 0x1000,
        dwords: 4,
        flags: 0,
    }; MAX_IBS + 1];
    let zero = [Ib {
        va: 0x1000,
        dwords: 0,
        flags: 0,
    }];
    let huge = [Ib {
        va: 0x1000,
        dwords: MAX_IB_DWORDS + 1,
        flags: 0,
    }];
    let unaligned = [Ib {
        va: 0x1002,
        dwords: 4,
        flags: 0,
    }];
    for (ring, v, ibs) in [
        (Ring::Gfx, bad_vmid, good.as_slice()),
        (Ring::Gfx, bad_vmid16, good.as_slice()),
        (Ring::Gfx, vm, empty.as_slice()),
        (Ring::Gfx, vm, too_many.as_slice()),
        (Ring::Gfx, vm, zero.as_slice()),
        (Ring::Gfx, vm, huge.as_slice()),
        (Ring::Gfx, vm, unaligned.as_slice()),
        (Ring::GfxSecondary, vm, good.as_slice()),
    ] {
        if validate(ring, v, ibs).is_ok() {
            return TestResult::Fail("an invalid submission was accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx11-submit",
    gfx11_validate_refuses_bad_submissions
);

fn gfx11_preamble_install_emits_csb_and_secondary() -> TestResult {
    let backend = Arc::new(FixtureBackend::new());
    let submitter = Navi31Submitter::new(0x9d31_0801, config(Gfx11Die::Navi31), backend.clone());
    if submitter.preamble_installed() {
        return TestResult::Fail("the preamble must start uninstalled");
    }
    if submitter.install_preamble(2).is_err() {
        return TestResult::Fail("preamble install was refused");
    }
    if !submitter.preamble_installed() {
        return TestResult::Fail("preamble install must set the flag");
    }
    let csb = backend.last_emitted(Ring::Gfx);
    if csb.len() as u32 != amdgpu_clearstate::CSB_DWORDS || csb.len() != 960 {
        return TestResult::Fail("the CSB must be 960 dwords");
    }
    if csb[0] != pm4::packet3(pm4::PACKET3_PREAMBLE_CNTL, 0)
        || csb[1] != amdgpu_clearstate::PREAMBLE_BEGIN_CLEAR_STATE
    {
        return TestResult::Fail("the CSB must open with BEGIN_CLEAR_STATE");
    }
    let second = backend.last_emitted(Ring::GfxSecondary);
    if second.len() != 2 || second[0] != pm4::packet3(pm4::PACKET3_CLEAR_STATE, 0) || second[1] != 0
    {
        return TestResult::Fail("the second gfx ring must get only CLEAR_STATE");
    }
    // One gfx ring: no secondary emission.
    let backend1 = Arc::new(FixtureBackend::new());
    let one = Navi31Submitter::new(0x9d31_0802, config(Gfx11Die::Navi31), backend1.clone());
    if one.install_preamble(1).is_err() || backend1.emitted_count(Ring::GfxSecondary) != 0 {
        return TestResult::Fail("one gfx ring must not emit a secondary CLEAR_STATE");
    }
    // A GC window-1 base outside the context aperture fails closed.
    let mut bad = config(Gfx11Die::Navi31);
    bad.layout.gc_base_1 = 0;
    let backend2 = Arc::new(FixtureBackend::new());
    let bad_submitter = Navi31Submitter::new(0x9d31_0803, bad, backend2.clone());
    if bad_submitter.install_preamble(1).is_ok() || bad_submitter.preamble_installed() {
        return TestResult::Fail("a bad GC window-1 base must fail closed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx11-submit",
    gfx11_preamble_install_emits_csb_and_secondary
);

fn gfx11_submitter_registers_and_answers_ring_for() -> TestResult {
    let backend = Arc::new(FixtureBackend::new());
    let card = 0x9d31_0804;
    let submitter = Navi31Submitter::register(card, config(Gfx11Die::Navi31), backend.clone());
    if crate::amdgpu_cs::submitter(card).is_none() {
        return TestResult::Fail("register must publish the submitter");
    }
    use crate::amdgpu_cs::Submitter as _;
    if submitter.ring_for(uapi::AMDGPU_HW_IP_GFX, 0, 0) != Some(0) {
        return TestResult::Fail("the gfx ring must resolve");
    }
    if submitter.ring_for(uapi::AMDGPU_HW_IP_COMPUTE, 0, 2) != Some(1) {
        return TestResult::Fail("compute rings 0-3 must share the one compute queue");
    }
    // DMA/VCN/JPEG belong to lanes 7 and 10: refused, not misrouted.
    for (ip, inst, ring) in [
        (uapi::AMDGPU_HW_IP_DMA, 0, 0),
        (uapi::AMDGPU_HW_IP_VCN_DEC, 0, 0),
        (uapi::AMDGPU_HW_IP_VCN_JPEG, 0, 0),
    ] {
        if submitter.ring_for(ip, inst, ring).is_some() {
            return TestResult::Fail("a non-GFX11 ring resolved");
        }
    }
    if submitter.max_ibs(0) != MAX_IBS as u32
        || submitter.max_ibs(1) != MAX_IBS as u32
        || submitter.max_ibs(2) != 0
    {
        return TestResult::Fail("max_ibs is wrong");
    }
    Navi31Submitter::unregister(card);
    if crate::amdgpu_cs::submitter(card).is_some() {
        return TestResult::Fail("unregister must withdraw the submitter");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx11-submit",
    gfx11_submitter_registers_and_answers_ring_for
);

fn gfx11_submit_end_to_end_on_fixture_backend() -> TestResult {
    const CARD: u32 = 0x9d31_0805;
    const VA: u64 = 0xffff_8001_0007_0000;
    let backend = Arc::new(FixtureBackend::new());
    let mut cfg = config(Gfx11Die::Navi31);
    cfg.gc = Some(navi31_gc());
    let submitter = Navi31Submitter::register(CARD, cfg, backend.clone());
    let (_gem, vm, _handle) = client_space(CARD, VA, 0x2000);
    let health = Arc::new(Health::default());
    use crate::amdgpu_cs::Submitter as _;
    // No preamble yet: refused before any ring access.
    let sub = gfx_submission(7, VA);
    if run(submitter.submit(&vm, &sub, &health)) != Err(FsError::InvalidData) {
        return TestResult::Fail("a submission before the preamble must be refused");
    }
    if submitter.install_preamble(2).is_err() {
        return TestResult::Fail("preamble install was refused");
    }
    // First submission: new context, so a context switch; VMID 1, flush.
    let ticket = match run(submitter.submit(&vm, &sub, &health)) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("a well-formed submission was refused"),
    };
    if ticket != 1 {
        return TestResult::Fail("the first ticket must be ring 0, sequence 1");
    }
    let frame = backend.last_emitted(Ring::Gfx);
    let p3 = pm4::packet3;
    let Some(at) = frame
        .windows(3)
        .position(|t| t[0] == p3(pm4::PACKET3_CONTEXT_CONTROL, 1))
    else {
        return TestResult::Fail("the frame must carry CONTEXT_CONTROL");
    };
    if frame[at + 1] != 0x8101_8003 {
        return TestResult::Fail("the first job of a context must switch context");
    }
    let Some(ib) = frame
        .windows(4)
        .position(|t| t[0] == p3(pm4::PACKET3_INDIRECT_BUFFER, 2))
    else {
        return TestResult::Fail("the frame must carry the IB");
    };
    if frame[ib + 3] != 4 | (1 << 24) {
        return TestResult::Fail("the IB must run under VMID 1");
    }
    if frame[frame.len() - 3] != 1 {
        return TestResult::Fail("the fence must carry sequence 1");
    }
    // Uncompleted: not signalled, not retired; then the backend reports
    // the fence and the job retires with a signal time.
    if submitter.signalled(ticket) || submitter.retired(ticket) {
        return TestResult::Fail("an uncompleted job must not signal or retire");
    }
    backend.complete(Ring::Gfx, 1);
    if !submitter.signalled(ticket) {
        return TestResult::Fail("a completed fence must signal");
    }
    let deadline = narf_time::monotonic_ns() + 1_000_000_000;
    if run(submitter.wait(ticket, deadline)) != Ok(true) {
        return TestResult::Fail("wait must report a completed job");
    }
    if !submitter.retired(ticket) || submitter.signal_time(ticket).is_none() {
        return TestResult::Fail("a completed job must retire with a signal time");
    }
    // Second submission, same context: no switch, no flush (same VMID and
    // root), pipeline sync skipped.
    let ticket2 = match run(submitter.submit(&vm, &sub, &health)) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("the second submission was refused"),
    };
    if ticket2 != 2 {
        return TestResult::Fail("the second ticket must be sequence 2");
    }
    let frame2 = backend.last_emitted(Ring::Gfx);
    let Some(at2) = frame2
        .windows(3)
        .position(|t| t[0] == p3(pm4::PACKET3_CONTEXT_CONTROL, 1))
    else {
        return TestResult::Fail("the second frame must carry CONTEXT_CONTROL");
    };
    if frame2[at2 + 1] != 0x8000_0000 {
        return TestResult::Fail("the same context must not switch again");
    }
    // Third submission, another context: the switch returns.
    let sub3 = gfx_submission(8, VA);
    if run(submitter.submit(&vm, &sub3, &health)).is_err() {
        return TestResult::Fail("the third submission was refused");
    }
    let frame3 = backend.last_emitted(Ring::Gfx);
    let Some(at3) = frame3
        .windows(3)
        .position(|t| t[0] == p3(pm4::PACKET3_CONTEXT_CONTROL, 1))
    else {
        return TestResult::Fail("the third frame must carry CONTEXT_CONTROL");
    };
    if frame3[at3 + 1] != 0x8101_8003 {
        return TestResult::Fail("a new context must switch again");
    }
    Navi31Submitter::unregister(CARD);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx11-submit",
    gfx11_submit_end_to_end_on_fixture_backend
);

fn gfx11_submit_refuses_dma_and_unmapped_vm() -> TestResult {
    const CARD: u32 = 0x9d31_0806;
    const VA: u64 = 0xffff_8001_0007_0000;
    let backend = Arc::new(FixtureBackend::new());
    let submitter = Navi31Submitter::register(CARD, config(Gfx11Die::Navi31), backend.clone());
    let (_gem, vm, _handle) = client_space(CARD, VA, 0x2000);
    let health = Arc::new(Health::default());
    use crate::amdgpu_cs::Submitter as _;
    if submitter.install_preamble(1).is_err() {
        return TestResult::Fail("setup: preamble install was refused");
    }
    // DMA belongs to lane 7.
    let mut dma = gfx_submission(7, VA);
    dma.ibs[0].ip_type = uapi::AMDGPU_HW_IP_DMA;
    if run(submitter.submit(&vm, &dma, &health)) != Err(FsError::InvalidData) {
        return TestResult::Fail("a DMA submission must be refused");
    }
    // A VM with no root has no page-table base to flush.
    let empty = VmState::new();
    let sub = gfx_submission(7, VA);
    if run(submitter.submit(&empty, &sub, &health)) != Err(FsError::InvalidData) {
        return TestResult::Fail("a submission without a mapped root must be refused");
    }
    Navi31Submitter::unregister(CARD);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx11-submit",
    gfx11_submit_refuses_dma_and_unmapped_vm
);

fn gfx11_dark_device_fails_waits_without_wedging() -> TestResult {
    const CARD: u32 = 0x9d31_0807;
    const VA: u64 = 0xffff_8001_0007_0000;
    let backend = Arc::new(FixtureBackend::new());
    let submitter = Navi31Submitter::register(CARD, config(Gfx11Die::Navi31), backend.clone());
    let (_gem, vm, _handle) = client_space(CARD, VA, 0x2000);
    let health = Arc::new(Health::default());
    use crate::amdgpu_cs::Submitter as _;
    if submitter.install_preamble(1).is_err() {
        return TestResult::Fail("setup: preamble install was refused");
    }
    let sub = gfx_submission(7, VA);
    let ticket = match run(submitter.submit(&vm, &sub, &health)) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("setup: submission was refused"),
    };
    // The device stops answering: a vanished device reports done so
    // waiters cannot wedge, and wait reports the loss.
    backend.go_dark();
    if !submitter.signalled(ticket) {
        return TestResult::Fail("a vanished device must report jobs done");
    }
    let deadline = narf_time::monotonic_ns() + 1_000_000_000;
    if run(submitter.wait(ticket, deadline)) != Err(FsError::NoDevice) {
        return TestResult::Fail("wait on a dark device must fail NoDevice");
    }
    if submitter.error(ticket) != Some(FsError::NoDevice) {
        return TestResult::Fail("the dark device must surface as the job error");
    }
    // A new submission after the loss is refused.
    if run(submitter.submit(&vm, &sub, &health)) != Err(FsError::NoDevice) {
        return TestResult::Fail("a submission after device loss must be refused");
    }
    Navi31Submitter::unregister(CARD);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx11-submit",
    gfx11_dark_device_fails_waits_without_wedging
);
