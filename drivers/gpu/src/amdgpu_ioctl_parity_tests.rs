//! amdgpu private-ioctl errnos and semantics against Linux
//! (amdgpu_ctx.c, amdgpu_cs.c, amdgpu_gem.c).
use crate::amdgpu_ctx::{dispatch as ctx_dispatch, CtxState};
use crate::amdgpu_gem::GemState;
use crate::amdgpu_uapi as u;
use crate::amdgpu_vm::{self as vm, VmState, GPU_PAGE_SIZE};
use crate::drm_uapi::DRM_COMMAND_BASE;
use narf_filesystem::FsError;
use narf_kernel_test::{kernel_test_in, TestResult};

fn ctx_call(state: &CtxState, op: u32, id: u32) -> (Result<u64, FsError>, [u8; 16]) {
    let mut req = [0u8; core::mem::size_of::<u::DrmAmdgpuCtx>()];
    req[0..4].copy_from_slice(&op.to_le_bytes());
    req[8..12].copy_from_slice(&id.to_le_bytes());
    let rc = ctx_dispatch(
        DRM_COMMAND_BASE + u::DRM_AMDGPU_CTX,
        req.as_mut_ptr() as usize,
        state,
        false,
    );
    let mut out = [0u8; 16];
    out.copy_from_slice(&req[..16]);
    (rc, out)
}

/// amdgpu_ctx.c: an unknown ctx id is -EINVAL for every op, and
/// QUERY_STATE reports a reset at most once (`reset_counter_query`).
fn amdgpu_ctx_errnos_and_reset_query_match_linux() -> TestResult {
    let state = CtxState::new();
    for op in [
        u::AMDGPU_CTX_OP_FREE_CTX,
        u::AMDGPU_CTX_OP_QUERY_STATE,
        u::AMDGPU_CTX_OP_QUERY_STATE2,
        u::AMDGPU_CTX_OP_GET_STABLE_PSTATE,
    ] {
        if ctx_call(&state, op, 4242).0 != Err(FsError::InvalidData) {
            return TestResult::Fail("an unknown ctx id is not EINVAL");
        }
    }
    let (rc, out) = ctx_call(&state, u::AMDGPU_CTX_OP_ALLOC_CTX, 0);
    if rc.is_err() {
        return TestResult::Fail("setup: ALLOC_CTX");
    }
    let id = u32::from_le_bytes(out[0..4].try_into().unwrap());
    for _ in 0..2 {
        let (rc, out) = ctx_call(&state, u::AMDGPU_CTX_OP_QUERY_STATE, id);
        let status = u32::from_le_bytes(out[12..16].try_into().unwrap());
        if rc.is_err() || status != u::AMDGPU_CTX_NO_RESET {
            return TestResult::Fail("QUERY_STATE without a reset is not NO_RESET");
        }
    }
    // A failed job reports UNKNOWN_RESET once (the ring reset bumps
    // gpu_reset_counter), then NO_RESET.
    if let Some(health) = state.health(id) {
        health.mark_guilty();
    } else {
        return TestResult::Fail("setup: context health");
    }
    let statuses: alloc::vec::Vec<u32> = (0..2)
        .map(|_| {
            let (_, out) = ctx_call(&state, u::AMDGPU_CTX_OP_QUERY_STATE, id);
            u32::from_le_bytes(out[12..16].try_into().unwrap())
        })
        .collect();
    if statuses != [u::AMDGPU_CTX_UNKNOWN_RESET, u::AMDGPU_CTX_NO_RESET] {
        return TestResult::Fail("a hang is not reported exactly once by QUERY_STATE");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/ioctl-parity",
    amdgpu_ctx_errnos_and_reset_query_match_linux
);

/// amdgpu_gem.c: GEM_OP on an unknown handle is -ENOENT
/// (drm_gem_object_lookup), not EINVAL.
fn amdgpu_gem_op_unknown_handle_is_enoent() -> TestResult {
    let gem = GemState::new();
    let mut op = [0u8; 24];
    op[0..4].copy_from_slice(&0xffffu32.to_le_bytes());
    op[4..8].copy_from_slice(&u::AMDGPU_GEM_OP_GET_GEM_CREATE_INFO.to_le_bytes());
    if crate::amdgpu_gem::dispatch(
        DRM_COMMAND_BASE + u::DRM_AMDGPU_GEM_OP,
        op.as_mut_ptr() as usize,
        &gem,
    ) != Err(FsError::NotFound)
    {
        return TestResult::Fail("GEM_OP of an unknown handle is not ENOENT");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/ioctl-parity",
    amdgpu_gem_op_unknown_handle_is_enoent
);

/// amdgpu_cs_pass1/amdgpu_cs_p2_shadow: CP_GFX_SHADOW is accepted with
/// INIT_SHADOW (ignored on GFX10.3) and refused with an undefined flag.
fn amdgpu_cs_accepts_cp_gfx_shadow_like_linux() -> TestResult {
    let gem = GemState::new();
    let state = VmState::new();
    let ctx = CtxState::new();
    let (rc, out) = ctx_call(&ctx, u::AMDGPU_CTX_OP_ALLOC_CTX, 0);
    if rc.is_err() {
        return TestResult::Fail("setup: ALLOC_CTX");
    }
    let ctx_id = u32::from_le_bytes(out[0..4].try_into().unwrap());
    const IB_VA: u64 = 0x2_0000_0000;
    let mut create = [0u8; 32];
    create[0..8].copy_from_slice(&GPU_PAGE_SIZE.to_le_bytes());
    create[16..24].copy_from_slice(&(u::AMDGPU_GEM_DOMAIN_GTT as u64).to_le_bytes());
    if crate::amdgpu_gem::dispatch(
        DRM_COMMAND_BASE + u::DRM_AMDGPU_GEM_CREATE,
        create.as_mut_ptr() as usize,
        &gem,
    )
    .is_err()
    {
        return TestResult::Fail("setup: GEM_CREATE");
    }
    let handle = u32::from_le_bytes(create[0..4].try_into().unwrap());
    let mut m = [0u8; 40];
    m[0..4].copy_from_slice(&handle.to_le_bytes());
    m[8..12].copy_from_slice(&u::AMDGPU_VA_OP_MAP.to_le_bytes());
    m[12..16]
        .copy_from_slice(&(u::AMDGPU_VM_PAGE_READABLE | u::AMDGPU_VM_PAGE_WRITEABLE).to_le_bytes());
    m[16..24].copy_from_slice(&IB_VA.to_le_bytes());
    m[32..40].copy_from_slice(&GPU_PAGE_SIZE.to_le_bytes());
    if vm::dispatch(
        DRM_COMMAND_BASE + u::DRM_AMDGPU_GEM_VA,
        m.as_mut_ptr() as usize,
        &state,
        &gem,
        None,
    )
    .is_err()
    {
        return TestResult::Fail("setup: GEM_VA map");
    }
    let parse = |shadow_flags: u32| {
        let mut ib = [0u32; 8];
        ib[2] = IB_VA as u32;
        ib[3] = (IB_VA >> 32) as u32;
        ib[4] = 64;
        ib[5] = u::AMDGPU_HW_IP_GFX;
        let mut shadow = [0u32; 8];
        shadow[6] = shadow_flags;
        let header = |id: u32, body: &[u32; 8]| {
            let p = body.as_ptr() as u64;
            [id, 8, p as u32, (p >> 32) as u32]
        };
        let h0 = header(u::AMDGPU_CHUNK_ID_IB, &ib);
        let h1 = header(u::AMDGPU_CHUNK_ID_CP_GFX_SHADOW, &shadow);
        let pointers = [h0.as_ptr() as u64, h1.as_ptr() as u64];
        crate::amdgpu_cs::parse(ctx_id, 2, pointers.as_ptr() as u64, &state, &ctx)
            .map(|s| s.ibs.len())
    };
    if parse(u::AMDGPU_CS_CHUNK_CP_GFX_SHADOW_FLAGS_INIT_SHADOW) != Ok(1) {
        return TestResult::Fail("CP_GFX_SHADOW with INIT_SHADOW refused");
    }
    if parse(0x2).is_ok() {
        return TestResult::Fail("CP_GFX_SHADOW with an undefined flag accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/ioctl-parity",
    amdgpu_cs_accepts_cp_gfx_shadow_like_linux
);
