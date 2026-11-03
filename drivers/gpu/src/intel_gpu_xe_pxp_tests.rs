// Native Xe PXP UAPI on MTL without an enabled PXP. MIT Linux b90c984d:
// xe_query.c::query_pxp_status, xe_exec_queue.c::{exec_queue_user_ext_set_
// property,exec_queue_set_pxp_type}, xe_bo.c::{gem_create_user_extensions,
// gem_create_user_ext_set_property,gem_create_set_pxp_type} and xe_pxp.c::
// {xe_pxp_is_supported,xe_pxp_get_readiness_status,xe_pxp_key_assign}:
// without CONFIG_INTEL_MEI_GSC_PROXY xe->pxp is NULL, which is NARF's case.
use super::*;

/// One set-property extension (drm_xe_user_extension + drm_xe_ext_set_property).
fn pxp_extension(user: &Cpu, at: u64, next: u64, name: u32, property: u32, value: u64) {
    let mut ext = [0; 48];
    put64(&mut ext, 0, next);
    put32(&mut ext, 8, name);
    put32(&mut ext, 16, property);
    put64(&mut ext, 24, value);
    user.wire.store(at, &ext);
}

fn smoke_xe_pxp_type_query_and_bo_refuse_with_linux_errnos() -> TestResult {
    let platform = GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake);
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let (_, info) = setup(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();

    // DRM_XE_DEVICE_QUERY_PXP_STATUS: size negotiation reports
    // sizeof(struct drm_xe_query_pxp_status), a wrong size is -EINVAL and
    // the exact size is -ENODEV with nothing copied out.
    let mut query = [0; 40];
    put32(&mut query, 8, 9);
    user.wire.store(64, &query);
    assert_eq!(invoke(&file, &info, &user, xe::DEVICE_QUERY), Ok(0));
    assert_eq!(u32_at(&user.wire.load(64, 40), 12), 8);
    user.wire.store(4096, &[0xa5; 8]);
    put64(&mut query, 16, 4096);
    for (size, error) in [
        (4, FsError::InvalidData),
        (16, FsError::InvalidData),
        (8, FsError::NoDevice),
    ] {
        put32(&mut query, 12, size);
        user.wire.store(64, &query);
        assert_eq!(invoke(&file, &info, &user, xe::DEVICE_QUERY), Err(error));
    }
    assert_eq!(user.wire.load(4096, 8), [0xa5; 8]);
    // xe_query_ioctl refuses extensions before the query function runs.
    put64(&mut query, 0, 8192);
    user.wire.store(64, &query);
    assert_eq!(
        invoke(&file, &info, &user, xe::DEVICE_QUERY),
        Err(FsError::InvalidData)
    );

    // DRM_XE_EXEC_QUEUE_SET_PROPERTY_PXP_TYPE on an RCS0 queue.
    let vm = create_vm(&file, &info, &user);
    user.wire.store(512, &[0u8; 8]);
    let queue = |extensions: u64| {
        let mut wire = [0; 48];
        put64(&mut wire, 0, extensions);
        put32(&mut wire, 8, 0x00010001);
        put32(&mut wire, 12, vm);
        put64(&mut wire, 24, 512);
        user.wire.store(64, &wire);
        let result = invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE);
        (result, u32_at(&user.wire.load(64, 48), 20))
    };
    let before = arena.live_allocations();
    // HWDRM is -ENODEV; any other session type is -EINVAL.
    for (value, error) in [
        (1, FsError::NoDevice),
        (2, FsError::InvalidData),
        (u64::MAX, FsError::InvalidData),
    ] {
        pxp_extension(&user, 8192, 0, 0, 2, value);
        assert_eq!(queue(8192), (Err(error), 0));
    }
    // NONE is accepted and the chain refuses at the HWDRM that follows.
    pxp_extension(&user, 8192, 8256, 0, 2, 0);
    pxp_extension(&user, 8256, 0, 0, 2, 1);
    assert_eq!(queue(8192), (Err(FsError::NoDevice), 0));
    assert_eq!(arena.live_allocations(), before);
    // NONE alone is the default and creates the queue.
    pxp_extension(&user, 8192, 0, 0, 2, 0);
    let (result, id) = queue(8192);
    assert_eq!(result, Ok(0));
    assert_ne!(id, 0);
    let mut destroy = [0; 24];
    put32(&mut destroy, 0, id);
    user.wire.store(64, &destroy);
    assert_eq!(invoke(&file, &info, &user, xe::EXEC_QUEUE_DESTROY), Ok(0));

    // DRM_XE_GEM_CREATE_SET_PROPERTY_PXP_TYPE on a system object.
    let gem = |extensions: u64, vm: u32, size: u64| {
        let mut wire = [0; 56];
        put64(&mut wire, 0, extensions);
        put64(&mut wire, 8, size);
        put32(&mut wire, 16, 1);
        put32(&mut wire, 24, vm);
        wire[32] = 1;
        user.wire.store(64, &wire);
        let result = invoke(&file, &info, &user, xe::GEM_CREATE);
        (result, u32_at(&user.wire.load(64, 56), 28))
    };
    // gem_create_set_pxp_type: HWDRM reaches xe_pxp_key_assign(NULL).
    pxp_extension(&user, 8192, 0, 0, 0, 1);
    assert_eq!(gem(8192, 0, 4096), (Err(FsError::NoDevice), 0));
    // Ioctl argument and VM refusals come first: the chain runs only once
    // the object exists.
    assert_eq!(gem(8192, 0, 4095), (Err(FsError::InvalidData), 0));
    assert_eq!(gem(8192, 99, 4096), (Err(FsError::NotFound), 0));
    for value in [2, u64::MAX] {
        pxp_extension(&user, 8192, 0, 0, 0, value);
        assert_eq!(gem(8192, 0, 4096), (Err(FsError::InvalidData), 0));
    }
    // Only property 0 (PXP_TYPE) and extension name 0 (SET_PROPERTY) exist.
    pxp_extension(&user, 8192, 0, 0, 1, 0);
    assert_eq!(gem(8192, 0, 4096), (Err(FsError::InvalidData), 0));
    pxp_extension(&user, 8192, 0, 1, 0, 0);
    assert_eq!(gem(8192, 0, 4096), (Err(FsError::InvalidData), 0));
    // Either pad word is -EINVAL.
    for pad in [8192 + 12, 8192 + 20] {
        pxp_extension(&user, 8192, 0, 0, 0, 0);
        user.wire.store(pad, &1u32.to_le_bytes());
        assert_eq!(gem(8192, 0, 4096), (Err(FsError::InvalidData), 0));
    }
    // The header is copied before the body: a bad name at the end of the
    // user range is -EINVAL, a good one whose body is unreadable -EFAULT.
    let edge = 32768 - 16;
    pxp_extension(&user, 8192, 0, 0, 0, 0);
    user.wire.store(edge, &{
        let mut base = [0u8; 16];
        put32(&mut base, 8, 1);
        base
    });
    assert_eq!(gem(edge, 0, 4096), (Err(FsError::InvalidData), 0));
    user.wire.store(edge, &[0u8; 16]);
    assert_eq!(gem(edge, 0, 4096), (Err(FsError::BadAddress), 0));
    assert_eq!(gem(0x10000, 0, 4096), (Err(FsError::BadAddress), 0));
    // NONE then HWDRM refuses at the second extension.
    pxp_extension(&user, 8192, 8256, 0, 0, 0);
    pxp_extension(&user, 8256, 0, 0, 0, 1);
    assert_eq!(gem(8192, 0, 4096), (Err(FsError::NoDevice), 0));
    // Sixteen NONE extensions are accepted; a seventeenth is Linux's
    // -E2BIG, which FsError carries as -EINVAL.
    for index in 0..17u64 {
        let next = if index == 16 {
            0
        } else {
            8192 + (index + 1) * 64
        };
        pxp_extension(&user, 8192 + index * 64, next, 0, 0, 0);
    }
    assert_eq!(gem(8192, 0, 4096), (Err(FsError::InvalidData), 0));
    pxp_extension(&user, 8192 + 15 * 64, 0, 0, 0, 0);
    let (result, handle) = gem(8192, 0, 4096);
    assert_eq!(result, Ok(0));
    assert!(file.gem.object(handle).is_ok());
    // No refused request published an object under any earlier handle.
    for earlier in handle.saturating_sub(32)..handle {
        assert!(file.gem.object(earlier).is_err());
    }

    drop(file);
    drop(info);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_xe_pxp_type_query_and_bo_refuse_with_linux_errnos
);
