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

/// `len` chained PXP_TYPE NONE extensions at 8192, 8256, ... (64 apart).
fn none_chain(user: &Cpu, len: u64, property: u32) {
    for index in 0..len {
        let next = if index + 1 == len {
            0
        } else {
            8192 + (index + 1) * 64
        };
        pxp_extension(user, 8192 + index * 64, next, 0, property, 0);
    }
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
    // __exec_queue_user_extensions: `if (ext_number >= MAX_USER_EXTENSIONS)
    // return -E2BIG;`, MAX_USER_EXTENSIONS being 16. A seventeenth extension
    // is -E2BIG, not the -EINVAL this used to fold into.
    none_chain(&user, 17, 2);
    assert_eq!(queue(8192), (Err(FsError::ArgumentListTooLong), 0));
    // The bound precedes copy_from_user: a seventeenth at an unreadable
    // address is -E2BIG, never -EFAULT.
    pxp_extension(&user, 8192 + 15 * 64, 0x10000, 0, 2, 0);
    assert_eq!(queue(8192), (Err(FsError::ArgumentListTooLong), 0));
    // The sixteenth (ext_number 15) is still copied and applied in full: its
    // HWDRM is -ENODEV although a seventeenth follows.
    pxp_extension(&user, 8192 + 15 * 64, 8192 + 16 * 64, 0, 2, 1);
    assert_eq!(queue(8192), (Err(FsError::NoDevice), 0));
    // Linux keeps no visited set: an extension that names itself is applied
    // sixteen times and the seventeenth visit is -E2BIG.
    pxp_extension(&user, 8192, 8192, 0, 2, 0);
    assert_eq!(queue(8192), (Err(FsError::ArgumentListTooLong), 0));
    assert_eq!(arena.live_allocations(), before);
    let destroy_queue = |id: u32| {
        let mut destroy = [0; 24];
        put32(&mut destroy, 0, id);
        user.wire.store(64, &destroy);
        assert_eq!(invoke(&file, &info, &user, xe::EXEC_QUEUE_DESTROY), Ok(0));
    };
    // NONE alone is the default and creates the queue.
    pxp_extension(&user, 8192, 0, 0, 2, 0);
    let (result, id) = queue(8192);
    assert_eq!(result, Ok(0));
    assert_ne!(id, 0);
    destroy_queue(id);
    // Sixteen chained extensions are within the bound.
    none_chain(&user, 16, 2);
    let (result, id) = queue(8192);
    assert_eq!(result, Ok(0));
    assert_ne!(id, 0);
    destroy_queue(id);

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
    // gem_create_user_extensions: `if (ext_number >= MAX_USER_EXTENSIONS)
    // return -E2BIG;`, MAX_USER_EXTENSIONS being 16. This pinned -EINVAL
    // while FsError had no E2BIG; Linux's answer is -E2BIG.
    none_chain(&user, 17, 0);
    assert_eq!(gem(8192, 0, 4096), (Err(FsError::ArgumentListTooLong), 0));
    // Like every extension verdict it lands only once the object exists, so
    // the ioctl argument and VM refusals still come first.
    assert_eq!(gem(8192, 0, 4095), (Err(FsError::InvalidData), 0));
    assert_eq!(gem(8192, 99, 4096), (Err(FsError::NotFound), 0));
    // The bound precedes copy_from_user: the seventeenth is never read, so
    // neither its bad name nor its HWDRM matters, and an unreadable address
    // is -E2BIG rather than -EFAULT.
    pxp_extension(&user, 8192 + 16 * 64, 0, 1, 0, 1);
    assert_eq!(gem(8192, 0, 4096), (Err(FsError::ArgumentListTooLong), 0));
    pxp_extension(&user, 8192 + 15 * 64, 0x10000, 0, 0, 0);
    assert_eq!(gem(8192, 0, 4096), (Err(FsError::ArgumentListTooLong), 0));
    // The sixteenth (ext_number 15) is still copied and applied in full: its
    // HWDRM is -ENODEV although a seventeenth follows.
    pxp_extension(&user, 8192 + 15 * 64, 8192 + 16 * 64, 0, 0, 1);
    assert_eq!(gem(8192, 0, 4096), (Err(FsError::NoDevice), 0));
    // No visited set: a self-referencing NONE is applied sixteen times and
    // the seventeenth visit is -E2BIG.
    pxp_extension(&user, 8192, 8192, 0, 0, 0);
    assert_eq!(gem(8192, 0, 4096), (Err(FsError::ArgumentListTooLong), 0));
    // Sixteen NONE extensions are accepted.
    none_chain(&user, 16, 0);
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

// MIT Linux b90c984d xe_exec_queue.c::{xe_exec_queue_create_ioctl,
// __exec_queue_user_extensions,exec_queue_user_ext_set_property,
// exec_queue_user_ext_check_final,exec_queue_set_multi_group,
// exec_queue_set_multi_queue_priority,exec_queue_set_hang_replay_state} and
// xe_lrc.c::xe_gt_lrc_hang_replay_size, on MTL (GRAPHICS_VER 12).
fn smoke_xe_exec_queue_extensions_follow_linux_check_order() -> TestResult {
    let platform = GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake);
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let (_, info) = setup(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let vm = create_vm(&file, &info, &user);
    let doomed = create_vm(&file, &info, &user);
    assert_eq!(close(&file, &info, &user, xe::VM_DESTROY, doomed), Ok(0));
    // RCS0 at 512, VM_BIND at 520 and an RCS0/RCS0 width-two row at 528.
    user.wire.store(512, &[0u8; 8]);
    user.wire.store(520, &[5, 0, 0, 0, 0, 0, 0, 0]);
    user.wire.store(528, &[0u8; 16]);
    let create = |extensions: u64, vm: u32, instances: u64, width: u32| {
        let mut wire = [0; 48];
        put64(&mut wire, 0, extensions);
        put32(&mut wire, 8, width | 1 << 16);
        put32(&mut wire, 12, vm);
        put64(&mut wire, 24, instances);
        user.wire.store(64, &wire);
        let result = invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE);
        (result, u32_at(&user.wire.load(64, 48), 20))
    };
    let queue = |extensions: u64| create(extensions, vm, 512, 1);
    let bind = |extensions: u64| create(extensions, vm, 520, 1);
    let destroy_queue = |id: u32| {
        assert_eq!(
            close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, id),
            Ok(0)
        );
    };
    let before = arena.live_allocations();

    // __exec_queue_user_extensions copies the 16-byte drm_xe_user_extension
    // and refuses its pad or name before exec_queue_user_ext_set_property
    // copies the 48-byte body. At the end of the user range a bad header is
    // -EINVAL; a good one whose body is unreadable is -EFAULT.
    let edge = 32768 - 16;
    for (at, word) in [(8, 1u32), (12, 1)] {
        let mut header = [0u8; 16];
        put32(&mut header, at, word);
        user.wire.store(edge, &header);
        assert_eq!(queue(edge), (Err(FsError::InvalidData), 0));
    }
    user.wire.store(edge, &[0u8; 16]);
    assert_eq!(queue(edge), (Err(FsError::BadAddress), 0));

    // The property index is bounded by ARRAY_SIZE(exec_queue_set_property_
    // funcs), six: past it is -EINVAL, never -ENOSYS, as is a nonzero pad.
    for property in [6, 7, u32::MAX] {
        pxp_extension(&user, 8192, 0, 0, property, 0);
        assert_eq!(queue(8192), (Err(FsError::InvalidData), 0));
    }
    pxp_extension(&user, 8192, 0, 0, 2, 0);
    user.wire.store(8192 + 20, &1u32.to_le_bytes());
    assert_eq!(queue(8192), (Err(FsError::InvalidData), 0));
    // reserved[2] is copied but never checked: a NONE with nonzero
    // reserved words creates the queue.
    pxp_extension(&user, 8192, 0, 0, 2, 0);
    user.wire.store(8192 + 32, &[0xa5; 16]);
    let (result, id) = queue(8192);
    assert_eq!(result, Ok(0));
    assert_ne!(id, 0);
    destroy_queue(id);

    // MULTI_GROUP: exec_queue_set_multi_group's first check is
    // xe_exec_queue_supports_multi_queue, false for every pinned graphics
    // descriptor, so any value is -ENODEV.
    for value in [0, 1, 1 << 63] {
        pxp_extension(&user, 8192, 0, 0, 4, value);
        assert_eq!(queue(8192), (Err(FsError::NoDevice), 0));
    }
    // MULTI_QUEUE_PRIORITY: above XE_MULTI_QUEUE_PRIORITY_HIGH is -EINVAL in
    // the setter. A valid one is stored, so the chain goes on (a later
    // extension's error wins) and exec_queue_user_ext_check_final refuses
    // it without MULTI_GROUP.
    pxp_extension(&user, 8192, 0, 0, 5, 3);
    assert_eq!(queue(8192), (Err(FsError::InvalidData), 0));
    for value in [0, 1, 2] {
        pxp_extension(&user, 8192, 0, 0, 5, value);
        assert_eq!(queue(8192), (Err(FsError::InvalidData), 0));
        pxp_extension(&user, 8192, 8256, 0, 5, value);
        pxp_extension(&user, 8256, 0, 0, 2, 1);
        assert_eq!(queue(8192), (Err(FsError::NoDevice), 0));
        pxp_extension(&user, 8192, 0x10000, 0, 5, value);
        assert_eq!(queue(8192), (Err(FsError::BadAddress), 0));
    }

    // HANG_REPLAY_STATE: vmemdup_user of xe_gt_lrc_hang_replay_size. An MTL
    // RCS image is thirteen pages, more than the fixture's user range, so
    // even a valid base is -EFAULT. A bind queue is a COPY-class queue,
    // whose image is one page.
    for value in [0, 4096] {
        pxp_extension(&user, 8192, 0, 0, 3, value);
        assert_eq!(queue(8192), (Err(FsError::BadAddress), 0));
    }
    pxp_extension(&user, 8192, 0, 0, 3, 32768 - 4095);
    assert_eq!(bind(8192), (Err(FsError::BadAddress), 0));
    // A readable image is accepted by Linux, which goes on with the chain:
    // the later extension's error wins over NARF's refusal of the image.
    pxp_extension(&user, 8192, 8256, 0, 3, 16384);
    pxp_extension(&user, 8256, 0, 0, 6, 0);
    assert_eq!(bind(8192), (Err(FsError::InvalidData), 0));
    pxp_extension(&user, 8192, 0x10000, 0, 3, 32768 - 4096);
    assert_eq!(bind(8192), (Err(FsError::BadAddress), 0));
    // With a readable image and a clean chain Linux creates the queue from
    // that LRC image.
    pxp_extension(&user, 8192, 0, 0, 3, 32768 - 4096);
    let (result, id) = bind(8192);
    assert_eq!(result, Ok(0));
    assert_ne!(id, 0);
    destroy_queue(id);

    // xe_exec_queue_create_ioctl runs the chain inside xe_exec_queue_create,
    // after calc_validate_logical_mask and the VM lookup. An RCS0/RCS0 row
    // is not logically contiguous (-EINVAL) and an unknown or destroyed VM
    // is -ENOENT, whatever the chain holds.
    assert_eq!(
        create(0x10000, vm, 528, 2),
        (Err(FsError::InvalidData), 0)
    );
    assert_eq!(create(0x10000, 99, 528, 2), (Err(FsError::InvalidData), 0));
    pxp_extension(&user, 8192, 0, 0, 6, 0);
    for extensions in [8192, 0x10000, edge] {
        assert_eq!(create(extensions, 99, 512, 1), (Err(FsError::NotFound), 0));
        assert_eq!(create(extensions, 99, 520, 1), (Err(FsError::NotFound), 0));
    }
    assert_eq!(
        create(8192, doomed, 512, 1),
        (Err(FsError::NotFound), 0)
    );
    assert_eq!(arena.live_allocations(), before);

    drop(file);
    drop(info);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe",
    smoke_xe_exec_queue_extensions_follow_linux_check_order
);
