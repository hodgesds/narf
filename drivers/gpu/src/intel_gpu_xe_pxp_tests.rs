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

/// A native Xe backend with `xe->pxp` published, as the GT runtime does with
/// `narf.intel.pxp=1` after xe_pxp_init.
#[derive(Debug)]
struct PxpNative {
    native: Native,
    pxp: Arc<crate::intel_gpu_gt::media::pxp::Pxp>,
}
impl UserBackend for PxpNative {
    fn status(&self) -> Option<UserStatus> {
        self.native.status()
    }
    fn native_xe(&self) -> bool {
        true
    }
    fn device_facts(&self) -> Option<crate::intel_gpu_user::DeviceFacts> {
        self.native.device_facts()
    }
    fn pxp(&self) -> Option<Arc<crate::intel_gpu_gt::media::pxp::Pxp>> {
        Some(self.pxp.clone())
    }
    fn submit<'a>(
        &'a self,
        context: Arc<UserContext>,
        batch: UserBatch,
    ) -> FsFuture<'a, Arc<CompletionFence>> {
        self.native.submit(context, batch)
    }
}

/// MIT Linux 7.4-rc4 with an enabled PXP: xe_query.c::query_pxp_status
/// (status 0/1 with BIT(DRM_XE_PXP_TYPE_HWDRM), -EIO for a firmware error),
/// exec_queue_set_pxp_type + xe_pxp_exec_queue_add (-EBUSY until ready),
/// gem_create_set_pxp_type + xe_pxp_key_assign, xe_vm_bind_ioctl_validate_bo's
/// DRM_XE_VM_BIND_FLAG_CHECK_PXP and xe_exec_ioctl's xe_vm_validate_protected
/// on an object whose key a termination made stale. Linux's -ENOEXEC for a
/// stale key is EINVAL here (`FsError` carries no ENOEXEC).
fn smoke_xe_pxp_enabled_queues_objects_and_stale_key_checks() -> TestResult {
    use crate::intel_gpu_gt::media::pxp::{Pxp, Readiness, Status};
    let platform = GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake);
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let (mailbox, mut info) = setup(&mut gt, &w, platform);
    let pxp = Pxp::new();
    info.backend = Some(Arc::new(PxpNative {
        native: Native {
            mailbox,
            facts: gt.device_facts().unwrap(),
            media: None,
        },
        pxp: pxp.clone(),
    }));
    let file = RenderFile::new();
    let user = Cpu::new();

    // DRM_XE_DEVICE_QUERY_PXP_STATUS: in progress, ready, then -EIO.
    let status = |user: &Cpu| {
        let mut query = [0; 40];
        put32(&mut query, 8, 9);
        put32(&mut query, 12, 8);
        put64(&mut query, 16, 4096);
        user.wire.store(64, &query);
        user.wire.store(4096, &[0xa5; 8]);
        let result = invoke(&file, &info, user, xe::DEVICE_QUERY);
        (result, user.wire.load(4096, 8))
    };
    assert_eq!(status(&user), (Ok(0), alloc::vec![0, 0, 0, 0, 2, 0, 0, 0]));
    pxp.publish(Readiness::Error);
    assert_eq!(
        status(&user),
        (Err(crate::intel_gpu_user::io_error()), alloc::vec![0xa5; 8])
    );
    pxp.publish(Readiness::Pending);
    // Size negotiation and the wrong size are unchanged.
    let mut query = [0; 40];
    put32(&mut query, 8, 9);
    user.wire.store(64, &query);
    assert_eq!(invoke(&file, &info, &user, xe::DEVICE_QUERY), Ok(0));
    assert_eq!(u32_at(&user.wire.load(64, 40), 12), 8);
    put32(&mut query, 12, 16);
    user.wire.store(64, &query);
    assert_eq!(
        invoke(&file, &info, &user, xe::DEVICE_QUERY),
        Err(FsError::InvalidData)
    );

    let vm = create_vm(&file, &info, &user);
    let queue = |class: u8, extensions: u64| {
        user.wire.store(512, &[class, 0, 0, 0, 0, 0, 0, 0]);
        let mut wire = [0; 48];
        put64(&mut wire, 0, extensions);
        put32(&mut wire, 8, 0x00010001);
        put32(&mut wire, 12, vm);
        put64(&mut wire, 24, 512);
        user.wire.store(64, &wire);
        let result = invoke(&file, &info, &user, xe::EXEC_QUEUE_CREATE);
        (result, u32_at(&user.wire.load(64, 48), 20))
    };
    // Not ready: HWDRM is -EBUSY and publishes nothing; NONE still works.
    pxp_extension(&user, 8192, 0, 0, 2, 1);
    assert_eq!(queue(0, 8192), (Err(FsError::Busy), 0));
    pxp_extension(&user, 8192, 0, 0, 2, 0);
    let (result, plain) = queue(0, 8192);
    assert_eq!(result, Ok(0));
    assert_ne!(plain, 0);
    assert_eq!(pxp.queues(), 0);
    // Any other session type is still -EINVAL.
    pxp_extension(&user, 8192, 0, 0, 2, 2);
    assert_eq!(queue(0, 8192), (Err(FsError::InvalidData), 0));
    // An error state is -EIO.
    pxp.publish(Readiness::Error);
    pxp_extension(&user, 8192, 0, 0, 2, 1);
    assert_eq!(queue(0, 8192), (Err(crate::intel_gpu_user::io_error()), 0));

    // Active: RCS0 (run alone) and BCS0 PXP queues join the list; a NONE
    // after HWDRM keeps the queue protected.
    pxp.activate_for_test();
    assert_eq!(status(&user), (Ok(0), alloc::vec![1, 0, 0, 0, 2, 0, 0, 0]));
    pxp_extension(&user, 8192, 8256, 0, 2, 1);
    pxp_extension(&user, 8256, 0, 0, 2, 0);
    let (result, render) = queue(0, 8192);
    assert_eq!(result, Ok(0));
    assert_ne!(render, 0);
    assert_eq!(pxp.queues(), 1);
    // Through the waiting path native Xe files take.
    user.wire.store(512, &[1, 0, 0, 0, 0, 0, 0, 0]);
    let mut wire = [0; 48];
    put64(&mut wire, 0, 8192);
    put32(&mut wire, 8, 0x00010001);
    put32(&mut wire, 12, vm);
    put64(&mut wire, 24, 512);
    user.wire.store(64, &wire);
    assert_eq!(
        narf_scheduler::block_on_spin(file.dispatch_user(&info, xe::EXEC_QUEUE_CREATE, 64, &user)),
        Some(Ok(0))
    );
    let copy = u32_at(&user.wire.load(64, 48), 20);
    assert_ne!(copy, 0);
    assert_eq!(pxp.queues(), 2);
    // xe_exec_queue_destroy takes the queue off the list.
    assert_eq!(
        close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, copy),
        Ok(0)
    );
    assert_eq!(pxp.queues(), 1);

    // GEM_CREATE: HWDRM marks the object with the current key, NONE not.
    let gem = |extensions: u64| {
        let mut wire = [0; 56];
        put64(&mut wire, 0, extensions);
        put64(&mut wire, 8, 4096);
        put32(&mut wire, 16, 1);
        wire[32] = 1;
        user.wire.store(64, &wire);
        let result = invoke(&file, &info, &user, xe::GEM_CREATE);
        (result, u32_at(&user.wire.load(64, 56), 28))
    };
    pxp_extension(&user, 8192, 0, 0, 0, 1);
    let (result, stale) = gem(8192);
    assert_eq!(result, Ok(0));
    assert_eq!(file.gem.object(stale).unwrap().pxp_key(), 1);
    pxp_extension(&user, 8192, 0, 0, 0, 0);
    let (result, clear) = gem(8192);
    assert_eq!(result, Ok(0));
    assert_eq!(file.gem.object(clear).unwrap().pxp_key(), 0);
    // A value other than NONE/HWDRM is still -EINVAL.
    pxp_extension(&user, 8192, 0, 0, 0, 2);
    assert_eq!(gem(8192), (Err(FsError::InvalidData), 0));

    // VM_BIND with CHECK_PXP maps a protected object while its key is current.
    let pat = batch_pat(platform);
    bind_wire(&user, vm, &[mapping(stale, 0x10_0000, 0, 4096, pat, 0x10)], &[]);
    assert_eq!(bind_now(&file, &info, &user), Ok(0));

    // A termination (here xe_pxp_pm_suspend) kills the PXP queues and moves
    // the key on; the session is started again later.
    pxp.suspend();
    pxp.resume(true);
    assert_eq!(pxp.status(), Status::TerminationInProgress);
    pxp.activate_for_test();
    assert_eq!(pxp.queues(), 0);
    assert_eq!(pxp.key_assign(), 2);
    // The stale object no longer maps with CHECK_PXP; without it, and for an
    // unprotected object, the bind is unaffected.
    bind_wire(&user, vm, &[mapping(stale, 0x20_0000, 0, 4096, pat, 0x10)], &[]);
    assert_eq!(bind_now(&file, &info, &user), Err(FsError::InvalidData));
    bind_wire(&user, vm, &[mapping(clear, 0x30_0000, 0, 4096, pat, 0x10)], &[]);
    assert_eq!(bind_now(&file, &info, &user), Ok(0));
    pxp_extension(&user, 8192, 0, 0, 0, 1);
    let (result, fresh) = gem(8192);
    assert_eq!(result, Ok(0));
    assert_eq!(file.gem.object(fresh).unwrap().pxp_key(), 2);
    bind_wire(&user, vm, &[mapping(fresh, 0x40_0000, 0, 4096, pat, 0x10)], &[]);
    assert_eq!(bind_now(&file, &info, &user), Ok(0));

    // The killed queue is -ECANCELED; a new PXP queue on the same VM refuses
    // to run while the VM still maps the stale object; a plain queue runs
    // the same VM's checks without PXP's.
    exec_wire(&user, render, false, &[]);
    assert_eq!(
        narf_scheduler::block_on_spin(file.dispatch_user(&info, xe::EXEC, 64, &user)),
        Some(Err(FsError::Canceled))
    );
    pxp_extension(&user, 8192, 0, 0, 2, 1);
    let (result, protected) = queue(0, 8192);
    assert_eq!(result, Ok(0));
    exec_wire(&user, protected, false, &[]);
    assert_eq!(
        narf_scheduler::block_on_spin(file.dispatch_user(&info, xe::EXEC, 64, &user)),
        Some(Err(FsError::InvalidData))
    );
    assert_eq!(close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, protected), Ok(0));
    assert_eq!(close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, render), Ok(0));
    assert_eq!(close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, plain), Ok(0));
    assert_eq!(pxp.queues(), 0);

    drop(file);
    drop(info);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_xe_pxp_enabled_queues_objects_and_stale_key_checks
);

/// MIT Linux 7.4-rc4, a protected queue's LRC through the GuC: an HWDRM
/// exec queue on MTL (graphics 12.70) gets XE_LRC_CREATE_RUNALONE from
/// xe_exec_queue.c::__xe_exec_queue_init when its class is RENDER or COMPUTE
/// (Xe2 would take XE_LRC_CREATE_PXP instead), and xe_lrc.c::xe_lrc_init ORs
/// REG_MASKED_FIELD_ENABLE(CTX_CTRL_RUN_ALONE) (regs/xe_engine_regs.h bit 7:
/// 0x00800080) into CTX_CONTEXT_CONTROL after the ring registers;
/// xe_guc_submit.c::register_exec_queue then names that LRC in
/// REGISTER_CONTEXT with nothing PXP-specific. The unprotected value is
/// i915 intel_lrc.c::init_common_regs for a context that restores its state
/// (`_MASKED_BIT_ENABLE(CTX_CTRL_INHIBIT_SYN_CTX_SWITCH)` 0x00080008 |
/// `_MASKED_BIT_DISABLE(CTX_CTRL_ENGINE_CTX_RESTORE_INHIBIT)` 0x00010000).
/// So the image the GuC model registers carries 0x00890088 at
/// RCS0/CCS0's CTX_CONTEXT_CONTROL (engine base + 0x244) and 0x00090008 on
/// a protected BCS0 queue and an unprotected RCS0 one, and every batch runs.
/// Without a published `xe->pxp` the HWDRM queue is -ENODEV first.
fn smoke_xe_pxp_protected_queue_lrc_registers_run_alone_through_the_guc() -> TestResult {
    use crate::intel_gpu_gt::media::pxp::Pxp;
    let platform = GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake);
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let (mailbox, mut info) = setup(&mut gt, &w, platform);
    let file = RenderFile::new();
    let user = Cpu::new();
    let vm = create_vm(&file, &info, &user);
    let create = |info: &DeviceInfo, class: u8, protected: bool| {
        user.wire.store(512, &[class, 0, 0, 0, 0, 0, 0, 0]);
        pxp_extension(&user, 8192, 0, 0, 2, u64::from(protected));
        let mut wire = [0; 48];
        put64(&mut wire, 0, 8192);
        put32(&mut wire, 8, 0x00010001);
        put32(&mut wire, 12, vm);
        put64(&mut wire, 24, 512);
        user.wire.store(64, &wire);
        let result = invoke(&file, info, &user, xe::EXEC_QUEUE_CREATE);
        (result, u32_at(&user.wire.load(64, 48), 20))
    };
    // PXP disabled (xe->pxp NULL): HWDRM is -ENODEV and creates nothing.
    assert_eq!(create(&info, 0, true), (Err(FsError::NoDevice), 0));

    let pxp = Pxp::new();
    info.backend = Some(Arc::new(PxpNative {
        native: Native {
            mailbox: mailbox.clone(),
            facts: gt.device_facts().unwrap(),
            media: None,
        },
        pxp: pxp.clone(),
    }));
    pxp.activate_for_test();
    let handles = buffers(&file, &info, &user, vm);
    // (class, HWDRM, CTX_CONTEXT_CONTROL register, its LRC value).
    let cases = [
        (0u8, true, 0x2244u32, 0x0089_0088u32),
        (4, true, 0x1a244, 0x0089_0088),
        (1, true, 0x22244, 0x0009_0008),
        (0, false, 0x2244, 0x0009_0008),
    ];
    let mut queues = Vec::new();
    for &(class, protected, _, _) in &cases {
        let (result, queue) = create(&info, class, protected);
        assert_eq!(result, Ok(0));
        assert_ne!(queue, 0);
        queues.push(queue);
    }
    // xe_pxp_exec_queue_add: the three HWDRM queues are on the PXP list.
    assert_eq!(pxp.queues(), 3);

    let mut now = 100;
    for (&queue, &(_, _, register, control)) in queues.iter().zip(&cases) {
        exec_wire(&user, queue, true, &[]);
        let mut call = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
        assert!(call
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        let (_, fence) = mailbox.accept(&mut gt, now);
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Ok(0)))
        );
        // Every image REGISTER_CONTEXT named, read while it is registered.
        let mut registered = BTreeMap::new();
        let mut seen: Vec<(u32, u32)> = Vec::new();
        for t in now + 1..now + 60 {
            assert_eq!(gt.poll(t), Poll::Ready(Ok(GtState::SchedulingReady)));
            service_contexts(&w, &mut registered, true);
            for base in registered.values() {
                let image = w.0.borrow().memory[base].clone();
                let words = image.borrow();
                let slot = (words[1024 + 2], words[1024 + 3]);
                if !seen.contains(&slot) {
                    seen.push(slot);
                }
            }
            now = t;
            if fence.result().is_some() {
                break;
            }
        }
        assert_eq!(fence.result(), Some(Ok(())));
        assert!(registered.is_empty());
        // The queue's LRC on its engine, with nothing else registered there.
        assert!(seen.contains(&(register, control)));
        assert!(seen.iter().all(|&(at, value)| at != register || value == control));
        now += 10;
    }
    // The batch's MI_STORE_DATA_IMM ran.
    assert_eq!(user.read_u64_acquire(0x4080), Ok(0x4e415246));

    for queue in queues {
        assert_eq!(
            close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, queue),
            Ok(0)
        );
    }
    assert_eq!(pxp.queues(), 0);
    for handle in handles {
        assert_eq!(close(&file, &info, &user, abi::GEM_CLOSE, handle), Ok(0));
    }
    user.mapping.lock().take();
    assert_eq!(close(&file, &info, &user, xe::VM_DESTROY, vm), Ok(0));
    drop(file);
    drop(info);
    drop(mailbox);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_xe_pxp_protected_queue_lrc_registers_run_alone_through_the_guc
);
