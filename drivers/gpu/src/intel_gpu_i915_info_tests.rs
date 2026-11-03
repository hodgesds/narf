// Native i915 discovery copies and context lookup against immutable observed
// fuses. Independent literals follow Linux b90c984d i915_getparam.c,
// get_sseu/intel_sseu_from_device_info and the UAPI's 32-byte SSEU structure.
use super::*;
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_user::{DeviceFacts, UserBackend, UserBatch, UserContext, UserStatus};
use core::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug)]
struct Facts {
    live: AtomicBool,
    platform: GtPlatform,
    clock: u32,
}
impl UserBackend for Facts {
    fn status(&self) -> Option<UserStatus> {
        self.live.load(Ordering::Acquire).then_some(UserStatus {
            epoch: 41,
            platform: self.platform,
            submission_version: (1, 0, 0),
            engines: crate::intel_gpu_engine::EngineSet::of(&[
                crate::intel_gpu_engine::Engine::Rcs0,
                crate::intel_gpu_engine::Engine::Bcs0,
            ]),
        })
    }
    fn device_facts(&self) -> Option<DeviceFacts> {
        Some(DeviceFacts {
            revision: 0x61,
            graphics_version: 1270,
            graphics_step: 0,
            reference_clock: self.clock,
        })
    }
    fn submit<'a>(
        &'a self,
        _: Arc<UserContext>,
        _: UserBatch,
    ) -> narf_filesystem::FsFuture<'a, Arc<crate::intel_gpu_fence::CompletionFence>> {
        alloc::boxed::Box::pin(async { Err(FsError::Unsupported) })
    }
}
struct FuseImage;
impl MmioWindow for FuseImage {
    fn read32(&self, offset: u64) -> u32 {
        match offset {
            0x913c => 0x8000_0101,
            0x9144 => 0x1002,
            0x9134 => 5,
            // load_l3_bank_mask's MIRROR_FUSE3 and (graphics 12.70) XEHP_FUSE4.
            0x9118 => 1,
            0x9114 => 0x10,
            _ => panic!("discovery accessed unrelated register"),
        }
    }
    fn write32(&self, _: u64, _: u32) {
        panic!("discovery wrote fuses");
    }
}
fn observed(platform: GtPlatform) -> (DeviceInfo, Arc<Facts>) {
    let backend = Arc::new(Facts {
        live: AtomicBool::new(true),
        platform,
        clock: 19_200_000,
    });
    let topology = crate::intel_gpu_topology::GtTopology::read(&FuseImage, platform).unwrap();
    let mut info = info(Generation::MeteorLake);
    info.platform = platform;
    info.topology = Some(Arc::new(topology));
    info.backend = Some(backend.clone());
    (info, backend)
}
fn parameter(
    file: &RenderFile,
    info: &DeviceInfo,
    user: &User,
    param: u32,
) -> Result<i32, FsError> {
    let mut wire = [0; 16];
    put32(&mut wire, 0, param);
    put64(&mut wire, 8, 1024);
    user.store(64, &wire);
    file.dispatch(info, abi::GETPARAM, 64, user).unwrap()?;
    Ok(i32::from_le_bytes(user.load(1024, 4).try_into().unwrap()))
}
fn context(file: &RenderFile, info: &DeviceInfo, user: &User) -> u32 {
    user.store(64, &[0; 16]);
    assert_eq!(
        file.dispatch(info, abi::GEM_CONTEXT_CREATE, 64, user),
        Some(Ok(0))
    );
    u32_at(&user.load(64, 16), 0)
}
fn sseu(
    file: &RenderFile,
    info: &DeviceInfo,
    user: &User,
    id: u32,
    size: u32,
    set: bool,
) -> Result<u64, FsError> {
    let mut wire = [0; 24];
    put32(&mut wire, 0, id);
    put32(&mut wire, 4, size);
    put64(&mut wire, 8, 7);
    put64(&mut wire, 16, 2048);
    user.store(64, &wire);
    file.dispatch(
        info,
        if set {
            abi::GEM_CONTEXT_SETPARAM
        } else {
            abi::GEM_CONTEXT_GETPARAM
        },
        64,
        user,
    )
    .unwrap()
}
fn smoke_i915_observed_discovery_and_immutable_facts_after_loss() -> TestResult {
    for platform in [
        GtPlatform::Alchemist,
        GtPlatform::Battlemage,
        GtPlatform::Integrated(Generation::MeteorLake),
    ] {
        let (info, backend) = observed(platform);
        let file = RenderFile::new();
        let user = User::new();
        for live in [true, false] {
            backend.live.store(live, Ordering::Release);
            for (param, value) in [
                (32, 0x61),
                (33, 5),
                (
                    34,
                    if platform == GtPlatform::Battlemage {
                        10
                    } else {
                        20
                    },
                ),
                (51, 19_200_000),
                // I915_SCHEDULER_CAP_ENABLED | PRIORITY, or 0.
                (41, if live { 3 } else { 0 }),
            ] {
                assert_eq!(parameter(&file, &info, &user, param), Ok(value));
            }
        }
        for param in [46, 47, 0, 60, u32::MAX] {
            assert_eq!(
                parameter(&file, &info, &user, param),
                Err(FsError::InvalidData)
            );
        }
        for param in [1, 2, 3, 14] {
            user.store(1024, &[0xa5; 4]);
            assert_eq!(
                parameter(&file, &info, &user, param),
                Err(FsError::NoDevice)
            );
            assert_eq!(user.load(1024, 4), [0xa5; 4]);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_render",
    smoke_i915_observed_discovery_and_immutable_facts_after_loss
);

fn smoke_i915_discovery_missing_cross_platform_and_faulted_copies() -> TestResult {
    let (mut info, _) = observed(GtPlatform::Alchemist);
    let file = RenderFile::new();
    let user = User::new();
    *user.fail_write.lock() = Some(1024);
    assert_eq!(parameter(&file, &info, &user, 33), Err(FsError::BadAddress));
    *user.fail_write.lock() = None;
    *user.fail_read.lock() = Some(64);
    assert_eq!(parameter(&file, &info, &user, 33), Err(FsError::BadAddress));
    *user.fail_read.lock() = None;
    info.platform = GtPlatform::Battlemage;
    for param in [33, 34] {
        assert_eq!(
            parameter(&file, &info, &user, param),
            Err(FsError::NoDevice)
        );
    }
    info.topology = None;
    info.backend = None;
    for param in [32, 33, 34, 51] {
        assert_eq!(
            parameter(&file, &info, &user, param),
            Err(FsError::NoDevice)
        );
    }
    info.backend = Some(Arc::new(Facts {
        live: AtomicBool::new(false),
        platform: info.platform,
        clock: 0,
    }));
    assert_eq!(parameter(&file, &info, &user, 51), Err(FsError::NoDevice));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_render",
    smoke_i915_discovery_missing_cross_platform_and_faulted_copies
);

fn smoke_i915_sseu_default_wire_size_context_finalization_and_loss() -> TestResult {
    let (info, backend) = observed(GtPlatform::Alchemist);
    let file = RenderFile::new();
    let user = User::new();
    let id = context(&file, &info, &user);
    *user.fail_read.lock() = Some(2048);
    assert_eq!(sseu(&file, &info, &user, id, 0, false), Ok(0));
    assert_eq!(u32_at(&user.load(64, 24), 4), 32);
    *user.fail_read.lock() = None;
    backend.live.store(false, Ordering::Release);
    let mut wire = [0xa5; 40];
    wire[..8].fill(0);
    wire[28..32].fill(0);
    user.store(2048, &wire);
    assert_eq!(sseu(&file, &info, &user, id, 40, false), Ok(0));
    let mut expected = wire;
    put64(&mut expected, 8, 1);
    put64(&mut expected, 16, 3); // old eight-bit default-context ABI view
    expected[24..28].copy_from_slice(&[16, 0, 16, 0]);
    assert_eq!(user.load(2048, 40), expected);
    assert_eq!(u32_at(&user.load(64, 24), 4), 32);
    assert_eq!(
        sseu(&file, &info, &user, id + 1, 0, false),
        Err(FsError::NotFound)
    );
    assert_eq!(
        sseu(&file, &info, &user, id, 31, false),
        Err(FsError::InvalidData)
    );
    assert_eq!(
        sseu(&file, &info, &user, id, 31, true),
        Err(FsError::InvalidData)
    );
    assert_eq!(
        sseu(&file, &info, &user, id, 32, true),
        Err(FsError::NoDevice)
    );
    // Even size-only lookup finalizes the proto-context like Linux lookup.
    let mut request = [0; 24];
    put32(&mut request, 0, id);
    put32(&mut request, 4, 12);
    put64(&mut request, 8, 10);
    put64(&mut request, 16, 3000);
    user.store(64, &request);
    assert_eq!(
        file.dispatch(&info, abi::GEM_CONTEXT_SETPARAM, 64, &user),
        Some(Err(FsError::InvalidData))
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_render",
    smoke_i915_sseu_default_wire_size_context_finalization_and_loss
);

fn smoke_i915_sseu_indexed_engines_refusals_and_copy_rollback() -> TestResult {
    let (info, _) = observed(GtPlatform::Battlemage);
    let file = RenderFile::new();
    let user = User::new();
    let id = context(&file, &info, &user);
    let mut map = [0; 20];
    map[12..16].copy_from_slice(&[1, 0, 0, 0]);
    map[16..20].fill(0xff); // unpopulated map slot
    user.store(3000, &map);
    let mut request = [0; 24];
    put32(&mut request, 0, id);
    put32(&mut request, 4, 20);
    put64(&mut request, 8, 10);
    put64(&mut request, 16, 3000);
    user.store(64, &request);
    assert_eq!(
        file.dispatch(&info, abi::GEM_CONTEXT_SETPARAM, 64, &user),
        Some(Ok(0))
    );
    let mut wire = [0; 32];
    wire[..4].copy_from_slice(&[0xfe, 0xff, 1, 0]); // class ignored for index1
    put32(&mut wire, 4, 1);
    user.store(2048, &wire);
    assert_eq!(sseu(&file, &info, &user, id, 32, false), Ok(0));
    assert_eq!(user.load(2048 + 24, 4), [8, 0, 8, 0]);
    for (index, flags, reserved) in [(1, 0, 0), (1, 2, 0), (1, 1, 1), (2, 1, 0), (3, 1, 0)] {
        let mut bad = wire;
        bad[2..4].copy_from_slice(&(index as u16).to_le_bytes());
        put32(&mut bad, 4, flags);
        put32(&mut bad, 28, reserved);
        user.store(2048, &bad);
        assert_eq!(
            sseu(&file, &info, &user, id, 32, false),
            Err(FsError::InvalidData)
        );
        assert_eq!(user.load(2048, 32), bad);
    }
    user.store(2048, &wire);
    *user.fail_write.lock() = Some(2048);
    assert_eq!(
        sseu(&file, &info, &user, id, 64, false),
        Err(FsError::BadAddress)
    );
    assert_eq!(u32_at(&user.load(64, 24), 4), 64);
    *user.fail_write.lock() = None;
    *user.fail_read.lock() = Some(2048);
    assert_eq!(
        sseu(&file, &info, &user, id, 32, false),
        Err(FsError::BadAddress)
    );
    let other = RenderFile::new();
    assert_eq!(
        sseu(&other, &info, &user, id, 0, false),
        Err(FsError::NotFound)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_render",
    smoke_i915_sseu_indexed_engines_refusals_and_copy_rollback
);

/// Capabilities the credential fixture grants, and those asked, as masks.
static GRANTED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static ASKED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
fn capable(capability: u32) -> bool {
    ASKED.fetch_or(1 << capability, Ordering::AcqRel);
    GRANTED.load(Ordering::Acquire) & 1 << capability != 0
}
/// Installs `capable` as the caller's credentials; restores the previous
/// hook on drop.
struct Credentials(Option<fn(u32) -> bool>);
impl Credentials {
    fn install() -> Self {
        GRANTED.store(0, Ordering::Release);
        ASKED.store(0, Ordering::Release);
        Self(narf_filesystem::__test_swap_caller_capable_hook(Some(
            capable,
        )))
    }
    fn grant(&self, capabilities: &[u32]) {
        let mask = capabilities.iter().fold(0, |mask, cap| mask | 1 << cap);
        GRANTED.store(mask, Ordering::Release);
    }
    /// The capabilities asked since the last call.
    fn asked(&self) -> u64 {
        ASKED.swap(0, Ordering::AcqRel)
    }
}
impl Drop for Credentials {
    fn drop(&mut self) {
        let _ = narf_filesystem::__test_swap_caller_capable_hook(self.0);
    }
}
/// One GEM_CONTEXT_GETPARAM/SETPARAM; the reply's size and value.
#[allow(clippy::too_many_arguments)]
fn context_param(
    file: &RenderFile,
    info: &DeviceInfo,
    user: &User,
    set: bool,
    id: u32,
    size: u32,
    param: u64,
    value: u64,
) -> Result<(u32, u64), FsError> {
    let mut wire = [0; 24];
    put32(&mut wire, 0, id);
    put32(&mut wire, 4, size);
    put64(&mut wire, 8, param);
    put64(&mut wire, 16, value);
    user.store(64, &wire);
    let cmd = if set {
        abi::GEM_CONTEXT_SETPARAM
    } else {
        abi::GEM_CONTEXT_GETPARAM
    };
    file.dispatch(info, cmd, 64, user).unwrap()?;
    let wire = user.load(64, 24);
    Ok((u32_at(&wire, 4), u64_at(&wire, 16)))
}

/// MIT Linux b90c984d i915_gem_context.c: setparam_ioctl:2600 and
/// getparam_ioctl:2527 look the context up before any parameter check;
/// SETPARAM then runs set_proto_ctx_param:877 on a proto-context and
/// ctx_setparam:2190 on a finalized one, with validate_priority:173,
/// proto_context_set_persistence:212, __context_set_persistence:1560 and
/// proto_context_set_protected:253. capable() is asked only where Linux
/// asks it: CAP_SYS_ADMIN for any size-0 BANNABLE, CAP_SYS_NICE for an
/// in-range positive PRIORITY.
fn smoke_i915_context_params_follow_set_proto_ctx_param_and_ctx_setparam() -> TestResult {
    const ADMIN: u32 = 21;
    const NICE: u32 = 23;
    let (info, backend) = observed(GtPlatform::Integrated(Generation::MeteorLake));
    let file = RenderFile::new();
    let user = User::new();
    let credentials = Credentials::install();
    let set = |id: u32, size: u32, param: u64, value: u64| {
        context_param(&file, &info, &user, true, id, size, param, value).map(|_| ())
    };
    let get = |id: u32, param: u64| {
        context_param(&file, &info, &user, false, id, 0, param, 0).map(|(_, value)| value)
    };
    let neg = |value: i64| value as u64;
    // I915_SCHEDULER_CAP_ENABLED | PRIORITY while live.
    assert_eq!(parameter(&file, &info, &user, 41), Ok(3));
    // The lookup precedes every size and parameter check.
    for param in [4, 5, 6, 8, 9, 11, 13, u64::MAX] {
        assert_eq!(set(99, 1, param, 0), Err(FsError::NotFound));
        assert_eq!(
            context_param(&file, &info, &user, false, 99, 1, param, 0),
            Err(FsError::NotFound)
        );
    }
    assert_eq!(credentials.asked(), 0, "capable() before the size check");

    // Context 0 is finalized at open (ctx_setparam); a created context is a
    // proto-context (set_proto_ctx_param) until GETPARAM looks it up.
    for live in [false, true] {
        let id = if live { 0 } else { context(&file, &info, &user) };
        credentials.grant(&[]);
        // BANNABLE: size, then `!capable(CAP_SYS_ADMIN) && !args->value`.
        assert_eq!(set(id, 1, 5, 0), Err(FsError::InvalidData));
        assert_eq!(credentials.asked(), 0, "capable() before the size check");
        assert_eq!(set(id, 0, 5, 0), Err(FsError::OperationNotPermitted));
        assert_eq!(set(id, 0, 5, 2), Ok(()), "any nonzero value sets it");
        assert_eq!(credentials.asked(), 1 << ADMIN);
        credentials.grant(&[ADMIN]);
        assert_eq!(set(id, 0, 5, 0), Ok(()));
        // RECOVERABLE: size, then 0 clears and anything else sets it.
        assert_eq!(set(id, 4, 8, 1), Err(FsError::InvalidData));
        assert_eq!(set(id, 0, 8, 7), Ok(()));
        // PERSISTENCE: setting needs hangcheck (always armed); clearing
        // needs I915_SCHEDULER_CAP_PREEMPTION, which is not advertised.
        assert_eq!(set(id, 1, 11, 1), Err(FsError::InvalidData));
        assert_eq!(set(id, 0, 11, 0), Err(FsError::NoDevice));
        assert_eq!(set(id, 0, 11, 5), Ok(()));
        // PROTECTED_CONTENT: no size check on a proto, 0 clears, anything
        // else needs PXP (-ENODEV); ctx_setparam refuses it.
        if live {
            assert_eq!(set(id, 0, 13, 0), Err(FsError::InvalidData));
        } else {
            assert_eq!(set(id, 99, 13, 0), Ok(()));
            assert_eq!(set(id, 99, 13, 1), Err(FsError::NoDevice));
        }
        assert_eq!(credentials.asked(), 1 << ADMIN);
        // GETPARAM ignores the input size and reports size 0; this lookup
        // finalizes the proto-context.
        for (param, expected) in [(5, 0), (8, 1), (11, 1), (13, 0), (6, 0)] {
            assert_eq!(
                context_param(&file, &info, &user, false, id, 0xfeed, param, 7),
                Ok((0, expected))
            );
        }
        assert_eq!(credentials.asked(), 0, "GETPARAM asked capable()");
        // ctx_setparam: BANNABLE and RECOVERABLE as before; a context
        // already persistent returns early; PROTECTED_CONTENT is EINVAL.
        credentials.grant(&[]);
        assert_eq!(set(id, 0, 5, 0), Err(FsError::OperationNotPermitted));
        assert_eq!(set(id, 0, 5, 1), Ok(()));
        assert_eq!(set(id, 0, 8, 0), Ok(()));
        assert_eq!((get(id, 5), get(id, 8)), (Ok(1), Ok(0)));
        assert_eq!(set(id, 1, 11, 1), Err(FsError::InvalidData));
        assert_eq!(set(id, 0, 11, 1), Ok(()));
        assert_eq!(set(id, 0, 11, 0), Err(FsError::NoDevice));
        assert_eq!(get(id, 11), Ok(1));
        assert_eq!(set(id, 0, 13, 0), Err(FsError::InvalidData));
        assert_eq!(set(id, 99, 13, 0), Err(FsError::InvalidData));
    }

    // PRIORITY: size, I915_SCHEDULER_CAP_PRIORITY, the s64 range, then
    // CAP_SYS_NICE above I915_CONTEXT_DEFAULT_PRIORITY.
    for live in [false, true] {
        let id = if live { 0 } else { context(&file, &info, &user) };
        credentials.grant(&[]);
        credentials.asked();
        for (size, value, expected) in [
            (1, 0, FsError::InvalidData),
            (0, 1024, FsError::InvalidData),
            (0, neg(-1024), FsError::InvalidData),
            (0, 1 << 32, FsError::InvalidData),
            (0, 1, FsError::OperationNotPermitted),
            (0, 1023, FsError::OperationNotPermitted),
        ] {
            assert_eq!(set(id, size, 6, value), Err(expected), "{size} {value:#x}");
        }
        assert_eq!(credentials.asked(), 1 << NICE);
        for value in [0, neg(-1), neg(-1023)] {
            assert_eq!(set(id, 0, 6, value), Ok(()));
        }
        assert_eq!(credentials.asked(), 0, "capable() for a priority <= 0");
        credentials.grant(&[NICE]);
        assert_eq!(set(id, 0, 6, 1024), Err(FsError::InvalidData));
        assert_eq!(credentials.asked(), 0, "capable() before the range check");
        assert_eq!(set(id, 0, 6, 1023), Ok(()));
        assert_eq!(credentials.asked(), 1 << NICE);
        assert_eq!(get(id, 6), Ok(1023));
        // ctx_setparam's set_priority; GETPARAM sign-extends the int.
        assert_eq!(set(id, 0, 6, neg(-7)), Ok(()));
        assert_eq!(get(id, 6), Ok(neg(-7)));
        credentials.grant(&[]);
        assert_eq!(set(id, 0, 6, 2), Err(FsError::OperationNotPermitted));
        assert_eq!(get(id, 6), Ok(neg(-7)));
    }
    // With no uabi engine i915->caps.scheduler is 0: PRIORITY is -ENODEV
    // after the size check, whatever its value.
    backend.live.store(false, Ordering::Release);
    assert_eq!(parameter(&file, &info, &user, 41), Ok(0));
    assert_eq!(set(0, 1, 6, 0), Err(FsError::InvalidData));
    assert_eq!(set(0, 0, 6, 0), Err(FsError::NoDevice));
    assert_eq!(set(0, 0, 6, 5000), Err(FsError::NoDevice));
    backend.live.store(true, Ordering::Release);

    // CREATE_EXT applies the same set_proto_ctx_param at each link.
    let create_ext = |size: u32, param: u64, value: u64| {
        let mut ext = [0; 56];
        put32(&mut ext, 36, size);
        put64(&mut ext, 40, param);
        put64(&mut ext, 48, value);
        user.store(256, &ext);
        let mut request = [0; 16];
        put32(&mut request, 4, 1);
        put64(&mut request, 8, 256);
        user.store(64, &request);
        file.dispatch(&info, abi::GEM_CONTEXT_CREATE_EXT, 64, &user)
            .unwrap()
            .map(|_| u32_at(&user.load(64, 16), 0))
    };
    credentials.grant(&[]);
    for (size, param, value, expected) in [
        (0, 5, 0, FsError::OperationNotPermitted),
        (0, 6, 5, FsError::OperationNotPermitted),
        (1, 6, 0, FsError::InvalidData),
        (0, 11, 0, FsError::NoDevice),
        (7, 13, 1, FsError::NoDevice),
    ] {
        assert_eq!(create_ext(size, param, value), Err(expected));
    }
    credentials.grant(&[ADMIN, NICE]);
    for (size, param, value, expected) in [(0, 5, 0, 0), (0, 6, 5, 5), (0, 8, 1, 1), (7, 13, 0, 0)]
    {
        let id = create_ext(size, param, value).expect("applied link");
        assert_eq!(get(id, param), Ok(expected));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_render",
    smoke_i915_context_params_follow_set_proto_ctx_param_and_ctx_setparam
);
