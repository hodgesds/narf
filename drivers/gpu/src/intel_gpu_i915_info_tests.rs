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
                (41, i32::from(live)),
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
