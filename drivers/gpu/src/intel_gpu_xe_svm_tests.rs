// Native Xe CPU-address-mirror VMs (`narf.intel.svm=1`; MIT Linux 7.4-rc4
// xe_vm.c vm_bind_ioctl_check_args and prefetch_ranges, xe_query.c, xe_svm.c,
// drm_gpusvm.c). Expected values come from those sources: the flag and query
// bits, fault_chunk_sizes and the errnos of each refusal.
use super::*;
use crate::intel_gpu_xe_vm::svm;

/// DRM_XE_VM_CREATE_FLAG_LR_MODE | FAULT_MODE, and LR_MODE alone.
const LR_FAULT: u32 = 6;
const LR: u32 = 2;

/// Device facts only: DEVICE_QUERY, VM_CREATE and binds need no GT.
#[derive(Debug)]
struct Facts {
    platform: GtPlatform,
    svm: bool,
}
impl UserBackend for Facts {
    fn status(&self) -> Option<UserStatus> {
        Some(UserStatus {
            epoch: 7,
            platform: self.platform,
            submission_version: (1, 0, 0),
            engines: crate::intel_gpu_engine::EngineSet::of(&[]),
        })
    }
    fn native_xe(&self) -> bool {
        true
    }
    fn device_facts(&self) -> Option<crate::intel_gpu_user::DeviceFacts> {
        Some(crate::intel_gpu_user::DeviceFacts {
            revision: 0,
            graphics_version: 2004,
            graphics_step: 0,
            reference_clock: 19_200_000,
            oa_timestamp_frequency: 19_200_000,
        })
    }
    fn cpu_addr_mirror(&self) -> bool {
        self.svm
    }
    fn submit<'a>(
        &'a self,
        _: Arc<UserContext>,
        _: UserBatch,
    ) -> FsFuture<'a, Arc<CompletionFence>> {
        Box::pin(async { Err(FsError::NoDevice) })
    }
}

fn vm_with(file: &RenderFile, info: &DeviceInfo, user: &Cpu, flags: u32) -> u32 {
    let mut wire = [0; 32];
    put32(&mut wire, 8, flags);
    user.wire.store(64, &wire);
    assert_eq!(invoke(file, info, user, xe::VM_CREATE), Ok(0));
    u32_at(&user.wire.load(64, 32), 12)
}

/// DRM_XE_VM_BIND_OP_MAP with DRM_XE_VM_BIND_FLAG_CPU_ADDR_MIRROR.
fn mirror_op(va: u64, length: u64, pat: u16, flags: u32) -> [u8; 80] {
    mapping(0, va, 0, length, pat, svm::BIND_FLAG_CPU_ADDR_MIRROR | flags)
}

fn op_with(mut op: [u8; 80], code: u32) -> [u8; 80] {
    put32(&mut op, 40, code);
    op
}

fn bind_ops(file: &RenderFile, info: &DeviceInfo, user: &Cpu, vm: u32, ops: &[[u8; 80]]) -> Result<u64, FsError> {
    bind_wire(user, vm, ops, &[]);
    bind_now(file, info, user)
}

/// The mirror-VMA set arithmetic a bind applies (xe_vm.c
/// xe_vm_find_cpu_addr_mirror_vma_range, vm_bind_ioctl_ops_parse) and
/// fault_chunk_sizes.
fn smoke_xe_svm_mirror_vma_merge_carve_and_cover() -> TestResult {
    // fault_chunk_sizes: 2 MiB, 64 KiB, 4 KiB.
    assert_eq!(svm::CHUNK_SIZES, [0x20_0000, 0x1_0000, 0x1000]);
    let vma = |start, end| svm::MirrorVma {
        start,
        end,
        pat: 2,
        read_only: false,
    };
    // xe_vm_find_cpu_addr_mirror_vma_range takes the VMAs holding start - 4K
    // and end + 1, not ones a page away.
    let vmas = [vma(0x1_0000, 0x2_0000), vma(0x3_0000, 0x4_0000), vma(0x5_1000, 0x6_0000)];
    assert_eq!(svm::merge_extent(&vmas, 0x2_0000, 0x3_0000), (0x1_0000, 0x4_0000));
    assert_eq!(svm::merge_extent(&vmas, 0x4_0000, 0x5_0000), (0x3_0000, 0x5_0000));
    assert_eq!(svm::merge_extent(&vmas, 0x1_8000, 0x1_9000), (0x1_0000, 0x2_0000));
    assert_eq!(svm::merge_extent(&vmas, 0, 0x1000), (0, 0x1000));
    // A REMAP keeps both sides; a live range in the removed part is -EBUSY
    // unless the op is a mirror MAP (ALLOW_SVM_UNMAP).
    let mut set = vmas.to_vec();
    svm::carve(&mut set, 0x1_4000, 0x3_8000, Some(&|_, _| false)).unwrap();
    assert_eq!(set, [vma(0x1_0000, 0x1_4000), vma(0x3_8000, 0x4_0000), vma(0x5_1000, 0x6_0000)]);
    let busy = |start: u64, end: u64| start < 0x5_2000 && 0x5_1000 < end;
    let before = set.clone();
    assert_eq!(svm::carve(&mut set, 0x5_0000, 0x5_8000, Some(&busy)), Err(FsError::Busy));
    assert_eq!(set, before);
    svm::carve(&mut set, 0x5_8000, 0x7_0000, Some(&busy)).unwrap();
    svm::carve(&mut set, 0x5_0000, 0x5_8000, None).unwrap();
    assert_eq!(set, [vma(0x1_0000, 0x1_4000), vma(0x3_8000, 0x4_0000)]);
    // PREFETCH admission: the union of mappings and mirror VMAs.
    assert!(svm::covered(&[], &set, 0x1_0000, 0x4000));
    assert!(!svm::covered(&[], &set, 0x1_0000, 0x5000));
    assert!(!svm::covered(&[], &set, 0x1_0000, 0));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe",
    smoke_xe_svm_mirror_vma_merge_carve_and_cover
);

/// The option-off refusal and vm_bind_ioctl_check_args for mirrors. Without
/// `narf.intel.svm=1`, or on a device without USM (Meteor Lake), the query
/// bit is clear and CPU_ADDR_MIRROR / MADVISE_AUTORESET are EINVAL exactly
/// as before. Admitted, a mirror binds on fault-mode VMs only, with no
/// object or offset, as a MAP, and with a coherent uncompressed PAT on an
/// iGPU; PREFETCH faults its CPU pages in, a VMA change over a live range is
/// -EBUSY, and a CPU munmap lets it through.
fn smoke_xe_svm_option_off_refusal_and_mirror_bind_admission() -> TestResult {
    use core::sync::atomic::Ordering::Relaxed;
    use narf_memory::{mmu_notifier::registered_intervals, VirtAddr};
    let lnl = GtPlatform::Integrated(crate::intel_gpu::Generation::LunarLake);
    let ptl = GtPlatform::Integrated(crate::intel_gpu::Generation::PantherLake);
    let mtl = GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake);
    for (platform, device, opted) in [
        (lnl, 0x6420, false),
        (GtPlatform::Battlemage, 0xe20b, false),
        (lnl, 0x6420, true),
        (ptl, 0xb080, true),
        (GtPlatform::Battlemage, 0xe20b, true),
        (mtl, 0x7d55, true),
    ] {
        let info = DeviceInfo {
            device_id: device,
            platform,
            memory_bytes: 0x8000_0000,
            hwconfig: None,
            topology: None,
            vram: None,
            backend: Some(Arc::new(Facts {
                platform,
                svm: opted,
            })),
        };
        // xe->info.has_usm: graphics 20 and later.
        let admitted = opted && platform != mtl;
        assert_eq!(svm::admitted(&info), admitted);
        let file = RenderFile::new();
        let user = Cpu::new();
        let baseline = registered_intervals();
        let config = xe_query(&file, &info, &user, 2);
        // DRM_XE_QUERY_CONFIG_FLAG_HAS_CPU_ADDR_MIRROR is bit 2.
        assert_eq!(u64_at(&config, 16) & 4 != 0, admitted, "{platform:?}");
        let fault = vm_with(&file, &info, &user, LR_FAULT);
        let lr = vm_with(&file, &info, &user, LR);
        let pat = batch_pat(platform);
        let expected = if admitted {
            Ok(0)
        } else {
            Err(FsError::InvalidData)
        };
        assert_eq!(
            bind_ops(&file, &info, &user, fault, &[mirror_op(0x40_0000, 0x20_0000, pat, 0)]),
            expected
        );
        // Not in fault mode: !xe_vm_in_fault_mode.
        assert_eq!(
            bind_ops(&file, &info, &user, lr, &[mirror_op(0x40_0000, 0x20_0000, pat, 0)]),
            Err(FsError::InvalidData)
        );
        // MADVISE_AUTORESET needs a mirror MAP; with one it is admitted.
        assert_eq!(
            bind_ops(
                &file,
                &info,
                &user,
                fault,
                &[mapping(0, 0x80_0000, 0, 0x1000, pat, svm::BIND_FLAG_MADVISE_AUTORESET)]
            ),
            Err(FsError::InvalidData)
        );
        assert_eq!(
            bind_ops(
                &file,
                &info,
                &user,
                fault,
                &[mirror_op(0x90_0000, 0x1000, pat, svm::BIND_FLAG_MADVISE_AUTORESET)]
            ),
            expected
        );
        if !admitted {
            assert_eq!(user.pin_calls.load(Relaxed), 0);
            continue;
        }
        let bo = create_bo(&file, &info, &user, 0x1_0000, 0);
        let compressed = (0..32).find(|pat| crate::intel_gpu_xe_vm::pat_compressed(platform, *pat));
        let noncoherent = (0..32)
            .find(|pat| {
                crate::intel_gpu_xe_vm::pat_noncoherent(platform, *pat)
                    && !crate::intel_gpu_xe_vm::pat_compressed(platform, *pat)
            })
            .unwrap();
        let mut refused = alloc::vec![
            {
                let mut op = mirror_op(0xa0_0000, 0x1000, pat, 0);
                put32(&mut op, 8, bo); // obj && is_cpu_addr_mirror
                op
            },
            {
                let mut op = mirror_op(0xa0_0000, 0x1000, pat, 0);
                put64(&mut op, 16, 0x1000); // cpu_addr_mirror_offset MBZ
                op
            },
            op_with(mirror_op(0xa0_0000, 0x1000, 0, 0), 1), // not a MAP
            op_with(mirror_op(0xa0_0000, 0x1000, 0, 0), 4),
            mirror_op(0xa0_0000, 0x1000, pat, svm::BIND_FLAG_NULL),
            mirror_op(0xa0_0000, 0x1000, pat, 1 << 7), // DECOMPRESS
            mirror_op(0xa0_0000, 0x1000, 16, 0),       // hw reserved
        ];
        if let Some(compressed) = compressed {
            refused.push(mirror_op(0xa0_0000, 0x1000, compressed, 0));
        }
        if !platform.is_discrete() {
            // !IS_DGFX && coh_mode == XE_COH_NONE.
            refused.push(mirror_op(0xa0_0000, 0x1000, noncoherent, 0));
        }
        for op in refused {
            assert_eq!(bind_ops(&file, &info, &user, fault, &[op]), Err(FsError::InvalidData));
        }
        if platform.is_discrete() {
            assert_eq!(
                bind_ops(&file, &info, &user, fault, &[mirror_op(0xa0_0000, 0x1000, noncoherent, 0)]),
                Ok(0)
            );
        }
        assert_eq!(user.pin_calls.load(Relaxed), 0, "a mirror bind collects nothing");
        assert_eq!(registered_intervals(), baseline);

        // A mirror over [0, 1 MiB); the CPU maps 0x4000 (rw) and 0x6000 (ro).
        assert_eq!(
            bind_ops(&file, &info, &user, fault, &[mirror_op(0, 0x10_0000, pat, 0)]),
            Ok(0)
        );
        let host = create_bo(&file, &info, &user, 4096, 0);
        *user.mapping.lock() = Some(file.gem.object(host).unwrap().backing(0, 4096).unwrap());
        let prefetch = |start: u64, length: u64| {
            op_with(mapping(0, start, 0, length, 0, 0), 4)
        };
        // prefetch_ranges: 0x4000 becomes a 4 KiB range (the 2 MiB chunk
        // leaves the VMA, the 64 KiB one holds unmapped VA 0); the CPU hole
        // at 0x5000 is skipped.
        assert_eq!(bind_ops(&file, &info, &user, fault, &[prefetch(0x4000, 0x2000)]), Ok(0));
        assert_eq!(user.pin_calls.load(Relaxed), 3);
        assert_eq!(registered_intervals(), baseline + 1);
        // Again: the range is valid, the hole is probed once more.
        assert_eq!(bind_ops(&file, &info, &user, fault, &[prefetch(0x4000, 0x2000)]), Ok(0));
        assert_eq!(user.pin_calls.load(Relaxed), 4);
        // A writable mirror over the read-only page: find_or_insert's -EPERM.
        assert_eq!(
            bind_ops(&file, &info, &user, fault, &[prefetch(0x6000, 0x1000)]),
            Err(FsError::OperationNotPermitted)
        );
        // Prefetch outside every VMA is EINVAL, as before.
        assert_eq!(
            bind_ops(&file, &info, &user, fault, &[prefetch(0x200_0000, 0x1000)]),
            Err(FsError::InvalidData)
        );
        // UNMAP, or a BO MAP, over the live range is -EBUSY; elsewhere a BO
        // MAP splits the mirror, and a mirror MAP over it merges.
        let unmap = op_with(mapping(0, 0, 0, 0x10_0000, 0, 0), 1);
        assert_eq!(bind_ops(&file, &info, &user, fault, &[unmap]), Err(FsError::Busy));
        assert_eq!(
            bind_ops(&file, &info, &user, fault, &[mapping(bo, 0, 0, 0x1_0000, pat, 0)]),
            Err(FsError::Busy)
        );
        assert_eq!(
            bind_ops(&file, &info, &user, fault, &[mapping(bo, 0x8_0000, 0, 0x1_0000, pat, 0)]),
            Ok(0)
        );
        assert_eq!(
            bind_ops(&file, &info, &user, fault, &[mirror_op(0x1_0000, 0x8_0000, pat, 0)]),
            Ok(0)
        );
        assert_eq!(registered_intervals(), baseline + 1);
        // munmap: the garbage collector drops the range, so the UNMAP passes.
        user.space.punch_fixed(VirtAddr::new(0x4000), 4096).unwrap();
        assert_eq!(bind_ops(&file, &info, &user, fault, &[unmap]), Ok(0));
        assert_eq!(registered_intervals(), baseline);
        user.mapping.lock().take();
        assert_eq!(close(&file, &info, &user, xe::VM_DESTROY, fault), Ok(0));
        assert_eq!(close(&file, &info, &user, xe::VM_DESTROY, lr), Ok(0));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe",
    smoke_xe_svm_option_off_refusal_and_mirror_bind_admission
);
