// Native Xe CPU-address-mirror VMs (`narf.intel.svm=1`; MIT Linux 7.4-rc4
// xe_vm.c vm_bind_ioctl_check_args and prefetch_ranges, xe_query.c, xe_svm.c,
// xe_pagefault.c, xe_guc_pagefault.c, drm_gpusvm.c). Expected values come
// from those sources: the flag and query bits, the GuC descriptor/reply field
// layout of xe_guc_fwif.h, fault_chunk_sizes and the errnos of each refusal.
use super::*;
use crate::intel_gpu_xe_vm::svm::{self, guc};

/// DRM_XE_VM_CREATE_FLAG_SCRATCH_PAGE | LR_MODE | FAULT_MODE.
const SCRATCH_LR_FAULT: u32 = 7;
/// DRM_XE_VM_CREATE_FLAG_LR_MODE | FAULT_MODE, and LR_MODE alone.
const LR_FAULT: u32 = 6;
const LR: u32 = 2;

/// Forwards to the fixture's backend and publishes GPUSVM, as the GT owner
/// does under `narf.intel.svm=1`.
#[derive(Debug)]
struct Mirroring(Arc<dyn UserBackend>);
impl UserBackend for Mirroring {
    fn status(&self) -> Option<UserStatus> {
        self.0.status()
    }
    fn media_gt(&self) -> Option<crate::intel_gpu_user::MediaGtStatus> {
        self.0.media_gt()
    }
    fn native_xe(&self) -> bool {
        self.0.native_xe()
    }
    fn device_facts(&self) -> Option<crate::intel_gpu_user::DeviceFacts> {
        self.0.device_facts()
    }
    fn cpu_addr_mirror(&self) -> bool {
        true
    }
    fn submit<'a>(
        &'a self,
        context: Arc<UserContext>,
        batch: UserBatch,
    ) -> FsFuture<'a, Arc<CompletionFence>> {
        self.0.submit(context, batch)
    }
}

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

/// struct xe_guc_pagefault_desc (xe_guc_fwif.h) for a not-present fault
/// (PFD_FAULT_TYPE 0) at page `address` from RCS0: PFD_FAULT_LEVEL 1,
/// PFD_SRC_ID 0x20, PFD_PDATA 0x1235 and `access` in PFD_ACCESS_TYPE.
fn fault_desc(address: u64, access: u32, asid: u32) -> [u32; 4] {
    [
        1 | 0x20 << 3 | 0x5 << 28,
        0x123 | asid << 12,
        access | (address as u32 & 0xffff_f000),
        (address >> 32) as u32,
    ]
}

/// The decoder and encoder against the field layout of xe_guc_fwif.h, every
/// field non-zero.
fn smoke_xe_svm_guc_fault_descriptor_and_reply() -> TestResult {
    // dw0: PFD_FAULT_LEVEL 3, PFD_SRC_ID 0xa5, PFD_ENG_INSTANCE 0x2a,
    // PFD_ENG_CLASS 4, PFD_PDATA_LO 0xc. dw1: PFD_PDATA_HI 0xabc, PFD_ASID
    // 0x12345. dw2: PFD_ACCESS_TYPE 2 (atomic), PFD_FAULT_TYPE 1 (write
    // violation), PFD_VFID 0x15, PFD_PREFETCH, PFD_VIRTUAL_ADDR_LO
    // 0x89abc. dw3: PFD_VIRTUAL_ADDR_HI 0x1234.
    let desc = [0xc950_052b, 0x1234_5abc, 0x89ab_c956, 0x1234];
    let fault = guc::PageFault::from_guc(&desc).unwrap();
    assert_eq!(fault.page_addr, 0x1234_89ab_c000);
    assert_eq!(fault.asid, 0x12345);
    assert_eq!(fault.srcid, 0xa5);
    assert_eq!(fault.access_type, guc::ACCESS_ATOMIC | guc::ACCESS_PREFETCH);
    assert!(fault.atomic());
    // XE_PAGEFAULT_LEVEL_MASK 2:0, XE_PAGEFAULT_TYPE_MASK from bit 3.
    assert_eq!(fault.fault_type_level, 3 | 1 << 3);
    assert_eq!((fault.engine_class, fault.engine_instance), (4, 0x2a));
    // guc_ack_fault: PFR_VALID, PFR_SUCCESS = !!err, PFR_REPLY = PFR_ACCESS,
    // PFR_DESC_TYPE = FAULT_RESPONSE_DESC, PFR_ASID; then PFR_VFID,
    // PFR_PREFETCH (only on error), PFR_ENG_INSTANCE, PFR_ENG_CLASS and the
    // 16-bit PFR_PDATA 0xabcc.
    assert_eq!(fault.guc_reply(false), [0x6003, 0x1234_5401, 0xabcc_9515]);
    assert_eq!(fault.guc_reply(true), [0x6003, 0x1234_5403, 0xabcc_9555]);
    assert_eq!(guc::ACTION_REPORT_PAGE_FAULT_REQ_DESC, 0x6002);
    // XE2_PFD_TRVA_FAULT asks for a NACK; the length must be four dwords.
    let nack = guc::PageFault::from_guc(&[desc[0] | 1 << 18, desc[1], desc[2], desc[3]]).unwrap();
    assert_eq!(nack.fault_type_level, guc::TYPE_LEVEL_NACK);
    for payload in [&desc[..3], &[0; 5][..]] {
        assert_eq!(guc::PageFault::from_guc(payload), Err(FsError::Protocol));
    }
    // The read-access fixture descriptor decodes to its own fields.
    let read = guc::PageFault::from_guc(&fault_desc(0x7fff_1234_5000, 0, 9)).unwrap();
    assert_eq!((read.page_addr, read.asid, read.access_type), (0x7fff_1234_5000, 9, 0));
    assert!(!read.atomic());
    assert_eq!(read.fault_type_level, 1);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe",
    smoke_xe_svm_guc_fault_descriptor_and_reply
);

/// The mirror-VMA set arithmetic a bind applies (xe_vm.c
/// xe_vm_find_cpu_addr_mirror_vma_range, vm_bind_ioctl_ops_parse) and
/// fault_chunk_sizes.
fn smoke_xe_svm_mirror_vma_merge_carve_and_cover() -> TestResult {
    // fault_chunk_sizes: 2 MiB, 64 KiB, 4 KiB.
    assert_eq!(svm::CHUNK_SIZES, [0x20_0000, 0x1_0000, 0x1000]);
    let vma = |start, end| svm::MirrorVma::new(start, end, 2, false, false);
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

/// A Lunar Lake GT through context defaults (the LNL native fixture's
/// prelude), with the contexts it registered.
fn lnl_gt() -> (Window, Arena, GuCGt<Window, Arena>, BTreeMap<u32, u32>) {
    let platform = GtPlatform::Integrated(crate::intel_gpu::Generation::LunarLake);
    let (w, arena, mut gt) = hardware_model_with_identity(platform, 0xdfc, 1, Some(0x6420));
    hardware_discovery(&mut gt, &w, 0xdfc);
    hardware_scheduling_reload_mode(&mut gt, &w, 4);
    hardware_enable_ct(&mut gt, &w);
    let defaults = gt.begin_context_defaults(26).unwrap();
    let mut registered = BTreeMap::new();
    for now in 27..500 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(&w, &mut registered, true);
        if defaults.result().is_some() {
            break;
        }
    }
    assert_eq!(defaults.result(), Some(Ok(())));
    (w, arena, gt, registered)
}

/// GPU faults on a Lunar Lake mirror VM, through the GuC fault descriptor:
/// before a fault the batch's store reaches only scratch; a fault populates
/// a 4 KiB range from the CPU's page and the store lands in it; mprotect
/// zaps the range, the next job's refault fails EPERM (scratch again) and
/// succeeds once the page is writable; munmap zaps and garbage-collects it,
/// and only a new fault populates it from the new page. The fault service
/// refuses VMA-less addresses, CPU holes, writes to a read-only mirror and
/// another process.
fn smoke_xe_svm_gpu_fault_populates_zaps_and_refaults() -> TestResult {
    use core::sync::atomic::Ordering::Relaxed;
    use narf_memory::{mmu_notifier::registered_intervals, RegionPerms, VirtAddr};
    const CPU: u64 = 0x2345_0000_0000;
    const VALUE: u32 = 0x4e41_5246;
    let platform = GtPlatform::Integrated(crate::intel_gpu::Generation::LunarLake);
    let (w, arena, mut gt, mut registered) = lnl_gt();
    let (mailbox, mut info) = setup(&mut gt, &w, platform);
    info.backend = Some(Arc::new(Mirroring(info.backend.take().unwrap())));
    let file = RenderFile::new();
    let user = Cpu::new();
    let baseline = registered_intervals();
    let vm = vm_with(&file, &info, &user, SCRATCH_LR_FAULT);
    let queue = create_queue(&file, &info, &user, vm, 0);
    // The batch at 0x1234_0000_0000 stores VALUE to GPU VA CPU + 0x80.
    let code = create_bo(&file, &info, &user, 8192, 0);
    let words = [0x1000_0002u32, 0x80, 0x2345, VALUE, 0x0500_0000, 0];
    let bytes: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    file.gem.object(code).unwrap().write(4096, &bytes).unwrap();
    let pat = batch_pat(platform);
    assert_eq!(
        bind_ops(&file, &info, &user, vm, &[mapping(code, 0x1234_0000_0000, 4096, 4096, pat, 1)]),
        Ok(0)
    );
    // The process maps one page at CPU; the mirror covers 2 MiB there.
    user.space
        .map_region(cpu_vma(CPU, RegionPerms::READ | RegionPerms::WRITE))
        .unwrap();
    let page = |user: &Cpu| {
        let handle = create_bo(&file, &info, user, 4096, 0);
        let object = file.gem.object(handle).unwrap();
        *user.mapping.lock() = Some(object.backing(0, 4096).unwrap());
        object
    };
    let stored = |object: &Arc<crate::intel_gpu_gem::GemObject>| {
        let mut value = [0; 4];
        object.read(0x80, &mut value).unwrap();
        u32::from_le_bytes(value)
    };
    let host = page(&user);
    assert_eq!(bind_ops(&file, &info, &user, vm, &[mirror_op(CPU, 0x20_0000, pat, 0)]), Ok(0));
    assert_eq!(registered_intervals(), baseline, "a mirror bind maps nothing");
    let fault = |address: u64, access: u32, user: &Cpu| {
        narf_scheduler::block_on_spin(file.xe().service_page_fault(
            vm,
            &fault_desc(address, access, 1),
            user,
        ))
        .unwrap()
    };
    let mut exec = |now: u64, gt: &mut GuCGt<Window, Arena>| {
        userptr_exec(
            &file,
            &info,
            &user,
            queue,
            true,
            &mailbox,
            gt,
            &w,
            &mut registered,
            now,
        )
    };

    // Unfaulted, the store reaches scratch.
    assert_eq!(exec(1_000_000, &mut gt), Ok(0));
    assert_eq!(stored(&host), 0);
    assert_eq!(user.pin_calls.load(Relaxed), 0);

    // A write fault: the 2 MiB and 64 KiB chunks hold unmapped pages, so the
    // range is the 4 KiB CPU page. guc_ack_fault reports success.
    let served = fault(CPU, guc::ACCESS_WRITE as u32, &user);
    assert_eq!(served.result, Ok((CPU, CPU + 0x1000)));
    assert_eq!(served.reply, [0x6003, 1 | 1 << 10 | 1 << 12, 0x1235 << 16]);
    assert_eq!(user.pin_calls.load(Relaxed), 3);
    assert_eq!(registered_intervals(), baseline + 1);
    assert_eq!(exec(1_001_000, &mut gt), Ok(0));
    assert_eq!(stored(&host), VALUE);
    // A second fault finds the range valid and collects nothing.
    assert_eq!(fault(CPU, guc::ACCESS_READ as u32, &user).result, Ok((CPU, CPU + 0x1000)));
    assert_eq!(user.pin_calls.load(Relaxed), 3);

    // Refusals: no VMA (-EINVAL), a CPU hole in the mirror (-ENOENT), a
    // write to a read-only mirror (-EPERM), and another process (ENOSYS).
    // Each reply sets PFR_SUCCESS (!!err).
    let none = fault(0x4000_0000_0000, 0, &user);
    assert_eq!(none.result, Err(FsError::InvalidData));
    assert_eq!(none.reply[1] & 2, 2);
    assert_eq!(fault(CPU + 0x10_0000, 0, &user).result, Err(FsError::NotFound));
    assert_eq!(
        bind_ops(&file, &info, &user, vm, &[mirror_op(0x6000, 0x1000, pat, 1)]),
        Ok(0)
    );
    let pins = user.pin_calls.load(Relaxed);
    assert_eq!(
        fault(0x6000, guc::ACCESS_WRITE as u32, &user).result,
        Err(FsError::OperationNotPermitted)
    );
    assert_eq!(user.pin_calls.load(Relaxed), pins);
    assert_eq!(fault(0x6000, 0, &user).result, Ok((0x6000, 0x7000)));
    let other = Cpu::new();
    assert_eq!(fault(CPU, 0, &other).result, Err(FsError::NotImplemented));
    assert_eq!(other.pin_calls.load(Relaxed), 0);
    let pins = user.pin_calls.load(Relaxed);

    // mprotect(PROT_READ) zaps the writable range: the job's refault is
    // EPERM, so the store reaches scratch, and a GPU fault fails the same way.
    host.write(0x80, &[0; 4]).unwrap();
    user.space
        .mprotect_range(VirtAddr::new(CPU), 4096, RegionPerms::READ)
        .unwrap();
    assert_eq!(exec(1_002_000, &mut gt), Ok(0));
    assert_eq!(stored(&host), 0, "the GPU wrote through a zapped range");
    assert_eq!(user.pin_calls.load(Relaxed), pins + 1);
    let refused = fault(CPU, guc::ACCESS_WRITE as u32, &user);
    assert_eq!(refused.result, Err(FsError::OperationNotPermitted));
    assert_eq!(refused.reply[1] & 2, 2);
    // Writable again: the next job refaults the range from the CPU page.
    user.space
        .mprotect_range(VirtAddr::new(CPU), 4096, RegionPerms::READ | RegionPerms::WRITE)
        .unwrap();
    assert_eq!(exec(1_003_000, &mut gt), Ok(0));
    assert_eq!(stored(&host), VALUE);
    assert_eq!(user.pin_calls.load(Relaxed), pins + 3);
    assert_eq!(registered_intervals(), baseline + 2);

    // munmap + mmap of a new page: the range is zapped and collected, so the
    // next job maps neither page; a fault then populates the new one.
    host.write(0x80, &[0; 4]).unwrap();
    user.space.punch_fixed(VirtAddr::new(CPU), 4096).unwrap();
    user.space
        .map_region(cpu_vma(CPU, RegionPerms::READ | RegionPerms::WRITE))
        .unwrap();
    let fresh = page(&user);
    assert_eq!(exec(1_004_000, &mut gt), Ok(0));
    assert_eq!((stored(&host), stored(&fresh)), (0, 0));
    assert_eq!(user.pin_calls.load(Relaxed), pins + 3);
    assert_eq!(registered_intervals(), baseline + 1);
    assert_eq!(fault(CPU, guc::ACCESS_WRITE as u32, &user).result, Ok((CPU, CPU + 0x1000)));
    assert_eq!(exec(1_005_000, &mut gt), Ok(0));
    assert_eq!((stored(&host), stored(&fresh)), (0, VALUE));
    assert_eq!(registered_intervals(), baseline + 2);

    // The mirror's UNMAP waits for the CPU: -EBUSY while the range lives.
    let unmap = op_with(mapping(0, CPU, 0, 0x20_0000, 0, 0), 1);
    assert_eq!(bind_ops(&file, &info, &user, vm, &[unmap]), Err(FsError::Busy));
    user.space.punch_fixed(VirtAddr::new(CPU), 4096).unwrap();
    assert_eq!(bind_ops(&file, &info, &user, vm, &[unmap]), Ok(0));
    assert_eq!(registered_intervals(), baseline + 1);

    drop(host);
    drop(fresh);
    user.mapping.lock().take();
    assert_eq!(
        close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, queue),
        Ok(0)
    );
    assert_eq!(close(&file, &info, &user, xe::VM_DESTROY, vm), Ok(0));
    assert_eq!(registered_intervals(), baseline);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_xe_svm_gpu_fault_populates_zaps_and_refaults
);
