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
    lnl_gt_with(None)
}

/// [`lnl_gt`], its GuC's page faults routed to `usm` when given
/// (`narf.intel.svm=1`).
fn lnl_gt_with(
    usm: Option<Arc<crate::intel_gpu_xe_usm::Usm>>,
) -> (Window, Arena, GuCGt<Window, Arena>, BTreeMap<u32, u32>) {
    let platform = GtPlatform::Integrated(crate::intel_gpu::Generation::LunarLake);
    let (w, arena, mut gt) = hardware_model_with_identity(platform, 0xdfc, 1, Some(0x6420));
    if let Some(usm) = usm {
        gt.set_usm(usm);
    }
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

/// Forwards to the fixture's backend and publishes GPUSVM and the device's
/// USM state, as the GT owner does under `narf.intel.svm=1` on a USM device.
#[derive(Debug)]
struct MirroringUsm(Arc<dyn UserBackend>, Arc<crate::intel_gpu_xe_usm::Usm>);
impl UserBackend for MirroringUsm {
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
    fn usm(&self) -> Option<Arc<crate::intel_gpu_xe_usm::Usm>> {
        Some(self.1.clone())
    }
    fn submit<'a>(
        &'a self,
        context: Arc<UserContext>,
        batch: UserBatch,
    ) -> FsFuture<'a, Arc<CompletionFence>> {
        self.0.submit(context, batch)
    }
}

/// xe->usm against xe_vm.c, xe_device.c, xe_pagefault.c and
/// xe_guc_tlb_inval.c: cyclic ASIDs in [1, XE_MAX_ASID - 1] that are erased
/// with their VM, the fault queue's size and -ENOSPC, the service's refusals
/// before any VM state, and the page-selective PPGTT invalidation payload.
/// Then NARF's in-place rebind of a live leaf, which frees no table.
fn smoke_xe_usm_asids_fault_queue_and_ppgtt_invalidation() -> TestResult {
    use crate::intel_gpu_ppgtt::{FramePtMemory, Ppgtt, Rebind, WalkOutcome};
    use crate::intel_gpu_xe_usm::{self as usm, Usm};
    use crate::intel_gpu_xe_vm::Vm;
    // XE_MAX_ASID is BIT(20).
    assert_eq!(usm::MAX_ASID, 0x10_0000);
    let usm = Usm::new();
    let vm = || Vm::new(false, true, true).unwrap();
    let vms = [vm(), vm(), vm()];
    for vm in &vms {
        vm.assign_asid(&usm).unwrap();
    }
    // xa_alloc_cyclic from next_asid 0 over XA_LIMIT(1, XE_MAX_ASID - 1).
    assert_eq!(vms.each_ref().map(|vm| vm.asid()), [1, 2, 3]);
    assert!(Arc::ptr_eq(&usm.asid_to_vm(2).unwrap(), &vms[1]));
    // xe_vm_close_and_put erases the ASID; the cyclic allocator moves on.
    vms[0].release_asid();
    assert_eq!(vms[0].asid(), 0);
    assert!(usm.asid_to_vm(1).is_none());
    let fourth = vm();
    fourth.assign_asid(&usm).unwrap();
    assert_eq!(fourth.asid(), 4);
    // From next_asid XE_MAX_ASID - 1: that ASID, then the wrap to the
    // lowest free one.
    usm.set_next_asid(usm::MAX_ASID - 1);
    let top = vm();
    top.assign_asid(&usm).unwrap();
    assert_eq!(top.asid(), 0xf_ffff);
    let wrapped = vm();
    wrapped.assign_asid(&usm).unwrap();
    assert_eq!(wrapped.asid(), 1);
    // A dropped VM's ASID is erased with it, so it is free again.
    drop(top);
    usm.set_next_asid(usm::MAX_ASID - 1);
    let again = vm();
    again.assign_asid(&usm).unwrap();
    assert_eq!(again.asid(), 0xf_ffff);

    // xe_pagefault_queue_init: roundup_pow_of_two((total_num_eus +
    // XE_NUM_HW_ENGINES) * PF_MULTIPLIER) entries, one left free by
    // xe_pagefault_queue_full. XE_NUM_HW_ENGINES is 27.
    assert_eq!(usm::NUM_HW_ENGINES, 27);
    // 64 EUs (eight Xe2 Xe-cores of eight XVEs): (64 + 27) * 8 = 728 -> 1024.
    assert_eq!(usm::queue_capacity(64), 1023);
    // 160 EUs (twenty Xe-cores): (160 + 27) * 8 = 1496 -> 2048.
    assert_eq!(usm::queue_capacity(160), 2047);
    let fault = |access: u32, asid: u32| guc::PageFault::from_guc(&fault_desc(0x1000, access, asid)).unwrap();
    // Unsized (no producer): xe_pagefault_handler's -ENOSPC.
    assert_eq!(usm.push(fault(0, 1)), Err(FsError::NoSpace));
    usm.size_queue(0).unwrap();
    for _ in 0..255 {
        usm.push(fault(0, 0x777)).unwrap();
    }
    assert_eq!(usm.push(fault(0, 0x777)), Err(FsError::NoSpace));
    assert_eq!(usm.queued(), 255);
    narf_scheduler::block_on_spin(usm.drain());
    assert_eq!(usm.queued(), 0);
    for _ in 0..255 {
        // No VM holds ASID 0x777: XE_PAGEFAULT_ERROR_VM_NOT_FOUND, -EINVAL.
        let resolution = usm.pop_resolved().unwrap();
        assert_eq!((resolution.asid, resolution.result.as_ref().err()), (0x777, Some(&FsError::InvalidData)));
    }
    assert!(usm.pop_resolved().is_none());
    // A producer NACK (XE2_PFD_TRVA_FAULT, dw0 bit 18) is -EFAULT; a VM not
    // in fault mode -EINVAL; a fault-mode VM without the address in any VMA
    // -EINVAL. Each reply sets PFR_SUCCESS (!!err).
    let lr = Vm::new(false, true, false).unwrap();
    lr.assign_asid(&usm).unwrap();
    let mut nack = fault_desc(0x1000, 0, wrapped.asid());
    nack[0] |= 1 << 18;
    usm.push(guc::PageFault::from_guc(&nack).unwrap()).unwrap();
    usm.push(fault(0, lr.asid())).unwrap();
    usm.push(fault(0, wrapped.asid())).unwrap();
    narf_scheduler::block_on_spin(usm.drain());
    for expected in [FsError::BadAddress, FsError::InvalidData, FsError::InvalidData] {
        let resolution = usm.pop_resolved().unwrap();
        assert_eq!(resolution.result.as_ref().err(), Some(&expected));
        let replies: Vec<_> = resolution.replies(true).collect();
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0][0] & 2, 2);
    }

    // normalize_invalidation_range: at least 4 KiB, a naturally aligned
    // power of two covering the range, 16 MiB once it reaches 2 MiB.
    assert_eq!(usm::normalize_invalidation_range(0x1000, 0x2000), (0x1000, 0x1000));
    assert_eq!(usm::normalize_invalidation_range(0x1234_5000, 0x1234_5800), (0x1234_5000, 0x1000));
    assert_eq!(usm::normalize_invalidation_range(0x3000, 0x5000), (0, 0x8000));
    assert_eq!(usm::normalize_invalidation_range(0x20_0000, 0x40_0000), (0, 0x100_0000));
    // send_tlb_inval_ppgtt: seqno, MAKE_INVAL_OP(XE_GUC_TLB_INVAL_PAGE_SELECTIVE)
    // (type 1, MODE_HEAVY 0 << 8, FLUSH_CACHE bit 31), the ASID, the start's
    // low and high dwords and ilog2(length) - ilog2(SZ_4K).
    assert_eq!(
        usm::ppgtt_invalidation(9, 0x1_2345, 0x2345_0000_3000, 0x2345_0000_5000),
        [9, 0x8000_0001, 0x1_2345, 0, 0x2345, 3]
    );
    // Past MAX_RANGE_TLB_INVALIDATION_LENGTH: MAKE_INVAL_OP(XE_GUC_TLB_INVAL_FULL).
    assert_eq!(usm::ppgtt_invalidation(9, 1, 0, u64::MAX), [9, 0x8000_0000]);

    // Ppgtt::rebind (NARF): an absent leaf is bound, the same page again
    // changes nothing, another page and then NULL replace it in place, and no
    // table is allocated or freed past the first bind.
    let mut memory = FramePtMemory::new();
    let mut tables =
        Ppgtt::with_root_level(&mut memory, crate::intel_gpu_gtt::PteFormat::Xe2, 2, 4).unwrap();
    let page = |phys| Rebind::System(phys);
    assert_eq!(tables.rebind(&mut memory, 0x4000, page(0x1_0000_0000), 2, true), Ok(true));
    let live = memory.diagnostic_tables().count();
    assert_eq!(tables.translate(&memory, 0x4000), Ok(WalkOutcome::Mapped(0x1_0000_0000)));
    assert_eq!(tables.rebind(&mut memory, 0x4000, page(0x1_0000_0000), 2, true), Ok(false));
    assert_eq!(tables.rebind(&mut memory, 0x4000, page(0x2_0000_0000), 2, true), Ok(true));
    assert_eq!(tables.translate(&memory, 0x4000), Ok(WalkOutcome::Mapped(0x2_0000_0000)));
    assert_eq!(tables.rebind(&mut memory, 0x4000, Rebind::Null, 2, true), Ok(true));
    assert_eq!(tables.translate(&memory, 0x4000), Ok(WalkOutcome::Null));
    assert_eq!(memory.diagnostic_tables().count(), live);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe",
    smoke_xe_usm_asids_fault_queue_and_ppgtt_invalidation
);

/// A GPU page fault routed from the GuC on a Lunar Lake mirror VM
/// (`narf.intel.svm=1`, xe_guc_pagefault.c, xe_pagefault.c, xe_svm.c,
/// xe_guc_tlb_inval.c). The VM takes the device's first ASID and its copy
/// job's LRC carries it in CTX_ASID. The job's tables lack the mirror page
/// (no scratch). Two REPORT_PAGE_FAULT_REQ_DESCs for that page are queued; the
/// service collects the CPU page once through the grabbed address space and
/// answers the second from its cache; the GT owner binds the page into the
/// running job, sends one page-selective invalidation for the ASID, and only
/// after its DONE the two PAGE_FAULT_RES_DESCs. The job's store then lands in
/// the CPU page, and VM_DESTROY erases the ASID.
fn smoke_xe_svm_guc_fault_rebinds_running_job_and_acks() -> TestResult {
    use core::sync::atomic::Ordering::Relaxed;
    use narf_memory::RegionPerms;
    const CPU: u64 = 0x2345_0000_0000;
    const VALUE: u32 = 0x4e41_5246;
    let platform = GtPlatform::Integrated(crate::intel_gpu::Generation::LunarLake);
    let usm = crate::intel_gpu_xe_usm::Usm::new();
    let (w, arena, mut gt, mut registered) = lnl_gt_with(Some(usm.clone()));
    let (mailbox, mut info) = setup(&mut gt, &w, platform);
    info.backend = Some(Arc::new(MirroringUsm(info.backend.take().unwrap(), usm.clone())));
    let file = RenderFile::new();
    let user = Cpu::new();
    // The process's one page at CPU, grabbed at VM_CREATE (gpusvm->mm).
    let host = create_bo(&file, &info, &user, 4096, 0);
    let host = file.gem.object(host).unwrap();
    let mm = user.grab(host.backing(0, 4096).unwrap().frames[0]);
    user.space
        .map_region(cpu_vma(CPU, RegionPerms::READ | RegionPerms::WRITE))
        .unwrap();
    let vm = vm_with(&file, &info, &user, LR_FAULT);
    let asid = 1;
    assert!(usm.asid_to_vm(asid).is_some(), "xe_vm_create's first ASID");
    // DRM_XE_ENGINE_CLASS_COPY: the batch stores VALUE to CPU + 0x80.
    let queue = create_queue(&file, &info, &user, vm, 1);
    let code = create_bo(&file, &info, &user, 8192, 0);
    let words = [0x1000_0002u32, 0x80, (CPU >> 32) as u32, VALUE, 0x0500_0000, 0];
    let bytes: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    file.gem.object(code).unwrap().write(4096, &bytes).unwrap();
    let pat = batch_pat(platform);
    assert_eq!(
        bind_ops(&file, &info, &user, vm, &[mapping(code, 0x1234_0000_0000, 4096, 4096, pat, 1)]),
        Ok(0)
    );
    assert_eq!(bind_ops(&file, &info, &user, vm, &[mirror_op(CPU, 0x20_0000, pat, 0)]), Ok(0));

    // The job is registered and enabled but not run.
    let before: alloc::collections::BTreeSet<u32> = registered.values().copied().collect();
    exec_wire(&user, queue, true, &[]);
    let mut call = core::pin::pin!(file.dispatch_user(&info, xe::EXEC, 64, &user));
    assert!(call
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    let (_, fence) = mailbox.accept(&mut gt, 1_000_000);
    assert_eq!(
        call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Some(Ok(0)))
    );
    for now in 1_000_001..1_000_040 {
        assert_eq!(gt.poll(now), Poll::Ready(Ok(GtState::SchedulingReady)));
        service_contexts(&w, &mut registered, false);
    }
    let image = registered
        .values()
        .copied()
        .find(|base| !before.contains(base))
        .expect("registered job");
    // xe_lrc_init: CTX_ASID (0x2e + 1) holds vm->usm.asid.
    assert_eq!(w.0.borrow().memory[&image].borrow()[1024 + 0x2f], asid);
    assert!(fence.result().is_none());

    // Two write faults on the page, read from the G2H ring in one poll.
    for _ in 0..2 {
        event(&ct_memory(&w), 0x6002, &fault_desc(CPU, guc::ACCESS_WRITE as u32, asid));
    }
    assert_eq!(gt.poll(1_000_100), Poll::Ready(Ok(GtState::SchedulingReady)));
    assert_eq!(usm.queued(), 2);
    narf_scheduler::block_on_spin(usm.drain());
    // The 2 MiB and 64 KiB chunks hold unmapped pages; the 4 KiB one pins.
    // The second fault hits the service's cache and collects nothing.
    assert_eq!(mm.pin_calls.load(Relaxed), 3);
    assert_eq!(user.pin_calls.load(Relaxed), 0);
    assert!(w.0.borrow().fault_h2g.is_empty());
    assert_eq!(gt.poll(1_000_101), Poll::Ready(Ok(GtState::SchedulingReady)));
    service_contexts(&w, &mut registered, false);
    assert_eq!(gt.poll(1_000_102), Poll::Ready(Ok(GtState::SchedulingReady)));
    service_contexts(&w, &mut registered, false);
    let h2g = core::mem::take(&mut w.0.borrow_mut().fault_h2g);
    assert_eq!(h2g.len(), 3, "{h2g:x?}");
    // send_tlb_inval_ppgtt over the 4 KiB range: page selective, the ASID,
    // the range's start and ilog2(SZ_4K) - ilog2(SZ_4K).
    assert_eq!(h2g[0][0] as u16, 0x7000);
    assert_eq!(&h2g[0][2..], &[0x8000_0001, asid, CPU as u32, (CPU >> 32) as u32, 0]);
    // guc_ack_fault, after the DONE: PFR_VALID, PFR_SUCCESS 0, PFR_REPLY =
    // PFR_ACCESS, FAULT_RESPONSE_DESC, PFR_ASID; then fault_desc's PDATA
    // 0x1235. The cached fault needed no invalidation of its own.
    for reply in &h2g[1..] {
        assert_eq!(reply[0] as u16, 0x6003);
        assert_eq!(&reply[1..], &[1 | 1 << 10 | asid << 12, 0x1235 << 16]);
    }

    // The job runs: its store reaches the CPU page through the rebound PTE.
    execute_copy(&w, image);
    finish(&mut gt, &w, &fence, &mut registered, 1_000_200);
    let mut value = [0; 4];
    host.read(0x80, &mut value).unwrap();
    assert_eq!(u32::from_le_bytes(value), VALUE);

    assert_eq!(close(&file, &info, &user, xe::EXEC_QUEUE_DESTROY, queue), Ok(0));
    assert_eq!(close(&file, &info, &user, xe::VM_DESTROY, vm), Ok(0));
    assert!(usm.asid_to_vm(asid).is_none(), "xe_vm_close_and_put");
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_xe_svm_guc_fault_rebinds_running_job_and_acks
);

/// `struct drm_xe_madvise` with the union's first two dwords and its
/// reserved qword: start 8, range 16, vm_id 24, type 28, union 32..48.
fn madvise_wire(start: u64, range: u64, kind: u32, value: u32, word36: u32, reserved: u64) -> [u8; 64] {
    let mut wire = [0; 64];
    put64(&mut wire, 8, start);
    put64(&mut wire, 16, range);
    put32(&mut wire, 24, 7);
    put32(&mut wire, 28, kind);
    put32(&mut wire, 32, value);
    put32(&mut wire, 36, word36);
    put64(&mut wire, 40, reserved);
    wire
}

/// DRM_IOCTL_XE_MADVISE (xe_vm_madvise.c, xe_drm.h): madvise_args_are_sane
/// per type; then on a Lunar Lake mirror VM, the VMA split at the range's
/// edges, unchanged advice skipped, a preferred device other than the
/// defaults -ENOENT, PAT advice splitting a buffer-side VMA, a VMA-less range
/// doing nothing, default-attribute merging, and MADVISE_AUTORESET returning
/// a CPU-unmapped range's part to default attributes
/// (xe_svm_range_set_default_attr).
fn smoke_xe_madvise_args_split_zap_and_autoreset() -> TestResult {
    use crate::intel_gpu_xe_vm::{
        madvise::{self, Advice, Madvise},
        svm::{Mirror, MirrorVma},
        Vm,
    };
    use narf_memory::{RegionPerms, VirtAddr};
    let lnl = GtPlatform::Integrated(crate::intel_gpu::Generation::LunarLake);
    let parse = |wire: [u8; 64]| Madvise::parse(&wire, lnl);
    let at = |advice| Madvise {
        vm_id: 7,
        start: 0x1000,
        end: 0x2000,
        advice,
    };
    // 4 KiB aligned start and range, at least 4 KiB; an unknown type (4).
    assert_eq!(parse(madvise_wire(0x1800, 0x1000, 1, 1, 0, 0)), Err(FsError::InvalidData));
    assert_eq!(parse(madvise_wire(0x1000, 0x1800, 1, 1, 0, 0)), Err(FsError::InvalidData));
    assert_eq!(parse(madvise_wire(0x1000, 0, 1, 1, 0, 0)), Err(FsError::InvalidData));
    assert_eq!(parse(madvise_wire(0x1000, 0x1000, 4, 0, 0, 0)), Err(FsError::InvalidData));
    // ATOMIC: val at most DRM_XE_ATOMIC_CPU (3), pad and reserved zero.
    assert_eq!(parse(madvise_wire(0x1000, 0x1000, 1, 4, 0, 0)), Err(FsError::InvalidData));
    assert_eq!(parse(madvise_wire(0x1000, 0x1000, 1, 3, 1, 0)), Err(FsError::InvalidData));
    assert_eq!(parse(madvise_wire(0x1000, 0x1000, 1, 3, 0, 1)), Err(FsError::InvalidData));
    assert_eq!(parse(madvise_wire(0x1000, 0x1000, 1, 2, 0, 0)), Ok(at(Advice::Atomic(2))));
    // PREFERRED_LOC: devmem_fd at least DEFAULT_SYSTEM (-1); region_instance
    // (offset 38) MBZ for fd <= DEFAULT_DEVICE; migration_policy (offset 36)
    // at most ONLY_SYSTEM_PAGES (1); reserved zero.
    assert_eq!(parse(madvise_wire(0x1000, 0x1000, 0, -2i32 as u32, 0, 0)), Err(FsError::InvalidData));
    assert_eq!(parse(madvise_wire(0x1000, 0x1000, 0, 0, 1 << 16, 0)), Err(FsError::InvalidData));
    assert_eq!(parse(madvise_wire(0x1000, 0x1000, 0, u32::MAX, 2, 0)), Err(FsError::InvalidData));
    assert_eq!(parse(madvise_wire(0x1000, 0x1000, 0, 0, 0, 1)), Err(FsError::InvalidData));
    assert_eq!(
        parse(madvise_wire(0x1000, 0x1000, 0, 5, 1 << 16, 0)),
        Ok(at(Advice::PreferredLoc {
            devmem_fd: 5,
            migration_policy: 0
        }))
    );
    assert_eq!(
        parse(madvise_wire(0x1000, 0x1000, 0, u32::MAX, 1, 0)),
        Ok(at(Advice::PreferredLoc {
            devmem_fd: u32::MAX,
            migration_policy: 1
        }))
    );
    // PAT (xe2_pat_table): an index below n_entries (32) with a coherency
    // mode. 0 and the compressed 9 are XE_COH_NONE; 16 is reserved; 1 is
    // one-way, 2 two-way and 22 one-way with L3 CLOS 1.
    for (pat, admitted) in [(0, false), (1, true), (2, true), (9, false), (16, false), (22, true), (32, false)] {
        let parsed = parse(madvise_wire(0x1000, 0x1000, 2, pat, 0, 0));
        let expected = if admitted {
            Ok(at(Advice::Pat(pat as u8)))
        } else {
            Err(FsError::InvalidData)
        };
        assert_eq!(parsed, expected, "PAT {pat}");
    }
    // reserved[2] MBZ.
    let mut reserved = madvise_wire(0x1000, 0x1000, 1, 1, 0, 0);
    put64(&mut reserved, 56, 1);
    assert_eq!(parse(reserved), Err(FsError::InvalidData));
    // PURGEABLE_STATE: WILLNEED (0) or DONTNEED (1) with pad zero, then
    // EOPNOTSUPP: NARF objects have no purgeable state.
    assert_eq!(parse(madvise_wire(0x1000, 0x1000, 3, 2, 0, 0)), Err(FsError::InvalidData));
    assert_eq!(parse(madvise_wire(0x1000, 0x1000, 3, 1, 1, 0)), Err(FsError::InvalidData));
    assert_eq!(parse(madvise_wire(0x1000, 0x1000, 3, 1, 0, 0)), Err(FsError::Unsupported));
    // xe_device_uncanonicalize_addr keeps the low 48 bits.
    assert_eq!(
        parse(madvise_wire(0xffff_8000_0000_0000, 0x1000, 1, 1, 0, 0)).map(|m| m.start),
        Ok(0x8000_0000_0000)
    );

    // A mirror VM; the mirror VMA [1 MiB, 3 MiB) was bound with AUTORESET,
    // and a NULL VMA [4 MiB, 4 MiB + 16 KiB).
    let info = DeviceInfo {
        device_id: 0x6420,
        platform: lnl,
        memory_bytes: 0x8000_0000,
        hwconfig: None,
        topology: None,
        vram: None,
        backend: Some(Arc::new(Facts {
            platform: lnl,
            svm: true,
        })),
    };
    let file = RenderFile::new();
    let user = Cpu::new();
    let page = create_bo(&file, &info, &user, 4096, 0);
    *user.mapping.lock() = Some(file.gem.object(page).unwrap().backing(0, 4096).unwrap());
    let vm = Vm::with_svm(
        false,
        true,
        true,
        Some(Mirror {
            space: user.space.identity(),
            remote: None,
            discrete: false,
        }),
    )
    .unwrap();
    let svm = vm.svm.as_ref().unwrap();
    let mut state = narf_scheduler::block_on_spin(vm.state.lock());
    svm.set_vmas(&state, alloc::vec![MirrorVma::new(0x10_0000, 0x30_0000, 2, false, true)]);
    state.publish(alloc::vec![crate::intel_gpu_exec::VmMapping {
        object: None,
        va: 0x40_0000,
        offset: 0,
        length: 0x4000,
        writable: true,
        pat: 2,
        dumpable: false,
    }]);
    let advise = |state: &mut _, start, end, advice| {
        madvise::apply(
            &vm,
            state,
            &Madvise {
                vm_id: 0,
                start,
                end,
                advice,
            },
        )
    };
    let attrs = |state: &_| -> Vec<(u64, u64, u32, u32, u8)> {
        vm.svm_vmas(state)
            .iter()
            .map(|vma| (vma.start, vma.end, vma.attr.atomic, vma.attr.devmem_fd, vma.pat))
            .collect()
    };
    // xe_vm_alloc_madvise_vma, then madvise_atomic on the middle part.
    let global = Advice::Atomic(madvise::ATOMIC_GLOBAL);
    advise(&mut state, 0x18_0000, 0x20_0000, global).unwrap();
    let split = alloc::vec![
        (0x10_0000, 0x18_0000, madvise::ATOMIC_UNDEFINED, 0, 2),
        (0x18_0000, 0x20_0000, madvise::ATOMIC_GLOBAL, 0, 2),
        (0x20_0000, 0x30_0000, madvise::ATOMIC_UNDEFINED, 0, 2),
    ];
    assert_eq!(attrs(&state), split);
    // The same advice again is skip_invalidation: nothing changes.
    advise(&mut state, 0x18_0000, 0x20_0000, global).unwrap();
    assert_eq!(attrs(&state), split);
    // is_cpu_addr_vma_with_default_attr: a neighbour with advice is not
    // absorbed (start stays), a default one is (end grows).
    let vmas = vm.svm_vmas(&state);
    assert_eq!(svm::merge_extent(&vmas, 0x20_0000, 0x20_1000), (0x20_0000, 0x30_0000));
    assert_eq!(svm::merge_extent(&vmas, 0x30_0000, 0x40_0000), (0x20_0000, 0x40_0000));
    // A range with no VMA does nothing; PAT advice splits the NULL VMA.
    advise(&mut state, 0x80_0000, 0x80_1000, Advice::Atomic(1)).unwrap();
    assert_eq!(attrs(&state), split);
    advise(&mut state, 0x40_1000, 0x40_2000, Advice::Pat(1)).unwrap();
    let pats: Vec<_> = state.mappings.iter().map(|m| (m.va, m.length, m.pat)).collect();
    assert_eq!(pats, [(0x40_0000, 0x1000, 2), (0x40_1000, 0x1000, 1), (0x40_2000, 0x2000, 2)]);
    assert_eq!(attrs(&state), split);

    // MADVISE_AUTORESET: a range PREFETCH collected in the advised part, then
    // unmapped by the CPU. The garbage collector returns the range's part to
    // default attributes, merged with the default VMA before it.
    user.space
        .map_region(cpu_vma(0x18_0000, RegionPerms::READ | RegionPerms::WRITE))
        .unwrap();
    svm.prefetch(&vm, &state, 0x18_0000, 0x1000, 0, &user).unwrap();
    assert!(svm.has_mapping(0x18_0000, 0x18_1000));
    user.space.punch_fixed(VirtAddr::new(0x18_0000), 4096).unwrap();
    vm.svm_collect_garbage(&state);
    assert!(!svm.has_mapping(0x18_0000, 0x18_1000));
    assert_eq!(
        attrs(&state),
        [
            (0x10_0000, 0x18_1000, madvise::ATOMIC_UNDEFINED, 0, 2),
            (0x18_1000, 0x20_0000, madvise::ATOMIC_GLOBAL, 0, 2),
            (0x20_0000, 0x30_0000, madvise::ATOMIC_UNDEFINED, 0, 2),
        ]
    );

    // A preferred device other than the defaults: xe_drm_pagemap_from_fd's
    // -ENOENT without CONFIG_DRM_XE_PAGEMAP. DEFAULT_SYSTEM (-1) applies.
    let device = Advice::PreferredLoc {
        devmem_fd: 5,
        migration_policy: 0,
    };
    assert_eq!(advise(&mut state, 0x10_0000, 0x30_0000, device), Err(FsError::NotFound));
    let system = Advice::PreferredLoc {
        devmem_fd: u32::MAX,
        migration_policy: 0,
    };
    advise(&mut state, 0x10_0000, 0x30_0000, system).unwrap();
    assert!(vm.svm_vmas(&state).iter().all(|vma| vma.attr.devmem_fd == u32::MAX));
    // A closed VM: xe_vm_is_closed_or_banned's -ENOENT.
    vm.dead.store(true, core::sync::atomic::Ordering::Release);
    assert_eq!(advise(&mut state, 0x10_0000, 0x30_0000, global), Err(FsError::NotFound));
    drop(state);
    user.mapping.lock().take();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe",
    smoke_xe_madvise_args_split_zap_and_autoreset
);

/// DRM_IOCTL_XE_MADVISE exists only with GPUSVM published: with the option
/// off it is EINVAL like any ioctl past the table, and with it an unknown VM
/// is EINVAL (xe_vm_lookup) before the arguments. On Battlemage, Linux built
/// without CONFIG_DRM_XE_PAGEMAP (drm_pagemap needs ZONE_DEVICE, which NARF
/// lacks): a PREFETCH to VRAM and an atomic fault under DEVICE advice collect
/// system pages, a preferred device is -ENOENT, and an atomic fault under
/// DRM_XE_ATOMIC_CPU advice is xe_vma_need_vram_for_atomic's -EACCES.
fn smoke_xe_madvise_option_off_and_battlemage_system_pages() -> TestResult {
    use crate::intel_gpu_xe_vm::{
        madvise::{self, Advice, Madvise},
        svm::{Mirror, MirrorVma},
        Vm,
    };
    use narf_memory::RegionPerms;
    // DRM_IOW(DRM_COMMAND_BASE + DRM_XE_MADVISE (0x0c), 64 bytes).
    assert_eq!(xe::MADVISE, 0x4040_644c);
    let lnl = GtPlatform::Integrated(crate::intel_gpu::Generation::LunarLake);
    let mtl = GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake);
    for (platform, device, opted) in [
        (lnl, 0x6420, false),
        (lnl, 0x6420, true),
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
        let file = RenderFile::new();
        let user = Cpu::new();
        let vm = vm_with(&file, &info, &user, LR);
        let mut wire = madvise_wire(0x10_0000, 0x1000, 1, 1, 0, 0);
        put32(&mut wire, 24, vm);
        user.wire.store(64, &wire);
        let call = |user: &Cpu| {
            narf_scheduler::block_on_spin(file.dispatch_user(&info, xe::MADVISE, 64, user))
                .expect("native ioctl handled")
        };
        // No VMA in the range: nothing to advise.
        let expected = if opted { Ok(0) } else { Err(FsError::InvalidData) };
        assert_eq!(call(&user), expected, "{platform:?}");
        // An unknown VM, and bad arguments on a known one.
        put32(&mut wire, 24, vm + 100);
        user.wire.store(64, &wire);
        assert_eq!(call(&user), Err(FsError::InvalidData));
        put32(&mut wire, 24, vm);
        put32(&mut wire, 32, 9);
        user.wire.store(64, &wire);
        assert_eq!(call(&user), Err(FsError::InvalidData));
    }

    // Battlemage: a discrete mirror VM with one CPU page at CPU.
    const CPU: u64 = 0x50_0000;
    let info = DeviceInfo {
        device_id: 0xe20b,
        platform: GtPlatform::Battlemage,
        memory_bytes: 0x8000_0000,
        hwconfig: None,
        topology: None,
        vram: None,
        backend: Some(Arc::new(Facts {
            platform: GtPlatform::Battlemage,
            svm: true,
        })),
    };
    let file = RenderFile::new();
    let user = Cpu::new();
    let page = create_bo(&file, &info, &user, 4096, 0);
    *user.mapping.lock() = Some(file.gem.object(page).unwrap().backing(0, 4096).unwrap());
    user.space
        .map_region(cpu_vma(CPU, RegionPerms::READ | RegionPerms::WRITE))
        .unwrap();
    let vm = Vm::with_svm(
        true,
        true,
        true,
        Some(Mirror {
            space: user.space.identity(),
            remote: None,
            discrete: true,
        }),
    )
    .unwrap();
    let svm = vm.svm.as_ref().unwrap();
    let mut state = narf_scheduler::block_on_spin(vm.state.lock());
    svm.set_vmas(&state, alloc::vec![MirrorVma::new(0x40_0000, 0x60_0000, 2, false, false)]);
    let advise = |state: &mut _, advice| {
        madvise::apply(
            &vm,
            state,
            &Madvise {
                vm_id: 0,
                start: 0x40_0000,
                end: 0x60_0000,
                advice,
            },
        )
    };
    // DEFAULT_DEVICE is admitted; a device fd needs a drm_pagemap.
    let preferred = |devmem_fd| Advice::PreferredLoc {
        devmem_fd,
        migration_policy: 0,
    };
    advise(&mut state, preferred(0)).unwrap();
    assert_eq!(advise(&mut state, preferred(3)), Err(FsError::NotFound));
    // PREFETCH to region 1 (VRAM): prefetch_ranges collects system pages.
    svm.prefetch(&vm, &state, CPU, 0x1000, 1, &user).unwrap();
    let range = svm.range_mapping(CPU).expect("prefetched range");
    assert!(!range.object.as_ref().unwrap().is_vram());
    // Atomic faults: DRM_XE_ATOMIC_CPU is -EACCES on a dGPU; under DEVICE
    // the range (already valid) is served from system memory.
    let atomic = guc::PageFault::from_guc(&fault_desc(CPU, guc::ACCESS_ATOMIC as u32, 1)).unwrap();
    advise(&mut state, Advice::Atomic(madvise::ATOMIC_CPU)).unwrap();
    assert_eq!(guc::service(&vm, &state, &atomic, &user), Err(FsError::PermissionDenied));
    advise(&mut state, Advice::Atomic(madvise::ATOMIC_DEVICE)).unwrap();
    // The advice zapped the range: the fault collects it again.
    assert_eq!(guc::service(&vm, &state, &atomic, &user), Ok((CPU, CPU + 0x1000)));
    let range = svm.range_mapping(CPU).expect("refaulted range");
    assert!(!range.object.as_ref().unwrap().is_vram());
    drop(state);
    user.mapping.lock().take();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe",
    smoke_xe_madvise_option_off_and_battlemage_system_pages
);
