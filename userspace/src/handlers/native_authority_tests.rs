use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_native_file_bridge_rejects_worker_identity() -> TestResult {
    let id = narf_scheduler::TaskId(0xfa03_0001);
    let authority = narf_scheduler::prepare_user_authority(id);
    narf_scheduler::__set_task_active_domain_for_test(id, narf_lib::id::DomainId::USERSPACE_K);
    let subject = narf_abi::DispatchContext::new(&authority, authority.image().unwrap());
    let result = abi_file_op_bridge(
        Some(subject),
        narf_abi::FileOpKind::Mmap,
        &narf_abi::FileOpArgs {
            a1: 4096,
            ..Default::default()
        },
        &narf_abi::CancelCtx::detached(),
    );
    authority.__retire_for_test();
    if result.status != narf_abi::NarfStatus::Unsupported as u32 {
        return TestResult::Fail("foreign owner reached ambient worker syscall handler");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/authority",
    smoke_native_file_bridge_rejects_worker_identity
);

fn smoke_native_ring_pages_survive_unmap() -> TestResult {
    // SAFETY: kernel tests run after paging and frame allocation are ready.
    let space = match unsafe { AddressSpace::new_for_user() } {
        Ok(space) => Arc::new(space),
        Err(_) => return TestResult::Fail("new_for_user"),
    };
    // SAFETY: fresh valid user address space; frames are pinned before mapping.
    let (pair, pins) = match unsafe { mint_shared_ring_pair(&space) } {
        Ok(pair) => pair,
        Err(_) => return TestResult::Fail("mint shared rings"),
    };
    for phys in [pair.sq_phys, pair.cq_phys] {
        if narf_memory::frame::cow::count(phys) != 2 {
            return TestResult::Fail("mapping and session do not own separate frame refs");
        }
    }
    if space
        .unmap_region(VirtAddr::new(pair.sq_user_vaddr))
        .is_err()
        || space
            .unmap_region(VirtAddr::new(pair.cq_user_vaddr))
            .is_err()
    {
        return TestResult::Fail("unmap shared rings");
    }
    for phys in [pair.sq_phys, pair.cq_phys] {
        if narf_memory::frame::cow::count(phys) != 1 {
            return TestResult::Fail("unmap released the session's ring frame ref");
        }
    }
    drop(pins);
    for phys in [pair.sq_phys, pair.cq_phys] {
        if narf_memory::frame::cow::count(phys) != 0 {
            return TestResult::Fail("closed unmapped session leaked a ring frame ref");
        }
    }
    TestResult::Pass
}
kernel_test_in!("userspace/authority", smoke_native_ring_pages_survive_unmap);
