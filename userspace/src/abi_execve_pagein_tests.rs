//! Exec page-in clustering (#740): the loader records the new image's
//! demand-paged PT_LOAD spans as a plan, and `loader::page_in_plan`
//! installs them through the bulk fault API (#738) instead of leaving
//! every page to fault individually at first touch.
//!
//! The witnesses are the two that cannot be faked, mirroring
//! `smoke_userspace_exec_reads_headers_not_whole_file` and
//! `abi_faultaround_tests`: after the load, the segment's pages are
//! NOT backed and the counting `FileOps` has seen header bytes only;
//! after one `page_in_plan` drive, the pages ARE backed
//! (`mapped_frame` finds frames with no further fault call) and the
//! counter grew by exactly the clustered pages' bytes — the batch
//! read each page once, as one clustered operation, not as N faults.
//!
//! The fixture is a synthetic in-memory `FileOps` whose reads are
//! byte-counted, loaded through the real type `execve` hands the
//! loader (`ExecSource::File`) — no device, no filesystem, so the
//! counts isolate the loader/batch behaviour exactly.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_filesystem::{FileOps, FsFuture, Stat};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::{AddressSpace, VirtAddr};

use crate::abi_test_support::*;

const PAGE: u64 = 4096;
/// The fixture segment's virtual address. Page-congruent with its file
/// offset (`SEG_FOFF`), which is what makes the segment demand-eligible
/// in the first place.
const SEG_VA: u64 = 0x0000_0080_0000_1000;
const SEG_FOFF: u64 = 0x1000;

#[cfg(target_arch = "x86_64")]
const EM_NATIVE: u16 = 0x3E;
#[cfg(target_arch = "aarch64")]
const EM_NATIVE: u16 = 0xB7;

/// Total bytes pulled through the fixture file's `read` — reset per
/// load, then read as deltas around the operations under test.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
static READ_BYTES: AtomicU64 = AtomicU64::new(0);

/// In-memory `FileOps` over a byte vector; every read is counted.
/// Same shape as the counting file in `tests/elf_loader.rs`.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
struct CountingFile(alloc::vec::Vec<u8>);

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
impl FileOps for CountingFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let off = offset as usize;
        let n = if off >= self.0.len() {
            0
        } else {
            let n = core::cmp::min(self.0.len() - off, buf.len());
            buf[..n].copy_from_slice(&self.0[off..off + n]);
            n
        };
        READ_BYTES.fetch_add(n as u64, Ordering::Relaxed);
        alloc::boxed::Box::pin(async move { Ok(n) })
    }
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let n = buf.len();
        alloc::boxed::Box::pin(async move { Ok(n) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: self.0.len() as u64,
            blocks: self.0.len().div_ceil(512) as u64,
            mode: narf_filesystem::Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }
}

/// The loaded fixture's address space, published for the demand hook's
/// lookup while a test drives the batch — the same install the sibling
/// demand smokes perform.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
static PAGEIN_AS: IrqSafeSpinLock<Option<Arc<AddressSpace>>> = IrqSafeSpinLock::new(None);

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn lookup_pagein_as() -> Option<Arc<AddressSpace>> {
    PAGEIN_AS.lock().clone()
}

/// Byte-built ET_EXEC image: one PT_LOAD R|X at `SEG_VA` whose header
/// DECLARES `filesz_pages`/`memsz_pages`, while the byte vector only
/// carries `present_pages` of segment content after the header page —
/// so `present < filesz` builds the truncated fixtures. Segment page
/// `k` is filled with `0x41 + k`, so a resident page's bytes prove
/// which file page was read.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn build_exec_elf(
    present_pages: usize,
    filesz_pages: u64,
    memsz_pages: u64,
) -> alloc::vec::Vec<u8> {
    let mut b = alloc::vec![0u8; (SEG_FOFF as usize) + present_pages * (PAGE as usize)];
    b[..16].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    b[0x10..0x12].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    b[0x12..0x14].copy_from_slice(&EM_NATIVE.to_le_bytes());
    b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    b[0x18..0x20].copy_from_slice(&(SEG_VA + 0x100).to_le_bytes()); // e_entry
    b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    b[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());
    b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
    b[0x38..0x3A].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
    let ph = 64usize;
    b[ph..ph + 0x04].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    b[ph + 0x04..ph + 0x08].copy_from_slice(&5u32.to_le_bytes()); // PF_R|PF_X
    b[ph + 0x08..ph + 0x10].copy_from_slice(&SEG_FOFF.to_le_bytes()); // p_offset
    b[ph + 0x10..ph + 0x18].copy_from_slice(&SEG_VA.to_le_bytes()); // p_vaddr
    b[ph + 0x18..ph + 0x20].copy_from_slice(&SEG_VA.to_le_bytes()); // p_paddr
    b[ph + 0x20..ph + 0x28].copy_from_slice(&(filesz_pages * PAGE).to_le_bytes()); // p_filesz
    b[ph + 0x28..ph + 0x30].copy_from_slice(&(memsz_pages * PAGE).to_le_bytes()); // p_memsz
    b[ph + 0x30..ph + 0x38].copy_from_slice(&PAGE.to_le_bytes()); // p_align
    for k in 0..present_pages {
        let start = SEG_FOFF as usize + k * PAGE as usize;
        b[start..start + PAGE as usize].fill(0x41u8.wrapping_add(k as u8));
    }
    b
}

/// Load `image` through the production file-sourced path, exactly as
/// `execve` does after resolving the path.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn try_load(image: alloc::vec::Vec<u8>) -> Result<crate::UserProcess, crate::ProcessLoadError> {
    let file_size = image.len() as u64;
    let ops: Arc<dyn FileOps> = Arc::new(CountingFile(image));
    // The real type `execve` hands the loader, not a test stand-in.
    let source = crate::handlers::ExecSource::File {
        ops: Arc::clone(&ops),
        size: file_size,
    };
    READ_BYTES.store(0, Ordering::Relaxed);
    // SAFETY: the kernel-test harness keeps the kernel direct map live
    // and the frame allocator initialised — the loader's `# Safety`
    // contract, upheld the same way by the sibling exec smokes.
    unsafe {
        crate::load_user_process_with_root_file(
            &source,
            &["x"],
            &[],
            &[],
            None,
            crate::alloc_pid(),
            Some(&ops),
            None,
        )
    }
}

/// Load `image` (the load must succeed), publish its AS for the demand
/// hook, run `body`, then give everything back — the pid included, so
/// the fixture cannot perturb the suite it runs inside.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn with_loaded(
    image: alloc::vec::Vec<u8>,
    body: impl FnOnce(&crate::UserProcess) -> Result<(), &'static str>,
) -> TestResult {
    let proc = match try_load(image) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("file-sourced load failed"),
    };
    *PAGEIN_AS.lock() = Some(Arc::clone(&proc.address_space));
    crate::handlers::install_address_space_lookup(lookup_pagein_as);
    let verdict = body(&proc);
    crate::handlers::restore_address_space_lookup(None);
    *PAGEIN_AS.lock() = None;
    let pid = proc.pid;
    drop(proc);
    crate::release_pid(pid);
    match verdict {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}

/// The frame currently backing `va` (0 / `None` = unbacked). Finding a
/// frame here — without any fault call — is what *installed* means.
/// Same helper as `abi_faultaround_tests`.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn mapped_frame(aspace: &AddressSpace, va: u64) -> Option<u64> {
    let region = aspace.lookup(VirtAddr::new(va))?;
    let index = ((va & !(PAGE - 1)) - region.base.as_u64()) / PAGE;
    let phys = region.phys.get(index as usize)?.raw();
    (phys != 0).then_some(phys)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn assert_backed(aspace: &AddressSpace, base: u64, index: u64) -> Result<(), &'static str> {
    if mapped_frame(aspace, base + index * PAGE).is_none() {
        return Err("a page the batch should have installed is not backed");
    }
    Ok(())
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn assert_unbacked(aspace: &AddressSpace, base: u64, index: u64) -> Result<(), &'static str> {
    if mapped_frame(aspace, base + index * PAGE).is_some() {
        return Err("a page outside the batch's work is unexpectedly backed");
    }
    Ok(())
}

/// Bytes the mapping shows at `va` (must be backed), `len` of them,
/// copied page by page through each page's own frame.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn mapped_bytes(
    aspace: &AddressSpace,
    va: u64,
    len: usize,
) -> Result<alloc::vec::Vec<u8>, &'static str> {
    let mut out = alloc::vec::Vec::with_capacity(len);
    let mut done = 0usize;
    while done < len {
        let cur = va + done as u64;
        let phys = mapped_frame(aspace, cur).ok_or("the page is not backed")?;
        let in_page = (cur & (PAGE - 1)) as usize;
        let take = core::cmp::min(PAGE as usize - in_page, len - done);
        let ptr = narf_memory::PhysAddr::new(phys).kernel_ptr::<u8>();
        // SAFETY: `ptr` is the direct-map alias of a frame the mapping
        // holds; `in_page + take` stays inside that one frame.
        out.extend_from_slice(unsafe { core::slice::from_raw_parts(ptr.add(in_page), take) });
        done += take;
    }
    Ok(out)
}

/// A 32-page demand segment loads with its whole span as the plan,
/// nothing resident and nothing but headers read; one batch drive
/// installs all 32 pages, reads exactly their bytes once, serves the
/// file's content, and is a no-op when driven again.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_execve_pagein_clusters_demand_segment() -> TestResult {
    with_loaded(build_exec_elf(32, 32, 32), |proc| {
        if proc.page_in_plan.as_slice() != [(SEG_VA, 32)] {
            return Err("the plan is not the demand segment's whole span");
        }
        assert_unbacked(&proc.address_space, SEG_VA, 0)?;
        assert_unbacked(&proc.address_space, SEG_VA, 31)?;
        let before = READ_BYTES.load(Ordering::Relaxed);
        if before == 0 {
            return Err("nothing was read at all — the image cannot have parsed");
        }
        if before >= PAGE {
            return Err("the load already read a segment page — the image is not demand-paged");
        }
        // SAFETY: this fixture published the process AS as the
        // harness's lookup target (the sibling demand smokes' pattern);
        // the production call sites run this post-activation, which is
        // the same live-root arrangement the batch contract asks for.
        let installed =
            unsafe { crate::loader::page_in_plan(&proc.address_space, &proc.page_in_plan) };
        if installed != 32 {
            return Err("the batch did not install the whole segment");
        }
        if READ_BYTES.load(Ordering::Relaxed) - before != 32 * PAGE {
            return Err("the batch did not read exactly the segment's bytes, once each");
        }
        for index in 0..32 {
            assert_backed(&proc.address_space, SEG_VA, index)?;
        }
        if mapped_bytes(&proc.address_space, SEG_VA, PAGE as usize)?
            != alloc::vec![0x41u8; PAGE as usize]
        {
            return Err("the first clustered page does not serve the file's bytes");
        }
        if mapped_bytes(&proc.address_space, SEG_VA + 31 * PAGE, PAGE as usize)?
            != alloc::vec![0x41u8.wrapping_add(31); PAGE as usize]
        {
            return Err("the last clustered page does not serve the file's bytes");
        }
        // Re-driving the plan installs nothing and reads nothing: the
        // batch is a pure accelerator over pages already resident.
        let before = READ_BYTES.load(Ordering::Relaxed);
        // SAFETY: same arrangement as the first drive.
        let again = unsafe { crate::loader::page_in_plan(&proc.address_space, &proc.page_in_plan) };
        if again != 0 || READ_BYTES.load(Ordering::Relaxed) != before {
            return Err("re-driving the plan was not a no-op");
        }
        Ok(())
    })
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!(
    "syscall_abi/execve_pagein/clusters_demand_segment",
    smoke_execve_pagein_clusters_demand_segment
);

/// The budget binds: a 400-page segment's plan is clamped to
/// EXEC_PAGEIN_MAX_PAGES (256), the batch installs exactly that head,
/// and the unclustered remainder still faults in on demand — the split
/// the cap promises (large images pay bounded exec cost, never
/// correctness).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_execve_pagein_budget_bounds_large_segment() -> TestResult {
    with_loaded(build_exec_elf(400, 400, 400), |proc| {
        if proc.page_in_plan.as_slice() != [(SEG_VA, 256)] {
            return Err("the plan was not clamped to the exec page-in budget");
        }
        let before = READ_BYTES.load(Ordering::Relaxed);
        // SAFETY: see the sibling test's note on the live-root fixture.
        let installed =
            unsafe { crate::loader::page_in_plan(&proc.address_space, &proc.page_in_plan) };
        if installed != 256 {
            return Err("the batch did not install exactly the budgeted head");
        }
        if READ_BYTES.load(Ordering::Relaxed) - before != 256 * PAGE {
            return Err("the batch read more or less than the budgeted pages");
        }
        assert_backed(&proc.address_space, SEG_VA, 0)?;
        assert_backed(&proc.address_space, SEG_VA, 255)?;
        assert_unbacked(&proc.address_space, SEG_VA, 256)?;
        assert_unbacked(&proc.address_space, SEG_VA, 399)?;
        // A page past the budget faults in through the ordinary
        // single-page path, unchanged.
        // SAFETY: `SEG_VA + 300 pages` lies in this process's
        // FILE_DEMAND region, inside the file.
        if unsafe {
            proc.address_space
                .demand_alloc_page(VirtAddr::new(SEG_VA + 300 * PAGE))
        }
        .is_err()
        {
            return Err("a page past the budget no longer faults in on demand");
        }
        assert_backed(&proc.address_space, SEG_VA, 300)?;
        Ok(())
    })
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!(
    "syscall_abi/execve_pagein/budget_bounds_large_segment",
    smoke_execve_pagein_budget_bounds_large_segment
);

/// A demand segment truncated after the headers still LOADS — the
/// deferred failure is today's documented demand behaviour — and the
/// batch installs only the pages the file actually has. The missing
/// tail stays unbacked: it will SIGBUS on touch, exactly as it did
/// before clustering existed.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_execve_pagein_truncated_demand_defers_failure() -> TestResult {
    with_loaded(build_exec_elf(20, 32, 32), |proc| {
        if proc.page_in_plan.as_slice() != [(SEG_VA, 32)] {
            return Err("the plan does not cover the declared segment span");
        }
        let before = READ_BYTES.load(Ordering::Relaxed);
        // SAFETY: see the sibling test's note on the live-root fixture.
        let installed =
            unsafe { crate::loader::page_in_plan(&proc.address_space, &proc.page_in_plan) };
        if installed != 20 {
            return Err("the batch installed pages the truncated file does not have");
        }
        if READ_BYTES.load(Ordering::Relaxed) - before != 20 * PAGE {
            return Err("the batch read bytes other than the present pages");
        }
        assert_backed(&proc.address_space, SEG_VA, 0)?;
        assert_backed(&proc.address_space, SEG_VA, 19)?;
        assert_unbacked(&proc.address_space, SEG_VA, 20)?;
        assert_unbacked(&proc.address_space, SEG_VA, 31)?;
        Ok(())
    })
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!(
    "syscall_abi/execve_pagein/truncated_demand_defers_failure",
    smoke_execve_pagein_truncated_demand_defers_failure
);

/// The regression guard for exec semantics: a segment BELOW the
/// demand floor loads eagerly, so a truncated one keeps failing the
/// load synchronously — with the same error it produced before
/// clustering. Clustering must never convert a synchronous ENOEXEC
/// into a deferred fault.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_execve_pagein_truncated_eager_fails_load() -> TestResult {
    // 8 declared pages (32 KiB) is under the 64 KiB demand floor, so
    // the loader copies eagerly; only 4 pages are actually present.
    match try_load(build_exec_elf(4, 8, 8)) {
        Err(crate::ProcessLoadError::Load(crate::LoadBytesError::ByteCopyOutOfBounds)) => {
            TestResult::Pass
        }
        Err(_) => TestResult::Fail("truncated eager image failed with the wrong error"),
        Ok(proc) => {
            let pid = proc.pid;
            drop(proc);
            crate::release_pid(pid);
            TestResult::Fail("truncated eager image loaded")
        }
    }
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!(
    "syscall_abi/execve_pagein/truncated_eager_fails_load",
    smoke_execve_pagein_truncated_eager_fails_load
);
