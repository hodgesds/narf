//! Demand-paged exec: the loader maps a file-backed image's PT_LOAD
//! segments as FILE_DEMAND regions and reads nothing inside execve —
//! every page faults in on first touch after the new image starts,
//! like Linux's `binfmt_elf`.
//!
//! The witnesses are the two that cannot be faked, mirroring
//! `smoke_userspace_exec_reads_headers_not_whole_file` and
//! `abi_faultaround_tests`: after the load, the segment's pages are
//! NOT backed and the counting `FileOps` has seen header bytes only;
//! after a first touch, exactly that page IS backed
//! (`mapped_frame` finds its frame with no further fault call) and the
//! counter grew by exactly one page's bytes — the fault read the page
//! once, as one fault, not as an eager bulk copy.
//!
//! The fixture is a synthetic in-memory `FileOps` whose reads are
//! byte-counted, loaded through the real type `execve` hands the
//! loader (`ExecSource::File`) — no device, no filesystem, so the
//! counts isolate the loader behaviour exactly.

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
/// lookup while a test drives a fault — the same install the sibling
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
        return Err("a page first touch should have installed is not backed");
    }
    Ok(())
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn assert_unbacked(aspace: &AddressSpace, base: u64, index: u64) -> Result<(), &'static str> {
    if mapped_frame(aspace, base + index * PAGE).is_some() {
        return Err("a page no first touch reached is unexpectedly backed");
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

/// Fault a single page in through the ordinary first-touch path.
/// The fixture published the process AS as the harness's lookup
/// target (the sibling demand smokes' pattern); the caller passes
/// the page to fault.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn fault_page(aspace: &AddressSpace, va: u64) -> Result<(), narf_memory::AddressSpaceError> {
    // SAFETY: the fixture published this AS for the demand hook, the
    // same live-root arrangement the production fault path runs under.
    unsafe { aspace.demand_alloc_page(VirtAddr::new(va)) }
}

/// A 32-page demand segment loads with nothing resident and nothing but
/// headers read; a first touch faults exactly that page in, reads its
/// bytes once, and serves the file's content — while untouched pages
/// stay out, and re-faulting a resident page reads nothing.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_execve_pagein_demand_segment_faults_on_first_touch() -> TestResult {
    with_loaded(build_exec_elf(32, 32, 32), |proc| {
        assert_unbacked(&proc.address_space, SEG_VA, 0)?;
        assert_unbacked(&proc.address_space, SEG_VA, 31)?;
        let before = READ_BYTES.load(Ordering::Relaxed);
        if before == 0 {
            return Err("nothing was read at all — the image cannot have parsed");
        }
        if before >= PAGE {
            return Err("the load already read a segment page — the image is not demand-paged");
        }
        if fault_page(&proc.address_space, SEG_VA).is_err() {
            return Err("first touch did not fault the page in");
        }
        if READ_BYTES.load(Ordering::Relaxed) - before != PAGE {
            return Err("the first touch read more or less than one page");
        }
        assert_backed(&proc.address_space, SEG_VA, 0)?;
        assert_unbacked(&proc.address_space, SEG_VA, 1)?;
        if mapped_bytes(&proc.address_space, SEG_VA, PAGE as usize)?
            != alloc::vec![0x41u8; PAGE as usize]
        {
            return Err("the faulted page does not serve the file's bytes");
        }
        // A distant page faults in independently; untouched pages stay out.
        if fault_page(&proc.address_space, SEG_VA + 31 * PAGE).is_err() {
            return Err("a later page did not fault in on first touch");
        }
        assert_backed(&proc.address_space, SEG_VA, 31)?;
        assert_unbacked(&proc.address_space, SEG_VA, 30)?;
        if mapped_bytes(&proc.address_space, SEG_VA + 31 * PAGE, PAGE as usize)?
            != alloc::vec![0x41u8.wrapping_add(31); PAGE as usize]
        {
            return Err("the last faulted page does not serve the file's bytes");
        }
        // Re-faulting a resident page reads nothing: the fault is a pure
        // accelerator over pages already resident.
        let before = READ_BYTES.load(Ordering::Relaxed);
        if fault_page(&proc.address_space, SEG_VA).is_err() {
            return Err("re-faulting a resident page failed");
        }
        if READ_BYTES.load(Ordering::Relaxed) != before {
            return Err("re-faulting a resident page re-read it");
        }
        Ok(())
    })
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!(
    "syscall_abi/execve_pagein/demand_segment_faults_on_first_touch",
    smoke_execve_pagein_demand_segment_faults_on_first_touch
);

/// A 400-page segment loads with nothing resident: there is no eager
/// page-in budget clamping the head any more, and a page anywhere in
/// the span faults in through the ordinary single-page path.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_execve_pagein_large_segment_faults_on_first_touch() -> TestResult {
    with_loaded(build_exec_elf(400, 400, 400), |proc| {
        assert_unbacked(&proc.address_space, SEG_VA, 0)?;
        assert_unbacked(&proc.address_space, SEG_VA, 255)?;
        assert_unbacked(&proc.address_space, SEG_VA, 256)?;
        assert_unbacked(&proc.address_space, SEG_VA, 399)?;
        if fault_page(&proc.address_space, SEG_VA + 300 * PAGE).is_err() {
            return Err("a page past the old budget no longer faults in on demand");
        }
        assert_backed(&proc.address_space, SEG_VA, 300)?;
        assert_unbacked(&proc.address_space, SEG_VA, 299)?;
        Ok(())
    })
}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
kernel_test_in!(
    "syscall_abi/execve_pagein/large_segment_faults_on_first_touch",
    smoke_execve_pagein_large_segment_faults_on_first_touch
);

/// A demand segment truncated after the headers still LOADS — the
/// deferred failure is today's documented demand behaviour — and a
/// present page still faults in, while a page past EOF refuses the
/// fault and stays unbacked: it will SIGBUS on touch, exactly as a
/// truncated `mmap`ped text segment does on Linux.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn smoke_execve_pagein_truncated_demand_defers_failure() -> TestResult {
    with_loaded(build_exec_elf(20, 32, 32), |proc| {
        if fault_page(&proc.address_space, SEG_VA).is_err() {
            return Err("a present truncated-segment page did not fault in");
        }
        assert_backed(&proc.address_space, SEG_VA, 0)?;
        assert_unbacked(&proc.address_space, SEG_VA, 20)?;
        if fault_page(&proc.address_space, SEG_VA + 20 * PAGE).is_ok() {
            return Err("a page past EOF faulted in");
        }
        assert_unbacked(&proc.address_space, SEG_VA, 20)?;
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
/// demand paging existed. Dropping the eager page-in must never
/// convert a synchronous ENOEXEC into a deferred fault.
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

/// FS-backed interpreter: the kernel neither relocates it nor slurps
/// it. The interpreter comes from a memfs mounted ONLY in a private
/// namespace (the smoke-5f pattern), the program names it via
/// PT_INTERP, and the load goes through the production
/// `load_user_process_with_root_file` path.
///
/// Witnesses, after the load:
///   a. The interpreter's text AND writable-data pages are NOT backed
///      — both demand-page now. The old code backed the writable
///      segment eagerly (for the relocation pass) and read the whole
///      file up front.
///   b. The RELA target slot still holds the file's marker bytes: the
///      kernel did not patch it. The old pass would have overwritten
///      it with ADDEND + bias.
///   c. Entry is the interpreter's entry at its (pinned) bias.
///
/// The byte-count half of (a) — "the file saw headers only" — is not
/// directly observable here: the interpreter is served by the VFS
/// (memfs has no read counter), not by the counting `FileOps`. The
/// read behaviour itself is the same `ExecSource::File` bounded range
/// reads the program-side counting tests above already prove; what
/// this test pins is the observable consequence on the FS path: no
/// eager backing, no patched slot.
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "container"
))]
use crate::syscall::{SyscallArgs, SyscallReturn, TrapContext};

/// Pinned interpreter base: `UserAslrGuard::off()` holds the loader
/// to the canonical `INTERP_NOMINAL_BASE`.
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "container"
))]
const INTERP_BASE: u64 = 0x0000_4000_0000_0000;
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "container"
))]
const INTERP_TEXT_VA: u64 = 0x1000;
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "container"
))]
const INTERP_DATA_VA: u64 = 0x11000;
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "container"
))]
const RELA_SLOT_VA: u64 = 0x11100;
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "container"
))]
const INTERP_ENTRY: u64 = 0x1234;
/// The RELA slot's pre-relocation content in the file. The old kernel
/// pass would have overwritten it with `RELA_ADDEND + INTERP_BASE`.
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "container"
))]
const SLOT_MARKER: u64 = 0xDEAD_BEEF_DEAD_BEEF;

#[cfg(target_arch = "x86_64")]
#[cfg(feature = "container")]
const RELA_RELATIVE: u64 = 8; // R_X86_64_RELATIVE
#[cfg(target_arch = "aarch64")]
#[cfg(feature = "container")]
const RELA_RELATIVE: u64 = 1027; // R_AARCH64_RELATIVE

/// Minimal TrapContext for the `unshare(CLONE_NEWNS)` call — the
/// mount-smoke pattern, local so this file does not depend on
/// `mount_e2e_tests`'s private helpers.
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "container"
))]
struct NsStubCtx {
    args: SyscallArgs,
    ret: Option<SyscallReturn>,
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "container"
))]
impl TrapContext for NsStubCtx {
    fn args(&self) -> &SyscallArgs {
        &self.args
    }
    fn set_return(&mut self, r: SyscallReturn) {
        self.ret = Some(r);
    }
    fn user_rsp(&self) -> u64 {
        0
    }
    fn rip(&self) -> u64 {
        0
    }
    fn set_rip(&mut self, _rip: u64) {}
    fn redirect_to_kernel(&mut self, _rip: u64, _rsp: u64) -> bool {
        false
    }
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "container"
))]
fn ns_flags_args(flags: u64) -> SyscallArgs {
    SyscallArgs {
        arg0: flags,
        ..Default::default()
    }
}

/// Synthetic ET_DYN interpreter: 16-page R-X text, 16-page R-W data
/// (both at/above the 64 KiB demand floor, so both demand-page), one
/// PT_DYNAMIC page carrying a single RELATIVE RELA entry against a
/// slot in the data segment. File size 0x22000.
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "container"
))]
fn build_interp_elf() -> alloc::vec::Vec<u8> {
    const TEXT_OFF: usize = 0x1000;
    const DATA_OFF: usize = 0x11000;
    const DYN_OFF: usize = 0x21000;
    const RELA_OFF: usize = 0x21100;
    const SLOT_OFF: usize = 0x11100;
    const ADDEND: u64 = 0x1122_3344_5566_7788;

    let mut b = alloc::vec![0u8; 0x22000];
    b[..16].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    b[0x10..0x12].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
    b[0x12..0x14].copy_from_slice(&EM_NATIVE.to_le_bytes());
    b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    b[0x18..0x20].copy_from_slice(&INTERP_ENTRY.to_le_bytes()); // e_entry
    b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    b[0x34..0x36].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    b[0x38..0x3A].copy_from_slice(&3u16.to_le_bytes()); // e_phnum
                                                        // Phdr 0: PT_LOAD R+X text, 16 pages.
    let ph = 64usize;
    b[ph..ph + 0x04].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    b[ph + 0x04..ph + 0x08].copy_from_slice(&5u32.to_le_bytes()); // PF_R|PF_X
    b[ph + 0x08..ph + 0x10].copy_from_slice(&(TEXT_OFF as u64).to_le_bytes());
    b[ph + 0x10..ph + 0x18].copy_from_slice(&INTERP_TEXT_VA.to_le_bytes());
    b[ph + 0x18..ph + 0x20].copy_from_slice(&INTERP_TEXT_VA.to_le_bytes());
    b[ph + 0x20..ph + 0x28].copy_from_slice(&(16 * PAGE).to_le_bytes());
    b[ph + 0x28..ph + 0x30].copy_from_slice(&(16 * PAGE).to_le_bytes());
    b[ph + 0x30..ph + 0x38].copy_from_slice(&PAGE.to_le_bytes());
    // Phdr 1: PT_LOAD R+W data, 16 pages.
    let ph = 64 + 56;
    b[ph..ph + 0x04].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    b[ph + 0x04..ph + 0x08].copy_from_slice(&6u32.to_le_bytes()); // PF_R|PF_W
    b[ph + 0x08..ph + 0x10].copy_from_slice(&(DATA_OFF as u64).to_le_bytes());
    b[ph + 0x10..ph + 0x18].copy_from_slice(&INTERP_DATA_VA.to_le_bytes());
    b[ph + 0x18..ph + 0x20].copy_from_slice(&INTERP_DATA_VA.to_le_bytes());
    b[ph + 0x20..ph + 0x28].copy_from_slice(&(16 * PAGE).to_le_bytes());
    b[ph + 0x28..ph + 0x30].copy_from_slice(&(16 * PAGE).to_le_bytes());
    b[ph + 0x30..ph + 0x38].copy_from_slice(&PAGE.to_le_bytes());
    // Phdr 2: PT_DYNAMIC, one page.
    let ph = 64 + 112;
    b[ph..ph + 0x04].copy_from_slice(&2u32.to_le_bytes()); // PT_DYNAMIC
    b[ph + 0x04..ph + 0x08].copy_from_slice(&4u32.to_le_bytes()); // PF_R
    b[ph + 0x08..ph + 0x10].copy_from_slice(&(DYN_OFF as u64).to_le_bytes());
    b[ph + 0x10..ph + 0x18].copy_from_slice(&0x21000u64.to_le_bytes());
    b[ph + 0x18..ph + 0x20].copy_from_slice(&0x21000u64.to_le_bytes());
    b[ph + 0x20..ph + 0x28].copy_from_slice(&PAGE.to_le_bytes());
    b[ph + 0x28..ph + 0x30].copy_from_slice(&PAGE.to_le_bytes());
    b[ph + 0x30..ph + 0x38].copy_from_slice(&8u64.to_le_bytes());
    // .dynamic entries: DT_RELA, DT_RELASZ, DT_RELAENT, DT_NULL.
    b[DYN_OFF..DYN_OFF + 8].copy_from_slice(&7i64.to_le_bytes());
    b[DYN_OFF + 8..DYN_OFF + 16].copy_from_slice(&0x21100u64.to_le_bytes());
    b[DYN_OFF + 16..DYN_OFF + 24].copy_from_slice(&8i64.to_le_bytes());
    b[DYN_OFF + 24..DYN_OFF + 32].copy_from_slice(&24u64.to_le_bytes());
    b[DYN_OFF + 32..DYN_OFF + 40].copy_from_slice(&9i64.to_le_bytes());
    b[DYN_OFF + 40..DYN_OFF + 48].copy_from_slice(&24u64.to_le_bytes());
    b[DYN_OFF + 48..DYN_OFF + 56].copy_from_slice(&0i64.to_le_bytes());
    b[DYN_OFF + 56..DYN_OFF + 64].copy_from_slice(&0u64.to_le_bytes());
    // The one RELA entry: RELATIVE against the data slot.
    b[RELA_OFF..RELA_OFF + 8].copy_from_slice(&RELA_SLOT_VA.to_le_bytes());
    b[RELA_OFF + 8..RELA_OFF + 16].copy_from_slice(&RELA_RELATIVE.to_le_bytes());
    b[RELA_OFF + 16..RELA_OFF + 24].copy_from_slice(&ADDEND.to_le_bytes());
    // The slot's pre-relocation content.
    b[SLOT_OFF..SLOT_OFF + 8].copy_from_slice(&SLOT_MARKER.to_le_bytes());
    // Text page 0 carries a recognizable byte.
    b[TEXT_OFF..TEXT_OFF + PAGE as usize].fill(0xCC);
    b
}

/// Synthetic ET_EXEC program: one PT_LOAD R+X page at `SEG_VA` plus
/// PT_INTERP naming the mounted interpreter.
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "container"
))]
fn build_interp_program_elf() -> alloc::vec::Vec<u8> {
    const INTERP_STR_OFF: usize = 0x200;
    let mut b = alloc::vec![0u8; 0x2000];
    b[..16].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    b[0x10..0x12].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    b[0x12..0x14].copy_from_slice(&EM_NATIVE.to_le_bytes());
    b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    b[0x18..0x20].copy_from_slice(&(SEG_VA + 0x100).to_le_bytes()); // e_entry
    b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    b[0x34..0x36].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    b[0x38..0x3A].copy_from_slice(&2u16.to_le_bytes()); // e_phnum
                                                        // Phdr 0: PT_LOAD R+X at SEG_VA.
    let ph = 64usize;
    b[ph..ph + 0x04].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    b[ph + 0x04..ph + 0x08].copy_from_slice(&5u32.to_le_bytes()); // PF_R|PF_X
    b[ph + 0x08..ph + 0x10].copy_from_slice(&SEG_FOFF.to_le_bytes());
    b[ph + 0x10..ph + 0x18].copy_from_slice(&SEG_VA.to_le_bytes());
    b[ph + 0x18..ph + 0x20].copy_from_slice(&SEG_VA.to_le_bytes());
    b[ph + 0x20..ph + 0x28].copy_from_slice(&PAGE.to_le_bytes());
    b[ph + 0x28..ph + 0x30].copy_from_slice(&PAGE.to_le_bytes());
    b[ph + 0x30..ph + 0x38].copy_from_slice(&PAGE.to_le_bytes());
    // Phdr 1: PT_INTERP naming the mounted interpreter.
    let ph = 64 + 56;
    b[ph..ph + 0x04].copy_from_slice(&3u32.to_le_bytes()); // PT_INTERP
    b[ph + 0x04..ph + 0x08].copy_from_slice(&4u32.to_le_bytes()); // PF_R
    b[ph + 0x08..ph + 0x10].copy_from_slice(&(INTERP_STR_OFF as u64).to_le_bytes());
    b[ph + 0x10..ph + 0x18].copy_from_slice(&(INTERP_STR_OFF as u64).to_le_bytes());
    b[ph + 0x18..ph + 0x20].copy_from_slice(&(INTERP_STR_OFF as u64).to_le_bytes());
    b[ph + 0x20..ph + 0x28].copy_from_slice(&16u64.to_le_bytes());
    b[ph + 0x28..ph + 0x30].copy_from_slice(&16u64.to_le_bytes());
    b[ph + 0x30..ph + 0x38].copy_from_slice(&1u64.to_le_bytes());
    b[INTERP_STR_OFF..INTERP_STR_OFF + 16].copy_from_slice(b"/pxinterp/ld.so\0");
    b[SEG_FOFF as usize..SEG_FOFF as usize + PAGE as usize].fill(0x41);
    b
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "container"
))]
fn smoke_execve_fs_interp_not_relocated_nor_slurped() -> TestResult {
    // Harness fresh view (resets namespaces, installs the task-id
    // lookup); pair with teardown() on every exit path.
    setup();
    let _aslr = crate::tests::UserAslrGuard::off();
    // Every exit runs the namespace cleanup + teardown.
    let finish = |verdict: TestResult| -> TestResult {
        crate::handlers::clear_current_mount_namespace_for_test();
        crate::handlers::__test_root_dir_reset();
        crate::handlers::__test_cwd_reset();
        teardown();
        verdict
    };
    set_task(0x71_e1);
    crate::handlers::__test_root_dir_reset();
    crate::handlers::__test_cwd_reset();
    crate::handlers::clear_current_mount_namespace_for_test();

    const CLONE_NEWNS: u64 = 0x0002_0000;
    narf_filesystem::__test_ensure_mount_target("/");
    let mut uctx = NsStubCtx {
        args: ns_flags_args(CLONE_NEWNS),
        ret: None,
    };
    crate::handlers::sys_unshare(&mut uctx);
    if !matches!(uctx.ret, Some(r) if r.value == 0) {
        return finish(TestResult::Fail("unshare(CLONE_NEWNS) failed"));
    }
    // A memfs ld.so mounted ONLY in the private namespace.
    let interp = build_interp_elf();
    let fs: Arc<dyn narf_filesystem::FsInstance> = Arc::new(narf_filesystem::MemFs::with_seeds(
        "pxld",
        &[("ld.so", interp.as_slice())],
    ));
    let auth = narf_filesystem::bootstrap_mount_authority();
    if crate::handlers::current_mount_arc(&auth, "/pxinterp", fs).is_err() {
        return finish(TestResult::Fail("private mount of /pxinterp failed"));
    }
    let proc = match try_load(build_interp_program_elf()) {
        Ok(p) => p,
        Err(_) => return finish(TestResult::Fail("file-sourced load with FS interp failed")),
    };
    *PAGEIN_AS.lock() = Some(Arc::clone(&proc.address_space));
    crate::handlers::install_address_space_lookup(lookup_pagein_as);
    let verdict = (|| {
        // (c) Entry is the interpreter's entry at its (pinned) bias.
        if proc.entry.0.raw() != INTERP_BASE + INTERP_ENTRY {
            return Err("entry is not the interpreter entry at its bias");
        }
        // (a) The interpreter's pages are NOT backed after load: text
        // and writable data alike demand-page. The old code backed the
        // writable segment eagerly (for the relocation pass) and read
        // the whole file up front.
        assert_unbacked(&proc.address_space, INTERP_BASE + INTERP_TEXT_VA, 0)?;
        assert_unbacked(&proc.address_space, INTERP_BASE + INTERP_DATA_VA, 0)?;
        // (b) Fault the page holding the RELA target in and read the
        // slot: it still holds the file's marker. The old kernel pass
        // would have overwritten it with ADDEND + bias.
        if fault_page(&proc.address_space, INTERP_BASE + RELA_SLOT_VA).is_err() {
            return Err("the RELA slot page did not fault in on first touch");
        }
        assert_backed(&proc.address_space, INTERP_BASE + INTERP_DATA_VA, 0)?;
        if mapped_bytes(&proc.address_space, INTERP_BASE + RELA_SLOT_VA, 8)?
            != SLOT_MARKER.to_le_bytes()
        {
            return Err("the RELA slot was patched — the kernel relocation pass ran");
        }
        Ok(())
    })();
    crate::handlers::restore_address_space_lookup(None);
    *PAGEIN_AS.lock() = None;
    let pid = proc.pid;
    drop(proc);
    crate::release_pid(pid);
    finish(match verdict {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    })
}
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "container"
))]
kernel_test_in!(
    "syscall_abi/execve_pagein/fs_interp_not_relocated_nor_slurped",
    smoke_execve_fs_interp_not_relocated_nor_slurped
);
