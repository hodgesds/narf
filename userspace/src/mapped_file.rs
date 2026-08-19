//! Lifetime tracking for `MAP_SHARED` file/device mappings.
//!
//! Address-space regions store physical frames but intentionally do not depend
//! on filesystem objects. Keep the backing open-file description alive here
//! until the last process mapping disappears, matching Linux's VMA-held file
//! reference without adding a filesystem dependency to the memory TCB.
//!
//! That reference is **load-bearing for memory safety**, not only for
//! writeback. A file whose frames are aliased into userspace `MAP_SHARED` —
//! `mmap_frames` or `mmap_fault` — must outlive every mapping of them, or
//! teardown returns user-mapped frames to the buddy and userspace keeps a
//! writable window onto whatever is allocated next. `/dev/fb0` and perf's ring
//! are accidentally safe (device memory that is never in the buddy; a ring
//! that lives as long as the task); a BPF arena is not, which is what turned
//! this table from bookkeeping into the thing that makes `Arena::drop` sound.
//! `memory/src/bpf_arena.rs`'s `Arena::drop` names the test that pins it.

use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_filesystem::FileOps;
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::PhysAddr;

#[derive(Clone)]
struct FileWriteback {
    offset: u64,
    phys: Vec<PhysAddr>,
}

struct MappingOwner {
    pid: u64,
    base: u64,
    len: u64,
    /// File offset of `base`. Needed by [`demand_frame`] to turn a faulting
    /// address back into the file offset `FileOps::mmap_fault` expects, and
    /// therefore adjusted wherever `base` moves (`punch`).
    file_offset: u64,
    ops: Arc<dyn FileOps>,
    /// Ordinary file MAP_SHARED mappings use private physical frames as a
    /// fallback when the filesystem cannot expose cache pages directly. Keep
    /// their frame list so fsync/msync can copy dirty bytes back to FileOps.
    /// Device mappings leave this `None`: they already alias device memory.
    writeback: Option<FileWriteback>,
}

static MAPPING_OWNERS: IrqSafeSpinLock<Vec<MappingOwner>> = IrqSafeSpinLock::new(Vec::new());

/// Physical file-cache pages for generic `MAP_SHARED` fallbacks. A filesystem
/// which cannot directly expose its own page-cache frames still needs one
/// backing page per `(open file description, file offset)`: otherwise two
/// overlapping mappings diverge and the last writeback can overwrite a newer
/// change through the other mapping.
struct SharedFilePage {
    ops: Arc<dyn FileOps>,
    offset: u64,
    phys: PhysAddr,
    mappings: usize,
    /// Exact bytes last read from, or successfully written to, the backing
    /// file. Generic mappings cannot rely on hardware dirty bits here, so an
    /// exact snapshot lets fsync skip clean pages without risking a hash
    /// collision that could lose a write.
    clean: Vec<u8>,
}

static SHARED_FILE_PAGES: IrqSafeSpinLock<Vec<SharedFilePage>> = IrqSafeSpinLock::new(Vec::new());

fn current_pid() -> u64 {
    let task = crate::handlers::current_task_id();
    crate::handlers::task_to_pid_raw(task).unwrap_or(task)
}

pub(crate) fn register_current(base: u64, len: u64, offset: u64, ops: Arc<dyn FileOps>) {
    register(current_pid(), base, len, offset, ops, None);
}

/// Resolve a fault on a demand-paged `MAP_SHARED` mapping to the frame its
/// backing file wants at `vaddr`.
///
/// Installed into `narf-memory` as the `RegionPerms::FILE_DEMAND` hook (see
/// `sys_mmap`), which is why this lives with the mapping owners rather than
/// with the syscall: the owner table is already the thing that knows which
/// file a user address belongs to, and it is the reference that keeps that
/// file alive while the mapping exists.
///
/// The lock is dropped before entering the file. `FileOps::mmap_fault` may
/// allocate and take its own locks — a BPF arena installs a kernel page-table
/// entry inside it — and holding `MAPPING_OWNERS` across that would put this
/// lock beneath every lock any demand-pageable file might take, on a path
/// entered from the page-fault handler.
pub(crate) fn demand_frame(vaddr: u64) -> Option<u64> {
    let page = vaddr & !0xFFFu64;
    let pid = current_pid();
    let (offset, ops) = {
        let owners = MAPPING_OWNERS.lock();
        let owner = owners.iter().find(|mapping| {
            mapping.pid == pid
                && page >= mapping.base
                && page < mapping.base.saturating_add(mapping.len)
        })?;
        (
            owner.file_offset.checked_add(page - owner.base)?,
            Arc::clone(&owner.ops),
        )
    };
    ops.mmap_fault(offset).ok()
}

/// Register a file-backed shared mapping whose frames must be written back on
/// `fsync(2)` / `msync(2)`. Filesystems that expose their own physical cache
/// pages continue through `register_current` above and need no copying.
pub(crate) fn register_file_current(
    base: u64,
    len: u64,
    offset: u64,
    ops: Arc<dyn FileOps>,
    phys: Vec<PhysAddr>,
) {
    register(
        current_pid(),
        base,
        len,
        offset,
        ops,
        Some(FileWriteback { offset, phys }),
    );
}

/// Publish freshly loaded fallback pages into the process-independent file
/// page cache. A concurrent/overlapping mapper may already have published a
/// page; in that case use its physical page and return the unused allocation
/// to the frame allocator.
pub(crate) fn publish_shared_file_pages(
    ops: &Arc<dyn FileOps>,
    offset: u64,
    candidates: Vec<PhysAddr>,
) -> Vec<PhysAddr> {
    let mut rejected = Vec::new();
    let mut canonical = Vec::with_capacity(candidates.len());
    {
        let mut pages = SHARED_FILE_PAGES.lock();
        for (index, candidate) in candidates.into_iter().enumerate() {
            let page_offset = offset.saturating_add(index as u64 * 4096);
            if let Some(existing) = pages
                .iter()
                .find(|page| page.offset == page_offset && Arc::ptr_eq(&page.ops, ops))
            {
                canonical.push(existing.phys);
                if candidate.raw() != existing.phys.raw() {
                    rejected.push(candidate);
                }
            } else {
                // SAFETY: `candidate` is a freshly allocated, identity-mapped
                // fallback page which remains owned by this cache entry.
                let clean = unsafe {
                    core::slice::from_raw_parts(candidate.raw() as *const u8, 4096).to_vec()
                };
                pages.push(SharedFilePage {
                    ops: Arc::clone(ops),
                    offset: page_offset,
                    phys: candidate,
                    mappings: 0,
                    clean,
                });
                canonical.push(candidate);
            }
        }
    }
    for phys in rejected {
        if phys.raw() != 0 {
            narf_memory::free_frame(narf_memory::PhysFrame::new(phys));
        }
    }
    canonical
}

/// Abandon cache pages which were published just before a failed map attempt.
/// Existing pages remain retained by their live mappings; only entries with no
/// mapping references are reclaimed.
pub(crate) fn discard_unmapped_shared_file_pages(phys: &[PhysAddr]) {
    let mut free = Vec::new();
    {
        let mut pages = SHARED_FILE_PAGES.lock();
        let old = core::mem::take(&mut *pages);
        for page in old {
            if page.mappings == 0 && phys.contains(&page.phys) {
                free.push(page.phys);
            } else {
                pages.push(page);
            }
        }
    }
    for phys in free {
        narf_memory::free_frame(narf_memory::PhysFrame::new(phys));
    }
}

/// Memory's `RegionPerms::SHARED` hooks call these to tie each mapped alias to
/// the fallback page cache's lifetime. Return false for non-file-cache pages
/// so the System V shared-memory registry can handle them instead.
pub(crate) fn retain_shared_file_page(phys: u64) -> bool {
    let mut pages = SHARED_FILE_PAGES.lock();
    let Some(page) = pages.iter_mut().find(|page| page.phys.raw() == phys) else {
        return false;
    };
    page.mappings = page.mappings.saturating_add(1);
    true
}

pub(crate) fn release_shared_file_page(phys: u64) -> bool {
    let page = {
        let mut pages = SHARED_FILE_PAGES.lock();
        let Some(index) = pages.iter().position(|page| page.phys.raw() == phys) else {
            return false;
        };
        let page = &mut pages[index];
        page.mappings = page.mappings.saturating_sub(1);
        if page.mappings != 0 {
            return true;
        }
        pages.swap_remove(index)
    };
    narf_memory::free_frame(narf_memory::PhysFrame::new(page.phys));
    true
}

fn register(
    pid: u64,
    base: u64,
    len: u64,
    file_offset: u64,
    ops: Arc<dyn FileOps>,
    writeback: Option<FileWriteback>,
) {
    MAPPING_OWNERS.lock().push(MappingOwner {
        pid,
        base,
        len,
        file_offset,
        ops,
        writeback,
    });
}

pub(crate) fn unmap_current(base: u64) {
    let pid = current_pid();
    MAPPING_OWNERS
        .lock()
        .retain(|mapping| mapping.pid != pid || mapping.base != base);
}

/// Mirror `AddressSpace::punch_fixed` splitting for owner references.
pub(crate) fn punch_current(base: u64, len: u64) {
    punch(current_pid(), base, len);
}

fn punch(pid: u64, base: u64, len: u64) {
    let Some(end) = base.checked_add(len) else {
        return;
    };
    let mut owners = MAPPING_OWNERS.lock();
    let old = core::mem::take(&mut *owners);
    for mut mapping in old {
        if mapping.pid != pid {
            owners.push(mapping);
            continue;
        }
        let Some(mapping_end) = mapping.base.checked_add(mapping.len) else {
            continue;
        };
        if mapping_end <= base || mapping.base >= end {
            owners.push(mapping);
            continue;
        }
        if mapping.base < base {
            let original_base = mapping.base;
            let suffix = if mapping_end > end {
                let mut suffix = MappingOwner {
                    pid,
                    base: end,
                    len: mapping_end - end,
                    // The suffix starts `end - original_base` further into the
                    // file, exactly as its writeback offset below does. A
                    // stale offset here would fault the wrong page of the file
                    // into the surviving half of a punched mapping.
                    file_offset: mapping.file_offset.saturating_add(end - original_base),
                    ops: Arc::clone(&mapping.ops),
                    writeback: mapping.writeback.clone(),
                };
                if let Some(wb) = suffix.writeback.as_mut() {
                    let skip = ((end - original_base) / 4096) as usize;
                    wb.offset = wb.offset.saturating_add(end - original_base);
                    wb.phys = wb.phys.get(skip..).unwrap_or_default().to_vec();
                }
                Some(suffix)
            } else {
                None
            };
            mapping.len = base - mapping.base;
            if let Some(wb) = mapping.writeback.as_mut() {
                wb.phys.truncate((mapping.len / 4096) as usize);
            }
            owners.push(mapping);
            if let Some(suffix) = suffix {
                owners.push(suffix);
            }
        } else if mapping_end > end {
            let skipped = end - mapping.base;
            mapping.base = end;
            mapping.len = mapping_end - end;
            mapping.file_offset = mapping.file_offset.saturating_add(skipped);
            if let Some(wb) = mapping.writeback.as_mut() {
                let pages = (skipped / 4096) as usize;
                wb.offset = wb.offset.saturating_add(skipped);
                wb.phys = wb.phys.get(pages..).unwrap_or_default().to_vec();
            }
            owners.push(mapping);
        }
    }
}

pub(crate) fn fork_process(parent_pid: u64, child_pid: u64) {
    let mut owners = MAPPING_OWNERS.lock();
    let inherited: Vec<_> = owners
        .iter()
        .filter(|mapping| mapping.pid == parent_pid)
        .map(|mapping| MappingOwner {
            pid: child_pid,
            base: mapping.base,
            len: mapping.len,
            file_offset: mapping.file_offset,
            ops: Arc::clone(&mapping.ops),
            writeback: mapping.writeback.clone(),
        })
        .collect();
    owners.extend(inherited);
}

pub(crate) fn process_exit(pid: u64, _tid: u64) {
    MAPPING_OWNERS.lock().retain(|mapping| mapping.pid != pid);
}

fn owner_count(pid: u64) -> usize {
    MAPPING_OWNERS
        .lock()
        .iter()
        .filter(|mapping| mapping.pid == pid)
        .count()
}

/// Commit all fallback `MAP_SHARED` pages of `ops` in the current process.
/// The kernel copies one page at a time before awaiting FileOps::write, so no
/// IRQ-safe mapping lock spans filesystem I/O and an unmap racing this flush
/// cannot free a page before its bytes have been snapshotted.
pub(crate) fn flush_current_file(ops: &Arc<dyn FileOps>) -> Result<(), ()> {
    let pid = current_pid();
    let mappings: Vec<FileWriteback> = MAPPING_OWNERS
        .lock()
        .iter()
        .filter(|mapping| mapping.pid == pid && Arc::ptr_eq(&mapping.ops, ops))
        .filter_map(|mapping| mapping.writeback.clone())
        .collect();
    flush_mappings(ops, mappings)
}

/// Commit the current process's fallback shared mappings overlapping
/// `[base, base + len)`. `msync` uses this range form; a zero length follows
/// Linux's no-op convention.
pub(crate) fn flush_current_range(base: u64, len: u64) -> Result<(), ()> {
    if len == 0 {
        return Ok(());
    }
    let Some(end) = base.checked_add(len) else {
        return Err(());
    };
    let pid = current_pid();
    let mappings: Vec<(Arc<dyn FileOps>, FileWriteback)> = MAPPING_OWNERS
        .lock()
        .iter()
        .filter(|mapping| mapping.pid == pid)
        .filter(|mapping| mapping.base < end && base < mapping.base.saturating_add(mapping.len))
        .filter_map(|mapping| {
            mapping
                .writeback
                .clone()
                .map(|wb| (Arc::clone(&mapping.ops), wb))
        })
        .collect();
    for (ops, mapping) in mappings {
        flush_mappings(&ops, alloc::vec![mapping])?;
    }
    Ok(())
}

fn flush_mappings(ops: &Arc<dyn FileOps>, mappings: Vec<FileWriteback>) -> Result<(), ()> {
    for mapping in mappings {
        for (index, phys) in mapping.phys.iter().enumerate() {
            if phys.raw() == 0 {
                continue;
            }
            let offset = mapping.offset + (index as u64) * 4096;
            let file_len = ops.stat().size;
            if offset >= file_len {
                continue;
            }
            let len = ((file_len - offset) as usize).min(4096);
            let Some(bytes) = snapshot_dirty_page(ops, offset, *phys, len) else {
                continue;
            };
            let mut done = 0;
            while done < bytes.len() {
                match crate::handlers::poll_io_to_completion(
                    ops.write(offset + done as u64, &bytes[done..]),
                ) {
                    Some(Ok(0)) | Some(Err(_)) | None => return Err(()),
                    Some(Ok(n)) => done += n,
                }
            }
            mark_page_clean(ops, offset, *phys, &bytes);
        }
    }
    Ok(())
}

/// Snapshot a fallback page only when it differs from the last file image.
/// Holding the cache lock pins the page against final-unmap reclamation while
/// its bytes are copied; filesystem I/O starts only after the lock is dropped.
fn snapshot_dirty_page(
    ops: &Arc<dyn FileOps>,
    offset: u64,
    phys: PhysAddr,
    len: usize,
) -> Option<Vec<u8>> {
    let pages = SHARED_FILE_PAGES.lock();
    let page = pages
        .iter()
        .find(|page| page.offset == offset && page.phys == phys && Arc::ptr_eq(&page.ops, ops))?;
    // SAFETY: the cache entry owns `phys`; the cache lock prevents its last
    // mapping release from removing and freeing the entry during this copy.
    let current = unsafe { core::slice::from_raw_parts(phys.raw() as *const u8, len) };
    if page.clean.get(..len) == Some(current) {
        None
    } else {
        Some(current.to_vec())
    }
}

/// Advance the exact clean image only after the whole page write succeeds.
/// If userspace changes the mapped page during I/O, the stored snapshot still
/// describes what reached the file, so the next fsync observes it as dirty.
fn mark_page_clean(ops: &Arc<dyn FileOps>, offset: u64, phys: PhysAddr, bytes: &[u8]) {
    let mut pages = SHARED_FILE_PAGES.lock();
    if let Some(page) = pages
        .iter_mut()
        .find(|page| page.offset == offset && page.phys == phys && Arc::ptr_eq(&page.ops, ops))
    {
        page.clean[..bytes.len()].copy_from_slice(bytes);
    }
}

mod tests {
    use super::*;
    use alloc::boxed::Box;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use narf_filesystem::{FsFuture, Mode, Stat};
    use narf_kernel_test::{kernel_test_in, TestResult};

    static DROPS: AtomicUsize = AtomicUsize::new(0);

    struct TestOwner;

    impl Drop for TestOwner {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl FileOps for TestOwner {
        fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
            Box::pin(async { Ok(0) })
        }

        fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
            Box::pin(async move { Ok(buf.len()) })
        }

        fn stat(&self) -> Stat {
            Stat {
                size: 0,
                blocks: 0,
                mode: Mode::FILE_RW,
                mtime_cycles: 0,
            }
        }
    }

    fn smoke_mapped_file_owner_lifecycle() -> TestResult {
        const PARENT: u64 = u64::MAX - 20;
        const CHILD: u64 = u64::MAX - 19;
        process_exit(PARENT, PARENT);
        process_exit(CHILD, CHILD);
        DROPS.store(0, Ordering::Relaxed);

        let owner: Arc<dyn FileOps> = Arc::new(TestOwner);
        register(PARENT, 0x1000, 0x3000, 0, Arc::clone(&owner), None);
        drop(owner);
        if DROPS.load(Ordering::Relaxed) != 0 || owner_count(PARENT) != 1 {
            return TestResult::Fail("mapping did not retain its file owner");
        }

        fork_process(PARENT, CHILD);
        if owner_count(CHILD) != 1 {
            return TestResult::Fail("fork did not inherit the mapping owner");
        }

        // Punch the middle page: parent retains prefix + suffix references.
        punch(PARENT, 0x2000, 0x1000);
        if owner_count(PARENT) != 2 {
            return TestResult::Fail("MAP_FIXED punch did not split the mapping owner");
        }
        process_exit(PARENT, PARENT);
        if DROPS.load(Ordering::Relaxed) != 0 || owner_count(CHILD) != 1 {
            return TestResult::Fail("parent exit released an inherited mapping owner");
        }
        process_exit(CHILD, CHILD);
        if DROPS.load(Ordering::Relaxed) != 1 {
            return TestResult::Fail("last mapping did not release its file owner");
        }
        TestResult::Pass
    }

    kernel_test_in!("userspace/perf", smoke_mapped_file_owner_lifecycle);
}
