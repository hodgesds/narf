//! btrfs page-cache coherence matrix (#742): the scenarios FAT's
//! matrix pinned down, ported to btrfs's fixtures.
//!
//! * truncate-grow reads zeros (the #692 shape): btrfs grows by
//!   size only — the new range is holes, and its read path serves
//!   holes as zeros — so a grown range must fault and read back as
//!   zeros, never EIO or stale bytes. (The shrink-then-regrow
//!   interaction lives in `abi_truncate_unmap_tests`.)
//! * msync must not clobber `write(2)` (the #688 shape): after a
//!   `pwrite64` through a second open folds new bytes into the
//!   retained frame and its snapshot, an `msync` of the still-clean
//!   mapping must leave the written bytes on disk — and a store
//!   through the mapping followed by `msync(MS_SYNC)` must be what
//!   `read(2)` serves afterwards.

use alloc::sync::Arc;

use narf_filesystem::{FileOps, FsInstance};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::{AddressSpace, VirtAddr};

use crate::abi_test_support::*;

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_SHARED: u64 = 1;
const O_RDWR: u32 = 2;
const PAGE: u64 = 4096;
const MS_SYNC: u64 = 4;

static COH_AS: IrqSafeSpinLock<Option<Arc<AddressSpace>>> = IrqSafeSpinLock::new(None);

fn lookup_coh_as() -> Option<Arc<AddressSpace>> {
    COH_AS.lock().clone()
}

struct Fixture {
    /// The first open, read directly: the filesystem's own answer, with no
    /// file-cache overlay.
    ops1: Arc<dyn FileOps>,
    aspace: Arc<AddressSpace>,
    fd1: u64,
    fd2: u64,
}

fn install_fd(ops: &Arc<dyn FileOps>) -> Result<u64, &'static str> {
    crate::fd::install(
        FAKE_TASK,
        crate::fd::FdEntry {
            ops: Arc::clone(ops),
            offset: 0,
            flags: 0,
            status_flags: O_RDWR,
        },
    )
    .map(u64::from)
    .ok_or("installing the fd failed")
}

/// Mount the btrfs fixture with `narf.txt` seeded with `seed`, open it
/// twice, and run `body` against both fds in a fresh address space.
fn with_btrfs(seed: &[u8], body: impl FnOnce(&Fixture) -> Result<(), &'static str>) -> TestResult {
    with_setup(move || {
        // SAFETY: kernel tests run with paging enabled; the new root
        // inherits only the kernel half and is owned by this fixture.
        let aspace = match unsafe { AddressSpace::new_for_user() } {
            Ok(aspace) => Arc::new(aspace),
            Err(_) => return Err("failed to create the test address space"),
        };
        *COH_AS.lock() = Some(Arc::clone(&aspace));
        crate::handlers::install_address_space_lookup(lookup_coh_as);
        let result = (|| {
            let volume = crate::abi_fault_write_tests::btrfs_volume_with_file(seed)?;
            let open = || {
                crate::handlers::poll_io_to_completion(volume.root().lookup_async("narf.txt"))
                    .and_then(|r| r.ok())
                    .ok_or("lookup of narf.txt failed")
            };
            let ops1 = open()?;
            let ops2 = open()?;
            let fd1 = install_fd(&ops1)?;
            let fd2 = install_fd(&ops2)?;
            body(&Fixture {
                aspace,
                fd1,
                fd2,
                ops1: Arc::clone(&ops1),
            })
        })();
        crate::handlers::restore_address_space_lookup(None);
        *COH_AS.lock() = None;
        result
    })
}

fn map_shared(fd: u64, len: u64) -> Result<u64, &'static str> {
    let args = SyscallArgs {
        arg0: 0,
        arg1: len,
        arg2: PROT_READ | PROT_WRITE,
        arg3: MAP_SHARED,
        arg4: fd,
        arg5: 0,
    };
    match call(Syscall::Mmap.raw(), args) {
        Some(addr) if addr > 0 => Ok(addr as u64),
        _ => Err("MAP_SHARED mmap failed"),
    }
}

fn mapped_frame(aspace: &AddressSpace, va: u64) -> Option<u64> {
    let region = aspace.lookup(VirtAddr::new(va))?;
    let index = ((va & !(PAGE - 1)) - region.base.as_u64()) / PAGE;
    let phys = region.phys.get(index as usize)?.raw();
    (phys != 0).then_some(phys)
}

/// Fault `va` in and return the direct-map alias of its frame, the
/// way `abi_filemap_tests` drives mapped loads and stores.
fn fault(aspace: &AddressSpace, va: u64) -> Result<*mut u8, &'static str> {
    // SAFETY: `aspace` is a live user root and paging is enabled.
    unsafe { aspace.demand_alloc_page(VirtAddr::new(va)) }
        .map_err(|_| "a fault inside the file's EOF was refused")?;
    let phys = mapped_frame(aspace, va).ok_or("the fault left the page unbacked")?;
    Ok(narf_memory::PhysAddr::new(phys).kernel_mut_ptr::<u8>())
}

fn mapped_bytes(ptr: *const u8, len: usize) -> alloc::vec::Vec<u8> {
    // SAFETY: `ptr` is the direct-map alias of a frame the mapping holds.
    unsafe { core::slice::from_raw_parts(ptr, len).to_vec() }
}

fn store(ptr: *mut u8, bytes: &[u8]) {
    // A real store faults on the clean page's read-only PTE first and the
    // write-notify hook records it; through the direct map the test takes
    // that step itself.
    let page = narf_memory::PhysAddr::from_kernel_ptr(ptr).raw() & !0xFFF;
    crate::mapped_file::shared_page_write_fault(page);
    // SAFETY: as `mapped_bytes`; the frame stays mapped for the test.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len()) }
}

fn content(len: usize) -> alloc::vec::Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn ftruncate(fd: u64, len: u64) -> Result<(), &'static str> {
    match call(Syscall::Ftruncate.raw(), a1(fd, len)) {
        Some(0) => Ok(()),
        _ => Err("ftruncate failed"),
    }
}

fn pread(fd: u64, buf: &mut [u8], offset: u64) -> Result<(), &'static str> {
    match call(
        Syscall::Pread64.raw(),
        a3(fd, buf.as_mut_ptr() as u64, buf.len() as u64, offset),
    ) {
        Some(n) if n == buf.len() as i64 => Ok(()),
        _ => Err("pread was short or failed"),
    }
}

fn pwrite_page(fd: u64, offset: u64, byte: u8) -> Result<(), &'static str> {
    let buf = alloc::vec![byte; PAGE as usize];
    let args = SyscallArgs {
        arg0: fd,
        arg1: buf.as_ptr() as u64,
        arg2: PAGE,
        arg3: offset,
        arg4: 0,
        arg5: 0,
    };
    match call(Syscall::Pwrite64.raw(), args) {
        Some(n) if n == PAGE as i64 => Ok(()),
        _ => Err("pwrite64 failed or was short"),
    }
}

fn msync(addr: u64, len: u64) -> Result<(), &'static str> {
    match call(Syscall::Msync.raw(), a2(addr, len, MS_SYNC)) {
        Some(0) => Ok(()),
        _ => Err("msync(MS_SYNC) failed"),
    }
}

/// The #692 shape on btrfs: a small seeded file, `ftruncate` up to
/// three pages, and the grown range must fault in and read as zeros
/// while the seeded head is untouched.
fn smoke_btrfs_truncate_grow_reads_zeros() -> TestResult {
    with_btrfs(&content(100), |fx| {
        let base = map_shared(fx.fd1, 3 * PAGE)?;
        ftruncate(fx.fd1, 3 * PAGE)?;
        // The grown tail faults in as zeros (holes).
        let tail = fault(&fx.aspace, base + 2 * PAGE)?;
        if mapped_bytes(tail, PAGE as usize).iter().any(|&b| b != 0) {
            return Err("the grown range does not fault in as zeros");
        }
        let mut disk = alloc::vec![0xFFu8; PAGE as usize];
        pread(fx.fd2, &mut disk, 2 * PAGE)?;
        if disk.iter().any(|&b| b != 0) {
            return Err("the grown range does not read as zeros");
        }
        // The boundary page straddling the old EOF: seed, then zeros.
        let mid = fault(&fx.aspace, base + PAGE)?;
        if mapped_bytes(mid, PAGE as usize).iter().any(|&b| b != 0) {
            return Err("the boundary page of the grown range is not zeros");
        }
        let head = fault(&fx.aspace, base)?;
        if mapped_bytes(head, 100) != content(100) {
            return Err("grow damaged the file's seeded head bytes");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/coherence/btrfs",
    smoke_btrfs_truncate_grow_reads_zeros
);

/// The #688 shape on btrfs, two halves on two pages:
/// (a) fault page 0 in, `pwrite64` a full new page through the
///     second open, store *different* bytes through the mapping,
///     `msync` — `read(2)` must serve the stored bytes (the flush
///     wrote the frame, not a snapshot);
/// (b) fault page 1 in, `pwrite64` through the second open, `msync`
///     the still-clean mapping — `read(2)` must still serve the
///     written bytes (the clean snapshot must not clobber the fold).
fn smoke_btrfs_msync_does_not_clobber_write() -> TestResult {
    let seed = content(3 * PAGE as usize - 100);
    with_btrfs(&seed, |fx| {
        let base = map_shared(fx.fd1, 3 * PAGE)?;
        // (a) store + msync wins over the folded write.
        let p0 = fault(&fx.aspace, base)?;
        pwrite_page(fx.fd2, 0, 0xC3)?;
        store(p0, b"mapped-store-wins");
        msync(base, PAGE)?;
        let mut disk = alloc::vec![0u8; 32];
        pread(fx.fd2, &mut disk, 0)?;
        if &disk[..17] != b"mapped-store-wins" {
            return Err("msync did not flush the mapped store over the folded write");
        }
        if disk[17..].iter().any(|&b| b != 0xC3) {
            return Err("msync disturbed the folded bytes past the mapped store");
        }
        // (b) clean msync must not resurrect the seed over the fold.
        let _p1 = fault(&fx.aspace, base + PAGE)?;
        pwrite_page(fx.fd2, PAGE, 0x5A)?;
        msync(base + PAGE, PAGE)?;
        let mut disk1 = alloc::vec![0u8; PAGE as usize];
        pread(fx.fd2, &mut disk1, PAGE)?;
        if disk1.iter().any(|&b| b != 0x5A) {
            return Err("msync of a clean page clobbered the write(2) bytes");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/coherence/btrfs",
    smoke_btrfs_msync_does_not_clobber_write
);

fn munmap(addr: u64, len: u64) -> Result<(), &'static str> {
    match call(Syscall::Munmap.raw(), a2(addr, len, 0)) {
        Some(0) => Ok(()),
        _ => Err("munmap failed"),
    }
}

fn fsync(fd: u64) -> Result<(), &'static str> {
    match call(Syscall::Fsync.raw(), a1(fd, 0)) {
        Some(0) => Ok(()),
        _ => Err("fsync failed"),
    }
}

/// Store `byte` over `[from, to)` of the file through a fresh `MAP_SHARED`
/// mapping of `fd`, then unmap it: the integrity worker's one generation.
fn mapped_generation(
    fx: &Fixture,
    fd: u64,
    len: u64,
    from: u64,
    to: u64,
    byte: u8,
) -> Result<(), &'static str> {
    let base = map_shared(fd, len)?;
    let mut at = from;
    while at < to {
        let page_end = ((at / PAGE) + 1) * PAGE;
        let end = page_end.min(to);
        let ptr = fault(&fx.aspace, base + at)?;
        // `fault` returns the start of the page's frame.
        // SAFETY: `at % PAGE + (end - at) <= PAGE`, inside that frame.
        let ptr = unsafe { ptr.add((at % PAGE) as usize) };
        store(ptr, &alloc::vec![byte; (end - at) as usize]);
        at = end;
    }
    munmap(base, len)
}

/// `[at, at + len)` of the file read through `fd` holds only `byte`.
fn reads_as(fd: u64, at: u64, len: usize, byte: u8) -> Result<bool, &'static str> {
    let mut buf = alloc::vec![0u8; len];
    pread(fd, &mut buf, at)?;
    Ok(buf.iter().all(|b| *b == byte))
}

/// The soak integrity worker's mismatch, op for op (scaled down): store
/// 0x83 through one mapping, unmap, fsync; store 0x77 over an overlapping
/// range through a second mapping, unmap, no msync; then `pread` across the
/// second store. Linux returns 0x77 there every time. It must too: right
/// after the unmap (served from the dirty cache pages), after the cache has
/// written them back, through the open that wrote them and through another,
/// and after the cache has dropped them so a fresh mapping refaults them
/// from the filesystem.
fn smoke_btrfs_read_after_two_mapped_generations() -> TestResult {
    const LEN: u64 = 64 * PAGE;
    let seed = alloc::vec![0x11u8; LEN as usize];
    with_btrfs(&seed, |fx| {
        // Generation 1: 0x83 over [5.3 pages, 37.8 pages), then fsync.
        let (g1_from, g1_to) = (5 * PAGE + 1300, 37 * PAGE + 3300);
        mapped_generation(fx, fx.fd1, LEN, g1_from, g1_to, 0x83)?;
        fsync(fx.fd1)?;
        // Generation 2: 0x77 over [2.1 pages, 33.9 pages), no msync.
        let (g2_from, g2_to) = (2 * PAGE + 500, 33 * PAGE + 3700);
        mapped_generation(fx, fx.fd1, LEN, g2_from, g2_to, 0x77)?;
        // The read that straddles the end of generation 2.
        let (r_from, r_len) = (20 * PAGE + 123, (g2_to - (20 * PAGE + 123)) as usize);
        if !reads_as(fx.fd1, r_from, r_len, 0x77)? {
            return Err("pread right after munmap returned the older generation");
        }
        if !reads_as(fx.fd2, r_from, r_len, 0x77)? {
            return Err(
                "pread through another open right after munmap returned the older generation",
            );
        }
        // The cache writes generation 2 back, as the flusher would.
        let _ = crate::mapped_file::sync_all_files(None);
        if !reads_as(fx.fd1, r_from, r_len, 0x77)? {
            return Err("pread after writeback returned the older generation (same open)");
        }
        if !reads_as(fx.fd2, r_from, r_len, 0x77)? {
            return Err("pread after writeback returned the older generation (other open)");
        }
        // The cache lets go of the pages; a fresh mapping refaults them.
        crate::mapped_file::shrink_all_for_test();
        let base = map_shared(fx.fd2, LEN)?;
        let fresh = fault(&fx.aspace, base + 21 * PAGE)?;
        let page = mapped_bytes(fresh, PAGE as usize);
        munmap(base, LEN)?;
        if page.iter().any(|b| *b != 0x77) {
            return Err("a fresh mapping refaulted the older generation from the filesystem");
        }
        if !reads_as(fx.fd2, r_from, r_len, 0x77)? {
            return Err("pread after the cache dropped its pages returned the older generation");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/coherence/btrfs",
    smoke_btrfs_read_after_two_mapped_generations
);

fn pwrite_range(fd: u64, from: u64, to: u64, byte: u8) -> Result<(), &'static str> {
    let buf = alloc::vec![byte; (to - from) as usize];
    let args = SyscallArgs {
        arg0: fd,
        arg1: buf.as_ptr() as u64,
        arg2: to - from,
        arg3: from,
        arg4: 0,
        arg5: 0,
    };
    match call(Syscall::Pwrite64.raw(), args) {
        Some(n) if n == (to - from) as i64 => Ok(()),
        // A short write is legal: write the rest.
        Some(n) if n > 0 && n < (to - from) as i64 => pwrite_range(fd, from + n as u64, to, byte),
        // Out of space on the small fixture volume: commit, which frees the
        // extents copy-on-write left behind, and try once more.
        Some(-28) => {
            fsync(fd)?;
            match call(Syscall::Pwrite64.raw(), args) {
                Some(n) if n == (to - from) as i64 => Ok(()),
                Some(-28) => Err("pwrite64: ENOSPC even after a commit"),
                _ => Err("pwrite64 failed after a commit"),
            }
        }
        Some(n) if n < 0 => {
            use core::fmt::Write as _;
            let _ = writeln!(narf_console::Writer, "INTEG-PWRITE errno {}", -n);
            Err("pwrite64 failed")
        }
        _ => Err("pwrite64 failed"),
    }
}

/// Soak case (2): pwrite 0xbd over a range, map-store 0xaf over an
/// overlapping one, unmap, then pread from the map-store's first byte: it
/// must read 0xaf — before writeback, after it, through either open.
fn smoke_btrfs_pwrite_then_map_store_then_pread() -> TestResult {
    const LEN: u64 = 64 * PAGE;
    let seed = alloc::vec![0x11u8; LEN as usize];
    with_btrfs(&seed, |fx| {
        let (w_from, w_to) = (5 * PAGE + 1832, 31 * PAGE + 999);
        pwrite_range(fx.fd1, w_from, w_to, 0xbd)?;
        let (m_from, m_to) = (14 * PAGE + 3256, 31 * PAGE + 1096);
        mapped_generation(fx, fx.fd1, LEN, m_from, m_to, 0xaf)?;
        let len = (m_to - m_from) as usize;
        let mut model = seed.clone();
        model[w_from as usize..w_to as usize].fill(0xbd);
        model[m_from as usize..m_to as usize].fill(0xaf);
        for fd in [fx.fd1, fx.fd2] {
            let mut buf = alloc::vec![0u8; len];
            pread(fd, &mut buf, m_from)?;
            if let Some(at) = buf.iter().position(|b| *b != 0xaf) {
                let verdict = diagnose(fx, 0, &model, m_from + at as u64, buf[at]);
                if let Some(detail) = INTEG_VERDICT.lock().take() {
                    use core::fmt::Write as _;
                    let _ = writeln!(narf_console::Writer, "INTEG-CASE2 fd {fd}: {detail}");
                }
                return Err(verdict);
            }
        }
        let _ = crate::mapped_file::sync_all_files(None);
        if !reads_as(fx.fd1, m_from, len, 0xaf)? {
            return Err("pread after writeback returned the pwrite's bytes (same open)");
        }
        if !reads_as(fx.fd2, m_from, len, 0xaf)? {
            return Err("pread after writeback returned the pwrite's bytes (other open)");
        }
        crate::mapped_file::shrink_all_for_test();
        if !reads_as(fx.fd2, m_from, len, 0xaf)? {
            return Err("pread after the cache dropped its pages returned the pwrite's bytes");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/coherence/btrfs",
    smoke_btrfs_pwrite_then_map_store_then_pread
);

/// Soak case (1): two map-store generations, then a fresh mapping of a
/// page both covered: it must show the second generation, before and after
/// writeback and after the cache let go of the page.
fn smoke_btrfs_two_map_stores_then_fresh_map() -> TestResult {
    const LEN: u64 = 64 * PAGE;
    let seed = alloc::vec![0x11u8; LEN as usize];
    with_btrfs(&seed, |fx| {
        mapped_generation(fx, fx.fd1, LEN, 3 * PAGE + 1808, 40 * PAGE + 2042, 0xc1)?;
        mapped_generation(fx, fx.fd1, LEN, 2 * PAGE + 2424, 25 * PAGE + 2544, 0x93)?;
        let fresh = |fd: u64| -> Result<bool, &'static str> {
            let base = map_shared(fd, LEN)?;
            let ptr = fault(&fx.aspace, base + 20 * PAGE)?;
            let page = mapped_bytes(ptr, PAGE as usize);
            munmap(base, LEN)?;
            Ok(page.iter().all(|b| *b == 0x93))
        };
        if !fresh(fx.fd2)? {
            return Err("a fresh mapping showed the first generation before writeback");
        }
        let _ = crate::mapped_file::sync_all_files(None);
        if !fresh(fx.fd2)? {
            return Err("a fresh mapping showed the first generation after writeback");
        }
        crate::mapped_file::shrink_all_for_test();
        if !fresh(fx.fd2)? {
            return Err("a fresh mapping refaulted the first generation from the filesystem");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/coherence/btrfs",
    smoke_btrfs_two_map_stores_then_fresh_map
);

static INTEG_VERDICT: IrqSafeSpinLock<Option<alloc::string::String>> = IrqSafeSpinLock::new(None);

/// The integrity worker, replayed against a byte model of the file: random
/// pwrite, map-store (MAP_SHARED, store, munmap), pread, fresh-mapping
/// fault, fsync, cache writeback and cache drop, on both opens. Every read
/// must return the model.
///
/// On the first mismatch the test reads the wrong bytes again straight
/// from btrfs, with no cache overlay, and looks at the cache page, and says
/// which layer produced them:
/// * the cache page holds a store the read did not show — the overlay
///   missed it (the mapped-file cache);
/// * the cache has no unwritten bytes there and btrfs itself returns the
///   older data — the filesystem returned stale bytes for data it was
///   written.
fn smoke_btrfs_integrity_replay() -> TestResult {
    const LEN: u64 = 96 * PAGE;
    const OPS: usize = 4000;
    let seed = alloc::vec![0x11u8; LEN as usize];
    let result = with_btrfs(&seed, |fx| {
        let mut model = seed.clone();
        let mut history: alloc::collections::VecDeque<(usize, u64, u64, u64, u64)> =
            alloc::collections::VecDeque::new();
        let mut state: u64 = 0x5eed_1234_abcd_9876;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for op in 0..OPS {
            let kind = next() % 12;
            let from = next() % LEN;
            let span = 1 + next() % (12 * PAGE);
            let to = (from + span).min(LEN);
            let byte = (next() % 254 + 1) as u8;
            let fd = if next() % 2 == 0 { fx.fd1 } else { fx.fd2 };
            if history.len() == 12 {
                history.pop_front();
            }
            history.push_back((op, kind, from, to, fd));
            match kind {
                0..=2 => {
                    if let Err(error) = pwrite_range(fd, from, to, byte) {
                        use core::fmt::Write as _;
                        let _ = writeln!(
                            narf_console::Writer,
                            "INTEG-HISTORY (op, kind, from, to, fd), kinds 0-2 pwrite 3-5 map-store \
                             6-8 pread 9 fresh-map 10 fsync 11 writeback/drop: {history:?}"
                        );
                        return Err(error);
                    }
                    model[from as usize..to as usize].fill(byte);
                }
                3..=5 => {
                    mapped_generation(fx, fx.fd1, LEN, from, to, byte)?;
                    model[from as usize..to as usize].fill(byte);
                }
                6..=8 => {
                    let mut buf = alloc::vec![0u8; (to - from) as usize];
                    pread(fd, &mut buf, from)?;
                    if buf != model[from as usize..to as usize] {
                        let first = buf
                            .iter()
                            .zip(&model[from as usize..to as usize])
                            .position(|(got, want)| got != want)
                            .unwrap_or(0) as u64
                            + from;
                        return Err(diagnose(
                            fx,
                            op,
                            &model,
                            first,
                            buf[(first - from) as usize],
                        ));
                    }
                }
                9 => {
                    let page = from & !(PAGE - 1);
                    let base = map_shared(fx.fd2, LEN)?;
                    let ptr = fault(&fx.aspace, base + page)?;
                    let got = mapped_bytes(ptr, PAGE as usize);
                    munmap(base, LEN)?;
                    let want = &model[page as usize..(page + PAGE) as usize];
                    if got != want {
                        let at = got.iter().zip(want).position(|(g, w)| g != w).unwrap_or(0);
                        return Err(diagnose(fx, op, &model, page + at as u64, got[at]));
                    }
                }
                10 => fsync(fd)?,
                _ => {
                    if next() % 2 == 0 {
                        let _ = crate::mapped_file::sync_all_files(None);
                    } else {
                        crate::mapped_file::shrink_all_for_test();
                    }
                }
            }
        }
        Ok(())
    });
    if let Some(verdict) = INTEG_VERDICT.lock().take() {
        use core::fmt::Write as _;
        let _ = writeln!(narf_console::Writer, "INTEG-REPLAY {verdict}");
    }
    result
}

/// Classify the first wrong byte at `at` (read `got`); see the test.
fn diagnose(fx: &Fixture, op: usize, model: &[u8], at: u64, got: u8) -> &'static str {
    let want = model[at as usize];
    let mut direct = [0u8; 1];
    let fs = crate::handlers::poll_io_to_completion(fx.ops1.read(at, &mut direct))
        .and_then(|r| r.ok())
        .map(|_| direct[0]);
    let cache = crate::mapped_file::cached_page_state_for_test(fx.ops1.as_ref(), at);
    *INTEG_VERDICT.lock() = Some(alloc::format!(
        "op {op} offset {at}: read {got:#x}, expected {want:#x}, btrfs direct {fs:?}, cache page \
         (dirty, idle_dirty, mappings) {cache:?}"
    ));
    let unwritten = cache.is_some_and(|(dirty, idle_dirty, _)| dirty || idle_dirty);
    match (unwritten, fs) {
        (true, _) => "replay: the cache held the store but the read did not show it (overlay)",
        (false, Some(direct)) if direct == got && direct != want => {
            "replay: btrfs returned stale bytes for data written to it (cache page clean or absent)"
        }
        (false, Some(direct)) if direct == want => {
            "replay: btrfs has the right bytes but the read returned others"
        }
        _ => "replay: mismatch of unclassified origin",
    }
}
// Tagged apart from the coherence set: it currently stops on a btrfs write
// error (ENOENT from pwrite after ~50 operations), routed to the btrfs
// driver; run it with `--subsystem syscall_abi/btrfs_integrity`.
kernel_test_in!("syscall_abi/btrfs_integrity", smoke_btrfs_integrity_replay);
