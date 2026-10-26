//! MINIX page-cache coherence matrix (#742): the scenarios FAT's
//! matrix pinned down, ported to MINIX's fixtures.
//!
//! * truncate-grow reads zeros (the #692 shape): minix grows
//!   sparsely — size only, zones are allocated lazily — and its read
//!   path zero-fills unmapped zones, so a grown range must fault and
//!   read back as zeros, never EIO or stale bytes. (The shrink-then-
//!   regrow interaction is a different shape with a different
//!   verdict; it lives in `abi_truncate_unmap_tests`.)
//! * msync must not clobber `write(2)` (the #688 shape): after a
//!   `pwrite64` through a second open folds new bytes into the
//!   retained frame and its snapshot, an `msync` of the still-clean
//!   mapping must leave the written bytes on disk — and a store
//!   through the mapping followed by `msync(MS_SYNC)` must be what
//!   `read(2)` serves afterwards.

use alloc::sync::Arc;

use narf_block::ram::RamBlockDevice;
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

/// Mount the MINIX fixture image seeded with `seed`, open `hi.txt`
/// twice, and run `body` against both fds in a fresh address space.
fn with_minix(seed: &[u8], body: impl FnOnce(&Fixture) -> Result<(), &'static str>) -> TestResult {
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
            let image = crate::abi_fault_write_tests::minix3_image(seed);
            let device = RamBlockDevice::from_image(512, image);
            let volume = crate::handlers::poll_io_to_completion(
                narf_drivers_fs_minix::volume::MinixVolume::mount(
                    device,
                    narf_lib::id::DomainId::DRIVER_0,
                ),
            )
            .and_then(|r| r.ok())
            .ok_or("mounting the test MINIX image failed")?;
            let open = || {
                crate::handlers::poll_io_to_completion(volume.root().lookup_async("hi.txt"))
                    .and_then(|r| r.ok())
                    .ok_or("lookup of hi.txt failed")
            };
            let ops1 = open()?;
            let ops2 = open()?;
            let fd1 = install_fd(&ops1)?;
            let fd2 = install_fd(&ops2)?;
            body(&Fixture { aspace, fd1, fd2 })
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

/// The #692 shape on MINIX: a small seeded file, `ftruncate` up to
/// three pages, and the grown range must fault in and read as zeros
/// while the seeded head is untouched.
fn smoke_minix_truncate_grow_reads_zeros() -> TestResult {
    with_minix(&content(100), |fx| {
        let base = map_shared(fx.fd1, 3 * PAGE)?;
        ftruncate(fx.fd1, 3 * PAGE)?;
        // The grown tail faults in as zeros (sparse zones).
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
    "syscall_abi/coherence/minix",
    smoke_minix_truncate_grow_reads_zeros
);

/// The #688 shape on MINIX, two halves on two pages:
/// (a) fault page 0 in, `pwrite64` a full new page through the
///     second open, store *different* bytes through the mapping,
///     `msync` — `read(2)` must serve the stored bytes (the flush
///     wrote the frame, not a snapshot);
/// (b) fault page 1 in, `pwrite64` through the second open, `msync`
///     the still-clean mapping — `read(2)` must still serve the
///     written bytes (the clean snapshot must not clobber the fold).
fn smoke_minix_msync_does_not_clobber_write() -> TestResult {
    let seed = content(3 * PAGE as usize - 100);
    with_minix(&seed, |fx| {
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
    "syscall_abi/coherence/minix",
    smoke_minix_msync_does_not_clobber_write
);
