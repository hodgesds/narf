//! Page-cache coherence of file mappings, against a real ext2 volume.
//!
//! Linux keeps ONE `address_space` per inode and every path into the file —
//! `read(2)`, `write(2)`, every `MAP_SHARED` mapping of every open of every
//! hard link — reads and writes the same page-cache folios
//! (`mm/filemap.c::filemap_fault` maps the cache folio itself). So:
//!
//!  * two mappings of one inode, through different names, alias one page;
//!  * `write(2)` is visible through an existing mapping;
//!  * a store through a mapping is visible to `read(2)` without `msync`;
//!  * reclaim never evicts a mapped folio (it would have to unmap it first);
//!  * truncation unmaps the pages past the new EOF and a later touch of them
//!    is `SIGBUS` (`mm/truncate.c::truncate_pagecache`), while the partial
//!    last page stays mapped with its tail zeroed.
//!
//! The volume is a byte-built image (`narf_drivers_fs_ext2::testing`) on a
//! `RamBlockDevice`; its file is named twice (`data`, `link`). Page faults
//! are driven with `AddressSpace::demand_alloc_page`, the same entry the
//! trap handler uses, and the user-visible bytes are read through the
//! faulted frame's direct-map alias.

use alloc::sync::Arc;

use narf_block::ram::RamBlockDevice;
use narf_drivers_fs_ext2::testing;
use narf_drivers_fs_ext2::volume::Ext2Volume;
use narf_filesystem::{FileOps, FsInstance};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::{AddressSpace, VirtAddr};

use crate::abi_test_support::*;

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_SHARED: u64 = 1;
const O_RDWR: u32 = 2;
const PAGE: u64 = 4096;

static FILEMAP_AS: IrqSafeSpinLock<Option<Arc<AddressSpace>>> = IrqSafeSpinLock::new(None);

fn lookup_filemap_as() -> Option<Arc<AddressSpace>> {
    FILEMAP_AS.lock().clone()
}

struct Fixture {
    volume: Arc<Ext2Volume<RamBlockDevice>>,
    aspace: Arc<AddressSpace>,
    /// fd of the file opened through the name `data`.
    fd_data: u64,
    /// fd of the same inode opened through its hard link `link`.
    fd_link: u64,
}

fn open_name(volume: &Arc<Ext2Volume<RamBlockDevice>>, name: &str) -> Option<Arc<dyn FileOps>> {
    match crate::handlers::poll_io_to_completion(volume.root().lookup_async(name)) {
        Some(Ok(ops)) => Some(ops),
        _ => None,
    }
}

fn install_rdwr(ops: Arc<dyn FileOps>) -> Option<u64> {
    crate::fd::install(
        FAKE_TASK,
        crate::fd::FdEntry {
            ops,
            offset: 0,
            flags: 0,
            status_flags: O_RDWR,
        },
    )
    .map(u64::from)
}

/// Mount an ext2 volume holding `content` (named `data` and `link`), give
/// the harness task an address space, and open both names read-write.
fn with_fixture(
    content: &[u8],
    body: impl FnOnce(&Fixture) -> Result<(), &'static str>,
) -> TestResult {
    let image = testing::hard_link_image(content);
    with_setup(move || {
        // SAFETY: kernel tests run with paging enabled; the new root inherits
        // only the kernel half and is owned by this fixture.
        let aspace = match unsafe { AddressSpace::new_for_user() } {
            Ok(aspace) => Arc::new(aspace),
            Err(_) => return Err("failed to create the test address space"),
        };
        *FILEMAP_AS.lock() = Some(Arc::clone(&aspace));
        crate::handlers::install_address_space_lookup(lookup_filemap_as);
        let result = (|| {
            let device = RamBlockDevice::from_image(512, image);
            let volume = match crate::handlers::poll_io_to_completion(Ext2Volume::mount(
                device,
                narf_lib::id::DomainId::DRIVER_0,
            )) {
                Some(Ok(volume)) => volume,
                _ => return Err("mounting the test ext2 image failed"),
            };
            let data = open_name(&volume, "data").ok_or("lookup of `data` failed")?;
            let link = open_name(&volume, "link").ok_or("lookup of `link` failed")?;
            let fd_data = install_rdwr(data).ok_or("installing the `data` fd failed")?;
            let fd_link = install_rdwr(link).ok_or("installing the `link` fd failed")?;
            body(&Fixture {
                volume,
                aspace: Arc::clone(&aspace),
                fd_data,
                fd_link,
            })
        })();
        crate::handlers::restore_address_space_lookup(None);
        *FILEMAP_AS.lock() = None;
        result
    })
}

/// `mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)`.
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
        _ => Err("MAP_SHARED mmap of the ext2 file failed"),
    }
}

/// Touch `va` the way a user access would and return the direct-map alias
/// of the frame the mapping now holds there.
fn fault(aspace: &AddressSpace, va: u64) -> Result<*mut u8, &'static str> {
    // SAFETY: `aspace` is a live user root and paging is enabled.
    unsafe { aspace.demand_alloc_page(VirtAddr::new(va)) }
        .map_err(|_| "a fault inside the file's EOF was refused")?;
    let phys = mapped_frame(aspace, va).ok_or("the fault left the page unbacked")?;
    Ok(narf_memory::PhysAddr::new(phys).kernel_mut_ptr::<u8>())
}

/// The frame currently backing `va` (0 / `None` = unbacked).
fn mapped_frame(aspace: &AddressSpace, va: u64) -> Option<u64> {
    let region = aspace.lookup(VirtAddr::new(va))?;
    let index = ((va & !(PAGE - 1)) - region.base.as_u64()) / PAGE;
    let phys = region.phys.get(index as usize)?.raw();
    (phys != 0).then_some(phys)
}

fn pread(fd: u64, buf: &mut [u8], offset: u64) -> Option<i64> {
    call(
        Syscall::Pread64.raw(),
        a3(fd, buf.as_mut_ptr() as u64, buf.len() as u64, offset),
    )
}

fn pwrite(fd: u64, buf: &[u8], offset: u64) -> Option<i64> {
    call(
        Syscall::Pwrite64.raw(),
        a3(fd, buf.as_ptr() as u64, buf.len() as u64, offset),
    )
}

/// Read `len` bytes the mapping shows at `ptr`.
fn mapped_bytes(ptr: *const u8, len: usize) -> alloc::vec::Vec<u8> {
    // SAFETY: `ptr` is the direct-map alias of a frame the test mapping holds.
    unsafe { core::slice::from_raw_parts(ptr, len).to_vec() }
}

/// Store `bytes` through the mapping at `ptr`.
fn store(ptr: *mut u8, bytes: &[u8]) {
    // SAFETY: as `mapped_bytes`; the frame stays mapped for the whole test.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len()) }
}

fn content(len: usize) -> alloc::vec::Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// (a) Two `MAP_SHARED` mappings of one inode, opened through two different
/// names (a hard link), alias one page: a store through either is what the
/// other reads. NARF used to key its fallback shared pages by the open
/// file's `Arc` pointer and built a fresh ext2 node per lookup, so the two
/// names got two divergent copies of the same file offset.
fn smoke_abi_filemap_hard_link_mappings_share_pages() -> TestResult {
    with_fixture(&content(6000), |fx| {
        let a = map_shared(fx.fd_data, 2 * PAGE)?;
        let b = map_shared(fx.fd_link, 2 * PAGE)?;
        let pa = fault(&fx.aspace, a + PAGE)?;
        let pb = fault(&fx.aspace, b + PAGE)?;
        store(pa, b"via data");
        if mapped_bytes(pb, 8) != b"via data" {
            return Err("a store through `data` is invisible through the `link` mapping");
        }
        store(pb, b"via link");
        if mapped_bytes(pa, 8) != b"via link" {
            return Err("a store through `link` is invisible through the `data` mapping");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/filemap/hard_link",
    smoke_abi_filemap_hard_link_mappings_share_pages
);

/// (b) `write(2)` through one descriptor is visible through an existing
/// `MAP_SHARED` mapping made through another — the write lands in the very
/// folio the mapping holds.
fn smoke_abi_filemap_write_is_visible_in_existing_mapping() -> TestResult {
    with_fixture(&content(6000), |fx| {
        let b = map_shared(fx.fd_link, 2 * PAGE)?;
        let pb = fault(&fx.aspace, b)?;
        if mapped_bytes(pb, 4) != content(4) {
            return Err("the mapping does not show the file's bytes");
        }
        if pwrite(fx.fd_data, b"WRITTEN", 100) != Some(7) {
            return Err("pwrite through `data` failed");
        }
        if mapped_bytes(unsafe_add(pb, 100), 7) != b"WRITTEN" {
            return Err("write(2) is not visible through an existing MAP_SHARED mapping");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/filemap/write_visible",
    smoke_abi_filemap_write_is_visible_in_existing_mapping
);

fn unsafe_add(ptr: *mut u8, off: usize) -> *mut u8 {
    // SAFETY: callers stay within the one 4 KiB frame `ptr` starts.
    unsafe { ptr.add(off) }
}

/// (c) A store through a `MAP_SHARED` mapping is visible to `read(2)`
/// immediately — no `msync` — because both are the same page-cache page.
fn smoke_abi_filemap_mapped_store_is_visible_to_read() -> TestResult {
    with_fixture(&content(6000), |fx| {
        let a = map_shared(fx.fd_data, 2 * PAGE)?;
        let pa = fault(&fx.aspace, a)?;
        store(unsafe_add(pa, 10), b"stored");
        let mut buf = [0u8; 6];
        if pread(fx.fd_data, &mut buf, 10) != Some(6) {
            return Err("pread through `data` failed");
        }
        if &buf != b"stored" {
            return Err("a MAP_SHARED store is invisible to read(2) on the same fd");
        }
        if pread(fx.fd_link, &mut buf, 10) != Some(6) || &buf != b"stored" {
            return Err("a MAP_SHARED store is invisible to read(2) through the hard link");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/filemap/store_visible",
    smoke_abi_filemap_mapped_store_is_visible_to_read
);

/// (e) Reclaim never evicts a mapped folio. If it did, the next access
/// through `read(2)`/`write(2)` would refill a NEW folio and the mapping
/// would keep the old one: the two views of the file would silently
/// diverge. Drive every shrinker to the limit and check that the mapping
/// and the file still share their page in both directions.
fn smoke_abi_filemap_reclaim_keeps_mapped_folios() -> TestResult {
    with_fixture(&content(6000), |fx| {
        let a = map_shared(fx.fd_data, 2 * PAGE)?;
        let pa = fault(&fx.aspace, a)?;
        let frame = mapped_frame(&fx.aspace, a);
        narf_memory::reclaim::shrink_all(usize::MAX);
        if mapped_frame(&fx.aspace, a) != frame {
            return Err("reclaim changed the frame behind a live mapping");
        }
        if pwrite(fx.fd_data, b"after reclaim", 0) != Some(13) {
            return Err("pwrite after reclaim failed");
        }
        if mapped_bytes(pa, 13) != b"after reclaim" {
            return Err("after reclaim, write(2) no longer reaches the mapped page");
        }
        store(unsafe_add(pa, 20), b"mapped");
        let mut buf = [0u8; 6];
        if pread(fx.fd_data, &mut buf, 20) != Some(6) || &buf != b"mapped" {
            return Err("after reclaim, read(2) no longer sees the mapped page");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/filemap/reclaim",
    smoke_abi_filemap_reclaim_keeps_mapped_folios
);

/// `mm/truncate.c::truncate_pagecache`: shrinking a mapped file unmaps
/// every page wholly past the new EOF from every mapping, and a later touch
/// of one is `SIGBUS` (`filemap_fault` refuses an index past `i_size`). The
/// page that straddles the new EOF stays mapped, its tail zeroed
/// (`truncate_inode_partial_folio`).
fn smoke_abi_filemap_truncate_unmaps_pages_past_eof() -> TestResult {
    with_fixture(&content(3 * PAGE as usize - 100), |fx| {
        let a = map_shared(fx.fd_data, 3 * PAGE)?;
        let b = map_shared(fx.fd_link, 3 * PAGE)?;
        for page in 0..3 {
            fault(&fx.aspace, a + page * PAGE)?;
            fault(&fx.aspace, b + page * PAGE)?;
        }
        const NEW_LEN: u64 = PAGE + 904;
        if call(Syscall::Ftruncate.raw(), a1(fx.fd_data, NEW_LEN)) != Some(0) {
            return Err("ftruncate failed");
        }
        for base in [a, b] {
            if mapped_frame(&fx.aspace, base + 2 * PAGE).is_some() {
                return Err("a page wholly past the new EOF is still mapped after truncate");
            }
            // SAFETY: live user root, paging enabled.
            if unsafe { fx.aspace.demand_alloc_page(VirtAddr::new(base + 2 * PAGE)) }.is_ok() {
                return Err("a fault past the new EOF was served instead of raising SIGBUS");
            }
            let partial = mapped_frame(&fx.aspace, base + PAGE)
                .ok_or("the page straddling the new EOF was unmapped")?;
            let ptr = narf_memory::PhysAddr::new(partial).kernel_ptr::<u8>();
            let in_page = (NEW_LEN - PAGE) as usize;
            let tail = mapped_bytes(ptr.wrapping_add(in_page), PAGE as usize - in_page);
            if tail.iter().any(|&b| b != 0) {
                return Err("the mapped tail past the new EOF was not zeroed");
            }
            let head = mapped_bytes(ptr, in_page);
            if head != content(PAGE as usize + in_page)[PAGE as usize..] {
                return Err("truncate damaged bytes before the new EOF");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/filemap/truncate",
    smoke_abi_filemap_truncate_unmaps_pages_past_eof
);

/// `msync(MS_SYNC)` writes a mapped store back to the disk: the device
/// block under the file holds the new bytes afterwards.
fn smoke_abi_filemap_msync_writes_mapped_store_to_disk() -> TestResult {
    const MS_SYNC: u64 = 4;
    with_fixture(&content(6000), |fx| {
        let a = map_shared(fx.fd_data, 2 * PAGE)?;
        let pa = fault(&fx.aspace, a + PAGE)?;
        store(unsafe_add(pa, 8), b"durable");
        if call(Syscall::Msync.raw(), a2(a, 2 * PAGE, MS_SYNC)) != Some(0) {
            return Err("msync(MS_SYNC) failed");
        }
        // File offset 4096 + 8 is block FILE_FIRST_BLOCK + 4, byte 8.
        let block = u64::from(testing::FILE_FIRST_BLOCK) + 4;
        let mut disk = [0u8; testing::BLOCK_SIZE];
        match crate::handlers::poll_io_to_completion(fx.volume.read_block(block, &mut disk)) {
            Some(Ok(())) => {}
            _ => return Err("reading the file's block back from the device failed"),
        }
        if &disk[8..15] != b"durable" {
            return Err("msync(MS_SYNC) did not write the mapped store to the disk");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/filemap/msync",
    smoke_abi_filemap_msync_writes_mapped_store_to_disk
);
