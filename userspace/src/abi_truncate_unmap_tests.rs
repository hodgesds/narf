//! Shrink-truncate revokes already-mapped pages past the new EOF (#678).
//!
//! `mm/truncate.c::truncate_pagecache` unmaps every page wholly past the
//! new EOF from every mapping before the filesystem retires the pages
//! behind them; a later touch is `SIGBUS`. Only the ext2 driver did this
//! (its own `unmap_mapping_range` call); memfs and every filesystem on the
//! generic mapped-file path left the installed PTEs serving the retired
//! frames — stale bytes on read, silently dropped stores.
//!
//! These tests drive the syscall surface the way
//! `smoke_abi_filemap_truncate_unmaps_pages_past_eof` does for ext2 —
//! a real address space, `AddressSpace::demand_alloc_page` as the fault
//! entry — once against tmpfs (the coherent `mmap_fault` path) and once
//! against a byte-built FAT12 volume (the generic fallback path).
//! Scenario per filesystem:
//!
//!   1. map 3 pages `MAP_SHARED`, fault all three in;
//!   2. `ftruncate` to the middle of page 1: page 2's frame must be
//!      revoked and a fresh fault of it must be refused, while page 1
//!      (straddling the new EOF) stays mapped;
//!   3. `ftruncate` back up: the zapped tail faults back in through the
//!      SAME mapping — the truncate zap keeps the VMA (#691), where the
//!      #678-era revoke removed it outright — as a hole where the
//!      filesystem materialises holes (tmpfs), and after a rewrite the
//!      range serves the new bytes, never the pre-truncate content. A
//!      second shrink/grow cycle repeats the zap, and a `MAP_FIXED`
//!      mapping over the zapped window replaces the retained tail.

use alloc::sync::Arc;

use narf_block::ram::RamBlockDevice;
use narf_filesystem::{FileOps, FsInstance};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::{AddressSpace, VirtAddr};

use crate::abi_test_support::*;

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_SHARED: u64 = 1;
const MAP_FIXED: u64 = 0x10;
const O_RDWR: u32 = 2;
const PAGE: u64 = 4096;

static TRUNC_AS: IrqSafeSpinLock<Option<Arc<AddressSpace>>> = IrqSafeSpinLock::new(None);

fn lookup_trunc_as() -> Option<Arc<AddressSpace>> {
    TRUNC_AS.lock().clone()
}

struct Fixture {
    aspace: Arc<AddressSpace>,
    fd: u64,
    /// Whether this filesystem's fault path materialises in-size holes
    /// as zero pages (memfs does; FAT's read path errors past the end of
    /// the cluster chain instead — a pre-existing gap tracked
    /// separately — so its scenario materialises the range with a
    /// write before faulting it).
    hole_fault_zero: bool,
}

/// Give the harness task an address space, install `ops` as an fd opened
/// read-write, and run `body` against them.
fn with_file(
    make_ops: impl FnOnce() -> Result<Arc<dyn FileOps>, &'static str>,
    hole_fault_zero: bool,
    body: impl FnOnce(&Fixture) -> Result<(), &'static str>,
) -> TestResult {
    with_setup(move || {
        // SAFETY: kernel tests run with paging enabled; the new root
        // inherits only the kernel half and is owned by this fixture.
        let aspace = match unsafe { AddressSpace::new_for_user() } {
            Ok(aspace) => Arc::new(aspace),
            Err(_) => return Err("failed to create the test address space"),
        };
        *TRUNC_AS.lock() = Some(Arc::clone(&aspace));
        crate::handlers::install_address_space_lookup(lookup_trunc_as);
        let result = (|| {
            let ops = make_ops()?;
            let fd = crate::fd::install(
                FAKE_TASK,
                crate::fd::FdEntry {
                    ops: Arc::clone(&ops),
                    offset: 0,
                    flags: 0,
                    status_flags: O_RDWR,
                },
            )
            .map(u64::from)
            .ok_or("installing the fd failed")?;
            body(&Fixture {
                aspace,
                fd,
                hole_fault_zero,
            })
        })();
        crate::handlers::restore_address_space_lookup(None);
        *TRUNC_AS.lock() = None;
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
        _ => Err("MAP_SHARED mmap failed"),
    }
}

/// `mmap(addr, len, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED, fd, offset)`.
fn map_fixed_shared(fd: u64, addr: u64, len: u64, offset: u64) -> Result<u64, &'static str> {
    let args = SyscallArgs {
        arg0: addr,
        arg1: len,
        arg2: PROT_READ | PROT_WRITE,
        arg3: MAP_SHARED | MAP_FIXED,
        arg4: fd,
        arg5: offset,
    };
    match call(Syscall::Mmap.raw(), args) {
        Some(placed) if placed > 0 => Ok(placed as u64),
        _ => Err("MAP_FIXED mmap failed"),
    }
}

/// Whether a region still covers `va` — the retention half of the zap
/// contract (the #678-era revoke removed the tail region outright).
fn region_present(aspace: &AddressSpace, va: u64) -> bool {
    aspace.lookup(VirtAddr::new(va)).is_some()
}

/// The frame currently backing `va` (0 / `None` = unbacked).
fn mapped_frame(aspace: &AddressSpace, va: u64) -> Option<u64> {
    let region = aspace.lookup(VirtAddr::new(va))?;
    let index = ((va & !(PAGE - 1)) - region.base.as_u64()) / PAGE;
    let phys = region.phys.get(index as usize)?.raw();
    (phys != 0).then_some(phys)
}

/// Fault `va` in the way a user access would.
fn fault(aspace: &AddressSpace, va: u64) -> Result<(), &'static str> {
    // SAFETY: `aspace` is a live user root and paging is enabled.
    unsafe { aspace.demand_alloc_page(VirtAddr::new(va)) }
        .map_err(|_| "a fault inside the file's EOF was refused")?;
    if mapped_frame(aspace, va).is_none() {
        return Err("the fault left the page unbacked");
    }
    Ok(())
}

/// Bytes the mapping shows at `va` (must be backed), `len` of them.
fn mapped_bytes(
    aspace: &AddressSpace,
    va: u64,
    len: usize,
) -> Result<alloc::vec::Vec<u8>, &'static str> {
    let phys = mapped_frame(aspace, va).ok_or("the page is not backed")?;
    let ptr = narf_memory::PhysAddr::new(phys).kernel_ptr::<u8>();
    // SAFETY: `ptr` is the direct-map alias of a frame the mapping holds.
    Ok(unsafe { core::slice::from_raw_parts(ptr, len).to_vec() })
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

/// The #678 scenario, shared by both filesystem fixtures.
fn run_scenario(fx: &Fixture) -> Result<(), &'static str> {
    let bytes = content(3 * PAGE as usize - 100);
    let base = map_shared(fx.fd, 3 * PAGE)?;
    for page in 0..3 {
        fault(&fx.aspace, base + page * PAGE)?;
    }
    if mapped_bytes(&fx.aspace, base, 32)? != bytes[..32] {
        return Err("the mapping does not show the file's first bytes");
    }
    if mapped_bytes(&fx.aspace, base + 2 * PAGE, 32)?
        != bytes[2 * PAGE as usize..2 * PAGE as usize + 32]
    {
        return Err("the mapping does not show the file's page-2 bytes");
    }

    // Shrink into the middle of page 1.
    const NEW_LEN: u64 = PAGE + 904;
    ftruncate(fx.fd, NEW_LEN)?;

    // The page wholly past the new EOF is zapped — its frame retired
    // while its VMA stays — and re-faulting it is refused (the SIGBUS
    // case) rather than served stale bytes.
    if mapped_frame(&fx.aspace, base + 2 * PAGE).is_some() {
        return Err("a page wholly past the new EOF is still mapped after truncate");
    }
    // SAFETY: live user root, paging enabled.
    if unsafe { fx.aspace.demand_alloc_page(VirtAddr::new(base + 2 * PAGE)) }.is_ok() {
        return Err("a fault past the new EOF was served instead of raising SIGBUS");
    }
    if mapped_frame(&fx.aspace, base + 2 * PAGE).is_some() {
        return Err("the refused fault left a backing frame behind");
    }
    // The straddling page stays mapped, its pre-EOF bytes intact.
    if mapped_frame(&fx.aspace, base + PAGE).is_none() {
        return Err("the page straddling the new EOF was unmapped");
    }
    let head = mapped_bytes(&fx.aspace, base + PAGE, (NEW_LEN - PAGE) as usize)?;
    if head.as_slice() != &bytes[PAGE as usize..NEW_LEN as usize] {
        return Err("truncate damaged bytes before the new EOF");
    }

    // Re-extending must not resurrect the truncated bytes — but the
    // truncate zap (#691) keeps the tail VMA, where the #678-era revoke
    // removed it outright: the region is still there, still unbacked
    // (growing a file faults nothing in), and the SAME mapping faults
    // the range back in place, exactly like Linux.
    ftruncate(fx.fd, 3 * PAGE)?;
    if !region_present(&fx.aspace, base + 2 * PAGE) {
        return Err("truncate destroyed the tail VMA instead of zapping it");
    }
    if mapped_frame(&fx.aspace, base + 2 * PAGE).is_some() {
        return Err("re-extending the file remapped the zapped tail");
    }
    if fx.hole_fault_zero {
        // A filesystem whose fault path materialises holes serves the
        // truncated range as zeros through the original mapping, never
        // as the pre-truncate bytes.
        fault(&fx.aspace, base + 2 * PAGE)?;
        let regrown = mapped_bytes(&fx.aspace, base + 2 * PAGE, PAGE as usize)?;
        if regrown.iter().any(|&b| b != 0) {
            return Err("re-extending the file resurrected stale bytes in the truncated range");
        }
    }
    // Rewrite the truncated range with new bytes through `pwrite64`;
    // a fault through the original mapping must serve those, never the
    // pre-truncate content. The write goes through the syscall surface
    // on purpose: write(2) coherence for generic-fallback filesystems
    // lives in the handler's `note_file_written` fold (#688), so a raw
    // `FileOps::write` here would model a sequence no user program can
    // produce — one whose bytes reach the disk but never the retained
    // cache frame (#724).
    let new_bytes = alloc::vec![0xC3u8; PAGE as usize];
    let args = SyscallArgs {
        arg0: fx.fd,
        arg1: new_bytes.as_ptr() as u64,
        arg2: PAGE,
        arg3: 2 * PAGE,
        arg4: 0,
        arg5: 0,
    };
    match call(Syscall::Pwrite64.raw(), args) {
        Some(n) if n == PAGE as i64 => {}
        _ => return Err("rewrite of the truncated range failed or was short"),
    }
    fault(&fx.aspace, base + 2 * PAGE)?;
    if mapped_bytes(&fx.aspace, base + 2 * PAGE, PAGE as usize)? != new_bytes {
        return Err("the rewritten range does not serve the new bytes");
    }
    if mapped_bytes(&fx.aspace, base, 32)? != bytes[..32] {
        return Err("truncate damaged the file's surviving head bytes");
    }

    // A second shrink -> grow cycle over the same mapping: the zap is
    // repeatable, and the range the rewrite populated is discarded by
    // the second shrink (those bytes were the file's tail again), so
    // the second regrow faults zeros back in — in place, no fresh mmap.
    ftruncate(fx.fd, NEW_LEN)?;
    if mapped_frame(&fx.aspace, base + 2 * PAGE).is_some() {
        return Err("the second shrink left the tail mapped");
    }
    // SAFETY: live user root, paging enabled.
    if unsafe { fx.aspace.demand_alloc_page(VirtAddr::new(base + 2 * PAGE)) }.is_ok() {
        return Err("a fault past the second shrink's EOF was served instead of raising SIGBUS");
    }
    ftruncate(fx.fd, 3 * PAGE)?;
    if !region_present(&fx.aspace, base + 2 * PAGE) {
        return Err("the second truncate destroyed the tail VMA");
    }
    if fx.hole_fault_zero {
        fault(&fx.aspace, base + 2 * PAGE)?;
        let regrown = mapped_bytes(&fx.aspace, base + 2 * PAGE, PAGE as usize)?;
        if regrown.iter().any(|&b| b != 0) {
            return Err("the second regrow resurrected bytes the second shrink discarded");
        }
    }

    // MAP_FIXED over the zapped window: the fixed-remap machinery keeps
    // its range-removing semantics over a retained region — the new
    // mapping lands exactly on the window and serves the file's current
    // bytes there. The range is materialised with a write first, as on
    // the first pass, so both filesystem fixtures read real content.
    let fixed_bytes = alloc::vec![0x5Au8; PAGE as usize];
    let args = SyscallArgs {
        arg0: fx.fd,
        arg1: fixed_bytes.as_ptr() as u64,
        arg2: PAGE,
        arg3: 2 * PAGE,
        arg4: 0,
        arg5: 0,
    };
    match call(Syscall::Pwrite64.raw(), args) {
        Some(n) if n == PAGE as i64 => {}
        _ => return Err("rewrite before the MAP_FIXED case failed or was short"),
    }
    let fixed = map_fixed_shared(fx.fd, base + 2 * PAGE, PAGE, 2 * PAGE)?;
    if fixed != base + 2 * PAGE {
        return Err("MAP_FIXED did not land on the zapped window");
    }
    fault(&fx.aspace, fixed)?;
    if mapped_bytes(&fx.aspace, fixed, PAGE as usize)? != fixed_bytes {
        return Err("the MAP_FIXED replacement does not serve the file's current bytes");
    }
    if mapped_bytes(&fx.aspace, base, 32)? != bytes[..32] {
        return Err("MAP_FIXED over the zapped window damaged the surviving head");
    }
    Ok(())
}

fn smoke_truncate_unmap_memfs() -> TestResult {
    with_file(
        || {
            let fs =
                TmpFs::from_options("size=1M", 0, 0).map_err(|_| "tmpfs construction failed")?;
            let file = crate::handlers::poll_io_to_completion(fs.root().create("data"))
                .and_then(|r| r.ok())
                .ok_or("tmpfs create failed")?;
            let bytes = content(3 * PAGE as usize - 100);
            let written = crate::handlers::poll_io_to_completion(file.write(0, &bytes))
                .and_then(|r| r.ok())
                .ok_or("tmpfs seed write failed")?;
            if written != bytes.len() {
                return Err("tmpfs seed write was short");
            }
            Ok(file)
        },
        true,
        run_scenario,
    )
}
kernel_test_in!(
    "syscall_abi/truncate_unmap/memfs",
    smoke_truncate_unmap_memfs
);

/// Byte-built FAT12 image holding one file, `NARF.TXT`, whose content is
/// `data` spread over a cluster chain (512-byte clusters, one-sector
/// FATs). Modeled on `drivers/fs/fat`'s own test-image builder, extended
/// to a multi-cluster chain.
fn fat12_image(data: &[u8]) -> alloc::vec::Vec<u8> {
    use alloc::vec;
    const LBS: usize = 512;
    fn fat12_set(fat: &mut [u8], idx: u32, val: u16) {
        let off = (idx + idx / 2) as usize;
        let v = val & 0x0FFF;
        if idx % 2 == 0 {
            fat[off] = (v & 0xFF) as u8;
            fat[off + 1] = (fat[off + 1] & 0xF0) | (((v >> 8) & 0x0F) as u8);
        } else {
            fat[off] = (fat[off] & 0x0F) | (((v << 4) & 0xF0) as u8);
            fat[off + 1] = ((v >> 4) & 0xFF) as u8;
        }
    }
    let clusters = (data.len() as u32).div_ceil(LBS as u32);
    let total_sectors = 4 + clusters;
    let mut img = vec![0u8; LBS * total_sectors as usize];
    img[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    img[3..11].copy_from_slice(b"NARFFAT ");
    img[11..13].copy_from_slice(&(LBS as u16).to_le_bytes());
    img[13] = 1; // sec/clus
    img[14..16].copy_from_slice(&1u16.to_le_bytes()); // rsvd_sec_cnt
    img[16] = 2; // num_fats
    img[17..19].copy_from_slice(&16u16.to_le_bytes()); // root_ent_cnt
    img[19..21].copy_from_slice(&(total_sectors as u16).to_le_bytes());
    img[21] = 0xF8; // media
    img[22..24].copy_from_slice(&1u16.to_le_bytes()); // fat_sz_16
    img[510] = 0x55;
    img[511] = 0xAA;
    for lba in [1usize, 2] {
        let fat = &mut img[lba * LBS..lba * LBS + LBS];
        fat12_set(fat, 0, 0xFF8);
        fat12_set(fat, 1, 0xFFF);
        for c in 0..clusters {
            let idx = 2 + c;
            let val = if c + 1 == clusters { 0xFFF } else { idx + 1 };
            fat12_set(fat, idx, val as u16);
        }
    }
    let entry = &mut img[3 * LBS..3 * LBS + 32];
    entry[0..11].copy_from_slice(b"NARF    TXT");
    entry[11] = 0x20; // ARCHIVE
    entry[26..28].copy_from_slice(&2u16.to_le_bytes()); // fst_clus_lo
    entry[28..32].copy_from_slice(&(data.len() as u32).to_le_bytes());
    img[4 * LBS..4 * LBS + data.len()].copy_from_slice(data);
    img
}

fn smoke_truncate_unmap_fat() -> TestResult {
    with_file(
        || {
            let image = fat12_image(&content(3 * PAGE as usize - 100));
            let device = RamBlockDevice::from_image(512, image);
            let volume = crate::handlers::poll_io_to_completion(
                narf_drivers_fs_fat::volume::FatVolume::mount(
                    device,
                    narf_lib::id::DomainId::DRIVER_0,
                ),
            )
            .and_then(|r| r.ok())
            .ok_or("mounting the test FAT image failed")?;
            let file =
                crate::handlers::poll_io_to_completion(volume.root().lookup_async("NARF.TXT"))
                    .and_then(|r| r.ok())
                    .ok_or("lookup of NARF.TXT failed")?;
            Ok(file)
        },
        false,
        run_scenario,
    )
}
kernel_test_in!("syscall_abi/truncate_unmap/fat", smoke_truncate_unmap_fat);
