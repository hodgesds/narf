//! Revocable device mappings through the real `mmap(2)` path.
//!
//! `sys_mmap` must install the VM relocation hook before asking the device
//! for backing, and call `FileOps::mmap_published` exactly once, only after
//! the leaves exist. The hook (`mapped_file::relocate_device_frames`) then
//! revokes the published aliases, preserves a driver commit error, refuses a
//! census shortfall as `Busy`, and on success rebinds present leaves while a
//! PROT_NONE page stays absent. `munmap` releases the device's lifetime token.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use narf_filesystem::{FileOps, FsError, FsFuture, MmapBacking, MmapLifetime, Mode, Stat};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::{AddressSpace, PhysAddr, VirtAddr};

use crate::abi_test_support::*;

const PROT_NONE: u64 = 0;
const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_SHARED: u64 = 1;
const O_RDWR: u32 = 2;
const PAGE: u64 = 4096;

static DEVICE_AS: IrqSafeSpinLock<Option<Arc<AddressSpace>>> = IrqSafeSpinLock::new(None);
static FRAMES: IrqSafeSpinLock<Vec<u64>> = IrqSafeSpinLock::new(Vec::new());
static PUBLISHED: AtomicUsize = AtomicUsize::new(0);
/// Publications that observed every frame already reverse-mapped.
static PUBLISHED_AFTER_LEAVES: AtomicUsize = AtomicUsize::new(0);
static TOKENS_DROPPED: AtomicUsize = AtomicUsize::new(0);
/// Census answer for the old frames; 0 means "use the real metadata count".
static CENSUS_EXTRA: AtomicUsize = AtomicUsize::new(0);

fn lookup_device_as() -> Option<Arc<AddressSpace>> {
    DEVICE_AS.lock().clone()
}

struct Token;
impl Drop for Token {
    fn drop(&mut self) {
        TOKENS_DROPPED.fetch_add(1, Ordering::AcqRel);
    }
}

/// A device whose frames are relocatable only after publication.
struct Device;
impl FileOps for Device {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        alloc::boxed::Box::pin(async { Ok(0) })
    }
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        alloc::boxed::Box::pin(async move { Ok(buf.len()) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }
    fn mmap_backing(&self, offset: u64, len: usize) -> Result<MmapBacking, FsError> {
        let frames = FRAMES.lock();
        let first = (offset / PAGE) as usize;
        let count = len / PAGE as usize;
        let frames = frames
            .get(first..first + count)
            .ok_or(FsError::InvalidData)?
            .to_vec();
        Ok(MmapBacking {
            frames,
            lifetime: Some(Arc::new(Token) as Arc<dyn MmapLifetime>),
            memory_type: narf_memory::MemoryType::WriteBack,
        })
    }
    fn mmap_published(&self, lifetime: Option<&Arc<dyn MmapLifetime>>) {
        PUBLISHED.fetch_add(1, Ordering::AcqRel);
        let any: Option<&dyn core::any::Any> = lifetime.map(|l| l.as_ref() as _);
        let leaves = FRAMES
            .lock()
            .iter()
            .all(|&frame| narf_memory::rmap::owner_count(PhysAddr::new(frame)) == 1);
        if any.is_some_and(|token| token.is::<Token>()) && leaves {
            PUBLISHED_AFTER_LEAVES.fetch_add(1, Ordering::AcqRel);
        }
    }
}

/// Runs with every region table locked, so it may only take leaf locks: each
/// mapped device frame has exactly one metadata alias, plus any injected one.
fn census(phys: u64) -> usize {
    usize::from(FRAMES.lock().contains(&phys)) + CENSUS_EXTRA.load(Ordering::Acquire)
}

fn translated(space: &AddressSpace, va: u64) -> Option<u64> {
    // SAFETY: the test-owned root is live and never activated.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            narf_memory::x86_64::paging::translate(space.root, VirtAddr::new(va)).map(PhysAddr::raw)
        }
        #[cfg(target_arch = "aarch64")]
        {
            narf_memory::aarch64::paging::translate(space.root, VirtAddr::new(va))
                .map(PhysAddr::raw)
        }
    }
}

fn smoke_abi_device_mmap_publishes_then_relocates() -> TestResult {
    let mut owned = Vec::new();
    for _ in 0..4 {
        match narf_memory::alloc_frame() {
            Ok(frame) => owned.push(frame.start_address()),
            Err(_) => {
                for &phys in &owned {
                    narf_memory::free_frame(narf_memory::PhysFrame::new(phys));
                }
                return TestResult::Skip("device frame allocation failed");
            }
        }
    }
    let old: Vec<u64> = owned[..2].iter().map(|p| p.raw()).collect();
    let new: Vec<u64> = owned[2..].iter().map(|p| p.raw()).collect();
    *FRAMES.lock() = old.clone();
    PUBLISHED.store(0, Ordering::Release);
    PUBLISHED_AFTER_LEAVES.store(0, Ordering::Release);
    TOKENS_DROPPED.store(0, Ordering::Release);
    CENSUS_EXTRA.store(0, Ordering::Release);
    let result = with_setup(|| {
        // SAFETY: paging is enabled; the root is owned by this test.
        let space = Arc::new(
            unsafe { AddressSpace::new_for_user() }.map_err(|_| "address space allocation")?,
        );
        *DEVICE_AS.lock() = Some(space.clone());
        crate::handlers::install_address_space_lookup(lookup_device_as);
        let outcome = (|| -> Result<(), &'static str> {
            let fd = crate::fd::install(
                FAKE_TASK,
                crate::fd::FdEntry {
                    ops: Arc::new(Device),
                    offset: 0,
                    flags: 0,
                    status_flags: O_RDWR,
                },
            )
            .ok_or("fd install failed")? as u64;
            let base = match call(
                Syscall::Mmap.raw(),
                SyscallArgs {
                    arg0: 0,
                    arg1: 2 * PAGE,
                    arg2: PROT_READ | PROT_WRITE,
                    arg3: MAP_SHARED,
                    arg4: fd,
                    arg5: 0,
                },
            ) {
                Some(addr) if addr > 0 => addr as u64,
                _ => return Err("MAP_SHARED device mmap failed"),
            };
            if PUBLISHED.load(Ordering::Acquire) != 1
                || PUBLISHED_AFTER_LEAVES.load(Ordering::Acquire) != 1
            {
                return Err("mmap_published was not called once, after the leaves");
            }
            if call(Syscall::MProtect.raw(), a2(base + PAGE, PAGE, PROT_NONE)) != Some(0)
                || translated(&space, base + PAGE).is_some()
            {
                return Err("PROT_NONE did not revoke the second leaf");
            }
            // A driver commit error comes back unchanged; old aliases stay.
            let mut inside = None;
            let failed =
                narf_filesystem::mmap_relocation::relocate(&old, &new, census, &mut || {
                    inside = Some(translated(&space, base));
                    Err(FsError::NoSpace)
                });
            if failed != Err(FsError::NoSpace)
                || inside != Some(None)
                || translated(&space, base) != Some(old[0])
            {
                return Err("driver commit error was not preserved with old aliases");
            }
            // A metadata alias outside the snapshot (fork gap) refuses.
            CENSUS_EXTRA.store(1, Ordering::Release);
            let mut called = false;
            let refused =
                narf_filesystem::mmap_relocation::relocate(&old, &new, census, &mut || {
                    called = true;
                    Ok(())
                });
            CENSUS_EXTRA.store(0, Ordering::Release);
            if refused != Err(FsError::Busy) || called {
                return Err("census shortfall did not refuse before commit");
            }
            narf_filesystem::mmap_relocation::relocate(&old, &new, census, &mut || Ok(()))
                .map_err(|_| "published device mapping refused relocation")?;
            let metadata = space.lookup(VirtAddr::new(base + PAGE)).and_then(|r| {
                r.phys
                    .get(((base + PAGE - r.base.as_u64()) / PAGE) as usize)
                    .copied()
            });
            if translated(&space, base) != Some(new[0])
                || translated(&space, base + PAGE).is_some()
                || metadata.map(PhysAddr::raw) != Some(new[1])
            {
                return Err("relocation did not rebind present and PROT_NONE aliases");
            }
            if call(Syscall::Munmap.raw(), a1(base, 2 * PAGE)) != Some(0) {
                return Err("munmap of the device mapping failed");
            }
            let _ = call(Syscall::Close.raw(), a0(fd));
            if TOKENS_DROPPED.load(Ordering::Acquire) != 1 {
                return Err("munmap did not release the device lifetime token");
            }
            Ok(())
        })();
        crate::handlers::restore_address_space_lookup(None);
        *DEVICE_AS.lock() = None;
        outcome
    });
    FRAMES.lock().clear();
    for &phys in &owned {
        narf_memory::free_frame(narf_memory::PhysFrame::new(phys));
    }
    result
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_device_mmap_publishes_then_relocates
);

// ── Memory type: a device asks for write-combining through mmap(2) ──────

static WC_FRAMES: IrqSafeSpinLock<Vec<u64>> = IrqSafeSpinLock::new(Vec::new());

/// A device whose `mmap_backing` asks for write-combining, as a Linux
/// driver applies `pgprot_writecombine` to `vm_page_prot`.
struct WcDevice;
impl FileOps for WcDevice {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        alloc::boxed::Box::pin(async { Ok(0) })
    }
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        alloc::boxed::Box::pin(async move { Ok(buf.len()) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }
    fn mmap_backing(&self, offset: u64, len: usize) -> Result<MmapBacking, FsError> {
        let frames = WC_FRAMES.lock();
        let first = (offset / PAGE) as usize;
        let count = len / PAGE as usize;
        Ok(MmapBacking {
            frames: frames
                .get(first..first + count)
                .ok_or(FsError::InvalidData)?
                .to_vec(),
            lifetime: None,
            memory_type: narf_memory::MemoryType::WriteCombining,
        })
    }
}

fn wc_census(phys: u64) -> usize {
    usize::from(WC_FRAMES.lock().contains(&phys))
}

/// A physical page that is not System RAM (past every memory block, 1 GiB
/// aligned, at least 4 GiB). Only ever placed in descriptors of a root that
/// is never activated; never dereferenced.
fn non_ram_phys() -> Option<u64> {
    const GIB: u64 = 1 << 30;
    let end = narf_memory::memory_blocks()
        .iter()
        .map(|b| b.start + narf_memory::MEMORY_BLOCK_SIZE)
        .max()
        .unwrap_or(0)
        .max(4 * GIB);
    let phys = end.div_ceil(GIB) * GIB + GIB;
    (!narf_memory::frame::is_system_ram(PhysAddr::new(phys))).then_some(phys)
}

/// The memory-type selector bits of the leaf mapping `va`.
fn leaf_selector(space: &AddressSpace, va: u64) -> Option<u64> {
    // SAFETY: the test-owned root is live and never activated.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            use narf_memory::x86_64::paging::{leaf_flags_at, PtFlags};
            leaf_flags_at(space.root, VirtAddr::new(va))
                .map(|(flags, _)| flags.bits() & PtFlags::CACHE_MASK_4K.bits())
        }
        #[cfg(target_arch = "aarch64")]
        {
            use narf_memory::aarch64::paging::{leaf_flags_at, PtFlags};
            leaf_flags_at(space.root, VirtAddr::new(va))
                .map(|(flags, _)| flags.bits() & PtFlags::ATTR_MASK.bits())
        }
    }
}

fn wc_selector() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        narf_memory::memtype::x86_leaf_bits_4k(narf_memory::MemoryType::WriteCombining).bits()
    }
    #[cfg(target_arch = "aarch64")]
    {
        narf_memory::aarch64::paging::PtFlags::ATTR_NORMAL_NC.bits()
    }
}

/// End to end through `sys_mmap`: a device page gets a write-combining
/// leaf, a RAM page in the same mapping gets write-back (the alias rule),
/// and relocating the device page onto RAM re-derives the type from the
/// new frame — the moved leaf is write-back.
fn smoke_abi_device_mmap_write_combining() -> TestResult {
    let Some(dev) = non_ram_phys() else {
        return TestResult::Skip("no non-RAM physical address to test with");
    };
    let mut owned = Vec::new();
    for _ in 0..2 {
        match narf_memory::alloc_frame() {
            Ok(frame) => owned.push(frame.start_address()),
            Err(_) => {
                for &phys in &owned {
                    narf_memory::free_frame(narf_memory::PhysFrame::new(phys));
                }
                return TestResult::Skip("frame allocation failed");
            }
        }
    }
    let ram = owned[0].raw();
    let relocation_target = owned[1].raw();
    *WC_FRAMES.lock() = alloc::vec![dev, ram];
    let result = with_setup(|| {
        // SAFETY: paging is enabled; the root is owned by this test.
        let space = Arc::new(
            unsafe { AddressSpace::new_for_user() }.map_err(|_| "address space allocation")?,
        );
        *DEVICE_AS.lock() = Some(space.clone());
        crate::handlers::install_address_space_lookup(lookup_device_as);
        let outcome = (|| -> Result<(), &'static str> {
            let fd = crate::fd::install(
                FAKE_TASK,
                crate::fd::FdEntry {
                    ops: Arc::new(WcDevice),
                    offset: 0,
                    flags: 0,
                    status_flags: O_RDWR,
                },
            )
            .ok_or("fd install failed")? as u64;
            let base = match call(
                Syscall::Mmap.raw(),
                SyscallArgs {
                    arg0: 0,
                    arg1: 2 * PAGE,
                    arg2: PROT_READ | PROT_WRITE,
                    arg3: MAP_SHARED,
                    arg4: fd,
                    arg5: 0,
                },
            ) {
                Some(addr) if addr > 0 => addr as u64,
                _ => return Err("MAP_SHARED WC device mmap failed"),
            };
            let region_type = space
                .lookup(VirtAddr::new(base))
                .map(|r| r.perms.memory_type());
            if region_type != Some(narf_memory::MemoryType::WriteCombining) {
                return Err("the VMA did not record the device's memory type");
            }
            if translated(&space, base) != Some(dev)
                || leaf_selector(&space, base) != Some(wc_selector())
            {
                return Err("device page is not write-combining");
            }
            if leaf_selector(&space, base + PAGE) != Some(0) {
                return Err("RAM page in a WC mapping is not write-back");
            }
            // Move the device page onto RAM: the rebuilt leaf must follow the
            // new frame and drop to write-back.
            narf_filesystem::mmap_relocation::relocate(
                &[dev],
                &[relocation_target],
                wc_census,
                &mut || Ok(()),
            )
            .map_err(|_| "relocation of the WC page refused")?;
            if translated(&space, base) != Some(relocation_target)
                || leaf_selector(&space, base) != Some(0)
            {
                return Err("WC leaf relocated onto RAM kept a non-WB type");
            }
            if call(Syscall::Munmap.raw(), a1(base, 2 * PAGE)) != Some(0) {
                return Err("munmap of the WC mapping failed");
            }
            let _ = call(Syscall::Close.raw(), a0(fd));
            Ok(())
        })();
        crate::handlers::restore_address_space_lookup(None);
        *DEVICE_AS.lock() = None;
        outcome
    });
    WC_FRAMES.lock().clear();
    for &phys in &owned {
        narf_memory::free_frame(narf_memory::PhysFrame::new(phys));
    }
    result
}
kernel_test_in!("syscall_abi", smoke_abi_device_mmap_write_combining);
