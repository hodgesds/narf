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
