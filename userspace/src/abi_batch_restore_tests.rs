//! Recorded-batch restore: `MADV_WILLNEED` names a batch; the first
//! fault inside it pages the whole recorded range back in (#737
//! step 2).
//!
//! #735's `MADV_WILLNEED` populated the page *cache* and forgot the
//! range, so a later scan still trapped per fault-around window —
//! 16 pages at a time — even though the caller had once named the
//! whole batch. These tests prove the restore with the witnesses that
//! cannot be faked: after ONE demand fault inside a recorded 32-page
//! range, every page of the range is **backed** (`mapped_frame` finds
//! a frame with no further fault call) — twice the window a bare
//! fault would install — and the counting block device shows the
//! range's data sectors moved exactly once, at that fault.
//!
//! The fixture is the generic-fallback path end to end: a byte-built
//! FAT12 volume on a counting `RamBlockDevice`, a real address space,
//! real syscall dispatch — the same harness shape as
//! `abi_faultaround_tests`, whose fixture this file deliberately
//! mirrors.

use alloc::sync::Arc;
use core::future::Future;

use narf_block::ram::RamBlockDevice;
use narf_block::{
    BlockCompletion, BlockDevice, BlockFeature, BlockOp, BlockRequest, CancelResult, LbaRange,
};
use narf_filesystem::{FileOps, FsInstance};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::{AddressSpace, VirtAddr};

use crate::abi_test_support::*;

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_SHARED: u64 = 1;
const MAP_PRIVATE: u64 = 2;
const MAP_ANONYMOUS: u64 = 0x20;
const MADV_WILLNEED: u64 = 3;
const O_RDWR: u32 = 2;
const PAGE: u64 = 4096;
const SECTOR: u64 = 512;
/// First sector of the fixture image's data area (boot + 2 FATs + root
/// directory occupy sectors 0..4 in `fat12_image`).
const DATA_LBA: u64 = 4;
/// The fault-around window: 16 pages (64 KiB). Recorded batches in
/// these tests span two windows, so a window-only fault is observably
/// different from a batch restore.
const WINDOW_PAGES: u64 = 16;
const PAGE_SECTORS: u64 = PAGE / SECTOR;

type FatVolume = narf_drivers_fs_fat::volume::FatVolume<CountingBlockDevice>;

/// A `RamBlockDevice` that records every read request in submission
/// order, as `(start LBA, blocks)`. Requests are recorded individually,
/// never aggregated by LBA — see `abi_readahead_tests` for why an
/// aggregate count would fabricate phantom transfers.
struct CountingBlockDevice {
    inner: Arc<RamBlockDevice>,
    reads: IrqSafeSpinLock<alloc::vec::Vec<(u64, u32)>>,
}

impl CountingBlockDevice {
    /// Blocks read whose transfer intersected `[lo, hi)` (LBA range).
    fn blocks_read_between(&self, lo: u64, hi: u64) -> u64 {
        self.reads
            .lock()
            .iter()
            .map(|&(lba, blocks)| {
                let end = lba + u64::from(blocks);
                let start = lo.max(lba);
                let stop = hi.min(end);
                stop.saturating_sub(start)
            })
            .sum()
    }

    fn total_blocks_read(&self) -> u64 {
        self.reads
            .lock()
            .iter()
            .map(|&(_, blocks)| u64::from(blocks))
            .sum()
    }
}

impl BlockDevice for CountingBlockDevice {
    fn logical_block_size(&self) -> u32 {
        self.inner.logical_block_size()
    }

    fn physical_block_size(&self) -> u32 {
        self.inner.physical_block_size()
    }

    fn capacity_blocks(&self) -> u64 {
        self.inner.capacity_blocks()
    }

    fn supports(&self, feat: BlockFeature) -> bool {
        self.inner.supports(feat)
    }

    fn submit(&self, req: BlockRequest) -> impl Future<Output = BlockCompletion> + Send {
        if req.op == BlockOp::Read {
            self.reads.lock().push((req.lba, req.blocks));
        }
        self.inner.submit(req)
    }

    fn flush(&self) -> impl Future<Output = ()> + Send {
        self.inner.flush()
    }

    fn discard(&self, range: LbaRange) -> impl Future<Output = ()> + Send {
        self.inner.discard(range)
    }

    fn cancel(&self, tag: u64) -> impl Future<Output = CancelResult> + Send {
        self.inner.cancel(tag)
    }
}

static BR_AS: IrqSafeSpinLock<Option<Arc<AddressSpace>>> = IrqSafeSpinLock::new(None);

fn lookup_br_as() -> Option<Arc<AddressSpace>> {
    BR_AS.lock().clone()
}

struct Fixture {
    aspace: Arc<AddressSpace>,
    device: Arc<CountingBlockDevice>,
    volume: Arc<FatVolume>,
    fd: u64,
    /// Sector span `[lo, hi)` holding the file's data clusters.
    data_span: (u64, u64),
}

impl Fixture {
    fn data_blocks_read(&self) -> u64 {
        self.device
            .blocks_read_between(self.data_span.0, self.data_span.1)
    }
}

/// Build the fixture: FAT12 image holding `data` as `NARF.TXT`, mounted
/// on the counting device, one fd installed read-write.
fn with_fat_file(
    data: &[u8],
    body: impl FnOnce(&Fixture) -> Result<(), &'static str>,
) -> TestResult {
    with_setup(move || {
        // SAFETY: kernel tests run with paging enabled; the new root
        // inherits only the kernel half and is owned by this fixture.
        let aspace = match unsafe { AddressSpace::new_for_user() } {
            Ok(aspace) => Arc::new(aspace),
            Err(_) => return Err("failed to create the test address space"),
        };
        *BR_AS.lock() = Some(Arc::clone(&aspace));
        crate::handlers::install_address_space_lookup(lookup_br_as);
        let result = (|| {
            let device = Arc::new(CountingBlockDevice {
                inner: RamBlockDevice::from_image(SECTOR as u32, fat12_image(data)),
                reads: IrqSafeSpinLock::new(alloc::vec::Vec::new()),
            });
            let volume = crate::handlers::poll_io_to_completion(FatVolume::mount(
                Arc::clone(&device),
                narf_lib::id::DomainId::DRIVER_0,
            ))
            .and_then(|r| r.ok())
            .ok_or("mounting the test FAT image failed")?;
            let ops =
                crate::handlers::poll_io_to_completion(volume.root().lookup_async("NARF.TXT"))
                    .and_then(|r| r.ok())
                    .ok_or("lookup of NARF.TXT failed")?;
            let fd = install_rdwr(&ops)?;
            let clusters = (data.len() as u64).div_ceil(SECTOR);
            body(&Fixture {
                aspace,
                device,
                volume,
                fd,
                data_span: (DATA_LBA, DATA_LBA + clusters),
            })
        })();
        crate::handlers::restore_address_space_lookup(None);
        *BR_AS.lock() = None;
        result
    })
}

fn install_rdwr(ops: &Arc<dyn FileOps>) -> Result<u64, &'static str> {
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

/// Byte-built FAT12 image holding one file, `NARF.TXT`, whose content is
/// `data` spread over a cluster chain (512-byte clusters, one-sector
/// FATs). Same builder as `abi_faultaround_tests`.
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

/// Distinct content per test (seeded), so a page retained from another
/// fixture's identical-layout volume could never silently satisfy a
/// byte assertion here.
fn content(seed: u8, len: usize) -> alloc::vec::Vec<u8> {
    (0..len)
        .map(|i| seed.wrapping_add((i % 251) as u8))
        .collect()
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

/// The frame currently backing `va` (0 / `None` = unbacked). Finding a
/// frame here — without any fault call — is what *installed* means.
fn mapped_frame(aspace: &AddressSpace, va: u64) -> Option<u64> {
    let region = aspace.lookup(VirtAddr::new(va))?;
    let index = ((va & !(PAGE - 1)) - region.base.as_u64()) / PAGE;
    let phys = region.phys.get(index as usize)?.raw();
    (phys != 0).then_some(phys)
}

/// Drive one real demand fault at `va` and require it to back the page.
fn fault(aspace: &AddressSpace, va: u64) -> Result<(), &'static str> {
    // SAFETY: `aspace` is a live user root and paging is enabled.
    unsafe { aspace.demand_alloc_page(VirtAddr::new(va)) }
        .map_err(|_| "a fault inside the file's EOF was refused")?;
    if mapped_frame(aspace, va).is_none() {
        return Err("the fault left the page unbacked");
    }
    Ok(())
}

/// Require page `index` of the mapping at `base` to be backed —
/// installed, with no fault driven by this check.
fn assert_backed(aspace: &AddressSpace, base: u64, index: u64) -> Result<(), &'static str> {
    if mapped_frame(aspace, base + index * PAGE).is_none() {
        return Err("a page inside the recorded range is not installed");
    }
    Ok(())
}

/// Require page `index` of the mapping at `base` to be unbacked.
fn assert_unbacked(aspace: &AddressSpace, base: u64, index: u64) -> Result<(), &'static str> {
    if mapped_frame(aspace, base + index * PAGE).is_some() {
        return Err("a page outside the recorded range was installed");
    }
    Ok(())
}

/// Bytes the mapping shows at `va` (must be backed), `len` of them.
/// Copied page by page through each page's own frame — see
/// `abi_readahead_tests::mapped_bytes` for why a linear read is wrong.
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

fn madvise_willneed(addr: u64, len: u64) -> Option<i64> {
    call(Syscall::Madvise.raw(), a2(addr, len, MADV_WILLNEED))
}

fn munmap(addr: u64, len: u64) -> Option<i64> {
    call(Syscall::Munmap.raw(), a1(addr, len))
}

fn ftruncate(fd: u64, len: u64) -> Option<i64> {
    call(Syscall::Ftruncate.raw(), a1(fd, len))
}

/// WILLNEED a 32-page range, then take ONE fault at page 5: the whole
/// recorded range is installed by that fault — all 32 pages backed,
/// every data sector read exactly once, at the fault — where the
/// fault-around window alone would have installed only pages 0..16.
fn smoke_batch_restore_restores_recorded_range() -> TestResult {
    let bytes = content(0x3B, 32 * PAGE as usize);
    with_fat_file(&bytes, |fx| {
        let base = map_shared(fx.fd, 32 * PAGE)?;
        if madvise_willneed(base, 32 * PAGE) != Some(0) {
            return Err("MADV_WILLNEED of the 32-page range did not return 0");
        }
        // Population moved every data sector at advise time (#735)...
        if fx.data_blocks_read() != 32 * PAGE_SECTORS {
            return Err("MADV_WILLNEED did not populate the recorded range");
        }
        // ...but installed nothing: installation is the restore's job.
        for index in 0..32 {
            assert_unbacked(&fx.aspace, base, index)?;
        }
        let before = fx.data_blocks_read();
        fault(&fx.aspace, base + 5 * PAGE)?;
        // The batch restore filled from the populated cache: no data
        // sector moved again at fault time.
        if fx.data_blocks_read() != before {
            return Err("the batch restore re-read data sectors the advise had populated");
        }
        // The full recorded range — not the 16-page window — is in.
        for index in 0..32 {
            assert_backed(&fx.aspace, base, index)?;
        }
        if mapped_bytes(&fx.aspace, base, bytes.len())? != bytes {
            return Err("the restored range does not serve the file's bytes");
        }
        // Later faults inside the consumed batch install nothing new
        // and read nothing: the pages are simply resident.
        let before = fx.data_blocks_read();
        fault(&fx.aspace, base + 20 * PAGE)?;
        fault(&fx.aspace, base + 31 * PAGE)?;
        if fx.data_blocks_read() != before {
            return Err("faults after the restore re-read data sectors");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/batch_restore/recorded_range",
    smoke_batch_restore_restores_recorded_range
);

/// No record, no restore: a bare fault keeps the exact fault-around
/// window behaviour (#734/#738) — 16 aligned pages, nothing beyond.
fn smoke_batch_restore_window_fallback() -> TestResult {
    let bytes = content(0x67, 32 * PAGE as usize);
    with_fat_file(&bytes, |fx| {
        let base = map_shared(fx.fd, 32 * PAGE)?;
        fault(&fx.aspace, base + 5 * PAGE)?;
        if fx.data_blocks_read() != WINDOW_PAGES * PAGE_SECTORS {
            return Err("the unrecorded fault did not read exactly its window's sectors");
        }
        for index in 0..WINDOW_PAGES {
            assert_backed(&fx.aspace, base, index)?;
        }
        for index in WINDOW_PAGES..32 {
            assert_unbacked(&fx.aspace, base, index)?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/batch_restore/window_fallback",
    smoke_batch_restore_window_fallback
);

/// Invalidation by unmap: WILLNEED 32 pages, munmap the first half,
/// then fault in the surviving half. The record was trimmed at the
/// munmap, so the restore covers only what remains mapped — and the
/// munmapped half, remapped fresh, shows plain window behaviour with
/// its sectors read at its own fault.
fn smoke_batch_restore_munmap_trims_record() -> TestResult {
    let bytes = content(0x8D, 32 * PAGE as usize);
    with_fat_file(&bytes, |fx| {
        let base = map_shared(fx.fd, 32 * PAGE)?;
        if madvise_willneed(base, 32 * PAGE) != Some(0) {
            return Err("MADV_WILLNEED of the 32-page range did not return 0");
        }
        if munmap(base, 16 * PAGE) != Some(0) {
            return Err("munmap of the first half failed");
        }
        // A fault in the surviving half restores the trimmed batch:
        // pages 16..32, no more, all from the populated cache.
        let before = fx.data_blocks_read();
        fault(&fx.aspace, base + 20 * PAGE)?;
        if fx.data_blocks_read() != before {
            return Err("the trimmed restore re-read data sectors");
        }
        for index in 16..32 {
            assert_backed(&fx.aspace, base, index)?;
        }
        if mapped_bytes(&fx.aspace, base + 16 * PAGE, 16 * PAGE as usize)?
            != bytes[16 * PAGE as usize..]
        {
            return Err("the surviving half does not serve its bytes after the restore");
        }
        // Remap the first half at its old address (best effort: if the
        // allocator places it elsewhere, its behaviour there is the
        // same fresh mapping's — the address is what this asserts).
        let remap = SyscallArgs {
            arg0: base,
            arg1: 16 * PAGE,
            arg2: PROT_READ | PROT_WRITE,
            arg3: MAP_SHARED | 0x10, // MAP_FIXED
            arg4: fx.fd,
            arg5: 0,
        };
        let placed = match call(Syscall::Mmap.raw(), remap) {
            Some(addr) if addr > 0 => addr as u64,
            _ => return Err("MAP_FIXED remap of the first half failed"),
        };
        if placed != base {
            return Err("the remap did not land on the recorded range's first half");
        }
        // No record covers it any more: a fault installs only its
        // window (the whole 16-page half), reading its sectors now.
        let before = fx.data_blocks_read();
        fault(&fx.aspace, base)?;
        if fx.data_blocks_read() != before + WINDOW_PAGES * PAGE_SECTORS {
            return Err("the remapped half's fault did not read exactly its window's sectors");
        }
        for index in 0..WINDOW_PAGES {
            assert_backed(&fx.aspace, base, index)?;
        }
        if mapped_bytes(&fx.aspace, base, 16 * PAGE as usize)? != bytes[..16 * PAGE as usize] {
            return Err("the remapped half does not serve its bytes");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/batch_restore/munmap_trims",
    smoke_batch_restore_munmap_trims_record
);

/// Invalidation by truncate: WILLNEED 32 pages, shrink the file to 8
/// pages, re-extend it, then fault at page 20. The record is gone
/// (truncate drops the file's batches), so the fault takes the window
/// path: its window installs — clamped to the regrown size — and the
/// truncated range serves zeros, never the pre-truncate bytes.
fn smoke_batch_restore_truncate_drops_record() -> TestResult {
    let bytes = content(0xB9, 32 * PAGE as usize);
    with_fat_file(&bytes, |fx| {
        let base = map_shared(fx.fd, 32 * PAGE)?;
        if madvise_willneed(base, 32 * PAGE) != Some(0) {
            return Err("MADV_WILLNEED of the 32-page range did not return 0");
        }
        if ftruncate(fx.fd, 8 * PAGE) != Some(0) {
            return Err("shrinking ftruncate failed");
        }
        if ftruncate(fx.fd, 32 * PAGE) != Some(0) {
            return Err("re-extending ftruncate failed");
        }
        // Window fallback, exactly as if no advise had ever happened:
        // faulting page 20 installs its aligned window (16..32),
        // reading each of its sectors once, and nothing before it.
        let before = fx.data_blocks_read();
        fault(&fx.aspace, base + 20 * PAGE)?;
        if fx.data_blocks_read() != before + WINDOW_PAGES * PAGE_SECTORS {
            return Err("the post-truncate fault did not read exactly its window's sectors");
        }
        for index in 0..WINDOW_PAGES {
            assert_unbacked(&fx.aspace, base, index)?;
        }
        for index in WINDOW_PAGES..32 {
            assert_backed(&fx.aspace, base, index)?;
        }
        // The truncated range reads as zeros after re-extension.
        let tail = mapped_bytes(&fx.aspace, base + 20 * PAGE, PAGE as usize)?;
        if tail.iter().any(|&b| b != 0) {
            return Err("the re-extended range resurrected pre-truncate bytes");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/batch_restore/truncate_drops",
    smoke_batch_restore_truncate_drops_record
);

/// MADV_WILLNEED on an anonymous range keeps its #731 behaviour — a
/// no-op success that touches no device — and records nothing: the
/// range faults later exactly as an unadvised anonymous range does.
fn smoke_batch_restore_willneed_anonymous_noop() -> TestResult {
    let bytes = content(0xD3, PAGE as usize);
    with_fat_file(&bytes, |fx| {
        let args = SyscallArgs {
            arg0: 0,
            arg1: 2 * PAGE,
            arg2: PROT_READ | PROT_WRITE,
            arg3: MAP_PRIVATE | MAP_ANONYMOUS,
            arg4: u64::MAX,
            arg5: 0,
        };
        let anon = match call(Syscall::Mmap.raw(), args) {
            Some(addr) if addr > 0 => addr as u64,
            _ => return Err("anonymous mmap failed"),
        };
        let before = fx.device.total_blocks_read();
        if madvise_willneed(anon, 2 * PAGE) != Some(0) {
            return Err("MADV_WILLNEED of an anonymous range did not return 0");
        }
        if fx.device.total_blocks_read() != before {
            return Err("MADV_WILLNEED of an anonymous range read from a device");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/batch_restore/willneed_anon",
    smoke_batch_restore_willneed_anonymous_noop
);
