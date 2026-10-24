//! Fault-around: one file fault installs a bounded window of
//! neighbouring pages (#734).
//!
//! Before this lane, a fault filled exactly the faulted page, so a
//! sequential scan of a cold file trapped once per page. These tests
//! prove installation — not just population — with the two witnesses
//! that cannot be faked: after a single demand fault, the window's
//! pages are **backed** (`mapped_frame` finds a frame without any
//! further fault call), and the counting block device shows the
//! window's data sectors moved exactly once, at that first fault.
//!
//! The fixture is the generic-fallback path end to end: a byte-built
//! FAT12 volume on a counting `RamBlockDevice`, a real address space,
//! real syscall dispatch — the same harness shape as
//! `abi_readahead_tests`, whose per-request read accounting this file
//! deliberately mirrors.

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
const O_RDWR: u32 = 2;
const PAGE: u64 = 4096;
const SECTOR: u64 = 512;
/// First sector of the fixture image's data area (boot + 2 FATs + root
/// directory occupy sectors 0..4 in `fat12_image`).
const DATA_LBA: u64 = 4;
/// The fault-around window: 16 pages (64 KiB), Linux's
/// `fault_around_bytes`. A page is 8 data sectors in this fixture.
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

static FA_AS: IrqSafeSpinLock<Option<Arc<AddressSpace>>> = IrqSafeSpinLock::new(None);

fn lookup_fa_as() -> Option<Arc<AddressSpace>> {
    FA_AS.lock().clone()
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

    /// A genuinely second open of the fixture file — a fresh lookup, so
    /// a distinct node object; the #698 identity contract is what makes
    /// it the *same* file to the cache — installed as its own fd.
    fn reopen(&self) -> Result<u64, &'static str> {
        let ops =
            crate::handlers::poll_io_to_completion(self.volume.root().lookup_async("NARF.TXT"))
                .and_then(|r| r.ok())
                .ok_or("second lookup of NARF.TXT failed")?;
        install_rdwr(&ops)
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
        *FA_AS.lock() = Some(Arc::clone(&aspace));
        crate::handlers::install_address_space_lookup(lookup_fa_as);
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
        *FA_AS.lock() = None;
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
/// FATs). Same builder as `abi_readahead_tests`.
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
        return Err("a page inside the fault-around window is not installed");
    }
    Ok(())
}

/// Require page `index` of the mapping at `base` to be unbacked.
fn assert_unbacked(aspace: &AddressSpace, base: u64, index: u64) -> Result<(), &'static str> {
    if mapped_frame(aspace, base + index * PAGE).is_some() {
        return Err("a page outside the fault-around window was installed");
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

fn pwrite(fd: u64, buf: &[u8], offset: u64) -> Option<i64> {
    call(
        Syscall::Pwrite64.raw(),
        a3(fd, buf.as_ptr() as u64, buf.len() as u64, offset),
    )
}

/// One fault on page 0 installs the whole first window (pages 0..16)
/// and nothing beyond it; the window's sectors are read exactly once,
/// at that fault; a fault on page 16 then installs the second window.
fn smoke_fault_around_window() -> TestResult {
    let bytes = content(0x31, 32 * PAGE as usize);
    with_fat_file(&bytes, |fx| {
        let base = map_shared(fx.fd, 32 * PAGE)?;
        if fx.data_blocks_read() != 0 {
            return Err("mapping the file read its data before any fault");
        }
        assert_unbacked(&fx.aspace, base, 0)?;
        fault(&fx.aspace, base)?;
        // The fault on page 0 read the whole window's data exactly once.
        if fx.data_blocks_read() != WINDOW_PAGES * PAGE_SECTORS {
            return Err("the first fault did not read exactly the window's sectors");
        }
        for index in 0..WINDOW_PAGES {
            assert_backed(&fx.aspace, base, index)?;
        }
        for index in WINDOW_PAGES..32 {
            assert_unbacked(&fx.aspace, base, index)?;
        }
        // The installed pages serve the file's bytes with no new reads:
        // touching them is not a fault at all any more.
        let before = fx.data_blocks_read();
        if mapped_bytes(&fx.aspace, base, 16 * PAGE as usize)? != bytes[..16 * PAGE as usize] {
            return Err("the installed window does not serve the file's bytes");
        }
        if fx.data_blocks_read() != before {
            return Err("reading the installed window re-read data sectors");
        }
        // A fault in the second window installs that window too.
        fault(&fx.aspace, base + WINDOW_PAGES * PAGE)?;
        if fx.data_blocks_read() != 32 * PAGE_SECTORS {
            return Err("the second window's sectors were not read exactly once");
        }
        for index in WINDOW_PAGES..32 {
            assert_backed(&fx.aspace, base, index)?;
        }
        if mapped_bytes(&fx.aspace, base, bytes.len())? != bytes {
            return Err("the full mapping does not serve the file's bytes");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/fault_around/window", smoke_fault_around_window);

/// The window is aligned, not forward-only: a first fault on page 20
/// installs pages 16..32 (the aligned window containing it), including
/// the pages *before* the fault, and leaves pages 0..16 unbacked.
fn smoke_fault_around_aligned_window() -> TestResult {
    let bytes = content(0x59, 32 * PAGE as usize);
    with_fat_file(&bytes, |fx| {
        let base = map_shared(fx.fd, 32 * PAGE)?;
        fault(&fx.aspace, base + 20 * PAGE)?;
        if fx.data_blocks_read() != WINDOW_PAGES * PAGE_SECTORS {
            return Err("the fault did not read exactly its window's sectors");
        }
        for index in 0..WINDOW_PAGES {
            assert_unbacked(&fx.aspace, base, index)?;
        }
        for index in WINDOW_PAGES..32 {
            assert_backed(&fx.aspace, base, index)?;
        }
        if mapped_bytes(&fx.aspace, base + WINDOW_PAGES * PAGE, 16 * PAGE as usize)?
            != bytes[16 * PAGE as usize..]
        {
            return Err("the aligned window does not serve the file's bytes");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/fault_around/aligned_window",
    smoke_fault_around_aligned_window
);

/// The window clamps at EOF: in a mapping longer than the file, a fault
/// on the last file page installs the window's in-file pages only —
/// nothing at or past EOF is installed, no data past EOF is read, and a
/// demand fault on a past-EOF page still fails as SIGBUS.
fn smoke_fault_around_eof_clamp() -> TestResult {
    let bytes = content(0x77, 20 * PAGE as usize);
    with_fat_file(&bytes, |fx| {
        // The mapping is four pages longer than the file.
        let base = map_shared(fx.fd, 24 * PAGE)?;
        fault(&fx.aspace, base + 19 * PAGE)?;
        // Pages 16..20 are the window's in-file part: 4 pages of data.
        if fx.data_blocks_read() != 4 * PAGE_SECTORS {
            return Err("the fault read data other than the window's in-file pages");
        }
        for index in 16..20 {
            assert_backed(&fx.aspace, base, index)?;
        }
        for index in 20..24 {
            assert_unbacked(&fx.aspace, base, index)?;
        }
        if mapped_bytes(&fx.aspace, base + 16 * PAGE, 4 * PAGE as usize)?
            != bytes[16 * PAGE as usize..]
        {
            return Err("the clamped window does not serve the file's bytes");
        }
        // A page wholly past EOF still faults as SIGBUS (the demand
        // attempt errors and installs nothing).
        // SAFETY: `aspace` is a live user root and paging is enabled.
        let past_eof = unsafe { fx.aspace.demand_alloc_page(VirtAddr::new(base + 20 * PAGE)) };
        if past_eof.is_ok() {
            return Err("a fault past EOF unexpectedly succeeded");
        }
        assert_unbacked(&fx.aspace, base, 20)?;
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/fault_around/eof_clamp",
    smoke_fault_around_eof_clamp
);

/// A one-page file degenerates correctly: the window is just the page
/// itself, installed by its fault, with exactly its sectors read.
fn smoke_fault_around_one_page() -> TestResult {
    let bytes = content(0xA3, PAGE as usize);
    with_fat_file(&bytes, |fx| {
        let base = map_shared(fx.fd, PAGE)?;
        fault(&fx.aspace, base)?;
        if fx.data_blocks_read() != PAGE_SECTORS {
            return Err("the one-page fault did not read exactly the page's sectors");
        }
        assert_backed(&fx.aspace, base, 0)?;
        if mapped_bytes(&fx.aspace, base, PAGE as usize)? != bytes {
            return Err("the one-page mapping does not serve the file's bytes");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/fault_around/one_page",
    smoke_fault_around_one_page
);

/// An around-installed page is the canonical cache page, not a copy: a
/// `write(2)` through a second open lands in it via the #688 fold, and
/// the mapping serves the new bytes with no new device read and no new
/// fault. The same coherence holds for the window the written page
/// later faults in.
fn smoke_fault_around_write_coherence() -> TestResult {
    let bytes = content(0xC7, 32 * PAGE as usize);
    with_fat_file(&bytes, |fx| {
        let base = map_shared(fx.fd, 32 * PAGE)?;
        fault(&fx.aspace, base)?;
        assert_backed(&fx.aspace, base, 5)?;
        let fd2 = fx.reopen()?;
        let new_page = alloc::vec![0x3Cu8; PAGE as usize];
        if pwrite(fd2, &new_page, 5 * PAGE) != Some(PAGE as i64) {
            return Err("pwrite64 through the second open failed");
        }
        let before = fx.data_blocks_read();
        if mapped_bytes(&fx.aspace, base + 5 * PAGE, PAGE as usize)? != new_page {
            return Err("the around-installed page does not serve the written bytes");
        }
        if fx.data_blocks_read() != before {
            return Err("serving the written bytes re-read data sectors");
        }
        // A page in the second window, written before it is ever
        // faulted, faults in serving the new bytes exactly once.
        if pwrite(fd2, &new_page, 20 * PAGE) != Some(PAGE as i64) {
            return Err("second pwrite64 through the second open failed");
        }
        fault(&fx.aspace, base + 20 * PAGE)?;
        if mapped_bytes(&fx.aspace, base + 20 * PAGE, PAGE as usize)? != new_page {
            return Err("the second window does not serve the written bytes");
        }
        for index in WINDOW_PAGES..32 {
            assert_backed(&fx.aspace, base, index)?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/fault_around/write_coherence",
    smoke_fault_around_write_coherence
);
