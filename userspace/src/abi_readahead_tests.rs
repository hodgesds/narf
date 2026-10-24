//! Readahead population: `readahead(2)` and `MADV_WILLNEED` fill the
//! shared page cache (#731).
//!
//! Both syscalls used to validate their arguments and populate nothing,
//! so a caller following the Linux contract paid one synchronous device
//! read per page at fault time anyway. These tests prove population
//! with the one witness that cannot be faked — a counting block device:
//! the file's data sectors must be read **at advise time**, and reading
//! them again at fault time is a failure. A return of 0 alone would
//! prove nothing (the old no-op returned 0 too).
//!
//! The fixture is the generic-fallback path end to end: a byte-built
//! FAT12 volume on a counting `RamBlockDevice`, a real address space,
//! real syscall dispatch — the same harness shape as
//! `abi_truncate_unmap_tests`.

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

type FatVolume = narf_drivers_fs_fat::volume::FatVolume<CountingBlockDevice>;

/// A `RamBlockDevice` that records every read request in submission
/// order, as `(start LBA, blocks)`. Filesystems above it see an
/// ordinary device; the test reads the log to prove *when* the file's
/// data sectors moved.
///
/// Requests are recorded individually, never aggregated by LBA: the
/// FAT driver re-reads its one FAT sector for nearly every cluster hop,
/// so an aggregate count at that LBA would masquerade as one enormous
/// contiguous transfer overlapping the data area — a measurement
/// artifact that cost this lane a long detour. Per-request records
/// keep `blocks_read_between` honest: it sums real overlaps only.
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

static RA_AS: IrqSafeSpinLock<Option<Arc<AddressSpace>>> = IrqSafeSpinLock::new(None);

fn lookup_ra_as() -> Option<Arc<AddressSpace>> {
    RA_AS.lock().clone()
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
        *RA_AS.lock() = Some(Arc::clone(&aspace));
        crate::handlers::install_address_space_lookup(lookup_ra_as);
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
        *RA_AS.lock() = None;
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
/// FATs). Same builder as `abi_truncate_unmap_tests`.
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

/// The frame currently backing `va` (0 / `None` = unbacked).
fn mapped_frame(aspace: &AddressSpace, va: u64) -> Option<u64> {
    let region = aspace.lookup(VirtAddr::new(va))?;
    let index = ((va & !(PAGE - 1)) - region.base.as_u64()) / PAGE;
    let phys = region.phys.get(index as usize)?.raw();
    (phys != 0).then_some(phys)
}

/// Touch `va` the way a user access would: a no-op when the page is
/// already resident (a fully populated run is installed eagerly at
/// `mmap` time), a demand fault otherwise.
fn fault(aspace: &AddressSpace, va: u64) -> Result<(), &'static str> {
    if mapped_frame(aspace, va).is_some() {
        return Ok(());
    }
    // SAFETY: `aspace` is a live user root and paging is enabled.
    unsafe { aspace.demand_alloc_page(VirtAddr::new(va)) }
        .map_err(|_| "a fault inside the file's EOF was refused")?;
    if mapped_frame(aspace, va).is_none() {
        return Err("the fault left the page unbacked");
    }
    Ok(())
}

/// Bytes the mapping shows at `va` (must be backed), `len` of them.
///
/// Copied page by page through each page's own frame: the frames
/// backing one mapping are not physically contiguous, so a single
/// linear read from the first frame would run off into unrelated
/// physical memory and report garbage for every page after the first.
/// (That exact mistake — plus a per-LBA-aggregating read counter that
/// fabricated phantom transfers — accounts for this lane's two long
/// "kernel bug" detours; both were harness bugs, found by dumping the
/// device request sequence and bisecting against the fault path.)
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

fn readahead(fd: u64, offset: u64, count: u64) -> Option<i64> {
    call(Syscall::Readahead.raw(), a2(fd, offset, count))
}

fn madvise_willneed(addr: u64, len: u64) -> Option<i64> {
    call(Syscall::Madvise.raw(), a2(addr, len, MADV_WILLNEED))
}

fn pwrite(fd: u64, buf: &[u8], offset: u64) -> Option<i64> {
    call(
        Syscall::Pwrite64.raw(),
        a3(fd, buf.as_ptr() as u64, buf.len() as u64, offset),
    )
}

/// readahead(2) reads the file's data sectors at advise time; faulting
/// the range afterwards reads none of them again and serves the bytes.
fn smoke_readahead_populates() -> TestResult {
    let bytes = content(0x11, 3 * PAGE as usize);
    with_fat_file(&bytes, |fx| {
        if fx.data_blocks_read() != 0 {
            return Err("the fixture read file data before any advise");
        }
        if readahead(fx.fd, 0, 3 * PAGE) != Some(0) {
            return Err("readahead of the whole file did not return 0");
        }
        // 3 pages = 24 data sectors, each exactly once.
        if fx.data_blocks_read() != 24 {
            return Err("readahead did not read the file's data sectors at advise time");
        }
        let base = map_shared(fx.fd, 3 * PAGE)?;
        let before = fx.data_blocks_read();
        for page in 0..3 {
            fault(&fx.aspace, base + page * PAGE)?;
        }
        if fx.data_blocks_read() != before {
            return Err("faults after readahead re-read data sectors from the device");
        }
        if mapped_bytes(&fx.aspace, base, 3 * PAGE as usize)? != bytes {
            return Err("the mapping does not serve the file's bytes after readahead");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/readahead/populates", smoke_readahead_populates);

/// The advised range is clamped to `i_size`: a range running past EOF
/// populates only the pages the file actually has (the final partial
/// page filled exactly as a fault fills it, tail zeroed), and a range
/// wholly past EOF populates nothing. Both calls still return 0.
fn smoke_readahead_eof_clamp() -> TestResult {
    let bytes = content(0x47, 3 * PAGE as usize - 100);
    with_fat_file(&bytes, |fx| {
        if readahead(fx.fd, 2 * PAGE, 16 * PAGE) != Some(0) {
            return Err("readahead past EOF did not return 0");
        }
        // Only page 2 exists in the advised range: its 8 sectors.
        if fx.data_blocks_read() != 8 {
            return Err("readahead past EOF populated other than the file's last page");
        }
        if readahead(fx.fd, 100 * PAGE, PAGE) != Some(0) {
            return Err("readahead wholly past EOF did not return 0");
        }
        if fx.data_blocks_read() != 8 {
            return Err("readahead wholly past EOF read from the device");
        }
        let base = map_shared(fx.fd, 3 * PAGE)?;
        // Fault-around (#734) legitimately installs pages 0–1 during
        // this fault — their sectors move then, for the first time, by
        // design. The claim under test is narrower: the *populated*
        // page's own sectors are not read again, so count only page
        // 2's sector range (8 sectors per page in this fixture).
        let page2_lo = DATA_LBA + 2 * (PAGE / SECTOR);
        let before = fx
            .device
            .blocks_read_between(page2_lo, page2_lo + PAGE / SECTOR);
        fault(&fx.aspace, base + 2 * PAGE)?;
        if fx
            .device
            .blocks_read_between(page2_lo, page2_lo + PAGE / SECTOR)
            != before
        {
            return Err("faulting the populated last page re-read its data sectors");
        }
        let tail = mapped_bytes(&fx.aspace, base + 2 * PAGE, PAGE as usize)?;
        if tail[..PAGE as usize - 100] != bytes[2 * PAGE as usize..] {
            return Err("the last page does not serve the file's tail bytes");
        }
        if tail[PAGE as usize - 100..].iter().any(|&b| b != 0) {
            return Err("the last page is not zero past EOF");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/readahead/eof_clamp", smoke_readahead_eof_clamp);

/// MADV_WILLNEED on a mapped-but-unfaulted range populates it: the data
/// sectors move at advise time, the later faults read none of them.
fn smoke_willneed_populates() -> TestResult {
    let bytes = content(0x83, 3 * PAGE as usize);
    with_fat_file(&bytes, |fx| {
        let base = map_shared(fx.fd, 3 * PAGE)?;
        if fx.data_blocks_read() != 0 {
            return Err("mapping the file read its data before any advise");
        }
        if mapped_frame(&fx.aspace, base).is_some() {
            return Err("page 0 is backed before any fault or advise");
        }
        if mapped_frame(&fx.aspace, base + PAGE).is_some() {
            return Err("page 1 is backed before any fault or advise");
        }
        if mapped_frame(&fx.aspace, base + 2 * PAGE).is_some() {
            return Err("page 2 is backed before any fault or advise");
        }
        if madvise_willneed(base, 3 * PAGE) != Some(0) {
            return Err("MADV_WILLNEED of the mapped range did not return 0");
        }
        if fx.data_blocks_read() != 24 {
            return Err("MADV_WILLNEED did not read the file's data sectors at advise time");
        }
        let before = fx.data_blocks_read();
        for page in 0..3 {
            fault(&fx.aspace, base + page * PAGE)?;
        }
        if fx.data_blocks_read() != before {
            return Err("faults after MADV_WILLNEED re-read data sectors from the device");
        }
        if mapped_bytes(&fx.aspace, base, 3 * PAGE as usize)? != bytes {
            return Err("the mapping does not serve the file's bytes after MADV_WILLNEED");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/readahead/willneed", smoke_willneed_populates);

/// MADV_WILLNEED on an anonymous range stays a no-op success (Linux's
/// anon case is swap readahead; there is nothing to populate) and, with
/// no file behind it, touches no device.
fn smoke_willneed_anonymous_noop() -> TestResult {
    let bytes = content(0xC1, PAGE as usize);
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
    "syscall_abi/readahead/willneed_anon",
    smoke_willneed_anonymous_noop
);

/// A populated page behaves exactly like a fault-filled one afterwards.
/// A `write(2)` through a *second* open updates the file and bumps its
/// generation; the populated copy — though the #688 fold also lands on
/// it — must not be *reused* by the next fault, because its recorded
/// generation is stale. The fault reloads from the device and serves
/// the new bytes. The untouched neighbour page is invalidated by the
/// same bump (the generation is per file, not per page) and also
/// reloads, serving its original bytes — since fault-around (#734),
/// that reload happens inside the first fault's window, not at the
/// neighbour's own fault; the assertions below model both steps.
fn smoke_readahead_write_coherence() -> TestResult {
    let bytes = content(0x29, 3 * PAGE as usize);
    with_fat_file(&bytes, |fx| {
        if readahead(fx.fd, 0, 3 * PAGE) != Some(0) {
            return Err("readahead did not return 0");
        }
        if fx.data_blocks_read() != 24 {
            return Err("readahead did not populate the file");
        }
        let fd2 = fx.reopen()?;
        let new_page = alloc::vec![0x5Au8; PAGE as usize];
        if pwrite(fd2, &new_page, PAGE) != Some(PAGE as i64) {
            return Err("pwrite64 through the second open failed");
        }
        let base = map_shared(fx.fd, 3 * PAGE)?;
        let before = fx.data_blocks_read();
        fault(&fx.aspace, base + PAGE)?;
        if mapped_bytes(&fx.aspace, base + PAGE, PAGE as usize)? != new_page {
            return Err("the fault after the write does not serve the new bytes");
        }
        if fx.data_blocks_read() <= before {
            return Err("the post-write fault reused the stale populated page");
        }
        // Fault-around (#734) widened the page-1 fault above into its
        // window, so the neighbour's invalidation already happened
        // *there*: its stale populated copy was reloaded from the
        // device during that fault (part of the read increase the
        // step above asserted) and the fresh page installed. What
        // remains to pin here is the guarantee itself — the stale
        // copy is never served: the neighbour is backed, faulting it
        // reads nothing more, and it serves its original bytes.
        if mapped_frame(&fx.aspace, base).is_none() {
            return Err("the neighbour page was not installed by fault-around");
        }
        let before0 = fx.data_blocks_read();
        fault(&fx.aspace, base)?;
        if mapped_bytes(&fx.aspace, base, 64)? != bytes[..64] {
            return Err("the untouched page does not serve its original bytes");
        }
        if fx.data_blocks_read() != before0 {
            return Err("faulting the reloaded neighbour re-read data sectors");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/readahead/write_coherence",
    smoke_readahead_write_coherence
);

// ── Read(2)-path readahead (#743) ──────────────────────────────────
//
// The tests above advise population explicitly (`readahead(2)`,
// `MADV_WILLNEED`). These prove the implicit path: an ordinary
// sequential `read(2)` stream populates ahead of itself through the
// per-open-description pattern state, with the same counting device
// as the witness. Sector arithmetic throughout: one page is 8 data
// sectors in this fixture; the initial window is 128 KiB = 32 pages
// = 256 sectors; the window doubles after each populated window.

fn read_into(fd: u64, buf: &mut [u8]) -> Option<i64> {
    call(
        Syscall::Read.raw(),
        a2(fd, buf.as_mut_ptr() as u64, buf.len() as u64),
    )
}

fn pread_into(fd: u64, buf: &mut [u8], offset: u64) -> Option<i64> {
    call(
        Syscall::Pread64.raw(),
        a3(fd, buf.as_mut_ptr() as u64, buf.len() as u64, offset),
    )
}

fn lseek_set(fd: u64, offset: u64) -> Option<i64> {
    call(Syscall::Lseek.raw(), a2(fd, offset, 0))
}

/// Two sequential page reads open the initial window: the first only
/// candidates the stream (no speculative I/O), the second confirms it
/// and populates 128 KiB ahead of the consumed bytes. The served
/// bytes still come from the ordinary read path and are unchanged.
fn smoke_read_readahead_sequential_populates() -> TestResult {
    let bytes = content(0x31, 512 * 1024);
    with_fat_file(&bytes, |fx| {
        let mut buf = alloc::vec![0u8; PAGE as usize];
        if fx.data_blocks_read() != 0 {
            return Err("the fixture read file data before any read");
        }
        if read_into(fx.fd, &mut buf) != Some(PAGE as i64) {
            return Err("first sequential read did not return a full page");
        }
        if buf[..] != bytes[..PAGE as usize] {
            return Err("first sequential read served the wrong bytes");
        }
        // Candidate only: exactly the requested page's 8 sectors moved.
        if fx.data_blocks_read() != 8 {
            return Err("the first read of a stream already speculated");
        }
        if read_into(fx.fd, &mut buf) != Some(PAGE as i64) {
            return Err("second sequential read did not return a full page");
        }
        if buf[..] != bytes[PAGE as usize..2 * PAGE as usize] {
            return Err("second sequential read served the wrong bytes");
        }
        // 16 served sectors + the 256-sector initial window (pages
        // 2..34) populated ahead of the consumption offset.
        if fx.data_blocks_read() != 272 {
            return Err("the confirmed stream did not populate the initial window");
        }
        let window_lo = DATA_LBA + 16;
        if fx.device.blocks_read_between(window_lo, window_lo + 256) != 256 {
            return Err("the populated window is not the span ahead of the stream");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/read_readahead/sequential_populates",
    smoke_read_readahead_sequential_populates
);

/// Scattered positioned reads never confirm a stream, so they cause
/// no speculative device reads at all; and a seek — even to the exact
/// offset the stream would have continued at — resets the pattern,
/// so the read after it only candidates afresh.
fn smoke_read_readahead_random_and_seek_no_speculation() -> TestResult {
    let bytes = content(0x52, 512 * 1024);
    with_fat_file(&bytes, |fx| {
        let mut buf = alloc::vec![0u8; PAGE as usize];
        for page in [0u64, 64, 32, 96] {
            if pread_into(fx.fd, &mut buf, page * PAGE) != Some(PAGE as i64) {
                return Err("a scattered pread did not return a full page");
            }
        }
        // Four requested pages, 8 sectors each, and nothing else.
        if fx.data_blocks_read() != 32 {
            return Err("scattered reads caused speculative device reads");
        }
        let fd2 = fx.reopen()?;
        if read_into(fd2, &mut buf) != Some(PAGE as i64) {
            return Err("the seek-test stream's first read failed");
        }
        if lseek_set(fd2, PAGE) != Some(PAGE as i64) {
            return Err("lseek to the continuation offset failed");
        }
        if read_into(fd2, &mut buf) != Some(PAGE as i64) {
            return Err("the read after the seek failed");
        }
        // Two more served pages (16 sectors) and — because the seek
        // reset the pattern — no 256-sector window behind the second.
        if fx.data_blocks_read() != 48 {
            return Err("a seek to the continuation offset did not reset the pattern");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/read_readahead/random_and_seek",
    smoke_read_readahead_random_and_seek_no_speculation
);

/// A page populated by a sequential read stream is already in the
/// shared cache when an mmap fault reaches it: the fault installs it
/// (and its fault-around window, itself fully populated) with zero
/// new device reads.
fn smoke_read_readahead_populates_for_mmap() -> TestResult {
    let bytes = content(0x74, 512 * 1024);
    with_fat_file(&bytes, |fx| {
        let mut buf = alloc::vec![0u8; PAGE as usize];
        if read_into(fx.fd, &mut buf) != Some(PAGE as i64)
            || read_into(fx.fd, &mut buf) != Some(PAGE as i64)
        {
            return Err("the sequential reads that open the window failed");
        }
        if fx.data_blocks_read() != 272 {
            return Err("the stream did not populate the initial window");
        }
        let base = map_shared(fx.fd, 512 * 1024)?;
        let before = fx.data_blocks_read();
        // Page 20 sits inside the populated window (pages 2..34); its
        // fault-around window (pages 16..32) is populated too.
        fault(&fx.aspace, base + 20 * PAGE)?;
        if fx.data_blocks_read() != before {
            return Err("faulting a read-ahead page re-read data sectors");
        }
        let want = &bytes[20 * PAGE as usize..21 * PAGE as usize];
        if mapped_bytes(&fx.aspace, base + 20 * PAGE, PAGE as usize)? != want {
            return Err("the faulted read-ahead page serves the wrong bytes");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/read_readahead/populates_for_mmap",
    smoke_read_readahead_populates_for_mmap
);

/// Pattern state is per open description: two opens of the same file
/// interleaved read-by-read keep independent streams. The exact total
/// also pins window growth — the first stream's second window is the
/// doubled 256 KiB, not another 128 KiB.
fn smoke_read_readahead_per_open_state() -> TestResult {
    let bytes = content(0x96, 512 * 1024);
    with_fat_file(&bytes, |fx| {
        let mut buf = alloc::vec![0u8; PAGE as usize];
        let fd_b = fx.reopen()?;
        // A candidates (page 0); B candidates elsewhere (page 40).
        if read_into(fx.fd, &mut buf) != Some(PAGE as i64) {
            return Err("A's first read failed");
        }
        if pread_into(fd_b, &mut buf, 40 * PAGE) != Some(PAGE as i64) {
            return Err("B's first read failed");
        }
        if buf[..] != bytes[40 * PAGE as usize..41 * PAGE as usize] {
            return Err("B's read served the wrong bytes");
        }
        // A confirms at page 1: 8 served + 256 populated (pages 2..34).
        if read_into(fx.fd, &mut buf) != Some(PAGE as i64) {
            return Err("A's second read failed");
        }
        if fx.data_blocks_read() != 280 {
            return Err("A's window did not open on its own stream");
        }
        // B jumps to page 100: a reset for B, no speculation, and A's
        // state undisturbed.
        if pread_into(fd_b, &mut buf, 100 * PAGE) != Some(PAGE as i64) {
            return Err("B's scattered read failed");
        }
        if fx.data_blocks_read() != 288 {
            return Err("B's scattered read speculated or disturbed A's state");
        }
        // A continues at page 2: 8 served, then the doubled window
        // populates pages 34..67 (264 sectors).
        if read_into(fx.fd, &mut buf) != Some(PAGE as i64) {
            return Err("A's third read failed");
        }
        // B reads page 41 — sequential for nobody (B expects 101):
        // 8 served sectors and no window.
        if pread_into(fd_b, &mut buf, 41 * PAGE) != Some(PAGE as i64) {
            return Err("B's final read failed");
        }
        if fx.data_blocks_read() != 568 {
            return Err("interleaved opens did not keep independent pattern state");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/read_readahead/per_open_state",
    smoke_read_readahead_per_open_state
);
