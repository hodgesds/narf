//! `MADV_POPULATE_READ` / `MADV_POPULATE_WRITE`: strict population
//! (#741).
//!
//! Where `MADV_WILLNEED` (#731) only fills the page cache and leaves
//! installation to later faults, POPULATE must leave the range itself
//! installed — 0 is a guarantee about the pages, not about the call.
//! These tests therefore never accept a return value as evidence:
//! the file-range test counts device reads (population must move the
//! file's sectors exactly once, at advise time, and touching every
//! page afterwards must move none), the COW test inspects the frame
//! behind each address space's slot before and after, and the error
//! tests pin which pages a failed call did and did not install.
//!
//! The FAT fixture is the generic-fallback path end to end — a
//! byte-built FAT12 volume on a counting `RamBlockDevice`, a real
//! address space, real syscall dispatch — the same harness shape as
//! `abi_readahead_tests`, whose fixture this file's is copied from.

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
const MADV_POPULATE_READ: u64 = 22;
const MADV_POPULATE_WRITE: u64 = 23;
const O_RDWR: u32 = 2;
const PAGE: u64 = 4096;
const SECTOR: u64 = 512;
/// First sector of the fixture image's data area (boot + 2 FATs + root
/// directory occupy sectors 0..4 in `fat12_image`).
const DATA_LBA: u64 = 4;

type FatVolume = narf_drivers_fs_fat::volume::FatVolume<CountingBlockDevice>;

/// A `RamBlockDevice` that records every read request in submission
/// order, as `(start LBA, blocks)`. Copied from
/// `abi_readahead_tests`: requests are recorded individually, never
/// aggregated by LBA, so `blocks_read_between` sums real overlaps
/// only and a much-re-read metadata sector cannot masquerade as data
/// traffic.
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

static POP_AS: IrqSafeSpinLock<Option<Arc<AddressSpace>>> = IrqSafeSpinLock::new(None);

fn lookup_pop_as() -> Option<Arc<AddressSpace>> {
    POP_AS.lock().clone()
}

/// Point the harness's address-space lookup at `aspace`. The fork
/// test swaps this from parent to child mid-test, the way a real
/// context switch would change which space the syscall acts on.
fn set_current_as(aspace: &Arc<AddressSpace>) {
    *POP_AS.lock() = Some(Arc::clone(aspace));
}

fn fresh_aspace() -> Result<Arc<AddressSpace>, &'static str> {
    // SAFETY: kernel tests run with paging enabled; the new root
    // inherits only the kernel half and is owned by this fixture.
    unsafe { AddressSpace::new_for_user() }
        .map(Arc::new)
        .map_err(|_| "failed to create the test address space")
}

/// Run `body` with a fresh address space installed as the current
/// one, restoring the harness's no-AS baseline afterwards.
fn with_aspace(body: impl FnOnce(&Arc<AddressSpace>) -> Result<(), &'static str>) -> TestResult {
    with_setup(move || {
        let aspace = fresh_aspace()?;
        set_current_as(&aspace);
        crate::handlers::install_address_space_lookup(lookup_pop_as);
        let result = body(&aspace);
        crate::handlers::restore_address_space_lookup(None);
        *POP_AS.lock() = None;
        result
    })
}

struct Fixture {
    aspace: Arc<AddressSpace>,
    device: Arc<CountingBlockDevice>,
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

/// Build the fixture: FAT12 image holding `data` as `NARF.TXT`,
/// mounted on the counting device, one fd installed read-write.
fn with_fat_file(
    data: &[u8],
    body: impl FnOnce(&Fixture) -> Result<(), &'static str>,
) -> TestResult {
    with_setup(move || {
        let aspace = fresh_aspace()?;
        set_current_as(&aspace);
        crate::handlers::install_address_space_lookup(lookup_pop_as);
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
                aspace: Arc::clone(&aspace),
                device,
                fd,
                data_span: (DATA_LBA, DATA_LBA + clusters),
            })
        })();
        crate::handlers::restore_address_space_lookup(None);
        *POP_AS.lock() = None;
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

/// Byte-built FAT12 image holding one file, `NARF.TXT`, whose content
/// is `data` spread over a cluster chain (512-byte clusters, one-sector
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

/// Distinct content per test (seeded), so a page retained from
/// another fixture's identical-layout volume could never silently
/// satisfy a byte assertion here.
fn content(seed: u8, len: usize) -> alloc::vec::Vec<u8> {
    (0..len)
        .map(|i| seed.wrapping_add((i % 251) as u8))
        .collect()
}

/// `mmap(NULL, len, prot, flags, fd, 0)`.
fn map_file(fd: u64, len: u64, prot: u64, flags: u64) -> Result<u64, &'static str> {
    let args = SyscallArgs {
        arg0: 0,
        arg1: len,
        arg2: prot,
        arg3: flags,
        arg4: fd,
        arg5: 0,
    };
    match call(Syscall::Mmap.raw(), args) {
        Some(addr) if addr > 0 => Ok(addr as u64),
        _ => Err("file mmap failed"),
    }
}

/// `mmap(NULL, len, prot, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)`.
fn map_anon(len: u64, prot: u64) -> Result<u64, &'static str> {
    let args = SyscallArgs {
        arg0: 0,
        arg1: len,
        arg2: prot,
        arg3: MAP_PRIVATE | MAP_ANONYMOUS,
        arg4: u64::MAX,
        arg5: 0,
    };
    match call(Syscall::Mmap.raw(), args) {
        Some(addr) if addr > 0 => Ok(addr as u64),
        _ => Err("anonymous mmap failed"),
    }
}

fn madvise(addr: u64, len: u64, advice: u64) -> Option<i64> {
    call(Syscall::Madvise.raw(), a2(addr, len, advice))
}

/// The frame currently backing `va` (0 / `None` = unbacked).
fn mapped_frame(aspace: &AddressSpace, va: u64) -> Option<u64> {
    let region = aspace.lookup(VirtAddr::new(va))?;
    let index = ((va & !(PAGE - 1)) - region.base.as_u64()) / PAGE;
    let phys = region.phys.get(index as usize)?.raw();
    (phys != 0).then_some(phys)
}

/// Touch `va` the way a user access would: a no-op when the page is
/// already resident, a demand fault otherwise.
fn fault(aspace: &AddressSpace, va: u64) -> Result<(), &'static str> {
    if mapped_frame(aspace, va).is_some() {
        return Ok(());
    }
    // SAFETY: `aspace` is a live user root and paging is enabled.
    unsafe { aspace.demand_alloc_page(VirtAddr::new(va)) }
        .map_err(|_| "a fault inside the populated range was refused")?;
    if mapped_frame(aspace, va).is_none() {
        return Err("the fault left the page unbacked");
    }
    Ok(())
}

/// Bytes the mapping shows at `va` (must be backed), `len` of them,
/// copied page by page through each page's own frame.
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
        // SAFETY: `ptr` is the direct-map alias of a frame the
        // mapping holds; `in_page + take` stays inside that frame.
        out.extend_from_slice(unsafe { core::slice::from_raw_parts(ptr.add(in_page), take) });
        done += take;
    }
    Ok(out)
}

/// POPULATE_READ over a 32-page shared file mapping: the file's data
/// sectors move exactly once, at advise time; every page is
/// installed by the call itself (not by a later fault); touching the
/// whole range afterwards reads nothing more and serves the bytes.
fn smoke_populate_file_range() -> TestResult {
    let bytes = content(0x31, 32 * PAGE as usize);
    with_fat_file(&bytes, |fx| {
        let base = map_file(fx.fd, 32 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED)?;
        if fx.data_blocks_read() != 0 {
            return Err("mapping the file read its data before any advise");
        }
        for page in [0u64, 17, 31] {
            if mapped_frame(&fx.aspace, base + page * PAGE).is_some() {
                return Err("a page is backed before any fault or advise");
            }
        }
        if madvise(base, 32 * PAGE, MADV_POPULATE_READ) != Some(0) {
            return Err("MADV_POPULATE_READ of the whole file did not return 0");
        }
        // 32 pages = 256 data sectors, each exactly once.
        if fx.data_blocks_read() != 256 {
            return Err("populate did not read the file's data sectors exactly once");
        }
        for page in 0..32 {
            if mapped_frame(&fx.aspace, base + page * PAGE).is_none() {
                return Err("populate returned 0 but left a page uninstalled");
            }
        }
        let before = fx.data_blocks_read();
        for page in 0..32 {
            fault(&fx.aspace, base + page * PAGE)?;
        }
        if fx.data_blocks_read() != before {
            return Err("touching the populated range re-read data sectors");
        }
        if mapped_bytes(&fx.aspace, base, 32 * PAGE as usize)? != bytes {
            return Err("the populated mapping does not serve the file's bytes");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/populate/file_range", smoke_populate_file_range);

/// POPULATE_WRITE breaks COW up front; POPULATE_READ does not.
/// Following the `memory` crate's fork-smoke shape: the parent
/// faults two anonymous pages in and stamps them, `clone_for_fork`
/// shares both frames with the child, and the child populates one
/// page each way. Afterwards the WRITE-populated page must sit on a
/// private frame (a write through it cannot reach the parent),
/// while the READ-populated page still shares the parent's frame.
fn smoke_populate_write_breaks_cow() -> TestResult {
    with_aspace(|parent| {
        let base = map_anon(2 * PAGE, PROT_READ | PROT_WRITE)?;
        fault(parent, base)?;
        fault(parent, base + PAGE)?;
        let parent0 = mapped_frame(parent, base).ok_or("parent page 0 unbacked")?;
        let parent1 = mapped_frame(parent, base + PAGE).ok_or("parent page 1 unbacked")?;
        // SAFETY: both frames are exclusively the parent's until the
        // fork below; the writes go through the direct-map alias.
        unsafe {
            *narf_memory::PhysAddr::new(parent0).kernel_mut_ptr::<u32>() = 0xCAFE_BABE;
            *narf_memory::PhysAddr::new(parent1).kernel_mut_ptr::<u32>() = 0x1111_1111;
        }
        // SAFETY: kernel tests run with paging enabled; the parent
        // space is live and quiescent under the harness.
        let child =
            Arc::new(unsafe { parent.clone_for_fork() }.map_err(|_| "clone_for_fork failed")?);
        if mapped_frame(&child, base) != Some(parent0) {
            return Err("fork did not share page 0 with the child");
        }
        if mapped_frame(&child, base + PAGE) != Some(parent1) {
            return Err("fork did not share page 1 with the child");
        }
        set_current_as(&child);
        let result = (|| {
            if madvise(base, PAGE, MADV_POPULATE_WRITE) != Some(0) {
                return Err("MADV_POPULATE_WRITE on the COW page did not return 0");
            }
            let child0 = mapped_frame(&child, base).ok_or("child page 0 unbacked")?;
            if child0 == parent0 {
                return Err("POPULATE_WRITE left the page COW-shared with the parent");
            }
            if madvise(base + PAGE, PAGE, MADV_POPULATE_READ) != Some(0) {
                return Err("MADV_POPULATE_READ on the COW page did not return 0");
            }
            if mapped_frame(&child, base + PAGE) != Some(parent1) {
                return Err("POPULATE_READ broke the COW sharing it must preserve");
            }
            // A write through the child's now-private frame must not
            // reach the parent's still-shared frame.
            // SAFETY: `child0` is the child's private frame after
            // the split; the parent's frame is read, never written.
            unsafe {
                *narf_memory::PhysAddr::new(child0).kernel_mut_ptr::<u32>() = 0xDEAD_BEEF;
            }
            // SAFETY: `parent0` still backs the parent's page in
            // the live parent space; the read is the frame's first
            // word through the direct-map alias.
            let parent_word = unsafe { *narf_memory::PhysAddr::new(parent0).kernel_ptr::<u32>() };
            if parent_word != 0xCAFE_BABE {
                return Err("the child's post-populate write leaked into the parent");
            }
            // SAFETY: `child0` is the child's private frame after
            // the split (checked distinct from `parent0` above),
            // still mapped in the live child space; the read is
            // its first word through the direct-map alias.
            let child_word = unsafe { *narf_memory::PhysAddr::new(child0).kernel_ptr::<u32>() };
            if child_word != 0xDEAD_BEEF {
                return Err("the child's private frame did not retain the write");
            }
            Ok(())
        })();
        set_current_as(parent);
        result
    })
}
kernel_test_in!(
    "syscall_abi/populate/cow_write",
    smoke_populate_write_breaks_cow
);

/// A range running past the end of the mapping into unmapped space
/// fails with ENOMEM — and the mapped prefix stays populated (Linux:
/// pages populated before the failure remain; there is no rollback).
fn smoke_populate_unmapped_tail() -> TestResult {
    with_aspace(|aspace| {
        let base = map_anon(2 * PAGE, PROT_READ | PROT_WRITE)?;
        match madvise(base, 4 * PAGE, MADV_POPULATE_READ) {
            Some(v) if v == ENOMEM => {}
            _ => return Err("populate across an unmapped tail must fail with ENOMEM"),
        }
        if mapped_frame(aspace, base).is_none() || mapped_frame(aspace, base + PAGE).is_none() {
            return Err("the failed populate rolled back the mapped prefix");
        }
        if mapped_bytes(aspace, base, 2 * PAGE as usize)?
            .iter()
            .any(|&b| b != 0)
        {
            return Err("the populated anonymous prefix does not read as zero");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/populate/unmapped_tail",
    smoke_populate_unmapped_tail
);

/// A mapped range extending past the file's EOF: mappings may
/// extend past EOF, but the pages there can only SIGBUS on touch.
/// POPULATE must not generate that SIGBUS (the man page is
/// explicit) — it fails the call with ENOMEM instead, installs
/// nothing past EOF, and leaves the in-EOF pages populated. The
/// in-EOF range alone populates cleanly.
fn smoke_populate_past_eof() -> TestResult {
    let bytes = content(0x59, 3 * PAGE as usize);
    with_fat_file(&bytes, |fx| {
        let base = map_file(fx.fd, 5 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED)?;
        match madvise(base, 5 * PAGE, MADV_POPULATE_READ) {
            Some(v) if v == ENOMEM => {}
            _ => return Err("populate extending past EOF must fail with ENOMEM, not SIGBUS"),
        }
        for page in 0..3 {
            if mapped_frame(&fx.aspace, base + page * PAGE).is_none() {
                return Err("the in-EOF prefix was not populated by the failed call");
            }
        }
        for page in 3..5 {
            if mapped_frame(&fx.aspace, base + page * PAGE).is_some() {
                return Err("populate installed a page past EOF");
            }
        }
        if madvise(base, 3 * PAGE, MADV_POPULATE_READ) != Some(0) {
            return Err("populate of exactly the in-EOF range did not return 0");
        }
        if mapped_bytes(&fx.aspace, base, 3 * PAGE as usize)? != bytes {
            return Err("the populated in-EOF range does not serve the file's bytes");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/populate/past_eof", smoke_populate_past_eof);

/// Anonymous ranges populate in bulk with no file behind them:
/// POPULATE_WRITE installs every page up front (distinct zeroed
/// frames), and POPULATE_READ on a fresh range does the same.
fn smoke_populate_anonymous() -> TestResult {
    with_aspace(|aspace| {
        let base = map_anon(4 * PAGE, PROT_READ | PROT_WRITE)?;
        if madvise(base, 4 * PAGE, MADV_POPULATE_WRITE) != Some(0) {
            return Err("MADV_POPULATE_WRITE of an anonymous range did not return 0");
        }
        let mut frames = alloc::vec::Vec::new();
        for page in 0..4 {
            let phys = mapped_frame(aspace, base + page * PAGE)
                .ok_or("POPULATE_WRITE returned 0 but left a page uninstalled")?;
            if frames.contains(&phys) {
                return Err("two anonymous pages share one frame after POPULATE_WRITE");
            }
            frames.push(phys);
        }
        if mapped_bytes(aspace, base, 4 * PAGE as usize)?
            .iter()
            .any(|&b| b != 0)
        {
            return Err("the populated anonymous range does not read as zero");
        }
        let fresh = map_anon(2 * PAGE, PROT_READ | PROT_WRITE)?;
        if madvise(fresh, 2 * PAGE, MADV_POPULATE_READ) != Some(0) {
            return Err("MADV_POPULATE_READ of an anonymous range did not return 0");
        }
        for page in 0..2 {
            if mapped_frame(aspace, fresh + page * PAGE).is_none() {
                return Err("POPULATE_READ returned 0 but left an anonymous page uninstalled");
            }
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/populate/anonymous", smoke_populate_anonymous);

/// The permission rule: POPULATE_WRITE on a read-only mapping is
/// EINVAL (the man page refuses mappings without write permission),
/// and the refusal installs nothing. The same mapping populates
/// fine for reading.
fn smoke_populate_permissions() -> TestResult {
    let bytes = content(0x77, 2 * PAGE as usize);
    with_fat_file(&bytes, |fx| {
        let base = map_file(fx.fd, 2 * PAGE, PROT_READ, MAP_SHARED)?;
        match madvise(base, 2 * PAGE, MADV_POPULATE_WRITE) {
            Some(v) if v == EINVAL => {}
            _ => return Err("POPULATE_WRITE on a read-only mapping must fail with EINVAL"),
        }
        if mapped_frame(&fx.aspace, base).is_some() {
            return Err("the refused POPULATE_WRITE installed a page anyway");
        }
        if madvise(base, 2 * PAGE, MADV_POPULATE_READ) != Some(0) {
            return Err("POPULATE_READ of the read-only mapping did not return 0");
        }
        if mapped_bytes(&fx.aspace, base, 2 * PAGE as usize)? != bytes {
            return Err("the populated read-only mapping does not serve the file's bytes");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/populate/permissions",
    smoke_populate_permissions
);
