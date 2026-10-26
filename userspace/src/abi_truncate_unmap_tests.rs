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
use alloc::vec::Vec;

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

/// A fixture's keep-alive anchor: state the installed ops only borrow,
/// which must therefore outlive the scenario. btrfs nodes hold their
/// mount view (`BtrfsVolume`) by `Weak` — a node whose view has been
/// dropped answers every I/O op with `NotFound` — so the btrfs fixture
/// returns its view here and `with_file` keeps it bound until `body`
/// has run. memfs and FAT nodes own their backing (a FAT node holds
/// its volume by `Arc`) and return `None`.
type KeepAlive = Option<alloc::boxed::Box<dyn core::any::Any>>;

/// Give the harness task an address space, install `ops` as an fd opened
/// read-write, and run `body` against them.
fn with_file(
    make_ops: impl FnOnce() -> Result<(Arc<dyn FileOps>, KeepAlive), &'static str>,
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
            // `_keep_alive` must stay bound until `body` has run: it is
            // dropped at the end of this closure, after the scenario.
            let (ops, _keep_alive) = make_ops()?;
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

/// Fault `va` in the way a user access would. `step` names the
/// scenario step in the failure message: two steps fault the same
/// `va`, so a bare va cannot tell them apart.
fn fault(aspace: &AddressSpace, va: u64, step: &'static str) -> Result<(), &'static str> {
    // SAFETY: `aspace` is a live user root and paging is enabled.
    unsafe { aspace.demand_alloc_page(VirtAddr::new(va)) }.map_err(|e| {
        // Surface the error variant (#863 discriminator): the fixed
        // string this used to return discarded it, and the variant is
        // the one observation that names the production site when an
        // in-EOF fault is refused. The `&'static str` error type
        // leaves a leaked format as the only carrier; the path runs at
        // most once before the scenario aborts, so the leak is bounded.
        &*alloc::boxed::Box::leak(
            alloc::format!(
                "a fault inside the file's EOF was refused (step: {}, va {:#x}): {:?}",
                step,
                va,
                e
            )
            .into_boxed_str(),
        )
    })?;
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
        fault(&fx.aspace, base + page * PAGE, "seed fault-in")?;
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
        fault(&fx.aspace, base + 2 * PAGE, "post-regrow hole fault")?;
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
    fault(&fx.aspace, base + 2 * PAGE, "post-pwrite re-fault")?;
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
        fault(&fx.aspace, base + 2 * PAGE, "second-regrow hole fault")?;
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
    fault(&fx.aspace, fixed, "MAP_FIXED fault-in")?;
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
            Ok((file, None))
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
            Ok((file, None))
        },
        false,
        run_scenario,
    )
}
kernel_test_in!("syscall_abi/truncate_unmap/fat", smoke_truncate_unmap_fat);

/// Byte-built MINIX V3 image holding one file, `hi.txt`, whose content
/// is `data` spread over direct zones plus a single-indirect zone —
/// the multi-zone extension of `drivers/fs/minix`'s own
/// `build_minix3_image` (block size 1024, V3 magic 0x4D5A, 60-byte
/// names). Layout: block 0 boot, 1 superblock, 2 inode bitmap,
/// 3 zone bitmap, 4 inode table, 5 root directory zone, 6.. file
/// zones (7 direct, then an indirect zone, then the rest).
fn minix3_image(data: &[u8]) -> alloc::vec::Vec<u8> {
    use alloc::vec;
    const BS: usize = 1024;
    const NBLOCKS: usize = 32;
    let mut img = vec![0u8; BS * NBLOCKS];
    let sb = &mut img[BS..BS * 2];
    sb[0..2].copy_from_slice(&32u16.to_le_bytes()); // ninodes
    sb[4..6].copy_from_slice(&1u16.to_le_bytes()); // imap_blocks
    sb[6..8].copy_from_slice(&1u16.to_le_bytes()); // zmap_blocks
    sb[8..10].copy_from_slice(&5u16.to_le_bytes()); // first_data_zone
    sb[10..12].copy_from_slice(&0u16.to_le_bytes()); // log_zone_size
    sb[12..16].copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes()); // max_size
    sb[16..18].copy_from_slice(&0x4D5Au16.to_le_bytes()); // V3 magic
    sb[20..24].copy_from_slice(&(NBLOCKS as u32).to_le_bytes()); // s_zones
    sb[24..26].copy_from_slice(&1024u16.to_le_bytes()); // s_block_size
    img[BS * 2] = 0b0000_0111; // inodes 1 (root) and 2 (file) used

    let zones_needed = (data.len() as u32).div_ceil(BS as u32).max(1);
    let direct = zones_needed.min(7);
    let indirect: Vec<u32> = (0..zones_needed.saturating_sub(7))
        .map(|i| 14 + i)
        .collect();
    let mut file_zones: Vec<u32> = (0..direct).map(|i| 6 + i).collect();
    file_zones.extend_from_slice(&indirect);
    let mut top_zone = 6 + direct;
    if !indirect.is_empty() {
        top_zone = 14 + (indirect.len() as u32) - 1;
    }
    for z in 5..=top_zone {
        let bit = (z - 5) as usize;
        img[BS * 3 + bit / 8] |= 1 << (bit % 8);
    }

    let it = BS * 4;
    let i1 = &mut img[it..it + 64];
    i1[0..2].copy_from_slice(&(0o40000u16 | 0o755).to_le_bytes()); // IFDIR|0755
    i1[2..4].copy_from_slice(&2u16.to_le_bytes());
    i1[8..12].copy_from_slice(&186u32.to_le_bytes());
    i1[24..28].copy_from_slice(&5u32.to_le_bytes());
    let i2 = &mut img[it + 64..it + 128];
    i2[0..2].copy_from_slice(&(0o100000u16 | 0o644).to_le_bytes()); // IFREG|0644
    i2[2..4].copy_from_slice(&1u16.to_le_bytes());
    i2[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());
    for (slot, zone) in file_zones.iter().take(7).enumerate() {
        i2[24 + slot * 4..28 + slot * 4].copy_from_slice(&zone.to_le_bytes());
    }
    if !indirect.is_empty() {
        i2[24 + 7 * 4..28 + 7 * 4].copy_from_slice(&13u32.to_le_bytes());
        for (i, zone) in indirect.iter().enumerate() {
            img[BS * 13 + i * 4..BS * 13 + i * 4 + 4].copy_from_slice(&zone.to_le_bytes());
        }
    }
    let dr = BS * 5;
    img[dr..dr + 2].copy_from_slice(&1u16.to_le_bytes());
    img[dr + 2] = b'.';
    img[dr + 62..dr + 64].copy_from_slice(&1u16.to_le_bytes());
    img[dr + 64] = b'.';
    img[dr + 65] = b'.';
    img[dr + 124..dr + 126].copy_from_slice(&2u16.to_le_bytes());
    img[dr + 126..dr + 132].copy_from_slice(b"hi.txt");
    for (i, zone) in file_zones.iter().enumerate() {
        let lo = i * BS;
        let hi = ((i + 1) * BS).min(data.len());
        if lo < data.len() {
            img[*zone as usize * BS..*zone as usize * BS + (hi - lo)]
                .copy_from_slice(&data[lo..hi]);
        }
    }
    img
}

fn smoke_truncate_unmap_minix() -> TestResult {
    with_file(
        || {
            let image = minix3_image(&content(3 * PAGE as usize - 100));
            let device = RamBlockDevice::from_image(512, image);
            let volume = crate::handlers::poll_io_to_completion(
                narf_drivers_fs_minix::volume::MinixVolume::mount(
                    device,
                    narf_lib::id::DomainId::DRIVER_0,
                ),
            )
            .and_then(|r| r.ok())
            .ok_or("mounting the test MINIX image failed")?;
            let file = crate::handlers::poll_io_to_completion(volume.root().lookup_async("hi.txt"))
                .and_then(|r| r.ok())
                .ok_or("lookup of hi.txt failed")?;
            Ok((file, None))
        },
        // minix `read_file` zero-fills unmapped zones, so in-size
        // holes fault in as zero pages — the flag is the honest
        // encoding of the read-path contract. The shrink branch of
        // minix truncate frees every zone past the new EOF and
        // zeroes the partial tail zone (#844, fixed by PR #880), so
        // the regrown range is backed by holes, not the retained
        // pre-shrink zones — this pin failed by design until that
        // fix landed.
        true,
        run_scenario,
    )
}
kernel_test_in!(
    "syscall_abi/truncate_unmap/minix",
    smoke_truncate_unmap_minix
);

fn smoke_truncate_unmap_btrfs() -> TestResult {
    with_file(
        || {
            let volume = crate::abi_fault_write_tests::btrfs_volume_with_file(&content(
                3 * PAGE as usize - 100,
            ))?;
            let file =
                crate::handlers::poll_io_to_completion(volume.root().lookup_async("narf.txt"))
                    .and_then(|r| r.ok())
                    .ok_or("lookup of narf.txt failed")?;
            // The looked-up node holds the volume by `Weak` only, so
            // the view itself is the keep-alive anchor: were it dropped
            // with this closure, the scenario's first fault would meet
            // a node whose every read answers `NotFound` (surfacing as
            // a refused in-EOF fault, `Bus`) — the #863 seed fault-in
            // failure. The sibling btrfs fixtures bind the volume
            // across their scenario for the same reason.
            Ok((
                file,
                Some(alloc::boxed::Box::new(volume) as alloc::boxed::Box<dyn core::any::Any>),
            ))
        },
        // btrfs holes (dropped extents, never-allocated ranges) read
        // back as zeros, so a regrown range faults in as zero pages.
        true,
        run_scenario,
    )
}
kernel_test_in!(
    "syscall_abi/truncate_unmap/btrfs",
    smoke_truncate_unmap_btrfs
);
