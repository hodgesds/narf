//! Fault→write coherence (#724): a page faulted in through one open
//! must observe a later `write(2)` through another open.
//!
//! The generic mapped-file path keeps one canonical frame per file
//! page in the shared cache; a `write(2)` reaches that frame only via
//! the syscall handler's `note_file_written` fold (#688), which copies
//! the written bytes into the frame and its clean snapshot. The fold
//! is keyed by the writer's `mmap_backing_identity`, so this scenario
//! also pins the cross-open identity contract (#698): the page below
//! is faulted in through open 1 and written through open 2 — two
//! different node objects for the same on-disk file.
//!
//! #724 was filed from a deterministic failure of this shape in the
//! truncate-unmap smoke; the root cause was that the smoke rewrote
//! through a raw `FileOps::write`, bypassing the fold — a sequence no
//! user program can produce, since every write(2)-family handler
//! folds. These smokes drive the real syscall surface throughout.

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

static FW_AS: IrqSafeSpinLock<Option<Arc<AddressSpace>>> = IrqSafeSpinLock::new(None);

fn lookup_fw_as() -> Option<Arc<AddressSpace>> {
    FW_AS.lock().clone()
}

struct TwoOpens {
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

/// Give the harness task an address space, open the same file twice
/// (two independent node objects), and run `body` against both fds.
fn with_two_opens<S>(
    setup: impl FnOnce() -> Result<S, &'static str>,
    open: impl Fn(&S) -> Result<Arc<dyn FileOps>, &'static str>,
    body: impl FnOnce(&TwoOpens) -> Result<(), &'static str>,
) -> TestResult {
    with_setup(move || {
        // SAFETY: kernel tests run with paging enabled; the new root
        // inherits only the kernel half and is owned by this fixture.
        let aspace = match unsafe { AddressSpace::new_for_user() } {
            Ok(aspace) => Arc::new(aspace),
            Err(_) => return Err("failed to create the test address space"),
        };
        *FW_AS.lock() = Some(Arc::clone(&aspace));
        crate::handlers::install_address_space_lookup(lookup_fw_as);
        let result = (|| {
            let state = setup()?;
            let ops1 = open(&state)?;
            let ops2 = open(&state)?;
            let fd1 = install_fd(&ops1)?;
            let fd2 = install_fd(&ops2)?;
            body(&TwoOpens { aspace, fd1, fd2 })
        })();
        crate::handlers::restore_address_space_lookup(None);
        *FW_AS.lock() = None;
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

fn fault(aspace: &AddressSpace, va: u64) -> Result<(), &'static str> {
    // SAFETY: `aspace` is a live user root and paging is enabled.
    unsafe { aspace.demand_alloc_page(VirtAddr::new(va)) }
        .map_err(|_| "a fault inside the file's EOF was refused")?;
    if mapped_frame(aspace, va).is_none() {
        return Err("the fault left the page unbacked");
    }
    Ok(())
}

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

/// Map through open 1, fault page 2 in, `pwrite64` a full new page
/// over it through open 2, and require the mapping to serve the new
/// bytes (the #724 sequence, syscall-faithful throughout).
fn scenario_fault_then_write(fx: &TwoOpens) -> Result<(), &'static str> {
    let base = map_shared(fx.fd1, 3 * PAGE)?;
    fault(&fx.aspace, base + 2 * PAGE)?;
    let seed = content(3 * PAGE as usize - 100);
    if mapped_bytes(&fx.aspace, base + 2 * PAGE, 32)?
        != seed[2 * PAGE as usize..2 * PAGE as usize + 32]
    {
        return Err("the faulted page does not show the seed bytes");
    }
    let new_bytes = alloc::vec![0xC3u8; PAGE as usize];
    let args = SyscallArgs {
        arg0: fx.fd2,
        arg1: new_bytes.as_ptr() as u64,
        arg2: PAGE,
        arg3: 2 * PAGE,
        arg4: 0,
        arg5: 0,
    };
    match call(Syscall::Pwrite64.raw(), args) {
        Some(n) if n == PAGE as i64 => {}
        _ => return Err("pwrite64 through the second open failed or was short"),
    }
    if mapped_bytes(&fx.aspace, base + 2 * PAGE, PAGE as usize)? != new_bytes {
        return Err("the mapping does not serve the bytes pwrite64 wrote");
    }
    // The untouched head of the file still reads through the mapping.
    fault(&fx.aspace, base)?;
    if mapped_bytes(&fx.aspace, base, 32)? != seed[..32] {
        return Err("the write disturbed the file's head bytes");
    }
    Ok(())
}

/// Byte-built FAT12 image holding one file, `NARF.TXT` (modeled on
/// `abi_truncate_unmap_tests`' builder).
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
            fat[off] = (fat[off] & 0xF0) | (((v << 4) & 0xF0) as u8);
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

fn fat_volume() -> Result<Arc<narf_drivers_fs_fat::volume::FatVolume<RamBlockDevice>>, &'static str>
{
    let image = fat12_image(&content(3 * PAGE as usize - 100));
    let device = RamBlockDevice::from_image(512, image);
    crate::handlers::poll_io_to_completion(narf_drivers_fs_fat::volume::FatVolume::mount(
        device,
        narf_lib::id::DomainId::DRIVER_0,
    ))
    .and_then(|r| r.ok())
    .ok_or("mounting the test FAT image failed")
}

fn fat_open(
    volume: &Arc<narf_drivers_fs_fat::volume::FatVolume<RamBlockDevice>>,
) -> Result<Arc<dyn FileOps>, &'static str> {
    crate::handlers::poll_io_to_completion(volume.root().lookup_async("NARF.TXT"))
        .and_then(|r| r.ok())
        .ok_or("lookup of NARF.TXT failed")
}

fn smoke_fat_fault_then_write() -> TestResult {
    with_two_opens(fat_volume, fat_open, scenario_fault_then_write)
}
kernel_test_in!("syscall_abi/fault_write/fat", smoke_fat_fault_then_write);

/// Control: the same sequence on tmpfs, whose coherent `mmap_fault`
/// provider serves the write from its own store.
fn smoke_memfs_fault_then_write() -> TestResult {
    with_two_opens(
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
            Ok(fs)
        },
        |fs: &TmpFs| {
            crate::handlers::poll_io_to_completion(fs.root().lookup_async("data"))
                .and_then(|r| r.ok())
                .ok_or("tmpfs lookup failed")
        },
        scenario_fault_then_write,
    )
}
kernel_test_in!(
    "syscall_abi/fault_write/memfs",
    smoke_memfs_fault_then_write
);

/// The btrfs driver's own fixture image (`NARFBTR1` sparse encoding),
/// shared with `drivers/fs/btrfs`' test suite.
const BTRFS_FIXTURE_SPARSE: &[u8] =
    include_bytes!("../../drivers/fs/btrfs/testdata/fixture.img.sparse");

/// Reconstruct the full zero-filled image from the sparse encoding
/// (a copy of `drivers/fs/btrfs`' `decode_sparse`).
pub(crate) fn btrfs_decode_sparse(sparse: &[u8]) -> alloc::vec::Vec<u8> {
    use alloc::vec;
    assert!(
        sparse.len() >= 20 && &sparse[0..8] == b"NARFBTR1",
        "bad fixture magic"
    );
    let total = u64::from_le_bytes(sparse[8..16].try_into().unwrap()) as usize;
    let n_runs = u32::from_le_bytes(sparse[16..20].try_into().unwrap()) as usize;
    let mut img = vec![0u8; total];
    let mut p = 20usize;
    for _ in 0..n_runs {
        let off = u64::from_le_bytes(sparse[p..p + 8].try_into().unwrap()) as usize;
        let len = u64::from_le_bytes(sparse[p + 8..p + 16].try_into().unwrap()) as usize;
        p += 16;
        img[off..off + len].copy_from_slice(&sparse[p..p + len]);
        p += len;
    }
    img
}

/// Mount the btrfs fixture and seed `narf.txt` with `seed` through
/// the driver's own create/write path.
pub(crate) fn btrfs_volume_with_file(
    seed: &[u8],
) -> Result<Arc<narf_drivers_fs_btrfs::volume::BtrfsVolume<RamBlockDevice>>, &'static str> {
    let device = RamBlockDevice::from_image(512, btrfs_decode_sparse(BTRFS_FIXTURE_SPARSE));
    let volume = crate::handlers::poll_io_to_completion(
        narf_drivers_fs_btrfs::volume::BtrfsVolume::mount(device, narf_lib::id::DomainId::DRIVER_0),
    )
    .and_then(|r| r.ok())
    .ok_or("mounting the test btrfs fixture failed")?;
    let file = crate::handlers::poll_io_to_completion(volume.root().create("narf.txt"))
        .and_then(|r| r.ok())
        .ok_or("creating narf.txt on the btrfs fixture failed")?;
    let written = crate::handlers::poll_io_to_completion(file.write(0, seed))
        .and_then(|r| r.ok())
        .ok_or("seeding narf.txt failed")?;
    if written != seed.len() {
        return Err("seeding narf.txt was short");
    }
    Ok(volume)
}

fn btrfs_open(
    volume: &Arc<narf_drivers_fs_btrfs::volume::BtrfsVolume<RamBlockDevice>>,
) -> Result<Arc<dyn FileOps>, &'static str> {
    crate::handlers::poll_io_to_completion(volume.root().lookup_async("narf.txt"))
        .and_then(|r| r.ok())
        .ok_or("lookup of narf.txt failed")
}

/// The #724 sequence on btrfs (#742): btrfs bumps the (tree, inode)
/// generation in the shared core before engine mutations, keyed
/// independently of which node object writes, so the fold lands.
fn smoke_btrfs_fault_then_write() -> TestResult {
    with_two_opens(
        || btrfs_volume_with_file(&content(3 * PAGE as usize - 100)),
        btrfs_open,
        scenario_fault_then_write,
    )
}
kernel_test_in!(
    "syscall_abi/fault_write/btrfs",
    smoke_btrfs_fault_then_write
);
