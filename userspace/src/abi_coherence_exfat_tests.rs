//! exFAT page-cache coherence matrix (#742): the read-only column.
//!
//! exFAT content is immutable within a mount today — `write` and
//! `truncate` are `Unsupported` stubs and the crate has no
//! create/unlink/rename — which is exactly why its cache generation
//! may be constant per entry (#681). The matrix therefore pins the
//! two halves of that bargain:
//!
//! * the read/fault side works through the generic page cache: two
//!   opens of one file fault the same retained pages in and read
//!   the same bytes, and the generation both opens report is the
//!   same constant before and after the faults;
//! * the immutability side holds at the syscall surface:
//!   `pwrite64` and `ftruncate` fail, and the file is byte-identical
//!   afterwards. Together with the driver-level tripwire
//!   (`smoke_exfat_cache_generation_constant_until_writable`), this
//!   is what the future write path must break loudly, on its way to
//!   bumping the writable epoch first.
//!
//! The write-side scenarios of the matrix (fault→write coherence,
//! truncate-grow, msync) are not applicable until exFAT grows a
//! write path.

use alloc::sync::Arc;

use narf_block::ram::RamBlockDevice;
use narf_filesystem::{FileOps, FsInstance};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::{AddressSpace, VirtAddr};

use crate::abi_test_support::*;

const PROT_READ: u64 = 1;
const MAP_SHARED: u64 = 1;
const O_RDWR: u32 = 2;
const PAGE: u64 = 4096;

static COHEX_AS: IrqSafeSpinLock<Option<Arc<AddressSpace>>> = IrqSafeSpinLock::new(None);

fn lookup_cohex_as() -> Option<Arc<AddressSpace>> {
    COHEX_AS.lock().clone()
}

struct Fixture {
    aspace: Arc<AddressSpace>,
    fd1: u64,
    fd2: u64,
    ops1: Arc<dyn FileOps>,
    ops2: Arc<dyn FileOps>,
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

/// Mount the exFAT fixture image seeded with `seed`, open `NARF.TXT`
/// twice, and run `body` against both fds in a fresh address space.
fn with_exfat(seed: &[u8], body: impl FnOnce(&Fixture) -> Result<(), &'static str>) -> TestResult {
    with_setup(move || {
        // SAFETY: kernel tests run with paging enabled; the new root
        // inherits only the kernel half and is owned by this fixture.
        let aspace = match unsafe { AddressSpace::new_for_user() } {
            Ok(aspace) => Arc::new(aspace),
            Err(_) => return Err("failed to create the test address space"),
        };
        *COHEX_AS.lock() = Some(Arc::clone(&aspace));
        crate::handlers::install_address_space_lookup(lookup_cohex_as);
        let result = (|| {
            let image = exfat_image("NARF.TXT", seed);
            let device = RamBlockDevice::from_image(512, image);
            let volume = crate::handlers::poll_io_to_completion(
                narf_drivers_fs_exfat::volume::ExfatVolume::mount(
                    device,
                    narf_lib::id::DomainId::DRIVER_0,
                ),
            )
            .and_then(|r| r.ok())
            .ok_or("mounting the test exFAT image failed")?;
            let open = || {
                crate::handlers::poll_io_to_completion(volume.root().lookup_async("NARF.TXT"))
                    .and_then(|r| r.ok())
                    .ok_or("lookup of NARF.TXT failed")
            };
            let ops1 = open()?;
            let ops2 = open()?;
            let fd1 = install_fd(&ops1)?;
            let fd2 = install_fd(&ops2)?;
            body(&Fixture {
                aspace,
                fd1,
                fd2,
                ops1,
                ops2,
            })
        })();
        crate::handlers::restore_address_space_lookup(None);
        *COHEX_AS.lock() = None;
        result
    })
}

fn map_shared_ro(fd: u64, len: u64) -> Result<u64, &'static str> {
    let args = SyscallArgs {
        arg0: 0,
        arg1: len,
        arg2: PROT_READ,
        arg3: MAP_SHARED,
        arg4: fd,
        arg5: 0,
    };
    match call(Syscall::Mmap.raw(), args) {
        Some(addr) if addr > 0 => Ok(addr as u64),
        _ => Err("MAP_SHARED read-only mmap failed"),
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

fn pread(fd: u64, buf: &mut [u8], offset: u64) -> Result<(), &'static str> {
    match call(
        Syscall::Pread64.raw(),
        a3(fd, buf.as_mut_ptr() as u64, buf.len() as u64, offset),
    ) {
        Some(n) if n == buf.len() as i64 => Ok(()),
        _ => Err("pread was short or failed"),
    }
}

/// Two opens of one exFAT file share the retained pages, and the
/// generation they report is one constant value that faults and
/// reads do not move (the #681 contract, end-to-end).
fn smoke_exfat_fault_read_two_opens() -> TestResult {
    let seed = content(3 * PAGE as usize - 100);
    with_exfat(&seed, |fx| {
        let g1 = fx.ops1.mmap_cache_generation();
        let g2 = fx.ops2.mmap_cache_generation();
        if g1.is_none() || g1 != g2 {
            return Err("two opens of one exFAT file disagree on the cache generation");
        }
        let base = map_shared_ro(fx.fd1, 3 * PAGE)?;
        fault(&fx.aspace, base + 2 * PAGE)?;
        if mapped_bytes(&fx.aspace, base + 2 * PAGE, 32)?
            != seed[2 * PAGE as usize..2 * PAGE as usize + 32]
        {
            return Err("the faulted page does not show the seed bytes");
        }
        // A second mapping, through the second open, is served the
        // same bytes at the same offsets.
        let base2 = map_shared_ro(fx.fd2, 3 * PAGE)?;
        fault(&fx.aspace, base2)?;
        if mapped_bytes(&fx.aspace, base2, 32)? != seed[..32] {
            return Err("the second open's mapping does not show the file's head bytes");
        }
        let mut disk = alloc::vec![0u8; 64];
        pread(fx.fd2, &mut disk, 2 * PAGE)?;
        if disk[..] != seed[2 * PAGE as usize..2 * PAGE as usize + 64] {
            return Err("pread through the second open disagrees with the mapping");
        }
        if fx.ops1.mmap_cache_generation() != g1 {
            return Err("faults and reads moved the constant generation");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/coherence/exfat",
    smoke_exfat_fault_read_two_opens
);

/// The immutability half of the #681 bargain at the syscall
/// surface: writes and truncates fail, and the file is untouched.
fn smoke_exfat_write_and_truncate_are_unsupported() -> TestResult {
    let seed = content(600);
    with_exfat(&seed, |fx| {
        let buf = alloc::vec![0xABu8; 16];
        let args = SyscallArgs {
            arg0: fx.fd1,
            arg1: buf.as_ptr() as u64,
            arg2: 16,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        };
        if let Some(16) = call(Syscall::Pwrite64.raw(), args) {
            return Err("pwrite64 on an exFAT file unexpectedly succeeded");
        }
        if let Some(0) = call(Syscall::Ftruncate.raw(), a1(fx.fd1, PAGE)) {
            return Err("ftruncate on an exFAT file unexpectedly succeeded");
        }
        let mut disk = alloc::vec![0u8; 600];
        pread(fx.fd2, &mut disk, 0)?;
        if disk != seed {
            return Err("the failed mutations disturbed the file's bytes");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/coherence/exfat",
    smoke_exfat_write_and_truncate_are_unsupported
);

// ── Fixture image ───────────────────────────────────────────────
//
// A copy of `drivers/fs/exfat`' test `build_exfat_image`, extended
// in one respect: the file's data spans as many contiguous clusters
// as it needs (the stream entry keeps `NoFatChain`, so the data is
// the run of clusters starting at FILE_CLUSTER and the allocation
// bitmap marks the whole run in use). Geometry is the driver's:
// 512-byte sectors, 1 sector per cluster, FAT at 24, heap at 32.

const LBS: usize = 512;
const SECTORS_PER_CLUSTER: u32 = 1;
const FAT_OFFSET_SECTORS: u32 = 24;
const FAT_LENGTH_SECTORS: u32 = 8;
const CLUSTER_HEAP_OFFSET: u32 = 32;
const TOTAL_SECTORS: u64 = 256;
const CLUSTER_COUNT: u32 = 64;
const ROOT_DIRECTORY_CLUSTER: u32 = 2;
const BITMAP_CLUSTER: u32 = 3;
const UPCASE_CLUSTER: u32 = 4;
const FILE_CLUSTER: u32 = 5;

fn write_le_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn write_le_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn write_le_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn lba_off(img: &mut [u8], lba: u64) -> &mut [u8] {
    let start = lba as usize * LBS;
    &mut img[start..start + LBS]
}

fn exfat_image(file_name: &str, file_data: &[u8]) -> alloc::vec::Vec<u8> {
    use alloc::vec;
    use narf_drivers_fs_exfat::dir::{entry_type, file_attr, name_hash, stream_flags};
    use narf_drivers_fs_exfat::upcase::UpcaseTable;

    let cluster_bytes = LBS * SECTORS_PER_CLUSTER as usize;
    let file_clusters = (file_data.len() as u32)
        .div_ceil(cluster_bytes as u32)
        .max(1);
    let mut img = vec![0u8; (TOTAL_SECTORS as usize) * LBS];

    // Boot sector.
    {
        let s = lba_off(&mut img, 0);
        s[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
        s[3..11].copy_from_slice(b"EXFAT   ");
        write_le_u64(s, 64, 0);
        write_le_u64(s, 72, TOTAL_SECTORS);
        write_le_u32(s, 80, FAT_OFFSET_SECTORS);
        write_le_u32(s, 84, FAT_LENGTH_SECTORS);
        write_le_u32(s, 88, CLUSTER_HEAP_OFFSET);
        write_le_u32(s, 92, CLUSTER_COUNT);
        write_le_u32(s, 96, ROOT_DIRECTORY_CLUSTER);
        write_le_u32(s, 100, 0xDEAD_BEEF);
        s[104..106].copy_from_slice(&0x0100u16.to_le_bytes());
        s[108] = 9; // BytesPerSectorShift (512)
        s[109] = 0; // SectorsPerClusterShift (1)
        s[110] = 1; // NumberOfFats
        s[111] = 0x80; // DriveSelect
        s[510] = 0x55;
        s[511] = 0xAA;
    }
    // FAT: media/reserved + EOC for the single-cluster residents;
    // the file's run is NoFatChain, so its FAT entries are unused.
    {
        let s = lba_off(&mut img, FAT_OFFSET_SECTORS as u64);
        write_le_u32(s, 0, 0xFFFF_FFF8);
        write_le_u32(s, 4, 0xFFFF_FFFF);
        write_le_u32(s, ROOT_DIRECTORY_CLUSTER as usize * 4, 0xFFFF_FFFF);
        write_le_u32(s, BITMAP_CLUSTER as usize * 4, 0xFFFF_FFFF);
        write_le_u32(s, UPCASE_CLUSTER as usize * 4, 0xFFFF_FFFF);
        write_le_u32(s, FILE_CLUSTER as usize * 4, 0xFFFF_FFFF);
    }
    // Up-case table: 128 explicit ASCII entries + 0xFFFF escape.
    let upcase_stream_len: u32 = (0x80 * 2) + 4;
    {
        let upcase_lba = (CLUSTER_HEAP_OFFSET + (UPCASE_CLUSTER - 2) * SECTORS_PER_CLUSTER) as u64;
        let s = lba_off(&mut img, upcase_lba);
        for i in 0u16..0x80 {
            let mapped = if (b'a' as u16..=b'z' as u16).contains(&i) {
                i - (b'a' - b'A') as u16
            } else {
                i
            };
            s[(i as usize) * 2..(i as usize) * 2 + 2].copy_from_slice(&mapped.to_le_bytes());
        }
        let off = 0x80 * 2;
        s[off..off + 2].copy_from_slice(&0xFFFFu16.to_le_bytes());
        s[off + 2..off + 4].copy_from_slice(&((0x10000 - 0x80) as u16).to_le_bytes());
    }
    // Allocation bitmap: clusters 2..=(4 + file_clusters) in use.
    let bitmap_byte_count: u64 = (CLUSTER_COUNT as u64).div_ceil(8);
    {
        let bm_lba = (CLUSTER_HEAP_OFFSET + (BITMAP_CLUSTER - 2) * SECTORS_PER_CLUSTER) as u64;
        let s = lba_off(&mut img, bm_lba);
        for c in 2..=(4 + file_clusters) {
            let bit = (c - 2) as usize;
            s[bit / 8] |= 1 << (bit % 8);
        }
    }
    // Root directory: bitmap entry, up-case entry, file entry set.
    {
        let root_lba =
            (CLUSTER_HEAP_OFFSET + (ROOT_DIRECTORY_CLUSTER - 2) * SECTORS_PER_CLUSTER) as u64;
        let s = lba_off(&mut img, root_lba);
        let bm = &mut s[0..32];
        bm[0] = entry_type::ALLOCATION_BITMAP;
        write_le_u32(bm, 20, BITMAP_CLUSTER);
        write_le_u64(bm, 24, bitmap_byte_count);
        let uc = &mut s[32..64];
        uc[0] = entry_type::UPCASE_TABLE;
        write_le_u32(uc, 20, UPCASE_CLUSTER);
        write_le_u64(uc, 24, upcase_stream_len as u64);

        let name_utf16: alloc::vec::Vec<u16> = file_name.encode_utf16().collect();
        let name_len = name_utf16.len() as u8;
        let name_slots = name_len.div_ceil(15);
        let fe = &mut s[64..96];
        fe[0] = entry_type::FILE;
        fe[1] = 1 + name_slots; // SecondaryCount: 1 stream + N name
        write_le_u16(fe, 4, file_attr::ARCHIVE);
        let upcase = UpcaseTable::ascii_fallback();
        let upcased = upcase.upcase(&name_utf16);
        let hash = name_hash(&upcased);
        let se = &mut s[96..128];
        se[0] = entry_type::STREAM_EXTENSION;
        se[1] = stream_flags::ALLOCATION_POSSIBLE | stream_flags::NO_FAT_CHAIN;
        se[3] = name_len;
        se[4..6].copy_from_slice(&hash.to_le_bytes());
        write_le_u64(se, 8, file_data.len() as u64); // ValidDataLength
        write_le_u32(se, 20, FILE_CLUSTER);
        write_le_u64(se, 24, file_data.len() as u64); // DataLength
        let mut written = 0usize;
        for slot in 0..name_slots as usize {
            let off = 128 + slot * 32;
            let ne = &mut s[off..off + 32];
            ne[0] = entry_type::FILE_NAME;
            for i in 0..15 {
                if written < name_utf16.len() {
                    let bytes = name_utf16[written].to_le_bytes();
                    ne[2 + i * 2] = bytes[0];
                    ne[2 + i * 2 + 1] = bytes[1];
                    written += 1;
                }
            }
        }
    }
    // File data: the contiguous cluster run at FILE_CLUSTER.
    {
        let file_lba = (CLUSTER_HEAP_OFFSET + (FILE_CLUSTER - 2) * SECTORS_PER_CLUSTER) as u64;
        let start = file_lba as usize * LBS;
        img[start..start + file_data.len()].copy_from_slice(file_data);
    }
    img
}
