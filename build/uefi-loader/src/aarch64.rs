// SPDX-License-Identifier: GPL-2.0-or-later

use blake2::{Blake2b512, Digest};
#[cfg(not(test))]
use core::panic::PanicInfo;
use core::{ptr, slice};
use uefi::{
    boot::{self, AllocateType, MemoryType},
    cstr16, entry, guid,
    mem::memory_map::MemoryMap,
    prelude::Status,
    proto::media::file::{File, FileAttribute, FileMode, RegularFile},
    system,
};

const PAGE_SIZE: u64 = 4096;
const ELF_HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;
const MAX_PROGRAM_HEADERS: usize = 64;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const EM_AARCH64: u16 = 183;
const ET_EXEC: u16 = 2;
const EV_CURRENT: u32 = 1;
const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_HEADER_SIZE: usize = 40;
// ArmVirt EDK2 may expand QEMU's supplied tree with firmware nodes and slack;
// current Ubuntu firmware publishes a little over 2 MiB. Keep a strict bound
// while allowing that real configuration-table payload.
const MAX_DTB_SIZE: usize = 4 * 1024 * 1024;
const MAX_KERNEL_LOAD_SPAN: u64 = 1024 * 1024 * 1024;
/// Most firmware-occupied holes the kernel's file-backed span can straddle.
/// AAVMF parks one 128 KiB BOOT_SERVICES_DATA block inside it; eight is
/// headroom for denser firmware layouts, and anything more fails loudly
/// instead of silently dropping a hole.
const MAX_SPAN_HOLES: usize = 8;
/// Most memory-map entries that can overlap the file-backed span. The span
/// is under 1 GiB by the check above; three cover the observed AAVMF map.
const MAX_SPAN_ENTRIES: usize = 32;
/// Most staged file ranges (one per hole × segment overlap) deferred past
/// ExitBootServices. A hole normally sits inside a single segment.
const MAX_HOLE_FILLS: usize = 16;
const EFI_DTB_TABLE_GUID: uefi::Guid = guid!("b1b621d5-f19c-41a5-830b-d9152c69aae0");
const KERNEL_HASH_MARKER: [u8; 20] = *b"NARF_KERNEL_BLAKE2B=";
const KERNEL_HASH_PLACEHOLDER: [u8; 64] = [0xa5; 64];
const KERNEL_HASH_BUFFER_SIZE: usize = 4096;
/// QEMU `virt` PL011 UART base. The smoke test's serial capture is this
/// UART, and the firmware console writes through it, so direct MMIO writes
/// here after ExitBootServices land in the same captured stream.
const PL011_BASE: u64 = 0x0900_0000;
const PL011_DR_OFFSET: u64 = 0x000;
const PL011_FR_OFFSET: u64 = 0x018;
const PL011_FR_TXFF: u32 = 1 << 5;
/// PL011 peripheral-ID registers (read-only): part number 0x011 plus the
/// ARM PrimeCell ID block. PID2/PID3 are revision-dependent and deliberately
/// not checked.
const PL011_PERIPH_ID0_OFFSET: u64 = 0xfe0;
const PL011_PERIPH_ID1_OFFSET: u64 = 0xfe4;
const PL011_CELL_ID0_OFFSET: u64 = 0xff0;
const PL011_CELL_ID1_OFFSET: u64 = 0xff4;
const PL011_CELL_ID2_OFFSET: u64 = 0xff8;
const PL011_CELL_ID3_OFFSET: u64 = 0xffc;

/// One memory-map entry overlapping the kernel's file-backed span.
#[derive(Clone, Copy, Debug)]
struct MapEntry {
    start: u64,
    end: u64,
    ty: MemoryType,
}

/// The file-backed span split at firmware-occupied holes: free runs are
/// claimed with `AllocateAddress`, holes are deferred past ExitBootServices.
struct SpanPartition {
    free_runs: [(u64, u64); MAX_SPAN_HOLES + 1],
    free_count: usize,
    holes: [(u64, u64); MAX_SPAN_HOLES],
    hole_count: usize,
}

impl SpanPartition {
    fn free_runs(&self) -> &[(u64, u64)] {
        &self.free_runs[..self.free_count]
    }

    fn holes(&self) -> &[(u64, u64)] {
        &self.holes[..self.hole_count]
    }
}

/// File bytes staged before ExitBootServices for one hole: after the
/// firmware releases the pages, they are copied to `dest`.
#[derive(Clone, Copy)]
struct HoleFill {
    dest: u64,
    staging: u64,
    len: usize,
}

const EMPTY_HOLE_FILL: HoleFill = HoleFill {
    dest: 0,
    staging: 0,
    len: 0,
};

#[repr(C)]
struct KernelHashBinding {
    marker: [u8; 20],
    digest: [u8; 64],
}

// `packaging/bind-aarch64-uefi.py` replaces only `digest`, then the resulting
// PE/COFF image is signed. The volatile read below is intentional: without it
// the compiler may constant-fold the placeholder into code, making the binary
// patch ineffective even though this retained section changed.
#[used]
#[link_section = ".narfhash"]
static KERNEL_HASH_BINDING: KernelHashBinding = KernelHashBinding {
    marker: KERNEL_HASH_MARKER,
    digest: KERNEL_HASH_PLACEHOLDER,
};

#[derive(Clone, Copy)]
struct LoadSegment {
    file_offset: u64,
    physical: u64,
    file_size: u64,
    memory_size: u64,
    flags: u32,
}

const EMPTY_LOAD_SEGMENT: LoadSegment = LoadSegment {
    file_offset: 0,
    physical: 0,
    file_size: 0,
    memory_size: 0,
    flags: 0,
};

#[derive(Clone, Copy)]
struct ElfHeader {
    entry: u64,
    program_headers_offset: u64,
    program_headers_count: usize,
}

struct ParsedElf {
    entry: u64,
    segments: [LoadSegment; MAX_PROGRAM_HEADERS],
    segment_count: usize,
    load_start: u64,
    load_end: u64,
    /// Highest address holding FILE-backed bytes. `[file_backed_end,
    /// load_end)` is .bss: it must be zero when the kernel starts, but it
    /// need not be allocated while boot services are live.
    file_backed_end: u64,
}

impl ParsedElf {
    fn segments(&self) -> &[LoadSegment] {
        &self.segments[..self.segment_count]
    }
}

#[derive(Debug)]
enum LoadError {
    FileSystem,
    MissingDtb,
    MissingKernelTrust,
    KernelIntegrity,
    InvalidElf,
    UnsupportedElf,
    InvalidDtb,
    Arithmetic,
    Allocation,
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[entry]
fn main() -> Status {
    if uefi::helpers::init().is_err() {
        return Status::ABORTED;
    }

    match load_and_start() {
        Ok(()) => Status::ABORTED,
        Err(error) => {
            uefi::println!("NARF UEFI loader: {error:?}");
            Status::LOAD_ERROR
        }
    }
}

fn load_and_start() -> Result<(), LoadError> {
    // One line on the success path, so a silent hang can tell the loader
    // apart from the firmware: if this line is missing, the loader never
    // ran (or its console output never reached serial).
    uefi::println!("NARF UEFI loader: starting");
    let dtb = system::with_config_table(|tables| {
        tables
            .iter()
            .find(|entry| entry.guid == EFI_DTB_TABLE_GUID)
            .map(|entry| entry.address as usize)
    })
    .filter(|address| *address != 0)
    .ok_or(LoadError::MissingDtb)?;
    // SAFETY: the standard EFI DTB configuration-table entry is a
    // firmware-owned pointer valid through ExitBootServices.
    let dtb_header = unsafe { slice::from_raw_parts(dtb as *const u8, FDT_HEADER_SIZE) };
    if validate_dtb_header(dtb_header).is_err() {
        uefi::println!(
            "NARF UEFI loader: invalid DTB table at {:#x}, header {:02x?}",
            dtb,
            &dtb_header[..8]
        );
    }
    let dtb_size = validate_dtb_header(dtb_header)?;
    let dtb_end = dtb.checked_add(dtb_size).ok_or(LoadError::Arithmetic)?;

    // Stream the kernel instead of reading the whole ELF into a pool-backed
    // Vec. A large pool allocation may occupy pages inside the kernel's fixed
    // physical load range, making AllocateAddress fail even when enough RAM is
    // otherwise free.
    let mut protocol =
        boot::get_image_file_system(boot::image_handle()).map_err(|_| LoadError::FileSystem)?;
    let mut root = protocol.open_volume().map_err(|_| LoadError::FileSystem)?;
    let opened_kernel = root
        .open(
            cstr16!(r"\EFI\NARF\narf-frame"),
            FileMode::Read,
            FileAttribute::empty(),
        )
        .or_else(|_| {
            root.open(
                cstr16!(r"\boot\narf-frame"),
                FileMode::Read,
                FileAttribute::empty(),
            )
        })
        .map_err(|_| LoadError::FileSystem)?;
    let mut kernel = opened_kernel
        .into_regular_file()
        .ok_or(LoadError::FileSystem)?;
    kernel
        .set_position(RegularFile::END_OF_FILE)
        .map_err(|_| LoadError::FileSystem)?;
    let kernel_size = kernel.get_position().map_err(|_| LoadError::FileSystem)?;
    verify_kernel_hash(&mut kernel, kernel_size)?;

    let mut elf_header = [0u8; ELF_HEADER_SIZE];
    read_exact_at(&mut kernel, 0, &mut elf_header)?;
    let header = parse_elf_header(&elf_header, kernel_size)?;
    let table_size = PROGRAM_HEADER_SIZE
        .checked_mul(header.program_headers_count)
        .ok_or(LoadError::Arithmetic)?;
    let mut program_headers = [0u8; PROGRAM_HEADER_SIZE * MAX_PROGRAM_HEADERS];
    read_exact_at(
        &mut kernel,
        header.program_headers_offset,
        &mut program_headers[..table_size],
    )?;
    let elf = parse_program_headers(&header, &program_headers[..table_size], kernel_size)?;

    let page_start = align_down(elf.load_start, PAGE_SIZE);
    let page_end = align_up(elf.load_end, PAGE_SIZE).ok_or(LoadError::Arithmetic)?;
    // One snapshot for the DTB relocation below, the tail validation, the
    // hole-tolerant allocation, and the allocation-failure diagnostics. The
    // snapshot may list its own backing buffer as a LOADER_DATA hole inside
    // the span; the partition below treats that like any other reclaimable
    // hole.
    let map = boot::memory_map(MemoryType::LOADER_DATA).map_err(|_| LoadError::Allocation)?;
    // Each sub-check names itself. #2127 printed the operands but not which
    // disjunct fired, so every InvalidElf sighting since showed the span
    // line and then a bare `InvalidElf` (issue #2125): the span overrun and
    // the DTB overlap are now separate refusals. The file-backed end in the
    // overlap line tells the DTB-relocation follow-up whether the DTB sits
    // in file-backed bytes or in the .bss tail.
    if page_end - page_start > MAX_KERNEL_LOAD_SPAN {
        #[cfg(not(test))]
        uefi::println!(
            "NARF UEFI loader: load span {:#x}-{:#x} ({} bytes) exceeds max {}",
            page_start,
            page_end,
            page_end - page_start,
            MAX_KERNEL_LOAD_SPAN
        );
        return Err(LoadError::InvalidElf);
    }
    // The firmware-placed DTB may sit inside the load span: AAVMF parks it
    // at 0x47df5000 on the smoke path, past the file-backed end, in the
    // span's .bss tail — that overlap refusal is hang sighting #49 onward
    // (issue #2125). Relocate the DTB instead of refusing: copy it to
    // LOADER_DATA pages outside the span while boot services are live and
    // hand the kernel the new address. The kernel parses the DTB from x0
    // first and reserves its range before its allocator runs
    // (boot/src/aarch64/mod.rs `parse_raw`), so the relocation preserves
    // the handoff contract. No home for it is a loud refusal, not a
    // silent boot.
    let dtb = if ranges_overlap(page_start as usize, page_end as usize, dtb, dtb_end) {
        #[cfg(not(test))]
        uefi::println!(
            "NARF UEFI loader: DTB {:#x}-{:#x} overlaps load span {:#x}-{:#x} (file-backed end {:#x})",
            dtb,
            dtb_end,
            page_start,
            page_end,
            elf.file_backed_end
        );
        relocate_dtb(&map, dtb, dtb_size, page_start, page_end)?
    } else {
        dtb
    };

    // Allocate only the FILE-backed prefix, not the whole memsz span.
    //
    // The kernel's last segment is mostly .bss — ~35 MB of it on aarch64,
    // dominated by `perf_event::PENDING_SAMPLES` — and the span therefore
    // runs to 0x44034ac0. Firmware parks BOOT_SERVICES_DATA at
    // 0x44000000-0x44020000, inside that span, so an AllocateAddress for the
    // full range fails and the loader dies with `Allocation` even though RAM
    // is plentiful. The overshoot is only ~215 KB; the kernel does not
    // otherwise care.
    //
    // .bss does not need to exist while boot services are live — it only has
    // to be zero when the kernel starts. BOOT_SERVICES_* memory becomes free
    // for the OS at ExitBootServices, so the tail is claimed implicitly then
    // and zeroed just before the jump. That is the ordinary bootloader
    // contract, and it removes the size ceiling entirely rather than buying
    // headroom that the next 215 KB of growth would eat.
    let alloc_end = align_up(elf.file_backed_end, PAGE_SIZE).ok_or(LoadError::Arithmetic)?;
    // The deferred tail must be memory the OS actually owns after
    // ExitBootServices. Anything else (MMIO, runtime-services, reserved) would
    // make the post-EBS zeroing corrupt something, so refuse to boot instead.
    if alloc_end < page_end {
        let mut covered = alloc_end;
        while covered < page_end {
            let Some(descriptor) = map.entries().find(|d| {
                let end = d
                    .phys_start
                    .saturating_add(d.page_count.saturating_mul(PAGE_SIZE));
                d.phys_start <= covered && covered < end
            }) else {
                uefi::println!(
                    "NARF UEFI loader: .bss tail {:#x}-{:#x} has no memory-map entry at {:#x}",
                    alloc_end,
                    page_end,
                    covered
                );
                return Err(LoadError::Allocation);
            };
            if !is_reclaimable_after_ebs(descriptor.ty) {
                uefi::println!(
                    "NARF UEFI loader: .bss tail crosses non-reclaimable {:?} at {:#x}",
                    descriptor.ty,
                    covered
                );
                return Err(LoadError::Allocation);
            }
            covered = descriptor
                .phys_start
                .saturating_add(descriptor.page_count.saturating_mul(PAGE_SIZE));
        }
    }

    // Claim the file-backed prefix around firmware-occupied holes instead
    // of one AllocateAddress for the whole span. A single call needs the
    // entire range free, so one firmware block inside it fails the whole
    // allocation: AAVMF parks 128 KiB of BOOT_SERVICES_DATA at
    // 0x44000000, which the file-backed prefix grew past once the kernel
    // passed ~63 MiB of file-backed bytes, and the loader died with
    // `Allocation` even though RAM is plentiful. Each free run is claimed
    // on its own; each hole's file bytes are staged now and written after
    // ExitBootServices, once the firmware has released the pages.
    let mut overlapping: [MapEntry; MAX_SPAN_ENTRIES] = [MapEntry {
        start: 0,
        end: 0,
        ty: MemoryType::CONVENTIONAL,
    }; MAX_SPAN_ENTRIES];
    let mut overlapping_count = 0usize;
    for descriptor in map.entries() {
        let start = descriptor.phys_start;
        let end = start.saturating_add(descriptor.page_count.saturating_mul(PAGE_SIZE));
        if end <= page_start || start >= alloc_end {
            continue;
        }
        if overlapping_count == MAX_SPAN_ENTRIES {
            uefi::println!("NARF UEFI loader: too many memory-map entries in load span");
            return Err(LoadError::Allocation);
        }
        overlapping[overlapping_count] = MapEntry {
            start,
            end,
            ty: descriptor.ty,
        };
        overlapping_count += 1;
    }
    let partition =
        partition_load_span(page_start, alloc_end, &mut overlapping[..overlapping_count])
            .inspect_err(|_| {
                print_overlapping_map(&map, page_start, page_end);
            })?;
    for &(run_start, run_end) in partition.free_runs() {
        let pages = usize::try_from((run_end - run_start) / PAGE_SIZE)
            .map_err(|_| LoadError::Arithmetic)?;
        let allocation = boot::allocate_pages(
            AllocateType::Address(run_start),
            MemoryType::LOADER_DATA,
            pages,
        )
        .map_err(|_| {
            print_overlapping_map(&map, page_start, page_end);
            LoadError::Allocation
        })?;
        if allocation.as_ptr() as u64 != run_start {
            return Err(LoadError::Allocation);
        }
    }
    // Stage each hole's file-backed bytes before ExitBootServices: the
    // pages are firmware-owned until then, so they cannot be written yet,
    // and the filesystem is gone afterwards.
    let mut fills: [HoleFill; MAX_HOLE_FILLS] = [EMPTY_HOLE_FILL; MAX_HOLE_FILLS];
    let mut fill_count = 0usize;
    for &(hole_start, hole_end) in partition.holes() {
        uefi::println!(
            "NARF UEFI loader: deferring hole {:#x}-{:#x} past ExitBootServices",
            hole_start,
            hole_end
        );
        for segment in elf.segments() {
            let file_start = segment.physical.max(hole_start);
            let file_end = (segment.physical + segment.file_size).min(hole_end);
            if file_start >= file_end {
                continue;
            }
            if fill_count == MAX_HOLE_FILLS {
                uefi::println!("NARF UEFI loader: too many deferred hole fills");
                return Err(LoadError::Allocation);
            }
            let len = usize::try_from(file_end - file_start).map_err(|_| LoadError::Arithmetic)?;
            let pages = len
                .checked_add(PAGE_SIZE as usize - 1)
                .ok_or(LoadError::Arithmetic)?
                / PAGE_SIZE as usize;
            let staging =
                boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, pages)
                    .map_err(|_| LoadError::Allocation)?;
            // SAFETY: the staging pages were just allocated for this fill
            // and are exclusively owned by this loader.
            let buffer = unsafe { slice::from_raw_parts_mut(staging.as_ptr(), len) };
            read_exact_at(
                &mut kernel,
                segment.file_offset + (file_start - segment.physical),
                buffer,
            )?;
            fills[fill_count] = HoleFill {
                dest: file_start,
                staging: staging.as_ptr() as u64,
                len,
            };
            fill_count += 1;
        }
    }

    for segment in elf.segments() {
        let zero_len = usize::try_from(segment.memory_size - segment.file_size)
            .map_err(|_| LoadError::Arithmetic)?;
        // Copy the file-backed bytes, skipping firmware-occupied holes:
        // those bytes were staged above and are written after
        // ExitBootServices, once the firmware has released the pages.
        let seg_start = segment.physical;
        let seg_end = seg_start + segment.file_size;
        let mut cursor = seg_start;
        for &(hole_start, hole_end) in partition.holes() {
            if hole_end <= seg_start || hole_start >= seg_end {
                continue;
            }
            let skip_start = hole_start.max(seg_start);
            let skip_end = hole_end.min(seg_end);
            if skip_start > cursor {
                copy_segment_piece(&mut kernel, segment, cursor, skip_start)?;
            }
            cursor = skip_end.max(cursor);
        }
        if cursor < seg_end {
            copy_segment_piece(&mut kernel, segment, cursor, seg_end)?;
        }
        // The p_memsz - p_filesz tail is zeroed AFTER ExitBootServices — see
        // the allocation comment above. Part of it may still belong to
        // firmware right now.
        let _ = zero_len;
    }

    // [hang147] diagnostic: this is the last stage that can print through
    // the firmware console — `uefi::println!` is a no-op after
    // ExitBootServices — so the marker and the post-EBS plan are recorded
    // here.
    uefi::println!(
        "NARF UEFI loader: [hang147] stage: segments-copied load-span {:#x}-{:#x} file-backed-end {:#x} entry {:#x} dtb {:#x}",
        page_start,
        page_end,
        elf.file_backed_end,
        elf.entry,
        dtb
    );
    for fill in &fills[..fill_count] {
        uefi::println!(
            "NARF UEFI loader: [hang147] plan: hole-fill dest {:#x} len {:#x}",
            fill.dest,
            fill.len
        );
    }
    for segment in elf.segments() {
        let zero_len = segment.memory_size - segment.file_size;
        if zero_len != 0 {
            uefi::println!(
                "NARF UEFI loader: [hang147] plan: bss-zero {:#x}-{:#x}",
                segment.physical + segment.file_size,
                segment.physical + segment.memory_size
            );
        }
    }
    // The post-EBS markers bypass boot services entirely (direct PL011
    // writes), but only when a PL011 was positively identified before
    // ExitBootServices — see `pl011_available`. The DTB is the
    // (possibly relocated) firmware tree, header-validated above and
    // re-validated after the copy; its range stays live until EBS.
    // SAFETY: `dtb` points at the validated DTB and `dtb_size` is its
    // total size, so the slice covers exactly the firmware tree.
    let dtb_blob = unsafe { slice::from_raw_parts(dtb as *const u8, dtb_size) };
    let probe = pl011_available(dtb_blob);
    let uart = probe.is_available();
    if !uart {
        uefi::println!(
            "NARF UEFI loader: [hang147] note: no PL011 at {:#x}, post-EBS stage markers disabled",
            PL011_BASE
        );
        probe.print_why();
    }

    drop(kernel);
    drop(root);
    drop(protocol);
    // SAFETY: filesystem protocols and all pool-backed objects were dropped;
    // loaded pages and the firmware-owned DTB intentionally remain live.
    let memory_map = unsafe { boot::exit_boot_services(None) };
    core::mem::forget(memory_map);
    uart_marker(
        uart,
        format_args!(
            "NARF UEFI loader: [hang147] stage: exited-boot-services entry {:#x} dtb {:#x}\n",
            elf.entry, dtb
        ),
    );

    // The staged hole bytes go in first: the staging buffers may sit inside
    // the .bss tail, so they are copied before the tail zeroing below wipes
    // them.
    for fill in &fills[..fill_count] {
        // SAFETY: the staging buffer holds exactly `len` file bytes read
        // before ExitBootServices, and `dest` is inside the validated load
        // span, in pages the firmware has now released.
        unsafe {
            ptr::copy_nonoverlapping(fill.staging as *const u8, fill.dest as *mut u8, fill.len);
        }
    }
    uart_marker(
        uart,
        format_args!(
            "NARF UEFI loader: [hang147] stage: hole-fill-done fills {}\n",
            fill_count
        ),
    );

    // Boot services are gone, so every BOOT_SERVICES_* range is now ordinary
    // free memory owned by us — including the .bss tail deliberately left
    // outside the allocation above. Zero it now, before the kernel runs.
    // Validated as reclaimable before EBS; no diagnostics are possible here,
    // which is exactly why that check happens while console output still
    // works.
    // [hang147] diagnostic: zero the .bss tail in bounded chunks with
    // a marker before the first chunk and after it, so a fault inside
    // the zeroing is bracketed to "before the first chunk" vs "after
    // it" instead of the whole multi-MiB range. The chunking changes
    // nothing observable — the same bytes end up zero.
    const BSS_ZERO_CHUNK: u64 = 0x10000; // 64 KiB
    let mut first_chunk = true;
    for segment in elf.segments() {
        let zero_len = segment.memory_size - segment.file_size;
        if zero_len == 0 {
            continue;
        }
        let start = segment.physical + segment.file_size;
        let end = segment.physical + segment.memory_size;
        uart_marker(
            uart,
            format_args!(
                "NARF UEFI loader: [hang147] stage: bss-zero-start {:#x}-{:#x}\n",
                start, end
            ),
        );
        let mut offset: u64 = 0;
        while offset < zero_len {
            let chunk = (zero_len - offset).min(BSS_ZERO_CHUNK);
            // SAFETY: p_filesz <= p_memsz; the range lies inside the validated
            // load span, and after ExitBootServices the loader owns all of it.
            unsafe {
                ptr::write_bytes((start + offset) as *mut u8, 0, chunk as usize);
            }
            offset += chunk;
            if first_chunk {
                first_chunk = false;
                uart_marker(
                    uart,
                    format_args!(
                        "NARF UEFI loader: [hang147] stage: bss-zero-first-chunk {:#x}\n",
                        start + offset
                    ),
                );
            }
        }
    }
    let bss_zeroed: u64 = elf
        .segments()
        .iter()
        .map(|segment| segment.memory_size - segment.file_size)
        .sum();
    uart_marker(
        uart,
        format_args!(
            "NARF UEFI loader: [hang147] stage: bss-zero-done bytes {:#x}\n",
            bss_zeroed
        ),
    );

    // The NARF aarch64 entry follows the Linux boot protocol: x0 is the
    // physical DTB address and execution begins at the ELF entry at EL1.
    // SAFETY: parse_program_headers required entry to be inside an executable PT_LOAD
    // segment copied to its declared physical address.
    let kernel_entry: extern "C" fn(usize) -> ! =
        unsafe { core::mem::transmute(elf.entry as usize) };
    uart_marker(
        uart,
        format_args!(
            "NARF UEFI loader: [hang147] stage: jumping-to-kernel entry {:#x} dtb {:#x}\n",
            elf.entry, dtb
        ),
    );
    kernel_entry(dtb)
}

fn parse_elf_header(bytes: &[u8], file_size: u64) -> Result<ElfHeader, LoadError> {
    if bytes.len() < ELF_HEADER_SIZE
        || bytes.get(0..4) != Some(b"\x7fELF")
        || bytes[4] != 2
        || bytes[5] != 1
        || bytes[6] != 1
        || read_u16(bytes, 16)? != ET_EXEC
        || read_u16(bytes, 18)? != EM_AARCH64
        || read_u32(bytes, 20)? != EV_CURRENT
        || read_u16(bytes, 52)? as usize != ELF_HEADER_SIZE
    {
        return Err(LoadError::UnsupportedElf);
    }
    let entry = read_u64(bytes, 24)?;
    let phoff = read_u64(bytes, 32)?;
    let phentsize = read_u16(bytes, 54)? as usize;
    let phnum = read_u16(bytes, 56)? as usize;
    if phentsize != PROGRAM_HEADER_SIZE || phnum == 0 || phnum > MAX_PROGRAM_HEADERS {
        #[cfg(not(test))]
        uefi::println!(
            "NARF UEFI loader: bad program header table: entry size {} (want {}), count {} (max {})",
            phentsize,
            PROGRAM_HEADER_SIZE,
            phnum,
            MAX_PROGRAM_HEADERS
        );
        return Err(LoadError::InvalidElf);
    }
    let table_size = u64::try_from(phentsize.checked_mul(phnum).ok_or(LoadError::Arithmetic)?)
        .map_err(|_| LoadError::Arithmetic)?;
    let table_end = phoff.checked_add(table_size).ok_or(LoadError::Arithmetic)?;
    if table_end > file_size {
        #[cfg(not(test))]
        uefi::println!(
            "NARF UEFI loader: program header table ends at {:#x} but the file is {:#x} bytes",
            table_end,
            file_size
        );
        return Err(LoadError::InvalidElf);
    }
    Ok(ElfHeader {
        entry,
        program_headers_offset: phoff,
        program_headers_count: phnum,
    })
}

fn parse_program_headers(
    header: &ElfHeader,
    bytes: &[u8],
    file_size: u64,
) -> Result<ParsedElf, LoadError> {
    let expected_size = PROGRAM_HEADER_SIZE
        .checked_mul(header.program_headers_count)
        .ok_or(LoadError::Arithmetic)?;
    if bytes.len() != expected_size {
        #[cfg(not(test))]
        uefi::println!(
            "NARF UEFI loader: program header table is {} bytes, expected {}",
            bytes.len(),
            expected_size
        );
        return Err(LoadError::InvalidElf);
    }

    let mut segments = [EMPTY_LOAD_SEGMENT; MAX_PROGRAM_HEADERS];
    let mut segment_count = 0usize;
    let mut load_start = u64::MAX;
    let mut load_end = 0u64;
    // Highest address that must hold FILE bytes. The tail beyond this is
    // .bss, which only has to be zero by the time the kernel runs — see
    // `load_and_start` for why that distinction matters.
    let mut file_backed_end = 0u64;
    let mut entry_is_executable = false;
    for index in 0..header.program_headers_count {
        let offset = index * PROGRAM_HEADER_SIZE;
        if read_u32(bytes, offset)? != PT_LOAD {
            continue;
        }
        let segment = LoadSegment {
            flags: read_u32(bytes, offset + 4)?,
            file_offset: read_u64(bytes, offset + 8)?,
            physical: read_u64(bytes, offset + 24)?,
            file_size: read_u64(bytes, offset + 32)?,
            memory_size: read_u64(bytes, offset + 40)?,
        };
        let alignment = read_u64(bytes, offset + 48)?;
        if segment.file_size > segment.memory_size || segment.memory_size == 0 {
            #[cfg(not(test))]
            uefi::println!(
                "NARF UEFI loader: PT_LOAD {} has filesz {:#x} and memsz {:#x}",
                index,
                segment.file_size,
                segment.memory_size
            );
            return Err(LoadError::InvalidElf);
        }
        if alignment > 1
            && (!alignment.is_power_of_two()
                || segment.physical % alignment != segment.file_offset % alignment)
        {
            #[cfg(not(test))]
            uefi::println!(
                "NARF UEFI loader: PT_LOAD {} alignment {:#x} mismatches paddr {:#x} and offset {:#x}",
                index,
                alignment,
                segment.physical,
                segment.file_offset
            );
            return Err(LoadError::InvalidElf);
        }
        let file_end = segment
            .file_offset
            .checked_add(segment.file_size)
            .ok_or(LoadError::Arithmetic)?;
        if file_end > file_size {
            #[cfg(not(test))]
            uefi::println!(
                "NARF UEFI loader: PT_LOAD {} file range ends at {:#x} but the file is {:#x} bytes",
                index,
                file_end,
                file_size
            );
            return Err(LoadError::InvalidElf);
        }
        let memory_end = segment
            .physical
            .checked_add(segment.memory_size)
            .ok_or(LoadError::Arithmetic)?;
        if segment.flags & PF_X != 0
            && header.entry >= segment.physical
            && header.entry < memory_end
        {
            entry_is_executable = true;
        }
        load_start = load_start.min(segment.physical);
        load_end = load_end.max(memory_end);
        file_backed_end = file_backed_end.max(
            segment
                .physical
                .checked_add(segment.file_size)
                .ok_or(LoadError::Arithmetic)?,
        );
        segments[segment_count] = segment;
        segment_count += 1;
    }
    if segment_count == 0 || !entry_is_executable {
        #[cfg(not(test))]
        uefi::println!(
            "NARF UEFI loader: entry {:#x} is not inside an executable PT_LOAD ({} segments)",
            header.entry,
            segment_count
        );
        return Err(LoadError::InvalidElf);
    }
    for (index, left) in segments[..segment_count].iter().enumerate() {
        let left_end = left.physical + left.memory_size;
        // The index is used by the #[cfg(not(test))] overlap diagnostic
        // below, so it is load-bearing in the production build; clippy
        // only sees the test build, where the diagnostic is compiled out.
        #[allow(clippy::needless_range_loop)]
        for right_index in index + 1..segment_count {
            let right = &segments[right_index];
            let right_end = right.physical + right.memory_size;
            if left.physical < right_end && right.physical < left_end {
                #[cfg(not(test))]
                uefi::println!(
                    "NARF UEFI loader: PT_LOAD {} ({:#x}-{:#x}) overlaps PT_LOAD {} ({:#x}-{:#x})",
                    index,
                    left.physical,
                    left_end,
                    right_index,
                    right.physical,
                    right_end
                );
                return Err(LoadError::InvalidElf);
            }
        }
    }
    Ok(ParsedElf {
        entry: header.entry,
        segments,
        segment_count,
        load_start,
        load_end,
        file_backed_end,
    })
}

#[cfg(test)]
fn parse_elf(bytes: &[u8]) -> Result<ParsedElf, LoadError> {
    let file_size = u64::try_from(bytes.len()).map_err(|_| LoadError::Arithmetic)?;
    let header = parse_elf_header(bytes, file_size)?;
    let table_start =
        usize::try_from(header.program_headers_offset).map_err(|_| LoadError::Arithmetic)?;
    let table_size = PROGRAM_HEADER_SIZE
        .checked_mul(header.program_headers_count)
        .ok_or(LoadError::Arithmetic)?;
    let table_end = table_start
        .checked_add(table_size)
        .ok_or(LoadError::Arithmetic)?;
    let table = bytes
        .get(table_start..table_end)
        .ok_or(LoadError::InvalidElf)?;
    parse_program_headers(&header, table, file_size)
}

fn read_exact_at(
    file: &mut RegularFile,
    offset: u64,
    mut destination: &mut [u8],
) -> Result<(), LoadError> {
    file.set_position(offset)
        .map_err(|_| LoadError::FileSystem)?;
    while !destination.is_empty() {
        let read = file.read(destination).map_err(|_| LoadError::FileSystem)?;
        if read == 0 {
            return Err(LoadError::FileSystem);
        }
        destination = &mut destination[read..];
    }
    Ok(())
}

fn expected_kernel_hash() -> Result<[u8; 64], LoadError> {
    // SAFETY: the binding is an aligned immutable static. A volatile read is
    // required because its bytes are deliberately patched after linking.
    let binding = unsafe { ptr::read_volatile(&raw const KERNEL_HASH_BINDING) };
    if binding.marker != KERNEL_HASH_MARKER || binding.digest == KERNEL_HASH_PLACEHOLDER {
        return Err(LoadError::MissingKernelTrust);
    }
    Ok(binding.digest)
}

fn verify_kernel_hash(file: &mut RegularFile, size: u64) -> Result<(), LoadError> {
    let expected = expected_kernel_hash()?;
    file.set_position(0).map_err(|_| LoadError::FileSystem)?;
    let mut remaining = size;
    let mut buffer = [0u8; KERNEL_HASH_BUFFER_SIZE];
    let mut hasher = Blake2b512::new();
    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| LoadError::Arithmetic)?;
        let read = file
            .read(&mut buffer[..wanted])
            .map_err(|_| LoadError::FileSystem)?;
        if read == 0 {
            return Err(LoadError::FileSystem);
        }
        hasher.update(&buffer[..read]);
        remaining -= read as u64;
    }
    let actual = hasher.finalize();
    let mut different = 0u8;
    for (actual, expected) in actual.iter().zip(expected) {
        different |= actual ^ expected;
    }
    if different != 0 {
        return Err(LoadError::KernelIntegrity);
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, LoadError> {
    read_array(bytes, offset).map(u16::from_le_bytes)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, LoadError> {
    read_array(bytes, offset).map(u32::from_le_bytes)
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, LoadError> {
    read_array(bytes, offset).map(u64::from_le_bytes)
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], LoadError> {
    let end = offset.checked_add(N).ok_or(LoadError::Arithmetic)?;
    bytes
        .get(offset..end)
        .ok_or(LoadError::InvalidElf)?
        .try_into()
        .map_err(|_| LoadError::InvalidElf)
}

fn validate_dtb_header(bytes: &[u8]) -> Result<usize, LoadError> {
    let magic = u32::from_be_bytes(read_array(bytes, 0)?);
    let size = u32::from_be_bytes(read_array(bytes, 4)?) as usize;
    if magic != FDT_MAGIC || !(FDT_HEADER_SIZE..=MAX_DTB_SIZE).contains(&size) {
        return Err(LoadError::InvalidDtb);
    }
    Ok(size)
}

const fn ranges_overlap(
    left_start: usize,
    left_end: usize,
    right_start: usize,
    right_end: usize,
) -> bool {
    left_start < right_end && right_start < left_end
}

/// Find a home for the DTB outside the kernel load span.
///
/// Returns the start of the lowest CONVENTIONAL run that fits the
/// page-aligned DTB size entirely outside `[page_start, page_end)`. A
/// CONVENTIONAL run straddling the span contributes only its outside
/// part. `None` means no such home exists and the boot must refuse
/// loudly. The choice is deterministic for a given map: the lowest
/// fitting address wins. Only CONVENTIONAL runs are candidates, so the
/// destination can never be the memory-map snapshot's own backing buffer
/// (LOADER_DATA), the firmware DTB source (inside the span), or any
/// range the span allocation below will claim.
fn find_dtb_relocation(
    entries: impl Iterator<Item = MapEntry>,
    dtb_size: usize,
    page_start: u64,
    page_end: u64,
) -> Option<u64> {
    let needed = align_up(dtb_size as u64, PAGE_SIZE)?;
    let mut best: Option<u64> = None;
    for entry in entries {
        if !matches!(entry.ty, MemoryType::CONVENTIONAL) {
            continue;
        }
        for (candidate_start, candidate_end) in [
            (entry.start, entry.end.min(page_start)),
            (entry.start.max(page_end), entry.end),
        ] {
            if candidate_end <= candidate_start || candidate_end - candidate_start < needed {
                continue;
            }
            if best.is_none_or(|best| candidate_start < best) {
                best = Some(candidate_start);
            }
        }
    }
    best
}

/// Copy the firmware DTB to LOADER_DATA pages outside the kernel load span
/// and return the new address. Runs before ExitBootServices, while the
/// firmware-owned source is still valid and allocation is still possible.
/// The destination is claimed with `AllocateAddress` before the span
/// allocation and hole-fill staging below, so neither can reuse it; after
/// ExitBootServices it is ordinary OS-owned memory, and the kernel
/// reserves the DTB range before its allocator runs
/// (boot/src/aarch64/mod.rs `parse_raw`).
fn relocate_dtb(
    map: &impl MemoryMap,
    dtb: usize,
    dtb_size: usize,
    page_start: u64,
    page_end: u64,
) -> Result<usize, LoadError> {
    let Some(dest) = find_dtb_relocation(
        map.entries().map(|d| MapEntry {
            start: d.phys_start,
            end: d
                .phys_start
                .saturating_add(d.page_count.saturating_mul(PAGE_SIZE)),
            ty: d.ty,
        }),
        dtb_size,
        page_start,
        page_end,
    ) else {
        #[cfg(not(test))]
        uefi::println!(
            "NARF UEFI loader: no CONVENTIONAL home outside load span {:#x}-{:#x} for the {:#x}-byte DTB",
            page_start,
            page_end,
            dtb_size
        );
        return Err(LoadError::InvalidElf);
    };
    let pages = usize::try_from(
        align_up(dtb_size as u64, PAGE_SIZE).ok_or(LoadError::Arithmetic)? / PAGE_SIZE,
    )
    .map_err(|_| LoadError::Arithmetic)?;
    let allocation =
        boot::allocate_pages(AllocateType::Address(dest), MemoryType::LOADER_DATA, pages)
            .map_err(|_| LoadError::Allocation)?;
    if allocation.as_ptr() as u64 != dest {
        return Err(LoadError::Allocation);
    }
    // SAFETY: the source is the firmware DTB, valid through
    // ExitBootServices; the destination is freshly allocated LOADER_DATA
    // exclusively owned by this loader.
    unsafe {
        ptr::copy_nonoverlapping(dtb as *const u8, dest as *mut u8, dtb_size);
    }
    // Re-validate the copy: a corrupt destination would make the kernel
    // read a garbage DTB at entry, so fail loudly here instead.
    // SAFETY: the destination holds exactly `dtb_size` copied bytes, and
    // `dtb_size` is at least `FDT_HEADER_SIZE` by validation above.
    let copied = unsafe { slice::from_raw_parts(dest as *const u8, FDT_HEADER_SIZE) };
    validate_dtb_header(copied)?;
    #[cfg(not(test))]
    uefi::println!(
        "NARF UEFI loader: relocated DTB {:#x}-{:#x} to {:#x}-{:#x}",
        dtb,
        dtb.checked_add(dtb_size).ok_or(LoadError::Arithmetic)?,
        dest,
        dest.checked_add(dtb_size as u64)
            .ok_or(LoadError::Arithmetic)?
    );
    Ok(dest as usize)
}

/// Memory the OS owns after ExitBootServices, so the loader may write it
/// once boot services are gone — the same rule the .bss-tail validation
/// already applies. Anything else (runtime services, reserved, MMIO) must
/// refuse to boot instead of corrupting it.
fn is_reclaimable_after_ebs(ty: MemoryType) -> bool {
    matches!(
        ty,
        MemoryType::CONVENTIONAL
            | MemoryType::BOOT_SERVICES_CODE
            | MemoryType::BOOT_SERVICES_DATA
            | MemoryType::LOADER_CODE
            | MemoryType::LOADER_DATA
    )
}

/// Print the memory-map entries overlapping the load span, so an allocation
/// failure names the firmware reservation that caused it.
fn print_overlapping_map(map: &impl MemoryMap, page_start: u64, page_end: u64) {
    for descriptor in map.entries() {
        let end = descriptor
            .phys_start
            .saturating_add(descriptor.page_count.saturating_mul(PAGE_SIZE));
        if descriptor.phys_start < page_end && page_start < end {
            uefi::println!(
                "NARF UEFI loader: map {:?} {:#x}-{:#x}",
                descriptor.ty,
                descriptor.phys_start,
                end
            );
        }
    }
}

/// Split `[page_start, alloc_end)` at firmware-occupied holes.
///
/// `AllocateAddress` needs the whole range free, so a single firmware block
/// inside the span — AAVMF parks 128 KiB of BOOT_SERVICES_DATA at
/// 0x44000000, which the file-backed prefix grew past once the kernel
/// passed ~63 MiB of file-backed bytes — fails the entire allocation even
/// though RAM is plentiful. Free runs are claimed one by one; each hole
/// must be reclaimable after ExitBootServices (checked here) so its bytes
/// can be staged and written once the firmware releases the pages.
///
/// `entries` is sorted in place; entries outside the span are ignored.
fn partition_load_span(
    page_start: u64,
    alloc_end: u64,
    entries: &mut [MapEntry],
) -> Result<SpanPartition, LoadError> {
    let mut partition = SpanPartition {
        free_runs: [(0, 0); MAX_SPAN_HOLES + 1],
        free_count: 0,
        holes: [(0, 0); MAX_SPAN_HOLES],
        hole_count: 0,
    };
    if alloc_end <= page_start {
        return Ok(partition);
    }
    entries.sort_unstable_by_key(|entry| entry.start);
    let mut cursor = page_start;
    for entry in entries.iter() {
        if entry.end <= cursor || entry.start >= alloc_end {
            continue;
        }
        let start = entry.start.max(cursor);
        let end = entry.end.min(alloc_end);
        if start > cursor {
            // A stretch of the span no entry covers: not free, not a known
            // reservation — refuse rather than guess.
            return Err(LoadError::Allocation);
        }
        if matches!(entry.ty, MemoryType::CONVENTIONAL) {
            if partition.free_count > 0 && partition.free_runs[partition.free_count - 1].1 == start
            {
                partition.free_runs[partition.free_count - 1].1 = end;
            } else {
                if partition.free_count == partition.free_runs.len() {
                    return Err(LoadError::Allocation);
                }
                partition.free_runs[partition.free_count] = (start, end);
                partition.free_count += 1;
            }
        } else {
            if !is_reclaimable_after_ebs(entry.ty) {
                return Err(LoadError::Allocation);
            }
            if partition.hole_count == partition.holes.len() {
                return Err(LoadError::Allocation);
            }
            partition.holes[partition.hole_count] = (start, end);
            partition.hole_count += 1;
        }
        cursor = end;
    }
    if cursor < alloc_end {
        return Err(LoadError::Allocation);
    }
    Ok(partition)
}

/// Copy one hole-free piece of a segment's file-backed bytes to its
/// physical address.
fn copy_segment_piece(
    kernel: &mut RegularFile,
    segment: &LoadSegment,
    from: u64,
    to: u64,
) -> Result<(), LoadError> {
    let len = usize::try_from(to - from).map_err(|_| LoadError::Arithmetic)?;
    // SAFETY: the caller only passes pieces inside the segment's
    // file-backed range, which parse_program_headers proved lies in the
    // allocated range exclusively owned by this loader.
    let destination = unsafe { slice::from_raw_parts_mut(from as *mut u8, len) };
    read_exact_at(
        kernel,
        segment.file_offset + (from - segment.physical),
        destination,
    )
}

/// Outcome of the PL011 probe, with the failure reason attached. The
/// verdict logic is the guard's: the DTB must describe a PL011 at the
/// UART address, and the ID block must read as a PL011. The reason is
/// carried so the [hang147] diagnostic can report *why* the post-EBS
/// markers were disabled from runtime evidence — the log on sighting
/// #150 recorded no reason, and the why-reporting on sighting #154
/// showed the old memory-map half could never pass: AAVMF's
/// `GetMemoryMap()` contains no entry covering the UART address.
/// Prints only; the verdict is unchanged.
#[derive(Debug)]
enum Pl011Probe {
    /// Both halves passed; post-EBS markers may write to the UART.
    Available,
    /// The DTB describes no PL011 at the UART address. `found` is the
    /// base of the first `arm,pl011` node with a decodable `reg`, if
    /// any such node exists at all.
    NoDtbUart { found: Option<u64> },
    /// The ID block did not read as a PL011; the six raw bytes read,
    /// in register order (periph ID0/ID1, cell ID0–ID3).
    IdMismatch { id: [u8; 6] },
}

impl Pl011Probe {
    const fn is_available(&self) -> bool {
        matches!(self, Self::Available)
    }

    /// Print why the probe failed, pre-EBS only. No-op when available.
    /// Called next to the "no PL011" note so the log names the failing
    /// half from runtime evidence.
    fn print_why(&self) {
        match self {
            Self::Available => {}
            Self::NoDtbUart { found: None } => {
                uefi::println!(
                    "NARF UEFI loader: [hang147] why: no arm,pl011 node with a decodable reg in the DTB"
                );
            }
            Self::NoDtbUart { found: Some(addr) } => {
                uefi::println!(
                    "NARF UEFI loader: [hang147] why: DTB PL011 at {:#x}, not {:#x}",
                    addr,
                    PL011_BASE
                );
            }
            Self::IdMismatch { id } => {
                uefi::println!(
                    "NARF UEFI loader: [hang147] why: PL011 ID block mismatch {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x}",
                    id[0], id[1], id[2], id[3], id[4], id[5]
                );
            }
        }
    }
}

/// Scan the DTB for `arm,pl011` nodes. Returns `(at_base, first)`:
/// whether any such node's `reg` base is the UART address, and the
/// base of the first `arm,pl011` node with a decodable `reg` (for the
/// why-report when none sits at the UART address). The `reg` layout
/// follows whatever `#address-cells` / `#size-cells` the DTB's parent
/// declares — QEMU's `virt` tree uses 2/2 with
/// `reg = <0x0 0x09000000 0x0 0x1000>` on `serial@9000000`, but
/// nothing here assumes that shape. A malformed DTB simply yields no
/// match (the walker returns early), so the probe fails safe.
fn dtb_pl011(dtb: &[u8]) -> (bool, Option<u64>) {
    let mut first: Option<u64> = None;
    let mut at_base = false;
    narf_firmware_fdt::for_each_compatible(dtb, "arm,pl011", |_path, props, cells| {
        let mut base = None;
        for (name, value) in props {
            if name == "reg" {
                base = cells.read_one_reg(value, 0).map(|(addr, _size)| addr);
                break;
            }
        }
        if let Some(addr) = base {
            if first.is_none() {
                first = Some(addr);
            }
            if addr == PL011_BASE {
                at_base = true;
            }
        }
    });
    (at_base, first)
}

/// Is there a real PL011 at the QEMU `virt` UART address? Both halves
/// are checked while boot services are live: the DTB must describe a
/// PL011 at the address, and the PrimeCell ID block must read as a
/// PL011. The result is carried into the post-EBS stages, where no
/// firmware service can answer the question anymore — and where a
/// wrong guess would write marker bytes into an unrelated device's
/// registers.
///
/// The first half used to be a UEFI memory-map MMIO lookup; that
/// premise is wrong for this firmware (AAVMF's `GetMemoryMap()` never
/// lists the platform UART — device MMIO is described via DT, UEFI
/// spec 15.4 — confirmed from runtime evidence on sighting #154,
/// whose why-lines printed `no MMIO map entry covers 0x9000000`).
/// The DTB is the firmware's own device description and the loader
/// already holds and validates it, so it is the principled source.
fn pl011_available(dtb: &[u8]) -> Pl011Probe {
    let (at_base, first) = dtb_pl011(dtb);
    if !at_base {
        return Pl011Probe::NoDtbUart { found: first };
    }
    // SAFETY: the DTB describes a PL011 at this address, and the ID
    // registers are read-only by the PrimeCell specification.
    let id =
        |offset: u64| unsafe { ptr::read_volatile((PL011_BASE + offset) as *const u32) & 0xff };
    let bytes = [
        id(PL011_PERIPH_ID0_OFFSET) as u8,
        id(PL011_PERIPH_ID1_OFFSET) as u8,
        id(PL011_CELL_ID0_OFFSET) as u8,
        id(PL011_CELL_ID1_OFFSET) as u8,
        id(PL011_CELL_ID2_OFFSET) as u8,
        id(PL011_CELL_ID3_OFFSET) as u8,
    ];
    if bytes == [0x11, 0x10, 0x0d, 0xf0, 0x05, 0xb1] {
        Pl011Probe::Available
    } else {
        Pl011Probe::IdMismatch { id: bytes }
    }
}

/// Write one byte straight to the PL011 data register, waiting for TX
/// FIFO space first. Only called after ExitBootServices (see
/// `uart_marker`); the firmware leaves the UART configured, and the
/// smoke test captures this UART, so the bytes land in the same serial
/// log the firmware console was writing to.
unsafe fn uart_write_byte(byte: u8) {
    // SAFETY: the caller verified with `pl011_available` before
    // ExitBootServices that a PL011 lives at this address.
    while ptr::read_volatile((PL011_BASE + PL011_FR_OFFSET) as *const u32) & PL011_FR_TXFF != 0 {
        core::hint::spin_loop();
    }
    ptr::write_volatile((PL011_BASE + PL011_DR_OFFSET) as *mut u32, u32::from(byte));
}

/// Write `s` to the PL011, expanding `\n` to `\r\n` so the captured
/// serial log stays readable.
unsafe fn uart_write_str(s: &str) {
    for &byte in s.as_bytes() {
        if byte == b'\n' {
            uart_write_byte(b'\r');
        }
        uart_write_byte(byte);
    }
}

/// `core::fmt::Write` adapter over the direct PL011 writer, so post-EBS
/// stage markers can format addresses the same way `uefi::println!` does.
struct UartWriter;

impl core::fmt::Write for UartWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        // SAFETY: the caller verified the PL011 with `pl011_available`
        // before ExitBootServices; see `uart_marker`.
        unsafe { uart_write_str(s) };
        Ok(())
    }
}

/// Post-EBS stage marker. `uefi::println!` is a no-op once boot services
/// are gone (uefi 0.39 `helpers::_print` returns early when
/// `are_boot_services_active()` is false), so after ExitBootServices the
/// marker goes straight to the PL011 instead — the only output channel
/// left. When `uart` is false (no PL011 was found before EBS) the marker
/// is silently skipped, so a machine without a QEMU `virt` UART boots
/// exactly as before; the pre-EBS plan print is then the last record.
fn uart_marker(uart: bool, args: core::fmt::Arguments) {
    if uart {
        let _ = core::fmt::write(&mut UartWriter, args);
    }
}

const fn align_down(value: u64, alignment: u64) -> u64 {
    value & !(alignment - 1)
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    value
        .checked_add(alignment - 1)
        .map(|v| align_down(v, alignment))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    fn valid_elf() -> Vec<u8> {
        let mut bytes = vec![0u8; ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE + 4];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        bytes[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
        bytes[20..24].copy_from_slice(&EV_CURRENT.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x4008_0000u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&(ELF_HEADER_SIZE as u64).to_le_bytes());
        bytes[54..56].copy_from_slice(&(PROGRAM_HEADER_SIZE as u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
        bytes[52..54].copy_from_slice(&(ELF_HEADER_SIZE as u16).to_le_bytes());
        let ph = ELF_HEADER_SIZE;
        bytes[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        bytes[ph + 4..ph + 8].copy_from_slice(&PF_X.to_le_bytes());
        bytes[ph + 8..ph + 16]
            .copy_from_slice(&((ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE) as u64).to_le_bytes());
        bytes[ph + 24..ph + 32].copy_from_slice(&0x4008_0000u64.to_le_bytes());
        bytes[ph + 32..ph + 40].copy_from_slice(&4u64.to_le_bytes());
        bytes[ph + 40..ph + 48].copy_from_slice(&8u64.to_le_bytes());
        bytes[ph + 48..ph + 56].copy_from_slice(&1u64.to_le_bytes());
        bytes
    }

    #[test]
    fn file_backed_end_excludes_the_bss_tail() {
        // The loader allocates only up to `file_backed_end` and zeroes the
        // rest after ExitBootServices. If those two ever collapse to the same
        // value the allocation grows back to the full memsz span and aarch64
        // UEFI boot fails with `Allocation` again — firmware parks
        // BOOT_SERVICES_DATA inside that tail.
        let elf = parse_elf(&valid_elf()).unwrap();
        // The fixture is p_filesz = 4, p_memsz = 8.
        assert_eq!(elf.file_backed_end, 0x4008_0000 + 4);
        assert_eq!(elf.load_end, 0x4008_0000 + 8);
        assert!(
            elf.file_backed_end < elf.load_end,
            "the .bss tail must stay outside the allocated range"
        );
    }

    #[test]
    fn accepts_aarch64_load_segment_and_bss() {
        let elf = parse_elf(&valid_elf()).unwrap();
        assert_eq!(elf.entry, 0x4008_0000);
        assert_eq!(elf.segments().len(), 1);
        assert_eq!(elf.load_start, 0x4008_0000);
        assert_eq!(elf.load_end, 0x4008_0008);
    }

    #[test]
    fn rejects_non_aarch64_elf() {
        let mut bytes = valid_elf();
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        assert!(matches!(parse_elf(&bytes), Err(LoadError::UnsupportedElf)));
    }

    #[test]
    fn rejects_segment_with_filesz_larger_than_memsz() {
        let mut bytes = valid_elf();
        let ph = ELF_HEADER_SIZE;
        bytes[ph + 32..ph + 40].copy_from_slice(&9u64.to_le_bytes());
        assert!(matches!(parse_elf(&bytes), Err(LoadError::InvalidElf)));
    }

    #[test]
    fn rejects_entry_outside_executable_segment() {
        let mut bytes = valid_elf();
        bytes[24..32].copy_from_slice(&0x5000_0000u64.to_le_bytes());
        assert!(matches!(parse_elf(&bytes), Err(LoadError::InvalidElf)));
    }

    #[test]
    fn rejects_unbounded_program_header_table() {
        let mut bytes = valid_elf();
        bytes[56..58].copy_from_slice(&((MAX_PROGRAM_HEADERS + 1) as u16).to_le_bytes());
        assert!(matches!(parse_elf(&bytes), Err(LoadError::InvalidElf)));
    }

    #[test]
    fn validates_bounded_dtb_header() {
        let mut header = [0u8; FDT_HEADER_SIZE];
        header[0..4].copy_from_slice(&FDT_MAGIC.to_be_bytes());
        header[4..8].copy_from_slice(&(FDT_HEADER_SIZE as u32).to_be_bytes());
        assert_eq!(validate_dtb_header(&header).unwrap(), FDT_HEADER_SIZE);
        header[4..8].copy_from_slice(&((MAX_DTB_SIZE + 1) as u32).to_be_bytes());
        assert!(matches!(
            validate_dtb_header(&header),
            Err(LoadError::InvalidDtb)
        ));
    }

    #[test]
    fn unbound_loader_fails_closed() {
        assert!(matches!(
            expected_kernel_hash(),
            Err(LoadError::MissingKernelTrust)
        ));
    }

    fn conventional(start: u64, end: u64) -> MapEntry {
        MapEntry {
            start,
            end,
            ty: MemoryType::CONVENTIONAL,
        }
    }

    fn firmware_hole(start: u64, end: u64) -> MapEntry {
        MapEntry {
            start,
            end,
            ty: MemoryType::BOOT_SERVICES_DATA,
        }
    }

    #[test]
    fn partition_keeps_one_run_without_holes() {
        let mut entries = [conventional(0x4008_0000, 0x4800_0000)];
        let partition = partition_load_span(0x4008_0000, 0x4400_0000, &mut entries).unwrap();
        assert_eq!(
            partition.free_runs(),
            [(0x4008_0000u64, 0x4400_0000u64)].as_slice()
        );
        assert!(partition.holes().is_empty());
    }

    #[test]
    fn partition_splits_one_firmware_hole() {
        // The observed AAVMF map: 128 KiB of BOOT_SERVICES_DATA at
        // 0x44000000 inside the file-backed span.
        let mut entries = [
            conventional(0x4000_0000, 0x4400_0000),
            firmware_hole(0x4400_0000, 0x4402_0000),
            conventional(0x4402_0000, 0x476f_2000),
        ];
        let partition = partition_load_span(0x4008_0000, 0x4700_0000, &mut entries).unwrap();
        assert_eq!(
            partition.free_runs(),
            [
                (0x4008_0000u64, 0x4400_0000u64),
                (0x4402_0000u64, 0x4700_0000u64),
            ]
            .as_slice()
        );
        assert_eq!(
            partition.holes(),
            [(0x4400_0000u64, 0x4402_0000u64)].as_slice()
        );
    }

    #[test]
    fn partition_accepts_unsorted_entries() {
        let mut entries = [
            conventional(0x4402_0000, 0x476f_2000),
            firmware_hole(0x4400_0000, 0x4402_0000),
            conventional(0x4000_0000, 0x4400_0000),
        ];
        let partition = partition_load_span(0x4008_0000, 0x4700_0000, &mut entries).unwrap();
        assert_eq!(
            partition.holes(),
            [(0x4400_0000u64, 0x4402_0000u64)].as_slice()
        );
        assert_eq!(partition.free_runs().len(), 2);
    }

    #[test]
    fn partition_rejects_non_reclaimable_hole() {
        let mut entries = [
            conventional(0x4000_0000, 0x4400_0000),
            MapEntry {
                start: 0x4400_0000,
                end: 0x4402_0000,
                ty: MemoryType::RUNTIME_SERVICES_DATA,
            },
            conventional(0x4402_0000, 0x476f_2000),
        ];
        assert!(matches!(
            partition_load_span(0x4008_0000, 0x4700_0000, &mut entries),
            Err(LoadError::Allocation)
        ));
    }

    #[test]
    fn partition_rejects_gap_in_span() {
        let mut entries = [
            conventional(0x4000_0000, 0x4200_0000),
            conventional(0x4300_0000, 0x476f_2000),
        ];
        assert!(matches!(
            partition_load_span(0x4008_0000, 0x4700_0000, &mut entries),
            Err(LoadError::Allocation)
        ));
    }

    #[test]
    fn partition_rejects_too_many_holes() {
        // 19 alternating entries need 9 holes, over the cap of 8.
        let mut entries = [conventional(0, 0); MAX_SPAN_HOLES * 2 + 3];
        let mut start = 0x4008_0000u64;
        for (i, entry) in entries.iter_mut().enumerate() {
            let end = start + 0x1000;
            *entry = if i % 2 == 0 {
                conventional(start, end)
            } else {
                firmware_hole(start, end)
            };
            start = end;
        }
        assert!(matches!(
            partition_load_span(0x4008_0000, start, &mut entries),
            Err(LoadError::Allocation)
        ));
    }

    #[test]
    fn partition_empty_span_allocates_nothing() {
        let mut entries = [conventional(0x4000_0000, 0x4800_0000)];
        let partition = partition_load_span(0x4008_0000, 0x4008_0000, &mut entries).unwrap();
        assert!(partition.free_runs().is_empty());
        assert!(partition.holes().is_empty());
    }

    #[test]
    fn reclaimable_after_ebs_matches_tail_rule() {
        for ty in [
            MemoryType::CONVENTIONAL,
            MemoryType::BOOT_SERVICES_CODE,
            MemoryType::BOOT_SERVICES_DATA,
            MemoryType::LOADER_CODE,
            MemoryType::LOADER_DATA,
        ] {
            assert!(is_reclaimable_after_ebs(ty), "{ty:?} must be reclaimable");
        }
        for ty in [
            MemoryType::RUNTIME_SERVICES_CODE,
            MemoryType::RUNTIME_SERVICES_DATA,
            MemoryType::ACPI_RECLAIM,
            MemoryType::MMIO,
            MemoryType::RESERVED,
        ] {
            assert!(
                !is_reclaimable_after_ebs(ty),
                "{ty:?} must not be reclaimable"
            );
        }
    }

    #[test]
    fn relocation_finds_home_above_span() {
        // The live smoke-path layout: the firmware DTB sits at
        // 0x47df5000-0x47ffa000 inside the load span
        // 0x40080000-0x49c45000, with CONVENTIONAL RAM above the span.
        let entries = [
            conventional(0x4000_0000, 0x4008_0000),
            firmware_hole(0x47df_5000, 0x47ff_a000),
            conventional(0x49c4_5000, 0x8000_0000),
        ];
        assert_eq!(
            find_dtb_relocation(entries.iter().copied(), 0x205_000, 0x4008_0000, 0x49c4_5000),
            Some(0x49c4_5000)
        );
    }

    #[test]
    fn relocation_skips_runs_inside_the_span() {
        let entries = [conventional(0x4008_0000, 0x4400_0000)];
        assert_eq!(
            find_dtb_relocation(entries.iter().copied(), 0x1000, 0x4008_0000, 0x49c4_5000),
            None
        );
    }

    #[test]
    fn relocation_skips_firmware_memory() {
        let entries = [firmware_hole(0x49c4_5000, 0x5000_0000)];
        assert_eq!(
            find_dtb_relocation(entries.iter().copied(), 0x1000, 0x4008_0000, 0x49c4_5000),
            None
        );
    }

    #[test]
    fn relocation_uses_below_span_part_of_straddling_run() {
        let entries = [conventional(0x4000_0000, 0x4010_0000)];
        assert_eq!(
            find_dtb_relocation(entries.iter().copied(), 0x80000, 0x4008_0000, 0x49c4_5000),
            Some(0x4000_0000)
        );
    }

    #[test]
    fn relocation_uses_above_span_part_when_below_is_too_small() {
        let entries = [
            conventional(0x4000_0000, 0x4009_0000),
            conventional(0x49c4_5000, 0x4a00_0000),
        ];
        assert_eq!(
            find_dtb_relocation(entries.iter().copied(), 0x100_000, 0x4008_0000, 0x49c4_5000),
            Some(0x49c4_5000)
        );
    }

    #[test]
    fn relocation_returns_none_when_outside_run_is_too_small() {
        let entries = [conventional(0x49c4_5000, 0x49c4_6000)];
        assert_eq!(
            find_dtb_relocation(entries.iter().copied(), 0x2000, 0x4008_0000, 0x49c4_5000),
            None
        );
    }

    #[test]
    fn relocation_picks_lowest_fitting_address() {
        let entries = [
            conventional(0x5000_0000, 0x6000_0000),
            conventional(0x49c4_5000, 0x4a00_0000),
        ];
        assert_eq!(
            find_dtb_relocation(entries.iter().copied(), 0x1000, 0x4008_0000, 0x49c4_5000),
            Some(0x49c4_5000)
        );
    }

    /// One flat DTB node for the test helper: a name with its
    /// (property name, value) pairs. Named so the `build_dtb`
    /// signature stays below clippy's `type_complexity` threshold.
    type DtbNode<'a> = (&'a str, &'a [(&'a str, &'a [u8])]);

    /// Build a minimal DTB: root with `#address-cells` /
    /// `#size-cells` 2/2 (like QEMU's `virt` tree) plus flat child
    /// nodes, each a name with (prop-name, value) pairs. Mirrors
    /// `firmware/fdt`'s `build_blob` test helper.
    fn build_dtb(nodes: &[DtbNode<'_>]) -> Vec<u8> {
        let mut strings: Vec<u8> = Vec::new();
        let intern = |strings: &mut Vec<u8>, name: &str| -> u32 {
            let target = name.as_bytes();
            let mut i = 0;
            while i + target.len() < strings.len() {
                if &strings[i..i + target.len()] == target && strings[i + target.len()] == 0 {
                    return i as u32;
                }
                i += 1;
            }
            let off = strings.len() as u32;
            strings.extend_from_slice(target);
            strings.push(0);
            off
        };

        let mut s: Vec<u8> = Vec::new();
        // Root open: BEGIN_NODE + empty name + pad.
        s.extend_from_slice(&narf_firmware_fdt::FDT_BEGIN_NODE.to_be_bytes());
        s.extend_from_slice(&[0, 0, 0, 0]);
        for (pname, pval) in [
            ("#address-cells", 2u32.to_be_bytes()),
            ("#size-cells", 2u32.to_be_bytes()),
        ] {
            let off = intern(&mut strings, pname);
            s.extend_from_slice(&narf_firmware_fdt::FDT_PROP.to_be_bytes());
            s.extend_from_slice(&(pval.len() as u32).to_be_bytes());
            s.extend_from_slice(&off.to_be_bytes());
            s.extend_from_slice(&pval);
        }
        for (node_name, props) in nodes {
            s.extend_from_slice(&narf_firmware_fdt::FDT_BEGIN_NODE.to_be_bytes());
            s.extend_from_slice(node_name.as_bytes());
            s.push(0);
            while !s.len().is_multiple_of(4) {
                s.push(0);
            }
            for (pname, pval) in *props {
                let off = intern(&mut strings, pname);
                s.extend_from_slice(&narf_firmware_fdt::FDT_PROP.to_be_bytes());
                s.extend_from_slice(&(pval.len() as u32).to_be_bytes());
                s.extend_from_slice(&off.to_be_bytes());
                s.extend_from_slice(pval);
                while !s.len().is_multiple_of(4) {
                    s.push(0);
                }
            }
            s.extend_from_slice(&narf_firmware_fdt::FDT_END_NODE.to_be_bytes());
        }
        s.extend_from_slice(&narf_firmware_fdt::FDT_END_NODE.to_be_bytes());
        s.extend_from_slice(&narf_firmware_fdt::FDT_END.to_be_bytes());

        let struct_size = s.len() as u32;
        let strings_size = strings.len() as u32;
        // Empty reserve map: just the 16-byte terminator.
        let off_rsvmap = 40u32;
        let off_struct = off_rsvmap + 16;
        let off_strings = off_struct + struct_size;
        let totalsize = off_strings + strings_size;

        let mut out: Vec<u8> = Vec::with_capacity(totalsize as usize);
        out.extend_from_slice(&FDT_MAGIC.to_be_bytes());
        out.extend_from_slice(&totalsize.to_be_bytes());
        out.extend_from_slice(&off_struct.to_be_bytes());
        out.extend_from_slice(&off_strings.to_be_bytes());
        out.extend_from_slice(&off_rsvmap.to_be_bytes());
        out.extend_from_slice(&17u32.to_be_bytes());
        out.extend_from_slice(&16u32.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&strings_size.to_be_bytes());
        out.extend_from_slice(&struct_size.to_be_bytes());
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&s);
        out.extend_from_slice(&strings);
        out
    }

    /// `reg = <0x0 <base> 0x0 0x1000>` under root cells 2/2.
    fn pl011_reg(base: u32) -> [u8; 16] {
        let mut reg = [0u8; 16];
        reg[4..8].copy_from_slice(&base.to_be_bytes());
        reg[12..16].copy_from_slice(&0x1000u32.to_be_bytes());
        reg
    }

    #[test]
    fn dtb_pl011_finds_virt_uart_at_0x09000000() {
        // QEMU `virt` shape: `serial@9000000` with compatible
        // "arm,pl011", "arm,primecell" and reg <0x0 0x09000000 0x0 0x1000>.
        let reg = pl011_reg(0x0900_0000);
        let blob = build_dtb(&[(
            "serial@9000000",
            &[
                ("compatible", b"arm,pl011\0arm,primecell\0" as &[u8]),
                ("reg", &reg),
            ][..],
        )]);
        assert_eq!(dtb_pl011(&blob), (true, Some(0x0900_0000)));
    }

    #[test]
    fn dtb_pl011_reports_pl011_at_another_address() {
        let reg = pl011_reg(0x0901_0000);
        let blob = build_dtb(&[(
            "serial@9010000",
            &[("compatible", b"arm,pl011\0" as &[u8]), ("reg", &reg)][..],
        )]);
        assert_eq!(dtb_pl011(&blob), (false, Some(0x0901_0000)));
    }

    #[test]
    fn dtb_pl011_reports_no_pl011_node() {
        let blob = build_dtb(&[(
            "ethernet@a000000",
            &[("compatible", b"virtio,mmio\0" as &[u8])][..],
        )]);
        assert_eq!(dtb_pl011(&blob), (false, None));
        // A malformed blob fails safe the same way.
        assert_eq!(dtb_pl011(&[0u8; 64]), (false, None));
    }

    #[test]
    fn pl011_probe_reports_missing_dtb_uart() {
        // The DTB half of the probe, without touching hardware: no
        // PL011 node means the probe reports NoDtbUart and the ID
        // half never runs (no volatile read of the hardware address
        // on the host). The Available path is CI-only for the same
        // reason.
        let blob = build_dtb(&[]);
        match pl011_available(&blob) {
            Pl011Probe::NoDtbUart { found: None } => {}
            probe => panic!("expected NoDtbUart with no node, got {probe:?}"),
        }
    }
}
