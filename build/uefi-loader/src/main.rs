// SPDX-License-Identifier: GPL-2.0-or-later

#![cfg_attr(not(test), no_main)]
#![cfg_attr(not(test), no_std)]

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
const EFI_DTB_TABLE_GUID: uefi::Guid = guid!("b1b621d5-f19c-41a5-830b-d9152c69aae0");

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
    let mut kernel = root
        .open(
            cstr16!(r"\boot\narf-frame"),
            FileMode::Read,
            FileAttribute::empty(),
        )
        .map_err(|_| LoadError::FileSystem)?
        .into_regular_file()
        .ok_or(LoadError::FileSystem)?;
    kernel
        .set_position(RegularFile::END_OF_FILE)
        .map_err(|_| LoadError::FileSystem)?;
    let kernel_size = kernel.get_position().map_err(|_| LoadError::FileSystem)?;

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
    if page_end - page_start > MAX_KERNEL_LOAD_SPAN
        || ranges_overlap(page_start as usize, page_end as usize, dtb, dtb_end)
    {
        return Err(LoadError::InvalidElf);
    }

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
        let map = boot::memory_map(MemoryType::LOADER_DATA).map_err(|_| LoadError::Allocation)?;
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
            if !matches!(
                descriptor.ty,
                MemoryType::CONVENTIONAL
                    | MemoryType::BOOT_SERVICES_CODE
                    | MemoryType::BOOT_SERVICES_DATA
                    | MemoryType::LOADER_CODE
                    | MemoryType::LOADER_DATA
            ) {
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

    let pages =
        usize::try_from((alloc_end - page_start) / PAGE_SIZE).map_err(|_| LoadError::Arithmetic)?;
    let allocation = boot::allocate_pages(
        AllocateType::Address(page_start),
        MemoryType::LOADER_DATA,
        pages,
    )
    .map_err(|_| {
        if let Ok(map) = boot::memory_map(MemoryType::LOADER_DATA) {
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
        LoadError::Allocation
    })?;
    if allocation.as_ptr() as u64 != page_start {
        return Err(LoadError::Allocation);
    }

    for segment in elf.segments() {
        let source_len = usize::try_from(segment.file_size).map_err(|_| LoadError::Arithmetic)?;
        let zero_len = usize::try_from(segment.memory_size - segment.file_size)
            .map_err(|_| LoadError::Arithmetic)?;
        // SAFETY: parse_program_headers proved every segment lies in the
        // allocated range, which remains exclusively owned by this loader.
        let destination =
            unsafe { slice::from_raw_parts_mut(segment.physical as *mut u8, source_len) };
        read_exact_at(&mut kernel, segment.file_offset, destination)?;
        // The p_memsz - p_filesz tail is zeroed AFTER ExitBootServices — see
        // the allocation comment above. Part of it may still belong to
        // firmware right now.
        let _ = zero_len;
    }

    drop(kernel);
    drop(root);
    drop(protocol);
    // SAFETY: filesystem protocols and all pool-backed objects were dropped;
    // loaded pages and the firmware-owned DTB intentionally remain live.
    let memory_map = unsafe { boot::exit_boot_services(None) };
    core::mem::forget(memory_map);

    // Boot services are gone, so every BOOT_SERVICES_* range is now ordinary
    // free memory owned by us — including the .bss tail deliberately left
    // outside the allocation above. Zero it now, before the kernel runs.
    // Validated as reclaimable before EBS; no diagnostics are possible here,
    // which is exactly why that check happens while console output still
    // works.
    for segment in elf.segments() {
        let zero_len = segment.memory_size - segment.file_size;
        if zero_len == 0 {
            continue;
        }
        // SAFETY: p_filesz <= p_memsz; the range lies inside the validated
        // load span, and after ExitBootServices the loader owns all of it.
        unsafe {
            ptr::write_bytes(
                (segment.physical + segment.file_size) as *mut u8,
                0,
                zero_len as usize,
            )
        };
    }

    // The NARF aarch64 entry follows the Linux boot protocol: x0 is the
    // physical DTB address and execution begins at the ELF entry at EL1.
    // SAFETY: parse_program_headers required entry to be inside an executable PT_LOAD
    // segment copied to its declared physical address.
    let kernel_entry: extern "C" fn(usize) -> ! =
        unsafe { core::mem::transmute(elf.entry as usize) };
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
        return Err(LoadError::InvalidElf);
    }
    let table_size = u64::try_from(phentsize.checked_mul(phnum).ok_or(LoadError::Arithmetic)?)
        .map_err(|_| LoadError::Arithmetic)?;
    let table_end = phoff.checked_add(table_size).ok_or(LoadError::Arithmetic)?;
    if table_end > file_size {
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
            return Err(LoadError::InvalidElf);
        }
        if alignment > 1
            && (!alignment.is_power_of_two()
                || segment.physical % alignment != segment.file_offset % alignment)
        {
            return Err(LoadError::InvalidElf);
        }
        let file_end = segment
            .file_offset
            .checked_add(segment.file_size)
            .ok_or(LoadError::Arithmetic)?;
        if file_end > file_size {
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
        return Err(LoadError::InvalidElf);
    }
    for (index, left) in segments[..segment_count].iter().enumerate() {
        let left_end = left.physical + left.memory_size;
        for right in &segments[index + 1..segment_count] {
            let right_end = right.physical + right.memory_size;
            if left.physical < right_end && right.physical < left_end {
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
}
