// SPDX-License-Identifier: GPL-2.0-or-later

#![cfg_attr(not(test), no_main)]
#![cfg_attr(not(test), no_std)]

extern crate alloc;

#[cfg(not(test))]
use core::panic::PanicInfo;
use core::{ptr, slice};
use uefi::{
    boot::{self, AllocateType, MemoryType},
    cstr16, entry, guid,
    prelude::Status,
    system,
};

const PAGE_SIZE: u64 = 4096;
const ELF_HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;
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

    let kernel = {
        let protocol =
            boot::get_image_file_system(boot::image_handle()).map_err(|_| LoadError::FileSystem)?;
        let mut fs = uefi::fs::FileSystem::new(protocol);
        fs.read(cstr16!(r"\boot\narf-frame"))
            .map_err(|_| LoadError::FileSystem)?
    };

    let (entry, segments, load_start, load_end) = parse_elf(&kernel)?;
    let page_start = align_down(load_start, PAGE_SIZE);
    let page_end = align_up(load_end, PAGE_SIZE).ok_or(LoadError::Arithmetic)?;
    if page_end - page_start > MAX_KERNEL_LOAD_SPAN
        || ranges_overlap(page_start as usize, page_end as usize, dtb, dtb_end)
    {
        return Err(LoadError::InvalidElf);
    }
    let pages =
        usize::try_from((page_end - page_start) / PAGE_SIZE).map_err(|_| LoadError::Arithmetic)?;
    let allocation = boot::allocate_pages(
        AllocateType::Address(page_start),
        MemoryType::LOADER_DATA,
        pages,
    )
    .map_err(|_| LoadError::Allocation)?;
    if allocation.as_ptr() as u64 != page_start {
        return Err(LoadError::Allocation);
    }

    // SAFETY: the exact page range was allocated above and is exclusively
    // owned by this loader until control transfers to the kernel.
    unsafe { ptr::write_bytes(allocation.as_ptr(), 0, pages * PAGE_SIZE as usize) };
    for segment in segments {
        let source_start =
            usize::try_from(segment.file_offset).map_err(|_| LoadError::Arithmetic)?;
        let source_len = usize::try_from(segment.file_size).map_err(|_| LoadError::Arithmetic)?;
        let source_end = source_start
            .checked_add(source_len)
            .ok_or(LoadError::Arithmetic)?;
        let source = kernel
            .get(source_start..source_end)
            .ok_or(LoadError::InvalidElf)?;
        // SAFETY: parse_elf proved every segment lies in the allocated range,
        // and source is a live slice of exactly p_filesz bytes.
        unsafe {
            ptr::copy_nonoverlapping(source.as_ptr(), segment.physical as *mut u8, source.len())
        };
    }

    drop(kernel);
    // SAFETY: filesystem protocols and all pool-backed objects were dropped;
    // loaded pages and the firmware-owned DTB intentionally remain live.
    let memory_map = unsafe { boot::exit_boot_services(None) };
    core::mem::forget(memory_map);

    // The NARF aarch64 entry follows the Linux boot protocol: x0 is the
    // physical DTB address and execution begins at the ELF entry at EL1.
    // SAFETY: parse_elf required entry to be inside an executable PT_LOAD
    // segment copied to its declared physical address.
    let kernel_entry: extern "C" fn(usize) -> ! = unsafe { core::mem::transmute(entry as usize) };
    kernel_entry(dtb)
}

fn parse_elf(bytes: &[u8]) -> Result<(u64, alloc::vec::Vec<LoadSegment>, u64, u64), LoadError> {
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
    if phentsize != PROGRAM_HEADER_SIZE || phnum == 0 {
        return Err(LoadError::InvalidElf);
    }
    let table_start = usize::try_from(phoff).map_err(|_| LoadError::Arithmetic)?;
    let table_size = phentsize.checked_mul(phnum).ok_or(LoadError::Arithmetic)?;
    let table_end = table_start
        .checked_add(table_size)
        .ok_or(LoadError::Arithmetic)?;
    if table_end > bytes.len() {
        return Err(LoadError::InvalidElf);
    }

    let mut segments = alloc::vec::Vec::new();
    let mut load_start = u64::MAX;
    let mut load_end = 0u64;
    let mut entry_is_executable = false;
    for index in 0..phnum {
        let offset = table_start + index * phentsize;
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
        if file_end > bytes.len() as u64 {
            return Err(LoadError::InvalidElf);
        }
        let memory_end = segment
            .physical
            .checked_add(segment.memory_size)
            .ok_or(LoadError::Arithmetic)?;
        if segment.flags & PF_X != 0 && entry >= segment.physical && entry < memory_end {
            entry_is_executable = true;
        }
        load_start = load_start.min(segment.physical);
        load_end = load_end.max(memory_end);
        segments.push(segment);
    }
    if segments.is_empty() || !entry_is_executable {
        return Err(LoadError::InvalidElf);
    }
    for (index, left) in segments.iter().enumerate() {
        let left_end = left.physical + left.memory_size;
        for right in &segments[index + 1..] {
            let right_end = right.physical + right.memory_size;
            if left.physical < right_end && right.physical < left_end {
                return Err(LoadError::InvalidElf);
            }
        }
    }
    Ok((entry, segments, load_start, load_end))
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
    use alloc::vec;

    fn valid_elf() -> alloc::vec::Vec<u8> {
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
    fn accepts_aarch64_load_segment_and_bss() {
        let (entry, segments, start, end) = parse_elf(&valid_elf()).unwrap();
        assert_eq!(entry, 0x4008_0000);
        assert_eq!(segments.len(), 1);
        assert_eq!(start, 0x4008_0000);
        assert_eq!(end, 0x4008_0008);
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
