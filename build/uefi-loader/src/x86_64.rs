// SPDX-License-Identifier: GPL-2.0-or-later
//! Self-contained EFI application using NARF's existing Multiboot2 entry.

use core::{
    arch::{asm, global_asm},
    mem,
    ptr::{self, NonNull},
    slice,
    sync::atomic::{compiler_fence, Ordering},
};
use narf_boot_protocol::{
    normalize_memory_map, BootBundle, ElfImage, Error, MemoryRegion, Multiboot2Builder,
    MAX_MEMORY_REGIONS, PAGE_SIZE,
};
use uefi::{
    boot::{self, AllocateType, MemoryType},
    entry,
    mem::memory_map::MemoryMap,
    proto::console::gop::{GraphicsOutput, PixelFormat},
    system,
    table::cfg::ConfigTableEntry,
    Status,
};

use sha2::{Digest, Sha256};

#[used]
#[link_section = ".narf"]
static BUNDLE: [u8; include_bytes!(concat!(env!("OUT_DIR"), "/bundle.bin")).len()] =
    *include_bytes!(concat!(env!("OUT_DIR"), "/bundle.bin"));
const MAX_DESCRIPTORS: usize = 1024;
const HANDOFF_PAGES: usize = 32;
/// The image moves only in these steps: boot.S builds the kernel window from
/// 2 MiB pages.
const PLACEMENT_ALIGN: u64 = 2 * 1024 * 1024;
/// boot.S runs the image in 32-bit mode under an identity map of the low
/// 4 GiB, so the whole image must sit below this.
const PLACEMENT_LIMIT: u64 = 1 << 32;

#[derive(Debug)]
enum LoadError {
    Image(Error),
    Firmware(Status),
    InvalidFirmwareTable,
    TooManyDescriptors,
    BridgeTooLarge,
    /// The link range is not free (the firmware's status), and no free
    /// range above it on the placement grid fits the image below 4 GiB.
    NoPlacement(Status),
}

impl From<Error> for LoadError {
    fn from(value: Error) -> Self {
        Self::Image(value)
    }
}

/// Pages remain owned until kernel entry; early errors return them to EFI.
struct Pages {
    pointer: NonNull<u8>,
    count: usize,
}

impl Pages {
    fn new(kind: MemoryType, count: usize, address: Option<u64>) -> Result<Self, LoadError> {
        let allocation = address.map_or(
            AllocateType::MaxAddress(u32::MAX as u64 - PAGE_SIZE),
            AllocateType::Address,
        );
        let pointer = boot::allocate_pages(allocation, kind, count)
            .map_err(|error| LoadError::Firmware(error.status()))?;
        Ok(Self { pointer, count })
    }
    fn address(&self) -> u64 {
        self.pointer.as_ptr() as u64
    }
    fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: uniquely owned EFI pages are writable and identity-mapped.
        unsafe { slice::from_raw_parts_mut(self.pointer.as_ptr(), self.count * PAGE_SIZE as usize) }
    }
}

impl Drop for Pages {
    fn drop(&mut self) {
        // SAFETY: live allocations are forgotten before ExitBootServices.
        let _ = unsafe { boot::free_pages(self.pointer, self.count) };
    }
}

#[entry]
fn main() -> Status {
    if uefi::helpers::init().is_err() {
        return Status::ABORTED;
    }
    uefi::println!("NARF native EFI: embedded kernel + initramfs");
    // Read while firmware services are live. This diagnostic is independent
    // of the kernel's separate runtime-variable/cache initialization.
    let variable = |name| {
        let mut byte = [0u8; 1];
        uefi::runtime::get_variable(
            name,
            &uefi::runtime::VariableVendor::GLOBAL_VARIABLE,
            &mut byte,
        )
        .ok()
        .and_then(|(bytes, _)| bytes.first().copied())
    };
    let secure_boot = variable(uefi::cstr16!("SecureBoot"));
    let setup_mode = variable(uefi::cstr16!("SetupMode"));
    uefi::println!("NARF native EFI: SecureBoot={secure_boot:?} SetupMode={setup_mode:?}");
    match load_and_start() {
        Ok(()) => Status::ABORTED,
        Err(error) => {
            match error {
                LoadError::Image(reason) => {
                    uefi::println!("NARF native EFI: image rejected: {reason:?}")
                }
                LoadError::Firmware(status) => {
                    uefi::println!("NARF native EFI: firmware error: {status:?}")
                }
                LoadError::NoPlacement(status) => uefi::println!(
                    "NARF native EFI: the kernel's link range is not free ({status:?}), \
                     and no free range above it below 4 GiB fits the kernel"
                ),
                other => uefi::println!("NARF native EFI: {other:?}"),
            }
            Status::LOAD_ERROR
        }
    }
}

fn load_and_start() -> Result<(), LoadError> {
    let bundle = BootBundle::parse(&BUNDLE)?;
    for (data, expected) in [bundle.kernel, bundle.initramfs, bundle.cmdline.as_bytes()]
        .into_iter()
        .zip(bundle.hashes)
    {
        if Sha256::digest(data).as_slice() != expected {
            return Err(Error::InvalidBundle.into());
        }
    }
    let elf = ElfImage::parse(bundle.kernel)?;
    let kernel_pages = ((elf.load_end - elf.load_start) / PAGE_SIZE) as usize;
    #[cfg(narf_occupy_link)]
    occupy_link_range(&elf)?;
    let (mut loaded, delta) = place_kernel(&elf, kernel_pages)?;
    let entry = u32::try_from(u64::from(elf.entry) + delta).map_err(|_| Error::Overflow)?;
    loaded.bytes_mut().fill(0);
    for segment in elf.segments() {
        let offset = (segment.physical - elf.load_start) as usize;
        loaded.bytes_mut()[offset..offset + segment.file_size]
            .copy_from_slice(elf.segment_bytes(segment).ok_or(Error::InvalidSegment)?);
    }
    let mut initramfs = Pages::new(
        MemoryType::LOADER_DATA,
        bundle.initramfs.len().div_ceil(PAGE_SIZE as usize),
        None,
    )?;
    initramfs.bytes_mut().fill(0);
    initramfs.bytes_mut()[..bundle.initramfs.len()].copy_from_slice(bundle.initramfs);
    let mut handoff = Pages::new(MemoryType::LOADER_DATA, HANDOFF_PAGES, None)?;
    let info_address = handoff.address();
    let mut bridge = Pages::new(MemoryType::LOADER_CODE, 1, None)?;
    let bridge_address = bridge.address();
    unsafe extern "C" {
        static narf_bridge_start: u8;
        static narf_bridge_end: u8;
    }
    let start = ptr::addr_of!(narf_bridge_start);
    let len = (ptr::addr_of!(narf_bridge_end) as usize)
        .checked_sub(start as usize)
        .ok_or(LoadError::BridgeTooLarge)?;
    if len == 0 || len > PAGE_SIZE as usize {
        return Err(LoadError::BridgeTooLarge);
    }
    // SAFETY: assembler labels bound a readable position-independent blob;
    // destination is a distinct allocation at least len bytes long.
    unsafe { ptr::copy_nonoverlapping(start, bridge.bytes_mut().as_mut_ptr(), len) };

    let mut builder = Multiboot2Builder::new(handoff.bytes_mut())?;
    builder.command_line(bundle.cmdline)?;
    builder.initramfs(initramfs.address(), bundle.initramfs.len() as u64)?;
    if let Some(table) = uefi::table::system_table_raw() {
        builder.tag(12, &(table.as_ptr() as u64).to_le_bytes())?;
    }
    firmware_tags(&mut builder)?;
    framebuffer_tag(&mut builder)?;
    // Preflight while EFI diagnostics still work; ExitBootServices obtains
    // the final map again and retries if its map key becomes stale.
    let map = boot::memory_map(MemoryType::LOADER_DATA)
        .map_err(|error| LoadError::Firmware(error.status()))?;
    let mut raw_regions = [MemoryRegion::default(); MAX_DESCRIPTORS];
    let mut normalized = [MemoryRegion::default(); MAX_MEMORY_REGIONS];
    let _ = convert_memory_map(&map, &mut raw_regions, &mut normalized)?;
    drop(map);
    uefi::println!(
        "NARF native EFI: kernel {:#x}..{:#x}, initramfs {} bytes; exiting boot services",
        loaded.address(),
        loaded.address() + (elf.load_end - elf.load_start),
        bundle.initramfs.len()
    );
    mem::forget(loaded);
    mem::forget(initramfs);
    mem::forget(bridge);
    // SAFETY: protocol guards were dropped; all retained pages are explicitly
    // reserved LOADER_CODE/DATA. No firmware-owned destructor runs below.
    let final_map = unsafe { boot::exit_boot_services(Some(MemoryType::LOADER_DATA)) };
    let count = match convert_memory_map(&final_map, &mut raw_regions, &mut normalized) {
        Ok(count) => count,
        Err(_) => fatal_after_exit(b"NARF native EFI: final memory map rejected\r\n"),
    };
    let meta = final_map.meta();
    if builder
        .memory_map(&normalized[..count])
        .and_then(|()| {
            builder.efi_memory_map(
                meta.desc_size as u32,
                meta.desc_version,
                &final_map.buffer()[..meta.map_size],
            )
        })
        .and_then(|()| builder.finish())
        .is_err()
    {
        fatal_after_exit(b"NARF native EFI: handoff exceeds capacity\r\n");
    }
    mem::forget(handoff);
    mem::forget(final_map);
    // SAFETY: the copied bridge is executable and below 4 GiB. It disables
    // interrupts, enters protected mode, and jumps to the validated entry.
    let enter: unsafe extern "efiapi" fn(u32, u32, u64) -> ! =
        unsafe { mem::transmute(bridge_address as usize) };
    compiler_fence(Ordering::SeqCst);
    // SAFETY: the validated entry, moved with the image, the information
    // block and the executable bridge remain reserved. The bridge never
    // returns to Rust.
    unsafe { enter(entry, info_address as u32, bridge_address) }
}

/// Allocate the kernel's pages, returning them and how far above its link
/// address they are.
///
/// The link address when that whole range is free. Otherwise, firmware owns
/// part of it, as on the ThinkPad P14s Gen 5 AMD (ACPI NVS, ACPI tables and
/// a reserved block at 0x179ec000-0x1f46bfff, inside the link range
/// 0x10000000-0x1e807000). Then the image goes a whole number of 2 MiB steps
/// higher, into one free range below 4 GiB, and boot.S finds it there. The
/// step is chosen at random from every slot that fits, as Linux's EFI stub
/// places its kernel (`efi_random_alloc`,
/// drivers/firmware/efi/libstub/randomalloc.c). Without a firmware RNG it is
/// the lowest slot, as Linux's `efi_low_alloc_above` fallback is.
///
/// AllocateAddress excludes the running image and firmware-owned pages, so
/// neither path overwrites their contents.
fn place_kernel(elf: &ElfImage<'_>, pages: usize) -> Result<(Pages, u64), LoadError> {
    let refused = match Pages::new(MemoryType::LOADER_DATA, pages, Some(elf.load_start)) {
        Ok(pages) => return Ok((pages, 0)),
        Err(LoadError::Firmware(status)) => status,
        Err(other) => return Err(other),
    };
    let size = pages as u64 * PAGE_SIZE;
    let slots = |start: u64, page_count: u64| -> Option<(u64, u64)> {
        let end = start
            .checked_add(page_count.checked_mul(PAGE_SIZE)?)?
            .min(PLACEMENT_LIMIT);
        let above = start.max(elf.load_start) - elf.load_start;
        let first = elf
            .load_start
            .checked_add(above.checked_next_multiple_of(PLACEMENT_ALIGN)?)?;
        let last = end.checked_sub(size)?;
        (first <= last).then(|| (first, (last - first) / PLACEMENT_ALIGN + 1))
    };
    // Free ranges big enough for the image are few; past this many, the
    // rest only add candidates, so they are left out.
    let mut free = [(0u64, 0u64); 64];
    let mut ranges = 0;
    {
        let map = boot::memory_map(MemoryType::LOADER_DATA)
            .map_err(|error| LoadError::Firmware(error.status()))?;
        for descriptor in map.entries() {
            if descriptor.ty != MemoryType::CONVENTIONAL || ranges == free.len() {
                continue;
            }
            if let Some(range) = slots(descriptor.phys_start, descriptor.page_count) {
                free[ranges] = range;
                ranges += 1;
            }
        }
    }
    let total: u64 = free[..ranges].iter().map(|&(_, count)| count).sum();
    if total == 0 {
        return Err(LoadError::NoPlacement(refused));
    }
    let mut pick = firmware_random().map_or(0, |value| value % total);
    let mut address = None;
    for &(first, count) in &free[..ranges] {
        if pick < count {
            address = Some(first + pick * PLACEMENT_ALIGN);
            break;
        }
        pick -= count;
    }
    let address = address.ok_or(LoadError::NoPlacement(refused))?;
    let placed = Pages::new(MemoryType::LOADER_DATA, pages, Some(address))?;
    uefi::println!(
        "NARF native EFI: link range {:#x}..{:#x} not free ({refused:?}); kernel placed at {address:#x}",
        elf.load_start,
        elf.load_end
    );
    Ok((placed, address - elf.load_start))
}

/// Eight bytes from the firmware's EFI_RNG_PROTOCOL, if it has one.
fn firmware_random() -> Option<u64> {
    use uefi::proto::rng::Rng;
    let handle = boot::get_handle_for_protocol::<Rng>().ok()?;
    let mut rng = boot::open_protocol_exclusive::<Rng>(handle).ok()?;
    let mut bytes = [0u8; 8];
    rng.get_rng(None, &mut bytes).ok()?;
    Some(u64::from_le_bytes(bytes))
}

/// Test builds only (`cargo xtask efi-image --occupy-link-range`): hold one
/// page in the middle of the kernel's link range as ACPI NVS, as the
/// ThinkPad P14s Gen 5 AMD firmware holds part of it, so an OVMF boot takes
/// the placement path in `place_kernel`.
#[cfg(narf_occupy_link)]
fn occupy_link_range(elf: &ElfImage<'_>) -> Result<(), LoadError> {
    let middle = (elf.load_start + (elf.load_end - elf.load_start) / 2) & !(PAGE_SIZE - 1);
    mem::forget(Pages::new(MemoryType::ACPI_NON_VOLATILE, 1, Some(middle))?);
    uefi::println!("NARF native EFI: test: {middle:#x} held as ACPI NVS");
    Ok(())
}

fn convert_memory_map(
    map: &impl MemoryMap,
    raw: &mut [MemoryRegion],
    normalized: &mut [MemoryRegion],
) -> Result<usize, LoadError> {
    let mut count = 0;
    for descriptor in map.entries() {
        if descriptor.page_count == 0 {
            continue;
        }
        let region = raw.get_mut(count).ok_or(LoadError::TooManyDescriptors)?;
        let kind = if descriptor
            .att
            .contains(uefi::boot::MemoryAttribute::RUNTIME)
        {
            2
        } else {
            match descriptor.ty {
                MemoryType::CONVENTIONAL => 1,
                MemoryType::ACPI_RECLAIM => 3,
                MemoryType::ACPI_NON_VOLATILE => 4,
                // Also retain boot-services allocations: the EFI configuration
                // tables/event logs may still point into them. Reclaiming those
                // pages needs a kernel-side firmware-table lifetime audit first.
                // Loader allocations, runtime services and MMIO stay reserved too.
                _ => 2,
            }
        };
        *region = MemoryRegion {
            start: descriptor.phys_start,
            len: descriptor
                .page_count
                .checked_mul(PAGE_SIZE)
                .ok_or(Error::Overflow)?,
            kind,
        };
        count += 1;
    }
    Ok(normalize_memory_map(&mut raw[..count], normalized)?)
}

fn firmware_tags(builder: &mut Multiboot2Builder<'_>) -> Result<(), LoadError> {
    let mut rsdp = None;
    let mut v2 = false;
    let mut smbios = [None; 2];
    system::with_config_table(|tables| {
        for table in tables {
            if table.guid == ConfigTableEntry::ACPI2_GUID {
                rsdp = Some(table.address);
                v2 = true;
            } else if table.guid == ConfigTableEntry::ACPI_GUID && !v2 {
                rsdp = Some(table.address);
            } else if table.guid == ConfigTableEntry::SMBIOS3_GUID {
                smbios[0] = Some(table.address);
            } else if table.guid == ConfigTableEntry::SMBIOS_GUID {
                smbios[1] = Some(table.address);
            }
        }
    });
    if let Some(address) = rsdp.filter(|address| !address.is_null()) {
        // SAFETY: EFI publishes an RSDP with at least the ACPI v1 header.
        let prefix = unsafe { slice::from_raw_parts(address.cast::<u8>(), 20) };
        if &prefix[..8] != b"RSD PTR " {
            return Err(LoadError::InvalidFirmwareTable);
        }
        let size = if v2 { 36 } else { 20 };
        // SAFETY: ACPI2's entry includes the 36-byte XSDP. The kernel checks
        // its checksum and length before following any child tables.
        let rsdp = unsafe { slice::from_raw_parts(address.cast::<u8>(), size) };
        if v2 && u32::from_le_bytes(rsdp[20..24].try_into().unwrap()) != 36 {
            return Err(LoadError::InvalidFirmwareTable);
        }
        builder.tag(if v2 { 15 } else { 14 }, rsdp)?;
    }
    for (index, address) in smbios.into_iter().enumerate() {
        let Some(address) = address.filter(|address| !address.is_null()) else {
            continue;
        };
        let size = if index == 0 { 24 } else { 31 };
        // SAFETY: EFI SMBIOS GUIDs identify fixed entry-point structures.
        let entry = unsafe { slice::from_raw_parts(address.cast::<u8>(), size) };
        let mut payload = [0u8; 40];
        payload[0] = if index == 0 { entry[7] } else { entry[6] };
        payload[1] = if index == 0 { entry[8] } else { entry[7] };
        payload[8..8 + size].copy_from_slice(entry);
        builder.tag(13, &payload[..8 + size])?;
    }
    Ok(())
}

fn framebuffer_tag(builder: &mut Multiboot2Builder<'_>) -> Result<(), LoadError> {
    let Ok(handle) = boot::get_handle_for_protocol::<GraphicsOutput>() else {
        return Ok(());
    };
    let Ok(mut gop) = boot::open_protocol_exclusive::<GraphicsOutput>(handle) else {
        return Ok(());
    };
    let mode = gop.current_mode_info();
    // The current kernel ABI assumes BGRX; other layouts remain serial-only.
    if mode.pixel_format() != PixelFormat::Bgr {
        return Ok(());
    }
    let (width, height) = mode.resolution();
    let pitch = mode
        .stride()
        .checked_mul(4)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(LoadError::InvalidFirmwareTable)?;
    let width = u32::try_from(width).map_err(|_| LoadError::InvalidFirmwareTable)?;
    let height = u32::try_from(height).map_err(|_| LoadError::InvalidFirmwareTable)?;
    let mut framebuffer = gop.frame_buffer();
    let required = u64::from(height) * u64::from(pitch);
    let address = framebuffer.as_mut_ptr() as u64;
    if pitch
        < width
            .checked_mul(4)
            .ok_or(LoadError::InvalidFirmwareTable)?
        || address.checked_add(required).is_none()
        || height == 0
        || width == 0
        || required > framebuffer.size() as u64
    {
        return Err(LoadError::InvalidFirmwareTable);
    }
    let mut tag = [0u8; 30];
    tag[..8].copy_from_slice(&address.to_le_bytes());
    tag[8..12].copy_from_slice(&pitch.to_le_bytes());
    tag[12..16].copy_from_slice(&width.to_le_bytes());
    tag[16..20].copy_from_slice(&height.to_le_bytes());
    tag[20] = 32;
    tag[21] = 1;
    tag[24..].copy_from_slice(&[16, 8, 8, 8, 0, 8]);
    builder.tag(8, &tag)?;
    Ok(())
}

fn fatal_after_exit(message: &[u8]) -> ! {
    for &byte in message {
        // SAFETY: COM1 diagnostics without firmware services or allocation.
        unsafe {
            asm!("out dx, al", in("dx") 0x3f8u16, in("al") byte, options(nomem, nostack, preserves_flags))
        };
    }
    loop {
        // SAFETY: terminal boot failure; prevent any further firmware access.
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    fatal_after_exit(b"NARF native EFI: panic\r\n")
}

// Copied below 4 GiB. Internal addresses use RIP-relative displacements,
// so the blob needs no PE relocations. EFI x64 passes entry/info/base in
// RCX/RDX/R8. No stack access follows paging disable before kernel entry.
global_asm!(
    r#"
    .text
    .balign 8
    .global narf_bridge_start
    .global narf_bridge_end
narf_bridge_start:
    cli
    cld
    mov edi, ecx
    mov ebx, edx
    lea rax, [rip + narf_bridge_gdt]
    mov [rip + narf_bridge_gdtr + 2], rax
    lgdt [rip + narf_bridge_gdtr]
    mov rax, cr4
    btr rax, 17
    mov cr4, rax
    lea rax, [rip + narf_bridge_compat]
    push 0x10
    push rax
    retfq
    .code32
narf_bridge_compat:
    mov ax, 0x18
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov eax, cr0
    and eax, 0x7fffffff
    mov cr0, eax
    mov ecx, 0xc0000080
    rdmsr
    and eax, 0xfffffeff
    wrmsr
    mov eax, cr4
    and eax, 0xffffefdf
    mov cr4, eax
    mov eax, 0x36d76289
    jmp edi
    .code64
    .balign 8
narf_bridge_gdt:
    .quad 0
    .quad 0x00af9a000000ffff
    .quad 0x00cf9a000000ffff
    .quad 0x00cf92000000ffff
narf_bridge_gdtr:
    .word 31
    .quad 0
narf_bridge_end:
"#
);
