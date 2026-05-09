//! x86_64 boot-protocol handoffs (PVH + multiboot2).

pub mod multiboot2;
pub mod pvh;

use narf_memory::{PhysAddr, VirtAddr};

use crate::info::{BootError, BootInfo, MemRegion, MemRegionKind, RawBootInfo};

/// Default 16550A COM1 port on PC-compatible platforms.
pub const UART_DEFAULT_PORT: u16 = 0x3F8;

/// Number of memory-map entries we keep in a static buffer. Sizing: 64 is
/// more than any sane QEMU memory map; overflow is rejected.
pub const MAX_MEM_REGIONS: usize = 64;

/// Storage for the parsed memory map. Lives in `.bss`; populated once by
/// `parse_raw`.
static mut MEMORY_MAP: [MemRegion; MAX_MEM_REGIONS] = [MemRegion {
    start: PhysAddr::new(0),
    len: 0,
    kind: MemRegionKind::Reserved,
}; MAX_MEM_REGIONS];
static mut MEMORY_MAP_LEN: usize = 0;

/// Backing for the command-line string; empty in Stage 1.
static CMDLINE: &str = "";

/// Consume the raw bootloader payload and produce a validated `BootInfo`.
///
/// # Safety
/// Caller must supply the exact `RawBootInfo` the bootloader left in the
/// entry registers; reading from a random pointer is undefined.
pub unsafe fn parse_raw(raw: &RawBootInfo) -> Result<BootInfo, BootError> {
    // Two protocols share `_start` (see frame/src/x86_64/boot.S):
    //   - Multiboot2: EAX = 0x36d76289, EBX = phys(mbi).
    //   - PVH:        EAX = undefined,  EBX = phys(hvm_start_info).
    // Discriminate first on the magic; fall back to the payload-magic
    // probe so PVH (which doesn't set a documented EAX) still works.
    let info_ptr = raw.payload.raw() as usize;
    let proto = if raw.magic == multiboot2::BOOT_MAGIC {
        Protocol::Multiboot2
    } else {
        // SAFETY: bootloader contract guarantees ≥ 4 bytes of readable
        // memory at the payload pointer.
        if unsafe { pvh::is_hvm_start_info(raw.payload) } {
            Protocol::Pvh
        } else {
            return Err(BootError::BadMagic);
        }
    };

    // SAFETY: payload pointer + protocol determined above.
    let count = unsafe {
        match proto {
            Protocol::Pvh => pvh::parse_memory_map(
                info_ptr,
                core::ptr::addr_of_mut!(MEMORY_MAP).cast::<MemRegion>(),
                MAX_MEM_REGIONS,
            ),
            Protocol::Multiboot2 => multiboot2::parse_memory_map(
                info_ptr,
                core::ptr::addr_of_mut!(MEMORY_MAP).cast::<MemRegion>(),
                MAX_MEM_REGIONS,
            ),
        }
    };

    // SAFETY: `count` is the return value from the parser; we write to the
    // accompanying `MEMORY_MAP_LEN` under single-threaded boot conditions.
    unsafe {
        core::ptr::addr_of_mut!(MEMORY_MAP_LEN).write(count);
    }

    // Minimum Wave-1 validation: at least one Usable region with ≥ 1 MiB.
    // SAFETY: MEMORY_MAP[..count] was initialised by the parser above.
    let regions = unsafe {
        core::slice::from_raw_parts(core::ptr::addr_of!(MEMORY_MAP).cast::<MemRegion>(), count)
    };
    let any_usable = regions
        .iter()
        .any(|r| r.kind == MemRegionKind::Usable && r.len >= 1024 * 1024);
    if !any_usable {
        return Err(BootError::NoUsableRam);
    }

    // SAFETY: payload validated above by the protocol probe.
    let rsdp = unsafe {
        match proto {
            Protocol::Pvh => pvh::rsdp_phys(info_ptr),
            Protocol::Multiboot2 => multiboot2::rsdp_phys(info_ptr),
        }
    }
    .map(PhysAddr::new);

    let initramfs = scan_initramfs_module(raw, proto);
    let framebuffer = match proto {
        // SAFETY: payload validated above.
        Protocol::Multiboot2 => unsafe { multiboot2::framebuffer(info_ptr) },
        // PVH doesn't carry framebuffer info today.
        Protocol::Pvh => None,
    };

    Ok(BootInfo {
        memory_map: regions,
        cmdline: CMDLINE,
        uart_phys: PhysAddr::new(UART_DEFAULT_PORT as u64),
        uart_virt: VirtAddr::new(UART_DEFAULT_PORT as u64), // pre-MMU identity
        dtb_phys: None,
        acpi_rsdp_phys: rsdp,
        initramfs,
        framebuffer,
    })
}

#[derive(Copy, Clone)]
enum Protocol {
    Pvh,
    Multiboot2,
}

/// Scan the bootloader-provided module list for the first entry
/// whose cmdline is `"initramfs"` (case-insensitive). Both PVH
/// (`hvm_modlist_entry`) and multiboot2 (tag type 3) are supported;
/// the per-protocol parsers in `pvh::initramfs_module` /
/// `multiboot2::initramfs_module` differ in tag layout but return
/// the same `(start, size)` shape.
fn scan_initramfs_module(raw: &crate::RawBootInfo, proto: Protocol) -> Option<MemRegion> {
    if raw.payload.raw() == 0 {
        return None;
    }
    let info_ptr = raw.payload.raw() as usize;
    // SAFETY: bootloader contract — `raw.payload` points at a valid
    // info struct of the matching protocol; magic mismatch returns
    // `None` from the parser without dereferencing modlist memory.
    let (start, size) = unsafe {
        match proto {
            Protocol::Pvh => pvh::initramfs_module(info_ptr)?,
            Protocol::Multiboot2 => multiboot2::initramfs_module(info_ptr)?,
        }
    };
    if size == 0 {
        return None;
    }
    Some(MemRegion {
        start: PhysAddr::new(start),
        len: size,
        kind: MemRegionKind::Reserved,
    })
}
