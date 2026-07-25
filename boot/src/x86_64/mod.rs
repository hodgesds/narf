//! x86_64 boot-protocol handoffs (PVH + multiboot2).

pub mod multiboot2;
pub mod pvh;

use narf_memory::{PhysAddr, VirtAddr};

use crate::info::{
    validate_memory_map, BootError, BootInfo, MemRegion, MemRegionKind, RawBootInfo,
};

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

/// Backing buffer for the bootloader-supplied command-line. Copied
/// out of the transient bootinfo region during `parse_raw`, then
/// borrowed as a `&'static str` for the rest of boot.
const CMDLINE_CAP: usize = 512;
static mut CMDLINE_BUF: [u8; CMDLINE_CAP] = [0; CMDLINE_CAP];
static mut CMDLINE_LEN: usize = 0;

/// Borrow the populated command-line as a `&'static str`. Empty
/// before `parse_raw` runs, or when the bootloader passed no
/// cmdline. Invalid UTF-8 bytes are dropped (best-effort lossy
/// decode is reserved for diagnostics; the kernel only cares about
/// ASCII flags).
pub fn cmdline() -> &'static str {
    // SAFETY: written exactly once at boot before any reader runs.
    unsafe {
        let len = core::ptr::addr_of!(CMDLINE_LEN).read();
        let bytes = core::slice::from_raw_parts(core::ptr::addr_of!(CMDLINE_BUF).cast::<u8>(), len);
        core::str::from_utf8(bytes).unwrap_or("")
    }
}

/// Copy a bootloader-supplied cmdline byte slice into the static
/// backing buffer. Truncates at `CMDLINE_CAP - 1` bytes.
///
/// # Safety
/// Single-threaded boot path: caller must invoke before any other
/// thread observes `cmdline()`.
unsafe fn store_cmdline(src: &[u8]) {
    let n = src.len().min(CMDLINE_CAP - 1);
    // SAFETY: single-writer in the boot path.
    unsafe {
        let dst = core::ptr::addr_of_mut!(CMDLINE_BUF).cast::<u8>();
        core::ptr::copy_nonoverlapping(src.as_ptr(), dst, n);
        core::ptr::addr_of_mut!(CMDLINE_LEN).write(n);
    }
}

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
        // SAFETY: Valid memory or trusted environment
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
    }?;

    // SAFETY: `count` is the return value from the parser; we write to the
    // accompanying `MEMORY_MAP_LEN` under single-threaded boot conditions.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::ptr::addr_of_mut!(MEMORY_MAP_LEN).write(count);
    }

    // SAFETY: MEMORY_MAP[..count] was initialised by the parser above.
    let regions = unsafe {
        core::slice::from_raw_parts(core::ptr::addr_of!(MEMORY_MAP).cast::<MemRegion>(), count)
    };
    validate_memory_map(regions)?;

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

    // SAFETY: payload validated; single-threaded boot.
    let cmdline_bytes = unsafe {
        match proto {
            Protocol::Multiboot2 => multiboot2::cmdline(info_ptr),
            Protocol::Pvh => pvh::cmdline(info_ptr),
        }
    };
    if let Some(bytes) = cmdline_bytes {
        // SAFETY: single-threaded boot, before any other thread runs.
        unsafe { store_cmdline(bytes) };
    }

    Ok(BootInfo {
        memory_map: regions,
        cmdline: cmdline(),
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
    // SAFETY: Valid memory or trusted environment
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
