//! x86_64 multiboot2 handoff.

pub mod multiboot2;

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
    start: PhysAddr::new(0), len: 0, kind: MemRegionKind::Reserved,
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
    // PVH doesn't set EAX to any documented magic, so we discriminate on
    // the *payload's* content: if it has the `hvm_start_info` magic at
    // offset 0 we parse that. The EAX-provided magic is unused today
    // and will regain meaning when Limine / Multiboot2 is wired in.
    // SAFETY: the bootloader contract guarantees at least 4 bytes of
    // readable memory at `payload`.
    let is_pvh = unsafe { multiboot2::is_hvm_start_info(raw.payload) };
    if !is_pvh {
        return Err(BootError::BadMagic);
    }

    // SAFETY: bootloader contract — the payload pointer targets an
    // hvm_start_info with the documented trailing memmap buffer.
    let count = unsafe {
        multiboot2::parse_memory_map(
            raw.payload.raw() as usize,
            core::ptr::addr_of_mut!(MEMORY_MAP).cast::<MemRegion>(),
            MAX_MEM_REGIONS,
        )
    };

    // SAFETY: `count` is the return value from the parser; we write to the
    // accompanying `MEMORY_MAP_LEN` under single-threaded boot conditions.
    unsafe { core::ptr::addr_of_mut!(MEMORY_MAP_LEN).write(count); }

    // Minimum Wave-1 validation: at least one Usable region with ≥ 1 MiB.
    // SAFETY: MEMORY_MAP[..count] was initialised by parse_memory_map.
    let regions = unsafe {
        core::slice::from_raw_parts(
            core::ptr::addr_of!(MEMORY_MAP).cast::<MemRegion>(),
            count,
        )
    };
    let any_usable = regions.iter().any(|r|
        r.kind == MemRegionKind::Usable && r.len >= 1024 * 1024);
    if !any_usable {
        return Err(BootError::NoUsableRam);
    }

    Ok(BootInfo {
        memory_map: regions,
        cmdline:    CMDLINE,
        uart_phys:  PhysAddr::new(UART_DEFAULT_PORT as u64),
        uart_virt:  VirtAddr::new(UART_DEFAULT_PORT as u64),   // pre-MMU identity
        dtb_phys:   None,
    })
}
