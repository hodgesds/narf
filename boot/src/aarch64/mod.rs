//! aarch64 U-Boot / FDT handoff.
//!
//! Entry: `x0` holds the physical address of a device tree blob. The
//! bootloader hands that to `frame::_start`, which packs it into a
//! `RawBootInfo` and calls `parse_raw`.

use narf_memory::{PhysAddr, VirtAddr};

use crate::info::{BootError, BootInfo, MemRegion, MemRegionKind, RawBootInfo};

/// DTB magic per Devicetree Specification (big-endian on the wire).
pub const DTB_MAGIC_BE: u32 = 0xd00d_feed;

/// QEMU `virt` machine's PL011 base MMIO address.
pub const PL011_QEMU_VIRT: u64 = 0x0900_0000;

/// Maximum number of memory regions we track pre-parse. FDT parsing is
/// deferred to Wave 2; for Wave 1 we synthesise a single "all of RAM"
/// region from platform knowledge.
pub const MAX_MEM_REGIONS: usize = 16;

static mut MEMORY_MAP: [MemRegion; MAX_MEM_REGIONS] = [MemRegion {
    start: PhysAddr::new(0), len: 0, kind: MemRegionKind::Reserved,
}; MAX_MEM_REGIONS];
static mut MEMORY_MAP_LEN: usize = 0;

static CMDLINE: &str = "";

/// Parse a U-Boot-style handoff. Wave 1 trusts QEMU `virt` defaults — the
/// full FDT walker lands with `memory/` at a later wave.
///
/// Tolerates a null or bogus DTB pointer: when QEMU's `-kernel` path
/// doesn't populate X0 with an FDT address (observed on ELF inputs
/// without an explicit `-dtb`), we synthesise a plausible memory
/// map from the standard QEMU `virt` layout instead of faulting.
/// Real FDT parsing becomes load-bearing only when Stage 3 needs the
/// device tree for peripherals.
///
/// # Safety
/// `raw.payload` may be null; we check before dereferencing.
pub unsafe fn parse_raw(raw: &RawBootInfo) -> Result<BootInfo, BootError> {
    // Validate DTB magic only if the bootloader gave us a non-null
    // pointer. Null → treat as "no DTB, use defaults."
    if raw.payload.raw() != 0 {
        // SAFETY: non-null pointer into identity-mapped RAM; read of
        // 4 unaligned bytes is defined on aarch64.
        let magic_ptr = raw.payload.raw() as *const u32;
        let magic = unsafe { magic_ptr.read_unaligned() }.to_be();
        if magic != DTB_MAGIC_BE {
            // Non-null but bad magic — really wrong, bail.
            return Err(BootError::BadDtbMagic);
        }
    }

    // Wave-1 placeholder: a single 128-MiB usable region starting at the
    // standard virt-machine RAM base. Real FDT parsing in Wave 2 replaces
    // this with the actual `/memory` node.
    let region = MemRegion {
        start: PhysAddr::new(0x4000_0000),
        len:   0x0800_0000,           // 128 MiB
        kind:  MemRegionKind::Usable,
    };
    // SAFETY: single-threaded boot path writes to the static buffer.
    unsafe {
        core::ptr::addr_of_mut!(MEMORY_MAP).cast::<MemRegion>().write(region);
        core::ptr::addr_of_mut!(MEMORY_MAP_LEN).write(1);
    }
    // SAFETY: slice refers to the static we just wrote.
    let regions = unsafe {
        core::slice::from_raw_parts(
            core::ptr::addr_of!(MEMORY_MAP).cast::<MemRegion>(),
            1,
        )
    };

    Ok(BootInfo {
        memory_map: regions,
        cmdline:    CMDLINE,
        uart_phys:  PhysAddr::new(PL011_QEMU_VIRT),
        uart_virt:  VirtAddr::new(PL011_QEMU_VIRT),  // pre-MMU identity
    })
}
