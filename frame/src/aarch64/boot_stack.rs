//! The boot CPU's stack: how deep it has gone, and whether it ran off the end.
//!
//! `boot.S` paints the stack and the guard region below it with
//! [`PAINT`] before first use. The stack grows down from `stack_top`, so the
//! lowest word that no longer holds the paint is its high-water mark, and
//! any changed word in the guard means a frame reached past `stack_bottom`.
//! The guard is checked after boot: the boot stack runs every initcall, and
//! it used to sit directly above the boot page tables, where an overflow
//! silently cleared kernel-image L2 descriptors.

use narf_memory::PhysAddr;

/// Word `boot.S` fills the stack and its guard with ("ATSKATSK").
pub const PAINT: u64 = 0x4B53_5441_4B53_5441;

/// Measured use of the boot stack.
#[derive(Clone, Copy, Debug)]
pub struct Usage {
    /// Stack size in bytes (`stack_top - stack_bottom`).
    pub size: u64,
    /// Bytes below `stack_top` that have been written at least once.
    pub used: u64,
    /// Guard size in bytes.
    pub guard: u64,
    /// Guard words that no longer hold the paint.
    pub guard_written: u64,
    /// Lowest guard address written, when any was.
    pub lowest_written: Option<u64>,
}

/// Read the paint: high-water mark and guard state.
pub fn usage() -> Usage {
    unsafe extern "C" {
        static __boot_stack_bounds: [u64; 3];
    }
    // SAFETY: three linker-populated words in the image (`.boot_stack_bounds`
    // in build/linker/aarch64.ld), read-only.
    let bounds = unsafe { core::ptr::addr_of!(__boot_stack_bounds).read() };
    // Link-time physical values; the image may have been relocated.
    let [guard, bottom, top] = bounds.map(narf_memory::kaslr::image_link_phys);
    let word = |phys: u64| -> u64 {
        // SAFETY: inside the kernel image, which the direct map covers; the
        // words are only read, and a racing write is just a newer value.
        unsafe { core::ptr::read_volatile(PhysAddr::new(phys).kernel_ptr::<u64>()) }
    };
    let mut guard_written = 0;
    let mut lowest_written = None;
    for phys in (guard..bottom).step_by(8) {
        if word(phys) != PAINT {
            guard_written += 1;
            lowest_written.get_or_insert(phys);
        }
    }
    let deepest = (bottom..top)
        .step_by(8)
        .find(|&phys| word(phys) != PAINT)
        .unwrap_or(top);
    Usage {
        size: top - bottom,
        used: top - deepest,
        guard: bottom - guard,
        guard_written,
        lowest_written,
    }
}
