//! x86 user segment state for IA-32 emulation: Linux's 64-bit GDT layout
//! and the per-CPU GDT registry the TLS slots are written through.
//!
//! The layout follows `arch/x86/include/asm/segment.h` for every
//! user-visible selector. The kernel selectors stay NARF's (0x08 code,
//! 0x10 data): user code never names them, and the IDT, `IA32_STAR` and the
//! AP trampoline are built around them.
//!
//! | index | selector | descriptor |
//! |-------|----------|------------|
//! | 0 | — | null |
//! | 1 | 0x08 | kernel code, long mode |
//! | 2 | 0x10 | kernel data |
//! | 3 | — | unused |
//! | 4 | 0x23 | `__USER32_CS`: 32-bit user code |
//! | 5 | 0x2b | `__USER_DS`: user data |
//! | 6 | 0x33 | `__USER_CS`: 64-bit user code |
//! | 7 | — | unused |
//! | 8–9 | 0x40 | TSS (`GDT_ENTRY_TSS`) |
//! | 10–11 | — | LDT slot, unused (no `modify_ldt`) |
//! | 12–14 | 0x63, 0x6b, 0x73 | TLS (`GDT_ENTRY_TLS_MIN`..), per task |
//! | 15 | — | unused (Linux `GDT_ENTRY_CPUNODE`) |
//!
//! `frame` owns the tables (the BSP's static one and each AP's leaked
//! block) and registers each CPU's here once it has loaded it, so the
//! scheduler's switch-in can rewrite the running CPU's TLS slots without
//! depending on `frame`.

use core::sync::atomic::{AtomicPtr, Ordering};

/// Descriptors in every CPU's GDT (Linux `GDT_ENTRIES`).
pub const GDT_ENTRIES: usize = 16;
/// Index of the 32-bit user code segment (`GDT_ENTRY_DEFAULT_USER32_CS`).
pub const GDT_ENTRY_DEFAULT_USER32_CS: usize = 4;
/// Index of the user data segment (`GDT_ENTRY_DEFAULT_USER_DS`).
pub const GDT_ENTRY_DEFAULT_USER_DS: usize = 5;
/// Index of the 64-bit user code segment (`GDT_ENTRY_DEFAULT_USER_CS`).
pub const GDT_ENTRY_DEFAULT_USER_CS: usize = 6;
/// First of the two slots the 16-byte TSS descriptor occupies.
pub const GDT_ENTRY_TSS: usize = 8;
/// First TLS slot (`GDT_ENTRY_TLS_MIN`).
pub const GDT_ENTRY_TLS_MIN: usize = 12;
/// Number of TLS slots (`GDT_ENTRY_TLS_ENTRIES`).
pub const GDT_ENTRY_TLS_ENTRIES: usize = 3;
/// Last TLS slot (`GDT_ENTRY_TLS_MAX`).
pub const GDT_ENTRY_TLS_MAX: usize = GDT_ENTRY_TLS_MIN + GDT_ENTRY_TLS_ENTRIES - 1;

/// Kernel code selector.
pub const KERNEL_CS: u16 = 0x08;
/// Kernel data selector.
pub const KERNEL_DS: u16 = 0x10;
/// `__USER32_CS`: compatibility-mode user code, RPL 3.
pub const USER32_CS: u16 = ((GDT_ENTRY_DEFAULT_USER32_CS as u16) << 3) | 3;
/// `__USER_DS`: user data and stack, RPL 3.
pub const USER_DS: u16 = ((GDT_ENTRY_DEFAULT_USER_DS as u16) << 3) | 3;
/// `__USER_CS`: 64-bit user code, RPL 3.
pub const USER_CS: u16 = ((GDT_ENTRY_DEFAULT_USER_CS as u16) << 3) | 3;
/// The TSS selector `LTR` loads.
pub const TSS_SELECTOR: u16 = (GDT_ENTRY_TSS as u16) << 3;

/// Kernel code: long mode, DPL 0, execute/read.
pub const DESC_KERNEL_CS: u64 = 0x00af_9a00_0000_ffff;
/// Kernel data: DPL 0, read/write.
pub const DESC_KERNEL_DS: u64 = 0x00cf_9200_0000_ffff;
/// `__USER32_CS`: flat 4 GiB, D=1 L=0, DPL 3, execute/read.
pub const DESC_USER32_CS: u64 = 0x00cf_fa00_0000_ffff;
/// `__USER_DS`: flat 4 GiB, B=1, DPL 3, read/write.
pub const DESC_USER_DS: u64 = 0x00cf_f200_0000_ffff;
/// `__USER_CS`: long mode, DPL 3, execute/read.
pub const DESC_USER_CS: u64 = 0x00af_fa00_0000_ffff;

/// Each CPU's live GDT, indexed by logical CPU id. Null until `frame` has
/// built and loaded that CPU's table.
static CPU_GDT: [AtomicPtr<u64>; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; narf_lib::percpu::MAX_CPUS];

/// Publish `gdt` as CPU `cpu`'s live GDT.
///
/// # Safety
/// `gdt` must point at `GDT_ENTRIES` writable descriptors that CPU `cpu`
/// has loaded with `LGDT`, and must stay valid for the life of the system.
/// Only that CPU may later write its TLS slots through the registry.
pub unsafe fn register_cpu_gdt(cpu: usize, gdt: *mut u64) {
    if let Some(slot) = CPU_GDT.get(cpu) {
        slot.store(gdt, Ordering::Release);
    }
}

/// CPU `cpu`'s registered GDT, or null before `frame` registered it.
pub fn cpu_gdt(cpu: usize) -> *mut u64 {
    CPU_GDT
        .get(cpu)
        .map_or(core::ptr::null_mut(), |slot| slot.load(Ordering::Acquire))
}
