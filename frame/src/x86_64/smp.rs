//! x86_64 SMP bring-up via INIT-SIPI-SIPI.
//!
//! `start_aps()` mirrors the aarch64 PSCI flow but for x86_64:
//!   1. Copy the AP trampoline blob to physical 0x8000 (the SIPI
//!      vector page) and patch its parameter block with CR3, the
//!      BSP-built GDT, the per-AP stack table, and the Rust entry
//!      pointer.
//!   2. For each AP (logical id 1..cpu_count): allocate a stack,
//!      slot it into AP_STACKS, send INIT, sleep ≥10 ms, send SIPI,
//!      sleep ≥200 µs, send a second SIPI (Intel SDM §10.4.4.1
//!      universal-startup pattern).
//!   3. Spin until each AP marks itself online via
//!      `narf_lib::smp::mark_online`.
//!
//! AP entry path: `_ap_trampoline_start` (real mode) → patched-CR3
//! load → long mode → `_ap_start_rust(logical_id)`. The trampoline
//! lives in `.text.ap_trampoline` and is copied to phys 0x8000 at
//! runtime — the BSP's identity mapping covers the first 1 GiB so
//! both source and destination are reachable.

use core::arch::asm;
use core::sync::atomic::{compiler_fence, Ordering};

use narf_console::Writer;
use core::fmt::Write;

use narf_memory::alloc_frame;

/// Where the AP trampoline lives at runtime. SIPI vector = 0x08
/// → linear address 0x8000.
const TRAMPOLINE_PHYS: u64 = 0x0000_8000;

/// SIPI vector-page byte (vector_page << 12 = TRAMPOLINE_PHYS).
const SIPI_VECTOR_PAGE: u8 = (TRAMPOLINE_PHYS >> 12) as u8;

/// Per-AP stack-top table. Indexed by logical CPU id (== APIC id
/// on QEMU). Each entry is the virtual address of the top of the
/// AP's kernel stack — the trampoline loads `rsp = AP_STACKS[id]`
/// before calling into Rust.
#[unsafe(no_mangle)]
static mut AP_STACKS: [u64; narf_lib::percpu::MAX_CPUS] =
    [0u64; narf_lib::percpu::MAX_CPUS];

/// AP stack pages — 4 KiB is sufficient for the WFI parking loop.
const AP_STACK_PAGES: usize = 1;

extern "C" {
    static _ap_trampoline_start: u8;
    static _ap_trampoline_end:   u8;
    /// Patched parameters inside the trampoline (linker symbols
    /// pointing into `.text.ap_trampoline`).
    static mut ap_param_cr3:        u64;
    static mut ap_param_gdt_limit:  u16;
    static mut ap_param_gdt_base:   u32;
    static mut ap_param_stacks:     u64;
    static mut ap_param_rust_entry: u64;
    static mut ap_param_gdt32_base: u32;
}

/// Copy the trampoline blob to phys 0x8000 and patch its parameter
/// block. Idempotent — repeated calls overwrite the same memory.
///
/// # Safety
/// - BSP, post-paging.
/// - The first 1 GiB is identity-mapped (BSP's boot.S sets this up).
unsafe fn install_trampoline() {
    // Source: kernel high-half virt of the trampoline.
    let src = core::ptr::addr_of!(_ap_trampoline_start) as *const u8;
    let end = core::ptr::addr_of!(_ap_trampoline_end)   as *const u8;
    // SAFETY: both symbols are within the same .text section so
    // pointer subtraction is sound.
    let len = unsafe { end.offset_from(src) } as usize;

    // Dest: identity-mapped phys 0x8000.
    let dst = TRAMPOLINE_PHYS as *mut u8;

    // SAFETY: src/dst are well-formed and non-overlapping (src is
    // in the kernel high half, dst is at low phys 0x8000).
    unsafe { core::ptr::copy_nonoverlapping(src, dst, len); }

    // Patch the param block in the *runtime* trampoline at
    // TRAMPOLINE_PHYS. We compute (kernel symbol offset within
    // .text.ap_trampoline) once per param and apply the same offset
    // to the runtime copy.
    let trampoline_kernel_base = src as u64;
    let phys_addr = |kern_sym: u64| -> u64 {
        TRAMPOLINE_PHYS + (kern_sym - trampoline_kernel_base)
    };

    // SAFETY: writes target identity-mapped phys 0x8000+; the BSP's
    // 1 GiB identity mapping covers the trampoline page as RW.
    unsafe {
        // CR3: read current PML4 base.
        let cr3: u64;
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        let p_cr3 = phys_addr(core::ptr::addr_of!(ap_param_cr3) as u64);
        (p_cr3 as *mut u64).write_unaligned(cr3);

        // GDT (m16&32 descriptor): limit (u16) + low 32 bits of *phys*
        // base. The 32-bit lgdt zero-extends the base; if we passed
        // the virt high-half address, the page-walk after CR0.PG=1
        // would fault since the high-half mapping is at canonical
        // 0xFFFF_FFFF_8000_0000+, not at 0x8000_0000+ (the truncation
        // of those high bits). Instead we pass the kernel-image phys
        // (virt - KERNEL_VIRT_BASE), which the identity map covers.
        const KERNEL_VIRT_BASE: u64 = 0xFFFF_FFFF_8000_0000;
        let gdt_phys = super::gdt::gdt_base() - KERNEL_VIRT_BASE;
        let gdt_limit = super::gdt::gdt_limit();
        let p_lim = phys_addr(core::ptr::addr_of!(ap_param_gdt_limit) as u64);
        let p_gdt = phys_addr(core::ptr::addr_of!(ap_param_gdt_base) as u64);
        (p_lim as *mut u16).write_unaligned(gdt_limit);
        (p_gdt as *mut u32).write_unaligned(gdt_phys as u32);

        // AP_STACKS array virt addr.
        let p_stk = phys_addr(core::ptr::addr_of!(ap_param_stacks) as u64);
        (p_stk as *mut u64).write_unaligned(
            core::ptr::addr_of!(AP_STACKS) as u64);

        // Rust entry pointer.
        let p_rs = phys_addr(core::ptr::addr_of!(ap_param_rust_entry) as u64);
        (p_rs as *mut u64).write_unaligned(_ap_start_rust as u64);

        // gdt32_ptr base. The 32-bit GDT lives 24 bytes before the
        // gdt32_ptr's limit field, and limit is 2 bytes before
        // ap_param_gdt32_base. So gdt32_start_phys = ap_param_gdt32_base_phys - 2 - 24.
        let p_gdt32 = phys_addr(core::ptr::addr_of!(ap_param_gdt32_base) as u64);
        let gdt32_start_phys = p_gdt32 - 2 - 24;
        (p_gdt32 as *mut u32).write_unaligned(gdt32_start_phys as u32);
    }

    compiler_fence(Ordering::SeqCst);
}

/// AP entry from the trampoline. Runs in 64-bit long mode with the
/// kernel's CR3, GDT, and stack already loaded; IDT not yet loaded.
/// `logical_id` was placed in RDI by the trampoline (read from
/// CPUID leaf 1 EBX[31:24] == APIC id under QEMU).
#[unsafe(no_mangle)]
pub extern "C" fn _ap_start_rust(logical_id: u64) -> ! {
    let id = logical_id as u32;

    // 1. Set IA32_TSC_AUX so current_cpu() returns logical_id.
    // SAFETY: per-CPU one-shot during bring-up.
    unsafe { narf_arch::x86_64::cpu::set_current_cpu(id); }

    // 2. Load the BSP-built IDT register on this CPU.
    // SAFETY: BSP populated IDT during init_traps; per-CPU IDTR
    // load is required even when entries are shared.
    unsafe { super::idt::load_idtr_ap(); }

    // 3. Per-CPU LAPIC bring-up: enable x2APIC + spurious vector +
    //    mask the timer LVT until the scheduler asks for it.
    // SAFETY: x2APIC is BSP-confirmed via CPUID; this AP just turns
    // it on for itself.
    unsafe { narf_interrupts::x86_64::apic::init_ap(); }

    // 4. Mark online — the BSP's start_aps() spins on this.
    // SAFETY: per-CPU bookkeeping.
    unsafe { narf_lib::smp::mark_online(id); }

    // 5. Park in HLT. Each external IRQ wakes the AP for ack-and-
    //    return-to-HLT. Real per-CPU scheduler run-loop lands when
    //    the run queues become per-CPU.
    loop {
        // SAFETY: HLT at CPL=0 with IRQs masked is a safe park; with
        // IRQs unmasked it sleeps until the next external interrupt.
        unsafe { asm!("hlt", options(nostack, preserves_flags)); }
    }
}

/// Bring up every AP advertised by `narf_lib::smp::cpu_count()`.
/// Returns the number of APs that successfully marked themselves
/// online within the per-AP timeout.
///
/// # Safety
/// - `narf_memory::init_from_map` must have run.
/// - The BSP's CR3 / GDT / IDT are valid + reachable identity-mapped.
/// - LAPIC is up (x2APIC mode, BSP-side init_bsp ran).
pub unsafe fn start_aps() -> u32 {
    let total = narf_lib::smp::cpu_count();
    if total <= 1 {
        return 0;
    }

    // SAFETY: BSP, post-paging.
    unsafe { install_trampoline(); }

    let _ = writeln!(Writer,
        "  smp(x86): trampoline installed at {:#x}", TRAMPOLINE_PHYS);

    let mut started = 0u32;
    for logical in 1..total {
        // Allocate a stack frame.
        let mut stack_top: u64 = 0;
        for _ in 0..AP_STACK_PAGES {
            match alloc_frame() {
                Ok(f) => {
                    let base = f.start_address().raw();
                    if stack_top == 0 { stack_top = base + 4096; }
                }
                Err(_) => {
                    let _ = writeln!(Writer,
                        "  smp(x86): AP {}: stack alloc failed", logical);
                    continue;
                }
            }
        }
        if stack_top == 0 { continue; }

        // SAFETY: AP_STACKS is in .data; the only writer is the BSP
        // during this start_aps call, before the AP runs.
        unsafe {
            (*core::ptr::addr_of_mut!(AP_STACKS))[logical as usize] =
                stack_top;
        }
        compiler_fence(Ordering::SeqCst);

        // Send INIT-SIPI-SIPI. APIC id == logical id under QEMU virt
        // with `-smp N -cpu max`.
        let target = logical;

        // SAFETY: x2APIC enabled by init_bsp.
        unsafe {
            narf_interrupts::x86_64::apic::send_init_ipi(target);
        }
        delay_us(10_000);            // 10 ms per Intel SDM §10.4.4.1
        // SAFETY: same.
        unsafe {
            narf_interrupts::x86_64::apic::send_startup_ipi(
                target, SIPI_VECTOR_PAGE);
        }
        delay_us(200);               // ≥200 µs between SIPIs
        // SAFETY: same.
        unsafe {
            narf_interrupts::x86_64::apic::send_startup_ipi(
                target, SIPI_VECTOR_PAGE);
        }

        let _ = writeln!(Writer,
            "  smp(x86): INIT-SIPI-SIPI to APIC {} sent", target);

        // Wait for AP to mark itself online.
        let mut spins = 0u32;
        while !narf_lib::smp::is_online(logical) {
            spins += 1;
            if spins > 50_000_000 {
                let _ = writeln!(Writer,
                    "  smp(x86): AP {} never reported online", logical);
                break;
            }
            core::hint::spin_loop();
        }
        if narf_lib::smp::is_online(logical) {
            started += 1;
        }
    }
    started
}

/// Crude TSC-based microsecond delay. Enough for the SIPI timing
/// constraints; the calibrated time source replaces this when
/// `narf-time` lands SMP-aware calibration.
fn delay_us(us: u64) {
    // Assume a ≥1 GHz TSC (QEMU's invariant TSC defaults to host
    // freq, which is comfortably above 1 GHz on any modern host;
    // the 10 ms / 200 µs timing only requires a *minimum* delay so
    // overshooting is harmless).
    let cycles = us * 1_000;
    let start = read_tsc();
    while read_tsc().wrapping_sub(start) < cycles {
        core::hint::spin_loop();
    }
}

#[inline]
fn read_tsc() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: RDTSC is always legal at CPL=0.
    unsafe {
        asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}
