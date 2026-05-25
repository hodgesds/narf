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

use core::fmt::Write;
use narf_console::Writer;

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
static mut AP_STACKS: [u64; narf_lib::percpu::MAX_CPUS] = [0u64; narf_lib::percpu::MAX_CPUS];

/// AP stack pages — 4 KiB is sufficient for the WFI parking loop.
const AP_STACK_PAGES: usize = 1;

extern "C" {
    static _ap_trampoline_start: u8;
    static _ap_trampoline_end: u8;
    /// Patched parameters inside the trampoline (linker symbols
    /// pointing into `.text.ap_trampoline`).
    static mut ap_param_cr3: u64;
    static mut ap_param_gdt_limit: u16;
    static mut ap_param_gdt_base: u32;
    static mut ap_param_stacks: u64;
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
    let end = core::ptr::addr_of!(_ap_trampoline_end) as *const u8;
    // SAFETY: both symbols are within the same .text section so
    // pointer subtraction is sound.
    let len = unsafe { end.offset_from(src) } as usize;

    // Dest: identity-mapped phys 0x8000.
    let dst = TRAMPOLINE_PHYS as *mut u8;

    // SAFETY: src/dst are well-formed and non-overlapping (src is
    // in the kernel high half, dst is at low phys 0x8000).
    unsafe {
        core::ptr::copy_nonoverlapping(src, dst, len);
    }

    // Patch the param block in the *runtime* trampoline at
    // TRAMPOLINE_PHYS. We compute (kernel symbol offset within
    // .text.ap_trampoline) once per param and apply the same offset
    // to the runtime copy.
    let trampoline_kernel_base = src as u64;
    let phys_addr =
        |kern_sym: u64| -> u64 { TRAMPOLINE_PHYS + (kern_sym - trampoline_kernel_base) };

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
        (p_stk as *mut u64).write_unaligned(core::ptr::addr_of!(AP_STACKS) as u64);

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
    unsafe {
        narf_arch::x86_64::cpu::set_current_cpu(id);
    }

    // 1a. Record this AP's hybrid CPU type. Order matters: must
    //     come after set_current_cpu (so the slot index is right
    //     even if a future revision changes how the slot is
    //     keyed) and before any code that might want to consult
    //     CPU_TYPES[id]. CPUID leaf 0x1A is per-LP, so each AP
    //     reads its own value — the BSP's reading wouldn't apply.
    //     On non-hybrid silicon (AMD, pre-Alder-Lake Intel) the
    //     leaf is undefined and reads zero, which decodes to
    //     CpuType::Unknown.
    // SAFETY: CPUID at CPL=0 is always legal.
    unsafe {
        let raw = narf_arch::x86_64::cpuid::read_hybrid_cpu_type();
        narf_lib::percpu::set_cpu_type(
            id,
            narf_lib::percpu::CpuType::from_raw(raw),
        );
    }

    // 1b. Apply per-silicon errata on this AP. Same table as the
    //     BSP — chicken bits like AMD DE_CFG[9] / [14] are
    //     per-core MSRs, not core-cluster-shared, so each AP
    //     needs the write itself. SAFETY: CPL=0; per-entry SAFETY
    //     notes apply.
    unsafe {
        let _ = narf_arch::x86_64::errata::apply_for_current_cpu();
    }

    // 2. Load the BSP-built IDT register on this CPU.
    // SAFETY: BSP populated IDT during init_traps; per-CPU IDTR
    // load is required even when entries are shared.
    unsafe {
        super::idt::load_idtr_ap();
    }

    // 3. Per-CPU LAPIC bring-up: enable x2APIC + spurious vector +
    //    mask the timer LVT until the scheduler asks for it.
    // SAFETY: x2APIC is BSP-confirmed via CPUID; this AP just turns
    // it on for itself.
    unsafe {
        narf_interrupts::x86_64::apic::init_ap();
    }

    // 3a. Arm the per-CPU LAPIC timer in periodic mode. Without
    //     this, halt_until_irq parks the AP forever — no timer
    //     ticks, no IPIs, never wakes — so its run_until_empty
    //     never gets a chance to drain its queue or steal work.
    //     Mirror the BSP arm in LapicClockEvent::arm_periodic
    //     (prefer TSC-deadline, fall back to fixed-count
    //     periodic) so the trap handler routes ticks identically
    //     per CPU. APs only run tasks they can legally take
    //     (Affinity.allowed.contains(this_cpu)) — today
    //     TaskSpec::unthrottled() pins to BSP, so APs idle until
    //     something is explicitly spawned at AP affinity. The
    //     SMP-safety audit per task is gated on this being in
    //     place + the affinity defaults having flipped.
    // SAFETY: init_ap above already enabled x2APIC + spurious;
    // LAPIC timer programming is per-CPU MSR/MMIO.
    unsafe {
        let feats = narf_arch::x86_64::Features::probe();
        if feats.tsc_deadline {
            // 100 Hz default — match BSP's arm_periodic(100, vec).
            let cpns = narf_time::wall::cycles_per_ns().max(1) as u64;
            let period_cycles = (10_000_000u64).saturating_mul(cpns);
            narf_interrupts::x86_64::apic::start_timer_tsc_deadline(
                narf_interrupts::VECTOR_TIMER,
                period_cycles,
            );
        } else {
            narf_interrupts::x86_64::apic::start_timer(
                narf_interrupts::VECTOR_TIMER,
                10_000,
            );
        }
    }

    // 3b. Match the BSP's domain-enforcer state on this AP. CR4 is
    //     per-CPU, so when the BSP picked the PCID backend at boot
    //     each AP must also enable CR4.PCIDE to participate. CR3 was
    //     loaded by the trampoline with PCID = 0 in its low bits, so
    //     the PCIDE prerequisite is satisfied. The PML4 registry +
    //     bootstrap PML4 are global state already armed by the BSP.
    //
    //     For the PKS path the same logic applies: AP CR4.PKS must
    //     mirror BSP. We enable both per the BSP's effective backend.
    if narf_arch::effective_backend() == narf_arch::DomainBackend::Pcid {
        // SAFETY: PCID is a baseline x86_64 feature; CR3 has PCID = 0.
        unsafe {
            narf_arch::x86_64::pcid::enable_pcide();
        }
    } else if narf_arch::effective_backend() == narf_arch::DomainBackend::Pks {
        // Mirror CR4.PKS on this AP. CPUID gating already happened on
        // the BSP — if PKS is selected we know the silicon supports it.
        // SAFETY: BSP confirmed PKS support via CPUID.
        unsafe {
            let cr4 = narf_arch::x86_64::cr::read_cr4();
            narf_arch::x86_64::cr::write_cr4(cr4 | narf_arch::x86_64::cr::CR4_PKS);
            narf_arch::x86_64::msr::wrmsr(narf_arch::x86_64::msr::IA32_PKRS, 0);
        }
    }

    // 4. Mark online — the BSP's start_aps() spins on this.
    // SAFETY: per-CPU bookkeeping.
    unsafe {
        narf_lib::smp::mark_online(id);
    }

    // 4b. Unmask IRQs so cross-CPU IPIs (TLB shootdown, RESCHED, …)
    //     can land on this AP. Without this, the AP halts in
    //     halt_until_irq's spin-loop fallback and never sees IPIs.
    // SAFETY: IDT is loaded, x2APIC is up, traps are wired.
    unsafe {
        narf_arch::enable_interrupts();
    }

    // 5. Enter the per-CPU scheduler run loop. `run_forever` drains
    //    this CPU's ready queue, attempts to steal from siblings,
    //    and halts on IRQ when nothing is runnable. Returns never.
    narf_scheduler::run_forever();
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

    // IPI senders dispatch on `X2APIC_ACTIVE`: x2APIC ICR (MSR
    // 0x830) when live, xAPIC MMIO ICR (LAPIC base + 0x300/0x310)
    // otherwise. So SMP works on real HW with x2APIC and under
    // QEMU TCG (which emulates xAPIC MMIO but not x2APIC ICR).
    if !narf_interrupts::x86_64::apic::X2APIC_ACTIVE
        .load(core::sync::atomic::Ordering::Acquire)
    {
        let _ = writeln!(Writer, "  smp(x86): using xAPIC MMIO IPI fallback");
    }

    // SAFETY: BSP, post-paging.
    unsafe {
        install_trampoline();
    }

    let _ = writeln!(
        Writer,
        "  smp(x86): trampoline installed at {:#x}",
        TRAMPOLINE_PHYS
    );

    // Allocate stacks for every AP up front so a partial failure
    // (frame allocator exhausted mid-batch) doesn't leave half the
    // APs ready and half not. Skipped slots stay 0 in AP_STACKS;
    // the trampoline halts the AP if its stack-top entry is 0.
    // Stack-allocated viable list to avoid pulling `alloc` into
    // this module — `MAX_CPUS` is a small fixed bound.
    let mut viable_buf = [0u32; narf_lib::percpu::MAX_CPUS];
    let mut viable_len: usize = 0;
    for logical in 1..total {
        let mut stack_top: u64 = 0;
        for _ in 0..AP_STACK_PAGES {
            match alloc_frame() {
                Ok(f) => {
                    let base = f.start_address().raw();
                    if stack_top == 0 {
                        stack_top = base + 4096;
                    }
                }
                Err(_) => {
                    let _ = writeln!(Writer, "  smp(x86): AP {}: stack alloc failed", logical);
                    break;
                }
            }
        }
        if stack_top == 0 {
            continue;
        }
        // SAFETY: AP_STACKS is in .data; the only writer is the BSP
        // during this start_aps call, before the AP runs.
        unsafe {
            (*core::ptr::addr_of_mut!(AP_STACKS))[logical as usize] = stack_top;
        }
        viable_buf[viable_len] = logical;
        viable_len += 1;
    }
    let viable = &viable_buf[..viable_len];
    compiler_fence(Ordering::SeqCst);

    // Parallelise the INIT-SIPI-SIPI handshake across APs: a serial
    // per-AP loop pays `(10ms + 200us)` for *every* AP (≈ 630ms wall
    // time at 64 cores) — the SDM §10.4.4.1 timing constraints are
    // *minimum* delays between phases against any single AP, so
    // batching across APs is fine. With this shape the entire phase
    // takes ~10.2ms regardless of AP count.
    //
    // APIC id == logical id under QEMU's `-smp N`; on real silicon
    // MADT enumeration produces the same identity for the
    // common-case Local APIC entries (apic_id == cpu_index). When
    // ACPI ever surfaces a non-trivial mapping this loop wants a
    // proper apic_id_for_logical(id) lookup.

    // SAFETY: x2APIC enabled by init_bsp.
    for &logical in viable.iter() {
        unsafe {
            narf_interrupts::x86_64::apic::send_init_ipi(logical);
        }
    }
    delay_us(10_000); // 10 ms per Intel SDM §10.4.4.1, single shared wait

    // SAFETY: same.
    for &logical in viable.iter() {
        unsafe {
            narf_interrupts::x86_64::apic::send_startup_ipi(logical, SIPI_VECTOR_PAGE);
        }
    }
    delay_us(200); // ≥200 µs between SIPIs, single shared wait

    // SAFETY: same.
    for &logical in viable.iter() {
        unsafe {
            narf_interrupts::x86_64::apic::send_startup_ipi(logical, SIPI_VECTOR_PAGE);
        }
    }

    let _ = writeln!(
        Writer,
        "  smp(x86): INIT-SIPI-SIPI broadcast to {} AP(s)",
        viable_len
    );

    // Single shared online-spin watchdog instead of per-AP.
    // 500 ms wall-clock budget — generous for real APs (typically
    // come up in <10 ms each) and tight enough that a wedged
    // controller doesn't burn forever. responsive_spin_until
    // ticks sleep_pumps so cursor/FB/serial stay alive.
    let _ = narf_scheduler::responsive_spin_until(
        || {
            viable
                .iter()
                .filter(|&&id| narf_lib::smp::is_online(id))
                .count() as u32
                == viable_len as u32
        },
        narf_time::Deadline::after_ms(500),
    );
    let started = viable
        .iter()
        .filter(|&&id| narf_lib::smp::is_online(id))
        .count() as u32;
    if started != viable_len as u32 {
        for &id in viable.iter() {
            if !narf_lib::smp::is_online(id) {
                let _ = writeln!(Writer, "  smp(x86): AP {} never reported online", id);
            }
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
