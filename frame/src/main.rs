//! narf-frame — the TCB bin crate. Contains `_start`, BSP bring-up, and
//! the panic path. Stage 1 is deliberately minimal: do the boot-loader
//! handoff, initialise the serial console, print a hello line, and halt.
//!
//! Spec: `frame/specification/spec.md`. Full BSP responsibilities
//! (GDT/IDT/TSS with IST slots on x86_64, EL1 vector table on aarch64,
//! trap-prologue PKRS save scaffolding) land alongside Wave 2's memory
//! bring-up.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use core::fmt::Write;
use core::panic::PanicInfo;

use narf_boot::{RawBootInfo};
use narf_console::{self as console, UartKind};
use narf_memory::{PhysAddr, BumpAllocator};

#[global_allocator]
static GLOBAL_ALLOC: BumpAllocator = BumpAllocator;

#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "aarch64")]
mod aarch64;

/// Called from the arch-specific boot stub once the CPU is in a state
/// capable of executing Rust: stack set up, appropriate privilege level,
/// long mode (on x86_64), and a `RawBootInfo` packed from the bootloader's
/// handoff registers.
///
/// # Safety
/// - `raw` must describe a real bootloader handoff (the arch stub
///   constructed it from the machine registers, so this holds by
///   construction).
/// - MMU / TLB / interrupt controller are in the bootloader-documented
///   state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start_rust(raw: RawBootInfo) -> ! {
    // Step 1: bring up the early serial console before doing anything else,
    // so any failure from here on is visible.
    #[cfg(target_arch = "x86_64")]
    {
        // 16550A COM1 at I/O port 0x3F8 — hard-coded default. Real detection
        // lands with the ACPI/FDT parse in Wave 2.
        console::early_init(PhysAddr::new(0x3F8), UartKind::Uart16550);
    }
    #[cfg(target_arch = "aarch64")]
    {
        // PL011 at QEMU virt's MMIO base.
        console::early_init(PhysAddr::new(0x0900_0000), UartKind::Pl011);
    }

    let _ = writeln!(console::Writer, "NARF Stage 1 Wave 1 — hello from a bare kernel.");
    let arch_name = if cfg!(target_arch = "x86_64") { "x86_64" }
                    else if cfg!(target_arch = "aarch64") { "aarch64" }
                    else { "unknown" };
    let _ = writeln!(console::Writer,
        "  arch: {} | backend: {:?}", arch_name, narf_arch::BACKEND);

    // Install the IDT so any exception from here on becomes a structured
    // panic instead of a silent triple-fault. Wave 2 will extend this
    // with GDT/TSS and per-IST stacks for NMI, #DF, #MC.
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: first call, BSP, pre-AP.
        unsafe { x86_64::init_traps(); }
        let _ = writeln!(console::Writer, "  idt: loaded — 32 CPU-exception vectors routed");
    }

    // Stage 2 feature probe. Print what the CPU supports; gate
    // per-feature enables on explicit CPUID presence so the kernel
    // boots on pre-PKS / pre-UIPI hardware (with degraded behaviour
    // in later stages rather than a boot panic).
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: CPUID is always legal at CPL=0.
        let feats = unsafe { narf_arch::x86_64::Features::probe() };
        let _ = writeln!(console::Writer,
            "  features: nx={} tsc_inv={} pku={} pks={} uipi={} rdseed={} rdrand={}",
            feats.nx, feats.invariant_tsc, feats.pku, feats.pks,
            feats.uipi, feats.rdseed, feats.rdrand);

        // Attempt to enable CR4.PKS if available. Success means the
        // IA32_PKRS MSR is now accessible and per-page PK bits are
        // active — Stage 2 domain-switch machinery can now use them.
        if feats.pks {
            // SAFETY: CPUID confirmed PKS support.
            unsafe {
                let cr4 = narf_arch::x86_64::cr::read_cr4();
                narf_arch::x86_64::cr::write_cr4(cr4 | narf_arch::x86_64::cr::CR4_PKS);
                narf_arch::x86_64::msr::wrmsr(narf_arch::x86_64::msr::IA32_PKRS, 0);
            }
            let _ = writeln!(console::Writer,
                "  pks: enabled (CR4.PKS=1, IA32_PKRS=0 / all-allow)");
        } else {
            let _ = writeln!(console::Writer,
                "  pks: unavailable — Stage-2 Barrier domain switch will degrade");
        }

        // NX enable. PTE bit 63 (NO_EXEC) is reserved-zero unless
        // IA32_EFER.NXE=1. Flipping the bit at boot makes subsequent
        // `PtFlags::NO_EXEC` mappings actually block execution.
        if feats.nx {
            // SAFETY: CPUID confirmed NX support.
            unsafe {
                use narf_arch::x86_64::msr::{rdmsr, wrmsr, IA32_EFER, IA32_EFER_NXE};
                let efer = rdmsr(IA32_EFER);
                wrmsr(IA32_EFER, efer | IA32_EFER_NXE);
            }
            let _ = writeln!(console::Writer,
                "  nx: enabled (IA32_EFER.NXE=1, PTE NO_EXEC active)");
        } else {
            let _ = writeln!(console::Writer, "  nx: unavailable");
        }

        // x2APIC + LAPIC timer. Gated on CPUID.x2APIC; absence leaves
        // the scheduler in its Stage-1 busy-poll mode, which still
        // works, just without timer IRQs.
        if feats.x2apic {
            // SAFETY: CPUID confirmed x2APIC.
            unsafe { narf_interrupts::x86_64::apic::init_bsp(); }
            let _ = writeln!(console::Writer,
                "  apic: x2APIC enabled, 8259 PICs masked");
        }
    }

    // aarch64 feature probe — mirrors the x86_64 block above. Gates
    // the MTE/GICv3/PAC enable on actual silicon support so the same
    // kernel image boots across CPU variants.
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: MRS of ID_AA64* is always legal at EL1.
        let feats = unsafe { narf_arch::aarch64::Features::probe() };
        // SAFETY: CNTFRQ_EL0 is always readable.
        let hz = unsafe { narf_arch::aarch64::cpuid::generic_timer_hz() };
        let _ = writeln!(console::Writer,
            "  features: mte={} pauth={} bti={} gicv3_sr={} cntfrq={}Hz",
            feats.mte, feats.pauth, feats.bti, feats.gicv3_sysreg, hz);
    }

    // Boot-time domain enumeration — STAGE1.md exit-gate #5. Confirm the
    // authoritative DomainId table from security-model/ §4.1 is the one
    // `narf_lib::id` declares at compile time.
    {
        use narf_lib::id::DomainId;
        const DOMAINS: &[(DomainId, &str)] = &[
            (DomainId::FRAME,       "FRAME"),
            (DomainId::CAPS,        "CAPS"),
            (DomainId::MEMORY_MGR,  "MEMORY_MGR"),
            (DomainId::SCHED,       "SCHED"),
            (DomainId::IPC,         "IPC"),
            (DomainId::TRACER,      "TRACER"),
            (DomainId::KEYS,        "KEYS"),
            (DomainId::OBSERVE,     "OBSERVE"),
            (DomainId::USERSPACE_K, "USERSPACE_K"),
            (DomainId::DRIVER_0,    "DRIVER_0"),
            (DomainId::DRIVER_1,    "DRIVER_1"),
            (DomainId::DRIVER_2,    "DRIVER_2"),
            (DomainId::DRIVER_3,    "DRIVER_3"),
            (DomainId::DRIVER_4,    "DRIVER_4"),
            (DomainId::DRIVER_5,    "DRIVER_5"),
            (DomainId::SCRATCH,     "SCRATCH"),
        ];
        let _ = writeln!(console::Writer,
            "  domains: {} declared (Stage 1 all PKS/MTE-off, rights = all-allow)",
            DOMAINS.len());
    }

    // Step 2: parse the bootloader handoff into a validated BootInfo.
    // SAFETY: the raw struct came from the arch stub; bootloader contract.
    let boot_result = unsafe {
        #[cfg(target_arch = "x86_64")]
        { narf_boot::x86_64::parse_raw(&raw) }
        #[cfg(target_arch = "aarch64")]
        { narf_boot::aarch64::parse_raw(&raw) }
    };

    match boot_result {
        Ok(info) => {
            let _ = writeln!(console::Writer,
                "  boot info: {} memory region(s), uart_phys={:?}",
                info.memory_map.len(), info.uart_phys);
            let mut usable_bytes: u64 = 0;
            for r in info.memory_map {
                if r.kind == narf_boot::MemRegionKind::Usable {
                    usable_bytes = usable_bytes.saturating_add(r.len);
                }
            }
            let _ = writeln!(console::Writer,
                "  usable RAM: {} MiB", usable_bytes / (1024 * 1024));

            // Bring the frame allocator online. Exclude the kernel image
            // itself so we don't hand out our own code/data as free frames.
            // SAFETY: __kernel_start / __kernel_end are linker-provided
            // symbols bounding the loaded image in physical memory.
            extern "C" {
                static __kernel_start: u8;
                static __kernel_end:   u8;
            }
            let kstart = core::ptr::addr_of!(__kernel_start) as u64;
            let kend   = core::ptr::addr_of!(__kernel_end)   as u64;

            let regions: alloc::vec::Vec<narf_memory::UsableRegion> =
                info.memory_map.iter()
                    .filter(|r| r.kind == narf_boot::MemRegionKind::Usable)
                    .map(|r| narf_memory::UsableRegion {
                        start: r.start,
                        len:   r.len,
                    })
                    .collect();
            let exclude: &[(u64, u64)] = &[(kstart, kend)];

            // SAFETY: first call, BSP, memory map came from parse_raw
            // which validated magic + min-RAM.
            unsafe { narf_memory::init_from_map(&regions, exclude); }

            let s = narf_memory::frame_stats();
            let _ = writeln!(console::Writer,
                "  frames: total {} / free {} / reserved {} ({} MiB usable)",
                s.total, s.free, s.reserved,
                (s.free as u64) * narf_memory::PAGE_SIZE / (1024 * 1024));

            // MMU handoff per console/ §3.1. The three-step sequence
            // (print, swap, remap) is orchestrated here because
            // memory/ can't depend on console/ without creating a
            // crate cycle. Closes Stage 1 exit-gate #2.
            #[cfg(target_arch = "x86_64")]
            {
                let _ = writeln!(console::Writer, "  mmu: handoff...");
                // SAFETY: BSP, interrupts disabled (boot.S CLI + IDT
                // doesn't unmask), allocator populated above.
                match unsafe { narf_memory::mmu::init_mmu() } {
                    Ok(pml4) => {
                        // The new PML4 identity-maps 0..=4 GiB, so the
                        // UART (I/O port on x86_64) is reachable and
                        // console::remap_to_virtual with an identity
                        // address is correct.
                        narf_console::remap_to_virtual(info.uart_virt);
                        let _ = writeln!(console::Writer,
                            "  mmu: installed, PML4 @ {:?}, console remapped", pml4);
                    }
                    Err(e) => {
                        let _ = writeln!(console::Writer,
                            "  mmu: init failed: {e:?}");
                    }
                }
            }
        }
        Err(e) => {
            let _ = writeln!(console::Writer, "  boot parse failed: {e:?}");
        }
    }

    // Quick self-test: trigger a #UD (invalid-opcode) to prove the IDT
    // actually dispatches. The handler prints the trap frame and calls
    // exit_kernel(42). If the IDT weren't installed this would
    // triple-fault into a reset loop (blocked by `-no-reboot`).
    #[cfg(all(target_arch = "x86_64", feature = "idt-selftest"))]
    {
        let _ = writeln!(console::Writer, "  self-test: triggering #UD ...");
        // SAFETY: `ud2` is an intentional fault; our handler catches it
        // and calls exit_kernel(42), so this asm never returns.
        unsafe { core::arch::asm!("ud2", options(noreturn)); }
    }

    // Run the kernel-test harness instead of the async demo when the
    // `kernel-test` feature is on. `run_all_and_exit` never returns.
    #[cfg(feature = "kernel-test")]
    { narf_verification::run_all_and_exit(); }

    // ─── Stage 1 exit-gate demo: async executor + timer-driven yield ──
    #[cfg(not(any(feature = "kernel-test", feature = "idt-selftest")))]
    run_async_demo()
}

#[cfg(not(any(feature = "kernel-test", feature = "idt-selftest")))]
fn run_async_demo() -> ! {
    // Stage 2 Barrier: LAPIC timer IRQs are now live. `init_bsp`
    // masks both legacy 8259 PICs so their BIOS-default vectors
    // can't land on ours. Start a periodic timer and enable CPU
    // IRQs — the async demo below runs with real timer-driven
    // interrupts visible through `timer_ticks()`.
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: APIC is up (init_bsp ran), IDT is loaded, PIC
        // is masked. This starts the periodic timer + unmasks CPU
        // IRQs; from here the LAPIC timer fires vector 32 every
        // `initial_count` LAPIC ticks, the IDT dispatches to
        // `rust_trap_handler` which increments `timer_ticks` and
        // EOIs.
        unsafe {
            narf_interrupts::x86_64::apic::start_timer(
                narf_interrupts::VECTOR_TIMER,
                1_000_000,
            );
            narf_arch::enable_interrupts();
        }
        let _ = writeln!(console::Writer,
            "  apic: LAPIC timer live on vector {}, IRQs unmasked",
            narf_interrupts::VECTOR_TIMER);
    }

    narf_scheduler::init();
    let _ = writeln!(console::Writer, "  scheduler: ready queue initialised");

    narf_scheduler::spawn(async {
        use core::fmt::Write as _;
        let start = narf_time::Instant::now();
        // Assume a ~1 GHz clock for the tick spacing. Calibration is a
        // Wave 3 task (consult HPET / ACPI / FDT). 1e8 cycles ≈ 100 ms
        // at 1 GHz; at 2-3 GHz it's correspondingly faster.
        const TICK_CYCLES: u64 = 100_000_000;
        for n in 0..5 {
            narf_time::sleep_cycles(TICK_CYCLES).await;
            let elapsed = narf_time::Instant::now().cycles_since(start);
            let _ = writeln!(console::Writer,
                "  tick {}: elapsed {} Mcycles", n, elapsed / 1_000_000);
            narf_scheduler::yield_now().await;
        }
        let _ = writeln!(console::Writer, "  async demo: done");
    });

    let _ = writeln!(console::Writer, "  scheduler: spawning 1 task, running to completion");
    narf_scheduler::run_until_empty();

    let _ = writeln!(console::Writer, "  heap used: {} / {} bytes",
        narf_memory::heap::used_bytes(), narf_memory::heap::capacity_bytes());
    #[cfg(target_arch = "x86_64")]
    {
        let ticks = narf_interrupts::x86_64::apic::timer_ticks();
        let _ = writeln!(console::Writer,
            "  timer IRQs delivered: {} ticks", ticks);
    }
    let _ = writeln!(console::Writer, "  halting — Stage 1 exit-gate demo complete.");

    // SAFETY: exit_kernel is infallible; on QEMU it exits cleanly via
    // the isa-debug-exit device (x86_64) or semihosting (aarch64); on
    // real hardware it falls back to a quiet halt.
    unsafe { narf_arch::exit_kernel(0) }
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    console::panic_sink(info)
}
