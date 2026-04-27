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

        // Install EL1 vector table so exceptions route through Rust
        // handlers instead of whatever default state the bootloader
        // left.
        // SAFETY: first call, BSP, IRQs masked (DAIF left as boot
        // defaults; we'll explicitly unmask later).
        unsafe { aarch64::init_traps(); }
        let _ = writeln!(console::Writer,
            "  vbar_el1: loaded — 16 EL1 vectors routed");

        // GICv3 bring-up (only if the sysreg interface is there).
        if feats.gicv3_sysreg {
            // SAFETY: CPUID confirmed GICv3; still at EL1 with IRQs
            // masked.
            unsafe { narf_interrupts::aarch64::init_bsp(); }
            let _ = writeln!(console::Writer,
                "  gic: v3 enabled, timer PPI {} unmasked", narf_interrupts::aarch64::TIMER_PPI);
        } else {
            let _ = writeln!(console::Writer,
                "  gic: v3 sysreg interface unavailable — IRQs stay masked");
        }
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

                // Bus enumeration. The MMU's identity map covers the
                // q35 ECAM at 0xb000_0000, so the walker can read raw
                // 4-byte cfg-space words without a separate mapping
                // step. Real MCFG parsing (boot/) feeds the base in
                // when ACPI lands; until then we use the QEMU default.
                // SAFETY: ECAM_DEFAULT_BASE is identity-mapped; the
                // walker only does naturally-aligned reads + rejects
                // 0xFFFF vendors.
                let n_dev = unsafe {
                    narf_bus::init(narf_bus::x86_64::ECAM_DEFAULT_BASE)
                };
                let _ = writeln!(console::Writer,
                    "  bus: PCIe ECAM walk found {} function(s)", n_dev);
                let _ = writeln!(console::Writer,
                    "  smp: {} CPU(s) advertised, {} online (ACPI MADT pending)",
                    narf_lib::smp::cpu_count(),
                    narf_lib::smp::online_count());
            }
            #[cfg(target_arch = "aarch64")]
            {
                let _ = writeln!(console::Writer, "  mmu: handoff...");
                // SAFETY: BSP, interrupts disabled, allocator populated.
                match unsafe { narf_memory::mmu::init_mmu() } {
                    Ok(ttbr0) => {
                        narf_console::remap_to_virtual(info.uart_virt);
                        let _ = writeln!(console::Writer,
                            "  mmu: installed, TTBR0 @ {:?}, console remapped", ttbr0);
                    }
                    Err(e) => {
                        let _ = writeln!(console::Writer,
                            "  mmu: init failed: {e:?}");
                    }
                }

                // Bus enumeration. The DTB pointer comes through
                // `BootInfo`; if QEMU's `-kernel` path didn't supply
                // one, the walker falls back to the QEMU virt
                // virtio-mmio defaults.
                // SAFETY: DTB blob is in identity-mapped low RAM;
                // reads validate magic before trusting offsets.
                let n_dev = unsafe { narf_bus::init(info.dtb_phys) };
                let devs  = narf_bus::devices();
                let n_pcie = devs.iter()
                    .filter(|d| matches!(d.kind, narf_bus::BusKind::Pcie { .. }))
                    .count();
                let n_mmio = devs.iter()
                    .filter(|d| matches!(d.kind, narf_bus::BusKind::VirtioMmio { .. }))
                    .count();
                let _ = writeln!(console::Writer,
                    "  bus: dtb={:?} → {} dev ({} pcie, {} virtio-mmio)",
                    info.dtb_phys, n_dev, n_pcie, n_mmio);

                // GIC ITS bring-up. Memory is online, GICv3 is up
                // (gic::init_bsp ran above). Programs the device /
                // collection / command-queue tables, sets
                // GICR_PROPBASER / GICR_PENDBASER, enables LPIs, then
                // submits MAPC for collection 0 → CPU 0. Idempotent.
                // SAFETY: GICv3 distributor + CPU 0 redistributor are
                // enabled; allocator is online; QEMU virt's ITS lives
                // at the documented MMIO base.
                match unsafe { narf_interrupts::aarch64::its::init_bsp() } {
                    Ok(())  => {
                        let _ = writeln!(console::Writer,
                            "  its: GICv3 ITS up, doorbell @ {:#x}",
                            narf_interrupts::aarch64::its::doorbell_pa());
                    }
                    Err(e) => {
                        let _ = writeln!(console::Writer,
                            "  its: bring-up failed: {e:?}");
                    }
                }
                // BSP's default SGI handlers (PANIC_HALT, RESCHED).
                narf_interrupts::aarch64::sgi::install_defaults();

                // SMP discovery: count CPUs from the DTB.
                if let Some(p) = info.dtb_phys {
                    // SAFETY: DTB validated by boot/aarch64.
                    let n = unsafe {
                        narf_lib::smp::count_aarch64_cpus_in_dtb(p.raw())
                    };
                    if n > 0 {
                        narf_lib::smp::set_cpu_count(n);
                    }
                    let _ = writeln!(console::Writer,
                        "  smp: {} CPU(s) advertised", narf_lib::smp::cpu_count());
                }

                // AP bring-up via PSCI CPU_ON. Each AP runs through
                // smp_entry.S → _ap_start_rust which marks itself
                // online via narf_lib::smp::mark_online.
                // SAFETY: memory + GIC + DTB-supplied topology
                // already initialised above.
                let started = unsafe { aarch64::smp::start_aps() };
                let _ = writeln!(console::Writer,
                    "  smp: started {} AP(s); {} CPU(s) online",
                    started, narf_lib::smp::online_count());
            }

            // ── PCIe driver registration + dispatch ───────────────
            // Register every in-tree PCIe driver with the bus
            // match table, then walk the registry binding each
            // discovered device to its driver. Keeps boot-time
            // driver dispatch in one place (kernel-test harness
            // re-runs this per smoke; the boot path establishes
            // the canonical set of drivers).
            narf_drivers_nvme::register_pci_driver();
            narf_drivers_virtio::blk_pci::register_pci_driver();
            narf_drivers_virtio::net_pci::register_pci_driver();
            narf_drivers_virtio::rng_pci::register_pci_driver();
            narf_drivers_virtio::balloon_pci::register_pci_driver();
            narf_drivers_net::e1000::register_pci_driver();
            narf_drivers_storage::ahci::register_pci_driver();
            narf_drivers_usb::xhci::register_pci_driver();

            let auth = narf_bus::bootstrap_registry_authority();
            match narf_bus::probe_all_pci(&auth) {
                Ok(n) => {
                    let bound = narf_drivers::bound_drivers();
                    let _ = writeln!(console::Writer,
                        "  drivers: bound {} PCIe device(s); inventory={}",
                        n, bound.len());
                    for b in &bound {
                        let _ = writeln!(console::Writer,
                            "    {} ({:?}) {:04x}:{:04x}",
                            b.name, b.kind,
                            b.pci_vid.unwrap_or(0), b.pci_did.unwrap_or(0));
                    }
                }
                Err(_) => {
                    let _ = writeln!(console::Writer,
                        "  drivers: probe_all_pci failed");
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
    // aarch64 timer start. GICv3 + vector table already installed
    // earlier; this starts the generic-timer PPI and unmasks IRQs
    // in DAIF.
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: GIC is up (or the feature check in _start_rust
        // skipped init_bsp, in which case timer IRQs fire but are
        // never delivered — still safe, just silent).
        unsafe {
            narf_interrupts::aarch64::start_timer(
                aarch64::trap::TIMER_TVAL_DEFAULT);
            narf_arch::enable_interrupts();
        }
        let _ = writeln!(console::Writer,
            "  gic: generic timer started, IRQs unmasked");
    }

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
    #[cfg(target_arch = "aarch64")]
    {
        let ticks = narf_interrupts::aarch64::timer_ticks();
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
