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
// ── NUMA topology hooks for narf-memory's frame allocator ──────────
//
// `narf-memory` declares these as `extern "Rust"` so it doesn't take
// a circular dependency on `narf-acpi`. We bridge here, since
// `narf-frame` is the only crate that links both.
#[unsafe(no_mangle)]
pub fn narf_phys_to_node(addr: u64) -> u32 {
    narf_acpi::memory_node(addr).unwrap_or(0)
}
#[unsafe(no_mangle)]
pub fn narf_cpu_to_node(cpu: u32) -> u32 {
    narf_acpi::cpu_node(cpu).unwrap_or(0)
}

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

        // Domain-enforcer selection. PKS is the fast path (single
        // WRMSR per crossing); when it's absent — typically AMD
        // silicon or pre-SPR Intel — fall back to the PCID enforcer:
        // CR3 swap with PCID-preserve. Per-domain PML4 *divergence*
        // (the part that makes isolation strict instead of nominal)
        // requires a memory/ surface change and is not yet wired —
        // unregistered domains share the bootstrap PML4. The CR3
        // swap path itself is exercised either way.
        if feats.pks {
            // SAFETY: CPUID confirmed PKS support.
            unsafe {
                let cr4 = narf_arch::x86_64::cr::read_cr4();
                narf_arch::x86_64::cr::write_cr4(cr4 | narf_arch::x86_64::cr::CR4_PKS);
                narf_arch::x86_64::msr::wrmsr(narf_arch::x86_64::msr::IA32_PKRS, 0);
            }
            narf_arch::x86_64::pks::mark_active();
            narf_arch::set_effective_backend(narf_arch::DomainBackend::Pks);
            let _ = writeln!(console::Writer,
                "  domain enforcer: pks (CR4.PKS=1, IA32_PKRS=0 / all-allow)");
        } else {
            // PCID fallback. Order matters: enable CR4.PCIDE first
            // (this requires CR3 to currently have PCID = 0, which is
            // the case at boot — bootloader hands us a CR3 with the
            // legacy PWT/PCD bits clear), then snapshot CR3 as the
            // bootstrap PML4 in `pcid::init`. After init, allocate 16
            // per-domain PML4s as byte-copies of the bootstrap. Because
            // the copy preserves the PML4 entries (which are pointers
            // to PDPT pages), the 16 clones share the same downstream
            // page tables — KAISER-style fan-out: any kernel-side
            // mapping change after boot is visible to all 16 domains
            // automatically. Domain-private mappings (which require
            // a per-domain PDPT under one PML4 slot) are a follow-up.
            //
            // SAFETY: PCID is a baseline x86_64 feature on all
            // long-mode CPUs; the bootloader-provided CR3's low bits
            // are zero.
            unsafe {
                narf_arch::x86_64::pcid::enable_pcide();
                narf_arch::x86_64::pcid::init();
            }
            // Allocate + register 16 per-domain PML4 clones, spread
            // across NUMA nodes. Domain D's PML4 lands on node
            // (D % num_nodes) so PML4 reads on a CPU local to that
            // node hit local memory.
            let num_nodes = if narf_memory::is_numa_aware() {
                // Count nodes with non-zero free pages.
                let mut n = 0usize;
                for i in 0..narf_memory::FRAME_MAX_NUMA_NODES {
                    if narf_memory::node_free(i) > 0 { n = i + 1; }
                }
                n.max(1)
            } else { 1 };
            let mut registered = 0u8;
            for domain in 0u8..16 {
                let node = (domain as usize) % num_nodes;
                // SAFETY: paging on, identity map covers low frames,
                // alloc_frame_on returns identity-mapped 4 KiB.
                match unsafe { narf_memory::paging::new_user_pml4_on(node) } {
                    Ok(phys) => {
                        // SAFETY: domain<16; phys is a valid 4KiB frame.
                        unsafe { narf_arch::x86_64::pcid::set_domain_pml4(domain, phys.raw()); }
                        registered += 1;
                    }
                    Err(_) => {
                        // Out of frames at boot is unexpected, but bail
                        // out of the loop and run nominal-isolation if so.
                        break;
                    }
                }
            }
            // Install per-domain private PDPTs (slot 256+D in each
            // domain's PML4). After this, accesses to domain D's
            // private VA range from any other domain hard-fault at
            // PML4 level.
            // SAFETY: pcid::init has run; PML4s are registered;
            // identity map still covers low frames.
            let private_pdpts = match unsafe { narf_memory::domain::init_per_domain_pdpts() } {
                Ok(n)  => n,
                Err(_) => 0,
            };
            narf_arch::set_effective_backend(narf_arch::DomainBackend::Pcid);
            let _ = writeln!(console::Writer,
                "  domain enforcer: pcid (CR4.PCIDE=1, {} PML4 clones, \
                 {} private PDPTs at slots 256..=271; cross-domain \
                 access to private VAs faults at PML4 level)",
                registered, private_pdpts);
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
            // Install the TLB-shootdown IPI handler now — APs may
            // call shoot_va once they come up, and the handler must
            // be live before the first IPI lands.
            narf_interrupts::x86_64::ipi::install();
            // Wire the memory subsystem's `invlpg_global` to
            // broadcast through this IPI surface. After this call,
            // every unmap_4kb fans out to peer CPUs.
            narf_memory::paging::set_shootdown_hook(|va| {
                // SAFETY: x2APIC online, IPI handler installed.
                unsafe { narf_interrupts::x86_64::ipi::shoot_va(va); }
            });
            // Range hook: one IPI for a contiguous run of pages.
            narf_memory::paging::set_range_shootdown_hook(|va, pages| {
                // SAFETY: x2APIC online, IPI handler installed.
                unsafe { narf_interrupts::x86_64::ipi::shoot_range(va, pages); }
            });
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

        // Domain-enforcer selection. MTE is the fast path on aarch64;
        // when it's absent we will eventually fall back to ASID-tagged
        // per-domain page tables (the aarch64 analogue of the PCID
        // path on x86_64). Today only the MTE branch is wired.
        // ID_AA64PFR1_EL1.MTE is a 4-bit field: 0=none, 1=instructions
        // only, 2=memory tagging supported, 3+=advanced. Anything >=2
        // is sufficient for our purposes.
        if feats.mte >= 2 {
            narf_arch::set_effective_backend(narf_arch::DomainBackend::Mte);
            let _ = writeln!(console::Writer,
                "  domain enforcer: mte");
        } else {
            // No MTE — for now stay on the Mte type alias (its
            // unimplemented stubs are never invoked in this config)
            // and report Pcid-class fallback intent.
            narf_arch::set_effective_backend(narf_arch::DomainBackend::Pcid);
            let _ = writeln!(console::Writer,
                "  domain enforcer: pcid-class fallback \
                 (no MTE — ASID-tagged per-domain page tables pending)");
        }

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

                // ACPI tables (RSDP → XSDT → SRAT/MADT/MCFG). PVH
                // bootloaders may or may not populate `rsdp_paddr`;
                // QEMU's `-kernel` path leaves it zero even when ACPI
                // is present. Fall back to a 0xE_0000..0x10_0000
                // BIOS-area scan for the "RSD PTR " signature.
                // ACPI parsing precedes bus init so MCFG can supply
                // the PCIe ECAM base, and precedes SMP discovery so
                // MADT can provide the CPU count.
                let rsdp = info.acpi_rsdp_phys
                    // SAFETY: identity-mapped low ROM scan.
                    .or_else(|| unsafe { narf_acpi::scan_bios_for_rsdp() });
                match rsdp {
                    Some(p) => {
                        // SAFETY: RSDP is in identity-mapped RAM /
                        // ROM; the XSDT chain it leads to lives in
                        // ACPI-reclaimable RAM the boot map listed.
                        match unsafe { narf_acpi::parse_srat(p) } {
                            Ok(n) => {
                                let _ = writeln!(console::Writer,
                                    "  acpi: SRAT parsed, {} entries, {} NUMA node(s)",
                                    n, narf_acpi::node_count());
                                // Redistribute the frame allocator's
                                // free pool by NUMA node now that
                                // memory_node() is populated. Subsequent
                                // alloc_frame() calls honour locality.
                                narf_memory::rebalance_to_topology();
                                let n_nodes = narf_acpi::node_count() as usize;
                                let mut totals = 0usize;
                                for i in 0..n_nodes.min(narf_memory::FRAME_MAX_NUMA_NODES) {
                                    let f = narf_memory::node_free(i);
                                    totals += f;
                                    let _ = writeln!(console::Writer,
                                        "    node {}: {} free frames", i, f);
                                }
                                let _ = writeln!(console::Writer,
                                    "  frames: NUMA-rebalanced ({} per-node total)", totals);
                            }
                            Err(e) => {
                                let _ = writeln!(console::Writer,
                                    "  acpi: SRAT parse skipped: {:?}", e);
                            }
                        }
                        // SAFETY: same RSDP, validated above.
                        match unsafe { narf_acpi::parse_madt(p) } {
                            Ok(n) => {
                                let _ = writeln!(console::Writer,
                                    "  acpi: MADT parsed, {} entries, {} CPU(s), LAPIC base {:#x}",
                                    n, narf_acpi::cpu_count_from_madt(),
                                    narf_acpi::lapic_base().unwrap_or(0));
                            }
                            Err(e) => {
                                let _ = writeln!(console::Writer,
                                    "  acpi: MADT parse skipped: {:?}", e);
                            }
                        }
                        // SAFETY: same.
                        match unsafe { narf_acpi::parse_mcfg(p) } {
                            Ok(base) => {
                                let _ = writeln!(console::Writer,
                                    "  acpi: MCFG ECAM base {:#x}", base);
                            }
                            Err(e) => {
                                let _ = writeln!(console::Writer,
                                    "  acpi: MCFG parse skipped: {:?}", e);
                            }
                        }
                        // SAFETY: same.
                        match unsafe { narf_acpi::parse_hmat(p) } {
                            Ok(n) => {
                                let _ = writeln!(console::Writer,
                                    "  acpi: HMAT parsed, {} entries", n);
                            }
                            Err(e) => {
                                let _ = writeln!(console::Writer,
                                    "  acpi: HMAT parse skipped: {:?}", e);
                            }
                        }
                        // SAFETY: same.
                        match unsafe { narf_aml::parse_namespace(p) } {
                            Ok(n) => {
                                let mut devs = 0u32;
                                narf_aml::for_each_device(|_| { devs += 1; });
                                let _ = writeln!(console::Writer,
                                    "  aml: namespace built, {} nodes ({} devices)",
                                    n, devs);
                                // Snapshot — later tests that mutate
                                // the live namespace can still consult
                                // the boot-time numbers.
                                narf_aml::capture_boot_snapshot();
                            }
                            Err(e) => {
                                let _ = writeln!(console::Writer,
                                    "  aml: namespace build skipped: {:?}", e);
                            }
                        }
                        // SAFETY: same RSDP, validated above.
                        let _ = unsafe { narf_acpi::parse_gpe_blocks(p) };
                        let n = narf_aml::gpe::install_aml_handlers();
                        let _ = writeln!(console::Writer,
                            "  acpi: GPE blocks parsed, {} AML handler(s)", n);
                        // SAFETY: same.
                        match unsafe { narf_acpi::parse_pmtt(p) } {
                            Ok(n) => {
                                let (s, c, d) = narf_acpi::pmtt_counts();
                                let _ = writeln!(console::Writer,
                                    "  acpi: PMTT parsed, {} structures ({} socket, {} ctrl, {} dimm)",
                                    n, s, c, d);
                            }
                            Err(e) => {
                                let _ = writeln!(console::Writer,
                                    "  acpi: PMTT parse skipped: {:?}", e);
                            }
                        }
                    }
                    None => {
                        let _ = writeln!(console::Writer,
                            "  acpi: no RSDP found; running flat");
                    }
                }

                // PCIe enumeration. Prefer the MCFG-derived ECAM
                // base when ACPI was parsed; fall back to the QEMU
                // q35 hardcoded default. SAFETY: ECAM base is
                // identity-mapped; the walker only does
                // naturally-aligned reads + rejects 0xFFFF vendors.
                let ecam = narf_acpi::mcfg_ecam_base()
                    .map(narf_memory::PhysAddr::new)
                    .unwrap_or(narf_bus::x86_64::ECAM_DEFAULT_BASE);
                let n_dev = unsafe { narf_bus::init(ecam) };
                let _ = writeln!(console::Writer,
                    "  bus: PCIe ECAM walk @ {:?} found {} function(s)",
                    ecam, n_dev);

                // SMP CPU count: prefer MADT (canonical APIC
                // enumeration), then SRAT (covers multi-socket
                // configs), then CPUID leaf 0xB sub-1 (per-core
                // count, only correct on single-socket configs).
                let n_madt = narf_acpi::cpu_count_from_madt();
                let n_srat = narf_acpi::cpu_count_from_srat();
                let (n, src) = if n_madt > 0 {
                    (n_madt, "MADT")
                } else if n_srat > 0 {
                    (n_srat, "SRAT")
                } else {
                    // SAFETY: CPUID is always legal at CPL=0.
                    (unsafe { narf_lib::smp::count_x86_64_cpus_via_cpuid() }, "CPUID")
                };
                if n > 0 {
                    narf_lib::smp::set_cpu_count(n);
                }
                let _ = writeln!(console::Writer,
                    "  smp: {} CPU(s) advertised (source: {})",
                    narf_lib::smp::cpu_count(), src);

                // Initialise per-CPU scheduler queues *before* AP
                // bring-up — APs jump straight into the scheduler
                // run loop and need their own queue ready.
                narf_scheduler::init();

                // AP bring-up via INIT-SIPI-SIPI. Trampoline lands at
                // phys 0x8000; APs enter `_ap_start_rust` after the
                // 16→32→64 mode walk.
                // SAFETY: memory + LAPIC + IDT/GDT all initialised
                // above; identity map covers 0x8000.
                let started = unsafe { x86_64::smp::start_aps() };
                let _ = writeln!(console::Writer,
                    "  smp: started {} AP(s); {} CPU(s) online",
                    started, narf_lib::smp::online_count());
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

                // Initialise per-CPU scheduler queues *before* AP
                // bring-up — APs jump straight into the scheduler
                // run loop and need their own queue ready.
                narf_scheduler::init();

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
            // Initialise the shared input event ring before any
            // input driver pushes to it. Capacity 256 is enough for
            // ~1 second of bursty keyboard input.
            narf_input::init_global_ring(256);

            // Best-effort i8042 PS/2 keyboard bring-up on x86_64.
            // QEMU q35 always exposes i8042 even with USB present;
            // legacy hardware does too. A failure here just means
            // no keyboard events arrive — drivers fed from
            // virtio-input still work.
            #[cfg(target_arch = "x86_64")]
            {
                // SAFETY: BSP, no other agent driving 0x60/0x64.
                match unsafe { narf_input_driver::i8042::init() } {
                    Ok(()) => {
                        let _ = writeln!(console::Writer,
                            "  input: i8042 PS/2 keyboard initialised (IRQ 1)");
                    }
                    Err(e) => {
                        let _ = writeln!(console::Writer,
                            "  input: i8042 init skipped ({:?})", e);
                    }
                }
            }

            narf_drivers_nvme::register_pci_driver();
            narf_drivers_virtio::blk_pci::register_pci_driver();
            narf_drivers_virtio::net_pci::register_pci_driver();
            narf_drivers_virtio::rng_pci::register_pci_driver();
            narf_drivers_virtio::balloon_pci::register_pci_driver();
            narf_drivers_virtio::input_pci::register_pci_driver();
            narf_drivers_virtio::gpu_pci::register_pci_driver();
            narf_drivers_net::e1000::register_pci_driver();
            narf_drivers_storage::ahci::register_pci_driver();
            narf_drivers_usb::xhci::register_pci_driver();
            #[cfg(target_arch = "x86_64")]
            narf_graphics_driver::bochs::register_pci_driver();

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

            // Splash blit: if a framebuffer device probed AND its
            // BAR0 lies inside the low-4-GiB identity map, paint a
            // background + a centred "NARF" banner sketched from
            // filled rectangles. Above 4 GiB the boot PML4 has no
            // PTEs covering the BAR yet — log + skip.
            #[cfg(target_arch = "x86_64")]
            {
                use narf_graphics::Pixel32;
                let painted = narf_graphics_driver::bochs::with_controller(|d| {
                    if !d.fb_reachable() {
                        let _ = writeln!(console::Writer,
                            "  splash: bochs framebuffer at {:#x} above 4 GiB \
                             identity map; deferred until ioremap lands",
                            d.fb_phys());
                        return (0u32, 0u32);
                    }
                    // SAFETY: BSP, no concurrent draw, framebuffer is
                    // the device's exclusive scanout buffer.
                    let mut fb = unsafe { d.framebuffer() };
                    fb.clear(Pixel32::NARF_BG);
                    // Centred NARF banner: 4 letterforms, 64 px tall,
                    // 6 px stroke, 16 px gap. Total width ≈ 4*48 + 3*16 = 240 px.
                    let stroke = 6u32;
                    let h = 64u32;
                    let w = 48u32;
                    let gap = 16u32;
                    let total = 4 * w + 3 * gap;
                    let x0 = (fb.width.saturating_sub(total)) / 2;
                    let y0 = (fb.height.saturating_sub(h)) / 2;
                    let fg = Pixel32::NARF_FG;
                    // Helper: draw an "N".
                    let mut x = x0;
                    // Left vertical
                    fb.fill_rect(x, y0, stroke, h, fg);
                    // Right vertical
                    fb.fill_rect(x + w - stroke, y0, stroke, h, fg);
                    // Diagonal: approximated by a series of stepped
                    // rects so we don't need a line primitive yet.
                    {
                        let steps = h / stroke;
                        for i in 0..steps {
                            let dx = (i * (w - stroke)) / steps;
                            fb.fill_rect(x + dx, y0 + i * stroke, stroke, stroke, fg);
                        }
                    }
                    // 'A'
                    x += w + gap;
                    fb.fill_rect(x, y0, stroke, h, fg);                                  // left vertical
                    fb.fill_rect(x + w - stroke, y0, stroke, h, fg);                     // right vertical
                    fb.fill_rect(x, y0, w, stroke, fg);                                  // top bar
                    fb.fill_rect(x, y0 + h/2 - stroke/2, w, stroke, fg);                 // mid bar
                    // 'R'
                    x += w + gap;
                    fb.fill_rect(x, y0, stroke, h, fg);                                  // left vertical
                    fb.fill_rect(x, y0, w, stroke, fg);                                  // top bar
                    fb.fill_rect(x + w - stroke, y0, stroke, h/2, fg);                   // upper-right vertical
                    fb.fill_rect(x, y0 + h/2 - stroke/2, w, stroke, fg);                 // mid bar
                    {
                        // diagonal lower stroke (R's leg) via stepped rects.
                        let steps = (h - h/2) / stroke;
                        for i in 0..steps {
                            let dx = (i * (w - stroke)) / steps.max(1);
                            fb.fill_rect(x + dx, y0 + h/2 + i * stroke, stroke, stroke, fg);
                        }
                    }
                    // 'F'
                    x += w + gap;
                    fb.fill_rect(x, y0, stroke, h, fg);                                  // left vertical
                    fb.fill_rect(x, y0, w, stroke, fg);                                  // top bar
                    fb.fill_rect(x, y0 + h/2 - stroke/2, w*3/4, stroke, fg);             // mid bar
                    (d.width, d.height)
                });
                if let Some((w, h)) = painted {
                    if w > 0 {
                        let _ = writeln!(console::Writer,
                            "  splash: {}x{} bochs framebuffer painted with NARF banner",
                            w, h);
                    }
                }
            }

            // virtio-gpu splash (cross-arch). If bochs already drew
            // its banner above, this paints the same banner on the
            // virtio-gpu scanout so multi-display setups light up
            // both heads. On aarch64 this is the primary path.
            {
                use narf_graphics::Pixel32;
                let painted = narf_drivers_virtio::gpu_pci::with_controller_mut(|d| {
                    // SAFETY: BSP, post-bring_up.
                    if !d.ready {
                        if let Err(e) = unsafe { d.init_scanout() } {
                            let _ = writeln!(console::Writer,
                                "  splash: virtio-gpu init_scanout failed: {:?}", e);
                            return (0u32, 0u32);
                        }
                    }
                    // SAFETY: BSP, no concurrent draw. The 32×32
                    // scanout is too small for the rectangular-NARF
                    // banner used on bochs; instead paint a 4-coloured
                    // diamond pattern that's visibly the kernel's
                    // signature (TL=red, TR=green, BL=blue, BR=NARF_FG).
                    let mut fb = unsafe { d.framebuffer() };
                    let half = 16u32;
                    fb.fill_rect(0,    0,    half, half, Pixel32::RED);
                    fb.fill_rect(half, 0,    half, half, Pixel32::GREEN);
                    fb.fill_rect(0,    half, half, half, Pixel32::BLUE);
                    fb.fill_rect(half, half, half, half, Pixel32::NARF_FG);
                    // SAFETY: bring_up complete; ctrl_q ready.
                    let _ = unsafe { d.flush() };
                    (d.mode.width, d.mode.height)
                });
                if let Some((w, h)) = painted {
                    if w > 0 {
                        let _ = writeln!(console::Writer,
                            "  splash: {}x{} virtio-gpu scanout painted (4-quadrant pattern)",
                            w, h);
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
