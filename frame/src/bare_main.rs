//! Bare-metal kernel content for `narf-frame`. Included from
//! `main.rs` as a module gated on `target_os = "none"`. Crate-
//! level attributes (`#![no_std]`, `#![no_main]`, lint flags)
//! live in `main.rs` so they aren't re-applied here.
//!
//! Contains `_start`, BSP bring-up, and the panic path. Spec:
//! `frame/specification/spec.md`. Full BSP responsibilities
//! (GDT/IDT/TSS with IST slots on x86_64, EL1 vector table on
//! aarch64, trap-prologue PKRS save scaffolding) land alongside
//! Wave 2's memory bring-up.

extern crate alloc;

// Force-link crates whose only public surface is kernel tests
// registered via `#[link_section = "narf.tests"]`. Without an
// explicit `extern crate`, rustc would not pull the rlib into the
// link, and the linker's `KEEP(*(narf.tests))` would never see the
// crate's test entries. (Crates that the kernel actually uses by
// name pick themselves up — these are the test-only ones.)
extern crate narf_bluetooth as _;
extern crate narf_drivers_fs_fat as _;
extern crate narf_edid as _;
extern crate narf_efi as _;
extern crate narf_hid as _;
extern crate narf_pinctrl as _;

use core::fmt::Write;
use core::panic::PanicInfo;

use narf_boot::{BootInfo, RawBootInfo};
use narf_console::{self as console, UartKind};
use narf_memory::{BumpAllocator, PhysAddr};

static mut RAW_BOOT_INFO: Option<RawBootInfo> = None;
static mut BOOT_INFO: Option<BootInfo> = None;

#[global_allocator]
static GLOBAL_ALLOC: BumpAllocator = BumpAllocator;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

mod measure;

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

    let _ = writeln!(
        console::Writer,
        "NARF Stage 1 Wave 1 — hello from a bare kernel."
    );
    let arch_name = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "unknown"
    };
    let _ = writeln!(
        console::Writer,
        "  arch: {} | backend: {:?}",
        arch_name,
        narf_arch::BACKEND
    );

    // Install the IDT so any exception from here on becomes a structured
    // panic instead of a silent triple-fault. Wave 2 will extend this
    // with GDT/TSS and per-IST stacks for NMI, #DF, #MC.
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: first call, BSP, pre-AP.
        unsafe {
            x86_64::init_traps();
        }
        let _ = writeln!(
            console::Writer,
            "  idt: loaded — 32 CPU-exception vectors routed"
        );
    }

    // Stage 2 feature probe. Print what the CPU supports; gate
    // per-feature enables on explicit CPUID presence so the kernel
    // boots on pre-PKS / pre-UIPI hardware (with degraded behaviour
    // in later stages rather than a boot panic).
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: CPUID is always legal at CPL=0.
        let feats = unsafe { narf_arch::x86_64::Features::probe() };
        let _ = writeln!(
            console::Writer,
            "  features: nx={} tsc_inv={} pku={} pks={} uipi={} rdseed={} rdrand={}",
            feats.nx,
            feats.invariant_tsc,
            feats.pku,
            feats.pks,
            feats.uipi,
            feats.rdseed,
            feats.rdrand
        );

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
            let _ = writeln!(
                console::Writer,
                "  domain enforcer: pks (CR4.PKS=1, IA32_PKRS=0 / all-allow)"
            );
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
                    if narf_memory::node_free(i) > 0 {
                        n = i + 1;
                    }
                }
                n.max(1)
            } else {
                1
            };
            // Initialise the cross-arch per-domain root registry +
            // ASID/PCID allocator before populating per-domain PML4s.
            narf_memory::asid_alloc::allocator_init();
            narf_memory::per_domain_root::init();
            let mut registered = 0u8;
            for domain in 0u8..16 {
                let node = (domain as usize) % num_nodes;
                // SAFETY: paging on, identity map covers low frames,
                // alloc_frame_on returns identity-mapped 4 KiB.
                match unsafe { narf_memory::paging::new_user_pml4_on(node) } {
                    Ok(phys) => {
                        // SAFETY: domain<16; phys is a valid 4KiB frame.
                        unsafe {
                            narf_arch::x86_64::pcid::set_domain_pml4(domain, phys.raw());
                        }
                        // Mirror into the unified registry. Errors
                        // here are benign — the pcid registry above
                        // is the authoritative copy.
                        let _ = narf_memory::per_domain_root::register_root(
                            narf_lib::id::DomainId::new(domain),
                            phys.raw(),
                        );
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
                Ok(n) => n,
                Err(_) => 0,
            };
            narf_arch::set_effective_backend(narf_arch::DomainBackend::Pcid);
            let _ = writeln!(
                console::Writer,
                "  domain enforcer: pcid (CR4.PCIDE=1, {} PML4 clones, \
                 {} private PDPTs at slots 256..=271; cross-domain \
                 access to private VAs faults at PML4 level)",
                registered,
                private_pdpts
            );
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
            let _ = writeln!(
                console::Writer,
                "  nx: enabled (IA32_EFER.NXE=1, PTE NO_EXEC active)"
            );
        } else {
            let _ = writeln!(console::Writer, "  nx: unavailable");
        }

        // x2APIC + LAPIC timer. Gated on CPUID.x2APIC; absence leaves
        // the scheduler in its Stage-1 busy-poll mode, which still
        // works, just without timer IRQs.
        if feats.x2apic {
            // SAFETY: CPUID confirmed x2APIC.
            unsafe {
                narf_interrupts::x86_64::apic::init_bsp();
            }
            let _ = writeln!(console::Writer, "  apic: x2APIC enabled, 8259 PICs masked");
            // Install the TLB-shootdown IPI handler now — APs may
            // call shoot_va once they come up, and the handler must
            // be live before the first IPI lands.
            narf_interrupts::x86_64::ipi::install();
            // Wire the memory subsystem's `invlpg_global` to
            // broadcast through this IPI surface. After this call,
            // every unmap_4kb fans out to peer CPUs.
            narf_memory::paging::set_shootdown_hook(|va| {
                // SAFETY: x2APIC online, IPI handler installed.
                unsafe {
                    narf_interrupts::x86_64::ipi::shoot_va(va);
                }
            });
            // Range hook: one IPI for a contiguous run of pages.
            narf_memory::paging::set_range_shootdown_hook(|va, pages| {
                // SAFETY: x2APIC online, IPI handler installed.
                unsafe {
                    narf_interrupts::x86_64::ipi::shoot_range(va, pages);
                }
            });
            // Install the unified `narf_memory::tlb_shootdown::shootdown`
            // → IPI fan-out hook so the asid/pcid-isolation surface
            // also benefits from cross-CPU dispatch.
            narf_interrupts::install_tlb_shootdown_bridge();
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
        let _ = writeln!(
            console::Writer,
            "  features: mte={} pauth={} bti={} gicv3_sr={} cntfrq={}Hz",
            feats.mte,
            feats.pauth,
            feats.bti,
            feats.gicv3_sysreg,
            hz
        );

        // Domain-enforcer selection. MTE is the fast path on aarch64;
        // when it's absent we will eventually fall back to ASID-tagged
        // per-domain page tables (the aarch64 analogue of the PCID
        // path on x86_64). Today only the MTE branch is wired.
        // ID_AA64PFR1_EL1.MTE is a 4-bit field: 0=none, 1=instructions
        // only, 2=memory tagging supported, 3+=advanced. Anything >=2
        // is sufficient for our purposes.
        if feats.mte >= 2 {
            narf_arch::set_effective_backend(narf_arch::DomainBackend::Mte);
            let _ = writeln!(console::Writer, "  domain enforcer: mte");
        } else {
            // No MTE — for now stay on the Mte type alias (its
            // unimplemented stubs are never invoked in this config)
            // and report Pcid-class fallback intent.
            narf_arch::set_effective_backend(narf_arch::DomainBackend::Pcid);
            let _ = writeln!(
                console::Writer,
                "  domain enforcer: pcid-class fallback \
                 (no MTE — ASID-tagged per-domain page tables pending)"
            );
        }

        // Install EL1 vector table so exceptions route through Rust
        // handlers instead of whatever default state the bootloader
        // left.
        // SAFETY: first call, BSP, IRQs masked (DAIF left as boot
        // defaults; we'll explicitly unmask later).
        unsafe {
            aarch64::init_traps();
        }
        let _ = writeln!(
            console::Writer,
            "  vbar_el1: loaded — 16 EL1 vectors routed"
        );

        // GICv3 bring-up (only if the sysreg interface is there).
        if feats.gicv3_sysreg {
            // SAFETY: CPUID confirmed GICv3; still at EL1 with IRQs
            // masked.
            unsafe {
                narf_interrupts::aarch64::init_bsp();
            }
            let _ = writeln!(
                console::Writer,
                "  gic: v3 enabled, timer PPI {} unmasked",
                narf_interrupts::aarch64::TIMER_PPI
            );
            // Install the unified `narf_memory::tlb_shootdown::shootdown`
            // → SGI fan-out hook on aarch64 too.
            narf_interrupts::install_tlb_shootdown_bridge();
        } else {
            let _ = writeln!(
                console::Writer,
                "  gic: v3 sysreg interface unavailable — IRQs stay masked"
            );
        }
    }

    // Boot-time domain enumeration — STAGE1.md exit-gate #5. Confirm the
    // authoritative DomainId table from security-model/ §4.1 is the one
    // `narf_lib::id` declares at compile time.
    {
        use narf_lib::id::DomainId;
        const DOMAINS: &[(DomainId, &str)] = &[
            (DomainId::FRAME, "FRAME"),
            (DomainId::CAPS, "CAPS"),
            (DomainId::MEMORY_MGR, "MEMORY_MGR"),
            (DomainId::SCHED, "SCHED"),
            (DomainId::IPC, "IPC"),
            (DomainId::TRACER, "TRACER"),
            (DomainId::KEYS, "KEYS"),
            (DomainId::OBSERVE, "OBSERVE"),
            (DomainId::USERSPACE_K, "USERSPACE_K"),
            (DomainId::DRIVER_0, "DRIVER_0"),
            (DomainId::DRIVER_1, "DRIVER_1"),
            (DomainId::DRIVER_2, "DRIVER_2"),
            (DomainId::DRIVER_3, "DRIVER_3"),
            (DomainId::DRIVER_4, "DRIVER_4"),
            (DomainId::DRIVER_5, "DRIVER_5"),
            (DomainId::SCRATCH, "SCRATCH"),
        ];
        let _ = writeln!(
            console::Writer,
            "  domains: {} declared (Stage 1 all PKS/MTE-off, rights = all-allow)",
            DOMAINS.len()
        );
    }

    // Step 2: parse the bootloader handoff into a validated BootInfo.
    // SAFETY: the raw struct came from the arch stub; bootloader contract.
    let boot_result = unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            narf_boot::x86_64::parse_raw(&raw)
        }
        #[cfg(target_arch = "aarch64")]
        {
            narf_boot::aarch64::parse_raw(&raw)
        }
    };

    match boot_result {
        Ok(info) => {
            // SAFETY: Single-threaded boot path.
            unsafe {
                RAW_BOOT_INFO = Some(raw);
                BOOT_INFO = Some(info.clone());
            }
            let _ = writeln!(
                console::Writer,
                "  boot info: {} memory region(s), uart_phys={:?}",
                info.memory_map.len(),
                info.uart_phys
            );
            let mut usable_bytes: u64 = 0;
            for r in info.memory_map {
                if r.kind == narf_boot::MemRegionKind::Usable {
                    usable_bytes = usable_bytes.saturating_add(r.len);
                }
            }
            let _ = writeln!(
                console::Writer,
                "  usable RAM: {} MiB",
                usable_bytes / (1024 * 1024)
            );

            // Stage the bootloader-supplied initramfs (if any) so
            // Stage::Late consumers (firmware scanner, /boot mount,
            // userspace init binary loader) can borrow it. Done
            // BEFORE the frame allocator goes live so the
            // bootloader's reserved phys range is still
            // unambiguously identity-mapped readable.
            if let Some(region) = info.initramfs {
                // SAFETY: bootloader contract — the region is
                // identity-mapped reserved memory of exactly
                // `region.len` bytes carrying a CPIO newc
                // archive. `narf-initramfs` parses + leaks the
                // result so the lifetime extends to kernel
                // shutdown.
                let staged = unsafe {
                    narf_initramfs::stage_from_phys(
                        "boot-initramfs",
                        region.start.raw(),
                        region.len,
                    )
                };
                match staged {
                    Ok(()) => {
                        let _ = writeln!(
                            console::Writer,
                            "  initramfs: staged {} byte(s) at phys {:#x}",
                            region.len,
                            region.start.raw()
                        );
                    }
                    Err(e) => {
                        let _ = writeln!(console::Writer, "  initramfs: parse rejected ({:?})", e);
                    }
                }
            }

            // Bring the frame allocator online. Exclude the kernel image
            // itself so we don't hand out our own code/data as free frames.
            // SAFETY: __kernel_start / __kernel_end are linker-provided
            // symbols bounding the loaded image in physical memory.
            extern "C" {
                static __kernel_start: u8;
                static __kernel_end: u8;
            }
            let kstart = core::ptr::addr_of!(__kernel_start) as u64;
            let kend = core::ptr::addr_of!(__kernel_end) as u64;

            let regions: alloc::vec::Vec<narf_memory::UsableRegion> = info
                .memory_map
                .iter()
                .filter(|r| r.kind == narf_boot::MemRegionKind::Usable)
                .map(|r| narf_memory::UsableRegion {
                    start: r.start,
                    len: r.len,
                })
                .collect();
            let exclude: &[(u64, u64)] = &[(kstart, kend)];

            // SAFETY: first call, BSP, memory map came from parse_raw
            // which validated magic + min-RAM.
            unsafe {
                narf_memory::init_from_map(&regions, exclude);
            }

            // Register the generic framebuffer if provided by the bootloader.
            if let Some(fb_info) = info.framebuffer {
                let fb = narf_graphics_driver::generic::GenericFb::new(
                    fb_info.addr.raw(),
                    fb_info.width,
                    fb_info.height,
                    fb_info.pitch,
                    fb_info.bpp,
                );
                narf_fb::register_generic(fb);
                let _ = writeln!(
                    console::Writer,
                    "  generic-fb: registered {}x{} at {:#x}",
                    fb_info.width,
                    fb_info.height,
                    fb_info.addr.raw()
                );
            }

            let s = narf_memory::frame_stats();
            let _ = writeln!(
                console::Writer,
                "  frames: total {} / free {} / reserved {} ({} MiB usable)",
                s.total,
                s.free,
                s.reserved,
                (s.free as u64) * narf_memory::PAGE_SIZE / (1024 * 1024)
            );

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
                        let _ = writeln!(
                            console::Writer,
                            "  mmu: installed, PML4 @ {:?}, console remapped",
                            pml4
                        );
                    }
                    Err(e) => {
                        let _ = writeln!(console::Writer, "  mmu: init failed: {e:?}");
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
                let rsdp = info
                    .acpi_rsdp_phys
                    // SAFETY: identity-mapped low ROM scan.
                    .or_else(|| unsafe { narf_acpi::scan_bios_for_rsdp() });
                match rsdp {
                    Some(p) => {
                        // SAFETY: RSDP is in identity-mapped RAM /
                        // ROM; the XSDT chain it leads to lives in
                        // ACPI-reclaimable RAM the boot map listed.
                        match unsafe { narf_acpi::parse_srat(p) } {
                            Ok(n) => {
                                let _ = writeln!(
                                    console::Writer,
                                    "  acpi: SRAT parsed, {} entries, {} NUMA node(s)",
                                    n,
                                    narf_acpi::node_count()
                                );
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
                                    let _ = writeln!(
                                        console::Writer,
                                        "    node {}: {} free frames",
                                        i,
                                        f
                                    );
                                }
                                let _ = writeln!(
                                    console::Writer,
                                    "  frames: NUMA-rebalanced ({} per-node total)",
                                    totals
                                );
                            }
                            Err(e) => {
                                let _ = writeln!(
                                    console::Writer,
                                    "  acpi: SRAT parse skipped: {:?}",
                                    e
                                );
                            }
                        }
                        // SAFETY: same RSDP, validated above.
                        match unsafe { narf_acpi::parse_madt(p) } {
                            Ok(n) => {
                                let _ =
                                    writeln!(console::Writer,
                                    "  acpi: MADT parsed, {} entries, {} CPU(s), LAPIC base {:#x}",
                                    n, narf_acpi::cpu_count_from_madt(),
                                    narf_acpi::lapic_base().unwrap_or(0));
                            }
                            Err(e) => {
                                let _ = writeln!(
                                    console::Writer,
                                    "  acpi: MADT parse skipped: {:?}",
                                    e
                                );
                            }
                        }
                        // SAFETY: same.
                        match unsafe { narf_acpi::parse_mcfg(p) } {
                            Ok(base) => {
                                let _ =
                                    writeln!(console::Writer, "  acpi: MCFG ECAM base {:#x}", base);
                            }
                            Err(e) => {
                                let _ = writeln!(
                                    console::Writer,
                                    "  acpi: MCFG parse skipped: {:?}",
                                    e
                                );
                            }
                        }
                        // SAFETY: same.
                        match unsafe { narf_acpi::parse_hmat(p) } {
                            Ok(n) => {
                                let _ =
                                    writeln!(console::Writer, "  acpi: HMAT parsed, {} entries", n);
                            }
                            Err(e) => {
                                let _ = writeln!(
                                    console::Writer,
                                    "  acpi: HMAT parse skipped: {:?}",
                                    e
                                );
                            }
                        }
                        // SAFETY: same.
                        match unsafe { narf_aml::parse_namespace(p) } {
                            Ok(n) => {
                                let mut devs = 0u32;
                                narf_aml::for_each_device(|_| {
                                    devs += 1;
                                });
                                let _ = writeln!(
                                    console::Writer,
                                    "  aml: namespace built, {} nodes ({} devices)",
                                    n,
                                    devs
                                );
                                // Snapshot — later tests that mutate
                                // the live namespace can still consult
                                // the boot-time numbers.
                                narf_aml::capture_boot_snapshot();
                            }
                            Err(e) => {
                                let _ = writeln!(
                                    console::Writer,
                                    "  aml: namespace build skipped: {:?}",
                                    e
                                );
                            }
                        }
                        // SAFETY: same RSDP, validated above.
                        let _ = unsafe { narf_acpi::parse_ecdt(p) };
                        let _ = unsafe { narf_acpi::parse_gpe_blocks(p) };
                        let n = narf_aml::gpe::install_aml_handlers();
                        let _ = writeln!(
                            console::Writer,
                            "  acpi: GPE blocks parsed, {} AML handler(s)",
                            n
                        );
                        // SAFETY: same.
                        match unsafe { narf_acpi::parse_pmtt(p) } {
                            Ok(n) => {
                                let (s, c, d) = narf_acpi::pmtt_counts();
                                let _ = writeln!(console::Writer,
                                    "  acpi: PMTT parsed, {} structures ({} socket, {} ctrl, {} dimm)",
                                    n, s, c, d);
                            }
                            Err(e) => {
                                let _ = writeln!(
                                    console::Writer,
                                    "  acpi: PMTT parse skipped: {:?}",
                                    e
                                );
                            }
                        }
                    }
                    None => {
                        let _ = writeln!(console::Writer, "  acpi: no RSDP found; running flat");
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
                let _ = writeln!(
                    console::Writer,
                    "  bus: PCIe ECAM walk @ {:?} found {} function(s)",
                    ecam,
                    n_dev
                );

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
                    (
                        unsafe { narf_lib::smp::count_x86_64_cpus_via_cpuid() },
                        "CPUID",
                    )
                };
                if n > 0 {
                    narf_lib::smp::set_cpu_count(n);
                }
                let _ = writeln!(
                    console::Writer,
                    "  smp: {} CPU(s) advertised (source: {})",
                    narf_lib::smp::cpu_count(),
                    src
                );

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
                let _ = writeln!(
                    console::Writer,
                    "  smp: started {} AP(s); {} CPU(s) online",
                    started,
                    narf_lib::smp::online_count()
                );
            }
            #[cfg(target_arch = "aarch64")]
            {
                let _ = writeln!(console::Writer, "  mmu: handoff...");
                // SAFETY: BSP, interrupts disabled, allocator populated.
                match unsafe { narf_memory::mmu::init_mmu() } {
                    Ok(ttbr0) => {
                        narf_console::remap_to_virtual(info.uart_virt);
                        let _ = writeln!(
                            console::Writer,
                            "  mmu: installed, TTBR0 @ {:?}, console remapped",
                            ttbr0
                        );
                    }
                    Err(e) => {
                        let _ = writeln!(console::Writer, "  mmu: init failed: {e:?}");
                    }
                }

                // Bus enumeration. The DTB pointer comes through
                // `BootInfo`; if QEMU's `-kernel` path didn't supply
                // one, the walker falls back to the QEMU virt
                // virtio-mmio defaults.
                // SAFETY: DTB blob is in identity-mapped low RAM;
                // reads validate magic before trusting offsets.
                let n_dev = unsafe { narf_bus::init(info.dtb_phys) };
                let devs = narf_bus::devices();
                let n_pcie = devs
                    .iter()
                    .filter(|d| matches!(d.kind, narf_bus::BusKind::Pcie { .. }))
                    .count();
                let n_mmio = devs
                    .iter()
                    .filter(|d| matches!(d.kind, narf_bus::BusKind::VirtioMmio { .. }))
                    .count();
                let _ = writeln!(
                    console::Writer,
                    "  bus: dtb={:?} → {} dev ({} pcie, {} virtio-mmio)",
                    info.dtb_phys,
                    n_dev,
                    n_pcie,
                    n_mmio
                );

                // PCIe BAR self-allocator. NARF on QEMU virt boots
                // via `-kernel` without firmware, so PCIe BARs come
                // up unassigned (read as 0). Initialise the MMIO
                // pool with the QEMU virt PCIe MMIO low window
                // (0x1000_0000 .. 0x3eff_0000 = ~750 MiB) and walk
                // every device to assign + enable BARs before
                // drivers probe.
                narf_bus::init_mmio_pool(0x1000_0000, 0x3eff_0000 - 0x1000_0000);
                let mut bar_assigned_total = 0u32;
                for dev in &devs {
                    if !matches!(dev.kind, narf_bus::BusKind::Pcie { .. }) {
                        continue;
                    }
                    // SAFETY: BSP, exclusive cfg-space access here.
                    if let Ok(n) = unsafe { narf_bus::assign_unprogrammed_bars(dev) } {
                        bar_assigned_total += n;
                    }
                }
                if bar_assigned_total > 0 {
                    let _ = writeln!(
                        console::Writer,
                        "  bus: assigned {} unprogrammed BAR(s) from MMIO pool",
                        bar_assigned_total
                    );
                }

                // GIC ITS bring-up. Memory is online, GICv3 is up
                // (gic::init_bsp ran above). Programs the device /
                // collection / command-queue tables, sets
                // GICR_PROPBASER / GICR_PENDBASER, enables LPIs, then
                // submits MAPC for collection 0 → CPU 0. Idempotent.
                // SAFETY: GICv3 distributor + CPU 0 redistributor are
                // enabled; allocator is online; QEMU virt's ITS lives
                // at the documented MMIO base.
                match unsafe { narf_interrupts::aarch64::its::init_bsp() } {
                    Ok(()) => {
                        let _ = writeln!(
                            console::Writer,
                            "  its: GICv3 ITS up, doorbell @ {:#x}",
                            narf_interrupts::aarch64::its::doorbell_pa()
                        );
                    }
                    Err(e) => {
                        let _ = writeln!(console::Writer, "  its: bring-up failed: {e:?}");
                    }
                }
                // BSP's default SGI handlers (PANIC_HALT, RESCHED).
                narf_interrupts::aarch64::sgi::install_defaults();

                // SMP discovery: count CPUs from the DTB.
                if let Some(p) = info.dtb_phys {
                    // SAFETY: DTB validated by boot/aarch64.
                    let n = unsafe { narf_lib::smp::count_aarch64_cpus_in_dtb(p.raw()) };
                    if n > 0 {
                        narf_lib::smp::set_cpu_count(n);
                    }
                    let _ = writeln!(
                        console::Writer,
                        "  smp: {} CPU(s) advertised",
                        narf_lib::smp::cpu_count()
                    );
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
                let _ = writeln!(
                    console::Writer,
                    "  smp: started {} AP(s); {} CPU(s) online",
                    started,
                    narf_lib::smp::online_count()
                );
            }

            // ── PCIe driver registration + dispatch ───────────────
            // Register every in-tree PCIe driver with the bus
            // match table, then walk the registry binding each
            // discovered device to its driver. Keeps boot-time
            // driver dispatch in one place (kernel-test harness
            // re-runs this per smoke; the boot path establishes
            // the canonical set of drivers).
            // ── Staged init: Linux-style *_initcall registry ────
            //
            // Each subsystem crate exposes `register_initcalls()`
            // which adds its driver bring-ups to the appropriate
            // stage. Frame's role here is just to enumerate the
            // crates once + run every stage in order.
            //
            //   Subsys: input event ring + register_pci_driver chain.
            //   Device: probe_all_pci (binds drivers to discovered
            //           PCIe devices), best-effort PS/2 init.
            //   Late:   FB console install, virtio-gpu splash,
            //           end-of-boot panel.
            // Verbose initcall trace — emits "init: <stage>/<name>
            // ..." before each call and "-> ok|not-present|error"
            // after. Diagnoses kernel hangs that swallow all
            // output by surfacing the *last* initcall name
            // before silence.
            fn _init_log(line: &str) {
                let _ = writeln!(console::Writer, "  {}", line);
            }
            narf_init::set_log_hook(_init_log);
            narf_init::set_verbose_log(true);
            // Per-driver probe trace — same shape as init-log but
            // for the bus walker's per-device dispatch. Surfaces a
            // hung probe by name + (vendor:device) before silence.
            narf_bus::set_probe_log_hook(_init_log);
            narf_bus::set_probe_log(true);

            narf_input::register_initcalls();
            narf_drivers_nvme::register_initcalls();
            narf_drivers_virtio::register_initcalls();
            narf_drivers_net::register_initcalls();
            narf_drivers_wireless::register_initcalls();
            narf_drivers_i3c::register_initcalls();
            narf_drivers_storage::register_initcalls();
            narf_drivers_usb::register_initcalls();
            narf_drivers_platform::register_initcalls();
            narf_graphics_driver::register_initcalls();
            narf_drivers_gpu::register_initcalls();
            narf_input_driver::register_initcalls();
            narf_fb::register_initcalls();
            narf_audio::register_initcalls();
            narf_power::register_initcalls();
            narf_wireless::register_initcalls();
            narf_accel::register_initcalls();
            narf_tpm::register_initcalls();
            narf_i3c::register_initcalls();
            narf_pwm::register_initcalls();
            narf_pmbus::register_initcalls();
            narf_spdm::register_initcalls();
            narf_scmi::register_initcalls();
            narf_shmem::register_initcalls();
            narf_initramfs::register_initcalls();
            narf_filesystem::register_initcalls();
            narf_firmware::register_initcalls();
            narf_firmware_fw_cfg::register_initcalls();
            narf_firmware_smbios::register_initcalls();
            narf_firmware_fdt::register_initcalls();
            // Stage the trusted-loader authority so the
            // `sys_firmware_install` syscall can hot-install blobs
            // from a privileged userspace daemon. The Read half is
            // dropped because the registry's `open()` path is
            // currently in-kernel only; once a per-task cap-table
            // for firmware lookups lands (Stage-7), the Read cap
            // moves into the daemon's bootstrap kit.
            {
                let (write, _read) = narf_firmware::bootstrap_authority();
                narf_firmware::install_trusted_loader_authority(write);
                // Grant task 0 (the kernel boot identity) a per-
                // task firmware-registry authority cap. The
                // sys_firmware_install trap handler picks this
                // cap up via firmware_authority_of(pid). A
                // userspace firmware-load daemon would receive
                // its own grant — typically from this same boot
                // path once the daemon's pid is known, or from
                // a privileged spawn helper.
                let _ = narf_firmware::grant_firmware_authority(0);
            }

            // PCI probe lives in Stage::Device — it binds every
            // driver registered by Subsys above.
            narf_init::register(narf_init::Stage::Device, "pci-probe-all", || {
                let auth = narf_bus::bootstrap_registry_authority();
                match narf_bus::probe_all_pci(&auth) {
                    Ok(n) => {
                        let bound = narf_drivers::bound_drivers();
                        let _ = writeln!(
                            console::Writer,
                            "  drivers: bound {} PCIe device(s); inventory={}",
                            n,
                            bound.len()
                        );
                        for b in &bound {
                            let _ = writeln!(
                                console::Writer,
                                "    {} ({:?}) {:04x}:{:04x}",
                                b.name,
                                b.kind,
                                b.pci_vid.unwrap_or(0),
                                b.pci_did.unwrap_or(0)
                            );
                        }
                        narf_init::InitResult::Ok
                    }
                    Err(_) => narf_init::InitResult::Error("probe_all_pci failed"),
                }
            });

            // Stage::Late initcalls: FB console + virtio-gpu splash.
            narf_init::register(narf_init::Stage::Late, "measured-boot", || {
                narf_scheduler::spawn(async move {
                    let _ = writeln!(
                        console::Writer,
                        "  measured-boot: starting hardware attestation..."
                    );

                    // SAFETY: Single-threaded boot path, statics populated in _start_rust.
                    let (raw, info) = unsafe { (RAW_BOOT_INFO.as_ref(), BOOT_INFO.as_ref()) };

                    // PCR 0: Kernel binary.
                    extern "C" {
                        static __kernel_start: u8;
                        static __kernel_end: u8;
                    }
                    let kstart = core::ptr::addr_of!(__kernel_start) as u64;
                    let kend = core::ptr::addr_of!(__kernel_end) as u64;
                    if let Err(e) = measure::measure_phys(0, "kernel", kstart, kend - kstart).await
                    {
                        let _ = writeln!(
                            console::Writer,
                            "  measured-boot: PCR 0 extend failed: {:?}",
                            e
                        );
                    }

                    // PCR 4: Bootloader handoff.
                    if let Some(r) = raw {
                        if let Err(e) = measure::measure(4, "raw_boot_info", unsafe {
                            core::slice::from_raw_parts(
                                r as *const _ as *const u8,
                                core::mem::size_of::<RawBootInfo>(),
                            )
                        })
                        .await
                        {
                            let _ = writeln!(
                                console::Writer,
                                "  measured-boot: PCR 4 extend failed: {:?}",
                                e
                            );
                        }
                    }

                    // PCR 9: Initramfs.
                    if let Some(r) = info.and_then(|i| i.initramfs) {
                        if let Err(e) =
                            measure::measure_phys(9, "initramfs", r.start.raw(), r.len).await
                        {
                            let _ = writeln!(
                                console::Writer,
                                "  measured-boot: PCR 9 extend failed: {:?}",
                                e
                            );
                        }
                    }

                    // PCR 10: Peripheral Firmware (SPDM).
                    let spdm_devices = narf_spdm::registry::list();
                    for device in spdm_devices {
                        if let Err(e) =
                            measure::measure_device(10, "spdm_device", device.as_ref()).await
                        {
                            let _ = writeln!(
                                console::Writer,
                                "  measured-boot: SPDM attestation failed: {:?}",
                                e
                            );
                        }
                    }

                    // Log completion.

                    let log = measure::get_log();
                    let _ = writeln!(
                        console::Writer,
                        "  measured-boot: {} components anchored in hardware",
                        log.len()
                    );
                });
                narf_init::InitResult::Ok
            });

            #[cfg(target_arch = "x86_64")]
            narf_init::register(narf_init::Stage::Late, "fb-console-install", || {
                use narf_graphics::{FbConsole, Pixel32};
                let r = narf_graphics_driver::bochs::with_controller(|d| {
                    if !d.fb_reachable() {
                        let _ = writeln!(
                            console::Writer,
                            "  splash: bochs framebuffer at {:#x} above 4 GiB \
                             identity map; deferred until ioremap lands",
                            d.fb_phys()
                        );
                        return false;
                    }
                    // SAFETY: BSP, no concurrent draw.
                    let fb = unsafe { d.framebuffer() };
                    let con = FbConsole::new(fb, Pixel32::NARF_FG, Pixel32::NARF_BG);
                    let (cols, rows) = (con.cols(), con.rows());
                    narf_graphics::install_fb_console(con);
                    console::set_fb_hook(narf_graphics::console::write_bytes);
                    let _ = writeln!(
                        console::Writer,
                        "  splash: {}x{} bochs framebuffer console installed \
                         ({} cols x {} rows of 8x8 glyphs)",
                        cols * 8,
                        rows * 8,
                        cols,
                        rows
                    );
                    true
                });
                match r {
                    Some(true) => narf_init::InitResult::Ok,
                    Some(false) => narf_init::InitResult::NotPresent,
                    None => narf_init::InitResult::NotPresent,
                }
            });

            narf_init::register(narf_init::Stage::Late, "virtio-gpu-splash", || {
                use narf_graphics::Pixel32;
                let painted = narf_drivers_virtio::gpu_pci::with_controller_mut(|d| {
                    // SAFETY: BSP, post-bring_up.
                    if !d.ready {
                        if let Err(e) = unsafe { d.init_scanout() } {
                            let _ = writeln!(
                                console::Writer,
                                "  splash: virtio-gpu init_scanout failed: {:?}",
                                e
                            );
                            return (0u32, 0u32);
                        }
                    }
                    // SAFETY: BSP, no concurrent draw.
                    let mut fb = unsafe { d.framebuffer() };
                    let half = 16u32;
                    fb.fill_rect(0, 0, half, half, Pixel32::RED);
                    fb.fill_rect(half, 0, half, half, Pixel32::GREEN);
                    fb.fill_rect(0, half, half, half, Pixel32::BLUE);
                    fb.fill_rect(half, half, half, half, Pixel32::NARF_FG);
                    // SAFETY: bring_up complete.
                    let _ = unsafe { d.flush() };
                    (d.mode.width, d.mode.height)
                });
                match painted {
                    Some((w, h)) if w > 0 => {
                        let _ = writeln!(
                            console::Writer,
                            "  splash: {}x{} virtio-gpu scanout painted (4-quadrant)",
                            w,
                            h
                        );
                        narf_init::InitResult::Ok
                    }
                    _ => narf_init::InitResult::NotPresent,
                }
            });

            // Run every stage in order, then print the per-stage
            // summary (call counts + cycles) to console + (after
            // Stage::Late, since fb-console-install lives there)
            // the framebuffer.
            let _ = narf_init::run_all_through(narf_init::Stage::Late);
            let _ = narf_init::print_summary(&mut console::Writer);
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
        unsafe {
            core::arch::asm!("ud2", options(noreturn));
        }
    }

    // End-of-boot splash. Composes a one-screen "kernel up" panel
    // through the framebuffer console: title bar + invariants + the
    // arrow cursor centred over everything. Visible when QEMU runs
    // with a display backend (`-display gtk` / `-vnc :1`); under
    // `-display none` it still paints into FB memory but isn't
    // rendered to a host window.
    #[cfg(target_arch = "x86_64")]
    {
        let arch_str = "x86_64";
        let backend = match narf_arch::effective_backend() {
            narf_arch::DomainBackend::Pks => "pks",
            narf_arch::DomainBackend::Mte => "mte",
            narf_arch::DomainBackend::Pcid => "pcid",
            narf_arch::DomainBackend::Sfi => "sfi",
        };
        let cpu_count = narf_lib::smp::cpu_count() as u32;
        let numa_nodes = if narf_memory::is_numa_aware() {
            (0..narf_memory::FRAME_MAX_NUMA_NODES)
                .filter(|&i| narf_memory::node_free(i) > 0)
                .count() as u32
        } else {
            1
        };
        let bound = narf_drivers::bound_drivers().len() as u32;
        let info = narf_graphics::BootInfo {
            arch: arch_str,
            version: env!("CARGO_PKG_VERSION"),
            cpu_count,
            numa_nodes,
            bound_drivers: bound,
            backend,
        };
        if narf_graphics::render_splash(&info) {
            let _ = writeln!(
                console::Writer,
                "  splash: end-of-boot panel composed ({} drivers, {} cpus, {} nodes)",
                bound,
                cpu_count,
                numa_nodes
            );
        }
    }

    // Run the kernel-test harness instead of the async demo when the
    // `kernel-test` feature is on. `run_all_and_exit` never returns.
    #[cfg(feature = "kernel-test")]
    {
        narf_verification::run_all_and_exit();
    }

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
            narf_interrupts::aarch64::start_timer(aarch64::trap::TIMER_TVAL_DEFAULT);
            narf_arch::enable_interrupts();
        }
        let _ = writeln!(
            console::Writer,
            "  gic: generic timer started, IRQs unmasked"
        );
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
            narf_interrupts::x86_64::apic::start_timer(narf_interrupts::VECTOR_TIMER, 1_000_000);
            narf_arch::enable_interrupts();
        }
        let _ = writeln!(
            console::Writer,
            "  apic: LAPIC timer live on vector {}, IRQs unmasked",
            narf_interrupts::VECTOR_TIMER
        );
    }

    narf_scheduler::init();
    let _ = writeln!(console::Writer, "  scheduler: ready queue initialised");

    #[cfg(feature = "boot-init")]
    boot_userspace_init();

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
            let _ = writeln!(
                console::Writer,
                "  tick {}: elapsed {} Mcycles",
                n,
                elapsed / 1_000_000
            );
            narf_scheduler::yield_now().await;
        }
        let _ = writeln!(console::Writer, "  async demo: done");
    });

    let _ = writeln!(
        console::Writer,
        "  scheduler: spawning 1 task, running to completion"
    );
    narf_scheduler::run_until_empty();

    let _ = writeln!(
        console::Writer,
        "  heap used: {} / {} bytes",
        narf_memory::heap::used_bytes(),
        narf_memory::heap::capacity_bytes()
    );
    #[cfg(target_arch = "x86_64")]
    {
        let ticks = narf_interrupts::x86_64::apic::timer_ticks();
        let _ = writeln!(console::Writer, "  timer IRQs delivered: {} ticks", ticks);
    }
    #[cfg(target_arch = "aarch64")]
    {
        let ticks = narf_interrupts::aarch64::timer_ticks();
        let _ = writeln!(console::Writer, "  timer IRQs delivered: {} ticks", ticks);
    }
    let _ = writeln!(
        console::Writer,
        "  halting — Stage 1 exit-gate demo complete."
    );

    // SAFETY: exit_kernel is infallible; on QEMU it exits cleanly via
    // the isa-debug-exit device (x86_64) or semihosting (aarch64); on
    // real hardware it falls back to a quiet halt.
    unsafe { narf_arch::exit_kernel(0) }
}

/// Production boot of `userspace/init`. Sets up the syscall surface,
/// the per-task subsystem stores, the address-space lookup the
/// in-syscall handlers consult, then loads the verified
/// `NARF_INIT_ELF` and spawns it on the scheduler as a
/// `UserTaskFuture`.
///
/// Called from `run_async_demo` only when the `boot-init` feature
/// is enabled. `kernel-test` builds route through
/// `narf_verification::run_all_and_exit()` instead, so this fn
/// never fires under `cargo xtask test`.
#[cfg(all(feature = "boot-init", target_arch = "x86_64"))]
fn boot_userspace_init() {
    use core::fmt::Write as _;
    use narf_userspace::{
        bootstrap_init, brk_init, cwd_init, install_address_space_lookup,
        install_core_syscalls, install_global, install_task_id_lookup,
        install_user_task_hooks, load_user_process_with, sigaction_init, signal_init,
        SyscallTable, UserTaskFuture,
    };

    let bytes = narf_verification::NARF_INIT_ELF;
    if bytes.is_empty() {
        let _ = writeln!(
            console::Writer,
            "  boot-init: NARF_INIT_ELF is empty — skipping init load"
        );
        return;
    }

    // Per-task subsystem stores. Idempotent — fine to call once.
    bootstrap_init();
    brk_init();
    cwd_init();
    sigaction_init();
    signal_init();
    narf_userspace::fd::init();

    // Syscall table.
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // The handlers reach `current_task_id()` then look up its
    // address space — this lookup goes through the scheduler's
    // ready-queue scan.
    install_address_space_lookup(|| {
        let id = narf_scheduler::current_task_id();
        narf_scheduler::address_space_of(id)
    });
    // Make `gettid` (and any handler that calls
    // `current_task_id`) report the scheduler's TaskId rather
    // than 0. Required for `sys_clone` to be observable from user
    // code via `gettid()` returning distinct values per thread.
    install_task_id_lookup(|| narf_scheduler::current_task_id().raw());

    // Hooks the trap path needs to longjmp from int 0x80 back into
    // the cooperative executor.
    install_user_task_hooks();

    // Parse + map the ELF into a fresh AddressSpace. We pass a
    // single-element argv (`["init"]`) so the SysV-AMD64 stack
    // gets a real `argc | argv[0] | NULL | NULL | AT_NULL` frame
    // laid down — the bare `load_user_process` shape (no args)
    // leaves rsp one past the mapped stack region, which traps
    // the first `read [rsp]` inside `__libc_start_main`.
    //
    // SAFETY: the boot identity map covers low 4 GiB, the frame
    // allocator was initialised earlier in `_start_rust`.
    let proc = match unsafe { load_user_process_with(bytes, &["init"], &[], &[]) } {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(
                console::Writer,
                "  boot-init: load_user_process_with failed: {e:?}"
            );
            return;
        }
    };
    let pid = proc.pid;
    let addr_space = proc.address_space.clone();

    let _ = writeln!(
        console::Writer,
        "  boot-init: spawning init pid={} entry={:#x}",
        pid.raw(),
        proc.entry.0.as_u64()
    );

    let _id = narf_scheduler::spawn_user(
        UserTaskFuture::new(proc),
        narf_scheduler::TaskSpec::unthrottled(),
        addr_space,
    );
}

/// aarch64 stub. The user-mode-entry / IRET-equivalent + EL0 trap
/// vector wiring (`narf_scheduler::enter_user_mode` on aarch64) is
/// not on the Stage-3 path yet — the scheduler-side comment at
/// `scheduler/src/lib.rs:362` flags `addr_space.activate()` as
/// returning `NotImplemented` on aarch64. Until that lands, this
/// is a no-op so a `cargo xtask run --arch=aarch64 --features
/// boot-init` build still links.
#[cfg(all(feature = "boot-init", not(target_arch = "x86_64")))]
fn boot_userspace_init() {
    use core::fmt::Write as _;
    let _ = writeln!(
        console::Writer,
        "  boot-init: aarch64 user-mode entry not yet wired"
    );
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    console::panic_sink(info)
}
