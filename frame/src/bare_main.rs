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
extern crate narf_security as _;
extern crate narf_drivers_fs_ext2;
extern crate narf_drivers_fs_fat;
extern crate narf_drivers_fs_exfat as _;
extern crate narf_drivers_fs_minix as _;
extern crate narf_drivers_fs_iso9660 as _;
extern crate narf_drivers_fs_udf as _;
extern crate narf_drivers_fs_9p as _;
extern crate narf_edid as _;
extern crate narf_efi as _;
extern crate narf_hid as _;
extern crate narf_pinctrl as _;
extern crate narf_drivers_psp as _;

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

mod canary;
mod cross_crate_init;
mod measure;
mod secure_boot;

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

/// Install the framebuffer console early (right after MMU init)
/// so subsequent kernel logs and panics paint to the laptop
/// screen rather than only to serial. Best-effort: skips with a
/// diagnostic line on serial if the FB phys is above the 4 GiB
/// identity map, the pixel format isn't packed RGB, or the FB
/// driver layer isn't ready.
///
/// On success, every later `console::Writer` write fans out to
/// both UART and the FB via the hook installed in
/// `console::set_fb_hook`. The Stage::Late `fb-console-install`
/// initcall remains in place; it re-binds the hook to whichever
/// scanout `narf_fb::select_active()` picks (potentially a real
/// GPU driver instead of the bootloader-supplied generic FB).
fn try_install_early_fb_console(fb_info: narf_boot::info::FramebufferInfo) {
    use narf_graphics::{FbConsole, Pixel32};

    // Identity map covers 0..=4 GiB. UEFI sometimes maps the GOP
    // FB above 4 GiB; defer those to the Late install path which
    // runs after `ioremap`-style high-mem mapping.
    let phys = fb_info.addr.raw();
    let end = phys.saturating_add(fb_info.height as u64 * fb_info.pitch as u64);
    if end > (4u64 << 30) {
        let _ = writeln!(
            console::Writer,
            "  early-fb: skipping — FB at {:#x} above 4 GiB identity map",
            phys
        );
        return;
    }

    // The bootloader gave us an FB. Wrap it in a generic scanout
    // and ask narf_fb to surface it. select_active() then returns
    // the generic-fb scanout (we registered it earlier).
    let scanout = match narf_fb::select_active() {
        Some(s) => s,
        None => {
            let _ = writeln!(
                console::Writer,
                "  early-fb: skipping — no scanout registered"
            );
            return;
        }
    };
    // Mark the FB phys range Write-Combining via MTRR so the
    // memmove on scroll (one full screen worth of u32 writes per
    // newline) doesn't run at uncached-MMIO speed (~150 ns/write,
    // ~1 row per second on real-HW UEFI GOP). WC turns those
    // writes into burst transactions and shaves the scroll cost
    // by ~10×.
    //
    // The variable-MTRR window must be a power of two ≥ FB size,
    // aligned to its own size. The FB phys (UEFI GOP) is
    // typically already aligned to 64 KiB or better; we round
    // the size up to the next power-of-two ≥ end-phys. The MTRR
    // may then cover ~2× the FB extent — benign because the post-
    // FB phys is OS-reserved memory we manage.
    let fb_size = end.saturating_sub(phys);
    let pow2 = fb_size.next_power_of_two().max(0x100_000); // ≥ 1 MiB
    // Align phys down to the pow2 boundary so the MTRR window
    // fully covers the FB. The slop below `phys` is also OS-
    // managed reserved.
    let mtrr_phys = phys & !(pow2 - 1);
    // SAFETY: CPL=0; phys + size point at a UEFI-claimed GOP FB.
    // The MTRR program runs before any cacheable mapping spans
    // this window (we're pre-MMU-rebind here in the early-FB
    // path).
    let wc_slot = unsafe { narf_arch::x86_64::mtrr::set_write_combining(mtrr_phys, pow2) };
    let _ = wc_slot;

    // SAFETY: BSP, no concurrent draw; FB phys is identity-mapped
    // (verified above to be < 4 GiB).
    let fb = unsafe { scanout.framebuffer() };
    let con = FbConsole::new(fb, Pixel32::NARF_FG, Pixel32::NARF_BG);
    let (cols, rows) = (con.cols(), con.rows());
    narf_graphics::install_fb_console(con);
    console::set_fb_hook(narf_graphics::console::write_bytes);
    let _ = writeln!(
        console::Writer,
        "  early-fb: console installed via {} ({}x{} → {}x{} chars; wc-mtrr={:?})",
        scanout.name(),
        fb_info.width,
        fb_info.height,
        cols,
        rows,
        wc_slot,
    );
}

/// Parse `stop_at=<stage>` and `safe_mode[=...]` from a kernel
/// command-line. Returns the highest stage that should run; defaults
/// to `Stage::Late` (run everything). Unknown stage names fall back
/// to `Stage::Late` with no error — diagnostics-only.
/// Parse `key=N` out of cmdline, returning N as `usize`. Used by
/// the hugepage pre-reservation path for `hugepages_2m=N` and
/// `hugepages_1g=N`. Returns 0 if absent or malformed — the
/// hugepage path treats 0 as "no reservation".
fn parse_cmdline_count(cmdline: &str, key: &str) -> usize {
    for tok in cmdline.split_ascii_whitespace() {
        if let Some((k, v)) = tok.split_once('=') {
            if k == key {
                return v.parse().unwrap_or(0);
            }
        }
    }
    0
}

fn parse_stop_at(cmdline: &str) -> narf_init::Stage {
    use narf_init::Stage;
    let mut last = Stage::Late;
    for tok in cmdline.split_ascii_whitespace() {
        let (key, val) = match tok.split_once('=') {
            Some((k, v)) => (k, v),
            None => (tok, ""),
        };
        match key {
            "stop_at" => {
                let s = match val {
                    "early" => Stage::Early,
                    "core" => Stage::Core,
                    "postcore" => Stage::PostCore,
                    "arch" => Stage::Arch,
                    "subsys" => Stage::Subsys,
                    "fs" => Stage::Fs,
                    "device" => Stage::Device,
                    "late" => Stage::Late,
                    _ => continue,
                };
                if (s as u8) < (last as u8) {
                    last = s;
                }
            }
            "safe_mode" => {
                // Stop after Subsys: the kernel core, drivers
                // registry, ACPI, MMU + heap are up; PCI probe,
                // FS mount, FB-console, and userspace spawn are
                // all skipped.
                if (Stage::Subsys as u8) < (last as u8) {
                    last = Stage::Subsys;
                }
            }
            _ => {}
        }
    }
    last
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start_rust(raw: RawBootInfo) -> ! {
    // Boot beacons (left-to-right, top-left of FB). Each lit
    // slot proves we passed that stage. See `boot_beacon` doc.
    //   slot 0 RED    — _start_rust entered
    //   slot 1 ORANGE — UART init done
    //   slot 2 PURPLE — about to call parse_raw
    //   slot 3 BLUE   — parse_raw returned (Ok or Err)
    //   slot 4 YELLOW — parse_raw Ok branch
    //   slot 5 WHITE  — parse_raw Err branch (sad path)
    //   slot 6 GREEN  — frame allocator init done
    //   slot 7 CYAN   — MMU init done
    #[cfg(target_arch = "x86_64")]
    let _early_fb: Option<narf_boot::info::FramebufferInfo> = {
        if raw.magic == narf_boot::x86_64::multiboot2::BOOT_MAGIC {
            // SAFETY: bootloader contract; payload is the mb2 info struct.
            let info_ptr = raw.payload.raw() as usize;
            let fb = unsafe { narf_boot::x86_64::multiboot2::framebuffer(info_ptr) };
            if let Some(ref fb_info) = fb {
                // Register the FB for any code that wants to paint
                // boot beacons (including init_mmu deep in the
                // memory crate). Stride in pixels = pitch / bytes-
                // per-pixel. Phys ceiling = 4 GiB to match boot.S
                // identity map.
                let stride_px = (fb_info.pitch as u32) / ((fb_info.bpp as u32).max(8) / 8);
                narf_memory::beacon::register(
                    fb_info.addr.raw(),
                    stride_px,
                    fb_info.width,
                    fb_info.height,
                    4u64 << 30,
                );
                // BUILD MARKER v4: a SOLID 32-px-tall PURPLE bar
                // across the entire top of the screen. Painted
                // before any per-slot beacon. If you don't see
                // purple covering the whole top edge, this build
                // isn't running.
                narf_memory::beacon::paint_build_stripe(0x00800080); // PURPLE
                narf_memory::beacon::paint(0, 0x0000FFFF); // CYAN — _start_rust alive
                // Wire arch-side beacon hook to memory beacon
                // facility so arch code (pcid::enable_pcide etc.)
                // can paint without depending on memory.
                narf_arch::set_beacon_hook(narf_memory::beacon::paint);
            }
            fb
        } else {
            None
        }
    };

    // Step 1: bring up the early serial console before doing anything else,
    // so any failure from here on is visible.
    #[cfg(target_arch = "x86_64")]
    {
        // 16550A COM1 at I/O port 0x3F8 — hard-coded default. Real detection
        // lands with the ACPI/FDT parse in Wave 2.
        console::early_init(PhysAddr::new(0x3F8), UartKind::Uart16550);
                    narf_memory::beacon::paint(1, 0x00FF_8000); // ORANGE
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

        // EFER.NXE — make PTE bit 63 mean "no execute" instead of
        // reserved. Defensive against firmware paths (some real
        // Phoenix/Renoir UEFI fast-paths) that skip Limine's NXE
        // setup. Without this, every user data/stack PTE with
        // NO_EXEC=1 triggers a reserved-bit #PF on first access
        // (QEMU TCG is lax about this; real silicon isn't).
        // SAFETY: CPL=0, pre-userspace, idempotent if already set.
        unsafe {
            narf_arch::x86_64::msr::enable_nxe();
        }

        // PAT — program IA32_PAT so PA1 = WC (Linux convention).
        // After this, any future PTE with PWT=1 maps that page
        // write-combining. The early-FB-console install path
        // doesn't use this yet (it runs before MMU rebind), but
        // the Stage::Late `fb-wc-remap` initcall ioremaps the FB
        // at a fresh WC virt for fast console scroll. Other
        // drivers (GPU command rings, etc.) can also opt-in via
        // `MmioAttrs::WriteCombining`.
        // SAFETY: CPL=0, single-threaded boot, before any
        // cacheable mapping spans a region we're changing.
        let _ = unsafe { narf_arch::x86_64::pat::init_default() };

        // Baseline CPU validation. Reads CPUID + CR4 + EFER and
        // refuses to proceed only if a TRULY required bit is off
        // (long-mode, NX, EFER.LME/NXE, CR4.PAE). Other bits get
        // logged + beacon-painted but don't gate boot — they're
        // useful diagnostics, not preconditions. The narrower
        // gate avoids halting on kernel-test QEMU profiles that
        // don't expose Invariant TSC or some CR4 enables.
        // SAFETY: CPL=0; validate() reads CPUID + RDMSR.
        let cpuval = unsafe { narf_arch::x86_64::cpu_validate::validate() };
        let fatal: Option<&'static str> = if !cpuval.long_mode {
            Some("CPUID: Long Mode missing")
        } else if !cpuval.nx {
            Some("CPUID: NX missing")
        } else if !cpuval.efer_lme_on {
            Some("EFER.LME not enabled")
        } else if !cpuval.efer_nxe_on {
            Some("EFER.NXE not enabled (after enable_nxe — wrmsr was rejected?)")
        } else if !cpuval.cr4_pae_on {
            Some("CR4.PAE not enabled")
        } else {
            None
        };
        let _ = writeln!(
            console::Writer,
            "  cpu-validate: NX={} SMEP={}/{} SMAP={}/{} OSXSAVE={}/{} \
             EFER.LME={} EFER.NXE={} CR4.PAE={} fsgsbase={} invariant_tsc={}",
            cpuval.nx,
            cpuval.smep, cpuval.cr4_smep_on,
            cpuval.smap, cpuval.cr4_smap_on,
            cpuval.xsave, cpuval.cr4_osxsave_on,
            cpuval.efer_lme_on,
            cpuval.efer_nxe_on,
            cpuval.cr4_pae_on,
            cpuval.cr4_fsgsbase_on,
            cpuval.invariant_tsc,
        );
        match fatal {
            None => {
                // Slot 31 = baseline ok. Stays lit through the
                // whole boot so a glance at the row confirms the
                // gate passed.
                narf_memory::beacon::paint(31, 0x0000FF80); // bright green
            }
            Some(why) => {
                let _ = writeln!(
                    console::Writer,
                    "  cpu-validate: FATAL — {}", why
                );
                // Slot 31 = baseline fail (bright red). Halt with
                // CLI+HLT loop so the operator sees the message
                // + beacon instead of crashing into a userspace
                // fault five stages later.
                narf_memory::beacon::paint(31, 0x00FF0000); // bright red
                #[allow(clippy::empty_loop)]
                loop {
                    // SAFETY: CLI + HLT at CPL=0 is the canonical
                    // "stop here, IRQ-quiet" idle.
                    unsafe {
                        core::arch::asm!("cli; hlt", options(nomem, nostack));
                    }
                }
            }
        }
    }

    // PaX-style security init — runs before any user-mode entry and
    // before the first task spawn. Order is sensitive: SMEP/SMAP both
    // depend on CR4 being writable (CPL=0, post-paging), KPTI detect
    // depends on CPUID + IA32_ARCH_CAPABILITIES, canary depends on the
    // RDRAND/RDSEED probe. Doing it here (post cpu_validate, pre
    // Features::probe / domain bring-up) gives all of those a stable
    // foundation. Per security-hardening doctrine: do not gate behind
    // a runtime knob — SMEP/SMAP are mandatory floors.
    #[cfg(target_arch = "x86_64")]
    {
        use narf_arch::x86_64::{kpti, smap, smep};

        // SMEP — fault on instruction fetch from a U=1 page at CPL=0.
        // No-op if CPU doesn't advertise; otherwise flip CR4.20.
        if smep::supported() {
            // SAFETY: SMEP supported; flipping CR4.20 has no other
            // prerequisite at CPL=0 post-paging.
            unsafe { smep::enable(); }
        }
        // SMAP — fault on data access to a U=1 page from CPL=0 outside
        // an EFLAGS.AC bracket. Same shape.
        if smap::supported() {
            // SAFETY: SMAP supported; CR4.21 flip is benign here.
            unsafe { smap::enable(); }
        }
        // KPTI detect — Renoir + Phoenix come back Posture::Native and
        // we skip the dual-CR3 dance entirely. Log the decision once.
        let pti = kpti::detect();
        let _ = writeln!(
            console::Writer,
            "  hardening: SMEP={} SMAP={} KPTI={:?}",
            smep::is_enabled(),
            smap::is_enabled(),
            pti,
        );

        // Initialise the global stack canary from RDRAND/RDSEED.
        // Subsequent stack-protected functions will see a real value
        // instead of the static-init sentinel.
        canary::init_global_canary();

        // Populate the global PostureReport so observability has a
        // single source of truth for "which hardening knobs are live".
        {
            use core::sync::atomic::Ordering;
            let p = &narf_security::posture::REPORT;
            p.smep.store(smep::is_enabled(), Ordering::Release);
            p.smap.store(smap::is_enabled(), Ordering::Release);
            p.kpti.store(
                match pti {
                    kpti::Posture::Native => narf_security::posture::Posture::Native.as_byte(),
                    kpti::Posture::Isolate => narf_security::posture::Posture::Isolate.as_byte(),
                },
                Ordering::Release,
            );
            // KASLR and canary always ran. W^X is enforced by the
            // mmap/mprotect layer (compile-time / runtime). ro_after_init
            // is set once we cross mark_init_complete().
            p.kaslr.store(true, Ordering::Release);
            p.canary.store(true, Ordering::Release);
            p.w_xor_x.store(true, Ordering::Release);
        }
    }

    // Stage 2 feature probe. Print what the CPU supports; gate
    // per-feature enables on explicit CPUID presence so the kernel
    // boots on pre-PKS / pre-UIPI hardware (with degraded behaviour
    // in later stages rather than a boot panic).
    #[cfg(target_arch = "x86_64")]
    {
        // Fine-grained early-boot beacons (slots 22+ are
        // diagnostic, used to localize hangs between ORANGE and
        // PURPLE on real HW).
        narf_memory::beacon::paint(22, 0x00FFA500); // amber: post-orange / pre-features
        // SAFETY: CPUID is always legal at CPL=0.
        let feats = unsafe { narf_arch::x86_64::Features::probe() };
        narf_memory::beacon::paint(23, 0x00FFB347); // peach: CPUID done
        let _ = writeln!(
            console::Writer,
            "  features: nx={} tsc_inv={} pku={} pks={} uipi={} rdseed={} rdrand={} hybrid={}",
            feats.nx,
            feats.invariant_tsc,
            feats.pku,
            feats.pks,
            feats.uipi,
            feats.rdseed,
            feats.rdrand,
            feats.hybrid
        );
        narf_memory::beacon::paint(24, 0x0000FF80); // mint: features-writeln OK

        // Record the BSP's hybrid CPU type. CPUID leaf 0x1A
        // EAX[31:24] is per-LP — APs populate their own slots
        // during _ap_start_rust. Gated on the Hybrid feature bit so
        // we don't read leaf 0x1A on silicon that doesn't define
        // it (returns zero anyway, which decodes to Unknown — the
        // gate is purely to skip the extra CPUID for the AMD /
        // pre-Alder-Lake common case).
        //
        // SAFETY: BSP logical id is 0 (TSC_AUX defaults to 0 and
        // we don't write it on the BSP). CPUID at CPL=0 is always
        // legal. The set_cpu_type / read_hybrid_cpu_type pair is
        // documented as "must run on the CPU whose slot you're
        // writing" — we're on the BSP writing slot 0.
        let bsp_cpu_type = if feats.hybrid {
            // SAFETY: CPUID legal at CPL=0.
            let raw = unsafe { narf_arch::x86_64::cpuid::read_hybrid_cpu_type() };
            narf_lib::percpu::CpuType::from_raw(raw)
        } else {
            narf_lib::percpu::CpuType::Unknown
        };
        narf_lib::percpu::set_cpu_type(0, bsp_cpu_type);

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
            narf_memory::beacon::paint(25, 0x0000FFC0); // aqua: pre-PCID
            unsafe {
                narf_arch::x86_64::pcid::enable_pcide();
                narf_arch::x86_64::pcid::init();
            }
            narf_memory::beacon::paint(21, 0x0040FFC0); // pale-cyan: PCID init done
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
            narf_memory::beacon::paint(27, 0x0080FFC0); // sea-green: pre-PML4 loop
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

        // CPU identification + per-silicon errata application.
        // Errata table covers Zen 1 1474, Zen 2 Zenbleed
        // (CVE-2023-20593), Zen 4 1485, plus a Zen 5 detection
        // marker. apply_for_current_cpu walks the table and
        // applies every entry whose vendor/family/model/stepping
        // match the BSP. Idempotent — APs call the same function
        // from `_ap_start_rust`.
        let cpu = narf_arch::x86_64::ident::read();
        let brand = narf_arch::x86_64::ident::brand_str(&cpu);
        let _ = writeln!(
            console::Writer,
            "  cpu: {} (vendor {:?}, family {:#x}, model {:#x}, stepping {})",
            brand, cpu.vendor, cpu.family, cpu.model, cpu.stepping
        );
        // SAFETY: CPL=0; per-entry SAFETY notes apply; gated by
        // vendor/family/model match.
        let (applied, n) = unsafe { narf_arch::x86_64::errata::apply_for_current_cpu() };
        if n == 0 {
            let _ = writeln!(console::Writer, "  errata: no entries matched this CPU");
        } else {
            let _ = writeln!(console::Writer, "  errata: applied {} entries:", n);
            for e in &applied[..n] {
                let _ = writeln!(console::Writer, "    - {}", e);
            }
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
                // tag=0 → handler uses plain INVLPG (this hook fires
                // from kernel-side mapping mutations that don't know
                // which PCID owns the entry).
                unsafe {
                    narf_interrupts::x86_64::ipi::shoot_va(va, 0);
                }
            });
            // Range hook: one IPI for a contiguous run of pages.
            narf_memory::paging::set_range_shootdown_hook(|va, pages| {
                // SAFETY: x2APIC online, IPI handler installed.
                unsafe {
                    narf_interrupts::x86_64::ipi::shoot_range(va, pages, 0);
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

    narf_memory::beacon::paint(2, 0x00FF_00FF); // PURPLE: pre-parse_raw

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

            narf_memory::beacon::paint(3, 0x0000_00FF); // BLUE: parse_raw returned

    match boot_result {
        Ok(info) => {
            // SAFETY: Single-threaded boot path.
            unsafe {
                RAW_BOOT_INFO = Some(raw);
                BOOT_INFO = Some(info.clone());
            }
                            narf_memory::beacon::paint(4, 0x00FF_FF00); // YELLOW: Ok branch
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

            // Hugepage pre-reservation: parse cmdline `hugepages_2m=N`
            // and `hugepages_1g=N`; carve naturally-aligned chunks
            // out of the usable regions BEFORE the buddy gets them.
            // Whatever's left (head misalignment + tail of each
            // region) is donated to the buddy via init_from_map.
            let want_2m = parse_cmdline_count(narf_boot::cmdline(), "hugepages_2m");
            let want_1g = parse_cmdline_count(narf_boot::cmdline(), "hugepages_1g");
            let huge_excludes = if want_2m > 0 || want_1g > 0 {
                narf_memory::hugepage::reserve_from_regions(&regions, want_2m, want_1g)
            } else {
                alloc::vec::Vec::new()
            };
            let mut excludes: alloc::vec::Vec<(u64, u64)> =
                alloc::vec::Vec::with_capacity(1 + huge_excludes.len());
            excludes.push((kstart, kend));
            excludes.extend(huge_excludes.iter().copied());

            // SAFETY: first call, BSP, memory map came from parse_raw
            // which validated magic + min-RAM.
            unsafe {
                narf_memory::init_from_map(&regions, &excludes);
            }
                            narf_memory::beacon::paint(6, 0x0000_FF00); // GREEN: frame alloc

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
                // Pre-init_mmu beacon (slot 8: dim red).
                                    narf_memory::beacon::paint(8, 0x00800000);
                // SAFETY: BSP, interrupts disabled (boot.S CLI + IDT
                // doesn't unmask), allocator populated above.
                match unsafe { narf_memory::mmu::init_mmu() } {
                    Ok(pml4) => {
                        // Post-init_mmu beacon (slot 9: dim green —
                        // init_mmu returned, but CR3 is now using the
                        // new PML4. If we see this but not the next
                        // remap_to_virtual print, something between
                        // CR3 swap and serial output is wedged.
                                                    narf_memory::beacon::paint(9, 0x00008000);
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
                                                    narf_memory::beacon::paint(7, 0x0000_FFFF); // CYAN: MMU

                        // Real-HW bring-up aid: install the FB
                        // console NOW, not at Stage::Late. Without
                        // this, a boot hang anywhere between MMU
                        // init and Late shows nothing on the laptop
                        // screen (only on serial) — a black screen
                        // is the worst possible bring-up signal.
                        // The Late `fb-console-install` call will
                        // re-bind to the active scanout (potentially
                        // virtio-gpu / amdgpu) once those drivers
                        // attach, but for now we want anything that
                        // panics during ACPI/SMP/PCI to land on
                        // screen via the bootloader-provided generic
                        // FB.
                        if let Some(fb_info) = info.framebuffer {
                            try_install_early_fb_console(fb_info);
                        }
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
                        // SRAT is informational (NUMA topology) — its
                        // absence is *normal* for single-socket boxes
                        // (most laptops, including the UM425I bring-up
                        // target). Slab promotion must NOT be gated on
                        // it; otherwise a no-SRAT host runs the whole
                        // boot on the 8 MiB bootstrap arena and panics
                        // with a 16-byte alloc failure once the AML
                        // walk + Stage::Device probes catch up.
                        match unsafe { narf_acpi::parse_srat(p) } {
                            Ok(n) => {
                                narf_memory::beacon::paint(15, 0x0080_FF40); // LIME: ACPI parsed
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
                            }
                            Err(e) => {
                                let _ = writeln!(
                                    console::Writer,
                                    "  acpi: SRAT parse skipped: {:?} (single-NUMA-node fallback)",
                                    e
                                );
                            }
                        }
                        // Slab promotion runs unconditionally — it
                        // only needs the buddy alive (init_from_map
                        // already ran), not NUMA topology.
                        {
                            narf_memory::reserve_for_slab_promotion();
                            let _ = writeln!(
                                console::Writer,
                                "  heap: promoting bump→slab (bootstrap used: {} / {} bytes)",
                                narf_memory::heap::used_bytes(),
                                narf_memory::heap::capacity_bytes()
                            );
                            narf_memory::heap::promote_to_slab();
                            let _ = writeln!(
                                console::Writer,
                                "  heap: slab is live"
                            );
                            let n_nodes = narf_acpi::node_count().max(1) as usize;
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
                                "  frames: {} per-node total; slab live",
                                totals
                            );
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
                        // FADT power-management surface — needed for
                        // ACPI reboot (RESET_REG) + S5 power-off
                        // (PM1a/b CNT). Parsing here populates the
                        // narf_acpi::FADT_PM cache that
                        // narf_power::system::reboot/power_off
                        // consult.
                        // SAFETY: same.
                        match unsafe { narf_acpi::parse_fadt_pm(p) } {
                            Ok(pm) => {
                                let _ = writeln!(
                                    console::Writer,
                                    "  acpi: FADT PM parsed (RESET {:#x} = {:#x}, PM1a_CNT {:#x})",
                                    pm.reset_reg_addr, pm.reset_value, pm.pm1a_cnt
                                );
                                // Arm the power-button enable bit so
                                // PM1.PWRBTN sets reliably when the
                                // user presses the chassis power
                                // switch. Polling-side handler
                                // installed below picks up the
                                // status bit.
                                if narf_acpi::power_button_arm() {
                                    let _ = writeln!(
                                        console::Writer,
                                        "  acpi: power-button armed (PM1_EN.PWRBTN set)"
                                    );
                                }
                            }
                            Err(e) => {
                                let _ = writeln!(
                                    console::Writer,
                                    "  acpi: FADT PM parse skipped: {:?}",
                                    e
                                );
                            }
                        }
                        // FACS — Firmware ACPI Control Structure.
                        // Reached via FADT.firmware_ctrl /
                        // X_FirmwareCtrl. Required for S3 suspend so
                        // `arm_s3_waking_vector` has a phys to write
                        // the resume vector into. Absence is normal
                        // on hypervisor-only platforms that don't
                        // expose S-state firmware (QEMU `-machine pc`
                        // for example).
                        // SAFETY: same.
                        match unsafe { narf_acpi::parse_facs(p) } {
                            Ok(()) => {
                                if let Some(fi) = narf_acpi::facs_info() {
                                    let _ = writeln!(
                                        console::Writer,
                                        "  acpi: FACS parsed (v{}, hw-sig {:#x})",
                                        fi.version,
                                        fi.hardware_signature,
                                    );
                                }
                            }
                            Err(e) => {
                                let _ = writeln!(
                                    console::Writer,
                                    "  acpi: FACS parse skipped: {:?}",
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
                        // IOMMU topology: IVRS (AMD-Vi) + DMAR
                        // (Intel VT-d). Either one being present
                        // is enough for narf_io::iommu::init below
                        // to pick a backend.
                        // SAFETY: same.
                        match unsafe { narf_acpi::parse_ivrs(p) } {
                            Ok(n) => {
                                let _ = writeln!(
                                    console::Writer,
                                    "  acpi: IVRS parsed, {} IOMMU(s)",
                                    n
                                );
                            }
                            Err(e) => {
                                let _ = writeln!(
                                    console::Writer,
                                    "  acpi: IVRS parse skipped: {:?}",
                                    e
                                );
                            }
                        }
                        // SAFETY: same.
                        match unsafe { narf_acpi::parse_dmar(p) } {
                            Ok(n) => {
                                let _ = writeln!(
                                    console::Writer,
                                    "  acpi: DMAR parsed, {} DRHD(s)",
                                    n
                                );
                            }
                            Err(e) => {
                                let _ = writeln!(
                                    console::Writer,
                                    "  acpi: DMAR parse skipped: {:?}",
                                    e
                                );
                            }
                        }
                        let _ = writeln!(
                            console::Writer,
                            "  aml: parsing namespace..."
                        );
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
                                if let Some((a, b)) = narf_aml::evaluate_s5() {
                                    let _ = writeln!(
                                        console::Writer,
                                        "  aml: \\_S5 → SLP_TYPa={} SLP_TYPb={}",
                                        a, b
                                    );
                                }
                                // Snapshot — later tests that mutate
                                // the live namespace can still consult
                                // the boot-time numbers.
                                narf_aml::capture_boot_snapshot();

                                // _PIC(1) — flip ACPI's interrupt mode
                                // to APIC. ACPI defaults to PIC mode
                                // (0); without this the firmware's
                                // `_PRT` packages still describe
                                // PIC-routed IRQs and the IOAPIC
                                // tables we install below would race
                                // the firmware. Many DSDTs simply
                                // don't define `\_PIC` (QEMU's q35
                                // does); a missing method is fine
                                // and silently skipped.
                                let pic = narf_aml::eval::evaluate_method(
                                    "\\_PIC",
                                    &[narf_aml::Value::Integer(1)],
                                );
                                match pic {
                                    Ok(_) => {
                                        let _ = writeln!(
                                            console::Writer,
                                            "  acpi: \\_PIC(1) — APIC mode declared"
                                        );
                                    }
                                    Err(narf_aml::AmlError::MethodNotFound) => {
                                        let _ = writeln!(
                                            console::Writer,
                                            "  acpi: \\_PIC absent — firmware doesn't \
                                             distinguish PIC/APIC routing"
                                        );
                                    }
                                    Err(e) => {
                                        let _ = writeln!(
                                            console::Writer,
                                            "  acpi: \\_PIC(1) failed: {:?}",
                                            e
                                        );
                                    }
                                }

                                // For every PCIe root bridge (`_HID`
                                // matches PNP0A03 PCI / PNP0A08 PCIe),
                                // evaluate `_PRT` to learn the
                                // per-slot/pin → GSI map. Stash the
                                // result in `narf_aml::irq_routing`'s
                                // global registry so the future
                                // IOAPIC programmer (and PCI driver
                                // bind path) can route legacy INTx
                                // through the right vector.
                                let mut prt_total = 0usize;
                                let mut bridges = 0usize;
                                narf_aml::for_each_device(|n| {
                                    let hid = narf_aml::device_hid(&n.path)
                                        .unwrap_or_default();
                                    if hid != "PNP0A03" && hid != "PNP0A08" {
                                        return;
                                    }
                                    bridges += 1;
                                    match narf_aml::prt_crs::evaluate_prt_for(&n.path) {
                                        Ok(entries) => {
                                            prt_total += entries.len();
                                            narf_aml::irq_routing::register_bridge(
                                                &n.path, &entries,
                                            );
                                        }
                                        Err(narf_aml::prt_crs::BridgeError::MethodNotFound) => {
                                            // Some bridges have a
                                            // Name(_PRT, ...) instead
                                            // of Method — the bridge
                                            // module flags those as
                                            // MethodNotFound for
                                            // now. Skip silently.
                                        }
                                        Err(e) => {
                                            let _ = writeln!(
                                                console::Writer,
                                                "  acpi: _PRT eval at {} failed: {:?}",
                                                n.path,
                                                e
                                            );
                                        }
                                    }
                                });
                                if bridges > 0 {
                                    let _ = writeln!(
                                        console::Writer,
                                        "  acpi: walked {} PCIe root bridge(s), \
                                         {} _PRT entries indexed",
                                        bridges,
                                        prt_total
                                    );
                                }
                                // Diagnostic 2: dump first few device
                                // paths to see what we have.
                                let mut shown = 0u32;
                                narf_aml::for_each_device(|n| {
                                    if shown < 12 {
                                        let hid = narf_aml::device_hid(&n.path)
                                            .unwrap_or_default();
                                        let _ = writeln!(
                                            console::Writer,
                                            "    dev: {} (HID={:?})",
                                            n.path, hid
                                        );
                                        shown += 1;
                                    }
                                });
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

                // PCIe enumeration only when ACPI's MCFG actually
                // tells us where ECAM lives. On hosts without MCFG
                // (e.g. QEMU `-machine pc` / i440fx without
                // explicit PCIe wiring) we used to fall back to the
                // q35 hardcoded base 0xb000_0000 — which is
                // unmapped or backed by random RAM there, so the
                // walker would return phantom devices and any
                // subsequent driver probe could hang.
                //
                // No-MCFG → skip enumeration. No PCIe devices, no
                // probes. Drivers' Stage::Device initcalls then
                // see nothing registered and return NotPresent, per
                // the no-block-on-missing-hardware rule.
                if let Some(ecam_phys) = narf_acpi::mcfg_ecam_base() {
                    let ecam = narf_memory::PhysAddr::new(ecam_phys);
                    let n_dev = unsafe { narf_bus::init(ecam) };
                    let _ = writeln!(
                        console::Writer,
                        "  bus: PCIe ECAM walk @ {:?} found {} function(s)",
                        ecam,
                        n_dev
                    );
                } else {
                    let _ = writeln!(
                        console::Writer,
                        "  bus: PCIe enumeration skipped — no ACPI MCFG (legacy host?)"
                    );
                }

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
                //
                // `nosmp` cmdline flag skips the AP-bringup path
                // entirely. Useful for QEMU TCG (whose x2APIC ICR
                // emulation is incomplete and #GPs the BSP
                // mid-IPI), and as a fallback on real silicon
                // when SMP isn't a critical-path requirement.
                let nosmp = narf_boot::cmdline()
                    .split_ascii_whitespace()
                    .any(|t| t == "nosmp");
                if nosmp {
                    let _ = writeln!(
                        console::Writer,
                        "  smp: SKIPPED via nosmp cmdline (BSP only)"
                    );
                    narf_memory::beacon::paint(16, 0x00808080); // GRAY: SMP skipped
                    // BSP-only topology summary. Same as the SMP
                    // path below but with no APs to count.
                    let bsp_ty = narf_lib::percpu::cpu_type(0);
                    let n_p = narf_lib::percpu::count_cpu_type(
                        narf_lib::percpu::CpuType::Core,
                    );
                    let n_e = narf_lib::percpu::count_cpu_type(
                        narf_lib::percpu::CpuType::Atom,
                    );
                    let _ = writeln!(
                        console::Writer,
                        "  cpu-topology: BSP={}, {} P-core(s) + {} E-core(s)",
                        bsp_ty.as_str(),
                        n_p,
                        n_e
                    );
                } else {
                    // SAFETY: memory + LAPIC + IDT/GDT all initialised
                    // above; identity map covers 0x8000.
                    let started = unsafe { x86_64::smp::start_aps() };
                    narf_memory::beacon::paint(16, 0x0040_FFFF); // TEAL: SMP up
                    let _ = writeln!(
                        console::Writer,
                        "  smp: started {} AP(s); {} CPU(s) online",
                        started,
                        narf_lib::smp::online_count()
                    );

                    // Hybrid-CPU topology summary. Counts P-cores
                    // (Core, 0x40) and E-cores (Atom, 0x20) across
                    // the now-online set. AMD silicon and pre-12th-
                    // gen Intel report BSP=Unknown and zero P/E
                    // counts — that's the correct answer for
                    // uniform-core parts, not a regression. Intel
                    // Alder Lake / Raptor Lake / Meteor Lake report
                    // the real split (e.g. 12 P-cores + 4 E-cores
                    // on a 12700K). This line is informational
                    // only — the scheduler doesn't yet consult
                    // cpu_type; affinity-hinting is follow-up
                    // work.
                    let bsp_ty = narf_lib::percpu::cpu_type(0);
                    let n_p = narf_lib::percpu::count_cpu_type(
                        narf_lib::percpu::CpuType::Core,
                    );
                    let n_e = narf_lib::percpu::count_cpu_type(
                        narf_lib::percpu::CpuType::Atom,
                    );
                    let _ = writeln!(
                        console::Writer,
                        "  cpu-topology: BSP={}, {} P-core(s) + {} E-core(s)",
                        bsp_ty.as_str(),
                        n_p,
                        n_e
                    );

                    // APs idle in run_forever until work-stealing
                    // lets them pull from BSP's queue. Gated out
                    // of kernel-test because the existing smokes
                    // call sync run_until_empty + assume BSP-only
                    // execution — APs stealing in-flight test
                    // tasks races the smoke's assertion. SMP-safing
                    // the test harness is a separate effort.
                    #[cfg(not(feature = "kernel-test"))]
                    if started > 0 {
                        narf_scheduler::enable_work_stealing();
                        let _ = writeln!(
                            console::Writer,
                            "  smp: work-stealing enabled"
                        );
                    }
                }
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
                #[cfg(not(feature = "kernel-test"))]
                if started > 0 {
                    narf_scheduler::enable_work_stealing();
                    let _ = writeln!(
                        console::Writer,
                        "  smp: work-stealing enabled"
                    );
                }
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
            narf_drivers_gpio::register_initcalls();
            narf_drivers_i2c::register_initcalls();
            narf_drivers_usbpd::register_initcalls();
            narf_drivers_storage::register_initcalls();
            narf_drivers_usb::register_initcalls();
            narf_drivers_thunderbolt::register_initcalls();
            narf_drivers_fingerprint::register_initcalls();
            narf_drivers_fs_ext2::register_initcalls();
            narf_drivers_fs_ext4::register_initcalls();
            narf_drivers_fs_fat::register_initcalls();
            narf_drivers_platform::register_initcalls();
            // Bridge: ACPI power-button events (delivered by the
            // SCI dispatcher in narf-drivers-platform::ec) into
            // the system-power surface. Subscribers run in SCI
            // IRQ context — `system::power_off` is a never-
            // returns terminal action, so calling it directly
            // from the IRQ is safe (any locks held elsewhere
            // become moot once the platform powers off).
            #[cfg(target_arch = "x86_64")]
            narf_drivers_platform::ec::subscribe_platform_event(|event| {
                if event == narf_drivers_platform::ec::PlatformEvent::PowerButton {
                    let _ = writeln!(
                        console::Writer,
                        "  acpi: power button → entering S5"
                    );
                    narf_power::system::power_off();
                }
            });
            narf_graphics_driver::register_initcalls();
            narf_drivers_gpu::register_initcalls();
            narf_drivers_nvidia::register_initcalls();
            narf_input_driver::register_initcalls();
            narf_fb::register_initcalls();
            narf_audio::register_initcalls();
            narf_bluetooth::register_initcalls();
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

                    // PCR 0 is for FIRMWARE measurement per TCG PC Client
                    // Platform Firmware Profile §3.3 — owned by UEFI /
                    // coreboot, NOT by the kernel. The bootloader is what
                    // extends our kernel hash into PCR 4 ("boot loader
                    // code"). Kernel self-measuring into PCR 0 is wrong
                    // and (until just now) crashed boot because the
                    // `__kernel_start` / `__kernel_end` linker symbols
                    // are in different address spaces — `__kernel_end =
                    // . - KERNEL_VIRT_BASE` gives a phys-equivalent
                    // offset, so `kend - kstart` underflows wildly when
                    // treated as a virtual-range length. The frame
                    // allocator (bare_main.rs:851) uses the same symbols
                    // for their intended phys-range purpose.

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

                    // PCR 5: Kernel command-line. Extends with the
                    // EV_IPL_PARTITION_DATA tag so userspace attestation
                    // tools can byte-match against the boot-cmdline.
                    if let Some(i) = info {
                        if let Err(e) = measure::measure_cmdline(i.cmdline).await {
                            let _ = writeln!(
                                console::Writer,
                                "  measured-boot: PCR 5 cmdline extend failed: {:?}",
                                e
                            );
                        }
                    }

                    // PCR 6: Initramfs. PC Client Spec recommends PCR 6
                    // for OEM-specific boot artifacts; the Linux IMA +
                    // measurement convention also lands the initramfs
                    // there. The bootloader-supplied region is identity-
                    // mapped at this point.
                    if let Some(r) = info.and_then(|i| i.initramfs) {
                        // SAFETY: BootInfo::initramfs is the bootloader-
                        // staged identity-mapped initramfs region.
                        let res = unsafe {
                            measure::measure_initramfs(r.start.raw(), r.len).await
                        };
                        if let Err(e) = res {
                            let _ = writeln!(
                                console::Writer,
                                "  measured-boot: PCR 6 initramfs extend failed: {:?}",
                                e
                            );
                        }
                    }

                    // PCR 9: Driver-firmware blobs. Walk the registry's
                    // snapshot at this point and extend a per-blob entry
                    // (path, hash, length). Subsequent hot-installs
                    // extend incrementally as they land.
                    for ident in narf_firmware::snapshot() {
                        if let Err(e) = measure::measure_firmware_blob(
                            ident.name,
                            &ident.sha256,
                            ident.size as u64,
                        )
                        .await
                        {
                            let _ = writeln!(
                                console::Writer,
                                "  measured-boot: PCR 9 firmware extend failed for {}: {:?}",
                                ident.name,
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
                    let _ = writeln!(
                        console::Writer,
                        "  measured-boot: secure-boot enabled={}",
                        secure_boot::enabled()
                    );
                });
                narf_init::InitResult::Ok
            });

            #[cfg(target_arch = "x86_64")]
            narf_init::register(narf_init::Stage::Late, "fb-console-install", || {
                use narf_graphics::{FbConsole, Pixel32};
                // Skip if the early-FB install already wired a
                // working console. Re-installing would call
                // FbConsole::new → fb.clear() and wipe all the
                // boot-time output (beacons, build stripe, init
                // log). The early install only succeeds when the
                // bootloader-supplied FB is below 4 GiB; if it was
                // skipped (deferred-to-late path), is_installed()
                // returns false and we proceed.
                if narf_graphics::console::is_installed() {
                    let _ = writeln!(
                        console::Writer,
                        "  splash: fb-console already installed by early-fb path — skipping re-install"
                    );
                    return narf_init::InitResult::Ok;
                }
                // Pick the active scanout: bochs / virtio-gpu / amdgpu
                // / generic. Generic is what Limine + UEFI hand us via
                // the multiboot2 framebuffer tag — it has no doorbell,
                // so writes land in pixels directly. The picker also
                // covers the bochs path that QEMU `-kernel` lights up.
                let scanout = match narf_fb::select_active() {
                    Some(s) => s,
                    None => {
                        let _ = writeln!(
                            console::Writer,
                            "  splash: no active scanout — fb-console install skipped"
                        );
                        return narf_init::InitResult::NotPresent;
                    }
                };
                // SAFETY: BSP, no concurrent draw. Each scanout's
                // `framebuffer()` returns a Framebuffer wrapping a
                // live identity-mapped pixel buffer; the bochs branch
                // additionally requires `fb_reachable()`, so guard
                // that one explicitly.
                if scanout.name() == "bochs" {
                    let reachable = narf_graphics_driver::bochs::with_controller(|d| {
                        d.fb_reachable()
                    })
                    .unwrap_or(false);
                    if !reachable {
                        let phys = narf_graphics_driver::bochs::with_controller(|d| d.fb_phys())
                            .unwrap_or(0);
                        let _ = writeln!(
                            console::Writer,
                            "  splash: bochs framebuffer at {:#x} above 4 GiB \
                             identity map; deferred until ioremap lands",
                            phys
                        );
                        return narf_init::InitResult::NotPresent;
                    }
                }
                let fb = unsafe { scanout.framebuffer() };
                let con = FbConsole::new(fb, Pixel32::NARF_FG, Pixel32::NARF_BG);
                let (cols, rows) = (con.cols(), con.rows());
                let backend = scanout.name();
                narf_graphics::install_fb_console(con);
                console::set_fb_hook(narf_graphics::console::write_bytes);
                let _ = writeln!(
                    console::Writer,
                    "  splash: {}x{} {} framebuffer console installed \
                     ({} cols x {} rows of 8x8 glyphs)",
                    cols * 8,
                    rows * 8,
                    backend,
                    cols,
                    rows
                );
                narf_init::InitResult::Ok
            });

            // FB write-combining remap. After `fb-console-install`
            // wired the boot-time path through the early identity
            // map (uncached MMIO — ~75 ns/pixel-write, glacial on
            // real silicon), re-map the FB phys at a fresh kernel
            // virt with PAT=WC. Subsequent writes coalesce into
            // burst transactions, ~10× faster.
            //
            // The existing FbConsole holds a Framebuffer over the
            // OLD (uncached) virt. We update GenericFb so future
            // scanout consumers (cursor pump, status panel, beacon
            // re-registration) hit WC; the running FbConsole is
            // not re-installed (would wipe scrollback). The next
            // boot's early-fb install would happen pre-MMU and
            // still be uncached — only post-Stage::Late activity
            // benefits.
            narf_init::register(narf_init::Stage::Late, "fb-wc-remap", || {
                use narf_memory::ioremap::{ioremap, MmioAttrs};
                let info = match narf_fb::info() {
                    Some(i) => i,
                    None => return narf_init::InitResult::NotPresent,
                };
                // GenericFb's stride is in pixels; pitch in bytes
                // = stride * 4 (XRGB8888). FB byte-length =
                // height * pitch, rounded up to page granularity
                // for ioremap.
                let phys = match narf_fb::generic_phys() {
                    Some(p) => p,
                    None => return narf_init::InitResult::NotPresent,
                };
                let pitch_bytes = info.stride as u64 * 4;
                let raw_len = info.height as u64 * pitch_bytes;
                let len = (raw_len + 0xFFF) & !0xFFFu64;
                // SAFETY: FB phys was registered by Limine/UEFI;
                // exclusive kernel-side; the new virt is fresh
                // vmalloc.
                let m = match unsafe { ioremap(phys, len, MmioAttrs::WriteCombining) } {
                    Ok(m) => m,
                    Err(_) => {
                        let _ = writeln!(
                            console::Writer,
                            "  fb-wc-remap: ioremap-WC failed; FB writes stay uncached"
                        );
                        return narf_init::InitResult::Error("ioremap-WC failed");
                    }
                };
                narf_fb::rebase_generic(m.virt);
                // Re-register beacon at the WC virt. Subsequent
                // paint() calls (cursor liveness, slot 50/52
                // bisection beacons, etc.) burst-write instead of
                // uncached.
                narf_memory::beacon::register(
                    m.virt,
                    info.stride,
                    info.width,
                    info.height,
                    /* ceiling: WC virt is in kernel half, well
                     * above the 4 GiB identity-map cap, but
                     * beacon ignores ceiling=0 and treats
                     * non-zero as the bound. Pass u64::MAX so
                     * any beacon write succeeds. */
                    u64::MAX,
                );
                // Rebase the installed FbConsole's internal
                // Framebuffer to the WC virt. Without this the
                // FbConsole keeps writing to the old uncached
                // identity-mapped phys — text scroll stays
                // glacial. The rebase is in-place, doesn't
                // wipe scrollback, doesn't move the cursor.
                // SAFETY: WC virt covers stride*height*4 bytes
                // (ioremap rounded `len` to that); the mapping
                // lives until iounmap which we never call.
                unsafe {
                    narf_graphics::console::rebase_installed(m.virt as *mut u32);
                }
                let _ = writeln!(
                    console::Writer,
                    "  fb-wc-remap: FB ioremap'd at {:#x} ({} KiB, WC); console rebased",
                    m.virt,
                    len / 1024,
                );
                narf_init::InitResult::Ok
            });

            // Auto-mount root if a known FS lives on any probed
            // block device. Two paths, in order:
            //
            // 1. Initramfs (RAM-staged CPIO from the bootloader) —
            //    tried first so a freshly-built initramfs always
            //    beats a stale on-disk image. Used on real hardware
            //    when there's no mountable disk yet (USB stick that
            //    is purely an initramfs delivery vehicle), and so
            //    userspace binaries iterate without rebuilding the
            //    kernel.
            //
            // 2. fs-factory registry walk — every FS driver
            //    (ext2/3/4, FAT, future) registers an
            //    `Arc<dyn BlockDeviceSync> -> Arc<dyn FsInstance>`
            //    factory at `Stage::Subsys`. `try_mount_root` walks
            //    `narf_block::block_devices()`, runs
            //    `detect_filesystem` on each, looks up the matching
            //    factory, and mounts the first hit. NVMe / AHCI /
            //    RamBlockDevice / virtio-blk-as-sync all funnel
            //    through this one path — no driver-specific code
            //    here.
            narf_init::register(narf_init::Stage::Late, "root-mount-auto", || {
                let auth = narf_filesystem::bootstrap_mount_authority();

                // Boot ordering:
                //   1. If the cmdline carries root=, honour it strictly:
                //      try_mount_root picks the named partition / FS.
                //      Refuse silent fallback when root= misses — wrong
                //      disk + right shell is worse than a broken boot.
                //   2. Otherwise, prefer initramfs when staged (the
                //      ISO-on-USB path NARF has shipped with). The
                //      initramfs always works + is small, so it's the
                //      safe default.
                //   3. Final fallback: walk the block registry via
                //      try_mount_root and mount whatever ext / FAT
                //      filesystem the fs-factory registry finds.
                let cmdline = narf_boot::cmdline();
                let has_root_eq = narf_filesystem::root_selector::RootSelector::from_cmdline(
                    cmdline,
                )
                .is_some();

                if has_root_eq {
                    match narf_filesystem::root_mount::try_mount_root(&auth) {
                        Ok(report) => {
                            let _ = writeln!(
                                console::Writer,
                                "  root-mount: {:?} on {} mounted at \"/\" (cmdline root= selector)",
                                report.fs_type, report.device_name
                            );
                            return narf_init::InitResult::Ok;
                        }
                        Err(e) => {
                            let _ = writeln!(
                                console::Writer,
                                "  root-mount: cmdline root= selector failed: {:?}",
                                e
                            );
                            // Fall through to initramfs/walk fallbacks
                            // so a typoed root= still boots into a shell
                            // rather than panicking the kernel.
                        }
                    }
                }

                if narf_initramfs::is_staged() {
                    match narf_initramfs::mount_at_path(&auth, "/") {
                        Ok(()) => {
                            let _ = writeln!(
                                console::Writer,
                                "  root-mount: initramfs mounted at \"/\""
                            );
                            return narf_init::InitResult::Ok;
                        }
                        Err(()) => {
                            let _ = writeln!(
                                console::Writer,
                                "  root-mount: initramfs mount at \"/\" rejected"
                            );
                        }
                    }
                }

                match narf_filesystem::root_mount::try_mount_root(&auth) {
                    Ok(report) => {
                        let _ = writeln!(
                            console::Writer,
                            "  root-mount: {:?} on {} mounted at \"/\" via fs-factory walk",
                            report.fs_type, report.device_name
                        );
                        return narf_init::InitResult::Ok;
                    }
                    Err(e) => {
                        let _ = writeln!(
                            console::Writer,
                            "  root-mount: fs-factory walk found nothing mountable: {:?}",
                            e
                        );
                    }
                }
                narf_init::InitResult::NotPresent
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
            //
            // The cmdline `stop_at=<stage>` flag (see narf_boot::
            // cmdline) caps the run, e.g. `stop_at=device` halts
            // before Late so the FB-console + virtio-gpu splash
            // don't run. `safe_mode` is shorthand for
            // `stop_at=subsys`. Useful for narrowing real-HW
            // bring-up failures: each stage that completes prints
            // a summary line, the next stage is the suspect.
            let last_stage = parse_stop_at(narf_boot::cmdline());
            if last_stage != narf_init::Stage::Late {
                let _ = writeln!(
                    console::Writer,
                    "  cmdline: stop_at={} (stages after this will be skipped)",
                    last_stage.name()
                );
            }
            // Run stages one at a time so each completion paints a
            // beacon. Slot 17+ light up as we cross into Subsys, Fs,
            // Device, Late — anyone watching the screen sees the
            // initcall pipeline progress in real time.
            for s in narf_init::Stage::ALL {
                if (s as u8) > (last_stage as u8) {
                    break;
                }
                let _ = narf_init::run_stage(s);
                let (slot, color) = match s {
                    narf_init::Stage::Subsys => (17u32, 0x00FF_C0CB), // PINK
                    narf_init::Stage::Fs     => (18u32, 0x00FF_D700), // GOLD
                    narf_init::Stage::Device => (19u32, 0x0087_CEEB), // SKY
                    narf_init::Stage::Late   => (20u32, 0x00E6_E6FA), // LAVENDER
                    _ => continue,
                };
                narf_memory::beacon::paint(slot, color);
            }
            let _ = narf_init::print_summary(&mut console::Writer);

            // AMD-specific amd-pstate active-mode bring-up. Sibling
            // of narf_power::pstate (which handled Intel HWP /
            // SpeedStep / AMD HwPstate during the Subsys initcall
            // above). amd_pstate gates itself on CPUID — AMD Family
            // 0x17 Models 0x30..=0xAF (Zen2 Renoir / Lucienne /
            // Matisse) — so this is a clean no-op on Intel, on QEMU
            // `-cpu max`, and on AMD parts outside the Zen2 window.
            // Touches MSR_AMD_CPPC_CAP1 (0xC001_02B0) +
            // MSR_AMD_CPPC_REQ (0xC001_02B1); writes use the GP-safe
            // wrmsr_or_gp so BIOS-locked CPPC MSRs surface in the
            // status line instead of wedging boot.
            #[cfg(target_arch = "x86_64")]
            {
                use narf_arch::x86_64::amd_pstate::{boot_init, BootInitOutcome};
                let outcome = boot_init();
                let line = match outcome {
                    BootInitOutcome::NotZen2 => "amd-pstate: skipped (not Zen2)",
                    BootInitOutcome::Cap1Gp => {
                        "amd-pstate: CAP1 #GP — firmware-locked, default left in place"
                    }
                    BootInitOutcome::ReqGp => {
                        "amd-pstate: REQ #GP — firmware-locked, default left in place"
                    }
                    BootInitOutcome::Programmed { .. } => {
                        "amd-pstate: programmed (min=lo_nonlin, max=hi, des=nom, EPP=bal-perf)"
                    }
                };
                let _ = writeln!(console::Writer, "  {}", line);
            }
        }
        Err(e) => {
                            narf_memory::beacon::paint(5, 0x00FF_FFFF); // WHITE: Err branch
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

    // Boot-smoke: real init flow + clean ACPI/isa-debug-exit shutdown.
    // Drains queued async tasks (including measured-boot) for ~2 s so
    // the boot log surfaces, then exits via the same port 0xF4 path
    // the test harness uses. The xtask `boot-smoke` subcommand waits
    // for QEMU to exit naturally + checks stdout for panic markers,
    // rather than killing the child after a wall-clock timeout.
    #[cfg(feature = "boot-smoke")]
    {
        let _ = writeln!(console::Writer, "  boot-smoke: draining tasks...");
        // Same async-runtime spin pattern as run_async_demo, capped
        // at ~2 seconds so the boot log is fully emitted.
        let deadline = narf_time::Deadline::after_ms(2_000);
        narf_scheduler::responsive_spin_until(|| deadline.expired(), deadline);
        let _ = writeln!(console::Writer, "  boot-smoke: clean exit");
        // SAFETY: exit_kernel never returns; this is the only post-
        // boot action we're authorised to take.
        unsafe {
            narf_arch::exit_kernel(0);
        }
    }

    // ─── Stage 1 exit-gate demo: async executor + timer-driven yield ──
    #[cfg(not(any(feature = "kernel-test", feature = "boot-smoke", feature = "idt-selftest")))]
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
    // Bring up HPET FIRST so the clockevent registry has access
    // to it during probe. Earlier code ran `select_primary`
    // before `hpet::init` — HPET's `supported()` then returned
    // false because hpet::is_present() was false, so the HPET
    // backend was silently rejected and only LAPIC was tried.
    // Real-HW result on Renoir 4700U: clk=none:0 (LAPIC vec 32
    // doesn't deliver, HPET never tried).
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: BSP, single-threaded boot context.
        match unsafe { narf_time::hpet::init() } {
            Ok(()) => {
                let hz = narf_time::hpet::frequency_hz();
                let n = narf_time::hpet::num_comparators();
                let _ = writeln!(
                    console::Writer,
                    "  hpet: enabled @ {} MHz, {} comparators",
                    hz / 1_000_000,
                    n,
                );
                // Per-comparator caps — surfaces whether MSI-FSB
                // delivery and periodic mode are actually available
                // on this chipset. Critical diagnostic for boot
                // failures where 'hpet armed but probe fired 0 ticks'
                // — tells us which path was tried.
                for i in 0..n {
                    let periodic = narf_time::hpet::comparator_supports_periodic(i);
                    let fsb = narf_time::hpet::comparator_supports_fsb(i);
                    let route_cap = narf_time::hpet::timer_route_cap(i);
                    let _ = writeln!(
                        console::Writer,
                        "  hpet:   comp{} periodic={} fsb={} route_cap={:#010x}",
                        i, periodic, fsb, route_cap,
                    );
                }
                // LAPIC MMIO base from IA32_APIC_BASE MSR — Linux
                // honors BIOS relocation via this MSR rather than
                // hardcoding 0xFEE0_0000. If our hardcoded base
                // doesn't match, MMIO writes go nowhere and MSI
                // delivery (targeted at 0xFEE0_0000) won't reach
                // the LAPIC.
                let apic_base = unsafe {
                    narf_arch::x86_64::msr::rdmsr(0x0000_001B)
                };
                let lapic_phys = apic_base & 0x0000_000F_FFFF_F000;
                let _ = writeln!(
                    console::Writer,
                    "  apic: IA32_APIC_BASE={:#018x} (LAPIC phys={:#010x}, en={}, extd={})",
                    apic_base,
                    lapic_phys,
                    (apic_base >> 11) & 1,
                    (apic_base >> 10) & 1,
                );
            }
            Err(e) => {
                let _ = writeln!(console::Writer, "  hpet: probe failed: {e:?}");
            }
        }
        let (tsc_hz, tsc_src) = narf_time::calibrate_clocks_with_source();
        if tsc_hz != 0 {
            let _ = writeln!(
                console::Writer,
                "  tsc: calibrated to {} MHz ({} cyc/ns) via {}",
                tsc_hz / 1_000_000,
                (tsc_hz / 1_000_000_000).max(1),
                tsc_src.name(),
            );
        } else {
            let _ = writeln!(
                console::Writer,
                "  tsc: calibration failed — running in raw-tick units"
            );
        }
    }

    #[cfg(target_arch = "x86_64")]
    {
        // Register candidate tick sources. LAPIC first (highest
        // preference — per-CPU, low resolution_ns, no shared
        // device contention). HPET second, as fallback: it owns
        // comparator 1+ exclusively (comparator 0 is reserved
        // for `narf_interrupts::x86_64::timer_pump`'s oneshot
        // wheel arming). `select_primary` calls arm_periodic +
        // probes each in registry order, picks the first that
        // delivers ticks. So on Renoir-style platforms where the
        // LAPIC timer arms but never delivers IRQs, the HPET
        // backend is the canonical Linux-style fallback.
        narf_time::clockevent::register(
            &narf_interrupts::x86_64::apic::LAPIC_CLOCKEVENT,
        );
        narf_time::clockevent::register(
            &narf_interrupts::x86_64::hpet_clockevent::HPET_CLOCKEVENT,
        );

        // Enable CPU-side IRQ delivery BEFORE select_primary so
        // the probe can actually observe ticks. Without this the
        // probe always fails (arm programs the device, but IF=0
        // → no delivery → tick_count stuck at 0 → probe fails).
        // SAFETY: APIC + IDT live; PIC masked.
        unsafe {
            narf_arch::enable_interrupts();
        }

        let selected = narf_time::clockevent::select_primary(
            100, // 100 Hz tick — 10 ms period
            narf_interrupts::VECTOR_TIMER,
        );
        match selected {
            Some(dev) => {
                let _ = writeln!(
                    console::Writer,
                    "  clockevent: selected '{}' on vector {} (probe: {} ticks)",
                    dev.name(),
                    narf_interrupts::VECTOR_TIMER,
                    dev.tick_count(),
                );
            }
            None => {
                // No backend's probe passed. The trap-handler
                // fail-safe (fire_due on every IRQ) keeps the
                // wheel advancing off whatever IRQs the platform
                // does deliver (xHCI, NIC, ACPI SCI, etc.).
                // Degraded but not wedged.
                let _ = writeln!(
                    console::Writer,
                    "  clockevent: NO BACKEND PASSED PROBE — degraded mode (opportunistic fire_due)"
                );
            }
        }
    }

    // Bring up the HPET timer-wheel pump now that HPET, IDT, and
    // the IOAPIC are all live. Future `SleepUntil` registrations
    // arm HPET via this pump rather than busy-polling the
    // executor. Failure is non-fatal — sleep_cycles falls back
    // to self-wake busy-poll when no arm callback is installed.
    #[cfg(target_arch = "x86_64")]
    {
        match narf_interrupts::x86_64::timer_pump::init() {
            Ok(()) => {
                let _ = writeln!(console::Writer, "  timer_pump: HPET wheel armed");
            }
            Err(e) => {
                let _ = writeln!(
                    console::Writer,
                    "  timer_pump: init failed ({:?}) — sleeps will busy-poll",
                    e
                );
            }
        }
    }

    // IOMMU probe + identity-map enable. Drivers doing DMA
    // benefit from a known-good translation path (no SMMU faults
    // on virtualized hosts; future per-driver isolation slots
    // in here). Failure is non-fatal — alloc_coherent + the
    // IommuContext::map fallback still hand out identity-
    // equivalent addresses, so drivers see the same behaviour
    // they did before the IOMMU work landed.
    {
        match narf_io::iommu::init() {
            Ok(mode) => {
                let caps = narf_io::iommu::caps();
                let _ = writeln!(
                    console::Writer,
                    "  iommu: {} initialised in {:?} mode ({} unit(s), max_iova_bits {}, IR {})",
                    narf_io::iommu::vendor(),
                    mode,
                    narf_io::iommu::unit_count(),
                    caps.max_iova_bits,
                    if caps.interrupt_remap { "supported" } else { "absent" },
                );
            }
            Err(e) => {
                let _ = writeln!(
                    console::Writer,
                    "  iommu: init skipped ({:?}) — drivers use identity-equivalence",
                    e
                );
            }
        }
    }

    // NOTE: do NOT call narf_scheduler::init() here. It already
    // ran before AP bring-up (line ~1247) and the queues survive.
    // A second init() unconditionally wipes every per-CPU
    // VecDeque, dropping any task spawned by Stage::Late
    // initcalls (cursor pump, USB HID supervisor, FB drain task,
    // anything else that spawns long-running work). That was a
    // silent kill — tasks vanished without a panic and the
    // affected subsystems just stopped working on real HW.
    let _ = writeln!(
        console::Writer,
        "  scheduler: ready queues already live (no re-init)"
    );

    // Slot 19: build-freshness sentinel. Painted before any
    // executor work. If you re-burn the ISO and slot 19 is
    // *missing* (only the original 28/29/30 show), the ISO is
    // built from a stale binary — the source-tree changes never
    // reached the kernel image. Verify with `cargo xtask image`
    // (or whatever you use), make sure it rebuilds `narf-frame`,
    // and confirm Limine is loading the freshly-built kernel.
    narf_memory::beacon::paint(19, 0x00FF_00FF); // magenta

    #[cfg(feature = "boot-init")]
    boot_userspace_init();

    // Periodic serial heartbeat — surfaces input-pipeline counters
    // (ASCII_PUSH / ASCII_POP / KEY_PUSH) every ~2s so a headless
    // serial capture shows whether keystrokes are reaching the
    // shell. Spawned BEFORE run_until_empty so it lives in the
    // queue regardless of the headless-vs-interactive branch
    // below (run_until_empty doesn't return when there are
    // boot-init user tasks alive, so a post-run_until_empty
    // spawn would never reach the executor).
    {
        struct Heartbeat;
        impl core::future::Future for Heartbeat {
            type Output = ();
            fn poll(
                self: core::pin::Pin<&mut Self>,
                cx: &mut core::task::Context<'_>,
            ) -> core::task::Poll<()> {
                use core::sync::atomic::{AtomicU64, Ordering};
                static LAST_TSC: AtomicU64 = AtomicU64::new(0);
                // Tick at ~10 Hz so the FB beacon slots animate
                // promptly when keystrokes arrive (a 5s period would
                // mean a typed char takes 5s to reflect). The serial
                // line only prints every 5s; the beacon slots paint
                // every tick.
                const PERIOD_CYCLES: u64 = 100_000_000;
                let now = narf_time::now_cycles();
                let last = LAST_TSC.load(Ordering::Relaxed);
                if now.saturating_sub(last) >= PERIOD_CYCLES {
                    LAST_TSC.store(now, Ordering::Relaxed);
                    let ascii_in = narf_input::ASCII_PUSH_COUNT.load(Ordering::Relaxed);
                    let ascii_out = narf_input::ASCII_POP_COUNT.load(Ordering::Relaxed);
                    let key_in = narf_input::KEY_PUSH_COUNT.load(Ordering::Relaxed);
                    // FB beacon visualization — six slots on row 0,
                    // far right of the row. White label slots paint
                    // once-and-stick; counter slots cycle colour as
                    // the corresponding counter increments. If the
                    // user presses a key and slot 37 changes colour,
                    // the kbd is delivering KEY_PUSH events. Same
                    // for slot 35 = serial RX pushes, slot 33 =
                    // ascii pops drained by the shell.
                    const PALETTE: [u32; 8] = [
                        0x00FF_0000, // red
                        0x00FF_8000, // orange
                        0x00FF_FF00, // yellow
                        0x0000_FF00, // green
                        0x0000_FF80, // mint
                        0x0000_FFFF, // cyan
                        0x0000_80FF, // sky
                        0x00FF_00FF, // magenta
                    ];
                    narf_memory::beacon::paint(40, 0x00FF_FFFF); // label "I"
                    narf_memory::beacon::paint(41, PALETTE[(ascii_in as usize) & 7]);
                    narf_memory::beacon::paint(42, 0x00FF_FFFF); // label "O"
                    narf_memory::beacon::paint(43, PALETTE[(ascii_out as usize) & 7]);
                    narf_memory::beacon::paint(44, 0x00FF_FFFF); // label "K"
                    narf_memory::beacon::paint(45, PALETTE[(key_in as usize) & 7]);
                    // Serial heartbeat removed — the FB beacon
                    // visualization above already shows liveness
                    // (slots 41/43/45 cycle colour on each event),
                    // so the console line was pure noise on a
                    // healthy boot.
                }
                cx.waker().wake_by_ref();
                core::task::Poll::Pending
            }
        }
        let _ = narf_scheduler::spawn(Heartbeat);
    }

    // Spawn the cursor pump *before* run_until_empty so it's in the
    // queue when the executor starts. With boot-init the user task
    // futures (init / shell) loop forever, so run_until_empty never
    // returns; if we waited until after to spawn the pump, the
    // mouse would never move.
    // Cursor pump + USB HID supervisor are spawned by their own
    // Stage::Late initcalls — no manual re-spawn needed now that
    // the redundant scheduler::init() above is gone.
    // Beacon slot 28 (free): `narf_fb::info()` returned Some — i.e.
    // a scanout was registered. If you see this beacon BUT no
    // status panel + no shell, the panel-paint code path failed
    // independently. If you DON'T see this beacon, no scanout was
    // ever registered (Limine FB tag absent / select_active picked
    // None).
    if narf_fb::info().is_some() {
        narf_memory::beacon::paint(28, 0x00FF_8C00); // dark-orange: fb-info-some
        let cap = narf_fb::bootstrap_writer();
        if let Ok(panel_writer) = narf_fb::FbWriter::new(cap) {
            narf_fb::status::paint(&panel_writer);
            narf_memory::beacon::paint(29, 0x00FF_FF40); // pale-yellow: panel-painted
        }
    }
    // FB up implies the cursor-pump task was spawned by the
    // fb-cursor-pump initcall (and the USB HID supervisor by
    // its own initcall). Used as the gate for run_forever
    // below — when there's an interactive surface, we don't
    // exit after the demo.
    let interactive = narf_fb::info().is_some();

    let _ = writeln!(
        console::Writer,
        "  scheduler: spawning 1 task, running to completion"
    );
    // Beacon slot 30: about to enter run_until_empty. If you see
    // 30 paint but never see 31, run_until_empty hung (busy-spin
    // task or kernel-wide deadlock). If you see 31, the executor
    // returned cleanly and the issue is later.
    narf_memory::beacon::paint(30, 0x0000_FF80); // mint: pre-run_until_empty
    narf_scheduler::run_until_empty();
    narf_memory::beacon::paint(31, 0x0080_FF00); // chartreuse: post-run_until_empty

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

    // Interactive boot (FB up → cursor pump + USB HID supervisor
    // are alive): switch to run_forever so timer/IRQ wakes resume
    // polling instead of exiting. Without this the kernel would
    // proceed to the exit-kernel path and tear down still-live
    // tasks. Headless boots (no FB) fall through to the existing
    // 5 s pause + exit_kernel path.
    if interactive {
        let _ = writeln!(
            console::Writer,
            "  Stage 1 exit-gate demo complete; entering interactive run_forever"
        );
        narf_scheduler::run_forever();
    }

    let _ = writeln!(
        console::Writer,
        "  halting — Stage 1 exit-gate demo complete. (5s pause so the screen can be read)"
    );

    // TSC-based busy-wait: synchronous (we're at end-of-boot,
    // executor not running for an async sleep). 5 GHz × 5s =
    // 2.5e10 cycles is the pad — runs faster on slower CPUs,
    // never longer than ~5s on a 5 GHz core.
    #[cfg(target_arch = "x86_64")]
    {
        let start = unsafe { core::arch::x86_64::_rdtsc() };
        let target = start.wrapping_add(25_000_000_000u64);
        while unsafe { core::arch::x86_64::_rdtsc() } < target {
            core::hint::spin_loop();
        }
    }

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
    narf_userspace::handlers::init_per_task_state();
    narf_userspace::fd::init();
    // Cross-crate fn-pointer wiring (console signal hook, /proc
    // per-pid hooks, kernel-side TCP stack + RX pump). One call
    // covers everything that used to be inline here.
    cross_crate_init::install_all_hooks();

    // Syscall table.
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // The handlers reach `current_task_id()` then look up its
    // address space — this lookup goes through the scheduler's
    // ready-queue scan.
    install_address_space_lookup(|| {
        // Prefer the executor-published "currently-polling AS" —
        // address_space_of searches the run-queue, which doesn't
        // include the popped-and-being-polled slot. The fallback
        // is kept so kernel-side introspection paths that resolve
        // by id (not currently-polling) still work for tasks that
        // are sitting on the queue.
        if let Some(a) = narf_scheduler::current_address_space() {
            return Some(a);
        }
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

    // Register a scheduler-step pump so the cooperative executor
    // keeps draining its run-queue while a user task is parked in
    // `sys_sleep` or while a sync driver path is busy-waiting
    // inside `responsive_spin_until`. Without this, kernel async
    // tasks that don't have their own dedicated sleep_pump (USB-HID
    // supervisor, virtio-input pump, TCPM task, ...) stop making
    // forward progress during long busy-waits, so e.g. typing
    // through a USB-kbd into a userspace `sleep 5` would have keys
    // queued in the kbd report ring but never drained because the
    // supervisor task wasn't polled.
    //
    // Re-entrancy: `poll_one_round` re-enters here every time the
    // task it polls calls into a sync path that ticks sleep_pumps.
    // A per-CPU recursion guard breaks the chain — only the
    // outermost call drives `poll_one_round`; nested calls see
    // the flag set and skip. The skip is correct because the
    // outermost call is already round-robining tasks; nested
    // calls would just visit the same queue position twice.
    fn scheduler_step_pump() {
        use core::sync::atomic::{AtomicBool, Ordering};
        // Per-CPU "currently inside scheduler_step_pump" flag.
        // SMP scaling: BSP only for now (boot-init runs on the
        // BSP); when AP-side run_forever loops also call into
        // sleep_pumps the flag should be promoted to a per-CPU
        // array. Guarding only the BSP is safe because nested
        // sync waits on APs can still tick sleep_pumps without
        // reaching this fn — they fire OTHER pumps (FB drain,
        // cursor) but skip the scheduler step.
        static IN_FLIGHT: AtomicBool = AtomicBool::new(false);
        if IN_FLIGHT
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let _ = narf_scheduler::poll_one_round();
        IN_FLIGHT.store(false, Ordering::Release);
    }
    narf_userspace::handlers::sleep_pumps::register(scheduler_step_pump);

    // Drain any RX bytes the platform UART has queued (typed bytes
    // via `qemu -serial stdio`, or a real serial console on bare
    // metal) and publish them as `InputEvent::AsciiByte` on the
    // global input ring so /dev/console reads see them. Bounded
    // per-tick so a runaway producer can't monopolise the pump.
    fn serial_input_pump() {
        for _ in 0..16 {
            match narf_console::try_read_byte() {
                Some(b) => {
                    let _ = narf_input::push_global(narf_input::InputEvent::AsciiByte(b));
                }
                None => break,
            }
        }
    }
    // Keep the pump as a defensive backstop — runs whenever a
    // user task parks in sys_sleep. The IRQ path below is the
    // primary delivery mechanism; the pump catches anything
    // that slips past (e.g. on systems where IRQ 4 routing
    // failed).
    narf_userspace::handlers::sleep_pumps::register(serial_input_pump);

    // Real IRQ-driven serial RX: install a handler at ISA IRQ 4
    // (COM1's standard line), route the GSI through the IOAPIC,
    // then enable the 16550A's IER.RDA bit so the chipset
    // asserts the line when bytes arrive. Failure leaves the
    // pump as the only delivery path; success makes typing on
    // the console latency-free instead of bounded by the
    // ~10-50 ms scheduler tick the pump rides.
    #[cfg(target_arch = "x86_64")]
    {
        // The handler drains the same way the pump does — bounded
        // at 16 bytes/IRQ to keep the ISR latency predictable
        // for level-triggered IRQs that re-fire if the line stays
        // asserted (which it would until the FIFO drains).
        fn serial_isr() {
            for _ in 0..16 {
                match narf_console::try_read_byte() {
                    Some(b) => {
                        let _ = narf_input::push_global(narf_input::InputEvent::AsciiByte(b));
                    }
                    None => break,
                }
            }
        }
        // ISA IRQ 4 → GSI (with ISO override resolution) →
        // IOAPIC. PC AT default for IRQ 4 is edge-triggered
        // active-high, but ACPI may override — copied from the
        // pattern in drivers/input/lib.rs::install_isa_irq.
        let mut overrides =
            [narf_acpi::IsaOverride::default(); narf_acpi::MAX_ISA_OVERRIDES];
        let n = narf_acpi::copy_isa_overrides(&mut overrides);
        let (gsi, flags) = overrides[..n]
            .iter()
            .find(|ov| ov.bus == 0 && ov.source == 4)
            .map(|ov| {
                let pol = match ov.flags & 0b11 {
                    0b11 => narf_acpi::ioapic::POLARITY_LOW,
                    _ => narf_acpi::ioapic::POLARITY_HIGH,
                };
                let trig = match (ov.flags >> 2) & 0b11 {
                    0b11 => narf_acpi::ioapic::TRIGGER_LEVEL,
                    _ => narf_acpi::ioapic::TRIGGER_EDGE,
                };
                (ov.gsi, pol | trig)
            })
            .unwrap_or((
                4,
                narf_acpi::ioapic::POLARITY_HIGH | narf_acpi::ioapic::TRIGGER_EDGE,
            ));
        if let Ok(v) = narf_interrupts::vector::alloc() {
            narf_interrupts::install_handler(v, serial_isr);
            // SAFETY: vector + handler installed before
            // unmasking the IOAPIC entry + enabling IER.
            let routed =
                unsafe { narf_acpi::ioapic::route_gsi_to_vector(gsi, v, 0, flags) };
            if routed {
                narf_console::enable_rx_irq();
                let _ = writeln!(
                    console::Writer,
                    "  serial: IRQ 4 → GSI {} → vec {} (RX IRQ enabled)",
                    gsi, v
                );
            }
        }
    }

    // Helper: load + spawn one user binary. Both init and shell go
    // through the same path; the only difference is the argv[0]
    // string (which `__libc_start_main` consumes) and the binary
    // bytes. SysV-AMD64 demands a non-empty argv so the stack frame
    // (`argc | argv[0] | NULL | NULL | AT_NULL`) is well-formed —
    // the bare `load_user_process` shape leaves rsp past the mapped
    // stack and traps on the first `read [rsp]`.
    //
    // SAFETY: low-4-GiB identity map is live, frame allocator
    // initialised in `_start_rust`.
    fn spawn_one(name: &'static str, bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            let _ = writeln!(
                console::Writer,
                "  boot-init: {name}: ELF is empty — skipping"
            );
            return false;
        }
        let proc = match unsafe { load_user_process_with(bytes, &[name], &[], &[]) } {
            Ok(p) => p,
            Err(e) => {
                let _ = writeln!(
                    console::Writer,
                    "  boot-init: {name}: load_user_process_with failed: {e:?}"
                );
                return false;
            }
        };
        let pid = proc.pid;
        let entry = proc.entry.0.as_u64();
        let addr_space = proc.address_space.clone();
        let _ = writeln!(
            console::Writer,
            "  boot-init: spawning {name} pid={} entry={:#x}",
            pid.raw(),
            entry
        );
        let tid = narf_scheduler::spawn_user(
            UserTaskFuture::new(proc),
            narf_scheduler::TaskSpec::unthrottled(),
            addr_space,
        );
        // /proc/[pid]/cmdline + comm seed for the boot-spawned
        // process. argv = ["init"] / ["shell"] is the convention
        // load_user_process_with uses above.
        narf_userspace::handlers::set_proc_argv(tid.raw(), &[name]);
        narf_userspace::handlers::set_proc_comm(tid.raw(), name);
        // Slot 24 = init spawned (lime), slot 23 = shell spawned
        // (cyan). Lets the user see at a glance which user task
        // got past load_user_process_with on real silicon. Both
        // colours stick — no toggle — so a missing colour means
        // that user task never reached spawn.
        match name {
            "init" => narf_memory::beacon::paint(24, 0x0080_FF00),
            "shell" => narf_memory::beacon::paint(23, 0x0000_FFFF),
            _ => {}
        }
        true
    }

    // Try to load `/{name}` from whatever root filesystem is
    // mounted at "/". Returns the file's bytes (heap-allocated, the
    // caller hands them to `load_user_process_with` which copies
    // into the new AS), or None if the file is missing / the read
    // path errored / no root mount is present.
    //
    // The walk: registry().resolve_absolute strips the matching
    // mount prefix and hands the FsInstance + the rest of the path
    // to the closure; we then resolve_async against the FS root,
    // stat for the size, and read the body in one shot. Capped at
    // 16 MiB to bound the kernel-heap allocation in case the disk
    // returns a huge stat.
    async fn try_load_from_root(name: &'static str) -> Option<alloc::vec::Vec<u8>> {
        use alloc::sync::Arc;
        use alloc::vec::Vec;
        use narf_filesystem::{registry, resolve_async, DirOps};

        let abs = alloc::format!("/{}", name);
        // Pull `(root_dir, rel_path)` out under the registry lock so
        // we don't hold it across awaits.
        let pair: Option<(Arc<dyn DirOps>, alloc::string::String)> =
            registry().resolve_absolute(&abs, |fs, rel| {
                (fs.root(), alloc::string::String::from(rel))
            });
        let (root, rel) = pair?;
        let file = resolve_async(root, &rel).await.ok()?;
        let stat = file.stat_async().await.ok()?;
        let size = stat.size as usize;
        const MAX_BIN: usize = 16 * 1024 * 1024;
        if size == 0 || size > MAX_BIN {
            return None;
        }
        let mut out = Vec::<u8>::with_capacity(size);
        out.resize(size, 0);
        // Loop until EOF or buf full — FileOps::read may return
        // short on cross-cluster boundaries.
        let mut filled = 0usize;
        while filled < size {
            let n = file.read(filled as u64, &mut out[filled..]).await.ok()?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        out.truncate(filled);
        Some(out)
    }

    // Init is the canonical first user process; shell runs as a
    // peer (no fork/execve yet). Both reach `__libc_start_main`
    // now that `process::load_user_process_with` always stages a
    // synthetic TLS region for binaries without PT_TLS — the
    // previous startup `#PF` came from `mov %fs:[0]` against
    // `FS_BASE = 0`. Shell is still gated behind the
    // `boot-init` cargo feature.
    //
    // Spawn a kernel async task to do the FAT-root resolution +
    // user-task spawn. Prefer disk-loaded /init + /shell so the
    // binaries can be iterated without rebuilding the kernel; fall
    // back to the baked `narf_verification::*_ELF` blobs when the
    // disk version is missing (smoke-test images that haven't been
    // populated, real-HW first boot before initramfs lands).
    let baked_init: &'static [u8] = bytes;
    let baked_shell: &'static [u8] = narf_verification::NARF_SHELL_ELF;
    // Disk-load path (`try_load_from_root`) is skipped on real
    // silicon — it wedges in block-device I/O waiting for IRQs the
    // laptop isn't delivering. Baked ELF goes straight in. Re-wire
    // disk-load once the storage IRQ path is healthy on Zen2 FCH.
    let _ = try_load_from_root; // keep symbol referenced
    spawn_one("init", baked_init);
    spawn_one("shell", baked_shell);
}

/// aarch64 boot-init stub.
///
/// All the underlying primitives are now in place — `AddressSpace::activate`
/// issues the architected `MSR TTBR0_EL1` sequence,
/// `narf_arch::aarch64::user_mode::{enter_user_mode, enter_user_mode_resume}`
/// drop into EL0 via `eret`, the EL1 vector table routes synchronous /
/// IRQ / data-abort traps back through `frame::aarch64::trap`, and
/// `UserTaskFuture` polls the EL0↔EL1 round-trip. What's missing is
/// the plumbing wiring `userspace::loader::load_user_process_with` to
/// the aarch64 init/shell ELFs (the loader's PT_LOAD segment-walker is
/// arch-neutral, but the init/shell crates currently link against the
/// x86_64 testbin layout). Until that ELF-side work lands the boot-init
/// path stays a no-op so `cargo xtask run --arch=aarch64
/// --features boot-init` still links and boots the kernel proper.
#[cfg(all(feature = "boot-init", not(target_arch = "x86_64")))]
fn boot_userspace_init() {
    use core::fmt::Write as _;
    let _ = writeln!(
        console::Writer,
        "  boot-init: aarch64 ELF wiring pending (kernel EL0 path is live)"
    );
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    console::panic_sink(info)
}
