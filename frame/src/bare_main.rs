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
extern crate narf_drivers_crypto as _;
extern crate narf_drivers_fs_9p as _;
extern crate narf_drivers_fs_exfat as _;
extern crate narf_drivers_fs_ext2;
extern crate narf_drivers_fs_fat;
extern crate narf_drivers_fs_iso9660 as _;
extern crate narf_drivers_fs_minix as _;
extern crate narf_drivers_fs_squashfs;
extern crate narf_drivers_fs_udf as _;
extern crate narf_drivers_psp as _;
extern crate narf_edid as _;
extern crate narf_efi as _;
extern crate narf_hid as _;
extern crate narf_pinctrl as _;
extern crate narf_security as _;

use core::fmt::Write;
use core::panic::PanicInfo;

use narf_boot::{BootInfo, RawBootInfo};
use narf_console::{self as console, UartKind};
use narf_memory::{BumpAllocator, PhysAddr};

static mut RAW_BOOT_INFO: Option<RawBootInfo> = None;
static mut BOOT_INFO: Option<BootInfo> = None;

#[global_allocator]
static GLOBAL_ALLOC: BumpAllocator = BumpAllocator;

/// Monotonic timestamp (ns) at/after which kswapd may run its next pass.
/// The cadence is ADAPTIVE (set at the end of each pass), not a fixed
/// timer: relaxed when memory is healthy, tight under pressure. This
/// bounds how often the (buddy-locking) watermark probe runs when idle
/// while letting reclaim run nearly continuously under pressure.
static KSWAPD_NEXT_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Pages kswapd reclaims per online CPU per wake, as a floor. More CPUs
/// means more concurrent allocators building pressure, so kswapd must
/// shed a bigger batch to keep ahead of them.
const KSWAPD_PAGES_PER_CPU: usize = 64;

/// kswapd-analogue: proactive background page reclaim. Registered as a
/// `sleep_pumps` callback so it runs in cooperative executor (task, NOT
/// IRQ) context — safe to take the buddy lock while freeing reclaimed
/// frames.
///
/// Linux's kswapd is event-driven (the allocator wakes it when a zone
/// drops below its low watermark, and it reclaims until the zone is
/// balanced at the high watermark). NARF's cooperative model has no
/// wakeable kthread, so this polls from the executor's `sleep_pumps` —
/// but the WATERMARK, not a fixed timer, is the gate, and the poll
/// cadence adapts to pressure so behaviour approximates "reclaim until
/// balanced":
///
/// * healthy (free >= low): relaxed ~100 ms poll, LRU aging only;
/// * pressured (free < low): reclaim toward `high`, re-check in ~2 ms;
/// * emergency (free < min): reclaim now and re-run next pass.
///
/// The reclaim target scales with BOTH the free-memory deficit
/// (`reclaim_goal_pages` = high − free) and the online CPU count
/// (`KSWAPD_PAGES_PER_CPU` floor). Lives here (not in `memory`) because
/// the clock + CPU count come from `narf_scheduler`, which the low-level
/// `memory` crate does not depend on.
fn kswapd_pump() {
    use core::sync::atomic::Ordering;
    const IDLE_INTERVAL_NS: u64 = 100_000_000; // healthy: relax the poll
    const PRESSURE_INTERVAL_NS: u64 = 2_000_000; // under pressure: re-check ~2 ms

    let now = narf_scheduler::narf_time::monotonic_ns();
    let next = KSWAPD_NEXT_NS.load(Ordering::Relaxed);
    if now < next {
        return;
    }
    // Claim this tick (optimistically set the pressured cadence) so
    // concurrent executors don't all reclaim at once; the winner adjusts
    // the next-run time below based on what it observes.
    if KSWAPD_NEXT_NS
        .compare_exchange(
            next,
            now.saturating_add(PRESSURE_INTERVAL_NS),
            Ordering::AcqRel,
            Ordering::Relaxed,
        )
        .is_err()
    {
        return;
    }

    // Batch floor scales with the number of online CPUs (concurrent
    // allocators); the actual target also tracks the free-memory deficit.
    let cpu_floor =
        (narf_scheduler::online_cpu_set().len() as usize).saturating_mul(KSWAPD_PAGES_PER_CPU);

    if narf_memory::reclaim::under_min_watermark() {
        // Emergency: reclaim hard and re-run on the very next pass.
        let target = narf_memory::reclaim::reclaim_goal_pages().max(cpu_floor);
        narf_memory::reclaim::try_to_free(target);
        KSWAPD_NEXT_NS.store(now, Ordering::Relaxed);
    } else if narf_memory::reclaim::under_low_watermark() {
        // Pressured: reclaim toward the high watermark; the CAS above
        // already scheduled a prompt (~2 ms) re-check.
        let target = narf_memory::reclaim::reclaim_goal_pages().max(cpu_floor);
        narf_memory::reclaim::try_to_free(target);
    } else {
        // Healthy: just age the LRU and relax the poll cadence.
        narf_memory::reclaim::reclaim_sweep_pump();
        KSWAPD_NEXT_NS.store(now.saturating_add(IDLE_INTERVAL_NS), Ordering::Relaxed);
    }
}

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

mod canary;
mod cross_crate_init;
mod measure;
mod secure_boot;
/// SMP exercise for the JIT-text W^X seal. Lives here rather than in
/// `memory/` because it needs to pin a task to a peer CPU and the scheduler
/// sits above `narf-memory` in the dependency graph.
#[cfg(feature = "kernel-test")]
mod wx_smp;

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
    narf_memory::hotplug_node_for_phys(addr)
        .map(|node| node as u32)
        .unwrap_or_else(|| narf_acpi::memory_node(addr).unwrap_or(0))
}
#[unsafe(no_mangle)]
pub fn narf_cpu_to_node(cpu: u32) -> u32 {
    narf_acpi::cpu_node(cpu).unwrap_or(0)
}
#[unsafe(no_mangle)]
pub fn narf_node_distance(from: u32, to: u32) -> u32 {
    narf_acpi::node_distance(from, to) as u32
}
/// Online NUMA node count for sysfs/procfs/mempolicy consumers that
/// reach it through a weak hook (keeping filesystem/userspace off a
/// direct narf-acpi dep). Always >= 1.
#[unsafe(no_mangle)]
pub fn narf_numa_node_count() -> u32 {
    narf_acpi::numa_node_count().max(narf_memory::online_node_count())
}
/// CPU → NUMA node, returning `u32::MAX` when the CPU has no SRAT
/// proximity entry (so sysfs cpulist can distinguish "node 0" from
/// "unknown"). The `narf_cpu_to_node` hook above collapses that to 0.
#[unsafe(no_mangle)]
pub fn narf_cpu_node_opt(cpu: u32) -> u32 {
    narf_acpi::cpu_node(cpu).unwrap_or(u32::MAX)
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
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
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
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Valid memory or trusted environment
    let wc_slot = unsafe { narf_arch::x86_64::mtrr::set_write_combining(mtrr_phys, pow2) };
    #[cfg(not(target_arch = "x86_64"))]
    let wc_slot: Option<u32> = None;
    let _ = mtrr_phys;

    // SAFETY: BSP, no concurrent draw; FB phys is identity-mapped
    // (verified above to be < 4 GiB).
    // SAFETY: Valid memory or trusted environment
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

/// PCID domain-enforcer setup: enable CR4.PCIDE, snapshot the kernel
/// bootstrap PML4, and allocate + register one private PML4 (with its
/// per-domain PDPT) for each of the 16 domains.
///
/// This MUST run AFTER the MMU handoff (`init_mmu` installs the final
/// kernel PML4 and rewrites CR3) and AFTER the buddy allocator is
/// populated from the memory map (`init_from_map`): `pcid::init`
/// snapshots CR3 as the bootstrap PML4, and `new_user_pml4_on` both
/// reads CR3 to clone the kernel half AND needs a live buddy to get
/// frames. Running it in the early-features block (before the handoff)
/// snapshotted the bootloader's stale PML4 and hit an empty buddy, so
/// every clone failed → 0 domains registered → strict isolation silently
/// degraded to the shared-bootstrap fallback (only observable under PCID,
/// i.e. KVM / real silicon — TCG CI never enables it).
#[cfg(target_arch = "x86_64")]
fn setup_pcid_domains() {
    // SAFETY: PCID is a baseline long-mode feature; the post-handoff CR3
    // has PCID==0 (init_mmu wrote a clean CR3), as enable_pcide requires.
    unsafe {
        narf_arch::x86_64::pcid::enable_pcide();
        narf_arch::x86_64::pcid::init();
    }
    // Spread domain D's PML4 onto NUMA node (D % num_nodes) for locality.
    let num_nodes = if narf_memory::is_numa_aware() {
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
    narf_memory::asid_alloc::allocator_init();
    narf_memory::per_domain_root::init();
    let mut registered = 0u8;
    for domain in 0u8..16 {
        let node = (domain as usize) % num_nodes;
        // SAFETY: paging on, buddy populated, identity map covers low frames.
        match unsafe { narf_memory::paging::new_user_pml4_on(node) } {
            Ok(phys) => {
                // SAFETY: domain<16; phys is a valid 4 KiB frame.
                unsafe {
                    narf_arch::x86_64::pcid::set_domain_pml4(domain, phys.raw());
                }
                let _ = narf_memory::per_domain_root::register_root(
                    narf_lib::id::DomainId::new(domain),
                    phys.raw(),
                );
                registered += 1;
            }
            Err(_) => break,
        }
    }
    // SAFETY: pcid::init has run; PML4s are registered; identity map covers
    // low frames.
    let private_pdpts = unsafe { narf_memory::domain::init_per_domain_pdpts() }.unwrap_or_default();
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start_rust(raw: RawBootInfo) -> ! {
    // Status-panel diag: first non-firmware phase. set_phase is a
    // single atomic store — safe from very-early boot before any
    // allocator is alive.
    narf_memory::diag::set_phase(narf_memory::diag::BootPhase::StartRust);
    #[cfg(target_arch = "x86_64")]
    let _early_fb: Option<narf_boot::info::FramebufferInfo> = {
        if raw.magic == narf_boot::x86_64::multiboot2::BOOT_MAGIC {
            let info_ptr = raw.payload.raw() as usize;
            // SAFETY: `raw.magic` just matched `BOOT_MAGIC`, so the
            // bootloader contract guarantees `payload` points at the
            // multiboot2 info struct that `framebuffer` walks.
            // SAFETY: Valid memory or trusted environment
            unsafe { narf_boot::x86_64::multiboot2::framebuffer(info_ptr) }
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
        // SAFETY: Valid memory or trusted environment
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
            cpuval.smep,
            cpuval.cr4_smep_on,
            cpuval.smap,
            cpuval.cr4_smap_on,
            cpuval.xsave,
            cpuval.cr4_osxsave_on,
            cpuval.efer_lme_on,
            cpuval.efer_nxe_on,
            cpuval.cr4_pae_on,
            cpuval.cr4_fsgsbase_on,
            cpuval.invariant_tsc,
        );
        match fatal {
            None => {}
            Some(why) => {
                let _ = writeln!(console::Writer, "  cpu-validate: FATAL — {}", why);
                // Halt with CLI+HLT loop so the operator sees the
                // message instead of crashing into a userspace
                // fault five stages later.
                #[allow(clippy::empty_loop)]
                loop {
                    // SAFETY: CLI + HLT at CPL=0 is the canonical
                    // "stop here, IRQ-quiet" idle.
                    // SAFETY: Valid memory or trusted environment
                    unsafe {
                        core::arch::asm!("cli; hlt", options(nomem, nostack));
                    }
                }
            }
        }
    }

    // Apply the protected boot policy on the BSP itself. The API is
    // current-CPU scoped so future per-core policy changes cannot silently
    // weaken siblings. APs repeat this before becoming scheduler-visible.
    // SAFETY: privileged boot context; no untrusted task can run yet.
    let speculation_state = unsafe {
        narf_arch::speculation::configure_current_cpu(narf_arch::speculation::Policy::Protected)
    };
    assert!(
        speculation_state != narf_arch::speculation::State::Failed,
        "speculation-control transition failed on BSP"
    );

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
            // SAFETY: Valid memory or trusted environment
            unsafe {
                smep::enable();
            }
        }
        // SMAP — fault on data access to a U=1 page from CPL=0 outside
        // an EFLAGS.AC bracket. Same shape.
        if smap::supported() {
            // SAFETY: SMAP supported; CR4.21 flip is benign here.
            unsafe {
                smap::enable();
            }
        }
        // SSE / FXSR — required for SSE2 instruction execution. SSE2
        // is architectural on x86_64 so no CPUID gate; CR4.OSFXSR
        // (bit 9) is the OS opt-in that makes `movq %xmm0` etc.
        // legal. Without it, a musl-static binary's TLS init memcpy
        // (`movq %rbx, %xmm0`) raises #UD and the task dies with
        // SIGILL before reaching main. CR4.OSXMMEXCPT (bit 10) is
        // intentionally NOT flipped — it requires a #XF (vec 19)
        // IDT handler which NARF doesn't have, and an unhandled
        // SIMD-FP exception cascades into #DF (observed in CI's
        // TCG emulation, masked on KVM-accelerated hosts). The
        // #XF handler + OSXMMEXCPT flip land together.
        // SAFETY: CPL=0; SSE2 is architectural.
        unsafe {
            narf_arch::x86_64::sse::enable();
            let mut cr4 = narf_arch::x86_64::cr::read_cr4();
            cr4 |= narf_arch::x86_64::cr::CR4_OSXSAVE;
            narf_arch::x86_64::cr::write_cr4(cr4);
            narf_arch::x86_64::xsave::enable_default();
            // Select the per-task FPU save method now that XCR0 is set:
            // XSAVE/XRSTOR of the full enabled state (AVX/AVX-512) when the
            // CPU supports it, else the FXSAVE fallback. Without this, AVX-512
            // (zmm) state is lost across a context switch — glibc, which uses
            // zmm in startup, then faults on a corrupted pointer.
            narf_arch::x86_64::xsave::init_task_fpu();

            let c = narf_arch::x86_64::xsave::caps();
            let enabled = narf_arch::x86_64::xsave::read_xcr0();
            let _ = core::fmt::Write::write_fmt(
                &mut console::Writer,
                core::format_args!(
                    "  xsave: supported={:x} enabled={:x} avx={} avx512={}\n",
                    c.xcr0_supported,
                    enabled,
                    enabled & narf_arch::x86_64::xsave::XSAVE_AVX != 0,
                    enabled & narf_arch::x86_64::xsave::XSAVE_AVX512_GROUP
                        == narf_arch::x86_64::xsave::XSAVE_AVX512_GROUP
                ),
            );
        }
        // KPTI detect — Renoir + Phoenix come back Posture::Native and
        // we skip the dual-CR3 dance entirely. Log the decision once.
        let pti = kpti::detect();
        let _ = writeln!(
            console::Writer,
            "  hardening: SMEP={} SMAP={} KPTI={:?} SPEC={:?}",
            smep::is_enabled(),
            smap::is_enabled(),
            pti,
            speculation_state,
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
        // SAFETY: CPUID is always legal at CPL=0.
        let feats = unsafe { narf_arch::x86_64::Features::probe() };
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
        // CR3 swap with PCID-preserve, plus per-domain PML4 *divergence*
        // (strict isolation) wired in `setup_pcid_domains()` after the MMU
        // handoff. PKS is armed here; PCID is deferred (see below).
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
        }
        // PCID enforcer setup (the !PKS fallback) is DEFERRED to
        // `setup_pcid_domains()`, called AFTER the MMU handoff + buddy
        // populate further down. Doing it here snapshotted the stale
        // bootloader PML4 and hit an empty buddy → 0 domains registered.
        // See setup_pcid_domains() for the full ordering rationale.

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
            brand,
            cpu.vendor,
            cpu.family,
            cpu.model,
            cpu.stepping
        );
        // SAFETY: CPL=0; per-entry SAFETY notes apply; gated by
        // vendor/family/model match.
        // SAFETY: Valid memory or trusted environment
        let (applied, n) = unsafe { narf_arch::x86_64::errata::apply_for_current_cpu() };
        if n == 0 {
            let _ = writeln!(console::Writer, "  errata: no entries matched this CPU");
        } else {
            let _ = writeln!(console::Writer, "  errata: applied {} entries:", n);
            for e in &applied[..n] {
                let _ = writeln!(console::Writer, "    - {}", e);
            }
        }

        // LAPIC init — always runs. `init_bsp` first tries x2APIC
        // mode (MSR-based access); on platforms where the BIOS
        // refuses the IA32_APIC_BASE.EXTD bit (some AMD silicon,
        // QEMU TCG without explicit `+x2apic`) it falls back to
        // xAPIC MMIO mode. Either path leaves the LAPIC in a known
        // state with SIVR enabled, every LVT masked except
        // LVT_ERROR, and the diagnostic handlers installed — all
        // load-bearing for the first `sti` not delivering a
        // BIOS-time stale-vector IRQ into an unhandled slot and
        // cascading into #DF.
        //
        // The previous gate (`if feats.x2apic`) skipped the entire
        // block on TCG / non-x2APIC hosts, leaving the LAPIC in
        // its BIOS-default state — CI's #DF after `tsc: calibrated`
        // was the consequence.
        //
        // SAFETY: CPL=0; LAPIC is always present on long-mode
        // x86_64 silicon; init_bsp handles both x2APIC and xAPIC
        // paths internally.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            narf_interrupts::x86_64::apic::init_bsp();
        }
        let x2apic_active = narf_interrupts::x86_64::apic::X2APIC_ACTIVE
            .load(core::sync::atomic::Ordering::Acquire);
        let _ = writeln!(
            console::Writer,
            "  apic: {} active, 8259 PICs masked",
            if x2apic_active { "x2APIC" } else { "xAPIC" }
        );
        // TLB-shootdown IPI fan-out — requires x2APIC for ICR MSR
        // writes. Skipped under xAPIC fallback; cross-CPU
        // invalidation falls back to the per-CPU INVLPG only.
        if x2apic_active {
            // Install the TLB-shootdown IPI handler now — APs may
            // call shoot_va once they come up, and the handler must
            // be live before the first IPI lands.
            narf_interrupts::x86_64::ipi::install();
            // Reschedule IPI: handler (a no-op — being interrupted is the
            // point) + the scheduler's sender hook. A cross-core waker uses
            // this to un-halt an idle owner CPU immediately instead of
            // waiting out its next timer tick (the cross-core wake tail).
            narf_interrupts::install_resched_ipi();
            narf_scheduler::set_resched_ipi_hook(|cpu| {
                narf_interrupts::x86_64::apic::send_fixed_ipi(
                    1u64 << cpu,
                    narf_interrupts::VECTOR_RESCHED,
                );
            });
            // Idle-halt LOST-WAKEUP backstop: let the executor arm a short
            // fallback LAPIC deadline before HLT so a halted AP always
            // re-scans within a bounded time even if a cross-core wake is
            // lost. `arm_tsc_deadline_if_earlier` only pulls the deadline
            // IN, never pushes it out, so it can't delay a sooner real wake.
            narf_scheduler::set_idle_backstop_hook(|deadline| {
                narf_interrupts::x86_64::apic::arm_tsc_deadline_if_earlier(deadline);
            });
            // Per-task kernel-stack retargeting (Linux `update_task_stack`):
            // points TSS.rsp0 + SYSCALL gs:[8] at the running user task's own
            // kernel stack so a trap/syscall lands there, not on a shared
            // per-CPU stack. DORMANT until the scheduler wires it in (Stage 2);
            // `top==0` restores the per-CPU baseline.
            narf_scheduler::set_kernel_stack_hook(super::x86_64::gdt::set_task_kernel_stack);
            // Reader counterpart: lets `poll_to_yield` snapshot the live rsp0 so a
            // nested poll restores the OUTER task's stack top, not the baseline.
            narf_scheduler::set_get_kernel_stack_hook(super::x86_64::percpu::kernel_stack_top);
            // Wire the memory subsystem's `invlpg_global` to
            // broadcast through this IPI surface. After this call,
            // every unmap_4kb fans out to peer CPUs.
            narf_memory::paging::set_shootdown_hook(|va| {
                // SAFETY: x2APIC online, IPI handler installed.
                // tag=0 → handler uses plain INVLPG (this hook fires
                // from kernel-side mapping mutations that don't know
                // which PCID owns the entry).
                // SAFETY: Valid memory or trusted environment
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
            // Full-flush hook: one IPI for a whole-address-space batch
            // invalidation (fork COW WRITE-strip, exit teardown) — the
            // Linux flush_tlb_mm shape. Without it those paths paid a
            // per-page broadcast + ack-wait, which made every fork of a
            // large process take ~0.5 s (stress-ng --sigrt's "hang").
            narf_memory::paging::set_full_shootdown_hook(|| {
                // SAFETY: x2APIC online, IPI handler installed.
                unsafe {
                    narf_interrupts::x86_64::ipi::shoot_full();
                }
            });
            // Install the unified `narf_memory::tlb_shootdown::shootdown`
            // → IPI fan-out hook so the asid/pcid-isolation surface
            // also benefits from cross-CPU dispatch.
            narf_interrupts::install_tlb_shootdown_bridge();
            // Let a CPU spinning on an IrqSafeSpinLock (IRQs masked) drain a
            // shootdown a peer published to it — otherwise the peer's ack-wait
            // would spin to its cap and give up, stranding a stale TLB on a
            // shared address space. Only meaningful with the IPI surface live
            // (i.e. x2APIC), which is exactly this block.
            narf_lib::sync::set_lock_spin_hook(|| {
                // SAFETY: CPL=0; poll_pending_shootdown only consumes this
                // CPU's pending shootdown cells and INVLPGs.
                unsafe {
                    narf_interrupts::x86_64::ipi::poll_pending_shootdown();
                }
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
        // SAFETY: Valid memory or trusted environment
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
            // SAFETY: Valid memory or trusted environment
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
                // SAFETY: Valid memory or trusted environment
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

            // KASAN: reserve a flat shadow byte-array (1 byte / 8 memory
            // bytes) covering [0, ram_top) out of the buddy, so the software
            // outline check (memory/src/kasan.rs) can poison freed slab
            // blocks. Carved from the largest usable region's tail and kept
            // out of the buddy via `excludes`; it is identity-mapped once the
            // MMU comes up below, then zeroed + armed. `init`/`arm` run after
            // `release_early_ceiling` so the mapping is guaranteed live.
            #[cfg(feature = "kasan")]
            let kasan_shadow: Option<(u64, u64)> = {
                let ram_top = regions
                    .iter()
                    .map(|r| r.start.raw() + r.len)
                    .max()
                    .unwrap_or(0);
                let ps = narf_memory::PAGE_SIZE;
                let shadow_len = ((ram_top >> 3) + ps - 1) & !(ps - 1);
                // Carve from the LOWEST-start region that fits, not the
                // largest: on a 2-node machine the largest region is the high
                // NUMA node, and gutting its tail starves that node's local
                // allocations (SRAT setup then OOMs with GiB still free). The
                // low region is node 0, which the kernel already lives in.
                let biggest = regions
                    .iter()
                    .filter(|r| r.len >= shadow_len && shadow_len > 0)
                    .min_by_key(|r| r.start.raw());
                match biggest {
                    Some(r) => {
                        let shadow_phys = (r.start.raw() + r.len - shadow_len) & !(ps - 1);
                        excludes.push((shadow_phys, shadow_phys + shadow_len));
                        let _ = writeln!(
                            console::Writer,
                            "  kasan: shadow {} MiB reserved @ {:#x} (ram_top {:#x})",
                            shadow_len / (1024 * 1024),
                            shadow_phys,
                            ram_top
                        );
                        Some((ram_top, shadow_phys))
                    }
                    _ => {
                        let _ = writeln!(
                            console::Writer,
                            "  kasan: DISABLED — no region fits {} MiB shadow",
                            shadow_len / (1024 * 1024)
                        );
                        None
                    }
                }
            };

            // SAFETY: first call, BSP, memory map came from parse_raw
            // which validated magic + min-RAM.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                narf_memory::init_from_map(&regions, &excludes);
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

            // Size the file page-cache reclaim from RAM (Linux-shaped): let
            // the cache grow to ~half of RAM as a hard backstop, but reclaim
            // clean pages once free memory falls below ~3% of total so the
            // *watermark*, not a fixed cap, is the primary limiter. Sized here
            // because total RAM is only known after the frame allocator inits.
            narf_filesystem::page_cache::set_default_capacity_pages(s.total / 2);
            narf_filesystem::page_cache::set_low_watermark_pages(s.total / 32);

            // Install the central reclaim watermarks (min/low/high) from total
            // RAM — the single free-memory pressure signal the reclaim
            // subsystem (direct reclaim, future kswapd) keys off. See
            // memory/src/reclaim.rs. Sized here for the same reason as above.
            narf_memory::reclaim::init_watermarks(s.total);
            // Start the kswapd-analogue: proactive background reclaim on the
            // cooperative executor (sleep_pumps), rate-limited to ~100 ms, so
            // memory pressure is relieved BEFORE an allocation fails rather
            // than only reactively in the alloc-failure path.
            narf_scheduler::sleep_pumps::register(kswapd_pump);

            // MMU handoff per console/ §3.1. The three-step sequence
            // (print, swap, remap) is orchestrated here because
            // memory/ can't depend on console/ without creating a
            // crate cycle. Closes Stage 1 exit-gate #2.
            #[cfg(target_arch = "x86_64")]
            {
                let _ = writeln!(console::Writer, "  mmu: handoff...");
                // Top of installed RAM — the high-half kernel direct map
                // is sized to cover [0, max_ram_phys) so frames above
                // 512 GiB (which the low identity map can't reach) are
                // still accessible via PhysAddr::kernel_mut_ptr.
                let max_ram_phys = info
                    .memory_map
                    .iter()
                    .filter(|r| r.kind == narf_boot::MemRegionKind::Usable)
                    .map(|r| r.start.raw() + r.len)
                    .max()
                    .unwrap_or(0);
                // SAFETY: BSP, interrupts disabled (boot.S CLI + IDT
                // doesn't unmask), allocator populated above.
                // SAFETY: Valid memory or trusted environment
                match unsafe { narf_memory::mmu::init_mmu(max_ram_phys) } {
                    Ok(pml4) => {
                        // The new PML4 identity-maps 0..512 GiB, so the
                        // UART (I/O port on x86_64) is reachable and
                        // console::remap_to_virtual with an identity
                        // address is correct.
                        narf_console::remap_to_virtual(info.uart_virt);
                        let _ = writeln!(
                            console::Writer,
                            "  mmu: installed, PML4 @ {:?}, console remapped",
                            pml4
                        );
                        // Supervisor stores ignore the read-only bit unless
                        // CR0.WP is set (Intel SDM Vol 3 §4.6.1), and boot.S
                        // only ever set CR0.PG — measured CR0 at this point
                        // was 0x80000011, WP=0. Every read-only kernel
                        // mapping in this tree was therefore advisory. Set it
                        // here, on the BSP, immediately after the CR3 handoff
                        // and while the console is live, so a latent write
                        // through a read-only mapping surfaces as a
                        // diagnosable fault rather than silent corruption.
                        // `_ap_start_rust` does the same for each AP — WP is
                        // per-CPU state.
                        // SAFETY: CPL=0, on the BSP, single-threaded.
                        unsafe {
                            narf_memory::text_poke::enable_write_protect();
                        }

                        // The kernel direct map now covers all installed
                        // RAM (the low 512 GiB identity window), so the
                        // frame allocator may hand out frames above 4 GiB.
                        // Drop the early phys ceiling that kept pre-MMU
                        // allocations inside boot.S's 4 GiB identity map;
                        // without this, RAM relocated above the q35 PCI
                        // hole (QEMU -m ≥ 4G, real 16 GiB laptops) stays
                        // permanently unusable.
                        narf_memory::release_early_ceiling();
                        let s = narf_memory::frame_stats();
                        let _ = writeln!(
                            console::Writer,
                            "  frames: ceiling released, {} MiB free now allocatable",
                            (s.free as u64) * narf_memory::PAGE_SIZE / (1024 * 1024)
                        );

                        // KASAN: the reserved shadow span is now identity-
                        // mapped (init_mmu covers [0, max_ram_phys)). Zero it
                        // and arm poisoning so freed slab blocks start being
                        // tracked from here on.
                        #[cfg(feature = "kasan")]
                        if let Some((ram_top, shadow_phys)) = kasan_shadow {
                            // SAFETY: [shadow_phys, shadow_phys + ram_top/8) was
                            // reserved out of the buddy above and is identity-
                            // mapped RW by init_mmu.
                            unsafe { narf_memory::kasan::init(ram_top, shadow_phys) };
                            narf_memory::kasan::arm();
                            let _ = writeln!(console::Writer, "  kasan: armed");
                        }

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

                // BPF kernel-VA windows. MUST run here: after the MMU handoff
                // (CR3 is the final kernel PML4) and BEFORE the first
                // `new_user_pml4`, which `setup_pcid_domains()` immediately
                // below is. `new_user_pml4_on` snapshot-copies PML4[256..511]
                // BY VALUE and nothing propagates later changes, so a BPF slot
                // first populated after a user address space exists leaves
                // that AS's CR3 holding a zero entry — and the first BPF
                // access taken while that task is current triple-faults. This
                // is a direct call rather than a staged initcall precisely
                // because the ordering is too load-bearing to delegate.
                // `bpf/specification/spec.md` §4.1.
                match narf_memory::bpf_text::reserve_kernel_slots() {
                    Ok(()) => {
                        let _ = writeln!(
                            console::Writer,
                            "  bpf: kernel VA slots reserved (text {:#x}, arena {:#x})",
                            narf_memory::bpf_text::BPF_TEXT_BASE,
                            narf_memory::bpf_text::BPF_ARENA_BASE
                        );
                    }
                    Err(e) => {
                        let _ = writeln!(console::Writer, "  bpf: slot reservation failed: {e:?}");
                    }
                }

                // Per-domain PCID PML4s — deferred here, AFTER the MMU
                // handoff (CR3 is now the final kernel PML4) and the buddy
                // populate, so the clones snapshot the right PML4 from a live
                // allocator. PKS systems already armed their enforcer in the
                // features block above; only the PCID fallback needs this.
                // SAFETY: a single CPUID read, legal at CPL=0.
                if !unsafe { narf_arch::x86_64::Features::probe() }.pks {
                    setup_pcid_domains();
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
                        // SAFETY: Valid memory or trusted environment
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
                                // SLIT is the distance matrix; parse it
                                // alongside SRAT so node_distance() reflects
                                // the firmware-advertised locality costs.
                                // Absence is normal (Linux falls back to
                                // 10/20); only log on success.
                                // SAFETY: same validated RSDP as parse_srat.
                                match unsafe { narf_acpi::parse_slit(p) } {
                                    Ok(loc) => {
                                        let _ = writeln!(
                                            console::Writer,
                                            "  acpi: SLIT parsed, {} localities (d(0,1)={})",
                                            loc,
                                            narf_acpi::node_distance(0, 1)
                                        );
                                    }
                                    Err(e) => {
                                        let _ = writeln!(
                                            console::Writer,
                                            "  acpi: SLIT parse skipped: {:?} (10/20 distance fallback)",
                                            e
                                        );
                                    }
                                }
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
                            let (spill_regions, spill_bytes) = narf_memory::heap_spill_stats();
                            let _ = writeln!(
                                console::Writer,
                                "  heap: promoting bump→slab (bootstrap used: {} / {} bytes, \
                                 spill: {} region(s) / {} KiB)",
                                narf_memory::heap::used_bytes(),
                                narf_memory::heap::capacity_bytes(),
                                spill_regions,
                                spill_bytes / 1024,
                            );
                            narf_memory::heap::promote_to_slab();
                            // Status-panel diag: heap is live; mark
                            // the phase so the bare-metal status
                            // panel transitions out of StartRust.
                            narf_memory::diag::set_phase(narf_memory::diag::BootPhase::HeapUp);
                            let _ = writeln!(console::Writer, "  heap: slab is live");
                            let n_nodes = narf_acpi::node_count().max(1) as usize;
                            let mut totals = 0usize;
                            for i in 0..n_nodes.min(narf_memory::FRAME_MAX_NUMA_NODES) {
                                let f = narf_memory::node_free(i);
                                totals += f;
                                let _ =
                                    writeln!(console::Writer, "    node {}: {} free frames", i, f);
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
                                let _ =
                                    writeln!(
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
                                for node in 0..narf_acpi::numa_node_count()
                                    .min(narf_memory::FRAME_MAX_NUMA_NODES as u32)
                                {
                                    let bandwidth = narf_acpi::hmat_value(
                                        narf_acpi::HmatLatBwKind::AccessBandwidth,
                                        0,
                                        node,
                                        node,
                                    )
                                    .or_else(|| {
                                        let read = narf_acpi::hmat_value(
                                            narf_acpi::HmatLatBwKind::ReadBandwidth,
                                            0,
                                            node,
                                            node,
                                        )?;
                                        let write = narf_acpi::hmat_value(
                                            narf_acpi::HmatLatBwKind::WriteBandwidth,
                                            0,
                                            node,
                                            node,
                                        )?;
                                        Some(read.min(write))
                                    })
                                    .unwrap_or(0);
                                    if bandwidth != 0 {
                                        let _ = narf_memory::set_interleave_bandwidth(
                                            node as usize,
                                            bandwidth,
                                        );
                                    }
                                    let latency = narf_acpi::hmat_value(
                                        narf_acpi::HmatLatBwKind::AccessLatency,
                                        0,
                                        node,
                                        node,
                                    )
                                    .unwrap_or(0);
                                    if bandwidth != 0 || latency != 0 {
                                        let _ = narf_memory::set_node_performance(
                                            node as usize,
                                            bandwidth,
                                            latency,
                                        );
                                    }
                                }
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
                                let _ =
                                    writeln!(console::Writer, "  acpi: DMAR parsed, {} DRHD(s)", n);
                            }
                            Err(e) => {
                                let _ = writeln!(
                                    console::Writer,
                                    "  acpi: DMAR parse skipped: {:?}",
                                    e
                                );
                            }
                        }
                        let _ = writeln!(console::Writer, "  aml: parsing namespace...");
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
                                        a,
                                        b
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
                                    let hid = narf_aml::device_hid(&n.path).unwrap_or_default();
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
                                        let hid = narf_aml::device_hid(&n.path).unwrap_or_default();
                                        let _ = writeln!(
                                            console::Writer,
                                            "    dev: {} (HID={:?})",
                                            n.path,
                                            hid
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
                        // SAFETY: `p` is the same validated RSDP pointer
                        // accepted by `parse_ecdt` just above.
                        // SAFETY: Valid memory or trusted environment
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
                    // SAFETY: `ecam_phys` is the ECAM base reported by the
                    // ACPI MCFG table; the frame allocator is online and
                    // the bootloader handoff invariants hold at this point.
                    // SAFETY: Valid memory or trusted environment
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
                        // SAFETY: Valid memory or trusted environment
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
                    // BSP-only topology summary. Same as the SMP
                    // path below but with no APs to count.
                    let bsp_ty = narf_lib::percpu::cpu_type(0);
                    let n_p = narf_lib::percpu::count_cpu_type(narf_lib::percpu::CpuType::Core);
                    let n_e = narf_lib::percpu::count_cpu_type(narf_lib::percpu::CpuType::Atom);
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
                    // SAFETY: Valid memory or trusted environment
                    let started = unsafe { x86_64::smp::start_aps() };
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
                    let n_p = narf_lib::percpu::count_cpu_type(narf_lib::percpu::CpuType::Core);
                    let n_e = narf_lib::percpu::count_cpu_type(narf_lib::percpu::CpuType::Atom);
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
                        let _ = writeln!(console::Writer, "  smp: work-stealing enabled");
                        // User-task SMP migration — gated on the
                        // `user-task-smp` feature (in frame's default set).
                        // The per-CPU AP hardware setup is unconditional; this
                        // gate is only the runtime *migration* enable.
                        // The dynamic-linker / shootdown deadlock + AP
                        // EFER/CR4 gaps are fixed, so we actually enable
                        // migration here. Still gated on x2APIC: the cross-CPU
                        // TLB-shootdown broadcast hook is only wired when
                        // x2APIC is active (see the `set_shootdown_hook` block
                        // above); under the xAPIC fallback unmap/mprotect
                        // can't invalidate peer TLBs, so a thread group
                        // sharing an address space across cores would
                        // use-after-unmap — there we leave tasks BOOT-pinned.
                        #[cfg(feature = "user-task-smp")]
                        {
                            let x2apic_active = narf_interrupts::x86_64::apic::X2APIC_ACTIVE
                                .load(core::sync::atomic::Ordering::Acquire);
                            if x2apic_active {
                                narf_scheduler::enable_user_task_smp();
                                let _ = writeln!(
                                    console::Writer,
                                    "  smp: user-task SMP enabled (TLB shootdown wired)"
                                );
                            } else {
                                let _ = writeln!(
                                    console::Writer,
                                    "  smp: user-task SMP disabled (xAPIC — no cross-CPU \
                                     TLB shootdown); user tasks stay BOOT-pinned"
                                );
                            }
                        }
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

                // BPF kernel-VA windows — same call as the x86_64 arm above.
                // aarch64 does not have the PML4-snapshot hazard (user space
                // lives in TTBR0, the kernel in TTBR1, separate roots), but the
                // windows still have to exist before anything maps into them,
                // and keeping one call site shape across arches means the
                // ordering rule is stated once.
                match narf_memory::bpf_text::reserve_kernel_slots() {
                    Ok(()) => {
                        let _ = writeln!(
                            console::Writer,
                            "  bpf: kernel VA slots reserved (text {:#x}, arena {:#x})",
                            narf_memory::bpf_text::BPF_TEXT_BASE,
                            narf_memory::bpf_text::BPF_ARENA_BASE
                        );
                    }
                    Err(e) => {
                        let _ = writeln!(console::Writer, "  bpf: slot reservation failed: {e:?}");
                    }
                }

                // Bus enumeration. The DTB pointer comes through
                // `BootInfo`; if QEMU's `-kernel` path didn't supply
                // one, the walker falls back to the QEMU virt
                // virtio-mmio defaults.
                // SAFETY: DTB blob is in identity-mapped low RAM;
                // reads validate magic before trusting offsets.
                // SAFETY: Valid memory or trusted environment
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
                if let Some(dtb) = info.dtb_phys {
                    // SAFETY: the bus walker already validated this live,
                    // identity-mapped firmware blob.
                    if let Some(ppi) = unsafe { narf_bus::aarch64::discover_pmu_ppi(dtb) } {
                        if narf_interrupts::aarch64::gic::configure_pmu_ppi(ppi).is_ok() {
                            let _ = writeln!(
                                console::Writer,
                                "  pmu: firmware-routed PPI {} enabled",
                                ppi
                            );
                        }
                    }
                }

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
                // SAFETY: Valid memory or trusted environment
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
                // SAFETY: Valid memory or trusted environment
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
                    let _ = writeln!(console::Writer, "  smp: work-stealing enabled");
                }

                // Promote bump arena to slab allocator so allocations/deallocations
                // are managed dynamically and avoid static bump arena exhaustion.
                {
                    narf_memory::reserve_for_slab_promotion();
                    let _ = writeln!(
                        console::Writer,
                        "  heap: promoting bump→slab (bootstrap used: {} / {} bytes)",
                        narf_memory::heap::used_bytes(),
                        narf_memory::heap::capacity_bytes()
                    );
                    narf_memory::heap::promote_to_slab();
                    narf_memory::diag::set_phase(narf_memory::diag::BootPhase::HeapUp);
                    let _ = writeln!(console::Writer, "  heap: slab is live");
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

            // BPF: collect and validate the `narf.kfuncs` link section.
            // `Subsys` because collection allocates; the boot-order
            // constraint that actually matters for BPF — reserving the
            // kernel-VA slots *before* the first user address space
            // (`bpf/specification/spec.md` §4.1) — is a direct call, not an
            // initcall, and arrives with the arena work.
            narf_bpf::register_initcalls();
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
            narf_drivers_video::register_initcalls();
            narf_drivers_media::register_initcalls();
            narf_drivers_thunderbolt::register_initcalls();
            narf_drivers_fingerprint::register_initcalls();
            narf_drivers_fs_ext2::register_initcalls();
            narf_drivers_fs_ext4::register_initcalls();
            narf_drivers_fs_fat::register_initcalls();
            narf_drivers_fs_squashfs::register_initcalls();
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
                    let _ = writeln!(console::Writer, "  acpi: power button → entering S5");
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
                    #[allow(static_mut_refs)]
                    // TODO(narf): migrate this boot-time static to addr_of!/OnceCell
                    // SAFETY: Valid memory or trusted environment
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
                        // SAFETY: `r` is the live `&RawBootInfo` handed in
                        // by the bootloader; the slice spans exactly its
                        // `size_of::<RawBootInfo>()` bytes for measuring.
                        // SAFETY: Valid memory or trusted environment
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
                        // SAFETY: Valid memory or trusted environment
                        let res = unsafe { measure::measure_initramfs(r.start.raw(), r.len).await };
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
                    let reachable =
                        narf_graphics_driver::bochs::with_controller(|d| d.fb_reachable())
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
                // SAFETY: running on the BSP with no concurrent draw, and
                // the bochs guard above ensured the pixel buffer is
                // reachable; `framebuffer()` wraps that live mapping.
                // SAFETY: Valid memory or trusted environment
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
                #[cfg(target_arch = "x86_64")]
                let attrs = MmioAttrs::WriteCombining;
                #[cfg(not(target_arch = "x86_64"))]
                let attrs = MmioAttrs::Device;
                // SAFETY: `phys`/`len` cover the FB region registered by
                // Limine/UEFI and owned exclusively kernel-side; ioremap
                // maps it into a fresh vmalloc range with `attrs`.
                // SAFETY: Valid memory or trusted environment
                let m = match unsafe { ioremap(phys, len, attrs) } {
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
                // Rebase the installed FbConsole's internal
                // Framebuffer to the WC virt. Without this the
                // FbConsole keeps writing to the old uncached
                // identity-mapped phys — text scroll stays
                // glacial. The rebase is in-place, doesn't
                // wipe scrollback, doesn't move the cursor.
                // SAFETY: WC virt covers stride*height*4 bytes
                // (ioremap rounded `len` to that); the mapping
                // lives until iounmap which we never call.
                // SAFETY: Valid memory or trusted environment
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
                let has_root_eq =
                    narf_filesystem::root_selector::RootSelector::from_cmdline(cmdline).is_some();

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
                            report.fs_type,
                            report.device_name
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

            // Wave-50: secondary mount at /mnt. Walks the block
            // registry, skipping the device root-mount-auto already
            // consumed (FAT-on-nvme0 in QEMU), and mounts the first
            // ext-family filesystem it finds via the registered
            // ext factory. Lets us demonstrate persistent ext2
            // alongside the existing FAT root.
            narf_init::register(narf_init::Stage::Late, "mnt-mount-ext2", || {
                use narf_block::fs_detect::{detect_filesystem, FsType};
                let auth = narf_filesystem::bootstrap_mount_authority();
                let devices = narf_block::block_devices();
                let mut mounted = false;
                for entry in &devices {
                    let dev = entry.dev.clone();
                    let detect = match detect_filesystem(&dev) {
                        Ok(Some(FsType::Ext)) => FsType::Ext,
                        _ => continue,
                    };
                    let factory = match narf_filesystem::root_mount::lookup_factory(detect) {
                        Some(f) => f,
                        None => continue,
                    };
                    let fs = match factory(dev) {
                        Ok(f) => f,
                        Err(e) => {
                            let _ = writeln!(
                                console::Writer,
                                "  mnt-mount-ext2: factory failed on {}: {:?}",
                                entry.name,
                                e
                            );
                            continue;
                        }
                    };
                    match narf_filesystem::registry().mount_arc(&auth, "/mnt", fs) {
                        Ok(_) => {
                            let _ = writeln!(
                                console::Writer,
                                "  mnt-mount-ext2: ext on {} mounted at \"/mnt\"",
                                entry.name
                            );
                            mounted = true;
                            break;
                        }
                        Err(e) => {
                            let _ = writeln!(
                                console::Writer,
                                "  mnt-mount-ext2: mount_arc(/mnt) failed: {:?}",
                                e
                            );
                        }
                    }
                }
                if mounted {
                    narf_init::InitResult::Ok
                } else {
                    narf_init::InitResult::NotPresent
                }
            });

            // Populate /sys/class/input/event<N> from the live evdev router.
            // The early filesystem populate_all() ran before the virtio
            // keyboard/tablet drivers probed (ROUTER was empty), so re-run it
            // at Stage::Late once the devices are registered. Idempotent
            // (get_or_create_child). libudev/libinput enumerate input here.
            narf_init::register(narf_init::Stage::Late, "sysfs-input-class", || {
                narf_filesystem::sysfs::populate_input_class();
                narf_init::InitResult::Ok
            });

            // Make NARF's /dev reachable inside a chrooted /mnt rootfs, so a
            // real distro booted from the virtio-blk image (see distro_init /
            // distro_desktop) can open device files — /dev/fb0, /dev/dri,
            // /dev/uinput — from within chroot("/mnt"). Best-effort: only acts
            // when both /dev and /mnt are mounted and /mnt/dev isn't already
            // bound. Mirrors a container runtime bind-mounting /dev.
            narf_init::register(narf_init::Stage::Late, "mnt-dev-bind", || {
                let mounts = narf_filesystem::registry().list();
                let have_dev = mounts.iter().any(|m| m == "/dev");
                let have_mnt = mounts.iter().any(|m| m == "/mnt");
                let already = mounts.iter().any(|m| m == "/mnt/dev");
                if have_dev && have_mnt && !already {
                    let auth = narf_filesystem::bootstrap_mount_authority();
                    match narf_filesystem::registry().bind_mount(&auth, "/dev", "/mnt/dev") {
                        Ok(_) => {
                            let _ = writeln!(
                                console::Writer,
                                "  mnt-dev-bind: /dev bound at /mnt/dev (distro device access)"
                            );
                            // Also give the chroot a writable /tmp (a fresh
                            // in-memory FS) — a distro's runtime dir for
                            // sockets/lock files (e.g. the Wayland display
                            // socket) since the on-disk rootfs may be read-only.
                            if !mounts.iter().any(|m| m == "/mnt/tmp") {
                                let tmp = narf_filesystem::MemFs::new("tmpfs");
                                let _ = narf_filesystem::registry().mount(&auth, "/mnt/tmp", tmp);
                                let _ = writeln!(
                                    console::Writer,
                                    "  mnt-dev-bind: writable /tmp mounted at /mnt/tmp"
                                );
                            }
                            // And a writable /run (tmpfs). udevd + most daemons
                            // keep runtime state here (control socket, queue,
                            // watch dir, /run/udev/data, /run/user/<uid>) which
                            // need unlink/rename + nested dirs the ext2 rootfs
                            // lacks. On real Linux /run is always tmpfs.
                            if !mounts.iter().any(|m| m == "/mnt/run") {
                                let run = narf_filesystem::MemFs::new("tmpfs");
                                let _ = narf_filesystem::registry().mount(&auth, "/mnt/run", run);
                                let _ = writeln!(
                                    console::Writer,
                                    "  mnt-dev-bind: writable /run mounted at /mnt/run"
                                );
                            }
                            // Bind /sys and /proc into the chroot too — libudev/
                            // libinput enumerate devices via /sys/class/*, and
                            // most Linux software pokes /proc. Best-effort.
                            for (src, dst) in [("/sys", "/mnt/sys"), ("/proc", "/mnt/proc")] {
                                if mounts.iter().any(|m| m == src)
                                    && !mounts.iter().any(|m| m == dst)
                                    && narf_filesystem::registry()
                                        .bind_mount(&auth, src, dst)
                                        .is_ok()
                                {
                                    let _ = writeln!(
                                        console::Writer,
                                        "  mnt-dev-bind: {} bound at {}",
                                        src,
                                        dst
                                    );
                                }
                            }
                            // The /sys bind above does NOT carry the nested
                            // cgroup-v2 mount at /sys/fs/cgroup, so a chrooted
                            // session manager (elogind/logind/systemd) statfs'ing
                            // the chroot's /sys/fs/cgroup finds nothing and
                            // exit(1)s. Mount a fresh cgroup-v2 hierarchy at the
                            // chroot path so it sees CGROUP2_SUPER_MAGIC and can
                            // create its own child cgroups there.
                            #[cfg(feature = "cgroup")]
                            if !mounts.iter().any(|m| m == "/mnt/sys/fs/cgroup") {
                                let cg = narf_filesystem::cgroupfs::CgroupFs::new();
                                if narf_filesystem::registry()
                                    .mount(&auth, "/mnt/sys/fs/cgroup", cg)
                                    .is_ok()
                                {
                                    let _ = writeln!(
                                        console::Writer,
                                        "  mnt-dev-bind: cgroup2 mounted at /mnt/sys/fs/cgroup"
                                    );
                                }
                            }
                            narf_init::InitResult::Ok
                        }
                        Err(e) => {
                            let _ = writeln!(
                                console::Writer,
                                "  mnt-dev-bind: bind /dev -> /mnt/dev failed: {:?}",
                                e
                            );
                            narf_init::InitResult::NotPresent
                        }
                    }
                } else {
                    narf_init::InitResult::NotPresent
                }
            });

            narf_init::register(narf_init::Stage::Late, "virtio-gpu-splash", || {
                use narf_graphics::Pixel32;
                // `probed_device` avoids holding the IRQ-masking
                // controller lock across the init/flush round-trips;
                // the device's request gate serialises submitters.
                let painted = narf_drivers_virtio::gpu_pci::probed_device().map(|d| {
                    if !d.is_ready() {
                        if let Err(e) = d.init_scanout() {
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
                    let _ = d.flush();
                    let mode = d.mode();
                    (mode.width, mode.height)
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
            // Run stages one at a time.
            for s in narf_init::Stage::ALL {
                if (s as u8) > (last_stage as u8) {
                    break;
                }
                let _ = narf_init::run_stage(s);
            }
            let _ = narf_init::print_summary(&mut console::Writer);
            // Status-panel diag: initcalls done; flip the phase to
            // Userspace so the panel shows the kernel reached its
            // final boot phase (scheduler, executors, sleep_pumps).
            narf_memory::diag::set_phase(narf_memory::diag::BootPhase::Userspace);

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
        // SAFETY: Valid memory or trusted environment
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
        let cpu_count = narf_lib::smp::cpu_count();
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
        // `test_subsystem=a,b,c` selects those subsystems (prefix-matched:
        // `filesystem` selects `filesystem/page_cache` too). This is the
        // change-based CI path — `cargo xtask affected` computes the
        // affected set and CI threads it here. Absent/empty ⇒ run all.
        let selected = narf_boot::cmdline()
            .split_ascii_whitespace()
            .find_map(|arg| arg.strip_prefix("test_subsystem="));
        match selected {
            Some(list) if !list.is_empty() => {
                let wanted: alloc::vec::Vec<&str> =
                    list.split(',').filter(|s| !s.is_empty()).collect();
                if wanted.is_empty() {
                    narf_verification::run_all_and_exit()
                } else {
                    narf_verification::run_subsystems_and_exit(&wanted)
                }
            }
            _ => narf_verification::run_all_and_exit(),
        }
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
        // SAFETY: Valid memory or trusted environment
        unsafe {
            narf_arch::exit_kernel(0);
        }
    }

    // ─── Stage 1 exit-gate demo: async executor + timer-driven yield ──
    #[cfg(not(any(
        feature = "kernel-test",
        feature = "boot-smoke",
        feature = "idt-selftest"
    )))]
    run_async_demo()
}

#[cfg(not(any(
    feature = "kernel-test",
    feature = "boot-smoke",
    feature = "idt-selftest"
)))]
fn run_async_demo() -> ! {
    // aarch64 timer start. GICv3 + vector table already installed
    // earlier; this starts the generic-timer PPI and unmasks IRQs
    // in DAIF.
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: GIC is up (or the feature check in _start_rust
        // skipped init_bsp, in which case timer IRQs fire but are
        // never delivered — still safe, just silent).
        // SAFETY: Valid memory or trusted environment
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
                        i,
                        periodic,
                        fsb,
                        route_cap,
                    );
                }
                // LAPIC MMIO base from IA32_APIC_BASE MSR — Linux
                // honors BIOS relocation via this MSR rather than
                // hardcoding 0xFEE0_0000. If our hardcoded base
                // doesn't match, MMIO writes go nowhere and MSI
                // delivery (targeted at 0xFEE0_0000) won't reach
                // the LAPIC.
                // SAFETY: `rdmsr` of IA32_APIC_BASE (0x1B) — an
                // architectural MSR present on every long-mode CPU — at
                // CPL0, so the privileged `rdmsr` is permitted here.
                // SAFETY: Valid memory or trusted environment
                let apic_base = unsafe { narf_arch::x86_64::msr::rdmsr(0x0000_001B) };
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
        narf_time::clockevent::register(&narf_interrupts::x86_64::apic::LAPIC_CLOCKEVENT);
        narf_time::clockevent::register(&narf_interrupts::x86_64::hpet_clockevent::HPET_CLOCKEVENT);

        // Enable CPU-side IRQ delivery BEFORE select_primary so
        // the probe can actually observe ticks. Without this the
        // probe always fails (arm programs the device, but IF=0
        // → no delivery → tick_count stuck at 0 → probe fails).
        // SAFETY: APIC + IDT live; PIC masked.
        unsafe {
            narf_arch::enable_interrupts();
        }

        let selected = narf_time::clockevent::select_primary(
            1000, // 1000 Hz tick — 1 ms period (match Linux CONFIG_HZ_1000)
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
                let _ =
                    writeln!(
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

    #[cfg(feature = "boot-init")]
    boot_userspace_init();

    // Spawn the cursor pump *before* run_until_empty so it's in the
    // queue when the executor starts. With boot-init the user task
    // futures (init / shell) loop forever, so run_until_empty never
    // returns; if we waited until after to spawn the pump, the
    // mouse would never move.
    // Cursor pump + USB HID supervisor are spawned by their own
    // Stage::Late initcalls — no manual re-spawn needed now that
    // the redundant scheduler::init() above is gone.
    if narf_fb::info().is_some() {
        let cap = narf_fb::bootstrap_writer();
        if let Ok(panel_writer) = narf_fb::FbWriter::new(cap) {
            narf_fb::status::paint(&panel_writer);
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
        // SAFETY: `_rdtsc` (RDTSC) is unprivileged and always available
        // in long mode; it only reads the time-stamp counter.
        // SAFETY: Valid memory or trusted environment
        let start = unsafe { core::arch::x86_64::_rdtsc() };
        let target = start.wrapping_add(25_000_000_000u64);
        // SAFETY: same as above — RDTSC just samples the TSC each spin.
        while unsafe { core::arch::x86_64::_rdtsc() } < target {
            core::hint::spin_loop();
        }
    }

    // SAFETY: exit_kernel is infallible; on QEMU it exits cleanly via
    // the isa-debug-exit device (x86_64) or semihosting (aarch64); on
    // real hardware it falls back to a quiet halt.
    // SAFETY: Valid memory or trusted environment
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
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
fn boot_userspace_init() {
    use core::fmt::Write as _;
    use narf_userspace::{
        bootstrap_init, brk_init, cwd_init, install_address_space_lookup,
        install_all_address_spaces_lookup, install_core_syscalls, install_global,
        install_task_id_lookup, install_user_task_hooks, load_user_process_with,
        load_user_process_with_root, sigaction_init, signal_init, SyscallTable,
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
    // `trace_comm=<prefix>[,<prefix>...]` retargets the syscall-trace feature's
    // comm filter without a rebuild (default `systemd-executo`). No-op unless
    // the kernel was built with `--features syscall-trace`.
    #[cfg(feature = "syscall-trace")]
    if let Some(prefix) = narf_boot::cmdline()
        .split_ascii_whitespace()
        .find_map(|t| t.strip_prefix("trace_comm="))
    {
        narf_userspace::syscall::set_trace_comm(prefix);
        let _ = writeln!(
            console::Writer,
            "  boot-init: syscall-trace comm='{prefix}'"
        );
    }
    // Build the shared vDSO + vvar pages now that the TSC/counter scale is
    // calibrated; every process maps them and gets AT_SYSINFO_EHDR.
    narf_userspace::vdso::register_vdso_image(
        narf_verification::NARF_VDSO_ELF,
        narf_scheduler::narf_time::cycles_per_ns(),
    );
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
    install_all_address_spaces_lookup(narf_scheduler::all_address_spaces);
    narf_memory::install_shared_frame_hooks(
        narf_userspace::retain_external_shared_frame,
        narf_userspace::release_external_shared_frame,
    );
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
        // Never poll the executor recursively from inside an active task poll.
        // Polled sync I/O calls `sleep_pumps::run()` while holding its driver
        // lock; a nested user task can enter the same driver and spin forever
        // on that lock (observed during startplasma DSO fault-in). The normal
        // per-CPU executor loop already advances peers at the next yield.
        if narf_scheduler::current_task_id().raw() != 0 {
            return;
        }
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
        // Non-blocking: this backstop fires on every core's every park, so
        // it must NEVER spin on the shared CONSOLE.lock — under a
        // thread-dense SMP workload (KDE Plasma) that becomes a
        // machine-wide thundering herd. IRQ 4 is the primary RX path; a
        // skipped cycle when the lock is contended is free.
        for _ in 0..16 {
            match narf_console::try_read_byte_uncontended() {
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
        let mut overrides = [narf_acpi::IsaOverride::default(); narf_acpi::MAX_ISA_OVERRIDES];
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
            // SAFETY: Valid memory or trusted environment
            let routed = unsafe { narf_acpi::ioapic::route_gsi_to_vector(gsi, v, 0, flags) };
            if routed {
                narf_console::enable_rx_irq();
                let _ = writeln!(
                    console::Writer,
                    "  serial: IRQ 4 → GSI {} → vec {} (RX IRQ enabled)",
                    gsi,
                    v
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
        spawn_one_argv(name, bytes, &[name])
    }

    // Like `spawn_one` but with an explicit argv (argv[0] should be the
    // program name). Lets a boot-spawned daemon receive flags — e.g.
    // redis-server needs `--bind 0.0.0.0 --protected-mode no` to serve
    // off-box.
    fn spawn_one_argv(name: &'static str, bytes: &[u8], argv: &[&str]) -> bool {
        if bytes.is_empty() {
            let _ = writeln!(
                console::Writer,
                "  boot-init: {name}: ELF is empty — skipping"
            );
            return false;
        }
        // SAFETY: Valid memory or trusted environment
        let proc = match unsafe { load_user_process_with(bytes, argv, &[], &[]) } {
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
        let _ = writeln!(
            console::Writer,
            "  boot-init: spawning {name} pid={} entry={:#x}",
            pid.raw(),
            entry
        );
        // Boot-init's initial user tasks (init / getty / the login
        // shell) stay BOOT-pinned: they live on the console / tty /
        // job-control path, which isn't SMP-hardened (un-locked shared
        // state, output-ordering the gates assert on). Their fork/exec
        // CHILDREN — the actual workload — spawn with `user_task()` and
        // migrate freely (see do_clone3 / sys_fork). `unthrottled()` is
        // the BOOT-pinned spec.
        let tid = narf_userspace::user_task::spawn_user_process(
            proc,
            narf_scheduler::TaskSpec::unthrottled(),
        );
        // Register PID <-> TID mapping so syscalls like kill(pid) work.
        narf_userspace::handlers::register_pid_task_mapping(pid.raw(), tid.raw());

        // Place the boot-spawned process into the root cgroup so it
        // appears in /sys/fs/cgroup/cgroup.procs. Children inherit
        // this at fork/clone.
        #[cfg(feature = "cgroup")]
        narf_filesystem::cgroupfs::attach_to_root(pid.raw());

        // /proc/[pid]/cmdline + comm seed for the boot-spawned
        // process. argv = ["init"] / ["shell"] is the convention
        // load_user_process_with uses above.
        narf_userspace::handlers::set_proc_argv(tid.raw(), argv);
        narf_userspace::handlers::set_proc_comm(tid.raw(), name);
        true
    }

    // Directly load a dynamic program from an already-mounted filesystem root.
    // The task's root is installed before it is enqueued, so systemd is the
    // first and only process in its PID-1 chain — no chroot shell/launcher is
    // involved.
    fn spawn_rooted_pid1(name: &'static str, bytes: &[u8], root: &str) -> bool {
        if bytes.is_empty() {
            return false;
        }
        let argv = [name];
        let envp = [
            "container=narf",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ];
        // SAFETY: boot has the loader's identity mapping and frame allocator.
        let proc = match unsafe {
            load_user_process_with_root(
                bytes,
                &argv,
                &envp,
                &[],
                Some(root),
                narf_userspace::alloc_pid(),
            )
        } {
            Ok(p) => p,
            Err(e) => {
                let _ = writeln!(
                    console::Writer,
                    "  boot-init: {name}: direct load failed: {e:?}"
                );
                return false;
            }
        };
        let pid = proc.pid;
        let pending = narf_userspace::user_task::prepare_user_process_initial(
            proc,
            narf_scheduler::TaskSpec::unthrottled(),
        );
        let tid = pending.task_id();
        if !narf_userspace::handlers::install_root_dir(tid.raw(), root) {
            let _ = writeln!(
                console::Writer,
                "  boot-init: {name}: could not install root {root}"
            );
            let _ = narf_userspace::task::release_task(tid.raw());
            return false;
        }
        narf_userspace::handlers::register_pid_task_mapping(pid.raw(), tid.raw());
        #[cfg(feature = "cgroup")]
        narf_filesystem::cgroupfs::attach_to_root(pid.raw());
        narf_userspace::handlers::set_proc_argv(tid.raw(), &argv);
        narf_userspace::handlers::set_proc_comm(tid.raw(), name);
        pending.spawn();
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
        let pair: Option<(Arc<dyn DirOps>, alloc::string::String)> = registry()
            .resolve_absolute(&abs, |fs, rel| {
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

    // Wave-49: mount a MemFs at /bin and seed it with the baked
    // coreutil ELFs. The shell's fork+exec resolves /bin/<name>
    // through libc::execve → posix_open(path, O_RDONLY) → kernel
    // VFS, so this single mount is the whole story for shipping
    // pwd / cat / ls / ps under `qemu -kernel` (no Limine
    // initramfs CPIO module is delivered there).
    {
        use narf_filesystem::{bootstrap_mount_authority, registry, MemFs};
        let auth = bootstrap_mount_authority();
        let fs = MemFs::with_seeds(
            "bin",
            &[
                ("echo", narf_verification::NARF_COREUTIL_ECHO_ELF),
                ("pwd", narf_verification::NARF_COREUTIL_PWD_ELF),
                ("cat", narf_verification::NARF_COREUTIL_CAT_ELF),
                ("ls", narf_verification::NARF_COREUTIL_LS_ELF),
                ("ps", narf_verification::NARF_COREUTIL_PS_ELF),
                // The login shell, seeded so getty can `execve("/bin/shell")`
                // after it establishes the session + controlling tty.
                ("shell", narf_verification::NARF_SHELL_ELF),
                // Wave-78: linux-compat demo binary. Direct-syscall
                // hello-world built with stock binutils (no libc, no
                // PT_INTERP). Type `hello` at the `narf>` shell
                // prompt; the exec path goes through posix_open +
                // execve and the binary issues raw Linux x86_64
                // syscalls (write=1, exit_group=231).
                ("hello", narf_verification::NARF_HELLO_STATIC_ELF),
                // Wave-78 follow-up 2: real musl-static binary built
                // with musl-gcc. Exercises the actual musl init path
                // (set_tid_address / rt_sigaction / brk / ...). Caveat:
                // musl uses the `syscall` instruction internally, and
                // NARF's current `syscall` dispatch doesn't reach the
                // raw handlers (see verification/data/musl-demo/
                // hello_musl_x86_64.c). The binary loads + enters
                // user mode cleanly; whether `write` prints depends
                // on the syscall-dispatch convergence sub-wave.
                ("hello_musl", narf_verification::NARF_HELLO_MUSL_ELF),
                // Wave-78 follow-up 3: dynamic-linked musl-static
                // binary. PT_INTERP points at
                // `/lib/ld-musl-x86_64.so.1`, which we stage as a
                // sibling MemFs below. Exercises Wave-75's
                // FS-backed PT_INTERP + R_X86_64_TPOFF64 /
                // DTPOFF64 / GLOB_DAT / JUMP_SLOT relocation
                // processing end-to-end.
                ("hello_musl_dyn", narf_verification::NARF_HELLO_MUSL_DYN_ELF),
                // pthread demo — exercises clone3 +
                // CLONE_THREAD/VM/SETTLS, per-thread TLS, futex
                // FUTEX_WAIT/WAKE for pthread_join, and stdio
                // from both threads.
                ("hello_pthread", narf_verification::NARF_HELLO_PTHREAD_ELF),
                // Wave-PTY: PTY smoke — open /dev/ptmx, allocate
                // a slave via TIOCSPTLCK + TIOCGPTN, open
                // /dev/pts/N, round-trip "ping" / "pong" across
                // the master/slave pair. Success token "pty-ok".
                ("pty_smoke", narf_verification::NARF_PTY_SMOKE_ELF),
                // Framebuffer smoke — opens /dev/fb0, mmaps it
                // MAP_SHARED, draws + reads back. Proves the
                // device-mmap keystone end-to-end. Success: `fb-ok`.
                ("fb_smoke", narf_verification::NARF_FB_SMOKE_ELF),
                ("scm_smoke", narf_verification::NARF_SCM_SMOKE_ELF),
                // DRM/KMS dumb-buffer smoke — opens /dev/dri/card0,
                // GET_CAP(DUMB_BUFFER), CREATE_DUMB, MAP_DUMB, mmap
                // MAP_SHARED, ADDFB2, SETCRTC. Success: `drm-ok`.
                ("drm_smoke", narf_verification::NARF_DRM_SMOKE_ELF),
                (
                    "tfd_epoll_smoke",
                    narf_verification::NARF_TFD_EPOLL_SMOKE_ELF,
                ),
                // Pure-timeout poll/epoll park hammer (slab-canary
                // false-positive regression pin). Success: `polltmo-ok`.
                ("polltmo_hammer", narf_verification::NARF_POLLTMO_HAMMER_ELF),
                (
                    "unix_epoll_smoke",
                    narf_verification::NARF_UNIX_EPOLL_SMOKE_ELF,
                ),
                // modetest — real libdrm KMS client (Rung 4 DRM probe).
                ("modetest", narf_verification::NARF_MODETEST_ELF),
                ("wl_handshake", narf_verification::NARF_WL_HANDSHAKE_ELF),
                ("wl_shm", narf_verification::NARF_WL_SHM_ELF),
                (
                    "mini_compositor",
                    narf_verification::NARF_MINI_COMPOSITOR_ELF,
                ),
                ("wl_2proc", narf_verification::NARF_WL_2PROC_ELF),
                ("wl_multi", narf_verification::NARF_WL_MULTI_ELF),
                ("wl_xdg", narf_verification::NARF_WL_XDG_ELF),
                ("wl_input", narf_verification::NARF_WL_INPUT_ELF),
                ("wl_kms", narf_verification::NARF_WL_KMS_ELF),
                ("wl_evdev", narf_verification::NARF_WL_EVDEV_ELF),
                ("simple_shm", narf_verification::NARF_SIMPLE_SHM_ELF),
                ("wl_app", narf_verification::NARF_WL_APP_ELF),
                ("distro_init", narf_verification::NARF_DISTRO_INIT_ELF),
                ("distro_desktop", narf_verification::NARF_DISTRO_DESKTOP_ELF),
                ("distro_kde", narf_verification::NARF_DISTRO_KDE_ELF),
                // Fedora 43 + KDE Plasma 6 (glibc). Needs the rootfs built by
                // REGEN_fedora_kde_rootfs.sh mounted at /mnt — boot with
                // NARF_VBLK_IMG=target/narf-fedora-vblk.img.
                ("distro_fedora", narf_verification::NARF_DISTRO_FEDORA_ELF),
                ("chroot_run", narf_verification::NARF_CHROOT_RUN_ELF),
                ("shmfork_smoke", narf_verification::NARF_SHMFORK_SMOKE_ELF),
                ("net_smoke", narf_verification::NARF_NET_SMOKE_ELF),
                ("net6_smoke", narf_verification::NARF_NET6_SMOKE_ELF),
                ("unix_smoke", narf_verification::NARF_UNIX_SMOKE_ELF),
                (
                    "fork_pipe_smoke",
                    narf_verification::NARF_FORK_PIPE_SMOKE_ELF,
                ),
                ("popenw_smoke", narf_verification::NARF_POPENW_SMOKE_ELF),
                ("wlserve_smoke", narf_verification::NARF_WLSERVE_SMOKE_ELF),
                (
                    "fork_exec_burst_smoke",
                    narf_verification::NARF_FORK_EXEC_BURST_SMOKE_ELF,
                ),
                (
                    "sched_affinity_smp_smoke",
                    narf_verification::NARF_SCHED_AFFINITY_SMP_SMOKE_ELF,
                ),
                ("epoll_smoke", narf_verification::NARF_EPOLL_SMOKE_ELF),
                ("signal_smoke", narf_verification::NARF_SIGNAL_SMOKE_ELF),
                ("sigrcx_smoke", narf_verification::NARF_SIGRCX_SMOKE_ELF),
                ("pipeblk_smoke", narf_verification::NARF_PIPEBLK_SMOKE_ELF),
                ("sigrt_smoke", narf_verification::NARF_SIGRT_SMOKE_ELF),
                ("strace_smoke", narf_verification::NARF_STRACE_SMOKE_ELF),
                ("fs_smoke", narf_verification::NARF_FS_SMOKE_ELF),
                // Linux-compat round: eventfd2 / getrandom / socketpair
                // / accept4 exercised end-to-end by real musl binaries.
                ("eventfd_smoke", narf_verification::NARF_EVENTFD_SMOKE_ELF),
                (
                    "getrandom_smoke",
                    narf_verification::NARF_GETRANDOM_SMOKE_ELF,
                ),
                ("sockpair_smoke", narf_verification::NARF_SOCKPAIR_SMOKE_ELF),
                // socketpair(2) across fork(2): the child writes, the PARENT
                // waits with poll/epoll — dbus-daemon's babysitter protocol.
                (
                    "sockpairfork_smoke",
                    narf_verification::NARF_SOCKPAIRFORK_SMOKE_ELF,
                ),
                // Unlinked-but-open file: bash builds EVERY here-document
                // this way, so losing the data with the name blanks them.
                (
                    "unlinkopen_smoke",
                    narf_verification::NARF_UNLINKOPEN_SMOKE_ELF,
                ),
                // Pipe hangup when the last writer EXITS without close():
                // how dbus-daemon learns an activated service died.
                ("pipehup_smoke", narf_verification::NARF_PIPEHUP_SMOKE_ELF),
                ("accept4_smoke", narf_verification::NARF_ACCEPT4_SMOKE_ELF),
                // Linux-compat round 2: mremap / sendfile / creds / waitid.
                ("mremap_smoke", narf_verification::NARF_MREMAP_SMOKE_ELF),
                ("sendfile_smoke", narf_verification::NARF_SENDFILE_SMOKE_ELF),
                ("creds_smoke", narf_verification::NARF_CREDS_SMOKE_ELF),
                ("waitid_smoke", narf_verification::NARF_WAITID_SMOKE_ELF),
                // Linux-compat round 3: ppoll / sysinfo / splice / membarrier+clock_getres.
                ("ppoll_smoke", narf_verification::NARF_PPOLL_SMOKE_ELF),
                ("sysinfo_smoke", narf_verification::NARF_SYSINFO_SMOKE_ELF),
                ("splice_smoke", narf_verification::NARF_SPLICE_SMOKE_ELF),
                ("barrier_smoke", narf_verification::NARF_BARRIER_SMOKE_ELF),
                // Linux-compat round 4: close_range / sched-policy / msync+mincore / sync+syncfs+personality.
                (
                    "closerange_smoke",
                    narf_verification::NARF_CLOSERANGE_SMOKE_ELF,
                ),
                (
                    "fd_cloexec_exec_smoke",
                    narf_verification::NARF_FD_CLOEXEC_EXEC_SMOKE_ELF,
                ),
                ("sched_smoke", narf_verification::NARF_SCHED_SMOKE_ELF),
                ("mcore_smoke", narf_verification::NARF_MCORE_SMOKE_ELF),
                ("sync_smoke", narf_verification::NARF_SYNC_SMOKE_ELF),
                // Linux-compat round 5: dup3+fadvise64+mlock2 / robust lists / renameat2 / pidfd_send_signal.
                ("dup3fam_smoke", narf_verification::NARF_DUP3FAM_SMOKE_ELF),
                ("robust_smoke", narf_verification::NARF_ROBUST_SMOKE_ELF),
                (
                    "renameat2_smoke",
                    narf_verification::NARF_RENAMEAT2_SMOKE_ELF,
                ),
                ("pidfdsig_smoke", narf_verification::NARF_PIDFDSIG_SMOKE_ELF),
                // Linux-compat round 6: sethostname+setdomainname / sendmmsg+recvmmsg / openat2 / preadv+pwritev.
                ("host_smoke", narf_verification::NARF_HOST_SMOKE_ELF),
                ("mmsg_smoke", narf_verification::NARF_MMSG_SMOKE_ELF),
                ("openat2_smoke", narf_verification::NARF_OPENAT2_SMOKE_ELF),
                ("pv_smoke", narf_verification::NARF_PV_SMOKE_ELF),
                // Linux-compat round 7: capget+capset / setitimer+getitimer+alarm / xattr / readahead+sync_file_range.
                ("cap_smoke", narf_verification::NARF_CAP_SMOKE_ELF),
                ("itimer_smoke", narf_verification::NARF_ITIMER_SMOKE_ELF),
                ("xattr_smoke", narf_verification::NARF_XATTR_SMOKE_ELF),
                ("perf_smoke", narf_verification::NARF_PERF_SMOKE_ELF),
                ("fhint_smoke", narf_verification::NARF_FHINT_SMOKE_ELF),
                // Linux-compat round 8: mq_* / inotify / pkey_* / process_vm_*.
                ("mq_smoke", narf_verification::NARF_MQ_SMOKE_ELF),
                ("inotify_smoke", narf_verification::NARF_INOTIFY_SMOKE_ELF),
                ("pkey_smoke", narf_verification::NARF_PKEY_SMOKE_ELF),
                ("pvm_smoke", narf_verification::NARF_PVM_SMOKE_ELF),
                // Linux-compat round 9: mempolicy / sched_attr / adjtimex / introspection.
                (
                    "mempolicy_smoke",
                    narf_verification::NARF_MEMPOLICY_SMOKE_ELF,
                ),
                (
                    "schedattr_smoke",
                    narf_verification::NARF_SCHEDATTR_SMOKE_ELF,
                ),
                ("adjtimex_smoke", narf_verification::NARF_ADJTIMEX_SMOKE_ELF),
                (
                    "introspect_smoke",
                    narf_verification::NARF_INTROSPECT_SMOKE_ELF,
                ),
                // Linux-compat round 10: vectored + extended I/O.
                ("vio_smoke", narf_verification::NARF_VIO_SMOKE_ELF),
                // Linux-compat round 11: System V semaphores + message queues.
                ("sysvipc_smoke", narf_verification::NARF_SYSVIPC_SMOKE_ELF),
                // Linux-compat round 12: System V shared memory.
                ("shm_smoke", narf_verification::NARF_SHM_SMOKE_ELF),
                // Linux-compat round 13: xattr l*/f*/remove variants.
                ("xattr2_smoke", narf_verification::NARF_XATTR2_SMOKE_ELF),
                // Linux-compat round 14: filesystem misc (creat/lchown/utime/utimes).
                ("fsmisc_smoke", narf_verification::NARF_FSMISC_SMOKE_ELF),
                // Linux-compat round 15: credential gaps (real/effective/fs ids).
                ("creds2_smoke", narf_verification::NARF_CREDS2_SMOKE_ELF),
                // Linux-compat round 16: signal queueing + signalfd4.
                ("sig2_smoke", narf_verification::NARF_SIG2_SMOKE_ELF),
                // Linux-compat round 18: mlockall/memfd_secret/NUMA/process_madvise.
                ("mem2_smoke", narf_verification::NARF_MEM2_SMOKE_ELF),
                // Linux-compat round 19: process & scheduling.
                ("psched_smoke", narf_verification::NARF_PSCHED_SMOKE_ELF),
                // Linux-compat round 20: futex2 wait/wake/requeue/waitv.
                ("futex2_smoke", narf_verification::NARF_FUTEX2_SMOKE_ELF),
                // Contended futex: N-thread mutex + join + condvar ping-pong.
                (
                    "futex_contend_smoke",
                    narf_verification::NARF_FUTEX_CONTEND_SMOKE_ELF,
                ),
                // Condvar broadcast handoff: the FUTEX_REQUEUE path.
                (
                    "condbcast_smoke",
                    narf_verification::NARF_CONDBCAST_SMOKE_ELF,
                ),
                // Systemd-style READY=1 datagram: a CPU-1 service wakes the
                // CPU-0 manager's blocking epoll_wait and supplies SCM_CREDENTIALS.
                (
                    "notify_epoll_smp_smoke",
                    narf_verification::NARF_NOTIFY_EPOLL_SMP_SMOKE_ELF,
                ),
                // Linux-compat round 21: keyrings (add_key/request_key/keyctl).
                ("keyring_smoke", narf_verification::NARF_KEYRING_SMOKE_ELF),
                // Linux-compat round 22: inotify real event delivery.
                ("inotify2_smoke", narf_verification::NARF_INOTIFY2_SMOKE_ELF),
                // Linux-compat round 23: fanotify (init/mark + fd events).
                ("fanotify_smoke", narf_verification::NARF_FANOTIFY_SMOKE_ELF),
                // Linux-compat round 24: Landlock path-rule enforcement.
                ("landlock_smoke", narf_verification::NARF_LANDLOCK_SMOKE_ELF),
                // Linux-compat round 25: generic LSM self-attr syscalls.
                ("lsm_smoke", narf_verification::NARF_LSM_SMOKE_ELF),
                // vDSO: real fast-path linux-vdso.so.1 (clock_gettime).
                ("vdso_smoke", narf_verification::NARF_VDSO_SMOKE_ELF),
                // New mount API round 1: file handles.
                ("fhandle_smoke", narf_verification::NARF_FHANDLE_SMOKE_ELF),
                // New mount API round 2: fsopen/fsconfig/fsmount/move_mount.
                ("mountapi_smoke", narf_verification::NARF_MOUNTAPI_SMOKE_ELF),
                // Job control + termios: pty termios round-trip + SIGTTIN.
                ("jobctl_smoke", narf_verification::NARF_JOBCTL_SMOKE_ELF),
                // Job control stop/resume: SIGSTOP stop + SIGCONT resume,
                // observed through wait4 WUNTRACED/WCONTINUED.
                ("jobctl2_smoke", narf_verification::NARF_JOBCTL2_SMOKE_ELF),
                // Filesystem navigation: chdir + getcwd + opendir/getdents64
                // (directory fds) — what makes `cd` and `ls` work.
                ("navfs_smoke", narf_verification::NARF_NAVFS_SMOKE_ELF),
                // OCI container: minimal runtime that reads the /oci
                // bundle, unshares namespaces, chroots into the bundle
                // rootfs, and execs the contained entrypoint.
                ("oci_smoke", narf_verification::NARF_OCI_SMOKE_ELF),
                // Off-box network serving: TCP echo server bound to
                // 0.0.0.0, reached from the host via QEMU hostfwd.
                ("netserve_smoke", narf_verification::NARF_NETSERVE_SMOKE_ELF),
                // Unmodified redis-server (7.2.x, musl) — a real server
                // daemon, run off-box via the qemu-net + hostfwd harness.
                ("redis-server", narf_verification::NARF_REDIS_SERVER_ELF),
                // Pipe blocking-read + EOF on writer exit (fd teardown on
                // exit) — the mechanism behind shell `$(...)` substitution.
                ("pipeof_smoke", narf_verification::NARF_PIPEOF_SMOKE_ELF),
                // Relative-path *at resolution: mkdir/rename/symlink/unlink/
                // rmdir against the cwd — `mkdir foo`/`mv a b`/`rm foo` work.
                ("relpaths_smoke", narf_verification::NARF_RELPATHS_SMOKE_ELF),
                // Console is a tty: isatty + cooked tcgetattr + tcsetattr
                // round-trip, so an interactive shell line-edits + prompts.
                (
                    "consoletty_smoke",
                    narf_verification::NARF_CONSOLETTY_SMOKE_ELF,
                ),
                // (a) Preemptive SIGALRM: alarm()/setitimer fires on a
                // CPU-bound task that never parks (raised from the timer
                // ISR, delivered on the IRQ return to user).
                (
                    "alarmloop_smoke",
                    narf_verification::NARF_ALARMLOOP_SMOKE_ELF,
                ),
                // (b) Preemptive scheduling: a CPU-bound child is time-
                // sliced so the parent's timed sleep returns on time.
                (
                    "preemptsched_smoke",
                    narf_verification::NARF_PREEMPTSCHED_SMOKE_ELF,
                ),
                // procfs breadth: /proc/stat + fuller /proc/<pid>/status.
                ("procfs2_smoke", narf_verification::NARF_PROCFS2_SMOKE_ELF),
                // NUMA sysfs: /sys/devices/system/node/{online,nodeN/distance,meminfo}.
                ("numa_smoke", narf_verification::NARF_NUMA_SMOKE_ELF),
                // multi-DSO dynamic linking: main -> libb -> liba -> libc.
                ("dso_smoke", narf_verification::NARF_DSO_SMOKE_ELF),
                // per-DSO TLS: thread-locals in a shared library (libtls).
                ("tls_smoke", narf_verification::NARF_TLS_SMOKE_ELF),
                // Wave-79: BusyBox static, built at workspace
                // build time by `verification/busybox/build.rs`.
                // Empty slice when the host lacked musl-gcc — the
                // resulting zero-byte /bin/busybox file is harmless
                // (exec fails on an empty ELF) and the demo just
                // doesn't work until musl is installed.
                ("busybox", narf_verification::NARF_BUSYBOX),
            ],
        );
        let count = fs.file_count();
        let _ = registry().mount(&auth, "/bin", fs);
        let _ = writeln!(
            console::Writer,
            "  boot-init: mounted /bin (memfs) with {} coreutils",
            count,
        );

        // /etc/passwd + /etc/shadow — getty's credential store. passwd is
        // the 7-field record with `x` in field 2 (password is shadowed);
        // shadow holds the salted SHA-256 hash `$n1$<salt>$<hexhash>` of the
        // password (user `root`, password `narf`; salt `n4rf`). No plaintext
        // on disk. NARF has no crypt(3) and a capability-based authority
        // model (uids are cosmetic), so this gates the login flow rather than
        // enforcing a security boundary. The hash is verified by login-core
        // (host-unit-tested); regenerate it there if you change the password.
        const ETC_PASSWD: &[u8] = b"root:x:0:0:root:/root:/bin/shell\n";
        const ETC_SHADOW: &[u8] =
            b"root:$n1$n4rf$366fcdb3a40735e32d92d92d11fe1b9593d98d7e7546262e66cfeb72bd07ddec:0:0:99999:7:::\n";
        // /etc/os-release — the freedesktop os-release(5) identity file.
        // systemd (booting as PID 1) reads it at startup to name the OS in
        // its logs; a missing file makes `read_os_release_at` fail. VERSION_ID
        // tracks the kernel's `uname -r` release (sys_uname reports 6.1.0-narf).
        // Linux convention makes /etc/os-release a symlink to
        // ../usr/lib/os-release; NARF has no symlink-across-mount support here,
        // so it's a plain file at /etc/os-release and mirrored at
        // /usr/lib/os-release (below) for readers that consult that path.
        const ETC_OS_RELEASE: &[u8] = b"NAME=\"NARF\"\n\
PRETTY_NAME=\"NARF 6.1.0-narf\"\n\
ID=narf\n\
VERSION_ID=6.1.0\n\
VERSION=\"6.1.0-narf\"\n\
ANSI_COLOR=\"0;36\"\n\
HOME_URL=\"https://github.com/dhodges-daniel/narf\"\n\
BUG_REPORT_URL=\"https://github.com/dhodges-daniel/narf/issues\"\n";
        let etc_fs = MemFs::with_seeds(
            "etc",
            &[
                ("passwd", ETC_PASSWD),
                ("shadow", ETC_SHADOW),
                ("os-release", ETC_OS_RELEASE),
            ],
        );
        // DAC: /etc/shadow holds password hashes and must be a real
        // root-only secret — 0600 owned by (0, 0). getty reads it as
        // uid 0 at boot (it setsid's but never setuid's before the
        // read), so the owner-rw bits suffice for it; any process that
        // has dropped privilege is now denied by posix_access_ok. passwd
        // stays world-readable 0o666 (the default).
        if !etc_fs.set_file_perms_owner("shadow", 0o600, 0, 0) {
            let _ = writeln!(
                console::Writer,
                "  boot-init: WARNING failed to tighten /etc/shadow perms"
            );
        }
        let _ = registry().mount(&auth, "/etc", etc_fs);
        let _ = writeln!(
            console::Writer,
            "  boot-init: mounted /etc (memfs) with passwd + shadow + os-release"
        );

        // /usr/lib/os-release — the canonical location os-release(5) lives at
        // on a stock Linux (with /etc/os-release a symlink to it). systemd and
        // other readers fall back to this path, so mirror the same content
        // here as a real file.
        let usrlib_fs = MemFs::with_seeds("usrlib", &[("os-release", ETC_OS_RELEASE)]);
        let _ = registry().mount(&auth, "/usr/lib", usrlib_fs);
        let _ = writeln!(
            console::Writer,
            "  boot-init: mounted /usr/lib (memfs) with os-release"
        );

        // Wave-78 follow-up 3: /lib MemFs carrying the ld-musl
        // interpreter. NARF_LD_MUSL is empty (0 bytes) when the
        // host build didn't have musl installed — in that case
        // skip the mount so the loader's PT_INTERP lookup falls
        // through to its existing error path instead of seeding
        // /lib/ with a zero-byte file the user might try to exec.
        if !narf_verification::NARF_LD_MUSL.is_empty() {
            // ld-musl plus the multi-DSO test libraries (empty placeholders
            // when musl-gcc was absent at build time). liba/libb let
            // dso_smoke exercise a real DT_NEEDED chain (main → libb → liba
            // → libc), loaded by ld-musl via file-backed mmap.
            let lib_fs = MemFs::with_seeds(
                "lib",
                &[
                    ("ld-musl-x86_64.so.1", narf_verification::NARF_LD_MUSL),
                    ("liba.so", narf_verification::NARF_LIBA_SO),
                    ("libb.so", narf_verification::NARF_LIBB_SO),
                    ("libtls.so", narf_verification::NARF_LIBTLS_SO),
                ],
            );
            let lib_count = lib_fs.file_count();
            let _ = registry().mount(&auth, "/lib", lib_fs);
            let _ = writeln!(
                console::Writer,
                "  boot-init: mounted /lib (memfs) with {} interpreter ({} bytes)",
                lib_count,
                narf_verification::NARF_LD_MUSL.len(),
            );
        } else {
            let _ = writeln!(
                console::Writer,
                "  boot-init: /lib mount skipped (no ld-musl at build time; \
                 dynamic-linked binaries will fail to exec)"
            );
        }

        // ── OCI container bundle ────────────────────────────────────
        // Seed a minimal OCI bundle at /oci so the `oci_smoke` runtime
        // has a real bundle to launch: a `config.json` runtime-spec
        // subset (hostname / root.path / namespaces / process), plus a
        // `rootfs/` holding the static entrypoint at /oci/rootfs/init
        // and the container's own /etc/os-release. Three nested MemFs
        // mounts — the registry's longest-prefix resolver routes
        // /oci/config.json, /oci/rootfs/init and /oci/rootfs/etc/os-release
        // to the right mount, and after the runtime chroots to
        // /oci/rootfs the entrypoint's "/init" + "/etc/os-release"
        // resolve under it. Only seeded when the entrypoint was actually
        // built (musl-gcc present); an empty placeholder would just fail
        // to exec, so we skip it like the /lib mount above.
        if !narf_verification::NARF_OCI_SMOKE_ELF.is_empty() {
            const OCI_CONFIG_JSON: &[u8] = br#"{
  "ociVersion": "1.0.2",
  "hostname": "narfbox",
  "root": { "path": "/oci/rootfs", "readonly": false },
  "process": {
    "cwd": "/",
    "args": ["/init", "--contained"],
    "env": ["PATH=/bin", "OCI_CONTAINER=1"]
  },
  "linux": {
    "namespaces": [
      { "type": "pid" },
      { "type": "uts" },
      { "type": "ipc" },
      { "type": "mount" },
      { "type": "network" }
    ]
  }
}
"#;
            const OCI_OS_RELEASE: &[u8] =
                b"NAME=\"NARF-Container\"\nID=narf-container\nPRETTY_NAME=\"NARF OCI Container\"\n";
            let oci_fs = MemFs::with_seeds("oci", &[("config.json", OCI_CONFIG_JSON)]);
            let _ = registry().mount(&auth, "/oci", oci_fs);
            let rootfs = MemFs::with_seeds(
                "ocirootfs",
                &[("init", narf_verification::NARF_OCI_SMOKE_ELF)],
            );
            let _ = registry().mount(&auth, "/oci/rootfs", rootfs);
            let etc = MemFs::with_seeds("ocietc", &[("os-release", OCI_OS_RELEASE)]);
            let _ = registry().mount(&auth, "/oci/rootfs/etc", etc);
            // The entrypoint is a dynamic-PIE musl binary, so the bundle
            // rootfs carries its own copy of the loader at
            // /oci/rootfs/lib/ld-musl-x86_64.so.1. The execve loader
            // resolves PT_INTERP under the container's chroot (see
            // process.rs), so the contained process loads *this* loader,
            // not the host's /lib — the container is self-contained.
            if !narf_verification::NARF_LD_MUSL.is_empty() {
                let lib = MemFs::with_seeds(
                    "ocilib",
                    &[("ld-musl-x86_64.so.1", narf_verification::NARF_LD_MUSL)],
                );
                let _ = registry().mount(&auth, "/oci/rootfs/lib", lib);
            }
            let _ = writeln!(
                console::Writer,
                "  boot-init: seeded OCI bundle at /oci ({} byte entrypoint)",
                narf_verification::NARF_OCI_SMOKE_ELF.len(),
            );
        }
    }

    // `systemd_pid1` cmdline flag: boot the mounted /mnt rootfs's
    // `/usr/lib/systemd/systemd` directly as PID 1 instead of the NARF
    // init/getty/shell stack. The mounted Fedora filesystem is installed as
    // the task's root before scheduler publication; there is no launcher,
    // shell, chroot helper, or exec chain ahead of systemd.
    // The Stage::Late `mnt-dev-bind`/`root-mount-auto` initcalls have
    // already run synchronously above (see the run_stage loop in
    // `_start_rust`), so /mnt + /mnt/{dev,run,tmp,sys,proc} + the chroot
    // cgroup2 mount are live before this task ever runs. init/getty are
    // skipped: there is no NARF login shell in this mode.
    let systemd_pid1 = narf_boot::cmdline()
        .split_ascii_whitespace()
        .any(|t| t == "systemd_pid1");
    if systemd_pid1 {
        let systemd_path = "/mnt/usr/lib/systemd/systemd";
        let systemd = narf_userspace::process::read_path_from_vfs(systemd_path);
        if systemd.is_none() {
            let _ = writeln!(
                console::Writer,
                "  boot-init: systemd_pid1 requested but {systemd_path} is unavailable"
            );
        } else {
            spawn_rooted_pid1("systemd", systemd.as_deref().unwrap_or(&[]), "/mnt");
        }
        let _ = baked_shell;
        return;
    }

    spawn_one("init", baked_init);
    // Spawn getty in place of the shell: it sets up a login session
    // (setsid → controlling tty → foreground pgrp) and then execs
    // `/bin/shell`, so the shell runs with real job control. `baked_shell`
    // is seeded at `/bin/shell` (above) for getty's execve.
    let _ = baked_shell;
    spawn_one("getty", narf_verification::NARF_GETTY_ELF);

    // Off-box network serving smoke (opt-in `qemu-net`): auto-spawn the
    // TCP echo server alongside getty. The kernel statically configured
    // vnet0 with the SLIRP lease (cross_crate_init), and QEMU forwards a
    // host port to guest :7777, so the host-side `cargo xtask net-smoke`
    // harness can connect and round-trip without driving the console.
    #[cfg(feature = "qemu-net")]
    {
        if !narf_verification::NARF_NETSERVE_SMOKE_ELF.is_empty() {
            spawn_one("netserve", narf_verification::NARF_NETSERVE_SMOKE_ELF);
        }
        // Unmodified redis-server, bound off-box on 0.0.0.0:6379. Args
        // skip IPv6 + RDB/AOF persistence so it serves from RAM only; the
        // host-side `cargo xtask redis-smoke` harness then does SET/GET
        // over the hostfwd port. Suppressed under `mt-echo`, which
        // dedicates the box to the multithreaded benchmark workload — and
        // under the `no_redis` cmdline flag, which `cargo xtask net-smoke`
        // sets so redis's heavy startup can't starve netserve's RX path on
        // a single CI vcpu past the host deadline (the net-smoke flake).
        #[cfg(not(feature = "mt-echo"))]
        if !narf_boot::cmdline()
            .split_whitespace()
            .any(|t| t == "no_redis")
            && !narf_verification::NARF_REDIS_SERVER_ELF.is_empty()
        {
            spawn_one_argv(
                "redis-server",
                narf_verification::NARF_REDIS_SERVER_ELF,
                &[
                    "redis-server",
                    "--bind",
                    "0.0.0.0",
                    "--protected-mode",
                    "no",
                    "--save",
                    "",
                    "--appendonly",
                    "no",
                ],
            );
        }
        // mt-echo: multithreaded SO_REUSEPORT echo server — the
        // multi-queue/RSS benchmark workload. One listener (== one kernel
        // Listen TCB) per worker thread on 0.0.0.0:7000; the stack steers
        // distinct flows to distinct workers (add_to_listener_accept_queue)
        // so RX is consumed in parallel across cores. Thread count from
        // the kernel cmdline `mt_echo_threads=N` (default = CPU count) so
        // the harness can sweep it without rebuilding the kernel.
        #[cfg(feature = "mt-echo")]
        if !narf_verification::NARF_MT_ECHO_ELF.is_empty() {
            let n = parse_cmdline_count(narf_boot::cmdline(), "mt_echo_threads");
            let threads = if n == 0 {
                (narf_lib::smp::cpu_count() as usize).max(1)
            } else {
                n
            };
            let threads_str = alloc::format!("{threads}");
            spawn_one_argv(
                "mt-echo",
                narf_verification::NARF_MT_ECHO_ELF,
                &["mt-echo", "7000", &threads_str],
            );
        }
    }
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
#[allow(dead_code)] // TODO(narf): aarch64 boot-init stub; its caller is cfg'd out under kernel-test
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
