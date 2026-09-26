//! aarch64 SMP bring-up via PSCI.
//!
//! `cpu_on(target_aff, entry, context)` issues a `CPU_ON` SMC. QEMU
//! virt's PSCI implementation accepts HVC; real silicon may use SMC
//! depending on `psci-method` in the DTB. We default to HVC since
//! that's what QEMU exposes; SMC fallback can land if needed.
//!
//! The AP entry path lives in `smp_entry.S`. Rust on the BSP side:
//!   1. Reserves a contiguous per-CPU stack for each AP via `alloc_pages_on`.
//!   2. Stores the stack-top phys in `AP_STACKS[logical_id]`.
//!   3. Calls `cpu_on(target_aff, _ap_start_phys, logical_id)`.
//!   4. Spins until the AP marks itself online via
//!      `narf_lib::smp::mark_online(logical_id)`.

use core::arch::asm;
use core::sync::atomic::{compiler_fence, Ordering};

use core::fmt::Write;
use narf_console::Writer;

use narf_memory::alloc_pages_on;

/// PSCI 1.0 function ids.
const PSCI_CPU_ON_64: u64 = 0xC400_0003;

/// AP kernel stack order. APs run the full executor and take interrupts on this
/// stack, so they need the same 64 KiB headroom as x86_64 APs. A single 4 KiB
/// frame was observed to underflow by 0x3a0 bytes in `drain_and_wake`,
/// overwriting the adjacent live AArch64 page table.
///
/// The allocation must be one contiguous block: the entry trampoline receives
/// only a stack-top address and grows downward through the complete range.
const AP_STACK_ORDER: u8 = 4;
const AP_STACK_PAGES: u64 = 1 << AP_STACK_ORDER;

// Physical addresses of the AP trampoline entry and its stack table.
//
// `_ap_start` and `AP_STACKS` live in `.boot` / `.boot.data`, linked low so an
// AP can run them with the MMU off. Referencing them from here — kernel-half
// code — would emit a PC-relative page reference across ~512 GiB, which
// aarch64 ADRP cannot make; that is what pins this target to
// `code-model=large`. The linker puts the two VALUES in a kernel-half word
// instead, exactly as it does for the image bounds. Linux takes the same route
// in `psci.c`: `__pa_symbol(secondary_entry)`, never a physical symbol.
//
// See `.ap_boot_syms` in `build/linker/aarch64.ld`.
unsafe extern "C" {
    static __ap_boot_syms: [u64; 2];
}

/// Physical address of the AP trampoline entry (`_ap_start`).
#[inline]
fn ap_entry_phys() -> u64 {
    // SAFETY: a linker-populated word inside the image, read-only.
    let link_phys = unsafe { core::ptr::addr_of!(__ap_boot_syms).read()[0] };
    // The linker recorded where `_ap_start` was LINKED. If the image was
    // physically relocated, the copy is what runs and the original is still
    // sitting there looking valid, so an AP sent to the link-time address boots
    // against stale page tables and never checks in.
    narf_memory::kaslr::image_link_phys(link_phys)
}

/// Physical address of the per-CPU stack-top table (`AP_STACKS`,
/// `[u64; MAX_CPUS]` in `.boot.data`).
#[inline]
fn ap_stacks_phys() -> u64 {
    // SAFETY: a linker-populated word inside the image, read-only.
    let link_phys = unsafe { core::ptr::addr_of!(__ap_boot_syms).read()[1] };
    // Same conversion as the entry point, and it has to match: the BSP fills
    // this table through its kernel VA (so, the copy) while the AP reads it by
    // physical address. Converting only one of the two would have them
    // disagreeing about where the stacks are.
    narf_memory::kaslr::image_link_phys(link_phys)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PsciError {
    NotSupported = -1,
    InvalidParams = -2,
    Denied = -3,
    AlreadyOn = -4,
    OnPending = -5,
    InternalFail = -6,
    NotPresent = -7,
    Disabled = -8,
    InvalidAddress = -9,
    Unknown = -100,
}

fn map_psci_status(s: i64) -> Result<(), PsciError> {
    match s {
        0 => Ok(()),
        -1 => Err(PsciError::NotSupported),
        -2 => Err(PsciError::InvalidParams),
        -3 => Err(PsciError::Denied),
        -4 => Err(PsciError::AlreadyOn),
        -5 => Err(PsciError::OnPending),
        -6 => Err(PsciError::InternalFail),
        -7 => Err(PsciError::NotPresent),
        -8 => Err(PsciError::Disabled),
        -9 => Err(PsciError::InvalidAddress),
        _ => Err(PsciError::Unknown),
    }
}

/// Issue a PSCI `CPU_ON` HVC. `target_aff` is the MPIDR affinity
/// pack of the target CPU. `entry` is a *physical* address — APs
/// start with the MMU off, so passing a virtual kernel-half symbol
/// would land in unmapped space.
///
/// # Safety
/// HVC #0 traps to the secure firmware (or PSCI emulator). Caller
/// must confirm the platform exposes PSCI via HVC (QEMU virt does).
pub unsafe fn cpu_on(target_aff: u64, entry: u64, context: u64) -> Result<(), PsciError> {
    let status: i64;
    // SAFETY: HVC at EL1 invokes EL2's PSCI handler. Args follow
    // PSCI 1.0 §5.1.4: x0=function id, x1=target, x2=entry, x3=context.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        asm!(
            "hvc #0",
            inout("x0") PSCI_CPU_ON_64 => status,
            in("x1") target_aff,
            in("x2") entry,
            in("x3") context,
            // PSCI clobbers x0..x3 but defines x0 as the return.
            out("x4") _, out("x5") _, out("x6") _, out("x7") _,
            out("x8") _, out("x9") _, out("x10") _, out("x11") _,
            out("x12") _, out("x13") _, out("x14") _, out("x15") _,
            out("x16") _, out("x17") _,
            options(nostack),
        );
    }
    map_psci_status(status)
}

/// Bring up every AP advertised by `narf_lib::smp::cpu_count()`.
/// Each AP gets a freshly-allocated stack and is started via
/// PSCI `CPU_ON` with its logical id as the PSCI context.
///
/// Returns the number of APs that successfully marked themselves
/// online within the per-AP timeout.
///
/// # Safety
/// - `narf_memory::init_from_map` must have run.
/// - The kernel's TTBR0 / TTBR1 page tables (`l0_lo` / `l0_hi`) are
///   set up + reachable identity-mapped.
/// - GIC distributor is up.
pub unsafe fn start_aps() -> u32 {
    let total = narf_lib::smp::cpu_count();
    if total <= 1 {
        return 0;
    }

    let mut started = 0u32;
    for logical in 1..total {
        // Allocate one contiguous stack block. The AP starts with the MMU off,
        // so AP_STACKS carries its physical top; smp_entry.S rebases the empty
        // stack to the high direct map immediately after enabling the MMU.
        let stack_top = match alloc_pages_on(0, AP_STACK_ORDER) {
            Ok(f) => f.start_address().raw() + AP_STACK_PAGES * 4096,
            Err(_) => {
                let _ = writeln!(Writer, "  smp: AP {}: stack alloc failed", logical);
                continue;
            }
        };

        // SAFETY: the table is `[u64; MAX_CPUS]` in `.boot.data`, still
        // identity-mapped at this point in bring-up, `logical < total <=
        // MAX_CPUS`, and the BSP inside this call is its only writer.
        unsafe {
            (ap_stacks_phys() as *mut u64)
                .add(logical as usize)
                .write(stack_top);
        }
        compiler_fence(Ordering::SeqCst);

        // Target affinity: QEMU virt assigns Aff0 = logical_id (no
        // multi-cluster / multi-thread topology). Real platforms
        // need a DTB-derived MPIDR-affinity table; we default-derive
        // here.
        let target_aff = logical as u64;

        // Entry address: physical pointer to _ap_start (which lives
        // in .text, identity-mapped at low PA).
        let entry = ap_entry_phys();

        // Map this AP's GIC redistributor from the BSP, before the AP runs.
        // The AP would otherwise have to `ioremap` its own frame inside
        // `gic::init_ap`, which means allocating and taking the vmalloc locks
        // on a CPU that is still mid-bring-up with interrupts masked. Doing it
        // here keeps that work on the BSP and bounds it to CPUs that actually
        // start, rather than pre-mapping all MAX_CPUS frames.
        narf_interrupts::aarch64::gic::remap_mmio(logical);

        // SAFETY: PSCI HVC; arguments well-formed.
        match unsafe { cpu_on(target_aff, entry, logical as u64) } {
            Ok(()) => {
                let _ = writeln!(
                    Writer,
                    "  smp: PSCI CPU_ON aff={:#x} entry={:#x} ok",
                    target_aff, entry
                );
                // Wait briefly for the AP to mark itself online.
                let mut spins = 0u32;
                while !narf_lib::smp::is_online(logical) {
                    spins += 1;
                    if spins > 10_000_000 {
                        let _ = writeln!(Writer, "  smp: AP {} never reported online", logical);
                        break;
                    }
                    core::hint::spin_loop();
                }
                if narf_lib::smp::is_online(logical) {
                    started += 1;
                }
            }
            Err(e) => {
                let _ = writeln!(
                    Writer,
                    "  smp: PSCI CPU_ON aff={:#x} failed: {:?}",
                    target_aff, e
                );
            }
        }
    }
    started
}

/// Per-AP entry from `smp_entry.S`. Runs in EL1 with the MMU on
/// + the same TTBRs the BSP installed. Stack is set; FP/SIMD
/// + ATA enabled.
#[unsafe(no_mangle)]
pub extern "C" fn _ap_start_rust(logical_id: u64) -> ! {
    // 1. Register MPIDR mapping so current_cpu() returns logical_id
    //    for this CPU.
    let aff = narf_arch::aarch64::cpu::mpidr_aff();
    // SAFETY: per-CPU registration, called exactly once on this
    // CPU during bring-up.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        narf_arch::aarch64::cpu::set_current_cpu(aff, logical_id as u32);
    }

    // PSTATE.SSBS is per-CPU. Apply the protected policy before this AP
    // becomes visible to the scheduler.
    // SAFETY: EL1, IRQs masked, and this AP is not yet online.
    let speculation_state = unsafe {
        narf_arch::speculation::configure_current_cpu(narf_arch::speculation::Policy::Protected)
    };
    if speculation_state == narf_arch::speculation::State::Failed {
        narf_arch::halt_forever();
    }

    // 2. Install the EL1 vector table — APs share the BSP's table
    //    in .text but each CPU writes its own VBAR_EL1 to point at
    //    it.
    extern "C" {
        static __narf_vector_table: u8;
    }
    let vbar = core::ptr::addr_of!(__narf_vector_table) as u64;
    // SAFETY: vector-table base is the linker-provided symbol, valid
    // for every CPU's EL1 view.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        narf_arch::aarch64::sysreg::write_vbar_el1(vbar);
    }

    // 3. Per-CPU GICv3 init: cpu interface + redistributor wake +
    //    timer-PPI enable.
    // SAFETY: distributor was already brought up by the BSP; this
    // CPU only touches its own redistributor + sysregs.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        narf_interrupts::aarch64::gic::init_ap(logical_id as u32);
    }

    // 3b. Install framework-default SGI handlers (PANIC_HALT,
    //     RESCHED). Drivers can override after.
    narf_interrupts::aarch64::sgi::install_defaults();

    // 4. Mark online — the BSP's start_aps() spins on this.
    // SAFETY: per-CPU bookkeeping.
    unsafe {
        narf_lib::smp::mark_online(logical_id as u32);
    }

    // 5. Start this CPU's generic timer + unmask DAIF for IRQ
    //    delivery. With the timer firing the AP-side trap path
    //    drives the per-CPU tick counter.
    // SAFETY: GIC + vector table installed.
    unsafe {
        narf_interrupts::aarch64::timer::start_timer(crate::aarch64::trap::TIMER_TVAL_DEFAULT);
        narf_arch::enable_interrupts();
    }

    // 6. Enter the per-CPU scheduler run loop. `run_forever` drains
    //    this CPU's ready queue, attempts to steal from siblings,
    //    and halts on IRQ (WFI inside `halt_until_irq`) when there
    //    is nothing to run. Returns never.
    narf_scheduler::run_forever();
}
