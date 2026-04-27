//! aarch64 SMP bring-up via PSCI.
//!
//! `cpu_on(target_aff, entry, context)` issues a `CPU_ON` SMC. QEMU
//! virt's PSCI implementation accepts HVC; real silicon may use SMC
//! depending on `psci-method` in the DTB. We default to HVC since
//! that's what QEMU exposes; SMC fallback can land if needed.
//!
//! The AP entry path lives in `smp_entry.S`. Rust on the BSP side:
//!   1. Reserves a per-CPU stack for each AP via `alloc_frame`.
//!   2. Stores the stack-top phys in `AP_STACKS[logical_id]`.
//!   3. Calls `cpu_on(target_aff, _ap_start_phys, logical_id)`.
//!   4. Spins until the AP marks itself online via
//!      `narf_lib::smp::mark_online(logical_id)`.

use core::arch::asm;
use core::sync::atomic::{compiler_fence, Ordering};

use narf_console::Writer;
use core::fmt::Write;

use narf_memory::alloc_frame;

/// PSCI 1.0 function ids.
const PSCI_CPU_ON_64:        u64 = 0xC400_0003;

/// Per-AP stack size in bytes (4 KiB → one frame). Matches BSP's
/// boot stack; kernel-test workloads fit in a single frame.
const AP_STACK_PAGES: usize = 1;

/// AP entry symbol (defined in `smp_entry.S`).
extern "C" {
    fn _ap_start();
    /// Per-CPU stack-top table — [u64; MAX_CPUS] in `.boot.data`.
    static mut AP_STACKS: [u64; 64];
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PsciError {
    NotSupported   = -1,
    InvalidParams  = -2,
    Denied         = -3,
    AlreadyOn      = -4,
    OnPending      = -5,
    InternalFail   = -6,
    NotPresent     = -7,
    Disabled       = -8,
    InvalidAddress = -9,
    Unknown        = -100,
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
pub unsafe fn cpu_on(target_aff: u64, entry: u64, context: u64)
    -> Result<(), PsciError>
{
    let status: i64;
    // SAFETY: HVC at EL1 invokes EL2's PSCI handler. Args follow
    // PSCI 1.0 §5.1.4: x0=function id, x1=target, x2=entry, x3=context.
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
        // Allocate a stack for this AP.
        let mut stack_top: u64 = 0;
        for _ in 0..AP_STACK_PAGES {
            match alloc_frame() {
                Ok(f) => {
                    let base = f.start_address().raw();
                    // Stack grows down; top = base + 4 KiB.
                    if stack_top == 0 { stack_top = base + 4096; }
                }
                Err(_) => {
                    let _ = writeln!(Writer,
                        "  smp: AP {}: stack alloc failed", logical);
                    continue;
                }
            }
        }
        if stack_top == 0 { continue; }

        // SAFETY: AP_STACKS is in .boot.data, the only writer is
        // the BSP during this start_aps call.
        unsafe {
            (*core::ptr::addr_of_mut!(AP_STACKS))[logical as usize] =
                stack_top;
        }
        compiler_fence(Ordering::SeqCst);

        // Target affinity: QEMU virt assigns Aff0 = logical_id (no
        // multi-cluster / multi-thread topology). Real platforms
        // need a DTB-derived MPIDR-affinity table; we default-derive
        // here.
        let target_aff = logical as u64;

        // Entry address: physical pointer to _ap_start (which lives
        // in .text, identity-mapped at low PA).
        let entry = (_ap_start as usize) as u64;

        // SAFETY: PSCI HVC; arguments well-formed.
        match unsafe { cpu_on(target_aff, entry, logical as u64) } {
            Ok(()) => {
                let _ = writeln!(Writer,
                    "  smp: PSCI CPU_ON aff={:#x} entry={:#x} ok",
                    target_aff, entry);
                // Wait briefly for the AP to mark itself online.
                let mut spins = 0u32;
                while !narf_lib::smp::is_online(logical) {
                    spins += 1;
                    if spins > 10_000_000 {
                        let _ = writeln!(Writer,
                            "  smp: AP {} never reported online", logical);
                        break;
                    }
                    core::hint::spin_loop();
                }
                if narf_lib::smp::is_online(logical) {
                    started += 1;
                }
            }
            Err(e) => {
                let _ = writeln!(Writer,
                    "  smp: PSCI CPU_ON aff={:#x} failed: {:?}",
                    target_aff, e);
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
    unsafe { narf_arch::aarch64::cpu::set_current_cpu(aff, logical_id as u32); }

    // 2. Install the EL1 vector table — APs share the BSP's table
    //    in .text but each CPU writes its own VBAR_EL1 to point at
    //    it.
    extern "C" {
        static __narf_vector_table: u8;
    }
    let vbar = core::ptr::addr_of!(__narf_vector_table) as u64;
    // SAFETY: vector-table base is the linker-provided symbol, valid
    // for every CPU's EL1 view.
    unsafe { narf_arch::aarch64::sysreg::write_vbar_el1(vbar); }

    // 3. Per-CPU GICv3 init: cpu interface + redistributor wake +
    //    timer-PPI enable.
    // SAFETY: distributor was already brought up by the BSP; this
    // CPU only touches its own redistributor + sysregs.
    unsafe { narf_interrupts::aarch64::gic::init_ap(logical_id as u32); }

    // 3b. Install framework-default SGI handlers (PANIC_HALT,
    //     RESCHED). Drivers can override after.
    narf_interrupts::aarch64::sgi::install_defaults();

    // 4. Mark online — the BSP's start_aps() spins on this.
    // SAFETY: per-CPU bookkeeping.
    unsafe { narf_lib::smp::mark_online(logical_id as u32); }

    // 5. Start this CPU's generic timer + unmask DAIF for IRQ
    //    delivery. With the timer firing the AP-side trap path
    //    drives the per-CPU tick counter.
    // SAFETY: GIC + vector table installed.
    unsafe {
        narf_interrupts::aarch64::timer::start_timer(
            crate::aarch64::trap::TIMER_TVAL_DEFAULT);
        narf_arch::enable_interrupts();
    }

    // 6. Park in WFI. Each timer IRQ wakes the AP for ack + tick
    //    increment, then back to sleep. Real per-CPU scheduler
    //    run-loop lands when the run queues become per-CPU.
    loop {
        // SAFETY: WFI at EL1 wakes on IRQ regardless of DAIF mask
        // state; we're unmasked so timer IRQs deliver.
        unsafe { asm!("wfi", options(nostack, preserves_flags)); }
    }
}
