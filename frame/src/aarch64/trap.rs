//! aarch64 trap-handler Rust dispatch.
//!
//! The EL1 vector table (`vec.S`) saves 31 GPRs on the current stack,
//! then calls one of these with `x0 = &TrapFrame`. IRQ path dispatches
//! to registered handlers + EOIs the GIC; everything else prints the
//! trap state and exits.

use core::fmt::Write;

use narf_console::Writer;
use narf_arch::aarch64::sysreg;

/// On-stack layout saved by `vec.S`'s `SAVE_ALL_GPRS` macro.
/// The last push is `x30`, so `x30` is at offset 0 when Rust reads
/// the frame pointer (= current SP after the macro).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct TrapFrame {
    pub x30: u64,
    pub x0:  u64, pub x1:  u64,
    pub x2:  u64, pub x3:  u64,
    pub x4:  u64, pub x5:  u64,
    pub x6:  u64, pub x7:  u64,
    pub x8:  u64, pub x9:  u64,
    pub x10: u64, pub x11: u64,
    pub x12: u64, pub x13: u64,
    pub x14: u64, pub x15: u64,
    pub x16: u64, pub x17: u64,
    pub x18: u64, pub x19: u64,
    pub x20: u64, pub x21: u64,
    pub x22: u64, pub x23: u64,
    pub x24: u64, pub x25: u64,
    pub x26: u64, pub x27: u64,
    pub x28: u64, pub x29: u64,
}

/// Called from `__narf_vec_irq` in `vec.S`. Reads the GIC's ICC_IAR1_EL1
/// to acknowledge the IRQ, dispatches to the registered handler by
/// INTID, then writes ICC_EOIR1_EL1 to release the priority.
#[unsafe(no_mangle)]
pub extern "C" fn rust_aarch64_irq(_frame: &TrapFrame) {
    // SAFETY: we are in the IRQ handler by the vector-table contract.
    let iar = unsafe { sysreg::read_icc_iar1_el1() };
    let intid = (iar & 0x00FF_FFFF) as u32;

    match intid {
        n if n == narf_interrupts::aarch64::TIMER_PPI => {
            narf_interrupts::aarch64::timer::on_timer_tick();
            // Re-arm the timer for another round. Same value as the
            // initial programming — the Stage-2 period is controlled
            // by whoever called `start_timer` originally; for the
            // default demo we use TIMER_TVAL_DEFAULT.
            // SAFETY: we are inside the timer IRQ handler.
            unsafe {
                narf_interrupts::aarch64::timer::rearm_timer(TIMER_TVAL_DEFAULT);
            }
        }
        1023 => {
            // Spurious: ICC_IAR1_EL1 returned the spurious INTID;
            // don't EOI, just return.
            return;
        }
        _ => { /* unregistered vector — drop */ }
    }

    // SAFETY: write the same IAR value we read to EOI.
    unsafe { narf_interrupts::aarch64::eoi_for(iar); }
}

/// Default generic-timer countdown in CNTPCT ticks. At QEMU virt's
/// typical 62.5 MHz CNTFRQ this is ~80 ms per IRQ.
pub const TIMER_TVAL_DEFAULT: u64 = 5_000_000;

#[unsafe(no_mangle)]
pub extern "C" fn rust_aarch64_sync(frame: &TrapFrame) -> ! {
    // SAFETY: MRS ESR_EL1 / FAR_EL1 / ELR_EL1 are always legal.
    let (esr, far, elr) = unsafe {
        (sysreg::read_esr_el1(), sysreg::read_far_el1(), sysreg::read_elr_el1())
    };
    let _ = writeln!(Writer, "\n*** AARCH64 SYNCHRONOUS EXCEPTION ***");
    let _ = writeln!(Writer, "  ESR_EL1: {:#018x}", esr);
    let _ = writeln!(Writer, "  FAR_EL1: {:#018x}", far);
    let _ = writeln!(Writer, "  ELR_EL1: {:#018x}", elr);
    dump_frame(frame);
    // SAFETY: exit is our fail path.
    unsafe { narf_arch::exit_kernel(42) }
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_aarch64_sync_sp0(frame: &TrapFrame) -> ! {
    // SAFETY: ESR_EL1 always legal.
    let esr = unsafe { sysreg::read_esr_el1() };
    let _ = writeln!(Writer, "\n*** AARCH64 SYNC (SP0) ***  ESR={:#x}", esr);
    dump_frame(frame);
    // SAFETY: exit.
    unsafe { narf_arch::exit_kernel(42) }
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_aarch64_serror(frame: &TrapFrame) -> ! {
    // SAFETY: ESR_EL1 always legal.
    let esr = unsafe { sysreg::read_esr_el1() };
    let _ = writeln!(Writer, "\n*** AARCH64 SError ***  ESR={:#x}", esr);
    dump_frame(frame);
    // SAFETY: exit.
    unsafe { narf_arch::exit_kernel(42) }
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_aarch64_unimpl(frame: &TrapFrame) -> ! {
    let _ = writeln!(Writer, "\n*** AARCH64 vector: unimplemented slot ***");
    dump_frame(frame);
    // SAFETY: exit.
    unsafe { narf_arch::exit_kernel(42) }
}

fn dump_frame(f: &TrapFrame) {
    let _ = writeln!(Writer, "  x0:  {:#018x}   x1:  {:#018x}", f.x0, f.x1);
    let _ = writeln!(Writer, "  x2:  {:#018x}   x3:  {:#018x}", f.x2, f.x3);
    let _ = writeln!(Writer, "  x30: {:#018x}", f.x30);
}
