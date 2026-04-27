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
/// The last push is `str x30, [sp, #-16]!`, which grows the stack
/// by 16 bytes but only stores 8 — so there's an 8-byte pad between
/// `x30` and the start of the saved GPR pairs. ELR_EL1 + SPSR_EL1
/// ride on the stack above x30 so handlers can rewrite them.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct TrapFrame {
    pub x30:   u64,
    pub _pad:  u64,                  // forced by `str x30, [sp, #-16]!`
    pub elr:   u64,                  // ELR_EL1 — return RIP
    pub spsr:  u64,                  // SPSR_EL1 — return PSTATE + target EL
    pub x0:   u64, pub x1:  u64,
    pub x2:   u64, pub x3:  u64,
    pub x4:   u64, pub x5:  u64,
    pub x6:   u64, pub x7:  u64,
    pub x8:   u64, pub x9:  u64,
    pub x10:  u64, pub x11: u64,
    pub x12:  u64, pub x13: u64,
    pub x14:  u64, pub x15: u64,
    pub x16:  u64, pub x17: u64,
    pub x18:  u64, pub x19: u64,
    pub x20:  u64, pub x21: u64,
    pub x22:  u64, pub x23: u64,
    pub x24:  u64, pub x25: u64,
    pub x26:  u64, pub x27: u64,
    pub x28:  u64, pub x29: u64,
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
        n if n < 16 => {
            // Software-Generated Interrupt (cross-CPU IPI).
            narf_interrupts::aarch64::sgi::on_sgi(n as u8);
        }
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
        _ => {
            // Driver-registered IRQ. The dispatch table is keyed on a
            // logical 8-bit vector; for SPIs in 32..=287 and LPIs >=
            // 8192 the low byte is enough to disambiguate inside any
            // one driver (Stage-3 contract).
            narf_interrupts::on_irq((intid & 0xFF) as u8);
        }
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

/// Synchronous-exception dispatcher entered via `__narf_vec_sync_spx`.
///
/// Reads `ESR_EL1.EC` and routes:
/// - `EC = 0b010101` (SVC from AArch64): marshal x0..x5 + x8 into a
///   `SyscallArgs`, call `kernel_syscall_entry`, store the return
///   value + status in `frame.x0` / `frame.x1` so RESTORE_ALL_GPRS
///   + `eret` delivers them back to user space. Returns normally.
/// - Anything else: fatal — delegates to `rust_aarch64_sync` which
///   prints diagnostics and calls `exit_kernel`.
#[unsafe(no_mangle)]
pub extern "C" fn rust_aarch64_sync_dispatch(frame: &mut TrapFrame) {
    // SAFETY: ESR_EL1 read at EL1 is always defined.
    let esr = unsafe { sysreg::read_esr_el1() };
    let ec  = (esr >> 26) & 0x3F;

    const EC_SVC_AARCH64: u64 = 0b01_0101;

    if ec == EC_SVC_AARCH64 {
        // Convention: x8 = syscall number, x0..x5 = args. Return
        // value placed in x0 (value) + x1 (status) so callers can
        // read both without a follow-up instruction.
        let num = frame.x8 as u32;
        let mut ctx = Aarch64TrapContext::from_svc(frame);
        narf_userspace::kernel_syscall_entry(num, &mut ctx);
        return;
    }

    // Non-SVC synchronous exception — fatal.
    rust_aarch64_sync(frame);
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

// ── TrapContext impl for the SVC path ──────────────────────────────

use narf_userspace::{SyscallArgs, SyscallReturn, TrapContext};

/// aarch64 `TrapContext` wrapper around a live SVC-trap frame.
struct Aarch64TrapContext<'a> {
    frame: &'a mut TrapFrame,
    args:  SyscallArgs,
}

impl<'a> Aarch64TrapContext<'a> {
    fn from_svc(frame: &'a mut TrapFrame) -> Self {
        let args = SyscallArgs {
            arg0: frame.x0, arg1: frame.x1, arg2: frame.x2,
            arg3: frame.x3, arg4: frame.x4, arg5: frame.x5,
        };
        Self { frame, args }
    }
}

impl<'a> TrapContext for Aarch64TrapContext<'a> {
    fn args(&self) -> &SyscallArgs { &self.args }

    fn set_return(&mut self, ret: SyscallReturn) {
        self.frame.x0 = ret.value;
        self.frame.x1 = ret.status as u64;
    }

    fn redirect_to_kernel(&mut self, rip: u64, rsp: u64) -> bool {
        // Rewrite ELR_EL1 to the kernel landing; SPSR_EL1's mode
        // field picks EL1h (SP_ELx selected). Push the requested
        // kernel stack into x30 so the landing can `mov sp, x30`
        // if it wants a custom stack (a naked trampoline can also
        // load a full jmpbuf rsp separately).
        self.frame.elr = rip;
        // SPSR_EL1: M[4:0] = 0b00101 (EL1h), DAIF cleared.
        self.frame.spsr = 0x0000_0000_0000_0005;
        self.frame.x30 = rsp;
        true
    }
}

fn dump_frame(f: &TrapFrame) {
    let _ = writeln!(Writer, "  x0:  {:#018x}   x1:  {:#018x}", f.x0, f.x1);
    let _ = writeln!(Writer, "  x2:  {:#018x}   x3:  {:#018x}", f.x2, f.x3);
    let _ = writeln!(Writer, "  x30: {:#018x}", f.x30);
}
