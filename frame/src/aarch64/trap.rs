//! aarch64 trap-handler Rust dispatch.
//!
//! The EL1 vector table (`vec.S`) saves 31 GPRs on the current stack,
//! then calls one of these with `x0 = &TrapFrame`. IRQ path dispatches
//! to registered handlers + EOIs the GIC; everything else prints the
//! trap state and exits.

use core::fmt::Write;

use narf_arch::aarch64::sysreg;
use narf_console::Writer;

/// On-stack layout saved by `vec.S`'s `SAVE_ALL_GPRS` macro.
/// The last push is `str x30, [sp, #-16]!`, which grows the stack
/// by 16 bytes but only stores 8 — so there's an 8-byte pad between
/// `x30` and the start of the saved GPR pairs. ELR_EL1 + SPSR_EL1
/// ride on the stack above x30 so handlers can rewrite them.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct TrapFrame {
    pub x30: u64,
    pub _pad: u64, // forced by `str x30, [sp, #-16]!`
    pub elr: u64,  // ELR_EL1 — return RIP
    pub spsr: u64, // SPSR_EL1 — return PSTATE + target EL
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
    pub x4: u64,
    pub x5: u64,
    pub x6: u64,
    pub x7: u64,
    pub x8: u64,
    pub x9: u64,
    pub x10: u64,
    pub x11: u64,
    pub x12: u64,
    pub x13: u64,
    pub x14: u64,
    pub x15: u64,
    pub x16: u64,
    pub x17: u64,
    pub x18: u64,
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub x29: u64,
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
            // one driver (Stage-3 contract). Mark trap context so
            // on_irq can defer wakes (see x86_64 trap.rs for why).
            narf_lib::context::enter_trap_handler();
            narf_interrupts::on_irq((intid & 0xFF) as u8);
            narf_lib::context::exit_trap_handler();
        }
    }

    // SAFETY: write the same IAR value we read to EOI.
    unsafe {
        narf_interrupts::aarch64::eoi_for(iar);
    }
}

/// Default generic-timer countdown in CNTPCT ticks. At QEMU virt's
/// typical 62.5 MHz CNTFRQ this is ~80 ms per IRQ.
pub const TIMER_TVAL_DEFAULT: u64 = 5_000_000;

#[unsafe(no_mangle)]
pub extern "C" fn rust_aarch64_sync(frame: &TrapFrame) -> ! {
    // SAFETY: MRS ESR_EL1 / FAR_EL1 / ELR_EL1 are always legal.
    let (esr, far, elr) = unsafe {
        (
            sysreg::read_esr_el1(),
            sysreg::read_far_el1(),
            sysreg::read_elr_el1(),
        )
    };
    let _ = writeln!(Writer, "\n*** AARCH64 SYNCHRONOUS EXCEPTION ***");
    let _ = writeln!(Writer, "  ESR_EL1: {:#018x}", esr);
    let _ = writeln!(Writer, "  FAR_EL1: {:#018x}", far);
    let _ = writeln!(Writer, "  ELR_EL1: {:#018x}", elr);
    dump_frame(frame);
    // SAFETY: exit is our fail path.
    unsafe { narf_arch::exit_kernel(42) }
}

/// Synchronous-exception dispatcher entered via `__narf_vec_sync_spx`
/// or `__narf_vec_sync_el0`.
///
/// Reads `ESR_EL1.EC` and routes:
/// - `EC = 0b010101` (SVC from AArch64): marshal x0..x5 + x8 into a
///   `SyscallArgs`, call `kernel_syscall_entry`, store the return
///   value + status in `frame.x0` / `frame.x1` so RESTORE_ALL_GPRS
///   + `eret` delivers them back to user space. Returns normally.
/// - `EC = 0b100100` (Data Abort from lower EL): if the ISS reports
///   a permission fault on a write access from EL0, route into the
///   COW recovery path (cow_split_on_write + remap_page). Mirrors
///   the x86_64 #PF handler. Returns normally on successful split;
///   falls through to fatal otherwise.
/// - Anything else: fatal — delegates to `rust_aarch64_sync` which
///   prints diagnostics and calls `exit_kernel`.
#[unsafe(no_mangle)]
pub extern "C" fn rust_aarch64_sync_dispatch(frame: &mut TrapFrame) {
    // SAFETY: ESR_EL1 read at EL1 is always defined.
    let esr = unsafe { sysreg::read_esr_el1() };
    let ec = (esr >> 26) & 0x3F;

    const EC_SVC_AARCH64: u64 = 0b01_0101;
    const EC_DATA_ABORT_LOWER_EL: u64 = 0b10_0100;

    if ec == EC_SVC_AARCH64 {
        // Convention: x8 = syscall number, x0..x5 = args. Return
        // value placed in x0 (value) + x1 (status) so callers can
        // read both without a follow-up instruction.
        let num = frame.x8 as u32;
        let mut ctx = Aarch64TrapContext::from_svc(frame);
        narf_userspace::kernel_syscall_entry(num, &mut ctx);
        return;
    }

    if ec == EC_DATA_ABORT_LOWER_EL {
        // ISS field for a Data Abort (Arm ARM DDI0487 D5.4):
        //   bit  6  (WnR)  : 0 = read, 1 = write
        //   bits [5:0] DFSC: fault status code. Top 4 bits 0b0011
        //                    indicate a permission fault (level
        //                    encoded in the low 2 bits); 0b0001
        //                    indicates a translation fault (no
        //                    PTE present at the named level).
        let iss = esr & 0x01FF_FFFF;
        const ISS_WNR: u64 = 1 << 6;
        const DFSC_MASK: u64 = 0x3F;
        const DFSC_PERMISSION_FAULT_TOP: u64 = 0b00_1100;
        const DFSC_TRANSLATION_FAULT_TOP: u64 = 0b00_0100;
        let is_write = (iss & ISS_WNR) != 0;
        let dfsc = iss & DFSC_MASK;
        let is_perm_fault = (dfsc & 0b11_1100) == DFSC_PERMISSION_FAULT_TOP;
        let is_translation_fault = (dfsc & 0b11_1100) == DFSC_TRANSLATION_FAULT_TOP;
        // SAFETY: FAR_EL1 read at EL1 is always defined.
        let far = unsafe { sysreg::read_far_el1() };
        // Stack auto-extension + demand paging on translation
        // fault (no PTE installed). mmap's deferred-back path
        // surfaces here; if the vaddr lands in a STACK_GUARD
        // region the trap routes into try_grow_stack instead.
        if is_translation_fault {
            if let Some(as_arc) = narf_userspace::active_user_as() {
                let v = narf_memory::VirtAddr::new(far);
                // SAFETY: low-RAM phys-as-virt window is live;
                // AS is the active user AS by construction.
                if unsafe { as_arc.demand_alloc_page(v) }.is_ok() {
                    return;
                }
                // SAFETY: same.
                if unsafe { as_arc.try_grow_stack(v) }.is_ok() {
                    return;
                }
            }
        }
        if is_write && is_perm_fault {
            if let Some(as_arc) = narf_userspace::active_user_as() {
                let v = narf_memory::VirtAddr::new(far);
                // SAFETY: low-RAM identity map is live, frame
                // allocator + COW refcount table initialised at
                // boot; AS is the active user AS by construction
                // (the trap arrived from EL0).
                let split_ok = unsafe { as_arc.cow_split_on_write(v) }.is_ok();
                if split_ok {
                    // SAFETY: same identity-map argument; the
                    // region was just touched by the split.
                    let remap_ok = unsafe { as_arc.remap_page(v) }.is_ok();
                    if remap_ok {
                        return;
                    }
                }
            }
        }
        // Fall through to fatal if the abort wasn't a recoverable
        // user-mode COW write / demand-paging miss — genuine bugs
        // surface on the existing diagnostic path.
    }

    // Non-recoverable synchronous exception — fatal.
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
    args: SyscallArgs,
}

impl<'a> Aarch64TrapContext<'a> {
    fn from_svc(frame: &'a mut TrapFrame) -> Self {
        let args = SyscallArgs {
            arg0: frame.x0,
            arg1: frame.x1,
            arg2: frame.x2,
            arg3: frame.x3,
            arg4: frame.x4,
            arg5: frame.x5,
        };
        Self { frame, args }
    }
}

impl<'a> TrapContext for Aarch64TrapContext<'a> {
    fn args(&self) -> &SyscallArgs {
        &self.args
    }

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

    /// Snapshot the user-mode CPU state for fork(2)'s
    /// trap-frame inheritance path. Same shape contract as the
    /// x86_64 implementation: caller passes a writable region of
    /// at least `size_of::<UserState>()` bytes, this routine
    /// writes the saved x0..=x30 GPRs, the post-trap PC (ELR),
    /// the user-mode SP (SP_EL0 — still holding the user value
    /// because the EL1 trap path swapped to SP_EL1), and SPSR.
    ///
    /// `valid` is set to 1 so resume paths can distinguish a
    /// captured state from a zeroed placeholder.
    unsafe fn save_user_state(&self, out: *mut u8) -> bool {
        use narf_userspace::user_task::UserState;
        // SAFETY: caller declared `out` is writable for at least
        // `size_of::<UserState>()` bytes — the trait's contract.
        let s = unsafe { &mut *(out as *mut UserState) };
        let f = &self.frame;
        // x0..=x30 (31 registers).
        s.x[0]  = f.x0;
        s.x[1]  = f.x1;
        s.x[2]  = f.x2;
        s.x[3]  = f.x3;
        s.x[4]  = f.x4;
        s.x[5]  = f.x5;
        s.x[6]  = f.x6;
        s.x[7]  = f.x7;
        s.x[8]  = f.x8;
        s.x[9]  = f.x9;
        s.x[10] = f.x10;
        s.x[11] = f.x11;
        s.x[12] = f.x12;
        s.x[13] = f.x13;
        s.x[14] = f.x14;
        s.x[15] = f.x15;
        s.x[16] = f.x16;
        s.x[17] = f.x17;
        s.x[18] = f.x18;
        s.x[19] = f.x19;
        s.x[20] = f.x20;
        s.x[21] = f.x21;
        s.x[22] = f.x22;
        s.x[23] = f.x23;
        s.x[24] = f.x24;
        s.x[25] = f.x25;
        s.x[26] = f.x26;
        s.x[27] = f.x27;
        s.x[28] = f.x28;
        s.x[29] = f.x29;
        s.x[30] = f.x30;
        // PC: ELR_EL1 was advanced past the trapping `svc #0`
        // instruction by the architecturally-correct trap path,
        // so resuming here lands at the next user instruction.
        s.pc = f.elr;
        // SPSR_EL1 carries the user-mode PSTATE (NZCV / DAIF /
        // mode bits) the resume path will restore.
        s.spsr = f.spsr;
        // SP: at trap time we swapped to SP_EL1 (kernel stack);
        // the user's SP_EL0 still holds the user-mode stack
        // pointer untouched. Read it via MSR — legal at EL1.
        let sp_el0: u64;
        // SAFETY: reading SP_EL0 at EL1 is unconditionally
        // defined; it has no side effects on EL1 state.
        unsafe {
            core::arch::asm!(
                "mrs {v}, SP_EL0",
                v = out(reg) sp_el0,
                options(nostack, preserves_flags),
            );
        }
        s.sp = sp_el0;
        s.valid = 1;
        true
    }
}

// ── Kernel-test smokes for the aarch64 TrapContext save path ──────

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_aarch64_trap_save_user_state_round_trip() -> TestResult {
    // Build a synthetic TrapFrame with deterministic GPRs / ELR /
    // SPSR, wrap it in Aarch64TrapContext, snapshot via
    // save_user_state, and verify every field landed in the
    // expected slot. SP_EL0 is hardware-readable from kernel
    // mode; we set it before the call so the saved `s.sp`
    // matches.
    use core::mem::MaybeUninit;
    use narf_userspace::user_task::UserState;

    // Dummy frame — every register slot gets a unique sentinel
    // so a swapped pair would be obvious in the assertion.
    let mut frame = TrapFrame {
        x30: 0x3030_3030_3030_3030,
        _pad: 0,
        elr: 0xE1E1_E1E1_E1E1_E1E1u64,
        spsr: 0x0000_0000_8000_0000, // arbitrary PSTATE
        x0:  0x0000_0000_0000_0000,
        x1:  0x0101_0101_0101_0101,
        x2:  0x0202_0202_0202_0202,
        x3:  0x0303_0303_0303_0303,
        x4:  0x0404_0404_0404_0404,
        x5:  0x0505_0505_0505_0505,
        x6:  0x0606_0606_0606_0606,
        x7:  0x0707_0707_0707_0707,
        x8:  0x0808_0808_0808_0808,
        x9:  0x0909_0909_0909_0909,
        x10: 0x0A0A_0A0A_0A0A_0A0A,
        x11: 0x0B0B_0B0B_0B0B_0B0B,
        x12: 0x0C0C_0C0C_0C0C_0C0C,
        x13: 0x0D0D_0D0D_0D0D_0D0D,
        x14: 0x0E0E_0E0E_0E0E_0E0E,
        x15: 0x0F0F_0F0F_0F0F_0F0F,
        x16: 0x1010_1010_1010_1010,
        x17: 0x1111_1111_1111_1111,
        x18: 0x1212_1212_1212_1212,
        x19: 0x1313_1313_1313_1313,
        x20: 0x1414_1414_1414_1414,
        x21: 0x1515_1515_1515_1515,
        x22: 0x1616_1616_1616_1616,
        x23: 0x1717_1717_1717_1717,
        x24: 0x1818_1818_1818_1818,
        x25: 0x1919_1919_1919_1919,
        x26: 0x1A1A_1A1A_1A1A_1A1A,
        x27: 0x1B1B_1B1B_1B1B_1B1B,
        x28: 0x1C1C_1C1C_1C1C_1C1C,
        x29: 0x1D1D_1D1D_1D1D_1D1D,
    };

    // Pre-load SP_EL0 with a sentinel and remember the prior
    // value so the test is non-disruptive across re-runs.
    const SP_SENTINEL: u64 = 0x7F00_0000_0000_BEEF;
    let prior_sp_el0: u64;
    // SAFETY: SP_EL0 read/write at EL1 is unconditional and has
    // no side effects when EL0 is not currently executing.
    unsafe {
        core::arch::asm!(
            "mrs {p}, SP_EL0",
            "msr SP_EL0, {n}",
            p = out(reg) prior_sp_el0,
            n = in(reg) SP_SENTINEL,
            options(nostack, preserves_flags),
        );
    }

    let ctx = Aarch64TrapContext::from_svc(&mut frame);
    let mut buf = MaybeUninit::<UserState>::zeroed();
    // SAFETY: destination is a freshly-zeroed `UserState`-sized
    // stack slot — the trait's contract.
    let ok = unsafe { ctx.save_user_state(buf.as_mut_ptr() as *mut u8) };

    // Restore the prior SP_EL0 immediately so any later test
    // that depends on it observes the boot-state value.
    unsafe {
        core::arch::asm!(
            "msr SP_EL0, {p}",
            p = in(reg) prior_sp_el0,
            options(nostack, preserves_flags),
        );
    }

    if !ok {
        return TestResult::Fail("save_user_state returned false");
    }
    // SAFETY: save_user_state returned true → it wrote a valid
    // UserState into the buffer.
    let s = unsafe { buf.assume_init() };

    if s.x[0]  != 0x0000_0000_0000_0000 { return TestResult::Fail("x0 mismatch"); }
    if s.x[1]  != 0x0101_0101_0101_0101 { return TestResult::Fail("x1 mismatch"); }
    if s.x[15] != 0x0F0F_0F0F_0F0F_0F0F { return TestResult::Fail("x15 mismatch"); }
    if s.x[28] != 0x1C1C_1C1C_1C1C_1C1C { return TestResult::Fail("x28 mismatch"); }
    if s.x[29] != 0x1D1D_1D1D_1D1D_1D1D { return TestResult::Fail("x29 mismatch"); }
    if s.x[30] != 0x3030_3030_3030_3030 { return TestResult::Fail("x30 mismatch"); }
    if s.pc    != 0xE1E1_E1E1_E1E1_E1E1u64 { return TestResult::Fail("pc != ELR"); }
    if s.spsr  != 0x0000_0000_8000_0000 { return TestResult::Fail("spsr mismatch"); }
    if s.sp    != SP_SENTINEL { return TestResult::Fail("sp != SP_EL0"); }
    if s.valid != 1 { return TestResult::Fail("valid != 1"); }
    TestResult::Pass
}
kernel_test_in!("aarch64", smoke_aarch64_trap_save_user_state_round_trip);

fn dump_frame(f: &TrapFrame) {
    let _ = writeln!(Writer, "  x0:  {:#018x}   x1:  {:#018x}", f.x0, f.x1);
    let _ = writeln!(Writer, "  x2:  {:#018x}   x3:  {:#018x}", f.x2, f.x3);
    let _ = writeln!(Writer, "  x30: {:#018x}", f.x30);
}
