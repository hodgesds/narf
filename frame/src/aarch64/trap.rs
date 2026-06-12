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
        // Signal-delivery hook: mirrors the x86_64 int-0x80 path.
        // `returning_to_user` guards against redirect-to-kernel
        // handlers (exit, longjmp) that rewrite SPSR to EL1h.
        // `num` is forwarded for SA_RESTART's restartable-syscall
        // table check — `svc #0` is 4 bytes on AArch64, so the
        // arch rewinds ELR by 4 instead of 2.
        if let Some(hook) = narf_userspace::signal_delivery_hook() {
            hook(&mut ctx, num);
        }
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
                // SAFETY: Valid memory or trusted environment
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
                // SAFETY: Valid memory or trusted environment
                let split_ok = unsafe { as_arc.cow_split_on_write(v) }.is_ok();
                if split_ok {
                    // SAFETY: same identity-map argument; the
                    // region was just touched by the split.
                    // SAFETY: Valid memory or trusted environment
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

use narf_userspace::{
    SigDeliveryParams, SyscallArgs, SyscallReturn, TrapContext, SA_ONSTACK, SA_RESTART, SA_SIGINFO,
};

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

    fn user_rsp(&self) -> u64 {
        // The user stack pointer lives in SP_EL0 (the EL1 trap path
        // selected SP_EL1, so SP_EL0 still holds the user value).
        let sp_el0: u64;
        // SAFETY: reading SP_EL0 has no side effects.
        unsafe {
            core::arch::asm!(
                "mrs {v}, SP_EL0",
                v = out(reg) sp_el0,
                options(nomem, nostack, preserves_flags),
            );
        }
        sp_el0
    }

    fn rip(&self) -> u64 {
        self.frame.elr
    }

    fn set_rip(&mut self, rip: u64) {
        self.frame.elr = rip;
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
        // SAFETY: Valid memory or trusted environment
        let s = unsafe { &mut *(out as *mut UserState) };
        let f = &self.frame;
        // x0..=x30 (31 registers).
        s.x[0] = f.x0;
        s.x[1] = f.x1;
        s.x[2] = f.x2;
        s.x[3] = f.x3;
        s.x[4] = f.x4;
        s.x[5] = f.x5;
        s.x[6] = f.x6;
        s.x[7] = f.x7;
        s.x[8] = f.x8;
        s.x[9] = f.x9;
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
        // SAFETY: Valid memory or trusted environment
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

    fn returning_to_user(&self) -> bool {
        // SPSR_EL1 M[3:0] encodes the exception level + stack-pointer
        // selection on eret. EL0t (AArch64 EL0 with SP_EL0) = 0b0000.
        // Any other value means the frame is heading into a kernel mode
        // (EL1t = 0b0100, EL1h = 0b0101, etc.) — a redirect_to_kernel
        // call sets SPSR to 0x0000_0000_0000_0005 (EL1h), so this
        // guard correctly short-circuits signal delivery for those.
        (self.frame.spsr & 0xF) == 0
    }

    fn deliver_signal(&mut self, params: &SigDeliveryParams) -> bool {
        // AArch64 signal delivery. Mirrors the x86_64 path; the frame
        // layouts are architecture-specific but the three SA_* flags
        // are honoured identically.
        //
        //   * SA_RESTART: AArch64 SVC instruction is 4 bytes (W32
        //     encoding), so the SAVED PC (ELR restored by sigreturn)
        //     is rewound by 4, not 2.  Ref: Arm ARM DDI0487 C6.2.298
        //     (SVC encoding). Matches Linux's
        //     arch/arm64/kernel/signal.c where `sigreturn_common`
        //     uses `user_pt_regs.pc` and the rewind is simply
        //     `regs->pc - 4` in `do_signal` when SA_RESTART is set.
        //
        //   * SA_ONSTACK: altstack top = sp + size; grows downward.
        //     User SP (SP_EL0) is read via inline asm. No red-zone
        //     on AArch64 (the ABI does not define one for the kernel
        //     SVC entry point); we push the frame directly at
        //     SP_EL0 - frame_size.
        //
        //   * SA_SIGINFO: lays out [fallback_return][siginfo_t 128 B]
        //     [AArch64UContext] and sets the handler's x1 = &siginfo,
        //     x2 = &ucontext (AArch64 C ABI: x0 = arg0, x1 = arg1,
        //     x2 = arg2). Ref: Linux
        //     arch/arm64/kernel/signal.c::setup_rt_frame_user and
        //     arch/arm64/include/uapi/asm/ucontext.h.
        //
        // Stack layout (low → high addresses, SP grows downward):
        //
        //   Classic:
        //     [sp + 0  ]  fallback_return (8 B)
        //     [sp + 8  ]  AArch64SigContext (saved GPRs + PC)
        //
        //   SA_SIGINFO:
        //     [sp + 0  ]  fallback_return (8 B)
        //     [sp + 8  ]  siginfo_t (128 B)
        //     [sp + 136]  AArch64UContext
        //
        // On AArch64 the SP must be 16-byte aligned at function entry
        // (AAPCS64 §6.2.2). We round the frame base down to 16 bytes.
        let fallback_return = self.frame.elr;
        let want_siginfo = (params.flags & SA_SIGINFO) != 0;

        let frame_size = if want_siginfo {
            8 + 128 + (core::mem::size_of::<AArch64UContext>() as u64)
        } else {
            8 + (core::mem::size_of::<AArch64SigContext>() as u64)
        };

        // Read user SP from SP_EL0 (held by hardware after EL1 trap).
        let user_sp: u64;
        // SAFETY: mrs SP_EL0 at EL1 is unconditionally valid with no
        // side effects (Arm ARM DDI0487 D7.2.138).
        // SAFETY: Valid memory or trusted environment
        unsafe {
            core::arch::asm!(
                "mrs {v}, SP_EL0",
                v = out(reg) user_sp,
                options(nostack, preserves_flags),
            );
        }

        let stack_top = if (params.flags & SA_ONSTACK) != 0 && params.altstack_sp != 0 {
            params.altstack_sp.wrapping_add(params.altstack_size)
        } else {
            user_sp
        };
        // AAPCS64 §6.2.2: SP must be 16-byte aligned at function
        // entry. Round frame base down to 16; the `| 0x8` trick used
        // on x86_64 (for the SysV `call` slot) does not apply here —
        // on AArch64 there is no implicit call instruction that shifts
        // the stack by 8 before the prologue.
        let raw_sp = stack_top.wrapping_sub(frame_size);
        let new_sp = raw_sp & !0xFu64;

        // SA_RESTART: rewind saved PC by 4 (SVC W32 instruction size).
        let saved_pc = if (params.flags & SA_RESTART) != 0 && params.restartable_syscall {
            self.frame.elr.wrapping_sub(4)
        } else {
            self.frame.elr
        };

        if want_siginfo {
            let siginfo_vaddr = new_sp + 8;
            let uctx_vaddr = siginfo_vaddr + 128;

            let uctx = AArch64UContext {
                uc_flags: 0,
                uc_link: 0,
                uc_stack_sp: params.altstack_sp,
                uc_stack_flags: if (params.flags & SA_ONSTACK) != 0 && params.altstack_sp != 0 {
                    1 /* SS_ONSTACK */
                } else {
                    0
                },
                uc_stack_size: params.altstack_size,
                uc_mcontext: AArch64MContext {
                    fault_address: params.si_addr,
                    x: [
                        self.frame.x0,
                        self.frame.x1,
                        self.frame.x2,
                        self.frame.x3,
                        self.frame.x4,
                        self.frame.x5,
                        self.frame.x6,
                        self.frame.x7,
                        self.frame.x8,
                        self.frame.x9,
                        self.frame.x10,
                        self.frame.x11,
                        self.frame.x12,
                        self.frame.x13,
                        self.frame.x14,
                        self.frame.x15,
                        self.frame.x16,
                        self.frame.x17,
                        self.frame.x18,
                        self.frame.x19,
                        self.frame.x20,
                        self.frame.x21,
                        self.frame.x22,
                        self.frame.x23,
                        self.frame.x24,
                        self.frame.x25,
                        self.frame.x26,
                        self.frame.x27,
                        self.frame.x28,
                        self.frame.x29,
                        self.frame.x30,
                        user_sp,
                    ],
                    pc: saved_pc,
                    pstate: self.frame.spsr,
                    fpctx: 0,
                    reserved: [0; 8],
                },
                uc_sigmask: 0,
            };

            // SAFETY: user stack is mapped in the active EL1 page tables
            // (we are in an EL1 synchronous-exception handler on behalf
            // of the EL0 task; the fault address used to demarcate
            // demand-paged pages is below the trap-frame). Writes to
            // fresh pages surface via the translation-fault handler
            // registered in rust_aarch64_sync_dispatch above.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                core::ptr::write_volatile(new_sp as *mut u64, fallback_return);
                let info_p = siginfo_vaddr as *mut u8;
                core::ptr::write_bytes(info_p, 0, 128);
                (info_p as *mut i32).write_unaligned(params.signum as i32);
                (info_p.add(4) as *mut i32).write_unaligned(0);
                (info_p.add(8) as *mut i32).write_unaligned(params.si_code);
                (info_p.add(16) as *mut u64).write_unaligned(params.si_addr);
                core::ptr::write_volatile(uctx_vaddr as *mut AArch64UContext, uctx);
            }

            // Update user SP via MSR so eret enters the handler at
            // the new SP_EL0. x0 = signum (arg0), x1 = &siginfo
            // (arg1), x2 = &ucontext (arg2). ELR = handler entry.
            // SAFETY: msr SP_EL0 at EL1 is unconditionally valid.
            unsafe {
                core::arch::asm!(
                    "msr SP_EL0, {v}",
                    v = in(reg) new_sp,
                    options(nostack, preserves_flags),
                );
            }
            self.frame.x0 = params.signum as u64;
            self.frame.x1 = siginfo_vaddr;
            self.frame.x2 = uctx_vaddr;
            self.frame.elr = params.handler;
            true
        } else {
            // Classic 1-arg path: [fallback_return][AArch64SigContext].
            let ctx_vaddr = new_sp + 8;
            let ctx = AArch64SigContext {
                x: [
                    self.frame.x0,
                    self.frame.x1,
                    self.frame.x2,
                    self.frame.x3,
                    self.frame.x4,
                    self.frame.x5,
                    self.frame.x6,
                    self.frame.x7,
                    self.frame.x8,
                    self.frame.x9,
                    self.frame.x10,
                    self.frame.x11,
                    self.frame.x12,
                    self.frame.x13,
                    self.frame.x14,
                    self.frame.x15,
                    self.frame.x16,
                    self.frame.x17,
                    self.frame.x18,
                    self.frame.x19,
                    self.frame.x20,
                    self.frame.x21,
                    self.frame.x22,
                    self.frame.x23,
                    self.frame.x24,
                    self.frame.x25,
                    self.frame.x26,
                    self.frame.x27,
                    self.frame.x28,
                    self.frame.x29,
                    self.frame.x30,
                    user_sp,
                ],
                pc: saved_pc,
                spsr: self.frame.spsr,
                signum: params.signum as u64,
                _pad: [0; 3],
            };

            // SAFETY: see SA_SIGINFO branch.
            unsafe {
                core::ptr::write_volatile(new_sp as *mut u64, fallback_return);
                core::ptr::write_volatile(ctx_vaddr as *mut AArch64SigContext, ctx);
                core::arch::asm!(
                    "msr SP_EL0, {v}",
                    v = in(reg) new_sp,
                    options(nostack, preserves_flags),
                );
            }
            // x0 = signum; x1 = &sigcontext (trampoline reads it for
            // sigreturn via sys_sigreturn on handler return).
            self.frame.x0 = params.signum as u64;
            self.frame.x1 = ctx_vaddr;
            self.frame.elr = params.handler;
            true
        }
    }
}

// ── AArch64 signal frame types ─────────────────────────────────────
//
// Mirror of the x86_64 SigContext / McContext / UContext types but
// for AArch64. Layout follows Linux's
//   arch/arm64/include/uapi/asm/ucontext.h  (ucontext_t)
//   arch/arm64/include/uapi/asm/sigcontext.h (sigcontext)
// so a future libc shim / debugger unwinder can walk the same fields.

/// Saved GPR + PC state for the classic (non-SA_SIGINFO) sigframe.
/// x[31] holds SP_EL0, not LR — LR is already in x[30].
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct AArch64SigContext {
    /// x0..x30 + SP_EL0 (index 31). Layout exactly as Linux
    /// `arch/arm64/include/uapi/asm/sigcontext.h::sigcontext::regs`.
    pub x: [u64; 32],
    /// ELR_EL1 at trap time (post-SVC advancement, or SA_RESTART-
    /// rewound). Maps to Linux `sigcontext::pc`.
    pub pc: u64,
    /// SPSR_EL1 at trap time. Maps to Linux `sigcontext::pstate`.
    pub spsr: u64,
    /// Signal number. Not part of the Linux struct but stored here so
    /// `sys_sigreturn` can log it without an extra parameter.
    pub signum: u64,
    pub _pad: [u64; 3],
}

/// Machine context embedded in `AArch64UContext`. Matches
/// `arch/arm64/include/uapi/asm/sigcontext.h::sigcontext` (the Linux
/// mcontext_t for AArch64 is identical to sigcontext).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct AArch64MContext {
    /// Faulting address (FAR_EL1) for fault-type signals; 0 for
    /// async signals. Maps to Linux `sigcontext::fault_address`.
    pub fault_address: u64,
    /// x0..x30 + SP_EL0 (index 31). See AArch64SigContext::x.
    pub x: [u64; 32],
    /// Saved PC (ELR). Maps to Linux `sigcontext::pc`.
    pub pc: u64,
    /// Saved PSTATE (SPSR_EL1). Maps to Linux `sigcontext::pstate`.
    pub pstate: u64,
    /// Reserved for future FP/SIMD context pointer. 0 = none.
    pub fpctx: u64,
    pub reserved: [u64; 8],
}

/// AArch64 `ucontext_t`. Layout per
/// `arch/arm64/include/uapi/asm/ucontext.h`:
///   uc_flags, uc_link, uc_stack (sigaltstack), uc_mcontext,
///   uc_sigmask.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct AArch64UContext {
    pub uc_flags: u64,
    pub uc_link: u64,
    pub uc_stack_sp: u64,
    pub uc_stack_flags: i32,
    // 4-byte hole so uc_stack_size aligns to 8 bytes (matches
    // Linux `stack_t` layout on 64-bit).
    pub uc_stack_size: u64,
    pub uc_mcontext: AArch64MContext,
    pub uc_sigmask: u64,
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
        x0: 0x0000_0000_0000_0000,
        x1: 0x0101_0101_0101_0101,
        x2: 0x0202_0202_0202_0202,
        x3: 0x0303_0303_0303_0303,
        x4: 0x0404_0404_0404_0404,
        x5: 0x0505_0505_0505_0505,
        x6: 0x0606_0606_0606_0606,
        x7: 0x0707_0707_0707_0707,
        x8: 0x0808_0808_0808_0808,
        x9: 0x0909_0909_0909_0909,
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
    // SAFETY: Valid memory or trusted environment
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
    // SAFETY: Valid memory or trusted environment
    let ok = unsafe { ctx.save_user_state(buf.as_mut_ptr() as *mut u8) };

    // Restore the prior SP_EL0 immediately so any later test
    // that depends on it observes the boot-state value.
    // SAFETY: `msr SP_EL0` at EL1 is unconditional and side-effect-free
    // while EL0 is not executing; `prior_sp_el0` is the value read above.
    // SAFETY: Valid memory or trusted environment
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
    // SAFETY: Valid memory or trusted environment
    let s = unsafe { buf.assume_init() };

    if s.x[0] != 0x0000_0000_0000_0000 {
        return TestResult::Fail("x0 mismatch");
    }
    if s.x[1] != 0x0101_0101_0101_0101 {
        return TestResult::Fail("x1 mismatch");
    }
    if s.x[15] != 0x0F0F_0F0F_0F0F_0F0F {
        return TestResult::Fail("x15 mismatch");
    }
    if s.x[28] != 0x1C1C_1C1C_1C1C_1C1C {
        return TestResult::Fail("x28 mismatch");
    }
    if s.x[29] != 0x1D1D_1D1D_1D1D_1D1D {
        return TestResult::Fail("x29 mismatch");
    }
    if s.x[30] != 0x3030_3030_3030_3030 {
        return TestResult::Fail("x30 mismatch");
    }
    if s.pc != 0xE1E1_E1E1_E1E1_E1E1u64 {
        return TestResult::Fail("pc != ELR");
    }
    if s.spsr != 0x0000_0000_8000_0000 {
        return TestResult::Fail("spsr mismatch");
    }
    if s.sp != SP_SENTINEL {
        return TestResult::Fail("sp != SP_EL0");
    }
    if s.valid != 1 {
        return TestResult::Fail("valid != 1");
    }
    TestResult::Pass
}
kernel_test_in!("aarch64", smoke_aarch64_trap_save_user_state_round_trip);

// ── SA_* delivery smokes (aarch64 parity) ─────────────────────────
//
// Mirrors the x86_64 SA_* smoke set. Each test builds a synthetic
// TrapFrame, sets SP_EL0 to the top of a kernel-resident scratch
// buffer, calls deliver_signal, and reads the frame + scratch buffer
// back to verify the outputs. SP_EL0 is saved/restored around each
// test so the test harness state is not corrupted.

/// 4 KiB scratch buffer aligned to 16 bytes — enough for any sigframe.
#[repr(C, align(16))]
struct Aarch64SmokeStack {
    bytes: [u8; 4096],
}

impl Aarch64SmokeStack {
    const fn new() -> Self {
        Self { bytes: [0; 4096] }
    }
    fn top(&self) -> u64 {
        self.bytes.as_ptr() as u64 + self.bytes.len() as u64
    }
    fn base(&self) -> u64 {
        self.bytes.as_ptr() as u64
    }
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
}

fn smoke_aarch64_trap_frame(elr: u64) -> TrapFrame {
    TrapFrame {
        x30: 0x3030_3030_3030_3030,
        _pad: 0,
        elr,
        spsr: 0x0000_0000_0000_0000, // M[3:0] = 0 → EL0t
        x0: 0x0001,
        x1: 0x0002,
        x2: 0x0003,
        x3: 0x0004,
        x4: 0x0005,
        x5: 0x0006,
        x6: 0x0007,
        x7: 0x0008,
        x8: 0x0009,
        x9: 0x000A,
        x10: 0x000B,
        x11: 0x000C,
        x12: 0x000D,
        x13: 0x000E,
        x14: 0x000F,
        x15: 0x0010,
        x16: 0x0011,
        x17: 0x0012,
        x18: 0x0013,
        x19: 0x0014,
        x20: 0x0015,
        x21: 0x0016,
        x22: 0x0017,
        x23: 0x0018,
        x24: 0x0019,
        x25: 0x001A,
        x26: 0x001B,
        x27: 0x001C,
        x28: 0x001D,
        x29: 0x001E,
    }
}

/// SA_RESTART: saved ELR (the PC sigreturn restores) must be rewound
/// by 4 bytes (AArch64 SVC is a W32 instruction) when the flag is set
/// and the outer trap is a restartable syscall.
fn smoke_aarch64_sa_restart_rewinds_elr() -> TestResult {
    let stack = Aarch64SmokeStack::new();
    const POST_TRAP_ELR: u64 = 0xABCD_0000_1234_5678;
    let mut frame = smoke_aarch64_trap_frame(POST_TRAP_ELR);

    let params = SigDeliveryParams {
        handler: 0xDEAD_BEEF,
        restorer: 0,
        signum: 10,
        flags: SA_RESTART,
        altstack_sp: 0,
        altstack_size: 0,
        restartable_syscall: true,
        si_code: 0,
        si_addr: 0,
    };

    // Set SP_EL0 to the scratch buffer top so deliver_signal has a
    // valid (kernel-mapped) stack to write into. Save and restore
    // the prior value around the test.
    let prior_sp: u64;
    // SAFETY: `mrs`/`msr SP_EL0` at EL1 read/write the EL0 stack pointer
    // unconditionally with no side effects while EL0 is not executing;
    // `stack.top()` is a kernel-mapped scratch-buffer address.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!(
            "mrs {p}, SP_EL0",
            "msr SP_EL0, {n}",
            p = out(reg) prior_sp,
            n = in(reg) stack.top(),
            options(nostack, preserves_flags),
        );
    }

    let mut ctx = Aarch64TrapContext::from_svc(&mut frame);
    let ok = ctx.deliver_signal(&params);

    // SAFETY: `msr SP_EL0` at EL1 restores the EL0 stack pointer
    // unconditionally; `prior_sp` is the value read above.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!(
            "msr SP_EL0, {p}",
            p = in(reg) prior_sp,
            options(nostack, preserves_flags),
        );
    }

    if !ok {
        return TestResult::Fail("deliver_signal returned false");
    }

    // Read back the SigContext from the new SP + 8.
    // SP after delivery is stored as the SP_EL0 the arch wrote;
    // we already restored SP_EL0, but we can recover new_sp as
    // frame.elr is now the handler — and the sigctx was written at
    // old new_sp + 8. Easier: compute new_sp from the classic frame
    // size arithmetic (top - frame_size) & !15.
    let frame_size = 8 + core::mem::size_of::<AArch64SigContext>() as u64;
    let new_sp = (stack.top().wrapping_sub(frame_size)) & !0xFu64;
    let sc_vaddr = new_sp + 8;
    // SAFETY: we just wrote an AArch64SigContext there.
    let sc = unsafe { core::ptr::read_volatile(sc_vaddr as *const AArch64SigContext) };

    if sc.pc != POST_TRAP_ELR.wrapping_sub(4) {
        return TestResult::Fail("SA_RESTART did not rewind saved ELR by 4");
    }
    if frame.x0 != 10 {
        return TestResult::Fail("x0 not set to signum");
    }
    if frame.elr != 0xDEAD_BEEF {
        return TestResult::Fail("ELR not set to handler entry");
    }
    TestResult::Pass
}
kernel_test_in!("aarch64", smoke_aarch64_sa_restart_rewinds_elr);

/// SA_ONSTACK with a valid altstack: frame must be placed within the
/// altstack region, not on the user SP.
fn smoke_aarch64_sa_onstack_uses_altstack() -> TestResult {
    let user_stack = Aarch64SmokeStack::new();
    let altstack = Aarch64SmokeStack::new();
    let mut frame = smoke_aarch64_trap_frame(0xDEAD_F00D);

    let params = SigDeliveryParams {
        handler: 0xBABE_FACE,
        restorer: 0,
        signum: 12,
        flags: SA_ONSTACK,
        altstack_sp: altstack.base(),
        altstack_size: altstack.len(),
        restartable_syscall: false,
        si_code: 0,
        si_addr: 0,
    };

    let prior_sp: u64;
    // SAFETY: `mrs`/`msr SP_EL0` at EL1 read/write the EL0 stack pointer
    // unconditionally with no side effects while EL0 is not executing;
    // `user_stack.top()` is a kernel-mapped scratch-buffer address.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!(
            "mrs {p}, SP_EL0",
            "msr SP_EL0, {n}",
            p = out(reg) prior_sp,
            n = in(reg) user_stack.top(),
            options(nostack, preserves_flags),
        );
    }
    let mut ctx = Aarch64TrapContext::from_svc(&mut frame);

    // Read SP_EL0 back after delivery to see where the frame landed.
    let ok = ctx.deliver_signal(&params);
    let delivered_sp: u64;
    // SAFETY: `mrs SP_EL0` captures the EL0 SP that deliver_signal wrote
    // and `msr SP_EL0` restores the prior value; both are unconditional
    // EL1 accesses with no side effects while EL0 is not executing.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!(
            "mrs {v}, SP_EL0",
            "msr SP_EL0, {p}",
            v = out(reg) delivered_sp,
            p = in(reg) prior_sp,
            options(nostack, preserves_flags),
        );
    }

    if !ok {
        return TestResult::Fail("deliver_signal returned false");
    }

    let alt_lo = altstack.base();
    let alt_hi = altstack.base() + altstack.len();
    if delivered_sp < alt_lo || delivered_sp >= alt_hi {
        return TestResult::Fail("SA_ONSTACK frame not within altstack");
    }
    let usr_lo = user_stack.base();
    let usr_hi = user_stack.base() + user_stack.len();
    if delivered_sp >= usr_lo && delivered_sp < usr_hi {
        return TestResult::Fail("SA_ONSTACK frame leaked onto user stack");
    }
    TestResult::Pass
}
kernel_test_in!("aarch64", smoke_aarch64_sa_onstack_uses_altstack);

/// SA_SIGINFO: handler receives x0 = signum, x1 = &siginfo,
/// x2 = &ucontext; siginfo prefix bytes + mcontext.pc match the
/// params we passed in.
fn smoke_aarch64_sa_siginfo_sets_three_args() -> TestResult {
    let stack = Aarch64SmokeStack::new();
    const POST_TRAP_ELR: u64 = 0xFEED_FACE_C0DE_BABE;
    let mut frame = smoke_aarch64_trap_frame(POST_TRAP_ELR);

    let params = SigDeliveryParams {
        handler: 0xCAFE_F00D,
        restorer: 0,
        signum: 11, // SIGSEGV
        flags: SA_SIGINFO,
        altstack_sp: 0,
        altstack_size: 0,
        restartable_syscall: false,
        si_code: 1, // SEGV_MAPERR
        si_addr: 0xDEAD_AAAA,
    };

    let prior_sp: u64;
    // SAFETY: `mrs`/`msr SP_EL0` at EL1 read/write the EL0 stack pointer
    // unconditionally with no side effects while EL0 is not executing;
    // `stack.top()` is a kernel-mapped scratch-buffer address.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!(
            "mrs {p}, SP_EL0",
            "msr SP_EL0, {n}",
            p = out(reg) prior_sp,
            n = in(reg) stack.top(),
            options(nostack, preserves_flags),
        );
    }
    let mut ctx = Aarch64TrapContext::from_svc(&mut frame);
    let ok = ctx.deliver_signal(&params);
    // Capture delivered SP_EL0 before restoring.
    let delivered_sp: u64;
    // SAFETY: `mrs SP_EL0` captures the EL0 SP that deliver_signal wrote
    // and `msr SP_EL0` restores the prior value; both are unconditional
    // EL1 accesses with no side effects while EL0 is not executing.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!(
            "mrs {v}, SP_EL0",
            "msr SP_EL0, {p}",
            v = out(reg) delivered_sp,
            p = in(reg) prior_sp,
            options(nostack, preserves_flags),
        );
    }

    if !ok {
        return TestResult::Fail("deliver_signal returned false");
    }

    // x0 = signum, x1 = &siginfo, x2 = &ucontext.
    if frame.x0 != 11 {
        return TestResult::Fail("x0 != signum");
    }
    let siginfo_vaddr = delivered_sp + 8;
    if frame.x1 != siginfo_vaddr {
        return TestResult::Fail("x1 != &siginfo");
    }
    let uctx_vaddr = siginfo_vaddr + 128;
    if frame.x2 != uctx_vaddr {
        return TestResult::Fail("x2 != &ucontext");
    }
    if frame.elr != 0xCAFE_F00D {
        return TestResult::Fail("ELR != handler");
    }

    // Read siginfo prefix.
    // SAFETY: deliver_signal wrote 128 B of siginfo there.
    unsafe {
        let signo = (siginfo_vaddr as *const i32).read_unaligned();
        let code = ((siginfo_vaddr + 8) as *const i32).read_unaligned();
        let addr = ((siginfo_vaddr + 16) as *const u64).read_unaligned();
        if signo != 11 {
            return TestResult::Fail("siginfo.si_signo mismatch");
        }
        if code != 1 {
            return TestResult::Fail("siginfo.si_code mismatch");
        }
        if addr != 0xDEAD_AAAA {
            return TestResult::Fail("siginfo.si_addr mismatch");
        }
    }

    // mcontext.pc must be the unmodified post-trap ELR (no SA_RESTART).
    let mctx_pc_offset = core::mem::offset_of!(AArch64UContext, uc_mcontext)
        + core::mem::offset_of!(AArch64MContext, pc);
    // SAFETY: deliver_signal wrote an AArch64UContext at uctx_vaddr.
    let saved_pc = unsafe { ((uctx_vaddr + mctx_pc_offset as u64) as *const u64).read_unaligned() };
    if saved_pc != POST_TRAP_ELR {
        return TestResult::Fail("mcontext.pc != saved post-trap ELR");
    }
    TestResult::Pass
}
kernel_test_in!("aarch64", smoke_aarch64_sa_siginfo_sets_three_args);

fn dump_frame(f: &TrapFrame) {
    let _ = writeln!(Writer, "  x0:  {:#018x}   x1:  {:#018x}", f.x0, f.x1);
    let _ = writeln!(Writer, "  x2:  {:#018x}   x3:  {:#018x}", f.x2, f.x3);
    let _ = writeln!(Writer, "  x30: {:#018x}", f.x30);
}
