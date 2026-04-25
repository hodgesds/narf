//! x86_64 trap frame + Rust-side dispatch.
//!
//! Each CPU exception has an asm stub (`trap_entry.S`) that:
//!
//!   1. Optionally pushes a zero error code for vectors that don't push one.
//!   2. Pushes the vector number.
//!   3. Pushes all general-purpose registers.
//!   4. Calls `rust_trap_handler(&TrapFrame)`.
//!   5. Does NOT return (Stage 1 turns every exception into a panic).
//!
//! Full trap-prologue PKRS save / restore discipline (frame/ §4) comes
//! with the Stage-2 domain-switch work. Stage 1 has a single domain so
//! PKRS is always the open mask.

use core::fmt::Write;

use narf_console::Writer;

/// The on-stack layout that `common_trap` builds before calling here.
///
/// Order follows the asm's reverse pushes + CPU-pushed frame at the end.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct TrapFrame {
    // General-purpose registers, in the order `common_trap` pushes them.
    pub r15: u64, pub r14: u64, pub r13: u64, pub r12: u64,
    pub r11: u64, pub r10: u64, pub r9:  u64, pub r8:  u64,
    pub rbp: u64, pub rdi: u64, pub rsi: u64, pub rdx: u64,
    pub rcx: u64, pub rbx: u64, pub rax: u64,

    // Pushed by `common_trap` before the GP saves.
    pub vector:     u64,
    pub error_code: u64,

    // Pushed by the CPU on exception. In long mode these are always
    // 64-bit and the SS/RSP pair is always present.
    pub rip:    u64,
    pub cs:     u64,
    pub rflags: u64,
    pub rsp:    u64,
    pub ss:     u64,
}

impl core::fmt::Debug for TrapFrame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f,
            "TrapFrame {{ vec={}, err={:#x}, rip={:#018x}, cs={:#x}, rflags={:#x} }}",
            self.vector, self.error_code, self.rip, self.cs, self.rflags)
    }
}

fn vector_name(v: u64) -> &'static str {
    match v {
         0 => "#DE  divide-by-zero",
         1 => "#DB  debug",
         2 => "NMI",
         3 => "#BP  breakpoint",
         4 => "#OF  overflow",
         5 => "#BR  bound-range",
         6 => "#UD  invalid-opcode",
         7 => "#NM  device-not-available",
         8 => "#DF  double-fault",
        10 => "#TS  invalid-TSS",
        11 => "#NP  segment-not-present",
        12 => "#SS  stack-segment",
        13 => "#GP  general-protection",
        14 => "#PF  page-fault",
        16 => "#MF  x87-float",
        17 => "#AC  alignment-check",
        18 => "#MC  machine-check",
        19 => "#XM  SIMD-float",
        20 => "#VE  virtualisation",
        21 => "#CP  control-protection",
        _  => "reserved / unknown",
    }
}

/// Rust-side trap dispatch. Called from `common_trap` in `trap_entry.S`
/// with a mutable pointer to the `TrapFrame` on the trap stack.
///
/// Contract:
///   - If a probe is armed (`narf_arch::x86_64::probe` globals), consume
///     it: record the vector, rewrite `frame.rip` to the probe's
///     recovery RIP, and return. The asm tail restores GPRs and
///     `iretq`s to the rewritten RIP.
///   - Otherwise print the frame and call `exit_kernel(42)`, which
///     does not return.
#[unsafe(no_mangle)]
pub extern "C" fn rust_trap_handler(frame: &mut TrapFrame) {
    // Software-interrupt syscall gate. `int 0x80` arrives here; the
    // caller's registers have been saved into `frame` already.
    // Convention: rax = syscall number, rdi/rsi/rdx/r10/r8/r9 =
    // args 0..5. Return value in rax, status in rdx.
    //
    // Raw handlers can `redirect_to_kernel` to rewrite the frame
    // instead of returning to the caller's context — the iretq at
    // the tail of common_trap then lands at the kernel RIP we set
    // here, with kernel CS/SS and the supplied RSP. swapgs on exit
    // is gated on the (possibly rewritten) frame.cs, so a redirect
    // to KCODE correctly skips the user-side swapgs.
    if frame.vector == 128 {
        let num = frame.rax as u32;
        let mut ctx = X86TrapContext::from_int80(frame);
        narf_userspace::kernel_syscall_entry(num, &mut ctx);
        return;
    }

    // External IRQ path (vectors 32..=255). Dispatch to the
    // subsystem-registered handler (or ignore if no handler), then
    // EOI. Bypasses the probe-catch path — probes are for catching
    // CPU *exceptions* (vectors 0..=31), not asynchronous IRQs.
    if frame.vector >= 32 {
        match frame.vector {
            32 => narf_interrupts::x86_64::apic::on_timer_tick(),
            _  => {}
        }
        // SAFETY: APIC is initialised before interrupts are enabled.
        unsafe { narf_interrupts::eoi(); }
        return;
    }

    // Recoverable-probe path. `consume` is atomic: a second fault
    // inside the handler can't double-claim the recovery.
    let recovery = narf_arch::x86_64::probe::consume(
        frame.vector as u32, frame.error_code);
    if recovery != 0 {
        frame.rip = recovery;
        return;
    }

    let _ = writeln!(Writer, "\n*** CPU EXCEPTION ***");
    let _ = writeln!(Writer, "  vector: {:3} — {}", frame.vector, vector_name(frame.vector));
    let _ = writeln!(Writer, "  error:  {:#018x}", frame.error_code);
    let _ = writeln!(Writer, "  rip:    {:#018x}   cs:     {:#018x}", frame.rip, frame.cs);
    let _ = writeln!(Writer, "  rflags: {:#018x}   rsp:    {:#018x}   ss: {:#018x}",
        frame.rflags, frame.rsp, frame.ss);
    let _ = writeln!(Writer, "  rax:    {:#018x}   rbx:    {:#018x}",   frame.rax, frame.rbx);
    let _ = writeln!(Writer, "  rcx:    {:#018x}   rdx:    {:#018x}",   frame.rcx, frame.rdx);
    let _ = writeln!(Writer, "  rsi:    {:#018x}   rdi:    {:#018x}",   frame.rsi, frame.rdi);
    let _ = writeln!(Writer, "  rbp:    {:#018x}   r8:     {:#018x}",   frame.rbp, frame.r8);
    let _ = writeln!(Writer, "  r9:     {:#018x}   r10:    {:#018x}",   frame.r9,  frame.r10);
    let _ = writeln!(Writer, "  r11:    {:#018x}   r12:    {:#018x}",   frame.r11, frame.r12);
    let _ = writeln!(Writer, "  r13:    {:#018x}   r14:    {:#018x}",   frame.r13, frame.r14);
    let _ = writeln!(Writer, "  r15:    {:#018x}",                       frame.r15);

    // SAFETY: after a fatal exception we have no policy to resume; exit with
    // a non-zero code so xtask / verification can see the failure.
    unsafe { narf_arch::exit_kernel(42) }
}

// ── TrapContext impl for the int-0x80 path ─────────────────────────

use narf_userspace::{SyscallArgs, SyscallReturn, TrapContext};

/// Arch-specific `TrapContext` wrapper around a live trap frame.
/// Constructed at int-0x80 dispatch time so raw handlers get
/// `set_return` + `redirect_to_kernel` bound to the real frame.
struct X86TrapContext<'a> {
    frame: &'a mut TrapFrame,
    args:  SyscallArgs,
}

impl<'a> X86TrapContext<'a> {
    fn from_int80(frame: &'a mut TrapFrame) -> Self {
        let args = SyscallArgs {
            arg0: frame.rdi,
            arg1: frame.rsi,
            arg2: frame.rdx,
            arg3: frame.r10,
            arg4: frame.r8,
            arg5: frame.r9,
        };
        Self { frame, args }
    }
}

impl<'a> TrapContext for X86TrapContext<'a> {
    fn args(&self) -> &SyscallArgs { &self.args }

    fn set_return(&mut self, ret: SyscallReturn) {
        self.frame.rax = ret.value;
        self.frame.rdx = ret.status as u64;
    }

    fn redirect_to_kernel(&mut self, rip: u64, rsp: u64) -> bool {
        // Rewrite the CPU-pushed fields so common_trap's iretq
        // lands in kernel mode at the supplied RIP/RSP. CS=KCODE,
        // SS=KDATA match the kernel's data-segment convention.
        // RFLAGS retains the caller's flags — kernel code is
        // prepared for any flag state.
        self.frame.rip = rip;
        self.frame.cs  = super::gdt::KCODE_SEL as u64;
        self.frame.rsp = rsp;
        self.frame.ss  = super::gdt::KDATA_SEL as u64;
        true
    }

    unsafe fn save_user_state(&self, out: *mut u8) -> bool {
        use super::user::UserState;
        // SAFETY: caller declared `out` is writable for at least
        // `size_of::<UserState>()` bytes — the trait's contract.
        let s = unsafe { &mut *(out as *mut UserState) };
        let f = &self.frame;
        s.r15 = f.r15; s.r14 = f.r14; s.r13 = f.r13; s.r12 = f.r12;
        s.r11 = f.r11; s.r10 = f.r10; s.r9  = f.r9;  s.r8  = f.r8;
        s.rbp = f.rbp; s.rdi = f.rdi; s.rsi = f.rsi; s.rdx = f.rdx;
        s.rcx = f.rcx; s.rbx = f.rbx; s.rax = f.rax;
        s.rip = f.rip; s.rflags = f.rflags; s.rsp = f.rsp;
        s.valid = 1;
        true
    }
}
