//! Fast SYSCALL/SYSRET entry path.
//!
//! Companion to the existing `int 0x80` software-interrupt syscall
//! gate in `trap.rs`. Both paths funnel into
//! `narf_userspace::kernel_syscall_entry_plain(num, &args)` so the
//! Rust-side dispatch logic stays in one place.
//!
//! Unlike `int 0x80`, the `syscall` instruction:
//!   * Takes the entry RIP from `IA32_LSTAR` (no IDT lookup).
//!   * Loads CS/SS from `IA32_STAR[47:32]` (kernel side) /
//!     `IA32_STAR[63:48]` + offsets (user side, on `sysret`).
//!   * Saves the user `rip` into `rcx` and the user `rflags` into
//!     `r11`, then masks `rflags` with `IA32_FMASK`.
//!
//! Stack switch on entry: GS still holds the user-mode value, so
//! the asm stub `swapgs` first to pick up the per-CPU pointer at
//! `gs:0`, saves `user_rsp` into the per-CPU scratch slot, then
//! loads the kernel stack top from the same per-CPU page. On exit
//! the inverse: restore user `rsp` from per-CPU, `swapgs`, then
//! `sysretq` lands back at the user RIP saved in `rcx` with the
//! user RFLAGS in `r11`.
//!
//! Layout dependency: `PerCpu` field 0 is `user_rsp_save`, field 1
//! is `kernel_stack_top` (each `u64`). The asm reads both at
//! `gs:0` / `gs:8`. See `frame/src/x86_64/percpu.rs`.
//!
//! Reference: AMD APM Vol 2 §6.1.1 (SYSCALL) / §6.1.2 (SYSRET);
//! Intel SDM Vol 2A "SYSCALL — Fast System Call".

use core::arch::naked_asm;

use narf_arch::x86_64::msr;

// IA32 MSR numbers for SYSCALL/SYSRET (SDM Vol 4 Ch 2.16, AMD APM Vol 2 §3.2).
const IA32_EFER: u32 = 0xC000_0080;
const IA32_STAR: u32 = 0xC000_0081;
const IA32_LSTAR: u32 = 0xC000_0082;
const IA32_FMASK: u32 = 0xC000_0084;

/// EFER.SCE — System Call Enable. Required to enable the
/// `syscall` / `sysret` instructions in 64-bit mode.
const EFER_SCE: u64 = 1;

/// Bits to mask out of RFLAGS on SYSCALL entry. Clear IF
/// (interrupts) so the kernel runs with IRQs off until it
/// chooses to re-enable; clear DF (direction flag) so string
/// instructions in the kernel run forward by default; clear TF
/// so single-step from user can't trigger a debug exception
/// inside the kernel entry.
const RFLAGS_IF: u64 = 1 << 9;
const RFLAGS_DF: u64 = 1 << 10;
const RFLAGS_TF: u64 = 1 << 8;
const RFLAGS_AC: u64 = 1 << 18;
const SFMASK_BITS: u64 = RFLAGS_IF | RFLAGS_DF | RFLAGS_TF | RFLAGS_AC;

/// Naked assembly SYSCALL entry. Hardware loads RIP from
/// `IA32_LSTAR` here when a user task executes `syscall`. On
/// entry:
///   - `rax` = syscall number
///   - `rdi`/`rsi`/`rdx`/`r10`/`r8`/`r9` = args 0..5 (note: r10
///     is used in place of rcx because hardware clobbers rcx
///     with the saved user RIP)
///   - `rcx` = user RIP (clobbered by `syscall`)
///   - `r11` = user RFLAGS (clobbered by `syscall`)
///   - `rsp` = user stack
///   - GS.base = user GS base (we swapgs to load kernel)
///
/// On return:
///   - `rax` = SyscallReturn.status
///   - `rdx` = SyscallReturn.value
///   - `rcx` = user RIP (consumed by `sysretq`)
///   - `r11` = user RFLAGS (consumed by `sysretq`)
///
/// # Safety
// `sti`/`cli` bracketing the syscall body is gated on user-task SMP:
// only a MIGRATED user task needs IRQs on mid-syscall so a peer CPU can
// service its broadcast TLB-shootdown IPI while the sender spins on the
// ack. With the feature OFF, syscalls keep the historical
// IRQs-off-during-syscall behaviour — which the default builds rely on
// (notably the kernel-test build has no LAPIC timer, so an errant IF=1
// reaching `halt_until_irq` wedges; see `user_task.rs`'s pre-iretq
// `cli`). The macros expand to a no-op (empty) asm line when off, so
// the feature-off code path is byte-identical to before.
#[cfg(feature = "user-task-smp")]
macro_rules! syscall_irq_on {
    () => {
        "sti"
    };
}
#[cfg(not(feature = "user-task-smp"))]
macro_rules! syscall_irq_on {
    () => {
        ""
    };
}
#[cfg(feature = "user-task-smp")]
macro_rules! syscall_irq_off {
    () => {
        "cli"
    };
}
#[cfg(not(feature = "user-task-smp"))]
macro_rules! syscall_irq_off {
    () => {
        ""
    };
}

/// Raw `syscall` instruction landing pad installed in `IA32_LSTAR`.
///
/// # Safety
/// Never call this from Rust. It assumes it was entered by the
/// `syscall` instruction from CPL=3 with the kernel `GS` base in
/// `IA32_KERNEL_GS_BASE`, executes `swapgs`, and switches to the
/// per-CPU kernel stack. Invoking it in any other context corrupts
/// `GS`/`rsp` and the user-state snapshot.
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn syscall_entry_x86_64() {
    naked_asm!(
        // Switch to kernel GS so gs:0 / gs:8 hit the per-CPU
        // page.
        "swapgs",
        // Save user RSP and load kernel RSP. Per-CPU layout from
        // `percpu.rs`: `user_rsp_save` at gs:0, `kernel_stack_top`
        // at gs:8.
        "mov gs:[0], rsp",
        "mov rsp, gs:[8]",

        // Build a full `UserState` snapshot on the kernel stack.
        // Layout (low addr → high addr) from
        // `narf_arch::x86_64::user_mode::UserState`:
        //   0: r15  8: r14   16: r13  24: r12  32: r11  40: r10
        //  48: r9  56: r8    64: rbp  72: rdi  80: rsi  88: rdx
        //  96: rcx 104: rbx 112: rax 120: rip 128: rflags 136: rsp
        // 144: valid (total 152 bytes).
        // Push runs high→low, so we push in REVERSE field order:
        // valid first, then rsp/rflags/rip/rax/rbx/rcx/.../r15.
        //
        // The user `RCX` and `R11` slots are stored as 0 because
        // the `syscall` instruction clobbered the user's original
        // values with the saved RIP / RFLAGS before we got here
        // (Linux's syscall ABI mandates exactly that, so musl-
        // built code knows not to expect those preserved).
        //
        // The user's RAX held the syscall number on entry; we
        // stash it in the rax slot so the dispatcher can read it
        // from the state, and the handler's `set_return` writes
        // the SyscallReturn back into the same slot.
        "push 1",                              // valid
        "push qword ptr gs:[0]",               // rsp (user)
        "push r11",                            // rflags (user)
        "push rcx",                            // rip (user)
        "push rax",                            // rax (= syscall num)
        "push rbx",                            // rbx
        "push 0",                              // rcx (lost)
        "push rdx",                            // rdx (= arg2)
        "push rsi",                            // rsi (= arg1)
        "push rdi",                            // rdi (= arg0)
        "push rbp",                            // rbp
        "push r8",                             // r8  (= arg4)
        "push r9",                             // r9  (= arg5)
        "push r10",                            // r10 (= arg3)
        "push 0",                              // r11 (lost)
        "push r12",                            // r12
        "push r13",                            // r13
        "push r14",                            // r14
        "push r15",                            // r15

        // Re-enable interrupts for the body of the syscall. SYSCALL
        // entry cleared IF via IA32_FMASK (SFMASK_BITS); now that the
        // full UserState snapshot is safe on the kernel stack and we're
        // on the per-CPU kernel stack with kernel GS, IRQs can fire
        // again. This is REQUIRED for user-task SMP: a migrated task's
        // mprotect/munmap does a broadcast TLB shootdown that spins
        // waiting for every peer CPU to ACK the IPI — and a peer also
        // in a syscall can only service that IPI if ITS interrupts are
        // on. The AS-mutation shootdown paths hold no lock during the
        // spin (the region lock is dropped first), and the timer-tick
        // handler is CPL-gated (no preempt / signal-frame build while
        // CPL=0), so running the syscall body with IRQs on is safe.
        // `cli` is re-asserted before the return swapgs below.
        syscall_irq_on!(),

        // SysV calling convention for
        // `dispatch_syscall(num, &state)`:
        // arg0 (num) → rdi, arg1 (&state) → rsi.
        // Read syscall num from the rax slot at offset 112.
        "mov edi, dword ptr [rsp + 112]",      // syscall number (low 32 of rax slot)
        "mov rsi, rsp",                        // &UserState

        // Pre-call rsp = kernel_stack_top - 152 = -152, which is
        // 8-aligned; the call's push lands at -160 = 16-aligned,
        // which is what SysV requires inside the callee.
        "call {dispatch}",

        // After dispatch the SysV 16-byte struct return
        // `SyscallReturn { value: u64, status: NarfStatus }` lands as:
        //   rax = SyscallReturn.value   (first eightbyte, offset 0)
        //   rdx = SyscallReturn.status  (second eightbyte, offset 8)
        // The user state on the stack is intact unless the
        // handler wrote back into it via `set_return` /
        // `save_user_state`. The handler's `set_return` modifies
        // the rax slot at [rsp + 112].
        //
        // Linux's syscall ABI returns a single signed value in
        // rax: positive on success, negative-errno on failure.
        // rdx, rdi, rsi, r10, r8, r9 must all be PRESERVED (they
        // get reloaded from the saved UserState slots below). musl
        // emits patterns like `mov %fs:0, %rdx; syscall; movq $0,
        // 0x98(%rdx)` around `__init_tp`'s `set_tid_address` call,
        // expecting rdx to survive the syscall — the reload below
        // restores it.
        //
        // Fold: if status != OK, set rax = -EINVAL (-22) so
        // userspace sees a negative-errno error per Linux
        // semantics. Otherwise rax already holds value.
        "test edx, edx",                       // status (rdx) == 0 (OK)?
        "jz 2f",                               // status == OK: keep rax = value
        "mov rax, -22",                        // status != OK: rax = -EINVAL
        "2:",

        // Restore the six user-side arg registers from the
        // UserState slots. SysV says the C dispatcher freely
        // clobbers these as caller-saved, so they need to be
        // reloaded; Linux's syscall ABI mandates we preserve them
        // across the syscall.
        "mov rdi, [rsp + 72]",   // rdi
        "mov rsi, [rsp + 80]",   // rsi
        "mov rdx, [rsp + 88]",   // rdx
        "mov r10, [rsp + 40]",   // r10
        "mov r8,  [rsp + 56]",   // r8
        "mov r9,  [rsp + 48]",   // r9

        // Restore the callee-saved user registers from the UserState slots too.
        // For an ordinary syscall this is a no-op: the SysV C dispatcher already
        // PRESERVES rbx/rbp/r12-r15, so the live values equal the snapshot. But a
        // handler that PARKS does so via `kernel_switch` (own-stack model), whose
        // switch-back restores the KERNEL's callee-saved registers at the yield
        // point — NOT the user's. Without reloading them here, a re-executed /
        // resumed syscall returns to userspace with garbage rbp/rbx/r12-r15: the
        // caller's frame pointer is clobbered (observed as chroot_run's
        // `##UFAULT## rbp=0x0`, and as a parked accept()/read() resuming with a
        // corrupt frame so the server never echoes — net-smoke flake). Linux's
        // syscall ABI mandates these are preserved across a syscall; reloading
        // from the entry snapshot guarantees it for the park/resume path.
        "mov rbx, [rsp + 104]",  // rbx
        "mov rbp, [rsp + 64]",   // rbp
        "mov r12, [rsp + 24]",   // r12
        "mov r13, [rsp + 16]",   // r13
        "mov r14, [rsp + 8]",    // r14
        "mov r15, [rsp + 0]",    // r15

        // Reload user RIP, RFLAGS from saved slots for sysretq.
        "mov rcx, [rsp + 120]",                // user RIP
        "mov r11, [rsp + 128]",                // user RFLAGS

        // Restore user RSP from the UserState `rsp` slot rather than
        // the entry-time per-CPU scratch. For an ordinary syscall the
        // slot still holds the original user RSP (pushed from gs:[0]
        // at entry), so this is a no-op change. But a handler that
        // parks/resumes or delivers a signal rewrites the snapshot's
        // RSP slot to move the user stack (e.g. onto a signal frame);
        // honouring the slot here makes those rewrites take effect on
        // `sysretq`. Must read [rsp+136] BEFORE dropping the scratch.
        // Clear IF BEFORE restoring the user RSP — order matters. With IF
        // left on (re-enabled at entry), the window between loading the
        // user RSP and `sysretq` runs at CPL=0 on the USER stack; an IRQ
        // landing there does NOT switch stacks (no CPL change, no IST), so
        // a CPL=0 handler runs on the user stack and (with the wrong GS,
        // since swapgs hasn't run) faults — fault-on-bad-stack → #DF. This
        // window is sub-instruction but a high IRQ rate (NAPI RX poll at
        // ~560k/s during heavy redis load) hits it deterministically.
        // Masking first means the user RSP is only ever live with IRQs off;
        // also covers the original swapgs→sysretq concern (a CPL=0 IRQ with
        // user GS reading gs:[N] against user state). sysretq restores the
        // user's RFLAGS (IF=1) atomically.
        syscall_irq_off!(),
        "mov rsp, [rsp + 136]",                // user RSP (from state)
        "swapgs",
        "sysretq",
        dispatch = sym dispatch_syscall,
    )
}

/// C-ABI dispatcher invoked from the naked asm. The state
/// pointer references a full `UserState` snapshot the asm built
/// directly on the kernel stack: the SyscallArgs view is just
/// the first six GPR slots (rdi/rsi/rdx/r10/r8/r9 at offsets
/// 72/80/88/40/56/48 of `UserState`, NOT a contiguous prefix —
/// see the comment in `narf_userspace::SyscallArgs` for the
/// reshape). Handlers that need to save full user state for
/// resume (e.g. `sys_futex`'s park path) borrow the same
/// pointer through `ArgsOnlyCtx::with_state`.
extern "C" fn dispatch_syscall(
    num: u32,
    state: &mut narf_arch::x86_64::user_mode::UserState,
) -> narf_userspace::SyscallReturn {
    let args = narf_userspace::SyscallArgs {
        arg0: state.rdi,
        arg1: state.rsi,
        arg2: state.rdx,
        arg3: state.r10,
        arg4: state.r8,
        arg5: state.r9,
    };
    // Capture the post-syscall return RIP before the handler runs. A blocking
    // handler that parks for re-execution rewinds this by 2 (the `syscall`
    // instruction width) so the task re-issues the syscall on resume.
    let entry_rip = state.rip;
    let mut ret = narf_userspace::kernel_syscall_entry_plain_with_state(
        num,
        &args,
        state as *mut _ as *mut u8,
    );

    // RESTART semantics (Linux ERESTART). If the handler rewound RIP to
    // re-execute the syscall (own-stack park: console-read / nanosleep / futex /
    // accept / epoll_wait …), the user's `rax` MUST be restored to the syscall
    // NUMBER so the re-issued `syscall` dispatches correctly — and the status
    // MUST be Ok so the return asm doesn't fold `rax` to -EINVAL(-22).
    //
    // The longjmp model never needed this: it longjmp'd out of the handler,
    // bypassing the syscall-return asm, and restored the saved `rax` (= number)
    // via `enter_user_mode_resume`. The own-stack park instead returns NORMALLY
    // through `dispatch_syscall` + the return asm, so a park that left a non-Ok
    // status folded `rax` to -22; the re-issued `syscall` then used -22 as its
    // number → spurious EINVAL (observed as redis's `epoll_wait: Invalid
    // argument` panic under own-stack).
    if state.rip == entry_rip.wrapping_sub(2) {
        ret = narf_userspace::SyscallReturn::ok(num as u64);
    }

    // SYSRET-canonical guard. Linux forces IRET instead of SYSRET when the
    // return RIP may be non-canonical ("SYSRET has trouble with uncanonical
    // addresses" — arch/x86/entry/entry_64.S). NARF's sysret tail
    // (`syscall_entry_x86_64`) has no such guard: a non-canonical return RIP
    // makes `sysretq` #GP at CPL=0 AFTER it has already loaded the user RSP and
    // swapgs'd (syscall.rs `mov rsp,[..]; swapgs; sysretq`) — i.e. the #GP fires
    // on the USER stack with user GS. NARF's trap entry decides swapgs by CS.RPL
    // (not by the GS base like Linux's paranoid_entry), so it runs that #GP
    // handler on the user stack with the wrong GS → wild control transfer (the
    // `rip=0x3` kernel #UD class). Rewriting a non-canonical RIP to 0 makes the
    // `sysretq` land in USER mode and fault THERE (#PF, CS=user), which routes
    // through the normal user-fault → SIGSEGV path: the process dies cleanly and
    // the kernel survives. The return value is unchanged.
    state.rip = sysret_safe_rip(state.rip);
    ret
}

/// Canonical-address guard for a SYSRET target RIP. Returns `rip` unchanged
/// when it is canonical (bits [63:47] are a sign-extension of bit 47, the only
/// form `sysretq` can return to without #GP), and `0` otherwise. `0` is
/// canonical and unmapped in user space, so a `sysretq` to it faults cleanly in
/// USER mode rather than #GP'ing at CPL=0 on the user stack. See the call site
/// in `dispatch_syscall` for the full rationale.
#[inline]
pub fn sysret_safe_rip(rip: u64) -> u64 {
    // Canonical iff sign-extending bit 47 reproduces the value.
    if ((rip as i64) << 16 >> 16) as u64 == rip {
        rip
    } else {
        0
    }
}

/// Program the SYSCALL MSRs and enable EFER.SCE. After this
/// returns, user-mode tasks executing `syscall` land in
/// `syscall_entry_x86_64`.
///
/// Idempotent: re-running rewrites the MSRs with the same values.
///
/// # Safety
/// Caller asserts:
///   - GDT is configured with KCODE at 0x08, KDATA at 0x10,
///     UCODE at 0x33 (UCODE-16 == 0x20 = STAR[63:48]),
///     UDATA at 0x2B.
///   - `init_bsp` (percpu) has set `IA32_GS_BASE` and
///     `IA32_KERNEL_GS_BASE` so swapgs lands at a valid PerCpu.
///   - This is called exactly once per CPU, after IDT and TSS
///     are live.
pub unsafe fn enable() {
    // STAR layout (Intel SDM Vol 4 §2.16.4):
    //   [31:0]  reserved
    //   [47:32] SYSCALL kernel CS (and SS = CS+8)
    //   [63:48] SYSRET user CS (CS_user = STAR[63:48]+16,
    //                            SS_user = STAR[63:48]+8)
    //
    // We want SYSCALL to land at KCODE=0x08, SS=KDATA=0x10
    // (already CS+8 ✓), and SYSRET to land at UCODE=0x33,
    // SS=UDATA=0x2B.
    //
    // SYSRET derives the user selectors as CS = STAR[63:48]+16 and
    // SS = STAR[63:48]+8. On Intel, SYSRET then ORs RPL=3 into BOTH
    // selectors, so STAR[63:48]=0x20 would give CS=0x33, SS=0x2B.
    // But on AMD (Zen4, e.g. under KVM `-cpu host`) SYSRET forces
    // RPL=3 into CS but NOT into SS — it leaves SS = STAR[63:48]+8
    // verbatim. With STAR[63:48]=0x20 that yields SS=0x28 (RPL=0),
    // so the task runs at CPL3 with a CPL0-RPL stack selector; the
    // next fault/IRQ then saves SS=0x28 and its return `iretq` #GPs
    // (SS.RPL != CS.RPL). TCG emulates the Intel OR-RPL behaviour,
    // which is why this only bit under KVM-on-AMD.
    //
    // Fix exactly as Linux does: set STAR[63:48] to a selector that
    // already carries RPL=3 (Linux uses __USER32_CS = 0x23). Then
    // CS = 0x23+16 = 0x33 and SS = 0x23+8 = 0x2B with the RPL bits
    // present in the base value — correct whether or not the CPU
    // re-ORs RPL=3. The +8/+16 only shift the GDT index (SS→idx5,
    // CS→idx6); SYSRET synthesises the descriptors, so no GDT entry
    // at index 4 (the 0x23 base) is required.
    let kernel_cs: u64 = 0x08;
    let user_cs_base: u64 = 0x23;
    let star = (user_cs_base << 48) | (kernel_cs << 32);

    let lstar = syscall_entry_x86_64 as usize as u64;

    // SAFETY: WRMSR at CPL=0 against architecturally-defined
    // SYSCALL MSRs. Reads + writes EFER preserving other bits
    // so we don't disable NX or LME.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        msr::wrmsr(IA32_STAR, star);
        msr::wrmsr(IA32_LSTAR, lstar);
        msr::wrmsr(IA32_FMASK, SFMASK_BITS);

        let efer = msr::rdmsr(IA32_EFER);
        if efer & EFER_SCE == 0 {
            msr::wrmsr(IA32_EFER, efer | EFER_SCE);
        }
    }
}

// ── SYSRET-canonical guard tests ───────────────────────────────────
//
// `sysret_safe_rip` is the guard that prevents a non-canonical return
// RIP from reaching `sysretq` (which would #GP at CPL=0 on the user
// stack — the rip=0x3 wild-jump class). Canonical RIPs pass through
// unchanged; non-canonical ones are rewritten to 0 (canonical +
// unmapped → a clean user-mode #PF → SIGSEGV).
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_x86_64_sysret_canonical_rips_pass_through() -> TestResult {
    // Canonical low (user) addresses, including the boundary 2^47-1.
    for &rip in &[
        0x0u64,
        0x1000,
        0x4000_0000,
        0x0000_7fff_ffff_ffff, // max canonical low half
    ] {
        if sysret_safe_rip(rip) != rip {
            return TestResult::Fail("canonical low RIP was altered");
        }
    }
    // Canonical high (kernel) addresses, including the boundary.
    for &rip in &[
        0xffff_8000_0000_0000, // min canonical high half
        0xffff_ffff_8000_0000, // kernel text
        0xffff_ffff_ffff_ffff,
    ] {
        if sysret_safe_rip(rip) != rip {
            return TestResult::Fail("canonical high RIP was altered");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "frame/x86_64",
    smoke_x86_64_sysret_canonical_rips_pass_through
);

fn smoke_x86_64_sysret_noncanonical_rips_rewritten_to_zero() -> TestResult {
    // Non-canonical RIPs (bits [63:47] not a sign-extension of bit 47) —
    // exactly the values that make `sysretq` #GP at CPL=0 on the user
    // stack — must be neutralised to 0.
    for &rip in &[
        0x0000_8000_0000_0000, // first non-canonical above the low half
        0x1234_5678_9abc_def0,
        0xdead_beef_dead_beef,
        0x7fff_ffff_ffff_ffff, // bit 47 clear but high bits set
        0xffff_7fff_ffff_ffff, // just below the canonical high half
    ] {
        if sysret_safe_rip(rip) != 0 {
            return TestResult::Fail("non-canonical RIP was not rewritten to 0");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "frame/x86_64",
    smoke_x86_64_sysret_noncanonical_rips_rewritten_to_zero
);
