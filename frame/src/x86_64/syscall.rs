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

        // After dispatch:
        //   rax = SyscallReturn.status (low 32 of struct return)
        //   rdx = SyscallReturn.value
        // The user state on the stack is intact unless the
        // handler wrote back into it via `set_return` /
        // `save_user_state`. The handler's `set_return` modifies
        // the rax slot at [rsp + 112].
        //
        // Linux's syscall ABI returns a single signed value in
        // rax: positive on success, negative-errno on failure.
        // rdx, rdi, rsi, r10, r8, r9 must all be PRESERVED. The
        // previous "rax = value, rdx = status" convention worked
        // for narf-libc callers that read both registers, but it
        // breaks every musl-built binary — musl emits patterns
        // like `mov %fs:0, %rdx; syscall; movq $0, 0x98(%rdx)`
        // around `__init_tp`'s `set_tid_address` call, expecting
        // rdx to survive the syscall. When we clobbered rdx with
        // the status word (0 for OK), every forked child #PF'd at
        // CR2=0x98 inside `__init_tp` because rdx → 0.
        //
        // Fold: if status != OK, set rax = -EINVAL (-22) so
        // userspace sees a negative-errno error per Linux
        // semantics. Otherwise rax = value.
        "mov rcx, rax",                        // status → rcx (scratch — about to reload)
        "test ecx, ecx",                       // status == 0 (OK)?
        "mov rax, rdx",                        // rax = value (assumed-success path)
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

        // Reload user RIP, RFLAGS from saved slots for sysretq.
        "mov rcx, [rsp + 120]",                // user RIP
        "mov r11, [rsp + 128]",                // user RFLAGS

        // Drop the UserState scratch.
        "add rsp, 152",

        // Restore user RSP from the per-CPU scratch slot, swap
        // back to user GS, and return to user mode. `sysretq`
        // jumps to `rcx` with `rflags = r11`, CS/SS from
        // STAR[63:48] (+16 / +8 with RPL forced to 3).
        "mov rsp, gs:[0]",
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
    narf_userspace::kernel_syscall_entry_plain_with_state(num, &args, state as *mut _ as *mut u8)
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
    // SS=UDATA=0x2B. Hardware ORs in RPL=3 for sysret, so
    // STAR[63:48] = UCODE & ~3 - 16 = 0x30 - 16 = 0x20.
    let kernel_cs: u64 = 0x08;
    let user_cs_minus_16: u64 = 0x20;
    let star = (user_cs_minus_16 << 48) | (kernel_cs << 32);

    let lstar = syscall_entry_x86_64 as u64;

    // SAFETY: WRMSR at CPL=0 against architecturally-defined
    // SYSCALL MSRs. Reads + writes EFER preserving other bits
    // so we don't disable NX or LME.
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
