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

        // Save the registers `sysretq` consumes on return:
        // rcx (user RIP) and r11 (user RFLAGS).
        "push r11",
        "push rcx",

        // Build a SyscallArgs struct in-place on the kernel
        // stack from rdi/rsi/rdx/r10/r8/r9 (the user-side
        // syscall arg registers — note r10 substitutes for rcx
        // because the syscall instruction clobbered rcx with
        // the user RIP). SyscallArgs is `#[repr(C)]` so the
        // declaration order { arg0, arg1, ..., arg5 } is the
        // memory order, matching this push sequence (reverse
        // order so &SyscallArgs = current rsp lays out arg0
        // at offset 0).
        "push r9",        // arg5
        "push r8",        // arg4
        "push r10",       // arg3
        "push rdx",       // arg2
        "push rsi",       // arg1
        "push rdi",       // arg0

        // SysV calling convention for `dispatch_syscall(num, &args)`:
        // arg0 (num) → rdi, arg1 (&args) → rsi.
        "mov edi, eax",   // syscall number
        "mov rsi, rsp",   // &SyscallArgs

        // Pre-call rsp = kernel_stack_top - 16 (r11+rcx) - 48
        // (six 8-byte arg pushes) = -64, which is 16-aligned ✓.
        // The call's return-address push lands at -72, which is
        // 16k+8 — exactly what SysV requires inside the callee.
        "call {dispatch}",

        // Linux's syscall ABI requires the kernel to preserve
        // every GPR EXCEPT `rax` (return), `rcx` (used by sysretq
        // for user RIP), and `r11` (used by sysretq for user
        // RFLAGS). The C-ABI `dispatch_syscall` call freely
        // clobbers rdi/rsi/rdx/r8/r9/r10 as caller-saved, so we
        // MUST restore them from the SyscallArgs push scratch on
        // the stack before sysretq.
        //
        // Bug pre-fix: a bare `add rsp, 48` left these holding
        // C-frame trash. Symptom: musl's `__stdout_write` saves
        // stdout in r8 BEFORE `ioctl(TIOCGWINSZ)` and restores
        // from r8 AFTER; the trashed r8 became the FILE* fed to
        // `__stdio_write` which #PFed reading `f->wpos` at a
        // truncated address (`cr2=0x1e8848, rip=0x...62d9a`).
        //
        // Stash the dispatcher's rax/rdx into rcx/r11 — those
        // two registers are about to be reloaded from the stack
        // for sysretq anyway, so we can borrow them as scratch.
        "mov rcx, rax",   // stash dispatcher status (low 32 of SyscallReturn) in rcx
        "mov r11, rdx",   // stash dispatcher value (high 64 of SyscallReturn) in r11

        // Restore the six user-side arg registers from the
        // SyscallArgs scratch (in reverse push order so each
        // register lands back where the user had it).
        "pop rdi",        // arg0
        "pop rsi",        // arg1
        "pop rdx",        // arg2
        "pop r10",        // arg3
        "pop r8",         // arg4
        "pop r9",         // arg5

        // SyscallReturn final convention (matches the int 0x80
        // path's `frame.rax = value, frame.rdx = status` in
        // trap.rs, so user-side wrappers see the same layout
        // regardless of entry instruction): rax = value,
        // rdx = status.
        "mov rax, r11",   // rax = dispatcher value
        "mov rdx, rcx",   // rdx = dispatcher status

        // Restore user rcx (RIP) and r11 (RFLAGS) from the slots
        // we pushed at entry.
        "pop rcx",
        "pop r11",

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

/// C-ABI dispatcher invoked from the naked asm. Marshals into
/// the existing `narf_userspace::kernel_syscall_entry_plain`
/// machinery so the int 0x80 path and the SYSCALL path share
/// dispatch logic. `args` is a borrow of the 6-u64 struct the
/// asm built directly on the kernel stack — `SyscallArgs` is
/// `#[repr(C)]` so the asm's push order matches the field
/// layout exactly.
extern "C" fn dispatch_syscall(
    num: u32,
    args: &narf_userspace::SyscallArgs,
) -> narf_userspace::SyscallReturn {
    narf_userspace::kernel_syscall_entry_plain(num, args)
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
