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

        // Save the registers that `sysretq` needs to consume on
        // return: rcx (user RIP) and r11 (user RFLAGS). Push
        // these first so they're easy to find on the way out.
        "push r11",
        "push rcx",

        // Build a SyscallArgs struct on the stack from the
        // user-side argument registers. SysV passes args in
        // rdi/rsi/rdx/rcx/r8/r9; the syscall ABI substitutes r10
        // for rcx because rcx carries the return RIP. Push in
        // reverse so the struct lays out as
        // { arg0=rdi, arg1=rsi, arg2=rdx, arg3=r10, arg4=r8, arg5=r9 }
        // when we pass &args = rsp.
        "push r9",        // arg5
        "push r8",        // arg4
        "push r10",       // arg3
        "push rdx",       // arg2
        "push rsi",       // arg1
        "push rdi",       // arg0

        // Stash the syscall number (rax) so the dispatcher's
        // calling convention can use it as the first argument
        // without losing it across the call.
        "mov edi, eax",   // syscall number → arg0
        "mov rsi, rsp",   // &SyscallArgs → arg1

        // Reserve the 16-byte SysV stack alignment + nothing else;
        // we already pushed 6+2=8 dwords (64 bytes), so RSP is
        // already 16-byte-aligned for the call.
        "call {dispatch}",

        // SyscallReturn is a 16-byte struct: status:u32 + padding,
        // then value:u64. SysV returns it in rax + rdx; rax holds
        // status (low 32 bits zero-extended), rdx holds value.
        //
        // Match the int 0x80 path's userland-visible convention
        // (set_return in trap.rs: frame.rax = value, frame.rdx =
        // status), so user-runtime's syscall wrappers see the same
        // register layout regardless of which entry path was used.
        // `xchg` accomplishes the swap in one instruction with no
        // scratch register needed.
        "xchg rax, rdx",

        // Drop the SyscallArgs scratch (6 × 8 = 48 bytes).
        "add rsp, 48",

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
/// dispatch logic.
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
