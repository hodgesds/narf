//! narf-testbin — no_std user binary for NARF's user-mode test.
//!
//! Links at user virt `0x0000_0080_0000_1000` via the sibling
//! `testbin.ld`. The `_start` entry point calls the kernel via
//! `int 0x80` using NARF's syscall ABI (rax = number, rdi..r9 =
//! args; return value in rax, status in rdx).
//!
//! Behaviour:
//! 1. Syscall::Write(fd=1, "user: ok\n", 9) — proves user→kernel
//!    transition + console write.
//! 2. Syscall::ExitTask — syscall handler redirects the trap frame
//!    back into kernel state via `redirect_to_kernel`.
//! 3. Hang loop — should never execute; `ud2`-equivalent if the
//!    exit redirect somehow fails.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::arch::asm;
use core::panic::PanicInfo;

// Syscall numbers (mirror `narf_userspace::Syscall` — keep in
// sync). NARF reserves 100+ so there's no Linux collision.
const SYS_WRITE:     u64 = 112;
const SYS_EXIT_TASK: u64 = 103;
const SYS_MMAP:      u64 = 120;

#[inline(always)]
unsafe fn syscall3(num: u64, a0: u64, a1: u64, a2: u64) -> u64 {
    let mut rax: u64 = num;
    // SAFETY: inline asm that invokes the int-0x80 syscall gate —
    // the kernel has registered handlers for the numbers we use.
    // rcx + r11 are trap-clobbered; rdx returns the status
    // separately (we don't observe it here).
    unsafe {
        asm!(
            "int 0x80",
            inout("rax") rax,
            in("rdi") a0, in("rsi") a1, in("rdx") a2,
            out("rcx") _, out("r11") _,
            options(nostack, preserves_flags),
        );
    }
    rax
}

#[inline(always)]
unsafe fn syscall0(num: u64) -> u64 {
    let mut rax: u64 = num;
    // SAFETY: see `syscall3`.
    unsafe {
        asm!(
            "int 0x80",
            inout("rax") rax,
            out("rcx") _, out("r11") _, out("rdx") _,
            options(nostack, preserves_flags),
        );
    }
    rax
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    const MSG: &[u8] = b"user: ok\n";
    // SAFETY: we're the user program, the kernel has set up the
    // int-0x80 gate, and the message lives in our RX segment.
    unsafe {
        // Use Mmap so the const is referenced; the address is
        // returned into rax. We don't deference it yet — the
        // Mmap-backed-page write-fault is tracked separately.
        let _ = syscall3(SYS_MMAP, 0, 0x1000, 0);
        syscall3(SYS_WRITE, 1, MSG.as_ptr() as u64, MSG.len() as u64);
        syscall0(SYS_EXIT_TASK);
    }
    loop { core::hint::spin_loop(); }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop { core::hint::spin_loop(); }
}
