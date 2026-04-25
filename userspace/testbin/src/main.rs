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
#[cfg(target_arch = "x86_64")]
const SYS_MMAP:      u64 = 120;
#[cfg(target_arch = "x86_64")]
const SYS_BOOTSTRAP: u64 = 101;
#[cfg(target_arch = "x86_64")]
const NARF_MAGIC:    u32 = 0x4E_41_52_46;  // "NARF" LE

#[cfg(target_arch = "x86_64")]
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

#[cfg(target_arch = "x86_64")]
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

// aarch64 ABI: x8 = syscall number, x0..x5 = args, return in x0.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn syscall3(num: u64, a0: u64, a1: u64, a2: u64) -> u64 {
    let mut ret: u64;
    // SAFETY: kernel has registered handlers for these numbers
    // and the SVC gate (Lower-EL-AArch64 sync vector) routes via
    // `rust_aarch64_sync_dispatch`.
    unsafe {
        asm!(
            "svc #0",
            in("x8") num,
            inout("x0") a0 => ret,
            in("x1") a1, in("x2") a2,
            options(nostack, preserves_flags),
        );
    }
    ret
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn syscall0(num: u64) -> u64 {
    let mut ret: u64;
    unsafe {
        asm!(
            "svc #0",
            in("x8") num,
            lateout("x0") ret,
            options(nostack, preserves_flags),
        );
    }
    ret
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    const MSG:    &[u8] = b"user: ok\n";
    #[cfg(target_arch = "x86_64")]
    const BOK:    &[u8] = b"boot: ok\n";
    #[cfg(target_arch = "x86_64")]
    const BBAD:   &[u8] = b"boot: bad\n";
    // SAFETY: we're the user program, the kernel has set up the
    // int-0x80 gate, and the message lives in our RX segment.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            let addr = syscall3(SYS_MMAP, 0, 0x1000, 0);
            // Probe-write to the mmap'd page.
            if addr != 0 && addr != !0u64 {
                let p = addr as *mut u64;
                core::ptr::write_volatile(p, 0xCAFEu64);
            }

            // Bootstrap: mint per-task config page + SQ/CQ rings.
            // Returns the user vaddr of the config page; first u32
            // is the "NARF" magic. Proves SYS_BOOTSTRAP works from
            // real user mode.
            let cfg = syscall0(SYS_BOOTSTRAP);
            let ok = cfg != 0 && cfg != !0u64
                && core::ptr::read_volatile(cfg as *const u32) == NARF_MAGIC;
            let (mp, ml) = if ok { (BOK.as_ptr(), BOK.len()) }
                           else   { (BBAD.as_ptr(), BBAD.len()) };
            syscall3(SYS_WRITE, 1, mp as u64, ml as u64);
        }
        syscall3(SYS_WRITE, 1, MSG.as_ptr() as u64, MSG.len() as u64);
        syscall0(SYS_EXIT_TASK);
    }
    loop { core::hint::spin_loop(); }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop { core::hint::spin_loop(); }
}
