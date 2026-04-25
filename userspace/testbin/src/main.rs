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
const SYS_MUNMAP:    u64 = 121;
#[cfg(target_arch = "x86_64")]
const SYS_BOOTSTRAP: u64 = 101;
#[cfg(target_arch = "x86_64")]
const SYS_OPEN:      u64 = 110;
#[cfg(target_arch = "x86_64")]
const SYS_READ:      u64 = 111;
#[cfg(target_arch = "x86_64")]
const SYS_CLOSE:     u64 = 113;
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
unsafe fn syscall4(num: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    let mut rax: u64 = num;
    // SAFETY: see `syscall3`. r10 is the 4th-arg register in NARF's
    // syscall ABI (mirrors Linux's amd64 convention).
    unsafe {
        asm!(
            "int 0x80",
            inout("rax") rax,
            in("rdi") a0, in("rsi") a1, in("rdx") a2, in("r10") a3,
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

// Naked entry point. SysV-AMD64 startup contract: at entry, [rsp]
// = argc, [rsp+8..] = argv pointers, etc. We grab the original
// rsp before any prologue runs, hand it to `start_rust` as the
// first argument, then align rsp to 16 (SysV ABI requires) and
// tail-call.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, rsp",
        "and rsp, -16",
        "call {entry}",
        // start_rust is `-> !`; if it returns we're in trouble — fall
        // through to ud2.
        "ud2",
        entry = sym start_rust,
    );
}

// aarch64 has no argv-on-stack reading in this round; keep the
// existing flow.
#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    start_rust(0)
}

fn start_rust(rsp_at_entry: u64) -> ! {
    const MSG:    &[u8] = b"user: ok\n";
    #[cfg(target_arch = "x86_64")]
    const BOK:    &[u8] = b"boot: ok\n";
    #[cfg(target_arch = "x86_64")]
    const BBAD:   &[u8] = b"boot: bad\n";
    #[cfg(target_arch = "x86_64")]
    const FOK:    &[u8] = b"fs: ok\n";
    #[cfg(target_arch = "x86_64")]
    const FBAD:   &[u8] = b"fs: bad\n";
    #[cfg(target_arch = "x86_64")]
    const FILE_PATH: &[u8] = b"f";
    #[cfg(target_arch = "x86_64")]
    const MOUNT:     &[u8] = b"/testbin";
    #[cfg(target_arch = "x86_64")]
    const FILE_BYTES: &[u8] = b"hello-fs";
    #[cfg(target_arch = "x86_64")]
    const AOK:        &[u8] = b"argv: ok\n";
    #[cfg(target_arch = "x86_64")]
    const ABAD:       &[u8] = b"argv: bad\n";
    #[cfg(target_arch = "x86_64")]
    const EXPECT_ARGV0: &[u8] = b"narf-testbin";
    #[cfg(target_arch = "x86_64")]
    const AUX_OK:     &[u8] = b"aux: ok\n";
    #[cfg(target_arch = "x86_64")]
    const AUX_BAD:    &[u8] = b"aux: bad\n";
    #[cfg(target_arch = "x86_64")]
    const AT_NULL:    u64 = 0;
    #[cfg(target_arch = "x86_64")]
    const AT_PAGESZ:  u64 = 6;
    // SAFETY: we're the user program, the kernel has set up the
    // int-0x80 gate, and the message lives in our RX segment.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            // argv probe: read argc + argv[0] string from the
            // entry-rsp passed into start_rust. If the kernel ran
            // load_user_process_with(["narf-testbin", ...]), argc
            // is 2 and argv[0] points to "narf-testbin".
            if rsp_at_entry != 0 {
                let argc = core::ptr::read_volatile(rsp_at_entry as *const u64);
                let argv0_p = core::ptr::read_volatile((rsp_at_entry + 8) as *const u64);
                let mut argv_ok = argc >= 1 && argv0_p != 0;
                if argv_ok {
                    for i in 0..EXPECT_ARGV0.len() {
                        let b = core::ptr::read_volatile((argv0_p + i as u64) as *const u8);
                        if b != EXPECT_ARGV0[i] { argv_ok = false; break; }
                    }
                }
                let (ap, al) = if argv_ok { (AOK.as_ptr(), AOK.len()) }
                                else       { (ABAD.as_ptr(), ABAD.len()) };
                syscall3(SYS_WRITE, 1, ap as u64, al as u64);

                // Walk past argv (argc+1 entries) + envp (until NULL)
                // to find the aux-vector. Verify AT_PAGESZ=4096 lives
                // there.
                let mut cursor = rsp_at_entry + 8 + (argc + 1) * 8;
                while core::ptr::read_volatile(cursor as *const u64) != 0 {
                    cursor += 8;
                }
                cursor += 8;  // step past envp NULL terminator
                let mut aux_ok = false;
                loop {
                    let key = core::ptr::read_volatile(cursor as *const u64);
                    let val = core::ptr::read_volatile((cursor + 8) as *const u64);
                    if key == AT_NULL { break; }
                    if key == AT_PAGESZ && val == 4096 { aux_ok = true; }
                    cursor += 16;
                }
                let (xp, xl) = if aux_ok { (AUX_OK.as_ptr(), AUX_OK.len()) }
                                else      { (AUX_BAD.as_ptr(), AUX_BAD.len()) };
                syscall3(SYS_WRITE, 1, xp as u64, xl as u64);
            }

            let addr = syscall3(SYS_MMAP, 0, 0x1000, 0);
            // Probe-write + munmap round-trip. munmap returning 0
            // proves the inverse of mmap works at CPL=3.
            const MOK:    &[u8] = b"mmap: ok\n";
            const MBAD:   &[u8] = b"mmap: bad\n";
            let mut mmap_ok = false;
            if addr != 0 && addr != !0u64 {
                let p = addr as *mut u64;
                core::ptr::write_volatile(p, 0xCAFEu64);
                let r = syscall3(SYS_MUNMAP, addr, 0, 0);
                mmap_ok = r == 0;
            }
            let (mp_a, ml_a) = if mmap_ok { (MOK.as_ptr(), MOK.len()) }
                                else        { (MBAD.as_ptr(), MBAD.len()) };
            syscall3(SYS_WRITE, 1, mp_a as u64, ml_a as u64);

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

            // VFS round-trip: open + read + close from real user
            // mode. Mounted under "/testbin"; "f" is the file name.
            let fd = syscall4(SYS_OPEN,
                FILE_PATH.as_ptr() as u64, FILE_PATH.len() as u64,
                MOUNT.as_ptr()     as u64, MOUNT.len()     as u64);
            let mut buf = [0u8; 16];
            let mut fs_ok = false;
            const WROK:  &[u8] = b"wr: ok\n";
            const WRBAD: &[u8] = b"wr: bad\n";
            const PAYLOAD: &[u8] = b"PUT";
            let mut wr_ok = false;
            if fd != !0u64 {
                let n = syscall3(SYS_READ,
                    fd, buf.as_mut_ptr() as u64, buf.len() as u64);
                if n == FILE_BYTES.len() as u64 {
                    fs_ok = true;
                    for i in 0..(n as usize) {
                        if buf[i] != FILE_BYTES[i] { fs_ok = false; break; }
                    }
                }
                // Write to the same fd: the stub FS accepts writes
                // and returns the byte count. Verifies SYS_WRITE
                // routes fd>2 through the per-task fd table.
                let wn = syscall3(SYS_WRITE,
                    fd, PAYLOAD.as_ptr() as u64, PAYLOAD.len() as u64);
                wr_ok = wn == PAYLOAD.len() as u64;
                let _ = syscall3(SYS_CLOSE, fd, 0, 0);
            }
            let (fp, fl) = if fs_ok { (FOK.as_ptr(), FOK.len()) }
                           else      { (FBAD.as_ptr(), FBAD.len()) };
            syscall3(SYS_WRITE, 1, fp as u64, fl as u64);
            let (wp, wl) = if wr_ok { (WROK.as_ptr(), WROK.len()) }
                            else     { (WRBAD.as_ptr(), WRBAD.len()) };
            syscall3(SYS_WRITE, 1, wp as u64, wl as u64);
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
