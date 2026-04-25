//! narf-testbin — no_std user binary for NARF's user-mode test.
//!
//! Links at user virt `0x0000_0080_0000_1000` via the sibling
//! `testbin.ld`. The `_start` entry point invokes the kernel via
//! `narf-user-runtime`, which in turn issues `int 0x80` (x86_64) /
//! `svc #0` (aarch64) using NARF's syscall ABI.
//!
//! Behaviour: drives the 12 probes the e2e harness greps for
//! (argv / aux / mmap / boot / ring / fs / wr / pid / brk / clk /
//! sig / user) and finally calls `exit_task`. Anything past the
//! exit is unreachable; the trailing spin-loop is just a
//! `-> !` fallback.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;
use narf_user_runtime as rt;

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
    #[cfg(target_arch = "x86_64")]
    run_probes_x86_64(rsp_at_entry);
    #[cfg(not(target_arch = "x86_64"))]
    let _ = rsp_at_entry;

    rt::print_str("user: ok\n");
    rt::exit_task();
}

#[cfg(target_arch = "x86_64")]
fn run_probes_x86_64(rsp_at_entry: u64) {
    const EXPECT_ARGV0: &[u8] = b"narf-testbin";
    const FILE_BYTES:   &[u8] = b"hello-fs";
    const AT_NULL:      u64 = 0;
    const AT_PAGESZ:    u64 = 6;

    // ── argv probe ─────────────────────────────────────────────
    // Read argc + argv[0] from the saved entry-rsp. If the kernel
    // ran load_user_process_with(["narf-testbin", ...]), argc is
    // ≥ 1 and argv[0] points to "narf-testbin".
    if rsp_at_entry != 0 {
        let mut argv_ok;
        // SAFETY: the kernel hands us a valid argv stack at entry;
        // we only read words it laid down before jumping to user.
        unsafe {
            let argc = core::ptr::read_volatile(rsp_at_entry as *const u64);
            let argv0_p = core::ptr::read_volatile((rsp_at_entry + 8) as *const u64);
            argv_ok = argc >= 1 && argv0_p != 0;
            if argv_ok {
                for i in 0..EXPECT_ARGV0.len() {
                    let b = core::ptr::read_volatile((argv0_p + i as u64) as *const u8);
                    if b != EXPECT_ARGV0[i] { argv_ok = false; break; }
                }
            }
        }
        rt::print_str(if argv_ok { "argv: ok\n" } else { "argv: bad\n" });

        // ── aux probe ─────────────────────────────────────────
        // Walk past argv (argc+1 entries) + envp (until NULL) to
        // find the aux-vector. Verify AT_PAGESZ == 4096 lives in it.
        let mut aux_ok = false;
        // SAFETY: same justification as the argv walk.
        unsafe {
            let argc = core::ptr::read_volatile(rsp_at_entry as *const u64);
            let mut cursor = rsp_at_entry + 8 + (argc + 1) * 8;
            while core::ptr::read_volatile(cursor as *const u64) != 0 {
                cursor += 8;
            }
            cursor += 8;  // step past envp NULL terminator
            loop {
                let key = core::ptr::read_volatile(cursor as *const u64);
                let val = core::ptr::read_volatile((cursor + 8) as *const u64);
                if key == AT_NULL { break; }
                if key == AT_PAGESZ && val == 4096 { aux_ok = true; }
                cursor += 16;
            }
        }
        rt::print_str(if aux_ok { "aux: ok\n" } else { "aux: bad\n" });
    }

    // ── mmap / munmap round-trip ──────────────────────────────
    let mut mmap_ok = false;
    // SAFETY: a 4-KiB anonymous mapping; we write one u64 to confirm
    // the page is R+W and immediately munmap it.
    unsafe {
        let p = rt::mmap(0, 0x1000, 0);
        if !p.is_null() {
            core::ptr::write_volatile(p as *mut u64, 0xCAFE);
            mmap_ok = rt::munmap(p).is_ok();
        }
    }
    rt::print_str(if mmap_ok { "mmap: ok\n" } else { "mmap: bad\n" });

    // ── bootstrap probe ───────────────────────────────────────
    // SAFETY: SYS_BOOTSTRAP returns a kernel-mapped config page
    // that outlives the calling task; we only inspect the magic.
    let cfg = unsafe { rt::bootstrap() };
    let boot_ok = match cfg {
        Some(p) => {
            // SAFETY: `p` is non-null on Some + the kernel always
            // writes the magic before returning the page.
            unsafe { (*p).magic == rt::NARF_MAGIC }
        }
        None => false,
    };
    rt::print_str(if boot_ok { "boot: ok\n" } else { "boot: bad\n" });

    // ── shared-ring fast path ─────────────────────────────────
    // Write a Submission directly into SQ slot[0], bump the head,
    // kick the kernel, then read the Completion back from CQ
    // slot[0]. Proves the SharedRing layout matches between
    // kernel and CPL=3 views of the same phys.
    let mut ring_ok = false;
    if let Some(cfg_ptr) = cfg {
        // SAFETY: `cfg_ptr` is wire-stable (BootstrapHeader); we
        // observe the shared SQ/CQ vaddrs through it.
        let (sq_v, cq_v) = unsafe { ((*cfg_ptr).shared_sq_vaddr, (*cfg_ptr).shared_cq_vaddr) };

        // SharedRing layout: head u32 (0) | tail u32 (4) | closed u32 (8) | pad..64 | slots
        // Submission (#[repr(C)], 144 bytes):
        //   op u32 (0) / flags u32 (4) / pad..16 / caps[4]CapSlot 16..80 /
        //   tag u64 80..88 / inline[6]u64 88..136 / pad..144
        // SAFETY: the kernel maps the shared rings R+W in this AS;
        // writing to slot[0] is the standard producer fast path.
        unsafe {
            let sq_head_p = sq_v as *mut u32;
            let sq_slot0  = (sq_v + 64) as *mut u8;
            core::ptr::write_bytes(sq_slot0, 0, 144);
            core::ptr::write_volatile(sq_slot0 as *mut u32, 0u32);  // OpCode::Noop
            core::ptr::write_volatile((sq_slot0 as u64 + 80) as *mut u64, 0xFEED_u64);
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            core::ptr::write_volatile(sq_head_p, 1u32);

            if rt::ring_kick() == 1 {
                let cq_head = cq_v as *const u32;
                let cq_tail_p = (cq_v + 4) as *mut u32;
                let cq_slot0 = (cq_v + 64) as *const u8;
                if core::ptr::read_volatile(cq_head) == 1 {
                    let tag = core::ptr::read_volatile(cq_slot0 as *const u64);
                    let status = core::ptr::read_volatile((cq_slot0 as u64 + 8) as *const u32);
                    if tag == 0xFEED && status == 0 { ring_ok = true; }
                    core::ptr::write_volatile(cq_tail_p, 1u32);
                }
            }
        }
    }
    rt::print_str(if ring_ok { "ring: ok\n" } else { "ring: bad\n" });

    // ── VFS open / read / write / close ───────────────────────
    let mut fs_ok = false;
    let mut wr_ok = false;
    if let Some(fd) = rt::open("f", "/testbin") {
        let mut buf = [0u8; 16];
        let n = rt::read(fd, &mut buf);
        if n == FILE_BYTES.len() {
            fs_ok = true;
            for i in 0..n {
                if buf[i] != FILE_BYTES[i] { fs_ok = false; break; }
            }
        }
        // The stub FS accepts writes and returns the byte count;
        // verifies SYS_WRITE routes fd > 2 through the per-task fd
        // table.
        let payload = b"PUT";
        let wn = rt::write(fd, payload);
        wr_ok = wn == payload.len();
        let _ = rt::close(fd);
    }
    rt::print_str(if fs_ok { "fs: ok\n" } else { "fs: bad\n" });
    rt::print_str(if wr_ok { "wr: ok\n" } else { "wr: bad\n" });

    // ── pid probe ─────────────────────────────────────────────
    // Stage-4: getpid returns the kernel's task lookup value (no
    // parent tracking yet so getppid is 0).
    let _pid = rt::getpid();
    let pid_ok = rt::getppid() == 0;
    rt::print_str(if pid_ok { "pid: ok\n" } else { "pid: bad\n" });

    // ── brk probe ─────────────────────────────────────────────
    // Query → grow by one page → write a byte to the new slot →
    // query again to confirm the break stuck.
    let initial = rt::brk(0);
    let target  = initial + 0x1000;
    let after   = rt::brk(target);
    let mut brk_ok = initial != 0 && initial != usize::MAX && after == target;
    if brk_ok {
        // SAFETY: brk just R+W-mapped [initial, target).
        unsafe { core::ptr::write_volatile(initial as *mut u8, 0x5A); }
        if rt::brk(0) != target { brk_ok = false; }
    }
    rt::print_str(if brk_ok { "brk: ok\n" } else { "brk: bad\n" });

    // ── clock_gettime probe ───────────────────────────────────
    let (sec, nsec) = rt::clock_gettime(0);
    let clk_ok = sec >= 0 && nsec >= 0 && nsec < 1_000_000_000;
    rt::print_str(if clk_ok { "clk: ok\n" } else { "clk: bad\n" });

    // ── sigaction probe ──────────────────────────────────────
    // Install handler 0xDEADBEEF for SIGTERM, then clear it and
    // confirm the prior handler is reported.
    // SAFETY: we never deliver a signal; Stage-4 sigaction is
    // record-only, so 0xDEADBEEF is a sentinel pointer that's
    // never dereferenced.
    unsafe {
        rt::sigaction(15, 0xDEADBEEF);
    }
    // SAFETY: clears the handler and reads the prior into the
    // SDK's stack-local out-pointer.
    let prior = unsafe { rt::sigaction(15, 0) };
    let sig_ok = prior == 0xDEADBEEF;
    rt::print_str(if sig_ok { "sig: ok\n" } else { "sig: bad\n" });
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop { core::hint::spin_loop(); }
}
