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

// The signal handler stores the received signum at a fixed user
// vaddr that the brk probe previously grew into the AS. We can't
// use a `static AtomicU32` because the testbin's linker script
// collapses .data/.bss into the R+X PT_LOAD (Stage-4 loader
// limitation) — every static is read-only. The brk-grown heap
// page at `BRK_DEFAULT_BASE = 0x0000_5000_0000_0000` is R+W and
// known-stable across the whole task.
const SIG_RECV_VADDR: u64 = 0x0000_5000_0000_0000;

// SysV-AMD64 signal handler: signum lives in rdi (first integer
// arg). Must `ret` cleanly — the kernel synthesised a `[saved_rip,
// signum]` pair on the user stack so the handler's epilogue pops
// `saved_rip` and resumes the trapped instruction. Volatile
// store-through-pointer only — anything reentrant-unsafe in here
// would corrupt the trapped-context resumption.
extern "C" fn signal_handler(signum: u32) {
    // SAFETY: the brk probe earlier in `start_rust` grew the heap
    // by one page so [BRK_DEFAULT_BASE, +0x1000) is R+W in the
    // active AS for the lifetime of this task.
    // SAFETY: Valid memory or trusted environment
    unsafe { core::ptr::write_volatile(SIG_RECV_VADDR as *mut u32, signum); }
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
    #[cfg(target_arch = "x86_64")]
    run_probes_x86_64(rsp_at_entry);
    #[cfg(not(target_arch = "x86_64"))]
    let _ = rsp_at_entry;

    rt::print_str("user: ok\n");
    rt::exit_task();
}

/// Triangle wave: 0 → span → 0 over `period` frames. Lets the
/// FB demo bounce a sprite without dragging in libm.
fn tri_wave(frame: u32, period: u32, span: u32) -> u32 {
    if span == 0 || period == 0 { return 0; }
    let phase = frame % period;
    let half = period / 2;
    let progress = if phase < half { phase } else { period - phase };
    ((progress as u64 * span as u64) / half.max(1) as u64) as u32
}

/// Format `n` as decimal into `buf` (must be ≥10 bytes). Returns the
/// subslice containing the digits (no leading zeros except "0" itself).
#[cfg(target_arch = "x86_64")]
fn fmt_u32(buf: &mut [u8; 10], n: u32) -> &[u8] {
    if n == 0 {
        buf[9] = b'0';
        return &buf[9..];
    }
    let mut i = 10usize;
    let mut v = n;
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    &buf[i..]
}

/// `struct fb_var_screeninfo` wire layout (160 bytes, x86_64 ABI).
/// Only the fields we read are named; the rest is `_rest`.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct WireVarScreenInfo {
    xres: u32,
    yres: u32,
    xres_virtual: u32,
    yres_virtual: u32,
    xoffset: u32,
    yoffset: u32,
    bits_per_pixel: u32,
    grayscale: u32,
    // bitfields, flags … (160 bytes total, we only inspect first 8 u32s)
    _rest: [u8; 128],
}

/// `struct fb_fix_screeninfo` wire layout (x86_64: 80 bytes).
/// unsigned long → u64 on x86_64.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct WireFixScreenInfo {
    id: [u8; 16],       // 0..16
    smem_start: u64,    // 16..24
    smem_len: u32,      // 24..28
    fb_type: u32,       // 28..32
    type_aux: u32,      // 32..36
    visual: u32,        // 36..40
    xpanstep: u16,      // 40..42
    ypanstep: u16,      // 42..44
    ywrapstep: u16,     // 44..46
    _pad: u16,          // 46..48 (implicit alignment pad before line_length)
    line_length: u32,   // 48..52
    mmio_start: u64,    // 52..60
    mmio_len: u32,      // 60..64
    accel: u32,         // 64..68
    capabilities: u16,  // 68..70
    reserved: [u16; 2], // 70..74  + 6 bytes padding to align to 80
    _tail: [u8; 6],     // 74..80
}

/// Probe `/dev/fb0`:
///  1. open, FBIOGET_VSCREENINFO, FBIOGET_FSCREENINFO
///  2. mmap MAP_SHARED
///  3. draw a horizontal gradient across the first scanline
///  4. print "fb0: ok <W>x<H>\n" on success, "fb0: bad ...\n" on failure
#[cfg(target_arch = "x86_64")]
fn probe_dev_fb0() {
    const FBIOGET_VSCREENINFO: u32 = 0x4600;
    const FBIOGET_FSCREENINFO: u32 = 0x4602;
    const SYS_IOCTL: u64 = 16;
    const SYS_MMAP: u64 = 9;
    const PROT_READ: u64 = 0x1;
    const PROT_WRITE: u64 = 0x2;
    const MAP_SHARED: u64 = 0x01;

    // Resolves only in a /dev-bearing namespace (the boot-init shell
    // rootfs). The bare testbin kernel-test mounts no /dev, so this
    // skips quietly there — the device itself is covered by the
    // `smoke_fbdev_*` kernel smokes.
    let fd = match rt::open("fb0", "/dev").or_else(|| rt::open_abs("/dev/fb0")) {
        Some(f) => f,
        None => {
            rt::print_str("fb0: skip (no /dev)\n");
            return;
        }
    };

    // ── FBIOGET_VSCREENINFO ──────────────────────────────────────
    // SAFETY: WireVarScreenInfo is repr(C), zeroed is a valid bit pattern,
    // and we pass its address to the ioctl which writes exactly sizeof bytes.
    let mut vsi: WireVarScreenInfo = unsafe { core::mem::zeroed() };
    let r = unsafe {
        rt::syscall3_raw(
            SYS_IOCTL,
            fd as u64,
            FBIOGET_VSCREENINFO as u64,
            &mut vsi as *mut WireVarScreenInfo as u64,
        )
    };
    if r != 0 {
        let _ = rt::close(fd);
        rt::print_str("fb0: bad (vscreeninfo)\n");
        return;
    }
    let w = vsi.xres;
    let h = vsi.yres;
    if w == 0 || h == 0 || vsi.bits_per_pixel != 32 {
        let _ = rt::close(fd);
        rt::print_str("fb0: bad (geom)\n");
        return;
    }

    // ── FBIOGET_FSCREENINFO ──────────────────────────────────────
    // SAFETY: same justification as above.
    let mut fsi: WireFixScreenInfo = unsafe { core::mem::zeroed() };
    let r = unsafe {
        rt::syscall3_raw(
            SYS_IOCTL,
            fd as u64,
            FBIOGET_FSCREENINFO as u64,
            &mut fsi as *mut WireFixScreenInfo as u64,
        )
    };
    if r != 0 {
        let _ = rt::close(fd);
        rt::print_str("fb0: bad (fscreeninfo)\n");
        return;
    }
    let map_len = fsi.smem_len as usize;
    let map_len_rounded = (map_len + 0xFFF) & !0xFFF;
    if map_len_rounded == 0 {
        let _ = rt::close(fd);
        rt::print_str("fb0: bad (map_len=0)\n");
        return;
    }

    // ── mmap MAP_SHARED ──────────────────────────────────────────
    // Call mmap(0, map_len_rounded, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)
    // using inline asm since rt::mmap hardcodes fd=-1 (anonymous).
    // SAFETY: We hold `fd`, which was opened above and is valid for the
    // duration of the mapping; MAP_SHARED aliases the device's physical
    // frames directly; we pass hint=0 so the kernel picks the address.
    let fb_ptr: *mut u32 = {
        let r = unsafe {
            // x86_64 syscall ABI: rax=num, rdi=a0, rsi=a1, rdx=a2,
            // r10=a3 (not rcx!), r8=a4, r9=a5.
            let ret: u64;
            core::arch::asm!(
                "syscall",
                inlateout("rax") SYS_MMAP => ret,
                in("rdi") 0u64,
                in("rsi") map_len_rounded as u64,
                in("rdx") PROT_READ | PROT_WRITE,
                in("r10") MAP_SHARED,
                in("r8")  fd as u64,
                in("r9")  0u64,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
            ret
        };
        if r == 0 || r > u64::MAX - 4096 {
            let _ = rt::close(fd);
            rt::print_str("fb0: bad (mmap)\n");
            return;
        }
        r as *mut u32
    };

    // ── draw a horizontal gradient across the first scanline ─────
    let stride_px = (fsi.line_length / 4) as usize; // pixels per scanline
    let grad_w = w.min(256) as usize;
    for x in 0..grad_w {
        let r8 = (x * 255 / grad_w.max(1)) as u32;
        let g8 = ((grad_w - x) * 255 / grad_w.max(1)) as u32;
        let pixel = (r8 << 16) | (g8 << 8) | 0x80; // XRGB8888
        // SAFETY: fb_ptr + x is within the mmap'd region (stride_px ≥ w).
        unsafe { core::ptr::write_volatile(fb_ptr.add(x.min(stride_px - 1)), pixel); }
    }

    let _ = rt::close(fd);

    // ── print "fb0: ok <W>x<H>" ───────────────────────────────────
    let mut wb = [0u8; 10];
    let mut hb = [0u8; 10];
    let ws = fmt_u32(&mut wb, w);
    let hs = fmt_u32(&mut hb, h);
    rt::print_str("fb0: ok ");
    // SAFETY: fmt_u32 produces valid ASCII digits only.
    rt::print_str(unsafe { core::str::from_utf8_unchecked(ws) });
    rt::print_str("x");
    rt::print_str(unsafe { core::str::from_utf8_unchecked(hs) });
    rt::print_str("\n");
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
        // SAFETY: Valid memory or trusted environment
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
    // SAFETY: Valid memory or trusted environment
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
    // SAFETY: Valid memory or trusted environment
    let cfg = unsafe { rt::bootstrap() };
    let boot_ok = match cfg {
        Some(p) => {
            // SAFETY: `p` is non-null on Some + the kernel always
            // writes the magic before returning the page.
            // SAFETY: Valid memory or trusted environment
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
        // SAFETY: Valid memory or trusted environment
        let (sq_v, cq_v) = unsafe { ((*cfg_ptr).shared_sq_vaddr, (*cfg_ptr).shared_cq_vaddr) };

        // SharedRing layout: head u32 (0) | tail u32 (4) | closed u32 (8) | pad..64 | slots
        // Submission (#[repr(C)], 144 bytes):
        //   op u32 (0) / flags u32 (4) / pad..16 / caps[4]CapSlot 16..80 /
        //   tag u64 80..88 / inline[6]u64 88..136 / pad..144
        // SAFETY: the kernel maps the shared rings R+W in this AS;
        // writing to slot[0] is the standard producer fast path.
        // SAFETY: Valid memory or trusted environment
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
    // SAFETY: Valid memory or trusted environment
    unsafe {
        rt::sigaction(15, 0xDEADBEEF);
    }
    // SAFETY: clears the handler and reads the prior into the
    // SDK's stack-local out-pointer.
    // SAFETY: Valid memory or trusted environment
    let prior = unsafe { rt::sigaction(15, 0) };
    let sig_ok = prior == 0xDEADBEEF;
    rt::print_str(if sig_ok { "sig: ok\n" } else { "sig: bad\n" });

    // ── signal-delivery probe ─────────────────────────────────
    // Install `signal_handler` for SIGUSR1 (10), kill ourselves,
    // then yield a few times — the kernel pops the pending bit
    // and rewrites the trap frame on the very next int-0x80
    // trap-return so by the time `yield_now()` actually returns
    // here, the handler has already run and stored the signum
    // into SIG_RECV.
    // SAFETY: brk-grown heap page is R+W in the active AS.
    unsafe { core::ptr::write_volatile(SIG_RECV_VADDR as *mut u32, 0); }
    // SAFETY: signal_handler is a valid SysV-AMD64 entry point;
    // the kernel records the address against the calling task's
    // sigaction table.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        rt::sigaction(10, signal_handler as usize);
    }
    let _ = rt::kill(rt::getpid(), 10);
    for _ in 0..4 {
        rt::yield_now();
        // SAFETY: same page as above.
        if unsafe { core::ptr::read_volatile(SIG_RECV_VADDR as *const u32) } != 0 { break; }
    }
    // SAFETY: same page as above.
    let signal_ok = unsafe { core::ptr::read_volatile(SIG_RECV_VADDR as *const u32) } == 10;
    rt::print_str(if signal_ok { "signal: ok\n" } else { "signal: bad\n" });

    // ── fb probe ──────────────────────────────────────────────
    // Open the active scanout via libnarf-graphics, sanity-check
    // geometry, draw a colorful demo pattern (so a developer
    // running `cargo xtask run --display gtk --features
    // user-mode-testbin` can actually SEE userspace pixels land
    // on the framebuffer), flush, and pause briefly so the demo
    // is visible before QEMU exits. Drop closes the connection.
    let fb_ok = match rt::graphics::FbContext::open() {
        Ok(mut fb) => {
            let info = *fb.info();
            let geom_ok = info.width > 0
                       && info.height > 0
                       && info.format == rt::FB_FORMAT_XRGB8888;
            if !geom_ok {
                false
            } else {
                let mut all_ok = true;
                let palette = [
                    0xFFE53935u32, 0xFFFB8C00, 0xFFFDD835, 0xFF43A047,
                    0xFF1E88E5, 0xFF5E35B1, 0xFFD81B60, 0xFFE0E0E0,
                ];
                let bar_w = info.width / 8;
                let s = 96u32.min(info.width.min(info.height) / 4);

                // ~30 fps × 10 s = 300 frames. The producer ring is
                // 16 deep, so a `RingFull` just means yield + retry
                // — `nanosleep` is the natural pacing source.
                const FRAMES: u32 = 300;
                const FRAME_NS: u64 = 33_333_333;
                for frame in 0..FRAMES {
                    // Background: solid dark blue.
                    while fb.fill(0, 0, info.width, info.height, 0xFF101840).is_err() {
                        rt::yield_now();
                    }
                    // Static 8 vertical color bars (the visual
                    // anchor that says "userspace pixels landed").
                    for (i, &color) in palette.iter().enumerate() {
                        let x = (i as u32) * bar_w;
                        let h = info.height / 2;
                        while fb.fill(x, info.height / 4, bar_w, h, color).is_err() {
                            rt::yield_now();
                        }
                    }
                    // Bouncing yellow square: triangle-wave on x,
                    // cosine-ish on y via a second triangle-wave at
                    // a different period so the motion is visibly
                    // 2D without pulling in libm.
                    let span_x = info.width.saturating_sub(s);
                    let span_y = info.height.saturating_sub(s);
                    let x = tri_wave(frame, 120, span_x);
                    let y = tri_wave(frame.wrapping_add(30), 90, span_y);
                    while fb.fill(x, y, s, s, 0xFFFFD700).is_err() {
                        rt::yield_now();
                    }
                    while fb.flush(0, 0, info.width, info.height).is_err() {
                        rt::yield_now();
                    }
                    rt::nanosleep(FRAME_NS);
                    if frame == FRAMES - 1 { all_ok = true; }
                }
                all_ok
            }
        }
        Err(_) => false,
    };
    rt::print_str(if fb_ok { "fb: ok\n" } else { "fb: bad\n" });

    // ── /dev/fb0 probe ──────────────────────────────────────────────
    // Prints "fb0: ok <W>x<H>" on success, "fb0: bad ..." on failure.
    probe_dev_fb0();
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop { core::hint::spin_loop(); }
}
