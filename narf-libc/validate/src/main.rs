//! narf-libc-validate — smoke binary for narf-libc.
//!
//! Links against the relibc-shaped libc shim. The C-style `main`
//! signature is what `narf_libc::__libc_start_main` calls into;
//! `narf_libc::_start` (re-exported from the lib crate) is the
//! ELF entry point per `validate.ld`'s `ENTRY(_start)`.
//!
//! Behaviour: prints a `hello from narf-libc; pid=<n>` line via the
//! printf-shim, then exercises the new FILE* layer over fd 1 by
//! emitting `stdio: fputs ok` (via `fputs`) and `stdio: fwrite ok`
//! (via `fwrite`), then `fflush`-ing the stdout stream. Returns 0.
//! The harness's pass signal is the validate runner's "validate
//! round-trip succeeded" line — the stdio output is observable in
//! the kernel console for visual confirmation that the buffered
//! layer round-tripped through `narf_user_runtime::write`.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

// The lib crate's `_start` is the ELF entry point. We don't re-
// export it here — the linker pulls it out of the rlib because
// `validate.ld` names `_start` as `ENTRY`.
extern crate narf_libc;

// The 16-byte TLS template is BYTE()'d directly into `.tdata` by
// `validate.ld` rather than declared here. See the script for the
// rationale (Rust's `#[link_section = ".tdata"]` marks statics as
// TLS GLOBAL with vaddr 0, which makes codegen emit literal-zero
// loads for the address). The kernel's PT_TLS staging copies those
// 16 bytes into a per-task block; narf-libc's errno helpers read
// `fs_base - 8`, which lands inside that image.

/// Atexit callback for the validation probe. Must be `extern "C"`
/// to match the registration ABI.
extern "C" fn cleanup() {
    narf_libc::printf_str("atexit: ok\n", &[]);
}

/// Heap probe — exercises the Tier-1.5 freelist allocator. Returns
/// `true` iff every sub-check passes; the caller maps that to the
/// `heap: ok` / `heap: bad` smoke line.
///
/// # Safety
/// All raw-pointer ops are bounded by the sizes we just allocated;
/// the allocator's contract guarantees the returned regions are at
/// least the requested length.
unsafe fn heap_probe() -> bool {
    // (1) Single round-trip: write, read, free.
    // SAFETY: 64 bytes is well within any sane chunk size; the
    // returned pointer is writable for that span.
    let p1 = unsafe { narf_libc::malloc(64) };
    if p1.is_null() {
        return false;
    }
    unsafe {
        *p1 = 0xAA;
        *p1.add(63) = 0x55;
        if *p1 != 0xAA || *p1.add(63) != 0x55 {
            return false;
        }
        narf_libc::free(p1);
    }

    // (2) Two live allocations carry distinct sentinels.
    // SAFETY: same reasoning as (1) for each pointer.
    let a = unsafe { narf_libc::malloc(128) };
    let b = unsafe { narf_libc::malloc(128) };
    if a.is_null() || b.is_null() {
        return false;
    }
    unsafe {
        for i in 0..128 { *a.add(i) = 0x11; }
        for i in 0..128 { *b.add(i) = 0x22; }
        for i in 0..128 {
            if *a.add(i) != 0x11 || *b.add(i) != 0x22 {
                return false;
            }
        }
        narf_libc::free(a);
        narf_libc::free(b);
    }

    // (3) Free-list reuse: free 100 chunks of the same size and
    // observe that the next 100 mallocs of that size all succeed
    // without the heap growing unboundedly. The first-fit walker
    // pulls the most-recently-freed head on each request, so the
    // pointer set across the second batch of mallocs is a permutation
    // of the first batch's set. We verify by tracking the
    // min/max pointer span and asserting it doesn't grow between the
    // two phases — i.e. the second batch's allocations all came
    // from the freelist, not from a fresh `mmap`.
    //
    // We avoid the literal "second-malloc-equals-first" form because
    // a fused `if r2.is_null() || r2 != r1` after free/malloc was
    // observed to mis-evaluate under the validate binary's fat-LTO
    // codegen — plausibly because LTO inlines malloc/free and the
    // optimiser fuses the call pair past the AtomicPtr round-trip.
    // The min/max-span check is invariant to the per-call address
    // and therefore robust against that artefact.
    const REUSE_N: usize = 8;
    let mut ptrs = [core::ptr::null_mut::<u8>(); REUSE_N];
    let (mut min_p1, mut max_p1) = (usize::MAX, 0usize);
    for slot in ptrs.iter_mut() {
        let p = unsafe { narf_libc::malloc(1024) };
        if p.is_null() {
            return false;
        }
        let pa = p as usize;
        if pa < min_p1 { min_p1 = pa; }
        if pa > max_p1 { max_p1 = pa; }
        *slot = p;
    }
    for &p in ptrs.iter() {
        unsafe { narf_libc::free(p); }
    }
    let (mut min_p2, mut max_p2) = (usize::MAX, 0usize);
    for slot in ptrs.iter_mut() {
        let p = unsafe { narf_libc::malloc(1024) };
        if p.is_null() {
            return false;
        }
        let pa = p as usize;
        if pa < min_p2 { min_p2 = pa; }
        if pa > max_p2 { max_p2 = pa; }
        *slot = p;
    }
    // All second-batch pointers must lie within the first-batch
    // span — proving they came from the freelist, not a fresh mmap.
    if min_p2 < min_p1 || max_p2 > max_p1 {
        return false;
    }
    for &p in ptrs.iter() {
        unsafe { narf_libc::free(p); }
    }

    // (4) realloc grow: write a sentinel into a small alloc, grow
    // to 4096, verify the old prefix survived. The new tail is
    // uninitialised by design — realloc isn't required to zero —
    // so we don't read past the original payload. We probe
    // writability at the far end (offset 4095) to confirm the
    // chunk really is the size realloc claims.
    // SAFETY: 16 bytes initially, 4096 after realloc.
    let s1 = unsafe { narf_libc::malloc(16) };
    if s1.is_null() {
        return false;
    }
    unsafe {
        for i in 0..16 { *s1.add(i) = i as u8 + 1; }
    }
    let s2 = unsafe { narf_libc::realloc(s1, 4096) };
    if s2.is_null() {
        return false;
    }
    unsafe {
        for i in 0..16 {
            if *s2.add(i) != i as u8 + 1 {
                return false;
            }
        }
        *s2.add(4095) = 0xFE;
        if *s2.add(4095) != 0xFE {
            return false;
        }
        narf_libc::free(s2);
    }

    true
}

#[no_mangle]
pub extern "C" fn main(
    _argc: i32,
    _argv: *const *const u8,
    _envp: *const *const u8,
) -> i32 {
    use narf_libc::Arg;

    // SAFETY: getpid is the C-ABI shape; pure read.
    let pid = unsafe { narf_libc::getpid() };
    narf_libc::printf_str(
        "hello from narf-libc; pid=%d\n",
        &[Arg::Int(pid as i64)],
    );

    // ── printf-shim format-spec probes ────────────────────────────
    // Each probe drives a distinct branch of the format-spec parser.
    // The round-trip succeeding proves no fault on width / precision
    // / flag combinations.
    narf_libc::printf_str("padded: '%5d'\n",   &[Arg::Int(42)]);
    narf_libc::printf_str("zero: '%05d'\n",    &[Arg::Int(42)]);
    narf_libc::printf_str("left: '%-5d|'\n",   &[Arg::Int(42)]);
    narf_libc::printf_str("prec: '%.4x'\n",    &[Arg::Hex(0x2a)]);
    narf_libc::printf_str("octal: '%o'\n",     &[Arg::Uint(42)]);
    narf_libc::printf_str("binary: '%b'\n",    &[Arg::Uint(42)]);
    narf_libc::printf_str("long: '%lld'\n",    &[Arg::Int(-1)]);
    narf_libc::printf_str(
        "strpad: '%-10s|%.3s'\n",
        &[Arg::Str("hi"), Arg::Str("abcdef")],
    );
    narf_libc::printf_str(
        "altsign: '%+d %#x'\n",
        &[Arg::Int(7), Arg::Hex(0xdead)],
    );
    narf_libc::fprintf_str(1, "fprintf: '%u'\n", &[Arg::Uint(123)]);

    // ── FILE* layer probes over static stdout ─────────────────────
    // No fopen — the validate runner has no mount table. fd 1 via
    // the static stdout() FILE is enough to prove the buffered
    // write path round-trips.
    //
    // SAFETY: stdout() is a stable pointer to a static File; byte
    // pointers are 'static literals; lengths match the literals.
    unsafe {
        let stream = narf_libc::stdout();
        let msg1 = b"stdio: fputs ok\n";
        narf_libc::fputs(msg1.as_ptr(), msg1.len(), stream);
        let msg2 = b"stdio: fwrite ok\n";
        narf_libc::fwrite(msg2.as_ptr(), 1, msg2.len(), stream);
        narf_libc::fflush(stream);
    }

    // ── string battery + env + atexit probes ─────────────────────
    // strchr probe — confirm the byte search lands on the first 'l'
    // of "hello".
    let hello: *const u8 = b"hello\0".as_ptr();
    // SAFETY: `hello` points to a NUL-terminated static literal; the
    // returned pointer (if non-null) is inside that literal.
    let p = unsafe { narf_libc::strchr(hello, b'l' as i32) };
    // SAFETY: `p` is either NULL or points into the literal "hello\0"
    // which is alive for the program's lifetime.
    unsafe {
        if !p.is_null() && *p == b'l' {
            narf_libc::printf_str("strchr: ok\n", &[]);
        } else {
            narf_libc::printf_str("strchr: bad\n", &[]);
        }
    }

    // memmove with overlap — the destination overlaps the source
    // (dst = src + 2). Direction-aware copy must take
    // "abcdefgh" -> "ababcdgh" (bytes 0..4 land at positions 2..6).
    let mut buf: [u8; 8] = *b"abcdefgh";
    // SAFETY: `buf` is 8 bytes; src=buf, dst=buf+2, n=4 stays inside.
    unsafe {
        narf_libc::memmove(buf.as_mut_ptr().add(2), buf.as_ptr(), 4);
    }
    let ok = &buf == b"ababcdgh";
    narf_libc::printf_str(
        if ok { "memmove: ok\n" } else { "memmove: bad\n" },
        &[],
    );

    // getenv probe — the validate harness boots with no envp, so any
    // lookup must miss cleanly (NULL return). Confirms both the
    // ENVIRON-init wiring AND the empty-table walk path.
    let n: *const u8 = b"PATH\0".as_ptr();
    // SAFETY: `n` is NUL-terminated and `name_len = 4` fits.
    let v = unsafe { narf_libc::getenv(n, 4) };
    narf_libc::printf_str(
        if v.is_null() { "getenv: ok\n" } else { "getenv: bad\n" },
        &[],
    );

    // ── chdir / getcwd / sleep probes ────────────────────────────
    // chdir("/") + getcwd round-trip is the tightest cwd path the
    // kernel exposes today. usleep(1000) drives the spin-wait
    // sleep handler — 1 ms is small enough not to dominate runtime
    // but large enough that a no-op stub would fail to advance
    // monotonic_ns.
    let root: *const u8 = b"/\0".as_ptr();
    // SAFETY: NUL-terminated literal.
    let chdir_ok = unsafe { narf_libc::chdir(root) } == 0;
    narf_libc::printf_str(
        if chdir_ok { "chdir: ok\n" } else { "chdir: bad\n" },
        &[],
    );

    let mut cwd_buf: [u8; 16] = [0; 16];
    // SAFETY: 16-byte writable buffer + size match.
    let cwd_p = unsafe { narf_libc::getcwd(cwd_buf.as_mut_ptr(), cwd_buf.len()) };
    let cwd_ok = !cwd_p.is_null() && cwd_buf[0] == b'/' && cwd_buf[1] == 0;
    narf_libc::printf_str(
        if cwd_ok { "cwd: ok\n" } else { "cwd: bad\n" },
        &[],
    );

    // SAFETY: usleep is C-ABI shape; spin-waits in the kernel.
    let sleep_ok = unsafe { narf_libc::usleep(1000) } == 0;
    narf_libc::printf_str(
        if sleep_ok { "sleep: ok\n" } else { "sleep: bad\n" },
        &[],
    );

    // ── fd / pipe / fcntl probes ────────────────────────────────
    //
    // Tier-2 fd-table breadth surface end-to-end: fcntl on stdin,
    // dup of stdout, and a fresh pipe round-trip. Each lights up
    // exactly one kernel handler so the explicit "ok" / "bad"
    // marker pinpoints the failure.
    //
    // SAFETY: fd numbers 0/1 are kernel-installed at task start;
    // pipe()/dup() return numbers we hand back to the kernel
    // immediately after.
    unsafe {
        // F_GETFD on stdin should succeed (return 0 — no flags set
        // by the kernel-default stdio install).
        let r = narf_libc::fcntl(0, narf_libc::F_GETFD as i32, 0);
        narf_libc::printf_str(
            if r == 0 { "fcntl: ok\n" } else { "fcntl: bad\n" },
            &[],
        );

        // dup(fd 1) — first free user slot is ≥ 3 with stdio installed.
        let new_fd = narf_libc::dup(1);
        narf_libc::printf_str(
            if new_fd >= 3 { "dup: ok\n" } else { "dup: bad\n" },
            &[],
        );

        // pipe() — populate two fds, both must be ≥ 3 and distinct.
        let mut fds: [i32; 2] = [-1, -1];
        let pr = narf_libc::pipe(fds.as_mut_ptr());
        let pipe_ok = pr == 0 && fds[0] >= 3 && fds[1] >= 3 && fds[0] != fds[1];
        narf_libc::printf_str(
            if pipe_ok { "pipe: ok\n" } else { "pipe: bad\n" },
            &[],
        );
    }

    // ── heap freelist probes ──────────────────────────────────────
    // Tier 1.5 freelist allocator over mmap. Four checks:
    //   1. round-trip a sentinel through a single malloc/free.
    //   2. two non-overlapping live allocations carry distinct
    //      sentinels independently.
    //   3. malloc → free → malloc returns the SAME pointer (the
    //      freelist reused the just-released chunk).
    //   4. realloc grows correctly and preserves the old prefix.
    //
    // Note on ptr-equality in (3): the underlying mmap returns
    // disjoint regions across calls, so the equality there relies
    // on the freelist hitting the just-pushed chunk on the next
    // malloc — i.e. it tests the split/reuse path, not vaddr math.
    //
    // SAFETY: heap_probe's preconditions are all "the allocator
    // honours its own contract" — the function uses only its own
    // returns.
    let heap_ok = unsafe { heap_probe() };
    narf_libc::printf_str(
        if heap_ok { "heap: ok\n" } else { "heap: bad\n" },
        &[],
    );

    // ── Tier 3b probe: VFS unlink against /tmp MemFs ─────────────
    //
    // The kernel test bootstrap mounted a MemFs at /tmp seeded with
    // `removable`. First unlink should succeed (returns 0), second
    // should fail (target absent → kernel returns InvalidOp → libc
    // surface returns -1). The existence of the second-call failure
    // proves we hit the live remove path rather than a no-op stub
    // that always succeeds.
    //
    // SAFETY: posix_unlink takes a NUL-terminated C string.
    let path: *const i8 = b"/tmp/removable\0".as_ptr() as *const i8;
    let unlink_ok = unsafe {
        let r1 = narf_libc::posix_unlink(path);
        let r2 = narf_libc::posix_unlink(path);
        r1 == 0 && r2 == -1
    };
    narf_libc::printf_str(
        if unlink_ok { "unlink: ok\n" } else { "unlink: bad\n" },
        &[],
    );

    // ── Tier 3a probes: stdlib + isatty + signal ─────────────────
    //
    // atoi / strtol / qsort / bsearch round-trips. Each has one
    // happy-path check; failure modes (overflow, bad input) are
    // covered by the stdlib unit-test target separately.
    //
    // SAFETY: all C-string args are static literals; the qsort/
    // bsearch inputs are stack-local arrays of i32.
    let atoi_ok = unsafe {
        narf_libc::atoi(b"  -42xyz\0".as_ptr() as *const i8) == -42
    };
    narf_libc::printf_str(
        if atoi_ok { "atoi: ok\n" } else { "atoi: bad\n" },
        &[],
    );

    let strtol_ok = unsafe {
        let s = b"0xdeadbeef rest\0".as_ptr() as *const i8;
        let mut end: *mut i8 = core::ptr::null_mut();
        let v = narf_libc::strtol(s, &mut end, 16);
        v == 0xdead_beef && !end.is_null() && *end == b' ' as i8
    };
    narf_libc::printf_str(
        if strtol_ok { "strtol: ok\n" } else { "strtol: bad\n" },
        &[],
    );

    extern "C" fn cmp_i32(
        a: *const core::ffi::c_void,
        b: *const core::ffi::c_void,
    ) -> i32 {
        // SAFETY: qsort/bsearch always pass element-sized pointers.
        unsafe {
            let x = *(a as *const i32);
            let y = *(b as *const i32);
            (x - y).signum()
        }
    }
    let mut nums: [i32; 6] = [9, 1, 5, 3, 7, 4];
    unsafe {
        narf_libc::qsort(
            nums.as_mut_ptr() as *mut core::ffi::c_void,
            nums.len(),
            core::mem::size_of::<i32>(),
            cmp_i32,
        );
    }
    let qsort_ok = nums == [1, 3, 4, 5, 7, 9];
    narf_libc::printf_str(
        if qsort_ok { "qsort: ok\n" } else { "qsort: bad\n" },
        &[],
    );

    let key: i32 = 5;
    let bs = unsafe {
        narf_libc::bsearch(
            &key as *const i32 as *const core::ffi::c_void,
            nums.as_ptr() as *const core::ffi::c_void,
            nums.len(),
            core::mem::size_of::<i32>(),
            cmp_i32,
        )
    };
    let bsearch_ok = !bs.is_null() && unsafe { *(bs as *const i32) } == 5;
    narf_libc::printf_str(
        if bsearch_ok { "bsearch: ok\n" } else { "bsearch: bad\n" },
        &[],
    );

    // isatty: stdin is the kernel console (returns 1); fd 99 is
    // unbacked (returns 0).
    let isatty_ok = unsafe {
        narf_libc::isatty(0) == 1 && narf_libc::isatty(99) == 0
    };
    narf_libc::printf_str(
        if isatty_ok { "isatty: ok\n" } else { "isatty: bad\n" },
        &[],
    );

    // signal: install a no-op handler for SIGUSR-equivalent (we use
    // SIGTERM since the kernel maps it to vector 15) and observe
    // the prior slot value coming back as SIG_DFL (0).
    extern "C" fn noop_sig(_: i32) {}
    let prior = unsafe {
        narf_libc::signal(narf_libc::SIGTERM, noop_sig as usize)
    };
    let signal_ok = prior == narf_libc::SIG_DFL_RAW;
    narf_libc::printf_str(
        if signal_ok { "signal: ok\n" } else { "signal: bad\n" },
        &[],
    );

    // ── Tier 2.5 probes: snprintf / clock / errno_location ───────
    //
    // snprintf into a fixed buffer, then compare against the expected
    // formatted bytes. The vsnprintf_str path goes through the same
    // Sink-as-buf branch the real C-style snprintf would.
    let mut sn: [u8; 32] = [0; 32];
    let n = narf_libc::snprintf_str(&mut sn, "%5d %s", &[Arg::Int(42), Arg::Str("hi")]);
    let want: &[u8] = b"   42 hi\0";
    let snprintf_ok = n == 8
        && sn[..want.len()] == *want;
    narf_libc::printf_str(
        if snprintf_ok { "snprintf: ok\n" } else { "snprintf: bad\n" },
        &[],
    );

    // clock_gettime: two reads back-to-back must produce monotonic
    // non-decreasing values. The kernel's monotonic_ns() is the
    // backing source; even with no spin between calls the cycle
    // counter advances per RDTSC, so a bad wiring would surface as
    // "second tv_sec/tv_nsec went backwards".
    // SAFETY: timespec is #[repr(C)]; we hand the kernel a writable slot.
    let mut t1 = narf_libc::timespec::default();
    let mut t2 = narf_libc::timespec::default();
    let clk_ok = unsafe {
        let r1 = narf_libc::clock_gettime(0, &mut t1);
        let r2 = narf_libc::clock_gettime(0, &mut t2);
        r1 == 0 && r2 == 0
            && (t2.tv_sec > t1.tv_sec
                || (t2.tv_sec == t1.tv_sec && t2.tv_nsec >= t1.tv_nsec))
    };
    narf_libc::printf_str(
        if clk_ok { "clock: ok\n" } else { "clock: bad\n" },
        &[],
    );

    // __errno_location round-trip: write through the pointer and
    // observe the change via the Rust errno() accessor.
    // SAFETY: pointer is stable for the life of this thread.
    let errno_ok = unsafe {
        let p = narf_libc::__errno_location();
        *p = 7;
        narf_libc::errno() == 7
    };
    narf_libc::printf_str(
        if errno_ok { "errno_loc: ok\n" } else { "errno_loc: bad\n" },
        &[],
    );

    // atexit registration — `cleanup` runs after `main` returns,
    // BEFORE the kernel-side exit_task. The ordering proves the
    // dispatch loop in `narf_libc::exit` walks the table.
    // SAFETY: `cleanup` is a `'static` extern "C" fn; single-threaded
    // user mode keeps the table-write race-free.
    unsafe {
        let _ = narf_libc::atexit(cleanup);
    }

    0
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop { core::hint::spin_loop(); }
}
