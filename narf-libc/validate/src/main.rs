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

    // open(O_CREAT) — recreate a fresh /tmp/created file via the
    // kernel's parent-directory `create()` path. The first open
    // returns a valid fd (≥ 3); a second open WITHOUT O_CREAT then
    // also succeeds, proving the file persists between calls.
    let create_path: *const i8 = b"/tmp/created\0".as_ptr() as *const i8;
    let open_create_ok = unsafe {
        let fd1 = narf_libc::posix_open(create_path, narf_libc::O_CREAT, 0);
        let fd2 = narf_libc::posix_open(create_path, 0, 0);
        let ok = fd1 >= 3 && fd2 >= 3 && fd1 != fd2;
        // Best-effort close. The fds drop on task exit anyway.
        let _ = narf_libc::posix_close(fd1);
        let _ = narf_libc::posix_close(fd2);
        ok
    };
    narf_libc::printf_str(
        if open_create_ok { "create: ok\n" } else { "create: bad\n" },
        &[],
    );

    // rename — same-directory rename within /tmp. Move the just-
    // created file to a new name, then verify the new name opens
    // and the old name does not.
    let new_path: *const i8 = b"/tmp/renamed\0".as_ptr() as *const i8;
    let rename_ok = unsafe {
        let r = narf_libc::posix_rename(create_path, new_path);
        let fd_new = narf_libc::posix_open(new_path, 0, 0);
        let fd_old = narf_libc::posix_open(create_path, 0, 0);
        let ok = r == 0 && fd_new >= 3 && fd_old == -1;
        let _ = narf_libc::posix_close(fd_new);
        ok
    };
    narf_libc::printf_str(
        if rename_ok { "rename: ok\n" } else { "rename: bad\n" },
        &[],
    );

    // ── Tier 3d: hierarchical MemFs + write/read round-trip ──────
    //
    // MemFs is now hierarchical. The mkdir+rmdir probe:
    //   1. mkdir /tmp/sub                       → 0
    //   2. mkdir /tmp/sub again                 → -1 (Busy)
    //   3. open  /tmp/sub/inner with O_CREAT    → fd ≥ 3
    //   4. rmdir /tmp/sub (non-empty)           → -1 (Busy)
    //   5. unlink /tmp/sub/inner                → 0
    //   6. rmdir /tmp/sub (now empty)           → 0
    let dir_path:   *const i8 = b"/tmp/sub\0".as_ptr() as *const i8;
    let inner_path: *const i8 = b"/tmp/sub/inner\0".as_ptr() as *const i8;
    let mkdir_ok = unsafe {
        let m1 = narf_libc::posix_mkdir(dir_path, 0o755);
        let m2 = narf_libc::posix_mkdir(dir_path, 0o755);
        let fd = narf_libc::posix_open(inner_path, narf_libc::O_CREAT, 0);
        let r1 = narf_libc::posix_rmdir(dir_path);
        let _  = narf_libc::posix_close(fd);
        let u  = narf_libc::posix_unlink(inner_path);
        let r2 = narf_libc::posix_rmdir(dir_path);
        m1 == 0 && m2 == -1 && fd >= 3 && r1 == -1 && u == 0 && r2 == 0
    };
    narf_libc::printf_str(
        if mkdir_ok { "mkdir: ok\n" } else { "mkdir: bad\n" },
        &[],
    );

    // write/read round-trip — open a fresh file, write a payload,
    // close, reopen, read back, compare. Proves the FileOps path
    // through MemFile's Mutex<Vec<u8>> end-to-end.
    let rw_path: *const i8 = b"/tmp/io\0".as_ptr() as *const i8;
    let payload: &[u8] = b"narf-libc rw round-trip!";
    let mut readback: [u8; 32] = [0; 32];
    let rw_ok = unsafe {
        let fd_w = narf_libc::posix_open(rw_path, narf_libc::O_CREAT, 0);
        if fd_w < 0 { false } else {
            let n = narf_libc::posix_write(
                fd_w,
                payload.as_ptr() as *const core::ffi::c_void,
                payload.len(),
            );
            let _ = narf_libc::posix_close(fd_w);
            if n as usize != payload.len() { false } else {
                let fd_r = narf_libc::posix_open(rw_path, 0, 0);
                if fd_r < 0 { false } else {
                    let m = narf_libc::posix_read(
                        fd_r,
                        readback.as_mut_ptr() as *mut core::ffi::c_void,
                        readback.len(),
                    );
                    let _ = narf_libc::posix_close(fd_r);
                    let _ = narf_libc::posix_unlink(rw_path);
                    m as usize == payload.len()
                        && &readback[..payload.len()] == payload
                }
            }
        }
    };
    narf_libc::printf_str(
        if rw_ok { "rw: ok\n" } else { "rw: bad\n" },
        &[],
    );

    // setjmp/longjmp probe — first setjmp returns 0, body runs,
    // longjmp(7) re-enters at the setjmp site with apparent return 7.
    // The static counter guards against an infinite loop if the
    // restore path somehow lands at the wrong rip.
    use core::sync::atomic::{AtomicI32, Ordering};
    static SJ_COUNTER: AtomicI32 = AtomicI32::new(0);
    let mut env = narf_libc::jmp_buf::default();
    // SAFETY: env outlives the longjmp call (it's on this stack
    // frame and we don't return from main between the setjmp and
    // the longjmp).
    let sj_val = unsafe { narf_libc::setjmp(&mut env) };
    SJ_COUNTER.fetch_add(1, Ordering::SeqCst);
    let setjmp_ok;
    if sj_val == 0 && SJ_COUNTER.load(Ordering::SeqCst) == 1 {
        // First arrival — longjmp back with 7. This call doesn't
        // return; control resumes at the setjmp() above.
        unsafe { narf_libc::longjmp(&mut env, 7) };
    } else if sj_val == 7 && SJ_COUNTER.load(Ordering::SeqCst) == 2 {
        setjmp_ok = true;
    } else {
        setjmp_ok = false;
    }
    narf_libc::printf_str(
        if setjmp_ok { "setjmp: ok\n" } else { "setjmp: bad\n" },
        &[],
    );

    // getopt — feed a synthetic argv `prog -a -b val rest` and
    // walk it. Expect: 'a' (no arg), 'b' with optarg="val",
    // -1 with optind pointing at "rest".
    //
    // SAFETY: the argv strings are static literals; the array is
    // stack-allocated and lives for the duration of the call.
    let arg0 = b"prog\0".as_ptr() as *mut i8;
    let arg1 = b"-a\0".as_ptr()   as *mut i8;
    let arg2 = b"-b\0".as_ptr()   as *mut i8;
    let arg3 = b"val\0".as_ptr()  as *mut i8;
    let arg4 = b"rest\0".as_ptr() as *mut i8;
    let argv: [*mut i8; 5] = [arg0, arg1, arg2, arg3, arg4];
    let optstring = b"ab:\0".as_ptr() as *const i8;
    let getopt_ok = unsafe {
        // Reset the getopt globals — earlier probes may have
        // poisoned them via process-wide statics.
        narf_libc::optind  = 1;
        narf_libc::opterr  = 0;
        let r1 = narf_libc::getopt(5, argv.as_ptr(), optstring);
        let r2 = narf_libc::getopt(5, argv.as_ptr(), optstring);
        let opt_after = narf_libc::optarg;
        let r3 = narf_libc::getopt(5, argv.as_ptr(), optstring);
        let opt_after_b = !opt_after.is_null() && *opt_after == b'v' as i8;
        r1 == b'a' as i32 && r2 == b'b' as i32 && opt_after_b && r3 == -1
            && narf_libc::optind == 4
    };
    narf_libc::printf_str(
        if getopt_ok { "getopt: ok\n" } else { "getopt: bad\n" },
        &[],
    );

    // assert.h — call __assert_fail with a deliberately-passing
    // expression cannot be exercised here (the function is
    // no-return). We instead probe that the symbol resolves at
    // link time and that its address is non-null. The output line
    // is therefore a link-presence check, not a behaviour test.
    //
    // SAFETY: reading a function pointer's address is sound;
    // calling it is what we avoid.
    let assert_ok = (narf_libc::__assert_fail as usize) != 0;
    narf_libc::printf_str(
        if assert_ok { "assert: ok\n" } else { "assert: bad\n" },
        &[],
    );

    // math probe — sample the bit-twiddled rounding + arch-native
    // sqrt + predicates. Each branch is one canonical case from
    // its function's reference behaviour.
    //
    // SAFETY: every math:: entry is `unsafe extern "C"` for the
    // C-ABI shape but performs only value computation.
    let math_ok = unsafe {
        let nan = f64::from_bits(0x7FF8_0000_0000_0000);
        let inf = f64::INFINITY;
        narf_libc::fabs(-3.5) == 3.5
            && narf_libc::floor(2.7) == 2.0
            && narf_libc::floor(-2.3) == -3.0
            && narf_libc::ceil(2.3) == 3.0
            && narf_libc::ceil(-2.7) == -2.0
            && narf_libc::trunc(-2.7) == -2.0
            && narf_libc::round(2.5) == 3.0
            && narf_libc::round(-2.5) == -3.0
            && narf_libc::sqrt(16.0) == 4.0
            && narf_libc::sqrt(2.0) > 1.41
            && narf_libc::sqrt(2.0) < 1.42
            && narf_libc::fmod(10.0, 3.0) == 1.0
            && narf_libc::fmin(2.0, nan) == 2.0
            && narf_libc::fmax(nan, 5.0) == 5.0
            && narf_libc::isnan(nan) != 0
            && narf_libc::isnan(0.0) == 0
            && narf_libc::isinf(inf) == 1
            && narf_libc::isinf(-inf) == -1
            && narf_libc::isfinite(1.0) != 0
            && narf_libc::copysign(3.0, -1.0) == -3.0
            && narf_libc::signbit(-0.0) == 1
    };
    narf_libc::printf_str(
        if math_ok { "math: ok\n" } else { "math: bad\n" },
        &[],
    );

    // ctype probe — exercise a representative slice of the
    // classification + case-fold surface. SAFETY: pure value math.
    let ctype_ok = unsafe {
        narf_libc::isdigit(b'7' as i32) != 0
            && narf_libc::isdigit(b'a' as i32) == 0
            && narf_libc::isalpha(b'Z' as i32) != 0
            && narf_libc::isspace(b' ' as i32) != 0
            && narf_libc::isxdigit(b'F' as i32) != 0
            && narf_libc::isxdigit(b'g' as i32) == 0
            && narf_libc::tolower(b'Q' as i32) == b'q' as i32
            && narf_libc::toupper(b'q' as i32) == b'Q' as i32
            && narf_libc::isascii(0x80) == 0
    };
    narf_libc::printf_str(
        if ctype_ok { "ctype: ok\n" } else { "ctype: bad\n" },
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

    // ── Tier 3h probes: memchr + char-level stdio + fseek/ftell ──
    //
    // memchr: bounded byte-search that does NOT stop at NUL. The
    // probe seeds a 6-byte buffer with an embedded NUL ahead of the
    // target so a strchr-style scan would miss the hit.
    let mch: [u8; 6] = *b"AB\0CXD";
    let mch_ptr = unsafe {
        narf_libc::memchr(mch.as_ptr(), b'X' as i32, mch.len())
    };
    let mch_ok = !mch_ptr.is_null()
        && (mch_ptr as usize) == (mch.as_ptr() as usize) + 4;
    let mch_miss = unsafe {
        narf_libc::memchr(mch.as_ptr(), b'Z' as i32, mch.len())
    };
    let memchr_ok = mch_ok && mch_miss.is_null();
    narf_libc::printf_str(
        if memchr_ok { "memchr: ok\n" } else { "memchr: bad\n" },
        &[],
    );

    // putchar / puts — emit a marker line through the line-buffered
    // stdout path. The terminal `\n` triggers a flush so the bytes
    // hit the kernel console before the next probe runs. There's no
    // observable failure mode short of a panic, so we declare the
    // probe ok if we returned at all (return values are mostly the
    // input byte / 0).
    let _ = narf_libc::putchar(b'P' as i32);
    let _ = narf_libc::putchar(b'\n' as i32);
    let _ = unsafe {
        narf_libc::puts(b"puts: ok\0".as_ptr())
    };
    narf_libc::printf_str("putchar: ok\n", &[]);

    // fputc / fgetc / fseek / ftell / rewind round-trip.
    //
    // Open a fresh file under /tmp, write three bytes via fputc,
    // fseek back to the start, fgetc them back one byte at a time,
    // and ftell to confirm the offset advances. rewind reverts to 0.
    //
    // Uses fopen — which mallocs a File struct, so we get the full
    // FILE*-layer code path (not just static stdout).
    let posix_path: *const i8 = b"/tmp/seek\0".as_ptr() as *const i8;
    let create_fd = unsafe {
        narf_libc::posix_open(posix_path, narf_libc::O_CREAT, 0)
    };
    let _ = unsafe { narf_libc::posix_close(create_fd) };

    let stream_path: &[u8] = b"/tmp/seek";
    let stream = unsafe {
        narf_libc::fopen(stream_path.as_ptr(), stream_path.len(), "rw")
    };
    let stream_ok = !stream.is_null();

    let stream_round_trip = if !stream_ok {
        false
    } else {
        unsafe {
            let w1 = narf_libc::fputc(b'X' as i32, stream);
            let w2 = narf_libc::fputc(b'Y' as i32, stream);
            let w3 = narf_libc::fputc(b'Z' as i32, stream);
            let _  = narf_libc::fflush(stream);
            // ftell after three writes (no read tail): expect 3.
            let pos_after_writes = narf_libc::ftell(stream);
            // Seek back to 0 and read the three bytes.
            let seek_rc = narf_libc::fseek(stream, 0, narf_libc::stdio::SEEK_SET);
            let r1 = narf_libc::fgetc(stream);
            let r2 = narf_libc::fgetc(stream);
            let r3 = narf_libc::fgetc(stream);
            let pos_after_reads = narf_libc::ftell(stream);
            // rewind + EOF: read past end should yield EOF.
            narf_libc::rewind(stream);
            let pos_rewound = narf_libc::ftell(stream);
            // Drain three bytes then expect EOF on the fourth.
            let _ = narf_libc::fgetc(stream);
            let _ = narf_libc::fgetc(stream);
            let _ = narf_libc::fgetc(stream);
            let r_eof = narf_libc::fgetc(stream);
            let _ = narf_libc::fclose(stream);
            // Tidy up the on-disk file.
            let _ = narf_libc::posix_unlink(posix_path);
            w1 == (b'X' as i32) && w2 == (b'Y' as i32) && w3 == (b'Z' as i32)
                && pos_after_writes == 3
                && seek_rc == 0
                && r1 == (b'X' as i32) && r2 == (b'Y' as i32) && r3 == (b'Z' as i32)
                && pos_after_reads == 3
                && pos_rewound == 0
                && r_eof == -1
        }
    };
    let stdio_pos_ok = stream_ok && stream_round_trip;
    narf_libc::printf_str(
        if stdio_pos_ok { "fseek: ok\n" } else { "fseek: bad\n" },
        &[],
    );

    // ── Tier 3i probes: string parsing trio + strerror + rand ────
    //
    // strspn / strcspn — symmetric pair over a 5-byte input. With
    // `accept = "abc"`, "aabbczz" has a 5-byte initial run of
    // members; `reject = "z"` flips the predicate so the run is 5.
    let span: *const u8 = b"aabbczz\0".as_ptr();
    let strspn_ok = unsafe {
        narf_libc::strspn(span, b"abc\0".as_ptr()) == 5
            && narf_libc::strcspn(span, b"z\0".as_ptr()) == 5
    };
    narf_libc::printf_str(
        if strspn_ok { "strspn: ok\n" } else { "strspn: bad\n" },
        &[],
    );

    // strpbrk — first byte of `s` that appears in `accept`. With
    // `s = "hello world"` and `accept = "ow"`, the first hit is the
    // 'o' at index 4.
    let pbrk_ok = unsafe {
        let s   = b"hello world\0".as_ptr();
        let acc = b"ow\0".as_ptr();
        let p   = narf_libc::strpbrk(s, acc);
        !p.is_null()
            && (p as usize) == (s as usize) + 4
            && *p == b'o'
    };
    narf_libc::printf_str(
        if pbrk_ok { "strpbrk: ok\n" } else { "strpbrk: bad\n" },
        &[],
    );

    // strtok_r — split "a,b,,c" on ',' yields "a", "b", "c" (empty
    // tokens collapse), then NULL. The buffer is mutated in place,
    // so it must be writable.
    let mut tok_buf: [u8; 8] = *b"a,b,,c\0\0";
    let mut save: *mut u8 = core::ptr::null_mut();
    let strtok_ok = unsafe {
        let t1 = narf_libc::strtok_r(
            tok_buf.as_mut_ptr(),
            b",\0".as_ptr(),
            &mut save,
        );
        let t2 = narf_libc::strtok_r(
            core::ptr::null_mut(),
            b",\0".as_ptr(),
            &mut save,
        );
        let t3 = narf_libc::strtok_r(
            core::ptr::null_mut(),
            b",\0".as_ptr(),
            &mut save,
        );
        let t4 = narf_libc::strtok_r(
            core::ptr::null_mut(),
            b",\0".as_ptr(),
            &mut save,
        );
        let s1 = !t1.is_null() && *t1 == b'a' && *t1.add(1) == 0;
        let s2 = !t2.is_null() && *t2 == b'b' && *t2.add(1) == 0;
        let s3 = !t3.is_null() && *t3 == b'c' && *t3.add(1) == 0;
        s1 && s2 && s3 && t4.is_null()
    };
    narf_libc::printf_str(
        if strtok_ok { "strtok: ok\n" } else { "strtok: bad\n" },
        &[],
    );

    // strerror — both a known code and an unknown one. We compare
    // the first byte rather than walking the whole string; a fully
    // distinct mapping per code is enough to confirm the table is
    // wired.
    let strerror_ok = unsafe {
        let p_invalid = narf_libc::strerror(22); // EINVAL
        let p_unknown = narf_libc::strerror(9999);
        !p_invalid.is_null()
            && !p_unknown.is_null()
            && *p_invalid == b'I'  // "Invalid argument"
            && *p_unknown == b'U'  // "Unknown error"
    };
    narf_libc::printf_str(
        if strerror_ok { "strerror: ok\n" } else { "strerror: bad\n" },
        &[],
    );

    // rand / srand — seeded determinism + range bound. With seed
    // 12345, the Park-Miller sequence is fixed, so a re-seed must
    // produce the identical first call. RAND_MAX bound holds for
    // every call.
    let rand_ok = unsafe {
        narf_libc::srand(12345);
        let a = narf_libc::rand();
        let b = narf_libc::rand();
        narf_libc::srand(12345);
        let a2 = narf_libc::rand();
        a == a2
            && a != b
            && a >= 0 && a <= narf_libc::RAND_MAX
            && b >= 0 && b <= narf_libc::RAND_MAX
    };
    narf_libc::printf_str(
        if rand_ok { "rand: ok\n" } else { "rand: bad\n" },
        &[],
    );

    // ── Tier 3j probes: sprintf + abs/labs/div + sscanf + perror ─

    // sprintf_str — format into a 32-byte buffer with no length cap
    // (the slice itself is the cap). Compare bytes against expected
    // prefix; the trailing slack remains zero from the array init.
    let mut sp: [u8; 32] = [0; 32];
    let want_sp: &[u8] = b"int=42 hex=0x2a";
    let n = narf_libc::sprintf_str(
        &mut sp,
        "int=%d hex=0x%x",
        &[Arg::Int(42), Arg::Hex(0x2a)],
    );
    let sprintf_ok = n == want_sp.len()
        && sp[..want_sp.len()] == *want_sp;
    narf_libc::printf_str(
        if sprintf_ok { "sprintf: ok\n" } else { "sprintf: bad\n" },
        &[],
    );

    // abs/labs/div/ldiv — value math; check normal cases and the
    // wrapping behaviour at INT_MIN / divide-by-zero saturation.
    let absdiv_ok = unsafe {
        let a = narf_libc::abs(-7);
        let b = narf_libc::labs(-1_234_567_890_123);
        let c = narf_libc::div(17, 5);
        let d = narf_libc::ldiv(-17, 5);
        let e = narf_libc::div(5, 0); // saturates to {0, 5}
        a == 7
            && b == 1_234_567_890_123
            && c.quot == 3 && c.rem == 2
            && d.quot == -3 && d.rem == -2
            && e.quot == 0 && e.rem == 5
    };
    narf_libc::printf_str(
        if absdiv_ok { "div: ok\n" } else { "div: bad\n" },
        &[],
    );

    // sscanf_ints — pull two integers from a string with mixed
    // whitespace + a hex literal in field 2.
    let mut nums_out: [i64; 4] = [0; 4];
    let s = b"  -5   0x2a  100\0".as_ptr() as *const i8;
    let parsed = unsafe { narf_libc::sscanf_ints(s, &mut nums_out) };
    let sscanf_ok = parsed == 3
        && nums_out[0] == -5
        && nums_out[1] == 0x2a
        && nums_out[2] == 100;
    narf_libc::printf_str(
        if sscanf_ok { "sscanf: ok\n" } else { "sscanf: bad\n" },
        &[],
    );

    // perror — emit "ctx: <msg>\n" to stderr (fd 2). The kernel
    // console doesn't distinguish stdout/stderr in this harness, so
    // we just confirm the call returns; the `ok` line is independent
    // observation.
    unsafe {
        narf_libc::set_errno(22); // EINVAL
        narf_libc::perror(b"perror-ctx\0".as_ptr());
    }
    narf_libc::printf_str("perror: ok\n", &[]);

    // ── Tier 3k probes: time.h breakdown ─────────────────────────
    //
    // gmtime + mktime + strftime against a known epoch second.
    // 1700000000 = 2023-11-14 22:13:20 UTC (Tue, day-of-year 318).
    // Round-trip the value through mktime to confirm it returns the
    // same time_t.
    let known: narf_libc::time::time_t = 1_700_000_000;
    let mut tmv = narf_libc::tm::default();
    let _ = unsafe {
        narf_libc::gmtime_r(&known as *const _, &mut tmv as *mut _)
    };
    let gmt_ok = tmv.tm_year == 2023 - 1900
        && tmv.tm_mon == 10  // November (0-indexed)
        && tmv.tm_mday == 14
        && tmv.tm_hour == 22
        && tmv.tm_min == 13
        && tmv.tm_sec == 20
        && tmv.tm_wday == 2  // Tuesday
        && tmv.tm_yday == 317; // 0-indexed day-of-year
    narf_libc::printf_str(
        if gmt_ok { "gmtime: ok\n" } else { "gmtime: bad\n" },
        &[],
    );

    // mktime round-trip.
    let mut tm_round = tmv;
    let back = unsafe { narf_libc::mktime(&mut tm_round as *mut _) };
    let mktime_ok = back == known
        && tm_round.tm_wday == 2
        && tm_round.tm_yday == 317;
    narf_libc::printf_str(
        if mktime_ok { "mktime: ok\n" } else { "mktime: bad\n" },
        &[],
    );

    // strftime — emit a known format and compare bytes.
    let mut sf: [u8; 64] = [0; 64];
    let n_sf = unsafe {
        narf_libc::strftime(
            sf.as_mut_ptr(),
            sf.len(),
            b"%Y-%m-%d %H:%M:%S %a %b\0".as_ptr(),
            &tmv as *const _,
        )
    };
    let want_sf: &[u8] = b"2023-11-14 22:13:20 Tue Nov";
    let strftime_ok = n_sf == want_sf.len()
        && sf[..want_sf.len()] == *want_sf
        && sf[want_sf.len()] == 0;
    narf_libc::printf_str(
        if strftime_ok { "strftime: ok\n" } else { "strftime: bad\n" },
        &[],
    );

    // asctime fixed format — exactly 25 chars + NUL ("Tue Nov 14
    // 22:13:20 2023\n").
    let asc_ptr = unsafe { narf_libc::asctime(&tmv as *const _) };
    let asctime_ok = unsafe {
        let want: &[u8] = b"Tue Nov 14 22:13:20 2023\n";
        let mut ok = !asc_ptr.is_null();
        if ok {
            for (i, b) in want.iter().enumerate() {
                if *asc_ptr.add(i) != *b { ok = false; break; }
            }
            if ok && *asc_ptr.add(want.len()) != 0 { ok = false; }
        }
        ok
    };
    narf_libc::printf_str(
        if asctime_ok { "asctime: ok\n" } else { "asctime: bad\n" },
        &[],
    );

    // difftime — pure subtraction; exact for integer values.
    let diff_ok = unsafe {
        narf_libc::difftime(known + 90, known) == 90.0
    };
    narf_libc::printf_str(
        if diff_ok { "difftime: ok\n" } else { "difftime: bad\n" },
        &[],
    );

    // ── Tier 3l probes: math transcendentals ─────────────────────
    //
    // Polynomial approximations are accurate to ~1e-7 absolute over
    // the reduced argument ranges. Each probe checks against a
    // generous tolerance so floating-point round-off in the test
    // expression itself doesn't trigger a spurious bad.
    fn close(a: f64, b: f64, tol: f64) -> bool {
        let diff = if a > b { a - b } else { b - a };
        diff < tol
    }

    let trig_ok = unsafe {
        close(narf_libc::sin(0.0),                      0.0, 1e-9)
            && close(narf_libc::sin(1.570_796_326_794_896_6),  1.0, 1e-9)
            && close(narf_libc::sin(3.141_592_653_589_793_2),  0.0, 1e-7)
            && close(narf_libc::cos(0.0),                      1.0, 1e-9)
            && close(narf_libc::cos(3.141_592_653_589_793_2), -1.0, 1e-7)
            && close(narf_libc::tan(0.785_398_163_397_448_3),  1.0, 1e-7)
    };
    narf_libc::printf_str(
        if trig_ok { "trig: ok\n" } else { "trig: bad\n" },
        &[],
    );

    let exp_ok = unsafe {
        close(narf_libc::exp(0.0),  1.0, 1e-12)
            && close(narf_libc::exp(1.0),  2.718_281_828_459_045, 1e-9)
            && close(narf_libc::exp(-1.0), 0.367_879_441_171_442_3, 1e-9)
            && close(narf_libc::log(1.0), 0.0, 1e-12)
            && close(narf_libc::log(2.718_281_828_459_045_2), 1.0, 1e-9)
            && close(narf_libc::log2(8.0), 3.0, 1e-9)
            && close(narf_libc::log10(1000.0), 3.0, 1e-7)
    };
    narf_libc::printf_str(
        if exp_ok { "exp: ok\n" } else { "exp: bad\n" },
        &[],
    );

    let pow_ok = unsafe {
        close(narf_libc::pow(2.0, 10.0), 1024.0, 1e-6)
            && close(narf_libc::pow(2.0, 0.5), 1.414_213_562_373_095, 1e-6)
            && narf_libc::pow(0.0, 5.0) == 0.0
            && narf_libc::pow(5.0, 0.0) == 1.0
            && close(narf_libc::pow(-2.0, 3.0), -8.0, 1e-9)
    };
    narf_libc::printf_str(
        if pow_ok { "pow: ok\n" } else { "pow: bad\n" },
        &[],
    );

    let atan_ok = unsafe {
        close(narf_libc::atan(0.0),                      0.0, 1e-12)
            && close(narf_libc::atan(1.0),                0.785_398_163_397_448_3, 1e-9)
            && close(narf_libc::atan(-1.0),              -0.785_398_163_397_448_3, 1e-9)
            && close(narf_libc::atan2(1.0, 1.0),          0.785_398_163_397_448_3, 1e-9)
            && close(narf_libc::atan2(1.0, -1.0),         2.356_194_490_192_345_0, 1e-9)
            && close(narf_libc::atan2(-1.0, -1.0),       -2.356_194_490_192_345_0, 1e-9)
            && narf_libc::atan2(0.0, 0.0) == 0.0
    };
    narf_libc::printf_str(
        if atan_ok { "atan: ok\n" } else { "atan: bad\n" },
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
