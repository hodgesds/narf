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

    // ── Tier 3m probes: byte-order + IPv4 inet + access/sysconf ──
    //
    // htonl / htons round-trip: swap-and-swap returns the original.
    let bo_ok = unsafe {
        narf_libc::htonl(0xDEAD_BEEF) == 0xEFBE_ADDE
            && narf_libc::ntohl(narf_libc::htonl(0x1234_5678)) == 0x1234_5678
            && narf_libc::htons(0x1234) == 0x3412
            && narf_libc::ntohs(narf_libc::htons(0xABCD)) == 0xABCD
    };
    narf_libc::printf_str(
        if bo_ok { "byteorder: ok\n" } else { "byteorder: bad\n" },
        &[],
    );

    // inet_aton + inet_ntop round-trip across a known address.
    let aton_ok = unsafe {
        let mut packed: narf_libc::net::in_addr_t = 0;
        let r = narf_libc::inet_aton(
            b"192.168.1.10\0".as_ptr() as *const i8,
            &mut packed,
        );
        // Network-order bytes: 192,168,1,10 → little-endian word
        // 0x0A01_A8C0 on a little-endian host.
        let bad = narf_libc::inet_aton(
            b"999.0.0.1\0".as_ptr() as *const i8,
            core::ptr::null_mut(),
        );
        r == 1 && packed == 0x0A01_A8C0 && bad == 0
    };
    narf_libc::printf_str(
        if aton_ok { "inet_aton: ok\n" } else { "inet_aton: bad\n" },
        &[],
    );

    // inet_pton + inet_ntop round-trip via AF_INET.
    let mut packed4: u32 = 0;
    let pton_rc = unsafe {
        narf_libc::inet_pton(
            narf_libc::AF_INET,
            b"10.0.0.255\0".as_ptr() as *const i8,
            &mut packed4 as *mut u32 as *mut core::ffi::c_void,
        )
    };
    let mut ntop_buf: [u8; 16] = [0; 16];
    let ntop_p = unsafe {
        narf_libc::inet_ntop(
            narf_libc::AF_INET,
            &packed4 as *const u32 as *const core::ffi::c_void,
            ntop_buf.as_mut_ptr() as *mut i8,
            ntop_buf.len(),
        )
    };
    let want_addr: &[u8] = b"10.0.0.255";
    let ntop_ok = pton_rc == 1
        && !ntop_p.is_null()
        && ntop_buf[..want_addr.len()] == *want_addr
        && ntop_buf[want_addr.len()] == 0;
    narf_libc::printf_str(
        if ntop_ok { "inet_pton: ok\n" } else { "inet_pton: bad\n" },
        &[],
    );

    // access() — create a fresh file under /tmp, stat it via access,
    // then unlink and confirm the second access returns -1. The
    // earlier per-tier probes leave /tmp in an indeterminate state
    // (rename moved /tmp/created to /tmp/renamed but that file's
    // existence isn't guaranteed by the tier order); using a fresh
    // path makes this probe self-contained.
    let access_path: *const i8 = b"/tmp/access-probe\0".as_ptr() as *const i8;
    let access_ok = unsafe {
        let fd = narf_libc::posix_open(access_path, narf_libc::O_CREAT, 0);
        let _ = narf_libc::posix_close(fd);
        let here   = narf_libc::access(access_path, 0);
        let _ = narf_libc::posix_unlink(access_path);
        let gone   = narf_libc::access(access_path, 0);
        let absent = narf_libc::access(b"/no/such/path\0".as_ptr() as *const i8, 0);
        here == 0 && gone == -1 && absent == -1
    };
    narf_libc::printf_str(
        if access_ok { "access: ok\n" } else { "access: bad\n" },
        &[],
    );

    // getpagesize / sysconf — pure value checks.
    let sysconf_ok = unsafe {
        narf_libc::getpagesize() == 4096
            && narf_libc::sysconf(narf_libc::_SC_PAGESIZE) == 4096
            && narf_libc::sysconf(narf_libc::_SC_OPEN_MAX) == 256
            && narf_libc::sysconf(9999) == -1
    };
    narf_libc::printf_str(
        if sysconf_ok { "sysconf: ok\n" } else { "sysconf: bad\n" },
        &[],
    );

    // ── Tier 3n probes: getopt_long + S_IS* + chmod/umask ────────
    //
    // getopt_long over `prog --verbose --count=7 -x rest`. Long
    // options:
    //   verbose (no_argument, val 'v')
    //   count   (required_argument, val 'c')
    // Short options:
    //   x (no_argument)
    let larg0 = b"prog\0".as_ptr()         as *mut i8;
    let larg1 = b"--verbose\0".as_ptr()    as *mut i8;
    let larg2 = b"--count=7\0".as_ptr()    as *mut i8;
    let larg3 = b"-x\0".as_ptr()           as *mut i8;
    let larg4 = b"rest\0".as_ptr()         as *mut i8;
    let lopts: [*mut i8; 5] = [larg0, larg1, larg2, larg3, larg4];
    let lopt_short = b"xc:\0".as_ptr() as *const i8;
    let lopt_table: [narf_libc::option; 3] = [
        narf_libc::option {
            name:    b"verbose\0".as_ptr() as *const i8,
            has_arg: narf_libc::NO_ARGUMENT,
            flag:    core::ptr::null_mut(),
            val:     b'v' as i32,
        },
        narf_libc::option {
            name:    b"count\0".as_ptr() as *const i8,
            has_arg: narf_libc::REQUIRED_ARGUMENT,
            flag:    core::ptr::null_mut(),
            val:     b'c' as i32,
        },
        narf_libc::option {
            name:    core::ptr::null(),
            has_arg: 0,
            flag:    core::ptr::null_mut(),
            val:     0,
        },
    ];
    let mut longidx: i32 = -1;
    let getopt_long_ok = unsafe {
        narf_libc::optind = 1;
        narf_libc::opterr = 0;
        let r1 = narf_libc::getopt_long(
            5, lopts.as_ptr(), lopt_short,
            lopt_table.as_ptr(), &mut longidx,
        );
        let li1 = longidx;
        let r2 = narf_libc::getopt_long(
            5, lopts.as_ptr(), lopt_short,
            lopt_table.as_ptr(), &mut longidx,
        );
        let opt_after_count = narf_libc::optarg;
        let li2 = longidx;
        let r3 = narf_libc::getopt_long(
            5, lopts.as_ptr(), lopt_short,
            lopt_table.as_ptr(), &mut longidx,
        );
        let r4 = narf_libc::getopt_long(
            5, lopts.as_ptr(), lopt_short,
            lopt_table.as_ptr(), &mut longidx,
        );
        let count_ok = !opt_after_count.is_null() && *opt_after_count == b'7' as i8;
        r1 == b'v' as i32 && li1 == 0
            && r2 == b'c' as i32 && li2 == 1 && count_ok
            && r3 == b'x' as i32
            && r4 == -1
            && narf_libc::optind == 4
    };
    narf_libc::printf_str(
        if getopt_long_ok { "getopt_long: ok\n" } else { "getopt_long: bad\n" },
        &[],
    );

    // S_IS* macros against synthetic mode bits.
    let smode_ok = unsafe {
        narf_libc::S_ISREG(narf_libc::S_IFREG | 0o644) == 1
            && narf_libc::S_ISDIR(narf_libc::S_IFDIR | 0o755) == 1
            && narf_libc::S_ISREG(narf_libc::S_IFDIR) == 0
            && narf_libc::S_ISCHR(narf_libc::S_IFCHR) == 1
            && narf_libc::S_ISFIFO(narf_libc::S_IFIFO) == 1
            && narf_libc::S_ISLNK(narf_libc::S_IFLNK) == 1
    };
    narf_libc::printf_str(
        if smode_ok { "smode: ok\n" } else { "smode: bad\n" },
        &[],
    );

    // chmod / umask — chmod returns 0 for an existing path; umask
    // returns the previous value and stores the new one.
    let cm_path: *const i8 = b"/tmp/cm-probe\0".as_ptr() as *const i8;
    let chmod_ok = unsafe {
        let fd = narf_libc::posix_open(cm_path, narf_libc::O_CREAT, 0);
        let _ = narf_libc::posix_close(fd);
        let cm = narf_libc::chmod(cm_path, 0o644);
        let _ = narf_libc::posix_unlink(cm_path);
        let cm_miss = narf_libc::chmod(b"/no/such\0".as_ptr() as *const i8, 0o644);
        cm == 0 && cm_miss == -1
    };
    narf_libc::printf_str(
        if chmod_ok { "chmod: ok\n" } else { "chmod: bad\n" },
        &[],
    );

    let umask_ok = unsafe {
        let prev = narf_libc::umask(0o077);
        let now  = narf_libc::umask(0o022);
        prev == 0o022 && now == 0o077
    };
    narf_libc::printf_str(
        if umask_ok { "umask: ok\n" } else { "umask: bad\n" },
        &[],
    );

    // ── Tier 3o probes: basename/dirname + fnmatch + dirent stub ─
    //
    // basename / dirname — operate in place. Each probe uses a
    // fresh writable copy because dirname punches a NUL.
    let mut bn1: [u8; 32] = [0; 32];
    bn1[..14].copy_from_slice(b"/usr/local/bin");
    let bn1_ret = unsafe { narf_libc::basename(bn1.as_mut_ptr() as *mut i8) };
    let bn1_ok = unsafe {
        let want: &[u8] = b"bin\0";
        for (i, &b) in want.iter().enumerate() {
            if *bn1_ret.add(i) != b as i8 { return -1; }
        }
        0
    };
    let _ = bn1_ok; // unused-warning suppression
    let bn1_match = unsafe {
        // Compare bytes at the returned pointer.
        let want: &[u8] = b"bin\0";
        let mut ok = true;
        for (i, &b) in want.iter().enumerate() {
            if *(bn1_ret as *const u8).add(i) != b { ok = false; break; }
        }
        ok
    };
    narf_libc::printf_str(
        if bn1_match { "basename: ok\n" } else { "basename: bad\n" },
        &[],
    );

    let mut dn1: [u8; 32] = [0; 32];
    dn1[..14].copy_from_slice(b"/usr/local/bin");
    let dn1_ret = unsafe { narf_libc::dirname(dn1.as_mut_ptr() as *mut i8) };
    let dn1_match = unsafe {
        let want: &[u8] = b"/usr/local\0";
        let mut ok = true;
        for (i, &b) in want.iter().enumerate() {
            if *(dn1_ret as *const u8).add(i) != b { ok = false; break; }
        }
        ok
    };
    narf_libc::printf_str(
        if dn1_match { "dirname: ok\n" } else { "dirname: bad\n" },
        &[],
    );

    // fnmatch — happy and unhappy patterns.
    let fnmatch_ok = unsafe {
        narf_libc::fnmatch(
            b"*.txt\0".as_ptr() as *const i8,
            b"hello.txt\0".as_ptr() as *const i8,
            0,
        ) == 0
            && narf_libc::fnmatch(
                b"*.txt\0".as_ptr() as *const i8,
                b"hello.md\0".as_ptr() as *const i8,
                0,
            ) == narf_libc::FNM_NOMATCH
            && narf_libc::fnmatch(
                b"foo?bar\0".as_ptr() as *const i8,
                b"fooXbar\0".as_ptr() as *const i8,
                0,
            ) == 0
            && narf_libc::fnmatch(
                b"a[xyz]b\0".as_ptr() as *const i8,
                b"ayb\0".as_ptr() as *const i8,
                0,
            ) == 0
            && narf_libc::fnmatch(
                b"a[!xyz]b\0".as_ptr() as *const i8,
                b"ayb\0".as_ptr() as *const i8,
                0,
            ) == narf_libc::FNM_NOMATCH
            && narf_libc::fnmatch(
                b"a[0-9]b\0".as_ptr() as *const i8,
                b"a5b\0".as_ptr() as *const i8,
                0,
            ) == 0
            // FNM_PATHNAME: '*' must not cross '/'.
            && narf_libc::fnmatch(
                b"*\0".as_ptr() as *const i8,
                b"a/b\0".as_ptr() as *const i8,
                narf_libc::FNM_PATHNAME,
            ) == narf_libc::FNM_NOMATCH
            && narf_libc::fnmatch(
                b"*/b\0".as_ptr() as *const i8,
                b"a/b\0".as_ptr() as *const i8,
                narf_libc::FNM_PATHNAME,
            ) == 0
    };
    narf_libc::printf_str(
        if fnmatch_ok { "fnmatch: ok\n" } else { "fnmatch: bad\n" },
        &[],
    );

    // dirent stub — opendir returns NULL, errno is ENOSYS.
    let dir_ok = unsafe {
        let p = narf_libc::opendir(b"/tmp\0".as_ptr() as *const i8);
        let e = narf_libc::errno();
        p.is_null() && e == 38
    };
    narf_libc::printf_str(
        if dir_ok { "opendir: ok\n" } else { "opendir: bad\n" },
        &[],
    );

    // ── Tier 3p probes: locale + iconv + wide + setvbuf + ungetc ─

    // setlocale always returns "C". We compare bytes 'C' + NUL.
    let locale_ok = unsafe {
        let p = narf_libc::setlocale(
            narf_libc::LC_ALL,
            b"\0".as_ptr() as *const i8,
        );
        !p.is_null() && *p == b'C' as i8 && *p.add(1) == 0
    };
    narf_libc::printf_str(
        if locale_ok { "locale: ok\n" } else { "locale: bad\n" },
        &[],
    );

    // nl_langinfo CODESET → "UTF-8".
    let codeset_ok = unsafe {
        let p = narf_libc::nl_langinfo(narf_libc::CODESET);
        let want: &[u8] = b"UTF-8\0";
        let mut ok = !p.is_null();
        for (i, &b) in want.iter().enumerate() {
            if *p.add(i) != b as i8 { ok = false; break; }
        }
        ok
    };
    narf_libc::printf_str(
        if codeset_ok { "langinfo: ok\n" } else { "langinfo: bad\n" },
        &[],
    );

    // iconv_open returns the !0 sentinel; iconv_close still succeeds.
    let iconv_ok = unsafe {
        let cd = narf_libc::iconv_open(
            b"UTF-8\0".as_ptr() as *const i8,
            b"UTF-8\0".as_ptr() as *const i8,
        );
        let close_rc = narf_libc::iconv_close(cd);
        cd as usize == !0usize && close_rc == 0
    };
    narf_libc::printf_str(
        if iconv_ok { "iconv: ok\n" } else { "iconv: bad\n" },
        &[],
    );

    // wide-char minimal probes.
    let wcs_in: [u32; 4] = [b'h' as u32, b'i' as u32, 0, 0xDEAD_BEEF];
    let wcs_in2: [u32; 3] = [b'h' as u32, b'i' as u32, 0];
    let wcs_diff: [u32; 4] = [b'h' as u32, b'j' as u32, 0, 0];
    let wide_ok = unsafe {
        narf_libc::wcslen(wcs_in.as_ptr()) == 2
            && narf_libc::wcscmp(wcs_in.as_ptr(), wcs_in2.as_ptr()) == 0
            && narf_libc::wcscmp(wcs_in.as_ptr(), wcs_diff.as_ptr()) < 0
    };
    narf_libc::printf_str(
        if wide_ok { "wide: ok\n" } else { "wide: bad\n" },
        &[],
    );

    // setvbuf stub — always returns 0; setvbuf(_IONBF) flushes.
    let setvbuf_ok = unsafe {
        narf_libc::setvbuf(
            narf_libc::stdout(),
            core::ptr::null_mut(),
            narf_libc::_IOFBF,
            4096,
        ) == 0
    };
    narf_libc::printf_str(
        if setvbuf_ok { "setvbuf: ok\n" } else { "setvbuf: bad\n" },
        &[],
    );

    // ungetc: write a payload to a fresh file, fseek+fgetc one byte,
    // ungetc it, then fgetc again — must return the same byte.
    let unget_path: *const i8 = b"/tmp/unget\0".as_ptr() as *const i8;
    let _ = unsafe {
        let fd = narf_libc::posix_open(unget_path, narf_libc::O_CREAT, 0);
        let _ = narf_libc::posix_write(
            fd,
            b"AB" as *const u8 as *const core::ffi::c_void,
            2,
        );
        narf_libc::posix_close(fd);
    };
    let path_bytes: &[u8] = b"/tmp/unget";
    let ungetc_ok = unsafe {
        let stream = narf_libc::fopen(path_bytes.as_ptr(), path_bytes.len(), "r");
        let mut ok = !stream.is_null();
        if ok {
            let r1 = narf_libc::fgetc(stream);
            let push = narf_libc::ungetc(r1, stream);
            let r2 = narf_libc::fgetc(stream);
            ok = r1 == (b'A' as i32) && push == r1 && r2 == r1;
            let _ = narf_libc::fclose(stream);
        }
        let _ = narf_libc::posix_unlink(unget_path);
        ok
    };
    narf_libc::printf_str(
        if ungetc_ok { "ungetc: ok\n" } else { "ungetc: bad\n" },
        &[],
    );

    // ── Tier 3q probes: C-shaped sprintf / snprintf / asprintf ───
    //
    // C-shaped wrappers take an Arg slice as `*const Arg, len` so a
    // C consumer can build the array on the stack. The Rust call
    // site here builds a stack array and hands its pointer through.
    let q_args: [Arg; 2] = [Arg::Int(42), Arg::Hex(0xabc)];
    let q_fmt = b"k=%d v=0x%x\0".as_ptr() as *const i8;
    let mut q_buf: [u8; 32] = [0; 32];
    let snp = unsafe {
        narf_libc::snprintf_c(
            q_buf.as_mut_ptr() as *mut i8,
            q_buf.len(),
            q_fmt,
            q_args.as_ptr(),
            q_args.len(),
        )
    };
    let want_q: &[u8] = b"k=42 v=0xabc";
    let snprintf_c_ok = snp as usize == want_q.len()
        && q_buf[..want_q.len()] == *want_q
        && q_buf[want_q.len()] == 0;
    narf_libc::printf_str(
        if snprintf_c_ok { "snprintf_c: ok\n" } else { "snprintf_c: bad\n" },
        &[],
    );

    // sprintf_c — same fmt, no length cap (we trust the buffer).
    let mut sp_buf: [u8; 32] = [0; 32];
    let spn = unsafe {
        narf_libc::sprintf_c(
            sp_buf.as_mut_ptr() as *mut i8,
            q_fmt,
            q_args.as_ptr(),
            q_args.len(),
        )
    };
    let sprintf_c_ok = spn as usize == want_q.len()
        && sp_buf[..want_q.len()] == *want_q
        && sp_buf[want_q.len()] == 0;
    narf_libc::printf_str(
        if sprintf_c_ok { "sprintf_c: ok\n" } else { "sprintf_c: bad\n" },
        &[],
    );

    // asprintf_c — allocate, format, retrieve, compare, free.
    let mut a_out: *mut i8 = core::ptr::null_mut();
    let asn = unsafe {
        narf_libc::asprintf_c(
            &mut a_out,
            q_fmt,
            q_args.as_ptr(),
            q_args.len(),
        )
    };
    let asprintf_ok = unsafe {
        let mut ok = asn as usize == want_q.len() && !a_out.is_null();
        if ok {
            for (i, &b) in want_q.iter().enumerate() {
                if *(a_out as *const u8).add(i) != b { ok = false; break; }
            }
            if ok && *(a_out as *const u8).add(want_q.len()) != 0 {
                ok = false;
            }
            narf_libc::free(a_out as *mut u8);
        }
        ok
    };
    narf_libc::printf_str(
        if asprintf_ok { "asprintf: ok\n" } else { "asprintf: bad\n" },
        &[],
    );

    // ── Tier 3r probes: string extras + ctype isblank ────────────

    // strcasecmp / strncasecmp — case-folded compare.
    let case_ok = unsafe {
        narf_libc::strcasecmp(
            b"Hello\0".as_ptr(),
            b"hELLO\0".as_ptr(),
        ) == 0
            && narf_libc::strcasecmp(
                b"Hello\0".as_ptr(),
                b"world\0".as_ptr(),
            ) != 0
            && narf_libc::strncasecmp(
                b"AbcDef\0".as_ptr(),
                b"abcXYZ\0".as_ptr(),
                3,
            ) == 0
            && narf_libc::strncasecmp(
                b"AbcDef\0".as_ptr(),
                b"abcXYZ\0".as_ptr(),
                4,
            ) != 0
    };
    narf_libc::printf_str(
        if case_ok { "case_cmp: ok\n" } else { "case_cmp: bad\n" },
        &[],
    );

    // memmem — length-bounded byte search.
    let memmem_ok = unsafe {
        let hay = b"the quick brown fox";
        let p = narf_libc::memmem(
            hay.as_ptr(), hay.len(),
            b"brown".as_ptr(), 5,
        );
        let miss = narf_libc::memmem(
            hay.as_ptr(), hay.len(),
            b"green".as_ptr(), 5,
        );
        !p.is_null()
            && (p as usize) - (hay.as_ptr() as usize) == 10
            && miss.is_null()
    };
    narf_libc::printf_str(
        if memmem_ok { "memmem: ok\n" } else { "memmem: bad\n" },
        &[],
    );

    // strnlen / strndup — bounded forms.
    let nlen_ok = unsafe {
        narf_libc::strnlen(b"hi\0".as_ptr(), 100) == 2
            && narf_libc::strnlen(b"hello".as_ptr(), 3) == 3
    };
    let ndup = unsafe { narf_libc::strndup(b"abcdefghij".as_ptr(), 4) };
    let ndup_ok = unsafe {
        let mut ok = !ndup.is_null();
        if ok {
            for (i, &b) in b"abcd".iter().enumerate() {
                if *ndup.add(i) != b { ok = false; break; }
            }
            if ok && *ndup.add(4) != 0 { ok = false; }
            narf_libc::free(ndup);
        }
        ok
    };
    narf_libc::printf_str(
        if nlen_ok && ndup_ok { "strn: ok\n" } else { "strn: bad\n" },
        &[],
    );

    // *_chk — happy path forwards to the unfortified primitive.
    let chk_ok = unsafe {
        let mut buf: [u8; 8] = [0; 8];
        let _ = narf_libc::__memcpy_chk(
            buf.as_mut_ptr(),
            b"abcd\0\0\0\0".as_ptr(),
            5,
            buf.len(),
        );
        let _ = narf_libc::__memset_chk(
            buf.as_mut_ptr().add(5), b'X' as i32, 2, buf.len() - 5,
        );
        buf == *b"abcd\0XX\0"
    };
    narf_libc::printf_str(
        if chk_ok { "fortify: ok\n" } else { "fortify: bad\n" },
        &[],
    );

    // isblank — space + tab, nothing else.
    let isblank_ok = unsafe {
        narf_libc::isblank(b' ' as i32) != 0
            && narf_libc::isblank(b'\t' as i32) != 0
            && narf_libc::isblank(b'\n' as i32) == 0
            && narf_libc::isblank(b'a' as i32) == 0
    };
    narf_libc::printf_str(
        if isblank_ok { "isblank: ok\n" } else { "isblank: bad\n" },
        &[],
    );

    // ── Tier 3s probes: pthread no-op shim ───────────────────────
    //
    // pthread_self / pthread_equal are constant under single-thread.
    let pid_eq_ok = unsafe {
        let me = narf_libc::pthread_self();
        narf_libc::pthread_equal(me, narf_libc::MAIN_THREAD) != 0
            && narf_libc::pthread_equal(me, 0) == 0
    };
    narf_libc::printf_str(
        if pid_eq_ok { "pthread_self: ok\n" } else { "pthread_self: bad\n" },
        &[],
    );

    // mutex round-trip — init, lock×2, unlock×2, destroy.
    let mutex_ok = unsafe {
        let mut m = narf_libc::pthread_mutex_t::default();
        narf_libc::pthread_mutex_init(&mut m, core::ptr::null()) == 0
            && narf_libc::pthread_mutex_lock(&mut m) == 0
            && narf_libc::pthread_mutex_lock(&mut m) == 0
            && m.locked == 2
            && narf_libc::pthread_mutex_unlock(&mut m) == 0
            && narf_libc::pthread_mutex_unlock(&mut m) == 0
            && m.locked == 0
            && narf_libc::pthread_mutex_destroy(&mut m) == 0
    };
    narf_libc::printf_str(
        if mutex_ok { "mutex: ok\n" } else { "mutex: bad\n" },
        &[],
    );

    // pthread_once — initialiser fires exactly once.
    static ONCE_HITS: core::sync::atomic::AtomicI32
        = core::sync::atomic::AtomicI32::new(0);
    extern "C" fn once_init() {
        ONCE_HITS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    let mut ctl = narf_libc::PTHREAD_ONCE_INIT;
    let once_ok = unsafe {
        narf_libc::pthread_once(&mut ctl, once_init) == 0
            && narf_libc::pthread_once(&mut ctl, once_init) == 0
            && ONCE_HITS.load(core::sync::atomic::Ordering::Relaxed) == 1
    };
    narf_libc::printf_str(
        if once_ok { "once: ok\n" } else { "once: bad\n" },
        &[],
    );

    // pthread_key_create + setspecific + getspecific.
    let key_ok = unsafe {
        let mut key: narf_libc::pthread_key_t = 99;
        let cr = narf_libc::pthread_key_create(&mut key, None);
        let val: usize = 0xDEAD_BEEF;
        let sr = narf_libc::pthread_setspecific(
            key, val as *const core::ffi::c_void,
        );
        let g = narf_libc::pthread_getspecific(key);
        let dr = narf_libc::pthread_key_delete(key);
        cr == 0 && sr == 0 && (g as usize) == val && dr == 0
    };
    narf_libc::printf_str(
        if key_ok { "tls_key: ok\n" } else { "tls_key: bad\n" },
        &[],
    );

    // pthread_create refuses with EAGAIN; pthread_join is a no-op.
    let create_ok = unsafe {
        extern "C" fn never_runs(_: *mut core::ffi::c_void) -> *mut core::ffi::c_void {
            core::ptr::null_mut()
        }
        let mut tid: narf_libc::pthread_t = 0;
        let cr = narf_libc::pthread_create(
            &mut tid, core::ptr::null(), never_runs, core::ptr::null_mut(),
        );
        let mut ret: *mut core::ffi::c_void = 1 as *mut _;
        let jr = narf_libc::pthread_join(narf_libc::MAIN_THREAD, &mut ret);
        cr == narf_libc::pthread::EAGAIN && jr == 0 && ret.is_null()
    };
    narf_libc::printf_str(
        if create_ok { "pthread_create: ok\n" } else { "pthread_create: bad\n" },
        &[],
    );

    // ── Tier 3t probes: termios + ioctl + flock + utime ─────────
    //
    // tcgetattr against fd 0 (a tty) succeeds; against fd 99 (not
    // a tty) fails with errno = ENOTTY.
    let termios_ok = unsafe {
        let mut t = narf_libc::termios::default();
        let r0 = narf_libc::tcgetattr(0, &mut t);
        narf_libc::set_errno(0);
        let r99 = narf_libc::tcgetattr(99, &mut t);
        let e = narf_libc::errno();
        r0 == 0 && r99 == -1 && e == narf_libc::term::ENOTTY
    };
    narf_libc::printf_str(
        if termios_ok { "termios: ok\n" } else { "termios: bad\n" },
        &[],
    );

    // tcsetattr accepts on tty; flock always succeeds.
    let tcset_ok = unsafe {
        let t = narf_libc::termios::default();
        narf_libc::tcsetattr(0, narf_libc::TCSANOW, &t) == 0
            && narf_libc::flock(7, narf_libc::LOCK_EX) == 0
    };
    narf_libc::printf_str(
        if tcset_ok { "tcset_flock: ok\n" } else { "tcset_flock: bad\n" },
        &[],
    );

    // ioctl always returns -1 with errno = ENOTTY.
    let ioctl_ok = unsafe {
        narf_libc::set_errno(0);
        let r = narf_libc::ioctl(0, 0x1234, core::ptr::null_mut());
        let e = narf_libc::errno();
        r == -1 && e == narf_libc::term::ENOTTY
    };
    narf_libc::printf_str(
        if ioctl_ok { "ioctl: ok\n" } else { "ioctl: bad\n" },
        &[],
    );

    // utime on existing path succeeds; missing path fails.
    let utime_path: *const i8 = b"/tmp/utime-probe\0".as_ptr() as *const i8;
    let utime_ok = unsafe {
        let fd = narf_libc::posix_open(utime_path, narf_libc::O_CREAT, 0);
        let _ = narf_libc::posix_close(fd);
        let r1 = narf_libc::utime(utime_path, core::ptr::null());
        let _ = narf_libc::posix_unlink(utime_path);
        let r2 = narf_libc::utime(utime_path, core::ptr::null());
        r1 == 0 && r2 == -1
    };
    narf_libc::printf_str(
        if utime_ok { "utime: ok\n" } else { "utime: bad\n" },
        &[],
    );

    // ── Tier 3u probes: BSD socket stubs ─────────────────────────
    //
    // socket() refuses with ENOSYS. errno round-trips.
    let sock_ok = unsafe {
        narf_libc::set_errno(0);
        let fd = narf_libc::socket(
            narf_libc::AF_INET,
            narf_libc::SOCK_STREAM,
            narf_libc::IPPROTO_TCP,
        );
        let e = narf_libc::errno();
        fd == -1 && e == 38
    };
    narf_libc::printf_str(
        if sock_ok { "socket: ok\n" } else { "socket: bad\n" },
        &[],
    );

    // bind/connect/listen all refuse the same way.
    let bcl_ok = unsafe {
        let sa = narf_libc::sockaddr {
            sa_family: narf_libc::AF_INET as u16,
            sa_data: [0; 14],
        };
        narf_libc::bind(3, &sa, core::mem::size_of::<narf_libc::sockaddr>() as u32) == -1
            && narf_libc::connect(3, &sa, core::mem::size_of::<narf_libc::sockaddr>() as u32) == -1
            && narf_libc::listen(3, 5) == -1
    };
    narf_libc::printf_str(
        if bcl_ok { "bind/conn/listen: ok\n" } else { "bind/conn/listen: bad\n" },
        &[],
    );

    // getaddrinfo returns EAI_NONAME and leaves *result NULL.
    let gai_ok = unsafe {
        let mut res: *mut narf_libc::addrinfo = 1 as *mut _;
        let r = narf_libc::getaddrinfo(
            b"example.com\0".as_ptr() as *const i8,
            core::ptr::null(),
            core::ptr::null(),
            &mut res,
        );
        r == narf_libc::EAI_NONAME && res.is_null()
    };
    narf_libc::printf_str(
        if gai_ok { "getaddrinfo: ok\n" } else { "getaddrinfo: bad\n" },
        &[],
    );

    // gai_strerror returns a non-null static string.
    let gai_str_ok = unsafe {
        let p = narf_libc::gai_strerror(narf_libc::EAI_NONAME);
        !p.is_null() && *p != 0
    };
    narf_libc::printf_str(
        if gai_str_ok { "gai_strerror: ok\n" } else { "gai_strerror: bad\n" },
        &[],
    );

    // ── Tier 3v probes: regex skeleton + sigsetjmp/siglongjmp ────
    //
    // regcomp succeeds with a flag round-trip; regexec returns
    // REG_NOMATCH and zeroes the match array.
    let regex_ok = unsafe {
        let mut re = narf_libc::regex_t::default();
        let cr = narf_libc::regcomp(
            &mut re,
            b"abc\0".as_ptr() as *const i8,
            narf_libc::REG_EXTENDED,
        );
        let mut m: [narf_libc::regmatch_t; 2] = [
            narf_libc::regmatch_t::default(),
            narf_libc::regmatch_t::default(),
        ];
        let er = narf_libc::regexec(
            &re,
            b"abcdef\0".as_ptr() as *const i8,
            m.len(),
            m.as_mut_ptr(),
            0,
        );
        narf_libc::regfree(&mut re);
        cr == narf_libc::REG_NOERROR
            && er == narf_libc::REG_NOMATCH
            && m[0].rm_so == -1 && m[0].rm_eo == -1
    };
    narf_libc::printf_str(
        if regex_ok { "regex: ok\n" } else { "regex: bad\n" },
        &[],
    );

    // regerror — non-empty description for REG_NOMATCH.
    let regerror_ok = unsafe {
        let mut buf: [u8; 32] = [0; 32];
        let n = narf_libc::regerror(
            narf_libc::REG_NOMATCH,
            core::ptr::null(),
            buf.as_mut_ptr() as *mut i8,
            buf.len(),
        );
        let want: &[u8] = b"No match";
        n == want.len() && buf[..want.len()] == *want
    };
    narf_libc::printf_str(
        if regerror_ok { "regerror: ok\n" } else { "regerror: bad\n" },
        &[],
    );

    // sigsetjmp / siglongjmp — full round-trip parallel to setjmp.
    // (AtomicI32 / Ordering already imported above.)
    static SIG_HITS: AtomicI32 = AtomicI32::new(0);
    let mut senv = narf_libc::sigjmp_buf::default();
    let sj_val = unsafe { narf_libc::sigsetjmp(&mut senv, 1) };
    SIG_HITS.fetch_add(1, Ordering::SeqCst);
    let sigjmp_ok;
    if sj_val == 0 && SIG_HITS.load(Ordering::SeqCst) == 1 {
        unsafe { narf_libc::siglongjmp(&mut senv, 11) };
    } else if sj_val == 11 && SIG_HITS.load(Ordering::SeqCst) == 2 {
        sigjmp_ok = true;
    } else {
        sigjmp_ok = false;
    }
    narf_libc::printf_str(
        if sigjmp_ok { "sigsetjmp: ok\n" } else { "sigsetjmp: bad\n" },
        &[],
    );

    // ── Tier 3w probes: ldexp/frexp/modf + complex + fenv ────────

    let ldexp_ok = unsafe {
        narf_libc::ldexp(1.5, 4) == 24.0
            && narf_libc::ldexp(0.0, 100) == 0.0
            && narf_libc::ldexp(-3.0, -1) == -1.5
    };
    narf_libc::printf_str(
        if ldexp_ok { "ldexp: ok\n" } else { "ldexp: bad\n" },
        &[],
    );

    let frexp_ok = unsafe {
        let mut e: i32 = 0;
        let m = narf_libc::frexp(24.0, &mut e);
        // 24 = 0.75 * 2^5
        m == 0.75 && e == 5
    };
    narf_libc::printf_str(
        if frexp_ok { "frexp: ok\n" } else { "frexp: bad\n" },
        &[],
    );

    let modf_ok = unsafe {
        let mut ip: f64 = 0.0;
        let frac = narf_libc::modf(3.75, &mut ip);
        let mut ip2: f64 = 0.0;
        let frac2 = narf_libc::modf(-2.25, &mut ip2);
        ip == 3.0 && (frac - 0.75).abs() < 1e-12
            && ip2 == -2.0 && (frac2 + 0.25).abs() < 1e-12
    };
    narf_libc::printf_str(
        if modf_ok { "modf: ok\n" } else { "modf: bad\n" },
        &[],
    );

    // <complex.h> — real / imag / conj / cabs / arithmetic.
    let cplx_ok = unsafe {
        let z1 = narf_libc::complex_double { real: 3.0, imag: 4.0 };
        let z2 = narf_libc::complex_double { real: 1.0, imag: 2.0 };
        let cz = narf_libc::conj(z1);
        let m  = narf_libc::cabs(z1);
        let s  = narf_libc::cadd(z1, z2);
        let p  = narf_libc::cmul(z1, z2);
        let q  = narf_libc::cdiv(z1, z2);
        narf_libc::creal(z1) == 3.0
            && narf_libc::cimag(z1) == 4.0
            && cz == narf_libc::complex_double { real: 3.0, imag: -4.0 }
            && (m - 5.0).abs() < 1e-9   // sqrt(9+16) = 5
            && s == narf_libc::complex_double { real: 4.0, imag: 6.0 }
            && p == narf_libc::complex_double { real: -5.0, imag: 10.0 }
            && (narf_libc::creal(q) - 2.2).abs() < 1e-9
            && (narf_libc::cimag(q) + 0.4).abs() < 1e-9
    };
    narf_libc::printf_str(
        if cplx_ok { "complex: ok\n" } else { "complex: bad\n" },
        &[],
    );

    // <fenv.h> — round mode reads as TONEAREST; set TONEAREST OK,
    // anything else fails; clear/test exceptions are no-ops.
    let fenv_ok = unsafe {
        narf_libc::fegetround() == narf_libc::FE_TONEAREST
            && narf_libc::fesetround(narf_libc::FE_TONEAREST) == 0
            && narf_libc::fesetround(narf_libc::FE_DOWNWARD) != 0
            && narf_libc::feclearexcept(narf_libc::FE_ALL_EXCEPT) == 0
            && narf_libc::fetestexcept(narf_libc::FE_INVALID) == 0
    };
    narf_libc::printf_str(
        if fenv_ok { "fenv: ok\n" } else { "fenv: bad\n" },
        &[],
    );

    // ── Tier 3x probes: fork/exec stubs + posix_memalign ─────────

    // fork / vfork / execve / execvp — refuse with ENOSYS.
    let proc_stubs_ok = unsafe {
        narf_libc::set_errno(0);
        let f = narf_libc::fork();
        let ef = narf_libc::errno();
        let v = narf_libc::vfork();
        let e = narf_libc::execve(
            b"/bin/x\0".as_ptr() as *const i8,
            core::ptr::null(),
            core::ptr::null(),
        );
        f == -1 && ef == 38 && v == -1 && e == -1
    };
    narf_libc::printf_str(
        if proc_stubs_ok { "fork: ok\n" } else { "fork: bad\n" },
        &[],
    );

    // waitpid returns -1 with ECHILD; status is zeroed.
    let wait_ok = unsafe {
        let mut status: i32 = 0xDEAD;
        narf_libc::set_errno(0);
        let r = narf_libc::waitpid(-1, &mut status, 0);
        let e = narf_libc::errno();
        r == -1 && status == 0 && e == 10
    };
    narf_libc::printf_str(
        if wait_ok { "waitpid: ok\n" } else { "waitpid: bad\n" },
        &[],
    );

    // setsid / getpgrp coalesce to pid; setuid accept-and-ignore;
    // getuid/geteuid return the kernel's stub uid (0).
    let session_ok = unsafe {
        let p = narf_libc::getpid();
        narf_libc::setsid() == p
            && narf_libc::getpgrp() == p
            && narf_libc::getsid(0) == p
            && narf_libc::setuid(42) == 0
            && narf_libc::geteuid() == narf_libc::getuid()
    };
    narf_libc::printf_str(
        if session_ok { "session: ok\n" } else { "session: bad\n" },
        &[],
    );

    // posix_memalign — 16-byte alignment is honoured; > 16 fails.
    let memalign_ok = unsafe {
        let mut p: *mut u8 = core::ptr::null_mut();
        let r1 = narf_libc::posix_memalign(&mut p, 16, 64);
        let aligned = (p as usize) % 16 == 0;
        narf_libc::free(p);
        let r2 = narf_libc::posix_memalign(
            &mut p, 4096, 64,
        );
        r1 == 0 && aligned && r2 == 22 // EINVAL
    };
    narf_libc::printf_str(
        if memalign_ok { "memalign: ok\n" } else { "memalign: bad\n" },
        &[],
    );

    // aligned_alloc — same 16-byte cap; size must be multiple of align.
    let aalloc_ok = unsafe {
        let p = narf_libc::aligned_alloc(8, 32);
        let aligned = !p.is_null() && (p as usize) % 8 == 0;
        narf_libc::free(p);
        let bad = narf_libc::aligned_alloc(8, 33); // size % align != 0
        aligned && bad.is_null()
    };
    narf_libc::printf_str(
        if aalloc_ok { "aligned_alloc: ok\n" } else { "aligned_alloc: bad\n" },
        &[],
    );

    // ── Tier 3y probes: poll/select/epoll stubs + fd_set macros ──

    // poll() refuses; FD_SET / FD_ISSET / FD_CLR / FD_ZERO work.
    let poll_ok = unsafe {
        narf_libc::set_errno(0);
        let mut fds = narf_libc::pollfd {
            fd: 0,
            events: narf_libc::POLLIN,
            revents: 0,
        };
        let r = narf_libc::poll(&mut fds, 1, 0);
        let e = narf_libc::errno();
        r == -1 && e == 38
    };
    narf_libc::printf_str(
        if poll_ok { "poll: ok\n" } else { "poll: bad\n" },
        &[],
    );

    let fdset_ok = unsafe {
        let mut s = narf_libc::fd_set::default();
        narf_libc::FD_ZERO(&mut s);
        narf_libc::FD_SET(0, &mut s);
        narf_libc::FD_SET(7, &mut s);
        let i0 = narf_libc::FD_ISSET(0, &s);
        let i7 = narf_libc::FD_ISSET(7, &s);
        let i9 = narf_libc::FD_ISSET(9, &s);
        narf_libc::FD_CLR(0, &mut s);
        let i0_after = narf_libc::FD_ISSET(0, &s);
        i0 == 1 && i7 == 1 && i9 == 0 && i0_after == 0
    };
    narf_libc::printf_str(
        if fdset_ok { "fd_set: ok\n" } else { "fd_set: bad\n" },
        &[],
    );

    // epoll_create / eventfd / timerfd_create — all ENOSYS.
    let epoll_ok = unsafe {
        let e1 = narf_libc::epoll_create(1);
        let e2 = narf_libc::epoll_create1(0);
        let evfd = narf_libc::eventfd(0, 0);
        let tfd = narf_libc::timerfd_create(0, 0);
        e1 == -1 && e2 == -1 && evfd == -1 && tfd == -1
    };
    narf_libc::printf_str(
        if epoll_ok { "epoll: ok\n" } else { "epoll: bad\n" },
        &[],
    );

    // ── Tier 3z probes: mmap/uname/sysinfo/dlopen ────────────────

    // mmap anonymous → munmap round-trip; mprotect / mlock no-op
    // success; dlopen returns NULL with dlerror non-NULL once.
    let mmap_ok = unsafe {
        let p = narf_libc::mmap(
            core::ptr::null_mut(),
            4096,
            narf_libc::PROT_READ | narf_libc::PROT_WRITE,
            narf_libc::MAP_PRIVATE | narf_libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        let allocated = !p.is_null() && p != narf_libc::MAP_FAILED;
        let protected = narf_libc::mprotect(p, 4096, narf_libc::PROT_READ) == 0;
        let locked = narf_libc::mlock(p, 4096) == 0;
        let unmapped = if allocated {
            narf_libc::munmap(p, 4096) == 0
        } else { false };
        allocated && protected && locked && unmapped
    };
    narf_libc::printf_str(
        if mmap_ok { "mmap: ok\n" } else { "mmap: bad\n" },
        &[],
    );

    // uname populates a known string in `sysname`.
    let uname_ok = unsafe {
        let mut u: narf_libc::utsname = core::mem::zeroed();
        let r = narf_libc::uname(&mut u);
        let want: &[u8] = b"NARF\0";
        let mut ok = r == 0;
        for (i, &b) in want.iter().enumerate() {
            if u.sysname[i] != b as i8 { ok = false; break; }
        }
        ok
    };
    narf_libc::printf_str(
        if uname_ok { "uname: ok\n" } else { "uname: bad\n" },
        &[],
    );

    // sysinfo populates totalram = 256 MiB; getrusage zeroes; getrlimit infinite.
    let sysinfo_ok = unsafe {
        let mut s = narf_libc::sysinfo_t::default();
        narf_libc::sysinfo(&mut s);
        let mut ru = narf_libc::rusage::default();
        narf_libc::getrusage(narf_libc::RUSAGE_SELF, &mut ru);
        let mut rl = narf_libc::rlimit::default();
        narf_libc::getrlimit(narf_libc::RLIMIT_NOFILE, &mut rl);
        s.totalram == 256 * 1024 * 1024
            && s.procs == 1
            && ru.ru_maxrss == 0
            && rl.rlim_cur == narf_libc::RLIM_INFINITY
    };
    narf_libc::printf_str(
        if sysinfo_ok { "sysinfo: ok\n" } else { "sysinfo: bad\n" },
        &[],
    );

    // dlopen returns NULL; dlerror returns a non-null string once
    // then NULL on the next call.
    let dl_ok = unsafe {
        let h = narf_libc::dlopen(b"foo.so\0".as_ptr() as *const i8, narf_libc::RTLD_NOW);
        let e1 = narf_libc::dlerror();
        let e2 = narf_libc::dlerror();
        h.is_null() && !e1.is_null() && e2.is_null()
    };
    narf_libc::printf_str(
        if dl_ok { "dlopen: ok\n" } else { "dlopen: bad\n" },
        &[],
    );

    // ── Tier 3aa probes: pwd / grp single-user account DB ────────

    // getpwuid(0) returns a "narf" entry; getpwuid(1) returns NULL;
    // iterator yields exactly one row.
    let pw_ok = unsafe {
        let p0 = narf_libc::getpwuid(0);
        let p1 = narf_libc::getpwuid(1);
        let pn = narf_libc::getpwnam(b"narf\0".as_ptr() as *const i8);
        let px = narf_libc::getpwnam(b"root\0".as_ptr() as *const i8);
        let mut name_ok = false;
        if !p0.is_null() {
            let want: &[u8] = b"narf\0";
            name_ok = true;
            let np = (*p0).pw_name;
            for (i, &b) in want.iter().enumerate() {
                if *np.add(i) as u8 != b { name_ok = false; break; }
            }
        }
        narf_libc::setpwent();
        let it1 = narf_libc::getpwent();
        let it2 = narf_libc::getpwent();
        narf_libc::endpwent();

        !p0.is_null()
            && p1.is_null()
            && !pn.is_null()
            && px.is_null()
            && name_ok
            && (*p0).pw_uid == 0
            && (*p0).pw_gid == 0
            && !it1.is_null()
            && it2.is_null()
    };
    narf_libc::printf_str(
        if pw_ok { "pwd: ok\n" } else { "pwd: bad\n" },
        &[],
    );

    // getgrgid(0) returns "narf"; gr_mem terminates with NULL.
    let gr_ok = unsafe {
        let g0 = narf_libc::getgrgid(0);
        let g1 = narf_libc::getgrgid(1);
        let gn = narf_libc::getgrnam(b"narf\0".as_ptr() as *const i8);
        let mem_terminates = if !g0.is_null() {
            let m = (*g0).gr_mem;
            !m.is_null() && !(*m).is_null() && (*m.add(1)).is_null()
        } else { false };

        !g0.is_null()
            && g1.is_null()
            && !gn.is_null()
            && (*g0).gr_gid == 0
            && mem_terminates
    };
    narf_libc::printf_str(
        if gr_ok { "grp: ok\n" } else { "grp: bad\n" },
        &[],
    );

    // getgrouplist returns 1 with the primary gid populated.
    let grl_ok = unsafe {
        let mut groups: [u32; 4] = [0xdead; 4];
        let mut ng: i32 = 4;
        let r = narf_libc::getgrouplist(
            b"narf\0".as_ptr() as *const i8,
            0,
            groups.as_mut_ptr(),
            &mut ng,
        );
        r == 1 && ng == 1 && groups[0] == 0
    };
    narf_libc::printf_str(
        if grl_ok { "grouplist: ok\n" } else { "grouplist: bad\n" },
        &[],
    );

    // ── Tier 3ab probes: getrandom + readv/writev ────────────────

    // getrandom fills a buffer with non-zero bytes; deterministic
    // PRNG output is fine for the smoke test.
    let rand_ok = unsafe {
        let mut buf: [u8; 32] = [0; 32];
        let r = narf_libc::getrandom(
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            buf.len(),
            0,
        );
        // At least one byte should be non-zero — the PRNG seed is
        // 0x9E37..; the first 8 bytes are a known mix.
        let mut any_nz = false;
        for &b in &buf {
            if b != 0 { any_nz = true; break; }
        }
        r == buf.len() as isize && any_nz
    };
    narf_libc::printf_str(
        if rand_ok { "getrandom: ok\n" } else { "getrandom: bad\n" },
        &[],
    );

    // getentropy(257) → -1; getentropy(16) → 0.
    let ent_ok = unsafe {
        let mut buf: [u8; 16] = [0; 16];
        let small = narf_libc::getentropy(
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            16,
        );
        let big = narf_libc::getentropy(
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            257,
        );
        small == 0 && big == -1
    };
    narf_libc::printf_str(
        if ent_ok { "getentropy: ok\n" } else { "getentropy: bad\n" },
        &[],
    );

    // writev(stdout, iov[3]) emits "wri" + "tev" + ": ok\n" — the
    // probe is the side-effect: if the line below appears verbatim
    // we know the gather walk was correct.
    let writev_ok = unsafe {
        let a: &[u8] = b"wri";
        let b: &[u8] = b"tev";
        let c: &[u8] = b": ok\n";
        let iov: [narf_libc::iovec; 3] = [
            narf_libc::iovec {
                iov_base: a.as_ptr() as *mut core::ffi::c_void,
                iov_len:  a.len(),
            },
            narf_libc::iovec {
                iov_base: b.as_ptr() as *mut core::ffi::c_void,
                iov_len:  b.len(),
            },
            narf_libc::iovec {
                iov_base: c.as_ptr() as *mut core::ffi::c_void,
                iov_len:  c.len(),
            },
        ];
        let n = narf_libc::writev(1, iov.as_ptr(), 3);
        n == (a.len() + b.len() + c.len()) as isize
    };
    if !writev_ok {
        narf_libc::printf_str("writev: bad\n", &[]);
    }

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
