//! `<assert.h>` — failure handler for the standard `assert(expr)`
//! macro.
//!
//! The macro itself isn't expressible in Rust (it'd need a real C
//! preprocessor), but C consumers expand `assert(expr)` to:
//!     ((expr) ? (void)0 :
//!      __assert_fail(#expr, __FILE__, __LINE__, __func__))
//!
//! so we ship `__assert_fail` here. The implementation prints a
//! POSIX-shaped diagnostic to stderr and calls `abort()`. The symbol
//! name `__assert_fail` is the standard SysV C-runtime hook a real C
//! `<assert.h>` expands to, so consumers link without additional shims.

use crate::posix::c_char;

/// SysV-C-runtime assertion failure handler. Never returns.
///
/// # Safety
/// All four pointer arguments must be NUL-terminated C strings (or
/// null, which is tolerated by emitting `"<unknown>"` in their slot).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __assert_fail(
    expr: *const c_char,
    file: *const c_char,
    line: u32,
    func: *const c_char,
) -> ! {
    use crate::Arg;
    // SAFETY: caller contract — all four args are valid C strings or
    // null. cstr_or_unknown forwards null to a fixed literal.
    let e = unsafe { cstr_or_unknown(expr) };
    let f = unsafe { cstr_or_unknown(file) };
    let n = unsafe { cstr_or_unknown(func) };
    crate::fprintf_str(
        2,
        "narf-libc: %s:%u: %s: Assertion `%s' failed.\n",
        &[
            Arg::Str(f),
            Arg::Uint(line as u64),
            Arg::Str(n),
            Arg::Str(e),
        ],
    );
    // SAFETY: abort never returns; pure delegate.
    unsafe { crate::abort() }
}

/// Build a `&'static str` view over a C string, or return
/// `"<unknown>"` if the pointer is null.
unsafe fn cstr_or_unknown(p: *const c_char) -> &'static str {
    if p.is_null() {
        return "<unknown>";
    }
    let mut n = 0usize;
    // SAFETY: caller contract — `p` is NUL-terminated.
    unsafe {
        while *p.add(n) != 0 {
            n += 1;
        }
        let bytes = core::slice::from_raw_parts(p as *const u8, n);
        // Use core::str::from_utf8_unchecked for the static-lifetime
        // borrow — assertion strings are typically ASCII literals
        // from `__FILE__` / `__func__` so non-UTF-8 is vanishingly
        // unlikely; falling back to a placeholder on the rare bad
        // input keeps the output safe.
        match core::str::from_utf8(bytes) {
            Ok(s) => {
                // Promote to 'static via mem::transmute on the
                // pointer + length is unnecessary — caller-provided
                // strings outlive the abort path (the program is
                // about to terminate).
                core::mem::transmute::<&str, &'static str>(s)
            }
            Err(_) => "<non-utf8>",
        }
    }
}
