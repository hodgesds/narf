//! The kernel ABI a loadable module may call.
//!
//! Until this file existed, KSYMTAB was empty — there was not one
//! `narf_export!` call site in the tree — so a module could be parsed,
//! relocated and started, but could not call a single kernel function.
//!
//! ## Why this is a hand-written surface
//!
//! Rust has no stable ABI. `narf_block::register_block_device(&dyn BlockDev)`
//! cannot be exported to a separately-compiled module: the layout of `&dyn`,
//! of every `repr(Rust)` struct, and of the calling convention itself are all
//! free to change between compilations, and nothing in the toolchain will tell
//! you when they do. The only things that can safely cross the boundary are
//! `extern "C"` functions over primitives and `repr(C)` types.
//!
//! So the module ABI is not a projection of the kernel's internal APIs — it is
//! a deliberate, curated set of C shims, and every addition is a promise. It
//! starts small on purpose. `bpf/src/kfuncs.rs` made the same call for the same
//! reason ("deliberately tiny"), and is the closest in-tree precedent.
//!
//! Conventions, so the surface stays predictable as it grows:
//!
//!   * Errors are a negative errno in an `i32`, matching the syscall layer.
//!   * Sizes and counts are `usize`; addresses are raw pointers.
//!   * Anything with kernel-side lifetime is an opaque `u64` handle, never a
//!     borrowed reference.
//!   * No function may unwind. Every one is `extern "C"` and the kernel is
//!     built `panic=abort`, so this holds by construction.
//!   * **Every export is `unsafe`**, including ones taking no pointers. The
//!     caller is separately-compiled kernel-mode code whose arguments nothing
//!     has verified, so the boundary is unsafe as a whole; marking only the
//!     pointer-taking ones would imply the rest had been checked, and would
//!     mean adding a pointer argument later silently changes a function's
//!     contract without changing its declaration.
//!
//! ## Versioning
//!
//! Each export carries a CRC derived from its signature *as written* —
//! `crc_for_signature` hashes the stringified argument and return types at
//! compile time. Change a parameter and the CRC changes, so a module built
//! against the old signature is refused by `symbols::resolve` with
//! `CrcMismatch` instead of being called with the wrong stack layout. This is
//! Linux's MODVERSIONS idea (`kernel/module/version.c`) without needing
//! genksyms: the macro sees the tokens, so it can hash them.
//!
//! `DESIGN.md` deferred CRC generation to "build-system integration". It turns
//! out none is needed.

use alloc::alloc::{alloc, dealloc};
use core::alloc::Layout;

/// FNV-1a over a signature string, evaluated at compile time.
///
/// Not a real CRC despite the field name it feeds; the property that matters
/// is that any change to the signature changes the value, and FNV-1a gives
/// that in a `const fn` with no table.
pub const fn crc_for_signature(sig: &str) -> u32 {
    let b = sig.as_bytes();
    let mut h: u32 = 0x811C_9DC5;
    let mut i = 0;
    while i < b.len() {
        h ^= b[i] as u32;
        h = h.wrapping_mul(0x0100_0193);
        i += 1;
    }
    h
}

/// Define the kernel ABI surface.
///
/// One invocation defines every export *and* the function that registers
/// them, so the two cannot drift — adding a function to the list is the only
/// step. Each export's CRC is computed from its own stringified signature.
macro_rules! kernel_abi {
    ($(
        $(#[$meta:meta])*
        fn $name:ident ( $($arg:ident : $aty:ty),* $(,)? ) $(-> $ret:ty)? $body:block
    )*) => {
        $(
            $(#[$meta])*
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn $name ( $($arg : $aty),* ) $(-> $ret)? $body
        )*

        /// Every export's name, for diagnostics and the `/proc` surface.
        pub const NAMES: &[&str] = &[$(stringify!($name)),*];

        /// An empty ABI surface would mean no module can call anything —
        /// a build-time mistake, so it fails at build time.
        const _: () = assert!(!NAMES.is_empty(), "kernel ABI surface is empty");

        /// Register the whole surface with KSYMTAB.
        ///
        /// Called from the `modules-abi` initcall before any module can be
        /// loaded, and again by `symbols::__reset_for_test` to restore the
        /// boot state. Idempotent for that reason: re-registering a name
        /// would otherwise duplicate the entry and skew the ABI hash, which
        /// sums over the table.
        pub fn register_all() {
            $(
                if !crate::symbols::is_exported(stringify!($name)) {
                crate::symbols::export(
                    stringify!($name),
                    $name as usize,
                    crc_for_signature(concat!(
                        stringify!($name),
                        "(",
                        $(stringify!($aty), ",",)*
                        ")",
                        $("->", stringify!($ret),)?
                    )),
                );
                }
            )*
        }
    };
}

kernel_abi! {
    /// Write `len` bytes of UTF-8 at `ptr` to the kernel console.
    ///
    /// Returns 0, or `-EINVAL` if the pointer is null or the bytes are not
    /// valid UTF-8. Modules that want formatting do it on their own side and
    /// hand over the finished bytes — exporting a varargs printf across an
    /// ABI boundary is a supply of foot-guns for no gain.
    ///
    /// # Safety
    /// `ptr` must name `len` readable bytes that stay valid for the duration
    /// of the call. A null pointer or a zero length is rejected rather than
    /// dereferenced; nothing else is checked.
    fn narf_printk(ptr: *const u8, len: usize) -> i32 {
        if ptr.is_null() || len == 0 {
            return -22;
        }
        // SAFETY: the module promises `ptr` names `len` readable bytes. This
        // is the ABI's trust boundary — a module is kernel-mode code and can
        // corrupt its own domain regardless; the check above only catches the
        // common mistake.
        let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
        match core::str::from_utf8(bytes) {
            Ok(s) => {
                narf_console::write_str(s);
                0
            }
            Err(_) => -22,
        }
    }

    /// Allocate `size` bytes with `align` from the kernel heap. Returns null
    /// on failure or on an invalid layout.
    ///
    /// Paired strictly with [`narf_kfree`], which must be given the same size
    /// and alignment — the kernel heap is not `malloc` and does not record
    /// the layout for you.
    ///
    /// # Safety
    /// No preconditions beyond the ABI's blanket one: an invalid or
    /// zero-sized layout returns null rather than allocating. The returned
    /// pointer must be released with [`narf_kfree`] and the same
    /// `size`/`align`, or it leaks.
    fn narf_kmalloc(size: usize, align: usize) -> *mut u8 {
        let Ok(layout) = Layout::from_size_align(size, align) else {
            return core::ptr::null_mut();
        };
        if layout.size() == 0 {
            return core::ptr::null_mut();
        }
        // SAFETY: the layout is non-zero-sized and valid, as `alloc` requires.
        unsafe { alloc(layout) }
    }

    /// Release an allocation from [`narf_kmalloc`].
    ///
    /// # Safety
    /// `ptr` must have come from [`narf_kmalloc`], must not have been freed
    /// already, and `size`/`align` must be exactly the values it was
    /// allocated with — the kernel heap does not record the layout, so a
    /// mismatch corrupts the allocator rather than failing. A null `ptr` is a
    /// no-op.
    fn narf_kfree(ptr: *mut u8, size: usize, align: usize) {
        if ptr.is_null() {
            return;
        }
        let Ok(layout) = Layout::from_size_align(size, align) else {
            return;
        };
        if layout.size() == 0 {
            return;
        }
        // SAFETY: forwarded from the module's contract — `ptr` came from
        // `narf_kmalloc` with this exact layout.
        unsafe { dealloc(ptr, layout) }
    }

    /// Nanoseconds on the monotonic clock. The one every driver needs first,
    /// for timeouts and rate limiting.
    ///
    /// # Safety
    /// None in practice — it takes no arguments and reads a clock. `unsafe`
    /// only because the whole ABI surface is; see the module docs.
    fn narf_monotonic_ns() -> u64 {
        narf_time::monotonic_ns()
    }
}

// ── In-kernel smokes ───────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

/// The surface must actually be in KSYMTAB. Before `kabi` existed this table
/// was empty tree-wide, so a module could be relocated and started but could
/// not call one kernel function; this is the test that keeps that from
/// silently coming back if the `modules-abi` initcall is ever dropped.
fn smoke_kabi_surface_is_registered() -> TestResult {
    for name in NAMES {
        if !crate::symbols::is_exported(name) {
            return TestResult::Fail("a kernel ABI export is missing from KSYMTAB");
        }
    }
    TestResult::Pass
}
kernel_test_in!("modules/kabi", smoke_kabi_surface_is_registered);

/// Registration is idempotent: a second call must not duplicate entries,
/// because the ABI hash sums over the table and would change.
fn smoke_kabi_register_all_is_idempotent() -> TestResult {
    let before = crate::symbols::export_count();
    let hash_before = crate::symbols::compute_abi_hash();
    register_all();
    if crate::symbols::export_count() != before {
        return TestResult::Fail("register_all duplicated entries on a second call");
    }
    if crate::symbols::compute_abi_hash() != hash_before {
        return TestResult::Fail("ABI hash moved across an idempotent re-registration");
    }
    TestResult::Pass
}
kernel_test_in!("modules/kabi", smoke_kabi_register_all_is_idempotent);

/// The CRC must track the signature. If it did not, a module built against
/// an old signature would be called with the wrong stack layout instead of
/// being refused — the exact failure MODVERSIONS exists to prevent.
fn smoke_kabi_crc_tracks_signature() -> TestResult {
    let a = crc_for_signature("narf_printk(*const u8,usize,)->i32");
    let same = crc_for_signature("narf_printk(*const u8,usize,)->i32");
    let arg_changed = crc_for_signature("narf_printk(*const u8,u32,)->i32");
    let ret_changed = crc_for_signature("narf_printk(*const u8,usize,)->i64");
    let name_changed = crc_for_signature("narf_printq(*const u8,usize,)->i32");

    if a != same {
        return TestResult::Fail("crc_for_signature is not deterministic");
    }
    if a == arg_changed || a == ret_changed || a == name_changed {
        return TestResult::Fail("crc_for_signature collided on a changed signature");
    }
    TestResult::Pass
}
kernel_test_in!("modules/kabi", smoke_kabi_crc_tracks_signature);

/// The ABI hash must be derived from the table, not a constant — otherwise
/// it cannot catch the "wrong kernel" case it exists for.
fn smoke_kabi_abi_hash_follows_the_table() -> TestResult {
    let before = crate::symbols::compute_abi_hash();
    if before == 0 {
        return TestResult::Fail("ABI hash is zero over a non-empty export table");
    }
    if crate::symbols::kernel_abi() != before {
        return TestResult::Fail("published kernel_abi does not match the current table");
    }

    // Adding a symbol must move it.
    crate::symbols::export("narf_kabi_smoke_probe", 0xDEAD_BEEF, 0x1234_5678);
    let after = crate::symbols::compute_abi_hash();

    // Restores the boot surface, dropping the probe.
    crate::symbols::__reset_for_test();
    crate::symbols::set_kernel_abi(crate::symbols::compute_abi_hash());

    if after == before {
        return TestResult::Fail("ABI hash did not change when an export was added");
    }
    if crate::symbols::compute_abi_hash() != before {
        return TestResult::Fail("reset did not restore the boot export surface");
    }
    TestResult::Pass
}
kernel_test_in!("modules/kabi", smoke_kabi_abi_hash_follows_the_table);

/// `narf_printk` must reject rather than dereference bad input — a module
/// passing a null pointer is a bug to report, not a kernel fault.
fn smoke_kabi_printk_rejects_bad_input() -> TestResult {
    // SAFETY: deliberately passing the arguments the function documents as
    // rejected; neither is dereferenced.
    let null = unsafe { narf_printk(core::ptr::null(), 8) };
    // SAFETY: the pointer is valid; the zero length is what is under test.
    let zero = unsafe { narf_printk(b"x".as_ptr(), 0) };
    // 0x80 is a continuation byte with no lead byte — not valid UTF-8.
    let bad: [u8; 2] = [0x80, 0x80];
    // SAFETY: `bad` names 2 readable bytes for the duration of the call.
    let invalid = unsafe { narf_printk(bad.as_ptr(), bad.len()) };

    if null == -22 && zero == -22 && invalid == -22 {
        TestResult::Pass
    } else {
        TestResult::Fail("narf_printk accepted input it documents as invalid")
    }
}
kernel_test_in!("modules/kabi", smoke_kabi_printk_rejects_bad_input);

/// The heap pair must round-trip, including the layouts it documents as
/// rejected.
fn smoke_kabi_kmalloc_round_trip() -> TestResult {
    // SAFETY: valid layout.
    let p = unsafe { narf_kmalloc(64, 8) };
    if p.is_null() {
        return TestResult::Fail("narf_kmalloc(64, 8) returned null");
    }
    // SAFETY: `p` names 64 writable bytes just allocated.
    unsafe { core::ptr::write_bytes(p, 0xA5, 64) };
    // SAFETY: `p` came from `narf_kmalloc` with exactly this layout.
    let readback = unsafe { *p };
    // SAFETY: as above; freed exactly once.
    unsafe { narf_kfree(p, 64, 8) };

    // Zero size and a non-power-of-two alignment are both invalid layouts.
    // SAFETY: no allocation is performed for either.
    let zero = unsafe { narf_kmalloc(0, 8) };
    // SAFETY: as above.
    let bad_align = unsafe { narf_kmalloc(64, 3) };
    // SAFETY: null is documented as a no-op.
    unsafe { narf_kfree(core::ptr::null_mut(), 64, 8) };

    if readback != 0xA5 {
        return TestResult::Fail("kmalloc'd memory did not hold what was written");
    }
    if !zero.is_null() || !bad_align.is_null() {
        return TestResult::Fail("narf_kmalloc accepted an invalid layout");
    }
    TestResult::Pass
}
kernel_test_in!("modules/kabi", smoke_kabi_kmalloc_round_trip);
