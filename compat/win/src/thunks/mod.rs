//! Win32 API thunk dispatch.
//!
//! ## ABI
//!
//! Each Win32 API we implement is a single Rust function declared
//! with the per-arch Win32 calling convention:
//!
//! - **amd64:** `extern "win64"` — Microsoft x64 ABI. First four
//!   args in `rcx, rdx, r8, r9`; further args at `[rsp+0x28..]`
//!   (caller pre-reserves a 32-byte shadow space). The compiler
//!   emits the right prologue / shadow-space handling automatically;
//!   no naked-asm trampoline is required.
//! - **aarch64:** `extern "C"` — `extern "C"` on aarch64 targets is
//!   AAPCS64, which is also Win32 ARM64's calling convention. A
//!   thunk entry on aarch64 is therefore a direct branch from the
//!   PE caller; no register shuffle is needed.
//!
//! ## IAT patching
//!
//! Each `Thunk` exposes `entry_addr()` returning the address of
//! its entry function as a `u64`. The PE loader's import resolver
//! looks up `(module, symbol)` in the registry, takes that address,
//! and writes it into the IAT slot — `call qword ptr [iat]` from a
//! PE binary then lands directly on the Rust function with arguments
//! already in the right registers.
//!
//! The previous skeleton used a `ThunkRegs` struct + a generic
//! `unsafe fn invoke(&self, regs: &mut ThunkRegs)` indirection. That
//! shape can't carry stack-passed args without per-thunk naked asm,
//! so we dropped it before it ossified — each thunk is now a typed
//! Rust function with the actual Win32 signature.

use core::sync::atomic::{AtomicPtr, Ordering};

pub mod kernel32;

pub trait Thunk: Send + Sync + core::fmt::Debug {
    /// `(module, symbol)`, both lowercase ASCII. Win32 imports are
    /// case-insensitive; the dispatcher canonicalises lookups so
    /// PE imports written as `KERNEL32.DLL!ExitProcess` match a
    /// thunk registered as `("kernel32.dll", "exitprocess")`.
    fn name(&self) -> (&'static str, &'static str);

    /// Address of the per-arch entry function — the value the PE
    /// loader patches into the IAT slot. Cast back from a typed
    /// `extern "win64" fn(...)` (amd64) or `extern "C" fn(...)`
    /// (aarch64) pointer.
    fn entry_addr(&self) -> u64;
}

/// Thunk registry: install-once at boot, read-only afterwards. M0
/// uses a single static slice; M1 will move to a hash-keyed table
/// when the API set grows past a few dozen entries.
static REGISTRY: AtomicPtr<&'static [&'static dyn Thunk]> =
    AtomicPtr::new(core::ptr::null_mut());

/// Install the canonical thunk table. Called once per boot from
/// the kernel's per-arch init, *before* any PE image is loaded.
/// Idempotent within a boot — re-installing the same table is fine;
/// installing a different one is the caller's problem.
pub fn install_registry(table: &'static &'static [&'static dyn Thunk]) {
    REGISTRY.store(
        table as *const _ as *mut _,
        Ordering::Release,
    );
}

/// Look up a thunk by `(module, symbol)`. Returns `None` if the
/// import is not implemented; callers map `None` to a load-time
/// `LoadError::UnresolvedImport` rather than installing a silent
/// stub.
pub fn dispatch_thunk(module: &str, symbol: &str) -> Option<&'static dyn Thunk> {
    let ptr = REGISTRY.load(Ordering::Acquire);
    if ptr.is_null() {
        return None;
    }
    // SAFETY: `install_registry` only stores `&'static` references;
    // once non-null, the pointee lives forever and is read-only.
    let table: &'static [&'static dyn Thunk] = unsafe { *(ptr as *const _) };
    for t in table {
        let (m, s) = t.name();
        if m.eq_ignore_ascii_case(module) && s.eq_ignore_ascii_case(symbol) {
            return Some(*t);
        }
    }
    None
}

/// Convenience wrapper used by the PE loader as the default import
/// resolver: `dispatch_thunk(module, symbol).map(|t| t.entry_addr())`.
pub fn resolve_addr(module: &str, symbol: &str) -> Option<u64> {
    dispatch_thunk(module, symbol).map(|t| t.entry_addr())
}

/// Helper macro: declare a per-thunk entry function with the right
/// per-arch ABI, plus a `Thunk` impl whose `entry_addr` returns
/// that function's address.
///
/// Usage:
/// ```ignore
/// win_thunk! {
///     name = ("kernel32.dll", "exitprocess");
///     struct ExitProcess;
///     extern fn entry(code: u32) -> ! { loop { core::hint::spin_loop(); } }
/// }
/// ```
#[macro_export]
macro_rules! win_thunk {
    (
        name = ($module:literal, $symbol:literal);
        struct $ty:ident;
        extern fn $entry:ident ( $($arg:ident : $aty:ty),* $(,)? ) $(-> $ret:ty)? $body:block
    ) => {
        #[cfg(target_arch = "x86_64")]
        extern "win64" fn $entry ( $($arg : $aty),* ) $(-> $ret)? $body

        #[cfg(target_arch = "aarch64")]
        extern "C" fn $entry ( $($arg : $aty),* ) $(-> $ret)? $body

        // Fallback ABI for hosts that aren't amd64/aarch64 (e.g.
        // running cargo test on an ARM Mac wouldn't hit "win64",
        // and a hypothetical RISC-V host wouldn't hit either).
        // The fallback never gets called from a real PE — only the
        // unit tests touch the entry directly, so a host C ABI is
        // safe for that path.
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        extern "C" fn $entry ( $($arg : $aty),* ) $(-> $ret)? $body

        #[derive(Debug)]
        pub struct $ty;
        impl $crate::thunks::Thunk for $ty {
            fn name(&self) -> (&'static str, &'static str) { ($module, $symbol) }
            fn entry_addr(&self) -> u64 { $entry as u64 }
        }
    };
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec;
    use super::*;

    static TABLE: &[&dyn Thunk] = kernel32::KERNEL32_THUNKS;

    fn ensure_registered() {
        // install_registry is idempotent within a boot; tests may
        // run in any order, so we re-install on every test entry.
        // Storing the same pointer repeatedly is a no-op effect.
        static REF: &&[&dyn Thunk] = &TABLE;
        install_registry(REF);
    }

    #[test]
    fn dispatch_canonicalises_case() {
        ensure_registered();
        let t1 = dispatch_thunk("KERNEL32.DLL", "ExitProcess").expect("found");
        let t2 = dispatch_thunk("kernel32.dll", "exitprocess").expect("found");
        assert_eq!(t1.entry_addr(), t2.entry_addr());
    }

    #[test]
    fn dispatch_misses_unknown() {
        ensure_registered();
        assert!(dispatch_thunk("kernel32.dll", "createfilew").is_none());
        assert!(dispatch_thunk("ntdll.dll", "ntwritefile").is_none());
    }

    #[test]
    fn entry_addrs_distinct_across_thunks() {
        ensure_registered();
        let mut seen = vec![];
        for t in TABLE {
            let a = t.entry_addr();
            assert!(a != 0, "{:?} has zero entry_addr", t.name());
            assert!(!seen.contains(&a), "{:?} duplicates entry_addr {:#x}", t.name(), a);
            seen.push(a);
        }
    }
}
