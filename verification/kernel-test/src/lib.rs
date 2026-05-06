//! narf-kernel-test — zero-dep kernel-test framework.
//!
//! Holds the `KernelTest` struct, the `kernel_test!` /
//! `kernel_test_in!` macros, the `narf.tests` ELF section
//! collector, and the `TestResult` / `Summary` enums. Driver crates
//! depend on this (rather than `narf-verification`) so they can
//! register their own subsystem-aware smokes without cycling — the
//! higher-level harness (`narf-verification`) re-exports these
//! types and adds the runner that prints results to the console.
//!
//! ## Subsystem awareness
//!
//! Each `KernelTest` carries a `subsystem` string identifying which
//! driver / module / library / feature owns it (e.g.
//! `"drivers/net/r8169"` or `"audio/hda"`). The runner groups output
//! by subsystem so a failure in one subsystem doesn't drown the
//! others. The `kernel_test!(name)` macro defaults the subsystem to
//! `"verification"`; `kernel_test_in!("subsystem", name)` lets a
//! crate set its own.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

/// A single test case. Tests are `fn() -> TestResult` with no
/// arguments — keep them pure so they can be reordered /
/// parallelised later.
#[derive(Copy, Clone)]
pub struct KernelTest {
    pub name: &'static str,
    /// Subsystem path, e.g. `"drivers/net/r8169"`. Used by the
    /// runner to group output and by selectors that want to run
    /// just one subsystem's tests.
    pub subsystem: &'static str,
    pub run: fn() -> TestResult,
}

impl core::fmt::Debug for KernelTest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KernelTest")
            .field("name", &self.name)
            .field("subsystem", &self.subsystem)
            .finish_non_exhaustive()
    }
}

/// Pass / fail / skip, with a static reason string.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TestResult {
    Pass,
    Fail(&'static str),
    Skip(&'static str),
}

/// Summary returned by the runner.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Summary {
    AllOk,
    SomeFailed,
}

// ── test registration via an ELF section ───────────────────────────

extern "Rust" {
    static __narf_tests_start: KernelTest;
    static __narf_tests_end: KernelTest;
}

/// Return a slice over every registered test. Tests land in the
/// `narf.tests` ELF section; the linker synthesises the start / end
/// symbols.
pub fn tests() -> &'static [KernelTest] {
    // SAFETY: the linker synthesises the start/end symbols at the
    // boundaries of the `narf.tests` section. The section contains
    // zero or more `KernelTest` structs and nothing else (the
    // `kernel_test!` / `kernel_test_in!` macros are the only writers).
    let start = unsafe { &__narf_tests_start as *const KernelTest };
    let end = unsafe { &__narf_tests_end as *const KernelTest };
    let len = (end as usize - start as usize) / core::mem::size_of::<KernelTest>();
    // SAFETY: `start` and `len` derived from the linker symbols.
    unsafe { core::slice::from_raw_parts(start, len) }
}

/// Register a test under the default `"verification"` subsystem.
/// Backwards-compatible with the old `kernel_test!` API.
#[macro_export]
macro_rules! kernel_test {
    ($name:ident) => {
        const _: () = {
            #[used]
            #[link_section = "narf.tests"]
            static ENTRY: $crate::KernelTest = $crate::KernelTest {
                name: stringify!($name),
                subsystem: "verification",
                run: $name,
            };
        };
    };
}

/// Register a test under a specific subsystem. Use this from
/// driver / library crates so the runner reports failures grouped
/// by subsystem.
///
/// ```ignore
/// use narf_kernel_test::{kernel_test_in, TestResult};
/// fn smoke_r8169_pci_probe() -> TestResult { TestResult::Pass }
/// kernel_test_in!("drivers/net/r8169", smoke_r8169_pci_probe);
/// ```
#[macro_export]
macro_rules! kernel_test_in {
    ($subsystem:literal, $name:ident) => {
        const _: () = {
            #[used]
            #[link_section = "narf.tests"]
            static ENTRY: $crate::KernelTest = $crate::KernelTest {
                name: stringify!($name),
                subsystem: $subsystem,
                run: $name,
            };
        };
    };
}
