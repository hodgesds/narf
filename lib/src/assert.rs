//! Assertion / diagnostic macros.
//!
//! Spec: `lib/specification/spec.md` §3.4. Stage-3 scope wires these
//! to a real domain-query hook: the TCB (frame/) installs a weak
//! extern that reports the currently-active domain. `lib/` calls it
//! through a safe wrapper (`current_domain()`) that defaults to
//! `DomainId::FRAME` when the hook is absent (host tests, pre-boot
//! bring-up) — the macros never fail to compile, never UB on a
//! missing link.
//!
//! The `tracing/` integration (routing a bug event through a
//! flight-recorder slot before panic) is explicitly deferred. `tracing/`
//! depends on `narf-lib`, so a clean back-edge needs a second weak
//! extern — tracked for Stage-4 once the dependency pattern is
//! formalised.

use crate::id::DomainId;

// ── domain-query hook ──────────────────────────────────────────────
//
// narf-lib cannot depend on narf-arch (arch depends on lib), so the
// current-domain read is a weak extern that narf-arch / narf-frame
// provides at link time. Stage-2 default: returns 0 (DomainId::FRAME).
// Stage-3 full PKS/MTE-aware bring-up hands back the actual PKRU /
// PKRS / TCF view. Matches the narf_arch_cpu_id pattern in percpu.rs.

#[cfg(not(test))]
extern "Rust" {
    fn narf_arch_current_domain() -> u8;
}

/// Current domain as observed by the running task. Safe wrapper: host
/// tests see `DomainId::FRAME`; kernel builds go through the `arch/`
/// hook.
#[inline]
pub fn current_domain() -> DomainId {
    #[cfg(test)]
    {
        DomainId::FRAME
    }
    #[cfg(not(test))]
    {
        // SAFETY: `narf_arch_current_domain` is supplied by narf-arch
        // (or whichever TCB crate owns the domain state) via
        // `#[no_mangle] pub extern "Rust" fn …`. It's a pure read.
        let raw = unsafe { narf_arch_current_domain() };
        DomainId::new(raw)
    }
}

// ── macros ─────────────────────────────────────────────────────────

/// Debug-only assertion that the current domain equals `$expected`.
/// Panics with a message that names both the expected and observed
/// domain so post-mortems don't have to read registers.
#[macro_export]
macro_rules! debug_assert_in_domain {
    ($expected:expr) => {
        #[cfg(debug_assertions)]
        {
            let _expected: $crate::id::DomainId = $expected;
            let _observed = $crate::assert::current_domain();
            if _observed != _expected {
                core::panic!(
                    "domain assertion failed: expected {}, observed {}",
                    _expected.raw(),
                    _observed.raw(),
                );
            }
        }
    };
}

/// Asserts the current domain equals `$expected` in BOTH debug and
/// release builds. Use for invariants where a wrong-domain read / write
/// is a security bug, not just a correctness bug.
#[macro_export]
macro_rules! assert_in_domain {
    ($expected:expr) => {{
        let _expected: $crate::id::DomainId = $expected;
        let _observed = $crate::assert::current_domain();
        if _observed != _expected {
            core::panic!(
                "domain assertion failed: expected {}, observed {}",
                _expected.raw(),
                _observed.raw(),
            );
        }
    }};
}

/// Asserts the caller is executing inside the Trusted Computing Base —
/// i.e. the `DomainId::FRAME` domain. Always-on: a misplaced TCB-only
/// helper is a confused-deputy bug that release-mode should catch.
#[macro_export]
macro_rules! assert_tcb {
    () => {
        $crate::assert_in_domain!($crate::id::DomainId::FRAME);
    };
}

/// "Bug" panic: a panic path reserved for proven-impossible invariants
/// that a defect could reach. Always compiled in, release included —
/// buggy invariants should fail loud. The Stage-4 extension routes a
/// bug event through `tracing/` before panicking so a flight-recorder
/// snapshot captures the lead-in; for Stage 3 we just panic with a
/// domain-tagged message.
#[macro_export]
macro_rules! bug_on {
    ($cond:expr, $($fmt:tt)+) => {
        if $cond {
            let _dom = $crate::assert::current_domain();
            core::panic!("bug in domain {}: {}", _dom.raw(), core::format_args!($($fmt)+));
        }
    };
    ($cond:expr) => {
        if $cond {
            let _dom = $crate::assert::current_domain();
            core::panic!("bug in domain {}: {}", _dom.raw(), stringify!($cond));
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::id::DomainId;

    #[test]
    fn current_domain_stubs_to_frame_in_host_tests() {
        // Host-side: the `#[cfg(test)]` branch in `current_domain`
        // returns FRAME unconditionally. Kernel-mode is exercised by
        // verification/src/lib.rs.
        assert_eq!(super::current_domain(), DomainId::FRAME);
    }

    #[test]
    fn debug_assert_in_domain_passes_on_frame() {
        debug_assert_in_domain!(DomainId::FRAME);
    }

    #[test]
    fn assert_in_domain_passes_on_frame() {
        assert_in_domain!(DomainId::FRAME);
    }

    #[test]
    fn assert_tcb_passes_in_host_tests() { assert_tcb!(); }

    #[test]
    #[should_panic(expected = "bug in domain 0: forced")]
    fn bug_on_triggers_with_domain_tag() { bug_on!(true, "forced"); }

    #[test]
    fn bug_on_false_is_silent() { bug_on!(false, "should not fire"); }

    #[test]
    #[should_panic(expected = "domain assertion failed: expected 1, observed 0")]
    fn assert_in_domain_panics_on_mismatch() {
        assert_in_domain!(DomainId::new(1));
    }
}
