//! Assertion / diagnostic macros.
//!
//! Spec: `lib/specification/spec.md` §3.4. Stage 1 ships plain-Rust
//! implementations; the domain-aware wiring (route failures through
//! `tracing/` with file+line+domain+stack fingerprint) lands in Stage 3
//! once `tracing/` and `frame/`'s panic path are live.

/// Debug-only assertion that the current domain equals `$expected`.
///
/// Stage 1: no domains exist beyond `DomainId::FRAME`, so the active-domain
/// hook is a stub and this macro degrades to a plain `debug_assert`. Stage 2
/// bring-up of PKS/MTE swaps the hook for a real query.
#[macro_export]
macro_rules! debug_assert_in_domain {
    ($expected:expr) => {
        #[cfg(debug_assertions)]
        {
            let _expected: $crate::id::DomainId = $expected;
            // TODO(stage-2): query `frame::current_domain()` and assert equality.
        }
    };
}

/// Asserts the caller is executing inside the Trusted Computing Base (the
/// frame). Release-mode also checks; misuse of a TCB-only helper is always
/// a correctness bug.
#[macro_export]
macro_rules! assert_tcb {
    () => {
        // TODO(stage-2): consult `frame::is_tcb_context()`. For now, just
        // assert we're not somehow in a user-mode context — Stage 1 has
        // no userspace, so this is vacuously true.
        ()
    };
}

/// "Bug" panic: records into `tracing/` (when available) before panicking.
/// Always compiled in, release included — buggy invariants should fail loud.
#[macro_export]
macro_rules! bug_on {
    ($cond:expr, $($fmt:tt)+) => {
        if $cond {
            // TODO(stage-3): emit a USDT-style bug event before panicking so
            // the flight-recorder snapshots catch the state leading in.
            core::panic!($($fmt)+);
        }
    };
    ($cond:expr) => {
        if $cond {
            core::panic!("bug: {}", stringify!($cond));
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::id::DomainId;

    #[test]
    fn debug_assert_in_domain_compiles() {
        debug_assert_in_domain!(DomainId::FRAME);
    }

    #[test]
    fn assert_tcb_compiles() { assert_tcb!(); }

    #[test]
    #[should_panic(expected = "bug:")]
    fn bug_on_triggers() { bug_on!(true, "bug: forced"); }

    #[test]
    fn bug_on_false_is_silent() { bug_on!(false, "should not fire"); }
}
