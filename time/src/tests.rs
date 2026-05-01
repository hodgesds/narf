//! Subsystem smokes for `narf-time`.
//!
//! Migrated from `narf-verification`. Tests register under the
//! `time` subsystem.
//!
//! Note: `smoke_sleep_future_waits` was *not* migrated here because
//! it depends on `narf-scheduler`, which is downstream of `narf-time`
//! and cannot be added without forming a cycle. That smoke remains in
//! the verification mega-lib (or should move into a scheduler-side
//! `tests.rs`).

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_monotonic_advances() -> TestResult {
    let a = crate::now_cycles();
    for _ in 0..100_000 { core::hint::spin_loop(); }
    let b = crate::now_cycles();
    if b > a { TestResult::Pass } else { TestResult::Fail("monotonic counter didn't advance") }
}
kernel_test_in!("time", smoke_monotonic_advances);
