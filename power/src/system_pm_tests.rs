use super::*;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use core::task::{Context, Poll, Waker};
use narf_kernel_test::{kernel_test_in, TestResult};

struct TargetDriver {
    order: Arc<AtomicU64>,
    target: Arc<AtomicU8>,
    id: u8,
    fail: bool,
}

fn record(order: &AtomicU64, value: u8) {
    let _ = order.fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
        Some((old << 4) | u64::from(value))
    });
}

impl AsyncSystemPm for TargetDriver {
    fn prepare_suspend<'a>(&'a self) -> SystemPmFuture<'a> {
        Box::pin(async { Err(DevicePmError::DriverError) })
    }

    fn prepare_suspend_target<'a>(&'a self, target: SystemSleepState) -> SystemPmFuture<'a> {
        Box::pin(async move {
            self.target.store(
                match target {
                    SystemSleepState::S0Idle => 1,
                    SystemSleepState::S3 => 3,
                },
                Ordering::Release,
            );
            record(&self.order, self.id);
            if self.fail {
                Err(DevicePmError::Busy)
            } else {
                Ok(())
            }
        })
    }

    fn resume_from_suspend<'a>(&'a self) -> SystemPmFuture<'a> {
        Box::pin(async {
            record(&self.order, self.id + 8);
            Ok(())
        })
    }
}

struct LegacyDriver(Arc<AtomicU64>);

impl AsyncSystemPm for LegacyDriver {
    fn prepare_suspend<'a>(&'a self) -> SystemPmFuture<'a> {
        Box::pin(async {
            record(&self.0, 3);
            Ok(())
        })
    }
    fn resume_from_suspend<'a>(&'a self) -> SystemPmFuture<'a> {
        Box::pin(async {
            record(&self.0, 11);
            Ok(())
        })
    }
}

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let mut cx = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("self-contained PM callback fixture unexpectedly waited"),
    }
}

fn actual_sleep_target_preserves_prepare_resume_order_and_legacy_callbacks() -> TestResult {
    for target in [SystemSleepState::S0Idle, SystemSleepState::S3] {
        let order = Arc::new(AtomicU64::new(0));
        let observed = Arc::new(AtomicU8::new(0));
        let entries = alloc::vec![
            Entry {
                name: String::from("parent"),
                ops: Arc::new(TargetDriver {
                    order: order.clone(),
                    target: observed.clone(),
                    id: 1,
                    fail: false
                }),
            },
            Entry {
                name: String::from("legacy"),
                ops: Arc::new(LegacyDriver(order.clone()))
            },
            Entry {
                name: String::from("child"),
                ops: Arc::new(TargetDriver {
                    order: order.clone(),
                    target: observed.clone(),
                    id: 2,
                    fail: false
                }),
            },
        ];
        let transition = ready(prepare_entries(entries, target));
        let expected_target = if target == SystemSleepState::S0Idle {
            1
        } else {
            3
        };
        if !transition.succeeded()
            || observed.load(Ordering::Acquire) != expected_target
            || order.load(Ordering::Acquire) != 0x231
        {
            return TestResult::Fail("actual target or child-to-parent preparation was lost");
        }
        if !ready(transition.resume()).is_empty() || order.load(Ordering::Acquire) != 0x2319ba {
            return TestResult::Fail("target-aware prepare changed paired parent-to-child resume");
        }
    }
    let order = Arc::new(AtomicU64::new(0));
    let target = Arc::new(AtomicU8::new(0));
    let entries = alloc::vec![
        Entry {
            name: String::from("failing-parent"),
            ops: Arc::new(TargetDriver {
                order: order.clone(),
                target: target.clone(),
                id: 1,
                fail: true
            }),
        },
        Entry {
            name: String::from("prepared-child"),
            ops: Arc::new(TargetDriver {
                order: order.clone(),
                target,
                id: 2,
                fail: false
            }),
        },
    ];
    let transition = ready(prepare_entries(entries, SystemSleepState::S0Idle));
    if transition.succeeded()
        || transition.failure().map(|failure| failure.name.as_str()) != Some("failing-parent")
        || !ready(transition.resume()).is_empty()
        || order.load(Ordering::Acquire) != 0x21a
    {
        return TestResult::Fail(
            "target-aware failure resumed an unprepared driver or lost rollback order",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/system_pm",
    actual_sleep_target_preserves_prepare_resume_order_and_legacy_callbacks
);
