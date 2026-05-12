//! narf-scmi — ARM System Control and Management Interface.
//!
//! Spec: `scmi/specification/spec.md`.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use alloc::boxed::Box;
use async_trait::async_trait;
use narf_capabilities::{CapKind, CapType};

/// SCMI Capability Type.
#[derive(Debug, Clone, Copy)]
pub struct ScmiCapType;

impl CapType for ScmiCapType {
    const KIND: CapKind = CapKind::Scmi;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScmiError {
    NotSupported,
    InvalidParameters,
    Denied,
    NotFound,
    ProtocolError,
    TransportError,
}

#[derive(Debug, Clone, Copy)]
pub struct ClockAttributes {
    pub enabled: bool,
    pub name: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct PowerDomainAttributes {
    pub name: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct PerfAttributes {
    pub name: &'static str,
}

/// SCMI Clock Management trait.
#[async_trait]
pub trait ScmiClock: Send + Sync {
    async fn get_count(&self) -> Result<u32, ScmiError>;
    async fn get_attributes(&self, clock_id: u32) -> Result<ClockAttributes, ScmiError>;
    async fn set_rate(&self, clock_id: u32, rate: u64) -> Result<(), ScmiError>;
    async fn get_rate(&self, clock_id: u32) -> Result<u64, ScmiError>;
    async fn enable(&self, clock_id: u32, enable: bool) -> Result<(), ScmiError>;
}

/// SCMI Power Domain Management trait.
#[async_trait]
pub trait ScmiPowerDomain: Send + Sync {
    async fn get_count(&self) -> Result<u32, ScmiError>;
    async fn get_attributes(&self, domain_id: u32) -> Result<PowerDomainAttributes, ScmiError>;
    async fn set_state(&self, domain_id: u32, state: u32) -> Result<(), ScmiError>;
    async fn get_state(&self, domain_id: u32) -> Result<u32, ScmiError>;
}

/// SCMI Performance State Management trait.
#[async_trait]
pub trait ScmiPerformance: Send + Sync {
    async fn get_count(&self) -> Result<u32, ScmiError>;
    async fn get_attributes(&self, domain_id: u32) -> Result<PerfAttributes, ScmiError>;
    async fn set_level(&self, domain_id: u32, level: u32) -> Result<(), ScmiError>;
    async fn get_level(&self, domain_id: u32) -> Result<u32, ScmiError>;
}

/// Force-link hook.
pub fn register_initcalls() {}

// ── Smoke Tests ───────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct MockScmi;

    #[async_trait]
    impl ScmiClock for MockScmi {
        async fn get_count(&self) -> Result<u32, ScmiError> {
            Ok(2)
        }
        async fn get_attributes(&self, _clock_id: u32) -> Result<ClockAttributes, ScmiError> {
            Ok(ClockAttributes {
                enabled: true,
                name: "mock-clk",
            })
        }
        async fn set_rate(&self, _clock_id: u32, _rate: u64) -> Result<(), ScmiError> {
            Ok(())
        }
        async fn get_rate(&self, _clock_id: u32) -> Result<u64, ScmiError> {
            Ok(100_000_000)
        }
        async fn enable(&self, _clock_id: u32, _enable: bool) -> Result<(), ScmiError> {
            Ok(())
        }
    }

    fn smoke_scmi_async_mock() -> TestResult {
        narf_scheduler::__reset_queues_for_test();
        let success = Arc::new(AtomicUsize::new(0));
        let s = success.clone();

        narf_scheduler::spawn(async move {
            let mock = MockScmi;
            if let Ok(count) = mock.get_count().await {
                if count == 2 {
                    s.fetch_add(1, Ordering::SeqCst);
                }
            }
            if let Ok(rate) = mock.get_rate(0).await {
                if rate == 100_000_000 {
                    s.fetch_add(1, Ordering::SeqCst);
                }
            }
        });

        narf_scheduler::run_until_empty();

        if success.load(Ordering::SeqCst) == 2 {
            TestResult::Pass
        } else {
            TestResult::Fail("SCMI async mock test failed to complete steps")
        }
    }

    kernel_test_in!("scmi", smoke_scmi_async_mock);
}
