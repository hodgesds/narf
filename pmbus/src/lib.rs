#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use async_trait::async_trait;
use narf_capabilities::{CapKind, CapType};

pub mod types;

pub use types::{PmBusError, PowerReading};

/// A specialized capability for PMBus operations.
#[derive(Debug)]
pub enum PmBusRight {
    /// Allows reading telemetry (voltage, current, power).
    Read,
    /// Allows configuring thresholds and limits.
    Config,
    /// Allows administrative operations (calibration, inventory).
    Admin,
}

#[derive(Copy, Clone, Debug)]
pub struct PmBusCapType;

impl CapType for PmBusCapType {
    const KIND: CapKind = CapKind::PmBus;
}

/// A specialized PMBus monitor interface.
#[async_trait]
pub trait PmBusMonitor: Send + Sync {
    /// Returns static information about the power device.
    fn get_info(&self) -> PmBusInfo;

    /// Reads real-time power telemetry.
    async fn read_telemetry(&self) -> Result<PowerReading, PmBusError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PmBusInfo {
    pub manufacturer: Vec<u8>,
    pub model: Vec<u8>,
    pub revision: u8,
}

/// Force-link hook.
pub fn register_initcalls() {}

// ── Smoke Tests ───────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct MockPmBus {
        reads: AtomicU32,
    }

    #[async_trait]
    impl PmBusMonitor for MockPmBus {
        fn get_info(&self) -> PmBusInfo {
            PmBusInfo {
                manufacturer: alloc::vec![b'N', b'A', b'R', b'F'],
                model: alloc::vec![b'P', b'S', b'U'],
                revision: 1,
            }
        }

        async fn read_telemetry(&self) -> Result<PowerReading, PmBusError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(PowerReading {
                voltage_mv: 12000,
                current_ma: 5000,
                power_mw: 60000,
                temp_mc: 35000,
            })
        }
    }

    fn smoke_pmbus_read_cycle() -> TestResult {
        narf_scheduler::__reset_queues_for_test();
        let mock = Arc::new(MockPmBus {
            reads: AtomicU32::new(0),
        });
        let success = Arc::new(core::sync::atomic::AtomicBool::new(false));

        let m = mock.clone();
        let s = success.clone();
        narf_scheduler::spawn(async move {
            let res = m.read_telemetry().await.expect("read_telemetry failed");
            if res.voltage_mv == 12000 && res.power_mw == 60000 {
                s.store(true, Ordering::SeqCst);
            }
        });

        narf_scheduler::run_until_empty();
        if success.load(Ordering::SeqCst) {
            TestResult::Pass
        } else {
            TestResult::Fail("pmbus telemetry read failed")
        }
    }
    kernel_test_in!("pmbus", smoke_pmbus_read_cycle);

    fn smoke_pmbus_cap_kind() -> TestResult {
        use narf_capabilities::CapType;
        if matches!(PmBusCapType::KIND, CapKind::PmBus) {
            TestResult::Pass
        } else {
            TestResult::Fail("cap kind mismatch")
        }
    }
    kernel_test_in!("pmbus", smoke_pmbus_cap_kind);
}
