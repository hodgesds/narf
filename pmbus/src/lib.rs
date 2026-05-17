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

    fn smoke_pmbus_error_variants_distinct() -> TestResult {
        let all = [
            PmBusError::NotPresent,
            PmBusError::Timeout,
            PmBusError::Nack,
            PmBusError::CrcError,
            PmBusError::InvalidArgs,
            PmBusError::Denied,
            PmBusError::HardwareError,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j && a == b {
                    return TestResult::Fail("PmBusError variants collapsed");
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("pmbus", smoke_pmbus_error_variants_distinct);

    fn smoke_pmbus_power_reading_field_round_trip() -> TestResult {
        let r = PowerReading {
            voltage_mv: 12_345,
            current_ma: 6_789,
            power_mw: 80_000,
            temp_mc: -25_000,
        };
        if r.voltage_mv != 12_345
            || r.current_ma != 6_789
            || r.power_mw != 80_000
            || r.temp_mc != -25_000
        {
            return TestResult::Fail("PowerReading fields didn't round-trip");
        }
        // Clone preserves all four fields.
        let c = r.clone();
        if c.voltage_mv != r.voltage_mv
            || c.current_ma != r.current_ma
            || c.power_mw != r.power_mw
            || c.temp_mc != r.temp_mc
        {
            return TestResult::Fail("PowerReading Clone dropped a field");
        }
        TestResult::Pass
    }
    kernel_test_in!("pmbus", smoke_pmbus_power_reading_field_round_trip);

    fn smoke_pmbus_info_field_round_trip() -> TestResult {
        let info = PmBusInfo {
            manufacturer: alloc::vec![b'X', b'Y', b'Z'],
            model: alloc::vec![b'9', b'0'],
            revision: 7,
        };
        if info.manufacturer != alloc::vec![b'X', b'Y', b'Z'] {
            return TestResult::Fail("manufacturer round-trip");
        }
        if info.model != alloc::vec![b'9', b'0'] {
            return TestResult::Fail("model round-trip");
        }
        if info.revision != 7 {
            return TestResult::Fail("revision round-trip");
        }
        // Eq derives field-wise.
        let other = PmBusInfo {
            manufacturer: alloc::vec![b'X', b'Y', b'Z'],
            model: alloc::vec![b'9', b'0'],
            revision: 8,
        };
        if info == other {
            return TestResult::Fail("Eq ignored revision");
        }
        TestResult::Pass
    }
    kernel_test_in!("pmbus", smoke_pmbus_info_field_round_trip);
}
