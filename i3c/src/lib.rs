#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use async_trait::async_trait;
use core::task::Waker;
use narf_capabilities::{CapKind, CapType};

pub mod registry;
pub mod types;

pub use types::{I3cError, I3cOp, IbiPayload};

/// A specialized capability for I3C operations.
#[derive(Debug)]
pub enum I3cRight {
    /// Allows reading from a specific device.
    Read(u8),
    /// Allows writing to a specific device.
    Write(u8),
    /// Allows receiving In-Band Interrupts.
    Notify(u8),
    /// Full bus management (Dynamic Address Assignment, etc.)
    Admin,
}

#[derive(Copy, Clone, Debug)]
pub struct I3cCapType;

impl CapType for I3cCapType {
    const KIND: CapKind = CapKind::I3cBus;
}

/// A specialized I3C bus interface.
#[async_trait]
pub trait I3cBus: Send + Sync {
    /// Performs a transfer to/from a specific target device.
    async fn transfer(&self, addr: u8, ops: &mut [I3cOp]) -> Result<(), I3cError>;

    /// Registers an async waker for an In-Band Interrupt (IBI).
    fn register_ibi_waker(&self, addr: u8, waker: Waker);

    /// Unregisters an async waker.
    fn unregister_ibi_waker(&self, addr: u8);
}

/// Force-link hook.
pub fn register_initcalls() {}

// ── Smoke Tests ───────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::sync::IrqSafeSpinLock;

    struct MockI3c {
        transfers: IrqSafeSpinLock<Vec<u8>>,
    }

    #[async_trait]
    impl I3cBus for MockI3c {
        async fn transfer(&self, addr: u8, ops: &mut [I3cOp]) -> Result<(), I3cError> {
            self.transfers.lock().push(addr);
            for op in ops {
                match op {
                    I3cOp::Write(data) => self.transfers.lock().extend_from_slice(data),
                    I3cOp::Read(buf) => {
                        for i in 0..buf.len() {
                            buf[i] = 0x55;
                        }
                    }
                }
            }
            Ok(())
        }

        fn register_ibi_waker(&self, _addr: u8, _waker: Waker) {}
        fn unregister_ibi_waker(&self, _addr: u8) {}
    }

    fn smoke_i3c_transfer() -> TestResult {
        narf_scheduler::__reset_queues_for_test();
        let mock = Arc::new(MockI3c {
            transfers: IrqSafeSpinLock::new(Vec::new()),
        });
        let success = Arc::new(core::sync::atomic::AtomicU32::new(0));

        let m = mock.clone();
        let s = success.clone();
        narf_scheduler::spawn(async move {
            let mut data = [0u8; 4];
            let mut ops = [I3cOp::Write(&[0x1, 0x2]), I3cOp::Read(&mut data)];
            m.transfer(0x08, &mut ops).await.expect("transfer failed");
            if data[0] == 0x55 {
                s.store(1, core::sync::atomic::Ordering::SeqCst);
            }
        });

        narf_scheduler::run_until_empty();
        if success.load(core::sync::atomic::Ordering::SeqCst) == 1 {
            TestResult::Pass
        } else {
            TestResult::Fail("transfer check failed")
        }
    }
    kernel_test_in!("i3c", smoke_i3c_transfer);

    fn smoke_i3c_cap_kind() -> TestResult {
        use narf_capabilities::CapType;
        if matches!(I3cCapType::KIND, CapKind::I3cBus) {
            TestResult::Pass
        } else {
            TestResult::Fail("cap kind mismatch")
        }
    }
    kernel_test_in!("i3c", smoke_i3c_cap_kind);

    fn smoke_i3c_error_variants_distinct() -> TestResult {
        let all = [
            I3cError::NoDevice,
            I3cError::BusBusy,
            I3cError::Timeout,
            I3cError::Nack,
            I3cError::CrcError,
            I3cError::Denied,
            I3cError::InvalidArgs,
            I3cError::HardwareError,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j && a == b {
                    return TestResult::Fail("I3cError variants collapsed");
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("i3c", smoke_i3c_error_variants_distinct);

    fn smoke_i3c_mock_read_op_fills_buf_from_mock() -> TestResult {
        // The MockI3c here writes 0x55 to every Read byte. Exercise
        // an end-to-end Write-then-Read transfer and assert the
        // Write tail landed in `transfers` while the Read buf was
        // populated.
        narf_scheduler::__reset_queues_for_test();
        let mock = Arc::new(MockI3c {
            transfers: IrqSafeSpinLock::new(Vec::new()),
        });
        let ok = Arc::new(core::sync::atomic::AtomicBool::new(false));
        let m = mock.clone();
        let o = ok.clone();
        narf_scheduler::spawn(async move {
            let mut rbuf = [0u8; 3];
            let mut ops = [I3cOp::Write(&[0xAB, 0xCD]), I3cOp::Read(&mut rbuf)];
            if m.transfer(0x42, &mut ops).await.is_ok()
                && rbuf == [0x55, 0x55, 0x55]
            {
                o.store(true, core::sync::atomic::Ordering::SeqCst);
            }
        });
        narf_scheduler::run_until_empty();
        if !ok.load(core::sync::atomic::Ordering::SeqCst) {
            return TestResult::Fail("Write-Read round-trip didn't complete");
        }
        // Mock pushed addr then write bytes into transfers.
        let log = mock.transfers.lock();
        if log.len() < 3 || log[0] != 0x42 || log[1] != 0xAB || log[2] != 0xCD {
            return TestResult::Fail("Write tail not recorded by mock");
        }
        TestResult::Pass
    }
    kernel_test_in!("i3c", smoke_i3c_mock_read_op_fills_buf_from_mock);

    fn smoke_i3c_ibi_payload_field_round_trip() -> TestResult {
        let p = IbiPayload {
            addr: 0x3C,
            data: alloc::vec![0xDE, 0xAD],
        };
        if p.addr != 0x3C {
            return TestResult::Fail("IbiPayload.addr round-trip");
        }
        if p.data != alloc::vec![0xDE, 0xAD] {
            return TestResult::Fail("IbiPayload.data round-trip");
        }
        TestResult::Pass
    }
    kernel_test_in!("i3c", smoke_i3c_ibi_payload_field_round_trip);
}
