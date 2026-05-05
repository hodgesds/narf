#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use alloc::boxed::Box;
use async_trait::async_trait;
use narf_capabilities::{CapType, CapKind};
use core::task::Waker;

pub mod types;
pub mod registry;

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
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::sync::IrqSafeSpinLock;
    use alloc::sync::Arc;

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
                        for i in 0..buf.len() { buf[i] = 0x55; }
                    }
                }
            }
            Ok(())
        }

        fn register_ibi_waker(&self, _addr: u8, _waker: Waker) {}
        fn unregister_ibi_waker(&self, _addr: u8) {}
    }

    fn smoke_i3c_transfer() -> TestResult {
        narf_scheduler::init();
        let mock = Arc::new(MockI3c { transfers: IrqSafeSpinLock::new(Vec::new()) });
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
        if success.load(core::sync::atomic::Ordering::SeqCst) == 1 { TestResult::Pass }
        else { TestResult::Fail("transfer check failed") }
    }
    kernel_test_in!("i3c", smoke_i3c_transfer);

    fn smoke_i3c_cap_kind() -> TestResult {
        use narf_capabilities::CapType;
        if matches!(I3cCapType::KIND, CapKind::I3cBus) { TestResult::Pass }
        else { TestResult::Fail("cap kind mismatch") }
    }
    kernel_test_in!("i3c", smoke_i3c_cap_kind);
}
