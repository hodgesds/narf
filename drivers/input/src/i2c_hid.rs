//! I2C HID Input driver — clean-room.
//!
//! Spec: "HID Over I2C Protocol Specification" (Microsoft).
//! Supports touchpads and keyboards over I2C/I3C using the HID standard.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use async_trait::async_trait;
use narf_drivers::core::{Driver, DriverEnv, DriverError, DriverFuture};
use narf_i3c::{I3cBus, I3cError, I3cOp};
use narf_input::{push_global, InputEvent, KeyCode, KeyEvent, PointerEvent};

pub struct I2cHidDriver {
    bus: Arc<dyn I3cBus>,
    addr: u8,
    hid_desc_register: u16,
}

impl I2cHidDriver {
    pub fn new(bus: Arc<dyn I3cBus>, addr: u8, hid_desc_register: u16) -> Self {
        Self {
            bus,
            addr,
            hid_desc_register,
        }
    }

    async fn read_report(&self) -> Result<Vec<u8>, I3cError> {
        // Implementation for Stage 5: Read HID report.
        let mut buf = [0u8; 64];
        let mut ops = [I3cOp::Read(&mut buf)];
        self.bus.transfer(self.addr, &mut ops).await?;
        Ok(buf.to_vec())
    }
}

impl Driver for I2cHidDriver {
    fn start<'a>(&'a mut self, _env: DriverEnv<'a>) -> DriverFuture<'a> {
        Box::pin(async move {
            // 1. Read HID Descriptor.
            // 2. Initialise device.
            Ok(())
        })
    }

    fn quiesce<'a>(&'a mut self) -> DriverFuture<'a> {
        Box::pin(async move { Ok(()) })
    }
}

pub fn register_initcalls() {
    // Discovery via ACPI/DTB lands in Stage 5.
}
