//! I2C HID Input driver — clean-room.
//!
//! Spec: "HID Over I2C Protocol Specification" (Microsoft).
//! Supports touchpads and keyboards over I2C/I3C using the HID standard.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;
use narf_drivers::{Driver, DriverEnv, DriverFuture};
use narf_i3c::{I3cBus, I3cError, I3cOp};

pub struct I2cHidDriver {
    bus: Arc<dyn I3cBus>,
    addr: u8,
    hid_desc_register: u16,
}

impl core::fmt::Debug for I2cHidDriver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("I2cHidDriver")
            .field("addr", &self.addr)
            .field("hid_desc_register", &self.hid_desc_register)
            .finish_non_exhaustive()
    }
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
        })
    }

    fn quiesce<'a>(&'a mut self) -> DriverFuture<'a> {
        Box::pin(async move {})
    }
}

pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Device, "i2c-hid-probe", || {
        if let Some(device) = narf_aml::find_device_by_hid("PNP0C50") {
            let _ = writeln!(
                narf_console::Writer,
                "  i2c-hid: found {} via AML, initialization deferred to Stage 5",
                device.path
            );
            // In a real system, we'd find the parent I2C bus and bind.
            InitResult::Ok
        } else {
            InitResult::NotPresent
        }
    });
}
