//! ACPI Embedded Controller (EC) driver — clean-room.
//!
//! Spec: ACPI 6.5 §12.3 (Embedded Controller Interface).
//! The EC is the gatekeeper for laptop-specific hardware: battery, AC,
//! thermal zones, and FN keys.

use alloc::boxed::Box;
use narf_drivers::core::{Driver, DriverEnv, DriverError, DriverFuture};
use narf_lib::sync::IrqSafeSpinLock;

// ── Standard EC Ports (ACPI §12.3) ──────────────────────────────────
pub const EC_DATA_PORT: u16 = 0x62;
pub const EC_COMMAND_PORT: u16 = 0x66;
pub const EC_STATUS_PORT: u16 = 0x66;

// ── EC Commands ─────────────────────────────────────────────────────
const EC_CMD_READ: u8 = 0x80;
const EC_CMD_WRITE: u8 = 0x81;
const EC_CMD_QUERY: u8 = 0x84; // Query SCI event

// ── Status Bits ─────────────────────────────────────────────────────
const EC_STS_OBF: u8 = 1 << 0; // Output buffer full
const EC_STS_IBF: u8 = 1 << 1; // Input buffer full
const EC_STS_SCI: u8 = 1 << 5; // SCI event pending

pub struct AcpiEc {
    control_port: u16,
    data_port: u16,
}

impl AcpiEc {
    pub const fn new(control_port: u16, data_port: u16) -> Self {
        Self {
            control_port,
            data_port,
        }
    }

    /// Wait for the Input Buffer to be empty.
    fn wait_ibf_empty(&self) -> Result<(), DriverError> {
        for _ in 0..100_000 {
            // SAFETY: validated EC status port from ECDT or standard base.
            let sts = unsafe { narf_arch::x86_64::io::in8(self.control_port) };
            if sts & EC_STS_IBF == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(DriverError::Timeout)
    }

    /// Wait for the Output Buffer to be full.
    fn wait_obf_full(&self) -> Result<(), DriverError> {
        for _ in 0..100_000 {
            let sts = unsafe { narf_arch::x86_64::io::in8(self.control_port) };
            if sts & EC_STS_OBF != 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(DriverError::Timeout)
    }

    pub fn read_byte(&self, addr: u8) -> Result<u8, DriverError> {
        self.wait_ibf_empty()?;
        unsafe {
            narf_arch::x86_64::io::out8(self.control_port, EC_CMD_READ);
        }
        self.wait_ibf_empty()?;
        unsafe {
            narf_arch::x86_64::io::out8(self.data_port, addr);
        }
        self.wait_obf_full()?;
        Ok(unsafe { narf_arch::x86_64::io::in8(self.data_port) })
    }

    pub fn write_byte(&self, addr: u8, val: u8) -> Result<(), DriverError> {
        self.wait_ibf_empty()?;
        unsafe {
            narf_arch::x86_64::io::out8(self.control_port, EC_CMD_WRITE);
        }
        self.wait_ibf_empty()?;
        unsafe {
            narf_arch::x86_64::io::out8(self.data_port, addr);
        }
        self.wait_ibf_empty()?;
        unsafe {
            narf_arch::x86_64::io::out8(self.data_port, val);
        }
        Ok(())
    }
}

impl Driver for AcpiEc {
    fn start<'a>(&'a mut self, _env: DriverEnv<'a>) -> DriverFuture<'a> {
        Box::pin(async move {
            // In a real system, we'd check ECDT or AML here.
            // For now, we just expose the primitives.
            Ok(())
        })
    }

    fn quiesce<'a>(&'a mut self) -> DriverFuture<'a> {
        Box::pin(async move { Ok(()) })
    }
}

static GLOBAL_EC: IrqSafeSpinLock<Option<AcpiEc>> = IrqSafeSpinLock::new(None);

pub fn init() {
    let (ctrl, data) = if let Some(info) = narf_acpi::ecdt_info() {
        (info.control_port, info.data_port)
    } else {
        (EC_COMMAND_PORT, EC_DATA_PORT)
    };
    *GLOBAL_EC.lock() = Some(AcpiEc::new(ctrl, data));
}

pub fn with_ec<R>(f: impl FnOnce(&AcpiEc) -> R) -> Option<R> {
    GLOBAL_EC.lock().as_ref().map(f)
}
