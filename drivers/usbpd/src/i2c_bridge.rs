//! Sync→async I2C bridge for the TCPC chip drivers.
//!
//! The chip-side `I2cBus` trait (see `fusb302::I2cBus`) is sync,
//! because the per-register helpers in `fusb302.rs` / `tps65987.rs`
//! call it once per byte — building a future for every TCPC register
//! poke would mean every helper became `async fn`. The kernel-side
//! controller bus (`narf_drivers_i2c::I2cBus`) is async because the
//! AMD FCH I2C controller is IRQ-driven and the bus mutex serialises
//! concurrent transfers.
//!
//! Bridge: wrap the kernel bus in a sync façade that uses
//! [`narf_scheduler::block_on_spin`] to drive each `transfer` future
//! to completion. Safe at initcall time + from inside the synchronous
//! TCPC chip-init code (no executor poll active). For the eventual
//! TCPM step task — which will run async — the chip driver methods
//! still appear sync, but the underlying bus is the same async one
//! the rest of the kernel uses, so I2C contention is mediated by the
//! same mutex (no parallel-master races).
//!
//! References (public, non-GPL only):
//! - **USB Power Delivery 3.1 v1.8** (USB-IF) — §5.6 BMC framing
//!   (informs the FIFO usage that drives the I2C transfers below).
//!   <https://www.usb.org/document-library/usb-power-delivery>
//!
//! No GPL/BSD source consulted.

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_drivers_i2c::{I2cBus as KernelI2cBus, I2cOp};
use narf_usbpd::tcpc::TcpcError;

use crate::fusb302::I2cBus as ChipI2cBus;

/// Sync façade over an async kernel I2C bus, suitable for passing to
/// `Fusb302::new` / `Tps65987::new`.
#[derive(Debug)]
pub struct KernelBusBridge {
    bus: Arc<dyn KernelI2cBus>,
}

impl KernelBusBridge {
    /// Wrap a kernel I2C bus handle. The same bus may be wrapped in
    /// multiple bridges — the kernel bus's internal mutex serialises
    /// the concurrent transfers.
    pub fn new(bus: Arc<dyn KernelI2cBus>) -> Self {
        Self { bus }
    }

    fn run(&self, addr: u8, ops: &mut [I2cOp<'_>]) -> Result<(), TcpcError> {
        // Drive the async transfer to completion via the scheduler's
        // sync→async bridge. `block_on_spin` panics if called from
        // inside an executor poll — we're either at initcall time
        // (no executor) or from a spin-only path (panic dump),
        // both safe.
        let fut = self.bus.transfer(addr, ops);
        let r = narf_scheduler::block_on_spin(fut);
        // Map the kernel I2C error onto TcpcError. The chip-side
        // `TcpcError::BusError` is the only "I2C bus failed" code so
        // every kernel error class collapses to it.
        r.map_err(|_| TcpcError::BusError)
    }
}

impl ChipI2cBus for KernelBusBridge {
    fn write_reg(&self, addr: u8, reg: u8, value: u8) -> Result<(), TcpcError> {
        // I²C "write register": single START, [reg, val], STOP. The
        // FUSB302 / TPS65987 register map auto-increments inside a
        // single Write op so a 2-byte payload writes one register.
        let buf = [reg, value];
        let mut ops = [I2cOp::Write(&buf)];
        self.run(addr, &mut ops)
    }

    fn read_reg(&self, addr: u8, reg: u8) -> Result<u8, TcpcError> {
        // I²C "read register": Write(reg), Read(1). Repeated-START
        // between the two ops per the bus contract.
        let reg_buf = [reg];
        let mut out = [0u8; 1];
        let mut ops = [I2cOp::Write(&reg_buf), I2cOp::Read(&mut out)];
        self.run(addr, &mut ops)?;
        Ok(out[0])
    }

    fn read_burst(&self, addr: u8, reg: u8, out: &mut [u8]) -> Result<(), TcpcError> {
        let reg_buf = [reg];
        let mut ops = [I2cOp::Write(&reg_buf), I2cOp::Read(out)];
        self.run(addr, &mut ops)
    }

    fn write_burst(&self, addr: u8, reg: u8, data: &[u8]) -> Result<(), TcpcError> {
        // Need a contiguous payload [reg, data...]. Allocate so we
        // don't borrow `data` for an extra place.
        let mut payload: Vec<u8> = Vec::with_capacity(1 + data.len());
        payload.push(reg);
        payload.extend_from_slice(data);
        let mut ops = [I2cOp::Write(&payload)];
        self.run(addr, &mut ops)
    }
}
