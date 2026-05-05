//! NXP I3C Master Controller driver.
//!
//! Based on the NXP I3C register map found in i.MX 93 and MCX N series.
//! Clean-room implementation following the publicly documented register map.

use alloc::sync::Arc;
use alloc::boxed::Box;
use async_trait::async_trait;
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion, map_bar};
use narf_i3c::{I3cBus, I3cError, I3cOp, registry};
use narf_drivers::{Driver, DriverEnv, DriverFuture};
use narf_capabilities::{Cap, Write};
use core::task::Waker;
use narf_lib::sync::IrqSafeSpinLock;

// ── NXP I3C Register Offsets ───────────────────────────────────────
const REG_MCTRL:      u64 = 0x00; // Main Control
const REG_MSTATUS:    u64 = 0x04; // Main Status
const REG_IBIRULES:   u64 = 0x08; // IBI Rules
const REG_MINTSET:    u64 = 0x0C; // Interrupt Set
const REG_MDATACTRL:  u64 = 0x20; // Data Control
const REG_MWDATAB:    u64 = 0x24; // Write Data Byte
const REG_MRDATAB:    u64 = 0x2C; // Read Data Byte
const REG_MWMSG_SADDR: u64 = 0x30; // Static Address
const REG_MCONFIG:    u64 = 0x40; // Master Config

// ── Register Bits ──────────────────────────────────────────────────
const MCTRL_REQUEST_NONE: u32 = 0x0;
const MCTRL_REQUEST_START: u32 = 0x1;
const MCTRL_TYPE_I3C:     u32 = 0x0 << 4;
const MCTRL_TYPE_I2C:     u32 = 0x1 << 4;

const MSTATUS_COMPLETE: u32 = 1 << 0;
const MSTATUS_ERROR:    u32 = 1 << 1;

pub fn probe(
    device: BusDevice,
    _cap:     Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    // SAFETY: caller-authority over the device.
    let mmio = unsafe { map_bar(&device, 0) }.map_err(|_| narf_bus::ProbeError::BadDevice)?;

    let driver = Arc::new(NxpI3c {
        mmio: mmio.clone(),
        ibi_wakers: IrqSafeSpinLock::new([const { None }; 128]),
    });

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name:    alloc::string::String::from("nxp-i3c"),
        kind:    narf_drivers::BoundKind::Other,
        pci_vid: None,
        pci_did: None,
        domain:  narf_drivers::BoundKind::Other.default_domain(),
    });

    registry::register(driver);
    Ok(())
}

pub fn register() {
    // In a real system, this would be a platform driver match.
    // narf_bus::register_platform_driver(...)
}

#[derive(Debug)]
pub struct NxpI3c {
    mmio: MmioRegion,
    ibi_wakers: IrqSafeSpinLock<[Option<Waker>; 128]>,
}

impl Driver for NxpI3c {
    fn start<'a>(&'a mut self, _env: DriverEnv<'a>) -> DriverFuture<'a> {
        Box::pin(async move {
            // Initialize the master.
            unsafe { self.mmio.write32(REG_MCONFIG, 0x1); } // Basic enable
        })
    }

    fn quiesce<'a>(&'a mut self) -> DriverFuture<'a> {
        Box::pin(async move {
            unsafe { self.mmio.write32(REG_MCONFIG, 0x0); }
        })
    }
}

#[async_trait]
impl I3cBus for NxpI3c {
    async fn transfer(&self, addr: u8, ops: &mut [I3cOp]) -> Result<(), I3cError> {
        // 1. Set the target address.
        unsafe { self.mmio.write32(REG_MWMSG_SADDR, (addr as u32) << 1); }

        for op in ops {
            match op {
                I3cOp::Write(data) => {
                    for &byte in data.iter() {
                        // Wait for FIFO space... (simplified)
                        unsafe { self.mmio.write32(REG_MWDATAB, byte as u32); }
                    }
                }
                I3cOp::Read(buf) => {
                    for i in 0..buf.len() {
                        // Wait for data... (simplified)
                        buf[i] = unsafe { self.mmio.read32(REG_MRDATAB) as u8 };
                    }
                }
            }
        }

        // 2. Trigger the transfer.
        unsafe { self.mmio.write32(REG_MCTRL, MCTRL_REQUEST_START | MCTRL_TYPE_I3C); }

        // 3. Wait for completion.
        loop {
            let status = unsafe { self.mmio.read32(REG_MSTATUS) };
            if (status & MSTATUS_COMPLETE) != 0 { break; }
            if (status & MSTATUS_ERROR) != 0 { return Err(I3cError::HardwareError); }
            narf_scheduler::yield_now().await;
        }

        Ok(())
    }

    fn register_ibi_waker(&self, addr: u8, waker: Waker) {
        if addr < 128 {
            self.ibi_wakers.lock()[addr as usize] = Some(waker);
        }
    }

    fn unregister_ibi_waker(&self, addr: u8) {
        if addr < 128 {
            self.ibi_wakers.lock()[addr as usize] = None;
        }
    }
}
