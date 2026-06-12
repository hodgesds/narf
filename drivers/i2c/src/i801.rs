//! Intel 82801 (ICH/PCH) SMBus controller driver.
//!
//! Ref: Linux `drivers/i2c/busses/i2c-i801.c`.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use async_trait::async_trait;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_bus::{BusDevice, BusDeviceCap, MatchKind, MmioRegion, PciMatch};
use narf_capabilities::{Cap, Write};
use narf_lib::mutex::Mutex as AsyncMutex;

use crate::{I2cBus, I2cError, I2cOp};

pub const I801_VENDOR: u16 = 0x8086;

// Device IDs for a few common PCHs.
pub const I801_DID_LYNX_POINT: u16 = 0x8c22;
pub const I801_DID_SUNRISE_POINT_H: u16 = 0xa123;
pub const I801_DID_KABY_LAKE: u16 = 0xa2a3;

const SMBBAR: usize = 4;

const SMBHSTSTS: u32 = 0x0;
const SMBHSTCNT: u32 = 0x2;
const SMBHSTCMD: u32 = 0x3;
const SMBHSTADD: u32 = 0x4;
const SMBHSTDAT0: u32 = 0x5;
const SMBHSTDAT1: u32 = 0x6;
const SMBHSTSTS_FAILED: u8 = 1 << 4;
const SMBHSTSTS_BUS_ERR: u8 = 1 << 3;
const SMBHSTSTS_DEV_ERR: u8 = 1 << 2;
const SMBHSTSTS_INTR: u8 = 1 << 1;
const SMBHSTSTS_HOST_BUSY: u8 = 1 << 0;

const SMBHSTCNT_START: u8 = 1 << 6;
const I801_BYTE: u8 = 0x04;
const I801_BYTE_DATA: u8 = 0x08;
const I801_WORD_DATA: u8 = 0x0C;

const TRANSFER_TIMEOUT_POLLS: u32 = 100_000;

#[derive(Debug)]
pub struct I801Smbus {
    name: String,
    mmio: MmioRegion,
    bus: AsyncMutex<()>,
    pub(crate) enabled: AtomicBool,
}

impl I801Smbus {
    pub fn new(name: String, mmio: MmioRegion) -> Self {
        Self {
            name,
            mmio,
            bus: AsyncMutex::new(()),
            enabled: AtomicBool::new(true),
        }
    }

    unsafe fn read8(&self, off: u32) -> u8 {
        // SAFETY: MMIO access is valid
        unsafe { narf_arch::mmio::read8(self.mmio.phys.raw() + off as u64) }
    }

    unsafe fn write8(&self, off: u32, val: u8) {
        // SAFETY: MMIO access is valid
        unsafe { narf_arch::mmio::write8(self.mmio.phys.raw() + off as u64, val) }
    }

    fn check_status(&self) -> Result<(), I2cError> {
        // SAFETY: MMIO access is valid
        let sts = unsafe { self.read8(SMBHSTSTS) };
        if sts & SMBHSTSTS_FAILED != 0 {
            // SAFETY: MMIO access is valid
            unsafe { self.write8(SMBHSTSTS, SMBHSTSTS_FAILED) };
            return Err(I2cError::BadHardware);
        }
        if sts & SMBHSTSTS_BUS_ERR != 0 {
            // SAFETY: MMIO access is valid
            unsafe { self.write8(SMBHSTSTS, SMBHSTSTS_BUS_ERR) };
            return Err(I2cError::ArbLost);
        }
        if sts & SMBHSTSTS_DEV_ERR != 0 {
            // SAFETY: MMIO access is valid
            unsafe { self.write8(SMBHSTSTS, SMBHSTSTS_DEV_ERR) };
            return Err(I2cError::Nack);
        }
        Ok(())
    }

    async fn wait_ready(&self) -> Result<(), I2cError> {
        for _ in 0..TRANSFER_TIMEOUT_POLLS {
            // SAFETY: MMIO access is valid
            let sts = unsafe { self.read8(SMBHSTSTS) };
            if sts & SMBHSTSTS_HOST_BUSY == 0 {
                return Ok(());
            }
            narf_scheduler::yield_now().await;
        }
        Err(I2cError::Timeout)
    }

    async fn wait_intr(&self) -> Result<(), I2cError> {
        for _ in 0..TRANSFER_TIMEOUT_POLLS {
            // SAFETY: MMIO access is valid
            let sts = unsafe { self.read8(SMBHSTSTS) };
            if sts & (SMBHSTSTS_INTR | SMBHSTSTS_DEV_ERR | SMBHSTSTS_BUS_ERR | SMBHSTSTS_FAILED)
                != 0
            {
                return Ok(());
            }
            narf_scheduler::yield_now().await;
        }
        Err(I2cError::Timeout)
    }
}

#[async_trait]
impl I2cBus for I801Smbus {
    async fn transfer(&self, addr: u8, ops: &mut [I2cOp<'_>]) -> Result<(), I2cError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(I2cError::BadHardware);
        }
        let _bus_guard = self.bus.lock().await;

        self.wait_ready().await?;

        // Clear status
        // SAFETY: MMIO access is valid
        unsafe {
            self.write8(
                SMBHSTSTS,
                SMBHSTSTS_INTR | SMBHSTSTS_DEV_ERR | SMBHSTSTS_BUS_ERR | SMBHSTSTS_FAILED,
            );
        }

        // SMBus doesn't support generic I2C transfers nicely. We try to map it to SMBus commands.
        // For simplicity, we implement Byte Read and Byte Write.
        if ops.len() == 1 {
            match &mut ops[0] {
                I2cOp::Write(data) => {
                    if data.len() == 1 {
                        // Byte Write
                        // SAFETY: MMIO access is valid
                        unsafe {
                            self.write8(SMBHSTADD, addr << 1);
                            self.write8(SMBHSTCMD, data[0]);
                            self.write8(SMBHSTCNT, I801_BYTE_DATA | SMBHSTCNT_START);
                        }
                    } else if data.len() == 2 {
                        // Word Write (assume first byte is command, second is data)
                        // SAFETY: MMIO access is valid
                        unsafe {
                            self.write8(SMBHSTADD, addr << 1);
                            self.write8(SMBHSTCMD, data[0]);
                            self.write8(SMBHSTDAT0, data[1]);
                            self.write8(SMBHSTCNT, I801_BYTE_DATA | SMBHSTCNT_START);
                        }
                    } else {
                        return Err(I2cError::BadHardware);
                    }
                }
                I2cOp::Read(buf) => {
                    if buf.len() == 1 {
                        // SAFETY: MMIO access is valid
                        unsafe {
                            self.write8(SMBHSTADD, (addr << 1) | 1);
                            self.write8(SMBHSTCNT, I801_BYTE | SMBHSTCNT_START);
                        }
                    } else {
                        return Err(I2cError::BadHardware);
                    }
                }
            }
        } else if ops.len() == 2 {
            let (first, second) = ops.split_at_mut(1);
            if let (I2cOp::Write(w), I2cOp::Read(r)) = (&first[0], &mut second[0]) {
                if w.len() == 1 && r.len() == 1 {
                    // SMBus Read Byte
                    // SAFETY: MMIO access is valid
                    unsafe {
                        self.write8(SMBHSTADD, (addr << 1) | 1);
                        self.write8(SMBHSTCMD, w[0]);
                        self.write8(SMBHSTCNT, I801_BYTE_DATA | SMBHSTCNT_START);
                    }
                } else if w.len() == 1 && r.len() == 2 {
                    // SMBus Read Word
                    // SAFETY: MMIO access is valid
                    unsafe {
                        self.write8(SMBHSTADD, (addr << 1) | 1);
                        self.write8(SMBHSTCMD, w[0]);
                        self.write8(SMBHSTCNT, I801_WORD_DATA | SMBHSTCNT_START);
                    }
                } else {
                    return Err(I2cError::BadHardware);
                }
            } else {
                return Err(I2cError::BadHardware);
            }
        } else {
            return Err(I2cError::BadHardware);
        }

        self.wait_intr().await?;
        self.check_status()?;

        // Clear INTR
        // SAFETY: MMIO access is valid
        unsafe {
            self.write8(SMBHSTSTS, SMBHSTSTS_INTR);
        }

        // Read back data if needed
        if ops.len() == 1 {
            if let I2cOp::Read(buf) = &mut ops[0] {
                if buf.len() == 1 {
                    // SAFETY: MMIO access is valid
                    buf[0] = unsafe { self.read8(SMBHSTDAT0) };
                }
            }
        } else if ops.len() == 2 {
            if let I2cOp::Read(buf) = &mut ops[1] {
                if buf.len() == 1 {
                    // SAFETY: MMIO access is valid
                    buf[0] = unsafe { self.read8(SMBHSTDAT0) };
                } else if buf.len() == 2 {
                    // SAFETY: MMIO access is valid
                    buf[0] = unsafe { self.read8(SMBHSTDAT0) };
                    // SAFETY: MMIO access is valid
                    buf[1] = unsafe { self.read8(SMBHSTDAT1) };
                }
            }
        }

        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::IO_SPACE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: MMIO access is valid
    let mmio = unsafe { narf_bus::map_bar(&device, SMBBAR as u8) }
        .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    let name = match device.kind {
        narf_bus::BusKind::Pcie { addr, .. } => {
            format!(
                "smbus-i801-{:02x}:{:02x}.{}",
                addr.bus, addr.device, addr.function
            )
        }
        _ => String::from("smbus-i801-unknown"),
    };
    let driver = Arc::new(I801Smbus::new(name.clone(), mmio));

    crate::registry::register_unique(driver);

    let _ = core::fmt::write(
        &mut narf_console::Writer,
        format_args!("  i801: detected at {} \n", name),
    );
    Ok(())
}

pub fn register_pci_driver() {
    for did in [
        I801_DID_LYNX_POINT,
        I801_DID_SUNRISE_POINT_H,
        I801_DID_KABY_LAKE,
    ] {
        narf_bus::register_pci_driver(PciMatch {
            name: "i801_smbus",
            kind: MatchKind::VendorDevice {
                vendor: I801_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

#[doc(hidden)]
pub fn __new_for_test(name: String, mmio: MmioRegion) -> I801Smbus {
    I801Smbus::new(name, mmio)
}
