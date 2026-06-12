//! AMD PIIX4 / FCH SMBus controller driver.
//!
//! Ref: Linux `drivers/i2c/busses/i2c-piix4.c`.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use async_trait::async_trait;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_bus::{BusDevice, BusDeviceCap, MatchKind, PciMatch};
use narf_capabilities::{Cap, Write};
use narf_lib::mutex::Mutex as AsyncMutex;

use crate::{I2cBus, I2cError, I2cOp};

pub const AMD_VENDOR_ID: u16 = 0x1022;
pub const AMD_KERNCZ_SMBUS: u16 = 0x790b; // Found on Zen/Zen2/Zen3/Zen4 FCH

const SMBHSTSTS: u16 = 0x0;
const SMBHSTCNT: u16 = 0x2;
const SMBHSTCMD: u16 = 0x3;
const SMBHSTADD: u16 = 0x4;
const SMBHSTDAT0: u16 = 0x5;
const SMBHSTDAT1: u16 = 0x6;

const SMBHSTSTS_FAILED: u8 = 1 << 4;
const SMBHSTSTS_BUS_ERR: u8 = 1 << 3;
const SMBHSTSTS_DEV_ERR: u8 = 1 << 2;
const SMBHSTSTS_INTR: u8 = 1 << 1;
const SMBHSTSTS_HOST_BUSY: u8 = 1 << 0;

const SMBHSTCNT_START: u8 = 1 << 6;
const PIIX4_BYTE: u8 = 0x04;
const PIIX4_BYTE_DATA: u8 = 0x08;
const PIIX4_WORD_DATA: u8 = 0x0C;

const TRANSFER_TIMEOUT_POLLS: u32 = 100_000;

#[derive(Debug)]
pub struct Piix4Smbus {
    name: String,
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    io_base: u16,
    bus: AsyncMutex<()>,
    pub(crate) enabled: AtomicBool,
}

impl Piix4Smbus {
    pub fn new(name: String, io_base: u16) -> Self {
        Self {
            name,
            io_base,
            bus: AsyncMutex::new(()),
            enabled: AtomicBool::new(true),
        }
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn read8(&self, off: u16) -> u8 {
        // SAFETY: IO port access within bounds of the controller
        unsafe { narf_arch::x86_64::io_port::inb(self.io_base + off) }
    }

    #[cfg(not(target_arch = "x86_64"))]
    unsafe fn read8(&self, _off: u16) -> u8 {
        0
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn write8(&self, off: u16, val: u8) {
        // SAFETY: IO port access within bounds of the controller
        unsafe { narf_arch::x86_64::io_port::outb(self.io_base + off, val) }
    }

    #[cfg(not(target_arch = "x86_64"))]
    unsafe fn write8(&self, _off: u16, _val: u8) {}

    fn check_status(&self) -> Result<(), I2cError> {
        // SAFETY: IO port access is valid
        let sts = unsafe { self.read8(SMBHSTSTS) };
        if sts & SMBHSTSTS_FAILED != 0 {
            // SAFETY: Valid MMIO bounds or trusted driver environment
            unsafe { self.write8(SMBHSTSTS, SMBHSTSTS_FAILED) };
            return Err(I2cError::BadHardware);
        }
        if sts & SMBHSTSTS_BUS_ERR != 0 {
            // SAFETY: Valid MMIO bounds or trusted driver environment
            unsafe { self.write8(SMBHSTSTS, SMBHSTSTS_BUS_ERR) };
            return Err(I2cError::ArbLost);
        }
        if sts & SMBHSTSTS_DEV_ERR != 0 {
            // SAFETY: Valid MMIO bounds or trusted driver environment
            unsafe { self.write8(SMBHSTSTS, SMBHSTSTS_DEV_ERR) };
            return Err(I2cError::Nack);
        }
        Ok(())
    }

    async fn wait_ready(&self) -> Result<(), I2cError> {
        for _ in 0..TRANSFER_TIMEOUT_POLLS {
            // SAFETY: IO port access is valid
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
            // SAFETY: IO port access is valid
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
impl I2cBus for Piix4Smbus {
    async fn transfer(&self, addr: u8, ops: &mut [I2cOp<'_>]) -> Result<(), I2cError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(I2cError::BadHardware);
        }
        let _bus_guard = self.bus.lock().await;

        self.wait_ready().await?;

        // Clear status
        // SAFETY: IO port access is valid
        unsafe {
            self.write8(
                SMBHSTSTS,
                SMBHSTSTS_INTR | SMBHSTSTS_DEV_ERR | SMBHSTSTS_BUS_ERR | SMBHSTSTS_FAILED,
            );
        }

        // Map to SMBus commands
        if ops.len() == 1 {
            match &mut ops[0] {
                I2cOp::Write(data) => {
                    if data.len() == 1 {
                        // SAFETY: Valid MMIO bounds or trusted driver environment
                        unsafe {
                            self.write8(SMBHSTADD, addr << 1);
                            self.write8(SMBHSTCMD, data[0]);
                            self.write8(SMBHSTCNT, PIIX4_BYTE_DATA | SMBHSTCNT_START);
                        }
                    } else if data.len() == 2 {
                        // SAFETY: Valid MMIO bounds or trusted driver environment
                        unsafe {
                            self.write8(SMBHSTADD, addr << 1);
                            self.write8(SMBHSTCMD, data[0]);
                            self.write8(SMBHSTDAT0, data[1]);
                            self.write8(SMBHSTCNT, PIIX4_BYTE_DATA | SMBHSTCNT_START);
                        }
                    } else {
                        return Err(I2cError::BadHardware);
                    }
                }
                I2cOp::Read(buf) => {
                    if buf.len() == 1 {
                        // SAFETY: Valid MMIO bounds or trusted driver environment
                        unsafe {
                            self.write8(SMBHSTADD, (addr << 1) | 1);
                            self.write8(SMBHSTCNT, PIIX4_BYTE | SMBHSTCNT_START);
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
                    // SAFETY: Valid MMIO bounds or trusted driver environment
                    unsafe {
                        self.write8(SMBHSTADD, (addr << 1) | 1);
                        self.write8(SMBHSTCMD, w[0]);
                        self.write8(SMBHSTCNT, PIIX4_BYTE_DATA | SMBHSTCNT_START);
                    }
                } else if w.len() == 1 && r.len() == 2 {
                    // SAFETY: Valid MMIO bounds or trusted driver environment
                    unsafe {
                        self.write8(SMBHSTADD, (addr << 1) | 1);
                        self.write8(SMBHSTCMD, w[0]);
                        self.write8(SMBHSTCNT, PIIX4_WORD_DATA | SMBHSTCNT_START);
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
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            self.write8(SMBHSTSTS, SMBHSTSTS_INTR);
        }

        // Read back data if needed
        if ops.len() == 1 {
            if let I2cOp::Read(buf) = &mut ops[0] {
                if buf.len() == 1 {
                    // SAFETY: Valid MMIO bounds or trusted driver environment
                    buf[0] = unsafe { self.read8(SMBHSTDAT0) };
                }
            }
        } else if ops.len() == 2 {
            if let I2cOp::Read(buf) = &mut ops[1] {
                if buf.len() == 1 {
                    // SAFETY: Valid MMIO bounds or trusted driver environment
                    buf[0] = unsafe { self.read8(SMBHSTDAT0) };
                } else if buf.len() == 2 {
                    // SAFETY: Valid MMIO bounds or trusted driver environment
                    buf[0] = unsafe { self.read8(SMBHSTDAT0) };
                    // SAFETY: Valid MMIO bounds or trusted driver environment
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

#[cfg(target_arch = "x86_64")]
fn get_amd_fch_smba() -> Option<u16> {
    const SB800_PIIX4_SMB_IDX: u16 = 0xcd6;
    let smb_en: u8 = 0x2c; // main port
    let smba_en_lo: u8;
    let smba_en_hi: u8;

    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        narf_arch::x86_64::io_port::outb(SB800_PIIX4_SMB_IDX, smb_en);
        smba_en_lo = narf_arch::x86_64::io_port::inb(SB800_PIIX4_SMB_IDX + 1);
        narf_arch::x86_64::io_port::outb(SB800_PIIX4_SMB_IDX, smb_en + 1);
        smba_en_hi = narf_arch::x86_64::io_port::inb(SB800_PIIX4_SMB_IDX + 1);
    }

    let status = smba_en_lo & 0x01;
    if status == 0 {
        return None;
    }

    let io_base = (((smba_en_hi as u16) << 8) | (smba_en_lo as u16)) & 0xffe0;
    Some(io_base)
}

#[cfg(not(target_arch = "x86_64"))]
fn get_amd_fch_smba() -> Option<u16> {
    None
}

pub fn probe(
    device: BusDevice,
    _cap: Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    let io_base = match get_amd_fch_smba() {
        Some(base) => base,
        None => return Err(narf_bus::ProbeError::BadDevice),
    };

    let name = match device.kind {
        narf_bus::BusKind::Pcie { addr, .. } => {
            format!(
                "smbus-piix4-{:02x}:{:02x}.{}",
                addr.bus, addr.device, addr.function
            )
        }
        _ => String::from("smbus-piix4-unknown"),
    };
    let driver = Arc::new(Piix4Smbus::new(name.clone(), io_base));

    crate::registry::register_unique(driver);

    let _ = core::fmt::write(
        &mut narf_console::Writer,
        format_args!("  piix4: detected at {} (IO={:#06x})\n", name, io_base),
    );
    Ok(())
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(PciMatch {
        name: "piix4_smbus",
        kind: MatchKind::VendorDevice {
            vendor: AMD_VENDOR_ID,
            device: AMD_KERNCZ_SMBUS,
        },
        probe,
    });
}
