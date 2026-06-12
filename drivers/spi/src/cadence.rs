//! Cadence SPI controller driver.
//!
//! Provides support for the Cadence SPI controller found in many ARM
//! and Xilinx Zynq SoCs.
//!
//! References: `linux/drivers/spi/spi-cadence.c`

extern crate alloc;

use alloc::string::String;

use narf_memory::PhysAddr;
use narf_lib::sync::IrqSafeSpinLock;

use crate::{SpiBus, SpiError, SpiMode};

// ── Register offsets ───────────────────────────────────────────────

const CDNS_SPI_CR: u64   = 0x00; // Configuration Register
const CDNS_SPI_ISR: u64  = 0x04; // Interrupt Status Register
const CDNS_SPI_IER: u64  = 0x08; // Interrupt Enable Register
const CDNS_SPI_IDR: u64  = 0x0c; // Interrupt Disable Register
const CDNS_SPI_IMR: u64  = 0x10; // Interrupt Enabled Mask
const CDNS_SPI_ER: u64   = 0x14; // Enable/Disable Register
const CDNS_SPI_DR: u64   = 0x18; // Delay Register
const CDNS_SPI_TXD: u64  = 0x1C; // Data Transmit Register
const CDNS_SPI_RXD: u64  = 0x20; // Data Receive Register
const CDNS_SPI_SICR: u64 = 0x24; // Slave Idle Count Register
const CDNS_SPI_THLD: u64 = 0x28; // Transmit FIFO Watermark

const CDNS_SPI_CR_MANSTRT: u32   = 0x0001_0000;
const CDNS_SPI_CR_CPHA: u32      = 0x0000_0004;
const CDNS_SPI_CR_CPOL: u32      = 0x0000_0002;
const CDNS_SPI_CR_SSCTRL: u32    = 0x0000_3C00;
const CDNS_SPI_CR_MSTREN: u32    = 0x0000_0001;
const CDNS_SPI_CR_MANSTRTEN: u32 = 0x0000_8000;
const CDNS_SPI_CR_SSFORCE: u32   = 0x0000_4000;
const CDNS_SPI_CR_BAUD_DIV: u32  = 0x0000_0038;

const CDNS_SPI_ER_ENABLE: u32  = 0x0000_0001;
const CDNS_SPI_ER_DISABLE: u32 = 0x0000_0000;

const CDNS_SPI_IXR_TXOW: u32    = 0x0000_0004; // TX FIFO Overwater
const CDNS_SPI_IXR_RXNEMTY: u32 = 0x0000_0010; // RX FIFO Not Empty

// ── Controller struct ──────────────────────────────────────────────

#[derive(Debug)]
pub struct CadenceSpi {
    name: String,
    mmio_base: PhysAddr,
    state: IrqSafeSpinLock<()>,
}

impl CadenceSpi {
    pub fn new(name: String, mmio_base: PhysAddr) -> Self {
        let spi = Self {
            name,
            mmio_base,
            state: IrqSafeSpinLock::new(()),
        };
        // Initial reset
        spi.write_u32(CDNS_SPI_ER, CDNS_SPI_ER_DISABLE);
        
        let mut cr = spi.read_u32(CDNS_SPI_CR);
        cr |= CDNS_SPI_CR_MSTREN | CDNS_SPI_CR_SSFORCE | CDNS_SPI_CR_MANSTRTEN;
        spi.write_u32(CDNS_SPI_CR, cr);
        
        spi.write_u32(CDNS_SPI_ER, CDNS_SPI_ER_ENABLE);
        spi
    }

    fn read_u32(&self, off: u64) -> u32 {
        unsafe { narf_arch::mmio::read32(self.mmio_base.raw() + off) }
    }

    fn write_u32(&self, off: u64, val: u32) {
        unsafe { narf_arch::mmio::write32(self.mmio_base.raw() + off, val) }
    }

    fn read_rx(&self) -> u32 {
        self.read_u32(CDNS_SPI_RXD)
    }

    fn write_tx(&self, val: u32) {
        self.write_u32(CDNS_SPI_TXD, val);
    }
}

impl SpiBus for CadenceSpi {
    fn name(&self) -> &str {
        &self.name
    }

    fn transfer(&self, tx: &[u8], rx: &mut [u8]) -> Result<(), SpiError> {
        let _guard = self.state.lock();
        
        let len = core::cmp::max(tx.len(), rx.len());
        for i in 0..len {
            let out_byte = if i < tx.len() { tx[i] } else { 0 };
            
            // Wait for TX room (naive poll)
            let mut timeout = 100_000;
            while (self.read_u32(CDNS_SPI_ISR) & CDNS_SPI_IXR_TXOW) == 0 {
                timeout -= 1;
                if timeout == 0 {
                    return Err(SpiError::Timeout);
                }
                core::hint::spin_loop();
            }
            
            self.write_tx(out_byte as u32);
            
            // Manual start
            let cr = self.read_u32(CDNS_SPI_CR);
            self.write_u32(CDNS_SPI_CR, cr | CDNS_SPI_CR_MANSTRT);

            // Wait for RX ready
            timeout = 100_000;
            while (self.read_u32(CDNS_SPI_ISR) & CDNS_SPI_IXR_RXNEMTY) == 0 {
                timeout -= 1;
                if timeout == 0 {
                    return Err(SpiError::Timeout);
                }
                core::hint::spin_loop();
            }
            
            let in_byte = self.read_rx() as u8;
            if i < rx.len() {
                rx[i] = in_byte;
            }
        }
        
        Ok(())
    }

    fn transfer_full_duplex(&self, tx: &mut [u8], rx: &mut [u8]) -> Result<(), SpiError> {
        let len = core::cmp::min(tx.len(), rx.len());
        self.transfer(&tx[..len], &mut rx[..len])
    }

    fn set_mode(&self, mode: SpiMode) -> Result<(), SpiError> {
        let _guard = self.state.lock();
        let mut cr = self.read_u32(CDNS_SPI_CR);
        
        if mode.cpol() {
            cr |= CDNS_SPI_CR_CPOL;
        } else {
            cr &= !CDNS_SPI_CR_CPOL;
        }
        
        if mode.cpha() {
            cr |= CDNS_SPI_CR_CPHA;
        } else {
            cr &= !CDNS_SPI_CR_CPHA;
        }
        
        self.write_u32(CDNS_SPI_CR, cr);
        Ok(())
    }

    fn set_freq(&self, _hz: u32) -> Result<(), SpiError> {
        // Frequency setting requires clock framework to calculate baud div.
        Ok(())
    }

    fn set_cs(&self, cs: u8) -> Result<(), SpiError> {
        if cs > 3 {
            return Err(SpiError::InvalidCs);
        }
        let _guard = self.state.lock();
        let mut cr = self.read_u32(CDNS_SPI_CR);
        cr &= !CDNS_SPI_CR_SSCTRL;
        
        // Cadence uses inverted CS select or fully decoded?
        // Let's use basic shifting for now.
        let ss_mask = !(1 << cs) & 0xF;
        cr |= (ss_mask << 10) & CDNS_SPI_CR_SSCTRL;
        
        self.write_u32(CDNS_SPI_CR, cr);
        Ok(())
    }
}

/// Probe for Cadence SPI controllers.
pub fn probe_all() -> usize {
    // Basic DT / ACPI Platform device probing placeholder.
    // Xilinx Zynq systems will typically expose this as a platform device.
    // Since we don't have DT yet, we return 0.
    0
}
